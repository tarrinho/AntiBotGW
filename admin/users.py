# admin/users.py — Phase 8: dashboard user accounts + session management
# Extracted from proxy.py lines 11621–13155 area
import base64 as _b64  # noqa: F401
import time as _t  # noqa: F401
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR  # noqa: F401 — underscore not exported by *
from state import *    # noqa: F401,F403
from helpers import slog, now, get_ip  # noqa: F401
from admin.auth import _internal_authed, _request_username  # noqa: F401
from aiohttp import web

# ── 1.6.7: dashboard user accounts ──────────────────────────────────
_USERNAME_RE  = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
_USER_ROLES   = ("admin",)            # extension point: viewer/editor
_USER_STATUS  = ("active", "disabled")
_SESSION_COOKIE = "agw_session"
_SESSION_TTL  = 12 * 3600              # 12h sliding session
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1   # ~70 ms on a single core
_LOGIN_BUCKET: dict = {}               # ip → (window_start, count)
_LOGIN_BUCKET_LOCK = asyncio.Lock()
# 1.6.7 — last-seen-ts per signed-in user. Bumped on every cookie-
# authenticated request inside `_internal_authed`. In-memory so it
# resets on container restart (acceptable: a fresh boot shows everyone
# offline until they next interact). The Users list considers a user
# "online" if seen in the last `_ACTIVE_SESSION_TTL_S` seconds.
_ACTIVE_SESSION_TTL_S = 60
_ACTIVE_SESSIONS: dict = {}            # username → last_seen_ts

# 1.6.7 — per-session state. Each login mints a fresh sid; the server-
# side `user_sessions` row is the source of truth for whether a token
# is still valid. The in-memory cache is loaded at boot from the table
# and updated on login/logout/revoke. O(1) verify on the request path.
_SESSION_CACHE: dict = {}              # sid → {username, expires_ts, revoked}
_SESSION_CACHE_LOCK = asyncio.Lock()
_SID_RE = re.compile(r"^[A-Za-z0-9_-]{16,32}$")


def _password_hash(pw: str) -> str:
    """scrypt with random 16-byte salt; result is `scrypt$N$r$p$salt$hash`
    base64url so it round-trips in JSON / SQL cleanly."""
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode("utf-8"), salt=salt,
                        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
                        maxmem=64 * 1024 * 1024)
    salt_b = _b64.urlsafe_b64encode(salt).rstrip(b"=").decode("ascii")
    hash_b = _b64.urlsafe_b64encode(h).rstrip(b"=").decode("ascii")
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt_b}${hash_b}"


def _password_verify(pw: str, stored: str) -> bool:
    """Constant-time compare. Returns False on any malformed stored value."""
    try:
        algo, n, r, p, salt_b, hash_b = stored.split("$")
        if algo != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        salt = _b64.urlsafe_b64decode(salt_b + "=" * (-len(salt_b) % 4))
        want = _b64.urlsafe_b64decode(hash_b + "=" * (-len(hash_b) % 4))
        got  = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                               maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(want, got)
    except (ValueError, TypeError):
        return False


def _new_sid() -> str:
    """22-char URL-safe random — matches secrets.token_urlsafe(16)."""
    return secrets.token_urlsafe(16)


def _session_sign(username: str, sid: str | None = None,
                   ttl: int = _SESSION_TTL) -> str:
    """Return a tamper-evident session token: `username|sid|expiry|HMAC`.
    The sid lets the server revoke individual sessions (older format
    without sid is no longer accepted — operators re-login on upgrade).
    HMAC-SHA256 over `username|sid|expiry` keyed with SESSION_KEY."""
    if sid is None:
        sid = _new_sid()
    expiry = int(_t.time()) + int(ttl)
    payload = f"{username}|{sid}|{expiry}".encode("utf-8")
    sig = hmac.new(SESSION_KEY, payload, hashlib.sha256).digest()
    sig_b = _b64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    return f"{username}|{sid}|{expiry}|{sig_b}"


def _session_parse(token: str) -> tuple[str, str, int] | None:
    """Verify HMAC + structural shape; return (username, sid, expiry) or
    None. Does NOT consult the cache — that's the caller's job."""
    if not token or token.count("|") != 3:
        return None
    try:
        username, sid, expiry_s, sig_b = token.split("|")
        expiry = int(expiry_s)
    except (ValueError, TypeError):
        return None
    if expiry < int(_t.time()):
        return None
    if not _USERNAME_RE.match(username):
        return None
    if not _SID_RE.match(sid):
        return None
    payload = f"{username}|{sid}|{expiry}".encode("utf-8")
    want = hmac.new(SESSION_KEY, payload, hashlib.sha256).digest()
    try:
        got = _b64.urlsafe_b64decode(sig_b + "=" * (-len(sig_b) % 4))
    except (ValueError, TypeError):
        return None
    if not hmac.compare_digest(want, got):
        return None
    return username, sid, expiry


def _session_verify(token: str) -> str | None:
    """Return the username if the token is structurally valid AND the
    sid is still active in `_SESSION_CACHE`. A revoked sid fails here,
    making the operator's "Revoke" click effective on the very next
    request. Falls back to `_session_parse` semantics when the cache
    is cold (just after boot, before the loader runs)."""
    parsed = _session_parse(token)
    if parsed is None:
        return None
    username, sid, expiry = parsed
    cached = _SESSION_CACHE.get(sid)
    if cached is None:
        # Cold cache OR row purged; trust the HMAC + expiry only when
        # the cache hasn't loaded yet (boot-window grace). After boot
        # we require the cache hit to be present — see _session_cache_ready.
        if not _SESSION_CACHE_READY:
            return username
        return None
    if cached.get("revoked"):
        return None
    if cached.get("username") != username:
        return None
    if cached.get("expires_ts", 0) < _t.time():
        return None
    return username


# Track whether the cache loader has finished (post-boot).
_SESSION_CACHE_READY = False


def _session_cache_load() -> None:
    """Populate `_SESSION_CACHE` from the `user_sessions` table at boot
    and after a writer-loop refresh. O(active_sessions) reads."""
    global _SESSION_CACHE_READY
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT sid, username, expires_ts, status FROM user_sessions "
            "WHERE status = 'active' AND expires_ts > ?",
            (_t.time(),)).fetchall()
        conn.close()
    except Exception as e:
        slog("session_cache_load_failed", level="error", err=str(e)[:200])
        _SESSION_CACHE_READY = True
        return
    fresh = {}
    for r in rows:
        fresh[r["sid"]] = {
            "username":   r["username"],
            "expires_ts": float(r["expires_ts"] or 0),
            "revoked":    False,
        }
    _SESSION_CACHE.clear()
    _SESSION_CACHE.update(fresh)
    _SESSION_CACHE_READY = True
    slog("session_cache_loaded", level="info", count=len(fresh))


def _session_create(username: str, ip: str, user_agent: str) -> str:
    """Mint a fresh session: insert the row, prime the cache, return
    the cookie token. Caller is responsible for setting the cookie on
    the response."""
    sid = _new_sid()
    n = _t.time()
    expires_ts = n + _SESSION_TTL
    if db_queue is not None:
        try:
            db_queue.put_nowait((
                "user_session_create",
                (sid, username, ip or "", (user_agent or "")[:512],
                 n, n, expires_ts),
            ))
        except asyncio.QueueFull:
            pass
    _SESSION_CACHE[sid] = {
        "username": username, "expires_ts": expires_ts, "revoked": False,
    }
    return _session_sign(username, sid=sid)


def _session_revoke(sid: str, by_username: str) -> bool:
    """Mark a session revoked. Effective on the next request via the
    cache miss. Returns False if the sid is unknown."""
    if sid not in _SESSION_CACHE:
        return False
    _SESSION_CACHE[sid]["revoked"] = True
    if db_queue is not None:
        try:
            db_queue.put_nowait((
                "user_session_revoke",
                (sid, by_username or "", _t.time()),
            ))
        except asyncio.QueueFull:
            pass
    return True


def _session_touch(sid: str) -> None:
    """Bump last_seen_ts on the row. Throttled — at most one update
    per session per 30s to avoid flooding the writer queue."""
    n = _t.time()
    cached = _SESSION_CACHE.get(sid)
    if not cached:
        return
    last_touch = cached.get("_last_touch", 0)
    if n - last_touch < 30:
        return
    cached["_last_touch"] = n
    if db_queue is not None:
        try:
            db_queue.put_nowait(("user_session_touch", (n, sid)))
        except asyncio.QueueFull:
            pass


def _user_load(username: str) -> dict | None:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM users WHERE username = ?",
                            (username,)).fetchone()
        conn.close()
    except Exception:
        return None
    return dict(row) if row else None


def _user_load_all() -> list[dict]:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT username, role, status, created_ts, updated_ts, "
            "last_login_ts, last_login_ip FROM users ORDER BY username"
        ).fetchall()
        conn.close()
    except Exception:
        return []
    return [dict(r) for r in rows]


def _user_count() -> int:
    try:
        conn = sqlite3.connect(DB_PATH)
        n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        conn.close()
        return int(n or 0)
    except Exception:
        return 0


def _user_validate_username(u: str) -> tuple[bool, str]:
    if not u or not isinstance(u, str):
        return False, "username required"
    if len(u) > 64:
        return False, "username too long (max 64)"
    if not _USERNAME_RE.match(u):
        return False, "username must be lowercase alphanumeric + . _ - (2-64)"
    return True, ""


def _user_bootstrap() -> None:
    """1.6.7 — on first start (no users in the table), auto-create an
    `admin` user whose password is the existing INTERNAL_KEY. This
    preserves the existing single-key auth model as the operator's
    bootstrap credential while moving forward to per-user accounts.
    Once the operator changes the password, the INTERNAL_KEY → admin
    mapping is gone (the key still works as a bearer for scripted
    clients via `_internal_authed`)."""
    if _user_count() > 0:
        return
    n = _t.time()
    pw_hash = _password_hash(INTERNAL_KEY)
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO users (username, password_hash, role, status, "
            "created_ts, updated_ts) VALUES (?, ?, 'admin', 'active', ?, ?)",
            ("admin", pw_hash, n, n))
        conn.commit()
        conn.close()
        slog("user_bootstrap", level="warn", username="admin",
             note="initial admin password = INTERNAL_KEY (rotate via /__rotate-keys or Settings)")
    except Exception as e:
        print(f"[users] bootstrap failed: {e}", flush=True)


async def _login_rate_limit(ip: str) -> bool:
    """Return True iff this IP is allowed to attempt another login.
    5 attempts per 60s rolling window. Failed attempts are counted; a
    successful login does not reset (cheap, good-enough back-pressure)."""
    n = _t.time()
    async with _LOGIN_BUCKET_LOCK:
        st = _LOGIN_BUCKET.get(ip)
        if st is None or n - st[0] > 60:
            _LOGIN_BUCKET[ip] = [n, 1]
            return True
        st[1] += 1
        if st[1] > 5:
            return False
        _LOGIN_BUCKET[ip] = st
        return True


def _bootstrap_hint_html() -> str:
    """Return the first-time-setup banner only when no user has ever
    logged in. Once any account has a non-null `last_login_ts`, the
    bootstrap message is suppressed so a returning operator doesn't see
    the "Sign in as admin using the startup-issued key" hint indefinitely."""
    try:
        conn = sqlite3.connect(DB_PATH)
        seen = conn.execute(
            "SELECT COUNT(*) FROM users WHERE last_login_ts IS NOT NULL"
        ).fetchone()[0]
        conn.close()
    except Exception:
        seen = 1   # fail-closed: don't show the hint if the DB is wonky
    if seen and seen > 0:
        return ""
    return (
        '<div class="bootstrap-note" id="bootstrap-note">'
        '<strong>First-time setup?</strong> Sign in as <code>admin</code> '
        'using the gateway\'s startup-issued admin key. After login you '
        'can change the password and add other users from '
        '<em>Settings → Users</em>.'
        '</div>')


async def login_page_endpoint(request: web.Request):
    """GET /antibot-appsec-gateway/login — render the sign-in form. Public
    sub-path; no auth required to view. The first-time-setup hint is
    rendered only until the operator's first successful login."""
    if request.cookies.get(_SESSION_COOKIE) and _session_verify(
            request.cookies.get(_SESSION_COOKIE)):
        next_url = request.query.get("next") or "/antibot-appsec-gateway/secured/dashboard"
        return web.HTTPFound(next_url)
    body = (_DASHBOARDS_DIR / "login.html").read_text(encoding="utf-8").replace(
        "__BOOTSTRAP_HINT__", _bootstrap_hint_html())
    return web.Response(
        text=body, content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })


async def login_submit_endpoint(request: web.Request):
    """POST /antibot-appsec-gateway/login — verify credentials and set the
    session cookie. Body: form-urlencoded `username`, `password`, `next`."""
    ip = get_ip(request)
    if not await _login_rate_limit(ip):
        return web.json_response({"error": "too many attempts; wait 60s"},
                                  status=429,
                                  headers={"Cache-Control": "no-store",
                                           "Retry-After": "60"})
    try:
        raw = await asyncio.wait_for(request.content.read(8 * 1024),
                                      timeout=BODY_TIMEOUT)
    except asyncio.TimeoutError:
        return web.json_response({"error": "timeout"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    from urllib.parse import parse_qs
    try:
        params = parse_qs(raw.decode("utf-8", errors="replace"),
                           keep_blank_values=True)
    except Exception:
        return web.json_response({"error": "bad form"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    username = (params.get("username", [""])[0] or "").strip().lower()
    password = params.get("password", [""])[0] or ""
    next_url = params.get("next", ["/antibot-appsec-gateway/secured/dashboard"])[0]
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/antibot-appsec-gateway/secured/dashboard"
    ok, msg = _user_validate_username(username)
    if not ok or not password:
        slog("login_failed", level="warn", username=username, ip=ip,
             reason="bad-input")
        return web.json_response({"error": "invalid credentials"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    user = _user_load(username)
    if user is None or user.get("status") != "active":
        slog("login_failed", level="warn", username=username, ip=ip,
             reason="no-such-user-or-disabled")
        return web.json_response({"error": "invalid credentials"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    if not _password_verify(password, user.get("password_hash") or ""):
        slog("login_failed", level="warn", username=username, ip=ip,
             reason="bad-password")
        return web.json_response({"error": "invalid credentials"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    # 1.6.7 — mint a fresh per-session cookie (sid embedded). Captures
    # the source IP and User-Agent for the session ledger so the
    # operator can spot unfamiliar sessions and revoke them.
    if db_queue is not None:
        try:
            db_queue.put_nowait((
                "user_login_recorded",
                (_t.time(), ip, username),
            ))
        except asyncio.QueueFull:
            pass
    slog("login_success", level="warn", username=username, ip=ip)
    _ACTIVE_SESSIONS[username] = _t.time()
    ua = (request.headers.get("User-Agent") or "")[:512]
    token = _session_create(username, ip, ua)
    resp = web.json_response({"ok": True, "redirect": next_url, "username": username},
                              headers={"Cache-Control": "no-store"})
    # SameSite=Lax + HttpOnly + Secure-when-TLS — the cookie travels on
    # top-level navigations from the login form's redirect, never cross-
    # site, never readable by JavaScript.
    resp.set_cookie(_SESSION_COOKIE, token,
                     max_age=_SESSION_TTL, httponly=True,
                     samesite="Lax", path="/",
                     secure=bool(int(os.environ.get("TLS_ENABLED", "0"))))
    return resp


async def logout_endpoint(request: web.Request):
    """GET /antibot-appsec-gateway/logout — revoke the current session
    server-side AND clear the cookie. Revoking on the server makes the
    cookie unusable even if it leaks; the operator's other sessions on
    the same account stay live."""
    user = ""
    sid  = ""
    cookie = request.cookies.get(_SESSION_COOKIE, "")
    if cookie:
        parsed = _session_parse(cookie)
        if parsed:
            user, sid, _ = parsed
    if user:
        slog("logout", level="warn", username=user, ip=get_ip(request), sid=sid)
        _ACTIVE_SESSIONS.pop(user, None)
        if sid:
            _session_revoke(sid, by_username=user)
    resp = web.HTTPFound("/antibot-appsec-gateway/login")
    resp.del_cookie(_SESSION_COOKIE, path="/")
    return resp


async def ip_intel_endpoint(request: web.Request):
    """GET <NS>/secured/ip-intel/{ip} — aggregate every reputation +
    geolocation signal the gateway already has on an IP into one
    payload. Powers the Identity-details popover in agents.html /
    main.html. All sub-lookups are best-effort: a downed AbuseIPDB or
    missing MaxMind file degrades to source='disabled'/'unknown', the
    rest of the payload still returns.

    Layers (in increasing reliance on remote services):
      • internal: ban state, risk score, request counts (free, local DB)
      • geo:      MaxMind GeoLite2-City  (free, local mmdb)
      • asn:      MaxMind GeoLite2-ASN  (free, local mmdb)
      • tor_exit: in-memory torbulkexitlist set
      • abuseipdb: SQLite cache (or live API if cache stale + key set)
      • crowdsec:  in-process cache (or LAPI poll if stale + URL set)
    """
    import ipaddress as _ipaddress
    ip = (request.match_info.get("ip") or "").strip()
    try:
        _ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return web.json_response({"error": "invalid IP"}, status=400,
                                  headers={"Cache-Control": "no-store"})

    out: dict = {"ip": ip}

    # ── geo (City) ────────────────────────────────────────────────
    city_rec = _city_lookup(ip)
    if city_rec:
        lat, lng, country, city = city_rec
        out["geo"] = {"country": country, "city": city,
                      "lat": lat, "lng": lng}
    else:
        out["geo"] = {"country": "", "city": "", "lat": None, "lng": None}

    # ── ASN ──────────────────────────────────────────────────────
    asn, org, is_hosting, asn_src = _asn_lookup(ip)
    out["asn"] = {"asn": asn, "org": org,
                  "is_hosting": is_hosting, "source": asn_src}

    # ── Tor exit set ─────────────────────────────────────────────
    out["tor_exit"] = ip in _tor_exits

    # ── AbuseIPDB ────────────────────────────────────────────────
    ab_score, ab_country, ab_src = await _abuseipdb_lookup(ip)
    out["abuseipdb"] = {"score": ab_score, "country": ab_country,
                        "source": ab_src,
                        "url": (f"https://www.abuseipdb.com/check/{ip}"
                                if ab_src not in ("disabled", "private",
                                                   "invalid") else None)}

    # ── CrowdSec ─────────────────────────────────────────────────
    cs_decision, cs_src = await _crowdsec_check(ip)
    out["crowdsec"] = {"decision": cs_decision, "source": cs_src}

    # ── Internal: bans + recent activity + risk ──────────────────
    n = _t.time()
    banned_until = None; ban_reason = None
    requests_24h = 0; allowed_24h = 0; blocked_24h = 0
    first_seen_ts = None; last_seen_ts = None
    last_path = None
    blocks_by_reason: dict = {}
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        b = conn.execute(
            "SELECT banned_until, reason FROM bans WHERE ip = ?",
            (ip,)).fetchone()
        if b and (b["banned_until"] or 0) > n:
            banned_until = b["banned_until"]
            ban_reason   = b["reason"]
        # Activity from clients table (column names: first_seen / last_seen).
        c = conn.execute(
            "SELECT allowed_count, blocked_count, "
            "       first_seen, last_seen, "
            "       last_path, blocks_by_reason "
            "FROM clients WHERE ip = ? "
            "ORDER BY last_seen DESC LIMIT 1",
            (ip,)).fetchone()
        if c:
            allowed_24h   = int(c["allowed_count"] or 0)
            blocked_24h   = int(c["blocked_count"] or 0)
            requests_24h  = allowed_24h + blocked_24h
            first_seen_ts = c["first_seen"]
            last_seen_ts  = c["last_seen"]
            last_path     = c["last_path"]
            try:
                blocks_by_reason = json.loads(c["blocks_by_reason"] or "{}")
            except (ValueError, TypeError):
                blocks_by_reason = {}
        conn.close()
    except Exception as _e:
        slog("ip_intel_internal_failed", level="warn", err=str(_e)[:200])

    # Risk score lives in-memory on `ip_state` keyed by track_key. Scan
    # for entries whose `last_ip` matches and take the maximum — multiple
    # identities can share an IP (NAT, shared device).
    risk_score = 0
    try:
        for s in ip_state.values():
            if getattr(s, "last_ip", "") == ip:
                rs = int(s.risk_score or 0)
                if rs > risk_score:
                    risk_score = rs
    except Exception:
        pass

    out["internal"] = {
        "banned": bool(banned_until),
        "banned_until_ts": banned_until,
        "banned_remaining_secs": (int(banned_until - n)
                                   if banned_until else None),
        "ban_reason": ban_reason,
        "risk_score": risk_score,
        "first_seen_ts": first_seen_ts,
        "last_seen_ts":  last_seen_ts,
        "requests_24h":  requests_24h,
        "allowed_24h":   allowed_24h,
        "blocked_24h":   blocked_24h,
        "last_path":     last_path,
        "blocks_by_reason": blocks_by_reason,
    }

    # ── Risk verdict — single human-readable label combining all signals.
    # Mirrors the kind of summary scamalytics.com prints on top of the page.
    flags: list[str] = []
    if banned_until:                flags.append("banned")
    if cs_decision:                 flags.append(f"crowdsec:{cs_decision}")
    if ab_score >= 75:              flags.append("abuse-high")
    elif ab_score >= 25:            flags.append("abuse-med")
    if out["tor_exit"]:             flags.append("tor-exit")
    if is_hosting:                  flags.append("datacenter")
    if risk_score >= 100:           flags.append("risk-critical")
    elif risk_score >= 50:          flags.append("risk-high")
    elif risk_score >= 25:          flags.append("risk-med")
    if not flags:
        verdict = "clean"
    elif any(f in flags for f in
              ("banned", "abuse-high", "risk-critical")) \
         or any(f.startswith("crowdsec:") for f in flags):
        verdict = "high-risk"
    elif any(f in flags for f in
              ("abuse-med", "tor-exit", "risk-high")):
        verdict = "medium-risk"
    else:
        verdict = "low-risk"
    out["verdict"] = verdict
    out["flags"]   = flags

    return web.json_response(out, headers={"Cache-Control": "no-store"})


async def whoami_endpoint(request: web.Request):
    """GET /antibot-appsec-gateway/secured/whoami — return the calling
    operator's identity. Used by the dashboard's top-right strip."""
    username = _request_username(request)
    via = "session" if request.get("_session_user") else "admin-key"
    user_row = None
    if username and username not in ("admin-key", "unknown"):
        u = _user_load(username)
        if u:
            user_row = {
                "username": u["username"],
                "role":     u["role"],
                "status":   u["status"],
                "last_login_ts": u.get("last_login_ts"),
            }
    return web.json_response({
        "username": username, "via": via, "user": user_row,
        "ip": get_ip(request),
    }, headers={"Cache-Control": "no-store"})


# ── Users CRUD ───────────────────────────────────────────────────────
async def users_list_endpoint(request: web.Request):
    """GET <NS>/secured/admin/users — list all dashboard users (no
    password material). Each row gains `online` and `last_seen_ts` from
    the in-memory active-session map (bumped on every authenticated
    request)."""
    rows = _user_load_all()
    n = _t.time()
    for r in rows:
        ts = _ACTIVE_SESSIONS.get(r["username"], 0.0)
        r["last_seen_ts"] = ts or None
        r["online"] = bool(ts and (n - ts) < _ACTIVE_SESSION_TTL_S)
    return web.json_response(
        {"users": rows, "roles": list(_USER_ROLES),
         "statuses": list(_USER_STATUS),
         "current": _request_username(request),
         "online_ttl_secs": _ACTIVE_SESSION_TTL_S},
        headers={"Cache-Control": "no-store"})


async def users_create_endpoint(request: web.Request):
    """POST <NS>/secured/admin/users — body: {username, password, role}."""
    try:
        body = await asyncio.wait_for(request.content.read(8 * 1024),
                                       timeout=BODY_TIMEOUT)
        data = json.loads(body.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    role     = (data.get("role") or "admin").strip()
    ok, msg = _user_validate_username(username)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    if role not in _USER_ROLES:
        return web.json_response({"error": f"role must be one of {list(_USER_ROLES)}"},
                                  status=400, headers={"Cache-Control": "no-store"})
    if len(password) < 8:
        return web.json_response({"error": "password must be at least 8 chars"},
                                  status=400, headers={"Cache-Control": "no-store"})
    if _user_load(username) is not None:
        return web.json_response({"error": "username already exists"}, status=409,
                                  headers={"Cache-Control": "no-store"})
    n = _t.time()
    pw_hash = _password_hash(password)
    if db_queue is not None:
        try:
            db_queue.put_nowait((
                "user_create",
                (username, pw_hash, role, "active", n, n),
            ))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    from admin.mesh import _gw_audit  # noqa: F401
    _gw_audit("user_created", username, _request_username(request), role=role)
    return web.json_response(
        {"username": username, "role": role, "status": "active",
         "created_ts": n, "updated_ts": n},
        status=201, headers={"Cache-Control": "no-store"})


async def users_get_endpoint(request: web.Request):
    """GET <NS>/secured/admin/users/{username}"""
    username = request.match_info.get("username", "").strip().lower()
    ok, msg = _user_validate_username(username)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    u = _user_load(username)
    if not u:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    out = {k: u[k] for k in ("username", "role", "status", "created_ts",
                              "updated_ts", "last_login_ts", "last_login_ip")}
    return web.json_response(out, headers={"Cache-Control": "no-store"})


async def users_update_endpoint(request: web.Request):
    """PATCH <NS>/secured/admin/users/{username} — body may include
    `password`, `status`, `role`."""
    username = request.match_info.get("username", "").strip().lower()
    ok, msg = _user_validate_username(username)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    cur = _user_load(username)
    if cur is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    try:
        body = await asyncio.wait_for(request.content.read(8 * 1024),
                                       timeout=BODY_TIMEOUT)
        data = json.loads(body.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    fields: dict = {}
    audit_fields: dict = {}
    if "password" in data:
        pw = data.get("password") or ""
        if len(pw) < 8:
            return web.json_response({"error": "password must be at least 8 chars"},
                                      status=400, headers={"Cache-Control": "no-store"})
        fields["password_hash"] = _password_hash(pw)
        audit_fields["password_changed"] = True
    if "role" in data:
        if data["role"] not in _USER_ROLES:
            return web.json_response({"error": "invalid role"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        fields["role"] = data["role"]; audit_fields["role"] = data["role"]
    if "status" in data:
        if data["status"] not in _USER_STATUS:
            return web.json_response({"error": "invalid status"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        # Refuse to disable the LAST active admin — would lock everyone out.
        if data["status"] != "active":
            actives = [u for u in _user_load_all() if u["status"] == "active"]
            if len(actives) <= 1 and any(u["username"] == username for u in actives):
                return web.json_response(
                    {"error": "cannot disable the last active admin"},
                    status=400, headers={"Cache-Control": "no-store"})
        fields["status"] = data["status"]; audit_fields["status"] = data["status"]
    if not fields:
        return web.json_response({"error": "no updates supplied"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    fields["updated_ts"] = _t.time()
    if db_queue is not None:
        try:
            db_queue.put_nowait(("user_update", (username, fields)))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    from admin.mesh import _gw_audit  # noqa: F401
    _gw_audit("user_updated", username, _request_username(request), **audit_fields)
    return web.json_response({"username": username, "updates": list(audit_fields)},
                              headers={"Cache-Control": "no-store"})


async def user_sessions_list_endpoint(request: web.Request):
    """GET <NS>/secured/admin/users/{username}/sessions — list every
    session ever recorded for `username`. Active sessions float to the
    top; revoked / expired follow. Includes the requester's own sid so
    the FE can flag the "this is you" row."""
    username = request.match_info.get("username", "").strip().lower()
    ok, msg = _user_validate_username(username)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    if _user_load(username) is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT sid, username, ip, user_agent, created_ts, last_seen_ts, "
            "expires_ts, status, revoked_ts, revoked_by "
            "FROM user_sessions WHERE username = ? "
            "ORDER BY (status='active') DESC, created_ts DESC LIMIT 200",
            (username,)).fetchall()
        conn.close()
    except Exception as e:
        slog("user_sessions_query_failed", level="error", err=str(e)[:200])
        return web.json_response({"error": "session query failed"}, status=500,
                                  headers={"Cache-Control": "no-store"})
    n = _t.time()
    out = []
    for r in rows:
        d = dict(r)
        # Mark expired rows as such even if still recorded as active.
        if d["status"] == "active" and d.get("expires_ts", 0) < n:
            d["status"] = "expired"
        d["online"] = (
            d["status"] == "active"
            and d.get("last_seen_ts", 0) > n - _ACTIVE_SESSION_TTL_S
        )
        out.append(d)
    return web.json_response(
        {"username": username,
         "current_sid": request.get("_session_sid") or "",
         "sessions": out},
        headers={"Cache-Control": "no-store"})


async def user_session_revoke_endpoint(request: web.Request):
    """POST <NS>/secured/admin/users/{username}/sessions/{sid}/revoke"""
    username = request.match_info.get("username", "").strip().lower()
    sid      = request.match_info.get("sid", "").strip()
    ok, msg = _user_validate_username(username)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    if not _SID_RE.match(sid):
        return web.json_response({"error": "invalid sid"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    cached = _SESSION_CACHE.get(sid)
    if cached is None or cached.get("username") != username:
        return web.json_response({"error": "session not found or already revoked"},
                                  status=404, headers={"Cache-Control": "no-store"})
    actor = _request_username(request)
    self_revoke = (request.get("_session_sid") == sid)
    _session_revoke(sid, by_username=actor)
    from admin.mesh import _gw_audit  # noqa: F401
    _gw_audit("user_session_revoked", username, actor,
              sid=sid, self_revoke=self_revoke)
    return web.json_response(
        {"username": username, "sid": sid, "revoked": True,
         "self_revoke": self_revoke},
        headers={"Cache-Control": "no-store"})


async def users_delete_endpoint(request: web.Request):
    """DELETE <NS>/secured/admin/users/{username}"""
    username = request.match_info.get("username", "").strip().lower()
    ok, msg = _user_validate_username(username)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    cur = _user_load(username)
    if cur is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    # Refuse to delete the last active admin.
    actives = [u for u in _user_load_all() if u["status"] == "active"]
    if len(actives) <= 1 and any(u["username"] == username for u in actives):
        return web.json_response(
            {"error": "cannot delete the last active admin"},
            status=400, headers={"Cache-Control": "no-store"})
    # Refuse self-delete (operator must hand off first).
    if _request_username(request) == username:
        return web.json_response(
            {"error": "cannot delete your own account while signed in as it"},
            status=400, headers={"Cache-Control": "no-store"})
    if db_queue is not None:
        try:
            db_queue.put_nowait(("user_delete", (username,)))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    from admin.mesh import _gw_audit  # noqa: F401
    _gw_audit("user_deleted", username, _request_username(request))
    return web.json_response({"username": username, "deleted": True},
                              headers={"Cache-Control": "no-store"})
