# admin/users.py — Phase 8: dashboard user accounts + session management
# Extracted from proxy.py lines 11621–13155 area
import base64 as _b64  # noqa: F401
import time as _t  # noqa: F401
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR  # noqa: F401 — underscore not exported by *
from state import *    # noqa: F401,F403
from state import _ACTIVE_SESSIONS, _ACTIVE_SESSION_TTL_S  # noqa: F401 — private names not exported by *
from helpers import slog, now, get_ip  # noqa: F401
from admin.auth import _internal_authed, _request_username, _request_role, _role_denied, _require_csrf  # noqa: F401
from aiohttp import web
from reputation.maxmind import _city_lookup, _asn_lookup  # noqa: F401
from reputation.abuseipdb import _abuseipdb_lookup  # noqa: F401
from reputation.crowdsec import _crowdsec_check  # noqa: F401
from reputation.tor import _tor_exits  # noqa: F401

# FE4-07: compile once; matches only paths within the gateway namespace
_NEXT_URL_RE = re.compile(r"^/[A-Za-z0-9/._~:@!$&'()*+,;=%-]+$")


def _next_url_safe(url: str) -> bool:
    """True when url is a safe same-origin relative path within the gateway namespace."""
    if not url:
        return False
    if not url.startswith(ADMIN_NS + "/") and url != ADMIN_NS:
        return False
    if url.startswith("//"):
        return False
    return bool(_NEXT_URL_RE.match(url))


# ── 1.8.6 Week 3 — Task D: Password complexity ───────────────────────────────
_BREACHED_PASSWORDS = frozenset({
    "password", "password1", "admin", "admin123", "123456",
    "qwerty", "letmein", "welcome", "monkey", "dragon",
    "iloveyou", "sunshine", "princess", "football", "shadow",
    "master", "superman", "batman", "trustno1", "pass123",
})


def _validate_password_strength(password: str) -> "str | None":
    """Returns error message or None if OK."""
    if len(password) < 12:
        return "Minimum 12 characters required"
    if not re.search(r'[A-Z]', password):
        return "Must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return "Must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return "Must contain at least one digit"
    if not re.search(r'[^A-Za-z0-9]', password):
        return "Must contain at least one special character"
    if password.lower() in _BREACHED_PASSWORDS:
        return "Password is too common"
    return None


# ── 1.6.7: dashboard user accounts ──────────────────────────────────
_USERNAME_RE  = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
_USER_ROLES   = ("admin", "maintainer", "viewer")
_USER_STATUS  = ("active", "disabled", "pending")
_SESSION_COOKIE = "agw_session"
_SESSION_TTL  = 12 * 3600              # 12h sliding session
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**17, 8, 1   # OWASP recommended; ~500 ms on a single core
_LOGIN_BUCKET: dict = {}               # ip → (window_start, count)
_LOGIN_BUCKET_LOCK = asyncio.Lock()

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
                        maxmem=256 * 1024 * 1024)
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
                               maxmem=256 * 1024 * 1024)
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
            "SELECT sid, username, expires_ts, status, ip, last_seen_ts "
            "FROM user_sessions "
            "WHERE status = 'active' AND expires_ts > ?",
            (_t.time(),)).fetchall()
        conn.close()
    except Exception as e:
        slog("session_cache_load_failed", level="error", err=str(e)[:200])
        _SESSION_CACHE_READY = True
        return
    fresh = {}
    for r in rows:
        # 1.8.11: restore source_ip + last-seen so BIND_SESSION_TO_IP and the
        # idle-timeout keep enforcing after a restart. Previously these were
        # dropped on reload, silently disabling IP-binding for every live
        # session post-restart (common in container redeploys).
        fresh[r["sid"]] = {
            "username":    r["username"],
            "expires_ts":  float(r["expires_ts"] or 0),
            "revoked":     False,
            "source_ip":   r["ip"] or "",
            "_last_touch": float(r["last_seen_ts"] or 0),
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
        "source_ip": ip or "",
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


def _enforce_session_limit(username: str) -> None:
    """Revoke oldest active sessions beyond MAX_ADMIN_SESSIONS."""
    import config as _cfg
    max_sess = _cfg.MAX_ADMIN_SESSIONS
    n = _t.time()
    active = [
        (sid, info) for sid, info in _SESSION_CACHE.items()
        if info.get("username") == username
        and not info.get("revoked")
        and info.get("expires_ts", 0) > n
    ]
    # Sort by expiry ascending (oldest first)
    active.sort(key=lambda x: x[1].get("expires_ts", 0))
    if len(active) >= max_sess:
        to_revoke = active[:len(active) - max_sess + 1]
        for sid, _ in to_revoke:
            _session_revoke(sid, by_username="system")


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
            "last_login_ts, last_login_ip, sso_source, oidc_sub FROM users ORDER BY username"
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
        # H5: evict expired windows to prevent unbounded growth from unique attacker IPs.
        _expired = [_ip for _ip, (_w, _) in _LOGIN_BUCKET.items() if n - _w > 60]
        for _ip in _expired:
            del _LOGIN_BUCKET[_ip]
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
        next_url = request.query.get("next") or "/antibot-appsec-gateway/secured/control-center"
        # FE4-07: only allow paths within the gateway namespace to prevent open redirects
        if not _next_url_safe(next_url):
            next_url = "/antibot-appsec-gateway/secured/control-center"
        return web.HTTPFound(next_url)
    from admin.oidc import oidc_button_html, _ERROR_CODES
    import html as _html
    oidc_error_code = request.query.get("oidc_error", "").strip()
    oidc_error_html = ""
    if oidc_error_code:
        # AUTH4-13: resolve opaque code to safe message — never reflect raw URL value
        safe_msg = _html.escape(_ERROR_CODES.get(oidc_error_code,
                                                  _ERROR_CODES["err_generic"]))
        oidc_error_html = (  # nosemgrep: python.django.security.injection.raw-html-format.raw-html-format — safe_msg is from static _ERROR_CODES dict, already html.escape()'d
            f'<div id="err" class="err show">SSO: {safe_msg}</div>')
    body = ((_DASHBOARDS_DIR / "login.html").read_text(encoding="utf-8")
            .replace("__BOOTSTRAP_HINT__", _bootstrap_hint_html())
            .replace("__OIDC_BUTTON__", oidc_button_html())
            .replace("__OIDC_ERROR__", oidc_error_html))
    # FE4-06: strict CSP for the login page — no inline scripts (F-11)
    csp = (
        "default-src 'none'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "font-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return web.Response(
        text=body, content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": csp,
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
    next_url = params.get("next", ["/antibot-appsec-gateway/secured/control-center"])[0]
    # FE4-07: only allow paths within the gateway namespace
    if not _next_url_safe(next_url):
        next_url = "/antibot-appsec-gateway/secured/control-center"
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
    # 1.8.6 — TOTP two-factor authentication: if user has 2FA enabled (or REQUIRE_2FA),
    # issue a short-lived partial token and require the second factor before minting the session.
    import config as _cfg_totp
    if user.get("totp_enabled") or _cfg_totp.REQUIRE_2FA:
        from state import _TOTP_PENDING
        _totp_window = int(_t.time() // 300)
        partial_token = hmac.new(
            SESSION_KEY,
            (username + "|" + str(_totp_window)).encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        # Store pending state so totp_verify_endpoint can locate the user
        _TOTP_PENDING[username] = {"step": "totp_required", "ts": _t.time()}
        slog("login_totp_required", level="warn", username=username, ip=ip)
        return web.json_response(
            {"step": "totp_required", "partial_token": partial_token},
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
    # 1.8.6 Week 3 — Task E: concurrent session limit
    _enforce_session_limit(username)
    token = _session_create(username, ip, ua)
    sid = token.split("|")[1]
    csrf_token = hmac.new(SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
    resp = web.json_response({"ok": True, "redirect": next_url, "username": username},
                              headers={"Cache-Control": "no-store"})
    resp.set_cookie(_SESSION_COOKIE, token,
                     max_age=_SESSION_TTL, httponly=True,
                     samesite="Strict", path="/",
                     secure=SESSION_SECURE)
    resp.set_cookie("agw_csrf", csrf_token,
                     max_age=_SESSION_TTL, httponly=False,
                     samesite="Strict", path=ADMIN_NS,  # 1.8.11 (M1): keep off upstream surface
                     secure=SESSION_SECURE)
    return resp


async def logout_endpoint(request: web.Request):
    """POST /antibot-appsec-gateway/logout — revoke the current session
    server-side AND clear the cookie. Revoking on the server makes the
    cookie unusable even if it leaks; the operator's other sessions on
    the same account stay live. POST prevents CSRF logout via GET link.
    No CSRF token required: logout-CSRF is low risk (no data exfiltration)
    and the endpoint is protected by the session cookie itself."""
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
    # Clear agw_csrf too — otherwise it lingers and, after a re-login that
    # mints a new sid, the stale token mismatches and every POST fails with
    # "CSRF token invalid". (The session_cookie_finalizer self-heal also
    # re-issues it, but clearing on logout keeps the cookie jar clean.)
    resp.del_cookie("agw_csrf", path=ADMIN_NS)  # 1.8.11 (M1): match the scoped set-path
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
    risk_breakdown: list = []
    try:
        for s in ip_state.values():
            if getattr(s, "last_ip", "") == ip:
                rs = int(s.risk_score or 0)
                if rs > risk_score:
                    risk_score = rs
                    risk_breakdown = sorted(
                        ((r, round(v, 1)) for r, v in s.risk_by_reason.items() if v >= 0.5),
                        key=lambda x: x[1], reverse=True,
                    )
    except Exception:
        pass

    out["internal"] = {
        "banned": bool(banned_until),
        "banned_until_ts": banned_until,
        "banned_remaining_secs": (int(banned_until - n)
                                   if banned_until else None),
        "ban_reason": ban_reason,
        "risk_score": risk_score,
        "risk_breakdown": risk_breakdown,
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
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
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


@_require_csrf
async def users_create_endpoint(request: web.Request):
    """POST <NS>/secured/admin/users — body: {username, password, role}."""
    if denied := _role_denied(request, "admin"):
        return denied
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
    pw_err = _validate_password_strength(password)
    if pw_err:
        return web.json_response({"error": pw_err}, status=400,
                                  headers={"Cache-Control": "no-store"})
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
    caller_role = _request_role(request)
    if caller_role not in ("admin", "maintainer") and _request_username(request) != username:
        return web.json_response({"error": "forbidden"}, status=403,
                                  headers={"Cache-Control": "no-store"})
    u = _user_load(username)
    if not u:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    out = {k: u[k] for k in ("username", "role", "status", "created_ts",
                              "updated_ts", "last_login_ts", "last_login_ip")}
    return web.json_response(out, headers={"Cache-Control": "no-store"})


@_require_csrf
async def users_update_endpoint(request: web.Request):
    """PATCH <NS>/secured/admin/users/{username} — body may include
    `password`, `status`, `role`. Viewers may only change their own password."""
    username = request.match_info.get("username", "").strip().lower()
    ok, msg = _user_validate_username(username)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    caller = _request_username(request)
    caller_role = _request_role(request)
    is_self = (caller == username)
    # Viewers: only own-password change allowed.
    if caller_role == "viewer":
        if not is_self:
            return web.json_response({"error": "forbidden"}, status=403,
                                      headers={"Cache-Control": "no-store"})
    # Non-self updates require admin or maintainer.
    elif not is_self:
        if denied := _role_denied(request, "admin", "maintainer"):
            return denied
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
        pw_err = _validate_password_strength(pw)
        if pw_err:
            return web.json_response({"error": pw_err}, status=400,
                                      headers={"Cache-Control": "no-store"})
        if is_self:
            cur_pw = data.get("current_password") or ""
            if not cur_pw:
                return web.json_response({"error": "current_password required"},
                                          status=400, headers={"Cache-Control": "no-store"})
            if not _password_verify(cur_pw, cur.get("password_hash", "")):
                return web.json_response({"error": "current password is incorrect"},
                                          status=403, headers={"Cache-Control": "no-store"})
        fields["password_hash"] = _password_hash(pw)
        audit_fields["password_changed"] = True
    if "role" in data:
        if caller_role == "viewer":
            return web.json_response({"error": "forbidden: viewers cannot change roles"},
                                      status=403, headers={"Cache-Control": "no-store"})
        if data["role"] not in _USER_ROLES:
            return web.json_response({"error": "invalid role"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        fields["role"] = data["role"]; audit_fields["role"] = data["role"]
    if "status" in data:
        if caller_role == "viewer":
            return web.json_response({"error": "forbidden: viewers cannot change status"},
                                      status=403, headers={"Cache-Control": "no-store"})
        if data["status"] not in _USER_STATUS:
            return web.json_response({"error": "invalid status"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        # Refuse to disable the LAST active admin — would lock everyone out.
        if data["status"] != "active":
            active_admins = [u for u in _user_load_all()
                             if u["status"] == "active" and u.get("role") == "admin"]
            if len(active_admins) <= 1 and any(u["username"] == username for u in active_admins):
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
    caller_role = _request_role(request)
    if caller_role not in ("admin", "maintainer") and _request_username(request) != username:
        return web.json_response({"error": "forbidden"}, status=403,
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


@_require_csrf
async def user_session_revoke_endpoint(request: web.Request):
    """POST <NS>/secured/admin/users/{username}/sessions/{sid}/revoke"""
    username = request.match_info.get("username", "").strip().lower()
    sid      = request.match_info.get("sid", "").strip()
    ok, msg = _user_validate_username(username)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    caller_role = _request_role(request)
    if caller_role not in ("admin", "maintainer") and _request_username(request) != username:
        return web.json_response({"error": "forbidden"}, status=403,
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


# ── 1.8.6 — TOTP Two-Factor Authentication ──────────────────────────────────


def _totp_generate_secret() -> str:
    import pyotp
    return pyotp.random_base32()


def _totp_verify(secret: str, code: str) -> bool:
    import pyotp
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:
        return False


def _totp_provisioning_uri(secret: str, username: str) -> str:
    import pyotp
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="AppSecGW")


def _generate_backup_codes() -> list:  # F-08: 10 bytes = 80 bits per code
    import secrets as _sec
    return [_sec.token_hex(10).upper() for _ in range(8)]


async def totp_verify_endpoint(request: web.Request):
    """POST /antibot-appsec-gateway/login/totp — verify TOTP code after partial auth.
    Body: {partial_token, code} (JSON)."""
    ip = get_ip(request)
    if not await _login_rate_limit(ip):
        return web.json_response({"error": "too many attempts; wait 60s"},
                                  status=429,
                                  headers={"Cache-Control": "no-store",
                                           "Retry-After": "60"})
    try:
        body_bytes = await asyncio.wait_for(request.content.read(4 * 1024), timeout=BODY_TIMEOUT)
        data = json.loads(body_bytes.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    partial_token = (data.get("partial_token") or "").strip()
    code = (data.get("code") or "").strip()
    if not partial_token or not code:
        return web.json_response({"error": "partial_token and code required"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    # Reconstruct the expected partial token for current and previous 5-min windows
    # The partial_token was derived from: HMAC(username + "|" + window)[:16]
    # We need to recover username from the token — it's stored in _TOTP_PENDING
    from state import _TOTP_PENDING
    # Find which user this partial token belongs to
    matched_username = None
    _now_window = int(_t.time() // 300)
    for _uname, _pending in list(_TOTP_PENDING.items()):
        if _pending.get("step") != "totp_required":
            continue
        for _window in (_now_window, _now_window - 1):
            _expected = hmac.new(
                SESSION_KEY,
                (_uname + "|" + str(_window)).encode(),
                hashlib.sha256
            ).hexdigest()[:16]
            if hmac.compare_digest(partial_token, _expected):
                matched_username = _uname
                break
        if matched_username:
            break
    if not matched_username:
        slog("totp_verify_invalid_token", level="warn", ip=ip)
        return web.json_response({"error": "invalid or expired token"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    user = _user_load(matched_username)
    if user is None or user.get("status") != "active":
        return web.json_response({"error": "invalid credentials"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    totp_secret = user.get("totp_secret") or ""
    # Check TOTP code
    totp_ok = totp_secret and _totp_verify(totp_secret, code)
    # Check backup codes
    backup_ok = False
    if not totp_ok:
        backup_raw = user.get("totp_backup_codes") or "[]"
        try:
            backup_codes = json.loads(backup_raw)
        except (ValueError, TypeError):
            backup_codes = []
        code_upper = code.upper()
        # INT4-08: constant-time comparison for backup codes — iterate all, no early exit
        backup_ok = any(hmac.compare_digest(_bc, code_upper) for _bc in backup_codes)
        if backup_ok:
            backup_codes = [_bc for _bc in backup_codes
                            if not hmac.compare_digest(_bc, code_upper)]
            # Persist updated backup codes
            if db_queue is not None:
                try:
                    db_queue.put_nowait(("user_update", (matched_username, {
                        "totp_backup_codes": json.dumps(backup_codes),
                        "updated_ts": _t.time(),
                    })))
                except asyncio.QueueFull:
                    pass
    if not (totp_ok or backup_ok):
        slog("totp_verify_failed", level="warn", username=matched_username, ip=ip)
        return web.json_response({"error": "invalid code"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    # Clear pending state
    _TOTP_PENDING.pop(matched_username, None)
    # Create full session
    slog("totp_verify_success", level="warn", username=matched_username, ip=ip,
         via="backup" if backup_ok else "totp")
    _ACTIVE_SESSIONS[matched_username] = _t.time()
    ua = (request.headers.get("User-Agent") or "")[:512]
    _enforce_session_limit(matched_username)
    token = _session_create(matched_username, ip, ua)
    sid = token.split("|")[1]
    csrf_token = hmac.new(SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
    resp = web.json_response({"ok": True, "username": matched_username},
                              headers={"Cache-Control": "no-store"})
    resp.set_cookie(_SESSION_COOKIE, token,
                     max_age=_SESSION_TTL, httponly=True,
                     samesite="Strict", path="/",
                     secure=SESSION_SECURE)
    resp.set_cookie("agw_csrf", csrf_token,
                     max_age=_SESSION_TTL, httponly=False,
                     samesite="Strict", path=ADMIN_NS,  # 1.8.11 (M1): keep off upstream surface
                     secure=SESSION_SECURE)
    return resp


async def totp_setup_endpoint(request: web.Request):
    """GET /antibot-appsec-gateway/secured/2fa-setup — generate a new TOTP secret.
    Stores it temporarily in _TOTP_PENDING[username] and returns the provisioning URI."""
    if not _internal_authed(request):
        return web.json_response({"error": "auth"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    username = _request_username(request)
    if not username or username in ("admin-key", "unknown"):
        return web.json_response({"error": "session required for 2FA setup"}, status=403,
                                  headers={"Cache-Control": "no-store"})
    from state import _TOTP_PENDING
    import io as _io
    import qrcode as _qrcode
    import qrcode.image.svg as _qrsvg
    secret = _totp_generate_secret()
    _TOTP_PENDING[username] = {"secret": secret, "ts": _t.time()}
    uri = _totp_provisioning_uri(secret, username)
    qr_obj = _qrcode.QRCode(error_correction=_qrcode.constants.ERROR_CORRECT_M)
    qr_obj.add_data(uri)
    qr_obj.make(fit=True)
    img = qr_obj.make_image(image_factory=_qrsvg.SvgImage)
    buf = _io.BytesIO()
    img.save(buf)
    # Inject white background rect so the QR is scannable on dark UIs.
    # SvgImage emits no background; insert a white rect after the opening
    # <svg …> tag (skip the <?xml …?> declaration to find the right '>').
    svg_str = buf.getvalue().decode()
    svg_open_end = svg_str.index('>', svg_str.index('<svg')) + 1
    svg_str = (svg_str[:svg_open_end]
               + '<rect width="100%" height="100%" fill="white"/>'
               + svg_str[svg_open_end:])
    qr_data_url = "data:image/svg+xml;base64," + _b64.b64encode(svg_str.encode()).decode()
    return web.json_response({"provisioning_uri": uri, "qr_data_url": qr_data_url},
                              headers={"Cache-Control": "no-store"})


@_require_csrf
async def totp_confirm_endpoint(request: web.Request):
    """POST /antibot-appsec-gateway/secured/2fa-confirm — verify code and enable TOTP.
    Body: {code}."""
    if not _internal_authed(request):
        return web.json_response({"error": "auth"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    username = _request_username(request)
    if not username or username in ("admin-key", "unknown"):
        return web.json_response({"error": "session required for 2FA confirm"}, status=403,
                                  headers={"Cache-Control": "no-store"})
    from state import _TOTP_PENDING
    pending = _TOTP_PENDING.get(username)
    if not pending or _t.time() - pending.get("ts", 0) > 600:
        return web.json_response({"error": "no pending TOTP setup — call 2fa-setup first"},
                                  status=400, headers={"Cache-Control": "no-store"})
    try:
        body_bytes = await asyncio.wait_for(request.content.read(4 * 1024), timeout=BODY_TIMEOUT)
        data = json.loads(body_bytes.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    code = (data.get("code") or "").strip()
    secret = pending["secret"]
    if not _totp_verify(secret, code):
        return web.json_response({"error": "invalid code"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    backup_codes = _generate_backup_codes()
    fields = {
        "totp_secret": secret,
        "totp_enabled": 1,
        "totp_backup_codes": json.dumps(backup_codes),
        "updated_ts": _t.time(),
    }
    queued = False
    if db_queue is not None:
        try:
            db_queue.put_nowait(("user_update", (username, fields)))
            queued = True
        except asyncio.QueueFull:
            pass
    if not queued:
        # Queue full or absent — write synchronously so 2FA enable always persists.
        try:
            _cols   = ", ".join(f"{k}=?" for k in fields)
            _params = list(fields.values()) + [username]
            _conn = sqlite3.connect(DB_PATH)
            _conn.execute(f"UPDATE users SET {_cols} WHERE username=?",  # nosec B608
                          _params)
            _conn.commit()
            _conn.close()
        except Exception as _e:
            slog("totp_confirm_sync_write_failed", level="error",
                 username=username, err=str(_e)[:200])
            return web.json_response({"error": "db write failed"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    _TOTP_PENDING.pop(username, None)
    slog("totp_enabled", level="warn", username=username, ip=get_ip(request))
    return web.json_response({"ok": True, "backup_codes": backup_codes},
                              headers={"Cache-Control": "no-store"})


@_require_csrf
async def totp_disable_endpoint(request: web.Request):
    """POST /antibot-appsec-gateway/secured/2fa-disable — disable TOTP.
    Body: {code} — current TOTP code or backup code required."""
    if not _internal_authed(request):
        return web.json_response({"error": "auth"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    username = _request_username(request)
    if not username or username in ("admin-key", "unknown"):
        return web.json_response({"error": "session required"}, status=403,
                                  headers={"Cache-Control": "no-store"})
    try:
        body_bytes = await asyncio.wait_for(request.content.read(4 * 1024), timeout=BODY_TIMEOUT)
        data = json.loads(body_bytes.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    code = (data.get("code") or "").strip()
    user = _user_load(username)
    if not user:
        return web.json_response({"error": "user not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    if not user.get("totp_enabled"):
        return web.json_response({"error": "2FA is not enabled"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    totp_secret = user.get("totp_secret") or ""
    totp_ok = totp_secret and _totp_verify(totp_secret, code)
    backup_ok = False
    if not totp_ok:
        backup_raw = user.get("totp_backup_codes") or "[]"
        try:
            backup_codes = json.loads(backup_raw)
        except (ValueError, TypeError):
            backup_codes = []
        if code.upper() in backup_codes:
            backup_ok = True
    if not (totp_ok or backup_ok):
        return web.json_response({"error": "invalid code"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    fields = {
        "totp_secret": None,
        "totp_enabled": 0,
        "totp_backup_codes": None,
        "updated_ts": _t.time(),
    }
    queued = False
    if db_queue is not None:
        try:
            db_queue.put_nowait(("user_update", (username, fields)))
            queued = True
        except asyncio.QueueFull:
            pass
    if not queued:
        # Queue full or absent — write synchronously so disable always succeeds.
        try:
            _cols   = ", ".join(f"{k}=?" for k in fields)
            _params = list(fields.values()) + [username]
            _conn = sqlite3.connect(DB_PATH)
            _conn.execute(f"UPDATE users SET {_cols} WHERE username=?",  # nosec B608
                          _params)
            _conn.commit()
            _conn.close()
        except Exception as _e:
            slog("totp_disable_sync_write_failed", level="error",
                 username=username, err=str(_e)[:200])
            return web.json_response({"error": "db write failed"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    slog("totp_disabled", level="warn", username=username, ip=get_ip(request))
    return web.json_response({"ok": True}, headers={"Cache-Control": "no-store"})


async def totp_status_endpoint(request: web.Request):
    """GET /antibot-appsec-gateway/secured/2fa-status — return current 2FA state."""
    if not _internal_authed(request):
        return web.json_response({"error": "auth"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    username = _request_username(request)
    if not username or username in ("admin-key", "unknown"):
        return web.json_response({"enabled": False}, headers={"Cache-Control": "no-store"})
    # Never let a users-table read fault 500 this endpoint: the Settings 2FA
    # card calls it on every page load and an HTML 500 page would surface as a
    # cryptic "error" badge. Degrade to enabled:false and log instead.
    try:
        user = _user_load(username)
        enabled = bool(user and user.get("totp_enabled"))
    except Exception as _e:  # noqa: BLE001 — defensive: DB/backend hiccup must not crash the card
        slog("totp_status_load_failed", level="warn", username=username,
             ip=get_ip(request), error=str(_e))
        enabled = False
    return web.json_response({"enabled": enabled}, headers={"Cache-Control": "no-store"})


@_require_csrf
async def users_delete_endpoint(request: web.Request):
    """DELETE <NS>/secured/admin/users/{username}"""
    if denied := _role_denied(request, "admin"):
        return denied
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
    active_admins = [u for u in _user_load_all()
                     if u["status"] == "active" and u.get("role") == "admin"]
    if len(active_admins) <= 1 and any(u["username"] == username for u in active_admins):
        return web.json_response(
            {"error": "cannot delete the last active admin"},
            status=400, headers={"Cache-Control": "no-store"})
    # Refuse self-delete (operator must hand off first).
    if _request_username(request) == username:
        return web.json_response(
            {"error": "cannot delete your own account while signed in as it"},
            status=400, headers={"Cache-Control": "no-store"})
    # AUTH4-02: revoke all active sessions for the deleted user BEFORE queuing the DB delete
    import time as _del_t
    _del_now = _del_t.time()
    _active_sids = [
        sid for sid, info in _SESSION_CACHE.items()
        if info.get("username") == username
        and not info.get("revoked")
        and info.get("expires_ts", 0) > _del_now
    ]
    for _sid in _active_sids:
        _session_revoke(_sid, by_username=_request_username(request))
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
