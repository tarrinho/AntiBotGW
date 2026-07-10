# admin/auth.py — Phase 8: admin IP allowlist + internal-auth helpers
# Extracted from proxy.py lines 167–360
import asyncio
import functools
import hashlib
import hmac
import time as _t  # noqa: F401
from collections import deque
from config import *   # noqa: F401,F403
from db import open_conn
from state import *    # noqa: F401,F403
from helpers import slog, get_ip, _is_admin_path  # noqa: F401
from aiohttp import web
import ipaddress as _ipaddress

_CSRF_COOKIE = "agw_csrf"

_ADMIN_RL_LOCK = asyncio.Lock()
_ADMIN_RL_BUCKETS: dict = {}


def _csrf_token_valid(request, require_for_safe: bool = False) -> bool:
    """Validate the X-CSRF-Token header against the HMAC of the session sid.

    `require_for_safe=True` forces the check even on GET/HEAD/OPTIONS — used
    by sensitive read-side endpoints (e.g. settings-export with
    include_secrets=1) that would otherwise be triggerable from a tab the
    operator opened by accident."""
    if not require_for_safe and request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    from admin.users import _SESSION_COOKIE, _session_parse
    cookies = getattr(request, "cookies", None)
    cookie = cookies.get(_SESSION_COOKIE, "") if cookies else ""
    if not cookie:
        return False
    parsed = _session_parse(cookie)
    if not parsed:
        return False
    _, sid, _ = parsed
    expected = hmac.new(SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
    provided = request.headers.get("X-CSRF-Token", "")
    if not provided:
        return False
    try:
        return hmac.compare_digest(expected, provided)
    except Exception:
        return False


def _require_csrf(handler):
    """Decorator: reject non-safe methods with missing/wrong CSRF token.
    1.9.0 (F13) — response shape normalised to `{"error":"forbidden"}` to
    match `_role_denied`'s shape. The previous distinct shape leaked
    information that let an authenticated low-priv probe map which endpoints
    are role-gated vs only CSRF-gated."""
    @functools.wraps(handler)
    async def _wrapped(request):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if not _csrf_token_valid(request):
                return web.json_response({"error": "forbidden"}, status=403,
                                          headers={"Cache-Control": "no-store"})
        return await handler(request)
    return _wrapped


async def _admin_rate_limit_check(request) -> bool:
    """60 req per 10s per session. Returns False when exceeded."""
    import time as _time
    sid = request.get("_session_sid") if hasattr(request, "get") else None
    key = sid or get_ip(request)
    n = _time.time()
    cutoff = n - 10.0
    async with _ADMIN_RL_LOCK:
        bucket = _ADMIN_RL_BUCKETS.setdefault(key, deque())
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= 60:
            return False
        bucket.append(n)
        stale = [k for k, v in _ADMIN_RL_BUCKETS.items() if not v or v[-1] < n - 30]
        for k in stale:
            del _ADMIN_RL_BUCKETS[k]
    return True


async def _admin_rl_response(request) -> "web.Response | None":
    """Return 429 if rate limit exceeded, else None."""
    if not await _admin_rate_limit_check(request):
        sid = request.get("_session_sid") if hasattr(request, "get") else None
        slog("admin_rate_limit", level="warn", sid=sid, ip=get_ip(request))
        return web.json_response({"error": "rate limit exceeded"}, status=429,
                                  headers={"Cache-Control": "no-store",
                                           "Retry-After": "10"})
    return None

# ── Admin IP allowlist ─────────────────────────────────────────────────────
# Comma-separated list of source IPs / CIDRs allowed to reach /__* endpoints
# (other than /__live, which is the unauthenticated liveness probe). When
# empty, no IP restriction (admin-key auth only). When set, BOTH the IP check
# and the admin-key must pass — defence-in-depth.
_admin_ips_raw = os.environ.get("ADMIN_ALLOWED_IPS", "").strip()
ADMIN_ALLOWED_NETS: list = []          # parsed ip_network objects
ADMIN_ALLOWED_ENTRIES: list = []       # [{cidr, note, source}, …] for the UI
ADMIN_ENV_SEED: list = []              # initial env-supplied entries (read once)
if _admin_ips_raw:
    for _entry in _admin_ips_raw.split(","):
        _entry = _entry.strip()
        if not _entry:
            continue
        try:
            _net = _ipaddress.ip_network(_entry, strict=False)
            ADMIN_ALLOWED_NETS.append(_net)
            ADMIN_ENV_SEED.append(str(_net))
            ADMIN_ALLOWED_ENTRIES.append({"cidr": str(_net), "note": "env",
                                          "source": "env", "added_ts": 0})
        except ValueError as _e:
            print(f"FATAL: invalid ADMIN_ALLOWED_IPS entry {_entry!r} — {_e}",
                  flush=True)
            raise SystemExit(2) from _e


def _internal_authed(request) -> bool:
    """1.6.7 — session-cookie only. The shared-admin-key bearer
    (`X-Admin-Key` header / `?key=…`) was removed in 1.6.7; the only way
    to reach `/secured/...` is to sign in via /antibot-appsec-gateway/login
    and carry the resulting `agw_session` cookie. INTERNAL_KEY is now used
    EXCLUSIVELY as the bootstrap admin password (see `_user_bootstrap`);
    the operator should change it at first login.

    Cookies are an aiohttp-only surface; fake-request unit tests pass
    objects that only expose .headers/.query, so the access is guarded."""
    # Import here to avoid circular: admin.users defines _session_verify etc.
    from admin.users import (_SESSION_COOKIE, _session_verify, _session_parse,  # noqa: F401
                             _session_touch, _SESSION_CACHE, _session_revoke,   # noqa: F401
                             _SESSION_TTL)                                       # noqa: F401
    from state import _ACTIVE_SESSIONS  # noqa: F401
    cookies = getattr(request, "cookies", None)
    cookie = cookies.get(_SESSION_COOKIE, "") if cookies else ""
    if not cookie:
        return False
    u = _session_verify(cookie)
    if not u:
        return False
    # Pull the sid for the touch-on-activity path + the operator's
    # current-session indicator in the sessions modal.
    parsed = _session_parse(cookie)
    sid = parsed[1] if parsed else ""
    # 1.8.5 Week 3 — Task F: idle timeout check (before touch)
    from config import SESSION_IDLE_TIMEOUT  # noqa: F401
    from admin.users import _SESSION_TTL  # noqa: F401 — _SESSION_TTL lives in users.py
    if sid and SESSION_IDLE_TIMEOUT > 0:
        cached = _SESSION_CACHE.get(sid)
        if cached:
            last_touch = cached.get("_last_touch", cached.get("expires_ts", _t.time()) - _SESSION_TTL)
            if _t.time() - last_touch > SESSION_IDLE_TIMEOUT:
                _session_revoke(sid, by_username="system")
                return False
    try:
        request["_session_user"] = u
        request["_session_sid"]  = sid
    except (TypeError, AttributeError): pass  # nosec B110 — fake request objects in unit tests do not support item assignment
    # Bump the in-memory last-seen marker so the Users list can show
    # an online indicator without persisting per-request writes.
    try: _ACTIVE_SESSIONS[u] = _t.time()
    except (TypeError, KeyError): pass  # nosec B110 — defensive guard on shared dict; not on the request path
    if sid:
        _session_touch(sid)
    return True


def _request_username(request) -> str:
    """Identify the operator behind a call: returns the session-cookie
    username if signed in, else 'unknown'."""
    u = request.get("_session_user") if hasattr(request, "get") else None
    return u or "unknown"


def _request_role(request) -> str:
    """Return the role of the session user, or 'admin' for key-only auth.

    A session referencing a username that no longer exists (deleted, purged
    by mirror-repair, race between DELETE and outstanding request) returns
    ``"none"`` — an empty string would be truthy-checked as invalid input
    downstream; ``"none"`` never matches any allowed_roles tuple so every
    role-gated endpoint denies. Do NOT return "admin" here (fail-open)."""
    from admin.users import _user_load  # lazy: avoid circular import at module load
    u = request.get("_session_user") if hasattr(request, "get") else None
    if not u:
        return "admin"  # key-only auth path; session guard already verified admin_key
    user = _user_load(u)
    if user is None:
        return "none"  # session valid, user row gone → deny (fail-closed)
    return user.get("role") or "none"


def _role_denied(request, *allowed_roles: str):
    """Return a 403 response if the caller's role is not in allowed_roles,
    else return None so callers can use `if denied := _role_denied(...)`.

    1.9.0 (F13) — response shape simplified to `{"error":"forbidden"}` (no
    `role` / `required` echo). The previous shape leaked which endpoints
    are role-gated vs only CSRF-gated to authenticated low-priv probes
    (reconnaissance). The caller's role is still logged via slog for
    operator forensics."""
    from aiohttp import web as _web
    role = _request_role(request)
    if role in allowed_roles:
        return None
    try:
        slog("role_denied", level="info", role=role or "",
             required=",".join(allowed_roles), path=request.path)
    except Exception:
        pass  # nosec B110 — slog never raises a request, defensive
    return _web.json_response(
        {"error": "forbidden"},
        status=403, headers={"Cache-Control": "no-store"})


def _admin_ip_allowed(request) -> bool:
    """Allowed iff source IP matches one of the configured networks. Returns
    True when no allowlist is configured (open by default — admin key still
    required). Uses get_ip() so TRUST_XFF=last works behind a trusted proxy."""
    if not ADMIN_ALLOWED_NETS:
        return True
    try:
        ip = _ipaddress.ip_address(get_ip(request))
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in ADMIN_ALLOWED_NETS)


def _is_admin_ip(ip_str: str) -> bool:
    """True when ip_str is in ADMIN_ALLOWED_NETS (empty list → False)."""
    if not ADMIN_ALLOWED_NETS or not ip_str:
        return False
    try:
        ip = _ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in ADMIN_ALLOWED_NETS)


def _rebuild_admin_nets_from_entries():
    """Re-parse ADMIN_ALLOWED_ENTRIES → ADMIN_ALLOWED_NETS. Hot-reload safe."""
    nets = []
    for e in ADMIN_ALLOWED_ENTRIES:
        try:
            nets.append(_ipaddress.ip_network(e["cidr"], strict=False))
        except ValueError:
            continue
    ADMIN_ALLOWED_NETS[:] = nets  # in-place: preserves shared reference across modules


def db_load_admin_ips():
    """Merge DB-stored admin IPs into in-memory state, seeding env entries on
    first boot. Idempotent.

    1.9.1 fix (LIVE-1/6): `INSERT OR IGNORE` is SQLite-only and was
    silently failing under PG-only mode, so env-seeded admin CIDRs were
    never persisted into PG. We now branch the seed DML by backend so the
    env entries round-trip through whichever DB is active."""
    try:
        from db import active_backend as _active
        _be = _active()
    except Exception:
        _be = "sqlite"
    try:
        conn = open_conn()
        # Cross-backend: SQLite uses sqlite3.Row natively; the PG wrapper
        # detects this and switches its cursor to psycopg.dict_row so
        # `r["cidr"]` keeps working without touching the read-side code.
        conn.row_factory = sqlite3.Row
        # Seed env entries once (source='env', upsert).
        # Both branches use `?` placeholders so the PG conn wrapper's
        # rewriter swaps them to `%s` correctly. Hand-rolling `%s` here
        # would trip the wrapper's bare-`%` escape and leave the query
        # with zero placeholders ("0 placeholders but 4 parameters").
        if _be == "postgres":
            _seed_sql = (
                "INSERT INTO admin_ips (cidr, added_ts, note, source, description) "
                "VALUES (?, ?, ?, 'env', ?) ON CONFLICT (cidr) DO NOTHING")
        else:
            _seed_sql = (
                "INSERT OR IGNORE INTO admin_ips (cidr, added_ts, note, source, description) "
                "VALUES (?, ?, ?, 'env', ?)")
        for cidr in ADMIN_ENV_SEED:
            conn.execute(
                _seed_sql,
                (cidr, _t.time(), "from ADMIN_ALLOWED_IPS env",
                 "Seeded from ADMIN_ALLOWED_IPS environment variable"))
        conn.commit()
        rows = conn.execute(
            "SELECT cidr, added_ts, note, source, description FROM admin_ips ORDER BY added_ts"
        ).fetchall()
        conn.close()
        ADMIN_ALLOWED_ENTRIES[:] = [
            {"cidr": r["cidr"], "added_ts": r["added_ts"] or 0,
             "note": r["note"] or "", "source": r["source"] or "manual",
             "description": (r["description"] if "description" in r.keys() else "") or ""}
            for r in rows
        ]
        _rebuild_admin_nets_from_entries()
    except Exception as e:
        print(f"[admin_ips] load error: {e}", flush=True)


def _strip_html_brackets(s: str) -> str:
    """1.9.1 fix (LIVE-7): server-side defence-in-depth — neutralise raw
    angle-brackets in operator-supplied free-text fields (note/description)
    so that any future dashboard innerHTML regression cannot escalate to
    stored XSS. Dashboards already render via textContent in covered sinks;
    this guard keeps the DB itself clean."""
    if not s:
        return s
    return s.replace("<", "").replace(">", "")


async def admin_ip_add(cidr: str, note: str = "", source: str = "manual",
                        description: str = "") -> tuple[bool, str]:
    """Validate + persist + reload. Returns (ok, message)."""
    cidr = (cidr or "").strip()
    note = _strip_html_brackets((note or "").strip()[:200])
    description = _strip_html_brackets((description or "").strip()[:500])
    if not cidr:
        return False, "empty cidr"
    try:
        net = _ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return False, f"invalid cidr: {e}"
    canon = str(net)
    if any(e["cidr"] == canon for e in ADMIN_ALLOWED_ENTRIES):
        return False, "already exists"
    if db_queue is not None:
        try:
            db_queue.put_nowait(("admin_ip_add",
                (canon, _t.time(), note, source, description)))
        except asyncio.QueueFull:
            return False, "queue full"
    ADMIN_ALLOWED_ENTRIES.append({"cidr": canon, "added_ts": _t.time(),
                                  "note": note, "source": source,
                                  "description": description})
    _rebuild_admin_nets_from_entries()
    return True, "added"


async def admin_ip_update_description(cidr: str, description: str) -> tuple[bool, str]:
    """Update the description of an existing entry in-place. Returns (ok, msg)."""
    cidr = (cidr or "").strip()
    description = _strip_html_brackets((description or "").strip()[:500])
    try:
        canon = str(_ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        return False, "invalid cidr"
    found = None
    for e in ADMIN_ALLOWED_ENTRIES:
        if e["cidr"] == canon:
            found = e
            break
    if found is None:
        return False, "not present"
    if db_queue is not None:
        try:
            db_queue.put_nowait(("admin_ip_update_description", (description, canon)))
        except asyncio.QueueFull:
            return False, "queue full"
    found["description"] = description
    return True, "updated"


async def admin_ip_remove(cidr: str) -> tuple[bool, str]:
    """Remove from DB + reload."""
    cidr = (cidr or "").strip()
    try:
        canon = str(_ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        return False, "invalid cidr"
    if not any(e["cidr"] == canon for e in ADMIN_ALLOWED_ENTRIES):
        return False, "not present"
    if db_queue is not None:
        try:
            db_queue.put_nowait(("admin_ip_remove", (canon,)))
        except asyncio.QueueFull:
            return False, "queue full"
    ADMIN_ALLOWED_ENTRIES[:] = [e for e in ADMIN_ALLOWED_ENTRIES if e["cidr"] != canon]
    _rebuild_admin_nets_from_entries()
    return True, "removed"
