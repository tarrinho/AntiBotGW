# admin/auth.py — Phase 8: admin IP allowlist + internal-auth helpers
# Extracted from proxy.py lines 167–360
import asyncio
import functools
import hashlib
import hmac
import time as _t  # noqa: F401
from collections import deque
from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from helpers import slog, get_ip, _is_admin_path  # noqa: F401
from aiohttp import web
import ipaddress as _ipaddress

_CSRF_COOKIE = "agw_csrf"

_ADMIN_RL_LOCK = asyncio.Lock()
_ADMIN_RL_BUCKETS: dict = {}


def _csrf_token_valid(request) -> bool:
    """Validate the X-CSRF-Token header against the HMAC of the session sid."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
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
    """Decorator: reject non-safe methods with missing/wrong CSRF token."""
    @functools.wraps(handler)
    async def _wrapped(request):
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if not _csrf_token_valid(request):
                return web.json_response({"error": "CSRF token invalid"}, status=403,
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
            raise SystemExit(2) from None


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
    # 1.8.6 Week 3 — Task F: idle timeout check (before touch)
    from config import SESSION_IDLE_TIMEOUT  # noqa: F401
    from admin.users import _SESSION_TTL  # noqa: F401 — _SESSION_TTL lives in users.py
    if sid and SESSION_IDLE_TIMEOUT > 0:
        cached = _SESSION_CACHE.get(sid)
        if cached:
            last_touch = cached.get("_last_touch", cached.get("expires_ts", _t.time()) - _SESSION_TTL)
            if _t.time() - last_touch > SESSION_IDLE_TIMEOUT:
                _session_revoke(sid, by_username="system")
                return False
    # 1.8.6 Week 4 — Task J: session IP binding check
    from config import BIND_SESSION_TO_IP  # noqa: F401
    if BIND_SESSION_TO_IP and sid:
        _cached_for_ip = _SESSION_CACHE.get(sid)
        if _cached_for_ip:
            stored_ip = _cached_for_ip.get("source_ip", "")
            req_ip = get_ip(request)
            if stored_ip and req_ip and stored_ip != req_ip:
                slog("session_ip_mismatch", level="warn",
                     sid=sid[:8], stored_ip=stored_ip, request_ip=req_ip)
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
    """Return the role of the session user, or 'admin' for key-only auth."""
    from admin.users import _user_load, _session_revoke  # lazy: avoid circular import
    u = request.get("_session_user") if hasattr(request, "get") else None
    if not u:
        return "admin"  # key-only (admin_key) auth — grants admin by design
    user = _user_load(u)
    if not user:
        # User deleted after session was issued; revoke defensively (AUTH4-01)
        sid = request.get("_session_sid") if hasattr(request, "get") else None
        if sid:
            _session_revoke(sid, by_username="system")
        return "viewer"  # fail-closed: deleted user must not get admin
    role = (user.get("role") or "").strip()
    return role if role in ("admin", "maintainer", "viewer") else "viewer"


def _role_denied(request, *allowed_roles: str):
    """Return a 403 response if the caller's role is not in allowed_roles,
    else return None so callers can use `if denied := _role_denied(...)`."""
    from aiohttp import web as _web
    role = _request_role(request)
    if role in allowed_roles:
        return None
    return _web.json_response(
        {"error": "forbidden", "role": role, "required": list(allowed_roles)},
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
    first boot. Idempotent."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        # Seed env entries once (source='env', upsert)
        for cidr in ADMIN_ENV_SEED:
            conn.execute(
                "INSERT OR IGNORE INTO admin_ips (cidr, added_ts, note, source, description) "
                "VALUES (?, ?, ?, 'env', ?)",
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


async def admin_ip_add(cidr: str, note: str = "", source: str = "manual",
                        description: str = "") -> tuple[bool, str]:
    """Validate + persist + reload. Returns (ok, message)."""
    cidr = (cidr or "").strip()
    note = (note or "").strip()[:200]
    description = (description or "").strip()[:500]
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
    description = (description or "").strip()[:500]
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
