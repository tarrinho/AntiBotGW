"""core/middleware.py — aiohttp middleware layer.

Extracted from proxy.py (Phase 9).  Contains:
  • session_cookie_finalizer  — sets session cookie on every response
  • cost_meter                — outer timing middleware for dashboard cost graph
"""

import time

from aiohttp import web

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from helpers import now, slog  # noqa: F401
from core.metrics import _cost_bump  # noqa: F401
from identity import _sign_session   # noqa: F401 — used in session_cookie_finalizer


# ── Cookie finalizer: outer middleware. Sets the session cookie on every
#    response where the inner protect() flagged a new session — ensures the
#    cookie is set on silent-decoy responses too, not just allowed ones.
@web.middleware
async def session_cookie_finalizer(request: web.Request, handler):
    response = await handler(request)
    sid    = request.get("_sid")
    is_new = request.get("_is_new")
    if sid and is_new:
        try:
            response.set_cookie(
                SESSION_COOKIE, _sign_session(sid),
                httponly=True, samesite=SESSION_SAMESITE,
                secure=SESSION_SECURE, path="/",
                max_age=SESSION_TTL_SECS,
            )
        except Exception:
            pass  # FileResponse / streaming responses may not allow cookies post-hoc
    _csrf_self_heal(request, response)
    return response


def _csrf_self_heal(request: web.Request, response) -> None:
    """Keep the dashboard's CSRF token reachable for the current admin session,
    via TWO independent channels so it survives hostile intermediaries:

      1. Re-issue the agw_csrf cookie whenever it is missing or stale.
      2. Inject `window.__AGW_CSRF__` into authenticated dashboard HTML.

    The CSRF token is HMAC(SESSION_KEY, sid)[:32] — derived from the admin
    session sid (the agw_session cookie). It is set at login but can drift out
    of sync (a logout that only cleared agw_session, an SSO login, a re-login
    where the browser kept the old value), making every state-mutating POST
    fail with "CSRF token invalid" even though the session itself is valid.

    Channel 2 exists because a CDN/proxy in front of the gateway (observed
    behind Cloudflare) can rewrite Set-Cookie to add `HttpOnly`, which
    makes agw_csrf unreadable by `document.cookie` — so the JS shim would send
    an empty token and every POST would 403. Injecting the token into the page
    as a JS global lets the shim read it regardless of what the CDN does to the
    cookie. Neither channel weakens CSRF: the value is still bound to the
    httponly session sid an attacker cannot read or forge.

    Runs on EVERY response (this middleware wraps all routes, including
    registered dashboard pages like /secured/settings).
    """
    # Lazy import: admin.users imports config/state, importing it at module
    # load time would create a cycle through this middleware module.
    try:
        from admin.users import _session_parse, _SESSION_COOKIE, _SESSION_TTL
    except Exception:
        return
    try:
        cookie = request.cookies.get(_SESSION_COOKIE, "")
    except Exception:
        return
    if not cookie:
        return
    parsed = _session_parse(cookie)
    if not parsed:
        return
    _, sid, _ = parsed
    import hmac as _hmac, hashlib as _hashlib
    want = _hmac.new(SESSION_KEY, sid.encode(), _hashlib.sha256).hexdigest()[:32]

    # ── Channel 1: re-issue the cookie when missing/stale ────────────────────
    try:
        have = request.cookies.get("agw_csrf", "")
    except Exception:
        have = ""
    if have != want:
        try:
            response.set_cookie(
                "agw_csrf", want,
                max_age=_SESSION_TTL, httponly=False,
                samesite="Strict", path="/", secure=SESSION_SECURE,
            )
        except Exception:
            pass  # streaming/FileResponse may not allow post-hoc cookies

    # ── Channel 2: inject window.__AGW_CSRF__ into dashboard HTML ─────────────
    _inject_csrf_global(request, response, want)


def _inject_csrf_global(request: web.Request, response, token: str) -> None:
    """Inject `<script>window.__AGW_CSRF__="<token>"</script>` into the <head>
    of authenticated dashboard HTML responses. CDN-proof CSRF token delivery —
    the dashboard fetch shim reads this global first, falling back to the cookie
    only when the global is absent (e.g. a page served before this shipped)."""
    try:
        path = request.path or ""
        if not path.startswith(ADMIN_NS_SECURED):
            return
        ctype = (getattr(response, "content_type", "") or "")
        if ctype != "text/html":
            return
        body = getattr(response, "body", None)
        if not isinstance(body, (bytes, bytearray)):
            return
        text = body.decode("utf-8", "replace")
        # Idempotency must key on a UNIQUE marker, not the bare global name —
        # the dashboard fetch shim itself contains `window.__AGW_CSRF__` (the
        # `||` fallback), so checking for that string would always match and the
        # real injection would be skipped, leaving the global undefined.
        if 'data-agw-csrf' in text or "</head>" not in text:
            return
        # token is a 32-char hex string; json.dumps gives a safely-quoted JS literal
        import json as _json
        tag = '<script data-agw-csrf>window.__AGW_CSRF__=' + _json.dumps(token) + ";</script>"
        response.body = text.replace("</head>", tag + "</head>", 1).encode("utf-8")
    except Exception:
        pass  # never break a response over token injection


# ── Middleware ─────────────────────────────────────────────────────────────
@web.middleware
async def cost_meter(request: web.Request, handler):
    """1.5.4 — outer timing middleware. Records the wall-time the proxy
    spends on this request (middleware + upstream forwarding). Used by the
    main-dashboard cost graph to show 'how much latency did the controls
    add this minute on average?'."""
    t0 = time.perf_counter()
    try:
        return await handler(request)
    finally:
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        try:
            _cost_bump(elapsed_ms)
        except Exception:
            pass
