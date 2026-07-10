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
    # 1.8.11 (M1): only ever touch the CSRF token inside the admin namespace.
    # Both channels — and the cookie's path=ADMIN_NS below — keep the readable
    # agw_csrf token off the proxied upstream surface, so an XSS in the upstream
    # app cannot read it and drive same-origin admin actions.
    if not (request.path or "").startswith(ADMIN_NS):
        return
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
    # 1.8.14 (T0-2): CSRF token is the per-session random nonce stored in
    # _SESSION_CACHE.  Fall back to HMAC(SESSION_KEY, sid)[:32] only for
    # pre-migration sessions (NULL csrf_nonce in DB / not yet in cache).
    import hmac as _hmac
    import hashlib as _hashlib
    try:
        from admin.users import _SESSION_CACHE as _sc_mw
        _entry_mw = _sc_mw.get(sid)
        _nonce_mw = _entry_mw.get("csrf_nonce") if _entry_mw else None
    except Exception:
        _nonce_mw = None
    if _nonce_mw:
        want = _nonce_mw
    else:
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
                samesite="Strict", path=ADMIN_NS, secure=SESSION_SECURE,
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
        # token is a 32-char hex string; json.dumps gives a safely-quoted JS literal.
        # 1.8.11: also inject the operator-set SERVICE_OWNER (the org this gateway
        # protects) and a tiny renderer that appends its name to every
        # .portal-footer. Read the
        # value live from config (hot-reload propagates there). json.dumps makes
        # both values JS-string-safe; the renderer uses textContent (XSS-safe).
        import json as _json
        import config as _cfg
        _owner = getattr(_cfg, "SERVICE_OWNER", "") or ""
        # H1 fix: json.dumps is JS-string-safe but NOT <script>-context-safe — a
        # value like "</script>…" would break out of the tag. Neutralize < > &
        # (and the JS line separators) so a literal </script> / <!-- can't appear.
        def _js(v):
            return (_json.dumps(v).replace("<", "\\u003c")
                    .replace(">", "\\u003e").replace("&", "\\u0026"))
        tag = (
            '<script data-agw-csrf>window.__AGW_CSRF__=' + _js(token) +
            ';window.__AGW_SERVICE_OWNER__=' + _js(_owner) +
            ';(function(){var o=window.__AGW_SERVICE_OWNER__;if(!o)return;'
            'function r(){var fs=document.querySelectorAll("footer.portal-footer");'
            'for(var i=0;i<fs.length;i++){var f=fs[i];if(f.querySelector(".svc-owner"))continue;'
            'var s=document.createElement("span");s.className="sep";s.textContent="\\u00b7";'
            'var e=document.createElement("span");e.className="svc-owner";'
            'e.textContent=o;f.appendChild(s);f.appendChild(e);}}'
            'if(document.readyState!=="loading")r();'
            'else document.addEventListener("DOMContentLoaded",r);})();</script>'
        )
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
