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
    return response


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
