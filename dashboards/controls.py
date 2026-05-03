# dashboards/controls.py — Phase 8: controls/geo/logs dashboard endpoints
# Extracted from proxy.py lines 11281–11297
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR  # noqa: F401 — leading-underscore not in *
from admin.auth import _internal_authed  # noqa: F401
from aiohttp import web

CONTROLS_DASHBOARD_HTML = (_DASHBOARDS_DIR / "controls.html").read_text(encoding="utf-8")
GEO_DASHBOARD_HTML      = (_DASHBOARDS_DIR / "geo.html").read_text(encoding="utf-8")
LOGS_DASHBOARD_HTML     = (_DASHBOARDS_DIR / "logs.html").read_text(encoding="utf-8")


async def controls_dashboard_endpoint(request: web.Request):
    """Ops dashboard with on/off switches + thresholds for every hot-reloadable knob."""
    body = CONTROLS_DASHBOARD_HTML
    return web.Response(
        text=body, content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })
