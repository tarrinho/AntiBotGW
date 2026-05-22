# dashboards/controls.py — Phase 8: controls/geo/logs dashboard endpoints
# Extracted from proxy.py lines 11281–11297
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR  # noqa: F401 — leading-underscore not in *
from admin.auth import _internal_authed, _request_role, _role_denied  # noqa: F401
from aiohttp import web

CONTROLS_DASHBOARD_HTML  = (_DASHBOARDS_DIR / "controls.html").read_text(encoding="utf-8")
GEO_DASHBOARD_HTML       = (_DASHBOARDS_DIR / "geo.html").read_text(encoding="utf-8")
LOGS_DASHBOARD_HTML      = (_DASHBOARDS_DIR / "logs.html").read_text(encoding="utf-8")
CONTROLS_TEST_A_HTML     = (_DASHBOARDS_DIR / "controls_testA.html").read_text(encoding="utf-8")
CONTROLS_TEST_B_HTML     = (_DASHBOARDS_DIR / "controls_testB.html").read_text(encoding="utf-8")


_PROTO_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'"
    ),
}


async def controls_test_a_endpoint(request: web.Request):
    """Prototype A — split-pane controls layout (temporary, not in menus)."""
    # AUTH4-10/FE4-04: require full session auth + admin/maintainer role
    if not _internal_authed(request):
        return web.json_response({"error": "auth"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    _body_a = CONTROLS_TEST_A_HTML.replace('<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1)
    return web.Response(text=_body_a, content_type="text/html", headers=_PROTO_HEADERS)


async def controls_test_b_endpoint(request: web.Request):
    """Prototype B — modified-first controls layout (temporary, not in menus)."""
    # AUTH4-10/FE4-04: require full session auth + admin/maintainer role
    if not _internal_authed(request):
        return web.json_response({"error": "auth"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    _body_b = CONTROLS_TEST_B_HTML.replace('<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1)
    return web.Response(text=_body_b, content_type="text/html", headers=_PROTO_HEADERS)


async def controls_dashboard_endpoint(request: web.Request):
    """Ops dashboard with on/off switches + thresholds for every hot-reloadable knob."""
    if _request_role(request) == "viewer":
        return web.HTTPFound("/antibot-appsec-gateway/secured/live-feed")
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    _body = CONTROLS_DASHBOARD_HTML.replace('<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1)
    return web.Response(text=_body, content_type="text/html", headers=_PROTO_HEADERS)
