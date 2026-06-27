"""1.8.13 #5 — shared dashboard assets.

escapeHtml was duplicated inline across 14 dashboards (3 drifted variants); it's
now defined once in dashboards/assets/dashboard-common.js and included by each
dashboard. /assets/ is auth-gated (only botd.bundle.js is public), so the asset
serves to the operator's authenticated browser — these guards prove that, and
that every dashboard that uses escapeHtml provides it.
"""
import asyncio
import pathlib
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

_DASH = pathlib.Path(__file__).resolve().parent.parent / "dashboards"
_ASSET = _DASH / "assets" / "dashboard-common.js"
_INCLUDE = "dashboard-common.js"
_SERVED = ["main.html", "agents.html", "controls.html", "settings.html",
           "control_center.html", "geo.html", "logs.html", "service.html",
           "siem.html", "vhost_policy.html", "honeypots.html"]


def _run(c): return asyncio.new_event_loop().run_until_complete(c)


@asynccontextmanager
async def _spin(pm):
    pm.UPSTREAM = "https://example.com"
    c = TestClient(TestServer(pm.make_app()))
    await c.start_server()
    try:
        yield c
    finally:
        await c.close()


def _cookie(pm):
    sid = pm._new_sid()
    pm._SESSION_CACHE[sid] = {"username": "admin",
                             "expires_ts": pm._t.time() + pm._SESSION_TTL,
                             "revoked": False}
    pm._SESSION_CACHE_READY = True
    return pm._session_sign("admin", sid=sid)


def test_shared_asset_defines_escapehtml():
    assert _ASSET.exists(), "dashboards/assets/dashboard-common.js missing"
    src = _ASSET.read_text(encoding="utf-8")
    assert "window.escapeHtml" in src and "function" in src


@pytest.mark.parametrize("fname", _SERVED)
def test_dashboard_provides_escapehtml_if_used(fname):
    src = (_DASH / fname).read_text(encoding="utf-8")
    if "escapeHtml(" not in src:
        return
    assert ("function escapeHtml(" in src) or (_INCLUDE in src), (
        f"{fname}: calls escapeHtml() but neither defines it inline nor includes "
        f"{_INCLUDE} → escapeHtml would be undefined")


def test_shared_asset_served_to_authed_operator(proxy_module):
    """The crux: the dashboard <script src=…dashboard-common.js> only works if the
    gateway actually serves it to the authenticated operator. (Cookieless fetches
    404 by design — /assets/ is auth-gated except botd.) Forge a valid session and
    confirm 200 + escapeHtml definition."""
    def go():
        async def _t():
            async with _spin(proxy_module) as c:
                ck = {proxy_module._SESSION_COOKIE: _cookie(proxy_module)}
                r = await c.get("/antibot-appsec-gateway/assets/dashboard-common.js",
                                cookies=ck)
                assert r.status == 200, f"asset not served to authed operator: {r.status}"
                body = (await r.read()).decode("utf-8", "replace")
                assert "window.escapeHtml" in body
        _run(_t())
    go()
