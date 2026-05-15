"""
Tests for Live Feed "Detection methods" / "Top Methods" panels (v1.8.2 fix).

Bug: loadDetectorStats() and loadLogLevel() in main.html called `url(path)`
where `url` is not a function at that scope — TypeError was silently caught,
leaving both panels blank.

Fix: replaced url(path) with the bare string literal.

Groups:
  S1-S4  Static — main.html source checks
  D1-D6  Dynamic — /secured/detector-stats HTTP contract
"""
import asyncio
import inspect
import os
from pathlib import Path
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


# ── Paths ────────────────────────────────────────────────────────────────────

_REPO = Path(__file__).resolve().parent.parent
_MAIN_HTML = _REPO / "dashboards" / "main.html"

NS = "/antibot-appsec-gateway/secured"


# ── Shared async helpers ─────────────────────────────────────────────────────

async def _echo(request: web.Request):
    return web.json_response({"path": request.path})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _echo)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


def _make_session(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── Static tests (main.html source) ─────────────────────────────────────────

@pytest.fixture(scope="module")
def _main_src():
    return _MAIN_HTML.read_text(encoding="utf-8")


def test_s1_loadDetectorStats_no_url_wrapper(_main_src):
    """loadDetectorStats() must fetch the path string directly, not via url()."""
    assert "fetch(url('/antibot-appsec-gateway/secured/detector-stats')" not in _main_src, (
        "main.html: loadDetectorStats() still calls url(path) — url is not a function "
        "at that scope, causing a silent TypeError and blank Detection Methods panel."
    )


def test_s2_loadDetectorStats_fetches_detector_stats(_main_src):
    """loadDetectorStats() must contain the detector-stats path as a bare string."""
    assert "fetch('/antibot-appsec-gateway/secured/detector-stats'" in _main_src, (
        "main.html: loadDetectorStats() does not fetch '/antibot-appsec-gateway/secured/detector-stats'. "
        "Detection Methods / Top Methods panels will always be empty."
    )


def test_s3_loadLogLevel_no_url_wrapper(_main_src):
    """loadLogLevel() must fetch /secured/config without the broken url() wrapper."""
    assert "fetch(url('/antibot-appsec-gateway/secured/config')" not in _main_src, (
        "main.html: loadLogLevel() still calls url(path) — url is not a function "
        "at that scope, causing a silent TypeError and wrong log-level display."
    )


def test_s4_no_global_url_function_calls(_main_src):
    """No remaining url() calls with /antibot-appsec-gateway paths remain."""
    import re
    hits = re.findall(r"fetch\(url\(['\"].*?['\"]", _main_src)
    assert not hits, (
        f"main.html: {len(hits)} remaining fetch(url(...)) call(s) found. "
        f"url() is not a function — these will silently fail: {hits}"
    )


# ── Dynamic tests (/secured/detector-stats HTTP contract) ───────────────────

def test_d1_detector_stats_returns_200(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_session(proxy_module)
                r = await c.get(NS + "/detector-stats",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
    _run(go())


def test_d2_detector_stats_has_required_keys(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_session(proxy_module)
                r = await c.get(NS + "/detector-stats",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                d = await r.json()
                for key in ("signals", "methods", "chal"):
                    assert key in d, f"/detector-stats missing top-level key: {key}"
    _run(go())


def test_d3_detector_stats_signals_and_methods_are_lists(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_session(proxy_module)
                r = await c.get(NS + "/detector-stats",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                d = await r.json()
                assert isinstance(d["signals"], list)
                assert isinstance(d["methods"], list)
    _run(go())


def test_d4_detector_stats_chal_has_required_fields(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_session(proxy_module)
                r = await c.get(NS + "/detector-stats",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                d = await r.json()
                chal = d["chal"]
                for f in ("required", "minted", "mint_rate"):
                    assert f in chal, f"/detector-stats chal missing field: {f}"
    _run(go())


def test_d5_detector_stats_methods_shape_after_hit(proxy_module):
    """After _detector_record fires, methods entries have required fields."""
    import core.proxy_handler as ph
    ph._detector_record("ua-curl", 12.5)
    ph._detector_record("ua-curl", 18.0)

    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_session(proxy_module)
                r = await c.get(NS + "/detector-stats",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                d = await r.json()
                assert d["methods"], "methods list empty even after _detector_record"
                m = d["methods"][0]
                for f in ("method", "hits", "p99_ms", "reasons"):
                    assert f in m, f"methods entry missing field: {f}"
    _run(go())
    # cleanup
    ph._detector_hits.pop("ua-curl", None)
    ph._detector_latency.pop("ua-curl", None)


def test_d6_detector_stats_no_cache(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_session(proxy_module)
                r = await c.get(NS + "/detector-stats",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert "no-store" in r.headers.get("Cache-Control", ""), (
                    "/detector-stats missing Cache-Control: no-store"
                )
    _run(go())
