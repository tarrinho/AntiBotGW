"""
tests/test_v197_security_headers_and_live.py — guard the 1.9.7 DAST fixes.

DAST smoke flagged 3 baseline gaps on a direct (no-CDN) hit:
  1. GET /antibot-appsec-gateway/live → 404 (loopback-only decoy)
  2. Missing X-Content-Type-Options on the proxied root
  3. Missing X-Frame-Options on the proxied root

Fixes:
  - New outermost `security_headers` middleware stamps X-Frame-Options /
    X-Content-Type-Options / Referrer-Policy on EVERY response when absent.
  - /live is now a public 200 "ok" (liveness probes are conventionally
    reachable; leaks nothing).

These are static + functional guards so a refactor can't silently revert.
"""
import asyncio
import os
import sys
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

PUB = "/antibot-appsec-gateway"


# ── Static structure ────────────────────────────────────────────────────

def _mw_src():
    return open(os.path.join(_ROOT, "core", "middleware.py"),
                encoding="utf-8").read()


def _proxy_src():
    return open(os.path.join(_ROOT, "proxy.py"), encoding="utf-8").read()


def test_security_headers_middleware_defined():
    src = _mw_src()
    assert "async def security_headers(" in src, (
        "core/middleware.py must define the security_headers middleware"
    )
    for h in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
        assert h in src, f"security_headers must set {h}"


def test_security_headers_only_set_when_absent():
    """Must not clobber upstream/endpoint-supplied headers."""
    src = _mw_src()
    assert "not in resp.headers" in src, (
        "security_headers must only set a header when ABSENT (preserve "
        "upstream/endpoint values)"
    )


def test_security_headers_wired_outermost():
    """It must be FIRST in the middleware list so it sees the final response
    (including the proxied root). aiohttp applies middlewares outside-in."""
    src = _proxy_src()
    import re
    m = re.search(r"middlewares=\[([^\]]*)\]", src)
    assert m, "make_app must declare a middlewares list"
    order = [x.strip() for x in m.group(1).split(",") if x.strip()]
    assert order and order[0] == "security_headers", (
        f"security_headers must be the FIRST middleware, got order {order}"
    )


def test_live_is_public_200():
    """/live handler must not gate on loopback any more."""
    src = open(os.path.join(_ROOT, "core", "proxy_handler.py"),
               encoding="utf-8").read()
    i = src.find('request.path == ADMIN_NS + "/live"')
    assert i != -1, "/live handler must exist"
    block = src[i:i + 600]
    assert "127.0.0.1" not in block and "::1" not in block, (
        "/live must no longer gate on loopback (127.0.0.1/::1)"
    )
    assert "live-not-loopback" not in block, (
        "/live must not record the non-loopback decoy reason any more"
    )
    assert 'text="ok"' in block, "/live must return the bare 'ok' body"


# ── Functional: spin a real in-process app ──────────────────────────────

async def _echo(request):
    # Upstream that sets NO security headers — proves the gateway adds them.
    return web.json_response({"ok": True})


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


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _browser_headers():
    return {
        "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120 Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }


def test_live_returns_200_from_any_caller(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(PUB + "/live")
                assert r.status == 200, f"/live expected 200, got {r.status}"
                assert (await r.text()).strip() == "ok"
    _run(go())


def test_security_headers_on_proxied_response(proxy_module):
    """The proxied root must carry the baseline headers even though the
    upstream echo sets none."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get("/", headers=_browser_headers())
                assert r.headers.get("X-Content-Type-Options") == "nosniff", (
                    "proxied response missing X-Content-Type-Options"
                )
                assert r.headers.get("X-Frame-Options") == "DENY", (
                    "proxied response missing X-Frame-Options"
                )
                assert r.headers.get("Referrer-Policy") == "no-referrer", (
                    "proxied response missing Referrer-Policy"
                )
    _run(go())


def test_security_headers_on_live(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(PUB + "/live")
                assert r.headers.get("X-Content-Type-Options") == "nosniff"
                assert r.headers.get("X-Frame-Options") == "DENY"
    _run(go())
