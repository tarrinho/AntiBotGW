"""
1.9.7 — Server header version-disclosure hardening
===================================================

aiohttp stamps a `Server: Python/X aiohttp/Y` banner on every response. That
fingerprints the gateway (framework + exact version) and breaks honeypot decoy
fidelity — a normal site behind a CDN does not advertise its app framework.

`core.middleware.session_cookie_finalizer` now normalises the header to a
generic `nginx` token on EVERY response (it wraps all routes). These tests pin
that behaviour so the banner can't silently regress.

Covers the same property asserted by:
  • dast-smoke.sh §15  "Server header does not disclose aiohttp"
  • tests/dynamic/cat18 HP-2 decoy fidelity
  • tests/test_live_gw.py::test_j03_no_server_version_disclosure
"""
import asyncio
from contextlib import asynccontextmanager

from aiohttp.test_utils import TestServer, TestClient

NS = "/antibot-appsec-gateway"


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@asynccontextmanager
async def _spin(proxy_module):
    proxy_module.UPSTREAM = "https://example.com"
    app = proxy_module.make_app()
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()


def _assert_normalized(resp):
    srv = resp.headers.get("Server", "")
    assert srv == "nginx", f"Server header should be normalized to 'nginx', got {srv!r}"
    low = srv.lower()
    assert "aiohttp" not in low and "python" not in low, \
        f"Server header must not disclose framework/version: {srv!r}"


def test_server_header_normalized_on_gw_page(proxy_module):
    """A GW-native page (login) must report Server: nginx, not aiohttp/python."""
    async def go():
        async with _spin(proxy_module) as c:
            _assert_normalized(await c.get(NS + "/login"))
    _run(go())


def test_server_header_normalized_on_decoy_404(proxy_module):
    """The finalizer wraps EVERY route — the silent decoy 404 must also be
    normalized, since an unauthenticated probe of a secured path is exactly
    where an attacker would fingerprint the framework."""
    async def go():
        async with _spin(proxy_module) as c:
            _assert_normalized(await c.get(NS + "/secured/config"))
            _assert_normalized(await c.get("/some-random-decoy-path-xyz"))
    _run(go())


def test_source_finalizer_sets_server_header():
    """Pin the implementation site so the normalization can't be dropped from
    the response finalizer without this test failing."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "middleware.py").read_text(encoding="utf-8")
    fn = src[src.index("async def session_cookie_finalizer("):]
    fn = fn[:fn.index("\nasync def ", 1)] if "\nasync def " in fn[1:] else fn
    assert 'headers["Server"]' in fn or "headers['Server']" in fn, \
        "session_cookie_finalizer must set the Server header"
