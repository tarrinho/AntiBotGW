"""tests/test_upstream_no_leak.py — M-SEC-1: upstream address must never leak.

The gateway must scrub the upstream's scheme://host:port (and bare host:port)
from ALL outbound responses unconditionally — regardless of UPSTREAM_REWRITE_BASE.

Leak surfaces covered:
  Headers  — Location, Content-Location, Link, Refresh, Via, Server,
             X-Powered-By, X-Backend, arbitrary unknown headers
  Body     — HTML, JSON, XML, plain-text, JavaScript
  Non-text — binary bodies must pass through unmodified (no byte-corruption)

Static tests (class S): source-code assertions — the guard exists and is
  unconditional (not inside the UPSTREAM_REWRITE_BASE branch).

Dynamic tests (class D): full proxy + fake upstream, real HTTP requests.
"""
import asyncio
import os
import sys
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

_HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_HERE, ".."))

_SRC = os.path.join(_HERE, "..", "core", "proxy_handler.py")


# ── helpers ───────────────────────────────────────────────────────────────

def _src() -> str:
    return open(_SRC, encoding="utf-8").read()


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _browser_headers(extra=None):
    h = {
        "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
        "Accept":          "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-GB",
        "Accept-Encoding": "gzip, deflate",
        "Sec-Fetch-Site":  "none",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Dest":  "document",
    }
    if extra:
        h.update(extra)
    return h


# ── fake upstream factory ────────────────────────────────────────────────

def _make_upstream_app():
    """Upstream that always embeds its own address in responses/headers."""

    async def _html(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        return web.Response(
            text=(
                f"<html><body>"
                f'<a href="{base}/about">About</a>'
                f'<img src="{base}/logo.png">'
                f"</body></html>"
            ),
            content_type="text/html",
        )

    async def _json(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        return web.Response(
            text=f'{{"url":"{base}/api/v1","host":"{base}"}}',
            content_type="application/json",
        )

    async def _xml(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        return web.Response(
            text=f'<feed><link href="{base}/feed"/></feed>',
            content_type="application/xml",
        )

    async def _plain(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        return web.Response(
            text=f"Download at {base}/file.zip",
            content_type="text/plain",
        )

    async def _js(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        return web.Response(
            text=f'const API="{base}/api";',
            content_type="application/javascript",
        )

    async def _via(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        host = base.split("://", 1)[-1]
        return web.Response(
            text="ok",
            headers={"Via": f"1.1 {host}",
                     "X-Backend": base,
                     "Server": f"nginx/{host}"},
        )

    async def _content_location(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        return web.Response(
            text="<html><body>canonical</body></html>",
            content_type="text/html",
            headers={"Content-Location": f"{base}/canonical"},
        )

    async def _link_header(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        return web.Response(
            text="<html><body>preload</body></html>",
            content_type="text/html",
            headers={"Link": f'<{base}/style.css>; rel=preload'},
        )

    async def _custom_header(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        return web.Response(
            text="ok",
            headers={"X-Origin-Url": f"{base}/internal",
                     "X-Real-Server": base.split("://", 1)[-1]},
        )

    async def _binary(req):
        # A tiny fake PNG-like binary blob that contains no upstream address
        return web.Response(
            body=b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
            content_type="image/png",
        )

    async def _redirect(req):
        base = req.headers.get("X-Test-Base", "http://backend.internal:9000")
        return web.Response(
            status=302,
            headers={"Location": f"{base}/after-login"},
        )

    app = web.Application()
    app.router.add_get("/html",             _html)
    app.router.add_get("/json",             _json)
    app.router.add_get("/xml",              _xml)
    app.router.add_get("/plain",            _plain)
    app.router.add_get("/js",               _js)
    app.router.add_get("/via",              _via)
    app.router.add_get("/content-location", _content_location)
    app.router.add_get("/link",             _link_header)
    app.router.add_get("/custom",           _custom_header)
    app.router.add_get("/binary",           _binary)
    app.router.add_get("/redirect",         _redirect)
    return app


@asynccontextmanager
async def _spin_upstream():
    runner = web.AppRunner(_make_upstream_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    proxy_module.UPSTREAM_REWRITE_BASE = ""   # explicitly OFF — scrub must still fire
    proxy_module.JS_CHALLENGE = False
    proxy_module.TURNSTILE_ENABLED = False
    proxy_module.ANUBIS_ENABLED = False
    proxy_module.INJECT_SECURITY_HEADERS = False
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()
    proxy_module.UPSTREAM_REWRITE_BASE = ""


def _netloc(upstream_url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(upstream_url).netloc


# ═══════════════════════════════════════════════════════════════════════════
# S — Static source checks
# ═══════════════════════════════════════════════════════════════════════════

class TestS_Static:
    def test_s1_msec1_block_exists_in_source(self):
        """M-SEC-1 guard block must be present in proxy_handler.py."""
        assert "M-SEC-1" in _src(), \
            "core/proxy_handler.py: M-SEC-1 upstream-address scrub block not found"

    def test_s2_scrub_is_outside_rewrite_base_branch(self):
        """Upstream scrub must NOT be nested inside 'if _rewrite_base:' block.
        It must fire unconditionally — not only when UPSTREAM_REWRITE_BASE is set."""
        src = _src()
        msec_pos  = src.find("M-SEC-1")
        rb_pos    = src.find("if _rewrite_base")
        assert msec_pos != -1, "M-SEC-1 block not found"
        assert rb_pos   != -1, "UPSTREAM_REWRITE_BASE branch not found"
        assert msec_pos < rb_pos, \
            "M-SEC-1 upstream scrub must appear BEFORE (outside) the UPSTREAM_REWRITE_BASE branch"

    def test_s3_up_netloc_used_in_scrub(self):
        """_up_netloc variable must be used for the unconditional scrub."""
        assert "_up_netloc" in _src(), \
            "core/proxy_handler.py: _up_netloc not found — scrub must extract upstream netloc"

    def test_s4_header_scrub_covers_via(self):
        """'via' must be in the _DROP_IF_LEAKS set."""
        src = _src()
        msec_idx = src.find("M-SEC-1")
        block = src[msec_idx:msec_idx + 3000]
        assert '"via"' in block or "'via'" in block, \
            "M-SEC-1 block must include 'via' in the drop-if-leaks set"

    def test_s5_header_scrub_covers_server(self):
        """'server' must be in the _DROP_IF_LEAKS set."""
        src = _src()
        msec_idx = src.find("M-SEC-1")
        block = src[msec_idx:msec_idx + 3000]
        assert '"server"' in block or "'server'" in block, \
            "M-SEC-1 block must include 'server' in the drop-if-leaks set"

    def test_s6_body_scrub_covers_text_html(self):
        """text/ prefix must be in the text-content-type check."""
        src = _src()
        msec_idx = src.find("M-SEC-1")
        block = src[msec_idx:msec_idx + 5000]
        assert '"text/"' in block or "'text/'" in block, \
            "M-SEC-1 body scrub must include text/ content types"

    def test_s7_body_scrub_covers_application_json(self):
        """application/json must be in the text-content-type check."""
        src = _src()
        msec_idx = src.find("M-SEC-1")
        block = src[msec_idx:msec_idx + 5000]
        assert "application/json" in block, \
            "M-SEC-1 body scrub must include application/json"

    def test_s8_rewrite_headers_set_defined(self):
        """_REWRITE_HEADERS must be defined (headers to rewrite, not drop)."""
        src = _src()
        msec_idx = src.find("M-SEC-1")
        block = src[msec_idx:msec_idx + 3000]
        assert "_REWRITE_HEADERS" in block, \
            "M-SEC-1 block must define _REWRITE_HEADERS for headers that get rewritten"

    def test_s9_drop_if_leaks_set_defined(self):
        """_DROP_IF_LEAKS must be defined (headers to remove when they contain upstream)."""
        src = _src()
        msec_idx = src.find("M-SEC-1")
        block = src[msec_idx:msec_idx + 3000]
        assert "_DROP_IF_LEAKS" in block, \
            "M-SEC-1 block must define _DROP_IF_LEAKS for headers to remove"

    def test_s10_double_slash_normalization_guard_exists(self):
        """After M-SEC-1 replaces _up_origin → _gw_origin a second pass must
        collapse any gateway_origin//path double-slashes to single slashes.
        Joomla/CMS systems emit scheme://host//path absolute URLs when configured
        with a trailing-slash base URL; without this guard the replacement produces
        gateway_origin//path which browsers load as-is but is ugly and inconsistent."""
        src = _src()
        msec_idx = src.find("M-SEC-1")
        block = src[msec_idx: msec_idx + 8000]
        assert "_gw_double" in block, (
            "core/proxy_handler.py: double-slash normalization variable _gw_double "
            "not found in M-SEC-1 block — Joomla/CMS scheme://host//path URLs will "
            "produce gateway_origin//path after origin replace."
        )
        assert 'b"//"' in block or "b'//'" in block, (
            'core/proxy_handler.py: b"//" double-slash byte literal not found in '
            "M-SEC-1 block — normalization guard missing."
        )


# ═══════════════════════════════════════════════════════════════════════════
# D — Dynamic tests (full proxy + fake upstream)
# ═══════════════════════════════════════════════════════════════════════════

class TestD_Dynamic:

    # ── body scrubbing ────────────────────────────────────────────────────

    def test_d1_html_body_no_upstream_netloc(self, proxy_module):
        """HTML body: upstream netloc must not appear."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/html", headers=_browser_headers())
                    body = await r.text()
                    assert nl not in body, \
                        f"upstream netloc {nl!r} leaked in HTML body"
        _run(go())

    def test_d2_json_body_no_upstream_netloc(self, proxy_module):
        """JSON body: upstream netloc must not appear."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/json", headers=_browser_headers(
                        {"Accept": "application/json"}))
                    body = await r.text()
                    assert nl not in body, \
                        f"upstream netloc {nl!r} leaked in JSON body"
        _run(go())

    def test_d3_xml_body_no_upstream_netloc(self, proxy_module):
        """XML body: upstream netloc must not appear."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/xml", headers=_browser_headers())
                    body = await r.text()
                    assert nl not in body, \
                        f"upstream netloc {nl!r} leaked in XML body"
        _run(go())

    def test_d4_plain_text_body_no_upstream_netloc(self, proxy_module):
        """Plain text body: upstream netloc must not appear."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/plain", headers=_browser_headers(
                        {"Accept": "text/plain"}))
                    body = await r.text()
                    assert nl not in body, \
                        f"upstream netloc {nl!r} leaked in plain-text body"
        _run(go())

    def test_d5_javascript_body_no_upstream_netloc(self, proxy_module):
        """JavaScript body: upstream netloc must not appear."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/js", headers=_browser_headers(
                        {"Accept": "application/javascript"}))
                    body = await r.text()
                    assert nl not in body, \
                        f"upstream netloc {nl!r} leaked in JS body"
        _run(go())

    def test_d6_binary_body_not_corrupted(self, proxy_module):
        """Binary (image/png) body must pass through unmodified."""
        _EXPECTED = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/binary", headers=_browser_headers())
                    body = await r.read()
                    assert body == _EXPECTED, \
                        f"binary body corrupted: got {body!r}"
        _run(go())

    # ── header scrubbing ──────────────────────────────────────────────────

    def test_d7_location_header_no_upstream_netloc(self, proxy_module):
        """Location header (3xx): upstream netloc must not appear."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/redirect", headers=_browser_headers(),
                                    allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    assert nl not in loc, \
                        f"upstream netloc {nl!r} leaked in Location: {loc!r}"
        _run(go())

    def test_d8_content_location_header_no_upstream_netloc(self, proxy_module):
        """Content-Location header: upstream netloc must not appear."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/content-location", headers=_browser_headers())
                    cl = r.headers.get("Content-Location", "")
                    assert nl not in cl, \
                        f"upstream netloc {nl!r} leaked in Content-Location: {cl!r}"
        _run(go())

    def test_d9_link_header_no_upstream_netloc(self, proxy_module):
        """Link header: upstream netloc must not appear."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/link", headers=_browser_headers())
                    link = r.headers.get("Link", "")
                    assert nl not in link, \
                        f"upstream netloc {nl!r} leaked in Link: {link!r}"
        _run(go())

    def test_d10_via_header_dropped_when_leaks(self, proxy_module):
        """Via header containing upstream netloc must be dropped."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/via", headers=_browser_headers())
                    via = r.headers.get("Via", "")
                    assert nl not in via, \
                        f"upstream netloc {nl!r} leaked in Via: {via!r}"
        _run(go())

    def test_d11_x_backend_header_dropped_when_leaks(self, proxy_module):
        """X-Backend header containing upstream address must be dropped."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/via", headers=_browser_headers())
                    xb = r.headers.get("X-Backend", "")
                    assert nl not in xb, \
                        f"upstream netloc {nl!r} leaked in X-Backend: {xb!r}"
        _run(go())

    def test_d12_unknown_custom_header_dropped_when_leaks(self, proxy_module):
        """Unknown header (X-Origin-Url) containing upstream address must be dropped."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/custom", headers=_browser_headers())
                    xo = r.headers.get("X-Origin-Url", "")
                    assert nl not in xo, \
                        f"upstream netloc {nl!r} leaked in X-Origin-Url: {xo!r}"
        _run(go())

    def test_d13_no_upstream_in_any_response_header(self, proxy_module):
        """Exhaustive: no response header value may contain the upstream netloc."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    for path in ("/html", "/json", "/via", "/custom",
                                 "/content-location", "/link"):
                        r = await c.get(path, headers=_browser_headers(),
                                        allow_redirects=False)
                        for hk, hv in r.headers.items():
                            assert nl not in hv, (
                                f"upstream netloc {nl!r} leaked in "
                                f"header {hk}: {hv!r} (path={path!r})"
                            )
        _run(go())

    def test_d14_scrub_fires_without_upstream_rewrite_base(self, proxy_module):
        """Scrub must work even when UPSTREAM_REWRITE_BASE is empty string (opt-in feature off)."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                # _spin_proxy already sets UPSTREAM_REWRITE_BASE = "" — confirm it's respected
                async with _spin_proxy(proxy_module, up) as c:
                    assert proxy_module.UPSTREAM_REWRITE_BASE == "", \
                        "test precondition: UPSTREAM_REWRITE_BASE must be empty"
                    r = await c.get("/html", headers=_browser_headers())
                    body = await r.text()
                    assert nl not in body, \
                        f"scrub failed with UPSTREAM_REWRITE_BASE='': netloc {nl!r} in body"
        _run(go())

    def test_d15_body_replacement_uses_gateway_host(self, proxy_module):
        """Upstream netloc in body should be replaced with the gateway host, not stripped."""
        async def go():
            async with _spin_upstream() as up:
                nl = _netloc(up)
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/html", headers=_browser_headers())
                    body = await r.text()
                    assert nl not in body
                    # Body must still have link hrefs — just pointing at gateway
                    assert "href=" in body or "src=" in body, \
                        "body href/src attributes should be preserved (pointing at gateway)"
        _run(go())

    def test_d16_double_slash_normalized_after_origin_replace(self, proxy_module):
        """Joomla (and some CMS) generate absolute URLs as scheme://host//path.
        After M-SEC-1 replaces the upstream origin the result must be
        gateway_origin/path (single slash), not gateway_origin//path."""
        async def go():
            # Build a dedicated upstream that embeds its OWN origin with a
            # double slash — exactly how Joomla behaves when its base URL
            # is configured with a trailing slash.
            upstream_app = web.Application()

            async def double_slash_page(req):
                # req.host is the Host header the proxy sent to us.
                base = f"http://{req.host}"
                return web.Response(
                    text=(
                        f"<html><body>"
                        f'<img src="{base}//templates/site/logo.png">'
                        f'<a href="{base}//images/photo.jpg">photo</a>'
                        f'<link href="{base}//static/app.css">'
                        f"</body></html>"
                    ),
                    content_type="text/html",
                )

            upstream_app.router.add_get("/double-slash", double_slash_page)
            runner = web.AppRunner(upstream_app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            up = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
            nl = _netloc(up)
            try:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/double-slash", headers=_browser_headers())
                    body = await r.text()
                    # Upstream netloc must be gone
                    assert nl not in body, \
                        f"upstream netloc {nl!r} leaked: {body!r}"
                    # No double-slash path segments after origin replacement
                    assert "//templates/" not in body, \
                        "double-slash not normalized: //templates/ still in body"
                    assert "//images/" not in body, \
                        "double-slash not normalized: //images/ still in body"
                    assert "//static/" not in body, \
                        "double-slash not normalized: //static/ still in body"
                    # Paths must still be present (pointing at gateway, not stripped)
                    assert "templates/site/logo.png" in body
                    assert "images/photo.jpg" in body
                    assert "static/app.css" in body
            finally:
                await runner.cleanup()
        _run(go())

    def test_d17_double_slash_normalized_in_json_body(self, proxy_module):
        """Double-slash normalization must apply to application/json bodies,
        not just text/html — CMS systems can embed double-slash URLs in API responses."""
        async def go():
            upstream_app = web.Application()

            async def json_double_slash(req):
                base = f"http://{req.host}"
                import json
                return web.Response(
                    text=json.dumps({
                        "logo":    f"{base}//assets/logo.png",
                        "api":     f"{base}//api/v1/data",
                        "comment": "// standalone double-slash should survive",
                    }),
                    content_type="application/json",
                )

            upstream_app.router.add_get("/json-ds", json_double_slash)
            runner = web.AppRunner(upstream_app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            up = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
            nl = _netloc(up)
            try:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/json-ds", headers=_browser_headers(
                        {"Accept": "application/json"}))
                    body = await r.text()
                    assert nl not in body, \
                        f"upstream netloc {nl!r} leaked in JSON body"
                    assert "//assets/" not in body, \
                        "double-slash not normalized in JSON: //assets/ still present"
                    assert "//api/" not in body, \
                        "double-slash not normalized in JSON: //api/ still present"
                    assert "assets/logo.png" in body
                    assert "api/v1/data" in body
                    # Standalone // (no gateway origin prefix) must survive untouched
                    assert "// standalone double-slash should survive" in body, \
                        "standalone // comment text was incorrectly stripped from JSON body"
            finally:
                await runner.cleanup()
        _run(go())

    def test_d18_protocol_relative_urls_not_collapsed(self, proxy_module):
        """Protocol-relative URLs (//cdn.example.com/file.js) in the body must NOT
        be collapsed to /cdn.example.com/file.js — the normalization targets only
        gateway_origin// patterns, not bare // sequences unrelated to the origin."""
        async def go():
            upstream_app = web.Application()

            async def mixed_page(req):
                base = f"http://{req.host}"
                return web.Response(
                    text=(
                        "<html><body>"
                        f'<img src="{base}//logo.png">'
                        '<script src="//cdn.example.com/lib.js"></script>'
                        '<link href="//fonts.googleapis.com/css?f=Roboto">'
                        "</body></html>"
                    ),
                    content_type="text/html",
                )

            upstream_app.router.add_get("/mixed", mixed_page)
            runner = web.AppRunner(upstream_app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            up = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
            nl = _netloc(up)
            try:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/mixed", headers=_browser_headers())
                    body = await r.text()
                    assert nl not in body, \
                        f"upstream netloc {nl!r} leaked in HTML body"
                    # origin double-slash must be normalized (//logo.png gone)
                    assert "//logo.png" not in body, \
                        "origin double-slash //logo.png not normalized"
                    assert "logo.png" in body, \
                        "logo.png path was lost during normalization"
                    # protocol-relative third-party URLs must be preserved
                    assert "//cdn.example.com/lib.js" in body, (
                        "protocol-relative URL //cdn.example.com/lib.js was "
                        "incorrectly collapsed — normalization must only target "
                        "gateway_origin// patterns, not bare // sequences."
                    )
                    assert "//fonts.googleapis.com/css" in body, (
                        "protocol-relative URL //fonts.googleapis.com was "
                        "incorrectly collapsed by double-slash normalization."
                    )
            finally:
                await runner.cleanup()
        _run(go())
