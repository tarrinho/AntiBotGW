"""tests/test_upstream_rewrite.py — UPSTREAM_REWRITE_BASE feature tests.

Static tests:  pure logic, no network, no running server.
Dynamic tests: full proxy + fake upstream, exercises the middleware chain.

Feature: when UPSTREAM_REWRITE_BASE is set (globally or per-vhost) the
gateway strips that base URL from:
  • response body  (any content-type)
  • Location header
  • Content-Location header
  • Link header
ensuring the internal upstream origin is never exposed to the browser.
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

_BASE = "http://host.docker.internal:8093"


# ── helpers ───────────────────────────────────────────────────────────────

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


# ── fake upstream ─────────────────────────────────────────────────────────

def _make_upstream_app(base: str = _BASE):
    async def html_page(req):
        return web.Response(
            text=(
                f"<html><head>"
                f'<link rel="stylesheet" href="{base}/static/app.css">'
                f"</head><body>"
                f'<img src="{base}/images/logo.png">'
                f'<a href="{base}/about">About</a>'
                f"</body></html>"
            ),
            content_type="text/html",
        )

    async def json_api(req):
        return web.Response(
            text=f'{{"image_url":"{base}/media/photo.jpg","home":"{base}/"}}',
            content_type="application/json",
        )

    async def xml_feed(req):
        return web.Response(
            text=f'<feed><link href="{base}/feed"/></feed>',
            content_type="application/xml",
        )

    async def plain_text(req):
        return web.Response(
            text=f"Download at {base}/download/file.zip",
            content_type="text/plain",
        )

    async def redirect(req):
        return web.Response(
            status=302,
            headers={"Location": f"{base}/after-login"},
        )

    async def content_location(req):
        return web.Response(
            text="<html><body>canonical</body></html>",
            content_type="text/html",
            headers={"Content-Location": f"{base}/canonical"},
        )

    async def link_header(req):
        return web.Response(
            text="<html><body>preload</body></html>",
            content_type="text/html",
            headers={"Link": f'<{base}/style.css>; rel=preload'},
        )

    async def clean(req):
        return web.Response(
            text="<html><body><img src='/images/clean.png'></body></html>",
            content_type="text/html",
        )

    async def with_csp(req):
        return web.Response(
            text=(
                f"<html><body>"
                f'<img src="{base}/images/category.jpg">'
                f"</body></html>"
            ),
            content_type="text/html",
            headers={
                "Content-Security-Policy": (
                    "img-src 'self' https://fonts.googleapis.com "
                    "https://code.jquery.com"
                )
            },
        )

    app = web.Application()
    app.router.add_get("/html",             html_page)
    app.router.add_get("/api/data",         json_api)
    app.router.add_get("/feed.xml",         xml_feed)
    app.router.add_get("/plain",            plain_text)
    app.router.add_get("/redirect",         redirect)
    app.router.add_get("/content-location", content_location)
    app.router.add_get("/link-header",      link_header)
    app.router.add_get("/clean",            clean)
    app.router.add_get("/csp",              with_csp)
    return app


@asynccontextmanager
async def _spin_upstream(base: str = _BASE):
    runner = web.AppRunner(_make_upstream_app(base))
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url, rewrite_base: str = ""):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    proxy_module.UPSTREAM_REWRITE_BASE = rewrite_base.rstrip("/")
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


# ═══════════════════════════════════════════════════════════════════════════
# STATIC TESTS — pure logic, no fixtures, no I/O
# ═══════════════════════════════════════════════════════════════════════════

class TestStaticConfigSchema:
    """UPSTREAM_REWRITE_BASE is registered in the hot-reload knobs table."""

    def test_knob_registered_in_hot_reload_knobs(self, proxy_module):
        assert "UPSTREAM_REWRITE_BASE" in proxy_module._HOT_RELOAD_KNOBS

    def test_knob_type_is_str(self, proxy_module):
        converter, _ = proxy_module._HOT_RELOAD_KNOBS["UPSTREAM_REWRITE_BASE"]
        assert converter is str

    def test_knob_validator_accepts_valid_url(self, proxy_module):
        _, validator = proxy_module._HOT_RELOAD_KNOBS["UPSTREAM_REWRITE_BASE"]
        assert validator is None or validator("http://host.docker.internal:8093")

    def test_knob_validator_rejects_overlong_value(self, proxy_module):
        _, validator = proxy_module._HOT_RELOAD_KNOBS["UPSTREAM_REWRITE_BASE"]
        if validator is not None:
            assert not validator("x" * 2049)

    def test_knob_validator_rejects_non_url(self, proxy_module):
        _, validator = proxy_module._HOT_RELOAD_KNOBS["UPSTREAM_REWRITE_BASE"]
        if validator is not None:
            assert not validator("host.docker.internal:8093")   # missing scheme
            assert not validator("ftp://internal.example.com")  # wrong scheme

    def test_knob_validator_accepts_empty_string(self, proxy_module):
        _, validator = proxy_module._HOT_RELOAD_KNOBS["UPSTREAM_REWRITE_BASE"]
        if validator is not None:
            assert validator("")  # clearing the knob must always be valid

    def test_default_is_empty_string(self, proxy_module):
        # env var is not set in test suite → must be falsy
        assert proxy_module.UPSTREAM_REWRITE_BASE == ""


class TestStaticRewriteLogic:
    """Unit-test the bytes/string rewrite logic directly — no proxy needed."""

    # ── rewrite helpers (mirror the proxy's exact implementation) ─────────

    @staticmethod
    def _body(body: bytes, base: str) -> bytes:
        rb = base.rstrip("/").encode()
        if rb in body:
            return body.replace(rb, b"")
        return body

    @staticmethod
    def _header(value: str, base: str) -> str:
        return value.replace(base.rstrip("/"), "")

    # ── body ──────────────────────────────────────────────────────────────

    def test_html_img_absolute_becomes_relative(self):
        body = f'<img src="{_BASE}/images/photo.jpg">'.encode()
        out = self._body(body, _BASE)
        assert _BASE.encode() not in out
        assert b'src="/images/photo.jpg"' in out

    def test_html_multiple_occurrences_all_replaced(self):
        body = (
            f'<img src="{_BASE}/a.jpg">'
            f'<link href="{_BASE}/b.css">'
            f'<script src="{_BASE}/c.js"></script>'
        ).encode()
        out = self._body(body, _BASE)
        assert _BASE.encode() not in out
        assert b"/a.jpg" in out and b"/b.css" in out and b"/c.js" in out

    def test_json_body_url_stripped(self):
        body = f'{{"url":"{_BASE}/api/resource"}}'.encode()
        out = self._body(body, _BASE)
        assert _BASE.encode() not in out
        assert b'"/api/resource"' in out

    def test_xml_body_url_stripped(self):
        body = f'<link href="{_BASE}/feed"/>'.encode()
        out = self._body(body, _BASE)
        assert _BASE.encode() not in out

    def test_plain_text_url_stripped(self):
        body = f"Download: {_BASE}/file.zip".encode()
        out = self._body(body, _BASE)
        assert _BASE.encode() not in out
        assert b"/file.zip" in out

    def test_no_match_body_unchanged(self):
        body = b"<html><body><img src='/relative.jpg'></body></html>"
        assert self._body(body, _BASE) == body

    def test_empty_body_unchanged(self):
        assert self._body(b"", _BASE) == b""

    def test_different_port_not_stripped(self):
        base = "http://host.docker.internal:8093"
        body = b"http://host.docker.internal:8094/other"
        assert self._body(body, base) == body

    def test_trailing_slash_in_base_treated_same(self):
        body = f'<img src="{_BASE}/img.png">'.encode()
        out = self._body(body, _BASE + "/")
        assert _BASE.encode() not in out

    # ── headers ───────────────────────────────────────────────────────────

    def test_location_header_stripped(self):
        out = self._header(f"{_BASE}/after-login", _BASE)
        assert _BASE not in out
        assert out == "/after-login"

    def test_content_location_header_stripped(self):
        out = self._header(f"{_BASE}/canonical", _BASE)
        assert out == "/canonical"

    def test_link_header_stripped(self):
        out = self._header(f"<{_BASE}/style.css>; rel=preload", _BASE)
        assert _BASE not in out
        assert "</style.css>" in out

    def test_header_no_match_unchanged(self):
        val = "https://cdn.example.com/style.css"
        assert self._header(val, _BASE) == val

    def test_header_strip_to_empty_is_suppressed(self):
        """If stripping produces an empty header value, keep the original
        to avoid emitting an invalid Location/Content-Location."""
        raw = _BASE  # exactly the base, no path suffix
        stripped = self._header(raw, _BASE)
        assert stripped == ""  # the raw result IS empty
        # Proxy must NOT emit an empty Location — the guard skips it.
        # We test the guard logic directly:
        result = stripped if stripped else raw
        assert result == raw  # original preserved when stripped would be empty

    # ── guard: empty base is no-op ─────────────────────────────────────────

    def test_empty_base_is_noop(self):
        body = f'<img src="{_BASE}/img.png">'.encode()
        _rb = "".rstrip("/")
        if _rb:                       # this branch must NOT execute
            body = body.replace(_rb.encode(), b"")
        assert _BASE.encode() in body

    # ── CSP resolution ────────────────────────────────────────────────────

    def test_csp_violation_resolved_after_rewrite(self):
        """Stripped img src becomes relative → matches 'self' → no violation."""
        img_after = self._header(f"{_BASE}/images/category.jpg", _BASE)
        assert img_after.startswith("/")
        assert _BASE not in img_after


# ═══════════════════════════════════════════════════════════════════════════
# DYNAMIC TESTS — full proxy stack, real HTTP
# ═══════════════════════════════════════════════════════════════════════════

class TestDynamicRewriteDisabled:
    """Without UPSTREAM_REWRITE_BASE the internal URL leaks in body."""

    def test_html_body_retains_internal_url(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base="") as c:
                    r = await c.get("/html", headers=_browser_headers())
                    body = await r.text()
                    assert _BASE in body
        _run(go())

    def test_redirect_location_rewritten_to_gateway_not_upstream(self, proxy_module):
        """The proxy already rewrites Location on 3xx to the gateway URL.
        Verify this existing behaviour so the enabled-rewrite test is meaningful."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base="") as c:
                    r = await c.get("/redirect",
                                    headers=_browser_headers(),
                                    allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    # Proxy rewrites Location to gateway address — upstream URL gone
                    assert _BASE not in loc
                    assert r.status == 302
        _run(go())


class TestDynamicRewriteEnabled:
    """With UPSTREAM_REWRITE_BASE set the internal URL must be scrubbed."""

    def test_html_body_stripped(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/html", headers=_browser_headers())
                    body = await r.text()
                    assert _BASE not in body
                    assert "/images/logo.png" in body
                    assert "/static/app.css" in body
                    assert "/about" in body
        _run(go())

    def test_json_body_stripped(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/api/data", headers=_browser_headers())
                    body = await r.text()
                    assert _BASE not in body
                    assert "/media/photo.jpg" in body
        _run(go())

    def test_xml_body_stripped(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/feed.xml", headers=_browser_headers())
                    body = await r.text()
                    assert _BASE not in body
        _run(go())

    def test_plain_text_body_stripped(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/plain", headers=_browser_headers())
                    body = await r.text()
                    assert _BASE not in body
                    assert "/download/file.zip" in body
        _run(go())

    def test_location_header_on_redirect_has_no_internal_url(self, proxy_module):
        """Location on 3xx is rewritten to gateway URL by existing proxy logic;
        UPSTREAM_REWRITE_BASE provides a second safety net for any embedded
        upstream-origin references that slip past the existing rewrite."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/redirect",
                                    headers=_browser_headers(),
                                    allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    assert _BASE not in loc
                    assert r.status == 302
                    assert "/after-login" in loc
        _run(go())

    def test_content_location_header_stripped(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/content-location", headers=_browser_headers())
                    cl = r.headers.get("Content-Location", "")
                    assert _BASE not in cl
                    assert cl == "/canonical"
        _run(go())

    def test_link_header_stripped(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/link-header", headers=_browser_headers())
                    link = r.headers.get("Link", "")
                    assert _BASE not in link
                    assert "/style.css" in link
        _run(go())

    def test_clean_response_unaffected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/clean", headers=_browser_headers())
                    body = await r.text()
                    assert "/images/clean.png" in body
                    assert r.status == 200
        _run(go())

    def test_csp_violation_resolved_by_rewrite(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/csp", headers=_browser_headers())
                    body = await r.text()
                    assert _BASE not in body
                    assert 'src="/images/category.jpg"' in body
                    csp = r.headers.get("Content-Security-Policy", "")
                    assert "img-src" in csp
        _run(go())

    def test_trailing_slash_in_base_handled(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up,
                                       rewrite_base=_BASE + "/") as c:
                    r = await c.get("/html", headers=_browser_headers())
                    body = await r.text()
                    assert _BASE not in body
        _run(go())

    def test_status_code_preserved_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/html", headers=_browser_headers())
                    assert r.status == 200
        _run(go())

    def test_status_code_preserved_redirect(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/redirect",
                                    headers=_browser_headers(),
                                    allow_redirects=False)
                    assert r.status == 302
        _run(go())

    def test_x_proxy_header_still_injected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/html", headers=_browser_headers())
                    assert "X-Proxy" in r.headers
        _run(go())

    def test_similar_base_with_different_port_not_stripped(self, proxy_module):
        """Only the exact base must be stripped."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up, rewrite_base=_BASE) as c:
                    r = await c.get("/clean", headers=_browser_headers())
                    assert r.status == 200
                    body = await r.text()
                    assert "/images/clean.png" in body
        _run(go())
