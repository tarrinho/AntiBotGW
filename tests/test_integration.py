"""
HTTP-level integration tests against the real aiohttp app, using aiohttp's
built-in test client. No external upstream — we run a tiny in-process echo
server and point UPSTREAM at it.
"""
import asyncio
import os
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


# ── Tiny upstream for the proxy to forward to ────────────────────────────

async def _echo_handler(request: web.Request):
    body = await request.read()
    payload = {
        "method": request.method,
        "path":   request.path,
        "headers": {k: v for k, v in request.headers.items()},
        "body":   body.decode("utf-8", errors="replace"),
    }
    return web.json_response(payload, headers={"Server": "echo/1"})


async def _echo_redirect(request: web.Request):
    """Issue a 302 with a Location pointing at our upstream — used to test
    SSO Location-rewriting."""
    return web.Response(status=302, headers={
        "Location":   f"{os.environ['UPSTREAM']}/after-redirect?x=1",
        "Set-Cookie": "sessid=abc; Domain=upstream.example.com; Path=/; HttpOnly",
    })


async def _echo_html(request: web.Request):
    return web.Response(
        body=b"<html><body>hi</body></html>",
        content_type="text/html",
    )


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_get("/redirect", _echo_redirect)
    app.router.add_get("/html",      _echo_html)
    app.router.add_route("*", "/{tail:.*}", _echo_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


# ── Test helper that boots proxy as TestServer with UPSTREAM = echo ───────

@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url):
    """Re-init UPSTREAM into the running module + create the proxy app."""
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


def _browser_headers(extra=None):
    h = {
        "User-Agent":       "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
        "Accept":           "text/html,application/json",
        "Accept-Language":  "en-GB",
        "Accept-Encoding":  "gzip",
        "Sec-Ch-Ua":        '"Chromium"; v="120"',
        "Sec-Fetch-Site":   "none",
        "Sec-Fetch-Mode":   "navigate",
        "Sec-Fetch-Dest":   "document",
    }
    if extra:
        h.update(extra)
    return h


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── /antibot-appsec-gateway/live (always open, even unauthed) ─────────────────────────────────

def test_live_endpoint_open_no_auth(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get("/antibot-appsec-gateway/live")
                assert r.status == 200
                assert (await r.text()).strip() == "ok"
    _run(go())


# ── /antibot-appsec-gateway/secured/dashboard requires admin key (silent-decoyed otherwise) ───────────

def test_dashboard_silent_decoy_without_key(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get("/antibot-appsec-gateway/secured/dashboard")
                # Silent decoy: 200 OK with NO X-Proxy header (admin handler
                # would set X-Proxy via the dashboard response on real flows;
                # the decoy doesn't).
                assert r.status == 200
                assert "AppSecGW · Dashboard" not in await r.text()
    _run(go())


def test_dashboard_works_with_session_cookie(proxy_module, url_safe_key):
    """1.6.7 — bearer-key auth was removed. The dashboard reads only the
    session cookie now: prime an admin session in the in-memory cache,
    pass the signed cookie, expect 200."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                sid = proxy_module._new_sid()
                proxy_module._SESSION_CACHE[sid] = {
                    "username": "admin",
                    "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
                    "revoked": False,
                }
                proxy_module._SESSION_CACHE_READY = True
                cookie = proxy_module._session_sign("admin", sid=sid)
                r = await client.get(
                    "/antibot-appsec-gateway/secured/dashboard",
                    cookies={proxy_module._SESSION_COOKIE: cookie})
                body = await r.text()
                assert r.status == 200
                assert "AppSecGW" in body
                assert "Dashboard" in body
    _run(go())


# ── Method allowlist (Layer 0) ───────────────────────────────────────────

def test_method_not_allowed_returns_405(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.request("DELETE", "/some-path",
                                         headers=_browser_headers())
                assert r.status == 405
                assert "Allow" in r.headers
    _run(go())


def test_method_allowed_passes_through(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get("/api/foo", headers=_browser_headers())
                # Echo upstream returns 200; some layers might silent-decoy
                # depending on identity history, but for a fresh test it
                # passes through.
                assert r.status in (200, 404)
    _run(go())


# ── Control-byte rejection (Layer 0) ─────────────────────────────────────

def test_control_byte_in_path_returns_400(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                # %7F is DEL — a control byte
                r = await client.get("/foo%7F", headers=_browser_headers())
                assert r.status == 400
    _run(go())


# ── X-Proxy header on allowed responses ──────────────────────────────────

def test_x_proxy_header_on_allowed_response(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get("/api/something", headers=_browser_headers())
                # The proxy adds X-Proxy on responses that came from the
                # actual proxy() handler (not silent decoys).
                if r.status == 200:
                    assert r.headers.get("X-Proxy", "").startswith("AppSecGW")
    _run(go())


# ── SSO Location rewriting + Set-Cookie Domain stripping ────────────────

def test_location_rewrite_and_set_cookie_domain_strip(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            # 1.6.8 — keep os.environ["UPSTREAM"] in lockstep with the
            # per-test upstream URL so `_echo_redirect` (which reads from
            # os.environ) emits a Location whose netloc actually matches
            # what the proxy is configured to forward to. Without this,
            # the rewrite path is bypassed (lp.netloc != up_parsed.netloc),
            # the assertion below passes by coincidence on a fresh module
            # but breaks once any earlier test mutates os.environ.
            os.environ["UPSTREAM"] = up
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get("/redirect", headers=_browser_headers(),
                                     allow_redirects=False)
                # Location must NOT contain the upstream's full netloc
                # any more (host:port) — gateway should rewrite to its
                # own scheme://host:port. Checking by netloc rather than
                # bare host so the test still works when both upstream
                # and gateway run on 127.0.0.1 with different ports.
                assert r.status == 302
                loc = r.headers.get("Location", "")
                up_netloc = up.split("//", 1)[1]
                assert up_netloc not in loc, \
                    f"Location still contains upstream netloc {up_netloc}: {loc}"
                # Set-Cookie must NOT contain Domain= attribute
                cookies = r.headers.getall("Set-Cookie", [])
                upstream_cookie = next((c for c in cookies if c.startswith("sessid=")), None)
                assert upstream_cookie is not None
                assert "Domain=" not in upstream_cookie
    _run(go())


# ── Security response headers on HTML ────────────────────────────────────

def test_security_headers_injected_on_html(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get("/html", headers=_browser_headers())
                if r.status == 200 and "text/html" in r.headers.get("Content-Type", ""):
                    for h in ("X-Frame-Options",
                              "X-Content-Type-Options",
                              "Referrer-Policy",
                              "Strict-Transport-Security"):
                        assert h in r.headers, f"missing {h}"
    _run(go())


# ── Host allowlist (when configured) ─────────────────────────────────────

def test_host_allowlist_blocks_mismatch(proxy_module):
    """When ALLOWED_HOSTS is set, mismatched Host → silent decoy."""
    import ipaddress
    proxy_module.ALLOWED_HOSTS = {"good.example.com"}

    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get("/api/x",
                                     headers=_browser_headers({"Host": "evil.example.com"}))
                # silent decoy: 200, but X-Proxy must NOT be set (decoy must not fingerprint the gateway)
                assert r.status == 200
                assert "X-Proxy" not in r.headers
    try:
        _run(go())
    finally:
        proxy_module.ALLOWED_HOSTS = set()


# ── agents-bucket drill-down endpoint (1.5.4 / 1.7.1) ───────────────────

def _make_admin_session(proxy_module):
    """Inject a valid admin session into the module cache and return the signed cookie."""
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def test_agents_bucket_decoy_without_auth(proxy_module):
    """Unauthenticated request to /secured/agents-bucket returns a silent
    decoy (200 OK) — the response must NOT contain 'bucket_t'."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get(
                    "/antibot-appsec-gateway/secured/agents-bucket",
                    params={"t": "0", "bucket_secs": "60"})
                assert r.status == 200
                text = await r.text()
                assert "bucket_t" not in text
    _run(go())


def test_agents_bucket_shape_with_auth(proxy_module):
    """Authenticated request returns JSON with detected/missed/clean lists,
    each with bucket_t and bucket_secs. Every entry in detected/clean must
    carry an 'ip' field (regression: IPs were absent from dashboard popover)."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                cookie = _make_admin_session(proxy_module)
                r = await client.get(
                    "/antibot-appsec-gateway/secured/agents-bucket",
                    params={"t": "0", "bucket_secs": "60"},
                    cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                data = await r.json()
                for key in ("detected", "missed", "clean", "bucket_t", "bucket_secs"):
                    assert key in data, f"response missing '{key}'"
                assert isinstance(data["detected"], list)
                assert isinstance(data["missed"],   list)
                assert isinstance(data["clean"],     list)
                for entry in data["detected"]:
                    assert "ip"      in entry, f"detected entry missing 'ip': {entry}"
                    assert "count"   in entry, f"detected entry missing 'count': {entry}"
                    assert "reasons" in entry, f"detected entry missing 'reasons': {entry}"
                for entry in data["clean"]:
                    assert "ip"    in entry, f"clean entry missing 'ip': {entry}"
                    assert "count" in entry, f"clean entry missing 'count': {entry}"
                for entry in data["missed"]:
                    assert "ip" in entry, f"missed entry missing 'ip': {entry}"
    _run(go())


def test_agents_bucket_bad_t_param_returns_400(proxy_module):
    """Non-integer 't' param returns HTTP 400 with an 'error' key."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                cookie = _make_admin_session(proxy_module)
                r = await client.get(
                    "/antibot-appsec-gateway/secured/agents-bucket",
                    params={"t": "notanint", "bucket_secs": "60"},
                    cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 400
                data = await r.json()
                assert "error" in data
    _run(go())


def test_agents_bucket_invalid_bucket_secs_falls_back_to_60(proxy_module):
    """bucket_secs not in the allowed set (60/300/900/3600/86400) silently
    falls back to 60; response must reflect bucket_secs == 60."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                cookie = _make_admin_session(proxy_module)
                r = await client.get(
                    "/antibot-appsec-gateway/secured/agents-bucket",
                    params={"t": "0", "bucket_secs": "999"},
                    cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                data = await r.json()
                assert data.get("bucket_secs") == 60, \
                    f"expected fallback to 60, got {data.get('bucket_secs')}"
    _run(go())


def test_agents_bucket_list_cap_500(proxy_module):
    """Each list in the response is capped at 500 entries server-side."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                cookie = _make_admin_session(proxy_module)
                r = await client.get(
                    "/antibot-appsec-gateway/secured/agents-bucket",
                    params={"t": "0", "bucket_secs": "86400"},
                    cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                data = await r.json()
                assert len(data.get("detected", [])) <= 500, "detected exceeds 500-entry cap"
                assert len(data.get("missed",   [])) <= 500, "missed exceeds 500-entry cap"
                assert len(data.get("clean",    [])) <= 500, "clean exceeds 500-entry cap"
    _run(go())


def test_agents_bucket_kind_filter(proxy_module):
    """?kind=detected adds 'only':'detected' to the response payload."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                cookie = _make_admin_session(proxy_module)
                r = await client.get(
                    "/antibot-appsec-gateway/secured/agents-bucket",
                    params={"t": "0", "bucket_secs": "60", "kind": "detected"},
                    cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                data = await r.json()
                assert data.get("only") == "detected", \
                    f"expected 'only':'detected', got {data.get('only')!r}"
    _run(go())
