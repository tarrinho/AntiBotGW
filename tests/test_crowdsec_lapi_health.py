"""
tests/test_crowdsec_lapi_health.py — CrowdSec LAPI health-probe feature.

The /__integrations (Controls page) CrowdSec card includes a live
`lapi_health` block produced by _crowdsec_lapi_health():
  reachable (bool|None), ping_ms (float|None),
  version   (str|None),  error   (str|None)

Result is cached for _CROWDSEC_HEALTH_TTL seconds — safe to call on
every page load without hammering the LAPI container.

Static tests (S):  source-code assertions — function exists, cache dict
                   exists, `lapi_health` key wired into external_endpoint.
Dynamic tests (D): in-process gateway + mock LAPI server; verifies the
                   probe fires, caches, and degrades gracefully.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

_HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_HERE, ".."))

_CROWDSEC_SRC = Path(_HERE).parent / "reputation" / "crowdsec.py"
_HANDLER_SRC  = Path(_HERE).parent / "core" / "proxy_handler.py"

NS = "/antibot-appsec-gateway/secured"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ═══════════════════════════════════════════════════════════════════════════
# S — Static source checks
# ═══════════════════════════════════════════════════════════════════════════

class TestS_Static:

    def test_s01_health_function_defined(self):
        """_crowdsec_lapi_health must be defined in reputation/crowdsec.py."""
        assert "async def _crowdsec_lapi_health" in _read(_CROWDSEC_SRC), (
            "reputation/crowdsec.py: _crowdsec_lapi_health() not found. "
            "Controls page cannot show live LAPI status."
        )

    def test_s02_health_cache_dict_exists(self):
        """_crowdsec_health_cache dict must exist for TTL caching."""
        assert "_crowdsec_health_cache" in _read(_CROWDSEC_SRC), (
            "reputation/crowdsec.py: _crowdsec_health_cache not found — "
            "health probe will hammer LAPI on every Controls page load."
        )

    def test_s03_health_cache_ttl_defined(self):
        """_CROWDSEC_HEALTH_TTL constant must be defined."""
        assert "_CROWDSEC_HEALTH_TTL" in _read(_CROWDSEC_SRC), (
            "reputation/crowdsec.py: _CROWDSEC_HEALTH_TTL not found — "
            "cache expiry has no named constant."
        )

    def test_s04_heartbeat_endpoint_used(self):
        """Health probe must call /v1/heartbeat (CrowdSec standard liveness)."""
        src = _read(_CROWDSEC_SRC)
        fn_start = src.find("async def _crowdsec_lapi_health")
        assert fn_start != -1, "_crowdsec_lapi_health not found"
        body = src[fn_start: fn_start + 2000]
        assert "/v1/heartbeat" in body, (
            "reputation/crowdsec.py: _crowdsec_lapi_health() does not call "
            "/v1/heartbeat — use the standard CrowdSec liveness endpoint."
        )

    def test_s05_health_returns_reachable_key(self):
        """Return dict must include 'reachable' key."""
        src = _read(_CROWDSEC_SRC)
        fn_start = src.find("async def _crowdsec_lapi_health")
        body = src[fn_start: fn_start + 2000]
        assert '"reachable"' in body or "'reachable'" in body, (
            "reputation/crowdsec.py: _crowdsec_lapi_health() result dict "
            "missing 'reachable' key."
        )

    def test_s06_health_returns_version_key(self):
        """Return dict must include 'version' key."""
        src = _read(_CROWDSEC_SRC)
        fn_start = src.find("async def _crowdsec_lapi_health")
        body = src[fn_start: fn_start + 2000]
        assert '"version"' in body or "'version'" in body, (
            "reputation/crowdsec.py: _crowdsec_lapi_health() result dict "
            "missing 'version' key."
        )

    def test_s07_health_returns_ping_ms_key(self):
        """Return dict must include 'ping_ms' key."""
        src = _read(_CROWDSEC_SRC)
        fn_start = src.find("async def _crowdsec_lapi_health")
        body = src[fn_start: fn_start + 2000]
        assert '"ping_ms"' in body or "'ping_ms'" in body, (
            "reputation/crowdsec.py: _crowdsec_lapi_health() result dict "
            "missing 'ping_ms' key."
        )

    def test_s08_timeout_is_generous(self):
        """Health probe timeout must be >= 2s (Controls page can afford to wait;
        per-request CROWDSEC_TIMEOUT_S is 1s)."""
        src = _read(_CROWDSEC_SRC)
        fn_start = src.find("async def _crowdsec_lapi_health")
        body = src[fn_start: fn_start + 2000]
        import re
        m = re.search(r"ClientTimeout\(total\s*=\s*([\d.]+)\)", body)
        assert m, "reputation/crowdsec.py: ClientTimeout not found in _crowdsec_lapi_health()"
        assert float(m.group(1)) >= 2.0, (
            f"reputation/crowdsec.py: health probe timeout {m.group(1)}s < 2s — "
            "too tight for slow Pi hardware under load."
        )

    def test_s09_handler_imports_health_fn(self):
        """proxy_handler.py must import _crowdsec_lapi_health."""
        src = _read(_HANDLER_SRC)
        assert "_crowdsec_lapi_health" in src, (
            "core/proxy_handler.py: _crowdsec_lapi_health not imported — "
            "external_endpoint cannot call it."
        )

    def test_s10_external_endpoint_includes_lapi_health(self):
        """external_endpoint must include lapi_health in the CrowdSec card."""
        src = _read(_HANDLER_SRC)
        cs_block_start = src.find("# 3. CrowdSec")
        assert cs_block_start != -1, "core/proxy_handler.py: '# 3. CrowdSec' marker not found"
        # Search next 800 chars — covers the integrations.append() call
        block = src[cs_block_start: cs_block_start + 800]
        assert "lapi_health" in block, (
            "core/proxy_handler.py: 'lapi_health' key missing from CrowdSec "
            "integrations card in external_endpoint — Controls page won't show LAPI status."
        )

    def test_s11_health_fn_awaited_in_external_endpoint(self):
        """_crowdsec_lapi_health must be awaited in external_endpoint."""
        src = _read(_HANDLER_SRC)
        cs_block_start = src.find("# 3. CrowdSec")
        block = src[cs_block_start: cs_block_start + 400]
        assert "await _crowdsec_lapi_health()" in block, (
            "core/proxy_handler.py: _crowdsec_lapi_health() not awaited in "
            "external_endpoint — lapi_health will contain a coroutine object, not a dict."
        )

    def test_s12_404_fallback_handled(self):
        """Health probe must handle HTTP 404 gracefully (older LAPI without /v1/heartbeat)."""
        src = _read(_CROWDSEC_SRC)
        fn_start = src.find("async def _crowdsec_lapi_health")
        body = src[fn_start: fn_start + 2000]
        assert "404" in body, (
            "reputation/crowdsec.py: _crowdsec_lapi_health() does not handle "
            "HTTP 404 — older CrowdSec LAPI versions lack /v1/heartbeat and "
            "will be incorrectly reported as unreachable."
        )

    def test_s13_not_configured_returns_none_reachable(self):
        """When CROWDSEC_ENABLED is False the function must return early with
        reachable=None (not False) to distinguish 'not configured' from 'down'."""
        src = _read(_CROWDSEC_SRC)
        fn_start = src.find("async def _crowdsec_lapi_health")
        body = src[fn_start: fn_start + 500]
        assert "not configured" in body, (
            "reputation/crowdsec.py: _crowdsec_lapi_health() must return "
            "{'reachable': None, ..., 'error': 'not configured'} when disabled "
            "so the Controls card can distinguish unconfigured from unreachable."
        )


# ═══════════════════════════════════════════════════════════════════════════
# D — Dynamic tests
#
# We call _crowdsec_lapi_health() DIRECTLY after patching the crowdsec module
# (not via the proxy gateway). This avoids the session-scoped proxy_module
# import caching issue where module-level CROWDSEC_ENABLED baked at first
# import doesn't propagate to the gateway's copy.
#
# D07 is the only gateway integration test: verifies lapi_health appears in
# the Controls page response (with reachable=None since no LAPI configured
# in the session fixture).
# ═══════════════════════════════════════════════════════════════════════════

import reputation.crowdsec as _cs_mod
from reputation.crowdsec import _crowdsec_lapi_health


@asynccontextmanager
async def _mock_lapi(handler):
    """Spin a tiny LAPI server with a /v1/heartbeat route."""
    app = web.Application()
    app.router.add_get("/v1/heartbeat", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _patched_cs(lapi_url: str, api_key: str):
    """Patch reputation.crowdsec globals, clear health cache, restore after."""
    orig_url     = _cs_mod.CROWDSEC_LAPI_URL
    orig_key     = _cs_mod.CROWDSEC_API_KEY
    orig_enabled = _cs_mod.CROWDSEC_ENABLED
    _cs_mod.CROWDSEC_LAPI_URL = lapi_url.rstrip("/")
    _cs_mod.CROWDSEC_API_KEY  = api_key
    _cs_mod.CROWDSEC_ENABLED  = bool(lapi_url and api_key)
    _cs_mod._crowdsec_health_cache.clear()
    # also close any stale session so a fresh one is created in this loop
    if _cs_mod._http_session and not _cs_mod._http_session.closed:
        await _cs_mod._http_session.close()
    _cs_mod._http_session = None
    try:
        yield
    finally:
        _cs_mod.CROWDSEC_LAPI_URL = orig_url
        _cs_mod.CROWDSEC_API_KEY  = orig_key
        _cs_mod.CROWDSEC_ENABLED  = orig_enabled
        _cs_mod._crowdsec_health_cache.clear()
        if _cs_mod._http_session and not _cs_mod._http_session.closed:
            await _cs_mod._http_session.close()
        _cs_mod._http_session = None


# ── D01: LAPI up → reachable=True, version, ping_ms ─────────────────────

@pytest.mark.asyncio
async def test_d01_lapi_up_reports_reachable():
    """When LAPI /v1/heartbeat returns 200 + version, reachable must be True."""
    async def _ok(req):
        return web.json_response({"version": "v1.6.3"})

    async with _mock_lapi(_ok) as lapi_url, _patched_cs(lapi_url, "testkey"):
        result = await _crowdsec_lapi_health()

    assert result["reachable"] is True, \
        f"reachable should be True, got {result['reachable']!r}"
    assert result["version"] == "v1.6.3", \
        f"version should be 'v1.6.3', got {result['version']!r}"
    assert isinstance(result["ping_ms"], float) and result["ping_ms"] >= 0, \
        f"ping_ms should be non-negative float, got {result['ping_ms']!r}"
    assert result["error"] is None, \
        f"error should be None when up, got {result['error']!r}"


# ── D02: LAPI 404 → reachable=True (older LAPI) ──────────────────────────

@pytest.mark.asyncio
async def test_d02_lapi_404_reports_reachable_unknown_version():
    """HTTP 404 on /v1/heartbeat = older LAPI without the endpoint.
    Must still mark reachable=True so the card doesn't falsely show 'down'."""
    async def _not_found(req):
        return web.Response(status=404)

    async with _mock_lapi(_not_found) as lapi_url, _patched_cs(lapi_url, "testkey"):
        result = await _crowdsec_lapi_health()

    assert result["reachable"] is True, \
        "HTTP 404 should mark reachable=True (older LAPI)"
    assert result["version"] and "unknown" in result["version"].lower(), \
        f"version should contain 'unknown', got {result['version']!r}"


# ── D03: LAPI down → reachable=False, error present ──────────────────────

@pytest.mark.asyncio
async def test_d03_lapi_down_reports_unreachable():
    """Connection refused to LAPI → reachable=False, error non-empty."""
    async with _patched_cs("http://127.0.0.1:19999", "testkey"):
        result = await _crowdsec_lapi_health()

    assert result["reachable"] is False, \
        f"Unreachable LAPI → reachable should be False, got {result['reachable']!r}"
    assert result["error"], \
        "Unreachable LAPI should produce a non-empty error string"


# ── D04: not configured → reachable=None ─────────────────────────────────

@pytest.mark.asyncio
async def test_d04_not_configured_reachable_is_none():
    """No LAPI configured → reachable=None (not False) to distinguish
    'unconfigured' from 'configured but down'."""
    async with _patched_cs("", ""):
        result = await _crowdsec_lapi_health()

    assert result["reachable"] is None, \
        f"Unconfigured → reachable should be None, got {result['reachable']!r}"
    assert result["error"] == "not configured", \
        f"error should be 'not configured', got {result['error']!r}"


# ── D05: result is cached (second call skips LAPI) ───────────────────────

@pytest.mark.asyncio
async def test_d05_health_result_is_cached():
    """Second call within TTL must return cached result — no second HTTP call."""
    call_count = 0

    async def _counting(req):
        nonlocal call_count
        call_count += 1
        return web.json_response({"version": "v1.6.0"})

    async with _mock_lapi(_counting) as lapi_url, _patched_cs(lapi_url, "testkey"):
        await _crowdsec_lapi_health()   # first — hits LAPI
        await _crowdsec_lapi_health()   # second — must use cache

    assert call_count == 1, (
        f"_crowdsec_lapi_health() made {call_count} LAPI calls for 2 invocations "
        "— result must be cached for _CROWDSEC_HEALTH_TTL seconds."
    )


# ── D06: LAPI 500 → reachable=False, error mentions status ───────────────

@pytest.mark.asyncio
async def test_d06_lapi_500_reports_error():
    """HTTP 5xx from LAPI → reachable=False, error string contains status code."""
    async def _server_err(req):
        return web.Response(status=500)

    async with _mock_lapi(_server_err) as lapi_url, _patched_cs(lapi_url, "testkey"):
        result = await _crowdsec_lapi_health()

    assert result["reachable"] is False, \
        f"HTTP 500 → reachable should be False, got {result['reachable']!r}"
    assert result["error"] and "500" in result["error"], \
        f"error should mention '500', got {result['error']!r}"


# ── D07: gateway integration — lapi_health key present in Controls page ──

@pytest.mark.asyncio
async def test_d07_lapi_health_present_in_external_endpoint(proxy_module):
    """/__integrations response must include lapi_health in the CrowdSec card.
    Tested without a live LAPI so reachable=None (not configured in session)."""
    from aiohttp.test_utils import TestClient, TestServer

    async def _echo(request: web.Request):
        return web.json_response({"ok": True})

    upstream_app = web.Application()
    upstream_app.router.add_route("*", "/{tail:.*}", _echo)
    runner = web.AppRunner(upstream_app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    upstream_url = f"http://127.0.0.1:{port}"

    proxy_module.UPSTREAM = upstream_url
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()

    # Build admin session cookie
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    token = proxy_module._session_sign("admin", sid=sid)
    cookies = {proxy_module._SESSION_COOKIE: token}

    r = await client.get(f"{NS}/external", cookies=cookies)
    assert r.status == 200, f"GET /secured/external returned {r.status}"
    data = await r.json()
    cs = next((i for i in data["integrations"] if i.get("name") == "CrowdSec"), None)
    assert cs, "CrowdSec card missing from /secured/external response"
    assert "lapi_health" in cs, (
        "CrowdSec card missing 'lapi_health' key — Controls page cannot show LAPI status"
    )
    health = cs["lapi_health"]
    assert set(health.keys()) >= {"reachable", "ping_ms", "version", "error"}, \
        f"lapi_health missing required keys: {set(health.keys())!r}"

    await client.close()
    await runner.cleanup()
