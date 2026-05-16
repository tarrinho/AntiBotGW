"""
Tests for the geo dashboard and the loading/ready status pill (v1.7.7).

Coverage:
  • Unit — static analysis of geo.html: pill HTML, CSS, and JS are present
            and correctly structured in the file served by the gateway.
  • Functional — /secured/geo (HTML page) and /secured/geo-data (API)
                 behave correctly: response shape, param validation,
                 security headers, unconfigured path.
  • Regression — previous geo-data keys + geo dashboard features not broken
                 by the pill addition.

Auth-guard tests follow the content-check pattern from test_dashboard_data.py:
  assert r.status != 200 or <expected-content> not in text
because in the test env ADMIN_ALLOWED_IPS="" causes operator bypass from
127.0.0.1, so the session gate is not enforced.

MAXMIND-dependent tests patch core.proxy_handler attributes INSIDE the
`async with _spin_proxy` block — i.e. after client.start_server() completes.
This is required because on_startup calls _init_maxmind() and then propagates
MAXMIND_ENABLED / MAXMIND_CITY_ENABLED to every loaded module, overwriting
any pre-startup monkeypatch. Patching after startup and clearing _GEO_CACHE
ensures geo_data_endpoint takes the configured code path.
"""
import asyncio
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


# ── Helpers ──────────────────────────────────────────────────────────────

async def _echo_handler(request: web.Request):
    return web.json_response({"path": request.path})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _echo_handler)
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


def _make_admin_session(proxy_module):
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


NS = "/antibot-appsec-gateway/secured"

# Static geo.html file — unit tests read it directly.
_GEO_HTML = Path(__file__).resolve().parent.parent / "dashboards" / "geo.html"

# Dummy _city_lookup return value (Paris).
_PARIS = (48.8566, 2.3522, "FR", "Paris")


def _enable_maxmind_after_startup():
    """Patch core.proxy_handler after startup so geo_data_endpoint takes the
    configured code path.  Returns (orig_enabled, orig_lookup, orig_asn) for
    the caller to restore in a finally block.

    Must be called inside `async with _spin_proxy` — i.e. after start_server()
    has completed and on_startup has propagated MAXMIND state."""
    import core.proxy_handler as cph
    orig_enabled = cph.MAXMIND_CITY_ENABLED
    orig_lookup  = cph._city_lookup
    orig_asn     = cph.MAXMIND_ENABLED
    cph.MAXMIND_CITY_ENABLED = True
    cph._city_lookup         = lambda ip: _PARIS
    cph.MAXMIND_ENABLED      = False
    cph._GEO_CACHE.clear()
    return orig_enabled, orig_lookup, orig_asn


def _restore_maxmind(orig_enabled, orig_lookup, orig_asn):
    import core.proxy_handler as cph
    cph.MAXMIND_CITY_ENABLED = orig_enabled
    cph._city_lookup         = orig_lookup
    cph.MAXMIND_ENABLED      = orig_asn
    cph._GEO_CACHE.clear()


# ═══════════════════════════════════════════════════════════════════════════
# UNIT TESTS — static analysis of geo.html
# ═══════════════════════════════════════════════════════════════════════════

class TestGeoPillHTML:
    """Verify the pill feature was correctly applied to the HTML source."""

    @pytest.fixture(scope="class")
    def html(self):
        return _GEO_HTML.read_text()

    def test_load_status_element_present(self, html):
        assert 'id="load-status"' in html

    def test_pill_starts_without_ready_class(self, html):
        """The opening tag of load-status must NOT include the 'ready' class —
        only JS adds it after the first successful fetch."""
        match = re.search(r'<span[^>]+id="load-status"[^>]*>', html)
        assert match, "load-status span not found"
        assert "ready" not in match.group(0)

    def test_pill_initial_text_contains_loading(self, html):
        """The full pill element must contain 'Loading' in the initial HTML —
        the JS only changes it to 'Loading Ready'."""
        idx = html.find('id="load-status"')
        assert idx != -1
        # Scan forward enough to include the text node after the inner span
        snippet = html[idx: idx + 200]
        assert "Loading" in snippet

    def test_pill_initial_html_not_loading_ready(self, html):
        """'Loading Ready' must NOT appear inside the static pill element —
        it is injected by JS only after the first successful tick()."""
        idx = html.find('id="load-status"')
        assert idx != -1
        snippet = html[idx: idx + 100]
        assert "Loading Ready" not in snippet

    def test_pill_dot_span_present(self, html):
        assert 'class="dot"' in html

    def test_css_load_status_rule_exists(self, html):
        assert "#load-status{" in html or "#load-status {" in html

    def test_css_ready_variant_exists(self, html):
        assert "#load-status.ready{" in html or "#load-status.ready {" in html

    def test_css_dot_animation_exists(self, html):
        assert "#load-status .dot{" in html or "#load-status .dot {" in html

    def test_css_keyframe_ls_pulse_exists(self, html):
        assert "@keyframes ls-pulse" in html

    def test_css_transition_property_present(self, html):
        """Pill CSS block must declare a transition for the color animation."""
        for needle in ("#load-status{", "#load-status {"):
            idx = html.find(needle)
            if idx != -1:
                block = html[idx: idx + 400]
                assert "transition:" in block or "transition :" in block
                return
        pytest.fail("#load-status CSS rule not found")

    def test_js_flip_logic_present(self, html):
        assert "classList.add('ready')" in html or 'classList.add("ready")' in html

    def test_js_flip_sets_loading_ready_text(self, html):
        assert "Loading Ready" in html

    def test_js_flip_inside_double_raf(self, html):
        """Flip must be wrapped in double requestAnimationFrame to ensure DOM
        paint before state change (matching controls.html pattern)."""
        assert html.count("requestAnimationFrame") >= 2

    def test_js_flip_idempotent_check(self, html):
        """Guard with !s.classList.contains('ready') prevents re-ticks from
        resetting the text after it has already been set."""
        assert "classList.contains('ready')" in html

    def test_pill_positioned_before_world_map_text(self, html):
        """The pill must appear before 'World-map of accesses' in source order
        and inside the same h2 element."""
        pill_pos = html.find('id="load-status"')
        text_pos = html.find("World-map of accesses")
        assert pill_pos != -1
        assert text_pos != -1
        assert pill_pos < text_pos, \
            "load-status pill must precede 'World-map of accesses' text"
        h2_start = html.rfind("<h2", 0, pill_pos)
        h2_end   = html.find("</h2>", pill_pos)
        assert h2_start != -1 and h2_end != -1
        assert h2_start < text_pos < h2_end, \
            "'World-map of accesses' must be in the same h2 as the pill"

    def test_pill_yellow_border_color(self, html):
        """Initial pill state must use the --yellow CSS variable."""
        for needle in ("#load-status{", "#load-status {"):
            idx = html.find(needle)
            if idx != -1:
                block = html[idx: idx + 400]
                assert "var(--yellow)" in block
                return
        pytest.fail("#load-status CSS rule not found")

    def test_ready_class_uses_green(self, html):
        """Ready state must use the --green CSS variable."""
        for needle in ("#load-status.ready{", "#load-status.ready {"):
            idx = html.find(needle)
            if idx != -1:
                block = html[idx: idx + 200]
                assert "var(--green)" in block
                return
        pytest.fail("#load-status.ready CSS rule not found")


# ═══════════════════════════════════════════════════════════════════════════
# FUNCTIONAL TESTS — /secured/geo (HTML page)
# ═══════════════════════════════════════════════════════════════════════════

class TestGeoDashboardPage:

    def test_geo_page_auth_guard(self, proxy_module):
        """Unauthenticated request must not serve the full dashboard.
        Content-check pattern: status != 200 OR dashboard marker absent."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/geo")
                    body = await r.text()
                    assert r.status != 200 or 'id="load-status"' not in body
        _run(go())

    def test_geo_page_serves_html_with_auth(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/geo",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    assert "text/html" in r.headers.get("Content-Type", "")
        _run(go())

    def test_geo_page_contains_load_status_pill(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/geo",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    assert 'id="load-status"' in body
        _run(go())

    def test_geo_page_pill_starts_loading(self, proxy_module):
        """Served HTML must have the pill in the loading (non-ready) state."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/geo",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    match = re.search(r'<span[^>]+id="load-status"[^>]*>', body)
                    assert match, "load-status pill element missing in served HTML"
                    assert "ready" not in match.group(0)
        _run(go())

    def test_geo_page_no_store_header(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/geo",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert "no-store" in r.headers.get("Cache-Control", "")
        _run(go())

    def test_geo_page_x_frame_options_deny(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/geo",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.headers.get("X-Frame-Options") == "DENY"
        _run(go())


# ═══════════════════════════════════════════════════════════════════════════
# FUNCTIONAL TESTS — /secured/geo-data (data API the pill depends on)
# ═══════════════════════════════════════════════════════════════════════════

class TestGeoDataAPI:

    def test_geo_data_auth_guard(self, proxy_module):
        """Content-check: status != 200 OR structured geo data absent."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/geo-data")
                    text = await r.text()
                    assert r.status != 200 or "countries" not in text
        _run(go())

    def test_geo_data_returns_200_with_auth(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/geo-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_geo_data_always_has_configured_key(self, proxy_module):
        """'configured' must always be present so the JS can branch on it."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/geo-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "configured" in d
        _run(go())

    def test_geo_data_always_has_points_key(self, proxy_module):
        """'points' must always be present (empty list when unconfigured)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/geo-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "points" in d
                    assert isinstance(d["points"], list)
        _run(go())

    def test_geo_data_unconfigured_returns_configured_false(self, proxy_module):
        """When MAXMIND_CITY_ENABLED is False the endpoint returns
        configured=False with a hint so JS tick() can exit gracefully."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import core.proxy_handler as cph
                    # Startup has already set MAXMIND_CITY_ENABLED=False in test
                    # env (no mmdb files); verify the endpoint handles it cleanly.
                    orig = cph.MAXMIND_CITY_ENABLED
                    cph.MAXMIND_CITY_ENABLED = False
                    cph._GEO_CACHE.clear()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        assert r.status == 200
                        d = await r.json()
                        assert d.get("configured") is False
                        assert "hint" in d
                    finally:
                        cph.MAXMIND_CITY_ENABLED = orig
                        cph._GEO_CACHE.clear()
        _run(go())

    def test_geo_data_unconfigured_hint_mentions_data_path(self, proxy_module):
        """The hint must tell operators where to put the mmdb file."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import core.proxy_handler as cph
                    orig = cph.MAXMIND_CITY_ENABLED
                    cph.MAXMIND_CITY_ENABLED = False
                    cph._GEO_CACHE.clear()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        assert "/data" in d.get("hint", "")
                    finally:
                        cph.MAXMIND_CITY_ENABLED = orig
                        cph._GEO_CACHE.clear()
        _run(go())

    def test_geo_data_no_store_header(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/geo-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert "no-store" in r.headers.get("Cache-Control", "")
        _run(go())

    # ── Tests requiring the full (configured) response path ───────────────
    # Patch after startup (inside _spin_proxy) so on_startup propagation
    # does not overwrite the patch.  Always restore in finally.

    def test_geo_data_top_level_keys_when_configured(self, proxy_module):
        """All keys the geo JS tick() function reads must be present."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        for key in ("configured", "points", "countries",
                                    "asns", "events", "geo_state", "summary"):
                            assert key in d, f"missing top-level key: {key!r}"
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_summary_keys_when_configured(self, proxy_module):
        """summary dict must have all fields the pill and stat counters read."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        summary = d.get("summary", {})
                        for key in (
                            "total_points", "total_events", "total_blocked",
                            "total_missed", "total_clean", "total_tor", "total_dc",
                            "method_totals", "skipped_no_geo",
                            "range_min", "end_epoch", "start_epoch",
                        ):
                            assert key in summary, f"missing summary key: {key!r}"
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_summary_types_when_configured(self, proxy_module):
        """Numeric summary fields must be int or float."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        s = d.get("summary", {})
                        for key in ("total_points", "total_events", "total_blocked",
                                    "total_missed", "total_clean", "total_tor", "total_dc",
                                    "skipped_no_geo", "range_min", "end_epoch", "start_epoch"):
                            assert isinstance(s[key], (int, float)), \
                                f"summary[{key!r}] is not numeric: {type(s[key])}"
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_method_totals_is_dict(self, proxy_module):
        """method_totals feeds renderMethods() which runs before the pill flips."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        assert isinstance(d["summary"]["method_totals"], dict)
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_geo_state_keys(self, proxy_module):
        """geo_state must have the three keys the geo-block UI reads."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        gs = d.get("geo_state", {})
                        assert "country_block_enabled" in gs
                        assert "country_denylist" in gs
                        assert "country_allowlist" in gs
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_start_before_end_epoch(self, proxy_module):
        """start_epoch must be strictly less than end_epoch."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        s = d["summary"]
                        assert s["start_epoch"] < s["end_epoch"]
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_range_param_accepted(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data?range=180",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        assert r.status == 200
                        d = await r.json()
                        assert d["summary"]["range_min"] == 180
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_invalid_range_uses_default(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data?range=banana",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        assert r.status == 200
                        d = await r.json()
                        assert isinstance(d["summary"]["range_min"], int)
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_range_clamped_low(self, proxy_module):
        """range < 5 must clamp to 5."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data?range=1",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        assert r.status == 200
                        d = await r.json()
                        assert d["summary"]["range_min"] >= 5
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_range_clamped_high(self, proxy_module):
        """range > 43200 must clamp to 43200 (30-day max)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data?range=99999",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        assert r.status == 200
                        d = await r.json()
                        assert d["summary"]["range_min"] <= 43200
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_events_is_list(self, proxy_module):
        """events list feeds the time-scrubber playback."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        assert isinstance(d["events"], list)
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_countries_is_list(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        assert isinstance(d["countries"], list)
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_asns_is_list(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        assert isinstance(d["asns"], list)
                    finally:
                        _restore_maxmind(*orig)
        _run(go())


# ═══════════════════════════════════════════════════════════════════════════
# REGRESSION TESTS — existing geo behaviour not broken by the pill addition
# ═══════════════════════════════════════════════════════════════════════════

class TestGeoPillRegression:

    def test_geo_html_still_has_live_pill(self):
        """The existing #live LIVE/ERR indicator must still be present."""
        html = _GEO_HTML.read_text()
        assert 'id="live"' in html

    def test_geo_html_still_has_map_container(self):
        """The Leaflet map container must still be present."""
        html = _GEO_HTML.read_text()
        assert 'id="map"' in html

    def test_geo_html_still_has_country_section(self):
        """Country leaderboard section must still be present."""
        html = _GEO_HTML.read_text()
        assert "country" in html.lower()

    def test_geo_html_version_string_correct(self):
        """Version banner must match docker-compose image tag."""
        html = _GEO_HTML.read_text()
        assert "AppSecGW_1.8.6" in html

    def test_geo_html_tick_function_present(self):
        """tick() is the polling function — the pill flip hangs off it."""
        html = _GEO_HTML.read_text()
        assert "function tick(" in html or "async function tick(" in html

    def test_geo_html_render_map_still_called(self):
        """renderMap() must still be called inside tick() before the pill flip."""
        html = _GEO_HTML.read_text()
        assert "renderMap()" in html

    def test_geo_html_render_asns_before_pill(self):
        """renderAsns() must appear before the pill flip JS in source order —
        the pill only flips after ALL renders have run."""
        html = _GEO_HTML.read_text()
        asns_pos = html.find("renderAsns()")
        flip_pos = html.find("classList.add('ready')")
        if flip_pos == -1:
            flip_pos = html.find('classList.add("ready")')
        assert asns_pos != -1, "renderAsns() call missing"
        assert flip_pos != -1, "pill flip JS missing"
        assert asns_pos < flip_pos, \
            "pill flip must come after renderAsns() in source order"

    def test_geo_html_live_pill_separate_from_load_status(self):
        """#live and #load-status must be distinct elements."""
        html = _GEO_HTML.read_text()
        assert 'id="live"' in html
        assert 'id="load-status"' in html
        assert html.find('id="live"') != html.find('id="load-status"')

    def test_geo_html_css_green_variable_unchanged(self):
        """--green CSS variable must still be defined (used by both pills)."""
        html = _GEO_HTML.read_text()
        assert "--green:" in html or "--green :" in html

    def test_geo_html_css_yellow_variable_unchanged(self):
        """--yellow CSS variable must still be defined (used by load-status)."""
        html = _GEO_HTML.read_text()
        assert "--yellow:" in html or "--yellow :" in html

    def test_geo_data_point_fields_present(self, proxy_module):
        """Each point in the points list must have the fields renderMap() reads."""
        import sqlite3, time as _time
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        import core.proxy_handler as _cph
                        # Seed into the DB path the proxy actually uses (may differ
                        # from os.environ["DB_PATH"] when test_functional.py overrides it).
                        db_path = _cph.DB_PATH
                        conn = sqlite3.connect(db_path)
                        conn.execute(
                            "INSERT INTO events(ts, ip, reason, status) "
                            "VALUES (?, ?, ?, ?)",
                            (int(_time.time()) - 10, "5.6.7.8", "ua", 403))
                        conn.commit()
                        conn.close()
                        _cph._GEO_CACHE.clear()

                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        pts = d.get("points", [])
                        assert pts, "expected at least one point from seeded event"
                        for key in ("lat", "lng", "clean", "missed", "blocked",
                                    "total", "methods", "pin_type",
                                    "tor_hits", "dc_hits", "country", "city"):
                            assert key in pts[0], f"points[0] missing key: {key!r}"
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_data_country_fields_present(self, proxy_module):
        """Each entry in countries must have the fields the leaderboard reads."""
        import sqlite3, time as _time
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        import core.proxy_handler as _cph
                        db_path = _cph.DB_PATH
                        conn = sqlite3.connect(db_path)
                        conn.execute(
                            "INSERT INTO events(ts, ip, reason, status) "
                            "VALUES (?, ?, ?, ?)",
                            (int(_time.time()) - 10, "5.6.7.8", "ua", 403))
                        conn.commit()
                        conn.close()
                        _cph._GEO_CACHE.clear()

                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        countries = d.get("countries", [])
                        assert countries, "expected at least one country from seeded event"
                        for key in ("country", "clean", "missed", "blocked",
                                    "total", "methods", "effectiveness_pct", "bypass_pct"):
                            assert key in countries[0], \
                                f"countries[0] missing: {key!r}"
                    finally:
                        _restore_maxmind(*orig)
        _run(go())


# ═══════════════════════════════════════════════════════════════════════════
# v1.7.10 — scrubber / play-mode cumulative correctness
#
# The aggregate view (scrubBucketIdx=-1) uses lastData.points (full DB query).
# The play/cumulative view builds from lastData.events — a reservoir-sampled
# subset capped at _SCRUBBER_CAP=5000.
#
# Bug: with large event windows, sparse-location IPs may be absent from the
# sample → cumulative frame shows fewer circles than the aggregate.
# These tests pin the contract so the gap is detectable and regressions are caught.
# ═══════════════════════════════════════════════════════════════════════════

class TestGeoScrubberCumulativeCorrectness:

    def _seed(self, proxy_module, rows):
        import sqlite3
        conn = sqlite3.connect(proxy_module.DB_PATH)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS events "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, ua TEXT, "
            "path TEXT, xff TEXT DEFAULT '', status INTEGER DEFAULT 200, reason TEXT DEFAULT '')"
        )
        conn.executemany(
            "INSERT INTO events (ts, ip, ua, path, status, reason) VALUES (?,?,?,?,?,?)",
            rows,
        )
        conn.commit()
        conn.close()

    def test_geo_events_entry_shape(self, proxy_module):
        """Each entry in events must be a 4-element list [ts, lat, lng, kind]
        so rebuildBuckets() can unpack [ts, lat, lng, kind] without error."""
        import time as _time
        self._seed(proxy_module, [
            (int(_time.time()) - 30, "5.6.7.9", "UA", "/path", 200, ""),
        ])

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        import core.proxy_handler as _cph
                        _cph._GEO_CACHE.clear()
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        events = d.get("events", [])
                        assert events, "events list empty — seeded event not found"
                        for ev in events:
                            assert isinstance(ev, list) and len(ev) == 4, (
                                f"each events entry must be [ts, lat, lng, kind], got: {ev!r}"
                            )
                            ts, lat, lng, kind = ev
                            assert isinstance(ts,  (int, float)), f"ts must be numeric, got {ts!r}"
                            assert isinstance(lat, (int, float)), f"lat must be numeric, got {lat!r}"
                            assert isinstance(lng, (int, float)), f"lng must be numeric, got {lng!r}"
                            assert kind in ("clean", "blocked", "authorized_robot"), (
                                f"kind must be clean/blocked/authorized_robot, got {kind!r}"
                            )
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_events_summary_has_start_and_end_epoch(self, proxy_module):
        """summary must include start_epoch and end_epoch so rebuildBuckets()
        can compute correct bucket boundaries without falling back to events[0][0]."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        import core.proxy_handler as _cph
                        _cph._GEO_CACHE.clear()
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        sm = d.get("summary", {})
                        assert "start_epoch" in sm, (
                            "summary missing start_epoch — rebuildBuckets() will fall back "
                            "to events[0][0] which may be wrong if events are unsorted"
                        )
                        assert "end_epoch" in sm, "summary missing end_epoch"
                        assert sm["end_epoch"] >= sm["start_epoch"], (
                            "summary end_epoch must be >= start_epoch"
                        )
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_events_cap_at_scrubber_limit(self, proxy_module):
        """When total geo-resolved events exceed _SCRUBBER_CAP (5000), the events
        list must be capped at ≤ 5000 entries — prevents unbounded payload growth."""
        import time as _time
        now = int(_time.time())
        rows = [(now - i, "5.6.7.8", "UA", "/path", 200, "") for i in range(6000)]
        self._seed(proxy_module, rows)

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        import core.proxy_handler as _cph
                        _cph._GEO_CACHE.clear()
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data?range=1440",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        events = d.get("events", [])
                        assert len(events) <= 5000, (
                            f"events must be capped at 5000 (SCRUBBER_CAP), got {len(events)}"
                        )
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_events_small_dataset_locations_complete(self, proxy_module):
        """With fewer events than SCRUBBER_CAP and multiple distinct locations,
        every location in points must also appear in events (within 0.26° tolerance)
        — ensuring the cumulative play view shows the same circles as the aggregate.

        This is the core regression guard for the 'play shows fewer circles
        than aggregate' bug."""
        import time as _time
        import core.proxy_handler as _cph
        now = int(_time.time())

        LOCS = {
            "11.11.11.11": (48.8566,  2.3522,  "FR", "Paris"),
            "22.22.22.22": (51.5074, -0.1278,  "GB", "London"),
            "33.33.33.33": (40.7128, -74.0060, "US", "New York"),
        }
        rows = []
        for ip in LOCS:
            for i in range(5):
                rows.append((now - i * 10, ip, "UA", "/path", 200, ""))
        self._seed(proxy_module, rows)

        def _multi_city_lookup(ip):
            return LOCS.get(ip)

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig_enabled = _cph.MAXMIND_CITY_ENABLED
                    orig_lookup  = _cph._city_lookup
                    orig_asn     = _cph.MAXMIND_ENABLED
                    _cph.MAXMIND_CITY_ENABLED = True
                    _cph._city_lookup         = _multi_city_lookup
                    _cph.MAXMIND_ENABLED      = False
                    _cph._GEO_CACHE.clear()
                    try:
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        events = d.get("events", [])
                        points = d.get("points", [])

                        ev_coords = {(round(e[1]*2)/2, round(e[2]*2)/2) for e in events}
                        pt_coords = set()
                        for p in points:
                            if p.get("clean", 0) + p.get("blocked", 0) + p.get("authorized_robot", 0) > 0:
                                pt_coords.add((round(p["lat"]*2)/2, round(p["lng"]*2)/2))

                        missing = pt_coords - ev_coords
                        assert not missing, (
                            f"Locations in aggregate (points) missing from events — "
                            f"play/cumulative will show fewer circles than aggregate: {missing}\n"
                            f"events coords: {ev_coords}  points coords: {pt_coords}"
                        )
                    finally:
                        _cph.MAXMIND_CITY_ENABLED = orig_enabled
                        _cph._city_lookup         = orig_lookup
                        _cph.MAXMIND_ENABLED      = orig_asn
                        _cph._GEO_CACHE.clear()
        _run(go())

    def test_geo_events_kind_never_missed(self, proxy_module):
        """'missed' must never appear as a kind in events — missed is derived from
        live in-memory state, not DB events, so it cannot be replayed in the scrubber."""
        import time as _time
        self._seed(proxy_module, [
            (int(_time.time()) - 5, "5.6.7.8", "UA", "/path", 200, ""),
        ])

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    orig = _enable_maxmind_after_startup()
                    try:
                        import core.proxy_handler as _cph
                        _cph._GEO_CACHE.clear()
                        cookie = _make_admin_session(proxy_module)
                        r = await c.get(NS + "/geo-data",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        for ev in d.get("events", []):
                            assert ev[3] != "missed", (
                                "events must not contain kind='missed' — "
                                "missed is live-state derived and cannot appear in the scrubber"
                            )
                    finally:
                        _restore_maxmind(*orig)
        _run(go())

    def test_geo_html_scrubber_missed_warning_present(self):
        """geo.html must contain the scrubber tooltip warning that missed events
        are not available in scrubber mode — so operators understand why the play
        view differs from the aggregate view."""
        html = _GEO_HTML.read_text()
        assert "missed N/A in scrubber" in html, (
            "geo.html: scrubber tooltip warning 'missed N/A in scrubber' missing — "
            "operators need to know why play-mode shows fewer circles than the aggregate"
        )

    def test_geo_html_rebuildBuckets_prefers_summary_epoch(self):
        """rebuildBuckets() must prefer sm.start_epoch over events[0][0] as the
        bucket boundary — unsorted events would produce wrong bins if events[0][0]
        is not the minimum timestamp."""
        html = _GEO_HTML.read_text()
        idx = html.index("function rebuildBuckets")
        body = html[idx: idx + 600]
        assert "sm.start_epoch" in body, (
            "rebuildBuckets() must read start_epoch from sm (summary), "
            "not only from events[0][0]"
        )
        assert "sm.start_epoch || lastData.events[0][0]" in body, (
            "rebuildBuckets() must use 'sm.start_epoch || lastData.events[0][0]' "
            "so summary epoch takes priority over first-event fallback"
        )
