# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1813_external_js_guards.py

Guards for the two external JavaScript dependencies:
  • Leaflet (geo dashboard, unpkg CDN) — must show a visible on-page error when
    it fails to load instead of a silently-broken page.
  • Cloudflare Turnstile (challenge page) — optional SRI pin (TURNSTILE_SRI) +
    fail-closed when the loader script can't load / fails its integrity check.
"""
import pathlib

import pytest
from aiohttp.test_utils import make_mocked_request

_ROOT = pathlib.Path(__file__).parent.parent


# ── Leaflet (geo dashboard) ───────────────────────────────────────────────────
def _geo_html() -> str:
    return (_ROOT / "dashboards" / "geo.html").read_text(encoding="utf-8")


def test_leaflet_still_loaded_from_cdn_with_sri():
    html = _geo_html()
    assert "unpkg.com/leaflet" in html, "Leaflet still loaded from unpkg (kept as-is)"
    # SRI must remain on the external script
    assert 'integrity="sha256-' in html.split("leaflet.js")[1][:200] or \
           "integrity=" in html, "Leaflet <script> must keep its SRI hash"


def test_leaflet_failure_flag_on_script_tag():
    html = _geo_html()
    blk = html.split("leaflet.js")[1][:200]
    assert "onerror=" in blk and "__leafletFailed" in blk, \
        "Leaflet <script> must set a failure flag via onerror"


def test_leaflet_error_banner_and_guard_present():
    html = _geo_html()
    assert 'id="map-load-error"' in html, "missing the visible map-load-error banner"
    assert "Map library failed to load" in html, "banner must explain the failure"
    # the init must guard on L being undefined / the failure flag and reveal banner
    assert "typeof L === 'undefined'" in html or "typeof L==='undefined'" in html, \
        "map init must guard for missing Leaflet"
    assert "map-load-error" in html.split("L.map('map'")[0][-800:], \
        "guard that reveals the banner must run before L.map() is called"


# ── Turnstile (challenge page) ────────────────────────────────────────────────
def test_turnstile_sri_knob_exists():
    import config
    assert hasattr(config, "TURNSTILE_SRI"), "TURNSTILE_SRI config knob missing"


def test_turnstile_script_has_onerror_failclosed():
    src = (_ROOT / "challenge" / "js_challenge.py").read_text(encoding="utf-8")
    # script tag must carry the integrity slot + onerror fail flag
    assert "__TS_INTEGRITY__" in src, "Turnstile script must template an integrity slot"
    assert 'onerror="window.__tsLoadFailed=true"' in src, "Turnstile script needs onerror"
    # waitForTurnstile must reject immediately on the load-failure flag
    assert "window.__tsLoadFailed" in src and "reject(new Error('security challenge script blocked" in src, \
        "Turnstile must fail closed/fast when the loader is blocked"


@pytest.mark.asyncio
async def test_turnstile_render_default_no_integrity(monkeypatch):
    import challenge.js_challenge as jc
    monkeypatch.setattr(jc, "TURNSTILE_SRI", "")
    monkeypatch.setattr(jc, "TURNSTILE_SITEKEY", "1x00000000000000000000AA")
    body = jc._serve_js_challenge(make_mocked_request("GET", "/foo")).body.decode()
    assert "__TS_INTEGRITY__" not in body, "integrity placeholder must be substituted"
    assert "integrity=" not in body.split("api.js")[1][:120], "no integrity when knob empty"
    assert "__tsLoadFailed" in body, "fail-closed onerror present regardless of SRI"


@pytest.mark.asyncio
async def test_turnstile_render_with_sri(monkeypatch):
    import challenge.js_challenge as jc
    monkeypatch.setattr(jc, "TURNSTILE_SRI", "sha384-UNITTESTHASH")
    monkeypatch.setattr(jc, "TURNSTILE_SITEKEY", "1x00000000000000000000AA")
    body = jc._serve_js_challenge(make_mocked_request("GET", "/foo")).body.decode()
    seg = body.split("api.js")[1][:160]
    assert 'integrity="sha384-UNITTESTHASH"' in seg, "SRI hash must be injected when set"
    assert 'crossorigin="anonymous"' in seg, "crossorigin required for SRI on a cross-origin script"
