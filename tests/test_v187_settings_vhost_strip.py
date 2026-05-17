"""
tests/test_v187_settings_vhost_strip.py — QA for the v1.8.7 settings page
gateway identity strip enhancement (vhost + upstream display).

H-tests: HTML structure (static checks on settings.html)
  H01  gw-vhost element present
  H02  gw-upstream element present
  H03  "Vhost" label present above gw-vhost
  H04  "Upstream" label present above gw-upstream
  H05  gw-vhost div uses display:flex for badge layout
  H06  gw-upstream has text-overflow:ellipsis for long URL truncation
  H07  gw-upstream has title attribute placeholder for tooltip
  H08  gateway identity strip card appears before the virtual hosts card

J-tests: JS logic (static checks on settings.html)
  J01  IIFE fetches /secured/health-score
  J02  IIFE fetches /secured/vhosts
  J03  hostname textContent assigned BEFORE the await Promise.all (robustness fix)
  J04  textContent used for hostname (not innerHTML — no escapeHtml dependency)
  J05  badge element created with font-size:9px pill style
  J06  "vhost" badge state (registered with own upstream)
  J07  "global" badge state (registered, inherits global)
  J08  "unregistered" badge state (not in vhost table)
  J09  vhostUpstream read from entry.UPSTREAM
  J10  global upstream fallback uses j.upstream from health-score
  J11  upstream set on gw-upstream via textContent
  J12  upstream title attribute populated for tooltip
  J13  badge appended to gw-vhost with appendChild
  J14  catch logs via console.error, not silently discarded

A-tests: API contract (source-level, no server)
  A01  health_score_endpoint emits "upstream" key in JSON
  A02  health_score_endpoint references UPSTREAM module variable

V-tests: vhost_list() and vhosts_endpoint format
  V01  vhost_list() returns a list
  V02  vhost_list() empty when VHOSTS dict is empty
  V03  vhost list entry contains "hostname" key
  V04  vhost list entry contains UPSTREAM value when set
  V05  vhosts_endpoint GET wraps list in {"vhosts": [...]}
"""
import os
import sys
import re
import tempfile
from pathlib import Path

import pytest

# ── env / path setup ─────────────────────────────────────────────────────────

_TMP = tempfile.mkdtemp(prefix="appsecgw-v187-strip-")
os.environ.setdefault("UPSTREAM",  "https://backend.example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "antibot-v187-strip.db"))

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

_DASHBOARDS = Path(_ROOT) / "dashboards"


def _settings() -> str:
    return (_DASHBOARDS / "settings.html").read_text(encoding="utf-8")


# ── helpers ───────────────────────────────────────────────────────────────────

def _iife_block(src: str) -> str:
    """Return the text of the gateway identity strip IIFE."""
    marker = "Gateway identity strip"
    idx = src.find(marker)
    if idx == -1:
        return ""
    # Grab from the marker to the next top-level IIFE close `})();`
    tail = src[idx:]
    end = tail.find("})();")
    return tail[:end + 5] if end != -1 else tail[:3000]


# ── H: HTML structure ─────────────────────────────────────────────────────────

class TestSettingsVhostStripHTML:
    def setup_method(self):
        self.src = _settings()

    def test_h01_gw_vhost_element_present(self):
        assert 'id="gw-vhost"' in self.src, "gw-vhost element missing from settings.html"

    def test_h02_gw_upstream_element_present(self):
        assert 'id="gw-upstream"' in self.src, "gw-upstream element missing from settings.html"

    def test_h03_vhost_label_present(self):
        assert "Vhost" in self.src, '"Vhost" label missing from settings.html identity strip'

    def test_h04_upstream_label_present(self):
        assert "Upstream" in self.src, '"Upstream" label missing from settings.html identity strip'

    def test_h05_gw_vhost_uses_flex_for_badge(self):
        """gw-vhost must use display:flex so the hostname and badge sit inline."""
        vhost_tag = re.search(r'<div[^>]*id="gw-vhost"[^>]*>', self.src)
        assert vhost_tag, "gw-vhost element not found"
        tag_text = vhost_tag.group(0)
        assert "display:flex" in tag_text or "display: flex" in tag_text, (
            "gw-vhost must have display:flex for badge layout"
        )

    def test_h06_gw_upstream_has_ellipsis(self):
        """gw-upstream must truncate long upstream URLs with text-overflow:ellipsis."""
        upstream_tag = re.search(r'<div[^>]*id="gw-upstream"[^>]*>', self.src)
        assert upstream_tag, "gw-upstream element not found"
        tag_text = upstream_tag.group(0)
        assert "text-overflow:ellipsis" in tag_text or "text-overflow: ellipsis" in tag_text, (
            "gw-upstream must have text-overflow:ellipsis for long URL truncation"
        )

    def test_h07_gw_upstream_has_title_attribute(self):
        """gw-upstream must have a title attribute for the full-URL tooltip."""
        upstream_tag = re.search(r'<div[^>]*id="gw-upstream"[^>]*>', self.src)
        assert upstream_tag, "gw-upstream element not found"
        assert 'title=""' in upstream_tag.group(0) or "title=" in upstream_tag.group(0), (
            "gw-upstream must have a title attribute (populated by JS with full URL)"
        )

    def test_h08_strip_before_vhosts_card(self):
        """Identity strip card must appear before the Virtual Hosts card."""
        vhost_strip_pos = self.src.find('id="gw-vhost"')
        vhosts_card_pos = self.src.find('id="card-vhosts"')
        assert vhost_strip_pos != -1, "gw-vhost not found"
        assert vhosts_card_pos != -1, "card-vhosts not found"
        assert vhost_strip_pos < vhosts_card_pos, (
            "Gateway identity strip must appear before the Virtual Hosts card"
        )


# ── J: JS logic ───────────────────────────────────────────────────────────────

class TestSettingsVhostStripJS:
    def setup_method(self):
        self.src = _settings()
        self.iife = _iife_block(self.src)

    def test_j01_iife_fetches_health_score(self):
        assert "health-score" in self.iife, (
            "Gateway identity strip IIFE must fetch /secured/health-score"
        )

    def test_j02_iife_fetches_vhosts(self):
        assert "/secured/vhosts" in self.iife, (
            "Gateway identity strip IIFE must fetch /secured/vhosts for registration lookup"
        )

    def test_j03_hostname_before_await(self):
        """Hostname must be set BEFORE the await so it shows even if fetches fail."""
        hostname_pos = self.iife.find('$("gw-vhost").textContent')
        await_pos    = self.iife.find("await Promise.all")
        assert hostname_pos != -1, '$("gw-vhost").textContent assignment not found in IIFE'
        assert await_pos    != -1, "await Promise.all not found in IIFE"
        assert hostname_pos < await_pos, (
            "Hostname textContent must be assigned BEFORE await Promise.all — "
            "so the hostname always shows even if the fetch fails"
        )

    def test_j04_hostname_uses_text_content_not_inner_html(self):
        """textContent is safe and doesn't require escapeHtml to be pre-defined."""
        assert '$("gw-vhost").textContent' in self.iife, (
            "hostname must use .textContent (not .innerHTML) to avoid escapeHtml dependency"
        )
        assert '$("gw-vhost").innerHTML' not in self.iife, (
            "gw-vhost must not use .innerHTML for hostname — use .textContent"
        )

    def test_j05_badge_created_as_span(self):
        assert 'createElement("span")' in self.iife or "createElement('span')" in self.iife, (
            "badge must be created as a <span> element"
        )

    def test_j06_vhost_badge_state(self):
        """Badge shows 'vhost' when the current host has its own upstream override."""
        assert '"vhost"' in self.iife or "'vhost'" in self.iife, (
            "IIFE must have a 'vhost' badge state for registered hosts with own upstream"
        )

    def test_j07_global_badge_state(self):
        """Badge shows 'global' when registered but inheriting the global upstream."""
        assert '"global"' in self.iife or "'global'" in self.iife, (
            "IIFE must have a 'global' badge state for registered hosts without own upstream"
        )

    def test_j08_unregistered_badge_state(self):
        """Badge shows 'unregistered' when the host has no vhost table entry."""
        assert '"unregistered"' in self.iife or "'unregistered'" in self.iife, (
            "IIFE must have an 'unregistered' badge state"
        )

    def test_j09_vhost_upstream_from_entry(self):
        """Vhost-specific upstream is read from entry.UPSTREAM."""
        assert "entry.UPSTREAM" in self.iife, (
            "IIFE must read vhost-specific upstream from entry.UPSTREAM"
        )

    def test_j10_global_upstream_fallback(self):
        """Global upstream fallback uses j.upstream from health-score."""
        assert "j.upstream" in self.iife, (
            "IIFE must fall back to j.upstream (global UPSTREAM from health-score)"
        )

    def test_j11_upstream_set_on_element(self):
        """Upstream value is written to gw-upstream via textContent."""
        assert '$("gw-upstream")' in self.iife or 'upEl' in self.iife, (
            "IIFE must write the upstream URL to the gw-upstream element"
        )
        assert "upEl.textContent" in self.iife, (
            "upstream must be set via .textContent on the gw-upstream element"
        )

    def test_j12_upstream_title_populated(self):
        """gw-upstream title attribute is populated for the full-URL tooltip."""
        assert "upEl.title" in self.iife, (
            "IIFE must populate upEl.title for the full-URL tooltip on gw-upstream"
        )

    def test_j13_badge_appended_to_gw_vhost(self):
        """Badge span is appended to gw-vhost so hostname and badge appear inline."""
        assert '$("gw-vhost").appendChild(badge)' in self.iife, (
            "IIFE must append the badge span to gw-vhost"
        )

    def test_j14_catch_logs_to_console(self):
        """Errors must be logged via console.error, not silently swallowed."""
        assert "console.error" in self.iife, (
            "IIFE catch block must call console.error — silent catch hides bugs"
        )


# ── A: API contract (source-level) ───────────────────────────────────────────

class TestHealthScoreUpstreamField:
    def test_a01_health_score_emits_upstream_key(self):
        """health_score_endpoint must include 'upstream' in its JSON response."""
        import inspect
        import importlib
        ph = importlib.import_module("core.proxy_handler")
        src = inspect.getsource(ph.health_score_endpoint)
        assert '"upstream"' in src, (
            "health_score_endpoint must emit 'upstream' key — settings page depends on it"
        )

    def test_a02_health_score_references_upstream_variable(self):
        """The upstream key must reference the UPSTREAM module variable."""
        import inspect
        import importlib
        ph = importlib.import_module("core.proxy_handler")
        src = inspect.getsource(ph.health_score_endpoint)
        assert '"upstream":' in src and "UPSTREAM" in src, (
            "health_score_endpoint must map 'upstream' to the UPSTREAM config variable"
        )


# ── V: vhost_list() and endpoint format ──────────────────────────────────────

class TestVhostListFormat:
    def setup_method(self):
        """Clear VHOSTS before each test for isolation."""
        import vhost as vh
        self._orig = dict(vh.VHOSTS)
        vh.VHOSTS.clear()

    def teardown_method(self):
        import vhost as vh
        vh.VHOSTS.clear()
        vh.VHOSTS.update(self._orig)

    def test_v01_vhost_list_returns_list(self):
        from vhost import vhost_list
        result = vhost_list()
        assert isinstance(result, list), "vhost_list() must return a list"

    def test_v02_vhost_list_empty_when_no_vhosts(self):
        from vhost import vhost_list
        assert vhost_list() == [], "vhost_list() must return [] when VHOSTS is empty"

    def test_v03_vhost_entry_has_hostname_key(self):
        """JS depends on entry.hostname for vhost matching."""
        import vhost as vh
        from vhost import vhost_list
        vh.VHOSTS["app.example.com"] = {"UPSTREAM": "https://backend.example.com"}
        entries = vhost_list()
        assert len(entries) == 1
        assert "hostname" in entries[0], (
            "vhost_list() entries must include 'hostname' key — JS uses entry.hostname"
        )
        assert entries[0]["hostname"] == "app.example.com"

    def test_v04_vhost_entry_has_upstream_key(self):
        """JS reads entry.UPSTREAM for per-vhost upstream override."""
        import vhost as vh
        from vhost import vhost_list
        vh.VHOSTS["shop.example.com"] = {"UPSTREAM": "https://shop-backend.example.com"}
        entries = vhost_list()
        assert len(entries) == 1
        assert "UPSTREAM" in entries[0], (
            "vhost_list() entries must include 'UPSTREAM' key — JS reads entry.UPSTREAM"
        )
        assert entries[0]["UPSTREAM"] == "https://shop-backend.example.com"

    def test_v05_vhosts_endpoint_wraps_in_vhosts_key(self):
        """GET /secured/vhosts must return {"vhosts": [...]} — JS does vd.vhosts."""
        import inspect
        from admin.settings import vhosts_endpoint
        src = inspect.getsource(vhosts_endpoint)
        assert '"vhosts"' in src and "vhost_list()" in src, (
            'vhosts_endpoint GET must return {"vhosts": vhost_list()} — '
            "JS accesses vd.vhosts"
        )
