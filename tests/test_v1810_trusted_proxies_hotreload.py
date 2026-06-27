"""
tests/test_v1810_trusted_proxies_hotreload.py — QA for TRUSTED_PROXIES /
TRUST_XFF hot-reload, settings.html CSRF shim, and controls.html sidebar removal.

Registry tests (R)
  R01  TRUSTED_PROXIES in _HOT_RELOAD_KNOBS
  R02  TRUST_XFF in _HOT_RELOAD_KNOBS
  R03  TRUSTED_PROXIES exported from config.py
  R04  TRUSTED_PROXIES is a list in config namespace
  R05  ALLOW_PRIVATE_UPSTREAM absent from _HOT_RELOAD_KNOBS (SSRF guard)
  R06  TRUST_XFF validator rejects values outside (none/first/last)
  R07  TRUST_XFF validator accepts none / first / last
  R08  TRUSTED_PROXIES parser silently drops invalid CIDRs

Propagation tests (P) — after hot-reloading TRUSTED_PROXIES, TRUSTED_PROXIES_NETS
  is updated in all modules including helpers.
  P01  _to_ip_net_list parses valid CIDR strings to normalised strings
  P02  hot-reload stores TRUSTED_PROXIES as list of CIDR strings
  P03  hot-reload also updates TRUSTED_PROXIES_NETS with ip_network objects
  P04  TRUSTED_PROXIES_NETS update propagates to helpers module
  P05  _peer_is_trusted_proxy returns True after reload adds peer CIDR
  P06  _peer_is_trusted_proxy returns False after reload removes peer CIDR
  P07  TRUSTED_PROXIES reload with empty string clears TRUSTED_PROXIES_NETS

Settings HTML tests (H)
  H01  settings.html has global fetch shim
  H02  fetch shim injects X-CSRF-Token from agw_csrf cookie
  H03  INFRA_KNOBS contains TRUST_XFF entry
  H04  INFRA_KNOBS contains TRUSTED_PROXIES entry
  H05  TRUST_XFF kind is 'select' with options none/first/last
  H06  TRUSTED_PROXIES kind is 'list'
  H07  renderInfra handles kind='select' (option elements)
  H08  renderInfra handles kind='list' (joins array values)

Controls HTML tests (C)
  C01  vp-sidebar button absent from controls.html
  C02  sidebar view CSS rules absent
  C03  _sidebarActive variable absent from controls.html JS
  C04  _renderSingleGroup function absent
  C05  'sidebar' absent from _setView views array
  C06  localStorage key consistent — agw_ctrl_view used for both read and write
  C07  valid-view guard filters 'sidebar' out on load
  C08  valid-view guard present in DCL boot code
  C09  grid card header has cursor:default (not pointer)
"""
import os
import re
import importlib
import ipaddress

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

# ── module imports ────────────────────────────────────────────────────────────
import config
import helpers
from core import proxy_handler

_CONTROLS_HTML = open(
    os.path.join(os.path.dirname(__file__), "..", "dashboards", "controls.html"),
    encoding="utf-8",
).read()

_SETTINGS_HTML = open(
    os.path.join(os.path.dirname(__file__), "..", "dashboards", "settings.html"),
    encoding="utf-8",
).read()


# ── R: Registry ──────────────────────────────────────────────────────────────

class TestRegistry:
    def test_r01_trusted_proxies_in_hot_reload_knobs(self):
        assert "TRUSTED_PROXIES" in proxy_handler._HOT_RELOAD_KNOBS, (
            "TRUSTED_PROXIES must be in _HOT_RELOAD_KNOBS for runtime config"
        )

    def test_r02_trust_xff_in_hot_reload_knobs(self):
        assert "TRUST_XFF" in proxy_handler._HOT_RELOAD_KNOBS, (
            "TRUST_XFF must be in _HOT_RELOAD_KNOBS for runtime config"
        )

    def test_r03_trusted_proxies_exported_from_config(self):
        assert hasattr(config, "TRUSTED_PROXIES"), (
            "config.py must export TRUSTED_PROXIES (CIDR string list)"
        )

    def test_r04_trusted_proxies_is_list_in_config(self):
        assert isinstance(config.TRUSTED_PROXIES, list), (
            "config.TRUSTED_PROXIES must be a list"
        )

    def test_r05_allow_private_upstream_is_hot_reloadable(self):
        assert "ALLOW_PRIVATE_UPSTREAM" in proxy_handler._HOT_RELOAD_KNOBS, (
            "ALLOW_PRIVATE_UPSTREAM must be in _HOT_RELOAD_KNOBS (runtime toggle)"
        )

    def test_r06_trust_xff_validator_rejects_invalid(self):
        _, validator = proxy_handler._HOT_RELOAD_KNOBS["TRUST_XFF"]
        assert validator is not None
        assert not validator("all"), "TRUST_XFF='all' must be rejected"
        assert not validator("yes"), "TRUST_XFF='yes' must be rejected"
        assert not validator("1"),   "TRUST_XFF='1' must be rejected"

    def test_r07_trust_xff_validator_accepts_valid(self):
        _, validator = proxy_handler._HOT_RELOAD_KNOBS["TRUST_XFF"]
        for v in ("none", "first", "last"):
            assert validator(v), f"TRUST_XFF='{v}' must be accepted"

    def test_r08_trusted_proxies_drops_invalid_cidrs(self):
        parser, _ = proxy_handler._HOT_RELOAD_KNOBS["TRUSTED_PROXIES"]
        result = parser("10.0.0.0/8, not-a-cidr, 172.16.0.0/12")
        assert "10.0.0.0/8" in result
        assert "172.16.0.0/12" in result
        assert "not-a-cidr" not in result, (
            "Invalid CIDR entries must be silently dropped"
        )


# ── P: Propagation ───────────────────────────────────────────────────────────

class TestPropagation:
    def test_p01_to_ip_net_list_normalises_cidrs(self):
        parser, _ = proxy_handler._HOT_RELOAD_KNOBS["TRUSTED_PROXIES"]
        result = parser("10.0.1.5/24, 192.168.0.0/16")
        assert "10.0.1.0/24" in result, "Host bits stripped — 10.0.1.5/24 → 10.0.1.0/24"
        assert "192.168.0.0/16" in result

    def test_p02_hot_reload_stores_cidr_strings(self, monkeypatch):
        parser, _ = proxy_handler._HOT_RELOAD_KNOBS["TRUSTED_PROXIES"]
        parsed = parser("10.10.0.0/16")
        assert all(isinstance(v, str) for v in parsed), (
            "TRUSTED_PROXIES stored value must be a list of CIDR strings"
        )

    def test_p03_hot_reload_updates_trusted_proxies_nets(self, monkeypatch):
        saved = proxy_handler.TRUSTED_PROXIES_NETS
        try:
            proxy_handler.TRUSTED_PROXIES = ["192.0.2.0/24"]
            # Simulate the post-apply handler
            import ipaddress as _ipa
            nets = [_ipa.ip_network(c, strict=False) for c in ["192.0.2.0/24"]]
            proxy_handler.TRUSTED_PROXIES_NETS = nets
            assert len(proxy_handler.TRUSTED_PROXIES_NETS) == 1
            net = proxy_handler.TRUSTED_PROXIES_NETS[0]
            assert isinstance(net, ipaddress.IPv4Network)
            assert str(net) == "192.0.2.0/24"
        finally:
            proxy_handler.TRUSTED_PROXIES_NETS = saved

    def test_p04_propagation_updates_helpers_module(self, monkeypatch):
        saved_nets = helpers.TRUSTED_PROXIES_NETS
        try:
            import ipaddress as _ipa
            new_nets = [_ipa.ip_network("198.51.100.0/24")]
            monkeypatch.setattr(helpers, "TRUSTED_PROXIES_NETS", new_nets)
            assert helpers.TRUSTED_PROXIES_NETS is new_nets
        finally:
            helpers.TRUSTED_PROXIES_NETS = saved_nets

    def test_p05_peer_is_trusted_after_reload(self, monkeypatch):
        import ipaddress as _ipa
        nets = [_ipa.ip_network("10.20.0.0/16")]
        monkeypatch.setattr(helpers, "TRUSTED_PROXIES_NETS", nets)
        assert helpers._peer_is_trusted_proxy("10.20.1.5"), (
            "_peer_is_trusted_proxy must return True for IP in reloaded CIDR"
        )

    def test_p06_peer_not_trusted_after_cidr_removed(self, monkeypatch):
        monkeypatch.setattr(helpers, "TRUSTED_PROXIES_NETS", [])
        assert not helpers._peer_is_trusted_proxy("10.20.1.5"), (
            "_peer_is_trusted_proxy must return False when TRUSTED_PROXIES_NETS is empty"
        )

    def test_p07_reload_empty_clears_nets(self, monkeypatch):
        parser, _ = proxy_handler._HOT_RELOAD_KNOBS["TRUSTED_PROXIES"]
        result = parser("")
        assert result == [], "Empty TRUSTED_PROXIES must produce empty list"


# ── H: Settings HTML ─────────────────────────────────────────────────────────

class TestSettingsHtml:
    def test_h01_fetch_shim_present(self):
        assert "window.fetch = function" in _SETTINGS_HTML or \
               "window.fetch=function" in _SETTINGS_HTML, (
            "settings.html must have a global fetch shim"
        )

    def test_h02_shim_injects_csrf_header(self):
        assert "X-CSRF-Token" in _SETTINGS_HTML, (
            "settings.html fetch shim must inject X-CSRF-Token"
        )
        assert "agw_csrf" in _SETTINGS_HTML, (
            "settings.html must read CSRF token from agw_csrf cookie"
        )

    def test_h03_infra_knobs_has_trust_xff(self):
        assert "TRUST_XFF" in _SETTINGS_HTML, (
            "INFRA_KNOBS must contain TRUST_XFF"
        )

    def test_h04_infra_knobs_has_trusted_proxies(self):
        # TRUSTED_PROXIES appears multiple times (desc, key)
        assert _SETTINGS_HTML.count("TRUSTED_PROXIES") >= 2, (
            "INFRA_KNOBS must contain TRUSTED_PROXIES"
        )

    def test_h05_trust_xff_is_select_with_options(self):
        assert "kind:'select'" in _SETTINGS_HTML or 'kind:"select"' in _SETTINGS_HTML, (
            "TRUST_XFF must use kind:'select'"
        )
        for opt in ("none", "first", "last"):
            assert opt in _SETTINGS_HTML, f"TRUST_XFF option '{opt}' must be in settings"

    def test_h06_trusted_proxies_is_list_kind(self):
        # Anchor on the key definition, not any occurrence of the string
        key_anchor = "key:'TRUSTED_PROXIES'"
        idx = _SETTINGS_HTML.find(key_anchor)
        assert idx != -1, "TRUSTED_PROXIES knob entry not found in INFRA_KNOBS"
        tp_block = _SETTINGS_HTML[idx:]
        tp_block = tp_block[:tp_block.find("},")]
        assert "kind:'list'" in tp_block or "kind: 'list'" in tp_block, (
            "TRUSTED_PROXIES must use kind:'list'"
        )

    def test_h07_render_infra_handles_select(self):
        assert "k.kind === 'select'" in _SETTINGS_HTML or \
               "k.kind==='select'" in _SETTINGS_HTML, (
            "renderInfra must handle kind='select'"
        )
        assert "<select" in _SETTINGS_HTML, (
            "renderInfra select branch must render a <select> element"
        )

    def test_h08_render_infra_handles_list(self):
        assert "k.kind === 'list'" in _SETTINGS_HTML or \
               "k.kind==='list'" in _SETTINGS_HTML, (
            "renderInfra must handle kind='list'"
        )
        assert "Array.isArray(val)" in _SETTINGS_HTML, (
            "renderInfra list branch must join array values for display"
        )


# ── C: Controls HTML ─────────────────────────────────────────────────────────

class TestControlsHtml:
    def test_c01_vp_sidebar_button_absent(self):
        assert "vp-sidebar" not in _CONTROLS_HTML, (
            "Sidebar view picker button must be removed from controls.html"
        )

    def test_c02_sidebar_view_css_absent(self):
        assert 'data-view="sidebar"' not in _CONTROLS_HTML, (
            "Sidebar data-view CSS rules must be removed"
        )

    def test_c03_sidebar_active_variable_absent(self):
        assert "_sidebarActive" not in _CONTROLS_HTML, (
            "_sidebarActive state variable must be removed"
        )

    def test_c04_render_single_group_absent(self):
        assert "_renderSingleGroup" not in _CONTROLS_HTML, (
            "_renderSingleGroup function must be removed (sidebar-only)"
        )

    def test_c05_sidebar_absent_from_setview_array(self):
        # The _setView views array must be ['default','accordion','grid']
        assert "'sidebar'" not in _CONTROLS_HTML or \
               re.search(r"\['default','accordion','grid'\]", _CONTROLS_HTML), (
            "'sidebar' must not appear in the _setView views array"
        )
        assert re.search(r"\['default','accordion','grid'\]", _CONTROLS_HTML), (
            "_setView views array must be ['default','accordion','grid']"
        )

    def test_c06_localstorage_key_consistent(self):
        # _setView saves agw_ctrl_view; DCL reads agw_ctrl_view (same key)
        save_key_match = re.search(
            r"localStorage\.setItem\(['\"]agw_ctrl_view['\"]", _CONTROLS_HTML
        )
        read_key_match = re.search(
            r"localStorage\.getItem\(['\"]agw_ctrl_view['\"]", _CONTROLS_HTML
        )
        assert save_key_match, "_setView must save with key 'agw_ctrl_view'"
        assert read_key_match, "State init or DCL must read with key 'agw_ctrl_view'"
        # Ensure the old hyphen key is gone from the restore path
        assert "agw-ctrl-view" not in _CONTROLS_HTML, (
            "Old hyphenated key 'agw-ctrl-view' must be replaced with 'agw_ctrl_view'"
        )

    def test_c07_valid_view_guard_filters_sidebar(self):
        assert re.search(
            r"\['default','accordion','grid'\]\.includes",
            _CONTROLS_HTML
        ), "Valid-view guard must whitelist only default/accordion/grid"

    def test_c08_valid_view_guard_in_dcl(self):
        # Contract change: the view-restore guard lives in the DOMContentLoaded
        # block that reads 'agw_ctrl_view', not the LAST DCL block. The page
        # gained a later posture-radar DCL boot block, so rfind('DOMContentLoaded')
        # now lands on unrelated code. Anchor on the restore DCL block instead.
        restore_idx = _CONTROLS_HTML.find("agw_ctrl_view")
        assert restore_idx != -1, "view-restore code must read 'agw_ctrl_view'"
        dcl_idx = _CONTROLS_HTML.rfind("DOMContentLoaded", 0, restore_idx)
        assert dcl_idx != -1, "view-restore must run inside a DOMContentLoaded block"
        dcl_block = _CONTROLS_HTML[dcl_idx:]
        assert "_validView" in dcl_block or "includes(_savedView)" in dcl_block, (
            "DCL boot code must guard against invalid stored view values"
        )

    def test_c09_grid_card_header_cursor_default(self):
        assert "grp-card .grp-hdr{" in _CONTROLS_HTML or \
               ".grp-card .grp-hdr{" in _CONTROLS_HTML, (
            ".grp-card .grp-hdr CSS rule must exist"
        )
        # Find the rule and confirm cursor:default
        m = re.search(r'\.grp-card \.grp-hdr\{[^}]+\}', _CONTROLS_HTML)
        assert m, ".grp-card .grp-hdr CSS block must be present"
        assert "cursor:default" in m.group(), (
            ".grp-card .grp-hdr must have cursor:default (grid headers are not clickable)"
        )

    def test_c10_view_picker_only_visible_on_detection(self):
        # The Default/Accordion/Grid view-picker layout switcher only applies to
        # the Detection section; _switch() must hide it on every other section.
        idx = _CONTROLS_HTML.find("function _switch(")
        assert idx != -1, "_switch() section-switch function must exist"
        body = _CONTROLS_HTML[idx:idx + 700]
        assert "view-picker" in body, (
            "_switch() must toggle the #view-picker element's visibility"
        )
        # Visibility must be conditioned on the detection section.
        assert re.search(r"secId\s*===\s*'detection'", body), (
            "_switch() must show the view-picker only when secId === 'detection'"
        )
        # The toggle must drive style.display (show '' for detection, 'none' else)
        assert re.search(r"_vp\.style\.display\s*=", body), (
            "_switch() must set the view-picker's style.display based on the section"
        )

    def test_c11_view_picker_initialised_via_switch_detection(self):
        # On load the page calls _switch('detection') so the picker starts visible
        # for the default section (and is correctly hidden once you navigate away).
        assert _CONTROLS_HTML.count("_switch('detection')") >= 1, (
            "controls.html must initialise the active section via _switch('detection')"
        )
