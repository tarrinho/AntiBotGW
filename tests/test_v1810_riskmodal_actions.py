"""
tests/test_v1810_riskmodal_actions.py — guards for the round-3 risk-modal
actions + fleet panel:
  1. ban-vs-score header + self-ban (admin IP) banner + Unban button
  2. inline quick-disable (clickable control dot → POST /config)
  3. Top controls by blocks panel (live feed)

These are wired with delegated listeners (DOMPurify strips inline handlers), so
the tests assert the data-* hooks + the wireRiskActions wiring + the endpoints.
"""
import os
import re

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")

def _read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()

_DASH = ["dashboards/main.html", "dashboards/agents.html"]


# ── 1. ban header + unban + self-ban ─────────────────────────────────────────

class TestBanHeaderUnban:
    def test_ban_header_rendered_when_banned(self):
        for p in _DASH:
            h = _read(p)
            assert "gw-ban-hdr" in h, f"{p} must render a ban header block"
            assert "d.banned_secs > 0" in h, f"{p} ban header must key on banned_secs"
            assert "_fmtdur(" in h, f"{p} must show remaining ban time (duration fmt)"

    def test_ban_vs_score_explanation(self):
        for p in _DASH:
            h = _read(p)
            assert "gw-ban-note" in h and "does <b>not</b> decay" in h, (
                f"{p} must explain live-score-decays-but-ban-persists"
            )

    def test_self_ban_admin_ip_banner(self):
        for p in _DASH:
            h = _read(p)
            assert "gw-self" in h and "d.is_admin_ip" in h, (
                f"{p} must show a self-ban banner for admin-IP identities"
            )

    def test_unban_button_and_wiring(self):
        for p in _DASH:
            h = _read(p)
            assert "gw-unban" in h and "data-unban-id" in h, f"{p} needs an Unban button"
            assert "secured/unban" in h, f"{p} unban must POST to the unban endpoint"
            assert "function wireRiskActions" in h, f"{p} must define wireRiskActions"
            assert "window.confirm(" in h, f"{p} unban/disable must confirm first"

    def test_wire_called_after_render(self):
        # main uses modal-body, agents uses pop-body; both must wire after innerHTML
        m = _read("dashboards/main.html")
        a = _read("dashboards/agents.html")
        assert "wireRiskActions(document.getElementById('modal-body'), d)" in m
        assert "wireRiskActions(document.getElementById('pop-body'), d)" in a


# ── 2. inline quick-disable ──────────────────────────────────────────────────

class TestInlineQuickDisable:
    def test_dot_is_a_toggle_button(self):
        for p in _DASH:
            h = _read(p)
            assert "gw-qd" in h and "data-qd-knob" in h and "data-qd-on" in h, (
                f"{p} bool control dot must be a quick-toggle button with knob+state"
            )

    def test_disable_posts_to_config(self):
        for p in _DASH:
            h = _read(p)
            idx = h.find("function wireRiskActions")
            body = h[idx:idx + 4000]
            assert "secured/config" in body, f"{p} quick-toggle must POST to /config"
            assert "body[knob] = next" in body, (
                f"{p} quick-toggle must send {{knob: !current}}"
            )
            assert "j.applied" in body, f"{p} must confirm the change applied"

    def test_qd_only_for_bool(self):
        for p in _DASH:
            h = _read(p)
            # the toggle button is created inside the kind==='bool' branch
            assert re.search(r"ctrl\.kind === 'bool'[\s\S]{0,200}gw-qd", h), (
                f"{p} quick-toggle dot must only render for bool controls"
            )

    def test_qd_css(self):
        for p in _DASH:
            h = _read(p)
            assert ".gw-qd{" in h and ".gw-qd:hover" in h, f"{p} missing .gw-qd CSS"


# ── 3. top controls by blocks panel ──────────────────────────────────────────

class TestTopControlsPanel:
    _M = _read("dashboards/main.html")

    def test_panel_present(self):
        assert 'id="top-controls"' in self._M, "live feed must have a top-controls panel"
        assert "Top controls by blocks" in self._M

    def test_aggregates_reasons_to_controls(self):
        idx = self._M.find("Top controls by blocks — aggregate")
        assert idx != -1, "must aggregate by_reason → control"
        block = self._M[idx:idx + 1500]
        assert "signalKnob()" in block, "must use the reason→knob map"
        assert "agg[knob]" in block, "must sum block counts per control"
        assert "sort((a, b) => b[1] - a[1])" in block, "must rank controls by count"

    def test_controls_are_clickable_to_page(self):
        idx = self._M.find("Top controls by blocks — aggregate")
        block = self._M[idx:idx + 1500]
        assert "knobPage()" in block and "secured/' + page + '#knob='" in block, (
            "top-controls entries must deep-link to the knob's page"
        )

    def test_popover_exposes_maps(self):
        for p in _DASH:
            h = _read(p)
            assert "signalKnob: function()" in h and "knobPage: function()" in h, (
                f"{p} popover must expose signalKnob()/knobPage() for the panel"
            )
