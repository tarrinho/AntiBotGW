# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1814_qa_ui_ux.py — UI and UX QA for 1.8.14 dashboard changes.

Dashboards covered:
  VP — dashboards/vhost_policy.html  : knob map, vhost dropdown, escapeHtml
  AG — dashboards/agents.html        : signal→knob mapping for new signals

Test types:
  UI  — structural presence of elements (IDs, CSS classes, data attributes)
  UX  — user-facing behaviour (dropdown shows all vhosts, search filter, labels)
  SEC — security invariants (escapeHtml on dynamic output, no raw innerHTML)
  VER — version label consistency (sidebar-brand-ver, title)
  REG — regression guards (known UX bugs that must not return)
"""
from __future__ import annotations

import os
import re

import pytest

_DASHBOARDS = os.path.join(os.path.dirname(__file__), "..", "dashboards")

def _read(name: str) -> str:
    with open(os.path.join(_DASHBOARDS, name), encoding="utf-8") as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════════════════
# VP — vhost_policy.html
# ═══════════════════════════════════════════════════════════════════════════

class TestVhostPolicyVersion:
    """VER: version labels in vhost_policy.html."""

    def test_title_shows_1814(self):
        src = _read("vhost_policy.html")
        assert "AntiBotWaf_GW_1.9.8" in src, "Page title must contain AntiBotWaf_GW_1.9.8"

    def test_sidebar_brand_ver_shows_1814(self):
        import config as _cfg
        _ver = _cfg.GW_VERSION.rsplit("_", 1)[1]
        src = _read("vhost_policy.html")
        assert re.search(
            r'id="sidebar-brand-ver"[^>]*>\s*' + re.escape(_ver) + r'\s*<', src), \
            f"sidebar-brand-ver must display {_ver}"

    def test_no_stale_1815_labels(self):
        src = _read("vhost_policy.html")
        assert "1.8.15" not in src, \
            "vhost_policy.html must not contain any '1.8.15' label"


class TestVhostPolicyKnobMap:
    """UI: 1.8.14 knobs are present in KNOB_MAP with correct groups and types."""

    def setup_method(self):
        self.src = _read("vhost_policy.html")

    # ── Threat Intel feed knobs ──

    @pytest.mark.parametrize("knob", [
        "FEODO_ENABLED",
        "CINS_ENABLED",
        "URLHAUS_ENABLED",
    ])
    def test_feed_knob_in_knob_map(self, knob):
        assert knob in self.src, f"{knob} must be in KNOB_MAP"

    @pytest.mark.parametrize("knob", [
        "FEODO_ENABLED",
        "CINS_ENABLED",
        "URLHAUS_ENABLED",
    ])
    def test_feed_knob_group_threat_intel(self, knob):
        m = re.search(rf"{re.escape(knob)}\s*:\s*\{{g:'([^']+)'", self.src)
        assert m, f"{knob} group not found"
        assert m.group(1) == "Threat Intel", \
            f"{knob} must be in 'Threat Intel' group, got {m.group(1)!r}"

    @pytest.mark.parametrize("knob", [
        "FEODO_ENABLED",
        "CINS_ENABLED",
        "URLHAUS_ENABLED",
    ])
    def test_feed_knob_type_bool(self, knob):
        m = re.search(rf"{re.escape(knob)}\s*:\s*\{{[^}}]*t:'([^']+)'", self.src)
        assert m, f"{knob} type not found"
        assert m.group(1) == "bool", f"{knob} must have type 'bool'"

    # ── H2 fingerproxy knobs ──

    @pytest.mark.parametrize("knob", [
        "H2_SETTINGS_FP_ENABLED",
        "H2_FP_DENY_ENABLED",
        "H2_SETTINGS_MISMATCH_ENABLED",
    ])
    def test_h2fp_knob_in_knob_map(self, knob):
        assert knob in self.src, f"{knob} must be in KNOB_MAP"

    @pytest.mark.parametrize("knob", [
        "H2_SETTINGS_FP_ENABLED",
        "H2_FP_DENY_ENABLED",
        "H2_SETTINGS_MISMATCH_ENABLED",
    ])
    def test_h2fp_knob_group_fingerprint(self, knob):
        m = re.search(rf"{re.escape(knob)}\s*:\s*\{{g:'([^']+)'", self.src)
        assert m, f"{knob} group not found"
        assert m.group(1) == "Fingerprint", \
            f"{knob} must be in 'Fingerprint' group, got {m.group(1)!r}"

    @pytest.mark.parametrize("knob", [
        "H2_SETTINGS_FP_ENABLED",
        "H2_FP_DENY_ENABLED",
        "H2_SETTINGS_MISMATCH_ENABLED",
    ])
    def test_h2fp_knob_type_bool(self, knob):
        m = re.search(rf"{re.escape(knob)}\s*:\s*\{{[^}}]*t:'([^']+)'", self.src)
        assert m, f"{knob} type not found"
        assert m.group(1) == "bool", f"{knob} must have type 'bool'"

    # ── JS consistency knobs ──

    @pytest.mark.parametrize("knob", [
        "JS_CONSISTENCY_ENABLED",
        "JS_CUA_VERSION_CHECK_ENABLED",
        "JS_MOBILE_HINT_CHECK_ENABLED",
        "JS_FETCH_IMPOSSIBLE_CHECK_ENABLED",
    ])
    def test_js_consistency_knob_in_knob_map(self, knob):
        assert knob in self.src, f"{knob} must be in KNOB_MAP"

    @pytest.mark.parametrize("knob", [
        "JS_CONSISTENCY_ENABLED",
        "JS_CUA_VERSION_CHECK_ENABLED",
        "JS_MOBILE_HINT_CHECK_ENABLED",
        "JS_FETCH_IMPOSSIBLE_CHECK_ENABLED",
    ])
    def test_js_consistency_knob_group_detectors(self, knob):
        m = re.search(rf"{re.escape(knob)}\s*:\s*\{{g:'([^']+)'", self.src)
        assert m, f"{knob} group not found"
        assert m.group(1) == "Detectors", \
            f"{knob} must be in 'Detectors' group, got {m.group(1)!r}"

    @pytest.mark.parametrize("knob", [
        "JS_CONSISTENCY_ENABLED",
        "JS_CUA_VERSION_CHECK_ENABLED",
        "JS_MOBILE_HINT_CHECK_ENABLED",
        "JS_FETCH_IMPOSSIBLE_CHECK_ENABLED",
    ])
    def test_js_consistency_knob_type_bool(self, knob):
        m = re.search(rf"{re.escape(knob)}\s*:\s*\{{[^}}]*t:'([^']+)'", self.src)
        assert m, f"{knob} type not found"
        assert m.group(1) == "bool", f"{knob} must have type 'bool'"

    # ── RISK_OVERRIDES ──

    def test_risk_overrides_in_knob_map(self):
        assert "RISK_OVERRIDES" in self.src

    def test_risk_overrides_group_risk_weights(self):
        m = re.search(r"RISK_OVERRIDES\s*:\s*\{g:'([^']+)'", self.src)
        assert m, "RISK_OVERRIDES group not found"
        assert m.group(1) == "Risk Weights", \
            f"RISK_OVERRIDES group must be 'Risk Weights', got {m.group(1)!r}"

    def test_risk_overrides_type_str(self):
        """RISK_OVERRIDES is a JSON dict → rendered as text input (type='str'), not a bool toggle."""
        m = re.search(r"RISK_OVERRIDES\s*:\s*\{[^}]*t:'([^']+)'", self.src)
        assert m, "RISK_OVERRIDES type not found"
        assert m.group(1) == "str", \
            f"RISK_OVERRIDES must have type 'str' (text input), got {m.group(1)!r}"


class TestVhostDropdownUX:
    """UX: vhost dropdown shows all vhosts without age filter (1.8.14 fix)."""

    def setup_method(self):
        self.src = _read("vhost_policy.html")

    # REG: the 300-second age filter was removed in 1.8.14
    def test_no_age_filter_in_dropdown_loop(self):
        """Regression: age>=300 filter must be absent — every vhost always shown."""
        assert "age>=300" not in self.src and "age >= 300" not in self.src, \
            "Age filter must have been removed from vhost dropdown loop"

    def test_no_pinned_set_filtering(self):
        """_pinned localStorage filter was part of the removed age-filter logic."""
        assert "_pinned.has(vh)" not in self.src, \
            "_pinned filter must have been removed from vhost dropdown loop"

    def test_vhost_select_element_present(self):
        assert 'id="vhost-select"' in self.src

    def test_vhost_dropdown_loop_iterates_all(self):
        """forEach loop on d.vhosts must not have an early return/skip guard."""
        m = re.search(
            r'\(d\.vhosts\|\|\[\]\)\.forEach\(function\(vh\)\{(.*?)\}\)',
            self.src, re.DOTALL,
        )
        assert m, "vhost forEach loop not found"
        body = m.group(1)
        # No early return that would skip a vhost
        assert "return;" not in body or body.count("return;") == 0, \
            "vhost dropdown loop must not have an early return (filter removed)"

    def test_search_filter_input_present(self):
        """vhost-policy-search input enables text filtering without hiding vhosts structurally."""
        assert "vhost-policy-search" in self.src

    def test_search_filter_uses_hidden_not_skip(self):
        """Search filter uses opt.hidden (CSS), not structural skip — all vhosts in DOM."""
        search_block = re.search(
            r'oninput.*?vhost-policy-search.*?indexOf.*?\}\)',
            self.src, re.DOTALL,
        )
        if search_block:
            assert "hidden" in search_block.group(0), \
                "Search filter should use .hidden attribute"

    def test_vhost_count_tracked(self):
        """_visCount must still be incremented (used for search-box visibility threshold)."""
        assert "_visCount++" in self.src or "_visCount +" in self.src


class TestVhostPolicySecurity:
    """SEC: XSS prevention — escapeHtml used on every dynamic output."""

    def setup_method(self):
        self.src = _read("vhost_policy.html")

    def test_escape_html_function_defined(self):
        assert "function escapeHtml" in self.src

    def test_escape_html_covers_all_special_chars(self):
        """escapeHtml must escape &, <, >, ", ', `, / — OWASP minimum."""
        for char in ("&amp;", "&lt;", "&gt;", "&quot;", "&#39;", "&#96;", "&#47;"):
            assert char in self.src, f"escapeHtml missing escape for {char!r}"

    def test_knob_name_escaped_in_picker(self):
        """Knob names rendered in picker UI must go through escapeHtml."""
        assert "escapeHtml(knob)" in self.src

    def test_vhost_hostname_escaped_in_dropdown(self):
        """Vhost hostname rendered in override sections must go through escapeHtml."""
        assert "escapeHtml(vh)" in self.src or "escapeHtml(_hostname)" in self.src

    def test_knob_value_escaped_in_render(self):
        """Knob values written into DOM must be escaped."""
        assert "escapeHtml(String(val" in self.src or "escapeHtml(gval" in self.src

    def test_no_unescaped_innerhtml_with_data(self):
        """innerHTML assignments must not pass raw server data directly.
        Pattern: innerHTML = d.<something> without escapeHtml() wrap is forbidden."""
        # Allow innerHTML= only with escapeHtml, _dp (DOMPurify), or static strings
        raw_set = re.findall(r'\.innerHTML\s*=\s*([^;]+);', self.src)
        for expr in raw_set:
            expr_stripped = expr.strip()
            # Skip: empty string, static HTML, escapeHtml-wrapped, _dp-wrapped, html var
            if (expr_stripped in ('""', "''", '""', "''")
                    or expr_stripped.startswith('"')
                    or expr_stripped.startswith("'")
                    or "escapeHtml" in expr_stripped
                    or "_dp(" in expr_stripped
                    or re.match(r'^html\b', expr_stripped)
                    or re.match(r'^"<', expr_stripped)
                    or re.match(r"^'<", expr_stripped)):
                continue
            # Flag: direct d.X or raw variable without escape
            if re.search(r'\bd\.[a-zA-Z]', expr_stripped):
                pytest.fail(
                    f"Potentially unescaped innerHTML: .innerHTML = {expr_stripped[:80]!r}"
                )


# ═══════════════════════════════════════════════════════════════════════════
# AG — agents.html
# ═══════════════════════════════════════════════════════════════════════════

class TestAgentsSignalKnobMapping:
    """UI: 1.8.14 signals correctly mapped to their controlling knob."""

    def setup_method(self):
        self.src = _read("agents.html")

    @pytest.mark.parametrize("signal,knob", [
        # Threat intel signals → feed knobs
        ("feodo-c2",        "FEODO_ENABLED"),
        ("cins-rogue",      "CINS_ENABLED"),
        ("urlhaus-malware", "URLHAUS_ENABLED"),
        # H2 fingerproxy signals → master switch
        ("h2-settings-deny",     "H2_SETTINGS_FP_ENABLED"),
        ("h2-settings-mismatch", "H2_SETTINGS_FP_ENABLED"),
        # JS consistency signals → JS master switch
        ("js-cua-version-mismatch", "JS_CONSISTENCY_ENABLED"),
        ("js-mobile-hint-mismatch", "JS_CONSISTENCY_ENABLED"),
        ("js-fetch-impossible",     "JS_CONSISTENCY_ENABLED"),
    ])
    def test_signal_mapped_to_knob(self, signal, knob):
        pattern = rf'"{re.escape(signal)}"\s*:\s*"{re.escape(knob)}"'
        assert re.search(pattern, self.src), \
            f"Signal {signal!r} must map to knob {knob!r} in agents.html"

    def test_threat_intel_signals_present(self):
        for sig in ("feodo-c2", "cins-rogue", "urlhaus-malware"):
            assert f'"{sig}"' in self.src, f"Signal {sig!r} missing from agents.html"

    def test_h2fp_signals_present(self):
        for sig in ("h2-settings-deny", "h2-settings-mismatch"):
            assert f'"{sig}"' in self.src, f"Signal {sig!r} missing from agents.html"

    def test_js_consistency_signals_present(self):
        for sig in ("js-cua-version-mismatch", "js-mobile-hint-mismatch", "js-fetch-impossible"):
            assert f'"{sig}"' in self.src, f"Signal {sig!r} missing from agents.html"


class TestAgentsVersion:
    """VER: agents.html version labels."""

    def test_title_shows_1814(self):
        src = _read("agents.html")
        assert "AntiBotWaf_GW_1.9.8" in src

    def test_sidebar_brand_ver_shows_1814(self):
        import config as _cfg
        _ver = _cfg.GW_VERSION.rsplit("_", 1)[1]
        src = _read("agents.html")
        assert re.search(
            r'id="sidebar-brand-ver"[^>]*>\s*' + re.escape(_ver) + r'\s*<', src)

    def test_no_stale_1815_labels(self):
        src = _read("agents.html")
        assert "1.8.15" not in src, \
            "agents.html must not contain any '1.8.15' label"


# ═══════════════════════════════════════════════════════════════════════════
# Cross-dashboard UI invariants
# ═══════════════════════════════════════════════════════════════════════════

class TestCrossDashboardVersion:
    """VER: all dashboards show 1.8.14, none show 1.8.15."""

    @pytest.mark.parametrize("dashboard", [
        "vhost_policy.html",
        "agents.html",
        "main.html",
        "settings.html",
        "controls.html",
        "logs.html",
        "siem.html",
        "service.html",
        "geo.html",
        "honeypots.html",
        "login.html",
    ])
    def test_no_stale_1815_in_dashboard(self, dashboard):
        src = _read(dashboard)
        assert "1.8.15" not in src, \
            f"{dashboard} contains stale '1.8.15' label"

    @pytest.mark.parametrize("dashboard", [
        "vhost_policy.html",
        "agents.html",
        "main.html",
    ])
    def test_sidebar_brand_ver_1814(self, dashboard):
        # Version-agnostic (iter-11): read the canonical X.Y.Z from
        # config.GW_VERSION instead of a hardcoded literal, so this test
        # tracks every bump automatically and never goes stale again.
        import config as _cfg
        _ver = _cfg.GW_VERSION.rsplit("_", 1)[1]   # "AntiBotWaf_GW_1.9.8" → "1.9.4"
        src = _read(dashboard)
        assert re.search(
            r'id="sidebar-brand-ver"[^>]*>\s*' + re.escape(_ver) + r'\s*<', src), \
            f"{dashboard} sidebar-brand-ver must show {_ver}"


class TestCrossDashboardSecurity:
    """SEC: escapeHtml defined in every dashboard that renders user data."""

    @pytest.mark.parametrize("dashboard", [
        "vhost_policy.html",
        "agents.html",
        "main.html",
        "logs.html",
        "siem.html",
        "honeypots.html",
    ])
    def test_escape_html_defined(self, dashboard):
        src = _read(dashboard)
        assert "function escapeHtml" in src or "escapeHtml" in src, \
            f"{dashboard} must define or import escapeHtml"

    @pytest.mark.parametrize("dashboard", [
        "main.html",
        "agents.html",
        "logs.html",
    ])
    def test_timers_tracked_in_array(self, dashboard):
        """setInterval calls must be tracked in _timers for cleanup on unload."""
        src = _read(dashboard)
        if "setInterval" not in src:
            return  # dashboard has no intervals — nothing to check
        assert "_timers" in src, \
            f"{dashboard} uses setInterval but missing _timers array"
        assert "_timers.push(setInterval" in src, \
            f"{dashboard} setInterval calls must be pushed to _timers"

    @pytest.mark.parametrize("dashboard", [
        "main.html",
        "agents.html",
        "logs.html",
    ])
    def test_beforeunload_clears_timers(self, dashboard):
        """beforeunload handler must clear all tracked intervals — prevents memory leaks."""
        src = _read(dashboard)
        if "setInterval" not in src:
            return
        assert "beforeunload" in src and "clearInterval" in src, \
            f"{dashboard} must clear _timers in beforeunload handler"


# ═══════════════════════════════════════════════════════════════════════════
# SEC (extended) — per-dashboard and cross-dashboard security invariants
# ═══════════════════════════════════════════════════════════════════════════

class TestAgentsSecurity:
    """SEC: agents.html XSS, CSRF-interceptor, and safe DOM-write invariants."""

    def setup_method(self):
        self.src = _read("agents.html")

    def test_no_eval_in_agents(self):
        """eval() must not appear — any dynamic eval is a JS injection surface."""
        assert "eval(" not in self.src, "agents.html must not use eval()"

    def test_no_document_write_in_agents(self):
        """document.write() bypasses the DOM parser and is an XSS sink."""
        assert "document.write(" not in self.src

    def test_csrf_interceptor_present(self):
        """agents.html must include the _agwTok CSRF interceptor for API calls."""
        assert "_agwTok" in self.src, \
            "agents.html must define _agwTok for CSRF-protected fetch calls"

    def test_no_inline_event_handlers_with_server_data(self):
        """on* attributes must not interpolate server data — XSS via event handler."""
        risky = re.findall(r'on\w+="[^"]*\bd\.[a-zA-Z]', self.src)
        assert not risky, \
            f"Inline event handlers with server data found: {risky[:3]}"


class TestCrossDashboardSecurityExtended:
    """SEC: no eval/document.write in any data-rendering dashboard."""

    _DATA_DASHBOARDS = [
        "vhost_policy.html",
        "agents.html",
        "main.html",
        "logs.html",
        "siem.html",
        "honeypots.html",
    ]

    @pytest.mark.parametrize("dashboard", _DATA_DASHBOARDS)
    def test_no_eval_in_data_dashboard(self, dashboard):
        """eval() is a JS injection sink — forbidden in all data-rendering dashboards."""
        src = _read(dashboard)
        assert "eval(" not in src, f"{dashboard} must not use eval()"

    @pytest.mark.parametrize("dashboard", _DATA_DASHBOARDS)
    def test_no_document_write_in_data_dashboard(self, dashboard):
        """document.write() bypasses DOM parser — forbidden in data-rendering dashboards."""
        src = _read(dashboard)
        assert "document.write(" not in src, \
            f"{dashboard} must not use document.write()"

    @pytest.mark.parametrize("dashboard", [
        "vhost_policy.html",
        "agents.html",
        "main.html",
        "logs.html",
        "siem.html",
        "honeypots.html",
        "service.html",
        "geo.html",
    ])
    def test_csrf_interceptor_present(self, dashboard):
        """Dashboards that make API calls must include the _agwTok CSRF interceptor."""
        src = _read(dashboard)
        assert "_agwTok" in src, \
            f"{dashboard} must define _agwTok for CSRF-protected fetch calls"


# ═══════════════════════════════════════════════════════════════════════════
# Missed-category tooltip — main.html + agents.html
# ═══════════════════════════════════════════════════════════════════════════

_MISSED_TOOLTIP_KEYWORDS = [
    "SOFT_CHALLENGE_SCORE",
    "BAN_THRESHOLD",
    "medium band",
    "served to the upstream",
]

class TestMissedCategoryTooltipMainHtml:
    """UI/UX: every ● missed legend pill in main.html carries the explanatory tooltip."""

    def setup_method(self):
        self.src = _read("main.html")

    def test_missed_legend_has_tooltip(self):
        """All three panel-legend missed pills must have a title attribute beyond 'Toggle Missed'."""
        import re
        hits = re.findall(
            r'data-leg-cats="missed"[^>]*title="([^"]+)"', self.src
        )
        assert len(hits) == 3, (
            f"Expected 3 missed legend pills with title, found {len(hits)}"
        )
        for title in hits:
            assert title != "Toggle Missed", (
                "missed legend title must be descriptive, not just 'Toggle Missed'"
            )

    @pytest.mark.parametrize("keyword", _MISSED_TOOLTIP_KEYWORDS)
    def test_missed_tooltip_contains_keyword(self, keyword):
        """Tooltip must mention key terms so operators understand what missed means."""
        import re
        hits = re.findall(
            r'data-leg-cats="missed"[^>]*title="([^"]+)"', self.src
        )
        assert hits, "No missed legend pills found in main.html"
        for title in hits:
            assert keyword in title, (
                f"missed tooltip must contain '{keyword}'; got: {title[:80]!r}"
            )

    def test_missed_tooltip_count_matches_legend_count(self):
        """Every missed panel-leg-item span must have the tooltip — none left as plain 'Toggle Missed'."""
        plain_count = self.src.count('title="Toggle Missed"')
        assert plain_count == 0, (
            f"{plain_count} missed legend pill(s) still have plain 'Toggle Missed' title"
        )

    def test_missed_pill_color_orange(self):
        """missed legend pill must be styled orange — distinguishable from allowed/blocked."""
        assert '"missed"' in self.src or "data-leg-cats=\"missed\"" in self.src
        assert "#ff7b3a" in self.src or "var(--orange" in self.src, (
            "missed pill must use orange color (#ff7b3a or var(--orange))"
        )

    def test_inline_info_tip_explains_missed(self):
        """The Live events info-tip table must include a row explaining missed."""
        assert "medium-risk band" in self.src or "medium band" in self.src or \
               "medium risk" in self.src.lower(), (
            "Live events info-tip must explain missed as medium-risk band"
        )


class TestMissedCategoryTooltipAgentsHtml:
    """UI/UX: ● Missed button in agents.html carries the explanatory tooltip."""

    def setup_method(self):
        self.src = _read("agents.html")

    def test_missed_button_has_title(self):
        """The ● Missed cat-pill button must have a title attribute."""
        import re
        m = re.search(r'data-cat="missed"[^>]*title="([^"]+)"', self.src)
        assert m, "agents.html ● Missed button must have a title tooltip"

    @pytest.mark.parametrize("keyword", _MISSED_TOOLTIP_KEYWORDS)
    def test_missed_button_tooltip_contains_keyword(self, keyword):
        """Tooltip on ● Missed button must contain key explanation terms."""
        import re
        m = re.search(r'data-cat="missed"[^>]*title="([^"]+)"', self.src)
        assert m, "agents.html ● Missed button must have a title tooltip"
        assert keyword in m.group(1), (
            f"agents.html missed tooltip must contain '{keyword}'; "
            f"got: {m.group(1)[:80]!r}"
        )

    def test_missed_button_title_not_generic(self):
        """The title must be substantive — not just 'Missed' or 'Toggle Missed'."""
        import re
        m = re.search(r'data-cat="missed"[^>]*title="([^"]+)"', self.src)
        assert m, "agents.html ● Missed button must have a title tooltip"
        title = m.group(1)
        assert title not in ("Missed", "Toggle Missed", "● Missed"), (
            f"agents.html missed button title must be descriptive, got {title!r}"
        )

    def test_agents_has_inline_missed_explanation(self):
        """agents.html already has an inline 'missed = allowed but ...' note — must be present."""
        assert "missed" in self.src and (
            "allowed but" in self.src or "medium" in self.src.lower()
        ), "agents.html must have an inline explanation of the missed category"


class TestMissedCategoryTooltipConsistency:
    """UX: tooltip text is consistent between main.html and agents.html."""

    def test_both_dashboards_reference_soft_challenge_score(self):
        """Both main.html and agents.html missed tooltips must reference SOFT_CHALLENGE_SCORE."""
        for dashboard in ("main.html", "agents.html"):
            src = _read(dashboard)
            assert "SOFT_CHALLENGE_SCORE" in src, (
                f"{dashboard} missed tooltip must reference SOFT_CHALLENGE_SCORE"
            )

    def test_both_dashboards_reference_ban_threshold(self):
        """Both must reference BAN_THRESHOLD — the upper bound of the medium band."""
        for dashboard in ("main.html", "agents.html"):
            src = _read(dashboard)
            assert "BAN_THRESHOLD" in src, (
                f"{dashboard} missed tooltip must reference BAN_THRESHOLD"
            )

    def test_main_html_has_three_missed_tooltips(self):
        """main.html has 3 separate legend panels — each needs the tooltip."""
        import re
        count = len(re.findall(r'data-leg-cats="missed"[^>]*title="[^"]*SOFT_CHALLENGE', _read("main.html")))
        assert count == 3, (
            f"Expected 3 missed legend pills with SOFT_CHALLENGE_SCORE in title, got {count}"
        )
