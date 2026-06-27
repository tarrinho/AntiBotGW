# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1814_qa_ux.py — comprehensive QA for the v1.8.14 UX review fixes
(U-H1..U-H13, U-M, U-L).

All tests are source-inspection — they verify the HTML/CSS/JS patterns that
implement each UX fix are present in the dashboards. Runtime browser
behaviour is covered by the Playwright suite (§17j).
"""
from __future__ import annotations

import os
import re

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

import pathlib
_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
# U-H1 — Stale banner shows endpoint + status + elapsed time
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH1StaleBannerDetail:
    """Stale banner is updated with specific failure context on every poll."""

    def setup_method(self):
        self.src = _read("dashboards/main.html")

    def test_banner_text_is_dynamic(self):
        assert "_staleEl.textContent" in self.src or "stale-banner" in self.src

    def test_banner_includes_endpoint_name(self):
        assert "/metrics fetch failed" in self.src

    def test_banner_includes_elapsed_seconds(self):
        assert "last good " in self.src and "s ago" in self.src

    def test_lastSuccessfulFetchTs_recorded(self):
        assert "_lastSuccessfulFetchTs" in self.src


# ═══════════════════════════════════════════════════════════════════════════
# U-H2 — Vhost fetch errors surface to user
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH2VhostFetchError:
    """vhost fetch failures don't silently produce empty dropdown."""

    def test_error_field_set_on_fail(self):
        src = _read("dashboards/main.html")
        assert "_error" in src and "vhost list unavailable" in src

    def test_error_option_added_to_select(self):
        src = _read("dashboards/main.html")
        assert "vhost list unavailable" in src


# ═══════════════════════════════════════════════════════════════════════════
# U-H3 — Clients table cap indicator
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH3ClientsTableCap:
    """The 100-row cap is shown to the user in the clients-count badge."""

    def test_cap_message_present(self):
        src = _read("dashboards/main.html")
        assert "showing top" in src and "use filters to narrow" in src

    def test_cap_is_constant(self):
        src = _read("dashboards/main.html")
        # Either explicit _CAP constant or commented 100 — at minimum the slice
        assert "_CAP" in src and "slice(0, _CAP)" in src


# ═══════════════════════════════════════════════════════════════════════════
# U-H4 — Live events grid has responsive overflow
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH4ResponsiveGrid:
    """Live events grid has horizontal scroll wrapper below 1100px."""

    def test_min_width_on_grid(self):
        src = _read("dashboards/main.html")
        # iter-18: live-events grid widened to 8 cols (Time · Verdict · IP ·
        # Domain · Status · Score · Path · Action) so min-width grew from
        # 780→890 (default) and 1010 (mobile media). Either value asserts
        # the responsive floor still exists.
        assert any(s in src for s in (
            "min-width:780px", "min-width: 780px",
            "min-width:890px", "min-width: 890px",
            "min-width:1010px", "min-width: 1010px",
        )), "live events grid lost its min-width responsive floor"

    def test_media_query_for_narrow(self):
        src = _read("dashboards/main.html")
        assert "max-width:1100px" in src and "overflow-x:auto" in src


# ═══════════════════════════════════════════════════════════════════════════
# U-H5 — Status distribution empty state
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH5StatusEmptyState:
    """#statuses panel has a default placeholder."""

    def test_no_traffic_yet_placeholder(self):
        src = _read("dashboards/main.html")
        # The statuses div must have a non-empty initial body — either text
        # or a <span class="dim"> placeholder.
        full = re.search(r'<div class="reasons" id="statuses">.*?</div>', src, re.S)
        assert full, "statuses div must be present"
        body = full.group(0)
        assert "no traffic" in body or "dim" in body, (
            "#statuses must have an inline empty-state placeholder"
        )


# ═══════════════════════════════════════════════════════════════════════════
# U-H6 — _gwAlert position consistency
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH6GwAlertConsistency:
    """_gwAlert appears in the same screen corner across dashboards."""

    def test_main_html_top_right(self):
        src = _read("dashboards/main.html")
        assert "top:16px;right:16px" in src

    def test_agents_html_top_right(self):
        src = _read("dashboards/agents.html")
        assert "top:16px;right:16px" in src


# ═══════════════════════════════════════════════════════════════════════════
# U-H7 — Bulk unban confirmation includes count + warning
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH7BulkUnbanConfirm:
    """Bulk unban requires explicit confirmation and warns it's irreversible."""

    def test_confirm_present(self):
        src = _read("dashboards/agents.html")
        assert "window.confirm" in src

    def test_confirm_mentions_irreversible(self):
        src = _read("dashboards/agents.html")
        assert "cannot be undone" in src.lower() or "irreversible" in src.lower()


# ═══════════════════════════════════════════════════════════════════════════
# U-H8 — Log pane shows actionable error on fetch failure
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH8LogPaneError:
    """logs.html replaces the 'loading…' placeholder with a real error on catch."""

    def test_loading_replaced_in_catch(self):
        src = _read("dashboards/logs.html")
        # The catch handler must update the pane content
        assert "Could not load logs" in src

    def test_error_suggests_session_refresh(self):
        src = _read("dashboards/logs.html")
        assert "Session may have expired" in src or "refresh" in src.lower()


# ═══════════════════════════════════════════════════════════════════════════
# U-H9 — Modal close is a button, not a span
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH9KeyboardAccessibleClose:
    """Modal/popover close controls are <button> elements with aria-label."""

    @pytest.mark.parametrize("dashboard", ["main.html", "agents.html"])
    def test_no_span_close_x(self, dashboard):
        src = _read(f"dashboards/{dashboard}")
        # The legacy pattern was <span class="x" id="modal-close">×</span>
        assert '<span class="x" id="modal-close">' not in src
        assert '<span class="x" id="pop-close">' not in src
        assert '<span class="x" id="risk-pop-x">' not in src

    @pytest.mark.parametrize("dashboard", ["main.html", "agents.html"])
    def test_close_buttons_have_aria_label(self, dashboard):
        src = _read(f"dashboards/{dashboard}")
        # At least one button.x with aria-label
        assert re.search(r'<button[^>]*class="x"[^>]*aria-label=', src), (
            f"{dashboard} must have <button class='x' aria-label='...'> for modal close"
        )


# ═══════════════════════════════════════════════════════════════════════════
# U-H10 — Live regions for stale banner + toasts
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH10AriaLiveRegions:
    """Error states announce to screen readers via aria-live."""

    def test_stale_banner_is_aria_live(self):
        src = _read("dashboards/main.html")
        assert "stale-banner" in src
        # The banner element must have role=alert or aria-live
        m = re.search(r'<div id="stale-banner"[^>]*>', src)
        assert m
        attrs = m.group(0)
        assert 'role="alert"' in attrs or 'aria-live=' in attrs

    @pytest.mark.parametrize("dashboard", ["main.html", "agents.html"])
    def test_gwalert_sets_aria_live(self, dashboard):
        src = _read(f"dashboards/{dashboard}")
        # The dynamically created _gwAlert div must set aria-live or role
        gwa_idx = src.find("function _gwAlert")
        assert gwa_idx != -1
        block = src[gwa_idx: gwa_idx + 600]
        assert "aria-live" in block or 'role' in block


# ═══════════════════════════════════════════════════════════════════════════
# U-H11 — Per-identity aria-label on ban buttons
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH11BanButtonAriaLabel:
    """Ban control buttons include the identity in their aria-label."""

    def test_main_html_ban_buttons_aria_labelled(self):
        src = _read("dashboards/main.html")
        # The template literal must include aria-label="Allow identity ..."
        assert 'aria-label="Allow identity' in src
        assert 'aria-label="Ban identity' in src

    def test_ban_group_has_role(self):
        src = _read("dashboards/main.html")
        assert 'role="group"' in src
        assert "Ban controls for identity" in src


# ═══════════════════════════════════════════════════════════════════════════
# U-H12 — Log level selector is prominently labelled
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH12LogLevelSelector:
    """The persistent LOG_LEVEL selector warns the operator about its scope."""

    def test_label_text_says_persistent(self):
        src = _read("dashboards/main.html")
        assert "LOG_LEVEL" in src
        # The title attribute (tooltip) must mention persistence
        assert "persists across restarts" in src or "persistent" in src.lower()

    def test_select_has_aria_label(self):
        src = _read("dashboards/main.html")
        assert 'aria-label="Server log level' in src or "persistent" in src.lower()


# ═══════════════════════════════════════════════════════════════════════════
# U-H13 — Quick ban from SIEM dossier
# ═══════════════════════════════════════════════════════════════════════════

class TestUxH13SiemQuickBan:
    """SIEM dossier has a single-click ban button bound to the open IP."""

    def setup_method(self):
        self.src = _read("dashboards/siem.html")

    def test_quick_ban_button_present(self):
        assert 'id="dossier-quick-ban"' in self.src

    def test_quick_ban_has_aria_label(self):
        assert 'aria-label="Ban this IP' in self.src

    def test_quick_ban_handler_wires_ip(self):
        # The handler must read dataset.ip and POST to /secured/ban
        assert "dataset.ip = ip" in self.src or "_qb.dataset.ip" in self.src
        assert "/secured/ban?ip=" in self.src

    def test_quick_ban_has_confirmation(self):
        assert "window.confirm" in self.src
        # The confirmation must mention 24 hours
        assert "24 hours" in self.src or "24h" in self.src.lower()

    def test_quick_ban_uses_csrf_header(self):
        assert "X-CSRF-Token" in self.src and "_agwTok" in self.src


# ═══════════════════════════════════════════════════════════════════════════
# U-M — Medium UX fixes
# ═══════════════════════════════════════════════════════════════════════════

class TestUxMediumFilterConsistency:
    """Default _activeFilters has an explicit, documented choice per dashboard.

    main.html intentionally excludes gwmgmt to reduce noise from gateway
    self-traffic. agents.html includes gwmgmt because the agents view is
    expected to be inspected. Both choices must be documented inline so
    future refactors don't silently break the deliberate asymmetry.
    """

    def test_main_html_excludes_gwmgmt_by_design(self):
        src = _read("dashboards/main.html")
        m = re.search(r"_activeFilters = new Set\(\[([^\]]+)\]\)", src)
        assert m
        body = m.group(1)
        assert "'gwmgmt'" not in body, (
            "main.html: gwmgmt deliberately excluded (test_gwmgmt_off_by_default_in_main_and_agents)"
        )

    def test_agents_html_includes_gwmgmt(self):
        src = _read("dashboards/agents.html")
        m = re.search(r"_activeFilters = new Set\(\[([^\]]+)\]\)", src)
        assert m
        assert "'gwmgmt'" in m.group(1)

    def test_choice_documented_in_main_html(self):
        """Comment must explain the deliberate asymmetry so a refactor doesn't 'fix' it."""
        src = _read("dashboards/main.html")
        # Find the line with _activeFilters and check the preceding comment lines
        for i, line in enumerate(src.splitlines()):
            if "_activeFilters = new Set" in line and "window" in line:
                preceding = "\n".join(src.splitlines()[max(0, i-3):i])
                assert "gwmgmt" in preceding.lower() or "intentional" in preceding.lower(), (
                    "main.html _activeFilters definition must be preceded by a comment "
                    "documenting the deliberate gwmgmt-off choice"
                )
                break
        else:
            pytest.fail("could not find _activeFilters in main.html")


class TestUxMediumMissedPillColor:
    """Missed pill is orange across dashboards (was grey in logs.html)."""

    def test_logs_missed_pill_orange(self):
        src = _read("dashboards/logs.html")
        # Look for the cat-pill[data-cat="missed"] rule
        m = re.search(r'\.cat-pill\[data-cat="missed"\]\{[^}]+\}', src)
        assert m
        rule = m.group(0)
        assert "orange" in rule.lower() or "#ff7b3a" in rule


class TestUxMediumThresholdSliderRange:
    """Defense threshold slider description includes 0–100 range and typical values."""

    def test_range_label_present(self):
        src = _read("dashboards/main.html")
        assert "0–100" in src or "0-100" in src
        assert "typical:" in src or "typical" in src.lower()


class TestUxMediumStalenessCounter:
    """Footer shows last-good-fetch age, color-coded with escalation."""

    def setup_method(self):
        self.src = _read("dashboards/main.html")

    def test_staleness_counter_element(self):
        assert 'id="staleness-counter"' in self.src

    def test_counter_updates_on_interval(self):
        assert "staleness-counter" in self.src and "_lastSuccessfulFetchTs" in self.src

    def test_color_escalates_with_age(self):
        # _age > 30 → red, > 10 → yellow
        assert "_age > 30" in self.src
        assert "_age > 10" in self.src

    def test_counter_has_aria_live(self):
        m = re.search(r'<span id="staleness-counter"[^>]*>', self.src)
        assert m and 'aria-live' in m.group(0)


class TestUxLowNavAriaLabel:
    """Main navigation in every dashboard has aria-label='Main navigation'."""

    @pytest.mark.parametrize("dashboard", [
        "main.html", "agents.html", "geo.html", "honeypots.html",
        "service.html", "siem.html", "settings.html",
    ])
    def test_nav_has_aria_label(self, dashboard):
        src = _read(f"dashboards/{dashboard}")
        assert 'nav id="sidebar-nav" aria-label="Main navigation"' in src


# ═══════════════════════════════════════════════════════════════════════════
# UX sweeps
# ═══════════════════════════════════════════════════════════════════════════

class TestUxSweeps:
    """Cross-cutting invariants."""

    def test_no_silent_catch_empty_obj_on_critical_fetches(self):
        """Critical state fetches must not use silent .catch(()=>({})) — fixed in main.html for vhost."""
        src = _read("dashboards/main.html")
        # The vhost fetch must set _error not silently default
        vhost_block = src[src.find("/secured/vhosts"): src.find("/secured/vhosts") + 800]
        assert "_error" in vhost_block

    def test_modal_close_buttons_are_keyboard_focusable(self):
        """No <span class='x'> close controls remain — must be <button>."""
        for f in ("dashboards/main.html", "dashboards/agents.html"):
            src = _read(f)
            # Find every line with class="x"
            for line in src.splitlines():
                if 'class="x"' in line and ('×' in line or '&#10005' in line or '&times' in line):
                    # Must be a <button> not <span>
                    assert "<button" in line or "<input" in line, (
                        f"{f}: keyboard-inaccessible close in: {line.strip()[:120]}"
                    )
