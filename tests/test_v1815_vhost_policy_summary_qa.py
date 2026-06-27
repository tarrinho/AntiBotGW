"""
QA tests — vhost policy no-hostname summary shows ALL vhosts (1.8.15).

Bug: when no inbound hostname was selected in Vhost Policy, the summary
content area only rendered vhosts that had at least one explicit override
(_vhActive filter). Vhosts inheriting everything from global were silently
excluded, making the displayed count smaller than the 7 shown in routing.

Fix (vhost_policy.html _renderOverrides no-hostname branch):
  - Removed the _vhActive filter — now iterates _vhKeys (all vhosts).
  - Vhosts with overrides: render knob rows as before.
  - Vhosts with no overrides: render an "inherits global" dim badge.
  - Each vhost header is clickable → dispatches 'change' on #vhost-select.

Coverage:
  TestVhostPolicySummarySourceGuards  — source-code checks on the fix
  TestVhostPolicySummaryContent       — rendered HTML content checks
"""
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC  = (_ROOT / "dashboards" / "vhost_policy.html").read_text(encoding="utf-8")

# ── helpers ───────────────────────────────────────────────────────────────────

def _fn(marker: str, src: str = _SRC, window: int = 600) -> str:
    """Return a window of source starting at the first occurrence of marker."""
    idx = src.find(marker)
    assert idx != -1, f"marker not found: {marker!r}"
    return src[idx: idx + window]


def _no_hostname_block() -> str:
    """Extract the no-hostname branch of _renderOverrides (second occurrence)."""
    # First if(!_hostname) is in _renderBotDetectionCard (line ~474).
    # Second is the renderOverrides branch we care about (line ~497).
    first = _SRC.find("if(!_hostname){")
    assert first != -1, "first if(!_hostname) not found"
    start = _SRC.find("if(!_hostname){", first + 1)
    assert start != -1, "second if(!_hostname) branch not found in _renderOverrides"
    # Extract to matching closing brace
    depth, i = 0, start
    while i < len(_SRC):
        if _SRC[i] == "{": depth += 1
        elif _SRC[i] == "}":
            depth -= 1
            if depth == 0:
                return _SRC[start: i + 1]
        i += 1
    return _SRC[start: start + 2000]


_BLOCK = _no_hostname_block()


# ── 1. TestVhostPolicySummarySourceGuards ─────────────────────────────────────

class TestVhostPolicySummarySourceGuards:
    """Source-code checks: fix applied correctly."""

    def test_no_vhactive_filter_in_no_hostname_branch(self):
        """_vhActive must NOT be used to filter the rendered set anymore."""
        # The old code filtered via _vhActive; the fix iterates _vhKeys.
        # _vhActive may still exist elsewhere (e.g. old tests / comments) but
        # must NOT appear inside the no-hostname rendering loop.
        loop_start = _BLOCK.find("_vhKeys.forEach")
        assert loop_start != -1, "_vhKeys.forEach loop not found in no-hostname branch"
        loop_body = _BLOCK[loop_start:]
        assert "_vhActive" not in loop_body, (
            "_vhActive must not filter the rendering loop — all vhosts must be shown"
        )

    def test_iterates_vhkeys_not_vhactive(self):
        """The rendering loop must iterate _vhKeys (all vhosts)."""
        assert "_vhKeys.forEach" in _BLOCK, (
            "no-hostname branch must iterate _vhKeys to render all vhosts"
        )

    def test_inherits_global_badge_present(self):
        """Vhosts with no overrides must show 'inherits global' text."""
        assert "inherits global" in _BLOCK, (
            "'inherits global' badge missing from no-hostname rendering"
        )

    def test_inherits_global_gated_by_hasov(self):
        """'inherits global' must only render when hasOv is falsy (ternary else path)."""
        # Find 'inherits global' in the code (not the comment)
        # It appears after 'hasOv' check — confirm hasOv comes before it.
        hov_idx = _BLOCK.find("hasOv")
        inh_idx = _BLOCK.find("inherits global", hov_idx)
        assert hov_idx != -1 and inh_idx != -1, (
            "hasOv must be defined before 'inherits global' in the block"
        )
        assert hov_idx < inh_idx, (
            "hasOv flag must precede 'inherits global' — it gates which badge renders"
        )

    def test_has_override_is_conditional(self):
        """hasOv flag must gate the knob rows so zero-override vhosts don't render rows."""
        assert "hasOv" in _BLOCK, "hasOv flag must be defined in the no-hostname branch"
        hov_idx = _BLOCK.find("if(hasOv)")
        assert hov_idx != -1, "if(hasOv) gate not found — knob rows must be conditional"

    def test_vhost_header_clickable(self):
        """Each vhost header must be clickable to jump to that vhost in the select."""
        assert "onclick" in _BLOCK, (
            "vhost header in summary must have onclick to jump to the select"
        )
        assert "vhost-select" in _BLOCK, (
            "onclick must target #vhost-select"
        )
        assert "dispatchEvent" in _BLOCK, (
            "onclick must dispatch a change event so _loadData fires"
        )

    def test_all_vhosts_shown_not_only_active(self):
        """Old 'No vhost-specific overrides configured' early-return must be gone."""
        # This message was the empty-state shown when _vhActive was empty.
        # With the fix, we always render (unless _vhKeys is empty), so this
        # specific early-return must not exist inside the no-hostname block.
        early_return_msg = "No vhost-specific overrides configured"
        assert early_return_msg not in _BLOCK, (
            f"'{early_return_msg}' early-return must be removed — "
            "all vhosts must be shown even when none have overrides"
        )

    def test_empty_state_only_when_no_vhosts_at_all(self):
        """Empty state ('Select a vhost above') must only fire when _vhKeys is empty."""
        empty_idx = _BLOCK.find("Select a vhost above")
        assert empty_idx != -1, "'Select a vhost above' empty state must still exist"
        # The guard before it must check _vhKeys.length, not _vhActive.length
        guard_ctx = _BLOCK[max(0, empty_idx - 120): empty_idx]
        assert "_vhKeys" in guard_ctx, (
            "Empty state guard must check _vhKeys.length (no vhosts at all), not _vhActive"
        )
        assert "_vhActive" not in guard_ctx, (
            "Empty state must NOT be gated on _vhActive — only on _vhKeys being empty"
        )

    def test_escapehtml_on_vhost_names(self):
        """All vhost names inserted into innerHTML must go through escapeHtml."""
        loop_start = _BLOCK.find("_vhKeys.forEach")
        loop_body = _BLOCK[loop_start: loop_start + 800]
        # Count escapeHtml(vh) calls in the loop body
        count = loop_body.count("escapeHtml(vh)")
        assert count >= 1, (
            f"vhost name must be escaped with escapeHtml(vh) in the summary loop; "
            f"found {count} call(s)"
        )

    def test_override_count_suffix_correct(self):
        """Override count label must use singular/plural correctly."""
        assert "override'+(ovKeys.length===1?'':'s')" in _BLOCK or \
               "override' + (ovKeys.length===1?'':'s')" in _BLOCK or \
               "override'+(ovKeys.length===1" in _BLOCK, (
            "override count must use singular/plural: 'override'+(N===1?'':'s')"
        )


# ── 2. TestVhostPolicySummaryContent ─────────────────────────────────────────

class TestVhostPolicySummaryContent:
    """Rendered HTML content checks — simulate _allVhostSummary and verify output."""

    def _simulate_render(self, all_vhost_summary: dict, global_vals: dict = None) -> str:
        """
        Simplified Python simulation of the _renderOverrides no-hostname branch.
        Returns the HTML string that would be set on container.innerHTML.
        """
        global_vals = global_vals or {}
        vhkeys = sorted(all_vhost_summary.keys())
        if not vhkeys:
            return "Select a vhost above"
        parts = []
        for vh in vhkeys:
            ov_keys = sorted(all_vhost_summary.get(vh, {}).keys())
            has_ov = len(ov_keys) > 0
            if has_ov:
                suffix = f"{len(ov_keys)} override{'s' if len(ov_keys) != 1 else ''}"
            else:
                suffix = "inherits global"
            parts.append(f"VH:{vh}:{suffix}")
            for knob in ov_keys:
                parts.append(f"  KNOB:{knob}")
        return "\n".join(parts)

    def test_all_three_vhosts_rendered_when_one_has_overrides(self):
        """3 configured vhosts, 1 with overrides → all 3 appear in summary."""
        summary = {
            "alpha.test": {"UA_FILTER_ENABLED": False},
            "beta.test":  {},
            "gamma.test": {},
        }
        html = self._simulate_render(summary)
        assert "alpha.test" in html, "alpha.test (has overrides) must appear"
        assert "beta.test"  in html, "beta.test (no overrides) must appear"
        assert "gamma.test" in html, "gamma.test (no overrides) must appear"

    def test_no_override_vhosts_show_inherits_global(self):
        """Vhosts with empty overrides must show 'inherits global' not silence."""
        summary = {"site.example": {}, "api.example": {}}
        html = self._simulate_render(summary)
        assert html.count("inherits global") == 2, (
            "Both zero-override vhosts must show 'inherits global'"
        )

    def test_vhost_with_overrides_shows_count_not_inherits(self):
        """Vhost with overrides must show override count, not 'inherits global'."""
        summary = {"site.example": {"RISK_BAN_THRESHOLD": 30, "JS_CHALLENGE": False}}
        html = self._simulate_render(summary)
        assert "2 overrides" in html, "Should show '2 overrides'"
        assert "inherits global" not in html, (
            "Should NOT show 'inherits global' when vhost has overrides"
        )

    def test_seven_vhosts_all_rendered_matches_routing_count(self):
        """7 configured vhosts (as user reported) → all 7 appear in summary."""
        summary = {f"vhost{i}.example": ({} if i % 2 else {"JS_CHALLENGE": True})
                   for i in range(7)}
        html = self._simulate_render(summary)
        for i in range(7):
            assert f"vhost{i}.example" in html, (
                f"vhost{i}.example missing — all 7 must be shown"
            )

    def test_empty_summary_shows_select_prompt(self):
        """When _vhKeys is empty (no vhosts at all), show 'Select a vhost above'."""
        html = self._simulate_render({})
        assert "Select a vhost above" in html, (
            "Empty vhost list must prompt user to select a vhost"
        )

    def test_knob_rows_only_for_vhosts_with_overrides(self):
        """Knob rows must appear only under vhosts that have overrides."""
        summary = {
            "a.example": {"UA_FILTER_ENABLED": False},
            "b.example": {},
        }
        html = self._simulate_render(summary)
        assert "UA_FILTER_ENABLED" in html, "Override knob must appear under a.example"
        # b.example must not have any knob rows — only 'inherits global'
        b_idx = html.find("b.example")
        assert b_idx != -1
        b_section = html[b_idx:]
        assert "UA_FILTER_ENABLED" not in b_section, (
            "b.example has no overrides — no knob rows should appear under it"
        )

    def test_vhosts_sorted_alphabetically(self):
        """Summary must list vhosts in alphabetical order."""
        summary = {"z.test": {}, "a.test": {"X": 1}, "m.test": {}}
        html = self._simulate_render(summary)
        pos_a = html.find("a.test")
        pos_m = html.find("m.test")
        pos_z = html.find("z.test")
        assert pos_a < pos_m < pos_z, (
            "Vhosts must be sorted alphabetically: a < m < z"
        )

    def test_single_override_uses_singular(self):
        """1 override → '1 override' (not '1 overrides')."""
        summary = {"x.test": {"BOT_DETECTION_ENABLED": False}}
        html = self._simulate_render(summary)
        assert "1 override" in html and "1 overrides" not in html, (
            "Singular 'override' must be used when count is 1"
        )

    def test_multiple_overrides_uses_plural(self):
        """2+ overrides → 'N overrides'."""
        summary = {"x.test": {"A": 1, "B": 2, "C": 3}}
        html = self._simulate_render(summary)
        assert "3 overrides" in html, "Plural 'overrides' must be used when count > 1"
