"""
QA tests — banned-silent / ban-outcome signal in risk breakdown (1.8.14 iter 10).

Bug: `banned-silent` appearing in the risk breakdown showed `RISK_BAN_THRESHOLD 500`
as the control column, making it look like the signal costs 500 pts.  In reality
banned-silent adds 0 risk — it is a post-ban outcome record (the identity was already
banned; the proxy served a silent decoy).  Three operator-confusion issues were fixed:

1. `RISK_BAN_THRESHOLD` rendered as a numeric-cost control → now shown as an
   "outcome · threshold≥N" label with tooltip explaining it is a threshold, not a cost.
2. When ban has already expired (`banned_secs === 0`), no header was shown at all,
   leaving the operator with no context for why live risk is 0.0 while banned-silent
   events exist → new `.gw-expired-ban` yellow-warning block explains the situation
   and offers "View requests →".
3. Active-ban header "likely tripped banned-silent" was circular → skip outcome
   signals when picking the top-reason; fall back to empty string if none.

Coverage:
  TestBanOutcomeSignalConstants  — JS source guards on _BAN_OUTCOME_SIGNALS
  TestBanOutcomeControlColumn    — outcome-signal rendering in buildRiskHtml
  TestExpiredBanNote             — gw-expired-ban block presence and content
  TestActiveBanTopReason         — topRsnEntry skips outcome signals correctly
  TestBanOutcomeCSS              — new CSS classes present and themed
"""
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MAIN_SRC = (_ROOT / "dashboards" / "main.html").read_text(encoding="utf-8")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _fn(marker: str, end_marker: str = None, before: int = 0, after: int = 600) -> str:
    idx = _MAIN_SRC.find(marker)
    assert idx != -1, f"Marker not found: {marker!r}"
    end = _MAIN_SRC.find(end_marker, idx) if end_marker else idx + after
    return _MAIN_SRC[max(0, idx - before): end + (len(end_marker) if end_marker else 0)]


# ── 1. TestBanOutcomeSignalConstants ─────────────────────────────────────────

class TestBanOutcomeSignalConstants:
    """_BAN_OUTCOME_SIGNALS Set must exist and cover both known outcome signals."""

    def test_ban_outcome_signals_set_defined(self):
        """_BAN_OUTCOME_SIGNALS must be defined as a Set."""
        assert "_BAN_OUTCOME_SIGNALS" in _MAIN_SRC, (
            "_BAN_OUTCOME_SIGNALS constant not found in main.html"
        )
        assert "new Set(" in _MAIN_SRC[_MAIN_SRC.find("_BAN_OUTCOME_SIGNALS"):
                                       _MAIN_SRC.find("_BAN_OUTCOME_SIGNALS") + 100], (
            "_BAN_OUTCOME_SIGNALS must use new Set(...)"
        )

    def test_banned_silent_in_outcome_set(self):
        """'banned-silent' must be in _BAN_OUTCOME_SIGNALS."""
        block = _fn("_BAN_OUTCOME_SIGNALS")
        assert "'banned-silent'" in block or '"banned-silent"' in block, (
            "'banned-silent' missing from _BAN_OUTCOME_SIGNALS"
        )

    def test_fp_banned_in_outcome_set(self):
        """'fp-banned' must be in _BAN_OUTCOME_SIGNALS."""
        block = _fn("_BAN_OUTCOME_SIGNALS")
        assert "'fp-banned'" in block or '"fp-banned"' in block, (
            "'fp-banned' missing from _BAN_OUTCOME_SIGNALS"
        )

    def test_outcome_hits_computed(self):
        """buildRiskHtml must compute outcomeHits from the breakdown."""
        assert "outcomeHits" in _MAIN_SRC, (
            "outcomeHits variable not found in main.html"
        )
        block = _fn("outcomeHits")
        assert "_BAN_OUTCOME_SIGNALS.has" in block, (
            "outcomeHits must filter using _BAN_OUTCOME_SIGNALS.has()"
        )


# ── 2. TestBanOutcomeControlColumn ───────────────────────────────────────────

class TestBanOutcomeControlColumn:
    """The control column for outcome signals must NOT use the standard
    cost-knob rendering — it must show 'outcome' label + threshold reference."""

    def test_outcome_branch_present_in_ctrl_logic(self):
        """buildRiskHtml must have a branch for _BAN_OUTCOME_SIGNALS."""
        assert "_BAN_OUTCOME_SIGNALS.has(reason)" in _MAIN_SRC, (
            "No _BAN_OUTCOME_SIGNALS.has(reason) branch found in buildRiskHtml"
        )

    def test_outcome_label_rendered(self):
        """Outcome signals must render a 'gw-outcome-label' span."""
        assert "gw-outcome-label" in _MAIN_SRC, (
            "gw-outcome-label class not found in main.html"
        )
        block = _fn("gw-outcome-label", after=300)
        assert "outcome" in block.lower(), (
            "gw-outcome-label span must contain 'outcome' text"
        )

    def test_outcome_label_has_tooltip(self):
        """gw-outcome-label must have a title tooltip explaining 0-risk."""
        # Use the JS template occurrence (class="gw-outcome-label"), not the CSS rule (.gw-outcome-label{)
        block = _fn('class="gw-outcome-label"', after=200)
        assert "title=" in block, (
            "gw-outcome-label must have a title tooltip"
        )
        assert "0" in block and "risk" in block.lower(), (
            "gw-outcome-label tooltip must mention '0 risk' or '0 pts'"
        )

    def test_threshold_shown_with_gte_prefix(self):
        """Threshold value badge must be prefixed with ≥ (not bare number)."""
        # The threshold is shown as ≥N — distinguishes it from a cost value.
        assert "&#8805;" in _MAIN_SRC or "≥" in _MAIN_SRC, (
            "Threshold value in outcome control must use ≥ (&#8805; or Unicode U+2265)"
        )

    def test_threshold_knob_link_has_explanatory_title(self):
        """The RISK_BAN_THRESHOLD link title must explain it is a threshold, not a cost."""
        block = _fn("_BAN_OUTCOME_SIGNALS.has(reason)", after=800)
        assert "threshold" in block.lower() and "not" in block.lower(), (
            "RISK_BAN_THRESHOLD link title must clarify 'threshold, not a cost'"
        )

    def test_outcome_branch_before_regular_knob_branch(self):
        """Outcome-signal branch must come before the regular ctrl.knob branch."""
        idx_outcome = _MAIN_SRC.find("_BAN_OUTCOME_SIGNALS.has(reason)")
        idx_regular = _MAIN_SRC.find("} else if (ctrl.knob) {")
        assert idx_outcome != -1 and idx_regular != -1, (
            "Both branches must exist"
        )
        assert idx_outcome < idx_regular, (
            "Outcome branch must appear before the regular ctrl.knob branch"
        )


# ── 3. TestExpiredBanNote ─────────────────────────────────────────────────────

class TestExpiredBanNote:
    """gw-expired-ban block must appear when outcomeHits > 0 and ban is not active."""

    def test_expired_ban_condition_present(self):
        """JavaScript must check outcomeHits > 0 && !(d.banned_secs > 0)."""
        assert "outcomeHits > 0" in _MAIN_SRC, (
            "No outcomeHits > 0 guard found for expired-ban note"
        )
        block = _fn("outcomeHits > 0", after=100)
        assert "banned_secs" in block, (
            "Expired-ban guard must also check d.banned_secs"
        )

    def test_expired_ban_div_class_present(self):
        """gw-expired-ban div must exist in the template."""
        assert 'class="gw-expired-ban"' in _MAIN_SRC, (
            "gw-expired-ban div not found in buildRiskHtml template"
        )

    def test_expired_ban_line_class_present(self):
        """gw-expired-ban-line header must exist."""
        assert "gw-expired-ban-line" in _MAIN_SRC, (
            "gw-expired-ban-line element missing"
        )

    def test_expired_ban_mentions_decoy(self):
        """Expired-ban note must explain that requests were served a decoy."""
        block = _fn('class="gw-expired-ban"', after=400)
        assert "decoy" in block.lower(), (
            "Expired-ban note must mention 'decoy' to explain what happened"
        )

    def test_expired_ban_mentions_risk_threshold(self):
        """Expired-ban note must reference RISK_BAN_THRESHOLD for re-ban guidance."""
        block = _fn('class="gw-expired-ban"', after=500)
        assert "RISK_BAN_THRESHOLD" in block, (
            "Expired-ban note must reference RISK_BAN_THRESHOLD for operator guidance"
        )

    def test_expired_ban_has_view_logs_button(self):
        """Expired-ban note must include a 'View requests' button."""
        block = _fn('class="gw-expired-ban"', after=600)
        assert "gw-view-logs" in block, (
            "Expired-ban note must include a gw-view-logs button"
        )

    def test_expired_ban_note_inserted_in_return(self):
        """expiredBanNote must be included in the return template string."""
        assert "expiredBanNote" in _MAIN_SRC, (
            "expiredBanNote variable not found in main.html"
        )
        # There should be ${expiredBanNote} in the return template
        assert "${expiredBanNote}" in _MAIN_SRC, (
            "${expiredBanNote} must be interpolated in the return template"
        )


# ── 4. TestActiveBanTopReason ─────────────────────────────────────────────────

class TestActiveBanTopReason:
    """Active-ban header must skip outcome signals when picking the top reason."""

    def test_top_rsn_entry_uses_find_not_index(self):
        """topRsn must use breakdown.find() to skip outcome signals."""
        assert "topRsnEntry" in _MAIN_SRC, (
            "topRsnEntry variable not found — active-ban header must use find() to skip outcomes"
        )
        block = _fn("topRsnEntry", after=200)
        assert "_BAN_OUTCOME_SIGNALS.has" in block, (
            "topRsnEntry must filter via _BAN_OUTCOME_SIGNALS.has()"
        )

    def test_top_rsn_old_direct_index_removed(self):
        """The old direct breakdown[0][0] lookup for topRsn must be removed."""
        # Old code: const topRsn = breakdown.length ? escapeHtml(breakdown[0][0]) : '';
        # This is circular when banned-silent is breakdown[0].
        old_pattern = "breakdown[0][0]"
        # It should no longer appear in the banHdr block
        ban_hdr_block = _fn("let banHdr", "return `", after=0)
        assert old_pattern not in ban_hdr_block, (
            "Old direct breakdown[0][0] topRsn lookup must be replaced with "
            "find()-based topRsnEntry that skips outcome signals"
        )

    def test_ban_line_uses_toprsn_from_entry(self):
        """Ban line template must use topRsn derived from topRsnEntry."""
        # Use the JS template occurrence (class="gw-ban-line"), not the CSS rule (.gw-ban-line{)
        block = _fn('class="gw-ban-line"', after=200)
        assert "topRsn" in block, (
            "gw-ban-line must interpolate topRsn (derived from topRsnEntry)"
        )

    def test_ban_line_no_longer_says_likely(self):
        """'likely tripped' wording replaced with cleaner 'tripped' (no circular hedge)."""
        block = _fn('class="gw-ban-line"', after=200)
        assert "likely tripped" not in block, (
            "'likely tripped' wording should be removed — use 'tripped' (the topRsn "
            "already skips outcome signals, so it's an actual trigger signal)"
        )


# ── 5. TestBanOutcomeCSS ─────────────────────────────────────────────────────

class TestBanOutcomeCSS:
    """New CSS classes must be defined and use theme-aware colors."""

    def test_gw_expired_ban_css_defined(self):
        """gw-expired-ban CSS rule must exist."""
        assert ".gw-expired-ban{" in _MAIN_SRC or ".gw-expired-ban {" in _MAIN_SRC, (
            ".gw-expired-ban CSS rule not found"
        )

    def test_gw_expired_ban_uses_yellow(self):
        """gw-expired-ban must use yellow color scheme (warning, not error)."""
        block = _fn(".gw-expired-ban{", after=200)
        assert "210,153,34" in block or "yellow" in block.lower() or "var(--yellow)" in block, (
            ".gw-expired-ban must use yellow/warning color (not red/error)"
        )

    def test_gw_expired_ban_line_css_defined(self):
        """gw-expired-ban-line CSS rule must exist."""
        assert ".gw-expired-ban-line{" in _MAIN_SRC, (
            ".gw-expired-ban-line CSS rule not found"
        )

    def test_gw_expired_ban_line_uses_yellow_var(self):
        """gw-expired-ban-line must use var(--yellow) for text color."""
        block = _fn(".gw-expired-ban-line{", after=100)
        assert "var(--yellow)" in block, (
            ".gw-expired-ban-line must use var(--yellow) for color"
        )

    def test_gw_outcome_label_css_defined(self):
        """gw-outcome-label CSS rule must exist."""
        assert ".gw-outcome-label{" in _MAIN_SRC, (
            ".gw-outcome-label CSS rule not found"
        )

    def test_gw_outcome_label_uses_dim_color(self):
        """gw-outcome-label must use dim color (it's informational, not an error)."""
        block = _fn(".gw-outcome-label{", after=150)
        assert "var(--dim)" in block, (
            ".gw-outcome-label must use var(--dim) for color"
        )
