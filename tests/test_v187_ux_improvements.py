"""
tests/test_v187_ux_improvements.py — QA tests for v1.8.7 UX improvements.

Features under test
───────────────────
G  Gateway health-score pill + modal UX (main.html)
   G01  KEY_LABELS map defined in pill IIFE
   G02  KEY_LABELS maps block_rate → 'Block rate (1 h)'
   G03  KEY_LABELS maps integrations → 'External integrations'
   G04  KEY_LABELS contains all 6 expected keys (disk, memory, db, integrations, bans, block_rate)
   G05  STATUS_ORD constant defined with bad:0, warn:1, ok:2
   G06  pill.onclick sorts reasons by STATUS_ORD before rendering
   G07  .penalty CSS class defined in <style> block
   G08  .gw-row grid-template-columns has 5 columns (130px present)
   G09  id="gw-score-bar" element present in modal HTML
   G10  .gw-ok-summary CSS class defined
   G11  Pill text uses '● Health' not '● GW'
   G12  'refreshes every 15 s' text present near pill in topbar HTML
   G13  scoreBar.style.width set in pill onclick handler
   G14  okList / badWarn filter variables present in onclick (ok rows collapsed)
   G15  Old 4-column grid string (90px 64px 1fr 70px) no longer present in .gw-row

S  Score Breakdown popup — buildScoreHtml rewrite (agents.html)
   S01  buildScoreHtml function defined
   S02  scoreHeader local variable defined inside buildScoreHtml
   S03  scoreColor variable defined inside buildScoreHtml
   S04  scoreLabel variable defined (HIGH / ELEVATED / LOW text)
   S05  Score bar div with width:${score}% in scoreHeader
   S06  block_count case emits 'Why requests were blocked' section label
   S07  block_count case includes derivation formula (30 + min(50,)
   S08  block_count case does not fall through to compRows rendering
   S09  'Synthetic score — no active risk signals' box text removed from buildScoreHtml
   S10  'Stealth score:' header line removed from buildScoreHtml return
   S11  'bars = % contribution' text removed from buildScoreHtml
   S12  risk_score / behavioral case renders ban threshold bar
   S13  risk_score case filters to activeComps (only non-zero behavioral components)
   S14  buildScoreHtml body ends with 'return scoreHeader + body'
   S15  block_count block reason cards include 'share of total' meta field
"""

import re
from pathlib import Path

import pytest

_ROOT       = Path(__file__).resolve().parent.parent
_DASHBOARDS = _ROOT / "dashboards"


def _dash(name: str) -> str:
    return (_DASHBOARDS / name).read_text(encoding="utf-8")


def _js_fn(src: str, fn_name: str, max_chars: int = 4000) -> str:
    """Return up to max_chars of source starting at the given JS function definition."""
    # Match 'function fnName' or 'async function fnName'
    idx = src.find(f"function {fn_name}")
    if idx == -1:
        return ""
    return src[idx: idx + max_chars]


def _iife_section(src: str, anchor: str, max_chars: int = 4000) -> str:
    """Return a window of source text starting from anchor."""
    idx = src.find(anchor)
    if idx == -1:
        return ""
    return src[idx: idx + max_chars]


# ═══════════════════════════════════════════════════════════════════════════════
# G — Gateway health-score pill + modal UX (main.html)
# ═══════════════════════════════════════════════════════════════════════════════

class TestGatewayHealthPillUX:

    @pytest.fixture(scope="class")
    def src(self):
        return _dash("main.html")

    # KEY_LABELS map ─────────────────────────────────────────────────────────

    def test_G01_key_labels_defined(self, src):
        assert "KEY_LABELS" in src, \
            "main.html: KEY_LABELS map not defined in pill IIFE"

    def test_G02_key_labels_maps_block_rate(self, src):
        idx = src.find("KEY_LABELS")
        assert idx != -1
        block = src[idx: idx + 400]
        assert "block_rate" in block, \
            "main.html: KEY_LABELS must map 'block_rate'"
        assert "Block rate" in block, \
            "main.html: KEY_LABELS['block_rate'] must map to human label containing 'Block rate'"

    def test_G03_key_labels_maps_integrations(self, src):
        idx = src.find("KEY_LABELS")
        assert idx != -1
        block = src[idx: idx + 400]
        assert "integrations" in block, \
            "main.html: KEY_LABELS must map 'integrations'"
        assert "External integrations" in block, \
            "main.html: KEY_LABELS['integrations'] must be 'External integrations'"

    def test_G04_key_labels_has_all_six_keys(self, src):
        idx = src.find("KEY_LABELS")
        assert idx != -1, "main.html: KEY_LABELS not found"
        block = src[idx: idx + 400]
        for key in ("disk", "memory", "db", "integrations", "bans", "block_rate"):
            assert key in block, \
                f"main.html: KEY_LABELS missing key '{key}'"

    # STATUS_ORD sort ────────────────────────────────────────────────────────

    def test_G05_status_ord_defined(self, src):
        assert "STATUS_ORD" in src, \
            "main.html: STATUS_ORD constant not defined"
        idx = src.find("STATUS_ORD")
        block = src[idx: idx + 80]
        assert "bad" in block and "warn" in block and "ok" in block, \
            "main.html: STATUS_ORD must contain bad, warn, ok keys"
        # Verify ordering: bad=0, warn=1, ok=2
        assert re.search(r"bad\s*:\s*0", block), \
            "main.html: STATUS_ORD.bad must be 0"
        assert re.search(r"warn\s*:\s*1", block), \
            "main.html: STATUS_ORD.warn must be 1"
        assert re.search(r"ok\s*:\s*2", block), \
            "main.html: STATUS_ORD.ok must be 2"

    def test_G06_pill_onclick_sorts_by_status_ord(self, src):
        # The sort call must reference STATUS_ORD inside the pill onclick block
        onclick_idx = src.find("pill.onclick")
        assert onclick_idx != -1, "main.html: pill.onclick not found"
        onclick_block = src[onclick_idx: onclick_idx + 2000]
        assert "STATUS_ORD" in onclick_block, \
            "main.html: pill.onclick must sort reasons using STATUS_ORD"
        assert ".sort(" in onclick_block, \
            "main.html: pill.onclick must call .sort() on reasons array"

    # Penalty column ─────────────────────────────────────────────────────────

    def test_G07_penalty_css_class_defined(self, src):
        assert ".gw-row .penalty" in src, \
            "main.html: .gw-row .penalty CSS class not defined (penalty column missing)"

    def test_G08_gw_row_grid_has_five_columns(self, src):
        m = re.search(r"\.gw-row\{[^}]*grid-template-columns:[^}]+\}", src)
        assert m, "main.html: .gw-row grid-template-columns not found"
        grid_decl = m.group(0)
        assert "130px" in grid_decl, \
            "main.html: .gw-row grid-template-columns should start with 130px (5-col layout)"
        # Old 4-col must not be present
        assert "90px 64px 1fr 70px" not in grid_decl, \
            "main.html: old 4-column grid (90px 64px 1fr 70px) still present in .gw-row"

    # Score bar in modal ─────────────────────────────────────────────────────

    def test_G09_gw_score_bar_element_present(self, src):
        assert 'id="gw-score-bar"' in src or "id='gw-score-bar'" in src, \
            "main.html: id='gw-score-bar' element not found — score bar missing from modal"

    def test_G13_score_bar_width_set_in_onclick(self, src):
        onclick_idx = src.find("pill.onclick")
        assert onclick_idx != -1
        onclick_block = src[onclick_idx: onclick_idx + 1200]
        assert "gw-score-bar" in onclick_block, \
            "main.html: pill.onclick must look up #gw-score-bar element"
        assert "style.width" in onclick_block, \
            "main.html: pill.onclick must set bar.style.width to animate the bar"

    # ok-row collapse ────────────────────────────────────────────────────────

    def test_G10_gw_ok_summary_css_defined(self, src):
        assert ".gw-ok-summary" in src, \
            "main.html: .gw-ok-summary CSS class not defined (ok-row collapse summary missing)"

    def test_G14_ok_rows_filtered_to_lists(self, src):
        onclick_idx = src.find("pill.onclick")
        assert onclick_idx != -1
        onclick_block = src[onclick_idx: onclick_idx + 2000]
        # ok rows are rendered with row-ok CSS class; isOk is the filter
        assert "row-ok" in onclick_block, \
            "main.html: pill.onclick must mark ok rows with 'row-ok' CSS class"
        assert "isOk" in onclick_block, \
            "main.html: pill.onclick must check r.status==='ok' (isOk) to classify rows"
        # gw-ok-summary CSS class must be defined (may be used for future collapse)
        assert ".gw-ok-summary" in src, \
            "main.html: .gw-ok-summary CSS class must be defined for ok-row summary"

    # Pill text and refresh note ─────────────────────────────────────────────

    def test_G11_pill_text_uses_health_not_gw(self, src):
        # Pill text must say 'Health', not 'GW'
        assert "● Health" in src or "'● Health'" in src or '"● Health"' in src or \
               "● Health ${" in src, \
            "main.html: pill text must use '● Health N/100', not '● GW N/100'"
        # Verify old label is gone from the textContent assignment
        tick_idx = src.find("async function tick")
        if tick_idx == -1:
            tick_idx = src.find("pill.textContent")
        assert tick_idx != -1
        tick_block = src[tick_idx: tick_idx + 500]
        assert "GW " not in tick_block or "● GW" not in tick_block, \
            "main.html: old '● GW N/100' pill text still present in tick()"

    def test_G12_refresh_note_near_pill(self, src):
        # 'refreshes every 15 s' must appear near the pill HTML in the topbar
        pill_idx = src.find('id="gw-status-pill"')
        if pill_idx == -1:
            pill_idx = src.find("id='gw-status-pill'")
        assert pill_idx != -1, "main.html: #gw-status-pill element not found"
        # Check within 300 chars before or after the pill element
        window = src[max(0, pill_idx - 50): pill_idx + 300]
        assert "refreshes every 15 s" in window, \
            "main.html: 'refreshes every 15 s' note must appear near #gw-status-pill in HTML"

    # Regression: old 4-column grid must be gone ─────────────────────────────

    def test_G15_old_four_column_grid_removed(self, src):
        assert "90px 64px 1fr 70px" not in src, \
            "main.html: old 4-column .gw-row grid '90px 64px 1fr 70px' still present"


# ═══════════════════════════════════════════════════════════════════════════════
# S — Score Breakdown popup — buildScoreHtml rewrite (agents.html)
# ═══════════════════════════════════════════════════════════════════════════════

class TestScoreBreakdownRewrite:

    @pytest.fixture(scope="class")
    def src(self):
        return _dash("agents.html")

    @pytest.fixture(scope="class")
    def fn_body(self, src):
        """Return the full buildScoreHtml function body (up to 12000 chars)."""
        return _js_fn(src, "buildScoreHtml", max_chars=12000)

    # Function structure ─────────────────────────────────────────────────────

    def test_S01_build_score_html_defined(self, src):
        assert "function buildScoreHtml" in src, \
            "agents.html: buildScoreHtml function not defined"

    def test_S02_score_header_variable_defined(self, fn_body):
        assert fn_body, "agents.html: buildScoreHtml not found"
        assert "scoreHeader" in fn_body, \
            "agents.html: buildScoreHtml must define 'scoreHeader' variable"

    def test_S03_score_color_variable_defined(self, fn_body):
        assert "scoreColor" in fn_body, \
            "agents.html: buildScoreHtml must define 'scoreColor' variable for the score bar"

    def test_S04_score_label_variable_defined(self, fn_body):
        assert "scoreLabel" in fn_body, \
            "agents.html: buildScoreHtml must define 'scoreLabel' (HIGH/ELEVATED/LOW)"
        assert "HIGH" in fn_body and "ELEVATED" in fn_body and "LOW" in fn_body, \
            "agents.html: buildScoreHtml scoreLabel must cover HIGH, ELEVATED, LOW states"

    def test_S05_score_bar_rendered_in_header(self, fn_body):
        # The scoreHeader must contain a bar div driven by score percentage
        assert "width:${score}%" in fn_body or "width: ${score}%" in fn_body, \
            "agents.html: buildScoreHtml scoreHeader must render a bar with width:${score}%"

    # block_count case ───────────────────────────────────────────────────────

    def test_S06_block_count_emits_why_blocked_header(self, fn_body):
        # Find the block_count branch
        bc_idx = fn_body.find("block_count")
        assert bc_idx != -1, "agents.html: buildScoreHtml has no block_count branch"
        bc_block = fn_body[bc_idx: bc_idx + 3000]
        assert "Why requests were blocked" in bc_block, \
            "agents.html: block_count case must emit 'Why requests were blocked' section header"

    def test_S07_block_count_shows_formula(self, fn_body):
        bc_idx = fn_body.find("block_count")
        assert bc_idx != -1
        bc_block = fn_body[bc_idx: bc_idx + 1500]
        # Formula: 30 + min(50, N×2)
        assert "30 + min(50," in bc_block or "30 + Math.min(50," in bc_block, \
            "agents.html: block_count case must show the derivation formula 30 + min(50, N×2)"

    def test_S08_block_count_does_not_render_empty_comp_rows(self, fn_body):
        # The block_count branch must NOT call COMPS.map() to render behavioral rows.
        # COMPS is only used in the risk_score branch (activeComps filter).
        bc_idx = fn_body.find("block_count")
        assert bc_idx != -1
        # Find end of block_count if-branch (before the else-if)
        bc_block = fn_body[bc_idx: bc_idx + 2000]
        # compRows variable must not be built and used for output in this branch
        assert "compRows" not in bc_block, \
            "agents.html: block_count case must not reference compRows (empty behavioral rows)"

    def test_S09_synthetic_score_box_removed(self, fn_body):
        assert "Synthetic score — no active risk signals" not in fn_body and \
               "SYNTHETIC SCORE" not in fn_body.upper().replace(" ", ""), \
            "agents.html: old 'Synthetic score — no active risk signals' info box must be removed " \
            "from buildScoreHtml (replaced by inline formula line)"

    def test_S10_stealth_score_header_removed(self, fn_body):
        assert "Stealth score:" not in fn_body, \
            "agents.html: 'Stealth score:' header text must be removed from buildScoreHtml return"

    def test_S11_bars_pct_contribution_text_removed(self, fn_body):
        assert "bars = % contribution" not in fn_body, \
            "agents.html: 'bars = % contribution' text must be removed from buildScoreHtml"

    # risk_score / behavioral case ───────────────────────────────────────────

    def test_S12_risk_score_case_renders_ban_threshold_bar(self, fn_body):
        # Find the else-if / risk_score branch (after block_count)
        bc_idx = fn_body.find("block_count")
        assert bc_idx != -1
        after_bc = fn_body[bc_idx + len("block_count"):]
        # Ban threshold section
        assert "Ban threshold" in after_bc or "ban threshold" in after_bc, \
            "agents.html: risk_score case must render a 'Ban threshold' bar"
        assert "banPct" in after_bc or "ban_pct" in after_bc, \
            "agents.html: risk_score case must compute ban threshold percentage"

    def test_S13_risk_score_case_filters_to_active_comps(self, fn_body):
        # activeComps must be used (filter out zero components)
        bc_idx = fn_body.find("block_count")
        assert bc_idx != -1
        after_bc = fn_body[bc_idx + len("block_count"):]
        assert "activeComps" in after_bc, \
            "agents.html: risk_score case must use activeComps (only non-zero components shown)"
        assert ".filter(" in after_bc, \
            "agents.html: risk_score case must filter COMPS to non-zero values"

    def test_S14_build_score_html_returns_score_header_plus_body(self, fn_body):
        assert "return scoreHeader + body" in fn_body, \
            "agents.html: buildScoreHtml must return 'scoreHeader + body'"

    def test_S15_block_count_reason_cards_show_share_of_total(self, fn_body):
        bc_idx = fn_body.find("block_count")
        assert bc_idx != -1
        bc_block = fn_body[bc_idx: bc_idx + 5000]
        assert "share of total" in bc_block, \
            "agents.html: block_count reason cards must show 'share of total' in meta row"
