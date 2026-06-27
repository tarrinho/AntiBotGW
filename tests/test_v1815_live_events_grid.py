"""
1.8.15 — Live events grid alignment.

Bug: the row renderer in main.html outputs 8 cells per row
(Time · Verdict · IP · Domain · Status · Score · Path · Action), but the
CSS grid template + header had only 7 columns. Cells overflowed one
position right → Score showed in the Path column, ban control wrapped to
the next visual line.

Fix: grid template uses 8 columns; header `.evt-hdr` lists 8 spans
matching the row output order.

Coverage:
  TestLiveEventsGridSource — count CSS columns vs header spans vs row cells
"""
import pathlib
import re


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MN   = (_ROOT / "dashboards" / "main.html").read_text(encoding="utf-8")


def _grid_col_count(css_line: str) -> int:
    """Return the number of column tracks in a grid-template-columns rule."""
    m = re.search(r"grid-template-columns:([^;}]+)", css_line)
    assert m, "no grid-template-columns rule found"
    tracks = m.group(1).strip().split()
    return len(tracks)


def _header_span_count(html: str) -> int:
    """Count <span> children inside the evt-hdr div."""
    m = re.search(
        r'<div class="evt-hdr"[^>]*>([\s\S]*?)</div>', html)
    assert m, "no .evt-hdr div found"
    return len(re.findall(r"<span\b[^>]*>", m.group(1)))


def _row_cell_count(js: str) -> int:
    """Count TOP-LEVEL <span> children inside the row template literal.

    Nested spans inside `${...}` interpolations (e.g. the literal
    `<span class="dim">—</span>` inside the Score cell's conditional)
    must NOT be counted as separate cells — they're rendered inside a
    parent cell. Top-level cells in this template are each on their own
    line with 6-space indentation.
    """
    idx = js.find('return `<div class="evt ')
    assert idx != -1, "row template not found"
    end = js.find("`;", idx + 10)
    template = js[idx: end]
    # Only lines that begin with exactly 6 spaces + <span are top-level cells.
    return len(re.findall(r"(?m)^      <span\b", template))


# ── 1. Source-level guard: counts must agree ───────────────────────────────

class TestLiveEventsGridSource:

    def test_grid_has_8_columns(self):
        m = re.search(
            r"\.evt,\.evt-hdr\{[^}]*grid-template-columns:([^;}]+)",
            _MN)
        assert m, "evt/evt-hdr grid rule missing"
        tracks = m.group(1).strip().split()
        assert len(tracks) == 8, (
            f"Live events grid must have 8 columns (Time, Verdict, IP, Domain, "
            f"Status, Score, Path, Action); got {len(tracks)}: {tracks}"
        )

    def test_header_has_8_spans(self):
        assert _header_span_count(_MN) == 8, (
            "Live events header must declare 8 columns (Time, Verdict, IP, "
            "Domain, Status, Score, Path, Action)"
        )

    def test_header_includes_domain_label(self):
        m = re.search(r'<div class="evt-hdr"[^>]*>([\s\S]*?)</div>', _MN)
        assert m
        assert ">Domain<" in m.group(1), (
            "Domain column header missing — without it the row's vhost cell "
            "appears unlabelled"
        )

    def test_row_renderer_emits_8_cells(self):
        idx = _MN.find("function _renderEvents(")
        assert idx != -1
        nxt = _MN.find("\nfunction ", idx + 10)
        block = _MN[idx: nxt if nxt != -1 else idx + 6000]
        assert _row_cell_count(block) == 8, (
            f"Live events row must render 8 top-level cells; got {_row_cell_count(block)}"
        )

    def test_grid_and_header_and_row_agree(self):
        """Single source of truth: every place that counts cells must agree."""
        m = re.search(
            r"\.evt,\.evt-hdr\{[^}]*grid-template-columns:([^;}]+)",
            _MN)
        grid_cols = len(m.group(1).strip().split())
        hdr_cells = _header_span_count(_MN)
        idx = _MN.find("function _renderEvents(")
        nxt = _MN.find("\nfunction ", idx + 10)
        block = _MN[idx: nxt if nxt != -1 else idx + 6000]
        row_cells = _row_cell_count(block)
        assert grid_cols == hdr_cells == row_cells, (
            f"Live events grid mismatch: CSS={grid_cols} cols, "
            f"header={hdr_cells} spans, row={row_cells} cells — all three "
            "must match or rows will misalign"
        )

    def test_path_column_capped_with_minmax(self):
        """Path column (7th) must be bounded with minmax(0, MAX) so a long
        path ellipsises rather than pushing Action off-screen."""
        m = re.search(
            r"\.evt,\.evt-hdr\{[^}]*grid-template-columns:([^;}]+)",
            _MN)
        tracks = m.group(1).strip().split()
        path_track = tracks[6]  # 7th = Path
        assert path_track.startswith("minmax("), (
            f"Path column must use minmax(0, MAX) to cap width; got {path_track!r}"
        )
        # Must have 0 as min so it can shrink and ellipsis kicks in
        assert "minmax(0" in path_track, (
            f"Path column minmax min must be 0 (allows shrink + ellipsis); got {path_track!r}"
        )

    def test_cells_have_overflow_ellipsis(self):
        """Every grid cell except the last (Action with buttons) must have
        overflow:hidden + text-overflow:ellipsis so content can't overlap
        the next column."""
        assert re.search(
            r"\.evt\s*>\s*span,\s*\.evt-hdr\s*>\s*span\s*\{[^}]*overflow:hidden",
            _MN), (
            ".evt > span / .evt-hdr > span must set overflow:hidden"
        )
        assert re.search(
            r"\.evt\s*>\s*span,\s*\.evt-hdr\s*>\s*span\s*\{[^}]*text-overflow:ellipsis",
            _MN), (
            ".evt > span / .evt-hdr > span must set text-overflow:ellipsis"
        )
        assert re.search(
            r"\.evt\s*>\s*span,\s*\.evt-hdr\s*>\s*span\s*\{[^}]*min-width:0",
            _MN), (
            ".evt > span / .evt-hdr > span must set min-width:0 (required for "
            "grid-item ellipsis to actually shrink)"
        )

    def test_action_column_exempt_from_ellipsis(self):
        """The Action column hosts ban buttons (.ban-ctrl, .ban-btn); ellipsis
        would clip them. The :last-child rule must override the global ellipsis."""
        assert re.search(
            r"\.evt\s*>\s*span:last-child[^{]*\{[^}]*overflow:visible",
            _MN), (
            "Action column (:last-child) must set overflow:visible — ellipsis "
            "would clip ban buttons"
        )
