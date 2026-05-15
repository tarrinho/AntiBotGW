"""
Dashboard UI and chart QA — static-analysis checks for:

  Chart fills (all three main dashboards):
    - fill: 'origin' minimum count per file
    - solid rgba backgroundColor (no gradients, no scriptable functions)
    - rgba alpha >= MIN_ALPHA (visibly solid)

  Popover viewport clamping (agents.html):
    - openPopover() sets maxHeight + overflowY before getBoundingClientRect()
      so tall identity details never overflow the viewport without a scrollbar
    - closePopover() still resets overrides for the next openBucketDetail() call

  Modal scrollability (main.html):
    - .modal CSS has max-height and overflow:auto so centered identity modal
      stays within viewport on small screens

Run as part of any release that touches dashboards/agents.html or dashboards/main.html.
"""
import re
from pathlib import Path

import pytest

_DASHBOARDS = Path(__file__).resolve().parent.parent / "dashboards"
MIN_ALPHA = 0.30

# Minimum number of fill:'origin' data-series datasets expected per file.
# Threshold lines (fill:false) and stacked db datasets (fill:true) are excluded.
_EXPECTED_ORIGIN_FILLS = {
    "main.html":    9,
    "service.html": 6,
    "agents.html":  5,
}

_RGBA_RE = re.compile(
    r"backgroundColor\s*:\s*['\"]rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([\d.]+)\s*\)['\"]"
)


def _read(name: str) -> str:
    return (_DASHBOARDS / name).read_text(encoding="utf-8")


# ── fill: 'origin' minimum count ──────────────────────────────────────────

@pytest.mark.parametrize("filename,min_count", list(_EXPECTED_ORIGIN_FILLS.items()))
def test_chart_fill_origin_minimum_count(filename, min_count):
    src = _read(filename)
    count = len(re.findall(r"fill\s*:\s*['\"]origin['\"]", src))
    assert count >= min_count, (
        f"{filename}: expected ≥{min_count} fill:'origin' datasets, found {count}. "
        "Data-series charts must fill to the x-axis."
    )


# ── no gradient fills ─────────────────────────────────────────────────────

@pytest.mark.parametrize("filename", list(_EXPECTED_ORIGIN_FILLS.keys()))
def test_no_gradient_background_color(filename):
    src = _read(filename)
    assert "createLinearGradient" not in src, (
        f"{filename}: createLinearGradient found — use solid rgba() string instead of canvas gradient."
    )


# ── no scriptable (function) backgroundColor ──────────────────────────────

@pytest.mark.parametrize("filename", list(_EXPECTED_ORIGIN_FILLS.keys()))
def test_no_scriptable_background_color_function(filename):
    src = _read(filename)
    m = re.search(r"backgroundColor\s*:\s*(?:function\s*\(|(?:\w+\s*)?=>)", src)
    assert m is None, (
        f"{filename}: scriptable backgroundColor function at char {m.start()} — "
        "use a static rgba() string (gradient-via-function not allowed)."
    )


# ── rgba alpha >= MIN_ALPHA ───────────────────────────────────────────────

@pytest.mark.parametrize("filename", list(_EXPECTED_ORIGIN_FILLS.keys()))
def test_background_color_alpha_is_solid(filename):
    src = _read(filename)
    matches = [(m.group(0), float(m.group(4))) for m in _RGBA_RE.finditer(src)]
    assert matches, f"{filename}: no rgba backgroundColor found — check dataset definitions."
    faint = [(val, alpha) for val, alpha in matches if alpha < MIN_ALPHA]
    assert not faint, (
        f"{filename}: {len(faint)} backgroundColor(s) have alpha < {MIN_ALPHA} (too transparent). "
        f"Offenders: {[v for v,_ in faint]}"
    )


# ── rgba backgroundColor count matches fill:'origin' count ────────────────

@pytest.mark.parametrize("filename,min_count", list(_EXPECTED_ORIGIN_FILLS.items()))
def test_background_color_count_matches_fill_origin(filename, min_count):
    src = _read(filename)
    rgba_count = len(_RGBA_RE.findall(src))
    origin_count = len(re.findall(r"fill\s*:\s*['\"]origin['\"]", src))
    # rgba count must be >= origin count (stacked/threshold may add extra rgba entries)
    assert rgba_count >= origin_count, (
        f"{filename}: {rgba_count} rgba backgroundColor(s) but {origin_count} fill:'origin' datasets — "
        "every fill:'origin' dataset must have a backgroundColor."
    )


# ── agents.html popover viewport clamping ─────────────────────────────────
# openPopover() must constrain the popover to the viewport height and enable
# overflow-y scroll BEFORE measuring getBoundingClientRect(), so positioning
# math uses the clamped height rather than the unconstrained height.
# Without this, tall identity-detail popovers on rows near the bottom of the
# screen extend below the viewport with no way to scroll.

def test_agents_popover_sets_max_height_before_rect():
    src = _read("agents.html")
    # Both must appear in openPopover — verify ordering:
    # maxHeight assignment must come before getBoundingClientRect()
    max_h_idx = src.find("window.innerHeight - 24")
    rect_idx   = src.find("getBoundingClientRect()", max_h_idx if max_h_idx != -1 else 0)
    assert max_h_idx != -1, (
        "agents.html: openPopover() must set maxHeight = (window.innerHeight - 24) + 'px' "
        "before getBoundingClientRect() so tall popovers fit in the viewport."
    )
    assert rect_idx != -1 and rect_idx > max_h_idx, (
        "agents.html: maxHeight constraint must appear BEFORE getBoundingClientRect() "
        "in openPopover() so the measured rect uses the clamped height."
    )


def _agents_open_popover_body(src: str) -> str:
    """Extract the body of openPopover() — from its definition to the next function."""
    start = src.find("function openPopover(")
    assert start != -1, "agents.html: openPopover() function not found."
    # find the next top-level function or async function after openPopover
    next_fn = re.search(r'\n(?:async\s+)?function\s+\w', src[start + 1:])
    end = (start + 1 + next_fn.start()) if next_fn else len(src)
    return src[start:end]


def test_agents_popover_sets_overflow_y_auto():
    src = _read("agents.html")
    body = _agents_open_popover_body(src)
    assert "overflowY = 'auto'" in body or 'overflowY = "auto"' in body, (
        "agents.html: openPopover() must set overflowY = 'auto' so tall identity "
        "details are scrollable when the popover is constrained to the viewport height."
    )


def test_agents_popover_open_does_not_clear_max_height():
    src = _read("agents.html")
    body = _agents_open_popover_body(src)
    # openPopover must not clear maxHeight (that's closePopover's job)
    assert "maxHeight = ''" not in body and 'maxHeight = ""' not in body, (
        "agents.html: openPopover() must not clear maxHeight — it should SET it "
        "to constrain the popover. Only closePopover() should clear it."
    )


def test_agents_close_popover_resets_max_height():
    src = _read("agents.html")
    close_fn_idx = src.find("function closePopover(")
    assert close_fn_idx != -1, "agents.html: closePopover() not found."
    # find end of closePopover (next function definition or end of script)
    next_fn = src.find("\nfunction ", close_fn_idx + 1)
    close_body = src[close_fn_idx: next_fn if next_fn != -1 else close_fn_idx + 500]
    assert "maxHeight = ''" in close_body or 'maxHeight = ""' in close_body, (
        "agents.html: closePopover() must reset maxHeight = '' so openBucketDetail() "
        "can set its own size override without interference."
    )


# ── main.html modal scrollability ─────────────────────────────────────────
# The centered identity modal must have max-height and overflow:auto in CSS
# so it never extends off-screen on short viewports.

# ── agents.html gwmgmt tooltip coverage ───────────────────────────────────
# The 'gw mgmt' dataset (datasets[4]) must be active by default so Chart.js
# includes it in the tooltip. Chart.js 4 skips hidden datasets in the tooltip,
# so if the gwmgmt filter is off on load the tooltip row is silently absent.

def test_agents_gwmgmt_in_initial_active_filters():
    src = _read("agents.html")
    m = re.search(r"window\._activeFilters\s*=\s*new Set\(\[([^\]]+)\]\)", src)
    assert m, "agents.html: window._activeFilters initial Set not found."
    filters_str = m.group(1)
    assert "'gwmgmt'" in filters_str or '"gwmgmt"' in filters_str, (
        "agents.html: 'gwmgmt' missing from initial window._activeFilters Set. "
        "datasets[4] starts hidden so Chart.js omits it from the tooltip."
    )


def test_agents_gwmgmt_pill_active_by_default():
    src = _read("agents.html")
    # The gwmgmt pill must have class="active" (or class="cat-pill active")
    m = re.search(r'<button[^>]*data-cat=["\']gwmgmt["\'][^>]*>', src)
    assert m, "agents.html: gwmgmt cat-pill button not found."
    assert "active" in m.group(0), (
        f"agents.html: gwmgmt cat-pill is not active by default: {m.group(0)!r}. "
        "Without 'active', datasets[4].hidden=true on load and the tooltip row is missing."
    )


# ── main.html modal scrollability ─────────────────────────────────────────
# The centered identity modal must have max-height and overflow:auto in CSS
# so it never extends off-screen on short viewports.

def test_main_modal_css_has_max_height():
    src = _read("main.html")
    # find the .modal CSS block and check it contains both constraints
    modal_css = re.search(r'\.modal\{[^}]+\}', src)
    assert modal_css, "main.html: .modal CSS rule not found."
    block = modal_css.group(0)
    assert "max-height" in block, (
        "main.html: .modal CSS must include max-height so the identity modal "
        "stays within the viewport on short screens."
    )
    assert "overflow" in block, (
        "main.html: .modal CSS must include overflow:auto so content inside "
        "the identity modal is scrollable when it exceeds max-height."
    )


# ── vhost breakdown chart: canvas reuse guard ─────────────────────────────
# Chart.js raises "Canvas is already in use" when new Chart() is called on a
# canvas that already has a chart registered in its internal registry.  This
# happens when the IIFE re-runs (navigation / script re-injection) and resets
# _vhChart to null while the old chart instance still occupies the canvas.
# The fix: call Chart.getChart(ctx) before new Chart() and destroy any
# orphaned instance that is not our own _vhChart reference.

def test_vhost_chart_orphan_guard_uses_chart_get_chart():
    """main.html must call Chart.getChart before creating the vhost chart."""
    src = _read("main.html")
    assert "Chart.getChart" in src, (
        "main.html: Chart.getChart() orphan-guard missing from vhost-breakdown "
        "chart — adding a new Chart() on a canvas that already has one registered "
        "will raise 'Canvas is already in use'."
    )


def test_vhost_chart_orphan_guard_destroys_orphan():
    """main.html must call destroy() on the orphaned chart before new Chart()."""
    src = _read("main.html")
    # The guard is in the JS section — locate it by the new-chart assignment
    # which immediately follows the guard, not the canvas HTML element.
    new_chart_pos = src.find("_vhChart = new Chart(ctx,")
    assert new_chart_pos != -1, "main.html: _vhChart = new Chart(ctx, ...) not found"
    # Scan the 400 chars before new Chart() for the orphan guard
    block = src[max(0, new_chart_pos - 400): new_chart_pos]
    assert "_orphan" in block and "destroy" in block, (
        "main.html: orphaned chart must be destroyed before new Chart() "
        "on vhost-breakdown-chart — pattern: if(_orphan){ _orphan.destroy(); }"
    )


def test_vhost_chart_orphan_guard_precedes_new_chart():
    """The orphan-destroy guard must appear before new Chart() in source order."""
    src = _read("main.html")
    orphan_pos = src.find("Chart.getChart")
    new_chart_pos = src.find("_vhChart = new Chart(ctx,")
    assert orphan_pos != -1, "main.html: Chart.getChart orphan check not found"
    assert new_chart_pos != -1, "main.html: _vhChart = new Chart(ctx, ...) not found"
    assert orphan_pos < new_chart_pos, (
        "main.html: Chart.getChart orphan check must appear BEFORE "
        "the new Chart(ctx, ...) call for vhost-breakdown-chart"
    )


# ── vhost breakdown chart: date-adapter fix ───────────────────────────────
# Chart.js 3+ type:'time' requires a registered date adapter (date-fns, luxon,
# etc.).  Without one it throws "This method is not implemented: Check that a
# complete date adapter is provided." — silently caught by .catch() so the
# status bar shows the error string instead of a working chart.
#
# Fix: use type:'category' with pre-formatted string labels (fmtTime) — no
# adapter needed, same axis behaviour as the main traffic chart.

def test_vhost_chart_does_not_use_time_axis():
    """vhost-breakdown chart must NOT use type:'time' (no date adapter bundled)."""
    src = _read("main.html")
    new_chart_pos = src.find("_vhChart = new Chart(ctx,")
    assert new_chart_pos != -1, "_vhChart = new Chart(ctx, ...) not found"
    # Inspect the 600 chars after new Chart() — that covers the options block
    block = src[new_chart_pos: new_chart_pos + 600]
    assert "type:'time'" not in block and 'type: "time"' not in block, (
        "main.html: vhost-breakdown chart uses type:'time' without a bundled "
        "date adapter — Chart.js raises 'This method is not implemented'. "
        "Use type:'category' with pre-formatted string labels instead."
    )


def test_vhost_chart_uses_category_axis():
    """vhost-breakdown chart must use type:'category' for its x-axis."""
    src = _read("main.html")
    new_chart_pos = src.find("_vhChart = new Chart(ctx,")
    assert new_chart_pos != -1, "_vhChart = new Chart(ctx, ...) not found"
    block = src[new_chart_pos: new_chart_pos + 600]
    assert "type:'category'" in block or "type: 'category'" in block, (
        "main.html: vhost-breakdown chart x-axis is not type:'category'. "
        "Without a date adapter, type:'time' will crash."
    )


def test_vhost_chart_labels_use_fmtTime():
    """vhost-breakdown must format timestamp labels with fmtTime(), not new Date()."""
    src = _read("main.html")
    # The labels map expression inside loadVhostBreakdown
    load_pos = src.find("function loadVhostBreakdown")
    assert load_pos != -1, "loadVhostBreakdown not found in main.html"
    block = src[load_pos: load_pos + 800]
    assert "fmtTime(" in block, (
        "main.html: loadVhostBreakdown() must use fmtTime() to produce string "
        "labels for the category axis — raw Date objects require type:'time'."
    )
    assert "new Date(ts*1000)" not in block, (
        "main.html: loadVhostBreakdown() still maps labels to Date objects. "
        "Switch to fmtTime(ts, bucket, range) string labels."
    )
