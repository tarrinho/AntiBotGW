"""
Source-code regression tests for the block-rate chart in dashboards/main.html.
Guards against the 3 bugs fixed in 1.7.2:
  1. hardcoded ?range=60 fetch inside the block-rate function
  2. duplicate HTTP call on every 5s interval
  3. toISOString().slice(11,16) label format instead of fmtTime(b.t, bucketSec)
"""
import re
from pathlib import Path

_MAIN_HTML = (Path(__file__).parent.parent / "dashboards" / "main.html").read_text(encoding="utf-8")


# ── helpers ──────────────────────────────────────────────────────────────

def _extract_function(src: str, fn_name: str) -> str:
    """Return the source text of a named JS function (brace-balanced)."""
    # Match `function name(...)` or `const/let/var name = (...) =>`
    pat = re.compile(
        r"(?:(?:async\s+)?function\s+" + re.escape(fn_name) + r"\s*\([^)]*\)\s*\{|"
        r"(?:const|let|var)\s+" + re.escape(fn_name) + r"\s*=\s*(?:async\s*)?\(?[^)]*\)?\s*=>\s*\{)"
    )
    m = pat.search(src)
    if not m:
        return ""
    brace_start = src.index("{", m.start())
    depth = 0; i = brace_start
    while i < len(src):
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[m.start():i + 1]
        i += 1
    return src[m.start():]


def _extract_between(src: str, start_marker: str, end_marker: str) -> str:
    a = src.find(start_marker)
    if a == -1:
        return ""
    b = src.find(end_marker, a + len(start_marker))
    if b == -1:
        return src[a:]
    return src[a:b + len(end_marker)]


# ── regression tests ─────────────────────────────────────────────────────

def test_no_hardcoded_range_60_fetch_in_blockrate():
    """Bug 1: paintBlockRate must not fetch metrics?range=60 on its own."""
    fn = _extract_function(_MAIN_HTML, "paintBlockRate")
    assert fn, "paintBlockRate function not found in main.html"
    assert "range=60" not in fn, "paintBlockRate still contains hardcoded ?range=60 fetch"


def test_no_fetch_call_in_paintblockrate():
    """Bug 1 (deeper): no fetch() at all inside paintBlockRate."""
    fn = _extract_function(_MAIN_HTML, "paintBlockRate")
    assert fn, "paintBlockRate function not found in main.html"
    assert "fetch(" not in fn, "paintBlockRate should not call fetch() — reads cached timeline"


def test_paintblockrate_reads_lastmaintimeline():
    """paintBlockRate must read window._lastMainTimeline (the cached data)."""
    fn = _extract_function(_MAIN_HTML, "paintBlockRate")
    assert fn, "paintBlockRate function not found in main.html"
    assert "_lastMainTimeline" in fn, "paintBlockRate does not read _lastMainTimeline"


def test_paintblockrate_reads_lastmainbucketsecs():
    """paintBlockRate must read window._lastMainBucketSecs for label formatting."""
    fn = _extract_function(_MAIN_HTML, "paintBlockRate")
    assert fn, "paintBlockRate function not found in main.html"
    assert "_lastMainBucketSecs" in fn, "paintBlockRate does not read _lastMainBucketSecs"


def test_setinterval_does_not_call_loadblockrate():
    """Bug 2: setInterval must not include loadBlockRate (deduplicates HTTP call)."""
    interval_block = _extract_between(
        _MAIN_HTML,
        "setInterval(",
        ");"
    )
    assert "loadBlockRate" not in interval_block, \
        "setInterval still calls loadBlockRate — duplicate fetch every 5s"


def test_window_paintblockrate_exposed():
    """paintBlockRate must be exported as window._paintBlockRate for tick() to call."""
    assert "window._paintBlockRate" in _MAIN_HTML, \
        "window._paintBlockRate not set — tick() cannot call it"


def test_tick_calls_window_paintblockrate():
    """tick() must call window._paintBlockRate after updating the main chart."""
    tick_fn = _extract_function(_MAIN_HTML, "tick")
    assert tick_fn, "tick function not found in main.html"
    assert "_paintBlockRate" in tick_fn, \
        "tick() does not call window._paintBlockRate"


def test_uses_fmttime_for_labels():
    """Bug 3: labels must use fmtTime(b.t, bucketSec) not toISOString()."""
    fn = _extract_function(_MAIN_HTML, "paintBlockRate")
    assert fn, "paintBlockRate function not found in main.html"
    assert "fmtTime(" in fn, "paintBlockRate does not use fmtTime() for labels"


def test_no_toisostring_in_paintblockrate():
    """Bug 3 (deeper): toISOString() must not appear in paintBlockRate."""
    fn = _extract_function(_MAIN_HTML, "paintBlockRate")
    assert fn, "paintBlockRate function not found in main.html"
    assert "toISOString" not in fn, \
        "paintBlockRate still uses toISOString() — should use fmtTime()"


def test_yaxis_min_0_max_100():
    """Y-axis must be bounded 0–100 for a percentage chart."""
    fn = _extract_function(_MAIN_HTML, "paintBlockRate")
    assert fn, "paintBlockRate function not found in main.html"
    assert "min: 0" in fn or "min:0" in fn, "y-axis min is not 0"
    assert "max: 100" in fn or "max:100" in fn, "y-axis max is not 100"


def test_formula_includes_missed_bucket():
    """Block-rate formula must account for b.missed to avoid inflated percentages."""
    fn = _extract_function(_MAIN_HTML, "paintBlockRate")
    assert fn, "paintBlockRate function not found in main.html"
    assert "missed" in fn, "paintBlockRate formula does not include b.missed"
