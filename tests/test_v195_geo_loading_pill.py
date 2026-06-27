"""
1.9.5 — GeoMap loading pill must update on EVERY fetch (range change, live tick),
not freeze on "Ready" after the first load.

Bug: the `ready` class latched after the first load and `_setLoadPct`/`_startLoadPct`
early-returned forever, so a slow timeline-window change gave no "Loading…" feedback
— and the done-state text literally read "Loading Ready" (a typo for "Ready").
"""
import os
import pathlib

os.environ.setdefault("UPSTREAM", "https://example.com")
_HTML = (pathlib.Path(__file__).resolve().parent.parent / "dashboards" / "geo.html").read_text()


def test_no_loading_ready_typo():
    assert "Loading Ready" not in _HTML, "done-state text must be 'Ready', not 'Loading Ready'"


def test_done_state_says_ready():
    assert "<span class=\"dot\"></span>Ready" in _HTML, "finish must set the pill to 'Ready'"


def test_no_ready_guard_early_return():
    # The latching guard that froze the pill after the first load must be gone.
    assert "classList.contains('ready')) return" not in _HTML, \
        "_setLoadPct/_startLoadPct must not early-return on the 'ready' class"


def test_startloadpct_clears_ready_on_new_fetch():
    assert "s.classList.remove('ready')" in _HTML, \
        "_startLoadPct must clear 'ready' so a new fetch shows 'Loading…' again"


def test_range_change_triggers_tick():
    assert "getElementById('range').onchange" in _HTML and "tick()" in _HTML, \
        "changing the timeline window must re-run tick() (which restarts the load pill)"
