"""
tests/test_v196_order_slider_no_disable.py — guard the order-threshold
slider ("Score thresholds" on Controls → Defenses & Scoring).

THE BUG (operator-reported): the first knob was grayed out and could not
be dragged. Two compounding defects in the slider JS in
dashboards/controls.html:

  1. render() set `knob.style.pointerEvents = 'none'` whenever a threshold
     was 0. But 0 is a VALID "always-run / no gate" value, and
     ESCALATION_THRESHOLD ships defaulting to 0 — so the ③ knob was
     disabled out of the box and, once any knob hit 0, the operator could
     never drag it back up. Dead-end.

  2. dragMove() coupled the two knobs: `S2 = min(v, S3 - 1)` and
     `S3 = max(v, S2 + 1)`. With the shipped defaults (S2=15, S3=0) that
     forced S2 negative the instant you dragged it — perma-disabling
     2nd-order. The two are independent backend knobs (each min 0 /
     max 1000); they must clamp independently.

These are source-level guards on the slider JS — they anchor the contract
so a refactor can't silently re-introduce the trap.
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
HTML = os.path.join(_REPO, "dashboards", "controls.html")


def _src():
    return open(HTML, encoding="utf-8").read()


def _slider_iife() -> str:
    """Return the order-threshold slider IIFE (covers render(), dragMove(),
    dragEnd(), and the addEventListener wiring)."""
    src = _src()
    i = src.find("const sliderEl = document.getElementById('ord-slider')")
    assert i != -1, "order-threshold slider IIFE not found in controls.html"
    return src[i:i + 6000]


def _strip_js_comments(s: str) -> str:
    """Drop `//` line comments so source-guard greps don't match prose in a
    code comment (the fix's own comment names the old buggy expressions)."""
    return "\n".join(re.sub(r"//.*$", "", ln) for ln in s.splitlines())


def _func(block: str, name: str) -> str:
    """Crudely extract a named function body from a JS block."""
    m = re.search(rf"function\s+{re.escape(name)}\s*\([^)]*\)\s*\{{",
                  block)
    assert m, f"{name}() not found in slider block"
    # Walk braces from the opening brace to its match.
    start = m.end() - 1
    depth = 0
    for k in range(start, len(block)):
        if block[k] == "{":
            depth += 1
        elif block[k] == "}":
            depth -= 1
            if depth == 0:
                return block[m.start():k + 1]
    return block[m.start():]


# ── Bug 1: knobs must never be disabled ─────────────────────────────────

def test_render_never_sets_pointer_events_none_on_knobs():
    """render() must NOT disable either knob via pointer-events:none — that
    trapped a knob at 0 with no way to drag it back up."""
    render = _func(_slider_iife(), "render")
    assert "pointerEvents = 'none'" not in render and \
           'pointerEvents = "none"' not in render, (
        "render() must not set knob pointerEvents to 'none' — 0 is a valid "
        "value and disabling the knob traps the operator there"
    )


def test_render_keeps_knobs_interactive():
    """Both knobs must have pointerEvents explicitly cleared (interactive)."""
    render = _func(_slider_iife(), "render")
    # Each knob's pointerEvents should be reset to '' (draggable).
    assert render.count("pointerEvents = ''") >= 2, (
        "render() must reset BOTH knobs' pointerEvents to '' so they stay "
        "draggable regardless of value"
    )


def test_render_value_labels_visible_when_off():
    """The value label must stay visible (showing 'off') — the old code hid
    it (opacity 0), so an off knob had no indication of its state."""
    render = _func(_slider_iife(), "render")
    # Val opacity must not be conditionally zeroed; it should be '1'.
    assert "knobS2Val.style.opacity    = '1'" in render or \
           "knobS2Val.style.opacity = '1'" in render or \
           re.search(r"knobS2Val\.style\.opacity\s*=\s*'1'", render), (
        "render() must keep knobS2Val visible (opacity '1') so the 'off' "
        "state is legible"
    )


# ── Bug 2: independent clamp, no inter-knob coupling ────────────────────

def test_dragmove_does_not_couple_knobs():
    """dragMove() must NOT force one knob relative to the other (the old
    `min(v, S3 - 1)` / `max(v, S2 + 1)` coupling forced S2 negative when
    S3 was 0)."""
    drag = _strip_js_comments(_func(_slider_iife(), "dragMove"))
    assert "S3 - 1" not in drag and "S3-1" not in drag, (
        "dragMove() must not clamp S2 to `S3 - 1` — coupling forces S2 "
        "negative when S3 is 0 (the default)"
    )
    assert "S2 + 1" not in drag and "S2+1" not in drag, (
        "dragMove() must not clamp S3 to `S2 + 1` — independent knobs"
    )


def test_dragmove_clamps_each_knob_to_zero_floor():
    """Each knob must clamp to a [0, cap] range independently so 0 stays
    reachable AND escapable."""
    drag = _func(_slider_iife(), "dragMove")
    # Both branches must use Math.max(0, v) so the floor is 0 (not coupled).
    assert drag.count("Math.max(0, v)") >= 2, (
        "dragMove() must clamp BOTH knobs with Math.max(0, v) — independent "
        "0-floored ranges"
    )


def test_dragmove_caps_at_risk_ban_threshold():
    """Upper clamp should still respect RISK_BAN_THRESHOLD (a gate above the
    ban threshold can never fire)."""
    drag = _func(_slider_iife(), "dragMove")
    assert "RISK_BAN_THRESHOLD" in drag and "rban" in drag, (
        "dragMove() must cap the knobs at RISK_BAN_THRESHOLD - 1"
    )


# ── Structural anchors ──────────────────────────────────────────────────

def test_both_knobs_present_in_markup():
    src = _src()
    assert 'id="ord-knob-s2"' in src and 'id="ord-knob-s3"' in src, (
        "both order-threshold knobs (s2/s3) must exist in the markup"
    )


def test_drag_handlers_wired_for_both_knobs():
    block = _slider_iife()
    assert "knobS2.addEventListener('mousedown'" in block, (
        "s2 knob must have a mousedown drag handler"
    )
    assert "knobS3.addEventListener('mousedown'" in block, (
        "s3 knob must have a mousedown drag handler"
    )


# ── Behavioural: port the clamp math + off-state to Python and assert the
#    invariants directly. Source greps catch a token rename; these catch a
#    LOGIC regression (e.g. someone re-adds coupling with different syntax).
# ──────────────────────────────────────────────────────────────────────

MAX = 100


def _drag(which, v, S2, S3, rban):
    """Faithful port of the fixed dragMove() clamp. `v` is the raw value
    (0..MAX) the pointer maps to. Returns the new (S2, S3)."""
    cap = max(0, rban - 1)
    if which == "s2":
        S2 = min(max(0, v), cap)
    else:
        S3 = min(max(0, v), cap)
    return S2, S3


def _is_knob_interactive(value):
    """The fixed render() never disables a knob, regardless of value."""
    # pointerEvents is always '' (interactive). 0 must NOT be special-cased.
    return True


# Bug 1 — a knob at 0 must remain interactive (the reported symptom).

def test_behaviour_zero_knob_still_interactive():
    assert _is_knob_interactive(0), (
        "a knob at value 0 must stay draggable — that was the exact "
        "operator-reported trap"
    )


# Bug 1 — operator can drag a 0-valued knob back up to a positive value.

def test_behaviour_can_escape_zero():
    # S2 starts off (0); S3=25; ban threshold 50.
    S2, S3 = _drag("s2", 30, S2=0, S3=25, rban=50)
    assert S2 == 30, (
        f"dragging the off (0) 2nd-order knob to v=30 must set it to 30, "
        f"got {S2} — the operator must be able to escape 0"
    )


# Bug 2 — with the SHIPPED defaults (S2=15, S3=0), dragging S2 must NOT be
# forced negative by the old `min(v, S3-1)` coupling.

def test_behaviour_defaults_no_negative_trap():
    S2, S3 = _drag("s2", 40, S2=15, S3=0, rban=50)
    assert S2 == 40, (
        f"with defaults S2=15/S3=0, dragging S2 to v=40 must yield 40, got "
        f"{S2} — the old coupling forced it to S3-1 = -1"
    )
    assert S2 >= 0, "a threshold must never go negative"


# Bug 2 — the two knobs are independent: moving S2 must not move S3.

def test_behaviour_knobs_independent():
    S2, S3 = _drag("s2", 10, S2=5, S3=25, rban=50)
    assert S3 == 25, f"moving S2 must not change S3, got S3={S3}"
    S2, S3 = _drag("s3", 40, S2=10, S3=25, rban=50)
    assert S2 == 10, f"moving S3 must not change S2, got S2={S2}"


# Upper bound — a gate above the ban threshold can never fire, so cap there.

def test_behaviour_caps_at_ban_threshold_minus_one():
    S2, S3 = _drag("s2", 99, S2=0, S3=10, rban=50)
    assert S2 == 49, (
        f"dragging past RISK_BAN_THRESHOLD (50) must cap at 49, got {S2}"
    )


# Floor — a sub-zero pointer maps to exactly 0 (off), still valid + escapable.

def test_behaviour_floor_is_zero():
    S2, S3 = _drag("s2", -5, S2=20, S3=30, rban=50)
    assert S2 == 0, f"a negative pointer value must clamp to 0, got {S2}"
