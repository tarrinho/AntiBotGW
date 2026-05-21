"""1.8.10 — static QA for the topbar overlap fix.

Two classes of fixed/floating widget were overlapping topbar content:
  * the fixed Health pill (`#gw-status-pill`, right:14) + log selector
    (`#gw-loglvl-wrap`, right:120) overlapped the topbar's right-hand buttons
    (e.g. Controls' "Apply changes" save button);
  * the collapsed-sidebar reopen button (`#sidebar-reopen`, left:10) overlapped
    the topbar title.

The fix reserves space in `#topbar` so flowing topbar content never lands under
those fixed widgets. These checks parse the CSS and assert the reserve is large
enough to clear each widget's offset.
"""
import re
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "dashboards"
# pages where the Health pill + log selector are position:fixed overlays
FIXED_PILL = ["controls", "agents", "geo", "service", "logs"]
# pages where those widgets live in the topbar flow (no fixed overlay)
INFLOW_PILL = ["main", "settings", "siem", "vhost_policy"]
ALL9 = FIXED_PILL + INFLOW_PILL


def _html(name):
    return (ROOT / f"{name}.html").read_text(encoding="utf-8")


def _px(pattern, text):
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


# ── fix #1 — fixed top-right widgets vs topbar buttons ───────────────────────

def test_fixed_pill_pages_have_fixed_widgets():
    """Sanity: these pages really do float the widgets (so the reserve matters)."""
    for name in FIXED_PILL:
        h = _html(name)
        assert "#gw-status-pill{position:fixed" in h, f"{name}: pill not fixed"
        assert "#gw-loglvl-wrap{position:fixed" in h, f"{name}: log selector not fixed"


def test_topbar_reserves_right_space_for_widgets():
    for name in FIXED_PILL:
        h = _html(name)
        reserve = _px(r"#topbar\{padding-right:(\d+)px\}", h)
        assert reserve is not None, f"{name}: no #topbar padding-right reserve"
        # left-most fixed widget is the log selector at right:120 plus its own
        # width; require the reserve to clear that offset by a safe margin.
        loglvl_right = _px(r"#gw-loglvl-wrap\{position:fixed;top:\d+px;right:(\d+)px", h)
        assert loglvl_right == 120, f"{name}: unexpected log-selector offset {loglvl_right}"
        assert reserve >= loglvl_right + 130, (
            f"{name}: topbar reserve {reserve}px too small to clear the fixed "
            f"widgets (need >= {loglvl_right + 130})")


def test_reserve_is_desktop_scoped():
    """Reserve must be behind the desktop breakpoint so mobile (where the topbar
    wraps) is unaffected."""
    for name in FIXED_PILL:
        h = _html(name)
        assert "@media(min-width:601px){#topbar{padding-right:280px}}" in h, \
            f"{name}: right reserve not desktop-gated"


def test_inflow_pages_keep_widgets_in_topbar():
    """In-flow pages must NOT float the pill (they keep it in #topbar-right), so
    they neither need nor get the right reserve."""
    for name in INFLOW_PILL:
        h = _html(name)
        assert "#gw-status-pill{position:fixed" not in h, \
            f"{name}: pill unexpectedly fixed"
        assert "#topbar{padding-right:280px}" not in h, \
            f"{name}: right reserve added where not needed"


# ── fix #2 — collapsed reopen button vs topbar title ─────────────────────────

def test_collapsed_topbar_reserves_left_space():
    for name in ALL9:
        h = _html(name)
        reserve = _px(r"body\.sb-collapsed #topbar\{padding-left:(\d+)px\}", h)
        assert reserve is not None, f"{name}: no collapsed left reserve"
        # reopen button sits at left:10 with ~8px padding each side + glyph (~16) +
        # border ~= 44px wide; reserve must clear left:10 + button width.
        reopen_left = _px(r"#sidebar-reopen\{display:none;position:fixed;top:\d+px;left:(\d+)px", h)
        assert reopen_left == 10, f"{name}: unexpected reopen offset {reopen_left}"
        assert reserve >= reopen_left + 38, (
            f"{name}: collapsed left reserve {reserve}px too small "
            f"(need >= {reopen_left + 38})")


def test_collapsed_reserve_desktop_scoped():
    for name in ALL9:
        h = _html(name)
        assert "@media(min-width:601px){body.sb-collapsed #topbar{padding-left:52px}}" in h, \
            f"{name}: collapsed left reserve not desktop-gated"
