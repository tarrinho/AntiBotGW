"""1.8.9 — sidebar full-hide collapse + submenu accordion on the 9 real
dashboards.

  * Whole sidebar hides via the ‹ toggle (#sidebar-reopen ☰ brings it back),
    desktop-only; mobile keeps its existing off-canvas #mob-menu.
  * Each parent group with sub-items (Control Center, Controls, Settings) gets
    a caret that collapses/expands its .sub children, state remembered.

Pure static-HTML assertions."""
import pathlib
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent / "dashboards"
REAL = ["main", "controls", "settings", "agents", "siem",
        "geo", "service", "logs", "vhost_policy", "control_center"]
PARENTS = ["control-center", "controls", "settings"]


def _html(name):
    return (ROOT / f"{name}.html").read_text(encoding="utf-8")


# ---- full-hide sidebar ----------------------------------------------------
@pytest.mark.parametrize("name", REAL)
def test_full_hide_toggle(name):
    h = _html(name)
    assert 'id="sidebar-toggle"' in h, f"{name}: hide toggle missing"
    assert 'onclick="_sbToggle()"' in h, f"{name}: toggle wired to _sbToggle()"
    assert 'id="sidebar-reopen"' in h, f"{name}: reopen ☰ button missing"
    assert "window._sbToggle" in h, f"{name}: _sbToggle not defined"


@pytest.mark.parametrize("name", REAL)
def test_full_hide_css_desktop_only(name):
    h = _html(name)
    assert "body.sb-collapsed #sidebar{display:none}" in h, f"{name}: hide CSS missing"
    assert "@media(min-width:601px){body.sb-collapsed" in h, \
        f"{name}: hide not desktop-gated"
    assert "@media(max-width:600px){#sidebar-toggle{display:none}}" in h, \
        f"{name}: toggle not hidden on mobile"


@pytest.mark.parametrize("name", REAL)
def test_full_hide_state_restored(name):
    h = _html(name)
    assert "agw_sb_collapsed" in h, f"{name}: collapse key missing"
    assert "localStorage.getItem('agw_sb_collapsed')" in h, \
        f"{name}: collapse state not restored"


# ---- submenu accordion ----------------------------------------------------
@pytest.mark.parametrize("name", REAL)
def test_parents_wrapped_with_caret(name):
    h = _html(name)
    for grp in PARENTS:
        assert f'class="nav-parent" data-group="{grp}"' in h, \
            f"{name}: parent group '{grp}' not wrapped"
    # exactly three carets, one per parent group
    assert h.count('class="nav-caret"') == 3, \
        f"{name}: expected 3 carets, got {h.count('nav-caret')}"
    assert h.count('onclick="_subToggle(this)"') == 3, \
        f"{name}: expected 3 caret handlers"


@pytest.mark.parametrize("name", REAL)
def test_accordion_js_and_css(name):
    h = _html(name)
    assert "window._subToggle" in h, f"{name}: _subToggle not defined"
    assert "agw_sub_" in h, f"{name}: per-group localStorage key missing"
    assert "#sidebar-nav a.sub.sub-hidden{display:none}" in h, \
        f"{name}: sub-hidden rule missing"


@pytest.mark.parametrize("name", REAL)
def test_geomap_has_no_caret(name):
    """GeoMap has no sub-items, so it must stay a plain link (no group wrapper)."""
    h = _html(name)
    assert 'data-group="geo"' not in h, f"{name}: GeoMap wrongly wrapped"


# ---- no leftovers from the icon-rail experiment ---------------------------
@pytest.mark.parametrize("name", REAL)
def test_no_rail_or_icon_markup(name):
    h = _html(name)
    for dead in ("sb-rail", "_sbRail", 'class="nav-ic"', 'class="nav-lbl"'):
        assert dead not in h, f"{name}: stale rail marker '{dead}' present"


@pytest.mark.parametrize("name", REAL)
def test_brand_version_current(name):
    h = _html(name)
    assert '<div id="sidebar-brand-ver">1.8.12</div>' in h, \
        f"{name}: brand version not 1.8.10"


def test_collapse_init_before_sidebar():
    """Sidebar-hide restore must run before #sidebar is parsed → no flash."""
    for name in REAL:
        h = _html(name)
        init = h.index("localStorage.getItem('agw_sb_collapsed')")
        bar = h.index('<div id="sidebar">')
        assert init < bar, f"{name}: collapse init after sidebar (flash risk)"
