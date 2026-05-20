"""1.8.9 — Settings-page second hide: the in-page section submenu
(#settings-nav) collapses to an icon-rail (section logos stay, labels hide),
mirroring the Controls page. Independent from the main sidebar full-hide.
Pure static-HTML assertions on settings.html."""
import pathlib

SET = (pathlib.Path(__file__).resolve().parent.parent /
       "dashboards" / "settings.html").read_text(encoding="utf-8")


def test_toggle_built_and_wired():
    # _buildNav wipes innerHTML, so the toggle is created in JS and wired
    assert "settings-nav-toggle" in SET
    assert "window._settingsNavToggle" in SET
    assert "tog.onclick = window._settingsNavToggle" in SET


def test_toggle_state_persisted():
    assert "agw_setnav_rail" in SET
    assert "localStorage.getItem('agw_setnav_rail')" in SET


def test_rail_css_keeps_icons_hides_labels():
    assert "#settings-nav.sn-rail{width:50px}" in SET
    assert "#settings-nav.sn-rail .sni-label{display:none}" in SET
    # section icons (.sni-icon) must stay visible in rail mode
    assert "sn-rail .sni-icon{display:none}" not in SET


def test_items_get_tooltip_for_rail():
    assert "el.title = sec.label" in SET


def test_restore_runs_before_build():
    """Rail class restored before _buildNav() so the toggle renders correct
    and there is no expand→collapse flash."""
    restore = SET.index("localStorage.getItem('agw_setnav_rail')")
    build = SET.index("_buildNav();\n    _switch('routing');")
    assert restore < build, "rail restore must precede _buildNav()"


def test_does_not_touch_main_sidebar_hide():
    assert "window._sbToggle" in SET          # sidebar full-hide intact
    assert 'class="nav-parent"' in SET        # sidebar accordion intact
    assert "sb-rail" not in SET               # no icon-rail leak into sidebar
