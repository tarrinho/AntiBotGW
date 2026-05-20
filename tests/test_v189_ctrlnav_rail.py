"""1.8.9 — Controls-page second hide: the in-page section submenu (#ctrl-nav)
collapses to an icon-rail (section logos stay, labels + search hide). This is
independent from the main sidebar full-hide. Pure static-HTML assertions on
controls.html."""
import pathlib

CTRL = (pathlib.Path(__file__).resolve().parent.parent /
        "dashboards" / "controls.html").read_text(encoding="utf-8")


def test_toggle_button_present():
    assert 'id="ctrl-nav-toggle"' in CTRL
    assert 'onclick="_ctrlNavToggle()"' in CTRL


def test_toggle_js_defined():
    assert "window._ctrlNavToggle" in CTRL
    assert "agw_ctrlnav_rail" in CTRL
    assert "localStorage.getItem('agw_ctrlnav_rail')" in CTRL


def test_rail_css_keeps_icons_hides_labels():
    assert "#ctrl-nav.cn-rail{width:50px}" in CTRL
    assert "#ctrl-nav.cn-rail .cni-label{display:none}" in CTRL
    # search box hides when railed
    assert "#ctrl-nav.cn-rail #ctrl-nav-search{display:none}" in CTRL
    # icons (.cni-icon) must NOT be hidden in rail mode
    assert "cn-rail .cni-icon{display:none}" not in CTRL


def test_items_get_tooltip_for_rail():
    # collapsed icons need a title so the section is still identifiable
    assert "el.title = sec.label" in CTRL


def test_does_not_touch_main_sidebar_hide():
    # the main sidebar full-hide + accordion stay intact on this page
    assert "window._sbToggle" in CTRL
    assert 'class="nav-parent"' in CTRL
    assert "window._subToggle" in CTRL
    # and no icon-rail leak into the main sidebar
    assert "sb-rail" not in CTRL
