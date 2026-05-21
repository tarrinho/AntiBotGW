"""1.8.10 — dynamic QA for the topbar overlap fix (headless Chromium).

Renders each dashboard HTML in a real browser at a desktop viewport and asserts,
via getBoundingClientRect, that the fixed top-right widgets (Health pill + log
selector) do not visually overlap the topbar buttons/title, and that the
collapsed-sidebar reopen button does not overlap the topbar title.

Skips automatically when Chromium/Chromedriver are unavailable.
"""
import shutil
import pathlib
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent / "dashboards"
FIXED_PILL = ["controls", "agents", "geo", "service", "logs"]
ALL9 = FIXED_PILL + ["main", "settings", "siem", "vhost_policy"]

_CHROMIUM = shutil.which("chromium") or shutil.which("chromium-browser") or "/usr/bin/chromium"
_DRIVER = shutil.which("chromedriver") or "/usr/bin/chromedriver"

selenium = pytest.importorskip("selenium")
from selenium import webdriver  # noqa: E402
from selenium.webdriver.chrome.options import Options  # noqa: E402
from selenium.webdriver.chrome.service import Service  # noqa: E402
from selenium.common.exceptions import NoSuchElementException  # noqa: E402

SLACK = 2  # px — ignore sub-pixel touching


@pytest.fixture(scope="module")
def driver():
    if not (pathlib.Path(_CHROMIUM).exists() and pathlib.Path(_DRIVER).exists()):
        pytest.skip("Chromium or chromedriver not available")
    opts = Options()
    for a in ("--headless=new", "--no-sandbox", "--disable-gpu",
              "--disable-dev-shm-usage", "--hide-scrollbars"):
        opts.add_argument(a)
    opts.binary_location = _CHROMIUM
    try:
        d = webdriver.Chrome(options=opts, service=Service(_DRIVER))
    except Exception as e:  # pragma: no cover - environment dependent
        pytest.skip(f"could not start Chromium webdriver: {e}")
    d.set_window_size(1366, 900)
    yield d
    d.quit()


def _rect(driver, css):
    try:
        el = driver.find_element("css selector", css)
    except NoSuchElementException:
        return None
    if not el.is_displayed():
        return None
    r = driver.execute_script(
        "const b=arguments[0].getBoundingClientRect();"
        "return [b.x,b.y,b.width,b.height];", el)
    if r[2] <= 0 or r[3] <= 0:
        return None
    return {"x": r[0], "y": r[1], "w": r[2], "h": r[3]}


def _overlaps(a, b):
    if a is None or b is None:
        return False
    iw = min(a["x"] + a["w"], b["x"] + b["w"]) - max(a["x"], b["x"])
    ih = min(a["y"] + a["h"], b["y"] + b["h"]) - max(a["y"], b["y"])
    return iw > SLACK and ih > SLACK


def _load(driver, name):
    driver.get((ROOT / f"{name}.html").resolve().as_uri())


@pytest.mark.parametrize("name", FIXED_PILL)
def test_fixed_widgets_do_not_overlap_topbar(driver, name):
    _load(driver, name)
    pill = _rect(driver, "#gw-status-pill")
    log = _rect(driver, "#gw-loglvl-wrap")
    assert pill is not None, f"{name}: Health pill not rendered"
    # the fixed widgets must clear the topbar title and any right-hand buttons
    targets = {
        "#topbar-title": _rect(driver, "#topbar-title"),
        "#apply": _rect(driver, "#apply"),
        "#reset": _rect(driver, "#reset"),
        "#view-picker": _rect(driver, "#view-picker"),
    }
    for label, tgt in targets.items():
        if tgt is None:
            continue
        assert not _overlaps(pill, tgt), f"{name}: Health pill overlaps {label}"
        assert not _overlaps(log, tgt), f"{name}: log selector overlaps {label}"


def test_controls_pill_clears_apply_button(driver):
    """Explicit check for the reported case: Health pill over Apply (save)."""
    _load(driver, "controls")
    pill = _rect(driver, "#gw-status-pill")
    log = _rect(driver, "#gw-loglvl-wrap")
    apply_btn = _rect(driver, "#apply")
    assert apply_btn is not None, "controls: #apply not rendered"
    assert not _overlaps(pill, apply_btn), "Health pill still overlaps Apply button"
    assert not _overlaps(log, apply_btn), "log selector still overlaps Apply button"
    # and Apply must sit to the LEFT of both widgets
    assert apply_btn["x"] + apply_btn["w"] <= pill["x"] + SLACK
    assert apply_btn["x"] + apply_btn["w"] <= log["x"] + SLACK


@pytest.mark.parametrize("name", ALL9)
def test_collapsed_reopen_does_not_overlap_title(driver, name):
    _load(driver, name)
    # enter collapsed state (desktop media shows #sidebar-reopen)
    driver.execute_script("document.body.classList.add('sb-collapsed');")
    reopen = _rect(driver, "#sidebar-reopen")
    title = _rect(driver, "#topbar-title")
    assert reopen is not None, f"{name}: reopen button not shown when collapsed"
    assert title is not None, f"{name}: topbar title not rendered"
    assert not _overlaps(reopen, title), \
        f"{name}: reopen ☰ overlaps the topbar title when sidebar collapsed"
