"""
tests/test_v185_controls_nav.py — Controls split-pane navigation QA.

Verifies the split-pane navigation added to controls.html (1.8.6):
  a secondary nav bar inside the controls page that groups knobs into
  sections and shows/hides card elements without page reload.

Static structure checks (S):
  S01  ctrl-split wrapper div present
  S02  ctrl-nav nav element present
  S03  ctrl-panels content div present
  S04  ctrl-scope-strip fixed-header strip present
  S05  ctrl-nav-search input present
  S06  .actions div with inline Apply/Reset removed (moved to topbar)
  S07  <main> not used as the section wrapper
  S08  Apply button present inside topbar-right
  S09  Reset button present inside topbar-right
  S10  #hint span present inside topbar-right
  S11  bypass-bar is inside ctrl-panels (not before ctrl-split)
  S12  vhost-scope-bar is inside ctrl-scope-strip

JS logic checks (J):
  J01  CARD_SEC object defined
  J02  card-scoring → detection mapping present
  J03  card-thresholds → thresholds mapping present
  J04  card-bypass → bypass mapping present
  J05  card-infrastructure → infra mapping present
  J06  card-external → external mapping present
  J07  card-active-rules → monitoring mapping present
  J08  card-lists-snap → monitoring mapping present
  J09  card-ep-policies → monitoring mapping present
  J10  card-unban → admin mapping present
  J11  card-admin-ip → admin mapping present
  J12  card-audit-log → admin mapping present
  J13  All 7 section IDs defined (detection/thresholds/bypass/infra/external/monitoring/admin)
  J14  _switch() function defined
  J15  _buildNav() function defined
  J16  _updateBadges() function defined
  J17  window._ctrlNavFilter exposed
  J18  window._ctrlNavUpdateBadges exposed
  J19  mark() patched to call _updateBadges in DOMContentLoaded
  J20  clearDirty() patched to call _updateBadges in DOMContentLoaded
  J21  cni-dirty class used for section dirty badges
  J22  ctrl-nav-item class used for nav buttons
  J23  DOMContentLoaded calls _buildNav()
  J24  DOMContentLoaded calls _switch with 'detection' as default section

Regression checks (R) — existing knob/card IDs not broken:
  R01–R09  All section cards still present in HTML
  R10  apply button id preserved
  R11  reset button id preserved
  R12  hint id preserved
  R13  bypass-bar id preserved
  R14  vhost-sel id preserved
  R15  loadScoring() still defined (scoring table not broken)
  R16  mark() still defined
  R17  clearDirty() still defined
  R18  vhost-scope-bar id preserved

Dynamic tests (D) — in-process gateway via aiohttp TestClient:
  D01  GET /secured/controls        authenticated → 200 HTML
  D02  GET /secured/controls        HTML contains ctrl-split
  D03  GET /secured/controls        HTML contains ctrl-nav
  D04  GET /secured/controls        HTML contains ctrl-panels
  D05  GET /secured/controls        HTML contains CARD_SEC mapping
  D06  GET /secured/controls        Apply button present in topbar-right HTML
  D07  GET /secured/controls        No standalone .actions div with Apply+Reset+hint
  D08  GET /secured/controls-test-a authenticated → 200 HTML (prototype reachable)
  D09  GET /secured/controls-test-b authenticated → 200 HTML (prototype reachable)
"""

import re
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

_DASHBOARDS = Path(__file__).resolve().parent.parent / "dashboards"
_NS = "/antibot-appsec-gateway/secured"


def _read(name: str) -> str:
    return (_DASHBOARDS / name).read_text(encoding="utf-8")


def _controls() -> str:
    return _read("controls.html")


# ── helpers ───────────────────────────────────────────────────────────────────

def _topbar_right(src: str) -> str:
    """Return the content of the #topbar-right element."""
    m = re.search(r'id=["\']topbar-right["\'][^>]*>(.*?)</div>', src, re.DOTALL)
    return m.group(1) if m else ""


def _ctrl_scope_strip(src: str) -> str:
    """Return content of #ctrl-scope-strip."""
    m = re.search(r'id=["\']ctrl-scope-strip["\'][^>]*>(.*?)</div>', src, re.DOTALL)
    return m.group(1) if m else ""


def _ctrl_panels_section(src: str) -> str:
    """Return content between id='ctrl-panels' and the closing of ctrl-split."""
    m = re.search(r'id=["\']ctrl-panels["\'][^>]*>(.*)', src, re.DOTALL)
    return m.group(1) if m else ""


def _dcl_block(src: str) -> str:
    """Return text starting at the last DOMContentLoaded occurrence."""
    idx = src.rfind("DOMContentLoaded")
    return src[idx:] if idx != -1 else ""


def _split_pane_script(src: str) -> str:
    """Return the Controls split-pane script block (the IIFE at the end)."""
    # The split-pane nav block starts with a distinctive comment
    idx = src.find("Controls split-pane navigation")
    return src[idx:] if idx != -1 else ""


# ═════════════════════════════════════════════════════════════════════════════
# S — Static HTML structure
# ═════════════════════════════════════════════════════════════════════════════

class TestStructure:
    def setup_method(self):
        self.src = _controls()

    def test_s01_ctrl_split_present(self):
        """#ctrl-split wrapper div must be present."""
        assert 'id="ctrl-split"' in self.src or "id='ctrl-split'" in self.src, (
            "controls.html: #ctrl-split div missing — split-pane layout not applied"
        )

    def test_s02_ctrl_nav_present(self):
        """#ctrl-nav nav element must be present."""
        assert 'id="ctrl-nav"' in self.src or "id='ctrl-nav'" in self.src, (
            "controls.html: #ctrl-nav nav element missing"
        )

    def test_s03_ctrl_panels_present(self):
        """#ctrl-panels content div must be present."""
        assert 'id="ctrl-panels"' in self.src or "id='ctrl-panels'" in self.src, (
            "controls.html: #ctrl-panels div missing"
        )

    def test_s04_ctrl_scope_strip_present(self):
        """#ctrl-scope-strip fixed header strip must be present."""
        assert 'id="ctrl-scope-strip"' in self.src or "id='ctrl-scope-strip'" in self.src, (
            "controls.html: #ctrl-scope-strip div missing — vhost bar no longer pinned"
        )

    def test_s05_ctrl_nav_search_present(self):
        """Filter input inside ctrl-nav must be present."""
        assert 'id="ctrl-nav-search"' in self.src or "id='ctrl-nav-search'" in self.src, (
            "controls.html: #ctrl-nav-search input missing"
        )

    def test_s06_no_standalone_actions_div(self):
        """Old .actions div (Apply + Reset + hint inline) must be removed.
        Apply/Reset are now in the topbar — the .actions card should be gone."""
        # The old pattern was: <div class="actions"><button id="apply"...
        m = re.search(r'<div class="actions"[^>]*>.*?<button[^>]*id=["\']apply["\']', self.src, re.DOTALL)
        assert not m, (
            "controls.html: .actions div with inline Apply button still present — "
            "should be removed (Apply moved to topbar-right)"
        )

    def test_s07_no_main_as_section_wrapper(self):
        """<main> must not wrap the section cards (replaced by #ctrl-split divs)."""
        # The old <main> wrapped card-external through card-audit-log.
        # After refactor it should not exist or be empty.
        main_tags = re.findall(r'<main\b[^>]*>', self.src)
        assert len(main_tags) == 0, (
            f"controls.html: <main> tag still present ({len(main_tags)} occurrence(s)) — "
            "section wrapping should use #ctrl-split / #ctrl-panels divs"
        )

    def test_s08_apply_in_topbar_right(self):
        """Apply button must be inside #topbar-right."""
        tr = _topbar_right(self.src)
        assert tr, "controls.html: #topbar-right element not found"
        assert 'id="apply"' in tr or "id='apply'" in tr, (
            "controls.html: Apply button not found inside #topbar-right"
        )

    def test_s09_reset_in_topbar_right(self):
        """Reset button must be inside #topbar-right."""
        tr = _topbar_right(self.src)
        assert tr, "controls.html: #topbar-right element not found"
        assert 'id="reset"' in tr or "id='reset'" in tr, (
            "controls.html: Reset button not found inside #topbar-right"
        )

    def test_s10_hint_in_topbar_right(self):
        """#hint span must be inside #topbar-right."""
        tr = _topbar_right(self.src)
        assert tr, "controls.html: #topbar-right element not found"
        assert 'id="hint"' in tr or "id='hint'" in tr, (
            "controls.html: #hint span not found inside #topbar-right"
        )

    def test_s11_bypass_bar_inside_ctrl_panels(self):
        """bypass-bar must be inside #ctrl-panels (scrolls with section content)."""
        panels = _ctrl_panels_section(self.src)
        assert panels, "controls.html: #ctrl-panels content not found"
        assert 'id="bypass-bar"' in panels or "id='bypass-bar'" in panels, (
            "controls.html: #bypass-bar not found inside #ctrl-panels"
        )

    def test_s12_vhost_scope_bar_inside_scope_strip(self):
        """vhost-scope-bar must be inside #ctrl-scope-strip (stays pinned above split)."""
        strip = _ctrl_scope_strip(self.src)
        assert strip, "controls.html: #ctrl-scope-strip content not found"
        assert 'id="vhost-scope-bar"' in strip or "id='vhost-scope-bar'" in strip, (
            "controls.html: #vhost-scope-bar not found inside #ctrl-scope-strip"
        )


# ═════════════════════════════════════════════════════════════════════════════
# J — JS logic
# ═════════════════════════════════════════════════════════════════════════════

class TestJSLogic:
    def setup_method(self):
        self.src = _controls()
        self.sp = _split_pane_script(self.src)

    def test_j01_card_sec_defined(self):
        """CARD_SEC mapping object must be defined in the split-pane script."""
        assert "CARD_SEC" in self.sp, (
            "controls.html split-pane script: CARD_SEC object not defined"
        )

    @pytest.mark.parametrize("card,sec", [
        ("card-scoring",       "detection"),
        ("card-thresholds",    "thresholds"),
        ("card-bypass",        "bypass"),
        ("card-infrastructure","infra"),
        ("card-external",      "external"),
        ("card-active-rules",  "monitoring"),
        ("card-lists-snap",    "monitoring"),
        ("card-ep-policies",   "monitoring"),
        ("card-unban",         "admin"),
        ("card-admin-ip",      "admin"),
        ("card-audit-log",     "admin"),
    ])
    def test_j02_card_sec_mapping(self, card, sec):
        """Each card ID must map to the correct section in CARD_SEC."""
        assert card in self.sp, (
            f"controls.html CARD_SEC: '{card}' key missing"
        )
        # The value must appear near the key in the source
        idx = self.sp.find(card)
        snippet = self.sp[idx:idx + 60]
        assert sec in snippet, (
            f"controls.html CARD_SEC: '{card}' does not map to '{sec}' (got: {snippet!r})"
        )

    @pytest.mark.parametrize("sec_id", [
        "detection", "thresholds", "bypass", "infra", "external", "monitoring", "admin"
    ])
    def test_j03_all_section_ids_defined(self, sec_id):
        """All 7 section IDs must appear in the SECTIONS array."""
        assert f"'{sec_id}'" in self.sp or f'"{sec_id}"' in self.sp, (
            f"controls.html split-pane script: section id '{sec_id}' not found in SECTIONS"
        )

    def test_j04_switch_function_defined(self):
        """_switch() internal function must be defined."""
        assert "function _switch(" in self.sp or "_switch = function(" in self.sp, (
            "controls.html split-pane script: _switch() function not defined"
        )

    def test_j05_build_nav_function_defined(self):
        """_buildNav() internal function must be defined."""
        assert "function _buildNav(" in self.sp or "_buildNav = function(" in self.sp, (
            "controls.html split-pane script: _buildNav() function not defined"
        )

    def test_j06_update_badges_function_defined(self):
        """_updateBadges() must be defined for dirty-count tracking."""
        assert "function _updateBadges(" in self.sp or "_updateBadges = function(" in self.sp, (
            "controls.html split-pane script: _updateBadges() function not defined"
        )

    def test_j07_ctrl_nav_filter_exposed(self):
        """window._ctrlNavFilter must be assigned (used by the search input oninput)."""
        assert "window._ctrlNavFilter" in self.sp, (
            "controls.html split-pane script: window._ctrlNavFilter not exposed"
        )

    def test_j08_ctrl_nav_update_badges_exposed(self):
        """window._ctrlNavUpdateBadges must be assigned for external callers."""
        assert "window._ctrlNavUpdateBadges" in self.sp, (
            "controls.html split-pane script: window._ctrlNavUpdateBadges not exposed"
        )

    def test_j09_mark_patched_in_dcl(self):
        """DOMContentLoaded must patch mark() to also call _updateBadges."""
        dcl = _dcl_block(self.sp)
        assert "_origMark" in dcl or ("mark" in dcl and "_updateBadges" in dcl), (
            "controls.html split-pane DOMContentLoaded: mark() not patched to call _updateBadges"
        )

    def test_j10_clear_dirty_patched_in_dcl(self):
        """DOMContentLoaded must patch clearDirty() to also call _updateBadges."""
        dcl = _dcl_block(self.sp)
        assert "_origClear" in dcl or ("clearDirty" in dcl and "_updateBadges" in dcl), (
            "controls.html split-pane DOMContentLoaded: clearDirty() not patched to call _updateBadges"
        )

    def test_j11_cni_dirty_class_used(self):
        """cni-dirty CSS class must be used for per-section dirty badges."""
        assert "cni-dirty" in self.src, (
            "controls.html: cni-dirty class not referenced — section dirty badges won't render"
        )

    def test_j12_ctrl_nav_item_class_used(self):
        """ctrl-nav-item class must be used for section nav buttons."""
        assert "ctrl-nav-item" in self.src, (
            "controls.html: ctrl-nav-item class not referenced — section nav buttons won't render"
        )

    def test_j13_dcl_calls_build_nav(self):
        """DOMContentLoaded must call _buildNav() to render the nav sidebar."""
        dcl = _dcl_block(self.sp)
        assert "_buildNav()" in dcl, (
            "controls.html split-pane DOMContentLoaded: _buildNav() not called"
        )

    def test_j14_dcl_switches_to_detection_by_default(self):
        """DOMContentLoaded must call _switch('detection') to open Detection first."""
        dcl = _dcl_block(self.sp)
        assert "_switch('detection')" in dcl or '_switch("detection")' in dcl, (
            "controls.html split-pane DOMContentLoaded: _switch('detection') not called — "
            "default section won't open on page load"
        )


# ═════════════════════════════════════════════════════════════════════════════
# R — Regression: existing card IDs and functions not broken
# ═════════════════════════════════════════════════════════════════════════════

class TestRegressions:
    def setup_method(self):
        self.src = _controls()

    @pytest.mark.parametrize("card_id", [
        "card-scoring",
        "card-thresholds",
        "card-bypass",
        "card-infrastructure",
        "card-external",
        "card-unban",
        "card-admin-ip",
        "card-active-rules",
        "card-lists-snap",
        "card-ep-policies",
        "card-audit-log",
    ])
    def test_r01_card_ids_preserved(self, card_id):
        """All section card IDs must still be present in the HTML."""
        assert f'id="{card_id}"' in self.src or f"id='{card_id}'" in self.src, (
            f"controls.html: #{card_id} card missing — may have been accidentally removed"
        )

    def test_r10_apply_id_preserved(self):
        """id='apply' must still be present (JS uses it)."""
        assert 'id="apply"' in self.src or "id='apply'" in self.src, (
            "controls.html: id='apply' button missing — apply() JS function will fail"
        )

    def test_r11_reset_id_preserved(self):
        """id='reset' must still be present."""
        assert 'id="reset"' in self.src or "id='reset'" in self.src, (
            "controls.html: id='reset' button missing"
        )

    def test_r12_hint_id_preserved(self):
        """id='hint' must still be present."""
        assert 'id="hint"' in self.src or "id='hint'" in self.src, (
            "controls.html: id='hint' element missing — pending-change counter won't update"
        )

    def test_r13_bypass_bar_id_preserved(self):
        """id='bypass-bar' must still be present."""
        assert 'id="bypass-bar"' in self.src or "id='bypass-bar'" in self.src, (
            "controls.html: id='bypass-bar' missing — bypass toggle JS will fail"
        )

    def test_r14_vhost_sel_id_preserved(self):
        """id='vhost-sel' must still be present."""
        assert 'id="vhost-sel"' in self.src or "id='vhost-sel'" in self.src, (
            "controls.html: id='vhost-sel' select missing — vhost scope switching will fail"
        )

    def test_r15_load_scoring_still_defined(self):
        """loadScoring() must still be defined (scoring table not broken)."""
        assert "function loadScoring(" in self.src or "loadScoring = function(" in self.src \
               or "loadScoring=function(" in self.src, (
            "controls.html: loadScoring() function definition missing — scoring table broken"
        )

    def test_r16_mark_still_defined(self):
        """mark() must still be defined."""
        assert "function mark(" in self.src, (
            "controls.html: mark() function definition missing — dirty tracking broken"
        )

    def test_r17_clear_dirty_still_defined(self):
        """clearDirty() must still be defined."""
        assert "function clearDirty(" in self.src, (
            "controls.html: clearDirty() function definition missing — reset broken"
        )

    def test_r18_vhost_scope_bar_id_preserved(self):
        """id='vhost-scope-bar' must still be present."""
        assert 'id="vhost-scope-bar"' in self.src or "id='vhost-scope-bar'" in self.src, (
            "controls.html: id='vhost-scope-bar' missing"
        )

    def test_r19_ctrl_nav_css_defined(self):
        """#ctrl-nav CSS rule must be in the <style> block."""
        assert "#ctrl-nav" in self.src, (
            "controls.html: #ctrl-nav CSS not defined — nav sidebar has no styling"
        )

    def test_r20_ctrl_panels_css_defined(self):
        """#ctrl-panels CSS rule must be in the <style> block."""
        assert "#ctrl-panels" in self.src, (
            "controls.html: #ctrl-panels CSS not defined"
        )

    def test_r21_ctrl_nav_item_css_defined(self):
        """ctrl-nav-item CSS must be defined for section button appearance."""
        assert ".ctrl-nav-item" in self.src, (
            "controls.html: .ctrl-nav-item CSS not defined"
        )

    def test_r22_cni_dirty_css_defined(self):
        """cni-dirty CSS class must be defined for dirty badge appearance."""
        assert ".cni-dirty" in self.src, (
            "controls.html: .cni-dirty CSS not defined — dirty badges won't show"
        )


# ═════════════════════════════════════════════════════════════════════════════
# D — Dynamic tests (in-process gateway)
# ═════════════════════════════════════════════════════════════════════════════

async def _echo_handler(request: web.Request):
    return web.json_response({"ok": True})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _echo_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _gateway(proxy_module, upstream):
    proxy_module.UPSTREAM = upstream.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


def _admin_cookie(proxy_module) -> dict:
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    token = proxy_module._session_sign("admin", sid=sid)
    return {proxy_module._SESSION_COOKIE: token}


@pytest.mark.asyncio
async def test_d01_controls_200_html(proxy_module):
    """GET /secured/controls authenticated → 200 HTML."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/controls", cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"/controls returned HTTP {r.status}"
            text = await r.text()
            assert "<html" in text.lower(), "/controls response is not HTML"


@pytest.mark.asyncio
async def test_d02_controls_html_has_ctrl_split(proxy_module):
    """GET /secured/controls HTML must contain ctrl-split element."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/controls", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            assert "ctrl-split" in text, (
                "/controls HTML missing ctrl-split — split-pane layout not served"
            )


@pytest.mark.asyncio
async def test_d03_controls_html_has_ctrl_nav(proxy_module):
    """GET /secured/controls HTML must contain ctrl-nav element."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/controls", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            assert "ctrl-nav" in text, (
                "/controls HTML missing ctrl-nav — section nav sidebar not served"
            )


@pytest.mark.asyncio
async def test_d04_controls_html_has_ctrl_panels(proxy_module):
    """GET /secured/controls HTML must contain ctrl-panels element."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/controls", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            assert "ctrl-panels" in text, (
                "/controls HTML missing ctrl-panels — section content area not served"
            )


@pytest.mark.asyncio
async def test_d05_controls_html_has_card_sec_mapping(proxy_module):
    """GET /secured/controls HTML must contain CARD_SEC mapping object."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/controls", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            assert "CARD_SEC" in text, (
                "/controls HTML missing CARD_SEC — section/card mapping not served"
            )


@pytest.mark.asyncio
async def test_d06_controls_html_apply_in_topbar(proxy_module):
    """GET /secured/controls HTML: Apply button appears inside topbar-right."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/controls", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            tr = _topbar_right(text)
            assert tr, "/controls HTML: topbar-right not found"
            assert 'id="apply"' in tr or "id='apply'" in tr, (
                "/controls HTML: Apply button not inside #topbar-right"
            )


@pytest.mark.asyncio
async def test_d07_controls_html_no_standalone_actions_div(proxy_module):
    """GET /secured/controls HTML: old .actions div with inline buttons must be gone."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/controls", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            m = re.search(
                r'<div class="actions"[^>]*>.*?<button[^>]*id=["\']apply["\']',
                text, re.DOTALL
            )
            assert not m, (
                "/controls HTML: standalone .actions div with Apply button still present — "
                "should have been removed (Apply is now in topbar-right)"
            )


@pytest.mark.asyncio
async def test_d08_controls_test_a_200(proxy_module):
    """GET /secured/controls-test-a authenticated → 200 HTML (prototype reachable)."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/controls-test-a", cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"/controls-test-a returned HTTP {r.status}"
            text = await r.text()
            assert "<html" in text.lower(), "/controls-test-a response is not HTML"


@pytest.mark.asyncio
async def test_d09_controls_test_b_200(proxy_module):
    """GET /secured/controls-test-b authenticated → 200 HTML (prototype reachable)."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/controls-test-b", cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"/controls-test-b returned HTTP {r.status}"
            text = await r.text()
            assert "<html" in text.lower(), "/controls-test-b response is not HTML"
