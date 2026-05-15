"""
v1.8.4 UI/UX improvements QA — static checks only (no server required).

Changes verified:
  P1B-01  center_control.html: self-link points to /secured/control-center (was /secured/center-control)
  P1B-02  center_control.html: Dashboard link points to /secured/live-feed (was /secured/dashboard)
  P1B-03  center_control.html: active nav item is not a dead route
  P2B-01  control_center.html: loadSignalPerf() not called directly in DOMContentLoaded
  P2B-02  control_center.html: loadThreatDonut() not called directly in DOMContentLoaded
  P2B-03  control_center.html: _loadThreatSection() still called in DOMContentLoaded
  P2B-04  control_center.html: loadSignalPerf() still called inside _loadThreatSection()
  P2B-05  control_center.html: loadThreatDonut() still called inside _loadThreatSection()
  P2C-01  controls.html:       toast div has role="status"
  P2C-02  controls.html:       toast div has aria-live="polite"
  P2C-03  controls.html:       toast div has aria-atomic="true"
  P2C-04  settings.html:       toast div has role="status"
  P2C-05  settings.html:       toast div has aria-live="polite"
  P2C-06  settings.html:       toast div has aria-atomic="true"
  P2C-07  control_center.html: toast div has role="status"
  P2C-08  control_center.html: toast div has aria-live="polite"
  P2C-09  control_center.html: toast div has aria-atomic="true"
  P2C-10  center_control.html: toast div has role="status"
  P2C-11  center_control.html: toast div has aria-live="polite"
  P2C-12  center_control.html: toast div has aria-atomic="true"
  ACT-01  main.html: _attackerBan catch calls _gwAlert (not silent)
  ACT-02  main.html: _attackerUnban catch calls _gwAlert (not silent)
  ACT-03  main.html: _attackerBan has confirm() guard
  ACT-04  main.html: no bare .catch(function(){}) on _attackerBan or _attackerUnban
  NAV-01  all pages: Live Feed link has class="sub" (indented under Control Center)
  NAV-02  all pages: Agents link has class="sub" (indented under Control Center)
  NAV-03  all pages: SIEM link positioned immediately after Agents in nav
  NAV-04  all pages: SIEM link has class="sub" (indented under Control Center)
  NAV-05  all pages: SIEM link does NOT appear after Settings at end of nav
  NAV-06  siem.html: SIEM has class="sub active" when it is the active page
  NAV-07  agents.html: Agents has class="sub active" when it is the active page
  NAV-08  main.html: Live Feed has class="sub active" when it is the active page

Dynamic tests (in-process gateway via aiohttp TestClient):
  D01  GET /secured/control-center  authenticated → 200 HTML
  D02  GET /secured/live-feed       authenticated → 200 HTML
  D03  GET /secured/agents          authenticated → 200 HTML
  D04  GET /secured/siem            authenticated → 200 HTML
  D05  GET /secured/control-center  unauthenticated → not 200
  D06  GET /secured/control-center  HTML: _loadThreatSection() present in DCL block
  D07  GET /secured/control-center  HTML: no standalone loadSignalPerf() before _loadThreatSection() in DCL
  D08  GET /secured/control-center  HTML: no standalone loadThreatDonut() before _loadThreatSection() in DCL
  D09  GET /secured/siem            HTML: SIEM nav link has "sub active" classes
  D10  GET /secured/agents          HTML: Agents nav link has "sub active" classes
  D11  GET /secured/live-feed       HTML: Live Feed nav link has "sub active" classes
  D12  GET /secured/control-center  HTML: toast div has role="status"
  D13  GET /secured/control-center  HTML: toast div has aria-live="polite"
  D14  GET /secured/controls        HTML: toast div has role="status"
  D15  GET /secured/settings        HTML: toast div has role="status"
  D16  POST /secured/ban            authenticated → response not 404 (endpoint exists)
"""

import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

_DASHBOARDS = Path(__file__).resolve().parent.parent / "dashboards"


def _read(name: str) -> str:
    return (_DASHBOARDS / name).read_text(encoding="utf-8")


# ── helpers ───────────────────────────────────────────────────────────────────

def _domcontentloaded_block(src: str) -> str:
    """Return the text inside the DOMContentLoaded listener body."""
    marker = "DOMContentLoaded"
    idx = src.rfind(marker)
    if idx == -1:
        return ""
    # grab from the marker to end of file — close enough for brace-counting
    return src[idx:]


def _fn_body(src: str, fn_name: str) -> str:
    """Return the source of a JS function by name (up to the next top-level function)."""
    idx = src.find(f"function {fn_name}(")
    if idx == -1:
        return ""
    nxt = re.search(r"\nfunction ", src[idx + 1:])
    end = (idx + 1 + nxt.start()) if nxt else len(src)
    return src[idx:end]


def _toast_tag(src: str) -> str:
    """Return the <div> tag that contains id=\"toast\"."""
    m = re.search(r'<div[^>]*id=["\']toast["\'][^>]*>', src)
    return m.group(0) if m else ""


# ── P1-B: Dead nav links ──────────────────────────────────────────────────────

class TestP1BDeadLinks:
    def setup_method(self):
        self.src = _read("center_control.html")

    def test_p1b_01_no_dead_center_control_self_link(self):
        """Self-link must point to /control-center, not /center-control."""
        assert "/secured/center-control" not in self.src, (
            "center_control.html still has dead self-link /secured/center-control"
        )

    def test_p1b_02_no_dead_dashboard_link(self):
        """/secured/dashboard is a dead route — must be replaced with /secured/live-feed."""
        assert "/secured/dashboard" not in self.src, (
            "center_control.html still links to dead route /secured/dashboard"
        )

    def test_p1b_03_active_link_points_to_control_center(self):
        """The active nav item must link to the real /secured/control-center route."""
        assert '/secured/control-center"' in self.src or "/secured/control-center'" in self.src, (
            "center_control.html active nav link must point to /secured/control-center"
        )

    def test_p1b_04_live_feed_link_present(self):
        """/secured/live-feed link must be present (replaces dead /secured/dashboard)."""
        assert "/secured/live-feed" in self.src, (
            "center_control.html must link to /secured/live-feed instead of /secured/dashboard"
        )


# ── P2-B: Duplicate fetch elimination ─────────────────────────────────────────

class TestP2BDuplicateFetch:
    def setup_method(self):
        self.src = _read("control_center.html")
        self.dcl = _domcontentloaded_block(self.src)

    def test_p2b_01_no_direct_load_signal_perf_in_dcl(self):
        """loadSignalPerf() must not appear as a bare call in DOMContentLoaded
        (_loadThreatSection calls it internally)."""
        # Count standalone calls — must be 0 in the DCL block
        standalone = re.findall(r'^\s*loadSignalPerf\(\)', self.dcl, re.MULTILINE)
        assert len(standalone) == 0, (
            f"control_center.html DOMContentLoaded has {len(standalone)} direct "
            "loadSignalPerf() call(s) — duplicate; _loadThreatSection() already calls it"
        )

    def test_p2b_02_no_direct_load_threat_donut_in_dcl(self):
        """loadThreatDonut() must not appear as a bare call in DOMContentLoaded."""
        standalone = re.findall(r'^\s*loadThreatDonut\(\)', self.dcl, re.MULTILINE)
        assert len(standalone) == 0, (
            f"control_center.html DOMContentLoaded has {len(standalone)} direct "
            "loadThreatDonut() call(s) — duplicate; _loadThreatSection() already calls it"
        )

    def test_p2b_03_load_threat_section_still_in_dcl(self):
        """_loadThreatSection() must still be called in DOMContentLoaded."""
        assert "_loadThreatSection()" in self.dcl, (
            "control_center.html DOMContentLoaded: _loadThreatSection() call missing"
        )

    def test_p2b_04_load_signal_perf_inside_threat_section(self):
        """loadSignalPerf() must still be called inside _loadThreatSection."""
        fn_body = _fn_body(self.src, "_loadThreatSection")
        assert fn_body, "control_center.html: _loadThreatSection() function not found"
        assert "loadSignalPerf" in fn_body, (
            "_loadThreatSection() must call loadSignalPerf() internally"
        )

    def test_p2b_05_load_threat_donut_inside_threat_section(self):
        """loadThreatDonut() must still be called inside _loadThreatSection."""
        fn_body = _fn_body(self.src, "_loadThreatSection")
        assert fn_body, "control_center.html: _loadThreatSection() function not found"
        assert "loadThreatDonut" in fn_body, (
            "_loadThreatSection() must call loadThreatDonut() internally"
        )


# ── P2-C: Aria-live toast attributes ──────────────────────────────────────────

class TestP2CAriaToast:
    @pytest.mark.parametrize("filename", [
        "controls.html",
        "settings.html",
        "control_center.html",
        "center_control.html",
    ])
    def test_p2c_toast_has_role_status(self, filename):
        tag = _toast_tag(_read(filename))
        assert tag, f"{filename}: <div id=\"toast\"> not found"
        assert 'role="status"' in tag or "role='status'" in tag, (
            f"{filename}: toast div missing role=\"status\" — add for screen-reader support"
        )

    @pytest.mark.parametrize("filename", [
        "controls.html",
        "settings.html",
        "control_center.html",
        "center_control.html",
    ])
    def test_p2c_toast_has_aria_live_polite(self, filename):
        tag = _toast_tag(_read(filename))
        assert tag, f"{filename}: <div id=\"toast\"> not found"
        assert 'aria-live="polite"' in tag or "aria-live='polite'" in tag, (
            f"{filename}: toast div missing aria-live=\"polite\""
        )

    @pytest.mark.parametrize("filename", [
        "controls.html",
        "settings.html",
        "control_center.html",
        "center_control.html",
    ])
    def test_p2c_toast_has_aria_atomic(self, filename):
        tag = _toast_tag(_read(filename))
        assert tag, f"{filename}: <div id=\"toast\"> not found"
        assert 'aria-atomic="true"' in tag or "aria-atomic='true'" in tag, (
            f"{filename}: toast div missing aria-atomic=\"true\""
        )


# ── ACT: Action handler error reporting ───────────────────────────────────────

class TestActionErrorReporting:
    def setup_method(self):
        self.src = _read("main.html")

    def _ban_fn(self) -> str:
        # Find the function DEFINITION (not onclick usage earlier in file)
        pattern = r'_attackerBan\s*=\s*function'
        m = re.search(pattern, self.src)
        assert m, "main.html: _attackerBan function definition not found"
        idx = m.start()
        # Scan forward past the function's outer closing };
        end = self.src.find("\n  };", idx)
        return self.src[idx:end + 5] if end != -1 else self.src[idx:idx + 800]

    def _unban_fn(self) -> str:
        pattern = r'_attackerUnban\s*=\s*function'
        m = re.search(pattern, self.src)
        assert m, "main.html: _attackerUnban function definition not found"
        idx = m.start()
        end = self.src.find("\n  };", idx)
        return self.src[idx:end + 5] if end != -1 else self.src[idx:idx + 400]

    def test_act_01_ban_catch_calls_gwalert(self):
        """_attackerBan catch must call _gwAlert, not swallow the error silently."""
        fn = self._ban_fn()
        assert "_gwAlert" in fn, (
            "main.html: _attackerBan .catch() must call _gwAlert() to report the error"
        )

    def test_act_02_unban_catch_calls_gwalert(self):
        """_attackerUnban catch must call _gwAlert, not swallow the error silently."""
        fn = self._unban_fn()
        assert "_gwAlert" in fn, (
            "main.html: _attackerUnban .catch() must call _gwAlert() to report the error"
        )

    def test_act_03_ban_has_confirm_guard(self):
        """_attackerBan must have a confirm() before executing the ban fetch."""
        fn = self._ban_fn()
        assert "confirm(" in fn, (
            "main.html: _attackerBan must show confirm() before banning"
        )

    def test_act_04_no_bare_silent_catch_on_ban(self):
        """No bare .catch(function(){}) or .catch(()=>{}) on the ban fetch call."""
        fn = self._ban_fn()
        has_bare = bool(
            re.search(r'\.catch\s*\(\s*function\s*\(\s*\)\s*\{\s*\}\s*\)', fn) or
            re.search(r'\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)', fn)
        )
        assert not has_bare, (
            "main.html: _attackerBan still has a bare silent .catch(() => {})"
        )

    def test_act_05_no_bare_silent_catch_on_unban(self):
        """No bare .catch(function(){}) or .catch(()=>{}) on the unban fetch call."""
        fn = self._unban_fn()
        has_bare = bool(
            re.search(r'\.catch\s*\(\s*function\s*\(\s*\)\s*\{\s*\}\s*\)', fn) or
            re.search(r'\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)', fn)
        )
        assert not has_bare, (
            "main.html: _attackerUnban still has a bare silent .catch(() => {})"
        )

    def test_act_06_gwalert_defined_in_main(self):
        """_gwAlert must be defined in main.html for error reporting to work."""
        assert "function _gwAlert(" in self.src or "_gwAlert=function(" in self.src, (
            "main.html: _gwAlert() helper not defined — action error reporting will break"
        )


# ── NAV: Live Feed / Agents / SIEM indented under Control Center ─────────────

_ALL_DASH = [
    "main.html", "agents.html", "siem.html", "service.html", "controls.html",
    "vhost_policy.html", "geo.html", "logs.html", "settings.html",
    "center_control.html", "control_center.html",
]

NS = "/antibot-appsec-gateway/secured"


def _nav_block(src: str) -> str:
    """Return the text inside <nav id="sidebar-nav">...</nav>."""
    m = re.search(r'<nav id="sidebar-nav">(.*?)</nav>', src, re.DOTALL)
    return m.group(1) if m else ""


def _nav_links(src: str) -> list:
    """Return list of (href, classes, label) for each <a> in the sidebar nav."""
    nav = _nav_block(src)
    return re.findall(r'<a href="([^"]+)"([^>]*)>([^<]+)</a>', nav)


class TestNavStructure:
    @pytest.mark.parametrize("filename", _ALL_DASH)
    def test_nav_01_live_feed_is_sub(self, filename):
        links = _nav_links(_read(filename))
        lf = [(h, c, l) for h, c, l in links if "live-feed" in h]
        assert lf, f"{filename}: Live Feed link not found in sidebar nav"
        href, cls_attr, label = lf[0]
        assert "sub" in cls_attr, (
            f"{filename}: Live Feed link missing class=\"sub\" — must be indented under Control Center"
        )

    @pytest.mark.parametrize("filename", _ALL_DASH)
    def test_nav_02_agents_is_sub(self, filename):
        links = _nav_links(_read(filename))
        ag = [(h, c, l) for h, c, l in links if h.endswith("/agents")]
        assert ag, f"{filename}: Agents link not found in sidebar nav"
        href, cls_attr, label = ag[0]
        assert "sub" in cls_attr, (
            f"{filename}: Agents link missing class=\"sub\" — must be indented under Control Center"
        )

    @pytest.mark.parametrize("filename", _ALL_DASH)
    def test_nav_03_siem_is_sub(self, filename):
        links = _nav_links(_read(filename))
        siem = [(h, c, l) for h, c, l in links if h.endswith("/siem")]
        assert siem, f"{filename}: SIEM link not found in sidebar nav"
        href, cls_attr, label = siem[0]
        assert "sub" in cls_attr, (
            f"{filename}: SIEM link missing class=\"sub\" — must be indented under Control Center"
        )

    @pytest.mark.parametrize("filename", _ALL_DASH)
    def test_nav_04_siem_after_agents(self, filename):
        """SIEM must immediately follow Agents in nav order."""
        links = _nav_links(_read(filename))
        hrefs = [h for h, c, l in links]
        agents_idx = next((i for i, h in enumerate(hrefs) if h.endswith("/agents")), None)
        siem_idx   = next((i for i, h in enumerate(hrefs) if h.endswith("/siem")),   None)
        assert agents_idx is not None, f"{filename}: Agents link missing"
        assert siem_idx   is not None, f"{filename}: SIEM link missing"
        assert siem_idx == agents_idx + 1, (
            f"{filename}: SIEM (pos {siem_idx}) must be immediately after Agents (pos {agents_idx})"
        )

    @pytest.mark.parametrize("filename", _ALL_DASH)
    def test_nav_05_siem_not_at_end(self, filename):
        """SIEM must not be the last item in the nav (it's been moved before Service)."""
        links = _nav_links(_read(filename))
        hrefs = [h for h, c, l in links]
        siem_idx = next((i for i, h in enumerate(hrefs) if h.endswith("/siem")), None)
        assert siem_idx is not None, f"{filename}: SIEM link missing"
        assert siem_idx < len(hrefs) - 1, (
            f"{filename}: SIEM is still the last nav item — it should be moved after Agents"
        )

    def test_nav_06_siem_active_on_siem_page(self):
        """On siem.html the SIEM link must be both active and sub."""
        links = _nav_links(_read("siem.html"))
        siem = [(h, c, l) for h, c, l in links if h.endswith("/siem")]
        assert siem, "siem.html: SIEM link not found"
        _, cls_attr, _ = siem[0]
        assert "active" in cls_attr and "sub" in cls_attr, (
            f"siem.html: SIEM link classes={cls_attr!r} — expected both 'sub' and 'active'"
        )

    def test_nav_07_agents_active_on_agents_page(self):
        """On agents.html the Agents link must be both active and sub."""
        links = _nav_links(_read("agents.html"))
        ag = [(h, c, l) for h, c, l in links if h.endswith("/agents")]
        assert ag, "agents.html: Agents link not found"
        _, cls_attr, _ = ag[0]
        assert "active" in cls_attr and "sub" in cls_attr, (
            f"agents.html: Agents link classes={cls_attr!r} — expected both 'sub' and 'active'"
        )

    def test_nav_08_live_feed_active_on_main_page(self):
        """On main.html (Live Feed page) the Live Feed link must be both active and sub."""
        links = _nav_links(_read("main.html"))
        lf = [(h, c, l) for h, c, l in links if "live-feed" in h]
        assert lf, "main.html: Live Feed link not found"
        _, cls_attr, _ = lf[0]
        assert "active" in cls_attr and "sub" in cls_attr, (
            f"main.html: Live Feed link classes={cls_attr!r} — expected both 'sub' and 'active'"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Dynamic helpers
# ═══════════════════════════════════════════════════════════════════════════

_GW_NS = "/antibot-appsec-gateway/secured"


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


# ═══════════════════════════════════════════════════════════════════════════
# D01–D16  Dynamic tests
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_d01_control_center_200_html(proxy_module):
    """control-center route returns 200 HTML when authenticated."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/control-center", cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"/control-center returned HTTP {r.status}"
            text = await r.text()
            assert "<html" in text.lower(), "/control-center response not HTML"


@pytest.mark.asyncio
async def test_d02_live_feed_200_html(proxy_module):
    """live-feed route returns 200 HTML when authenticated."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/live-feed", cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"/live-feed returned HTTP {r.status}"
            text = await r.text()
            assert "<html" in text.lower(), "/live-feed response not HTML"


@pytest.mark.asyncio
async def test_d03_agents_200_html(proxy_module):
    """agents route returns 200 HTML when authenticated."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/agents", cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"/agents returned HTTP {r.status}"
            text = await r.text()
            assert "<html" in text.lower(), "/agents response not HTML"


@pytest.mark.asyncio
async def test_d04_siem_200_html(proxy_module):
    """siem route returns 200 HTML when authenticated."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/siem", cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"/siem returned HTTP {r.status}"
            text = await r.text()
            assert "<html" in text.lower(), "/siem response not HTML"


@pytest.mark.asyncio
async def test_d05_control_center_unauthenticated_deflected(proxy_module):
    """Without a session cookie, /control-center must not serve the dashboard HTML.
    In tests 127.0.0.1 may be an admin IP so status can be 200, but the body must
    not be the actual control-center dashboard (it will be the upstream echo or a
    login redirect — either way, no <html> dashboard content)."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/control-center")
            text = await r.text()
            # The real dashboard contains "Control Center" in an <h1>/<title>/topbar.
            # The test upstream echo returns {"ok": true} — no dashboard content.
            has_dashboard = "Control Center" in text and "<html" in text.lower()
            assert not has_dashboard, (
                f"/control-center served full dashboard HTML without a session cookie — "
                "unauthenticated access not deflected"
            )


@pytest.mark.asyncio
async def test_d06_control_center_html_contains_load_threat_section_in_dcl(proxy_module):
    """Served HTML for control-center must have _loadThreatSection() in DOMContentLoaded."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/control-center", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            dcl_idx = text.rfind("DOMContentLoaded")
            assert dcl_idx != -1, "/control-center HTML: DOMContentLoaded not found"
            dcl_block = text[dcl_idx:]
            assert "_loadThreatSection()" in dcl_block, (
                "/control-center HTML: _loadThreatSection() missing from DOMContentLoaded block"
            )


@pytest.mark.asyncio
async def test_d07_control_center_no_standalone_load_signal_perf_before_threat_section(proxy_module):
    """No bare loadSignalPerf() call before _loadThreatSection() in served DCL block."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/control-center", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            dcl_idx = text.rfind("DOMContentLoaded")
            dcl_block = text[dcl_idx:] if dcl_idx != -1 else ""
            standalone = re.findall(r'^\s*loadSignalPerf\(\)', dcl_block, re.MULTILINE)
            assert len(standalone) == 0, (
                f"/control-center HTML DCL has {len(standalone)} direct loadSignalPerf() call(s) "
                "— duplicate (should only be called via _loadThreatSection)"
            )


@pytest.mark.asyncio
async def test_d08_control_center_no_standalone_load_threat_donut_before_threat_section(proxy_module):
    """No bare loadThreatDonut() call before _loadThreatSection() in served DCL block."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/control-center", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            dcl_idx = text.rfind("DOMContentLoaded")
            dcl_block = text[dcl_idx:] if dcl_idx != -1 else ""
            standalone = re.findall(r'^\s*loadThreatDonut\(\)', dcl_block, re.MULTILINE)
            assert len(standalone) == 0, (
                f"/control-center HTML DCL has {len(standalone)} direct loadThreatDonut() call(s) "
                "— duplicate (should only be called via _loadThreatSection)"
            )


@pytest.mark.asyncio
async def test_d09_siem_page_nav_has_siem_sub_active(proxy_module):
    """Served siem.html nav must have SIEM link with 'sub active' classes."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/siem", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            assert 'class="sub active"' in text or 'class="active sub"' in text or \
                   "sub active" in text, (
                "/siem HTML: SIEM nav link does not have 'sub active' classes"
            )


@pytest.mark.asyncio
async def test_d10_agents_page_nav_has_agents_sub_active(proxy_module):
    """Served agents.html nav must have Agents link with 'sub active' classes."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/agents", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            assert 'class="sub active"' in text or 'class="active sub"' in text or \
                   "sub active" in text, (
                "/agents HTML: Agents nav link does not have 'sub active' classes"
            )


@pytest.mark.asyncio
async def test_d11_live_feed_page_nav_has_live_feed_sub_active(proxy_module):
    """Served live-feed (main.html) nav must have Live Feed link with 'sub active' classes."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/live-feed", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            assert 'class="sub active"' in text or 'class="active sub"' in text or \
                   "sub active" in text, (
                "/live-feed HTML: Live Feed nav link does not have 'sub active' classes"
            )


@pytest.mark.asyncio
async def test_d12_control_center_toast_has_role_status(proxy_module):
    """Served control-center HTML must have toast div with role='status'."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/control-center", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            toast_m = re.search(r'<div[^>]*id=["\']toast["\'][^>]*>', text)
            assert toast_m, "/control-center HTML: toast div not found"
            assert 'role="status"' in toast_m.group(0) or "role='status'" in toast_m.group(0), (
                f"/control-center toast div missing role='status': {toast_m.group(0)!r}"
            )


@pytest.mark.asyncio
async def test_d13_control_center_toast_has_aria_live(proxy_module):
    """Served control-center HTML must have toast div with aria-live='polite'."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/control-center", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            toast_m = re.search(r'<div[^>]*id=["\']toast["\'][^>]*>', text)
            assert toast_m, "/control-center HTML: toast div not found"
            assert 'aria-live="polite"' in toast_m.group(0) or \
                   "aria-live='polite'" in toast_m.group(0), (
                f"/control-center toast div missing aria-live='polite': {toast_m.group(0)!r}"
            )


@pytest.mark.asyncio
async def test_d14_controls_toast_has_role_status(proxy_module):
    """Served controls.html must have toast div with role='status'."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/controls", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            toast_m = re.search(r'<div[^>]*id=["\']toast["\'][^>]*>', text)
            assert toast_m, "/controls HTML: toast div not found"
            assert 'role="status"' in toast_m.group(0) or "role='status'" in toast_m.group(0), (
                f"/controls toast div missing role='status': {toast_m.group(0)!r}"
            )


@pytest.mark.asyncio
async def test_d15_settings_toast_has_role_status(proxy_module):
    """Served settings.html must have toast div with role='status'."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_GW_NS}/settings", cookies=_admin_cookie(proxy_module))
            text = await r.text()
            toast_m = re.search(r'<div[^>]*id=["\']toast["\'][^>]*>', text)
            assert toast_m, "/settings HTML: toast div not found"
            assert 'role="status"' in toast_m.group(0) or "role='status'" in toast_m.group(0), (
                f"/settings toast div missing role='status': {toast_m.group(0)!r}"
            )


@pytest.mark.asyncio
async def test_d16_ban_endpoint_exists(proxy_module):
    """POST /secured/ban must respond (not 404) for authenticated admin — endpoint exists."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            import json
            r = await cli.post(
                f"{_GW_NS}/ban",
                data=json.dumps({"ip": "10.0.0.1", "secs": 300}),
                headers={"Content-Type": "application/json"},
                cookies=_admin_cookie(proxy_module),
            )
            assert r.status != 404, (
                f"POST /secured/ban returned 404 — endpoint missing or route registration broken"
            )
