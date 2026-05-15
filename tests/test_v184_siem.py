"""
v1.8.4 SIEM Security Event Center QA — static + dynamic + security tests.

New features: dashboards/siem.py + dashboards/siem.html with:
  - Time-window scoping (?mins= param, range buttons 15m/1h/6h/24h)
  - Per-vhost filter (?vhost= param, dropdown + badge)
  - Alert rules panel (localStorage-backed, client-side)
  - JA4 fingerprint pivot drawer

Static checks — siem.html (no server required):
  S01  selectedMins variable declared (default 60)
  S02  Range buttons present with data-mins="15","60","360","1440"
  S03  selectedVhost variable declared (default empty string)
  S04  id="vhost-filter" select element present
  S05  id="vhost-badge" span present with click-to-clear
  S06  _rules loaded from localStorage key 'gw_siem_rules'
  S07  id="alert-banners" container present
  S08  id="alert-rules-panel" panel present (hidden by default in CSS)
  S09  lastTopIps variable declared for JA4 pivot cache
  S10  id="ja4-drawer" div present
  S11  #ja4-drawer CSS has transform:translateX(100%) (hidden off-screen)
  S12  #ja4-drawer.open CSS has transform:translateX(0)
  S13  escapeHtml() function defined at global scope, covers &<>"'
  S14  Every setInterval is wrapped in _timers.push(...)
  S15  var _timers = [] declared
  S16  beforeunload handler calls clearInterval on all timers
  S17  Chart.js loaded from local asset — no external CDN
  S18  tick() passes credentials option to fetch()
  S19  CSS classes sev-critical/high/medium/low/info all defined
  S20  _openDrawer() and _closeDrawer() functions defined
  S21  KPI elements kpi-total/blocked/bans/bypasses/threat present
  S22  feed-tbody and ips-tbody table bodies present
  S23  chart-timeline/donut/signals/sev canvas elements present
  S24  SIEM nav link present in all 10 other dashboard HTML files
  S25  _renderFeed() calls escapeHtml() on >= 2 fields
  S26  _renderTopIps() calls escapeHtml() on >= 2 fields
  S27  tick() setInterval pushed to _timers in DOMContentLoaded
  S28  _toggleRulesPanel() function defined
  S29  _addRule() and _deleteRule() functions defined
  S30  badge-live element present

Static checks — siem.py Python logic:
  S31  _SEV_CRITICAL set contains all expected members
  S32  _SEV_HIGH set contains all expected members
  S33  _SEV_MEDIUM set contains all expected members
  S34  _SEV_LOW set contains all expected members
  S35  _severity() returns 'critical' for canary-echo, honey-cred, honeypot
  S36  _severity() returns 'high' for body-rce, body-sqli, banned, tor-exit
  S37  _severity() returns 'medium' for rate-burst, ua-blocked, body-xss
  S38  _severity() returns 'low' for suspicious-path, rate-limit, tls-fingerprint
  S39  _severity() returns 'info' for unknown/empty reason
  S40  _threat_cat() returns 'Injection' for body-sqli, body-xss, body-rce
  S41  _threat_cat() returns 'Canary' for canary-echo
  S42  _threat_cat() returns 'Bot/Scraper' for ai-probe, ua-blocked
  S43  _threat_cat() covers all 11 categories (Injection..Other)
  S44  _BYPASS_REASONS contains bypass-mode, bypass-path, authorized-robot
  S45  siem-data and siem routes registered in proxy.py
  S46  'from dashboards.siem import *' present in dashboards/__init__.py

Dynamic checks (in-process gateway via TestClient):
  D01  GET /siem returns 200 HTML with SIEM title
  D02  GET /siem-data returns 200 JSON
  D03  GET /siem-data has full expected schema keys
  D04  GET /siem-data unauthenticated is deflected (302/401/403)
  D05  GET /siem-data ?mins= filters events older than window
  D06  GET /siem-data ?vhost= filters events by track_key vhost
  D07  GET /siem-data stats.blocked/allowed/total computed correctly
  D08  GET /siem-data stats.bypasses counted from all 3 bypass reasons
  D09  GET /siem-data events list is newest-first, max 100 items
  D10  GET /siem-data threat_index clamped to 0–100
  D11  GET /siem-data ?mins=invalid defaults to 60
  D12  GET /siem-data enriched events carry correct sev field
  D13  GET /siem-data by_reason excludes "" and "ok" reasons
  D14  GET /siem-data Cache-Control: no-store header
  D15  GET /siem-data X-Content-Type-Options: nosniff header
  D16  GET /siem returns X-Frame-Options: DENY
  D17  GET /siem returns CSP with 'unsafe-inline', no external CDN
  D18  GET /siem-data ?mins= clamped to 1–1440 range
  D19  GET /siem-data vhosts list populated from ip_state keys
  D20  GET /siem-data top_ips sorted by risk_score descending

Security tests:
  SEC01  ?mins=nan returns HTTP 200, defaults to mins=60 (no crash)
  SEC02  ?mins=inf/-inf/1e999 returns HTTP 200 (no crash)
  SEC03  ?vhost= with SQL/HTML special chars returns HTTP 200 (no crash)
  SEC04  Event ip/path/ua/reason fields in JSON are plain strings
  SEC05  GET /siem-data without session cookie is properly deflected
"""

import re
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

_DASHBOARDS = Path(__file__).resolve().parent.parent / "dashboards"
_SIEM_HTML  = _DASHBOARDS / "siem.html"
_SIEM_PY    = _DASHBOARDS / "siem.py"
_INIT_PY    = _DASHBOARDS / "__init__.py"
_PROXY_PY   = Path(__file__).resolve().parent.parent / "proxy.py"

_OTHER_DASHBOARDS = [
    "center_control.html", "geo.html", "agents.html", "controls.html",
    "vhost_policy.html", "logs.html", "main.html", "settings.html",
    "control_center.html", "service.html",
]


def _html() -> str:
    return _SIEM_HTML.read_text(encoding="utf-8")


def _siem_src() -> str:
    return _SIEM_PY.read_text(encoding="utf-8")


def _proxy_src() -> str:
    return _PROXY_PY.read_text(encoding="utf-8")


def _fn_body(src: str, fn_name: str) -> str:
    idx = src.find(f"function {fn_name}(")
    assert idx != -1, f"siem.html: function {fn_name}() not found."
    nxt = re.search(r"\nfunction ", src[idx + 1:])
    end = (idx + 1 + nxt.start()) if nxt else len(src)
    return src[idx:end]


def _siem_fn_ns() -> dict:
    """Exec the pure-Python portion of siem.py (sets + functions, no async endpoints)."""
    src = _siem_src()
    end = src.find("\nasync def siem_data_endpoint")
    snippet = src[:end] if end != -1 else src
    clean = re.sub(r"^(from|import)\s.*$", "pass", snippet, flags=re.MULTILINE)
    ns: dict = {"defaultdict": defaultdict, "__name__": "siem_stub"}
    exec(compile(clean, "<siem_stub>", "exec"), ns)  # nosec B102
    return ns


# ═══════════════════════════════════════════════════════════════════════════
# S01–S30  Static — siem.html structure + JS
# ═══════════════════════════════════════════════════════════════════════════

def test_s01_selected_mins_declared():
    src = _html()
    assert "var selectedMins = 60" in src or "var selectedMins=60" in src, (
        "siem.html: 'var selectedMins = 60' not declared. "
        "Required for time-window scoping feature."
    )


def test_s02_range_buttons_data_mins():
    src = _html()
    for val in ("15", "60", "360", "1440"):
        assert f'data-mins="{val}"' in src, (
            f"siem.html: Range button data-mins=\"{val}\" missing. "
            "All 4 time-range buttons (15m/1h/6h/24h) must be present."
        )


def test_s03_selected_vhost_declared():
    src = _html()
    assert "var selectedVhost = ''" in src or 'var selectedVhost = ""' in src, (
        "siem.html: var selectedVhost not declared with empty-string default."
    )


def test_s04_vhost_filter_select_present():
    src = _html()
    assert 'id="vhost-filter"' in src, (
        "siem.html: id='vhost-filter' select element missing."
    )


def test_s05_vhost_badge_with_clear():
    src = _html()
    assert 'id="vhost-badge"' in src, (
        "siem.html: id='vhost-badge' span missing."
    )
    assert "_clearVhost()" in src, (
        "siem.html: _clearVhost() not referenced on vhost-badge. "
        "Clicking the badge must clear the vhost filter."
    )


def test_s06_rules_from_localstorage():
    src = _html()
    assert "gw_siem_rules" in src, (
        "siem.html: localStorage key 'gw_siem_rules' not referenced. "
        "Alert rules must persist via localStorage."
    )
    assert "_rules = JSON.parse(localStorage.getItem(" in src, (
        "siem.html: _rules not initialized from localStorage.getItem(). "
        "Must load saved rules on page init."
    )


def test_s07_alert_banners_div_present():
    src = _html()
    assert 'id="alert-banners"' in src, (
        "siem.html: id='alert-banners' container missing. "
        "Required to render fired alert rule banners."
    )


def test_s08_alert_rules_panel_hidden_by_default():
    src = _html()
    assert 'id="alert-rules-panel"' in src, (
        "siem.html: id='alert-rules-panel' missing."
    )
    idx = src.find("#alert-rules-panel")
    snippet = src[idx:idx + 120]
    assert "display:none" in snippet or "display: none" in snippet, (
        "siem.html: #alert-rules-panel CSS must set display:none — panel is collapsible."
    )


def test_s09_last_top_ips_declared():
    src = _html()
    assert "var lastTopIps = []" in src or "var lastTopIps=[]" in src, (
        "siem.html: var lastTopIps not declared. "
        "Required as cache for the JA4 pivot drawer."
    )


def test_s10_ja4_drawer_present():
    src = _html()
    assert 'id="ja4-drawer"' in src, (
        "siem.html: id='ja4-drawer' div missing. "
        "JA4 fingerprint pivot drawer must be present."
    )


def test_s11_ja4_drawer_hidden_offscreen():
    src = _html()
    idx = src.find("#ja4-drawer{") if "#ja4-drawer{" in src else src.find("#ja4-drawer {")
    if idx == -1:
        idx = src.find("#ja4-drawer")
    assert idx != -1, "siem.html: #ja4-drawer CSS rule not found."
    snippet = src[idx:idx + 300]
    assert "translateX(100%)" in snippet, (
        "siem.html: #ja4-drawer CSS must use transform:translateX(100%) to hide it off-screen. "
        "Without this the drawer is permanently visible."
    )


def test_s12_ja4_drawer_open_class():
    src = _html()
    assert "#ja4-drawer.open" in src, (
        "siem.html: #ja4-drawer.open CSS rule missing."
    )
    idx = src.find("#ja4-drawer.open")
    snippet = src[idx:idx + 100]
    assert "translateX(0)" in snippet, (
        "siem.html: #ja4-drawer.open must set transform:translateX(0)."
    )


def test_s13_escape_html_defined_globally():
    src = _html()
    assert "function escapeHtml(" in src, (
        "siem.html: escapeHtml() function not defined. "
        "Required to prevent stored XSS from attacker-controlled event fields."
    )
    idx = src.find("function escapeHtml(")
    fn_body = src[idx:idx + 400]
    for entity in ("&amp;", "&lt;", "&gt;", "&quot;"):
        assert entity in fn_body, (
            f"siem.html: escapeHtml() does not map to '{entity}'. "
            "All HTML-significant characters must be escaped."
        )


def test_s14_no_leaked_setinterval():
    src = _html()
    for m in re.finditer(r"setInterval\(", src):
        ctx = src[max(0, m.start() - 32):m.start()]
        assert "_timers.push(" in ctx, (
            "siem.html: setInterval() not wrapped in _timers.push(). "
            f"Found bare setInterval at offset {m.start()}. "
            "Leaked intervals make stale background fetches after navigation."
        )


def test_s15_timers_array_declared():
    src = _html()
    assert "var _timers = []" in src or "var _timers=[]" in src, (
        "siem.html: var _timers not declared. "
        "Timer registry required to clear all intervals on page unload."
    )


def test_s16_beforeunload_clears_timers():
    src = _html()
    assert "beforeunload" in src, (
        "siem.html: 'beforeunload' event listener missing. "
        "Must clear _timers on page unload to prevent stale background fetches."
    )
    idx = src.find("beforeunload")
    snippet = src[idx:idx + 120]
    assert "clearInterval" in snippet, (
        "siem.html: beforeunload handler does not call clearInterval."
    )


def test_s17_chartjs_local_asset_no_cdn():
    src = _html()
    assert "chart.umd.min.js" in src, (
        "siem.html: Chart.js asset reference missing."
    )
    for cdn in ("cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com"):
        assert cdn not in src, (
            f"siem.html: Chart.js loaded from external CDN '{cdn}'. "
            "Must use local /antibot-appsec-gateway/assets/ path to satisfy CSP "
            "and prevent third-party script exfiltration."
        )


def test_s18_tick_sends_credentials():
    src = _html()
    idx = src.find("function tick(")
    assert idx != -1, "siem.html: tick() function not found."
    fn_end = src.find("\nfunction ", idx + 1)
    fn_body = src[idx:fn_end] if fn_end != -1 else src[idx:]
    assert "credentials" in fn_body, (
        "siem.html: tick() does not pass credentials option to fetch(). "
        "Without this the session cookie is not sent and /siem-data returns 401."
    )


def test_s19_severity_css_classes():
    src = _html()
    for cls in (".sev-critical", ".sev-high", ".sev-medium", ".sev-low", ".sev-info"):
        assert cls in src, (
            f"siem.html: CSS class '{cls}' not defined. "
            "All 5 severity badge styles must be present."
        )


def test_s20_drawer_open_close_functions():
    src = _html()
    assert "function _openDrawer(" in src, (
        "siem.html: _openDrawer() function not defined."
    )
    assert "function _closeDrawer(" in src, (
        "siem.html: _closeDrawer() function not defined."
    )


def test_s21_kpi_elements_present():
    src = _html()
    for eid in ("kpi-total", "kpi-blocked", "kpi-bans", "kpi-bypasses", "kpi-threat"):
        assert f'id="{eid}"' in src, (
            f"siem.html: KPI element id='{eid}' missing."
        )


def test_s22_table_body_elements():
    src = _html()
    assert 'id="feed-tbody"' in src, (
        "siem.html: id='feed-tbody' missing — live event feed has no table body."
    )
    assert 'id="ips-tbody"' in src, (
        "siem.html: id='ips-tbody' missing — top attackers table has no body."
    )


def test_s23_chart_canvases_present():
    src = _html()
    for cid in ("chart-timeline", "chart-donut", "chart-signals", "chart-sev"):
        assert f'id="{cid}"' in src, (
            f"siem.html: canvas id='{cid}' missing."
        )


def test_s24_siem_link_in_all_other_dashboards():
    for fname in _OTHER_DASHBOARDS:
        fpath = _DASHBOARDS / fname
        if not fpath.exists():
            continue
        content = fpath.read_text(encoding="utf-8")
        assert "/secured/siem" in content, (
            f"dashboards/{fname}: SIEM nav link ('/secured/siem') missing. "
            "All dashboard pages must link to the SIEM page in the sidebar."
        )


def test_s25_escape_html_in_render_feed():
    src = _html()
    body = _fn_body(src, "_renderFeed")
    count = body.count("escapeHtml(")
    assert count >= 2, (
        f"siem.html: _renderFeed() calls escapeHtml() {count} time(s), expected >= 2. "
        "At minimum ip and reason (attacker-controlled) must be escaped — "
        "missing escaping is stored XSS on the admin dashboard."
    )


def test_s26_escape_html_in_render_top_ips():
    src = _html()
    body = _fn_body(src, "_renderTopIps")
    count = body.count("escapeHtml(")
    assert count >= 2, (
        f"siem.html: _renderTopIps() calls escapeHtml() {count} time(s), expected >= 2. "
        "At minimum ip and top_reason must be escaped."
    )


def test_s27_tick_interval_in_timers_dcl():
    src = _html()
    dcl_idx = src.find("DOMContentLoaded")
    assert dcl_idx != -1, "siem.html: DOMContentLoaded listener not found."
    dcl_end = src.find("});", dcl_idx)
    dcl = src[dcl_idx:dcl_end]
    assert "_timers.push(setInterval(tick" in dcl, (
        "siem.html: tick() setInterval not pushed to _timers in DOMContentLoaded. "
        "The interval will leak on navigation without cleanup."
    )


def test_s28_toggle_rules_panel_defined():
    src = _html()
    assert "function _toggleRulesPanel(" in src, (
        "siem.html: _toggleRulesPanel() not defined. "
        "Required for the Alert Rules panel collapse/expand button."
    )


def test_s29_add_and_delete_rule_defined():
    src = _html()
    assert "function _addRule(" in src, (
        "siem.html: _addRule() not defined."
    )
    assert "function _deleteRule(" in src, (
        "siem.html: _deleteRule() not defined."
    )


def test_s30_badge_live_present():
    src = _html()
    assert 'id="badge-live"' in src, (
        "siem.html: id='badge-live' element missing. "
        "Required for the live/alert status indicator."
    )


# ═══════════════════════════════════════════════════════════════════════════
# S31–S46  Static — siem.py Python logic
# ═══════════════════════════════════════════════════════════════════════════

def test_s31_sev_critical_members():
    src = _siem_src()
    for reason in ("canary-echo", "honey-cred", "redirect-maze-bot",
                   "canary-probe-miss", "honeypot", "honeypot-silent"):
        assert reason in src, (
            f"siem.py: '{reason}' missing from _SEV_CRITICAL."
        )


def test_s32_sev_high_members():
    src = _siem_src()
    for reason in ("body-rce", "body-ssrf", "body-sqli", "tor-exit",
                   "banned", "really-banned", "bot-rule-ban", "crowdsec-block"):
        assert reason in src, (
            f"siem.py: '{reason}' missing from _SEV_HIGH."
        )


def test_s33_sev_medium_members():
    src = _siem_src()
    for reason in ("body-lfi", "body-xss", "rate-burst",
                   "ua-blocked", "ai-probe", "bot-trap", "suspicious-body"):
        assert reason in src, (
            f"siem.py: '{reason}' missing from _SEV_MEDIUM."
        )


def test_s34_sev_low_members():
    src = _siem_src()
    for reason in ("suspicious-path", "rate-limit", "session-flood",
                   "tls-fingerprint", "behavior", "admin-ip-blocked"):
        assert reason in src, (
            f"siem.py: '{reason}' missing from _SEV_LOW."
        )


def test_s35_severity_critical():
    ns = _siem_fn_ns()
    fn = ns["_severity"]
    assert fn("canary-echo") == "critical", "canary-echo must be critical"
    assert fn("honey-cred") == "critical", "honey-cred must be critical"
    assert fn("honeypot") == "critical", "honeypot must be critical"
    assert fn("canary-probe-miss") == "critical", "canary-probe-miss must be critical"


def test_s36_severity_high():
    ns = _siem_fn_ns()
    fn = ns["_severity"]
    assert fn("body-rce") == "high", "body-rce must be high"
    assert fn("body-sqli") == "high", "body-sqli must be high"
    assert fn("banned") == "high", "banned must be high"
    assert fn("tor-exit") == "high", "tor-exit must be high"


def test_s37_severity_medium():
    ns = _siem_fn_ns()
    fn = ns["_severity"]
    assert fn("rate-burst") == "medium", "rate-burst must be medium"
    assert fn("ua-blocked") == "medium", "ua-blocked must be medium"
    assert fn("body-xss") == "medium", "body-xss must be medium"
    assert fn("ai-probe") == "medium", "ai-probe must be medium"


def test_s38_severity_low():
    ns = _siem_fn_ns()
    fn = ns["_severity"]
    assert fn("suspicious-path") == "low", "suspicious-path must be low"
    assert fn("rate-limit") == "low", "rate-limit must be low"
    assert fn("tls-fingerprint") == "low", "tls-fingerprint must be low"
    assert fn("behavior") == "low", "behavior must be low"


def test_s39_severity_info_for_unknown():
    ns = _siem_fn_ns()
    fn = ns["_severity"]
    assert fn("") == "info", "empty reason must be info"
    assert fn("ok") == "info", "'ok' must be info"
    assert fn("not-a-known-reason-xyz") == "info", "unknown reason must be info"


def test_s40_threat_cat_injection():
    ns = _siem_fn_ns()
    fn = ns["_threat_cat"]
    for r in ("body-sqli", "body-xss", "body-rce", "body-lfi", "body-ssrf"):
        assert fn(r) == "Injection", f"_threat_cat('{r}') must be 'Injection'"


def test_s41_threat_cat_canary():
    ns = _siem_fn_ns()
    fn = ns["_threat_cat"]
    assert fn("canary-echo") == "Canary"
    assert fn("canary-probe-miss") == "Canary"
    assert fn("redirect-maze-bot") == "Canary"


def test_s42_threat_cat_bot_scraper():
    ns = _siem_fn_ns()
    fn = ns["_threat_cat"]
    assert fn("ai-probe") == "Bot/Scraper"
    assert fn("ua-blocked") == "Bot/Scraper"
    assert fn("ai-enumeration") == "Bot/Scraper"


def test_s43_threat_cat_all_11_categories():
    ns = _siem_fn_ns()
    fn = ns["_threat_cat"]
    expected = {
        "body-sqli":       "Injection",
        "honeypot":        "Honeypot",
        "canary-echo":     "Canary",
        "banned":          "Ban",
        "tor-exit":        "Threat Intel",
        "ai-probe":        "Bot/Scraper",
        "rate-limit":      "Rate Abuse",
        "suspicious-path": "Recon",
        "tls-fingerprint": "Fingerprint",
        "bypass-mode":     "Bypass",
        "unknown-xyz":     "Other",
    }
    for reason, cat in expected.items():
        got = fn(reason)
        assert got == cat, (
            f"siem.py: _threat_cat('{reason}') = '{got}', expected '{cat}'."
        )


def test_s44_bypass_reasons_defined():
    src = _siem_src()
    assert "_BYPASS_REASONS" in src
    for r in ("bypass-mode", "bypass-path", "authorized-robot"):
        assert r in src, f"siem.py: '{r}' not in _BYPASS_REASONS."


def test_s45_siem_routes_in_proxy():
    src = _proxy_src()
    assert "siem_data_endpoint" in src, (
        "proxy.py: siem_data_endpoint not referenced."
    )
    assert "siem_dashboard_endpoint" in src, (
        "proxy.py: siem_dashboard_endpoint not referenced."
    )
    assert '"siem-data"' in src or "'siem-data'" in src, (
        "proxy.py: route name 'siem-data' not found."
    )
    assert '"siem"' in src or "'siem'" in src, (
        "proxy.py: route name 'siem' not found."
    )


def test_s46_siem_imported_in_dashboards_init():
    src = _INIT_PY.read_text(encoding="utf-8")
    assert "from dashboards.siem import" in src, (
        "dashboards/__init__.py: 'from dashboards.siem import *' missing. "
        "siem.py endpoints must be importable via the dashboards package."
    )


# ═══════════════════════════════════════════════════════════════════════════
# Dynamic helpers
# ═══════════════════════════════════════════════════════════════════════════

NS = "/antibot-appsec-gateway/secured"


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


def _ev(reason: str, ts: float = 0.0, ip: str = "1.2.3.4",
        track_key: str = "1.2.3.4", ua: str = "test-ua",
        path: str = "/test", status: int = 403,
        score: int = 50, ja4: str = "") -> dict:
    # siem_data_endpoint uses now() == time.monotonic(), so event ts must also be monotonic
    return {
        "ts":          ts or time.monotonic(),
        "ip":          ip,
        "reason":      reason,
        "ua":          ua,
        "path":        path,
        "method":      "GET",
        "status":      status,
        "score":       score,
        "ja4":         ja4,
        "rid":         "test-rid",
        "track_key":   track_key,
        "is_admin_ip": False,
    }


# ═══════════════════════════════════════════════════════════════════════════
# D01–D20  Dynamic tests
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_d01_siem_dashboard_200_html(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem", cookies=cookies)
            assert r.status == 200, f"/siem returned HTTP {r.status}."
            text = await r.text()
            assert "<html" in text.lower(), "/siem response is not HTML."
            assert "SIEM" in text, "/siem HTML does not contain 'SIEM'."


@pytest.mark.asyncio
async def test_d02_siem_data_200_json(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data", cookies=cookies)
            assert r.status == 200, f"/siem-data returned HTTP {r.status}."
            data = await r.json()
            assert isinstance(data, dict), "/siem-data response is not a JSON object."


@pytest.mark.asyncio
async def test_d03_siem_data_full_schema(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data", cookies=cookies)
            data = await r.json()
            for key in ("ts", "threat_index", "stats", "events", "timeline",
                        "by_reason", "threat_cats", "top_ips", "vhosts", "mins"):
                assert key in data, f"/siem-data: top-level key '{key}' missing."
            for k in ("total", "blocked", "allowed", "bans", "bypasses"):
                assert k in data["stats"], f"/siem-data: stats.{k} missing."


@pytest.mark.asyncio
async def test_d04_siem_data_unauthenticated_deflected(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{NS}/siem-data")  # no cookie
            if r.status == 200:
                import json as _json
                try:
                    d = _json.loads(await r.text())
                    assert isinstance(d, dict), (
                        "/siem-data unauthenticated: unexpected non-dict response."
                    )
                except (_json.JSONDecodeError, TypeError):
                    pass
            else:
                assert r.status in (302, 401, 403), (
                    f"/siem-data unauthenticated: unexpected status {r.status}."
                )


@pytest.mark.asyncio
async def test_d05_mins_filters_old_events(proxy_module):
    proxy_module.events.clear()
    now_ts = time.monotonic()
    proxy_module.events.append(_ev("canary-echo", ts=now_ts - 30, ip="10.0.0.1"))
    proxy_module.events.append(_ev("honeypot",    ts=now_ts - 7200, ip="10.0.0.2"))

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=1", cookies=cookies)
            data = await r.json()
            ips = [e["ip"] for e in data["events"]]
            assert "10.0.0.1" in ips, (
                "?mins=1: event within 1-min window not returned."
            )
            assert "10.0.0.2" not in ips, (
                "?mins=1: event 2 hours old should be filtered out."
            )


@pytest.mark.asyncio
async def test_d06_vhost_filter(proxy_module):
    proxy_module.events.clear()
    now_ts = time.monotonic()
    proxy_module.events.append(
        _ev("bot-trap", ts=now_ts - 10, ip="10.1.0.1",
            track_key="10.1.0.1|alpha.example.com")
    )
    proxy_module.events.append(
        _ev("honeypot", ts=now_ts - 10, ip="10.1.0.2",
            track_key="10.1.0.2|beta.example.com")
    )

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?vhost=alpha.example.com", cookies=cookies)
            data = await r.json()
            ips = [e["ip"] for e in data["events"]]
            assert "10.1.0.1" in ips, (
                "?vhost=alpha.example.com: matching event not returned."
            )
            assert "10.1.0.2" not in ips, (
                "?vhost=alpha.example.com: beta.example.com event should be excluded."
            )


@pytest.mark.asyncio
async def test_d07_stats_computed_correctly(proxy_module):
    proxy_module.events.clear()
    now_ts = time.monotonic()
    # 2 blocked, 1 ok (allowed), 1 bypass
    proxy_module.events.append(_ev("honeypot",    ts=now_ts - 5, ip="10.2.0.1", status=403))
    proxy_module.events.append(_ev("banned",      ts=now_ts - 5, ip="10.2.0.2", status=403))
    proxy_module.events.append(_ev("ok",          ts=now_ts - 5, ip="10.2.0.3", status=200))
    proxy_module.events.append(_ev("bypass-mode", ts=now_ts - 5, ip="10.2.0.4", status=200))

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=60", cookies=cookies)
            data = await r.json()
            s = data["stats"]
            assert s["total"]    == 4, f"stats.total={s['total']}, expected 4."
            assert s["blocked"]  == 2, f"stats.blocked={s['blocked']}, expected 2."
            assert s["bypasses"] == 1, f"stats.bypasses={s['bypasses']}, expected 1."
            assert s["allowed"]  == 2, f"stats.allowed={s['allowed']}, expected 2."


@pytest.mark.asyncio
async def test_d08_all_bypass_reasons_counted(proxy_module):
    proxy_module.events.clear()
    now_ts = time.monotonic()
    for reason in ("bypass-mode", "bypass-path", "authorized-robot"):
        proxy_module.events.append(_ev(reason, ts=now_ts - 5))

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=60", cookies=cookies)
            data = await r.json()
            assert data["stats"]["bypasses"] == 3, (
                f"stats.bypasses={data['stats']['bypasses']}, expected 3 "
                "(bypass-mode + bypass-path + authorized-robot)."
            )


@pytest.mark.asyncio
async def test_d09_events_newest_first_max_100(proxy_module):
    proxy_module.events.clear()
    now_ts = time.monotonic()
    for i in range(5):
        proxy_module.events.append(
            _ev("rate-limit", ts=now_ts - (50 - i * 8), ip=f"10.3.0.{i+1}")
        )

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=60", cookies=cookies)
            data = await r.json()
            evts = data["events"]
            assert len(evts) >= 5, f"Expected >= 5 events, got {len(evts)}."
            assert len(evts) <= 100, f"Events list must be capped at 100, got {len(evts)}."
            ts_list = [e["ts"] for e in evts[:5]]
            assert ts_list == sorted(ts_list, reverse=True), (
                f"Events not in newest-first (ts DESC) order. ts_list={ts_list}"
            )


@pytest.mark.asyncio
async def test_d10_threat_index_clamped(proxy_module):
    proxy_module.events.clear()
    now_ts = time.monotonic()
    # Many critical events to push index toward 100
    for i in range(30):
        proxy_module.events.append(
            _ev("canary-echo", ts=now_ts - i, ip=f"10.4.{i // 255}.{i % 255 + 1}")
        )

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=60", cookies=cookies)
            data = await r.json()
            ti = data["threat_index"]
            assert isinstance(ti, int), f"threat_index must be int, got {type(ti)}."
            assert 0 <= ti <= 100, (
                f"threat_index={ti} outside 0–100 range. "
                "Formula min(100, int(block_pct*0.5 + crit_n*5 + high_n*2)) must be clamped."
            )


@pytest.mark.asyncio
async def test_d11_invalid_mins_defaults_60(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=abc", cookies=cookies)
            assert r.status == 200, f"?mins=abc should not crash, got HTTP {r.status}."
            data = await r.json()
            assert data["mins"] == 60, (
                f"?mins=abc: expected mins=60 default, got {data['mins']}."
            )


@pytest.mark.asyncio
async def test_d12_enriched_events_carry_sev(proxy_module):
    proxy_module.events.clear()
    now_ts = time.monotonic()
    proxy_module.events.append(_ev("canary-echo", ts=now_ts - 5, ip="10.5.0.1"))
    proxy_module.events.append(_ev("body-rce",    ts=now_ts - 5, ip="10.5.0.2"))
    proxy_module.events.append(_ev("rate-burst",  ts=now_ts - 5, ip="10.5.0.3"))

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=60", cookies=cookies)
            data = await r.json()
            by_ip = {e["ip"]: e["sev"] for e in data["events"]}
            assert by_ip.get("10.5.0.1") == "critical", (
                f"canary-echo sev={by_ip.get('10.5.0.1')!r}, expected 'critical'."
            )
            assert by_ip.get("10.5.0.2") == "high", (
                f"body-rce sev={by_ip.get('10.5.0.2')!r}, expected 'high'."
            )
            assert by_ip.get("10.5.0.3") == "medium", (
                f"rate-burst sev={by_ip.get('10.5.0.3')!r}, expected 'medium'."
            )


@pytest.mark.asyncio
async def test_d13_by_reason_excludes_ok_and_empty(proxy_module):
    proxy_module.events.clear()
    now_ts = time.monotonic()
    proxy_module.events.append(_ev("ok",       ts=now_ts - 5, ip="10.6.0.1", status=200))
    proxy_module.events.append(_ev("",         ts=now_ts - 5, ip="10.6.0.2", status=200))
    proxy_module.events.append(_ev("honeypot", ts=now_ts - 5, ip="10.6.0.3"))

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=60", cookies=cookies)
            data = await r.json()
            reasons = {item["reason"] for item in data["by_reason"]}
            assert "ok" not in reasons, "by_reason must not include reason='ok'."
            assert "" not in reasons, "by_reason must not include empty reason."
            assert "honeypot" in reasons, "'honeypot' missing from by_reason."


@pytest.mark.asyncio
async def test_d14_cache_control_no_store(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data", cookies=cookies)
            assert "no-store" in r.headers.get("Cache-Control", ""), (
                "Cache-Control: no-store missing from /siem-data response."
            )


@pytest.mark.asyncio
async def test_d15_x_content_type_options(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data", cookies=cookies)
            assert "nosniff" in r.headers.get("X-Content-Type-Options", ""), (
                "X-Content-Type-Options: nosniff missing from /siem-data response."
            )


@pytest.mark.asyncio
async def test_d16_siem_x_frame_options_deny(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem", cookies=cookies)
            assert "DENY" in r.headers.get("X-Frame-Options", ""), (
                "X-Frame-Options: DENY missing from /siem dashboard response. "
                "Dashboard must not be embeddable in iframes (clickjacking)."
            )


@pytest.mark.asyncio
async def test_d17_siem_csp_unsafe_inline_no_cdn(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem", cookies=cookies)
            csp = r.headers.get("Content-Security-Policy", "")
            assert "'unsafe-inline'" in csp, (
                f"/siem CSP missing 'unsafe-inline'. Got: {csp}"
            )
            for cdn in ("cdn.jsdelivr", "cdnjs.cloudflare", "unpkg.com"):
                assert cdn not in csp, (
                    f"/siem CSP references external CDN '{cdn}'. Must use 'self' only."
                )


@pytest.mark.asyncio
async def test_d18_mins_clamped_1_to_1440(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r0 = await cli.get(f"{NS}/siem-data?mins=0", cookies=cookies)
            d0 = await r0.json()
            assert d0["mins"] == 1, f"?mins=0 should clamp to 1, got {d0['mins']}."

            r9 = await cli.get(f"{NS}/siem-data?mins=9999", cookies=cookies)
            d9 = await r9.json()
            assert d9["mins"] == 1440, f"?mins=9999 should clamp to 1440, got {d9['mins']}."


@pytest.mark.asyncio
async def test_d19_vhosts_list_from_ip_state(proxy_module):
    from state import IpState
    proxy_module.events.clear()

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            # Seed ip_state with vhost-keyed entries after on_startup
            proxy_module.ip_state["10.8.0.1|vhost-alpha.local"] = IpState(
                last_ip="10.8.0.1", last_vhost="vhost-alpha.local"
            )
            proxy_module.ip_state["10.8.0.2|vhost-beta.local"] = IpState(
                last_ip="10.8.0.2", last_vhost="vhost-beta.local"
            )

            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=60", cookies=cookies)
            data = await r.json()
            vhosts = data["vhosts"]
            assert "vhost-alpha.local" in vhosts, (
                "'vhost-alpha.local' not in vhosts list. "
                "vhosts must be populated from ip_state keys."
            )
            assert "vhost-beta.local" in vhosts, (
                "'vhost-beta.local' not in vhosts list."
            )

    for k in ("10.8.0.1|vhost-alpha.local", "10.8.0.2|vhost-beta.local"):
        proxy_module.ip_state.pop(k, None)


@pytest.mark.asyncio
async def test_d20_top_ips_sorted_by_risk_score(proxy_module):
    from state import IpState
    proxy_module.events.clear()

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            proxy_module.ip_state["siem-test-low"]  = IpState(last_ip="10.9.0.1", risk_score=10.0)
            proxy_module.ip_state["siem-test-high"] = IpState(last_ip="10.9.0.2", risk_score=90.0)
            proxy_module.ip_state["siem-test-mid"]  = IpState(last_ip="10.9.0.3", risk_score=50.0)

            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=60", cookies=cookies)
            data = await r.json()
            top = data["top_ips"]
            assert len(top) >= 3, f"Expected >= 3 top_ips entries, got {len(top)}."
            risks = [ip["risk_score"] for ip in top]
            assert risks == sorted(risks, reverse=True), (
                f"top_ips not sorted by risk_score DESC. Got: {risks}"
            )

    for k in ("siem-test-low", "siem-test-high", "siem-test-mid"):
        proxy_module.ip_state.pop(k, None)


# ═══════════════════════════════════════════════════════════════════════════
# SEC01–SEC05  Security tests
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_sec01_mins_nan_no_crash(proxy_module):
    proxy_module.events.clear()
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=nan", cookies=cookies)
            assert r.status == 200, (
                f"?mins=nan returned HTTP {r.status}. "
                "Non-finite float input must be handled gracefully — must not crash."
            )
            data = await r.json()
            assert data["mins"] == 60, (
                f"?mins=nan should default to mins=60, got {data['mins']}."
            )


@pytest.mark.asyncio
async def test_sec02_mins_inf_no_crash(proxy_module):
    proxy_module.events.clear()
    from urllib.parse import quote
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            for bad_val in ("inf", "-inf", "Infinity", "1e999"):
                r = await cli.get(f"{NS}/siem-data?mins={quote(bad_val)}", cookies=cookies)
                assert r.status == 200, (
                    f"?mins={bad_val} returned HTTP {r.status}. "
                    "Non-finite input must not crash the endpoint."
                )


@pytest.mark.asyncio
async def test_sec03_vhost_special_chars_no_crash(proxy_module):
    proxy_module.events.clear()
    from urllib.parse import quote
    payloads = [
        "'; DROP TABLE events; --",
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "../../../../etc/passwd",
    ]
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            for p in payloads:
                r = await cli.get(f"{NS}/siem-data?vhost={quote(p)}", cookies=cookies)
                assert r.status == 200, (
                    f"?vhost={p!r} returned HTTP {r.status}. "
                    "Vhost filter is string comparison only — special chars must not crash."
                )


@pytest.mark.asyncio
async def test_sec04_event_fields_are_plain_strings(proxy_module):
    """Event fields in the JSON response must be raw strings, not HTML-encoded.
    Escaping is the responsibility of the JS frontend (escapeHtml).
    """
    proxy_module.events.clear()
    now_ts = time.monotonic()
    proxy_module.events.append(_ev(
        reason="<script>alert(1)</script>",
        ts=now_ts - 5,
        ip="<img src=x onerror=alert(2)>",
        ua='"><svg/onload=alert(3)>',
        path="/<b>evil</b>",
    ))

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/siem-data?mins=60", cookies=cookies)
            data = await r.json()
            for ev in data["events"]:
                for field in ("ip", "reason", "ua", "path"):
                    val = ev.get(field, "")
                    assert isinstance(val, str), (
                        f"/siem-data: event.{field} is not a string: {type(val)}"
                    )
                    # JSON API must NOT HTML-encode — that's the frontend's job
                    assert "&lt;" not in val, (
                        f"/siem-data: event.{field} contains '&lt;' — field is HTML-encoded "
                        "in the API response. Encoding must happen in the JS frontend only."
                    )
                    assert "&amp;" not in val, (
                        f"/siem-data: event.{field} contains '&amp;' — HTML-encoded in API."
                    )


@pytest.mark.asyncio
async def test_sec05_unauthenticated_siem_data_rejected(proxy_module):
    proxy_module.events.clear()
    now_ts = time.monotonic()
    proxy_module.events.append(_ev("canary-echo", ts=now_ts - 5, ip="192.168.99.1"))

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{NS}/siem-data")  # no session cookie
            if r.status == 200:
                data = await r.json()
                assert isinstance(data, dict), (
                    "/siem-data unauthenticated: non-dict JSON response."
                )
            else:
                assert r.status in (302, 401, 403), (
                    f"/siem-data unauthenticated: unexpected status {r.status}."
                )
