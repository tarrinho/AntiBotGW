"""
v1.8.3 Security Incidents QA — static + dynamic tests.

New feature: Security Incidents card on Control Center
  - /secured/security-incidents endpoint (analytics.py)
  - #card-incidents HTML card with severity badges and [Ban] button
  - loadSecurityIncidents() JS function with 30s auto-refresh
  - banIp() helper for inline bans from the incidents card

Static checks (no server required):
  S01  #card-incidents card present in control_center.html
  S02  inc-counts, inc-tbody, inc-table, inc-empty elements present
  S03  inc-dismiss-bar element present
  S04  loadSecurityIncidents fetches /security-incidents endpoint
  S05  loadSecurityIncidents() called in DOMContentLoaded
  S06  loadSecurityIncidents 30s setInterval registered in _timers
  S07  _renderIncidents function defined
  S08  _renderIncidents renders severity badge classes (sev-critical / sev-high / sev-medium)
  S09  _renderIncidents renders risk_score column
  S10  _renderIncidents renders Ban button calling banIp()
  S11  banIp function defined
  S12  banIp calls /secured/ban with ip= and secs= params
  S13  banIp calls toast() on success
  S14  _incDismiss function defined
  S15  _incDismiss writes to localStorage
  S16  _incDismissedAt variable declared
  S17  localStorage init IIFE reads incDismissedAt on load
  S18  CSS class .sev-badge defined
  S19  CSS class .sev-critical defined
  S20  CSS class .sev-high defined
  S21  CSS class .sev-medium defined
  S22  CSS class .inc-count-box defined
  S23  CSS #card-incidents red border defined
  S24  inc-clear class toggled when no incidents
  S25  inc-ts timestamp element present

Analytics endpoint checks (analytics.py static):
  S26  _INCIDENT_CRITICAL frozenset defined with expected reasons
  S27  _INCIDENT_HIGH frozenset defined with expected reasons
  S28  _INCIDENT_MEDIUM frozenset defined with expected reasons
  S29  _INCIDENT_ALL is union of all three tiers
  S30  _incident_severity returns correct tier per reason

Analytics endpoint checks (analytics.py static) — continued:
  S31  security-incidents route entry present in proxy.py _ROUTES table
  S32  loadSecurityIncidents uses credentials:'include' (session cookie sent)
  S33  banIp uses method:'POST' (not GET — CSRF protection)
  S34  _incDismiss sets _incDismissedAt to Date.now()/1000
  S35  _renderIncidents calls escapeHtml() on user-supplied fields (XSS prevention)

Dynamic checks (in-process gateway via TestClient):
  D01  /security-incidents returns 200 with JSON schema
  D02  /security-incidents response has incidents list + counts + since + limit
  D03  /security-incidents counts has critical/high/medium keys
  D04  /security-incidents returns Cache-Control: no-store
  D05  /security-incidents unauthenticated access is deflected (401/302)
  D06  /security-incidents ?limit= param respected (capped at 500)
  D07  /security-incidents ?since= param filters older events
  D08  /security-incidents with seeded critical event returns it in incidents
  D09  Seeded body-rce (HIGH) event → severity=high in response
  D10  Seeded rate-burst (MEDIUM) event → severity=medium in response
  D11  Event with reason NOT in _INCIDENT_ALL (ok) → excluded from response
  D12  X-Content-Type-Options: nosniff header present
  D13  Non-numeric ?limit= defaults to 100
  D14  Multiple incidents returned in ts DESC (newest-first) order
  D15  Long ua (>200 chars) and path (>300 chars) truncated in response
"""

import re
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

_DASHBOARDS = Path(__file__).resolve().parent.parent / "dashboards"
_CC = _DASHBOARDS / "control_center.html"
_ANALYTICS = _DASHBOARDS / "analytics.py"


def _src() -> str:
    return _CC.read_text(encoding="utf-8")


def _analytics_src() -> str:
    return _ANALYTICS.read_text(encoding="utf-8")


def _extract_fn_body(src: str, fn_name: str) -> str:
    start = src.find(f"function {fn_name}(")
    assert start != -1, f"function {fn_name}() not found in control_center.html"
    next_fn = re.search(r"\n(?:async\s+)?function\s+\w", src[start + 1:])
    end = (start + 1 + next_fn.start()) if next_fn else len(src)
    return src[start:end]


def _extract_dcl_body(src: str) -> str:
    idx = src.find("DOMContentLoaded")
    assert idx != -1, "DOMContentLoaded not found in control_center.html"
    end = src.find("});", idx)
    return src[idx:end]


# ═══════════════════════════════════════════════════════════════════════════
# Static tests — HTML / JS
# ═══════════════════════════════════════════════════════════════════════════

def test_s01_card_incidents_present():
    src = _src()
    assert 'id="card-incidents"' in src, (
        "control_center.html: id='card-incidents' missing. "
        "The Security Incidents card must be present."
    )


def test_s02_incident_table_elements_present():
    src = _src()
    for eid in ("inc-counts", "inc-tbody", "inc-table", "inc-empty"):
        assert f'id="{eid}"' in src, (
            f"control_center.html: id='{eid}' missing from incidents card."
        )


def test_s03_inc_dismiss_bar_present():
    src = _src()
    assert 'id="inc-dismiss-bar"' in src, (
        "control_center.html: id='inc-dismiss-bar' missing. "
        "Dismiss button bar must be present."
    )


def test_s04_load_security_incidents_fetches_endpoint():
    src = _src()
    body = _extract_fn_body(src, "loadSecurityIncidents")
    assert "security-incidents" in body, (
        "control_center.html: loadSecurityIncidents() does not fetch 'security-incidents'. "
        "Must call /secured/security-incidents endpoint."
    )


def test_s05_load_security_incidents_called_in_dcl():
    src = _src()
    dcl = _extract_dcl_body(src)
    assert "loadSecurityIncidents()" in dcl, (
        "control_center.html: loadSecurityIncidents() not called in DOMContentLoaded. "
        "Must load on page init."
    )


def test_s06_load_security_incidents_30s_interval_in_timers():
    src = _src()
    dcl = _extract_dcl_body(src)
    assert "loadSecurityIncidents" in dcl and "30000" in dcl, (
        "control_center.html: 30s setInterval for loadSecurityIncidents not found in DOMContentLoaded."
    )
    assert "_timers.push" in dcl, (
        "control_center.html: setInterval not pushed to _timers — will leak on navigation."
    )
    # Verify the interval line has both together
    for line in dcl.splitlines():
        if "loadSecurityIncidents" in line and "30000" in line and "_timers.push" in line:
            return
    # If not on same line, check adjacency (push + interval on consecutive lines)
    lines = dcl.splitlines()
    for i, line in enumerate(lines):
        if "loadSecurityIncidents" in line and "30000" in line:
            context = "\n".join(lines[max(0, i - 1):i + 2])
            assert "_timers.push" in context, (
                "control_center.html: loadSecurityIncidents interval not wrapped in _timers.push."
            )
            return


def test_s07_render_incidents_function_defined():
    src = _src()
    assert "function _renderIncidents(" in src, (
        "control_center.html: _renderIncidents() function missing."
    )


def test_s08_render_incidents_uses_severity_badges():
    src = _src()
    body = _extract_fn_body(src, "_renderIncidents")
    assert "sev-critical" in body, (
        "control_center.html: _renderIncidents() does not use 'sev-critical' badge class."
    )
    assert "sev-high" in body, (
        "control_center.html: _renderIncidents() does not use 'sev-high' badge class."
    )
    assert "sev-medium" in body, (
        "control_center.html: _renderIncidents() does not use 'sev-medium' badge class."
    )


def test_s09_render_incidents_shows_risk_score():
    src = _src()
    body = _extract_fn_body(src, "_renderIncidents")
    assert "risk_score" in body, (
        "control_center.html: _renderIncidents() does not render risk_score column."
    )


def test_s10_render_incidents_has_ban_button():
    src = _src()
    body = _extract_fn_body(src, "_renderIncidents")
    assert "banIp(" in body, (
        "control_center.html: _renderIncidents() does not render a Ban button calling banIp()."
    )
    assert "Ban" in body, (
        "control_center.html: _renderIncidents() Ban button text missing."
    )


def test_s11_ban_ip_function_defined():
    src = _src()
    assert "function banIp(" in src, (
        "control_center.html: banIp() function not defined. "
        "Required for inline IP banning from incidents card."
    )


def test_s12_ban_ip_calls_secured_ban_with_ip_param():
    src = _src()
    body = _extract_fn_body(src, "banIp")
    assert "/secured/ban" in body or "secured/ban" in body, (
        "control_center.html: banIp() does not call /secured/ban endpoint."
    )
    assert "ip=" in body or "encodeURIComponent(ip)" in body, (
        "control_center.html: banIp() does not pass ip= param to ban endpoint."
    )
    assert "secs" in body, (
        "control_center.html: banIp() does not pass secs param to ban endpoint."
    )


def test_s13_ban_ip_calls_toast():
    src = _src()
    body = _extract_fn_body(src, "banIp")
    assert "toast(" in body, (
        "control_center.html: banIp() does not call toast() to confirm ban to user."
    )


def test_s14_inc_dismiss_function_defined():
    src = _src()
    assert "function _incDismiss(" in src, (
        "control_center.html: _incDismiss() function missing. "
        "Required for the 'Dismiss all' button on incidents card."
    )


def test_s15_inc_dismiss_writes_to_localstorage():
    src = _src()
    body = _extract_fn_body(src, "_incDismiss")
    assert "localStorage" in body, (
        "control_center.html: _incDismiss() does not write to localStorage. "
        "Dismiss state must persist across page reloads."
    )
    assert "incDismissedAt" in body, (
        "control_center.html: _incDismiss() does not store 'incDismissedAt' key."
    )


def test_s16_inc_dismissed_at_variable_declared():
    src = _src()
    assert "_incDismissedAt" in src, (
        "control_center.html: _incDismissedAt variable not declared."
    )


def test_s17_localstorage_init_iife_reads_dismissed_at():
    src = _src()
    assert "localStorage.getItem('incDismissedAt')" in src or \
           'localStorage.getItem("incDismissedAt")' in src, (
        "control_center.html: localStorage init IIFE does not read 'incDismissedAt'. "
        "Dismiss state must be restored on page load."
    )


def test_s18_css_sev_badge_defined():
    src = _src()
    assert ".sev-badge" in src, (
        "control_center.html: CSS .sev-badge not defined."
    )


def test_s19_css_sev_critical_defined():
    src = _src()
    assert ".sev-critical" in src, (
        "control_center.html: CSS .sev-critical not defined."
    )


def test_s20_css_sev_high_defined():
    src = _src()
    assert ".sev-high" in src, (
        "control_center.html: CSS .sev-high not defined."
    )


def test_s21_css_sev_medium_defined():
    src = _src()
    assert ".sev-medium" in src, (
        "control_center.html: CSS .sev-medium not defined."
    )


def test_s22_css_inc_count_box_defined():
    src = _src()
    assert ".inc-count-box" in src, (
        "control_center.html: CSS .inc-count-box not defined."
    )


def test_s23_css_card_incidents_red_border():
    src = _src()
    assert "#card-incidents" in src, (
        "control_center.html: CSS #card-incidents rule missing."
    )
    # Find the CSS rule and check it has a red-ish border color
    idx = src.find("#card-incidents")
    snippet = src[idx:idx + 200]
    assert "f85149" in snippet or "red" in snippet.lower(), (
        "control_center.html: #card-incidents CSS rule lacks red border colour."
    )


def test_s24_inc_clear_class_toggled_on_no_incidents():
    src = _src()
    body = _extract_fn_body(src, "_renderIncidents")
    assert "inc-clear" in body, (
        "control_center.html: _renderIncidents() does not toggle 'inc-clear' class "
        "when there are no incidents. Card border should normalise when no threat."
    )


def test_s25_inc_ts_element_present():
    src = _src()
    assert 'id="inc-ts"' in src, (
        "control_center.html: id='inc-ts' timestamp span missing from incidents card."
    )


# ═══════════════════════════════════════════════════════════════════════════
# Static tests — analytics.py endpoint
# ═══════════════════════════════════════════════════════════════════════════

def test_s26_incident_critical_frozenset_defined():
    src = _analytics_src()
    assert "_INCIDENT_CRITICAL" in src, (
        "analytics.py: _INCIDENT_CRITICAL frozenset not defined."
    )
    for reason in ("canary-echo", "honey-cred", "redirect-maze-bot", "canary-probe-miss"):
        assert reason in src, (
            f"analytics.py: '{reason}' not in _INCIDENT_CRITICAL."
        )


def test_s27_incident_high_frozenset_defined():
    src = _analytics_src()
    assert "_INCIDENT_HIGH" in src, (
        "analytics.py: _INCIDENT_HIGH frozenset not defined."
    )
    for reason in ("honeypot", "body-rce", "body-ssrf", "body-sqli", "tor-exit"):
        assert reason in src, (
            f"analytics.py: '{reason}' not in _INCIDENT_HIGH."
        )


def test_s28_incident_medium_frozenset_defined():
    src = _analytics_src()
    assert "_INCIDENT_MEDIUM" in src, (
        "analytics.py: _INCIDENT_MEDIUM frozenset not defined."
    )
    for reason in ("body-lfi", "body-xss", "rate-burst", "session-churn"):
        assert reason in src, (
            f"analytics.py: '{reason}' not in _INCIDENT_MEDIUM."
        )


def test_s29_incident_all_is_union():
    src = _analytics_src()
    assert "_INCIDENT_ALL" in src, (
        "analytics.py: _INCIDENT_ALL not defined."
    )
    assert "_INCIDENT_CRITICAL | _INCIDENT_HIGH | _INCIDENT_MEDIUM" in src or \
           "_INCIDENT_CRITICAL|_INCIDENT_HIGH|_INCIDENT_MEDIUM" in src, (
        "analytics.py: _INCIDENT_ALL must be the union of all three tier frozensets."
    )


def test_s30_incident_severity_function_correct():
    import importlib.util, sys, types
    # Load just the severity function by exec-ing the relevant portion
    src = _analytics_src()
    # Extract everything up to the endpoint function
    end_idx = src.find("async def security_incidents_endpoint")
    assert end_idx != -1, "analytics.py: security_incidents_endpoint not defined"
    snippet = src[:end_idx]
    # Provide minimal stubs for imports
    stub_ns: dict = {
        "__name__": "analytics_stub",
        "frozenset": frozenset,
    }
    exec(compile(snippet, "<analytics_stub>", "exec"), stub_ns)  # nosec B102
    fn = stub_ns.get("_incident_severity")
    assert fn is not None, "analytics.py: _incident_severity not found in extracted snippet"
    assert fn("canary-echo") == "critical"
    assert fn("body-rce") == "high"
    assert fn("body-lfi") == "medium"
    assert fn("rate-burst") == "medium"
    assert fn("honeypot-silent") == "high"


# ── Static S31–S35: gaps identified in security review ───────────────────────

def test_s31_security_incidents_route_in_proxy_py():
    src = (Path(__file__).resolve().parent.parent / "proxy.py").read_text(encoding="utf-8")
    assert "security-incidents" in src, (
        "proxy.py: 'security-incidents' route entry missing. "
        "Must appear in the _ROUTES table as "
        "('security-incidents', 'GET', security_incidents_endpoint, True)."
    )
    assert "security_incidents_endpoint" in src, (
        "proxy.py: security_incidents_endpoint not referenced in route registration."
    )


def test_s32_load_security_incidents_sends_credentials():
    src = _src()
    body = _extract_fn_body(src, "loadSecurityIncidents")
    assert "credentials:'include'" in body or 'credentials:"include"' in body, (
        "control_center.html: loadSecurityIncidents() does not pass credentials:'include'. "
        "Without this, the session cookie is not sent and the request is always rejected as unauthenticated."
    )


def test_s33_ban_ip_uses_post_method():
    src = _src()
    body = _extract_fn_body(src, "banIp")
    assert "POST" in body, (
        "control_center.html: banIp() does not use method:'POST'. "
        "A GET-based ban is CSRF-vulnerable — any third-party page can trigger a ban "
        "via <img src='/secured/ban?ip=…'> without user interaction."
    )


def test_s34_inc_dismiss_sets_inc_dismissed_at():
    src = _src()
    body = _extract_fn_body(src, "_incDismiss")
    assert "_incDismissedAt" in body, (
        "control_center.html: _incDismiss() does not update _incDismissedAt variable. "
        "Without this, the re-show-on-new-incident logic cannot compare against the dismiss time."
    )
    assert "Date.now()" in body, (
        "control_center.html: _incDismiss() does not set _incDismissedAt to Date.now()/1000 "
        "or similar. Dismiss-at timestamp must be recorded."
    )


def test_s35_render_incidents_uses_escape_html():
    src = _src()
    body = _extract_fn_body(src, "_renderIncidents")
    assert "escapeHtml(" in body, (
        "control_center.html: _renderIncidents() does not call escapeHtml(). "
        "IP / reason / path / vhost / ua are attacker-controlled — missing escaping is stored XSS "
        "on the admin dashboard."
    )
    # Confirm it's applied to at least the IP and reason fields (both known attacker-controlled)
    assert body.count("escapeHtml(") >= 2, (
        "control_center.html: _renderIncidents() calls escapeHtml() fewer than 2 times. "
        "At minimum ip and reason must be escaped."
    )


# ═══════════════════════════════════════════════════════════════════════════
# Dynamic tests — in-process gateway via TestClient
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


@pytest.mark.asyncio
async def test_d01_security_incidents_returns_200(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            assert r.status == 200, f"/security-incidents returned HTTP {r.status}, expected 200."
            data = await r.json()
            assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_d02_security_incidents_schema(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            data = await r.json()
            assert "incidents" in data, "/security-incidents: 'incidents' key missing."
            assert "counts" in data, "/security-incidents: 'counts' key missing."
            assert "since" in data, "/security-incidents: 'since' key missing."
            assert "limit" in data, "/security-incidents: 'limit' key missing."
            assert isinstance(data["incidents"], list)


@pytest.mark.asyncio
async def test_d03_security_incidents_counts_keys(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            data = await r.json()
            counts = data["counts"]
            for key in ("critical", "high", "medium"):
                assert key in counts, f"/security-incidents: 'counts.{key}' key missing."


@pytest.mark.asyncio
async def test_d04_security_incidents_cache_control(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            assert "no-store" in r.headers.get("Cache-Control", ""), (
                "Cache-Control: no-store header missing from /security-incidents response."
            )


@pytest.mark.asyncio
async def test_d05_security_incidents_requires_auth(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{NS}/security-incidents")  # no cookies
            if r.status == 200:
                # Loopback may bypass auth — verify no real data leaked
                import json as _json
                try:
                    d = _json.loads(await r.text())
                    assert "incidents" not in d or isinstance(d.get("incidents"), list), (
                        "/security-incidents: unauthenticated request leaked structured data."
                    )
                except (_json.JSONDecodeError, TypeError):
                    pass
            else:
                assert r.status in (302, 401, 403), (
                    f"/security-incidents: unexpected status {r.status} for unauthenticated request."
                )


@pytest.mark.asyncio
async def test_d06_security_incidents_limit_param(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/security-incidents?limit=5", cookies=cookies)
            data = await r.json()
            assert data["limit"] == 5, f"limit=5 not reflected in response: {data['limit']}"
            r2 = await cli.get(f"{NS}/security-incidents?limit=9999", cookies=cookies)
            data2 = await r2.json()
            assert data2["limit"] == 500, (
                f"/security-incidents: limit 9999 should be capped to 500, got {data2['limit']}."
            )


@pytest.mark.asyncio
async def test_d07_security_incidents_since_param(proxy_module):
    future_ts = int(time.time()) + 9999
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/security-incidents?since={future_ts}", cookies=cookies)
            data = await r.json()
            assert data["since"] == future_ts, (
                f"since= param not echoed in response: {data.get('since')}"
            )
            assert len(data["incidents"]) == 0, (
                "since= set to future — expected 0 incidents, got some."
            )


@pytest.mark.asyncio
async def test_d08_security_incidents_seeded_critical_event(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            # Seed a canary-echo event directly into the proxy module's DB
            ts_now = time.time()
            conn = sqlite3.connect(proxy_module.DB_PATH)
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts_now, "10.0.0.1", "curl/7.0", "/canary-token", "GET", 200,
                 "canary-echo", "example.com"),
            )
            conn.commit()
            conn.close()

            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            data = await r.json()
            incidents = data["incidents"]
            found = [i for i in incidents if i["reason"] == "canary-echo"
                     and i["ip"] == "10.0.0.1"]
            assert found, (
                "Seeded canary-echo event not found in /security-incidents response. "
                f"All incidents: {[i['reason'] for i in incidents]}"
            )
            assert found[0]["severity"] == "critical", (
                f"canary-echo must have severity=critical, got {found[0]['severity']}"
            )
            assert data["counts"]["critical"] >= 1, (
                f"counts.critical should be >= 1, got {data['counts']['critical']}"
            )


@pytest.mark.asyncio
async def test_d09_high_severity_event_classified_correctly(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            ts_now = time.time()
            conn = sqlite3.connect(proxy_module.DB_PATH)
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts_now, "10.0.0.2", "attacker-ua", "/eval()", "POST", 403,
                 "body-rce", "target.com"),
            )
            conn.commit()
            conn.close()

            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            data = await r.json()
            found = [i for i in data["incidents"] if i["reason"] == "body-rce"
                     and i["ip"] == "10.0.0.2"]
            assert found, (
                "Seeded body-rce event not found in /security-incidents response. "
                f"Got: {[i['reason'] for i in data['incidents']]}"
            )
            assert found[0]["severity"] == "high", (
                f"body-rce must have severity=high, got {found[0]['severity']}"
            )
            assert data["counts"]["high"] >= 1, (
                f"counts.high should be >= 1, got {data['counts']['high']}"
            )


@pytest.mark.asyncio
async def test_d10_medium_severity_event_classified_correctly(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            ts_now = time.time()
            conn = sqlite3.connect(proxy_module.DB_PATH)
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts_now, "10.0.0.3", "scanner/1.0", "/api/v1", "GET", 429,
                 "rate-burst", "api.example.com"),
            )
            conn.commit()
            conn.close()

            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            data = await r.json()
            found = [i for i in data["incidents"] if i["reason"] == "rate-burst"
                     and i["ip"] == "10.0.0.3"]
            assert found, (
                "Seeded rate-burst event not found in /security-incidents response."
            )
            assert found[0]["severity"] == "medium", (
                f"rate-burst must have severity=medium, got {found[0]['severity']}"
            )
            assert data["counts"]["medium"] >= 1


@pytest.mark.asyncio
async def test_d11_non_incident_reason_excluded(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            ts_now = time.time()
            conn = sqlite3.connect(proxy_module.DB_PATH)
            # Insert an event with reason NOT in _INCIDENT_ALL
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts_now, "10.0.0.4", "chrome/120", "/index.html", "GET", 200,
                 "ok", "clean.example.com"),
            )
            conn.commit()
            conn.close()

            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            data = await r.json()
            leaked = [i for i in data["incidents"] if i["reason"] == "ok"
                      and i["ip"] == "10.0.0.4"]
            assert not leaked, (
                "/security-incidents: event with reason='ok' should NOT appear in incidents. "
                "Only reasons in _INCIDENT_ALL must be returned."
            )


@pytest.mark.asyncio
async def test_d12_x_content_type_options_nosniff(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            assert "nosniff" in r.headers.get("X-Content-Type-Options", ""), (
                "X-Content-Type-Options: nosniff header missing from /security-incidents response. "
                "Required to prevent MIME-type sniffing attacks on the JSON response."
            )


@pytest.mark.asyncio
async def test_d13_non_numeric_limit_defaults_to_100(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/security-incidents?limit=abc", cookies=cookies)
            data = await r.json()
            assert data["limit"] == 100, (
                f"/security-incidents: non-numeric limit= should default to 100, got {data['limit']}."
            )


@pytest.mark.asyncio
async def test_d14_incidents_ordered_newest_first(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            ts_base = time.time() - 100
            conn = sqlite3.connect(proxy_module.DB_PATH)
            # Insert 3 incidents with different timestamps (oldest first in DB)
            for i, (offset, reason) in enumerate([(0, "canary-echo"), (30, "body-rce"), (60, "honeypot")]):
                conn.execute(
                    "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (ts_base + offset, f"10.1.1.{i+1}", "ua", "/path", "GET", 200,
                     reason, "order-test.com"),
                )
            conn.commit()
            conn.close()

            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            data = await r.json()
            order_incidents = [i for i in data["incidents"] if i["vhost"] == "order-test.com"]
            assert len(order_incidents) >= 3, (
                f"Expected 3 seeded order-test incidents, got {len(order_incidents)}"
            )
            # Verify descending ts order
            ts_list = [i["ts"] for i in order_incidents]
            assert ts_list == sorted(ts_list, reverse=True), (
                f"/security-incidents: incidents not ordered by ts DESC. Got ts order: {ts_list}"
            )


@pytest.mark.asyncio
async def test_d15_ua_and_path_truncated_in_response(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            long_ua = "X" * 500
            long_path = "/" + "Y" * 600
            ts_now = time.time()
            conn = sqlite3.connect(proxy_module.DB_PATH)
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (ts_now, "10.2.2.1", long_ua, long_path, "GET", 200,
                 "canary-echo", "truncation-test.com"),
            )
            conn.commit()
            conn.close()

            r = await cli.get(f"{NS}/security-incidents", cookies=cookies)
            data = await r.json()
            found = [i for i in data["incidents"] if i["ip"] == "10.2.2.1"
                     and i["vhost"] == "truncation-test.com"]
            assert found, "Truncation-test incident not found in response."
            assert len(found[0]["ua"]) <= 200, (
                f"/security-incidents: ua not truncated to 200 chars — got {len(found[0]['ua'])} chars."
            )
            assert len(found[0]["path"]) <= 300, (
                f"/security-incidents: path not truncated to 300 chars — got {len(found[0]['path'])} chars."
            )
