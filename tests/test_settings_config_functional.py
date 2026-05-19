"""
Functional tests — settings export/import + config endpoint (v1.7.11+).

Coverage:
  TestConfigGet            — GET /secured/config shape and completeness
  TestConfigPost           — POST /secured/config with correct {knob: value} format
  TestSettingsExportContent — exported ZIP/XML contains every live knob
  TestSettingsImportRoundTrip — full export → modify → import → verify rollback
  TestSettingsImportDryRun  — dry_run=1 counts but does not mutate state
  TestSettingsImportErrors  — bad ZIP, empty body, wrong XML entry name
  TestSettingsImportAdminIPs — admin_ips section round-trips correctly
  TestControlsDashboard    — controls page accessible and returns HTML

Pattern: in-process aiohttp TestServer (same as test_endpoints_dynamic.py) —
no Docker required, sessions primed via _make_admin_cookie().
"""
import asyncio
import io
import json
import zipfile
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager

import sqlite3

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clear_admin_nets_and_db(request):
    """Clear ADMIN_ALLOWED_NETS + ADMIN_ALLOWED_ENTRIES after every test so
    that a test adding an admin-IP CIDR doesn't block 127.0.0.1 for the next
    test (mirrors the identical fixture in test_endpoints_dynamic.py)."""
    yield
    import admin.auth as _auth
    _auth.ADMIN_ALLOWED_NETS.clear()
    _auth.ADMIN_ALLOWED_ENTRIES.clear()
    try:
        import proxy as _p
        db_path = getattr(_p, "DB_PATH", "")
        if db_path:
            conn = sqlite3.connect(db_path)
            conn.execute("DELETE FROM admin_ips")
            conn.commit()
            conn.close()
    except Exception:
        pass


# ── Helpers (mirrored from test_endpoints_dynamic.py) ────────────────────────

NS  = "/antibot-appsec-gateway/secured"
PUB = "/antibot-appsec-gateway"


async def _echo_handler(request: web.Request):
    return web.json_response({"path": request.path})


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
async def _spin_proxy(proxy_module, upstream_url):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


def _make_admin_cookie(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _csrf_hdr(proxy_module, cookie):
    """Return X-CSRF-Token header dict for CSRF-protected endpoints."""
    import hashlib, hmac as _hmac
    if isinstance(cookie, dict):
        cookie = next(iter(cookie.values()))
    sid = cookie.split("|")[1]
    token = _hmac.new(proxy_module.SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
    return {"X-CSRF-Token": token}

def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _make_zip(xml_text: str) -> bytes:
    """Pack XML string into a single-entry ZIP (mirrors the real export format)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("appsecgw-config.xml", xml_text.encode("utf-8"))
    return buf.getvalue()


def _make_config_xml(knobs: dict) -> str:
    """Build a minimal but valid appsecgw-config XML from a knob dict."""
    root = ET.Element("appsecgw-config", attrib={"version": "1.6.5", "exported_at": "0"})
    knobs_el = ET.SubElement(root, "knobs")
    for k, v in knobs.items():
        e = ET.SubElement(knobs_el, "knob", attrib={"name": k, "type": type(v).__name__})
        e.text = json.dumps(v, ensure_ascii=False)
    ET.SubElement(root, "admin_ips")
    ET.SubElement(root, "secrets")
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


# ── 1. TestConfigGet ─────────────────────────────────────────────────────────

class TestConfigGet:
    """GET /secured/config must return a JSON object with a 'state' key
    containing all hot-reloadable knob names and their current values."""

    def test_config_get_200_authenticated(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/config",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"expected 200, got {r.status}"
        _run(go())

    def test_config_get_has_state_key(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/config",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "state" in d, "response must contain 'state' key"
                    assert isinstance(d["state"], dict), "'state' must be a dict"
        _run(go())

    def test_config_get_contains_expected_knobs(self, proxy_module):
        """All knobs in _HOT_RELOAD_KNOBS must appear in the GET response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/config",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    state = (await r.json())["state"]
                    for knob in proxy_module._HOT_RELOAD_KNOBS:
                        assert knob in state, (
                            f"hot-reloadable knob {knob!r} missing from GET /config state"
                        )
        _run(go())

    def test_config_get_unauthenticated_decoy(self, proxy_module):
        """Unauthenticated GET must NOT leak real config data."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/config")
                    body = await r.text()
                    assert '"state"' not in body, (
                        "Unauthenticated /config must not return real state"
                    )
        _run(go())

    def test_config_get_content_type_json(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/config",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    ct = r.headers.get("Content-Type", "")
                    assert "application/json" in ct
        _run(go())


# ── 2. TestConfigPost ────────────────────────────────────────────────────────

class TestConfigPost:
    """POST /secured/config body must be a JSON object {knob_name: value}.
    NOT the 'key'/'value' wrapper form — that wrapper is rejected as
    'not-hot-reloadable' (confirmed during live dynamic check 2026-05-10)."""

    def test_config_post_correct_format_applies(self, proxy_module):
        """POST {"RISK_BAN_THRESHOLD": 75} must be applied and reflected in
        the returned state — the flat object format is the only valid format."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={"RISK_BAN_THRESHOLD": 75},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "RISK_BAN_THRESHOLD" in d.get("applied", {}), (
                        "RISK_BAN_THRESHOLD must appear in 'applied'"
                    )
                    assert d["state"]["RISK_BAN_THRESHOLD"] == 75, (
                        "state must reflect the new value after POST"
                    )
        _run(go())

    def test_config_post_wrong_format_rejected(self, proxy_module):
        """POST {'key': 'RISK_BAN_THRESHOLD', 'value': 75} must NOT apply
        the knob — 'key' and 'value' are not valid knob names."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={"key": "RISK_BAN_THRESHOLD", "value": 75},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    rejected = d.get("rejected", {})
                    assert "key" in rejected and "value" in rejected, (
                        "Wrapper-form keys 'key'/'value' must be rejected as "
                        "not-hot-reloadable — use flat {knob_name: value} format"
                    )
        _run(go())

    def test_config_post_multiple_knobs(self, proxy_module):
        """Multiple knobs in one POST body must all be applied atomically."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={
                                         "JS_CHALLENGE":        True,
                                         "RATE_LIMIT_BURST":    50,
                                         "HOSTILE_BAN_SECS":    3600,
                                     },
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    state = d["state"]
                    assert state["JS_CHALLENGE"]    is True
                    assert state["RATE_LIMIT_BURST"] == 50
                    assert state["HOSTILE_BAN_SECS"] == 3600
        _run(go())

    def test_config_post_unknown_knob_rejected(self, proxy_module):
        """A knob not in _HOT_RELOAD_KNOBS must land in 'rejected', not 'applied'."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={"NONEXISTENT_KNOB_XYZ": True},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "NONEXISTENT_KNOB_XYZ" in d.get("rejected", {}), (
                        "Unknown knob must appear in 'rejected'"
                    )
                    assert "NONEXISTENT_KNOB_XYZ" not in d.get("applied", {}), (
                        "Unknown knob must NOT appear in 'applied'"
                    )
        _run(go())

    def test_config_post_get_reflects_change(self, proxy_module):
        """After POST, a subsequent GET must return the updated value."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    await c.post(NS + "/config",
                                 json={"RATE_LIMIT_BURST": 99},
                                 headers=_csrf_hdr(proxy_module, cookie),
                                 cookies={proxy_module._SESSION_COOKIE: cookie})
                    r = await c.get(NS + "/config",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    state = (await r.json())["state"]
                    assert state["RATE_LIMIT_BURST"] == 99, (
                        "GET after POST must reflect the applied change"
                    )
        _run(go())

    def test_config_post_unauthenticated_decoy(self, proxy_module):
        """Unauthenticated POST must not apply changes."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.post(NS + "/config",
                                     json={"BYPASS_MODE": True})
                    body = await r.text()
                    assert '"applied"' not in body, (
                        "Unauthenticated POST must not return applied knobs"
                    )
        _run(go())


# ── 3. TestSettingsExportContent ─────────────────────────────────────────────

class TestSettingsExportContent:
    """The exported ZIP must contain a valid appsecgw-config.xml that
    faithfully captures the live hot-reload state."""

    def _export_and_parse(self, proxy_module):
        """Export, unzip, parse XML; return (root_element, knobs_dict)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings-export",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return await r.read()
        raw = _run(go())
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            xml_bytes = zf.read("appsecgw-config.xml")
        root = ET.fromstring(xml_bytes)
        knobs = {e.attrib["name"]: json.loads(e.text or "null")
                 for e in root.find("knobs").findall("knob")}
        return root, knobs

    def test_export_zip_magic_bytes(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings-export",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.read()
                    assert body[:2] == b"PK", "Response must be a ZIP (PK magic bytes)"
        _run(go())

    def test_export_contains_xml_entry(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings-export",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.read()
                    with zipfile.ZipFile(io.BytesIO(body)) as zf:
                        assert "appsecgw-config.xml" in zf.namelist(), (
                            "ZIP must contain 'appsecgw-config.xml'"
                        )
        _run(go())

    def test_export_xml_root_tag(self, proxy_module):
        root, _ = self._export_and_parse(proxy_module)
        assert root.tag == "appsecgw-config", (
            f"XML root tag must be 'appsecgw-config', got {root.tag!r}"
        )

    def test_export_xml_has_knobs_section(self, proxy_module):
        root, _ = self._export_and_parse(proxy_module)
        assert root.find("knobs") is not None

    def test_export_xml_has_admin_ips_section(self, proxy_module):
        root, _ = self._export_and_parse(proxy_module)
        assert root.find("admin_ips") is not None

    def test_export_xml_has_secrets_section(self, proxy_module):
        root, _ = self._export_and_parse(proxy_module)
        assert root.find("secrets") is not None

    def test_export_knobs_count_matches_hot_reload_knobs(self, proxy_module):
        """Exported XML must have one <knob> entry per hot-reloadable knob."""
        _, knobs = self._export_and_parse(proxy_module)
        expected = set(proxy_module._HOT_RELOAD_KNOBS.keys())
        exported = set(knobs.keys())
        missing = expected - exported
        extra   = exported - expected
        assert not missing, f"Knobs missing from export: {missing}"
        assert not extra,   f"Unknown knobs in export: {extra}"

    def test_export_knob_values_match_live_state(self, proxy_module):
        """Each exported knob value must equal the live GET /config state."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    # Snapshot live state
                    r_cfg = await c.get(NS + "/config",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                    live_state = (await r_cfg.json())["state"]
                    # Export
                    r_exp = await c.get(NS + "/settings-export",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                    raw = await r_exp.read()
            return live_state, raw
        live_state, raw = _run(go())
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            xml_bytes = zf.read("appsecgw-config.xml")
        root = ET.fromstring(xml_bytes)
        for e in root.find("knobs").findall("knob"):
            name = e.attrib["name"]
            exported_val = json.loads(e.text or "null")
            live_val = live_state.get(name)
            # Sets are exported as sorted lists; normalise for comparison.
            if isinstance(live_val, list):
                live_val_cmp = sorted(live_val,    key=str) if live_val    else live_val
                exported_cmp = sorted(exported_val, key=str) if exported_val else exported_val
                assert live_val_cmp == exported_cmp, (
                    f"Knob {name!r} value mismatch: live={live_val!r} exported={exported_val!r}"
                )
            else:
                assert exported_val == live_val, (
                    f"Knob {name!r} value mismatch: live={live_val!r} exported={exported_val!r}"
                )

    def test_export_content_disposition_filename(self, proxy_module):
        """Response must include Content-Disposition attachment header."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings-export",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    cd = r.headers.get("Content-Disposition", "")
                    assert "attachment" in cd, (
                        "Export must set Content-Disposition: attachment"
                    )
                    assert ".zip" in cd, (
                        "Content-Disposition filename must end with .zip"
                    )
        _run(go())

    def test_export_no_cache_control(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings-export",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert "no-store" in r.headers.get("Cache-Control", "")
        _run(go())


# ── 4. TestSettingsImportRoundTrip ───────────────────────────────────────────

class TestSettingsImportRoundTrip:
    """Full cycle: export current state → modify knobs via POST /config →
    import original ZIP → verify GET /config shows original values."""

    def test_roundtrip_four_knobs(self, proxy_module):
        """After import, all 4 modified knobs must revert to exported values."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}

                    # Step 1 — snapshot original values
                    orig = (await (await c.get(NS + "/config", cookies=ck)).json())["state"]

                    # Step 2 — export
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()

                    # Step 3 — modify 4 knobs (flat {name: value} format)
                    changes = {
                        "JS_CHALLENGE":      True,
                        "RISK_BAN_THRESHOLD": orig["RISK_BAN_THRESHOLD"] + 25,
                        "RATE_LIMIT_BURST":  orig["RATE_LIMIT_BURST"]  + 30,
                        "HOSTILE_BAN_SECS":  3600,
                    }
                    _csrf = _csrf_hdr(proxy_module, cookie)
                    mod_r = await c.post(NS + "/config", json=changes, headers=_csrf, cookies=ck)
                    mod_d = await mod_r.json()
                    for k in changes:
                        assert k in mod_d.get("applied", {}), f"{k} not applied"

                    # Step 4 — import original ZIP
                    imp_r = await c.post(
                        NS + "/settings-import?dry_run=0&overwrite_secrets=0",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream", **_csrf},
                        cookies=ck,
                    )
                    assert imp_r.status == 200
                    imp_d = await imp_r.json()
                    # Some knobs (e.g. LOCALE_GEO_CHECK_ENABLED, IMPOSSIBLE_TRAVEL_ENABLED)
                    # require the MaxMind City DB to be loaded when the value is True —
                    # they are legitimately rejected in test environments without the DB.
                    # Assert only that our 4 explicitly-modified knobs were not rejected.
                    rejected_keys = set(imp_d.get("rejected", {}).keys())
                    for k in changes:
                        assert k not in rejected_keys, (
                            f"Modified knob {k!r} was unexpectedly rejected: "
                            f"{imp_d['rejected'].get(k)}"
                        )
                    assert imp_d["errors"] == [], (
                        f"Import errors: {imp_d['errors']}"
                    )

                    # Step 5 — verify state matches original
                    after = (await (await c.get(NS + "/config", cookies=ck)).json())["state"]
                    for k in changes:
                        assert after[k] == orig[k], (
                            f"Knob {k!r} not restored: expected {orig[k]!r}, got {after[k]!r}"
                        )
        _run(go())

    def test_roundtrip_all_knobs_applied(self, proxy_module):
        """Import of a fresh export must report knobs_applied == len(_HOT_RELOAD_KNOBS)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    imp_r = await c.post(
                        NS + "/settings-import",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    imp_d = await imp_r.json()
                    expected = len(proxy_module._HOT_RELOAD_KNOBS)
                    total = imp_d["knobs_applied"] + imp_d["knobs_rejected"]
                    assert total == expected, (
                        f"Expected {expected} knobs processed, "
                        f"got applied={imp_d['knobs_applied']} rejected={imp_d['knobs_rejected']}"
                    )
                    assert imp_d["errors"] == []
        _run(go())

    def test_roundtrip_import_returns_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    r = await c.post(
                        NS + "/settings-import",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    assert r.status == 200
        _run(go())

    def test_roundtrip_import_json_summary_keys(self, proxy_module):
        """Import response must contain the documented summary keys."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    r = await c.post(
                        NS + "/settings-import",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    d = await r.json()
                    for key in ("knobs_applied", "knobs_rejected",
                                "admin_ips_added", "secrets_applied", "errors"):
                        assert key in d, f"Import summary missing key {key!r}"
        _run(go())


# ── 5. TestSettingsImportDryRun ──────────────────────────────────────────────

class TestSettingsImportDryRun:
    """dry_run=1: summary counts must reflect what would be applied, but the
    live state must remain unchanged after the call."""

    def test_dryrun_reports_knobs_but_does_not_apply(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}

                    # Capture state before
                    before = (await (await c.get(NS + "/config", cookies=ck)).json())["state"]

                    # Build a ZIP with RATE_LIMIT_BURST=999 (different from default)
                    xml = _make_config_xml({"RATE_LIMIT_BURST": 999})
                    raw_zip = _make_zip(xml)

                    r = await c.post(
                        NS + "/settings-import?dry_run=1",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    imp_d = await r.json()

                    # After dry_run, state must be unchanged
                    after = (await (await c.get(NS + "/config", cookies=ck)).json())["state"]

                    return imp_d, before, after
        imp_d, before, after = _run(go())

        assert imp_d["dry_run"] is True, "dry_run flag must be True in response"
        assert imp_d["knobs_applied"] == 1, "dry_run must count RATE_LIMIT_BURST as would-apply"
        assert after["RATE_LIMIT_BURST"] == before["RATE_LIMIT_BURST"], (
            f"dry_run must NOT mutate RATE_LIMIT_BURST: "
            f"was {before['RATE_LIMIT_BURST']}, is now {after['RATE_LIMIT_BURST']}"
        )

    def test_dryrun_flag_present_in_response(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    r = await c.post(
                        NS + "/settings-import?dry_run=1",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    d = await r.json()
                    assert d["dry_run"] is True
        _run(go())

    def test_dryrun_zero_errors_on_valid_zip(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    r = await c.post(
                        NS + "/settings-import?dry_run=1",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    d = await r.json()
                    assert d["errors"] == [], f"No errors expected on valid zip, got: {d['errors']}"
        _run(go())


# ── 6. TestSettingsImportErrors ──────────────────────────────────────────────

class TestSettingsImportErrors:
    """Import must reject invalid inputs with HTTP 400 and a descriptive error."""

    def test_empty_body_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(
                        NS + "/settings-import",
                        data=b"",
                        headers={"Content-Type": "application/octet-stream"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 400
                    d = await r.json()
                    assert "error" in d
        _run(go())

    def test_non_zip_body_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(
                        NS + "/settings-import",
                        data=b"this is not a zip file",
                        headers={"Content-Type": "application/octet-stream"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 400
                    d = await r.json()
                    assert "zip" in d.get("error", "").lower() or "bad" in d.get("error", "").lower()
        _run(go())

    def test_zip_missing_xml_entry_rejected(self, proxy_module):
        """A ZIP that doesn't contain 'appsecgw-config.xml' must return 400."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    buf = io.BytesIO()
                    with zipfile.ZipFile(buf, "w") as zf:
                        zf.writestr("wrong-name.xml", b"<x/>")
                    r = await c.post(
                        NS + "/settings-import",
                        data=buf.getvalue(),
                        headers={"Content-Type": "application/octet-stream"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 400
                    d = await r.json()
                    assert "appsecgw-config.xml" in d.get("error", ""), (
                        "Error message must name the missing XML entry"
                    )
        _run(go())

    def test_zip_with_bad_xml_rejected(self, proxy_module):
        """A ZIP whose XML is malformed must return 400."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    raw_zip = _make_zip("<<< NOT VALID XML >>>")
                    r = await c.post(
                        NS + "/settings-import",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 400
                    d = await r.json()
                    assert "xml" in d.get("error", "").lower()
        _run(go())

    def test_zip_with_wrong_root_tag_rejected(self, proxy_module):
        """XML with a root tag other than <appsecgw-config> must return 400."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    raw_zip = _make_zip("<completely-wrong-root/>")
                    r = await c.post(
                        NS + "/settings-import",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 400
                    d = await r.json()
                    assert "error" in d
        _run(go())

    def test_unauthenticated_import_decoy(self, proxy_module):
        """Unauthenticated POST to settings-import must not return import summary."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    raw_zip = _make_zip(
                        '<appsecgw-config version="1.6.5" exported_at="0">'
                        '<knobs/><admin_ips/><secrets/>'
                        "</appsecgw-config>"
                    )
                    r = await c.post(
                        NS + "/settings-import",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                    )
                    body = await r.text()
                    assert '"knobs_applied"' not in body, (
                        "Unauthenticated import must not return import summary"
                    )
        _run(go())


# ── 7. TestSettingsImportAdminIPs ─────────────────────────────────────────────

class TestSettingsImportAdminIPs:
    """admin_ips section in the export XML must round-trip through import."""

    def test_admin_ips_added_on_import(self, proxy_module):
        """A ZIP containing a manual admin_ip entry must add it via import."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}

                    xml = (
                        '<appsecgw-config version="1.6.5" exported_at="0">'
                        '<knobs/>'
                        '<admin_ips>'
                        '  <admin_ip cidr="203.0.113.0/24" note="test" source="manual" '
                        '    description="test range" added_ts="0"/>'
                        '</admin_ips>'
                        '<secrets/>'
                        '</appsecgw-config>'
                    )
                    raw_zip = _make_zip(xml)
                    r = await c.post(
                        NS + "/settings-import",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    d = await r.json()
                    assert d["admin_ips_added"] == 1, (
                        f"Expected 1 admin IP added, got {d['admin_ips_added']}"
                    )
                    assert d["errors"] == []
        _run(go())

        # Verify in-memory state directly — a second HTTP GET would be blocked by the
        # newly-added CIDR (203.0.113.0/24 excludes 127.0.0.1 the test client address).
        import admin.auth as _auth
        cidrs = [e.get("cidr") for e in _auth.ADMIN_ALLOWED_ENTRIES]
        assert "203.0.113.0/24" in cidrs, (
            "Imported admin IP must be present in ADMIN_ALLOWED_ENTRIES"
        )

    def test_invalid_admin_ip_lands_in_errors(self, proxy_module):
        """A malformed CIDR in admin_ips must land in errors[], not crash."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    xml = (
                        '<appsecgw-config version="1.6.5" exported_at="0">'
                        '<knobs/>'
                        '<admin_ips>'
                        '  <admin_ip cidr="not-a-cidr" note="" source="manual" '
                        '    description="" added_ts="0"/>'
                        '</admin_ips>'
                        '<secrets/>'
                        '</appsecgw-config>'
                    )
                    raw_zip = _make_zip(xml)
                    r = await c.post(
                        NS + "/settings-import",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    assert r.status == 200  # must not 500
                    d = await r.json()
                    assert len(d["errors"]) >= 1, "Invalid CIDR must produce an error entry"
        _run(go())

    def test_env_sourced_ips_not_exported(self, proxy_module):
        """Admin IPs with source='env' must NOT appear in the export XML."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
                        xml_bytes = zf.read("appsecgw-config.xml")
                    root = ET.fromstring(xml_bytes)
                    for ie in root.find("admin_ips").findall("admin_ip"):
                        assert ie.attrib.get("source") != "env", (
                            "Env-derived admin IPs must be excluded from export"
                        )
        _run(go())


# ── 9. TestSettingsImportEnvPinned ───────────────────────────────────────────

class TestSettingsImportEnvPinned:
    """Import must reject knobs that are env-pinned (_ENV_PROVIDED_KNOBS).
    Findings from live dynamic test 2026-05-10: 10 env-pinned knobs rejected,
    114 applied, 0 errors — total processed = 124 = len(_HOT_RELOAD_KNOBS).
    The handler reads _ENV_PROVIDED_KNOBS from core.proxy_handler globals at
    call time, so tests modify that module directly and restore in finally."""

    @staticmethod
    def _add_pin(*knobs):
        import core.proxy_handler as _ph
        old = _ph._ENV_PROVIDED_KNOBS
        _ph._ENV_PROVIDED_KNOBS = frozenset(old | set(knobs))
        return old

    @staticmethod
    def _restore_pin(old):
        import core.proxy_handler as _ph
        _ph._ENV_PROVIDED_KNOBS = old

    def test_env_pinned_knob_rejected_on_import(self, proxy_module):
        """A knob in _ENV_PROVIDED_KNOBS must be rejected with reason containing
        'env-pinned' when the import ZIP contains it — even with a valid value."""
        old = self._add_pin("RATE_LIMIT_BURST")
        try:
            async def go():
                async with _spin_upstream() as up:
                    async with _spin_proxy(proxy_module, up) as c:
                        cookie = _make_admin_cookie(proxy_module)
                        ck = {proxy_module._SESSION_COOKIE: cookie}
                        raw_zip = _make_zip(_make_config_xml({"RATE_LIMIT_BURST": 99}))
                        r = await c.post(
                            NS + "/settings-import",
                            data=raw_zip,
                            headers={"Content-Type": "application/octet-stream"},
                            cookies=ck,
                        )
                        return await r.json()
            d = _run(go())
        finally:
            self._restore_pin(old)
        rejected = d.get("rejected", {})
        assert "RATE_LIMIT_BURST" in rejected, "Env-pinned knob must appear in 'rejected'"
        assert "env-pinned" in rejected["RATE_LIMIT_BURST"].lower(), (
            f"Rejection reason must contain 'env-pinned', got: {rejected['RATE_LIMIT_BURST']!r}"
        )

    def test_env_pinned_knob_not_in_applied(self, proxy_module):
        """An env-pinned knob must NOT appear in 'applied'."""
        old = self._add_pin("RATE_LIMIT_BURST")
        try:
            async def go():
                async with _spin_upstream() as up:
                    async with _spin_proxy(proxy_module, up) as c:
                        cookie = _make_admin_cookie(proxy_module)
                        ck = {proxy_module._SESSION_COOKIE: cookie}
                        raw_zip = _make_zip(_make_config_xml({"RATE_LIMIT_BURST": 99}))
                        r = await c.post(
                            NS + "/settings-import",
                            data=raw_zip,
                            headers={"Content-Type": "application/octet-stream"},
                            cookies=ck,
                        )
                        return await r.json()
            d = _run(go())
        finally:
            self._restore_pin(old)
        assert "RATE_LIMIT_BURST" not in d.get("applied", {}), (
            "Env-pinned knob must NOT appear in 'applied'"
        )

    def test_env_pinned_knob_live_value_unchanged(self, proxy_module):
        """Importing a different value for an env-pinned knob must leave the
        live state unchanged — the env pin takes precedence over import."""
        old = self._add_pin("HOSTILE_BAN_SECS")
        try:
            async def go():
                async with _spin_upstream() as up:
                    async with _spin_proxy(proxy_module, up) as c:
                        cookie = _make_admin_cookie(proxy_module)
                        ck = {proxy_module._SESSION_COOKIE: cookie}
                        original = (
                            await (await c.get(NS + "/config", cookies=ck)).json()
                        )["state"]["HOSTILE_BAN_SECS"]
                        raw_zip = _make_zip(
                            _make_config_xml({"HOSTILE_BAN_SECS": original + 9999})
                        )
                        await c.post(
                            NS + "/settings-import",
                            data=raw_zip,
                            headers={"Content-Type": "application/octet-stream"},
                            cookies=ck,
                        )
                        after = (
                            await (await c.get(NS + "/config", cookies=ck)).json()
                        )["state"]["HOSTILE_BAN_SECS"]
                        return original, after
            original, after = _run(go())
        finally:
            self._restore_pin(old)
        assert after == original, (
            f"Env-pinned knob must not be mutated by import: was {original}, now {after}"
        )

    def test_env_pin_exclude_knobs_never_pinned(self, proxy_module):
        """JS_CHALLENGE, TURNSTILE_ENABLED, UPSTREAM are in _ENV_PIN_EXCLUDE —
        they must never appear in _ENV_PROVIDED_KNOBS regardless of env state."""
        import core.proxy_handler as _ph
        for k in _ph._ENV_PIN_EXCLUDE:
            assert k not in _ph._ENV_PROVIDED_KNOBS, (
                f"{k!r} is in _ENV_PIN_EXCLUDE but also in _ENV_PROVIDED_KNOBS — "
                "excluded knobs must not be env-pinnable"
            )

    def test_import_total_processed_equals_all_knobs(self, proxy_module):
        """applied + rejected must equal len(_HOT_RELOAD_KNOBS) for a full-export
        import. Live dynamic test 2026-05-10: 114 applied + 10 env-pinned = 124."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    r = await c.post(
                        NS + "/settings-import",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    return await r.json()
        d = _run(go())
        total = d["knobs_applied"] + d["knobs_rejected"]
        expected = len(proxy_module._HOT_RELOAD_KNOBS)
        assert total == expected, (
            f"applied({d['knobs_applied']}) + rejected({d['knobs_rejected']}) = {total}, "
            f"expected {expected} total hot-reload knobs"
        )

    def test_multiple_env_pinned_all_rejected(self, proxy_module):
        """When multiple knobs are env-pinned, every one must appear in rejected."""
        pinned = {"RATE_LIMIT_BURST", "HOSTILE_BAN_SECS", "CANARY_TTL_S"}
        old = self._add_pin(*pinned)
        try:
            async def go():
                async with _spin_upstream() as up:
                    async with _spin_proxy(proxy_module, up) as c:
                        cookie = _make_admin_cookie(proxy_module)
                        ck = {proxy_module._SESSION_COOKIE: cookie}
                        xml = _make_config_xml({
                            "RATE_LIMIT_BURST": 200,
                            "HOSTILE_BAN_SECS": 7200,
                            "CANARY_TTL_S": 600,
                        })
                        r = await c.post(
                            NS + "/settings-import",
                            data=_make_zip(xml),
                            headers={"Content-Type": "application/octet-stream"},
                            cookies=ck,
                        )
                        return await r.json()
            d = _run(go())
        finally:
            self._restore_pin(old)
        rejected = set(d.get("rejected", {}).keys())
        assert pinned.issubset(rejected), (
            f"All env-pinned knobs must be rejected. Missing: {pinned - rejected}"
        )


# ── 8. TestControlsDashboard ─────────────────────────────────────────────────

class TestControlsDashboard:
    """Controls and settings dashboard pages must be accessible to admin users
    and decoy unauthenticated requests."""

    def test_controls_page_200_authenticated(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/controls",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_controls_page_content_type_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/controls",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    ct = r.headers.get("Content-Type", "")
                    assert "text/html" in ct
        _run(go())

    def test_settings_page_200_authenticated(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_settings_page_content_type_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    ct = r.headers.get("Content-Type", "")
                    assert "text/html" in ct
        _run(go())

    def test_controls_unauthenticated_decoy(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/controls")
                    body = await r.text()
                    assert "AppSecGW" not in body or "agw-c-" in body, (
                        "Unauthenticated /controls must decoy"
                    )
        _run(go())

    def test_settings_no_cache_control(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc
        _run(go())


# ── 11. TestSettingsImportTestButton ─────────────────────────────────────────

class TestSettingsImportTestButton:
    """Validates the 'Test' button behaviour: always dry_run=1, never mutates
    state, returns errors field for invalid content, 200 for valid ZIP."""

    def test_test_button_valid_zip_returns_200(self, proxy_module):
        """Test button (dry_run=1) on a valid exported ZIP returns HTTP 200."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    r = await c.post(
                        NS + "/settings-import?dry_run=1&overwrite_secrets=0",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    return r.status
        assert _run(go()) == 200

    def test_test_button_dry_run_true_in_response(self, proxy_module):
        """Response must carry dry_run=True so the UI can label it as TEST."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    r = await c.post(
                        NS + "/settings-import?dry_run=1&overwrite_secrets=0",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    d = await r.json()
                    return d
        d = _run(go())
        assert d["dry_run"] is True, f"Expected dry_run=True, got: {d}"

    def test_test_button_does_not_mutate_state(self, proxy_module):
        """State must be identical before and after a test-button call."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    before = (await (await c.get(NS + "/config", cookies=ck)).json())["state"]
                    xml = _make_config_xml({"RATE_LIMIT_BURST": 9999})
                    raw_zip = _make_zip(xml)
                    await c.post(
                        NS + "/settings-import?dry_run=1&overwrite_secrets=0",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    after = (await (await c.get(NS + "/config", cookies=ck)).json())["state"]
                    return before, after
        before, after = _run(go())
        assert before["RATE_LIMIT_BURST"] == after["RATE_LIMIT_BURST"], (
            f"Test button must not mutate state: was {before['RATE_LIMIT_BURST']}, "
            f"now {after['RATE_LIMIT_BURST']}"
        )

    def test_test_button_zero_errors_on_valid_zip(self, proxy_module):
        """Valid exported ZIP must produce errors=[] from test-button endpoint."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    r = await c.post(
                        NS + "/settings-import?dry_run=1&overwrite_secrets=0",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    d = await r.json()
                    return d
        d = _run(go())
        assert d["errors"] == [], f"No errors expected on valid zip, got: {d['errors']}"

    def test_test_button_empty_body_returns_400(self, proxy_module):
        """Test button with empty body must return HTTP 400 (bad ZIP)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    r = await c.post(
                        NS + "/settings-import?dry_run=1&overwrite_secrets=0",
                        data=b"",
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    return r.status
        assert _run(go()) == 400

    def test_test_button_counts_knobs_that_would_apply(self, proxy_module):
        """Test button must count knob that differs from live value as would-apply."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    xml = _make_config_xml({"RATE_LIMIT_BURST": 9999})
                    raw_zip = _make_zip(xml)
                    r = await c.post(
                        NS + "/settings-import?dry_run=1&overwrite_secrets=0",
                        data=raw_zip,
                        headers={"Content-Type": "application/octet-stream"},
                        cookies=ck,
                    )
                    d = await r.json()
                    return d
        d = _run(go())
        assert d["knobs_applied"] >= 1, (
            f"Expected at least 1 would-apply knob (RATE_LIMIT_BURST=9999), got: {d}"
        )

    def test_settings_page_has_test_button(self, proxy_module):
        """Settings page HTML must contain btn-test element."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return await r.text()
        html = _run(go())
        assert 'id="btn-test"' in html, "Settings page must contain btn-test button"


# ── 1.8.1 — Vhost Policy endpoints ───────────────────────────────────────────

class TestVhostPolicyDashboard:
    """GET /vhost-policy serves HTML (auth-gated)."""

    def test_vhost_policy_page_auth_guard(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/vhost-policy")
                    body = await r.text()
                    assert r.status != 200 or 'id="vhost-select"' not in body
        _run(go())

    def test_vhost_policy_page_serves_html_with_auth(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return r.status, r.content_type, await r.text()
        status, ct, html = _run(go())
        assert status == 200, f"GET /vhost-policy with auth returned {status}"
        assert "html" in ct, f"Content-Type not HTML: {ct}"
        assert "AppSecGW_1.8.9" in html, "vhost-policy page missing version string"

    def test_vhost_policy_page_no_store_header(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return r.headers.get("Cache-Control", "")
        assert "no-store" in _run(go()), "GET /vhost-policy must return Cache-Control: no-store"

    def test_vhost_policy_page_x_frame_options(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return r.headers.get("X-Frame-Options", "")
        assert _run(go()) == "DENY", "GET /vhost-policy must return X-Frame-Options: DENY"


class TestVhostPolicyDataEndpoint:
    """GET /vhost-policy-data returns merged global+vhost state."""

    def test_vhost_policy_data_auth_guard(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/vhost-policy-data")
                    text = await r.text()
                    assert r.status != 200 or "vhost_knobs" not in text
        _run(go())

    def test_vhost_policy_data_returns_200_with_auth(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return r.status, await r.json()
        status, d = _run(go())
        assert status == 200, f"GET /vhost-policy-data returned {status}"

    def test_vhost_policy_data_has_required_keys(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return await r.json()
        d = _run(go())
        for key in ("hostname", "vhost_knobs", "overrides", "global", "vhosts"):
            assert key in d, f"vhost-policy-data response missing key: {key}"

    def test_vhost_policy_data_vhost_knobs_list(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return await r.json()
        d = _run(go())
        knobs = d["vhost_knobs"]
        assert isinstance(knobs, list), "vhost_knobs must be a list"
        assert len(knobs) >= 100, (
            f"vhost_knobs has only {len(knobs)} entries — expected ≥100 after 1.8.1 expansion"
        )
        assert "UPSTREAM" in knobs, "UPSTREAM must be in vhost_knobs"
        assert "RISK_BAN_THRESHOLD" in knobs, "RISK_BAN_THRESHOLD must be in vhost_knobs"
        assert "COUNTRY_BLOCK_ENABLED" in knobs, "COUNTRY_BLOCK_ENABLED must be in vhost_knobs"

    def test_vhost_policy_data_global_has_upstream(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return await r.json()
        d = _run(go())
        assert "UPSTREAM" in d["global"], "global dict must contain UPSTREAM key"
        assert d["global"]["UPSTREAM"] is not None, "global UPSTREAM must not be None"

    def test_vhost_policy_data_no_store_header(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return r.headers.get("Cache-Control", "")
        assert "no-store" in _run(go()), (
            "GET /vhost-policy-data must return Cache-Control: no-store"
        )

    def test_vhost_policy_data_hostname_param(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data?hostname=nonexistent.example.com",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return await r.json()
        d = _run(go())
        assert d["hostname"] == "nonexistent.example.com", (
            "vhost-policy-data must echo back the requested hostname"
        )
        assert d["overrides"] == {}, (
            "overrides must be empty for a vhost with no configured overrides"
        )

    def test_vhost_policy_data_vhosts_is_list(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    return await r.json()
        d = _run(go())
        assert isinstance(d["vhosts"], list), "vhosts field must be a list"


# ── 10. TestDbConfigExportImport ─────────────────────────────────────────────

class TestDbConfigExportImport:
    """Explicit coverage for DB_BACKEND and POSTGRES_DSN across the
    /secured/config → export → import pipeline.

    The general round-trip tests verify total knob counts but never name
    DB_BACKEND or POSTGRES_DSN.  These tests assert the exact values so a
    rename or accidental removal of either key is caught immediately.

    DB_BACKEND is not env-pinned in the test environment (conftest.py does
    not set DB_BACKEND in os.environ), so imports are allowed to change it.
    """

    # ── A: /secured/config GET ────────────────────────────────────────

    def test_config_state_has_db_backend(self, proxy_module):
        """GET /secured/config state must include DB_BACKEND."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(NS + "/config",
                                           cookies={proxy_module._SESSION_COOKIE: cookie})).json()
                    return d["state"]
        state = _run(go())
        assert "DB_BACKEND" in state, "DB_BACKEND missing from /secured/config state"

    def test_config_state_db_backend_default_sqlite(self, proxy_module):
        """Default DB_BACKEND must be 'sqlite'."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(NS + "/config",
                                           cookies={proxy_module._SESSION_COOKIE: cookie})).json()
                    return d["state"].get("DB_BACKEND")
        assert _run(go()) == "sqlite", "default DB_BACKEND must be 'sqlite'"

    def test_config_state_has_postgres_dsn(self, proxy_module):
        """GET /secured/config state must include POSTGRES_DSN (may be empty)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(NS + "/config",
                                           cookies={proxy_module._SESSION_COOKIE: cookie})).json()
                    return d["state"]
        state = _run(go())
        assert "POSTGRES_DSN" in state, "POSTGRES_DSN missing from /secured/config state"

    # ── B: export contains DB keys ────────────────────────────────────

    def test_export_xml_has_db_backend_knob(self, proxy_module):
        """Exported XML <knobs> section must contain a <knob name='DB_BACKEND'>."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    raw_zip = await (await c.get(NS + "/settings-export",
                                                 cookies={proxy_module._SESSION_COOKIE: cookie})).read()
                    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
                        xml_bytes = zf.read("appsecgw-config.xml")
                    root = ET.fromstring(xml_bytes)
                    names = {e.attrib["name"] for e in root.find("knobs").findall("knob")}
                    return names
        names = _run(go())
        assert "DB_BACKEND" in names, f"DB_BACKEND missing from export knobs; got {names}"

    def test_export_db_backend_value_matches_active(self, proxy_module):
        """Exported DB_BACKEND value must match the live /secured/config value."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    live_val = (await (await c.get(NS + "/config", cookies=ck)).json())["state"]["DB_BACKEND"]
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
                        xml_bytes = zf.read("appsecgw-config.xml")
                    root = ET.fromstring(xml_bytes)
                    exported_val = None
                    for e in root.find("knobs").findall("knob"):
                        if e.attrib["name"] == "DB_BACKEND":
                            exported_val = json.loads(e.text)
                            break
                    return live_val, exported_val
        live, exported = _run(go())
        assert exported == live, (
            f"exported DB_BACKEND {exported!r} does not match live value {live!r}"
        )

    def test_export_xml_has_postgres_dsn_knob(self, proxy_module):
        """Exported XML <knobs> section must contain a <knob name='POSTGRES_DSN'>."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    raw_zip = await (await c.get(NS + "/settings-export",
                                                 cookies={proxy_module._SESSION_COOKIE: cookie})).read()
                    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
                        xml_bytes = zf.read("appsecgw-config.xml")
                    root = ET.fromstring(xml_bytes)
                    return {e.attrib["name"] for e in root.find("knobs").findall("knob")}
        names = _run(go())
        assert "POSTGRES_DSN" in names, f"POSTGRES_DSN missing from export knobs; got {names}"

    # ── C: import applies DB keys ─────────────────────────────────────

    def test_import_db_backend_applied(self, proxy_module):
        """Importing a config XML with DB_BACKEND='postgres' must report it as applied."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    xml = _make_config_xml({"DB_BACKEND": "postgres"})
                    r = await c.post(
                        NS + "/settings-import",
                        data=_make_zip(xml),
                        headers={**csrf, "Content-Type": "application/zip"},
                        cookies=ck,
                    )
                    return await r.json()
        summary = _run(go())
        assert "DB_BACKEND" in summary.get("applied", []), (
            f"DB_BACKEND must be in applied list; got summary={summary}"
        )
        assert summary["knobs_applied"] >= 1

    def test_import_db_backend_reflects_in_config(self, proxy_module):
        """After importing DB_BACKEND='postgres', GET /secured/config must show 'postgres'."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    # Import postgres backend
                    xml = _make_config_xml({"DB_BACKEND": "postgres"})
                    await c.post(
                        NS + "/settings-import",
                        data=_make_zip(xml),
                        headers={**csrf, "Content-Type": "application/zip"},
                        cookies=ck,
                    )
                    # Read back
                    state = (await (await c.get(NS + "/config", cookies=ck)).json())["state"]
                    return state.get("DB_BACKEND")
        assert _run(go()) == "postgres", "DB_BACKEND must reflect 'postgres' after import"

    def test_import_postgres_dsn_applied(self, proxy_module):
        """Importing POSTGRES_DSN must report it as applied and update live state."""
        dsn = "postgresql://user:pass@localhost:5432/testdb"

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    xml = _make_config_xml({"POSTGRES_DSN": dsn})
                    r = await c.post(
                        NS + "/settings-import",
                        data=_make_zip(xml),
                        headers={**csrf, "Content-Type": "application/zip"},
                        cookies=ck,
                    )
                    summary = await r.json()
                    state = (await (await c.get(NS + "/config", cookies=ck)).json())["state"]
                    return summary, state.get("POSTGRES_DSN")
        summary, live_dsn = _run(go())
        assert "POSTGRES_DSN" in summary.get("applied", []), (
            f"POSTGRES_DSN must be in applied list; got summary={summary}"
        )
        assert live_dsn == dsn, f"live POSTGRES_DSN {live_dsn!r} != imported {dsn!r}"

    def test_export_after_db_change_reflects_new_value(self, proxy_module):
        """After importing DB_BACKEND='postgres', the next export must include 'postgres'."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    # Change backend to postgres via import
                    xml = _make_config_xml({"DB_BACKEND": "postgres"})
                    await c.post(
                        NS + "/settings-import",
                        data=_make_zip(xml),
                        headers={**csrf, "Content-Type": "application/zip"},
                        cookies=ck,
                    )
                    # Export and read back
                    raw_zip = await (await c.get(NS + "/settings-export", cookies=ck)).read()
                    with zipfile.ZipFile(io.BytesIO(raw_zip)) as zf:
                        xml_bytes = zf.read("appsecgw-config.xml")
                    root = ET.fromstring(xml_bytes)
                    for e in root.find("knobs").findall("knob"):
                        if e.attrib["name"] == "DB_BACKEND":
                            return json.loads(e.text)
                    return None
        assert _run(go()) == "postgres", (
            "export after DB_BACKEND change must reflect 'postgres'"
        )

    def test_import_invalid_db_backend_rejected(self, proxy_module):
        """Importing DB_BACKEND='mysql' must be rejected (validator only allows sqlite/postgres)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    xml = _make_config_xml({"DB_BACKEND": "mysql"})
                    r = await c.post(
                        NS + "/settings-import",
                        data=_make_zip(xml),
                        headers={**csrf, "Content-Type": "application/zip"},
                        cookies=ck,
                    )
                    return await r.json()
        summary = _run(go())
        assert "DB_BACKEND" not in summary.get("applied", []), (
            "DB_BACKEND='mysql' must NOT be applied"
        )
        assert "DB_BACKEND" in summary.get("rejected", {}), (
            "DB_BACKEND='mysql' must appear in rejected dict"
        )
