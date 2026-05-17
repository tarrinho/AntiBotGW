"""
tests/test_v188_settings_subnav.py — Settings page section nav QA (v1.8.8).

Verifies the split-pane section nav added to settings.html, mirroring the
controls page layout.  Cards are grouped into 5 sections shown/hidden by a
left-rail nav; the identity strip remains always-visible above the split.

Static HTML structure (S):
  S01  #settings-split wrapper present
  S02  #settings-nav nav element present
  S03  #settings-panels content div present
  S04  #settings-id-strip always-visible identity strip present
  S05  Identity strip is OUTSIDE (before) #settings-split
  S06  card-export has explicit id
  S07  card-import has explicit id
  S08  All 16 CARD_SEC target card ids present in HTML

CSS structure (C):
  C01  #settings-split has display:flex
  C02  #settings-nav has a pixel width defined
  C03  .sni class defined (nav item)
  C04  .sni.active has border-left-color:var(--blue)
  C05  #settings-panels has overflow-y:auto

JS logic (J):
  J01  SECTIONS array defined with 5 entries
  J02  All 5 expected section ids present: routing/identity/mesh/infra/config
  J03  CARD_SEC object defined
  J04  card-vhosts → routing mapping
  J05  card-discovered → routing mapping
  J06  card-sso → identity mapping
  J07  card-users → identity mapping
  J08  card-2fa → identity mapping
  J09  card-gw-registry → mesh mapping
  J10  card-mesh → mesh mapping
  J11  card-infrastructure → infra mapping
  J12  card-db → infra mapping
  J13  card-redis → infra mapping
  J14  card-export → config mapping
  J15  card-import → config mapping
  J16  _switch() function defined
  J17  _buildNav() function defined
  J18  window._settingsSwitch exposed
  J19  window._settingsBuildNav exposed
  J20  DOMContentLoaded calls _buildNav()
  J21  DOMContentLoaded calls _switch with 'routing' as default
  J22  .sni class used for nav item elements
  J23  dataset.sec used to identify active section
  J24  CARD_SEC covers every section id in SECTIONS (no empty sections)
  J25  No card id in CARD_SEC appears twice (no double-mapping)

Regression (R):
  R01  card-vhosts still present (not accidentally removed)
  R02  card-users still present
  R03  card-gw-registry still present
  R04  card-db still present
  R05  card-infrastructure still present
  R06  card-redis still present
  R07  card-sso still present
  R08  card-2fa still present
  R09  card-mesh still present
  R10  Identity strip elements (gw-version/gw-db/gw-started/gw-upstream) intact
  R11  main wrapper replaced by settings-id-strip + settings-split (no <main> tag)
  R12  #page-content has padding:0 override (panels handle their own padding)

Dynamic (D):
  D01  GET /secured/settings authenticated → 200 HTML
  D02  Response contains settings-split
  D03  Response contains settings-nav
  D04  Response contains settings-panels
  D05  Response contains CARD_SEC
  D06  Response contains _settingsSwitch
"""

import re
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

_DASHBOARDS = Path(__file__).resolve().parent.parent / "dashboards"
_NS = "/antibot-appsec-gateway/secured"

_EXPECTED_SECTIONS = {"routing", "identity", "mesh", "infra", "config"}

_CARD_SEC_EXPECTED = {
    "card-vhosts":         "routing",
    "card-discovered":     "routing",
    "card-sso":            "identity",
    "card-users":          "identity",
    "card-sso-pending":    "identity",
    "card-2fa":            "identity",
    "card-gw-registry":    "mesh",
    "card-mesh":           "mesh",
    "card-redis":          "mesh",
    "card-infrastructure": "infra",
    "card-db":             "infra",
    "card-storage":        "infra",
    "card-credentials":    "infra",
    "card-logging":        "infra",
    "card-export":         "config",
    "card-import":         "config",
}


def _settings() -> str:
    return (_DASHBOARDS / "settings.html").read_text(encoding="utf-8")


def _nav_script(src: str) -> str:
    """Return the Settings section nav script block."""
    marker = "Settings section nav"
    idx = src.find(marker)
    if idx == -1:
        return ""
    tail = src[idx:]
    end = tail.find("})();")
    return tail[:end + 5] if end != -1 else tail[:4000]


# ── S: HTML structure ─────────────────────────────────────────────────────────

class TestSettingsSubnavHTML:
    def setup_method(self):
        self.src = _settings()

    def test_s01_settings_split_present(self):
        assert 'id="settings-split"' in self.src, (
            "#settings-split wrapper missing — split-pane layout not implemented"
        )

    def test_s02_settings_nav_present(self):
        assert 'id="settings-nav"' in self.src, (
            "#settings-nav nav element missing — section nav sidebar not present"
        )

    def test_s03_settings_panels_present(self):
        assert 'id="settings-panels"' in self.src, (
            "#settings-panels content div missing — section content area not present"
        )

    def test_s04_settings_id_strip_present(self):
        assert 'id="settings-id-strip"' in self.src, (
            "#settings-id-strip missing — identity strip always-visible wrapper not present"
        )

    def test_s05_id_strip_before_split(self):
        """Identity strip must appear before #settings-split so it stays always-visible."""
        strip_pos = self.src.find('id="settings-id-strip"')
        split_pos = self.src.find('id="settings-split"')
        assert strip_pos != -1, "#settings-id-strip not found"
        assert split_pos != -1, "#settings-split not found"
        assert strip_pos < split_pos, (
            "#settings-id-strip must appear before #settings-split in the HTML"
        )

    def test_s06_card_export_has_id(self):
        assert 'id="card-export"' in self.src, (
            "Export card missing id='card-export' — cannot be targeted by section nav"
        )

    def test_s07_card_import_has_id(self):
        assert 'id="card-import"' in self.src, (
            "Import card missing id='card-import' — cannot be targeted by section nav"
        )

    @pytest.mark.parametrize("card_id", list(_CARD_SEC_EXPECTED.keys()))
    def test_s08_all_card_sec_targets_exist(self, card_id):
        """Every card id referenced in CARD_SEC must exist in the HTML."""
        assert f'id="{card_id}"' in self.src, (
            f"Card '{card_id}' referenced in CARD_SEC but not found in settings.html"
        )


# ── C: CSS ────────────────────────────────────────────────────────────────────

class TestSettingsSubnavCSS:
    def setup_method(self):
        self.src = _settings()
        # extract <style> block
        m = re.search(r'<style>(.*?)</style>', self.src, re.DOTALL)
        self.css = m.group(1) if m else ""

    def test_c01_settings_split_flex(self):
        assert "settings-split" in self.css and "flex" in self.css, (
            "#settings-split must have display:flex in the stylesheet"
        )
        assert re.search(r'#settings-split\s*\{[^}]*flex', self.css), (
            "#settings-split CSS rule must include flex"
        )

    def test_c02_settings_nav_has_width(self):
        m = re.search(r'#settings-nav\s*\{([^}]*)\}', self.css)
        assert m, "#settings-nav CSS rule not found"
        assert re.search(r'\d+px', m.group(1)), (
            "#settings-nav must have a pixel width in its CSS rule"
        )

    def test_c03_sni_class_defined(self):
        assert ".sni" in self.css, (
            ".sni class missing from stylesheet — nav items won't be styled"
        )

    def test_c04_sni_active_has_blue_border(self):
        m = re.search(r'\.sni\.active\s*\{([^}]*)\}', self.css)
        assert m, ".sni.active CSS rule not found"
        assert "var(--blue)" in m.group(1), (
            ".sni.active must use var(--blue) for the active border highlight"
        )

    def test_c05_settings_panels_scrollable(self):
        m = re.search(r'#settings-panels\s*\{([^}]*)\}', self.css)
        assert m, "#settings-panels CSS rule not found"
        assert "overflow-y" in m.group(1), (
            "#settings-panels must have overflow-y so long sections scroll independently"
        )


# ── J: JS logic ───────────────────────────────────────────────────────────────

class TestSettingsSubnavJS:
    def setup_method(self):
        self.src = _settings()
        self.nav_js = _nav_script(self.src)

    def test_j01_sections_array_defined(self):
        assert "const SECTIONS" in self.nav_js, (
            "SECTIONS array not defined in settings nav script"
        )

    def test_j02_five_sections(self):
        ids_found = set(re.findall(r"id:'(\w+)'", self.nav_js))
        missing = _EXPECTED_SECTIONS - ids_found
        assert not missing, (
            f"Missing section ids in SECTIONS: {missing}. "
            f"Found: {ids_found}"
        )

    def test_j03_card_sec_defined(self):
        assert "const CARD_SEC" in self.nav_js, (
            "CARD_SEC object not defined in settings nav script"
        )

    @pytest.mark.parametrize("card_id,section", [
        ("card-vhosts",         "routing"),
        ("card-discovered",     "routing"),
        ("card-sso",            "identity"),
        ("card-users",          "identity"),
        ("card-2fa",            "identity"),
        ("card-gw-registry",    "mesh"),
        ("card-mesh",           "mesh"),
        ("card-redis",          "mesh"),
        ("card-infrastructure", "infra"),
        ("card-db",             "infra"),
        ("card-export",         "config"),
        ("card-import",         "config"),
    ])
    def test_j04_to_j15_card_sec_mappings(self, card_id, section):
        """Each card in CARD_SEC must map to the correct section id."""
        pattern = rf"['\"]?{re.escape(card_id)}['\"]?\s*:\s*['\"]?{re.escape(section)}['\"]?"
        assert re.search(pattern, self.nav_js), (
            f"CARD_SEC missing mapping '{card_id}' → '{section}'"
        )

    def test_j16_switch_function_defined(self):
        assert "function _switch(" in self.nav_js or "_switch = function" in self.nav_js, (
            "_switch() not defined in settings nav script"
        )

    def test_j17_build_nav_function_defined(self):
        assert "function _buildNav(" in self.nav_js or "_buildNav = function" in self.nav_js, (
            "_buildNav() not defined in settings nav script"
        )

    def test_j18_settings_switch_exposed(self):
        assert "window._settingsSwitch" in self.nav_js, (
            "window._settingsSwitch not exposed — external callers can't trigger section switch"
        )

    def test_j19_settings_build_nav_exposed(self):
        assert "window._settingsBuildNav" in self.nav_js, (
            "window._settingsBuildNav not exposed"
        )

    def test_j20_dom_content_loaded_calls_build_nav(self):
        assert "DOMContentLoaded" in self.nav_js and "_buildNav()" in self.nav_js, (
            "DOMContentLoaded handler must call _buildNav()"
        )

    def test_j21_dom_content_loaded_default_routing(self):
        assert "_switch('routing')" in self.nav_js or '_switch("routing")' in self.nav_js, (
            "DOMContentLoaded must call _switch('routing') to show the Routing section by default"
        )

    def test_j22_sni_class_used_for_nav_items(self):
        assert "'sni'" in self.nav_js or '"sni"' in self.nav_js, (
            "Nav items must use class 'sni' for styling"
        )

    def test_j23_dataset_sec_used(self):
        assert "dataset.sec" in self.nav_js, (
            "Nav items must set dataset.sec to identify their section"
        )

    def test_j24_every_section_has_at_least_one_card(self):
        """No section in SECTIONS should be unreachable (no card pointing to it)."""
        sec_ids_in_card_sec = set(re.findall(
            r"['\"](?:routing|identity|mesh|infra|config)['\"]",
            self.nav_js
        ))
        # strip quotes
        sec_ids_in_card_sec = {s.strip("'\"") for s in sec_ids_in_card_sec}
        missing = _EXPECTED_SECTIONS - sec_ids_in_card_sec
        assert not missing, (
            f"Sections {missing} have no cards in CARD_SEC — they'd show an empty panel"
        )

    def test_j25_no_duplicate_card_mappings(self):
        """A card id must not appear more than once in CARD_SEC."""
        all_card_ids = re.findall(r"['\"]?(card-[\w-]+)['\"]?\s*:", self.nav_js)
        seen = {}
        for cid in all_card_ids:
            assert cid not in seen, (
                f"Card '{cid}' appears twice in CARD_SEC — would cause display/hide conflicts"
            )
            seen[cid] = True


# ── R: Regression ─────────────────────────────────────────────────────────────

class TestSettingsSubnavRegression:
    def setup_method(self):
        self.src = _settings()

    @pytest.mark.parametrize("card_id", [
        "card-vhosts", "card-users", "card-gw-registry", "card-db",
        "card-infrastructure", "card-redis", "card-sso", "card-2fa", "card-mesh",
    ])
    def test_r01_to_r09_existing_cards_intact(self, card_id):
        """Pre-existing card ids must not have been accidentally removed."""
        assert f'id="{card_id}"' in self.src, (
            f"Card '{card_id}' missing — was accidentally removed during refactor"
        )

    def test_r10_identity_strip_elements_intact(self):
        for eid in ("gw-version", "gw-db", "gw-started", "gw-upstream"):
            assert f'id="{eid}"' in self.src, (
                f"Identity strip element '{eid}' missing — was removed during nav refactor"
            )

    def test_r11_no_main_wrapper(self):
        """<main> wrapper replaced by #settings-id-strip + #settings-split."""
        assert "<main>" not in self.src, (
            "<main> wrapper still present — should have been replaced by "
            "#settings-id-strip + #settings-split layout"
        )

    def test_r12_page_content_has_no_padding(self):
        """#page-content must have padding:0 so panels handle their own padding."""
        m = re.search(r'id="page-content"[^>]*style="([^"]*)"', self.src)
        assert m, "#page-content with inline style not found"
        assert "padding:0" in m.group(1).replace(" ", ""), (
            "#page-content must have padding:0 — padding is now owned by #settings-panels"
        )


# ── T: DB test-button UX (v1.8.8 fix) ────────────────────────────────────────

class TestSettingsDbTestBtn:
    """
    T01  _tip-pg-test handler calls /secured/db-test (not /integration-check)
    T02  DSN is built from form fields, not from a pre-saved global
    T03  Handler validates that host, database and user are required
    T04  Handler validates that password is required (not silently skipped)
    T05  DSN URL includes all five fields: user, password, host, port, db
    T06  Successful response reads j.probe.ok (not j.latency_ms)
    T07  Success branch shows "✓ connected"
    T08  Failure branch shows "✗ " + reason from j.reason or probe.reason
    T09  Result element is updated before fetch (dim "testing…")
    T10  Button is re-enabled in finally path (no early-return bug)
    """

    def setup_method(self):
        self.src = _settings()

    def _tip_pg_test_handler(self) -> str:
        """Extract the _tip-pg-test onclick handler block from settings.html."""
        marker = "document.getElementById('_tip-pg-test').onclick"
        idx = self.src.find(marker)
        assert idx != -1, "_tip-pg-test onclick not found in settings.html"
        # grab ~80 lines of context (handler has grown with status-tile sync code)
        return self.src[idx: idx + 2200]

    def test_t01_calls_db_test_not_integration_check(self):
        blk = self._tip_pg_test_handler()
        assert "/db-test" in blk, (
            "_tip-pg-test must call /secured/db-test (probe DSN endpoint), not /integration-check"
        )
        assert "integration-check" not in blk, (
            "_tip-pg-test must NOT call /integration-check — that endpoint ignores the dsn param"
        )

    def test_t02_dsn_built_from_form_fields(self):
        blk = self._tip_pg_test_handler()
        # DSN must be built from getFields() output (f.u / f.w / f.h / f.p / f.d)
        assert "f.u" in blk and "f.w" in blk and "f.h" in blk, (
            "DSN in _tip-pg-test must be assembled from form field variables (f.u, f.w, f.h, …)"
        )
        # Must NOT rely on a pre-saved global POSTGRES_DSN
        assert "POSTGRES_DSN" not in blk, (
            "_tip-pg-test handler must not reference the global POSTGRES_DSN"
        )

    def test_t03_validates_host_db_user_required(self):
        blk = self._tip_pg_test_handler()
        assert "f.h" in blk and "f.d" in blk and "f.u" in blk, (
            "_tip-pg-test must check f.h, f.d and f.u (host / db / user) before fetching"
        )
        assert "required" in blk.lower(), (
            "_tip-pg-test must emit a 'required' message when fields are missing"
        )

    def test_t04_validates_password_required(self):
        blk = self._tip_pg_test_handler()
        assert "f.w" in blk, "_tip-pg-test must check f.w (password)"
        # Handler should guard on empty password with a user-visible message
        assert "Password required" in blk or "password required" in blk.lower(), (
            "_tip-pg-test must tell the user that a password is required to test"
        )

    def test_t05_dsn_contains_all_five_fields(self):
        blk = self._tip_pg_test_handler()
        # postgresql://${user}:${pass}@${host}:${port}/${db}
        for field in ("f.u", "f.w", "f.h", "f.p", "f.d"):
            assert field in blk, (
                f"DSN in _tip-pg-test must include field variable '{field}'"
            )

    def test_t06_success_reads_probe_ok(self):
        blk = self._tip_pg_test_handler()
        # Response structure: {ok, probe:{ok, version, round_trip_ms, …}}
        assert "j.probe" in blk or "probe" in blk, (
            "_tip-pg-test success branch must read from j.probe (db-test probe payload)"
        )

    def test_t07_success_shows_connected(self):
        blk = self._tip_pg_test_handler()
        assert "connected" in blk, (
            "_tip-pg-test must show '✓ connected …' on success"
        )

    def test_t08_failure_shows_reason(self):
        blk = self._tip_pg_test_handler()
        assert "j.reason" in blk or "p.reason" in blk, (
            "_tip-pg-test failure branch must display j.reason / probe.reason"
        )
        assert "\\u2717" in blk or "✗" in blk, (
            "_tip-pg-test failure branch must show ✗ prefix"
        )

    def test_t09_result_el_set_before_fetch(self):
        blk = self._tip_pg_test_handler()
        # "testing…" must appear before the fetch call
        idx_testing = blk.find("testing")
        idx_fetch   = blk.find("fetch(")
        assert idx_testing != -1, "_tip-pg-test must set result text to 'testing…' before fetch"
        assert idx_fetch   != -1, "_tip-pg-test must call fetch"
        assert idx_testing < idx_fetch, (
            "'testing…' status must be set BEFORE the fetch call, not after"
        )

    def test_t10_button_reenabled_after_request(self):
        blk = self._tip_pg_test_handler()
        # disabled=false must appear after disabled=true, and the re-enable must
        # not be inside an if-branch (so it fires even on error)
        assert "disabled=false" in blk or "disabled = false" in blk, (
            "_tip-pg-test must re-enable the button after the request completes"
        )
        idx_disable = blk.find("this.disabled=true")
        idx_enable  = blk.rfind("disabled=false")
        assert idx_disable < idx_enable, (
            "Button re-enable must appear AFTER the disable call"
        )


# ── B: Backend db-test probe-mode DSN patch (v1.8.8 fix) ─────────────────────

class TestDbTestProbeDsnPatch:
    """
    B01  db_test_endpoint probe mode patches db.postgres.POSTGRES_DSN before call
    B02  db_test_endpoint probe mode restores db.postgres.POSTGRES_DSN after call
    B03  probe mode with bad DSN returns ok=False + reason (not "not configured")
    B04  probe mode without ?dsn= falls through to normal mode (no patch attempt)
    B05  pg_test_roundtrip sees probe_dsn during call, not empty string
    """

    def _ph(self):
        import importlib, sys
        if "core.proxy_handler" not in sys.modules:
            import importlib.util, os
            proj = Path(__file__).resolve().parent.parent
            spec = importlib.util.spec_from_file_location(
                "core.proxy_handler",
                proj / "core" / "proxy_handler.py",
            )
            mod = importlib.util.module_from_spec(spec)
            sys.modules["core.proxy_handler"] = mod
            spec.loader.exec_module(mod)
        return sys.modules["core.proxy_handler"]

    def test_b01_probe_mode_patches_pg_mod(self):
        src = Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py"
        code = src.read_text(encoding="utf-8")
        # Probe block must assign to _pg_mod_dbt.POSTGRES_DSN (not just globals())
        assert "_pg_mod_dbt.POSTGRES_DSN = probe_dsn" in code, (
            "db_test_endpoint probe mode must patch db.postgres.POSTGRES_DSN "
            "before calling pg_test_roundtrip() — globals() patch alone is insufficient"
        )

    def test_b02_probe_mode_restores_pg_mod(self):
        src = Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py"
        code = src.read_text(encoding="utf-8")
        assert "_pg_mod_dbt.POSTGRES_DSN = _pg_mod_dbt_saved_dsn" in code, (
            "db_test_endpoint probe mode must restore db.postgres.POSTGRES_DSN "
            "in the finally block to avoid leaking the probe DSN into the live process"
        )

    def test_b03_probe_mode_finally_block_covers_restore(self):
        src = Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py"
        code = src.read_text(encoding="utf-8")
        # Locate the db_test_endpoint probe section
        marker = "1.6.10 — pre-flight probe mode"
        idx = code.find(marker)
        assert idx != -1, "probe mode comment not found in proxy_handler.py"
        blk = code[idx: idx + 1500]
        # Both the set and restore must be present in the same block
        assert "_pg_mod_dbt.POSTGRES_DSN = probe_dsn" in blk, (
            "probe DSN assignment to db.postgres missing from probe block"
        )
        assert "_pg_mod_dbt.POSTGRES_DSN = _pg_mod_dbt_saved_dsn" in blk, (
            "probe DSN restore in finally missing from probe block"
        )
        # Restore must come AFTER set
        idx_set     = blk.index("_pg_mod_dbt.POSTGRES_DSN = probe_dsn")
        idx_restore = blk.index("_pg_mod_dbt.POSTGRES_DSN = _pg_mod_dbt_saved_dsn")
        assert idx_set < idx_restore, (
            "DSN restore must appear after the DSN set in the probe block"
        )

    def test_b04_probe_variables_scoped_to_probe_block(self):
        src = Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py"
        code = src.read_text(encoding="utf-8")
        # The probe block ends at the return web.json_response that emits {ok, probe}.
        # Everything after that return is normal (non-probe) mode.
        # Confirm: after the probe return, pg_mod_dbt does NOT appear again.
        probe_return_marker = '"probe": {**probe, "dsn_masked": masked}}'
        idx = code.find(probe_return_marker)
        assert idx != -1, "probe return marker not found in db_test_endpoint"
        normal_mode = code[idx + len(probe_return_marker): idx + 3000]
        assert "pg_mod_dbt" not in normal_mode, (
            "pg_mod_dbt reference found after the probe return — "
            "probe variables must be scoped to the probe if-block only"
        )

    def test_b05_db_switch_and_db_test_both_patch_pg_mod(self):
        """Both endpoints that call pg_test_roundtrip with a caller DSN must patch db.postgres."""
        src = Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py"
        code = src.read_text(encoding="utf-8")
        # db-switch probe (existing, correct)
        assert "_pg_mod.POSTGRES_DSN = dsn" in code, (
            "db-switch probe must patch db.postgres.POSTGRES_DSN (existing fix must be intact)"
        )
        # db-test probe (new fix)
        assert "_pg_mod_dbt.POSTGRES_DSN = probe_dsn" in code, (
            "db-test probe must patch db.postgres.POSTGRES_DSN (new fix)"
        )


# ── D: Dynamic (live gateway) ─────────────────────────────────────────────────

async def _echo_handler(request: web.Request) -> web.Response:
    return web.Response(text="ok")


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
async def test_d01_settings_200(proxy_module):
    """GET /secured/settings authenticated → 200 HTML."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/settings", cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"/settings returned HTTP {r.status}"
            text = await r.text()
            assert "<html" in text.lower(), "/settings response is not HTML"


@pytest.mark.asyncio
async def test_d02_settings_has_split(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/settings", cookies=_admin_cookie(proxy_module))
            assert "settings-split" in await r.text(), (
                "/settings HTML missing settings-split"
            )


@pytest.mark.asyncio
async def test_d03_settings_has_nav(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/settings", cookies=_admin_cookie(proxy_module))
            assert "settings-nav" in await r.text(), (
                "/settings HTML missing settings-nav"
            )


@pytest.mark.asyncio
async def test_d04_settings_has_panels(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/settings", cookies=_admin_cookie(proxy_module))
            assert "settings-panels" in await r.text(), (
                "/settings HTML missing settings-panels"
            )


@pytest.mark.asyncio
async def test_d05_settings_has_card_sec(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/settings", cookies=_admin_cookie(proxy_module))
            assert "CARD_SEC" in await r.text(), (
                "/settings HTML missing CARD_SEC mapping"
            )


@pytest.mark.asyncio
async def test_d06_settings_has_switch_exposed(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/settings", cookies=_admin_cookie(proxy_module))
            assert "_settingsSwitch" in await r.text(), (
                "/settings HTML missing window._settingsSwitch"
            )


# ── D7-D12: db-test probe-DSN dynamic tests ──────────────────────────────────
#
# These tests exercise the /secured/db-test endpoint end-to-end via HTTP.
# They cover the two bugs fixed in v1.8.8:
#   Bug A (frontend): _tip-pg-test called /integration-check, which ignores
#          the &dsn= param — test calls /db-test directly with ?dsn=.
#   Bug B (backend): db_test_endpoint probe mode set globals()["POSTGRES_DSN"]
#          but not db.postgres.POSTGRES_DSN, so pg_test_roundtrip() always saw
#          empty DSN and returned "POSTGRES_DSN not configured".
#
# D07  No ?dsn= → normal mode: response has sqlite + postgres top-level keys
# D08  ?dsn=bad-addr → probe mode: ok=false, reason != "POSTGRES_DSN not configured"
# D09  After probe call db.postgres.POSTGRES_DSN is restored to original value
# D10  pg_test_roundtrip sees the probe_dsn during the call (not empty)
# D11  Probe response masks the password in dsn_masked
# D12  Unauthenticated /db-test returns 404 decoy (not 401/403)

import sys as _sys
import types as _types
import urllib.parse as _uparse


def _db_postgres_mod():
    """Return the live db.postgres module if loaded, else None."""
    return _sys.modules.get("db.postgres")


@pytest.mark.asyncio
async def test_d07_no_dsn_param_normal_mode(proxy_module):
    """Without ?dsn= the endpoint returns the full normal-mode response
    (sqlite + postgres keys), not the probe-mode shape {ok, probe}."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(
                f"{_NS}/db-test",
                cookies=_admin_cookie(proxy_module),
            )
            assert r.status == 200, f"/db-test returned HTTP {r.status}"
            j = await r.json()
            assert "sqlite" in j, (
                "normal mode /db-test must include 'sqlite' key — "
                "got: " + str(list(j.keys()))
            )
            assert "postgres" in j, (
                "normal mode /db-test must include 'postgres' key — "
                "got: " + str(list(j.keys()))
            )
            # probe key must NOT be present in normal mode
            assert "probe" not in j, (
                "normal mode /db-test must NOT include 'probe' key "
                "(that is probe-mode only)"
            )


@pytest.mark.asyncio
async def test_d08_probe_dsn_not_configured_msg_absent(proxy_module):
    """With ?dsn=<unreachable> probe mode must NOT return
    'POSTGRES_DSN not configured' — that was Bug B (db.postgres not patched).
    It must return a real connection-level error instead."""
    # Port 1 is always refused on loopback
    bad_dsn = "postgresql://qa:qa@127.0.0.1:1/qa_db"
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(
                f"{_NS}/db-test",
                params={"dsn": bad_dsn},
                cookies=_admin_cookie(proxy_module),
            )
            assert r.status == 200, f"/db-test?dsn= returned HTTP {r.status}"
            j = await r.json()
            # Must be probe mode response shape
            assert "probe" in j, (
                "?dsn= should trigger probe mode; response must contain 'probe' key — "
                "got: " + str(list(j.keys()))
            )
            assert j.get("ok") is False, "unreachable DSN probe must return ok=false"
            reason = (j.get("reason") or "").lower()
            assert "not configured" not in reason, (
                "probe mode must NOT return 'POSTGRES_DSN not configured' — "
                "that indicates db.postgres was not patched before calling "
                "pg_test_roundtrip(). Actual reason: " + j.get("reason", "")
            )


@pytest.mark.asyncio
async def test_d09_probe_dsn_restored_after_call(proxy_module):
    """After /db-test?dsn= completes, db.postgres.POSTGRES_DSN must be
    restored to its pre-call value (empty in a fresh test gateway)."""
    pg_mod = _db_postgres_mod()
    if pg_mod is None:
        pytest.skip("db.postgres not loaded yet — run after a db-test call")

    original = getattr(pg_mod, "POSTGRES_DSN", "")
    bad_dsn = "postgresql://qa:qa@127.0.0.1:1/qa_db"

    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            # Force db.postgres to load by triggering a normal-mode call first
            await cli.get(f"{_NS}/db-test", cookies=_admin_cookie(proxy_module))
            pg_mod = _db_postgres_mod()
            if pg_mod is None:
                pytest.skip("db.postgres still not loaded after warm-up call")

            pre_call_dsn = getattr(pg_mod, "POSTGRES_DSN", "")

            await cli.get(
                f"{_NS}/db-test",
                params={"dsn": bad_dsn},
                cookies=_admin_cookie(proxy_module),
            )

            post_call_dsn = getattr(pg_mod, "POSTGRES_DSN", "")
            assert post_call_dsn == pre_call_dsn, (
                f"db.postgres.POSTGRES_DSN leaked after probe call. "
                f"Before: {pre_call_dsn!r}, After: {post_call_dsn!r}. "
                f"The finally block must restore it."
            )


@pytest.mark.asyncio
async def test_d10_probe_captures_dsn_in_roundtrip(proxy_module):
    """pg_test_roundtrip must see the probe_dsn as POSTGRES_DSN during
    its call, not the module-level empty string (that was Bug B)."""
    captured = {}
    probe_dsn = "postgresql://cap_user:cap_pass@127.0.0.1:1/cap_db"

    original_fn = proxy_module.pg_test_roundtrip

    def _capturing_roundtrip():
        pg_mod = _db_postgres_mod()
        captured["dsn_seen"] = getattr(pg_mod, "POSTGRES_DSN", "") if pg_mod else None
        # Return a failure (no real connection) so the endpoint doesn't hang
        return {"ok": False, "reason": "capture-mock"}

    proxy_module.pg_test_roundtrip = _capturing_roundtrip
    try:
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                await cli.get(
                    f"{_NS}/db-test",
                    params={"dsn": probe_dsn},
                    cookies=_admin_cookie(proxy_module),
                )
    finally:
        proxy_module.pg_test_roundtrip = original_fn

    assert "dsn_seen" in captured, (
        "mock pg_test_roundtrip was never called — "
        "check that psycopg is installed in the test environment"
    )
    assert captured["dsn_seen"] == probe_dsn, (
        f"pg_test_roundtrip saw POSTGRES_DSN={captured['dsn_seen']!r} "
        f"but expected {probe_dsn!r}. "
        f"db.postgres.POSTGRES_DSN was not patched before the call."
    )


@pytest.mark.asyncio
async def test_d11_probe_masks_password_in_response(proxy_module):
    """The probe response must include dsn_masked with password replaced by ****."""
    secret_pass = "s3cr3tP@ssw0rd"
    dsn = f"postgresql://myuser:{secret_pass}@127.0.0.1:1/mydb"
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(
                f"{_NS}/db-test",
                params={"dsn": dsn},
                cookies=_admin_cookie(proxy_module),
            )
            j = await r.json()
            assert "probe" in j, "probe key missing from response"
            probe = j["probe"]
            assert "dsn_masked" in probe, (
                "probe object must contain 'dsn_masked' field"
            )
            masked = probe["dsn_masked"]
            assert secret_pass not in masked, (
                f"Password leaked in dsn_masked: {masked!r}"
            )
            # Proxy uses ">update password<" as the redaction placeholder
            assert ">update password<" in masked or "****" in masked, (
                f"dsn_masked must redact the password. Got: {masked!r}"
            )


@pytest.mark.asyncio
async def test_d12_unauthenticated_db_test_no_real_data(proxy_module):
    """Unauthenticated /db-test must not expose real gateway state.
    The gateway either proxies the request to upstream or returns a decoy;
    either way the response must not contain db-test JSON keys."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/db-test")
            body = await r.text()
            # Real db-test response always contains these keys
            for key in ('"sqlite"', '"postgres"', '"probe"'):
                assert key not in body, (
                    f"Unauthenticated /db-test must not expose real data. "
                    f"Found {key!r} in response body: {body[:200]!r}"
                )


# ─────────────────────────────────────────────────────────────────────────────
# Live-probe status + stats tests (L) — _dbShowTip refreshes from /metrics on open
# L01  _dbShowTip fetches /metrics (not /db-test) for postgres type
# L02  Success path reads pg.available or pg.enabled from services.db_postgres
# L03  Live probe updates _tip-pg-status-val to ✓ reachable on success
# L04  Failure path falls back to "unreachable" when pg not enabled/available
# L05  Failure path shows "DSN not configured" when pg.configured is false
# L06  Live-probe is guarded by type === 'postgres' (not fired for sqlite)
# L07  _tip-pg-status-val opacity set to 0.5 before fetch (loading indicator)
# L08  opacity restored to 1 after fetch resolves (both ok and error paths)
# L09  Stats grid wrapper has id="_tip-pg-stats" so live probe can update cells
# L10  Live probe rebuilds stats cells (Events, DB size) from fresh metrics data
# ─────────────────────────────────────────────────────────────────────────────

class TestDbShowTipLiveProbe:
    """Static-HTML tests verifying the live stats/status refresh added to _dbShowTip."""

    def setup_method(self):
        self.src = _settings()

    def _dbShowTip_block(self) -> str:
        """Extract the _dbShowTip function body."""
        marker = "window._dbShowTip = function"
        idx = self.src.find(marker)
        assert idx != -1, "_dbShowTip not found in settings.html"
        # 8000 chars covers the full function body including the live probe IIFE
        return self.src[idx: idx + 8000]

    def _probe_fetch_idx(self, blk: str) -> int:
        idx = blk.find("secured/metrics")
        assert idx != -1, "Live probe fetch to /metrics not found in _dbShowTip"
        return idx

    def test_l01_live_probe_fetches_metrics(self):
        blk = self._dbShowTip_block()
        assert "secured/metrics" in blk, (
            "_dbShowTip must fetch /secured/metrics on popup open (not /db-test)"
        )
        # Must NOT call /db-test from the live probe block
        probe_idx = self._probe_fetch_idx(blk)
        context = blk[max(0, probe_idx - 100): probe_idx + 200]
        assert "/db-test" not in context, (
            "Live probe must use /metrics, not /db-test"
        )

    def test_l02_success_reads_available_or_enabled(self):
        blk = self._dbShowTip_block()
        assert "pg.available" in blk or "pg.enabled" in blk, (
            "Live probe must read pg.available or pg.enabled from services.db_postgres"
        )
        assert "'✓ reachable'" in blk or '"✓ reachable"' in blk, (
            "Live probe success path must set textContent to '✓ reachable'"
        )

    def test_l03_status_tile_updated(self):
        blk = self._dbShowTip_block()
        assert "_tip-pg-status-val" in blk or "sv.textContent" in blk, (
            "Live probe must update the status tile element"
        )
        assert "'✓ reachable'" in blk or '"✓ reachable"' in blk, (
            "Live probe must write '✓ reachable' on success"
        )

    def test_l04_failure_defaults_to_unreachable(self):
        blk = self._dbShowTip_block()
        assert "unreachable" in blk, (
            "Live probe failure path must fall back to 'unreachable'"
        )

    def test_l05_failure_shows_dsn_not_configured(self):
        blk = self._dbShowTip_block()
        assert "configured" in blk and ("DSN not configured" in blk or "not configured" in blk), (
            "Live probe failure path must distinguish 'DSN not configured' from 'unreachable'"
        )

    def test_l06_postgres_type_guard(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        context_before = blk[max(0, probe_idx - 300): probe_idx]
        assert "postgres" in context_before, (
            "Live probe fetch must be inside a type === 'postgres' guard"
        )

    def test_l07_opacity_set_before_fetch(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        before_fetch = blk[max(0, probe_idx - 200): probe_idx]
        assert "opacity" in before_fetch and ("0.5" in before_fetch), (
            "Status tile opacity must be dimmed to 0.5 before the live fetch fires"
        )

    def test_l08_opacity_restored_after_fetch(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        after_fetch = blk[probe_idx: probe_idx + 2500]
        assert "opacity" in after_fetch and ("= '1'" in after_fetch or '= "1"' in after_fetch), (
            "Status tile opacity must be restored to 1 after live probe completes"
        )

    def test_l09_stats_grid_has_id(self):
        assert '_tip-pg-stats' in self.src, (
            "Stats grid wrapper must have id='_tip-pg-stats' so live probe can update it"
        )

    def test_l10_live_probe_rebuilds_stats_cells(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        after_fetch = blk[probe_idx: probe_idx + 1500]
        assert "_tip-pg-stats" in after_fetch, (
            "Live probe must update _tip-pg-stats element with fresh stats cells"
        )
        assert "events_rows" in after_fetch, (
            "Live probe must include events_rows in refreshed stats cells"
        )
        assert "db_bytes" in after_fetch, (
            "Live probe must include db_bytes in refreshed stats cells"
        )
