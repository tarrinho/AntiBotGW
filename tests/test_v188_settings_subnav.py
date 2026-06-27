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
        # 3500 chars — handler grew with HTTP-error branches (N-series UI honesty).
        return self.src[idx: idx + 3500]

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
        # Contract-rename align (1.9.x): the probe block aliases db.postgres as
        # `_pg_for_probe` (not the historical `_pg_mod_dbt`). Behaviour is
        # unchanged — it still patches db.postgres.POSTGRES_DSN before the call.
        assert "_pg_for_probe.POSTGRES_DSN = probe_dsn" in code, (
            "db_test_endpoint probe mode must patch db.postgres.POSTGRES_DSN "
            "before calling pg_test_roundtrip() — globals() patch alone is insufficient"
        )

    def test_b02_probe_mode_restores_pg_mod(self):
        src = Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py"
        code = src.read_text(encoding="utf-8")
        # Contract-rename align (1.9.x): restore uses `saved_pg_dsn` (was
        # `_pg_mod_dbt_saved_dsn`). Still restores db.postgres.POSTGRES_DSN in finally.
        assert "_pg_for_probe.POSTGRES_DSN = saved_pg_dsn" in code, (
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
        # Widened window (was 1500): the probe block grew with the 1.9.2
        # iter-25 executor-offload + 25s-timeout comment, pushing the finally
        # restore to ~offset 2266. The set/restore are still in the same block.
        blk = code[idx: idx + 2800]
        # Contract-rename align (1.9.x): `_pg_for_probe` / `saved_pg_dsn`.
        # Both the set and restore must be present in the same block.
        assert "_pg_for_probe.POSTGRES_DSN = probe_dsn" in blk, (
            "probe DSN assignment to db.postgres missing from probe block"
        )
        assert "_pg_for_probe.POSTGRES_DSN = saved_pg_dsn" in blk, (
            "probe DSN restore in finally missing from probe block"
        )
        # Restore must come AFTER set
        idx_set     = blk.index("_pg_for_probe.POSTGRES_DSN = probe_dsn")
        idx_restore = blk.index("_pg_for_probe.POSTGRES_DSN = saved_pg_dsn")
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
        # Contract-rename align (1.9.x): both probe sites alias db.postgres as
        # `_pg_for_probe` (was `_pg_mod` / `_pg_mod_dbt`). Both still patch the
        # module-level POSTGRES_DSN so pg_test_roundtrip sees the caller DSN.
        # db-switch probe (existing, correct)
        assert "_pg_for_probe.POSTGRES_DSN = dsn" in code, (
            "db-switch probe must patch db.postgres.POSTGRES_DSN (existing fix must be intact)"
        )
        # db-test probe (new fix)
        assert "_pg_for_probe.POSTGRES_DSN = probe_dsn" in code, (
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
# Live-probe status + stats + DSN auto-load (L) — _dbShowTip calls /db-test on open
# L01  _dbShowTip fetches /db-test (non-probe, no ?dsn=) for postgres type
# L02  Success path reads pg.available or pg.ok from j.postgres
# L03  Live probe updates _tip-pg-status-val to ✓ reachable on success
# L04  Failure path falls back to "unreachable"
# L05  Failure path shows "DSN not configured" when dsn_masked absent
# L06  Active-but-unreachable shows distinguishing "active · not reachable" label
# L07  Live-probe is guarded by type === 'postgres' (not fired for sqlite)
# L08  _tip-pg-status-val opacity set to 0.5 before fetch (loading indicator)
# L09  opacity restored to 1 after fetch resolves (both ok and error paths)
# L10  Stats grid wrapper has id="_tip-pg-stats" so live probe can update cells
# L11  Live probe rebuilds stats cells (Events, DB size, Latency) from fresh data
# L12  DSN auto-load parses dsn_masked and populates _tip-pg-host/port/db/user
# ─────────────────────────────────────────────────────────────────────────────

class TestDbShowTipLiveProbe:
    """Static-HTML tests verifying the live stats/status/DSN refresh added to _dbShowTip."""

    def setup_method(self):
        self.src = _settings()

    def _dbShowTip_block(self) -> str:
        """Extract the _dbShowTip function body."""
        marker = "window._dbShowTip = function"
        idx = self.src.find(marker)
        assert idx != -1, "_dbShowTip not found in settings.html"
        # 18000 chars covers the full body: render + live probe IIFE (stats grid +
        # dual-write-lag warning + DSN auto-fill + opacity restore) + button wiring.
        return self.src[idx: idx + 18000]

    def _probe_fetch_idx(self, blk: str) -> int:
        # The live probe fetches /db-test (no ?dsn= param)
        # Search for the fetch URL in the live-probe IIFE (not the _tip-pg-test handler)
        # The IIFE appears before "Wire PG save/test"
        wire_idx = blk.find("Wire PG save/test")
        section = blk[:wire_idx] if wire_idx != -1 else blk
        idx = section.find("secured/db-test")
        assert idx != -1, "Live probe fetch to /db-test not found in _dbShowTip (before wire section)"
        return idx

    def test_l01_live_probe_fetches_db_test(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        snippet = blk[probe_idx: probe_idx + 60]
        assert "dsn=" not in snippet, (
            "Live probe must call /db-test without ?dsn= (use configured DSN, not probe DSN)"
        )

    def test_l02_success_reads_available_or_ok(self):
        blk = self._dbShowTip_block()
        assert "pg.available" in blk or "pg.ok" in blk, (
            "Live probe must read pg.available or pg.ok from j.postgres"
        )
        assert "'✓ reachable'" in blk or '"✓ reachable"' in blk, (
            "Live probe success path must set textContent to '✓ reachable'"
        )

    def test_l03_status_tile_updated(self):
        blk = self._dbShowTip_block()
        assert "sv.textContent" in blk, (
            "Live probe must update sv (status tile) textContent"
        )
        assert "'✓ reachable'" in blk or '"✓ reachable"' in blk

    def test_l04_failure_defaults_to_unreachable(self):
        blk = self._dbShowTip_block()
        assert "unreachable" in blk, (
            "Live probe failure path must include 'unreachable' fallback"
        )

    def test_l05_failure_shows_dsn_not_configured(self):
        blk = self._dbShowTip_block()
        assert "DSN not configured" in blk or "not configured" in blk, (
            "Live probe must show 'DSN not configured' when dsn_masked is absent"
        )

    def test_l06_active_backend_label(self):
        blk = self._dbShowTip_block()
        assert "active_backend" in blk or "isActiveBackend" in blk, (
            "Live probe must check j.active_backend to distinguish active-but-unreachable"
        )
        assert "not reachable" in blk or "unreachable" in blk

    def test_l07_postgres_type_guard(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        # 1500-char lookback covers helper definitions + guard + opacity dim
        context_before = blk[max(0, probe_idx - 1500): probe_idx]
        assert "postgres" in context_before, (
            "Live probe fetch must be inside a type === 'postgres' guard"
        )

    def test_l08_opacity_set_before_fetch(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        # 1500-char lookback covers showUiError helper + opacity dim
        before_fetch = blk[max(0, probe_idx - 1500): probe_idx]
        assert "opacity" in before_fetch and "0.5" in before_fetch, (
            "Status tile opacity must be dimmed to 0.5 before the live fetch fires"
        )

    def test_l09_opacity_restored_after_fetch(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        # Window widened (1.8.x) to cover the full success path: the live probe
        # now rebuilds the stats grid + dual-write-lag warning + DSN auto-fill
        # before restoring opacity at the end, so the restore sits well past the
        # original 5500-char window. showUiError also restores it on every error
        # path. Cap at the block length.
        after_fetch = blk[probe_idx: probe_idx + 9000]
        assert "opacity" in after_fetch and ("= '1'" in after_fetch or '= "1"' in after_fetch), (
            "Status tile opacity must be restored to 1 after live probe completes"
        )

    def test_l10_stats_grid_has_id(self):
        assert '_tip-pg-stats' in self.src, (
            "Stats grid wrapper must have id='_tip-pg-stats' so live probe can update it"
        )

    def test_l11_live_probe_rebuilds_stats_cells(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        after_fetch = blk[probe_idx: probe_idx + 2000]
        assert "_tip-pg-stats" in after_fetch, (
            "Live probe must update _tip-pg-stats element with fresh stats cells"
        )
        assert "events_rows" in after_fetch, (
            "Live probe must include events_rows in refreshed stats cells"
        )
        assert "db_bytes" in after_fetch, (
            "Live probe must include db_bytes in refreshed stats cells"
        )

    def test_l12_dsn_auto_load_populates_form(self):
        blk = self._dbShowTip_block()
        probe_idx = self._probe_fetch_idx(blk)
        # 5000 chars — IIFE grew with HTTP-error branches + JSON-parse handling.
        after_fetch = blk[probe_idx: probe_idx + 5000]
        # Must parse dsn_masked and set form fields
        assert "dsn_masked" in after_fetch, (
            "Live probe must read j.postgres.dsn_masked to auto-populate form fields"
        )
        for field_id in ("_tip-pg-host", "_tip-pg-port", "_tip-pg-db", "_tip-pg-user"):
            assert field_id in after_fetch, (
                f"Live probe must populate form field '{field_id}' from parsed dsn_masked"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Load DSN button + hot-apply Save tests (M)
# M01  Explicit "Load DSN" button (id="_tip-pg-load") rendered in popup
# M02  Load button onclick wired with fetch to /db-test
# M03  Load button onclick parses dsn_masked with regex
# M04  Load button shows green ✓ feedback in _tip-pg-res on success
# M05  Load button shows dim ℹ feedback when no saved DSN
# M06  Save DSN toast message updated: "applied immediately" (not "restart to apply")
# M07  Auto-load shows ℹ feedback when no saved DSN
# M08  secrets_endpoint propagates POSTGRES_DSN via _propagate_global (hot-apply)
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadDsnButtonAndHotApply:
    """Tests for the explicit Load DSN button + Save DSN hot-apply fix."""

    def setup_method(self):
        self.src = _settings()

    def test_m01_load_button_rendered(self):
        assert '_tip-pg-load' in self.src, (
            "Popup must include id='_tip-pg-load' for the explicit Load DSN button"
        )
        assert 'Load DSN' in self.src, (
            "Load button label must say 'Load DSN'"
        )

    def _load_btn_handler(self) -> str:
        """Extract the Load button onclick handler body."""
        # The handler is bound as loadBtn.onclick after locating the button.
        # 3000 chars covers the body including HTTP-error branches + success path.
        idx = self.src.find("loadBtn.onclick")
        assert idx != -1, (
            "Load button onclick handler not wired in settings.html "
            "(expected 'loadBtn.onclick = ...' binding)"
        )
        return self.src[idx: idx + 3000]

    def test_m02_load_button_calls_db_test(self):
        block = self._load_btn_handler()
        assert "secured/db-test" in block, (
            "Load button must fetch /secured/db-test (no probe DSN)"
        )

    def test_m03_load_button_parses_dsn_masked(self):
        block = self._load_btn_handler()
        assert "dsn_masked" in block, (
            "Load button must parse dsn_masked from response"
        )
        for field_id in ("_tip-pg-host", "_tip-pg-port", "_tip-pg-db", "_tip-pg-user"):
            assert field_id in block, f"Load button must populate {field_id}"

    def test_m04_load_button_success_feedback(self):
        block = self._load_btn_handler()
        assert "loaded" in block.lower(), (
            "Load button must show 'loaded' confirmation on success"
        )
        assert "var(--green)" in block, (
            "Load button success path must use green color"
        )

    def test_m05_load_button_no_dsn_feedback(self):
        block = self._load_btn_handler()
        assert "no saved DSN" in block, (
            "Load button must show 'no saved DSN' when dsn_masked is empty"
        )

    def test_m06_save_toast_says_applied_immediately(self):
        assert "applied immediately" in self.src, (
            "Save DSN toast must say 'applied immediately' (hot-apply, not restart)"
        )
        assert "restart to apply" not in self.src, (
            "Save DSN toast must NOT say 'restart to apply' anymore"
        )

    def test_m07_auto_load_shows_no_dsn_feedback(self):
        # The live-probe IIFE should also show feedback when dsn_masked is empty
        blk = self._dbShowTip_block_full()
        assert "no saved DSN" in blk, (
            "Auto-load (live probe IIFE) must show 'no saved DSN' feedback when empty"
        )

    def _dbShowTip_block_full(self):
        marker = "window._dbShowTip = function"
        idx = self.src.find(marker)
        assert idx != -1
        # 12000 chars covers full body including auto-load IIFE + Load button wiring
        return self.src[idx: idx + 12000]

    # ──────────────────────────────────────────────────────────────────────
    # UI honesty (N) — popup must distinguish "can't read status" from "DB unreachable"
    # N01  Live-probe IIFE has a showUiError helper (or equivalent dim-coloured branch)
    # N02  HTTP non-ok in live probe → "status unknown" (NOT "unreachable")
    # N03  Live probe surfaces HTTP status code in the message
    # N04  Live probe distinguishes 404/403 (admin-allowlist) from generic HTTP errors
    # N05  Live probe handles JSON parse failure separately
    # N06  Test button distinguishes HTTP failure from real DB-unreachable
    # N07  Test button no longer says "network error" for non-network failures
    # N08  Load button distinguishes HTTP/JSON errors from "no saved DSN"
    # N09  All UI-error messages clarify "the DB itself may still be fine"
    # ──────────────────────────────────────────────────────────────────────

    def _live_probe_block(self) -> str:
        marker = "On popup open: load current config + refresh status + stats"
        idx = self.src.find(marker)
        assert idx != -1, "Live-probe IIFE marker not found"
        return self.src[idx: idx + 4500]

    def test_n01_live_probe_has_ui_error_helper(self):
        blk = self._live_probe_block()
        assert "showUiError" in blk or "status unknown" in blk, (
            "Live probe must have a dedicated UI-error helper or branch"
        )

    def test_n02_http_error_shows_status_unknown_not_unreachable(self):
        blk = self._live_probe_block()
        # The HTTP-error branch must say "status unknown" and NOT silently fall
        # through to "unreachable". Look at the !r.ok branch.
        assert "status unknown" in blk, (
            "On HTTP error, popup must show 'status unknown' (UI couldn't read), "
            "not 'unreachable' (which would lie about DB state)"
        )

    def test_n03_http_status_code_surfaced(self):
        blk = self._live_probe_block()
        assert "HTTP ${r.status}" in blk or "r.status" in blk, (
            "Live probe must surface the actual HTTP status code in the error message"
        )

    def test_n04_distinguishes_admin_blocked_from_generic_http(self):
        blk = self._live_probe_block()
        assert "403" in blk and "404" in blk, (
            "Live probe must explicitly handle 403/404 (admin-allowlist) cases"
        )
        assert "allowlist" in blk.lower() or "session" in blk.lower(), (
            "Live probe 403/404 message must mention allowlist or session as likely cause"
        )

    def test_n05_handles_json_parse_failure(self):
        blk = self._live_probe_block()
        assert "parse" in blk.lower() or "not valid JSON" in blk or "not JSON" in blk, (
            "Live probe must handle non-JSON responses separately (admin endpoint "
            "may return HTML decoy with HTTP 200 — JSON parse would throw)"
        )

    def test_n06_test_button_distinguishes_http_vs_db_failure(self):
        test_idx = self.src.find("_tip-pg-test').onclick")
        assert test_idx != -1
        blk = self.src[test_idx: test_idx + 3000]
        # Must check r.ok explicitly and surface HTTP error separately
        assert "r.ok" in blk or "!r.ok" in blk, (
            "Test button must check r.ok before parsing JSON"
        )
        assert "HTTP" in blk and "status unknown" in blk.lower() or "HTTP" in blk, (
            "Test button HTTP-error branch must surface HTTP status"
        )

    def test_n07_test_button_no_silent_network_error(self):
        test_idx = self.src.find("_tip-pg-test').onclick")
        assert test_idx != -1
        blk = self.src[test_idx: test_idx + 3000]
        # The OLD code had `catch(e){...textContent='✗ network error'}` for ALL
        # error cases. The new code must distinguish network/HTTP/JSON paths.
        network_err_count = blk.count("network")
        # We should still mention "network" specifically for actual network failures,
        # but NOT use it as the catch-all for HTTP or JSON errors.
        assert "cannot reach gateway" in blk or "network)" in blk, (
            "Test button must use 'cannot reach gateway (network)' only for real network errors"
        )

    def test_n08_load_button_separates_http_from_no_dsn(self):
        idx = self.src.find("loadBtn.onclick")
        assert idx != -1
        blk = self.src[idx: idx + 2500]
        assert "HTTP" in blk and "no saved DSN" in blk, (
            "Load button must distinguish HTTP error (cannot read) from "
            "'no saved DSN' (read fine but nothing configured)"
        )

    def test_n09_ui_errors_clarify_db_state_unknown(self):
        # At least one error message in the live probe should explicitly say
        # the DB itself may still be fine, so the user doesn't panic.
        blk = self._live_probe_block()
        assert "DB" in blk and ("may still be fine" in blk or "still be fine" in blk), (
            "UI error messages must clarify that the DB itself may still be fine "
            "when the UI cannot read the status"
        )

    def test_m08_secrets_endpoint_hot_applies_postgres_dsn(self):
        ph_path = Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py"
        ph = ph_path.read_text(encoding="utf-8")
        # Find the secrets_endpoint function
        idx = ph.find("async def secrets_endpoint")
        assert idx != -1, "secrets_endpoint not found in proxy_handler.py"
        # The propagation lives inside the for-loop body (~line 2078+); the
        # function spans ~150 lines, so search a 12000-char window.
        body = ph[idx: idx + 12000]
        assert '_propagate_global("POSTGRES_DSN"' in body or "_propagate_global('POSTGRES_DSN'" in body, (
            "secrets_endpoint must call _propagate_global for POSTGRES_DSN to "
            "hot-apply the change to db.postgres module (otherwise it stays stale "
            "until container restart)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Backend-aware reads + write-health (P series) — fixes the "armv7 server
# dashboards empty when DB_BACKEND=postgres" + "geomap not reading postgres
# after reboot" bugs reported by the operator.
# P01  db.db_read_events dispatcher exists
# P02  db._read_events_sql implementation exists
# P03  db._read_events_pg implementation exists
# P04  db.db_health_snapshot exists
# P05  geo_data_endpoint uses db_read_events (not hardcoded sqlite3.connect)
# P06  geo_drill_endpoint uses db_read_events
# P07  logs_data_endpoint uses db_read_events
# P08  logs_export_endpoint uses db_read_events
# P09  agents_bucket_detail uses db_read_events (one fetch, multi-classify)
# P10  health_score_endpoint uses db_read_events
# P11  metrics_endpoint (path-filter timeline) uses db_read_events
# P12  db-test response includes write_health (per-backend lag info)
# P13  Settings popup live-probe surfaces write_health lag warning
# P14  _events_health_sql returns dict with last_event_ts + events_rows
# P15  Helper enforces column whitelist (raises on invalid column)
# P16  Helper enforces order_by whitelist (raises on invalid)
# P17  Helper accepts start_ts=0 for "no lower bound" (logs use case)
# ─────────────────────────────────────────────────────────────────────────────

class TestBackendAwareReads:
    """Tests for the 1.8.8 backend-aware event-reader + write-health refactor."""

    def setup_method(self):
        self.ph_src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()

    def test_p01_db_read_events_dispatcher_exists(self):
        db_init = (Path(__file__).resolve().parent.parent / "db" / "__init__.py").read_text()
        assert "def db_read_events" in db_init, (
            "db.db_read_events dispatcher must exist for backend-aware event reads"
        )
        assert "DB_BACKEND" in db_init and "_postgres_available" in db_init, (
            "db_read_events must dispatch based on DB_BACKEND + _postgres_available"
        )

    def test_p02_read_events_sql_exists(self):
        sql_src = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text()
        assert "def _read_events_sql" in sql_src, (
            "db.sqlite._read_events_sql implementation must exist"
        )

    def test_p03_read_events_pg_exists(self):
        pg_src = (Path(__file__).resolve().parent.parent / "db" / "postgres.py").read_text()
        assert "def _read_events_pg" in pg_src, (
            "db.postgres._read_events_pg implementation must exist"
        )
        assert "EXTRACT(EPOCH FROM ts)" in pg_src, (
            "_read_events_pg must convert TIMESTAMPTZ to epoch float via EXTRACT(EPOCH FROM ts)"
        )

    def test_p04_db_health_snapshot_exists(self):
        db_init = (Path(__file__).resolve().parent.parent / "db" / "__init__.py").read_text()
        assert "def db_health_snapshot" in db_init, (
            "db.db_health_snapshot must exist for per-backend write-health observability"
        )
        for k in ("active_backend", "lag_seconds", "healthy", "sqlite", "postgres"):
            assert f'"{k}"' in db_init, f"db_health_snapshot must return key '{k}'"

    @pytest.mark.parametrize("fn", [
        "geo_data_endpoint",
        "geo_drill_endpoint",
        "logs_data_endpoint",
        "logs_export_endpoint",
        "agents_bucket_detail_endpoint",
        "health_score_endpoint",
        "metrics_endpoint",
    ])
    def test_p05_to_p11_endpoints_use_db_read_events(self, fn):
        """Each affected dashboard endpoint must read events in a backend-aware
        way (so postgres dashboards aren't empty on armv7). The original
        contract required the db_read_events dispatcher, but the 1.9.1 (iter-17)
        redesign routes these endpoints through the backend-aware open_conn()
        helper + dialect-aware SQL (active_backend()=='postgres' branches with
        to_timestamp()/EXTRACT) instead. open_conn() returns a Postgres-backed
        _PgConnWrapper when DB_BACKEND=postgres, so the read is backend-aware
        either way — the failure the test guards against (hardcoded
        sqlite3.connect(DB_PATH)) is gone. Accept either mechanism; what must
        NOT appear is a hardcoded sqlite3.connect(DB_PATH).
        The metrics endpoint's `timeline` table read is intentionally
        SQLite-only and not counted here (pre-aggregated, no Postgres mirror)."""
        fn_start = self.ph_src.find(f"async def {fn}")
        assert fn_start != -1, f"{fn} must exist in core/proxy_handler.py"
        # Pull the function body up to the next async def.
        next_fn = self.ph_src.find("async def ", fn_start + 1)
        body = self.ph_src[fn_start: next_fn if next_fn != -1 else fn_start + 8000]
        assert "sqlite3.connect(DB_PATH)" not in body, (
            f"{fn} must NOT use a hardcoded sqlite3.connect(DB_PATH) — "
            f"that leaves postgres dashboards empty"
        )
        assert ("db_read_events" in body) or ("open_conn(" in body), (
            f"{fn} must read events in a backend-aware way — via db_read_events "
            f"or the backend-aware open_conn() helper"
        )

    def test_p12_db_test_response_includes_write_health(self):
        idx = self.ph_src.find("async def db_test_endpoint")
        assert idx != -1
        # The response is built ~250 lines later
        body = self.ph_src[idx: idx + 8000]
        assert "write_health" in body, (
            "/db-test response must include write_health field for per-backend lag"
        )
        assert "db_health_snapshot" in body, (
            "db_test_endpoint must call db_health_snapshot()"
        )

    def test_p13_popup_surfaces_write_health_lag(self):
        settings = (Path(__file__).resolve().parent.parent / "dashboards" / "settings.html").read_text()
        assert "_tip-pg-lag" in settings, (
            "Popup must contain id='_tip-pg-lag' element to surface dual-write lag"
        )
        assert "write_health" in settings or "j.write_health" in settings, (
            "Popup JS must read write_health from /db-test response"
        )
        assert "Dual-write lag" in settings, (
            "Popup must show 'Dual-write lag' warning when backends disagree"
        )

    def test_p14_events_health_sql_shape(self):
        # Direct import/exec test — verify the function returns the expected shape.
        sql_src = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text()
        assert "def _events_health_sql" in sql_src
        assert "last_event_ts" in sql_src
        assert "events_rows" in sql_src

    def test_p15_column_whitelist_enforced(self):
        sql_src = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text()
        assert "_VALID_EVENT_COLUMNS" in sql_src, (
            "sqlite reader must whitelist column names to prevent SQL injection"
        )
        assert 'raise ValueError(f"invalid event column' in sql_src, (
            "sqlite reader must raise on unknown column names"
        )

    def test_p16_order_by_whitelist_enforced(self):
        sql_src = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text()
        assert "_VALID_ORDER_BY" in sql_src, (
            "sqlite reader must whitelist ORDER BY values"
        )

    def test_p17_no_lower_bound_supported(self):
        sql_src = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text()
        assert "start_ts and start_ts > 0" in sql_src, (
            "sqlite reader must treat start_ts=0 as 'no lower bound' for logs endpoint"
        )
