"""
tests/test_v187_new_features.py — QA tests for v1.8.7 feature additions.

Features under test
───────────────────
M  MaxMind 24-hour last-check timestamp gate
   M01  _MAXMIND_CHECK_TS_PATH constant defined (points to /data/.maxmind_last_check)
   M02  _MAXMIND_MIN_INTERVAL constant is 86 400 (24 h)
   M03  _read_last_check() defined
   M04  _write_last_check() defined
   M05  _maxmind_auto_fetch body calls _read_last_check
   M06  _maxmind_auto_fetch body calls _write_last_check
   M07  _maxmind_auto_fetch logs maxmind_fetch_skipped when within 24 h
   M08  _maxmind_refresh_loop calls _read_last_check
   M09  _maxmind_refresh_loop calls _write_last_check
   M10  _maxmind_refresh_loop wakes hourly (sleep 3600), not daily
   M11  _maxmind_refresh_loop no longer uses THIRTY_DAYS / 30-day file-mtime check
   M12  _read_last_check returns 0.0 when timestamp file is absent
   M13  _read_last_check returns stored float when file exists
   M14  _read_last_check returns 0.0 on corrupt file content
   M15  _write_last_check writes a parseable float timestamp
   M16  _maxmind_auto_fetch skips fetch call when last check < 24 h ago
   M17  _maxmind_auto_fetch proceeds (writes timestamp) when last check ≥ 24 h ago

L  Login page — TOTP credential-fields wrapper
   L01  id="credential-fields" wrapper div present in login.html
   L02  username input is inside #credential-fields
   L03  password input is inside #credential-fields
   L04  TOTP handler hides fields via getElementById('credential-fields')
   L05  .closest('label') call absent from TOTP handler
   L06  totp-step div hidden by default (display:none)

D  Settings page — DB backend sliding-pill toggle
   D01  id="db-track" element present in settings.html
   D02  id="db-thumb" element present in settings.html
   D03  id="db-lbl-sqlite" element present
   D04  id="db-lbl-pg" element present
   D05  dbSetTarget() function defined
   D06  dbToggle() function defined
   D07  dbSetTarget moves db-thumb (left style) for postgres vs sqlite
   D08  dbSetTarget shows/hides db-pg-fields
   D09  dbSetTarget enables/disables btn-db-apply based on _dbOrig comparison
   D10  Apply button handler uses _dbTarget (not radio querySelector)
   D11  No input[type=radio][name=db-backend] elements remain

N  Monitoring section moved Controls → Logs
   N01  controls.html: monitoring entry absent from SECTIONS array
   N02  controls.html: card-active-rules absent from CARD_SEC map
   N03  controls.html: card-lists-snap absent from CARD_SEC map
   N04  controls.html: card-ep-policies absent from CARD_SEC map
   N05  controls.html: loadActiveRules() function not defined in script
   N06  controls.html: loadLists() function not defined in script
   N07  controls.html: id="card-active-rules" HTML element absent
   N08  controls.html: id="card-lists-snap" HTML element absent
   N09  controls.html: id="card-ep-policies" HTML element absent
   N10  logs.html: id="card-active-rules" section present
   N11  logs.html: id="active-rules-tbl" table present
   N12  logs.html: id="chal-rate" element present
   N13  logs.html: id="card-lists-snap" section present
   N14  logs.html: id="lists-snap" content div present
   N15  logs.html: id="card-ep-policies" section present
   N16  logs.html: id="ep-policies-tbl" table present
   N17  logs.html: async function loadActiveRules defined
   N18  logs.html: async function loadLists defined
   N19  logs.html: monitoring JS uses _gwAlert (not showToast)
   N20  logs.html: monitoring JS refreshes every 7 000 ms
   N21  logs.html: detector-stats fetch path present
   N22  logs.html: lists-snapshot fetch path present
   N23  logs.html: monitoring monitoring cards appear after #card-audit-log
"""

import re
import time
import tempfile
import os
from pathlib import Path

import pytest

_ROOT       = Path(__file__).resolve().parent.parent
_DASHBOARDS = _ROOT / "dashboards"
_REPUTATION = _ROOT / "reputation"


# ── source helpers ────────────────────────────────────────────────────────────

def _dash(name: str) -> str:
    return (_DASHBOARDS / name).read_text(encoding="utf-8")

def _mm_src() -> str:
    return (_REPUTATION / "maxmind.py").read_text(encoding="utf-8")

def _fn_body(src: str, fn_name: str, max_chars: int = 2000) -> str:
    """Return up to max_chars of source starting at the given function definition."""
    idx = src.find(f"def {fn_name}")
    if idx == -1:
        return ""
    return src[idx: idx + max_chars]


# ═══════════════════════════════════════════════════════════════════════════════
# M — MaxMind 24-hour gate (source analysis)
# ═══════════════════════════════════════════════════════════════════════════════

class TestMaxmind24hGateSource:

    def test_M01_check_ts_path_constant(self):
        src = _mm_src()
        assert "_MAXMIND_CHECK_TS_PATH" in src, \
            "reputation/maxmind.py: _MAXMIND_CHECK_TS_PATH constant not defined"
        assert "/data/.maxmind_last_check" in src, \
            "reputation/maxmind.py: expected path /data/.maxmind_last_check not found"

    def test_M02_min_interval_is_86400(self):
        src = _mm_src()
        assert "_MAXMIND_MIN_INTERVAL" in src, \
            "reputation/maxmind.py: _MAXMIND_MIN_INTERVAL constant not defined"
        assert "86400" in _fn_body(src, "_MAXMIND_MIN_INTERVAL".replace("def ", "")) or \
               re.search(r"_MAXMIND_MIN_INTERVAL\s*=\s*86400", src), \
            "reputation/maxmind.py: _MAXMIND_MIN_INTERVAL != 86400"

    def test_M03_read_last_check_defined(self):
        assert "def _read_last_check" in _mm_src(), \
            "reputation/maxmind.py: _read_last_check not defined"

    def test_M04_write_last_check_defined(self):
        assert "def _write_last_check" in _mm_src(), \
            "reputation/maxmind.py: _write_last_check not defined"

    def test_M05_auto_fetch_calls_read_last_check(self):
        body = _fn_body(_mm_src(), "_maxmind_auto_fetch")
        assert "_read_last_check" in body, \
            "_maxmind_auto_fetch must call _read_last_check() to enforce the 24-h gate"

    def test_M06_auto_fetch_calls_write_last_check(self):
        body = _fn_body(_mm_src(), "_maxmind_auto_fetch")
        assert "_write_last_check" in body, \
            "_maxmind_auto_fetch must call _write_last_check() to record the attempt"

    def test_M07_auto_fetch_logs_skip_event(self):
        body = _fn_body(_mm_src(), "_maxmind_auto_fetch")
        assert "maxmind_fetch_skipped" in body, \
            "_maxmind_auto_fetch must log 'maxmind_fetch_skipped' when skipping"

    def test_M08_refresh_loop_calls_read_last_check(self):
        body = _fn_body(_mm_src(), "_maxmind_refresh_loop", max_chars=3000)
        assert "_read_last_check" in body, \
            "_maxmind_refresh_loop must gate on _read_last_check()"

    def test_M09_refresh_loop_calls_write_last_check(self):
        body = _fn_body(_mm_src(), "_maxmind_refresh_loop", max_chars=3000)
        assert "_write_last_check" in body, \
            "_maxmind_refresh_loop must call _write_last_check() after each fetch"

    def test_M10_refresh_loop_wakes_hourly(self):
        body = _fn_body(_mm_src(), "_maxmind_refresh_loop", max_chars=3000)
        assert "asyncio.sleep(3600)" in body, \
            "_maxmind_refresh_loop must sleep 3600 s (hourly) not 86400 s (daily)"
        assert "asyncio.sleep(86400)" not in body, \
            "_maxmind_refresh_loop must not sleep 86400 s — the 24-h gate is now timestamp-based"

    def test_M11_refresh_loop_no_thirty_day_check(self):
        body = _fn_body(_mm_src(), "_maxmind_refresh_loop", max_chars=3000)
        assert "THIRTY_DAYS" not in body, \
            "_maxmind_refresh_loop must not use THIRTY_DAYS; staleness is now controlled by the 24-h timestamp gate"
        assert "getmtime" not in body, \
            "_maxmind_refresh_loop must not check file mtime; staleness is now controlled by the 24-h timestamp gate"


# ── M12-M17: functional tests (no live network; patches the TS path) ─────────

class TestMaxmind24hGateFunctional:
    """Directly exercises _read_last_check / _write_last_check / _maxmind_auto_fetch
    by patching _MAXMIND_CHECK_TS_PATH on the loaded module."""

    @pytest.fixture(autouse=True)
    def _mm_module(self, tmp_path, monkeypatch):
        import sys
        # Ensure the project root is on sys.path
        proj = str(_ROOT)
        if proj not in sys.path:
            sys.path.insert(0, proj)
        # Remove cached module so the fresh import picks up our env patches
        for key in list(sys.modules.keys()):
            if "reputation.maxmind" in key or key == "reputation.maxmind":
                del sys.modules[key]
        # Minimal env so config/state imports don't explode
        monkeypatch.setenv("UPSTREAM", "https://example.com")
        monkeypatch.setenv("ADMIN_KEY", "test-key")
        monkeypatch.setenv("DB_PATH", str(tmp_path / "antibot.db"))
        monkeypatch.setenv("ALLOWED_HOSTS", "")
        monkeypatch.setenv("ADMIN_ALLOWED_IPS", "")
        try:
            import reputation.maxmind as mm
        except Exception:
            pytest.skip("Could not import reputation.maxmind (env not fully set up)")
        ts_file = str(tmp_path / ".maxmind_last_check")
        monkeypatch.setattr(mm, "_MAXMIND_CHECK_TS_PATH", ts_file)
        self.mm = mm
        self.ts_file = ts_file
        self.tmp_path = tmp_path

    def test_M12_read_last_check_missing_file(self):
        assert self.mm._read_last_check() == 0.0, \
            "_read_last_check must return 0.0 when the timestamp file does not exist"

    def test_M13_read_last_check_valid_file(self):
        ts = 1700000000.123
        Path(self.ts_file).write_text(str(ts))
        result = self.mm._read_last_check()
        assert abs(result - ts) < 0.01, \
            f"_read_last_check returned {result!r}, expected ~{ts}"

    def test_M14_read_last_check_corrupt_file(self):
        Path(self.ts_file).write_text("not-a-number")
        assert self.mm._read_last_check() == 0.0, \
            "_read_last_check must return 0.0 on corrupt/non-numeric file content"

    def test_M15_write_last_check_writes_parseable_float(self):
        before = time.time()
        self.mm._write_last_check()
        after = time.time()
        raw = Path(self.ts_file).read_text().strip()
        ts = float(raw)
        assert before <= ts <= after + 1, \
            f"_write_last_check wrote {raw!r} which is outside [{before}, {after}]"

    def test_M16_auto_fetch_skips_within_24h(self, monkeypatch):
        # Write a very recent timestamp
        self.mm._write_last_check()
        fetch_calls = []
        monkeypatch.setattr(self.mm, "_maxmind_fetch_edition",
                            lambda *a, **kw: fetch_calls.append(a) or "skipped")
        monkeypatch.setenv("MAXMIND_LICENSE_KEY", "fake-key")
        self.mm._maxmind_auto_fetch()
        assert fetch_calls == [], \
            "_maxmind_auto_fetch must not call _maxmind_fetch_edition when last check < 24 h ago"

    def test_M17_auto_fetch_proceeds_when_no_timestamp(self, monkeypatch, tmp_path):
        # No timestamp file → elapsed is huge → should proceed
        fetch_calls = []
        monkeypatch.setattr(self.mm, "_maxmind_fetch_edition",
                            lambda *a, **kw: fetch_calls.append(a) or "skipped")
        monkeypatch.setenv("MAXMIND_LICENSE_KEY", "fake-key")
        self.mm._maxmind_auto_fetch()
        # timestamp file must have been written
        assert Path(self.ts_file).exists(), \
            "_maxmind_auto_fetch must write the timestamp file before attempting fetch"
        assert len(fetch_calls) > 0, \
            "_maxmind_auto_fetch must call _maxmind_fetch_edition when no prior timestamp exists"


# ═══════════════════════════════════════════════════════════════════════════════
# L — Login TOTP credential-fields wrapper
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoginTotpFix:

    @pytest.fixture(scope="class")
    def src(self):
        return _dash("login.html")

    def test_L01_credential_fields_wrapper_present(self, src):
        assert 'id="credential-fields"' in src or "id='credential-fields'" in src, \
            "login.html: #credential-fields wrapper div must exist"

    def test_L02_username_input_inside_wrapper(self, src):
        # Find the wrapper block and confirm username is inside it
        m = re.search(
            r'id=["\']credential-fields["\'][^>]*>(.*?)</div>',
            src, re.DOTALL
        )
        assert m, "login.html: #credential-fields wrapper not found"
        assert 'id="username"' in m.group(1) or "id='username'" in m.group(1), \
            "login.html: username input must be inside #credential-fields"

    def test_L03_password_input_inside_wrapper(self, src):
        m = re.search(
            r'id=["\']credential-fields["\'][^>]*>(.*?)</div>',
            src, re.DOTALL
        )
        assert m, "login.html: #credential-fields wrapper not found"
        assert 'id="password"' in m.group(1) or "id='password'" in m.group(1), \
            "login.html: password input must be inside #credential-fields"

    def test_L04_totp_hides_credential_fields_by_id(self, src):
        # The TOTP handler must hide via getElementById('credential-fields')
        assert "getElementById('credential-fields')" in src or \
               'getElementById("credential-fields")' in src, \
            "login.html: TOTP handler must hide fields via getElementById('credential-fields')"

    def test_L05_no_closest_label_in_source(self, src):
        assert ".closest('label')" not in src and '.closest("label")' not in src, \
            "login.html: .closest('label') still present — this caused the null-deref crash"

    def test_L06_totp_step_hidden_by_default(self, src):
        m = re.search(r'id=["\']totp-step["\'][^>]*>', src)
        assert m, "login.html: #totp-step element not found"
        assert "display:none" in m.group(0) or "display: none" in m.group(0), \
            "login.html: #totp-step must be hidden by default (display:none)"


# ═══════════════════════════════════════════════════════════════════════════════
# D — Settings DB backend sliding-pill toggle
# ═══════════════════════════════════════════════════════════════════════════════

class TestSettingsDbToggle:

    @pytest.fixture(scope="class")
    def src(self):
        return _dash("settings.html")

    def test_D01_db_track_element(self, src):
        assert 'id="db-track"' in src or "id='db-track'" in src, \
            "settings.html: id='db-track' toggle element not found"

    def test_D02_db_thumb_element(self, src):
        assert 'id="db-thumb"' in src or "id='db-thumb'" in src, \
            "settings.html: id='db-thumb' thumb element not found"

    def test_D03_db_lbl_sqlite_element(self, src):
        assert 'id="db-lbl-sqlite"' in src or "id='db-lbl-sqlite'" in src, \
            "settings.html: id='db-lbl-sqlite' label element not found"

    def test_D04_db_lbl_pg_element(self, src):
        assert 'id="db-lbl-pg"' in src or "id='db-lbl-pg'" in src, \
            "settings.html: id='db-lbl-pg' label element not found"

    def test_D05_db_set_target_function_defined(self, src):
        assert "function dbSetTarget" in src, \
            "settings.html: dbSetTarget() function not defined"

    def test_D06_db_toggle_function_defined(self, src):
        assert "function dbToggle" in src, \
            "settings.html: dbToggle() function not defined"

    def test_D07_db_set_target_moves_thumb(self, src):
        idx = src.find("function dbSetTarget")
        assert idx != -1
        body = src[idx: idx + 600]
        assert "db-thumb" in body, \
            "dbSetTarget must manipulate #db-thumb"
        assert "style.left" in body or "left" in body, \
            "dbSetTarget must update the thumb position (left) when switching backends"

    def test_D08_db_set_target_shows_hides_pg_fields(self, src):
        idx = src.find("function dbSetTarget")
        body = src[idx: idx + 600]
        assert "db-pg-fields" in body, \
            "dbSetTarget must show/hide #db-pg-fields based on the selected backend"
        assert "display" in body, \
            "dbSetTarget must set display style on #db-pg-fields"

    def test_D09_db_set_target_gates_apply_button(self, src):
        idx = src.find("function dbSetTarget")
        body = src[idx: idx + 600]
        assert "btn-db-apply" in body, \
            "dbSetTarget must enable/disable #btn-db-apply based on whether selection differs from _dbOrig"
        assert "_dbOrig" in body, \
            "dbSetTarget must compare selection against _dbOrig to set the Apply button state"

    def test_D10_apply_handler_uses_db_target_variable(self, src):
        # Find btn-db-apply click handler
        idx = src.find("btn-db-apply")
        while idx != -1:
            snippet = src[idx: idx + 300]
            if "addEventListener" in snippet or "click" in snippet.lower():
                # the handler body must reference _dbTarget, not radio querySelector
                handler_idx = src.find("'click'", idx)
                if handler_idx == -1:
                    handler_idx = src.find('"click"', idx)
                if handler_idx != -1:
                    handler_body = src[handler_idx: handler_idx + 400]
                    assert "_dbTarget" in handler_body, \
                        "Apply handler must read _dbTarget, not document.querySelector radio"
                    assert 'querySelector' not in handler_body or \
                           'db-backend' not in handler_body, \
                        "Apply handler must not use querySelector for radio input"
                    break
            idx = src.find("btn-db-apply", idx + 1)

    def test_D11_no_radio_inputs_for_db_backend(self, src):
        radio_matches = re.findall(
            r'<input[^>]+type=["\']radio["\'][^>]+name=["\']db-backend["\']',
            src, re.IGNORECASE
        )
        assert len(radio_matches) == 0, \
            f"settings.html: {len(radio_matches)} radio input(s) with name=db-backend remain; " \
            "should be replaced by the sliding-pill toggle"


# ═══════════════════════════════════════════════════════════════════════════════
# N — Monitoring section moved Controls → Logs
# ═══════════════════════════════════════════════════════════════════════════════

class TestMonitoringMovedToLogs:

    @pytest.fixture(scope="class")
    def ctrl(self):
        return _dash("controls.html")

    @pytest.fixture(scope="class")
    def logs(self):
        return _dash("logs.html")

    # ── Controls: monitoring must be gone ────────────────────────────────────

    def test_N01_monitoring_absent_from_sections_array(self, ctrl):
        # Find SECTIONS array content
        m = re.search(r"const SECTIONS\s*=\s*\[(.*?)\];", ctrl, re.DOTALL)
        assert m, "controls.html: SECTIONS array not found"
        sections_body = m.group(1)
        assert "'monitoring'" not in sections_body and '"monitoring"' not in sections_body, \
            "controls.html: {id:'monitoring'} entry must be removed from SECTIONS array"

    def test_N02_card_active_rules_absent_from_card_sec(self, ctrl):
        m = re.search(r"const CARD_SEC\s*=\s*\{(.*?)\};", ctrl, re.DOTALL)
        assert m, "controls.html: CARD_SEC object not found"
        body = m.group(1)
        assert "card-active-rules" not in body, \
            "controls.html: 'card-active-rules': 'monitoring' must be removed from CARD_SEC"

    def test_N03_card_lists_snap_absent_from_card_sec(self, ctrl):
        m = re.search(r"const CARD_SEC\s*=\s*\{(.*?)\};", ctrl, re.DOTALL)
        body = m.group(1) if m else ""
        assert "card-lists-snap" not in body, \
            "controls.html: 'card-lists-snap': 'monitoring' must be removed from CARD_SEC"

    def test_N04_card_ep_policies_absent_from_card_sec(self, ctrl):
        m = re.search(r"const CARD_SEC\s*=\s*\{(.*?)\};", ctrl, re.DOTALL)
        body = m.group(1) if m else ""
        assert "card-ep-policies" not in body, \
            "controls.html: 'card-ep-policies': 'monitoring' must be removed from CARD_SEC"

    def test_N05_load_active_rules_not_defined_in_controls(self, ctrl):
        assert "async function loadActiveRules" not in ctrl and \
               "function loadActiveRules" not in ctrl, \
            "controls.html: loadActiveRules() is still defined — monitoring IIFE not fully removed"

    def test_N06_load_lists_not_defined_in_controls(self, ctrl):
        # 'loadLists' may appear as a call in the main Promise.all at startup —
        # what must be absent is the function *definition*.
        assert "async function loadLists" not in ctrl and \
               "function loadLists(" not in ctrl, \
            "controls.html: loadLists() is still defined — monitoring IIFE not fully removed"

    def test_N07_card_active_rules_html_absent_from_controls(self, ctrl):
        # The HTML element id="card-active-rules" must not exist as a tag attribute
        assert not re.search(r'id=["\']card-active-rules["\']', ctrl), \
            "controls.html: id='card-active-rules' HTML element still present — HTML card not removed"

    def test_N08_card_lists_snap_html_absent_from_controls(self, ctrl):
        assert not re.search(r'id=["\']card-lists-snap["\']', ctrl), \
            "controls.html: id='card-lists-snap' HTML element still present"

    def test_N09_card_ep_policies_html_absent_from_controls(self, ctrl):
        assert not re.search(r'id=["\']card-ep-policies["\']', ctrl), \
            "controls.html: id='card-ep-policies' HTML element still present"

    # ── Logs: monitoring must be present ─────────────────────────────────────

    def test_N10_logs_active_rules_card_present(self, logs):
        assert re.search(r'id=["\']card-active-rules["\']', logs), \
            "logs.html: id='card-active-rules' section not found — card not added"

    def test_N11_logs_active_rules_table_present(self, logs):
        assert re.search(r'id=["\']active-rules-tbl["\']', logs), \
            "logs.html: id='active-rules-tbl' table not found"

    def test_N12_logs_chal_rate_element_present(self, logs):
        assert re.search(r'id=["\']chal-rate["\']', logs), \
            "logs.html: id='chal-rate' element not found (challenge-cookie mint stats)"

    def test_N13_logs_lists_snap_card_present(self, logs):
        assert re.search(r'id=["\']card-lists-snap["\']', logs), \
            "logs.html: id='card-lists-snap' section not found"

    def test_N14_logs_lists_snap_div_present(self, logs):
        assert re.search(r'id=["\']lists-snap["\']', logs), \
            "logs.html: id='lists-snap' content div not found"

    def test_N15_logs_ep_policies_card_present(self, logs):
        assert re.search(r'id=["\']card-ep-policies["\']', logs), \
            "logs.html: id='card-ep-policies' section not found"

    def test_N16_logs_ep_policies_table_present(self, logs):
        assert re.search(r'id=["\']ep-policies-tbl["\']', logs), \
            "logs.html: id='ep-policies-tbl' table not found"

    def test_N17_logs_load_active_rules_defined(self, logs):
        assert "async function loadActiveRules" in logs, \
            "logs.html: loadActiveRules() async function not defined in monitoring JS block"

    def test_N18_logs_load_lists_defined(self, logs):
        assert "async function loadLists" in logs, \
            "logs.html: loadLists() async function not defined in monitoring JS block"

    def test_N19_logs_monitoring_uses_gwAlert(self, logs):
        # Find the monitoring IIFE (after card-ep-policies)
        idx = logs.find("async function loadActiveRules")
        assert idx != -1
        monitoring_js = logs[idx: idx + 3000]
        assert "_gwAlert" in monitoring_js, \
            "logs.html: monitoring JS must use _gwAlert() (not showToast which doesn't exist in logs.html)"
        assert "showToast" not in monitoring_js, \
            "logs.html: monitoring JS must not call showToast() — function is undefined in logs.html"

    def test_N20_logs_monitoring_refreshes_every_7s(self, logs):
        # The setInterval is at the end of the monitoring IIFE, after both functions.
        # Search the full monitoring block (from the COL_M declaration to the IIFE close).
        idx = logs.find("COL_M = {")
        if idx == -1:
            idx = logs.find("async function loadActiveRules")
        assert idx != -1, "logs.html: monitoring IIFE not found"
        monitoring_js = logs[idx: idx + 6000]
        assert "7000" in monitoring_js, \
            "logs.html: monitoring JS must setInterval every 7000 ms"

    def test_N21_logs_monitoring_fetches_detector_stats(self, logs):
        idx = logs.find("async function loadActiveRules")
        assert idx != -1
        fn_body = logs[idx: idx + 1000]
        assert "detector-stats" in fn_body, \
            "logs.html: loadActiveRules must fetch /secured/detector-stats"

    def test_N22_logs_monitoring_fetches_lists_snapshot(self, logs):
        idx = logs.find("async function loadLists")
        assert idx != -1
        fn_body = logs[idx: idx + 1000]
        assert "lists-snapshot" in fn_body, \
            "logs.html: loadLists must fetch /secured/lists-snapshot"

    def test_N23_monitoring_cards_appear_after_audit_log(self, logs):
        audit_pos      = logs.find('id="card-audit-log"')
        active_pos     = logs.find('id="card-active-rules"')
        lists_pos      = logs.find('id="card-lists-snap"')
        ep_pos         = logs.find('id="card-ep-policies"')
        assert audit_pos != -1,  "logs.html: #card-audit-log not found"
        assert active_pos != -1, "logs.html: #card-active-rules not found"
        assert lists_pos  != -1, "logs.html: #card-lists-snap not found"
        assert ep_pos     != -1, "logs.html: #card-ep-policies not found"
        assert audit_pos < active_pos, \
            "logs.html: #card-active-rules must appear after #card-audit-log"
        assert audit_pos < lists_pos, \
            "logs.html: #card-lists-snap must appear after #card-audit-log"
        assert audit_pos < ep_pos, \
            "logs.html: #card-ep-policies must appear after #card-audit-log"
