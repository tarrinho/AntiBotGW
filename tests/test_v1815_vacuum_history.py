"""
1.8.15 — VACUUM history + migration guard.

Behaviour:
  * Each VACUUM run is recorded in `gw_audit` (action='db_vacuum') with
    before/after sizes, saved bytes, duration_ms, ok flag.
  * Response includes `history` — last 5 runs (newest first).
  * GET /secured/db-vacuum-history returns the same list without triggering
    a new VACUUM.
  * Migration guard: if `_BG_MIGRATION["running"]` is True → 409 Conflict.
  * Single-flight: a second concurrent VACUUM → 409 Conflict.
  * db_switch_endpoint also refuses while VACUUM is in flight.

Coverage:
  TestVacuumHistorySourceGuards   — code-level guards
  TestVacuumHistoryUnit           — _vacuum_history reads gw_audit rows
  TestDashboardWiring             — settings.html has history table + load
"""
import pathlib
import sqlite3
import json


_ROOT   = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_PXY_SRC = (_ROOT / "proxy.py").read_text(encoding="utf-8")
_ST_SRC = (_ROOT / "dashboards" / "settings.html").read_text(encoding="utf-8")


# ── 1. Source guards ────────────────────────────────────────────────────────

class TestVacuumHistorySourceGuards:

    def test_history_helper_exists(self):
        assert "def _vacuum_history(conn" in _PH_SRC, (
            "_vacuum_history helper must exist"
        )

    def test_vacuum_records_to_gw_audit(self):
        idx = _PH_SRC.find("async def _db_vacuum_execute(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "INSERT INTO gw_audit" in block, (
            "VACUUM run must INSERT into gw_audit for history"
        )
        assert "'db_vacuum'" in block, (
            "audit row must use action='db_vacuum'"
        )
        assert "duration_ms" in block, (
            "audit details must include duration_ms"
        )

    def test_response_includes_history(self):
        idx = _PH_SRC.find("async def _db_vacuum_execute(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert '"history": history' in block or "\"history\": history" in block, (
            "VACUUM response must include 'history' field"
        )

    def test_get_history_endpoint_exists(self):
        assert "async def db_vacuum_history_endpoint(" in _PH_SRC, (
            "GET /secured/db-vacuum-history endpoint must exist"
        )

    def test_get_history_endpoint_routed(self):
        assert '"db-vacuum-history"' in _PXY_SRC or "'db-vacuum-history'" in _PXY_SRC, (
            "db-vacuum-history route must be registered in proxy.py"
        )

    def test_migration_guard_in_vacuum(self):
        idx = _PH_SRC.find("async def db_vacuum_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_BG_MIGRATION" in block, (
            "VACUUM endpoint must consult _BG_MIGRATION['running']"
        )
        assert "409" in block, (
            "VACUUM must return 409 Conflict during migration"
        )

    def test_single_flight_lock(self):
        assert "_DB_VACUUM_LOCK" in _PH_SRC, (
            "_DB_VACUUM_LOCK must guard against concurrent VACUUMs"
        )
        idx = _PH_SRC.find("async def db_vacuum_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_DB_VACUUM_LOCK.locked()" in block, (
            "endpoint must short-circuit if lock already held"
        )

    def test_switch_guarded_against_vacuum(self):
        """db_switch_endpoint must also refuse while VACUUM is running."""
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_DB_VACUUM_LOCK.locked()" in block, (
            "db_switch_endpoint must also check _DB_VACUUM_LOCK"
        )


# ── 2. Unit: _vacuum_history reads what's in gw_audit ──────────────────────

class TestVacuumHistoryUnit:

    def test_returns_rows_newest_first(self, tmp_path):
        import sys
        sys.path.insert(0, str(_ROOT))
        import core.proxy_handler as _cph

        dbp = tmp_path / "t.db"
        conn = sqlite3.connect(str(dbp))
        conn.executescript(
            "CREATE TABLE gw_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "ts REAL NOT NULL, action TEXT NOT NULL, gw_id TEXT, actor TEXT, "
            "details TEXT);"
        )
        # Seed 3 vacuum runs + 1 unrelated audit
        rows = [
            (1000.0, "db_vacuum", "gw1", "alice",
             json.dumps({"ok": True, "saved_bytes": 100, "duration_ms": 5})),
            (2000.0, "db_vacuum", "gw1", "bob",
             json.dumps({"ok": True, "saved_bytes": 200, "duration_ms": 8})),
            (3000.0, "db_vacuum", "gw1", "carol",
             json.dumps({"ok": False, "reason": "disk full",
                         "duration_ms": 2})),
            (1500.0, "config_change", "gw1", "alice", "{}"),
        ]
        conn.executemany(
            "INSERT INTO gw_audit (ts, action, gw_id, actor, details) "
            "VALUES (?, ?, ?, ?, ?)", rows)
        conn.commit()

        history = _cph._vacuum_history(conn, limit=5)
        conn.close()

        assert len(history) == 3, f"must return 3 vacuum runs; got {len(history)}"
        assert history[0]["actor"] == "carol", "newest first"
        assert history[0]["ok"] is False
        assert history[0]["reason"] == "disk full"
        assert history[1]["actor"] == "bob"
        assert history[1]["saved_bytes"] == 200
        assert history[2]["actor"] == "alice"

    def test_limit_caps_result(self, tmp_path):
        import sys
        sys.path.insert(0, str(_ROOT))
        import core.proxy_handler as _cph

        dbp = tmp_path / "t.db"
        conn = sqlite3.connect(str(dbp))
        conn.executescript(
            "CREATE TABLE gw_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "ts REAL NOT NULL, action TEXT NOT NULL, gw_id TEXT, actor TEXT, "
            "details TEXT);"
        )
        for i in range(10):
            conn.execute(
                "INSERT INTO gw_audit (ts, action, gw_id, actor, details) "
                "VALUES (?, 'db_vacuum', 'gw1', 'op', '{}')",
                (float(i),))
        conn.commit()
        history = _cph._vacuum_history(conn, limit=5)
        conn.close()
        assert len(history) == 5, "limit must cap at 5"


# ── 3. Dashboard wiring ────────────────────────────────────────────────────

class TestDashboardWiring:

    def test_history_table_in_settings_html(self):
        assert 'id="vacuum-history"' in _ST_SRC, (
            "settings.html must declare vacuum-history container"
        )
        assert "Last 5 VACUUM runs" in _ST_SRC, (
            "history section heading must read 'Last 5 VACUUM runs'"
        )

    def test_render_function_present(self):
        assert "function renderVacuumHistory(" in _ST_SRC, (
            "settings.html must define renderVacuumHistory"
        )
        assert "function loadVacuumHistory(" in _ST_SRC or \
               "async function loadVacuumHistory(" in _ST_SRC, (
            "settings.html must define loadVacuumHistory"
        )

    def test_load_called_on_init(self):
        # Must be invoked alongside other loaders at boot
        assert "loadVacuumHistory();" in _ST_SRC, (
            "loadVacuumHistory must run on initial load"
        )

    def test_busy_handling(self):
        """409 (busy/migration) must show as warning, not error."""
        idx = _ST_SRC.find("'/antibot-appsec-gateway/secured/db-vacuum'")
        block = _ST_SRC[idx: idx + 1500]
        assert "409" in block, (
            "vacuum click handler must distinguish 409 from generic failure"
        )

    def test_renderer_uses_escapehtml(self):
        idx = _ST_SRC.find("function renderVacuumHistory(")
        nxt = _ST_SRC.find("function ", idx + 30)
        block = _ST_SRC[idx: nxt if nxt != -1 else idx + 3000]
        assert "escapeHtml(" in block, (
            "renderVacuumHistory must escape every user-influenced cell"
        )
