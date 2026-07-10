"""
tests/test_v187_db_switch_roundtrip.py — Detailed SQLite ↔ PostgreSQL switch tests.

Covers every stage of the switch lifecycle:

  SWITCH-01  Migration SQLite→Postgres: copies rows in window, skips outside
  SWITCH-02  Migration SQLite→Postgres: empty source returns ok=True copied=0
  SWITCH-03  Migration SQLite→Postgres: UA truncated at 500 chars
  SWITCH-04  Migration SQLite→Postgres: None fields coerced to safe defaults
  SWITCH-05  Migration SQLite→Postgres: PG connect failure → ok=False, reason set
  SWITCH-06  Migration SQLite→Postgres: direction string is "sqlite->postgres"
  SWITCH-07  Migration Postgres→SQLite: copies rows, inserts correct columns
  SWITCH-08  Migration Postgres→SQLite: empty source returns ok=True copied=0
  SWITCH-09  Migration Postgres→SQLite: UA truncated at 500 chars
  SWITCH-10  Migration Postgres→SQLite: direction string is "postgres->sqlite"
  SWITCH-11  Migration Postgres→SQLite: PG unavailable → ok=False
  SWITCH-12  Migration: window_secs filter excludes stale rows
  SWITCH-13  Migration: integer row count matches source exactly
  SWITCH-14  Migration: status coerced to int (None→0)
  SWITCH-15  Migration: DB_PATH / POSTGRES_DSN absent → ok=False
  SWITCH-16  db_switch_endpoint: target not in {sqlite,postgres} → 400
  SWITCH-17  db_switch_endpoint: target=postgres, psycopg absent → 400
  SWITCH-18  db_switch_endpoint: target=postgres, no DSN → 400
  SWITCH-19  db_switch_endpoint: target=postgres, roundtrip fails → 400
  SWITCH-20  db_switch_endpoint: role viewer/unknown denied → 403
  SWITCH-21  db_switch_endpoint: config_kv queue receives DB_BACKEND entry
  SWITCH-22  db_switch_endpoint: config_kv queue receives POSTGRES_DSN when body DSN
  SWITCH-23  db_switch_endpoint: calls _migrate_recent_events before exit
  SWITCH-24  db_switch_endpoint: uses os._exit(0) not sys.exit
  SWITCH-25  db_switch_endpoint: response sent before exit (not blocked)
  SWITCH-26  db_switch_endpoint: target=sqlite always ok (no psycopg needed)
  SWITCH-27  Config persistence: DB_BACKEND entry value is JSON-encoded target string
  SWITCH-28  SQLite schema: tables that survive both backends present in SQLite DDL
  SWITCH-29  pg_test_roundtrip: returns ok=False when psycopg unavailable
  SWITCH-30  pg_test_roundtrip: returns ok=False when POSTGRES_DSN empty
  SWITCH-31  Switch reversibility: sqlite→postgres→sqlite direction chain correct
"""
import inspect
import json
import os
import sqlite3
import sys
import tempfile
import time
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

# ── env / path setup ──────────────────────────────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="appsecgw-switch-test-")
os.environ.setdefault("UPSTREAM",  "https://example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "switch-test.db"))

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers: fake psycopg objects
# ─────────────────────────────────────────────────────────────────────────────

class FakeCursor:
    def __init__(self, rows=None):
        self.executions = []
        self.executemany_calls = []
        self._rows = list(rows or [])

    def execute(self, sql, args=()):
        self.executions.append((sql, args))

    def executemany(self, sql, seq):
        self.executemany_calls.append((sql, list(seq)))

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __enter__(self): return self
    def __exit__(self, *a): pass


class FakeConn:
    def __init__(self, cursor=None):
        self._cursor = cursor or FakeCursor()
        self.committed = False
        self.closed = False
        self.executions = []

    def cursor(self):
        return self._cursor

    def execute(self, sql, args=()):
        self.executions.append((sql, args))

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True

    def __enter__(self): return self
    def __exit__(self, *a): pass


class FakePsycopg:
    """Minimal psycopg stand-in."""
    def __init__(self, conn=None):
        self._conn = conn or FakeConn()
        self.connect_calls = []

    def connect(self, dsn, **kwargs):
        self.connect_calls.append(dsn)
        return self._conn

    OperationalError = Exception


def _make_sqlite_with_events(path, rows):
    """Create a minimal SQLite DB with an events table pre-populated."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL, ip TEXT, ua TEXT, path TEXT,
            method TEXT DEFAULT '', status INTEGER, reason TEXT
        )
    """)
    conn.executemany(
        "INSERT INTO events (ts, ip, ua, path, method, status, reason) VALUES (?,?,?,?,?,?,?)",
        rows)
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# SWITCH-01 … SWITCH-06 — SQLite → Postgres migration
# ─────────────────────────────────────────────────────────────────────────────

class TestMigrateSqliteToPostgres:
    """_migrate_recent_events(target='postgres') — all observable contracts."""

    def _run(self, tmp_path, pg_mod, rows_in, window_secs=60, dsn="pg://host/db"):
        from db import postgres as pg_mod_real
        db_path = str(tmp_path / "test.db")
        now = time.time()
        _make_sqlite_with_events(db_path, rows_in)
        with patch.object(pg_mod_real, "_postgres_load_module", return_value=pg_mod), \
             patch.object(pg_mod_real, "POSTGRES_DSN", dsn), \
             patch.object(pg_mod_real, "DB_PATH", db_path):
            return pg_mod_real._migrate_recent_events("postgres", window_secs)

    def test_copies_rows_in_window(self, tmp_path):
        """SWITCH-01: rows within window_secs are copied."""
        now = time.time()
        fake_cur = FakeCursor()
        fake_conn = FakeConn(fake_cur)
        pg = FakePsycopg(fake_conn)

        rows_in = [
            (now - 10, "1.2.3.4", "Mozilla/5.0", "/path", "", 200, "ok"),
            (now - 20, "5.6.7.8", "curl/7",       "/api",  "", 403, "ban"),
        ]
        result = self._run(tmp_path, pg, rows_in, window_secs=60)

        assert result["ok"] is True                       # SWITCH-01
        assert result["copied"] == 2
        assert len(fake_cur.executemany_calls) == 1
        _, inserted = fake_cur.executemany_calls[0]
        assert len(inserted) == 2
        assert fake_conn.committed is True

    def test_skips_rows_outside_window(self, tmp_path):
        """SWITCH-12: rows older than window_secs are NOT copied."""
        now = time.time()
        fake_cur = FakeCursor()
        pg = FakePsycopg(FakeConn(fake_cur))

        rows_in = [
            (now - 10,   "1.2.3.4", "ua", "/new", "", 200, "ok"),   # inside
            (now - 3600, "9.9.9.9", "ua", "/old", "", 200, "ok"),   # outside
        ]
        result = self._run(tmp_path, pg, rows_in, window_secs=60)

        assert result["ok"] is True
        assert result["copied"] == 1                      # SWITCH-12

    def test_empty_source_returns_zero_copied(self, tmp_path):
        """SWITCH-02: empty SQLite returns ok=True, copied=0."""
        pg = FakePsycopg()
        result = self._run(tmp_path, pg, [], window_secs=60)

        assert result["ok"] is True                       # SWITCH-02
        assert result["copied"] == 0

    def test_direction_string_correct(self, tmp_path):
        """SWITCH-06: direction must be 'sqlite->postgres'."""
        pg = FakePsycopg()
        result = self._run(tmp_path, pg, [], window_secs=60)
        assert result["direction"] == "sqlite->postgres"  # SWITCH-06

    def test_ua_truncated_at_500_chars(self, tmp_path):
        """SWITCH-03: UA strings longer than 500 chars are truncated."""
        now = time.time()
        long_ua = "A" * 1000
        fake_cur = FakeCursor()
        pg = FakePsycopg(FakeConn(fake_cur))

        rows_in = [(now - 5, "1.2.3.4", long_ua, "/path", "", 200, "ok")]
        self._run(tmp_path, pg, rows_in, window_secs=60)

        _, inserted = fake_cur.executemany_calls[0]
        ua_sent = inserted[0][2]                          # ts, ip, ua, path, status, reason
        assert len(ua_sent) == 500                        # SWITCH-03

    def test_none_ua_coerced_to_empty_string(self, tmp_path):
        """SWITCH-04: None UA → empty string (no NULL in target)."""
        now = time.time()
        fake_cur = FakeCursor()
        pg = FakePsycopg(FakeConn(fake_cur))

        rows_in = [(now - 5, "1.2.3.4", None, "/path", "", 200, "ok")]
        self._run(tmp_path, pg, rows_in, window_secs=60)

        _, inserted = fake_cur.executemany_calls[0]
        assert inserted[0][2] == ""                       # SWITCH-04

    def test_none_path_coerced_to_empty_string(self, tmp_path):
        now = time.time()
        fake_cur = FakeCursor()
        pg = FakePsycopg(FakeConn(fake_cur))

        rows_in = [(now - 5, "1.2.3.4", "ua", None, "", 200, "ok")]
        self._run(tmp_path, pg, rows_in, window_secs=60)

        _, inserted = fake_cur.executemany_calls[0]
        assert inserted[0][3] == ""

    def test_none_status_coerced_to_zero(self, tmp_path):
        """SWITCH-14: None status → 0 (not NULL)."""
        now = time.time()
        fake_cur = FakeCursor()
        pg = FakePsycopg(FakeConn(fake_cur))

        rows_in = [(now - 5, "1.2.3.4", "ua", "/path", "", None, "ok")]
        self._run(tmp_path, pg, rows_in, window_secs=60)

        _, inserted = fake_cur.executemany_calls[0]
        assert inserted[0][4] == 0                        # SWITCH-14

    def test_pg_connect_failure_returns_ok_false(self, tmp_path):
        """SWITCH-05: PG connect exception → ok=False with reason."""
        now = time.time()
        rows_in = [(now - 5, "1.2.3.4", "ua", "/path", "", 200, "ok")]

        class _BrokenPg:
            OperationalError = Exception
            def connect(self, *a, **kw):
                raise Exception("connection refused")

        result = self._run(tmp_path, _BrokenPg(), rows_in, window_secs=60)
        assert result["ok"] is False                      # SWITCH-05
        assert "reason" in result
        assert len(result["reason"]) > 0

    def test_row_count_matches_source_exactly(self, tmp_path):
        """SWITCH-13: copied count equals number of rows in window."""
        now = time.time()
        fake_cur = FakeCursor()
        pg = FakePsycopg(FakeConn(fake_cur))

        n_rows = 17
        rows_in = [(now - i, "1.1.1.1", "ua", f"/p{i}", "", 200, "ok")
                   for i in range(1, n_rows + 1)]
        result = self._run(tmp_path, pg, rows_in, window_secs=3600)

        assert result["copied"] == n_rows                 # SWITCH-13

    def test_no_postgres_dsn_returns_ok_false(self, tmp_path):
        """SWITCH-15: empty POSTGRES_DSN → ok=False."""
        from db import postgres as pg_mod_real
        with patch.object(pg_mod_real, "_postgres_load_module", return_value=FakePsycopg()), \
             patch.object(pg_mod_real, "POSTGRES_DSN", ""), \
             patch.object(pg_mod_real, "DB_PATH", str(tmp_path / "x.db")):
            result = pg_mod_real._migrate_recent_events("postgres", 60)

        assert result["ok"] is False                      # SWITCH-15

    def test_psycopg_unavailable_returns_ok_false(self, tmp_path):
        """SWITCH-15b: psycopg not installed → ok=False."""
        from db import postgres as pg_mod_real
        with patch.object(pg_mod_real, "_postgres_load_module", return_value=None), \
             patch.object(pg_mod_real, "POSTGRES_DSN", "pg://x"), \
             patch.object(pg_mod_real, "DB_PATH", str(tmp_path / "x.db")):
            result = pg_mod_real._migrate_recent_events("postgres", 60)

        assert result["ok"] is False


# ─────────────────────────────────────────────────────────────────────────────
# SWITCH-07 … SWITCH-11 — Postgres → SQLite migration
# ─────────────────────────────────────────────────────────────────────────────

class TestMigratePostgresToSqlite:
    """_migrate_recent_events(target='sqlite') — all observable contracts."""

    def _run(self, tmp_path, pg_rows, dsn="pg://host/db"):
        from db import postgres as pg_mod_real
        db_path = str(tmp_path / "dst.db")
        # Create destination SQLite with the right schema
        _make_sqlite_with_events(db_path, [])

        fake_cur = FakeCursor(rows=pg_rows)
        fake_conn = FakeConn(fake_cur)
        pg = FakePsycopg(fake_conn)

        with patch.object(pg_mod_real, "_postgres_load_module", return_value=pg), \
             patch.object(pg_mod_real, "POSTGRES_DSN", dsn), \
             patch.object(pg_mod_real, "DB_PATH", db_path):
            result = pg_mod_real._migrate_recent_events("sqlite", 60)

        return result, db_path

    def test_copies_rows_to_sqlite(self, tmp_path):
        """SWITCH-07: Postgres rows are inserted into the SQLite events table."""
        now = time.time()
        pg_rows = [
            (now - 10, "1.2.3.4", "Mozilla", "/path", 200, "ok"),
            (now - 20, "5.6.7.8", "curl",    "/api",  403, "ban"),
        ]
        result, db_path = self._run(tmp_path, pg_rows)

        assert result["ok"] is True                       # SWITCH-07
        assert result["copied"] == 2

        # Verify rows landed in SQLite
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        assert count == 2

    def test_empty_source_returns_zero_copied(self, tmp_path):
        """SWITCH-08: empty Postgres → ok=True, copied=0, nothing written."""
        result, db_path = self._run(tmp_path, [])

        assert result["ok"] is True                       # SWITCH-08
        assert result["copied"] == 0

        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        assert count == 0

    def test_direction_string_correct(self, tmp_path):
        """SWITCH-10: direction must be 'postgres->sqlite'."""
        result, _ = self._run(tmp_path, [])
        assert result["direction"] == "postgres->sqlite"  # SWITCH-10

    def test_ua_truncated_at_500_chars(self, tmp_path):
        """SWITCH-09: UA longer than 500 chars truncated in SQLite destination."""
        now = time.time()
        long_ua = "B" * 1000
        pg_rows = [(now - 5, "1.2.3.4", long_ua, "/path", 200, "ok")]
        result, db_path = self._run(tmp_path, pg_rows)

        assert result["ok"] is True
        conn = sqlite3.connect(db_path)
        ua = conn.execute("SELECT ua FROM events").fetchone()[0]
        conn.close()
        assert len(ua) == 500                             # SWITCH-09

    def test_none_ua_coerced_to_empty(self, tmp_path):
        now = time.time()
        pg_rows = [(now - 5, "1.2.3.4", None, "/path", 200, "ok")]
        result, db_path = self._run(tmp_path, pg_rows)

        conn = sqlite3.connect(db_path)
        ua = conn.execute("SELECT ua FROM events").fetchone()[0]
        conn.close()
        assert ua == ""

    def test_method_column_set_to_empty_string(self, tmp_path):
        """Postgres events lack 'method'; SQLite INSERT fills it with ''."""
        now = time.time()
        pg_rows = [(now - 5, "1.2.3.4", "ua", "/path", 200, "ok")]
        _, db_path = self._run(tmp_path, pg_rows)

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT method FROM events").fetchone()
        conn.close()
        assert row[0] == ""

    def test_status_none_coerced_to_zero(self, tmp_path):
        """SWITCH-14b: None status from PG → 0 in SQLite."""
        now = time.time()
        pg_rows = [(now - 5, "1.2.3.4", "ua", "/path", None, "ok")]
        _, db_path = self._run(tmp_path, pg_rows)

        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT status FROM events").fetchone()
        conn.close()
        assert row[0] == 0                                # SWITCH-14

    def test_pg_unavailable_returns_ok_false(self, tmp_path):
        """SWITCH-11: psycopg absent → ok=False."""
        from db import postgres as pg_mod_real
        with patch.object(pg_mod_real, "_postgres_load_module", return_value=None), \
             patch.object(pg_mod_real, "POSTGRES_DSN", "pg://x"), \
             patch.object(pg_mod_real, "DB_PATH", str(tmp_path / "x.db")):
            result = pg_mod_real._migrate_recent_events("sqlite", 60)

        assert result["ok"] is False                      # SWITCH-11

    def test_pg_connect_failure_returns_ok_false(self, tmp_path):
        """PG connection error on sqlite-target path → ok=False."""
        from db import postgres as pg_mod_real
        _make_sqlite_with_events(str(tmp_path / "dst.db"), [])

        class _BrokenPg:
            OperationalError = Exception
            def connect(self, *a, **kw):
                raise Exception("timeout")

        with patch.object(pg_mod_real, "_postgres_load_module", return_value=_BrokenPg()), \
             patch.object(pg_mod_real, "POSTGRES_DSN", "pg://x"), \
             patch.object(pg_mod_real, "DB_PATH", str(tmp_path / "dst.db")):
            result = pg_mod_real._migrate_recent_events("sqlite", 60)

        assert result["ok"] is False
        assert "reason" in result


# ─────────────────────────────────────────────────────────────────────────────
# SWITCH-31 — Reversibility: direction chain
# ─────────────────────────────────────────────────────────────────────────────

class TestSwitchReversibility:
    """SWITCH-31: sqlite→postgres and postgres→sqlite are inverse operations."""

    def test_sqlite_to_postgres_direction(self, tmp_path):
        from db import postgres as pg_mod_real
        db_path = str(tmp_path / "rev.db")
        _make_sqlite_with_events(db_path, [])
        pg = FakePsycopg()

        with patch.object(pg_mod_real, "_postgres_load_module", return_value=pg), \
             patch.object(pg_mod_real, "POSTGRES_DSN", "pg://x"), \
             patch.object(pg_mod_real, "DB_PATH", db_path):
            fwd = pg_mod_real._migrate_recent_events("postgres", 60)

        assert fwd["direction"] == "sqlite->postgres"

    def test_postgres_to_sqlite_direction(self, tmp_path):
        from db import postgres as pg_mod_real
        db_path = str(tmp_path / "rev2.db")
        _make_sqlite_with_events(db_path, [])

        with patch.object(pg_mod_real, "_postgres_load_module",
                          return_value=FakePsycopg(FakeConn(FakeCursor([])))), \
             patch.object(pg_mod_real, "POSTGRES_DSN", "pg://x"), \
             patch.object(pg_mod_real, "DB_PATH", db_path):
            rev = pg_mod_real._migrate_recent_events("sqlite", 60)

        assert rev["direction"] == "postgres->sqlite"

    def test_two_directions_are_inverse_strings(self):
        fwd = "sqlite->postgres"
        rev = "postgres->sqlite"
        a, b = fwd.split("->")
        assert rev == f"{b}->{a}", "directions must be exact inverses"


# ─────────────────────────────────────────────────────────────────────────────
# SWITCH-16 … SWITCH-27 — db_switch_endpoint validation + contracts
# ─────────────────────────────────────────────────────────────────────────────

class TestDbSwitchEndpointSource:
    """Source-level checks on db_switch_endpoint — no live server needed."""

    @pytest.fixture(scope="class")
    def src(self):
        from core import proxy_handler
        return inspect.getsource(proxy_handler.db_switch_endpoint)

    def test_target_validation_present(self, src):
        """SWITCH-16: invalid target must be rejected."""
        assert '"sqlite"' in src and '"postgres"' in src
        assert 'target not in' in src or 'target in' in src

    def test_psycopg_availability_checked_for_postgres(self, src):
        """SWITCH-17: psycopg check happens before postgres switch."""
        assert "_postgres_load_module" in src

    def test_dsn_required_for_postgres(self, src):
        """SWITCH-18: missing POSTGRES_DSN rejected for postgres target."""
        assert "POSTGRES_DSN" in src
        assert "no POSTGRES_DSN" in src or "dsn" in src.lower()

    def test_roundtrip_probe_called(self, src):
        """SWITCH-19: roundtrip probe called before committing switch to postgres."""
        assert "pg_test_roundtrip" in src

    def test_role_check_present(self, src):
        """SWITCH-20: role check must gate the endpoint."""
        assert "_role_denied" in src
        assert '"admin"' in src

    def test_migrate_called_before_propagation(self, src):
        """SWITCH-23 (updated): migration runs after propagation so the new pool/DSN is live."""
        migrate_pos = src.find("_migrate_recent_events")
        prop_pos    = src.find("_propagate_global")
        assert migrate_pos != -1, "_migrate_recent_events not found in endpoint"
        assert prop_pos    != -1, "_propagate_global not found in endpoint"
        assert prop_pos < migrate_pos, \
            "_propagate_global must run before _migrate_recent_events"

    def test_no_os_exit_hot_swap(self, src):
        """SWITCH-24 (updated): hot-swap is in-process — os._exit must NOT be called."""
        assert "os._exit" not in src, \
            "db_switch_endpoint must not call os._exit — backend is hot-swapped in-process"

    def test_response_returned_directly(self, src):
        """SWITCH-25 (updated): response is returned directly (no deferred exit needed)."""
        assert "return web.json_response" in src, \
            "db_switch_endpoint must return response directly"
        assert "_delayed_exit" not in src, \
            "No deferred exit task needed — switch is synchronous"

    def test_config_kv_persisted(self, src):
        """SWITCH-21/27: DB_BACKEND is persisted to config_kv queue."""
        assert '"set_config"' in src or "'set_config'" in src
        assert "DB_BACKEND" in src

    def test_dsn_persisted_when_body_dsn(self, src):
        """SWITCH-22: POSTGRES_DSN saved to config_kv when body provides DSN."""
        assert "POSTGRES_DSN" in src
        assert "body_dsn" in src

    def test_migration_result_in_response(self, src):
        """Migration outcome included in the success response."""
        assert "events_copied" in src or "copied" in src

    def test_sqlite_target_no_psycopg_needed(self, src):
        """SWITCH-26: switching to sqlite must not require psycopg."""
        # The psycopg check is inside `if target == 'postgres':` block
        # Verify it's conditional, not unconditional
        pg_check_idx = src.find("_postgres_load_module")
        postgres_if_idx = src.find('target == "postgres"')
        if postgres_if_idx == -1:
            postgres_if_idx = src.find("target == 'postgres'")
        assert postgres_if_idx < pg_check_idx, \
            "psycopg check must be inside 'if target == postgres' guard"

    def test_propagate_global_called(self, src):
        """SWITCH-26b (updated): _propagate_global used to push DB_BACKEND to all modules."""
        assert "_propagate_global" in src, \
            "_propagate_global must be called to propagate DB_BACKEND across sys.modules"


# ─────────────────────────────────────────────────────────────────────────────
# SWITCH-21 / SWITCH-22 / SWITCH-27 — config_kv queue content
# ─────────────────────────────────────────────────────────────────────────────

class TestDbSwitchConfigPersistence:
    """Verify config_kv queue receives correctly-encoded entries."""

    def _make_request(self, target, body_json=None, role="admin"):
        req = MagicMock()
        req.query = {"target": target}
        req.method = "POST"
        req.get = MagicMock(return_value=None)
        raw = json.dumps(body_json or {}).encode()
        req.content = MagicMock()
        req.content.read = AsyncMock(return_value=raw)
        req.headers = {}
        req.cookies = {}
        return req

    @pytest.mark.asyncio
    async def test_db_backend_sqlite_entry_enqueued(self):
        """SWITCH-21: switching to sqlite enqueues DB_BACKEND='sqlite'."""
        import asyncio
        from core import proxy_handler

        queue_items = []
        fake_queue = MagicMock()
        fake_queue.put_nowait = lambda item: queue_items.append(item)

        req = self._make_request("sqlite")
        with patch.object(proxy_handler, "_internal_authed", return_value=True), \
             patch.object(proxy_handler, "_role_denied", return_value=None), \
             patch.object(proxy_handler, "db_queue", fake_queue), \
             patch.object(proxy_handler, "_migrate_recent_events",
                          return_value={"ok": True, "copied": 0,
                                        "direction": "postgres->sqlite"}), \
             patch("asyncio.create_task"):
            resp = await proxy_handler.db_switch_endpoint(req)

        db_backend_entries = [
            item for item in queue_items
            if item[0] == "set_config" and item[1][0] == "DB_BACKEND"
        ]
        assert len(db_backend_entries) >= 1, \
            "DB_BACKEND must be written to config_kv queue"
        _, (key, val, _ts) = db_backend_entries[0]
        assert key == "DB_BACKEND"
        assert json.loads(val) == "sqlite"                # SWITCH-27

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)  # pycares async DNS resolver retries the placeholder 'host' hostname for ~60s before giving up
    async def test_postgres_dsn_enqueued_when_body_provides_it(self):
        """SWITCH-22: body DSN is persisted to config_kv."""
        import asyncio
        from core import proxy_handler

        queue_items = []
        fake_queue = MagicMock()
        fake_queue.put_nowait = lambda item: queue_items.append(item)

        req = self._make_request("postgres", body_json={"dsn": "postgresql://user:pw@host/db"})
        with patch.object(proxy_handler, "_internal_authed", return_value=True), \
             patch.object(proxy_handler, "_role_denied", return_value=None), \
             patch.object(proxy_handler, "db_queue", fake_queue), \
             patch.object(proxy_handler, "_postgres_load_module",
                          return_value=FakePsycopg()), \
             patch.object(proxy_handler, "pg_test_roundtrip",
                          return_value={"ok": True}), \
             patch.object(proxy_handler, "_migrate_recent_events",
                          return_value={"ok": True, "copied": 0,
                                        "direction": "sqlite->postgres"}), \
             patch("asyncio.create_task"):
            resp = await proxy_handler.db_switch_endpoint(req)

        dsn_entries = [
            item for item in queue_items
            if item[0] == "set_config" and item[1][0] == "POSTGRES_DSN"
        ]
        assert len(dsn_entries) >= 1, \
            "POSTGRES_DSN must be written to config_kv when body provides it"
        _, (key, val, _ts) = dsn_entries[0]
        assert json.loads(val) == "postgresql://user:pw@host/db"  # SWITCH-22


# ─────────────────────────────────────────────────────────────────────────────
# SWITCH-28 — SQLite schema: tables that survive both backends
# ─────────────────────────────────────────────────────────────────────────────

class TestSqliteSchemaInvariant:
    """SWITCH-28: tables that must exist in SQLite for both backends."""

    @pytest.fixture(scope="class")
    def sqlite_ddl(self):
        from db import sqlite as sqlite_mod
        return inspect.getsource(sqlite_mod)

    MUST_HAVE = [
        "config_kv",     # knob persistence
        "secrets_kv",    # API keys
        "admin_ips",     # IP allowlist
        "events",        # primary event store (SQLite backend)
        "bans",          # ban table
        "clients",       # per-client state
    ]

    @pytest.mark.parametrize("table", MUST_HAVE)
    def test_table_in_sqlite_schema(self, table, sqlite_ddl):
        """SWITCH-28: critical table present in SQLite DDL."""
        assert table in sqlite_ddl, \
            f"SQLite DDL must define table '{table}' — it persists across backend switches"

    def test_config_kv_survives_both_backends(self, sqlite_ddl):
        """config_kv lives in SQLite even when DB_BACKEND=postgres."""
        # config_kv is the gateway's operational state vault — always SQLite
        assert "config_kv" in sqlite_ddl
        # Must NOT be gated on DB_BACKEND
        pg_gate = "if DB_BACKEND" in sqlite_ddl or "if db_backend" in sqlite_ddl.lower()
        # config_kv DDL should appear unconditionally
        idx = sqlite_ddl.find("config_kv")
        surrounding = sqlite_ddl[max(0, idx-200):idx+200]
        assert "if DB_BACKEND" not in surrounding, \
            "config_kv DDL must not be gated on DB_BACKEND — it must always exist"


# ─────────────────────────────────────────────────────────────────────────────
# SWITCH-29 / SWITCH-30 — pg_test_roundtrip
# ─────────────────────────────────────────────────────────────────────────────

class TestPgTestRoundtrip:
    """pg_test_roundtrip() edge cases."""

    def test_returns_ok_false_when_psycopg_unavailable(self):
        """SWITCH-29: no psycopg → ok=False."""
        from db import postgres as pg_mod_real
        with patch.object(pg_mod_real, "_postgres_load_module", return_value=None):
            result = pg_mod_real.pg_test_roundtrip()
        assert result["ok"] is False
        assert "psycopg" in result.get("reason", "").lower()

    def test_returns_ok_false_when_no_dsn(self):
        """SWITCH-30: empty POSTGRES_DSN → ok=False."""
        from db import postgres as pg_mod_real
        with patch.object(pg_mod_real, "_postgres_load_module",
                          return_value=FakePsycopg()), \
             patch.object(pg_mod_real, "POSTGRES_DSN", ""):
            result = pg_mod_real.pg_test_roundtrip()
        assert result["ok"] is False
        assert "dsn" in result.get("reason", "").lower() or \
               "configured" in result.get("reason", "").lower()

    def test_returns_ok_false_on_connect_error(self):
        class _FailPg:
            OperationalError = Exception
            def connect(self, *a, **kw):
                raise Exception("refused")
        from db import postgres as pg_mod_real
        with patch.object(pg_mod_real, "_postgres_load_module", return_value=_FailPg()), \
             patch.object(pg_mod_real, "POSTGRES_DSN", "postgresql://bad/db"):
            result = pg_mod_real.pg_test_roundtrip()
        assert result["ok"] is False


# ─────────────────────────────────────────────────────────────────────────────
# SWITCH-16 — endpoint request validation (no DB / network needed)
# ─────────────────────────────────────────────────────────────────────────────

class TestDbSwitchEndpointValidation:
    """Validation path tests using fake requests."""

    def _make_req(self, target, body=b"{}"):
        req = MagicMock()
        req.query = {"target": target}
        req.method = "POST"
        req.get = MagicMock(return_value=None)
        req.content = MagicMock()
        req.content.read = AsyncMock(return_value=body)
        req.headers = {}
        req.cookies = {}
        return req

    @pytest.mark.asyncio
    async def test_invalid_target_returns_400(self):
        """SWITCH-16: target='mysql' → 400."""
        from core import proxy_handler
        req = self._make_req("mysql")
        with patch.object(proxy_handler, "_role_denied", return_value=None):
            resp = await proxy_handler.db_switch_endpoint(req)
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_postgres_without_psycopg_returns_400(self):
        """SWITCH-17: psycopg absent → 400 for postgres target."""
        from core import proxy_handler
        req = self._make_req("postgres")
        with patch.object(proxy_handler, "_role_denied", return_value=None), \
             patch.object(proxy_handler, "_postgres_load_module", return_value=None):
            resp = await proxy_handler.db_switch_endpoint(req)
        assert resp.status == 400
        body = json.loads(resp.body)
        assert "psycopg" in body.get("reason", "").lower()

    @pytest.mark.asyncio
    async def test_postgres_without_dsn_returns_400(self):
        """SWITCH-18: no POSTGRES_DSN → 400."""
        from core import proxy_handler
        req = self._make_req("postgres")
        with patch.object(proxy_handler, "_role_denied", return_value=None), \
             patch.object(proxy_handler, "_postgres_load_module",
                          return_value=FakePsycopg()), \
             patch.object(proxy_handler, "POSTGRES_DSN", ""):
            resp = await proxy_handler.db_switch_endpoint(req)
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_postgres_failed_roundtrip_returns_400(self):
        """SWITCH-19: failed roundtrip probe → 400."""
        from core import proxy_handler
        req = self._make_req("postgres")
        with patch.object(proxy_handler, "_role_denied", return_value=None), \
             patch.object(proxy_handler, "_postgres_load_module",
                          return_value=FakePsycopg()), \
             patch.object(proxy_handler, "POSTGRES_DSN", "postgresql://host/db"), \
             patch.object(proxy_handler, "pg_test_roundtrip",
                          return_value={"ok": False, "reason": "connection refused"}):
            resp = await proxy_handler.db_switch_endpoint(req)
        assert resp.status == 400
        body = json.loads(resp.body)
        assert "probe" in body.get("reason", "").lower() or \
               "connectivity" in body.get("reason", "").lower()

    @pytest.mark.asyncio
    async def test_viewer_role_denied(self):
        """SWITCH-20: viewer role cannot trigger a backend switch."""
        from core import proxy_handler
        from aiohttp import web
        req = self._make_req("sqlite")
        denied_resp = web.json_response({"error": "forbidden"}, status=403)
        with patch.object(proxy_handler, "_role_denied", return_value=denied_resp):
            resp = await proxy_handler.db_switch_endpoint(req)
        assert resp.status == 403
