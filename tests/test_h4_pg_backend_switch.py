"""
test_h4_pg_backend_switch.py — Unit tests for PostgreSQL backend switch path.

Covers the QA gaps identified in the SQLite→Postgres switch:
  1. _migrate_recent_events correctness (fake pg.connect, real SQLite tmp files)
  2. _pg_mirror_kv coverage for all 8 supported ops
  3. pg_insert_event execute path via fake pool
  4. Known SQLite-only tables (dlp_patterns, audit_events, svc_metrics)
     are absent from db_init_postgres DDL — documented as intentional.
  5. db_switch_endpoint request validation (structural + source-level)

No live Postgres instance required; psycopg is never actually imported.
"""
import sqlite3
import time
from contextlib import contextmanager

import pytest


# ── Shared fakes ──────────────────────────────────────────────────────────────

class _Cursor:
    """Fake psycopg cursor — records SQL executions."""
    def __init__(self):
        self.executions = []        # list of (sql, args)
        self.executemany_calls = [] # list of (sql, list-of-rows)
        self._rows = []             # for fetchall()

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


class _Conn:
    """Fake psycopg connection."""
    def __init__(self):
        self._cursor = _Cursor()
        self.committed = False
        self.closed = False
        self.executions = []  # direct conn.execute() calls

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


class _Pool:
    """Minimal fake pool — connection() yields the given _Conn."""
    def __init__(self, conn):
        self._conn = conn

    @contextmanager
    def connection(self, timeout=2.0):
        yield self._conn


def _make_fake_pg(conn):
    """Return a fake 'psycopg' module whose connect() yields *conn*."""
    class _FakePg:
        @staticmethod
        @contextmanager
        def connect(*a, **kw):
            yield conn
    return _FakePg()


# ══════════════════════════════════════════════════════════════════════════════
# 1. _migrate_recent_events
# ══════════════════════════════════════════════════════════════════════════════

class TestMigrateRecentEvents:

    def test_returns_error_when_pg_unavailable(self, monkeypatch):
        """Returns {ok:False} when _postgres_load_module() is None."""
        import db.postgres as pgm
        monkeypatch.setattr(pgm, "_postgres_load_module", lambda: None)
        result = pgm._migrate_recent_events("postgres")
        assert result["ok"] is False
        assert "postgres unavailable" in result["reason"]

    def test_returns_error_when_no_dsn(self, monkeypatch):
        """Returns {ok:False} when POSTGRES_DSN is empty."""
        import db.postgres as pgm
        monkeypatch.setattr(pgm, "_postgres_load_module",
                            lambda: _make_fake_pg(_Conn()))
        monkeypatch.setattr(pgm, "POSTGRES_DSN", "")
        result = pgm._migrate_recent_events("postgres")
        assert result["ok"] is False

    def test_sqlite_to_postgres_no_rows(self, monkeypatch, tmp_path):
        """Returns {ok:True, copied:0} when SQLite has no events in window."""
        import db.postgres as pgm
        db_path = str(tmp_path / "empty.db")
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE events "
                     "(ts REAL, ip TEXT, ua TEXT, path TEXT, "
                     "status INTEGER, reason TEXT)")
        conn.commit()
        conn.close()

        monkeypatch.setattr(pgm, "_postgres_load_module",
                            lambda: _make_fake_pg(_Conn()))
        monkeypatch.setattr(pgm, "POSTGRES_DSN", "host=fake")
        monkeypatch.setattr(pgm, "DB_PATH", db_path)

        result = pgm._migrate_recent_events("postgres", window_secs=60)
        assert result["ok"] is True
        assert result["copied"] == 0
        assert result["direction"] == "sqlite->postgres"

    def test_sqlite_to_postgres_copies_window_rows(self, monkeypatch, tmp_path):
        """Only rows within the window are sent to Postgres."""
        import db.postgres as pgm
        db_path = str(tmp_path / "events.db")
        now = time.time()

        src = sqlite3.connect(db_path)
        src.execute("CREATE TABLE events "
                    "(ts REAL, ip TEXT, ua TEXT, path TEXT, "
                    "status INTEGER, reason TEXT)")
        src.executemany(
            "INSERT INTO events VALUES (?, ?, 'UA', '/', 200, 'ok')",
            [(now - 10, "1.1.1.1"),
             (now - 20, "2.2.2.2"),
             (now - 30, "3.3.3.3"),
             (now - 120, "4.4.4.4"),  # outside 60 s window — must NOT copy
             ])
        src.commit()
        src.close()

        dst_conn = _Conn()
        monkeypatch.setattr(pgm, "_postgres_load_module",
                            lambda: _make_fake_pg(dst_conn))
        monkeypatch.setattr(pgm, "POSTGRES_DSN", "host=fake")
        monkeypatch.setattr(pgm, "DB_PATH", db_path)

        result = pgm._migrate_recent_events("postgres", window_secs=60)
        assert result["ok"] is True
        assert result["copied"] == 3
        assert result["direction"] == "sqlite->postgres"

        assert len(dst_conn._cursor.executemany_calls) == 1
        sql, rows = dst_conn._cursor.executemany_calls[0]
        assert "INSERT INTO events" in sql
        assert "to_timestamp" in sql
        assert len(rows) == 3
        # IPs in the copy must not include the old row
        ips = {r[1] for r in rows}
        assert "4.4.4.4" not in ips

    def test_sqlite_to_postgres_pg_connect_failure(self, monkeypatch, tmp_path):
        """Returns {ok:False, reason:...} when pg.connect raises."""
        import db.postgres as pgm
        db_path = str(tmp_path / "events.db")
        now = time.time()
        src = sqlite3.connect(db_path)
        src.execute("CREATE TABLE events "
                    "(ts REAL, ip TEXT, ua TEXT, path TEXT, "
                    "status INTEGER, reason TEXT)")
        src.execute("INSERT INTO events VALUES (?, '1.2.3.4', 'UA', '/', 200, 'ok')",
                    (now - 5,))
        src.commit()
        src.close()

        class _BrokenConnect:
            def __enter__(self):
                raise ConnectionRefusedError("PG down")
            def __exit__(self, *a): pass

        class _FailPg:
            @staticmethod
            def connect(*a, **kw):
                return _BrokenConnect()

        monkeypatch.setattr(pgm, "_postgres_load_module", lambda: _FailPg())
        monkeypatch.setattr(pgm, "POSTGRES_DSN", "host=fake")
        monkeypatch.setattr(pgm, "DB_PATH", db_path)

        result = pgm._migrate_recent_events("postgres", window_secs=60)
        assert result["ok"] is False
        assert "ConnectionRefusedError" in result["reason"]

    def test_postgres_to_sqlite_no_rows(self, monkeypatch, tmp_path):
        """Returns {ok:True, copied:0} when Postgres source has no rows."""
        import db.postgres as pgm
        db_path = str(tmp_path / "dst.db")
        dst = sqlite3.connect(db_path)
        dst.execute("CREATE TABLE events "
                    "(ts REAL, ip TEXT, ua TEXT, path TEXT, "
                    "method TEXT, status INTEGER, reason TEXT)")
        dst.commit()
        dst.close()

        class _EmptyCursor:
            def execute(self, *a, **kw): pass
            def fetchall(self): return []
            def __enter__(self): return self
            def __exit__(self, *a): pass

        class _SrcConn:
            def cursor(self): return _EmptyCursor()
            def __enter__(self): return self
            def __exit__(self, *a): pass

        class _FakePg:
            @staticmethod
            def connect(*a, **kw): return _SrcConn()

        monkeypatch.setattr(pgm, "_postgres_load_module", lambda: _FakePg())
        monkeypatch.setattr(pgm, "POSTGRES_DSN", "host=fake")
        monkeypatch.setattr(pgm, "DB_PATH", db_path)

        result = pgm._migrate_recent_events("sqlite", window_secs=60)
        assert result["ok"] is True
        assert result["copied"] == 0
        assert result["direction"] == "postgres->sqlite"

    def test_postgres_to_sqlite_copies_rows(self, monkeypatch, tmp_path):
        """Rows returned by Postgres cursor are inserted into SQLite."""
        import db.postgres as pgm
        db_path = str(tmp_path / "dst.db")
        dst = sqlite3.connect(db_path)
        dst.execute("CREATE TABLE events "
                    "(ts REAL, ip TEXT, ua TEXT, path TEXT, "
                    "method TEXT, status INTEGER, reason TEXT)")
        dst.commit()
        dst.close()

        now = time.time()
        fake_rows = [
            (now - 10, "1.1.1.1", "UA", "/a", 200, "ok"),  # older ts — sorts first
            (now - 5,  "2.2.2.2", "UA", "/b", 403, "ban"),
        ]

        class _FakeCursor:
            def execute(self, *a, **kw): pass
            def fetchall(self): return list(fake_rows)
            def __enter__(self): return self
            def __exit__(self, *a): pass

        class _SrcConn:
            def cursor(self): return _FakeCursor()
            def __enter__(self): return self
            def __exit__(self, *a): pass

        class _FakePg:
            @staticmethod
            def connect(*a, **kw): return _SrcConn()

        monkeypatch.setattr(pgm, "_postgres_load_module", lambda: _FakePg())
        monkeypatch.setattr(pgm, "POSTGRES_DSN", "host=fake")
        monkeypatch.setattr(pgm, "DB_PATH", db_path)

        result = pgm._migrate_recent_events("sqlite", window_secs=60)
        assert result["ok"] is True
        assert result["copied"] == 2
        assert result["direction"] == "postgres->sqlite"

        # Verify rows landed in SQLite
        check = sqlite3.connect(db_path)
        rows = check.execute("SELECT ip FROM events ORDER BY ts").fetchall()
        check.close()
        assert len(rows) == 2
        assert rows[0][0] == "1.1.1.1"
        assert rows[1][0] == "2.2.2.2"


# ══════════════════════════════════════════════════════════════════════════════
# 2. _pg_mirror_kv — all 8 supported ops
# ══════════════════════════════════════════════════════════════════════════════

class TestPgMirrorKvOps:
    """_pg_mirror_kv routes each op to the correct SQL statement."""

    def _run(self, op, args):
        """Execute op via _pg_mirror_kv with a fake pool; return (result, conn)."""
        from db.postgres import _pg_mirror_kv
        import state as _state
        conn = _Conn()
        pool = _Pool(conn)
        old_pool = _state._postgres_pool
        _state._postgres_pool = pool
        try:
            result = _pg_mirror_kv(op, args)
        finally:
            _state._postgres_pool = old_pool
        return result, conn

    def _sql(self, conn):
        """Return the first SQL string executed on the cursor."""
        return conn._cursor.executions[0][0]

    # ── happy path, one test per op ───────────────────────────────────────────

    def test_set_config(self):
        result, conn = self._run("set_config", ("DB_BACKEND", "sqlite", 1.0))
        assert result is True
        assert "INSERT INTO config_kv" in self._sql(conn)
        assert "ON CONFLICT" in self._sql(conn)

    def test_del_config(self):
        result, conn = self._run("del_config", ("DB_BACKEND",))
        assert result is True
        assert "DELETE FROM config_kv" in self._sql(conn)

    def test_set_secret(self):
        result, conn = self._run("set_secret", ("WEBHOOK_SECRET", "s3cr3t", 1.0))
        assert result is True
        assert "INSERT INTO secrets_kv" in self._sql(conn)

    def test_del_secret(self):
        result, conn = self._run("del_secret", ("WEBHOOK_SECRET",))
        assert result is True
        assert "DELETE FROM secrets_kv" in self._sql(conn)

    def test_set_admin_ip(self):
        result, conn = self._run("set_admin_ip",
                                 ("10.0.0.1/32", 1.0, "note", "manual", "desc"))
        assert result is True
        assert "INSERT INTO admin_ips" in self._sql(conn)

    def test_del_admin_ip(self):
        result, conn = self._run("del_admin_ip", ("10.0.0.1/32",))
        assert result is True
        assert "DELETE FROM admin_ips" in self._sql(conn)

    def test_update_admin_ip_description(self):
        result, conn = self._run("update_admin_ip_description",
                                 ("new description", "10.0.0.1/32"))
        assert result is True
        sql = self._sql(conn)
        assert "UPDATE admin_ips" in sql
        assert "description" in sql

    def test_gw_audit_add(self):
        result, conn = self._run("gw_audit_add",
                                 (1.0, "config_change", "gw-1", "admin", "{}"))
        assert result is True
        assert "INSERT INTO gw_audit" in self._sql(conn)

    # ── error paths ───────────────────────────────────────────────────────────

    def test_unknown_op_returns_false(self):
        result, _conn = self._run("nonexistent_op_xyz", ("arg",))
        assert result is False

    def test_pool_timeout_returns_false(self):
        """Pool raising TimeoutError must be swallowed — never propagated."""
        from db.postgres import _pg_mirror_kv
        import state as _state

        class _BrokenPool:
            @contextmanager
            def connection(self, timeout=2.0):
                raise TimeoutError("pool exhausted")
                yield  # noqa: unreachable

        old_pool = _state._postgres_pool
        _state._postgres_pool = _BrokenPool()
        try:
            result = _pg_mirror_kv("set_config", ("k", "v", 1.0))
        finally:
            _state._postgres_pool = old_pool
        assert result is False

    def test_no_pool_no_dsn_returns_false(self, monkeypatch):
        """When pool is None and DSN is empty, returns False immediately."""
        from db.postgres import _pg_mirror_kv
        import state as _state
        import db.postgres as pgm
        old_pool = _state._postgres_pool
        _state._postgres_pool = None
        monkeypatch.setattr(pgm, "POSTGRES_DSN", "")
        try:
            result = _pg_mirror_kv("set_config", ("k", "v", 1.0))
        finally:
            _state._postgres_pool = old_pool
        assert result is False

    # ── args correctness ──────────────────────────────────────────────────────

    def test_set_config_passes_three_args(self):
        """set_config must pass (key, value, ts) — 3 args to the cursor."""
        _result, conn = self._run("set_config", ("KEY", "val", 42.0))
        args = conn._cursor.executions[0][1]
        assert len(args) == 3
        assert args[0] == "KEY"
        assert args[1] == "val"
        assert args[2] == 42.0

    def test_del_config_passes_one_arg(self):
        """del_config passes only (key,) — 1 arg to the cursor."""
        _result, conn = self._run("del_config", ("KEY",))
        args = conn._cursor.executions[0][1]
        assert len(args) == 1
        assert args[0] == "KEY"

    def test_gw_audit_add_passes_five_args(self):
        """gw_audit_add passes (ts, action, gw_id, actor, details) — 5 args."""
        _result, conn = self._run("gw_audit_add",
                                  (123.0, "rotate_key", "gw-1", "admin", "{}"))
        args = conn._cursor.executions[0][1]
        assert len(args) == 5
        assert args[1] == "rotate_key"


# ══════════════════════════════════════════════════════════════════════════════
# 3. pg_insert_event — execute path via fake pool
# ══════════════════════════════════════════════════════════════════════════════

class TestPgInsertEvent:

    def _insert(self, monkeypatch, **kw):
        """Run pg_insert_event with a fake postgres pool; return (result, conn)."""
        import db.postgres as pgm
        import state as _state
        conn = _Conn()
        pool = _Pool(conn)
        old_pool = _state._postgres_pool
        _state._postgres_pool = pool
        old_backend = pgm.DB_BACKEND
        pgm.DB_BACKEND = "postgres"
        try:
            result = pgm.pg_insert_event(**kw)
        finally:
            pgm.DB_BACKEND = old_backend
            _state._postgres_pool = old_pool
        return result, conn

    def test_returns_true_on_success(self, monkeypatch):
        result, _conn = self._insert(
            monkeypatch, ts=time.time(), ip="1.2.3.4", ua="TestUA",
            path="/", status=200, reason="ok")
        assert result is True

    def test_executes_insert_sql(self, monkeypatch):
        _result, conn = self._insert(
            monkeypatch, ts=time.time(), ip="1.2.3.4", ua="UA",
            path="/api", status=403, reason="ban")
        assert len(conn.executions) == 1
        sql = conn.executions[0][0]
        assert "INSERT INTO events" in sql
        assert "to_timestamp" in sql

    def test_ua_truncated_at_500_chars(self, monkeypatch):
        long_ua = "X" * 600
        _result, conn = self._insert(
            monkeypatch, ts=time.time(), ip="1.2.3.4", ua=long_ua,
            path="/", status=200, reason="ok")
        # args[2] is the ua parameter (after ts, ip)
        ua_sent = conn.executions[0][1][2]
        assert len(ua_sent) == 500

    def test_none_ua_coerced_to_empty(self, monkeypatch):
        _result, conn = self._insert(
            monkeypatch, ts=time.time(), ip="1.2.3.4", ua=None,
            path="/", status=200, reason="ok")
        ua_sent = conn.executions[0][1][2]
        assert ua_sent == ""

    def test_returns_false_on_sqlite_backend(self, monkeypatch):
        import db.postgres as pgm
        old_backend = pgm.DB_BACKEND
        pgm.DB_BACKEND = "sqlite"
        try:
            result = pgm.pg_insert_event(
                ts=time.time(), ip="1.2.3.4", ua="UA",
                path="/", status=200, reason="ok")
        finally:
            pgm.DB_BACKEND = old_backend
        assert result is False

    def test_returns_false_when_pool_none(self, monkeypatch):
        import db.postgres as pgm
        monkeypatch.setattr(pgm, "_get_pool", lambda: None)
        old_backend = pgm.DB_BACKEND
        pgm.DB_BACKEND = "postgres"
        try:
            result = pgm.pg_insert_event(
                ts=time.time(), ip="1.2.3.4", ua="UA",
                path="/", status=200, reason="ok")
        finally:
            pgm.DB_BACKEND = old_backend
        assert result is False

    def test_returns_false_on_execute_exception(self, monkeypatch):
        import db.postgres as pgm
        import state as _state

        class _BrokenConn(_Conn):
            def execute(self, sql, args=()):
                raise OSError("connection lost")

        class _BrokenPool(_Pool):
            def __init__(self):
                super().__init__(_BrokenConn())

        old_pool = _state._postgres_pool
        _state._postgres_pool = _BrokenPool()
        old_backend = pgm.DB_BACKEND
        pgm.DB_BACKEND = "postgres"
        try:
            result = pgm.pg_insert_event(
                ts=time.time(), ip="1.2.3.4", ua="UA",
                path="/", status=200, reason="ok")
        finally:
            pgm.DB_BACKEND = old_backend
            _state._postgres_pool = old_pool
        assert result is False

    def test_all_optional_fields_default_to_empty(self, monkeypatch):
        """Optional fields (track_key, sid, fp, ja4, request_id) default to ''."""
        _result, conn = self._insert(
            monkeypatch, ts=time.time(), ip="1.2.3.4", ua="UA",
            path="/", status=200, reason="ok")
        args = conn.executions[0][1]
        # args: (ts, ip, ua, path, status, reason, track_key, sid, fp, ja4, request_id)
        assert len(args) == 11
        for field in args[6:]:  # optional fields start at index 6
            assert field == ""


# ══════════════════════════════════════════════════════════════════════════════
# 4. Known SQLite-only tables — documented gap assertions
# ══════════════════════════════════════════════════════════════════════════════

class TestKnownSqliteOnlyTables:
    """
    dlp_patterns, audit_events, and svc_metrics intentionally live ONLY in
    SQLite and are absent from the Postgres schema (db_init_postgres).

    These tests assert the gap is explicit. If you are adding Postgres mirror
    support for any of these tables, remove the corresponding assertion here
    and add migration coverage in TestMigrateRecentEvents.
    """

    def _pg_init_src(self):
        import inspect
        import db.postgres as pgm
        return inspect.getsource(pgm.db_init_postgres)

    def test_dlp_patterns_absent_from_pg_schema(self):
        assert "dlp_patterns" not in self._pg_init_src(), (
            "dlp_patterns must NOT appear in db_init_postgres — it is SQLite-only. "
            "If adding Postgres support, remove this assertion and add migration tests."
        )

    def test_audit_events_absent_from_pg_schema(self):
        assert "audit_events" not in self._pg_init_src(), (
            "audit_events must NOT appear in db_init_postgres — it is SQLite-only. "
            "If adding Postgres support, remove this assertion and add migration tests."
        )

    def test_svc_metrics_absent_from_pg_schema(self):
        assert "svc_metrics" not in self._pg_init_src(), (
            "svc_metrics is a SQLite-only operational scratchpad. "
            "It must NOT appear in db_init_postgres DDL."
        )

    def test_schema_migrations_svc_metrics_pg_ddl_all_none(self):
        """All svc_metrics entries in _SCHEMA_MIGRATIONS must have pg_ddl=None."""
        from db.sqlite import _SCHEMA_MIGRATIONS
        for table, col, _sqlite_ddl, pg_ddl in _SCHEMA_MIGRATIONS:
            if table == "svc_metrics":
                assert pg_ddl is None, (
                    f"svc_metrics.{col} has pg_ddl={pg_ddl!r}; "
                    "svc_metrics is SQLite-only and must never define Postgres DDL"
                )

    def test_dlp_patterns_only_in_sqlite_schema(self):
        """dlp_patterns table DDL exists in db/sqlite.py but not db/postgres.py."""
        import inspect
        import db.sqlite as sqm
        import db.postgres as pgm
        sqlite_src = inspect.getsource(sqm)
        pg_src = inspect.getsource(pgm)
        assert "dlp_patterns" in sqlite_src, (
            "dlp_patterns must be defined in db/sqlite.py"
        )
        assert "dlp_patterns" not in pg_src, (
            "dlp_patterns must NOT be referenced in db/postgres.py"
        )


# ══════════════════════════════════════════════════════════════════════════════
# 5. db_switch_endpoint — structural and source-level validation
# ══════════════════════════════════════════════════════════════════════════════

class TestDbSwitchValidation:
    """
    Validates that the endpoint's guard clauses are present and structurally
    correct. These tests catch accidental removals of critical safety checks
    without requiring a running aiohttp server.
    """

    def _src(self):
        import inspect
        from core.proxy_handler import db_switch_endpoint
        return inspect.getsource(db_switch_endpoint)

    def test_endpoint_is_callable(self):
        from core.proxy_handler import db_switch_endpoint
        import asyncio
        assert callable(db_switch_endpoint)
        assert asyncio.iscoroutinefunction(db_switch_endpoint), (
            "db_switch_endpoint must be an async function"
        )

    def test_target_allowlist_checked(self):
        """Endpoint must reject target values outside {sqlite, postgres}."""
        src = self._src()
        assert '"sqlite"' in src and '"postgres"' in src
        # Either "target not in" or a status=400 response with a message
        assert "target must be sqlite or postgres" in src or \
               "target not in" in src, (
            "db_switch_endpoint must explicitly validate target ∈ {sqlite, postgres}"
        )

    def test_psycopg_availability_checked(self):
        """Endpoint must verify psycopg is loadable before allowing postgres."""
        src = self._src()
        assert "_postgres_load_module" in src, (
            "db_switch_endpoint must call _postgres_load_module() to guard "
            "against psycopg not being installed"
        )
        assert "psycopg not installed" in src, (
            "db_switch_endpoint must return a clear error when psycopg is absent"
        )

    def test_dsn_required_for_postgres(self):
        """Endpoint must check that POSTGRES_DSN is set (or supplied in body)."""
        src = self._src()
        assert "POSTGRES_DSN" in src, (
            "db_switch_endpoint must reference POSTGRES_DSN"
        )
        assert "no POSTGRES_DSN configured" in src, (
            "db_switch_endpoint must return a clear error when DSN is missing"
        )

    def test_roundtrip_probe_called(self):
        """Endpoint must call pg_test_roundtrip() before committing the switch."""
        src = self._src()
        assert "pg_test_roundtrip" in src, (
            "db_switch_endpoint must probe DB connectivity via pg_test_roundtrip() "
            "before persisting the backend change"
        )

    def test_event_migration_called(self):
        """Endpoint must call _migrate_recent_events before restarting."""
        src = self._src()
        assert "_migrate_recent_events" in src, (
            "db_switch_endpoint must call _migrate_recent_events to copy the "
            "recent-events window across the cut-over"
        )

    def test_db_backend_persisted_to_config_kv(self):
        """DB_BACKEND must be written to config_kv before the container exits."""
        src = self._src()
        assert "set_config" in src and "DB_BACKEND" in src, (
            "db_switch_endpoint must persist DB_BACKEND to config_kv so the "
            "new process boots with the correct backend"
        )

    def test_os_exit_used_for_restart(self):
        """1.8.7 — hot-swap: no restart needed; uses _propagate_global instead of os._exit."""
        src = self._src()
        assert "os._exit" not in src, (
            "db_switch_endpoint must NOT call os._exit — 1.8.7 uses _propagate_global hot-swap"
        )
        assert "_propagate_global" in src, (
            "db_switch_endpoint must use _propagate_global for in-process backend switch"
        )

    def test_response_before_exit(self):
        """The JSON response must be returned BEFORE the exit is scheduled."""
        src = self._src()
        # The response must be constructed and returned, then the exit is deferred
        assert "json_response" in src, (
            "db_switch_endpoint must return a JSON response before calling os._exit"
        )
        # asyncio.create_task or similar deferred pattern must be used
        assert "create_task" in src or "asyncio.sleep" in src, (
            "db_switch_endpoint must defer the os._exit call so the HTTP "
            "response can be flushed before the process exits"
        )

    def test_migration_result_in_response(self):
        """Switch response must include migration stats for operator visibility."""
        src = self._src()
        assert "events_copied" in src, (
            "db_switch_endpoint response must include events_copied so the "
            "operator can confirm the migration window was handled"
        )

    def test_db_switch_registered_in_router(self):
        """db-switch endpoint must be registered in the proxy router."""
        import proxy
        assert hasattr(proxy, "db_switch_endpoint") or \
               any("db-switch" in str(r) or "db_switch" in str(r)
                   for r in dir(proxy)), \
               "db_switch_endpoint must be importable from proxy"
        from core.proxy_handler import db_switch_endpoint
        assert callable(db_switch_endpoint)


# ══════════════════════════════════════════════════════════════════════════════
# 6. on_startup calls db_init_postgres when DB_BACKEND=postgres
# ══════════════════════════════════════════════════════════════════════════════

class TestStartupPostgresPath:

    def test_on_startup_calls_db_init_postgres(self):
        """on_startup delegates to _startup_postgres_schema which calls
        db_init_postgres(). Verified via source inspection of both functions."""
        import inspect
        import proxy
        # on_startup must delegate to _startup_postgres_schema
        on_startup_src = inspect.getsource(proxy.on_startup)
        assert "_startup_postgres_schema" in on_startup_src, (
            "on_startup must call _startup_postgres_schema() (which calls "
            "db_init_postgres) so the Postgres schema is initialised on first boot"
        )
        # _startup_postgres_schema must call db_init_postgres
        helper_src = inspect.getsource(proxy._startup_postgres_schema)
        assert "db_init_postgres" in helper_src, (
            "_startup_postgres_schema must call db_init_postgres() so the Postgres "
            "schema is initialised on first boot with DB_BACKEND=postgres"
        )

    def test_db_init_postgres_called_regardless_of_backend(self):
        """db_init_postgres should be called even with DB_BACKEND=sqlite so
        the standby schema is ready for an operator-triggered switch.
        Verified via source: no DB_BACKEND guard immediately before the call."""
        import inspect
        import proxy
        src = inspect.getsource(proxy._startup_postgres_schema)
        # The call must exist in the helper
        assert "db_init_postgres" in src
        # Find the call site and verify there's no 'if DB_BACKEND' guard
        # immediately before it (it was intentionally made unconditional in 1.6.5)
        lines = src.split("\n")
        call_idx = next(
            (i for i, ln in enumerate(lines) if "db_init_postgres" in ln), None)
        assert call_idx is not None
        # Check the line just before the call is not a 'if DB_BACKEND' guard
        if call_idx > 0:
            prev_line = lines[call_idx - 1].strip()
            assert not (prev_line.startswith("if") and "DB_BACKEND" in prev_line), (
                "db_init_postgres() must NOT be guarded by DB_BACKEND — it must "
                "always run so the standby Postgres schema stays ready for a switch"
            )

    def test_db_init_postgres_idempotent_source(self):
        """db_init_postgres must use CREATE TABLE IF NOT EXISTS — safe to call
        multiple times (e.g. on container restart)."""
        import inspect
        import db.postgres as pgm
        src = inspect.getsource(pgm.db_init_postgres)
        assert "CREATE TABLE IF NOT EXISTS" in src, (
            "db_init_postgres must use CREATE TABLE IF NOT EXISTS for idempotency"
        )
        assert "CREATE INDEX IF NOT EXISTS" in src, (
            "db_init_postgres must use CREATE INDEX IF NOT EXISTS for idempotency"
        )
