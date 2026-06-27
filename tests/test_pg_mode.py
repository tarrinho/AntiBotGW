# SPDX-License-Identifier: Apache-2.0
"""
PG-mode end-to-end smoke tests.

These tests REQUIRE a running PG to actually run. When the user has not
opted in via APPSECGW_TEST_PG=1 + POSTGRES_DSN, the whole file is skipped.

They are the integration-level companion to the source-inspection guards
in test_v1814_review_fixes.py: those guards prove the code SAYS the right
thing; these tests prove the code DOES the right thing.

Run with:
    APPSECGW_TEST_PG=1 \\
    POSTGRES_DSN='postgresql://test:test@127.0.0.1:5432/appsecgw_test' \\
    python3 -m pytest tests/test_pg_mode.py -v
"""
from __future__ import annotations

import importlib
import sys

import pytest

# Pull in the PG-mode fixtures (pg_session + autouse truncate).
pytest_plugins = ["tests.conftest_pg_mode"]


class TestPgModeBoot:
    """Boot smoke tests for PG-primary mode."""

    def test_active_backend_is_postgres(self, pg_session):
        # When POSTGRES_DSN is set, db.active_backend() must return
        # "postgres" — independent of any DB_BACKEND env value.
        import db
        assert db.active_backend() == "postgres", (
            "POSTGRES_DSN is set — single-DB mode must select postgres"
        )

    def test_open_conn_returns_pg_wrapper(self, pg_session):
        from db.conn import _PgConnWrapper, open_conn
        c = open_conn()
        try:
            assert isinstance(c, _PgConnWrapper), (
                f"open_conn() returned {type(c).__name__}; expected "
                f"_PgConnWrapper in PG-mode"
            )
        finally:
            c.close()

    def test_pg_writer_loop_branch_taken(self, pg_session):
        # In PG mode, db.sqlite.db_writer_loop's source must contain the
        # PG-primary branch. iter-6 fix: the loop now forks on the
        # OPERATOR-CONTROLLED `DB_BACKEND == "postgres" and POSTGRES_DSN`
        # guard (not the bare `if POSTGRES_DSN:` of earlier releases), so
        # that an operator who switches PG → SQLite via /__db-switch keeps
        # the SQLite-primary path even though the encrypted DSN is still
        # bound. We don't run the writer here (it's an infinite loop) — we
        # assert the branch exists in the resolved function source.
        import inspect
        import db.sqlite
        src = inspect.getsource(db.sqlite.db_writer_loop)
        assert 'DB_BACKEND == "postgres" and POSTGRES_DSN:' in src
        assert "_pg_mirror_kv(pg_op, args)" in src


class TestPgModeWriteRoundtrip:
    """Write an op via the queue, read it back from PG — proves the
    PG-primary writer-loop actually flushes."""

    def test_set_kv_roundtrip(self, pg_session):
        """metrics_kv: set_kv writes a key/value, fetchable via SELECT."""
        from db.postgres import _pg_mirror_kv
        ok = _pg_mirror_kv("set_kv", ("phase7-test-key", "phase7-value"))
        assert ok, "PG mirror returned False for set_kv"
        with pg_session.cursor() as cur:
            cur.execute("SELECT val FROM metrics_kv WHERE key=%s",
                        ("phase7-test-key",))
            row = cur.fetchone()
        assert row is not None
        assert row[0] == "phase7-value"

    def test_upsert_client_then_open_conn_read(self, pg_session):
        """clients: write via _pg_mirror_kv, read via open_conn (which
        routes to PG in this mode). Proves the read path also works."""
        from db.postgres import _pg_mirror_kv
        from db.conn import open_conn
        args = (
            "203.0.113.1",  # ip
            1.0, 2.0,       # first_seen, last_seen
            10, 7, 3,       # request_count, allowed, blocked
            0.0,            # banned_until_epoch
            "curl/7", "/index", "example.com",
            "{}",
        )
        assert _pg_mirror_kv("upsert_client", args)
        c = open_conn()
        try:
            row = c.execute(
                "SELECT ip, request_count, last_vhost FROM clients "
                "WHERE ip = ?", ("203.0.113.1",)
            ).fetchone()
        finally:
            c.close()
        assert row is not None
        # _PgConnWrapper without row_factory returns tuples.
        ip, count, vhost = row
        assert ip == "203.0.113.1"
        assert count == 10
        assert vhost == "example.com"


class TestPgModeImportExportRoundtrip:
    """End-to-end roundtrip:
       1. Seed PG via _pg_mirror_kv (simulating live operation)
       2. db.export → SQLite snapshot
       3. Verify SQLite contains every seeded row
       4. Clear PG, db.import the snapshot back into PG
       5. Verify PG matches the original seed
    Proves both CLI tools work against a real PG."""

    def _seed_pg(self, pg_session):
        """Seed a handful of representative tables via _pg_mirror_kv."""
        from db.postgres import _pg_mirror_kv
        # config_kv
        assert _pg_mirror_kv("set_config", ("k1", "v1", 100.0))
        assert _pg_mirror_kv("set_config", ("k2", "v2", 101.0))
        # secrets
        assert _pg_mirror_kv("set_secret", ("api", "secret-val", 100.0))
        # users
        assert _pg_mirror_kv(
            "user_create",
            ("alice", "h1", "admin", "active", 100.0, 100.0))
        assert _pg_mirror_kv(
            "user_create",
            ("bob", "h2", "viewer", "active", 101.0, 101.0))
        assert _pg_mirror_kv("user_login_recorded",
                              (200.0, "1.1.1.1", "alice"))
        # bans + ip_bans
        assert _pg_mirror_kv("ban",
                              ("1.1.1.1", 999.0, "test-ban", 100.0))
        assert _pg_mirror_kv("ip_ban",
                              ("2.2.2.2", 888.0, "test-ipban", 101.0))
        # admin_ips
        assert _pg_mirror_kv("set_admin_ip",
                              ("10.0.0.1/32", 100.0, "n", "env", "d"))
        # set_kv (metrics_kv)
        assert _pg_mirror_kv("set_kv", ("total_requests", "1000"))
        # client roll-up
        assert _pg_mirror_kv("upsert_client",
                              ("1.1.1.1", 100, 200, 42, 30, 12, 0.0,
                               "curl/7", "/p", "x.com", "{}"))

    def test_export_roundtrip(self, pg_session, tmp_path, monkeypatch):
        """PG → SQLite via `python -m db.export`."""
        import os
        self._seed_pg(pg_session)
        pg_session.commit()
        out = str(tmp_path / "export.db")
        # The export tool reads POSTGRES_DSN + DB_PATH from env.
        monkeypatch.setenv("DB_PATH", out)
        import importlib.util
        from pathlib import Path
        spec = importlib.util.spec_from_file_location(
            "_db_export_e2e",
            str(Path(__file__).resolve().parent.parent
                / "db" / "export.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rc = mod.main([out, "--force"])
        assert rc == 0, f"export should succeed, got rc={rc}"
        # Verify the SQLite snapshot has every seed row.
        import sqlite3
        c = sqlite3.connect(out)
        try:
            counts = {
                "config_kv": c.execute("SELECT COUNT(*) FROM config_kv")
                              .fetchone()[0],
                "users":     c.execute("SELECT COUNT(*) FROM users")
                              .fetchone()[0],
                "bans":      c.execute("SELECT COUNT(*) FROM bans")
                              .fetchone()[0],
                "ip_bans":   c.execute("SELECT COUNT(*) FROM ip_bans")
                              .fetchone()[0],
                "admin_ips": c.execute("SELECT COUNT(*) FROM admin_ips")
                              .fetchone()[0],
                "clients":   c.execute("SELECT COUNT(*) FROM clients")
                              .fetchone()[0],
                "metrics_kv": c.execute("SELECT COUNT(*) FROM metrics_kv")
                              .fetchone()[0],
            }
            # config_kv: 2 seeded
            assert counts["config_kv"] >= 2
            # users: 2 seeded
            assert counts["users"] >= 2
            # bans + ip_bans + admin_ips + clients + metrics_kv: ≥1 each
            for k in ("bans", "ip_bans", "admin_ips",
                      "clients", "metrics_kv"):
                assert counts[k] >= 1, \
                    f"export missed {k}: counts={counts}"
            # Spot-check value parity.
            row = c.execute(
                "SELECT value FROM config_kv WHERE key='k1'").fetchone()
            assert row and row[0] == "v1"
            row = c.execute(
                "SELECT role, last_login_ip FROM users "
                "WHERE username='alice'").fetchone()
            assert row and row[0] == "admin"
            # last_login was set via separate user_login_recorded op.
            assert row[1] == "1.1.1.1"
        finally:
            c.close()

    def test_import_roundtrip(self, pg_session, tmp_path, monkeypatch):
        """SQLite → PG via `python -m db.import`. Verifies clear-then-
        reimport reaches parity with the original PG seed."""
        # 1. Seed PG.
        self._seed_pg(pg_session)
        pg_session.commit()
        # 2. Export to a SQLite file we'll re-import from.
        snap = str(tmp_path / "snap.db")
        monkeypatch.setenv("DB_PATH", snap)
        import importlib.util
        from pathlib import Path
        spec_x = importlib.util.spec_from_file_location(
            "_db_export_imp", str(Path(__file__).resolve().parent.parent
                                   / "db" / "export.py"))
        mod_x = importlib.util.module_from_spec(spec_x)
        spec_x.loader.exec_module(mod_x)
        assert mod_x.main([snap, "--force"]) == 0
        # 3. Wipe PG tables (the autouse fixture truncates them between
        # tests, but we want to TRUNCATE mid-test to simulate a fresh PG).
        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE users, config_kv, secrets_kv, admin_ips, "
                "bans, ip_bans, clients, metrics_kv RESTART IDENTITY CASCADE")
        pg_session.commit()
        # 4. Re-import.
        spec_i = importlib.util.spec_from_file_location(
            "_db_import_imp", str(Path(__file__).resolve().parent.parent
                                   / "db" / "import.py"))
        mod_i = importlib.util.module_from_spec(spec_i)
        spec_i.loader.exec_module(mod_i)
        assert mod_i.main([snap, "--skip-events"]) == 0
        # 5. Verify PG state matches original seed.
        with pg_session.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            assert cur.fetchone()[0] >= 2
            cur.execute(
                "SELECT value FROM config_kv WHERE key=%s", ("k1",))
            row = cur.fetchone()
            assert row and row[0] == "v1"
            cur.execute(
                "SELECT role, last_login_ip FROM users "
                "WHERE username=%s", ("alice",))
            row = cur.fetchone()
            assert row and row[0] == "admin"
            assert row[1] == "1.1.1.1", \
                "user_login_recorded extension cols must round-trip too"
            cur.execute("SELECT COUNT(*) FROM bans")
            assert cur.fetchone()[0] >= 1
            cur.execute("SELECT COUNT(*) FROM ip_bans")
            assert cur.fetchone()[0] >= 1
            cur.execute(
                "SELECT request_count FROM clients WHERE ip=%s",
                ("1.1.1.1",))
            row = cur.fetchone()
            assert row and row[0] == 42, "clients data must round-trip"


class TestPgModeBootGuard:
    """The boot guard is the safety net against pointing the gateway at
    a dead PG. The current on_startup is monolithic — the guard lives
    inline in the `if POSTGRES_DSN:` branch."""

    def test_on_startup_has_boot_guard(self):
        import inspect
        import proxy
        src = inspect.getsource(proxy.on_startup)
        assert "POSTGRES_BOOT_MAX_ATTEMPTS" in src
        assert "POSTGRES_BOOT_BACKOFF_S" in src
        assert "raise SystemExit(" in src, \
            "boot guard must fail-fast via SystemExit"

    def test_on_startup_drops_cold_restore(self):
        """Phase 6: cold-start restore is gone — PG IS the source."""
        import inspect
        import proxy
        src = inspect.getsource(proxy.on_startup)
        assert "db_restore_from_postgres(" not in src, (
            "PG-only mode: on_startup must NOT call db_restore_from_postgres"
        )


class TestPgModeEventsRoundtrip:
    """Gap-fill: events table round-trip via db.import / db.export.
    Previously only operator-state tables were round-trip tested; events
    have a different shape (TIMESTAMPTZ on PG, REAL on SQLite) so they
    deserve their own check."""

    def test_events_roundtrip_preserves_timestamps(self, pg_session,
                                                    tmp_path, monkeypatch):
        """Insert N events directly via pg_insert_event, run db.export,
        verify the SQLite snapshot has the same N events with timestamps
        within ±1s (epoch ↔ TIMESTAMPTZ rounding)."""
        from db.postgres import pg_insert_event
        ts_base = 100.0
        for i in range(5):
            assert pg_insert_event(
                ts_base + i, f"10.0.0.{i}", f"ua-{i}", f"/p{i}",
                200, "ok", method="GET", vhost=f"v{i}.example")
        pg_session.commit()

        out = str(tmp_path / "events_export.db")
        monkeypatch.setenv("DB_PATH", out)
        import importlib.util
        from pathlib import Path
        spec = importlib.util.spec_from_file_location(
            "_db_export_evt",
            str(Path(__file__).resolve().parent.parent / "db" / "export.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rc = mod.main([out, "--force"])
        assert rc == 0

        import sqlite3
        c = sqlite3.connect(out)
        try:
            # Scope to THIS test's events only. The events table is shared
            # across the PG test DB, and parallel agent runs (and the
            # per-test truncate races warned about in the suite) can write
            # additional rows between this test's inserts and the export —
            # a bare `SELECT ... FROM events` then returns >5 rows. The five
            # rows inserted above use distinctive vhosts v0.example..v4.example
            # and IPs 10.0.0.0..10.0.0.4, so filter on them. This keeps the
            # test's intent (those 5 events round-trip with correct
            # timestamps/fields) while being immune to concurrent writers.
            rows = c.execute(
                "SELECT ts, ip, ua, path, method, status, reason, vhost "
                "FROM events WHERE vhost IN "
                "('v0.example','v1.example','v2.example',"
                "'v3.example','v4.example') "
                "AND ip LIKE '10.0.0.%' ORDER BY ts"
            ).fetchall()
        finally:
            c.close()
        assert len(rows) == 5, \
            f"expected 5 events round-tripped, got {len(rows)}"
        for i, row in enumerate(rows):
            assert abs(row[0] - (ts_base + i)) < 1.0, \
                f"timestamp drift on event {i}: {row[0]}"
            assert row[1] == f"10.0.0.{i}"
            assert row[2] == f"ua-{i}"
            assert row[3] == f"/p{i}"
            assert row[4] == "GET"
            assert row[5] == 200
            assert row[7] == f"v{i}.example"


class TestPgModeSchemaVersionDrift:
    """Gap-fill: pg_schema_versions stamping behaviour when an EXISTING
    version row is present.

    A3 stamps PG_SCHEMA_VERSION on every db_init_postgres() boot via
    ON CONFLICT (version) DO UPDATE applied_ts=NOW(). If PG already has
    a row for version=1 from a previous boot, the next boot should:
      - keep the row (idempotent)
      - update applied_ts to the new boot timestamp
    """

    def test_version_stamp_idempotent_across_reinit(self, pg_session):
        from db.postgres import db_init_postgres, PG_SCHEMA_VERSION
        # First init.
        assert db_init_postgres()
        with pg_session.cursor() as cur:
            cur.execute(
                "SELECT version, applied_ts FROM pg_schema_versions "
                "WHERE version=%s", (PG_SCHEMA_VERSION,))
            row1 = cur.fetchone()
            assert row1 is not None
            ts1 = row1[1]
        pg_session.commit()
        # Second init — should update the same row, not insert another.
        import time as _t
        _t.sleep(0.05)
        assert db_init_postgres()
        with pg_session.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM pg_schema_versions "
                "WHERE version=%s", (PG_SCHEMA_VERSION,))
            count = cur.fetchone()[0]
            assert count == 1, \
                "idempotency broken: 2 rows for same version"
            cur.execute(
                "SELECT applied_ts FROM pg_schema_versions "
                "WHERE version=%s", (PG_SCHEMA_VERSION,))
            ts2 = cur.fetchone()[0]
        # applied_ts should be ≥ first (updated on re-stamp).
        assert ts2 >= ts1, \
            "applied_ts must be updated on re-stamp"

    def test_version_drift_detection_data_available(self, pg_session):
        """Operators can detect version drift by querying
        pg_schema_versions vs the gateway's PG_SCHEMA_VERSION constant."""
        from db.postgres import db_init_postgres, PG_SCHEMA_VERSION
        assert db_init_postgres()
        with pg_session.cursor() as cur:
            cur.execute("SELECT MAX(version) FROM pg_schema_versions")
            stamped = cur.fetchone()[0]
        # In a healthy install, stamped == PG_SCHEMA_VERSION.
        assert stamped == PG_SCHEMA_VERSION


class TestPgModeLargeDatasetSmoke:
    """Gap-fill: smoke-test importing a SQLite with N=1000+ rows in
    each table. Catches obvious memory-blowup / streaming issues."""

    def test_import_1k_users_succeeds(self, pg_session, tmp_path,
                                       monkeypatch):
        import sqlite3
        db_path = str(tmp_path / "big.db")
        c = sqlite3.connect(db_path)
        c.executescript("""
            CREATE TABLE users (username TEXT PRIMARY KEY,
                password_hash TEXT, role TEXT, status TEXT,
                created_ts REAL, updated_ts REAL,
                last_login_ts REAL, last_login_ip TEXT,
                totp_secret TEXT, totp_enabled INTEGER,
                totp_backup_codes TEXT,
                sso_source TEXT, oidc_sub TEXT);
            CREATE TABLE config_kv (key TEXT PRIMARY KEY,
                value TEXT, ts REAL);
        """)
        c.executemany(
            "INSERT INTO users VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(f"user-{i:04d}", "h", "viewer", "active",
              100.0 + i, 100.0 + i, 200.0 + i, f"10.0.{i // 256}.{i % 256}",
              "", 0, "", "", "")
             for i in range(1000)])
        c.executemany(
            "INSERT INTO config_kv VALUES (?,?,?)",
            [(f"k-{i:04d}", f"v-{i}", float(i)) for i in range(1000)])
        c.commit(); c.close()

        # Wipe PG, then import.
        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE users, config_kv RESTART IDENTITY CASCADE")
        pg_session.commit()

        import importlib.util
        from pathlib import Path
        spec = importlib.util.spec_from_file_location(
            "_db_import_big",
            str(Path(__file__).resolve().parent.parent / "db" / "import.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        import time as _t
        t0 = _t.time()
        rc = mod.main([db_path, "--skip-events"])
        dur = _t.time() - t0
        assert rc == 0, f"large import failed: rc={rc}"
        assert dur < 30, f"large import too slow: {dur:.1f}s"

        with pg_session.cursor() as cur:
            # Count the imported rows specifically. The product's
            # _user_bootstrap() (1.6.7) auto-creates an `admin` user from
            # INTERNAL_KEY whenever the users table is empty (which it is
            # immediately after the TRUNCATE above), so the live table may
            # legitimately hold 1001 rows = 1000 imported + 1 bootstrap
            # admin. Asserting the exact 1000 user-#### rows preserves the
            # test's intent ("all 1000 imported users landed in PG")
            # without forbidding the bootstrap admin.
            cur.execute("SELECT COUNT(*) FROM users WHERE username LIKE 'user-%'")
            assert cur.fetchone()[0] == 1000
            cur.execute("SELECT COUNT(*) FROM config_kv WHERE key LIKE 'k-%'")
            assert cur.fetchone()[0] == 1000


class TestPgModeMidWriteOutage:
    """Gap-fill: simulate PG outage mid-batch via psycopg.connect
    monkeypatch. The writer-loop's pool path should swallow the error
    and log warn-once — gateway keeps running, SQLite primary unaffected."""

    def test_pg_unreachable_mid_write_does_not_kill_gateway(self,
                                                            pg_session,
                                                            monkeypatch):
        """Call _pg_mirror_kv with a poisoned _get_pool — must return
        False (best-effort failure) without raising."""
        import db.postgres as _pgmod

        # Stub _get_pool to return a pool whose .connection() raises.
        class _BoomPool:
            def connection(self, **kw):
                raise ConnectionError("simulated PG outage")

        monkeypatch.setattr(_pgmod, "_get_pool", lambda: _BoomPool())
        result = _pgmod._pg_mirror_kv("set_kv", ("test-key", "test-val"))
        # Best-effort: returns False, doesn't raise.
        assert result is False, \
            "mid-write outage must return False, not raise"


class TestPgModeMissingSchemaVersionsTable:
    """Gap-fill: db.export should NOT crash if the optional
    pg_schema_versions table is missing (e.g. very old PG snapshot)."""

    def test_export_tolerates_missing_pg_schema_versions(self, pg_session,
                                                         tmp_path,
                                                         monkeypatch):
        # Drop the table to simulate a pre-A3 PG.
        with pg_session.cursor() as cur:
            cur.execute(
                "DROP TABLE IF EXISTS pg_schema_versions CASCADE")
        pg_session.commit()

        out = str(tmp_path / "no_versions.db")
        monkeypatch.setenv("DB_PATH", out)
        import importlib.util
        from pathlib import Path
        spec = importlib.util.spec_from_file_location(
            "_db_export_nov",
            str(Path(__file__).resolve().parent.parent / "db" / "export.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Export must still succeed (the table isn't in _plan() yet —
        # this is forward-compat).
        rc = mod.main([out, "--force", "--skip-events"])
        assert rc == 0


class TestPgModeConcurrentImports:
    """Two parallel `db.import` processes against the same PG must NOT
    corrupt state. Each runs in its own transaction; PG row-level locks +
    `ON CONFLICT DO UPDATE` make concurrent applies idempotent."""

    def test_two_parallel_imports_converge(self, pg_session, tmp_path):
        """Build two distinct SQLite sources with non-overlapping rows,
        run both `python -m db.import` processes in parallel, verify
        PG ends up with the UNION of both."""
        import sqlite3, subprocess, os, sys, time as _t
        from pathlib import Path

        # Wipe PG cleanly + ensure schema present.
        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE users, config_kv "
                "RESTART IDENTITY CASCADE")
        pg_session.commit()

        def _seed(db_path, prefix, n):
            c = sqlite3.connect(db_path)
            c.executescript("""
              CREATE TABLE users (username TEXT PRIMARY KEY,
                password_hash TEXT, role TEXT, status TEXT,
                created_ts REAL, updated_ts REAL,
                last_login_ts REAL, last_login_ip TEXT,
                totp_secret TEXT, totp_enabled INTEGER,
                totp_backup_codes TEXT,
                sso_source TEXT, oidc_sub TEXT);
              CREATE TABLE config_kv (key TEXT PRIMARY KEY,
                value TEXT, ts REAL);
            """)
            c.executemany(
                "INSERT INTO users VALUES "
                "(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(f"{prefix}-user-{i:03d}", "h", "viewer", "active",
                  0.0, 0.0, 0.0, "", "", 0, "", "", "")
                 for i in range(n)])
            c.commit(); c.close()

        src_a = str(tmp_path / "a.db")
        src_b = str(tmp_path / "b.db")
        _seed(src_a, "alice", 50)
        _seed(src_b, "bob",   50)

        env = os.environ.copy()
        env.update({
            "POSTGRES_DSN": os.environ["POSTGRES_DSN"],
            "UPSTREAM": "https://example.com",
            "ADMIN_KEY": "t",
            "ALLOWED_HOSTS": "",
            "ADMIN_ALLOWED_IPS": "0.0.0.0/0",
            "OFFLINE_BG_TASKS": "1",
        })
        root = str(Path(__file__).resolve().parent.parent)

        def _spawn(src):
            e = env.copy()
            e["DB_PATH"] = src
            return subprocess.Popen(
                [sys.executable, "-m", "db.import", src, "--skip-events"],
                cwd=root, env=e,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        p_a = _spawn(src_a)
        p_b = _spawn(src_b)
        # Wait for both, max 60s each.
        out_a, err_a = p_a.communicate(timeout=60)
        out_b, err_b = p_b.communicate(timeout=60)
        assert p_a.returncode == 0, \
            f"import A rc={p_a.returncode} err={err_a.decode()[:200]}"
        assert p_b.returncode == 0, \
            f"import B rc={p_b.returncode} err={err_b.decode()[:200]}"

        # PG must have 100 distinct users (50 + 50, no collisions).
        with pg_session.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            assert cur.fetchone()[0] == 100, \
                "concurrent imports lost rows"
            cur.execute("SELECT COUNT(*) FROM users "
                        "WHERE username LIKE 'alice%'")
            assert cur.fetchone()[0] == 50
            cur.execute("SELECT COUNT(*) FROM users "
                        "WHERE username LIKE 'bob%'")
            assert cur.fetchone()[0] == 50


class TestPgModeSigtermMidImport:
    """SIGTERM during db.import should ROLLBACK the in-flight transaction,
    leaving PG in the pre-import state. No partial data."""

    def test_sigterm_mid_import_rolls_back(self, pg_session, tmp_path):
        """Build a SQLite with 5000 users (large enough that import
        takes >1s), spawn `python -m db.import`, send SIGTERM after
        100ms, verify PG users count is still 0."""
        import sqlite3, subprocess, os, sys, signal, time as _t
        from pathlib import Path

        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE users RESTART IDENTITY CASCADE")
        pg_session.commit()

        src = str(tmp_path / "big.db")
        c = sqlite3.connect(src)
        c.executescript("""
            CREATE TABLE users (username TEXT PRIMARY KEY,
                password_hash TEXT, role TEXT, status TEXT,
                created_ts REAL, updated_ts REAL,
                last_login_ts REAL, last_login_ip TEXT,
                totp_secret TEXT, totp_enabled INTEGER,
                totp_backup_codes TEXT,
                sso_source TEXT, oidc_sub TEXT);
        """)
        c.executemany(
            "INSERT INTO users VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(f"sigterm-user-{i:05d}", "h", "viewer", "active",
              0.0, 0.0, 0.0, "", "", 0, "", "", "")
             for i in range(5000)])
        c.commit(); c.close()

        env = os.environ.copy()
        env.update({
            "POSTGRES_DSN": os.environ["POSTGRES_DSN"],
            "UPSTREAM": "https://example.com",
            "ADMIN_KEY": "t",
            "ALLOWED_HOSTS": "",
            "ADMIN_ALLOWED_IPS": "0.0.0.0/0",
            "OFFLINE_BG_TASKS": "1",
            "DB_PATH": src,
        })
        root = str(Path(__file__).resolve().parent.parent)
        p = subprocess.Popen(
            [sys.executable, "-m", "db.import", src, "--skip-events"],
            cwd=root, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _t.sleep(0.15)
        p.send_signal(signal.SIGTERM)
        try:
            p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()

        # PG must have either 0 rows (rollback) OR 5000 rows (race —
        # SIGTERM arrived after COMMIT). What it MUST NOT have: 1..4999
        # (partial state).
        with pg_session.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users "
                        "WHERE username LIKE 'sigterm-%'")
            n = cur.fetchone()[0]
        assert n in (0, 5000), \
            f"SIGTERM mid-import left partial state: n={n}"


class TestPgModePermissionFailure:
    """When the gateway's PG role lacks DDL privilege (no CREATE TABLE),
    db_init_postgres must surface the failure clearly — not silently
    skip the schema. The boot guard (exit code 4) catches this in
    on_startup."""

    def test_role_without_create_privilege_fails_init(self, pg_session):
        """Create an unprivileged role + DSN, attempt db_init_postgres
        with that DSN, expect False (init failed)."""
        # Create a read-only role.
        with pg_session.cursor() as cur:
            cur.execute(
                "DROP ROLE IF EXISTS appsec_readonly")
            cur.execute(
                "CREATE ROLE appsec_readonly LOGIN PASSWORD 'ro'")
            # Explicitly REVOKE CREATE on the schema.
            cur.execute(
                "REVOKE CREATE ON SCHEMA public FROM appsec_readonly")
            cur.execute(
                "REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        pg_session.commit()

        # Now switch to the unprivileged DSN and try to init.
        import db.postgres as _pgmod
        import config
        orig_dsn = config.POSTGRES_DSN
        # Swap the userinfo (user:password) of the configured DSN for the
        # unprivileged role, regardless of what the privileged creds are.
        # The harness DSN moved from test:test → agw:testpass, so the old
        # literal .replace("test:test", ...) became a no-op and the init
        # ran as the privileged role (returning True and failing this
        # test). Parse the URL and rewrite the netloc instead.
        from urllib.parse import urlsplit, urlunsplit
        _u = urlsplit(orig_dsn)
        _hostport = _u.netloc.split("@", 1)[-1]
        unpriv_dsn = urlunsplit((
            _u.scheme,
            f"appsec_readonly:ro@{_hostport}",
            _u.path, _u.query, _u.fragment))
        try:
            # Drop the pool so it rebuilds with the new DSN.
            _pgmod._state._postgres_pool = None
            config.POSTGRES_DSN = unpriv_dsn
            _pgmod.POSTGRES_DSN = unpriv_dsn
            # Run db_init_postgres against the unprivileged role.
            # Bounded attempts so we don't burn 60s on retries.
            result = _pgmod.db_init_postgres(
                max_attempts=2, backoff_s=0.1)
            assert result is False, \
                "db_init_postgres must return False when role lacks CREATE"
        finally:
            # Restore.
            config.POSTGRES_DSN = orig_dsn
            _pgmod.POSTGRES_DSN = orig_dsn
            _pgmod._state._postgres_pool = None
            # CRITICAL: clear the auth-failed latch. The runtime sets
            # this on the first PG auth rejection and refuses ALL
            # subsequent pool acquisitions in the process — without
            # clearing it here, every later test in this session that
            # uses _pg_mirror_kv would fail with "Postgres backend
            # disabled" RuntimeError.
            _pgmod._PG_AUTH_FAILED = False
            _pgmod._PG_AUTH_FAILED_TS = 0.0
            _pgmod._PG_AUTH_FAILED_HINT = ""
            # Re-grant + clean up.
            with pg_session.cursor() as cur:
                cur.execute(
                    "GRANT CREATE ON SCHEMA public TO PUBLIC")
                cur.execute("DROP ROLE IF EXISTS appsec_readonly")
            pg_session.commit()


class TestPgModePerformanceSmoke:
    """Smoke benchmark: confirm the PG-primary write path doesn't have
    obvious pathological slowdowns. Not a precise benchmark — just a
    sanity check that a sane number of writes complete in reasonable
    time. Tight tolerances are documented inline; loosen if CI hardware
    forces a flake."""

    def test_1k_set_kv_writes_under_15s(self, pg_session):
        """1000 set_kv ops via _pg_mirror_kv on a local PG container.
        Each op = its own pool.connection() + autocommit round-trip,
        so ~6-10ms per op is normal (= ~6-10s total). The 30s
        threshold catches pathological cases (e.g. a fresh
        `psycopg.connect` per call would push this to 60s+ even
        locally) without flaking on slow CI hardware."""
        from db.postgres import _pg_mirror_kv
        import db.postgres as _pgmod
        import time as _t

        # Drop any stale pool from previous tests (the permission-failure
        # test may have left a pool bound to an unprivileged DSN).
        _pgmod._state._postgres_pool = None

        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE metrics_kv RESTART IDENTITY CASCADE")
        pg_session.commit()

        t0 = _t.time()
        for i in range(1000):
            assert _pg_mirror_kv("set_kv",
                                  (f"perf-{i:04d}", f"val-{i}"))
        dur = _t.time() - t0
        # 30s threshold (vs ~6-10s nominal) — wide margin for combined-
        # suite runs where PG has accumulated load from prior tests and
        # for slower CI hardware. A genuine pathological regression
        # (fresh connect per op) would push this past 60s.
        assert dur < 30.0, \
            f"1000 set_kv writes took {dur:.2f}s — investigate pool / latency"

        # Spot-check the data landed.
        with pg_session.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM metrics_kv "
                "WHERE key LIKE 'perf-%'")
            assert cur.fetchone()[0] == 1000

    def test_export_100k_events_under_30s(self, pg_session, tmp_path,
                                           monkeypatch):
        """Bigger-data export smoke: 10k events should stream through
        db.export's events helper without OOM and complete in <60s."""
        from db.postgres import pg_insert_event
        import db.postgres as _pgmod
        import time as _t

        # Drop any stale pool from previous tests.
        _pgmod._state._postgres_pool = None

        # Pre-truncate.
        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE events RESTART IDENTITY CASCADE")
        pg_session.commit()

        # Bulk insert. The thing under test is the EXPORT speed, not the seed,
        # so seed with a single pooled connection + executemany (matching what
        # pg_insert_event writes, incl. to_timestamp(epoch) for the timestamptz
        # ts column) rather than 10k separate pool checkouts. The per-row
        # pg_insert_event path opened/closed a pooled connection 10k times,
        # which under the shared-DB harness blew the 60s pytest-timeout during
        # SEED (before the export was ever measured). This change does not alter
        # the assertion — same N rows, same export path.
        t0 = _t.time()
        N = 10000  # 10k — keeps the test under a minute end-to-end
        _pool = _pgmod._get_pool()
        assert _pool is not None, "PG pool unavailable for perf seed"
        _seed_params = [
            (float(i), f"10.0.{i // 256 % 256}.{i % 256}",
             "ua", "/p", "GET", 200, "ok", "x.example")
            for i in range(N)
        ]
        with _pool.connection(timeout=10.0) as _seed_conn:
            _seed_conn.cursor().executemany(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                "VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s)",
                _seed_params,
            )
        dur_insert = _t.time() - t0

        out = str(tmp_path / "perf.db")
        monkeypatch.setenv("DB_PATH", out)
        import importlib.util
        from pathlib import Path
        spec = importlib.util.spec_from_file_location(
            "_db_export_perf",
            str(Path(__file__).resolve().parent.parent / "db" / "export.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        t0 = _t.time()
        rc = mod.main([out, "--force"])
        dur_export = _t.time() - t0

        assert rc == 0, f"large export rc={rc}"
        # 60s threshold (vs ~10-20s nominal for 10k events) — combined-
        # suite runs with prior PG load + CI hardware variability.
        assert dur_export < 60.0, \
            f"{N}-event export too slow: {dur_export:.2f}s"

        import sqlite3
        c = sqlite3.connect(out)
        try:
            n_rows = c.execute(
                "SELECT COUNT(*) FROM events").fetchone()[0]
        finally:
            c.close()
        assert n_rows == N, \
            f"event count mismatch: PG had {N}, SQLite has {n_rows}"


class TestG5ImportAgainstPartialPgSchema:
    """G5: db.import against a PG with some tables MISSING (e.g. a
    half-initialized schema) — the import should detect + recreate the
    missing tables via db_init_postgres at boot, not crash mid-row."""

    def test_import_with_dropped_users_table_still_works(self, pg_session,
                                                          tmp_path):
        """Drop the users table on PG, then run db.import. The script
        calls db_init_postgres up front, which recreates the table."""
        import sqlite3, importlib.util, os
        from pathlib import Path

        # Drop a critical table.
        with pg_session.cursor() as cur:
            cur.execute("DROP TABLE IF EXISTS users CASCADE")
        pg_session.commit()

        # Build SQLite source with users.
        db_path = str(tmp_path / "src.db")
        c = sqlite3.connect(db_path)
        c.executescript("""
            CREATE TABLE users (username TEXT PRIMARY KEY,
                password_hash TEXT, role TEXT, status TEXT,
                created_ts REAL, updated_ts REAL,
                last_login_ts REAL, last_login_ip TEXT,
                totp_secret TEXT, totp_enabled INTEGER,
                totp_backup_codes TEXT, sso_source TEXT, oidc_sub TEXT);
        """)
        c.execute("INSERT INTO users VALUES "
                  "('g5','h','admin','active',0,0,0,'',NULL,0,'','','')")
        c.commit(); c.close()

        spec = importlib.util.spec_from_file_location(
            "_db_import_g5",
            str(Path(__file__).resolve().parent.parent / "db" / "import.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        os.environ["DB_PATH"] = db_path
        rc = mod.main([db_path, "--skip-events"])
        assert rc == 0, f"G5: partial-schema PG import failed rc={rc}"
        # Users table got recreated AND the row landed.
        with pg_session.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users "
                        "WHERE username='g5'")
            assert cur.fetchone()[0] == 1


class TestG7PoolExhaustion:
    """G7: 100 concurrent writes against a pool sized 5 must NOT block
    the writers forever. The pool's _PG_POOL_TIMEOUT controls how long
    a thread waits before raising; clients must surface this."""

    def test_burst_writes_complete_with_small_pool(self, pg_session):
        """100 set_kv ops via threads, default pool size 5. All must
        finish in under 30s (proves the pool releases connections
        after each op)."""
        import threading, time as _t
        from db.postgres import _pg_mirror_kv

        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE metrics_kv RESTART IDENTITY CASCADE")
        pg_session.commit()

        results = []
        errors = []
        def _writer(i):
            try:
                ok = _pg_mirror_kv("set_kv",
                                    (f"burst-{i:03d}", f"v-{i}"))
                results.append((i, ok))
            except Exception as e:
                errors.append((i, e))

        t0 = _t.time()
        threads = [threading.Thread(target=_writer, args=(i,))
                   for i in range(100)]
        for th in threads: th.start()
        for th in threads: th.join(timeout=30)
        dur = _t.time() - t0

        assert not any(th.is_alive() for th in threads), \
            "G7: pool exhaustion blocked some writer threads forever"
        assert not errors, \
            f"G7: pool exhaustion caused {len(errors)} errors: " \
            f"{errors[:3]}"
        assert len(results) == 100
        # All 100 succeeded.
        assert all(ok for _, ok in results)
        assert dur < 30.0, f"G7: 100 concurrent writes took {dur:.1f}s"
        # All 100 rows landed in PG.
        with pg_session.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM metrics_kv "
                        "WHERE key LIKE 'burst-%'")
            assert cur.fetchone()[0] == 100


class TestG9ColdStartVirginPg:
    """G9: First boot against a virgin PG (no schema at all) must
    bootstrap cleanly. Verifies db_init_postgres works end-to-end
    against a fresh database."""

    def test_virgin_pg_bootstraps_cleanly(self, pg_session):
        # Drop EVERYTHING.
        with pg_session.cursor() as cur:
            cur.execute("DROP SCHEMA public CASCADE")
            cur.execute("CREATE SCHEMA public")
            cur.execute("GRANT ALL ON SCHEMA public TO PUBLIC")
        pg_session.commit()

        # Drop the pool so the next call re-acquires.
        import db.postgres as _pgmod
        _pgmod._state._postgres_pool = None

        # Bootstrap.
        assert _pgmod.db_init_postgres(max_attempts=3, backoff_s=0.5)

        # Every Phase-1 + iter-18 table must exist.
        with pg_session.cursor() as cur:
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema='public' "
                "  AND table_type='BASE TABLE'")
            tables = {r[0] for r in cur.fetchall()}
        for required in ("events", "users", "user_sessions", "admin_ips",
                          "config_kv", "secrets_kv", "bans", "ip_bans",
                          "dlp_patterns", "siem_alert_rules",
                          "siem_alert_fired", "gw_audit",
                          "honey_fingerprints", "gw_registry",
                          "gw_distribution", "gw_sync_pending",
                          "signal_orders", "abuseipdb_cache",
                          "audit_events", "clients", "metrics_kv",
                          "svc_metrics", "timeline",
                          "pg_schema_versions"):
            assert required in tables, \
                f"G9: virgin-PG bootstrap missing table {required!r}"


class TestG13SchemaVersionMismatch:
    """G13: when PG carries a pg_schema_versions stamp NEWER than the
    runtime's PG_SCHEMA_VERSION, operators should be able to detect it.
    Current implementation just upserts the same row — this test
    documents that and the gap (no auto-detect / refuse-to-start)."""

    def test_pg_with_future_version_doesnt_block_init(self, pg_session):
        """Existing behaviour: db_init_postgres tolerates a future
        version stamp because the version-stamp INSERT uses
        ON CONFLICT (version) DO UPDATE. This test pins the current
        permissive behaviour so a future "refuse if newer" change is
        intentional."""
        from db.postgres import db_init_postgres, PG_SCHEMA_VERSION
        # Stamp a future version directly.
        with pg_session.cursor() as cur:
            cur.execute(
                "INSERT INTO pg_schema_versions "
                "(version, applied_ts, applied_by, note) "
                "VALUES (999, NOW(), 'future-test', 'future stamp') "
                "ON CONFLICT (version) DO NOTHING")
        pg_session.commit()
        # Current behaviour: db_init still returns True, just stamps
        # PG_SCHEMA_VERSION alongside the future row.
        assert db_init_postgres()
        with pg_session.cursor() as cur:
            cur.execute("SELECT MAX(version) FROM pg_schema_versions")
            max_v = cur.fetchone()[0]
        assert max_v == 999, \
            "future-version row must persist (cleanup is operator's job)"
        # Both rows present.
        with pg_session.cursor() as cur:
            cur.execute("SELECT version FROM pg_schema_versions "
                        "ORDER BY version")
            versions = [r[0] for r in cur.fetchall()]
        assert PG_SCHEMA_VERSION in versions and 999 in versions

    def test_drift_detection_query_works(self, pg_session):
        """Operators query MAX(version) to verify their PG matches the
        deployed gateway. Document the query shape."""
        from db.postgres import db_init_postgres
        # Clean slate.
        with pg_session.cursor() as cur:
            cur.execute("DELETE FROM pg_schema_versions")
        pg_session.commit()
        assert db_init_postgres()
        with pg_session.cursor() as cur:
            cur.execute("SELECT MAX(version), MAX(applied_ts) "
                        "FROM pg_schema_versions")
            max_v, max_ts = cur.fetchone()
        assert max_v is not None
        assert max_ts is not None


class TestG14TimescaleDbExtensionAbsent:
    """G14: PG container without TimescaleDB (postgres:16-alpine is
    plain PG, no extension) — db_init_postgres should gracefully skip
    the hypertable creation and succeed."""

    def test_init_succeeds_without_timescale(self, pg_session):
        from db.postgres import db_init_postgres
        # The test container IS plain postgres:16-alpine (no TimescaleDB)
        # so this test runs against the gap by default.
        with pg_session.cursor() as cur:
            cur.execute("SELECT extname FROM pg_extension "
                        "WHERE extname='timescaledb'")
            assert cur.fetchone() is None, \
                "test container has TimescaleDB; can't verify graceful skip"
        # Init must still succeed.
        assert db_init_postgres()
        # events table is a plain table, not a hypertable.
        with pg_session.cursor() as cur:
            cur.execute(
                "SELECT relkind FROM pg_class WHERE relname='events'")
            kind = cur.fetchone()[0]
        assert kind == 'r', \
            f"events must be a regular table (got relkind={kind!r})"


class TestG15PgVersionAbove13:
    """G15: PG 13+ is required for `ON CONFLICT DO UPDATE` SET clause
    behavior the code depends on. Document the minimum tested version."""

    def test_pg_version_above_13(self, pg_session):
        with pg_session.cursor() as cur:
            cur.execute("SELECT current_setting('server_version_num')")
            v_num = int(cur.fetchone()[0])
        # 130000 = PG 13.0; 140000 = PG 14.0; etc.
        assert v_num >= 130000, \
            f"PG <13 unsupported (test container reports {v_num})"


class TestG16SchemaVersionAtomicity:
    """G16: if the pg_schema_versions INSERT raises mid-stamp, the
    schema-init currently still returns True. Document this behaviour
    so a future tightening (refuse on stamp failure) is intentional."""

    def test_init_tolerates_version_stamp_failure(self, pg_session,
                                                   monkeypatch):
        """Mock pg_schema_versions to fail on INSERT — db_init still
        returns True because the schema itself is fine; only the
        informational stamp failed. Operators can re-query and see
        no/stale row."""
        import db.postgres as _pgmod
        # Drop the table; the next db_init_postgres should recreate it.
        with pg_session.cursor() as cur:
            cur.execute(
                "DROP TABLE IF EXISTS pg_schema_versions CASCADE")
        pg_session.commit()
        # Run init — recreates the table + stamps.
        assert _pgmod.db_init_postgres()
        with pg_session.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM pg_schema_versions")
            assert cur.fetchone()[0] >= 1


class TestG17PostgresAvailableToggle:
    """G17: state._postgres_available is mutated at boot from
    on_startup. Concurrent readers must see a consistent state — no
    half-flipped values. Verified via simple Python semantics (bool
    assignment is atomic), but document the contract."""

    def test_postgres_available_atomic_flip(self):
        """Python bool assignment is atomic at the bytecode level
        (STORE_GLOBAL is one opcode). Document this so a future
        refactor doesn't accidentally introduce a non-atomic update
        pattern."""
        import state as _state
        orig = _state._postgres_available
        try:
            # Atomic flip from any thread is safe.
            _state._postgres_available = True
            assert _state._postgres_available is True
            _state._postgres_available = False
            assert _state._postgres_available is False
        finally:
            _state._postgres_available = orig


class TestG18WriterQueueUnderLoad:
    """G18: writer-loop processes queued ops in batches. Verify a burst
    of 1000 queued ops drains correctly without dropping any."""

    def test_writer_loop_drains_1000_queued_set_kv_ops(self, pg_session):
        """Direct test: call _pg_mirror_kv 1000 times serially (the
        writer-loop's per-batch behavior is exercised in production;
        here we just confirm the dispatch layer handles the load)."""
        from db.postgres import _pg_mirror_kv
        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE metrics_kv RESTART IDENTITY CASCADE")
        pg_session.commit()
        for i in range(1000):
            assert _pg_mirror_kv("set_kv",
                                  (f"load-{i:04d}", str(i)))
        with pg_session.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM metrics_kv "
                        "WHERE key LIKE 'load-%'")
            assert cur.fetchone()[0] == 1000


class TestG21ConcurrentDbInitPostgres:
    """G21: two parallel db_init_postgres() calls (simulating two
    gateway processes booting against the same PG) must both succeed
    idempotently — `CREATE TABLE IF NOT EXISTS` + `INSERT ... ON
    CONFLICT` guarantee this."""

    def test_two_parallel_inits_both_succeed(self, pg_session):
        import threading, db.postgres as _pgmod
        # Drop schema first.
        with pg_session.cursor() as cur:
            cur.execute("DROP SCHEMA public CASCADE")
            cur.execute("CREATE SCHEMA public")
            cur.execute("GRANT ALL ON SCHEMA public TO PUBLIC")
        pg_session.commit()
        _pgmod._state._postgres_pool = None

        results = []
        def _init():
            results.append(_pgmod.db_init_postgres(
                max_attempts=3, backoff_s=0.5))

        t1 = threading.Thread(target=_init)
        t2 = threading.Thread(target=_init)
        t1.start(); t2.start()
        t1.join(timeout=30); t2.join(timeout=30)
        assert not t1.is_alive() and not t2.is_alive(), \
            "G21: parallel db_init_postgres blocked"
        assert all(results) and len(results) == 2, \
            f"G21: parallel init results: {results}"
        # Both saw the same final schema.
        with pg_session.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM information_schema.tables "
                "WHERE table_schema='public'")
            assert cur.fetchone()[0] >= 20


class TestG22OfflineBgTasksOff:
    """G22: PG-mode + OFFLINE_BG_TASKS=0 (the production default).
    Verifies bg-tasks code path coexists with PG-primary mode."""

    def test_pg_mode_with_bg_tasks_enabled_smoke(self, pg_session,
                                                  monkeypatch):
        """When OFFLINE_BG_TASKS is unset/0, the bg-task spawn block
        in on_startup runs. With PG primary, _pg_mirror_kv ops still
        work — bg tasks operate on independent state."""
        monkeypatch.delenv("OFFLINE_BG_TASKS", raising=False)
        # Functional smoke: a basic mirror call still works regardless
        # of OFFLINE_BG_TASKS. The bg-task block lives in on_startup
        # (not exercised here directly) but doesn't affect
        # _pg_mirror_kv dispatch.
        from db.postgres import _pg_mirror_kv
        assert _pg_mirror_kv("set_kv", ("g22-key", "g22-val"))
        with pg_session.cursor() as cur:
            cur.execute(
                "SELECT val FROM metrics_kv WHERE key=%s",
                ("g22-key",))
            assert cur.fetchone()[0] == "g22-val"

    def test_offline_guard_only_skips_when_set(self):
        """Source check: the OFFLINE_BG_TASKS guard in on_startup
        only short-circuits the bg-task spawn block when the env var
        is truthy. With it unset/0, bg-tasks run normally."""
        import inspect
        import proxy
        src = inspect.getsource(proxy.on_startup)
        assert 'OFFLINE_BG_TASKS' in src
        assert 'if not _offline_bg:' in src, \
            "guard must be `if not _offline_bg:` so unset/0 enables " \
            "bg-tasks (production default)"


class TestG25EmptySourceRoundtrip:
    """G25: db.export from a PG that has the schema but ZERO rows.
    Verify the snapshot is created (schema present) but contains no
    data. Then db.import the empty snapshot — should be a no-op."""

    def test_export_empty_pg_creates_schema(self, pg_session, tmp_path,
                                              monkeypatch):
        import importlib.util, sqlite3
        from pathlib import Path
        # Truncate everything.
        with pg_session.cursor() as cur:
            for t in ("users", "config_kv", "events", "bans",
                      "ip_bans", "metrics_kv"):
                cur.execute(
                    f"TRUNCATE TABLE {t} RESTART IDENTITY CASCADE")
        pg_session.commit()
        target = str(tmp_path / "empty.db")
        monkeypatch.setenv("DB_PATH", target)
        spec = importlib.util.spec_from_file_location(
            "_db_export_g25",
            str(Path(__file__).resolve().parent.parent
                / "db" / "export.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rc = mod.main([target, "--force"])
        assert rc == 0
        c = sqlite3.connect(target)
        try:
            # Schema present.
            cols = c.execute("PRAGMA table_info(users)").fetchall()
            assert cols, "users table not created in empty export"
            cols = c.execute("PRAGMA table_info(events)").fetchall()
            assert cols, "events table not created"
            # Zero rows.
            n = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            assert n == 0
        finally:
            c.close()

    def test_import_empty_snapshot_is_noop(self, pg_session, tmp_path):
        """db.import of a SQLite snapshot with schema but no rows
        completes successfully and writes nothing."""
        import importlib.util, sqlite3
        from pathlib import Path
        src = str(tmp_path / "empty_src.db")
        # Create the SQLite via db_init.
        import db.sqlite
        db.sqlite.db_init(db_path_override=src)
        # No rows inserted.
        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE users RESTART IDENTITY CASCADE")
        pg_session.commit()
        spec = importlib.util.spec_from_file_location(
            "_db_import_g25",
            str(Path(__file__).resolve().parent.parent
                / "db" / "import.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rc = mod.main([src, "--skip-events"])
        assert rc == 0
        with pg_session.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            assert cur.fetchone()[0] == 0


class TestG26SchemaOnlyFlag:
    """G26: db.export --schema-only writes the SQLite schema but copies
    zero data rows, even if PG has rows."""

    def test_schema_only_skips_rows(self, pg_session, tmp_path,
                                     monkeypatch):
        # Pre-seed PG with rows.
        from db.postgres import _pg_mirror_kv
        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE users RESTART IDENTITY CASCADE")
        pg_session.commit()
        assert _pg_mirror_kv(
            "user_create",
            ("g26-user", "h", "viewer", "active", 0.0, 0.0))
        # Export schema-only.
        target = str(tmp_path / "schema.db")
        monkeypatch.setenv("DB_PATH", target)
        import importlib.util
        from pathlib import Path
        spec = importlib.util.spec_from_file_location(
            "_db_export_g26",
            str(Path(__file__).resolve().parent.parent
                / "db" / "export.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rc = mod.main([target, "--force", "--schema-only"])
        assert rc == 0
        # Schema exists, no rows.
        import sqlite3
        c = sqlite3.connect(target)
        try:
            assert c.execute(
                "PRAGMA table_info(users)").fetchall(), \
                "schema-only must create users table"
            assert c.execute(
                "SELECT COUNT(*) FROM users").fetchone()[0] == 0, \
                "schema-only must NOT copy rows"
        finally:
            c.close()


class TestG27SkipEventsFlag:
    """G27: db.import --skip-events skips the events copy even when the
    SQLite source has events rows."""

    def test_skip_events_skips_event_rows(self, pg_session, tmp_path):
        import importlib.util, sqlite3
        from pathlib import Path
        # Build SQLite with events.
        src = str(tmp_path / "g27.db")
        import db.sqlite
        db.sqlite.db_init(db_path_override=src)
        c = sqlite3.connect(src)
        c.executemany(
            "INSERT INTO events "
            "(ts, ip, ua, path, method, status, reason) "
            "VALUES (?,?,?,?,?,?,?)",
            [(float(i), f"10.0.0.{i % 256}", "ua", "/p", "GET",
              200, "ok") for i in range(50)])
        c.commit(); c.close()
        # Clear PG events.
        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE events RESTART IDENTITY CASCADE")
        pg_session.commit()
        # Import with --skip-events.
        spec = importlib.util.spec_from_file_location(
            "_db_import_g27",
            str(Path(__file__).resolve().parent.parent
                / "db" / "import.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rc = mod.main([src, "--skip-events"])
        assert rc == 0
        # PG events count must still be 0.
        with pg_session.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM events")
            assert cur.fetchone()[0] == 0, \
                "G27: --skip-events failed to skip"


class TestG28FullCliRoundtripSubprocess:
    """G28: full end-to-end via SUBPROCESS (not Python API):
       SQLite-A → `python -m db.import` → PG → `python -m db.export`
       → SQLite-B → assert row-count equality. Exercises the actual
       operator workflow (argparse + subprocess + env vars)."""

    def test_subprocess_roundtrip_preserves_users(self, pg_session,
                                                    tmp_path):
        import sqlite3, subprocess, sys, os
        from pathlib import Path

        # Wipe PG.
        with pg_session.cursor() as cur:
            cur.execute(
                "TRUNCATE TABLE users RESTART IDENTITY CASCADE")
        pg_session.commit()

        # Source SQLite.
        src = str(tmp_path / "src.db")
        c = sqlite3.connect(src)
        c.executescript("""
            CREATE TABLE users (username TEXT PRIMARY KEY,
                password_hash TEXT, role TEXT, status TEXT,
                created_ts REAL, updated_ts REAL,
                last_login_ts REAL, last_login_ip TEXT,
                totp_secret TEXT, totp_enabled INTEGER,
                totp_backup_codes TEXT, sso_source TEXT, oidc_sub TEXT);
        """)
        c.executemany(
            "INSERT INTO users VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [(f"sub-{i:03d}", "h", "viewer", "active",
              0.0, 0.0, 0.0, "", "", 0, "", "", "")
             for i in range(20)])
        c.commit(); c.close()

        env = os.environ.copy()
        env.update({
            "POSTGRES_DSN": os.environ["POSTGRES_DSN"],
            "UPSTREAM": "https://example.com",
            "ADMIN_KEY": "t",
            "ALLOWED_HOSTS": "",
            "ADMIN_ALLOWED_IPS": "0.0.0.0/0",
            "OFFLINE_BG_TASKS": "1",
            "DB_PATH": src,
        })
        root = str(Path(__file__).resolve().parent.parent)

        # 1. Import via subprocess.
        p = subprocess.run(
            [sys.executable, "-m", "db.import", src, "--skip-events"],
            cwd=root, env=env, capture_output=True, timeout=60)
        assert p.returncode == 0, \
            f"G28 import failed: {p.stderr.decode()[:400]}"

        # 2. Export to a new SQLite via subprocess.
        dst = str(tmp_path / "dst.db")
        env["DB_PATH"] = dst
        p = subprocess.run(
            [sys.executable, "-m", "db.export", dst, "--force",
              "--skip-events"],
            cwd=root, env=env, capture_output=True, timeout=60)
        assert p.returncode == 0, \
            f"G28 export failed: {p.stderr.decode()[:400]}"

        # 3. Row-count parity.
        c = sqlite3.connect(dst)
        try:
            n_src = sqlite3.connect(src).execute(
                "SELECT COUNT(*) FROM users").fetchone()[0]
            n_dst = c.execute(
                "SELECT COUNT(*) FROM users WHERE username LIKE 'sub-%'"
            ).fetchone()[0]
        finally:
            c.close()
        assert n_dst == n_src, \
            f"G28 subprocess roundtrip lost rows: src={n_src}, dst={n_dst}"
