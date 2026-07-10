"""
tests/test_v188_backend_aware_reads.py — QA for the 1.8.8 backend-aware
event-reader + write-health observability refactor.

Context: dashboards (geo-data, logs-data, agents-bucket-detail, metrics
timeline, health-score) used to hardcode `sqlite3.connect(DB_PATH)` even
when DB_BACKEND=postgres. On armv7 deployments where SQLite dual-write
lagged or stopped, dashboards showed stale data with no obvious cause.

This file covers the fix end-to-end:

Functional (Q)  — exercise the helpers against a real ephemeral SQLite DB
  Q01  _read_events_sql returns empty list when DB has no events in range
  Q02  _read_events_sql returns rows when DB has events in range
  Q03  Column filter — only requested columns appear in returned dicts
  Q04  Default columns (ts, ip, reason) when columns=None
  Q05  ts is normalised to float (epoch seconds)
  Q06  start_ts=0 means "no lower bound" (logs endpoint use case)
  Q07  end_ts=0 means "no upper bound"
  Q08  vhost filter — exact match
  Q09  path_like filter — case-insensitive substring
  Q10  reason_like filter — case-insensitive substring
  Q11  ip_exact filter — exact match
  Q12  order_by ts ASC
  Q13  order_by ts DESC
  Q14  order_by id ASC / id DESC
  Q15  limit + offset pagination
  Q16  Invalid column → raises ValueError
  Q17  Invalid order_by → raises ValueError
  Q18  Whitelist enforcement — column injection attempt rejected
  Q19  Empty filter args don't add WHERE clause (no SQL syntax error)

Health (H)
  H01  _events_health_sql returns expected shape
  H02  _events_health_sql.last_event_ts matches MAX(ts) in DB
  H03  _events_health_sql.events_rows matches COUNT(*) in DB
  H04  _events_health_sql returns ok=False with error key when DB missing
  H05  db_health_snapshot returns expected top-level keys
  H06  db_health_snapshot.active_backend reflects DB_BACKEND
  H07  db_health_snapshot.lag_seconds is None when only one backend has data
  H08  db_health_snapshot.healthy=True when only one backend has data
  H09  db_health_snapshot postgres section reports unavailable when _postgres_available=False

Dispatcher (D)
  D01  db_read_events dispatches to sqlite when DB_BACKEND=sqlite
  D02  db_read_events dispatches to sqlite when DB_BACKEND=postgres but _postgres_available=False
  D03  db_read_events falls back to sqlite when postgres impl raises

Postgres (PG) — mock-based since we can't depend on a live PG in CI
  PG01  _read_events_pg raises if POSTGRES_DSN is empty
  PG02  _read_events_pg raises on invalid column
  PG03  _read_events_pg raises on invalid order_by
  PG04  vhost filter skipped on postgres (logs slog warning, doesn't raise)
  PG05  method/vhost columns filled with empty string in returned dicts
"""
import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


_ROOT = Path(__file__).resolve().parent.parent


# ─────────────────────────────────────────────────────────────────────────────
# Fixture: build an ephemeral SQLite DB with the events schema + sample rows
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_events_db(monkeypatch):
    """Create a temp sqlite events DB and monkeypatch DB_PATH everywhere
    it's bound (db.sqlite, db.postgres, config) so both readers + the bg
    migration find this fixture's data."""
    fd, db_path = tempfile.mkstemp(suffix=".db", prefix="appsecgw_test_")
    os.close(fd)
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            ip TEXT NOT NULL,
            ua TEXT,
            path TEXT,
            method TEXT,
            status INTEGER,
            reason TEXT,
            vhost TEXT
        )
    """)
    # Seed 6 events: 3 in the 100-200 window, 2 before, 1 after.
    seed = [
        (50.0,  "1.1.1.1", "BotA", "/a",     "GET",  200, "",                "host1"),
        (90.0,  "2.2.2.2", "BotB", "/b",     "GET",  403, "body-sqli",        "host2"),
        (150.0, "1.1.1.1", "BotA", "/admin", "GET",  200, "",                "host1"),
        (180.0, "3.3.3.3", "BotC", "/login", "POST", 401, "authorized-robot", "host1"),
        (195.0, "4.4.4.4", "BotD", "/api",   "GET",  200, "",                "host2"),
        (250.0, "5.5.5.5", "BotE", "/x",     "GET",  500, "internal-probe",   "host1"),
    ]
    for row in seed:
        conn.execute("INSERT INTO events (ts,ip,ua,path,method,status,reason,vhost) VALUES (?,?,?,?,?,?,?,?)", row)
    conn.commit()
    conn.close()

    import db.sqlite as sql_mod
    import db.postgres as pg_mod
    monkeypatch.setattr(sql_mod, "DB_PATH", db_path)
    monkeypatch.setattr(pg_mod, "DB_PATH", db_path)
    # Also force sqlite mode for the dispatcher
    import sys
    ph_mod = sys.modules.get("core.proxy_handler")
    if ph_mod is not None:
        monkeypatch.setattr(ph_mod, "DB_BACKEND", "sqlite", raising=False)
    yield db_path
    try: os.unlink(db_path)
    except OSError: pass


@pytest.fixture
def empty_events_db(monkeypatch):
    """Empty events DB (schema exists but no rows)."""
    fd, db_path = tempfile.mkstemp(suffix=".db", prefix="appsecgw_empty_")
    os.close(fd)
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL, ip TEXT, ua TEXT, path TEXT, method TEXT, status INTEGER, reason TEXT, vhost TEXT)")
    conn.commit()
    conn.close()
    import db.sqlite as sql_mod
    monkeypatch.setattr(sql_mod, "DB_PATH", db_path)
    yield db_path
    try: os.unlink(db_path)
    except OSError: pass


# ─────────────────────────────────────────────────────────────────────────────
# Q — functional tests against an ephemeral SQLite DB
# ─────────────────────────────────────────────────────────────────────────────

class TestReadEventsSqliteFunctional:

    def test_q01_empty_range_returns_empty_list(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(1000.0, 2000.0)  # window past all seed events
        assert rows == []

    def test_q02_returns_rows_in_range(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(100.0, 200.0)
        assert len(rows) == 3, f"Expected 3 events in [100,200], got {len(rows)}"

    def test_q03_column_filter(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(100.0, 200.0, columns=["ip", "reason"])
        assert all(set(r.keys()) == {"ip", "reason"} for r in rows), (
            f"Returned dicts must only contain requested columns. Got keys: "
            f"{[set(r.keys()) for r in rows]}"
        )

    def test_q04_default_columns(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(100.0, 200.0)
        assert all(set(r.keys()) == {"ts", "ip", "reason"} for r in rows), (
            f"Default columns must be (ts, ip, reason). Got: {[set(r.keys()) for r in rows]}"
        )

    def test_q05_ts_is_float(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(100.0, 200.0)
        for r in rows:
            assert isinstance(r["ts"], float), f"ts must be float (epoch), got {type(r['ts'])}"

    def test_q06_start_ts_zero_no_lower_bound(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        # No lower bound — should include all events ≤ 200
        rows = _read_events_sql(0, 200.0)
        assert len(rows) == 5, f"start_ts=0 should fetch all 5 events ≤ 200, got {len(rows)}"

    def test_q07_end_ts_zero_no_upper_bound(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(100.0, 0)
        assert len(rows) == 4, f"end_ts=0 should fetch all 4 events ≥ 100, got {len(rows)}"

    def test_q08_vhost_filter(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(0, 0, vhost="host2", columns=["ts", "ip", "vhost"])
        assert len(rows) == 2
        assert all(r["vhost"] == "host2" for r in rows)

    def test_q09_path_like_case_insensitive(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        # /Admin (uppercase) should match /admin in the DB
        rows = _read_events_sql(0, 0, path_like="ADMIN", columns=["path"])
        assert len(rows) == 1
        assert rows[0]["path"] == "/admin"

    def test_q10_reason_like_case_insensitive(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(0, 0, reason_like="SQLI", columns=["reason"])
        assert len(rows) == 1
        assert rows[0]["reason"] == "body-sqli"

    def test_q11_ip_exact(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(0, 0, ip_exact="1.1.1.1", columns=["ip"])
        assert len(rows) == 2
        assert all(r["ip"] == "1.1.1.1" for r in rows)

    def test_q12_order_by_ts_asc(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(0, 0, order_by="ts asc", columns=["ts"])
        timestamps = [r["ts"] for r in rows]
        assert timestamps == sorted(timestamps)

    def test_q13_order_by_ts_desc(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(0, 0, order_by="ts desc", columns=["ts"])
        timestamps = [r["ts"] for r in rows]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_q14_order_by_id(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(0, 0, order_by="id desc", columns=["id"])
        ids = [r["id"] for r in rows]
        assert ids == sorted(ids, reverse=True)

    def test_q15_limit_offset_pagination(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        page1 = _read_events_sql(0, 0, columns=["id"], order_by="id asc", limit=2)
        page2 = _read_events_sql(0, 0, columns=["id"], order_by="id asc", limit=2, offset=2)
        page3 = _read_events_sql(0, 0, columns=["id"], order_by="id asc", limit=2, offset=4)
        assert len(page1) == 2 and len(page2) == 2 and len(page3) == 2
        ids = [r["id"] for r in page1 + page2 + page3]
        assert len(set(ids)) == 6, f"Pagination must yield disjoint rows; got duplicates in {ids}"

    def test_q16_invalid_column_raises(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        with pytest.raises(ValueError, match="invalid event column"):
            _read_events_sql(0, 0, columns=["ts", "DROP TABLE events"])

    def test_q17_invalid_order_by_raises(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        with pytest.raises(ValueError, match="invalid order_by"):
            _read_events_sql(0, 0, order_by="; DROP TABLE events; --")

    def test_q18_column_injection_blocked(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        # Whitelist prevents column names that look like SQL
        for evil in ["ts; DROP", "(SELECT 1)", "ts UNION SELECT"]:
            with pytest.raises(ValueError):
                _read_events_sql(0, 0, columns=[evil])

    def test_q19_no_filters_works(self, tmp_events_db):
        from db.sqlite import _read_events_sql
        rows = _read_events_sql(0, 0)
        assert len(rows) == 6, "No filters + start_ts=end_ts=0 should return all rows"


# ─────────────────────────────────────────────────────────────────────────────
# H — db.db_health_snapshot + _events_health_sql
# ─────────────────────────────────────────────────────────────────────────────

class TestHealthSnapshot:

    def test_h01_health_sql_shape(self, tmp_events_db):
        from db.sqlite import _events_health_sql
        h = _events_health_sql()
        for k in ("last_event_ts", "events_rows", "ok"):
            assert k in h
        assert h["ok"] is True

    def test_h02_last_event_ts(self, tmp_events_db):
        from db.sqlite import _events_health_sql
        h = _events_health_sql()
        # Seed has max ts 250.0
        assert abs(h["last_event_ts"] - 250.0) < 0.001

    def test_h03_events_rows_count(self, tmp_events_db):
        from db.sqlite import _events_health_sql
        h = _events_health_sql()
        assert h["events_rows"] == 6

    def test_h04_missing_db_returns_error(self, monkeypatch, tmp_path):
        import db.sqlite as sql_mod
        # Point DB_PATH at a non-existent file's parent (sqlite would create
        # an empty DB but no schema, COUNT will fail).
        missing = tmp_path / "nonexistent.db"
        # Create empty file (sqlite happy) but no table → COUNT fails
        missing.touch()
        monkeypatch.setattr(sql_mod, "DB_PATH", str(missing))
        h = sql_mod._events_health_sql()
        assert h["ok"] is False
        assert "error" in h

    def test_h05_snapshot_top_level_keys(self, tmp_events_db):
        from db import db_health_snapshot
        hs = db_health_snapshot()
        for k in ("sqlite", "postgres", "active_backend", "lag_seconds", "healthy"):
            assert k in hs

    def test_h06_active_backend_from_proxy_handler(self, tmp_events_db, monkeypatch):
        import sys
        ph = sys.modules.get("core.proxy_handler")
        if ph is None:
            pytest.skip("core.proxy_handler not loaded")
        monkeypatch.setattr(ph, "DB_BACKEND", "postgres", raising=False)
        from db import db_health_snapshot
        hs = db_health_snapshot()
        assert hs["active_backend"] == "postgres"

    def test_h07_lag_none_when_only_sqlite_has_data(self, tmp_events_db):
        from db import db_health_snapshot
        hs = db_health_snapshot()
        # postgres has no data → lag_seconds undefined
        assert hs["postgres"]["last_event_ts"] is None
        assert hs["lag_seconds"] is None

    def test_h08_healthy_true_when_single_backend(self, tmp_events_db, monkeypatch):
        import sys
        ph = sys.modules.get("core.proxy_handler")
        if ph is not None:
            monkeypatch.setattr(ph, "DB_BACKEND", "sqlite", raising=False)
        from db import db_health_snapshot
        hs = db_health_snapshot()
        assert hs["healthy"] is True

    def test_h09_postgres_unavailable_reported(self, tmp_events_db, monkeypatch):
        import sys
        st = sys.modules.get("state")
        if st is not None:
            monkeypatch.setattr(st, "_postgres_available", False, raising=False)
        from db import db_health_snapshot
        hs = db_health_snapshot()
        assert hs["postgres"]["available"] is False


# ─────────────────────────────────────────────────────────────────────────────
# D — dispatcher routing
# ─────────────────────────────────────────────────────────────────────────────

class TestDispatcher:

    def test_d01_sqlite_mode_routes_to_sql(self, tmp_events_db, monkeypatch):
        import sys
        ph = sys.modules.get("core.proxy_handler")
        if ph is not None:
            monkeypatch.setattr(ph, "DB_BACKEND", "sqlite", raising=False)
        from db import db_read_events
        rows = db_read_events(100.0, 200.0)
        assert len(rows) == 3
        # Should NOT have touched postgres
        for r in rows:
            assert "ts" in r

    def test_d02_postgres_unavailable_falls_back_to_sqlite(self, tmp_events_db, monkeypatch):
        import sys
        ph = sys.modules.get("core.proxy_handler")
        st = sys.modules.get("state")
        if ph is not None:
            monkeypatch.setattr(ph, "DB_BACKEND", "postgres", raising=False)
        if st is not None:
            monkeypatch.setattr(st, "_postgres_available", False, raising=False)
        from db import db_read_events
        rows = db_read_events(100.0, 200.0)
        assert len(rows) == 3, "Should fall back to sqlite when postgres unavailable"

    def test_d03_postgres_error_falls_back_to_sqlite(self, tmp_events_db, monkeypatch):
        import sys
        ph = sys.modules.get("core.proxy_handler")
        st = sys.modules.get("state")
        if ph is not None:
            monkeypatch.setattr(ph, "DB_BACKEND", "postgres", raising=False)
        if st is not None:
            monkeypatch.setattr(st, "_postgres_available", True, raising=False)
        # Force _read_events_pg to raise
        import db.postgres as pg_mod
        def _boom(*a, **kw):
            raise RuntimeError("simulated postgres failure")
        monkeypatch.setattr(pg_mod, "_read_events_pg", _boom)
        from db import db_read_events
        rows = db_read_events(100.0, 200.0)
        assert len(rows) == 3, "Should fall back to sqlite when postgres impl raises"


# ─────────────────────────────────────────────────────────────────────────────
# PG — mock-based tests for postgres impl
# ─────────────────────────────────────────────────────────────────────────────

class TestPostgresImpl:

    def test_pg01_raises_without_dsn(self, monkeypatch):
        import db.postgres as pg_mod
        monkeypatch.setattr(pg_mod, "POSTGRES_DSN", "", raising=False)
        # Need to make _postgres_load_module return something so we get past
        # the first check and hit the DSN check.
        fake_pg = MagicMock()
        monkeypatch.setattr(pg_mod, "_postgres_load_module", lambda: fake_pg)
        with pytest.raises(RuntimeError, match="POSTGRES_DSN not configured"):
            pg_mod._read_events_pg(0, 0)

    def test_pg02_invalid_column_raises(self, monkeypatch):
        import db.postgres as pg_mod
        monkeypatch.setattr(pg_mod, "POSTGRES_DSN", "postgresql://x", raising=False)
        fake_pg = MagicMock()
        monkeypatch.setattr(pg_mod, "_postgres_load_module", lambda: fake_pg)
        with pytest.raises(ValueError, match="invalid event column"):
            pg_mod._read_events_pg(0, 0, columns=["evil; DROP"])

    def test_pg03_invalid_order_by_raises(self, monkeypatch):
        import db.postgres as pg_mod
        monkeypatch.setattr(pg_mod, "POSTGRES_DSN", "postgresql://x", raising=False)
        fake_pg = MagicMock()
        # Make connect/cursor unused — we should fail before reaching execute
        monkeypatch.setattr(pg_mod, "_postgres_load_module", lambda: fake_pg)
        with pytest.raises(ValueError, match="invalid order_by"):
            pg_mod._read_events_pg(0, 0, order_by="; DROP")

    def test_pg04_vhost_filter_applied(self, monkeypatch):
        """vhost filter is applied in Postgres SQL (real column added in 1.8.13)."""
        import db.postgres as pg_mod
        monkeypatch.setattr(pg_mod, "POSTGRES_DSN", "postgresql://x", raising=False)
        # Mock the connection chain
        fake_cur = MagicMock()
        fake_cur.description = [("ts",), ("ip",), ("reason",)]
        fake_cur.fetchall.return_value = []
        fake_conn = MagicMock()
        fake_conn.__enter__ = lambda self: fake_conn
        fake_conn.__exit__  = lambda self, *a: None
        fake_conn.cursor.return_value.__enter__  = lambda self: fake_cur
        fake_conn.cursor.return_value.__exit__   = lambda self, *a: None
        fake_pg = MagicMock()
        fake_pg.connect.return_value = fake_conn
        monkeypatch.setattr(pg_mod, "_postgres_load_module", lambda: fake_pg)
        result = pg_mod._read_events_pg(0, 100.0, vhost="filtered.example.com")
        assert isinstance(result, list)
        # 1.8.13: vhost is a real column — filter must appear in the SQL
        sql = fake_cur.execute.call_args[0][0]
        assert "vhost" in sql.lower(), (
            f"vhost filter must be present in postgres SQL: {sql}"
        )

    def test_pg05_method_vhost_are_real_columns(self, monkeypatch):
        """method/vhost are real Postgres columns (added via 1.8.0/1.8.13 migrations)
        and are returned normally from SELECT — not substituted with empty strings."""
        import db.postgres as pg_mod
        monkeypatch.setattr(pg_mod, "POSTGRES_DSN", "postgresql://x", raising=False)
        fake_cur = MagicMock()
        # Postgres now has method and vhost as real columns
        fake_cur.description = [("ts",), ("ip",), ("reason",), ("method",), ("vhost",)]
        fake_cur.fetchall.return_value = [
            (100.0, "1.2.3.4", "body-sqli", "GET",  "example.com"),
            (200.0, "5.6.7.8", "OK",        "POST", "other.com"),
        ]
        fake_conn = MagicMock()
        fake_conn.__enter__ = lambda self: fake_conn
        fake_conn.__exit__  = lambda self, *a: None
        fake_conn.cursor.return_value.__enter__ = lambda self: fake_cur
        fake_conn.cursor.return_value.__exit__  = lambda self, *a: None
        fake_pg = MagicMock()
        fake_pg.connect.return_value = fake_conn
        monkeypatch.setattr(pg_mod, "_postgres_load_module", lambda: fake_pg)
        rows = pg_mod._read_events_pg(
            0, 0,
            columns=["ts", "ip", "reason", "method", "vhost"],
        )
        assert len(rows) == 2
        assert rows[0]["method"] == "GET"
        assert rows[0]["vhost"] == "example.com"
        assert rows[1]["method"] == "POST"
        assert rows[1]["vhost"] == "other.com"
        # Verify both columns appear in the SELECT (not substituted)
        sql = fake_cur.execute.call_args[0][0]
        assert "method" in sql.lower(), f"method must be in SELECT: {sql}"
        assert "vhost" in sql.lower(), f"vhost must be in SELECT: {sql}"


# ─────────────────────────────────────────────────────────────────────────────
# E — End-to-end integration tests against a live aiohttp test gateway.
# These verify the refactored endpoints actually serve event data from
# whichever backend is active, and that /db-test surfaces write_health.
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
from contextlib import asynccontextmanager

from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


@asynccontextmanager
async def _spin_upstream():
    async def echo(_): return web.Response(text="ok")
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", echo)
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


_NS = "/antibot-appsec-gateway/secured"


@pytest.mark.asyncio
async def test_e01_db_test_response_includes_write_health(proxy_module):
    """E01: /db-test response must include write_health key with per-backend
    last_event_ts, events_rows, and a top-level lag_seconds/healthy."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/db-test", cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"db-test returned {r.status}"
            j = await r.json()
            assert "write_health" in j, (
                "db-test response must include write_health (1.8.8 observability)"
            )
            wh = j["write_health"]
            for k in ("sqlite", "postgres", "active_backend", "healthy"):
                assert k in wh, f"write_health must include '{k}', got keys {list(wh.keys())}"
            assert "last_event_ts" in wh["sqlite"]
            assert "events_rows"   in wh["sqlite"]
            assert "available"     in wh["postgres"]


@pytest.mark.asyncio
async def test_e02_geo_data_endpoint_routes_through_db_read_events(proxy_module):
    """E02: geo-data endpoint must NOT raise even when the events table has
    no rows (verifies the refactor handles the empty-DB case).

    Two acceptable response shapes:
      - {configured: False, hint, points: []} — MaxMind City DB not loaded
      - {configured: True, points, countries, asns, summary, ...} — full path
    Either is acceptable; both must include 'points' and not crash."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/geo-data?range=60",
                              cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"geo-data returned {r.status}"
            j = await r.json()
            assert "points" in j, f"geo-data must always return 'points'; got {list(j.keys())}"
            if j.get("configured") is False:
                # MaxMind City DB not configured — short-circuit return is correct.
                assert j["points"] == [], "no points when not configured"
            else:
                # Full path executed — verify the refactor didn't break aggregation.
                assert "summary" in j, f"geo-data response missing 'summary'; got {list(j.keys())}"


@pytest.mark.asyncio
async def test_e03_logs_data_endpoint_uses_helper(proxy_module):
    """E03: logs-data endpoint must serve a valid JSON response (no SQL
    error from the refactor). Empty list is acceptable; non-200 isn't."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/logs-data?kind=requests&limit=10",
                              cookies=_admin_cookie(proxy_module))
            assert r.status == 200, f"logs-data returned {r.status}"
            j = await r.json()
            assert isinstance(j, dict)
            # Must have either rows or items key (depending on shape)
            assert any(k in j for k in ("rows", "items", "events", "logs"))


@pytest.mark.asyncio
async def test_e04_health_score_endpoint_uses_helper(proxy_module):
    """E04: health-score must compute the block ratio via db_read_events.
    Verify response is well-formed."""
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{_NS}/health-score",
                              cookies=_admin_cookie(proxy_module))
            # health-score returns 200 with a score even on empty DB
            assert r.status == 200, f"health-score returned {r.status}"
            j = await r.json()
            assert "score" in j or "reasons" in j


# ─────────────────────────────────────────────────────────────────────────────
# I — Idempotent background migration (Approach A: watermark by MAX(ts)).
# Tests source-side dedup logic by inspecting _bg_sqlite_to_pg's SQL,
# verifying _BG_MIGRATION shape, and exercising the migration function
# against a mocked psycopg connection (no live Postgres required).
# ─────────────────────────────────────────────────────────────────────────────

class TestIdempotentMigration:

    def test_i01_bg_migration_shape_has_watermark(self):
        """I01: _BG_MIGRATION dict must include watermark + skipped_already_present
        so the dashboard can report 'X rows already in target; Y new rows copied'."""
        from db.postgres import _BG_MIGRATION
        for k in ("watermark", "skipped_already_present"):
            assert k in _BG_MIGRATION, (
                f"_BG_MIGRATION must include '{k}' field (1.8.8 idempotent migration)"
            )

    def test_i02_bg_sqlite_to_pg_reads_min_and_max(self):
        """I02: _bg_sqlite_to_pg must read MIN(ts) AND MAX(ts) from postgres
        (two-sided gap-fill watermark)."""
        pg_src = (Path(__file__).resolve().parent.parent / "db" / "postgres.py").read_text()
        fn_start = pg_src.find("def _bg_sqlite_to_pg")
        assert fn_start != -1
        body = pg_src[fn_start: fn_start + 5000]
        assert "MIN(ts)" in body, (
            "_bg_sqlite_to_pg must read MIN(ts) for backfill (older history postgres lacks)"
        )
        assert "MAX(ts)" in body, (
            "_bg_sqlite_to_pg must read MAX(ts) for forward watermark"
        )

    def test_i03_bg_sqlite_to_pg_gap_fill_filter(self):
        """I03: INSERT loop must use the gap-fill filter — copy rows OUTSIDE
        the target's [min, max] range, i.e. (ts < min OR ts > max)."""
        pg_src = (Path(__file__).resolve().parent.parent / "db" / "postgres.py").read_text()
        fn_start = pg_src.find("def _bg_sqlite_to_pg")
        body = pg_src[fn_start: fn_start + 5000]
        assert "ts < ? OR ts > ?" in body, (
            "_bg_sqlite_to_pg batch SELECT must filter by gap-fill: "
            "(ts < pg_min OR ts > pg_max)"
        )

    def test_i04_bg_pg_to_sqlite_reads_min_and_max(self):
        """I04: Symmetric — _bg_pg_to_sqlite must read MIN and MAX from sqlite."""
        pg_src = (Path(__file__).resolve().parent.parent / "db" / "postgres.py").read_text()
        fn_start = pg_src.find("def _bg_pg_to_sqlite")
        assert fn_start != -1
        body = pg_src[fn_start: fn_start + 5000]
        assert "MIN(ts), MAX(ts) FROM events" in body, (
            "_bg_pg_to_sqlite must read MIN(ts) AND MAX(ts) from sqlite in one query"
        )

    def test_i05_bg_pg_to_sqlite_gap_fill_filter(self):
        pg_src = (Path(__file__).resolve().parent.parent / "db" / "postgres.py").read_text()
        fn_start = pg_src.find("def _bg_pg_to_sqlite")
        body = pg_src[fn_start: fn_start + 5000]
        assert "ts < to_timestamp(%s) OR ts > to_timestamp(%s)" in body, (
            "_bg_pg_to_sqlite batch SELECT must filter by gap-fill"
        )

    @staticmethod
    def _build_pg_mock(monkeypatch, pg_min_ts, pg_max_ts):
        """Wire a fake psycopg into db.postgres.

        The first cursor.execute() is the MIN/MAX watermark query —
        fetchone() returns (pg_min_ts, pg_max_ts). Subsequent execute()
        calls are no-ops; executemany() captures rows in `copied_rows`.

        pg_min_ts / pg_max_ts can both be None to simulate an empty target.
        Returns the captured copied_rows list.
        """
        import db.postgres as pg_mod
        copied_rows: list = []
        call_count = [0]

        def _fetchone():
            # First execute = MIN/MAX query → return 2-tuple. After that,
            # the migration may run COUNT queries — return (0,) so they
            # don't crash; the real flow doesn't depend on those counts
            # for the assertions below.
            return (pg_min_ts, pg_max_ts) if call_count[0] == 1 else (0,)

        def _execute(sql, params=None):
            call_count[0] += 1

        def _executemany(sql, vals):
            copied_rows.extend(list(vals))

        def _make_cursor():
            cur = MagicMock()
            cur.execute = _execute
            cur.executemany = _executemany
            cur.fetchone = _fetchone
            cm = MagicMock()
            cm.__enter__ = MagicMock(return_value=cur)
            cm.__exit__  = MagicMock(return_value=None)
            return cm

        fake_conn = MagicMock()
        fake_conn.__enter__ = MagicMock(return_value=fake_conn)
        fake_conn.__exit__  = MagicMock(return_value=None)
        fake_conn.cursor    = _make_cursor
        fake_conn.commit    = MagicMock()

        fake_pg = MagicMock()
        fake_pg.connect.return_value = fake_conn
        monkeypatch.setattr(pg_mod, "_postgres_load_module", lambda: fake_pg)
        monkeypatch.setattr(pg_mod, "POSTGRES_DSN", "postgresql://x", raising=False)
        return copied_rows

    def test_i06_empty_postgres_first_migration(self, tmp_events_db, monkeypatch):
        """I06: Postgres empty (MIN=MAX=None) — copy all 6 source rows."""
        import db.postgres as pg_mod
        from db.postgres import _BG_MIGRATION
        copied = self._build_pg_mock(monkeypatch, pg_min_ts=None, pg_max_ts=None)
        _BG_MIGRATION.update({"watermark": 0.0, "skipped_already_present": 0,
                              "total": 0, "copied": 0})
        pg_mod._bg_sqlite_to_pg(cutoff_ts=1e9, batch_size=10, batch_sleep=0)
        assert _BG_MIGRATION["watermark"] == 0.0
        assert _BG_MIGRATION["skipped_already_present"] == 0
        assert _BG_MIGRATION["copied"] == 6, (
            f"All 6 seed rows should be copied (empty postgres), got {_BG_MIGRATION['copied']}"
        )
        assert len(copied) == 6

    def test_i07_target_range_equals_source_skips_all(self, tmp_events_db, monkeypatch):
        """I07: Postgres MIN=50, MAX=250 → covers entire source range →
        all 6 rows are inside [50, 250] → 0 copied (skipped as 'in range')."""
        import db.postgres as pg_mod
        from db.postgres import _BG_MIGRATION
        copied = self._build_pg_mock(monkeypatch, pg_min_ts=50.0, pg_max_ts=250.0)
        _BG_MIGRATION.update({"watermark": 0.0, "skipped_already_present": 0,
                              "total": 0, "copied": 0})
        pg_mod._bg_sqlite_to_pg(cutoff_ts=1e9, batch_size=10, batch_sleep=0)
        assert _BG_MIGRATION["watermark"] == 250.0, (
            f"Watermark should reflect MAX(ts)=250, got {_BG_MIGRATION['watermark']}"
        )
        assert _BG_MIGRATION["copied"] == 0, (
            f"All 6 rows in [50, 250] should be skipped, got copied={_BG_MIGRATION['copied']}"
        )
        assert _BG_MIGRATION["skipped_already_present"] == 6
        assert len(copied) == 0

    def test_i08_forward_gap_only(self, tmp_events_db, monkeypatch):
        """I08: Postgres has [50, 100] — only forward gap-fill, ts>100 → 4 rows
        (150, 180, 195, 250). ts in [50, 100] (rows 50, 90) skipped."""
        import db.postgres as pg_mod
        from db.postgres import _BG_MIGRATION
        copied = self._build_pg_mock(monkeypatch, pg_min_ts=50.0, pg_max_ts=100.0)
        _BG_MIGRATION.update({"watermark": 0.0, "skipped_already_present": 0,
                              "total": 0, "copied": 0})
        pg_mod._bg_sqlite_to_pg(cutoff_ts=1e9, batch_size=10, batch_sleep=0)
        assert _BG_MIGRATION["copied"] == 4, (
            f"Expected 4 forward-gap rows (ts > 100), got {_BG_MIGRATION['copied']}"
        )
        assert _BG_MIGRATION["skipped_already_present"] == 2, (
            f"Expected 2 in-range rows (50, 90), got {_BG_MIGRATION['skipped_already_present']}"
        )
        copied_ts = sorted(row[0] for row in copied)
        assert copied_ts == [150.0, 180.0, 195.0, 250.0]

    def test_i09_both_sided_gap_fill(self, tmp_events_db, monkeypatch):
        """I09: Postgres has [80, 200] — sqlite has rows ts < 80 (50) AND
        ts > 200 (250). Both ends should be copied → 2 rows total."""
        import db.postgres as pg_mod
        from db.postgres import _BG_MIGRATION
        # Seed: 50, 90, 150, 180, 195, 250
        # In  [80, 200]: 90, 150, 180, 195 → skip (4)
        # Outside:        50, 250          → copy (2)
        copied = self._build_pg_mock(monkeypatch, pg_min_ts=80.0, pg_max_ts=200.0)
        _BG_MIGRATION.update({"watermark": 0.0, "skipped_already_present": 0,
                              "total": 0, "copied": 0})
        pg_mod._bg_sqlite_to_pg(cutoff_ts=1e9, batch_size=10, batch_sleep=0)
        assert _BG_MIGRATION["copied"] == 2, (
            f"Two-sided gap-fill must copy 2 rows (ts=50 backfill + ts=250 forward), "
            f"got {_BG_MIGRATION['copied']}"
        )
        assert _BG_MIGRATION["skipped_already_present"] == 4
        copied_ts = sorted(row[0] for row in copied)
        assert copied_ts == [50.0, 250.0], (
            f"Must copy exactly the two edge rows (50, 250), got {copied_ts}"
        )

    def test_i10_backfill_only(self, tmp_events_db, monkeypatch):
        """I10: Postgres has [150, 300] — only sqlite events with ts < 150
        should be backfilled. ts in [150, 300] (4 rows) skipped."""
        import db.postgres as pg_mod
        from db.postgres import _BG_MIGRATION
        copied = self._build_pg_mock(monkeypatch, pg_min_ts=150.0, pg_max_ts=300.0)
        _BG_MIGRATION.update({"watermark": 0.0, "skipped_already_present": 0,
                              "total": 0, "copied": 0})
        pg_mod._bg_sqlite_to_pg(cutoff_ts=1e9, batch_size=10, batch_sleep=0)
        # Backfill: ts < 150 → 50, 90 (2 rows)
        # In range [150, 300] → 150, 180, 195, 250 (4 rows skipped)
        assert _BG_MIGRATION["copied"] == 2, (
            f"Backfill-only: expected 2 rows (ts < 150), got {_BG_MIGRATION['copied']}"
        )
        assert _BG_MIGRATION["skipped_already_present"] == 4
        copied_ts = sorted(row[0] for row in copied)
        assert copied_ts == [50.0, 90.0]


# ─────────────────────────────────────────────────────────────────────────────
# S — db_load_secrets cross-module propagation (1.8.8 startup-time fix)
# Catches the bug where the popup's Load DSN button said "no saved DSN"
# even when secrets_kv held the value, because db_load_secrets() updated
# only proxy.py's namespace.
# ─────────────────────────────────────────────────────────────────────────────

class TestDbLoadSecretsPropagation:
    """Verify that db_load_secrets propagates each loaded value to every
    sys.modules entry that already binds the same name (matching the patch
    already in secrets_endpoint and db_switch_endpoint)."""

    def test_s01_source_calls_propagation_loop(self):
        """S01: db_load_secrets source must iterate sys.modules and setattr
        each loaded secret."""
        src = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text()
        fn_start = src.find("def db_load_secrets")
        assert fn_start != -1
        body = src[fn_start: fn_start + 4000]
        assert "sys.modules" in body or "_sys.modules" in body, (
            "db_load_secrets must iterate sys.modules to propagate values"
        )
        assert "setattr" in body, (
            "db_load_secrets must setattr the global_name on each affected module"
        )

    def _seed_secrets_db(self, db_path, dsn_value):
        """Build a minimal sqlite DB with a single POSTGRES_DSN secret."""
        conn = sqlite3.connect(str(db_path))
        conn.executescript(
            "CREATE TABLE secrets_kv (key TEXT PRIMARY KEY, value TEXT, ts REAL);"
        )
        conn.execute(
            "INSERT INTO secrets_kv (key, value, ts) VALUES (?, ?, ?)",
            ("POSTGRES_DSN", dsn_value, 1.0),
        )
        conn.commit()
        conn.close()

    def test_s02_propagates_postgres_dsn_to_all_modules(self, tmp_path, monkeypatch):
        """S02: end-to-end — seed POSTGRES_DSN in secrets_kv, call
        db_load_secrets, verify core.proxy_handler and db.postgres both
        see the new value. Mocks _refresh_integration_state to keep the
        test focused on the propagation step."""
        db_path = tmp_path / "secrets_test.db"
        test_dsn = "postgresql://test_user:test_pw@test-host:5432/test_db"
        self._seed_secrets_db(db_path, test_dsn)

        import db.sqlite as sql_mod
        monkeypatch.setattr(sql_mod, "DB_PATH", str(db_path))
        monkeypatch.delenv("POSTGRES_DSN", raising=False)
        # Stub out the integration-state refresher so we test the
        # propagation step in isolation. (It needs many keys in globals
        # that don't matter for this test.)
        monkeypatch.setattr(sql_mod, "_refresh_integration_state",
                            lambda *_a, **_k: None)

        import sys
        snapshots = []
        for m in list(sys.modules.values()):
            if m is not None and hasattr(m, "POSTGRES_DSN"):
                snapshots.append((m, getattr(m, "POSTGRES_DSN")))
        # Clear current bindings so we can detect propagation
        for m, _ in snapshots:
            try: setattr(m, "POSTGRES_DSN", "")
            except Exception: pass

        try:
            fake_globals = {"POSTGRES_DSN": ""}
            sql_mod.db_load_secrets(fake_globals)

            assert fake_globals["POSTGRES_DSN"] == test_dsn, (
                "db_load_secrets must update the passed-in globals dict"
            )
            ph = sys.modules.get("core.proxy_handler")
            if ph is not None and hasattr(ph, "POSTGRES_DSN"):
                assert ph.POSTGRES_DSN == test_dsn, (
                    f"core.proxy_handler.POSTGRES_DSN must be propagated, "
                    f"got {ph.POSTGRES_DSN!r}"
                )
            pg = sys.modules.get("db.postgres")
            if pg is not None and hasattr(pg, "POSTGRES_DSN"):
                assert pg.POSTGRES_DSN == test_dsn, (
                    f"db.postgres.POSTGRES_DSN must be propagated, "
                    f"got {pg.POSTGRES_DSN!r}"
                )
        finally:
            for m, val in snapshots:
                try: setattr(m, "POSTGRES_DSN", val)
                except Exception: pass

    def test_s04_config_kv_does_not_stomp_secret(self, tmp_path, monkeypatch):
        """S04 (regression for the 'POSTGRES_DSN keeps coming back empty'
        bug observed on the operator's armv7 server): if config_kv contains
        an entry whose key is ALSO in _SECRET_KEYS (e.g. POSTGRES_DSN),
        db_load_config must SKIP it. The secret value owned by
        db_load_secrets must not be overwritten by config_kv.
        """
        db_path = tmp_path / "secret_vs_config.db"
        secret_dsn = "postgresql://real_user:real_pw@real-host:5432/real_db"
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE secrets_kv (key TEXT PRIMARY KEY, value TEXT, ts REAL);
            CREATE TABLE config_kv  (key TEXT PRIMARY KEY, value TEXT, ts REAL);
        """)
        # secrets_kv has the real DSN
        conn.execute("INSERT INTO secrets_kv (key, value, ts) VALUES (?, ?, ?)",
                     ("POSTGRES_DSN", secret_dsn, 1.0))
        # config_kv has the empty-string stomper (JSON-encoded "")
        conn.execute("INSERT INTO config_kv (key, value, ts) VALUES (?, ?, ?)",
                     ("POSTGRES_DSN", '""', 1.0))
        conn.commit()
        conn.close()

        import db.sqlite as sql_mod
        monkeypatch.setattr(sql_mod, "DB_PATH", str(db_path))
        monkeypatch.delenv("POSTGRES_DSN", raising=False)
        monkeypatch.setattr(sql_mod, "_refresh_integration_state",
                            lambda *_a, **_k: None)

        # Build a globals dict matching what proxy.py provides at boot
        fake_globals = {
            "POSTGRES_DSN": "",
            "_HOT_RELOAD_KNOBS":   sql_mod._SECRET_KEYS and {
                "POSTGRES_DSN": (str, lambda v: True),
            },
            "_ENV_PROVIDED_KNOBS": set(),
        }
        # The real apps put _HOT_RELOAD_KNOBS in core.proxy_handler — fake one
        import core.proxy_handler as ph
        monkeypatch.setattr(ph, "_HOT_RELOAD_KNOBS",
                            {"POSTGRES_DSN": (str, lambda v: True)},
                            raising=False)

        # Step 1: db_load_secrets sets fake_globals + propagates
        sql_mod.db_load_secrets(fake_globals)
        assert fake_globals["POSTGRES_DSN"] == secret_dsn, (
            "Setup error: db_load_secrets must apply the secret first"
        )

        # Step 2: db_load_config runs next. The fix: it must NOT stomp.
        sql_mod.db_load_config(fake_globals)
        assert fake_globals["POSTGRES_DSN"] == secret_dsn, (
            f"db_load_config stomped POSTGRES_DSN with config_kv's empty value. "
            f"Got {fake_globals['POSTGRES_DSN']!r}, expected {secret_dsn!r}. "
            f"_SECRET_KEYS entries must be skipped in db_load_config."
        )

    def test_s03_env_pinned_does_not_overwrite_modules(self, tmp_path, monkeypatch):
        """S03: if env POSTGRES_DSN is set, DB value must NOT be propagated
        (env-pin wins). Regression guard."""
        db_path = tmp_path / "secrets_envpin.db"
        db_dsn  = "postgresql://from-db:p@db-host:5432/d"
        env_dsn = "postgresql://from-env:p@env-host:5432/e"
        self._seed_secrets_db(db_path, db_dsn)

        import db.sqlite as sql_mod
        monkeypatch.setattr(sql_mod, "DB_PATH", str(db_path))
        monkeypatch.setenv("POSTGRES_DSN", env_dsn)
        monkeypatch.setattr(sql_mod, "_refresh_integration_state",
                            lambda *_a, **_k: None)

        import sys
        ph = sys.modules.get("core.proxy_handler")
        if ph is not None:
            monkeypatch.setattr(ph, "POSTGRES_DSN", env_dsn, raising=False)

        fake_globals = {"POSTGRES_DSN": env_dsn}
        sql_mod.db_load_secrets(fake_globals)
        # Env-pinned → DB value must NOT be applied to fake_globals
        assert fake_globals["POSTGRES_DSN"] == env_dsn, (
            "Env-pinned secret must NOT be overwritten by DB value"
        )
        # Modules also must still have env value
        if ph is not None and hasattr(ph, "POSTGRES_DSN"):
            assert ph.POSTGRES_DSN == env_dsn, (
                f"Env-pin: module must keep env value, got {ph.POSTGRES_DSN!r}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# X — XFF/TRUSTED_PROXIES misconfiguration alert (1.8.8)
# Regression target: operator's armv7 deployment had TRUSTED_PROXIES set to
# `172.17.0.0/16,172.19.0.0/16` while the gateway actually ran on the
# `172.18.0.0/16` Docker bridge. cloudflared forwarded traffic with XFF
# from 172.18.0.X (its sidecar IP) — gateway didn't recognise that as a
# trusted proxy, ignored XFF, and recorded every event with `ip=172.18.0.1`.
# All clients merged into one internal IP → GeoMap empty.
#
# The alert: when XFF header is present AND peer is RFC1918 AND not in
# TRUSTED_PROXIES, emit slog `xff_ignored_proxy_untrusted` once per peer.
# ─────────────────────────────────────────────────────────────────────────────

class TestXffMisconfigAlert:

    def test_x01_alert_source_exists(self):
        """X01: helpers.py must contain the xff_ignored_proxy_untrusted slog."""
        src = (Path(__file__).resolve().parent.parent / "helpers.py").read_text()
        assert "xff_ignored_proxy_untrusted" in src, (
            "helpers.py must emit slog 'xff_ignored_proxy_untrusted' "
            "to surface TRUSTED_PROXIES misconfigurations"
        )
        assert "_XFF_UNTRUSTED_PEERS_WARNED" in src, (
            "helpers.py must dedup the warning so per-request spam is bounded"
        )

    def test_x02_alert_fires_for_untrusted_private_peer(self, monkeypatch):
        """X02: get_ip() emits the warn slog when XFF is present, peer is
        RFC1918, and peer is NOT in TRUSTED_PROXIES_NETS."""
        import helpers
        import ipaddress
        # Empty trusted list → no peer is trusted
        monkeypatch.setattr(helpers, "TRUSTED_PROXIES_NETS",
                            [ipaddress.ip_network("127.0.0.1/32")],
                            raising=False)
        monkeypatch.setattr(helpers, "TRUST_XFF", "last", raising=False)
        helpers._XFF_UNTRUSTED_PEERS_WARNED.clear()

        # Capture slog calls
        captured = []
        def _fake_slog(event, **kwargs):
            captured.append((event, kwargs))
        monkeypatch.setattr(helpers, "slog", _fake_slog)

        # Build a fake request: XFF present, peer is private but untrusted
        fake_req = type("R", (), {
            "headers": {"X-Forwarded-For": "1.2.3.4"},
            "remote":  "172.18.0.5",
        })()
        result = helpers.get_ip(fake_req)

        # get_ip falls back to the untrusted peer (correct behaviour),
        # AND emits the alert
        assert result == "172.18.0.5", (
            f"Untrusted peer XFF must be ignored; got {result!r}"
        )
        warns = [c for c in captured if c[0] == "xff_ignored_proxy_untrusted"]
        assert len(warns) == 1, (
            f"Expected exactly 1 'xff_ignored_proxy_untrusted' warning, got {len(warns)}"
        )
        kwargs = warns[0][1]
        assert kwargs.get("peer") == "172.18.0.5"
        assert "hint" in kwargs and "TRUSTED_PROXIES" in kwargs["hint"]
        assert kwargs.get("level") == "warn"

    def test_x03_alert_dedup_per_peer(self, monkeypatch):
        """X03: subsequent requests from the SAME untrusted peer must NOT
        re-fire the warning (log dedup)."""
        import helpers, ipaddress
        monkeypatch.setattr(helpers, "TRUSTED_PROXIES_NETS",
                            [ipaddress.ip_network("127.0.0.1/32")],
                            raising=False)
        monkeypatch.setattr(helpers, "TRUST_XFF", "last", raising=False)
        helpers._XFF_UNTRUSTED_PEERS_WARNED.clear()

        captured = []
        monkeypatch.setattr(helpers, "slog",
                            lambda event, **kw: captured.append((event, kw)))

        fake_req = type("R", (), {
            "headers": {"X-Forwarded-For": "1.2.3.4"},
            "remote":  "172.18.0.5",
        })()
        for _ in range(10):
            helpers.get_ip(fake_req)
        warns = [c for c in captured if c[0] == "xff_ignored_proxy_untrusted"]
        assert len(warns) == 1, (
            f"Same-peer warning must be deduped; got {len(warns)} (expected 1)"
        )

    def test_x04_no_alert_when_peer_is_trusted(self, monkeypatch):
        """X04: when peer IS in TRUSTED_PROXIES_NETS, no alert fires and
        XFF is honoured."""
        import helpers, ipaddress
        monkeypatch.setattr(helpers, "TRUSTED_PROXIES_NETS",
                            [ipaddress.ip_network("172.18.0.0/16")],
                            raising=False)
        monkeypatch.setattr(helpers, "TRUST_XFF", "last", raising=False)
        helpers._XFF_UNTRUSTED_PEERS_WARNED.clear()
        captured = []
        monkeypatch.setattr(helpers, "slog",
                            lambda event, **kw: captured.append((event, kw)))

        fake_req = type("R", (), {
            "headers": {"X-Forwarded-For": "203.0.113.7"},
            "remote":  "172.18.0.5",
        })()
        result = helpers.get_ip(fake_req)
        assert result == "203.0.113.7", (
            f"Trusted peer XFF must be honoured; got {result!r}"
        )
        assert not [c for c in captured if c[0] == "xff_ignored_proxy_untrusted"], (
            "No alert should fire when peer is trusted"
        )

    def test_x05_no_alert_for_public_peers(self, monkeypatch):
        """X05: only RFC1918 peers trigger the alert. Public peers with XFF
        that aren't trusted are normal anti-spoofing rejections — not a
        misconfig — and should NOT spam the log.

        Note: 203.0.113.x is reserved TEST-NET-3 which Python's
        ipaddress.is_private classifies as private. Use a truly global
        address (8.8.8.8 - Google Public DNS) to exercise the public path.
        """
        import helpers, ipaddress
        monkeypatch.setattr(helpers, "TRUSTED_PROXIES_NETS",
                            [ipaddress.ip_network("127.0.0.1/32")],
                            raising=False)
        monkeypatch.setattr(helpers, "TRUST_XFF", "last", raising=False)
        helpers._XFF_UNTRUSTED_PEERS_WARNED.clear()
        captured = []
        monkeypatch.setattr(helpers, "slog",
                            lambda event, **kw: captured.append((event, kw)))

        fake_req = type("R", (), {
            "headers": {"X-Forwarded-For": "1.2.3.4"},
            "remote":  "8.8.8.8",
        })()
        helpers.get_ip(fake_req)
        assert not [c for c in captured if c[0] == "xff_ignored_proxy_untrusted"], (
            "Public-peer XFF rejection is NOT a misconfig; no alert should fire. "
            f"Captured: {captured}"
        )

    def test_x06_warned_set_bounded(self, monkeypatch):
        """X06: warned-peers set must be bounded so a malicious flood of
        unique peer IPs can't OOM the gateway."""
        import helpers, ipaddress
        monkeypatch.setattr(helpers, "TRUSTED_PROXIES_NETS",
                            [ipaddress.ip_network("127.0.0.1/32")],
                            raising=False)
        monkeypatch.setattr(helpers, "TRUST_XFF", "last", raising=False)
        monkeypatch.setattr(helpers, "slog", lambda *a, **k: None)
        helpers._XFF_UNTRUSTED_PEERS_WARNED.clear()

        # Hammer with 300 unique private peers
        for i in range(300):
            fake_req = type("R", (), {
                "headers": {"X-Forwarded-For": "1.2.3.4"},
                "remote":  f"10.0.{i // 256}.{i % 256}",
            })()
            helpers.get_ip(fake_req)
        # Set must have been reset when it hit ~256
        assert len(helpers._XFF_UNTRUSTED_PEERS_WARNED) < 300, (
            f"Warned-peers set unbounded ({len(helpers._XFF_UNTRUSTED_PEERS_WARNED)} entries)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# C — config_kv-stomps-secret alert (postgres-DSN topic, 1.8.8)
# Continues from S01-S04 in TestDbLoadSecretsPropagation. Verifies that
# `db_load_config` not only skips a secret-conflicting key but also emits a
# per-collision WARN slog so operators can find the offending row.
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigKvStompAlert:

    def test_c01_alert_source_exists(self):
        src = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text()
        assert "config_kv_stomp_blocked" in src, (
            "db_load_config must slog 'config_kv_stomp_blocked' on each "
            "secret-collision skip"
        )

    def test_c02_alert_fires_for_each_collision(self, tmp_path, monkeypatch):
        """C02: stage a stomper row in config_kv for a secret key; verify
        the slog warn fires with the right kwargs.

        Cleanup note: db_load_secrets propagates POSTGRES_DSN to every loaded
        module via direct setattr — this bypasses monkeypatch's revert, so
        without explicit cleanup later test classes (TestEnvPinnedKnobUx,
        TestBypassModeAbsolute) see the polluted DSN value and fail.
        Snapshot DSN across all modules and restore on teardown.
        """
        import sys as _sys_c02
        _dsn_snapshot = {}
        for _m_name, _m in list(_sys_c02.modules.items()):
            if _m is None:
                continue
            if hasattr(_m, "POSTGRES_DSN"):
                try:
                    _dsn_snapshot[_m_name] = getattr(_m, "POSTGRES_DSN")
                except AttributeError:
                    pass
        def _restore_dsn():
            for _mn, _v in _dsn_snapshot.items():
                _m = _sys_c02.modules.get(_mn)
                if _m is not None:
                    try:
                        setattr(_m, "POSTGRES_DSN", _v)
                    except (AttributeError, TypeError):
                        pass
        # request.addfinalizer would need the request fixture; use monkeypatch.undo via finally
        # at end of test body — monkeypatch handles its own things, but our cross-module
        # mutation needs a manual restore. Wrap the test body in try/finally below.

        db_path = tmp_path / "stomp_alert.db"
        secret_dsn = "postgresql://u:p@h:5432/d"
        conn = sqlite3.connect(str(db_path))
        conn.executescript("""
            CREATE TABLE secrets_kv (key TEXT PRIMARY KEY, value TEXT, ts REAL);
            CREATE TABLE config_kv  (key TEXT PRIMARY KEY, value TEXT, ts REAL);
        """)
        conn.execute("INSERT INTO secrets_kv (key,value,ts) VALUES (?,?,?)",
                     ("POSTGRES_DSN", secret_dsn, 1.0))
        # Stomper — would have overwritten secret with empty
        conn.execute("INSERT INTO config_kv  (key,value,ts) VALUES (?,?,?)",
                     ("POSTGRES_DSN", '""', 1.0))
        conn.commit()
        conn.close()

        import db.sqlite as sql_mod
        monkeypatch.setattr(sql_mod, "DB_PATH", str(db_path))
        monkeypatch.delenv("POSTGRES_DSN", raising=False)
        # Ensure env DB_PATH doesn't override the monkeypatched module global
        # (db_load_config reads `g.get("DB_PATH") or os.environ.get("DB_PATH")
        #  or DB_PATH` and env wins over module-level).
        monkeypatch.delenv("DB_PATH", raising=False)
        monkeypatch.setattr(sql_mod, "_refresh_integration_state",
                            lambda *_a, **_k: None)
        import core.proxy_handler as ph
        monkeypatch.setattr(ph, "_HOT_RELOAD_KNOBS",
                            {"POSTGRES_DSN": (str, lambda v: True)},
                            raising=False)

        captured = []
        monkeypatch.setattr(sql_mod, "slog",
                            lambda event, **kw: captured.append((event, kw)))

        # Pass DB_PATH explicitly via the globals so db_load_config uses our
        # temp DB even if the env happens to have DB_PATH set.
        fake_globals = {
            "POSTGRES_DSN": "",
            "DB_PATH": str(db_path),
            "_HOT_RELOAD_KNOBS": {"POSTGRES_DSN": (str, lambda v: True)},
            "_ENV_PROVIDED_KNOBS": set(),
        }
        sql_mod.db_load_secrets(fake_globals)
        sql_mod.db_load_config(fake_globals)

        try:
            alerts = [c for c in captured if c[0] == "config_kv_stomp_blocked"]
            assert len(alerts) >= 1, (
                f"Expected at least 1 config_kv_stomp_blocked alert, got 0. "
                f"All events: {[c[0] for c in captured]}"
            )
            ev_name, kwargs = alerts[0]
            assert kwargs.get("key") == "POSTGRES_DSN"
            assert kwargs.get("level") == "warn"
            assert kwargs.get("stomper_value_len") == 2, (
                f"stomper_value_len should report len('\"\"')==2 (empty JSON string), "
                f"got {kwargs.get('stomper_value_len')!r}"
            )
            # Hint should be actionable — accept either DELETE/delete or remove
            _note = kwargs.get("note", "")
            assert any(w in _note for w in ("DELETE", "delete", "remove")), (
                f"note should give actionable cleanup hint; got {_note!r}"
            )
        finally:
            _restore_dsn()


# ─────────────────────────────────────────────────────────────────────────────
# F — Review-finding fixes (1.8.9):
# F-M1  TOCTOU lock on _BG_MIGRATION (concurrent /db-switch can't double-schedule)
# F-L1  Accurate copied counter on INSERT OR IGNORE side
# F-L2  trailing_backend field replaces popup's abs()-inferred direction
# F-L3  Regex accepts both postgresql:// and postgres:// schemes
# ─────────────────────────────────────────────────────────────────────────────

class TestReviewFindingFixes:

    # ─── F-M1: TOCTOU lock on _BG_MIGRATION ──────────────────────────────

    def test_f_m1_claim_helper_exists(self):
        """F-M1: _try_claim_bg_migration helper must exist and use the lock."""
        src = (Path(__file__).resolve().parent.parent / "db" / "postgres.py").read_text()
        assert "def _try_claim_bg_migration" in src, (
            "1.8.9 must add _try_claim_bg_migration to atomically check+flip running"
        )
        assert "_BG_MIGRATION_LOCK" in src
        assert "with _BG_MIGRATION_LOCK:" in src, (
            "claim helper must hold the lock across check+flip"
        )

    def test_f_m1_claim_returns_true_first_then_false(self, monkeypatch):
        """F-M1: first call wins, second call (while running=True) returns False."""
        import db.postgres as pg
        # Reset state for the test
        pg._BG_MIGRATION.update({"running": False, "done": False})
        assert pg._try_claim_bg_migration("sqlite->postgres") is True
        assert pg._BG_MIGRATION["running"] is True, (
            "claim must flip running=True synchronously"
        )
        assert pg._try_claim_bg_migration("sqlite->postgres") is False, (
            "second concurrent caller must be rejected"
        )
        # Cleanup so we don't leak state into other tests
        pg._BG_MIGRATION.update({"running": False, "done": True})

    def test_f_m1_concurrent_claim_only_one_wins(self, monkeypatch):
        """F-M1: under threaded concurrent claims, exactly one wins."""
        import db.postgres as pg
        import threading
        pg._BG_MIGRATION.update({"running": False, "done": False})

        wins = []
        def attempt():
            if pg._try_claim_bg_migration("test"):
                wins.append(1)

        threads = [threading.Thread(target=attempt) for _ in range(20)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert len(wins) == 1, (
            f"Exactly one of 20 concurrent claims must win, got {len(wins)}"
        )
        pg._BG_MIGRATION.update({"running": False, "done": True})

    def test_f_m1_endpoint_uses_claim_helper(self):
        """F-M1: db_switch_endpoint in proxy_handler must call the claim
        helper instead of the racy `not _BG_MIGRATION.get("running")` check."""
        ph = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
        # Find the db_switch_endpoint function
        idx = ph.find("async def db_switch_endpoint")
        assert idx != -1
        body = ph[idx: idx + 8000]
        assert "_try_claim_bg_migration" in body, (
            "db_switch_endpoint must call _try_claim_bg_migration (no more racy check)"
        )

    # ─── F-L1: accurate copied counter ──────────────────────────────────

    def test_f_l1_pg_to_sqlite_uses_total_changes(self):
        """F-L1: _bg_pg_to_sqlite must use sqlite3 total_changes delta to
        count actual inserts, not len(rows) which would overcount when
        INSERT OR IGNORE drops UNIQUE-conflict rows."""
        src = (Path(__file__).resolve().parent.parent / "db" / "postgres.py").read_text()
        fn_start = src.find("def _bg_pg_to_sqlite")
        body = src[fn_start: fn_start + 4000]
        assert "total_changes" in body, (
            "_bg_pg_to_sqlite must use dst.total_changes to compute the actual "
            "insert count (INSERT OR IGNORE drops dups silently)"
        )
        # The += must be the delta, not len(rows)
        assert "inserted_now" in body or "before = dst.total_changes" in body, (
            "Must capture before/after total_changes around the executemany"
        )

    # ─── F-L2: trailing_backend field ────────────────────────────────────

    def test_f_l2_snapshot_includes_trailing_backend(self):
        """F-L2: db_health_snapshot must return trailing_backend when both
        backends have data, so the popup doesn't have to infer direction
        from the bilateral diff (which fails under clock skew)."""
        src = (Path(__file__).resolve().parent.parent / "db" / "__init__.py").read_text()
        assert "trailing_backend" in src, (
            "db_health_snapshot must return a trailing_backend field"
        )

    def test_f_l2_trailing_backend_correct(self):
        """F-L2: when sqlite ts < postgres ts → sqlite trails;
        when postgres ts < sqlite ts → postgres trails;
        when equal → None."""
        import sys
        import db as db_pkg
        # Stub out the underlying probes so we control ts values
        st = sys.modules.get("state")
        ph = sys.modules.get("core.proxy_handler")
        # SQLite trails (older ts)
        with self._stub_health(db_pkg, sqlite_ts=100.0, postgres_ts=200.0):
            h = db_pkg.db_health_snapshot()
            assert h["trailing_backend"] == "sqlite", (
                f"sqlite ts=100 < postgres ts=200 → sqlite trails; got {h.get('trailing_backend')}"
            )
        # Postgres trails (older ts)
        with self._stub_health(db_pkg, sqlite_ts=200.0, postgres_ts=100.0):
            h = db_pkg.db_health_snapshot()
            assert h["trailing_backend"] == "postgres"
        # Equal — neither trails
        with self._stub_health(db_pkg, sqlite_ts=150.0, postgres_ts=150.0):
            h = db_pkg.db_health_snapshot()
            assert h["trailing_backend"] is None

    @staticmethod
    def _stub_health(db_pkg, sqlite_ts, postgres_ts):
        """Context manager that stubs _events_health_sql / _events_health_pg."""
        from contextlib import contextmanager
        from unittest.mock import patch
        import sys
        # Make pg appear available
        st = sys.modules.get("state")
        orig_avail = getattr(st, "_postgres_available", None) if st else None
        @contextmanager
        def _cm():
            if st is not None:
                st._postgres_available = True
            with patch("db.sqlite._events_health_sql",
                       return_value={"last_event_ts": sqlite_ts, "events_rows": 1, "ok": True}), \
                 patch("db.postgres._events_health_pg",
                       return_value={"last_event_ts": postgres_ts, "events_rows": 1, "ok": True}):
                yield
            if st is not None and orig_avail is not None:
                st._postgres_available = orig_avail
        return _cm()

    def test_f_l2_popup_uses_trailing_backend_field(self):
        """F-L2: popup JS must consume trailing_backend, NOT recompute it
        from sqlite/postgres last_event_ts (which would re-introduce the
        clock-skew bug)."""
        src = (Path(__file__).resolve().parent.parent / "dashboards" / "settings.html").read_text()
        assert "wh.trailing_backend" in src, (
            "Popup must read wh.trailing_backend from /db-test response"
        )
        # And the old inference should be gone
        assert "(wh.sqlite?.last_event_ts || 0) < (wh.postgres?.last_event_ts || 0)" not in src, (
            "Old abs()-inference must be removed; use server-provided trailing_backend"
        )

    # ─── F-L3: accept both postgresql:// and postgres:// schemes ────────

    def test_f_l3_regex_accepts_both_schemes(self):
        """F-L3: the DSN-parsing regex in settings.html must accept both
        postgresql:// (canonical) and postgres:// (psycopg also accepts it)."""
        src = (Path(__file__).resolve().parent.parent / "dashboards" / "settings.html").read_text()
        # The pattern should use postgres(?:ql)? to match either scheme
        assert "postgres(?:ql)?:" in src, (
            "DSN-parsing regex must accept both postgresql:// and postgres:// schemes "
            "(use 'postgres(?:ql)?' in the pattern)"
        )
        # And the old strict pattern should be gone
        assert "postgresql:\\/\\/" not in src or "postgres(?:ql)?:\\/\\/" in src, (
            "Old strict 'postgresql://' pattern must be widened to accept 'postgres://' too"
        )


# ─────────────────────────────────────────────────────────────────────────────
# K — Env-pinned-knob UX (1.8.9)
# Regression target: operator hit `reject - {}` after Apply Changes on
# ALLOW_PRIVATE_UPSTREAM because the knob is env-pinned (compose has
# ALLOW_PRIVATE_UPSTREAM=1 which `_to_bool` evaluates True). The server
# correctly rejected the POST, but the GET /config response didn't expose
# the env-pinned set so the UI couldn't disable the control upfront.
#
# K01-K05  static (response shape + UI handling)
# K06-K08  dynamic (live gateway POST + GET round-trip)
# ─────────────────────────────────────────────────────────────────────────────

class TestEnvPinnedKnobUx:

    def setup_method(self):
        self.src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
        self.ctl = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()

    # ─── static / source-level ──────────────────────────────────────────

    def test_k01_get_config_exposes_env_pinned(self):
        """K01: GET /config response must include the env_pinned list so the
        UI can render those knobs as read-only instead of letting operators
        edit them and bounce off 'env-pinned' rejection after Apply."""
        assert '"env_pinned"' in self.src, (
            "config_endpoint GET response must carry an 'env_pinned' key"
        )
        # Both the global-state branch and the vhost branch must include it
        idx = self.src.find("async def config_endpoint")
        body = self.src[idx: idx + 4000]
        assert body.count('"env_pinned":') >= 2, (
            "Both the global and vhost branches of GET /config must include env_pinned. "
            f"Got {body.count('env_pinned:')} occurrences."
        )

    def test_k02_post_rejects_env_pinned_knob(self):
        """K02: POST /config code path must reject env-pinned knobs with the
        actionable 'env-pinned (set via container env...)' message."""
        idx = self.src.find("if k in _ENV_PROVIDED_KNOBS:")
        assert idx != -1, "config_endpoint must check _ENV_PROVIDED_KNOBS"
        body = self.src[idx: idx + 200]
        assert "env-pinned" in body
        assert "container env" in body, (
            "Rejection message must mention 'container env' so operators know where to look"
        )

    def test_k03_allow_private_upstream_is_a_hot_reload_knob(self):
        """K03: ALLOW_PRIVATE_UPSTREAM must be registered in _HOT_RELOAD_KNOBS
        with a _to_bool parser. Regression target — the knob was missing from
        the spec at one point and silently rejected even unrelated POSTs."""
        assert '"ALLOW_PRIVATE_UPSTREAM": (_to_bool, None)' in self.src, (
            "ALLOW_PRIVATE_UPSTREAM must be in _HOT_RELOAD_KNOBS with _to_bool parser"
        )

    def test_k04_env_knob_is_provided_boolean_truthy(self):
        """K04: _env_knob_is_provided returns True for truthy boolean env
        values like '1', 'true' (so the knob is env-pinned). Confirms the
        path that bites the operator: ALLOW_PRIVATE_UPSTREAM=1 → pinned."""
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from core.proxy_handler import _env_knob_is_provided
        # Pretend ALLOW_PRIVATE_UPSTREAM=1 is set
        import os
        old = os.environ.get("ALLOW_PRIVATE_UPSTREAM")
        try:
            os.environ["ALLOW_PRIVATE_UPSTREAM"] = "1"
            assert _env_knob_is_provided("ALLOW_PRIVATE_UPSTREAM") is True, (
                "ALLOW_PRIVATE_UPSTREAM=1 must register as env-provided "
                "(this is what causes operator's 'reject -{}' on Apply)"
            )
            os.environ["ALLOW_PRIVATE_UPSTREAM"] = "0"
            assert _env_knob_is_provided("ALLOW_PRIVATE_UPSTREAM") is False, (
                "ALLOW_PRIVATE_UPSTREAM=0 must NOT pin (allows DB-stored value to win)"
            )
        finally:
            if old is None: os.environ.pop("ALLOW_PRIVATE_UPSTREAM", None)
            else:           os.environ["ALLOW_PRIVATE_UPSTREAM"] = old

    def test_k05_controls_ui_consumes_env_pinned(self):
        """K05: controls.html must capture body.env_pinned and apply
        readonly/disabled state + 'env-pinned' badge to those controls."""
        assert "envPinnedKnobs" in self.ctl, (
            "controls.html must hold an envPinnedKnobs set"
        )
        assert "body.env_pinned" in self.ctl, (
            "controls.html load() must read body.env_pinned from GET /config"
        )
        assert "env-pinned" in self.ctl, (
            "controls.html must show an 'env-pinned' badge / tooltip"
        )
        assert ".disabled = true" in self.ctl, (
            "controls.html must disable input/select/textarea for env-pinned knobs"
        )

    # ─── dynamic / live gateway round-trip ──────────────────────────────

    @pytest.mark.asyncio
    async def test_k06_get_config_returns_env_pinned_field(self, proxy_module):
        """K06: GET /secured/config returns env_pinned: [<list of knob names>]."""
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                r = await cli.get(f"{_NS}/config", cookies=_admin_cookie(proxy_module))
                assert r.status == 200
                j = await r.json()
                assert "env_pinned" in j, (
                    f"GET /config response missing 'env_pinned'. Keys: {list(j.keys())}"
                )
                assert isinstance(j["env_pinned"], list)

    @staticmethod
    def _force_admin_role(monkeypatch):
        """The test gateway has no admin-user record, so `_request_role`
        returns 'viewer' and `_role_denied` 403s on /config POST. Patch
        `_role_denied` to a no-op directly in `core.proxy_handler` (its
        local binding) — patching the source module isn't enough because
        proxy_handler imported the function value at module-load time.
        Same for `_require_csrf` / `_csrf_token_valid` — the test fixture
        doesn't compute the per-session CSRF token, so bypass the check.
        """
        import core.proxy_handler as ph
        import admin.auth as auth
        monkeypatch.setattr(ph,   "_role_denied",       lambda req, *roles: None)
        monkeypatch.setattr(ph,   "_csrf_token_valid",  lambda req: True, raising=False)
        monkeypatch.setattr(auth, "_csrf_token_valid",  lambda req: True)

    @pytest.mark.asyncio
    async def test_k07_post_env_pinned_knob_returns_rejected(self, proxy_module, monkeypatch):
        """K07: with ALLOW_PRIVATE_UPSTREAM in _ENV_PROVIDED_KNOBS, POSTing
        any value yields rejected[ALLOW_PRIVATE_UPSTREAM] = 'env-pinned ...'.
        This is the exact 'Apply Changes' failure the operator hit."""
        import core.proxy_handler as ph
        self._force_admin_role(monkeypatch)
        orig = set(ph._ENV_PROVIDED_KNOBS)
        monkeypatch.setattr(ph, "_ENV_PROVIDED_KNOBS",
                            orig | {"ALLOW_PRIVATE_UPSTREAM"}, raising=False)
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                r = await cli.post(f"{_NS}/config",
                                   json={"ALLOW_PRIVATE_UPSTREAM": False},
                                   cookies=_admin_cookie(proxy_module))
                assert r.status == 200, f"POST returned {r.status}, body: {await r.text()}"
                j = await r.json()
                assert "rejected" in j, f"POST response shape: {list(j.keys())}"
                assert "ALLOW_PRIVATE_UPSTREAM" in j["rejected"], (
                    f"Knob in _ENV_PROVIDED_KNOBS must be in 'rejected'. Got: {j['rejected']}"
                )
                reason = j["rejected"]["ALLOW_PRIVATE_UPSTREAM"]
                assert "env-pinned" in reason, (
                    f"Rejection reason must mention env-pinned for operator clarity. Got: {reason!r}"
                )

    @pytest.mark.asyncio
    async def test_k08_get_then_apply_round_trip_for_pinned_knob(self, proxy_module, monkeypatch):
        """K08: full operator round-trip — GET shows env_pinned list including
        the knob, POST returns rejected with same reason. Verifies the UI's
        Apply Changes path can detect the lockdown via GET BEFORE the POST
        bounces."""
        import core.proxy_handler as ph
        self._force_admin_role(monkeypatch)
        orig = set(ph._ENV_PROVIDED_KNOBS)
        monkeypatch.setattr(ph, "_ENV_PROVIDED_KNOBS",
                            orig | {"ALLOW_PRIVATE_UPSTREAM"}, raising=False)
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                # Step 1: GET tells the UI the knob is env-pinned
                r1 = await cli.get(f"{_NS}/config", cookies=_admin_cookie(proxy_module))
                j1 = await r1.json()
                assert "ALLOW_PRIVATE_UPSTREAM" in j1["env_pinned"], (
                    "GET must surface the env-pinned status so the UI can disable the control"
                )
                # Step 2: POST proves the server backs up the GET-side promise
                r2 = await cli.post(f"{_NS}/config",
                                    json={"ALLOW_PRIVATE_UPSTREAM": True},
                                    cookies=_admin_cookie(proxy_module))
                j2 = await r2.json()
                assert j2.get("rejected", {}).get("ALLOW_PRIVATE_UPSTREAM"), (
                    "POST must reject (server-side enforcement, regardless of UI hint)"
                )


# ─────────────────────────────────────────────────────────────────────────────
# B — BYPASS_MODE absolute pass-through (1.8.9)
# Operator's directive: when "Bot Detection" toggle is OFF (BYPASS_MODE=True),
# ZERO blocks fire. Previously the BYPASS_MODE check sat below
# AUTHORIZED_BOT_UAS in protect(), letting `action=ban` and `action=really-ban`
# entries still ban traffic in bypass mode. Fix: hoisted BYPASS_MODE check
# above AUTHORIZED_BOT_UAS (and BYPASS_PATHS) so the early-return wins.
# ─────────────────────────────────────────────────────────────────────────────

class TestBypassModeAbsolute:

    def setup_method(self):
        self.src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()

    def test_b01_bypass_check_precedes_authorized_bot_uas(self):
        """B01: BYPASS_MODE check must appear BEFORE the AUTHORIZED_BOT_UAS
        loop in protect() so operator-policy ban actions can't fire when
        the operator has explicitly disabled all controls."""
        bypass_idx = self.src.find("if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path")
        bot_uas_idx = self.src.find("if AUTHORIZED_BOT_UAS:")
        assert bypass_idx != -1, "BYPASS_MODE check missing from protect()"
        assert bot_uas_idx != -1, "AUTHORIZED_BOT_UAS loop missing"
        assert bypass_idx < bot_uas_idx, (
            f"BYPASS_MODE check at {bypass_idx} must precede AUTHORIZED_BOT_UAS "
            f"loop at {bot_uas_idx}. Otherwise `action=ban` entries still fire "
            f"when bypass is on, contradicting the operator's intent."
        )

    def test_b02_only_one_bypass_branch(self):
        """B02: only one active BYPASS_MODE branch in protect(). Regression
        guard against accidentally re-introducing the duplicate at the
        old location below AUTHORIZED_BOT_UAS."""
        # Count occurrences of the actual `if` guard (not comments)
        count = sum(1 for line in self.src.splitlines()
                    if line.strip().startswith("if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path"))
        assert count == 1, (
            f"Expected exactly 1 active `if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path` "
            f"branch in protect(), found {count}."
        )

    def test_b03_bypass_below_protocol_safety(self):
        """B03: BYPASS_MODE check must sit BELOW protocol-level safety
        checks (control-byte path reject). Bypass mode is for detection
        and bot-policy bypass, not CRLF/injection protocol safety."""
        bypass_idx  = self.src.find("if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path")
        ctrl_idx    = self.src.find("def _has_ctrl(s: str)")
        assert ctrl_idx != -1, "control-byte path reject helper missing"
        assert ctrl_idx < bypass_idx, (
            "control-byte/CRLF path reject must execute before BYPASS_MODE — "
            "bypass is for detection, not protocol safety"
        )

    @pytest.mark.asyncio
    async def test_b04_bypass_skips_authorized_bot_ban(self, proxy_module, monkeypatch):
        """B04: dynamic — with BYPASS_MODE=True AND a matching
        AUTHORIZED_BOT_UAS entry whose action='ban', the request must
        STILL pass through (200), not be banned. Confirms the hoist."""
        import core.proxy_handler as ph
        monkeypatch.setattr(ph, "BYPASS_MODE", True, raising=False)
        monkeypatch.setattr(ph, "AUTHORIZED_BOT_UAS", [
            {"name": "evil", "ua": "EvilBot", "path": "/", "ips": [],
             "action": "ban", "enabled": True}
        ], raising=False)
        # Disable role/CSRF for the test fixture
        monkeypatch.setattr(ph, "_role_denied",      lambda req, *r: None)
        monkeypatch.setattr(ph, "_csrf_token_valid", lambda req: True, raising=False)
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                # Use the AUTHORIZED_BOT_UAS-matching UA
                r = await cli.get("/", headers={"User-Agent": "EvilBot/1.0"})
                # BYPASS_MODE must override the AUTHORIZED_BOT_UAS ban
                assert r.status == 200, (
                    f"Bypass mode must override AUTHORIZED_BOT_UAS ban action. "
                    f"Got HTTP {r.status} — bypass hoist may not have landed."
                )

    def test_b06_label_renamed_to_bot_protection(self):
        """B06: bypass-bar label says 'Bot Protection (Active)' (renamed
        from 'Bot Detection' in 1.8.9). The 'Active' suffix makes the
        currently-running state obvious to operators."""
        ctl = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
        assert 'id="bypass-label">Bot Protection (Active)' in ctl, (
            "bypass-label initial text must read 'Bot Protection (Active)' (was 'Bot Detection')"
        )
        assert ">Bot Detection</span>" not in ctl, (
            "Stale 'Bot Detection' label must be removed"
        )
        # _setBypassUI must flip the label when bypass toggles
        assert "Bot Protection (Disabled)" in ctl, (
            "_setBypassUI must set label to 'Bot Protection (Disabled)' when bypass on"
        )

    def test_b07_bypass_fetch_sends_csrf_header(self):
        """B07: _activateBypass + _deactivateBypass must explicitly set the
        X-CSRF-Token header (not rely solely on the global fetch shim) and
        bail with a clear toast when the agw_csrf cookie is missing."""
        ctl = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
        act_idx = ctl.find("async function _activateBypass")
        deact_idx = ctl.find("async function _deactivateBypass")
        for fn_name, idx in [("_activateBypass", act_idx), ("_deactivateBypass", deact_idx)]:
            assert idx != -1, f"{fn_name} missing"
            body = ctl[idx: idx + 2500]
            assert "'X-CSRF-Token':" in body, (
                f"{fn_name} must set X-CSRF-Token header explicitly (defence in depth)"
            )
            assert "CSRF cookie missing" in body, (
                f"{fn_name} must show actionable hint when agw_csrf cookie absent"
            )
            assert "agw_csrf=" in body, (
                f"{fn_name} must read the agw_csrf cookie before POST"
            )

    def test_b05_bypass_branch_uses_empty_reason(self):
        """B05: source check — the hoisted BYPASS_MODE branch calls record()
        with reason="" so traffic shows as clean (no 'bypass-mode' label).
        Verifying the static pattern is enough; the dynamic record-hook is
        awkward because `core.metrics` is shadowed by `from core.metrics
        import *` in `core/__init__.py`.
        """
        # Find the FIRST (hoisted) bypass branch — at line ~2855
        idx = self.src.find("if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path")
        assert idx != -1
        block = self.src[idx: idx + 600]
        assert "record(" in block, "Bypass branch must call record() for dashboard timeline"
        # The empty-reason call: `request.path, resp.status, ""`
        assert ', resp.status, ""' in block, (
            "Bypass branch must record with empty reason (shows as clean in dashboard)"
        )

    # ─── dynamic — bypass via /config POST + CSRF ───────────────────────

    @staticmethod
    def _bypass_helpers(monkeypatch):
        """Shared setup: disable role+CSRF gates so dynamic tests can POST."""
        import core.proxy_handler as ph
        import admin.auth as auth
        monkeypatch.setattr(ph, "_role_denied", lambda req, *r: None)

    @pytest.mark.asyncio
    @pytest.mark.timeout(120)  # pycares async DNS resolver thread blocks on placeholder upstream hostnames
    async def test_b08_post_bypass_mode_true_applies(self, proxy_module, monkeypatch):
        """B08: dynamic — POST /config {BYPASS_MODE: true} with valid CSRF
        applies the knob (no rejection). Verifies the operator's primary
        action against a live gateway."""
        import core.proxy_handler as ph
        import admin.auth as auth
        self._bypass_helpers(monkeypatch)
        monkeypatch.setattr(ph,   "_csrf_token_valid", lambda req: True, raising=False)
        monkeypatch.setattr(auth, "_csrf_token_valid", lambda req: True)
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                r = await cli.post(f"{_NS}/config",
                                   json={"BYPASS_MODE": True},
                                   cookies=_admin_cookie(proxy_module))
                assert r.status == 200, f"POST /config returned {r.status}: {await r.text()}"
                j = await r.json()
                assert j.get("applied", {}).get("BYPASS_MODE") is True, (
                    f"BYPASS_MODE=true must be applied; got {j!r}"
                )
                assert not j.get("rejected"), (
                    f"BYPASS_MODE must not be rejected; got {j.get('rejected')!r}"
                )

    @pytest.mark.asyncio
    async def test_b09_post_bypass_without_csrf_header_returns_403(self, proxy_module, monkeypatch):
        """B09: dynamic — reproduce the operator's symptom. POST /config
        with the session cookie but WITHOUT X-CSRF-Token header must
        return HTTP 403 with body 'CSRF token invalid'."""
        import core.proxy_handler as ph
        self._bypass_helpers(monkeypatch)
        # Leave CSRF check REAL — that's what we're testing
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                # Explicit empty X-CSRF-Token = "intentionally no token": the
                # conftest auto-CSRF shim skips when the header key is present,
                # so the server still sees an empty/invalid token.
                r = await cli.post(f"{_NS}/config",
                                   json={"BYPASS_MODE": True},
                                   headers={"X-CSRF-Token": ""},
                                   cookies=_admin_cookie(proxy_module))
                # No valid X-CSRF-Token → server rejects
                assert r.status == 403, (
                    f"POST without X-CSRF-Token must return 403, got {r.status}"
                )
                body = await r.text()
                assert "CSRF" in body or "csrf" in body, (
                    f"403 body must mention CSRF for operator clarity. Got: {body[:200]!r}"
                )

    @pytest.mark.asyncio
    async def test_b10_post_bypass_with_csrf_header_succeeds(self, proxy_module, monkeypatch):
        """B10: dynamic — POST /config WITH a valid X-CSRF-Token header
        AND the right session cookie succeeds. Proves the controls.html
        explicit-header fix is correct.

        Test focus is CSRF validation, so we bypass the upstream auth
        gate (_internal_authed) via monkeypatch — that's covered by other
        suites. We DO keep `_csrf_token_valid` real to actually exercise
        the CSRF path the operator's browser hits.
        """
        import hashlib, hmac
        import core.proxy_handler as ph
        self._bypass_helpers(monkeypatch)
        # Patch session/IP auth to no-op so we isolate CSRF behaviour
        monkeypatch.setattr(ph, "_internal_authed", lambda req: True)
        monkeypatch.setattr(ph, "_admin_ip_allowed", lambda req: True)
        cookies = _admin_cookie(proxy_module)
        token = cookies[proxy_module._SESSION_COOKIE]
        _, sid, _ = proxy_module._session_parse(token)
        session_key = proxy_module.SESSION_KEY
        csrf = hmac.new(session_key, sid.encode(), hashlib.sha256).hexdigest()[:32]
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                r = await cli.post(f"{_NS}/config",
                                   json={"BYPASS_MODE": False},
                                   cookies=cookies,
                                   headers={"X-CSRF-Token": csrf})
                assert r.status == 200, (
                    f"POST with valid X-CSRF-Token must succeed, got {r.status}: {await r.text()}"
                )
                j = await r.json()
                assert j.get("applied", {}).get("BYPASS_MODE") is False
                assert not j.get("rejected")

    @pytest.mark.asyncio
    async def test_b11_get_controls_page_shows_new_label(self, proxy_module, monkeypatch):
        """B11: dynamic — GET /secured/controls returns HTML containing the
        new 'Bot Protection (Active)' label, not the old 'Bot Detection'."""
        self._bypass_helpers(monkeypatch)
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                r = await cli.get(f"{_NS}/controls", cookies=_admin_cookie(proxy_module))
                assert r.status == 200, f"GET /controls returned {r.status}"
                html = await r.text()
                assert "Bot Protection (Active)" in html, (
                    "Served /controls HTML must contain new 'Bot Protection (Active)' label"
                )
                # Old label gone from the bypass-label span specifically
                assert '>Bot Detection</span>' not in html, (
                    "Old 'Bot Detection' label must be removed from bypass-label span"
                )

    # ─── persistence coverage — all knobs dual-write to both DBs ────────

    def test_b13_every_knob_persists_to_both_dbs(self):
        """B13: every entry in _HOT_RELOAD_KNOBS (except _NOT_PERSIST_KNOBS)
        must be eligible for the set_config persistence path. The path
        writes to SQLite config_kv AND calls _pg_mirror_bg which writes
        to Postgres config_kv. Verifies the config_endpoint queues the
        set_config op for every persistable knob.
        """
        import core.proxy_handler as ph
        all_knobs   = set(ph._HOT_RELOAD_KNOBS.keys())
        not_persist = set(ph._NOT_PERSIST_KNOBS)
        persistable = all_knobs - not_persist
        assert len(persistable) >= 80, (
            f"Expected ≥80 persistable knobs; got {len(persistable)}. "
            f"Knob registry may have shrunk."
        )
        # config_endpoint must guard the queue call with `k not in _NOT_PERSIST_KNOBS`
        ph_src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
        assert "k not in _NOT_PERSIST_KNOBS" in ph_src, (
            "config_endpoint must skip _NOT_PERSIST_KNOBS when queueing set_config"
        )
        assert 'db_queue.put_nowait((\n                        "set_config"' in ph_src \
            or '"set_config"' in ph_src, (
            "config_endpoint must enqueue 'set_config' for the writer loop"
        )

    def test_b14_writer_loop_writes_set_config_to_both_dbs(self):
        """B14: db.sqlite.db_writer_loop's set_config branch must (1)
        INSERT OR REPLACE into SQLite config_kv AND (2) call _pg_mirror_bg
        with 'set_config'. Verifies the dual-write contract at source level."""
        sql_src = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text()
        # Find the set_config branch of the writer loop
        idx = sql_src.find('elif op == "set_config":')
        assert idx != -1, "writer loop must handle 'set_config' op"
        block = sql_src[idx: idx + 800]
        assert "INSERT OR REPLACE INTO config_kv" in block, (
            "set_config branch must INSERT OR REPLACE into SQLite config_kv"
        )
        assert "_pg_mirror_bg" in block and '"set_config"' in block, (
            "set_config branch must call _pg_mirror_bg('set_config', args) "
            "to mirror the same row into Postgres config_kv"
        )

    def test_b15_pg_mirror_handles_set_config(self):
        """B15: db.postgres._pg_mirror_kv must accept op='set_config' and
        translate it into a Postgres UPSERT (INSERT ... ON CONFLICT
        DO UPDATE) into config_kv with the same (key, value, ts) tuple.
        (sqlite calls _pg_mirror_bg — the off-loop background wrapper —
        which dispatches to _pg_mirror_kv where the SQL lives.)"""
        pg_src = (Path(__file__).resolve().parent.parent / "db" / "postgres.py").read_text()
        idx = pg_src.find("def _pg_mirror_kv")
        body = pg_src[idx: idx + 3000]
        assert 'if op == "set_config":' in body
        assert "INSERT INTO config_kv" in body, (
            "_pg_mirror_kv set_config branch must INSERT INTO config_kv"
        )
        assert "ON CONFLICT (key)" in body, (
            "Mirror must use ON CONFLICT (key) DO UPDATE to be idempotent"
        )

    @pytest.mark.asyncio
    async def test_b16_dynamic_set_config_writes_to_sqlite(self, proxy_module, monkeypatch, tmp_path):
        """B16: end-to-end — POST /config writes the new value into the
        in-memory SQLite test DB. Picks a representative recent knob
        (RATE_LIMIT_ENABLED) and verifies the row lands."""
        import core.proxy_handler as ph
        import admin.auth as auth
        import db.sqlite as sql_mod
        self._bypass_helpers(monkeypatch)
        monkeypatch.setattr(ph,   "_internal_authed",  lambda req: True)
        monkeypatch.setattr(ph,   "_admin_ip_allowed", lambda req: True)
        # _require_csrf decorator looks up _csrf_token_valid in admin.auth's
        # globals at call time — patch there to bypass for this test.
        monkeypatch.setattr(auth, "_csrf_token_valid", lambda req: True)
        # Pick a knob to flip + verify it persists
        target_knob = None
        for k in ("RATE_LIMIT_ENABLED", "WAF_BODY_ENABLED",
                  "INJECT_SECURITY_HEADERS", "JS_CHALLENGE"):
            if k in ph._HOT_RELOAD_KNOBS:
                target_knob = k
                break
        assert target_knob is not None, "no representative knob found in registry"
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                r = await cli.post(f"{_NS}/config",
                                   json={target_knob: False},
                                   cookies=_admin_cookie(proxy_module))
                assert r.status == 200, f"POST returned {r.status}: {await r.text()}"
                j = await r.json()
                assert target_knob in j.get("applied", {}), (
                    f"Knob {target_knob} must be in applied: {j}"
                )
        # Give the writer loop a beat to drain the queue + check SQLite
        await asyncio.sleep(0.5)
        import sqlite3
        conn = sqlite3.connect(sql_mod.DB_PATH)
        try:
            row = conn.execute(
                "SELECT key, value FROM config_kv WHERE key = ?",
                (target_knob,)
            ).fetchone()
        finally:
            conn.close()
        assert row is not None, (
            f"config_kv must contain a row for {target_knob} after POST /config"
        )
        assert row[0] == target_knob
        assert row[1] == "false", (
            f"Persisted value must be JSON-encoded boolean; got {row[1]!r}"
        )

    @pytest.mark.asyncio
    async def test_b12_bypass_mode_active_skips_block_dynamic(self, proxy_module, monkeypatch):
        """B12: dynamic end-to-end — set BYPASS_MODE=True directly, send a
        request that WOULD normally be blocked by AUTHORIZED_BOT_UAS
        (action=ban), confirm HTTP 200 (no block). Re-test of B04 with
        explicit assertion that ban set is unchanged afterward."""
        import core.proxy_handler as ph
        monkeypatch.setattr(ph, "BYPASS_MODE", True, raising=False)
        monkeypatch.setattr(ph, "AUTHORIZED_BOT_UAS", [
            {"name": "evil", "ua": "EvilBotForB12", "path": "/", "ips": [],
             "action": "ban", "enabled": True}
        ], raising=False)
        self._bypass_helpers(monkeypatch)
        # Snapshot ban state to verify it doesn't grow under bypass
        from state import ip_state
        bans_before = sum(1 for s in ip_state.values() if s.banned_until > 0)
        async with _spin_upstream() as up:
            async with _gateway(proxy_module, up) as cli:
                r = await cli.get("/", headers={"User-Agent": "EvilBotForB12/1.0"})
                assert r.status == 200, (
                    f"Bypass must pass through AUTHORIZED_BOT_UAS ban. Got {r.status}"
                )
        bans_after = sum(1 for s in ip_state.values() if s.banned_until > 0)
        assert bans_after == bans_before, (
            f"Bypass must not create new bans. Before={bans_before} after={bans_after}"
        )
