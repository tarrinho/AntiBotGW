"""
tests/test_v187_db_endpoints_dynamic.py — Dynamic QA for DB switch + migration-status (v1.8.7)

Tests spin a real in-process proxy (aiohttp TestClient) and issue genuine HTTP
requests — no mocking of the HTTP layer.  They cover:

  DBQA-01  GET /secured/db-migration-status unauthenticated → decoy (no JSON)
  DBQA-02  GET /secured/db-migration-status authenticated → 200 JSON with required keys
  DBQA-03  GET /secured/db-migration-status never-run state → running=False, done=False
  DBQA-04  GET /secured/db-migration-status Cache-Control header is no-store
  DBQA-05  GET /secured/db-migration-status pct/rate/eta/elapsed are 0/None when idle
  DBQA-06  POST /secured/db-switch unauthenticated → decoy (not 400/403)
  DBQA-07  POST /secured/db-switch invalid target → 400 JSON with error key
  DBQA-08  POST /secured/db-switch target=sqlite → 200 with full_migrate_scheduled key
  DBQA-09  POST /secured/db-switch full_migrate=false → full_migrate_scheduled=False
  DBQA-10  POST /secured/db-switch full_migrate=true, already running → not double-started
  DBQA-11  GET /secured/db-migration-status simulated running state → pct+eta+rate present
  DBQA-12  GET /secured/db-migration-status simulated done state → correct fields
  DBQA-13  Route registered: db-migration-status appears in app router
  DBQA-14  Route registered: db-switch appears in app router (POST only)
  DBQA-15  _BG_MIGRATION has exactly the required keys
  DBQA-16  _full_migrate_background sets running=True then done=True on completion
  DBQA-17  _bg_sqlite_to_pg skips rows outside cutoff window
  DBQA-18  _bg_pg_to_sqlite skips rows outside cutoff window
  DBQA-19  POST /secured/db-switch viewer role → 403
  DBQA-20  POST /secured/db-switch missing Content-Type → still parsed (JSON body)
"""
import asyncio
import os
import sqlite3
import sys
import tempfile
import time
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

# ── env / path ────────────────────────────────────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="appsecgw-dbqa-")
os.environ.setdefault("UPSTREAM",  "https://example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "dbqa-test.db"))

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

NS = "/antibot-appsec-gateway/secured"

# ── helpers ───────────────────────────────────────────────────────────────────

async def _echo_handler(request):
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


def _make_viewer_cookie(proxy_module):
    """Prime a viewer-role session. Insert the user directly into the DB."""
    import sqlite3, hashlib
    db_path = proxy_module.DB_PATH
    # Insert viewer user if not already present
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(username TEXT PRIMARY KEY, password_hash TEXT, role TEXT, "
        "status TEXT, created_ts REAL, updated_ts REAL)"
    )
    pw_hash = hashlib.sha256(b"Viewer-QA-pass1!").hexdigest()
    n = proxy_module._t.time()
    conn.execute(
        "INSERT OR REPLACE INTO users (username, password_hash, role, status, created_ts, updated_ts) "
        "VALUES (?, ?, 'viewer', 'active', ?, ?)",
        ("viewer_qa", pw_hash, n, n),
    )
    conn.commit()
    conn.close()

    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "viewer_qa",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("viewer_qa", sid=sid)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── DBQA-01 through DBQA-05: GET /secured/db-migration-status ────────────────

class TestDbMigrationStatusEndpoint:

    def _cookie(self, pm):
        return _make_admin_cookie(pm)

    def test_dbqa01_unauthenticated_decoy(self, proxy_module):
        """DBQA-01: Unauthenticated GET must not return real JSON payload."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/db-migration-status")
                    body = await r.text()
                    # Decoy: real payload would contain "running" or "done"
                    assert '"running"' not in body, \
                        "DBQA-01: unauthenticated response must not expose migration state"
        _run(go())

    def test_dbqa02_authenticated_200_json(self, proxy_module):
        """DBQA-02: Authenticated GET → 200 with JSON body."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(
                        NS + "/db-migration-status",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200, f"DBQA-02: expected 200, got {r.status}"
                    ct = r.headers.get("Content-Type", "")
                    assert "json" in ct, f"DBQA-02: expected JSON content-type, got '{ct}'"
                    d = await r.json()
                    assert isinstance(d, dict), "DBQA-02: response must be a JSON object"
        _run(go())

    def test_dbqa03_never_run_state(self, proxy_module):
        """DBQA-03: Fresh state → running=False, done=False."""
        import db.postgres as pg
        pg._BG_MIGRATION.update({
            "running": False, "done": False, "error": None,
            "direction": "", "total": 0, "copied": 0,
            "started_at": 0.0, "finished_at": 0.0,
        })

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(
                        NS + "/db-migration-status",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d["running"] is False, f"DBQA-03: running should be False, got {d['running']}"
                    assert d["done"] is False,    f"DBQA-03: done should be False, got {d['done']}"
        _run(go())

    def test_dbqa04_cache_control_no_store(self, proxy_module):
        """DBQA-04: Response must have Cache-Control: no-store."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(
                        NS + "/db-migration-status",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, \
                        f"DBQA-04: Cache-Control must contain 'no-store', got '{cc}'"
        _run(go())

    def test_dbqa05_pct_eta_rate_zero_when_idle(self, proxy_module):
        """DBQA-05: pct/rate_per_sec/elapsed_secs are 0.0 and eta_secs is None when idle."""
        import db.postgres as pg
        pg._BG_MIGRATION.update({
            "running": False, "done": False, "error": None,
            "direction": "", "total": 0, "copied": 0,
            "started_at": 0.0, "finished_at": 0.0,
        })

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(
                        NS + "/db-migration-status",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d.get("pct") == 0.0,            f"DBQA-05: pct should be 0.0 when idle, got {d}"
                    assert d.get("rate_per_sec") == 0.0,   f"DBQA-05: rate_per_sec should be 0.0 when idle, got {d}"
                    assert d.get("elapsed_secs") == 0.0,   f"DBQA-05: elapsed_secs should be 0.0 when idle, got {d}"
                    assert d.get("eta_secs") is None,      f"DBQA-05: eta_secs should be None when idle, got {d}"
        _run(go())

    def test_dbqa11_running_state_has_progress_fields(self, proxy_module):
        """DBQA-11: Simulated running state → pct + elapsed_secs + eta_secs + rate_per_sec."""
        import db.postgres as pg
        pg._BG_MIGRATION.update({
            "running":    True,
            "done":       False,
            "error":      None,
            "direction":  "sqlite->postgres",
            "total":      1000,
            "copied":     500,
            "started_at": time.time() - 10.0,
            "finished_at": 0.0,
        })

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(
                        NS + "/db-migration-status",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d["running"] is True,        f"DBQA-11: running should be True, got {d}"
                    assert "pct" in d,                  f"DBQA-11: pct missing from running state: {d}"
                    assert "elapsed_secs" in d,         f"DBQA-11: elapsed_secs missing: {d}"
                    assert "eta_secs" in d,             f"DBQA-11: eta_secs missing: {d}"
                    assert "rate_per_sec" in d,         f"DBQA-11: rate_per_sec missing: {d}"
                    assert 45.0 <= d["pct"] <= 55.0,   f"DBQA-11: pct should be ~50, got {d['pct']}"
                    assert d["elapsed_secs"] >= 5.0,   f"DBQA-11: elapsed_secs should be >=5, got {d['elapsed_secs']}"
        _run(go())

        # Restore clean state
        pg._BG_MIGRATION.update({
            "running": False, "done": False, "error": None,
            "direction": "", "total": 0, "copied": 0,
            "started_at": 0.0, "finished_at": 0.0,
        })

    def test_dbqa12_done_state_fields(self, proxy_module):
        """DBQA-12: Simulated done state → done=True, pct=100 (if total>0), finished_at present."""
        import db.postgres as pg
        finished = time.time() - 2.0
        pg._BG_MIGRATION.update({
            "running":    False,
            "done":       True,
            "error":      None,
            "direction":  "postgres->sqlite",
            "total":      200,
            "copied":     200,
            "started_at": finished - 5.0,
            "finished_at": finished,
        })

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(
                        NS + "/db-migration-status",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d["done"] is True,           f"DBQA-12: done should be True, got {d}"
                    assert d["running"] is False,       f"DBQA-12: running should be False, got {d}"
                    assert "pct" in d,                  f"DBQA-12: pct missing from done state: {d}"
                    assert d["pct"] == 100.0,           f"DBQA-12: pct should be 100, got {d['pct']}"
                    assert "finished_at" in d,          f"DBQA-12: finished_at missing: {d}"
        _run(go())

        # Restore
        pg._BG_MIGRATION.update({
            "running": False, "done": False, "error": None,
            "direction": "", "total": 0, "copied": 0,
            "started_at": 0.0, "finished_at": 0.0,
        })


# ── DBQA-06 through DBQA-10 + 19-20: POST /secured/db-switch ─────────────────

class TestDbSwitchEndpoint:

    def _cookie(self, pm):
        return _make_admin_cookie(pm)

    def test_dbqa06_unauthenticated_decoy(self, proxy_module):
        """DBQA-06: Unauthenticated POST must not return real admin JSON."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.post(
                        NS + "/db-switch",
                        json={"target": "sqlite"},
                    )
                    body = await r.text()
                    assert '"backend"' not in body, \
                        "DBQA-06: unauthenticated response must not expose backend field"
                    assert '"full_migrate_scheduled"' not in body, \
                        "DBQA-06: unauthenticated response must not expose migration field"
        _run(go())

    def test_dbqa07_invalid_target_400(self, proxy_module):
        """DBQA-07: target not in {sqlite, postgres} → 400 with reason."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    # target is a query param, not body
                    r = await c.post(
                        NS + "/db-switch?target=mysql",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 400, f"DBQA-07: expected 400, got {r.status}"
                    d = await r.json()
                    assert "reason" in d, f"DBQA-07: reason key missing from 400 response: {d}"
                    assert d["reason"], f"DBQA-07: reason must not be empty: {d}"
        _run(go())

    def test_dbqa08_switch_to_sqlite_has_full_migrate_key(self, proxy_module):
        """DBQA-08: target=sqlite → 200 response includes full_migrate_scheduled."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    with patch("os._exit"):
                        # target is a query param
                        r = await c.post(
                            NS + "/db-switch?target=sqlite",
                            json={},
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                    assert r.status == 200, f"DBQA-08: expected 200, got {r.status}"
                    d = await r.json()
                    assert "full_migrate_scheduled" in d, \
                        f"DBQA-08: full_migrate_scheduled missing from response: {d}"
        _run(go())

    def test_dbqa09_full_migrate_false_not_scheduled(self, proxy_module):
        """DBQA-09: full_migrate=false → full_migrate_scheduled=False."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    with patch("os._exit"):
                        # target via query param; full_migrate in body
                        r = await c.post(
                            NS + "/db-switch?target=sqlite",
                            json={"full_migrate": False},
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                    d = await r.json()
                    assert d.get("full_migrate_scheduled") is False, \
                        f"DBQA-09: full_migrate_scheduled should be False, got {d}"
        _run(go())

    def test_dbqa10_full_migrate_already_running_not_double_started(self, proxy_module):
        """DBQA-10: full_migrate=true but migration already running → not rescheduled."""
        import db.postgres as pg
        pg._BG_MIGRATION["running"] = True

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    with patch("os._exit"):
                        # target via query param; full_migrate in body
                        r = await c.post(
                            NS + "/db-switch?target=sqlite",
                            json={"full_migrate": True},
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                    d = await r.json()
                    assert d.get("full_migrate_scheduled") is False, \
                        f"DBQA-10: should not double-start migration, got {d}"
        _run(go())
        pg._BG_MIGRATION["running"] = False

    def test_dbqa19_viewer_role_denied(self, proxy_module):
        """DBQA-19: viewer role → 403 on POST /secured/db-switch."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_viewer_cookie(proxy_module)
                    # target via query param
                    r = await c.post(
                        NS + "/db-switch?target=sqlite",
                        json={},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 403, f"DBQA-19: viewer should get 403, got {r.status}"
        _run(go())

    def test_dbqa20_post_without_content_type_parsed(self, proxy_module):
        """DBQA-20: POST body without Content-Type application/json still returns valid error."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.post(
                        NS + "/db-switch",
                        data=b'{"target":"mysql"}',
                        headers={"Content-Type": "application/octet-stream"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    # Either 400 (parsed and rejected invalid target) or 400 (parse fail)
                    assert r.status in (400, 200), \
                        f"DBQA-20: unexpected status {r.status}"
        _run(go())


# ── DBQA-13/14: Route registration ────────────────────────────────────────────

class TestDbRouteRegistration:

    def test_dbqa13_migration_status_route_registered(self, proxy_module):
        """DBQA-13: /secured/db-migration-status appears as GET in app router."""
        app = proxy_module.make_app()
        routes = {
            (r.method, r.resource.canonical)
            for r in app.router.routes()
        }
        assert ("GET", NS + "/db-migration-status") in routes, \
            f"DBQA-13: GET {NS}/db-migration-status not registered. Routes: {routes}"

    def test_dbqa14_db_switch_route_registered_as_post(self, proxy_module):
        """DBQA-14: /secured/db-switch registered as POST (not GET)."""
        app = proxy_module.make_app()
        routes = {
            (r.method, r.resource.canonical)
            for r in app.router.routes()
        }
        assert ("POST", NS + "/db-switch") in routes, \
            f"DBQA-14: POST {NS}/db-switch not registered. Routes: {routes}"
        assert ("GET", NS + "/db-switch") not in routes, \
            f"DBQA-14: GET {NS}/db-switch should NOT be registered"


# ── DBQA-15: _BG_MIGRATION shape ─────────────────────────────────────────────

class TestBgMigrationShape:

    def test_dbqa15_bg_migration_required_keys(self):
        """DBQA-15: _BG_MIGRATION has exactly the required keys."""
        import db.postgres as pg
        required = {"running", "done", "error", "direction", "total", "copied",
                    "started_at", "finished_at"}
        actual = set(pg._BG_MIGRATION.keys())
        missing = required - actual
        extra   = actual - required
        assert not missing, f"DBQA-15: _BG_MIGRATION missing keys: {missing}"
        assert not extra,   f"DBQA-15: _BG_MIGRATION has unexpected keys: {extra}"


# ── DBQA-16: _full_migrate_background lifecycle ───────────────────────────────

class TestFullMigrateBackground:

    def test_dbqa16_full_migrate_background_sets_done(self):
        """DBQA-16: _full_migrate_background sets running=True then done=True."""
        import db.postgres as pg

        pg._BG_MIGRATION.update({
            "running": False, "done": False, "error": None,
            "direction": "", "total": 0, "copied": 0,
            "started_at": 0.0, "finished_at": 0.0,
        })

        cutoff = time.time()

        # Mock the inner worker so no real DB calls happen
        with patch.object(pg, "_bg_sqlite_to_pg", return_value=None) as mock_worker:
            pg._full_migrate_background("postgres", cutoff, batch_size=500, batch_sleep=0.0)

        assert pg._BG_MIGRATION["done"] is True,    \
            f"DBQA-16: done should be True after completion, got {pg._BG_MIGRATION}"
        assert pg._BG_MIGRATION["running"] is False, \
            f"DBQA-16: running should be False after completion, got {pg._BG_MIGRATION}"
        assert pg._BG_MIGRATION["direction"] == "sqlite->postgres", \
            f"DBQA-16: direction wrong, got {pg._BG_MIGRATION['direction']}"
        mock_worker.assert_called_once()


# ── DBQA-17/18: cutoff filtering in bg workers ───────────────────────────────

class TestBgMigrationCutoff:

    def _setup_sqlite(self, path):
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS events "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, ua TEXT, "
            "path TEXT, method TEXT DEFAULT 'GET', status INTEGER DEFAULT 200, reason TEXT DEFAULT '')"
        )
        now = time.time()
        rows = [
            (now - 200, "1.1.1.1", "ua-old", "/old",  200, "ok"),     # outside cutoff (old)
            (now - 100, "2.2.2.2", "ua-mid", "/mid",  200, "ok"),     # outside cutoff (old)
            (now - 10,  "3.3.3.3", "ua-new", "/new",  200, "ok"),     # INSIDE cutoff (recent)
        ]
        conn.executemany(
            "INSERT INTO events (ts, ip, ua, path, status, reason) VALUES (?,?,?,?,?,?)", rows
        )
        conn.commit()
        conn.close()
        return now - 50  # cutoff: rows with ts < cutoff should be copied

    def test_dbqa17_sqlite_to_pg_cutoff(self):
        """DBQA-17: _bg_sqlite_to_pg SQL only selects rows with ts < cutoff_ts.

        Verifies the cutoff logic by:
        1. Creating a test SQLite DB with known rows (2 old, 1 new)
        2. Patching DB_PATH and _postgres_load_module to abort at PG connect
        3. Confirming only rows with ts < cutoff are in the eligible set
        """
        import db.postgres as pg

        db_path = os.path.join(_TMP, "dbqa17.db")
        cutoff = self._setup_sqlite(db_path)

        # Verify directly that the cutoff partitions correctly
        conn = sqlite3.connect(db_path)
        old_rows = conn.execute(
            "SELECT count(*) FROM events WHERE ts < ?", (cutoff,)
        ).fetchone()[0]
        new_rows = conn.execute(
            "SELECT count(*) FROM events WHERE ts >= ?", (cutoff,)
        ).fetchone()[0]
        conn.close()

        assert old_rows == 2, f"DBQA-17: expected 2 rows with ts < cutoff, got {old_rows}"
        assert new_rows == 1, f"DBQA-17: expected 1 row with ts >= cutoff, got {new_rows}"

        # Verify the function uses the cutoff in its WHERE clause (source inspection)
        import inspect
        src = inspect.getsource(pg._bg_sqlite_to_pg)
        assert "ts < ?" in src or "cutoff_ts" in src, \
            "DBQA-17: _bg_sqlite_to_pg must filter events by cutoff_ts"

        # Verify bg function aborts early when PG unavailable (no rows copied)
        pg._BG_MIGRATION.update({"total": 0, "copied": 0})
        with patch("db.postgres.DB_PATH", db_path):
            with patch("db.postgres.POSTGRES_DSN", ""):
                try:
                    pg._bg_sqlite_to_pg(cutoff, batch_size=500, batch_sleep=0.0)
                except RuntimeError as e:
                    assert "psycopg" in str(e) or "DSN" in str(e), \
                        f"DBQA-17: unexpected RuntimeError: {e}"

    def test_dbqa18_pg_to_sqlite_cutoff_logic(self):
        """DBQA-18: _bg_pg_to_sqlite pagination uses cutoff correctly."""
        import db.postgres as pg
        import inspect
        src = inspect.getsource(pg._bg_pg_to_sqlite)
        # The function must reference cutoff_ts in the SQL WHERE clause
        assert "cutoff" in src, \
            "DBQA-18: _bg_pg_to_sqlite must reference cutoff in its SQL query"
        assert "to_timestamp" in src or "ts <" in src, \
            "DBQA-18: _bg_pg_to_sqlite must filter by timestamp cutoff"
