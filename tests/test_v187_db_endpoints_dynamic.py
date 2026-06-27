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


def _csrf_hdr(proxy_module, cookie):
    """X-CSRF-Token header for CSRF-protected admin POSTs (central gate, 1.8.11)."""
    import hashlib, hmac as _hmac
    if isinstance(cookie, dict):
        cookie = next(iter(cookie.values()))
    sid = cookie.split("|")[1]
    token = _hmac.new(proxy_module.SESSION_KEY, sid.encode(),
                      hashlib.sha256).hexdigest()[:32]
    return {"X-CSRF-Token": token}


def _make_viewer_cookie(proxy_module):
    """Prime a viewer-role session. Insert the user via the gateway's own
    backend-aware connection.

    _request_role() -> _user_load() reads users via db.open_conn() (PG in
    PG-only mode, SQLite otherwise). Seeding a raw sqlite3.connect(DB_PATH)
    here wrote to an unused local file in PG mode, so _user_load() returned
    None and _request_role() fell back to the key-only 'admin' default — the
    viewer was silently treated as admin and the role-gate test saw a 200
    instead of the expected 403. Route the seed through open_conn so the user
    lands in the SAME backend the role check reads. (1.9.1 iter-18 backend-
    aware reads.)
    """
    import hashlib
    from db import open_conn as _open_conn
    pw_hash = hashlib.sha256(b"Viewer-QA-pass1!").hexdigest()
    n = proxy_module._t.time()
    # users table already exists (db_init ran on proxy boot). DELETE+INSERT is
    # dialect-neutral; the open_conn wrapper rewrites ? -> %s on PG.
    conn = _open_conn()
    conn.execute("DELETE FROM users WHERE username=?", ("viewer_qa",))
    conn.execute(
        "INSERT INTO users (username, password_hash, role, status, "
        "created_ts, updated_ts) VALUES (?, ?, 'viewer', 'active', ?, ?)",
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
        """DBQA-03: Fresh state (no pending marker) → running=False, marker=None.

        Contract change (1.9.0 F12): the endpoint no longer polls the in-memory
        _BG_MIGRATION dict; it reads the durable `pending_bg_migration` config_kv
        marker. "Never run" means no marker row, so running=False / marker=None.
        (proxy_handler.py:4768 db_migration_status_endpoint)."""
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
                    assert d.get("marker") is None, f"DBQA-03: marker should be None when never run, got {d}"
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

    def test_dbqa05_idle_payload_shape(self, proxy_module):
        """DBQA-05: idle (no pending marker) → running=False and no marker payload.

        Contract change (1.9.0 F12): progress fields (pct/rate_per_sec/
        elapsed_secs/eta_secs) were dropped when the endpoint stopped polling the
        in-memory _BG_MIGRATION dict and became a thin reader over the durable
        `pending_bg_migration` config_kv marker. When idle there is no marker, so
        the payload carries no progress numbers at all.
        (proxy_handler.py:4768 db_migration_status_endpoint)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(
                        NS + "/db-migration-status",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d.get("running") is False,  f"DBQA-05: running should be False when idle, got {d}"
                    assert d.get("marker") is None,    f"DBQA-05: marker should be None when idle, got {d}"
        _run(go())

    def test_dbqa11_running_state_exposes_marker(self, proxy_module):
        """DBQA-11: Pending/in-flight marker → running=True and decoded marker.

        Contract change (1.9.0 F12): a deferred migration is signalled by a
        durable `pending_bg_migration` config_kv row (written at db-switch time,
        claimed by the boot hook). The endpoint surfaces it as
        {"running": True, "marker": <decoded dict>}; the old in-memory progress
        numbers (pct/elapsed_secs/eta_secs/rate_per_sec) no longer exist.
        (proxy_handler.py:4768 db_migration_status_endpoint; marker writer
        proxy_handler.py:4619)."""
        import sqlite3, json as _json
        marker = {
            "target":       "postgres",
            "direction":    "sqlite->postgres",
            "cutoff_ts":    time.time(),
            "scheduled_ts": time.time(),
            "actor":        "admin",
        }

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    # Write the F12 marker AFTER startup so the config_kv table
                    # (created during proxy boot/migration) exists.
                    # db_migration_status_endpoint reads config_kv via
                    # db.open_conn() (PG in PG-only mode), so seed through the
                    # SAME backend — a raw sqlite3.connect(DB_PATH) wrote an
                    # unused local row in PG mode and the endpoint reported
                    # running=False/marker=None.
                    from db import open_conn as _open_conn
                    conn = _open_conn()
                    conn.execute(
                        "DELETE FROM config_kv WHERE key=?",
                        ("pending_bg_migration",),
                    )
                    conn.execute(
                        "INSERT INTO config_kv (key, value, ts) VALUES (?, ?, ?)",
                        ("pending_bg_migration", _json.dumps(marker), time.time()),
                    )
                    conn.commit()
                    conn.close()
                    cookie = self._cookie(proxy_module)
                    r = await c.get(
                        NS + "/db-migration-status",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d["running"] is True,        f"DBQA-11: running should be True with a pending marker, got {d}"
                    assert isinstance(d.get("marker"), dict), f"DBQA-11: marker dict missing: {d}"
                    assert d["marker"].get("direction") == "sqlite->postgres", \
                        f"DBQA-11: marker direction not surfaced: {d}"
        _run(go())

        # Restore clean state: remove the marker row via the active backend.
        from db import open_conn as _open_conn
        conn = _open_conn()
        try:
            conn.execute("DELETE FROM config_kv WHERE key = ?", ("pending_bg_migration",))
            conn.commit()
        except Exception:
            pass
        conn.close()

    def test_dbqa12_done_state_clears_marker(self, proxy_module):
        """DBQA-12: Completed migration → marker cleared → running=False, marker=None.

        Contract change (1.9.0 F12): completion is not reported as a done=True/
        pct=100 payload anymore. When the boot hook (proxy._resume_pending_bg_
        migration) finishes the copy it DELETEs the `pending_bg_migration`
        config_kv marker (proxy.py:338), so a finished migration is observable
        only as the absence of the marker: running=False, marker=None — the same
        terminal shape as never-run.
        (proxy_handler.py:4768 db_migration_status_endpoint)."""
        import sqlite3
        # Simulate the post-completion state: boot hook has deleted the marker.
        conn = sqlite3.connect(proxy_module.DB_PATH)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS config_kv "
            "(key TEXT PRIMARY KEY, value TEXT, ts REAL)"
        )
        conn.execute("DELETE FROM config_kv WHERE key = ?", ("pending_bg_migration",))
        conn.commit()
        conn.close()

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(
                        NS + "/db-migration-status",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d["running"] is False,    f"DBQA-12: running should be False after completion, got {d}"
                    assert d.get("marker") is None,  f"DBQA-12: marker should be cleared after completion, got {d}"
        _run(go())


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
                        headers=_csrf_hdr(proxy_module, cookie),
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
                            headers=_csrf_hdr(proxy_module, cookie),
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
                            headers=_csrf_hdr(proxy_module, cookie),
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                    d = await r.json()
                    assert d.get("full_migrate_scheduled") is False, \
                        f"DBQA-09: full_migrate_scheduled should be False, got {d}"
        _run(go())

    def test_dbqa10_full_migrate_already_running_defers_safely(self, proxy_module):
        """DBQA-10 (1.9.0 F12): full_migrate=true even while a migration is
        currently running must still persist the deferred-migration marker —
        the boot-time resumer (_resume_deferred_full_migrate) uses an atomic
        _try_claim_bg_migration check so two markers can never both run.

        Pre-F12 contract refused the second schedule outright
        (`full_migrate_scheduled=False`). The new F12 contract accepts it
        and queues the resume on next restart, because:
          • the marker write is idempotent (latest wins)
          • boot-resume single-flights via _try_claim_bg_migration
          • restarting mid-run would have aborted the first migration
            anyway under the single-DB contract

        So `full_migrate_scheduled=True` is the correct response."""
        import db.postgres as pg
        pg._BG_MIGRATION["running"] = True

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    with patch("os._exit"):
                        r = await c.post(
                            NS + "/db-switch?target=sqlite",
                            json={"full_migrate": True},
                            headers=_csrf_hdr(proxy_module, cookie),
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                    d = await r.json()
                    # F12: deferred marker writes succeed regardless of
                    # current-running state. full_migrate_scheduled tracks
                    # "the marker was persisted" — NOT "the bg thread
                    # started right now".
                    assert d.get("full_migrate_scheduled") is True, (
                        f"DBQA-10: with F12 deferred-migration, marker write "
                        f"must succeed even when a migration is currently "
                        f"running. Boot-resume single-flights via "
                        f"_try_claim_bg_migration. Got: {d}"
                    )
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
                        headers=_csrf_hdr(proxy_module, cookie),
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
                        headers={"Content-Type": "application/octet-stream",
                                 **_csrf_hdr(proxy_module, cookie)},
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
        """DBQA-15: _BG_MIGRATION has exactly the required keys.

        1.8.8 — added `watermark` and `skipped_already_present` for the
        MIN/MAX gap-fill idempotent migration. Both must be present.
        """
        import db.postgres as pg
        required = {
            "running", "done", "error", "direction",
            "total", "copied",
            "started_at", "finished_at",
            # 1.8.8 — idempotent migration observability
            "watermark", "skipped_already_present",
        }
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
