"""
QA tests for v1.8.1 — Admin Audit Trail (gw_audit)

Coverage:
  U1  db/sqlite.py — gw_audit table exists with required columns after on_startup
  U2  db/sqlite.py — gw_audit_add op SQL inserts row with correct field values
  U3  admin/mesh.py — _gw_audit() helper enqueues (gw_audit_add, args) to db_queue
  U4  admin/mesh.py — _gw_audit() is a no-op when db_queue is None (never raises)
  U5  admin/auth.py — _request_username() returns _session_user from request dict
  U6  admin/auth.py — _request_username() returns "unknown" when _session_user absent

  F1  config_endpoint POST applied knob → one gw_audit row per applied knob
  F2  config_endpoint POST → audit row actor matches the logged-in admin username
  F3  config_endpoint POST → audit row details JSON has key, old, new fields
  F4  config_endpoint POST rejected knob → no audit row written for that knob
  F5  config_endpoint POST multiple knobs → one row per knob applied
  F6  vhosts_endpoint POST → audit row action=vhost_set with hostname in details
  F7  vhosts_endpoint POST → audit row actor field populated from session
  F8  vhosts_endpoint POST → audit row upstream in details
  F9  vhosts_endpoint DELETE → audit row action=vhost_delete with hostname
  F10 vhosts_endpoint DELETE → audit row actor field populated
  F11 settings_import non-dry-run → audit row action=settings_import written
  F12 settings_import dry_run=1 → NO audit row written (guard works)
  F13 settings_import audit detail contains knobs_applied count
  F14 audit_log_endpoint GET authenticated → 200, {rows: [...], count: N}
  F15 audit_log_endpoint GET unauthenticated → decoy response, no audit data
  F16 audit_log_endpoint GET → rows and count are correct types
  F17 audit_log_endpoint GET → count field equals len(rows)
  F18 audit_log_endpoint GET ?action= substring filter returns only matching rows
  F19 audit_log_endpoint GET ?actor= exact filter returns only matching rows
  F20 audit_log_endpoint GET ?limit=N restricts result count
  F21 audit_log_endpoint GET ?since= excludes rows older than cutoff
  F22 audit_log_endpoint GET → details field returned as JSON object, not raw string
  F23 audit_log_endpoint GET ?limit=invalid → 200 with rows (falls back to default)
  F24 audit_log_endpoint GET ?limit=9999 → 200 (oversized limit silently capped)

  R1  db/postgres.py — gw_audit_add case present in _pg_mirror_kv with %s placeholders
  R2  db/sqlite.py — gw_audit_add calls _pg_mirror_kv after the SQLite insert
  R3  core/proxy_handler.py — old_v captured before g[k] = value in config_endpoint
  R4  core/proxy_handler.py — gw_audit_add op enqueued inside config_endpoint body
  R5  core/proxy_handler.py — slog("config_changed") includes actor= keyword argument
  R6  admin/settings.py — vhost POST calls _gw_audit() after slog("vhost_set")
  R7  admin/settings.py — vhost DELETE calls _gw_audit() after slog("vhost_delete")
  R8  admin/settings.py — settings_import _gw_audit call guarded by `not dry_run`
  R9  admin/settings.py — audit_log_endpoint WHERE clauses are hardcoded (no interpolation)
  R10 admin/settings.py — audit_log_endpoint limit capped at 1000 via min()
  R11 admin/settings.py — audit_log_endpoint registered in proxy.py route table
"""
import asyncio
import inspect
import io
import json
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# ── Constants ─────────────────────────────────────────────────────────────────

NS   = "/antibot-appsec-gateway/secured"
ROOT = Path(__file__).resolve().parent.parent

# ── Shared helpers ────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _echo_handler(request: web.Request):
    return web.json_response({"path": request.path})


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
    """Return X-CSRF-Token header dict for CSRF-protected endpoints."""
    import hashlib, hmac as _hmac
    if isinstance(cookie, dict):
        cookie = next(iter(cookie.values()))
    sid = cookie.split("|")[1]
    token = _hmac.new(proxy_module.SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
    return {"X-CSRF-Token": token}


def _audit_rows(proxy_module, action=None):
    """Query gw_audit table directly; optionally filter by action."""
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    if action:
        rows = conn.execute(
            "SELECT * FROM gw_audit WHERE action=? ORDER BY ts", (action,)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM gw_audit ORDER BY ts").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _seed_audit(proxy_module, action="test_action", actor="admin",
                details=None, ts=None):
    """Insert a row directly into gw_audit for query-side tests."""
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.execute(
        "INSERT INTO gw_audit (ts, action, gw_id, actor, details) VALUES (?,?,?,?,?)",
        (ts or time.time(), action, "gw-test", actor,
         json.dumps(details or {"key": "val"})),
    )
    conn.commit()
    conn.close()


def _wipe_audit(proxy_module):
    try:
        conn = sqlite3.connect(proxy_module.DB_PATH)
        conn.execute("DELETE FROM gw_audit")
        conn.commit()
        conn.close()
    except sqlite3.OperationalError:
        pass


def _make_config_zip(knobs: dict) -> bytes:
    """Build a minimal settings ZIP/XML compatible with settings_import_endpoint."""
    root = ET.Element("appsecgw-config", attrib={"version": "1.6.5", "exported_at": "0"})
    knobs_el = ET.SubElement(root, "knobs")
    for k, v in knobs.items():
        e = ET.SubElement(knobs_el, "knob", attrib={"name": k, "type": type(v).__name__})
        e.text = json.dumps(v, ensure_ascii=False)
    ET.SubElement(root, "admin_ips")
    ET.SubElement(root, "secrets")
    ET.indent(root, space="  ")
    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("appsecgw-config.xml", xml_bytes)
    return buf.getvalue()


# ── Autouse: isolate gw_audit before/after every test in this module ──────────

@pytest.fixture(autouse=True)
def _isolate_audit_table():
    import sys, proxy as _p
    _wipe_audit(_p)
    # Snapshot hot-reloadable knobs that config-endpoint tests modify so they
    # don't leak into later tests (config_endpoint propagates to all modules).
    import config as _cfg
    _snap = {k: getattr(_cfg, k) for k in dir(_cfg)
             if not k.startswith("_") and isinstance(getattr(_cfg, k), (int, float, bool, str, list))}
    yield
    _wipe_audit(_p)
    # Restore snapshotted config values across all loaded modules.
    for k, v in _snap.items():
        if getattr(_cfg, k, None) != v:
            setattr(_cfg, k, v)
            for _m in list(sys.modules.values()):
                if _m is not None and _m is not _cfg and hasattr(_m, k):
                    try:
                        setattr(_m, k, v)
                    except (AttributeError, TypeError):
                        pass


# ── U1: gw_audit table schema ─────────────────────────────────────────────────

class TestU1AuditTableSchema:
    """gw_audit table must exist with the correct schema after on_startup."""

    def test_gw_audit_has_required_columns(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as _:
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    cols = {r[1] for r in conn.execute(
                        "PRAGMA table_info(gw_audit)"
                    ).fetchall()}
                    conn.close()
                    required = {"id", "ts", "action", "gw_id", "actor", "details"}
                    assert required <= cols, \
                        f"gw_audit missing columns; expected {required}, found {cols}"
        _run(go())

    def test_gw_audit_ts_index_exists(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as _:
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    idx = {r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='index' AND tbl_name='gw_audit'"
                    ).fetchall()}
                    conn.close()
                    assert any("ts" in i for i in idx), \
                        f"gw_audit must have a ts index; found: {idx}"
        _run(go())

    def test_gw_audit_gw_id_index_exists(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as _:
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    idx = {r[0] for r in conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='index' AND tbl_name='gw_audit'"
                    ).fetchall()}
                    conn.close()
                    assert any("gw_id" in i for i in idx), \
                        f"gw_audit must have a gw_id index; found: {idx}"
        _run(go())


# ── U2: gw_audit_add SQLite op ────────────────────────────────────────────────

class TestU2GwAuditAddOp:
    """The SQL statement used by gw_audit_add must correctly insert rows."""

    _SQL = ("INSERT INTO gw_audit (ts, action, gw_id, actor, details) "
            "VALUES (?,?,?,?,?)")

    def _fresh_db(self):
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE gw_audit ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "ts REAL NOT NULL, action TEXT NOT NULL, "
            "gw_id TEXT, actor TEXT, details TEXT)"
        )
        return conn

    def test_insert_creates_one_row(self):
        conn = self._fresh_db()
        conn.execute(self._SQL, (time.time(), "config_change", "gw-1", "alice", "{}"))
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM gw_audit").fetchone()[0] == 1

    def test_insert_stores_correct_action(self):
        conn = self._fresh_db()
        conn.execute(self._SQL, (time.time(), "vhost_set", "gw-1", "bob", "{}"))
        conn.commit()
        assert conn.execute("SELECT action FROM gw_audit").fetchone()[0] == "vhost_set"

    def test_insert_stores_correct_actor(self):
        conn = self._fresh_db()
        conn.execute(self._SQL, (time.time(), "config_change", "gw-1", "charlie", "{}"))
        conn.commit()
        assert conn.execute("SELECT actor FROM gw_audit").fetchone()[0] == "charlie"

    def test_insert_details_json_roundtrips(self):
        conn = self._fresh_db()
        payload = {"key": "RATE_LIMIT_BURST", "old": 20, "new": 50}
        conn.execute(self._SQL,
                     (time.time(), "config_change", "gw-1", "admin",
                      json.dumps(payload)))
        conn.commit()
        raw = conn.execute("SELECT details FROM gw_audit").fetchone()[0]
        assert json.loads(raw) == payload

    def test_insert_id_is_autoincrement(self):
        conn = self._fresh_db()
        for i in range(3):
            conn.execute(self._SQL,
                         (time.time() + i, f"a{i}", "gw-1", "u", "{}"))
        conn.commit()
        ids = [r[0] for r in conn.execute(
            "SELECT id FROM gw_audit ORDER BY id"
        ).fetchall()]
        assert ids == [1, 2, 3], f"autoincrement IDs must be sequential, got {ids}"

    def test_insert_null_actor_allowed(self):
        conn = self._fresh_db()
        conn.execute(self._SQL, (time.time(), "startup", "gw-1", None, "{}"))
        conn.commit()
        row = conn.execute("SELECT actor FROM gw_audit").fetchone()
        assert row[0] is None


# ── U3: _gw_audit() helper ────────────────────────────────────────────────────

class TestU3GwAuditHelper:
    """_gw_audit() must enqueue the right op and never raise on queue failures."""

    def test_enqueues_gw_audit_add_op(self):
        import admin.mesh as _mesh
        mock_q = MagicMock()
        with patch.object(_mesh, "db_queue", mock_q):
            _mesh._gw_audit("config_change", "gw-1", "admin", key="JS_CHALLENGE")
        mock_q.put_nowait.assert_called_once()
        op, _ = mock_q.put_nowait.call_args[0][0]
        assert op == "gw_audit_add"

    def test_enqueued_args_have_correct_action(self):
        import admin.mesh as _mesh
        mock_q = MagicMock()
        with patch.object(_mesh, "db_queue", mock_q):
            _mesh._gw_audit("vhost_set", "gw-1", "alice")
        _, args = mock_q.put_nowait.call_args[0][0]
        assert args[1] == "vhost_set"

    def test_enqueued_args_have_correct_actor(self):
        import admin.mesh as _mesh
        mock_q = MagicMock()
        with patch.object(_mesh, "db_queue", mock_q):
            _mesh._gw_audit("vhost_delete", "gw-1", "charlie")
        _, args = mock_q.put_nowait.call_args[0][0]
        assert args[3] == "charlie"

    def test_kwargs_serialised_as_json_details(self):
        import admin.mesh as _mesh
        mock_q = MagicMock()
        with patch.object(_mesh, "db_queue", mock_q):
            _mesh._gw_audit("settings_import", "gw-1", "admin",
                            knobs_applied=3, applied=["A", "B", "C"])
        _, args = mock_q.put_nowait.call_args[0][0]
        details = json.loads(args[4])
        assert details["knobs_applied"] == 3
        assert details["applied"] == ["A", "B", "C"]

    def test_noop_when_db_queue_none(self):
        import admin.mesh as _mesh
        with patch.object(_mesh, "db_queue", None):
            _mesh._gw_audit("config_change", "gw-1", "admin", key="X")

    def test_queue_full_does_not_raise(self):
        import admin.mesh as _mesh
        mock_q = MagicMock()
        mock_q.put_nowait.side_effect = asyncio.QueueFull()
        with patch.object(_mesh, "db_queue", mock_q):
            _mesh._gw_audit("config_change", "gw-1", "admin")

    def test_empty_kwargs_produces_empty_string_details(self):
        import admin.mesh as _mesh
        mock_q = MagicMock()
        with patch.object(_mesh, "db_queue", mock_q):
            _mesh._gw_audit("startup", "gw-1", "system")
        _, args = mock_q.put_nowait.call_args[0][0]
        assert args[4] == ""


# ── U4/U5: _request_username ──────────────────────────────────────────────────

class TestU4RequestUsername:
    """_request_username() must return the session user or 'unknown'."""

    def test_returns_session_user(self):
        from admin.auth import _request_username
        assert _request_username({"_session_user": "alice"}) == "alice"

    def test_returns_unknown_when_key_absent(self):
        from admin.auth import _request_username
        assert _request_username({}) == "unknown"

    def test_returns_unknown_when_value_none(self):
        from admin.auth import _request_username
        assert _request_username({"_session_user": None}) == "unknown"

    def test_returns_unknown_when_value_empty_string(self):
        from admin.auth import _request_username
        assert _request_username({"_session_user": ""}) == "unknown"

    def test_returns_unknown_on_non_dict_request(self):
        from admin.auth import _request_username
        assert _request_username(object()) == "unknown"


# ── F1–F5: config_endpoint audit writes ───────────────────────────────────────

class TestF1ConfigEndpointAudit:
    """config_endpoint POST must write gw_audit rows for each applied knob."""

    def test_writes_audit_row_on_applied_knob(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={"RISK_BAN_THRESHOLD": 75},
                                     cookies={proxy_module._SESSION_COOKIE: cookie},
                                     headers=_csrf_hdr(proxy_module, cookie))
                    assert r.status == 200
                    d = await r.json()
                    assert "RISK_BAN_THRESHOLD" in d.get("applied", {}), \
                        "precondition: RISK_BAN_THRESHOLD must be applied"
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="config_change")
                    assert len(rows) >= 1, \
                        "config POST must write at least one gw_audit row"
        _run(go())

    def test_audit_actor_matches_logged_in_user(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    await c.post(NS + "/config",
                                 json={"RATE_LIMIT_BURST": 30},
                                 cookies={proxy_module._SESSION_COOKIE: cookie},
                                 headers=_csrf_hdr(proxy_module, cookie))
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="config_change")
                    assert rows, "expected audit row"
                    assert rows[0]["actor"] == "admin", \
                        f"audit actor must be 'admin', got {rows[0]['actor']!r}"
        _run(go())

    def test_audit_detail_has_key_old_new(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    await c.post(NS + "/config",
                                 json={"RATE_LIMIT_BURST": 42},
                                 cookies={proxy_module._SESSION_COOKIE: cookie},
                                 headers=_csrf_hdr(proxy_module, cookie))
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="config_change")
                    assert rows, "expected at least one config_change audit row"
                    detail = json.loads(rows[0]["details"])
                    assert "key" in detail, "audit detail must have 'key'"
                    assert "old" in detail, "audit detail must have 'old'"
                    assert "new" in detail, "audit detail must have 'new'"
                    assert detail["key"] == "RATE_LIMIT_BURST"
                    assert detail["new"] == 42
        _run(go())

    def test_multiple_knobs_produce_multiple_rows(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={"RATE_LIMIT_BURST": 25, "IP_BURST": 40},
                                     cookies={proxy_module._SESSION_COOKIE: cookie},
                                     headers=_csrf_hdr(proxy_module, cookie))
                    n_applied = len((await r.json()).get("applied", {}))
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="config_change")
                    assert len(rows) == n_applied, (
                        f"expected {n_applied} audit rows (one per knob), got {len(rows)}"
                    )
        _run(go())

    def test_rejected_knob_writes_no_audit_row(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={"TOTALLY_FAKE_KNOB_XYZ_999": True},
                                     cookies={proxy_module._SESSION_COOKIE: cookie},
                                     headers=_csrf_hdr(proxy_module, cookie))
                    d = await r.json()
                    assert "TOTALLY_FAKE_KNOB_XYZ_999" in d.get("rejected", {}), \
                        "precondition: unknown knob must be rejected"
                    await asyncio.sleep(0.2)
                    rows = _audit_rows(proxy_module, action="config_change")
                    assert len(rows) == 0, \
                        "rejected knob must not produce any audit row"
        _run(go())


# ── F6–F10: vhosts_endpoint audit writes ──────────────────────────────────────

class TestF2VhostsEndpointAudit:
    """vhosts_endpoint POST/DELETE must write to gw_audit."""

    _SAFE_UPSTREAM = "https://httpbin.org"

    def test_vhost_post_writes_vhost_set_row(self, proxy_module):
        async def go():
            import vhost as _v
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(
                        NS + "/vhosts",
                        json={"hostname": "audit-post.example.com",
                              "UPSTREAM": self._SAFE_UPSTREAM},
                        headers=_csrf_hdr(proxy_module, {proxy_module._SESSION_COOKIE: cookie}),
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200, f"POST /vhosts returned {r.status}"
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="vhost_set")
                    assert rows, "vhost POST must write action=vhost_set audit row"
            _v.VHOSTS.pop("audit-post.example.com", None)
        _run(go())

    def test_vhost_post_audit_actor(self, proxy_module):
        async def go():
            import vhost as _v
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    await c.post(
                        NS + "/vhosts",
                        json={"hostname": "actor-post.example.com",
                              "UPSTREAM": self._SAFE_UPSTREAM},
                        headers=_csrf_hdr(proxy_module, {proxy_module._SESSION_COOKIE: cookie}),
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="vhost_set")
                    assert rows, "expected vhost_set audit row"
                    assert rows[0]["actor"] == "admin", \
                        f"vhost POST audit actor must be 'admin', got {rows[0]['actor']!r}"
            _v.VHOSTS.pop("actor-post.example.com", None)
        _run(go())

    def test_vhost_post_audit_detail_has_hostname(self, proxy_module):
        async def go():
            import vhost as _v
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    await c.post(
                        NS + "/vhosts",
                        json={"hostname": "detail-post.example.com",
                              "UPSTREAM": self._SAFE_UPSTREAM},
                        headers=_csrf_hdr(proxy_module, {proxy_module._SESSION_COOKIE: cookie}),
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="vhost_set")
                    assert rows
                    detail = json.loads(rows[0]["details"])
                    assert detail.get("hostname") == "detail-post.example.com", \
                        f"audit detail must contain hostname; got {detail}"
            _v.VHOSTS.pop("detail-post.example.com", None)
        _run(go())

    def test_vhost_delete_writes_vhost_delete_row(self, proxy_module):
        async def go():
            import vhost as _v
            _v.VHOSTS["del-audit.example.com"] = {
                "UPSTREAM": self._SAFE_UPSTREAM
            }
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.delete(
                        NS + "/vhosts",
                        json={"hostname": "del-audit.example.com"},
                        headers=_csrf_hdr(proxy_module, {proxy_module._SESSION_COOKIE: cookie}),
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200, f"DELETE /vhosts returned {r.status}"
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="vhost_delete")
                    assert rows, "vhost DELETE must write action=vhost_delete audit row"
        _run(go())

    def test_vhost_delete_audit_actor(self, proxy_module):
        async def go():
            import vhost as _v
            _v.VHOSTS["delactor.example.com"] = {"UPSTREAM": self._SAFE_UPSTREAM}
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    await c.delete(
                        NS + "/vhosts",
                        json={"hostname": "delactor.example.com"},
                        headers=_csrf_hdr(proxy_module, {proxy_module._SESSION_COOKIE: cookie}),
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="vhost_delete")
                    assert rows
                    assert rows[0]["actor"] == "admin", \
                        f"vhost DELETE audit actor must be 'admin', got {rows[0]['actor']!r}"
        _run(go())

    def test_vhost_delete_audit_detail_has_hostname(self, proxy_module):
        async def go():
            import vhost as _v
            _v.VHOSTS["deldetail.example.com"] = {"UPSTREAM": self._SAFE_UPSTREAM}
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    await c.delete(
                        NS + "/vhosts",
                        json={"hostname": "deldetail.example.com"},
                        headers=_csrf_hdr(proxy_module, {proxy_module._SESSION_COOKIE: cookie}),
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="vhost_delete")
                    assert rows
                    detail = json.loads(rows[0]["details"])
                    assert detail.get("hostname") == "deldetail.example.com"
        _run(go())


# ── F11–F13: settings_import audit writes ─────────────────────────────────────

class TestF3SettingsImportAudit:
    """settings_import_endpoint must write to gw_audit only when not dry_run."""

    def test_non_dry_run_writes_settings_import_row(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    zip_data = _make_config_zip({"RATE_LIMIT_BURST": 22})
                    r = await c.post(
                        NS + "/settings-import",
                        data=zip_data,
                        headers={"Content-Type": "application/zip"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    assert (await r.json())["dry_run"] is False
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="settings_import")
                    assert rows, \
                        "non-dry-run import must write action=settings_import audit row"
        _run(go())

    def test_dry_run_writes_no_audit_row(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    zip_data = _make_config_zip({"RATE_LIMIT_BURST": 24})
                    r = await c.post(
                        NS + "/settings-import?dry_run=1",
                        data=zip_data,
                        headers={"Content-Type": "application/zip"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    assert (await r.json())["dry_run"] is True
                    await asyncio.sleep(0.2)
                    rows = _audit_rows(proxy_module, action="settings_import")
                    assert len(rows) == 0, \
                        "dry_run=1 must NOT write any gw_audit row"
        _run(go())

    def test_import_audit_detail_has_knobs_applied(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    zip_data = _make_config_zip({"RATE_LIMIT_BURST": 23, "IP_BURST": 35})
                    await c.post(
                        NS + "/settings-import",
                        data=zip_data,
                        headers={"Content-Type": "application/zip"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    await asyncio.sleep(0.3)
                    rows = _audit_rows(proxy_module, action="settings_import")
                    assert rows, "expected settings_import audit row"
                    detail = json.loads(rows[0]["details"])
                    assert "knobs_applied" in detail, \
                        "audit detail must contain knobs_applied count"
                    assert detail["knobs_applied"] >= 1
        _run(go())


# ── F14–F24: audit_log_endpoint ───────────────────────────────────────────────

class TestF4AuditLogEndpoint:
    """GET /secured/audit-log must filter, page, and return correct structure."""

    def test_authenticated_returns_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/audit-log",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_unauthenticated_does_not_leak_audit_data(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_audit(proxy_module, action="supersecret_event")
                    r = await c.get(NS + "/audit-log")
                    body = await r.text()
                    assert "supersecret_event" not in body, \
                        "unauthenticated /audit-log must not expose audit data"
        _run(go())

    def test_response_has_rows_and_count_keys(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(
                        NS + "/audit-log",
                        cookies={proxy_module._SESSION_COOKIE: cookie}
                    )).json()
                    assert "rows" in d and "count" in d
                    assert isinstance(d["rows"], list)
                    assert isinstance(d["count"], int)
        _run(go())

    def test_count_equals_rows_length(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_audit(proxy_module, action="count_test")
                    _seed_audit(proxy_module, action="count_test")
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(
                        NS + "/audit-log",
                        cookies={proxy_module._SESSION_COOKIE: cookie}
                    )).json()
                    assert d["count"] == len(d["rows"]), \
                        f"count {d['count']} must equal len(rows) {len(d['rows'])}"
        _run(go())

    def test_action_substring_filter(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_audit(proxy_module, action="config_change")
                    _seed_audit(proxy_module, action="vhost_set")
                    _seed_audit(proxy_module, action="vhost_delete")
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(
                        NS + "/audit-log?action=vhost",
                        cookies={proxy_module._SESSION_COOKIE: cookie}
                    )).json()
                    actions = {row["action"] for row in d["rows"]}
                    assert "config_change" not in actions, \
                        "?action=vhost must exclude config_change"
                    assert all("vhost" in a for a in actions), \
                        "?action=vhost must only return rows containing 'vhost'"
        _run(go())

    def test_actor_exact_filter(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_audit(proxy_module, actor="alice")
                    _seed_audit(proxy_module, actor="bob")
                    _seed_audit(proxy_module, actor="alice")
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(
                        NS + "/audit-log?actor=alice",
                        cookies={proxy_module._SESSION_COOKIE: cookie}
                    )).json()
                    assert d["count"] == 2, \
                        f"?actor=alice must return 2 rows, got {d['count']}"
                    assert all(r["actor"] == "alice" for r in d["rows"])
        _run(go())

    def test_actor_filter_excludes_others(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_audit(proxy_module, actor="alice")
                    _seed_audit(proxy_module, actor="bob")
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(
                        NS + "/audit-log?actor=bob",
                        cookies={proxy_module._SESSION_COOKIE: cookie}
                    )).json()
                    assert d["count"] == 1
                    assert d["rows"][0]["actor"] == "bob"
        _run(go())

    def test_limit_restricts_result_count(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    for _ in range(5):
                        _seed_audit(proxy_module, action="limit_test")
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(
                        NS + "/audit-log?limit=2",
                        cookies={proxy_module._SESSION_COOKIE: cookie}
                    )).json()
                    assert d["count"] <= 2, \
                        f"?limit=2 must return at most 2 rows, got {d['count']}"
        _run(go())

    def test_since_excludes_old_rows(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    now = time.time()
                    _seed_audit(proxy_module, action="old_event", ts=now - 3600)
                    _seed_audit(proxy_module, action="new_event", ts=now + 1)
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(
                        NS + f"/audit-log?since={now - 60}",
                        cookies={proxy_module._SESSION_COOKIE: cookie}
                    )).json()
                    actions = {r["action"] for r in d["rows"]}
                    assert "old_event" not in actions, \
                        "?since= must exclude rows older than the cutoff"
                    assert "new_event" in actions, \
                        "?since= must include rows newer than the cutoff"
        _run(go())

    def test_details_returned_as_json_object(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_audit(proxy_module, details={"nested": {"key": "value"}})
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(
                        NS + "/audit-log",
                        cookies={proxy_module._SESSION_COOKIE: cookie}
                    )).json()
                    assert d["rows"], "expected at least one row"
                    det = d["rows"][0]["details"]
                    assert isinstance(det, dict), \
                        f"details must be a JSON object, got {type(det).__name__}"
        _run(go())

    def test_invalid_limit_returns_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/audit-log?limit=notanumber",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "rows" in d, "must return rows even with invalid limit"
        _run(go())

    def test_oversized_limit_returns_200(self, proxy_module):
        """?limit=9999 must not error — it is silently capped at 1000."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/audit-log?limit=9999",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_row_has_all_expected_fields(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_audit(proxy_module, action="field_check", actor="tester")
                    cookie = _make_admin_cookie(proxy_module)
                    d = await (await c.get(
                        NS + "/audit-log",
                        cookies={proxy_module._SESSION_COOKIE: cookie}
                    )).json()
                    assert d["rows"]
                    row = d["rows"][0]
                    for field in ("id", "ts", "action", "gw_id", "actor", "details"):
                        assert field in row, f"audit row missing field '{field}'"
        _run(go())


# ── R1–R11: source-level regression guards ────────────────────────────────────

class TestRSourceGuards:
    """Structural source-code checks — verify key implementation invariants."""

    def _src(self, *parts):
        return (ROOT.joinpath(*parts)).read_text()

    # ── db/postgres.py ────────────────────────────────────────────────────────

    def test_postgres_has_gw_audit_add_case(self):
        src = self._src("db", "postgres.py")
        assert 'op == "gw_audit_add"' in src, \
            "db/postgres.py _pg_mirror_kv must handle 'gw_audit_add' op"

    def test_postgres_gw_audit_add_uses_percent_s_placeholders(self):
        src = self._src("db", "postgres.py")
        pos = src.find('op == "gw_audit_add"')
        assert pos != -1
        block = src[pos:pos + 300]
        assert "%s" in block, \
            "postgres gw_audit INSERT must use %s placeholders, not ?"
        assert "?" not in block.split("gw_audit")[1][:100], \
            "postgres gw_audit INSERT must NOT use SQLite-style ? placeholders"

    # ── db/sqlite.py ──────────────────────────────────────────────────────────

    def test_sqlite_calls_pg_mirror_after_gw_audit_insert(self):
        src = self._src("db", "sqlite.py")
        audit_pos = src.find('"gw_audit_add"')
        assert audit_pos != -1
        block = src[audit_pos:audit_pos + 400]
        assert '_pg_mirror_kv("gw_audit_add"' in block, \
            "db/sqlite.py must call _pg_mirror_kv('gw_audit_add', args) " \
            "after the SQLite INSERT"

    # ── core/proxy_handler.py ─────────────────────────────────────────────────

    def test_config_endpoint_captures_old_v_before_assignment(self):
        import core.proxy_handler as _ph
        src = inspect.getsource(_ph.config_endpoint)
        old_pos = src.find("old_v = g.get(k)")
        assign_pos = src.find("g[k] = value")
        assert old_pos != -1, \
            "config_endpoint must capture 'old_v = g.get(k)'"
        assert old_pos < assign_pos, \
            "old_v must be captured BEFORE 'g[k] = value'"

    def test_config_endpoint_enqueues_gw_audit_add(self):
        import core.proxy_handler as _ph
        src = inspect.getsource(_ph.config_endpoint)
        assert '"gw_audit_add"' in src, \
            "config_endpoint must enqueue 'gw_audit_add' to db_queue"

    def test_config_endpoint_slog_includes_actor_kwarg(self):
        import core.proxy_handler as _ph
        src = inspect.getsource(_ph.config_endpoint)
        slog_pos = src.find('slog("config_changed"')
        assert slog_pos != -1, "config_endpoint must call slog('config_changed')"
        slog_block = src[slog_pos:slog_pos + 250]
        assert "actor=" in slog_block, \
            "slog('config_changed') must include 'actor=' keyword argument"

    # ── admin/settings.py ─────────────────────────────────────────────────────

    def test_vhost_post_calls_gw_audit_after_slog(self):
        src = self._src("admin", "settings.py")
        slog_pos = src.find('slog("vhost_set"')
        assert slog_pos != -1
        block = src[slog_pos:slog_pos + 400]
        assert "_gw_audit(" in block, \
            "vhosts_endpoint POST must call _gw_audit() near slog('vhost_set')"

    def test_vhost_delete_calls_gw_audit_after_slog(self):
        src = self._src("admin", "settings.py")
        slog_pos = src.find('slog("vhost_delete"')
        assert slog_pos != -1
        block = src[slog_pos:slog_pos + 400]
        assert "_gw_audit(" in block, \
            "vhosts_endpoint DELETE must call _gw_audit() near slog('vhost_delete')"

    def test_settings_import_gw_audit_guarded_by_not_dry_run(self):
        src = self._src("admin", "settings.py")
        fn_start = src.find("async def settings_import_endpoint")
        assert fn_start != -1, "settings_import_endpoint not found in settings.py"
        next_fn = src.find("\nasync def ", fn_start + 1)
        fn_block = src[fn_start:next_fn] if next_fn != -1 else src[fn_start:]
        audit_pos = fn_block.rfind("_gw_audit(")
        assert audit_pos != -1, \
            "settings_import_endpoint must call _gw_audit()"
        guard_pos = fn_block.rfind("not dry_run")
        assert guard_pos != -1, \
            "settings_import_endpoint must check 'not dry_run' before writing audit"
        assert guard_pos < audit_pos, \
            "'not dry_run' guard must appear before the _gw_audit() call"

    def test_audit_log_where_clauses_no_user_input_interpolation(self):
        src = self._src("admin", "settings.py")
        fn_start = src.find("async def audit_log_endpoint")
        assert fn_start != -1, "audit_log_endpoint not found in settings.py"
        next_fn = src.find("\nasync def ", fn_start + 1)
        fn_block = src[fn_start:next_fn] if next_fn != -1 else src[fn_start:]
        # User inputs must go into params list, never into where_clauses strings
        assert "params.append" in fn_block, \
            "user filter inputs must be appended to params list (parameterized)"
        # The f-string that builds WHERE must use where_sql (built from safe literals)
        assert "where_sql" in fn_block, \
            "final SQL must use where_sql variable, not raw user input"
        # where_clauses.append must only contain string literals — no action_filter/actor_filter
        for line in fn_block.splitlines():
            stripped = line.strip()
            if stripped.startswith("where_clauses.append("):
                assert "action_filter" not in stripped and "actor_filter" not in stripped, \
                    f"where_clauses must only append string literals, not user vars: {stripped}"

    def test_audit_log_limit_capped_at_1000_in_source(self):
        src = self._src("admin", "settings.py")
        fn_start = src.find("async def audit_log_endpoint")
        fn_block = src[fn_start:fn_start + 2000]
        assert "min(1000," in fn_block or "min(1000" in fn_block, \
            "audit_log_endpoint must cap limit at 1000 via min()"

    def test_audit_log_endpoint_registered_in_proxy(self):
        src = self._src("proxy.py")
        assert "audit_log_endpoint" in src, \
            "audit_log_endpoint must appear in proxy.py"
        assert '"audit-log"' in src, \
            "'audit-log' URL suffix must be in proxy.py route table"
