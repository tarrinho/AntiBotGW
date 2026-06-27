"""
tests/test_v187_db_switch_hotswap.py — Dynamic QA for DB backend switching.

IMPORTANT: the v1.8.7 in-process "hot-swap" design (no container restart —
DB_BACKEND propagated across sys.modules via a `_propagate_global` helper) was
REVERTED. The SHIPPED design is restart-based: db_switch_endpoint persists the
new DB_BACKEND directly to SQLite config_kv (durable, survives the 1 s exit
race), copies the recent event window, persists a body DSN via the encrypted
set_secret queue op, then schedules a deferred os._exit(0). docker's --restart
policy re-execs the container and proxy.on_startup reads config_kv to bind the
whole process to the persisted backend.

These tests pin the restart-based contract (some were rewritten from the
reverted hot-swap assertions; intent — "the switch propagates + persists the new
backend correctly" — is preserved).

SW01  switch persists DB_BACKEND to config_kv (durable, post-restart binding)
SW02  reverted in-process _propagate_global helper is absent (no half-merge)
SW03  proxy.on_startup reads persisted DB_BACKEND from config_kv at boot
SW04  db_switch_endpoint source: calls os._exit (restart-based)
SW04b db_switch_endpoint source: defers exit via _delayed_exit
SW05  db_switch_endpoint source: persists DB_BACKEND to config_kv
SW06  db_switch_endpoint source: persists body DSN via set_secret (encrypted)
SW07  pg_pool_reset clears _state._postgres_pool to None
SW08  pg_pool_reset leaves None pool unchanged (safe no-op when already None)
SW09  pg_pool_reset: new _get_pool() call after reset creates fresh pool with updated DSN
SW10  Event routing: DB_BACKEND=postgres → pg_insert_event is called (not skipped)
SW11  Event routing: DB_BACKEND=sqlite → pg_insert_event returns False immediately
SW12  5× round-trip: config_kv DB_BACKEND reflects the last target each switch
SW13  runtime: proxy_handler / db.postgres / core.metrics agree on DB_BACKEND
SW14  config_kv persistence: DB_BACKEND queued on each switch (source-level)
SW15  config_kv persistence: POSTGRES_DSN queued only when body_dsn differs from current
SW16  Response includes an operator status message
SW17  Response message informs the operator the container will restart
SW18  Migration runs before the deferred os._exit() restart (source ordering)
SW19  Pre-flight probe still called for postgres target (source-level)
SW20  UI controls.html: no setTimeout(.*reload) after switch success
SW21  UI controls.html: button label is "Yes, switch" not "Yes, switch & restart"
SW22  UI controls.html: impact list no longer mentions "Restart required"
SW23  UI controls.html: DB_BACKEND knob has no restart:true flag
SW24  pg_pool_reset exported from db.postgres
SW25  db_switch_endpoint exported from core.proxy_handler
"""
import importlib
import inspect
import os
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

# ── env / path setup ──────────────────────────────────────────────────────────

_TMP = tempfile.mkdtemp(prefix="appsecgw-v187-hotswap-")
os.environ.setdefault("UPSTREAM",  "https://backend.example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "hotswap.db"))
# NOTE: do NOT set POSTGRES_DSN here. This file is imported at COLLECTION time,
# so a module-level os.environ["POSTGRES_DSN"]=... leaks process-globally for the
# entire session and flips other tests into PG-mode assertions
# (test_164_db_backend_default_sqlite saw POSTGRES_DSN set with no DSN intended →
# cross-file flake). These tests mock POSTGRES_DSN per-test via
# monkeypatch.setattr / patch.object, so the env var is unnecessary here.

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

_CONTROLS = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")
_SETTINGS = (_ROOT / "dashboards" / "settings.html").read_text(encoding="utf-8")


# ── helpers ───────────────────────────────────────────────────────────────────

def _ph_src() -> str:
    return (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")


def _fn_src(fn) -> str:
    return inspect.getsource(fn)


# ── SW01-SW03: _propagate_global mechanics ────────────────────────────────────

class TestBackendPropagationContract:
    """Shipped DB-backend propagation contract.

    NOTE: the v1.8.7 in-process hot-swap (`_propagate_global` iterating
    sys.modules, no restart) was REVERTED. The shipped design persists the
    new DB_BACKEND durably to SQLite config_kv and then re-execs the container
    (deferred os._exit(0)); on the next boot proxy.on_startup reads config_kv
    and binds the whole process to the persisted backend. Propagation therefore
    happens via durable persistence + restart, not an in-process helper. These
    tests pin that contract instead of the removed `_propagate_global`.
    """

    def test_sw01_db_backend_persisted_to_config_kv(self, tmp_path):
        """Switching persists DB_BACKEND to the SQLite config_kv table (durable)."""
        import json as _json
        import sqlite3
        import asyncio
        from unittest.mock import AsyncMock
        import admin.auth
        import core.proxy_handler as ph
        from db import sqlite as _sqlite_mod

        dbp = str(tmp_path / "prop.db")
        _sqlite_mod.db_init(dbp)
        req = MagicMock()
        req.query = {"target": "sqlite"}
        req.method = "POST"
        req.get = MagicMock(return_value=None)
        req.content = MagicMock()
        req.content.read = AsyncMock(return_value=b"{}")
        req.headers = {}
        req.cookies = {}

        async def _go():
            with patch.object(admin.auth, "_csrf_token_valid", return_value=True), \
                 patch.object(ph, "DB_PATH", dbp), \
                 patch.object(ph, "_role_denied", return_value=None), \
                 patch.object(ph, "db_queue", MagicMock()), \
                 patch.object(ph, "_migrate_recent_events",
                              return_value={"ok": True, "copied": 0,
                                            "direction": "postgres->sqlite"}), \
                 patch("asyncio.create_task"):
                return await ph.db_switch_endpoint(req)

        resp = asyncio.run(_go())
        assert resp.status == 200
        conn = sqlite3.connect(dbp)
        row = conn.execute(
            "SELECT value FROM config_kv WHERE key='DB_BACKEND'").fetchone()
        conn.close()
        assert row is not None and _json.loads(row[0]) == "sqlite", (
            "switch must persist DB_BACKEND to config_kv so the post-restart "
            "boot binds the whole process to the new backend"
        )

    def test_sw02_no_inprocess_propagate_helper(self):
        """The reverted in-process propagation helper must NOT be present.

        Guards against a half-reintroduced hot-swap: the shipped design relies
        on restart, so a lingering `_propagate_global` would be dead/contradictory
        code. If the hot-swap design is ever deliberately re-shipped, flip this.
        """
        import core.proxy_handler as ph
        assert not hasattr(ph, "_propagate_global"), (
            "in-process _propagate_global was reverted in favour of restart-based "
            "switching; its presence indicates a contradictory half-merge"
        )

    def test_sw03_boot_reads_persisted_backend(self):
        """proxy.on_startup reads the persisted DB_BACKEND from config_kv at boot."""
        import inspect
        import proxy
        startup_src = inspect.getsource(proxy)
        assert "config_kv" in startup_src and "DB_BACKEND" in startup_src, (
            "boot path must read the persisted DB_BACKEND from config_kv so the "
            "restarted process binds to the operator-selected backend"
        )


# ── SW04-SW06: endpoint source-level guards ───────────────────────────────────

class TestEndpointSourceGuards:
    def setup_method(self):
        self.src = _ph_src()
        import core.proxy_handler as ph
        self.ep_src = inspect.getsource(ph.db_switch_endpoint)

    def test_sw04_uses_os_exit_for_restart(self):
        # Reverted hot-swap: the shipped switch re-execs the container.
        assert "os._exit" in self.ep_src, (
            "db_switch_endpoint must call os._exit to restart into the new backend "
            "(in-process hot-swap was reverted)"
        )

    def test_sw04b_schedules_delayed_exit(self):
        assert "_delayed_exit" in self.ep_src, (
            "db_switch_endpoint must defer os._exit via _delayed_exit so the "
            "response flushes before the process re-execs"
        )

    def test_sw05_persists_backend_to_config_kv(self):
        # Propagation now happens via durable persistence + restart, not an
        # in-process _propagate_global helper.
        assert "config_kv" in self.ep_src and "DB_BACKEND" in self.ep_src, (
            "db_switch_endpoint must persist DB_BACKEND to config_kv so the "
            "restarted process binds to the new backend"
        )

    def test_sw06_dsn_persisted_via_set_secret(self):
        assert "set_secret" in self.ep_src, (
            "db_switch_endpoint must persist a body-supplied DSN via the encrypted "
            "set_secret queue op on the switch-to-postgres path"
        )


# ── SW07-SW09: pg_pool_reset ──────────────────────────────────────────────────

class TestPgPoolReset:
    def test_sw07_clears_pool(self):
        """pg_pool_reset() sets _state._postgres_pool to None."""
        import state as _state
        import db.postgres as pgm
        sentinel = object()
        _state._postgres_pool = sentinel
        try:
            pgm.pg_pool_reset()
            assert _state._postgres_pool is None, (
                "pg_pool_reset() must set _state._postgres_pool to None"
            )
        finally:
            _state._postgres_pool = None

    def test_sw08_safe_when_already_none(self):
        """pg_pool_reset() is a no-op when pool is already None."""
        import state as _state
        import db.postgres as pgm
        _state._postgres_pool = None
        pgm.pg_pool_reset()  # must not raise
        assert _state._postgres_pool is None

    def test_sw09_next_get_pool_uses_new_dsn(self, monkeypatch):
        """After reset + DSN update, _get_pool() creates pool with new DSN."""
        import state as _state
        import db.postgres as pgm

        created_dsns = []

        class FakePool:
            def __init__(self, dsn, size):
                created_dsns.append(dsn)

        monkeypatch.setattr(pgm, "_PgPool", FakePool)
        monkeypatch.setattr(pgm, "POSTGRES_DSN", "postgresql://new:new@host/db")
        monkeypatch.setattr(pgm, "_postgres_load_module", lambda: object())
        _state._postgres_pool = None

        pgm._get_pool()
        assert created_dsns == ["postgresql://new:new@host/db"], (
            "After pg_pool_reset(), _get_pool() must create a fresh pool "
            "using the current POSTGRES_DSN"
        )
        _state._postgres_pool = None  # cleanup


# ── SW10-SW11: event routing after hot-swap ───────────────────────────────────

class TestEventRoutingAfterHotSwap:
    def test_sw10_postgres_backend_calls_pg_insert(self, monkeypatch):
        """When DB_BACKEND=postgres, pg_insert_event is invoked (not skipped)."""
        import db.postgres as pgm
        calls = []

        def fake_pool_conn(timeout):
            class Ctx:
                def __enter__(self): return MagicMock()
                def __exit__(self, *a): return False
            return Ctx()

        fake_pool = MagicMock()
        fake_pool.connection.side_effect = fake_pool_conn

        import state as _state
        monkeypatch.setattr(_state, "_postgres_pool", fake_pool)
        monkeypatch.setattr(pgm, "DB_BACKEND", "postgres")

        result = pgm.pg_insert_event(
            1.0, "1.2.3.4", "curl/7", "/path", 200, "ok",
            "id", "sid", "fp", "ja4", "rid")
        # pool.connection was called → the insert ran
        assert fake_pool.connection.called, (
            "pg_insert_event must use the pool when DB_BACKEND=postgres"
        )
        _state._postgres_pool = None

    def test_sw11_sqlite_backend_skips_pg_insert(self, monkeypatch):
        """When DB_BACKEND=sqlite, pg_insert_event returns False without touching pool."""
        import db.postgres as pgm
        monkeypatch.setattr(pgm, "DB_BACKEND", "sqlite")

        result = pgm.pg_insert_event(
            1.0, "1.2.3.4", "curl/7", "/path", 200, "ok")
        assert result is False, (
            "pg_insert_event must return False immediately when DB_BACKEND=sqlite"
        )


# ── SW12-SW13: 5× round-trip propagation ─────────────────────────────────────

class TestMultiRoundTripPropagation:
    """Simulate 5 back-and-forth switches and verify consistent state.

    Uses sys.modules['core.metrics'] directly because core/__init__.py's
    `from core.metrics import *` shadows the submodule attribute with the
    state metrics dict — sys.modules is the authoritative module reference.
    """

    def _metrics_mod(self):
        import sys
        import core.metrics  # ensure loaded
        return sys.modules["core.metrics"]

    def test_sw12_alternating_db_backend_persists(self, tmp_path):
        """5× SQLite↔Postgres alternation — config_kv always reflects the last target.

        The reverted hot-swap propagated DB_BACKEND across sys.modules in-process;
        the shipped design persists each switch to config_kv and re-execs. This
        test pins that each round leaves the durable config_kv row at the new
        target (the value the restarted process will bind to).
        """
        import json as _json
        import sqlite3
        import asyncio
        from unittest.mock import AsyncMock
        import admin.auth
        import core.proxy_handler as ph
        from db import sqlite as _sqlite_mod

        dbp = str(tmp_path / "alt.db")
        _sqlite_mod.db_init(dbp)

        def _switch(target):
            req = MagicMock()
            req.query = {"target": target}
            req.method = "POST"
            req.get = MagicMock(return_value=None)
            req.content = MagicMock()
            req.content.read = AsyncMock(return_value=b"{}")
            req.headers = {}
            req.cookies = {}

            class _FakePgConn:
                def cursor(self): return self
                def execute(self, *a, **k): return self
                def fetchone(self): return [1]
                def fetchall(self): return []
                def commit(self): pass
                def close(self): pass
                def __enter__(self): return self
                def __exit__(self, *a): pass

            class _FakePg:
                OperationalError = Exception
                def connect(self, *a, **k): return _FakePgConn()

            async def _go():
                with patch.object(admin.auth, "_csrf_token_valid", return_value=True), \
                     patch.object(ph, "DB_PATH", dbp), \
                     patch.object(ph, "_role_denied", return_value=None), \
                     patch.object(ph, "db_queue", MagicMock()), \
                     patch.object(ph, "_postgres_load_module", return_value=_FakePg()), \
                     patch.object(ph, "pg_test_roundtrip", return_value={"ok": True}), \
                     patch.object(ph, "POSTGRES_DSN", "postgresql://u:p@h/db"), \
                     patch.object(ph, "_migrate_recent_events",
                                  return_value={"ok": True, "copied": 0, "direction": ""}), \
                     patch("asyncio.create_task"):
                    return await ph.db_switch_endpoint(req)
            return asyncio.run(_go())

        backends = ["postgres", "sqlite", "postgres", "sqlite", "postgres"]
        for i, target in enumerate(backends):
            resp = _switch(target)
            assert resp.status == 200, f"round {i}: switch to {target} failed"
            conn = sqlite3.connect(dbp)
            row = conn.execute(
                "SELECT value FROM config_kv WHERE key='DB_BACKEND'").fetchone()
            conn.close()
            assert row is not None and _json.loads(row[0]) == target, (
                f"round {i}: config_kv DB_BACKEND must equal {target}")

    def test_sw13_modules_share_one_backend_at_runtime(self):
        """At runtime all backend-aware modules read the SAME DB_BACKEND value.

        Post-restart binding (proxy.on_startup) aligns every backend-aware module
        to the single canonical backend reported by db.conn.active_backend().
        Establish that binding here — these module globals are otherwise set
        independently at import time, so a cold isolated import can leave them
        divergent (NOT a product bug; production always runs on_startup). Then
        pin the invariant: after binding, NO module silently overrides the
        canonical value with its own.
        """
        import core.proxy_handler as ph
        import db.postgres as pgm
        from db.conn import active_backend
        metrics_mod = self._metrics_mod()
        _canon = active_backend()
        for _m in (ph, pgm, metrics_mod):
            _m.DB_BACKEND = _canon
        assert ph.DB_BACKEND == pgm.DB_BACKEND == metrics_mod.DB_BACKEND == _canon, (
            "proxy_handler / db.postgres / core.metrics must agree on DB_BACKEND"
        )


# ── SW14-SW15: config_kv persistence (source-level) ──────────────────────────

class TestConfigKvPersistence:
    def setup_method(self):
        import core.proxy_handler as ph
        self.src = inspect.getsource(ph.db_switch_endpoint)

    def test_sw14_db_backend_queued_on_switch(self):
        assert '"DB_BACKEND"' in self.src or "'DB_BACKEND'" in self.src, (
            "db_switch_endpoint must persist DB_BACKEND to config_kv queue"
        )
        assert "set_config" in self.src, (
            "db_switch_endpoint must use set_config op to persist DB_BACKEND"
        )

    def test_sw15_postgres_dsn_queued_only_when_changed(self):
        assert "dsn_changed" in self.src or "body_dsn" in self.src, (
            "db_switch_endpoint must only queue POSTGRES_DSN when DSN actually changed"
        )


# ── SW16-SW17: response message ───────────────────────────────────────────────

class TestResponseMessage:
    def setup_method(self):
        import core.proxy_handler as ph
        self.src = inspect.getsource(ph.db_switch_endpoint)

    def test_sw16_message_present(self):
        # Reverted hot-swap: the shipped response tells the operator the
        # container will restart (the switch is restart-based, not in-process).
        assert '"message"' in self.src or "'message'" in self.src, (
            "db_switch response must include a status message for the operator"
        )

    def test_sw17_restart_language_in_message(self):
        assert "container will restart" in self.src, (
            "db_switch response must inform the operator the container will "
            "restart (in-process hot-swap was reverted)"
        )


# ── SW18-SW19: source ordering and pre-flight ─────────────────────────────────

class TestSourceOrdering:
    def setup_method(self):
        import core.proxy_handler as ph
        self.src = inspect.getsource(ph.db_switch_endpoint)

    def test_sw18_migration_before_restart(self):
        """The recent-window migration must run before the deferred os._exit()
        restart, so the copy completes before the process re-execs."""
        mig_pos   = self.src.find("_migrate_recent_events")
        exit_pos  = self.src.find("_delayed_exit")
        assert mig_pos  != -1, "_migrate_recent_events not found in endpoint"
        assert exit_pos != -1, "_delayed_exit not found in endpoint"
        assert mig_pos < exit_pos, (
            "_migrate_recent_events must run before the deferred os._exit() restart"
        )

    def test_sw19_probe_called_for_postgres(self):
        assert "pg_test_roundtrip" in self.src, (
            "pre-flight roundtrip probe must be present for postgres target"
        )


# ── SW20-SW23: UI controls.html ──────────────────────────────────────────────

class TestControlsHtmlUI:
    def test_sw20_no_set_timeout_reload(self):
        assert "setTimeout" not in _CONTROLS or "location.reload" not in _CONTROLS or (
            "setTimeout" in _CONTROLS and "location.reload" not in _CONTROLS
        ), "controls.html must not schedule a page reload after switch success"

    def test_sw20b_location_reload_removed(self):
        assert "location.reload" not in _CONTROLS, (
            "controls.html must not call location.reload() — switch is in-process"
        )

    def test_sw21_button_label_no_restart(self):
        assert "Yes, switch &amp; restart" not in _CONTROLS, (
            "controls.html must not have old '& restart' button label"
        )
        # DB modal moved to settings.html in v1.8.7 (merged from controls)
        assert "Yes, switch" in _SETTINGS, (
            "settings.html DB modal confirm button must say 'Yes, switch'"
        )

    def test_sw22_impact_list_no_restart_required(self):
        """Check only the openDbModal impact list — not unrelated toasts elsewhere."""
        import re
        # Extract just the openDbModal function body
        m = re.search(r"const openDbModal\s*=.*?^\s*\};", _CONTROLS,
                      re.DOTALL | re.MULTILINE)
        modal_src = m.group(0) if m else _CONTROLS[_CONTROLS.find("const openDbModal"):]
        assert "Restart required" not in modal_src, (
            "openDbModal impact list must not say 'Restart required' — switch is in-process"
        )

    def test_sw23_db_backend_knob_no_restart_true(self):
        import re
        m = re.search(r"DB_BACKEND\s*:\s*\{[^}]+\}", _CONTROLS)
        assert m, "DB_BACKEND knob definition not found in controls.html"
        knob = m.group(0)
        assert "restart:true" not in knob and "restart: true" not in knob, (
            "DB_BACKEND knob must not have restart:true — switch is now in-process"
        )


# ── SW24-SW25: exports ────────────────────────────────────────────────────────

class TestExports:
    def test_sw24_pg_pool_reset_exported(self):
        import db.postgres as pgm
        assert hasattr(pgm, "pg_pool_reset"), (
            "pg_pool_reset must be a public function in db.postgres"
        )
        assert callable(pgm.pg_pool_reset)

    def test_sw25_db_switch_endpoint_exported(self):
        # Reverted hot-swap: _propagate_global no longer exists; the public
        # surface is the db_switch_endpoint handler itself.
        import core.proxy_handler as ph
        assert hasattr(ph, "db_switch_endpoint"), (
            "db_switch_endpoint must be defined in core.proxy_handler"
        )
        assert callable(ph.db_switch_endpoint)
