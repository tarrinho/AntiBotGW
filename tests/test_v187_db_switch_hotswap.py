"""
tests/test_v187_db_switch_hotswap.py — Dynamic QA for hot-swap DB backend switching.

Tests the in-process SQLite ↔ Postgres backend swap introduced in v1.8.7:
no container restart required — DB_BACKEND propagates across all loaded modules
via sys.modules iteration, the Postgres pool is reset on DSN change, and the
SQLite writer loop continues unaffected throughout.

SW01  _propagate_global sets the value in the calling module's globals
SW02  _propagate_global propagates to a second module that has the attribute
SW03  _propagate_global silently skips modules without the attribute
SW04  db_switch_endpoint source: no os._exit / _delayed_exit present
SW05  db_switch_endpoint source: calls _propagate_global (not direct globals assign)
SW06  db_switch_endpoint source: calls pg_pool_reset (on DSN change path)
SW07  pg_pool_reset clears _state._postgres_pool to None
SW08  pg_pool_reset leaves None pool unchanged (safe no-op when already None)
SW09  pg_pool_reset: new _get_pool() call after reset creates fresh pool with updated DSN
SW10  Event routing: DB_BACKEND=postgres → pg_insert_event is called (not skipped)
SW11  Event routing: DB_BACKEND=sqlite → pg_insert_event returns False immediately
SW12  5× round-trip: DB_BACKEND alternates sqlite/postgres across all modules each time
SW13  5× round-trip: each switch leaves DB_BACKEND consistent in metrics and postgres modules
SW14  config_kv persistence: DB_BACKEND queued on each switch (source-level)
SW15  config_kv persistence: POSTGRES_DSN queued only when body_dsn differs from current
SW16  Response message says "active immediately" — no restart language
SW17  Response has no restart message (no "container will restart")
SW18  Migration called before propagation restores globals (source-level ordering)
SW19  Pre-flight probe still called for postgres target (source-level)
SW20  UI controls.html: no setTimeout(.*reload) after switch success
SW21  UI controls.html: button label is "Yes, switch" not "Yes, switch & restart"
SW22  UI controls.html: impact list no longer mentions "Restart required"
SW23  UI controls.html: DB_BACKEND knob has no restart:true flag
SW24  pg_pool_reset exported from db.postgres
SW25  _propagate_global exported from core.proxy_handler
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
os.environ.setdefault("POSTGRES_DSN", "postgresql://test:test@localhost:5432/testdb")

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

class TestPropagateGlobal:
    """_propagate_global must update globals() and all sys.modules members."""

    def _make_fake_module(self, **attrs) -> types.ModuleType:
        m = types.ModuleType("_fake_test_mod")
        for k, v in attrs.items():
            setattr(m, k, v)
        return m

    def test_sw01_sets_value_in_globals(self):
        """After _propagate_global('X', val), globals()['X'] == val in proxy_handler."""
        import core.proxy_handler as ph
        original = getattr(ph, "DB_BACKEND", "sqlite")
        try:
            ph._propagate_global("DB_BACKEND", "postgres")
            assert ph.DB_BACKEND == "postgres", (
                "_propagate_global must update the module's own globals"
            )
        finally:
            ph._propagate_global("DB_BACKEND", original)

    def test_sw02_propagates_to_other_module(self):
        """_propagate_global must set the attr on every sys.modules member that has it."""
        import core.proxy_handler as ph
        fake = self._make_fake_module(DB_BACKEND="sqlite")
        original_ph = ph.DB_BACKEND
        sys.modules["_fake_propagate_target"] = fake
        try:
            ph._propagate_global("DB_BACKEND", "postgres")
            assert fake.DB_BACKEND == "postgres", (
                "_propagate_global must propagate to all sys.modules members"
            )
        finally:
            ph._propagate_global("DB_BACKEND", original_ph)
            sys.modules.pop("_fake_propagate_target", None)

    def test_sw03_skips_modules_without_attr(self):
        """_propagate_global must not raise when a module lacks the attribute."""
        import core.proxy_handler as ph
        no_attr_mod = self._make_fake_module(OTHER_ATTR="unchanged")
        sys.modules["_fake_no_attr"] = no_attr_mod
        try:
            ph._propagate_global("DB_BACKEND", "sqlite")  # no DB_BACKEND on fake mod
            assert no_attr_mod.OTHER_ATTR == "unchanged"  # untouched
        finally:
            sys.modules.pop("_fake_no_attr", None)


# ── SW04-SW06: endpoint source-level guards ───────────────────────────────────

class TestEndpointSourceGuards:
    def setup_method(self):
        self.src = _ph_src()
        import core.proxy_handler as ph
        self.ep_src = inspect.getsource(ph.db_switch_endpoint)

    def test_sw04_no_os_exit_in_endpoint(self):
        assert "os._exit" not in self.ep_src, (
            "db_switch_endpoint must not call os._exit — hot-swap is in-process"
        )

    def test_sw04b_no_delayed_exit_in_endpoint(self):
        assert "_delayed_exit" not in self.ep_src, (
            "db_switch_endpoint must not schedule _delayed_exit — no restart needed"
        )

    def test_sw05_calls_propagate_global(self):
        assert "_propagate_global" in self.ep_src, (
            "db_switch_endpoint must use _propagate_global to push DB_BACKEND "
            "across all loaded modules"
        )

    def test_sw06_calls_pg_pool_reset(self):
        assert "pg_pool_reset" in self.ep_src, (
            "db_switch_endpoint must call pg_pool_reset() when DSN changes "
            "so stale connections are discarded"
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

    def test_sw12_alternating_db_backend_propagates(self):
        """5× SQLite↔Postgres alternation — every module sees correct backend."""
        import core.proxy_handler as ph
        import db.postgres as pgm
        metrics_mod = self._metrics_mod()

        original = ph.DB_BACKEND
        try:
            backends = ["postgres", "sqlite", "postgres", "sqlite", "postgres"]
            for i, target in enumerate(backends):
                ph._propagate_global("DB_BACKEND", target)
                assert ph.DB_BACKEND == target,              f"round {i}: proxy_handler.DB_BACKEND wrong"
                assert metrics_mod.DB_BACKEND == target,     f"round {i}: core.metrics.DB_BACKEND wrong"
                assert pgm.DB_BACKEND == target,             f"round {i}: db.postgres.DB_BACKEND wrong"
        finally:
            ph._propagate_global("DB_BACKEND", original)

    def test_sw13_final_state_consistent_across_modules(self):
        """After N switches, all three modules agree on the final value."""
        import core.proxy_handler as ph
        import db.postgres as pgm
        metrics_mod = self._metrics_mod()

        original = ph.DB_BACKEND
        try:
            for target in ["postgres", "sqlite", "postgres", "sqlite", "sqlite"]:
                ph._propagate_global("DB_BACKEND", target)
            final = "sqlite"
            assert ph.DB_BACKEND == final
            assert metrics_mod.DB_BACKEND == final
            assert pgm.DB_BACKEND == final
        finally:
            ph._propagate_global("DB_BACKEND", original)


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

    def test_sw16_active_immediately_in_message(self):
        assert "active immediately" in self.src, (
            "db_switch response must say 'active immediately' — no restart needed"
        )

    def test_sw17_no_restart_language_in_message(self):
        assert "container will restart" not in self.src, (
            "db_switch response must not mention container restart"
        )


# ── SW18-SW19: source ordering and pre-flight ─────────────────────────────────

class TestSourceOrdering:
    def setup_method(self):
        import core.proxy_handler as ph
        self.src = inspect.getsource(ph.db_switch_endpoint)

    def test_sw18_migration_before_propagation(self):
        """Migration must be attempted AFTER propagation (pool/DSN is live by then)."""
        prop_pos  = self.src.find("_propagate_global")
        mig_pos   = self.src.find("_migrate_recent_events")
        assert prop_pos != -1, "_propagate_global not found in endpoint"
        assert mig_pos  != -1, "_migrate_recent_events not found in endpoint"
        assert prop_pos < mig_pos, (
            "_propagate_global must appear before _migrate_recent_events "
            "so migration runs on the correct (new) backend"
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

    def test_sw25_propagate_global_exported(self):
        import core.proxy_handler as ph
        assert hasattr(ph, "_propagate_global"), (
            "_propagate_global must be defined in core.proxy_handler"
        )
        assert callable(ph._propagate_global)
