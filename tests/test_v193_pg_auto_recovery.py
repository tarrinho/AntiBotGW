"""
1.9.2 iter-21 — QA for Postgres auto-recovery.

Background: `_disable_postgres_for_process` used to latch the Postgres backend
OFF until an operator restarted the gateway. Any transient Postgres failure (a
container restart, a network blip, a password drift later corrected) therefore
left the gateway permanently degraded to SQLite — empty dashboards, dead
geo-data / event reads — even after Postgres came back healthy.

1.9.2 iter-21 makes the disable RECOVERABLE:

  * `_disable_postgres_for_process` records WHY the backend went down
    (`_PG_DISABLED_BY_FAILURE = True`) instead of latching forever.
  * `pg_recovery_probe()` does a direct connect + `SELECT 1`, bypassing the
    pool and the auth latch, to test reachability+auth.
  * `pg_maybe_recover()` — called by the background `_pg_recovery_loop` every
    PG_RECOVERY_PROBE_SECS — re-enables the backend the instant the probe
    succeeds, with NO restart.
  * `_reenable_postgres_for_process` fully reverses the disable: clears the
    auth latch, flips `_postgres_available` back on across every module, and
    restores DB_BACKEND=postgres.

These tests lock that state machine + the no-op-when-healthy contract.
"""
import os
import sys
import types

os.environ.setdefault("UPSTREAM", "https://example.com")

import db.postgres as pg
import state as st


def _reset():
    """Return the module to the healthy/enabled baseline between tests."""
    pg._PG_AUTH_FAILED = False
    pg._PG_DISABLED_BY_FAILURE = False
    st._postgres_available = True


# ── disable now records the *reason* (recoverable), not a permanent latch ──
def test_disable_marks_disabled_by_failure():
    _reset()
    assert pg._PG_DISABLED_BY_FAILURE is False
    pg._disable_postgres_for_process(reason="unit-test")
    assert pg._PG_DISABLED_BY_FAILURE is True
    assert pg._PG_DISABLED_TS > 0
    assert st._postgres_available is False
    _reset()


# ── re-enable fully reverses disable ───────────────────────────────────────
def test_reenable_reverses_disable():
    _reset()
    pg._disable_postgres_for_process(reason="unit-test")
    pg._PG_AUTH_FAILED = True
    before = pg._PG_RECOVERED_COUNT
    pg._reenable_postgres_for_process(reason="unit")
    assert st._postgres_available is True
    assert pg._PG_AUTH_FAILED is False
    assert pg._PG_DISABLED_BY_FAILURE is False
    assert pg._PG_RECOVERED_COUNT == before + 1
    _reset()


def test_reenable_restores_db_backend_on_proxy_handler():
    """A live PG deployment that fails reverts DB_BACKEND to sqlite on
    core.proxy_handler; recovery must restore it to postgres or writes keep
    taking the SQLite path forever."""
    _reset()
    fake = types.ModuleType("core.proxy_handler")
    fake.DB_BACKEND = "postgres"
    fake._postgres_available = True
    saved = sys.modules.get("core.proxy_handler")
    sys.modules["core.proxy_handler"] = fake
    try:
        pg._disable_postgres_for_process(reason="unit-test")
        assert fake.DB_BACKEND == "sqlite"          # reverted on failure
        pg._reenable_postgres_for_process(reason="unit")
        assert fake.DB_BACKEND == "postgres"        # restored on recovery
        assert fake._postgres_available is True
    finally:
        if saved is not None:
            sys.modules["core.proxy_handler"] = saved
        else:
            sys.modules.pop("core.proxy_handler", None)
        _reset()


# ── maybe_recover is a no-op while healthy (zero steady-state cost) ─────────
def test_maybe_recover_noop_when_healthy(monkeypatch):
    _reset()
    called = {"probe": 0}

    def _spy_probe(*a, **k):
        called["probe"] += 1
        return True

    monkeypatch.setattr(pg, "pg_recovery_probe", _spy_probe)
    assert pg.pg_maybe_recover() is False           # not disabled → returns fast
    assert called["probe"] == 0                      # MUST NOT probe when healthy
    _reset()


# ── maybe_recover re-enables when the probe + schema-init succeed ──────────
def test_maybe_recover_reenables_on_probe_success(monkeypatch):
    _reset()
    pg._disable_postgres_for_process(reason="unit-test")
    monkeypatch.setattr(pg, "POSTGRES_DSN", "postgresql://x@h/db", raising=False)
    monkeypatch.setattr(pg, "pg_recovery_probe", lambda *a, **k: True)
    # Recovery re-ensures the schema (idempotent) before re-enabling — stub it
    # so the test doesn't dial a real Postgres.
    monkeypatch.setattr(pg, "db_init_postgres", lambda *a, **k: True)
    assert pg.pg_maybe_recover() is True
    assert st._postgres_available is True
    assert pg._PG_DISABLED_BY_FAILURE is False
    _reset()


# ── recovery aborts (stays disabled) if the schema re-init fails ───────────
def test_maybe_recover_stays_disabled_if_schema_init_fails(monkeypatch):
    _reset()
    pg._disable_postgres_for_process(reason="unit-test")
    monkeypatch.setattr(pg, "POSTGRES_DSN", "postgresql://x@h/db", raising=False)
    monkeypatch.setattr(pg, "pg_recovery_probe", lambda *a, **k: True)
    monkeypatch.setattr(pg, "db_init_postgres", lambda *a, **k: False)  # init fails
    assert pg.pg_maybe_recover() is False
    assert st._postgres_available is False
    assert pg._PG_DISABLED_BY_FAILURE is True        # still disabled, will retry
    _reset()


# ── maybe_recover stays disabled when the probe still fails ────────────────
def test_maybe_recover_stays_disabled_on_probe_failure(monkeypatch):
    _reset()
    pg._disable_postgres_for_process(reason="unit-test")
    monkeypatch.setattr(pg, "POSTGRES_DSN", "postgresql://x@h/db", raising=False)
    monkeypatch.setattr(pg, "pg_recovery_probe", lambda *a, **k: False)
    assert pg.pg_maybe_recover() is False
    assert pg._PG_DISABLED_BY_FAILURE is True        # still disabled, will retry
    assert st._postgres_available is False
    _reset()


# ── probe is safe with no DSN configured ───────────────────────────────────
def test_probe_false_without_dsn(monkeypatch):
    _reset()
    monkeypatch.setattr(pg, "POSTGRES_DSN", "", raising=False)
    assert pg.pg_recovery_probe() is False
    _reset()


# ── maybe_recover needs a DSN even when disabled-by-failure ─────────────────
def test_maybe_recover_requires_dsn(monkeypatch):
    _reset()
    pg._disable_postgres_for_process(reason="unit-test")
    monkeypatch.setattr(pg, "POSTGRES_DSN", "", raising=False)
    # No DSN → cannot probe → no recovery, but must not raise.
    assert pg.pg_maybe_recover() is False
    _reset()


# ── probe never raises even when the driver connect blows up ───────────────
def test_probe_swallows_connect_errors(monkeypatch):
    _reset()
    monkeypatch.setattr(pg, "POSTGRES_DSN", "postgresql://x@h/db", raising=False)

    class _BoomModule:
        def connect(self, *a, **k):
            raise RuntimeError("connection refused")

    monkeypatch.setattr(pg, "_postgres_load_module", lambda: _BoomModule())
    assert pg.pg_recovery_probe() is False           # swallowed, returns False
    _reset()


# ── probe interval is configurable + floored ───────────────────────────────
def test_probe_interval_floor():
    assert pg._PG_RECOVERY_PROBE_SECS >= 5.0


# ── the recovery loop coroutine exists + is wired into proxy ───────────────
def test_recovery_loop_defined_in_proxy():
    import proxy
    assert hasattr(proxy, "_pg_recovery_loop")
    import inspect
    assert inspect.iscoroutinefunction(proxy._pg_recovery_loop)
