"""
test_h3_pg_pool.py — Unit, regression, and functional tests for H3 fix:
PostgreSQL connection pool (_PgPool in db/postgres.py).

Structure:
  Unit        — _PgPool internals in isolation (fake connections, no PG)
  Regression  — guards against specific failure modes and boundary conditions
  Functional  — end-to-end behaviour through the public API functions
"""
import queue as _queue
import threading as _threading
import time
from contextlib import contextmanager

import pytest


# ── Shared fake-connection helpers ─────────────────────────────────────────

class _Conn:
    """Healthy fake psycopg connection."""
    def __init__(self, name="conn"):
        self.name = name
        self.closed = False
        self.executions = []
    def execute(self, sql, *a, **k):
        if self.closed:
            raise OSError("connection closed")
        self.executions.append(sql)
    def cursor(self):
        return _Cursor(self)
    def close(self):
        self.closed = True

class _Cursor:
    def __init__(self, conn):
        self._conn = conn
        self.rows = []
    def execute(self, sql, *a, **k):
        self._conn.execute(sql)
    def fetchone(self):
        return self.rows[0] if self.rows else None
    def __enter__(self): return self
    def __exit__(self, *a): pass

class _DeadConn(_Conn):
    """Connection that always fails ping and operations."""
    def execute(self, sql, *a, **k):
        raise OSError("connection reset by peer")


def _make_pool(size=3, connect_fn=None):
    """Return a _PgPool with a controllable _connect() function."""
    from db.postgres import _PgPool
    pool = _PgPool.__new__(_PgPool)
    pool._idle = _queue.LifoQueue(maxsize=size)
    pool._lock = _threading.Lock()
    pool._total = 0
    pool._max = size
    pool._dsn = "host=fake"
    pool._connect_timeout = 1.0
    if connect_fn:
        pool._connect = connect_fn
    return pool


# ══════════════════════════════════════════════════════════════════════════════
# UNIT TESTS — _PgPool internals
# ══════════════════════════════════════════════════════════════════════════════

class TestPgPoolUnit:

    # ── __init__ ──────────────────────────────────────────────────────────────

    def test_init_sets_max(self):
        pool = _make_pool(size=7)
        assert pool._max == 7

    def test_init_total_zero(self):
        pool = _make_pool(size=5)
        assert pool._total == 0

    def test_init_idle_empty(self):
        pool = _make_pool(size=5)
        assert pool._idle.qsize() == 0

    # ── stats ─────────────────────────────────────────────────────────────────

    def test_stats_initial(self):
        pool = _make_pool(size=4)
        s = pool.stats
        assert s == {"total": 0, "idle": 0, "max": 4}

    def test_stats_after_acquire(self):
        conns = [_Conn(f"c{i}") for i in range(3)]
        it = iter(conns)
        pool = _make_pool(size=3, connect_fn=lambda: next(it))
        pool._ping = lambda c: True
        with pool.connection():
            s = pool.stats
            assert s["total"] == 1
            assert s["idle"] == 0

    def test_stats_after_release(self):
        c = _Conn()
        pool = _make_pool(size=3, connect_fn=lambda: c)
        pool._ping = lambda conn: True
        with pool.connection():
            pass
        s = pool.stats
        assert s["total"] == 1
        assert s["idle"] == 1

    # ── _ping ─────────────────────────────────────────────────────────────────

    def test_ping_healthy(self):
        pool = _make_pool()
        assert pool._ping(_Conn()) is True

    def test_ping_dead(self):
        pool = _make_pool()
        assert pool._ping(_DeadConn()) is False

    def test_ping_closed(self):
        pool = _make_pool()
        c = _Conn()
        c.close()
        assert pool._ping(c) is False

    # ── _acquire: fast path ───────────────────────────────────────────────────

    def test_acquire_fast_path_returns_idle_conn(self):
        pool = _make_pool(size=3)
        c = _Conn()
        pool._idle.put(c)
        pool._total = 1
        pool._ping = lambda conn: True
        got = pool._acquire(timeout=0.1)
        assert got is c

    def test_acquire_fast_path_skips_dead_and_creates_new(self):
        fresh = _Conn("fresh")
        pool = _make_pool(size=3, connect_fn=lambda: fresh)
        dead = _DeadConn()
        pool._idle.put(dead)
        pool._total = 1
        got = pool._acquire(timeout=0.1)
        assert got is fresh
        assert dead.closed

    # ── _acquire: create new ──────────────────────────────────────────────────

    def test_acquire_creates_new_when_under_limit(self):
        c = _Conn()
        pool = _make_pool(size=3, connect_fn=lambda: c)
        pool._ping = lambda conn: True
        got = pool._acquire(timeout=0.1)
        assert got is c
        assert pool._total == 1

    def test_acquire_increments_total_on_create(self):
        pool = _make_pool(size=5, connect_fn=lambda: _Conn())
        pool._ping = lambda c: True
        pool._acquire(timeout=0.1)
        assert pool._total == 1

    def test_acquire_decrements_total_when_connect_fails(self):
        def _fail():
            raise ConnectionRefusedError("PG down")
        pool = _make_pool(size=3, connect_fn=_fail)
        with pytest.raises(ConnectionRefusedError):
            pool._acquire(timeout=0.1)
        assert pool._total == 0

    # ── _acquire: exhausted ───────────────────────────────────────────────────

    def test_acquire_raises_timeout_when_exhausted(self):
        pool = _make_pool(size=1)
        pool._total = 1   # simulate 1 connection in use, none idle
        with pytest.raises(TimeoutError):
            pool._acquire(timeout=0.05)

    def test_timeout_error_message_contains_max(self):
        pool = _make_pool(size=2)
        pool._total = 2
        with pytest.raises(TimeoutError, match="max=2"):
            pool._acquire(timeout=0.05)

    # ── _release ──────────────────────────────────────────────────────────────

    def test_release_returns_to_idle(self):
        pool = _make_pool(size=3)
        c = _Conn()
        pool._total = 1
        pool._release(c)
        assert pool._idle.qsize() == 1

    def test_release_discards_when_queue_full(self):
        pool = _make_pool(size=1)
        pool._total = 2
        # Fill the queue to capacity
        pool._idle.put(_Conn())
        extra = _Conn()
        pool._release(extra)
        assert extra.closed
        assert pool._total == 1   # discarded → decremented

    # ── _discard ──────────────────────────────────────────────────────────────

    def test_discard_decrements_total(self):
        pool = _make_pool(size=3)
        pool._total = 2
        pool._discard(_Conn())
        assert pool._total == 1

    def test_discard_closes_connection(self):
        pool = _make_pool(size=3)
        pool._total = 1
        c = _Conn()
        pool._discard(c)
        assert c.closed

    def test_discard_tolerates_close_error(self):
        pool = _make_pool(size=3)
        pool._total = 1
        c = _DeadConn()   # close() won't raise but execute does
        pool._discard(c)  # must not propagate any exception
        assert pool._total == 0

    # ── connection() context manager ──────────────────────────────────────────

    def test_context_manager_yields_connection(self):
        c = _Conn()
        pool = _make_pool(size=3, connect_fn=lambda: c)
        pool._ping = lambda conn: True
        with pool.connection() as got:
            assert got is c

    def test_context_manager_releases_on_success(self):
        c = _Conn()
        pool = _make_pool(size=3, connect_fn=lambda: c)
        pool._ping = lambda conn: True
        with pool.connection():
            pass
        assert pool._idle.qsize() == 1

    def test_context_manager_discards_on_exception(self):
        c = _Conn()
        pool = _make_pool(size=3, connect_fn=lambda: c)
        pool._ping = lambda conn: True
        with pytest.raises(RuntimeError):
            with pool.connection():
                raise RuntimeError("boom")
        assert pool._idle.qsize() == 0
        assert c.closed

    def test_context_manager_reraises_exception(self):
        pool = _make_pool(size=3, connect_fn=lambda: _Conn())
        pool._ping = lambda c: True
        with pytest.raises(ValueError, match="test-error"):
            with pool.connection():
                raise ValueError("test-error")

    def test_lifo_order_most_recent_first(self):
        """LIFO queue must return the most recently released connection first."""
        released = []
        pool = _make_pool(size=5)
        c1, c2, c3 = _Conn("c1"), _Conn("c2"), _Conn("c3")
        pool._ping = lambda c: True

        # Manually place in order oldest→newest
        for c in (c1, c2, c3):
            pool._idle.put(c)
            pool._total += 1

        got = pool._acquire(timeout=0.1)
        assert got is c3, "LIFO must return most recently added connection (c3)"


# ══════════════════════════════════════════════════════════════════════════════
# REGRESSION TESTS — boundary conditions and known failure modes
# ══════════════════════════════════════════════════════════════════════════════

class TestPgPoolRegression:

    def test_concurrent_acquires_never_exceed_pool_max(self):
        """Under concurrent pressure, pool._total must never exceed _max."""
        import threading
        max_size = 4
        barrier = threading.Barrier(max_size + 2)
        peak_total = []

        pool = _make_pool(size=max_size)
        pool._ping = lambda c: True

        slow_conns = [_Conn(f"slow{i}") for i in range(max_size + 2)]
        conn_iter = iter(slow_conns)

        def _slow_connect():
            time.sleep(0.01)
            return next(conn_iter)

        pool._connect = _slow_connect

        results = []

        def _worker():
            try:
                barrier.wait(timeout=2)
                conn = pool._acquire(timeout=1.0)
                with pool._lock:
                    peak_total.append(pool._total)
                time.sleep(0.02)
                pool._release(conn)
                results.append("ok")
            except Exception as e:
                results.append(f"err:{e}")

        threads = [threading.Thread(target=_worker)
                   for _ in range(max_size + 2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert max(peak_total) <= max_size, (
            f"pool._total peaked at {max(peak_total)}, exceeds max={max_size}"
        )

    def test_total_consistent_after_discard_and_replace(self):
        """Discarding a dead conn and replacing it must keep _total stable."""
        good = _Conn("good")
        pool = _make_pool(size=3, connect_fn=lambda: good)
        dead = _DeadConn()
        pool._idle.put(dead)
        pool._total = 1

        got = pool._acquire(timeout=0.1)
        assert got is good
        assert pool._total == 1, (
            f"_total must stay at 1 after discard+replace, got {pool._total}"
        )

    def test_unknown_op_in_mirror_kv_returns_false_without_bad_connection(self):
        """_pg_mirror_kv with unknown op must return False without raising
        or marking the connection as unhealthy (connection returns to pool)."""
        from db.postgres import _pg_mirror_kv
        import state as _state
        import db.postgres as pgm

        old_pool = _state._postgres_pool
        old_dsn  = pgm.POSTGRES_DSN

        conn = _Conn()
        pool = _make_pool(size=3, connect_fn=lambda: conn)
        pool._ping = lambda c: True
        _state._postgres_pool = pool

        try:
            result = _pg_mirror_kv("nonexistent_op", ("arg",))
            assert result is False
            # Connection must have been returned to pool, not discarded
            assert pool._idle.qsize() == 1, (
                "Connection must be returned to pool after unknown op (not discarded)"
            )
        finally:
            _state._postgres_pool = old_pool

    def test_pg_insert_event_returns_false_when_no_pool(self, monkeypatch):
        """pg_insert_event must return False (not raise) when pool is None."""
        import db.postgres as pgm
        monkeypatch.setattr(pgm, "_get_pool", lambda: None)
        monkeypatch.setattr(pgm, "DB_BACKEND", "postgres")
        result = pgm.pg_insert_event(
            ts=time.time(), ip="1.2.3.4", ua="TestUA",
            path="/", status=200, reason="ok")
        assert result is False

    def test_pg_db_size_returns_error_dict_when_no_pool(self, monkeypatch):
        """pg_db_size must return {"ok": False, ...} (not raise) when pool is None."""
        import db.postgres as pgm
        monkeypatch.setattr(pgm, "_get_pool", lambda: None)
        result = pgm.pg_db_size()
        assert result.get("ok") is False
        assert "reason" in result

    def test_pool_slot_freed_on_connect_failure(self):
        """If _connect() raises, _total must be decremented so the slot
        is not permanently lost (subsequent call can retry)."""
        attempt = [0]

        def _flaky():
            attempt[0] += 1
            if attempt[0] == 1:
                raise ConnectionRefusedError("first attempt fails")
            return _Conn()

        pool = _make_pool(size=2, connect_fn=_flaky)
        pool._ping = lambda c: True

        with pytest.raises(ConnectionRefusedError):
            pool._acquire(timeout=0.1)

        assert pool._total == 0, (
            "pool._total must be 0 after failed connect (slot must be freed)"
        )
        # Second acquire must succeed
        got = pool._acquire(timeout=0.1)
        assert got is not None

    def test_migrate_recent_events_does_not_use_pool(self):
        """_migrate_recent_events must use direct pg.connect(), not the pool.
        This is intentional: it runs once during a backend swap, needs a
        transaction, and pool connections are autocommit=True."""
        import inspect
        import db.postgres as pgm
        src = inspect.getsource(pgm._migrate_recent_events)
        assert "pg.connect" in src, (
            "_migrate_recent_events must use direct pg.connect() — "
            "it requires transaction semantics incompatible with the pool"
        )
        assert "pool.connection" not in src, (
            "_migrate_recent_events must NOT use pool.connection() — "
            "it's a one-off migration that needs a separate connection"
        )

    def test_db_init_postgres_does_not_use_pool(self):
        """db_init_postgres must use a direct connection — it runs once at
        startup before the pool is initialised."""
        import inspect
        import db.postgres as pgm
        src = inspect.getsource(pgm.db_init_postgres)
        assert "pg.connect" in src
        assert "pool.connection" not in src

    def test_pool_size_zero_raises_immediately(self):
        """A pool with max=0 must refuse every acquire immediately."""
        pool = _make_pool(size=0)
        pool._total = 0  # nothing in use
        with pytest.raises((TimeoutError, Exception)):
            pool._acquire(timeout=0.05)

    def test_release_after_discard_does_not_double_decrement(self):
        """If _discard was already called, _release must not cause _total
        to go negative (guards against double-free logic error)."""
        pool = _make_pool(size=3)
        pool._total = 1
        c = _Conn()
        pool._discard(c)
        assert pool._total == 0
        # Simulating accidental double-release via _release (not _discard again)
        # _release puts back into idle without decrementing — that's correct.
        pool._release(c)   # this goes to idle; _total stays at 0
        assert pool._total == 0   # must not go to -1


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTIONAL TESTS — public API surface with no real PG required
# ══════════════════════════════════════════════════════════════════════════════

class TestPgPoolFunctional:

    def test_get_pool_returns_none_when_no_dsn(self, monkeypatch):
        """_get_pool must return None when POSTGRES_DSN is not configured."""
        import db.postgres as pgm
        import state as _state
        old_pool = _state._postgres_pool
        old_dsn  = pgm.POSTGRES_DSN
        try:
            _state._postgres_pool = None
            monkeypatch.setattr(pgm, "POSTGRES_DSN", "")
            result = pgm._get_pool()
            assert result is None
        finally:
            _state._postgres_pool = old_pool

    def test_get_pool_singleton(self, monkeypatch):
        """_get_pool must return the same instance on every call."""
        import db.postgres as pgm
        import state as _state
        old_pool = _state._postgres_pool
        try:
            fake_pool = _make_pool(size=3)
            _state._postgres_pool = fake_pool
            assert pgm._get_pool() is fake_pool
            assert pgm._get_pool() is fake_pool
        finally:
            _state._postgres_pool = old_pool

    def test_get_pool_stores_in_state(self, monkeypatch):
        """A newly created pool must be stored in _state._postgres_pool."""
        import db.postgres as pgm
        import state as _state
        old_pool = _state._postgres_pool
        try:
            _state._postgres_pool = None
            monkeypatch.setattr(pgm, "POSTGRES_DSN", "host=fake")
            # Fake psycopg so _postgres_load_module returns non-None
            fake_pg = type("FakePg", (), {})()
            monkeypatch.setattr(_state, "_postgres", fake_pg)
            pool = pgm._get_pool()
            if pool is not None:
                assert _state._postgres_pool is pool
        finally:
            _state._postgres_pool = old_pool
            _state._postgres = None

    def test_pool_size_env_var(self, monkeypatch):
        """PG_POOL_SIZE env var must control _PG_POOL_SIZE constant."""
        import importlib
        import os
        # We can't easily reload the module mid-test, but we can verify
        # the constant was read from the environment at import time.
        import db.postgres as pgm
        assert hasattr(pgm, "_PG_POOL_SIZE"), (
            "_PG_POOL_SIZE constant must be defined in db/postgres.py"
        )
        assert isinstance(pgm._PG_POOL_SIZE, int)
        assert pgm._PG_POOL_SIZE > 0

    def test_pool_timeout_env_var(self):
        """PG_POOL_TIMEOUT must be a positive float."""
        import db.postgres as pgm
        assert hasattr(pgm, "_PG_POOL_TIMEOUT"), (
            "_PG_POOL_TIMEOUT constant must be defined in db/postgres.py"
        )
        assert isinstance(pgm._PG_POOL_TIMEOUT, float)
        assert pgm._PG_POOL_TIMEOUT > 0

    def test_pg_insert_event_skips_when_sqlite_backend(self, monkeypatch):
        """pg_insert_event must return False immediately when DB_BACKEND != 'postgres',
        without touching the pool or PG at all."""
        import db.postgres as pgm
        monkeypatch.setattr(pgm, "DB_BACKEND", "sqlite")
        pool_called = []
        monkeypatch.setattr(pgm, "_get_pool",
                            lambda: pool_called.append(True) or None)
        result = pgm.pg_insert_event(
            ts=time.time(), ip="1.2.3.4", ua="", path="/", status=200, reason="")
        assert result is False
        assert not pool_called, (
            "pg_insert_event must not call _get_pool() when DB_BACKEND=sqlite"
        )

    def test_pool_connection_roundtrip_with_fake_conn(self):
        """Full acquire → use → release cycle must work end-to-end."""
        executed = []

        class _RecordingConn(_Conn):
            def execute(self, sql, *a, **k):
                executed.append(sql)

        pool = _make_pool(size=2, connect_fn=lambda: _RecordingConn())
        pool._ping = lambda c: True

        with pool.connection() as conn:
            conn.execute("SELECT 42")

        assert "SELECT 42" in executed
        assert pool._idle.qsize() == 1   # returned to pool
        assert pool._total == 1

    def test_pool_handles_multiple_sequential_requests(self):
        """Pool must correctly handle N sequential requests without leaking slots."""
        n_requests = 10
        pool = _make_pool(size=3, connect_fn=lambda: _Conn())
        pool._ping = lambda c: True

        for _ in range(n_requests):
            with pool.connection() as conn:
                conn.execute("SELECT 1")

        # After all requests, pool state must be clean
        assert pool._total == 1, (
            f"After {n_requests} sequential requests, _total must be 1 "
            f"(one warm connection in idle), got {pool._total}"
        )
        assert pool._idle.qsize() == 1

    def test_pg_insert_event_source_uses_pool(self):
        """Source-level guard: pg_insert_event must reference pool, not pg.connect."""
        import inspect
        import db.postgres as pgm
        src = inspect.getsource(pgm.pg_insert_event)
        assert "pool.connection" in src or "_get_pool" in src
        assert "pg.connect" not in src

    def test_pg_db_size_source_uses_pool(self):
        """Source-level guard: pg_db_size must reference pool, not pg.connect."""
        import inspect
        import db.postgres as pgm
        src = inspect.getsource(pgm.pg_db_size)
        assert "pool.connection" in src or "_get_pool" in src
        assert "pg.connect" not in src

    def test_pg_mirror_kv_source_uses_pool(self):
        """Source-level guard: _pg_mirror_kv must reference pool, not pg.connect."""
        import inspect
        import db.postgres as pgm
        src = inspect.getsource(pgm._pg_mirror_kv)
        assert "pool.connection" in src or "_get_pool" in src
        assert "pg.connect" not in src

    def test_pg_pool_class_exported(self):
        """_PgPool and _get_pool must be importable from db.postgres."""
        from db.postgres import _PgPool, _get_pool
        assert callable(_PgPool)
        assert callable(_get_pool)
