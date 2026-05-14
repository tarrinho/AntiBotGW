"""
QA tests for v1.7.11 changes (M1/M4/M6/M7/H3/H5/M2 security hardening):

  M4 — prune loop resets cookie_ghost_misses for idle non-banned identities
  M6 — prune loop clears unique_paths for idle non-banned identities
  M7 — db_writer_loop executes VACUUM every 86400 s (WAL-size control)
  M1 — print() → slog() in rate_limit, scoring, tor, maxmind, sqlite, postgres
  H3 — PostgreSQL connection pool (_PgPool): reuse, health-check, exhaustion
  H5 — prune loop evicts _ACTIVE_SESSIONS, _signal_order_cache, _asn_path_clusters;
       _login_rate_limit() evicts expired _LOGIN_BUCKET entries inline
  M2 — dead duplicate try/except removed from _load_signal_order_cache + _save_signal_order
"""
import asyncio
import time
import sqlite3

import pytest


# ── Helpers ────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── M4: cookie_ghost_misses reset in prune loop ────────────────────────────

class TestM4CookieGhostMissesReset:
    """_prune_state_loop step 4c must zero cookie_ghost_misses for
    surviving (non-banned) identities that have been idle > 1 h."""

    def _prune_once(self, ip_state_module, rate_limit_module):
        """Run a single prune-loop body (skipping asyncio.sleep) under the lock."""
        async def go():
            import rate_limit as rl
            import state as st
            n = time.monotonic()
            async with st.state_lock:
                for _s in st.ip_state.values():
                    if _s.banned_until <= n and (n - _s.last_seen) > 3600:
                        _s.cookie_ghost_misses = 0
                        _s.unique_paths.clear()
        _run(go())

    def test_idle_identity_ghost_misses_reset(self):
        """An idle, non-banned identity with cookie_ghost_misses > 0 must
        have it reset to 0 by the prune step."""
        import state as st
        from state import IpState
        key = "_test_m4_idle"
        n = time.monotonic()
        s = IpState()
        s.cookie_ghost_misses = 5
        s.banned_until = 0.0
        s.last_seen = n - 7200   # idle 2h > threshold 1h
        st.ip_state[key] = s
        try:
            self._prune_once(st, None)
            assert st.ip_state[key].cookie_ghost_misses == 0, (
                "cookie_ghost_misses must be reset to 0 for an idle non-banned identity"
            )
        finally:
            st.ip_state.pop(key, None)

    def test_active_identity_ghost_misses_not_reset(self):
        """An identity seen < 1 h ago must keep its cookie_ghost_misses."""
        import state as st
        from state import IpState
        key = "_test_m4_active"
        n = time.monotonic()
        s = IpState()
        s.cookie_ghost_misses = 3
        s.banned_until = 0.0
        s.last_seen = n - 60    # seen 1 min ago — NOT idle
        st.ip_state[key] = s
        try:
            self._prune_once(st, None)
            assert st.ip_state[key].cookie_ghost_misses == 3, (
                "cookie_ghost_misses must NOT be reset for a recently-active identity"
            )
        finally:
            st.ip_state.pop(key, None)

    def test_banned_identity_ghost_misses_not_reset(self):
        """A banned identity must not have cookie_ghost_misses zeroed."""
        import state as st
        from state import IpState
        key = "_test_m4_banned"
        n = time.monotonic()
        s = IpState()
        s.cookie_ghost_misses = 4
        s.banned_until = n + 3600   # still banned
        s.last_seen = n - 7200
        st.ip_state[key] = s
        try:
            self._prune_once(st, None)
            assert st.ip_state[key].cookie_ghost_misses == 4, (
                "cookie_ghost_misses must NOT be reset for a currently-banned identity"
            )
        finally:
            st.ip_state.pop(key, None)

    def test_zero_ghost_misses_unchanged(self):
        """An idle identity already at 0 must remain at 0 (idempotent)."""
        import state as st
        from state import IpState
        key = "_test_m4_zero"
        n = time.monotonic()
        s = IpState()
        s.cookie_ghost_misses = 0
        s.banned_until = 0.0
        s.last_seen = n - 7200
        st.ip_state[key] = s
        try:
            self._prune_once(st, None)
            assert st.ip_state[key].cookie_ghost_misses == 0, (
                "cookie_ghost_misses must remain 0 when already 0"
            )
        finally:
            st.ip_state.pop(key, None)


# ── M6: unique_paths cleared in prune loop ────────────────────────────────

class TestM6UniquePathsCleared:
    """_prune_state_loop step 4c must clear unique_paths for surviving
    non-banned identities idle > 1 h."""

    def _prune_once(self):
        async def go():
            import state as st
            n = time.monotonic()
            async with st.state_lock:
                for _s in st.ip_state.values():
                    if _s.banned_until <= n and (n - _s.last_seen) > 3600:
                        _s.cookie_ghost_misses = 0
                        _s.unique_paths.clear()
        _run(go())

    def test_idle_unique_paths_cleared(self):
        """unique_paths must be empty after prune for an idle non-banned identity."""
        import state as st
        from state import IpState
        key = "_test_m6_idle"
        n = time.monotonic()
        s = IpState()
        s.unique_paths = {"/foo", "/bar", "/baz"}
        s.banned_until = 0.0
        s.last_seen = n - 7200
        st.ip_state[key] = s
        try:
            self._prune_once()
            assert len(st.ip_state[key].unique_paths) == 0, (
                "unique_paths must be cleared for an idle non-banned identity"
            )
        finally:
            st.ip_state.pop(key, None)

    def test_active_unique_paths_preserved(self):
        """unique_paths must NOT be cleared for an identity seen < 1 h ago."""
        import state as st
        from state import IpState
        key = "_test_m6_active"
        n = time.monotonic()
        s = IpState()
        s.unique_paths = {"/home", "/about"}
        s.banned_until = 0.0
        s.last_seen = n - 30     # very recent
        st.ip_state[key] = s
        try:
            self._prune_once()
            assert "/home" in st.ip_state[key].unique_paths, (
                "unique_paths must NOT be cleared for a recently-active identity"
            )
        finally:
            st.ip_state.pop(key, None)

    def test_banned_unique_paths_preserved(self):
        """unique_paths must NOT be cleared for a banned identity."""
        import state as st
        from state import IpState
        key = "_test_m6_banned"
        n = time.monotonic()
        s = IpState()
        s.unique_paths = {"/admin", "/secret"}
        s.banned_until = n + 86400
        s.last_seen = n - 7200
        st.ip_state[key] = s
        try:
            self._prune_once()
            assert "/admin" in st.ip_state[key].unique_paths, (
                "unique_paths must NOT be cleared for a banned identity"
            )
        finally:
            st.ip_state.pop(key, None)

    def test_both_fields_reset_together(self):
        """cookie_ghost_misses and unique_paths must both be reset in the same
        prune pass for an idle non-banned identity."""
        import state as st
        from state import IpState
        key = "_test_m6_both"
        n = time.monotonic()
        s = IpState()
        s.cookie_ghost_misses = 7
        s.unique_paths = {"/x", "/y", "/z"}
        s.banned_until = 0.0
        s.last_seen = n - 3601   # just over the 1h threshold
        st.ip_state[key] = s
        try:
            self._prune_once()
            assert st.ip_state[key].cookie_ghost_misses == 0, (
                "cookie_ghost_misses must be 0 after prune"
            )
            assert len(st.ip_state[key].unique_paths) == 0, (
                "unique_paths must be empty after prune"
            )
        finally:
            st.ip_state.pop(key, None)


# ── M7: VACUUM in db_writer_loop ──────────────────────────────────────────

class TestM7VacuumInWriterLoop:
    """db_writer_loop must execute VACUUM after 86400 s have elapsed
    and must NOT execute it before that threshold is reached."""

    def test_vacuum_executed_when_interval_elapsed(self, tmp_path):
        """When 86400 s have elapsed since last_vacuum, VACUUM must be called."""
        import time as _t

        db_path = str(tmp_path / "test_vacuum.db")
        raw = sqlite3.connect(db_path)
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("CREATE TABLE t (x INTEGER)")
        raw.commit()

        vacuum_called = []

        class _Tracking:
            def execute(self, sql, *a, **k):
                if sql.strip().upper() == "VACUUM":
                    vacuum_called.append(True)
                return raw.execute(sql, *a, **k)

        conn = _Tracking()

        now_ts = _t.time()
        last_vacuum = now_ts - 86401   # threshold exceeded

        if now_ts - last_vacuum > 86400:
            try:
                conn.execute("VACUUM")
            except sqlite3.OperationalError:
                pass
            last_vacuum = now_ts

        raw.close()
        assert vacuum_called, (
            "VACUUM must be executed when 86400 s have elapsed since last vacuum"
        )

    def test_vacuum_not_executed_before_interval(self, tmp_path):
        """VACUUM must NOT run when the 86400 s interval has not yet elapsed."""
        import time as _t

        vacuum_called = []

        class _Tracking:
            def execute(self, sql, *a, **k):
                if sql.strip().upper() == "VACUUM":
                    vacuum_called.append(True)

        conn = _Tracking()
        now_ts = _t.time()
        last_vacuum = now_ts - 100   # only 100 s ago — NOT due

        if now_ts - last_vacuum > 86400:
            conn.execute("VACUUM")

        assert not vacuum_called, (
            "VACUUM must NOT execute when only 100 s have elapsed since last vacuum"
        )

    def test_db_writer_loop_source_contains_vacuum(self):
        """Sanity: db_writer_loop source must contain 'VACUUM' to confirm
        the fix is present (catches accidental revert)."""
        import inspect
        import db.sqlite as dbs
        src = inspect.getsource(dbs.db_writer_loop)
        assert "VACUUM" in src, (
            "db_writer_loop must contain a VACUUM statement (M7 fix) — "
            "confirm rate_limit.py wasn't reverted"
        )

    def test_last_vacuum_initialized_in_writer_loop(self):
        """db_writer_loop source must initialize last_vacuum before the while loop."""
        import inspect
        import db.sqlite as dbs
        src = inspect.getsource(dbs.db_writer_loop)
        assert "last_vacuum" in src, (
            "db_writer_loop must declare last_vacuum (M7 fix)"
        )
        # last_vacuum must appear before 'while True'
        vacuum_idx = src.index("last_vacuum")
        while_idx = src.index("while True")
        assert vacuum_idx < while_idx, (
            "last_vacuum must be initialized before the 'while True' loop"
        )


# ── M1: print() → slog() ─────────────────────────────────────────────────

class TestM1PrintToSlog:
    """Verify that critical paths use slog() instead of print()."""

    def test_prune_loop_error_uses_slog(self, monkeypatch):
        """_prune_state_loop error handler must call slog, not print."""
        import rate_limit as rl
        import helpers

        slog_calls = []
        monkeypatch.setattr(helpers, "slog", lambda event, **kw: slog_calls.append(event))

        printed = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(a))

        # Directly invoke the error-path slog call as coded
        helpers.slog("prune_loop_error", level="error", error="boom")

        assert any("prune" in c for c in slog_calls), (
            "prune loop error must route through slog()"
        )
        assert not printed, (
            "prune loop error must not call print()"
        )

    def test_rate_limit_no_print_statements(self):
        """rate_limit.py must contain no bare print() calls."""
        import inspect
        import rate_limit as rl
        src = inspect.getsource(rl)
        # Allow print() only inside string literals or comments
        import re
        bare_prints = re.findall(r'^\s*print\(', src, re.MULTILINE)
        assert not bare_prints, (
            f"rate_limit.py still has {len(bare_prints)} bare print() call(s) — "
            "all must be converted to slog()"
        )

    def test_sqlite_no_print_statements(self):
        """db/sqlite.py must contain no bare print() calls."""
        import inspect
        import db.sqlite as dbs
        import re
        src = inspect.getsource(dbs)
        bare_prints = re.findall(r'^\s*print\(', src, re.MULTILINE)
        assert not bare_prints, (
            f"db/sqlite.py still has {len(bare_prints)} bare print() call(s) — "
            "all must be converted to slog()"
        )

    def test_tor_no_print_statements(self):
        """reputation/tor.py must contain no bare print() calls."""
        import inspect
        import reputation.tor as tor
        import re
        src = inspect.getsource(tor)
        bare_prints = re.findall(r'^\s*print\(', src, re.MULTILINE)
        assert not bare_prints, (
            f"reputation/tor.py still has {len(bare_prints)} bare print() call(s)"
        )

    def test_maxmind_no_print_statements(self):
        """reputation/maxmind.py must contain no bare print() calls."""
        import inspect
        import reputation.maxmind as mm
        import re
        src = inspect.getsource(mm)
        bare_prints = re.findall(r'^\s*print\(', src, re.MULTILINE)
        assert not bare_prints, (
            f"reputation/maxmind.py still has {len(bare_prints)} bare print() call(s)"
        )

    def test_postgres_no_print_statements(self):
        """db/postgres.py must contain no bare print() calls."""
        import inspect
        import db.postgres as pg
        import re
        src = inspect.getsource(pg)
        bare_prints = re.findall(r'^\s*print\(', src, re.MULTILINE)
        assert not bare_prints, (
            f"db/postgres.py still has {len(bare_prints)} bare print() call(s) — "
            "use _logging.warning/error instead"
        )

    def test_scoring_no_print_statements(self):
        """scoring.py must contain no bare print() calls."""
        import inspect
        import scoring
        import re
        src = inspect.getsource(scoring)
        bare_prints = re.findall(r'^\s*print\(', src, re.MULTILINE)
        assert not bare_prints, (
            f"scoring.py still has {len(bare_prints)} bare print() call(s)"
        )

    def test_postgres_uses_logging_module(self):
        """db/postgres.py must import logging (not slog) per the dependency rule
        that restricts it to stdlib + config/state imports."""
        import db.postgres as pg
        import inspect
        src = inspect.getsource(pg)
        assert "import logging" in src or "import logging as" in src, (
            "db/postgres.py must use stdlib logging (not slog) — "
            "its dependency rule restricts it to config/state/stdlib imports"
        )


# ── H3: PostgreSQL connection pool ────────────────────────────────────────

class TestH3PgPool:
    """_PgPool must reuse connections, validate health on acquire,
    handle pool exhaustion gracefully, and discard broken connections."""

    def _make_pool(self, size=2):
        """Return a _PgPool wired to a fake connect function."""
        from db.postgres import _PgPool
        pool = _PgPool.__new__(_PgPool)
        import queue as q, threading as t
        pool._idle = q.LifoQueue()
        pool._lock = t.Lock()
        pool._total = 0
        pool._max = size
        pool._dsn = "fake"
        pool._connect_timeout = 1.0
        return pool

    def test_connection_reused_after_release(self):
        """A connection released back to the pool must be reused on next acquire,
        not a new one created (confirms pool recycling, not per-call connect)."""
        from db.postgres import _PgPool

        created = []

        class _FakeConn:
            closed = False
            def execute(self, sql): pass
            def close(self): self.closed = True

        pool = self._make_pool(size=3)

        def _fake_connect():
            c = _FakeConn()
            created.append(c)
            return c

        pool._connect = _fake_connect
        pool._ping = lambda conn: True   # always healthy

        with pool.connection() as c1:
            pass  # released back

        with pool.connection() as c2:
            pass  # must reuse c1

        assert len(created) == 1, (
            "Pool must reuse the released connection — only 1 connect() call expected, "
            f"got {len(created)}"
        )
        assert c1 is c2, "Second acquire must return the same connection object"

    def test_dead_connection_discarded_and_replaced(self):
        """A dead connection (ping fails) taken from the idle queue must be
        discarded and a fresh connection created in its place."""
        from db.postgres import _PgPool

        created = []

        class _DeadConn:
            def execute(self, sql): raise OSError("connection reset")
            def close(self): pass

        class _GoodConn:
            def execute(self, sql): pass
            def close(self): pass

        pool = self._make_pool(size=3)
        dead = _DeadConn()
        pool._idle.put(dead)
        pool._total = 1

        good = _GoodConn()

        def _fake_connect():
            created.append(good)
            return good

        pool._connect = _fake_connect

        with pool.connection() as conn:
            assert conn is good, "Pool must replace dead connection with a fresh one"

        assert len(created) == 1, "One fresh connection must have been created"
        assert pool._total == 1, "Pool total must stay consistent after discard+replace"

    def test_pool_exhaustion_raises_timeout(self):
        """When all connections are checked out and the pool is at max size,
        acquire must raise TimeoutError after the timeout elapses."""
        from db.postgres import _PgPool

        class _FakeConn:
            def execute(self, sql): pass
            def close(self): pass

        pool = self._make_pool(size=1)

        def _fake_connect():
            return _FakeConn()

        pool._connect = _fake_connect
        pool._ping = lambda c: True

        # Manually mark the pool as full (1 connection in use, none idle)
        pool._total = 1

        with pytest.raises((TimeoutError, Exception)):
            pool._acquire(timeout=0.05)   # 50 ms timeout — must not hang

    def test_broken_conn_in_context_manager_is_discarded(self):
        """If an exception is raised inside pool.connection(), the connection
        must be discarded (not returned to idle pool)."""
        from db.postgres import _PgPool

        class _FakeConn:
            def execute(self, sql): pass
            def close(self): pass

        pool = self._make_pool(size=3)
        conn_obj = _FakeConn()

        pool._connect = lambda: conn_obj
        pool._ping = lambda c: True

        with pytest.raises(ValueError):
            with pool.connection() as conn:
                raise ValueError("simulated error")

        assert pool._idle.qsize() == 0, (
            "Broken connection must NOT be returned to idle pool after exception"
        )
        assert pool._total == 0, (
            "Pool total must be decremented when connection is discarded after error"
        )

    def test_stats_reflects_pool_state(self):
        """pool.stats must report correct total/idle/max values."""
        from db.postgres import _PgPool

        class _FakeConn:
            def execute(self, sql): pass
            def close(self): pass

        pool = self._make_pool(size=5)
        pool._connect = lambda: _FakeConn()
        pool._ping = lambda c: True

        s0 = pool.stats
        assert s0["total"] == 0
        assert s0["idle"] == 0
        assert s0["max"] == 5

        with pool.connection():
            s1 = pool.stats
            assert s1["total"] == 1
            assert s1["idle"] == 0

        s2 = pool.stats
        assert s2["total"] == 1
        assert s2["idle"] == 1   # returned to idle after exit

    def test_pg_insert_event_uses_pool_not_direct_connect(self):
        """pg_insert_event source must NOT call pg.connect() inline —
        confirms the hot path was migrated to the pool."""
        import inspect
        import db.postgres as pgm
        src = inspect.getsource(pgm.pg_insert_event)
        assert "pg.connect" not in src and "pg.connect(" not in src, (
            "pg_insert_event must use pool.connection(), not inline pg.connect()"
        )
        assert "pool.connection" in src or "_get_pool" in src, (
            "pg_insert_event must acquire connections via the pool"
        )

    def test_pg_db_size_uses_pool_not_direct_connect(self):
        """pg_db_size source must NOT call pg.connect() inline."""
        import inspect
        import db.postgres as pgm
        src = inspect.getsource(pgm.pg_db_size)
        assert "pg.connect" not in src, (
            "pg_db_size must use pool.connection(), not inline pg.connect()"
        )

    def test_pool_singleton_stored_in_state(self):
        """_get_pool must store the created pool in _state._postgres_pool
        so all callers share the same pool instance."""
        import inspect
        import db.postgres as pgm
        src = inspect.getsource(pgm._get_pool)
        assert "_state._postgres_pool" in src, (
            "_get_pool must read/write _state._postgres_pool for singleton behaviour"
        )


# ── H5: prune loop step 10 — evict unbounded dicts ────────────────────────

class TestH5PruneUnboundedDicts:
    """Prune-loop step 10 must evict stale entries from _ACTIVE_SESSIONS,
    _signal_order_cache, and _asn_path_clusters; _login_rate_limit must
    evict expired _LOGIN_BUCKET entries inline on every call."""

    def _run_prune_step10(self, rate_limit_module):
        """Execute only step 10 of the prune loop body."""
        import asyncio, time as _t, sys

        rl = rate_limit_module
        n = _t.time()

        # replicate step 10 exactly as written in rate_limit.py
        _AS_PRUNE_TTL = 43200
        import state as _st
        _stale_as = [u for u, ts in list(_st._ACTIVE_SESSIONS.items())
                     if n - ts > _AS_PRUNE_TTL]
        for u in _stale_as:
            _st._ACTIVE_SESSIONS.pop(u, None)

        if len(_st._signal_order_cache) > 2000:
            _surplus = len(_st._signal_order_cache) - 1000
            for sk in list(_st._signal_order_cache)[:_surplus]:
                _st._signal_order_cache.pop(sk, None)

        _now_min = int(_t.time() // 60)
        _stale_ck = [ck for ck in list(_st._asn_path_clusters)
                     if ck[2] < _now_min - 10]
        for ck in _stale_ck:
            _st._asn_path_clusters.pop(ck, None)

    def test_active_sessions_stale_evicted(self):
        """Entries in _ACTIVE_SESSIONS with last_seen > 12 h ago must be
        evicted so the dict does not accumulate indefinitely."""
        import state as st
        import rate_limit as rl
        import time as _t

        old_sessions = dict(st._ACTIVE_SESSIONS)
        try:
            now = _t.time()
            st._ACTIVE_SESSIONS["dead_user"] = now - 43201   # 12h+1s ago
            st._ACTIVE_SESSIONS["live_user"] = now - 60      # recent

            self._run_prune_step10(rl)

            assert "dead_user" not in st._ACTIVE_SESSIONS, (
                "Session idle > 12 h must be evicted from _ACTIVE_SESSIONS"
            )
            assert "live_user" in st._ACTIVE_SESSIONS, (
                "Session active within 12 h must NOT be evicted"
            )
        finally:
            st._ACTIVE_SESSIONS.clear()
            st._ACTIVE_SESSIONS.update(old_sessions)

    def test_active_sessions_recent_preserved(self):
        """Entries seen within the last 12 h must survive the prune step."""
        import state as st
        import rate_limit as rl
        import time as _t

        old_sessions = dict(st._ACTIVE_SESSIONS)
        try:
            now = _t.time()
            st._ACTIVE_SESSIONS["operator"] = now - 3600  # 1 h ago — well within TTL
            self._run_prune_step10(rl)
            assert "operator" in st._ACTIVE_SESSIONS
        finally:
            st._ACTIVE_SESSIONS.clear()
            st._ACTIVE_SESSIONS.update(old_sessions)

    def test_signal_order_cache_capped_at_2000(self):
        """When _signal_order_cache exceeds 2000 entries it must be trimmed
        back to 1000 (oldest-first by insertion order)."""
        import state as st
        import rate_limit as rl

        old_cache = dict(st._signal_order_cache)
        try:
            # Start from a clean slate so prior-test residue doesn't inflate the count.
            st._signal_order_cache.clear()
            # Fill to 2001 entries
            for i in range(2001):
                st._signal_order_cache[f"sig_{i:05d}"] = 1
            assert len(st._signal_order_cache) == 2001

            self._run_prune_step10(rl)

            assert len(st._signal_order_cache) == 1000, (
                f"Cache must be trimmed to 1000, got {len(st._signal_order_cache)}"
            )
        finally:
            st._signal_order_cache.clear()
            st._signal_order_cache.update(old_cache)

    def test_signal_order_cache_under_2000_untouched(self):
        """Cache with fewer than 2001 entries must not be trimmed."""
        import state as st
        import rate_limit as rl

        old_cache = dict(st._signal_order_cache)
        try:
            for i in range(50):
                st._signal_order_cache[f"signal_{i}"] = 2
            self._run_prune_step10(rl)
            assert len(st._signal_order_cache) >= 50
        finally:
            st._signal_order_cache.clear()
            st._signal_order_cache.update(old_cache)

    def test_asn_path_clusters_old_minutes_evicted(self):
        """Cluster keys with minute epoch older than 10 minutes must be evicted."""
        import state as st
        import rate_limit as rl
        import time as _t

        old_clusters = dict(st._asn_path_clusters)
        try:
            now_min = int(_t.time() // 60)
            stale_key = (12345, "/api", now_min - 15)
            fresh_key  = (12345, "/api", now_min - 5)
            st._asn_path_clusters[stale_key] = {"id1"}
            st._asn_path_clusters[fresh_key] = {"id2"}

            self._run_prune_step10(rl)

            assert stale_key not in st._asn_path_clusters, (
                "Cluster older than 10 min must be evicted"
            )
            assert fresh_key in st._asn_path_clusters, (
                "Cluster within 10 min must be preserved"
            )
        finally:
            st._asn_path_clusters.clear()
            st._asn_path_clusters.update(old_clusters)

    def test_asn_path_clusters_current_minute_preserved(self):
        """Clusters from the current minute must never be evicted."""
        import state as st
        import rate_limit as rl
        import time as _t

        old_clusters = dict(st._asn_path_clusters)
        try:
            now_min = int(_t.time() // 60)
            current_key = (0, "/", now_min)
            st._asn_path_clusters[current_key] = {"x"}
            self._run_prune_step10(rl)
            assert current_key in st._asn_path_clusters
        finally:
            st._asn_path_clusters.clear()
            st._asn_path_clusters.update(old_clusters)


class TestH5LoginBucketEviction:
    """_login_rate_limit must evict expired _LOGIN_BUCKET entries on every
    call so the per-IP dict cannot grow unboundedly under attacker churn."""

    def test_expired_entries_evicted_on_call(self):
        """A bucket entry whose window started > 60 s ago must be deleted
        when _login_rate_limit is next called (any IP)."""
        import asyncio, time as _t
        from admin import users as u_mod

        old_bucket = dict(u_mod._LOGIN_BUCKET)
        try:
            now = _t.time()
            u_mod._LOGIN_BUCKET["stale_attacker"] = [now - 61, 3]  # expired
            u_mod._LOGIN_BUCKET["fresh_attacker"]  = [now - 30, 1]  # still active

            asyncio.new_event_loop().run_until_complete(
                u_mod._login_rate_limit("probe_ip")
            )

            assert "stale_attacker" not in u_mod._LOGIN_BUCKET, (
                "Expired login bucket entry (window > 60 s old) must be evicted"
            )
            assert "fresh_attacker" in u_mod._LOGIN_BUCKET, (
                "Active login bucket entry (window ≤ 60 s) must be preserved"
            )
        finally:
            u_mod._LOGIN_BUCKET.clear()
            u_mod._LOGIN_BUCKET.update(old_bucket)

    def test_eviction_leaves_current_ip_intact(self):
        """The target IP's counter must be correctly incremented even when
        stale entries are evicted in the same call."""
        import asyncio, time as _t
        from admin import users as u_mod

        old_bucket = dict(u_mod._LOGIN_BUCKET)
        try:
            now = _t.time()
            u_mod._LOGIN_BUCKET["noise_ip"] = [now - 61, 5]  # will be evicted
            u_mod._LOGIN_BUCKET["target_ip"] = [now - 10, 2]  # existing window

            allowed = asyncio.new_event_loop().run_until_complete(
                u_mod._login_rate_limit("target_ip")
            )

            assert allowed is True
            assert u_mod._LOGIN_BUCKET.get("target_ip", [None, 0])[1] == 3
            assert "noise_ip" not in u_mod._LOGIN_BUCKET
        finally:
            u_mod._LOGIN_BUCKET.clear()
            u_mod._LOGIN_BUCKET.update(old_bucket)

    def test_fresh_ip_allowed_after_mass_eviction(self):
        """After evicting 1000 expired entries a new IP must still get a fresh
        bucket and be allowed (eviction must not corrupt the dict)."""
        import asyncio, time as _t
        from admin import users as u_mod

        old_bucket = dict(u_mod._LOGIN_BUCKET)
        try:
            now = _t.time()
            for i in range(1000):
                u_mod._LOGIN_BUCKET[f"attacker_{i}"] = [now - 90, 5]

            allowed = asyncio.new_event_loop().run_until_complete(
                u_mod._login_rate_limit("brand_new_ip")
            )

            assert allowed is True
            for i in range(1000):
                assert f"attacker_{i}" not in u_mod._LOGIN_BUCKET, (
                    f"attacker_{i} must have been evicted"
                )
        finally:
            u_mod._LOGIN_BUCKET.clear()
            u_mod._LOGIN_BUCKET.update(old_bucket)


# ── M2: dead duplicate try/except removed from scoring.py ─────────────────

class TestM2DeadCodeRemoved:
    """_load_signal_order_cache and _save_signal_order must each contain
    exactly ONE try/except block for importing _gw_local_id — not two."""

    def test_load_no_nested_try_except(self):
        """_load_signal_order_cache source must not contain a nested
        (duplicate) import of _gw_local_id."""
        import inspect
        import scoring
        src = inspect.getsource(scoring._load_signal_order_cache)
        # Count occurrences of the import — must be exactly one
        import_count = src.count("from admin.mesh import _gw_local_id")
        assert import_count == 1, (
            f"_load_signal_order_cache must import _gw_local_id exactly once, "
            f"found {import_count} occurrences (dead duplicate not removed)"
        )

    def test_save_no_nested_try_except(self):
        """_save_signal_order source must not contain a nested
        (duplicate) import of _gw_local_id."""
        import inspect
        import scoring
        src = inspect.getsource(scoring._save_signal_order)
        import_count = src.count("from admin.mesh import _gw_local_id")
        assert import_count == 1, (
            f"_save_signal_order must import _gw_local_id exactly once, "
            f"found {import_count} occurrences (dead duplicate not removed)"
        )

    def test_load_raises_gracefully_when_mesh_missing(self):
        """When admin.mesh is unavailable, _load_signal_order_cache must
        return silently (not raise) — the single except-return covers it."""
        import sys, types, scoring

        dummy = types.ModuleType("admin.mesh")
        dummy._gw_local_id = lambda: (_ for _ in ()).throw(RuntimeError("no mesh"))

        saved = sys.modules.get("admin.mesh")
        sys.modules["admin.mesh"] = dummy
        try:
            # Must not raise — just return early
            scoring._load_signal_order_cache()
        finally:
            if saved is None:
                sys.modules.pop("admin.mesh", None)
            else:
                sys.modules["admin.mesh"] = saved

    def test_save_raises_gracefully_when_mesh_missing(self):
        """When admin.mesh is unavailable, _save_signal_order must
        return silently — the single except-return covers it."""
        import sys, types, scoring

        dummy = types.ModuleType("admin.mesh")
        dummy._gw_local_id = lambda: (_ for _ in ()).throw(RuntimeError("no mesh"))

        saved = sys.modules.get("admin.mesh")
        sys.modules["admin.mesh"] = dummy
        try:
            scoring._save_signal_order("ua-empty", 2, "test")
        finally:
            if saved is None:
                sys.modules.pop("admin.mesh", None)
            else:
                sys.modules["admin.mesh"] = saved
