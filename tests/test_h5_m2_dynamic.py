"""
Dynamic QA tests for H5 + M2 (v1.7.11 security hardening).

"Dynamic" means these tests run the *real* coroutines / functions — not
hand-replicated logic — so they catch regressions in the actual code path:
import order, lock acquisition, loop structure, and state mutation.

  H5-D — _prune_state_loop step 10 verified via the real rate_limit coroutine
           (asyncio.sleep patched to instant-then-cancel so the body runs once)
  H5-D — _login_rate_limit() LOGIN_BUCKET eviction end-to-end via real call
  M2-D — _load_signal_order_cache / _save_signal_order called for real;
           mesh unavailability handled without raise or duplicate import
"""
import asyncio
import time as _time
from unittest.mock import patch, AsyncMock

import pytest


# ── Helper: run the real prune loop for exactly one body execution ─────────

def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _prune_once_real():
    """Run the real _prune_state_loop() for exactly one iteration by
    patching asyncio.sleep:
      · first call  → return immediately (triggers the prune body)
      · second call → raise CancelledError (loop breaks cleanly)
    """
    import rate_limit as rl

    _n = 0

    async def _instant_then_cancel(_delay):
        nonlocal _n
        _n += 1
        if _n > 1:
            raise asyncio.CancelledError()

    with patch("asyncio.sleep", side_effect=_instant_then_cancel):
        await rl._prune_state_loop()


# ── H5-D: _ACTIVE_SESSIONS evicted via real prune loop ────────────────────

class TestH5DynamicActiveSessions:
    """Step 10 of the real _prune_state_loop must evict stale _ACTIVE_SESSIONS
    entries through the full coroutine path (lock, import, dict mutation)."""

    def test_stale_session_evicted_through_real_loop(self):
        """Insert a session idle > 12 h, run the real prune coroutine once,
        and assert the entry is gone — verifying the full code path."""
        import state as st

        old = dict(st._ACTIVE_SESSIONS)
        try:
            now = _time.time()
            st._ACTIVE_SESSIONS["ghost_user"] = now - 43201  # 12 h + 1 s
            st._ACTIVE_SESSIONS["alive_user"] = now - 60     # 1 min ago

            _run(_prune_once_real())

            assert "ghost_user" not in st._ACTIVE_SESSIONS, (
                "Entry idle > 12 h must be evicted by real _prune_state_loop step 10"
            )
            assert "alive_user" in st._ACTIVE_SESSIONS, (
                "Entry idle < 12 h must survive real prune"
            )
        finally:
            st._ACTIVE_SESSIONS.clear()
            st._ACTIVE_SESSIONS.update(old)

    def test_empty_active_sessions_prune_is_noop(self):
        """Step 10 must not crash when _ACTIVE_SESSIONS is empty."""
        import state as st

        old = dict(st._ACTIVE_SESSIONS)
        try:
            st._ACTIVE_SESSIONS.clear()
            _run(_prune_once_real())   # must not raise
            assert len(st._ACTIVE_SESSIONS) == 0
        finally:
            st._ACTIVE_SESSIONS.clear()
            st._ACTIVE_SESSIONS.update(old)

    def test_all_recent_sessions_survive(self):
        """When every session is recent, none must be evicted."""
        import state as st

        old = dict(st._ACTIVE_SESSIONS)
        try:
            now = _time.time()
            for i in range(10):
                st._ACTIVE_SESSIONS[f"user_{i}"] = now - (i * 100)  # 0..900 s

            _run(_prune_once_real())

            for i in range(10):
                assert f"user_{i}" in st._ACTIVE_SESSIONS, (
                    f"user_{i} (idle {i*100}s) must not be evicted — all under TTL"
                )
        finally:
            st._ACTIVE_SESSIONS.clear()
            st._ACTIVE_SESSIONS.update(old)


# ── H5-D: _signal_order_cache capped via real prune loop ──────────────────

class TestH5DynamicSignalOrderCache:
    """Step 10 of the real _prune_state_loop must cap _signal_order_cache
    at 2000 → 1000 through the full coroutine path."""

    def test_oversized_cache_trimmed_by_real_loop(self):
        """Fill _signal_order_cache to 2001, run the real prune once,
        and assert it was trimmed to exactly 1000."""
        import state as st

        old = dict(st._signal_order_cache)
        try:
            st._signal_order_cache.clear()
            for i in range(2001):
                st._signal_order_cache[f"s_{i:05d}"] = 1

            _run(_prune_once_real())

            assert len(st._signal_order_cache) == 1000, (
                f"Cache must be trimmed to 1000 by real prune, "
                f"got {len(st._signal_order_cache)}"
            )
        finally:
            st._signal_order_cache.clear()
            st._signal_order_cache.update(old)

    def test_under_limit_cache_untouched_by_real_loop(self):
        """Cache with ≤ 2000 entries must not be altered by the real prune."""
        import state as st

        old = dict(st._signal_order_cache)
        try:
            st._signal_order_cache.clear()
            for i in range(100):
                st._signal_order_cache[f"sig_{i}"] = 2
            expected = set(st._signal_order_cache.keys())

            _run(_prune_once_real())

            assert set(st._signal_order_cache.keys()) == expected, (
                "Cache under 2000 entries must not be modified by prune"
            )
        finally:
            st._signal_order_cache.clear()
            st._signal_order_cache.update(old)


# ── H5-D: _asn_path_clusters evicted via real prune loop ──────────────────

class TestH5DynamicAsnPathClusters:
    """Step 10 of the real _prune_state_loop must time-evict stale
    _asn_path_clusters entries (key[2] is minute epoch, evict if < now-10)."""

    def test_old_clusters_evicted_by_real_loop(self):
        """Clusters older than 10 minutes must be removed by the real loop."""
        import state as st

        old = dict(st._asn_path_clusters)
        try:
            now_min = int(_time.time() // 60)
            stale = (0, "/api", now_min - 20)
            fresh = (0, "/api", now_min - 3)
            st._asn_path_clusters[stale] = {"x"}
            st._asn_path_clusters[fresh] = {"y"}

            _run(_prune_once_real())

            assert stale not in st._asn_path_clusters, (
                "Cluster 20 min old must be evicted by real prune step 10"
            )
            assert fresh in st._asn_path_clusters, (
                "Cluster 3 min old must survive real prune step 10"
            )
        finally:
            st._asn_path_clusters.clear()
            st._asn_path_clusters.update(old)

    def test_current_minute_cluster_preserved(self):
        """A cluster created in the current minute must never be evicted."""
        import state as st

        old = dict(st._asn_path_clusters)
        try:
            now_min = int(_time.time() // 60)
            key = (1234, "/login", now_min)
            st._asn_path_clusters[key] = {"z"}

            _run(_prune_once_real())

            assert key in st._asn_path_clusters, (
                "Current-minute cluster must not be evicted"
            )
        finally:
            st._asn_path_clusters.clear()
            st._asn_path_clusters.update(old)

    def test_empty_clusters_prune_is_noop(self):
        """Empty _asn_path_clusters must survive prune without error."""
        import state as st

        old = dict(st._asn_path_clusters)
        try:
            st._asn_path_clusters.clear()
            _run(_prune_once_real())
            assert len(st._asn_path_clusters) == 0
        finally:
            st._asn_path_clusters.clear()
            st._asn_path_clusters.update(old)


# ── H5-D: _login_rate_limit inline LOGIN_BUCKET eviction (end-to-end) ─────

class TestH5DynamicLoginBucket:
    """Call the real _login_rate_limit coroutine and verify expired entries
    are purged inline — no helper replication."""

    def test_real_function_evicts_expired_on_call(self):
        """The real _login_rate_limit must evict expired windows without
        affecting the current IP's rate-limit decision."""
        from admin import users as u

        old = dict(u._LOGIN_BUCKET)
        try:
            now = _time.time()
            u._LOGIN_BUCKET["expired_ip"] = [now - 70, 5]  # window closed
            u._LOGIN_BUCKET["active_ip"]  = [now - 10, 2]  # window open

            result = _run(u._login_rate_limit("new_ip"))

            assert result is True, "Fresh IP must be allowed"
            assert "expired_ip" not in u._LOGIN_BUCKET, (
                "Expired login bucket entry must be evicted by real _login_rate_limit"
            )
            assert "active_ip" in u._LOGIN_BUCKET, (
                "Active login bucket entry must be preserved"
            )
        finally:
            u._LOGIN_BUCKET.clear()
            u._LOGIN_BUCKET.update(old)

    def test_blocked_ip_still_blocked_after_eviction(self):
        """An IP that has hit the 5-attempt limit must still be blocked
        even when other stale entries are evicted in the same call."""
        from admin import users as u

        old = dict(u._LOGIN_BUCKET)
        try:
            now = _time.time()
            u._LOGIN_BUCKET["noise"] = [now - 90, 5]   # will be evicted
            u._LOGIN_BUCKET["blocked_ip"] = [now - 5, 5]  # 5 attempts, within window

            # 6th attempt on blocked_ip — must be denied
            result = _run(u._login_rate_limit("blocked_ip"))

            assert result is False, (
                "IP at attempt limit must remain blocked even after stale eviction"
            )
            assert "noise" not in u._LOGIN_BUCKET
        finally:
            u._LOGIN_BUCKET.clear()
            u._LOGIN_BUCKET.update(old)

    def test_mass_eviction_doesnt_corrupt_bucket(self):
        """Evicting 500 expired entries must leave the bucket consistent
        for subsequent calls."""
        from admin import users as u

        old = dict(u._LOGIN_BUCKET)
        try:
            now = _time.time()
            for i in range(500):
                u._LOGIN_BUCKET[f"attacker_{i}"] = [now - 120, 5]

            # Two calls — both should succeed without KeyError or corruption
            r1 = _run(u._login_rate_limit("clean_ip_1"))
            r2 = _run(u._login_rate_limit("clean_ip_2"))

            assert r1 is True and r2 is True
            assert not any(f"attacker_{i}" in u._LOGIN_BUCKET for i in range(500)), (
                "All 500 expired entries must be evicted"
            )
        finally:
            u._LOGIN_BUCKET.clear()
            u._LOGIN_BUCKET.update(old)

    def test_window_reset_for_expired_ip_on_return(self):
        """When an IP's old window has expired, the next call must treat it
        as a fresh IP (window_start reset, count = 1)."""
        from admin import users as u

        old = dict(u._LOGIN_BUCKET)
        try:
            now = _time.time()
            # IP had 5 attempts 2 minutes ago — window expired
            u._LOGIN_BUCKET["returning_ip"] = [now - 120, 5]

            result = _run(u._login_rate_limit("returning_ip"))

            assert result is True, (
                "IP with expired window must be treated as fresh (allowed)"
            )
            assert u._LOGIN_BUCKET["returning_ip"][1] == 1, (
                "Count must reset to 1 for returning IP with expired window"
            )
        finally:
            u._LOGIN_BUCKET.clear()
            u._LOGIN_BUCKET.update(old)


# ── M2-D: dead-code removal verified via real function calls ───────────────

class TestM2DynamicScoringFunctions:
    """Call _load_signal_order_cache and _save_signal_order with a stubbed
    admin.mesh to confirm both exit cleanly (single except-return) and that
    no AttributeError or recursion occurs from the removed duplicate import."""

    def test_load_exits_cleanly_when_mesh_raises(self):
        """_load_signal_order_cache must return None (not raise) when
        _gw_local_id raises — single except-return path."""
        import sys, types, scoring

        dummy = types.ModuleType("admin.mesh")
        dummy._gw_local_id = lambda: (_ for _ in ()).throw(RuntimeError("no mesh"))
        saved = sys.modules.get("admin.mesh")
        sys.modules["admin.mesh"] = dummy
        try:
            result = scoring._load_signal_order_cache()
            assert result is None
        finally:
            if saved is None:
                sys.modules.pop("admin.mesh", None)
            else:
                sys.modules["admin.mesh"] = saved

    def test_save_exits_cleanly_when_mesh_raises(self):
        """_save_signal_order must return None (not raise) when _gw_local_id
        raises — single except-return path."""
        import sys, types, scoring

        dummy = types.ModuleType("admin.mesh")
        dummy._gw_local_id = lambda: (_ for _ in ()).throw(RuntimeError("no mesh"))
        saved = sys.modules.get("admin.mesh")
        sys.modules["admin.mesh"] = dummy
        try:
            result = scoring._save_signal_order("ua-empty", 2, "tester")
            assert result is None
        finally:
            if saved is None:
                sys.modules.pop("admin.mesh", None)
            else:
                sys.modules["admin.mesh"] = saved

    def test_load_no_infinite_retry_on_failure(self):
        """With the duplicate try removed, a failing _gw_local_id must trigger
        exactly ONE import attempt — verified by call-count instrumentation."""
        import sys, types, scoring

        call_log = []

        def _failing_id():
            call_log.append(1)
            raise RuntimeError("mesh offline")

        dummy = types.ModuleType("admin.mesh")
        dummy._gw_local_id = _failing_id
        saved = sys.modules.get("admin.mesh")
        sys.modules["admin.mesh"] = dummy
        try:
            scoring._load_signal_order_cache()
        finally:
            if saved is None:
                sys.modules.pop("admin.mesh", None)
            else:
                sys.modules["admin.mesh"] = saved

        assert len(call_log) == 1, (
            f"_gw_local_id must be called exactly once (dead duplicate removed), "
            f"got {len(call_log)} calls"
        )

    def test_save_no_infinite_retry_on_failure(self):
        """With the duplicate try removed, _save_signal_order must call
        _gw_local_id exactly once on failure."""
        import sys, types, scoring

        call_log = []

        def _failing_id():
            call_log.append(1)
            raise RuntimeError("mesh offline")

        dummy = types.ModuleType("admin.mesh")
        dummy._gw_local_id = _failing_id
        saved = sys.modules.get("admin.mesh")
        sys.modules["admin.mesh"] = dummy
        try:
            scoring._save_signal_order("bot-score", 3, "tester")
        finally:
            if saved is None:
                sys.modules.pop("admin.mesh", None)
            else:
                sys.modules["admin.mesh"] = saved

        assert len(call_log) == 1, (
            f"_gw_local_id must be called exactly once (dead duplicate removed), "
            f"got {len(call_log)} calls"
        )

    def test_load_source_has_single_import(self):
        """Static guard: inspect source to confirm exactly one occurrence of
        the _gw_local_id import (structural regression check)."""
        import inspect, scoring
        src = inspect.getsource(scoring._load_signal_order_cache)
        count = src.count("from admin.mesh import _gw_local_id")
        assert count == 1, (
            f"_load_signal_order_cache must have exactly 1 import of _gw_local_id, "
            f"found {count}"
        )

    def test_save_source_has_single_import(self):
        """Static guard: inspect source to confirm exactly one occurrence of
        the _gw_local_id import in _save_signal_order."""
        import inspect, scoring
        src = inspect.getsource(scoring._save_signal_order)
        count = src.count("from admin.mesh import _gw_local_id")
        assert count == 1, (
            f"_save_signal_order must have exactly 1 import of _gw_local_id, "
            f"found {count}"
        )
