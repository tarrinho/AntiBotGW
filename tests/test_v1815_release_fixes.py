"""
1.8.15 — security + perf fix regression suite.

Covers all P0/P1/P2 items from the threat model:
  E-2  : host gate consults VHOSTS when ALLOWED_HOSTS empty
  E-3  : @_require_csrf on db_vacuum_endpoint + db_switch + admin_ips +
         secrets + rotate_keys + signal_orders
  T-2  : ALLOW_PRIVATE_UPSTREAM default = "0" (guard armed)
  P0a  : legacy 24h VACUUM removed from db_writer_loop
  P0b  : VACUUM runs via asyncio.to_thread (does not block event loop)
  P1a  : per-upstream decoy fetch lock (_decoy_lock_for)
  P1b  : vc() memoizes fallback module lookups (_VC_MEMO)
  P1c  : silent decoy short-circuits when circuit breaker is OPEN
  P1d  : _detector_record evicts when over _DETECTOR_REASONS_CAP
  P1e  : _prune_state_loop prunes _pow_seen / _honeypot_ip_clusters / _LOGIN_BUCKET
  P1f  : _periodic_404_refresh_loop uses asyncio.gather
  P2a  : GW_AUDIT_RETENTION_DAYS knob + prune_gw_audit helper
  P2b  : _decoy_entry evicts LRU at len(VHOSTS) + 8
"""
import asyncio
import importlib
import os
import pathlib
import re
import sys
import sqlite3
import time
from contextlib import asynccontextmanager

import pytest


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_CFG_SRC  = (_ROOT / "config.py").read_text(encoding="utf-8")
_VH_SRC   = (_ROOT / "vhost.py").read_text(encoding="utf-8")
_SQ_SRC   = (_ROOT / "db" / "sqlite.py").read_text(encoding="utf-8")
_RL_SRC   = (_ROOT / "rate_limit.py").read_text(encoding="utf-8")


# ── E-2 host gate ──────────────────────────────────────────────────────────

class TestHostGateUsesVhosts:
    def test_gate_consults_vhosts_when_allowed_hosts_empty(self):
        """The Layer-0 host gate must enter when ALLOWED_HOSTS OR VHOSTS is
        populated — not ALLOWED_HOSTS alone."""
        idx = _PH_SRC.find("host-header-based reconnaissance")
        block = _PH_SRC[idx: idx + 1500]
        # Must reference VHOSTS in the gate condition
        assert "_VHOSTS_LAYER0" in block, (
            "Layer-0 host gate must import VHOSTS and use it in the gate "
            "condition; otherwise vhost-implicit allowlist is bypassed when "
            "ALLOWED_HOSTS is empty"
        )
        # iter-11 added an admin-path exemption, so the condition is now
        # `if (ALLOWED_HOSTS or _VHOSTS_LAYER0) and not _is_admin_path(...)`.
        # The invariant this test guards is unchanged: the gate must consult
        # BOTH ALLOWED_HOSTS and the implicit vhost allowlist (the OR).
        assert "ALLOWED_HOSTS or _VHOSTS_LAYER0" in block, (
            "Gate condition must consult `ALLOWED_HOSTS or _VHOSTS_LAYER0` "
            "so the vhost-implicit allowlist applies when ALLOWED_HOSTS is empty"
        )
        assert "not _is_admin_path(request.path)" in block, (
            "Layer-0 host gate must exempt admin paths (iter-11) — they are "
            "IP+auth gated, and Host-matching would otherwise lock the "
            "operator out of the dashboard when VHOSTS is configured"
        )


# ── E-3 CSRF on state-mutating endpoints ───────────────────────────────────

class TestCsrfOnMutatingEndpoints:
    @pytest.mark.parametrize("endpoint", [
        "db_vacuum_endpoint",
        "db_switch_endpoint",
        "signal_orders_endpoint",
        "admin_ips_endpoint",
        "secrets_endpoint",
        "rotate_keys_endpoint",
    ])
    def test_decorator_present(self, endpoint):
        idx = _PH_SRC.find(f"async def {endpoint}(")
        assert idx != -1, f"{endpoint} not found"
        # Walk back to the previous non-blank line; it must be @_require_csrf
        # (allow up to 5 lines of decorators / docstring before it).
        prefix = _PH_SRC[max(0, idx - 200): idx]
        assert "@_require_csrf" in prefix, (
            f"{endpoint} must carry @_require_csrf — state-mutating endpoint"
        )


# ── T-2 ALLOW_PRIVATE_UPSTREAM default ─────────────────────────────────────

class TestAllowPrivateUpstreamDefault:
    def test_default_is_zero(self):
        idx = _CFG_SRC.find("ALLOW_PRIVATE_UPSTREAM = ")
        block = _CFG_SRC[idx: idx + 120]
        assert '"0"' in block, (
            "ALLOW_PRIVATE_UPSTREAM env default must be '0' (guard armed). "
            "Setting it to '1' opens an SSRF surface when an admin/maintainer "
            "configures a vhost UPSTREAM pointing at internal hosts."
        )

    def test_docstring_matches(self):
        """vhost.py:_assert_upstream_public docstring must NOT claim
        ALLOW_PRIVATE_UPSTREAM=1 is the default (stale comment was a bug)."""
        idx = _VH_SRC.find("def _assert_upstream_public(")
        block = _VH_SRC[idx: idx + 800]
        assert "ALLOW_PRIVATE_UPSTREAM=0 (guard armed)" in block, (
            "docstring must state the actual default (0 = armed)"
        )


# ── P0a legacy VACUUM removed ──────────────────────────────────────────────

class TestLegacyVacuumRemoved:
    def test_no_vacuum_in_writer_loop(self):
        idx = _SQ_SRC.find("async def db_writer_loop(")
        assert idx != -1
        # Take the function body — up to the next top-level `def `/`async def `.
        nxt = _SQ_SRC.find("\nasync def ", idx + 10)
        if nxt == -1:
            nxt = _SQ_SRC.find("\ndef ", idx + 10)
        block = _SQ_SRC[idx: nxt if nxt != -1 else idx + 8000]
        assert 'conn.execute("VACUUM")' not in block, (
            "db_writer_loop must not run VACUUM inline — the new scheduler "
            "(core/proxy_handler.py:_vacuum_scheduler_loop) owns daily VACUUM "
            "with migration guard + single-flight lock + asyncio.to_thread."
        )


# ── P0b VACUUM via asyncio.to_thread ───────────────────────────────────────

class TestVacuumViaToThread:
    def test_execute_wrapped_in_to_thread(self):
        idx = _PH_SRC.find("async def _db_vacuum_execute(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "asyncio.to_thread" in block, (
            "_db_vacuum_execute must call asyncio.to_thread() so the event "
            "loop stays responsive during multi-second VACUUM"
        )
        # The wrapped function must call VACUUM
        assert 'conn.execute("VACUUM")' in block or '_conn.execute("VACUUM")' in block, (
            "VACUUM SQL must be inside the threaded function"
        )


# ── P1a per-upstream decoy lock ────────────────────────────────────────────

class TestPerUpstreamDecoyLock:
    def test_helper_exists(self):
        assert "def _decoy_lock_for(upstream:" in _PH_SRC, (
            "_decoy_lock_for(upstream) helper must exist"
        )

    def test_silent_decoy_uses_per_upstream_lock(self):
        idx = _PH_SRC.find("async def _silent_decoy_response(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_decoy_lock_for(_vhost_upstream)" in block, (
            "homepage-decoy refresh must acquire the per-upstream lock"
        )


# ── P1b vc() memoize ───────────────────────────────────────────────────────

class TestVcMemoize:
    def test_memo_dict_exists(self):
        assert "_VC_MEMO" in _VH_SRC, (
            "vc() must memoize fallback module per attribute name"
        )

    def test_vc_consults_memo_before_scan(self):
        idx = _VH_SRC.find("def vc(name:")
        nxt = _VH_SRC.find("\ndef ", idx + 1)
        block = _VH_SRC[idx: nxt]
        # Memo lookup happens BEFORE the sys.modules scan
        memo_idx = block.find("_VC_MEMO.get(name)")
        scan_idx = block.find("for _mod in list(_sys.modules.values())")
        assert memo_idx != -1 and scan_idx != -1
        assert memo_idx < scan_idx, (
            "vc() must check _VC_MEMO before the cold sys.modules scan"
        )


# ── P1c decoy honors circuit breaker ───────────────────────────────────────

class TestDecoyHonorsCircuit:
    def test_decoy_short_circuits_on_open_circuit(self):
        idx = _PH_SRC.find("async def _silent_decoy_response(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_circuit_is_open()" in block, (
            "_silent_decoy_response must short-circuit when the upstream "
            "circuit breaker is open (avoids serializing 10s timeouts under "
            "the lock during upstream outage)"
        )
        # Condition must guard the homepage refresh block
        m = re.search(
            r"\(not _slot\[.body.\] or \(n - _slot\[.fetched_at.\]\) > _DECOY_TTL\) and not _circuit_is_open\(\)",
            block)
        assert m, (
            "The cache-refresh condition must include `and not _circuit_is_open()`"
        )


# ── P1d _detector_record reasons cap ───────────────────────────────────────

class TestDetectorReasonsCap:
    def test_cap_constant_exists(self):
        assert "_DETECTOR_REASONS_CAP" in _PH_SRC, (
            "_DETECTOR_REASONS_CAP must bound _detector_hits / _detector_latency"
        )

    def test_eviction_logic_present(self):
        idx = _PH_SRC.find("def _detector_record(")
        nxt = _PH_SRC.find("\ndef ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_DETECTOR_REASONS_CAP" in block, (
            "_detector_record body must consult the cap"
        )
        assert "_detector_hits.pop" in block, (
            "Eviction must drop entries from _detector_hits"
        )
        assert "_detector_latency.pop" in block, (
            "Eviction must drop matching entries from _detector_latency"
        )


# ── P1e prune additions ────────────────────────────────────────────────────

class TestPruneStateLoopAdditions:
    @pytest.mark.parametrize("dict_name", [
        "_pow_seen",
        "_honeypot_ip_clusters",
        "_LOGIN_BUCKET",
    ])
    def test_prune_present(self, dict_name):
        assert dict_name in _RL_SRC, (
            f"_prune_state_loop must prune {dict_name} to bound memory under "
            "rotating-key attacks"
        )


# ── P1f _periodic_404_refresh parallel ─────────────────────────────────────

class TestPeriodicRefreshParallel:
    def test_uses_asyncio_gather(self):
        idx = _PH_SRC.find("async def _periodic_404_refresh_loop(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "asyncio.gather" in block, (
            "_periodic_404_refresh_loop must use asyncio.gather to refresh "
            "upstreams in parallel; serial loop blocked all on one slow upstream"
        )
        assert "return_exceptions=True" in block, (
            "gather must use return_exceptions=True so one failure doesn't "
            "cancel siblings"
        )


# ── P2a gw_audit retention ─────────────────────────────────────────────────

class TestGwAuditRetention:
    def test_config_knob_defined(self):
        assert "GW_AUDIT_RETENTION_DAYS" in _CFG_SRC, (
            "GW_AUDIT_RETENTION_DAYS env knob must be in config.py"
        )

    def test_default_is_365(self):
        idx = _CFG_SRC.find("GW_AUDIT_RETENTION_DAYS")
        block = _CFG_SRC[idx: idx + 200]
        assert '"365"' in block, "Default must be 365 days"

    def test_prune_helper_exists(self):
        assert "def prune_gw_audit(" in _SQ_SRC, (
            "prune_gw_audit(retention_days) helper must exist in db/sqlite.py"
        )

    def test_prune_loop_calls_helper(self):
        assert "prune_gw_audit" in _RL_SRC, (
            "_prune_state_loop must call prune_gw_audit on the events-prune cadence"
        )


# ── P2b _decoy_cache LRU bound ─────────────────────────────────────────────

class TestDecoyCacheLru:
    def test_cap_constant_exists(self):
        assert "_DECOY_CACHE_MIN_SLOTS" in _PH_SRC, (
            "_DECOY_CACHE_MIN_SLOTS bound for decoy caches must be defined"
        )

    def test_decoy_entry_evicts_lru(self):
        idx = _PH_SRC.find("def _decoy_entry(")
        nxt = _PH_SRC.find("\n\n", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_decoy_cache_cap()" in block, (
            "_decoy_entry must consult _decoy_cache_cap() on insert"
        )
        assert "fetched_at" in block and "sort" in block, (
            "_decoy_entry must evict the LRU entry by fetched_at on overflow"
        )


# ── Functional smoke: per-upstream lock holds independence ────────────────

def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestPerUpstreamLockFunctional:
    def test_distinct_upstreams_get_distinct_locks(self):
        sys.path.insert(0, str(_ROOT))
        import core.proxy_handler as _cph
        importlib.reload(_cph) if False else None  # don't reload — heavy
        async def go():
            la = _cph._decoy_lock_for("http://up-a/")
            lb = _cph._decoy_lock_for("http://up-b/")
            assert la is not lb, "distinct upstreams must get distinct locks"
            # Same upstream returns the same lock
            la2 = _cph._decoy_lock_for("http://up-a/")
            assert la is la2, "same upstream must return the same lock object"
        _run(go())


# ── Functional smoke: prune_gw_audit deletes old rows ──────────────────────

class TestPruneGwAuditFunctional:
    def test_deletes_rows_past_retention(self, tmp_path):
        sys.path.insert(0, str(_ROOT))
        # Avoid importing db/sqlite (which init-binds DB_PATH) — exercise the
        # helper against an isolated DB by patching its DB_PATH module global.
        import db.sqlite as _sq
        orig = _sq.DB_PATH
        _sq.DB_PATH = str(tmp_path / "t.db")
        try:
            conn = sqlite3.connect(_sq.DB_PATH)
            conn.executescript(
                "CREATE TABLE gw_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "ts REAL NOT NULL, action TEXT NOT NULL, gw_id TEXT, "
                "actor TEXT, details TEXT);"
            )
            now = time.time()
            # 5 rows: 3 old (90 days ago), 2 recent
            rows = [
                (now - 90 * 86400, "db_vacuum", "gw", "alice", "{}"),
                (now - 90 * 86400, "db_vacuum", "gw", "alice", "{}"),
                (now - 90 * 86400, "db_vacuum", "gw", "alice", "{}"),
                (now - 1, "db_vacuum", "gw", "alice", "{}"),
                (now, "db_vacuum", "gw", "alice", "{}"),
            ]
            conn.executemany(
                "INSERT INTO gw_audit (ts, action, gw_id, actor, details) "
                "VALUES (?, ?, ?, ?, ?)", rows)
            conn.commit()
            conn.close()
            deleted = _sq.prune_gw_audit(30)  # 30-day retention
            assert deleted == 3, f"expected 3 rows pruned, got {deleted}"
            conn = sqlite3.connect(_sq.DB_PATH)
            remaining = conn.execute("SELECT COUNT(*) FROM gw_audit").fetchone()[0]
            conn.close()
            assert remaining == 2, f"2 rows must remain; got {remaining}"
        finally:
            _sq.DB_PATH = orig
