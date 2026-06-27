"""
QA tests — 1.8.15 perf quick-wins (post pt4.tech slowness investigation).

Five hot-path optimisations:

#2  json.dumps + db_queue.put_nowait + slog moved OUTSIDE state_lock in record()
#3  compute_ja4h() skipped when JA4H_DENY_ENABLED=0 AND JA4H_LOG_ENABLED=0
#4  JA4H telemetry write no longer acquires state_lock (single attr assign)
#5  _decay_risk() skipped when risk_score=0 AND risk_by_reason empty
#6  _llm_heuristic.observe() skipped on static asset paths
#8  current_vhost_host() cached once per record() call (was 3 ContextVar reads)

These tests pin the invariants so future edits don't accidentally regress the
hot path. Each fix is sensitive to a specific source pattern; the test reads
the source and verifies the structural property.

Coverage:
  TestRecordSerializationOutsideLock   — #2 + #8: json.dumps / db_queue puts off-lock
  TestDecaySkipOnZeroRisk              — #5: _decay_risk gated on score>0 or risk_by_reason
  TestJA4HShortCircuit                 — #3 + #4: compute_ja4h gated; no state_lock for write
  TestLLMHeuristicSkipsStatic          — #6: _llm_heuristic.observe skipped on static paths
  TestStaticAssetHelper                — _is_static_asset_path exposed + correct
  TestJA4HLogEnabledKnob               — JA4H_LOG_ENABLED config knob exists
"""
import pathlib
import re

_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_MET_SRC  = (_ROOT / "core" / "metrics.py").read_text(encoding="utf-8")
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_HLP_SRC  = (_ROOT / "helpers.py").read_text(encoding="utf-8")
_CFG_SRC  = (_ROOT / "config.py").read_text(encoding="utf-8")


def _record_fn_body() -> str:
    """Extract the body of async def record() from metrics.py."""
    start = _MET_SRC.find("async def record(")
    assert start != -1
    # Function ends at the next top-level `async def` / `def ` / EOF
    next_def = _MET_SRC.find("\nasync def ", start + 10)
    if next_def == -1:
        next_def = _MET_SRC.find("\ndef ", start + 10)
    return _MET_SRC[start: next_def if next_def != -1 else len(_MET_SRC)]


# ── #2 + #8 — Serialization & vhost-cache outside state_lock ─────────────────

class TestRecordSerializationOutsideLock:
    """The hot path: record() must hold state_lock ONLY for state mutation.
    json.dumps + db_queue.put_nowait + slog run AFTER the lock is released."""

    def test_state_lock_block_does_not_contain_json_dumps(self):
        body = _record_fn_body()
        lock_idx = body.find("async with state_lock:")
        assert lock_idx != -1, "state_lock block not found in record()"
        # Find the close of the locked block — first dedent (a line that
        # starts with content but NOT 8+ spaces of indent inside the lock).
        # Simpler heuristic: the locked block ends where the "End of locked
        # region" marker comment is.
        end_marker = body.find("End of locked region")
        assert end_marker != -1, (
            "record() must have an explicit 'End of locked region' marker "
            "so reviewers can see where the lock is released"
        )
        locked_block = body[lock_idx: end_marker]
        # json.dumps inside the lock is the regression we are guarding against.
        # The snapshot pattern (dict(...)) is fine; json.dumps on those snapshots
        # must happen AFTER the marker.
        # Strip comment lines so the regression check doesn't false-positive
        # on perf-explanation comments that legitimately reference json.dumps.
        code_only = "\n".join(
            line for line in locked_block.split("\n")
            if not line.lstrip().startswith("#")
        )
        assert "json.dumps(" not in code_only, (
            "json.dumps() call inside state_lock holds the lock during "
            "serialisation. Snapshot dicts inside the lock, serialise outside."
        )

    def test_db_queue_put_nowait_outside_lock(self):
        body = _record_fn_body()
        end_marker = body.find("End of locked region")
        assert end_marker != -1
        post_lock = body[end_marker:]
        # The 4 db_queue.put_nowait calls (event + upsert_client + upsert_timeline
        # + set_kv batch) must all live below the marker.
        n = post_lock.count("db_queue.put_nowait(")
        assert n >= 3, (
            f"Expected db_queue.put_nowait calls outside the lock; found {n}. "
            "Either the refactor was reverted or split incorrectly."
        )

    def test_slog_outside_lock(self):
        body = _record_fn_body()
        end_marker = body.find("End of locked region")
        assert end_marker != -1
        post_lock = body[end_marker:]
        assert 'slog("request"' in post_lock, (
            'slog("request", ...) must run AFTER state_lock is released '
            "so stdout write latency doesn't serialise concurrent requests"
        )

    def test_pg_mirror_executor_outside_lock(self):
        body = _record_fn_body()
        end_marker = body.find("End of locked region")
        assert end_marker != -1
        post_lock = body[end_marker:]
        assert "run_in_executor" in post_lock and "pg_insert_event" in post_lock, (
            "Postgres mirror (pg_insert_event run_in_executor) must run "
            "outside state_lock — was already off-loop but in pre-refactor "
            "code it was inside the lock block"
        )

    def test_vhost_cached_once(self):
        body = _record_fn_body()
        # `_vhost = current_vhost_host()` should appear once at the top.
        first_call = body.find("current_vhost_host()")
        assert first_call != -1, "current_vhost_host() must be called in record()"
        # Count total occurrences — pre-fix was 3, post-fix is 1.
        n = body.count("current_vhost_host()")
        assert n == 1, (
            f"current_vhost_host() called {n} times in record(); expected 1 "
            "(was 3 pre-fix — ContextVar read repetition)"
        )
        # The cached value should be used multiple times via `_vhost`.
        assert body.count("_vhost") >= 3, (
            "Cached _vhost variable should be used at multiple sites "
            "(last_vhost, _evt vhost, persist payload)"
        )


# ── #5 — Decay skipped on zero-risk identities ───────────────────────────────

class TestDecaySkipOnZeroRisk:
    """_decay_risk() is a no-op on identities with no accumulated risk.
    Skipping the call saves ~2µs per record() on clean traffic (~95% of req)."""

    def test_decay_call_is_gated(self):
        body = _record_fn_body()
        # Pattern: `if s.risk_score > 0 or s.risk_by_reason: _decay_risk(...)`
        decay_idx = body.find("_decay_risk(s, now())")
        assert decay_idx != -1, "_decay_risk(s, now()) call not found"
        # Look 200 chars before the call for the guard
        guard_block = body[max(0, decay_idx - 300): decay_idx]
        assert "risk_score" in guard_block and "risk_by_reason" in guard_block, (
            "_decay_risk must be gated by `if s.risk_score > 0 or s.risk_by_reason` "
            "— skipping the call on clean traffic saves CPU on the hot path"
        )


# ── #3 + #4 — JA4H gated + no state_lock for write ───────────────────────────

class TestJA4HShortCircuit:
    """compute_ja4h is only called when JA4H_DENY_ENABLED or JA4H_LOG_ENABLED.
    The telemetry write happens without acquiring state_lock."""

    def test_ja4h_compute_is_gated(self):
        # Find the protect() invocation site
        idx = _PH_SRC.find("from identity import compute_ja4h")
        assert idx != -1, "compute_ja4h import not found"
        # Within 300 chars BEFORE the import, JA4H_DENY_ENABLED or JA4H_LOG_ENABLED guard
        guard_block = _PH_SRC[max(0, idx - 400): idx]
        assert ("JA4H_DENY_ENABLED" in guard_block
                and "JA4H_LOG_ENABLED" in guard_block), (
            "compute_ja4h must be gated by `if JA4H_DENY_ENABLED or JA4H_LOG_ENABLED`"
        )

    def test_ja4h_write_no_state_lock(self):
        # Locate the ja4h-write block and ensure NO `async with state_lock:`
        # appears between it and the JA4H_DENY check.
        # The write pattern is now: `ip_state.get(track_key)`; `s.last_ja4h = ja4h`
        idx = _PH_SRC.find("last_ja4h = ja4h")
        assert idx != -1, "last_ja4h write not found"
        # Look 200 chars before — must NOT have `async with state_lock:`
        window = _PH_SRC[max(0, idx - 200): idx]
        assert "async with state_lock:" not in window, (
            "JA4H write must NOT acquire state_lock — single attr assign is "
            "atomic under GIL, and we use ip_state.get() to avoid LRU mutation"
        )
        # Must use ip_state.get(track_key) — NOT ip_state[track_key]
        assert "ip_state.get(track_key)" in window or "ip_state.get(track_key)" in _PH_SRC[idx-300:idx+100], (
            "JA4H write must use ip_state.get(track_key) to avoid mutating "
            "the LRU OrderedDict on every request"
        )


# ── #6 — LLM heuristic skips static assets ───────────────────────────────────

class TestLLMHeuristicSkipsStatic:
    """_llm_heuristic.observe must be skipped for static asset paths; the
    heuristic detects identities pulling HTML without subresources, so a
    sub-resource request can't be a positive signal anyway."""

    def test_observe_gated_on_static_check(self):
        idx = _PH_SRC.find("_llm_heuristic.observe(")
        assert idx != -1, "_llm_heuristic.observe call not found"
        # Look 200 chars before for the static-asset guard
        guard_block = _PH_SRC[max(0, idx - 200): idx]
        assert "_is_static_asset_path" in guard_block, (
            "_llm_heuristic.observe must be gated by `not _is_static_asset_path(...)`"
        )


# ── Static-asset helper ──────────────────────────────────────────────────────

class TestStaticAssetHelper:
    """The shared _is_static_asset_path helper must exist in helpers.py and
    be exported via the (underscore-explicit) import in proxy_handler.py."""

    def test_helper_defined_in_helpers(self):
        assert "def _is_static_asset_path(" in _HLP_SRC, (
            "_is_static_asset_path must be defined in helpers.py"
        )

    def test_helper_imported_in_proxy_handler(self):
        idx = _PH_SRC.find("from helpers import (")
        end = _PH_SRC.find(")", idx)
        import_block = _PH_SRC[idx:end]
        assert "_is_static_asset_path" in import_block, (
            "_is_static_asset_path must be explicitly imported in proxy_handler.py"
        )

    def test_helper_correctly_classifies(self):
        import importlib
        h = importlib.import_module("helpers")
        # Static paths → True
        for p in ("/static/app.css", "/dist/main.js", "/img/hero.png",
                   "/fonts/sans.woff2", "/m.mp4", "/doc.pdf"):
            assert h._is_static_asset_path(p), f"{p!r} should be classified static"
        # Non-static paths → False
        for p in ("/", "/api/v1/users", "/login", "/.env", "/products"):
            assert not h._is_static_asset_path(p), (
                f"{p!r} should NOT be classified static"
            )

    def test_helper_lists_common_extensions(self):
        # Sanity: list must cover the obvious sub-resource types operators
        # would expect to be skipped (regression guard against accidental edits).
        for ext in (".css", ".js", ".png", ".woff2", ".webp", ".svg", ".mp4"):
            assert ext in _HLP_SRC, f"extension {ext!r} missing from _STATIC_ASSET_EXTS"


# ── #11 — Conditional LRU promotion ──────────────────────────────────────────

class TestConditionalLruPromotion:
    """`_BoundedIpStateDict` must NOT call move_to_end on every access when
    well below cap. Above the threshold (default 50% of maxsize), LRU kicks in.
    """

    def test_threshold_constant_defined(self):
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent / "state.py").read_text()
        assert "_LRU_PROMOTE_THRESHOLD" in src, (
            "_BoundedIpStateDict must define _LRU_PROMOTE_THRESHOLD constant "
            "so the LRU-promote heuristic is documented + tunable in one place"
        )

    def test_should_promote_helper_exists(self):
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent / "state.py").read_text()
        assert "def _should_promote(" in src, (
            "_should_promote() helper missing — needed for clean call sites"
        )

    def test_below_threshold_no_promotion(self):
        """At 10% of cap, accessing an existing key must NOT change ordering."""
        from state import _BoundedIpStateDict, IpState
        d = _BoundedIpStateDict(maxsize=1000)  # threshold = 500
        # Fill to 100 entries (10% — below threshold)
        for i in range(100):
            d[f"k{i:03d}"] = IpState()
        # Snapshot insertion order
        original = list(d.keys())
        # Access k000 multiple times — should NOT bubble to end
        for _ in range(5):
            _ = d["k000"]
            _ = d.get("k050")
        after = list(d.keys())
        assert original == after, (
            "Below LRU threshold, accesses must NOT reorder entries — "
            "saves move_to_end overhead at normal load"
        )

    def test_above_threshold_promotion_fires(self):
        """At 80% of cap, accessing must promote so LRU eviction works."""
        from state import _BoundedIpStateDict, IpState
        d = _BoundedIpStateDict(maxsize=10)  # threshold = 5
        for i in range(8):
            d[f"k{i}"] = IpState()
        # At 80% > 50% threshold — promotion should fire
        _ = d["k0"]  # access oldest
        keys = list(d.keys())
        assert keys[-1] == "k0", (
            f"Above LRU threshold, accessing oldest key must promote it to end; "
            f"got order {keys}"
        )

    def test_capacity_overflow_still_evicts(self):
        """When inserting at cap, oldest must be evicted regardless of threshold."""
        from state import _BoundedIpStateDict, IpState
        d = _BoundedIpStateDict(maxsize=3)
        d["a"] = IpState()
        d["b"] = IpState()
        d["c"] = IpState()
        d["d"] = IpState()  # forces eviction
        assert "a" not in d, "Oldest key must be evicted on overflow"
        assert "d" in d
        assert len(d) == 3

    def test_new_insertion_at_cap_promotes_self(self):
        """When inserting a new key at cap, the new key must be promoted to
        end so it doesn't get immediately evicted on the next insert."""
        from state import _BoundedIpStateDict, IpState
        d = _BoundedIpStateDict(maxsize=3)
        d["a"] = IpState(); d["b"] = IpState(); d["c"] = IpState()
        d["d"] = IpState()
        # d should now be last; next insert should evict 'b' (oldest of 'b','c','d')
        d["e"] = IpState()
        assert "b" not in d, (
            f"After cap-overflow insert, 'b' should now be oldest and "
            f"get evicted by next insert; got keys {list(d.keys())}"
        )


# ── #12 — User-Agent cache helper ────────────────────────────────────────────

class TestUserAgentCache:
    """`_ua_of(request)` caches the User-Agent header on request["_ua"] so the
    ~7 hot-path reads per request collapse to one header parse."""

    def test_helper_defined_in_helpers(self):
        assert "def _ua_of(" in _HLP_SRC, (
            "_ua_of() helper must be defined in helpers.py"
        )

    def test_helper_caches_on_request(self):
        idx = _HLP_SRC.find("def _ua_of(")
        body = _HLP_SRC[idx: idx + 800]
        assert 'request["_ua"]' in body or "request['_ua']" in body, (
            "_ua_of must store the captured UA on request[\"_ua\"]"
        )
        assert '"_ua" not in request' in body or "'_ua' not in request" in body, (
            "_ua_of must guard the capture with a `'_ua' not in request` check "
            "so repeated calls don't re-parse the header"
        )

    def test_helper_imported_in_proxy_handler(self):
        idx = _PH_SRC.find("from helpers import (")
        end = _PH_SRC.find(")", idx)
        import_block = _PH_SRC[idx:end]
        assert "_ua_of" in import_block, (
            "_ua_of must be imported in proxy_handler.py"
        )

    def test_no_raw_user_agent_reads_in_proxy_handler(self):
        """All `request.headers.get('User-Agent', '')` patterns must go through
        the cached helper. This is the regression guard."""
        # Allow zero raw lookups
        count = _PH_SRC.count('request.headers.get("User-Agent"')
        assert count == 0, (
            f"Found {count} raw `request.headers.get(\"User-Agent\"...)` calls "
            "in proxy_handler.py — must use `_ua_of(request)` for the cache"
        )

    def test_helper_returns_cached_value_on_second_call(self):
        """End-to-end behavioural test: second call must return the cached
        value even if the underlying header object is mutated/removed."""
        import importlib
        h = importlib.import_module("helpers")
        # Mock a minimal aiohttp Request-like object: headers + dict storage
        class _FakeHeaders:
            def __init__(self): self._h = {"User-Agent": "first"}
            def get(self, k, d=""): return self._h.get(k, d)
        class _FakeReq:
            def __init__(self):
                self.headers = _FakeHeaders()
                self._store = {}
            def __contains__(self, k): return k in self._store
            def __getitem__(self, k): return self._store[k]
            def __setitem__(self, k, v): self._store[k] = v
        r = _FakeReq()
        first = h._ua_of(r)
        assert first == "first"
        # Mutate header underneath — cached value must persist
        r.headers._h["User-Agent"] = "second"
        second = h._ua_of(r)
        assert second == "first", (
            f"_ua_of cache must persist across calls; got {second!r}"
        )


# ── JA4H_LOG_ENABLED knob ────────────────────────────────────────────────────

class TestJA4HLogEnabledKnob:
    """JA4H_LOG_ENABLED is the new optional knob to keep capturing JA4H for
    telemetry even when the deny-list isn't in use."""

    def test_knob_defined_in_config(self):
        assert "JA4H_LOG_ENABLED" in _CFG_SRC, (
            "JA4H_LOG_ENABLED missing from config.py"
        )

    def test_knob_default_off(self):
        m = re.search(r'JA4H_LOG_ENABLED\s*=\s*os\.environ\.get\([^"]*"JA4H_LOG_ENABLED"\s*,\s*"(\d)"',
                       _CFG_SRC)
        assert m, "JA4H_LOG_ENABLED env-read pattern not found"
        assert m.group(1) == "0", (
            "JA4H_LOG_ENABLED must default to OFF — operators opt in when they "
            "want telemetry; default-on would re-introduce the per-request cost"
        )
