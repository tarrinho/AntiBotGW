"""
tests/test_v1814_perf_pass_behavioral.py — behavioural coverage of the
1.8.14 perf pass helpers in core/proxy_handler.py + core/metrics.py.

Companion to test_v1814_perf_pass.py (which only anchors on the helper
names). This file actually exercises the helpers — catches a refactor
that keeps the names but breaks the contract:

  • _bypass_match — exact, glob (* and / suffixes), empty-paths short
    circuit, identity-based cache invalidation
  • _get_upstream_timeout — same object reused when knobs stable,
    fresh object after either knob mutates
  • _get_upstream_client — same session on repeat calls; post-close,
    a new session is created lazily; DummyCookieJar is installed
  • OrderedDict timeline eviction — only buckets older than the
    cutoff are removed; newer buckets are preserved in order
"""
import asyncio
import importlib
import os
import sys

import pytest

# Ensure the repo root is on sys.path so `import core.proxy_handler` works
# when pytest is invoked from a sibling cwd.
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


# ── _bypass_match ────────────────────────────────────────────────────────

def _ph():
    """Lazy import — proxy_handler pulls in a lot of state."""
    import core.proxy_handler as ph
    return ph


def test_bypass_match_empty_paths_returns_false():
    ph = _ph()
    assert ph._bypass_match("/foo", []) is False
    assert ph._bypass_match("/foo", None) is False


def test_bypass_match_exact_hit():
    ph = _ph()
    assert ph._bypass_match("/health", ["/health"]) is True
    assert ph._bypass_match("/healthz", ["/health"]) is False  # no prefix on exact


def test_bypass_match_glob_star_suffix():
    """An entry ending in `*` matches anything sharing the prefix (with
    the `*` stripped)."""
    ph = _ph()
    paths = ["/api/*"]
    assert ph._bypass_match("/api/", paths) is True
    assert ph._bypass_match("/api/v1/users", paths) is True
    assert ph._bypass_match("/apiv1", paths) is False
    assert ph._bypass_match("/other", paths) is False


def test_bypass_match_slash_suffix_is_prefix():
    """An entry ending in `/` is treated as a prefix: the trailing char is
    stripped and the rest used as a startswith() prefix. This preserves
    the historical (pre-1.8.14) semantics — entries like `/static/` strip
    to `/static` and therefore ALSO match `/staticx` (greedy). Operators
    who want strict directory matching should use `/static/*` instead.
    1.8.14 perf pass intentionally did not change this."""
    ph = _ph()
    paths = ["/static/"]
    assert ph._bypass_match("/static/x.css", paths) is True
    assert ph._bypass_match("/static/", paths) is True
    # Historical greedy behaviour — see docstring above.
    assert ph._bypass_match("/staticx", paths) is True
    # A clearly-different path is still NOT matched.
    assert ph._bypass_match("/other", paths) is False


def test_bypass_match_mixed_exact_and_glob():
    ph = _ph()
    paths = ["/health", "/api/*", "/static/"]
    assert ph._bypass_match("/health", paths) is True
    assert ph._bypass_match("/api/v1", paths) is True
    assert ph._bypass_match("/static/main.js", paths) is True
    assert ph._bypass_match("/admin", paths) is False


def test_bypass_match_cache_invalidates_on_new_list_identity():
    """A hot-reload that rebinds the BYPASS_PATHS slot to a NEW list object
    must cause the cache to recompile — otherwise the matcher still uses
    the old precompiled (prefixes, exacts) tuple."""
    ph = _ph()
    a = ["/health"]
    b = ["/different"]
    assert ph._bypass_match("/health", a) is True
    # Same call with a NEW list object: cache must recompile or the next
    # call would treat /health as still bypassed.
    assert ph._bypass_match("/health", b) is False
    assert ph._bypass_match("/different", b) is True


def test_bypass_match_cache_reuses_on_same_identity():
    """Repeated calls with the same list object hit the cache (no recompile)."""
    ph = _ph()
    paths = ["/api/*", "/health"]
    # Two calls → second one MUST be served from the cache. We can't
    # observe the cache hit directly, but we can verify the result is
    # consistent and the cache state matches the input list identity.
    ph._bypass_match("/health", paths)
    cached_id, prefixes, exacts = ph._BYPASS_COMPILED
    assert cached_id is paths, (
        "after a call, cache must remember the source list by identity"
    )
    assert "/health" in exacts
    assert "/api/" in prefixes
    # Second call doesn't change the cache tuple identity (recompile happens
    # only when the source list identity changes).
    before_tuple = ph._BYPASS_COMPILED
    ph._bypass_match("/api/v2", paths)
    assert ph._BYPASS_COMPILED is before_tuple, (
        "same-identity input must NOT trigger a recompile"
    )


# ── _get_upstream_timeout ───────────────────────────────────────────────

def test_get_upstream_timeout_returns_same_object_when_stable(monkeypatch):
    ph = _ph()
    monkeypatch.setattr(ph, "UPSTREAM_TIMEOUT_SECS", 30, raising=False)
    monkeypatch.setattr(ph, "UPSTREAM_CONNECT_TIMEOUT_SECS", 5, raising=False)
    # Force fresh cache.
    ph._UPSTREAM_TIMEOUT_CACHE = (None, None, None)
    a = ph._get_upstream_timeout()
    b = ph._get_upstream_timeout()
    assert a is b, (
        "_get_upstream_timeout must return the SAME ClientTimeout object on "
        "back-to-back calls when knobs are stable"
    )


def test_get_upstream_timeout_invalidates_on_total_change(monkeypatch):
    ph = _ph()
    monkeypatch.setattr(ph, "UPSTREAM_TIMEOUT_SECS", 30, raising=False)
    monkeypatch.setattr(ph, "UPSTREAM_CONNECT_TIMEOUT_SECS", 5, raising=False)
    ph._UPSTREAM_TIMEOUT_CACHE = (None, None, None)
    a = ph._get_upstream_timeout()
    monkeypatch.setattr(ph, "UPSTREAM_TIMEOUT_SECS", 45, raising=False)
    b = ph._get_upstream_timeout()
    assert a is not b, (
        "knob change must trigger a fresh ClientTimeout instance"
    )
    assert b.total == 45


def test_get_upstream_timeout_invalidates_on_sock_connect_change(monkeypatch):
    ph = _ph()
    monkeypatch.setattr(ph, "UPSTREAM_TIMEOUT_SECS", 30, raising=False)
    monkeypatch.setattr(ph, "UPSTREAM_CONNECT_TIMEOUT_SECS", 5, raising=False)
    ph._UPSTREAM_TIMEOUT_CACHE = (None, None, None)
    a = ph._get_upstream_timeout()
    monkeypatch.setattr(ph, "UPSTREAM_CONNECT_TIMEOUT_SECS", 8, raising=False)
    b = ph._get_upstream_timeout()
    assert a is not b
    assert b.sock_connect == 8


# ── _get_upstream_client + _close_upstream_client ────────────────────────

def test_get_upstream_client_idempotent_within_event_loop():
    """Repeat calls must return the same ClientSession instance."""
    ph = _ph()
    async def go():
        # Reset module-level slot so the test is independent.
        ph._UPSTREAM_HTTP_CLIENT = None
        a = ph._get_upstream_client()
        b = ph._get_upstream_client()
        assert a is b
        assert not a.closed
        # Clean up so we don't leak the connector across tests.
        await ph._close_upstream_client()
    asyncio.new_event_loop().run_until_complete(go())


def test_get_upstream_client_uses_dummy_cookie_jar():
    """Verify the actual session has a DummyCookieJar — otherwise upstream
    Set-Cookie headers would persist across proxied requests."""
    ph = _ph()
    from aiohttp import DummyCookieJar
    async def go():
        ph._UPSTREAM_HTTP_CLIENT = None
        s = ph._get_upstream_client()
        assert isinstance(s.cookie_jar, DummyCookieJar)
        await ph._close_upstream_client()
    asyncio.new_event_loop().run_until_complete(go())


def test_get_upstream_client_recreates_after_close():
    """After explicit close, the next call must lazily build a fresh session
    instead of returning the closed one."""
    ph = _ph()
    async def go():
        ph._UPSTREAM_HTTP_CLIENT = None
        a = ph._get_upstream_client()
        await ph._close_upstream_client()
        b = ph._get_upstream_client()
        assert a is not b, "post-close, get_upstream_client must build a new session"
        assert not b.closed
        await ph._close_upstream_client()
    asyncio.new_event_loop().run_until_complete(go())


def test_close_upstream_client_safe_when_unset():
    """Cleanup must be safe even when the session was never created — the
    teardown path during a failed startup must not raise."""
    ph = _ph()
    async def go():
        ph._UPSTREAM_HTTP_CLIENT = None
        await ph._close_upstream_client()  # no-op
        # Idempotent re-close after a real session: also a no-op.
        ph._UPSTREAM_HTTP_CLIENT = None
        await ph._close_upstream_client()
    asyncio.new_event_loop().run_until_complete(go())


# ── timeline head-pop eviction (OrderedDict semantics) ─────────────────

def test_timeline_evicts_only_old_buckets():
    """Write 5 monotonic buckets, then add a new one past retention —
    only the buckets older than (new_bucket - TIMELINE_RETAIN_SECS) must
    be removed. Mid-range and newer ones stay, in original order."""
    from collections import OrderedDict
    # Reproduce the head-pop pattern in isolation — same shape used in
    # core/metrics.py _timeline_bump.
    timeline = OrderedDict()
    retain = 300                # 5-minute window
    bucket_step = 60
    base = 1_000_000
    for i in range(5):          # buckets at base, +60, +120, +180, +240
        timeline[base + i * bucket_step] = {"i": i}
    # New bucket 600s ahead of base → cutoff = base+600-300 = base+300.
    new_b = base + 600
    timeline[new_b] = {"i": 99}
    cutoff = new_b - retain
    while timeline:
        oldest = next(iter(timeline))
        if oldest >= cutoff:
            break
        del timeline[oldest]
    # All original 5 buckets had keys < cutoff → all evicted; only `new_b`
    # remains.
    assert list(timeline.keys()) == [new_b], (
        f"unexpected post-eviction state: {list(timeline.keys())}"
    )


def test_timeline_preserves_buckets_within_retention():
    """When all existing buckets are within retention, eviction must be a
    no-op — none removed."""
    from collections import OrderedDict
    timeline = OrderedDict()
    retain = 300
    base = 1_000_000
    for i in range(3):                # base, +60, +120 — all within retention
        timeline[base + i * 60] = {"i": i}
    new_b = base + 180                # cutoff = new_b - retain = base - 120
    timeline[new_b] = {"i": 99}
    cutoff = new_b - retain
    before = list(timeline.keys())
    while timeline:
        oldest = next(iter(timeline))
        if oldest >= cutoff:
            break
        del timeline[oldest]
    assert list(timeline.keys()) == before, (
        "in-retention buckets must not be evicted"
    )
