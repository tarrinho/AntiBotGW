"""
tests/test_v1814_perf_pass.py — guard the 1.8.14 performance pass.

Covers three speedups applied to the hot path:

  1. Shared upstream ClientSession + pooled TCPConnector
     (was: fresh session per request → TCP+TLS handshake per upstream call).
  2. Cached ClientTimeout (was: new object per request).
  3. OrderedDict timeline eviction in core/metrics.py
     (was: O(N) list comprehension on every minute roll).
  4. Precompiled BYPASS_PATHS (was: per-request `any()` over the list).

These are signature-level / static checks — they catch a refactor that
silently re-introduces per-request session creation or removes the cache.
Functional equivalence is covered by tests/test_pure.py BYPASS_PATHS
tests + existing upstream-proxy integration tests.
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
HANDLER = os.path.join(_REPO, "core", "proxy_handler.py")
METRICS = os.path.join(_REPO, "core", "metrics.py")
PROXY = os.path.join(_REPO, "proxy.py")
STATE = os.path.join(_REPO, "state.py")


def _src(path):
    return open(path, encoding="utf-8").read()


# ── Shared upstream client ───────────────────────────────────────────────

def test_module_level_upstream_client_exists():
    src = _src(HANDLER)
    assert "_UPSTREAM_HTTP_CLIENT" in src, (
        "core/proxy_handler.py must declare a module-level "
        "_UPSTREAM_HTTP_CLIENT to be reused across requests"
    )
    assert "def _get_upstream_client" in src, (
        "must define _get_upstream_client() to lazily init the shared session"
    )


def test_upstream_client_uses_dummy_cookie_jar():
    """Critical safety property — without DummyCookieJar, an upstream
    Set-Cookie from request A could leak into request B's outgoing
    headers. We proxy cookies via headers ourselves; no jar needed."""
    src = _src(HANDLER)
    m = re.search(r"def _get_upstream_client\b.*?\n(?:def |\nasync def )",
                  src, re.DOTALL)
    assert m, "must define _get_upstream_client"
    body = m.group(0)
    assert "DummyCookieJar" in body, (
        "_get_upstream_client must instantiate ClientSession with "
        "cookie_jar=DummyCookieJar() — sharing a real jar leaks Set-Cookie "
        "between requests"
    )


def test_upstream_client_uses_pooled_connector():
    """TCPConnector with explicit limits + DNS cache is the whole point of
    sharing the session — verify it isn't dropped to defaults."""
    src = _src(HANDLER)
    m = re.search(r"def _get_upstream_client\b.*?\n(?:def |\nasync def )",
                  src, re.DOTALL)
    body = m.group(0)
    assert "TCPConnector" in body, (
        "_get_upstream_client must construct a TCPConnector explicitly"
    )
    assert "ttl_dns_cache" in body, (
        "TCPConnector must enable a DNS cache (ttl_dns_cache=…) so repeated "
        "upstream hostname lookups don't re-resolve every request"
    )


def test_main_proxy_path_no_longer_creates_session_per_request():
    """The proxy() hot-path's `async with ClientSession(timeout=ClientTimeout(`
    construction must be gone — replaced by `_get_upstream_client()`."""
    src = _src(HANDLER)
    # Match the multi-line pattern that USED to wrap the upstream request.
    # If it's back, the perf win is gone.
    bad = re.search(
        r"async with ClientSession\(\s*timeout\s*=\s*ClientTimeout\(\s*\n\s*total\s*=\s*UPSTREAM_TIMEOUT_SECS",
        src, re.DOTALL,
    )
    assert not bad, (
        "proxy() hot-path must NOT construct a fresh ClientSession per request "
        "— use _get_upstream_client() to reuse the pooled session. A refactor "
        "that re-introduces this kills ~20-30% RPS."
    )


def test_main_proxy_uses_shared_client():
    """proxy() must reuse the shared session via _get_upstream_client()."""
    src = _src(HANDLER)
    # The hot path must reference both the shared session and the cached
    # timeout helpers.
    assert "session = _get_upstream_client()" in src, (
        "proxy() must call `session = _get_upstream_client()` once per request"
    )
    assert "_get_upstream_timeout()" in src, (
        "proxy() must call `_get_upstream_timeout()` for the per-request "
        "ClientTimeout instead of constructing a new one inline"
    )


# ── Cached ClientTimeout ─────────────────────────────────────────────────

def test_upstream_timeout_cache_present():
    src = _src(HANDLER)
    assert "_UPSTREAM_TIMEOUT_CACHE" in src, (
        "must declare _UPSTREAM_TIMEOUT_CACHE so we don't allocate a new "
        "ClientTimeout per request when the knobs are stable"
    )
    assert "def _get_upstream_timeout" in src, (
        "must define _get_upstream_timeout() helper"
    )


def test_upstream_timeout_invalidates_on_knob_change():
    """The cache must compare current UPSTREAM_TIMEOUT_SECS /
    UPSTREAM_CONNECT_TIMEOUT_SECS values, so hot-reload of those knobs
    takes effect immediately."""
    src = _src(HANDLER)
    m = re.search(r"def _get_upstream_timeout\b.*?\n(?:def |\nasync def )",
                  src, re.DOTALL)
    assert m, "_get_upstream_timeout must be defined"
    body = m.group(0)
    assert "UPSTREAM_TIMEOUT_SECS" in body, (
        "cache key must reference UPSTREAM_TIMEOUT_SECS"
    )
    assert "UPSTREAM_CONNECT_TIMEOUT_SECS" in body, (
        "cache key must reference UPSTREAM_CONNECT_TIMEOUT_SECS"
    )


# ── on_cleanup drains the shared client ─────────────────────────────────

def test_on_cleanup_closes_shared_client():
    src = _src(PROXY)
    assert "_close_upstream_client" in src, (
        "proxy.on_cleanup must close the shared upstream client so the pool "
        "drains cleanly at shutdown"
    )
    # And the close must happen INSIDE on_cleanup, not on_startup.
    m = re.search(r"async def on_cleanup\b.*?\nasync def ", src, re.DOTALL)
    if m is None:
        # on_cleanup might be the last async function in the file
        m = re.search(r"async def on_cleanup\b.*", src, re.DOTALL)
    assert m, "on_cleanup must be defined"
    assert "_close_upstream_client" in m.group(0), (
        "_close_upstream_client must be awaited inside on_cleanup"
    )


# ── Precompiled BYPASS_PATHS ────────────────────────────────────────────

def test_bypass_match_helper_defined():
    src = _src(HANDLER)
    assert "def _bypass_match" in src, (
        "must define _bypass_match() that holds the precompiled "
        "(prefixes, exacts) tuple"
    )


def test_bypass_match_helper_caches_per_list_identity():
    """The cache must be invalidated on `is` identity change so a hot-reload
    that rebinds globals()['BYPASS_PATHS'] = new_list re-compiles."""
    src = _src(HANDLER)
    # Grab the full function body — from its `def` to the next top-level def.
    m = re.search(r"def _bypass_match\b.*?(?=\ndef |\nasync def )",
                  src, re.DOTALL)
    assert m, "_bypass_match must be defined"
    body = m.group(0)
    assert "is not" in body or "is " in body, (
        "_bypass_match must compare the cached source list by identity (`is`) "
        "so hot-reload rebind invalidates correctly"
    )
    # Compiled forms must use a tuple of prefixes + a frozenset of exacts.
    assert "frozenset" in body, "exact-match cache must be a frozenset"
    assert "tuple" in body or "startswith(prefixes)" in body, (
        "prefix cache must be a tuple so startswith(tuple) does the inner "
        "loop in C"
    )


def test_bypass_match_uses_startswith_tuple_in_protect():
    """The hot path must call _bypass_match — never re-implement the loop."""
    src = _src(HANDLER)
    # Cheap protection: the legacy any() form must not exist anymore.
    assert "vc('BYPASS_PATHS') and any(" not in src, (
        "protect() must use _bypass_match() — the legacy `any(...)` form "
        "is the one we're eliminating"
    )
    assert "_bypass_match(request.path" in src, (
        "protect() must call _bypass_match(request.path, vc('BYPASS_PATHS'))"
    )


# ── OrderedDict timeline eviction ───────────────────────────────────────

def test_state_timeline_is_ordered_dict():
    src = _src(STATE)
    # state.py must declare timeline as OrderedDict explicitly (not plain
    # dict) so the head-eviction pattern in metrics.py is correct.
    assert re.search(r"timeline\s*:\s*OrderedDict", src), (
        "state.timeline must be typed as OrderedDict so popitem(last=False) "
        "/ next(iter(.)) eviction is sound"
    )
    assert re.search(r"cost_timeline\s*:\s*OrderedDict", src), (
        "state.cost_timeline must be typed as OrderedDict too"
    )


def test_timeline_eviction_uses_head_pop_not_list_scan():
    """The old `for k in [k for k in timeline if k < cutoff]: del …` scanned
    every bucket on each minute roll. New code must use the head-pop
    pattern: O(buckets-to-evict) instead of O(all-buckets)."""
    src = _src(METRICS)
    # The list-comprehension scan pattern must be gone.
    assert "[k for k in timeline if k < cutoff]" not in src, (
        "metrics.py must NOT use a list-comprehension scan to evict old "
        "buckets — switch to next(iter(.)) head-pop"
    )
    assert "[k for k in cost_timeline if k < cutoff]" not in src, (
        "metrics.py cost_timeline eviction must also use head-pop, not a "
        "list-comprehension scan"
    )
    # The head-pop pattern must appear in both eviction sites.
    assert src.count("next(iter(timeline))") >= 1, (
        "timeline eviction must use `next(iter(timeline))` to peek the "
        "oldest bucket"
    )
    assert src.count("next(iter(cost_timeline))") >= 1, (
        "cost_timeline eviction must use `next(iter(cost_timeline))` to "
        "peek the oldest bucket"
    )
