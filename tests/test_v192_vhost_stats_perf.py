"""
tests/test_v192_vhost_stats_perf.py — guard the 1.9.2 /vhost-stats perf
regression that took the Vhost Policy + Settings dashboards to ~4 s.

Pre-1.9.2 contract:
  • Endpoint called `db_read_events(start_ts=h24, end_ts=now, limit=0)`
    → pulled EVERY event from the last 24 h over the wire.
  • Then aggregated bucket counts in a Python for-loop.
  • Wire size and Python time both scaled with row count.
  • No caching — every page-load + every auto-refresh re-ran the scan.

1.9.2 contract:
  • Aggregation is pushed to SQL via `COUNT(*) FILTER (WHERE ...)` +
    `GROUP BY vhost`. Wire returns ONE row per vhost, ~10s of rows max.
  • Backend-branched timestamp form (PG TIMESTAMPTZ → to_timestamp(),
    SQLite → raw epoch float).
  • Result cached in `_VHOST_STATS_CACHE` for 15 s so back-to-back
    page-loads + multi-user dashboards stay fast.
  • Endpoint never re-implements the SQL inline — it only calls the
    cache helper.

These tests anchor the contract so a future refactor that "simplifies"
back to a per-row scan is caught at PR time, not in production logs.
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
SETTINGS = os.path.join(_REPO, "admin", "settings.py")


def _src():
    return open(SETTINGS, encoding="utf-8").read()


# ── Cache scaffolding ────────────────────────────────────────────────────

def test_vhost_stats_cache_globals_present():
    src = _src()
    assert "_VHOST_STATS_CACHE" in src, (
        "must declare _VHOST_STATS_CACHE module-global for the 15 s "
        "in-process cache"
    )
    assert "_VHOST_STATS_TTL" in src, (
        "must declare _VHOST_STATS_TTL — caller-tunable cache lifetime"
    )


def test_vhost_stats_cache_ttl_is_15_seconds():
    """15 s is the operator-visible UX trade-off — short enough that new
    traffic shows up on a manual refresh; long enough to skip the GROUP
    BY scan on auto-poll. Anchor the value so a refactor doesn't
    accidentally drop it to zero (defeats the cache) or widen it past
    a minute (feels stale on the dashboard)."""
    src = _src()
    assert re.search(r"_VHOST_STATS_TTL\s*=\s*15\.?", src), (
        "_VHOST_STATS_TTL must be 15 seconds (current operator-UX value)"
    )


def test_vhost_stats_cache_helper_defined():
    src = _src()
    assert "def _vhost_stats_cached" in src, (
        "must define a _vhost_stats_cached() helper that the endpoint "
        "calls instead of running the GROUP BY inline"
    )


# ── SQL aggregation contract ─────────────────────────────────────────────

def test_sql_uses_group_by_vhost_not_per_row_scan():
    """The whole point of the perf fix — the helper MUST push the
    aggregation to SQL via GROUP BY, not pull every row and bucket in
    Python."""
    src = _src()
    helper_idx = src.find("def _vhost_stats_cached")
    end = src.find("\n\nasync def", helper_idx + 1)
    block = src[helper_idx: end if end > 0 else helper_idx + 6000]
    assert "GROUP BY vhost" in block, (
        "_vhost_stats_cached must aggregate via SQL `GROUP BY vhost` — "
        "without it the helper still pulls every row over the wire"
    )


def test_sql_uses_count_filter_for_bucket_aggregation():
    """COUNT(*) FILTER (WHERE ...) lets us compute total_1h /
    allowed_1h / blocked_1h / blocked_24h in ONE query instead of
    separate scans + a Python merge. Both PG and SQLite ≥3.30 support
    this — Python 3.13 ships SQLite 3.45+, so we don't need a
    legacy fallback."""
    src = _src()
    helper_idx = src.find("def _vhost_stats_cached")
    end = src.find("\n\nasync def", helper_idx + 1)
    block = src[helper_idx: end if end > 0 else helper_idx + 6000]
    # Must use COUNT(*) FILTER for the per-bucket counts.
    assert "COUNT(*) FILTER (WHERE" in block, (
        "_vhost_stats_cached must use COUNT(*) FILTER (WHERE ...) — that's "
        "the single-query bucketing primitive that makes this fast"
    )


def test_sql_branches_on_backend_for_timestamp_form():
    """PG `ts` is TIMESTAMPTZ — bounds need `to_timestamp(?)`. SQLite
    `ts` is a REAL epoch — raw `?` binds the float directly. The helper
    must check `active_backend()` and pick the right form per-call."""
    src = _src()
    helper_idx = src.find("def _vhost_stats_cached")
    end = src.find("\n\nasync def", helper_idx + 1)
    block = src[helper_idx: end if end > 0 else helper_idx + 6000]
    assert "active_backend" in block, (
        "_vhost_stats_cached must branch on db.active_backend() to pick "
        "the right timestamp-bind form"
    )
    assert "to_timestamp(?)" in block, (
        "PG branch must use to_timestamp(?) for the WHERE-ts bounds"
    )
    assert "EXTRACT(EPOCH FROM MAX(ts))" in block, (
        "PG branch must normalise the last-seen_ts back to a float "
        "via EXTRACT(EPOCH FROM ...)"
    )


def test_sql_groups_by_real_vhost_column():
    """Don't aggregate empty-vhost rows into a phantom group — the
    bots-without-Host-header rows would otherwise dominate the panel."""
    src = _src()
    helper_idx = src.find("def _vhost_stats_cached")
    end = src.find("\n\nasync def", helper_idx + 1)
    block = src[helper_idx: end if end > 0 else helper_idx + 6000]
    assert re.search(r"vhost\s*!=\s*''", block), (
        "WHERE-clause must filter `vhost != ''` so empty-host events "
        "don't form a meaningless group"
    )


# ── Endpoint contract: must call the cache helper, never re-impl SQL ─────

def test_endpoint_calls_cache_helper():
    src = _src()
    fn_idx = src.find("async def vhost_stats_endpoint")
    end = src.find("\nasync def ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else len(src)]
    assert "_vhost_stats_cached()" in block, (
        "vhost_stats_endpoint must call _vhost_stats_cached() instead "
        "of re-running the GROUP BY inline"
    )


def test_endpoint_does_not_call_db_read_events():
    """db_read_events with no limit pulls every event row — that's the
    behaviour we're eliminating. The endpoint must not call it as code
    (docstring mentions are fine and useful for historical context)."""
    src = _src()
    fn_idx = src.find("async def vhost_stats_endpoint")
    end = src.find("\nasync def ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else len(src)]
    # Strip docstrings so a historical mention in the function comment
    # doesn't fail the test.
    code = re.sub(r'"""[\s\S]*?"""', "", block)
    assert "db_read_events(" not in code, (
        "vhost_stats_endpoint must NOT call db_read_events() — that's "
        "the per-row scan we're replacing with the GROUP BY aggregation"
    )
    # `from db import db_read_events` would also reintroduce the per-row
    # dependency at the endpoint level.
    assert ("import db_read_events" not in code
            and "from db import" not in code or "db_read_events" not in code), (
        "vhost_stats_endpoint must not import db_read_events"
    )


def test_endpoint_does_not_inline_aggregation_loop():
    """No `for e in evts:` style Python-side bucketing — that's the old
    contract."""
    src = _src()
    fn_idx = src.find("async def vhost_stats_endpoint")
    end = src.find("\nasync def ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else len(src)]
    assert "for e in evts" not in block, (
        "vhost_stats_endpoint must not run the legacy Python-side "
        "per-event aggregation loop"
    )


# ── Cache safety: hiccup must NOT 500 the dashboard ──────────────────────

def test_cache_helper_swallows_db_errors():
    """A transient DB hiccup mid-query must not raise — the helper
    returns the last cached list (or empty) so the dashboard never
    surfaces a 500 from this endpoint."""
    src = _src()
    helper_idx = src.find("def _vhost_stats_cached")
    end = src.find("\n\nasync def", helper_idx + 1)
    block = src[helper_idx: end if end > 0 else helper_idx + 6000]
    assert "except Exception" in block, (
        "cache helper must `except Exception:` and fall back to the "
        "prior cached value — the dashboard must not 500 on a DB blip"
    )


# ── Return shape ─────────────────────────────────────────────────────────

def test_helper_returns_required_dict_keys():
    """Every dict in the returned list must carry the keys the endpoint
    response shape expects, so the endpoint's `r["total_1h"]` etc.
    don't KeyError."""
    src = _src()
    helper_idx = src.find("def _vhost_stats_cached")
    end = src.find("\n\nasync def", helper_idx + 1)
    block = src[helper_idx: end if end > 0 else helper_idx + 6000]
    for key in ("vhost", "total_1h", "allowed_1h", "blocked_1h",
                "total_24h", "blocked_24h", "last_seen_ts"):
        assert f'"{key}":' in block, (
            f"helper output dict missing required key: {key!r}"
        )
