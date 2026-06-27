"""
tests/test_v192_vhost_policy_perf.py — guard the 1.9.2 vhost-policy load
perf pass.

Pre-1.9.2, every call to `/secured/vhost-policy-data?hostname=<vh>`:
  • re-ran the 30-day DISTINCT-vhost scan on the events table
  • re-serialised ~50 vhost-overridable globals
  • re-listed every vhost configured in VHOSTS

The Vhost Policy dashboard fires this **once per vhost** in parallel via
`_loadAllVhostSummary` — so 7 vhosts = 7 × full events-table scan, multi-
second wait on a busy Postgres deployment.

This file anchors the two-prong fix:
  1. `?summary=1` mode short-circuits to `{hostname, overrides}` only.
  2. `seen_vhosts` is computed via a 60 s in-process cache so even the
     full-mode call avoids the scan on hot reload.

Also guards the dashboard now passes `&summary=1` on the fan-out fetch
(otherwise the backend's summary fast-path is unreached).
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
SETTINGS = os.path.join(_REPO, "admin", "settings.py")
HTML = os.path.join(_REPO, "dashboards", "vhost_policy.html")


def _src(path):
    return open(path, encoding="utf-8").read()


# ── Backend: summary mode ─────────────────────────────────────────────────

def test_endpoint_accepts_summary_query_param():
    src = _src(SETTINGS)
    assert "vhost_policy_data_endpoint" in src
    fn_idx = src.find("async def vhost_policy_data_endpoint")
    end = src.find("\nasync def ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else len(src)]
    assert 'request.query.get("summary"' in block, (
        "vhost_policy_data_endpoint must read `summary` query param so the "
        "Policy dashboard's fan-out can request a lean response"
    )


def test_summary_mode_short_circuits_to_overrides_only():
    """In summary mode the response payload must be just `hostname` +
    `overrides` — none of the expensive fields."""
    src = _src(SETTINGS)
    fn_idx = src.find("async def vhost_policy_data_endpoint")
    end = src.find("\nasync def ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else len(src)]
    # The summary branch must return BEFORE vhost_knobs / global_vals /
    # seen_vhosts computation. Find its `if summary:` and the
    # web.json_response immediately after.
    m = re.search(r"if\s+summary:\s*\n\s*return\s+web\.json_response\((\s*\{.*?\}\s*),",
                  block, re.DOTALL)
    assert m, (
        "summary branch must short-circuit with `if summary: return "
        "web.json_response({...})` BEFORE the heavy work"
    )
    short_payload = m.group(1)
    # Lean payload — just hostname + overrides.
    assert '"hostname"' in short_payload
    assert '"overrides"' in short_payload
    # Must NOT include the heavy fields.
    for forbidden in ('"vhost_knobs"', '"global"', '"seen_vhosts"',
                      '"vhosts"'):
        assert forbidden not in short_payload, (
            f"summary payload must not include {forbidden} — it defeats "
            "the perf optimisation"
        )


def test_summary_branch_precedes_heavy_work():
    """The `if summary:` branch must sit BEFORE the events-table scan and
    BEFORE the global_vals serialisation — otherwise we still pay the
    cost we set out to skip."""
    src = _src(SETTINGS)
    fn_idx = src.find("async def vhost_policy_data_endpoint")
    end = src.find("\nasync def ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else len(src)]
    summary_idx = block.find("if summary:")
    # Look for the events-table scan + global_vals after the summary branch.
    events_idx = block.find("DISTINCT vhost FROM events")
    globals_idx = block.find("global_vals = {")
    assert summary_idx != -1, "summary short-circuit missing"
    assert events_idx == -1 or summary_idx < events_idx, (
        "summary short-circuit must precede the events-table scan"
    )
    assert globals_idx == -1 or summary_idx < globals_idx, (
        "summary short-circuit must precede the global_vals serialisation"
    )


# ── Backend: seen_vhosts cache ────────────────────────────────────────────

def test_seen_vhosts_cache_helper_defined():
    src = _src(SETTINGS)
    assert "_SEEN_VHOSTS_CACHE" in src, (
        "must declare _SEEN_VHOSTS_CACHE for the 60 s in-process cache"
    )
    assert "_seen_vhosts_cached" in src, (
        "must define a _seen_vhosts_cached() helper that the endpoint "
        "calls in full-payload mode"
    )


def test_seen_vhosts_cache_ttl_is_60_seconds():
    """60 s is the operator-visible UX trade-off — short enough that
    new vhosts appear in the picker within a refresh; long enough to skip
    the scan on a back-to-back page navigation. Anchor the value so a
    refactor doesn't widen it past 5 min (which would feel stale)."""
    src = _src(SETTINGS)
    assert re.search(r"_SEEN_VHOSTS_TTL\s*=\s*60\.?", src), (
        "_SEEN_VHOSTS_TTL must be 60 seconds (current operator-UX value)"
    )


def test_endpoint_full_mode_uses_cache_not_inline_scan():
    """The full-payload path must call _seen_vhosts_cached() — NOT
    re-implement the SELECT DISTINCT inline (which is what we're
    eliminating). Anchor on the async def block only, NOT the sync
    cache-helper that follows."""
    src = _src(SETTINGS)
    fn_idx = src.find("async def vhost_policy_data_endpoint")
    # Block ends at the next top-level `def ` OR `async def ` — whichever
    # comes first. The sync `_seen_vhosts_cached` helper is the next
    # top-level def, so we want to stop BEFORE it.
    rest = src[fn_idx + 1:]
    m = re.search(r"\n(?:async\s+)?def\s+", rest)
    end = (fn_idx + 1 + m.start()) if m else len(src)
    block = src[fn_idx: end]
    assert "_seen_vhosts_cached()" in block, (
        "vhost_policy_data_endpoint must call _seen_vhosts_cached() in "
        "full-payload mode"
    )
    assert block.count("DISTINCT vhost FROM events") == 0, (
        "events-table scan must live in _seen_vhosts_cached(), NOT inline "
        "in the endpoint body (which would defeat the cache)"
    )


def test_cache_helper_backend_branches_postgres_to_timestamp():
    src = _src(SETTINGS)
    helper_idx = src.find("def _seen_vhosts_cached")
    assert helper_idx != -1
    end = src.find("\n\n", helper_idx + 1)
    block = src[helper_idx: end if end > 0 else helper_idx + 2000]
    # PG branch must use to_timestamp() for the TIMESTAMPTZ bound.
    assert "to_timestamp(?)" in block, (
        "PG branch of _seen_vhosts_cached must use to_timestamp() — "
        "events.ts is TIMESTAMPTZ"
    )
    # Backend dispatch must come from db.active_backend (single source of truth).
    assert "active_backend" in block, (
        "cache helper must branch on db.active_backend() for the SQL form"
    )


def test_cache_helper_swallow_errors_returns_list():
    """A DB hiccup mid-scan must NOT raise — the helper returns the cached
    list (or empty) so the dashboard never sees a 500 just because the
    seen_vhosts query failed."""
    src = _src(SETTINGS)
    helper_idx = src.find("def _seen_vhosts_cached")
    end = src.find("\n\n", helper_idx + 1)
    block = src[helper_idx: end if end > 0 else helper_idx + 2000]
    assert "except Exception" in block, (
        "cache helper must `except Exception:` so a transient DB error "
        "doesn't crash the dashboard"
    )


# ── Frontend: fan-out uses summary=1 ──────────────────────────────────────

def test_dashboard_summary_query_param_on_fan_out():
    """`_loadAllVhostSummary` is the N-vhost parallel fetch. Without
    `&summary=1` it falls back to the heavy path and the backend perf
    fix is unreached."""
    src = _src(HTML)
    fn_idx = src.find("function _loadAllVhostSummary")
    end = src.find("\nfunction ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else fn_idx + 2000]
    assert "&summary=1" in block, (
        "_loadAllVhostSummary must pass `&summary=1` so the fan-out hits "
        "the backend short-circuit"
    )


def test_initial_load_does_not_use_summary_mode():
    """The initial single-fetch in `_loadData` needs the FULL payload
    (vhost_knobs + global + seen_vhosts) to populate the picker. Only
    the per-vhost fan-out should pass `summary=1`."""
    src = _src(HTML)
    fn_idx = src.find("function _loadData(")
    end = src.find("\nfunction ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else fn_idx + 2000]
    assert "&summary=1" not in block, (
        "_loadData (initial single fetch) must NOT pass summary=1 — it "
        "needs the full payload to render the picker"
    )
