"""
tests/test_v191_iter17_sweep_qa.py — per-site QA for the 17 PG-mode
events reads fixed in the iter-17 sweep.

The iter-17 forward-looking guard (test_v191_iter17_pg_events_read_guard.py)
fails if ANY new bare `ts <op> ?` SQL lands without a PG branch. This
file complements it by locking down each of the 17 specific fixes —
anchored on the function name + SQL shape — so a refactor that DROPS
the branch (e.g. someone "simplifies" the if/else back into one path)
is caught even if the resulting SQL happens to satisfy the guard
heuristic.

Coverage matrix:
  dashboards/agents.py      — 5 reads (timeline buckets)
  dashboards/analytics.py   — 3 reads (vhost block-rate, incidents, ban-events)
  admin/settings.py         — 2 reads (per-vhost slot, DISTINCT vhost)
  core/proxy_handler.py     — 7 reads (geo cursor, geo target-points,
                              path-detail, agents bucket-detail × 4)

Each test:
  • finds the function/region by a stable anchor string,
  • asserts the PG branch contains `to_timestamp(?)` for ts bounds,
  • asserts the SQLite branch keeps the original `ts <op> ?` form
    (no regression for SQLite-only deployments),
  • asserts EXTRACT(EPOCH FROM ts) is projected when downstream code
    consumes `r["ts"]` as a numeric.
"""

from __future__ import annotations

import os
import re


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    return open(os.path.join(_REPO, rel), encoding="utf-8").read()


def _slice_between(src: str, start_anchor: str, end_anchor: str,
                   tag: str = "") -> str:
    """Return the source slice between start_anchor and the next end_anchor.
    The slice has the start anchor and stops just before the end anchor."""
    s = src.find(start_anchor)
    assert s != -1, f"{tag}: start anchor lost — `{start_anchor[:60]}…`"
    e = src.find(end_anchor, s)
    assert e != -1, f"{tag}: end anchor lost — `{end_anchor[:60]}…`"
    return src[s:e]


# ── dashboards/agents.py — 5 timeline-bucket reads ─────────────────────


def _agents_block() -> str:
    """The five bucketed reads live inside one try-block beginning at
    the `detected, allowed_total, missed, …` line. The whole region is
    bounded above by `end_b = (int(_t.time())` and below by the
    immediately-following `series = []`."""
    src = _read("dashboards/agents.py")
    return _slice_between(
        src,
        "detected, allowed_total, missed, authorized_robot, gwmgmt",
        "series = []",
        tag="agents.py timeline-bucket region",
    )


def test_agents_uses_backend_branch_template_up_front():
    """iter-17 chose the readable approach: compute `_bucket_expr`,
    `_ts_lb`, `_ts_ub` ONCE based on `active_backend()` and reuse in
    each of the 5 reads. The 5 reads stay short instead of branching
    inline. This test pins that template."""
    blk = _agents_block()
    assert "active_backend" in blk, (
        "agents.py timeline must check active_backend() before issuing "
        "the bucketed reads"
    )
    assert "_bucket_expr" in blk, (
        "agents.py must define `_bucket_expr` once and reuse in all 5 "
        "reads (keeps each read site short + scannable)"
    )
    assert "_ts_lb" in blk and "_ts_ub" in blk, (
        "agents.py must define `_ts_lb` / `_ts_ub` templates so the 5 "
        "reads all pick the right WHERE bound flavour"
    )


def test_agents_pg_branch_wraps_ts_in_to_timestamp():
    blk = _agents_block()
    assert re.search(r"_ts_lb\s*=\s*['\"]ts\s*>=\s*to_timestamp\(\?\)['\"]", blk), (
        "agents.py PG branch must set `_ts_lb` to `ts >= to_timestamp(?)`"
    )
    assert re.search(r"_ts_ub\s*=\s*['\"]ts\s*<=\s*to_timestamp\(\?\)['\"]", blk), (
        "agents.py PG branch must set `_ts_ub` to `ts <= to_timestamp(?)`"
    )


def test_agents_pg_branch_uses_extract_epoch_for_bucket_arithmetic():
    """The bucket formula `CAST(ts / bucket AS INTEGER) * bucket` divides
    a numeric, so the PG branch must project `ts` via EXTRACT(EPOCH FROM ts)
    before the divide — otherwise PG raises on TIMESTAMPTZ / integer."""
    blk = _agents_block()
    assert re.search(
        r"CAST\(\s*EXTRACT\s*\(\s*EPOCH\s+FROM\s+ts\s*\)\s*/\s*\{bucket_secs\}",
        blk,
    ), (
        "agents.py PG branch must wrap `ts / bucket_secs` in "
        "`EXTRACT(EPOCH FROM ts)` — bare arithmetic on TIMESTAMPTZ fails"
    )


def test_agents_sqlite_branch_preserves_original_bucket_formula():
    """Regression guard for SQLite-only deployments — the SQLite branch
    must keep the pre-iter-17 epoch-int divide form."""
    blk = _agents_block()
    # SQLite branch uses raw `ts / {bucket_secs}` (no EXTRACT).
    assert re.search(
        r"CAST\(\s*ts\s*/\s*\{bucket_secs\}\s*AS\s+INTEGER",
        blk, re.IGNORECASE,
    ), (
        "agents.py SQLite branch must keep `CAST(ts/{bucket_secs} AS INTEGER)` "
        "so SQLite-only deployments do not regress"
    )
    assert re.search(r"_ts_lb\s*=\s*['\"]ts\s*>=\s*\?['\"]", blk), (
        "agents.py SQLite branch must set `_ts_lb` to `ts >= ?`"
    )


def test_agents_all_five_reads_use_template():
    """Each of the five `conn.execute(...)` reads inside the timeline
    block must use the `_bucket_expr` and `_ts_lb`/`_ts_ub` placeholders.
    A read that bypasses the template (back to raw `ts >= ?`) is a
    regression we want to catch."""
    blk = _agents_block()
    # Count read sites that inject the bucket template.
    bucket_uses = len(re.findall(r"\{_bucket_expr\}", blk))
    bound_uses  = len(re.findall(r"\{_ts_lb\}\s+AND\s+\{_ts_ub\}", blk))
    assert bucket_uses >= 5, (
        f"all 5 reads must use `{{_bucket_expr}}` (found {bucket_uses})"
    )
    assert bound_uses >= 5, (
        f"all 5 reads must use `{{_ts_lb}} AND {{_ts_ub}}` (found {bound_uses})"
    )


# ── dashboards/analytics.py — 3 reads ──────────────────────────────────


def test_analytics_vhost_blockrate_branches_by_backend():
    src = _read("dashboards/analytics.py")
    blk = _slice_between(
        src,
        "vhost_totals:   dict = {}",
        "for row in rows:",
        tag="analytics vhost block-rate region",
    )
    assert "active_backend" in blk or "_active_vh" in blk
    assert re.search(r"ts\s*>=\s*to_timestamp\(\?\)", blk), (
        "vhost block-rate PG branch must wrap lower bound"
    )
    assert re.search(r"CAST\(EXTRACT\(EPOCH FROM ts\)", blk), (
        "vhost block-rate PG branch must project ts via EXTRACT for the "
        "slot bucket divide"
    )
    # SQLite branch preserved.
    assert "CAST(ts / ? AS INTEGER) * ? AS slot" in blk


def test_analytics_incident_feed_branches_by_backend():
    src = _read("dashboards/analytics.py")
    blk = _slice_between(
        src,
        "# Fetch matching events from DB",
        '"ts":         float(row["ts"])',
        tag="analytics incident feed region",
    )
    assert "_active_inc" in blk or "active_backend" in blk
    assert "to_timestamp(?)" in blk, (
        "incident feed PG branch must wrap lower bound"
    )
    assert "EXTRACT(EPOCH FROM ts)" in blk, (
        "incident feed PG branch must project ts → epoch so the "
        "downstream `float(row['ts'])` consumer works"
    )


def test_analytics_ban_timeline_branches_by_backend():
    src = _read("dashboards/analytics.py")
    blk = _slice_between(
        src,
        "in_mem_oldest = int(_t.time()) - TIMELINE_RETAIN_SECS",
        "for row in rows:",
        tag="analytics ban-timeline region",
    )
    assert "_active_bt" in blk or "active_backend" in blk
    assert "to_timestamp(?)" in blk
    assert "EXTRACT(EPOCH FROM ts)" in blk, (
        "ban-event timeline must project ts → epoch so `int(row['ts'])` "
        "still works downstream"
    )


# ── admin/settings.py — 2 reads ────────────────────────────────────────


def test_settings_per_vhost_slot_branches_by_backend():
    src = _read("admin/settings.py")
    # Anchor by the slot-formula-with-EXTRACT to find the iter-17 PG
    # branch in the per-vhost SIEM slot read.
    idx = src.find(
        "CAST((EXTRACT(EPOCH FROM ts) - ?) / ? AS INTEGER) AS slot, "
        '"\n                "  COUNT(*) AS cnt'
    )
    assert idx != -1, (
        "settings.py per-vhost slot read must use the PG-aware "
        "`CAST((EXTRACT(EPOCH FROM ts) - ?) / ? AS INTEGER)` slot form"
    )
    # Confirm the SQLite sibling in the same block.
    blk = src[max(0, idx - 600):idx + 1200]
    assert "CAST((ts - ?) / ? AS INTEGER) AS slot" in blk, (
        "per-vhost slot SQLite branch must stay byte-identical to "
        "pre-iter-17 form"
    )
    assert "active_backend" in blk or "_active_vs" in blk


def test_settings_distinct_vhost_scan_branches_by_backend():
    src = _read("admin/settings.py")
    # Contract change (1.9.2 perf): the 30-day DISTINCT vhost scan moved out
    # of the inline `seen_vhosts: list = []` block into the cached helper
    # `_seen_vhosts_cached()`. Re-anchor the slice onto that helper; the
    # backend-branched scan itself is unchanged.
    blk = _slice_between(
        src,
        "def _seen_vhosts_cached() -> list:",
        "_VHOST_STATS_CACHE",
        tag="settings DISTINCT vhost scan region",
    )
    assert "active_backend" in blk or "_active_dv" in blk, (
        "DISTINCT vhost scan must check active_backend"
    )
    # Match across SQL multi-literal concatenation by checking the two
    # halves independently (Python source has `"events " \n "WHERE …"`
    # which a single regex can't span without also allowing quotes/newlines).
    assert "DISTINCT vhost FROM events" in blk, (
        "DISTINCT vhost scan must read from events"
    )
    assert "ts >= to_timestamp(?)" in blk, (
        "DISTINCT vhost scan PG branch must wrap ts in to_timestamp(?)"
    )
    # Sibling SQLite path.
    assert "WHERE vhost != '' AND ts >= ? " in blk, (
        "DISTINCT vhost scan SQLite branch must keep `ts >= ?` form"
    )


# ── core/proxy_handler.py — 7 reads ────────────────────────────────────


def test_proxy_handler_geo_bucket_cursor_branches_by_backend():
    src = _read("core/proxy_handler.py")
    blk = _slice_between(
        src,
        "_geo_sql_args = [start_epoch, end_epoch]",
        "for r in cursor:",
        tag="proxy_handler geo-bucket cursor region",
    )
    assert "_active_geo" in blk or "active_backend" in blk
    assert "ts >= to_timestamp(?)" in blk
    assert "ts >= ?" in blk, (
        "geo-bucket cursor SQLite branch must keep `ts >= ?`"
    )


def test_proxy_handler_geo_target_points_branches_by_backend():
    src = _read("core/proxy_handler.py")
    blk = _slice_between(
        src,
        "target_key = (round(lat * 2) / 2, round(lng * 2) / 2)",
        "ip_map = {}",
        tag="proxy_handler geo-target-points region",
    )
    assert "_active_geom" in blk or "active_backend" in blk
    assert "to_timestamp(?)" in blk
    assert "EXTRACT(EPOCH FROM ts) AS ts" in blk, (
        "geo target-points PG branch must project ts → epoch so the "
        "downstream consumer keeps working"
    )


def test_proxy_handler_path_detail_branches_by_backend():
    src = _read("core/proxy_handler.py")
    blk = _slice_between(
        src,
        "def _fetch_path_rows(db_path, path_val, since):",
        "rows = []",
        tag="proxy_handler path-detail region",
    )
    assert "_active_p" in blk or "active_backend" in blk
    assert "open_conn" in blk, (
        "path-detail must use open_conn (was bare sqlite3.connect)"
    )
    assert "WHERE path = ? AND ts >= to_timestamp(?)" in blk, (
        "path-detail PG branch must wrap the ts bound"
    )
    assert "EXTRACT(EPOCH FROM ts) AS ts" in blk


def test_proxy_handler_agents_bucket_detail_uses_shared_template():
    """The four sibling reads in the agents bucket-detail endpoint share
    a `_ts_ag` template computed once — same readability pattern as the
    agents.py timeline. This test pins the template."""
    src = _read("core/proxy_handler.py")
    blk = _slice_between(
        src,
        # Start from the iter-17 comment that introduces the template so
        # the slice includes the `from db import … _active_ag` line.
        "# 1.9.1 iter-17: backend-branch the four agent-page reads",
        "missed_list = []",
        tag="proxy_handler agents bucket-detail region",
    )
    assert "_active_ag" in blk or "active_backend" in blk
    assert "_ts_ag" in blk, (
        "proxy_handler agents bucket-detail must define a `_ts_ag` "
        "template up-front so the four reads (block / clean / "
        "authorized-robot / gwmgmt) all use the same WHERE shape"
    )
    # The four expected reads must all use the template.
    uses = len(re.findall(r"\{_ts_ag\}", blk))
    assert uses >= 4, (
        f"agents bucket-detail must use `{{_ts_ag}}` in all four reads "
        f"(found {uses})"
    )
    assert "ts >= to_timestamp(?) AND ts < to_timestamp(?)" in blk, (
        "_ts_ag PG flavour must wrap both bounds in to_timestamp(?)"
    )
    assert '"ts >= ? AND ts < ?"' in blk, (
        "_ts_ag SQLite flavour must keep the original `ts >= ? AND ts < ?` "
        "form"
    )


# ── admin/settings.py top-paths (18th site, found by iter-17 sweep QA) ──


def test_settings_top_paths_branches_by_backend():
    """The top-paths read was the 18th site — the iter-17 forward-looking
    guard missed it (the dow×hour heatmap's to_timestamp() was in its
    detection window) and the iter-17 sweep QA's open_conn check caught
    it. Pin the fix here."""
    src = _read("admin/settings.py")
    idx = src.find("_active_tp")
    assert idx != -1, (
        "top-paths read must check active_backend via _active_tp alias"
    )
    blk = src[idx:idx + 1200]
    assert "_open_conn_tp" in blk or "open_conn(" in blk, (
        "top-paths must use open_conn (was bare _sq3.connect → empty in "
        "PG-only mode)"
    )
    assert "WHERE ts >= to_timestamp(?)" in blk, (
        "top-paths PG branch must wrap the ts bound"
    )
    assert re.search(r"WHERE ts >= \? AND path IS NOT NULL", blk), (
        "top-paths SQLite branch must keep `ts >= ?` form"
    )


# ── Cross-cutting QA ───────────────────────────────────────────────────


def test_each_active_backend_alias_unique_per_file():
    """Each function defines its own `_active_<tag>` alias to avoid
    cross-function bleed. This test confirms the aliases stay distinct
    within each file (no alias collision that would mask the wrong
    backend in a sibling function)."""
    cases = [
        ("dashboards/agents.py",       ["_active_a"]),
        ("dashboards/analytics.py",    ["_active_vh", "_active_inc", "_active_bt"]),
        ("admin/settings.py",          ["_active_e", "_active_h", "_active_vs", "_active_dv", "_active_tp"]),
        ("core/proxy_handler.py",      ["_active_geo", "_active_geom", "_active_p", "_active_ag"]),
    ]
    for rel, aliases in cases:
        src = _read(rel)
        for alias in aliases:
            # Match `as _active_X` (import-time rename) OR a later use
            # like `_active_X = …` / `_active_X(`.
            found = (
                (f"as {alias}" in src)
                or (f"{alias} = " in src)
                or (f"{alias}(" in src)
            )
            assert found, (
                f"{rel}: must define `{alias}` so the read can pick the "
                f"right backend at call time (import-as / assignment / call)"
            )


def test_all_iter17_fixes_route_through_open_conn():
    """No iter-17 fix may bypass the connection wrapper. Specifically,
    raw `sqlite3.connect(_DATA_PATH)` patterns must not reappear in any
    of the four fixed files inside an events-reading try-block."""
    for rel in (
        "dashboards/agents.py",
        "dashboards/analytics.py",
        "admin/settings.py",
        "core/proxy_handler.py",
    ):
        src = _read(rel)
        # Find every "FROM events" SQL and look back for a connection
        # opener — must be open_conn() or its alias, not sqlite3.connect.
        for m in re.finditer(r"FROM\s+events\b", src, re.IGNORECASE):
            window = src[max(0, m.start() - 1500):m.start()]
            # Take the LAST connection opener in the window (closest
            # caller).
            opens = list(re.finditer(
                r"(sqlite3\.connect|_sq3\.connect|_sq_imp\.connect|open_conn|_open_conn_\w+)\s*\(",
                window,
            ))
            if not opens:
                continue
            last = opens[-1].group(1)
            assert not last.endswith("connect") or last == "open_conn", (
                f"{rel}:{src.count(chr(10), 0, m.start()) + 1}: "
                f"FROM events read uses a raw `{last}(...)` connection — "
                f"must route through `open_conn()` or an `_open_conn_*` "
                f"alias so the PG wrapper handles cursor + placeholders"
            )
