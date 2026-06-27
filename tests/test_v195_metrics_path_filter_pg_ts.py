"""
tests/test_v195_metrics_path_filter_pg_ts.py — guard the 1.9.5 fix for the
PG-side TypeError on /secured/metrics + /secured/cost-timeline when a path
or vhost filter is active.

The filtered branch in `metrics_endpoint` (core/proxy_handler.py) was
running the same `ts >= ? AND ts <= ?` predicate on both backends. Fine
on SQLite (REAL epoch column) but on Postgres `events.ts` is TIMESTAMPTZ
and the bind params are epoch floats — psycopg routes them through as
INTEGER/NUMERIC, producing:

    operator does not exist: timestamp with time zone >= integer

(Visible in the user's TimescaleDB container logs.) The SQL ran, the
endpoint caught the exception and silently fell through to "unfiltered"
data; the operator still got their dashboard, but the filter was a no-op.

Fix: backend-branch the SQL — PG variant wraps the epoch bounds with
`to_timestamp(?)` and projects `EXTRACT(EPOCH FROM ts) AS ts` so the
downstream `int(row["ts"])` still gets a numeric.

These tests anchor both the structural fix (no inline unbranched query)
and the static SQL shape (PG variant uses to_timestamp + EXTRACT).
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
HANDLER = os.path.join(_REPO, "core", "proxy_handler.py")


def _src():
    return open(HANDLER, encoding="utf-8").read()


# ── Structural: no unbranched raw-epoch query against events ─────────────

def test_no_raw_ts_bind_in_events_query():
    """The exact regression: `WHERE ts >= ? AND ts <= ?` against the
    events table is BROKEN on Postgres. If a fresh inline query appears
    that compares events.ts to a raw bind without to_timestamp(), this
    test catches it at PR time."""
    src = _src()
    # Look for an events SELECT immediately followed by an unbranched
    # `ts >= ?` / `ts <= ?`. Allow the legacy form to remain in the
    # SQLite branch — the test only fires when the predicate is used
    # WITHOUT a sibling `to_timestamp(?)` in nearby code.
    bad = re.findall(
        r'"SELECT[^"]*FROM events[^"]*WHERE[^"]*ts\s*>=\s*\?',
        src,
    )
    for hit in bad:
        # Tolerated: clearly inside an `else:` SQLite branch where the
        # surrounding `if active_backend() == "postgres":` provides the
        # PG variant. We can't trivially diff branches by regex; instead,
        # require the function this snippet lives in to ALSO contain a
        # to_timestamp(?) call — proving the backend split exists.
        snippet_idx = src.find(hit)
        # Look back up to 1.5KB for the enclosing function's PG branch.
        window = src[max(0, snippet_idx - 1500): snippet_idx]
        assert "to_timestamp(?)" in window, (
            "an inline events query uses `ts >= ?` but the nearby code "
            "has no `to_timestamp(?)` PG branch — Postgres will raise "
            "`operator does not exist: timestamp with time zone >= integer`. "
            f"offending snippet: {hit!r}"
        )


# ── metrics_endpoint specifically: filtered branch is backend-branched ──

def _metrics_filtered_block() -> str:
    """Return the source slice covering the `if path_q or _vhost_filter:`
    branch of metrics_endpoint — the exact spot that produced the user's
    Postgres error."""
    src = _src()
    fn_idx = src.find("async def metrics_endpoint")
    assert fn_idx != -1, "metrics_endpoint must exist"
    end = src.find("\nasync def ", fn_idx + 1)
    fn_block = src[fn_idx: end if end > 0 else len(src)]
    gate_idx = fn_block.find("if path_q or _vhost_filter:")
    assert gate_idx != -1, "filtered-timeline branch missing from metrics_endpoint"
    # Take ~3 KB of the branch — enough to cover both the SELECT and the
    # follow-up bucketing.
    return fn_block[gate_idx: gate_idx + 3000]


def test_filtered_branch_uses_active_backend_check():
    block = _metrics_filtered_block()
    assert "active_backend()" in block, (
        "filtered-timeline branch must call active_backend() so the PG "
        "vs SQLite SQL form can be selected per call"
    )


def test_filtered_branch_pg_variant_wraps_ts_in_to_timestamp():
    block = _metrics_filtered_block()
    # Both lower and upper bounds need to_timestamp on PG; one without
    # the other is a partial fix and would still error.
    assert "ts >= to_timestamp(?)" in block, (
        "PG variant must use `ts >= to_timestamp(?)` for the lower bound "
        "— epoch float can't compare to TIMESTAMPTZ"
    )
    assert "ts <= to_timestamp(?)" in block, (
        "PG variant must use `ts <= to_timestamp(?)` for the upper bound"
    )


def test_filtered_branch_pg_variant_projects_epoch():
    """psycopg returns TIMESTAMPTZ as a Python datetime. Without
    EXTRACT(EPOCH FROM ts) the downstream `int(row["ts"]) // bucket_secs`
    raises TypeError. Anchor the projection."""
    block = _metrics_filtered_block()
    assert "EXTRACT(EPOCH FROM ts) AS ts" in block, (
        "PG variant must project `EXTRACT(EPOCH FROM ts) AS ts` so the "
        "downstream `int(row[\"ts\"])` works"
    )


def test_filtered_branch_sqlite_path_unchanged():
    """SQLite stores `ts` as REAL epoch — the raw `?` bind + bare `ts`
    projection still works there. Don't accidentally break SQLite while
    fixing PG."""
    block = _metrics_filtered_block()
    # The SQLite branch should still bind raw `?` and select bare `ts`.
    assert re.search(r'_ts_lower\s*=\s*"ts\s*>=\s*\?"', block), (
        "SQLite branch must keep the raw `ts >= ?` form — no needless "
        "to_timestamp() rewrite (SQLite has no such function)"
    )
    assert re.search(r'_ts_col\s*=\s*"ts"', block), (
        "SQLite branch must keep the bare `ts` projection — no EXTRACT"
    )


# ── Belt + braces: the original error message must NOT be reachable ─────

def test_filtered_select_does_not_combine_raw_ts_with_no_branch():
    """Direct check: the final SELECT string in the filtered branch
    must NOT contain a raw `ts >= ?` literal pasted as the ONLY form.
    The string is now built from _ts_lower/_ts_upper variables, so the
    literal can't appear inline."""
    block = _metrics_filtered_block()
    # Find the SELECT statement.
    m = re.search(r'f?"SELECT \{?_?ts_col\}?,\s*path,\s*reason FROM events', block)
    assert m, (
        "filtered-timeline SELECT must use the {_ts_col} interpolation — "
        "anything pasted as a literal SQL string risks slipping the PG "
        "fix again"
    )
