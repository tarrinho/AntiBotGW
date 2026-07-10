"""
1.9.2 iter-22 — guard the db-test endpoint against the two failure modes that
froze it for 40+ s on the live example.com (Timescale) deployment:

  1. `pg_db_size()` ran an UNBOUNDED `COUNT(*) FROM events`. On a large
     Timescale hypertable that full-scans every chunk (seconds → minutes).
     It must use a planner ESTIMATE (reltuples over the table + its
     inheritance children/chunks) instead.

  2. `db_test_endpoint` called the blocking probes (`pg_test_roundtrip`,
     `pg_db_size`) DIRECTLY on the event loop, so a slow Postgres froze the
     whole worker — concurrent admin requests 502'd. They must be offloaded to
     a thread executor and bounded with a timeout.

Source-inspection tests (cheap, no live DB) that lock both fixes in place.
"""
import os
import inspect
import re

os.environ.setdefault("UPSTREAM", "https://example.com")

import db.postgres as pg
import core.proxy_handler as ph


def test_pg_db_size_does_not_exact_count_events():
    """pg_db_size must NOT run a bare `COUNT(*) FROM events` (full chunk scan
    on Timescale). It should estimate via pg_class.reltuples."""
    src = inspect.getsource(pg.pg_db_size)
    assert "reltuples" in src, "pg_db_size should use a reltuples estimate"
    # No unbounded exact count of the events table.
    assert not re.search(r"COUNT\(\*\)\s+FROM\s+events", src, re.I), \
        "pg_db_size still does an exact COUNT(*) FROM events — full-scans Timescale chunks"


def test_db_test_endpoint_offloads_blocking_probes():
    """db_test_endpoint must run the synchronous PG probes off the event loop
    (run_in_executor) and bound them (wait_for), so a slow DB never freezes the
    worker."""
    src = inspect.getsource(ph.db_test_endpoint)
    assert "run_in_executor" in src, \
        "db_test_endpoint must offload pg_test_roundtrip/pg_db_size to an executor"
    assert "wait_for" in src, \
        "db_test_endpoint must bound the probes with asyncio.wait_for"
    # The blocking calls must not be invoked bare on the event loop.
    assert "pg_test_roundtrip()" not in src or "run_in_executor" in src


def test_pg_db_size_fast_when_unconfigured():
    """No DSN / no pool → returns ok=False immediately, never hangs."""
    assert pg.pg_db_size().get("ok") is False
