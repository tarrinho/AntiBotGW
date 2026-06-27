"""
1.9.6 — two real PG-mode bugs found while un-crashing the hidden-failure suite:

  1. `/secured/logs-data` 500 on Postgres — `r["ts"]` is a TIMESTAMPTZ `datetime`
     (not JSON-serializable). Fixed via the `_epoch()` coercion helper.
  2. `db_writer_loop` raised `task_done() called too many times` on cancellation
     (shutdown/test teardown): `batch` was assigned inside the `try`, so a
     CancelledError during `await get()` left a stale prior-iteration batch that
     the `finally` re-`task_done()`'d. Fixed by resetting `batch = []` before the try.
"""
import os
import re
import datetime
import pathlib
import inspect

os.environ.setdefault("UPSTREAM", "https://example.com")
_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_epoch_helper_coerces_datetime_and_floats():
    import core.proxy_handler as ph
    # tz-aware datetime (what PG TIMESTAMPTZ yields) → epoch float
    dt = datetime.datetime(2026, 6, 22, 12, 0, tzinfo=datetime.timezone.utc)
    assert ph._epoch(dt) == dt.timestamp()
    assert ph._epoch(1234.5) == 1234.5      # SQLite REAL passthrough
    assert ph._epoch(None) == 0.0           # null-safe
    assert ph._epoch("bad") == 0.0          # never raises


def test_logs_data_uses_epoch_for_ts():
    src = inspect.getsource(__import__("core.proxy_handler", fromlist=["logs_data_endpoint"]).logs_data_endpoint)
    assert '_epoch(r["ts"])' in src, "logs-data must coerce ts via _epoch (PG datetime → 500 otherwise)"


def test_writer_loop_resets_batch_before_try():
    """Both db_writer_loop variants must set `batch = []` before the try so a
    CancelledError in `await get()` can't double-`task_done()` a stale batch."""
    src = (_ROOT / "db" / "sqlite.py").read_text()
    # two writer loops, each must reset batch before consuming the queue.
    resets = len(re.findall(r"^\s*batch = \[\]", src, re.M))
    awaits = len(re.findall(r"batch = \[await _state\.db_queue\.get\(\)\]", src))
    assert awaits >= 2, "expected two writer-loop get() sites"
    assert resets >= awaits, f"each writer loop must reset batch=[] before try (resets={resets}, loops={awaits})"
