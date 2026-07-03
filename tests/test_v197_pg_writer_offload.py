"""
1.9.7 — PG-primary writer offloads psycopg writes off the event loop
====================================================================

In PG-primary mode the writer drained each queued batch by calling
`pg_insert_event` / `_pg_mirror_kv` (synchronous psycopg: pool.connection() +
execute) DIRECTLY on the event loop. A slow Postgres query (cold pool,
checkpoint, lock, write-burst) therefore froze the WHOLE loop — `/live`
(healthcheck) and real requests timed out → front-proxy 502, even with CPU
idle (armv7 production).

Fix: the batch's PG work runs in a worker thread via `asyncio.to_thread`
(`_drain_batch_pg`), so a slow query can't block the loop. The psycopg pool is
thread-safe; `task_done()` stays on the loop (queue contract intact).

Source-anchored because exercising the PG-primary writer needs a live Postgres
(the functional `test_pg_mode.py` suite skips without one), and the project
already source-asserts the writer's backend branch.
"""
import re
from pathlib import Path

_SRC = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text(encoding="utf-8")


def _writer_loop_src():
    i = _SRC.index("async def db_writer_loop(")
    nxt = _SRC.find("\nasync def ", i + 1)
    end = _SRC.find("\ndef ", i + 1)
    cut = min(x for x in (nxt, end, len(_SRC)) if x != -1)
    return _SRC[i:cut]


def test_pg_batch_runs_in_worker_thread():
    body = _writer_loop_src()
    assert "asyncio.to_thread(_drain_batch_pg" in body, \
        "PG-primary writer must drain each batch via asyncio.to_thread (off the event loop)"
    assert "def _drain_batch_pg(" in body, "the worker-thread batch drainer must be defined"


def test_sync_pg_calls_are_inside_the_thread_fn_not_the_loop_body():
    """Within the PG-PRIMARY branch, pg_insert_event / _pg_mirror_kv must live
    INSIDE _drain_batch_pg (the worker thread), never directly in the awaited
    loop body where they'd block the event loop. (The separate SQLite-primary
    branch below mirrors to PG via _pg_mirror_bg and is out of scope here.)"""
    body = _writer_loop_src()
    pg_start = body.index("def _drain_batch_pg(")
    pg_end = body.index("SQLite-primary writer-loop")   # start of the other branch
    pg_branch = body[pg_start:pg_end]

    drain_end = pg_branch.index("while True:")
    drain_fn = pg_branch[:drain_end]            # the _drain_batch_pg body
    loop_body = pg_branch[drain_end:]           # the PG-primary while-loop body
    for call in ("pg_insert_event(", "_pg_mirror_kv("):
        assert call in drain_fn, f"{call} must be inside _drain_batch_pg (the worker thread)"
        assert call not in loop_body, \
            f"{call} must NOT appear in the PG-primary loop body — it would block the event loop"


def test_task_done_stays_on_the_loop():
    """The queue contract: every drained item is task_done()'d in the finally,
    on the loop — not inside the worker thread."""
    body = _writer_loop_src()
    assert re.search(r"finally:\s*\n\s*for _ in batch:\s*\n\s*_state\.db_queue\.task_done\(\)", body), \
        "task_done() must run per batch item in the loop's finally (queue contract)"
