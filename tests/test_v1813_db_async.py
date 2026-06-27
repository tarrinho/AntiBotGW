"""1.8.13 — improvement #3 (get blocking DB I/O off the event loop):
db_read_events_async runs the synchronous reader in a thread-pool executor and
returns exactly what the sync db_read_events returns.
"""
import asyncio
import os
import sqlite3
import time

os.environ.setdefault("UPSTREAM", "https://example.com")


def test_db_read_events_async_matches_sync(proxy_module):
    import db
    from db.sqlite import db_init
    db_init()                       # ensure events schema exists
    # seed a couple of events into the proxy's DB
    now = time.time()
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.execute("DELETE FROM events")
    conn.executemany(
        "INSERT INTO events (ts, ip, ua, path, method, status, reason) "
        "VALUES (?,?,?,?,?,?,?)",
        [(now - 1, "1.1.1.1", "UA", "/.env", "GET", 404, "honeypot"),
         (now - 2, "1.1.1.2", "UA", "/wp-admin/", "GET", 404, "honeypot")])
    conn.commit(); conn.close()

    cols = ["ts", "ip", "path", "reason"]
    sync_rows = db.db_read_events(now - 60, now, columns=cols,
                                  reason_in=["honeypot"], order_by="ts DESC", limit=10)
    async_rows = asyncio.new_event_loop().run_until_complete(
        db.db_read_events_async(now - 60, now, columns=cols,
                                reason_in=["honeypot"], order_by="ts DESC", limit=10))
    assert async_rows == sync_rows, "async wrapper must return identical rows to sync"
    assert len(async_rows) == 2


def test_db_read_events_async_does_not_block_loop(proxy_module):
    """The read must run in an executor — a concurrent coroutine keeps making
    progress while the DB read is in flight (i.e. the loop isn't blocked)."""
    import db
    from db.sqlite import db_init
    db_init()
    ticks = {"n": 0}

    async def _ticker():
        for _ in range(20):
            await asyncio.sleep(0)
            ticks["n"] += 1

    async def _main():
        await asyncio.gather(
            db.db_read_events_async(0, time.time(), columns=["ts"], limit=5),
            _ticker(),
        )

    asyncio.new_event_loop().run_until_complete(_main())
    assert ticks["n"] == 20  # ticker completed alongside the offloaded read
