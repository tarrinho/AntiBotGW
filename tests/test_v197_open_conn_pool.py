"""
1.9.7 — open_conn() reuses a pooled PG connection (no per-call handshake)
========================================================================

A SIGUSR1 dump caught the event loop frozen in psycopg `_connect_gen`/`wait_conn`
under open_conn() → top_attackers_endpoint: open_conn() called `pg.connect()`
directly, doing a fresh TCP+auth handshake to Postgres PER call on the event
loop. Every dashboard read endpoint (46 open_conn sites) did this → on a slow/
loaded timescaledb each froze the whole loop.

Fix: open_conn() borrows from the existing _PgPool (reused connection, no
handshake); _PgConnWrapper.close() rolls back + returns it to the pool. One
change fixes all call sites.

The functional reuse check needs a live Postgres (APPSECGW_TEST_PG=1); the
source anchors run everywhere.
"""
import os
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_CONN = (_REPO / "db" / "conn.py").read_text(encoding="utf-8")


def test_open_conn_borrows_from_pool():
    i = _CONN.index("def open_conn(")
    body = _CONN[i: _CONN.index("\ndef ", i + 1)]
    assert "_get_pool" in body and "_acquire(" in body, \
        "open_conn() must borrow a pooled connection, not pg.connect() per call"


def test_wrapper_close_releases_to_pool():
    assert re.search(r'self\._pool\._release\(self\._conn\)', _CONN), \
        "_PgConnWrapper.close() must release pooled connections back to the pool"
    assert '"_pool"' in _CONN, "_PgConnWrapper must carry a _pool slot"


@pytest.mark.skipif(os.environ.get("APPSECGW_TEST_PG") != "1",
                    reason="needs a live Postgres (APPSECGW_TEST_PG=1)")
def test_open_conn_reuses_connections_under_load():
    import db.conn as c
    from db.postgres import _get_pool
    for _ in range(25):
        conn = c.open_conn()
        conn.execute("SELECT 1").fetchone()
        conn.close()
    p = _get_pool()
    assert p is not None
    # 25 borrow/return cycles must NOT have opened 25 connections.
    assert p.stats["total"] <= 5, f"pool should reuse, not handshake per call: {p.stats}"


def test_sqlite_mode_open_conn_is_plain_sqlite(proxy_module):
    """Default SQLite path: active_backend()=='sqlite' → open_conn returns a
    plain sqlite3.Connection (no pool wrapper); pooling is PG-only."""
    import sqlite3
    from db.conn import open_conn, active_backend
    if active_backend() != "sqlite":
        pytest.skip("not in sqlite mode")
    conn = open_conn()
    try:
        assert isinstance(conn, sqlite3.Connection), "sqlite mode must not return a pooled wrapper"
        assert conn.execute("SELECT 1").fetchone()[0] == 1
    finally:
        conn.close()
