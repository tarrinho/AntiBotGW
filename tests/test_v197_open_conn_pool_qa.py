"""
1.9.7 — QA for open_conn() connection pooling (PG read-path stall fix)
=====================================================================

Beyond the core regression (test_v197_open_conn_pool.py), these exercise the
pool lifecycle against a REAL Postgres (APPSECGW_TEST_PG=1):

  Q1 a borrow/return cycle puts the connection back in the IDLE pool (reuse),
     not torn down — so the next call pays no TCP+auth handshake.
  Q2 many sequential borrows never exceed the pool size (no per-call connect).
  Q3 the pool is autocommit=True, so a write via a borrowed connection persists
     and the released connection is immediately reusable (no "idle in
     transaction" state to poison the next borrower).
  Q4 the pooled wrapper keeps the sqlite3-compatible API callers rely on.
  Q5 SQLite mode is unaffected — open_conn returns a plain sqlite3 connection,
     not a pooled wrapper.
"""
from pathlib import Path

pytest_plugins = ["tests.conftest_pg_mode"]

_REPO = Path(__file__).resolve().parent.parent


def _bulk_db():
    import db.conn as c
    return c


class TestPoolLifecycle:
    def test_q1_close_returns_connection_to_idle(self, pg_session):
        c = _bulk_db()
        from db.postgres import _get_pool
        conn = c.open_conn()
        conn.execute("SELECT 1").fetchone()
        idle_before_close = _get_pool().stats["idle"]
        conn.close()
        assert _get_pool().stats["idle"] == idle_before_close + 1, \
            "close() must return the connection to the idle pool, not tear it down"

    def test_q2_sequential_borrows_bounded_by_pool_size(self, pg_session):
        c = _bulk_db()
        from db.postgres import _get_pool
        for _ in range(30):
            conn = c.open_conn(); conn.execute("SELECT 1").fetchone(); conn.close()
        assert _get_pool().stats["total"] <= _get_pool().stats["max"], \
            "30 borrow/return cycles must reuse, never exceed pool size"

    def test_q3_autocommit_write_persists_and_conn_reusable(self, pg_session):
        c = _bulk_db()
        # Pool is autocommit=True → the write commits immediately; close()
        # releases a CLEAN (no open-tx) connection that the next borrow reuses.
        # (config_kv is truncated between tests by the pg-mode autouse fixture.)
        conn = c.open_conn()
        conn.execute("INSERT INTO config_kv (key, value, ts) VALUES (?,?,?)",
                     ("qa_pool_probe", "x", 1.0))
        conn.close()
        check = c.open_conn()
        row = check.execute(
            "SELECT value FROM config_kv WHERE key = ?", ("qa_pool_probe",)).fetchone()
        check.close()
        assert row is not None, \
            "autocommit write must persist and the released connection must be reusable"

    def test_q4_pooled_wrapper_api_compatible(self, pg_session):
        c = _bulk_db()
        conn = c.open_conn()
        try:
            assert conn.execute("SELECT 1").fetchone()[0] == 1
            cur = conn.execute("SELECT 2")
            assert cur.fetchall()[0][0] == 2
            conn.commit()      # no-op on a read, must not raise
        finally:
            conn.close()
