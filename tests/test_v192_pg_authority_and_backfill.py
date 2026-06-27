"""
1.9.2 iter-23 — two PG robustness guarantees the operator asked for:

  1. POSTGRES_DSN authority: if a DSN is defined, the gateway runs Postgres —
     a stale persisted `DB_BACKEND="sqlite"` in config_kv must NOT silently
     keep it on SQLite. (db_load_config coerces it to postgres.)

  2. Boot gap back-fill: on a PG-mode restart, events that accumulated in the
     LOCAL SQLite store while the gateway was (mis)configured on SQLite are
     imported into Postgres — every row newer than PG's max(ts). It must be a
     clean no-op (never crash) when there is no local SQLite, no events table,
     or no gap.
"""
import os
import inspect
import sqlite3
import tempfile

os.environ.setdefault("UPSTREAM", "https://example.com")

import db.postgres as pg
import db.sqlite as dbs


# ── Fake psycopg plumbing ──────────────────────────────────────────────────
class _FakeCursor:
    def __init__(self, pg_max, sink):
        self._pg_max = pg_max
        self._sink = sink
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, sql, params=None):
        return self
    def fetchone(self):
        return [self._pg_max]
    def executemany(self, sql, seq):
        self._sink.extend(seq)


class _FakeConn:
    def __init__(self, pg_max, sink):
        self._pg_max = pg_max
        self._sink = sink
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, sql, params=None):
        return _FakeCursor(self._pg_max, self._sink)
    def cursor(self):
        return _FakeCursor(self._pg_max, self._sink)
    def commit(self): pass


class _FakePg:
    def __init__(self, pg_max, sink):
        self._pg_max = pg_max
        self._sink = sink
    def connect(self, *a, **k):
        return _FakeConn(self._pg_max, self._sink)


def _mk_sqlite(rows):
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE events (ts REAL, ip TEXT, ua TEXT, path TEXT, "
              "method TEXT, status INTEGER, reason TEXT, vhost TEXT)")
    c.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?)", rows)
    c.commit(); c.close()
    return path


# ── Back-fill: imports only rows newer than PG max(ts) ─────────────────────
def test_backfill_imports_only_gap(monkeypatch):
    # PG already has events up to ts=100. SQLite has 90,100,150,200.
    rows = [(90.0, "1.1.1.1", "ua", "/a", "GET", 200, "ok", "h"),
            (100.0, "1.1.1.1", "ua", "/b", "GET", 200, "ok", "h"),
            (150.0, "2.2.2.2", "ua", "/c", "GET", 403, "ban", "h"),
            (200.0, "3.3.3.3", "ua", "/d", "GET", 200, "ok", "h")]
    path = _mk_sqlite(rows)
    sink = []
    try:
        monkeypatch.setattr(pg, "POSTGRES_DSN", "postgresql://x@h/db", raising=False)
        monkeypatch.setattr(pg, "DB_PATH", path, raising=False)
        monkeypatch.setattr(pg, "_postgres_load_module", lambda: _FakePg(100.0, sink))
        res = pg._backfill_events_gap_from_sqlite()
        assert res["ok"] is True, res
        # Only ts>100 → 150 and 200 copied (90 and 100 excluded).
        assert res["copied"] == 2, res
        copied_ts = sorted(r[0] for r in sink)
        assert copied_ts == [150.0, 200.0]
    finally:
        os.unlink(path)


# ── Back-fill: no gap → clean no-op ────────────────────────────────────────
def test_backfill_no_gap(monkeypatch):
    rows = [(50.0, "1.1.1.1", "ua", "/a", "GET", 200, "ok", "h")]
    path = _mk_sqlite(rows)
    sink = []
    try:
        monkeypatch.setattr(pg, "POSTGRES_DSN", "postgresql://x@h/db", raising=False)
        monkeypatch.setattr(pg, "DB_PATH", path, raising=False)
        monkeypatch.setattr(pg, "_postgres_load_module", lambda: _FakePg(100.0, sink))
        res = pg._backfill_events_gap_from_sqlite()
        assert res["ok"] is True and res["copied"] == 0, res
        assert sink == []
    finally:
        os.unlink(path)


# ── Back-fill: missing SQLite file → clean no-op, never crashes ────────────
def test_backfill_no_sqlite_file(monkeypatch):
    monkeypatch.setattr(pg, "POSTGRES_DSN", "postgresql://x@h/db", raising=False)
    monkeypatch.setattr(pg, "DB_PATH", "/nonexistent/path/antibot.db", raising=False)
    monkeypatch.setattr(pg, "_postgres_load_module", lambda: _FakePg(0.0, []))
    res = pg._backfill_events_gap_from_sqlite()
    assert res["ok"] is True and res["copied"] == 0
    assert "no local sqlite" in res["reason"]


# ── Back-fill: SQLite without an events table → clean no-op ────────────────
def test_backfill_no_events_table(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db"); os.close(fd)
    c = sqlite3.connect(path); c.execute("CREATE TABLE other (x INT)"); c.commit(); c.close()
    try:
        monkeypatch.setattr(pg, "POSTGRES_DSN", "postgresql://x@h/db", raising=False)
        monkeypatch.setattr(pg, "DB_PATH", path, raising=False)
        monkeypatch.setattr(pg, "_postgres_load_module", lambda: _FakePg(0.0, []))
        res = pg._backfill_events_gap_from_sqlite()
        assert res["ok"] is True and res["copied"] == 0, res
    finally:
        os.unlink(path)


# ── Back-fill: no DSN → no-op (PG not configured) ──────────────────────────
def test_backfill_no_dsn(monkeypatch):
    monkeypatch.setattr(pg, "POSTGRES_DSN", "", raising=False)
    res = pg._backfill_events_gap_from_sqlite()
    assert res["ok"] is False and res["copied"] == 0


# ── Change 1: db_load_config coerces persisted DB_BACKEND→postgres when DSN set
def test_db_load_config_coerces_backend_when_dsn_set():
    """Source guard: the DB_BACKEND coercion must be present and gated on
    POSTGRES_DSN, so a stale persisted sqlite value can't keep PG idle."""
    src = inspect.getsource(dbs.db_load_config)
    assert 'key == "DB_BACKEND" and POSTGRES_DSN' in src, \
        "db_load_config must force DB_BACKEND=postgres when POSTGRES_DSN is set"
    assert 'json.dumps("postgres")' in src, \
        "coercion must rewrite the persisted value to postgres"


# ── Boot wiring: the back-fill is invoked in on_startup ─────────────────────
def test_backfill_wired_into_startup():
    import proxy
    src = inspect.getsource(proxy.on_startup)
    assert "_backfill_events_gap_from_sqlite" in src, \
        "on_startup must call the gap back-fill in the PG branch"


# ── 1.9.3: coercion self-heals the stale config_kv row (no manual DELETE) ───
def test_db_load_config_self_heals_stale_backend_row():
    """Source guard: when DB_BACKEND is coerced, db_load_config must rewrite the
    persisted config_kv row to postgres (UPDATE), so the stale value self-cleans
    and the boot warning stops recurring."""
    src = inspect.getsource(dbs.db_load_config)
    assert "_stale_backend_row" in src, "must flag a coerced stale backend row"
    assert "UPDATE config_kv SET value=?" in src, \
        "must rewrite the persisted config_kv DB_BACKEND row"
    assert "db_backend_row_self_healed" in src, \
        "must log the self-heal so operators can see it"
