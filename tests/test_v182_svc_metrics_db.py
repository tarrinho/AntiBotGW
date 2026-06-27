"""
Tests — v1.8.2: svc_metrics 30-day DB read path.

service_metrics_data_endpoint previously read only the in-memory deque
(SERVICE_METRICS_HISTORY, maxlen=8640 ≈ 12 h at 5 s/sample).  The fix
adds _svc_db_history() which is called when the requested window extends
beyond the buffer, delegating aggregation to SQLite (retains 30 d by
default via SVC_DB_RETENTION_HOURS=720).

Groups
──────
A  Static source checks  (_svc_db_history exists, endpoint uses _mem_raw)
B  _svc_db_history unit  (empty DB, data present, bucket boundaries)
C  Endpoint routing      (in-memory path vs DB path selection)
S  Additional static QA  (conn.close, try/except, AVG/MAX/SUM_KEYS, window param)
D  Dynamic HTTP tests    (spin proxy, real /secured/service-data requests)
"""
import os
import sys
import sqlite3
import tempfile
import time
import types
import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

_SRC = os.path.join(os.path.dirname(__file__), "..", "dashboards", "service_metrics.py")


def _svc_src() -> str:
    return open(_SRC, encoding="utf-8").read()


# ─── A. Static source checks ──────────────────────────────────────────────────

class TestA_StaticChecks:
    def test_a1_svc_db_history_defined(self):
        assert "def _svc_db_history(" in _svc_src(), \
            "_svc_db_history helper must be defined in service_metrics.py"

    def test_a2_endpoint_uses_mem_raw_not_raw(self):
        import re as _re
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        assert fn_start != -1
        fn_body = src[fn_start:fn_start + 4000]
        assert "_mem_raw = list(SERVICE_METRICS_HISTORY)" in fn_body, \
            "endpoint must assign _mem_raw = list(SERVICE_METRICS_HISTORY)"
        # Use word-boundary check — "_mem_raw = list(...)" must NOT be confused with bare "raw = list(...)"
        assert not _re.search(r'(?<![_\w])raw\s*=\s*list\(SERVICE_METRICS_HISTORY\)', fn_body), \
            "old bare 'raw = list(SERVICE_METRICS_HISTORY)' must be removed from endpoint"

    def test_a3_endpoint_calls_svc_db_history(self):
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 4000]
        assert "_svc_db_history(" in fn_body, \
            "endpoint must call _svc_db_history() for the DB fallback path"

    def test_a4_endpoint_checks_buf_oldest(self):
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 4000]
        assert "_buf_oldest" in fn_body, \
            "endpoint must compute _buf_oldest to decide in-memory vs DB path"

    def test_a5_samples_in_buffer_uses_mem_raw(self):
        import re as _re
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        # Use full remainder — function can be >5000 chars
        fn_body = src[fn_start:]
        assert "len(_mem_raw)" in fn_body, \
            "samples_in_buffer response field must use len(_mem_raw), not len(raw)"
        assert not _re.search(r'(?<![_\w])len\(raw\)', fn_body), \
            "stale len(raw) reference must be removed from endpoint"

    def test_a6_buffer_oldest_ts_uses_mem_raw(self):
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 5000]
        assert "_mem_raw[0]" in fn_body, \
            "buffer_oldest_ts response field must reference _mem_raw[0]"

    def test_a7_db_history_uses_coalesce(self):
        src = _svc_src()
        fn_start = src.find("def _svc_db_history(")
        fn_body = src[fn_start:fn_start + 2000]
        assert "COALESCE" in fn_body, \
            "_svc_db_history SQL must COALESCE nullable columns to 0"

    def test_a8_db_history_groups_by_bucket(self):
        src = _svc_src()
        fn_start = src.find("def _svc_db_history(")
        fn_body = src[fn_start:fn_start + 2000]
        assert "GROUP BY" in fn_body.upper(), \
            "_svc_db_history must use GROUP BY for SQL-side aggregation"

    def test_a9_svc_db_retention_hours_default_720(self):
        """Default 30-day on-disk retention must be 720 h."""
        src = _svc_src()
        assert '"SVC_DB_RETENTION_HOURS", "720"' in src, \
            "SVC_DB_RETENTION_HOURS default must be 720 (= 30 days)"


# ─── B. _svc_db_history unit tests ───────────────────────────────────────────

def _make_test_db(rows: list[dict]) -> str:
    """Create a temp SQLite file with svc_metrics rows. Returns path."""
    f = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    f.close()
    conn = sqlite3.connect(f.name)
    conn.execute("""
        CREATE TABLE svc_metrics (
            ts REAL PRIMARY KEY,
            cpu_pct REAL, load1 REAL, load5 REAL, load15 REAL,
            mem_used INTEGER, mem_total INTEGER, mem_avail INTEGER, mem_pct REAL,
            swap_used INTEGER, swap_total INTEGER,
            cg_used INTEGER, cg_limit INTEGER, cg_pct REAL,
            disk_used INTEGER, disk_total INTEGER, disk_avail INTEGER, disk_pct REAL,
            procs INTEGER, open_fds INTEGER,
            net_rx_bps INTEGER, net_tx_bps INTEGER,
            db_db INTEGER, db_wal INTEGER, db_shm INTEGER, db_total INTEGER,
            pg_db_bytes INTEGER, pg_events_rows INTEGER,
            identities_count INTEGER, total_requests INTEGER,
            pg_index_bytes INTEGER, pg_active_conns INTEGER, pg_idle_conns INTEGER,
            pg_cache_hit_pct REAL, pg_tx_total INTEGER
        )
    """)
    for r in rows:
        conn.execute("""
            INSERT OR REPLACE INTO svc_metrics
            (ts, cpu_pct, load1, load5, load15, mem_used, mem_total, mem_avail, mem_pct,
             swap_used, swap_total, cg_used, cg_limit, cg_pct,
             disk_used, disk_total, disk_avail, disk_pct,
             procs, open_fds, net_rx_bps, net_tx_bps,
             db_db, db_wal, db_shm, db_total,
             pg_db_bytes, pg_events_rows, identities_count, total_requests,
             pg_index_bytes, pg_active_conns, pg_idle_conns, pg_cache_hit_pct, pg_tx_total)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            r.get("ts", 0), r.get("cpu_pct", 0), r.get("load1", 0), r.get("load5", 0), r.get("load15", 0),
            r.get("mem_used", 0), r.get("mem_total", 1000), r.get("mem_avail", 1000), r.get("mem_pct", 0),
            r.get("swap_used", 0), r.get("swap_total", 0), r.get("cg_used", 0), r.get("cg_limit", -1), r.get("cg_pct", 0),
            r.get("disk_used", 0), r.get("disk_total", 1000), r.get("disk_avail", 1000), r.get("disk_pct", 0),
            r.get("procs", 0), r.get("open_fds", 0), r.get("net_rx_bps", 0), r.get("net_tx_bps", 0),
            r.get("db_db", 0), r.get("db_wal", 0), r.get("db_shm", 0), r.get("db_total", 0),
            r.get("pg_db_bytes"), r.get("pg_events_rows"),
            r.get("identities_count", 0), r.get("total_requests", 0),
            r.get("pg_index_bytes", 0), r.get("pg_active_conns", 0), r.get("pg_idle_conns", 0),
            r.get("pg_cache_hit_pct", 0.0), r.get("pg_tx_total", 0),
        ))
    conn.commit()
    conn.close()
    return f.name


AVG_KEYS = ("cpu_pct", "mem_pct", "swap_used", "load1", "load5", "load15",
            "disk_pct", "cg_pct", "mem_used", "disk_used", "pg_cache_hit_pct")
MAX_KEYS = ("procs", "open_fds", "db_db", "db_wal", "db_shm", "db_total",
            "cg_used", "cg_limit", "mem_total", "disk_total", "disk_avail", "swap_total",
            "pg_db_bytes", "pg_events_rows", "identities_count", "total_requests",
            "pg_index_bytes", "pg_active_conns", "pg_idle_conns", "pg_tx_total")
SUM_KEYS = ("net_rx_bps", "net_tx_bps")


from contextlib import contextmanager as _contextmanager


@_contextmanager
def _route_svc_db_history_to(db_path: str):
    """Force _svc_db_history's connection to the given temp SQLite file.

    CONTRACT CHANGE (1.9.1 iter-18, aligned 2026-06): _svc_db_history no longer
    does a bare `sqlite3.connect(_DATA_PATH)` — it routes the read through
    `db.open_conn()` so the Service-page history works in PG-only mode
    (svc_metrics IS PG-mirrored). Patching `_DATA_PATH` is therefore a dead
    seam under APPSECGW_TEST_PG=1: the read targets Postgres, not the test's
    temp file, so the seeded sample is invisible and every aggregation reads 0.

    This helper patches the real seam (`db.open_conn`) to hand back a SQLite
    connection to the test fixture, keeping the test backend-agnostic AND
    isolated from the shared Postgres (no cross-agent flake). The aggregation
    logic under test (bucketing, zero-fill, AVG/MAX) is exercised unchanged.
    """
    import importlib
    _db = importlib.import_module("db")
    _orig = getattr(_db, "open_conn", None)

    def _fake_open_conn(*_a, **_k):
        return sqlite3.connect(db_path)

    _db.open_conn = _fake_open_conn
    try:
        yield
    finally:
        if _orig is not None:
            _db.open_conn = _orig


def _import_svc_db_history(db_path: str):
    """Import _svc_db_history with _DATA_PATH patched to db_path."""
    import importlib, importlib.util
    spec = importlib.util.spec_from_file_location("svc_m_test", _SRC)
    mod = importlib.util.module_from_spec(spec)
    # Stub out heavy imports before exec
    for name in ("config", "state", "helpers", "admin.auth", "aiohttp"):
        stub = types.ModuleType(name)
        stub.__dict__.update({
            "__all__": [], "os": os, "asyncio": __import__("asyncio"),
            "web": types.SimpleNamespace(Request=object, json_response=None),
            "slog": lambda *a, **k: None,
            "now": time.time,
            "_internal_authed": lambda r: True,
            "SERVICE_METRICS_HISTORY": [],
            "ip_state": {}, "ip_buckets": {}, "metrics": {}, "events": [],
            "db_queue": None, "state_lock": None,
            "_postgres_available": False, "POSTGRES_DSN": "",
            "START_EPOCH": 0, "GW_VERSION": "test",
            "_DASHBOARDS_DIR": __import__("pathlib").Path(_SRC).parent,
        })
        sys.modules.setdefault(name, stub)
    # Override _DATA_PATH before module body runs
    mod._DATA_PATH = db_path
    try:
        spec.loader.exec_module(mod)
    except Exception:
        pass  # partial import OK — we only need _svc_db_history
    # Patch _DATA_PATH after exec too (it might have been reset by config.*)
    mod._DATA_PATH = db_path
    return mod._svc_db_history


class TestB_SvcDbHistory:
    def test_b1_empty_db_returns_zero_filled_buckets(self, tmp_path):
        db = str(tmp_path / "empty.db")
        _make_test_db([])  # creates empty table in a different path; use _make_test_db for schema
        # Use the real function via a patched module
        import importlib.util, types as _types
        fn = _import_svc_db_history(db.replace(".db", "_empty.db") if False else db)
        # Create schema
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE IF NOT EXISTS svc_metrics (ts REAL PRIMARY KEY, cpu_pct REAL, mem_pct REAL, procs INTEGER, net_rx_bps INTEGER, net_tx_bps INTEGER)")
        conn.commit(); conn.close()

        # Use minimal key sets for this test
        a = ("cpu_pct", "mem_pct")
        m = ("procs",)
        s = ("net_rx_bps", "net_tx_bps")
        # patch _DATA_PATH
        import dashboards.service_metrics as sm
        orig = sm._DATA_PATH
        sm._DATA_PATH = db
        try:
            result = sm._svc_db_history(1000, 1060, 60, a, m, s)
        finally:
            sm._DATA_PATH = orig
        assert len(result) == 2, "should produce 2 buckets for range 1000-1060 step 60"
        for row in result:
            assert "ts" in row
            assert row["cpu_pct"] == 0
            assert row["procs"] == 0
            assert row["net_rx_bps"] == 0

    def test_b2_single_sample_lands_in_correct_bucket(self, tmp_path):
        import dashboards.service_metrics as sm
        db = str(tmp_path / "one.db")
        now_b = (int(time.time()) // 300) * 300  # 5-min bucket
        rows = [{"ts": now_b + 10, "cpu_pct": 42.0, "mem_pct": 55.0,
                 "procs": 99, "net_rx_bps": 1000, "net_tx_bps": 500}]
        _make_test_db(rows)
        # _make_test_db writes to a temp file; write to our db instead
        conn = sqlite3.connect(db)
        conn.execute("""CREATE TABLE svc_metrics (
            ts REAL PRIMARY KEY, cpu_pct REAL DEFAULT 0, mem_pct REAL DEFAULT 0,
            load1 REAL DEFAULT 0, load5 REAL DEFAULT 0, load15 REAL DEFAULT 0,
            swap_used INTEGER DEFAULT 0, disk_pct REAL DEFAULT 0, cg_pct REAL DEFAULT 0,
            mem_used INTEGER DEFAULT 0, disk_used INTEGER DEFAULT 0,
            pg_cache_hit_pct REAL DEFAULT 0,
            procs INTEGER DEFAULT 0, open_fds INTEGER DEFAULT 0,
            db_db INTEGER DEFAULT 0, db_wal INTEGER DEFAULT 0,
            db_shm INTEGER DEFAULT 0, db_total INTEGER DEFAULT 0,
            cg_used INTEGER DEFAULT 0, cg_limit INTEGER DEFAULT -1,
            mem_total INTEGER DEFAULT 0, disk_total INTEGER DEFAULT 0,
            disk_avail INTEGER DEFAULT 0, swap_total INTEGER DEFAULT 0,
            pg_db_bytes INTEGER, pg_events_rows INTEGER,
            identities_count INTEGER DEFAULT 0, total_requests INTEGER DEFAULT 0,
            pg_index_bytes INTEGER DEFAULT 0, pg_active_conns INTEGER DEFAULT 0,
            pg_idle_conns INTEGER DEFAULT 0, pg_tx_total INTEGER DEFAULT 0,
            net_rx_bps INTEGER DEFAULT 0, net_tx_bps INTEGER DEFAULT 0)""")
        conn.execute("INSERT INTO svc_metrics (ts, cpu_pct, mem_pct, procs, net_rx_bps, net_tx_bps) VALUES (?,?,?,?,?,?)",
                     (now_b + 10, 42.0, 55.0, 99, 1000, 500))
        conn.commit(); conn.close()

        orig = sm._DATA_PATH
        sm._DATA_PATH = db
        try:
            with _route_svc_db_history_to(db):
                result = sm._svc_db_history(now_b, now_b + 300, 300, AVG_KEYS, MAX_KEYS, SUM_KEYS)
        finally:
            sm._DATA_PATH = orig

        assert len(result) == 2
        hit = next((r for r in result if r["ts"] == now_b), None)
        assert hit is not None, f"bucket {now_b} missing from result"
        assert hit["cpu_pct"] == 42.0
        assert hit["mem_pct"] == 55.0
        assert hit["procs"] == 99
        assert hit["net_rx_bps"] == 1000

    def test_b3_empty_buckets_filled_with_zeros(self, tmp_path):
        import dashboards.service_metrics as sm
        db = str(tmp_path / "sparse.db")
        base = 0
        conn = sqlite3.connect(db)
        conn.execute("""CREATE TABLE svc_metrics (
            ts REAL PRIMARY KEY, cpu_pct REAL DEFAULT 0, mem_pct REAL DEFAULT 0,
            load1 REAL DEFAULT 0, load5 REAL DEFAULT 0, load15 REAL DEFAULT 0,
            swap_used INTEGER DEFAULT 0, disk_pct REAL DEFAULT 0, cg_pct REAL DEFAULT 0,
            mem_used INTEGER DEFAULT 0, disk_used INTEGER DEFAULT 0,
            pg_cache_hit_pct REAL DEFAULT 0,
            procs INTEGER DEFAULT 0, open_fds INTEGER DEFAULT 0,
            db_db INTEGER DEFAULT 0, db_wal INTEGER DEFAULT 0, db_shm INTEGER DEFAULT 0,
            db_total INTEGER DEFAULT 0, cg_used INTEGER DEFAULT 0, cg_limit INTEGER DEFAULT -1,
            mem_total INTEGER DEFAULT 0, disk_total INTEGER DEFAULT 0,
            disk_avail INTEGER DEFAULT 0, swap_total INTEGER DEFAULT 0,
            pg_db_bytes INTEGER, pg_events_rows INTEGER,
            identities_count INTEGER DEFAULT 0, total_requests INTEGER DEFAULT 0,
            pg_index_bytes INTEGER DEFAULT 0, pg_active_conns INTEGER DEFAULT 0,
            pg_idle_conns INTEGER DEFAULT 0, pg_tx_total INTEGER DEFAULT 0,
            net_rx_bps INTEGER DEFAULT 0, net_tx_bps INTEGER DEFAULT 0)""")
        # Only insert a sample in bucket 0; buckets 3600 and 7200 will be missing
        conn.execute("INSERT INTO svc_metrics (ts, cpu_pct) VALUES (?,?)", (base + 1, 10.0))
        conn.commit(); conn.close()

        orig = sm._DATA_PATH
        sm._DATA_PATH = db
        try:
            with _route_svc_db_history_to(db):
                result = sm._svc_db_history(base, base + 3 * 3600, 3600, AVG_KEYS, MAX_KEYS, SUM_KEYS)
        finally:
            sm._DATA_PATH = orig

        assert len(result) == 4, f"expected 4 buckets, got {len(result)}"
        assert result[0]["cpu_pct"] == 10.0
        assert result[1]["cpu_pct"] == 0   # empty bucket → zero
        assert result[2]["cpu_pct"] == 0
        assert result[3]["cpu_pct"] == 0

    def test_b4_result_has_all_required_keys(self, tmp_path):
        import dashboards.service_metrics as sm
        db = str(tmp_path / "keys.db")
        conn = sqlite3.connect(db)
        conn.execute("""CREATE TABLE svc_metrics (
            ts REAL PRIMARY KEY, cpu_pct REAL DEFAULT 0, mem_pct REAL DEFAULT 0,
            load1 REAL DEFAULT 0, load5 REAL DEFAULT 0, load15 REAL DEFAULT 0,
            swap_used INTEGER DEFAULT 0, disk_pct REAL DEFAULT 0, cg_pct REAL DEFAULT 0,
            mem_used INTEGER DEFAULT 0, disk_used INTEGER DEFAULT 0,
            pg_cache_hit_pct REAL DEFAULT 0, procs INTEGER DEFAULT 0,
            open_fds INTEGER DEFAULT 0, db_db INTEGER DEFAULT 0, db_wal INTEGER DEFAULT 0,
            db_shm INTEGER DEFAULT 0, db_total INTEGER DEFAULT 0,
            cg_used INTEGER DEFAULT 0, cg_limit INTEGER DEFAULT -1,
            mem_total INTEGER DEFAULT 0, disk_total INTEGER DEFAULT 0,
            disk_avail INTEGER DEFAULT 0, swap_total INTEGER DEFAULT 0,
            pg_db_bytes INTEGER, pg_events_rows INTEGER,
            identities_count INTEGER DEFAULT 0, total_requests INTEGER DEFAULT 0,
            pg_index_bytes INTEGER DEFAULT 0, pg_active_conns INTEGER DEFAULT 0,
            pg_idle_conns INTEGER DEFAULT 0, pg_tx_total INTEGER DEFAULT 0,
            net_rx_bps INTEGER DEFAULT 0, net_tx_bps INTEGER DEFAULT 0)""")
        conn.commit(); conn.close()
        orig = sm._DATA_PATH
        sm._DATA_PATH = db
        try:
            result = sm._svc_db_history(0, 3600, 3600, AVG_KEYS, MAX_KEYS, SUM_KEYS)
        finally:
            sm._DATA_PATH = orig
        assert len(result) == 2
        row = result[0]
        for k in AVG_KEYS + MAX_KEYS + SUM_KEYS:
            assert k in row, f"key '{k}' missing from _svc_db_history result row"
        assert "ts" in row


# ─── C. Endpoint routing ──────────────────────────────────────────────────────

class TestC_EndpointRouting:
    def test_c1_uses_db_path_when_range_exceeds_buffer(self):
        """When start_b < buffer oldest ts, _svc_db_history must be called."""
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 5000]
        # The condition must compare start_b to _buf_oldest
        assert "start_b < _buf_oldest" in fn_body, \
            "endpoint must branch on 'start_b < _buf_oldest' to select DB path"

    def test_c2_memory_path_unchanged_for_short_ranges(self):
        """The in-memory bucketing loop must still exist for short ranges."""
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 5000]
        assert "for s in _mem_raw:" in fn_body, \
            "in-memory bucketing loop 'for s in _mem_raw:' must exist for short-range path"

    def test_c3_current_always_from_memory(self):
        """current snapshot must come from _mem_raw (not the DB query result)."""
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 1000]
        assert "current = _mem_raw[-1]" in fn_body, \
            "current must always be taken from _mem_raw (most recent in-memory sample)"

    def test_c4_db_retention_hours_used_in_prune(self):
        """svc_metric_prune must reference SVC_DB_RETENTION_HOURS."""
        src = open(os.path.join(os.path.dirname(_SRC), "service_metrics.py"),
                   encoding="utf-8").read()
        assert "SVC_DB_RETENTION_HOURS" in src, \
            "SVC_DB_RETENTION_HOURS must be used in the prune logic"
        assert "svc_metric_prune" in src, \
            "svc_metric_prune queue op must still be present"


# ─── S. Additional static QA ──────────────────────────────────────────────────

class TestS_StaticQA:
    @staticmethod
    def _svc_db_history_body(src: str) -> str:
        """Return the full _svc_db_history function body.

        The function grew a long docstring + comment block (1.9.1 iter-18:
        routed through db.open_conn for PG-only mode), pushing conn.close()
        and the except clause past the old fixed 2000-char window. Slice to
        the next top-level def instead so the structural guard still anchors
        on the function's real extent.
        """
        fn_start = src.find("def _svc_db_history(")
        nxt = src.find("\ndef ", fn_start + 1)
        nxt2 = src.find("\nasync def ", fn_start + 1)
        ends = [e for e in (nxt, nxt2) if e != -1]
        fn_end = min(ends) if ends else fn_start + 4000
        return src[fn_start:fn_end]

    def test_s1_svc_db_history_closes_connection(self):
        src = _svc_src()
        fn_body = self._svc_db_history_body(src)
        assert "conn.close()" in fn_body, \
            "_svc_db_history must call conn.close() after query"

    def test_s2_svc_db_history_has_try_except(self):
        src = _svc_src()
        fn_body = self._svc_db_history_body(src)
        assert "except Exception" in fn_body, \
            "_svc_db_history must catch Exception to survive DB errors"

    def test_s3_avg_keys_max_keys_sum_keys_defined_in_endpoint(self):
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 3000]
        for name in ("AVG_KEYS", "MAX_KEYS", "SUM_KEYS"):
            assert name in fn_body, \
                f"{name} must be defined inside service_metrics_data_endpoint"

    def test_s4_endpoint_reads_range_query_param(self):
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 2000]
        assert '"range"' in fn_body or "'range'" in fn_body, \
            "endpoint must read ?range query param"

    def test_s5_endpoint_reads_bucket_query_param(self):
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 2000]
        assert '"bucket"' in fn_body or "'bucket'" in fn_body, \
            "endpoint must read ?bucket query param"

    def test_s6_svc_db_history_uses_avg_for_avg_keys(self):
        src = _svc_src()
        fn_start = src.find("def _svc_db_history(")
        fn_body = src[fn_start:fn_start + 2000]
        assert "AVG(" in fn_body.upper(), \
            "_svc_db_history must use AVG() for avg_keys aggregation"

    def test_s7_svc_db_history_uses_max_for_max_keys(self):
        src = _svc_src()
        fn_start = src.find("def _svc_db_history(")
        fn_body = src[fn_start:fn_start + 2000]
        assert "MAX(" in fn_body.upper(), \
            "_svc_db_history must use MAX() for max_keys aggregation"

    def test_s8_endpoint_range_cap_is_30_days(self):
        """Range cap must allow up to 30d (43200 min) so long windows work."""
        src = _svc_src()
        assert "43200" in src, \
            "endpoint range cap must allow up to 43200 minutes (30 days)"

    def test_s9_buf_oldest_uses_float_inf_when_empty(self):
        src = _svc_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        fn_body = src[fn_start:fn_start + 5000]
        assert "float(\"inf\")" in fn_body or "float('inf')" in fn_body, \
            "_buf_oldest must default to float('inf') when deque is empty so DB path triggers"


# ─── D. Dynamic HTTP tests ───────────────────────────────────────────────────

import asyncio
from contextlib import asynccontextmanager
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


@asynccontextmanager
async def _spin_upstream_d():
    app = web.Application()
    async def _echo(req): return web.json_response({"ok": True})
    app.router.add_route("*", "/{tail:.*}", _echo)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy_d(proxy_module, upstream_url):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


def _authed_cookie_d(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _run_d(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _seed_svc_metrics(db_path: str, rows: list[dict]):
    """Insert rows into svc_metrics in the test DB."""
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE IF NOT EXISTS svc_metrics (
        ts REAL PRIMARY KEY,
        cpu_pct REAL DEFAULT 0, load1 REAL DEFAULT 0, load5 REAL DEFAULT 0,
        load15 REAL DEFAULT 0, mem_used INTEGER DEFAULT 0,
        mem_total INTEGER DEFAULT 0, mem_avail INTEGER DEFAULT 0,
        mem_pct REAL DEFAULT 0, swap_used INTEGER DEFAULT 0,
        swap_total INTEGER DEFAULT 0, cg_used INTEGER DEFAULT 0,
        cg_limit INTEGER DEFAULT -1, cg_pct REAL DEFAULT 0,
        disk_used INTEGER DEFAULT 0, disk_total INTEGER DEFAULT 0,
        disk_avail INTEGER DEFAULT 0, disk_pct REAL DEFAULT 0,
        procs INTEGER DEFAULT 0, open_fds INTEGER DEFAULT 0,
        net_rx_bps INTEGER DEFAULT 0, net_tx_bps INTEGER DEFAULT 0,
        db_db INTEGER DEFAULT 0, db_wal INTEGER DEFAULT 0,
        db_shm INTEGER DEFAULT 0, db_total INTEGER DEFAULT 0,
        pg_db_bytes INTEGER, pg_events_rows INTEGER,
        identities_count INTEGER DEFAULT 0, total_requests INTEGER DEFAULT 0,
        pg_index_bytes INTEGER DEFAULT 0, pg_active_conns INTEGER DEFAULT 0,
        pg_idle_conns INTEGER DEFAULT 0, pg_cache_hit_pct REAL DEFAULT 0,
        pg_tx_total INTEGER DEFAULT 0)""")
    for r in rows:
        conn.execute(
            "INSERT OR REPLACE INTO svc_metrics (ts, cpu_pct, mem_pct, procs) VALUES (?,?,?,?)",
            (r["ts"], r.get("cpu_pct", 0.0), r.get("mem_pct", 0.0), r.get("procs", 0)))
    conn.commit()
    conn.close()


NS = "/antibot-appsec-gateway/secured"


class TestD_Dynamic:
    def test_d1_service_data_returns_200(self, proxy_module):
        """Basic authenticated request to /service-data → 200."""
        async def go():
            async with _spin_upstream_d() as up:
                async with _spin_proxy_d(proxy_module, up) as c:
                    cookie = _authed_cookie_d(proxy_module)
                    r = await c.get(NS + "/service-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run_d(go())

    def test_d2_service_data_response_has_required_keys(self, proxy_module):
        """Response must contain timeline/history and current keys."""
        async def go():
            async with _spin_upstream_d() as up:
                async with _spin_proxy_d(proxy_module, up) as c:
                    cookie = _authed_cookie_d(proxy_module)
                    r = await c.get(NS + "/service-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "current" in d, "response must have 'current' key"
                    assert "history" in d or "timeline" in d, \
                        "response must have 'history' or 'timeline' key"
        _run_d(go())

    def test_d3_service_data_db_path_with_seeded_data(self, proxy_module):
        """Request 30d window — start_b will be days ago, always < buffer oldest.
        Seed one row in the DB; verify DB path fires and returns non-empty history.
        Does NOT mutate SERVICE_METRICS_HISTORY to avoid session contamination."""
        import dashboards.service_metrics as sm

        # Seed SQLite with a sample 2 hours ago
        now_ts = int(time.time())
        two_h_ago = now_ts - 7200
        _seed_svc_metrics(proxy_module.DB_PATH, [
            {"ts": two_h_ago, "cpu_pct": 37.5, "mem_pct": 62.0, "procs": 123},
        ])

        orig_data_path = sm._DATA_PATH
        sm._DATA_PATH = proxy_module.DB_PATH

        async def go():
            async with _spin_upstream_d() as up:
                async with _spin_proxy_d(proxy_module, up) as c:
                    cookie = _authed_cookie_d(proxy_module)
                    # 30-day window with 1h buckets: start_b is ~30d ago, always < _buf_oldest
                    r = await c.get(NS + "/service-data?range=43200&bucket=3600",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    hist = d.get("history") or d.get("timeline") or []
                    assert isinstance(hist, list), "history must be a list"
                    assert len(hist) > 0, "history must be non-empty when DB has data"
        try:
            _run_d(go())
        finally:
            sm._DATA_PATH = orig_data_path

    def test_d4_service_data_no_secret_keys_in_response(self, proxy_module):
        """Response must never expose secret env vars (admin key, session key, etc.)."""
        async def go():
            async with _spin_upstream_d() as up:
                async with _spin_proxy_d(proxy_module, up) as c:
                    cookie = _authed_cookie_d(proxy_module)
                    r = await c.get(NS + "/service-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    for secret in ("ADMIN_KEY", "SESSION_KEY", "POW_HMAC_KEY", ".admin_key"):
                        assert secret not in body, \
                            f"service-data response must not contain secret: {secret!r}"
        _run_d(go())

    def test_d5_service_data_samples_in_buffer_field_present(self, proxy_module):
        """Response metadata must include samples_in_buffer."""
        async def go():
            async with _spin_upstream_d() as up:
                async with _spin_proxy_d(proxy_module, up) as c:
                    cookie = _authed_cookie_d(proxy_module)
                    r = await c.get(NS + "/service-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "samples_in_buffer" in d, \
                        "response must include samples_in_buffer field"
        _run_d(go())

    def test_d6_service_data_cache_control_no_store(self, proxy_module):
        """Response must not be cached (Cache-Control: no-store)."""
        async def go():
            async with _spin_upstream_d() as up:
                async with _spin_proxy_d(proxy_module, up) as c:
                    cookie = _authed_cookie_d(proxy_module)
                    r = await c.get(NS + "/service-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, \
                        f"Cache-Control must include no-store, got: {cc!r}"
        _run_d(go())
