"""
1.9.4 — in-memory hardening: cardinality cap + timeline rehydrate
=================================================================

Two related robustness fixes for the "everything lives in memory" design:

A. CARDINALITY CAP — `metrics["by_path"]`, `by_path_by_cat[*]` (keyed by raw
   request path) and `metrics["by_ja4"]` (keyed by TLS fingerprint) are all
   client-controllable and were unbounded. A path-enumeration / TLS-churn flood
   could grow them until the process is OOM-killed. `_bump_capped` bounds them
   FIFO (oldest-inserted evicted first).

B. TIMELINE REHYDRATE — after a restart the in-memory `timeline` minute-bucket
   dict starts empty and the Live Feed chart never falls back to the DB for the
   recent window, so existing history shows blank. `_rehydrate_timeline()`
   repopulates it from the (backend-aware) `timeline` table on startup.

Coverage
────────
A1  _bump_capped bounds a dict at cap (FIFO eviction), increments existing keys
A2  source: the 3 hot-path counters use _bump_capped (no bare `[k] += 1`)
B1  _rehydrate_timeline loads persisted buckets into the in-memory OrderedDict
B2  source: uses open_conn() (backend-aware), NOT a bare sqlite connect
B3  source: proxy.py on_startup calls _rehydrate_timeline
"""
import json
import sqlite3
from pathlib import Path

_PROJ = Path(__file__).resolve().parent.parent


# ── A: cardinality cap ────────────────────────────────────────────────────────

def test_bump_capped_bounds_and_fifo(proxy_module):
    from core.metrics import _bump_capped
    d = {}
    for i in range(5000):
        _bump_capped(d, f"/p/{i}", cap=2048)
    assert len(d) == 2048, f"dict must be bounded at cap, got {len(d)}"
    # existing key just increments (no eviction)
    before = dict(d)
    any_key = next(iter(before))
    _bump_capped(d, any_key, cap=2048)
    assert d[any_key] == before[any_key] + 1
    assert len(d) == 2048
    # FIFO: oldest-inserted evicted first
    d2 = {}
    for k in ("/x", "/y", "/z"):
        _bump_capped(d2, k, cap=2)
    assert "/x" not in d2 and "/y" in d2 and "/z" in d2


def test_hotpath_counters_use_cap():
    src = (_PROJ / "core" / "metrics.py").read_text(encoding="utf-8")
    assert "_bump_capped(metrics[\"by_path\"]" in src, "by_path must use the cap helper"
    assert "_bump_capped(metrics[\"by_ja4\"]" in src, "by_ja4 must use the cap helper"
    assert "_bump_capped(by_path_by_cat[_req_cat]" in src, "by_path_by_cat must use the cap helper"
    # the old unbounded increments must be gone
    assert "metrics[\"by_path\"][path] += 1" not in src
    assert "by_path_by_cat[_req_cat][path] += 1" not in src


# ── B: timeline rehydrate ──────────────────────────────────────────────────────

def test_rehydrate_timeline_loads_db_buckets(proxy_module):
    import state
    from db.sqlite import _rehydrate_timeline
    # Seed two persisted buckets into the timeline table on the ACTIVE backend.
    # _rehydrate_timeline() is backend-aware (open_conn()), so under
    # APPSECGW_TEST_PG it reads Postgres, not the local SQLite file. Seeding
    # via sqlite3.connect(DB_PATH) directly therefore loaded the wrong store
    # in PG mode (rehydrate returned PG's rows, not the seeded ones). Seed
    # through db.open_conn() so the test exercises whichever backend is live.
    from db import open_conn
    conn = open_conn()
    conn.execute("CREATE TABLE IF NOT EXISTS timeline (bucket_minute INTEGER PRIMARY KEY, "
                 "total INTEGER DEFAULT 0, allowed INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, "
                 "missed INTEGER DEFAULT 0, by_reason TEXT)")
    conn.execute("DELETE FROM timeline")
    import time as _t
    b1 = (int(_t.time()) // 60) * 60 - 120
    b2 = b1 + 60
    conn.execute("INSERT INTO timeline (bucket_minute,total,allowed,blocked,missed,by_reason) "
                 "VALUES (?,?,?,?,?,?)", (b1, 10, 7, 3, 1, json.dumps({"ua-blocked": 3})))
    conn.execute("INSERT INTO timeline (bucket_minute,total,allowed,blocked,missed,by_reason) "
                 "VALUES (?,?,?,?,?,?)", (b2, 5, 5, 0, 0, json.dumps({})))
    conn.commit(); conn.close()

    state.timeline.clear()
    n = _rehydrate_timeline()
    assert n == 2, f"expected 2 buckets rehydrated, got {n}"
    assert b1 in state.timeline and b2 in state.timeline
    assert state.timeline[b1]["total"] == 10
    assert state.timeline[b1]["blocked"] == 3
    assert state.timeline[b1]["by_reason"]["ua-blocked"] == 3
    # ascending insert order → oldest (b1) at the head (eviction assumption)
    assert next(iter(state.timeline)) == b1


def test_rehydrate_timeline_is_backend_aware():
    src = (_PROJ / "db" / "sqlite.py").read_text(encoding="utf-8")
    fn = src[src.index("def _rehydrate_timeline("):]
    fn = fn[:fn.index("\ndef ", 1)]
    assert "open_conn()" in fn, "_rehydrate_timeline must use backend-aware open_conn()"
    assert "_sqlite_connect(" not in fn, \
        "_rehydrate_timeline must NOT use a bare sqlite connect (timeline is PG-mirrored)"


def test_onstartup_calls_rehydrate_timeline():
    src = (_PROJ / "proxy.py").read_text(encoding="utf-8")
    assert "_rehydrate_timeline()" in src, "on_startup must call _rehydrate_timeline()"
