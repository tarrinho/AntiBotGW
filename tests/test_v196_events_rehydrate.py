"""
1.9.6 — recent-event ring-buffer rehydrate on restart
=====================================================

Companion to _rehydrate_timeline (1.9.4, restores the trend chart). The
dashboard's "recent events" list + by-reason/by-path breakdowns are built from
in-memory ring buffers (events_by_cat / events / by_path_by_cat) that start
EMPTY on a restart and only refill as new traffic arrives. _rehydrate_events
repopulates them from the persisted events table at startup (backend-aware via
db_read_events), mirroring record()'s category mapping.

Coverage
────────
B1  rehydrate populates events_by_cat with correct categories
    (allowed / ban / authbots / gwmgmt) + the events deque + by_path_by_cat
B2  source: on_startup calls _rehydrate_events; reader is backend-aware
"""
import sqlite3
import time
from pathlib import Path

_PROJ = Path(__file__).resolve().parent.parent
_EVENTS_DDL = (
    "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "ts REAL NOT NULL, ip TEXT NOT NULL, ua TEXT, path TEXT, method TEXT, "
    "status INTEGER, reason TEXT, vhost TEXT)"
)


def test_rehydrate_events_categorizes(proxy_module):
    import state
    from db.sqlite import _rehydrate_events
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.execute(_EVENTS_DDL)
    conn.execute("DELETE FROM events")
    n = time.time()
    rows = [
        (n - 5, "1.1.1.1", "ua", "/page", "GET", 200, "", ""),                # allowed
        (n - 4, "2.2.2.2", "curl", "/.env", "GET", 404, "honeypot", ""),      # ban
        (n - 3, "3.3.3.3", "bot", "/x", "GET", 200, "authorized-robot", ""),  # authbots
        (n - 2, "4.4.4.4", "ua", "/antibot-appsec-gateway/secured/x", "GET", 200, "operator-self", ""),  # gwmgmt
    ]
    conn.executemany("INSERT INTO events (ts,ip,ua,path,method,status,reason,vhost) "
                     "VALUES (?,?,?,?,?,?,?,?)", rows)
    conn.commit(); conn.close()

    for dq in state.events_by_cat.values():
        dq.clear()
    state.events.clear()

    got = _rehydrate_events()
    assert got == 4, f"expected 4 events rehydrated, got {got}"
    assert "1.1.1.1" in {e["ip"] for e in state.events_by_cat["allowed"]}
    assert "2.2.2.2" in {e["ip"] for e in state.events_by_cat["ban"]}
    assert "3.3.3.3" in {e["ip"] for e in state.events_by_cat["authbots"]}
    assert "4.4.4.4" in {e["ip"] for e in state.events_by_cat["gwmgmt"]}, \
        "admin-namespace path must categorize as gwmgmt before reason check"
    assert len(state.events) == 4
    # by_path_by_cat populated for the breakdowns
    assert state.by_path_by_cat["ban"].get("/.env", 0) == 1


def test_source_rehydrate_events_wired():
    proxy_src = (_PROJ / "proxy.py").read_text(encoding="utf-8")
    assert "_rehydrate_events()" in proxy_src, "on_startup must call _rehydrate_events()"
    db_src = (_PROJ / "db" / "sqlite.py").read_text(encoding="utf-8")
    fn = db_src[db_src.index("def _rehydrate_events("):]
    fn = fn[:fn.index("\ndef ", 1)]
    assert "db_read_events" in fn, "_rehydrate_events must use the backend-aware db_read_events"
    assert "_sqlite_connect" not in fn, "must not bypass the backend dispatcher"
