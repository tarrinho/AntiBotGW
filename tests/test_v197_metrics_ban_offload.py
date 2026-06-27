"""
1.9.7 — metrics_endpoint must not do a synchronous SQLite ban-check per identity
================================================================================

A SIGUSR1 stack dump on armv7 caught the event loop frozen in:
    _sqlite_connect ← check_ip_ban ← check_ip_ban_cached ← metrics_endpoint
metrics_endpoint called check_ip_ban_cached() once PER tracked identity, each a
fresh _sqlite_connect (file open + WAL/mmap PRAGMAs) on the event loop — N synchronous
opens per dashboard poll froze the loop / `/live` on slow storage.

Fix: read the banned-IP set ONCE off the loop (asyncio.to_thread(check_ip_bans_bulk))
and membership-test in memory. This pins that.
"""
import sqlite3
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_PH = (_REPO / "core" / "proxy_handler.py").read_text(encoding="utf-8")


def _metrics_src():
    i = _PH.index("async def metrics_endpoint(")
    return _PH[i: _PH.find("\nasync def ", i + 1)]


def test_metrics_reads_bans_once_off_loop():
    body = _metrics_src()
    assert "to_thread(_cib_bulk)" in body or "to_thread(check_ip_bans_bulk" in body, \
        "metrics_endpoint must read the ban set once via asyncio.to_thread (off the loop)"


def test_metrics_has_no_per_identity_ban_check():
    body = _metrics_src()
    assert "check_ip_ban_cached(" not in body, \
        "metrics_endpoint must NOT call check_ip_ban_cached per identity (sync _sqlite_connect on the loop)"


def test_check_ip_bans_bulk_returns_banned_set(proxy_module):
    from db.sqlite import check_ip_bans_bulk, _sqlite_connect
    conn = _sqlite_connect(proxy_module.DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS ip_bans (ip TEXT PRIMARY KEY, banned_until REAL)")
    conn.execute("DELETE FROM ip_bans")
    n = time.time()
    conn.executemany("INSERT INTO ip_bans (ip, banned_until) VALUES (?,?)",
                     [("1.1.1.1", n + 3600), ("2.2.2.2", n - 10), ("3.3.3.3", n + 3600)])
    conn.commit(); conn.close()
    s = check_ip_bans_bulk()
    assert "1.1.1.1" in s and "3.3.3.3" in s, "currently-banned IPs must be returned"
    assert "2.2.2.2" not in s, "expired bans must be excluded"
