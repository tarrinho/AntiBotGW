"""
1.9.5 perf — guard the two hot-path optimizations:

  #1 Shared pooled upstream ClientSession (was: new session + TCP/TLS per request)
  #3 TTL cache for the per-request IP-ban SQLite lookup (writer invalidates on write)
"""
import os
import time
import asyncio
import inspect

os.environ.setdefault("UPSTREAM", "https://example.com")

import core.proxy_handler as ph
import db.sqlite as s


# ── #1 shared upstream session ─────────────────────────────────────────────
def test_shared_session_is_reused_and_pooled():
    async def go():
        await ph._close_upstream_session()  # clean slate
        s1 = ph._get_upstream_session()
        s2 = ph._get_upstream_session()
        assert s1 is s2, "session must be reused across calls, not recreated"
        assert not s1.closed
        # pooled connector with the configured limit + keep-alive
        assert s1.connector.limit == ph.UPSTREAM_POOL_LIMIT
        await ph._close_upstream_session()
        assert ph._UPSTREAM_SESSION is None
        assert s1.closed, "close must actually close the session"
    asyncio.run(go())


def test_shared_session_recreated_after_close():
    async def go():
        s1 = ph._get_upstream_session()
        await ph._close_upstream_session()
        s2 = ph._get_upstream_session()
        assert s2 is not s1 and not s2.closed, "must transparently recreate after close"
        await ph._close_upstream_session()
    asyncio.run(go())


def test_proxy_forward_uses_shared_session_not_per_request():
    src = inspect.getsource(ph.proxy)
    assert "_get_upstream_session()" in src, "proxy() must use the shared session"
    # the old per-request pattern must be gone from the forward path
    assert "async with ClientSession(timeout=ClientTimeout(total=30))" not in src, \
        "proxy() must not open a new ClientSession per request"


def test_close_wired_into_on_cleanup():
    import proxy as proxymod
    src = inspect.getsource(proxymod.on_cleanup)
    assert "_close_upstream_session" in src, "on_cleanup must close the shared session"


# ── #3 TTL ban cache ───────────────────────────────────────────────────────
def test_ban_cache_serves_hit_from_cache(monkeypatch):
    s._ban_cache.clear()
    calls = {"n": 0}
    future = time.time() + 1000
    def fake(ip):
        calls["n"] += 1
        return future
    monkeypatch.setattr(s, "check_ip_ban", fake)
    assert s.check_ip_ban_cached("1.2.3.4") == future   # DB hit
    assert s.check_ip_ban_cached("1.2.3.4") == future   # cache hit
    assert calls["n"] == 1, "second lookup must be served from cache (no DB)"
    s._ban_cache.clear()


def test_ban_cache_negative_cached_then_invalidated(monkeypatch):
    s._ban_cache.clear()
    calls = {"n": 0}
    def fake(ip):
        calls["n"] += 1
        return 0.0
    monkeypatch.setattr(s, "check_ip_ban", fake)
    assert s.check_ip_ban_cached("5.5.5.5") == 0.0       # DB hit, caches "clear"
    assert s.check_ip_ban_cached("5.5.5.5") == 0.0       # cache hit
    assert calls["n"] == 1
    # writer invalidation forces a re-read (so a fresh ban is enforced now)
    s._ban_cache_invalidate("5.5.5.5")
    assert s.check_ip_ban_cached("5.5.5.5") == 0.0
    assert calls["n"] == 2, "invalidation must force a DB re-read"
    s._ban_cache.clear()


def test_ban_cache_expired_ban_rereads(monkeypatch):
    """A cached banned_until that has since passed must NOT be served stale."""
    s._ban_cache.clear()
    past = time.time() - 1
    # seed cache directly with an already-expired ban, freshly cached
    s._ban_cache["7.7.7.7"] = (past, time.time())
    calls = {"n": 0}
    def fake(ip):
        calls["n"] += 1
        return 0.0
    monkeypatch.setattr(s, "check_ip_ban", fake)
    assert s.check_ip_ban_cached("7.7.7.7") == 0.0
    assert calls["n"] == 1, "expired cached ban must trigger a re-read, not serve stale"
    s._ban_cache.clear()


def test_ban_cache_ttl_expiry(monkeypatch):
    s._ban_cache.clear()
    monkeypatch.setattr(s, "_BAN_CACHE_TTL", 0.0)  # force every lookup to re-read
    calls = {"n": 0}
    def fake(ip):
        calls["n"] += 1
        return 0.0
    monkeypatch.setattr(s, "check_ip_ban", fake)
    s.check_ip_ban_cached("8.8.8.8")
    s.check_ip_ban_cached("8.8.8.8")
    assert calls["n"] == 2, "zero TTL must re-read every time"
    s._ban_cache.clear()


def test_vhost_ban_cache(monkeypatch):
    s._ban_cache_vhost.clear()
    calls = {"n": 0}
    future = time.time() + 1000
    def fake(ip, vhost):
        calls["n"] += 1
        return future
    monkeypatch.setattr(s, "check_ip_ban_vhost", fake)
    assert s.check_ip_ban_vhost_cached("1.1.1.1", "a.tld") == future
    assert s.check_ip_ban_vhost_cached("1.1.1.1", "a.tld") == future
    assert calls["n"] == 1
    # global invalidation also clears per-vhost entries for that IP
    s._ban_cache_invalidate("1.1.1.1")
    assert ("1.1.1.1", "a.tld") not in s._ban_cache_vhost
    s._ban_cache_vhost.clear()


def test_writer_invalidates_ban_cache_on_write():
    """Source guard: every ban insert/delete op invalidates the cache."""
    src = inspect.getsource(s.db_writer_loop)
    assert src.count("_ban_cache_invalidate(") >= 4, \
        "all 4 ban ops (ip_ban, ip_ban_del, ip_ban_vhost, ip_ban_vhost_del) must invalidate"
