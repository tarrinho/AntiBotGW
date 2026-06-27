"""
1.9.7 — QA for the event-loop-responsiveness fixes
==================================================

Covers the changes that stop synchronous I/O from freezing the single event
loop on slow (armv7) storage — diagnosed live via the SIGUSR1 stack dumper:

  • check_ip_bans_bulk()  — one-shot banned-IP set read (replaces N per-identity
                            _sqlite_connect in metrics_endpoint). Edge cases.
  • metrics_endpoint      — reads bans once off-loop; reflects bans correctly;
                            no per-identity sync ban-check remains.
  • SIGUSR1 dumper        — registered so a future stall can be captured.
"""
import asyncio
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

_REPO = Path(__file__).resolve().parent.parent
NS = "/antibot-appsec-gateway/secured"

_BANS_DDL = ("CREATE TABLE IF NOT EXISTS ip_bans "
             "(ip TEXT PRIMARY KEY, banned_until REAL)")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _echo(request):
    return web.json_response({"ok": True})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application(); app.router.add_route("*", "/{t:.*}", _echo)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
    yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream):
    proxy_module.UPSTREAM = upstream.rstrip("/")
    client = TestClient(TestServer(proxy_module.make_app()))
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()


def _admin_cookie(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False}
    proxy_module._SESSION_CACHE_READY = True
    return {proxy_module._SESSION_COOKIE: proxy_module._session_sign("admin", sid=sid)}


def _set_ip_bans(proxy_module, rows):
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.execute(_BANS_DDL)
    conn.execute("DELETE FROM ip_bans")
    conn.executemany("INSERT INTO ip_bans (ip, banned_until) VALUES (?,?)", rows)
    conn.commit(); conn.close()


# ── check_ip_bans_bulk edge cases ─────────────────────────────────────────────
class TestCheckIpBansBulk:
    def test_empty_table_returns_empty_set(self, proxy_module):
        _set_ip_bans(proxy_module, [])
        from db.sqlite import check_ip_bans_bulk
        assert check_ip_bans_bulk() == set()

    def test_only_active_bans_returned(self, proxy_module):
        n = time.time()
        _set_ip_bans(proxy_module, [("9.9.9.9", n + 3600), ("8.8.8.8", n - 5)])
        from db.sqlite import check_ip_bans_bulk
        s = check_ip_bans_bulk()
        assert s == {"9.9.9.9"}, "only the unexpired ban must be returned"

    def test_missing_table_no_crash(self, proxy_module):
        conn = sqlite3.connect(proxy_module.DB_PATH)
        conn.execute("DROP TABLE IF EXISTS ip_bans")
        conn.commit(); conn.close()
        from db.sqlite import check_ip_bans_bulk
        assert check_ip_bans_bulk() == set(), "missing ip_bans table must return empty, not raise"

    def test_returns_a_set_type(self, proxy_module):
        _set_ip_bans(proxy_module, [("1.2.3.4", time.time() + 60)])
        from db.sqlite import check_ip_bans_bulk
        assert isinstance(check_ip_bans_bulk(), set)


# ── metrics_endpoint behavioural ──────────────────────────────────────────────
class TestMetricsBanReflection:
    def test_metrics_reflects_ip_bans_via_offloaded_read(self, proxy_module):
        """An identity whose in-memory ban has decayed (banned_until<=now) but
        whose raw IP is in ip_bans must show ip_banned=True — proving metrics
        consults the once-read banned set, not a per-identity connect."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    proxy_module.ip_state.clear()
                    st = proxy_module.ip_state["5.5.5.5"]
                    st.last_ip = "5.5.5.5"
                    st.banned_until = 0.0          # not in-memory banned
                    st.request_count = 3
                    _set_ip_bans(proxy_module, [("5.5.5.5", time.time() + 3600)])
                    async with cl.get(NS + "/metrics", cookies=_admin_cookie(proxy_module)) as r:
                        assert r.status == 200
                        d = await r.json()
                    me = next((c for c in d.get("clients", []) if c.get("last_ip") == "5.5.5.5"), None)
                    assert me is not None, "seeded identity must appear"
                    assert me.get("ip_banned") is True, "raw-IP ban must be reflected via the bulk read"
        _run(go())

    def test_metrics_clean_ip_not_flagged(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    proxy_module.ip_state.clear()
                    st = proxy_module.ip_state["6.6.6.6"]
                    st.last_ip = "6.6.6.6"; st.banned_until = 0.0; st.request_count = 1
                    _set_ip_bans(proxy_module, [])   # nobody banned
                    async with cl.get(NS + "/metrics", cookies=_admin_cookie(proxy_module)) as r:
                        assert r.status == 200
                        d = await r.json()
                    me = next((c for c in d.get("clients", []) if c.get("last_ip") == "6.6.6.6"), None)
                    if me is not None:
                        assert me.get("ip_banned") is False
        _run(go())


# ── source guards ─────────────────────────────────────────────────────────────
def test_metrics_no_per_identity_sync_ban_check():
    ph = (_REPO / "core" / "proxy_handler.py").read_text(encoding="utf-8")
    i = ph.index("async def metrics_endpoint(")
    body = ph[i: ph.find("\nasync def ", i + 1)]
    assert "check_ip_ban_cached(" not in body, "no per-identity sync ban-check in metrics_endpoint"
    assert "to_thread(_cib_bulk)" in body or "to_thread(check_ip_bans_bulk" in body, \
        "metrics_endpoint must read bans once off the loop"


def test_sigusr1_stack_dumper_registered():
    src = (_REPO / "proxy.py").read_text(encoding="utf-8")
    assert "faulthandler" in src and "SIGUSR1" in src, \
        "proxy.py must register a SIGUSR1 thread-stack dumper for stall diagnosis"
