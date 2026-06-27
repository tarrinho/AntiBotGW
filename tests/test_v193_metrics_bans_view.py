"""
metrics_endpoint `?view=bans` fast path  (1.9.3 perf)
=====================================================

The Controls page bans table refreshes every 4 s via `loadBans()`, which used
to GET `/secured/metrics` with no params — forcing the handler to sort EVERY
tracked identity in `ip_state` and build a ~20-field dict per client under the
global `state_lock`, plus a timeline + top_paths + path→vhost aggregation, only
for the client to discard all but `banned_secs > 0`. On a busy gateway with
thousands of active identities that O(all-identities)-under-lock loop made the
Controls page slow to load (~6 s) and kept it churning.

`?view=bans` skips the sort, early-`continue`s non-banned clients BEFORE the
costly per-client build, and returns just `{clients:[…]}` — no timeline work.

Coverage
────────
B1  behavioural — view=bans returns ONLY banned clients
  B1.1  banned client present, clean client absent
  B1.2  every returned client has banned_secs > 0
  B1.3  fast path omits timeline / top_paths (proves the skip)
  B1.4  default view (no param) still includes timeline AND the clean client
R1  source guards — the fast path can't be silently removed
  R1.1  proxy_handler: `_bans_only` flag derived from ?view=bans
  R1.2  proxy_handler: early-continue on non-banned in bans mode
  R1.3  proxy_handler: early json_response({"clients": …}) return
  R1.4  controls.html: loadBans fetches metrics?view=bans
"""
import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

NS = "/antibot-appsec-gateway/secured"
_PROJ = Path(__file__).resolve().parent.parent


# ── Harness (mirrors test_vhost_filtering.py) ────────────────────────────────

async def _echo_handler(request: web.Request):
    return web.json_response({"path": request.path})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _echo_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


def _admin_cookie(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return {proxy_module._SESSION_COOKIE: proxy_module._session_sign("admin", sid=sid)}


def _seed_clients(proxy_module):
    """One banned + one clean identity in ip_state. banned_until is compared
    against now()=time.monotonic(), so use monotonic terms."""
    proxy_module.ip_state.clear()
    banned = proxy_module.ip_state["198.51.100.7"]
    banned.last_ip = "198.51.100.7"
    banned.banned_until = time.monotonic() + 3600
    banned.risk_score = 90.0
    banned.blocked_count = 5
    banned.last_user_agent = "curl/8.0"
    clean = proxy_module.ip_state["203.0.113.9"]
    clean.last_ip = "203.0.113.9"
    clean.banned_until = 0.0
    clean.risk_score = 5.0
    return "198.51.100.7", "203.0.113.9"


# ── B1: behavioural ──────────────────────────────────────────────────────────

class TestBansView:
    def test_view_bans_only_banned(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    bk, ck = _seed_clients(proxy_module)
                    cookie = _admin_cookie(proxy_module)
                    async with cl.get(NS + "/metrics?view=bans", cookies=cookie) as r:
                        assert r.status == 200
                        d = await r.json()
                    ids = {c["id"] for c in d.get("clients", [])}
                    # B1.1 — banned present, clean absent
                    assert bk in ids, "banned client must appear in view=bans"
                    assert ck not in ids, "clean client must NOT appear in view=bans"
                    # B1.2 — every returned client is actually banned
                    assert all(c["banned_secs"] > 0 for c in d["clients"]), \
                        "view=bans returned a non-banned client"
                    # B1.3 — fast path skips the timeline / top_paths build
                    assert "timeline" not in d, "view=bans must omit timeline"
                    assert "top_paths" not in d, "view=bans must omit top_paths"
        asyncio.new_event_loop().run_until_complete(go())

    def test_default_view_includes_timeline_and_clean(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    bk, ck = _seed_clients(proxy_module)
                    cookie = _admin_cookie(proxy_module)
                    async with cl.get(NS + "/metrics", cookies=cookie) as r:
                        assert r.status == 200
                        d = await r.json()
                    ids = {c["id"] for c in d.get("clients", [])}
                    # B1.4 — default path is unchanged: timeline present, clean client kept
                    assert "timeline" in d, "default metrics must include timeline"
                    assert bk in ids and ck in ids, \
                        "default metrics must include both banned and clean clients"
        asyncio.new_event_loop().run_until_complete(go())


# ── R1: source guards ─────────────────────────────────────────────────────────

class TestSourceGuards:
    def test_proxy_handler_has_bans_fast_path(self):
        src = (_PROJ / "core" / "proxy_handler.py").read_text(encoding="utf-8")
        # R1.1 — flag derived from the query param
        assert 'request.query.get("view", "") == "bans"' in src, \
            "metrics_endpoint must derive _bans_only from ?view=bans"
        assert "_bans_only" in src
        # R1.2 — early-continue on non-banned before the per-client dict build
        assert "_bans_only and s.banned_until <= n" in src, \
            "bans mode must skip non-banned clients before the costly build"
        # R1.3 — early return with just the clients list (no timeline work).
        # 1.9.6: the bans return now goes through the metrics response cache.
        assert '_metrics_cache_put(_ckey, {"clients": clients})' in src, \
            "bans mode must early-return {clients:[…]} before timeline build"

    def test_controls_loadbans_uses_view_bans(self):
        html = (_PROJ / "dashboards" / "controls.html").read_text(encoding="utf-8")
        assert "secured/metrics?view=bans" in html, \
            "controls.html loadBans must request the lightweight ?view=bans path"
