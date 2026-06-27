"""
1.9.6 — /__metrics short-TTL response cache
===========================================

Every open dashboard polls /__metrics ~every 2 s; a full computation iterates
all ip_state + events + a synchronous timeline DB query, all on the single
event loop — so two near-simultaneous loads (clicking between two pages) stall
the UI. A ~1 s response cache lets rapid/concurrent identical requests reuse a
recent result instead of recomputing on the loop.

Cache is keyed by the full query string and disabled by default in tests
(`METRICS_RESP_TTL=0`, set in conftest); this test turns it on explicitly.

Coverage
────────
B1  a 2nd identical request within TTL is served from cache (stale vs a
    live state change) — proves no recompute
B2  clearing the cache forces a fresh recompute (reflects the state change)
B3  different query strings are cached independently (no cross-view collision)
R1  source: env-configurable TTL + cache check before the lock + returns cached
"""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

NS = "/antibot-appsec-gateway/secured"
_PROJ = Path(__file__).resolve().parent.parent


async def _echo(request): return web.json_response({"ok": 1})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application(); app.router.add_route("*", "/{t:.*}", _echo)
    r = web.AppRunner(app); await r.setup()
    s = web.TCPSite(r, "127.0.0.1", 0); await s.start()
    yield f"http://127.0.0.1:{s._server.sockets[0].getsockname()[1]}"
    await r.cleanup()


@asynccontextmanager
async def _spin_proxy(pm, up):
    pm.UPSTREAM = up.rstrip("/")
    cl = TestClient(TestServer(pm.make_app())); await cl.start_server()
    yield cl; await cl.close()


def _admin_cookie(pm):
    sid = pm._new_sid()
    pm._SESSION_CACHE[sid] = {"username": "admin",
                             "expires_ts": pm._t.time() + pm._SESSION_TTL,
                             "revoked": False}
    pm._SESSION_CACHE_READY = True
    return {pm._SESSION_COOKIE: pm._session_sign("admin", sid=sid)}


def test_metrics_response_cache(proxy_module):
    import core.proxy_handler as ph
    import state

    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as cl:
                ck = _admin_cookie(proxy_module)
                ph._metrics_resp_cache.clear()
                ph._METRICS_RESP_TTL = 5.0          # enable caching for this test
                try:
                    async with cl.get(NS + "/metrics?range=60", cookies=ck) as r1:
                        d1 = await r1.json()
                    t1 = d1["total"]
                    # mutate live state — a recompute WOULD reflect this
                    async with state.state_lock:
                        state.metrics["total_requests"] += 999
                    # B1 — 2nd identical request within TTL: served from cache (stale)
                    async with cl.get(NS + "/metrics?range=60", cookies=ck) as r2:
                        d2 = await r2.json()
                    assert d2["total"] == t1, "2nd request must be served from cache (stale total)"
                    # B3 — a different query string is NOT served from the same entry
                    async with cl.get(NS + "/metrics?range=120", cookies=ck) as r3:
                        d3 = await r3.json()
                    assert d3["total"] == t1 + 999, "different query string must recompute (fresh total)"
                    # B2 — clearing the cache forces a recompute
                    ph._metrics_resp_cache.clear()
                    async with cl.get(NS + "/metrics?range=60", cookies=ck) as r4:
                        d4 = await r4.json()
                    assert d4["total"] == t1 + 999, "after cache clear, must reflect live state"
                finally:
                    ph._METRICS_RESP_TTL = 0.0       # restore test default
                    ph._metrics_resp_cache.clear()
    asyncio.new_event_loop().run_until_complete(go())


def test_source_cache_wiring():
    src = (_PROJ / "core" / "proxy_handler.py").read_text(encoding="utf-8")
    assert 'os.environ.get("METRICS_RESP_TTL"' in src, "TTL must be env-configurable"
    assert "_metrics_resp_cache.get(_ckey)" in src, "must check the cache before computing"
    assert src.count("_metrics_cache_put(_ckey,") >= 2, "both returns must populate the cache"
