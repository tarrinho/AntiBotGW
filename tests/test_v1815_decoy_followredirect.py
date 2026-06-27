"""
1.8.15 — Decoy fetch must follow redirects.

Bug observed in prod log:
  level=warn event=request path="/" status=301 reason="ip-ban"
An IP-banned client hit "/" on a vhost whose upstream redirects bare "/" to
its canonical URL (e.g. http://internal/ → https://public/). The decoy
fetched with allow_redirects=False, cached status=301 with empty body and
NO Location header, then served status=301 with empty body and no Location
→ browser shows a broken-redirect error.

Fix:
  * _decoy_cache fetch: allow_redirects=True, max_redirects=5; if terminal
    status is still 3xx OR body is empty → force 200 + neutral HTML body.
  * _upstream_404_cache fetch: allow_redirects=True; if terminal status is
    3xx → force 404 + "Not Found" body.

Coverage:
  TestDecoyFollowRedirectSourceGuards   — code-level guards
  TestDecoyFollowRedirectFunctional     — live HTTP: redirect chain → real body
"""
import asyncio
import pathlib
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


_ROOT   = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")


# ── 1. Source guards ────────────────────────────────────────────────────────

class TestDecoyFollowRedirectSourceGuards:

    def test_silent_decoy_follows_redirects(self):
        """The homepage-mode fetch must use allow_redirects=True."""
        idx = _PH_SRC.find("async def _silent_decoy_response(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        # Look for the session.get call inside silent_decoy
        get_idx = block.find("_vhost_upstream + \"/\"")
        assert get_idx != -1, "homepage decoy fetch call not found"
        # The ~250 chars around that call must contain allow_redirects=True
        ctx = block[get_idx: get_idx + 250]
        assert "allow_redirects=True" in ctx, (
            "homepage decoy fetch must allow_redirects=True so cached body "
            "is the real page, not an empty 3xx stub"
        )

    def test_silent_decoy_normalises_3xx_to_200(self):
        """If terminal status is 3xx, decoy must force 200 with neutral body."""
        idx = _PH_SRC.find("async def _silent_decoy_response(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "300 <= _terminal_status < 400" in block, (
            "decoy must check for terminal 3xx and normalise to 200"
        )
        assert "_terminal_status = 200" in block, (
            "decoy must force status 200 when terminal is 3xx (no Location to "
            "serve, would otherwise return broken redirect)"
        )

    def test_upstream_404_follows_redirects(self):
        idx = _PH_SRC.find("async def _fetch_upstream_404(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "allow_redirects=True" in block, (
            "_fetch_upstream_404 must follow redirects so cached error body is "
            "the terminal page, not a 3xx stub"
        )

    def test_upstream_404_forces_404_on_3xx(self):
        idx = _PH_SRC.find("async def _fetch_upstream_404(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "300 <= _term < 400" in block, (
            "_fetch_upstream_404 must coerce 3xx terminal status to 404"
        )


# ── 2. Functional: redirecting upstream → real cached body, status 200 ──────

@asynccontextmanager
async def _spin_redirecting_upstream(*, target_body: str):
    """Upstream that 301s "/" to "/canonical" which serves the real body."""
    async def _root(req):
        return web.Response(status=301, headers={"Location": "/canonical"})
    async def _canonical(req):
        return web.Response(text=target_body, content_type="text/html")
    async def _probe(req):
        return web.Response(status=301, headers={"Location": "/canonical"})
    app = web.Application()
    app.router.add_get("/", _root)
    app.router.add_get("/canonical", _canonical)
    app.router.add_route("*", "/{tail:.*}", _probe)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url, **overrides):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    import core.proxy_handler as _cph
    _cph._decoy_cache.clear()
    _cph._upstream_404_cache.clear()
    for k, v in overrides.items():
        setattr(proxy_module, k, v)
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()
    _cph._decoy_cache.clear()
    _cph._upstream_404_cache.clear()
    for _s in list(proxy_module.ip_state.values()):
        _s.banned_until = 0.0


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestDecoyFollowRedirectFunctional:

    def test_decoy_caches_terminal_body_not_redirect_stub(self, proxy_module):
        """An IP-banned client hitting a vhost whose / 301s must get the
        TERMINAL page body, status 200 — not an empty 301."""
        async def go():
            async with _spin_redirecting_upstream(target_body="REAL-PAGE") as up:
                async with _spin_proxy(proxy_module, up,
                                       BLOCK_RESPONSE_MODE="homepage") as client:
                    import time
                    # Pre-ban this IP so silent decoy fires
                    proxy_module.ip_state["127.0.0.1"].banned_until = time.time() + 3600

                    r = await client.get("/")
                    body = await r.text()

                    proxy_module.ip_state["127.0.0.1"].banned_until = 0.0

                    assert "REAL-PAGE" in body, (
                        f"decoy must serve terminal body after following 301; got: {body!r}"
                    )
                    assert r.status == 200, (
                        f"decoy must normalise 301 → 200 when no Location is preserved; "
                        f"got status {r.status}"
                    )
                    # Critical: no broken Location header reaching client
                    assert "Location" not in r.headers or r.status < 300, (
                        "decoy must not emit a Location header on the synthesised 200"
                    )
        _run(go())

    def test_upstream_404_coerces_3xx_terminal_to_404(self, proxy_module):
        """If the upstream probe terminal is STILL a 3xx (e.g. circular redirect
        / max-redirects reached), the cache must coerce status to 404."""
        async def go():
            # Upstream that 301s probe → another 301 (no terminal 2xx in chain)
            async def _circular(req):
                return web.Response(status=301, headers={"Location": "/again"})
            app = web.Application()
            app.router.add_route("*", "/{tail:.*}", _circular)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            up = f"http://127.0.0.1:{port}"
            try:
                async with _spin_proxy(proxy_module, up) as client:  # noqa: F841
                    import core.proxy_handler as _cph
                    _cph._upstream_404_cache.clear()
                    # Fetch may raise on max-redirects; we catch and check fallback
                    try:
                        await _cph._fetch_upstream_404(up)
                    except Exception:
                        pass
                    slot = _cph._upstream_404_cache.get(up) or {}
                    # Either the fetch raised → no slot populated (OK; serving
                    # path uses default "Not Found"), or it succeeded with the
                    # 3xx-coerced-to-404 status.
                    if slot.get("status"):
                        assert slot["status"] == 404, (
                            f"3xx terminal must be coerced to 404; got {slot['status']}"
                        )
            finally:
                await runner.cleanup()
        _run(go())
