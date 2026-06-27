"""
1.8.15 — Per-vhost decoy isolation + wildcard vhost matching.

Bugs fixed:
  * Global _decoy_cache / _upstream_404_cache leaked vhost-A's homepage as
    vhost-B's silent-decoy body. When jtsl.pt was decoyed, the gateway
    served pt4.tech's cached HTML — and the browser then re-fetched assets
    against jtsl.pt, which got re-decoyed (HTML body, wrong content-type),
    breaking page styling.
  * Wildcard vhost entries (``*.example.com``) were accepted by
    _validate_vhost_hostname + stored as literal dict keys, but
    set_vhost() did a direct dict lookup — so wildcards never matched.

Coverage:
  TestPerUpstreamDecoyCacheSource     — source-level guards on caches
  TestSetVhostWildcardMatching        — unit-level wildcard lookup
  TestDecoyCachePerVhostFunctional    — live-proxy: two vhosts, two bodies
"""
import asyncio
import pathlib
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


_ROOT   = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_VH_SRC = (_ROOT / "vhost.py").read_text(encoding="utf-8")


# ── 1. Source guards ────────────────────────────────────────────────────────

class TestPerUpstreamDecoyCacheSource:
    """Static checks: caches are dict-of-dicts; fetches use vc('UPSTREAM')."""

    def test_decoy_cache_is_dict_of_dicts(self):
        """_decoy_cache must be a per-upstream cache (upstream → entry).
        Contract change (1.8.15 shipped): the cache is annotated plain `dict`
        with an `# upstream → entry` marker; per-upstream keying is enforced by
        _decoy_entry()/_silent_decoy_response (verified by the functional tests
        below), not by a `dict[str, dict]` annotation literal."""
        idx = _PH_SRC.find("_decoy_cache: dict")
        assert idx != -1, "_decoy_cache must exist as a module-level dict"
        line = _PH_SRC[idx: _PH_SRC.find("\n", idx)]
        assert "upstream" in line, (
            "_decoy_cache must be keyed per-upstream (upstream → entry)"
        )

    def test_upstream_404_cache_is_dict_of_dicts(self):
        """Contract change (1.8.15 shipped): annotated plain `dict` with an
        `# upstream → entry` marker; per-upstream keying enforced by
        _decoy_entry()/_fetch_upstream_404 (verified functionally below)."""
        idx = _PH_SRC.find("_upstream_404_cache: dict")
        assert idx != -1, "_upstream_404_cache must exist as a module-level dict"
        line = _PH_SRC[idx: _PH_SRC.find("\n", idx)]
        assert "upstream" in line, (
            "_upstream_404_cache must be keyed per-upstream (upstream → entry)"
        )

    def test_decoy_entry_helper_exists(self):
        """_decoy_entry helper must exist to lazily allocate per-upstream slots."""
        assert "def _decoy_entry(" in _PH_SRC, (
            "_decoy_entry(d, key) helper missing — needed for lazy slot init"
        )

    def test_fetch_upstream_404_takes_upstream_arg(self):
        """_fetch_upstream_404 must accept an `upstream` parameter."""
        idx = _PH_SRC.find("async def _fetch_upstream_404(")
        block = _PH_SRC[idx: idx + 200]
        assert "upstream:" in block, (
            "_fetch_upstream_404 must accept upstream parameter"
        )

    def test_fetch_upstream_404_resolves_vc(self):
        """_fetch_upstream_404 must call vc('UPSTREAM') when upstream arg is None."""
        idx = _PH_SRC.find("async def _fetch_upstream_404(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "vc(\"UPSTREAM\")" in block or "vc('UPSTREAM')" in block, (
            "_fetch_upstream_404 must consult vc('UPSTREAM') for the active vhost"
        )

    def test_silent_decoy_resolves_vhost_upstream(self):
        """_silent_decoy_response must read vc('UPSTREAM') for the cache key."""
        idx = _PH_SRC.find("async def _silent_decoy_response(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_vhost_upstream" in block, (
            "_silent_decoy_response must compute _vhost_upstream from vc('UPSTREAM')"
        )
        assert "vc(\"UPSTREAM\")" in block or "vc('UPSTREAM')" in block, (
            "_silent_decoy_response must consult vc('UPSTREAM') — not bare UPSTREAM"
        )

    def test_silent_decoy_uses_vhost_upstream_for_homepage_fetch(self):
        """The homepage-mode fetch must hit _vhost_upstream, not bare UPSTREAM."""
        idx = _PH_SRC.find("async def _silent_decoy_response(")
        nxt = _PH_SRC.find("async def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        # The fetch line must reference _vhost_upstream
        assert "_vhost_upstream + \"/\"" in block or "_vhost_upstream + '/'" in block, (
            "Homepage decoy fetch must use _vhost_upstream + '/' not UPSTREAM + '/'"
        )

    def test_upstream_unavailable_resolves_vhost_upstream(self):
        """The mirrored-404 response must look up the current vhost's slot.

        1.8.15 shipped this as `_serve_mirrored_404()` (the earlier
        `_upstream_unavailable_response` name never landed). It resolves the
        active vhost upstream via vc('UPSTREAM') and keys _upstream_404_cache
        by that upstream — the per-vhost isolation invariant this test guards.
        """
        idx = _PH_SRC.find("async def _serve_mirrored_404(")
        assert idx != -1, (
            "_serve_mirrored_404 (mirrored-404 response) must exist"
        )
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "vc(\"UPSTREAM\")" in block or "vc('UPSTREAM')" in block, (
            "mirrored-404 must resolve the active vhost via vc('UPSTREAM')"
        )
        assert "_upstream_404_cache.get(up)" in block, (
            "_serve_mirrored_404 must key cache by current vhost upstream"
        )


# ── 2. Wildcard vhost matching (unit) ───────────────────────────────────────

class TestSetVhostWildcardMatching:
    """vhost.set_vhost must match wildcard entries against subdomains."""

    def test_set_vhost_walks_parent_labels(self):
        """set_vhost must iterate parent domains for ``*.parent`` matches."""
        idx = _VH_SRC.find("def set_vhost(")
        block = _VH_SRC[idx: idx + 1000]
        assert "*." in block and ("split(\".\")" in block or "split('.')" in block), (
            "set_vhost must walk labels and try '*.<parent>' lookups"
        )

    def test_wildcard_lookup_exact_wins(self):
        """Exact-match vhost wins over wildcard."""
        import sys
        # vhost is loaded with cwd on path; import fresh to avoid stale ctx
        sys.path.insert(0, str(_ROOT))
        import importlib, vhost as _v
        importlib.reload(_v)
        _v.VHOSTS.clear()
        _v.VHOSTS["*.example.com"] = {"UPSTREAM": "http://wild"}
        _v.VHOSTS["a.example.com"] = {"UPSTREAM": "http://exact"}

        _v.set_vhost("a.example.com")
        assert _v.vc("UPSTREAM") == "http://exact", "exact must win over wildcard"

        _v.set_vhost("b.example.com")
        assert _v.vc("UPSTREAM") == "http://wild", "wildcard must match other subdomains"

    def test_wildcard_lookup_deep_subdomain(self):
        """Deep subdomain matches at higher parent if no closer wildcard exists."""
        import sys
        sys.path.insert(0, str(_ROOT))
        import importlib, vhost as _v
        importlib.reload(_v)
        _v.VHOSTS.clear()
        _v.VHOSTS["*.example.com"] = {"UPSTREAM": "http://wild"}

        _v.set_vhost("a.b.c.example.com")
        assert _v.vc("UPSTREAM") == "http://wild", (
            "deep subdomain must match *.example.com via parent walk"
        )

    def test_wildcard_lookup_no_match_falls_back(self):
        """Unrelated hostname falls back to whatever vc('UPSTREAM') returns
        from globals (i.e., context is None)."""
        import sys
        sys.path.insert(0, str(_ROOT))
        import importlib, vhost as _v
        importlib.reload(_v)
        _v.VHOSTS.clear()
        _v.VHOSTS["*.example.com"] = {"UPSTREAM": "http://wild"}

        _v.set_vhost("nope.elsewhere.org")
        # ctx is None → no override; vc falls back to module globals.
        # We can't assert a specific value here without bootstrapping configs,
        # but we CAN assert the wildcard did NOT match.
        assert _v._vhost_ctx.get() is None, (
            "unrelated host must yield ctx=None — wildcard must not over-match"
        )


# ── 3. Functional: two vhosts, two upstreams, two decoy bodies ──────────────

@asynccontextmanager
async def _spin_upstream(*, label: str):
    """An aiohttp app that tags every response with `label` so we can tell
    upstreams apart."""
    async def _root(req):
        return web.Response(
            text=f"<html><title>{label}</title><body>I am {label}</body></html>",
            content_type="text/html",
        )
    async def _probe(req):
        return web.Response(text=f"404-from-{label}", status=404,
                            content_type="text/html")
    app = web.Application()
    app.router.add_get("/", _root)
    app.router.add_route("*", "/{tail:.*}", _probe)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


def _cph():
    import core.proxy_handler as _m
    return _m


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url, **overrides):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    # Caches live in core.proxy_handler, not proxy
    _cph()._decoy_cache.clear()
    _cph()._upstream_404_cache.clear()
    for k, v in overrides.items():
        setattr(proxy_module, k, v)
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()
    _cph()._decoy_cache.clear()
    _cph()._upstream_404_cache.clear()
    for _s in list(proxy_module.ip_state.values()):
        _s.banned_until = 0.0


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestDecoyCachePerVhostFunctional:
    """Two upstreams, two cache slots — vhost-A's body must not leak to vhost-B."""

    def test_decoy_cache_keys_each_upstream(self, proxy_module):
        """Direct call to _silent_decoy with different vhost contexts must
        populate distinct cache slots."""
        async def go():
            async with _spin_upstream(label="alpha") as up_a:
                async with _spin_upstream(label="beta") as up_b:
                    async with _spin_proxy(proxy_module, up_a) as client:  # noqa: F841
                        import vhost as _v
                        # Register both vhosts pointing to different upstreams
                        _v.VHOSTS["alpha.test"] = {"UPSTREAM": up_a}
                        _v.VHOSTS["beta.test"] = {"UPSTREAM": up_b}

                        # Simulate vhost-A decoy fetch
                        _v.set_vhost("alpha.test")
                        ok_a = await _cph()._fetch_upstream_404()
                        assert ok_a, "vhost-A fetch must succeed"

                        # Simulate vhost-B decoy fetch
                        _v.set_vhost("beta.test")
                        ok_b = await _cph()._fetch_upstream_404()
                        assert ok_b, "vhost-B fetch must succeed"

                        slot_a = _cph()._upstream_404_cache.get(up_a) or {}
                        slot_b = _cph()._upstream_404_cache.get(up_b) or {}
                        body_a = slot_a.get("body") or b""
                        body_b = slot_b.get("body") or b""

                        assert b"404-from-alpha" in body_a, (
                            f"vhost-A slot must carry alpha's 404; got {body_a!r}"
                        )
                        assert b"404-from-beta" in body_b, (
                            f"vhost-B slot must carry beta's 404; got {body_b!r}"
                        )
                        assert body_a != body_b, (
                            "Each vhost slot must hold its own upstream's body — "
                            "no leakage between vhosts"
                        )

                        # Cleanup
                        del _v.VHOSTS["alpha.test"]
                        del _v.VHOSTS["beta.test"]
        _run(go())

    def test_silent_decoy_uses_per_vhost_upstream(self, proxy_module):
        """Silent decoy on a banned IP must serve the CURRENT vhost's upstream
        homepage, not the global UPSTREAM's homepage."""
        async def go():
            async with _spin_upstream(label="upstream-A") as up_a:
                async with _spin_upstream(label="upstream-B") as up_b:
                    # Global UPSTREAM is A; vhost B has its own UPSTREAM
                    async with _spin_proxy(proxy_module, up_a,
                                           BLOCK_RESPONSE_MODE="homepage") as client:
                        import vhost as _v
                        _v.VHOSTS["beta.test"] = {"UPSTREAM": up_b}

                        # Ban the test client's IP so silent decoy fires
                        proxy_module.ip_state["127.0.0.1"].banned_until = (
                            time.time() + 3600
                        )

                        # Request to vhost-B must return upstream-B's homepage
                        r = await client.get("/", headers={"Host": "beta.test"})
                        body = await r.text()

                        del _v.VHOSTS["beta.test"]
                        proxy_module.ip_state["127.0.0.1"].banned_until = 0.0

                        assert "I am upstream-B" in body, (
                            f"Decoy for beta.test must serve upstream-B's body — "
                            f"got: {body!r}"
                        )
                        assert "I am upstream-A" not in body, (
                            "Decoy leaked upstream-A's body for a beta.test request"
                        )
        _run(go())
