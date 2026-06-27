"""
QA tests — BLOCK_RESPONSE_MODE knob (1.8.15).

Feature: operators can choose what blocked clients receive instead of the
default silent-decoy (upstream's / content).

  "homepage" (default) — upstream's / content, status mirrors upstream.
                         Blocked request is indistinguishable from a normal
                         page load.  Stealth mode.
  "404"               — upstream's real 404 page, status 404.
                         Explicit rejection signal; no deception.

API and admin-namespace paths always get a synthetic JSON 404 regardless of
the setting — serving an HTML homepage for those paths would be a cleaner
fingerprint for automated scanners than a 404 would.

Coverage:
  TestBlockResponseModeSourceGuards  — source/config/dashboard static checks
  TestBlockResponseModeFunctional    — live proxy: response body + status
"""
import asyncio
import json
import pathlib
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

# ── Source text ───────────────────────────────────────────────────────────────
_ROOT   = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_CFG_SRC = (_ROOT / "config.py").read_text(encoding="utf-8")
_VH_SRC  = (_ROOT / "vhost.py").read_text(encoding="utf-8")
_CTL_SRC = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")
_VHP_SRC = (_ROOT / "dashboards" / "vhost_policy.html").read_text(encoding="utf-8")


# ── Shared helpers ────────────────────────────────────────────────────────────

@asynccontextmanager
async def _spin_upstream(homepage_text="upstream-homepage",
                         status_404=404, body_404=b"upstream-not-found"):
    """Upstream that serves homepage_text on / and body_404 on everything else."""
    async def _handle(req):
        if req.path == "/":
            return web.Response(text=homepage_text, status=200)
        return web.Response(body=body_404,
                            content_type="text/html",
                            status=status_404)
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


def _cph():
    """Return core.proxy_handler module (has _decoy_cache, _upstream_404_cache)."""
    import core.proxy_handler as _m
    return _m


def _reset_caches():
    """1.8.15 — caches are now dict-of-dicts keyed by upstream URL.
    Clear all per-upstream entries to start each test cold."""
    m = _cph()
    m._decoy_cache.clear()
    m._upstream_404_cache.clear()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url, **overrides):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    _reset_caches()
    for k, v in overrides.items():
        setattr(proxy_module, k, v)  # propagates to core.proxy_handler via __setattr__
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()
    # Post-test cleanup: clear decoy caches and unban all ip_state entries so
    # subsequent tests (e.g. admin-bypass functional tests) don't see stale bans
    # or stale decoy bodies from our upstream stub.
    _reset_caches()
    for _s in list(proxy_module.ip_state.values()):
        _s.banned_until = 0.0


def _pre_ban(proxy_module, key="127.0.0.1"):
    """Force ip_state[key].banned_until to far future."""
    proxy_module.ip_state[key].banned_until = time.time() + 3600


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── 1. TestBlockResponseModeSourceGuards ─────────────────────────────────────

class TestBlockResponseModeSourceGuards:
    """Static checks: knob defined everywhere it needs to be."""

    def test_defined_in_config(self):
        """BLOCK_RESPONSE_MODE must be defined in config.py."""
        assert "BLOCK_RESPONSE_MODE" in _CFG_SRC, (
            "BLOCK_RESPONSE_MODE not found in config.py"
        )

    def test_default_is_homepage(self):
        """Default value must be 'homepage' (stealth / backward-compatible)."""
        idx = _CFG_SRC.find("BLOCK_RESPONSE_MODE")
        block = _CFG_SRC[idx: idx + 200]
        assert '"homepage"' in block or "'homepage'" in block, (
            "BLOCK_RESPONSE_MODE default must be 'homepage'"
        )

    def test_in_vhost_coerce(self):
        """BLOCK_RESPONSE_MODE must be in _VHOST_COERCE so it is per-vhost overridable."""
        assert "BLOCK_RESPONSE_MODE" in _VH_SRC, (
            "BLOCK_RESPONSE_MODE missing from _VHOST_COERCE in vhost.py"
        )

    def test_in_hot_reload_knobs(self):
        """BLOCK_RESPONSE_MODE must be in _HOT_RELOAD_KNOBS for live config changes."""
        assert "BLOCK_RESPONSE_MODE" in _PH_SRC, (
            "BLOCK_RESPONSE_MODE not found in proxy_handler.py"
        )
        idx = _PH_SRC.find('"BLOCK_RESPONSE_MODE"')
        block = _PH_SRC[idx: idx + 100]
        # validator must allow both valid modes
        assert "homepage" in block and "404" in block, (
            '_HOT_RELOAD_KNOBS validator must accept both "homepage" and "404"'
        )

    def test_404_mode_uses_upstream_404_cache(self):
        """In 404-mode the decoy must pull from _upstream_404_cache, not _decoy_cache."""
        idx = _PH_SRC.find('BLOCK_RESPONSE_MODE == "404"')
        assert idx != -1, '"BLOCK_RESPONSE_MODE == "404"" branch not found'
        block = _PH_SRC[idx: idx + 600]
        assert "_upstream_404_cache" in block, (
            '404-mode branch must read from _upstream_404_cache'
        )
        assert "_fetch_upstream_404" in block, (
            '404-mode branch must call _fetch_upstream_404() on cache miss'
        )

    def test_homepage_mode_uses_decoy_cache(self):
        """homepage-mode must read from _decoy_cache (upstream /)."""
        idx = _PH_SRC.find("BLOCK_RESPONSE_MODE")
        # find the else branch after the elif
        elif_idx = _PH_SRC.find('elif BLOCK_RESPONSE_MODE == "404":', idx)
        else_idx  = _PH_SRC.find("else:", elif_idx)
        block = _PH_SRC[else_idx: else_idx + 400]
        assert "_decoy_cache" in block, (
            "homepage-mode (else branch) must read from _decoy_cache"
        )

    def test_api_admin_paths_always_json_404(self):
        """API/admin detection must come BEFORE the mode branch (takes priority)."""
        looks_api_idx   = _PH_SRC.find("_looks_like_api")
        mode_branch_idx = _PH_SRC.find('elif BLOCK_RESPONSE_MODE == "404":')
        assert looks_api_idx < mode_branch_idx, (
            "_looks_like_api detection must precede BLOCK_RESPONSE_MODE branch"
        )
        # JSON body must appear inside the api/admin block, not the mode blocks
        if_block = _PH_SRC[looks_api_idx: mode_branch_idx]
        assert '"error":"not found"' in if_block or 'error.*not found' in if_block or \
               b'{"error"' in if_block.encode() or '{"error"' in if_block, (
            'synthetic JSON 404 must be in the api/admin block before mode branch'
        )

    def test_controls_html_has_select_knob(self):
        """controls.html must have BLOCK_RESPONSE_MODE as a select knob."""
        assert "BLOCK_RESPONSE_MODE" in _CTL_SRC, (
            "BLOCK_RESPONSE_MODE missing from controls.html"
        )
        idx = _CTL_SRC.find("BLOCK_RESPONSE_MODE")
        block = _CTL_SRC[idx: idx + 200]
        assert "kind:'select'" in block or 'kind: "select"' in block, (
            "BLOCK_RESPONSE_MODE must be kind:'select' in controls.html"
        )
        assert "'homepage'" in block or '"homepage"' in block, (
            "'homepage' option missing from controls.html BLOCK_RESPONSE_MODE"
        )
        assert "'404'" in block or '"404"' in block, (
            "'404' option missing from controls.html BLOCK_RESPONSE_MODE"
        )

    def test_vhost_policy_html_has_knob_meta(self):
        """vhost_policy.html KNOB_META must include BLOCK_RESPONSE_MODE."""
        assert "BLOCK_RESPONSE_MODE" in _VHP_SRC, (
            "BLOCK_RESPONSE_MODE missing from vhost_policy.html KNOB_META"
        )

    def test_mode_branch_is_elif_not_separate_if(self):
        """404-mode must be an elif (not a bare if) so it can't fire for API/admin paths."""
        idx = _PH_SRC.find("_looks_like_api or _looks_like_admin:")
        assert idx != -1, "_looks_like_api check not found"
        block = _PH_SRC[idx: idx + 200]
        assert "elif BLOCK_RESPONSE_MODE" in block, (
            "404-mode branch must be elif, not if — else API/admin JSON 404 is skipped"
        )


# ── 2. TestBlockResponseModeFunctional ───────────────────────────────────────

class TestBlockResponseModeFunctional:
    """Live proxy: verify blocked responses match the configured mode."""

    def test_homepage_mode_serves_upstream_root(self, proxy_module):
        """homepage mode (default) → blocked client receives upstream / content."""
        async def go():
            async with _spin_upstream(homepage_text="my-homepage-body") as up:
                async with _spin_proxy(proxy_module, up,
                                       BLOCK_RESPONSE_MODE="homepage") as client:
                    _pre_ban(proxy_module)
                    r = await client.get("/some-page")
                    text = await r.text()
                assert "my-homepage-body" in text, (
                    f"homepage mode must serve upstream / content; got {text!r}"
                )
                assert r.status == 200, (
                    f"homepage mode must mirror upstream / status (200); got {r.status}"
                )
        _run(go())

    def test_404_mode_serves_upstream_404(self, proxy_module):
        """404 mode → blocked client receives upstream's 404 page, status 404."""
        async def go():
            async with _spin_upstream(body_404=b"upstream-404-body",
                                      status_404=404) as up:
                async with _spin_proxy(proxy_module, up,
                                       BLOCK_RESPONSE_MODE="404") as client:
                    _pre_ban(proxy_module)
                    r = await client.get("/some-page")
                    body = await r.read()
                assert b"upstream-404-body" in body, (
                    f"404 mode must serve upstream 404 body; got {body!r}"
                )
                assert r.status == 404, (
                    f"404 mode must return status 404; got {r.status}"
                )
        _run(go())

    def test_api_path_always_json_404_in_homepage_mode(self, proxy_module):
        """API path + homepage mode → synthetic JSON 404 (not homepage content)."""
        async def go():
            async with _spin_upstream(homepage_text="my-homepage") as up:
                async with _spin_proxy(proxy_module, up,
                                       BLOCK_RESPONSE_MODE="homepage") as client:
                    _pre_ban(proxy_module)
                    r = await client.get("/api/users")
                    body = await r.read()
                assert b"my-homepage" not in body, (
                    "API path must not serve homepage even in homepage mode"
                )
                assert r.status == 404, (
                    f"API path must get status 404; got {r.status}"
                )
                assert b"error" in body.lower(), (
                    f"API path must get JSON error body; got {body!r}"
                )
        _run(go())

    def test_api_path_always_json_404_in_404_mode(self, proxy_module):
        """API path + 404 mode → synthetic JSON 404 (not upstream 404 HTML page)."""
        async def go():
            async with _spin_upstream(body_404=b"html-not-found") as up:
                async with _spin_proxy(proxy_module, up,
                                       BLOCK_RESPONSE_MODE="404") as client:
                    _pre_ban(proxy_module)
                    r = await client.get("/api/data.json")
                    body = await r.read()
                    ct   = r.headers.get("Content-Type", "")
                assert b"html-not-found" not in body, (
                    "API path in 404 mode must not serve upstream HTML 404"
                )
                assert "application/json" in ct, (
                    f"API path must return application/json; got {ct!r}"
                )
        _run(go())

    def test_admin_path_json_404_regardless_of_mode(self, proxy_module):
        """Admin-namespace path → JSON 404 in both homepage and 404 modes."""
        async def go():
            async with _spin_upstream(homepage_text="homepage") as up:
                for mode in ("homepage", "404"):
                    async with _spin_proxy(proxy_module, up,
                                           BLOCK_RESPONSE_MODE=mode) as client:
                        _pre_ban(proxy_module)
                        r = await client.get("/admin/panel")
                        ct = r.headers.get("Content-Type", "")
                        assert "application/json" in ct, (
                            f"Admin path in {mode!r} mode must return JSON; got {ct!r}"
                        )
                        assert r.status == 404, (
                            f"Admin path in {mode!r} mode must be 404; got {r.status}"
                        )
        _run(go())

    def test_404_mode_does_not_fetch_homepage(self, proxy_module):
        """In 404 mode, _decoy_cache (homepage) must not be populated by blocked requests."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up,
                                       BLOCK_RESPONSE_MODE="404") as client:
                    # ensure clean state — 1.8.15 dict-of-dicts
                    _cph()._decoy_cache.clear()
                    _pre_ban(proxy_module)
                    await client.get("/page")
                    # No per-upstream slot must carry a populated body
                    populated = [
                        up_url for up_url, slot in _cph()._decoy_cache.items()
                        if slot.get("body")
                    ]
                assert not populated, (
                    f"404 mode must not populate _decoy_cache on blocked requests; "
                    f"populated upstreams: {populated}"
                )
        _run(go())

    def test_mode_switch_takes_effect_immediately(self, proxy_module):
        """Switching from homepage to 404 mode changes response without restart."""
        async def go():
            async with _spin_upstream(homepage_text="homepage-content",
                                      body_404=b"404-content") as up:
                async with _spin_proxy(proxy_module, up,
                                       BLOCK_RESPONSE_MODE="homepage") as client:
                    _pre_ban(proxy_module)

                    # First: homepage mode
                    r1 = await client.get("/page")
                    text1 = await r1.text()
                    assert "homepage-content" in text1, (
                        f"homepage mode must serve homepage; got {text1!r}"
                    )

                    # Switch to 404 mode inline (simulates hot-reload)
                    # 1.8.15 — clear per-upstream cache to force fresh fetch
                    proxy_module.BLOCK_RESPONSE_MODE = "404"
                    _cph()._upstream_404_cache.clear()

                    r2 = await client.get("/page2")
                    body2 = await r2.read()
                    proxy_module.BLOCK_RESPONSE_MODE = "homepage"  # restore
                    assert b"404-content" in body2, (
                        f"after switch to 404 mode must serve 404 body; got {body2!r}"
                    )
        _run(go())
