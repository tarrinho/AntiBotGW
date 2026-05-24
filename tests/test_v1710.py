"""
QA tests for v1.7.10 changes:
  1. agents-bucket detail endpoint returns 'gwmgmt' key
  2. gwmgmt key reflects admin-namespace (/antibot-appsec-gateway/) events
  3. gwmgmt key is empty when no admin-namespace events exist in the bucket
  4. Non-admin-namespace events do not appear in gwmgmt key
  5. _serve_mirrored_404 does not crash when _upstream_404_cache is empty (KeyError fix)
  6. UPSTREAM hot-reload flushes 404 cache; subsequent admin-blocked requests served without 500
  7. BYPASS_PATHS config knob adds/removes paths via POST /secured/config
  8. JS_CHAL_OPEN_PATHS config knob adds/removes paths via POST /secured/config
"""
import asyncio
import sqlite3
import time

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient
from contextlib import asynccontextmanager


# ── Shared helpers (mirrors test_v179.py) ────────────────────────────────────

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


def _make_admin_session(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


NS = "/antibot-appsec-gateway/secured"
ADMIN_NS = "/antibot-appsec-gateway"


def _seed_events(proxy_module, rows):
    """Insert raw event rows into the test SQLite DB.
    Each row: (ts, ip, ua, path, status, reason)
    """
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS events "
        "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, ua TEXT, "
        "path TEXT, xff TEXT DEFAULT '', status INTEGER DEFAULT 200, reason TEXT DEFAULT '')"
    )
    conn.executemany(
        "INSERT INTO events (ts, ip, ua, path, status, reason) VALUES (?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()


# ── 1. agents-bucket returns gwmgmt key ──────────────────────────────────────

class TestAgentsBucketGwmgmt:
    def test_agents_bucket_detail_returns_gwmgmt_key(self, proxy_module):
        """agents-bucket response must include a 'gwmgmt' key (list) alongside
        detected / missed / clean / authorized_robot."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    t = int(time.time()) - 120
                    r = await c.get(
                        NS + f"/agents-bucket?t={t}&bucket_secs=300&all_blocks=1",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    d = await r.json()
                    assert "gwmgmt" in d, (
                        "agents-bucket response must include 'gwmgmt' key — "
                        "needed for bucket-detail modal GW Mgmt section"
                    )
                    assert isinstance(d["gwmgmt"], list), (
                        "agents-bucket 'gwmgmt' value must be a list"
                    )
        _run(go())

    def test_agents_bucket_gwmgmt_empty_when_no_admin_events(self, proxy_module):
        """When no admin-namespace events exist in the bucket window,
        gwmgmt must be an empty list, not absent or None."""
        now = time.time()
        _seed_events(proxy_module, [
            (now - 10, "1.2.3.4", "Mozilla/5.0", "/blog/post", 200, ""),
            (now - 20, "1.2.3.5", "Mozilla/5.0", "/about",     200, ""),
        ])

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    t = int(now) - 60
                    r = await c.get(
                        NS + f"/agents-bucket?t={t}&bucket_secs=120&all_blocks=1",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert "gwmgmt" in d, "gwmgmt key must always be present"
                    assert d["gwmgmt"] == [], (
                        "gwmgmt must be [] when no admin-namespace events in window"
                    )
        _run(go())

    def test_agents_bucket_gwmgmt_reflects_admin_namespace_events(self, proxy_module):
        """Seeded /antibot-appsec-gateway/ events must appear in gwmgmt list
        with correct ip and count fields."""
        now = time.time()
        _seed_events(proxy_module, [
            (now - 5,  "9.9.9.1", "AdminUA", ADMIN_NS + "/secured/metrics", 200, "operator-passthrough"),
            (now - 10, "9.9.9.1", "AdminUA", ADMIN_NS + "/secured/metrics", 200, "operator-passthrough"),
            (now - 15, "9.9.9.2", "AdminUA", ADMIN_NS + "/secured/ban",     200, "operator-passthrough"),
        ])

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    t = int(now) - 60
                    r = await c.get(
                        NS + f"/agents-bucket?t={t}&bucket_secs=120&all_blocks=1",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    gw = d.get("gwmgmt", [])
                    ips = {e["ip"] for e in gw}
                    assert "9.9.9.1" in ips, (
                        "gwmgmt must include 9.9.9.1 (seeded admin-namespace requests)"
                    )
                    assert "9.9.9.2" in ips, (
                        "gwmgmt must include 9.9.9.2 (seeded admin-namespace requests)"
                    )
                    hit_9991 = next(e for e in gw if e["ip"] == "9.9.9.1")
                    assert hit_9991["count"] >= 2, (
                        "9.9.9.1 made 2 admin-namespace requests; count must be ≥ 2"
                    )
        _run(go())

    def test_agents_bucket_gwmgmt_excludes_non_admin_paths(self, proxy_module):
        """Events on non-admin paths must NOT appear in gwmgmt — only paths
        starting with /antibot-appsec-gateway/ belong there."""
        now = time.time()
        _seed_events(proxy_module, [
            (now - 5,  "8.8.8.1", "Mozilla/5.0", "/app/dashboard",          200, ""),
            (now - 10, "8.8.8.2", "Mozilla/5.0", "/api/users",               200, ""),
            (now - 15, "8.8.8.3", "BotUA",        "/antibot-appsec-gateway-fake/x", 200, ""),
        ])

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    t = int(now) - 60
                    r = await c.get(
                        NS + f"/agents-bucket?t={t}&bucket_secs=120&all_blocks=1",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    gw_ips = {e["ip"] for e in d.get("gwmgmt", [])}
                    assert "8.8.8.1" not in gw_ips, (
                        "non-admin path /app/dashboard must not appear in gwmgmt"
                    )
                    assert "8.8.8.2" not in gw_ips, (
                        "non-admin path /api/users must not appear in gwmgmt"
                    )
                    assert "8.8.8.3" not in gw_ips, (
                        "path /antibot-appsec-gateway-fake/x must not match the "
                        "/antibot-appsec-gateway/ LIKE prefix (strict prefix required)"
                    )
        _run(go())

    def test_agents_bucket_gwmgmt_each_entry_has_required_fields(self, proxy_module):
        """Each gwmgmt entry must contain ip, count, ua, last_path, is_admin_ip
        — the same shape expected by renderGwMgmt in main.html."""
        now = time.time()
        _seed_events(proxy_module, [
            (now - 5, "5.5.5.1", "TestUA/1.0", ADMIN_NS + "/secured/metrics", 200, "operator-passthrough"),
        ])

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    t = int(now) - 60
                    r = await c.get(
                        NS + f"/agents-bucket?t={t}&bucket_secs=120&all_blocks=1",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    gw = d.get("gwmgmt", [])
                    entry = next((e for e in gw if e["ip"] == "5.5.5.1"), None)
                    assert entry is not None, (
                        "5.5.5.1 seeded admin-namespace event not found in gwmgmt"
                    )
                    for field in ("ip", "count", "ua", "last_path", "is_admin_ip"):
                        assert field in entry, (
                            f"gwmgmt entry missing required field '{field}' "
                            f"(needed by renderGwMgmt in main.html)"
                        )
        _run(go())


# ── 5-6. _serve_mirrored_404 empty-cache crash fix (KeyError: 'body') ────────

class TestServeMirrored404EmptyCache:
    """After an UPSTREAM change clears _upstream_404_cache, any request that
    reaches _serve_mirrored_404 must NOT raise KeyError: 'body' (500).
    The fix uses .get() with safe defaults so an empty cache triggers a fresh
    fetch rather than crashing."""

    def test_admin_blocked_request_no_500_when_cache_empty(self, proxy_module):
        """A non-admin-IP request to a secured path returns a non-500 response
        even when _upstream_404_cache has been cleared (simulating post-UPSTREAM-change state)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    # Clear the 404 cache to simulate post-UPSTREAM-change state
                    proxy_module._upstream_404_cache.clear()
                    # Request from a non-admin IP to a secured path triggers _serve_mirrored_404
                    r = await c.get(NS + "/metrics")
                    assert r.status != 500, (
                        "_serve_mirrored_404 must not raise KeyError: 'body' "
                        "when _upstream_404_cache is empty — use .get() not direct access"
                    )
        _run(go())

    def test_admin_blocked_returns_sensible_body_when_cache_empty(self, proxy_module):
        """When _upstream_404_cache is empty and the upstream fetch succeeds,
        the response body must be non-empty (upstream content or fallback)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    proxy_module._upstream_404_cache.clear()
                    r = await c.get(NS + "/metrics")
                    body = await r.read()
                    assert len(body) > 0, (
                        "response body must be non-empty even when 404 cache starts empty"
                    )
        _run(go())

    def test_upstream_change_then_admin_blocked_no_crash(self, proxy_module):
        """Simulates the exact crash scenario: change UPSTREAM (clears cache),
        then make a request that hits _serve_mirrored_404. Must not 500."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    # Simulate UPSTREAM change: change the value and clear cache
                    old_upstream = proxy_module.UPSTREAM
                    proxy_module.UPSTREAM = up  # same URL, different reference
                    proxy_module._upstream_404_cache.clear()
                    try:
                        # Non-admin-IP request to secured path hits _serve_mirrored_404
                        r = await c.get(NS + "/metrics")
                        assert r.status != 500, (
                            "500 means KeyError: 'body' crash — cache must be handled with .get()"
                        )
                    finally:
                        proxy_module.UPSTREAM = old_upstream
        _run(go())

    def test_serve_mirrored_404_repopulates_cache_after_clear(self, proxy_module):
        """After _upstream_404_cache is cleared and _serve_mirrored_404 runs,
        the cache must be repopulated (fetched_at and body keys present)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    proxy_module._upstream_404_cache.clear()
                    await c.get(NS + "/metrics")
                    # After the request, cache should be repopulated
                    assert "body" in proxy_module._upstream_404_cache, (
                        "_upstream_404_cache must have 'body' after _serve_mirrored_404 refetch"
                    )
                    assert "fetched_at" in proxy_module._upstream_404_cache, (
                        "_upstream_404_cache must have 'fetched_at' after refetch"
                    )
        _run(go())


# ── 7-8. BYPASS_PATHS / JS_CHAL_OPEN_PATHS config toggle ────────────────────

class TestPathCategoryConfigToggle:
    """Tests for BYPASS_PATHS and JS_CHAL_OPEN_PATHS hot-reload knobs that
    power the path category controls in the top-paths drill-down modal."""

    def test_bypass_paths_add_via_config_post(self, proxy_module):
        """POST /secured/config with BYPASS_PATHS list adds a path; subsequent
        requests to that path are allowed through without bot detection."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    import json
                    r = await c.post(
                        NS + "/config",
                        data=json.dumps({"BYPASS_PATHS": ["/test-bypass/"]}),
                        headers={"Content-Type": "application/json"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    d = await r.json()
                    assert "applied" in d, "config POST must return 'applied' dict"
                    assert "BYPASS_PATHS" in d["applied"], (
                        "BYPASS_PATHS must appear in 'applied' when successfully set"
                    )
                    assert "/test-bypass/" in d["applied"]["BYPASS_PATHS"], (
                        "applied BYPASS_PATHS must contain the path we added"
                    )
        _run(go())

    def test_bypass_paths_remove_via_config_post(self, proxy_module):
        """POST with an empty BYPASS_PATHS list clears all bypass paths."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    import json
                    # First add
                    await c.post(
                        NS + "/config",
                        data=json.dumps({"BYPASS_PATHS": ["/to-remove/"]}),
                        headers={"Content-Type": "application/json"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    # Then clear
                    r = await c.post(
                        NS + "/config",
                        data=json.dumps({"BYPASS_PATHS": []}),
                        headers={"Content-Type": "application/json"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    d = await r.json()
                    paths = d.get("applied", {}).get("BYPASS_PATHS", ["sentinel"])
                    assert "/to-remove/" not in paths, (
                        "cleared BYPASS_PATHS must not still contain the removed path"
                    )
        _run(go())

    def test_js_chal_open_paths_add_via_config_post(self, proxy_module):
        """POST /secured/config with JS_CHAL_OPEN_PATHS adds a path and
        the 'applied' response reflects it."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    import json
                    r = await c.post(
                        NS + "/config",
                        data=json.dumps({"JS_CHAL_OPEN_PATHS": ["/public-api/"]}),
                        headers={"Content-Type": "application/json"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    d = await r.json()
                    assert "JS_CHAL_OPEN_PATHS" in d.get("applied", {}), (
                        "JS_CHAL_OPEN_PATHS must appear in 'applied'"
                    )
                    assert "/public-api/" in d["applied"]["JS_CHAL_OPEN_PATHS"], (
                        "applied JS_CHAL_OPEN_PATHS must contain the path we added"
                    )
        _run(go())

    def test_path_config_toggle_auth_guard(self, proxy_module):
        """POST /secured/config without a session cookie must not succeed
        (must not be accessible without authentication)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import json
                    r = await c.post(
                        NS + "/config",
                        data=json.dumps({"BYPASS_PATHS": ["/evil/"]}),
                        headers={"Content-Type": "application/json"},
                    )
                    text = await r.text()
                    assert r.status != 200 or "key" not in text, (
                        "unauthenticated POST to /secured/config must not succeed"
                    )
        _run(go())

    def test_config_state_reflects_bypass_paths(self, proxy_module):
        """GET /secured/config 'state' dict must reflect the current BYPASS_PATHS
        value after it has been updated — this is what the JS UI reads on modal open."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    import json
                    await c.post(
                        NS + "/config",
                        data=json.dumps({"BYPASS_PATHS": ["/reflected/"]}),
                        headers={"Content-Type": "application/json"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    r = await c.get(
                        NS + "/config",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    d = await r.json()
                    state = d.get("state", {})
                    assert "BYPASS_PATHS" in state, (
                        "GET /config 'state' must include BYPASS_PATHS key"
                    )
                    assert "/reflected/" in state["BYPASS_PATHS"], (
                        "GET /config 'state.BYPASS_PATHS' must reflect the value set via POST"
                    )
        _run(go())
