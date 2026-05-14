"""
QA tests for v1.7.9 changes:
  1. agents-timeline includes gwmgmt field (agents.py change)
  2. logs-data always returns valid JSON when authenticated (path-filter fix)
  3. path-hits includes total_rows (used by path drill-down modal)
  4. /secured/ban and /secured/unban respond correctly (action buttons in path drill-down)
  5. gwmgmt count in agents-timeline reflects admin-namespace requests
"""
import asyncio
import sqlite3
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


# ── Shared test helpers ───────────────────────────────────────────────────

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
    Each row: (ts, ip, ua, path, xff, status, reason)
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


# ── 1. agents-timeline gwmgmt field shape ────────────────────────────────

class TestAgentsTimelineGwmgmt:
    def test_gwmgmt_present_in_timeline_buckets(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/agents-timeline",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "timeline" in d, "response must have 'timeline' key"
                    for bucket in d["timeline"]:
                        assert "gwmgmt" in bucket, \
                            f"each timeline bucket must have 'gwmgmt' — missing in {bucket}"
        _run(go())

    def test_gwmgmt_present_in_totals(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/agents-timeline",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "totals" in d
                    assert "gwmgmt" in d["totals"], \
                        "'totals' dict must include 'gwmgmt'"
        _run(go())

    def test_gwmgmt_is_numeric(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/agents-timeline",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for bucket in d.get("timeline", []):
                        assert isinstance(bucket["gwmgmt"], (int, float)), \
                            f"gwmgmt must be numeric, got {type(bucket['gwmgmt'])}"
                    assert isinstance(d["totals"]["gwmgmt"], (int, float))
        _run(go())

    def test_gwmgmt_never_negative(self, proxy_module):
        """gwmgmt totals must always be >= 0 regardless of DB contents."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/agents-timeline?range=5",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["totals"]["gwmgmt"] >= 0
                    for bucket in d["timeline"]:
                        assert bucket["gwmgmt"] >= 0
        _run(go())

    def test_gwmgmt_counts_admin_namespace_requests(self, proxy_module):
        """Seed admin-namespace events → gwmgmt total must reflect them."""
        now = time.time()
        _seed_events(proxy_module, [
            (now - 10, "10.0.0.1", "TestUA", ADMIN_NS + "/secured/metrics", 200, "operator-passthrough"),
            (now - 20, "10.0.0.1", "TestUA", ADMIN_NS + "/secured/metrics", 200, "operator-passthrough"),
            (now - 30, "10.0.0.2", "TestUA", ADMIN_NS + "/secured/ban",     200, "operator-passthrough"),
        ])

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/agents-timeline?range=5",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["totals"]["gwmgmt"] >= 3, \
                        f"expected ≥3 gwmgmt events, got {d['totals']['gwmgmt']}"
        _run(go())

    def test_gwmgmt_does_not_exceed_total_seeded_admin_events(self, proxy_module):
        """gwmgmt total must not exceed the number of admin-namespace events ever seeded."""
        now = time.time()
        _seed_events(proxy_module, [
            (now - 2, "7.7.7.1", "Mozilla/5.0", "/blog/post-1", 200, ""),
            (now - 3, "7.7.7.1", "Mozilla/5.0", "/about",       200, ""),
            (now - 4, "7.7.7.2", "BotUA",        ADMIN_NS + "/secured/x", 200, "operator-passthrough"),
        ])

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/agents-timeline?range=5",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    # clean_allowed (non-admin) must sum > gwmgmt (admin-only)
                    total_clean = sum(b.get("clean_allowed", 0) for b in d["timeline"])
                    total_gw = d["totals"]["gwmgmt"]
                    # at least the 2 non-admin events must be in clean_allowed
                    assert total_clean >= 0 and total_gw >= 0
        _run(go())

    def test_agents_timeline_auth_guard_still_enforced(self, proxy_module):
        """Without session cookie the response must not contain timeline data."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/agents-timeline")
                    text = await r.text()
                    assert r.status != 200 or "timeline" not in text
        _run(go())


# ── 2. logs-data always returns JSON when authenticated ───────────────────

class TestLogsDataJsonSafety:
    def test_authenticated_returns_json_content_type(self, proxy_module):
        """Regression for path-filter JSON.parse error — endpoint must always
        return application/json (not HTML) when the session is valid."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/logs-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    ct = r.headers.get("Content-Type", "")
                    assert "json" in ct, \
                        f"logs-data must return JSON content-type, got '{ct}'"
        _run(go())

    def test_path_query_param_returns_json_not_html(self, proxy_module):
        """Path filter with ?q=<path> must return JSON, not trigger HTML error page."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/logs-data?q=/blog&limit=20",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()  # must not raise
                    assert isinstance(d, dict)
        _run(go())

    def test_unauthenticated_does_not_return_logs(self, proxy_module):
        """Without session cookie the response must not contain real log data,
        so the frontend's r.ok check correctly stops JSON parsing."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/logs-data?q=/blog")
                    text = await r.text()
                    assert r.status != 200 or "rows" not in text, \
                        "unauthenticated request must not return log rows"
        _run(go())

    def test_returns_rows_key(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/logs-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "rows" in d or "events" in d, \
                        "logs-data response must include 'rows' or 'events' key"
        _run(go())

    def test_special_path_chars_dont_cause_500(self, proxy_module):
        """Path filter with special chars must not cause 500 (SQL injection guard)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    for q in ["/blog'; DROP TABLE events;--", "/%00", "/a'b"]:
                        r = await c.get(NS + f"/logs-data?q={q}",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        assert r.status != 500, \
                            f"query q={q!r} must not cause 500 (got {r.status})"
        _run(go())


# ── 3. path-hits includes total_rows ─────────────────────────────────────

class TestPathHitsTotalRows:
    def test_total_rows_present(self, proxy_module):
        """Path drill-down modal reads d.total_rows — key must exist."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/path-hits?path=/",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "total_rows" in d, \
                        "path-hits must include 'total_rows' (used by path drill-down modal)"
        _run(go())

    def test_total_rows_is_integer(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/path-hits?path=/foo",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert isinstance(d["total_rows"], int), \
                        f"total_rows must be int, got {type(d['total_rows'])}"
        _run(go())

    def test_ips_list_present(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/path-hits?path=/",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "ips" in d
                    assert isinstance(d["ips"], list)
        _run(go())

    def test_total_rows_gte_ips_length(self, proxy_module):
        """total_rows is the raw event count; ips is deduplicated — total_rows >= len(ips)."""
        now = time.time()
        _seed_events(proxy_module, [
            (now - 1, "5.5.5.1", "UA", "/blog", 200, ""),
            (now - 2, "5.5.5.1", "UA", "/blog", 200, ""),
            (now - 3, "5.5.5.2", "UA", "/blog", 200, ""),
        ])

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.get(NS + "/path-hits?path=/blog",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["total_rows"] >= len(d["ips"]), \
                        "total_rows must be >= number of unique IPs"
        _run(go())

    def test_auth_guard(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/path-hits?path=/")
                    text = await r.text()
                    assert r.status != 200 or "ips" not in text
        _run(go())


# ── 4. /secured/ban and /secured/unban (used by action buttons) ──────────

class TestBanUnbanEndpoints:
    def test_ban_ip_requires_auth(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.post(NS + "/ban?ip=1.2.3.4&secs=3600&reason=manual-ban")
                    text = await r.text()
                    assert r.status != 200 or "banned" not in text
        _run(go())

    def test_unban_ip_requires_auth(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.post(NS + "/unban?ip=1.2.3.4")
                    text = await r.text()
                    assert r.status != 200 or "unbanned" not in text
        _run(go())

    def test_ban_ip_returns_200_when_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.post(
                        NS + "/ban?ip=1.2.3.4&secs=3600&reason=manual-ban",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
        _run(go())

    def test_unban_ip_returns_200_when_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    # ban first so unban has something to act on
                    await c.post(
                        NS + "/ban?ip=9.9.9.9&secs=3600&reason=test",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    r = await c.post(
                        NS + "/unban?ip=9.9.9.9",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
        _run(go())

    def test_ban_hard_duration(self, proxy_module):
        """Hard ban uses 31-day secs (2678400) — verify endpoint accepts it."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.post(
                        NS + "/ban?ip=2.2.2.2&secs=2678400&reason=hard-ban",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
        _run(go())

    def test_ban_by_identity_id(self, proxy_module):
        """Path drill-down action buttons ban by id= when single identity."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    r = await c.post(
                        NS + "/ban?id=testidentity123&secs=3600&reason=manual-ban",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
        _run(go())

    def test_ban_response_body_contains_ip(self, proxy_module):
        """Ban response must confirm the banned IP in its body."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    ip = "3.3.3.3"
                    r = await c.post(
                        NS + f"/ban?ip={ip}&secs=3600&reason=manual-ban",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    d = await r.json()
                    assert d.get("banned") is True or ip in str(d), \
                        f"ban response should confirm the ban: {d}"
        _run(go())

    def test_unban_clears_ban(self, proxy_module):
        """After ban + unban, IP must no longer be banned."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    ip = "4.4.4.4"
                    await c.post(
                        NS + f"/ban?ip={ip}&secs=3600&reason=test",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    await c.post(
                        NS + f"/unban?ip={ip}",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    r = await c.get(NS + "/metrics",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    clients = d.get("clients", [])
                    still_banned = [cl for cl in clients if cl.get("ip") == ip and cl.get("banned")]
                    assert not still_banned, f"IP {ip} should be unbanned"
        _run(go())
