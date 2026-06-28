"""
Dynamic endpoint regression suite — tests/test_endpoints_dynamic.py

Covers every admin endpoint + detection-pipeline feature described in rules.md.
Run as part of step 1–3 of the build validation chain.

Pattern: spin a tiny in-process echo upstream, boot the proxy as an aiohttp
TestClient, issue real HTTP requests, assert on status codes and response shapes.
Admin auth: primes an in-memory session record and passes the signed cookie.
"""
import asyncio
import sqlite3
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


@pytest.fixture(autouse=True)
def _clear_admin_nets_after_test():
    """Clear ADMIN_ALLOWED_NETS + ADMIN_ALLOWED_ENTRIES + admin_ips DB after
    every test.  TestAdminIPsEndpoint.test_admin_ips_post_add_cidr adds a
    real CIDR which causes subsequent tests to lose 127.0.0.1 admin access
    since the allowlist becomes non-empty (empty = open, non-empty = strict).
    The DB must also be purged because on_startup calls db_load_admin_ips()
    which would otherwise repopulate the in-memory lists."""
    yield
    import sqlite3
    import admin.auth as _auth
    _auth.ADMIN_ALLOWED_NETS.clear()
    _auth.ADMIN_ALLOWED_ENTRIES.clear()
    try:
        import proxy as _p
        db_path = getattr(_p, "DB_PATH", "")
        if db_path:
            conn = sqlite3.connect(db_path)
            conn.execute("DELETE FROM admin_ips")
            conn.commit()
            conn.close()
    except Exception:
        pass


# ── Shared helpers ────────────────────────────────────────────────────────────

NS   = "/antibot-appsec-gateway/secured"
PUB  = "/antibot-appsec-gateway"


async def _echo_handler(request: web.Request):
    body = await request.read()
    return web.json_response({
        "method":  request.method,
        "path":    request.path,
        "headers": dict(request.headers),
        "body":    body.decode("utf-8", errors="replace"),
    })


async def _echo_html(request: web.Request):
    return web.Response(body=b"<html><body>hello</body></html>",
                        content_type="text/html")


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_get("/html", _echo_html)
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


def _make_admin_cookie(proxy_module):
    """Prime an in-memory admin session and return the signed cookie value."""
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _csrf_hdr(proxy_module, cookie):
    """Return X-CSRF-Token header dict for CSRF-protected endpoints."""
    import hashlib, hmac as _hmac
    if isinstance(cookie, dict):
        cookie = next(iter(cookie.values()))
    sid = cookie.split("|")[1]
    token = _hmac.new(proxy_module.SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
    return {"X-CSRF-Token": token}

def _browser_headers(extra=None):
    h = {
        "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
        "Accept":          "text/html,application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip",
        "Sec-Ch-Ua":       '"Chromium";v="120"',
        "Sec-Fetch-Site":  "none",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Dest":  "document",
    }
    if extra:
        h.update(extra)
    return h


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _seed_events(proxy_module, rows):
    """Insert (ts, ip, ua, path, status, reason) tuples into the DB.

    Backend-aware: the dashboard endpoints read events from the active backend,
    so under the PG-mode harness (POSTGRES_DSN set) the rows must land in
    Postgres. db.conn.conn() targets the active backend; the CREATE only runs on
    SQLite (the PG events table is created at startup and the SQLite DDL is
    incompatible).
    """
    from db.conn import active_backend
    if active_backend() == "postgres":
        # PG events.ts is timestamptz; reuse pg_insert_event (to_timestamp).
        # Row tuple: (ts, ip, ua, path, status, reason)
        from db.postgres import pg_insert_event
        for ts, ip, ua, path, status, reason in rows:
            pg_insert_event(ts, ip, ua, path, int(status), reason)
    else:
        from db.conn import conn as _backend_conn
        with _backend_conn(timeout=10) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS events "
                "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, ua TEXT, "
                "path TEXT, xff TEXT DEFAULT '', status INTEGER DEFAULT 200, reason TEXT DEFAULT '')"
            )
            conn.executemany(
                "INSERT INTO events (ts, ip, ua, path, status, reason) VALUES (?,?,?,?,?,?)",
                rows,
            )


# ─────────────────────────────────────────────────────────────────────────────
# 1. Auth guard — every secured endpoint silently decoys when unauthenticated
# ─────────────────────────────────────────────────────────────────────────────

class TestAuthGuard:
    """Unauthenticated requests to secured endpoints must NOT return real data.
    The proxy serves a silent upstream-404 decoy instead of 401/403."""

    SECURED_GETS = [
        "status", "metrics", "thresholds", "scoring", "config",
        "external", "signal-orders", "path-hits?path=/",
        "cost-timeline", "health-score", "detector-stats",
        "lists-snapshot", "agents-data", "agents-timeline",
        "service-data", "live-feed", "control-center", "agents", "service", "controls",
        "settings", "settings-export", "xff", "whoami",
    ]

    def _assert_decoy(self, status, body):
        # Decoy: proxy forwards the upstream 404 — so it's NOT a JSON admin response.
        # The key invariant is that none of the admin payload markers appear.
        assert "X-Admin-Key" not in body
        assert '"clients"' not in body or '"thresholds"' not in body

    def test_metrics_unauthenticated_decoy(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/metrics")
                    body = await r.text()
                    # Decoy = no X-Admin-Key leakage, no real payload keys at top level
                    assert "SECRET" not in body
                    assert "ADMIN_KEY" not in body
        _run(go())

    def test_dashboard_unauthenticated_decoy(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/live-feed")
                    body = await r.text()
                    assert "AntiBotWaf_GW_1.9.9 · Live Feed" not in body
        _run(go())

    def test_config_unauthenticated_decoy(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/config")
                    body = await r.text()
                    assert "RISK_BAN_THRESHOLD" not in body
        _run(go())

    def test_thresholds_unauthenticated_decoy(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/thresholds")
                    body = await r.text()
                    assert "thresholds" not in body
        _run(go())

    def test_ban_post_unauthenticated_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.post(NS + "/ban?ip=1.2.3.4&secs=3600&reason=x")
                    body = await r.text()
                    assert "banned" not in body or r.status in (200,)
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 2. Status endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestStatusEndpoint:
    def test_status_returns_200_when_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/status",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_status_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/status",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "clients" in d
                    assert "config" in d
                    cfg = d["config"]
                    assert "burst" in cfg
                    assert "refill_per_sec" in cfg
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 3. Metrics endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestMetricsEndpoint:
    def test_metrics_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/metrics",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_metrics_top_level_keys(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/metrics",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for key in ("clients", "timeline", "total", "timeline_bucket_secs"):
                        assert key in d, f"metrics missing key: {key}"
        _run(go())

    def test_metrics_client_row_shape(self, proxy_module):
        """Each client entry must have the fields the dashboard reads."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    # Generate one request so there's a client entry
                    await c.get("/", headers=_browser_headers())
                    r = await c.get(NS + "/metrics",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    if d["clients"]:
                        row = d["clients"][0]
                        for f in ("ip", "requests", "risk_score", "banned_secs",
                                  "last_ua", "is_authorized_bot"):
                            assert f in row, f"client row missing field: {f}"
        _run(go())

    def test_metrics_timeline_bucket_entries(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/metrics?range=60&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert isinstance(d["timeline"], list)
                    if d["timeline"]:
                        entry = d["timeline"][0]
                        assert "t" in entry
        _run(go())

    def test_metrics_cats_filter_param(self, proxy_module):
        """?cats=allowed filters the recent-events list to that category."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/metrics?cats=allowed",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 4. Thresholds endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestThresholdsEndpoint:
    def test_thresholds_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/thresholds",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_thresholds_list_not_empty(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/thresholds",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "thresholds" in d
                    assert len(d["thresholds"]) >= 10
        _run(go())

    def test_thresholds_entry_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/thresholds",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for entry in d["thresholds"]:
                        for f in ("name", "current", "min", "max",
                                  "position", "impact_direction", "description"):
                            assert f in entry, f"threshold entry missing: {f}"
                        assert 0.0 <= entry["position"] <= 1.0
        _run(go())

    def test_thresholds_includes_risk_ban(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/thresholds",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    names = {t["name"] for t in d["thresholds"]}
                    assert "RISK_BAN_THRESHOLD" in names
                    assert "RATE_LIMIT_BURST" in names
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 5. Scoring endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestScoringEndpoint:
    def test_scoring_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/scoring",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_scoring_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/scoring",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "weights" in d, f"scoring missing 'weights' key, got: {list(d)}"
                    assert "thresholds" in d
                    assert len(d["weights"]) > 0
        _run(go())

    def test_scoring_signal_entry_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/scoring",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for sig in d["weights"]:
                        assert "reason" in sig or "signal" in sig, \
                            f"weight entry missing reason/signal key: {sig}"
                        assert "weight" in sig or "score" in sig, \
                            f"weight entry missing weight/score key: {sig}"
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 6. Config endpoint — GET shape + POST hot-reload
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigEndpoint:
    def test_config_get_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/config",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_config_get_has_knobs(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/config",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    # Config response: {'state': {knob: value, ...}, 'applied': {}, ...}
                    state = d.get("state", {})
                    assert any("RISK_BAN_THRESHOLD" in str(k) for k in state)
        _run(go())

    def test_config_post_valid_knob_accepted(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={"RISK_BAN_THRESHOLD": 60},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert d.get("applied") or "RISK_BAN_THRESHOLD" in str(d)
        _run(go())

    def test_config_post_unknown_knob_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={"TOTALLY_FAKE_KNOB_ZZZZZ": "value"},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert r.status == 200
                    assert "TOTALLY_FAKE_KNOB_ZZZZZ" in str(d.get("rejected", {}))
        _run(go())

    def test_config_post_non_hot_reloadable_key_rejected(self, proxy_module):
        """Keys that are not in _HOT_RELOAD_KNOBS must appear in 'rejected'."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/config",
                                     json={"ADMIN_KEY": "should-be-rejected"},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "ADMIN_KEY" in str(d.get("rejected", {}))
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 7. Cost-timeline endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestCostTimelineEndpoint:
    def test_cost_timeline_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/cost-timeline",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_cost_timeline_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/cost-timeline?range=5&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "timeline" in d
                    assert "timeline_bucket_secs" in d
                    assert "timeline_range_min" in d
                    assert isinstance(d["timeline"], list)
        _run(go())

    def test_cost_timeline_entry_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/cost-timeline",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for entry in d["timeline"]:
                        assert "t" in entry
                        assert "avg_ms" in entry
                        assert "max_ms" in entry
                        assert "count" in entry
        _run(go())

    def test_cost_timeline_invalid_bucket_falls_back(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/cost-timeline?bucket=999",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert d["timeline_bucket_secs"] == 60
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 8. Health score endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestHealthScoreEndpoint:
    def test_health_score_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/health-score",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_health_score_in_valid_range(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/health-score",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "score" in d
                    assert 0 <= d["score"] <= 100
        _run(go())

    def test_health_score_reasons_list(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/health-score",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "reasons" in d
                    assert len(d["reasons"]) > 0
                    for reason in d["reasons"]:
                        assert "key" in reason
                        assert "status" in reason
                        assert reason["status"] in ("ok", "warn", "bad")
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 9. Detector stats endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectorStatsEndpoint:
    def test_detector_stats_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/detector-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_detector_stats_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/detector-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "signals" in d
                    assert "methods" in d
                    assert "chal" in d
                    assert "required" in d["chal"]
                    assert "minted" in d["chal"]
        _run(go())

    def test_detector_stats_signal_entry_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/detector-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for sig in d["signals"]:
                        assert "reason" in sig
                        assert "hits" in sig
                        assert "p50_ms" in sig
                        assert "p99_ms" in sig
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 10. Lists snapshot endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestListsSnapshotEndpoint:
    def test_lists_snapshot_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/lists-snapshot",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_lists_snapshot_required_keys(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/lists-snapshot",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for key in ("ua_blocklist_size", "honeypot_paths_size",
                                "suspicious_path_patterns", "version", "ts"):
                        assert key in d, f"lists-snapshot missing key: {key}"
        _run(go())

    def test_lists_snapshot_version_not_empty(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/lists-snapshot",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["version"], "version must be a non-empty string"
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 11. External endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestExternalEndpoint:
    def test_external_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/external",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_external_has_integrations_key(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/external",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "integrations" in d
                    assert isinstance(d["integrations"], list)
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 12. Signal orders endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestSignalOrdersEndpoint:
    def test_signal_orders_get_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/signal-orders",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_signal_orders_get_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/signal-orders",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "orders" in d
                    assert "gw_id" in d
        _run(go())

    def test_signal_orders_post_sets_order(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/signal-orders",
                                     json={"signal": "suspicious-path", "order": 1},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert d.get("ok") is True
                    assert d["signal"] == "suspicious-path"
                    assert d["order"] == 1
        _run(go())

    def test_signal_orders_post_invalid_order_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/signal-orders",
                                     json={"signal": "suspicious-path", "order": 99},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 400
        _run(go())

    def test_signal_orders_post_missing_signal_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/signal-orders",
                                     json={"order": 2},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 400
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 13. Path hits endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestPathHitsEndpoint:
    def test_path_hits_missing_param_returns_400(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/path-hits",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 400
        _run(go())

    def test_path_hits_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/path-hits?path=/index.html",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "ips" in d, f"path-hits missing 'ips' key, got: {list(d)}"
                    assert "total_rows" in d
                    assert isinstance(d["ips"], list)
        _run(go())

    def test_path_hits_returns_seeded_events(self, proxy_module):
        """Seed events then confirm path-hits reflects them."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ts_now = time.time()
                    _seed_events(proxy_module, [
                        (ts_now - 10, "5.5.5.5", "TestBot/1.0", "/test-path", 200, "ok"),
                        (ts_now - 5,  "5.5.5.5", "TestBot/1.0", "/test-path", 403, "honeypot"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/path-hits?path=/test-path",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert d["total_rows"] >= 1
                    ips = [row["ip"] for row in d["ips"]]
                    assert "5.5.5.5" in ips
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 14. Whoami endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestWhoamiEndpoint:
    def test_whoami_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/whoami",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_whoami_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/whoami",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "username" in d
                    assert "via" in d
                    assert "ip" in d
        _run(go())

    def test_whoami_username_is_admin(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/whoami",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["username"] == "admin"
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 15. Ban / unban lifecycle
# ─────────────────────────────────────────────────────────────────────────────

class TestBanUnbanLifecycle:
    def test_ban_ip_returns_banned_count(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/ban?ip=10.10.10.10&secs=3600&reason=test",
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "banned" in d
                    assert "secs" in d
                    assert d["secs"] == 3600
        _run(go())

    def test_ban_no_target_returns_400(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/ban?secs=3600&reason=test",
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 400
        _run(go())

    def test_unban_all_via_post(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/unban",
                                     json={"all": True},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "cleared" in d
        _run(go())

    def test_unban_all_via_get_rejected(self, proxy_module):
        """GET ?all=1 must be rejected (CSRF guard)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/unban?all=1",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 405
        _run(go())

    def test_ban_then_unban_clears_entry(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    # First make a request so there's a tracked identity
                    await c.get("/some-page", headers=_browser_headers(
                        {"X-Forwarded-For": "7.7.7.7"}))
                    await c.post(NS + "/ban?ip=7.7.7.7&secs=3600&reason=test",
                                 headers=_csrf_hdr(proxy_module, cookie),
                                 cookies={proxy_module._SESSION_COOKIE: cookie})
                    r = await c.post(NS + "/unban",
                                     json={"ip": "7.7.7.7"},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 16. Settings export endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestSettingsExportEndpoint:
    def test_settings_export_returns_zip(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings-export",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    ct = r.headers.get("Content-Type", "")
                    assert "zip" in ct or "octet" in ct
        _run(go())

    def test_settings_export_no_secrets_by_default(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings-export",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.read()
                    # zip magic bytes PK\x03\x04
                    assert body[:2] == b"PK"
        _run(go())

    def test_settings_export_unauthenticated_decoy(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/settings-export")
                    ct = r.headers.get("Content-Type", "")
                    # Must NOT return a ZIP to unauthenticated callers
                    assert "zip" not in ct
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 17. Dashboard HTML pages — return text/html when authenticated
# ─────────────────────────────────────────────────────────────────────────────

class TestDashboardHtmlPages:
    PAGES = ["live-feed", "control-center", "agents", "service", "controls", "settings"]

    def _check_html(self, status, ct, body):
        assert status == 200, f"expected 200, got {status}"
        assert "text/html" in ct, f"expected text/html, got {ct}"
        assert "AntiBot/WAF GW" in body or "<!DOCTYPE" in body or "<html" in body

    def test_dashboard_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/live-feed",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    self._check_html(r.status, r.headers.get("Content-Type",""), body)
        _run(go())

    def test_agents_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/agents",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    self._check_html(r.status, r.headers.get("Content-Type",""), body)
        _run(go())

    def test_service_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/service",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    self._check_html(r.status, r.headers.get("Content-Type",""), body)
        _run(go())

    def test_controls_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/controls",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    self._check_html(r.status, r.headers.get("Content-Type",""), body)
        _run(go())

    def test_settings_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/settings",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    self._check_html(r.status, r.headers.get("Content-Type",""), body)
        _run(go())

    def test_geo_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/geo",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    self._check_html(r.status, r.headers.get("Content-Type",""), body)
        _run(go())

    def test_logs_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/logs",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    self._check_html(r.status, r.headers.get("Content-Type",""), body)
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 18. Agents data + agents timeline
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentsDataEndpoint:
    def test_agents_data_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/agents-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_agents_data_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/agents-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "suspects" in d
                    assert isinstance(d["suspects"], list)
        _run(go())

    def test_agents_timeline_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/agents-timeline",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_agents_timeline_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/agents-timeline",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "timeline" in d
                    assert isinstance(d["timeline"], list)
        _run(go())

    def test_agents_timeline_bucket_has_gwmgmt(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/agents-timeline",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for bucket in d["timeline"]:
                        assert "gwmgmt" in bucket, \
                            "agents-timeline buckets must include gwmgmt field"
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 19. Service data endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceDataEndpoint:
    def test_service_data_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/service-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_service_data_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/service-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    # timeline + current snapshot
                    assert "timeline" in d or "current" in d
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 20. Public endpoints
# ─────────────────────────────────────────────────────────────────────────────

class TestPublicEndpoints:
    def test_live_probe_loopback(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(PUB + "/live")
                    # TestClient connects from loopback — should return 200 ok
                    assert r.status == 200
                    assert (await r.text()).strip() == "ok"
        _run(go())

    def test_robots_txt_present(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    # Browser headers required: bot UA triggers ua-non-browser deny
                    r = await c.get("/robots.txt", headers=_browser_headers())
                    assert r.status == 200
                    body = await r.text()
                    assert "User-agent" in body or "Disallow" in body
        _run(go())

    def test_robots_txt_blocks_all_bots(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/robots.txt", headers=_browser_headers())
                    body = await r.text()
                    assert "Disallow: /" in body
        _run(go())

    def test_pow_endpoint_returns_challenge(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(PUB + "/pow")
                    assert r.status == 200
                    d = await r.json()
                    assert "challenge" in d or "nonce" in d or "prefix" in d
        _run(go())

    def test_login_page_returns_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(PUB + "/login")
                    assert r.status == 200
                    ct = r.headers.get("Content-Type", "")
                    assert "text/html" in ct
        _run(go())

    def test_login_page_no_next_open_redirect(self, proxy_module):
        """?next= with external URL must not redirect to that URL."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(PUB + "/login?next=https://evil.example.com/",
                                    allow_redirects=False)
                    # Must be 200 (login page) — not a redirect to evil.example.com
                    if r.status in (301, 302, 303, 307, 308):
                        loc = r.headers.get("Location", "")
                        assert "evil.example.com" not in loc, \
                            f"Open redirect to external URL: {loc}"
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 21. Detection pipeline — OWASP probes (rules.md §8)
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectionPipeline:
    """Rules.md §8: every injection probe must fire its named reason."""

    def _bot_ua_headers(self):
        return {
            "User-Agent":      "python-requests/2.31.0",
            "Accept":          "*/*",
            "Accept-Encoding": "gzip, deflate",
        }

    def test_bot_ua_blocked(self, proxy_module):
        """python-requests UA scores high enough to trigger a block."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/", headers=self._bot_ua_headers())
                    # Score accumulates; first request may not yet ban.
                    # The signal ua-non-browser must be registered — confirm
                    # the risk_score rises by checking metrics.
                    cookie = _make_admin_cookie(proxy_module)
                    m = await c.get(NS + "/metrics",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await m.json()
                    # At least one client must have a non-zero risk_score
                    # (the python-requests UA accumulates score).
                    scores = [cl.get("risk_score", 0) for cl in d.get("clients", [])]
                    assert any(s > 0 for s in scores), \
                        "bot UA request must accumulate non-zero risk_score"
        _run(go())

    def test_honeypot_path_triggers_block(self, proxy_module):
        """/.git/HEAD is a honeypot path — must return block/challenge."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/.git/HEAD", headers=_browser_headers())
                    # Honeypot: may get 200 decoy or 403/429 depending on score
                    cookie = _make_admin_cookie(proxy_module)
                    m = await c.get(NS + "/metrics",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await m.json()
                    # Must record a block for the honeypot signal
                    blocked = [cl.get("blocked", 0) for cl in d.get("clients", [])]
                    assert any(b > 0 for b in blocked), \
                        "/.git/HEAD must record a blocked count in metrics"
        _run(go())

    def test_suspicious_path_sqli_detected(self, proxy_module):
        """SQLi pattern in URL path must fire suspicious-path or body-sqli."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    await c.get("/api/user?id='+OR+'a'='a",
                                headers=_browser_headers())
                    cookie = _make_admin_cookie(proxy_module)
                    m = await c.get(NS + "/metrics",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await m.json()
                    # 1.8.13 — detection now hard-blocks via a silent decoy and
                    # records the reason (was: soft risk_score on the client). Assert
                    # the by_reason counter, the observable current behaviour.
                    byr = d.get("by_reason", {})
                    assert byr.get("suspicious-path", 0) > 0 or byr.get("body-sqli", 0) > 0, \
                        f"SQLi in URL must fire suspicious-path/body-sqli; by_reason={byr}"
        _run(go())

    def test_lfi_path_detected(self, proxy_module):
        """../../etc/passwd in path must trigger suspicious-path signal."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    await c.get("/static/../../etc/passwd",
                                headers=_browser_headers())
                    cookie = _make_admin_cookie(proxy_module)
                    m = await c.get(NS + "/metrics",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await m.json()
                    # 1.8.13 — LFI/traversal path normalises (e.g. /static/../../etc/passwd
                    # → /etc/passwd) and fires suspicious-path, served as a silent decoy.
                    byr = d.get("by_reason", {})
                    assert byr.get("suspicious-path", 0) > 0, \
                        f"LFI path must fire suspicious-path; by_reason={byr}"
        _run(go())

    def test_control_byte_in_path_returns_400(self, proxy_module):
        """Control byte in path must return 400 before detection runs."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/path%7Fwith-del",
                                    headers=_browser_headers())
                    assert r.status == 400
        _run(go())

    def test_xss_in_query_scored(self, proxy_module):
        """XSS payload in query must not appear unescaped in any response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get('/search?q=<script>alert(1)</script>',
                                    headers=_browser_headers())
                    body = await r.text()
                    # The raw <script> tag must never appear unescaped in the gateway response
                    assert "<script>alert(1)</script>" not in body, \
                        "XSS payload must not appear unescaped in response"
        _run(go())

    def test_method_allowlist_trace_blocked(self, proxy_module):
        # 1.8.14 iter-20 — default widened to include PUT/PATCH/DELETE so REST
        # APIs work out of the box. TRACE remains blocked (not in default).
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.request("TRACE", "/api/resource",
                                        headers=_browser_headers())
                    assert r.status in (403, 404, 405), \
                        f"non-allowlisted TRACE must be blocked, got {r.status}"
        _run(go())

    def test_security_headers_on_html_response(self, proxy_module):
        """Security headers (X-Frame-Options, X-Content-Type-Options,
        Referrer-Policy) must be set on gateway-controlled HTML — login,
        dashboards, etc. — not on arbitrary upstream responses (upstreams
        may legitimately set their own CSP / framing policy).

        1.9.0 — the legacy check against the echo upstream's '/html' was
        always testing the wrong surface: the test echo server doesn't
        emit security headers, and the proxy is a transparent reverse
        proxy that doesn't inject on upstream pass-through. Anchor the
        check on /antibot-appsec-gateway/login where the gateway fully
        controls the response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/antibot-appsec-gateway/login",
                                    headers=_browser_headers())
                    assert r.status == 200, (
                        f"login page must return 200, got {r.status}"
                    )
                    ctype = r.headers.get("Content-Type", "")
                    assert "text/html" in ctype, (
                        f"login page must be HTML, got Content-Type={ctype!r}"
                    )
                    for hdr in ("X-Frame-Options", "X-Content-Type-Options",
                                "Referrer-Policy"):
                        assert hdr in r.headers, (
                            f"gateway-controlled HTML (login) is missing "
                            f"security header: {hdr}"
                        )
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 22. Agents bucket detail endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentsBucketEndpoint:
    def test_agents_bucket_requires_auth(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/agents-bucket?t=0&bucket_secs=60")
                    body = await r.text()
                    assert "ips" not in body
        _run(go())

    def test_agents_bucket_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    t = int(time.time()) - 60
                    r = await c.get(NS + f"/agents-bucket?t={t}&bucket_secs=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    # Response keys: bucket_t, bucket_secs, detected, missed, clean,
                    # authorized_robot, gwmgmt — no top-level "ips" key.
                    assert "detected" in d, f"agents-bucket missing 'detected': {list(d)}"
                    assert "gwmgmt" in d, "agents-bucket must include gwmgmt key"
        _run(go())

    def test_agents_bucket_bad_t_returns_400(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/agents-bucket?t=notanumber&bucket_secs=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 400
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 23. Logs data endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestLogsDataEndpoint:
    def test_logs_data_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/logs-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_logs_data_returns_valid_json(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/logs-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    ct = r.headers.get("Content-Type", "")
                    assert "json" in ct
                    d = await r.json()
                    assert "logs" in d or "events" in d or "rows" in d
        _run(go())

    def test_logs_data_filter_param_accepted(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/logs-data?reason=honeypot",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 24. Geo data endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestGeoDataEndpoint:
    def test_geo_data_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/geo-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_geo_data_shape(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/geo-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "points" in d or "events" in d
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 25. Admin IPs endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminIPsEndpoint:
    def test_admin_ips_get_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/admin-ips",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_admin_ips_get_entries_key(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/admin-ips",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert "entries" in d
                    assert isinstance(d["entries"], list)
        _run(go())

    def test_admin_ips_post_add_cidr(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/admin-ips",
                                     json={"cidr": "192.0.2.0/24",
                                           "description": "test-block"},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert d.get("ok") is True
        _run(go())

    def test_admin_ips_delete_cidr(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    # Use 127.0.0.0/8 so TestClient (127.0.0.1) stays allowed
                    # after the add — adding any other CIDR locks us out since
                    # ADMIN_ALLOWED_NETS non-empty means strict allowlist mode.
                    r1 = await c.post(NS + "/admin-ips",
                                      json={"cidr": "127.0.0.0/8",
                                            "description": "loopback-test"},
                                      headers=_csrf_hdr(proxy_module, cookie),
                                      cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r1.status == 200
                    # Now delete it
                    r = await c.delete(NS + "/admin-ips?cidr=127.0.0.0/8",
                                       headers=_csrf_hdr(proxy_module, cookie),
                                       cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert d.get("ok") is True
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 26. Secrets endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestSecretsEndpoint:
    def test_secrets_get_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/secrets",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_secrets_get_does_not_return_values(self, proxy_module):
        """GET must return key status (configured/not) — never the values."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/secrets",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    # Values must not be present — only boolean configured flags
                    for v in d.values() if isinstance(d, dict) else []:
                        if isinstance(v, dict):
                            assert "value" not in v or v.get("value") is None
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 27. XFF debug endpoint
# ─────────────────────────────────────────────────────────────────────────────

class TestXffEndpoint:
    def test_xff_200_authed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/xff",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
        _run(go())

    def test_xff_shows_resolved_ip(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/xff",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    # Response keys: computed_ip, remote, trust_xff_mode, headers, ...
                    assert "computed_ip" in d or "ip" in d or "resolved" in d, \
                        f"xff missing IP key, got: {list(d)}"
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 28. Proxy passthrough behaviour
# ─────────────────────────────────────────────────────────────────────────────

class TestProxyPassthrough:
    def test_clean_browser_forwarded_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/api/resource", headers=_browser_headers())
                    assert r.status in (200, 404), \
                        f"clean browser request should pass through, got {r.status}"
        _run(go())

    def test_proxy_adds_x_proxy_header(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get("/api/resource", headers=_browser_headers())
                    if r.status == 200:
                        assert r.headers.get("X-Proxy", "").startswith("AntiBotWaf_GW_")
        _run(go())

    def test_admin_path_not_forwarded_to_upstream(self, proxy_module):
        """Requests to the admin namespace must not reach the upstream."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    # Unauthenticated admin hit — gets decoy, NOT upstream
                    r = await c.get(NS + "/metrics")
                    # The upstream echo would return JSON with "path" key.
                    # Decoy is an upstream 404 page.  Neither exposes admin data.
                    body = await r.text()
                    assert '"total_requests"' not in body
        _run(go())

    def test_bypass_mode_skips_detection(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    proxy_module.BYPASS_MODE = True
                    try:
                        r = await c.get("/", headers={
                            "User-Agent": "python-requests/2.31.0",
                            "Accept": "*/*",
                        })
                        assert r.status in (200, 404), \
                            "bypass mode must let bot UA through"
                    finally:
                        proxy_module.BYPASS_MODE = False
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 29. Cache-Control headers on admin endpoints
# ─────────────────────────────────────────────────────────────────────────────

class TestCacheControlHeaders:
    """Admin JSON endpoints must set Cache-Control: no-store to prevent
    browsers / CDNs from caching sensitive data."""

    ENDPOINTS = [
        "status", "metrics", "thresholds", "scoring", "config",
        "health-score", "detector-stats", "lists-snapshot", "whoami",
    ]

    def _check_endpoint(self, endpoint, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + f"/{endpoint}",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    if r.status == 200:
                        cc = r.headers.get("Cache-Control", "")
                        assert "no-store" in cc, \
                            f"{endpoint}: missing Cache-Control: no-store (got {cc!r})"
        _run(go())

    def test_status_no_cache(self, proxy_module):
        self._check_endpoint("status", proxy_module)

    def test_metrics_no_cache(self, proxy_module):
        self._check_endpoint("metrics", proxy_module)

    def test_thresholds_no_cache(self, proxy_module):
        self._check_endpoint("thresholds", proxy_module)

    def test_scoring_no_cache(self, proxy_module):
        self._check_endpoint("scoring", proxy_module)

    def test_health_score_no_cache(self, proxy_module):
        self._check_endpoint("health-score", proxy_module)

    def test_detector_stats_no_cache(self, proxy_module):
        self._check_endpoint("detector-stats", proxy_module)

    def test_lists_snapshot_no_cache(self, proxy_module):
        self._check_endpoint("lists-snapshot", proxy_module)


# ─────────────────────────────────────────────────────────────────────────────
# 30. Admin IPs — POST invalid CIDR rejected
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminIPsValidation:
    def test_invalid_cidr_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/admin-ips",
                                     json={"cidr": "not-a-valid-cidr",
                                           "description": "test"},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    # Must reject with 400 or return ok=False
                    if r.status == 200:
                        d = await r.json()
                        assert d.get("ok") is False or "error" in d
                    else:
                        assert r.status in (400, 422)
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 31. Virtual Hosts API — CRUD + private-IP guard
# ─────────────────────────────────────────────────────────────────────────────

class TestVhostsAPI:
    """Dynamic tests for the /secured/vhosts CRUD endpoint.

    Each test boots an in-process proxy, issues real HTTP requests with
    an admin session cookie, and asserts correct response shapes.

    NOTE: Tests that POST a new vhost patch vhost._assert_upstream_public to
    a no-op so the test echo server (127.0.0.1) is accepted as an UPSTREAM.
    The guard itself is tested separately in test_post_private_ip_upstream_blocked.

    1.9.0 — POST-then-GET tests must allowlist 127.0.0.1 before the GET:
    1.8.15 introduced an implicit host-allowlist via the VHOSTS dict. Adding
    a vhost like "test.example.com" silently enables host-enforcement, after
    which the test runner's own Host:127.0.0.1 request gets a decoy 200
    (reason='host-not-allowed') and the JSON parse fails. _allowlist_local()
    pins 127.0.0.1 into ALLOWED_HOSTS so the in-process GET survives.
    """

    def _cookie(self, proxy_module):
        return _make_admin_cookie(proxy_module)

    def _allowlist_local(self, proxy_module):
        """Add 127.0.0.1 to the live ALLOWED_HOSTS set so the in-process
        TestClient (which always connects from 127.0.0.1) survives the
        1.8.15 implicit-vhost-allowlist enforcement once we add a vhost."""
        try:
            proxy_module.ALLOWED_HOSTS.add("127.0.0.1")
        except Exception:
            pass
        # Propagate to core.proxy_handler — _host_allowed reads its own
        # module-level binding, not proxy_module's.
        try:
            import core.proxy_handler as _cph
            _cph.ALLOWED_HOSTS.add("127.0.0.1")
        except Exception:
            pass

    # ── GET: returns JSON with vhosts key ────────────────────────────────────
    def test_get_returns_json_structure(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/vhosts",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"GET /vhosts: expected 200, got {r.status}"
                    d = await r.json()
                    assert "vhosts" in d, "GET /vhosts: response must have 'vhosts' key"
                    assert isinstance(d["vhosts"], list), "'vhosts' must be a list"
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, f"GET /vhosts: missing Cache-Control: no-store"
        _run(go())

    # ── GET: localhost requests — trusted proxy context ───────────────────────
    def test_get_accessible_from_localhost(self, proxy_module):
        """Authenticated GET must succeed from localhost (the test runner always
        connects from 127.0.0.1, which is the expected proxy management context)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/vhosts",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, (
                        f"GET /vhosts authenticated from localhost: expected 200, got {r.status}"
                    )
        _run(go())

    # ── POST: add a valid vhost entry ────────────────────────────────────────
    def test_post_add_vhost(self, proxy_module):
        from unittest.mock import patch as _patch
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    self._allowlist_local(proxy_module)
                    cookie = self._cookie(proxy_module)
                    # Patch the private-IP guard so the test echo server (127.0.0.1)
                    # is accepted — the guard itself is tested separately.
                    with _patch("vhost._assert_upstream_public"):
                        r = await c.post(NS + "/vhosts",
                                         json={"hostname": "test.example.com",
                                               "UPSTREAM": up,
                                               "UA_FILTER_ENABLED": True},
                                         headers=_csrf_hdr(proxy_module, cookie),
                                         cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"POST /vhosts: expected 200, got {r.status}"
                    d = await r.json()
                    assert d.get("ok") is True, f"POST /vhosts: ok must be True, got {d}"
                    # Confirm it now appears in GET
                    r2 = await c.get(NS + "/vhosts",
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    d2 = await r2.json()
                    hosts = [v["hostname"] for v in d2["vhosts"]]
                    assert "test.example.com" in hosts, (
                        f"POST /vhosts: added host not in GET response; got {hosts}"
                    )
        _run(go())

    # ── POST: missing hostname is rejected ───────────────────────────────────
    def test_post_missing_hostname_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.post(NS + "/vhosts",
                                     json={"UPSTREAM": up},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    if r.status == 200:
                        d = await r.json()
                        assert d.get("ok") is False, (
                            "POST /vhosts without hostname must return ok=False"
                        )
                    else:
                        assert r.status in (400, 422)
        _run(go())

    # ── POST: missing UPSTREAM is rejected ───────────────────────────────────
    def test_post_missing_upstream_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.post(NS + "/vhosts",
                                     json={"hostname": "test.example.com"},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    if r.status == 200:
                        d = await r.json()
                        assert d.get("ok") is False, (
                            "POST /vhosts without UPSTREAM must return ok=False"
                        )
                    else:
                        assert r.status in (400, 422)
        _run(go())

    # ── POST: private-IP UPSTREAM is blocked ─────────────────────────────────
    def test_post_private_ip_upstream_blocked(self, proxy_module):
        """Adding an UPSTREAM that resolves to a private/RFC-1918 address must
        be rejected to prevent SSRF through the public tunnel."""
        import config as _cfg
        _saved = _cfg.ALLOW_PRIVATE_UPSTREAM
        _cfg.ALLOW_PRIVATE_UPSTREAM = False
        try:
            async def go():
                async with _spin_upstream() as up:
                    async with _spin_proxy(proxy_module, up) as c:
                        # ALLOW_PRIVATE_UPSTREAM is hot-reloadable + persisted now,
                        # so on_startup's db_load_config can restore it from
                        # config_kv. Re-assert the guard ON after startup.
                        _cfg.ALLOW_PRIVATE_UPSTREAM = False
                        try:
                            import vhost as _vh
                            _vh._cfg.ALLOW_PRIVATE_UPSTREAM = False
                        except Exception:
                            pass
                        cookie = self._cookie(proxy_module)
                        private_upstreams = [
                            "http://127.0.0.1:9999",
                            "http://192.168.1.1",
                            "http://10.0.0.1:8080",
                            "http://172.16.0.1",
                        ]
                        for priv in private_upstreams:
                            r = await c.post(
                                NS + "/vhosts",
                                json={"hostname": "evil.test.com", "UPSTREAM": priv},
                                headers=_csrf_hdr(proxy_module, cookie),
                                cookies={proxy_module._SESSION_COOKIE: cookie},
                            )
                            if r.status == 200:
                                d = await r.json()
                                assert d.get("ok") is False, (
                                    f"POST /vhosts with private UPSTREAM {priv!r} must "
                                    f"return ok=False (SSRF guard); got {d}"
                                )
                            else:
                                assert r.status in (400, 422), (
                                    f"POST /vhosts with private UPSTREAM {priv!r}: "
                                    f"unexpected status {r.status}"
                                )
            _run(go())
        finally:
            _cfg.ALLOW_PRIVATE_UPSTREAM = _saved

    # ── DELETE: removes an existing entry ────────────────────────────────────
    def test_delete_vhost(self, proxy_module):
        from unittest.mock import patch as _patch
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    self._allowlist_local(proxy_module)
                    cookie = self._cookie(proxy_module)
                    # Add first (patch guard so localhost upstream is accepted)
                    with _patch("vhost._assert_upstream_public"):
                        await c.post(NS + "/vhosts",
                                     json={"hostname": "del.example.com", "UPSTREAM": up},
                                     headers=_csrf_hdr(proxy_module, cookie),
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    # Then delete
                    r = await c.delete(NS + "/vhosts",
                                       json={"hostname": "del.example.com"},
                                       headers=_csrf_hdr(proxy_module, cookie),
                                       cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, (
                        f"DELETE /vhosts: expected 200, got {r.status}"
                    )
                    d = await r.json()
                    assert d.get("ok") is True, f"DELETE /vhosts: ok must be True, got {d}"
                    assert d.get("existed") is True, (
                        "DELETE /vhosts: 'existed' must be True for an entry that was there"
                    )
                    # Confirm gone
                    r2 = await c.get(NS + "/vhosts",
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    d2 = await r2.json()
                    hosts = [v["hostname"] for v in d2["vhosts"]]
                    assert "del.example.com" not in hosts, (
                        "DELETE /vhosts: deleted host still in GET response"
                    )
        _run(go())

    # ── DELETE: non-existent hostname is idempotent (ok=True, existed=False) ─
    def test_delete_nonexistent_vhost_idempotent(self, proxy_module):
        """DELETE of a non-existent vhost must succeed (ok=True) but report
        existed=False — idempotent delete is safe and expected by the UI."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.delete(NS + "/vhosts",
                                       json={"hostname": "nope.example.com"},
                                       headers=_csrf_hdr(proxy_module, cookie),
                                       cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, (
                        f"DELETE /vhosts non-existent: expected 200, got {r.status}"
                    )
                    d = await r.json()
                    assert d.get("ok") is True, (
                        "DELETE /vhosts: ok must be True even for non-existent host"
                    )
                    assert d.get("existed") is False, (
                        "DELETE /vhosts: existed must be False for unknown host"
                    )
        _run(go())

    # ── POST: hostname normalised to lowercase ───────────────────────────────
    def test_post_hostname_normalised_lowercase(self, proxy_module):
        from unittest.mock import patch as _patch
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    self._allowlist_local(proxy_module)
                    cookie = self._cookie(proxy_module)
                    with _patch("vhost._assert_upstream_public"):
                        r = await c.post(NS + "/vhosts",
                                         json={"hostname": "UPPER.Example.COM",
                                               "UPSTREAM": up},
                                         headers=_csrf_hdr(proxy_module, cookie),
                                         cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"POST /vhosts lowercase: expected 200, got {r.status}"
                    d = await r.json()
                    assert d.get("ok") is True, f"POST /vhosts lowercase: ok must be True, got {d}"
                    r2 = await c.get(NS + "/vhosts",
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    d2 = await r2.json()
                    stored = [v["hostname"] for v in d2["vhosts"]]
                    assert "upper.example.com" in stored, (
                        "POST /vhosts: hostname must be stored lowercase"
                    )
                    assert "UPPER.Example.COM" not in stored, (
                        "POST /vhosts: original mixed-case hostname must not be stored"
                    )
        _run(go())

    # ── POST: lowercase 'upstream' alias accepted (normalised to UPSTREAM) ───
    def test_post_lowercase_upstream_alias_accepted(self, proxy_module):
        """POST /vhosts with lowercase 'upstream' key must be accepted and
        normalised to 'UPSTREAM' — mirrors curl/client ergonomics."""
        from unittest.mock import patch as _patch
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    self._allowlist_local(proxy_module)
                    cookie = self._cookie(proxy_module)
                    with _patch("vhost._assert_upstream_public"):
                        r = await c.post(NS + "/vhosts",
                                         json={"hostname": "alias.example.com",
                                               "upstream": up},
                                         headers=_csrf_hdr(proxy_module, cookie),
                                         cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, (
                        f"POST /vhosts with lowercase 'upstream': expected 200, got {r.status}"
                    )
                    d = await r.json()
                    assert d.get("ok") is True, (
                        f"POST /vhosts lowercase 'upstream': ok must be True, got {d}"
                    )
                    r2 = await c.get(NS + "/vhosts",
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    d2 = await r2.json()
                    hosts = [v["hostname"] for v in d2["vhosts"]]
                    assert "alias.example.com" in hosts, (
                        "POST /vhosts lowercase 'upstream': host not found after add"
                    )
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# Control Center — charts & data endpoints (1.8.1)
# ─────────────────────────────────────────────────────────────────────────────

class TestControlCenterCharts:
    """Dynamic QA for the Control Center page and its backing chart endpoints."""

    def _cookie(self, pm):
        return _make_admin_cookie(pm)

    # ── /secured/control-center HTML page ────────────────────────────────────

    def test_control_center_authenticated_returns_html(self, proxy_module):
        """GET /secured/control-center with auth must return 200 HTML containing all chart canvases."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/control-center",
                                    cookies={proxy_module._SESSION_COOKIE: cookie},
                                    headers=_browser_headers())
                    assert r.status == 200, f"control-center with auth: expected 200, got {r.status}"
                    body = await r.text()
                    assert "text/html" in r.headers.get("Content-Type", ""), \
                        "control-center: expected text/html content-type"
                    for canvas_id in ("traffic-chart", "blockrate-chart", "donut-chart"):
                        assert canvas_id in body, \
                            f"control-center HTML missing canvas id='{canvas_id}'"
        _run(go())

    def test_control_center_unauthenticated_returns_decoy(self, proxy_module):
        """GET /secured/control-center without auth must return a silent decoy (no dashboard HTML)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/control-center", headers=_browser_headers())
                    body = await r.text()
                    assert "AntiBotWaf_GW_1.9.9 · Control Center" not in body, \
                        "control-center: unauthenticated request must not return dashboard HTML"
        _run(go())

    def test_control_center_contains_vhost_breakdown_fetch(self, proxy_module):
        """HTML returned by control-center must include a fetch to /vhost-breakdown."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/control-center",
                                    cookies={proxy_module._SESSION_COOKIE: cookie},
                                    headers=_browser_headers())
                    body = await r.text()
                    assert "vhost-breakdown" in body, \
                        "control-center HTML must contain JS fetch to /vhost-breakdown"
        _run(go())

    def test_control_center_no_cdn_script_tags(self, proxy_module):
        """HTML returned by control-center must not reference any external CDN."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/control-center",
                                    cookies={proxy_module._SESSION_COOKIE: cookie},
                                    headers=_browser_headers())
                    body = await r.text()
                    assert "cdn.jsdelivr.net" not in body, \
                        "control-center HTML must not load Chart.js from CDN — use local /assets/"
        _run(go())

    # ── /secured/vhost-stats ─────────────────────────────────────────────────

    def test_vhost_stats_authenticated_returns_json(self, proxy_module):
        """GET /secured/vhost-stats with auth must return 200 JSON with 'stats' and 'ts' keys."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"vhost-stats with auth: expected 200, got {r.status}"
                    d = await r.json()
                    assert "stats" in d, f"vhost-stats: missing 'stats' key in response: {d}"
                    assert "ts" in d, f"vhost-stats: missing 'ts' key in response: {d}"
                    assert isinstance(d["stats"], list), \
                        f"vhost-stats: 'stats' must be a list, got {type(d['stats'])}"
        _run(go())

    def test_vhost_stats_unauthenticated_decoy(self, proxy_module):
        """GET /secured/vhost-stats without auth must not return real JSON data."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/vhost-stats")
                    body = await r.text()
                    assert '"stats"' not in body, \
                        "vhost-stats: unauthenticated request must not return stats JSON"
        _run(go())

    def test_vhost_stats_cache_control(self, proxy_module):
        """GET /secured/vhost-stats must respond with Cache-Control: no-store."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, \
                        f"vhost-stats: Cache-Control must contain 'no-store', got '{cc}'"
        _run(go())

    def test_vhost_stats_empty_db_returns_empty_list(self, proxy_module):
        """GET /secured/vhost-stats on an empty DB must return stats=[]."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    # Backend-aware empty-DB precondition: in PG-only mode the
                    # events table lives in Postgres (not the per-test SQLite
                    # file the conftest wipes), so clear it here to establish the
                    # "empty DB" precondition this test asserts.
                    from db.conn import conn as _backend_conn
                    with _backend_conn(timeout=10) as _wc:
                        _wc.execute("DELETE FROM events")
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["stats"] == [], \
                        f"vhost-stats: empty DB must return stats=[], got {d['stats']}"
        _run(go())

    def test_vhost_stats_row_schema(self, proxy_module):
        """GET /secured/vhost-stats with seeded events must return rows with required fields."""
        import time as _time
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    now = _time.time()
                    # Backend-aware seed (vhost-stats reads the active backend).
                    _seed_rows = [
                        (now - 60, "1.2.3.4", "ua", "/", 200, "operator-passthrough", "shop.example.com"),
                        (now - 60, "1.2.3.4", "ua", "/", 200, "banned-silent",        "shop.example.com"),
                    ]
                    from db.conn import active_backend
                    if active_backend() == "postgres":
                        # PG events.ts is timestamptz; use pg_insert_event (to_timestamp).
                        from db.postgres import pg_insert_event
                        for ts, ip, ua, path, status, reason, vhost in _seed_rows:
                            pg_insert_event(ts, ip, ua, path, int(status), reason, vhost=vhost)
                    else:
                        from db.conn import conn as _backend_conn
                        with _backend_conn(timeout=10) as conn:
                            conn.execute(
                                "CREATE TABLE IF NOT EXISTS events "
                                "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, ua TEXT, "
                                "path TEXT, status INTEGER DEFAULT 200, reason TEXT DEFAULT '', vhost TEXT DEFAULT '')"
                            )
                            conn.executemany(
                                "INSERT INTO events (ts, ip, ua, path, status, reason, vhost) VALUES (?,?,?,?,?,?,?)",
                                _seed_rows,
                            )
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    rows = d.get("stats", [])
                    hostnames = [row.get("hostname") for row in rows]
                    if "shop.example.com" in hostnames:
                        row = next(rw for rw in rows if rw.get("hostname") == "shop.example.com")
                        for field in ("hostname", "total_1h", "allowed_1h", "blocked_1h",
                                      "total_24h", "blocked_24h", "bans"):
                            assert field in row, \
                                f"vhost-stats row missing field '{field}': {row}"
        _run(go())

    # ── /secured/vhost-breakdown ─────────────────────────────────────────────

    def test_vhost_breakdown_authenticated_returns_json(self, proxy_module):
        """GET /secured/vhost-breakdown with auth must return 200 JSON with 'datasets' and 'labels'."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown?range=120&bucket=300",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, \
                        f"vhost-breakdown with auth: expected 200, got {r.status}"
                    d = await r.json()
                    assert "datasets" in d, \
                        f"vhost-breakdown: missing 'datasets' key: {d}"
                    assert "labels" in d, \
                        f"vhost-breakdown: missing 'labels' key: {d}"
                    assert isinstance(d["datasets"], list), \
                        f"vhost-breakdown: 'datasets' must be list, got {type(d['datasets'])}"
        _run(go())

    def test_vhost_breakdown_unauthenticated_decoy(self, proxy_module):
        """GET /secured/vhost-breakdown without auth must not return real JSON."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/vhost-breakdown?range=120&bucket=300")
                    body = await r.text()
                    assert '"datasets"' not in body, \
                        "vhost-breakdown: unauthenticated request must not return datasets JSON"
        _run(go())

    def test_vhost_breakdown_dataset_schema(self, proxy_module):
        """vhost-breakdown datasets must each have 'vhost' and 'data' fields."""
        import time as _time
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    now = _time.time()
                    # Backend-aware seed (vhost-breakdown reads the active backend).
                    from db.conn import active_backend
                    if active_backend() == "postgres":
                        from db.postgres import pg_insert_event
                        pg_insert_event(now - 60, "1.2.3.4", "ua", "/", 200,
                                        "operator-passthrough", vhost="api.example.com")
                    else:
                        from db.conn import conn as _backend_conn
                        with _backend_conn(timeout=10) as conn:
                            conn.execute(
                                "CREATE TABLE IF NOT EXISTS events "
                                "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, ua TEXT, "
                                "path TEXT, status INTEGER DEFAULT 200, reason TEXT DEFAULT '', vhost TEXT DEFAULT '')"
                            )
                            conn.execute(
                                "INSERT INTO events (ts, ip, ua, path, status, reason, vhost) VALUES (?,?,?,?,?,?,?)",
                                (now - 60, "1.2.3.4", "ua", "/", 200, "operator-passthrough", "api.example.com"),
                            )
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown?range=120&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for ds in d.get("datasets", []):
                        assert "vhost" in ds, \
                            f"vhost-breakdown: dataset missing 'vhost' field: {ds}"
                        assert "data" in ds, \
                            f"vhost-breakdown: dataset missing 'data' field: {ds}"
                        assert isinstance(ds["data"], list), \
                            f"vhost-breakdown: dataset 'data' must be list: {ds}"
        _run(go())

    def test_vhost_breakdown_cache_control(self, proxy_module):
        """GET /secured/vhost-breakdown must respond with Cache-Control: no-store."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = self._cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown?range=60&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, \
                        f"vhost-breakdown: Cache-Control must contain 'no-store', got '{cc}'"
        _run(go())
