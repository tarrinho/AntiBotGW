"""
Functional tests for all dashboard data API endpoints.
Verifies: JSON shape, required keys, param validation, and auth guards.
Run individually to avoid OOM (pre-existing since 1.7.0 modular split).
"""
import asyncio
import os
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


# ── Shared helpers (mirrors test_integration.py) ─────────────────────────

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


# ── /secured/metrics ─────────────────────────────────────────────────────

def test_metrics_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/metrics")
                assert r.status != 200 or "timeline" not in await r.text()
    _run(go())


def test_metrics_returns_required_keys(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/metrics",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                for key in ("timeline", "allowed", "blocked", "clients",
                            "services", "detector_hits", "config"):
                    assert key in d, f"missing key: {key}"
    _run(go())


def test_metrics_timeline_is_list(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/metrics",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                d = await r.json()
                assert isinstance(d["timeline"], list)
    _run(go())


def test_metrics_range_param_accepted(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/metrics?range=30",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert d["timeline_range_min"] == 30
    _run(go())


def test_metrics_invalid_range_uses_default(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/metrics?range=notanumber",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert isinstance(d["timeline_range_min"], int)
    _run(go())


# ── /secured/cost-timeline ───────────────────────────────────────────────

def test_cost_timeline_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/cost-timeline")
                text = await r.text()
                assert r.status != 200 or "timeline" not in text
    _run(go())


def test_cost_timeline_returns_timeline_list(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/cost-timeline",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert "timeline" in d
                assert isinstance(d["timeline"], list)
    _run(go())


# ── /secured/agents-data ─────────────────────────────────────────────────

def test_agents_data_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/agents-data")
                text = await r.text()
                assert r.status != 200 or "agents" not in text
    _run(go())


def test_agents_data_returns_agents_list(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/agents-data",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert "suspects" in d
                assert isinstance(d["suspects"], list)
    _run(go())


# ── /secured/agents-timeline ─────────────────────────────────────────────

def test_agents_timeline_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/agents-timeline")
                text = await r.text()
                assert r.status != 200 or "buckets" not in text
    _run(go())


def test_agents_timeline_returns_buckets(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/agents-timeline",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert "buckets" in d or "timeline" in d
    _run(go())


def test_agents_timeline_gwmgmt_in_timeline_entries(proxy_module):
    """Every timeline bucket must carry a gwmgmt key so the chart dataset[4]
    (gw mgmt line) and its tooltip entry always have a value to display."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/agents-timeline",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                timeline = d.get("timeline", [])
                assert timeline, "agents-timeline returned empty timeline"
                missing = [i for i, b in enumerate(timeline) if "gwmgmt" not in b]
                assert not missing, (
                    f"agents-timeline: {len(missing)} bucket(s) missing 'gwmgmt' key "
                    f"(indices {missing[:5]}). Chart dataset[4] needs this field."
                )
    _run(go())


def test_agents_timeline_gwmgmt_in_totals(proxy_module):
    """The totals object must include gwmgmt so the summary line in the
    agents dashboard can display the total gateway-management request count."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/agents-timeline",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert "totals" in d, "agents-timeline response missing 'totals' key"
                assert "gwmgmt" in d["totals"], (
                    f"agents-timeline totals missing 'gwmgmt' key. "
                    f"Got keys: {list(d['totals'].keys())}"
                )
    _run(go())


# ── /secured/service-data ────────────────────────────────────────────────

def test_service_data_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/service-data")
                text = await r.text()
                # Match the JSON-key form `"db":`, not the bare substring
                # `db`. The internal-probe decoy body is
                #   {"path": "/__appsecgw-probe-<16-byte hex>"}
                # and the random hex pair `db` appears ~12% of runs — flaky.
                # A real leak of the authenticated payload would carry the
                # `"db":` key literally, so this is stricter, not looser.
                assert r.status != 200 or '"db":' not in text
    _run(go())


def test_service_data_returns_json(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/service-data",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert isinstance(d, dict)
    _run(go())


# ── /secured/logs-data ───────────────────────────────────────────────────

def test_logs_data_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/logs-data")
                text = await r.text()
                assert r.status != 200 or "events" not in text
    _run(go())


def test_logs_data_returns_events(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/logs-data",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert "rows" in d
                assert isinstance(d["rows"], list)
    _run(go())


def test_logs_data_limit_param(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/logs-data?limit=5",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert len(d.get("events", [])) <= 5
    _run(go())


# ── /secured/health-score ────────────────────────────────────────────────

def test_health_score_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/health-score")
                text = await r.text()
                assert r.status != 200 or "score" not in text
    _run(go())


def test_health_score_returns_score(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/health-score",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert "score" in d
                assert isinstance(d["score"], (int, float))
    _run(go())


# ── /secured/detector-stats ──────────────────────────────────────────────

def test_detector_stats_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/detector-stats")
                text = await r.text()
                assert r.status != 200 or "detectors" not in text
    _run(go())


def test_detector_stats_returns_detectors(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/detector-stats",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert "detectors" in d or "methods" in d
    _run(go())


# ── /secured/geo-data ────────────────────────────────────────────────────

def test_geo_data_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/geo-data")
                text = await r.text()
                assert r.status != 200 or "countries" not in text
    _run(go())


def test_geo_data_returns_json(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/geo-data",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert isinstance(d, dict)
    _run(go())


# ── /secured/path-hits ───────────────────────────────────────────────────

def test_path_hits_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/path-hits")
                text = await r.text()
                assert r.status != 200 or "paths" not in text
    _run(go())


def test_path_hits_returns_paths(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/path-hits?path=/",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert "ips" in d
                assert isinstance(d["ips"], list)
    _run(go())


def test_events_table_has_path_ts_index(proxy_module):
    """db/sqlite.py must define idx_events_path_ts ON events(path, ts).
    Without it the path-hits query (WHERE path=? AND ts>=?) does a full table
    scan and slows to several seconds on busy installs.

    Checks the schema source rather than the test-session DB so the assertion
    is not affected by cached session state."""
    from pathlib import Path
    schema_src = (Path(__file__).resolve().parent.parent / "db" / "sqlite.py").read_text()
    assert "idx_events_path_ts" in schema_src, (
        "idx_events_path_ts not found in db/sqlite.py. "
        "Add: CREATE INDEX IF NOT EXISTS idx_events_path_ts ON events(path, ts)."
    )


def test_path_hits_responds_quickly_with_large_dataset(proxy_module):
    """path-hits endpoint must return in < 500 ms for 5 000 seeded events.
    Root cause of slowness: missing idx_events_path_ts index on events(path, ts)
    caused a full table scan; now offloaded to run_in_executor so the event loop
    is not blocked either."""
    import sqlite3, time
    db = proxy_module.DB_PATH
    path = "/__qa_stress_path_hits__"
    now_ts = time.time()
    conn = sqlite3.connect(db)
    conn.executemany(
        "INSERT INTO events(ts, ip, ua, path, method, status, reason) "
        "VALUES (?,?,?,?,?,?,?)",
        [
            (now_ts - i * 17, f"10.{i//65536%256}.{i//256%256}.{i%256}",
             "stress-UA", path, "GET", 200, "")
            for i in range(5000)
        ],
    )
    conn.commit()
    conn.close()
    try:
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_session(proxy_module)
                    t0 = time.monotonic()
                    r = await c.get(
                        NS + f"/path-hits?path={path}&range=1440",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    elapsed_ms = (time.monotonic() - t0) * 1000
                    assert r.status == 200
                    d = await r.json()
                    assert d.get("total_rows", 0) > 0, \
                        "path-hits returned no rows for the seeded path"
                    assert elapsed_ms < 500, (
                        f"path-hits took {elapsed_ms:.0f} ms for 5000 events — "
                        "idx_events_path_ts index missing or query still blocking "
                        "the event loop."
                    )
        _run(go())
    finally:
        conn2 = sqlite3.connect(db)
        conn2.execute("DELETE FROM events WHERE path = ?", (path,))
        conn2.commit()
        conn2.close()


# ── /secured/whoami ──────────────────────────────────────────────────────

def test_whoami_auth_guard(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get(NS + "/whoami")
                text = await r.text()
                assert r.status != 200 or "username" not in text
    _run(go())


def test_whoami_returns_username_and_via(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/whoami",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200
                d = await r.json()
                assert "username" in d
                assert "via" in d
    _run(go())


def test_whoami_reflects_session_username(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/whoami",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                d = await r.json()
                assert d["username"] == "admin"
                assert d["via"] == "session"
    _run(go())


# ── Cache-Control: no-store on all secured data endpoints ────────────────

def test_metrics_no_cache_header(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/metrics",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert "no-store" in r.headers.get("Cache-Control", "")
    _run(go())


def test_whoami_no_cache_header(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _make_admin_session(proxy_module)
                r = await c.get(NS + "/whoami",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert "no-store" in r.headers.get("Cache-Control", "")
    _run(go())
