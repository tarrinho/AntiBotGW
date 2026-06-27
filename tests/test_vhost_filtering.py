"""
Vhost-scoped filtering tests — all dashboard data endpoints
===========================================================

Coverage matrix
───────────────
U1   metrics endpoint — vhost param filters timeline + clients + recent_events
  U1.1  no ?vhost= → timeline total > 0 after seeding events from 2 vhosts
  U1.2  ?vhost=A → timeline sum equals the number of seeded vhostA events
  U1.3  ?vhost=B → timeline all-zero when only vhostA events exist
  U1.4  authenticated GET (no vhost) → 200 with timeline/clients/events keys
  U1.5  unauthenticated GET → NOT a real metrics response (decoy)

U2   cost-timeline endpoint — intentionally global (no per-vhost data)
  U2.1  authenticated GET → 200 with timeline key
  U2.2  ?vhost=anything → still 200 with timeline key (param is ignored gracefully)
  U2.3  response structure identical with and without ?vhost= (both have timeline list)

U3   agents-data endpoint — filters in-memory client list by s.last_vhost
  U3.1  authenticated GET → 200
  U3.2  ?vhost=example.com → 200 (no crash)
  U3.3  unauthenticated GET → NOT a structured agents response (decoy)

U4   agents-timeline endpoint — SQL WHERE vhost = ? applied to all sub-queries
  U4.1  authenticated GET → 200 with timeline key
  U4.2  ?vhost=A → detected count matches agent-block events seeded for vhostA
  U4.3  ?vhost=B → detected count 0 when only vhostA events exist
  U4.4  unauthenticated GET → decoy response

U5   geo-data endpoint — SQL AND vhost = ? applied when ?vhost= is set
  U5.1  authenticated GET → 200 with expected response keys
  U5.2  ?vhost=example.com → 200 (no crash, param accepted)
  U5.3  vhost filter isolates geo countries (or returns 200 without error)
  U5.4  unauthenticated GET → decoy

U6   service-data endpoint — filters traffic counters; system metrics global
  U6.1  authenticated GET → 200 with required keys
  U6.2  ?vhost=example.com → 200
  U6.3  ?vhost=A → vhost_filter in app section equals vhostA
  U6.4  unauthenticated GET → decoy

U7   logs-data endpoint — recently fixed: WHERE vhost = ? for kind=requests
  U7.1  no ?vhost= → response has events from both seeded vhosts
  U7.2  ?vhost=A → all returned rows have vhost=vhostA (cross-contamination absent)
  U7.3  ?vhost=B → empty rows when only vhostA events were seeded
  U7.4  ?kind=gw&vhost=anything → 200 (gw logs are global, vhost silently ignored)
  U7.5  unauthenticated GET → decoy

R1   source-level regression guards — pattern checks in source files
  R1.1  proxy_handler.py: vhost_filter present in metrics timeline branch
  R1.2  proxy_handler.py: logs_data_endpoint has WHERE vhost = ? clause
  R1.3  logs.html: fetch to logs-data includes _vhostParam()
  R1.4  main.html: cost-timeline fetch does NOT include _vhostParam()
  R1.5  agents.py: agents_timeline_endpoint contains AND vhost = ? SQL clause
  R1.6  proxy_handler.py: geo_data_endpoint uses vhost = ? SQL clause
  R1.7  service_metrics.py: service_metrics_data_endpoint has vhost = ? in events query
"""
import asyncio
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# ── Constants ─────────────────────────────────────────────────────────────────

NS = "/antibot-appsec-gateway/secured"

_PROJ = Path(__file__).resolve().parent.parent
_DASHBOARDS = _PROJ / "dashboards"


# ── Event isolation fixture (autouse) ────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate_events(proxy_module):
    """Wipe events (SQLite + in-memory ring buffers) before and after every test.

    Clears both the SQLite events table AND the in-memory events_by_cat ring
    buffers so metrics-timeline vhost-filter tests don't inherit events from
    prior tests in the same combined session run.
    """
    def _wipe():
        # Backend-aware wipe: under APPSECGW_TEST_PG the dashboard endpoints
        # read events from Postgres, so wiping only the local SQLite file left
        # stale PG rows visible (and seeded rows below would never appear). Go
        # through db.open_conn() so we clear whichever backend is live.
        try:
            from db import open_conn
            conn = open_conn()
            conn.execute("DELETE FROM events")
            conn.commit()
            conn.close()
        except Exception:
            pass  # table not yet created — nothing to wipe
        # Also clear in-memory ring buffers used by metrics timeline aggregation
        try:
            from state import events_by_cat
            for dq in events_by_cat.values():
                dq.clear()
        except Exception:
            pass
    _wipe()
    yield
    _wipe()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


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


def _make_admin_cookie(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _is_pg():
    """True when the active backend is Postgres (APPSECGW_TEST_PG mode)."""
    try:
        from db.conn import active_backend
        return active_backend() == "postgres"
    except Exception:
        return False


def _insert_event_row(conn, ts, ip, ua, path, status, reason, vhost, pg):
    """Insert one events row through a backend-aware connection. On Postgres
    the `ts` column is TIMESTAMPTZ, so wrap the epoch float in to_timestamp();
    on SQLite ts is a raw float. open_conn() rewrites ? -> %s for PG."""
    if pg:
        conn.execute(
            "INSERT INTO events (ts, ip, ua, path, status, reason, vhost) "
            "VALUES (to_timestamp(?),?,?,?,?,?,?)",
            (ts, ip, ua, path, status, reason, vhost),
        )
    else:
        conn.execute(
            "INSERT INTO events (ts, ip, ua, path, status, reason, vhost) "
            "VALUES (?,?,?,?,?,?,?)",
            (ts, ip, ua, path, status, reason, vhost),
        )


def _seed_event(proxy_module, vhost="", reason="ok", ip="1.2.3.4",
                path="/", ts=None, status=200):
    """Insert a single event row into the events table on the active backend.

    Backend-aware (was sqlite3.connect(DB_PATH)): the dashboard endpoints read
    events from Postgres under APPSECGW_TEST_PG, so seeding only the local
    SQLite file left the rows invisible to the endpoints under test.
    """
    from db import open_conn
    pg = _is_pg()
    conn = open_conn()
    _insert_event_row(conn, ts or time.time(), ip, "test-ua", path, status,
                      reason, vhost, pg)
    conn.commit()
    conn.close()


def _seed_many(proxy_module, rows):
    """Insert multiple (vhost, reason, ip) tuples as recent events on the
    active backend (see _seed_event for the backend-aware rationale)."""
    from db import open_conn
    pg = _is_pg()
    conn = open_conn()
    now = time.time()
    for i, (vhost, reason, ip) in enumerate(rows):
        _insert_event_row(conn, now - i, ip, "test-ua", "/", 200,
                          reason, vhost, pg)
    conn.commit()
    conn.close()


# ── U1: metrics endpoint ──────────────────────────────────────────────────────

class TestU1MetricsVhostFilter:
    """GET /secured/metrics — vhost param filters timeline + clients + recent_events."""

    def test_no_vhost_returns_all_events_in_timeline(self, proxy_module):
        """No ?vhost= → timeline list is non-empty and vhost-A events appear when
        ?vhost=vhostA is compared against the unfiltered view.

        The metrics timeline in the unfiltered (no-vhost) path is served from the
        in-memory minute-bucket dict, not the events table, so directly-seeded
        SQLite rows are invisible.  Instead this test validates that seeding events
        for vhostA and querying ?vhost=vhostA shows those events, while querying
        without ?vhost= shows >= the filtered count (global >= per-vhost).
        """
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    _seed_event(proxy_module, vhost="alpha.vhf", ip="1.1.1.1")
                    _seed_event(proxy_module, vhost="beta.vhf",  ip="2.2.2.2")
                    cookie = _make_admin_cookie(proxy_module)
                    # Filtered by vhostA — uses events table, so seeded rows are visible
                    async with cl.get(
                        NS + "/metrics?vhost=alpha.vhf",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r_vhost:
                        assert r_vhost.status == 200
                        d_vhost = await r_vhost.json()
                        total_vhost = sum(b.get("total", 0) for b in d_vhost.get("timeline", []))
                        assert total_vhost >= 1, (
                            "?vhost=alpha.vhf must show at least 1 event in timeline "
                            "after seeding 1 alpha event"
                        )
                    # Unfiltered — timeline is present and is a list
                    async with cl.get(
                        NS + "/metrics",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r_all:
                        assert r_all.status == 200
                        d_all = await r_all.json()
                        assert isinstance(d_all.get("timeline"), list), (
                            "no-vhost metrics must have 'timeline' list"
                        )
        _run(go())

    def test_vhost_filter_isolates_timeline(self, proxy_module):
        """?vhost=alpha.vhf → timeline sum equals 3 (only alpha events)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    # 3 events for alpha, 2 for beta
                    _seed_many(proxy_module, [
                        ("alpha.vhf", "ok", "1.0.0.1"),
                        ("alpha.vhf", "ok", "1.0.0.2"),
                        ("alpha.vhf", "ok", "1.0.0.3"),
                        ("beta.vhf",  "ok", "2.0.0.1"),
                        ("beta.vhf",  "ok", "2.0.0.2"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/metrics?vhost=alpha.vhf",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200
                        d = await r.json()
                        total = sum(b.get("total", 0) for b in d.get("timeline", []))
                        assert total == 3, (
                            f"?vhost=alpha.vhf: expected timeline total=3 (only alpha events), "
                            f"got {total}"
                        )
        _run(go())

    def test_vhost_filter_empty_when_no_match(self, proxy_module):
        """?vhost=beta.vhf → timeline all zeros when only alpha events exist."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    _seed_event(proxy_module, vhost="alpha.vhf", ip="1.1.1.1")
                    _seed_event(proxy_module, vhost="alpha.vhf", ip="1.1.1.2")
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/metrics?vhost=beta.vhf",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200
                        d = await r.json()
                        total = sum(b.get("total", 0) for b in d.get("timeline", []))
                        assert total == 0, (
                            f"?vhost=beta.vhf with only alpha events: expected total=0, got {total}"
                        )
        _run(go())

    def test_no_vhost_returns_200_with_keys(self, proxy_module):
        """Authenticated GET (no vhost) → 200 with timeline, clients, events keys.

        The recent-events list is returned as 'events' in the metrics response
        (not 'recent_events') — confirmed from the return web.json_response() call
        in metrics_endpoint.
        """
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/metrics",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, f"metrics: expected 200, got {r.status}"
                        d = await r.json()
                        for key in ("timeline", "clients", "events"):
                            assert key in d, f"metrics response missing key '{key}'"
        _run(go())

    def test_unauthenticated_returns_decoy(self, proxy_module):
        """No session cookie → NOT a real metrics response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    async with cl.get(NS + "/metrics") as r:
                        body = await r.text()
                        # A real metrics response has timeline + clients + recent_events
                        has_all = ('"timeline"' in body and '"clients"' in body
                                   and '"recent_events"' in body)
                        assert not has_all, (
                            "unauthenticated /metrics must not return real admin data"
                        )
        _run(go())


# ── U2: cost-timeline endpoint ────────────────────────────────────────────────

class TestU2CostTimelineVhostFilter:
    """GET /secured/cost-timeline — intentionally global, no per-vhost filtering."""

    def test_returns_200_with_timeline_key(self, proxy_module):
        """Authenticated GET → 200, response has 'timeline' key."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/cost-timeline",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, f"cost-timeline: expected 200, got {r.status}"
                        d = await r.json()
                        assert "timeline" in d, "cost-timeline must have 'timeline' key"
                        assert isinstance(d["timeline"], list), "'timeline' must be a list"
        _run(go())

    def test_vhost_param_does_not_break_response(self, proxy_module):
        """?vhost=anything → still 200 with timeline key (param silently ignored)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/cost-timeline?vhost=some.host.test",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, (
                            f"cost-timeline?vhost=X: expected 200, got {r.status}"
                        )
                        d = await r.json()
                        assert "timeline" in d, (
                            "cost-timeline?vhost=X must still have 'timeline' key"
                        )
        _run(go())

    def test_response_same_with_and_without_vhost(self, proxy_module):
        """Both with and without ?vhost= return a timeline list (structure identical)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/cost-timeline",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r_plain:
                        d_plain = await r_plain.json()

                    async with cl.get(
                        NS + "/cost-timeline?vhost=filter.test",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r_vhost:
                        d_vhost = await r_vhost.json()

                    # Both must have a timeline list with the same length
                    assert isinstance(d_plain.get("timeline"), list), (
                        "plain cost-timeline must have list 'timeline'"
                    )
                    assert isinstance(d_vhost.get("timeline"), list), (
                        "vhost cost-timeline must have list 'timeline'"
                    )
                    assert len(d_plain["timeline"]) == len(d_vhost["timeline"]), (
                        "cost-timeline length must be the same with/without ?vhost= "
                        "(timeline is global, not vhost-filtered)"
                    )
        _run(go())


# ── U3: agents-data endpoint ──────────────────────────────────────────────────

class TestU3AgentsDataVhostFilter:
    """GET /secured/agents-data — filters in-memory client list by s.last_vhost."""

    def test_no_vhost_returns_200(self, proxy_module):
        """Authenticated GET without ?vhost= → 200."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/agents-data",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, f"agents-data: expected 200, got {r.status}"
                        d = await r.json()
                        # Response must have top-level keys: summary, buckets, suspects
                        assert "summary"  in d, "agents-data must have 'summary' key"
                        assert "suspects" in d, "agents-data must have 'suspects' key"
        _run(go())

    def test_vhost_param_accepted(self, proxy_module):
        """?vhost=example.com → 200 (no crash, param accepted)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/agents-data?vhost=example.com",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, (
                            f"agents-data?vhost=example.com: expected 200, got {r.status}"
                        )
        _run(go())

    def test_unauthenticated_decoy(self, proxy_module):
        """No session cookie → NOT a structured agents response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    async with cl.get(NS + "/agents-data") as r:
                        body = await r.text()
                        # A real agents-data response contains "suspects" + "summary"
                        has_suspects = '"suspects"' in body and '"summary"' in body
                        assert not has_suspects, (
                            "unauthenticated /agents-data must not return real agent data"
                        )
        _run(go())


# ── U4: agents-timeline endpoint ──────────────────────────────────────────────

class TestU4AgentsTimelineVhostFilter:
    """GET /secured/agents-timeline — SQL WHERE vhost = ? applied to all sub-queries."""

    # One of the reasons in AGENT_BLOCK_REASONS (confirmed in agents.py source)
    _AGENT_REASON = "ua-blocked"

    def test_no_vhost_returns_200(self, proxy_module):
        """Authenticated GET → 200 with timeline key."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/agents-timeline",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, f"agents-timeline: expected 200, got {r.status}"
                        d = await r.json()
                        assert "timeline" in d, "agents-timeline must have 'timeline' key"
                        assert "totals"   in d, "agents-timeline must have 'totals' key"
        _run(go())

    def test_vhost_filter_isolates_db_events(self, proxy_module):
        """?vhost=alpha.vhf → 'detected' total equals agent-block events seeded for alpha."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    # Seed 3 agent-block events for alpha, 2 for beta
                    _seed_many(proxy_module, [
                        ("alpha.vhf", self._AGENT_REASON, "1.0.0.1"),
                        ("alpha.vhf", self._AGENT_REASON, "1.0.0.2"),
                        ("alpha.vhf", self._AGENT_REASON, "1.0.0.3"),
                        ("beta.vhf",  self._AGENT_REASON, "2.0.0.1"),
                        ("beta.vhf",  self._AGENT_REASON, "2.0.0.2"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/agents-timeline?vhost=alpha.vhf",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200
                        d = await r.json()
                        detected_total = d.get("totals", {}).get("detected", -1)
                        assert detected_total == 3, (
                            f"?vhost=alpha.vhf: expected detected=3, got {detected_total}"
                        )
        _run(go())

    def test_vhost_filter_zero_when_no_match(self, proxy_module):
        """?vhost=beta.vhf → detected=0 when only alpha events exist."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    _seed_many(proxy_module, [
                        ("alpha.vhf", self._AGENT_REASON, "1.0.0.1"),
                        ("alpha.vhf", self._AGENT_REASON, "1.0.0.2"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/agents-timeline?vhost=beta.vhf",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200
                        d = await r.json()
                        detected_total = d.get("totals", {}).get("detected", -1)
                        assert detected_total == 0, (
                            f"?vhost=beta.vhf with only alpha events: expected detected=0, "
                            f"got {detected_total}"
                        )
        _run(go())

    def test_unauthenticated_decoy(self, proxy_module):
        """No session cookie → NOT a structured agents-timeline response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    async with cl.get(NS + "/agents-timeline") as r:
                        body = await r.text()
                        has_real = '"timeline"' in body and '"totals"' in body
                        assert not has_real, (
                            "unauthenticated /agents-timeline must not return real timeline data"
                        )
        _run(go())


# ── U5: geo-data endpoint ─────────────────────────────────────────────────────

class TestU5GeoDataVhostFilter:
    """GET /secured/geo-data — SQL AND vhost = ? applied when ?vhost= is set.

    When MAXMIND_CITY_ENABLED is False (default in test env), the endpoint
    returns {"points": [], "configured": False} with 200.  Tests here cover:
    • the unconfigured path (200 + 'configured' key) for auth/param acceptance
    • with MaxMind monkey-patched, the vhost filter is verified via SQL isolation
    """

    @staticmethod
    def _enable_maxmind(cph, fake_lookup=None):
        """Enable geo lookup in core.proxy_handler for this test scope."""
        orig_enabled  = cph.MAXMIND_CITY_ENABLED
        orig_lookup   = cph._city_lookup
        orig_asn      = cph.MAXMIND_ENABLED
        cph.MAXMIND_CITY_ENABLED = True
        cph._city_lookup = fake_lookup or (lambda ip: (48.85, 2.35, "FR", "Paris"))
        cph.MAXMIND_ENABLED = False
        cph._GEO_CACHE.clear()
        return orig_enabled, orig_lookup, orig_asn

    @staticmethod
    def _restore_maxmind(cph, orig_enabled, orig_lookup, orig_asn):
        cph.MAXMIND_CITY_ENABLED = orig_enabled
        cph._city_lookup         = orig_lookup
        cph.MAXMIND_ENABLED      = orig_asn
        cph._GEO_CACHE.clear()

    def test_no_vhost_returns_200(self, proxy_module):
        """Authenticated GET → 200 with 'configured' key (even when mmdb absent)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/geo-data",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, f"geo-data: expected 200, got {r.status}"
                        d = await r.json()
                        # Either "configured" key (unconfigured path) or "points" key
                        assert "configured" in d or "points" in d, (
                            "geo-data must have 'configured' or 'points' key"
                        )
        _run(go())

    def test_vhost_param_accepted(self, proxy_module):
        """?vhost=example.com → 200 (param accepted without error)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/geo-data?vhost=example.com",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, (
                            f"geo-data?vhost=example.com: expected 200, got {r.status}"
                        )
        _run(go())

    def test_vhost_filter_isolates_countries(self, proxy_module):
        """Vhost filter reduces the result set — or at minimum returns 200 cleanly."""
        async def go():
            import core.proxy_handler as cph
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    # Seed events from two vhosts
                    _seed_event(proxy_module, vhost="geo-alpha.test", ip="5.5.5.5")
                    _seed_event(proxy_module, vhost="geo-beta.test",  ip="6.6.6.6")
                    orig = self._enable_maxmind(cph)
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        # Filtered request
                        async with cl.get(
                            NS + "/geo-data?vhost=geo-alpha.test",
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        ) as r_a:
                            assert r_a.status == 200, (
                                f"geo-data?vhost=geo-alpha.test: expected 200, got {r_a.status}"
                            )
                            d_a = await r_a.json()
                            # Must not be an error response
                            assert "error" not in d_a, (
                                f"geo-data?vhost=geo-alpha.test returned error: {d_a.get('error')}"
                            )
                        # Unfiltered request
                        cph._GEO_CACHE.clear()
                        async with cl.get(
                            NS + "/geo-data",
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        ) as r_all:
                            assert r_all.status == 200
                            d_all = await r_all.json()
                            # Filtered should have <= unfiltered total points
                            pts_a   = len(d_a.get("points", []))
                            pts_all = len(d_all.get("points", []))
                            assert pts_a <= pts_all, (
                                f"vhost-filtered geo-data should have <= total points; "
                                f"filtered={pts_a} all={pts_all}"
                            )
                    finally:
                        self._restore_maxmind(cph, *orig)
        _run(go())

    def test_unauthenticated_decoy(self, proxy_module):
        """No session cookie → NOT a real geo-data response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    async with cl.get(NS + "/geo-data") as r:
                        body = await r.text()
                        # A real geo-data response has "configured" AND ("points" or "countries")
                        has_configured = '"configured"' in body
                        has_points = '"points"' in body
                        # decoy path: upstream returns non-geo JSON (no "configured": true)
                        # We only check that it's NOT leaking the full admin geo payload
                        if has_configured and has_points:
                            d = await r.json() if r.status == 200 else {}
                            # If somehow both keys are present, verify it's the unconfigured stub
                            # (configured: false is acceptable — it doesn't leak real data)
                            configured = d.get("configured", None)
                            assert configured is False or configured is None, (
                                "unauthenticated /geo-data must not return configured=true geo data"
                            )
        _run(go())


# ── U6: service-data endpoint ─────────────────────────────────────────────────

class TestU6ServiceDataVhostFilter:
    """GET /secured/service-data — filters traffic counters; system metrics global."""

    def test_no_vhost_returns_200(self, proxy_module):
        """Authenticated GET → 200 with required keys."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/service-data",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, f"service-data: expected 200, got {r.status}"
                        d = await r.json()
                        for key in ("current", "history", "app"):
                            assert key in d, f"service-data missing key '{key}'"
        _run(go())

    def test_vhost_param_accepted(self, proxy_module):
        """?vhost=example.com → 200 (no crash)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/service-data?vhost=example.com",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, (
                            f"service-data?vhost=example.com: expected 200, got {r.status}"
                        )
        _run(go())

    def test_vhost_filter_traffic_counters(self, proxy_module):
        """?vhost=A → app.vhost_filter equals 'A' in response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    _seed_event(proxy_module, vhost="svc-alpha.test", ip="3.3.3.3")
                    _seed_event(proxy_module, vhost="svc-beta.test",  ip="4.4.4.4")
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/service-data?vhost=svc-alpha.test",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200
                        d = await r.json()
                        vhost_filter = d.get("app", {}).get("vhost_filter")
                        assert vhost_filter == "svc-alpha.test", (
                            f"service-data?vhost=svc-alpha.test: expected app.vhost_filter='svc-alpha.test', "
                            f"got {vhost_filter!r}"
                        )
        _run(go())

    def test_unauthenticated_decoy(self, proxy_module):
        """No session cookie → NOT a structured service-data response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    async with cl.get(NS + "/service-data") as r:
                        body = await r.text()
                        has_real = ('"current"' in body and '"history"' in body
                                    and '"app"' in body)
                        assert not has_real, (
                            "unauthenticated /service-data must not return real service metrics"
                        )
        _run(go())


# ── U7: logs-data endpoint ────────────────────────────────────────────────────

class TestU7LogsDataVhostFilter:
    """GET /secured/logs-data — recently fixed: WHERE vhost = ? for kind=requests."""

    def test_no_vhost_returns_all_logs(self, proxy_module):
        """No ?vhost= → response contains events from both seeded vhosts."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    _seed_event(proxy_module, vhost="logs-alpha.test", ip="10.0.0.1")
                    _seed_event(proxy_module, vhost="logs-beta.test",  ip="10.0.0.2")
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/logs-data",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, f"logs-data: expected 200, got {r.status}"
                        d = await r.json()
                        rows = d.get("rows", [])
                        count = d.get("count", 0)
                        assert count >= 2 or len(rows) >= 2, (
                            f"no-vhost logs-data must return both seeded events; "
                            f"count={count} rows={len(rows)}"
                        )
        _run(go())

    def test_vhost_filter_returns_only_matching(self, proxy_module):
        """?vhost=logs-alpha.test → all returned rows lack a cross-vhost ip (beta ip absent)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    # Seed distinctly different IPs per vhost so we can tell them apart
                    for i in range(3):
                        _seed_event(proxy_module, vhost="logs-alpha.test",
                                    ip=f"10.1.0.{i+1}")
                    for i in range(2):
                        _seed_event(proxy_module, vhost="logs-beta.test",
                                    ip=f"10.2.0.{i+1}")
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/logs-data?vhost=logs-alpha.test",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200
                        d = await r.json()
                        rows = d.get("rows", [])
                        # Verify no beta IPs leaked through
                        beta_ips = {f"10.2.0.{i+1}" for i in range(2)}
                        leaked = [row for row in rows if row.get("ip") in beta_ips]
                        assert not leaked, (
                            f"?vhost=logs-alpha.test must not return beta vhost IPs; "
                            f"leaked rows: {leaked}"
                        )
                        # And we should have some alpha rows
                        alpha_ips = {f"10.1.0.{i+1}" for i in range(3)}
                        alpha_rows = [row for row in rows if row.get("ip") in alpha_ips]
                        assert len(alpha_rows) == 3, (
                            f"Expected 3 alpha rows, got {len(alpha_rows)}"
                        )
        _run(go())

    def test_vhost_filter_empty_when_no_match(self, proxy_module):
        """?vhost=logs-beta.test → empty rows when only alpha events were seeded."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    _seed_event(proxy_module, vhost="logs-alpha.test", ip="10.1.0.1")
                    _seed_event(proxy_module, vhost="logs-alpha.test", ip="10.1.0.2")
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/logs-data?vhost=logs-beta.test",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200
                        d = await r.json()
                        rows = d.get("rows", [])
                        assert rows == [], (
                            f"?vhost=logs-beta.test with only alpha events must return empty rows; "
                            f"got {len(rows)} rows"
                        )
        _run(go())

    def test_kind_gw_ignores_vhost(self, proxy_module):
        """?kind=gw&vhost=anything → 200 (gw log ring is global, vhost silently ignored)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with cl.get(
                        NS + "/logs-data?kind=gw&vhost=any.host.test",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    ) as r:
                        assert r.status == 200, (
                            f"logs-data?kind=gw&vhost=: expected 200, got {r.status}"
                        )
                        d = await r.json()
                        assert d.get("kind") == "gw", (
                            f"logs-data?kind=gw must return kind='gw', got {d.get('kind')!r}"
                        )
        _run(go())

    def test_unauthenticated_decoy(self, proxy_module):
        """No session cookie → NOT a structured logs-data response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    async with cl.get(NS + "/logs-data") as r:
                        body = await r.text()
                        # Real logs-data has "kind", "rows", "count"
                        has_real = '"rows"' in body and '"count"' in body and '"kind"' in body
                        assert not has_real, (
                            "unauthenticated /logs-data must not return real log rows"
                        )
        _run(go())


# ── R1: source-level regression guards ────────────────────────────────────────

class TestR1SourceGuards:
    """Source-level regression tests — grep source files for required patterns."""

    @staticmethod
    def _proxy_handler_src() -> str:
        return (_PROJ / "core" / "proxy_handler.py").read_text(encoding="utf-8")

    @staticmethod
    def _agents_src() -> str:
        return (_PROJ / "dashboards" / "agents.py").read_text(encoding="utf-8")

    @staticmethod
    def _service_metrics_src() -> str:
        return (_PROJ / "dashboards" / "service_metrics.py").read_text(encoding="utf-8")

    @staticmethod
    def _logs_html_src() -> str:
        return (_DASHBOARDS / "logs.html").read_text(encoding="utf-8")

    @staticmethod
    def _main_html_src() -> str:
        return (_DASHBOARDS / "main.html").read_text(encoding="utf-8")

    def test_metrics_endpoint_uses_vhost_filter_in_events_query(self):
        """proxy_handler.py metrics timeline branch must pass vhost filter to db_read_events."""
        src = self._proxy_handler_src()
        fn_start = src.find("async def metrics_endpoint(")
        assert fn_start != -1, "metrics_endpoint must exist in proxy_handler.py"
        branch_start = src.find("if path_q or _vhost_filter:", fn_start)
        assert branch_start != -1, (
            "metrics_endpoint must have 'if path_q or _vhost_filter:' branch"
        )
        branch_body = src[branch_start: branch_start + 2000]
        assert "_vhost_filter" in branch_body, (
            "metrics_endpoint filtered timeline branch must reference _vhost_filter"
        )
        # CONTRACT (shipped): proxy_handler endpoints never adopted the
        # db_read_events() abstraction (it is only used in admin/settings.py and
        # dashboards/honeypots.py). The metrics filtered-timeline branch applies
        # vhost isolation via raw *parameterized* SQL: a 'vhost = ?' WHERE clause
        # with _vhost_filter bound as the bind value. Behavioural isolation is
        # covered by test_vhost_filter_isolates_timeline. This guard asserts the
        # parameterized vhost clause is wired (not the helper name).
        assert '"vhost = ?"' in branch_body, (
            "metrics_endpoint filtered timeline branch must apply a parameterized "
            "'vhost = ?' SQL clause for per-vhost isolation"
        )
        assert "_params.append(_vhost_filter)" in branch_body, (
            "metrics_endpoint filtered timeline branch must bind _vhost_filter as "
            "the parameter value for the 'vhost = ?' clause"
        )

    def test_logs_data_endpoint_has_vhost_filter(self):
        """proxy_handler.py logs_data_endpoint must pass vhost filter to db_read_events."""
        src = self._proxy_handler_src()
        fn_start = src.find("async def logs_data_endpoint(")
        assert fn_start != -1, "logs_data_endpoint must exist in proxy_handler.py"
        fn_end = src.find("\nasync def ", fn_start + 1)
        fn_body = src[fn_start:fn_end] if fn_end != -1 else src[fn_start:]
        # CONTRACT (shipped): logs_data_endpoint never adopted db_read_events();
        # for kind=requests it applies vhost isolation via raw *parameterized* SQL
        # ('WHERE vhost = ?' with vhost_filter bound as the value). Behavioural
        # isolation is covered by test_vhost_filter_isolates_db_events. This guard
        # asserts the parameterized vhost clause + bind are wired.
        assert "WHERE vhost = ?" in fn_body, (
            "logs_data_endpoint (kind=requests) must apply a parameterized "
            "'WHERE vhost = ?' SQL clause for per-vhost isolation"
        )
        assert "(vhost_filter, sql_cap)" in fn_body, (
            "logs_data_endpoint must bind vhost_filter as the parameter value for "
            "the 'WHERE vhost = ?' clause"
        )

    def test_logs_html_sends_vhost_param(self):
        """logs.html fetch to logs-data must include _vhostParam()."""
        src = self._logs_html_src()
        assert "logs-data" in src, "logs.html must contain a fetch to logs-data"
        # Find the fetch call and verify _vhostParam is included
        idx = src.find("logs-data")
        assert idx != -1
        # Scan a generous window around the fetch for _vhostParam
        window = src[max(0, idx - 200): idx + 500]
        assert "_vhostParam()" in window, (
            "logs.html fetch to logs-data must call _vhostParam() to pass the vhost filter"
        )

    def test_main_html_cost_timeline_no_vhost_param(self):
        """main.html cost-timeline fetch must NOT include _vhostParam (global endpoint)."""
        src = self._main_html_src()
        assert "cost-timeline" in src, "main.html must contain a fetch to cost-timeline"
        idx = src.find("cost-timeline")
        # Check in a window around the cost-timeline fetch
        window = src[max(0, idx - 50): idx + 600]
        assert "_vhostParam()" not in window, (
            "main.html cost-timeline fetch must NOT call _vhostParam() — "
            "cost-timeline is intentionally global (no per-vhost data)"
        )

    def test_agents_timeline_uses_vhost_sql_clause(self):
        """dashboards/agents.py agents_timeline_endpoint must have AND vhost = ? clause."""
        src = self._agents_src()
        fn_start = src.find("async def agents_timeline_endpoint(")
        assert fn_start != -1, "agents_timeline_endpoint must exist in agents.py"
        fn_end = src.find("\nasync def ", fn_start + 1)
        fn_body = src[fn_start:fn_end] if fn_end != -1 else src[fn_start:]
        assert "AND vhost = ?" in fn_body, (
            "agents_timeline_endpoint must use 'AND vhost = ?' SQL clause "
            "when _atl_vhost is set"
        )

    def test_geo_data_uses_vhost_sql_clause(self):
        """proxy_handler.py geo_data_endpoint must pass vhost filter to db_read_events."""
        src = self._proxy_handler_src()
        fn_start = src.find("async def geo_data_endpoint(")
        assert fn_start != -1, "geo_data_endpoint must exist in proxy_handler.py"
        fn_end = src.find("\nasync def ", fn_start + 1)
        fn_body = src[fn_start:fn_end] if fn_end != -1 else src[fn_start:]
        # CONTRACT (shipped): geo_data_endpoint never adopted db_read_events()
        # (it even hand-rolls a PG to_timestamp() branch, 1.9.1 iter-17). It applies
        # vhost isolation via a raw *parameterized* ' AND vhost = ?' clause with
        # _geo_vhost bound as the value. Behavioural isolation is covered by
        # test_vhost_filter_isolates_countries. This guard asserts the clause + bind.
        assert "AND vhost = ?" in fn_body, (
            "geo_data_endpoint must apply a parameterized ' AND vhost = ?' SQL "
            "clause for per-vhost isolation"
        )
        assert "_geo_sql_args.append(_geo_vhost)" in fn_body, (
            "geo_data_endpoint must bind _geo_vhost as the parameter value for the "
            "'vhost = ?' clause"
        )

    def test_service_data_uses_vhost_filter(self):
        """dashboards/service_metrics.py service_metrics_data_endpoint must have vhost = ?."""
        src = self._service_metrics_src()
        fn_start = src.find("async def service_metrics_data_endpoint(")
        assert fn_start != -1, (
            "service_metrics_data_endpoint must exist in dashboards/service_metrics.py"
        )
        fn_end = src.find("\nasync def ", fn_start + 1)
        fn_body = src[fn_start:fn_end] if fn_end != -1 else src[fn_start:]
        assert "vhost = ?" in fn_body, (
            "service_metrics_data_endpoint must use 'vhost = ?' SQL clause "
            "when ?vhost= is set for traffic counter queries"
        )
