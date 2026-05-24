"""
QA tests for v1.8.1 — Vhost comparison endpoints and dashboards

Coverage matrix
───────────────
U1   vhost_stats_endpoint — response schema contract
U2   vhost_stats_endpoint — empty DB → empty stats list
U3   vhost_stats_endpoint — 1h / 24h window bucketing
U4   vhost_stats_endpoint — allowed vs blocked reason classification
U5   vhost_stats_endpoint — operator-passthrough / internal-probe excluded from blocked
U6   vhost_stats_endpoint — events with empty vhost excluded
U7   vhost_stats_endpoint — ban counts from clients.ban_level
U8   vhost_stats_endpoint — events older than 24h excluded from all windows

U9   vhost_breakdown_endpoint — response schema contract
U10  vhost_breakdown_endpoint — empty DB → empty datasets
U11  vhost_breakdown_endpoint — slot arithmetic (events land in correct bucket)
U12  vhost_breakdown_endpoint — multiple vhost datasets isolated
U13  vhost_breakdown_endpoint — empty vhost events excluded from breakdown

U14  vhost_policy_data_endpoint — response schema contract
U15  vhost_policy_data_endpoint — ?hostname= with no match → empty overrides
U16  vhost_policy_data_endpoint — ?hostname= with configured vhost → returns overrides
U17  vhost_policy_data_endpoint — vhost_knobs list is non-empty and sorted

F1   GET /vhost-stats — unauthenticated returns 403/redirect
F2   GET /vhost-stats — authenticated returns 200 + JSON
F3   GET /vhost-stats — Cache-Control: no-store present
F4   GET /vhost-stats — seeded events aggregate by vhost correctly
F5   GET /vhost-stats — two vhosts produce two rows, sorted by total_1h DESC

F6   GET /vhost-breakdown — unauthenticated returns 403/redirect
F7   GET /vhost-breakdown — authenticated returns 200 + JSON
F8   GET /vhost-breakdown — Cache-Control: no-store present
F9   GET /vhost-breakdown — seeded events produce correct per-vhost dataset data
F10  GET /vhost-breakdown — labels array length matches n_slots calculation
F11  GET /vhost-breakdown — ?range=60&bucket=60 → small window honoured
F12  GET /vhost-breakdown — invalid range/bucket params → 400

F13  GET /vhost-policy — unauthenticated returns 403/redirect
F14  GET /vhost-policy — authenticated returns 200 + HTML
F15  GET /vhost-policy-data — unauthenticated returns 403/redirect
F16  GET /vhost-policy-data — authenticated returns 200 + JSON with all keys
F17  GET /vhost-policy-data — Cache-Control: no-store present

R1   /vhosts GET still works after adding new endpoints (regression)
R2   /vhost-stats POST/DELETE → 405 (only GET allowed)
R3   vhost_breakdown bucket clamped to 60s minimum
R4   vhost_stats_endpoint ts field is a recent unix timestamp
R5   vhost_breakdown end param accepted
"""
import asyncio
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# ── Helpers ───────────────────────────────────────────────────────────────────

NS = "/antibot-appsec-gateway/secured"

DASHBOARDS = Path(__file__).resolve().parent.parent / "dashboards"


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


def _wipe_events(proxy_module):
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()
    # clear in-memory ip_state so ban counts from prior tests don't leak
    import state as _st
    _st.ip_state.clear()


def _seed_events(proxy_module, rows):
    """Insert (ts, ip, ua, path, method, status, reason, vhost) rows."""
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.executemany(
        "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
        "VALUES (?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()


def _seed_banned_client(proxy_module, ip, vhost, ban_level=1):
    """Inject a banned identity into in-memory ip_state (where vhost_stats reads bans from)."""
    import state as _st
    from state import IpState
    s = _st.ip_state.setdefault(ip, IpState())
    if ban_level > 0:
        s.banned_until = time.time() + 3600  # banned for 1 more hour
    else:
        s.banned_until = 0.0
    s.last_vhost = vhost


# ── U1–U8: vhost_stats_endpoint unit tests ───────────────────────────────────

class TestU1VhostStatsSchema:
    """vhost_stats_endpoint returns correct top-level schema."""

    def test_response_has_stats_and_ts_keys(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"vhost-stats: expected 200, got {r.status}"
                    d = await r.json()
                    assert "stats" in d, "vhost-stats: response must have 'stats' key"
                    assert "ts" in d,    "vhost-stats: response must have 'ts' key"
                    assert isinstance(d["stats"], list), "'stats' must be a list"
                    assert isinstance(d["ts"], int), "'ts' must be an integer"
        _run(go())

    def test_stats_row_has_required_fields(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 10, "1.1.1.1", "UA", "/", "GET", 200, "ok", "alpha.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["stats"], "stats list must be non-empty after seeding"
                    row = d["stats"][0]
                    for field in ("hostname", "total_1h", "allowed_1h", "blocked_1h",
                                  "total_24h", "blocked_24h", "bans"):
                        assert field in row, f"stats row missing field '{field}'"
        _run(go())


class TestU2VhostStatsEmptyDB:
    def test_empty_db_returns_empty_stats(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["stats"] == [], "empty DB must return empty stats list"
        _run(go())


class TestU3VhostStatsWindows:
    """Events in different time windows land in the right counters."""

    def test_recent_event_counted_in_both_1h_and_24h(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    # event 30 minutes ago — inside both 1h and 24h windows
                    _seed_events(proxy_module, [
                        (now - 1800, "1.1.1.1", "UA", "/", "GET", 200, "ok", "alpha.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "alpha.test"), None)
                    assert row is not None
                    assert row["total_1h"] == 1,  "event at 30min ago must appear in total_1h"
                    assert row["total_24h"] == 1, "event at 30min ago must appear in total_24h"
        _run(go())

    def test_event_between_1h_and_24h_only_in_24h(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    # event 4 hours ago — outside 1h, inside 24h
                    _seed_events(proxy_module, [
                        (now - 4 * 3600, "2.2.2.2", "UA", "/", "GET", 200, "ok", "beta.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "beta.test"), None)
                    assert row is not None
                    assert row["total_1h"] == 0,  "event at 4h ago must NOT appear in total_1h"
                    assert row["total_24h"] == 1, "event at 4h ago must appear in total_24h"
        _run(go())

    def test_event_older_than_24h_excluded_from_all_windows(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    # event 30 hours ago — outside both windows
                    _seed_events(proxy_module, [
                        (now - 30 * 3600, "3.3.3.3", "UA", "/", "GET", 200, "ok", "gamma.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "gamma.test"), None)
                    assert row is None, "event older than 24h must not produce a stats row"
        _run(go())


class TestU4VhostStatsReasonClassification:
    """allowed vs blocked reason classification matches the gateway contract."""

    _ALLOWED_REASONS  = ("ok", "allowed", "authorized-robot")
    _EXCLUDED_REASONS = ("operator-passthrough", "internal-probe")
    _BLOCKED_REASONS  = ("ua-blocked", "honeypot", "rate-limit", "behavior", "sqli", "xss")

    def test_allowed_reasons_count_as_allowed(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    rows = [(now - 60, f"1.1.1.{i}", "UA", "/", "GET", 200, reason, "site.test")
                            for i, reason in enumerate(self._ALLOWED_REASONS)]
                    _seed_events(proxy_module, rows)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "site.test"), None)
                    assert row is not None
                    assert row["allowed_1h"] == len(self._ALLOWED_REASONS), (
                        f"Expected {len(self._ALLOWED_REASONS)} allowed, got {row['allowed_1h']}"
                    )
                    assert row["blocked_1h"] == 0, "allowed reasons must not count as blocked"
        _run(go())

    def test_blocked_reasons_count_as_blocked(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    rows = [(now - 60, f"2.2.2.{i}", "UA", "/", "GET", 403, reason, "blocked.test")
                            for i, reason in enumerate(self._BLOCKED_REASONS)]
                    _seed_events(proxy_module, rows)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "blocked.test"), None)
                    assert row is not None
                    assert row["blocked_1h"] == len(self._BLOCKED_REASONS), (
                        f"Expected {len(self._BLOCKED_REASONS)} blocked, got {row['blocked_1h']}"
                    )
        _run(go())


class TestU5VhostStatsExcludedReasons:
    """operator-passthrough and internal-probe must not appear in blocked count."""

    def test_excluded_reasons_not_in_blocked_count(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 60, "10.0.0.1", "UA", "/", "GET", 200, "operator-passthrough", "pass.test"),
                        (now - 60, "10.0.0.2", "UA", "/", "GET", 200, "internal-probe",        "pass.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "pass.test"), None)
                    assert row is not None
                    assert row["blocked_1h"] == 0, (
                        "operator-passthrough and internal-probe must not count as blocked"
                    )
        _run(go())


class TestU6VhostStatsEmptyVhostExcluded:
    """Events with empty vhost string must not appear in stats."""

    def test_empty_vhost_events_excluded(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 60, "5.5.5.5", "UA", "/", "GET", 200, "ok", ""),  # empty vhost
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["stats"] == [], "events with empty vhost must be excluded from stats"
        _run(go())


class TestU7VhostStatsBanCounts:
    """bans field counts clients with ban_level > 0 whose last_vhost matches."""

    def test_banned_client_counted_in_bans(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 60, "6.6.6.6", "UA", "/", "GET", 403, "ua-blocked", "ban.test"),
                    ])
                    _seed_banned_client(proxy_module, "6.6.6.6", "ban.test", ban_level=1)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "ban.test"), None)
                    assert row is not None
                    assert row["bans"] == 1, f"Expected bans=1, got {row['bans']}"
        _run(go())

    def test_unban_level_zero_not_counted(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 60, "7.7.7.7", "UA", "/", "GET", 200, "ok", "noban.test"),
                    ])
                    _seed_banned_client(proxy_module, "7.7.7.7", "noban.test", ban_level=0)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "noban.test"), None)
                    if row:
                        assert row["bans"] == 0, "ban_level=0 must not increment bans counter"
        _run(go())


class TestU8VhostStatsOldEventExcluded:
    """Events older than 24 h must be fully invisible to vhost-stats."""

    def test_stale_events_produce_no_row(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 25 * 3600, "8.8.8.8", "UA", "/", "GET", 200, "ok", "old.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "old.test"), None)
                    assert row is None, "event older than 24h must not appear in stats output"
        _run(go())


# ── U9–U13: vhost_breakdown_endpoint unit tests ──────────────────────────────

class TestU9VhostBreakdownSchema:
    def test_response_has_required_keys(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"vhost-breakdown: expected 200, got {r.status}"
                    d = await r.json()
                    for key in ("labels", "datasets", "bucket"):
                        assert key in d, f"vhost-breakdown: response missing key '{key}'"
                    assert isinstance(d["labels"],   list), "'labels' must be a list"
                    assert isinstance(d["datasets"], list), "'datasets' must be a list"
                    assert isinstance(d["bucket"],   int),  "'bucket' must be an int"
        _run(go())

    def test_dataset_items_have_vhost_and_data_keys(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 30, "1.1.1.1", "UA", "/", "GET", 200, "ok", "ds.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown?range=1&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["datasets"], "datasets must be non-empty after seeding"
                    item = d["datasets"][0]
                    assert "vhost" in item, "dataset item must have 'vhost' key"
                    assert "data"  in item, "dataset item must have 'data' key"
                    assert isinstance(item["data"], list), "'data' must be a list"
        _run(go())


class TestU10VhostBreakdownEmptyDB:
    def test_empty_db_returns_empty_datasets(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["datasets"] == [], "empty DB must return empty datasets"
        _run(go())


class TestU11VhostBreakdownSlotArithmetic:
    """Events land in the correct time slot."""

    def test_event_counted_in_correct_slot(self, proxy_module):
        bucket = 300   # 5 min
        range_min = 30
        now = time.time()
        # Event exactly 2 buckets ago (at start_ts + 1.5 * bucket → slot 1)
        event_ts = now - range_min * 60 + bucket * 1.5
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (event_ts, "9.9.9.9", "UA", "/", "GET", 200, "ok", "slot.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(
                        NS + f"/vhost-breakdown?range={range_min}&bucket={bucket}&end={now:.0f}",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    ds = next((x for x in d["datasets"] if x["vhost"] == "slot.test"), None)
                    assert ds is not None, "slot.test must appear in datasets"
                    total = sum(ds["data"])
                    assert total == 1, f"Expected 1 event total in dataset, got {total}"
                    # slot 1 (second bucket) must be the non-zero one
                    assert ds["data"][1] == 1, (
                        f"Event must land in slot 1; data={ds['data'][:5]}"
                    )
        _run(go())


class TestU12VhostBreakdownIsolation:
    """Each vhost gets its own isolated dataset."""

    def test_two_vhosts_produce_two_datasets(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 60, "1.1.1.1", "UA", "/", "GET", 200, "ok", "alpha.test"),
                        (now - 60, "2.2.2.2", "UA", "/", "GET", 200, "ok", "beta.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown?range=5&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    vhosts = {ds["vhost"] for ds in d["datasets"]}
                    assert "alpha.test" in vhosts, "alpha.test must produce a dataset"
                    assert "beta.test"  in vhosts, "beta.test must produce a dataset"

                    # Check isolation: alpha data must not include beta events
                    alpha_ds = next(x for x in d["datasets"] if x["vhost"] == "alpha.test")
                    beta_ds  = next(x for x in d["datasets"] if x["vhost"] == "beta.test")
                    assert sum(alpha_ds["data"]) == 1, "alpha dataset must contain exactly 1 event"
                    assert sum(beta_ds["data"])  == 1, "beta dataset must contain exactly 1 event"
        _run(go())


class TestU13VhostBreakdownEmptyVhostExcluded:
    def test_empty_vhost_events_not_in_datasets(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 60, "5.5.5.5", "UA", "/", "GET", 200, "ok", ""),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown?range=5&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["datasets"] == [], "empty-vhost events must not appear in datasets"
        _run(go())


# ── U14–U17: vhost_policy_data_endpoint unit tests ───────────────────────────

class TestU14VhostPolicyDataSchema:
    def test_response_has_required_keys(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"vhost-policy-data: expected 200, got {r.status}"
                    d = await r.json()
                    for key in ("hostname", "vhost_knobs", "overrides", "global", "vhosts"):
                        assert key in d, f"vhost-policy-data: missing key '{key}'"
        _run(go())


class TestU15VhostPolicyDataNoMatch:
    def test_unknown_hostname_returns_empty_overrides(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(
                        NS + "/vhost-policy-data?hostname=nonexistent.invalid",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d["overrides"] == {}, (
                        "unknown hostname must return empty overrides dict"
                    )
                    assert d["hostname"] == "nonexistent.invalid", (
                        "hostname echo must match the requested hostname"
                    )
        _run(go())


class TestU16VhostPolicyDataWithVhost:
    def test_configured_vhost_overrides_present(self, proxy_module):
        from unittest.mock import patch as _patch
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    # Add a vhost entry with a known override
                    import vhost as _v
                    _v.VHOSTS["policy.test"] = {
                        "hostname": "policy.test",
                        "UPSTREAM": up,
                        "UA_FILTER_ENABLED": False,
                    }
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(
                        NS + "/vhost-policy-data?hostname=policy.test",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert "UA_FILTER_ENABLED" in d["overrides"], (
                        "UA_FILTER_ENABLED override must appear in overrides"
                    )
                    assert d["overrides"]["UA_FILTER_ENABLED"] is False
                    _v.VHOSTS.pop("policy.test", None)
        _run(go())


class TestU17VhostPolicyDataKnobList:
    def test_vhost_knobs_is_non_empty_sorted_list(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    knobs = d["vhost_knobs"]
                    assert isinstance(knobs, list), "vhost_knobs must be a list"
                    assert len(knobs) > 0, "vhost_knobs must not be empty"
                    assert knobs == sorted(knobs), "vhost_knobs must be sorted alphabetically"
        _run(go())


# ── F1–F5: GET /vhost-stats functional tests ─────────────────────────────────

class TestF1F5VhostStatsEndpoint:

    def test_f1_unauthenticated_decoy(self, proxy_module):
        """Unauthenticated requests must receive a decoy (no admin data leaked).
        The proxy never returns 401/403 — it mirrors the upstream 404 silently."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/vhost-stats")
                    body = await r.text()
                    assert '"stats"' not in body or '"vhosts"' in body, (
                        "unauthenticated /vhost-stats must not return real admin data"
                    )
                    assert '"ts"' not in body or "hostname" not in body, (
                        "unauthenticated /vhost-stats must not leak per-vhost stats"
                    )
        _run(go())

    def test_f2_authenticated_returns_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"authenticated vhost-stats must return 200, got {r.status}"
        _run(go())

    def test_f3_cache_control_no_store(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, (
                        f"vhost-stats must return Cache-Control: no-store; got '{cc}'"
                    )
        _run(go())

    def test_f4_seeded_events_aggregate_correctly(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 60, "1.1.1.1", "UA", "/", "GET", 200, "ok",         "agg.test"),
                        (now - 60, "1.1.1.2", "UA", "/", "GET", 200, "ok",         "agg.test"),
                        (now - 60, "1.1.1.3", "UA", "/", "GET", 403, "ua-blocked", "agg.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    row = next((x for x in d["stats"] if x["hostname"] == "agg.test"), None)
                    assert row is not None
                    assert row["total_1h"]   == 3, f"total_1h wrong: {row}"
                    assert row["allowed_1h"] == 2, f"allowed_1h wrong: {row}"
                    assert row["blocked_1h"] == 1, f"blocked_1h wrong: {row}"
        _run(go())

    def test_f5_two_vhosts_sorted_by_total_1h_desc(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    # busy.test gets 5 events, quiet.test gets 1
                    _seed_events(proxy_module,
                        [(now - 60, f"1.1.1.{i}", "UA", "/", "GET", 200, "ok", "busy.test")
                         for i in range(5)] +
                        [(now - 60, "9.9.9.9", "UA", "/", "GET", 200, "ok", "quiet.test")]
                    )
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    rows = [x for x in d["stats"] if x["hostname"] in ("busy.test", "quiet.test")]
                    assert len(rows) == 2, f"Both vhosts must appear in stats; got {[x['hostname'] for x in d['stats']]}"
                    assert rows[0]["hostname"] == "busy.test", (
                        "Stats must be sorted by total_1h DESC: busy.test must be first"
                    )
        _run(go())


# ── F6–F12: GET /vhost-breakdown functional tests ────────────────────────────

class TestF6F12VhostBreakdownEndpoint:

    def test_f6_unauthenticated_decoy(self, proxy_module):
        """Unauthenticated requests must receive a decoy — no admin data leaked."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/vhost-breakdown")
                    body = await r.text()
                    assert '"datasets"' not in body, (
                        "unauthenticated /vhost-breakdown must not return real admin data"
                    )
        _run(go())

    def test_f7_authenticated_returns_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, (
                        f"authenticated vhost-breakdown must return 200, got {r.status}"
                    )
        _run(go())

    def test_f8_cache_control_no_store(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, (
                        f"vhost-breakdown must return Cache-Control: no-store; got '{cc}'"
                    )
        _run(go())

    def test_f9_seeded_events_in_correct_dataset(self, proxy_module):
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now - 30, "1.1.1.1", "UA", "/", "GET", 200, "ok", "bd.test"),
                        (now - 30, "1.1.1.2", "UA", "/", "GET", 200, "ok", "bd.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown?range=1&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    ds = next((x for x in d["datasets"] if x["vhost"] == "bd.test"), None)
                    assert ds is not None, "bd.test must appear in datasets"
                    assert sum(ds["data"]) == 2, (
                        f"Expected 2 events in bd.test dataset, got {sum(ds['data'])}"
                    )
        _run(go())

    def test_f10_labels_length_matches_range_and_bucket(self, proxy_module):
        range_min, bucket = 10, 60
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(
                        NS + f"/vhost-breakdown?range={range_min}&bucket={bucket}",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    expected_slots = range_min * 60 // bucket  # 10
                    assert len(d["labels"]) == expected_slots, (
                        f"labels length must equal range_min*60/bucket={expected_slots}, "
                        f"got {len(d['labels'])}"
                    )
        _run(go())

    def test_f11_small_range_window_honoured(self, proxy_module):
        """Events outside the requested window must not appear in results."""
        now = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    # Event 2 minutes ago — outside 1-minute window
                    _seed_events(proxy_module, [
                        (now - 120, "2.2.2.2", "UA", "/", "GET", 200, "ok", "window.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(
                        NS + "/vhost-breakdown?range=1&bucket=60",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    ds = next((x for x in d["datasets"] if x["vhost"] == "window.test"), None)
                    if ds is not None:
                        assert sum(ds["data"]) == 0, (
                            "Event outside the requested range window must not appear in data"
                        )
        _run(go())

    def test_f12_invalid_range_param_returns_400(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown?range=abc&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 400, (
                        f"invalid 'range' param must return 400, got {r.status}"
                    )
        _run(go())


# ── F13–F17: vhost_policy endpoints ──────────────────────────────────────────

class TestF13F17VhostPolicyEndpoints:

    def test_f13_vhost_policy_page_unauthenticated_decoy(self, proxy_module):
        """Unauthenticated requests to vhost-policy must receive a decoy."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/vhost-policy")
                    body = await r.text()
                    assert "AppSecGW" not in body or "Vhost Policy" not in body, (
                        "unauthenticated /vhost-policy must not serve the admin dashboard"
                    )
        _run(go())

    def test_f14_vhost_policy_page_authenticated_returns_html(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, (
                        f"authenticated vhost-policy must return 200, got {r.status}"
                    )
                    ct = r.headers.get("Content-Type", "")
                    assert "text/html" in ct, (
                        f"vhost-policy must return HTML; got Content-Type: {ct}"
                    )
        _run(go())

    def test_f15_vhost_policy_data_unauthenticated_decoy(self, proxy_module):
        """Unauthenticated requests to vhost-policy-data must receive a decoy."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/vhost-policy-data")
                    body = await r.text()
                    assert '"vhost_knobs"' not in body, (
                        "unauthenticated /vhost-policy-data must not leak knob list"
                    )
        _run(go())

    def test_f16_vhost_policy_data_authenticated_returns_all_keys(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    for key in ("hostname", "vhost_knobs", "overrides", "global", "vhosts"):
                        assert key in d, f"vhost-policy-data must return '{key}'"
        _run(go())

    def test_f17_vhost_policy_data_cache_control_no_store(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-policy-data",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, (
                        f"vhost-policy-data must set Cache-Control: no-store; got '{cc}'"
                    )
        _run(go())


# ── R-series: Regression tests ────────────────────────────────────────────────

class TestRegressions:

    def test_r1_vhosts_get_still_works_after_new_endpoints(self, proxy_module):
        """Adding /vhost-stats and /vhost-breakdown must not break /vhosts GET."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhosts",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, (
                        f"/vhosts regression: expected 200, got {r.status}"
                    )
                    d = await r.json()
                    assert "vhosts" in d, "/vhosts must still return 'vhosts' key"
        _run(go())

    def test_r2_vhost_stats_post_not_allowed(self, proxy_module):
        """vhost-stats is read-only — authenticated POST must return 405."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/vhost-stats", json={},
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    # 405 from aiohttp router (GET-only route); or 404/200 decoy if
                    # the route is not registered at all — either way NOT real admin data.
                    body = await r.text()
                    if r.status == 200:
                        # Verify no admin stats data leaked (decoy or empty response)
                        assert '"stats"' not in body or '"hostname"' not in body, (
                            "authenticated POST /vhost-stats must not return vhost stats data"
                        )
                    else:
                        assert r.status in (405, 404), (
                            f"authenticated POST /vhost-stats must return 405 or 404, got {r.status}"
                        )
        _run(go())

    def test_r3_vhost_breakdown_bucket_min_60(self, proxy_module):
        """bucket < 60 must be clamped to 60 (not produce an error or 0-division)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(
                        NS + "/vhost-breakdown?range=1&bucket=1",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200, (
                        f"bucket=1 (clamped to 60) must not cause a 5xx; got {r.status}"
                    )
                    d = await r.json()
                    assert d["bucket"] == 60, (
                        f"bucket must be clamped to 60 when requested value is < 60; got {d['bucket']}"
                    )
        _run(go())

    def test_r4_vhost_stats_ts_field_is_recent(self, proxy_module):
        """ts in vhost-stats response must be within 5 seconds of now."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    t_before = time.time()
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    t_after = time.time()
                    d = await r.json()
                    assert t_before - 5 <= d["ts"] <= t_after + 5, (
                        f"ts={d['ts']} is not within 5s of request time [{t_before:.0f}–{t_after:.0f}]"
                    )
        _run(go())

    def test_r5_vhost_breakdown_end_param_accepted(self, proxy_module):
        """?end= query param must be accepted without error."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    end = int(time.time())
                    r = await c.get(
                        NS + f"/vhost-breakdown?range=5&bucket=60&end={end}",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200, (
                        f"?end= param must be accepted; got {r.status}"
                    )
        _run(go())

    def test_r6_vhost_breakdown_labels_are_unix_timestamps(self, proxy_module):
        """labels must be unix timestamps (integers near current time - range)."""
        now = int(time.time())
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-breakdown?range=10&bucket=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    labels = d["labels"]
                    assert labels, "labels must be non-empty"
                    for lbl in labels:
                        assert isinstance(lbl, int), f"label {lbl!r} must be int (unix ts)"
                        assert now - 700 < lbl < now + 60, (
                            f"label {lbl} is not a plausible unix timestamp near now"
                        )
        _run(go())

    def test_r7_vhost_breakdown_post_not_allowed(self, proxy_module):
        """vhost-breakdown is read-only — authenticated POST must return 405 or decoy."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.post(NS + "/vhost-breakdown", json={},
                                     cookies={proxy_module._SESSION_COOKIE: cookie})
                    body = await r.text()
                    if r.status == 200:
                        assert '"datasets"' not in body, (
                            "authenticated POST /vhost-breakdown must not return breakdown data"
                        )
                    else:
                        assert r.status in (405, 404), (
                            f"authenticated POST /vhost-breakdown must return 405 or 404, got {r.status}"
                        )
        _run(go())


# ── GET /config?vhost=X — per-vhost effective config ─────────────────────────

class TestConfigVhostParam:
    """GET /config?vhost=X returns merged effective config for the named vhost."""

    def test_config_global_includes_vhosts_list(self, proxy_module):
        """GET /config with no vhost param must include a 'vhosts' list in response."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/config",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert "state" in d, "/config must include 'state' key"
                    assert "vhosts" in d, "/config must include 'vhosts' list for selector"
                    assert isinstance(d["vhosts"], list), "'vhosts' must be a list"
                    assert "overridden" in d, "/config must include 'overridden' key"
                    assert d["overridden"] == [], "global /config must have empty overridden list"
        _run(go())

    def test_config_vhost_unknown_returns_base_state(self, proxy_module):
        """GET /config?vhost=unknown returns base global state with empty overridden."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/config?vhost=nonexistent.invalid",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()
                    assert d["vhost"] == "nonexistent.invalid", "vhost echo must match request"
                    assert d["overridden"] == [], "unknown vhost must have empty overridden list"
                    assert "state" in d
        _run(go())

    def test_config_vhost_known_returns_merged_state(self, proxy_module):
        """GET /config?vhost=X applies vhost overrides on top of global state."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import vhost as _v
                    _v.VHOSTS["cmptest.internal"] = {
                        "UA_FILTER_ENABLED": False,
                        "UPSTREAM": up,
                    }
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        r = await c.get(NS + "/config?vhost=cmptest.internal",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        assert r.status == 200
                        d = await r.json()
                        assert d["vhost"] == "cmptest.internal"
                        assert "UA_FILTER_ENABLED" in d["overridden"], (
                            "UA_FILTER_ENABLED must appear in 'overridden' list"
                        )
                        assert d["state"].get("UA_FILTER_ENABLED") is False, (
                            "vhost override UA_FILTER_ENABLED=False must be reflected in merged state"
                        )
                    finally:
                        _v.VHOSTS.pop("cmptest.internal", None)
        _run(go())

    def test_config_vhost_overridden_keys_sorted(self, proxy_module):
        """'overridden' list must be sorted alphabetically."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import vhost as _v
                    _v.VHOSTS["sorted.internal"] = {
                        "UA_FILTER_ENABLED": False,
                        "JS_CHALLENGE": True,
                        "UPSTREAM": up,
                    }
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        r = await c.get(NS + "/config?vhost=sorted.internal",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        ov = d["overridden"]
                        assert ov == sorted(ov), (
                            f"'overridden' must be sorted alphabetically; got {ov}"
                        )
                    finally:
                        _v.VHOSTS.pop("sorted.internal", None)
        _run(go())

    def test_config_vhost_cache_control_no_store(self, proxy_module):
        """GET /config?vhost=X must set Cache-Control: no-store."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/config?vhost=any.test",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, (
                        f"GET /config?vhost=X must set Cache-Control: no-store; got '{cc}'"
                    )
        _run(go())

    def test_controls_html_has_vhost_scope_bar(self):
        """controls.html must include the vhost scope bar with selector and badge."""
        src = (DASHBOARDS / "controls.html").read_text()
        assert 'id="vhost-scope-bar"' in src, \
            "controls.html must have #vhost-scope-bar element"
        assert 'id="vhost-sel"' in src, \
            "controls.html must have #vhost-sel select element"
        assert 'id="vhost-ov-badge"' in src, \
            "controls.html must have #vhost-ov-badge span element"
        assert 'vhost-policy-lnk' in src, \
            "controls.html must have vhost-policy link"

    def test_controls_html_load_fetches_vhost_param(self):
        """load() in controls.html must build URL with ?vhost= when a vhost is selected."""
        src = (DASHBOARDS / "controls.html").read_text()
        load_idx = src.find("async function load()")
        assert load_idx != -1
        # Search within a generous window of the function
        load_body = src[load_idx: load_idx + 4000]
        assert "?vhost=" in load_body or "vhost=" in load_body, (
            "load() must include ?vhost= query param when vhost is selected"
        )
        assert "overriddenKnobs" in load_body, (
            "load() must update overriddenKnobs from body.overridden"
        )
        assert "vhost-ov" in load_body, (
            "load() must apply .vhost-ov CSS class to overridden ctrl elements"
        )


# ── TV: topbar vhost-select overlap fix tests ────────────────────────────────
#
# Coverage matrix
# ───────────────
# TV1  main.html: #vhost-select lives inside #topbar-right (not a standalone element)
# TV2  main.html: #gw-status-pill is inside #topbar-right (not position:fixed)
# TV3  main.html: #gw-loglvl-wrap is inside #topbar-right (not position:fixed)
# TV4  main.html: #gw-status-pill CSS has no position:fixed
# TV5  main.html: #gw-loglvl-wrap CSS has no position:fixed
# TV6  main.html: #gw-status-pill id appears exactly once
# TV7  main.html: #gw-loglvl-wrap id appears exactly once
# TV8  main.html: #gw-loglvl id appears exactly once (no duplicate select)
# TV9  main.html: #vhost-select has max-width to prevent topbar stretch
# TV10 main.html: #topbar-right contains all three controls in document order

class TestTVTopbarVhostOverlap:
    """QA for the vhost-select / fixed-pill overlap fix in main.html."""

    def test_tv1_vhost_select_inside_topbar_right(self):
        """#vhost-select must be a descendant of #topbar-right."""
        src = (DASHBOARDS / "main.html").read_text()
        tr_idx = src.find('id="topbar-right"')
        assert tr_idx != -1, "main.html must have #topbar-right element"
        # Find the closing tag of topbar-right by scanning for the next </div> at same depth
        after = src[tr_idx:]
        vs_idx = after.find('id="vhost-select"')
        assert vs_idx != -1, (
            "#vhost-select must be inside #topbar-right — "
            "placing it elsewhere causes overlap with the fixed status/loglvl pills"
        )
        # vhost-select must come before the closing of topbar-right
        # (simplest proxy: its position in the after-slice is before any sibling div)
        assert vs_idx < after.find('id="gw-status-pill"') or \
               after.find('id="gw-status-pill"') == -1, (
            "#vhost-select must appear before #gw-status-pill in #topbar-right"
        )

    def test_tv2_gw_status_pill_inside_topbar_right(self):
        """#gw-status-pill must be inside #topbar-right, not a free body element."""
        src = (DASHBOARDS / "main.html").read_text()
        tr_idx = src.find('id="topbar-right"')
        assert tr_idx != -1
        after_tr = src[tr_idx: tr_idx + 2000]
        assert 'id="gw-status-pill"' in after_tr, (
            "#gw-status-pill must be inside #topbar-right — "
            "a free body element with position:fixed overlaps #vhost-select"
        )

    def test_tv3_gw_loglvl_wrap_inside_topbar_right(self):
        """#gw-loglvl-wrap must be inside #topbar-right, not a free body element."""
        src = (DASHBOARDS / "main.html").read_text()
        tr_idx = src.find('id="topbar-right"')
        assert tr_idx != -1
        after_tr = src[tr_idx: tr_idx + 2000]
        assert 'id="gw-loglvl-wrap"' in after_tr, (
            "#gw-loglvl-wrap must be inside #topbar-right — "
            "a free body element with position:fixed overlaps #vhost-select"
        )

    def test_tv4_gw_status_pill_not_position_fixed(self):
        """#gw-status-pill CSS must not use position:fixed."""
        src = (DASHBOARDS / "main.html").read_text()
        # Find the CSS rule for gw-status-pill
        css_idx = src.find('#gw-status-pill{')
        if css_idx == -1:
            css_idx = src.find('#gw-status-pill {')
        assert css_idx != -1, "main.html must have a #gw-status-pill CSS rule"
        rule = src[css_idx: css_idx + 300]
        assert 'position:fixed' not in rule and 'position: fixed' not in rule, (
            "#gw-status-pill CSS must not use position:fixed — "
            "fixed positioning causes it to overlap #vhost-select in the topbar"
        )

    def test_tv5_gw_loglvl_wrap_not_position_fixed(self):
        """#gw-loglvl-wrap CSS must not use position:fixed."""
        src = (DASHBOARDS / "main.html").read_text()
        css_idx = src.find('#gw-loglvl-wrap{')
        if css_idx == -1:
            css_idx = src.find('#gw-loglvl-wrap {')
        assert css_idx != -1, "main.html must have a #gw-loglvl-wrap CSS rule"
        rule = src[css_idx: css_idx + 300]
        assert 'position:fixed' not in rule and 'position: fixed' not in rule, (
            "#gw-loglvl-wrap CSS must not use position:fixed — "
            "fixed positioning causes it to overlap #vhost-select in the topbar"
        )

    def test_tv6_gw_status_pill_id_unique(self):
        """#gw-status-pill id must appear exactly once (no duplicate after move)."""
        src = (DASHBOARDS / "main.html").read_text()
        count = src.count('id="gw-status-pill"')
        assert count == 1, (
            f'id="gw-status-pill" appears {count} times; must be exactly 1'
        )

    def test_tv7_gw_loglvl_wrap_id_unique(self):
        """#gw-loglvl-wrap id must appear exactly once (no duplicate after move)."""
        src = (DASHBOARDS / "main.html").read_text()
        count = src.count('id="gw-loglvl-wrap"')
        assert count == 1, (
            f'id="gw-loglvl-wrap" appears {count} times; must be exactly 1'
        )

    def test_tv8_gw_loglvl_select_id_unique(self):
        """#gw-loglvl select id must appear exactly once (no duplicate element)."""
        src = (DASHBOARDS / "main.html").read_text()
        count = src.count('id="gw-loglvl"')
        assert count == 1, (
            f'id="gw-loglvl" appears {count} times; must be exactly 1'
        )

    def test_tv9_vhost_select_has_max_width(self):
        """#vhost-select CSS must set max-width to prevent long hostnames stretching the topbar."""
        src = (DASHBOARDS / "main.html").read_text()
        css_idx = src.find('#vhost-select{')
        if css_idx == -1:
            css_idx = src.find('#vhost-select {')
        assert css_idx != -1, "main.html must have a #vhost-select CSS rule"
        rule = src[css_idx: css_idx + 300]
        assert 'max-width' in rule, (
            "#vhost-select CSS must set max-width — "
            "without it, long trycloudflare.com hostnames stretch the topbar"
        )

    def test_tv10_topbar_right_order(self):
        """#topbar-right must contain vhost-select, gw-loglvl-wrap, gw-status-pill in order."""
        src = (DASHBOARDS / "main.html").read_text()
        tr_idx = src.find('id="topbar-right"')
        assert tr_idx != -1
        after = src[tr_idx: tr_idx + 2000]
        vs  = after.find('id="vhost-select"')
        lw  = after.find('id="gw-loglvl-wrap"')
        sp  = after.find('id="gw-status-pill"')
        assert vs != -1 and lw != -1 and sp != -1, (
            "#topbar-right must contain all three controls"
        )
        assert vs < lw < sp, (
            f"Expected vhost-select({vs}) < gw-loglvl-wrap({lw}) < gw-status-pill({sp}) "
            "in document order inside #topbar-right"
        )


# ── RV: refreshVhosts() + load() vhost-selector dynamic-update tests ─────────
#
# Coverage matrix
# ───────────────
# RV1  controls.html: refreshVhosts() function is defined
# RV2  controls.html: refreshVhosts() uses credentials:'include'
# RV3  controls.html: refreshVhosts() is called immediately on DOMContentLoaded
# RV4  controls.html: refreshVhosts() is scheduled every 5 s via setInterval
# RV5  controls.html: refreshVhosts() fires on visibilitychange
# RV6  controls.html: load() syncs vhosts without a body.vhosts.length guard
# RV7  controls.html: load() removes stale options not present in server list
# RV8  GET /vhosts — response contains 'vhosts' list of objects with 'hostname'
# RV9  GET /vhosts — unauthenticated returns 403/redirect (not 200)
# RV10 GET /vhosts — newly-added vhost appears immediately in response
# RV11 GET /vhosts — deleted vhost is absent from response
# RV12 GET /config — 'vhosts' list reflects VHOSTS keys (not DB traffic history)

class TestRVRefreshVhosts:
    """QA for refreshVhosts() dynamic selector update and /vhosts endpoint contract."""

    # ── RV1-RV7: static HTML contract ────────────────────────────────────────

    def test_rv1_refresh_vhosts_function_defined(self):
        """controls.html must define an async refreshVhosts() function."""
        src = (DASHBOARDS / "controls.html").read_text()
        assert "async function refreshVhosts()" in src, (
            "controls.html must define async function refreshVhosts()"
        )

    def test_rv2_refresh_vhosts_uses_credentials_include(self):
        """refreshVhosts() fetch must include credentials:'include' for session cookie."""
        src = (DASHBOARDS / "controls.html").read_text()
        fn_idx = src.find("async function refreshVhosts()")
        assert fn_idx != -1
        # locate closing brace of the function (next top-level `}` after opening `{`)
        body = src[fn_idx: fn_idx + 800]
        assert "credentials:'include'" in body or "credentials: 'include'" in body, (
            "refreshVhosts() must pass credentials:'include' to fetch — "
            "without it the session cookie may be omitted on some agents"
        )

    def test_rv3_refresh_vhosts_called_on_domcontentloaded(self):
        """refreshVhosts() must be called in the DOMContentLoaded Promise.all block."""
        src = (DASHBOARDS / "controls.html").read_text()
        # Anchor search to after DOMContentLoaded so we skip the inner Promise.all
        # inside refreshVhosts() itself and find the startup block
        dcl_idx = src.find("DOMContentLoaded")
        assert dcl_idx != -1, "controls.html must have DOMContentLoaded listener"
        pa_idx = src.find("Promise.all([", dcl_idx)
        assert pa_idx != -1, "controls.html must have Promise.all startup block after DOMContentLoaded"
        pa_block = src[pa_idx: pa_idx + 400]
        assert "refreshVhosts()" in pa_block, (
            "Promise.all startup block must call refreshVhosts() so the selector "
            "is populated immediately on page load, not only after the first interval"
        )

    def test_rv4_refresh_vhosts_interval_5s(self):
        """setInterval for refreshVhosts must use 5000 ms."""
        src = (DASHBOARDS / "controls.html").read_text()
        assert "setInterval(refreshVhosts, 5000)" in src, (
            "controls.html must schedule refreshVhosts every 5 000 ms via setInterval"
        )

    def test_rv5_refresh_vhosts_on_visibilitychange(self):
        """refreshVhosts() must be called when the tab regains visibility."""
        src = (DASHBOARDS / "controls.html").read_text()
        vc_idx = src.find("visibilitychange")
        assert vc_idx != -1, "controls.html must listen for visibilitychange"
        # refreshVhosts() must appear near the visibilitychange handler
        vc_block = src[vc_idx: vc_idx + 200]
        assert "refreshVhosts" in vc_block, (
            "visibilitychange handler must call refreshVhosts()"
        )

    def test_rv6_load_syncs_vhosts_without_length_guard(self):
        """load() must sync vhosts even when the server returns an empty list."""
        src = (DASHBOARDS / "controls.html").read_text()
        load_idx = src.find("async function load()")
        assert load_idx != -1
        load_body = src[load_idx: load_idx + 4000]
        # Must check Array.isArray (type-safe) but must NOT gate on .length
        assert "Array.isArray(body.vhosts)" in load_body, (
            "load() must guard with Array.isArray(body.vhosts)"
        )
        assert "body.vhosts.length" not in load_body, (
            "load() must NOT gate on body.vhosts.length — that skips the sync "
            "when the list is empty, preventing stale options from being removed"
        )

    def test_rv7_load_removes_stale_vhost_options(self):
        """load() must remove selector options that are no longer in the server list."""
        src = (DASHBOARDS / "controls.html").read_text()
        load_idx = src.find("async function load()")
        assert load_idx != -1
        load_body = src[load_idx: load_idx + 4000]
        # The stale-removal logic iterates options and removes those not in `fresh`
        assert "fresh.has(o.value)" in load_body, (
            "load() must remove options whose value is not in the fresh vhosts set"
        )
        assert "o.remove()" in load_body, (
            "load() must call o.remove() to evict stale vhost options from the selector"
        )

    # ── RV8-RV12: /vhosts endpoint contract ──────────────────────────────────

    def test_rv8_vhosts_response_schema(self, proxy_module):
        """GET /vhosts must return {vhosts: [{hostname, ...}, ...]}."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import vhost as _v
                    _v.VHOSTS["schema.test"] = {"UPSTREAM": up}
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        r = await c.get(NS + "/vhosts",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        assert r.status == 200
                        d = await r.json()
                        assert "vhosts" in d, "GET /vhosts must return 'vhosts' key"
                        assert isinstance(d["vhosts"], list), "'vhosts' must be a list"
                        hostnames = [v.get("hostname") for v in d["vhosts"]]
                        assert "schema.test" in hostnames, (
                            "seeded vhost must appear in GET /vhosts response"
                        )
                    finally:
                        _v.VHOSTS.pop("schema.test", None)
        _run(go())

    def test_rv9_vhosts_unauthenticated_returns_decoy(self, proxy_module):
        """GET /vhosts without auth must not return real admin vhost data (decoy pattern).
        The proxy never returns 401/403 — it returns a decoy upstream response instead."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/vhosts")
                    body = await r.text()
                    # Must not reveal the real vhosts admin structure
                    assert '"vhosts"' not in body or r.status != 200, (
                        "unauthenticated GET /vhosts must not return real admin data; "
                        "proxy must serve a decoy response instead"
                    )
        _run(go())

    def test_rv10_vhosts_new_entry_appears_immediately(self, proxy_module):
        """A vhost added via POST /vhosts must appear in subsequent GET /vhosts.
        _assert_upstream_public is patched to allow loopback upstreams in tests."""
        import unittest.mock
        import vhost as _v
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _v.VHOSTS.pop("dynamic.test", None)
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        with unittest.mock.patch.object(_v, "_assert_upstream_public"):
                            r_post = await c.post(
                                NS + "/vhosts",
                                json={"hostname": "dynamic.test", "UPSTREAM": up},
                                cookies={proxy_module._SESSION_COOKIE: cookie},
                            )
                        assert r_post.status == 200, (
                            f"POST /vhosts must return 200, got {r_post.status}: "
                            f"{await r_post.text()}"
                        )
                        r_get = await c.get(NS + "/vhosts",
                                            cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r_get.json()
                        hostnames = [v.get("hostname") for v in d["vhosts"]]
                        assert "dynamic.test" in hostnames, (
                            "newly-POSTed vhost must appear in GET /vhosts immediately"
                        )
                    finally:
                        _v.VHOSTS.pop("dynamic.test", None)
        _run(go())

    def test_rv11_vhosts_deleted_entry_absent(self, proxy_module):
        """A vhost removed via DELETE /vhosts must be absent from subsequent GET /vhosts."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import vhost as _v
                    _v.VHOSTS["todelete.test"] = {"UPSTREAM": up}
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        r_del = await c.delete(
                            NS + "/vhosts",
                            json={"hostname": "todelete.test"},
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                        assert r_del.status == 200
                        r_get = await c.get(NS + "/vhosts",
                                            cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r_get.json()
                        hostnames = [v.get("hostname") for v in d["vhosts"]]
                        assert "todelete.test" not in hostnames, (
                            "deleted vhost must not appear in GET /vhosts"
                        )
                    finally:
                        _v.VHOSTS.pop("todelete.test", None)
        _run(go())

    def test_rv12_config_vhosts_reflects_vhosts_keys_not_db(self, proxy_module):
        """GET /config 'vhosts' list must come from VHOSTS dict, not DB traffic history."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import vhost as _v
                    # Seed a DB event for a domain that is NOT in VHOSTS
                    _seed_events(proxy_module, [
                        (time.time() - 60, "1.2.3.4", "UA", "/", "GET", 200, "ok",
                         "traffic-only.test"),
                    ])
                    # Add a different domain only to VHOSTS (no DB traffic)
                    _v.VHOSTS["config-only.test"] = {"UPSTREAM": up}
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        r = await c.get(NS + "/config",
                                        cookies={proxy_module._SESSION_COOKIE: cookie})
                        d = await r.json()
                        vhosts = d.get("vhosts", [])
                        assert "config-only.test" in vhosts, (
                            "GET /config 'vhosts' must include domains from VHOSTS dict"
                        )
                        assert "traffic-only.test" not in vhosts, (
                            "GET /config 'vhosts' must NOT include domains that only "
                            "appear in DB traffic — stale tunnel domains would pollute "
                            "the controls page scope selector"
                        )
                    finally:
                        _v.VHOSTS.pop("config-only.test", None)
        _run(go())


# ── V1: _validate_vhost_hostname unit tests ───────────────────────────────────

class TestV1ValidateVhostHostname:
    """Unit tests for vhost._validate_vhost_hostname().

    Coverage:
      V1.1  plain FQDN accepted
      V1.2  multi-label FQDN accepted
      V1.3  single-label hostname accepted (dev/local setups)
      V1.4  wildcard *.example.com accepted
      V1.5  trailing dot stripped and accepted
      V1.6  mixed-case normalised and accepted
      V1.7  empty string rejected
      V1.8  hostname with port number rejected
      V1.9  bare IPv4 address rejected
      V1.10 double wildcard rejected
      V1.11 bare asterisk rejected
      V1.12 label with leading hyphen rejected
      V1.13 label with trailing hyphen rejected
      V1.14 consecutive dots (empty label) rejected
      V1.15 label exceeding 63 chars rejected
      V1.16 total hostname exceeding 253 chars rejected
      V1.17 hostname with space rejected
      V1.18 hostname with underscore rejected
    """

    @staticmethod
    def _v(h):
        from vhost import _validate_vhost_hostname
        return _validate_vhost_hostname(h)

    def test_plain_fqdn_accepted(self):
        ok, err = self._v("example.com")
        assert ok, err

    def test_multi_label_fqdn_accepted(self):
        ok, err = self._v("sub.example.com")
        assert ok, err

    def test_single_label_accepted(self):
        ok, err = self._v("localhost")
        assert ok, err

    def test_wildcard_accepted(self):
        ok, err = self._v("*.example.com")
        assert ok, err

    def test_trailing_dot_stripped_and_accepted(self):
        ok, err = self._v("example.com.")
        assert ok, err

    def test_mixed_case_normalised_accepted(self):
        ok, err = self._v("Example.COM")
        assert ok, err

    def test_empty_string_rejected(self):
        ok, err = self._v("")
        assert not ok
        assert "empty" in err

    def test_port_number_rejected(self):
        ok, err = self._v("example.com:8080")
        assert not ok
        assert "port" in err

    def test_bare_ipv4_rejected(self):
        ok, err = self._v("192.168.1.1")
        assert not ok
        assert "IP" in err or "domain" in err

    def test_double_wildcard_rejected(self):
        ok, err = self._v("*.*.example.com")
        assert not ok
        assert "wildcard" in err

    def test_bare_asterisk_rejected(self):
        ok, err = self._v("*")
        assert not ok
        assert "wildcard" in err

    def test_leading_hyphen_label_rejected(self):
        ok, err = self._v("-bad.example.com")
        assert not ok
        assert "invalid" in err or "hyphen" in err

    def test_trailing_hyphen_label_rejected(self):
        ok, err = self._v("bad-.example.com")
        assert not ok
        assert "invalid" in err or "hyphen" in err

    def test_consecutive_dots_rejected(self):
        ok, err = self._v("bad..example.com")
        assert not ok
        assert "empty label" in err or "dot" in err

    def test_label_too_long_rejected(self):
        ok, err = self._v("a" * 64 + ".com")
        assert not ok
        assert "63" in err or "long" in err

    def test_total_too_long_rejected(self):
        ok, err = self._v("a" * 250 + ".com")
        assert not ok
        assert "253" in err or "long" in err

    def test_space_in_hostname_rejected(self):
        ok, err = self._v("hello world.com")
        assert not ok
        assert "invalid" in err

    def test_underscore_in_hostname_rejected(self):
        ok, err = self._v("hello_world.com")
        assert not ok
        assert "invalid" in err


# ── V2: vhost_set hostname validation integration tests ───────────────────────

class TestV2VhostSetValidation:
    """Integration tests: vhost_set() rejects invalid hostnames via the API.

    Coverage:
      V2.1  POST /vhosts with valid hostname → 200
      V2.2  POST /vhosts with port in hostname → 400
      V2.3  POST /vhosts with bare IP hostname → 400
      V2.4  POST /vhosts with underscore hostname → 400
      V2.5  POST /vhosts with double-dot hostname → 400
      V2.6  POST /vhosts with leading-hyphen hostname → 400
      V2.7  POST /vhosts with wildcard *.example.com → 200
    """

    @pytest.fixture(autouse=True)
    def _cleanup_vhosts(self, proxy_module):
        import vhost as _vh
        saved = dict(_vh.VHOSTS)
        yield
        _vh.VHOSTS.clear()
        _vh.VHOSTS.update(saved)

    def _post_vhost(self, client, proxy_module, cookie, hostname, upstream="https://httpbin.org"):
        return client.post(
            f"{NS}/vhosts",
            json={"hostname": hostname, "UPSTREAM": upstream},
            cookies={proxy_module._SESSION_COOKIE: cookie},
        )

    def test_valid_hostname_accepted(self, proxy_module):
        async def go():
            async with _spin_upstream() as _up:
                async with _spin_proxy(proxy_module, _up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with await self._post_vhost(cl, proxy_module, cookie, "valid-host.example.com") as r:
                        assert r.status == 200, await r.text()
        _run(go())

    def test_port_in_hostname_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as _up:
                async with _spin_proxy(proxy_module, _up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with await self._post_vhost(cl, proxy_module, cookie, "example.com:8080") as r:
                        assert r.status == 400
                        body = await r.json()
                        assert "port" in body.get("error", "").lower()
        _run(go())

    def test_bare_ip_hostname_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as _up:
                async with _spin_proxy(proxy_module, _up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with await self._post_vhost(cl, proxy_module, cookie, "1.2.3.4") as r:
                        assert r.status == 400
                        body = await r.json()
                        assert "error" in body
        _run(go())

    def test_underscore_hostname_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as _up:
                async with _spin_proxy(proxy_module, _up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with await self._post_vhost(cl, proxy_module, cookie, "my_app.example.com") as r:
                        assert r.status == 400
        _run(go())

    def test_double_dot_hostname_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as _up:
                async with _spin_proxy(proxy_module, _up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with await self._post_vhost(cl, proxy_module, cookie, "bad..example.com") as r:
                        assert r.status == 400
        _run(go())

    def test_leading_hyphen_hostname_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as _up:
                async with _spin_proxy(proxy_module, _up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with await self._post_vhost(cl, proxy_module, cookie, "-bad.example.com") as r:
                        assert r.status == 400
        _run(go())

    def test_wildcard_hostname_accepted(self, proxy_module):
        async def go():
            async with _spin_upstream() as _up:
                async with _spin_proxy(proxy_module, _up) as cl:
                    cookie = _make_admin_cookie(proxy_module)
                    async with await self._post_vhost(cl, proxy_module, cookie, "*.example.com") as r:
                        assert r.status == 200, await r.text()
        _run(go())


# ── V3: source guard — validator wired into vhost_set ─────────────────────────

class TestV3HostnameValidatorSourceGuards:
    """Source-level regression tests ensuring the validator is always called.

    Coverage:
      V3.1  _validate_vhost_hostname defined in vhost.py
      V3.2  vhost_set() calls _validate_vhost_hostname
      V3.3  VHOSTS env parse loop calls _validate_vhost_hostname
      V3.4  _LABEL_RE compiled regex present in vhost.py
    """

    @staticmethod
    def _src():
        return (Path(__file__).resolve().parent.parent / "vhost.py").read_text()

    def test_validator_function_defined(self):
        src = self._src()
        assert "def _validate_vhost_hostname(" in src, \
            "_validate_vhost_hostname must be defined in vhost.py"

    def test_vhost_set_calls_validator(self):
        src = self._src()
        fn_start = src.find("def vhost_set(")
        assert fn_start != -1
        next_fn = src.find("\ndef ", fn_start + 1)
        fn_body = src[fn_start:next_fn] if next_fn != -1 else src[fn_start:]
        assert "_validate_vhost_hostname(" in fn_body, \
            "vhost_set() must call _validate_vhost_hostname()"

    def test_env_parse_loop_calls_validator(self):
        src = self._src()
        parse_start = src.find("_VHOSTS_RAW = os.environ")
        assert parse_start != -1
        parse_block = src[parse_start:parse_start + 2000]
        assert "_validate_vhost_hostname(" in parse_block, \
            "VHOSTS env parse loop must call _validate_vhost_hostname()"

    def test_label_regex_defined(self):
        src = self._src()
        assert "_LABEL_RE" in src, \
            "_LABEL_RE compiled regex must be defined in vhost.py"


# ── POST /config?vhost=X — per-vhost override writes ─────────────────────────

class TestConfigVhostWrite:
    """POST /config?vhost=X writes overrides to that vhost via vhost_set(),
    not to global state.  Added for the controls-page multi-vhost fix."""

    def test_post_config_vhost_applies_override(self, proxy_module):
        """POST /config?vhost=X with a valid overridable key must update that
        vhost's entry, not the global config."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import vhost as _v
                    _v.VHOSTS["writevh.internal"] = {"UPSTREAM": up}
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        original_global = proxy_module.UA_FILTER_ENABLED
                        r = await c.post(
                            NS + "/config?vhost=writevh.internal",
                            json={"UA_FILTER_ENABLED": False},
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                        assert r.status == 200, f"POST /config?vhost: expected 200, got {r.status}"
                        d = await r.json()
                        assert "UA_FILTER_ENABLED" in (d.get("applied") or {}), (
                            "UA_FILTER_ENABLED must appear in 'applied'"
                        )
                        assert d.get("vhost") == "writevh.internal", (
                            "response must echo target vhost"
                        )
                        # Global must be unchanged
                        assert proxy_module.UA_FILTER_ENABLED == original_global, (
                            "POST /config?vhost must NOT mutate global UA_FILTER_ENABLED"
                        )
                        # Vhost override must be persisted in VHOSTS dict
                        assert _v.VHOSTS.get("writevh.internal", {}).get("UA_FILTER_ENABLED") is False, (
                            "vhost override must be stored in VHOSTS dict"
                        )
                    finally:
                        _v.VHOSTS.pop("writevh.internal", None)
        _run(go())

    def test_post_config_vhost_non_overridable_key_rejected(self, proxy_module):
        """Keys absent from _VHOST_COERCE must be rejected with 'not-vhost-overridable'."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import vhost as _v
                    _v.VHOSTS["rej.internal"] = {"UPSTREAM": up}
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        r = await c.post(
                            NS + "/config?vhost=rej.internal",
                            json={"RISK_BAN_THRESHOLD_NAT": 90},
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                        assert r.status == 200
                        d = await r.json()
                        assert "RISK_BAN_THRESHOLD_NAT" in (d.get("rejected") or {}), (
                            "non-overridable key must appear in 'rejected'"
                        )
                        assert (d.get("rejected") or {}).get("RISK_BAN_THRESHOLD_NAT") == "not-vhost-overridable"
                    finally:
                        _v.VHOSTS.pop("rej.internal", None)
        _run(go())

    def test_post_config_global_unaffected_when_vhost_targeted(self, proxy_module):
        """When ?vhost= is set, the global state must not change for any applied key."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import vhost as _v
                    _v.VHOSTS["isolate.internal"] = {"UPSTREAM": up}
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        before_burst = proxy_module.RATE_LIMIT_BURST
                        r = await c.post(
                            NS + "/config?vhost=isolate.internal",
                            json={"RATE_LIMIT_BURST": 9999},
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                        assert r.status == 200
                        d = await r.json()
                        assert "RATE_LIMIT_BURST" in (d.get("applied") or {}), (
                            "RATE_LIMIT_BURST must be in applied"
                        )
                        assert proxy_module.RATE_LIMIT_BURST == before_burst, (
                            "global RATE_LIMIT_BURST must not change when targeting a vhost"
                        )
                        assert _v.VHOSTS["isolate.internal"].get("RATE_LIMIT_BURST") == 9999, (
                            "vhost override RATE_LIMIT_BURST must be 9999"
                        )
                    finally:
                        _v.VHOSTS.pop("isolate.internal", None)
        _run(go())

    def test_post_config_vhost_unauthenticated_rejected(self, proxy_module):
        """POST /config?vhost=X without session cookie must not apply any changes
        (proxy serves a silent decoy — may be 200 but must not contain 'applied' admin data)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    import vhost as _v
                    _v.VHOSTS["unauth.internal"] = {"UPSTREAM": up}
                    original_ua = _v.VHOSTS["unauth.internal"].get("UA_FILTER_ENABLED")
                    try:
                        r = await c.post(
                            NS + "/config?vhost=unauth.internal",
                            json={"UA_FILTER_ENABLED": False},
                        )
                        # Denied or decoy — either way, the override must NOT be written
                        if r.content_type == "application/json":
                            d = await r.json()
                            assert "UA_FILTER_ENABLED" not in (d.get("applied") or {}), (
                                "unauthenticated POST /config?vhost must not apply changes"
                            )
                        assert _v.VHOSTS.get("unauth.internal", {}).get("UA_FILTER_ENABLED") == original_ua, (
                            "unauthenticated request must not mutate vhost overrides"
                        )
                    finally:
                        _v.VHOSTS.pop("unauth.internal", None)
        _run(go())

    def test_post_config_no_vhost_still_writes_global(self, proxy_module):
        """POST /config without ?vhost= must still apply to global state (backward compat)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    original = proxy_module.LOG_LEVEL
                    r = await c.post(
                        NS + "/config",
                        json={"LOG_LEVEL": original},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    d = await r.json()
                    assert "LOG_LEVEL" in (d.get("applied") or {}), (
                        "global POST /config must still apply LOG_LEVEL"
                    )
                    assert d.get("vhost", "") == "", (
                        "global POST must return empty vhost field"
                    )
        _run(go())
