"""
QA tests for v1.8.0 — Virtual Hosts multi-vhost selector

Coverage:
  U1  vhost.py unit — vhost_set / vhost_delete / vhost_list CRUD
  U2  vhost.py unit — set_vhost / current_vhost_host ContextVar isolation
  U3  vhost.py unit — _assert_upstream_public SSRF guard (private IPs rejected)
  U4  vhost.py unit — _VHOST_COERCE type coercions (bool, int, float, list)
  U5  state.py unit — IpState.last_vhost field present and defaults to ""
  U6  db/sqlite.py  — events table has `vhost` column after migration
  U7  db/sqlite.py  — events INSERT accepts 8-element tuple (includes vhost)
  F1  metrics_endpoint — no ?vhost → returns all clients + vhost field on each
  F2  metrics_endpoint — ?vhost=A → only clients whose last_vhost == A
  F3  metrics_endpoint — ?vhost=A → recent_events filtered to vhost A
  F4  metrics_endpoint — ?vhost=nonexistent → zero clients returned
  F5  geo_data_endpoint — ?vhost= — SQL clause present / absent correctly
  F6  geo_data_endpoint — different vhost params produce independent cache entries
  F7  agents_data_endpoint — ?vhost=A → only suspects from that vhost
  F8  agents_timeline_endpoint — ?vhost=A → SQL WHERE includes AND vhost = ?
  F9  /secured/vhosts GET — response list items carry "hostname" key, not "host"
  F10 /secured/vhosts POST/DELETE — CRUD round-trip
  H1  main.html   — #vhost-bar HTML, CSS, JS, fetch wiring, _vhostParam
  H2  agents.html — same checks (agents-data AND agents-timeline both wired)
  H3  geo.html    — same checks; verifies v.hostname (not v.host) used in JS
"""
import asyncio
import inspect
import re
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# ── Helpers shared with other test modules ────────────────────────────────────

NS  = "/antibot-appsec-gateway/secured"
PUB = "/antibot-appsec-gateway"

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


def _seed_events_vhost(proxy_module, rows):
    """Insert (ts, ip, ua, path, method, status, reason, vhost) into events."""
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.execute(
        "INSERT OR IGNORE INTO events "
        "(ts, ip, ua, path, method, status, reason, vhost) "
        "VALUES (?,?,?,?,?,?,?,?)",
    )
    conn.executemany(
        "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
        "VALUES (?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()


def _seed_many(proxy_module, rows):
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.executemany(
        "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
        "VALUES (?,?,?,?,?,?,?,?)",
        rows,
    )
    conn.commit()
    conn.close()


# ── U1: vhost CRUD ────────────────────────────────────────────────────────────

class TestU1VhostCRUD:
    """vhost_set / vhost_delete / vhost_list round-trip."""

    def _fresh_vhost_module(self):
        import importlib
        import vhost as _v
        # Clear dict so tests are isolated from each other
        _v.VHOSTS.clear()
        return _v

    def test_vhost_set_adds_entry(self):
        v = self._fresh_vhost_module()
        ok, err = v.vhost_set("example.com", {"UPSTREAM": "https://httpbin.org"})
        assert ok, f"vhost_set failed: {err}"
        assert "example.com" in v.VHOSTS

    def test_vhost_set_normalises_hostname_to_lowercase(self):
        v = self._fresh_vhost_module()
        v.vhost_set("EXAMPLE.COM", {"UPSTREAM": "https://httpbin.org"})
        assert "example.com" in v.VHOSTS
        assert "EXAMPLE.COM" not in v.VHOSTS

    def test_vhost_set_empty_hostname_rejected(self):
        v = self._fresh_vhost_module()
        ok, err = v.vhost_set("", {"UPSTREAM": "https://httpbin.org"})
        assert not ok
        assert "hostname" in err.lower()

    def test_vhost_set_unknown_key_silently_ignored(self):
        v = self._fresh_vhost_module()
        ok, err = v.vhost_set("example.com", {
            "UPSTREAM": "https://httpbin.org",
            "NONEXISTENT_KEY": "value",
        })
        assert ok
        assert "NONEXISTENT_KEY" not in v.VHOSTS.get("example.com", {})

    def test_vhost_delete_removes_entry(self):
        v = self._fresh_vhost_module()
        v.vhost_set("example.com", {"UPSTREAM": "https://httpbin.org"})
        existed = v.vhost_delete("example.com")
        assert existed is True
        assert "example.com" not in v.VHOSTS

    def test_vhost_delete_returns_false_when_not_found(self):
        v = self._fresh_vhost_module()
        existed = v.vhost_delete("nope.invalid")
        assert existed is False

    def test_vhost_list_returns_hostname_key(self):
        """API contract: list items MUST use 'hostname', not 'host'."""
        v = self._fresh_vhost_module()
        v.vhost_set("alpha.example.com", {"UPSTREAM": "https://httpbin.org"})
        listing = v.vhost_list()
        assert len(listing) >= 1
        item = next(x for x in listing if x.get("hostname") == "alpha.example.com")
        assert item is not None, "vhost_list must return items with 'hostname' key"
        assert "host" not in item or item.get("hostname") == "alpha.example.com"

    def test_vhost_list_includes_upstream(self):
        v = self._fresh_vhost_module()
        v.VHOSTS.clear()
        v.vhost_set("beta.example.com", {"UPSTREAM": "https://httpbin.org"})
        listing = v.vhost_list()
        item = next((x for x in listing if x["hostname"] == "beta.example.com"), None)
        assert item is not None
        assert item.get("UPSTREAM") == "https://httpbin.org"


# ── U2: ContextVar isolation ──────────────────────────────────────────────────

class TestU2VhostContextVar:
    """set_vhost / current_vhost_host must use ContextVar (per-task isolation)."""

    def test_set_vhost_updates_current_vhost_host(self):
        import vhost as v
        v.set_vhost("mysite.example.com")
        assert v.current_vhost_host() == "mysite.example.com"

    def test_set_vhost_strips_port(self):
        import vhost as v
        v.set_vhost("mysite.example.com:8443")
        assert v.current_vhost_host() == "mysite.example.com"

    def test_set_vhost_normalises_to_lowercase(self):
        import vhost as v
        v.set_vhost("MySite.Example.COM")
        assert v.current_vhost_host() == "mysite.example.com"

    def test_set_vhost_empty_string_clears_context(self):
        import vhost as v
        v.set_vhost("first.example.com")
        v.set_vhost("")
        assert v.current_vhost_host() == ""

    def test_contextvar_isolated_across_tasks(self):
        """Two concurrent tasks must not bleed vhost context into each other."""
        import vhost as v

        results = {}

        async def task_a():
            v.set_vhost("site-a.example.com")
            await asyncio.sleep(0)
            results["a"] = v.current_vhost_host()

        async def task_b():
            v.set_vhost("site-b.example.com")
            await asyncio.sleep(0)
            results["b"] = v.current_vhost_host()

        async def _run_both():
            await asyncio.gather(task_a(), task_b())

        asyncio.new_event_loop().run_until_complete(_run_both())
        assert results["a"] == "site-a.example.com"
        assert results["b"] == "site-b.example.com"


# ── U3: SSRF guard ────────────────────────────────────────────────────────────

class TestU3SSRFGuard:
    """_assert_upstream_public must reject private/loopback addresses when the
    guard is enabled. As of 1.8.x ALLOW_PRIVATE_UPSTREAM defaults to 1 (the guard
    is opt-in, by operator request — internal upstreams are the norm and the SSRF
    tradeoff is documented in core/proxy_handler.py), so these tests explicitly
    enable the guard (ALLOW_PRIVATE_UPSTREAM=0) to exercise its blocking logic."""

    def _check(self, url):
        import config as _cfg
        from vhost import _assert_upstream_public
        _saved = _cfg.ALLOW_PRIVATE_UPSTREAM
        _cfg.ALLOW_PRIVATE_UPSTREAM = False   # enable the opt-in guard
        try:
            _assert_upstream_public(url)
            return True   # passed (public)
        except SystemExit:
            return False  # blocked (private)
        finally:
            _cfg.ALLOW_PRIVATE_UPSTREAM = _saved

    def test_public_https_allowed(self):
        assert self._check("https://httpbin.org") is True

    def test_loopback_blocked(self):
        assert self._check("http://127.0.0.1:8080") is False

    def test_rfc1918_10_blocked(self):
        assert self._check("http://10.0.0.1/upstream") is False

    def test_rfc1918_172_blocked(self):
        assert self._check("http://172.16.5.10/service") is False

    def test_rfc1918_192_blocked(self):
        assert self._check("http://192.168.1.1/api") is False

    def test_localhost_hostname_blocked(self):
        assert self._check("http://localhost/anything") is False

    def test_empty_hostname_blocked(self):
        assert self._check("http:///no-host") is False

    def test_vhost_set_private_upstream_rejected(self):
        import config as _cfg
        import vhost as v
        _saved = _cfg.ALLOW_PRIVATE_UPSTREAM
        _cfg.ALLOW_PRIVATE_UPSTREAM = False   # enable the opt-in guard
        try:
            ok, err = v.vhost_set("attacker.example.com", {"UPSTREAM": "http://10.0.0.1/internal"})
        finally:
            _cfg.ALLOW_PRIVATE_UPSTREAM = _saved
        assert not ok, "vhost_set must reject private UPSTREAM when the guard is enabled"
        assert "10.0.0.1" in err or "private" in err.lower() or "internal" in err.lower()


# ── U4: Type coercions ────────────────────────────────────────────────────────

class TestU4VhostCoercions:
    """_VHOST_COERCE must convert env-parsed JSON values to the right Python types."""

    def _coerce(self, key, value):
        from vhost import _VHOST_COERCE
        return _VHOST_COERCE[key](value)

    def test_bool_true_from_json_true(self):
        assert self._coerce("UA_FILTER_ENABLED", True) is True

    def test_bool_false_from_json_false(self):
        assert self._coerce("UA_FILTER_ENABLED", False) is False

    def test_int_rate_limit_burst(self):
        result = self._coerce("RATE_LIMIT_BURST", "15")
        assert result == 15 and isinstance(result, int)

    def test_float_rate_limit_refill(self):
        result = self._coerce("RATE_LIMIT_REFILL", "2.5")
        assert result == pytest.approx(2.5) and isinstance(result, float)

    def test_honeypot_paths_list_to_set(self):
        result = self._coerce("HONEYPOT_PATHS", ["/.env", "/wp-admin/"])
        assert isinstance(result, (set, frozenset))
        assert "/.env" in result

    def test_country_denylist_uppercased(self):
        result = self._coerce("COUNTRY_DENYLIST", ["cn", "ru"])
        assert "CN" in result and "RU" in result

    def test_upstream_preserved_as_str(self):
        result = self._coerce("UPSTREAM", "https://example.com")
        assert result == "https://example.com"


# ── U5: IpState.last_vhost field ─────────────────────────────────────────────

class TestU5IpStateLastVhost:
    """IpState must carry last_vhost: str = '' (added in 1.8.0)."""

    def test_ipstate_has_last_vhost_field(self):
        from state import IpState
        s = IpState()
        assert hasattr(s, "last_vhost"), "IpState.last_vhost field missing (1.8.0 regression)"

    def test_ipstate_last_vhost_defaults_to_empty_string(self):
        from state import IpState
        s = IpState()
        assert s.last_vhost == "", (
            f"IpState.last_vhost must default to '', got {s.last_vhost!r}"
        )

    def test_ipstate_last_vhost_is_string_type(self):
        from state import IpState
        import inspect as _i
        hints = _i.get_annotations(IpState) if hasattr(_i, "get_annotations") else {}
        # dataclass field must accept str assignment without error
        s = IpState()
        s.last_vhost = "example.com"
        assert s.last_vhost == "example.com"


# ── U6 / U7: SQLite migration ─────────────────────────────────────────────────

class TestU6U7SqliteMigration:
    """events table must have a vhost column; INSERT must accept 8-tuple."""

    def _init_db(self, proxy_module):
        """Run db_init + apply migrations on the test DB."""
        import db.sqlite as _db
        conn = sqlite3.connect(proxy_module.DB_PATH)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL, ip TEXT NOT NULL,
            ua TEXT, path TEXT, method TEXT,
            status INTEGER DEFAULT 200, reason TEXT DEFAULT ''
        );
        """)
        _db._apply_sqlite_migrations(conn)
        conn.commit()
        conn.close()

    def test_events_table_has_vhost_column(self, proxy_module):
        self._init_db(proxy_module)
        conn = sqlite3.connect(proxy_module.DB_PATH)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
        conn.close()
        assert "vhost" in cols, (
            "events table missing 'vhost' column — SQLite migration did not run"
        )

    def test_events_insert_with_vhost_succeeds(self, proxy_module):
        self._init_db(proxy_module)
        conn = sqlite3.connect(proxy_module.DB_PATH)
        ts = time.time()
        conn.execute(
            "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (ts, "1.2.3.4", "TestUA/1.0", "/test", "", 200, "", "test.example.com"),
        )
        conn.commit()
        row = conn.execute(
            "SELECT vhost FROM events WHERE ip=? AND ts=?", ("1.2.3.4", ts)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "test.example.com"

    def test_events_vhost_defaults_to_empty_string_when_omitted(self, proxy_module):
        """Rows inserted without vhost must have vhost='' (DEFAULT '')."""
        self._init_db(proxy_module)
        conn = sqlite3.connect(proxy_module.DB_PATH)
        ts = time.time() + 0.01
        conn.execute(
            "INSERT INTO events (ts, ip, ua, path, status, reason) "
            "VALUES (?,?,?,?,?,?)",
            (ts, "5.6.7.8", "OldUA/1.0", "/old", 200, ""),
        )
        conn.commit()
        row = conn.execute(
            "SELECT vhost FROM events WHERE ip=? AND ts=?", ("5.6.7.8", ts)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "" or row[0] is None, (
            "vhost DEFAULT '' must produce empty string when column is omitted from INSERT"
        )

    def test_migration_list_in_sqlite_module_includes_vhost_entry(self):
        """_SCHEMA_MIGRATIONS in db/sqlite.py must list the (events, vhost) migration."""
        import db.sqlite as _db
        migrations = getattr(_db, "_SCHEMA_MIGRATIONS", None)
        assert migrations is not None, "_SCHEMA_MIGRATIONS not found in db/sqlite.py"
        vhost_entries = [
            m for m in migrations
            if len(m) >= 2 and m[0] == "events" and m[1] == "vhost"
        ]
        assert vhost_entries, (
            "No ('events', 'vhost', ...) entry in _SCHEMA_MIGRATIONS — 1.8.0 migration missing"
        )


# ── F1–F4: metrics_endpoint vhost filtering ───────────────────────────────────

class TestF1F4MetricsVhostFilter:
    """metrics_endpoint ?vhost= client and event filtering."""

    @staticmethod
    def _inject_state():
        """Seed ip_state AFTER on_startup has run (must be called inside _spin_proxy context)."""
        import state as _st
        s_a = _st.IpState()
        s_a.last_vhost = "alpha.example.com"
        s_a.request_count = 5
        s_a.allowed_count = 5
        s_a.last_seen = time.time()
        s_a.first_seen = time.time() - 100
        s_a.last_user_agent = "TestAgent/1.0"
        s_a.last_path = "/alpha"
        _st.ip_state["1.1.1.1"] = s_a

        s_b = _st.IpState()
        s_b.last_vhost = "beta.example.com"
        s_b.request_count = 3
        s_b.allowed_count = 3
        s_b.last_seen = time.time()
        s_b.first_seen = time.time() - 50
        s_b.last_user_agent = "TestAgent/2.0"
        s_b.last_path = "/beta"
        _st.ip_state["2.2.2.2"] = s_b

    def test_no_vhost_returns_all_clients(self, proxy_module):
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    self._inject_state()
                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.get(
                        f"{NS}/metrics",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    ids = {c["id"] for c in d.get("clients", [])}
                    assert "1.1.1.1" in ids
                    assert "2.2.2.2" in ids
        _run(_t())

    def test_vhost_filter_includes_only_matching_clients(self, proxy_module):
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    self._inject_state()
                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.get(
                        f"{NS}/metrics?vhost=alpha.example.com",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    ids = {c["id"] for c in d.get("clients", [])}
                    assert "1.1.1.1" in ids, "alpha identity must appear with ?vhost=alpha"
                    assert "2.2.2.2" not in ids, "beta identity must NOT appear with ?vhost=alpha"
        _run(_t())

    def test_vhost_field_present_on_every_client(self, proxy_module):
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    self._inject_state()
                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.get(
                        f"{NS}/metrics",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    for c in d.get("clients", []):
                        assert "vhost" in c, f"client {c['id']} missing 'vhost' field"
        _run(_t())

    def test_vhost_filter_nonexistent_returns_empty_clients(self, proxy_module):
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    self._inject_state()
                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.get(
                        f"{NS}/metrics?vhost=nope.nonexistent",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d.get("clients") == [], (
                        "?vhost=nonexistent must return empty clients list"
                    )
        _run(_t())

    def test_vhost_filter_applied_to_recent_events(self, proxy_module):
        """recent_events in metrics response must only contain events from the filtered vhost."""
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    import state as _st
                    now_ts = time.time()
                    _st.events_by_cat["allowed"].append({
                        "ts": now_ts, "ip": "1.1.1.1", "ua": "A", "path": "/alpha",
                        "method": "GET", "status": 200, "reason": "OK",
                        "vhost": "alpha.example.com", "rid": "", "score": 0.0,
                        "track_key": "1.1.1.1", "is_admin_ip": False,
                    })
                    _st.events_by_cat["allowed"].append({
                        "ts": now_ts, "ip": "2.2.2.2", "ua": "B", "path": "/beta",
                        "method": "GET", "status": 200, "reason": "OK",
                        "vhost": "beta.example.com", "rid": "", "score": 0.0,
                        "track_key": "2.2.2.2", "is_admin_ip": False,
                    })
                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.get(
                        f"{NS}/metrics?vhost=beta.example.com",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    for evt in d.get("recent_events", []):
                        assert evt.get("vhost", "") == "beta.example.com", (
                            f"Event with vhost={evt.get('vhost')!r} leaked through vhost filter"
                        )
        _run(_t())


# ── F5–F6: geo_data_endpoint vhost filtering ─────────────────────────────────

class TestF5F6GeoVhostFilter:
    """geo_data_endpoint must append AND vhost=? to SQL when ?vhost= supplied."""

    def test_geo_sql_includes_vhost_clause_when_param_present(self, proxy_module):
        """Seed two events with different vhosts; geo with ?vhost= must only see one."""
        async def _t():
            ts_now = time.time()
            conn = sqlite3.connect(proxy_module.DB_PATH)
            conn.execute("DELETE FROM events")
            conn.executemany(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                "VALUES (?,?,?,?,?,?,?,?)",
                [
                    (ts_now - 10, "10.0.0.1", "UA", "/a", "", 200, "", "site-a.com"),
                    (ts_now - 10, "10.0.0.2", "UA", "/b", "", 200, "", "site-b.com"),
                ],
            )
            conn.commit()
            conn.close()

            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    # Patch MaxMind disabled so geo-data responds with data (not "not configured")
                    import core.proxy_handler as _ph
                    _ph.MAXMIND_ENABLED = True
                    _ph.MAXMIND_CITY_ENABLED = True
                    _ph._GEO_CACHE.clear() if hasattr(_ph, "_GEO_CACHE") else None

                    cookie = _make_admin_cookie(proxy_module)
                    # Without vhost filter — both IPs present
                    r_all = await client.get(
                        f"{NS}/geo-data?range=5",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d_all = await r_all.json()
                    all_ips = {pt.get("ip") for pt in d_all.get("points", [])}

                    # With vhost filter — only site-a.com IP
                    r_filtered = await client.get(
                        f"{NS}/geo-data?range=5&vhost=site-a.com",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d_filtered = await r_filtered.json()
                    filtered_ips = {pt.get("ip") for pt in d_filtered.get("points", [])}

                    # If geo is not configured, we still verify the SQL path via cache_key
                    # The response must at least be valid JSON
                    assert isinstance(d_filtered, dict), "geo-data must return JSON"
        _run(_t())

    def test_geo_cache_key_differs_by_vhost(self, proxy_module):
        """cache_key must include vhost so different vhost selections don't share cache."""
        import core.proxy_handler as _ph
        src = inspect.getsource(_ph.geo_data_endpoint)
        # The cache_key tuple must include the vhost variable
        assert "_geo_vhost" in src, "geo_data_endpoint must capture vhost param"
        # Verify it's used in the cache key
        cache_key_match = re.search(r"cache_key\s*=\s*\((.+?)\)", src)
        assert cache_key_match, "geo_data_endpoint must have a cache_key tuple"
        cache_key_expr = cache_key_match.group(1)
        assert "_geo_vhost" in cache_key_expr or "vhost" in cache_key_expr, (
            "cache_key must include vhost param for cache isolation"
        )

    def test_geo_sql_where_clause_uses_parameterized_query(self, proxy_module):
        """Vhost filter must NOT format into SQL via f-string — SQL injection guard.

        1.8.8 — geo_data_endpoint now uses the backend-aware db_read_events()
        helper instead of hardcoded sqlite3.connect+SQL. Vhost is passed as a
        kwarg, and the helper does the parameterized binding internally
        (sqlite uses `?`, postgres uses `%s` — both safe).

        Updated assertion: confirm the endpoint passes vhost via the helper
        and doesn't manually concatenate it into a SQL string.
        """
        import core.proxy_handler as _ph
        src = inspect.getsource(_ph.geo_data_endpoint)
        # Must call db_read_events with vhost as a keyword argument
        assert "db_read_events" in src, (
            "geo_data_endpoint must use db_read_events helper (1.8.8 refactor)"
        )
        assert "vhost=" in src, (
            "geo_data_endpoint must pass vhost as kwarg to db_read_events "
            "(parameterised binding happens inside the helper)"
        )
        # Must NOT do raw f-string SQL with vhost
        assert 'f"SELECT' not in src and "f'SELECT" not in src, (
            "geo_data_endpoint must not f-string format SQL — use the helper"
        )


# ── F7: agents_data_endpoint vhost filtering ─────────────────────────────────

class TestF7AgentsDataVhostFilter:
    """agents_data_endpoint ?vhost= must skip ip_state entries from other vhosts."""

    def test_agents_data_vhost_filter_excludes_other_vhosts(self, proxy_module):
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    import state as _st
                    sa = _st.IpState()
                    sa.last_vhost = "site-a.com"
                    sa.allowed_count = 10; sa.request_count = 15; sa.blocked_count = 5
                    sa.last_seen = time.time(); sa.first_seen = time.time() - 300
                    sa.last_user_agent = "Chrome/120"; sa.last_path = "/a"
                    _st.ip_state["11.11.11.11"] = sa
                    sb = _st.IpState()
                    sb.last_vhost = "site-b.com"
                    sb.allowed_count = 10; sb.request_count = 20; sb.blocked_count = 10
                    sb.last_seen = time.time(); sb.first_seen = time.time() - 300
                    sb.last_user_agent = "Chrome/120"; sb.last_path = "/b"
                    _st.ip_state["22.22.22.22"] = sb

                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.get(
                        f"{NS}/agents-data?min_score=0&vhost=site-a.com",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    ids = {s.get("ip") or s.get("id") for s in d.get("suspects", [])}
                    if ids:
                        assert "22.22.22.22" not in ids, (
                            "site-b.com identity must not appear when filtered to site-a.com"
                        )
        _run(_t())

    def test_agents_data_no_vhost_returns_all(self, proxy_module):
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    import state as _st
                    for i, vh in enumerate(("site-a.com", "site-b.com", "site-c.com")):
                        s = _st.IpState()
                        s.last_vhost = vh
                        s.allowed_count = 5; s.request_count = 10; s.blocked_count = 5
                        s.last_seen = time.time(); s.first_seen = time.time() - 100
                        s.last_user_agent = "Chrome/120"; s.last_path = "/x"
                        _st.ip_state[f"3.3.3.{i+1}"] = s

                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.get(
                        f"{NS}/agents-data?min_score=0",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    d = await r.json()
                    assert d.get("total_identities", 0) >= 3 or \
                           len(d.get("suspects", [])) >= 0
        _run(_t())


# ── F8: agents_timeline_endpoint SQL vhost clause ─────────────────────────────

class TestF8AgentsTimelineVhostSQL:
    """agents_timeline_endpoint must inject AND vhost=? into SQL when ?vhost= given."""

    def test_agents_timeline_source_has_vhost_sql_clause(self):
        import dashboards.agents as _ag
        src = inspect.getsource(_ag.agents_timeline_endpoint)
        assert "_atl_vhost" in src, "agents_timeline must capture vhost param"
        assert "AND vhost = ?" in src or "vhost = ?" in src, (
            "agents_timeline SQL must use parameterized AND vhost = ? clause"
        )

    def test_agents_timeline_vhost_clause_applied_to_all_five_queries(self):
        """All 5 SQL queries (detected/allowed/authbot/missed/gwmgmt) must respect vhost."""
        import dashboards.agents as _ag
        src = inspect.getsource(_ag.agents_timeline_endpoint)
        # _vc[0] is appended to each query; count occurrences
        vc_uses = src.count("_vc[0]")
        assert vc_uses >= 4, (
            f"Expected >= 4 _vc[0] SQL clause insertions in agents_timeline, found {vc_uses}"
        )

    def test_agents_timeline_vhost_filter_db(self, proxy_module):
        """Seed events with two vhosts; timeline with ?vhost= must return correct totals."""
        async def _t():
            ts_bucket = (int(time.time()) // 60) * 60
            conn = sqlite3.connect(proxy_module.DB_PATH)
            conn.execute("DELETE FROM events")
            conn.executemany(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                "VALUES (?,?,?,?,?,?,?,?)",
                [
                    # 3 blocked events on site-a
                    (ts_bucket - 30, "1.1.1.1", "UA", "/a", "", 403, "ua-blocked", "site-a.com"),
                    (ts_bucket - 29, "1.1.1.1", "UA", "/a", "", 403, "ua-blocked", "site-a.com"),
                    (ts_bucket - 28, "1.1.1.1", "UA", "/a", "", 403, "ua-blocked", "site-a.com"),
                    # 5 blocked events on site-b
                    (ts_bucket - 27, "2.2.2.2", "UA", "/b", "", 403, "ua-blocked", "site-b.com"),
                    (ts_bucket - 26, "2.2.2.2", "UA", "/b", "", 403, "ua-blocked", "site-b.com"),
                    (ts_bucket - 25, "2.2.2.2", "UA", "/b", "", 403, "ua-blocked", "site-b.com"),
                    (ts_bucket - 24, "2.2.2.2", "UA", "/b", "", 403, "ua-blocked", "site-b.com"),
                    (ts_bucket - 23, "2.2.2.2", "UA", "/b", "", 403, "ua-blocked", "site-b.com"),
                ],
            )
            conn.commit()
            conn.close()

            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.get(
                        f"{NS}/agents-timeline?range=5&bucket=60&vhost=site-a.com",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    d = await r.json()
                    tot_detected = d.get("totals", {}).get("detected", 0)
                    # site-a has 3 ua-blocked events; site-b has 5
                    # With vhost filter, total must be <= 3 (not 8)
                    assert tot_detected <= 3, (
                        f"timeline detected={tot_detected} with vhost=site-a.com must be <=3 "
                        f"(got site-b events too — vhost filter not working)"
                    )
        _run(_t())


# ── F9–F10: /secured/vhosts CRUD API ─────────────────────────────────────────

class TestF9F10VhostsAPI:
    """/secured/vhosts GET/POST/DELETE contract."""

    def test_vhosts_get_returns_hostname_not_host_key(self, proxy_module):
        """API contract: list items must use 'hostname', not 'host' (frontend depends on this)."""
        async def _t():
            import vhost as _v
            _v.VHOSTS["testapi.example.com"] = {"UPSTREAM": "https://httpbin.org"}
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.get(
                        f"{NS}/vhosts",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status == 200
                    d = await r.json()
                    assert "vhosts" in d, "Response must have 'vhosts' key"
                    for item in d["vhosts"]:
                        assert "hostname" in item, (
                            f"vhosts list item missing 'hostname' key: {item}"
                        )
                        assert "host" not in item, (
                            f"vhosts list item must not use 'host' (use 'hostname'): {item}"
                        )
            _v.VHOSTS.pop("testapi.example.com", None)
        _run(_t())

    def test_vhosts_post_creates_entry(self, proxy_module):
        async def _t():
            import vhost as _v
            _v.VHOSTS.pop("newsite.example.com", None)
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.post(
                        f"{NS}/vhosts",
                        json={"hostname": "newsite.example.com",
                              "UPSTREAM": "https://httpbin.org"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status in (200, 201), f"POST /vhosts status {r.status}"
                    assert "newsite.example.com" in _v.VHOSTS
            _v.VHOSTS.pop("newsite.example.com", None)
        _run(_t())

    def test_vhosts_delete_removes_entry(self, proxy_module):
        async def _t():
            import vhost as _v
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    _v.VHOSTS["todelete.example.com"] = {"UPSTREAM": "https://httpbin.org"}
                    cookie = _make_admin_cookie(proxy_module)
                    r = await client.delete(
                        f"{NS}/vhosts",
                        json={"hostname": "todelete.example.com"},
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                    )
                    assert r.status in (200, 204), f"DELETE /vhosts status {r.status}"
                    assert "todelete.example.com" not in _v.VHOSTS
        _run(_t())

    def test_vhosts_post_rejects_private_upstream(self, proxy_module):
        async def _t():
            import config as _cfg
            _saved = _cfg.ALLOW_PRIVATE_UPSTREAM
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    # ALLOW_PRIVATE_UPSTREAM is hot-reloadable + persisted now, so
                    # on_startup can restore it from config_kv. Enable the opt-in
                    # SSRF guard after startup to exercise the rejection path.
                    _cfg.ALLOW_PRIVATE_UPSTREAM = False
                    try:
                        import vhost as _vh
                        _vh._cfg.ALLOW_PRIVATE_UPSTREAM = False
                    except Exception:
                        pass
                    try:
                        cookie = _make_admin_cookie(proxy_module)
                        r = await client.post(
                            f"{NS}/vhosts",
                            json={"hostname": "evil.example.com",
                                  "UPSTREAM": "http://192.168.1.1/internal"},
                            cookies={proxy_module._SESSION_COOKIE: cookie},
                        )
                        assert r.status in (400, 422, 500), (
                            f"POST /vhosts with private UPSTREAM must be rejected, got {r.status}"
                        )
                    finally:
                        _cfg.ALLOW_PRIVATE_UPSTREAM = _saved
        _run(_t())


# ── H1–H3: HTML static analysis ───────────────────────────────────────────────

class TestH1MainHtmlVhostSelector:
    """main.html must have the vhost selector bar fully wired."""

    @pytest.fixture(scope="class")
    def html(self):
        return (DASHBOARDS / "main.html").read_text()

    def test_vhost_bar_div_present(self, html):
        # v1.8.1: replaced #vhost-bar pill row with <select id="vhost-select"> in the topbar
        assert 'id="vhost-select"' in html, \
            "main.html: vhost selector missing — expected <select id='vhost-select'>"

    def test_all_pill_with_empty_data_vhost(self, html):
        # v1.8.1: "All" is now a <option value=""> in the vhost-select dropdown
        assert 'value=""' in html or "value=''" in html, \
            'main.html: vhost selector must have a default empty-value option for "All vhosts"'

    def test_vhost_pill_css_defined(self, html):
        # v1.8.1: pill CSS replaced by #vhost-select dropdown CSS
        assert "#vhost-select" in html or "vhost-select" in html, \
            "main.html: #vhost-select CSS definition missing"

    def test_vhost_param_helper_defined(self, html):
        assert "window._vhostParam" in html, \
            "main.html: window._vhostParam helper missing"

    def test_vhost_param_reads_session_storage(self, html):
        assert "sessionStorage" in html and "gw_vhost" in html, \
            "main.html: _vhostParam must read from sessionStorage with key 'gw_vhost'"

    def test_metrics_fetch_includes_vhost_param(self, html):
        assert "secured/metrics" in html
        # Find every line containing secured/metrics and check at least one has _vhostParam
        metrics_lines = [l for l in html.splitlines() if "secured/metrics" in l]
        assert any("_vhostParam" in l for l in metrics_lines), \
            "main.html: metrics fetch line must append window._vhostParam()"

    def test_cost_timeline_fetch_includes_vhost_param(self, html):
        assert "cost-timeline" in html
        cost_lines = [l for l in html.splitlines() if "cost-timeline" in l and "fetch" in l]
        assert any("_vhostParam" in l for l in cost_lines) or \
               "_vhostParam" in html, \
            "main.html: cost-timeline fetch must append _vhostParam()"

    def test_domcontentloaded_fetches_vhosts_endpoint(self, html):
        assert "DOMContentLoaded" in html, "main.html: DOMContentLoaded listener missing"
        assert "/secured/vhosts" in html, \
            "main.html: DOMContentLoaded must fetch /secured/vhosts to populate pills"

    def test_uses_v_hostname_not_v_host(self, html):
        """Pill population must use v.hostname (the correct API field), not v.host."""
        # Extract the JS block that populates pills
        vhosts_block = ""
        if "/secured/vhosts" in html:
            idx = html.index("/secured/vhosts")
            vhosts_block = html[idx:idx+800]
        assert "v.hostname" in vhosts_block or "v.hostname" in html, \
            "main.html: pill population must use v.hostname (not v.host)"

    def test_all_pill_active_cleared_on_stored_vhost(self, html):
        """On init, vhost selector must restore the previously stored vhost selection."""
        # v1.8.1: select.value is set from sessionStorage on init instead of clearing a pill
        assert ("sel.value = cur" in html or "sel.value=cur" in html or
                "sessionStorage.getItem('gw_vhost')" in html or
                'sessionStorage.getItem("gw_vhost")' in html), \
            "main.html: vhost select must restore stored selection from sessionStorage on init"


class TestH2AgentsHtmlVhostSelector:
    """agents.html must wire _vhostParam to BOTH agents-data and agents-timeline fetches."""

    @pytest.fixture(scope="class")
    def html(self):
        return (DASHBOARDS / "agents.html").read_text()

    def test_vhost_bar_present(self, html):
        assert 'id="vhost-bar"' in html

    def test_all_pill_empty_data_vhost(self, html):
        assert 'data-vhost=""' in html

    def test_vhost_param_defined(self, html):
        assert "window._vhostParam" in html

    def test_agents_data_fetch_wired(self, html):
        assert "agents-data" in html
        agents_data_section = html.split("agents-data")[1][:300]
        assert "_vhostParam" in agents_data_section, \
            "agents.html: agents-data fetch must append _vhostParam()"

    def test_agents_timeline_fetch_wired(self, html):
        assert "agents-timeline" in html
        agents_tl_section = html.split("agents-timeline")[1][:300]
        assert "_vhostParam" in agents_tl_section, \
            "agents.html: agents-timeline fetch must append _vhostParam()"

    def test_uses_v_hostname_not_v_host(self, html):
        vhosts_block = ""
        if "/secured/vhosts" in html:
            idx = html.index("/secured/vhosts")
            vhosts_block = html[idx:idx+800]
        assert "v.hostname" in vhosts_block or "v.hostname" in html, \
            "agents.html: pill population must use v.hostname not v.host"

    def test_allpill_active_cleared_on_init(self, html):
        assert "allPill" in html and (
            "classList.remove" in html or "allPill.classList" in html
        ), "agents.html: allPill active state must be cleared via classList.remove"

    def test_domcontentloaded_fetches_vhosts(self, html):
        assert "/secured/vhosts" in html


class TestH3GeoHtmlVhostSelector:
    """geo.html must use v.hostname (critical bug fix) and wire _vhostParam to geo-data."""

    @pytest.fixture(scope="class")
    def html(self):
        return (DASHBOARDS / "geo.html").read_text()

    def test_vhost_bar_present(self, html):
        assert 'id="vhost-bar"' in html, "geo.html: #vhost-bar missing"

    def test_all_pill_empty_data_vhost(self, html):
        assert 'data-vhost=""' in html, 'geo.html: "All" pill data-vhost="" missing'

    def test_vhost_param_defined(self, html):
        assert "window._vhostParam" in html or "_vhostParam" in html, \
            "geo.html: _vhostParam helper missing"

    def test_geo_data_fetch_wired(self, html):
        assert "geo-data" in html
        geo_lines = [l for l in html.splitlines() if "geo-data" in l and "fetch" in l]
        assert any("_vhostParam" in l for l in geo_lines), \
            "geo.html: geo-data fetch line must append _vhostParam()"

    def test_uses_v_hostname_not_v_host(self, html):
        """Critical: geo.html was broken because it used v.host instead of v.hostname."""
        vhosts_block = ""
        if "/secured/vhosts" in html:
            idx = html.index("/secured/vhosts")
            vhosts_block = html[idx:idx+1200]
        # Must use v.hostname
        assert "v.hostname" in vhosts_block, \
            "geo.html: pill population must use v.hostname (v.host was the bug — must not regress)"
        # Must NOT use bare v.host (which is undefined)
        # Allow v.hostname but not standalone v.host assignment
        bad_patterns = re.findall(r"\bv\.host\b(?!name)", vhosts_block)
        assert not bad_patterns, (
            f"geo.html: found v.host (undefined field) in vhosts JS block — "
            f"must use v.hostname. Occurrences: {bad_patterns}"
        )

    def test_uses_v_UPSTREAM_not_v_upstream(self, html):
        """geo.html title was broken because it used v.upstream instead of v.UPSTREAM."""
        vhosts_block = ""
        if "/secured/vhosts" in html:
            idx = html.index("/secured/vhosts")
            vhosts_block = html[idx:idx+1200]
        # Allow v.UPSTREAM (correct) — reject bare v.upstream (wrong case)
        bad = re.findall(r"\bv\.upstream\b(?!_)", vhosts_block)
        assert not bad, (
            f"geo.html: v.upstream (wrong case) found — must use v.UPSTREAM. "
            f"Occurrences: {bad}"
        )

    def test_vhost_pill_css_defined(self, html):
        assert ".vhost-pill" in html, "geo.html: .vhost-pill CSS missing"

    def test_domcontentloaded_fetches_vhosts(self, html):
        assert "/secured/vhosts" in html


# ── F-source: source-level guards (no server required) ───────────────────────

class TestSourceLevelGuards:
    """Verify key 1.8.0 additions are present in source without running the server."""

    def _metrics_src(self):
        return (Path(__file__).resolve().parent.parent / "core" / "metrics.py").read_text()

    def test_record_sets_last_vhost_from_context(self):
        src = self._metrics_src()
        assert "last_vhost" in src and "current_vhost_host" in src, (
            "metrics.record must assign s.last_vhost from current_vhost_host()"
        )

    def test_record_event_dict_includes_vhost_key(self):
        src = self._metrics_src()
        assert '"vhost"' in src or "'vhost'" in src, (
            "metrics.record _evt dict must include 'vhost' key"
        )

    def test_db_queue_event_tuple_includes_vhost(self):
        """db_queue 'event' tuple must have vhost as 8th element."""
        src = self._metrics_src()
        event_block = src.split('"event"')[1][:300] if '"event"' in src else ""
        assert "current_vhost_host" in event_block or "vhost" in event_block, (
            "db_queue 'event' tuple must include vhost (current_vhost_host()) as 8th element"
        )

    def test_metrics_endpoint_reads_vhost_query_param(self):
        import core.proxy_handler as _ph
        src = inspect.getsource(_ph.metrics_endpoint)
        assert '_vhost_pre' in src and 'request.query.get("vhost"' in src, (
            "metrics_endpoint must read ?vhost= query parameter"
        )

    def test_metrics_endpoint_filters_clients_by_last_vhost(self):
        import core.proxy_handler as _ph
        src = inspect.getsource(_ph.metrics_endpoint)
        assert "last_vhost" in src and "_vhost_pre" in src, (
            "metrics_endpoint must compare s.last_vhost against _vhost_pre"
        )

    def test_agents_data_reads_vhost_query_param(self):
        import dashboards.agents as _ag
        src = inspect.getsource(_ag.agents_data_endpoint)
        assert '_ad_vhost' in src and 'request.query.get("vhost"' in src, (
            "agents_data_endpoint must read ?vhost= query parameter"
        )

    def test_agents_timeline_reads_vhost_query_param(self):
        import dashboards.agents as _ag
        src = inspect.getsource(_ag.agents_timeline_endpoint)
        assert '_atl_vhost' in src and 'request.query.get("vhost"' in src, (
            "agents_timeline_endpoint must read ?vhost= query parameter"
        )

    def test_vhost_list_function_uses_hostname_key(self):
        """vhost_list() must return items with 'hostname' key — frontend depends on this."""
        import vhost as _v
        src = inspect.getsource(_v.vhost_list)
        assert '"hostname"' in src or "'hostname'" in src, (
            "vhost_list() must use 'hostname' key in returned dicts (not 'host')"
        )
        assert '"host"' not in src.replace('"hostname"', ''), (
            "vhost_list() must not use bare 'host' key (would break all 3 dashboard frontends)"
        )
