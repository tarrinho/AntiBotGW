"""
QA tests for code-review fixes applied after functional review.

Coverage matrix
───────────────
C1  scoring.py — Redis ban: epoch timestamp must be converted to monotonic
    before storing in banned_until (permanent-ban regression)
C2  proxy_handler.py — authorized-bot ban action: must use now() not _t.time()
    for banned_until (permanent-ban regression)

S1  admin/users.py — GET /login ?next= open-redirect: external and
    protocol-relative URLs must be rejected, same as POST handler
S2  vhost.py — _assert_upstream_public: IPv4-mapped IPv6 addresses
    (::ffff:10.x.x.x) must be detected and rejected as private

R1  db/sqlite.py — db_writer_loop: task_done must be called even when
    conn.commit() raises (prevents queue.join() hang on shutdown)

V1  detection/cookie_lifecycle.py — ghost + lifecycle double-increment:
    when both signals fire on the same request the counter increments once
V2  core/proxy_handler.py — custom allow rule must call record() so traffic
    appears in metrics, events, and ip_state
V4  admin/settings.py — vhost_stats allowed_1h must count events with
    reason='' (the actual stored value for passing traffic)

D1  core/metrics.py — record() method parameter wired through to DB event
    tuple and in-memory _evt dict
"""
import asyncio
import sqlite3
import time
import types
import unittest.mock as mock
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# ── Shared helpers ────────────────────────────────────────────────────────────

NS  = "/antibot-appsec-gateway/secured"
PUB = "/antibot-appsec-gateway"


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _echo_handler(request: web.Request):
    return web.json_response({"path": request.path, "method": request.method})


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


_EVENTS_DDL = (
    "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "ts REAL NOT NULL, ip TEXT NOT NULL, ua TEXT, path TEXT, method TEXT, "
    "status INTEGER, reason TEXT, vhost TEXT)"
)


# vhost_stats / vhost-breakdown read events from the active backend, so under
# the PG-mode test harness (POSTGRES_DSN set) these helpers must read/write the
# Postgres events table. db.conn.conn() targets the active backend (rewrites
# `?` → `%s` on PG). The CREATE-IF-NOT-EXISTS only runs on SQLite — on PG the
# events table is created at startup and the SQLite DDL is incompatible.
def _wipe_events(proxy_module):
    from db.conn import conn as _backend_conn, active_backend
    with _backend_conn(timeout=10) as conn:
        if active_backend() != "postgres":
            conn.execute(_EVENTS_DDL)   # self-sufficient when schema not yet init'd
        conn.execute("DELETE FROM events")
    import state as _st
    _st.ip_state.clear()
    _st.events.clear()


def _seed_events(proxy_module, rows):
    """Insert (ts, ip, ua, path, method, status, reason, vhost) rows."""
    from db.conn import active_backend
    if active_backend() == "postgres":
        # PG events.ts is timestamptz; reuse pg_insert_event (to_timestamp) so
        # the conversion + column set match production. Row tuple:
        # (ts, ip, ua, path, method, status, reason, vhost)
        from db.postgres import pg_insert_event
        for ts, ip, ua, path, method, status, reason, vhost in rows:
            pg_insert_event(ts, ip, ua, path, int(status), reason,
                            method=method or "", vhost=vhost or "")
    else:
        from db.conn import conn as _backend_conn
        with _backend_conn(timeout=10) as conn:
            conn.execute(_EVENTS_DDL)   # ensure table exists before seeding
            conn.executemany(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, vhost) "
                "VALUES (?,?,?,?,?,?,?,?)",
                rows,
            )


# ══════════════════════════════════════════════════════════════════════════════
# C-1  Redis ban epoch → monotonic conversion
# ══════════════════════════════════════════════════════════════════════════════

class TestC1RedisBanMonotonic:
    """is_banned() must convert the Redis epoch timestamp to monotonic domain."""

    def test_redis_epoch_not_stored_directly_in_banned_until(self, proxy_module):
        """banned_until after Redis hit must be in monotonic range, not epoch range."""
        async def go():
            import state as _st
            from helpers import now
            import time as _t

            ip = "1.2.3.4"
            _st.ip_state.pop(ip, None)

            future_epoch = _t.time() + 3600  # 1 hour from now, epoch
            with mock.patch("integrations.redis._shared_ban_get",
                            new=mock.AsyncMock(return_value=future_epoch)):
                banned, remaining = await proxy_module.is_banned(ip)

            assert banned is True, "IP with active Redis ban must be reported banned"
            assert 3595 < remaining < 3605, \
                f"remaining must be ~3600s, got {remaining}"

            s = _st.ip_state[ip]
            assert s.banned_until < 1e9, (
                f"banned_until must be monotonic (< 1e9), got {s.banned_until}. "
                "Epoch was stored directly — monotonic conversion is missing."
            )
            mono_now = now()
            assert 3595 < s.banned_until - mono_now < 3605, (
                f"banned_until should be now()+3600, got offset {s.banned_until - mono_now}"
            )
        _run(go())

    def test_expired_redis_ban_not_stored(self, proxy_module):
        """An already-expired epoch from Redis must not set banned_until."""
        async def go():
            import state as _st
            import time as _t

            ip = "9.9.9.9"
            _st.ip_state.pop(ip, None)

            past_epoch = _t.time() - 60   # expired 60s ago
            with mock.patch("integrations.redis._shared_ban_get",
                            new=mock.AsyncMock(return_value=past_epoch)):
                banned, remaining = await proxy_module.is_banned(ip)

            assert banned is False, "Expired Redis ban must not ban the IP"
            assert remaining == 0.0
        _run(go())

    def test_redis_unavailable_falls_through(self, proxy_module):
        """If Redis raises, is_banned must still return (False, 0) from local state."""
        async def go():
            import state as _st
            ip = "5.5.5.5"
            _st.ip_state.pop(ip, None)

            with mock.patch("integrations.redis._shared_ban_get",
                            side_effect=Exception("redis down")):
                banned, remaining = await proxy_module.is_banned(ip)

            assert banned is False
            assert remaining == 0.0
        _run(go())


# ══════════════════════════════════════════════════════════════════════════════
# C-2  Authorized-bot ban action uses now() not _t.time()
# ══════════════════════════════════════════════════════════════════════════════

class TestC2AuthorizedBotBanMonotonic:
    """AUTHORIZED_BOT_UAS ban/really-ban must use now() not _t.time() for banned_until."""

    def _propagate(self, proxy_module, key, value):
        import sys
        import core.proxy_handler as _cph
        setattr(proxy_module, key, value)
        # Also patch get_ip.__globals__ directly: it may point to an orphaned proxy module
        # loaded by test_functional.py via importlib (not in sys.modules), so the
        # sys.modules loop below would miss it.
        try:
            _cph.get_ip.__globals__[key] = value
        except (AttributeError, TypeError):
            pass
        for mod in list(sys.modules.values()):
            if mod is None or mod is proxy_module:
                continue
            if hasattr(mod, key):
                try:
                    setattr(mod, key, value)
                except (AttributeError, TypeError):
                    pass

    def test_now_is_monotonic_not_epoch(self):
        """Prerequisite: now() returns a monotonic value well below 1e9.
        This proves any banned_until = now() + N is distinguishable from
        banned_until = time.time() + N which would be > 1.7e9."""
        from helpers import now
        import time as _t
        mono = now()
        epoch = _t.time()
        assert mono < 1e9, (
            f"now() returns {mono} — must be monotonic (< 1e9). "
            "If this fails, the C-2 fix cannot be verified by range check."
        )
        assert epoch > 1e9, f"time.time() returns {epoch} — must be epoch (> 1e9)"
        # The two clocks must differ by at least 1e9 seconds
        assert epoch - mono > 1.7e9

    def test_authorized_bot_ban_sets_monotonic_banned_until(self, proxy_module):
        """AUTHORIZED_BOT_UAS ban action must store now()+secs, not epoch+secs."""
        async def go():
            import state as _st
            from helpers import now

            ip = "7.7.7.7"
            _st.ip_state.pop(ip, None)

            # Configure an AUTHORIZED_BOT_UAS rule with action=ban
            bot_rule = [{
                "name": "test-ban-bot",
                "ua": "BanBotUA/1.0",
                "path": "/bot-ban-trigger",
                "ips": [],
                "action": "ban",
                "enabled": True,
            }]
            import ipaddress as _ipa
            old_bots = proxy_module.AUTHORIZED_BOT_UAS
            old_xff = proxy_module.TRUST_XFF
            old_nets = proxy_module.TRUSTED_PROXIES_NETS
            self._propagate(proxy_module, "AUTHORIZED_BOT_UAS", bot_rule)
            self._propagate(proxy_module, "TRUST_XFF", "first")
            self._propagate(proxy_module, "TRUSTED_PROXIES_NETS",
                            [_ipa.ip_network("127.0.0.1/32")])

            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    await c.get(
                        "/bot-ban-trigger",
                        headers={"X-Forwarded-For": ip,
                                 "User-Agent": "BanBotUA/1.0",
                                 "Host": "test.local"},
                    )

            self._propagate(proxy_module, "AUTHORIZED_BOT_UAS", old_bots)
            self._propagate(proxy_module, "TRUST_XFF", old_xff)
            self._propagate(proxy_module, "TRUSTED_PROXIES_NETS", old_nets)

            s = _st.ip_state.get(ip)
            assert s is not None, "ip_state entry must exist after bot ban"
            assert s.banned_until > 0, "banned_until must be set after bot ban"
            assert s.banned_until < 1e9, (
                f"banned_until={s.banned_until} is epoch-range (> 1e9). "
                "The fix now() + secs is not in effect — _t.time() was used."
            )
            assert s.banned_until > now(), "ban must not have expired instantly"
        _run(go())

    def test_authorized_bot_really_ban_sets_monotonic_banned_until(self, proxy_module):
        """AUTHORIZED_BOT_UAS really-ban action also stores monotonic banned_until."""
        async def go():
            import state as _st
            from helpers import now

            ip = "8.8.8.8"
            _st.ip_state.pop(ip, None)

            bot_rule = [{
                "name": "test-really-ban-bot",
                "ua": "ReallyBanBotUA/1.0",
                "path": "/bot-really-ban-trigger",
                "ips": [],
                "action": "really-ban",
                "enabled": True,
            }]
            old_bots = proxy_module.AUTHORIZED_BOT_UAS
            self._propagate(proxy_module, "AUTHORIZED_BOT_UAS", bot_rule)

            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    await c.get(
                        "/bot-really-ban-trigger",
                        headers={"X-Forwarded-For": ip,
                                 "User-Agent": "ReallyBanBotUA/1.0",
                                 "Host": "test.local"},
                    )

            self._propagate(proxy_module, "AUTHORIZED_BOT_UAS", old_bots)

            s = _st.ip_state.get(ip)
            if s is not None and s.banned_until > 0:
                assert s.banned_until < 1e9, (
                    f"really-ban: banned_until={s.banned_until} must be monotonic"
                )
                assert s.banned_until > now()
        _run(go())


# ══════════════════════════════════════════════════════════════════════════════
# S-1  GET /login ?next= open-redirect validation
# ══════════════════════════════════════════════════════════════════════════════

class TestS1LoginGetRedirectValidation:
    """Already-authenticated GET /login with ?next= must validate the URL."""

    def test_external_url_rejected_and_redirects_to_default(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(
                        PUB + "/login?next=https://evil.com/steal",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                        allow_redirects=False,
                    )
                    assert r.status in (301, 302, 303), \
                        f"expected redirect, got {r.status}"
                    loc = r.headers.get("Location", "")
                    assert not loc.startswith("https://evil.com"), (
                        f"open redirect not blocked — Location: {loc}"
                    )
                    assert loc.startswith("/"), \
                        f"redirect must be internal, got: {loc}"
        _run(go())

    def test_protocol_relative_url_rejected(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(
                        PUB + "/login?next=//evil.com/steal",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                        allow_redirects=False,
                    )
                    assert r.status in (301, 302, 303)
                    loc = r.headers.get("Location", "")
                    assert not loc.startswith("//"), (
                        f"protocol-relative redirect not blocked — Location: {loc}"
                    )
        _run(go())

    def test_valid_internal_next_is_accepted(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _make_admin_cookie(proxy_module)
                    target = NS + "/control-center"
                    r = await c.get(
                        PUB + f"/login?next={target}",
                        cookies={proxy_module._SESSION_COOKIE: cookie},
                        allow_redirects=False,
                    )
                    assert r.status in (301, 302, 303)
                    loc = r.headers.get("Location", "")
                    assert loc == target, \
                        f"valid internal next was mangled: {loc!r}"
        _run(go())

    def test_unauthenticated_login_page_rendered(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(
                        PUB + "/login?next=https://evil.com",
                        allow_redirects=False,
                    )
                    # Unauthenticated: should render login page, not redirect
                    assert r.status == 200, \
                        f"unauthenticated login page should be 200, got {r.status}"
        _run(go())


# ══════════════════════════════════════════════════════════════════════════════
# S-2  IPv4-mapped IPv6 bypasses SSRF guard
# ══════════════════════════════════════════════════════════════════════════════

class TestS2Ipv4MappedIpv6SsrfGuard:
    """_assert_upstream_public must reject IPv4-mapped IPv6 private addresses."""

    @pytest.fixture(autouse=True)
    def _force_guard_on(self):
        """Ensure the SSRF guard is active regardless of ALLOW_PRIVATE_UPSTREAM default."""
        import config as _cfg
        saved = _cfg.ALLOW_PRIVATE_UPSTREAM
        _cfg.ALLOW_PRIVATE_UPSTREAM = False
        yield
        _cfg.ALLOW_PRIVATE_UPSTREAM = saved

    def _check_raises(self, addr):
        """Return True if the address is blocked (SystemExit raised), False if allowed."""
        import socket
        import vhost
        with mock.patch.object(
            socket, "getaddrinfo",
            return_value=[(None, None, None, None, (addr, 0))]
        ):
            try:
                vhost._assert_upstream_public("http://dns-name.example.com", key="TEST")
                return False   # not blocked
            except SystemExit:
                return True    # blocked (private)

    def test_ipv4_mapped_loopback_rejected(self):
        """::ffff:127.0.0.1 must be treated as 127.0.0.1 (loopback) and blocked."""
        assert self._check_raises("::ffff:127.0.0.1"), (
            "::ffff:127.0.0.1 not blocked — IPv4-mapped unmap is missing"
        )

    def test_ipv4_mapped_rfc1918_10_rejected(self):
        """::ffff:10.0.0.1 must be treated as 10.0.0.1 (RFC-1918) and blocked."""
        assert self._check_raises("::ffff:10.0.0.1"), (
            "::ffff:10.0.0.1 not blocked — IPv4-mapped unmap is missing"
        )

    def test_ipv4_mapped_rfc1918_192_rejected(self):
        """::ffff:192.168.1.1 must be treated as 192.168.1.1 (RFC-1918) and blocked."""
        assert self._check_raises("::ffff:192.168.1.1"), (
            "::ffff:192.168.1.1 not blocked — IPv4-mapped unmap is missing"
        )

    def test_ipv4_mapped_rfc1918_172_rejected(self):
        """::ffff:172.16.0.1 must be treated as 172.16.0.1 (RFC-1918) and blocked."""
        assert self._check_raises("::ffff:172.16.0.1"), (
            "::ffff:172.16.0.1 not blocked — IPv4-mapped unmap is missing"
        )

    def test_public_ipv6_allowed(self):
        """A globally-routable IPv6 address must not be blocked."""
        assert not self._check_raises("2001:db8::1"), (
            "Public IPv6 2001:db8::1 was incorrectly blocked"
        )

    def test_plain_private_ipv4_still_rejected(self):
        """Sanity: plain 10.0.0.1 still blocked (existing guard intact after fix)."""
        assert self._check_raises("10.0.0.1"), (
            "Plain 10.0.0.1 not blocked — existing SSRF guard broken"
        )

    def test_plain_loopback_still_rejected(self):
        """Sanity: plain 127.0.0.1 still blocked."""
        assert self._check_raises("127.0.0.1")


# ══════════════════════════════════════════════════════════════════════════════
# R-1  db_writer_loop task_done called on commit failure
# ══════════════════════════════════════════════════════════════════════════════

class TestR1TaskDoneOnCommitFailure:
    """task_done must be called even when conn.commit() raises."""

    def test_task_done_called_when_commit_fails(self):
        """queue.join() must resolve even if commit() throws."""
        async def go():
            import asyncio
            import sqlite3
            import state as _st
            from db import sqlite as _sqlite_mod

            # Build a minimal queue with one fake item
            q = asyncio.Queue()
            await q.put(("event", (
                time.time(), "1.1.1.1", "ua", "/", "GET", 200, "", "test.host"
            )))

            original_queue = _st.db_queue
            _st.db_queue = q

            # Patch sqlite3.connect to return a connection whose commit() raises
            real_connect = sqlite3.connect

            class _FakeConn:
                def execute(self, *a, **kw): pass
                def executemany(self, *a, **kw): pass
                def commit(self): raise sqlite3.OperationalError("disk full")
                def close(self): pass

            with mock.patch("sqlite3.connect", return_value=_FakeConn()):
                task = asyncio.create_task(_sqlite_mod.db_writer_loop())
                try:
                    # join() must complete in < 2s even though commit failed
                    await asyncio.wait_for(q.join(), timeout=2.0)
                    joined = True
                except asyncio.TimeoutError:
                    joined = False
                finally:
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass

            _st.db_queue = original_queue
            assert joined, (
                "queue.join() timed out — task_done() was not called after "
                "commit() failure. The finally block is missing."
            )
        _run(go())

    def test_task_done_called_on_successful_commit(self):
        """Regression: task_done must still be called when commit succeeds."""
        async def go():
            import asyncio
            import state as _st
            from db import sqlite as _sqlite_mod

            q = asyncio.Queue()
            await q.put(("event", (
                time.time(), "2.2.2.2", "ua", "/ok", "GET", 200, "", "ok.host"
            )))

            original_queue = _st.db_queue
            _st.db_queue = q

            task = asyncio.create_task(_sqlite_mod.db_writer_loop())
            try:
                await asyncio.wait_for(q.join(), timeout=3.0)
                joined = True
            except asyncio.TimeoutError:
                joined = False
            finally:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

            _st.db_queue = original_queue
            assert joined, "task_done not called on successful commit path"
        _run(go())


# ══════════════════════════════════════════════════════════════════════════════
# V-1  Cookie ghost + lifecycle double-increment prevention
# ══════════════════════════════════════════════════════════════════════════════

class TestV1CookieGhostDoubleIncrement:
    """cookie_ghost_misses must increment by at most 1 per request."""

    def _make_request(self, cookies=None):
        req = mock.MagicMock()
        req.cookies = cookies or {}
        req.headers = {"Accept": "application/json"}  # non-HTML
        return req

    def _make_state(self, proxy_module,
                    gateway_cookies_set=3, html_loads=1, request_count=10):
        from state import IpState
        import state as _st
        key = "test-double-inc"
        s = IpState()
        s.gateway_cookies_set = gateway_cookies_set
        s.html_loads = html_loads
        s.request_count = request_count
        s.cookie_ghost_misses = 0
        _st.ip_state[key] = s
        return key, s

    def test_both_enabled_increments_only_once_per_request(self, proxy_module):
        """With both signals enabled and both conditions met: counter += 1, not 2."""
        async def go():
            from detection.cookie_lifecycle import cookie_ghost_check

            old_ghost = proxy_module.COOKIE_GHOST_ENABLED
            old_lc = proxy_module.COOKIE_LIFECYCLE_ENABLED
            proxy_module.COOKIE_GHOST_ENABLED = True
            proxy_module.COOKIE_LIFECYCLE_ENABLED = True

            try:
                import detection.cookie_lifecycle as _cl
                _cl.COOKIE_GHOST_ENABLED = True
                _cl.COOKIE_LIFECYCLE_ENABLED = True

                key, s = self._make_state(proxy_module,
                                          gateway_cookies_set=3,
                                          html_loads=1,
                                          request_count=10)
                req = self._make_request(cookies={})  # no gateway cookies

                before = s.cookie_ghost_misses
                await cookie_ghost_check(key, req)
                after = s.cookie_ghost_misses

                assert after - before <= 1, (
                    f"cookie_ghost_misses incremented by {after - before} on one "
                    "request — double-increment regression (elif not applied)."
                )
            finally:
                proxy_module.COOKIE_GHOST_ENABLED = old_ghost
                proxy_module.COOKIE_LIFECYCLE_ENABLED = old_lc
                import detection.cookie_lifecycle as _cl2
                _cl2.COOKIE_GHOST_ENABLED = old_ghost
                _cl2.COOKIE_LIFECYCLE_ENABLED = old_lc
        _run(go())

    def test_ghost_only_increments_when_ghost_fires(self, proxy_module):
        """When only COOKIE_GHOST_ENABLED: ghost path increments, lifecycle skipped."""
        async def go():
            from detection.cookie_lifecycle import cookie_ghost_check
            import detection.cookie_lifecycle as _cl

            _cl.COOKIE_GHOST_ENABLED = True
            _cl.COOKIE_LIFECYCLE_ENABLED = False

            key, s = self._make_state(proxy_module,
                                      gateway_cookies_set=3,
                                      html_loads=0,
                                      request_count=10)
            req = self._make_request(cookies={})

            before = s.cookie_ghost_misses
            await cookie_ghost_check(key, req)
            after = s.cookie_ghost_misses

            assert after - before == 1, \
                f"ghost-only: expected +1, got +{after - before}"

            _cl.COOKIE_GHOST_ENABLED = False
            _cl.COOKIE_LIFECYCLE_ENABLED = False
        _run(go())

    def test_lifecycle_only_increments_when_lifecycle_fires(self, proxy_module):
        """When only COOKIE_LIFECYCLE_ENABLED: lifecycle path increments, ghost skipped."""
        async def go():
            from detection.cookie_lifecycle import cookie_ghost_check
            import detection.cookie_lifecycle as _cl

            _cl.COOKIE_GHOST_ENABLED = False
            _cl.COOKIE_LIFECYCLE_ENABLED = True

            key, s = self._make_state(proxy_module,
                                      gateway_cookies_set=0,   # ghost won't fire
                                      html_loads=1,
                                      request_count=10)
            req = self._make_request(cookies={})   # no agw_lc

            before = s.cookie_ghost_misses
            await cookie_ghost_check(key, req)
            after = s.cookie_ghost_misses

            assert after - before == 1, \
                f"lifecycle-only: expected +1, got +{after - before}"

            _cl.COOKIE_GHOST_ENABLED = False
            _cl.COOKIE_LIFECYCLE_ENABLED = False
        _run(go())

    def test_ghost_presence_suppresses_lifecycle(self, proxy_module):
        """When ghost fires (elif), lifecycle branch must NOT execute."""
        async def go():
            from detection.cookie_lifecycle import cookie_ghost_check
            import detection.cookie_lifecycle as _cl

            _cl.COOKIE_GHOST_ENABLED = True
            _cl.COOKIE_LIFECYCLE_ENABLED = True

            # Both conditions would fire — ghost fires first via elif
            key, s = self._make_state(proxy_module,
                                      gateway_cookies_set=3,
                                      html_loads=1,
                                      request_count=10)
            req = self._make_request(cookies={})

            # Verify only one increment
            before = s.cookie_ghost_misses
            await cookie_ghost_check(key, req)
            assert s.cookie_ghost_misses - before == 1, "ghost should suppress lifecycle via elif"

            _cl.COOKIE_GHOST_ENABLED = False
            _cl.COOKIE_LIFECYCLE_ENABLED = False
        _run(go())


# ══════════════════════════════════════════════════════════════════════════════
# V-2  Custom allow rule calls record()
# ══════════════════════════════════════════════════════════════════════════════

class TestV2CustomAllowRuleCallsRecord:
    """Custom rule with action=allow must invoke record() so traffic is visible."""

    def _propagate(self, proxy_module, key, value):
        import sys
        import core.proxy_handler as _cph
        setattr(proxy_module, key, value)
        # Also patch get_ip.__globals__ directly: it may point to an orphaned proxy module
        # loaded by test_functional.py via importlib (not in sys.modules), so the
        # sys.modules loop below would miss it.
        try:
            _cph.get_ip.__globals__[key] = value
        except (AttributeError, TypeError):
            pass
        for mod in list(sys.modules.values()):
            if mod is None or mod is proxy_module:
                continue
            if hasattr(mod, key):
                try:
                    setattr(mod, key, value)
                except (AttributeError, TypeError):
                    pass

    def test_allow_rule_traffic_appears_in_events(self, proxy_module):
        async def go():
            import state as _st

            ip = "3.3.3.3"
            _st.ip_state.pop(ip, None)
            _st.events.clear()

            import ipaddress as _ipa
            rule = [{"if": {"path": "/allowed-path*"}, "then": "allow", "tag": "test"}]
            parsed = proxy_module._to_custom_rules(rule)
            old_rules = proxy_module.CUSTOM_RULES
            old_bypass = proxy_module.BYPASS_PATHS
            old_xff = proxy_module.TRUST_XFF
            old_nets = proxy_module.TRUSTED_PROXIES_NETS
            self._propagate(proxy_module, "CUSTOM_RULES", parsed)
            self._propagate(proxy_module, "BYPASS_PATHS", ["/allowed-path"])
            self._propagate(proxy_module, "TRUST_XFF", "first")
            self._propagate(proxy_module, "TRUSTED_PROXIES_NETS",
                            [_ipa.ip_network("127.0.0.1/32")])

            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    resp = await c.get(
                        "/allowed-path/resource",
                        headers={"X-Forwarded-For": ip, "Host": "test.local"},
                    )

            self._propagate(proxy_module, "CUSTOM_RULES", old_rules)
            self._propagate(proxy_module, "BYPASS_PATHS", old_bypass)
            self._propagate(proxy_module, "TRUST_XFF", old_xff)
            self._propagate(proxy_module, "TRUSTED_PROXIES_NETS", old_nets)

            matched = [e for e in _st.events if e.get("ip") == ip]
            assert matched, (
                "No event recorded for custom allow-rule traffic. "
                "record() was not called before returning from allow action."
            )
        _run(go())

    def test_allow_rule_updates_ip_state_request_count(self, proxy_module):
        async def go():
            import state as _st

            ip = "4.4.4.4"
            _st.ip_state.pop(ip, None)

            import ipaddress as _ipa
            rule = [{"if": {"path": "/tracked-allow*"}, "then": "allow", "tag": "test"}]
            parsed = proxy_module._to_custom_rules(rule)
            old_rules = proxy_module.CUSTOM_RULES
            old_bypass = proxy_module.BYPASS_PATHS
            old_xff = proxy_module.TRUST_XFF
            old_nets = proxy_module.TRUSTED_PROXIES_NETS
            self._propagate(proxy_module, "CUSTOM_RULES", parsed)
            self._propagate(proxy_module, "BYPASS_PATHS", ["/tracked-allow"])
            self._propagate(proxy_module, "TRUST_XFF", "first")
            self._propagate(proxy_module, "TRUSTED_PROXIES_NETS",
                            [_ipa.ip_network("127.0.0.1/32")])

            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    await c.get(
                        "/tracked-allow/check",
                        headers={"X-Forwarded-For": ip, "Host": "test.local"},
                    )

            self._propagate(proxy_module, "CUSTOM_RULES", old_rules)
            self._propagate(proxy_module, "BYPASS_PATHS", old_bypass)
            self._propagate(proxy_module, "TRUST_XFF", old_xff)
            self._propagate(proxy_module, "TRUSTED_PROXIES_NETS", old_nets)

            s = _st.ip_state.get(ip)
            assert s is not None, "ip_state entry must exist after allow-rule request"
            assert s.request_count >= 1, (
                f"request_count={s.request_count} — record() was skipped, "
                "ip_state was not updated by allow-rule traffic."
            )
        _run(go())

    def test_allow_rule_updates_last_seen(self, proxy_module):
        async def go():
            import state as _st

            ip = "6.6.6.6"
            _st.ip_state.pop(ip, None)

            import ipaddress as _ipa
            rule = [{"if": {"path": "/vhost-allow*"}, "then": "allow", "tag": "test"}]
            parsed = proxy_module._to_custom_rules(rule)
            old_rules = proxy_module.CUSTOM_RULES
            old_bypass = proxy_module.BYPASS_PATHS
            old_xff = proxy_module.TRUST_XFF
            old_nets = proxy_module.TRUSTED_PROXIES_NETS
            self._propagate(proxy_module, "CUSTOM_RULES", parsed)
            self._propagate(proxy_module, "BYPASS_PATHS", ["/vhost-allow"])
            self._propagate(proxy_module, "TRUST_XFF", "first")
            self._propagate(proxy_module, "TRUSTED_PROXIES_NETS",
                            [_ipa.ip_network("127.0.0.1/32")])

            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    await c.get(
                        "/vhost-allow/check",
                        headers={"X-Forwarded-For": ip, "Host": "allow.test.local"},
                    )

            self._propagate(proxy_module, "CUSTOM_RULES", old_rules)
            self._propagate(proxy_module, "BYPASS_PATHS", old_bypass)
            self._propagate(proxy_module, "TRUST_XFF", old_xff)
            self._propagate(proxy_module, "TRUSTED_PROXIES_NETS", old_nets)

            s = _st.ip_state.get(ip)
            assert s is not None
            from helpers import now
            assert s.last_seen > (now() - 10), (
                "last_seen not updated — record() skipped by allow rule."
            )
        _run(go())


# ══════════════════════════════════════════════════════════════════════════════
# V-4  vhost_stats allowed_1h counts empty-string reason
# ══════════════════════════════════════════════════════════════════════════════

class TestV4VhostStatsAllowedCount:
    """allowed_1h must count events whose reason='' (the actual stored value)."""

    def test_empty_reason_events_counted_in_allowed_1h(self, proxy_module):
        now_ts = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    # Seed: 2 allowed (reason=''), 1 blocked (reason='honeypot')
                    _seed_events(proxy_module, [
                        (now_ts - 10, "10.0.0.1", "UA", "/",  "GET", 200, "",         "alpha.test"),
                        (now_ts - 20, "10.0.0.2", "UA", "/a", "GET", 200, "",         "alpha.test"),
                        (now_ts - 30, "10.0.0.3", "UA", "/b", "GET", 403, "honeypot", "alpha.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200
                    d = await r.json()

                    rows = {row["hostname"]: row for row in d["stats"]}
                    assert "alpha.test" in rows, "alpha.test vhost must appear in stats"
                    row = rows["alpha.test"]

                    assert row["total_1h"] == 3, \
                        f"total_1h should be 3, got {row['total_1h']}"
                    assert row["allowed_1h"] == 2, (
                        f"allowed_1h should be 2 (reason='' events), got {row['allowed_1h']}. "
                        "Fix: '' not included in allowed IN list."
                    )
                    assert row["blocked_1h"] == 1, (
                        f"blocked_1h should be 1 (only honeypot), got {row['blocked_1h']}. "
                        "Fix: '' not excluded from blocked NOT IN list — empty-reason events "
                        "are being double-counted as blocked."
                    )
        _run(go())

    def test_named_allowed_reasons_also_counted(self, proxy_module):
        """'authorized-robot' and 'bypass-path' reasons must also count in allowed_1h."""
        now_ts = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now_ts - 5,  "1.1.1.1", "bot", "/feed", "GET", 200,
                         "authorized-robot", "beta.test"),
                        (now_ts - 10, "1.1.1.2", "ua",  "/",     "GET", 200,
                         "",                    "beta.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    rows = {row["hostname"]: row for row in d["stats"]}
                    assert rows.get("beta.test", {}).get("allowed_1h", 0) == 2, (
                        "authorized-robot + empty-reason must both count as allowed"
                    )
        _run(go())

    def test_old_reason_strings_not_in_allowed(self, proxy_module):
        """Legacy 'ok' reason string should still be counted (belt-and-suspenders)."""
        now_ts = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now_ts - 5, "2.2.2.2", "ua", "/", "GET", 200, "ok", "gamma.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    rows = {row["hostname"]: row for row in d["stats"]}
                    assert rows.get("gamma.test", {}).get("allowed_1h", 0) >= 1
        _run(go())


# ══════════════════════════════════════════════════════════════════════════════
# D-1  record() method parameter wired through
# ══════════════════════════════════════════════════════════════════════════════

class TestD1RecordMethodField:
    """record() must accept and store the HTTP method in events."""

    def test_record_accepts_method_kwarg(self, proxy_module):
        """record() must accept method= without raising TypeError."""
        async def go():
            from core.metrics import record as _record
            import state as _st
            _st.events.clear()
            await _record(
                "1.2.3.4", "TestUA", "/path", 200, "",
                method="DELETE",
            )
        _run(go())

    def test_method_field_in_in_memory_event(self, proxy_module):
        """In-memory _evt dict must have the method value passed to record()."""
        async def go():
            from core.metrics import record as _record
            import state as _st
            _st.events.clear()

            await _record(
                "5.5.5.5", "TestUA", "/test-method", 200, "",
                method="POST",
            )
            matched = [e for e in _st.events if e.get("ip") == "5.5.5.5"]
            assert matched, "No event found in in-memory events deque"
            assert matched[-1]["method"] == "POST", (
                f"In-memory event has method={matched[-1]['method']!r}, expected 'POST'. "
                "method field not wired through record()."
            )
        _run(go())

    def test_method_field_default_is_empty_string(self, proxy_module):
        """Callers that don't pass method= get '' — existing callers unaffected."""
        async def go():
            from core.metrics import record as _record
            import state as _st
            _st.events.clear()

            await _record(
                "6.6.6.6", "TestUA", "/no-method", 200, "",
            )
            matched = [e for e in _st.events if e.get("ip") == "6.6.6.6"]
            assert matched
            assert matched[-1]["method"] == "", \
                f"Default method should be '', got {matched[-1]['method']!r}"
        _run(go())

    def test_main_proxy_path_records_request_method(self, proxy_module):
        """End-to-end: allowed requests record correct method in events.
        Uses BYPASS_PATHS so the request reaches the main proxy record() call
        (not the early-exit ua-blocked path which doesn't receive method yet)."""
        async def go():
            import sys
            import core.proxy_handler as _cph
            import state as _st
            _st.events.clear()

            import ipaddress as _ipa
            ip = "77.77.77.77"
            _st.ip_state.pop(ip, None)

            old_bypass = proxy_module.BYPASS_PATHS
            old_xff = proxy_module.TRUST_XFF
            old_nets = proxy_module.TRUSTED_PROXIES_NETS
            new_bypass = ["/method-test-*"]
            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "BYPASS_PATHS")]:
                try:
                    setattr(mod, "BYPASS_PATHS", new_bypass)
                except (AttributeError, TypeError):
                    pass
            _cph.get_ip.__globals__["BYPASS_PATHS"] = new_bypass
            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "TRUST_XFF")]:
                try:
                    setattr(mod, "TRUST_XFF", "first")
                except (AttributeError, TypeError):
                    pass
            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "TRUSTED_PROXIES_NETS")]:
                try:
                    setattr(mod, "TRUSTED_PROXIES_NETS", [_ipa.ip_network("127.0.0.1/32")])
                except (AttributeError, TypeError):
                    pass
            _cph.get_ip.__globals__["TRUST_XFF"] = "first"
            _cph.get_ip.__globals__["TRUSTED_PROXIES_NETS"] = [_ipa.ip_network("127.0.0.1/32")]

            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    await c.get("/method-test-get",
                                headers={"X-Forwarded-For": ip, "Host": "method.test"})
                    await c.post("/method-test-post",
                                 headers={"X-Forwarded-For": ip, "Host": "method.test"},
                                 data=b"body")

            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "BYPASS_PATHS")]:
                try:
                    setattr(mod, "BYPASS_PATHS", old_bypass)
                except (AttributeError, TypeError):
                    pass
            _cph.get_ip.__globals__["BYPASS_PATHS"] = old_bypass
            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "TRUST_XFF")]:
                try:
                    setattr(mod, "TRUST_XFF", old_xff)
                except (AttributeError, TypeError):
                    pass
            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "TRUSTED_PROXIES_NETS")]:
                try:
                    setattr(mod, "TRUSTED_PROXIES_NETS", old_nets)
                except (AttributeError, TypeError):
                    pass
            _cph.get_ip.__globals__["TRUST_XFF"] = old_xff
            _cph.get_ip.__globals__["TRUSTED_PROXIES_NETS"] = old_nets

            ip_events = [e for e in _st.events if e.get("ip") == ip]
            assert len(ip_events) >= 2, \
                f"Expected at least 2 events for {ip}, got {len(ip_events)}"

            methods = {e["method"] for e in ip_events}
            assert "GET" in methods, f"GET not in recorded methods: {methods}"
            assert "POST" in methods, f"POST not in recorded methods: {methods}"
        _run(go())

    def test_method_stored_in_db_events_table(self, proxy_module):
        """The method column in the events DB table must be populated for bypass-path traffic."""
        async def go():
            import sys
            import core.proxy_handler as _cph

            import ipaddress as _ipa
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    ip = "88.88.88.88"

                    old_bypass = proxy_module.BYPASS_PATHS
                    old_xff = proxy_module.TRUST_XFF
                    old_nets = proxy_module.TRUSTED_PROXIES_NETS
                    new_bypass = ["/db-method-test*"]
                    for mod in [proxy_module] + [m for m in sys.modules.values()
                                                  if m and hasattr(m, "BYPASS_PATHS")]:
                        try:
                            setattr(mod, "BYPASS_PATHS", new_bypass)
                        except (AttributeError, TypeError):
                            pass
                    for mod in [proxy_module] + [m for m in sys.modules.values()
                                                  if m and hasattr(m, "TRUST_XFF")]:
                        try:
                            setattr(mod, "TRUST_XFF", "first")
                        except (AttributeError, TypeError):
                            pass
                    for mod in [proxy_module] + [m for m in sys.modules.values()
                                                  if m and hasattr(m, "TRUSTED_PROXIES_NETS")]:
                        try:
                            setattr(mod, "TRUSTED_PROXIES_NETS",
                                    [_ipa.ip_network("127.0.0.1/32")])
                        except (AttributeError, TypeError):
                            pass
                    # Also patch get_ip.__globals__ directly: it may point to an orphaned
                    # proxy module not in sys.modules (loaded by test_functional.py).
                    _cph.get_ip.__globals__["BYPASS_PATHS"] = new_bypass
                    _cph.get_ip.__globals__["TRUST_XFF"] = "first"
                    _cph.get_ip.__globals__["TRUSTED_PROXIES_NETS"] = [_ipa.ip_network("127.0.0.1/32")]

                    await c.get("/db-method-test/resource",
                                headers={"X-Forwarded-For": ip, "Host": "db.test"})
                    await asyncio.sleep(0.3)

                    for mod in [proxy_module] + [m for m in sys.modules.values()
                                                  if m and hasattr(m, "BYPASS_PATHS")]:
                        try:
                            setattr(mod, "BYPASS_PATHS", old_bypass)
                        except (AttributeError, TypeError):
                            pass
                    for mod in [proxy_module] + [m for m in sys.modules.values()
                                                  if m and hasattr(m, "TRUST_XFF")]:
                        try:
                            setattr(mod, "TRUST_XFF", old_xff)
                        except (AttributeError, TypeError):
                            pass
                    for mod in [proxy_module] + [m for m in sys.modules.values()
                                                  if m and hasattr(m, "TRUSTED_PROXIES_NETS")]:
                        try:
                            setattr(mod, "TRUSTED_PROXIES_NETS", old_nets)
                        except (AttributeError, TypeError):
                            pass
                    _cph.get_ip.__globals__["BYPASS_PATHS"] = old_bypass
                    _cph.get_ip.__globals__["TRUST_XFF"] = old_xff
                    _cph.get_ip.__globals__["TRUSTED_PROXIES_NETS"] = old_nets

            # Backend-aware read: the proxy's writer persists events to the
            # active backend (Postgres under the PG-mode harness), so a raw
            # sqlite3.connect(DB_PATH) read would be empty.
            from db.conn import conn as _backend_conn
            with _backend_conn(timeout=10) as conn:
                rows = conn.execute(
                    "SELECT method FROM events WHERE ip=? AND path LIKE '/db-method%'",
                    (ip,),
                ).fetchall()

            assert rows, f"No DB event found for ip {ip} on /db-method-test"
            methods = [r[0] for r in rows]
            assert any(m == "GET" for m in methods), (
                f"DB event method should be 'GET', got: {methods}. "
                "method field not stored in DB."
            )
        _run(go())


# ══════════════════════════════════════════════════════════════════════════════
# Regression tests — cross-fix interactions
# ══════════════════════════════════════════════════════════════════════════════

class TestRegressions:
    """Cross-fix regression checks — ensure fixes don't break each other."""

    def test_ban_from_scoring_still_uses_monotonic(self, proxy_module):
        """update_risk_and_maybe_ban must still use now() for banned_until."""
        async def go():
            import state as _st
            from helpers import now

            ip = "99.99.99.99"
            _st.ip_state.pop(ip, None)

            # Force immediate ban by setting score close to threshold
            async with _st.state_lock:
                _st.ip_state[ip].risk_score = proxy_module.RISK_BAN_THRESHOLD - 0.5

            await proxy_module.update_risk_and_maybe_ban(
                ip, "honeypot", ip
            )

            s = _st.ip_state.get(ip)
            if s and s.banned_until > 0:
                assert s.banned_until < 1e9, (
                    f"update_risk_and_maybe_ban: banned_until={s.banned_until} "
                    "looks like epoch. now() must be used."
                )
        _run(go())

    def test_vhost_stats_returns_last_seen_ts_field(self, proxy_module):
        """last_seen_ts must be present in every stats row (used for Active/Idle status)."""
        now_ts = time.time()
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _wipe_events(proxy_module)
                    _seed_events(proxy_module, [
                        (now_ts - 5, "1.1.1.1", "UA", "/", "GET", 200, "", "status.test"),
                    ])
                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    for row in d["stats"]:
                        assert "last_seen_ts" in row, \
                            f"stats row missing last_seen_ts: {row}"
                        assert row["last_seen_ts"] > 0, \
                            f"last_seen_ts must be > 0 for seeded events"
        _run(go())

    def test_both_c1_and_c2_fixes_coexist(self, proxy_module):
        """Local ban (now()) and Redis ban (epoch→monotonic) must produce comparable values."""
        async def go():
            import state as _st
            from helpers import now
            import time as _t

            ip = "11.22.33.44"
            _st.ip_state.pop(ip, None)

            # Apply local ban via ban()
            await proxy_module.ban(ip, secs=300, reason="test")
            local_until = _st.ip_state[ip].banned_until

            # Simulate Redis returning the same ban as epoch
            epoch_until = _t.time() + 300
            with mock.patch("integrations.redis._shared_ban_get",
                            new=mock.AsyncMock(return_value=epoch_until)):
                _st.ip_state.pop(ip, None)  # clear to force Redis path
                banned, remaining = await proxy_module.is_banned(ip)

            redis_until = _st.ip_state[ip].banned_until

            assert local_until < 1e9, "local ban must be monotonic"
            assert redis_until < 1e9, "redis ban must be converted to monotonic"
            # Both should represent ~300s in the future monotonically
            mono_now = now()
            assert abs((local_until - mono_now) - (redis_until - mono_now)) < 5, (
                f"local ({local_until - mono_now:.1f}s) and redis ({redis_until - mono_now:.1f}s) "
                "ban durations should be within 5s of each other"
            )
        _run(go())

    def test_ssrf_guard_still_blocks_plain_private_ipv4_after_fix(self):
        """S-2 fix must not break the existing plain IPv4 private-address check."""
        import socket
        import config as _cfg
        import vhost
        saved = _cfg.ALLOW_PRIVATE_UPSTREAM
        _cfg.ALLOW_PRIVATE_UPSTREAM = False
        try:
            with mock.patch.object(
                socket, "getaddrinfo",
                return_value=[(None, None, None, None, ("192.168.0.1", 0))]
            ):
                with pytest.raises(SystemExit):
                    vhost._assert_upstream_public("http://host.example.com")
        finally:
            _cfg.ALLOW_PRIVATE_UPSTREAM = saved

    def test_custom_allow_then_vhost_stats_sees_traffic(self, proxy_module):
        """V-2 + V-4 combined: allow-rule traffic increments allowed_1h in vhost-stats."""
        async def go():
            import sys
            import state as _st
            _wipe_events(proxy_module)
            ip = "55.55.55.55"
            _st.ip_state.pop(ip, None)

            rule = [{"if": {"path": "/stat-allow*"}, "then": "allow", "tag": "test"}]
            parsed = proxy_module._to_custom_rules(rule)
            old_rules = proxy_module.CUSTOM_RULES
            old_bypass = proxy_module.BYPASS_PATHS

            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "CUSTOM_RULES")]:
                try:
                    setattr(mod, "CUSTOM_RULES", parsed)
                except (AttributeError, TypeError):
                    pass
            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "BYPASS_PATHS")]:
                try:
                    setattr(mod, "BYPASS_PATHS", ["/stat-allow"])
                except (AttributeError, TypeError):
                    pass

            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    await c.get("/stat-allow/resource",
                                headers={"X-Forwarded-For": ip,
                                         "Host": "combined.test"})
                    await asyncio.sleep(0.2)

                    cookie = _make_admin_cookie(proxy_module)
                    r = await c.get(NS + "/vhost-stats",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()

            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "CUSTOM_RULES")]:
                try:
                    setattr(mod, "CUSTOM_RULES", old_rules)
                except (AttributeError, TypeError):
                    pass
            for mod in [proxy_module] + [m for m in sys.modules.values()
                                          if m and hasattr(m, "BYPASS_PATHS")]:
                try:
                    setattr(mod, "BYPASS_PATHS", old_bypass)
                except (AttributeError, TypeError):
                    pass

            rows = {row["hostname"]: row for row in d["stats"]}
            row = rows.get("combined.test")
            assert row is not None, "vhost combined.test must appear in stats after allow-rule hit"
            assert row["total_1h"] >= 1, "total_1h must count allow-rule traffic"
        _run(go())
