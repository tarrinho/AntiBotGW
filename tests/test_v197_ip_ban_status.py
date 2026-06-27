"""
tests/test_v197_ip_ban_status.py — a PERSISTENT raw-IP ban (ip_bans table) must
surface in the dashboard status, not render as green "allowed".

Bug: the in-memory identity ban (`s.banned_until`) and the raw-IP ban
(`ip_bans` table) are independent. An IP can be in the hostile pool — every
request silent-decoyed — while the identity's own risk score has decayed below
threshold. The clients dump only exposed `banned_secs` (identity ban), so such
an identity showed STATUS "allowed" (green) in the reason-details popup and the
ALLOWED/BLOCKED/MISSED tabs, even though it was fully blocked.

Fix: the clients dump now also exposes `ip_banned`. 1.9.7 reads the whole banned
set ONCE per dump via `check_ip_bans_bulk()` (off the event loop, in a thread —
the old per-identity `check_ip_ban_cached` did a synchronous SQLite open per
tracked identity under state_lock and froze the loop on slow armv7 storage), then
does an in-memory membership test:
    `_ip_banned = (s.banned_until <= n) and ((s.last_ip or key) in _banned_ips)`.
The dashboard treats `ip_banned` as banned.

`check_ip_bans_bulk()` reads the SQLite `ip_bans` table at DB_PATH (the single
source of truth — also what the request-path `check_ip_ban` falls back to), so
these tests seed the **ip_bans table** rather than priming the TTL `_ban_cache`.
That keeps them correct in BOTH SQLite and PostgreSQL backend modes (ip_bans is
SQLite-resident regardless of the active event store).

Groups:
  B1 — behavioural: metrics dump flags the IP-banned identity
  B2 — enforcement: a banned IP is still silent-decoyed (request path)
  B3 — edge cases on the status flag
  R1 — source guards: backend field + frontend wiring + REASON_INFO entry
"""
import asyncio
import sqlite3
import time
import pathlib
from contextlib import asynccontextmanager

from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

NS = "/antibot-appsec-gateway/secured"
_PROJ = pathlib.Path(__file__).resolve().parent.parent


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
    client = TestClient(TestServer(app))
    await client.start_server()
    yield client
    await client.close()


def _admin_cookie(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return {proxy_module._SESSION_COOKIE: proxy_module._session_sign("admin", sid=sid)}


def _seed_ip_ban(proxy_module, ip, banned_until):
    """Insert a raw-IP ban into the `ip_bans` table at DB_PATH (SQLite) — the
    single source of truth read by `check_ip_bans_bulk` (the metrics dump) AND
    `check_ip_ban` (the request path). Evict the TTL cache so the next read hits
    the table. Backend-agnostic: ip_bans is SQLite-resident in PG mode too."""
    import db.sqlite as _dbs
    conn = sqlite3.connect(proxy_module.DB_PATH, timeout=5)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO ip_bans (ip, banned_until, reason, ts) "
            "VALUES (?,?,?,?)", (ip, float(banned_until), "test-ban", time.time()))
        conn.commit()
    finally:
        conn.close()
    _dbs._ban_cache.clear()
    try:
        _dbs._ban_cache_vhost.clear()
    except Exception:
        pass


def _clear_ip_bans(proxy_module):
    import db.sqlite as _dbs
    try:
        conn = sqlite3.connect(proxy_module.DB_PATH, timeout=5)
        conn.execute("DELETE FROM ip_bans")
        conn.commit()
        conn.close()
    except Exception:
        pass
    _dbs._ban_cache.clear()


# ── B1: behavioural ──────────────────────────────────────────────────────────

class TestIpBanStatus:
    def test_ip_banned_identity_flagged_despite_zero_identity_ban(self, proxy_module):
        """An identity whose in-memory ban has decayed (banned_until=0) but whose
        raw IP is in ip_bans must report ip_banned=True; a clean one must not."""

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    proxy_module.ip_state.clear()
                    _clear_ip_bans(proxy_module)
                    try:
                        proxy_module._metrics_cache.clear()
                    except Exception:
                        pass

                    BAD = "192.0.2.222"
                    GOOD = "203.0.113.55"
                    # IP-banned but identity ban decayed to 0 (the bug scenario).
                    bad = proxy_module.ip_state[BAD]
                    bad.last_ip = BAD
                    bad.banned_until = 0.0
                    bad.risk_score = 3.0          # below threshold → would show "allowed"
                    bad.request_count = 4
                    # Clean identity, no IP ban.
                    good = proxy_module.ip_state[GOOD]
                    good.last_ip = GOOD
                    good.banned_until = 0.0
                    good.risk_score = 1.0
                    good.request_count = 2

                    # BAD is in the persistent ban list (1h); GOOD is not.
                    _seed_ip_ban(proxy_module, BAD, time.time() + 3600)

                    cookie = _admin_cookie(proxy_module)
                    async with cl.get(NS + "/metrics", cookies=cookie) as r:
                        assert r.status == 200, r.status
                        d = await r.json()

                    by_id = {c["id"]: c for c in d.get("clients", [])}
                    assert BAD in by_id, f"banned IP identity missing from dump: {list(by_id)}"
                    assert GOOD in by_id, "clean identity missing from dump"
                    assert by_id[BAD].get("ip_banned") is True, (
                        "IP-banned identity (ip_bans hit, identity ban decayed) must "
                        f"report ip_banned=True; got {by_id[BAD].get('ip_banned')!r}"
                    )
                    assert by_id[GOOD].get("ip_banned") is False, (
                        "clean identity must report ip_banned=False"
                    )
            _clear_ip_bans(proxy_module)

        asyncio.new_event_loop().run_until_complete(go())


# ── R1: source guards ─────────────────────────────────────────────────────────

class TestSourceGuards:
    def test_backend_exposes_ip_banned(self):
        src = (_PROJ / "core" / "proxy_handler.py").read_text(encoding="utf-8")
        assert '"ip_banned": _ip_banned' in src, (
            "metrics_endpoint client dict must expose ip_banned"
        )
        # 1.9.7 — the whole banned set is read ONCE via check_ip_bans_bulk (in a
        # thread), then membership-tested in memory (no per-identity DB open).
        assert "check_ip_bans_bulk" in src, (
            "ip_banned must come from a bulk read of the ip_bans table"
        )
        assert "(s.last_ip or key) in _banned_ips" in src, (
            "ip_banned must membership-test last_ip against the banned set"
        )

    def test_frontend_treats_ip_banned_as_banned(self):
        html = (_PROJ / "dashboards" / "main.html").read_text(encoding="utf-8")
        # reason-details popup
        assert "c.banned_secs > 0 || c.ip_banned" in html, (
            "reason-details popup must treat ip_banned as banned"
        )
        # ALLOWED/BLOCKED/MISSED tab classifier
        assert "(c.banned_secs||0) > 0 || c.ip_banned" in html, (
            "_clientCats must treat ip_banned as a ban category"
        )
        # client-detail status line
        assert "d.ip_banned" in html, "client-detail status must handle ip_banned"

    def test_reason_info_documents_ip_ban(self):
        html = (_PROJ / "dashboards" / "main.html").read_text(encoding="utf-8")
        assert '"ip-ban":' in html, "REASON_INFO must document the ip-ban reason"
        # not the default 'No description available' fallback
        idx = html.find('"ip-ban":')
        snippet = html[idx: idx + 400]
        assert "persistent" in snippet.lower() and "ip_bans" in snippet, (
            "ip-ban description must explain the persistent ip_bans block"
        )

    def test_reason_info_ip_ban_is_hard_tier(self):
        """ip-ban is a terminal block — it must read as a 'hard' tier (red), not
        the 'info' default that made it look benign."""
        html = (_PROJ / "dashboards" / "main.html").read_text(encoding="utf-8")
        idx = html.find('"ip-ban":')
        snippet = html[idx: idx + 120]
        assert 'tier:"hard"' in snippet, f"ip-ban must be tier 'hard'; got {snippet[:80]!r}"

    def test_probe_guarded_to_non_identity_banned(self):
        """The membership test must be guarded by `s.banned_until <= n` so an
        already-identity-banned client (surfaced via banned_secs) isn't also
        double-flagged ip_banned."""
        src = (_PROJ / "core" / "proxy_handler.py").read_text(encoding="utf-8")
        assert "(s.banned_until <= n) and ((s.last_ip or key) in _banned_ips)" in src, (
            "ip_banned must be `(s.banned_until <= n) and "
            "((s.last_ip or key) in _banned_ips)`"
        )

    def test_banned_set_read_once_off_thread(self):
        """The banned set must be read ONCE per dump, off the event loop — not a
        synchronous DB open per tracked identity (the perf regression that froze
        /live on armv7)."""
        src = (_PROJ / "core" / "proxy_handler.py").read_text(encoding="utf-8")
        assert "to_thread" in src and "check_ip_bans_bulk" in src, (
            "the banned set must be read via asyncio.to_thread(check_ip_bans_bulk)"
        )

    def test_client_detail_renders_ip_banned_label(self):
        html = (_PROJ / "dashboards" / "main.html").read_text(encoding="utf-8")
        assert "IP-Banned" in html, (
            "client-detail status line must render an explicit IP-Banned label"
        )


# ── B2: enforcement (security-critical) ───────────────────────────────────────

class TestIpBanEnforcement:
    """The dashboard label was the bug — the BLOCK itself must keep working: a
    banned IP must be silent-decoyed (never reach real upstream content)."""

    def test_banned_ip_request_is_silent_decoyed(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    # The TestClient's socket IP is 127.0.0.1; with no XFF header
                    # get_ip() falls back to it regardless of TRUST_XFF. The
                    # request path checks check_ip_ban → ip_bans table.
                    _seed_ip_ban(proxy_module, "127.0.0.1", time.time() + 3600)
                    # Request a DISTINCTIVE non-root path. The echo upstream returns
                    # {"path": <path>}; a homepage silent-decoy fetches "/" instead,
                    # so the requested path must NOT be echoed back.
                    async with cl.get("/secret-unique-xyz-9988") as r:
                        body = await r.text()
                    assert "/secret-unique-xyz-9988" not in body, (
                        "banned IP reached real upstream content — ban BYPASSED "
                        f"(decoy expected). body={body[:200]!r}"
                    )
            _clear_ip_bans(proxy_module)

        asyncio.new_event_loop().run_until_complete(go())

    def test_unbanned_ip_reaches_upstream(self, proxy_module):
        """Control: with no IP ban, the same path DOES reach the echo upstream —
        proves the decoy in the test above is caused by the ban, not by another
        gate swallowing the request."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    _clear_ip_bans(proxy_module)
                    async with cl.get("/secret-unique-xyz-9988",
                                      headers={"User-Agent": (
                                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                                          "Chrome/120.0 Safari/537.36")}) as r:
                        body = await r.text()
                    assert "/secret-unique-xyz-9988" in body, (
                        "non-banned request did not reach the echo upstream "
                        f"(another gate intercepted?). body={body[:200]!r}"
                    )
            _clear_ip_bans(proxy_module)

        asyncio.new_event_loop().run_until_complete(go())


# ── B3: edge cases on the status flag ─────────────────────────────────────────

class TestIpBanStatusEdges:
    def test_identity_ban_takes_precedence_probe_skipped(self, proxy_module):
        """A client already identity-banned (banned_until>now) reports via
        banned_secs; ip_banned stays False (the `s.banned_until <= n` guard makes
        the membership test moot — banned_secs already drives the badge)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    proxy_module.ip_state.clear()
                    _clear_ip_bans(proxy_module)
                    try:
                        proxy_module._metrics_cache.clear()
                    except Exception:
                        pass
                    IP = "192.0.2.40"
                    s = proxy_module.ip_state[IP]
                    s.last_ip = IP
                    s.banned_until = proxy_module.now() + 3600   # identity-banned
                    s.request_count = 3
                    # Even though the IP is ALSO in the ban list, the guard wins.
                    _seed_ip_ban(proxy_module, IP, time.time() + 3600)
                    cookie = _admin_cookie(proxy_module)
                    async with cl.get(NS + "/metrics", cookies=cookie) as r:
                        d = await r.json()
                    c = {x["id"]: x for x in d.get("clients", [])}[IP]
                    assert c["banned_secs"] > 0, "identity ban must surface via banned_secs"
                    assert c.get("ip_banned") is False, (
                        "an already-identity-banned client must not be double-flagged ip_banned"
                    )
            _clear_ip_bans(proxy_module)

        asyncio.new_event_loop().run_until_complete(go())

    def test_expired_ip_ban_not_flagged(self, proxy_module):
        """A ban whose banned_until is in the past must NOT flag ip_banned —
        check_ip_bans_bulk only returns rows with banned_until > now."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    proxy_module.ip_state.clear()
                    _clear_ip_bans(proxy_module)
                    try:
                        proxy_module._metrics_cache.clear()
                    except Exception:
                        pass
                    IP = "192.0.2.41"
                    s = proxy_module.ip_state[IP]
                    s.last_ip = IP
                    s.banned_until = 0.0
                    s.request_count = 2
                    _seed_ip_ban(proxy_module, IP, time.time() - 10)  # expired
                    cookie = _admin_cookie(proxy_module)
                    async with cl.get(NS + "/metrics", cookies=cookie) as r:
                        d = await r.json()
                    c = {x["id"]: x for x in d.get("clients", [])}[IP]
                    assert c.get("ip_banned") is False, (
                        "an expired IP ban must not flag ip_banned"
                    )
            _clear_ip_bans(proxy_module)

        asyncio.new_event_loop().run_until_complete(go())

    def test_ip_banned_keys_on_last_ip_not_identity(self, proxy_module):
        """The ban lives on the raw IP; the identity key can be a fingerprint /
        session. ip_banned must membership-test last_ip, not the identity key."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as cl:
                    proxy_module.ip_state.clear()
                    _clear_ip_bans(proxy_module)
                    try:
                        proxy_module._metrics_cache.clear()
                    except Exception:
                        pass
                    IDENT = "fp:deadbeefcafe"       # identity key != IP
                    RAW_IP = "192.0.2.42"
                    s = proxy_module.ip_state[IDENT]
                    s.last_ip = RAW_IP
                    s.banned_until = 0.0
                    s.request_count = 5
                    _seed_ip_ban(proxy_module, RAW_IP, time.time() + 3600)
                    cookie = _admin_cookie(proxy_module)
                    async with cl.get(NS + "/metrics", cookies=cookie) as r:
                        d = await r.json()
                    c = {x["id"]: x for x in d.get("clients", [])}[IDENT]
                    assert c.get("ip_banned") is True, (
                        "ip_banned must key on last_ip (the raw IP that carries the ban)"
                    )
            _clear_ip_bans(proxy_module)

        asyncio.new_event_loop().run_until_complete(go())
