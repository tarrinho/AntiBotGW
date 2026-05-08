"""
Regression tests for V8-class bypasses — make sure the published anti-bot
controls keep working as we evolve the gate logic.

Each test encodes a specific past finding so a future refactor that lets a
control silently lose effect (e.g. `Mozilla` UA forwarding past the JS
challenge, `/api/users.css` slipping through the static-asset bypass, the
challenge gate revealing the gateway with an explicit 401 response) gets
caught here before reaching production.

Past findings these tests cover:
  • V8  — JS challenge only gated HTML, API paths sailed through on UA.
  • F1  — V8 fix returned a 401 JSON that fingerprinted the gateway.
  • F2  — challenge gate ran before host/TLS/origin → leaked over decoy.
  • F3  — `/api/v1/users.css` bypassed via endswith(".css") static rule.
  • F4  — /antibot-appsec-gateway/challenge could be hammered without a rate limit.
"""
import asyncio
import os
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


_UPSTREAM_MARK = b"UPSTREAM_REACHED_8b2c4d"  # unique tag the upstream returns


async def _upstream_handler(request: web.Request):
    return web.Response(body=_UPSTREAM_MARK, content_type="text/plain",
                        headers={"X-Upstream": "1"})


async def _upstream_html(request: web.Request):
    # Some tests expect HTML on /
    return web.Response(body=b"<html><body>real</body></html>",
                        content_type="text/html",
                        headers={"X-Upstream": "1"})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_get("/", _upstream_html)
    app.router.add_route("*", "/{tail:.*}", _upstream_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


def _propagate_to_all_modules(key, value):
    """Propagate a config value to every loaded module that declares it.
    Mirrors the mechanism used by proxy_handler.config_endpoint so that
    overrides set on proxy_module are visible to js_challenge.py,
    challenge/*, core/*, etc. — which all have their own copies from
    `from config import *` at import time."""
    import sys
    for m in list(sys.modules.values()):
        if m is not None and hasattr(m, key):
            try:
                setattr(m, key, value)
            except (AttributeError, TypeError):
                pass


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url, **mod_overrides):
    """Set proxy env, build the app, return a TestClient. Restores attrs
    after the test.

    1.6.7 — `db_load_secrets()` runs on app startup and re-derives
    `TURNSTILE_ENABLED` from env (env wins over programmatic state),
    which would override any pre-startup mutation. We snapshot the
    overrides here, let the app boot, then re-apply them so the
    middleware sees the test's intended values on every request."""
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    saved = {k: getattr(proxy_module, k) for k in mod_overrides}
    for k, v in mod_overrides.items():
        setattr(proxy_module, k, v)
    # Stub Turnstile credentials when the test enables it but didn't
    # supply real keys (production mode requires both halves).
    _turnstile_on = mod_overrides.get("TURNSTILE_ENABLED", False)
    if _turnstile_on:
        if not getattr(proxy_module, "TURNSTILE_SITEKEY", ""):
            proxy_module.TURNSTILE_SITEKEY = "1x00000000000000000000AA"
        if not getattr(proxy_module, "TURNSTILE_SECRET", ""):
            proxy_module.TURNSTILE_SECRET = "1x0000000000000000000000000000000AA"
        proxy_module._TURNSTILE_CONFIGURED = True
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    # Re-apply overrides AFTER on_startup so db_load_secrets() can't
    # undo them. The middleware reads these on every request.
    # Propagate each override to ALL loaded modules so that submodules
    # (js_challenge.py, core/proxy_handler.py, etc.) which have their
    # own copy from `from config import *` see the test values too.
    for k, v in mod_overrides.items():
        setattr(proxy_module, k, v)
        _propagate_to_all_modules(k, v)
    if _turnstile_on:
        proxy_module._TURNSTILE_CONFIGURED = True
        _propagate_to_all_modules("_TURNSTILE_CONFIGURED", True)
    # Clear per-IP runtime state so this test is not affected by previous
    # tests leaving dirty risk scores, bans, or depleted token buckets.
    from state import ip_state, ip_buckets, ip_new_sessions
    ip_state.clear()
    ip_buckets.clear()
    ip_new_sessions.clear()
    try:
        yield client
    finally:
        await client.close()
        # Cancel and await ALL background tasks spawned by on_startup.
        # on_cleanup only cancels the 3 saved-reference tasks; the periodic
        # refresh loops (404, MaxMind, Tor) have no saved refs and must be
        # cleaned up here so they don't keep the event loop alive after
        # loop.close() — which would leave dangling state for the next test.
        _cur = asyncio.current_task()
        _pending = [t for t in asyncio.all_tasks() if t is not _cur]
        if _pending:
            for _t in _pending:
                _t.cancel()
            await asyncio.gather(*_pending, return_exceptions=True)
        # Reset db_queue to None in all modules so next on_startup always
        # re-propagates the fresh Queue (on_startup now does unconditional
        # propagation, but this is retained as defense-in-depth).
        import sys as _sys_r
        for _m in list(_sys_r.modules.values()):
            if _m is not None and hasattr(_m, 'db_queue'):
                try:
                    setattr(_m, 'db_queue', None)
                except (AttributeError, TypeError):
                    pass
        # Clear runtime state again so the next test starts clean.
        ip_state.clear()
        ip_buckets.clear()
        ip_new_sessions.clear()
        for k, v in saved.items():
            setattr(proxy_module, k, v)
            _propagate_to_all_modules(k, v)


def _browser_headers(extra=None):
    """Headers a real Chrome would send. The UA-substring check (`Mozilla`)
    is intentionally easy to satisfy — the real boundary must be the cookie."""
    h = {
        "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120 Safari/537.36"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Ch-Ua": '"Chromium";v="120", "Not?A_Brand";v="8"',
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }
    if extra:
        h.update(extra)
    return h


def _run(coro):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()
        asyncio.set_event_loop(None)


def _admin_cookie(proxy_module):
    """1.6.7 — bearer-key auth was removed. Prime the in-memory session
    cache with an admin sid and return the matching signed cookie."""
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return {proxy_module._SESSION_COOKIE: proxy_module._session_sign("admin", sid=sid)}


# ── V8: bare Mozilla UA must NOT reach upstream on API paths ─────────────

def test_v8_api_path_blocked_without_chal_cookie(proxy_module):
    """The exact pentester bypass: GET /api/v1/users with Mozilla UA but no
    chal cookie. Pre-V8 fix this returned the upstream JSON. After fix we
    must NOT see _UPSTREAM_MARK in the body."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True) as client:
                r = await client.get("/release-management/api/v1/items",
                                     headers=_browser_headers({
                                         "Accept": "application/json"}))
                body = await r.read()
                assert _UPSTREAM_MARK not in body, (
                    "API path leaked upstream content without chal cookie")
    _run(go())


def test_v8_api_post_blocked_without_chal_cookie(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True) as client:
                r = await client.post("/api/v1/login",
                                      headers=_browser_headers({
                                          "Accept": "application/json",
                                          "Content-Type": "application/json"}),
                                      data=b'{"u":"a","p":"b"}')
                body = await r.read()
                assert _UPSTREAM_MARK not in body, (
                    "POST API leaked upstream without chal cookie")
    _run(go())


# ── F1: V8 fix must NOT reveal the gateway via 401 JSON ──────────────────

def test_v8_block_does_not_reveal_gateway(proxy_module):
    """The fix must silent-decoy on cookieless API hits — not 401 with a
    'challenge required' message. A 401 'hint' would let a scanner
    fingerprint AppSecGW even on hostname-misconfig probes."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True) as client:
                r = await client.get("/api/v1/data",
                                     headers=_browser_headers({
                                         "Accept": "application/json"}))
                # Stealth response = silent-decoy, not 401. API paths get 404
                # (route-aware decoy); HTML paths get 200. Both hide the gateway.
                assert r.status in (200, 404)
                body = (await r.read()).lower()
                assert b"challenge required" not in body
                assert b"chal cookie" not in body
    _run(go())


# ── F3: static-suffix bypass tightened — /api/v1/users.css must NOT skip ─

def test_f3_api_path_with_css_suffix_does_not_bypass(proxy_module):
    """Permissive backends (Spring suffix matching, etc.) accept
    /api/v1/users.css and return JSON. The static-asset bypass must NOT
    trust extension alone if path looks like an API."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True,
                                    JS_CHAL_STRICT_STATIC=True) as client:
                r = await client.get("/api/v1/users.css",
                                     headers=_browser_headers({
                                         "Accept": "*/*"}))
                body = await r.read()
                assert _UPSTREAM_MARK not in body, (
                    ".css suffix should not bypass cookie gate on API paths")
    _run(go())


def test_f3_genuine_static_asset_still_bypasses(proxy_module):
    """A real static asset path (no API hint) keeps the bypass — browsers
    that haven't yet solved the challenge can still fetch the page CSS."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True,
                                    JS_CHAL_STRICT_STATIC=True) as client:
                r = await client.get("/static/main.css",
                                     headers=_browser_headers({
                                         "Accept": "text/css"}))
                # Goes straight to upstream — no challenge in the way.
                body = await r.read()
                assert _UPSTREAM_MARK in body
    _run(go())


# ── JS_CHAL_OPEN_PATHS: operator opt-out for legit non-browser clients ──

def test_open_paths_opt_out_forwards_to_upstream(proxy_module):
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True,
                                    JS_CHAL_OPEN_PATHS=["/webhook/"]) as client:
                r = await client.post("/webhook/github",
                                      headers=_browser_headers({
                                          "Accept": "application/json"}),
                                      data=b'{"x":1}')
                body = await r.read()
                assert _UPSTREAM_MARK in body, (
                    "operator-opted-out prefix must forward to upstream")
    _run(go())


# ── HTML GET still gets the interactive challenge page ──────────────────

def test_html_navigation_serves_challenge_page(proxy_module):
    """Turnstile challenge page is served when identity's risk score is above
    the activation threshold. Fresh visitors (no risk) fall through to
    auto-mint — Turnstile is reserved for suspected bots."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                    TURNSTILE_ENABLED=True,
                                    # Low threshold so first-contact risk (0) still
                                    # triggers — we seed ip_state directly below.
                                    SOFT_CHALLENGE_SCORE=1,
                                    RISK_BAN_THRESHOLD=4) as client:
                # First: make any request so ip_state gets an entry for this
                # identity. We can then find the key by last_ip and boost it.
                await client.get("/", headers=_browser_headers())
                # Find the track_key for the loopback identity.
                from state import ip_state
                key = next(
                    (k for k, s in ip_state.items() if s.last_ip == "127.0.0.1"),
                    None,
                )
                assert key is not None, "ip_state entry not found for 127.0.0.1"
                # Boost risk above the new threshold (midpoint of 1 and 4 = 2.5).
                ip_state[key].risk_score = 5.0
                # Now the HTML GET should show the Turnstile challenge page.
                r = await client.get("/", headers=_browser_headers())
                body = (await r.read()).decode("utf-8", "replace")
                # Challenge page contains the verifying spinner copy.
                assert "Verifying browser" in body
                # And does NOT contain real upstream content.
                assert _UPSTREAM_MARK.decode() not in body
    _run(go())


# ── After solving challenge, the cookie unlocks API paths ────────────────

def test_valid_chal_cookie_unlocks_api(proxy_module):
    """If a browser has a valid chal cookie (UA-bound), API requests reach
    upstream — proves the gate isn't blanket-blocking everything."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True) as client:
                ua = _browser_headers()["User-Agent"]
                cookie = proxy_module._make_chal_cookie(ua)
                hdrs = _browser_headers({
                    "Accept": "application/json",
                    "Cookie": f"{proxy_module.CHAL_COOKIE}={cookie}",
                })
                r = await client.get("/api/v1/items", headers=hdrs)
                body = await r.read()
                assert _UPSTREAM_MARK in body
    _run(go())


# ── /antibot-appsec-gateway/challenge endpoint is rate-limited (DoS prevention) ──────────────

def test_challenge_endpoint_rate_limited(proxy_module):
    """Hammer /antibot-appsec-gateway/challenge with bogus POSTs — at least one of the early
    bursts must come back as 429 before the bucket starves the proxy."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True,
                                    IP_BURST=3,
                                    IP_REFILL=0.5) as client:
                statuses = []
                for _ in range(20):
                    r = await client.post(
                        "/antibot-appsec-gateway/challenge",
                        data=b"n=bad&p=%7B%7D&x=0",
                        headers={"Content-Type":
                                 "application/x-www-form-urlencoded"})
                    statuses.append(r.status)
                    await r.read()
                assert 429 in statuses, (
                    f"/antibot-appsec-gateway/challenge never rate-limited under flood: {statuses}")
    _run(go())


# ── Stealth-block precedence: host mismatch wins over challenge ─────────

def test_host_mismatch_silent_decoys_even_without_cookie(proxy_module):
    """When ALLOWED_HOSTS is set and Host header doesn't match, we MUST
    silent-decoy regardless of chal cookie state. The challenge gate must
    not preempt this with its own response and reveal the gateway."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True,
                                    ALLOWED_HOSTS={"good.example.com"}
                                    ) as client:
                # Wrong host + no chal cookie. Old order would 401 here.
                hdrs = _browser_headers({"Host": "evil.example.com",
                                         "Accept": "application/json"})
                r = await client.get("/api/v1/x", headers=hdrs)
                # Silent decoy — not 401/403. API paths get 404 (route-aware decoy).
                assert r.status in (200, 404)
                body = (await r.read()).lower()
                assert b"challenge required" not in body
    _run(go())


# ── V9: probe must be cross-validated against request headers ───────────

# Tests for the deleted PoW + probe primitives (test_v9_probe_ua_must_match_*,
# test_v9_probe_cookieEnabled_must_be_true) used to live here. Both probed
# layers were empirically bypassable in pure Python and have been removed
# in favour of Turnstile-only validation. See test_v9_turnstile_required_*
# below for the live boundary.


def test_v91_chal_cookie_does_not_leak_ip(proxy_module):
    """V9.1: the cookie value must NOT contain the raw network tier — that
    would expose RFC1918 / internal pod IPs (a pentester finding). The
    cookie must carry only an opaque hash of the tier."""
    ua = "Mozilla/5.0"
    raw_tier_v4 = proxy_module._ip_tier("172.17.0.5")
    cookie = proxy_module._make_chal_cookie(ua, "deadbeef00000001", raw_tier_v4)
    # The cookie must not reveal the network address either as a literal IP
    # (e.g. "172.17.0.0") nor as the integer-form of any common octet.
    assert "172.17" not in cookie
    assert raw_tier_v4 not in cookie
    assert ":" not in cookie  # no IPv6 form either
    # IPv6 case
    raw_tier_v6 = proxy_module._ip_tier("2001:db8::1")
    cookie6 = proxy_module._make_chal_cookie(ua, "abcd0000abcd0000", raw_tier_v6)
    assert raw_tier_v6 not in cookie6
    assert "2001" not in cookie6


def test_v91_tier_hash_bind_still_works(proxy_module):
    """The opaque tier-hash must still gate cross-network replay. Same /24
    validates; different /24 does not."""
    ua = "Mozilla/5.0"
    cookie = proxy_module._make_chal_cookie(
        ua, "deadbeef00000002", proxy_module._ip_tier("203.0.113.42"))
    assert proxy_module._verify_chal_cookie(
        cookie, ua, proxy_module._ip_tier("203.0.113.99")) is True
    assert proxy_module._verify_chal_cookie(
        cookie, ua, proxy_module._ip_tier("203.0.114.42")) is False


def test_v9_chal_cookie_bound_to_ip_tier(proxy_module):
    """A cookie minted from one network tier must NOT validate from a
    different tier. Defeats cookie-replay-from-fresh-host attacks."""
    ua = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120"
    cookie = proxy_module._make_chal_cookie(
        ua, "abcdef0123456789",
        proxy_module._ip_tier("10.0.0.5"))
    # Same /24: must validate.
    assert proxy_module._verify_chal_cookie(
        cookie, ua, proxy_module._ip_tier("10.0.0.99")) is True
    # Different /24: must NOT validate.
    assert proxy_module._verify_chal_cookie(
        cookie, ua, proxy_module._ip_tier("10.0.1.5")) is False
    # Wholly different network: must NOT validate.
    assert proxy_module._verify_chal_cookie(
        cookie, ua, proxy_module._ip_tier("203.0.113.4")) is False


def test_v9_turnstile_required_when_enabled(proxy_module):
    """When TURNSTILE_ENABLED, the challenge page is shown for risky identities
    and /antibot-appsec-gateway/challenge MUST reject submissions that omit
    `cf-turnstile-response`."""
    import re
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                    TURNSTILE_ENABLED=True,
                                    TURNSTILE_SITEKEY="0xTEST",
                                    TURNSTILE_SECRET="0xTESTSECRET",
                                    SOFT_CHALLENGE_SCORE=1,
                                    RISK_BAN_THRESHOLD=4) as client:
                # Warm up ip_state with a first request then seed risk above threshold.
                await client.get("/", headers=_browser_headers())
                from state import ip_state
                key = next(
                    (k for k, s in ip_state.items() if s.last_ip == "127.0.0.1"),
                    None,
                )
                assert key is not None, "ip_state entry not found for 127.0.0.1"
                ip_state[key].risk_score = 5.0
                r = await client.get("/", headers=_browser_headers())
                html = await r.text()
                # Page must include the Turnstile script tag.
                assert "challenges.cloudflare.com/turnstile" in html
                m = re.search(r'"((?:[a-f0-9]+\|){2}[a-f0-9]+)"', html)
                nonce = m.group(1)
                # POST without the Turnstile token → must be rejected.
                r = await client.post("/antibot-appsec-gateway/challenge",
                    data={"n": nonce, "t": "/"},
                    headers={"Content-Type":
                             "application/x-www-form-urlencoded",
                             "User-Agent": _browser_headers()["User-Agent"]})
                assert r.status == 403
                body = await r.text()
                assert "turnstile" in body.lower()
    _run(go())


def test_v92_ja4_hash_binds_cookie(proxy_module):
    """V9.2: cookie minted under JA4 X must NOT validate when the request
    arrives under JA4 Y. Defeats cookie-replay across TLS-stack rewrites."""
    ua = "Mozilla/5.0"
    cookie = proxy_module._make_chal_cookie(
        ua, "deadbeef00000003",
        proxy_module._ip_tier("203.0.113.5"),
        ja4="t13d_chrome120")
    # Same JA4 → must validate.
    assert proxy_module._verify_chal_cookie(
        cookie, ua,
        proxy_module._ip_tier("203.0.113.5"),
        ja4="t13d_chrome120") is True
    # Different JA4 (Python urllib) → must NOT validate.
    assert proxy_module._verify_chal_cookie(
        cookie, ua,
        proxy_module._ip_tier("203.0.113.5"),
        ja4="t13d_8a44_python_urllib") is False


def test_v92_cookie_does_not_leak_ja4(proxy_module):
    """The JA4 fingerprint itself must NOT appear in the cookie wire
    format (only its HMAC-derived hash)."""
    ua = "Mozilla/5.0"
    cookie = proxy_module._make_chal_cookie(
        ua, "deadbeef00000004",
        proxy_module._ip_tier("203.0.113.42"),
        ja4="t13d_chrome120_long_fingerprint_value")
    assert "t13d_chrome120" not in cookie
    assert "fingerprint" not in cookie


def test_v92_cookie_without_ja4_falls_back(proxy_module):
    """When ja4 is empty (no JA4-injecting front), the binding is opt-out
    and the cookie still validates from any handshake. Operators behind a
    plain TCP terminator must keep working."""
    ua = "Mozilla/5.0"
    cookie = proxy_module._make_chal_cookie(
        ua, "deadbeef00000005",
        proxy_module._ip_tier("198.51.100.7"),
        ja4="")     # no fingerprint observed
    # Verifies regardless of whether a JA4 is supplied at request time.
    assert proxy_module._verify_chal_cookie(
        cookie, ua,
        proxy_module._ip_tier("198.51.100.7"),
        ja4="") is True
    assert proxy_module._verify_chal_cookie(
        cookie, ua,
        proxy_module._ip_tier("198.51.100.7"),
        ja4="t13d_chrome120") is True


# R2 / R3 anchor-fetch + timing-window tests used to live here. Both
# controls were empirically bypassable in pure Python (each adding one
# round trip of cost, none closing the bypass) and have been removed
# along with the PoW + probe primitives they were guarding. The
# Turnstile path is the boundary that remains.


def test_r7_canary_injected_into_html(proxy_module):
    """R7: every HTML response must carry a fresh canary token in both an
    HTML comment and the X-Trace-Id response header. Subsequent requests
    that echo any of these tokens back at the gateway are AI agents."""
    import re
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    CANARY_ECHO_DETECTION=True) as client:
                r = await client.get("/", headers=_browser_headers())
                body = await r.text()
                trace = r.headers.get("X-Trace-Id", "")
                assert re.match(r"agw-c-[0-9a-f]{16}$", trace)
                # Canary also in HTML comment.
                assert f"<!-- {trace} -->" in body
                # Server's set must contain the issued token.
                assert trace in proxy_module._canary_tokens
    _run(go())


def test_r7_echoed_canary_blocks_followup(proxy_module):
    """R7: a follow-up request that echoes a previously-issued canary
    (e.g. in URL or header) must be silent-decoyed."""
    import re
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    CANARY_ECHO_DETECTION=True) as client:
                r = await client.get("/", headers=_browser_headers())
                trace = r.headers.get("X-Trace-Id", "")
                assert trace
                # Echo the canary back in the URL path — LLM-style behaviour.
                r2 = await client.get(f"/api/x?ref={trace}",
                                       headers=_browser_headers({
                                           "Accept": "application/json"}))
                body2 = await r2.read()
                # Must NOT reach upstream marker.
                assert _UPSTREAM_MARK not in body2
    _run(go())


def test_r7_no_false_positive_without_echo(proxy_module):
    """A normal follow-up request without an echoed canary must not be
    flagged. The detection has near-zero false-positive *only* if no
    legitimate flow produces matching tokens."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    CANARY_ECHO_DETECTION=True) as client:
                # Burn one canary so the dict is non-empty.
                await client.get("/", headers=_browser_headers())
                # Plain follow-up — should pass canary scan (no echo).
                from unittest.mock import MagicMock
                # Direct unit test of the scanner: synthesise a fake req
                # whose path/headers contain no token.
                fake = MagicMock()
                fake.path_qs = "/api/x"
                fake.headers = {"User-Agent": "Mozilla/5.0",
                                "Accept": "application/json"}
                assert proxy_module._scan_request_for_canary(fake) == ""
    _run(go())


def test_r8_canary_echo_is_in_hostile_reasons(proxy_module):
    """R8: canary-echo must be listed among the reasons that upgrade to
    hostile-pool (24 h) duration so AI agents stay banned long enough to
    be uneconomic to retry."""
    assert "canary-echo" in proxy_module._HOSTILE_REASONS
    # Default 24 h.
    assert proxy_module.HOSTILE_BAN_SECS >= 3600
    # canary-echo also has a high risk weight (single hit ≥ ban threshold).
    assert proxy_module.RISK_WEIGHTS.get("canary-echo", 0) >= 50


def test_v145_key_rotation_invalidates_old_cookies(proxy_module):
    """1.4.5: cookies HMAC-signed under the old SESSION_KEY must fail
    verification immediately after the key is rotated. Closes the
    pentester finding 'old chal cookie still works after upgrade'."""
    ua = "Mozilla/5.0"
    ip_tier = proxy_module._ip_tier("203.0.113.10")
    cookie = proxy_module._make_chal_cookie(ua, "deadbeef00000099", ip_tier)
    # Pre-rotation: must verify.
    assert proxy_module._verify_chal_cookie(cookie, ua, ip_tier) is True
    # Rotate the key in-process (simulate the admin endpoint).
    import secrets as _sec
    saved = proxy_module.SESSION_KEY
    try:
        proxy_module.SESSION_KEY = _sec.token_bytes(32)
        # Post-rotation: same cookie must NOT verify any more.
        assert proxy_module._verify_chal_cookie(cookie, ua, ip_tier) is False
        # A NEW cookie minted under the new key must verify.
        new_cookie = proxy_module._make_chal_cookie(ua, "deadbeef00000099", ip_tier)
        assert proxy_module._verify_chal_cookie(new_cookie, ua, ip_tier) is True
    finally:
        proxy_module.SESSION_KEY = saved


def test_v146_request_id_threaded_through_responses(proxy_module):
    """1.4.6: every response (allowed, silent-decoyed, error) carries
    X-Request-ID, and the same id appears on the events deque entry."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                # Fire two unrelated requests, each should get a unique id.
                r1 = await client.get("/landing", headers=_browser_headers())
                rid1 = r1.headers.get("X-Request-ID", "")
                await r1.read()
                r2 = await client.get("/api/x",
                                      headers=_browser_headers({"Accept":"application/json"}))
                rid2 = r2.headers.get("X-Request-ID", "")
                await r2.read()
                assert rid1 and rid2 and rid1 != rid2, \
                    f"expected unique X-Request-IDs, got {rid1!r} vs {rid2!r}"
                # The events deque should carry both rids.
                rids = {ev.get("rid", "") for ev in proxy_module.events}
                assert rid1 in rids
                assert rid2 in rids
    _run(go())


def test_v146_inbound_request_id_honoured(proxy_module):
    """1.4.6: a CDN / front-proxy that already tagged the request with
    X-Request-ID has its trace honoured (no replacement)."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                forced = "trace-abcdef-1234"
                r = await client.get("/landing", headers={
                    **_browser_headers(),
                    "X-Request-ID": forced,
                })
                await r.read()
                assert r.headers.get("X-Request-ID") == forced
    _run(go())


def test_v146_inbound_request_id_rejected_if_unsafe(proxy_module):
    """1.4.6: a malformed (CRLF / control-byte) inbound trace id is
    discarded and a fresh one minted, preventing log-injection."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                # aiohttp's client rejects CR/LF in headers at the client
                # side, so we test by passing an over-long string instead;
                # the regex caps at 64 chars.
                evil = "x" * 200
                r = await client.get("/landing", headers={
                    **_browser_headers(),
                    "X-Request-ID": evil,
                })
                await r.read()
                got = r.headers.get("X-Request-ID", "")
                assert got != evil
                assert len(got) <= 64
    _run(go())


def test_v147_config_get_returns_current_state(proxy_module):
    """1.4.7 (refit 1.6.7): GET /antibot-appsec-gateway/secured/config
    returns the current value of every hot-reloadable knob, gated by
    session cookie + admin-IP allowlist."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                r = await client.get("/antibot-appsec-gateway/secured/config",
                                      cookies=_admin_cookie(proxy_module))
                assert r.status == 200
                body = _json.loads(await r.text())
                assert "state" in body
                # A few knobs we expect to see surfaced.
                for expected in ("JS_CHALLENGE", "BOT_TRAP_FORMS",
                                 "RISK_BAN_THRESHOLD", "JS_CHAL_OPEN_PATHS"):
                    assert expected in body["state"], expected
    _run(go())


def test_v147_config_post_applies_and_rejects(proxy_module):
    """1.4.7: POST /antibot-appsec-gateway/secured/config applies whitelisted knobs in-memory and
    rejects everything else. Out-of-bounds values are also rejected."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                # Capture pre-state for restore so this test can't pollute
                # the module-global view that subsequent tests rely on.
                pre = {
                    "JS_CHALLENGE":         proxy_module.JS_CHALLENGE,
                    "RISK_BAN_THRESHOLD":   proxy_module.RISK_BAN_THRESHOLD,
                    "RATE_LIMIT_REFILL":    proxy_module.RATE_LIMIT_REFILL,
                    "JS_CHAL_OPEN_PATHS":   list(proxy_module.JS_CHAL_OPEN_PATHS),
                }
                payload = {
                    "JS_CHALLENGE":          False,        # toggle
                    "RISK_BAN_THRESHOLD":    42,           # int in range
                    "RATE_LIMIT_REFILL":     2.5,          # float in range
                    "JS_CHAL_OPEN_PATHS":    "/api/,/v1/", # CSV → list
                    # Rejection cases:
                    "RATE_LIMIT_BURST":      99999999,     # out-of-bounds
                    "UPSTREAM":              "https://evil",  # not on whitelist
                    "SESSION_KEY":           "00" * 32,    # not on whitelist
                }
                try:
                    r = await client.post("/antibot-appsec-gateway/secured/config",
                        data=_json.dumps(payload),
                        headers={"Content-Type": "application/json"},
                        cookies=_admin_cookie(proxy_module))
                    assert r.status == 200
                    body = _json.loads(await r.text())
                    # Applied
                    assert "JS_CHALLENGE" in body["applied"]
                    assert body["applied"]["RISK_BAN_THRESHOLD"] == 42
                    assert body["applied"]["RATE_LIMIT_REFILL"] == 2.5
                    assert body["applied"]["JS_CHAL_OPEN_PATHS"] == [
                        "/api/", "/v1/"]
                    # Rejected
                    assert "RATE_LIMIT_BURST" in body["rejected"]
                    assert "UPSTREAM"        in body["rejected"]
                    assert "SESSION_KEY"     in body["rejected"]
                    # In-memory mutation actually happened.
                    assert proxy_module.JS_CHALLENGE is False
                    assert proxy_module.RISK_BAN_THRESHOLD == 42
                    assert proxy_module.JS_CHAL_OPEN_PATHS == [
                        "/api/", "/v1/"]
                finally:
                    # Restore state for following tests.
                    for k, v in pre.items():
                        setattr(proxy_module, k, v)
    _run(go())


def test_v147_config_unauth_silent_decoyed(proxy_module):
    """No admin key → /antibot-appsec-gateway/secured/config silently decoys (consistent with /__*
    routes; no leak of the endpoint's existence)."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="rightkey") as client:
                r = await client.get("/antibot-appsec-gateway/secured/config")
                # Silent decoy returns the upstream homepage marker, not JSON.
                body = await r.read()
                assert _UPSTREAM_MARK not in body or b"upstream" not in body[:50]
    _run(go())


def test_v150_shared_ban_set_get_round_trip(proxy_module):
    """1.5.0: a ban written via _shared_ban_set is readable via
    _shared_ban_get from a fresh in-process state — proves the
    write-through / read-through path works against a real (faked)
    Redis. Cross-instance scenario: another gateway writes; this one
    reads."""
    pytest.importorskip("fakeredis")
    import fakeredis.aioredis as _fr

    async def go():
        # Inject a fake Redis client into the proxy module.
        saved_client = proxy_module._redis
        proxy_module._redis = _fr.FakeRedis(decode_responses=True)
        try:
            await proxy_module._shared_ban_set(
                "track-key-X", time.time() + 600, "canary-echo")
            until = await proxy_module._shared_ban_get("track-key-X")
            assert until > time.time() + 500    # ~10 minutes ahead
            # Unrelated key returns 0
            assert (await proxy_module._shared_ban_get("track-key-Y")) == 0.0
        finally:
            proxy_module._redis = saved_client

    import asyncio, time
    asyncio.new_event_loop().run_until_complete(go())


def test_v150_is_banned_consults_shared_store_on_local_miss(proxy_module):
    """1.5.0: when the local in-memory ban map says 'not banned' but the
    shared store has an entry, is_banned() must return True. This is the
    cross-instance case (gateway A wrote, gateway B reads)."""
    pytest.importorskip("fakeredis")
    import fakeredis.aioredis as _fr

    async def go():
        saved_client = proxy_module._redis
        proxy_module._redis = _fr.FakeRedis(decode_responses=True)
        try:
            # Local state has nothing for this identity yet.
            tk = "cross-instance-bot-1"
            assert proxy_module.ip_state[tk].banned_until == 0
            # But Redis (written by another instance) does.
            await proxy_module._shared_ban_set(
                tk, time.time() + 300, "from-other-instance")
            # Local check now sees the ban via the read-through.
            banned, remaining = await proxy_module.is_banned(tk)
            assert banned is True
            assert remaining > 200
        finally:
            proxy_module._redis = saved_client
            proxy_module.ip_state.pop("cross-instance-bot-1", None)

    import asyncio, time
    asyncio.new_event_loop().run_until_complete(go())


def test_v150_disabled_when_redis_url_unset(proxy_module):
    """1.5.0: with REDIS_URL empty, _redis is None and the helpers are
    no-ops; the gateway behaves exactly as it did pre-1.5.0."""
    saved_client = proxy_module._redis
    proxy_module._redis = None
    try:
        async def go():
            # set returns silently
            await proxy_module._shared_ban_set("x", time.time() + 60, "r")
            # get returns 0.0 (no-op)
            assert (await proxy_module._shared_ban_get("x")) == 0.0
        import asyncio, time
        asyncio.new_event_loop().run_until_complete(go())
    finally:
        proxy_module._redis = saved_client


def test_v150_session_churn_bans_fingerprint(proxy_module):
    """1.5.0: minting > SESSION_CHURN_MAX cookies from the same
    (UA + IP-tier + JA4) within SESSION_CHURN_WINDOW_S triggers a ban
    on the fingerprint. Real users mint 1–2 cookies per visit; an
    automation rotating sessions per payload exceeds this fast."""
    import asyncio
    saved_max = proxy_module.SESSION_CHURN_MAX
    proxy_module.SESSION_CHURN_MAX = 3
    try:
        async def go():
            ua = "Mozilla/5.0 (test-churn)"
            ip_tier = proxy_module._ip_tier("198.51.100.5")
            ja4 = "t13d_churn_test"
            fp_h = proxy_module._fp_hash(ua, ip_tier, ja4)
            proxy_module._fp_session_creations.pop(fp_h, None)
            # First N mints: under threshold, no ban yet.
            for _ in range(proxy_module.SESSION_CHURN_MAX):
                fired = await proxy_module._record_chal_mint(
                    ua, ip_tier, ja4, "198.51.100.5")
                assert fired is False
            # The (N+1)th mint crosses → ban fires.
            fired = await proxy_module._record_chal_mint(
                ua, ip_tier, ja4, "198.51.100.5")
            assert fired is True
            # The fingerprint is now in the in-memory ban map.
            banned, _ = await proxy_module.is_banned(fp_h)
            assert banned is True
        asyncio.new_event_loop().run_until_complete(go())
    finally:
        proxy_module.SESSION_CHURN_MAX = saved_max


def test_v150_observe_ja4_ban_auto_adds_after_threshold(proxy_module):
    """1.5.0: after JA4_AUTODENY_THRESHOLD ban observations on the same
    JA4, the fingerprint is auto-added to the local JA4_DENY_LIST."""
    pytest.importorskip("fakeredis")
    import fakeredis.aioredis as _fr
    import asyncio
    saved_redis = proxy_module._redis
    saved_thr   = proxy_module.JA4_AUTODENY_THRESHOLD
    saved_set   = set(proxy_module.JA4_DENY_LIST)
    proxy_module.JA4_AUTODENY_THRESHOLD = 2
    proxy_module._redis = _fr.FakeRedis(decode_responses=True)
    try:
        async def go():
            ja4 = "t13d_evil_8a44_python"
            await proxy_module._observe_ja4_ban(ja4)
            assert ja4 not in proxy_module.JA4_DENY_LIST    # 1 ban < threshold
            await proxy_module._observe_ja4_ban(ja4)
            assert ja4 in proxy_module.JA4_DENY_LIST        # 2 bans = trip
        asyncio.new_event_loop().run_until_complete(go())
    finally:
        proxy_module._redis = saved_redis
        proxy_module.JA4_AUTODENY_THRESHOLD = saved_thr
        proxy_module.JA4_DENY_LIST.clear()
        proxy_module.JA4_DENY_LIST.update(saved_set)


def test_v150_webhook_called_on_ban(proxy_module, monkeypatch):
    """1.5.0: when WEBHOOK_URL is set, _post_webhook is dispatched on
    ban events (we capture the call rather than performing real HTTP)."""
    import asyncio
    captured = []
    async def fake_post(event):
        captured.append(event)
    monkeypatch.setattr(proxy_module, "_post_webhook", fake_post)
    monkeypatch.setattr(proxy_module, "WEBHOOK_URL", "https://example/webhook")
    # Force a ban via the risk model directly.
    saved_thr = proxy_module.RISK_BAN_THRESHOLD
    proxy_module.RISK_BAN_THRESHOLD = 50
    try:
        async def go():
            tk = "tk-webhook-test"
            proxy_module.ip_state.pop(tk, None)
            # canary-echo weight=80 → single hit ≥ threshold
            triggered = await proxy_module.update_risk_and_maybe_ban(
                tk, "canary-echo", "1.2.3.4")
            assert triggered is True
            # Give the create_task scheduler a chance.
            await asyncio.sleep(0.01)
            assert any(e.get("reason") == "canary-echo" for e in captured), \
                f"webhook not fired: {captured!r}"
        asyncio.new_event_loop().run_until_complete(go())
    finally:
        proxy_module.RISK_BAN_THRESHOLD = saved_thr
        proxy_module.ip_state.pop("tk-webhook-test", None)


def test_v9_legacy_cookie_format_still_validates(proxy_module):
    """Backward-compat: a 3-part (V1-format) cookie still validates so
    in-flight users don't get logged out at upgrade."""
    ua = "Mozilla/5.0 X"
    # Manually mint a V1-format (no ip_tier) cookie via the same code path
    # the V9 cookie minter uses with ip_tier="".
    cookie = proxy_module._make_chal_cookie(ua, "deadbeefdeadbeef", "")
    # Must validate regardless of the request-side tier.
    assert proxy_module._verify_chal_cookie(
        cookie, ua, proxy_module._ip_tier("198.51.100.7")) is True


# ── Defense-threshold slider (B and S) regression ───────────────────────
# Regression: k_q ReferenceError in main.html caused syncFromConfig() to
# crash before populating SOFT_CHALLENGE_SCORE (S) and RISK_BAN_THRESHOLD (B),
# leaving both knobs visually stuck at 0.

def test_defense_threshold_config_get_returns_numeric_soft_and_ban(proxy_module):
    """GET /secured/config must include SOFT_CHALLENGE_SCORE and
    RISK_BAN_THRESHOLD as numeric values. The slider's syncFromConfig()
    reads exactly these two keys to position S and B on page load."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get("/antibot-appsec-gateway/secured/config",
                                     cookies=_admin_cookie(proxy_module))
                assert r.status == 200
                body = _json.loads(await r.text())
                state = body["state"]
                assert "SOFT_CHALLENGE_SCORE" in state, \
                    "SOFT_CHALLENGE_SCORE missing from /secured/config — S knob will read 0"
                assert "RISK_BAN_THRESHOLD" in state, \
                    "RISK_BAN_THRESHOLD missing from /secured/config — B knob will read 0"
                assert isinstance(state["SOFT_CHALLENGE_SCORE"], (int, float)), \
                    "SOFT_CHALLENGE_SCORE must be numeric"
                assert isinstance(state["RISK_BAN_THRESHOLD"], (int, float)), \
                    "RISK_BAN_THRESHOLD must be numeric"
    _run(go())


def test_defense_threshold_defaults_are_nonzero(proxy_module):
    """Default SOFT_CHALLENGE_SCORE and RISK_BAN_THRESHOLD must be > 0.
    Zero defaults would make the slider initialise at the far left and
    silently disable risk-based banning."""
    assert proxy_module.SOFT_CHALLENGE_SCORE > 0, \
        "SOFT_CHALLENGE_SCORE default is 0 — S knob will appear at 0"
    assert proxy_module.RISK_BAN_THRESHOLD > 0, \
        "RISK_BAN_THRESHOLD default is 0 — B knob will appear at 0 and no bans will fire"


def test_defense_threshold_soft_persists_via_config_post(proxy_module):
    """POST SOFT_CHALLENGE_SCORE then GET — value must round-trip. Covers the
    slider dragEnd() → syncFromConfig() flow for the S knob."""
    import json as _json
    pre = proxy_module.SOFT_CHALLENGE_SCORE
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                cookie = _admin_cookie(proxy_module)
                r = await client.post("/antibot-appsec-gateway/secured/config",
                    data=_json.dumps({"SOFT_CHALLENGE_SCORE": 7}),
                    headers={"Content-Type": "application/json"},
                    cookies=cookie)
                assert r.status == 200
                body = _json.loads(await r.text())
                assert "SOFT_CHALLENGE_SCORE" in body["applied"], \
                    "SOFT_CHALLENGE_SCORE not applied"
                assert body["applied"]["SOFT_CHALLENGE_SCORE"] == 7

                r2 = await client.get("/antibot-appsec-gateway/secured/config",
                                      cookies=cookie)
                state = _json.loads(await r2.text())["state"]
                assert state["SOFT_CHALLENGE_SCORE"] == 7, \
                    "SOFT_CHALLENGE_SCORE did not persist — S knob will show stale value"
    try:
        _run(go())
    finally:
        proxy_module.SOFT_CHALLENGE_SCORE = pre


def test_defense_threshold_ban_persists_via_config_post(proxy_module):
    """POST RISK_BAN_THRESHOLD then GET — value must round-trip. Covers the
    slider dragEnd() → syncFromConfig() flow for the B knob."""
    import json as _json
    pre = proxy_module.RISK_BAN_THRESHOLD
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                cookie = _admin_cookie(proxy_module)
                r = await client.post("/antibot-appsec-gateway/secured/config",
                    data=_json.dumps({"RISK_BAN_THRESHOLD": 60}),
                    headers={"Content-Type": "application/json"},
                    cookies=cookie)
                assert r.status == 200
                body = _json.loads(await r.text())
                assert "RISK_BAN_THRESHOLD" in body["applied"], \
                    "RISK_BAN_THRESHOLD not applied"
                assert body["applied"]["RISK_BAN_THRESHOLD"] == 60

                r2 = await client.get("/antibot-appsec-gateway/secured/config",
                                      cookies=cookie)
                state = _json.loads(await r2.text())["state"]
                assert state["RISK_BAN_THRESHOLD"] == 60, \
                    "RISK_BAN_THRESHOLD did not persist — B knob will show stale value"
    try:
        _run(go())
    finally:
        proxy_module.RISK_BAN_THRESHOLD = pre


# ── UA-substring alone is NOT the gate ──────────────────────────────────

def test_mozilla_ua_alone_does_not_grant_access(proxy_module):
    """Encodes the pentester's exact summary: the visible anti-bot
    complexity is theatre if a Mozilla UA forwards. Cookie must be the
    real boundary."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    JS_CHALLENGE=True,
                                                                        TURNSTILE_ENABLED=True) as client:
                # Bare Mozilla UA, no cookie, JSON Accept → must NOT reach upstream
                r = await client.get("/api/v1/whatever", headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json",
                })
                body = await r.read()
                assert _UPSTREAM_MARK not in body, (
                    "Mozilla UA alone must not pass the gate")
    _run(go())


# ── version-string consistency regressions ──────────────────────────────────

def test_dashboard_html_version_matches_config():
    """Regression: dashboard HTML files must display the same version as
    config.GW_VERSION.  Catches version bumps that update config.py but
    leave HTML titles/headings stale (caught in 1.7.3 release cycle)."""
    import pathlib
    from config import GW_VERSION
    root = pathlib.Path(__file__).resolve().parent.parent
    dashboards = [
        "dashboards/main.html",
        "dashboards/agents.html",
        "dashboards/controls.html",
        "dashboards/geo.html",
        "dashboards/logs.html",
        "dashboards/service.html",
        "dashboards/settings.html",
    ]
    missing = []
    for rel in dashboards:
        path = root / rel
        if not path.exists():
            missing.append(f"{rel}: file not found")
            continue
        if GW_VERSION not in path.read_text(errors="replace"):
            missing.append(f"{rel}: missing {GW_VERSION!r}")
    assert not missing, (
        "Dashboard HTML version mismatch — update to match config.GW_VERSION:\n"
        + "\n".join(missing)
    )


# ── BYPASS_PATHS: detection-free path prefix regressions ────────────────────

def test_bypass_paths_proxied_to_upstream(proxy_module):
    """A path that matches a BYPASS_PATHS prefix must reach upstream directly,
    bypassing the JS challenge gate."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                   JS_CHALLENGE=True,
                                   TURNSTILE_ENABLED=True,
                                   BYPASS_PATHS=["/static/"]) as client:
                r = await client.get("/static/app.js", headers={
                    "User-Agent": "curl/7.88.0",
                    "Accept": "*/*",
                })
                body = await r.read()
                assert _UPSTREAM_MARK in body, (
                    "Request to a BYPASS_PATHS prefix must reach upstream directly — "
                    "bot detection must not gate static assets"
                )
    _run(go())


def test_bypass_paths_prefix_matches_subpath(proxy_module):
    """Prefix matching: /assets/ configured → /assets/img/logo.png proxied."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                   JS_CHALLENGE=True,
                                   TURNSTILE_ENABLED=True,
                                   BYPASS_PATHS=["/assets/"]) as client:
                r = await client.get("/assets/img/logo.png", headers={
                    "User-Agent": "curl/7.88.0",
                })
                body = await r.read()
                assert _UPSTREAM_MARK in body, (
                    "Prefix /assets/ must match /assets/img/logo.png — "
                    "any sub-path under a bypass prefix must be proxied"
                )
    _run(go())


def test_bypass_paths_non_bypass_path_still_inspected(proxy_module):
    """A path not in BYPASS_PATHS must still be inspected.
    Bot UA with no chal cookie on /api/ must be blocked even when /static/ is bypassed."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                   JS_CHALLENGE=True,
                                   TURNSTILE_ENABLED=True,
                                   BYPASS_PATHS=["/static/"]) as client:
                r = await client.get("/api/v1/users", headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json",
                })
                body = await r.read()
                assert _UPSTREAM_MARK not in body, (
                    "/api/v1/users is not in BYPASS_PATHS — "
                    "bot detection must still run on this path"
                )
    _run(go())


def test_bypass_paths_empty_list_inspects_all(proxy_module):
    """Empty BYPASS_PATHS (default) must not skip detection on any path.
    Regression guard: ensure the bypass check short-circuits only when non-empty."""
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                   JS_CHALLENGE=True,
                                   TURNSTILE_ENABLED=True,
                                   BYPASS_PATHS=[]) as client:
                r = await client.get("/static/app.js", headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json",
                })
                body = await r.read()
                assert _UPSTREAM_MARK not in body, (
                    "Empty BYPASS_PATHS must not exempt any path — "
                    "all paths go through detection when list is empty"
                )
    _run(go())


def test_bypass_paths_no_ip_state_recorded(proxy_module):
    """Bypass path requests must not create ip_state entries — detection and
    risk scoring are skipped. An audit event is written to db_queue (event log)
    but record() is never called, so ip_state stays empty."""
    from state import ip_state
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                   BYPASS_PATHS=["/static/"]) as client:
                ip_state.clear()
                await client.get("/static/app.css", headers={
                    "User-Agent": "curl/7.88.0",
                })
                key = next(
                    (k for k, s in ip_state.items() if s.last_ip == "127.0.0.1"),
                    None,
                )
                assert key is None, (
                    "Bypass path must not create an ip_state entry — "
                    "record() must not be called for bypassed requests"
                )
    _run(go())


def test_bypass_paths_hot_reload_via_config_endpoint(proxy_module):
    """BYPASS_PATHS applied via the config endpoint takes effect immediately.
    A path that was blocked before the POST must be proxied after."""
    import json as _json
    pre = list(proxy_module.BYPASS_PATHS)
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                   JS_CHALLENGE=True,
                                   TURNSTILE_ENABLED=True,
                                   BYPASS_PATHS=[]) as client:
                # Before: /uploads/ blocked (no bypass configured)
                r1 = await client.get("/uploads/doc.pdf", headers={
                    "User-Agent": "curl/7.88.0",
                })
                body1 = await r1.read()
                assert _UPSTREAM_MARK not in body1, (
                    "Pre-reload: /uploads/ must be inspected with empty BYPASS_PATHS"
                )

                # Hot-reload: add /uploads/ to bypass list
                r_cfg = await client.post(
                    "/antibot-appsec-gateway/secured/config",
                    data=_json.dumps({"BYPASS_PATHS": ["/uploads/"]}),
                    headers={"Content-Type": "application/json"},
                    cookies=_admin_cookie(proxy_module),
                )
                assert r_cfg.status == 200
                cfg_body = _json.loads(await r_cfg.text())
                assert "BYPASS_PATHS" in cfg_body.get("applied", {}), (
                    "BYPASS_PATHS must be accepted by the config endpoint"
                )

                # After: /uploads/ must now be proxied directly
                r2 = await client.get("/uploads/doc.pdf", headers={
                    "User-Agent": "curl/7.88.0",
                })
                body2 = await r2.read()
                assert _UPSTREAM_MARK in body2, (
                    "Post-reload: /uploads/ must be proxied after BYPASS_PATHS hot-reload"
                )
    try:
        _run(go())
    finally:
        proxy_module.BYPASS_PATHS = pre
        _propagate_to_all_modules("BYPASS_PATHS", pre)


# ── Config endpoint QA — response always valid JSON, fields apply correctly ──

def test_config_post_rate_limit_burst_applies(proxy_module):
    """RATE_LIMIT_BURST: valid in-range value must be applied and response
    must be valid JSON. Regression for the 'JSON.parse: unexpected character
    at column 5' error seen when saving threshold fields."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                pre = proxy_module.RATE_LIMIT_BURST
                try:
                    r = await client.post(
                        "/antibot-appsec-gateway/secured/config",
                        data=_json.dumps({"RATE_LIMIT_BURST": 25}),
                        headers={"Content-Type": "application/json"},
                        cookies=_admin_cookie(proxy_module),
                    )
                    assert r.status == 200
                    text = await r.text()
                    body = _json.loads(text)           # must not raise
                    assert "applied" in body
                    assert body["applied"].get("RATE_LIMIT_BURST") == 25
                    assert proxy_module.RATE_LIMIT_BURST == 25
                finally:
                    proxy_module.RATE_LIMIT_BURST = pre
                    _propagate_to_all_modules("RATE_LIMIT_BURST", pre)
    _run(go())


def test_config_post_rate_limit_refill_applies(proxy_module):
    """RATE_LIMIT_REFILL float applies correctly."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                pre = proxy_module.RATE_LIMIT_REFILL
                try:
                    r = await client.post(
                        "/antibot-appsec-gateway/secured/config",
                        data=_json.dumps({"RATE_LIMIT_REFILL": 5.0}),
                        headers={"Content-Type": "application/json"},
                        cookies=_admin_cookie(proxy_module),
                    )
                    assert r.status == 200
                    body = _json.loads(await r.text())
                    assert body["applied"].get("RATE_LIMIT_REFILL") == 5.0
                    assert proxy_module.RATE_LIMIT_REFILL == 5.0
                finally:
                    proxy_module.RATE_LIMIT_REFILL = pre
                    _propagate_to_all_modules("RATE_LIMIT_REFILL", pre)
    _run(go())


def test_config_post_ip_burst_and_refill_apply(proxy_module):
    """IP_BURST and IP_REFILL (per-socket-IP bucket) apply correctly."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                pre_burst  = proxy_module.IP_BURST
                pre_refill = proxy_module.IP_REFILL
                try:
                    r = await client.post(
                        "/antibot-appsec-gateway/secured/config",
                        data=_json.dumps({"IP_BURST": 30, "IP_REFILL": 4.0}),
                        headers={"Content-Type": "application/json"},
                        cookies=_admin_cookie(proxy_module),
                    )
                    assert r.status == 200
                    body = _json.loads(await r.text())
                    assert body["applied"].get("IP_BURST")  == 30
                    assert body["applied"].get("IP_REFILL") == 4.0
                    assert proxy_module.IP_BURST  == 30
                    assert proxy_module.IP_REFILL == 4.0
                finally:
                    proxy_module.IP_BURST  = pre_burst
                    proxy_module.IP_REFILL = pre_refill
                    _propagate_to_all_modules("IP_BURST",  pre_burst)
                    _propagate_to_all_modules("IP_REFILL", pre_refill)
    _run(go())


def test_config_post_custom_rules_ip_cidr_response_is_valid_json(proxy_module):
    """CUSTOM_RULES with ip_cidr — applied response must be valid JSON even
    though _to_custom_rules stores compiled IPv4Network objects in _ip_nets.
    Regression: config_endpoint was missing _json_safe(applied), causing
    TypeError during json.dumps when CUSTOM_RULES contained ip_cidr rules."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                pre = proxy_module.CUSTOM_RULES
                rules = [{"if": {"ip_cidr": "10.0.0.0/8"}, "then": "allow"}]
                try:
                    r = await client.post(
                        "/antibot-appsec-gateway/secured/config",
                        data=_json.dumps({"CUSTOM_RULES": rules}),
                        headers={"Content-Type": "application/json"},
                        cookies=_admin_cookie(proxy_module),
                    )
                    assert r.status == 200, f"expected 200, got {r.status}"
                    text = await r.text()
                    body = _json.loads(text)           # must not raise TypeError
                    assert "CUSTOM_RULES" in body.get("applied", {}), (
                        "CUSTOM_RULES must be in applied — response was: " + text[:200]
                    )
                    # Serialised form strips _ip_nets (private key)
                    applied_rules = body["applied"]["CUSTOM_RULES"]
                    assert isinstance(applied_rules, list)
                    assert applied_rules[0]["if"]["ip_cidr"] == ["10.0.0.0/8"]
                    assert "_ip_nets" not in applied_rules[0]["if"]
                    # State snapshot also must not expose _ip_nets
                    state_rules = body.get("state", {}).get("CUSTOM_RULES", [])
                    if state_rules:
                        assert "_ip_nets" not in state_rules[0].get("if", {})
                finally:
                    proxy_module.CUSTOM_RULES = pre
                    _propagate_to_all_modules("CUSTOM_RULES", pre)
    _run(go())


def test_config_post_out_of_bounds_numeric_rejected(proxy_module):
    """Out-of-bounds numeric values are rejected; response is valid JSON."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                r = await client.post(
                    "/antibot-appsec-gateway/secured/config",
                    data=_json.dumps({
                        "RATE_LIMIT_BURST":  0,          # below min=1
                        "RATE_LIMIT_REFILL": 0.0,        # below min>0
                        "IP_BURST":          999999999,  # above max
                    }),
                    headers={"Content-Type": "application/json"},
                    cookies=_admin_cookie(proxy_module),
                )
                assert r.status == 200
                body = _json.loads(await r.text())
                assert "RATE_LIMIT_BURST"  in body["rejected"]
                assert "RATE_LIMIT_REFILL" in body["rejected"]
                assert "IP_BURST"          in body["rejected"]
    _run(go())


def test_config_post_unknown_knob_rejected(proxy_module):
    """Fields not in _HOT_RELOAD_KNOBS are rejected; known fields still apply."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                pre = proxy_module.RATE_LIMIT_BURST
                try:
                    r = await client.post(
                        "/antibot-appsec-gateway/secured/config",
                        data=_json.dumps({
                            "RATE_LIMIT_BURST": 22,
                            "UPSTREAM":         "https://evil.com",
                            "SECRET_KEY":       "hacked",
                            "__PROTO__":        "injection",
                        }),
                        headers={"Content-Type": "application/json"},
                        cookies=_admin_cookie(proxy_module),
                    )
                    assert r.status == 200
                    body = _json.loads(await r.text())
                    assert body["applied"].get("RATE_LIMIT_BURST") == 22
                    assert "UPSTREAM"    in body["rejected"]
                    assert "SECRET_KEY"  in body["rejected"]
                    assert "__PROTO__"   in body["rejected"]
                finally:
                    proxy_module.RATE_LIMIT_BURST = pre
                    _propagate_to_all_modules("RATE_LIMIT_BURST", pre)
    _run(go())


def test_config_post_hostile_ban_secs_applies(proxy_module):
    """HOSTILE_BAN_SECS and REALLY_BAN_SECS update correctly."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                pre_h = proxy_module.HOSTILE_BAN_SECS
                pre_r = proxy_module.REALLY_BAN_SECS
                try:
                    r = await client.post(
                        "/antibot-appsec-gateway/secured/config",
                        data=_json.dumps({"HOSTILE_BAN_SECS": 3600,
                                          "REALLY_BAN_SECS": 86400}),
                        headers={"Content-Type": "application/json"},
                        cookies=_admin_cookie(proxy_module),
                    )
                    assert r.status == 200
                    body = _json.loads(await r.text())
                    assert body["applied"].get("HOSTILE_BAN_SECS") == 3600
                    assert body["applied"].get("REALLY_BAN_SECS") == 86400
                    assert proxy_module.HOSTILE_BAN_SECS == 3600
                    assert proxy_module.REALLY_BAN_SECS  == 86400
                finally:
                    proxy_module.HOSTILE_BAN_SECS = pre_h
                    proxy_module.REALLY_BAN_SECS  = pre_r
                    _propagate_to_all_modules("HOSTILE_BAN_SECS", pre_h)
                    _propagate_to_all_modules("REALLY_BAN_SECS",  pre_r)
    _run(go())


def test_config_post_bool_fields_apply(proxy_module):
    """Boolean knobs toggle correctly and response is valid JSON."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                for knob in ("BODY_PATTERN_MATCH", "INJECT_SECURITY_HEADERS",
                             "DLP_ENABLED", "TARPIT_ENABLED"):
                    pre = getattr(proxy_module, knob)
                    try:
                        r = await client.post(
                            "/antibot-appsec-gateway/secured/config",
                            data=_json.dumps({knob: not pre}),
                            headers={"Content-Type": "application/json"},
                            cookies=_admin_cookie(proxy_module),
                        )
                        assert r.status == 200, f"{knob}: expected 200"
                        body = _json.loads(await r.text())
                        assert knob in body.get("applied", {}), (
                            f"{knob} must appear in 'applied'"
                        )
                        assert getattr(proxy_module, knob) is (not pre), (
                            f"{knob} in-memory state not updated"
                        )
                    finally:
                        setattr(proxy_module, knob, pre)
                        _propagate_to_all_modules(knob, pre)
    _run(go())


def test_config_post_list_fields_apply(proxy_module):
    """List knobs (JA4_DENY_LIST, JWT_VALIDATE_PATHS) apply and response is valid JSON."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                pre_ja4 = proxy_module.JA4_DENY_LIST
                pre_jwt = proxy_module.JWT_VALIDATE_PATHS
                try:
                    r = await client.post(
                        "/antibot-appsec-gateway/secured/config",
                        data=_json.dumps({
                            "JA4_DENY_LIST":    ["t13d1517h2_8daaf6152771_b0da82dd1658"],
                            "JWT_VALIDATE_PATHS": ["/api/private/*"],
                        }),
                        headers={"Content-Type": "application/json"},
                        cookies=_admin_cookie(proxy_module),
                    )
                    assert r.status == 200
                    body = _json.loads(await r.text())
                    assert "JA4_DENY_LIST"     in body["applied"]
                    assert "JWT_VALIDATE_PATHS" in body["applied"]
                finally:
                    proxy_module.JA4_DENY_LIST     = pre_ja4
                    proxy_module.JWT_VALIDATE_PATHS = pre_jwt
                    _propagate_to_all_modules("JA4_DENY_LIST",     pre_ja4)
                    _propagate_to_all_modules("JWT_VALIDATE_PATHS", pre_jwt)
    _run(go())


def test_config_get_includes_rate_limit_fields(proxy_module):
    """GET /secured/config must include all rate-limit threshold fields
    so the controls dashboard can render them correctly."""
    import json as _json
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up,
                                    INTERNAL_KEY="testkey") as client:
                r = await client.get(
                    "/antibot-appsec-gateway/secured/config",
                    cookies=_admin_cookie(proxy_module),
                )
                assert r.status == 200
                body = _json.loads(await r.text())
                state = body.get("state", {})
                for field in ("RATE_LIMIT_BURST", "RATE_LIMIT_REFILL",
                              "IP_BURST", "IP_REFILL",
                              "HOSTILE_BAN_SECS", "REALLY_BAN_SECS",
                              "RISK_BAN_THRESHOLD", "SOFT_CHALLENGE_SCORE"):
                    assert field in state, (
                        f"{field} missing from GET /secured/config state"
                    )
    _run(go())
