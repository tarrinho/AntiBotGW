"""
Tests for the v1.4 controls:
  • #4 body-pattern matching (extends suspicious-path to bodies)
  • #5 slowloris guard (BODY_TIMEOUT)
  • #6 bot-trap forms (hidden field auto-injection + detection)
  • #1 JS challenge (invisible CAPTCHA)
"""
import asyncio
import os
import time
import pytest
from contextlib import asynccontextmanager

from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── #4 — body pattern match ──────────────────────────────────────────────

@pytest.mark.parametrize("body,ctype,expected", [
    (b"x=1' UNION SELECT * FROM users--",   "application/x-www-form-urlencoded", True),
    (b"<script>alert(1)</script>",           "application/json",                 True),
    (b'{"q":"{{7*7}}"}',                     "application/json",                 True),
    (b"name=alice;cat /etc/passwd",          "application/x-www-form-urlencoded", True),
    (b"name=alice&age=30",                   "application/x-www-form-urlencoded", False),
    (b'{"name":"alice","age":30}',           "application/json",                 False),
    (b"\x89PNG\r\n\x1a\n",                   "image/png",                        False),  # binary skipped
    (b"",                                    "application/json",                 False),
])
def test_is_suspicious_body(proxy_module, body, ctype, expected):
    proxy_module.BODY_PATTERN_MATCH = True   # ensure enabled
    try:
        assert proxy_module.is_suspicious_body(body, ctype) is expected
    finally:
        proxy_module.BODY_PATTERN_MATCH = False


def test_body_pattern_off_by_default(proxy_module):
    proxy_module.BODY_PATTERN_MATCH = False
    assert proxy_module.is_suspicious_body(b"' OR 1=1 --", "application/json") is False


def test_body_pattern_decodes_percent_encoded_form(proxy_module):
    """L3: form-encoded SQLi like name=%27+OR+1%3D1 must be caught after
    percent-decoding."""
    proxy_module.BODY_PATTERN_MATCH = True
    try:
        # %27%20OR%201%3D1 == ' OR 1=1
        encoded = b"name=alice&q=%27%20OR%201%3D1"
        assert proxy_module.is_suspicious_body(encoded,
            "application/x-www-form-urlencoded") is True
        # Unrelated benign form: must not match
        assert proxy_module.is_suspicious_body(b"name=alice&age=30",
            "application/x-www-form-urlencoded") is False
    finally:
        proxy_module.BODY_PATTERN_MATCH = False


# ── #6 — bot-trap forms ──────────────────────────────────────────────────

def test_inject_bot_trap_when_enabled(proxy_module):
    proxy_module.BOT_TRAP_FORMS = True
    body = b"<html><body><form method=POST><input name=email></form></body></html>"
    out = proxy_module._inject_bot_trap(body)
    assert proxy_module.BOT_TRAP_FIELD.encode() in out
    assert b"position:absolute" in out  # the hidden styling
    proxy_module.BOT_TRAP_FORMS = False


def test_no_bot_trap_when_disabled(proxy_module):
    proxy_module.BOT_TRAP_FORMS = False
    body = b"<html><body><form method=POST></form></body></html>"
    assert proxy_module._inject_bot_trap(body) == body


def test_bot_trap_triggered_on_filled_field(proxy_module):
    """1.5.4 — _bot_trap_triggered now returns (triggered, matched_field).
    1.5.4 — BOT_TRAP_FIELD is now BOT_TRAP_FIELDS[] (per-process random suffixes)."""
    proxy_module.BOT_TRAP_FORMS = True
    field = proxy_module.BOT_TRAP_FIELDS[0]
    body = f"name=alice&{field}=spam@example.com&age=30".encode()
    triggered, matched = proxy_module._bot_trap_triggered(body, "application/x-www-form-urlencoded")
    assert triggered is True and matched == field
    proxy_module.BOT_TRAP_FORMS = False


def test_bot_trap_not_triggered_on_empty_field(proxy_module):
    proxy_module.BOT_TRAP_FORMS = True
    field = proxy_module.BOT_TRAP_FIELDS[0]
    body = f"name=alice&{field}=&age=30".encode()
    triggered, _ = proxy_module._bot_trap_triggered(body, "application/x-www-form-urlencoded")
    assert triggered is False
    proxy_module.BOT_TRAP_FORMS = False


def test_bot_trap_not_triggered_on_json(proxy_module):
    """Bot trap is for HTML forms — JSON bodies are ignored even if the
    string happens to match (avoids false positives)."""
    proxy_module.BOT_TRAP_FORMS = True
    field = proxy_module.BOT_TRAP_FIELDS[0]
    body = f'{{"{field}":"spam"}}'.encode()
    triggered, _ = proxy_module._bot_trap_triggered(body, "application/json")
    assert triggered is False
    proxy_module.BOT_TRAP_FORMS = False


# ── #1 — JS challenge ────────────────────────────────────────────────────

def test_make_and_verify_chal_nonce_round_trip(proxy_module):
    n = proxy_module._make_chal_nonce()
    assert proxy_module._verify_chal_nonce(n) is True


def test_chal_nonce_rejects_forged(proxy_module):
    fake = "deadbeef|" + str(int(time.time())) + "|" + "0" * 32
    assert proxy_module._verify_chal_nonce(fake) is False


def test_chal_nonce_rejects_expired(proxy_module):
    """Re-issue a nonce from 5 minutes ago — should fail (TTL is 120s)."""
    import hmac, hashlib
    nonce = "deadbeef"
    issued = str(int(time.time()) - 300)
    payload = f"{nonce}|{issued}"
    sig = hmac.new(proxy_module.SESSION_KEY, payload.encode(),
                   hashlib.sha256).hexdigest()[:32]
    token = f"{payload}|{sig}"
    assert proxy_module._verify_chal_nonce(token) is False


def test_chal_cookie_round_trip(proxy_module):
    ua = "Mozilla/5.0 Chrome/120"
    c = proxy_module._make_chal_cookie(ua)
    assert proxy_module._verify_chal_cookie(c, ua) is True


def test_chal_cookie_rejects_forged(proxy_module):
    assert proxy_module._verify_chal_cookie("12345|" + "0" * 64, "ua") is False


def test_chal_cookie_rejects_empty(proxy_module):
    assert proxy_module._verify_chal_cookie("", "ua") is False


def test_chal_cookie_rejects_ua_mismatch(proxy_module):
    """L4: cookie issued for one UA must not validate under a different UA."""
    c = proxy_module._make_chal_cookie("Browser-A/1.0")
    assert proxy_module._verify_chal_cookie(c, "Browser-A/1.0") is True
    assert proxy_module._verify_chal_cookie(c, "Browser-B/2.0") is False


class _FakeReq:
    def __init__(self, method="GET", path="/", accept="text/html", cookie="",
                 remote="127.0.0.1"):
        self.method = method
        self.path = path
        self.headers = {"Accept": accept}
        self.cookies = {proxy_module_chal_cookie_name(): cookie} if cookie else {}
        self.remote = remote
        # 1.5.4 — middleware now reads request.get("_track_key") in
        # _js_challenge_required / _js_challenge_applicable.  Provide a
        # dict-like .get() that mirrors aiohttp.web.Request.
        self._extras = {}
    def get(self, key, default=None):
        return self._extras.get(key, default)
    def __setitem__(self, key, value):
        self._extras[key] = value


def proxy_module_chal_cookie_name():
    # helper for the CHAL_COOKIE constant
    import importlib
    m = importlib.import_module("proxy")
    return m.CHAL_COOKIE


def test_js_challenge_applicable_off_by_default(proxy_module):
    proxy_module.JS_CHALLENGE = False
    proxy_module.TURNSTILE_ENABLED = False
    assert proxy_module._js_challenge_applicable(_FakeReq()) is False


def test_js_challenge_applies_on_html_get_no_cookie(proxy_module):
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        assert proxy_module._js_challenge_applicable(_FakeReq()) is True
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_skips_static_assets(proxy_module):
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        for p in ("/style.css", "/app.js", "/logo.png", "/font.woff2"):
            assert proxy_module._js_challenge_applicable(
                _FakeReq(path=p)) is False, f"{p} should be skipped"
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_skips_admin(proxy_module):
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        for p in ("/antibot-appsec-gateway/live", "/antibot-appsec-gateway/secured/dashboard", "/antibot-appsec-gateway/secured/metrics"):
            assert proxy_module._js_challenge_applicable(_FakeReq(path=p)) is False
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_skips_when_cookie_valid(proxy_module):
    """The fake _FakeReq must use the same UA for both cookie issuance and
    the applicability check. Default _FakeReq has no UA (empty string) so
    _make_chal_cookie('') matches _verify_chal_cookie(cookie, '')."""
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        cookie = proxy_module._make_chal_cookie("")
        assert proxy_module._js_challenge_applicable(
            _FakeReq(cookie=cookie)) is False
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_skips_non_html_accept(proxy_module):
    """API clients (Accept: application/json) shouldn't get HTML back."""
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        assert proxy_module._js_challenge_applicable(
            _FakeReq(accept="application/json")) is False
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_skips_non_get(proxy_module):
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        for m in ("POST", "PUT", "DELETE", "OPTIONS", "PATCH"):
            assert proxy_module._js_challenge_applicable(
                _FakeReq(method=m)) is False
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


# ── V8 fix: chal cookie is required on EVERY non-static, non-admin path ──
# (not only on HTML GETs). API/XHR/POST without a cookie must be blocked,
# not silently forwarded. _js_challenge_applicable still returns False for
# non-HTML / non-GET (no interactive page), but _js_challenge_required is True
# so the middleware will issue a 401 JSON instead of forwarding.

def test_js_challenge_required_on_api_no_cookie(proxy_module):
    """V8: API path without a chal cookie must require challenge."""
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        r = _FakeReq(path="/release-management/api/v1/items",
                     accept="application/json")
        assert proxy_module._js_challenge_required(r) is True
        assert proxy_module._js_challenge_applicable(r) is False
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_required_on_post_no_cookie(proxy_module):
    """V8: POST without a cookie must require challenge (not forward)."""
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    # 1.5.5 — earlier tests may have left JS_CHAL_OPEN_PATHS populated.
    # Clear it so /api/ doesn't bypass the gate in this test.
    _saved_open = list(proxy_module.JS_CHAL_OPEN_PATHS)
    proxy_module.JS_CHAL_OPEN_PATHS = []
    try:
        r = _FakeReq(method="POST", path="/api/v1/login",
                     accept="application/json")
        assert proxy_module._js_challenge_required(r) is True
        assert proxy_module._js_challenge_applicable(r) is False
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False
        proxy_module.JS_CHAL_OPEN_PATHS = _saved_open


def test_js_challenge_not_required_when_cookie_valid_on_api(proxy_module):
    """Browser XHR carries the cookie transparently → must pass."""
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        cookie = proxy_module._make_chal_cookie("")
        r = _FakeReq(method="POST", path="/api/v1/login",
                     accept="application/json", cookie=cookie)
        assert proxy_module._js_challenge_required(r) is False
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_open_paths_opt_out(proxy_module):
    """Operator-defined open prefixes (S2S, webhooks) bypass the cookie req."""
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    saved = proxy_module.JS_CHAL_OPEN_PATHS[:]
    proxy_module.JS_CHAL_OPEN_PATHS[:] = ["/webhook/", "/s2s/"]
    try:
        for p in ("/webhook/github", "/s2s/sync"):
            r = _FakeReq(method="POST", path=p, accept="application/json")
            assert proxy_module._js_challenge_required(r) is False, p
        # non-listed path still requires challenge
        r2 = _FakeReq(method="POST", path="/api/v1/x",
                      accept="application/json")
        assert proxy_module._js_challenge_required(r2) is True
    finally:
        proxy_module.JS_CHAL_OPEN_PATHS[:] = saved
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_required_skips_static(proxy_module):
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        for p in ("/style.css", "/app.js", "/logo.png", "/font.woff2"):
            r = _FakeReq(path=p, accept="*/*")
            assert proxy_module._js_challenge_required(r) is False, p
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_required_skips_admin(proxy_module):
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    try:
        for p in ("/antibot-appsec-gateway/live", "/antibot-appsec-gateway/secured/dashboard", "/antibot-appsec-gateway/secured/metrics", "/antibot-appsec-gateway/challenge"):
            r = _FakeReq(path=p, accept="*/*")
            assert proxy_module._js_challenge_required(r) is False, p
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


# ── HTTP integration: JS challenge HTML is served, then cookie issued ────

@asynccontextmanager
async def _spin_simple_upstream():
    async def handler(request):
        return web.Response(text="upstream-ok", content_type="text/html")
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url, turnstile=False):
    """1.6.7 — `db_load_secrets()` runs on app startup and re-derives
    `TURNSTILE_ENABLED` from env (env wins over programmatic state).
    Tests that need Turnstile mode pass `turnstile=True` so we apply
    the toggle AFTER startup completes — otherwise the secrets loader
    flips it back to False and the JS-challenge HTML never renders."""
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    if turnstile:
        # The protect middleware reads these globals on every request,
        # so this takes effect immediately on the next call.
        proxy_module.TURNSTILE_ENABLED   = True
        proxy_module._TURNSTILE_CONFIGURED = True
        if not proxy_module.TURNSTILE_SITEKEY:
            proxy_module.TURNSTILE_SITEKEY = "1x00000000000000000000AA"
        if not proxy_module.TURNSTILE_SECRET:
            proxy_module.TURNSTILE_SECRET = "1x0000000000000000000000000000000AA"
    yield client
    await client.close()


def _browser_headers():
    return {
        "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
        "Accept":          "text/html,application/json",
        "Accept-Language": "en-GB",
        "Accept-Encoding": "gzip",
        "Sec-Ch-Ua":       '"Chromium";v="120"',
        "Sec-Fetch-Site":  "none",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Dest":  "document",
    }


def test_js_challenge_html_served_when_enabled(proxy_module):
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    # 1.5.5 — Turnstile is risk-gated by `_turnstile_active_threshold()`.
    # Patch it to always return -1 so the widget renders on every fresh
    # request (the in-test new identity has risk_score=0 ≥ -1 → shown).
    _saved_open = list(proxy_module.JS_CHAL_OPEN_PATHS)
    _saved_active_threshold = proxy_module._turnstile_active_threshold
    proxy_module._turnstile_active_threshold = lambda: -1.0
    proxy_module.JS_CHAL_OPEN_PATHS = []

    async def go():
        async with _spin_simple_upstream() as up:
            async with _spin_proxy(proxy_module, up, turnstile=True) as client:
                r = await client.get("/some-page", headers=_browser_headers())
                # Returns the challenge page (200 + text/html with our marker JS)
                assert r.status == 200
                body = await r.text()
                assert "Verifying" in body, f"body did not contain challenge: {body[:200]}"
                # NOT the upstream's "upstream-ok"
                assert "upstream-ok" not in body
    try:
        _run(go())
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False
        proxy_module._turnstile_active_threshold = _saved_active_threshold
        proxy_module.JS_CHAL_OPEN_PATHS = _saved_open


def test_js_challenge_endpoint_requires_turnstile_token(proxy_module):
    """The /antibot-appsec-gateway/challenge endpoint mints a chal cookie ONLY against a valid
    Cloudflare Turnstile token. Without one (or with TURNSTILE_ENABLED off)
    no cookie is issued. This is the only check that scripted clients
    cannot fabricate locally — the token is minted server-side by
    Cloudflare. We don't make outbound calls in tests, so we only verify
    the negative path (missing / TS-disabled)."""
    import re
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True
    proxy_module.TURNSTILE_SITEKEY = "test-key"
    proxy_module.TURNSTILE_SECRET = "test-secret"
    # 1.5.5 — risk-gated Turnstile: patch the threshold getter to always-show.
    _saved_active_threshold = proxy_module._turnstile_active_threshold
    _saved_open = list(proxy_module.JS_CHAL_OPEN_PATHS)
    proxy_module._turnstile_active_threshold = lambda: -1.0
    proxy_module.JS_CHAL_OPEN_PATHS = []

    async def go():
        async with _spin_simple_upstream() as up:
            async with _spin_proxy(proxy_module, up, turnstile=True) as client:
                hdrs = _browser_headers()
                r = await client.get("/page", headers=hdrs)
                body = await r.text()
                m = re.search(r'const n = "([^"]+)"', body)
                assert m, f"no nonce in challenge HTML: {body[:200]}"
                nonce = m.group(1)

                # POST without a Turnstile token — must be rejected.
                r_bad = await client.post("/antibot-appsec-gateway/challenge",
                    data={"n": nonce, "t": "/"},
                    headers={"User-Agent": hdrs["User-Agent"],
                             "Content-Type": "application/x-www-form-urlencoded"})
                assert r_bad.status == 403
                assert "turnstile" in (await r_bad.text()).lower()

                # If we disable Turnstile mid-flight, the endpoint refuses
                # to mint a cookie even with a "token" present (defensive).
                proxy_module.TURNSTILE_ENABLED = False
                r_off = await client.post("/antibot-appsec-gateway/challenge",
                    data={"n": nonce, "t": "/", "cf-turnstile-response": "x"},
                    headers={"User-Agent": hdrs["User-Agent"],
                             "Content-Type": "application/x-www-form-urlencoded"})
                assert r_off.status == 503
    try:
        _run(go())
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False
        proxy_module._turnstile_active_threshold = _saved_active_threshold
        proxy_module.JS_CHAL_OPEN_PATHS = _saved_open


def test_js_challenge_target_blocks_open_redirect(proxy_module):
    """M1: a hand-crafted request-target like //evil.com/ must NOT survive into
    the rendered JS — challenge falls back to '/'."""
    proxy_module.JS_CHALLENGE = True
    proxy_module.TURNSTILE_ENABLED = True

    class _R:
        def __init__(self, pq):
            self.path_qs = pq
            self.headers = {"Accept": "text/html"}
            self.cookies = {}
            self.method = "GET"
            self.path = pq.split("?")[0]

    try:
        # M1 protects against protocol-relative redirects (//host).
        # `/foo` and `/evil.com/` (single slash) are paths on the gateway and
        # are NOT navigations to another origin, so they are allowed.
        for evil in ("//evil.com/", "//evil.com/path?x=1", "//x.y/"):
            r = _R(evil)
            resp = proxy_module._serve_js_challenge(r)
            body = resp.text
            # The protocol-relative form MUST be stripped.
            assert '"//evil' not in body, f"open redirect leak for {evil!r}"
            assert '"//x.y'  not in body, f"open redirect leak for {evil!r}"
            # Backslash injection (used in Edge/IE redirect tricks)
            assert "\\\\" not in body
    finally:
        proxy_module.JS_CHALLENGE = False
        proxy_module.TURNSTILE_ENABLED = False


def test_js_challenge_disabled_passes_through(proxy_module):
    """Ensure the JS-challenge layer is fully no-op when JS_CHALLENGE=0."""
    proxy_module.JS_CHALLENGE = False
    proxy_module.TURNSTILE_ENABLED = False

    async def go():
        async with _spin_simple_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                r = await client.get("/page", headers=_browser_headers())
                body = await r.text()
                # Got upstream content, NOT the challenge page
                assert "Verifying browser" not in body
    _run(go())


# ── #5 — slowloris (BODY_TIMEOUT respected) ──────────────────────────────

def test_body_timeout_constant_is_set(proxy_module):
    """Sanity-check the slowloris guard is wired in."""
    assert hasattr(proxy_module, "BODY_TIMEOUT")
    assert proxy_module.BODY_TIMEOUT > 0
    assert hasattr(proxy_module, "HEADERS_TIMEOUT")
    assert proxy_module.HEADERS_TIMEOUT > 0
