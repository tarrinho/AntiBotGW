"""Functional / integration tests for AppSecGW.

These spin up the real aiohttp app from proxy.py inside an
aiohttp.test_utils.TestServer, then exercise the full middleware chain
end-to-end (cost_meter → session_cookie_finalizer → protect → upstream).

Upstream is faked by another in-process aiohttp app so tests stay
self-contained (no network, no Docker).

Run with:  pytest tests/test_functional.py -v
Requires:  pytest, pytest-asyncio
"""
import asyncio
import importlib
import json
import os
import secrets

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# Test fixtures need a writable DB and a fake upstream URL.  Set BEFORE
# importing proxy so module-level reads pick them up.
TEST_DB = f"/tmp/pytest_func_{secrets.token_hex(4)}.db"
os.environ["DB_PATH"] = TEST_DB
os.environ["UPSTREAM"] = "http://127.0.0.1:18999"   # fake — overridden per-test
os.environ["JS_CHALLENGE"] = "0"                    # tests want predictable flow
os.environ["TLS_ENABLED"] = "0"
os.environ.pop("TURNSTILE_SITEKEY", None)
os.environ.pop("TURNSTILE_SECRET", None)
os.environ.pop("ABUSEIPDB_KEY", None)
os.environ.pop("CROWDSEC_LAPI_URL", None)
os.environ.pop("CROWDSEC_LAPI_KEY", None)
os.environ.pop("MAXMIND_LICENSE_KEY", None)

# Wipe any stale DB
if os.path.exists(TEST_DB):
    os.remove(TEST_DB)

PROXY_PATH = os.path.join(os.path.dirname(__file__), "..", "proxy.py")
spec = importlib.util.spec_from_file_location("proxy", PROXY_PATH)
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


# ── Fixtures ──────────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def fake_upstream(aiohttp_server):
    """Tiny aiohttp app standing in for the real backend."""
    async def homepage(req):
        return web.Response(text="<html><body>real upstream homepage</body></html>",
                            content_type="text/html")
    async def secret(req):
        return web.Response(text='{"flag":"FLAG{should-not-leak}"}',
                            content_type="application/json")
    async def echo(req):
        return web.json_response({
            "method": req.method, "path": req.path,
            "headers": dict(req.headers), "ua": req.headers.get("User-Agent", ""),
        })

    app = web.Application()
    app.router.add_get("/", homepage)
    app.router.add_get("/secret", secret)
    app.router.add_route("*", "/echo", echo)
    server = await aiohttp_server(app)
    yield server


@pytest_asyncio.fixture
async def gw_client(fake_upstream, aiohttp_client):
    """Spin up the GW pointed at the fake upstream."""
    proxy.UPSTREAM = f"http://{fake_upstream.host}:{fake_upstream.port}"
    proxy.JS_CHALLENGE = False                     # off for these tests
    proxy.TURNSTILE_ENABLED = False
    proxy.ANUBIS_ENABLED = False
    # Fresh in-memory state so test order doesn't bleed
    proxy.ip_state.clear()
    proxy.events.clear()
    proxy.metrics["total_requests"] = 0
    proxy.metrics["allowed"] = 0
    proxy.metrics["blocked"] = 0
    proxy.metrics["by_reason"].clear()
    proxy.metrics["by_status"].clear()
    proxy.timeline.clear()

    app = proxy.make_app()
    # Ensure on_startup ran (sets up db_queue, prune_task, etc.)
    # aiohttp_client triggers app lifecycle hooks automatically.
    return await aiohttp_client(app)


# ── F1 — basic forwarding works for legit clients ────────────────────────
@pytest.mark.asyncio
async def test_legit_browser_forwarded(gw_client):
    """Real browser UA + browser-like headers → request reaches upstream."""
    resp = await gw_client.get(
        "/", headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Chromium";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
        })
    assert resp.status == 200
    body = await resp.text()
    assert "real upstream homepage" in body


# ── F2 — bot UA blocked ───────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_curl_ua_blocked(gw_client):
    """curl/8 UA → blocked. May fire ua-too-short (length < 12) OR ua-blocked
    (substring 'curl/' in UA_BLOCKLIST). Either is the gate doing its job."""
    await gw_client.get("/", headers={"User-Agent": "curl/8.0.1"})
    assert (_has_block_reason(proxy, "ua-too-short")
            or _has_block_reason(proxy, "ua-blocked")), \
        f"curl UA reached upstream — by_reason={dict(proxy.metrics['by_reason'])}"


@pytest.mark.asyncio
async def test_claude_user_ua_blocked(gw_client):
    """Claude-User UA must be blocked. 1.6.0 split AI UAs into named
    groups, so this now fires `ua-ai-anthropic` rather than the generic
    `ua-blocked` — accept either to stay backwards-compatible."""
    await gw_client.get(
        "/echo", headers={
            "User-Agent": "Claude-User (claude-code/2.1.121; +https://anthropic.com/)",
        })
    assert (_has_block_reason(proxy, "ua-blocked")
            or _has_block_reason(proxy, "ua-ai-anthropic")), \
        "Claude-User UA must match UA_BLOCKLIST or AI group"


# ── F3 — honeypot path hit ────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_honeypot_path_blocked(gw_client):
    """/.env triggers honeypot-silent + bumps risk score."""
    await gw_client.get(
        "/.env", headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html",
        })
    assert _has_block_reason(proxy, "honeypot-silent")


# ── F4 — suspicious-path catches CTF / SQLi markers ──────────────────────
@pytest.mark.asyncio
async def test_suspicious_path_blocked(gw_client):
    """/flag.txt and SQLi-marker query both fire suspicious-path."""
    UA = "Mozilla/5.0 (X11; Linux) Chrome/120 Safari/537.36"
    await gw_client.get("/flag.txt", headers={"User-Agent": UA, "Accept": "text/html"})
    assert _has_block_reason(proxy, "suspicious-path")


# ── F5 — admin endpoints require key ─────────────────────────────────────
def _admin_cookie():
    """1.6.7 — bearer-key auth was removed and sessions are now per-sid
    (server-side ledger). Mint a sid, prime the in-memory cache directly
    so verification succeeds without writing through the writer queue,
    and return a signed token carrying that sid."""
    sid = proxy._new_sid()
    proxy._SESSION_CACHE[sid] = {
        "username": "admin",
        "expires_ts": proxy._t.time() + proxy._SESSION_TTL,
        "revoked": False,
    }
    proxy._SESSION_CACHE_READY = True
    return {proxy._SESSION_COOKIE: proxy._session_sign("admin", sid=sid)}


@pytest.mark.asyncio
async def test_admin_no_cookie(gw_client):
    """No session cookie → silent decoy (404, not a 401/403 leak)."""
    resp = await gw_client.get("/antibot-appsec-gateway/secured/metrics")
    assert resp.status == 404


@pytest.mark.asyncio
async def test_admin_with_cookie(gw_client):
    """Valid session cookie returns the metrics JSON."""
    resp = await gw_client.get("/antibot-appsec-gateway/secured/metrics",
                                cookies=_admin_cookie())
    assert resp.status == 200
    body = await resp.json()
    assert "services" in body
    assert "detector_hits" in body


@pytest.mark.asyncio
async def test_admin_bearer_key_no_longer_accepted(gw_client):
    """1.6.7 — `?key=` and `X-Admin-Key` were removed. The shared admin
    key MUST no longer authorise /secured/ access (it is now ONLY the
    bootstrap admin password used at the login form)."""
    resp = await gw_client.get(f"/antibot-appsec-gateway/secured/metrics?key={proxy.INTERNAL_KEY}")
    assert resp.status == 404
    resp = await gw_client.get("/antibot-appsec-gateway/secured/metrics",
                                headers={"X-Admin-Key": proxy.INTERNAL_KEY})
    assert resp.status == 404


@pytest.mark.asyncio
async def test_admin_wrong_cookie_constant_time(gw_client):
    """Tampered/forged cookie fails identically to no cookie."""
    resp = await gw_client.get("/antibot-appsec-gateway/secured/metrics",
                                cookies={proxy._SESSION_COOKIE: "garbage|0|x"})
    assert resp.status == 404


# ── F6 — /antibot-appsec-gateway/live is unauth probe ──────────────────────────────────────────
@pytest.mark.asyncio
async def test_live_probe(gw_client):
    resp = await gw_client.get("/antibot-appsec-gateway/live")
    assert resp.status == 200
    assert (await resp.text()).strip() == "ok"


# ── F7 — /antibot-appsec-gateway/secured/config persists to DB ─────────────────────────────────────────
@pytest.mark.asyncio
async def test_config_post_persists(gw_client):
    """POST /antibot-appsec-gateway/secured/config writes to config_kv table."""
    import sqlite3
    resp = await gw_client.post(
        "/antibot-appsec-gateway/secured/config",
        json={"RISK_BAN_THRESHOLD": 42, "ENUM_THRESHOLD": 250},
        cookies=_admin_cookie(),
    )
    body = await resp.json()
    assert resp.status == 200
    assert body["applied"] == {"RISK_BAN_THRESHOLD": 42, "ENUM_THRESHOLD": 250}
    # Allow the async db_writer to drain
    await asyncio.sleep(0.1)
    conn = sqlite3.connect(proxy.DB_PATH)
    rows = dict(conn.execute("SELECT key, value FROM config_kv").fetchall())
    conn.close()
    assert json.loads(rows["RISK_BAN_THRESHOLD"]) == 42
    assert json.loads(rows["ENUM_THRESHOLD"]) == 250


@pytest.mark.asyncio
async def test_config_rejects_unknown(gw_client):
    """POST /antibot-appsec-gateway/secured/config rejects keys not in _HOT_RELOAD_KNOBS."""
    resp = await gw_client.post(
        "/antibot-appsec-gateway/secured/config",
        json={"BOGUS_KNOB": 1},
        cookies=_admin_cookie(),
    )
    body = await resp.json()
    assert "BOGUS_KNOB" in body["rejected"]


@pytest.mark.asyncio
async def test_config_validator_rejects_out_of_range(gw_client):
    """Out-of-range values must hit the validator."""
    resp = await gw_client.post(
        "/antibot-appsec-gateway/secured/config",
        json={"RISK_BAN_THRESHOLD": 0},     # below min
        cookies=_admin_cookie(),
    )
    body = await resp.json()
    assert "RISK_BAN_THRESHOLD" in body["rejected"]


# ── F7b — db_load_config: credential-gated knobs rejected without creds ──────
#
# KNOWN STARTUP INFO (not a bug):
#   [config-kv] ABUSEIPDB_ENABLED failed validator — env default kept
#   [config-kv] TURNSTILE_ENABLED failed validator — env default kept
#
# These lines appear at startup when the DB holds ABUSEIPDB_ENABLED=true or
# TURNSTILE_ENABLED=true but the matching credentials are absent from the env:
#   • ABUSEIPDB_ENABLED validator: (not v) or bool(ABUSEIPDB_KEY)
#   • TURNSTILE_ENABLED validator: (not v) or bool(TURNSTILE_SITEKEY and TURNSTILE_SECRET)
# This is intentional — enabling an integration without credentials would silently
# break all lookups, so db_load_config keeps the env default (False) and logs.
# The tests below document and verify this contract.

def test_db_load_config_rejects_abuseipdb_enabled_without_key(tmp_path):
    """db_load_config must reject ABUSEIPDB_ENABLED=true when ABUSEIPDB_KEY absent."""
    import sqlite3, importlib, importlib.util, sys, os

    db = str(tmp_path / "test.db")
    # Seed DB with ABUSEIPDB_ENABLED=true
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE config_kv (key TEXT PRIMARY KEY, value TEXT, updated_at REAL)")
    conn.execute("INSERT INTO config_kv VALUES ('ABUSEIPDB_ENABLED', 'true', 0)")
    conn.commit()
    conn.close()

    # Load proxy with no ABUSEIPDB_KEY
    env_backup = {k: os.environ.pop(k, None) for k in ("ABUSEIPDB_KEY",)}
    _orig_db_path = os.environ.get("DB_PATH")
    _orig_upstream = os.environ.get("UPSTREAM")
    os.environ["DB_PATH"] = db
    os.environ["UPSTREAM"] = "http://127.0.0.1:1"
    try:
        proxy_path = os.path.join(os.path.dirname(__file__), "..", "proxy.py")
        spec = importlib.util.spec_from_file_location("_test_proxy_abuseipdb", proxy_path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)

        g = {"_HOT_RELOAD_KNOBS": m._HOT_RELOAD_KNOBS, "_ENV_PROVIDED_KNOBS": set()}
        g.update({k: getattr(m, k) for k in m._HOT_RELOAD_KNOBS if hasattr(m, k)})
        g["ABUSEIPDB_KEY"] = ""          # ensure absent

        from db.sqlite import db_load_config
        db_load_config(g)

        # Validator must have rejected it — stays False
        assert not g.get("ABUSEIPDB_ENABLED"), (
            "ABUSEIPDB_ENABLED should stay False when ABUSEIPDB_KEY is absent; "
            "startup log line '[config-kv] ABUSEIPDB_ENABLED failed validator' is expected."
        )
    finally:
        # Restore env
        for k, v in env_backup.items():
            if v is not None:
                os.environ[k] = v
        if _orig_db_path is not None:
            os.environ["DB_PATH"] = _orig_db_path
        else:
            os.environ.pop("DB_PATH", None)
        if _orig_upstream is not None:
            os.environ["UPSTREAM"] = _orig_upstream
        else:
            os.environ.pop("UPSTREAM", None)


def test_db_load_config_rejects_turnstile_enabled_without_creds(tmp_path):
    """db_load_config must reject TURNSTILE_ENABLED=true when Turnstile creds absent."""
    import sqlite3, importlib, importlib.util, os

    db = str(tmp_path / "test2.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE config_kv (key TEXT PRIMARY KEY, value TEXT, updated_at REAL)")
    conn.execute("INSERT INTO config_kv VALUES ('TURNSTILE_ENABLED', 'true', 0)")
    conn.commit()
    conn.close()

    env_backup = {k: os.environ.pop(k, None) for k in ("TURNSTILE_SITEKEY", "TURNSTILE_SECRET")}
    _orig_db_path = os.environ.get("DB_PATH")
    _orig_upstream = os.environ.get("UPSTREAM")
    os.environ["DB_PATH"] = db
    os.environ["UPSTREAM"] = "http://127.0.0.1:1"
    try:
        proxy_path = os.path.join(os.path.dirname(__file__), "..", "proxy.py")
        spec = importlib.util.spec_from_file_location("_test_proxy_turnstile", proxy_path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)

        g = {"_HOT_RELOAD_KNOBS": m._HOT_RELOAD_KNOBS, "_ENV_PROVIDED_KNOBS": set()}
        g.update({k: getattr(m, k) for k in m._HOT_RELOAD_KNOBS if hasattr(m, k)})
        g["TURNSTILE_SITEKEY"] = ""
        g["TURNSTILE_SECRET"] = ""

        from db.sqlite import db_load_config
        db_load_config(g)

        assert not g.get("TURNSTILE_ENABLED"), (
            "TURNSTILE_ENABLED should stay False when TURNSTILE_SITEKEY/SECRET absent; "
            "startup log line '[config-kv] TURNSTILE_ENABLED failed validator' is expected."
        )
    finally:
        for k, v in env_backup.items():
            if v is not None:
                os.environ[k] = v
        if _orig_db_path is not None:
            os.environ["DB_PATH"] = _orig_db_path
        else:
            os.environ.pop("DB_PATH", None)
        if _orig_upstream is not None:
            os.environ["UPSTREAM"] = _orig_upstream
        else:
            os.environ.pop("UPSTREAM", None)


def test_db_load_config_accepts_abuseipdb_enabled_with_key(tmp_path):
    """db_load_config MUST apply ABUSEIPDB_ENABLED=true when ABUSEIPDB_KEY is present."""
    import sqlite3, importlib, importlib.util, os

    db = str(tmp_path / "test3.db")
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE config_kv (key TEXT PRIMARY KEY, value TEXT, updated_at REAL)")
    conn.execute("INSERT INTO config_kv VALUES ('ABUSEIPDB_ENABLED', 'true', 0)")
    conn.commit()
    conn.close()

    _orig_db_path = os.environ.get("DB_PATH")
    _orig_upstream = os.environ.get("UPSTREAM")
    os.environ["DB_PATH"] = db
    os.environ["UPSTREAM"] = "http://127.0.0.1:1"
    os.environ["ABUSEIPDB_KEY"] = "fake-test-key-12345"
    try:
        proxy_path = os.path.join(os.path.dirname(__file__), "..", "proxy.py")
        spec = importlib.util.spec_from_file_location("_test_proxy_abuseipdb2", proxy_path)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)

        g = {"_HOT_RELOAD_KNOBS": m._HOT_RELOAD_KNOBS, "_ENV_PROVIDED_KNOBS": set()}
        g.update({k: getattr(m, k) for k in m._HOT_RELOAD_KNOBS if hasattr(m, k)})
        g["ABUSEIPDB_KEY"] = "fake-test-key-12345"

        from db.sqlite import db_load_config
        db_load_config(g)

        assert g.get("ABUSEIPDB_ENABLED") is True, (
            "ABUSEIPDB_ENABLED should be applied when ABUSEIPDB_KEY is present."
        )
    finally:
        os.environ.pop("ABUSEIPDB_KEY", None)
        if _orig_db_path is not None:
            os.environ["DB_PATH"] = _orig_db_path
        else:
            os.environ.pop("DB_PATH", None)
        if _orig_upstream is not None:
            os.environ["UPSTREAM"] = _orig_upstream
        else:
            os.environ.pop("UPSTREAM", None)


# ── F8 — risk-decay across the wire ───────────────────────────────────────
@pytest.mark.asyncio
async def test_risk_increments_on_block(gw_client):
    """Blocking a request bumps the per-identity risk_score."""
    await gw_client.get(
        "/.env", headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux) Chrome/120 Safari/537.36",
            "Accept": "text/html",
        })
    # honeypot weight is 50; one hit lands the identity at risk≈50 (or banned).
    risks = [s.risk_score for s in proxy.ip_state.values()]
    assert any(r >= 40 for r in risks), f"no identity over 40: {risks}"


# ── F9 — TRUSTED_PROXIES integration check ────────────────────────────────
@pytest.mark.asyncio
async def test_xff_spoof_blocked_when_peer_untrusted(gw_client):
    """When TRUSTED_PROXIES excludes the test peer, XFF is ignored.

    Both proxy.TRUSTED_PROXIES_NETS and helpers.TRUSTED_PROXIES_NETS must be
    patched — helpers.py imports the variable at module load time, so patching
    only the proxy module namespace has no effect on _peer_is_trusted_proxy().
    """
    import ipaddress
    import helpers as _helpers_mod
    restrict = [ipaddress.ip_network("10.99.0.0/16")]
    # Patch both namespaces — hot-reload in production does the same via setattr loop
    proxy.TRUSTED_PROXIES_NETS = restrict
    _helpers_mod.TRUSTED_PROXIES_NETS = restrict
    proxy.TRUST_XFF = "first"
    _helpers_mod.TRUST_XFF = "first"
    try:
        # Clear ip_state so max() finds only this request's identity
        async with proxy.state_lock:
            proxy.ip_state.clear()
        await gw_client.get(
            "/echo", headers={
                "User-Agent": "Mozilla/5.0 Chrome/120",
                "Accept": "text/html",
                "X-Forwarded-For": "8.8.8.8",
            })
        # Find the most-recent identity by last_seen — its IP must NOT be 8.8.8.8
        latest = max(proxy.ip_state.values(),
                     key=lambda s: s.last_seen, default=None)
        assert latest is not None
        assert latest.last_ip != "8.8.8.8", \
            f"XFF spoof leaked through: identity recorded as {latest.last_ip}"
    finally:
        proxy.TRUSTED_PROXIES_NETS = []
        _helpers_mod.TRUSTED_PROXIES_NETS = []


# ── helper ────────────────────────────────────────────────────────────────
def _has_block_reason(proxy, reason):
    """True iff the GW recorded at least one event with this reason."""
    return proxy.metrics["by_reason"].get(reason, 0) > 0


# ── F10 — AI Labyrinth (1.6.9) functional tests ───────────────────────────

@pytest.mark.asyncio
async def test_labyrinth_links_injected_in_html_response(gw_client):
    """Proxied HTML responses get hidden tarpit links injected before </body>."""
    proxy.LABYRINTH_ENABLED = True
    proxy.LABYRINTH_LINKS_PER = 2
    resp = await gw_client.get(
        "/",
        headers={"User-Agent": "Mozilla/5.0 Chrome/120",
                 "Accept": "text/html",
                 "Accept-Language": "en-US"},
    )
    body = await resp.text()
    assert "/antibot-appsec-gateway/tarpit/" in body, \
        "Labyrinth entry links should be injected into HTML response"
    assert 'rel="nofollow' in body, \
        "Injected links must have rel=nofollow"
    assert "display:none" in body, \
        "Injected links must be hidden via CSS"


@pytest.mark.asyncio
async def test_tarpit_endpoint_accessible_without_admin_auth(gw_client):
    """The tarpit endpoint must be reachable without admin credentials — it is
    a public subpath that bots follow from injected hidden links."""
    proxy.LABYRINTH_ENABLED = True
    token = proxy._tarpit_token(0)
    resp = await gw_client.get(
        f"/antibot-appsec-gateway/tarpit/{token}",
        headers={"User-Agent": "Mozilla/5.0 Chrome/120",
                 "Accept": "text/html"},
    )
    # Should NOT get a 404 silent-decoy — the endpoint is public
    assert resp.status != 404, (
        "tarpit endpoint returned 404 — /tarpit/ must be in _ADMIN_PUBLIC_SUBPATHS"
    )
    # Should return 200 (slow-drip fake page) or at least not 403/404
    assert resp.status == 200, f"Expected 200, got {resp.status}"
    body = await resp.text()
    assert "<html" in body, "tarpit response should be HTML content"


@pytest.mark.asyncio
async def test_tarpit_endpoint_rejects_invalid_token(gw_client):
    """Invalid tarpit tokens (wrong HMAC) return 404, not a maze page."""
    proxy.LABYRINTH_ENABLED = True
    resp = await gw_client.get(
        "/antibot-appsec-gateway/tarpit/0.fakefake.0000000000000000",
        headers={"User-Agent": "Mozilla/5.0 Chrome/120",
                 "Accept": "text/html"},
    )
    assert resp.status == 404, f"Invalid token should 404, got {resp.status}"


@pytest.mark.asyncio
async def test_tarpit_endpoint_disabled_returns_404(gw_client):
    """When LABYRINTH_ENABLED=False the endpoint returns 404."""
    orig = proxy.LABYRINTH_ENABLED
    proxy.LABYRINTH_ENABLED = False
    try:
        token = proxy._tarpit_token(0)
        resp = await gw_client.get(
            f"/antibot-appsec-gateway/tarpit/{token}",
            headers={"User-Agent": "Mozilla/5.0 Chrome/120",
                     "Accept": "text/html"},
        )
        assert resp.status == 404, f"Disabled labyrinth should 404, got {resp.status}"
    finally:
        proxy.LABYRINTH_ENABLED = orig
