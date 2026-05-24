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

    app = proxy.make_app()
    # Ensure on_startup ran (sets up db_queue, prune_task, etc.)
    # aiohttp_client triggers app lifecycle hooks automatically.
    client = await aiohttp_client(app)
    # Clear in-memory state AFTER on_startup so db_load_state() doesn't
    # repopulate ip_state/timeline with stale rows from prior tests.
    proxy.ip_state.clear()
    proxy.events.clear()
    proxy.metrics["total_requests"] = 0
    proxy.metrics["allowed"] = 0
    proxy.metrics["blocked"] = 0
    proxy.metrics["by_reason"].clear()
    proxy.metrics["by_status"].clear()
    proxy.timeline.clear()
    # M-4: clear ip_bans table so persistent hostile bans from prior tests
    # don't short-circuit the ip_ban early-return in protect().
    import sqlite3 as _sq
    try:
        with _sq.connect(TEST_DB) as _c:
            _c.execute("DELETE FROM ip_bans")
    except Exception:
        pass
    return client


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


def _csrf_hdr(cookies=None):
    """Return X-CSRF-Token header dict for CSRF-protected endpoints."""
    import hashlib, hmac as _hmac
    cookie = cookies.get(proxy._SESSION_COOKIE, "") if cookies else ""
    if not cookie:
        return {}
    sid = cookie.split("|")[1]
    token = _hmac.new(proxy.SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
    return {"X-CSRF-Token": token}


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
    _ck = _admin_cookie()
    resp = await gw_client.post(
        "/antibot-appsec-gateway/secured/config",
        json={"RISK_BAN_THRESHOLD": 42, "ENUM_THRESHOLD": 250},
        headers=_csrf_hdr(_ck),
        cookies=_ck,
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
    _ck = _admin_cookie()
    resp = await gw_client.post(
        "/antibot-appsec-gateway/secured/config",
        json={"BOGUS_KNOB": 1},
        headers=_csrf_hdr(_ck),
        cookies=_ck,
    )
    body = await resp.json()
    assert "BOGUS_KNOB" in body["rejected"]


@pytest.mark.asyncio
async def test_config_validator_rejects_out_of_range(gw_client):
    """Out-of-range values must hit the validator."""
    _ck = _admin_cookie()
    resp = await gw_client.post(
        "/antibot-appsec-gateway/secured/config",
        json={"RISK_BAN_THRESHOLD": 0},     # below min
        headers=_csrf_hdr(_ck),
        cookies=_ck,
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
    """When TRUSTED_PROXIES excludes the test peer, XFF is ignored."""
    import ipaddress
    import core.proxy_handler as _cph_fix
    restrict = [ipaddress.ip_network("10.99.0.0/16")]
    # core.proxy_handler.get_ip is a namespace-aware wrapper defined in proxy.py.
    # Its __globals__ may point to an orphaned proxy module loaded at collection
    # time via importlib exec_module — not reachable via sys.modules or via
    # _ProxyModule.__setattr__ propagation.  Patch its __globals__ dict directly
    # so the wrapper sees the restricted TRUSTED_PROXIES_NETS / TRUST_XFF values.
    _gip_g = _cph_fix.get_ip.__globals__
    _saved_nets = _gip_g.get("TRUSTED_PROXIES_NETS", [])
    _saved_xff = _gip_g.get("TRUST_XFF", "first")
    _gip_g["TRUSTED_PROXIES_NETS"] = restrict
    _gip_g["TRUST_XFF"] = "first"
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
        _gip_g["TRUSTED_PROXIES_NETS"] = _saved_nets
        _gip_g["TRUST_XFF"] = _saved_xff


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


# ── F11 — BYPASS_MODE QA (1.7.8) ─────────────────────────────────────────────
# protect() reads BYPASS_MODE from core.proxy_handler globals, not from the
# importlib-loaded proxy module — patch there directly.

@pytest.mark.asyncio
async def test_bypass_mode_skips_ua_detection(gw_client):
    """When BYPASS_MODE=True, bot-UA must pass with no block reason recorded."""
    import core.proxy_handler as _cph
    orig = _cph.BYPASS_MODE
    _cph.BYPASS_MODE = True
    try:
        await gw_client.get("/", headers={"User-Agent": "curl/8.0.1"})
        assert not (_has_block_reason(proxy, "ua-too-short")
                    or _has_block_reason(proxy, "ua-blocked")), (
            f"BYPASS_MODE=True must suppress UA detection, "
            f"by_reason={dict(proxy.metrics['by_reason'])}"
        )
    finally:
        _cph.BYPASS_MODE = orig


@pytest.mark.asyncio
async def test_bypass_mode_false_blocks_bot_ua(gw_client):
    """Sanity check: with BYPASS_MODE=False the same bot UA is blocked."""
    import core.proxy_handler as _cph
    _cph.BYPASS_MODE = False
    await gw_client.get("/", headers={"User-Agent": "curl/8.0.1"})
    assert (
        _has_block_reason(proxy, "ua-too-short")
        or _has_block_reason(proxy, "ua-blocked")
    ), "BYPASS_MODE=False must still block bot UAs"


@pytest.mark.asyncio
async def test_bypass_mode_not_written_to_db(gw_client):
    """Setting BYPASS_MODE via the config endpoint must NOT persist it to config_kv."""
    import sqlite3

    _ck = _admin_cookie()
    resp = await gw_client.post(
        "/antibot-appsec-gateway/secured/config",
        json={"BYPASS_MODE": True},
        headers=_csrf_hdr(_ck),
        cookies=_ck,
    )
    assert resp.status == 200
    body = await resp.json()
    assert "BYPASS_MODE" in body.get("applied", {}), (
        "BYPASS_MODE must be accepted by the config endpoint (in _HOT_RELOAD_KNOBS)"
    )
    await asyncio.sleep(0.1)   # let db_writer drain
    conn = sqlite3.connect(proxy.DB_PATH)
    rows = dict(conn.execute("SELECT key, value FROM config_kv").fetchall())
    conn.close()
    assert "BYPASS_MODE" not in rows, (
        "BYPASS_MODE must NOT be written to config_kv — it is session-only "
        "(_NOT_PERSIST_KNOBS) and must reset to False on container restart"
    )


# ── F11b — BOT_DETECTION_ENABLED per-vhost toggle ────────────────────────────
# BOT_DETECTION_ENABLED=False skips all heuristic detectors but still enforces
# existing bans. Bans are applied earlier in protect() so the gate only bypasses
# the scoring pipeline.

@pytest.mark.asyncio
async def test_bot_detection_disabled_skips_ua_detection(gw_client):
    """BOT_DETECTION_ENABLED=False must suppress UA detection for that vhost."""
    import core.proxy_handler as _cph
    orig = _cph.BOT_DETECTION_ENABLED
    _cph.BOT_DETECTION_ENABLED = False
    try:
        proxy.ip_state.clear()
        proxy.metrics["by_reason"].clear()
        await gw_client.get("/", headers={"User-Agent": "curl/8.0.1"})
        assert not (_has_block_reason(proxy, "ua-too-short")
                    or _has_block_reason(proxy, "ua-blocked")), (
            "BOT_DETECTION_ENABLED=False must suppress UA detection; "
            f"by_reason={dict(proxy.metrics['by_reason'])}"
        )
    finally:
        _cph.BOT_DETECTION_ENABLED = orig


@pytest.mark.asyncio
async def test_bot_detection_enabled_blocks_bot_ua(gw_client):
    """Sanity: BOT_DETECTION_ENABLED=True (default) must still block bot UAs."""
    import core.proxy_handler as _cph
    _cph.BOT_DETECTION_ENABLED = True
    try:
        proxy.ip_state.clear()
        proxy.metrics["by_reason"].clear()
        await gw_client.get("/", headers={"User-Agent": "curl/8.0.1"})
        assert (
            _has_block_reason(proxy, "ua-too-short")
            or _has_block_reason(proxy, "ua-blocked")
        ), "BOT_DETECTION_ENABLED=True must still block bot UAs"
    finally:
        pass  # True is the default; no restore needed


# ── F12 — BYPASS_PATHS QA (1.7.8) ────────────────────────────────────────────
# protect() reads BYPASS_PATHS from core.proxy_handler globals — patch there.

@pytest.mark.asyncio
async def test_bypass_paths_skips_honeypot_detection(gw_client):
    """A path in BYPASS_PATHS must NOT trigger honeypot detection."""
    import core.proxy_handler as _cph
    orig_bp = _cph.BYPASS_PATHS
    _cph.BYPASS_PATHS = ["/.env"]
    try:
        await gw_client.get(
            "/.env",
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux) Chrome/120 Safari/537.36",
                "Accept": "text/html",
            },
        )
        assert not _has_block_reason(proxy, "honeypot-silent"), (
            "honeypot-silent must NOT fire when path is in BYPASS_PATHS; "
            f"by_reason={dict(proxy.metrics['by_reason'])}"
        )
    finally:
        _cph.BYPASS_PATHS = orig_bp


@pytest.mark.asyncio
async def test_bypass_paths_traffic_appears_in_timeline(gw_client):
    """Requests matching BYPASS_PATHS must appear in timeline (record() with empty reason)."""
    import core.proxy_handler as _cph
    orig_bp = _cph.BYPASS_PATHS
    _cph.BYPASS_PATHS = ["/health"]
    proxy.timeline.clear()
    try:
        await gw_client.get(
            "/health",
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux) Chrome/120 Safari/537.36",
                "Accept": "text/html",
            },
        )
        assert len(proxy.timeline) > 0, (
            "BYPASS_PATHS request must appear in proxy.timeline — "
            "record() must be called with empty reason so bypass traffic is "
            "visible in the main dashboard"
        )
    finally:
        _cph.BYPASS_PATHS = orig_bp


# ── 1.7.8 — Live Events filter QA (dynamic) ──────────────────────────────
# These tests verify that the category + path filters on the main dashboard
# Live Events panel correctly show/hide events when toggled.
# The JS filter logic (_renderEvents) is simulated in Python so the test
# runs without a browser.

_BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_BROWSER_HDR = {"User-Agent": _BROWSER_UA, "Accept": "text/html", "Accept-Language": "en-US,en;q=0.9"}
_ADMIN_NS = "/antibot-appsec-gateway"


def _js_event_filter(events, active_filters, path_q=""):
    """Python replica of the JS _renderEvents() filter logic (main.html).
    active_filters: set of pill names currently active
                    {'allowed','ban','reallyban','missed','authbots','gwmgmt'}
    path_q:         lower-cased path search term (empty = no path filter)
    """
    result = []
    for e in events:
        p = (e.get("path") or "").lower()
        if "gwmgmt" not in active_filters and p.startswith(_ADMIN_NS.lower()):
            continue
        if path_q and path_q not in p:
            continue
        result.append(e)
    return result


_ALL_FILTERS = frozenset({"allowed", "ban", "reallyban", "missed", "authbots", "gwmgmt"})
_NO_GWMGMT   = _ALL_FILTERS - {"gwmgmt"}


@pytest.mark.asyncio
async def test_events_different_upstream_paths_all_recorded(gw_client):
    """Requests to different upstream paths must each appear in proxy.events
    with their exact path so the Live Events panel can display them."""
    proxy.events.clear()
    paths = ["/", "/products", "/api/v1/items", "/about"]
    for p in paths:
        await gw_client.get(p, headers=_BROWSER_HDR)

    recorded = {(e.get("path") or "") for e in proxy.events}
    for p in paths:
        assert p in recorded, (
            f"Path '{p}' not found in proxy.events — "
            f"recorded paths: {recorded}"
        )


@pytest.mark.asyncio
async def test_events_blocked_and_allowed_both_recorded(gw_client):
    """Allowed (browser UA) and blocked (bot UA) requests must both appear
    in proxy.events so the Live Events panel shows both green and red rows."""
    proxy.events.clear()
    await gw_client.get("/page-ok",  headers=_BROWSER_HDR)
    await gw_client.get("/page-bot", headers={"User-Agent": "curl/8.0"})

    reasons = {(e.get("reason") or "OK") for e in proxy.events}
    passthrough = {"operator-passthrough", "authorized-robot", "bypass-path", "bypass-mode"}
    has_ok    = any(r in ("", "OK") for r in reasons)
    has_block = any(r not in ("", "OK") and r not in passthrough for r in reasons)
    assert has_ok,    f"No allowed event recorded — reasons={reasons}"
    assert has_block, f"No blocked event recorded — reasons={reasons}"


@pytest.mark.asyncio
async def test_events_admin_path_recorded_as_gwmgmt(gw_client):
    """An authenticated request to a non-polling admin path must be recorded in
    proxy.events with reason 'operator-passthrough'. High-frequency polling paths
    (/secured/metrics, /secured/health-score, /secured/status) are excluded from
    the events buffer to prevent them from displacing real traffic events."""
    proxy.events.clear()
    await gw_client.get(
        "/antibot-appsec-gateway/secured/live-feed",
        cookies=_admin_cookie(),
    )
    gw_events = [
        e for e in proxy.events
        if (e.get("path") or "").startswith(_ADMIN_NS)
    ]
    assert gw_events, (
        "Authenticated admin request must appear in proxy.events with "
        f"path starting '{_ADMIN_NS}'"
    )
    reasons = {e.get("reason") for e in gw_events}
    assert "operator-passthrough" in reasons, (
        f"GW Mgmt event must have reason='operator-passthrough', got: {reasons}"
    )


@pytest.mark.asyncio
async def test_events_gwmgmt_filter_off_hides_admin_paths(gw_client):
    """When the GW Mgmt pill is off, /antibot-appsec-gateway/* events must
    be hidden by _renderEvents(); upstream events must remain visible.
    Simulates the JS filter logic against live proxy.events data."""
    proxy.events.clear()
    # Upstream traffic (should survive gwmgmt-off filter)
    await gw_client.get("/products", headers=_BROWSER_HDR)
    await gw_client.get("/api/items", headers=_BROWSER_HDR)
    # GW Mgmt traffic (should be hidden when gwmgmt filter is off)
    # Use /secured/live-feed — /secured/metrics is a poll path excluded from events buffer
    await gw_client.get(
        "/antibot-appsec-gateway/secured/live-feed",
        cookies=_admin_cookie(),
    )

    all_events = list(proxy.events)
    assert all_events, "proxy.events must not be empty after requests"

    shown_all    = _js_event_filter(all_events, _ALL_FILTERS)
    shown_no_gw  = _js_event_filter(all_events, _NO_GWMGMT)

    gw_in_all    = [e for e in shown_all   if (e.get("path") or "").startswith(_ADMIN_NS)]
    gw_in_no_gw  = [e for e in shown_no_gw if (e.get("path") or "").startswith(_ADMIN_NS)]
    up_in_no_gw  = [e for e in shown_no_gw if not (e.get("path") or "").startswith(_ADMIN_NS)]

    assert gw_in_all, (
        "With GW Mgmt ON, /antibot-appsec-gateway/* events must be visible"
    )
    assert not gw_in_no_gw, (
        "With GW Mgmt OFF, /antibot-appsec-gateway/* events must be hidden — "
        f"still visible: {[e.get('path') for e in gw_in_no_gw]}"
    )
    assert up_in_no_gw, (
        "With GW Mgmt OFF, upstream events (/products, /api/items) must still be visible"
    )


@pytest.mark.asyncio
async def test_events_path_filter_narrows_live_events(gw_client):
    """The path search filter must include only events whose path contains
    the search term (case-insensitive), hiding all non-matching events."""
    proxy.events.clear()
    await gw_client.get("/products/123", headers=_BROWSER_HDR)
    await gw_client.get("/api/items",    headers=_BROWSER_HDR)
    await gw_client.get("/login-page",   headers=_BROWSER_HDR)

    all_events = list(proxy.events)
    assert len(all_events) >= 3, "Need at least 3 events for path filter test"

    # Filter by '/products' — only /products/123 must survive
    products = _js_event_filter(all_events, _ALL_FILTERS, path_q="/products")
    assert all("/products" in (e.get("path") or "") for e in products), (
        "path filter '/products' must only include events with '/products' in path"
    )
    assert products, "path filter '/products' must match at least one event"

    # Filter by '/api' — only /api/items must survive; /products must not appear
    api = _js_event_filter(all_events, _ALL_FILTERS, path_q="/api")
    assert all("/api" in (e.get("path") or "") for e in api)
    assert all("/products" not in (e.get("path") or "") for e in api), (
        "path filter '/api' must not include /products events"
    )

    # Filter by '/zzz-nonexistent' — nothing must survive
    none_ = _js_event_filter(all_events, _ALL_FILTERS, path_q="/zzz-nonexistent")
    assert not none_, (
        "path filter with no match must return empty list — "
        f"got: {[e.get('path') for e in none_]}"
    )


# ── F11c — BOT_DETECTION_ENABLED dynamic QA ──────────────────────────────
# Additional dynamic tests exercising ban-still-enforced, record action
# correctness, and cross-detector suppression.

@pytest.mark.asyncio
async def test_bot_detection_disabled_ban_still_enforced(gw_client):
    """With BOT_DETECTION_ENABLED=False, pre-existing identity bans must still block traffic."""
    import core.proxy_handler as _cph
    from scoring import ip_state, now, state_lock
    orig = _cph.BOT_DETECTION_ENABLED
    try:
        proxy.ip_state.clear()
        proxy.metrics["by_reason"].clear()
        proxy.events.clear()
        # Step 1: fire one request (detection on) to register the identity/track_key
        _cph.BOT_DETECTION_ENABLED = True
        await gw_client.get(
            "/",
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
                "Accept": "text/html",
            },
        )
        await asyncio.sleep(0.05)
        # Step 2: extract the track_key from the recorded event
        assert proxy.events, "No events recorded after initial request"
        track_key = proxy.events[-1].get("track_key", "")
        assert track_key, "track_key must be non-empty in the event record"
        # Step 3: inject a live ban for that identity
        async with state_lock:
            ip_state[track_key].banned_until = now() + 3600.0
        # Step 4: disable detection and verify the ban is still enforced
        _cph.BOT_DETECTION_ENABLED = False
        proxy.metrics["by_reason"].clear()
        await gw_client.get(
            "/",
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
                "Accept": "text/html",
            },
        )
        assert _has_block_reason(proxy, "banned-silent"), (
            "BOT_DETECTION_ENABLED=False must NOT bypass an active identity ban — "
            "ban checks run before the detection gate. "
            f"by_reason={dict(proxy.metrics['by_reason'])}"
        )
    finally:
        _cph.BOT_DETECTION_ENABLED = orig
        proxy.ip_state.clear()


@pytest.mark.asyncio
async def test_bot_detection_disabled_records_operator_passthrough(gw_client):
    """With BOT_DETECTION_ENABLED=False, allowed traffic must be recorded as 'operator-passthrough'."""
    import core.proxy_handler as _cph
    orig = _cph.BOT_DETECTION_ENABLED
    _cph.BOT_DETECTION_ENABLED = False
    try:
        proxy.ip_state.clear()
        proxy.events.clear()
        await gw_client.get(
            "/",
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
                "Accept": "text/html",
            },
        )
        await asyncio.sleep(0.05)   # let record() drain
        reasons = {(e.get("reason") or "") for e in proxy.events}
        assert "operator-passthrough" in reasons, (
            "BOT_DETECTION_ENABLED=False: allowed request must be recorded with "
            "reason='operator-passthrough' so it appears correctly in dashboards. "
            f"Got reasons: {reasons}"
        )
    finally:
        _cph.BOT_DETECTION_ENABLED = orig


@pytest.mark.asyncio
async def test_bot_detection_disabled_suppresses_honeypot(gw_client):
    """With BOT_DETECTION_ENABLED=False, honeypot-path hit must NOT trigger honeypot-silent."""
    import core.proxy_handler as _cph
    orig = _cph.BOT_DETECTION_ENABLED
    _cph.BOT_DETECTION_ENABLED = False
    try:
        proxy.ip_state.clear()
        proxy.metrics["by_reason"].clear()
        # /.env is in the default HONEYPOT_PATHS
        await gw_client.get(
            "/.env",
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
                "Accept": "text/html",
            },
        )
        assert not _has_block_reason(proxy, "honeypot-silent"), (
            "BOT_DETECTION_ENABLED=False must suppress honeypot detection — "
            "no 'honeypot-silent' must be recorded when the detection pipeline is off. "
            f"by_reason={dict(proxy.metrics['by_reason'])}"
        )
    finally:
        _cph.BOT_DETECTION_ENABLED = orig


@pytest.mark.asyncio
async def test_bot_detection_disabled_suppresses_suspicious_path(gw_client):
    """With BOT_DETECTION_ENABLED=False, suspicious-path recon must NOT be flagged."""
    import core.proxy_handler as _cph
    orig = _cph.BOT_DETECTION_ENABLED
    _cph.BOT_DETECTION_ENABLED = False
    try:
        proxy.ip_state.clear()
        proxy.metrics["by_reason"].clear()
        # /flag.txt matches the suspicious-path pattern
        await gw_client.get(
            "/flag.txt",
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
                "Accept": "text/html",
            },
        )
        assert not _has_block_reason(proxy, "suspicious-path"), (
            "BOT_DETECTION_ENABLED=False must suppress suspicious-path detection — "
            "no 'suspicious-path' must be recorded when the detection pipeline is off. "
            f"by_reason={dict(proxy.metrics['by_reason'])}"
        )
    finally:
        _cph.BOT_DETECTION_ENABLED = orig
