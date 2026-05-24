"""
tests/test_oidc.py — Static + dynamic QA tests for admin/oidc.py (1.8.5 SSO).

Static (S01-S24): source-code assertions — config defaults, guard clauses,
    state-store TTL, redirect-URI build, username sanitization, HTML placeholders,
    proxy route registration, error-path coverage.

Dynamic (D01-D32): in-process tests calling endpoint functions directly or via
    a full aiohttp TestServer gateway, with a fake Keycloak server and/or
    module-level patching.
"""
from __future__ import annotations

import asyncio
import inspect
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# ── source helpers ─────────────────────────────────────────────────────────────

_SRC_OIDC  = (Path(__file__).parent.parent / "admin" / "oidc.py").read_text()
_SRC_LOGIN = (Path(__file__).parent.parent / "dashboards" / "login.html").read_text()
_SRC_PROXY = (Path(__file__).parent.parent / "proxy.py").read_text()
_SRC_USERS = (Path(__file__).parent.parent / "admin" / "users.py").read_text()


# ─────────────────────────────────────────────────────────────────────────────
# STATIC TESTS  (no I/O, no imports that side-effect at collection time)
# ─────────────────────────────────────────────────────────────────────────────

class TestS_OIDCStatic:

    def test_s01_oidc_enabled_requires_all_three_vars(self):
        assert "OIDC_ENABLED" in _SRC_OIDC
        assert "OIDC_ISSUER" in _SRC_OIDC
        assert "OIDC_CLIENT_ID" in _SRC_OIDC
        assert "OIDC_CLIENT_SECRET" in _SRC_OIDC
        # All three must be truthy for OIDC_ENABLED
        m = re.search(r"OIDC_ENABLED\s*=\s*bool\((.+?)\)", _SRC_OIDC)
        assert m, "OIDC_ENABLED must be bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET)"
        expr = m.group(1)
        assert "OIDC_ISSUER" in expr
        assert "OIDC_CLIENT_ID" in expr
        assert "OIDC_CLIENT_SECRET" in expr

    def test_s02_state_ttl_is_300_seconds(self):
        m = re.search(r"_STATE_TTL_S\s*=\s*(\d+)", _SRC_OIDC)
        assert m, "_STATE_TTL_S constant not found"
        assert int(m.group(1)) == 300, "State TTL must be 300 s (5 min)"

    def test_s03_oidc_login_returns_404_when_disabled(self):
        assert "status=404" in _SRC_OIDC or "status = 404" in _SRC_OIDC
        # Guard must check OIDC_ENABLED before doing anything
        src_login = _SRC_OIDC[_SRC_OIDC.find("async def oidc_login_endpoint"):]
        first_if   = src_login[:src_login.find("\n    if") + 100]
        assert "OIDC_ENABLED" in first_if, \
            "oidc_login_endpoint must guard on OIDC_ENABLED as first check"

    def test_s04_callback_returns_404_when_disabled(self):
        src_cb = _SRC_OIDC[_SRC_OIDC.find("async def oidc_callback_endpoint"):]
        first_if = src_cb[:src_cb.find("\n    if") + 100]
        assert "OIDC_ENABLED" in first_if, \
            "oidc_callback_endpoint must guard on OIDC_ENABLED as first check"

    def test_s05_state_is_popped_not_peeked(self):
        """State must be consumed (pop) on callback to prevent replay."""
        cb_src = _SRC_OIDC[_SRC_OIDC.find("async def oidc_callback_endpoint"):]
        assert "_OIDC_STATE.pop(" in cb_src, \
            "Callback must _OIDC_STATE.pop() the state — peek() allows replay"

    def test_s06_redirect_uri_built_from_request_host(self):
        src = _SRC_OIDC
        assert "request.host" in src, \
            "redirect_uri must use request.host so the gateway is host-agnostic"

    def test_s07_session_secure_controls_scheme(self):
        assert "SESSION_SECURE" in _SRC_OIDC, \
            "redirect_uri scheme must respect SESSION_SECURE env var"

    def test_s08_oidc_error_param_triggers_redirect_not_500(self):
        cb_src = _SRC_OIDC[_SRC_OIDC.find("async def oidc_callback_endpoint"):]
        assert "_redirect_error(" in cb_src, \
            "Callback must use _redirect_error() for error paths (not raise)"
        assert 'request.query.get("error")' in cb_src, \
            "Callback must handle ?error= from the IdP"

    def test_s09_oidc_provision_uses_insert_or_ignore(self):
        assert "INSERT OR IGNORE" in _SRC_OIDC, \
            "User provisioning must be idempotent (INSERT OR IGNORE)"

    def test_s10_direct_sqlite_write_for_provision(self):
        """Must use a direct sqlite3.connect() for provisioning — the async
        db_queue is too slow; _request_role() reads the table on every request."""
        assert "sqlite3.connect(DB_PATH)" in _SRC_OIDC, \
            "Provisioning must use a direct synchronous SQLite write, not db_queue"

    def test_s11_session_cookie_set_with_httponly_and_samesite(self):
        """Reuses _session_create + set_cookie exactly like password login."""
        src = _SRC_OIDC
        assert "_session_create(" in src
        assert "httponly=True" in src
        assert 'samesite="Lax"' in src
        assert "secure=SESSION_SECURE" in src

    def test_s12_default_role_falls_back_to_viewer(self):
        src = _SRC_OIDC
        assert '"viewer"' in src, "viewer must be the fallback OIDC_DEFAULT_ROLE"
        assert "_VALID_ROLES" in src, "Role must be validated against _VALID_ROLES"

    def test_s13_safe_username_rejects_invalid(self):
        src = _SRC_OIDC
        assert "_USERNAME_RE" in src, "_USERNAME_RE must guard username mapping"
        # Function uses conditional expression — verify the None branch exists
        fn_src = src[src.find("def _safe_username"):]
        fn_src = fn_src[:fn_src.find("\ndef ", 10)]
        assert "None" in fn_src, "_safe_username must be able to return None for invalid input"

    def test_s14_oidc_button_html_empty_when_disabled(self):
        assert "def oidc_button_html" in _SRC_OIDC
        fn_src = _SRC_OIDC[_SRC_OIDC.find("def oidc_button_html"):]
        assert 'return ""' in fn_src, \
            "oidc_button_html must return empty string when OIDC disabled"


class TestS_OIDCStaticExtra:

    def test_s15_callback_calls_purge_expired_states(self):
        cb_src = _SRC_OIDC[_SRC_OIDC.find("async def oidc_callback_endpoint"):]
        assert "_purge_expired_states()" in cb_src, \
            "oidc_callback_endpoint must call _purge_expired_states() to evict stale tokens"

    def test_s16_timeout_error_caught_in_callback(self):
        cb_src = _SRC_OIDC[_SRC_OIDC.find("async def oidc_callback_endpoint"):]
        assert "asyncio.TimeoutError" in cb_src, \
            "Callback must catch asyncio.TimeoutError from Keycloak HTTP calls"

    def test_s17_aiohttp_client_error_caught_in_callback(self):
        cb_src = _SRC_OIDC[_SRC_OIDC.find("async def oidc_callback_endpoint"):]
        assert "aiohttp.ClientError" in cb_src, \
            "Callback must catch aiohttp.ClientError from Keycloak HTTP calls"

    def test_s18_at_least_five_redirect_error_paths(self):
        cb_src = _SRC_OIDC[_SRC_OIDC.find("async def oidc_callback_endpoint"):]
        count = cb_src.count("return _redirect_error(")
        assert count >= 5, \
            f"oidc_callback_endpoint must have ≥5 redirect-on-error paths, found {count}"

    def test_s19_oidc_default_role_env_default_is_viewer(self):
        m = re.search(r'OIDC_DEFAULT_ROLE\s*=\s*os\.environ\.get\([^,]+,\s*"([^"]+)"', _SRC_OIDC)
        assert m, "OIDC_DEFAULT_ROLE must be read from os.environ.get()"
        assert m.group(1) == "viewer", "OIDC_DEFAULT_ROLE env default must be 'viewer'"

    def test_s20_redirect_error_goes_to_login_with_oidc_error_param(self):
        fn_src = _SRC_OIDC[_SRC_OIDC.find("def _redirect_error"):]
        fn_src = fn_src[:fn_src.find("\n\n", 10)]
        assert "/login" in fn_src, "_redirect_error must redirect to the /login page"
        assert "oidc_error=" in fn_src, "_redirect_error must include oidc_error= parameter"

    def test_s21_login_html_has_oidc_error_placeholder(self):
        assert "__OIDC_ERROR__" in _SRC_LOGIN, \
            "dashboards/login.html must contain __OIDC_ERROR__ placeholder"

    def test_s22_login_html_has_sso_css_classes(self):
        assert ".sso-btn" in _SRC_LOGIN, "login.html must define .sso-btn CSS class"
        assert ".sso-divider" in _SRC_LOGIN, "login.html must define .sso-divider CSS class"

    def test_s23_proxy_registers_both_oidc_routes(self):
        assert "oidc_login_endpoint" in _SRC_PROXY, \
            "proxy.py must import and register oidc_login_endpoint"
        assert "oidc_callback_endpoint" in _SRC_PROXY, \
            "proxy.py must import and register oidc_callback_endpoint"
        assert "/auth/oidc/login" in _SRC_PROXY, \
            "proxy.py must register the /auth/oidc/login route"
        assert "/auth/oidc/callback" in _SRC_PROXY, \
            "proxy.py must register the /auth/oidc/callback route"

    def test_s24_login_page_endpoint_injects_oidc_button(self):
        assert "oidc_button_html" in _SRC_USERS, \
            "admin/users.py login_page_endpoint must call oidc_button_html()"
        assert "__OIDC_BUTTON__" in _SRC_USERS, \
            "admin/users.py must replace __OIDC_BUTTON__ placeholder"
        assert "__OIDC_ERROR__" in _SRC_USERS, \
            "admin/users.py must replace __OIDC_ERROR__ placeholder"


# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC TESTS
# ─────────────────────────────────────────────────────────────────────────────

import admin.oidc as _oidc_mod


@asynccontextmanager
async def _patched_oidc(**overrides):
    """Patch admin.oidc module-level globals, clear state store, restore."""
    orig = {k: getattr(_oidc_mod, k) for k in overrides}
    for k, v in overrides.items():
        setattr(_oidc_mod, k, v)
    _oidc_mod._OIDC_STATE.clear()
    try:
        yield
    finally:
        for k, v in orig.items():
            setattr(_oidc_mod, k, v)
        _oidc_mod._OIDC_STATE.clear()


def _fake_request(query: dict | None = None, host: str = "gw.example.com",
                  scheme: str = "https") -> MagicMock:
    req = MagicMock()
    req.query = query or {}
    req.host   = host
    req.scheme = scheme
    req.headers = {}
    return req


@pytest.mark.asyncio
async def test_d01_login_returns_404_when_disabled():
    async with _patched_oidc(OIDC_ENABLED=False):
        req = _fake_request()
        resp = await _oidc_mod.oidc_login_endpoint(req)
        assert resp.status == 404


@pytest.mark.asyncio
async def test_d02_callback_returns_404_when_disabled():
    async with _patched_oidc(OIDC_ENABLED=False):
        req = _fake_request(query={"code": "abc", "state": "xyz"})
        resp = await _oidc_mod.oidc_callback_endpoint(req)
        assert resp.status == 404


@pytest.mark.asyncio
async def test_d03_login_stores_state_and_redirects_to_keycloak():
    async with _patched_oidc(
            OIDC_ENABLED=True,
            OIDC_ISSUER="https://kc.example.com/realms/test",
            OIDC_CLIENT_ID="gw-client",
            OIDC_CLIENT_SECRET="secret",
            OIDC_SCOPES="openid profile email"):
        req = _fake_request()
        with patch.object(_oidc_mod, "SESSION_SECURE", True):
            resp = await _oidc_mod.oidc_login_endpoint(req)
        # Must redirect
        assert resp.status in (301, 302, 303, 307, 308)
        loc = resp.headers.get("Location", "")
        assert "kc.example.com" in loc
        assert "response_type=code" in loc
        assert "client_id=gw-client" in loc
        # State must be stored
        assert len(_oidc_mod._OIDC_STATE) == 1
        state_val = list(_oidc_mod._OIDC_STATE.values())[0]
        assert "next_url" in state_val
        assert state_val["expires_ts"] > time.time()


@pytest.mark.asyncio
async def test_d04_callback_rejects_missing_code():
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="x", OIDC_CLIENT_SECRET="y"):
        req = _fake_request(query={"state": "somestate"})
        resp = await _oidc_mod.oidc_callback_endpoint(req)
        assert resp.status in (301, 302), "Missing code must redirect to login error"
        assert "oidc_error" in resp.headers.get("Location", "")


@pytest.mark.asyncio
async def test_d05_callback_rejects_unknown_state():
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="x", OIDC_CLIENT_SECRET="y"):
        req = _fake_request(query={"code": "abc123", "state": "no-such-state"})
        resp = await _oidc_mod.oidc_callback_endpoint(req)
        assert resp.status in (301, 302)
        assert "oidc_error" in resp.headers.get("Location", "")


@pytest.mark.asyncio
async def test_d06_callback_rejects_expired_state():
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="x", OIDC_CLIENT_SECRET="y"):
        state_tok = secrets.token_urlsafe(24)
        _oidc_mod._OIDC_STATE[state_tok] = {
            "next_url": "/antibot-appsec-gateway/secured/control-center",
            "expires_ts": time.time() - 1,   # already expired
        }
        req = _fake_request(query={"code": "abc123", "state": state_tok})
        resp = await _oidc_mod.oidc_callback_endpoint(req)
        assert resp.status in (301, 302)
        assert "oidc_error" in resp.headers.get("Location", "")
        # State must have been consumed (popped)
        assert state_tok not in _oidc_mod._OIDC_STATE


@pytest.mark.asyncio
async def test_d07_callback_handles_idp_error_param():
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="x", OIDC_CLIENT_SECRET="y"):
        req = _fake_request(query={"error": "access_denied",
                                   "error_description": "User cancelled"})
        resp = await _oidc_mod.oidc_callback_endpoint(req)
        assert resp.status in (301, 302)
        loc = resp.headers.get("Location", "")
        assert "oidc_error" in loc
        assert "access_denied" in loc


@pytest.mark.asyncio
async def test_d08_safe_username_normalization():
    mod = _oidc_mod
    assert mod._safe_username("alice")               == "alice"
    assert mod._safe_username("Alice.Smith")         == "alice.smith"
    assert mod._safe_username("user@example.com")    == "user.example.com"
    assert mod._safe_username("João")                == "jo.o"
    assert mod._safe_username("")                    is None
    assert mod._safe_username("a" * 65)              is None   # too long
    assert mod._safe_username("a")                   is None   # too short (min 2)


@pytest.mark.asyncio
async def test_d09_purge_expired_states():
    async with _patched_oidc(OIDC_ENABLED=False):
        now = time.time()
        _oidc_mod._OIDC_STATE["live"]    = {"next_url": "/", "expires_ts": now + 300}
        _oidc_mod._OIDC_STATE["expired"] = {"next_url": "/", "expires_ts": now - 1}
        _oidc_mod._purge_expired_states()
        assert "live"    in _oidc_mod._OIDC_STATE
        assert "expired" not in _oidc_mod._OIDC_STATE


@pytest.mark.asyncio
async def test_d10_oidc_button_html_empty_when_disabled():
    async with _patched_oidc(OIDC_ENABLED=False):
        assert _oidc_mod.oidc_button_html() == ""


@pytest.mark.asyncio
async def test_d11_oidc_button_html_present_when_enabled():
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="x", OIDC_CLIENT_SECRET="y"):
        html = _oidc_mod.oidc_button_html()
        assert html != ""
        assert "Keycloak" in html
        assert "auth/oidc/login" in html


# ── Integration: login page injects __OIDC_BUTTON__ placeholder ───────────────

@pytest.mark.asyncio
async def test_d12_login_page_placeholder_rendered(proxy_module):
    """Login page must replace __OIDC_BUTTON__ — placeholder must not appear
    in the served HTML (either empty string or actual SSO button)."""
    from aiohttp.test_utils import TestClient, TestServer

    async def _echo(req):
        return web.json_response({"ok": True})

    upstream_app = web.Application()
    upstream_app.router.add_route("*", "/{tail:.*}", _echo)
    runner = web.AppRunner(upstream_app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    proxy_module.UPSTREAM = f"http://127.0.0.1:{port}"
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()

    resp = await client.get("/antibot-appsec-gateway/login")
    assert resp.status == 200
    text = await resp.text()
    assert "__OIDC_BUTTON__" not in text, \
        "login.html template placeholder __OIDC_BUTTON__ was not replaced"
    assert "__OIDC_ERROR__"  not in text, \
        "login.html template placeholder __OIDC_ERROR__ was not replaced"

    await client.close()
    await runner.cleanup()


# ── _ADMIN_LOGIN_SUBPATHS includes OIDC paths ─────────────────────────────────

def test_d13_oidc_paths_in_admin_login_subpaths(proxy_module):
    subpaths = proxy_module._ADMIN_LOGIN_SUBPATHS
    assert "/auth/oidc/login"    in subpaths, \
        "/auth/oidc/login must be in _ADMIN_LOGIN_SUBPATHS (public, no session cookie)"
    assert "/auth/oidc/callback" in subpaths, \
        "/auth/oidc/callback must be in _ADMIN_LOGIN_SUBPATHS"


# ── config.py exports OIDC vars ───────────────────────────────────────────────

def test_d14_config_exports_oidc_vars():
    import config
    for attr in ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET",
                 "OIDC_DEFAULT_ROLE", "OIDC_SCOPES", "OIDC_ENABLED"):
        assert hasattr(config, attr), f"config.py missing {attr}"


# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL HELPERS  (D15-D32)
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def _fake_keycloak(token_status: int = 200, token_resp: dict | None = None,
                          userinfo_status: int = 200, userinfo_resp: dict | None = None):
    """Spin up a minimal Keycloak-shaped HTTP server for a single test."""
    _tok  = token_resp    or {"access_token": "tok123", "token_type": "Bearer"}
    _user = userinfo_resp or {"sub": "sub123", "preferred_username": "alice",
                               "email": "alice@example.com"}

    async def _token(req: web.Request) -> web.Response:
        return web.json_response(_tok, status=token_status)

    async def _userinfo(req: web.Request) -> web.Response:
        return web.json_response(_user, status=userinfo_status)

    app = web.Application()
    app.router.add_post("/realms/test/protocol/openid-connect/token",   _token)
    app.router.add_get( "/realms/test/protocol/openid-connect/userinfo", _userinfo)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}/realms/test"
    finally:
        await runner.cleanup()


def _valid_state(next_url: str = "/antibot-appsec-gateway/secured/control-center") -> str:
    """Insert a valid state token into _OIDC_STATE and return the token string."""
    tok = secrets.token_urlsafe(24)
    _oidc_mod._OIDC_STATE[tok] = {"next_url": next_url, "expires_ts": time.time() + 300}
    return tok


# ── D15 — Happy path: existing active user ────────────────────────────────────

@pytest.mark.asyncio
async def test_d15_happy_path_existing_user():
    """Existing active user: full KC exchange → redirect + agw_session cookie."""
    async with _fake_keycloak() as issuer:
        async with _patched_oidc(OIDC_ENABLED=True, OIDC_ISSUER=issuer,
                                  OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
            state_tok = _valid_state()
            req = _fake_request(query={"code": "authcode", "state": state_tok})

            with patch("admin.users._user_load",
                       return_value={"username": "alice", "role": "viewer",
                                     "status": "active"}), \
                 patch("admin.users._session_create", return_value="fake-session-tok"), \
                 patch("admin.users._ACTIVE_SESSIONS", {}), \
                 patch("admin.users._SESSION_COOKIE", "agw_session"), \
                 patch("admin.users._SESSION_TTL", 3600):
                resp = await _oidc_mod.oidc_callback_endpoint(req)

    assert resp.status in (301, 302)
    # Cookies are stored in resp.cookies (serialized to Set-Cookie headers only
    # during response prepare); inspect the Morsel directly.
    assert "agw_session" in resp.cookies, "agw_session cookie must be set"
    assert resp.cookies["agw_session"].value == "fake-session-tok"


# ── D16 — Happy path: new user auto-provisioned ───────────────────────────────

@pytest.mark.asyncio
async def test_d16_new_user_auto_provisioned():
    """Unknown user: INSERT OR IGNORE executed, then session issued."""
    async with _fake_keycloak() as issuer:
        async with _patched_oidc(OIDC_ENABLED=True, OIDC_ISSUER=issuer,
                                  OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
            state_tok = _valid_state()
            req = _fake_request(query={"code": "authcode", "state": state_tok})

            user_row = {"username": "alice", "role": "viewer", "status": "active"}
            mock_conn = MagicMock()

            with patch("admin.oidc.sqlite3.connect", return_value=mock_conn), \
                 patch("admin.users._user_load", side_effect=[None, user_row]), \
                 patch("admin.users._session_create", return_value="tok-new"), \
                 patch("admin.users._ACTIVE_SESSIONS", {}), \
                 patch("admin.users._SESSION_COOKIE", "agw_session"), \
                 patch("admin.users._SESSION_TTL", 3600):
                resp = await _oidc_mod.oidc_callback_endpoint(req)

    assert resp.status in (301, 302)
    assert "agw_session" in resp.cookies, "agw_session cookie must be set for new user"
    mock_conn.execute.assert_called_once()
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


# ── D17 — Disabled user → redirect error, no cookie ──────────────────────────

@pytest.mark.asyncio
async def test_d17_disabled_user_redirect_error_no_cookie():
    """Disabled account: redirect to login error, no agw_session cookie set."""
    async with _fake_keycloak() as issuer:
        async with _patched_oidc(OIDC_ENABLED=True, OIDC_ISSUER=issuer,
                                  OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
            state_tok = _valid_state()
            req = _fake_request(query={"code": "authcode", "state": state_tok})

            with patch("admin.users._user_load",
                       return_value={"username": "alice", "status": "disabled"}), \
                 patch("admin.users._SESSION_COOKIE", "agw_session"):
                resp = await _oidc_mod.oidc_callback_endpoint(req)

    assert resp.status in (301, 302)
    assert "oidc_error" in resp.headers.get("Location", "")
    assert "agw_session" not in resp.cookies, "No session cookie must be issued for disabled users"


# ── D18 — asyncio.TimeoutError during token exchange → redirect, not 500 ─────

@pytest.mark.asyncio
async def test_d18_network_timeout_gives_redirect_error():
    """asyncio.TimeoutError during HTTP to Keycloak → redirect error, not 500."""
    import aiohttp as _aiohttp

    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="http://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
        state_tok = _valid_state()
        req = _fake_request(query={"code": "abc", "state": state_tok})

        async def _raise(*a, **kw):
            raise asyncio.TimeoutError()

        mock_post_ctx = MagicMock()
        mock_post_ctx.__aenter__ = _raise
        mock_post_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_http = MagicMock()
        mock_http.post = MagicMock(return_value=mock_post_ctx)

        mock_sess_ctx = MagicMock()
        mock_sess_ctx.__aenter__ = AsyncMock(return_value=mock_http)
        mock_sess_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.object(_aiohttp, "ClientSession", return_value=mock_sess_ctx):
            resp = await _oidc_mod.oidc_callback_endpoint(req)

    assert resp.status in (301, 302)
    assert "oidc_error" in resp.headers.get("Location", "")


# ── D19 — Token endpoint 401 → redirect error ────────────────────────────────

@pytest.mark.asyncio
async def test_d19_token_endpoint_error_gives_redirect():
    """Token endpoint returns non-200 → redirect error (bad client config)."""
    async with _fake_keycloak(token_status=401,
                               token_resp={"error": "invalid_client"}) as issuer:
        async with _patched_oidc(OIDC_ENABLED=True, OIDC_ISSUER=issuer,
                                  OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
            state_tok = _valid_state()
            req = _fake_request(query={"code": "badcode", "state": state_tok})
            resp = await _oidc_mod.oidc_callback_endpoint(req)

    assert resp.status in (301, 302)
    assert "oidc_error" in resp.headers.get("Location", "")


# ── D20 — Userinfo 403 → redirect error ──────────────────────────────────────

@pytest.mark.asyncio
async def test_d20_userinfo_error_gives_redirect():
    """Userinfo returns non-200 → redirect error (bad scopes or token)."""
    async with _fake_keycloak(userinfo_status=403) as issuer:
        async with _patched_oidc(OIDC_ENABLED=True, OIDC_ISSUER=issuer,
                                  OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
            state_tok = _valid_state()
            req = _fake_request(query={"code": "authcode", "state": state_tok})
            resp = await _oidc_mod.oidc_callback_endpoint(req)

    assert resp.status in (301, 302)
    assert "oidc_error" in resp.headers.get("Location", "")


# ── D21 — Unmappable username → redirect error ────────────────────────────────

@pytest.mark.asyncio
async def test_d21_unmappable_username_redirect_error():
    """IdP preferred_username that cannot be mapped → redirect error."""
    async with _fake_keycloak(
            userinfo_resp={"sub": "sub123", "preferred_username": "!@#$%",
                           "email": "!@#$%"}) as issuer:
        async with _patched_oidc(OIDC_ENABLED=True, OIDC_ISSUER=issuer,
                                  OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
            state_tok = _valid_state()
            req = _fake_request(query={"code": "code", "state": state_tok})
            resp = await _oidc_mod.oidc_callback_endpoint(req)

    assert resp.status in (301, 302)
    assert "oidc_error" in resp.headers.get("Location", "")


# ── D22 — State consumed before HTTP (replay protection) ─────────────────────

@pytest.mark.asyncio
async def test_d22_state_consumed_before_http_call():
    """State is popped before any HTTP leg — replay impossible even on error."""
    async with _fake_keycloak() as issuer:
        async with _patched_oidc(OIDC_ENABLED=True, OIDC_ISSUER=issuer,
                                  OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
            state_tok = _valid_state()
            req = _fake_request(query={"code": "code", "state": state_tok})

            with patch("admin.users._user_load",
                       return_value={"username": "alice", "status": "disabled"}), \
                 patch("admin.users._SESSION_COOKIE", "agw_session"):
                resp = await _oidc_mod.oidc_callback_endpoint(req)

            assert state_tok not in _oidc_mod._OIDC_STATE, \
                "State token must be consumed even when login fails after HTTP exchange"

    assert resp.status in (301, 302)
    assert "oidc_error" in resp.headers.get("Location", "")


# ── D23 — Multiple concurrent states coexist ─────────────────────────────────

@pytest.mark.asyncio
async def test_d23_multiple_states_coexist():
    """Two concurrent /login initiations store independent state tokens."""
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
        target_a = "/antibot-appsec-gateway/secured/control-center"
        target_b = "/antibot-appsec-gateway/secured/live-feed"
        await _oidc_mod.oidc_login_endpoint(_fake_request(query={"next": target_a}))
        await _oidc_mod.oidc_login_endpoint(_fake_request(query={"next": target_b}))

        assert len(_oidc_mod._OIDC_STATE) == 2
        next_urls = {v["next_url"] for v in _oidc_mod._OIDC_STATE.values()}
        assert target_a in next_urls
        assert target_b in next_urls


# ── D24 — next_url in state used as post-login destination ───────────────────

@pytest.mark.asyncio
async def test_d24_next_url_honored_after_successful_login():
    """next_url from state data is the redirect target after login."""
    target = "/antibot-appsec-gateway/secured/settings"
    async with _fake_keycloak() as issuer:
        async with _patched_oidc(OIDC_ENABLED=True, OIDC_ISSUER=issuer,
                                  OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
            state_tok = _valid_state(next_url=target)
            req = _fake_request(query={"code": "code", "state": state_tok})

            with patch("admin.users._user_load",
                       return_value={"username": "alice", "role": "viewer",
                                     "status": "active"}), \
                 patch("admin.users._session_create", return_value="tok"), \
                 patch("admin.users._ACTIVE_SESSIONS", {}), \
                 patch("admin.users._SESSION_COOKIE", "agw_session"), \
                 patch("admin.users._SESSION_TTL", 3600):
                resp = await _oidc_mod.oidc_callback_endpoint(req)

    assert resp.status in (301, 302)
    assert target in resp.headers.get("Location", "")


# ── D25 — Open-redirect next_url values are rejected ─────────────────────────

@pytest.mark.asyncio
async def test_d25_malicious_next_url_replaced_with_safe_default():
    """//evil.com, https://evil.com open-redirect values replaced with safe path."""
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
        for bad_next in ["//evil.com", "https://evil.com", "http://evil.com"]:
            req = _fake_request(query={"next": bad_next})
            await _oidc_mod.oidc_login_endpoint(req)
            state_val = list(_oidc_mod._OIDC_STATE.values())[-1]
            assert state_val["next_url"] != bad_next, \
                f"next_url={bad_next!r} must not be stored verbatim (open-redirect)"
            assert "evil.com" not in state_val["next_url"]
            _oidc_mod._OIDC_STATE.clear()


# ── D26 / D27 — redirect_uri scheme follows SESSION_SECURE ───────────────────

@pytest.mark.asyncio
async def test_d26_redirect_uri_uses_https_when_session_secure():
    """redirect_uri is https:// when SESSION_SECURE=True regardless of request scheme."""
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
        with patch.object(_oidc_mod, "SESSION_SECURE", True):
            req = _fake_request(scheme="http", host="gw.example.com")
            resp = await _oidc_mod.oidc_login_endpoint(req)

    loc = resp.headers.get("Location", "")
    assert "redirect_uri=https" in loc or "redirect_uri=https%3A" in loc, \
        f"redirect_uri in Location must use https when SESSION_SECURE=True; got: {loc[:200]}"


@pytest.mark.asyncio
async def test_d27_redirect_uri_uses_request_scheme_when_not_session_secure():
    """redirect_uri uses request.scheme when SESSION_SECURE=False."""
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
        with patch.object(_oidc_mod, "SESSION_SECURE", False):
            req = _fake_request(scheme="http", host="gw.example.com")
            resp = await _oidc_mod.oidc_login_endpoint(req)

    loc = resp.headers.get("Location", "")
    assert "redirect_uri=http" in loc or "redirect_uri=http%3A" in loc, \
        f"redirect_uri must use http (request scheme) when SESSION_SECURE=False; got: {loc[:200]}"


# ── D28-D30 — Login page HTML rendering (direct endpoint, no server spin-up) ──

@pytest.mark.asyncio
async def test_d28_oidc_error_shown_in_login_page():
    """?oidc_error= renders 'SSO:' error in the login page body."""
    import admin.users as _users_mod
    req = MagicMock()
    req.query = {"oidc_error": "Token exchange failed"}
    req.cookies = {}
    resp = await _users_mod.login_page_endpoint(req)
    text = resp.text
    assert "SSO:" in text, "Login page must show 'SSO:' prefix for OIDC errors"
    assert "Token exchange failed" in text
    assert "__OIDC_ERROR__" not in text


@pytest.mark.asyncio
async def test_d29_oidc_button_present_in_login_page_when_enabled():
    """Login page includes Keycloak SSO button when OIDC_ENABLED=True."""
    import admin.users as _users_mod
    req = MagicMock()
    req.query = {}
    req.cookies = {}
    with patch.object(_oidc_mod, "OIDC_ENABLED", True), \
         patch.object(_oidc_mod, "OIDC_ISSUER", "https://kc.example.com/realms/test"):
        resp = await _users_mod.login_page_endpoint(req)
    text = resp.text
    # The CSS defines .sso-btn always; check for the actual anchor element.
    assert 'class="sso-btn"' in text, "Login page must render <a class='sso-btn'> when OIDC_ENABLED"
    assert "Keycloak" in text
    assert "__OIDC_BUTTON__" not in text


@pytest.mark.asyncio
async def test_d30_oidc_button_absent_in_login_page_when_disabled():
    """Login page has no SSO button when OIDC_ENABLED=False."""
    import admin.users as _users_mod
    req = MagicMock()
    req.query = {}
    req.cookies = {}
    with patch.object(_oidc_mod, "OIDC_ENABLED", False):
        resp = await _users_mod.login_page_endpoint(req)
    text = resp.text
    assert 'class="sso-btn"' not in text, "No sso-btn anchor must appear when OIDC disabled"
    assert "Keycloak" not in text
    assert "__OIDC_BUTTON__" not in text


# ── D31 — 10 sequential logins produce 10 unique state tokens ────────────────

@pytest.mark.asyncio
async def test_d31_sequential_logins_produce_unique_states():
    """Ten /login requests produce ten distinct, non-repeating state tokens."""
    async with _patched_oidc(OIDC_ENABLED=True,
                              OIDC_ISSUER="https://kc.example.com/realms/test",
                              OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s"):
        for _ in range(10):
            await _oidc_mod.oidc_login_endpoint(_fake_request())

        tokens = list(_oidc_mod._OIDC_STATE.keys())
        assert len(tokens) == 10
        assert len(set(tokens)) == 10, "All state tokens must be unique"


# ── D32 — _VALID_ROLES contains exactly the three expected roles ──────────────

def test_d32_valid_roles_set_exact():
    """_VALID_ROLES must be exactly {admin, maintainer, viewer} — no surprises."""
    assert _oidc_mod._VALID_ROLES == frozenset({"admin", "maintainer", "viewer"})
