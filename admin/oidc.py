"""
admin/oidc.py — Keycloak / OIDC authorization-code flow.

Env vars:
  OIDC_ISSUER         Keycloak realm base URL, e.g. https://kc.example.com/realms/myrealm
  OIDC_CLIENT_ID      Confidential client ID registered in Keycloak
  OIDC_CLIENT_SECRET  Client secret (Settings → Credentials in Keycloak console)
  OIDC_DEFAULT_ROLE   Gateway role assigned on auto-provision (default: viewer)
  OIDC_SCOPES         Space-separated OIDC scopes (default: openid profile email)

Flow:
  GET /antibot-appsec-gateway/auth/oidc/login
    → generate state, store with TTL, redirect to Keycloak auth endpoint

  GET /antibot-appsec-gateway/auth/oidc/callback?code=...&state=...
    → validate state (CSRF guard)
    → POST to /protocol/openid-connect/token (code exchange)
    → GET /protocol/openid-connect/userinfo (get preferred_username)
    → auto-provision local user row on first login (direct SQLite write)
    → call _session_create(), set agw_session cookie, redirect
"""
from __future__ import annotations

import asyncio
import re
import secrets
import sqlite3
import time as _t
from urllib.parse import quote, urlencode

import aiohttp
from aiohttp import web, ClientTimeout

from config import ADMIN_NS, SESSION_SECURE, DB_PATH
from state import db_queue
from helpers import slog, get_ip

# ── Config ────────────────────────────────────────────────────────────────────

import os

OIDC_ISSUER        = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID     = os.environ.get("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
OIDC_DEFAULT_ROLE  = os.environ.get("OIDC_DEFAULT_ROLE", "viewer").strip()
OIDC_SCOPES        = os.environ.get("OIDC_SCOPES", "openid profile email").strip()
OIDC_ENABLED       = bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET)

_CALLBACK_PATH      = ADMIN_NS + "/auth/oidc/callback"
_POST_LOGIN_PATH    = ADMIN_NS + "/secured/control-center"
_STATE_TTL_S        = 300   # 5-minute window for the browser round-trip

# ── State store — CSRF protection ─────────────────────────────────────────────
# state_token → {"next_url": str, "expires_ts": float}
_OIDC_STATE: dict = {}

_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
_VALID_ROLES  = frozenset({"admin", "maintainer", "viewer"})


def _safe_username(preferred: str) -> str | None:
    """Normalize Keycloak preferred_username to gateway username constraints.
    Returns None when normalization produces a string that still doesn't match."""
    u = (preferred or "").strip().lower()
    u = re.sub(r"[^a-z0-9._-]", ".", u)   # replace invalid chars with dots
    u = re.sub(r"\.{2,}", ".", u).strip(".")
    return u if _USERNAME_RE.match(u) else None


def _purge_expired_states() -> None:
    n = _t.time()
    stale = [k for k, v in _OIDC_STATE.items() if v["expires_ts"] < n]
    for k in stale:
        del _OIDC_STATE[k]


def _redirect_uri(request: web.Request) -> str:
    scheme = "https" if SESSION_SECURE else request.scheme
    return f"{scheme}://{request.host}{_CALLBACK_PATH}"


# ── Endpoints ─────────────────────────────────────────────────────────────────

async def oidc_login_endpoint(request: web.Request) -> web.Response:
    """GET /antibot-appsec-gateway/auth/oidc/login — redirect to Keycloak."""
    if not OIDC_ENABLED:
        return web.Response(status=404, text="OIDC not configured\n",
                            headers={"Cache-Control": "no-store"})

    next_url = request.query.get("next", "")
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = _POST_LOGIN_PATH

    state = secrets.token_urlsafe(24)
    _purge_expired_states()
    _OIDC_STATE[state] = {"next_url": next_url, "expires_ts": _t.time() + _STATE_TTL_S}

    params = {
        "response_type": "code",
        "client_id":     OIDC_CLIENT_ID,
        "redirect_uri":  _redirect_uri(request),
        "scope":         OIDC_SCOPES,
        "state":         state,
    }
    auth_url = f"{OIDC_ISSUER}/protocol/openid-connect/auth?{urlencode(params)}"
    return web.HTTPFound(auth_url)


async def oidc_callback_endpoint(request: web.Request) -> web.Response:
    """GET /antibot-appsec-gateway/auth/oidc/callback — complete OIDC login."""
    if not OIDC_ENABLED:
        return web.Response(status=404, text="OIDC not configured\n",
                            headers={"Cache-Control": "no-store"})

    _purge_expired_states()
    ip = get_ip(request)

    error = request.query.get("error")
    if error:
        slog("oidc_idp_error", level="warn", error=error,
             desc=(request.query.get("error_description") or "")[:200], ip=ip)
        return _redirect_error(f"Identity provider error: {error}")

    code  = request.query.get("code", "")
    state = request.query.get("state", "")
    if not code or not state:
        return _redirect_error("Missing code or state parameter")

    state_data = _OIDC_STATE.pop(state, None)
    if state_data is None or state_data["expires_ts"] < _t.time():
        slog("oidc_invalid_state", level="warn", ip=ip)
        return _redirect_error("Login session expired — please try again")

    next_url = state_data["next_url"]

    # ── Exchange code for tokens ──────────────────────────────────────────────
    try:
        timeout = ClientTimeout(total=8.0)
        async with aiohttp.ClientSession() as http:
            # Step 1: token endpoint
            async with http.post(
                    f"{OIDC_ISSUER}/protocol/openid-connect/token",
                    data={
                        "grant_type":    "authorization_code",
                        "code":          code,
                        "redirect_uri":  _redirect_uri(request),
                        "client_id":     OIDC_CLIENT_ID,
                        "client_secret": OIDC_CLIENT_SECRET,
                    },
                    headers={"Accept": "application/json"},
                    timeout=timeout) as resp:
                if resp.status != 200:
                    body = (await resp.text())[:300]
                    slog("oidc_token_exchange_failed", level="warn",
                         status=resp.status, body=body, ip=ip)
                    return _redirect_error("Token exchange failed — check Keycloak client config")
                token_data = await resp.json(content_type=None)

            access_token = token_data.get("access_token")
            if not access_token:
                slog("oidc_no_access_token", level="warn", ip=ip)
                return _redirect_error("No access token in IdP response")

            # Step 2: userinfo
            async with http.get(
                    f"{OIDC_ISSUER}/protocol/openid-connect/userinfo",
                    headers={"Authorization": f"Bearer {access_token}",
                             "Accept": "application/json"},
                    timeout=timeout) as resp:
                if resp.status != 200:
                    slog("oidc_userinfo_failed", level="warn",
                         status=resp.status, ip=ip)
                    return _redirect_error("Userinfo fetch failed — check Keycloak scopes")
                userinfo = await resp.json(content_type=None)

    except asyncio.TimeoutError:
        slog("oidc_timeout", level="warn", ip=ip)
        return _redirect_error("Identity provider timed out — try again")
    except aiohttp.ClientError as e:
        slog("oidc_network_error", level="warn",
             err=f"{type(e).__name__}: {str(e)[:120]}", ip=ip)
        return _redirect_error("Could not reach identity provider — try again")

    # ── Map IdP identity → gateway username ───────────────────────────────────
    preferred = (userinfo.get("preferred_username")
                 or userinfo.get("email")
                 or "").strip()
    username = _safe_username(preferred)
    if not username:
        slog("oidc_unmappable_username", level="warn",
             preferred=preferred[:80], ip=ip)
        return _redirect_error(
            f"Cannot map IdP identity {repr(preferred)[:60]} to a valid gateway username")

    # ── Provision user on first login ─────────────────────────────────────────
    from admin.users import (_user_load, _session_create,
                             _ACTIVE_SESSIONS, _SESSION_COOKIE, _SESSION_TTL)

    user = _user_load(username)
    if user is None:
        role = OIDC_DEFAULT_ROLE if OIDC_DEFAULT_ROLE in _VALID_ROLES else "viewer"
        n = _t.time()
        try:
            # Direct synchronous write: _request_role() reads the users table on
            # every authenticated request, so the row must exist before the session
            # is issued — the async db_queue flush would be too late.
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "INSERT OR IGNORE INTO users "
                "(username, password_hash, role, status, created_ts, updated_ts) "
                "VALUES (?, '', ?, 'active', ?, ?)",
                (username, role, n, n))
            conn.commit()
            conn.close()
        except Exception as e:
            slog("oidc_provision_failed", level="error",
                 username=username, err=str(e)[:200])
            return _redirect_error("Account provisioning failed — contact an administrator")
        slog("oidc_user_provisioned", level="warn",
             username=username, role=role, ip=ip)
        user = _user_load(username)

    elif user.get("status") != "active":
        slog("oidc_login_disabled_user", level="warn", username=username, ip=ip)
        return _redirect_error("Your account is disabled — contact an administrator")

    # ── Mint session (same machinery as password login) ───────────────────────
    ua    = (request.headers.get("User-Agent") or "")[:512]
    token = _session_create(username, ip, ua)
    _ACTIVE_SESSIONS[username] = _t.time()

    if db_queue is not None:
        try:
            db_queue.put_nowait(("user_login_recorded", (_t.time(), ip, username)))
        except asyncio.QueueFull:
            pass

    slog("oidc_login_success", level="warn", username=username, ip=ip)

    resp = web.HTTPFound(next_url)
    resp.set_cookie(_SESSION_COOKIE, token,
                    max_age=_SESSION_TTL, httponly=True,
                    samesite="Lax", path="/",
                    secure=SESSION_SECURE)
    return resp


# ── Helpers ───────────────────────────────────────────────────────────────────

def _redirect_error(msg: str) -> web.Response:
    """Redirect to /login with an error message surfaced in the query string."""
    return web.HTTPFound(f"{ADMIN_NS}/login?oidc_error={quote(msg)}")


def oidc_button_html() -> str:
    """Return the SSO button block for login.html, or '' when OIDC disabled."""
    if not OIDC_ENABLED:
        return ""
    return (
        '<div class="sso-divider"><span>or</span></div>'
        f'<a href="{ADMIN_NS}/auth/oidc/login" class="sso-btn">'
        '<svg width="16" height="16" viewBox="0 0 32 32" fill="none" '
        'style="vertical-align:middle;margin-right:7px;flex-shrink:0">'
        '<circle cx="16" cy="16" r="16" fill="#4D9BFF"/>'
        '<path d="M8 22V10h5l3 6 3-6h5v12h-3v-8l-4 8-4-8v8H8z" fill="#fff"/>'
        '</svg>Sign in with Keycloak</a>'
    )
