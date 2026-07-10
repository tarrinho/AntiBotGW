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
import hmac
import re
import secrets
import time as _t
from urllib.parse import quote, urlencode

import aiohttp
from aiohttp import web, ClientTimeout
import jwt as _pyjwt

from config import ADMIN_NS, SESSION_SECURE
from state import db_queue
from helpers import slog, get_ip

# ── id_token verification (1.8.11) ─────────────────────────────────────────────
# Asymmetric algorithms only — HS* (symmetric) and 'none' are excluded to block
# the classic alg-confusion attack where an attacker re-signs a token with the
# IdP's public key used as an HMAC secret.
_OIDC_ALLOWED_ALGS = ["RS256", "RS384", "RS512",
                      "PS256", "PS384", "PS512",
                      "ES256", "ES384", "ES512"]
_JWKS_LEEWAY_S = 30                         # clock-skew tolerance on exp / nbf
_JWKS_CACHE_TTL_S = 3600                    # cache the IdP signing keys for 1 h
# _JWKS_URI (set after the OIDC config block below) → {"jwks":..., "expires":...}
_JWKS_CACHE: dict = {}

# ── Opaque login-error codes (AUTH4-13) ────────────────────────────────────────
# The callback redirects to /login?oidc_error=<code> using ONLY these opaque
# codes — never a raw IdP/exception string — so nothing attacker-influenced is
# reflected into the login page. login_page_endpoint maps the code back to a
# fixed safe message; unknown codes fall back to err_generic.
_ERROR_CODES = {
    "err_idp_error":         "The identity provider reported an error. Please try again.",
    "err_missing_params":    "The login response was incomplete. Please try again.",
    "err_invalid_state":     "Your login session expired. Please try again.",
    "err_token_exchange":    "Could not complete sign-in with the identity provider.",
    "err_no_access_token":   "The identity provider did not return an access token.",
    "err_token_replay":      "The identity provider response was missing an ID token.",
    "err_idtoken":           "The identity provider's ID token could not be verified.",
    "err_userinfo":          "Could not read your profile from the identity provider.",
    "err_timeout":           "The identity provider timed out. Please try again.",
    "err_network":           "Could not reach the identity provider. Please try again.",
    "err_identity_mismatch": "Identity verification failed. Please contact an administrator.",
    "err_unmappable":        "Your identity could not be mapped to a gateway account.",
    "err_disabled":          "Your account is disabled. Contact an administrator.",
    "err_provision":         "Account provisioning failed. Contact an administrator.",
    "err_generic":           "Single sign-on failed. Please try again.",
}

# ── Config ────────────────────────────────────────────────────────────────────

import os

OIDC_ISSUER        = os.environ.get("OIDC_ISSUER", "").rstrip("/")
OIDC_CLIENT_ID     = os.environ.get("OIDC_CLIENT_ID", "").strip()
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
OIDC_DEFAULT_ROLE  = os.environ.get("OIDC_DEFAULT_ROLE", "viewer").strip()
OIDC_SCOPES        = os.environ.get("OIDC_SCOPES", "openid profile email").strip()
OIDC_ENABLED       = bool(OIDC_ISSUER and OIDC_CLIENT_ID and OIDC_CLIENT_SECRET)

# JWKS endpoint — Keycloak's certs URL under the realm issuer (patched in tests).
_JWKS_URI = (OIDC_ISSUER + "/protocol/openid-connect/certs") if OIDC_ISSUER else ""

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


async def _fetch_jwks(http, *, force: bool = False) -> dict:
    """Fetch the IdP's JWKS (signing keys), cached for _JWKS_CACHE_TTL_S.

    ``force=True`` bypasses the cache — used once on a kid-miss to pick up a
    rotated signing key before giving up.
    """
    # Signing keys MUST be fetched over TLS — a plaintext JWKS lets a network
    # attacker inject their own key and forge id_tokens. Loopback is exempt
    # (a co-located IdP sidecar on 127.x is a trusted dev pattern).
    if not (_JWKS_URI.startswith("https://")
            or _JWKS_URI.startswith("http://127.")
            or _JWKS_URI.startswith("http://[::1]")
            or _JWKS_URI.startswith("http://localhost")):
        raise ValueError("refusing to fetch JWKS over a non-TLS URL")
    now = _t.time()
    cached = _JWKS_CACHE.get(_JWKS_URI)
    if cached and not force and cached.get("expires", 0) > now:
        return cached["jwks"]
    async with http.get(_JWKS_URI, timeout=ClientTimeout(total=8.0)) as resp:
        jwks = await resp.json(content_type=None)
    _JWKS_CACHE[_JWKS_URI] = {"jwks": jwks, "expires": now + _JWKS_CACHE_TTL_S}
    return jwks


def _select_jwk(jwks: dict, kid: str) -> dict | None:
    # Require a concrete kid match. A token with no kid must NOT match a keyless
    # JWK entry (None == None) — force an explicit key selection.
    if not kid:
        return None
    for k in (jwks or {}).get("keys", []):
        if k.get("kid") == kid:
            return k
    return None


async def _verify_id_token(http, token: str, expected_nonce: str | None) -> dict:
    """Cryptographically verify an OIDC id_token and return its claims.

    Enforces (OIDC Core §3.1.3.7): asymmetric signature via the IdP JWKS,
    allowed-alg allowlist (no HS*/none — alg-confusion guard), iss == OIDC_ISSUER,
    aud == OIDC_CLIENT_ID, exp/nbf within ±_JWKS_LEEWAY_S, required iat/exp/sub
    claims, and the nonce binding to the login request. Raises on any failure.
    """
    # 1) Header: reject disallowed algs BEFORE any key work (alg-confusion guard).
    header = _pyjwt.get_unverified_header(token)
    alg = header.get("alg", "")
    if alg not in _OIDC_ALLOWED_ALGS:
        raise ValueError(f"disallowed id_token alg: {alg!r}")
    kid = header.get("kid")

    # 2) Resolve the signing key by kid; one forced JWKS refresh on a miss to
    #    tolerate key rotation between the login redirect and the callback.
    jwks = await _fetch_jwks(http)
    jwk = _select_jwk(jwks, kid)
    if jwk is None:
        jwks = await _fetch_jwks(http, force=True)
        jwk = _select_jwk(jwks, kid)
    if jwk is None:
        raise ValueError(f"no matching JWKS key for kid {kid!r}")
    key = _pyjwt.PyJWK(jwk).key

    # 3) Verify signature + standard claims. PyJWT raises typed exceptions
    #    (ExpiredSignatureError, InvalidIssuerError, InvalidAudienceError,
    #    ImmatureSignatureError, MissingRequiredClaimError, InvalidSignatureError).
    claims = _pyjwt.decode(
        token, key, algorithms=_OIDC_ALLOWED_ALGS,
        audience=OIDC_CLIENT_ID, issuer=OIDC_ISSUER,
        leeway=_JWKS_LEEWAY_S,
        options={"require": ["exp", "iat", "sub"]})

    # 4) Nonce binding — PyJWT does not check it. Constant-time compare; a missing
    #    or mismatched token nonce is fatal when we expected one.
    tok_nonce = claims.get("nonce", "")
    if not (expected_nonce and tok_nonce
            and hmac.compare_digest(str(expected_nonce), str(tok_nonce))):
        raise ValueError("id_token nonce mismatch")
    return claims


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
        return _redirect_error("err_idp_error")

    code  = request.query.get("code", "")
    state = request.query.get("state", "")
    if not code or not state:
        return _redirect_error("err_missing_params")

    # Consume the state token BEFORE any HTTP leg so a replay is impossible even
    # if a later step fails.
    state_data = _OIDC_STATE.pop(state, None)
    if state_data is None or state_data["expires_ts"] < _t.time():
        slog("oidc_invalid_state", level="warn", ip=ip)
        return _redirect_error("err_invalid_state")

    next_url = state_data["next_url"]
    nonce    = state_data.get("nonce")

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
                    return _redirect_error("err_token_exchange")
                token_data = await resp.json(content_type=None)

            access_token = token_data.get("access_token")
            if not access_token:
                slog("oidc_no_access_token", level="warn", ip=ip)
                return _redirect_error("err_no_access_token")

            # id_token is REQUIRED (OIDC Core) — absence means we can't bind the
            # authenticated identity (token-replay / userinfo-spoof guard).
            id_token = token_data.get("id_token") or ""
            if not id_token:
                slog("oidc_no_id_token", level="warn", ip=ip)
                return _redirect_error("err_token_replay")

            # Cryptographically verify the id_token (signature + claims + nonce).
            try:
                id_claims = await _verify_id_token(http, id_token, nonce)
            except Exception as e:
                slog("oidc_idtoken_invalid", level="warn",
                     err=f"{type(e).__name__}: {str(e)[:160]}", ip=ip)
                return _redirect_error("err_idtoken")

            # Step 2: userinfo
            async with http.get(
                    f"{OIDC_ISSUER}/protocol/openid-connect/userinfo",
                    headers={"Authorization": f"Bearer {access_token}",
                             "Accept": "application/json"},
                    timeout=timeout) as resp:
                if resp.status != 200:
                    slog("oidc_userinfo_failed", level="warn",
                         status=resp.status, ip=ip)
                    return _redirect_error("err_userinfo")
                userinfo = await resp.json(content_type=None)

    except asyncio.TimeoutError:
        slog("oidc_timeout", level="warn", ip=ip)
        return _redirect_error("err_timeout")
    except aiohttp.ClientError as e:
        slog("oidc_network_error", level="warn",
             err=f"{type(e).__name__}: {str(e)[:120]}", ip=ip)
        return _redirect_error("err_network")

    # ── INT4-10: bind the verified id_token sub to the userinfo sub ───────────
    # Both come from the same IdP; a mismatch means identity confusion (an
    # attacker substituting a different account) — refuse to issue a session.
    id_sub = (id_claims or {}).get("sub")
    ui_sub = userinfo.get("sub")
    if id_sub and ui_sub and str(id_sub) != str(ui_sub):
        slog("oidc_sub_mismatch", level="warn",
             id_sub=str(id_sub)[:64], ui_sub=str(ui_sub)[:64], ip=ip)
        return _redirect_error("err_identity_mismatch")

    # ── Map IdP identity → gateway username ───────────────────────────────────
    preferred = (userinfo.get("preferred_username")
                 or userinfo.get("email")
                 or "").strip()
    username = _safe_username(preferred)
    if not username:
        slog("oidc_unmappable_username", level="warn",
             preferred=preferred[:80], ip=ip)
        return _redirect_error("err_unmappable")

    # ── Provision user on first login (PENDING — needs admin approval) ────────
    from admin.users import (_user_load, _session_create,
                             _ACTIVE_SESSIONS, _SESSION_COOKIE, _SESSION_TTL)

    user = _user_load(username)
    if user is None:
        role = OIDC_DEFAULT_ROLE if OIDC_DEFAULT_ROLE in _VALID_ROLES else "viewer"
        n = _t.time()
        try:
            # Direct synchronous write — _request_role() reads the users
            # table on every authenticated request, so the row must land before
            # any session is issued; the async db_queue flush would be too late.
            # New SSO accounts are created status='pending', sso_source='oidc' —
            # they get NO session until an admin authorises them.
            #
            # 1.9.1 iter-18: route through open_conn + branch the DML by
            # backend. The old bare `sqlite3.connect(DB_PATH)` + SQLite-only
            # `INSERT OR IGNORE` wrote the pending row to the LOCAL SQLite
            # file in PG-only mode (where _request_role reads PG) — so the
            # SSO account was invisible and could never be approved. PG path
            # uses `ON CONFLICT (username) DO NOTHING`.
            from db import open_conn as _open_conn_sso, active_backend as _active_sso
            _be_sso = _active_sso()
            conn = _open_conn_sso()
            if _be_sso == "postgres":
                conn.execute(
                    "INSERT INTO users "
                    "(username, password_hash, role, status, sso_source, "
                    " created_ts, updated_ts) "
                    "VALUES (?, '', ?, 'pending', 'oidc', ?, ?) "
                    "ON CONFLICT (username) DO NOTHING",
                    (username, role, n, n))
            else:
                conn.execute(
                    "INSERT OR IGNORE INTO users "
                    "(username, password_hash, role, status, sso_source, "
                    " created_ts, updated_ts) "
                    "VALUES (?, '', ?, 'pending', 'oidc', ?, ?)",
                    (username, role, n, n))
            conn.commit()
            conn.close()
        except Exception as e:
            slog("oidc_provision_failed", level="error",
                 username=username, err=str(e)[:200])
            return _redirect_error("err_provision")
        slog("oidc_user_provisioned", level="warn",
             username=username, role=role, ip=ip)
        # Pending approval — no session, surface a 404 (admin must activate).
        return web.Response(
            status=404,
            text="Account created and pending administrator approval.\n",
            headers={"Cache-Control": "no-store"})

    if user.get("status") == "pending":
        slog("oidc_login_pending_user", level="warn", username=username, ip=ip)
        return web.Response(
            status=404,
            text="Account pending administrator approval.\n",
            headers={"Cache-Control": "no-store"})

    if user.get("status") != "active":
        slog("oidc_login_disabled_user", level="warn", username=username, ip=ip)
        return _redirect_error("err_disabled")

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
                    samesite="Strict", path="/",
                    secure=SESSION_SECURE)
    return resp


# ── Helpers ───────────────────────────────────────────────────────────────────

def _redirect_error(code: str) -> web.Response:
    """Redirect to /login with an OPAQUE error code (AUTH4-13). Only codes from
    _ERROR_CODES are emitted — login_page_endpoint maps them to safe messages,
    so no raw IdP/exception text is ever reflected into the page."""
    return web.HTTPFound(f"{ADMIN_NS}/login?oidc_error={quote(code)}")


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
