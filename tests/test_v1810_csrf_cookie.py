"""1.8.10 — CSRF cookie issuance + self-heal.

Bug: every state-mutating admin POST (config / bypass / "Disable all") failed
with 403 "CSRF token invalid" because the agw_csrf cookie was missing:
  * the OIDC/SSO login path set agw_session but never agw_csrf;
  * agw_csrf is only minted at login, so a session whose csrf cookie expired
    (it lives 12 h) or went stale had no valid token to send.

Fixes:
  * OIDC callback now issues agw_csrf like password login;
  * protect() re-issues the correct agw_csrf on any authed admin response where
    it's missing/stale, so loading a page self-heals it (no re-login).
"""
import os
import pathlib
import importlib

OIDC = pathlib.Path("admin/oidc.py").read_text()
USERS = pathlib.Path("admin/users.py").read_text()
PROXY = pathlib.Path("core/proxy_handler.py").read_text()
MIDDLEWARE = pathlib.Path("core/middleware.py").read_text()


def test_oidc_sets_csrf_cookie_after_session():
    # Contract change (1.9.1, locked by test_v1814_csrf_nonce_regression::test_n04):
    # agw_csrf delivery was CENTRALISED into core/middleware._csrf_self_heal, which
    # runs on EVERY admin response. The OIDC callback no longer mints agw_csrf
    # inline — it mints the session cookie (agw_session) and the middleware
    # self-heal re-issues agw_csrf on the first dashboard load. Assert the shipped
    # contract: OIDC sets the session cookie, and the centralised self-heal owns
    # the agw_csrf cookie (derived from the same sid + SESSION_KEY).
    assert 'set_cookie(_SESSION_COOKIE, token' in OIDC, \
        "OIDC callback must mint the session cookie"
    assert "def _csrf_self_heal" in MIDDLEWARE and '"agw_csrf"' in MIDDLEWARE, \
        "centralised middleware self-heal must own agw_csrf issuance"


def test_password_login_still_sets_csrf_cookie():
    assert USERS.count('set_cookie("agw_csrf"') >= 1, \
        "password login must keep setting agw_csrf"


def test_protect_reissues_csrf_when_missing_or_stale():
    # Contract change (1.9.1, locked by test_v1814_csrf_nonce_regression::test_n04):
    # the self-heal block was REMOVED from proxy_handler.protect() and centralised
    # in core/middleware._csrf_self_heal (runs on every admin response). The
    # security contract is unchanged and re-asserted here against the canonical
    # location: re-issue the agw_csrf cookie only when stale, derived from the
    # session sid with SESSION_KEY (same formula as the validator).
    assert "1.8.10 — self-heal the CSRF cookie" not in PROXY, \
        "self-heal must not be duplicated in proxy_handler"
    idx = MIDDLEWARE.find("def _csrf_self_heal")
    assert idx != -1, "middleware must own the canonical _csrf_self_heal"
    body = MIDDLEWARE[idx:idx + 4000]
    # only re-issues when the cookie differs from the expected token
    assert 'request.cookies.get("agw_csrf", "")' in body and "have != want" in body
    assert 'set_cookie(' in body and '"agw_csrf"' in body
    # derived from the session sid with SESSION_KEY (same as the validator)
    assert "sid" in body and "SESSION_KEY" in body


def test_record_still_called_in_authed_branch():
    """Guard: the self-heal block must not displace the operator-passthrough
    record() call from the authed admin branch."""
    start = PROXY.index("_admin_ip_allowed(request) and _internal_authed(request):")
    branch = PROXY[start:start + 1400]
    assert "await record(" in branch and "operator-passthrough" in branch


def test_csrf_validation_roundtrip():
    """Functional: a token derived the same way the cookie is minted validates,
    and a wrong token does not.

    Contract change (1.9.1, locked by test_v1814_csrf_nonce_regression::test_n01):
    the 1.8.14 T0-2 per-session nonce was intentionally SUPERSEDED. The shipped
    CSRF token is pure HMAC(SESSION_KEY, sid)[:32] double-submit — _session_create
    stores an EMPTY csrf_nonce slot (admin/users.py:216-220) and the validator
    derives the expected token via HMAC (admin/auth.py:40). Good token is that
    HMAC, not a cache nonce."""
    import hmac as _hmac
    import hashlib as _hashlib
    os.environ.setdefault("UPSTREAM", "https://example.com")
    auth = importlib.import_module("admin.auth")
    users = importlib.import_module("admin.users")
    from config import SESSION_KEY
    token = users._session_create("qa-admin", "127.0.0.1", "qa-agent")
    sid = token.split("|")[1]
    # 1.9.1: good token is HMAC(SESSION_KEY, sid)[:32] — same formula the cookie
    # is minted with and the validator checks against.
    good = _hmac.new(SESSION_KEY, sid.encode(), _hashlib.sha256).hexdigest()[:32]

    class _Req:
        method = "POST"
        def __init__(self, cookie, csrf):
            self.cookies = {users._SESSION_COOKIE: cookie}
            self.headers = {"X-CSRF-Token": csrf}
    assert auth._csrf_token_valid(_Req(token, good)) is True
    assert auth._csrf_token_valid(_Req(token, "deadbeef" * 4)) is False
    assert auth._csrf_token_valid(_Req(token, "")) is False
