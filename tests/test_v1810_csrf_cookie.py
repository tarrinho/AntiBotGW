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


def test_oidc_sets_csrf_cookie_after_session():
    assert 'set_cookie("agw_csrf"' in OIDC, "OIDC login must set agw_csrf"
    assert OIDC.index("_SESSION_COOKIE, token") < OIDC.index('set_cookie("agw_csrf"'), \
        "agw_csrf must be set alongside the session cookie in the OIDC callback"


def test_password_login_still_sets_csrf_cookie():
    assert USERS.count('set_cookie("agw_csrf"') >= 1, \
        "password login must keep setting agw_csrf"


def test_protect_reissues_csrf_when_missing_or_stale():
    assert "self-heal the CSRF cookie" in PROXY, "protect() CSRF self-heal missing"
    # only re-issues when the cookie differs from the expected token
    assert 'request.cookies.get("agw_csrf", "") != _want_csrf' in PROXY
    assert 'set_cookie("agw_csrf"' in PROXY
    # derived from the session sid with SESSION_KEY (same as the validator)
    assert "_session_sid" in PROXY and "SESSION_KEY" in PROXY


def test_record_still_called_in_authed_branch():
    """Guard: the self-heal block must not displace the operator-passthrough
    record() call from the authed admin branch."""
    start = PROXY.index("_admin_ip_allowed(request) and _internal_authed(request):")
    branch = PROXY[start:start + 1400]
    assert "await record(" in branch and "operator-passthrough" in branch


def test_csrf_validation_roundtrip():
    """Functional: a token derived the same way the cookie is minted validates,
    and a wrong token does not."""
    os.environ.setdefault("UPSTREAM", "https://example.com")
    import hmac, hashlib
    auth = importlib.import_module("admin.auth")
    users = importlib.import_module("admin.users")
    from config import SESSION_KEY
    token = users._session_create("qa-admin", "127.0.0.1", "qa-agent")
    sid = token.split("|")[1]
    good = hmac.new(SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]

    class _Req:
        method = "POST"
        def __init__(self, cookie, csrf):
            self.cookies = {users._SESSION_COOKIE: cookie}
            self.headers = {"X-CSRF-Token": csrf}
    assert auth._csrf_token_valid(_Req(token, good)) is True
    assert auth._csrf_token_valid(_Req(token, "deadbeef" * 4)) is False
    assert auth._csrf_token_valid(_Req(token, "")) is False
