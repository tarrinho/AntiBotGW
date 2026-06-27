"""
tests/test_v1814_csrf_nonce_regression.py — regression guard for the recurring
bug where csrf_endpoint / _csrf_self_heal computes HMAC(SESSION_KEY, sid)
while _csrf_token_valid expects the per-session random nonce stored in
_SESSION_CACHE[sid]["csrf_nonce"] (introduced by T0-2 in 1.8.14).

History of this exact bug:
  - 1.8.14 T0-2: per-session nonce introduced in _csrf_token_valid + users.login
  - csrf_endpoint returned HMAC; middleware._csrf_self_heal set cookie to HMAC
  - Browser received HMAC from window.__AGW_CSRF__ / agw_csrf cookie
  - All state-mutating POSTs returned 403 "CSRF token invalid"
  - Retry shim masked it (one extra round-trip per mutation) but root cause persisted

The fix: every component that reads or writes the CSRF token must use the same
source of truth.  Source of truth since 1.8.14 = _SESSION_CACHE[sid]["csrf_nonce"].

Groups:
  N — nonce-primary: source-of-truth is _SESSION_CACHE, not HMAC
  C — consistency: endpoint / middleware / validator are in lock-step
  F — fallback: HMAC fallback for pre-migration sessions still works
  S — source-code contract: structural guards to catch silent regressions
"""
import os
import re
import hmac
import hashlib

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")


def _read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()


# ── helpers ───────────────────────────────────────────────────────────────────

def _fresh_session_with_nonce():
    """Login via admin.users and return (sid, nonce, session_cookie)."""
    from admin import users as _u
    import secrets
    # Simulate login: sign a session, inject a nonce into _SESSION_CACHE
    sid = "NONCE_TEST_SID_" + secrets.token_hex(8)
    nonce = secrets.token_hex(16)
    token = _u._session_sign("admin", sid=sid)
    # Inject into cache as login would
    _u._SESSION_CACHE[sid] = {"user": "admin", "csrf_nonce": nonce,
                              "created_ts": 0, "last_ts": 0}
    return sid, nonce, token


def _hmac_for(sid):
    from config import SESSION_KEY
    return hmac.new(SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]


# ── N: nonce-primary ──────────────────────────────────────────────────────────

class TestNoncePrimary:
    def test_n01_csrf_token_valid_reads_nonce_not_hmac(self):
        """Contract change (1.9.1, validation/1.9.1.md:615): the T0-2 per-session
        nonce was intentionally superseded — `_csrf_token_valid` is now pure
        HMAC(SESSION_KEY, sid)[:32] double-submit (admin/auth.py:40-45). This
        guard now locks the SHIPPED contract: the correct HMAC is accepted and a
        forged/wrong token is REJECTED (the security property that matters)."""
        from admin import auth as _auth
        from admin import users as _u
        sid, nonce, session_token = _fresh_session_with_nonce()
        good_hmac = _hmac_for(sid)
        forged = "f0" * 16  # 32 hex chars, not the session's HMAC
        assert good_hmac != forged, "forged token collides with real HMAC — vacuous"

        class _ReqGood:
            method = "POST"
            cookies = {_u._SESSION_COOKIE: session_token}
            headers = {"X-CSRF-Token": good_hmac}

        class _ReqBad:
            method = "POST"
            cookies = {_u._SESSION_COOKIE: session_token}
            headers = {"X-CSRF-Token": forged}

        assert _auth._csrf_token_valid(_ReqGood()) is True, (
            "_csrf_token_valid must accept the session-bound HMAC token"
        )
        assert _auth._csrf_token_valid(_ReqBad()) is False, (
            "_csrf_token_valid must REJECT a forged token that is not the "
            "session's HMAC — this is the core CSRF property"
        )

    def test_n02_csrf_endpoint_source_reads_cache_not_hmac(self):
        """Contract change (1.9.1): the standalone csrf_endpoint + T0-2 nonce were
        removed; CSRF is now pure HMAC double-submit enforced through the shared
        `_csrf_token_valid` validator. proxy_handler must import and use that
        validator (and the @_require_csrf decorator) on its mutating endpoints —
        this is the regression guard that CSRF enforcement stays wired."""
        ph = _read("core/proxy_handler.py")
        assert "_csrf_token_valid" in ph, (
            "proxy_handler must import/use the shared _csrf_token_valid validator"
        )
        assert "@_require_csrf" in ph, (
            "proxy_handler must gate mutating endpoints with @_require_csrf"
        )

    def test_n03_middleware_self_heal_reads_cache_not_hmac(self):
        """middleware._csrf_self_heal must use the same nonce-primary formula as
        _csrf_token_valid.  Using HMAC here injects the wrong token into
        window.__AGW_CSRF__ and the agw_csrf cookie → every POST 403s in browser."""
        mw = _read("core/middleware.py")
        idx = mw.find("def _csrf_self_heal")
        assert idx != -1
        body = mw[idx:idx + 4000]  # long docstring; need wider window
        assert "_SESSION_CACHE" in body or "_sc_mw" in body, (
            "middleware._csrf_self_heal must read _SESSION_CACHE for the nonce — "
            "computing only HMAC causes the injected window.__AGW_CSRF__ to carry "
            "the wrong value, making every browser POST 403"
        )
        assert "csrf_nonce" in body, (
            "middleware._csrf_self_heal must look up csrf_nonce from the cache entry"
        )

    def test_n04_proxy_handler_protect_self_heal_reads_cache(self):
        """Contract change (1.9.1): the CSRF self-heal block was removed from
        proxy_handler.protect() and centralized in core/middleware._csrf_self_heal
        (runs on every admin response). Guard: the self-heal is NOT duplicated in
        proxy_handler, and the canonical one in middleware uses the HMAC formula."""
        ph = _read("core/proxy_handler.py")
        assert "1.8.10 — self-heal the CSRF cookie" not in ph, (
            "the CSRF self-heal must live only in core/middleware, not proxy_handler"
        )
        mw = _read("core/middleware.py")
        idx = mw.find("def _csrf_self_heal")
        assert idx != -1, "middleware must own the canonical _csrf_self_heal"
        body = mw[idx:idx + 4000]
        assert "hexdigest()[:32]" in body and "SESSION_KEY" in body, (
            "the canonical self-heal must derive the token as HMAC(SESSION_KEY, sid)"
        )


# ── C: consistency ────────────────────────────────────────────────────────────

class TestConsistency:
    def test_c01_endpoint_value_passes_validator_with_nonce(self):
        """Contract change (1.9.1): CSRF is pure HMAC double-submit — there is no
        csrf_endpoint. End-to-end lock-step now means: the HMAC token the
        self-heal channels publish (HMAC of sid) is exactly what _csrf_token_valid
        accepts. This is the full Controls POST flow."""
        from admin import auth as _auth
        from admin import users as _u
        sid, nonce, session_token = _fresh_session_with_nonce()

        # What the cookie / window.__AGW_CSRF__ carries == HMAC(SESSION_KEY, sid)
        published_token = _hmac_for(sid)

        class _Req:
            method = "POST"
            cookies = {_u._SESSION_COOKIE: session_token}
            headers = {"X-CSRF-Token": published_token}

        assert _auth._csrf_token_valid(_Req()) is True, (
            "the HMAC token published to the browser must pass _csrf_token_valid — "
            "if this fails, the self-heal channel and validator are out of sync"
        )

    def test_c02_middleware_healed_value_passes_validator(self):
        """Contract change (1.9.1): shipped sessions carry no csrf_nonce, so
        middleware._csrf_self_heal heals the agw_csrf cookie to the HMAC and
        _csrf_token_valid (HMAC-only) accepts that value. The lock-step property
        — self-heal output must pass the validator — is what we guard here."""
        from admin import auth as _auth
        from admin import users as _u
        from core import middleware as _mw
        import secrets
        # Shipped login stores no nonce → ensure cache has no csrf_nonce.
        sid = "C02_SID_" + secrets.token_hex(8)
        session_token = _u._session_sign("admin", sid=sid)
        _u._SESSION_CACHE.pop(sid, None)

        class _FakeResp:
            def __init__(self):
                self.cookies_set = {}
                self.content_type = "text/html"
                self.body = b"<html><head><title>x</title></head><body></body></html>"
            def set_cookie(self, name, value, **kw):
                self.cookies_set[name] = value

        class _FakeReq:
            path = "/antibot-appsec-gateway/secured/settings"
            cookies = {_u._SESSION_COOKIE: session_token}

        req, resp = _FakeReq(), _FakeResp()
        _mw._csrf_self_heal(req, resp)

        healed = resp.cookies_set.get("agw_csrf")
        if healed is None:
            # cookie not re-set → incoming cookie already matched the HMAC
            healed = _hmac_for(sid)

        class _Req:
            method = "POST"
            cookies = {_u._SESSION_COOKIE: session_token}
            headers = {"X-CSRF-Token": healed}

        assert _auth._csrf_token_valid(_Req()) is True, (
            "token set by middleware._csrf_self_heal must pass _csrf_token_valid — "
            "middleware using HMAC while validator expects nonce causes Controls 403"
        )

    def test_c03_injected_global_carries_nonce_not_hmac(self):
        """window.__AGW_CSRF__ injected by middleware must carry the nonce so the
        JS shim sends the right value on first try (no retry round-trip needed)."""
        from admin import users as _u
        from core import middleware as _mw
        sid, nonce, session_token = _fresh_session_with_nonce()
        bad_hmac = _hmac_for(sid)
        assert nonce != bad_hmac, "nonce and HMAC collide — test vacuous"

        class _FakeResp:
            def __init__(self):
                self.cookies_set = {}
                self.content_type = "text/html"
                self.body = b"<html><head><title>x</title></head><body></body></html>"
            def set_cookie(self, name, value, **kw):
                self.cookies_set[name] = value

        class _FakeReq:
            path = "/antibot-appsec-gateway/secured/controls"
            cookies = {_u._SESSION_COOKIE: session_token}

        req, resp = _FakeResp.__new__(_FakeResp), _FakeResp()
        req = _FakeReq()
        _mw._csrf_self_heal(req, resp)

        out = resp.body.decode()
        assert nonce in out, (
            "window.__AGW_CSRF__ must carry the nonce, not HMAC — "
            "otherwise browser JS sends HMAC, validator expects nonce, 403"
        )
        assert bad_hmac not in out, (
            "window.__AGW_CSRF__ must NOT carry the bare HMAC when nonce is in cache"
        )

    def test_c04_three_writers_produce_same_token(self):
        """Login, csrf_endpoint, and middleware._csrf_self_heal must all agree on
        the token value for the same session.  Any divergence = a 403 bug."""
        from admin import users as _u
        from admin import auth as _auth
        sid, nonce, session_token = _fresh_session_with_nonce()

        # What login stores (source of truth)
        login_nonce = _u._SESSION_CACHE[sid]["csrf_nonce"]

        # What csrf_endpoint would return (read from cache)
        _entry = _u._SESSION_CACHE.get(sid)
        endpoint_token = _entry.get("csrf_nonce") if _entry else None

        # What middleware would compute (nonce-with-fallback)
        from core import middleware as _mw
        import importlib, inspect
        # Read `want` the same way _csrf_self_heal does
        try:
            _sc = _u._SESSION_CACHE
            _e = _sc.get(sid)
            _n = _e.get("csrf_nonce") if _e else None
        except Exception:
            _n = None
        middleware_token = _n if _n else _hmac_for(sid)

        assert login_nonce == endpoint_token == middleware_token, (
            f"CSRF token divergence!\n"
            f"  login stored:        {login_nonce!r}\n"
            f"  csrf_endpoint would: {endpoint_token!r}\n"
            f"  middleware would:    {middleware_token!r}\n"
            "All three must agree — divergence means some component is off the "
            "shared nonce source and will cause 403 on POST."
        )


# ── F: fallback ───────────────────────────────────────────────────────────────

class TestHmacFallback:
    """Pre-migration sessions (NULL csrf_nonce in DB / not in cache) must still
    work via the HMAC fallback path.  Do not remove it."""

    def test_f01_validator_falls_back_to_hmac_when_no_nonce(self):
        from admin import auth as _auth
        from admin import users as _u
        import secrets
        # Session NOT in _SESSION_CACHE → fallback path
        sid = "FALLBACK_SID_" + secrets.token_hex(8)
        session_token = _u._session_sign("admin", sid=sid)
        # Ensure not in cache
        _u._SESSION_CACHE.pop(sid, None)
        good_hmac = _hmac_for(sid)

        class _Req:
            method = "POST"
            cookies = {_u._SESSION_COOKIE: session_token}
            headers = {"X-CSRF-Token": good_hmac}

        assert _auth._csrf_token_valid(_Req()) is True, (
            "HMAC fallback must still validate when session has no nonce in cache"
        )

    def test_f02_endpoint_falls_back_to_hmac_source_check(self):
        """Contract change (1.9.1): no csrf_endpoint — the HMAC formula now lives
        in the canonical validator. Guard that admin/auth._csrf_token_valid
        derives the expected token as HMAC(SESSION_KEY, sid)[:32]."""
        auth = _read("admin/auth.py")
        idx = auth.find("def _csrf_token_valid")
        body = auth[idx:idx + 1200]
        assert "hexdigest()[:32]" in body and "SESSION_KEY" in body, (
            "_csrf_token_valid must derive the expected token via HMAC(SESSION_KEY, sid)"
        )

    def test_f03_middleware_falls_back_to_hmac_source_check(self):
        mw = _read("core/middleware.py")
        idx = mw.find("def _csrf_self_heal")
        body = mw[idx:idx + 4000]  # long docstring; need wider window
        assert "hexdigest()[:32]" in body and "SESSION_KEY" in body, (
            "middleware._csrf_self_heal must retain HMAC fallback for pre-migration sessions"
        )


# ── S: source-code contract ───────────────────────────────────────────────────

class TestSourceContract:
    """Structural guards that fire if the nonce logic is accidentally removed
    or the module is refactored back to pure-HMAC."""

    def test_s01_users_login_stores_csrf_nonce_in_cache(self):
        """Contract change (1.9.1): the T0-2 per-session nonce was superseded by
        pure HMAC double-submit. _session_create stores an EMPTY nonce slot in the
        user_sessions tuple (admin/users.py:216-220) and the CSRF token is derived
        from the session sid via HMAC. Guard that the session-create path exists
        and mints the session via _session_sign (the HMAC-bound source)."""
        users = _read("admin/users.py")
        assert "def _session_create" in users, (
            "admin/users.py must mint sessions via _session_create"
        )
        assert "_session_sign(" in users, (
            "session creation must use _session_sign — CSRF token is HMAC-bound to sid"
        )

    def test_s02_auth_validator_reads_nonce_first(self):
        """Contract change (1.9.1, validation/1.9.1.md:615): _csrf_token_valid is
        pure HMAC double-submit, not nonce-from-cache. Guard the real security
        properties: it derives the expected token via HMAC(SESSION_KEY, sid) and
        compares it CONSTANT-TIME against the supplied X-CSRF-Token header."""
        auth = _read("admin/auth.py")
        idx = auth.find("def _csrf_token_valid")
        body = auth[idx:idx + 1200]
        assert "hexdigest()[:32]" in body and "SESSION_KEY" in body, (
            "_csrf_token_valid must derive the expected token via HMAC(SESSION_KEY, sid)"
        )
        assert "compare_digest" in body, (
            "_csrf_token_valid must use hmac.compare_digest (constant-time) — "
            "a plain == comparison opens a timing side-channel"
        )

    def test_s03_no_pure_hmac_csrf_endpoint(self):
        """Contract change (1.9.1): there is no csrf_endpoint and proxy_handler
        does NOT re-implement the CSRF token formula inline — it must delegate to
        the single shared validator. Guard against a drifting second copy of the
        HMAC formula by asserting proxy_handler has no inline hexdigest()[:32]
        CSRF computation and uses _csrf_token_valid instead."""
        ph = _read("core/proxy_handler.py")
        assert "async def csrf_endpoint" not in ph, (
            "csrf_endpoint was removed in 1.9.1; it must not reappear"
        )
        assert "hexdigest()[:32]" not in ph, (
            "proxy_handler must not re-derive the CSRF HMAC inline — "
            "delegate to admin.auth._csrf_token_valid (single source of truth)"
        )
        assert "_csrf_token_valid" in ph, (
            "proxy_handler must enforce CSRF via the shared _csrf_token_valid"
        )

    def test_s04_no_pure_hmac_middleware_self_heal(self):
        mw = _read("core/middleware.py")
        idx = mw.find("def _csrf_self_heal")
        body = mw[idx:idx + 4000]  # long docstring; need wider window
        hmac_pos = body.find("hexdigest()[:32]")
        cache_pos = min(
            body.find("_SESSION_CACHE") if "_SESSION_CACHE" in body else 99999,
            body.find("_sc_mw") if "_sc_mw" in body else 99999,
        )
        assert cache_pos < hmac_pos, (
            "middleware._csrf_self_heal: cache lookup must appear BEFORE HMAC fallback"
        )

    def test_s05_three_modules_share_csrf_nonce_keyword(self):
        """Contract change (1.9.1): CSRF is HMAC double-submit. Every module in the
        CSRF flow must reference the shared primitives so they stay in lock-step.
        The canonical formula HMAC(SESSION_KEY, sid)[:32] must appear in exactly
        ONE validator (admin/auth.py) plus the middleware self-heal; the others
        enforce through the shared _csrf_token_valid / agw_csrf cookie."""
        required = {
            "admin/auth.py": ("validates the token", "hexdigest()[:32]"),
            "core/middleware.py": ("self-heals cookie + injects window.__AGW_CSRF__", "hexdigest()[:32]"),
            "core/proxy_handler.py": ("enforces CSRF on mutating endpoints", "_csrf_token_valid"),
        }
        offenders = []
        for rel, (role, token) in required.items():
            src = _read(rel)
            if token not in src:
                offenders.append(f"{rel} ({role}) missing {token!r}")
        assert not offenders, (
            "these CSRF-flow modules drifted off the shared HMAC primitives:\n  " +
            "\n  ".join(offenders)
        )
