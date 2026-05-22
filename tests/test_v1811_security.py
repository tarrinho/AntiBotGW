"""
tests/test_v1811_security.py — QA for the 1.8.11 security release.

Covers the priority findings fixed in 1.8.11:
  H1  WAF body-scan window (no 64 KiB padding bypass)
  H2  Central CSRF gate in protect()
  H3  honey-cred bans the requester (not the victim) + is rate-limited
  M1  agw_csrf cookie scoped to the admin namespace (off the upstream surface)
  M2  ALLOW_PRIVATE_UPSTREAM defaults OFF (SSRF guard on)
  M3  OIDC id_token signature verification (JWKS / RS256; reject none/forged/etc.)
  M4  PoW minimum-solve-time floor is non-zero + token is single-use
  M7  session source_ip / last-seen restored on cache reload (BIND_SESSION_TO_IP)
"""
import asyncio
import inspect
import json
import os
import sqlite3
import time

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")
os.environ.setdefault("ADMIN_KEY", "x" * 16)

import config                                   # noqa: E402
from core import proxy_handler                  # noqa: E402
from challenge import pow as powmod             # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# H1 — WAF body-scan window
# ─────────────────────────────────────────────────────────────────────────────

class TestH1WafBodyWindow:
    def test_scan_window_covers_full_accepted_body(self):
        """WAF_BODY_SCAN_BYTES must be >= the body we accept+forward, else a
        payload past the scan window bypasses the WAF."""
        assert config.WAF_BODY_SCAN_BYTES >= proxy_handler.UPSTREAM_MAX_BODY

    def test_sqli_past_64kib_padding_is_detected(self):
        """A SQLi payload hidden behind 64 KiB of padding must still match —
        the old code only scanned body[:65536]."""
        saved = (config.BODY_PATTERN_MATCH, config.BODY_GROUP_SQLI_ENABLED)
        config.BODY_PATTERN_MATCH = True
        config.BODY_GROUP_SQLI_ENABLED = True
        try:
            body = b"q=" + b"A" * 70000 + b"+UNION+SELECT+password+FROM+users--"
            grp = config.match_body_group(body, "application/x-www-form-urlencoded")
            assert grp == "sqli", f"SQLi past padding must be detected, got {grp!r}"
        finally:
            config.BODY_PATTERN_MATCH, config.BODY_GROUP_SQLI_ENABLED = saved

    def test_inspectors_use_scan_window_constant(self):
        """No body inspector may keep the hardcoded 64 KiB cap."""
        src = inspect.getsource(config)
        assert "body[:65536]" not in src, "hardcoded 64 KiB body cap still present"
        assert "WAF_BODY_SCAN_BYTES" in src


# ─────────────────────────────────────────────────────────────────────────────
# H2 — central CSRF gate
# ─────────────────────────────────────────────────────────────────────────────

class TestH2CentralCsrf:
    def test_protect_enforces_csrf_in_authed_branch(self):
        """protect() must validate CSRF for non-safe methods in the
        authenticated-admin branch, so coverage can't drift per-handler."""
        src = inspect.getsource(proxy_handler.protect)
        i = src.find("_admin_ip_allowed(request) and _internal_authed(request)")
        assert i != -1
        block = src[i:i + 1600]
        assert "_csrf_token_valid" in block, (
            "protect() must call _csrf_token_valid in the authed-admin branch"
        )
        assert 'method not in ("GET", "HEAD", "OPTIONS")' in block

    def test_csrf_token_valid_accepts_correct_rejects_wrong(self):
        from admin.auth import _csrf_token_valid
        from admin import users as u
        import hmac as _h, hashlib as _hh

        class _Req:
            def __init__(self, method, cookie, token):
                self.method = method
                self.cookies = {u._SESSION_COOKIE: cookie} if cookie else {}
                self.headers = {"X-CSRF-Token": token} if token is not None else {}

        sid = "SID_test_abc0123456789XY"
        cookie = u._session_sign("admin", sid=sid)
        good = _h.new(config.SESSION_KEY, sid.encode(), _hh.sha256).hexdigest()[:32]
        assert _csrf_token_valid(_Req("POST", cookie, good)) is True
        assert _csrf_token_valid(_Req("POST", cookie, "deadbeef")) is False
        assert _csrf_token_valid(_Req("POST", cookie, None)) is False
        # Safe methods are always exempt.
        assert _csrf_token_valid(_Req("GET", cookie, None)) is True


# ─────────────────────────────────────────────────────────────────────────────
# H3 — honey-cred bans the requester, not the victim, and is rate-limited
# ─────────────────────────────────────────────────────────────────────────────

class TestH3HoneyCred:
    def test_honey_probe_is_rate_limited_and_targets_requester(self):
        src = inspect.getsource(proxy_handler.honey_probe_endpoint)
        assert "_probe_rate_limit_ok" in src, "honey probe must be rate-limited"
        # Ban must use the requester's identity, never the issued-for identity.
        assert 'request.get("_track_key")' in src or "get_identity(request)" in src, (
            "honey probe must ban the requester's own identity"
        )
        assert "update_risk_and_maybe_ban(honey_identity" not in src, (
            "honey probe must NOT ban the issued-for (victim) identity"
        )


# ─────────────────────────────────────────────────────────────────────────────
# M1 — agw_csrf cookie scoped to the admin namespace
# ─────────────────────────────────────────────────────────────────────────────

class TestM1CsrfCookieScope:
    def test_no_agw_csrf_cookie_set_at_root_path(self):
        """Every agw_csrf set/delete must be path=ADMIN_NS, never path='/',
        so the readable token never reaches the proxied upstream."""
        from core import middleware
        from admin import users, oidc
        for mod in (middleware, proxy_handler, users, oidc):
            src = inspect.getsource(mod)
            # crude but effective: no agw_csrf line should carry path="/"
            for line in src.splitlines():
                if "agw_csrf" in line and "path=" in line:
                    assert 'path="/"' not in line, (
                        f"{mod.__name__}: agw_csrf cookie must not use path='/': {line.strip()}"
                    )

    def test_self_heal_scopes_cookie_to_admin_ns(self):
        from core import middleware
        src = inspect.getsource(middleware._csrf_self_heal)
        assert "ADMIN_NS" in src
        assert "startswith(ADMIN_NS)" in src, (
            "_csrf_self_heal must early-return for non-admin paths"
        )


# ─────────────────────────────────────────────────────────────────────────────
# M2 — ALLOW_PRIVATE_UPSTREAM defaults OFF
# ─────────────────────────────────────────────────────────────────────────────

class TestM2PrivateUpstreamDefault:
    def test_default_is_off(self):
        src = inspect.getsource(config)
        assert 'os.environ.get("ALLOW_PRIVATE_UPSTREAM", "0")' in src, (
            "ALLOW_PRIVATE_UPSTREAM must default to '0' (SSRF guard on)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# M3 — OIDC id_token signature verification
# ─────────────────────────────────────────────────────────────────────────────

class TestM3OidcIdTokenVerify:
    @staticmethod
    def _setup():
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from admin import oidc

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": "testkid", "alg": "RS256", "use": "sig"})
        jwks = {"keys": [jwk]}

        oidc.OIDC_ISSUER = "https://idp.example.com/realms/test"
        oidc.OIDC_CLIENT_ID = "gw-client"

        async def _fake_fetch(http, *, force=False):
            return jwks
        oidc._fetch_jwks = _fake_fetch

        def make(alg="RS256", signing_key=None, headers=None, **claim_over):
            claims = {
                "iss": oidc.OIDC_ISSUER, "aud": oidc.OIDC_CLIENT_ID,
                "nonce": "NONCE123", "sub": "user-1",
                "exp": int(time.time()) + 300, "iat": int(time.time()),
            }
            claims.update(claim_over)
            hdr = {"kid": "testkid"}
            hdr.update(headers or {})
            if alg == "none":
                return jwt.encode(claims, None, algorithm="none", headers=hdr)
            return jwt.encode(claims, signing_key or key, algorithm=alg, headers=hdr)

        return oidc, key, make

    def _verify(self, oidc, token, nonce="NONCE123"):
        return asyncio.run(oidc._verify_id_token(None, token, nonce))

    def test_valid_token_passes(self):
        oidc, key, make = self._setup()
        claims = self._verify(oidc, make())
        assert claims["sub"] == "user-1"

    def test_none_alg_rejected(self):
        oidc, key, make = self._setup()
        with pytest.raises(Exception):
            self._verify(oidc, make(alg="none"))

    def test_wrong_signature_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        oidc, key, make = self._setup()
        attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with pytest.raises(Exception):
            self._verify(oidc, make(signing_key=attacker))

    def test_wrong_audience_rejected(self):
        oidc, key, make = self._setup()
        with pytest.raises(Exception):
            self._verify(oidc, make(aud="some-other-client"))

    def test_wrong_issuer_rejected(self):
        oidc, key, make = self._setup()
        with pytest.raises(Exception):
            self._verify(oidc, make(iss="https://evil.example.com/realms/test"))

    def test_nonce_mismatch_rejected(self):
        oidc, key, make = self._setup()
        with pytest.raises(Exception):
            self._verify(oidc, make(nonce="WRONG"))

    def test_expired_token_rejected(self):
        oidc, key, make = self._setup()
        with pytest.raises(Exception):
            self._verify(oidc, make(exp=int(time.time()) - 10, iat=int(time.time()) - 320))


# ─────────────────────────────────────────────────────────────────────────────
# M4 — PoW minimum-solve-time floor + single-use token
# ─────────────────────────────────────────────────────────────────────────────

class TestM4Pow:
    def test_solution_below_floor_rejected(self, monkeypatch):
        """A solution arriving faster than the (non-zero) floor must be rejected.
        Deterministic via patched clock — the old code collapsed the floor to 0,
        so this never fired at the default POW_MIN_SOLVE_MS=200."""
        t0 = 1_000_000.0
        monkeypatch.setattr(powmod.time, "time", lambda: t0)
        token = powmod.make_pow_challenge(method="POST", path="/x")   # issued=int(t0)
        # verify 50 ms later → below the 150 ms floor → rejected before the hash check
        monkeypatch.setattr(powmod.time, "time", lambda: t0 + 0.05)
        ok, reason = powmod.verify_pow(token, "anything", method="POST", path="/x")
        assert ok is False and "too quickly" in reason, reason

    def test_floor_is_non_zero_at_default(self):
        # floor = max(0, MIN - min(250, MIN*0.25)); for 200 → 150ms (not 0).
        assert config.POW_MIN_SOLVE_MS == 200
        drift = min(250.0, config.POW_MIN_SOLVE_MS * 0.25)
        assert config.POW_MIN_SOLVE_MS - drift > 0

    def test_replay_keyed_on_token(self):
        src = inspect.getsource(powmod.verify_pow)
        assert "_pow_seen[token]" in src, "replay store must record the token"
        assert "pair_key = (token, solution)" not in src, (
            "replay store must be keyed on the token alone (single-use), "
            "not (token, solution)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# M7 — session source_ip / last-seen restored on cache reload
# ─────────────────────────────────────────────────────────────────────────────

class TestM7SessionCacheRestore:
    def test_cache_load_restores_ip_and_last_touch(self, tmp_path, monkeypatch):
        from admin import users
        db = str(tmp_path / "sess.db")
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE user_sessions (sid TEXT PRIMARY KEY, username TEXT, "
            "ip TEXT, user_agent TEXT, created_ts REAL, last_seen_ts REAL, "
            "expires_ts REAL, status TEXT, revoked_ts REAL, revoked_by TEXT)"
        )
        now = time.time()
        conn.execute(
            "INSERT INTO user_sessions VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("sid1", "admin", "203.0.113.9", "ua", now, now - 5,
             now + 3600, "active", None, None),
        )
        conn.commit(); conn.close()

        monkeypatch.setattr(users, "DB_PATH", db)
        users._SESSION_CACHE.clear()
        users._session_cache_load()
        entry = users._SESSION_CACHE.get("sid1")
        assert entry is not None, "session not loaded"
        assert entry.get("source_ip") == "203.0.113.9", (
            "source_ip must be restored so BIND_SESSION_TO_IP survives restart"
        )
        assert entry.get("_last_touch") == pytest.approx(now - 5, abs=1), (
            "_last_touch must be restored so idle-timeout survives restart"
        )
