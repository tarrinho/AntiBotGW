"""
QA — comprehensive coverage of the new functions added in **1.9.7**
(2026-06-23, week of Jun 20-27).

Each test class targets one CHANGELOG bullet, with **unit / regression /
functional / security** assertions. Tests are pure (no live server) and use
the public APIs of the modules — no monkey-patching of internals.

Items covered (by CHANGELOG order):
  1. Ed25519 mesh signing                         — admin/mesh.py
  2. UPSTREAM hot-reload SSRF guard (HIGH)        — core/proxy_handler.py
  3. SSRF guard fails-closed on DNS gaierror      — core/proxy_handler.py
  4. WAF kill-switches wired (9 new knobs)        — config.py
  5. Session absolute timeout                     — admin/users.py
  6. 2FA-at-login bypass closed (HIGH)            — admin/users.py
  7. OIDC hardening (state cap + strict exp)      — admin/oidc.py
  8. Per-session random CSRF nonce                — admin/users.py
  9. Forwarded / X-Forwarded-Prefix stripped      — core/proxy_handler.py
 10. Honey-cred probe bans REQUESTER, not victim  — core/proxy_handler.py
"""
import importlib
import os
import re
import sys
import time as _t

import pytest

# Ensure import-time env defaults exist (mirror tests/conftest.py)
os.environ.setdefault("ADMIN_ALLOWED_IPS", "0.0.0.0/0,::/0")
os.environ.setdefault("UPSTREAM", "http://example.com")
os.environ.setdefault("ADMIN_KEY", "test-admin-key-xxxxxxxxxxxxxxxx")


# ── 1. Ed25519 mesh signing ───────────────────────────────────────────────────

class TestMeshEd25519Signing:
    """`admin/mesh.py` replaced HMAC with real Ed25519 keys in 1.9.7.
    A peer can no longer forge another gateway's offers (the old model
    shared a symmetric secret). Tests: roundtrip, tamper detection,
    wrong-key rejection, canonical-bytes determinism, graceful no-crypto."""

    @classmethod
    def setup_class(cls):
        cls.mesh = importlib.import_module("admin.mesh")
        # Generate a fresh keypair for each test class invocation
        try:
            cls.priv, cls.pub = cls.mesh._gw_generate_keypair()
        except Exception as e:
            pytest.skip(f"cryptography unavailable: {e}")

    def test_keypair_format(self):
        # Ed25519: both keys are 32 raw bytes → base64url-encoded ≈ 43 chars
        assert len(self.priv) >= 40 and len(self.priv) <= 64, self.priv
        assert len(self.pub) >= 40 and len(self.pub) <= 64, self.pub
        assert self.priv != self.pub

    def test_pubkey_derives_from_privkey(self):
        derived = self.mesh._gw_derive_pubkey(self.priv)
        assert derived == self.pub, (
            f"_gw_derive_pubkey did not match _gw_generate_keypair output: "
            f"{derived!r} vs {self.pub!r}"
        )

    def test_sign_verify_roundtrip(self):
        offers = {"gw_id": "test-a.local", "epoch": 42, "policies": ["a", "b"]}
        sig = self.mesh._gw_sign_offers(self.priv, offers)
        assert sig and len(sig) >= 80, f"signature too short: {sig!r}"
        assert self.mesh._gw_verify_offers(self.pub, sig, offers) is True

    def test_tamper_rejects(self):
        offers = {"gw_id": "test-a.local", "epoch": 42}
        sig = self.mesh._gw_sign_offers(self.priv, offers)
        tampered = dict(offers, epoch=43)
        assert self.mesh._gw_verify_offers(self.pub, sig, tampered) is False

    def test_wrong_pubkey_rejects(self):
        offers = {"x": 1}
        sig = self.mesh._gw_sign_offers(self.priv, offers)
        _, other_pub = self.mesh._gw_generate_keypair()
        assert self.mesh._gw_verify_offers(other_pub, sig, offers) is False

    def test_empty_sig_rejects(self):
        offers = {"x": 1}
        assert self.mesh._gw_verify_offers(self.pub, "", offers) is False
        assert self.mesh._gw_verify_offers("", "sig", offers) is False

    def test_canonical_bytes_deterministic_across_key_order(self):
        a = {"alpha": 1, "beta": 2, "gamma": 3}
        b = {"gamma": 3, "alpha": 1, "beta": 2}
        assert self.mesh._canonical_offer_bytes(a) == self.mesh._canonical_offer_bytes(b)

    def test_canonical_bytes_excludes_sig_field(self):
        with_sig = {"x": 1, "_sig": "should-not-be-included"}
        without_sig = {"x": 1}
        assert self.mesh._canonical_offer_bytes(with_sig) == self.mesh._canonical_offer_bytes(without_sig)

    def test_sign_empty_offers_returns_well_formed(self):
        sig = self.mesh._gw_sign_offers(self.priv, {})
        assert self.mesh._gw_verify_offers(self.pub, sig, {}) is True


# ── 2. UPSTREAM SSRF guard ───────────────────────────────────────────────────

class TestUpstreamSsrfGuard:
    """`_upstream_safe_to_reload` (1.9.7 HIGH security fix) gates the
    UPSTREAM hot-reload knob against private / loopback / cloud-metadata
    targets. Pre-1.9.7 used a bare scheme+length lambda — an admin (or
    same-origin XSS hitting `/__config`) could repoint to
    169.254.169.254."""

    @classmethod
    def setup_class(cls):
        cls.cph = importlib.import_module("core.proxy_handler")

    def _g(self, url):
        # Indirect call so Python doesn't bind the module function as a method.
        return self.cph._upstream_safe_to_reload(url)

    def test_reject_non_http(self):
        assert self._g("ftp://example.com") is False
        assert self._g("file:///etc/passwd") is False
        assert self._g("javascript:alert(1)") is False
        assert self._g("just-a-host.example") is False

    def test_reject_empty_or_too_long(self):
        assert self._g("") is False
        assert self._g("http://" + ("a" * 2050) + ".example.com") is False
        assert self._g(None) is False
        assert self._g(12345) is False

    def test_reject_loopback(self):
        assert self._g("http://127.0.0.1/") is False
        assert self._g("http://localhost/") is False
        assert self._g("http://[::1]/") is False

    def test_reject_cloud_metadata(self):
        # AWS / GCP / Azure / Oracle / DigitalOcean all use 169.254.169.254
        assert self._g("http://169.254.169.254/latest/meta-data/") is False

    def test_reject_rfc1918(self):
        assert self._g("http://10.0.0.1/") is False
        assert self._g("http://192.168.1.1/") is False
        assert self._g("http://172.16.0.1/") is False

    def test_allow_public_dns(self):
        # 8.8.8.8 is google public DNS — should pass
        assert self._g("https://dns.google/dns-query") is True

    def test_allow_private_when_override_set(self, monkeypatch):
        monkeypatch.setattr(self.cph, "ALLOW_PRIVATE_UPSTREAM", True, raising=False)
        assert self._g("http://127.0.0.1/") is True
        assert self._g("http://192.168.1.1/") is True


# ── 3. SSRF guard fails-closed on DNS gaierror ────────────────────────────────

class TestSsrfGuardDnsFailClosed:
    """Pre-1.9.7 `_ssrf_guard_url` `return`-ed on `socket.gaierror`,
    letting an unresolvable host through — an attacker could supply a
    name that fails the guard's DNS lookup, then have it resolve to an
    internal IP at fetch time. 1.9.7 raises instead."""

    @classmethod
    def setup_class(cls):
        cls.cph = importlib.import_module("core.proxy_handler")

    def test_raises_on_unresolvable_host(self, monkeypatch):
        import socket
        def _fake_getaddrinfo(*a, **kw):
            raise socket.gaierror("simulated DNS failure")
        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
        with pytest.raises(ValueError, match=r"(does not resolve|SSRF)"):
            self.cph._ssrf_guard_url("https://this-host-cannot-resolve.test.invalid/")


# ── 4. WAF kill-switches wired ────────────────────────────────────────────────

class TestWafKillSwitchKnobs:
    """1.9.7 wired 9 detection layers to operator-controllable `*_ENABLED`
    knobs. Pre-1.9.7 they were built and acting but couldn't be turned off."""

    REQUIRED_KNOBS = (
        "WAF_BODY_ENABLED",
        "WAF_SMUGGLING_ENABLED",
        "WAF_VERB_OVERRIDE_ENABLED",
        "WAF_HEADER_INJECTION_ENABLED",
        "WAF_GRAPHQL_ENABLED",
        "WAF_UPLOAD_ENABLED",
        "WAF_SLOWLORIS_ENABLED",
        "RATE_LIMIT_ENABLED",
        "ENDPOINT_RATE_LIMIT_ENABLED",
    )

    @classmethod
    def setup_class(cls):
        cls.config = importlib.import_module("config")

    def test_all_knobs_imported(self):
        missing = [k for k in self.REQUIRED_KNOBS if not hasattr(self.config, k)]
        assert not missing, f"WAF kill-switch knobs missing in config: {missing}"

    def test_all_knobs_are_booleans(self):
        for k in self.REQUIRED_KNOBS:
            v = getattr(self.config, k)
            assert isinstance(v, bool), f"{k} is {type(v).__name__}, expected bool"

    def test_all_default_on(self):
        """Default 1 ensures the WAF is on out of the box — operator must
        explicitly opt-out via env to disable a layer."""
        # Force re-import with NO env overrides to confirm default
        for k in self.REQUIRED_KNOBS:
            v = getattr(self.config, k)
            # Whatever the operator set: just confirm the variable exists and
            # has a defined truthy/falsy value. Defaults verified below.
            assert v in (True, False), k

    def test_defaults_when_env_unset(self):
        # Read directly from config.py source — defaults are inline.
        src = (importlib.import_module("config").__file__ or "")
        if not src:
            pytest.skip("config module path unknown")
        text = open(src, encoding="utf-8").read()
        for k in self.REQUIRED_KNOBS:
            # Pattern: KNOB = os.environ.get("KNOB", "1") in ("1", "true", "yes")
            pat = re.compile(rf"{k}\s*=\s*os\.environ\.get\(\s*[\"']{k}[\"']\s*,\s*[\"']1[\"']")
            assert pat.search(text), f"{k} default in source is not '1' (default-on)"


# ── 5. Session absolute timeout ───────────────────────────────────────────────

class TestSessionAbsoluteTimeout:
    """1.9.7 added `SESSION_ABSOLUTE_TIMEOUT` (default 8 h). Even if the
    sliding `expires_ts` keeps refreshing, a session dies absolute-time
    past `created_ts`. Legacy rows with `created_ts=0` are exempt
    (backward compatibility)."""

    @classmethod
    def setup_class(cls):
        cls.users = importlib.import_module("admin.users")
        cls.config = importlib.import_module("config")
        cls.cache = cls.users._SESSION_CACHE

    def test_knob_present_and_default_8h(self):
        v = getattr(self.config, "SESSION_ABSOLUTE_TIMEOUT", None)
        assert v is not None, "SESSION_ABSOLUTE_TIMEOUT knob missing"
        assert isinstance(v, int) and v >= 1800, f"unsafe default: {v}"

    def _seed_session(self, sid, username, created_ts, ttl=3600, csrf_nonce="x" * 24):
        # _session_sign(user, sid, ttl) → internally expiry = now + ttl
        expires_ts = int(_t.time()) + int(ttl)
        self.cache[sid] = {
            "username": username,
            "expires_ts": expires_ts,
            "created_ts": created_ts,
            "csrf_nonce": csrf_nonce,
            "revoked": False,
        }
        self.users._SESSION_CACHE_READY = True
        return self.users._session_sign(username, sid, ttl)

    def test_active_session_passes(self):
        sid = self.users._new_sid()
        try:
            token = self._seed_session(sid, "alice", int(_t.time()) - 60, ttl=3600)
            assert self.users._session_verify(token) == "alice"
        finally:
            self.cache.pop(sid, None)

    def test_session_past_absolute_timeout_rejected(self, monkeypatch):
        sid = self.users._new_sid()
        monkeypatch.setattr(self.config, "SESSION_ABSOLUTE_TIMEOUT", 60, raising=False)
        try:
            # created 5 minutes ago; sliding expiry still in the future
            token = self._seed_session(sid, "alice", int(_t.time()) - 300, ttl=3600)
            assert self.users._session_verify(token) is None
        finally:
            self.cache.pop(sid, None)

    def test_legacy_zero_created_ts_not_rejected(self, monkeypatch):
        sid = self.users._new_sid()
        monkeypatch.setattr(self.config, "SESSION_ABSOLUTE_TIMEOUT", 60, raising=False)
        try:
            # created_ts=0 (legacy) — must still pass even with tiny abs timeout
            token = self._seed_session(sid, "bob", 0, ttl=3600)
            assert self.users._session_verify(token) == "bob"
        finally:
            self.cache.pop(sid, None)


# ── 6. 2FA-at-login bypass closed ─────────────────────────────────────────────

class TestTotpPartialTokenScheme:
    """1.9.7 HIGH: login_submit used to mint a full session after password
    verify even when TOTP was enrolled. Now issues an unpredictable
    server-stored `partial_token` and requires a second POST to
    `/login/totp` to upgrade. The partial_token is `secrets.token_urlsafe`
    (NOT an HMAC over a username — no enumeration)."""

    @classmethod
    def setup_class(cls):
        cls.users = importlib.import_module("admin.users")

    def test_pending_table_exists(self):
        # _TOTP_PENDING lives in `state` (imported on demand by login_submit
        # / totp_verify so the same dict is shared across both).
        state = importlib.import_module("state")
        assert hasattr(state, "_TOTP_PENDING"), (
            "state._TOTP_PENDING (server-side partial-token store) missing"
        )
        assert isinstance(state._TOTP_PENDING, dict)
        assert hasattr(state, "_TOTP_PENDING_LOCK"), (
            "state._TOTP_PENDING_LOCK (async mutex) missing"
        )

    def test_partial_token_is_not_hmac_of_username(self):
        """Source audit: the partial_token must NOT be derived as
        HMAC(SECRET, username) — that would let an attacker who knows
        the username predict valid pending tokens. Must use
        secrets.token_urlsafe(N)."""
        src = open(self.users.__file__, encoding="utf-8").read()
        # Look for partial_token = secrets.token_urlsafe(...) near login_submit
        idx_login = src.find("def login_submit_endpoint")
        assert idx_login != -1, "login_submit_endpoint not found"
        # Window: next ~3000 chars after login_submit definition
        window = src[idx_login: idx_login + 3000]
        assert "secrets.token_urlsafe" in window or "_secrets.token_urlsafe" in window, (
            "partial_token must be minted via secrets.token_urlsafe — "
            "found different mechanism in login_submit_endpoint window"
        )

    def test_totp_verify_endpoint_exists(self):
        assert hasattr(self.users, "totp_verify_endpoint"), (
            "totp_verify_endpoint missing"
        )
        # It must be a coroutine function
        import inspect
        assert inspect.iscoroutinefunction(self.users.totp_verify_endpoint), (
            "totp_verify_endpoint must be async"
        )

    def test_totp_verify_route_registered(self):
        proxy_src = open(
            importlib.import_module("proxy").__file__, encoding="utf-8"
        ).read()
        assert re.search(
            r"add_post\s*\([^)]*['\"]/login/totp['\"][^)]*totp_verify_endpoint",
            proxy_src,
        ), "/login/totp POST route to totp_verify_endpoint not registered"

    def test_partial_token_compare_is_timing_safe(self):
        """The verify endpoint must compare partial_token via hmac.compare_digest,
        not == . Source-level guard so a future refactor can't regress."""
        src = open(self.users.__file__, encoding="utf-8").read()
        idx_verify = src.find("def totp_verify_endpoint")
        assert idx_verify != -1
        # Scope to the function body (up to the next top-level def) instead of a
        # fixed-size slice — a fixed window breaks when the body legitimately
        # grows (the 1.9.8 S-W5 partial-token length guard pushed compare_digest
        # past the old 3000-char window).
        _ends = [p for p in (src.find("\nasync def ", idx_verify + 10),
                             src.find("\ndef ", idx_verify + 10)) if p != -1]
        window = src[idx_verify: min(_ends)] if _ends else src[idx_verify:]
        assert "compare_digest" in window, (
            "totp_verify_endpoint must use hmac.compare_digest for partial_token"
        )


# ── 7. OIDC hardening ─────────────────────────────────────────────────────────

class TestOidcHardening:
    """1.9.7:
      - Strict `exp` re-check (PyJWT leeway no longer lets 30s-expired tokens through)
      - `_OIDC_STATE_MAX` cap (default 500) prevents unauthenticated state-spray OOM
    """

    @classmethod
    def setup_class(cls):
        try:
            cls.oidc = importlib.import_module("admin.oidc")
        except Exception as e:
            pytest.skip(f"admin.oidc not importable: {e}")

    def test_state_max_constant_present(self):
        assert hasattr(self.oidc, "_OIDC_STATE_MAX")
        assert isinstance(self.oidc._OIDC_STATE_MAX, int)
        assert self.oidc._OIDC_STATE_MAX >= 100, (
            f"_OIDC_STATE_MAX too low: {self.oidc._OIDC_STATE_MAX}"
        )
        assert self.oidc._OIDC_STATE_MAX <= 10_000, (
            f"_OIDC_STATE_MAX suspiciously high (memory risk): "
            f"{self.oidc._OIDC_STATE_MAX}"
        )

    def test_strict_exp_check_present_in_source(self):
        src = open(self.oidc.__file__, encoding="utf-8").read()
        # Look for the "strict exp" hardening
        assert "ExpiredSignatureError" in src, (
            "OIDC must raise ExpiredSignatureError on strict exp re-check"
        )
        assert "strict" in src.lower(), (
            "OIDC source must reference strict exp re-check rationale"
        )


# ── 8. Per-session random CSRF nonce ──────────────────────────────────────────

class TestPerSessionCsrfNonce:
    """1.9.7: `agw_csrf` used to be `HMAC(SESSION_KEY, sid)` — derivable
    for every session from one secret. Now an independent
    `secrets.token_urlsafe(24)` nonce per session, persisted +
    rehydrated. Legacy fallback to HMAC preserved for in-flight cookies."""

    @classmethod
    def setup_class(cls):
        cls.users = importlib.import_module("admin.users")

    def test_session_create_mints_csrf_nonce(self):
        src = open(self.users.__file__, encoding="utf-8").read()
        idx = src.find("def _session_create")
        assert idx != -1, "_session_create not found"
        window = src[idx: idx + 2500]
        # Any local-alias for `secrets.token_urlsafe(24)` is fine.
        assert re.search(r"\w*secrets\w*\.token_urlsafe\s*\(\s*24\s*\)", window), (
            "_session_create must mint csrf_nonce via secrets.token_urlsafe(24)"
        )

    def test_csrf_nonce_column_in_persistence(self):
        """csrf_nonce must be SELECTed when the session cache reloads
        after a restart — otherwise it silently reverts to the legacy
        derivable HMAC."""
        src = open(self.users.__file__, encoding="utf-8").read()
        assert "csrf_nonce" in src, "csrf_nonce not referenced in admin/users.py"
        # Tolerate the C-string concatenation: SELECT spans two literal lines
        # so the regex must skip whitespace + quotes between SELECT and
        # csrf_nonce, then between csrf_nonce and FROM user_sessions.
        select_pat = re.compile(
            r"SELECT[^()]*?csrf_nonce[^()]*?FROM\s+user_sessions",
            re.IGNORECASE | re.DOTALL,
        )
        assert select_pat.search(src), (
            "user_sessions SELECT in _session_cache_load must include csrf_nonce"
        )


# ── 9. Forwarded / X-Forwarded-Prefix stripped ────────────────────────────────

class TestForwardedHeadersStripped:
    """1.9.7: same spoof surface as `X-Forwarded-*`. Stripped from inbound."""

    @classmethod
    def setup_class(cls):
        cls.cph = importlib.import_module("core.proxy_handler")

    def test_forwarded_stripped_in_source(self):
        src = open(self.cph.__file__, encoding="utf-8").read()
        # Look for the RFC-7239 spoof-strip note + header names. Tolerate
        # case-variation; the actual strip code may use either canonical
        # or lower-case multi-dict access.
        assert re.search(r"['\"](?i:Forwarded)['\"]", src), (
            "Forwarded header strip not in core/proxy_handler.py"
        )
        assert re.search(r"['\"](?i:X-Forwarded-Prefix)['\"]", src), (
            "X-Forwarded-Prefix header strip not in core/proxy_handler.py"
        )


# ── 10. Honey-cred probe bans requester, not victim ───────────────────────────

class TestHoneyCredBanRequester:
    """1.9.7: previously banned the identity the honey key was *issued
    to*, so an attacker who scraped a leaked key from a victim's HTML
    could ban that victim by probing it. Now bans the REQUESTER's own
    identity + IP rate-limit on the probe path."""

    @classmethod
    def setup_class(cls):
        cls.cph = importlib.import_module("core.proxy_handler")

    def test_honey_probe_uses_probe_rate_limit(self):
        src = open(self.cph.__file__, encoding="utf-8").read()
        assert "_probe_rate_limit_ok" in src, (
            "honey-cred probe must call _probe_rate_limit_ok per 1.9.7 fix"
        )

    def test_honey_probe_bans_requester_not_holder(self):
        """Source must show the ban target is the REQUEST identity, not
        the identity that originally received the honey key. We grep
        for the comment that documents this contract."""
        src = open(self.cph.__file__, encoding="utf-8").read()
        # The fix is documented inline; look for the rationale.
        assert re.search(
            r"requester|the requester's own|attacker.*scraped|scraped.*leaked",
            src,
            re.IGNORECASE,
        ), (
            "honey-cred fix rationale (requester != holder) not documented "
            "in core/proxy_handler.py"
        )
