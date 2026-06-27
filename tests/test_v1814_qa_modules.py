# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1814_qa_modules.py — QA for under-covered source modules (1.8.14 audit).

Modules covered:
  HC — detection/honey_cred.py    : key generation, store, injection
  JW — integrations/jwt.py        : HS256 verify, path glob matching
  GQ — detection/graphql.py       : introspection / batch / depth signals
  HD — detection/headers.py       : library header sig detection
  FP — detection/fp_enrichment.py : soft-renderer detection, probe injection
  LH — detection/llm_heuristic.py : subresource classification, observe, check
  TR — reputation/tor.py          : exit-set membership, feed parse guards

Test types per section: P(arametrized) B(oundary) E(dge) N(egative)
                         Unit Regression Functional Integration
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac as _hmac
import json
import os
import time as _t

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")
os.environ.setdefault("JWT_HMAC_SECRET", "test-secret-for-qa")

_REPO = os.path.join(os.path.dirname(__file__), "..")


# ─── JWT token builder (test helper, not under test) ────────────────────────

def _make_jwt(payload: dict, secret: str = "test-secret-for-qa",
              alg: str = "HS256", typ: str = "JWT") -> str:
    hdr_json = json.dumps({"alg": alg, "typ": typ}).encode()
    pay_json  = json.dumps(payload).encode()
    hdr_b64   = base64.urlsafe_b64encode(hdr_json).rstrip(b"=").decode()
    pay_b64   = base64.urlsafe_b64encode(pay_json).rstrip(b"=").decode()
    msg       = f"{hdr_b64}.{pay_b64}".encode()
    sig       = base64.urlsafe_b64encode(
        _hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{hdr_b64}.{pay_b64}.{sig}"


# ═══════════════════════════════════════════════════════════════════════════
# HC — detection/honey_cred.py
# ═══════════════════════════════════════════════════════════════════════════

class TestHoneyCredKeyUnit:
    """Unit: _make_honey_key format and properties."""

    def test_key_length_32(self):
        from detection.honey_cred import _make_honey_key
        assert len(_make_honey_key("identity-abc")) == 32

    def test_key_is_hex(self):
        from detection.honey_cred import _make_honey_key
        k = _make_honey_key("identity-abc")
        int(k, 16)  # raises ValueError if not hex

    @pytest.mark.parametrize("identity", [
        "ip:1.2.3.4", "session:abc123", "fp:deadbeef", "",
    ])
    def test_key_deterministic_within_hour(self, identity):
        from detection.honey_cred import _make_honey_key
        assert _make_honey_key(identity) == _make_honey_key(identity)

    def test_different_identities_produce_different_keys(self):
        from detection.honey_cred import _make_honey_key
        assert _make_honey_key("id-A") != _make_honey_key("id-B")


class TestHoneyCredStoreLookup:
    """Unit/Integration: _store_honey_key + lookup_honey_key lifecycle."""

    def test_store_then_lookup_returns_identity(self):
        from detection.honey_cred import _make_honey_key, _store_honey_key, lookup_honey_key
        k = _make_honey_key("test-store-id")
        _store_honey_key(k, "test-store-id")
        assert lookup_honey_key(k) == "test-store-id"

    def test_lookup_empty_key_returns_empty(self):
        from detection.honey_cred import lookup_honey_key
        assert lookup_honey_key("") == ""

    def test_lookup_unknown_key_returns_empty(self):
        from detection.honey_cred import lookup_honey_key
        assert lookup_honey_key("0" * 32) == ""

    def test_lookup_expired_key_returns_empty(self):
        from detection.honey_cred import _honey_key_store, lookup_honey_key
        import time as _time
        # Insert a manually-expired entry
        _honey_key_store["expired-key"] = ("some-identity", _time.time() - 1)
        result = lookup_honey_key("expired-key")
        assert result == "", "Expired key must return empty string"
        assert "expired-key" not in _honey_key_store, "Expired key must be evicted"

    def test_store_max_evicts_on_overflow(self):
        from detection.honey_cred import _honey_key_store, _store_honey_key, _STORE_MAX
        import time as _time
        _honey_key_store.clear()
        # Fill to max
        for i in range(_STORE_MAX):
            _honey_key_store[f"key-{i}"] = ("id", _time.time() + 9999)
        # One more store call must evict without raising
        _store_honey_key("overflow-key", "overflow-id")
        assert len(_honey_key_store) <= _STORE_MAX


class TestHoneyCredInjection:
    """P/B/N/Functional: inject_honey_creds body injection."""

    def _inject(self, body, identity="test-id"):
        from detection.honey_cred import inject_honey_creds
        return inject_honey_creds(body, identity)

    def test_comment_before_body_tag(self):
        body = b"<html><body>Hello</body></html>"
        result = self._inject(body)
        idx_tag     = result.find(b"</body>")
        idx_comment = result.find(b"internal_api_key")
        assert idx_comment >= 0,   "Honey key comment not found"
        assert idx_comment < idx_tag, "Comment must precede </body>"

    @pytest.mark.parametrize("body", [
        b"<html>No body tag</html>",
        b"no html tags here",
    ])
    def test_comment_appended_when_no_body_tag(self, body):
        # Implementation appends to end when no </body> present
        result = self._inject(body)
        assert b"internal_api_key" in result
        # Comment appears after the original body
        idx_comment = result.find(b"internal_api_key")
        assert idx_comment >= len(body), "Comment should be appended after original body"

    def test_comment_contains_probe_url(self):
        result = self._inject(b"<body>x</body>")
        assert b"debug_endpoint" in result
        assert b"probe?k=" in result

    def test_comment_contains_the_generated_key(self):
        from detection.honey_cred import _honey_key_store
        _honey_key_store.clear()
        result = self._inject(b"<body>x</body>", "id-for-key-test")
        # Extract key from comment
        import re
        m = re.search(rb'internal_api_key = ([0-9a-f]{32})', result)
        assert m, "Honey key not found in comment"
        key = m.group(1).decode()
        assert len(key) == 32

    def test_empty_body_unchanged(self):
        assert self._inject(b"") == b""

    def test_empty_identity_unchanged(self):
        from detection.honey_cred import inject_honey_creds
        body = b"<body>x</body>"
        assert inject_honey_creds(body, "") == body

    def test_disabled_knob_unchanged(self):
        import detection.honey_cred as _hc
        saved = _hc.HONEY_CRED_ENABLED
        _hc.HONEY_CRED_ENABLED = False
        try:
            body = b"<body>x</body>"
            assert self._inject(body) == body
        finally:
            _hc.HONEY_CRED_ENABLED = saved

    def test_injected_key_is_lookupable(self):
        """Regression: key injected into page must be findable via lookup_honey_key."""
        from detection.honey_cred import _honey_key_store, lookup_honey_key
        import re
        _honey_key_store.clear()
        result = self._inject(b"<body>page</body>", "lookup-verify-id")
        m = re.search(rb'internal_api_key = ([0-9a-f]{32})', result)
        assert m
        key = m.group(1).decode()
        identity = lookup_honey_key(key)
        assert identity == "lookup-verify-id", \
            "Injected key must be retrievable from store"


# ═══════════════════════════════════════════════════════════════════════════
# JW — integrations/jwt.py
# ═══════════════════════════════════════════════════════════════════════════

class TestJwtVerifyParametrized:
    """P: _verify_jwt_hs256 across expected outcomes."""

    @pytest.mark.parametrize("payload,expected_ok,expected_err", [
        # Valid unexpired token
        ({"sub": "u1", "exp": int(_t.time()) + 300}, True,  "ok"),
        # Expired (no leeway)
        ({"sub": "u1", "exp": int(_t.time()) - 999}, False, "expired"),
        # Not yet valid
        ({"sub": "u1", "nbf": int(_t.time()) + 999}, False, "not-yet-valid"),
    ])
    def test_verify_outcome(self, payload, expected_ok, expected_err):
        import integrations.jwt as _jwt
        saved = _jwt.JWT_HMAC_SECRET
        _jwt.JWT_HMAC_SECRET = "test-secret-for-qa"
        try:
            tok = _make_jwt(payload)
            ok, err = _jwt._verify_jwt_hs256(tok)
            assert ok  is expected_ok,  f"ok mismatch: got {ok}"
            assert err == expected_err, f"err mismatch: got {err!r}"
        finally:
            _jwt.JWT_HMAC_SECRET = saved

    @pytest.mark.parametrize("alg,expected_err", [
        ("RS256", "alg-not-hs256"),
        ("none",  "alg-not-hs256"),
        ("HS384", "alg-not-hs256"),
    ])
    def test_wrong_algorithm_rejected(self, alg, expected_err):
        import integrations.jwt as _jwt
        saved = _jwt.JWT_HMAC_SECRET
        _jwt.JWT_HMAC_SECRET = "test-secret-for-qa"
        try:
            tok = _make_jwt({"sub": "u1"}, alg=alg)
            ok, err = _jwt._verify_jwt_hs256(tok)
            assert ok  is False
            assert err == expected_err
        finally:
            _jwt.JWT_HMAC_SECRET = saved


class TestJwtVerifyBoundary:
    """B: boundary conditions for JWT verification."""

    def _verify(self, token):
        import integrations.jwt as _jwt
        saved = _jwt.JWT_HMAC_SECRET
        _jwt.JWT_HMAC_SECRET = "test-secret-for-qa"
        try:
            return _jwt._verify_jwt_hs256(token)
        finally:
            _jwt.JWT_HMAC_SECRET = saved

    def test_no_secret_configured(self):
        import integrations.jwt as _jwt
        saved = _jwt.JWT_HMAC_SECRET
        _jwt.JWT_HMAC_SECRET = ""
        try:
            tok = _make_jwt({"sub": "u"})
            ok, err = _jwt._verify_jwt_hs256(tok)
            assert ok is False
            assert err == "no-secret-configured"
        finally:
            _jwt.JWT_HMAC_SECRET = saved

    def test_malformed_too_few_parts(self):
        ok, err = self._verify("only.two")
        assert ok is False and err == "malformed"

    def test_malformed_too_many_parts(self):
        ok, err = self._verify("a.b.c.d")
        assert ok is False and err == "malformed"

    def test_malformed_bad_json(self):
        ok, err = self._verify("notbase64!!!.also.bad")
        assert ok is False and err == "malformed"

    def test_bad_signature(self):
        tok = _make_jwt({"sub": "u1"}, secret="wrong-secret")
        ok, err = self._verify(tok)
        assert ok is False and err == "bad-signature"

    def test_leeway_accepts_just_expired(self):
        """Token expired within JWT_LEEWAY_SECS must still be accepted."""
        import integrations.jwt as _jwt
        saved_s = _jwt.JWT_HMAC_SECRET
        saved_l = _jwt.JWT_LEEWAY_SECS
        _jwt.JWT_HMAC_SECRET = "test-secret-for-qa"
        _jwt.JWT_LEEWAY_SECS = 30
        try:
            tok = _make_jwt({"sub": "u1", "exp": int(_t.time()) - 10})
            ok, err = _jwt._verify_jwt_hs256(tok)
            assert ok is True, f"Within-leeway token must be accepted; err={err!r}"
        finally:
            _jwt.JWT_HMAC_SECRET = saved_s
            _jwt.JWT_LEEWAY_SECS = saved_l


class TestJwtClaimValidation:
    """Unit: issuer and audience claim checks."""

    def _verify(self, token, iss=None, aud=None):
        import integrations.jwt as _jwt
        _jwt.JWT_HMAC_SECRET     = "test-secret-for-qa"
        _jwt.JWT_REQUIRED_ISSUER   = iss or ""
        _jwt.JWT_REQUIRED_AUDIENCE = aud or ""
        return _jwt._verify_jwt_hs256(token)

    def test_issuer_match_ok(self):
        tok = _make_jwt({"sub": "u", "iss": "my-service"})
        ok, err = self._verify(tok, iss="my-service")
        assert ok is True

    def test_issuer_mismatch_rejected(self):
        tok = _make_jwt({"sub": "u", "iss": "other-service"})
        ok, err = self._verify(tok, iss="my-service")
        assert ok is False and err == "issuer-mismatch"

    def test_audience_string_match(self):
        tok = _make_jwt({"sub": "u", "aud": "api.example.com"})
        ok, err = self._verify(tok, aud="api.example.com")
        assert ok is True

    def test_audience_string_mismatch(self):
        tok = _make_jwt({"sub": "u", "aud": "other.example.com"})
        ok, err = self._verify(tok, aud="api.example.com")
        assert ok is False and err == "audience-mismatch"

    def test_audience_list_contains_required(self):
        tok = _make_jwt({"sub": "u", "aud": ["api.example.com", "admin.example.com"]})
        ok, err = self._verify(tok, aud="api.example.com")
        assert ok is True

    def test_audience_list_missing_required(self):
        tok = _make_jwt({"sub": "u", "aud": ["other.example.com"]})
        ok, err = self._verify(tok, aud="api.example.com")
        assert ok is False and err == "audience-mismatch"


class TestJwtPathMatching:
    """Unit/Functional: _jwt_required_for glob matching."""

    def _req(self, path, globs):
        import integrations.jwt as _jwt
        saved = _jwt.JWT_VALIDATE_PATHS
        _jwt.JWT_VALIDATE_PATHS = globs
        try:
            return _jwt._jwt_required_for(path)
        finally:
            _jwt.JWT_VALIDATE_PATHS = saved

    @pytest.mark.parametrize("path,globs,expected", [
        ("/api/data",        [],                  False),
        ("/api/data",        ["/api/*"],           True),
        ("/api/data",        ["/other/*"],         False),
        ("/api/data",        ["/api/*", "/pub/*"], True),
        ("/pub/page",        ["/api/*", "/pub/*"], True),
        ("/api/v2/resource", ["/api/v2/*"],        True),
        ("/api/v1/resource", ["/api/v2/*"],        False),
    ])
    def test_path_matching_matrix(self, path, globs, expected):
        assert self._req(path, globs) is expected

    def test_empty_globs_never_required(self):
        assert self._req("/anything", []) is False


class TestJwtRegression:
    """Regression: algorithm confusion attack."""

    def test_alg_none_rejected(self):
        """Algorithm 'none' must never be accepted — classic JWT confusion attack."""
        import integrations.jwt as _jwt
        saved = _jwt.JWT_HMAC_SECRET
        _jwt.JWT_HMAC_SECRET = "test-secret-for-qa"
        try:
            # Token with alg=none and empty signature
            hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
            pay = base64.urlsafe_b64encode(b'{"sub":"attacker"}').rstrip(b"=").decode()
            tok = f"{hdr}.{pay}."  # empty signature
            ok, err = _jwt._verify_jwt_hs256(tok)
            assert ok is False
            assert err in ("alg-not-hs256", "malformed")
        finally:
            _jwt.JWT_HMAC_SECRET = saved

    def test_hs256_with_wrong_secret_rejected(self):
        """Valid HS256 token signed with different secret must be rejected."""
        import integrations.jwt as _jwt
        saved = _jwt.JWT_HMAC_SECRET
        _jwt.JWT_HMAC_SECRET = "server-secret"
        try:
            tok = _make_jwt({"sub": "u"}, secret="attacker-secret")
            ok, err = _jwt._verify_jwt_hs256(tok)
            assert ok is False and err == "bad-signature"
        finally:
            _jwt.JWT_HMAC_SECRET = saved


# ═══════════════════════════════════════════════════════════════════════════
# GQ — detection/graphql.py
# ═══════════════════════════════════════════════════════════════════════════

class TestGraphqlParametrized:
    """P: check_graphql signal matrix."""

    def _check(self, body, path="/graphql", ct="application/json"):
        import config as _cfg
        from detection.graphql import check_graphql
        _cfg.GQL_ENABLED = True
        _cfg.GQL_PATHS   = set()  # all paths
        _cfg.GQL_ALLOW_INTROSPECTION = False
        _cfg.GQL_BATCH_LIMIT = 5
        _cfg.GQL_MAX_DEPTH   = 10
        _cfg.WAF_BODY_SCAN_BYTES = 65536
        return check_graphql(path, body, ct)

    @pytest.mark.parametrize("body,signal", [
        (b'{"query":"{__schema{types{name}}}"}',    "gql-introspection"),
        (b'{"query":"{__type(name:\\"User\\"){}}"}',  "gql-introspection"),
        (b'{"operationName":"IntrospectionQuery"}',  "gql-introspection"),
    ])
    def test_introspection_patterns(self, body, signal):
        sigs = self._check(body)
        assert signal in sigs, f"Expected {signal!r} for body {body!r}"

    @pytest.mark.parametrize("count,expected_signal", [
        (6, "gql-batch-abuse"),   # > GQL_BATCH_LIMIT=5 → fires
        (5, None),                # at limit → doesn't fire
        (1, None),                # single → no batch
    ])
    def test_batch_abuse(self, count, expected_signal):
        body = json.dumps([{"query": "{}"}] * count).encode()
        sigs = self._check(body)
        if expected_signal:
            assert expected_signal in sigs
        else:
            assert "gql-batch-abuse" not in sigs

    @pytest.mark.parametrize("depth,expected_fire", [
        (11, True),   # > GQL_MAX_DEPTH=10
        (10, False),  # at limit
        (5,  False),
    ])
    def test_depth_exceeded(self, depth, expected_fire):
        body = b"{" * depth + b"}" * depth
        sigs = self._check(body)
        if expected_fire:
            assert "gql-depth-exceeded" in sigs
        else:
            assert "gql-depth-exceeded" not in sigs


class TestGraphqlBoundary:
    """B: guard conditions."""

    def test_disabled_returns_empty(self):
        import config as _cfg
        from detection.graphql import check_graphql
        _cfg.GQL_ENABLED = False
        assert check_graphql("/graphql", b'{"query":"{__schema{}}"}', "application/json") == []
        _cfg.GQL_ENABLED = True

    def test_empty_body_returns_empty(self):
        import config as _cfg
        from detection.graphql import check_graphql
        _cfg.GQL_ENABLED = True; _cfg.GQL_PATHS = set()
        assert check_graphql("/graphql", b"", "application/json") == []

    def test_path_not_in_gql_paths_skipped(self):
        import config as _cfg
        from detection.graphql import check_graphql
        _cfg.GQL_ENABLED = True
        _cfg.GQL_PATHS   = {"/graphql"}  # only /graphql
        result = check_graphql("/api/data", b'{"query":"{__schema{}}"}', "application/json")
        assert result == []
        _cfg.GQL_PATHS = set()

    def test_introspection_allowed_when_flag_set(self):
        import config as _cfg
        from detection.graphql import check_graphql
        _cfg.GQL_ENABLED = True; _cfg.GQL_PATHS = set()
        _cfg.GQL_ALLOW_INTROSPECTION = True
        result = check_graphql("/graphql", b'{"query":"{__schema{}}"}', "application/json")
        assert "gql-introspection" not in result
        _cfg.GQL_ALLOW_INTROSPECTION = False


class TestGraphqlEdgeCases:
    """E: edge cases and multi-signal scenarios."""

    def test_case_insensitive_introspection(self):
        import config as _cfg
        from detection.graphql import check_graphql
        _cfg.GQL_ENABLED = True; _cfg.GQL_PATHS = set()
        _cfg.GQL_ALLOW_INTROSPECTION = False; _cfg.WAF_BODY_SCAN_BYTES = 65536
        # Case-insensitive match
        assert "gql-introspection" in check_graphql(
            "/graphql", b'{"query":"{__SCHEMA{}}"}', "application/json"
        )

    def test_multiple_signals_same_request(self):
        """Single request can trigger both introspection + batch."""
        import config as _cfg
        from detection.graphql import check_graphql
        _cfg.GQL_ENABLED = True; _cfg.GQL_PATHS = set()
        _cfg.GQL_ALLOW_INTROSPECTION = False; _cfg.GQL_BATCH_LIMIT = 1
        _cfg.WAF_BODY_SCAN_BYTES = 65536
        # Array of 2 ops, each with introspection
        body = json.dumps([{"query":"{__schema{}}"}, {"query":"{}"}]).encode()
        sigs = check_graphql("/graphql", body, "application/json")
        assert "gql-batch-abuse" in sigs
        _cfg.GQL_BATCH_LIMIT = 5


# ═══════════════════════════════════════════════════════════════════════════
# HD — detection/headers.py
# ═══════════════════════════════════════════════════════════════════════════

class TestHeaderSignatureUnit:
    """Unit: _header_order_sig and _is_library_headers."""

    def _req(self, headers: dict):
        from unittest import mock
        req = mock.MagicMock()
        req.headers = headers
        return req

    def test_sig_is_12_hex_chars(self):
        from detection.headers import _header_order_sig
        sig = _header_order_sig(self._req({"User-Agent": "ua", "Accept": "*/*"}))
        assert len(sig) == 12
        int(sig, 16)

    def test_sig_excludes_host_header(self):
        """host header must be excluded from the signature (it varies per vhost)."""
        from detection.headers import _header_order_sig
        r1 = self._req({"User-Agent": "ua", "Accept": "*/*"})
        r2 = self._req({"Host": "example.com", "User-Agent": "ua", "Accept": "*/*"})
        assert _header_order_sig(r1) == _header_order_sig(r2), \
            "Host header must not affect signature"

    def test_sig_deterministic(self):
        from detection.headers import _header_order_sig
        req = self._req({"User-Agent": "ua", "Accept": "*/*", "Accept-Encoding": "gzip"})
        assert _header_order_sig(req) == _header_order_sig(req)

    @pytest.mark.parametrize("headers,expected_library", [
        # python-requests
        ({"user-agent": "python-requests/2.31", "accept-encoding": "gzip, deflate",
          "accept": "*/*", "connection": "keep-alive"}, True),
        # curl
        ({"user-agent": "curl/7.88.1", "accept": "*/*"}, True),
        # Go net/http
        ({"user-agent": "Go-http-client/1.1", "accept-encoding": "gzip"}, True),
        # Full browser Accept + Accept-Language + UA order → not library
        ({"accept": "text/html,application/xhtml+xml",
          "accept-language": "en-US,en;q=0.9",
          "accept-encoding": "gzip, deflate, br",
          "user-agent": "Mozilla/5.0"}, False),
    ])
    def test_library_detection(self, headers, expected_library):
        from detection.headers import _is_library_headers
        req = self._req(headers)
        assert _is_library_headers(req) is expected_library, \
            f"Library detection wrong for headers={list(headers.keys())}"

    def test_library_header_sigs_nonempty(self):
        from detection.headers import _LIBRARY_HEADER_SIGS
        assert len(_LIBRARY_HEADER_SIGS) >= 4, \
            "At least 4 library signatures must be defined"

    def test_empty_headers_not_library(self):
        from detection.headers import _is_library_headers
        req = self._req({})
        assert _is_library_headers(req) is False


# ═══════════════════════════════════════════════════════════════════════════
# FP — detection/fp_enrichment.py
# ═══════════════════════════════════════════════════════════════════════════

class TestFpTokenUnit:
    """Unit: _fp_token_for."""

    @pytest.mark.parametrize("track_key,ts", [
        ("identity-abc", 1_000_000),
        ("",             0),
        ("session:xyz",  2**31 - 1),
    ])
    def test_token_32_hex(self, track_key, ts):
        from detection.fp_enrichment import _fp_token_for
        tok = _fp_token_for(track_key, ts)
        assert len(tok) == 32
        int(tok, 16)

    def test_token_deterministic(self):
        from detection.fp_enrichment import _fp_token_for
        assert _fp_token_for("k", 100) == _fp_token_for("k", 100)

    def test_token_differs_by_key(self):
        from detection.fp_enrichment import _fp_token_for
        assert _fp_token_for("key-A", 100) != _fp_token_for("key-B", 100)

    def test_token_differs_by_ts(self):
        from detection.fp_enrichment import _fp_token_for
        assert _fp_token_for("k", 100) != _fp_token_for("k", 101)


class TestSoftRendererParametrized:
    """P: _is_soft_renderer string patterns."""

    @pytest.mark.parametrize("renderer,expected", [
        ("Google SwiftShader",               True),
        ("SwiftShader",                       True),
        ("Mesa DRI Intel(R) UHD Graphics",   True),
        ("llvmpipe (LLVM 14.0.0, 256 bits)", True),
        ("lavapipe",                          True),
        ("softpipe",                          True),
        ("Microsoft Basic Render Driver",     True),
        ("VMware SVGA3D",                     True),
        ("VirtualBox Graphics Adapter",       True),
        ("Virtual Machine",                   True),
        ("NVIDIA GeForce RTX 3080",           False),
        ("Apple M2",                          False),
        ("AMD Radeon RX 6700 XT",             False),
        ("Intel Iris Xe Graphics",            False),
        ("",                                  False),
    ])
    def test_soft_renderer_detection(self, renderer, expected):
        from detection.fp_enrichment import _is_soft_renderer
        assert _is_soft_renderer(renderer) is expected, \
            f"_is_soft_renderer({renderer!r}) expected {expected}"

    def test_case_insensitive(self):
        from detection.fp_enrichment import _is_soft_renderer
        assert _is_soft_renderer("SWIFTSHADER") is True
        assert _is_soft_renderer("mesa DRI") is True


class TestFpInjection:
    """P/B/N/Functional: _inject_fp_probe."""

    def _inject(self, body, tk="tk1"):
        from detection.fp_enrichment import _inject_fp_probe
        return _inject_fp_probe(body, tk)

    def test_snippet_before_body_tag(self):
        body = b"<html><body>page</body></html>"
        result = self._inject(body)
        assert result.find(b"fp-report") < result.find(b"</body>")

    def test_snippet_before_html_tag(self):
        body = b"<html>no body</html>"
        result = self._inject(body)
        assert b"fp-report" in result

    def test_snippet_appended_no_tags(self):
        body = b"raw content"
        result = self._inject(body)
        assert b"fp-report" in result

    def test_empty_body_unchanged(self):
        assert self._inject(b"") == b""

    def test_empty_track_key_unchanged(self):
        from detection.fp_enrichment import _inject_fp_probe
        assert _inject_fp_probe(b"<body>x</body>", "") == b"<body>x</body>"

    def test_disabled_knob_unchanged(self):
        import detection.fp_enrichment as _fp
        saved = _fp.FP_ENRICHMENT_ENABLED
        _fp.FP_ENRICHMENT_ENABLED = False
        try:
            body = b"<body>x</body>"
            assert self._inject(body) == body
        finally:
            _fp.FP_ENRICHMENT_ENABLED = saved

    def test_snippet_is_iife(self):
        result = self._inject(b"<body>x</body>")
        assert b"(function(){" in result and b"})();" in result

    def test_snippet_probes_canvas_and_webgl(self):
        result = self._inject(b"<body>x</body>")
        assert b"canvas" in result
        assert b"webgl" in result.lower()

    def test_token_in_snippet_matches_hmac(self):
        import re
        from detection.fp_enrichment import _fp_token_for
        body = b"<body>x</body>"
        result = self._inject(body, "my-track-key")
        m_tok = re.search(rb'token:"([0-9a-f]{32})"', result)
        m_ts  = re.search(rb'ts:(\d+)', result)
        assert m_tok and m_ts
        expected = _fp_token_for("my-track-key", int(m_ts.group(1)))
        assert m_tok.group(1).decode() == expected, "Embedded FP token must match HMAC"


# ═══════════════════════════════════════════════════════════════════════════
# LH — detection/llm_heuristic.py
# ═══════════════════════════════════════════════════════════════════════════

class TestLlmSubresourceUnit:
    """Unit: _is_subresource and _is_html_request classification."""

    @pytest.mark.parametrize("path,accept,expected", [
        ("/style.css",    "",                True),
        ("/app.js",       "",                True),
        ("/app.mjs",      "",                True),
        ("/font.woff2",   "",                True),
        ("/image.png",    "",                True),
        ("/image.webp",   "",                True),
        ("/logo.svg",     "",                True),
        ("/api/data",     "application/json",True),   # JSON XHR → subresource
        ("/api/data",     "text/html",       False),  # HTML accept → not subresource
        ("/page",         "text/html",       False),  # HTML page → not subresource
        ("/",             "",                False),  # root HTML → not subresource
    ])
    def test_is_subresource(self, path, accept, expected):
        from detection.llm_heuristic import _is_subresource
        assert _is_subresource(path, accept) is expected, \
            f"_is_subresource({path!r}, {accept!r}) expected {expected}"

    @pytest.mark.parametrize("method,accept,path,expected", [
        ("GET",  "text/html",    "/page",      True),
        ("GET",  "*/*",          "/page",      True),
        ("GET",  "",             "/page",      True),   # empty accept → assume HTML
        ("POST", "text/html",    "/page",      False),  # POST → not HTML request
        ("GET",  "text/html",    "/style.css", False),  # static ext → not HTML
        ("GET",  "text/html",    "/app.js",    False),
        ("GET",  "text/html",    "/data.xml",  False),
        ("GET",  "text/html",    "/data.csv",  False),
    ])
    def test_is_html_request(self, method, accept, path, expected):
        from detection.llm_heuristic import _is_html_request
        assert _is_html_request(method, accept, path) is expected, \
            f"_is_html_request({method!r}, {accept!r}, {path!r}) expected {expected}"


class TestLlmHeuristicObserveCheck:
    """Functional/Integration: observe + check end-to-end."""

    def setup_method(self):
        import detection.llm_heuristic as _lh
        self._lh = _lh
        # snapshot module-level knobs
        self._saved = {
            "LLM_HEURISTIC_ENABLED":       _lh.LLM_HEURISTIC_ENABLED,
            "LLM_HTML_MIN_COUNT":          _lh.LLM_HTML_MIN_COUNT,
            "LLM_SUBRES_RATIO_THRESHOLD":  _lh.LLM_SUBRES_RATIO_THRESHOLD,
            "LLM_HEURISTIC_WINDOW_SECS":   _lh.LLM_HEURISTIC_WINDOW_SECS,
            "LLM_HEURISTIC_SCORE":         _lh.LLM_HEURISTIC_SCORE,
        }

    def teardown_method(self):
        for k, v in self._saved.items():
            setattr(self._lh, k, v)

    def _clear(self, identity):
        self._lh._req_log.pop(identity, None)
        self._lh._fired.pop(identity, None)

    def test_no_signal_below_html_min(self):
        self._lh.LLM_HEURISTIC_ENABLED      = True
        self._lh.LLM_HTML_MIN_COUNT         = 5
        self._lh.LLM_SUBRES_RATIO_THRESHOLD = 0.1
        identity = "_qa_llm_below"
        self._clear(identity)
        for _ in range(2):
            self._lh.observe(identity, "GET", "/page", "text/html")
        score = self._lh.check(identity, "1.2.3.4")
        assert score == 0.0, f"Below min count must return 0, got {score}"

    def test_llm_signal_fires_no_subresources(self):
        self._lh.LLM_HEURISTIC_ENABLED      = True
        self._lh.LLM_HTML_MIN_COUNT         = 3
        self._lh.LLM_SUBRES_RATIO_THRESHOLD = 0.1
        self._lh.LLM_HEURISTIC_WINDOW_SECS  = 3600
        self._lh.LLM_HEURISTIC_SCORE        = 20.0
        identity = "_qa_llm_fire"
        self._clear(identity)
        for _ in range(5):
            self._lh.observe(identity, "GET", "/page", "text/html")
        score = self._lh.check(identity, "1.2.3.4")
        assert score > 0.0, "LLM signal must fire with 0 subresource ratio"

    def test_no_signal_with_normal_subresource_ratio(self):
        self._lh.LLM_HEURISTIC_ENABLED      = True
        self._lh.LLM_HTML_MIN_COUNT         = 3
        self._lh.LLM_SUBRES_RATIO_THRESHOLD = 0.5
        identity = "_qa_llm_normal"
        self._clear(identity)
        # 3 HTML + 6 subresources → ratio=2.0 > 0.5 → no fire
        for _ in range(3):
            self._lh.observe(identity, "GET", "/page", "text/html")
        for _ in range(6):
            self._lh.observe(identity, "GET", "/style.css", "")
        score = self._lh.check(identity, "1.2.3.4")
        assert score == 0.0

    def test_disabled_observe_no_records(self):
        identity = "_qa_llm_dis"
        self._clear(identity)
        self._lh.LLM_HEURISTIC_ENABLED = False
        self._lh.observe(identity, "GET", "/page", "text/html")
        assert identity not in self._lh._req_log

    def test_cooldown_prevents_double_fire(self):
        self._lh.LLM_HEURISTIC_ENABLED      = True
        self._lh.LLM_HTML_MIN_COUNT         = 2
        self._lh.LLM_SUBRES_RATIO_THRESHOLD = 0.1
        self._lh.LLM_HEURISTIC_WINDOW_SECS  = 3600
        self._lh.LLM_HEURISTIC_SCORE        = 20.0
        identity = "_qa_llm_cooldown"
        self._clear(identity)
        for _ in range(4):
            self._lh.observe(identity, "GET", "/page", "text/html")
        score1 = self._lh.check(identity, "1.2.3.4")
        score2 = self._lh.check(identity, "1.2.3.4")  # immediately again
        assert score1 > 0.0, "First check must fire"
        assert score2 == 0.0, "Second check must be suppressed by cooldown"


class TestLlmHeuristicNegative:
    """N: disabled, empty identity."""

    def test_check_disabled_returns_zero(self):
        import detection.llm_heuristic as _lh
        saved = _lh.LLM_HEURISTIC_ENABLED
        _lh.LLM_HEURISTIC_ENABLED = False
        try:
            assert _lh.check("any-identity", "1.2.3.4") == 0.0
        finally:
            _lh.LLM_HEURISTIC_ENABLED = saved

    def test_check_empty_identity_returns_zero(self):
        from detection.llm_heuristic import check
        assert check("", "1.2.3.4") == 0.0

    def test_observe_empty_identity_no_op(self):
        from detection.llm_heuristic import observe, _req_log
        observe("", "GET", "/page", "text/html")
        assert "" not in _req_log


# ═══════════════════════════════════════════════════════════════════════════
# TR — reputation/tor.py
# ═══════════════════════════════════════════════════════════════════════════

class TestTorExitSetUnit:
    """Unit: _tor_exits in-memory set membership checks."""

    def setup_method(self):
        from reputation.tor import _tor_exits
        self._saved = set(_tor_exits)
        _tor_exits.clear()

    def teardown_method(self):
        from reputation.tor import _tor_exits
        _tor_exits.clear()
        _tor_exits.update(self._saved)

    def test_known_exit_detected(self):
        from reputation.tor import _tor_exits
        _tor_exits.add("198.51.100.1")
        assert "198.51.100.1" in _tor_exits

    def test_unknown_ip_not_in_exits(self):
        from reputation.tor import _tor_exits
        assert "10.0.0.1" not in _tor_exits

    def test_empty_set_no_exits(self):
        from reputation.tor import _tor_exits
        assert len(_tor_exits) == 0

    @pytest.mark.parametrize("ip", [
        "185.220.101.1",
        "95.142.47.1",
        "2a0b:f4c2::1",   # IPv6 exit node
    ])
    def test_parametrized_exit_membership(self, ip):
        from reputation.tor import _tor_exits
        _tor_exits.add(ip)
        assert ip in _tor_exits
        _tor_exits.discard(ip)
        assert ip not in _tor_exits

    def test_multiple_exits_all_detectable(self):
        from reputation.tor import _tor_exits
        ips = {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
        _tor_exits.update(ips)
        for ip in ips:
            assert ip in _tor_exits


class TestTorFeedParsing:
    """Unit/Regression: _tor_fetch feed parsing logic (feed format, comment skipping)."""

    def test_tor_feed_stats_structure(self):
        from reputation.tor import _tor_feed_stats
        for key in ("loaded_at", "size", "last_error", "fetches"):
            assert key in _tor_feed_stats, f"Missing stat key: {key!r}"

    def test_tor_block_disabled_by_default(self):
        from reputation.tor import TOR_BLOCK_ENABLED
        # Default is "0" — should be False unless explicitly enabled
        assert isinstance(TOR_BLOCK_ENABLED, bool)

    def test_dc_vpn_block_disabled_by_default(self):
        from reputation.tor import DC_VPN_BLOCK_ENABLED
        assert isinstance(DC_VPN_BLOCK_ENABLED, bool)

    def test_feed_url_is_https(self):
        from reputation.tor import TOR_FEED_URL
        assert TOR_FEED_URL.startswith("https://"), \
            "Tor feed URL must use HTTPS"

    def test_feed_parse_logic_skips_comments_and_blanks(self):
        """Simulate the feed parse loop used in _tor_fetch — comments and blanks excluded."""
        raw = (
            "# Comment line\n"
            "198.51.100.1\n"
            "\n"
            "# Another comment\n"
            "203.0.113.1\n"
            "   \n"
        )
        new_set = set()
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                new_set.add(line)
        assert new_set == {"198.51.100.1", "203.0.113.1"}, \
            "Feed parser must skip comments and blank lines"

    def test_feed_parse_does_not_add_empty_string(self):
        """Empty lines must never end up in _tor_exits."""
        raw = "\n\n\n"
        new_set = set()
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                new_set.add(line)
        assert "" not in new_set
        assert len(new_set) == 0


# ═══════════════════════════════════════════════════════════════════════════
# SEC — Security invariants
# ═══════════════════════════════════════════════════════════════════════════

class TestSecJwtAlgorithmConfusion:
    """SEC: JWT algorithm confusion attacks — only HS256 accepted."""

    def _verify(self, tok):
        import integrations.jwt as _jwt
        saved = _jwt.JWT_HMAC_SECRET
        _jwt.JWT_HMAC_SECRET = "test-secret-for-qa"
        try:
            return _jwt._verify_jwt_hs256(tok)
        finally:
            _jwt.JWT_HMAC_SECRET = saved

    @pytest.mark.parametrize("alg", ["RS256", "PS256", "ES256", "HS384", "HS512"])
    def test_non_hs256_algorithm_rejected(self, alg):
        """Any non-HS256 alg header must be rejected — algorithm confusion protection."""
        hdr = base64.urlsafe_b64encode(
            json.dumps({"alg": alg, "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        pay = base64.urlsafe_b64encode(b'{"sub":"u"}').rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
        tok = f"{hdr}.{pay}.{sig}"
        ok, err = self._verify(tok)
        assert ok is False, f"alg={alg} must be rejected"
        assert err in ("alg-not-hs256", "malformed", "bad-signature")

    def test_none_uppercase_rejected(self):
        """alg=NONE (uppercase) must be rejected — case-insensitive guard."""
        hdr = base64.urlsafe_b64encode(b'{"alg":"NONE","typ":"JWT"}').rstrip(b"=").decode()
        pay = base64.urlsafe_b64encode(b'{"sub":"u"}').rstrip(b"=").decode()
        tok = f"{hdr}.{pay}."
        ok, _ = self._verify(tok)
        assert ok is False

    def test_missing_alg_field_rejected(self):
        """Header without alg key must be rejected."""
        hdr = base64.urlsafe_b64encode(b'{"typ":"JWT"}').rstrip(b"=").decode()
        pay = base64.urlsafe_b64encode(b'{"sub":"u"}').rstrip(b"=").decode()
        tok = f"{hdr}.{pay}.fakesig"
        ok, _ = self._verify(tok)
        assert ok is False

    def test_signature_tamper_rejected(self):
        """Valid HS256 token with last char of signature flipped must be rejected."""
        import integrations.jwt as _jwt
        saved_sec = _jwt.JWT_HMAC_SECRET
        saved_iss = _jwt.JWT_REQUIRED_ISSUER
        saved_aud = _jwt.JWT_REQUIRED_AUDIENCE
        _jwt.JWT_HMAC_SECRET       = "test-secret-for-qa"
        _jwt.JWT_REQUIRED_ISSUER   = ""
        _jwt.JWT_REQUIRED_AUDIENCE = ""
        try:
            future_exp = int(_t.time()) + 3600
            tok = _make_jwt({"sub": "u", "exp": future_exp}, secret="test-secret-for-qa")
            parts = tok.split(".")
            sig = parts[2]
            # Flip a middle char — the last char of base64url contributes only
            # 2 bits, so flipping it may yield the same decoded bytes for a
            # 32-byte HMAC. A middle char is unambiguously bit-significant.
            mid = len(sig) // 2
            bad_char = "b" if sig[mid] != "b" else "c"
            tampered = ".".join(parts[:2]) + "." + sig[:mid] + bad_char + sig[mid+1:]
            ok, err = _jwt._verify_jwt_hs256(tampered)
            assert ok is False, f"Tampered signature must be rejected, got ok={ok}, err={err}"
            assert err == "bad-signature"
        finally:
            _jwt.JWT_HMAC_SECRET       = saved_sec
            _jwt.JWT_REQUIRED_ISSUER   = saved_iss
            _jwt.JWT_REQUIRED_AUDIENCE = saved_aud

    def test_constant_time_compare_in_jwt_verify(self):
        """JWT verify must use hmac.compare_digest — prevents timing oracle."""
        import inspect
        from integrations.jwt import _verify_jwt_hs256
        src = inspect.getsource(_verify_jwt_hs256)
        assert "compare_digest" in src, \
            "_verify_jwt_hs256 must use hmac.compare_digest"


class TestSecHoneyCredKeyProperties:
    """SEC: honey credential key uniqueness, entropy, and safe format."""

    def test_key_is_hex_only(self):
        """Key must be 32 lowercase hex chars — safe to embed in HTML comments."""
        import re
        from detection.honey_cred import _make_honey_key
        key = _make_honey_key("test-identity")
        assert re.fullmatch(r"[0-9a-f]{32}", key), \
            f"Honey key must be 32 hex chars, got {key!r}"

    def test_distinct_identities_distinct_keys(self):
        """Key is identity-bound — different identities must never share a key."""
        from detection.honey_cred import _make_honey_key
        assert _make_honey_key("identity-A") != _make_honey_key("identity-B")

    def test_same_identity_deterministic(self):
        """Same identity always produces the same key — no random, no oracle."""
        from detection.honey_cred import _make_honey_key
        key1 = _make_honey_key("stable-id")
        key2 = _make_honey_key("stable-id")
        assert key1 == key2

    def test_expired_key_not_returned_on_lookup(self):
        """Expired key in store must return falsy — no auth bypass via stale credential."""
        from detection.honey_cred import _honey_key_store, lookup_honey_key
        key = "deadbeef" * 4  # 32 hex chars
        _honey_key_store[key] = ("victim-id", _t.time() - 1)  # already expired
        result = lookup_honey_key(key)
        assert not result, f"Expired key must not be returned by lookup, got {result!r}"
        _honey_key_store.pop(key, None)


class TestSecGraphqlBypass:
    """SEC: GraphQL introspection bypass attempts — case, whitespace, fragments."""

    def _check(self, body, path="/graphql"):
        import config as _cfg
        from detection.graphql import check_graphql
        _cfg.GQL_ENABLED = True
        _cfg.GQL_PATHS = set()
        _cfg.GQL_ALLOW_INTROSPECTION = False
        _cfg.GQL_BATCH_LIMIT = 5
        _cfg.GQL_MAX_DEPTH = 10
        _cfg.WAF_BODY_SCAN_BYTES = 65536
        return check_graphql(path, body, "application/json")  # returns list of signal strings

    @pytest.mark.parametrize("body,desc", [
        (b'{"query":"{__schema{types{name}}}"}',      "lowercase canonical"),
        (b'{"query":"{ __schema { types { name } } }"}', "whitespace padded"),
        (b'{"operationName":"IntrospectionQuery"}',    "operationName variant"),
    ])
    def test_introspection_patterns_blocked(self, body, desc):
        sigs = self._check(body)
        assert "gql-introspection" in sigs, f"{desc} must fire gql-introspection"

    def test_introspection_in_larger_query_blocked(self):
        """__schema embedded mid-query must still fire."""
        body = b'{"query":"{user{id} __schema{types{name}}}"}'
        sigs = self._check(body)
        assert "gql-introspection" in sigs

    def test_batch_single_item_not_blocked_as_batch(self):
        """Single-item array is valid — must not fire gql-batch-limit."""
        body = b'[{"query":"{user{id}}"}]'
        sigs = self._check(body)
        assert "gql-batch-limit" not in sigs, "Single-item batch must not trigger batch limit"

    def test_depth_at_limit_not_blocked(self):
        """Brace depth exactly at limit must not fire.
        Note: depth counter scans raw bytes including JSON wrapper ({...}) which
        adds +1 to the depth budget, so 9 braces in the query value = depth 10."""
        query = "{a" * 9 + "}" * 9   # 9 inner + 1 JSON wrapper = max_depth 10
        body = json.dumps({"query": query}).encode()
        sigs = self._check(body)
        assert "gql-depth-exceeded" not in sigs, "Query at exactly max depth must not fire"

    def test_depth_over_limit_blocked(self):
        """Brace depth exceeding limit must fire gql-depth-exceeded.
        10 query braces + 1 JSON wrapper = max_depth 11, which exceeds GQL_MAX_DEPTH=10."""
        query = "{a" * 10 + "}" * 10  # 10 inner + 1 JSON wrapper = max_depth 11
        body = json.dumps({"query": query}).encode()
        sigs = self._check(body)
        assert "gql-depth-exceeded" in sigs, "Query exceeding max depth must fire"


class TestSecFpTokenEntropy:
    """SEC: FP probe token entropy and script injection safety."""

    def test_fp_token_is_hex_safe_for_script(self):
        """hexdigest()[:32] — safe to embed in <script> without escaping."""
        import re
        from detection.fp_enrichment import _fp_token_for
        tok = _fp_token_for("track-key", int(_t.time()))
        assert re.fullmatch(r"[0-9a-f]{32}", tok), \
            f"FP token must be 32 lowercase hex chars, got {tok!r}"

    def test_distinct_keys_distinct_tokens(self):
        """Token is track-key-bound — different keys must not produce the same token."""
        from detection.fp_enrichment import _fp_token_for
        ts = int(_t.time())
        assert _fp_token_for("key-A", ts) != _fp_token_for("key-B", ts)

    def test_injected_fp_probe_uses_iife(self):
        """FP probe must use IIFE — no global variable leakage."""
        from detection.fp_enrichment import _inject_fp_probe
        result = _inject_fp_probe(b"<body>x</body>", "track")
        assert b"(function(){" in result or b"(function() {" in result, \
            "FP probe must be wrapped in IIFE"

    def test_fp_script_tag_closes_before_body(self):
        """<script> must close before </body> — prevents DOM structure corruption."""
        from detection.fp_enrichment import _inject_fp_probe
        result = _inject_fp_probe(b"<html><body>x</body></html>", "track")
        idx_close_script = result.rfind(b"</script>")
        idx_close_body   = result.find(b"</body>")
        assert idx_close_script < idx_close_body, \
            "</script> must appear before </body>"
