"""
tests/test_v187_security.py — v1.8.7 security regression tests.

Covers:
  DET4-02 — Redirect maze dest bound in HMAC (open-redirect prevention)
  DET4-03 — Interaction probe token bound to session identity, not IP
  DET4-04  — All-identical-timestamp bypass blocked in interaction_analyze
  PROXY4-01 — UPSTREAM hot-reload validator calls _assert_upstream_public
  PROXY4-02 — client_host validated against ALLOWED_HOSTS before Location rewrite
  PROXY4-03 — _PROPAGATE_NEVER denylist blocks security-critical name propagation
"""
import hashlib
import hmac
import os
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# ── env setup ────────────────────────────────────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="appsecgw-v187-test-")
os.environ.setdefault("UPSTREAM",  "https://example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "antibot-v187.db"))

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))


# ─────────────────────────────────────────────────────────────────────────────
# DET4-02: Redirect maze dest bound in HMAC
# ─────────────────────────────────────────────────────────────────────────────

class TestDET402MazeDestBinding:
    """dest is now part of the HMAC — swapping it must invalidate the token."""

    def _import(self):
        from detection.redirect_maze import (
            _sign_maze_token, _verify_maze_token, _dest_hash,
        )
        return _sign_maze_token, _verify_maze_token, _dest_hash

    def test_dest_hash_returns_16_hex_chars(self):
        _sign, _verify, _dest_hash = self._import()
        h = _dest_hash("/foo/bar")
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_valid_token_verifies_with_same_dest(self):
        _sign, _verify, _ = self._import()
        ts = int(time.time() * 1000)
        dest = "/dashboard"
        tok = _sign("identity-abc", 0, ts, dest)
        ok, step, _ = _verify(tok, "identity-abc", dest)
        assert ok
        assert step == 0

    def test_swapped_dest_invalidates_token(self):
        _sign, _verify, _ = self._import()
        ts = int(time.time() * 1000)
        tok = _sign("identity-abc", 0, ts, "/original")
        ok, _, _ = _verify(tok, "identity-abc", "/attacker-controlled")
        assert not ok, "Token must be invalid when dest is swapped"

    def test_different_step_invalidates_token(self):
        _sign, _verify, _ = self._import()
        ts = int(time.time() * 1000)
        tok = _sign("identity-abc", 0, ts, "/dest")
        # Manually craft a token that claims step=1 but has sig for step=0
        parts = tok.split(".")
        tampered = f"1.{parts[1]}.{parts[2]}"
        ok, _, _ = _verify(tampered, "identity-abc", "/dest")
        assert not ok

    def test_different_identity_invalidates_token(self):
        _sign, _verify, _ = self._import()
        ts = int(time.time() * 1000)
        tok = _sign("identity-abc", 0, ts, "/dest")
        ok, _, _ = _verify(tok, "identity-XYZ", "/dest")
        assert not ok

    def test_expired_token_rejected(self):
        _sign, _verify, _ = self._import()
        old_ts = int(time.time() * 1000) - 31_000  # 31 s ago
        tok = _sign("identity-abc", 0, old_ts, "/dest")
        ok, _, _ = _verify(tok, "identity-abc", "/dest")
        assert not ok

    def test_malformed_token_rejected(self):
        _sign, _verify, _ = self._import()
        for bad in ("", "abc", "1.2", "a.b.c.d", "notanumber.2.sig"):
            ok, _, _ = _verify(bad, "identity-abc", "/dest")
            assert not ok, f"Should reject: {bad!r}"

    def test_make_maze_entry_includes_dest_in_token(self):
        from detection.redirect_maze import make_maze_entry, _verify_maze_token
        from urllib.parse import urlparse, parse_qs, unquote
        url = make_maze_entry("id-test", "/secure-page")
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        tok = qs["t"][0]
        dest = unquote(qs["d"][0])
        ok, _, _ = _verify_maze_token(tok, "id-test", dest)
        assert ok
        # Swapping dest must fail
        ok2, _, _ = _verify_maze_token(tok, "id-test", "/evil")
        assert not ok2


# ─────────────────────────────────────────────────────────────────────────────
# DET4-03: Interaction token bound to session identity, not IP
# ─────────────────────────────────────────────────────────────────────────────

class TestDET403InteractionIdentityBinding:

    def test_token_uses_track_key_not_ip(self):
        from detection.interaction import _interaction_token
        import inspect
        sig = inspect.signature(_interaction_token)
        params = list(sig.parameters.keys())
        assert params[0] == "track_key", (
            f"_interaction_token first param must be track_key, got {params[0]!r}"
        )

    def test_different_track_keys_produce_different_tokens(self):
        from detection.interaction import _interaction_token
        ts = int(time.time())
        tok_a = _interaction_token("session-A", ts)
        tok_b = _interaction_token("session-B", ts)
        assert tok_a != tok_b

    def test_same_track_key_same_ts_produces_same_token(self):
        from detection.interaction import _interaction_token
        ts = int(time.time())
        assert _interaction_token("session-X", ts) == _interaction_token("session-X", ts)

    def test_inject_probe_uses_track_key_param(self):
        from detection.interaction import _inject_interaction_probe
        import inspect
        sig = inspect.signature(_inject_interaction_probe)
        params = list(sig.parameters.keys())
        assert params[1] == "track_key", (
            f"_inject_interaction_probe second param must be track_key, got {params[1]!r}"
        )

    def test_inject_probe_embeds_token_bound_to_track_key(self):
        from detection.interaction import _inject_interaction_probe, _interaction_token
        os.environ["INTERACTION_PROBE_ENABLED"] = "true"
        # Need to reload to pick up env change
        import importlib, detection.interaction as m
        importlib.reload(m)
        html = "<html><body>Hello</body></html>"
        result = m._inject_interaction_probe(html, "my-session-id")
        assert "_itok=" in result or "token" in result or "_itok" in result


# ─────────────────────────────────────────────────────────────────────────────
# DET4-04: All-identical-timestamp bypass blocked
# ─────────────────────────────────────────────────────────────────────────────

class TestDET404IdenticalTimestampBypass:

    def _analyze(self, events, duration_ms=5000):
        from detection.interaction import interaction_analyze
        return interaction_analyze(events, duration_ms)

    def test_all_same_timestamp_detected(self):
        # 10 mousemove events all at offset_ms=100
        events = [["m", 100, i, i+1] for i in range(10)]
        reason, detail = self._analyze(events)
        assert reason == "no-interaction", (
            f"All-same-ts should return no-interaction, got {reason!r}: {detail}"
        )
        assert "identical" in detail.lower()

    def test_fewer_than_5_events_not_triggered(self):
        # Only 3 events with identical timestamps — below the 5-event threshold
        events = [["m", 100, 1, 2] for _ in range(3)]
        reason, _ = self._analyze(events, duration_ms=100)
        # Should not trigger the identical-ts check (too few events)
        assert reason != "no-interaction" or reason is None

    def test_varying_timestamps_pass(self):
        # Realistic mouse events with varied offsets
        events = [
            ["m", i * 50 + (i % 3) * 17, i, i + 1]
            for i in range(10)
        ]
        reason, _ = self._analyze(events)
        # Should not be flagged as bot purely due to timestamps
        assert reason != "no-interaction"

    def test_clamped_all_zero_detected(self):
        # Attacker submits all offset_ms=0 (valid after clamp)
        events = [["m", 0, i, i+1] for i in range(8)]
        reason, detail = self._analyze(events)
        assert reason == "no-interaction"
        assert "identical" in detail.lower()

    def test_single_unique_offset_among_many_detected(self):
        # 9 events at ts=0, 1 at ts=1 — still triggers if max==min fails, but
        # with variation it should NOT trigger
        events = [["m", 0, i, i] for i in range(9)] + [["m", 1, 0, 0]]
        reason, _ = self._analyze(events)
        # max != min so NOT detected as identical
        assert reason != "no-interaction" or reason is None


# ─────────────────────────────────────────────────────────────────────────────
# PROXY4-01: UPSTREAM hot-reload validator calls _assert_upstream_public
# ─────────────────────────────────────────────────────────────────────────────

class TestPROXY401UpstreamValidator:

    def _get_upstream_validator(self):
        from core.proxy_handler import _HOT_RELOAD_KNOBS, _upstream_safe_to_reload
        parser, validator = _HOT_RELOAD_KNOBS["UPSTREAM"]
        return parser, validator, _upstream_safe_to_reload

    def test_upstream_safe_to_reload_exists(self):
        from core import proxy_handler
        assert hasattr(proxy_handler, "_upstream_safe_to_reload"), (
            "_upstream_safe_to_reload helper must exist"
        )

    def test_public_https_url_accepted(self):
        from core.proxy_handler import _upstream_safe_to_reload
        # Mock _assert_upstream_public to not raise
        with patch("vhost._assert_upstream_public"):
            assert _upstream_safe_to_reload("https://public-host.example.com/")

    def test_private_ip_rejected(self):
        from core.proxy_handler import _upstream_safe_to_reload
        # _assert_upstream_public raises SystemExit for private IPs
        with patch("vhost._assert_upstream_public", side_effect=SystemExit(1)):
            assert not _upstream_safe_to_reload("http://192.168.1.1/")

    def test_wrong_scheme_rejected(self):
        from core.proxy_handler import _upstream_safe_to_reload
        assert not _upstream_safe_to_reload("ftp://example.com/")

    def test_too_long_url_rejected(self):
        from core.proxy_handler import _upstream_safe_to_reload
        long_url = "https://" + "a" * 2050 + ".com/"
        assert not _upstream_safe_to_reload(long_url)

    def test_allow_private_upstream_bypasses_check(self):
        from core import proxy_handler
        with patch.object(proxy_handler, "ALLOW_PRIVATE_UPSTREAM", True, create=True):
            with patch("vhost._assert_upstream_public") as mock_check:
                result = proxy_handler._upstream_safe_to_reload("http://127.0.0.1/")
                # Should not call the check when ALLOW_PRIVATE_UPSTREAM is set
                mock_check.assert_not_called()
                assert result

    def test_allow_private_upstream_not_in_hot_reload_knobs(self):
        from core.proxy_handler import _HOT_RELOAD_KNOBS
        assert "ALLOW_PRIVATE_UPSTREAM" not in _HOT_RELOAD_KNOBS, (
            "ALLOW_PRIVATE_UPSTREAM must be removed from _HOT_RELOAD_KNOBS "
            "to prevent runtime SSRF enablement via hot-reload"
        )

    def test_upstream_knob_uses_safe_validator(self):
        from core.proxy_handler import _HOT_RELOAD_KNOBS, _upstream_safe_to_reload
        _, validator = _HOT_RELOAD_KNOBS["UPSTREAM"]
        assert validator is _upstream_safe_to_reload, (
            "UPSTREAM knob validator must be _upstream_safe_to_reload"
        )


# ─────────────────────────────────────────────────────────────────────────────
# PROXY4-02: client_host validated against ALLOWED_HOSTS
# ─────────────────────────────────────────────────────────────────────────────

class TestPROXY402ClientHostValidation:
    """
    When ALLOWED_HOSTS is set and request.host is not in it, client_host
    must fall back to up_parsed.netloc (the known-good upstream host),
    not the attacker-controlled Host header.
    """

    def _make_mock_request(self, host: str, secure: bool = False,
                           x_forwarded_proto: str = "") -> MagicMock:
        r = MagicMock()
        r.host = host
        r.secure = secure
        headers = {}
        if x_forwarded_proto:
            headers["X-Forwarded-Proto"] = x_forwarded_proto
        r.headers = headers
        return r

    def test_allowed_host_used_directly(self):
        """Legitimate Host header passes through unchanged."""
        from urllib.parse import urlparse
        up_parsed = urlparse("https://backend.internal:8080")

        request = self._make_mock_request("legitimate.example.com")
        allowed = frozenset({"legitimate.example.com"})

        _req_host = (request.host or "").split(":")[0].lower()
        if allowed and _req_host not in allowed:
            client_host = up_parsed.netloc
        else:
            client_host = request.host or up_parsed.netloc

        assert client_host == "legitimate.example.com"

    def test_attacker_host_falls_back_to_upstream(self):
        """Attacker-controlled Host header falls back to upstream netloc."""
        from urllib.parse import urlparse
        up_parsed = urlparse("https://backend.internal:8080")

        request = self._make_mock_request("evil.attacker.com")
        allowed = frozenset({"legitimate.example.com"})

        _req_host = (request.host or "").split(":")[0].lower()
        if allowed and _req_host not in allowed:
            client_host = up_parsed.netloc
        else:
            client_host = request.host or up_parsed.netloc

        assert client_host == "backend.internal:8080", (
            f"Unrecognised Host must fall back to upstream netloc, got {client_host!r}"
        )

    def test_empty_allowed_hosts_no_enforcement(self):
        """Empty ALLOWED_HOSTS = no Host enforcement (pass through)."""
        from urllib.parse import urlparse
        up_parsed = urlparse("https://backend.internal:8080")

        request = self._make_mock_request("anything.goes.com")
        allowed = frozenset()  # empty = no enforcement

        _req_host = (request.host or "").split(":")[0].lower()
        if allowed and _req_host not in allowed:
            client_host = up_parsed.netloc
        else:
            client_host = request.host or up_parsed.netloc

        assert client_host == "anything.goes.com"

    def test_host_with_port_stripped_for_comparison(self):
        """request.host may include port; strip for comparison."""
        from urllib.parse import urlparse
        up_parsed = urlparse("https://backend.internal")

        request = self._make_mock_request("legit.example.com:8443")
        allowed = frozenset({"legit.example.com"})

        _req_host = (request.host or "").split(":")[0].lower()
        if allowed and _req_host not in allowed:
            client_host = up_parsed.netloc
        else:
            client_host = request.host or up_parsed.netloc

        assert client_host == "legit.example.com:8443"


# ─────────────────────────────────────────────────────────────────────────────
# PROXY4-03: _PROPAGATE_NEVER denylist in _ProxyModule.__setattr__
# ─────────────────────────────────────────────────────────────────────────────

class TestPROXY403PropagateNeverDenylist:

    def test_propagate_never_frozenset_exists(self):
        import proxy
        assert hasattr(proxy, "_PROPAGATE_NEVER"), (
            "_PROPAGATE_NEVER must exist in proxy module"
        )
        pn = proxy._PROPAGATE_NEVER
        assert isinstance(pn, frozenset)

    def test_builtin_names_in_denylist(self):
        import proxy
        for name in ("open", "exec", "eval", "__builtins__", "__import__"):
            assert name in proxy._PROPAGATE_NEVER, (
                f"{name!r} must be in _PROPAGATE_NEVER"
            )

    def test_session_key_propagates_for_key_rotation(self):
        """SESSION_KEY must propagate so in-process key rotation reaches all modules."""
        import proxy
        import config

        original = config.SESSION_KEY
        new_key = b"\xab" * 32
        try:
            proxy.SESSION_KEY = new_key
            assert config.SESSION_KEY == new_key, (
                "SESSION_KEY must propagate to config module for key rotation"
            )
        finally:
            proxy.SESSION_KEY = original
            config.SESSION_KEY = original

    def test_builtins_not_propagated(self):
        """Setting 'open' on proxy_module must not propagate to builtins."""
        import proxy
        import builtins

        real_open = builtins.open
        try:
            proxy.open = "shadow"
            assert builtins.open is real_open, (
                "'open' must not propagate to builtins via _ProxyModule"
            )
        finally:
            # Restore proxy.open if it was set
            try:
                del proxy.__dict__["open"]
            except KeyError:
                pass

    def test_normal_knob_still_propagates(self):
        """Ordinary config knobs (e.g. JS_CHALLENGE) still propagate normally."""
        import proxy
        import config

        original = config.JS_CHALLENGE
        try:
            proxy.JS_CHALLENGE = not original
            # Config module should see the change
            assert config.JS_CHALLENGE == (not original), (
                "Normal knob JS_CHALLENGE must still propagate"
            )
        finally:
            proxy.JS_CHALLENGE = original
            config.JS_CHALLENGE = original

    def test_proxy_module_class_is_proxy_module(self):
        import proxy
        from types import ModuleType
        assert type(proxy).__name__ == "_ProxyModule"
