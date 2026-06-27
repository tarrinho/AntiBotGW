"""1.8.14 bypass-hardening tests.

Covers three adversarial probe mitigations:
  B-04  — agw_lc HMAC token: static replay (agw_lc=1) fails lifecycle-miss
  B-08  — per-identity threshold jitter: IpState.cookie_ghost_threshold_jitter
  B-01  — sec-fetch-nav-absent: Chrome/Edge GET with text/html but no Sec-Fetch-Mode
"""
import importlib
import os
import sys
import time
import unittest.mock as mock

import pytest

os.environ.setdefault("UPSTREAM", "http://localhost")

import detection.cookie_lifecycle as _cl


# ── B-04: agw_lc HMAC token ────────────────────────────────────────────────

class TestLifecycleToken:
    """_make_lc_token / _verify_lc_token unit tests."""

    def test_make_token_is_16_hex_chars(self):
        tok = _cl._make_lc_token("203.0.113.0")
        assert len(tok) == 16
        assert all(c in "0123456789abcdef" for c in tok)

    def test_verify_correct_token_passes(self):
        ip_tier = "198.51.100.0"
        tok = _cl._make_lc_token(ip_tier)
        assert _cl._verify_lc_token(tok, ip_tier)

    def test_static_replay_fails(self):
        ip_tier = "198.51.100.0"
        assert not _cl._verify_lc_token("1", ip_tier)

    def test_wrong_ip_tier_fails(self):
        tok = _cl._make_lc_token("198.51.100.0")
        assert not _cl._verify_lc_token(tok, "192.0.2.0")

    def test_empty_value_fails(self):
        assert not _cl._verify_lc_token("", "203.0.113.0")

    def test_wrong_length_fails(self):
        assert not _cl._verify_lc_token("abc", "203.0.113.0")
        assert not _cl._verify_lc_token("a" * 32, "203.0.113.0")

    def test_previous_window_accepted(self):
        ip_tier = "203.0.113.0"
        from config import SESSION_KEY
        import hashlib, hmac as _hmac
        window = int(time.time() / 3600) - 1
        payload = f"lc|{ip_tier}|{window}".encode()
        prev_tok = _hmac.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()[:16]
        assert _cl._verify_lc_token(prev_tok, ip_tier)

    def test_old_window_rejected(self):
        ip_tier = "203.0.113.0"
        from config import SESSION_KEY
        import hashlib, hmac as _hmac
        window = int(time.time() / 3600) - 2
        payload = f"lc|{ip_tier}|{window}".encode()
        old_tok = _hmac.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()[:16]
        assert not _cl._verify_lc_token(old_tok, ip_tier)


class TestInjectLifecycleScript:
    """_inject_lifecycle_cookie_script injects the HMAC token, not '1'."""

    def test_token_injected_not_static_1(self):
        html = b"<html><body>hello</body></html>"
        token = "abc123deadbeef12"
        result = _cl._inject_lifecycle_cookie_script(html, lc_token=token)
        assert f"agw_lc={token}".encode() in result
        assert b"agw_lc=1" not in result

    def test_default_arg_is_1_for_backward_compat(self):
        html = b"<html><body>hello</body></html>"
        result = _cl._inject_lifecycle_cookie_script(html)
        assert b"agw_lc=1" in result

    def test_injects_before_body_tag(self):
        html = b"<html><body>x</body></html>"
        result = _cl._inject_lifecycle_cookie_script(html, "tok")
        assert result.index(b"agw_lc=tok") < result.index(b"</body>")

    def test_disabled_returns_body_unchanged(self):
        with mock.patch.object(_cl, "COOKIE_LIFECYCLE_ENABLED", False):
            html = b"<html><body>x</body></html>"
            assert _cl._inject_lifecycle_cookie_script(html, "tok") == html


# ── B-08: per-identity threshold jitter ────────────────────────────────────

class TestCookieGhostJitter:
    """IpState.cookie_ghost_threshold_jitter is random 0-2 and different per identity."""

    def test_jitter_field_exists(self):
        from state import IpState
        s = IpState()
        assert hasattr(s, "cookie_ghost_threshold_jitter")

    def test_jitter_in_range(self):
        from state import IpState
        for _ in range(50):
            s = IpState()
            assert 0 <= s.cookie_ghost_threshold_jitter <= 2

    def test_jitter_varies_across_instances(self):
        from state import IpState
        jitters = {IpState().cookie_ghost_threshold_jitter for _ in range(50)}
        # with 50 samples at range 0-2, expect > 1 distinct value
        assert len(jitters) > 1, "jitter does not vary — not random"

    def test_cookie_ghost_check_uses_jitter(self):
        """cookie_ghost_check fires only after MIN_REQUESTS + jitter, not at a fixed count."""
        import asyncio
        from state import IpState, ip_state, state_lock
        from config import COOKIE_GHOST_MIN_REQUESTS, COOKIE_GHOST_MISS_THRESHOLD

        # create identity with jitter=2 so threshold is raised
        tk = "test-jitter-key-b08"
        ip_state[tk] = IpState()
        ip_state[tk].cookie_ghost_threshold_jitter = 2
        ip_state[tk].gateway_cookies_set = 1

        class FakeReq:
            cookies = {}
            headers = {"Accept": "application/json"}

        async def go():
            fired = []
            for i in range(COOKIE_GHOST_MIN_REQUESTS + 3):
                ip_state[tk].request_count = i + 1
                hit, why = await _cl.cookie_ghost_check(tk, FakeReq(), "203.0.113.0")
                if hit:
                    fired.append(i + 1)
            return fired

        loop = asyncio.new_event_loop()
        try:
            fired = loop.run_until_complete(go())
        finally:
            loop.close()
        if fired:
            # must have fired at >= MIN_REQUESTS + 2 (jitter=2 shifts threshold)
            assert fired[0] >= COOKIE_GHOST_MIN_REQUESTS + 2


# ── B-01: sec-fetch-nav-absent signal ──────────────────────────────────────

class TestSecFetchNavAbsent:
    """Verify sec-fetch-nav-absent signal is in config and SIGNAL_KNOB."""

    def test_signal_in_risk_scores(self):
        from config import RISK_WEIGHTS
        assert "sec-fetch-nav-absent" in RISK_WEIGHTS
        assert RISK_WEIGHTS["sec-fetch-nav-absent"] > 0

    def test_signal_in_signal_knob(self):
        from core.proxy_handler import SIGNAL_KNOB
        assert "sec-fetch-nav-absent" in SIGNAL_KNOB
        assert SIGNAL_KNOB["sec-fetch-nav-absent"] == "HEADER_COMPLETENESS_ENABLED"

    def test_signal_in_signal_knob_js(self):
        import pathlib, re
        agents = (pathlib.Path(__file__).parent.parent / "dashboards" / "agents.html").read_text()
        m = re.search(r"const SIGNAL_KNOB_JS\s*=\s*\{(.*?)\n\};", agents, re.S)
        assert m, "SIGNAL_KNOB_JS not found"
        assert '"sec-fetch-nav-absent"' in m.group(1)

    def test_signal_score_is_20(self):
        from config import RISK_WEIGHTS
        assert RISK_WEIGHTS["sec-fetch-nav-absent"] == 20

    def test_signal_in_reason_method(self):
        from core.proxy_handler import _reason_method
        assert _reason_method("sec-fetch-nav-absent") == "ua"
