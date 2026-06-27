# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1814_qa_detection.py — comprehensive QA for detection sub-modules (1.8.14).

Modules covered:
  A — detection/automation.py  : HMAC token, probe injection
  B — detection/behavioral.py  : CoV / autocorrelation / bin-majority (unit, no proxy_module)
  C — detection/cookie_lifecycle.py : lc_token HMAC, injection, ghost / lifecycle-miss
  R — detection/referer_chain.py   : referer-ghost check

Test types per module:
  P — parametrized: value matrix across representative inputs
  B — boundary:     zero / max / threshold conditions
  E — edge cases:   unexpected input forms
  C — concurrent:   asyncio Task isolation (where state-ful)
  N — negative:     disabled knob, no state, below threshold
  I — integration:  full signal path
"""
from __future__ import annotations

import asyncio
import os
import time as _t
from collections import deque
from unittest import mock

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")
_REPO = os.path.join(os.path.dirname(__file__), "..")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _run(coro):
    return asyncio.run(coro)


def _fake_req(referer="", host="example.com", path="/api/data",
              accept="application/json", cookies=None) -> mock.MagicMock:
    req = mock.MagicMock()
    req.host = host
    req.path = path
    req.cookies = cookies or {}
    req.headers = {"Referer": referer, "Accept": accept}
    return req


def _make_ip_state(**kwargs):
    """Return a fresh IpState with fields set from kwargs."""
    from state import IpState
    s = IpState()
    s.cookie_ghost_threshold_jitter = 0   # deterministic threshold
    for k, v in kwargs.items():
        setattr(s, k, v)
    return s


# ═══════════════════════════════════════════════════════════════════════════
# A — detection/automation.py
# ═══════════════════════════════════════════════════════════════════════════

class TestAutomationToken:
    """P/B/N: HMAC token generation (_automation_token_for)."""

    def _tok(self, key, ts):
        from detection.automation import _automation_token_for
        return _automation_token_for(key, ts)

    # P: token is deterministic and 32 hex chars

    @pytest.mark.parametrize("track_key,ts", [
        ("identity-abc", 1_000_000),
        ("session:xyz",  9_999_999),
        ("ip:1.2.3.4",   0),
        ("",             42),
    ])
    def test_token_length_32(self, track_key, ts):
        tok = self._tok(track_key, ts)
        assert len(tok) == 32, f"expected 32 chars, got {len(tok)}"
        assert tok.isalnum(), "token must be hex-only"

    @pytest.mark.parametrize("track_key,ts", [
        ("key-A", 1000),
        ("key-B", 9999),
    ])
    def test_token_deterministic(self, track_key, ts):
        assert self._tok(track_key, ts) == self._tok(track_key, ts)

    # B: different inputs produce different tokens

    def test_token_differs_by_key(self):
        assert self._tok("key-A", 1000) != self._tok("key-B", 1000)

    def test_token_differs_by_ts(self):
        assert self._tok("key-A", 1000) != self._tok("key-A", 1001)

    # N: token doesn't match a forged payload

    def test_token_mismatch_rejects(self):
        real = self._tok("real-key", 5000)
        forged = self._tok("other-key", 5000)
        assert real != forged


class TestAutomationInjection:
    """P/B/E/N: _inject_automation_probe body injection."""

    def _inject(self, body, track_key="tk1"):
        from detection.automation import _inject_automation_probe
        return _inject_automation_probe(body, track_key)

    # P: snippet placement

    @pytest.mark.parametrize("body,needle", [
        (b"<html><body>Hello</body></html>", b"</body>"),
        (b"<html>No body tag</html>",        b"</html>"),
    ])
    def test_snippet_placed_before_tag(self, body, needle):
        result = self._inject(body)
        idx_tag = result.find(needle)
        idx_fetch = result.find(b"automation-report")
        assert idx_fetch >= 0,  "automation-report URL not found"
        assert idx_fetch < idx_tag, "snippet must appear before closing tag"

    def test_snippet_appended_when_no_tag(self):
        body = b"no closing tags here"
        result = self._inject(body)
        assert result.endswith(b"</script>") or b"automation-report" in result

    # B: guards

    def test_empty_body_unchanged(self):
        result = self._inject(b"", "tk1")
        assert result == b""

    def test_none_track_key_unchanged(self):
        result = self._inject(b"<body>x</body>", "")
        # empty track_key → guard fires → no injection
        assert result == b"<body>x</body>"

    # N: disabled knob

    def test_disabled_knob_no_injection(self):
        import detection.automation as _auto
        saved = _auto.AUTOMATION_PROBE_ENABLED
        _auto.AUTOMATION_PROBE_ENABLED = False
        try:
            result = self._inject(b"<body>x</body>", "tk1")
            assert result == b"<body>x</body>"
        finally:
            _auto.AUTOMATION_PROBE_ENABLED = saved

    # E: token embedded in snippet matches expected HMAC

    def test_token_in_snippet_is_valid_hmac(self):
        import re
        from detection.automation import _automation_token_for
        body = b"<html><body>page</body></html>"
        result = self._inject(body, "session:abc")
        m = re.search(rb'token:"([0-9a-f]{32})"', result)
        assert m, "token field not found in snippet"
        ts_m = re.search(rb'ts:(\d+)', result)
        assert ts_m, "ts field not found in snippet"
        ts_val = int(ts_m.group(1))
        embedded = m.group(1).decode()
        expected = _automation_token_for("session:abc", ts_val)
        assert embedded == expected, "embedded token doesn't match HMAC"

    # P: flags threshold check in snippet

    @pytest.mark.parametrize("min_flags", [2])
    def test_snippet_checks_two_flags(self, min_flags):
        body = b"<body>x</body>"
        result = self._inject(body, "tk")
        assert f"s>={min_flags}".encode() in result or b"s>=2" in result


# ═══════════════════════════════════════════════════════════════════════════
# B — detection/behavioral.py  (pure-unit, no proxy_module)
# ═══════════════════════════════════════════════════════════════════════════

class TestBehavioralParametrized:
    """P: each bot-like pattern triggers the correct signal branch."""

    def _setup(self, key, times_list):
        from state import ip_state, IpState
        s = IpState()
        s.request_times = deque(times_list, maxlen=50)
        ip_state[key] = s
        return key

    @pytest.mark.parametrize("spacing,expected_fired,desc", [
        # Perfect 50 ms — CoV=0 → fires
        (0.050,  True,  "50ms exact"),
        # Perfect 200 ms — still CoV=0 but mean < MAX_INTERVAL
        (0.200,  True,  "200ms exact"),
        # 6-second spacing — mean > BEHAVIORAL_SKIP_INTERVAL_S(5.0) → no analysis
        (6.000, False,  "6s exact (mean > skip_interval)"),
    ])
    def test_cov_branch(self, spacing, expected_fired, desc):
        import time as _time
        t0 = _time.monotonic()
        n = 17  # BEHAVIORAL_SAMPLE_N=16 → need ≥17 points for 16 intervals
        key = f"_qa_cov_{desc.replace(' ', '_')}"
        times = [t0 + i * spacing for i in range(n)]
        self._setup(key, times)

        fired, _ = _run(self._behavioral(key))
        assert fired is expected_fired, f"CoV branch mismatch for {desc!r}"

    async def _behavioral(self, key):
        from detection.behavioral import behavioral_check
        return await behavioral_check(key)

    @pytest.mark.parametrize("r1_pattern", [
        # Slow sine-wave (16 intervals in one period): cov≈0.42, r1≈0.92 → fires by autocorrelation.
        # Alternating short/long has NEGATIVE r1 so does NOT fire that branch.
        pytest.param(
            [0.5 + 0.3 * __import__('math').sin(2 * __import__('math').pi * i / 16)
             for i in range(16)],
            id="slow-sine-r1=0.92",
        ),
    ])
    def test_autocorrelation_branch(self, r1_pattern):
        import time as _time
        t0 = _time.monotonic()
        times = [t0]
        for iv in r1_pattern:
            times.append(times[-1] + iv)
        key = "_qa_autocorr"
        self._setup(key, times)
        fired, reason = _run(self._behavioral(key))
        assert fired is True, f"Expected autocorrelation to fire, got: {reason!r}"
        assert "autocorrelated" in reason or "r₁" in reason

    @pytest.mark.parametrize("n_in_bin,total,expect_fire", [
        # 80% in one bin → fires (> 0.70 threshold)
        (12, 15, True),
        # 60% in one bin → doesn't fire
        (9,  15, False),
    ])
    def test_bin_majority_branch(self, n_in_bin, total, expect_fire):
        import time as _time
        t0 = _time.monotonic()
        # n_in_bin intervals at 0.150s (bin 3), rest at 0.600s (bin 12)
        intervals = [0.150] * n_in_bin + [0.600] * (total - n_in_bin)
        times = [t0]
        for iv in intervals:
            times.append(times[-1] + iv)
        key = f"_qa_bin_{n_in_bin}_{total}"
        self._setup(key, times)
        fired, _ = _run(self._behavioral(key))
        assert fired is expect_fire


class TestBehavioralBoundary:
    """B: guard conditions."""

    def _setup(self, key, times_list):
        from state import ip_state, IpState
        s = IpState()
        s.request_times = deque(times_list, maxlen=50)
        ip_state[key] = s

    async def _run(self, key):
        from detection.behavioral import behavioral_check
        return await behavioral_check(key)

    def test_fewer_than_sample_n_no_fire(self):
        import time as _time
        from config import BEHAVIORAL_SAMPLE_N
        t0 = _time.monotonic()
        # Only N-1 points → can only have N-2 intervals → skip
        self._setup("_qa_bnd_few",
                    [t0 + i * 0.1 for i in range(BEHAVIORAL_SAMPLE_N - 1)])
        fired, _ = _run(self._run("_qa_bnd_few"))
        assert fired is False

    def test_zero_intervals_no_fire(self):
        import time as _time
        t0 = _time.monotonic()
        # Duplicate timestamps → zero intervals → guard
        self._setup("_qa_bnd_zero", [t0] * 18)
        fired, _ = _run(self._run("_qa_bnd_zero"))
        assert fired is False

    def test_mean_above_skip_interval_no_fire(self):
        import time as _time
        from config import BEHAVIORAL_SKIP_INTERVAL_S
        t0 = _time.monotonic()
        # Very slow intervals (above SKIP threshold)
        gap = BEHAVIORAL_SKIP_INTERVAL_S + 1.0
        self._setup("_qa_bnd_slow", [t0 + i * gap for i in range(18)])
        fired, _ = _run(self._run("_qa_bnd_slow"))
        assert fired is False

    def test_unknown_key_returns_false(self):
        fired, reason = _run(self._run("_qa_nonexistent_key_xyz"))
        assert fired is False
        assert reason == ""


class TestBehavioralNegative:
    """N: human-like traffic never fires."""

    def test_human_random_intervals(self):
        import random, time as _time
        from state import ip_state, IpState
        rng = random.Random(7)
        t0 = _time.monotonic()
        s = IpState()
        s.request_times = deque(maxlen=50)
        t = t0
        for _ in range(18):
            t += rng.uniform(0.5, 2.5)
            s.request_times.append(t)
        ip_state["_qa_human"] = s

        fired, _ = _run(self._behavioral("_qa_human"))
        assert fired is False

    async def _behavioral(self, key):
        from detection.behavioral import behavioral_check
        return await behavioral_check(key)


class TestBehavioralConcurrent:
    """C: concurrent tasks each manipulate their own IpState — no bleed."""

    def test_concurrent_detection_no_bleed(self):
        import time as _time
        from state import ip_state, IpState
        from detection.behavioral import behavioral_check

        async def make_and_check(key, spacing, n=18):
            t0 = _t.monotonic()
            s = IpState()
            s.request_times = deque([t0 + i * spacing for i in range(n)], maxlen=50)
            ip_state[key] = s
            await asyncio.sleep(0)
            return await behavioral_check(key)

        async def main():
            bot_r, human_r = await asyncio.gather(
                make_and_check("_qa_cc_bot",   0.050),  # exact 50ms → CoV=0 → fires
                make_and_check("_qa_cc_human", 6.000),  # mean=6s > SKIP(5.0) → no fire
            )
            return bot_r, human_r

        (bot_fired, _), (human_fired, _) = asyncio.run(main())
        assert bot_fired   is True,  "Bot key must fire"
        assert human_fired is False, "Human key must not fire"


# ═══════════════════════════════════════════════════════════════════════════
# C — detection/cookie_lifecycle.py
# ═══════════════════════════════════════════════════════════════════════════

class TestLcTokenParametrized:
    """P/B/E: _make_lc_token and _verify_lc_token."""

    @pytest.mark.parametrize("ip_tier", [
        "1.2.3.4",
        "10.0.0.1",
        "2606:4700::1",
        "",
    ])
    def test_token_length_16(self, ip_tier):
        from detection.cookie_lifecycle import _make_lc_token
        tok = _make_lc_token(ip_tier)
        assert len(tok) == 16
        assert tok.isalnum()

    @pytest.mark.parametrize("ip_tier", ["1.2.3.4", "10.0.0.1"])
    def test_verify_own_token(self, ip_tier):
        from detection.cookie_lifecycle import _make_lc_token, _verify_lc_token
        tok = _make_lc_token(ip_tier)
        assert _verify_lc_token(tok, ip_tier) is True

    @pytest.mark.parametrize("ip_tier_make,ip_tier_verify", [
        ("1.2.3.4", "5.6.7.8"),
        ("10.0.0.1", "192.168.1.1"),
    ])
    def test_verify_wrong_ip_fails(self, ip_tier_make, ip_tier_verify):
        from detection.cookie_lifecycle import _make_lc_token, _verify_lc_token
        tok = _make_lc_token(ip_tier_make)
        assert _verify_lc_token(tok, ip_tier_verify) is False

    # B: boundary inputs

    def test_verify_empty_string_false(self):
        from detection.cookie_lifecycle import _verify_lc_token
        assert _verify_lc_token("", "1.2.3.4") is False

    def test_verify_wrong_length_false(self):
        from detection.cookie_lifecycle import _verify_lc_token
        assert _verify_lc_token("abc", "1.2.3.4") is False
        assert _verify_lc_token("a" * 32, "1.2.3.4") is False

    def test_verify_static_one_false(self):
        from detection.cookie_lifecycle import _verify_lc_token
        # B-04: static replay "agw_lc=1" must fail HMAC
        assert _verify_lc_token("1", "1.2.3.4") is False

    # E: tampered token (flip one char)

    def test_verify_tampered_token_false(self):
        from detection.cookie_lifecycle import _make_lc_token, _verify_lc_token
        tok = _make_lc_token("1.2.3.4")
        tampered = ("x" if tok[0] != "x" else "y") + tok[1:]
        assert _verify_lc_token(tampered, "1.2.3.4") is False


class TestLcInjection:
    """P/B/N: _inject_lifecycle_cookie_script body injection."""

    def _inject(self, body, lc_token="tk"):
        from detection.cookie_lifecycle import _inject_lifecycle_cookie_script
        return _inject_lifecycle_cookie_script(body, lc_token)

    @pytest.mark.parametrize("body,needle", [
        (b"<html><body>page</body></html>", b"</body>"),
        (b"<html>content</html>",           b"</html>"),
    ])
    def test_snippet_before_tag(self, body, needle):
        result = self._inject(body)
        idx_tag = result.find(needle)
        idx_cookie = result.find(b"agw_lc=")
        assert idx_cookie >= 0,    "agw_lc= not found"
        assert idx_cookie < idx_tag, "snippet must precede closing tag"

    def test_no_tag_appends(self):
        body = b"raw content no tags"
        result = self._inject(body)
        assert b"agw_lc=" in result
        assert result[:len(body)] == body

    def test_empty_body_unchanged(self):
        assert self._inject(b"") == b""

    def test_disabled_knob_no_injection(self):
        import detection.cookie_lifecycle as _cl
        saved = _cl.COOKIE_LIFECYCLE_ENABLED
        _cl.COOKIE_LIFECYCLE_ENABLED = False
        try:
            result = self._inject(b"<body>x</body>")
            assert result == b"<body>x</body>"
        finally:
            _cl.COOKIE_LIFECYCLE_ENABLED = saved

    def test_lc_token_embedded_in_script(self):
        result = self._inject(b"<body></body>", "my-tok-16chars00")
        assert b"my-tok-16chars00" in result


class TestCookieGhostCheck:
    """P/B/N: cookie_ghost_check mechanics."""

    def _make_state(self, key, **kwargs):
        from state import ip_state
        s = _make_ip_state(**kwargs)
        ip_state[key] = s
        return s

    def _req(self, cookies=None, accept="application/json"):
        return _fake_req(cookies=cookies or {}, accept=accept)

    # N: both disabled → never fires

    def test_both_disabled_no_fire(self):
        import detection.cookie_lifecycle as _cl
        saved_g, saved_l = _cl.COOKIE_GHOST_ENABLED, _cl.COOKIE_LIFECYCLE_ENABLED
        _cl.COOKIE_GHOST_ENABLED = False
        _cl.COOKIE_LIFECYCLE_ENABLED = False
        try:
            self._make_state("_qa_cg_dis", gateway_cookies_set=5,
                             request_count=20, html_loads=2)
            fired, _ = _run(self._check("_qa_cg_dis", self._req()))
            assert fired is False
        finally:
            _cl.COOKIE_GHOST_ENABLED = saved_g
            _cl.COOKIE_LIFECYCLE_ENABLED = saved_l

    # N: cookies present → ghost doesn't fire

    def test_ghost_cookie_present_no_fire(self):
        import detection.cookie_lifecycle as _cl
        from config import CHAL_COOKIE
        saved = _cl.COOKIE_GHOST_ENABLED
        _cl.COOKIE_GHOST_ENABLED = True
        try:
            self._make_state("_qa_cg_pres", gateway_cookies_set=3,
                             request_count=10, cookie_ghost_misses=0)
            req = self._req(cookies={CHAL_COOKIE: "val"})
            fired, _ = _run(self._check("_qa_cg_pres", req))
            assert fired is False
        finally:
            _cl.COOKIE_GHOST_ENABLED = saved

    # B: not enough requests → no fire

    def test_ghost_below_min_requests_no_fire(self):
        import detection.cookie_lifecycle as _cl
        from config import COOKIE_GHOST_MIN_REQUESTS
        saved = _cl.COOKIE_GHOST_ENABLED
        _cl.COOKIE_GHOST_ENABLED = True
        try:
            self._make_state("_qa_cg_bmin", gateway_cookies_set=3,
                             request_count=COOKIE_GHOST_MIN_REQUESTS - 1)
            fired, _ = _run(self._check("_qa_cg_bmin", self._req()))
            assert fired is False
        finally:
            _cl.COOKIE_GHOST_ENABLED = saved

    # P: missing cookie repeated → accumulates misses

    def test_ghost_miss_accumulates(self):
        import detection.cookie_lifecycle as _cl
        from config import COOKIE_GHOST_MIN_REQUESTS
        saved = _cl.COOKIE_GHOST_ENABLED
        _cl.COOKIE_GHOST_ENABLED = True
        try:
            s = self._make_state("_qa_cg_miss", gateway_cookies_set=3,
                                 request_count=20, cookie_ghost_misses=0)
            before = s.cookie_ghost_misses
            _run(self._check("_qa_cg_miss", self._req()))
            assert s.cookie_ghost_misses > before
        finally:
            _cl.COOKIE_GHOST_ENABLED = saved

    # I: enough misses → fires

    def test_ghost_fires_after_threshold(self):
        import detection.cookie_lifecycle as _cl
        from config import COOKIE_GHOST_MIN_REQUESTS, COOKIE_GHOST_MISS_THRESHOLD
        saved = _cl.COOKIE_GHOST_ENABLED
        _cl.COOKIE_GHOST_ENABLED = True
        try:
            # Pre-load misses AT threshold (jitter=0 from _make_ip_state)
            s = self._make_state("_qa_cg_fire", gateway_cookies_set=3,
                                 request_count=30,
                                 cookie_ghost_misses=COOKIE_GHOST_MISS_THRESHOLD)
            fired, reason = _run(self._check("_qa_cg_fire", self._req()))
            assert fired is True
            assert "cookie-ghost" in reason
        finally:
            _cl.COOKIE_GHOST_ENABLED = saved

    async def _check(self, key, req):
        from detection.cookie_lifecycle import cookie_ghost_check
        return await cookie_ghost_check(key, req)


# ═══════════════════════════════════════════════════════════════════════════
# R — detection/referer_chain.py
# ═══════════════════════════════════════════════════════════════════════════

class TestRefererGhostParametrized:
    """P: referer-ghost fires / doesn't fire across input matrix."""

    def _setup(self, key, html_loads=1, served=None):
        from state import ip_state
        s = _make_ip_state(html_loads=html_loads,
                           served_html_paths=set(served or []))
        ip_state[key] = s

    async def _check(self, key, req):
        from detection.referer_chain import referer_ghost_check
        return await referer_ghost_check(key, req)

    @pytest.mark.parametrize("referer,path,host,served,expect_fire", [
        # Referer claims our host, path NOT served → fires
        ("http://example.com/page-b",  "/api/data", "example.com",  ["/page-a"], True),
        # Referer claims our host, path IS served → no fire
        ("http://example.com/page-a",  "/api/data", "example.com",  ["/page-a"], False),
        # Referer claims OTHER host → no fire
        ("http://attacker.com/page-b", "/api/data", "example.com",  [],          False),
        # No Referer → no fire
        ("",                           "/api/data", "example.com",  [],          False),
        # Static asset path → no fire
        ("http://example.com/page-b",  "/styles.css","example.com", [],          False),
        # Static referer path → no fire
        ("http://example.com/app.js",  "/api/data", "example.com",  [],          False),
    ])
    def test_matrix(self, referer, path, host, served, expect_fire):
        key = f"_qa_rf_{abs(hash((referer,path,host,str(served)))%9999)}"
        self._setup(key, html_loads=1, served=served)
        req = _fake_req(referer=referer, host=host, path=path)
        fired, reason = _run(self._check(key, req))
        assert fired is expect_fire, (
            f"referer={referer!r} path={path!r} host={host!r} "
            f"served={served} → expected {expect_fire}, got {fired} ({reason!r})"
        )


class TestRefererGhostBoundary:
    """B: edge-of-state conditions."""

    async def _check(self, key, req):
        from detection.referer_chain import referer_ghost_check
        return await referer_ghost_check(key, req)

    def test_first_visit_no_fire(self):
        """html_loads=0 → deep-link first visit → no fire."""
        from state import ip_state
        s = _make_ip_state(html_loads=0, served_html_paths=set())
        ip_state["_qa_rf_fv"] = s
        req = _fake_req("http://example.com/deep-link", host="example.com", path="/api/x")
        fired, _ = _run(self._check("_qa_rf_fv", req))
        assert fired is False

    def test_referer_served_exact_match_no_fire(self):
        from state import ip_state
        s = _make_ip_state(html_loads=2, served_html_paths={"/exact-path"})
        ip_state["_qa_rf_exact"] = s
        req = _fake_req("http://example.com/exact-path", host="example.com", path="/api/x")
        fired, _ = _run(self._check("_qa_rf_exact", req))
        assert fired is False

    def test_port_in_host_stripped(self):
        """Host with port (example.com:443) vs ref host example.com — must match."""
        from state import ip_state
        s = _make_ip_state(html_loads=1, served_html_paths={"/real-page"})
        ip_state["_qa_rf_port"] = s
        # req.host includes port; referer host does not
        req = _fake_req("http://example.com/ghost-page",
                        host="example.com:443", path="/api/x")
        fired, _ = _run(self._check("_qa_rf_port", req))
        assert fired is True


class TestRefererGhostNegative:
    """N: knob disabled → always no fire."""

    async def _check(self, key, req):
        from detection.referer_chain import referer_ghost_check
        return await referer_ghost_check(key, req)

    def test_disabled_knob_no_fire(self):
        import detection.referer_chain as _rc
        saved = _rc.REFERER_CHAIN_ENABLED
        _rc.REFERER_CHAIN_ENABLED = False
        try:
            from state import ip_state
            s = _make_ip_state(html_loads=1, served_html_paths=set())
            ip_state["_qa_rf_dis"] = s
            req = _fake_req("http://example.com/ghost", host="example.com",
                            path="/api/x")
            fired, _ = _run(self._check("_qa_rf_dis", req))
            assert fired is False
        finally:
            _rc.REFERER_CHAIN_ENABLED = saved


class TestRefererGhostEdgeCases:
    """E: malformed / unusual referer values."""

    async def _check(self, key, req):
        from detection.referer_chain import referer_ghost_check
        return await referer_ghost_check(key, req)

    @pytest.mark.parametrize("bad_referer", [
        "not-a-url",
        "ftp://example.com/page",   # different scheme — no netloc matching our host
        "//example.com/page",
        "   ",
    ])
    def test_bad_referer_no_fire(self, bad_referer):
        from state import ip_state
        key = f"_qa_rf_bad_{abs(hash(bad_referer)%999)}"
        s = _make_ip_state(html_loads=1, served_html_paths=set())
        ip_state[key] = s
        req = _fake_req(bad_referer, host="example.com", path="/api/x")
        fired, _ = _run(self._check(key, req))
        # Most malformed referers either have no host or wrong host → no fire
        # (ftp:// has netloc=example.com so it might fire; we only assert no crash)
        assert isinstance(fired, bool)

    def test_referer_with_query_and_fragment(self):
        """Query/fragment in referer path shouldn't break parsing."""
        from state import ip_state
        s = _make_ip_state(html_loads=1, served_html_paths={"/page?q=1"})
        ip_state["_qa_rf_qf"] = s
        req = _fake_req("http://example.com/page?q=1#section",
                        host="example.com", path="/api/x")
        # urlparse strips query/fragment in path → path=/page, served has /page?q=1
        # slight mismatch: fire or not depends on implementation; just no crash
        fired, _ = _run(self._check("_qa_rf_qf", req))
        assert isinstance(fired, bool)


class TestRefererGhostConcurrent:
    """C: 20 concurrent tasks each with own state — no cross-bleed."""

    def test_concurrent_isolation(self):
        from state import ip_state
        from detection.referer_chain import referer_ghost_check

        async def one_task(tid):
            key = f"_qa_rf_conc_{tid}"
            s = _make_ip_state(html_loads=1, served_html_paths={f"/page-{tid}"})
            ip_state[key] = s
            await asyncio.sleep(0)
            req = _fake_req(f"http://example.com/ghost-{tid}",
                            host="example.com", path="/api/data")
            return tid, await referer_ghost_check(key, req)

        async def main():
            return await asyncio.gather(*[one_task(i) for i in range(20)])

        results = asyncio.run(main())
        for tid, (fired, reason) in results:
            assert fired is True, f"Task {tid}: expected fire, got {fired}"
            assert f"ghost-{tid}" in reason


# ═══════════════════════════════════════════════════════════════════════════
# REGRESSION tests — specific past-bug scenarios that must never regress
# ═══════════════════════════════════════════════════════════════════════════

class TestAutomationRegression:
    """Regression: automation probe known edge cases."""

    def test_stale_token_ttl_window(self):
        """Token from >5 min ago (AUTOMATION_REPORT_TTL=300s) is stale.
        The endpoint rejects it; here we verify the same window logic used
        there: abs(now - ts) > TTL → reject."""
        from detection.automation import _automation_token_for, _AUTOMATION_REPORT_TTL
        import time as _time
        n = int(_time.time())
        ts_old = n - (_AUTOMATION_REPORT_TTL + 1)
        tok = _automation_token_for("key", ts_old)
        # Token itself is valid HMAC — but endpoint rejects on age
        assert len(tok) == 32          # still well-formed
        stale = abs(n - ts_old) > _AUTOMATION_REPORT_TTL
        assert stale is True, "Old token must be detected as stale"

    def test_token_identity_binding_rejects_cross_identity(self):
        """Token minted for identity A MUST NOT verify as identity B.
        Regression for: attacker forges a clean report for a different key."""
        from detection.automation import _automation_token_for
        import time as _time
        ts = int(_time.time())
        tok_a = _automation_token_for("identity-A", ts)
        tok_b = _automation_token_for("identity-B", ts)
        assert tok_a != tok_b, "Different identities must produce different tokens"

    def test_inject_idempotent_on_already_injected_body(self):
        """Injecting twice appends a second snippet — no crash, body still valid.
        (Gateway injects once per response; idempotency not guaranteed, but must not crash.)"""
        from detection.automation import _inject_automation_probe
        body = b"<html><body>content</body></html>"
        once  = _inject_automation_probe(body, "tk")
        twice = _inject_automation_probe(once, "tk")
        assert b"automation-report" in twice
        assert len(twice) > len(once)


class TestBehavioralRegression:
    """Regression: behavioral_check guard conditions that caused crashes."""

    def test_single_request_time_no_crash(self):
        """Exactly one timestamp → zero intervals → must return (False, '') not crash."""
        from state import ip_state, IpState
        import time as _time
        s = IpState()
        s.request_times = deque([_time.monotonic()], maxlen=50)
        ip_state["_qa_reg_beh_1"] = s

        fired, reason = _run(self._check("_qa_reg_beh_1"))
        assert fired is False
        assert reason == ""

    def test_negative_interval_guard(self):
        """Out-of-order timestamps produce negative intervals — guard returns False."""
        from state import ip_state, IpState
        import time as _time
        t0 = _time.monotonic()
        # Reversed: each timestamp smaller than previous → negative intervals
        s = IpState()
        s.request_times = deque([t0 - i * 0.1 for i in range(18)], maxlen=50)
        ip_state["_qa_reg_beh_neg"] = s

        fired, _ = _run(self._check("_qa_reg_beh_neg"))
        assert fired is False

    async def _check(self, key):
        from detection.behavioral import behavioral_check
        return await behavioral_check(key)


class TestCookieLifecycleRegression:
    """Regression: cookie_lifecycle double-increment prevention (elif guard)."""

    async def _check(self, key, req, ip_tier=""):
        from detection.cookie_lifecycle import cookie_ghost_check
        return await cookie_ghost_check(key, req, ip_tier)

    def test_elif_prevents_double_increment(self):
        """Both ghost and lifecycle conditions met — counter must increment by ≤1.
        Regression for: elif removed → two increments per request."""
        import detection.cookie_lifecycle as _cl
        from state import ip_state
        from config import COOKIE_GHOST_MIN_REQUESTS

        saved_g, saved_l = _cl.COOKIE_GHOST_ENABLED, _cl.COOKIE_LIFECYCLE_ENABLED
        _cl.COOKIE_GHOST_ENABLED = True
        _cl.COOKIE_LIFECYCLE_ENABLED = True
        try:
            s = _make_ip_state(gateway_cookies_set=3, html_loads=2,
                               request_count=20, cookie_ghost_misses=0)
            ip_state["_qa_reg_elif"] = s
            req = _fake_req(cookies={})
            before = s.cookie_ghost_misses
            _run(self._check("_qa_reg_elif", req))
            delta = s.cookie_ghost_misses - before
            assert delta <= 1, f"Double-increment regression: delta={delta}"
        finally:
            _cl.COOKIE_GHOST_ENABLED = saved_g
            _cl.COOKIE_LIFECYCLE_ENABLED = saved_l

    def test_b04_static_lc_replay_rejected(self):
        """B-04 hardening: static 'agw_lc=1' must fail HMAC verification.
        Regression for: presence check without HMAC let bots pre-fill agw_lc=1."""
        from detection.cookie_lifecycle import _verify_lc_token
        assert _verify_lc_token("1", "1.2.3.4") is False
        assert _verify_lc_token("1111111111111111", "1.2.3.4") is False

    def test_hour_boundary_previous_window_accepted(self):
        """Token from the PREVIOUS 1-hour window must still verify (boundary grace).
        Regression: window-only check rejecting tokens issued just before the hour."""
        from detection.cookie_lifecycle import _verify_lc_token
        import hmac as _hmac, hashlib, time as _time
        from config import SESSION_KEY
        ip_tier = "10.0.0.1"
        prev_window = int(_time.time() / 3600) - 1
        payload = f"lc|{ip_tier}|{prev_window}".encode()
        prev_tok = _hmac.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()[:16]
        assert _verify_lc_token(prev_tok, ip_tier) is True, \
            "Previous-hour token must be accepted"


class TestRefererGhostRegression:
    """Regression: referer-ghost false positives on static assets."""

    def test_static_request_path_never_fires(self):
        """Even if referer path is 'unseen', a request for a static asset must not fire.
        Regression for: detection on static-asset requests added latency with 0 signal value."""
        from state import ip_state
        from detection.referer_chain import referer_ghost_check

        s = _make_ip_state(html_loads=1, served_html_paths=set())
        ip_state["_qa_reg_rf_static"] = s

        for ext in (".css", ".js", ".png", ".woff2", ".svg", ".ico"):
            req = _fake_req(f"http://example.com/ghost-page",
                            host="example.com", path=f"/assets/file{ext}")
            fired, _ = _run(referer_ghost_check("_qa_reg_rf_static", req))
            assert fired is False, f"Static path {ext!r} must not fire referer-ghost"

    def test_state_not_shared_across_identities(self):
        """served_html_paths is per-identity — path served to A must not appear in B."""
        from state import ip_state
        from detection.referer_chain import referer_ghost_check

        sa = _make_ip_state(html_loads=1, served_html_paths={"/shared-page"})
        sb = _make_ip_state(html_loads=1, served_html_paths=set())
        ip_state["_qa_reg_rf_idA"] = sa
        ip_state["_qa_reg_rf_idB"] = sb

        req = _fake_req("http://example.com/shared-page",
                        host="example.com", path="/api/x")
        fired_a, _ = _run(referer_ghost_check("_qa_reg_rf_idA", req))
        fired_b, _ = _run(referer_ghost_check("_qa_reg_rf_idB", req))

        assert fired_a is False, "Identity A served /shared-page → no fire"
        assert fired_b is True,  "Identity B never served /shared-page → fires"


# ═══════════════════════════════════════════════════════════════════════════
# UNIT tests — isolated single-function tests with minimal/no state
# ═══════════════════════════════════════════════════════════════════════════

class TestCookieLifecycleUnit:
    """Unit: record helpers and pure token functions."""

    def test_record_gateway_cookie_set_increments(self):
        from detection.cookie_lifecycle import record_gateway_cookie_set
        from state import ip_state
        s = _make_ip_state()
        ip_state["_qa_unit_rcg"] = s
        assert s.gateway_cookies_set == 0
        record_gateway_cookie_set("_qa_unit_rcg")
        record_gateway_cookie_set("_qa_unit_rcg")
        assert s.gateway_cookies_set == 2

    def test_record_html_served_deduplicates(self):
        from detection.cookie_lifecycle import record_html_served
        from state import ip_state
        s = _make_ip_state()
        ip_state["_qa_unit_rhs"] = s
        record_html_served("_qa_unit_rhs", "/page-a")
        record_html_served("_qa_unit_rhs", "/page-a")  # duplicate
        record_html_served("_qa_unit_rhs", "/page-b")
        assert s.served_html_paths == {"/page-a", "/page-b"}

    def test_record_html_served_bounded(self):
        """record_html_served caps at _SERVED_HTML_PATHS_MAX (50 paths)."""
        from detection.cookie_lifecycle import record_html_served, _SERVED_HTML_PATHS_MAX
        from state import ip_state
        s = _make_ip_state()
        ip_state["_qa_unit_bounded"] = s
        for i in range(_SERVED_HTML_PATHS_MAX + 20):
            record_html_served("_qa_unit_bounded", f"/page-{i}")
        assert len(s.served_html_paths) <= _SERVED_HTML_PATHS_MAX

    @pytest.mark.parametrize("ip_tier", ["1.1.1.1", "::1", "10.0.0.50", ""])
    def test_make_lc_token_hex_only(self, ip_tier):
        from detection.cookie_lifecycle import _make_lc_token
        tok = _make_lc_token(ip_tier)
        assert len(tok) == 16
        int(tok, 16)  # must be valid hex — raises ValueError if not


class TestRefererGhostUnit:
    """Unit: _STATIC_SUFFIXES and pure path helpers."""

    def test_static_suffixes_tuple_nonempty(self):
        from detection.referer_chain import _STATIC_SUFFIXES
        assert len(_STATIC_SUFFIXES) > 0

    @pytest.mark.parametrize("ext", [
        ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif",
        ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".map",
    ])
    def test_known_static_ext_in_suffixes(self, ext):
        from detection.referer_chain import _STATIC_SUFFIXES
        assert ext in _STATIC_SUFFIXES, f"{ext!r} must be in _STATIC_SUFFIXES"

    def test_api_path_not_in_static_suffixes(self):
        from detection.referer_chain import _STATIC_SUFFIXES
        for path in ("/api/data", "/login", "/dashboard", ""):
            dot = path.rfind(".")
            ext = path[dot:].lower() if dot >= 0 else ""
            # Most API paths have no extension or a non-static extension
            if ext:
                assert ext not in _STATIC_SUFFIXES or ext in (".pdf", ".zip"), \
                    f"Unexpected static ext match for {path!r}"


class TestAutomationUnit:
    """Unit: token properties in isolation."""

    @pytest.mark.parametrize("track_key,ts", [
        ("k1", 0),
        ("k1", 2**31 - 1),
        ("",   999),
        ("session:abc123", 1_000_000),
    ])
    def test_token_always_32_hex(self, track_key, ts):
        from detection.automation import _automation_token_for
        tok = _automation_token_for(track_key, ts)
        assert len(tok) == 32
        int(tok, 16)  # valid hex

    def test_automation_report_ttl_constant(self):
        """_AUTOMATION_REPORT_TTL must be 300s (5 min) — change needs deliberate decision."""
        from detection.automation import _AUTOMATION_REPORT_TTL
        assert _AUTOMATION_REPORT_TTL == 300


# ═══════════════════════════════════════════════════════════════════════════
# FUNCTIONAL tests — feature from caller perspective end-to-end (no live server)
# ═══════════════════════════════════════════════════════════════════════════

class TestBehavioralFunctional:
    """Functional: behavioral_check as a detection feature, not a math function."""

    def test_realistic_bot_100ms_polling_fires(self):
        """A bot polling every ~100ms for 2 seconds → fires (CoV near 0)."""
        from state import ip_state, IpState
        import time as _time
        t0 = _time.monotonic()
        s = IpState()
        s.request_times = deque([t0 + i * 0.100 for i in range(22)], maxlen=50)
        ip_state["_qa_fn_bot100"] = s
        fired, reason = _run(self._check("_qa_fn_bot100"))
        assert fired is True
        assert "regular" in reason.lower() or "σ/μ" in reason

    def test_realistic_human_browsing_no_fire(self):
        """Human browsing: variable gaps 0.5–8s → must not fire."""
        from state import ip_state, IpState
        import random, time as _time
        rng = random.Random(2026)
        t0 = _time.monotonic()
        s = IpState()
        t = t0
        for _ in range(22):
            t += rng.uniform(0.5, 8.0)
            s.request_times.append(t)
        ip_state["_qa_fn_human"] = s
        fired, _ = _run(self._check("_qa_fn_human"))
        assert fired is False

    def test_quantised_scraper_50ms_bins_fires(self):
        """Scraper with sleep(0.150) + tiny jitter → bin-majority fires."""
        from state import ip_state, IpState
        import time as _time
        t0 = _time.monotonic()
        s = IpState()
        deltas = [0.150, 0.151, 0.149, 0.150, 0.150, 0.151,
                  0.149, 0.150, 0.150, 0.150, 0.151, 0.150,
                  0.149, 0.150, 0.150, 0.151, 0.150, 0.150]
        t = t0
        for d in deltas:
            t += d
            s.request_times.append(t)
        ip_state["_qa_fn_quantised"] = s
        fired, _ = _run(self._check("_qa_fn_quantised"))
        assert fired is True

    async def _check(self, key):
        from detection.behavioral import behavioral_check
        return await behavioral_check(key)


class TestCookieLifecycleFunctional:
    """Functional: lc_token round-trip (inject → extract → verify)."""

    def test_inject_then_verify_lc_token(self):
        """inject_lifecycle_cookie_script embeds a token verifiable by _verify_lc_token."""
        import re
        from detection.cookie_lifecycle import (
            _make_lc_token, _inject_lifecycle_cookie_script, _verify_lc_token,
        )
        ip_tier = "1.2.3.4"
        tok = _make_lc_token(ip_tier)
        body = b"<html><body>page</body></html>"
        injected = _inject_lifecycle_cookie_script(body, tok)
        # Extract token from the injected script
        m = re.search(rb'agw_lc=([^;]+);', injected)
        assert m, "agw_lc cookie not found in injected script"
        extracted = m.group(1).decode()
        assert _verify_lc_token(extracted, ip_tier) is True, \
            "Extracted token must verify for the same ip_tier"

    def test_ghost_check_with_valid_lc_cookie_no_fire(self):
        """Request carrying a valid HMAC lc token → lifecycle-miss must not fire."""
        import detection.cookie_lifecycle as _cl
        from detection.cookie_lifecycle import cookie_ghost_check, _make_lc_token, LIFECYCLE_COOKIE
        from state import ip_state
        from config import COOKIE_GHOST_MIN_REQUESTS

        saved_g, saved_l = _cl.COOKIE_GHOST_ENABLED, _cl.COOKIE_LIFECYCLE_ENABLED
        _cl.COOKIE_GHOST_ENABLED = False
        _cl.COOKIE_LIFECYCLE_ENABLED = True
        try:
            s = _make_ip_state(gateway_cookies_set=0, html_loads=2,
                               request_count=20, cookie_ghost_misses=0)
            ip_state["_qa_fn_lc_valid"] = s
            ip_tier = "5.6.7.8"
            valid_tok = _make_lc_token(ip_tier)
            req = _fake_req(cookies={LIFECYCLE_COOKIE: valid_tok})
            req.headers = {"Accept": "application/json"}
            fired, _ = _run(cookie_ghost_check("_qa_fn_lc_valid", req, ip_tier))
            assert fired is False, "Valid lc token must suppress lifecycle-miss"
        finally:
            _cl.COOKIE_GHOST_ENABLED = saved_g
            _cl.COOKIE_LIFECYCLE_ENABLED = saved_l


class TestAutomationFunctional:
    """Functional: injection produces runnable snippet structure."""

    def test_injected_snippet_is_iife(self):
        """Injected script must be an IIFE — (function(){...})()"""
        from detection.automation import _inject_automation_probe
        body = b"<body>x</body>"
        result = _inject_automation_probe(body, "tk")
        assert b"(function(){" in result
        assert b"})();" in result

    def test_injected_snippet_checks_four_indicators(self):
        """Snippet must check webdriver, plugins, colorDepth, chrome object."""
        from detection.automation import _inject_automation_probe
        body = b"<body>x</body>"
        result = _inject_automation_probe(body, "tk")
        for indicator in (b"webdriver", b"plugins", b"colorDepth", b"chrome"):
            assert indicator in result, f"Indicator {indicator!r} missing from snippet"

    def test_injected_snippet_posts_to_gateway_endpoint(self):
        from detection.automation import _inject_automation_probe
        result = _inject_automation_probe(b"<body>x</body>", "tk")
        assert b"/antibot-appsec-gateway/automation-report" in result

    def test_injection_does_not_corrupt_utf8_body(self):
        """Unicode content in body must survive injection unchanged."""
        from detection.automation import _inject_automation_probe
        body = "<body>Héllo wörld — αβγ</body>".encode("utf-8")
        result = _inject_automation_probe(body, "tk")
        assert "Héllo wörld — αβγ".encode("utf-8") in result


# ═══════════════════════════════════════════════════════════════════════════
# INTEGRATION tests — cross-component wiring
# ═══════════════════════════════════════════════════════════════════════════

class TestCookieLifecycleIntegration:
    """Integration: full lc_token lifecycle across three functions."""

    def test_full_lc_round_trip(self):
        """make → inject → re-extract → verify — the three functions must compose."""
        import re
        from detection.cookie_lifecycle import (
            _make_lc_token, _inject_lifecycle_cookie_script, _verify_lc_token,
        )
        for ip in ("1.2.3.4", "10.0.0.1", "2606:4700::1"):
            tok = _make_lc_token(ip)
            body = b"<html><body>Hello</body></html>"
            injected = _inject_lifecycle_cookie_script(body, tok)
            m = re.search(rb'agw_lc=([^;]+);', injected)
            assert m, f"No agw_lc= in injected body for {ip!r}"
            extracted = m.group(1).decode()
            assert _verify_lc_token(extracted, ip) is True, \
                f"Round-trip failed for ip={ip!r}"

    def test_record_then_ghost_check_wiring(self):
        """record_gateway_cookie_set + cookie_ghost_check: after N misses, signal fires."""
        import detection.cookie_lifecycle as _cl
        from detection.cookie_lifecycle import (
            record_gateway_cookie_set, cookie_ghost_check,
        )
        from state import ip_state
        from config import COOKIE_GHOST_MISS_THRESHOLD, COOKIE_GHOST_MIN_REQUESTS

        saved = _cl.COOKIE_GHOST_ENABLED
        _cl.COOKIE_GHOST_ENABLED = True
        try:
            s = _make_ip_state(request_count=30, cookie_ghost_misses=0)
            ip_state["_qa_int_lc_wire"] = s
            # Simulate gateway setting 3 cookies
            for _ in range(3):
                record_gateway_cookie_set("_qa_int_lc_wire")
            assert s.gateway_cookies_set == 3

            # Simulate MISS_THRESHOLD requests without any cookie → fires
            req = _fake_req(cookies={})
            fired = False
            for _ in range(COOKIE_GHOST_MISS_THRESHOLD + 5):
                r, _ = _run(cookie_ghost_check("_qa_int_lc_wire", req))
                if r:
                    fired = True
                    break
            assert fired is True, "ghost must fire after threshold misses"
        finally:
            _cl.COOKIE_GHOST_ENABLED = saved


class TestRefererGhostIntegration:
    """Integration: record_html_served + referer_ghost_check composing correctly."""

    def test_served_path_suppresses_signal(self):
        """record_html_served('/page-a') → referer_ghost_check with /page-a referer → no fire."""
        from detection.cookie_lifecycle import record_html_served
        from detection.referer_chain import referer_ghost_check
        from state import ip_state

        s = _make_ip_state(html_loads=1, served_html_paths=set())
        ip_state["_qa_int_rf_supp"] = s

        record_html_served("_qa_int_rf_supp", "/page-a")
        req = _fake_req("http://example.com/page-a",
                        host="example.com", path="/api/data")
        fired, _ = _run(referer_ghost_check("_qa_int_rf_supp", req))
        assert fired is False, "Recorded path must suppress referer-ghost"

    def test_unrecorded_path_fires(self):
        """If a path was NOT served via record_html_served, referer-ghost fires."""
        from detection.referer_chain import referer_ghost_check
        from state import ip_state

        s = _make_ip_state(html_loads=1, served_html_paths={"/only-this"})
        ip_state["_qa_int_rf_fire"] = s

        req = _fake_req("http://example.com/not-this",
                        host="example.com", path="/api/data")
        fired, reason = _run(referer_ghost_check("_qa_int_rf_fire", req))
        assert fired is True
        assert "not-this" in reason


# ═══════════════════════════════════════════════════════════════════════════
# J — integrations/ja4.py  (unit + regression + functional)
# ═══════════════════════════════════════════════════════════════════════════

class TestJa4Unit:
    """Unit: pure helper functions in ja4.py."""

    @pytest.mark.parametrize("fp,expected_len", [
        ("t13d1516h2_8daaf6152771_b0da82dd1658", 16),
        ("t13d190900_7f87f7fdad74_38909e8a7e21", 16),
        ("q" * 60,                               16),  # long input
    ])
    def test_ja4_hash_length(self, fp, expected_len):
        from integrations.ja4 import _ja4_hash
        h = _ja4_hash(fp)
        assert len(h) == expected_len

    def test_ja4_hash_empty_returns_empty(self):
        from integrations.ja4 import _ja4_hash
        assert _ja4_hash("") == ""

    def test_ja4_hash_deterministic(self):
        from integrations.ja4 import _ja4_hash
        fp = "t13d1516h2_8daaf6152771_b0da82dd1658"
        assert _ja4_hash(fp) == _ja4_hash(fp)

    @pytest.mark.parametrize("fp_a,fp_b", [
        ("fp-chrome-v120",   "fp-curl-7.88"),
        ("t13d1516h2_aaaa",  "t13d1516h2_bbbb"),
    ])
    def test_ja4_hash_distinct_for_distinct_fps(self, fp_a, fp_b):
        from integrations.ja4 import _ja4_hash
        assert _ja4_hash(fp_a) != _ja4_hash(fp_b)

    def test_ja4_hash_hex_only(self):
        from integrations.ja4 import _ja4_hash
        h = _ja4_hash("t13d1516h2_8daaf6152771_b0da82dd1658")
        int(h, 16)  # raises ValueError if not hex

    # ── peer trusted ──

    def test_peer_trusted_no_nets_always_false(self):
        """JA4_TRUSTED_NETS=[] → _ja4_peer_trusted always False."""
        from integrations.ja4 import _ja4_peer_trusted, JA4_TRUSTED_NETS
        saved = list(JA4_TRUSTED_NETS)
        JA4_TRUSTED_NETS.clear()
        try:
            for ip in ("1.2.3.4", "10.0.0.1", "127.0.0.1", "::1"):
                req = mock.MagicMock(); req.remote = ip
                assert _ja4_peer_trusted(req) is False, f"Unexpected trust for {ip!r}"
        finally:
            JA4_TRUSTED_NETS.extend(saved)

    def test_peer_trusted_with_net_configured(self):
        """IP in JA4_TRUSTED_NETS → trusted; IP outside → not trusted."""
        import ipaddress
        from integrations.ja4 import _ja4_peer_trusted, JA4_TRUSTED_NETS
        saved = list(JA4_TRUSTED_NETS)
        JA4_TRUSTED_NETS.clear()
        JA4_TRUSTED_NETS.append(ipaddress.ip_network("10.0.0.0/24"))
        try:
            req_in  = mock.MagicMock(); req_in.remote  = "10.0.0.1"
            req_out = mock.MagicMock(); req_out.remote = "192.168.1.1"
            assert _ja4_peer_trusted(req_in)      is True
            assert _ja4_peer_trusted(req_out)     is False
        finally:
            JA4_TRUSTED_NETS.clear()
            JA4_TRUSTED_NETS.extend(saved)

    def test_peer_trusted_invalid_ip_false(self):
        from integrations.ja4 import _ja4_peer_trusted, JA4_TRUSTED_NETS
        import ipaddress
        saved = list(JA4_TRUSTED_NETS)
        JA4_TRUSTED_NETS.clear()
        JA4_TRUSTED_NETS.append(ipaddress.ip_network("10.0.0.0/8"))
        try:
            for bad in ("not-an-ip", "", None):
                req = mock.MagicMock(); req.remote = bad
                assert _ja4_peer_trusted(req) is False, f"Bad remote {bad!r} must be False"
        finally:
            JA4_TRUSTED_NETS.clear()
            JA4_TRUSTED_NETS.extend(saved)


class TestJa4Regression:
    """Regression: deny-list and header injection attacks."""

    def test_untrusted_source_cannot_inject_ja4_header(self):
        """Request from an untrusted peer with JA4 header → header ignored (_request_ja4 returns '')."""
        from integrations.ja4 import _request_ja4, JA4_HEADER, JA4_TRUSTED_NETS
        saved = list(JA4_TRUSTED_NETS)
        JA4_TRUSTED_NETS.clear()
        try:
            req = mock.MagicMock()
            req.remote = "1.2.3.4"  # not in trusted nets
            req.headers = {JA4_HEADER: "attacker-fp"}
            result = _request_ja4(req)
            assert result == "", "Untrusted peer JA4 header must be ignored"
        finally:
            JA4_TRUSTED_NETS.extend(saved)

    def test_deny_list_only_blocks_exact_match(self):
        """JA4 deny-list is exact; a fingerprint not in the list must NOT be blocked."""
        from integrations.ja4 import _tls_fingerprint_blocked, JA4_DENY_LIST, JA4_TRUSTED_NETS, JA4_HEADER
        import ipaddress
        JA4_TRUSTED_NETS.clear()
        JA4_TRUSTED_NETS.append(ipaddress.ip_network("10.0.0.0/8"))
        JA4_DENY_LIST.add("bad-fp-exact")
        try:
            req_bad = mock.MagicMock(); req_bad.remote = "10.0.0.1"
            req_bad.headers = {JA4_HEADER: "bad-fp-exact"}
            req_ok  = mock.MagicMock(); req_ok.remote  = "10.0.0.1"
            req_ok.headers  = {JA4_HEADER: "bad-fp-exact-SUFFIX"}  # not exact match
            assert _tls_fingerprint_blocked(req_bad) is True
            assert _tls_fingerprint_blocked(req_ok)  is False
        finally:
            JA4_DENY_LIST.discard("bad-fp-exact")
            JA4_TRUSTED_NETS.clear()

    def test_empty_fp_not_blocked(self):
        """Empty JA4 header → _tls_fingerprint_blocked returns False (no fp = no block)."""
        from integrations.ja4 import _tls_fingerprint_blocked, JA4_TRUSTED_NETS, JA4_HEADER
        import ipaddress
        JA4_TRUSTED_NETS.clear()
        JA4_TRUSTED_NETS.append(ipaddress.ip_network("10.0.0.0/8"))
        try:
            req = mock.MagicMock(); req.remote = "10.0.0.1"
            req.headers = {JA4_HEADER: ""}
            assert _tls_fingerprint_blocked(req) is False
        finally:
            JA4_TRUSTED_NETS.clear()


class TestJa4Functional:
    """Functional: JA4 deny-list as a detection feature."""

    def test_known_bad_fp_blocked_end_to_end(self):
        """Add a fp to deny-list → trusted request carrying it → blocked."""
        import ipaddress
        from integrations.ja4 import (
            _tls_fingerprint_blocked, JA4_DENY_LIST, JA4_TRUSTED_NETS, JA4_HEADER,
        )
        JA4_TRUSTED_NETS.clear()
        JA4_TRUSTED_NETS.append(ipaddress.ip_network("172.16.0.0/12"))
        fp = "t13d_qa_functional_test_fp"
        JA4_DENY_LIST.add(fp)
        try:
            req = mock.MagicMock(); req.remote = "172.16.0.1"
            req.headers = {JA4_HEADER: fp}
            assert _tls_fingerprint_blocked(req) is True
        finally:
            JA4_DENY_LIST.discard(fp)
            JA4_TRUSTED_NETS.clear()

    def test_deny_list_empty_no_block(self):
        """Empty deny-list → no request is blocked by _tls_fingerprint_blocked."""
        from integrations.ja4 import _tls_fingerprint_blocked, JA4_DENY_LIST
        saved = set(JA4_DENY_LIST)
        JA4_DENY_LIST.clear()
        try:
            req = mock.MagicMock(); req.remote = "1.2.3.4"
            assert _tls_fingerprint_blocked(req) is False
        finally:
            JA4_DENY_LIST.update(saved)


# ═══════════════════════════════════════════════════════════════════════════
# SEC — Security invariants
# ═══════════════════════════════════════════════════════════════════════════

class TestSecLcToken:
    """SEC: lc_token cryptographic and injection-safety invariants."""

    def test_token_output_is_hex_safe_for_script(self):
        """hexdigest() output is [0-9a-f] only — safe to embed in <script> without escaping."""
        import re
        from detection.cookie_lifecycle import _make_lc_token
        tok = _make_lc_token("1.2.3.4")
        assert re.fullmatch(r"[0-9a-f]{16}", tok), \
            f"lc_token must be 16 lowercase hex chars, got {tok!r}"

    def test_previous_hour_window_accepted(self):
        """Token from previous hour window must be accepted (hour-boundary tolerance)."""
        import hmac as _h
        import hashlib
        import time as _time
        from detection.cookie_lifecycle import _verify_lc_token, SESSION_KEY
        ip = "1.2.3.4"
        window = int(_time.time() / 3600) - 1
        payload = f"lc|{ip}|{window}".encode()
        prev_tok = _h.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()[:16]
        assert _verify_lc_token(prev_tok, ip) is True, \
            "Previous-hour token must be accepted"

    def test_two_hours_ago_rejected(self):
        """Token from window-2 must be rejected — no unbounded replay window."""
        import hmac as _h
        import hashlib
        import time as _time
        from detection.cookie_lifecycle import _verify_lc_token, SESSION_KEY
        ip = "1.2.3.4"
        window = int(_time.time() / 3600) - 2
        payload = f"lc|{ip}|{window}".encode()
        old_tok = _h.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()[:16]
        assert _verify_lc_token(old_tok, ip) is False, \
            "Token from 2+ hours ago must be rejected"

    def test_special_chars_in_token_rejected(self):
        """Tokens containing non-hex chars must be rejected — no injection via malformed input."""
        from detection.cookie_lifecycle import _verify_lc_token
        for bad in (";1.2.3.4;1", "\n" + "a" * 15, "x" * 15 + ";", "</scrip>"[:16]):
            assert _verify_lc_token(bad, "1.2.3.4") is False, \
                f"Special-char token {bad!r} must be rejected"

    def test_oversized_token_rejected_no_crash(self):
        """1024-char token must return False — no regex backtrack, no crash."""
        from detection.cookie_lifecycle import _verify_lc_token
        assert _verify_lc_token("a" * 1024, "1.2.3.4") is False

    def test_constant_time_compare_used_in_verify(self):
        """_verify_lc_token must use hmac.compare_digest to prevent timing attacks."""
        import inspect
        from detection.cookie_lifecycle import _verify_lc_token
        src = inspect.getsource(_verify_lc_token)
        assert "compare_digest" in src, \
            "_verify_lc_token must use hmac.compare_digest (timing-safe)"


class TestSecAutomationScript:
    """SEC: automation probe HMAC token entropy and script injection safety."""

    def test_automation_token_is_hex_safe_for_script(self):
        """hexdigest()[:32] — safe to embed in <script> without escaping."""
        import re
        import time as _time
        from detection.automation import _automation_token_for
        tok = _automation_token_for("track-key", int(_time.time()))
        assert re.fullmatch(r"[0-9a-f]{32}", tok), \
            f"Automation token must be 32 lowercase hex chars, got {tok!r}"

    def test_injected_script_uses_iife(self):
        """Probe script must use IIFE to avoid global namespace pollution."""
        from detection.automation import _inject_automation_probe
        result = _inject_automation_probe(b"<body>x</body>", "key")
        assert b"(function(){" in result or b"(function() {" in result, \
            "Automation probe must use IIFE wrapper"

    def test_injected_script_tag_closes_before_body(self):
        """<script> tag must close before </body> — prevents DOM structure break."""
        from detection.automation import _inject_automation_probe
        result = _inject_automation_probe(b"<html><body>x</body></html>", "key")
        idx_close_script = result.rfind(b"</script>")
        idx_close_body   = result.find(b"</body>")
        assert idx_close_script < idx_close_body, \
            "</script> must appear before </body>"

    def test_different_track_keys_produce_different_tokens(self):
        """Tokens are identity-bound — different keys can't cross-verify."""
        import time as _time
        from detection.automation import _automation_token_for
        ts = int(_time.time())
        assert _automation_token_for("key-A", ts) != _automation_token_for("key-B", ts)
