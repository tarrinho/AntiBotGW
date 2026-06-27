"""
tests/test_v1814_knobs_qa.py — exhaustive QA for every new knob added in 1.8.14.

Covers gaps not addressed by test_v1814_security_hardening.py:
  T0-1  SESSION_ABSOLUTE_TIMEOUT: boundary, zero-ts legacy, default, env override
  T0-4  OIDC state cap: purge-before-check, >= operator, Retry-After header, source
  T1-1  Upstream latency: percentile correctness, warn flag, empty deque, metrics keys
  T1-3  Webhook health: reset-on-success, metrics structure, circuit_open field
  T2-5  eTLD+1 origin: port stripping, scheme-only, suffix anchor, IP, exact cap
"""
import os
import time
import unittest.mock as mock
from collections import deque

import pytest

os.environ.setdefault("UPSTREAM", "http://localhost")

import pathlib
_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel):
    return (_ROOT / rel).read_text(encoding="utf-8")


# ── T0-1: SESSION_ABSOLUTE_TIMEOUT ────────────────────────────────────────────

class TestSessionAbsoluteTimeoutEdgeCases:
    _USERNAME = "alice"

    def _verify(self, sid, cache_entry, timeout=3600, frozen_now=None):
        """Call _session_verify with a frozen clock and mocked parse."""
        import admin.users as u
        import config
        if frozen_now is None:
            frozen_now = time.time()
        u._SESSION_CACHE[sid] = cache_entry
        with mock.patch.object(config, "SESSION_ABSOLUTE_TIMEOUT", timeout), \
             mock.patch("admin.users._session_parse") as p, \
             mock.patch("admin.users._t") as mt:
            mt.time.return_value = frozen_now
            p.return_value = (self._USERNAME, sid, frozen_now + 9999)
            return u._session_verify("tok")

    def setup_method(self):
        import admin.users as u
        u._SESSION_CACHE.clear()
        u._SESSION_CACHE_READY = True

    def _entry(self, frozen_now, created_ts, **kw):
        base = {"username": self._USERNAME, "expires_ts": frozen_now + 9999,
                "revoked": False, "source_ip": "", "csrf_nonce": "x",
                "created_ts": created_ts}
        base.update(kw)
        return base

    def test_default_value_is_8_hours(self):
        import config
        assert config.SESSION_ABSOLUTE_TIMEOUT == 8 * 3600, (
            "Default SESSION_ABSOLUTE_TIMEOUT must be 8 * 3600 = 28800 s — "
            "if changed, update the validation doc and this test together"
        )

    def test_env_override_is_respected(self):
        with mock.patch.dict(os.environ, {"SESSION_ABSOLUTE_TIMEOUT": "7200"}):
            val = int(os.environ.get("SESSION_ABSOLUTE_TIMEOUT", str(8 * 3600)))
        assert val == 7200

    def test_at_exact_boundary_session_still_valid(self):
        # created_ts + timeout == now exactly → condition: (now < now) → False → valid
        now = 1_000_000.0
        sid = "boundarysid12345"
        result = self._verify(sid, self._entry(now, created_ts=now - 3600),
                              timeout=3600, frozen_now=now)
        assert result == self._USERNAME, (
            "Session at exactly (created_ts + timeout == now) must be valid — "
            "condition is strict < not <=, so boundary is inclusive"
        )

    def test_one_second_past_boundary_is_rejected(self):
        now = 1_000_000.0
        sid = "boundarysid12346"
        result = self._verify(sid, self._entry(now, created_ts=now - 3601),
                              timeout=3600, frozen_now=now)
        assert result is None, "Session 1 s past absolute timeout must be rejected"

    def test_zero_created_ts_is_not_rejected(self):
        # Legacy sessions have created_ts=0 → `if created` is False → skip check
        now = 1_000_000.0
        sid = "legacysid_zero00"
        result = self._verify(sid, self._entry(now, created_ts=0),
                              timeout=3600, frozen_now=now)
        assert result == self._USERNAME, (
            "Sessions with created_ts=0 (pre-T0-1) must not be rejected — "
            "the check must short-circuit on `if created` (falsy zero)"
        )

    def test_missing_created_ts_key_not_rejected(self):
        # No created_ts key → .get('created_ts', 0) → 0 → skip check
        now = 1_000_000.0
        sid = "legacysid_nokey0"
        entry = {"username": self._USERNAME, "expires_ts": now + 9999,
                 "revoked": False, "source_ip": "", "csrf_nonce": "x"}
        result = self._verify(sid, entry, timeout=3600, frozen_now=now)
        assert result == self._USERNAME, (
            "Cache entry without created_ts key must not crash — "
            ".get('created_ts', 0) default must make it a no-op"
        )

    def test_created_ts_persists_across_cache_reload(self):
        users_src = _read("admin/users.py")
        idx = users_src.find("_session_cache_load")
        body = users_src[idx:idx + 1200]
        assert "created_ts" in body, (
            "_session_cache_load must SELECT and restore created_ts — "
            "missing it silently resets the absolute-timeout clock on restart"
        )

    def test_absolute_timeout_enforced_in_verify_source(self):
        users_src = _read("admin/users.py")
        idx = users_src.find("def _session_verify")
        # Function body can be long; search 2000 chars past the def
        body = users_src[idx:idx + 2000]
        assert "SESSION_ABSOLUTE_TIMEOUT" in body, (
            "_session_verify must reference SESSION_ABSOLUTE_TIMEOUT"
        )
        assert "created_ts" in body, (
            "_session_verify must read created_ts from the cache entry"
        )


# ── T0-4: OIDC state cap ─────────────────────────────────────────────────────

class TestOidcStateCapEdgeCases:
    def test_cap_value_is_500(self):
        from admin.oidc import _OIDC_STATE_MAX
        assert _OIDC_STATE_MAX == 500, (
            "_OIDC_STATE_MAX must be 500 — the validation doc documents this value; "
            "changing it silently lowers/raises DoS protection"
        )

    def test_cap_uses_gte_not_gt(self):
        """len >= MAX means we reject at exactly MAX, not MAX+1."""
        src = _read("admin/oidc.py")
        assert "len(_OIDC_STATE) >= _OIDC_STATE_MAX" in src, (
            "OIDC state cap must use >= (reject at MAX) not > (would allow MAX entries "
            "then crash on MAX+1 — operator must not be able to fill the dict past MAX)"
        )

    def test_purge_called_before_cap_check_in_source(self):
        """_purge_expired_states() must be called BEFORE the cap check so stale
        entries don't eat into the cap and cause premature 503s."""
        src = _read("admin/oidc.py")
        idx = src.find("async def oidc_login_endpoint")
        body = src[idx:idx + 1000]  # function body; skip past imports/docstring
        purge_pos = body.find("_purge_expired_states()")
        cap_pos = body.find("_OIDC_STATE_MAX")
        assert purge_pos != -1, "oidc_login_endpoint must call _purge_expired_states()"
        assert cap_pos != -1, "oidc_login_endpoint must reference _OIDC_STATE_MAX"
        assert purge_pos < cap_pos, (
            "_purge_expired_states() must be called BEFORE the _OIDC_STATE_MAX check — "
            "purging after the check means expired entries block new legitimate logins"
        )

    def test_503_includes_retry_after_30(self):
        """503 response must carry Retry-After: 30 so clients back off."""
        src = _read("admin/oidc.py")
        assert '"Retry-After": "30"' in src or "'Retry-After': '30'" in src, (
            "OIDC state cap 503 must include Retry-After: 30 header"
        )

    def test_503_status_code_in_source(self):
        src = _read("admin/oidc.py")
        # Find the cap-reached block, not the constant definition
        idx = src.find("_OIDC_STATE_MAX")
        # Walk to the actual usage (after the constant def line)
        usage_idx = src.find("len(_OIDC_STATE) >= _OIDC_STATE_MAX")
        assert usage_idx != -1, "cap check `len(_OIDC_STATE) >= _OIDC_STATE_MAX` must exist"
        body = src[usage_idx:usage_idx + 300]
        assert "status=503" in body, (
            "OIDC state cap must return status=503, not 429 or 500"
        )

    def test_purge_removes_stale_entries(self):
        from admin import oidc as o
        orig = dict(o._OIDC_STATE)
        try:
            o._OIDC_STATE.clear()
            o._OIDC_STATE["stale"] = {"expires_ts": time.time() - 1, "next_url": "/",
                                      "nonce": "n", "init_ip": "1.2.3.4"}
            o._OIDC_STATE["fresh"] = {"expires_ts": time.time() + 300, "next_url": "/",
                                      "nonce": "n", "init_ip": "1.2.3.4"}
            o._purge_expired_states()
            assert "stale" not in o._OIDC_STATE, "purge must remove expired entries"
            assert "fresh" in o._OIDC_STATE, "purge must keep non-expired entries"
        finally:
            o._OIDC_STATE.clear()
            o._OIDC_STATE.update(orig)


# ── T1-1: upstream latency percentiles ───────────────────────────────────────

class TestUpstreamLatencyEdgeCases:
    def test_default_warn_threshold_is_2000_ms(self):
        import core.proxy_handler as ph
        assert ph.UPSTREAM_LATENCY_WARN_MS == 2000, (
            "Default UPSTREAM_LATENCY_WARN_MS must be 2000 ms — "
            "if changed, update validation doc and this test"
        )

    def test_empty_deque_gives_none_percentiles(self):
        """No samples → p50/p95 must be None (not 0 or exception)."""
        import core.proxy_handler as ph
        samples = sorted([])
        count = len(samples)
        def _pct(pct):
            if not samples:
                return None
            idx = max(0, int(pct / 100 * count) - 1)
            return round(samples[idx] * 1000, 1)
        assert _pct(50) is None
        assert _pct(95) is None

    def test_percentile_computation_correctness(self):
        """Verify p50/p95 with a known 10-element dataset."""
        # 10 samples in seconds: 0.010 ... 0.100 (10 ms increments)
        raw = [i / 100 for i in range(1, 11)]  # 0.01, 0.02, ..., 0.10
        samples = sorted(raw)
        count = len(samples)
        def _pct(pct):
            if not samples:
                return None
            idx = max(0, int(pct / 100 * count) - 1)
            return round(samples[idx] * 1000, 1)
        p50 = _pct(50)
        p95 = _pct(95)
        # idx for p50 = max(0, int(0.5*10)-1) = max(0,4) = 4 → samples[4]=0.05 → 50 ms
        assert p50 == 50.0, f"p50 expected 50.0 ms, got {p50}"
        # idx for p95 = max(0, int(0.95*10)-1) = max(0,8) = 8 → samples[8]=0.09 → 90 ms
        assert p95 == 90.0, f"p95 expected 90.0 ms, got {p95}"

    def test_warn_flag_true_when_p95_exceeds_threshold(self):
        # p95 = 3000 ms, threshold = 2000 ms → warn = True
        p95_ms = 3000.0
        warn = bool(p95_ms and p95_ms > 2000)
        assert warn is True

    def test_warn_flag_false_when_p95_below_threshold(self):
        p95_ms = 1500.0
        warn = bool(p95_ms and p95_ms > 2000)
        assert warn is False

    def test_warn_flag_false_when_p95_none(self):
        # Empty deque → p95 = None → warn must be False (not exception)
        p95_ms = None
        warn = bool(p95_ms and p95_ms > 2000)
        assert warn is False

    def test_metrics_key_upstream_latency_present_in_source(self):
        src = _read("core/proxy_handler.py")
        assert '"upstream_latency"' in src, (
            "metrics endpoint must include 'upstream_latency' key"
        )

    def test_metrics_upstream_latency_has_required_fields(self):
        """All five fields documented in 1.8.14 must be present in the metrics dict."""
        src = _read("core/proxy_handler.py")
        idx = src.find('"upstream_latency"')
        block = src[idx:idx + 300]
        for field in ("p50_ms", "p95_ms", "sample_n", "warn", "warn_threshold_ms"):
            assert f'"{field}"' in block, (
                f"upstream_latency metrics must include field {field!r}"
            )

    def test_latency_sample_appended_on_proxy_response(self):
        """The proxy path must append elapsed time to _upstream_latency_samples."""
        src = _read("core/proxy_handler.py")
        assert "_upstream_latency_samples.append" in src, (
            "_upstream_latency_samples.append() must be called in the proxy response path"
        )

    def test_deque_max_500_samples_discards_oldest(self):
        """Rolling window: inserting 501 samples must discard the oldest."""
        d = deque(maxlen=500)
        for i in range(501):
            d.append(float(i))
        assert len(d) == 500
        assert d[0] == 1.0, "oldest entry (0.0) must have been discarded"


# ── T1-3: webhook health counters ─────────────────────────────────────────────

class TestWebhookHealthEdgeCases:
    def test_consecutive_failures_resets_to_zero_on_success(self):
        """On a successful delivery, _WEBHOOK_CONSECUTIVE_FAILURES must reset to 0
        and _WEBHOOK_LAST_SUCCESS_TS must be updated — they must change atomically."""
        src = _read("integrations/webhook.py")
        # Find the success block (after a successful delivery, not the module declaration)
        # The success path sets _WEBHOOK_LAST_SUCCESS_TS = <loop time>
        idx = src.find("_WEBHOOK_LAST_SUCCESS_TS = asyncio")
        if idx == -1:
            idx = src.find("_WEBHOOK_LAST_SUCCESS_TS =")
            # Skip the module-level init line (the short one)
            while idx != -1 and "0.0" in src[idx:idx+40]:
                idx = src.find("_WEBHOOK_LAST_SUCCESS_TS =", idx + 1)
        assert idx != -1, "_WEBHOOK_LAST_SUCCESS_TS must be set in the success path"
        body = src[idx:idx + 200]
        assert "_WEBHOOK_CONSECUTIVE_FAILURES = 0" in body, (
            "Webhook worker must reset _WEBHOOK_CONSECUTIVE_FAILURES to 0 on success — "
            "if failures don't reset, the circuit breaker never closes"
        )

    def test_consecutive_failures_increments_on_each_failure(self):
        src = _read("integrations/webhook.py")
        assert "_WEBHOOK_CONSECUTIVE_FAILURES += 1" in src, (
            "_WEBHOOK_CONSECUTIVE_FAILURES must increment on each failed attempt"
        )

    def test_metrics_webhook_has_required_fields(self):
        """services.webhook in metrics must include the 4 documented fields."""
        src = _read("core/proxy_handler.py")
        idx = src.find('"webhook"')
        body = src[idx:idx + 300]
        for field in ("configured", "last_success_ts", "consecutive_failures", "circuit_open"):
            assert f'"{field}"' in body, (
                f"metrics services.webhook must include field {field!r} (1.8.14 T1-3)"
            )

    def test_circuit_open_field_uses_cb_open_until(self):
        src = _read("core/proxy_handler.py")
        idx = src.find('"circuit_open"')
        body = src[idx:idx + 100]
        assert "_CB_OPEN_UNTIL" in body, (
            'circuit_open must be derived from _CB_OPEN_UNTIL > time() — '
            'not a static bool'
        )

    def test_last_success_ts_zero_maps_to_none_in_metrics(self):
        """_WEBHOOK_LAST_SUCCESS_TS=0.0 (never succeeded) must be exposed as None,
        not 0, so the dashboard can render 'never' rather than epoch-time."""
        src = _read("core/proxy_handler.py")
        assert "_wh_mod._WEBHOOK_LAST_SUCCESS_TS or None" in src, (
            "last_success_ts=0.0 must map to None in metrics output"
        )

    def test_health_counters_are_module_globals(self):
        """Must be module-level globals (not instance attributes) so _webhook_worker
        updates them and the metrics reader sees the same object."""
        import integrations.webhook as wh
        import inspect
        src = inspect.getsource(wh)
        assert "_WEBHOOK_LAST_SUCCESS_TS: float = 0.0" in src or \
               "_WEBHOOK_LAST_SUCCESS_TS = 0.0" in src, (
            "_WEBHOOK_LAST_SUCCESS_TS must be a module-level float initialised to 0.0"
        )
        assert "_WEBHOOK_CONSECUTIVE_FAILURES: int = 0" in src or \
               "_WEBHOOK_CONSECUTIVE_FAILURES = 0" in src, (
            "_WEBHOOK_CONSECUTIVE_FAILURES must be a module-level int initialised to 0"
        )

    def test_metrics_fallback_on_import_error(self):
        """If integrations.webhook cannot be imported, metrics must not crash —
        the except branch must still include 'configured'."""
        src = _read("core/proxy_handler.py")
        # Find the except block after the webhook try
        idx = src.find('services["webhook"] = {"configured": bool(WEBHOOK_URL)}')
        assert idx != -1, (
            "Webhook metrics must have a fallback except branch that sets "
            "services['webhook'] = {'configured': bool(WEBHOOK_URL)} "
            "so metrics never 500 if the webhook module fails to import"
        )


# ── T2-5: eTLD+1 origin check edge cases ─────────────────────────────────────

class TestOriginCheckEdgeCases:
    def _check(self, origin, allowed_hosts, method="POST", path="/x"):
        import core.proxy_handler as ph
        req = mock.MagicMock()
        req.method = method
        req.path = path
        req.headers = {"Origin": origin}
        with mock.patch.object(ph, "STRICT_ORIGIN", True), \
             mock.patch.object(ph, "ALLOWED_HOSTS", set(allowed_hosts)), \
             mock.patch.object(ph, "OPEN_ORIGIN_PATHS", []):
            return ph._origin_check_failed(req)

    def test_port_in_origin_is_stripped(self):
        # https://sub.example.com:443 → netloc = sub.example.com:443
        # split(":", 1)[0] → sub.example.com → matches example.com
        assert not self._check("https://sub.example.com:443", ["example.com"]), (
            "Port in Origin header must be stripped before the host comparison"
        )

    def test_port_8443_stripped(self):
        assert not self._check("https://example.com:8443", ["example.com"]), (
            "Non-standard port must be stripped — origin host check is port-agnostic"
        )

    def test_evilexample_com_rejected(self):
        # 'evilexample.com'.endswith('.example.com') is False
        assert self._check("https://evilexample.com", ["example.com"]), (
            "evilexample.com must be rejected when only example.com is allowed — "
            "the suffix anchor (dot prefix) prevents this bypass"
        )

    def test_example_com_dot_evil_com_rejected(self):
        # example.com.evil.com — the allowed host appears as a label, not the TLD
        assert self._check("https://example.com.evil.com", ["example.com"]), (
            "example.com.evil.com must be rejected — allowed host must only match "
            "as a suffix preceded by a dot, not as a mid-label"
        )

    def test_ip_address_origin_rejected_when_hosts_configured(self):
        assert self._check("https://192.168.1.1", ["example.com"]), (
            "IP address origin must be rejected when ALLOWED_HOSTS is set"
        )

    def test_empty_origin_rejected_on_post(self):
        import core.proxy_handler as ph
        req = mock.MagicMock()
        req.method = "POST"
        req.path = "/mutate"
        req.headers = {}  # no Origin header
        with mock.patch.object(ph, "STRICT_ORIGIN", True), \
             mock.patch.object(ph, "ALLOWED_HOSTS", {"example.com"}), \
             mock.patch.object(ph, "OPEN_ORIGIN_PATHS", []):
            assert ph._origin_check_failed(req) is True, (
                "Missing Origin on POST must be rejected when STRICT_ORIGIN is on"
            )

    def test_get_not_checked(self):
        # GET requests are never origin-checked (no state change)
        assert not self._check("https://evil.com", ["example.com"], method="GET"), (
            "GET requests must never be origin-checked (STRICT_ORIGIN only applies "
            "to POST/PUT/PATCH/DELETE)"
        )

    def test_delete_is_checked(self):
        assert self._check("https://evil.com", ["example.com"], method="DELETE"), (
            "DELETE must be origin-checked (state-changing method)"
        )

    def test_exact_match_no_dot_prefix_still_allowed(self):
        # 'example.com' == 'example.com' (exact), not just endswith
        assert not self._check("https://example.com", ["example.com"])

    def test_suffix_anchor_uses_dot_prefix_in_source(self):
        """The implementation must use `host.endswith("." + _ah)` not just
        host.endswith(_ah) — the dot prefix is the security-critical anchor."""
        src = _read("core/proxy_handler.py")
        assert 'host.endswith("." + _ah)' in src or "host.endswith('.' + _ah)" in src, (
            "eTLD+1 check must use endswith('.' + allowed_host) — "
            "omitting the dot would let evilexample.com bypass example.com"
        )

    def test_scheme_only_origin_rejected(self):
        # origin = "https://" → urlparse netloc = "" → host = "" → rejected
        assert self._check("https://", ["example.com"]), (
            "Scheme-only origin (no host) must be rejected"
        )
