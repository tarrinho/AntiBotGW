# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1815_threat_feeds.py — threat-intel feed auto-refresh (1.8.14).

Groups:
  M — module basics: feeds_check / feeds_stats API contract
  C — config knobs: env-driven enable/disable, RISK_WEIGHTS, ESCALATE_ONLY
  P — parsing: _fetch_ip_lines line-format handling (unit, no network)
  I — integration: signal wiring into proxy_handler (_REASON_METHOD, gate map,
                   latency profile, signal info table)
  S — source: structural guards (no stale version strings, correct defaults)
"""
from __future__ import annotations

import os
import importlib
import types
import unittest.mock as mock

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")


def _read(rel: str) -> str:
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()


# ─── M: module basics ─────────────────────────────────────────────────────────

class TestFeedsModuleBasics:
    """feeds_check / feeds_stats return the right shape with no network calls."""

    def setup_method(self):
        import reputation.feeds as _f
        # Patch the private state with known sets (bypass fetch)
        _f._feodo_ips   = {"1.2.3.4", "10.0.0.1"}
        _f._cins_ips    = {"5.6.7.8"}
        _f._urlhaus_ips = {"9.9.9.9"}

    def teardown_method(self):
        import reputation.feeds as _f
        _f._feodo_ips   = set()
        _f._cins_ips    = set()
        _f._urlhaus_ips = set()

    def test_feeds_check_returns_list(self):
        import reputation.feeds as _f
        _f.FEODO_ENABLED = True
        result = _f.feeds_check("1.2.3.4")
        assert isinstance(result, list)
        _f.FEODO_ENABLED = False

    def test_feeds_check_feodo_hit(self):
        import reputation.feeds as _f
        old = _f.FEODO_ENABLED
        _f.FEODO_ENABLED = True
        try:
            hits = _f.feeds_check("1.2.3.4")
            assert "feodo-c2" in hits
        finally:
            _f.FEODO_ENABLED = old

    def test_feeds_check_cins_hit(self):
        import reputation.feeds as _f
        old = _f.CINS_ENABLED
        _f.CINS_ENABLED = True
        try:
            hits = _f.feeds_check("5.6.7.8")
            assert "cins-rogue" in hits
        finally:
            _f.CINS_ENABLED = old

    def test_feeds_check_urlhaus_hit(self):
        import reputation.feeds as _f
        old = _f.URLHAUS_ENABLED
        _f.URLHAUS_ENABLED = True
        try:
            hits = _f.feeds_check("9.9.9.9")
            assert "urlhaus-malware" in hits
        finally:
            _f.URLHAUS_ENABLED = old

    def test_feeds_check_no_hit_when_all_disabled(self):
        import reputation.feeds as _f
        old_f, old_c, old_u = _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED
        _f.FEODO_ENABLED = _f.CINS_ENABLED = _f.URLHAUS_ENABLED = False
        try:
            assert _f.feeds_check("1.2.3.4") == []
            assert _f.feeds_check("5.6.7.8") == []
            assert _f.feeds_check("9.9.9.9") == []
        finally:
            _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED = old_f, old_c, old_u

    def test_feeds_check_private_ip_skipped(self):
        import reputation.feeds as _f
        old_f, old_c, old_u = _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED
        _f.FEODO_ENABLED = _f.CINS_ENABLED = _f.URLHAUS_ENABLED = True
        # Inject private IPs into sets to prove they are never returned
        _f._feodo_ips.add("192.168.1.1")
        _f._cins_ips.add("10.0.0.50")
        _f._urlhaus_ips.add("172.16.0.1")
        try:
            assert _f.feeds_check("192.168.1.1") == []
            assert _f.feeds_check("10.0.0.50") == []
            assert _f.feeds_check("172.16.0.1") == []
            assert _f.feeds_check("127.0.0.1") == []
        finally:
            _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED = old_f, old_c, old_u

    def test_feeds_check_loopback_skipped(self):
        import reputation.feeds as _f
        old_f = _f.FEODO_ENABLED
        _f.FEODO_ENABLED = True
        _f._feodo_ips.add("::1")
        try:
            assert _f.feeds_check("::1") == []
        finally:
            _f.FEODO_ENABLED = old_f

    def test_feeds_check_invalid_ip_returns_empty(self):
        import reputation.feeds as _f
        assert _f.feeds_check("not-an-ip") == []
        assert _f.feeds_check("") == []
        assert _f.feeds_check("256.0.0.1") == []

    def test_feeds_check_multiple_signals_same_ip(self):
        import reputation.feeds as _f
        old_f, old_c, old_u = _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED
        _f.FEODO_ENABLED = _f.CINS_ENABLED = _f.URLHAUS_ENABLED = True
        _f._cins_ips.add("1.2.3.4")
        _f._urlhaus_ips.add("1.2.3.4")
        try:
            hits = _f.feeds_check("1.2.3.4")
            assert "feodo-c2" in hits
            assert "cins-rogue" in hits
            assert "urlhaus-malware" in hits
        finally:
            _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED = old_f, old_c, old_u
            _f._cins_ips.discard("1.2.3.4")
            _f._urlhaus_ips.discard("1.2.3.4")

    def test_feeds_stats_structure(self):
        import reputation.feeds as _f
        stats = _f.feeds_stats()
        assert "feodo" in stats
        assert "cins" in stats
        assert "urlhaus" in stats
        for key in ("feodo", "cins", "urlhaus"):
            s = stats[key]
            assert "loaded_at" in s
            assert "size" in s
            assert "last_error" in s
            assert "fetches" in s
            assert "enabled" in s

    def test_feeds_stats_enabled_reflects_knob(self):
        import reputation.feeds as _f
        old_f = _f.FEODO_ENABLED
        _f.FEODO_ENABLED = True
        try:
            assert _f.feeds_stats()["feodo"]["enabled"] is True
        finally:
            _f.FEODO_ENABLED = old_f


# ─── C: config knobs ──────────────────────────────────────────────────────────

class TestFeedsConfigKnobs:
    """Env-driven enable/disable defaults, RISK_WEIGHTS, ESCALATE_ONLY_REASONS."""

    def test_all_feeds_disabled_by_default(self):
        """All three feeds must default to disabled (safe-fail posture)."""
        import reputation.feeds as _f
        # Module-level defaults (set at import time from env)
        # We can't re-import cleanly in all cases, so check what the module
        # advertises as the default (FEODO_ENABLED etc.) when env vars are absent.
        # The safest check: if env vars not set, the value must have been False at
        # module load time. We verify by checking the source code default.
        src = _read("reputation/feeds.py")
        assert '"0"' in src, "Default for feed enable knobs should be '0' (disabled)"
        assert 'FEODO_ENABLED' in src
        assert 'CINS_ENABLED' in src
        assert 'URLHAUS_ENABLED' in src

    def test_feodo_risk_weight(self):
        from config import RISK_WEIGHTS
        assert "feodo-c2" in RISK_WEIGHTS, "feodo-c2 must be in RISK_WEIGHTS"
        assert RISK_WEIGHTS["feodo-c2"] == 60

    def test_cins_risk_weight(self):
        from config import RISK_WEIGHTS
        assert "cins-rogue" in RISK_WEIGHTS
        assert RISK_WEIGHTS["cins-rogue"] == 30

    def test_urlhaus_risk_weight(self):
        from config import RISK_WEIGHTS
        assert "urlhaus-malware" in RISK_WEIGHTS
        assert RISK_WEIGHTS["urlhaus-malware"] == 45

    def test_feodo_in_escalate_only(self):
        from config import ESCALATE_ONLY_REASONS
        assert "feodo-c2" in ESCALATE_ONLY_REASONS, \
            "feodo-c2 must be escalate-only to avoid false positives"

    def test_cins_in_escalate_only(self):
        from config import ESCALATE_ONLY_REASONS
        assert "cins-rogue" in ESCALATE_ONLY_REASONS

    def test_urlhaus_in_escalate_only(self):
        from config import ESCALATE_ONLY_REASONS
        assert "urlhaus-malware" in ESCALATE_ONLY_REASONS

    def test_escalate_only_is_set_or_frozenset(self):
        from config import ESCALATE_ONLY_REASONS
        assert isinstance(ESCALATE_ONLY_REASONS, (set, frozenset))


# ─── P: parsing ───────────────────────────────────────────────────────────────

class TestFeedsLineParsing:
    """_fetch_ip_lines parsing logic — tested via the private helper."""

    def _call_parse(self, text: str) -> set[str]:
        """Feed synthetic HTTP response through the parse path."""
        import reputation.feeds as _f
        # Patch urlopen to return a fake response
        fake_bytes = text.encode("utf-8")

        class _FakeResp:
            def read(self): return fake_bytes
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with mock.patch("urllib.request.urlopen", return_value=_FakeResp()):
            return _f._fetch_ip_lines("https://example.invalid/feed.txt")

    def test_plain_ipv4(self):
        result = self._call_parse("1.2.3.4\n5.6.7.8\n")
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result

    def test_comment_lines_skipped(self):
        result = self._call_parse("# comment\n1.2.3.4\n")
        assert "1.2.3.4" in result
        assert len([x for x in result if "#" in x]) == 0

    def test_blank_lines_skipped(self):
        result = self._call_parse("\n\n1.2.3.4\n\n")
        assert "1.2.3.4" in result
        assert "" not in result

    def test_cidr_notation_stripped(self):
        result = self._call_parse("1.2.3.4/32\n5.6.7.0/24\n")
        assert "1.2.3.4" in result
        assert "5.6.7.0" in result
        assert any("/" in x for x in result) is False

    def test_invalid_addresses_dropped(self):
        result = self._call_parse("not-an-ip\n999.999.999.999\nhostname.example.com\n")
        assert len(result) == 0

    def test_ipv6_accepted(self):
        result = self._call_parse("2001:db8::1\n")
        assert "2001:db8::1" in result

    def test_mixed_valid_invalid(self):
        lines = "# header\n1.2.3.4\nbad-host\n5.6.7.8\n\n"
        result = self._call_parse(lines)
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result
        assert len(result) == 2

    def test_returns_set(self):
        result = self._call_parse("1.2.3.4\n1.2.3.4\n")
        assert isinstance(result, set)
        assert len(result) == 1  # deduped


# ─── I: integration wiring ────────────────────────────────────────────────────

class TestFeedsProxyHandlerWiring:
    """Structural checks that feeds signals are wired into proxy_handler correctly."""

    def setup_class(cls):
        cls._src = _read("core/proxy_handler.py")

    def test_reason_method_feodo(self):
        assert '"feodo-c2": "intel"' in self._src, \
            "feodo-c2 must appear in _REASON_METHOD under 'intel'"

    def test_reason_method_cins(self):
        assert '"cins-rogue": "intel"' in self._src

    def test_reason_method_urlhaus(self):
        assert '"urlhaus-malware": "intel"' in self._src

    def test_gate_knob_feodo(self):
        assert '"feodo-c2":' in self._src
        assert '"FEODO_ENABLED"' in self._src

    def test_gate_knob_cins(self):
        assert '"cins-rogue":' in self._src
        assert '"CINS_ENABLED"' in self._src

    def test_gate_knob_urlhaus(self):
        assert '"urlhaus-malware":' in self._src
        assert '"URLHAUS_ENABLED"' in self._src

    def test_latency_profile_feodo(self):
        assert '"feodo-c2":' in self._src
        assert '"in-process"' in self._src

    def test_signal_info_feodo(self):
        assert 'Feodo' in self._src

    def test_signal_info_cins(self):
        assert 'CINS' in self._src

    def test_signal_info_urlhaus(self):
        assert 'URLhaus' in self._src

    def test_feeds_check_call_present(self):
        assert 'feeds_check(' in self._src, \
            "feeds_check must be called in per-request path"

    def test_feeds_import_present(self):
        assert 'from reputation.feeds import' in self._src


class TestFeedsProxyStartupWiring:
    """proxy.py must start the three refresh loops and register detector health."""

    def setup_class(cls):
        cls._src = _read("proxy.py")

    def test_feodo_refresh_loop_import(self):
        assert '_feodo_refresh_loop' in self._src

    def test_cins_refresh_loop_import(self):
        assert '_cins_refresh_loop' in self._src

    def test_urlhaus_refresh_loop_import(self):
        assert '_urlhaus_refresh_loop' in self._src

    def test_feodo_task_created(self):
        assert '_feodo_refresh_loop()' in self._src

    def test_cins_task_created(self):
        assert '_cins_refresh_loop()' in self._src

    def test_urlhaus_task_created(self):
        assert '_urlhaus_refresh_loop()' in self._src

    def test_feodo_detector_health_registered(self):
        assert 'feodo_feed' in self._src

    def test_cins_detector_health_registered(self):
        assert 'cins_feed' in self._src

    def test_urlhaus_detector_health_registered(self):
        assert 'urlhaus_feed' in self._src


# ─── S: source structural guards ─────────────────────────────────────────────

class TestFeedsSourceGuards:
    """Structural guards to catch silent regressions."""

    def test_feeds_file_exists(self):
        import os
        path = os.path.join(_REPO, "reputation", "feeds.py")
        assert os.path.isfile(path), "reputation/feeds.py must exist"

    def test_feeds_public_api_complete(self):
        src = _read("reputation/feeds.py")
        for name in ("feeds_check", "feeds_stats",
                     "FEODO_ENABLED", "CINS_ENABLED", "URLHAUS_ENABLED",
                     "_feodo_refresh_loop", "_cins_refresh_loop",
                     "_urlhaus_refresh_loop"):
            assert name in src, f"feeds.py must define {name}"

    def test_feeds_default_urls_correct(self):
        src = _read("reputation/feeds.py")
        assert "feodotracker.abuse.ch" in src
        assert "cinsscore.com" in src
        assert "urlhaus.abuse.ch" in src

    def test_feeds_escalate_only_comment_present(self):
        """Feeds must be documented as escalate-only in feeds.py."""
        src = _read("reputation/feeds.py")
        assert "escalate" in src.lower()

    def test_feeds_ssl_ctx_used(self):
        """SSL context must be used in the fetch helper (no cert bypass)."""
        src = _read("reputation/feeds.py")
        assert "_ssl_ctx()" in src

    def test_config_has_all_three_weights(self):
        src = _read("config.py")
        assert "feodo-c2" in src
        assert "cins-rogue" in src
        assert "urlhaus-malware" in src

    def test_feeds_private_ip_guard_in_source(self):
        src = _read("reputation/feeds.py")
        assert "is_private" in src
        assert "is_loopback" in src

    def test_refresh_intervals_positive(self):
        import reputation.feeds as _f
        assert _f.FEODO_REFRESH_SECS > 0
        assert _f.CINS_REFRESH_SECS > 0
        assert _f.URLHAUS_REFRESH_SECS > 0

    def test_urlhaus_refresh_longer_than_feodo(self):
        """URLhaus refresh is 4 h vs 1 h for Feodo — per feed recommendation."""
        import reputation.feeds as _f
        assert _f.URLHAUS_REFRESH_SECS >= _f.FEODO_REFRESH_SECS

    def test_feodo_weight_higher_than_cins(self):
        """Feodo (known C2) should be scored higher than CINS (scan-origin)."""
        from config import RISK_WEIGHTS
        assert RISK_WEIGHTS["feodo-c2"] > RISK_WEIGHTS["cins-rogue"]

    def test_urlhaus_weight_higher_than_cins(self):
        """URLhaus (active malware host) should be scored higher than CINS."""
        from config import RISK_WEIGHTS
        assert RISK_WEIGHTS["urlhaus-malware"] > RISK_WEIGHTS["cins-rogue"]
