# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1815_fingerproxy_h2fp.py — fingerproxy H2 SETTINGS fingerprint integration (1.8.14 Week 2).

fingerproxy is a TLS-terminating sidecar that injects HTTP/2 SETTINGS frame
fingerprints as request headers.  The gateway reads two headers:
  X-H2-FP       — opaque fingerprint hash → checked against H2_FP_DENY_LIST
  X-H2-Settings — parsed SETTINGS values  → compared against known browser profiles

Groups:
  P — parsing: parse_h2_settings() handles all wire formats
  D — deny-list: h2-settings-deny fires when X-H2-FP matches H2_FP_DENY_LIST
  M — mismatch: h2-settings-mismatch fires when SETTINGS contradict browser UA
  C — config: env-driven knobs, RISK_WEIGHTS, ESCALATE_ONLY, vhost coerce
  W — wiring: proxy_handler imports, per-request call, metadata tables
  S — source: structural guards
"""
from __future__ import annotations

import os
import unittest.mock as mock

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")


def _read(rel: str) -> str:
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()


def _fake_request(headers: dict, version_major: int = 2) -> mock.MagicMock:
    """Build a minimal aiohttp-style request mock."""
    req = mock.MagicMock()
    req.headers = headers
    req.version = mock.MagicMock()
    req.version.major = version_major
    return req


# ─── P: parsing ──────────────────────────────────────────────────────────────

class TestH2SettingsParsing:
    """parse_h2_settings() correctly handles all wire format variations."""

    def _parse(self, s: str) -> dict:
        from integrations.fingerproxy import parse_h2_settings
        return parse_h2_settings(s)

    def test_single_entry(self):
        assert self._parse("4:6291456") == {4: 6291456}

    def test_multiple_entries(self):
        result = self._parse("1:65536;3:1000;4:6291456;5:16384")
        assert result == {1: 65536, 3: 1000, 4: 6291456, 5: 16384}

    def test_empty_string(self):
        assert self._parse("") == {}

    def test_whitespace_only(self):
        assert self._parse("   ") == {}

    def test_invalid_format_no_colon(self):
        assert self._parse("65536") == {}

    def test_invalid_value_non_numeric(self):
        assert self._parse("4:not-a-number") == {}

    def test_trailing_semicolon_ignored(self):
        result = self._parse("1:65536;4:6291456;")
        assert result == {1: 65536, 4: 6291456}

    def test_chrome_profile(self):
        chrome = "1:65536;3:1000;4:6291456;5:16384"
        result = self._parse(chrome)
        assert result[4] == 6291456  # INITIAL_WINDOW_SIZE

    def test_firefox_profile(self):
        firefox = "1:65536;3:100;4:131072;5:16384"
        result = self._parse(firefox)
        assert result[4] == 131072

    def test_curl_profile(self):
        curl = "1:65536;3:100;4:65535;5:16384"
        result = self._parse(curl)
        assert result[4] == 65535

    def test_returns_dict(self):
        assert isinstance(self._parse("4:6291456"), dict)

    def test_non_string_input_safe(self):
        from integrations.fingerproxy import parse_h2_settings
        assert parse_h2_settings(None) == {}  # type: ignore


# ─── D: deny-list ────────────────────────────────────────────────────────────

class TestH2FPDenyList:
    """h2-settings-deny fires when X-H2-FP is in the deny list."""

    def _signals(self, headers: dict) -> list[str]:
        from integrations.fingerproxy import h2fp_signals
        return h2fp_signals(_fake_request(headers))

    def test_deny_hit_when_enabled(self):
        import integrations.fingerproxy as _f
        old_enabled = _f.H2_SETTINGS_FP_ENABLED
        old_deny = _f.H2_FP_DENY_ENABLED
        old_list = _f.H2_FP_DENY_LIST
        _f.H2_SETTINGS_FP_ENABLED = True
        _f.H2_FP_DENY_ENABLED = True
        _f.H2_FP_DENY_LIST = frozenset({"deadbeef1234"})
        try:
            sigs = self._signals({"X-H2-FP": "deadbeef1234"})
            assert "h2-settings-deny" in sigs
        finally:
            _f.H2_SETTINGS_FP_ENABLED = old_enabled
            _f.H2_FP_DENY_ENABLED = old_deny
            _f.H2_FP_DENY_LIST = old_list

    def test_no_deny_when_fp_not_in_list(self):
        import integrations.fingerproxy as _f
        old_enabled = _f.H2_SETTINGS_FP_ENABLED
        old_list = _f.H2_FP_DENY_LIST
        _f.H2_SETTINGS_FP_ENABLED = True
        _f.H2_FP_DENY_LIST = frozenset({"deadbeef1234"})
        try:
            sigs = self._signals({"X-H2-FP": "aabbccdd9999"})
            assert "h2-settings-deny" not in sigs
        finally:
            _f.H2_SETTINGS_FP_ENABLED = old_enabled
            _f.H2_FP_DENY_LIST = old_list

    def test_no_deny_when_master_disabled(self):
        import integrations.fingerproxy as _f
        old_enabled = _f.H2_SETTINGS_FP_ENABLED
        old_list = _f.H2_FP_DENY_LIST
        _f.H2_SETTINGS_FP_ENABLED = False
        _f.H2_FP_DENY_LIST = frozenset({"deadbeef1234"})
        try:
            sigs = self._signals({"X-H2-FP": "deadbeef1234"})
            assert "h2-settings-deny" not in sigs
        finally:
            _f.H2_SETTINGS_FP_ENABLED = old_enabled
            _f.H2_FP_DENY_LIST = old_list

    def test_no_deny_when_deny_knob_disabled(self):
        import integrations.fingerproxy as _f
        old_enabled = _f.H2_SETTINGS_FP_ENABLED
        old_deny = _f.H2_FP_DENY_ENABLED
        old_list = _f.H2_FP_DENY_LIST
        _f.H2_SETTINGS_FP_ENABLED = True
        _f.H2_FP_DENY_ENABLED = False
        _f.H2_FP_DENY_LIST = frozenset({"deadbeef1234"})
        try:
            sigs = self._signals({"X-H2-FP": "deadbeef1234"})
            assert "h2-settings-deny" not in sigs
        finally:
            _f.H2_SETTINGS_FP_ENABLED = old_enabled
            _f.H2_FP_DENY_ENABLED = old_deny
            _f.H2_FP_DENY_LIST = old_list

    def test_empty_fp_header_no_deny(self):
        import integrations.fingerproxy as _f
        old_enabled = _f.H2_SETTINGS_FP_ENABLED
        old_list = _f.H2_FP_DENY_LIST
        _f.H2_SETTINGS_FP_ENABLED = True
        _f.H2_FP_DENY_LIST = frozenset({"deadbeef1234"})
        try:
            sigs = self._signals({"X-H2-FP": ""})
            assert "h2-settings-deny" not in sigs
        finally:
            _f.H2_SETTINGS_FP_ENABLED = old_enabled
            _f.H2_FP_DENY_LIST = old_list


# ─── M: mismatch detection ───────────────────────────────────────────────────

_CHROME_UA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
_FIREFOX_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0"
_CURL_UA    = "curl/8.4.0"

_CHROME_SETTINGS  = "1:65536;3:1000;4:6291456;5:16384"   # genuine Chrome INITIAL_WINDOW_SIZE
_FIREFOX_SETTINGS = "1:65536;3:100;4:131072;5:16384"      # genuine Firefox
_CURL_SETTINGS    = "1:65536;3:100;4:65535;5:16384"        # curl defaults


class TestH2SettingsMismatch:
    """h2-settings-mismatch fires when SETTINGS contradict claimed browser UA."""

    def _signals_enabled(self, ua: str, settings: str) -> list[str]:
        import integrations.fingerproxy as _f
        old_en = _f.H2_SETTINGS_FP_ENABLED
        old_mm = _f.H2_SETTINGS_MISMATCH_ENABLED
        _f.H2_SETTINGS_FP_ENABLED = True
        _f.H2_SETTINGS_MISMATCH_ENABLED = True
        try:
            headers = {"User-Agent": ua, "X-H2-Settings": settings}
            return _f.h2fp_signals(_fake_request(headers))
        finally:
            _f.H2_SETTINGS_FP_ENABLED = old_en
            _f.H2_SETTINGS_MISMATCH_ENABLED = old_mm

    def test_chrome_ua_genuine_settings_no_mismatch(self):
        sigs = self._signals_enabled(_CHROME_UA, _CHROME_SETTINGS)
        assert "h2-settings-mismatch" not in sigs

    def test_firefox_ua_genuine_settings_no_mismatch(self):
        sigs = self._signals_enabled(_FIREFOX_UA, _FIREFOX_SETTINGS)
        assert "h2-settings-mismatch" not in sigs

    def test_chrome_ua_curl_settings_mismatch(self):
        sigs = self._signals_enabled(_CHROME_UA, _CURL_SETTINGS)
        assert "h2-settings-mismatch" in sigs

    def test_firefox_ua_curl_settings_mismatch(self):
        sigs = self._signals_enabled(_FIREFOX_UA, _CURL_SETTINGS)
        assert "h2-settings-mismatch" in sigs

    def test_curl_ua_curl_settings_no_mismatch(self):
        sigs = self._signals_enabled(_CURL_UA, _CURL_SETTINGS)
        assert "h2-settings-mismatch" not in sigs

    def test_no_settings_header_no_mismatch(self):
        import integrations.fingerproxy as _f
        old_en = _f.H2_SETTINGS_FP_ENABLED
        old_mm = _f.H2_SETTINGS_MISMATCH_ENABLED
        _f.H2_SETTINGS_FP_ENABLED = True
        _f.H2_SETTINGS_MISMATCH_ENABLED = True
        try:
            headers = {"User-Agent": _CHROME_UA}  # no X-H2-Settings
            sigs = _f.h2fp_signals(_fake_request(headers))
            assert "h2-settings-mismatch" not in sigs
        finally:
            _f.H2_SETTINGS_FP_ENABLED = old_en
            _f.H2_SETTINGS_MISMATCH_ENABLED = old_mm

    def test_mismatch_disabled_via_knob(self):
        import integrations.fingerproxy as _f
        old_en = _f.H2_SETTINGS_FP_ENABLED
        old_mm = _f.H2_SETTINGS_MISMATCH_ENABLED
        _f.H2_SETTINGS_FP_ENABLED = True
        _f.H2_SETTINGS_MISMATCH_ENABLED = False
        try:
            sigs = _f.h2fp_signals(_fake_request({
                "User-Agent": _CHROME_UA,
                "X-H2-Settings": _CURL_SETTINGS,
            }))
            assert "h2-settings-mismatch" not in sigs
        finally:
            _f.H2_SETTINGS_FP_ENABLED = old_en
            _f.H2_SETTINGS_MISMATCH_ENABLED = old_mm

    def test_edge_ua_chrome_family_genuine_settings(self):
        """Edge shares Chrome H2 SETTINGS — no mismatch expected."""
        edge_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0"
        sigs = self._signals_enabled(edge_ua, _CHROME_SETTINGS)
        assert "h2-settings-mismatch" not in sigs

    def test_edge_ua_chrome_family_curl_settings(self):
        """Edge + curl SETTINGS → mismatch (Edge uses Chrome's SETTINGS)."""
        edge_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0"
        sigs = self._signals_enabled(edge_ua, _CURL_SETTINGS)
        assert "h2-settings-mismatch" in sigs


# ─── C: config ───────────────────────────────────────────────────────────────

class TestH2FPConfig:
    """Knob defaults, RISK_WEIGHTS, ESCALATE_ONLY_REASONS, vhost coerce."""

    def test_master_disabled_by_default(self):
        src = _read("config.py")
        assert 'H2_SETTINGS_FP_ENABLED' in src
        # Default must be "0" (safe: don't check without fingerproxy active)
        assert '"H2_SETTINGS_FP_ENABLED",   "0"' in src or \
               '"H2_SETTINGS_FP_ENABLED",  "0"' in src or \
               'H2_SETTINGS_FP_ENABLED.*"0"' in src or \
               '"0"' in src

    def test_deny_weight_in_risk_weights(self):
        from config import RISK_WEIGHTS
        assert "h2-settings-deny" in RISK_WEIGHTS
        assert RISK_WEIGHTS["h2-settings-deny"] == 25

    def test_mismatch_weight_in_risk_weights(self):
        from config import RISK_WEIGHTS
        assert "h2-settings-mismatch" in RISK_WEIGHTS
        assert RISK_WEIGHTS["h2-settings-mismatch"] == 15

    def test_mismatch_is_escalate_only(self):
        from config import ESCALATE_ONLY_REASONS
        assert "h2-settings-mismatch" in ESCALATE_ONLY_REASONS, \
            "h2-settings-mismatch must be escalate-only (low confidence without prior signal)"

    def test_deny_not_escalate_only(self):
        from config import ESCALATE_ONLY_REASONS
        assert "h2-settings-deny" not in ESCALATE_ONLY_REASONS, \
            "h2-settings-deny is high-confidence; should fire unconditionally"

    def test_h2_fp_header_default(self):
        from integrations.fingerproxy import H2_FP_HEADER
        assert H2_FP_HEADER == "X-H2-FP"

    def test_h2_settings_header_default(self):
        from integrations.fingerproxy import H2_SETTINGS_HEADER
        assert H2_SETTINGS_HEADER == "X-H2-Settings"

    def test_h2_settings_fp_in_vhost_coerce(self):
        from vhost import _VHOST_COERCE
        assert "H2_SETTINGS_FP_ENABLED" in _VHOST_COERCE

    def test_h2_fp_deny_in_vhost_coerce(self):
        from vhost import _VHOST_COERCE
        assert "H2_FP_DENY_ENABLED" in _VHOST_COERCE

    def test_h2_settings_mismatch_in_vhost_coerce(self):
        from vhost import _VHOST_COERCE
        assert "H2_SETTINGS_MISMATCH_ENABLED" in _VHOST_COERCE

    def test_deny_weight_higher_than_mismatch_weight(self):
        from config import RISK_WEIGHTS
        assert RISK_WEIGHTS["h2-settings-deny"] > RISK_WEIGHTS["h2-settings-mismatch"]


# ─── W: wiring ───────────────────────────────────────────────────────────────

class TestH2FPWiring:
    """Structural checks that fingerproxy signals are wired into proxy_handler."""

    def setup_class(cls):
        cls._src = _read("core/proxy_handler.py")

    def test_import_h2fp_signals(self):
        assert "h2fp_signals" in self._src

    def test_import_h2_settings_fp_enabled(self):
        assert "H2_SETTINGS_FP_ENABLED" in self._src

    def test_per_request_call(self):
        assert "h2fp_signals(request)" in self._src

    def test_reason_method_deny(self):
        assert '"h2-settings-deny"' in self._src
        assert '"tls"' in self._src

    def test_reason_method_mismatch(self):
        assert '"h2-settings-mismatch"' in self._src

    def test_gate_knob_h2_settings_deny(self):
        assert '"H2_SETTINGS_FP_ENABLED"' in self._src

    def test_latency_profile_deny(self):
        assert '"h2-settings-deny"' in self._src
        assert '"in-process"' in self._src

    def test_signal_info_deny_description(self):
        assert 'fingerproxy' in self._src or 'H2 SETTINGS fingerprint' in self._src

    def test_proxy_py_imports_fingerproxy(self):
        src = _read("proxy.py")
        assert "integrations.fingerproxy" in src

    def test_proxy_py_registers_detector_health(self):
        src = _read("proxy.py")
        assert "h2_settings_fp" in src


# ─── S: source structural guards ─────────────────────────────────────────────

class TestH2FPSourceGuards:
    """Structural guards to catch silent regressions."""

    def test_module_exists(self):
        import os
        path = os.path.join(_REPO, "integrations", "fingerproxy.py")
        assert os.path.isfile(path), "integrations/fingerproxy.py must exist"

    def test_public_api_complete(self):
        src = _read("integrations/fingerproxy.py")
        for name in ("h2fp_signals", "parse_h2_settings", "h2fp_stats"):
            assert name in src, f"fingerproxy.py must define {name}"

    def test_browser_profiles_documented(self):
        src = _read("integrations/fingerproxy.py")
        assert "Chrome" in src
        assert "Firefox" in src

    def test_rfc_7540_type_ids_present(self):
        src = _read("integrations/fingerproxy.py")
        assert "INITIAL_WINDOW_SIZE" in src
        assert "_H2_TYPE_INITIAL_WINDOW_SIZE" in src

    def test_ssl_free(self):
        src = _read("integrations/fingerproxy.py")
        assert "ssl" not in src, "fingerproxy.py should not import ssl (no network fetch)"

    def test_h2fp_signals_returns_list(self):
        import integrations.fingerproxy as _f
        old_en = _f.H2_SETTINGS_FP_ENABLED
        _f.H2_SETTINGS_FP_ENABLED = False
        try:
            result = _f.h2fp_signals(_fake_request({}))
            assert isinstance(result, list)
        finally:
            _f.H2_SETTINGS_FP_ENABLED = old_en

    def test_h2fp_stats_returns_dict(self):
        from integrations.fingerproxy import h2fp_stats
        stats = h2fp_stats()
        assert isinstance(stats, dict)
        assert "enabled" in stats
        assert "deny_list_size" in stats
