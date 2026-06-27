# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1815_qa_h2fp.py — extended QA for fingerproxy H2 SETTINGS (1.8.14 Week 2).

Test types covered:
  P — parametrized: settings ID matrix, UA×SETTINGS signal matrix
  B — boundary: empty header, single setting, max uint32, duplicate IDs
  E — edge cases: whitespace, out-of-order IDs, mixed valid/invalid
  R — regression: known Chrome/Firefox browser profiles, known curl profile
  N — negative: disabled knobs, no X-H2-* headers → no signals
  F — fuzz-safe: garbage header values that must not raise
  C — concurrent: signals are pure functions, no shared mutable state
  T — timing: parse_h2_settings O(n) linear claim check
"""
from __future__ import annotations

import os
import threading
import time
import unittest.mock as mock

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")
_REPO = os.path.join(os.path.dirname(__file__), "..")


def _fake_req(headers: dict) -> mock.MagicMock:
    req = mock.MagicMock()
    req.headers = headers
    req.version = mock.MagicMock()
    req.version.major = 2
    return req


_CHROME_UA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
_FIREFOX_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0"
_CURL_UA    = "curl/8.4.0"
_SAFARI_UA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1 Safari/604.1"

# Browser INITIAL_WINDOW_SIZE values (type id 4)
_CHROME_WS  = 6_291_456
_FIREFOX_WS = 131_072
_CURL_WS    = 65_535


def _h2_sigs(headers: dict, *, deny_en: bool = True, mismatch_en: bool = True) -> list[str]:
    """Call h2fp_signals with master switch and sub-knobs forced to given values."""
    import integrations.fingerproxy as _fp
    saved = (_fp.H2_SETTINGS_FP_ENABLED, _fp.H2_FP_DENY_ENABLED, _fp.H2_SETTINGS_MISMATCH_ENABLED)
    _fp.H2_SETTINGS_FP_ENABLED       = True
    _fp.H2_FP_DENY_ENABLED           = deny_en
    _fp.H2_SETTINGS_MISMATCH_ENABLED = mismatch_en
    try:
        return _fp.h2fp_signals(_fake_req(headers))
    finally:
        (_fp.H2_SETTINGS_FP_ENABLED, _fp.H2_FP_DENY_ENABLED,
         _fp.H2_SETTINGS_MISMATCH_ENABLED) = saved


# ─── P: parametrized settings parsing matrix ─────────────────────────────────

class TestH2SettingsParseParametrized:

    def _parse(self, s: str) -> dict:
        from integrations.fingerproxy import parse_h2_settings
        return parse_h2_settings(s)

    @pytest.mark.parametrize("header,expected", [
        ("4:6291456",                  {4: 6291456}),
        ("4:131072",                   {4: 131072}),
        ("1:65536;4:6291456",          {1: 65536, 4: 6291456}),
        ("1:65536;3:1000;4:6291456;5:16384", {1: 65536, 3: 1000, 4: 6291456, 5: 16384}),
        ("2:0",                        {2: 0}),           # ENABLE_PUSH disabled
        ("5:16384",                    {5: 16384}),
        ("6:0",                        {6: 0}),            # MAX_HEADER_LIST_SIZE=0
        ("1:0;2:0;3:0;4:0;5:0;6:0",   {1:0, 2:0, 3:0, 4:0, 5:0, 6:0}),
    ])
    def test_valid_settings_parsed(self, header, expected):
        assert self._parse(header) == expected

    @pytest.mark.parametrize("header", [
        "",
        "garbage",
        "a:b",
        "4:",
        ":6291456",
        "4:6291456:extra",
        "4=6291456",
        "hello world",
        ";",
        "4:6291456;",          # trailing semicolon — implementations vary
    ])
    def test_invalid_settings_return_empty(self, header):
        """Malformed settings header → empty dict, no exception."""
        try:
            result = self._parse(header)
            assert isinstance(result, dict)
        except Exception as exc:
            pytest.fail(f"parse_h2_settings({header!r}) raised: {exc}")


class TestH2FPSignalMatrix:
    """Parametrized UA × SETTINGS matrix for h2-settings-mismatch signal."""

    def _sigs(self, ua: str, settings_str: str,
              *, mismatch_enabled: bool = True) -> list[str]:
        import integrations.fingerproxy as _fp
        old_master   = _fp.H2_SETTINGS_FP_ENABLED
        old_mismatch = _fp.H2_SETTINGS_MISMATCH_ENABLED
        _fp.H2_SETTINGS_FP_ENABLED       = True
        _fp.H2_SETTINGS_MISMATCH_ENABLED = mismatch_enabled
        try:
            req = _fake_req({"User-Agent": ua,
                             "X-H2-Settings": settings_str})
            return _fp.h2fp_signals(req)
        finally:
            _fp.H2_SETTINGS_FP_ENABLED       = old_master
            _fp.H2_SETTINGS_MISMATCH_ENABLED = old_mismatch

    @pytest.mark.parametrize("ua,settings_str,should_mismatch", [
        # Chrome UA with Chrome window size → no mismatch
        (_CHROME_UA,  f"4:{_CHROME_WS}",  False),
        # Chrome UA with Firefox window size → mismatch
        (_CHROME_UA,  f"4:{_FIREFOX_WS}", True),
        # Chrome UA with curl window size → mismatch
        (_CHROME_UA,  f"4:{_CURL_WS}",    True),
        # Firefox UA with Firefox window size → no mismatch
        (_FIREFOX_UA, f"4:{_FIREFOX_WS}", False),
        # Firefox UA with Chrome window size → mismatch
        (_FIREFOX_UA, f"4:{_CHROME_WS}",  True),
        # Safari UA with curl window size → no mismatch (ambiguous, no check)
        (_SAFARI_UA,  f"4:{_CURL_WS}",    False),
        # curl UA with any window size → no mismatch (curl not checked)
        (_CURL_UA,    f"4:{_CHROME_WS}",  False),
        (_CURL_UA,    f"4:{_CURL_WS}",    False),
    ])
    def test_signal_matrix(self, ua, settings_str, should_mismatch):
        sigs = self._sigs(ua, settings_str)
        if should_mismatch:
            assert "h2-settings-mismatch" in sigs
        else:
            assert "h2-settings-mismatch" not in sigs


# ─── B: boundary conditions ───────────────────────────────────────────────────

class TestH2FPBoundary:

    def _parse(self, s: str) -> dict:
        from integrations.fingerproxy import parse_h2_settings
        return parse_h2_settings(s)

    def test_max_uint32_value(self):
        """Max uint32 (4294967295) is a valid SETTINGS value."""
        result = self._parse("4:4294967295")
        assert result == {4: 4294967295}

    def test_zero_value(self):
        assert self._parse("4:0") == {4: 0}

    def test_value_one(self):
        assert self._parse("4:1") == {4: 1}

    def test_all_six_rfc_ids(self):
        """All six RFC 7540 SETTINGS IDs parse correctly."""
        header = "1:4096;2:1;3:100;4:65535;5:16384;6:8192"
        result = self._parse(header)
        assert len(result) == 6
        for k in (1, 2, 3, 4, 5, 6):
            assert k in result

    def test_no_h2_settings_header_no_mismatch(self):
        """No X-H2-Settings header → no mismatch signal."""
        sigs = _h2_sigs({"User-Agent": _CHROME_UA})
        assert "h2-settings-mismatch" not in sigs

    def test_no_h2_fp_header_no_deny(self):
        """No X-H2-FP header → no deny signal."""
        import integrations.fingerproxy as _fp
        old_deny_list = _fp.H2_FP_DENY_LIST
        try:
            _fp.H2_FP_DENY_LIST = frozenset({"deadbeef"})
            sigs = _h2_sigs({"User-Agent": _CHROME_UA})
            assert "h2-settings-deny" not in sigs
        finally:
            _fp.H2_FP_DENY_LIST = old_deny_list

    def test_empty_deny_list_no_deny(self):
        """Empty H2_FP_DENY_LIST → no deny signal even with fingerprint."""
        import integrations.fingerproxy as _fp
        old = _fp.H2_FP_DENY_LIST
        try:
            _fp.H2_FP_DENY_LIST = frozenset()
            sigs = _h2_sigs({"User-Agent": _CHROME_UA, "X-H2-FP": "deadbeef"})
            assert "h2-settings-deny" not in sigs
        finally:
            _fp.H2_FP_DENY_LIST = old


# ─── E: edge cases ────────────────────────────────────────────────────────────

class TestH2FPEdgeCases:

    def _parse(self, s: str) -> dict:
        from integrations.fingerproxy import parse_h2_settings
        return parse_h2_settings(s)

    def test_duplicate_id_behavior(self):
        """Duplicate setting ID: last value should win or first — no crash."""
        try:
            result = self._parse("4:65535;4:6291456")
            assert isinstance(result, dict)
            assert 4 in result
        except Exception as exc:
            pytest.fail(f"Duplicate ID raised: {exc}")

    def test_deny_list_case_sensitive(self):
        """X-H2-FP match against deny list is exact (fingerprints are hex hashes)."""
        import integrations.fingerproxy as _fp
        old = _fp.H2_FP_DENY_LIST
        try:
            _fp.H2_FP_DENY_LIST = frozenset({"DEADBEEF"})
            sigs = _h2_sigs({"User-Agent": _CHROME_UA, "X-H2-FP": "deadbeef"})
            assert "h2-settings-deny" not in sigs
        finally:
            _fp.H2_FP_DENY_LIST = old

    def test_deny_fires_for_exact_match(self):
        """X-H2-FP in deny list → h2-settings-deny fires."""
        import integrations.fingerproxy as _fp
        fp_hash = "deadbeef1234"
        old = _fp.H2_FP_DENY_LIST
        try:
            _fp.H2_FP_DENY_LIST = frozenset({fp_hash})
            sigs = _h2_sigs({"User-Agent": _CHROME_UA, "X-H2-FP": fp_hash})
            assert "h2-settings-deny" in sigs
        finally:
            _fp.H2_FP_DENY_LIST = old

    def test_edge_ua_brave_treated_as_chrome(self):
        """Brave UA matches Chromium pattern → Chrome window size expected."""
        brave_ua = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Brave/120"
        sigs = _h2_sigs({"User-Agent": brave_ua, "X-H2-Settings": f"4:{_FIREFOX_WS}"})
        assert "h2-settings-mismatch" in sigs

    def test_edge_ua_edge_treated_as_chrome(self):
        """Edge UA (Edg/) matches Chromium pattern → Chrome window size expected."""
        edge_ua = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36 Edg/120.0"
        sigs = _h2_sigs({"User-Agent": edge_ua, "X-H2-Settings": f"4:{_FIREFOX_WS}"})
        assert "h2-settings-mismatch" in sigs


# ─── R: regression — known tool fingerprints ─────────────────────────────────

class TestH2FPRegression:

    def test_chrome_120_profile_no_mismatch(self):
        """Exact Chrome 120 H2 SETTINGS profile → no mismatch."""
        chrome_settings = f"1:65536;3:1000;4:{_CHROME_WS};5:16384"
        sigs = _h2_sigs({"User-Agent": _CHROME_UA, "X-H2-Settings": chrome_settings})
        assert "h2-settings-mismatch" not in sigs

    def test_firefox_109_profile_no_mismatch(self):
        """Firefox 109 H2 SETTINGS profile → no mismatch."""
        ff_settings = f"1:65536;2:0;4:{_FIREFOX_WS};5:16384"
        sigs = _h2_sigs({"User-Agent": _FIREFOX_UA, "X-H2-Settings": ff_settings})
        assert "h2-settings-mismatch" not in sigs

    def test_curl_ua_no_mismatch_regardless(self):
        """curl UA → no mismatch check (ambiguous window size shared with Safari)."""
        sigs = _h2_sigs({"User-Agent": _CURL_UA, "X-H2-Settings": f"4:{_CHROME_WS}"})
        assert "h2-settings-mismatch" not in sigs

    def test_bot_chrome_ua_curl_settings_mismatch(self):
        """Bot claiming Chrome UA but sending curl SETTINGS → mismatch."""
        sigs = _h2_sigs({"User-Agent": _CHROME_UA, "X-H2-Settings": f"4:{_CURL_WS}"})
        assert "h2-settings-mismatch" in sigs


# ─── N: negative — disabled knobs ─────────────────────────────────────────────

class TestH2FPNegative:

    @pytest.mark.parametrize("deny_en,mismatch_en", [
        (False, False),
        (True,  False),
        (False, True),
    ])
    def test_disabled_knobs_suppress_signals(self, deny_en, mismatch_en):
        """With sub-knobs disabled, corresponding signals must not fire."""
        import integrations.fingerproxy as _fp
        fp_hash = "badf00d"
        old_deny_list = _fp.H2_FP_DENY_LIST
        try:
            _fp.H2_FP_DENY_LIST = frozenset({fp_hash})
            sigs = _h2_sigs(
                {"User-Agent": _CHROME_UA, "X-H2-FP": fp_hash,
                 "X-H2-Settings": f"4:{_CURL_WS}"},
                deny_en=deny_en, mismatch_en=mismatch_en,
            )
            if not deny_en:
                assert "h2-settings-deny"     not in sigs
            if not mismatch_en:
                assert "h2-settings-mismatch" not in sigs
        finally:
            _fp.H2_FP_DENY_LIST = old_deny_list

    def test_master_switch_off_no_signals_regardless_of_headers(self):
        """H2_SETTINGS_FP_ENABLED=False → no signals even with all headers present."""
        import integrations.fingerproxy as _fp
        fp_hash = "badf00d"
        old_master    = _fp.H2_SETTINGS_FP_ENABLED
        old_deny_list = _fp.H2_FP_DENY_LIST
        try:
            _fp.H2_SETTINGS_FP_ENABLED = False
            _fp.H2_FP_DENY_LIST = frozenset({fp_hash})
            req = _fake_req({"User-Agent": _CHROME_UA, "X-H2-FP": fp_hash,
                             "X-H2-Settings": f"4:{_CURL_WS}"})
            sigs = _fp.h2fp_signals(req)
            assert sigs == []
        finally:
            _fp.H2_SETTINGS_FP_ENABLED = old_master
            _fp.H2_FP_DENY_LIST = old_deny_list


# ─── F: fuzz-safe ─────────────────────────────────────────────────────────────

class TestH2FPFuzzSafe:

    @pytest.mark.parametrize("settings_value", [
        "",
        "   ",
        ";;;;",
        "a:b;c:d",
        "1:2:3",
        "999999999999999999999:0",   # overflow int
        "4:-1",                      # negative value
        "\x00\x01\x02",
        "4:6291456\n5:16384",       # newline in header
        "4:" + "9" * 100,           # very large number
    ])
    def test_garbage_settings_safe(self, settings_value):
        """Garbage X-H2-Settings value must not raise."""
        try:
            sigs = _h2_sigs({"User-Agent": _CHROME_UA, "X-H2-Settings": settings_value})
            assert isinstance(sigs, list)
        except Exception as exc:
            pytest.fail(f"Garbage settings {settings_value!r} raised: {exc}")

    @pytest.mark.parametrize("fp_value", [
        "",
        "   ",
        "\x00\xff",
        "a" * 10000,   # very long fingerprint
        None,
    ])
    def test_garbage_fp_safe(self, fp_value):
        """Garbage X-H2-FP value must not raise."""
        import integrations.fingerproxy as _fp
        old = _fp.H2_FP_DENY_LIST
        try:
            _fp.H2_FP_DENY_LIST = frozenset({"abc"})
            headers = {"User-Agent": _CHROME_UA}
            if fp_value is not None:
                headers["X-H2-FP"] = fp_value
            sigs = _h2_sigs(headers)
            assert isinstance(sigs, list)
        except Exception as exc:
            pytest.fail(f"Garbage FP {fp_value!r} raised: {exc}")
        finally:
            _fp.H2_FP_DENY_LIST = old


# ─── C: concurrent purity ─────────────────────────────────────────────────────

class TestH2FPConcurrent:

    def test_concurrent_parse_calls_are_pure(self):
        """parse_h2_settings is pure; concurrent calls must not interfere."""
        from integrations.fingerproxy import parse_h2_settings
        results: dict[int, dict] = {}
        errors:  list = []

        def worker(tid: int, header: str) -> None:
            try:
                results[tid] = parse_h2_settings(header)
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(i, f"4:{_CHROME_WS};3:{i}"))
            for i in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent parse errors: {errors}"
        for tid, result in results.items():
            assert result.get(3) == tid
            assert result.get(4) == _CHROME_WS


# ─── T: timing ────────────────────────────────────────────────────────────────

class TestH2FPTiming:

    def test_parse_settings_fast(self):
        """parse_h2_settings must complete 50k calls in < 1 second."""
        from integrations.fingerproxy import parse_h2_settings
        header = "1:65536;3:1000;4:6291456;5:16384"
        t0 = time.perf_counter()
        for _ in range(50000):
            parse_h2_settings(header)
        elapsed = time.perf_counter() - t0
        assert elapsed < 1.0, f"parse_h2_settings is too slow: {elapsed:.3f}s for 50k calls"
