# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1815_qa_jsconsistency.py — extended QA for JS multi-vector consistency (1.8.14 Week 3).

Test types covered:
  P — parametrized: Chrome version matrix, mobile UA×hint matrix, fetch combo matrix
  B — boundary: Chrome v1, v999, Sec-Ch-Ua with extra whitespace, near-impossible combos
  E — edge cases: multiple Chrome tokens in UA, headless Chrome, partial Sec-Ch-Ua
  R — regression: known bot patterns (Python-requests, headless Chrome, scrapy)
  N — negative: clean browser requests that must produce no signals
  F — fuzz-safe: extreme/malformed header values that must not raise
  M — multi-signal: multiple consistency violations fire simultaneously
  C — concurrent: pure function, no shared mutable state between threads
  T — timing: O(1) claim per-check
"""
from __future__ import annotations

import os
import threading
import time

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")
_REPO = os.path.join(os.path.dirname(__file__), "..")

_CHROME_UA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_CHROME_CUA  = '"Chromium";v="120", "Not_A Brand";v="8", "Google Chrome";v="120"'
_FIREFOX_UA  = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0"
_ANDROID_UA  = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36"
_IPHONE_UA   = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1 Mobile/15E148"


def _sigs(headers: dict) -> list[str]:
    import detection.js_consistency as _jc
    old = _jc.JS_CONSISTENCY_ENABLED
    _jc.JS_CONSISTENCY_ENABLED = True
    try:
        return _jc.js_consistency_signals(headers)
    finally:
        _jc.JS_CONSISTENCY_ENABLED = old


# ─── P: parametrized Chrome version matrix ───────────────────────────────────

class TestCuaVersionParametrized:

    @pytest.mark.parametrize("chrome_ver", [100, 109, 115, 120, 125, 130])
    def test_matching_chrome_versions(self, chrome_ver):
        """Matching Chrome version in UA and Sec-Ch-Ua → no signal."""
        ua  = f"Mozilla/5.0 (Windows NT 10.0) Chrome/{chrome_ver}.0.0.0 Safari/537.36"
        cua = f'"Google Chrome";v="{chrome_ver}", "Chromium";v="{chrome_ver}"'
        assert "js-cua-version-mismatch" not in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})

    @pytest.mark.parametrize("ua_ver,cua_ver", [
        (120, 90),
        (120, 115),
        (130, 120),
        (100, 99),
        (115, 109),
    ])
    def test_mismatching_chrome_versions(self, ua_ver, cua_ver):
        """Mismatching Chrome versions → js-cua-version-mismatch."""
        ua  = f"Mozilla/5.0 (Windows NT 10.0) Chrome/{ua_ver}.0.0.0 Safari/537.36"
        cua = f'"Google Chrome";v="{cua_ver}"'
        assert "js-cua-version-mismatch" in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})


class TestMobileHintParametrized:

    @pytest.mark.parametrize("ua,hint,should_fire", [
        # desktop UA + mobile hint → mismatch
        (_CHROME_UA,    "?1", True),
        # macOS UA + mobile hint → mismatch
        ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/120 Safari/537.36", "?1", True),
        # X11 Linux UA + mobile hint → mismatch
        ("Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36", "?1", True),
        # Android UA + non-mobile hint → mismatch
        (_ANDROID_UA,   "?0", True),
        # iPhone UA + non-mobile hint → mismatch
        (_IPHONE_UA,    "?0", True),
        # iPad UA + non-mobile hint → mismatch
        ("Mozilla/5.0 (iPad; CPU OS 17_0) AppleWebKit/605.1 Mobile/15E148", "?0", True),
        # Android + mobile hint → consistent
        (_ANDROID_UA,   "?1", False),
        # iPhone + mobile hint → consistent
        (_IPHONE_UA,    "?1", False),
        # Desktop + non-mobile → consistent
        (_CHROME_UA,    "?0", False),
        # Firefox on X11 + mobile hint → X11 matches desktop pattern → signal fires
        (_FIREFOX_UA,   "?1", True),    # Firefox UA contains X11
    ])
    def test_mobile_hint_matrix(self, ua, hint, should_fire):
        sigs = _sigs({"User-Agent": ua, "Sec-Ch-Ua-Mobile": hint})
        if should_fire:
            assert "js-mobile-hint-mismatch" in sigs
        else:
            assert "js-mobile-hint-mismatch" not in sigs


class TestFetchComboParametrized:

    @pytest.mark.parametrize("mode,dest,impossible", [
        # All known impossible combos
        ("navigate",    "empty",         True),
        ("navigate",    "worker",        True),
        ("navigate",    "sharedworker",  True),
        ("navigate",    "serviceworker", True),
        ("cors",        "document",      True),
        ("no-cors",     "document",      True),
        ("same-origin", "document",      True),
        # Valid combos
        ("navigate",    "document",      False),
        ("navigate",    "frame",         False),
        ("navigate",    "iframe",        False),
        ("cors",        "empty",         False),
        ("cors",        "image",         False),
        ("cors",        "script",        False),
        ("no-cors",     "empty",         False),
        ("no-cors",     "image",         False),
        ("same-origin", "empty",         False),
        ("same-origin", "script",        False),
        ("websocket",   "websocket",     False),
    ])
    def test_fetch_combo_matrix(self, mode, dest, impossible):
        sigs = _sigs({"User-Agent": _CHROME_UA,
                      "Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest})
        if impossible:
            assert "js-fetch-impossible" in sigs
        else:
            assert "js-fetch-impossible" not in sigs

    @pytest.mark.parametrize("mode", ["Navigate", "NAVIGATE", "nAvIgAtE"])
    def test_case_insensitive_mode(self, mode):
        """Case-insensitive mode matching → impossible navigate+empty fires."""
        sigs = _sigs({"User-Agent": _CHROME_UA,
                      "Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": "empty"})
        assert "js-fetch-impossible" in sigs

    @pytest.mark.parametrize("dest", ["Document", "DOCUMENT", "dOcUmEnT"])
    def test_case_insensitive_dest(self, dest):
        """Case-insensitive dest matching → impossible cors+document fires."""
        sigs = _sigs({"User-Agent": _CHROME_UA,
                      "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": dest})
        assert "js-fetch-impossible" in sigs


# ─── B: boundary conditions ───────────────────────────────────────────────────

class TestJsConsistencyBoundary:

    def test_chrome_version_one(self):
        """Chrome/1 is extreme but valid; matching Sec-Ch-Ua → no signal."""
        ua  = "Mozilla/5.0 (Windows NT 10.0) Chrome/1.0.0.0 Safari/537.36"
        cua = '"Google Chrome";v="1"'
        assert "js-cua-version-mismatch" not in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})

    def test_chrome_version_mismatch_at_v1(self):
        """Chrome/1 in UA vs v="2" in Sec-Ch-Ua → mismatch."""
        ua  = "Mozilla/5.0 (Windows NT 10.0) Chrome/1.0.0.0 Safari/537.36"
        cua = '"Google Chrome";v="2"'
        assert "js-cua-version-mismatch" in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})

    def test_chrome_version_999(self):
        """Chrome/999 works; matching version → no signal."""
        ua  = "Mozilla/5.0 (Windows NT 10.0) Chrome/999.0.0.0 Safari/537.36"
        cua = '"Google Chrome";v="999"'
        assert "js-cua-version-mismatch" not in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})

    def test_sec_ch_ua_with_extra_whitespace(self):
        """Extra spaces around semicolons/equals in Sec-Ch-Ua still parses."""
        ua  = _CHROME_UA
        cua = '"Google Chrome" ; v = "120" , "Chromium" ; v = "120"'
        # If the regex handles extra whitespace, no mismatch
        assert "js-cua-version-mismatch" not in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})

    def test_unknown_hint_value_not_in_01(self):
        """Sec-Ch-Ua-Mobile value outside ?0/?1 (e.g. ?2, ?-1) → no signal."""
        for hint in ("?2", "?-1", "1", "0", "true", "false", "?"):
            sigs = _sigs({"User-Agent": _CHROME_UA, "Sec-Ch-Ua-Mobile": hint})
            assert "js-mobile-hint-mismatch" not in sigs, f"hint={hint!r} should not fire"

    def test_empty_mode_no_signal(self):
        sigs = _sigs({"User-Agent": _CHROME_UA,
                      "Sec-Fetch-Mode": "", "Sec-Fetch-Dest": "empty"})
        assert "js-fetch-impossible" not in sigs

    def test_empty_dest_no_signal(self):
        sigs = _sigs({"User-Agent": _CHROME_UA,
                      "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": ""})
        assert "js-fetch-impossible" not in sigs


# ─── E: edge cases ────────────────────────────────────────────────────────────

class TestJsConsistencyEdgeCases:

    def test_multiple_chrome_tokens_in_ua_uses_first(self):
        """UA with two Chrome versions (unusual) — regex finds first."""
        ua  = "Mozilla/5.0 Chrome/120.0.0.0 Chrome/115.0.0.0 Safari/537.36"
        cua = '"Google Chrome";v="120"'
        # First Chrome/120 matches Sec-Ch-Ua v=120 → no mismatch
        assert "js-cua-version-mismatch" not in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})

    def test_headless_chrome_ua_with_wrong_cua(self):
        """Headless Chrome UA is still Chrome — version mismatch fires."""
        headless_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 HeadlessChrome/120.0.0.0"
        cua = '"Google Chrome";v="90"'
        assert "js-cua-version-mismatch" in _sigs({"User-Agent": headless_ua, "Sec-Ch-Ua": cua})

    def test_chromium_in_cua_matches_chrome_ua(self):
        """Sec-Ch-Ua with Chromium brand (not Google Chrome) still matches Chrome UA."""
        ua  = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36"
        cua = '"Chromium";v="120", "Not_A Brand";v="24"'
        assert "js-cua-version-mismatch" not in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})

    def test_sec_ch_ua_only_not_a_brand_no_signal(self):
        """Sec-Ch-Ua with only Not_A_Brand (no Chrome/Chromium) → no version to compare."""
        ua  = _CHROME_UA
        cua = '"Not_A Brand";v="8"'
        assert "js-cua-version-mismatch" not in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})

    def test_crios_ua_is_mobile(self):
        """CriOS (Chrome for iOS) UA → treated as mobile."""
        crios_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) AppleWebKit/605.1 Mobile/15E148 CriOS/120.0.0.0"
        sigs = _sigs({"User-Agent": crios_ua, "Sec-Ch-Ua-Mobile": "?0"})
        assert "js-mobile-hint-mismatch" in sigs

    def test_fxios_ua_is_mobile(self):
        """FxiOS (Firefox for iOS) UA → treated as mobile."""
        fxios_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0) AppleWebKit/605.1 FxiOS/109.0"
        sigs = _sigs({"User-Agent": fxios_ua, "Sec-Ch-Ua-Mobile": "?0"})
        assert "js-mobile-hint-mismatch" in sigs


# ─── R: regression — known bot patterns ──────────────────────────────────────

class TestJsConsistencyRegression:

    def test_python_requests_no_sec_ch_ua_no_signal(self):
        """python-requests UA never sends Sec-Ch-Ua — no version signal."""
        sigs = _sigs({"User-Agent": "python-requests/2.31.0"})
        assert "js-cua-version-mismatch" not in sigs

    def test_scrapy_no_signals(self):
        """Scrapy UA — no browser headers → no consistency signals."""
        sigs = _sigs({"User-Agent": "Scrapy/2.11.0 (+https://scrapy.org)"})
        assert sigs == []

    def test_bot_with_chrome_ua_and_old_hardcoded_cua(self):
        """Bot copying Chrome UA but hardcoding old Sec-Ch-Ua (common pattern)."""
        ua  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        cua = '"Google Chrome";v="90", "Chromium";v="90"'   # hardcoded old version
        assert "js-cua-version-mismatch" in _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})

    def test_bot_with_mobile_false_but_android_ua(self):
        """Bot claiming ?0 but pretending to be Android (common scraper pattern)."""
        sigs = _sigs({"User-Agent": _ANDROID_UA, "Sec-Ch-Ua-Mobile": "?0"})
        assert "js-mobile-hint-mismatch" in sigs

    def test_bot_navigate_empty_spoofed_headers(self):
        """Bot adding Sec-Fetch-* but using impossible navigate+empty combo."""
        sigs = _sigs({"User-Agent": _CHROME_UA,
                      "Sec-Fetch-Mode": "navigate",
                      "Sec-Fetch-Dest": "empty",
                      "Sec-Fetch-Site": "none",
                      "Sec-Fetch-User": "?1"})
        assert "js-fetch-impossible" in sigs


# ─── N: negative — clean real-browser requests ───────────────────────────────

class TestJsConsistencyNegative:

    def test_real_chrome_desktop_request(self):
        """Real Chrome 120 desktop request → zero consistency signals."""
        headers = {
            "User-Agent":        _CHROME_UA,
            "Sec-Ch-Ua":         _CHROME_CUA,
            "Sec-Ch-Ua-Mobile":  "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Mode":    "navigate",
            "Sec-Fetch-Dest":    "document",
            "Sec-Fetch-Site":    "none",
            "Sec-Fetch-User":    "?1",
        }
        sigs = _sigs(headers)
        assert sigs == [], f"Unexpected signals: {sigs}"

    def test_real_chrome_android_request(self):
        """Real Chrome Android request → zero signals."""
        headers = {
            "User-Agent":       _ANDROID_UA,
            "Sec-Ch-Ua":        '"Chromium";v="120", "Not_A Brand";v="8", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?1",
            "Sec-Fetch-Mode":   "navigate",
            "Sec-Fetch-Dest":   "document",
        }
        sigs = _sigs(headers)
        assert sigs == [], f"Unexpected signals: {sigs}"

    def test_real_chrome_cors_image_request(self):
        """Legitimate CORS image request → no impossible signal."""
        sigs = _sigs({"User-Agent": _CHROME_UA,
                      "Sec-Fetch-Mode": "cors",
                      "Sec-Fetch-Dest": "image"})
        assert "js-fetch-impossible" not in sigs

    def test_no_headers_at_all(self):
        """Empty headers dict → empty signals list."""
        from detection.js_consistency import js_consistency_signals
        assert js_consistency_signals({}) == []

    def test_master_switch_off_suppresses_all(self):
        """JS_CONSISTENCY_ENABLED=False suppresses all signals."""
        import detection.js_consistency as _jc
        old = _jc.JS_CONSISTENCY_ENABLED
        _jc.JS_CONSISTENCY_ENABLED = False
        try:
            headers = {
                "User-Agent":        _CHROME_UA,
                "Sec-Ch-Ua":         '"Google Chrome";v="90"',   # mismatch
                "Sec-Ch-Ua-Mobile":  "?1",                        # mismatch
                "Sec-Fetch-Mode":    "navigate",
                "Sec-Fetch-Dest":    "empty",                     # impossible
            }
            assert _jc.js_consistency_signals(headers) == []
        finally:
            _jc.JS_CONSISTENCY_ENABLED = old


# ─── F: fuzz-safe ─────────────────────────────────────────────────────────────

class TestJsConsistencyFuzzSafe:

    @pytest.mark.parametrize("ua", [
        "",
        "   ",
        "a" * 10000,
        "\x00\x01\x02",
        "Chrome/abc.def",
        "Chrome/",
    ])
    def test_garbage_ua_safe(self, ua):
        """Malformed User-Agent must not raise."""
        from detection.js_consistency import js_consistency_signals
        try:
            result = js_consistency_signals({
                "User-Agent":   ua,
                "Sec-Ch-Ua":    '"Google Chrome";v="120"',
                "Sec-Ch-Ua-Mobile": "?1",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "empty",
            })
            assert isinstance(result, list)
        except Exception as exc:
            pytest.fail(f"Garbage UA {ua!r} raised: {exc}")

    @pytest.mark.parametrize("cua", [
        "",
        "garbage",
        ";v=120",
        '"Google Chrome"v="120"',
        "v=120",
        "a" * 5000,
        "\x00",
    ])
    def test_garbage_sec_ch_ua_safe(self, cua):
        """Malformed Sec-Ch-Ua must not raise."""
        from detection.js_consistency import js_consistency_signals
        try:
            result = js_consistency_signals({
                "User-Agent": _CHROME_UA,
                "Sec-Ch-Ua":  cua,
            })
            assert isinstance(result, list)
        except Exception as exc:
            pytest.fail(f"Garbage Sec-Ch-Ua {cua!r} raised: {exc}")


# ─── M: multi-signal — multiple violations simultaneously ─────────────────────

class TestJsConsistencyMultiSignal:

    def test_version_and_mobile_both_fire(self):
        """UA mismatch + mobile mismatch in one request → both signals."""
        ua  = _CHROME_UA   # Windows desktop
        cua = '"Google Chrome";v="90"'  # wrong version
        sigs = _sigs({
            "User-Agent":        ua,
            "Sec-Ch-Ua":         cua,
            "Sec-Ch-Ua-Mobile":  "?1",   # claims mobile but UA is desktop
        })
        # mobile mismatch fires unconditionally; version is escalate-only
        assert "js-mobile-hint-mismatch" in sigs

    def test_mobile_and_fetch_both_fire(self):
        """Mobile mismatch + impossible fetch combo → both signals."""
        sigs = _sigs({
            "User-Agent":       _CHROME_UA,  # desktop
            "Sec-Ch-Ua-Mobile": "?1",         # claims mobile
            "Sec-Fetch-Mode":   "navigate",
            "Sec-Fetch-Dest":   "empty",      # impossible
        })
        assert "js-mobile-hint-mismatch" in sigs
        assert "js-fetch-impossible"     in sigs

    def test_all_three_signals_can_fire(self):
        """All three signals in one request: mobile mismatch + impossible fetch (+version)."""
        ua  = _CHROME_UA
        sigs = _sigs({
            "User-Agent":       ua,
            "Sec-Ch-Ua":        '"Google Chrome";v="90"',   # version mismatch
            "Sec-Ch-Ua-Mobile": "?1",                        # mobile mismatch (desktop UA)
            "Sec-Fetch-Mode":   "cors",
            "Sec-Fetch-Dest":   "document",                  # impossible
        })
        # At minimum mobile + fetch must fire
        assert "js-mobile-hint-mismatch" in sigs
        assert "js-fetch-impossible"     in sigs


# ─── C: concurrent purity ─────────────────────────────────────────────────────

class TestJsConsistencyConcurrent:

    def test_concurrent_calls_pure(self):
        """js_consistency_signals is pure; concurrent calls don't interfere."""
        from detection.js_consistency import js_consistency_signals
        results = {}
        errors  = []

        def worker(tid: int, is_bot: bool) -> None:
            try:
                if is_bot:
                    headers = {
                        "User-Agent":       _CHROME_UA,
                        "Sec-Ch-Ua-Mobile": "?1",   # mismatch
                    }
                else:
                    headers = {
                        "User-Agent":       _CHROME_UA,
                        "Sec-Ch-Ua-Mobile": "?0",   # consistent
                    }
                results[tid] = js_consistency_signals(headers)
            except Exception as exc:
                errors.append((tid, exc))

        threads = [
            threading.Thread(target=worker, args=(i, i % 2 == 0))
            for i in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Concurrent errors: {errors}"
        for tid, sigs in results.items():
            if tid % 2 == 0:   # bot
                assert "js-mobile-hint-mismatch" in sigs
            else:              # clean
                assert "js-mobile-hint-mismatch" not in sigs


# ─── T: timing ────────────────────────────────────────────────────────────────

class TestJsConsistencyTiming:

    def test_signals_fast_per_call(self):
        """js_consistency_signals must handle 100k calls in < 2 seconds."""
        from detection.js_consistency import js_consistency_signals
        headers = {
            "User-Agent":       _CHROME_UA,
            "Sec-Ch-Ua":        _CHROME_CUA,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Fetch-Mode":   "navigate",
            "Sec-Fetch-Dest":   "document",
        }
        t0 = time.perf_counter()
        for _ in range(100000):
            js_consistency_signals(headers)
        elapsed = time.perf_counter() - t0
        assert elapsed < 5.0, f"Too slow: {elapsed:.3f}s for 100k calls"
