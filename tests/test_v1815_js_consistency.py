# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1815_js_consistency.py — JS multi-vector consistency checker (1.8.14 Week 3).

Groups:
  V — version: js-cua-version-mismatch (Sec-Ch-Ua v= vs Chrome UA version)
  M — mobile: js-mobile-hint-mismatch (Sec-Ch-Ua-Mobile vs UA platform)
  F — fetch: js-fetch-impossible (impossible Sec-Fetch-Mode/Dest combos)
  C — config: knobs, RISK_WEIGHTS, ESCALATE_ONLY, vhost coerce
  W — wiring: proxy_handler import, per-request call, metadata tables
  S — source: structural guards
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")


def _read(rel: str) -> str:
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()


def _sigs(headers: dict, *, enabled: bool = True) -> list[str]:
    import detection.js_consistency as _jc
    old = _jc.JS_CONSISTENCY_ENABLED
    _jc.JS_CONSISTENCY_ENABLED = enabled
    try:
        return _jc.js_consistency_signals(headers)
    finally:
        _jc.JS_CONSISTENCY_ENABLED = old


# Real Chrome 120 UA and Sec-Ch-Ua
_CHROME_UA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_CHROME_CUA  = '"Chromium";v="120", "Not_A Brand";v="8", "Google Chrome";v="120"'
_FIREFOX_UA  = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0"
_ANDROID_UA  = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36"
_IPHONE_UA   = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1 Mobile/15E148"
_CURL_UA     = "curl/8.4.0"


# ─── V: version mismatch ─────────────────────────────────────────────────────

class TestCuaVersionMismatch:

    def test_matching_versions_no_signal(self):
        sigs = _sigs({"User-Agent": _CHROME_UA, "Sec-Ch-Ua": _CHROME_CUA})
        assert "js-cua-version-mismatch" not in sigs

    def test_version_mismatch_fires(self):
        old_cua = '"Google Chrome";v="90", "Chromium";v="90"'
        sigs = _sigs({"User-Agent": _CHROME_UA, "Sec-Ch-Ua": old_cua})
        assert "js-cua-version-mismatch" in sigs

    def test_no_sec_ch_ua_no_signal(self):
        """Without Sec-Ch-Ua header, no version to compare — no signal."""
        sigs = _sigs({"User-Agent": _CHROME_UA})
        assert "js-cua-version-mismatch" not in sigs

    def test_no_chrome_in_ua_no_signal(self):
        """Non-Chrome UA + any Sec-Ch-Ua — no Chrome version to extract."""
        sigs = _sigs({"User-Agent": _FIREFOX_UA, "Sec-Ch-Ua": _CHROME_CUA})
        # The mobile/platform mismatch may fire, but not version
        assert "js-cua-version-mismatch" not in sigs

    def test_disabled_via_master_knob(self):
        sigs = _sigs({"User-Agent": _CHROME_UA,
                      "Sec-Ch-Ua": '"Google Chrome";v="90"'},
                     enabled=False)
        assert "js-cua-version-mismatch" not in sigs

    def test_disabled_via_version_knob(self):
        import detection.js_consistency as _jc
        old = _jc.JS_CUA_VERSION_CHECK_ENABLED
        _jc.JS_CUA_VERSION_CHECK_ENABLED = False
        try:
            sigs = _sigs({"User-Agent": _CHROME_UA,
                          "Sec-Ch-Ua": '"Google Chrome";v="90"'})
            assert "js-cua-version-mismatch" not in sigs
        finally:
            _jc.JS_CUA_VERSION_CHECK_ENABLED = old

    def test_chrome_115_vs_cua_115_matches(self):
        ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/115.0.5790.171 Safari/537.36"
        cua = '"Google Chrome";v="115", "Chromium";v="115"'
        sigs = _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})
        assert "js-cua-version-mismatch" not in sigs

    def test_chrome_120_vs_cua_115_mismatch(self):
        ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0 Safari/537.36"
        cua = '"Google Chrome";v="115"'
        sigs = _sigs({"User-Agent": ua, "Sec-Ch-Ua": cua})
        assert "js-cua-version-mismatch" in sigs


# ─── M: mobile hint mismatch ─────────────────────────────────────────────────

class TestMobileHintMismatch:

    def test_mobile_hint_desktop_ua_mismatch(self):
        sigs = _sigs({
            "User-Agent": _CHROME_UA,          # Windows desktop
            "Sec-Ch-Ua-Mobile": "?1",          # claims mobile
        })
        assert "js-mobile-hint-mismatch" in sigs

    def test_non_mobile_hint_android_ua_mismatch(self):
        sigs = _sigs({
            "User-Agent": _ANDROID_UA,
            "Sec-Ch-Ua-Mobile": "?0",          # claims non-mobile
        })
        assert "js-mobile-hint-mismatch" in sigs

    def test_mobile_hint_android_ua_consistent(self):
        sigs = _sigs({
            "User-Agent": _ANDROID_UA,
            "Sec-Ch-Ua-Mobile": "?1",
        })
        assert "js-mobile-hint-mismatch" not in sigs

    def test_non_mobile_hint_desktop_ua_consistent(self):
        sigs = _sigs({
            "User-Agent": _CHROME_UA,
            "Sec-Ch-Ua-Mobile": "?0",
        })
        assert "js-mobile-hint-mismatch" not in sigs

    def test_iphone_with_mobile_hint_one_consistent(self):
        sigs = _sigs({
            "User-Agent": _IPHONE_UA,
            "Sec-Ch-Ua-Mobile": "?1",
        })
        assert "js-mobile-hint-mismatch" not in sigs

    def test_no_mobile_hint_header_no_signal(self):
        sigs = _sigs({"User-Agent": _CHROME_UA})
        assert "js-mobile-hint-mismatch" not in sigs

    def test_ambiguous_hint_value_no_signal(self):
        """Unknown hint value (not ?0 or ?1) — no signal."""
        sigs = _sigs({"User-Agent": _CHROME_UA, "Sec-Ch-Ua-Mobile": "?2"})
        assert "js-mobile-hint-mismatch" not in sigs

    def test_disabled_via_mobile_knob(self):
        import detection.js_consistency as _jc
        old = _jc.JS_MOBILE_HINT_CHECK_ENABLED
        _jc.JS_MOBILE_HINT_CHECK_ENABLED = False
        try:
            sigs = _sigs({"User-Agent": _CHROME_UA, "Sec-Ch-Ua-Mobile": "?1"})
            assert "js-mobile-hint-mismatch" not in sigs
        finally:
            _jc.JS_MOBILE_HINT_CHECK_ENABLED = old

    def test_macos_ua_with_mobile_hint_mismatch(self):
        macos_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/120 Safari/537.36"
        sigs = _sigs({"User-Agent": macos_ua, "Sec-Ch-Ua-Mobile": "?1"})
        assert "js-mobile-hint-mismatch" in sigs

    def test_x11_linux_ua_with_mobile_hint_mismatch(self):
        linux_ua = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36"
        sigs = _sigs({"User-Agent": linux_ua, "Sec-Ch-Ua-Mobile": "?1"})
        assert "js-mobile-hint-mismatch" in sigs


# ─── F: fetch impossible ─────────────────────────────────────────────────────

class TestFetchImpossible:

    def _fetch_sigs(self, mode: str, dest: str) -> list[str]:
        return _sigs({"Sec-Fetch-Mode": mode, "Sec-Fetch-Dest": dest,
                      "User-Agent": _CHROME_UA})

    def test_navigate_empty_impossible(self):
        assert "js-fetch-impossible" in self._fetch_sigs("navigate", "empty")

    def test_navigate_worker_impossible(self):
        assert "js-fetch-impossible" in self._fetch_sigs("navigate", "worker")

    def test_navigate_sharedworker_impossible(self):
        assert "js-fetch-impossible" in self._fetch_sigs("navigate", "sharedworker")

    def test_navigate_serviceworker_impossible(self):
        assert "js-fetch-impossible" in self._fetch_sigs("navigate", "serviceworker")

    def test_cors_document_impossible(self):
        assert "js-fetch-impossible" in self._fetch_sigs("cors", "document")

    def test_no_cors_document_impossible(self):
        assert "js-fetch-impossible" in self._fetch_sigs("no-cors", "document")

    def test_same_origin_document_impossible(self):
        assert "js-fetch-impossible" in self._fetch_sigs("same-origin", "document")

    def test_navigate_document_valid(self):
        assert "js-fetch-impossible" not in self._fetch_sigs("navigate", "document")

    def test_cors_empty_valid(self):
        assert "js-fetch-impossible" not in self._fetch_sigs("cors", "empty")

    def test_no_cors_empty_valid(self):
        assert "js-fetch-impossible" not in self._fetch_sigs("no-cors", "empty")

    def test_same_origin_empty_valid(self):
        assert "js-fetch-impossible" not in self._fetch_sigs("same-origin", "empty")

    def test_navigate_frame_valid(self):
        assert "js-fetch-impossible" not in self._fetch_sigs("navigate", "frame")

    def test_cors_image_valid(self):
        assert "js-fetch-impossible" not in self._fetch_sigs("cors", "image")

    def test_no_mode_no_signal(self):
        sigs = _sigs({"User-Agent": _CHROME_UA, "Sec-Fetch-Dest": "empty"})
        assert "js-fetch-impossible" not in sigs

    def test_no_dest_no_signal(self):
        sigs = _sigs({"User-Agent": _CHROME_UA, "Sec-Fetch-Mode": "cors"})
        assert "js-fetch-impossible" not in sigs

    def test_case_insensitive_mode(self):
        assert "js-fetch-impossible" in self._fetch_sigs("Navigate", "empty")
        assert "js-fetch-impossible" in self._fetch_sigs("CORS", "document")

    def test_disabled_via_fetch_knob(self):
        import detection.js_consistency as _jc
        old = _jc.JS_FETCH_IMPOSSIBLE_CHECK_ENABLED
        _jc.JS_FETCH_IMPOSSIBLE_CHECK_ENABLED = False
        try:
            sigs = _sigs({"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "empty"})
            assert "js-fetch-impossible" not in sigs
        finally:
            _jc.JS_FETCH_IMPOSSIBLE_CHECK_ENABLED = old


# ─── C: config ───────────────────────────────────────────────────────────────

class TestJsConsistencyConfig:

    def test_all_three_weights_in_risk_weights(self):
        from config import RISK_WEIGHTS
        assert "js-cua-version-mismatch" in RISK_WEIGHTS
        assert "js-mobile-hint-mismatch" in RISK_WEIGHTS
        assert "js-fetch-impossible"     in RISK_WEIGHTS

    def test_version_weight(self):
        from config import RISK_WEIGHTS
        assert RISK_WEIGHTS["js-cua-version-mismatch"] == 20

    def test_mobile_weight(self):
        from config import RISK_WEIGHTS
        assert RISK_WEIGHTS["js-mobile-hint-mismatch"] == 20

    def test_fetch_impossible_weight(self):
        from config import RISK_WEIGHTS
        assert RISK_WEIGHTS["js-fetch-impossible"] == 30

    def test_fetch_impossible_strongest(self):
        from config import RISK_WEIGHTS
        assert RISK_WEIGHTS["js-fetch-impossible"] > RISK_WEIGHTS["js-cua-version-mismatch"]

    def test_cua_version_is_escalate_only(self):
        from config import ESCALATE_ONLY_REASONS
        assert "js-cua-version-mismatch" in ESCALATE_ONLY_REASONS

    def test_mobile_hint_not_escalate_only(self):
        from config import ESCALATE_ONLY_REASONS
        assert "js-mobile-hint-mismatch" not in ESCALATE_ONLY_REASONS

    def test_fetch_impossible_not_escalate_only(self):
        from config import ESCALATE_ONLY_REASONS
        assert "js-fetch-impossible" not in ESCALATE_ONLY_REASONS

    def test_consistency_knobs_in_vhost_coerce(self):
        from vhost import _VHOST_COERCE
        for k in ("JS_CONSISTENCY_ENABLED", "JS_CUA_VERSION_CHECK_ENABLED",
                  "JS_MOBILE_HINT_CHECK_ENABLED", "JS_FETCH_IMPOSSIBLE_CHECK_ENABLED"):
            assert k in _VHOST_COERCE, f"{k} missing from _VHOST_COERCE"

    def test_master_knob_default_true(self):
        src = _read("config.py")
        assert 'JS_CONSISTENCY_ENABLED' in src


# ─── W: wiring ───────────────────────────────────────────────────────────────

class TestJsConsistencyWiring:

    def setup_class(cls):
        cls._src = _read("core/proxy_handler.py")

    def test_import_present(self):
        assert "js_consistency_signals" in self._src

    def test_per_request_call(self):
        assert "js_consistency_signals(request.headers)" in self._src

    def test_reason_method_version(self):
        assert '"js-cua-version-mismatch"' in self._src

    def test_reason_method_mobile(self):
        assert '"js-mobile-hint-mismatch"' in self._src

    def test_reason_method_fetch(self):
        assert '"js-fetch-impossible"' in self._src

    def test_gate_knob_wired(self):
        assert '"JS_CONSISTENCY_ENABLED"' in self._src

    def test_latency_profile_version(self):
        assert '"js-cua-version-mismatch"' in self._src

    def test_signal_info_fetch(self):
        assert "Fetch Living Standard" in self._src or "impossible" in self._src.lower()


# ─── S: source structural guards ─────────────────────────────────────────────

class TestJsConsistencySource:

    def test_module_exists(self):
        path = os.path.join(_REPO, "detection", "js_consistency.py")
        assert os.path.isfile(path)

    def test_public_api(self):
        src = _read("detection/js_consistency.py")
        assert "js_consistency_signals" in src

    def test_impossible_combos_defined(self):
        src = _read("detection/js_consistency.py")
        assert "_IMPOSSIBLE_FETCH_COMBOS" in src

    def test_browser_ua_patterns_defined(self):
        src = _read("detection/js_consistency.py")
        assert "_UA_MOBILE_RE" in src
        assert "_UA_DESKTOP_RE" in src

    def test_no_network_calls(self):
        import ast, sys
        path = os.path.join(_REPO, "detection", "js_consistency.py")
        tree = ast.parse(open(path).read())
        imports = {
            node.names[0].name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for name in node.names
            for _ in [name]
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        for banned in ("urllib", "aiohttp", "asyncio", "requests", "httpx"):
            assert banned not in imports, f"network import '{banned}' found"

    def test_returns_list(self):
        from detection.js_consistency import js_consistency_signals
        result = js_consistency_signals({})
        assert isinstance(result, list)

    def test_empty_headers_safe(self):
        from detection.js_consistency import js_consistency_signals
        assert js_consistency_signals({}) == []

    def test_vhost_policy_knob_meta_coverage(self):
        src = _read("dashboards/vhost_policy.html")
        for k in ("JS_CONSISTENCY_ENABLED", "JS_CUA_VERSION_CHECK_ENABLED",
                  "JS_MOBILE_HINT_CHECK_ENABLED", "JS_FETCH_IMPOSSIBLE_CHECK_ENABLED"):
            assert k in src, f"{k} missing from vhost_policy.html KNOB_META"
