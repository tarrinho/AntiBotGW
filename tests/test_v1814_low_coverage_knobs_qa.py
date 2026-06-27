"""
tests/test_v1814_low_coverage_knobs_qa.py — QA for hot-reload knobs with low
test coverage (only 1 reference each in the full test suite prior to 1.8.14).

Each knob gets:
  - Membership in _HOT_RELOAD_KNOBS with correct parser type
  - Correct default value in config.py
  - Signal→knob mapping in SIGNAL_KNOB (where applicable)
  - Source-code gate presence in the detection hot-path
  - For numeric knobs: bounds validation (in-range accepts, out-of-range rejects)

Groups:
  B — bool knobs (18 knobs, ~54 tests)
  N — numeric knobs (5 knobs, ~20 tests)
"""
import os
import pathlib
import re
import pytest

os.environ.setdefault("UPSTREAM", "http://localhost")

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


def _hot_reload_knobs():
    from core.proxy_handler import _HOT_RELOAD_KNOBS
    return _HOT_RELOAD_KNOBS


def _signal_knob():
    from core.proxy_handler import SIGNAL_KNOB
    return SIGNAL_KNOB


def _to_bool_ref():
    from core.proxy_handler import _to_bool
    return _to_bool


# ── helpers ───────────────────────────────────────────────────────────────────

def _assert_bool_knob(name, default_val, signal=None, gate_file=None, gate_str=None):
    """Shared assertion bundle for every bool knob."""
    tb = _to_bool_ref()
    hrk = _hot_reload_knobs()

    assert name in hrk, f"{name} missing from _HOT_RELOAD_KNOBS"
    parser, _ = hrk[name]
    assert parser is tb, (
        f"{name} must use _to_bool as parser (got {parser!r}); "
        "changing the parser type is a breaking hot-reload contract change"
    )

    import config
    actual = getattr(config, name)
    assert actual == default_val, (
        f"config.{name} default is {actual!r}, expected {default_val!r}; "
        "update config.py or this test together"
    )

    if signal is not None:
        sk = _signal_knob()
        assert signal in sk, f"SIGNAL_KNOB missing key {signal!r}"
        assert sk[signal] == name, (
            f"SIGNAL_KNOB[{signal!r}] = {sk[signal]!r}, expected {name!r}"
        )

    if gate_file is not None and gate_str is not None:
        src = _read(gate_file)
        assert gate_str in src, (
            f"Source gate {gate_str!r} not found in {gate_file}; "
            f"{name} gate must be checked in the detection hot-path"
        )


# ── B: bool knobs ─────────────────────────────────────────────────────────────

class TestBoolKnobs:
    """One test per knob exercising the full assertion bundle."""

    # ── JS challenge knobs (1.8.13) ───────────────────────────────────────────

    def test_b01_js_chal_bind_ja4_registration(self):
        _assert_bool_knob(
            "JS_CHAL_BIND_JA4",
            default_val=True,
            gate_file="challenge/js_challenge.py",
            gate_str="JS_CHAL_BIND_JA4",
        )

    def test_b01_js_chal_bind_ja4_gate_binds_when_true(self):
        src = _read("challenge/js_challenge.py")
        # Full gate: `bind_ja4 = ja4 if (JS_CHAL_BIND_JA4 and ja4) else ""`
        assert "bind_ja4 = ja4 if" in src, (
            "JS_CHAL_BIND_JA4 gate must assign bind_ja4 conditionally "
            "(bind_ja4 = ja4 if (JS_CHAL_BIND_JA4 and ja4) else '')"
        )
        assert "JS_CHAL_BIND_JA4 and ja4" in src, (
            "JS_CHAL_BIND_JA4 gate expression must include 'JS_CHAL_BIND_JA4 and ja4'"
        )

    def test_b01_js_chal_bind_ja4_gate_empty_when_false(self):
        src = _read("challenge/js_challenge.py")
        # Gate pattern: `bind_ja4 = ja4 if (JS_CHAL_BIND_JA4 and ja4) else ""`
        assert 'else ""' in src or "else ''" in src, (
            "JS_CHAL_BIND_JA4 gate must fall back to empty string (no binding)"
        )

    # ── Detection knobs (1.8.13 group) ───────────────────────────────────────

    def test_b02_suspicious_path_enabled(self):
        _assert_bool_knob(
            "SUSPICIOUS_PATH_ENABLED",
            default_val=True,
            signal="suspicious-path",
            gate_file="core/proxy_handler.py",
            gate_str="SUSPICIOUS_PATH_ENABLED",
        )

    def test_b02_suspicious_path_gate_uses_vc(self):
        src = _read("core/proxy_handler.py")
        assert "vc('SUSPICIOUS_PATH_ENABLED')" in src, (
            "SUSPICIOUS_PATH_ENABLED must be checked via vc() for per-vhost override"
        )

    def test_b03_ai_probe_enabled(self):
        _assert_bool_knob(
            "AI_PROBE_ENABLED",
            default_val=True,
            signal="ai-probe",
            gate_file="core/proxy_handler.py",
            gate_str="if AI_PROBE_ENABLED",
        )

    def test_b04_ua_platform_check_enabled(self):
        _assert_bool_knob(
            "UA_PLATFORM_CHECK_ENABLED",
            default_val=True,
            signal="ua-platform-mismatch",
            gate_file="core/proxy_handler.py",
            gate_str="if UA_PLATFORM_CHECK_ENABLED",
        )

    def test_b04_ua_platform_check_exported_from_detection_headers(self):
        src = _read("detection/headers.py")
        assert "UA_PLATFORM_CHECK_ENABLED" in src, (
            "detection/headers.py must re-export UA_PLATFORM_CHECK_ENABLED "
            "so the extracted module stays consistent with proxy_handler"
        )

    def test_b05_header_completeness_enabled(self):
        _assert_bool_knob(
            "HEADER_COMPLETENESS_ENABLED",
            default_val=True,
            signal="ai-headers-empty",
            gate_file="core/proxy_handler.py",
            gate_str="if HEADER_COMPLETENESS_ENABLED",
        )

    def test_b05_header_completeness_second_signal_mapped(self):
        sk = _signal_knob()
        assert "ai-headers-incomplete" in sk
        assert sk["ai-headers-incomplete"] == "HEADER_COMPLETENESS_ENABLED", (
            "Both ai-headers-empty and ai-headers-incomplete must map to "
            "HEADER_COMPLETENESS_ENABLED (they share the same gate)"
        )

    def test_b05_header_completeness_exported_from_detection_headers(self):
        src = _read("detection/headers.py")
        assert "HEADER_COMPLETENESS_ENABLED" in src, (
            "detection/headers.py must re-export HEADER_COMPLETENESS_ENABLED"
        )

    def test_b06_behavioral_check_enabled(self):
        _assert_bool_knob(
            "BEHAVIORAL_CHECK_ENABLED",
            default_val=True,
            signal="behavior",
            gate_file="core/proxy_handler.py",
            gate_str="if BEHAVIORAL_CHECK_ENABLED",
        )

    def test_b06_behavioral_check_exported_from_detection_behavioral(self):
        src = _read("detection/behavioral.py")
        assert "BEHAVIORAL_CHECK_ENABLED" in src, (
            "detection/behavioral.py must import/re-export BEHAVIORAL_CHECK_ENABLED"
        )

    def test_b07_ai_enumeration_enabled(self):
        _assert_bool_knob(
            "AI_ENUMERATION_ENABLED",
            default_val=True,
            signal="ai-enumeration",
            gate_file="core/proxy_handler.py",
            gate_str="if AI_ENUMERATION_ENABLED",
        )

    def test_b08_ai_no_assets_enabled(self):
        _assert_bool_knob(
            "AI_NO_ASSETS_ENABLED",
            default_val=True,
            signal="ai-no-assets",
            gate_file="core/proxy_handler.py",
            gate_str="if AI_NO_ASSETS_ENABLED",
        )

    def test_b09_session_flood_enabled(self):
        _assert_bool_knob(
            "SESSION_FLOOD_ENABLED",
            default_val=True,
            signal="session-flood",
            gate_file="core/proxy_handler.py",
            gate_str="if SESSION_FLOOD_ENABLED",
        )

    def test_b10_upstream_404_tracking_enabled(self):
        _assert_bool_knob(
            "UPSTREAM_404_TRACKING_ENABLED",
            default_val=True,
            signal="upstream-404",
            gate_file="core/proxy_handler.py",
            gate_str="if UPSTREAM_404_TRACKING_ENABLED",
        )

    def test_b10_upstream_404_gate_checks_response_status(self):
        src = _read("core/proxy_handler.py")
        idx = src.find("if UPSTREAM_404_TRACKING_ENABLED")
        assert idx != -1
        window = src[idx:idx + 80]
        assert "404" in window, (
            "UPSTREAM_404_TRACKING_ENABLED gate must be conditioned on "
            "response.status == 404 in the same expression"
        )

    # ── Labyrinth / accept-fp knobs (1.6.8 / 1.6.10) ─────────────────────────

    def test_b11_labyrinth_jitter_enabled(self):
        _assert_bool_knob(
            "LABYRINTH_JITTER_ENABLED",
            default_val=True,
            signal="labyrinth-jitter",
            gate_file="challenge/tarpit.py",
            gate_str="if LABYRINTH_JITTER_ENABLED",
        )

    def test_b11_labyrinth_jitter_gate_not_in_proxy_handler(self):
        # Gate lives in challenge/tarpit.py (extracted module).
        # proxy_handler only holds the knob definition and SIGNAL_KNOB entry.
        src = _read("core/proxy_handler.py")
        assert "if LABYRINTH_JITTER_ENABLED" not in src, (
            "LABYRINTH_JITTER_ENABLED gate must stay in challenge/tarpit.py, "
            "not duplicated in proxy_handler"
        )

    def test_b12_accept_fp_enabled(self):
        _assert_bool_knob(
            "ACCEPT_FP_ENABLED",
            default_val=True,
            signal="accept-fp",
            gate_file="core/proxy_handler.py",
            gate_str="ACCEPT_FP_ENABLED",
        )

    def test_b12_accept_fp_gate_checks_sec_fetch_dest(self):
        src = _read("core/proxy_handler.py")
        idx = src.find("if (ACCEPT_FP_ENABLED")
        assert idx != -1, "ACCEPT_FP_ENABLED gate must use `if (ACCEPT_FP_ENABLED …)`"
        window = src[idx:idx + 120]
        assert "sec_fetch_dest" in window, (
            "ACCEPT_FP_ENABLED gate must include sec_fetch_dest == 'document' guard"
        )

    def test_b13_header_canary_enabled(self):
        _assert_bool_knob(
            "HEADER_CANARY_ENABLED",
            default_val=True,
            signal="header-canary",
            gate_file="core/proxy_handler.py",
            gate_str="if HEADER_CANARY_ENABLED",
        )

    def test_b13_header_canary_gate_sets_etag(self):
        src = _read("core/proxy_handler.py")
        idx = src.find("if HEADER_CANARY_ENABLED")
        assert idx != -1
        window = src[idx:idx + 200]
        assert "ETag" in window, (
            "HEADER_CANARY_ENABLED gate must plant canary in ETag header"
        )

    def test_b14_header_order_fp_enabled(self):
        _assert_bool_knob(
            "HEADER_ORDER_FP_ENABLED",
            default_val=True,
            signal="header-order-fp",
            gate_file="core/proxy_handler.py",
            gate_str="if HEADER_ORDER_FP_ENABLED",
        )

    def test_b14_header_order_fp_calls_is_library_headers(self):
        src = _read("core/proxy_handler.py")
        idx = src.find("if HEADER_ORDER_FP_ENABLED")
        assert idx != -1
        window = src[idx:idx + 100]
        assert "_is_library_headers" in window, (
            "HEADER_ORDER_FP_ENABLED gate must call _is_library_headers(request)"
        )

    def test_b15_ai_crawler_verify_enabled(self):
        _assert_bool_knob(
            "AI_CRAWLER_VERIFY_ENABLED",
            default_val=True,
            signal="ai-ua-ip-mismatch",
            gate_file="core/proxy_handler.py",
            gate_str="if AI_CRAWLER_VERIFY_ENABLED",
        )

    def test_b16_ja4_fail_closed(self):
        _assert_bool_knob(
            "JA4_FAIL_CLOSED",
            default_val=False,
            gate_file="core/proxy_handler.py",
            gate_str="if JA4_FAIL_CLOSED",
        )

    def test_b16_ja4_fail_closed_is_opt_in(self):
        import config
        assert config.JA4_FAIL_CLOSED is False, (
            "JA4_FAIL_CLOSED must default False — opt-in only. "
            "Defaulting to True would break deployments without JA4 headers."
        )

    def test_b17_robots_monitor_enabled(self):
        _assert_bool_knob(
            "ROBOTS_MONITOR_ENABLED",
            default_val=True,
            signal="robots-violation",
            gate_file="core/proxy_handler.py",
            gate_str="if ROBOTS_MONITOR_ENABLED",
        )

    def test_b18_h2_fp_enabled(self):
        _assert_bool_knob(
            "H2_FP_ENABLED",
            default_val=False,
            signal="h2-fp",
            gate_file="core/proxy_handler.py",
            gate_str="if H2_FP_ENABLED",
        )

    def test_b18_h2_fp_is_opt_in(self):
        import config
        assert config.H2_FP_ENABLED is False, (
            "H2_FP_ENABLED must default False — signal is weak without "
            "TLS context (see code comment). Opt-in only."
        )


# ── N: numeric knobs ──────────────────────────────────────────────────────────

class TestNumericKnobsRegistration:
    """Membership + parser type for the 5 numeric knobs."""

    def test_n01_cookie_ghost_min_requests_is_int(self):
        hrk = _hot_reload_knobs()
        assert "COOKIE_GHOST_MIN_REQUESTS" in hrk
        parser, validator = hrk["COOKIE_GHOST_MIN_REQUESTS"]
        assert parser is int, "COOKIE_GHOST_MIN_REQUESTS parser must be int"
        assert validator is not None, "must have a bounds validator"

    def test_n02_cookie_ghost_miss_threshold_is_int(self):
        hrk = _hot_reload_knobs()
        assert "COOKIE_GHOST_MISS_THRESHOLD" in hrk
        parser, validator = hrk["COOKIE_GHOST_MISS_THRESHOLD"]
        assert parser is int
        assert validator is not None

    def test_n03_impossible_travel_window_secs_is_int(self):
        hrk = _hot_reload_knobs()
        assert "IMPOSSIBLE_TRAVEL_WINDOW_SECS" in hrk
        parser, validator = hrk["IMPOSSIBLE_TRAVEL_WINDOW_SECS"]
        assert parser is int
        assert validator is not None

    def test_n04_pow_chal_threshold_is_float(self):
        hrk = _hot_reload_knobs()
        assert "POW_CHAL_THRESHOLD" in hrk
        parser, validator = hrk["POW_CHAL_THRESHOLD"]
        assert parser is float
        assert validator is not None

    def test_n05_turnstile_risk_threshold_is_float(self):
        hrk = _hot_reload_knobs()
        assert "TURNSTILE_RISK_THRESHOLD" in hrk
        parser, validator = hrk["TURNSTILE_RISK_THRESHOLD"]
        assert parser is float
        assert validator is not None


class TestNumericKnobDefaults:
    """Default values from config.py."""

    def test_n01_cookie_ghost_min_requests_default_3(self):
        import config
        assert config.COOKIE_GHOST_MIN_REQUESTS == 3, (
            "COOKIE_GHOST_MIN_REQUESTS default must be 3; changing it shifts "
            "the threshold for all running deployments"
        )

    def test_n02_cookie_ghost_miss_threshold_default_3(self):
        import config
        assert config.COOKIE_GHOST_MISS_THRESHOLD == 3

    def test_n03_impossible_travel_window_default_1800(self):
        import config
        assert config.IMPOSSIBLE_TRAVEL_WINDOW_SECS == 1800, (
            "IMPOSSIBLE_TRAVEL_WINDOW_SECS default must be 1800 s (30 min)"
        )

    def test_n04_pow_chal_threshold_default_30(self):
        import config
        assert config.POW_CHAL_THRESHOLD == 30.0, (
            "POW_CHAL_THRESHOLD default must be 30.0"
        )

    def test_n05_turnstile_risk_threshold_default_0(self):
        import config
        assert config.TURNSTILE_RISK_THRESHOLD == 0.0, (
            "TURNSTILE_RISK_THRESHOLD default must be 0.0 (disabled until "
            "operator sets a positive value or Turnstile is configured)"
        )


class TestNumericKnobBounds:
    """Bounds validators reject out-of-range values, accept edge values."""

    def _val(self, name, raw):
        hrk = _hot_reload_knobs()
        parser, validator = hrk[name]
        v = parser(raw)
        if validator:
            return validator(v)
        return True

    # COOKIE_GHOST_MIN_REQUESTS: 1 <= v <= 1000
    def test_n01_cookie_ghost_min_requests_low_edge_valid(self):
        assert self._val("COOKIE_GHOST_MIN_REQUESTS", 1) is True

    def test_n01_cookie_ghost_min_requests_high_edge_valid(self):
        assert self._val("COOKIE_GHOST_MIN_REQUESTS", 1000) is True

    def test_n01_cookie_ghost_min_requests_zero_invalid(self):
        assert self._val("COOKIE_GHOST_MIN_REQUESTS", 0) is False

    def test_n01_cookie_ghost_min_requests_over_max_invalid(self):
        assert self._val("COOKIE_GHOST_MIN_REQUESTS", 1001) is False

    # COOKIE_GHOST_MISS_THRESHOLD: 1 <= v <= 100
    def test_n02_cookie_ghost_miss_threshold_low_edge_valid(self):
        assert self._val("COOKIE_GHOST_MISS_THRESHOLD", 1) is True

    def test_n02_cookie_ghost_miss_threshold_high_edge_valid(self):
        assert self._val("COOKIE_GHOST_MISS_THRESHOLD", 100) is True

    def test_n02_cookie_ghost_miss_threshold_zero_invalid(self):
        assert self._val("COOKIE_GHOST_MISS_THRESHOLD", 0) is False

    def test_n02_cookie_ghost_miss_threshold_over_max_invalid(self):
        assert self._val("COOKIE_GHOST_MISS_THRESHOLD", 101) is False

    # IMPOSSIBLE_TRAVEL_WINDOW_SECS: 60 <= v <= 86400*7 = 604800
    def test_n03_impossible_travel_min_60_valid(self):
        assert self._val("IMPOSSIBLE_TRAVEL_WINDOW_SECS", 60) is True

    def test_n03_impossible_travel_max_604800_valid(self):
        assert self._val("IMPOSSIBLE_TRAVEL_WINDOW_SECS", 604800) is True

    def test_n03_impossible_travel_59_invalid(self):
        assert self._val("IMPOSSIBLE_TRAVEL_WINDOW_SECS", 59) is False

    def test_n03_impossible_travel_over_max_invalid(self):
        assert self._val("IMPOSSIBLE_TRAVEL_WINDOW_SECS", 604801) is False

    # POW_CHAL_THRESHOLD: 0.0 <= v <= 100000.0
    def test_n04_pow_chal_threshold_zero_valid(self):
        assert self._val("POW_CHAL_THRESHOLD", 0) is True

    def test_n04_pow_chal_threshold_max_valid(self):
        assert self._val("POW_CHAL_THRESHOLD", 100000.0) is True

    def test_n04_pow_chal_threshold_negative_invalid(self):
        assert self._val("POW_CHAL_THRESHOLD", -0.01) is False

    def test_n04_pow_chal_threshold_over_max_invalid(self):
        assert self._val("POW_CHAL_THRESHOLD", 100000.01) is False

    def test_n04_pow_chal_threshold_zero_disables_pow_gate(self):
        # When POW_CHAL_THRESHOLD == 0, the `if POW_CHAL_THRESHOLD > 0` guard
        # in proxy_handler must skip the PoW gate entirely.
        src = _read("core/proxy_handler.py")
        assert "if POW_CHAL_THRESHOLD > 0" in src, (
            "proxy_handler must short-circuit the PoW gate when "
            "POW_CHAL_THRESHOLD == 0 (disabled state)"
        )

    # TURNSTILE_RISK_THRESHOLD: 0.0 <= v <= 100000.0
    def test_n05_turnstile_risk_threshold_zero_valid(self):
        assert self._val("TURNSTILE_RISK_THRESHOLD", 0) is True

    def test_n05_turnstile_risk_threshold_max_valid(self):
        assert self._val("TURNSTILE_RISK_THRESHOLD", 100000.0) is True

    def test_n05_turnstile_risk_threshold_negative_invalid(self):
        assert self._val("TURNSTILE_RISK_THRESHOLD", -1.0) is False

    def test_n05_turnstile_risk_threshold_over_max_invalid(self):
        assert self._val("TURNSTILE_RISK_THRESHOLD", 100000.01) is False

    def test_n05_turnstile_risk_threshold_zero_disables_in_source(self):
        # challenge/js_challenge.py: `if TURNSTILE_RISK_THRESHOLD > 0: return ...`
        src = _read("challenge/js_challenge.py")
        assert "TURNSTILE_RISK_THRESHOLD > 0" in src, (
            "challenge/js_challenge.py must skip the Turnstile threshold when "
            "TURNSTILE_RISK_THRESHOLD == 0"
        )


class TestNumericKnobSourceGates:
    """Source-code gate presence in the detection hot-path."""

    def test_n01_cookie_ghost_uses_min_requests_in_lifecycle(self):
        src = _read("detection/cookie_lifecycle.py")
        assert "COOKIE_GHOST_MIN_REQUESTS" in src, (
            "COOKIE_GHOST_MIN_REQUESTS must be imported + used in "
            "detection/cookie_lifecycle.py"
        )

    def test_n01_cookie_ghost_uses_miss_threshold_in_lifecycle(self):
        src = _read("detection/cookie_lifecycle.py")
        assert "COOKIE_GHOST_MISS_THRESHOLD" in src

    def test_n01_cookie_lifecycle_gates_on_min_requests(self):
        src = _read("detection/cookie_lifecycle.py")
        assert "COOKIE_GHOST_MIN_REQUESTS" in src
        # B-08: threshold now uses effective_min = COOKIE_GHOST_MIN_REQUESTS + jitter;
        # accept either the old direct comparison or the jittered form.
        assert (">= COOKIE_GHOST_MIN_REQUESTS" in src or ">= effective_min" in src), (
            "cookie_lifecycle must compare req_count against COOKIE_GHOST_MIN_REQUESTS "
            "(directly or via effective_min = COOKIE_GHOST_MIN_REQUESTS + jitter)"
        )

    def test_n02_impossible_travel_uses_window_in_detection(self):
        src = _read("detection/impossible_travel.py")
        assert "IMPOSSIBLE_TRAVEL_WINDOW_SECS" in src, (
            "IMPOSSIBLE_TRAVEL_WINDOW_SECS must be used in "
            "detection/impossible_travel.py"
        )

    def test_n02_impossible_travel_gate_is_strict_lt(self):
        src = _read("detection/impossible_travel.py")
        # Gate: `if 0 < elapsed < IMPOSSIBLE_TRAVEL_WINDOW_SECS`
        assert "< IMPOSSIBLE_TRAVEL_WINDOW_SECS" in src, (
            "impossible_travel gate must compare elapsed < IMPOSSIBLE_TRAVEL_WINDOW_SECS "
            "(fires when two locations seen within the window)"
        )

    def test_n04_pow_chal_threshold_used_in_proxy_handler(self):
        src = _read("core/proxy_handler.py")
        # `if _s_pow and _s_pow.risk_score >= POW_CHAL_THRESHOLD`
        assert "POW_CHAL_THRESHOLD" in src
        assert "_s_pow.risk_score >= POW_CHAL_THRESHOLD" in src or \
               "risk_score >= POW_CHAL_THRESHOLD" in src, (
            "PoW gate must compare identity risk_score against POW_CHAL_THRESHOLD"
        )

    def test_n05_turnstile_risk_threshold_used_in_js_challenge(self):
        src = _read("challenge/js_challenge.py")
        assert "TURNSTILE_RISK_THRESHOLD" in src
