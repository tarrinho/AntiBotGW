"""
tests/test_v189_knob_kill_switches.py — QA for the 1.8.9 always-on → knob conversion.

Context: In 1.8.9 all 31 previously structural / always-on WAF checks gained
dedicated kill-switch knobs (default ON, togglable via env or hot-reload).
This file verifies the conversion is complete and correct.

Registry tests (R)  — structural completeness of the knob registry
  R01  All 29 new knobs are in _HOT_RELOAD_KNOBS
  R02  All 29 new knobs default to True in config.py
  R03  No signal maps to SIGNAL_KNOB=None in the full signal list
  R04  Every signal in RISK_WEIGHTS has a non-None SIGNAL_KNOB entry
  R05  All 29 new knob names are in config module namespace

Gate tests (G)  — gate logic: check is skipped when knob is False
  G01  WAF_BODY_ENABLED=False skips body-critical-injection check
  G02  WAF_BODY_ENABLED=False skips body-xxe check
  G03  WAF_SMUGGLING_ENABLED=False skips smuggling-cl-te check
  G04  WAF_VERB_OVERRIDE_ENABLED=False skips method-override check
  G05  WAF_HEADER_INJECTION_ENABLED=False skips header-ssti check
  G06  WAF_GRAPHQL_ENABLED=False skips gql-introspection check
  G07  WAF_UPLOAD_ENABLED=False skips upload-dangerous-ext check
  G08  SESSION_CHURN_ENABLED=False gates session_churn path
  G09  RATE_LIMIT_ENABLED=False gates rate limiter call

Hot-reload tests (H)  — knob survives round-trip through db_load_config
  H01  WAF_BODY_ENABLED persists False through round-trip
  H02  WAF_SMUGGLING_ENABLED persists False through round-trip
  H03  RATE_LIMIT_ENABLED persists False through round-trip
  H04  HOST_BLOCKING_ENABLED persists False through round-trip
  H05  All 29 new knobs present in test_165 round-trip guard
  H06  Setting a knob False then back True restores default behaviour

Signal-knob mapping tests (S)
  S01  SIGNAL_KNOB for 'slow-client' is 'WAF_SLOWLORIS_ENABLED'
  S02  SIGNAL_KNOB for 'accept-wildcard-html' is 'ACCEPT_WILDCARD_CHECK_ENABLED'
  S03  SIGNAL_KNOB for 'session-churn' is 'SESSION_CHURN_ENABLED'
  S04  SIGNAL_KNOB for 'rate-limit' is 'RATE_LIMIT_ENABLED'
  S05  SIGNAL_KNOB for 'tls-fingerprint' is 'TLS_FP_BLOCK_ENABLED'
  S06  SIGNAL_KNOB for 'auth-jwt-invalid' is 'JWT_VALIDATION_ENABLED'
  S07  SIGNAL_KNOB for 'direct-api-probe' is 'JOURNEY_CHECK_ENABLED'
  S08  SIGNAL_KNOB for 'coordinated-probe' is 'COORDINATED_ATTACK_ENABLED'
  S09  SIGNAL_KNOB for 'custom-rule-block' is 'CUSTOM_RULES_ENABLED'
  S10  SIGNAL_KNOB for 'fp-banned' is 'FP_BAN_CHECK_ENABLED'
  S11  SIGNAL_KNOB for 'traffic-threshold' is 'TRAFFIC_THRESHOLD_ENABLED'
  S12  SIGNAL_KNOB for 'upstream-auth-fail' is 'UPSTREAM_AUTH_FAIL_ENABLED'
  S13  SIGNAL_KNOB for 'rate-limit-ip' is 'RATE_LIMIT_IP_ENABLED'
  S14  SIGNAL_KNOB for 'rate-limit-endpoint' is 'ENDPOINT_RATE_LIMIT_ENABLED'
  S15  SIGNAL_KNOB for 'host-not-allowed' is 'HOST_BLOCKING_ENABLED'
  S16  SIGNAL_KNOB for 'missing-required-header' is 'REQUIRED_HEADERS_ENABLED'
  S17  SIGNAL_KNOB for 'ja4-required-missing' is 'JA4_REQUIRED_ENABLED'
  S18  SIGNAL_KNOB for 'ja4h-deny' is 'JA4H_DENY_ENABLED'
  S19  SIGNAL_KNOB for 'honey-cred' is 'HONEY_CRED_ENABLED'
  S20  SIGNAL_KNOB for 'canary-probe-miss' is 'CANARY_PROBE_ENABLED'
  S21  SIGNAL_KNOB for 'llm-no-subresources' is 'LLM_HEURISTIC_ENABLED'
  S22  SIGNAL_KNOB for 'webdriver-detected' is 'AUTOMATION_PROBE_ENABLED'
  S23  SIGNAL_KNOB for 'bot-motion' is 'INTERACTION_PROBE_ENABLED'

Dashboard tests (D)  — controls.html correctly exposes all new knobs
  D01  controls.html contains all 29 new knob names
  D02  No signal appears under the always-on section label in controls.html
  D03  WAF_BODY_ENABLED knob has bool kind in controls META
  D04  RATE_LIMIT_ENABLED knob has bool kind in controls META
"""

import os
import sqlite3
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE.parent))

os.environ.setdefault("UPSTREAM", "https://test-upstream.example.com")

import config  # noqa: E402
from core import proxy_handler as proxy  # noqa: E402

# ── All 29 new knobs introduced in 1.8.9 ──────────────────────────────────────
_NEW_KNOBS_189 = [
    "WAF_BODY_ENABLED",
    "WAF_SMUGGLING_ENABLED",
    "WAF_VERB_OVERRIDE_ENABLED",
    "WAF_HEADER_INJECTION_ENABLED",
    "WAF_GRAPHQL_ENABLED",
    "WAF_UPLOAD_ENABLED",
    "WAF_SLOWLORIS_ENABLED",
    "ACCEPT_WILDCARD_CHECK_ENABLED",
    "SESSION_CHURN_ENABLED",
    "JA4H_DENY_ENABLED",
    "HOST_BLOCKING_ENABLED",
    "REQUIRED_HEADERS_ENABLED",
    "JA4_REQUIRED_ENABLED",
    "UPSTREAM_AUTH_FAIL_ENABLED",
    "RATE_LIMIT_IP_ENABLED",
    "RATE_LIMIT_ENABLED",
    "FP_BAN_CHECK_ENABLED",
    "TRAFFIC_THRESHOLD_ENABLED",
    "TLS_FP_BLOCK_ENABLED",
    "JWT_VALIDATION_ENABLED",
    "CUSTOM_RULES_ENABLED",
    "ENDPOINT_RATE_LIMIT_ENABLED",
    "HONEY_CRED_ENABLED",
    "CANARY_PROBE_ENABLED",
    "LLM_HEURISTIC_ENABLED",
    "AUTOMATION_PROBE_ENABLED",
    "INTERACTION_PROBE_ENABLED",
    "COORDINATED_ATTACK_ENABLED",
    "JOURNEY_CHECK_ENABLED",
]

# ── Expected SIGNAL_KNOB mappings for the signals that lost their None ─────────
_EXPECTED_SIGNAL_KNOBS = {
    "slow-client":             "WAF_SLOWLORIS_ENABLED",
    "accept-wildcard-html":    "ACCEPT_WILDCARD_CHECK_ENABLED",
    "body-critical-injection": "WAF_BODY_ENABLED",
    "body-xxe":                "WAF_BODY_ENABLED",
    "body-proto-pollution":    "WAF_BODY_ENABLED",
    "smuggling-cl-te":         "WAF_SMUGGLING_ENABLED",
    "smuggling-te-cl":         "WAF_SMUGGLING_ENABLED",
    "smuggling-te-te":         "WAF_SMUGGLING_ENABLED",
    "smuggling-invalid-te":    "WAF_SMUGGLING_ENABLED",
    "smuggling-dual-header":   "WAF_SMUGGLING_ENABLED",
    "smuggling-obfuscated-te": "WAF_SMUGGLING_ENABLED",
    "smuggling-duplicate-cl":  "WAF_SMUGGLING_ENABLED",
    "method-override-attempt": "WAF_VERB_OVERRIDE_ENABLED",
    "header-ssti":             "WAF_HEADER_INJECTION_ENABLED",
    "host-header-injection":   "WAF_HEADER_INJECTION_ENABLED",
    "gql-introspection":       "WAF_GRAPHQL_ENABLED",
    "gql-batch-abuse":         "WAF_GRAPHQL_ENABLED",
    "gql-depth-exceeded":      "WAF_GRAPHQL_ENABLED",
    "upload-dangerous-ext":    "WAF_UPLOAD_ENABLED",
    "upload-dangerous-magic":  "WAF_UPLOAD_ENABLED",
    "session-churn":           "SESSION_CHURN_ENABLED",
    "ja4h-deny":               "JA4H_DENY_ENABLED",
    "host-not-allowed":        "HOST_BLOCKING_ENABLED",
    "missing-required-header": "REQUIRED_HEADERS_ENABLED",
    "ja4-required-missing":    "JA4_REQUIRED_ENABLED",
    "upstream-auth-fail":      "UPSTREAM_AUTH_FAIL_ENABLED",
    "rate-limit-ip":           "RATE_LIMIT_IP_ENABLED",
    "rate-limit":              "RATE_LIMIT_ENABLED",
    "fp-banned":               "FP_BAN_CHECK_ENABLED",
    "traffic-threshold":       "TRAFFIC_THRESHOLD_ENABLED",
    "tls-fingerprint":         "TLS_FP_BLOCK_ENABLED",
    "auth-jwt-invalid":        "JWT_VALIDATION_ENABLED",
    "custom-rule-block":       "CUSTOM_RULES_ENABLED",
    "rate-limit-endpoint":     "ENDPOINT_RATE_LIMIT_ENABLED",
    "honey-cred":              "HONEY_CRED_ENABLED",
    "canary-probe-miss":       "CANARY_PROBE_ENABLED",
    "llm-no-subresources":     "LLM_HEURISTIC_ENABLED",
    "webdriver-detected":      "AUTOMATION_PROBE_ENABLED",
    "bot-motion":              "INTERACTION_PROBE_ENABLED",
    "no-interaction":          "INTERACTION_PROBE_ENABLED",
    "scripted-motion":         "INTERACTION_PROBE_ENABLED",
    "bot-scroll":              "INTERACTION_PROBE_ENABLED",
    "scripted-keys":           "INTERACTION_PROBE_ENABLED",
    "low-entropy-input":       "INTERACTION_PROBE_ENABLED",
    "coordinated-probe":       "COORDINATED_ATTACK_ENABLED",
    "direct-api-probe":        "JOURNEY_CHECK_ENABLED",
}


# =============================================================================
# R — Registry completeness
# =============================================================================

class TestRegistryCompleteness:
    """R01–R05: structural checks on _HOT_RELOAD_KNOBS, config, SIGNAL_KNOB."""

    def test_r01_all_new_knobs_in_hot_reload(self):
        """R01 — all 29 new 1.8.9 knobs registered in _HOT_RELOAD_KNOBS."""
        missing = [k for k in _NEW_KNOBS_189 if k not in proxy._HOT_RELOAD_KNOBS]
        assert not missing, (
            f"These 1.8.9 knobs are missing from _HOT_RELOAD_KNOBS: {missing}"
        )

    def test_r02_all_new_knobs_default_true(self):
        """R02 — all 29 new knobs default to True in config (on by default)."""
        wrong = {k: getattr(config, k) for k in _NEW_KNOBS_189
                 if hasattr(config, k) and getattr(config, k) is not True}
        assert not wrong, (
            f"These 1.8.9 knobs do not default to True: {wrong}. "
            "Kill-switch knobs must be on by default."
        )

    def test_r03_no_signal_maps_to_none(self):
        """R03 — every *detection signal* in SIGNAL_KNOB is toggleable (non-None).

        Exception (1.8.10+): the admin-namespace request classifications
        — admin-probe / operator-self / internal-probe — are not detection
        signals and have no kill-switch by design (you cannot 'disable' the
        operator-self classification), so they legitimately map to None.
        """
        _ADMIN_NS_REASONS = {"admin-probe", "operator-self", "internal-probe"}
        none_signals = [sig for sig, knob in proxy.SIGNAL_KNOB.items()
                        if knob is None and sig not in _ADMIN_NS_REASONS]
        assert not none_signals, (
            f"These detection signals still map to None in SIGNAL_KNOB (always-on, "
            f"no kill-switch): {none_signals}. Every detection signal must have a "
            f"toggleable knob in 1.8.9+."
        )

    def test_r04_every_risk_weight_signal_has_knob(self):
        """R04 — every signal in RISK_WEIGHTS maps to a non-None knob."""
        missing_knob = []
        for sig in proxy.RISK_WEIGHTS:
            knob = proxy.SIGNAL_KNOB.get(sig)
            if knob is None:
                missing_knob.append(sig)
        assert not missing_knob, (
            f"Signals in RISK_WEIGHTS with no knob (None in SIGNAL_KNOB): {missing_knob}"
        )

    def test_r05_all_new_knob_names_in_config_namespace(self):
        """R05 — all 29 new knob names exist as attributes in the config module."""
        missing = [k for k in _NEW_KNOBS_189 if not hasattr(config, k)]
        assert not missing, f"Not in config module: {missing}"


# =============================================================================
# G — Gate logic
# =============================================================================

class TestGateLogic:
    """G01–G09: verify that setting knob=False disables the corresponding check."""

    def test_g01_waf_body_disabled_skips_body_critical_check(self):
        """G01 — WAF_BODY_ENABLED=False: body-critical-injection check must
        be gated. Operator-reported bug (iter-28): the original assertion
        had a tautology (`"WAF_BODY_ENABLED" in window` always true because
        the window is centered on WAF_BODY_ENABLED). Replaced with a real
        structural check: look back from the `"body-critical-injection"`
        ban line and require a `if WAF_BODY_ENABLED` gate within 15 lines
        — i.e. inside the SAME if-block, not just somewhere in the file."""
        # Look at the actual handler the proxy() route uses — the source
        # that runs in production. core/proxy_handler.py is where the
        # body-WAF gate lives in 1.9.x.
        import pathlib
        src = pathlib.Path("core/proxy_handler.py").read_text()
        lines = src.splitlines()
        # Only the detection/ban-site occurrence must be gated; skip the
        # SIGNAL_KNOB / _REASON_METHOD / description / latency data-dict entries
        # (where the literal is a dict KEY `"sig":`), which 1.9.7 added so the
        # signal has a kill-switch knob (required by r03/r04).
        crit_lines = [i for i, ln in enumerate(lines)
                      if '"body-critical-injection"' in ln
                      and '"body-critical-injection":' not in ln]
        assert crit_lines, "body-critical-injection literal not found"
        # For each occurrence, the previous 15 lines must contain
        # `if WAF_BODY_ENABLED` (the gate that wraps the block).
        for i in crit_lines:
            preceding = "\n".join(lines[max(0, i - 15):i])
            assert "if WAF_BODY_ENABLED" in preceding, (
                f"body-critical-injection at line {i+1} is not gated by "
                f"`if WAF_BODY_ENABLED` in the preceding 15 lines. The "
                f"comment may say 'ungated' — that was the pre-iter-28 "
                f"design, but operator-reported confusion forced the gate. "
                f"Surrounding lines:\n{preceding}"
            )

    def test_g02_waf_body_gate_covers_xxe(self):
        """G02 — WAF_BODY_ENABLED gate must cover the body-xxe check.
        Same structural fix as G01: look back from the ban-reason literal
        and require a `if WAF_BODY_ENABLED` within 15 lines (= same block).
        Pre-iter-28 the comment claimed "ungated, XML-gated" — XML-only,
        not killable. Now both gates apply."""
        import pathlib
        src = pathlib.Path("core/proxy_handler.py").read_text()
        lines = src.splitlines()
        # Skip data-dict entries (literal as a dict key `"body-xxe":`); only the
        # detection/ban-site occurrence must be WAF_BODY_ENABLED-gated.
        xxe_lines = [i for i, ln in enumerate(lines)
                     if '"body-xxe"' in ln and '"body-xxe":' not in ln]
        assert xxe_lines, "body-xxe literal not found"
        for i in xxe_lines:
            preceding = "\n".join(lines[max(0, i - 15):i])
            assert "if WAF_BODY_ENABLED" in preceding, (
                f"body-xxe at line {i+1} is not gated by "
                f"`if WAF_BODY_ENABLED` in the preceding 15 lines. "
                f"Surrounding lines:\n{preceding}"
            )

    def test_g03_waf_smuggling_gate_present(self):
        """G03 — WAF_SMUGGLING_ENABLED gate wraps smuggling checks."""
        import inspect
        src = inspect.getsource(proxy.proxy)
        idx = src.find("WAF_SMUGGLING_ENABLED")
        assert idx != -1, "WAF_SMUGGLING_ENABLED not found in protect() source"
        window = src[idx: idx + 600]
        assert "smuggling" in window.lower() or "check_smuggling" in window, (
            "WAF_SMUGGLING_ENABLED gate must be adjacent to smuggling check"
        )

    def test_g04_waf_verb_override_gate_present(self):
        """G04 — WAF_VERB_OVERRIDE_ENABLED gate wraps method-override check."""
        import inspect
        src = inspect.getsource(proxy.proxy)
        idx = src.find("WAF_VERB_OVERRIDE_ENABLED")
        assert idx != -1, "WAF_VERB_OVERRIDE_ENABLED not found in protect() source"
        window = src[idx: idx + 300]
        assert "override" in window.lower() or "method" in window.lower(), (
            "WAF_VERB_OVERRIDE_ENABLED gate must be adjacent to method-override check"
        )

    def test_g05_waf_header_injection_gate_present(self):
        """G05 — WAF_HEADER_INJECTION_ENABLED gate wraps header injection checks."""
        import inspect
        src = inspect.getsource(proxy.proxy)
        assert "WAF_HEADER_INJECTION_ENABLED" in src, (
            "WAF_HEADER_INJECTION_ENABLED gate must be in protect() source"
        )

    def test_g06_waf_graphql_gate_present(self):
        """G06 — WAF_GRAPHQL_ENABLED gate wraps gql checks."""
        import inspect
        src = inspect.getsource(proxy.proxy)
        idx = src.find("WAF_GRAPHQL_ENABLED")
        assert idx != -1, "WAF_GRAPHQL_ENABLED not found in protect() source"
        window = src[idx: idx + 400]
        assert "gql" in window.lower() or "graphql" in window.lower(), (
            "WAF_GRAPHQL_ENABLED gate must be adjacent to GraphQL check"
        )

    def test_g07_waf_upload_gate_present(self):
        """G07 — WAF_UPLOAD_ENABLED gate wraps upload checks."""
        import inspect
        src = inspect.getsource(proxy.proxy)
        assert "WAF_UPLOAD_ENABLED" in src, (
            "WAF_UPLOAD_ENABLED gate must be in protect() source"
        )

    def test_g08_session_churn_gate_in_identity(self):
        """G08 — SESSION_CHURN_ENABLED gate must be in identity.py churn path."""
        import inspect
        import identity
        src = inspect.getsource(identity)
        assert "SESSION_CHURN_ENABLED" in src, (
            "SESSION_CHURN_ENABLED gate must be in identity.py"
        )

    def test_g09_rate_limit_gate_in_protect(self):
        """G09 — RATE_LIMIT_ENABLED gate must be in protect()."""
        import inspect
        src = inspect.getsource(proxy.protect)
        assert "RATE_LIMIT_ENABLED" in src, (
            "RATE_LIMIT_ENABLED gate must be in protect() source"
        )


# =============================================================================
# H — Hot-reload round-trip
# =============================================================================

class TestHotReloadRoundTrip:
    """H01–H06: knobs persist through db_load_config() round-trip."""

    def _write_knob_and_reload(self, knob_name, value):
        """Helper: write a knob to config_kv and call db_load_config().

        Backend-aware: db_load_config() reads config_kv from the *active*
        backend (Postgres when POSTGRES_DSN is set, else SQLite at DB_PATH —
        see db/sqlite.py:db_load_config). A hardcoded ``sqlite3.connect`` write
        is invisible in PG mode, so we route the write through the same
        backend-aware ``db.conn.conn()`` context manager the loader reads from.
        ``?`` placeholders are rewritten to ``%s`` on PG transparently."""
        import json
        from db.conn import conn as _backend_conn
        proxy.db_init()
        v = value if not isinstance(value, bool) else ("true" if value else "false")
        with _backend_conn(timeout=5) as _bc:
            _bc.execute("DELETE FROM config_kv WHERE key = ?", (knob_name,))
            _bc.execute("INSERT INTO config_kv (key, value) VALUES (?, ?)",
                        (knob_name, json.dumps(v)))
        proxy.db_load_config(vars(proxy))
        return getattr(proxy, knob_name)

    def test_h01_waf_body_enabled_persists_false(self):
        """H01 — WAF_BODY_ENABLED=False persists through db_load_config()."""
        result = self._write_knob_and_reload("WAF_BODY_ENABLED", False)
        assert result is False, "WAF_BODY_ENABLED did not persist False"

    def test_h02_waf_smuggling_enabled_persists_false(self):
        """H02 — WAF_SMUGGLING_ENABLED=False persists through db_load_config()."""
        result = self._write_knob_and_reload("WAF_SMUGGLING_ENABLED", False)
        assert result is False, "WAF_SMUGGLING_ENABLED did not persist False"

    def test_h03_rate_limit_enabled_persists_false(self):
        """H03 — RATE_LIMIT_ENABLED=False persists through db_load_config()."""
        result = self._write_knob_and_reload("RATE_LIMIT_ENABLED", False)
        assert result is False, "RATE_LIMIT_ENABLED did not persist False"

    def test_h04_host_blocking_enabled_persists_false(self):
        """H04 — HOST_BLOCKING_ENABLED=False persists through db_load_config()."""
        result = self._write_knob_and_reload("HOST_BLOCKING_ENABLED", False)
        assert result is False, "HOST_BLOCKING_ENABLED did not persist False"

    def test_h05_all_new_knobs_in_hot_reload_registry(self):
        """H05 — all 29 new knobs are in _HOT_RELOAD_KNOBS (guard for test_165)."""
        missing = [k for k in _NEW_KNOBS_189 if k not in proxy._HOT_RELOAD_KNOBS]
        assert not missing, (
            f"Missing from _HOT_RELOAD_KNOBS: {missing}. "
            "Add them so the Controls UI can hot-toggle them and test_165 covers them."
        )

    def test_h06_toggle_false_then_true_restores_default(self):
        """H06 — setting WAF_BODY_ENABLED False then True restores True."""
        self._write_knob_and_reload("WAF_BODY_ENABLED", False)
        result = self._write_knob_and_reload("WAF_BODY_ENABLED", True)
        assert result is True, "WAF_BODY_ENABLED did not restore to True"


# =============================================================================
# S — Signal-knob mapping
# =============================================================================

class TestSignalKnobMapping:
    """S01–S23: verify specific signal→knob mappings."""

    @pytest.mark.parametrize("signal,expected_knob", list(_EXPECTED_SIGNAL_KNOBS.items()))
    def test_signal_maps_to_expected_knob(self, signal, expected_knob):
        """S — every previously-always-on signal maps to its kill-switch knob."""
        actual = proxy.SIGNAL_KNOB.get(signal)
        assert actual == expected_knob, (
            f"SIGNAL_KNOB['{signal}'] = {actual!r}, expected {expected_knob!r}. "
            f"The signal must map to the correct toggle knob."
        )

    def test_s01_slow_client(self):
        """S01 — slow-client → WAF_SLOWLORIS_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("slow-client") == "WAF_SLOWLORIS_ENABLED"

    def test_s02_accept_wildcard_html(self):
        """S02 — accept-wildcard-html → ACCEPT_WILDCARD_CHECK_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("accept-wildcard-html") == "ACCEPT_WILDCARD_CHECK_ENABLED"

    def test_s03_session_churn(self):
        """S03 — session-churn → SESSION_CHURN_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("session-churn") == "SESSION_CHURN_ENABLED"

    def test_s04_rate_limit(self):
        """S04 — rate-limit → RATE_LIMIT_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("rate-limit") == "RATE_LIMIT_ENABLED"

    def test_s05_tls_fingerprint(self):
        """S05 — tls-fingerprint → TLS_FP_BLOCK_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("tls-fingerprint") == "TLS_FP_BLOCK_ENABLED"

    def test_s06_auth_jwt_invalid(self):
        """S06 — auth-jwt-invalid → JWT_VALIDATION_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("auth-jwt-invalid") == "JWT_VALIDATION_ENABLED"

    def test_s07_direct_api_probe(self):
        """S07 — direct-api-probe → JOURNEY_CHECK_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("direct-api-probe") == "JOURNEY_CHECK_ENABLED"

    def test_s08_coordinated_probe(self):
        """S08 — coordinated-probe → COORDINATED_ATTACK_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("coordinated-probe") == "COORDINATED_ATTACK_ENABLED"

    def test_s09_custom_rule_block(self):
        """S09 — custom-rule-block → CUSTOM_RULES_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("custom-rule-block") == "CUSTOM_RULES_ENABLED"

    def test_s10_fp_banned(self):
        """S10 — fp-banned → FP_BAN_CHECK_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("fp-banned") == "FP_BAN_CHECK_ENABLED"

    def test_s11_traffic_threshold(self):
        """S11 — traffic-threshold → TRAFFIC_THRESHOLD_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("traffic-threshold") == "TRAFFIC_THRESHOLD_ENABLED"

    def test_s12_upstream_auth_fail(self):
        """S12 — upstream-auth-fail → UPSTREAM_AUTH_FAIL_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("upstream-auth-fail") == "UPSTREAM_AUTH_FAIL_ENABLED"

    def test_s13_rate_limit_ip(self):
        """S13 — rate-limit-ip → RATE_LIMIT_IP_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("rate-limit-ip") == "RATE_LIMIT_IP_ENABLED"

    def test_s14_rate_limit_endpoint(self):
        """S14 — rate-limit-endpoint → ENDPOINT_RATE_LIMIT_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("rate-limit-endpoint") == "ENDPOINT_RATE_LIMIT_ENABLED"

    def test_s15_host_not_allowed(self):
        """S15 — host-not-allowed → HOST_BLOCKING_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("host-not-allowed") == "HOST_BLOCKING_ENABLED"

    def test_s16_missing_required_header(self):
        """S16 — missing-required-header → REQUIRED_HEADERS_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("missing-required-header") == "REQUIRED_HEADERS_ENABLED"

    def test_s17_ja4_required_missing(self):
        """S17 — ja4-required-missing → JA4_REQUIRED_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("ja4-required-missing") == "JA4_REQUIRED_ENABLED"

    def test_s18_ja4h_deny(self):
        """S18 — ja4h-deny → JA4H_DENY_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("ja4h-deny") == "JA4H_DENY_ENABLED"

    def test_s19_honey_cred(self):
        """S19 — honey-cred → HONEY_CRED_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("honey-cred") == "HONEY_CRED_ENABLED"

    def test_s21_canary_probe_miss(self):
        """S21 — canary-probe-miss → CANARY_PROBE_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("canary-probe-miss") == "CANARY_PROBE_ENABLED"

    def test_s22_llm_no_subresources(self):
        """S22 — llm-no-subresources → LLM_HEURISTIC_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("llm-no-subresources") == "LLM_HEURISTIC_ENABLED"

    def test_s23_webdriver_detected(self):
        """S23 — webdriver-detected → AUTOMATION_PROBE_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("webdriver-detected") == "AUTOMATION_PROBE_ENABLED"

    def test_s24_bot_motion(self):
        """S24 — bot-motion → INTERACTION_PROBE_ENABLED."""
        assert proxy.SIGNAL_KNOB.get("bot-motion") == "INTERACTION_PROBE_ENABLED"


# =============================================================================
# D — Dashboard (controls.html) verification
# =============================================================================

class TestDashboardKnobs:
    """D01–D04: controls.html exposes all new knobs in the META table."""

    @pytest.fixture(scope="class")
    def controls_src(self):
        path = Path(__file__).parent.parent / "dashboards" / "controls.html"
        return path.read_text()

    def test_d01_all_new_knobs_in_controls_html(self, controls_src):
        """D01 — all 29 new knob names appear in controls.html."""
        missing = [k for k in _NEW_KNOBS_189 if k not in controls_src]
        assert not missing, (
            f"These 1.8.9 knobs are missing from controls.html: {missing}"
        )

    def test_d02_no_always_on_section_label(self, controls_src):
        """D02 — no 'no kill-switch' label appears in controls.html (section is empty)."""
        assert "no kill-switch" not in controls_src, (
            "controls.html still contains 'no kill-switch' label — "
            "the always-on section should be empty in 1.8.9"
        )

    def test_d03_waf_body_is_bool_kind(self, controls_src):
        """D03 — WAF_BODY_ENABLED has kind:'bool' in controls META."""
        idx = controls_src.find("WAF_BODY_ENABLED")
        assert idx != -1, "WAF_BODY_ENABLED not in controls.html"
        window = controls_src[idx: idx + 200]
        assert "bool" in window, (
            "WAF_BODY_ENABLED must have kind:'bool' in controls META"
        )

    def test_d04_rate_limit_enabled_is_bool_kind(self, controls_src):
        """D04 — RATE_LIMIT_ENABLED has kind:'bool' in controls META."""
        idx = controls_src.find("RATE_LIMIT_ENABLED")
        assert idx != -1, "RATE_LIMIT_ENABLED not in controls.html"
        window = controls_src[idx: idx + 200]
        assert "bool" in window, (
            "RATE_LIMIT_ENABLED must have kind:'bool' in controls META"
        )
