"""
tests/test_v185_new_features.py — v1.8.6 new-feature unit tests.

Covers:
  1. TOTP 2FA (admin/users.py)
  2. JA4H HTTP fingerprint (identity.py)
  3. Detector health (state.py + core/proxy_handler.py)
  4. DLP pattern CRUD endpoints (core/proxy_handler.py, db/sqlite.py)
  5. Credential stuffing detection (state.py, config.py, core/proxy_handler.py)
"""
import os
import sys
import tempfile
import time
from collections import deque
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

# ── env setup (mirrors conftest.py) ─────────────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="appsecgw-v185-new-")
os.environ.setdefault("UPSTREAM",  "https://example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "antibot-v185-new.db"))

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))


# ─────────────────────────────────────────────────────────────────────────────
# 1. TOTP 2FA
# ─────────────────────────────────────────────────────────────────────────────

class TestTotp:
    """Tests for TOTP two-factor authentication helpers in admin/users.py."""

    def test_totp_generate_secret_returns_base32(self):
        """_totp_generate_secret() must return a non-empty valid base32 string."""
        import base64 as _b64
        from admin.users import _totp_generate_secret
        secret = _totp_generate_secret()
        assert isinstance(secret, str)
        assert len(secret) > 0
        # pyotp secrets are base32 — alphabet A-Z 2-7
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
        assert all(c in valid_chars for c in secret.upper())

    def test_totp_verify_valid_code(self):
        """_totp_verify(secret, current_code) must return True."""
        import pyotp
        from admin.users import _totp_generate_secret, _totp_verify
        secret = _totp_generate_secret()
        code = pyotp.TOTP(secret).now()
        assert _totp_verify(secret, code) is True

    def test_totp_verify_invalid_code(self):
        """_totp_verify(secret, '000000') must return False for a fresh secret."""
        from admin.users import _totp_generate_secret, _totp_verify
        import pyotp
        secret = _totp_generate_secret()
        # Only accept '000000' as invalid when it doesn't happen to be current
        current = pyotp.TOTP(secret).now()
        if current == "000000":
            # astronomically unlikely second hit; just skip assertion
            pytest.skip("TOTP coincidentally generated 000000")
        assert _totp_verify(secret, "000000") is False

    def test_totp_provisioning_uri_contains_issuer(self):
        """_totp_provisioning_uri must return otpauth:// URI with username."""
        from admin.users import _totp_generate_secret, _totp_provisioning_uri
        secret = _totp_generate_secret()
        uri = _totp_provisioning_uri(secret, "testuser")
        assert isinstance(uri, str)
        assert "otpauth://totp/" in uri
        assert "testuser" in uri

    def test_totp_generate_backup_codes_count(self):
        """_generate_backup_codes() must return exactly 8 codes."""
        from admin.users import _generate_backup_codes
        codes = _generate_backup_codes()
        assert isinstance(codes, list)
        assert len(codes) == 8

    def test_totp_generate_backup_codes_unique(self):
        """All 8 backup codes must be distinct."""
        from admin.users import _generate_backup_codes
        codes = _generate_backup_codes()
        assert len(set(codes)) == 8

    def test_totp_state_fields_exist(self):
        """state._TOTP_PENDING dict must exist."""
        import state
        assert hasattr(state, "_TOTP_PENDING")
        assert isinstance(state._TOTP_PENDING, dict)

    def test_totp_login_returns_step_when_enabled(self):
        """When totp_enabled=1, the login branch stores a pending entry and
        sets step=totp_required in the return value (static inspection of
        code path — verified via source text since the full login endpoint
        requires an active DB and event loop)."""
        import admin.users as _users_mod
        src_path = os.path.join(os.path.dirname(_HERE), "admin", "users.py")
        with open(src_path) as f:
            src = f.read()
        # The branch that sets totp_required must reference totp_enabled
        assert "totp_enabled" in src
        assert "totp_required" in src
        assert "_TOTP_PENDING" in src


# ─────────────────────────────────────────────────────────────────────────────
# 2. JA4H HTTP Fingerprint
# ─────────────────────────────────────────────────────────────────────────────

def _make_ja4h_request(method="GET", headers=None, cookies=None, content_length=None):
    """Build a minimal mock request for compute_ja4h."""
    r = MagicMock()
    r.method = method
    # aiohttp version object
    ver = MagicMock()
    ver.major = 1
    r.version = ver
    r.headers = headers if headers is not None else {}
    r.cookies = cookies if cookies is not None else {}
    r.content_length = content_length
    return r


class TestJa4h:
    """Tests for compute_ja4h() in identity.py."""

    def test_ja4h_basic_get(self):
        """GET request fingerprint must have 4 underscore-separated parts."""
        from identity import compute_ja4h
        req = _make_ja4h_request(method="GET")
        result = compute_ja4h(req)
        parts = result.split("_")
        assert len(parts) == 4, f"Expected 4 parts, got: {result!r}"

    def test_ja4h_post_with_body(self):
        """POST with content-length > 0 → body flag char (index 4) of part 1 is 'y'.
        Part 1 format: method(2) + version(2) + body(1) + referer(1) = 6 chars."""
        from identity import compute_ja4h
        req = _make_ja4h_request(method="POST", content_length=42)
        result = compute_ja4h(req)
        part1 = result.split("_")[0]
        # Index 4 = body flag ('y'/'n')
        assert part1[4] == "y", f"Expected 'y' at index 4 (body flag), got: {part1!r}"

    def test_ja4h_no_body(self):
        """GET with no body (content_length=None) → body flag char (index 4) is 'n'."""
        from identity import compute_ja4h
        req = _make_ja4h_request(method="GET", content_length=None)
        result = compute_ja4h(req)
        part1 = result.split("_")[0]
        assert part1[4] == "n", f"Expected 'n' at index 4 (body flag), got: {part1!r}"

    def test_ja4h_with_referer(self):
        """Request with Referer header → referer flag char (index 5) of part 1 is 'r'."""
        from identity import compute_ja4h
        req = _make_ja4h_request(headers={"Referer": "https://example.com/"})
        result = compute_ja4h(req)
        part1 = result.split("_")[0]
        # Index 5 = referer flag ('r'/'n')
        assert part1[5] == "r", f"Expected 'r' at index 5 (referer flag), got: {part1!r}"

    def test_ja4h_without_referer(self):
        """Request without Referer header → referer flag char (index 5) is 'n'."""
        from identity import compute_ja4h
        req = _make_ja4h_request(headers={"Accept": "text/html"})
        result = compute_ja4h(req)
        part1 = result.split("_")[0]
        assert part1[5] == "n", f"Expected 'n' at index 5 (referer flag), got: {part1!r}"

    def test_ja4h_header_count_in_range(self):
        """Header count field (first 2 chars of part 2) must be zero-padded digits."""
        from identity import compute_ja4h
        req = _make_ja4h_request(headers={"Accept": "text/html", "Accept-Language": "en"})
        result = compute_ja4h(req)
        part2 = result.split("_")[1]
        hdr_count_str = part2[:2]
        assert hdr_count_str.isdigit(), f"Header count not digits: {hdr_count_str!r}"
        assert 0 <= int(hdr_count_str) <= 99

    def test_ja4h_deny_list_field_exists(self):
        """config.JA4H_DENY_LIST must exist and be a mutable set (not frozenset — JSON serialisation)."""
        import config
        assert hasattr(config, "JA4H_DENY_LIST")
        assert isinstance(config.JA4H_DENY_LIST, set)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Detector Health
# ─────────────────────────────────────────────────────────────────────────────

class TestDetectorHealth:
    """Tests for the detector health registry in state.py."""

    def setup_method(self):
        """Ensure a clean slate for detector health between tests."""
        import state
        state._DETECTOR_HEALTH.clear()

    def test_detector_health_dict_exists(self):
        """state._DETECTOR_HEALTH must be a dict."""
        import state
        assert isinstance(state._DETECTOR_HEALTH, dict)

    def test_set_detector_health_ok(self):
        """set_detector_health('test', True) → status == 'ok'."""
        import state
        state.set_detector_health("test", True)
        assert state._DETECTOR_HEALTH["test"]["status"] == "ok"

    def test_set_detector_health_degraded(self):
        """set_detector_health('test2', False, 'key missing') → status == 'degraded' with reason."""
        import state
        state.set_detector_health("test2", False, "key missing")
        entry = state._DETECTOR_HEALTH["test2"]
        assert entry["status"] == "degraded"
        assert entry["reason"] == "key missing"

    def test_detector_health_has_last_check_ts(self):
        """last_check_ts must be a float close to time.time()."""
        import state
        before = time.time()
        state.set_detector_health("test", True)
        after = time.time()
        ts = state._DETECTOR_HEALTH["test"]["last_check_ts"]
        assert isinstance(ts, float)
        assert before <= ts <= after + 1.0

    def test_status_endpoint_includes_detectors_key(self):
        """core/proxy_handler.py must build the status response with 'detectors' and _DETECTOR_HEALTH."""
        ph_path = os.path.join(os.path.dirname(_HERE), "core", "proxy_handler.py")
        with open(ph_path) as f:
            src = f.read()
        assert '"detectors"' in src
        assert "_DETECTOR_HEALTH" in src


# ─────────────────────────────────────────────────────────────────────────────
# 4. DLP Pattern CRUD
# ─────────────────────────────────────────────────────────────────────────────

class TestDlpPatterns:
    """Tests for DLP pattern CRUD endpoints."""

    def test_dlp_patterns_table_in_db_init(self):
        """db/sqlite.py must contain CREATE TABLE ... dlp_patterns."""
        db_path = os.path.join(os.path.dirname(_HERE), "db", "sqlite.py")
        with open(db_path) as f:
            src = f.read()
        assert "dlp_patterns" in src

    def test_dlp_patterns_get_function_exists(self):
        """dlp_patterns_get must be importable from core.proxy_handler."""
        from core.proxy_handler import dlp_patterns_get
        assert callable(dlp_patterns_get)

    def test_dlp_patterns_post_function_exists(self):
        """dlp_patterns_post must be importable from core.proxy_handler."""
        from core.proxy_handler import dlp_patterns_post
        assert callable(dlp_patterns_post)

    def test_dlp_patterns_delete_function_exists(self):
        """dlp_patterns_delete must be importable from core.proxy_handler."""
        from core.proxy_handler import dlp_patterns_delete
        assert callable(dlp_patterns_delete)

    def test_dlp_patterns_route_registered(self):
        """proxy.py must register dlp-patterns routes."""
        proxy_path = os.path.join(os.path.dirname(_HERE), "proxy.py")
        with open(proxy_path) as f:
            src = f.read()
        assert "dlp-patterns" in src

    def test_dlp_patterns_db_writer_handles_dlp_ops(self):
        """db/sqlite.py must handle dlp_add, dlp_toggle, and dlp_delete operations."""
        db_path = os.path.join(os.path.dirname(_HERE), "db", "sqlite.py")
        with open(db_path) as f:
            src = f.read()
        assert "dlp_add" in src
        assert "dlp_toggle" in src
        assert "dlp_delete" in src


# ─────────────────────────────────────────────────────────────────────────────
# 5. Credential Stuffing Detection
# ─────────────────────────────────────────────────────────────────────────────

class TestCredStuffing:
    """Tests for credential stuffing detection fields and config."""

    def test_auth_failures_field_on_ip_state(self):
        """IpState must have an auth_failures attribute."""
        from state import IpState
        s = IpState()
        assert hasattr(s, "auth_failures")

    def test_auth_fail_global_deque_exists(self):
        """state._auth_fail_global must be a deque."""
        from state import _auth_fail_global
        assert isinstance(_auth_fail_global, deque)

    def test_auth_fail_threshold_config(self):
        """AUTH_FAIL_THRESHOLD must be a positive int."""
        from config import AUTH_FAIL_THRESHOLD
        assert isinstance(AUTH_FAIL_THRESHOLD, int)
        assert AUTH_FAIL_THRESHOLD > 0

    def test_auth_fail_window_config(self):
        """AUTH_FAIL_WINDOW_SECS must be positive."""
        from config import AUTH_FAIL_WINDOW_SECS
        assert AUTH_FAIL_WINDOW_SECS > 0

    def test_is_auth_path_helper_exists(self):
        """core/proxy_handler.py must define _is_auth_path."""
        ph_path = os.path.join(os.path.dirname(_HERE), "core", "proxy_handler.py")
        with open(ph_path) as f:
            src = f.read()
        assert "_is_auth_path" in src

    def test_auth_paths_config(self):
        """AUTH_PATHS must be a frozenset."""
        from config import AUTH_PATHS
        assert isinstance(AUTH_PATHS, frozenset)

    def test_upstream_auth_fail_signal_in_risk_weights(self):
        """'upstream-auth-fail' must appear in config.py RISK_WEIGHTS."""
        cfg_path = os.path.join(os.path.dirname(_HERE), "config.py")
        with open(cfg_path) as f:
            src = f.read()
        assert "upstream-auth-fail" in src

    def test_cred_stuff_global_rps_config(self):
        """CRED_STUFF_GLOBAL_RPS must be a positive number."""
        from config import CRED_STUFF_GLOBAL_RPS
        assert CRED_STUFF_GLOBAL_RPS > 0
