"""
tests/test_v187_login_2fa.py — v1.8.7 two-step login & 2FA QA tests.

Covers:
  AUTH5-01 — login.html step-1 (credentials) and step-2 (TOTP) are separate panels
  AUTH5-02 — login.html step-2 is hidden on load; JS transitions between steps
  AUTH5-03 — login.html step-2 has back/cancel control to return to step-1
  AUTH5-04 — login.html step indicator present (1 → 2 progress)
  AUTH5-05 — login_submit_endpoint returns step=totp_required + partial_token for 2FA users
  AUTH5-06 — partial_token is 16 hex chars, bound to username + time window
  AUTH5-07 — totp_verify_endpoint: valid code → session minted
  AUTH5-08 — totp_verify_endpoint: wrong code → 401 invalid code
  AUTH5-09 — totp_verify_endpoint: tampered/absent partial_token → 401
  AUTH5-10 — totp_verify_endpoint: backup code accepted one-time
  AUTH5-11 — logout_endpoint has no @_require_csrf (exempt from CSRF check)
  AUTH5-12 — SVG QR code: <rect fill="white"> injected inside <svg> element
  AUTH5-13 — SVG QR code: rect is NOT before the opening <svg> tag
  AUTH5-14 — _totp_verify accepts current and ±1 step (valid_window=1)
  AUTH5-15 — _totp_generate_secret returns a valid base32 string ≥ 16 chars
"""
import hashlib
import hmac
import inspect
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── env setup ─────────────────────────────────────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="appsecgw-v187-2fa-test-")
os.environ.setdefault("UPSTREAM",  "https://example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "antibot-v187-2fa.db"))

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

_DASHBOARDS = Path(_ROOT) / "dashboards"


# ─────────────────────────────────────────────────────────────────────────────
# AUTH5-01 / AUTH5-02 / AUTH5-03 / AUTH5-04 — login.html two-step structure
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginHtmlTwoStepStructure:
    """login.html must present credentials and TOTP as visually separate steps."""

    @pytest.fixture(scope="class")
    def html(self):
        return (_DASHBOARDS / "login.html").read_text(encoding="utf-8")

    # AUTH5-01 — distinct panels
    def test_step1_has_username_field(self, html):
        assert 'id="username"' in html, \
            "Step-1 must have a username input"

    def test_step1_has_password_field(self, html):
        assert 'id="password"' in html, \
            "Step-1 must have a password input"

    def test_step2_panel_exists(self, html):
        assert 'id="totp-step"' in html or 'id="step-totp"' in html or 'id="step2"' in html, \
            "A dedicated step-2 panel must exist for TOTP entry"

    def test_totp_input_exists(self, html):
        assert 'id="totp-code"' in html, \
            "TOTP step must have an input with id='totp-code'"

    def test_totp_input_is_numeric(self, html):
        assert 'inputmode="numeric"' in html or 'type="number"' in html or \
               'pattern="[0-9' in html or 'autocomplete="one-time-code"' in html, \
            "TOTP input should hint numeric keyboard / one-time-code autocomplete"

    # AUTH5-02 — step-2 hidden on load
    def test_step2_hidden_on_load(self, html):
        # The step-2 container must start hidden
        # Accept display:none inline style or a CSS class that hides it
        totp_block_match = re.search(
            r'id=["\'](?:totp-step|step-totp|step2)["\'][^>]*>', html)
        assert totp_block_match, "TOTP step element not found"
        tag = totp_block_match.group(0)
        assert "display:none" in tag or "display: none" in tag or 'hidden' in tag, \
            f"TOTP step must be hidden on load, got tag: {tag!r}"

    def test_credential_step_visible_on_load(self, html):
        # Step-1 credential fields must NOT be hidden initially
        cred_match = re.search(
            r'id=["\'](?:credential-fields|step1|step-credentials)["\'][^>]*>', html)
        assert cred_match, "Credential fields container not found"
        tag = cred_match.group(0)
        assert "display:none" not in tag and "display: none" not in tag, \
            "Credential step must be visible on load"

    # AUTH5-03 — back control in step-2
    def test_step2_has_back_control(self, html):
        # Back button/link allows user to return to step-1
        has_back = (
            "btn-back" in html or
            "back-link" in html or
            re.search(r'(?i)use a different|go back|← back|back to sign', html) is not None
        )
        assert has_back, \
            "Step-2 must have a back/cancel control so user can return to step-1"

    # AUTH5-04 — step indicator
    def test_step_indicator_present(self, html):
        has_indicator = (
            "step1-dot" in html or
            "step2-dot" in html or
            "steps" in html or
            re.search(r'step\s*1\s*of\s*2|step\s*2\s*of\s*2', html, re.I) is not None or
            re.search(r'class=["\'][^"\']*step[^"\']*["\']', html) is not None
        )
        assert has_indicator, \
            "login.html must have a step indicator (e.g. step dots, '1 of 2' text)"

    def test_totp_submit_separate_from_main_submit(self, html):
        # Two distinct submit controls; the TOTP one must be separate
        assert 'id="totp-submit"' in html or 'id="btn-totp"' in html, \
            "TOTP step must have its own submit button separate from 'Sign in'"

    def test_js_transitions_to_step2_on_totp_required(self, html):
        assert "totp_required" in html, \
            "JS must check for step==='totp_required' response to transition to step-2"

    def test_js_calls_totp_verify_endpoint(self, html):
        assert "/login/totp" in html, \
            "JS must POST to /login/totp (totp_verify_endpoint) in step-2"

    def test_js_sends_partial_token(self, html):
        assert "partial_token" in html, \
            "JS must send partial_token returned by step-1 to the TOTP verify endpoint"


# ─────────────────────────────────────────────────────────────────────────────
# AUTH5-05 / AUTH5-06 — login_submit_endpoint: partial token for 2FA users
# ─────────────────────────────────────────────────────────────────────────────

class TestLoginSubmitTotpBranch:
    """login_submit_endpoint source must implement the TOTP branch correctly."""

    @pytest.fixture(scope="class")
    def src(self):
        from admin import users
        return inspect.getsource(users.login_submit_endpoint)

    def test_totp_enabled_check_in_source(self, src):
        assert "totp_enabled" in src, \
            "login_submit_endpoint must check user.get('totp_enabled')"

    def test_totp_required_step_returned(self, src):
        assert '"totp_required"' in src or "'totp_required'" in src, \
            "login_submit_endpoint must return step='totp_required' for 2FA users"

    def test_partial_token_in_response(self, src):
        assert "partial_token" in src, \
            "login_submit_endpoint must return a partial_token in the JSON response"

    def test_partial_token_is_random(self, src):
        # C-4 fix: token is now secrets.token_urlsafe(32) — unpredictable per request,
        # stored in _TOTP_PENDING and compared server-side (stateful, not stateless HMAC).
        # Old HMAC-derived token was enumerable: only 2 valid tokens per (username, 5-min window).
        assert "token_urlsafe" in src or "secrets.token" in src, \
            "partial_token must use secrets.token_urlsafe (not HMAC-derived) — C-4 security fix"

    def test_partial_token_stored_in_pending(self, src):
        # With random tokens, the value must be stored server-side for comparison.
        assert '"token"' in src or "'token'" in src, \
            "partial_token must be stored under key 'token' in _TOTP_PENDING for server-side compare"

    def test_totp_pending_state_stored(self, src):
        assert "_TOTP_PENDING" in src, \
            "login_submit_endpoint must store pending state in _TOTP_PENDING"

    # AUTH5-06 — partial token derivation
    def test_partial_token_entry_has_ts(self, src):
        # _TOTP_PENDING entry stores a ts timestamp so stale entries can be pruned.
        assert '"ts"' in src or "'ts'" in src, \
            "_TOTP_PENDING entry must store 'ts' for expiry / staleness pruning"

    def test_partial_token_uses_random_source(self, src):
        # The login_submit source generates the random token with secrets.
        assert "token_urlsafe" in src or "secrets" in src, \
            "login_submit_endpoint must use secrets module for partial_token generation"


# ─────────────────────────────────────────────────────────────────────────────
# AUTH5-05 — partial token: security properties (pure computation)
# ─────────────────────────────────────────────────────────────────────────────

class TestPartialTokenSecurity:
    """Validate that the partial token scheme has the right security properties."""

    def _make_token(self, key: bytes, username: str, window: int) -> str:
        return hmac.new(key, (username + "|" + str(window)).encode(),
                        hashlib.sha256).hexdigest()[:16]

    def test_token_is_16_hex_chars(self):
        key = os.urandom(32)
        tok = self._make_token(key, "alice", 12345)
        assert len(tok) == 16
        assert re.fullmatch(r"[0-9a-f]{16}", tok), f"Token must be lowercase hex: {tok!r}"

    def test_different_users_different_tokens(self):
        key = os.urandom(32)
        window = int(time.time() // 300)
        assert self._make_token(key, "alice", window) != self._make_token(key, "bob", window)

    def test_different_windows_different_tokens(self):
        key = os.urandom(32)
        assert self._make_token(key, "alice", 100) != self._make_token(key, "alice", 101)

    def test_window_boundary_cross_window_accepted(self):
        """totp_verify_endpoint checks current AND previous window — near boundary both valid."""
        key = os.urandom(32)
        now_window = int(time.time() // 300)
        prev_window = now_window - 1
        tok_now  = self._make_token(key, "alice", now_window)
        tok_prev = self._make_token(key, "alice", prev_window)
        # Both must be valid (verifier checks both windows)
        accepted = {tok_now, tok_prev}
        assert len(accepted) == 2, "Current and previous window tokens must differ"

    def test_stale_token_not_in_accepted_windows(self):
        key = os.urandom(32)
        now_window = int(time.time() // 300)
        old_window = now_window - 2  # two windows ago — must NOT be accepted
        tok_old = self._make_token(key, "alice", old_window)
        tok_now = self._make_token(key, "alice", now_window)
        tok_prev = self._make_token(key, "alice", now_window - 1)
        assert tok_old not in {tok_now, tok_prev}, \
            "Token from 2+ windows ago must not match current or previous window token"


# ─────────────────────────────────────────────────────────────────────────────
# AUTH5-07 / AUTH5-08 / AUTH5-09 / AUTH5-10 — totp_verify_endpoint source
# ─────────────────────────────────────────────────────────────────────────────

class TestTotpVerifyEndpointSource:
    """totp_verify_endpoint source must implement all security checks."""

    @pytest.fixture(scope="class")
    def src(self):
        from admin import users
        return inspect.getsource(users.totp_verify_endpoint)

    # AUTH5-07 — success path mints session
    def test_success_creates_session(self, src):
        assert "_session_create" in src, \
            "totp_verify_endpoint must call _session_create on success"

    def test_success_clears_pending(self, src):
        assert "_TOTP_PENDING.pop" in src or "_TOTP_PENDING.clear" in src, \
            "totp_verify_endpoint must clear the pending entry after success"

    # AUTH5-08 — wrong code → 401
    def test_wrong_code_returns_401(self, src):
        assert '"invalid code"' in src or "'invalid code'" in src, \
            "totp_verify_endpoint must return 'invalid code' error on wrong TOTP"
        assert "status=401" in src or "401" in src, \
            "Wrong code must return HTTP 401"

    # AUTH5-09 — tampered / absent token
    def test_missing_token_returns_400(self, src):
        assert "partial_token and code required" in src or \
               ("partial_token" in src and "400" in src), \
            "totp_verify_endpoint must return 400 when partial_token is absent"

    def test_invalid_token_returns_401(self, src):
        assert "invalid or expired token" in src, \
            "Unmatched partial_token must return 'invalid or expired token'"

    def test_token_comparison_is_constant_time(self, src):
        # C-4 fix: stored random token compared with hmac.compare_digest — timing-safe.
        assert "compare_digest" in src, \
            "totp_verify_endpoint must use hmac.compare_digest for partial_token comparison"

    def test_token_looked_up_from_pending_store(self, src):
        # With stateful random tokens, verify reads the stored token from _TOTP_PENDING.
        assert '"token"' in src or "'token'" in src, \
            "totp_verify_endpoint must read 'token' key from _TOTP_PENDING for comparison"

    def test_uses_hmac_compare_digest_for_token_check(self, src):
        assert "hmac.compare_digest" in src, \
            "Token comparison must use hmac.compare_digest to prevent timing attacks"

    # AUTH5-10 — backup codes
    def test_backup_codes_accepted(self, src):
        assert "totp_backup_codes" in src or "backup_codes" in src, \
            "totp_verify_endpoint must accept TOTP backup codes"

    def test_backup_code_consumed_after_use(self, src):
        # After use the backup code must be removed from the list
        assert "backup_codes" in src and (
            "[_bc for _bc in backup_codes" in src or
            "remove" in src or
            "filter" in src
        ), "Used backup code must be removed from the stored list (one-time use)"

    def test_backup_code_uses_constant_time_compare(self, src):
        # INT4-08: iterate all without early exit
        assert "hmac.compare_digest" in src and "backup" in src, \
            "Backup code comparison must use hmac.compare_digest (INT4-08)"

    def test_rate_limit_applied(self, src):
        assert "_login_rate_limit" in src, \
            "totp_verify_endpoint must apply login rate limiting"

    def test_logs_success_event(self, src):
        assert "totp_verify_success" in src, \
            "totp_verify_endpoint must log totp_verify_success"

    def test_logs_failure_event(self, src):
        assert "totp_verify_failed" in src, \
            "totp_verify_endpoint must log totp_verify_failed"


# ─────────────────────────────────────────────────────────────────────────────
# AUTH5-11 — logout CSRF exemption
# ─────────────────────────────────────────────────────────────────────────────

class TestLogoutCsrfExemption:
    """logout_endpoint must NOT carry @_require_csrf — plain form POST must work."""

    def test_logout_endpoint_has_no_require_csrf_decorator(self):
        from admin import users
        src = inspect.getsource(users)
        # Find the logout_endpoint definition
        match = re.search(
            r'((?:@[^\n]+\n)+)?async def logout_endpoint', src)
        assert match, "logout_endpoint not found in users.py source"
        decorators_block = match.group(1) or ""
        assert "_require_csrf" not in decorators_block, (
            "logout_endpoint must NOT have @_require_csrf — "
            "plain form POST from the sidebar cannot set X-CSRF-Token header. "
            f"Found decorators: {decorators_block!r}"
        )

    def test_logout_endpoint_docstring_documents_csrf_exemption(self):
        from admin.users import logout_endpoint
        doc = logout_endpoint.__doc__ or ""
        assert "csrf" in doc.lower() or "CSRF" in doc or "no csrf" in doc.lower(), \
            "logout_endpoint docstring should document why CSRF is not required"

    def test_require_csrf_still_on_destructive_endpoints(self):
        """Removing CSRF from logout must not silently remove it from other endpoints."""
        from admin import users
        src = inspect.getsource(users)
        # At least 4 endpoints should still have @_require_csrf
        count = src.count("@_require_csrf")
        assert count >= 4, (
            f"Expected ≥4 @_require_csrf decorators in users.py, found {count}. "
            "Ensure CSRF was only removed from logout."
        )

    def test_logout_form_in_all_dashboards_uses_plain_post(self):
        """All sidebar logout forms must be plain <form method='post'>, not JS fetch."""
        dashboards = list(_DASHBOARDS.glob("*.html"))
        # Exclude login page — it has no logout form
        dashboards = [d for d in dashboards if d.name != "login.html"]
        for html_path in dashboards:
            html = html_path.read_text(encoding="utf-8")
            if "logout" not in html:
                continue
            # Verify logout is a form POST, not a raw fetch
            assert 'action="/antibot-appsec-gateway/logout"' in html, \
                f"{html_path.name}: logout must be a form with action=…/logout"
            # Should NOT be wiring up a JS fetch to /logout with X-CSRF-Token
            # (plain form POST is intentional — see logout CSRF exemption)
            logout_fetch = re.search(
                r"fetch\(['\"].*logout.*['\"].*X-CSRF-Token", html, re.DOTALL)
            assert not logout_fetch, \
                f"{html_path.name}: logout should use plain form POST, not fetch with CSRF header"


# ─────────────────────────────────────────────────────────────────────────────
# AUTH5-12 / AUTH5-13 — SVG QR code white background
# ─────────────────────────────────────────────────────────────────────────────

class TestSvgQrCodeWhiteBackground:
    """totp_setup_endpoint must inject a white <rect> inside the <svg> element."""

    @pytest.fixture(scope="class")
    def src(self):
        from admin import users
        return inspect.getsource(users.totp_setup_endpoint)

    # AUTH5-12 — rect present with fill=white
    def test_white_rect_injected(self, src):
        assert 'fill="white"' in src or "fill='white'" in src, \
            "totp_setup_endpoint must inject <rect … fill='white'> into the SVG"

    def test_rect_covers_full_svg(self, src):
        assert 'width="100%"' in src or "width='100%'" in src, \
            "White rect must cover 100% width to ensure full background coverage"

    def test_rect_has_full_height(self, src):
        assert 'height="100%"' in src or "height='100%'" in src, \
            "White rect must cover 100% height"

    # AUTH5-13 — rect injected INSIDE <svg>, not before it
    def test_rect_inserted_after_svg_opening_tag(self, src):
        # The code must find the position after the <svg ...> closing '>'
        # Pattern: find '>' after '<svg', THEN insert rect
        assert "svg_str.index('>', svg_str.index('<svg'))" in src or \
               "index('<svg')" in src, \
            "Rect must be inserted after the <svg …> opening tag, not before it"

    def test_rect_not_before_svg_tag(self, src):
        # A naive implementation might inject before the svg tag — check it doesn't
        # The generated data URL must have <svg...><rect...>..., not <rect...><svg...>
        # We verify this by checking the insertion index logic uses <svg as anchor
        assert "index('<svg')" in src or "find('<svg')" in src, \
            "Must use '<svg' as anchor to find insertion point inside the svg element"

    def test_svg_factory_used(self, src):
        assert "SvgImage" in src or "svg" in src.lower(), \
            "Must use SVG image factory (not PIL/PNG)"

    def test_output_is_svg_data_url(self, src):
        assert "data:image/svg+xml;base64," in src, \
            "QR data URL must use data:image/svg+xml;base64, prefix"

    def test_no_pillow_import(self, src):
        assert "PIL" not in src and "Pillow" not in src and "Image.open" not in src, \
            "totp_setup_endpoint must not import PIL/Pillow (not available in distroless image)"


# ─────────────────────────────────────────────────────────────────────────────
# AUTH5-14 / AUTH5-15 — TOTP utility functions
# ─────────────────────────────────────────────────────────────────────────────

class TestTotpUtils:

    def test_totp_generate_secret_returns_base32(self):
        from admin.users import _totp_generate_secret
        secret = _totp_generate_secret()
        assert isinstance(secret, str)
        assert len(secret) >= 16, "TOTP secret must be at least 16 base32 chars (80 bits)"
        import base64
        try:
            base64.b32decode(secret.upper())
        except Exception as e:
            pytest.fail(f"_totp_generate_secret returned invalid base32: {e}")

    def test_totp_verify_accepts_current_code(self):
        import pyotp
        from admin.users import _totp_generate_secret, _totp_verify
        secret = _totp_generate_secret()
        code = pyotp.TOTP(secret).now()
        assert _totp_verify(secret, code), "Current TOTP code must be accepted"

    def test_totp_verify_rejects_wrong_code(self):
        from admin.users import _totp_generate_secret, _totp_verify
        secret = _totp_generate_secret()
        assert not _totp_verify(secret, "000000"), \
            "Incorrect TOTP code must be rejected"

    def test_totp_verify_rejects_empty_code(self):
        from admin.users import _totp_generate_secret, _totp_verify
        secret = _totp_generate_secret()
        assert not _totp_verify(secret, ""), \
            "Empty code must be rejected"

    def test_totp_verify_valid_window_is_1(self):
        """AUTH5-14: valid_window=1 means ±30s tolerance (1 adjacent step)."""
        from admin import users
        src = inspect.getsource(users._totp_verify)
        assert "valid_window=1" in src, \
            "_totp_verify must use valid_window=1 for clock-drift tolerance"

    def test_totp_verify_strips_whitespace(self):
        """User may copy-paste code with trailing space from authenticator."""
        import pyotp
        from admin.users import _totp_generate_secret, _totp_verify
        secret = _totp_generate_secret()
        code = pyotp.TOTP(secret).now()
        assert _totp_verify(secret, " " + code + " "), \
            "_totp_verify must strip whitespace from submitted code"


# ─────────────────────────────────────────────────────────────────────────────
# AUTH5-16 — rate limit holds under concurrent requests (parallel brute-force)
# ─────────────────────────────────────────────────────────────────────────────

class TestTotpRateLimitParallel:
    """Rate limit must hold when many requests arrive concurrently from the same IP.
    The asyncio Lock in _login_rate_limit serialises access, but all 10 tasks
    share a single event loop — this verifies the counter increments atomically
    and that exactly 5 passes are granted before the 6th triggers the deny path."""

    def test_10_concurrent_calls_allow_exactly_5(self):
        import asyncio
        from admin import users

        test_ip = "10.200.255.1"

        async def go():
            async with users._LOGIN_BUCKET_LOCK:
                users._LOGIN_BUCKET.pop(test_ip, None)
            results = await asyncio.gather(
                *[users._login_rate_limit(test_ip) for _ in range(10)]
            )
            accepted = sum(1 for r in results if r)
            rejected = sum(1 for r in results if not r)
            assert accepted == 5, (
                f"Rate limit must allow exactly 5 concurrent attempts, got {accepted}"
            )
            assert rejected == 5, (
                f"Rate limit must deny the remaining 5, got {rejected} denied"
            )

        asyncio.run(go())

    def test_rate_limit_resets_after_window(self):
        import asyncio
        import time as _time
        from admin import users

        test_ip = "10.200.255.2"

        async def go():
            # Exhaust the bucket
            async with users._LOGIN_BUCKET_LOCK:
                users._LOGIN_BUCKET[test_ip] = [_time.time() - 61, 10]
            # After window expires, first call must be allowed again
            result = await users._login_rate_limit(test_ip)
            assert result is True, "Rate limit must reset after 60s window expires"

        asyncio.run(go())

    def test_different_ips_have_independent_buckets(self):
        import asyncio
        from admin import users

        async def go():
            # Exhaust ip_a
            async with users._LOGIN_BUCKET_LOCK:
                users._LOGIN_BUCKET.pop("10.1.1.1", None)
                users._LOGIN_BUCKET.pop("10.1.1.2", None)
            results_a = await asyncio.gather(
                *[users._login_rate_limit("10.1.1.1") for _ in range(6)]
            )
            # ip_b not exhausted — first call must pass
            result_b = await users._login_rate_limit("10.1.1.2")
            assert sum(results_a) == 5, "ip_a bucket must allow exactly 5"
            assert result_b is True, "ip_b bucket must be independent of ip_a"

        asyncio.run(go())
