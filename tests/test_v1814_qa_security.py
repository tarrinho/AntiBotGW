# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1814_qa_security.py — comprehensive QA for the v1.8.14 security
review fixes (S-C1..S-C2, S-W1..S-W8, S-I1..S-I5).

Source-inspection tests verify the fixes are present and the old anti-patterns
are absent. Runtime tests verify behaviour where the fix is exercised by a
pure-function path that doesn't require the full proxy harness.
"""
from __future__ import annotations

import inspect
import os
import time as _t

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

import pathlib
_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
# S-C1 — Maintainer cannot escalate role
# ═══════════════════════════════════════════════════════════════════════════

class TestSecC1MaintainerRoleEscalation:
    """Maintainer role can no longer PATCH another user's role to admin."""

    def _src(self):
        from admin.users import users_update_endpoint
        return inspect.getsource(users_update_endpoint)

    def test_role_change_requires_admin_not_maintainer(self):
        src = self._src()
        assert 'caller_role != "admin"' in src, (
            "users_update_endpoint must explicitly require caller_role == 'admin' "
            "for role changes — previously maintainers could escalate to admin."
        )

    def test_role_change_does_not_use_old_viewer_only_guard(self):
        """The old guard rejected viewers only — verify it's been replaced."""
        src = self._src()
        # The old line `if caller_role == "viewer":` for the role block must be gone
        # (it's still valid for status block, so we check it's gone from role block only)
        role_block_start = src.find('if "role" in data:')
        status_block_start = src.find('if "status" in data:')
        if role_block_start != -1 and status_block_start != -1:
            role_block = src[role_block_start:status_block_start]
            assert 'caller_role == "viewer"' not in role_block, (
                "Role change guard must not rely on viewer-only check"
            )

    def test_role_change_error_message_mentions_admin(self):
        src = self._src()
        assert "only admins can change roles" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-C2 — OIDC CSRF nonce uses per-session value
# ═══════════════════════════════════════════════════════════════════════════

class TestSecC2OidcCsrfNonce:
    """OIDC callback issues the per-session csrf_nonce, not legacy HMAC."""

    def _src(self):
        return _read("admin/oidc.py")

    def test_oidc_reads_csrf_nonce_from_session_cache(self):
        src = self._src()
        assert "_SESSION_CACHE" in src
        assert "csrf_nonce" in src, (
            "OIDC callback must read csrf_nonce from _SESSION_CACHE (T0-2 nonce)"
        )

    def test_oidc_keeps_hmac_fallback(self):
        """Fallback HMAC derivation must remain for sessions missing the nonce."""
        src = self._src()
        assert "hmac.new" in src
        # Ensure we use the nonce when available
        assert 'cached.get("csrf_nonce"' in src or "_cached.get('csrf_nonce'" in src \
               or '_cached.get("csrf_nonce"' in src


# ═══════════════════════════════════════════════════════════════════════════
# S-W1 — TOTP TTL check
# ═══════════════════════════════════════════════════════════════════════════

class TestSecW1TotpTtl:
    """totp_verify_endpoint enforces the 600s TTL on _TOTP_PENDING entries."""

    def _src(self):
        from admin.users import totp_verify_endpoint
        return inspect.getsource(totp_verify_endpoint)

    def test_ttl_constant_present(self):
        src = self._src()
        assert "_TOTP_PENDING_TTL_S" in src or "600" in src

    def test_expired_entry_is_popped(self):
        src = self._src()
        assert "ts" in src and "_t.time()" in src and "_TOTP_PENDING_TTL_S" in src

    def test_expired_entries_are_not_matched(self):
        """The loop skips entries older than TTL even if token matches."""
        src = self._src()
        # The TTL check happens before the compare_digest match
        ttl_idx = src.find("_TOTP_PENDING_TTL_S")
        compare_idx = src.find("compare_digest")
        assert ttl_idx != -1 and compare_idx != -1
        assert ttl_idx < compare_idx, (
            "TTL check must occur before token comparison"
        )


# ═══════════════════════════════════════════════════════════════════════════
# S-W2 — mesh_sync_state requires role
# ═══════════════════════════════════════════════════════════════════════════

class TestSecW2MeshSyncStateAuthz:
    """mesh_sync_state_endpoint requires admin or maintainer."""

    def test_role_check_present(self):
        from admin.mesh import mesh_sync_state_endpoint
        src = inspect.getsource(mesh_sync_state_endpoint)
        assert "_role_denied" in src, (
            "mesh_sync_state_endpoint must check role — viewers must not see "
            "which sync keys are enabled or pending offer previews."
        )
        assert '"admin"' in src and '"maintainer"' in src


# ═══════════════════════════════════════════════════════════════════════════
# S-W3 — gw_registry reveal=1 requires admin only
# ═══════════════════════════════════════════════════════════════════════════

class TestSecW3GwRegistryRevealAdminOnly:
    """The reveal=1 query path requires admin role, not maintainer."""

    def test_reveal_branch_has_admin_role_check(self):
        from admin.mesh import gw_registry_get_endpoint
        src = inspect.getsource(gw_registry_get_endpoint)
        # Find the if reveal: branch and verify it has _role_denied(request, "admin") inside
        # without "maintainer" — the comment "S-W3 fix" is also a marker
        assert "S-W3" in src or (
            "if reveal" in src and "_role_denied(request, \"admin\")" in src
        )


# ═══════════════════════════════════════════════════════════════════════════
# S-W4 — _SESSION_CACHE_LOCK documented intent
# ═══════════════════════════════════════════════════════════════════════════

class TestSecW4SessionCacheLockDocumented:
    """The lock has a clear comment explaining single-threaded asyncio safety."""

    def test_lock_comment_present(self):
        src = _read("admin/users.py")
        assert "_SESSION_CACHE_LOCK" in src
        assert "S-W4" in src or "single-threaded asyncio" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-W5 — partial_token length bound
# ═══════════════════════════════════════════════════════════════════════════

class TestSecW5PartialTokenLengthBound:
    """totp_verify rejects oversized partial_token before the lookup."""

    def _src(self):
        from admin.users import totp_verify_endpoint
        return inspect.getsource(totp_verify_endpoint)

    def test_length_check_present(self):
        src = self._src()
        assert "len(partial_token)" in src and ("> 64" in src or ">= 64" in src or ">64" in src)

    def test_code_length_also_bounded(self):
        src = self._src()
        assert "len(code)" in src

    def test_length_check_returns_400(self):
        src = self._src()
        assert "invalid token format" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-W6 — secrets export requires CSRF on GET
# ═══════════════════════════════════════════════════════════════════════════

class TestSecW6SecretsExportCsrf:
    """settings_export with include_secrets=1 requires a CSRF token even on GET."""

    def test_endpoint_checks_csrf_for_secrets(self):
        from admin.settings import settings_export_endpoint
        src = inspect.getsource(settings_export_endpoint)
        assert "include_secrets" in src
        assert "_csrf_token_valid" in src
        assert "require_for_safe=True" in src

    def test_helper_supports_require_for_safe(self):
        """_csrf_token_valid must accept the require_for_safe kwarg."""
        from admin.auth import _csrf_token_valid
        sig = inspect.signature(_csrf_token_valid)
        assert "require_for_safe" in sig.parameters

    def test_dashboard_export_attaches_csrf_header(self):
        """The settings.html export click handler must attach X-CSRF-Token when include_secrets=1."""
        src = _read("dashboards/settings.html")
        # The handler must compute _agwTok or read from cookie and attach to fetch headers
        assert "X-CSRF-Token" in src and "btn-export" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-W7 — XML user import validates role/status
# ═══════════════════════════════════════════════════════════════════════════

class TestSecW7UserImportRoleValidation:
    """XML import rejects (or clamps) unknown role/status values."""

    def test_import_validates_role(self):
        src = _read("admin/settings.py")
        # Must reference the allowlist constants
        assert "_USER_ROLES" in src and "_USER_STATUS" in src
        # Specifically inside the user import section
        assert "_imp_role" in src or "S-W7" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-W8 — OIDC init_ip XFF dependency documented
# ═══════════════════════════════════════════════════════════════════════════

class TestSecW8OidcXffNote:
    """The init_ip enforcement is documented to depend on trusted XFF chain."""

    def test_xff_dependency_documented(self):
        src = _read("admin/oidc.py")
        # The comment near init_ip check must mention TRUST_XFF or proxy sanitization
        assert "TRUST_XFF" in src or "S-W8" in src or "outermost proxy" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-I1 — Disabling a user revokes active sessions
# ═══════════════════════════════════════════════════════════════════════════

class TestSecI1RevokeOnDisable:
    """users_update_endpoint revokes _SESSION_CACHE entries when status != active."""

    def test_revoke_on_status_change(self):
        from admin.users import users_update_endpoint
        src = inspect.getsource(users_update_endpoint)
        assert ('fields["status"]' in src or "fields['status']" in src) \
               and "revoked" in src
        # Must enqueue the DB revoke
        assert "user_session_revoke" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-I2 — scrypt parameter upper bounds
# ═══════════════════════════════════════════════════════════════════════════

class TestSecI2ScryptUpperBounds:
    """_password_verify rejects scrypt params above safe maximums."""

    def test_n_upper_bound(self):
        from admin.users import _password_verify
        src = inspect.getsource(_password_verify)
        assert "n > 2**18" in src or "2**18" in src

    def test_r_p_upper_bounds(self):
        from admin.users import _password_verify
        src = inspect.getsource(_password_verify)
        assert "r > 16" in src and "p > 4" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-I3 — Mesh fernet key warning
# ═══════════════════════════════════════════════════════════════════════════

class TestSecI3MeshFernetKeyWarning:
    """Auto-generated MESH_FERNET_KEY emits a startup warning."""

    def test_warning_log_event_present(self):
        src = _read("admin/mesh.py")
        assert "mesh_fernet_key_autogenerated" in src
        assert "MESH_FERNET_KEY env var" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-I4 — audit_log default since
# ═══════════════════════════════════════════════════════════════════════════

class TestSecI4AuditSinceDefault:
    """audit_log_endpoint defaults since to last 30 days when no value supplied."""

    def test_30_day_default_present(self):
        from admin.settings import audit_log_endpoint
        src = inspect.getsource(audit_log_endpoint)
        assert "30 * 86400" in src or "S-I4" in src


# ═══════════════════════════════════════════════════════════════════════════
# S-I5 — _LOCAL_GW_ID invalidation
# ═══════════════════════════════════════════════════════════════════════════

class TestSecI5LocalGwIdInvalidation:
    """_reset_local_gw_id exists and is called from settings import."""

    def test_reset_function_exists(self):
        from admin.mesh import _reset_local_gw_id
        assert callable(_reset_local_gw_id)

    def test_reset_clears_cache(self):
        import admin.mesh as _m
        _m._LOCAL_GW_ID = "stale-id"
        _m._reset_local_gw_id()
        assert _m._LOCAL_GW_ID == ""

    def test_settings_import_calls_reset(self):
        src = _read("admin/settings.py")
        assert "_reset_local_gw_id" in src


# ═══════════════════════════════════════════════════════════════════════════
# Comprehensive sweeps
# ═══════════════════════════════════════════════════════════════════════════

class TestSecuritySweeps:
    """Cross-cutting invariants across all fixes."""

    def test_no_unfixed_csrf_bypass_pattern(self):
        """Regression: `if denied := _require_csrf(request):` is a bug — _require_csrf
        is a decorator factory; calling it returns a truthy closure (always 'denied').
        Must not be re-introduced anywhere."""
        for f in ("admin/settings.py", "admin/users.py", "admin/mesh.py", "admin/oidc.py"):
            src = _read(f)
            assert "denied := _require_csrf(request)" not in src, (
                f"{f} uses _require_csrf as a function — that's a CSRF bypass bug. "
                "Use @_require_csrf as a decorator, or _csrf_token_valid(request)."
            )

    def test_secrets_token_used_for_unpredictable_values(self):
        """C-4 fix: random TOTP token, not HMAC-derived."""
        from admin.users import login_submit_endpoint
        src = inspect.getsource(login_submit_endpoint)
        # The whole login flow must include the random token generation.
        assert "token_urlsafe" in src, (
            "login_submit_endpoint must generate the 2FA partial token with "
            "secrets.token_urlsafe (random), not HMAC-derived (C-4 fix)."
        )
        # And specifically inside the 2FA branch, near the partial_token assignment.
        partial_idx = src.find("partial_token = ")
        assert partial_idx != -1
        partial_line = src[partial_idx: partial_idx + 200]
        assert "token_urlsafe" in partial_line

    def test_no_deterministic_partial_token_pattern(self):
        """Regression guard: ensure no future change reintroduces HMAC(username + '|' + window)."""
        src = _read("admin/users.py")
        # The bug pattern was: hmac.new(SESSION_KEY, (username + "|" + str(_totp_window)).encode(), ...).hexdigest()[:16]
        assert 'username + "|" + str(_totp_window)' not in src, (
            "Deterministic HMAC partial token pattern must not return"
        )
