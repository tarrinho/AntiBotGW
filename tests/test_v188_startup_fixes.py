"""
tests/test_v188_startup_fixes.py — regression tests for 1.8.8 container-startup
and test-button UX fixes.

Covers:
  C01-C03  docker-compose.yml tmpfs ≥ 64 MiB (root cause: 16 MiB too small
           for SQLite startup temp-files in read_only container)
  P01-P03  _tip-pg-test: password only required when no stored creds (credsOk2)
  U01-U03  _tip-pg-test: no-param URL path when password is empty + creds saved
  R01-R04  _tip-pg-test: both /db-test response shapes handled (j.probe / j.postgres)
  H01-H04  _tip-pg-test: soft HTTP-error branches (404/403 → warning, not crash)
"""

import re
import sys
import pathlib

import pytest

_ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))


def _settings_src() -> str:
    return (_ROOT / "dashboards" / "settings.html").read_text(encoding="utf-8")


def _compose_src() -> str:
    return (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")


def _tip_pg_test_handler() -> str:
    """Return the _tip-pg-test onclick block (up to 4000 chars)."""
    src = _settings_src()
    marker = "document.getElementById('_tip-pg-test').onclick"
    idx = src.find(marker)
    assert idx != -1, "_tip-pg-test onclick not found in settings.html"
    return src[idx: idx + 4000]


# ─────────────────────────────────────────────────────────────────────────────
# C-series: docker-compose.yml tmpfs size
# ─────────────────────────────────────────────────────────────────────────────

class TestComposeTmpfsSize:
    """1.8.8: tmpfs must be ≥ 64 MiB so SQLite startup temp-files don't exhaust /tmp."""

    def test_C01_tmpfs_line_present(self):
        """C01: compose must define a /tmp tmpfs mount for the gateway."""
        src = _compose_src()
        assert "/tmp:" in src, "docker-compose.yml must configure a /tmp tmpfs"

    def test_C02_tmpfs_at_least_64m(self):
        """C02: /tmp tmpfs size must be ≥ 64 MiB (SQLite needs >16 MiB in read-only mode)."""
        src = _compose_src()
        m = re.search(r'/tmp:size=(\d+)m', src)
        assert m is not None, "/tmp:size=<N>m not found in docker-compose.yml tmpfs"
        size_mb = int(m.group(1))
        assert size_mb >= 64, (
            f"tmpfs /tmp size is {size_mb}m — must be ≥ 64m. "
            "SQLite creates temp files >16 MiB at startup when the container "
            "filesystem is read-only (Python can't write __pycache__ to /app)."
        )

    def test_C03_read_only_flag_still_present(self):
        """C03: read_only: true must still be set — tmpfs increase must not remove hardening."""
        src = _compose_src()
        assert "read_only: true" in src or "read-only" in src, (
            "docker-compose.yml must retain read_only: true for the gateway container"
        )


# ─────────────────────────────────────────────────────────────────────────────
# P-series: password guard uses credsOk2 fallback
# ─────────────────────────────────────────────────────────────────────────────

class TestPgTestPasswordGuard:
    """1.8.8: password only mandatory when no saved creds exist (credsOk2)."""

    def test_P01_credsOk2_variable_defined(self):
        """P01: credsOk2 must be defined before the password guard."""
        blk = _tip_pg_test_handler()
        creds_idx  = blk.find("credsOk2")
        assert creds_idx != -1, "_tip-pg-test must define credsOk2"

    def test_P02_password_guard_uses_credsOk2(self):
        """P02: password guard must be '!f.w && !credsOk2', not just '!f.w'."""
        blk = _tip_pg_test_handler()
        # Both parts must appear in the same conditional
        assert "!f.w" in blk and "!credsOk2" in blk, (
            "_tip-pg-test password guard must check both !f.w AND !credsOk2"
        )
        # Must NOT have a bare '!f.w' guard that returns early without checking credsOk2
        m = re.search(r'if\s*\(\s*!f\.w\s*\)', blk)
        assert m is None, (
            "_tip-pg-test must NOT have a bare 'if (!f.w)' guard — "
            "use 'if (!f.w && !credsOk2)' so stored creds bypass the password requirement"
        )

    def test_P03_credsOk2_checks_configured_flag(self):
        """P03: credsOk2 must check _dbSvcCache.db_postgres.configured (not just .available)."""
        blk = _tip_pg_test_handler()
        assert "db_postgres" in blk and "configured" in blk, (
            "credsOk2 must check _dbSvcCache.db_postgres.configured"
        )


# ─────────────────────────────────────────────────────────────────────────────
# U-series: URL selection (DSN-param vs no-param)
# ─────────────────────────────────────────────────────────────────────────────

class TestPgTestUrlSelection:
    """1.8.8: handler picks the right /db-test URL based on whether password is present."""

    def test_U01_testUrl_variable_defined(self):
        """U01: testUrl variable must be set conditionally on f.w."""
        blk = _tip_pg_test_handler()
        assert "testUrl" in blk, "_tip-pg-test must define a testUrl variable"

    def test_U02_dsn_param_url_when_password_present(self):
        """U02: ?dsn= URL used when password is filled (f.w truthy)."""
        blk = _tip_pg_test_handler()
        assert "db-test?dsn=" in blk or "db-test\\?dsn=" in blk or "db-test?dsn" in blk, (
            "_tip-pg-test must build a ?dsn=<url> query when f.w is present"
        )

    def test_U03_no_param_url_when_password_empty(self):
        """U03: bare /db-test URL (no ?dsn) used when password empty + credsOk2."""
        blk = _tip_pg_test_handler()
        # The no-param branch should be the /db-test endpoint without a query string
        assert "'/antibot-appsec-gateway/secured/db-test'" in blk or \
               '"/antibot-appsec-gateway/secured/db-test"' in blk, (
            "_tip-pg-test must use bare /secured/db-test (no ?dsn=) when password is empty"
        )


# ─────────────────────────────────────────────────────────────────────────────
# R-series: both response shapes handled
# ─────────────────────────────────────────────────────────────────────────────

class TestPgTestResponseShapes:
    """1.8.8: handler normalises j.probe (?dsn= path) and j.postgres (no-param path)."""

    def test_R01_unified_probe_variable(self):
        """R01: handler must unify both shapes into a single variable (p = j.probe || j.postgres)."""
        blk = _tip_pg_test_handler()
        assert "j.probe" in blk and "j.postgres" in blk, (
            "_tip-pg-test must reference both j.probe and j.postgres response shapes"
        )

    def test_R02_success_check_covers_both_shapes(self):
        """R02: success condition must check j.ok OR p.ok to cover both response shapes."""
        blk = _tip_pg_test_handler()
        assert "j.ok" in blk and "p.ok" in blk, (
            "_tip-pg-test success check must cover j.ok (no-param path) and p.ok (probe path)"
        )

    def test_R03_version_uses_unified_p_variable(self):
        """R03: version / db / ms details must come from the unified p variable."""
        blk = _tip_pg_test_handler()
        assert "p.version" in blk, (
            "_tip-pg-test must read p.version from the unified probe variable"
        )
        assert "p.round_trip_ms" in blk or "round_trip_ms" in blk, (
            "_tip-pg-test must read round_trip_ms from the unified probe variable"
        )

    def test_R04_failure_reason_from_unified_p(self):
        """R04: failure reason must try j.reason then p.reason (both shapes)."""
        blk = _tip_pg_test_handler()
        assert "j.reason" in blk and "p.reason" in blk, (
            "_tip-pg-test must try j.reason||p.reason for failure message"
        )


# ─────────────────────────────────────────────────────────────────────────────
# H-series: soft HTTP-error handling
# ─────────────────────────────────────────────────────────────────────────────

class TestPgTestHttpErrorHandling:
    """1.8.8: non-200 HTTP responses produce a ⚠ warning, not a hard ✗ failure."""

    def test_H01_r_ok_check_present(self):
        """H01: handler must check r.ok before processing JSON."""
        blk = _tip_pg_test_handler()
        assert "r.ok" in blk, "_tip-pg-test must check r.ok for HTTP errors"

    def test_H02_404_403_hint_present(self):
        """H02: 404/403 must produce a hint about allowlist/session blocking."""
        blk = _tip_pg_test_handler()
        assert "404" in blk and "403" in blk, (
            "_tip-pg-test must mention 404 and 403 in its HTTP-error hint"
        )
        assert "allowlist" in blk or "session" in blk, (
            "_tip-pg-test 404/403 hint must mention allowlist or session as cause"
        )

    def test_H03_http_error_uses_warning_style(self):
        """H03: HTTP errors must use ⚠ prefix, NOT ✗ (ambiguous — DB may be fine)."""
        blk = _tip_pg_test_handler()
        # Find the r.ok false branch
        not_ok_idx = blk.find("!r.ok")
        assert not_ok_idx != -1, "!r.ok branch not found"
        not_ok_region = blk[not_ok_idx: not_ok_idx + 300]
        assert "⚠" in not_ok_region or "\\u26a0" in not_ok_region, (
            "HTTP error branch must show ⚠ (warning), not ✗ (hard failure)"
        )

    def test_H04_network_error_catch_present(self):
        """H04: fetch() must be wrapped in try/catch for network-level failures."""
        blk = _tip_pg_test_handler()
        # Must have a try/catch around the fetch
        try_idx   = blk.find("try {")
        catch_idx = blk.find("catch(")
        assert try_idx != -1, "_tip-pg-test must wrap fetch in try/catch"
        assert catch_idx != -1, "_tip-pg-test must have a catch block for network errors"
        assert try_idx < catch_idx
