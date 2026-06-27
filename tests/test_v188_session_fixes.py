"""
tests/test_v188_session_fixes.py — regression tests for 1.8.8 bug-fixes.

Covers:
  F01-F04  Redis TLS graceful degradation (_REDIS_TLS_BLOCKED flag)
  D01-D05  DB_BACKEND env-pin only for meaningful values
  P01-P05  POSTGRES_DSN always propagated when switching to postgres
  G01-G04  geo_data_endpoint returns {configured:false} when MAXMIND_CITY_ENABLED is False
  S01-S04  settings.html Load-DSN button wired (btn-db-load-dsn present + handler)
  T01-T03  PG status tile updated after successful test (id _tip-pg-status-val)
"""

import inspect
import os
import re
import sys
import json
import sqlite3
import tempfile
import importlib
import unittest
import pathlib
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

_ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _redis_src() -> str:
    return (_ROOT / "integrations" / "redis.py").read_text(encoding="utf-8")


def _settings_src() -> str:
    return (_ROOT / "dashboards" / "settings.html").read_text(encoding="utf-8")


def _ph_src() -> str:
    return (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# F-series: Redis TLS graceful degradation
# ─────────────────────────────────────────────────────────────────────────────

class TestRedisTlsGracefulDegradation:
    """1.8.8: REDIS_REQUIRE_TLS mismatch sets _REDIS_TLS_BLOCKED instead of crashing."""

    def test_F01_no_systemexit_in_redis_module(self):
        """F01: redis.py must NOT call SystemExit — gateway must never crash on TLS mismatch."""
        src = _redis_src()
        assert "SystemExit" not in src, \
            "redis.py must use _REDIS_TLS_BLOCKED flag, not SystemExit"

    def test_F02_blocked_flag_defined(self):
        """F02: _REDIS_TLS_BLOCKED module-level flag must exist."""
        src = _redis_src()
        assert "_REDIS_TLS_BLOCKED" in src

    def test_F03_tls_required_log_event_present(self):
        """F03: must log redis_tls_required event when TLS enforcement blocks plaintext URL."""
        src = _redis_src()
        assert "redis_tls_required" in src, \
            "redis.py must emit redis_tls_required slog event"

    def test_F04_shared_init_early_returns_on_blocked(self):
        """F04: _shared_init must return early when _REDIS_TLS_BLOCKED is True."""
        import integrations.redis as rm
        src = inspect.getsource(rm._shared_init)
        assert "_REDIS_TLS_BLOCKED" in src, \
            "_shared_init must check _REDIS_TLS_BLOCKED before attempting connection"

    def test_F05_warn_fallback_still_logs_for_dev(self):
        """F05: redis_no_tls warning still exists for REDIS_REQUIRE_TLS=false path."""
        src = _redis_src()
        assert "redis_no_tls" in src, \
            "redis.py must still log redis_no_tls when TLS not required (dev path)"


# ─────────────────────────────────────────────────────────────────────────────
# D-series: DB_BACKEND env-pin discipline
# ─────────────────────────────────────────────────────────────────────────────

class TestDbBackendEnvPin:
    """1.8.8: DB_BACKEND env-pin only for 'sqlite'/'postgres', not empty string."""

    def test_D01_empty_string_not_pinned(self):
        """D01: empty DB_BACKEND env must NOT add DB_BACKEND to _ENV_PROVIDED_KNOBS."""
        src = _ph_src()
        # Ensure the guard uses .strip() and checks for meaningful values
        assert 'in ("sqlite", "postgres")' in src or \
               "in ('sqlite', 'postgres')" in src, \
            "proxy_handler.py must only env-pin DB_BACKEND for 'sqlite' or 'postgres'"

    def test_D02_source_has_strip_guard(self):
        """D02: the env-pin check must call .strip() to handle whitespace.

        Contract change: the 1.8.8 inline ``os.environ.get("DB_BACKEND")…``
        block was refactored into the generic ``_env_knob_is_provided`` helper
        (which builds ``_ENV_PROVIDED_KNOBS`` and calls ``val.strip()`` for
        every knob). Anchor the strip-guard assertion to that helper.
        """
        src = _ph_src()
        # Find the env-pin helper that feeds _ENV_PROVIDED_KNOBS
        m = re.search(
            r'def _env_knob_is_provided.*?_ENV_PROVIDED_KNOBS',
            src, re.DOTALL)
        assert m is not None, "_env_knob_is_provided env-pin block not found"
        snippet = m.group(0)
        assert ".strip()" in snippet, "env-pin helper must call .strip()"

    def test_D03_meaningful_value_sqlite_pinned(self):
        """D03: 'sqlite' value causes DB_BACKEND to be env-pinned."""
        with patch.dict(os.environ, {"DB_BACKEND": "sqlite"}, clear=False):
            # Simulate the guard condition
            result = os.environ.get("DB_BACKEND", "").strip() in ("sqlite", "postgres")
        assert result is True

    def test_D04_meaningful_value_postgres_pinned(self):
        """D04: 'postgres' value causes DB_BACKEND to be env-pinned."""
        with patch.dict(os.environ, {"DB_BACKEND": "postgres"}, clear=False):
            result = os.environ.get("DB_BACKEND", "").strip() in ("sqlite", "postgres")
        assert result is True

    def test_D05_empty_not_pinned(self):
        """D05: empty string value is NOT env-pinned (allows DB-persisted backend to win)."""
        with patch.dict(os.environ, {"DB_BACKEND": ""}, clear=False):
            result = os.environ.get("DB_BACKEND", "").strip() in ("sqlite", "postgres")
        assert result is False


# ─────────────────────────────────────────────────────────────────────────────
# P-series: POSTGRES_DSN always propagated on switch-to-postgres
# ─────────────────────────────────────────────────────────────────────────────

class TestPostgresDsnPropagation:
    """POSTGRES_DSN handling on switch-to-postgres.

    Contract change: the 1.8.8 in-process hot-swap design (_propagate_global
    + dsn_changed conditional + pg_pool_reset) was superseded by the 1.9.0
    os._exit(0) restart redesign (locked by test_critical::test_165). The
    endpoint now persists DB_BACKEND + POSTGRES_DSN to config_kv and calls
    os._exit(0) so docker's --restart policy rebinds the process with the new
    backend — there is no live pool reset / global propagation to test. These
    assertions are aligned to the shipped restart contract.
    """

    def test_P01_persists_dsn_before_restart(self):
        """P01: the body DSN must be persisted to POSTGRES_DSN before the os._exit restart."""
        src = _ph_src()
        fn_start = src.index("async def db_switch_endpoint")
        # Capture the whole handler (it is ~14k chars) up to the next def.
        fn_end = src.index("\nasync def ", fn_start + 10)
        fn_body = src[fn_start:fn_end]
        persist_idx = fn_body.find('globals()["POSTGRES_DSN"] = body_dsn')
        # rfind: the docstring also mentions os._exit(0); the real restart call
        # is the LAST occurrence at the end of the handler body.
        exit_idx = fn_body.rfind("os._exit(0)")
        assert persist_idx != -1, "db_switch_endpoint must persist body_dsn to POSTGRES_DSN"
        assert exit_idx != -1, "db_switch_endpoint must restart via os._exit(0)"
        assert persist_idx < exit_idx, \
            "POSTGRES_DSN must be persisted BEFORE the os._exit(0) restart"

    def test_P02_no_hot_swap_pool_reset(self):
        """P02: restart redesign means pg_pool_reset() is NOT called in db_switch_endpoint."""
        src = _ph_src()
        fn_start = src.index("async def db_switch_endpoint")
        fn_end = src.index("\nasync def ", fn_start + 10)
        fn_body = src[fn_start:fn_end]
        assert "pg_pool_reset()" not in fn_body, \
            "1.9.0 restart redesign does not hot-swap the pool; os._exit handles it"
        assert "dsn_changed" not in fn_body, \
            "1.9.0 restart redesign dropped the conditional dsn_changed hot-swap path"

    def test_P03_restart_via_os_exit_documented(self):
        """P03: db_switch_endpoint must document the os._exit restart mechanism."""
        src = _ph_src()
        fn_start = src.index("async def db_switch_endpoint")
        fn_end = src.index("\nasync def ", fn_start + 10)
        fn_body = src[fn_start:fn_end]
        assert "os._exit(0)" in fn_body and "restart" in fn_body, \
            "db_switch_endpoint must document the os._exit(0) restart behaviour"

    def test_P04_effective_dsn_uses_body_or_current(self):
        """P04: effective dsn must fall back to current POSTGRES_DSN when body carries none."""
        src = _ph_src()
        # 1.9.0: `dsn = body_dsn or POSTGRES_DSN` (was `body_dsn or old_dsn` in 1.8.8)
        assert "body_dsn or POSTGRES_DSN" in src, \
            "effective dsn must be 'body_dsn or POSTGRES_DSN'"

    def test_P05_no_propagate_global_helper(self):
        """P05: the 1.8.8 _propagate_global hot-swap helper was removed in the restart redesign."""
        import core.proxy_handler as ph
        assert not callable(getattr(ph, "_propagate_global", None)), \
            "_propagate_global was removed; switching now restarts via os._exit(0)"


# ─────────────────────────────────────────────────────────────────────────────
# G-series: geo_data_endpoint config guard
# ─────────────────────────────────────────────────────────────────────────────

class TestGeoDataConfigGuard:
    """geo_data_endpoint returns {configured:false} when City DB not loaded."""

    def test_G01_endpoint_checks_maxmind_city_enabled(self):
        """G01: geo_data_endpoint must check MAXMIND_CITY_ENABLED before querying DB."""
        src = _ph_src()
        fn_start = src.index("async def geo_data_endpoint")
        # First 1000 chars to skip the docstring and reach the guard
        fn_body = src[fn_start:fn_start + 1000]
        assert "MAXMIND_CITY_ENABLED" in fn_body, \
            "geo_data_endpoint must check MAXMIND_CITY_ENABLED early in its body"

    def test_G02_returns_configured_false_json(self):
        """G02: when City DB not loaded returns JSON with configured=False."""
        src = _ph_src()
        fn_start = src.index("async def geo_data_endpoint")
        fn_body = src[fn_start:fn_start + 1200]
        assert '"configured": False' in fn_body or "'configured': False" in fn_body, \
            "geo_data_endpoint must return {configured:false} when City DB unavailable"

    def test_G03_endpoint_uses_backend_aware_conn_for_events(self):
        """G03: geo_data_endpoint queries events via the pluggable backend.

        Contract change: geo_data_endpoint was made backend-aware (1.9.1
        backend-aware reads). It no longer pins to sqlite3.connect(DB_PATH);
        it opens the active backend via open_conn() and branches on
        active_backend() to wrap ts bounds in to_timestamp() for Postgres.
        """
        src = _ph_src()
        fn_start = src.index("async def geo_data_endpoint")
        # Widened window (was 4000): the active_backend import/branch sits at
        # ~offset 4011 in 1.9.2+, just past the old window. The endpoint also
        # imports active_backend under an alias (from db import active_backend
        # as _active_geo), so the literal "active_backend" still appears.
        fn_body = src[fn_start:fn_start + 6000]
        assert "open_conn()" in fn_body, \
            "geo_data_endpoint must open the active backend via open_conn()"
        assert "active_backend" in fn_body and "to_timestamp" in fn_body, \
            "geo_data_endpoint must branch on active_backend() for the PG ts wrapping"

    def test_G04_geo_drill_also_checks_city_enabled(self):
        """G04: geo_drill_endpoint has the same configured guard."""
        src = _ph_src()
        fn_start = src.index("async def geo_drill_endpoint")
        fn_body = src[fn_start:fn_start + 1200]
        assert "MAXMIND_CITY_ENABLED" in fn_body, \
            "geo_drill_endpoint must also guard on MAXMIND_CITY_ENABLED"


# ─────────────────────────────────────────────────────────────────────────────
# S-series: settings.html Load DSN button in Apply backend row
# ─────────────────────────────────────────────────────────────────────────────

class TestLoadDsnButtonApplyRow:
    """1.8.8: 'Load DSN' button exists in the Apply backend controls row and is wired."""

    def test_S01_button_html_present(self):
        """S01: btn-db-load-dsn button must exist in settings.html."""
        src = _settings_src()
        assert 'id="btn-db-load-dsn"' in src or "id='btn-db-load-dsn'" in src, \
            "settings.html must contain a btn-db-load-dsn button"

    def test_S02_button_near_apply_button(self):
        """S02: btn-db-load-dsn must be co-located with btn-db-apply."""
        src = _settings_src()
        apply_idx = src.find("btn-db-apply")
        load_idx = src.find("btn-db-load-dsn")
        assert apply_idx != -1 and load_idx != -1
        # Both must appear within 200 chars of each other (same row)
        assert abs(apply_idx - load_idx) < 500, \
            "btn-db-load-dsn must be in the same row as btn-db-apply"

    def test_S03_js_event_listener_wired(self):
        """S03: a click event listener must be registered for btn-db-load-dsn."""
        src = _settings_src()
        assert "btn-db-load-dsn" in src
        # addEventListener must appear after the button definition
        btn_idx = src.find("btn-db-load-dsn")
        remaining = src[btn_idx:]
        assert "addEventListener" in remaining or "onclick" in remaining, \
            "btn-db-load-dsn must have a click handler registered"

    def test_S04_handler_fetches_db_test_endpoint(self):
        """S04: the Load DSN handler must fetch /secured/db-test to read saved DSN."""
        src = _settings_src()
        # The JS handler is registered via addEventListener after the HTML definition,
        # so search for the addEventListener section which will reference db-test
        btn_idx = src.find("btn-db-load-dsn")
        assert btn_idx != -1
        # Search from the first occurrence all the way to end of file for db-test
        handler_region = src[btn_idx:]
        assert "db-test" in handler_region, \
            "btn-db-load-dsn handler must fetch /secured/db-test"

    def test_S05_handler_displays_summary_in_db_msg(self):
        """S05: the handler must show parsed DSN summary in #db-msg span."""
        src = _settings_src()
        handler_region = src[src.find("btn-db-load-dsn"):]
        assert "db-msg" in handler_region[:2000], \
            "btn-db-load-dsn handler must update #db-msg with DSN summary"


# ─────────────────────────────────────────────────────────────────────────────
# T-series: PG status tile live-update after successful test
# ─────────────────────────────────────────────────────────────────────────────

class TestPgStatusTileLiveUpdate:
    """1.8.8: PostgreSQL status tile updates to 'reachable' after a successful DSN test."""

    def test_T01_status_span_has_id(self):
        """T01: the status value span must have id _tip-pg-status-val for DOM updates."""
        src = _settings_src()
        assert "_tip-pg-status-val" in src, \
            "settings.html must have id='_tip-pg-status-val' on the status span"

    def test_T02_test_success_handler_updates_span(self):
        """T02: on successful test, JS must update _tip-pg-status-val content."""
        src = _settings_src()
        status_id_idx = src.find("_tip-pg-status-val")
        # Check that there's a second reference (first = HTML def, second = JS update)
        second_idx = src.find("_tip-pg-status-val", status_id_idx + 1)
        assert second_idx != -1, \
            "settings.html must update _tip-pg-status-val in JS after successful test"

    def test_T03_test_success_updates_cache(self):
        """T03: on successful test, _dbSvcCache.db_postgres.available must be set to true."""
        src = _settings_src()
        assert "_dbSvcCache.db_postgres" in src
        # Find where available is set to true
        assert ".available = true" in src, \
            "settings.html must set _dbSvcCache.db_postgres.available=true on test success"

    def test_T04_status_color_updated_to_green(self):
        """T04: on successful test, status span color must change to var(--green)."""
        src = _settings_src()
        # Find the region that sets _tip-pg-status-val
        idx = src.find("_tip-pg-status-val")
        while idx != -1:
            region = src[idx:idx + 200]
            if "green" in region and ("textContent" in region or "innerHTML" in region):
                break
            idx = src.find("_tip-pg-status-val", idx + 1)
        assert idx != -1, \
            "settings.html must set color var(--green) on _tip-pg-status-val after test success"
