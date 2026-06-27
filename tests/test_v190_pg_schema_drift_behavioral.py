"""
tests/test_v190_pg_schema_drift_behavioral.py — behavioral coverage of
check_pg_schema_version() across the full drift matrix.

Existing v190 / pg_only_dynamic tests anchor on the constant + the
INSERT during init. This file actually drives the function across all 5
drift positions (-2, -1, 0, +1, +2) and asserts each returns the right
should_exit / severity / exit_code combo.

The boot-time contract for the function:

    diff = expected - current
      = 0      → no action, severity=info
      = +1     → forward migration (single-step), severity=info, ok=True
      = -1     → downgrade-tolerated, severity=warn, ok=True
      = +2+    → FATAL, exit_code=5, should_exit=True, ok=False
      = -2+    → FATAL, exit_code=5, should_exit=True, ok=False

Without these tests, a refactor that flipped the comparison or widened
the tolerance window would silently let a multi-version-skipped boot
proceed against a schema the gateway doesn't understand.
"""
import importlib
from contextlib import contextmanager
from unittest.mock import MagicMock, patch


def _pg():
    return importlib.import_module("db.postgres")


@contextmanager
def _patch_drift(current: "int | None", expected: int):
    """Patch the read-side + the constant so check_pg_schema_version sees
    the desired (current, expected) pair."""
    pg = _pg()
    # Stub pool that returns a connection so the early-return guards skip.
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_pool.connection.return_value.__enter__.return_value = mock_conn
    with patch.object(pg, "_get_pool", return_value=mock_pool), \
         patch.object(pg, "_read_pg_schema_version", return_value=current), \
         patch.object(pg, "PG_SCHEMA_VERSION", expected):
        yield


# ── Diff = 0: no drift ──────────────────────────────────────────────────

def test_drift_zero_is_ok():
    with _patch_drift(current=1, expected=1):
        r = _pg().check_pg_schema_version()
    assert r["ok"] is True
    assert r["should_exit"] is False
    assert r["diff"] == 0
    assert r["exit_code"] == 0
    assert r["severity"] in ("info", "ok")


# ── Diff = +1: forward migration ───────────────────────────────────────

def test_drift_plus_one_applies_single_step():
    with _patch_drift(current=1, expected=2):
        r = _pg().check_pg_schema_version()
    assert r["ok"] is True
    assert r["should_exit"] is False
    assert r["diff"] == 1
    assert r["severity"] == "info"
    assert "v1" in r["msg"] and "v2" in r["msg"]


# ── Diff = -1: downgrade-tolerated ─────────────────────────────────────

def test_drift_minus_one_warns_but_boots():
    with _patch_drift(current=2, expected=1):
        r = _pg().check_pg_schema_version()
    assert r["ok"] is True
    assert r["should_exit"] is False
    assert r["diff"] == -1
    assert r["severity"] == "warn"
    assert "downgrade-tolerated" in r["msg"].lower() or "downgrade" in r["msg"].lower()


# ── Diff = +2: FATAL ───────────────────────────────────────────────────

def test_drift_plus_two_refuses_with_exit_5():
    with _patch_drift(current=1, expected=3):
        r = _pg().check_pg_schema_version()
    pg = _pg()
    assert r["ok"] is False
    assert r["should_exit"] is True
    assert r["exit_code"] == pg._PG_SCHEMA_DRIFT_EXIT_CODE == 5
    assert r["severity"] == "error"
    assert "skip" in r["msg"].lower() or "intermediate" in r["msg"].lower()


# ── Diff = -2: FATAL ───────────────────────────────────────────────────

def test_drift_minus_two_refuses_with_exit_5():
    with _patch_drift(current=3, expected=1):
        r = _pg().check_pg_schema_version()
    pg = _pg()
    assert r["ok"] is False
    assert r["should_exit"] is True
    assert r["exit_code"] == pg._PG_SCHEMA_DRIFT_EXIT_CODE == 5
    assert r["severity"] == "error"
    assert "downgrade" in r["msg"].lower() or "predates" in r["msg"].lower()


# ── Fresh DB (current=None) ─────────────────────────────────────────────

def test_fresh_db_no_current_is_ok():
    """Empty pg_schema_versions table on a brand-new install → current=None.
    Must NOT crash on the None comparison; should report no drift."""
    with _patch_drift(current=None, expected=1):
        r = _pg().check_pg_schema_version()
    assert r["ok"] is True
    assert r["should_exit"] is False
    assert r["current"] is None
    assert r["diff"] is None
    # Should not look like an error.
    assert r["severity"] in ("info", "ok")


# ── No PG pool (DSN unset / psycopg missing) ───────────────────────────

def test_no_pool_short_circuits_ok():
    """When _get_pool() returns None — no DSN, or psycopg missing — the
    check must short-circuit with ok=True so the SQLite-mode boot path
    isn't poisoned by the absence of a PG schema-version row."""
    pg = _pg()
    with patch.object(pg, "_get_pool", return_value=None):
        r = pg.check_pg_schema_version()
    assert r["ok"] is True
    assert r["should_exit"] is False
    assert "skipped" in r["msg"].lower() or "no pg" in r["msg"].lower() or \
           "pool" in r["msg"].lower()
    assert r["severity"] == "info"


# ── Constant guard ──────────────────────────────────────────────────────

def test_drift_exit_code_constant_value():
    """The fail-fast exit code is part of the orchestrator contract — must
    stay at 5 so docker-compose / k8s restart policies are stable."""
    pg = _pg()
    assert pg._PG_SCHEMA_DRIFT_EXIT_CODE == 5, (
        "exit code 5 is the public PG-schema-drift contract; bumping it "
        "breaks orchestrator restart classification"
    )
