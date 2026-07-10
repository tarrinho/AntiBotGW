"""
Opt-in pytest plugin for running the suite against a real Postgres.

Activated via env: APPSECGW_TEST_PG=1 + POSTGRES_DSN=<dsn>.

When inactive, every test in this plugin's collection scope is skipped with
a clear reason — the default SQLite test path is unaffected.

Usage:
    APPSECGW_TEST_PG=1 \\
    POSTGRES_DSN=postgres://test:test@127.0.0.1:5432/appsecgw_test \\
    python3 -m pytest tests/test_pg_mode.py -q

The fixture truncates every PG-managed table between tests (much faster
than DROP/CREATE; avoids the ~50ms-per-test DDL cost).
"""
from __future__ import annotations

import os
import pytest


PG_TABLES_TO_TRUNCATE = (
    "events", "abuseipdb_cache", "audit_events", "clients", "metrics_kv",
    "svc_metrics", "timeline", "bans", "ip_bans", "dlp_patterns",
    "users", "user_sessions", "admin_ips", "config_kv", "secrets_kv",
    "gw_audit", "honey_fingerprints",
    "siem_alert_rules", "siem_alert_fired",
    "gw_registry", "gw_distribution", "gw_sync_pending",
    "signal_orders",
)


def pg_mode_active() -> bool:
    """Return True when the user has opted into PG-mode testing AND a DSN
    is present. The marker is documented so CI can set both atomically."""
    return (
        os.environ.get("APPSECGW_TEST_PG", "").lower() in ("1", "true", "yes")
        and bool(os.environ.get("POSTGRES_DSN", "").strip())
    )


def _connect_pg():
    """Returns a fresh psycopg connection or raises."""
    import psycopg  # noqa: F401 — must be installed when opted in
    return psycopg.connect(os.environ["POSTGRES_DSN"], connect_timeout=5)


@pytest.fixture(scope="session")
def pg_session():
    """Session-scoped fixture: opens a single PG connection for setup/
    teardown work. Skips the entire test if PG is not opted in or
    unreachable."""
    if not pg_mode_active():
        pytest.skip(
            "PG-mode tests require APPSECGW_TEST_PG=1 + POSTGRES_DSN. "
            "Skipped — the SQLite test path is the default."
        )
    try:
        conn = _connect_pg()
    except Exception as e:
        pytest.skip(
            f"PG-mode opted in but psycopg.connect failed: "
            f"{type(e).__name__}: {str(e)[:120]}. "
            f"Bring up PG before running these tests."
        )
    # Ensure schema exists for the test session.
    import sys
    if "proxy" not in sys.modules:
        import proxy  # noqa: F401 — triggers db_init_postgres via on_startup
    from db.postgres import db_init_postgres
    db_init_postgres()
    yield conn
    try:
        conn.close()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _pg_truncate_between_tests(pg_session):
    """Truncate every PG-managed table after each test so state never
    leaks across tests. Faster than DROP/CREATE."""
    yield
    try:
        with pg_session.cursor() as cur:
            tables = ", ".join(PG_TABLES_TO_TRUNCATE)
            cur.execute(f"TRUNCATE TABLE {tables} RESTART IDENTITY CASCADE")  # nosec B608
        pg_session.commit()
    except Exception as e:
        # Don't fail tests on cleanup error — surface as a warning so the
        # next test's setup may re-attempt. (psycopg.errors.UndefinedTable
        # on first run is expected if db_init_postgres hasn't completed.)
        import warnings
        warnings.warn(f"PG truncate cleanup failed: "
                      f"{type(e).__name__}: {str(e)[:120]}",
                      stacklevel=2)
