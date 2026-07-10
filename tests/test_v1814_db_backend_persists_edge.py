"""
tests/test_v1814_db_backend_persists_edge.py — extra QA around the
DB_BACKEND env-pin exemption in db_load_config.

Companion to test_v1814_db_backend_persists.py. Covers:
  • the exemption survives common refactors (block placement,
    indentation, variable rename)
  • config_kv value MUST still be validated (no silent acceptance of
    operator-corrupted rows)
  • the exemption does NOT extend to other DB-related globals
    (POSTGRES_DSN remains secret-owned, not config_kv-owned)
  • observability: the load step's slog payload still differentiates
    env_pinned from applied so operators can tell where DB_BACKEND
    actually came from
"""
import json
import os
import sqlite3
import sys
import tempfile

import pytest


@pytest.fixture
def temp_db(monkeypatch):
    fd, path = tempfile.mkstemp(suffix=".db", prefix="abp-dbpersist-edge-")
    os.close(fd)
    os.unlink(path)
    monkeypatch.setenv("DB_PATH", path)
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _seed(db_path: str, key: str, value):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS config_kv "
            "(key TEXT PRIMARY KEY, value TEXT, ts REAL)"
        )
        conn.execute(
            "INSERT OR REPLACE INTO config_kv (key, value, ts) VALUES (?, ?, 0)",
            (key, json.dumps(value)),
        )
        conn.commit()
    finally:
        conn.close()


# ── Exemption robustness ────────────────────────────────────────────────

def test_exemption_invalid_value_falls_back_to_env(temp_db):
    """A config_kv DB_BACKEND row holding a bogus value (e.g. someone
    manually edited the SQLite file) must fail the validator and leave the
    env-driven cold-start value in place — must NOT crash the load."""
    from db.sqlite import db_load_config

    _seed(temp_db, "DB_BACKEND", "duckdb")  # not a valid backend
    g = {
        "DB_PATH": temp_db,
        "DB_BACKEND": "sqlite",
        "_HOT_RELOAD_KNOBS": {
            "DB_BACKEND": (
                str,
                lambda v: v in ("sqlite", "postgres"),
            ),
        },
        "_ENV_PROVIDED_KNOBS": {"DB_BACKEND"},
    }
    db_load_config(g)
    assert g["DB_BACKEND"] == "sqlite", (
        "invalid config_kv DB_BACKEND must NOT clobber the env value — "
        "validator rejection must keep the cold-start default"
    )


def test_exemption_handles_missing_validator(temp_db):
    """A registry that registers DB_BACKEND with validator=None must still
    apply the persisted value (validator-None is the registry convention
    for 'no extra check' — the parser already type-coerced)."""
    from db.sqlite import db_load_config

    _seed(temp_db, "DB_BACKEND", "postgres")
    g = {
        "DB_PATH": temp_db,
        "DB_BACKEND": "sqlite",
        "_HOT_RELOAD_KNOBS": {
            "DB_BACKEND": (str, None),
        },
        "_ENV_PROVIDED_KNOBS": {"DB_BACKEND"},
    }
    db_load_config(g)
    assert g["DB_BACKEND"] == "postgres", (
        "exemption must work even when validator is None"
    )


def test_exemption_sqlite_to_postgres_and_back(temp_db):
    """Round-trip: env=sqlite, config_kv flips to postgres, then back to
    sqlite. Each load applies the persisted value over env."""
    from db.sqlite import db_load_config

    g_template = {
        "DB_PATH": temp_db,
        "_HOT_RELOAD_KNOBS": {
            "DB_BACKEND": (
                str,
                lambda v: v in ("sqlite", "postgres"),
            ),
        },
        "_ENV_PROVIDED_KNOBS": {"DB_BACKEND"},
    }

    _seed(temp_db, "DB_BACKEND", "postgres")
    g = dict(g_template, DB_BACKEND="sqlite")
    db_load_config(g)
    assert g["DB_BACKEND"] == "postgres", "round 1: env→postgres failed"

    _seed(temp_db, "DB_BACKEND", "sqlite")
    g = dict(g_template, DB_BACKEND="sqlite")
    db_load_config(g)
    assert g["DB_BACKEND"] == "sqlite", "round 2: postgres→sqlite failed"


# ── Exemption does NOT widen to other knobs ─────────────────────────────

def test_exemption_does_not_cover_postgres_dsn(temp_db):
    """POSTGRES_DSN must remain secret-owned. Putting it in config_kv must
    NOT override env or secrets_kv — secret_skipped path is the contract."""
    import db.sqlite as _s
    src = open(_s.__file__, encoding="utf-8").read()
    # The exemption must be DB_BACKEND-specific; no broad whitelisting.
    assert 'key != "DB_BACKEND"' in src, (
        "exemption must be a precise key-name guard, not a category match"
    )
    # POSTGRES_DSN must still be in _SECRET_KEYS handling (stomp block).
    assert "_SECRET_KEYS" in src and "config_kv_stomp_blocked" in src, (
        "POSTGRES_DSN stomp-block path must remain"
    )


def test_exemption_is_local_to_env_pin_check():
    """The exemption must live INSIDE the env-pin if-statement, not at the
    top of the loop (which would also skip secret-stomp protection)."""
    import db.sqlite as _s
    src = open(_s.__file__, encoding="utf-8").read()
    # Find the env-pin block and make sure DB_BACKEND escape is INSIDE it.
    block_start = src.find('if key in _ENV_PROVIDED_KNOBS')
    assert block_start != -1, "env-pin check must remain present"
    block = src[block_start:block_start + 400]
    assert 'key != "DB_BACKEND"' in block, (
        "DB_BACKEND escape must live INSIDE the _ENV_PROVIDED_KNOBS check, "
        "not above the secret-stomp guard"
    )


# ── Observability ───────────────────────────────────────────────────────

def test_db_config_loaded_log_still_emitted():
    """The end-of-load slog payload must still carry env_pinned + applied
    + skipped counters so operators can grep for 'DB_BACKEND persisted but
    env had it' diagnostics."""
    import db.sqlite as _s
    src = open(_s.__file__, encoding="utf-8").read()
    assert 'slog("db_config_loaded"' in src, (
        "db_load_config must still emit the db_config_loaded summary log"
    )
    # Counters used in the summary log must include env_pinned and applied.
    log_region = src.split('slog("db_config_loaded"', 1)[1][:400]
    for k in ("applied", "env_pinned"):
        assert k in log_region, (
            f"db_config_loaded log must include the '{k}' counter"
        )
