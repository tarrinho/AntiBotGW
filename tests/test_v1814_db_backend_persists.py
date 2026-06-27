"""
tests/test_v1814_db_backend_persists.py — guard the DB_BACKEND
config_kv-wins-over-env exception.

Pre-1.8.14 (this fix): db_load_config skipped any knob present in
_ENV_PROVIDED_KNOBS. DB_BACKEND was in that set whenever the operator
shipped DB_BACKEND=postgres|sqlite via container env. Side-effect: the
dedicated /secured/db-switch endpoint (operator-mediated, runs a
connectivity probe + schema init + pool reset + event-window migration
before flipping) persisted the operator's choice to config_kv, but env
re-won on every restart — so the switch silently reverted.

Fix: DB_BACKEND is exempt from the env-pin in db_load_config; the
config_kv value is authoritative once present.
"""
import json
import os
import sqlite3
import sys
import tempfile

import pytest


@pytest.fixture
def temp_db(monkeypatch):
    """Fresh DB_PATH per test; restore env afterwards."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="abp-dbpersist-")
    os.close(fd)
    os.unlink(path)
    monkeypatch.setenv("DB_PATH", path)
    yield path
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


@pytest.fixture
def force_sqlite_backend(monkeypatch):
    """Pin db_load_config to the SQLite backend for this test.

    db_load_config is backend-aware (1.9.2): when POSTGRES_DSN is set it reads
    config_kv from Postgres via active_backend(), ignoring the temp SQLite DB
    these tests seed. Under APPSECGW_TEST_PG=1 that means the seeded override is
    never read. Clearing POSTGRES_DSN in both the config module (consulted by
    active_backend() at call time) and the db.sqlite module-level binding
    (consulted by the PG-authority coercion in db_load_config) routes the read
    back to the per-test DB_PATH so the env-pin exemption is actually exercised.
    """
    import config as _cfg
    import db.sqlite as _s
    monkeypatch.setattr(_cfg, "POSTGRES_DSN", "", raising=False)
    monkeypatch.setattr(_s, "POSTGRES_DSN", "", raising=False)
    yield


def _seed_config_kv(db_path: str, key: str, value):
    """Schema-aware insert (config_kv ts column is NOT NULL on newer
    migrations)."""
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


def test_db_load_config_db_backend_exempt_from_env_pin(temp_db, force_sqlite_backend):
    """The core fix: with DB_BACKEND in _ENV_PROVIDED_KNOBS and a config_kv
    row holding the opposite value, db_load_config must apply the config_kv
    value (not skip it as env-pinned)."""
    from db.sqlite import db_load_config

    _seed_config_kv(temp_db, "DB_BACKEND", "postgres")
    g = {
        "DB_PATH": temp_db,
        "DB_BACKEND": "sqlite",       # cold-start default from env
        "_HOT_RELOAD_KNOBS": {
            "DB_BACKEND": (
                str,
                lambda v: v in ("sqlite", "postgres"),
            ),
        },
        # Worst case: DB_BACKEND IS env-pinned. Fix must override.
        "_ENV_PROVIDED_KNOBS": {"DB_BACKEND"},
    }
    db_load_config(g)
    assert g["DB_BACKEND"] == "postgres", (
        "db_load_config must let config_kv override env for DB_BACKEND so "
        "the operator's /db-switch choice survives container restart"
    )


def test_other_env_pinned_knobs_still_respect_env(temp_db):
    """Sibling regression: the DB_BACKEND exemption must be SPECIFIC; other
    env-pinned knobs must keep their env values when config_kv differs."""
    from db.sqlite import db_load_config

    _seed_config_kv(temp_db, "SOME_OTHER_KNOB", "from-db")
    g = {
        "DB_PATH": temp_db,
        "SOME_OTHER_KNOB": "from-env",
        "_HOT_RELOAD_KNOBS": {
            "SOME_OTHER_KNOB": (str, None),
        },
        "_ENV_PROVIDED_KNOBS": {"SOME_OTHER_KNOB"},
    }
    db_load_config(g)
    assert g["SOME_OTHER_KNOB"] == "from-env", (
        "env-pinned non-DB_BACKEND knobs must NOT be overridden by config_kv"
    )


def test_db_backend_exemption_is_documented_in_sqlite_module():
    """The exemption is load-bearing — its `key != \"DB_BACKEND\"` guard must
    stay paired with an explanatory comment so a future refactor doesn't
    silently re-pin it."""
    import db.sqlite as _s
    src = open(_s.__file__, encoding="utf-8").read()
    assert "key != \"DB_BACKEND\"" in src, (
        "db_load_config must guard the env-pin skip with `key != \"DB_BACKEND\"`"
    )
    # Anchor: comment must reference /db-switch so the rationale is preserved.
    assert "/secured/db-switch" in src or "db_switch" in src, (
        "exemption must be commented near a /db-switch reference so future "
        "maintainers understand why DB_BACKEND escapes the env-pin"
    )


def test_db_backend_with_no_config_kv_falls_through_to_env(temp_db):
    """When config_kv has NO row for DB_BACKEND, the env-driven cold-start
    value remains. (No config_kv = nothing to override with.)"""
    from db.sqlite import db_load_config

    g = {
        "DB_PATH": temp_db,
        "DB_BACKEND": "postgres",     # env cold-start default
        "_HOT_RELOAD_KNOBS": {
            "DB_BACKEND": (
                str,
                lambda v: v in ("sqlite", "postgres"),
            ),
        },
        "_ENV_PROVIDED_KNOBS": {"DB_BACKEND"},
    }
    # Empty config_kv → nothing applied.
    conn = sqlite3.connect(temp_db)
    conn.execute("CREATE TABLE IF NOT EXISTS config_kv "
                 "(key TEXT PRIMARY KEY, value TEXT, ts REAL)")
    conn.commit()
    conn.close()
    db_load_config(g)
    assert g["DB_BACKEND"] == "postgres", (
        "With no config_kv row for DB_BACKEND, env value must stand"
    )
