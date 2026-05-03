"""
db/ — Database backend package.
Extracted from proxy.py as part of Phase 2 modular refactoring.

Re-exports the public API so callers can do:
    from db import db_init, db_writer_loop, db_load_secrets, ...
"""

from db.sqlite import (
    db_init,
    db_writer_loop,
    db_load_secrets,
    db_load_config,
    db_load_state,
    _SECRET_KEYS,
    _SCHEMA_MIGRATIONS,
    _apply_sqlite_migrations,
    _refresh_integration_state,
)
from db.postgres import (
    db_init_postgres,
    pg_insert_event,
    pg_db_size,
    pg_test_roundtrip,
    _pg_mirror_kv,
    _migrate_recent_events,
    _apply_pg_migrations,
    _postgres_load_module,
)
