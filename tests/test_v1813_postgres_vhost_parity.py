"""
tests/test_v1813_postgres_vhost_parity.py — the vhost dashboard filter must
work on a Postgres/TimescaleDB-active deployment, not just SQLite.

The Postgres `events` table gained a real `vhost` column (via
_SCHEMA_MIGRATIONS, ADD COLUMN IF NOT EXISTS), but two spots were left stale:
  1. pg_insert_event never WROTE vhost  → every row vhost=''  → filter matches
     nothing for any specific vhost.
  2. _read_events_pg SKIPPED the vhost filter ("no column" — outdated).
Both, plus the record() → pg_insert_event propagation, are guarded here by
source/AST inspection (no live Postgres needed; importing config has
side-effects so we read source, not symbols).
"""
import ast
import os

_REPO = os.path.join(os.path.dirname(__file__), "..")


def _read(path):
    return open(os.path.join(_REPO, path), encoding="utf-8").read()


def _func_src(path, fname):
    src = _read(path)
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fname:
            return ast.get_source_segment(src, n)
    raise AssertionError(f"{fname} not found in {path}")


def test_pg_insert_event_writes_vhost():
    s = _func_src("db/postgres.py", "pg_insert_event")
    assert "vhost" in s.split("def ", 1)[0] or "vhost: str" in s, \
        "pg_insert_event must accept a vhost param"
    # vhost must be in BOTH the column list and the values tuple of the INSERT.
    assert "request_id, vhost)" in s, "pg INSERT column list missing vhost"
    assert "(vhost or \"\")" in s, "pg INSERT values tuple missing vhost"


def test_pg_reader_filters_by_vhost_not_skips():
    s = _func_src("db/postgres.py", "_read_events_pg")
    assert 'where.append("vhost = %s")' in s, "_read_events_pg doesn't filter on vhost"
    assert "db_read_events_pg_skip_vhost" not in s, \
        "_read_events_pg still SKIPS the vhost filter (stale)"


def test_record_propagates_vhost_to_pg():
    s = _func_src("core/metrics.py", "record")
    # the pg_insert_event executor call must propagate the current vhost.
    # 1.8.14 perf — the call site may use `current_vhost_host()` directly OR a
    # cached `_vhost = current_vhost_host()` variable / payload field (the
    # latter is the post-perf-pass pattern that snapshots vhost outside the
    # state_lock JSON dumps). Either is correct; what matters is the vhost
    # value reaches pg_insert_event.
    assert "pg_insert_event" in s, "record() doesn't call pg_insert_event"
    pg_idx = s.index("pg_insert_event")
    nearby = s[pg_idx:pg_idx + 400]
    # The vhost must reach the call: directly, via the cached local, or via
    # the payload dict that the executor unpacks.
    propagates = (
        "current_vhost_host()" in nearby
        or "_vhost" in nearby
        or 'p["vhost"]' in nearby
        or "p['vhost']" in nearby
    )
    assert propagates, (
        "vhost not propagated into pg_insert_event call — neither "
        "current_vhost_host(), _vhost cache, nor p['vhost'] payload found"
    )
    # If the cached form is used, also assert the cache is sourced from
    # current_vhost_host() somewhere in the function — guards against a
    # rename that loses the call entirely.
    assert "current_vhost_host()" in s, (
        "record() must call current_vhost_host() at least once "
        "(directly or via a cached _vhost = current_vhost_host())"
    )


def test_schema_migration_adds_pg_vhost_column():
    # the migration that brings existing Postgres tables up to date must list
    # events.vhost with a non-None Postgres DDL (ADD COLUMN IF NOT EXISTS).
    # _SCHEMA_MIGRATIONS entries are 4-tuples (table, col, sqlite_ddl, pg_ddl);
    # the events.vhost row must have a quoted (non-None) 4th element.
    import re
    src = _read("db/sqlite.py")
    m = re.search(
        r'\(\s*"events"\s*,\s*"vhost"\s*,\s*"[^"]*"\s*,\s*("[^"]+"|None)\s*\)', src)
    assert m, "no events.vhost entry found in _SCHEMA_MIGRATIONS"
    assert m.group(1) != "None", \
        "events.vhost has pg_ddl=None — the Postgres ALTER won't run for old tables"
