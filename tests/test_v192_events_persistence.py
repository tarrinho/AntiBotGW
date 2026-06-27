"""
1.9.2 iter-6 — events persistence after gw upgrade.

User reported: events disappear after a container upgrade. Root cause
in db/sqlite.py:db_writer_loop — the branch fork was on `if POSTGRES_DSN:`
which routed every event op to the PG-primary path regardless of the
operator-set DB_BACKEND in config_kv.

Scenario that surfaced it:

  1. operator runs SQLite mode (POSTGRES_DSN unset, events go to SQLite)
  2. operator switches to PG via /__db-switch  → events flow to PG; DSN
     is encrypted into secrets_kv
  3. operator switches back to SQLite via /__db-switch?target=sqlite
     → DB_BACKEND="sqlite" persists, BUT the DSN STAYS in secrets_kv
     (intentional — switching back to PG must not require re-typing)
  4. container restarts → db_load_secrets re-binds POSTGRES_DSN at boot
  5. db_writer_loop hits `if POSTGRES_DSN:` → PG-primary branch
  6. operator's events ALL go to PG, SQLite events table stays static
  7. operator (looking at SQLite-mode dashboards) sees events
     "disappearing after the upgrade"

Fix: fork on `if DB_BACKEND == "postgres" and POSTGRES_DSN:`. The
DB_BACKEND choice is the operator's explicit intent; the DSN is just
credential material that may be preserved across mode switches.

Also adds `DB_BACKEND` to the `from config import (...)` block in
db/sqlite.py — the bare reference inside `db_writer_loop` would
NameError without it, which previously crashed the writer task before
the fork condition could fire (caught during dynamic testing — the
slog stream stayed silent because the task died at function entry).
"""
import pathlib


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_DBSQ_SRC = (_ROOT / "db" / "sqlite.py").read_text(encoding="utf-8")


def test_db_backend_imported_from_config():
    """db_writer_loop references `DB_BACKEND` in its fork condition.
    Without it in the `from config import (...)` block, the writer
    task crashes at first read of DB_BACKEND with NameError and never
    drains the queue — events silently dropped at the queue level.
    Source-grep is sufficient: a runtime NameError would be caught
    by the broader test suite if the writer were exercised, but the
    writer is only spawned in on_startup which the unit tests skip."""
    import re as _re
    # Find the `from config import (...)` block
    m = _re.search(
        r"from config import \((.*?)\)",
        _DBSQ_SRC, _re.DOTALL)
    assert m, "db/sqlite.py: from config import (...) block missing"
    imports = m.group(1)
    assert "DB_BACKEND" in imports, (
        "db/sqlite.py must import DB_BACKEND from config — the writer-"
        "loop fork condition references it, and a bare reference "
        "without import raises NameError at function entry, silently "
        "killing the writer task (events drop into a black hole)."
    )


def test_writer_loop_forks_on_db_backend_not_dsn():
    """The fork between PG-primary and SQLite-primary writer paths
    must check BOTH the operator's DB_BACKEND choice AND the
    presence of POSTGRES_DSN. Checking POSTGRES_DSN alone meant
    that a switch-back-to-sqlite followed by a restart silently
    re-routed events to PG (because DSN stays in secrets_kv across
    the switch by design)."""
    # Find the fork line in db_writer_loop
    import re as _re
    # Locate the function body
    idx = _DBSQ_SRC.find("async def db_writer_loop")
    assert idx > 0
    nxt = _DBSQ_SRC.find("\nasync def ", idx + 1)
    body = _DBSQ_SRC[idx:nxt if nxt > 0 else len(_DBSQ_SRC)]
    # The OLD shape `if POSTGRES_DSN:` must NOT appear as the fork
    # condition. (It may still appear inside the branches as a feature
    # gate, e.g. for inline mirror calls — guard only the top-level
    # fork by looking near the PG-primary branch comment.)
    fork_idx = body.find("# ── PG-primary writer-loop")
    assert fork_idx > 0, "PG-primary writer-loop comment missing"
    # The fork condition is the next `if` line after the comment.
    # Slice ~2 KB of body following the comment so we don't trip on
    # other `if POSTGRES_DSN:` inside the function bodies.
    after = body[fork_idx:fork_idx + 2500]
    # The NEW fork must be present.
    assert "if DB_BACKEND == \"postgres\" and POSTGRES_DSN:" in after, (
        "db_writer_loop fork must check `DB_BACKEND == \"postgres\" "
        "and POSTGRES_DSN` — checking DSN alone bypasses the operator's "
        "explicit backend choice after a /__db-switch?target=sqlite "
        "round-trip."
    )


def test_writer_loop_iter6_docstring_present():
    """The fix block must carry the iter-6 marker so a future reader
    understands WHY the fork condition isn't just `if POSTGRES_DSN:`."""
    assert "iter-6 fix (events-persistence-after-upgrade)" in _DBSQ_SRC, (
        "db_writer_loop must carry an iter-6 fix marker explaining the "
        "events-persistence-after-upgrade hazard"
    )


def test_writer_loop_fork_uses_explicit_both_check():
    """Defensive: ensure the new condition uses BOTH operands. A bug
    that drops the `POSTGRES_DSN` half (e.g. `if DB_BACKEND ==
    "postgres":` alone) would let a misconfigured deployment with
    DB_BACKEND set but no DSN crash the writer when it tries to mirror."""
    import re as _re
    # The fork condition with both operands
    m = _re.search(
        r"if\s+DB_BACKEND\s*==\s*[\"']postgres[\"']\s+and\s+POSTGRES_DSN\s*:",
        _DBSQ_SRC)
    assert m, (
        "Fork condition must be exactly `if DB_BACKEND == \"postgres\" "
        "and POSTGRES_DSN:` — both operands required."
    )


# pg_insert_event silent-swallow fix

_DBPG_SRC = (_ROOT / "db" / "postgres.py").read_text(encoding="utf-8")


def test_pg_insert_event_logs_failures_not_silent():
    """The PG side of events persistence ALSO had a silent-drop bug:
    `pg_insert_event` caught every Exception and returned False with
    zero log. A legacy events schema missing the `method` or `vhost`
    column (an upgrade path where _apply_pg_migrations didn't run, or
    ran but rolled back) raised UndefinedColumn → silently dropped
    100% of events → operator saw "events disappear after upgrade"
    with no breadcrumb.

    Fix: log the first occurrence of each distinct exception class with
    the message so the operator can diagnose without searching for a
    health endpoint."""
    idx = _DBPG_SRC.find("def pg_insert_event")
    assert idx > 0, "pg_insert_event must exist"
    end = _DBPG_SRC.find("\ndef ", idx + 1)
    body = _DBPG_SRC[idx:end if end > 0 else len(_DBPG_SRC)]
    # The OLD shape: `except Exception: return False` (single line)
    # with no log call. The new shape: `except Exception as _e:` with
    # an _logging or slog call inside.
    assert "except Exception as _e:" in body, (
        "pg_insert_event must bind the exception so the failure can be "
        "logged. Previously `except Exception: return False` swallowed "
        "every error silently."
    )
    assert "pg-insert-event" in body and "DROPPED" in body, (
        "pg_insert_event must log dropped events with [pg-insert-event] "
        "prefix + 'DROPPED' marker so operators can grep for them."
    )


def test_pg_insert_event_rate_limits_log_spam():
    """The log must be rate-limited — `_seen_err_classes` set on the
    function attribute deduplicates by exception type so a sustained
    PG outage doesn't fill the log with thousands of identical errors."""
    idx = _DBPG_SRC.find("def pg_insert_event")
    end = _DBPG_SRC.find("\ndef ", idx + 1)
    body = _DBPG_SRC[idx:end if end > 0 else len(_DBPG_SRC)]
    assert "_seen_err_classes" in body, (
        "pg_insert_event must rate-limit error logs via a "
        "_seen_err_classes set (one log per exception class)"
    )


def test_pg_insert_event_logs_pool_init_failure():
    """A pool-init failure (no DSN, unreachable PG, auth failure) is
    a separate cause from per-event exceptions. Log it ONCE on the
    first call so the operator knows the writer is configured wrong."""
    idx = _DBPG_SRC.find("def pg_insert_event")
    end = _DBPG_SRC.find("\ndef ", idx + 1)
    body = _DBPG_SRC[idx:end if end > 0 else len(_DBPG_SRC)]
    assert "_pool_none_logged" in body, (
        "pg_insert_event must log the FIRST time the pool is None — "
        "currently it returns False silently, indistinguishable from a "
        "transient error"
    )
    assert "pool unavailable" in body, (
        "pool-init failure log line must say 'pool unavailable' so "
        "operators grepping for it find both root causes"
    )
