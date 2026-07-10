"""
db/conn.py — Backend-aware connection helper.

Phase 3 of the PG-only migration. Provides a single `conn()` context manager
that returns either a sqlite3.Connection or a thin wrapper around a psycopg
connection. The wrapper transparently rewrites `?` placeholders to `%s` so
existing query strings work unchanged.

Backend selection: POSTGRES_DSN set → PG. Otherwise → SQLite. The choice is
made at call time (not import time) so tests can override it per-test by
manipulating the config module.

Caveats:
  - sqlite3.Row row_factory has no PG equivalent in this wrapper; use
    explicit column indexing or psycopg's dict_row when on PG.
  - SQLite-only ops (PRAGMA, VACUUM, file-size lookups) must be gated on
    `active_backend() == "sqlite"` at the call site.
  - INSERT OR REPLACE / INSERT OR IGNORE are NOT rewritten. Callers that
    need cross-backend upsert should use INSERT ... ON CONFLICT (works in
    both SQLite 3.24+ and PG).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Any, Iterator, Optional


def _rewrite_placeholders(sql: str) -> str:
    """Rewrite SQLite-style `?` placeholders to psycopg-style `%s`, but
    only OUTSIDE string literals + line comments. Naive `str.replace("?",
    "%s")` would corrupt SQL like `WHERE name = '? what' AND id = ?`.

    Also escapes existing `%` so psycopg doesn't try to interpolate them.

    Recognised quote contexts:
      - Single-quoted strings: `'...'`. Doubled-up `''` is an escaped
        single-quote (SQL standard), stays inside the string.
      - Double-quoted identifiers: `"col name"`.
      - `--` line comments through end-of-line.
      - `/* */` block comments.
    """
    if "?" not in sql and "%" not in sql:
        return sql
    out = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        # Line comment — copy to EOL
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            end = sql.find("\n", i)
            if end < 0:
                end = n
            else:
                end += 1
            out.append(sql[i:end])
            i = end
            continue
        # Block comment — copy to `*/`
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            end = sql.find("*/", i + 2)
            if end < 0:
                end = n
            else:
                end += 2
            out.append(sql[i:end])
            i = end
            continue
        # Single-quoted string literal
        if ch == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    # Doubled single-quote is an escape — consume both.
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            # Escape any `%` inside the string literal for psycopg.
            out.append(sql[i:j].replace("%", "%%"))
            i = j
            continue
        # Double-quoted identifier
        if ch == '"':
            j = i + 1
            while j < n:
                if sql[j] == '"':
                    if j + 1 < n and sql[j + 1] == '"':
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            out.append(sql[i:j])
            i = j
            continue
        # Outside any string / comment: translate `?` → `%s` and escape
        # bare `%` so psycopg doesn't interpolate.
        if ch == "?":
            out.append("%s")
        elif ch == "%":
            out.append("%%")
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def active_backend() -> str:
    """Return 'postgres' if POSTGRES_DSN is set, else 'sqlite'.

    Looked up at call time so a test that monkeypatches config.POSTGRES_DSN
    immediately changes routing.

    L1 fix: catch ImportError specifically. A broad `except Exception` hid
    real config.py errors (env-var validation, key-file IO) behind a
    silent fallback to sqlite mode.
    """
    try:
        from config import POSTGRES_DSN
    except ImportError:
        return "sqlite"
    return "postgres" if POSTGRES_DSN else "sqlite"


class _PgCursorWrapper:
    """sqlite3-cursor-compatible wrapper around a psycopg cursor.

    Forwards execute() / executemany() through `_rewrite_placeholders` so
    callers that grab a cursor explicitly (`conn.cursor().execute(...)`)
    get the same `?` → `%s` translation as `conn.execute(...)`. Previously
    cursor() returned the raw psycopg cursor, so the placeholder syntax
    silently broke on PG.
    """

    __slots__ = ("_cur",)

    def __init__(self, cur):
        self._cur = cur

    def execute(self, sql, params=None):
        """L10 return contract — returns `self` (a _PgCursorWrapper).
        Pairs with _PgConnWrapper.execute() which returns a NEW
        _PgCursorWrapper. Both flow paths produce a fetchone/fetchall
        -able cursor object, so:
            conn.execute(sql).fetchone()
            conn.cursor().execute(sql).fetchone()
        are interchangeable. Callers must NOT depend on the wrapper
        being the same instance across either path."""
        sql_pg = _rewrite_placeholders(sql)
        if params is None:
            self._cur.execute(sql_pg)
        else:
            self._cur.execute(sql_pg, params)
        return self

    def executemany(self, sql, seq_of_params):
        """Same return contract as execute() (L10)."""
        sql_pg = _rewrite_placeholders(sql)
        self._cur.executemany(sql_pg, seq_of_params)
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __iter__(self):
        return iter(self._cur)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        try:
            self._cur.close()
        except Exception:
            pass  # nosec B110

    @property
    def lastrowid(self):
        # psycopg has no lastrowid; callers needing this on PG must use
        # RETURNING id and fetchone() instead.
        return None

    @property
    def rowcount(self):
        return self._cur.rowcount


class _PgConnWrapper:
    """sqlite3.Connection-compatible wrapper over a psycopg connection.

    Translates `?` placeholders to `%s`. Supports the subset of the
    sqlite3.Connection API actually used by callers in this codebase.
    """

    __slots__ = ("_conn", "_row_factory")

    def __init__(self, pg_conn):
        self._conn = pg_conn
        self._row_factory = None

    # row_factory — accepted but ignored. sqlite3.Row offers index + name
    # access; on PG callers should fall back to positional access until they
    # opt into psycopg's dict_row at a higher level.
    @property
    def row_factory(self):
        return self._row_factory

    @row_factory.setter
    def row_factory(self, factory):
        self._row_factory = factory

    def _make_cursor(self):
        """Build a cursor; honour sqlite3.Row request via psycopg's dict_row
        so callers using `row["col"]` access work cross-backend."""
        if self._row_factory is sqlite3.Row:
            try:
                from psycopg.rows import dict_row
                return self._conn.cursor(row_factory=dict_row)
            except Exception:
                # psycopg < 3 or import failure — fall back to tuple cursor.
                pass
        return self._conn.cursor()

    def execute(self, sql: str, params: Optional[Any] = None):
        """Return contract (L10): always returns a _PgCursorWrapper.
        Same as _PgCursorWrapper.execute() (which returns `self`) — both
        flow paths produce a fetchone/fetchall-able cursor object, so
        `conn.execute(...).fetchone()` and `conn.cursor().execute(...)
        .fetchone()` are interchangeable."""
        cur = self._make_cursor()
        sql_pg = _rewrite_placeholders(sql)
        if params is None:
            cur.execute(sql_pg)
        else:
            cur.execute(sql_pg, params)
        return _PgCursorWrapper(cur)

    def executemany(self, sql: str, seq_of_params):
        """Same return contract as execute() — see L10 note above."""
        cur = self._make_cursor()
        sql_pg = _rewrite_placeholders(sql)
        cur.executemany(sql_pg, seq_of_params)
        return _PgCursorWrapper(cur)

    def cursor(self):
        # M1 fix: wrap the psycopg cursor so callers that bypass
        # conn.execute() and go straight to cursor().execute() get the
        # same `?` → `%s` translation. Previously this returned the raw
        # psycopg cursor and callers using `?` placeholders silently
        # failed on PG.
        return _PgCursorWrapper(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        # H2 fix: commit() failures MUST propagate (constraint violation,
        # connection drop mid-tx, deferred trigger raising). Swallowing
        # them means callers get a clean exit and assume the data is
        # persisted when it isn't — silent data loss. rollback() failures
        # are still swallowed because the caller is already on the
        # exception path; close() failures are also swallowed because
        # they don't affect whether the data committed.
        try:
            if exc_type is None:
                self.commit()
            else:
                try:
                    self.rollback()
                except Exception:
                    pass  # nosec B110 — already on exception path
        finally:
            try:
                self.close()
            except Exception:
                pass  # nosec B110


class PgUnavailableError(RuntimeError):
    """Raised by open_conn / conn() when POSTGRES_DSN is configured but
    Postgres can't be reached. Replaces the previous silent SQLite
    fallback, which broke the single-DB contract by quietly writing to
    a stale local file. Callers must propagate or handle this — the
    request should fail loudly so the orchestrator restarts the gateway.

    The boot guard in proxy.py catches this case at startup; this
    exception is the runtime safety net for the rare case where PG
    becomes unreachable AFTER successful boot (e.g. transient outage).
    """


def open_conn(timeout: float = 10) -> Any:
    """Backend-aware connection opener (NON-context-manager).

    Returns either a sqlite3.Connection or a _PgConnWrapper. The caller is
    responsible for `.close()`. This matches the legacy pattern in code
    that pre-dates the migration; new code should prefer `conn()`.

    Raises `PgUnavailableError` if POSTGRES_DSN is set but psycopg isn't
    importable. Never silently degrades to SQLite when PG is configured.
    """
    backend = active_backend()
    if backend == "postgres":
        from config import POSTGRES_DSN
        try:
            from db.postgres import _postgres_load_module
        except ImportError as e:
            raise PgUnavailableError(
                f"POSTGRES_DSN set but db.postgres unimportable: {e}"
            ) from e
        pg = _postgres_load_module()
        if pg is None:
            raise PgUnavailableError(
                "POSTGRES_DSN set but psycopg failed to load — refusing "
                "to silently fall back to SQLite (single-DB contract)"
            )
        if not POSTGRES_DSN:
            # 1.9.0 (F5) — DSN was cleared between active_backend() and now.
            # The previous behaviour silently downgraded to SQLite — that
            # violates the documented single-DB contract ("never silently
            # degrades to SQLite when PG is configured") and creates a
            # split-brain write window during db_switch_endpoint. Fail loud
            # so the orchestrator handles the transient state cleanly.
            raise PgUnavailableError(
                "POSTGRES_DSN cleared between active_backend() and connect — "
                "refusing silent SQLite downgrade (single-DB contract)"
            )
        pg_conn = pg.connect(POSTGRES_DSN, connect_timeout=int(timeout))
        return _PgConnWrapper(pg_conn)
    from config import DB_PATH
    return sqlite3.connect(DB_PATH, timeout=timeout)


@contextmanager
def conn(timeout: float = 10) -> Iterator[Any]:
    """Backend-aware connection context manager.

    Yields a sqlite3.Connection when SQLite is the active backend, or a
    _PgConnWrapper (sqlite3.Connection-compatible) when Postgres is active.

    Callers should write queries using `?` placeholders — the wrapper
    rewrites to `%s` on PG. SELECT / UPDATE / DELETE / parameterised
    INSERT all work cross-backend without changes.

    1.9.0 (F3) — COMMITS ON CLEAN EXIT. The previous version only `close()`d
    the connection, which silently dropped uncommitted writes on both
    backends. Now: clean exit → commit; exception → rollback; always close.
    Matches the `with sqlite3.connect(...) as c:` semantics callers expect.
    Use `sqlite3.Connection.commit()` directly inside the block only if you
    need an early flush — the final commit on exit is a no-op when there's
    nothing pending.

    Raises `PgUnavailableError` if POSTGRES_DSN is set but psycopg isn't
    importable (same contract as open_conn). Also raises on the cleared-DSN
    race rather than silently degrading to SQLite.
    """
    backend = active_backend()
    if backend == "postgres":
        from config import POSTGRES_DSN
        try:
            from db.postgres import _postgres_load_module
        except ImportError as e:
            raise PgUnavailableError(
                f"POSTGRES_DSN set but db.postgres unimportable: {e}"
            ) from e
        pg = _postgres_load_module()
        if pg is None:
            raise PgUnavailableError(
                "POSTGRES_DSN set but psycopg failed to load — refusing "
                "to silently fall back to SQLite (single-DB contract)"
            )
        if not POSTGRES_DSN:
            # 1.9.0 (F5 parity) — race-window: DSN cleared between
            # active_backend() and the read here. Fail loud (same contract
            # as open_conn) so the caller doesn't get silent split-brain.
            raise PgUnavailableError(
                "POSTGRES_DSN cleared between active_backend() and connect — "
                "refusing silent SQLite downgrade (single-DB contract)"
            )
        pg_conn = pg.connect(POSTGRES_DSN, connect_timeout=int(timeout))
        wrapped = _PgConnWrapper(pg_conn)
        try:
            yield wrapped
            wrapped.commit()
        except Exception:
            try:
                wrapped.rollback()
            except Exception:
                pass  # nosec B110 — best-effort rollback; close still runs
            raise
        finally:
            wrapped.close()
    else:
        from config import DB_PATH
        c = sqlite3.connect(DB_PATH, timeout=timeout)
        try:
            yield c
            c.commit()
        except Exception:
            try:
                c.rollback()
            except Exception:
                pass  # nosec B110
            raise
        finally:
            c.close()
