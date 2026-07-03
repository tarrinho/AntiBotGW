"""
tests/test_v195_svc_rehydrate_backend_aware.py — guard the 1.9.5 fix that
makes the service-metrics buffer rehydration backend-aware.

THE BUG (reported in production): selecting a 7-day window on the Service
page showed only ~1 day of data, even though Postgres held 9 days.

ROOT CAUSE: `db_load_state()` in db/sqlite.py rehydrated
`SERVICE_METRICS_HISTORY` from the **local SQLite file** via the function's
hard-coded `conn = _sqlite_connect(DB_PATH)`. In PG-only mode the db-writer
mirrors `svc_metric` rows to Postgres and never touches local SQLite, so
the local table is frozen at the pre-cutover state. Rehydrating from it
loaded STALE samples whose old timestamps made the in-memory deque's
oldest entry look weeks old. That fooled
`service_metrics_data_endpoint`'s `start_b < _buf_oldest` heuristic into
taking the in-memory path (stale gap + most-recent live samples) instead
of the DB path (full history in PG) — so long windows rendered ~1 day.

THE FIX: rehydrate through `open_conn()` (backend-aware) so PG-only
deployments load a CONTIGUOUS recent buffer from Postgres, and the
endpoint heuristic stays sound.

These are source-level guards (the functional path needs a live PG, which
CI doesn't have). They anchor the contract so a future refactor can't
silently revert to the local-SQLite read.
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
SQLITE_PY = os.path.join(_REPO, "db", "sqlite.py")


def _db_load_state_src() -> str:
    """Return the source of db_load_state()."""
    src = open(SQLITE_PY, encoding="utf-8").read()
    i = src.find("def db_load_state(")
    assert i != -1, "db_load_state must exist in db/sqlite.py"
    # End at the next top-level `def ` (column-0).
    m = re.search(r"\ndef ", src[i + 1:])
    end = (i + 1 + m.start()) if m else len(src)
    return src[i:end]


def _svc_rehydrate_block() -> str:
    """Return just the svc_metrics rehydration region of db_load_state.

    Anchored on the `SERVICE_METRICS_HISTORY.clear()` line (start of the
    rehydrate) — NOT the docstring's mention of the deque — through the end
    of the function, so the whole try/except/finally is captured."""
    block = _db_load_state_src()
    i = block.find("SERVICE_METRICS_HISTORY.clear()")
    if i == -1:
        # Fall back to the rehydrate comment so a refactor that drops the
        # clear() still yields a meaningful (failing) slice.
        i = block.find("Re-hydrate the service-metrics history")
    assert i != -1, (
        "db_load_state must contain the svc_metrics rehydration block "
        "(SERVICE_METRICS_HISTORY.clear() or its lead comment)"
    )
    return block[i:]


# ── The core fix ─────────────────────────────────────────────────────────

def test_svc_rehydrate_uses_open_conn_not_local_sqlite():
    """The svc_metrics rehydration must read through open_conn() (the
    backend-aware helper), NOT the function-level `conn` (which is a
    hard-coded local SQLite connection)."""
    block = _svc_rehydrate_block()
    assert "open_conn" in block, (
        "svc_metrics rehydration must import/use open_conn() so PG-only "
        "deployments rehydrate from Postgres, not the stale local SQLite file"
    )


def test_svc_rehydrate_does_not_use_bare_conn_execute():
    """Specifically: the svc_metrics SELECT must NOT run on the raw
    function-level `conn` (the local SQLite connection). It must run on a
    dedicated backend-aware connection."""
    block = _svc_rehydrate_block()
    # The SELECT must be issued on a NON-`conn` connection variable. The fix
    # uses `_svc_conn`. Guard that the svc SELECT is bound to the
    # open_conn() connection, not `conn.execute`.
    # Find the svc_metrics SELECT line.
    m = re.search(r'(\w+)\.execute\(\s*\n?\s*"SELECT \* FROM svc_metrics',
                  block)
    assert m, "svc_metrics SELECT statement not found in rehydrate block"
    conn_var = m.group(1)
    assert conn_var != "conn", (
        "svc_metrics SELECT must NOT use the function-level `conn` (local "
        f"SQLite). Found `{conn_var}.execute` — must be the open_conn() "
        "connection (e.g. _svc_conn)"
    )


def test_svc_rehydrate_closes_its_connection():
    """The dedicated svc connection must be closed (returned to the pool in
    PG mode) — a leaked pooled connection per boot would exhaust the pool
    across restarts in a crash-loop."""
    block = _svc_rehydrate_block()
    # The open_conn() connection must be closed in a finally.
    assert "finally:" in block and ".close()" in block, (
        "svc rehydrate must close its open_conn() connection in a finally "
        "block"
    )


def test_svc_rehydrate_clears_buffer_first():
    """Repeated on_startup() calls (tests + restarts) must not accumulate —
    the deque is cleared before rehydration so stale entries from a prior
    invocation never linger."""
    block = _svc_rehydrate_block()
    assert "SERVICE_METRICS_HISTORY.clear()" in block, (
        "svc rehydrate must SERVICE_METRICS_HISTORY.clear() before loading "
        "so repeated on_startup() calls don't accumulate stale samples"
    )


def test_svc_rehydrate_still_bounded_by_retention():
    """The LIMIT must still cap at SERVICE_METRICS_RETENTION so a huge PG
    table doesn't load millions of rows into memory at boot."""
    block = _svc_rehydrate_block()
    assert re.search(r"LIMIT \?", block) and "SERVICE_METRICS_RETENTION" in block, (
        "svc rehydrate must keep `LIMIT ?` bound to SERVICE_METRICS_RETENTION"
    )


def test_svc_rehydrate_error_is_swallowed():
    """A rehydrate failure (table missing on first boot, PG briefly
    unreachable) must NOT crash startup — it's a warm-cache nicety, the
    endpoint's DB path serves history regardless."""
    block = _svc_rehydrate_block()
    assert "except Exception" in block, (
        "svc rehydrate must catch Exception so a transient DB error at boot "
        "doesn't crash the gateway (the endpoint DB path covers the gap)"
    )
    assert "db_svc_metrics_not_loaded" in block, (
        "svc rehydrate failure must emit the db_svc_metrics_not_loaded "
        "diagnostic slog"
    )


# ── Defence: every other state read in db_load_state already has a
#    backend-aware sibling; this guards that svc_metrics joined them. ─────

def test_no_inline_svc_select_on_function_conn_anywhere():
    """Belt + braces across the WHOLE function: there must be no
    `conn.execute("...svc_metrics...")` on the local-SQLite `conn`. (Other
    tables — clients/timeline/events — are overwritten by dedicated
    backend-aware rehydrate functions; svc_metrics had no such sibling, so
    its read had to move off `conn`.)"""
    src = _db_load_state_src()
    assert not re.search(r'\bconn\.execute\([^)]*svc_metrics', src, re.DOTALL), (
        "db_load_state must not SELECT svc_metrics on the local-SQLite "
        "`conn` — use the backend-aware open_conn() connection"
    )
