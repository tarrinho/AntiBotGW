"""
1.9.7 — DB_BACKEND is authoritative over POSTGRES_DSN presence
=============================================================

Bug: with `POSTGRES_DSN` set, config.py forced `DB_BACKEND="postgres"` and
ignored an explicit `DB_BACKEND=sqlite`. Worse, the READ path
(`active_backend()`/`open_conn()`) keyed on POSTGRES_DSN while the WRITER keyed
on DB_BACKEND — so a configured-but-unwanted DSN split reads→PG / writes→SQLite,
ran synchronous psycopg calls on the event loop, and stalled `/live` under load
(armv7 production → 502).

Fix (config.py): DB_BACKEND wins when explicit. `DB_BACKEND=sqlite` deactivates
the DSN so every DSN-keyed path (reads, writer, mirror) stays on SQLite. The DSN
stays in the env for a later flip to PG.

Matrix:
  DB_BACKEND=sqlite   + DSN     → sqlite   (DSN deactivated)
  DB_BACKEND=postgres + DSN     → postgres
  DB_BACKEND=unset    + DSN     → postgres (back-compat: DSN implies PG)
  DB_BACKEND=sqlite   + no DSN  → sqlite
  DB_BACKEND=postgres + no DSN  → sqlite   (invalid: PG needs a DSN)

Run in fresh interpreters because the reconciliation happens at config import.
"""
import os
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_DSN = "postgresql://u:p@db:5432/x"

_SNIPPET = (
    "import config, db.conn as c;"
    "print(config.DB_BACKEND, '1' if config.POSTGRES_DSN else '0', c.active_backend())"
)


def _resolve(db_backend, dsn):
    """Import config in a clean interpreter with the given env; return
    (DB_BACKEND, dsn_active('0'/'1'), active_backend())."""
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", "/tmp"),
           "UPSTREAM": "https://example.com"}
    if db_backend is not None:
        env["DB_BACKEND"] = db_backend
    if dsn is not None:
        env["POSTGRES_DSN"] = dsn
    r = subprocess.run([sys.executable, "-c", _SNIPPET], cwd=str(_REPO),
                       env=env, capture_output=True, text=True)
    assert r.returncode == 0, f"config import failed: {r.stderr[-500:]}"
    # config import emits `[db] ...` startup lines to stdout — our 3-token
    # result is the LAST line.
    return r.stdout.strip().splitlines()[-1].split()


def test_sqlite_pin_deactivates_dsn():
    """The explicit-sqlite-plus-DSN case: explicit sqlite + DSN → SQLite everywhere, DSN off."""
    backend, dsn_active, active = _resolve("sqlite", _DSN)
    assert backend == "sqlite", backend
    assert dsn_active == "0", "DSN must be deactivated so no path routes to PG"
    assert active == "sqlite", "reads must also resolve to sqlite (no split-brain)"


def test_postgres_explicit_with_dsn():
    backend, dsn_active, active = _resolve("postgres", _DSN)
    assert (backend, dsn_active, active) == ("postgres", "1", "postgres")


def test_dsn_only_defaults_to_postgres():
    """Back-compat: a DSN with no DB_BACKEND still selects Postgres."""
    backend, dsn_active, active = _resolve(None, _DSN)
    assert (backend, dsn_active, active) == ("postgres", "1", "postgres")


def test_sqlite_no_dsn():
    backend, dsn_active, active = _resolve("sqlite", None)
    assert (backend, dsn_active, active) == ("sqlite", "0", "sqlite")


def test_postgres_without_dsn_is_invalid_falls_back():
    backend, _dsn_active, active = _resolve("postgres", None)
    assert backend == "sqlite" and active == "sqlite", "PG needs a DSN → fall back to sqlite"


def test_reads_and_writes_agree_in_every_case():
    """The core invariant: active_backend() (reads) must match the DB_BACKEND
    the writer loop branches on — they can never diverge again."""
    for be, dsn in [("sqlite", _DSN), ("postgres", _DSN), (None, _DSN),
                    ("sqlite", None), ("postgres", None)]:
        backend, _da, active = _resolve(be, dsn)
        assert active == backend, f"read/write split for DB_BACKEND={be} dsn={bool(dsn)}: {active} != {backend}"


def test_source_anchor_sqlite_pin_branch():
    src = (_REPO / "config.py").read_text(encoding="utf-8")
    assert '_legacy_db_backend == "sqlite" and POSTGRES_DSN' in src, \
        "config.py must short-circuit to SQLite when DB_BACKEND=sqlite is explicit + DSN present"
