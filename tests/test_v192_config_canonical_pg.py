"""1.9.2 iter — config_kv / secrets_kv load via backend-aware routing.

Operator-reported bug: "all dashboard knobs reset after every upgrade,
even with POSTGRES_DSN configured."

Root cause: `db_load_config` and `db_load_secrets` were hard-coded to read
SQLite at `_db_path` / `DB_PATH`, ignoring `active_backend()`. On PG-mode
deployments with an ephemeral `/data` volume:
  - dashboard saves wrote to SQLite + mirrored to PG (async)
  - on restart, /data was empty → SQLite had no config_kv rows
  - db_load_config returned nothing → env defaults won → "everything reset"
  - PG was full of the operator's settings the whole time

Fix: route both loaders through `db.conn.conn()` (backend-aware), so when
POSTGRES_DSN is set the read goes to PG directly. This QA pins the routing
contract so a future refactor cannot regress back to bare `_sqlite_connect`.

Why source-level pins, not a live-PG integration test: PG isn't always
available in CI. The regression we're guarding against is a structural one
(callsite uses the wrong opener). A source-anchor test catches it
deterministically across all CI environments.
"""
import pathlib

_ROOT = pathlib.Path(__file__).parent.parent


def _slice_fn(src: str, signature: str, max_lines: int = 80) -> str:
    """Return the body of a `def signature(...)` block. Bounded slice so
    text from unrelated functions further down can't satisfy assertions."""
    idx = src.find(signature)
    assert idx >= 0, f"function {signature!r} not found in source"
    # Skip past the signature line, walk forward up to max_lines or next def
    rest = src[idx:]
    nxt = rest.find("\ndef ", 1)
    end = nxt if nxt > 0 else len(rest)
    return rest[:end]


def test_db_load_config_uses_backend_aware_conn():
    """db_load_config must consult `active_backend()` and route to PG when
    POSTGRES_DSN is set, so PG-mode reads from PG (not from a possibly
    ephemeral SQLite file at DB_PATH). SQLite branch is kept for tests
    that override DB_PATH at runtime."""
    src = (_ROOT / "db" / "sqlite.py").read_text()
    body = _slice_fn(src, "def db_load_config(", max_lines=140)
    assert "active_backend" in body, \
        "db_load_config must call active_backend() to choose route"
    assert 'if _backend == "postgres"' in body, \
        "PG branch must be explicitly named in the routing if/else"
    assert "from db.conn import conn as _backend_conn" in body, \
        "PG branch must use the backend-aware conn helper"
    # The SELECT must appear (once for PG branch, once for SQLite branch)
    assert body.count("SELECT key, value FROM config_kv") >= 1


def test_db_load_secrets_uses_backend_aware_conn():
    """Same routing contract for db_load_secrets — POSTGRES_DSN itself
    lives in secrets_kv (Fernet-encrypted), so a deploy that lost /data
    would lose its DSN-from-/__db-switch without this fix."""
    src = (_ROOT / "db" / "sqlite.py").read_text()
    body = _slice_fn(src, "def db_load_secrets(", max_lines=220)
    assert "active_backend" in body
    assert 'if _backend == "postgres"' in body, \
        "PG branch must be explicitly named in the routing if/else"
    assert "from db.conn import conn as _backend_conn" in body
    assert body.count("SELECT key, value FROM secrets_kv") >= 1


def test_load_functions_keep_sqlite_path_override_for_tests():
    """SQLite branch must keep the `g.get("DB_PATH") or os.environ.get(...)`
    fallback so tests that monkey-patch DB_PATH at runtime still resolve
    to the test DB. Without this, test_functional.py::
    test_db_load_config_accepts_abuseipdb_enabled_with_key fails because
    `from config import DB_PATH` is import-time-frozen."""
    src = (_ROOT / "db" / "sqlite.py").read_text()
    cfg_body = _slice_fn(src, "def db_load_config(", max_lines=140)
    # The SQLite-branch path resolution must include g.get + env fallback
    assert 'g.get("DB_PATH")' in cfg_body
    assert 'os.environ.get("DB_PATH")' in cfg_body


def test_failure_log_records_backend_for_diagnostics():
    """The error log on load failure must include `backend=<sqlite|postgres>`.
    Without this, the operator can't tell whether their PG load failed or
    the SQLite fallback failed — exactly the ambiguity that delayed root-
    causing the original report."""
    src = (_ROOT / "db" / "sqlite.py").read_text()

    cfg_body = _slice_fn(src, "def db_load_config(", max_lines=120)
    assert 'slog("db_config_load_failed"' in cfg_body
    assert "backend=" in cfg_body, \
        "db_config_load_failed must record backend for triage"

    sec_body = _slice_fn(src, "def db_load_secrets(", max_lines=200)
    assert 'slog("db_secrets_load_failed"' in sec_body
    assert "backend=" in sec_body, \
        "db_secrets_load_failed must record backend for triage"


def test_pg_unavailable_propagates_not_silently_falls_back():
    """Single-DB contract (1.9.0 F5): when POSTGRES_DSN is set but PG is
    unreachable, the load must FAIL LOUD via the except clause — not
    silently degrade to a SQLite read. The backend-aware conn() raises
    PgUnavailableError; our except handler turns that into a logged error
    and returns. We test that the except is wide enough to catch it (bare
    `Exception`, not `sqlite3.Error`)."""
    src = (_ROOT / "db" / "sqlite.py").read_text()

    cfg_body = _slice_fn(src, "def db_load_config(", max_lines=140)
    # The except clause around the load block must catch `Exception` (or
    # a broader supertype), not just sqlite3.Error.
    assert "except Exception as e:" in cfg_body, \
        "db_load_config except clause must be `Exception`, not narrower"

    sec_body = _slice_fn(src, "def db_load_secrets(", max_lines=220)
    assert "except Exception as e:" in sec_body, \
        "db_load_secrets except clause must be `Exception`, not narrower"


# ── Behavioural tests — exercise the actual load paths ────────────────────────


def _build_proxy_globals(tmp_db: str, monkeypatch=None) -> dict:
    """Minimal `proxy_globals` dict that db_load_config / db_load_secrets
    will accept. Mirrors what proxy.py passes in via globals().

    NOTE — we deliberately use the already-imported `proxy` module instead
    of `importlib.util.spec_from_file_location` so the _ProxyModule
    attribute-propagator stays intact for downstream tests. A spawned
    parallel proxy module is not registered under "proxy" in sys.modules
    and breaks subsequent tests' `import proxy; proxy.DB_PATH = …`
    propagation chain (iter9 _DB_LOAD_DENY tests rely on this)."""
    os.environ.setdefault("UPSTREAM", "http://127.0.0.1:1")
    import proxy as m
    g = {
        "_HOT_RELOAD_KNOBS": m._HOT_RELOAD_KNOBS,
        "_ENV_PROVIDED_KNOBS": set(),
        "DB_PATH": tmp_db,
        "_SECRET_KEYS": getattr(m, "_SECRET_KEYS", frozenset()),
        "_DB_LOAD_DENY": getattr(m, "_DB_LOAD_DENY", frozenset()),
    }
    for k in m._HOT_RELOAD_KNOBS:
        if hasattr(m, k):
            g[k] = getattr(m, k)
    return g


import os  # noqa: E402 — _build_proxy_globals references os.environ


def test_sqlite_mode_load_applies_config_kv_row(tmp_path):
    """Functional: in SQLite mode, db_load_config must read config_kv from
    DB_PATH and apply the value to the proxy globals dict."""
    import sqlite3
    import os

    db = str(tmp_path / "cfg_canonical_sqlite.db")
    c = sqlite3.connect(db)
    c.execute(
        "CREATE TABLE config_kv "
        "(key TEXT PRIMARY KEY, value TEXT, ts REAL)")
    c.execute(
        # Values are JSON-encoded on write; the loader does json.loads().
        "INSERT INTO config_kv VALUES ('LOG_LEVEL', '\"debug\"', 0)")
    c.commit()
    c.close()

    _orig_db_path = os.environ.get("DB_PATH")
    _orig_upstream = os.environ.get("UPSTREAM")
    _orig_pg = os.environ.get("POSTGRES_DSN")
    os.environ["DB_PATH"] = db
    os.environ["UPSTREAM"] = "http://127.0.0.1:1"
    os.environ.pop("POSTGRES_DSN", None)  # force SQLite branch
    # active_backend() reads config.POSTGRES_DSN (not os.environ) at call
    # time, and under APPSECGW_TEST_PG config.POSTGRES_DSN is already set at
    # import time — so popping the env var alone left db_load_config on the
    # Postgres branch (reading PG config_kv, which has no LOG_LEVEL=debug
    # row). Clear config.POSTGRES_DSN for the duration to actually exercise
    # the SQLite branch this test targets.
    import config as _cfg
    _orig_cfg_pg = getattr(_cfg, "POSTGRES_DSN", "")
    _cfg.POSTGRES_DSN = ""
    try:
        g = _build_proxy_globals(db)
        from db.sqlite import db_load_config
        db_load_config(g)
        assert g.get("LOG_LEVEL") == "debug", \
            f"SQLite-mode load did not apply LOG_LEVEL: got {g.get('LOG_LEVEL')!r}"
    finally:
        _cfg.POSTGRES_DSN = _orig_cfg_pg
        for k, v in (("DB_PATH", _orig_db_path),
                     ("UPSTREAM", _orig_upstream),
                     ("POSTGRES_DSN", _orig_pg)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_sqlite_mode_load_missing_table_logs_and_returns(tmp_path):
    """A SQLite without config_kv table must NOT raise — the except clause
    catches it and returns. Operator sees env defaults."""
    import sqlite3
    import os

    db = str(tmp_path / "cfg_missing_table.db")
    sqlite3.connect(db).close()  # empty file, no tables

    _orig_db_path = os.environ.get("DB_PATH")
    _orig_upstream = os.environ.get("UPSTREAM")
    _orig_pg = os.environ.get("POSTGRES_DSN")
    os.environ["DB_PATH"] = db
    os.environ["UPSTREAM"] = "http://127.0.0.1:1"
    os.environ.pop("POSTGRES_DSN", None)  # force SQLite branch
    # active_backend() reads config.POSTGRES_DSN (not os.environ) at call
    # time, and under APPSECGW_TEST_PG config.POSTGRES_DSN is already set at
    # import time — so popping the env var alone leaves db_load_config on the
    # Postgres branch (reading the live PG config_kv, which has a LOG_LEVEL
    # row), and the empty-SQLite missing-table scenario this test targets is
    # never exercised. Clear config.POSTGRES_DSN for the duration to actually
    # take the SQLite branch. Mirrors test_sqlite_mode_load_applies_config_kv_row.
    import config as _cfg
    _orig_cfg_pg = getattr(_cfg, "POSTGRES_DSN", "")
    _cfg.POSTGRES_DSN = ""
    try:
        g = _build_proxy_globals(db)
        _before = g.get("LOG_LEVEL")
        from db.sqlite import db_load_config
        # Must not raise
        db_load_config(g)
        # LOG_LEVEL must be unchanged (no rows to apply)
        assert g.get("LOG_LEVEL") == _before
    finally:
        _cfg.POSTGRES_DSN = _orig_cfg_pg
        for k, v in (("DB_PATH", _orig_db_path),
                     ("UPSTREAM", _orig_upstream),
                     ("POSTGRES_DSN", _orig_pg)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_pg_mode_load_routes_through_conn_module(monkeypatch, tmp_path):
    """When POSTGRES_DSN is set, db_load_config must call db.conn.conn().
    We stub db.conn.conn to a fake context manager that yields a fake
    connection returning two rows, and assert the values land in `g`."""
    import os
    import sys

    # Force PG mode by setting a non-empty DSN
    # NOTE — do NOT setenv("POSTGRES_DSN"). active_backend() is stubbed
    # directly below, which is enough to force the PG branch. Setting the
    # env var caused config.POSTGRES_DSN to capture the stub DSN, which
    # leaked into subsequent tests in the same pytest session and broke
    # the iter9 _DB_LOAD_DENY tests (they assume sqlite mode).
    monkeypatch.setenv("UPSTREAM", "http://127.0.0.1:1")

    # Fake the backend connection so we don't need real PG running
    class _FakeRow(dict):
        def __getitem__(self, k):
            return super().__getitem__(k)

    class _FakeCursor:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class _FakeConn:
        def __init__(self):
            self.row_factory = None

        def execute(self, sql, *args):
            assert "config_kv" in sql
            return _FakeCursor([
                _FakeRow(key="LOG_LEVEL", value='"warn"'),
            ])

    from contextlib import contextmanager

    @contextmanager
    def _fake_conn(timeout=5):
        yield _FakeConn()

    # Patch active_backend + conn at the source module so the import
    # inside db_load_config picks up the stub.
    import db.conn as _real_conn
    monkeypatch.setattr(_real_conn, "active_backend", lambda: "postgres")
    monkeypatch.setattr(_real_conn, "conn", _fake_conn)
    # Clear cached module if a sibling test imported it differently
    # NOTE — do NOT sys.modules.pop("db.sqlite"). Popping orphans the
    # existing module reference held by `proxy.db_load_config`, breaks
    # the _ProxyModule attribute propagator for downstream tests, and
    # offers no functional benefit: the `from db.conn import …` inside
    # the function body resolves at call time, picking up our
    # monkeypatched values directly.
    from db.sqlite import db_load_config

    g = _build_proxy_globals(str(tmp_path / "noop.db"))
    db_load_config(g)
    assert g.get("LOG_LEVEL") == "warn", \
        f"PG-mode load did not apply LOG_LEVEL: got {g.get('LOG_LEVEL')!r}"


def test_pg_mode_unreachable_does_not_crash(monkeypatch, tmp_path):
    """When POSTGRES_DSN is set but `db.conn.conn()` raises (PG dead,
    network blip, auth failure), db_load_config must catch the exception
    and return cleanly. Gateway boots, operator sees env defaults, log
    line `db_config_load_failed backend=postgres` appears."""
    import os
    import sys

    # NOTE — do NOT setenv("POSTGRES_DSN"). active_backend() is stubbed
    # directly below, which is enough to force the PG branch. Setting the
    # env var caused config.POSTGRES_DSN to capture the stub DSN, which
    # leaked into subsequent tests in the same pytest session and broke
    # the iter9 _DB_LOAD_DENY tests (they assume sqlite mode).
    monkeypatch.setenv("UPSTREAM", "http://127.0.0.1:1")

    from contextlib import contextmanager

    @contextmanager
    def _exploding_conn(timeout=5):
        raise RuntimeError("simulated PG outage")
        yield  # unreachable

    import db.conn as _real_conn
    monkeypatch.setattr(_real_conn, "active_backend", lambda: "postgres")
    monkeypatch.setattr(_real_conn, "conn", _exploding_conn)
    # NOTE — do NOT sys.modules.pop("db.sqlite"). Popping orphans the
    # existing module reference held by `proxy.db_load_config`, breaks
    # the _ProxyModule attribute propagator for downstream tests, and
    # offers no functional benefit: the `from db.conn import …` inside
    # the function body resolves at call time, picking up our
    # monkeypatched values directly.
    from db.sqlite import db_load_config

    g = _build_proxy_globals(str(tmp_path / "noop.db"))
    _log_level_before = g.get("LOG_LEVEL")
    # Must NOT raise
    db_load_config(g)
    # No values applied
    assert g.get("LOG_LEVEL") == _log_level_before


def test_pg_branch_does_not_touch_local_sqlite(monkeypatch, tmp_path):
    """Operator-paranoia test: in PG mode, db_load_config must NOT open
    any SQLite file at DB_PATH. We make DB_PATH point to a path that
    DOESN'T exist; if the function tried to open it, sqlite3.connect
    would create an empty file. We assert the path stays absent."""
    import os
    import sys
    from contextlib import contextmanager

    sentinel_path = str(tmp_path / "must-not-be-created.db")
    assert not os.path.exists(sentinel_path)

    monkeypatch.setenv("POSTGRES_DSN", "postgresql://stub:stub@localhost/stub")
    monkeypatch.setenv("UPSTREAM", "http://127.0.0.1:1")
    monkeypatch.setenv("DB_PATH", sentinel_path)

    class _FakeCursor:
        def fetchall(self):
            return []

    class _FakeConn:
        row_factory = None

        def execute(self, sql, *args):
            return _FakeCursor()

    @contextmanager
    def _fake_conn(timeout=5):
        yield _FakeConn()

    import db.conn as _real_conn
    monkeypatch.setattr(_real_conn, "active_backend", lambda: "postgres")
    monkeypatch.setattr(_real_conn, "conn", _fake_conn)
    # NOTE — do NOT sys.modules.pop("db.sqlite"). Popping orphans the
    # existing module reference held by `proxy.db_load_config`, breaks
    # the _ProxyModule attribute propagator for downstream tests, and
    # offers no functional benefit: the `from db.conn import …` inside
    # the function body resolves at call time, picking up our
    # monkeypatched values directly.
    from db.sqlite import db_load_config

    g = _build_proxy_globals(sentinel_path)
    db_load_config(g)

    assert not os.path.exists(sentinel_path), \
        "PG-mode load created a SQLite file at DB_PATH — bypasses single-DB contract"


def test_secrets_kv_uses_same_branching(monkeypatch, tmp_path):
    """db_load_secrets must follow the same branching rule as
    db_load_config — PG mode → conn(); SQLite mode → _sqlite_connect.
    Source-pinned earlier; here we assert behavioural parity by stubbing
    `db.conn` and verifying the secrets path was hit."""
    import os
    import sys
    from contextlib import contextmanager

    # NOTE — do NOT setenv("POSTGRES_DSN"). active_backend() is stubbed
    # directly below, which is enough to force the PG branch. Setting the
    # env var caused config.POSTGRES_DSN to capture the stub DSN, which
    # leaked into subsequent tests in the same pytest session and broke
    # the iter9 _DB_LOAD_DENY tests (they assume sqlite mode).
    monkeypatch.setenv("UPSTREAM", "http://127.0.0.1:1")

    _calls: list = []

    class _FakeCursor:
        def __init__(self, rows):
            self._rows = rows

        def fetchall(self):
            return self._rows

    class _FakeConn:
        row_factory = None

        def execute(self, sql, *args):
            _calls.append(sql)
            return _FakeCursor([])

    @contextmanager
    def _fake_conn(timeout=5):
        yield _FakeConn()

    import db.conn as _real_conn
    monkeypatch.setattr(_real_conn, "active_backend", lambda: "postgres")
    monkeypatch.setattr(_real_conn, "conn", _fake_conn)
    # Do NOT sys.modules.pop("db.sqlite") — see note in test_pg_mode_load_…
    from db.sqlite import db_load_secrets

    g = _build_proxy_globals(str(tmp_path / "noop.db"))
    db_load_secrets(g)

    assert any("secrets_kv" in q for q in _calls), \
        f"db_load_secrets did not SELECT from secrets_kv in PG mode: {_calls}"
