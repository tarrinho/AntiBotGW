"""
1.9.1 iter-7 — code-review follow-up fixes.

Functional review surfaced two issues missed by the iter-4-6 source-
inspection tests:

  HIGH  — 1.8.x → 1.9.x upgrade lost POSTGRES_DSN
          1.8.x stored POSTGRES_DSN as plaintext in config_kv. F14
          (1.9.0 iter-4) moved it to secrets_kv + Fernet. But
          `db_load_config` is now SECRET-AWARE: any `_SECRET_KEYS` row
          in config_kv is SKIPPED with a `config_kv_stomp_blocked`
          warn. An operator upgrading 1.8.x → 1.9.x with the DSN in
          config_kv silently lost their PG configuration because
          `db_load_secrets` had nothing to load and `db_load_config`
          refused to apply the legacy row.

          Fix: one-shot lift in `db_load_secrets` — if secrets_kv has
          no POSTGRES_DSN row AND config_kv has one (legacy plaintext),
          encrypt + write to secrets_kv, then DELETE the legacy
          config_kv row. Logs `legacy_dsn_lifted` (level=warn) so the
          operator sees the migration.

  MED   — direct sqlite writes used bare `sqlite3.connect()` not
          `_sqlite_connect()`. Inherited the existing journal_mode
          (WAL if already set) but missed the synchronous=NORMAL +
          wal_autocheckpoint + temp_store=MEMORY + mmap_size=256MB
          pragma tuning. Risk: lower throughput on the path that runs
          right before `os._exit(0)` (where every ms of fsync delay
          increases the chance of the queue not flushing).

          Fix: switch all four iter-5 B3/B4/B5/B6 direct-write sites
          to `_sqlite_connect()`.
"""
import pathlib


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_DBSQ_SRC = (_ROOT / "db" / "sqlite.py").read_text(encoding="utf-8")
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_PROXY    = (_ROOT / "proxy.py").read_text(encoding="utf-8")


# HIGH — 1.8.x → 1.9.x legacy DSN lift

def test_iter7_legacy_dsn_lift_present_in_db_load_secrets():
    """db_load_secrets must contain a one-shot migration that lifts a
    1.8.x-era plaintext POSTGRES_DSN out of config_kv into secrets_kv
    (encrypted) on first 1.9.x boot. Without this, every operator
    upgrading from 1.8.x loses their persisted DSN."""
    idx = _DBSQ_SRC.find("def db_load_secrets")
    assert idx > 0, "db_load_secrets not found"
    # Slice the function body (rough — until next def)
    end = _DBSQ_SRC.find("\ndef ", idx + 1)
    body = _DBSQ_SRC[idx:end if end > 0 else len(_DBSQ_SRC)]
    assert "legacy_dsn_lifted" in body, (
        "db_load_secrets must emit a `legacy_dsn_lifted` slog when "
        "the 1.8.x → 1.9.x DSN migration fires — otherwise the lift "
        "is invisible to ops"
    )
    assert "_dsn_encrypt" in body and "secrets_kv" in body, (
        "lift must encrypt the legacy plaintext DSN via _dsn_encrypt "
        "before writing to secrets_kv"
    )
    assert "DELETE FROM config_kv" in body, (
        "lift must DELETE the legacy config_kv row after the move so "
        "the config_kv_stomp_blocked warn stops firing on subsequent "
        "boots"
    )


def test_iter7_legacy_dsn_lift_gated_on_no_existing_secret():
    """The lift must be guarded so it doesn't overwrite a freshly-set
    DSN in secrets_kv. Idempotent — secrets_kv POSTGRES_DSN present →
    no-op."""
    idx = _DBSQ_SRC.find("def db_load_secrets")
    end = _DBSQ_SRC.find("\ndef ", idx + 1)
    body = _DBSQ_SRC[idx:end if end > 0 else len(_DBSQ_SRC)]
    # Must check `SELECT 1 FROM secrets_kv WHERE key = 'POSTGRES_DSN'`
    # BEFORE doing the migration
    assert "SELECT 1 FROM secrets_kv WHERE key = 'POSTGRES_DSN'" in body \
        or "SELECT 1 FROM secrets_kv\n            WHERE key = 'POSTGRES_DSN'" in body, (
        "lift must short-circuit when secrets_kv already has a "
        "POSTGRES_DSN row"
    )


def test_iter7_legacy_dsn_lift_handles_json_quoted_value():
    """db_load_config persisted config_kv values as `json.dumps(str)`
    (so a string value is quoted as `\"…\"`). The lift must
    json.loads() before re-encrypting; raw plaintext also accepted as
    a fallback. Otherwise the encrypted ciphertext would decrypt to
    `"…"` (with the literal quotes), and pg.connect() would fail."""
    idx = _DBSQ_SRC.find("def db_load_secrets")
    end = _DBSQ_SRC.find("\ndef ", idx + 1)
    body = _DBSQ_SRC[idx:end if end > 0 else len(_DBSQ_SRC)]
    assert "json.loads" in body or "_json_mig.loads" in body, (
        "lift must call json.loads() on the legacy config_kv value to "
        "strip the json.dumps() quoting that 1.8.x applied"
    )


# MED — direct sqlite writes via _sqlite_connect

def test_iter7_b3_marker_read_uses_sqlite_connect():
    """proxy._resume_pending_bg_migration's marker read (iter-5 B3)
    must use _sqlite_connect() so it inherits WAL + tuned pragmas."""
    idx = _PROXY.find("async def _resume_pending_bg_migration")
    end = _PROXY.find("\nasync def ", idx + 1)
    body = _PROXY[idx:end if end > 0 else len(_PROXY)]
    assert "_sqlite_connect" in body, (
        "B3 marker read must use _sqlite_connect() (not bare "
        "sqlite3.connect) for WAL inheritance"
    )


def test_iter7_b4_marker_clear_uses_sqlite_connect():
    """proxy._resume_pending_bg_migration's marker clear (iter-5 B4)
    must also use _sqlite_connect()."""
    idx = _PROXY.find("_runner")
    if idx == -1:
        idx = _PROXY.find("async def _resume_pending_bg_migration")
    end = _PROXY.find("\n\n", idx + 200)
    body = _PROXY[idx:end if end > 0 else idx + 3000]
    # The _runner finally block does the DELETE — must reference
    # _sqlite_connect either by name or via import.
    assert "_sqlite_connect" in body, (
        "B4 marker clear must use _sqlite_connect()"
    )


def test_iter7_b5_db_backend_persist_uses_sqlite_connect():
    """db_switch_endpoint's direct DB_BACKEND write (iter-5 B5) must
    use _sqlite_connect() for WAL + tuned-pragma parity."""
    idx = _PH_SRC.find("def db_switch_endpoint")
    end = _PH_SRC.find("\nasync def ", idx + 1)
    body = _PH_SRC[idx:end if end > 0 else len(_PH_SRC)]
    assert "_sqlite_connect" in body, (
        "B5 DB_BACKEND persist must use _sqlite_connect()"
    )


def test_iter7_b6_marker_write_uses_sqlite_connect():
    """db_switch_endpoint's direct F12 marker write (iter-5 B6) must
    also use _sqlite_connect(). Both writes appear in the same
    function body so the same check covers them — assert the import
    of _sqlite_connect is present at least once."""
    idx = _PH_SRC.find("def db_switch_endpoint")
    end = _PH_SRC.find("\nasync def ", idx + 1)
    body = _PH_SRC[idx:end if end > 0 else len(_PH_SRC)]
    # Two distinct writes inside db_switch_endpoint: marker + DB_BACKEND.
    # Both should land via _sqlite_connect(). Count distinct usages:
    n = body.count("_sqlite_connect")
    assert n >= 2, (
        f"B5+B6 expect 2 distinct _sqlite_connect calls in "
        f"db_switch_endpoint (marker + DB_BACKEND), found {n}"
    )


def test_iter7_no_bare_sqlite_connect_in_iter5_blocks():
    """Regression guard: no `sqlite3.connect(DB_PATH` (bare form) in
    the iter-5 direct-write blocks. A future refactor that reverts to
    bare sqlite3 would silently lose WAL/pragma tuning."""
    # Inside _resume_pending_bg_migration in proxy.py
    idx = _PROXY.find("async def _resume_pending_bg_migration")
    end = _PROXY.find("\nasync def ", idx + 1)
    body = _PROXY[idx:end if end > 0 else len(_PROXY)]
    assert "sqlite3.connect(_DB_PATH_LOCAL" not in body, (
        "iter-7 reverted: bare sqlite3.connect in _resume_pending_bg_migration"
    )
    # Inside db_switch_endpoint in core/proxy_handler.py
    idx = _PH_SRC.find("def db_switch_endpoint")
    end = _PH_SRC.find("\nasync def ", idx + 1)
    body = _PH_SRC[idx:end if end > 0 else len(_PH_SRC)]
    assert "sqlite3.connect(DB_PATH, timeout=5)" not in body, (
        "iter-7 reverted: bare sqlite3.connect(DB_PATH) in db_switch_endpoint"
    )
