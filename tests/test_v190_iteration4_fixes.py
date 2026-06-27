"""
1.9.0 same-version iteration 4 — 5 more secure-code-review findings:

  F11 — db_switch audit row records bg_scheduled, full_migrate_requested,
        and cutoff_ts (slog stream is in-memory; gw_audit is the only
        durable forensic anchor for the historical-events copy)
  F12 — historical migration deferred to post-restart on_startup hook;
        handler writes a `pending_bg_migration` config_kv marker, boot
        consumes it via _resume_pending_bg_migration (prevents the
        previous race where os._exit(0) interrupted the executor 1 s
        after scheduling)
  F13 — _role_denied / _require_csrf no longer echo caller role or
        required-roles list; response is `{"error":"forbidden"}` only,
        forensic detail goes to slog
  F14 — POSTGRES_DSN persisted in secrets_kv (never in /__config) and
        wrapped in Fernet keyed off SESSION_KEY (enc:v1: prefix);
        decrypt round-trip works; legacy plaintext keeps booting
  F15 — POSTGRES_DSN_ALLOWED_HOSTS operator-hardening callout in
        validation/1.9.0.md
"""
import importlib
import pathlib


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_PROXY    = (_ROOT / "proxy.py").read_text(encoding="utf-8")
_DBSQL    = (_ROOT / "db" / "sqlite.py").read_text(encoding="utf-8")
_AUTH     = (_ROOT / "admin" / "auth.py").read_text(encoding="utf-8")
_VALMD    = (_ROOT / "validation" / "1.9.0.md").read_text(encoding="utf-8")


# F11

def test_f11_audit_row_includes_bg_scheduled():
    assert '"bg_scheduled"' in _PH_SRC


def test_f11_audit_row_includes_full_migrate_requested():
    assert "full_migrate_requested" in _PH_SRC


def test_f11_audit_row_includes_cutoff_ts():
    assert "cutoff_ts" in _PH_SRC


# F12

def test_f12_handler_writes_pending_bg_migration_marker():
    assert "pending_bg_migration" in _PH_SRC
    assert "db_switch_bg_migrate_deferred" in _PH_SRC


def test_f12_handler_no_longer_calls_full_migrate_background_directly():
    assert "_resume_pending_bg_migration" in _PROXY
    bad = "run_in_executor(\n                    None, _full_migrate_background"
    assert bad not in _PH_SRC, \
        "db_switch_endpoint still schedules _full_migrate_background in-handler"


def test_f12_resume_hook_invoked_in_on_startup():
    assert "await _resume_pending_bg_migration()" in _PROXY


def test_f12_resume_helper_drops_stale_markers():
    assert "86_400" in _PROXY or "86400" in _PROXY


def test_f12_resume_helper_uses_single_flight_claim():
    assert "_try_claim_bg_migration" in _PROXY


def test_f12_resume_helper_clears_marker_after_run():
    idx = _PROXY.find("async def _resume_pending_bg_migration")
    assert idx >= 0, "_resume_pending_bg_migration helper missing"
    end = _PROXY.find("\nasync def ", idx + 1)
    body = _PROXY[idx:end if end > 0 else len(_PROXY)]
    assert "del_config" in body
    assert "pending_bg_migration" in body


# F13

def test_f13_role_denied_response_shape_is_forbidden_only():
    idx = _AUTH.find("def _role_denied")
    assert idx >= 0
    end = _AUTH.find("\ndef ", idx + 1)
    body = _AUTH[idx:end if end > 0 else len(_AUTH)]
    assert '{"error": "forbidden"}' in body or "{'error': 'forbidden'}" in body
    resp_idx = body.find("json_response")
    assert resp_idx >= 0
    payload_slice = body[resp_idx:resp_idx + 400]
    assert '"role":' not in payload_slice
    assert '"required":' not in payload_slice


def test_f13_role_denied_emits_slog_forensic_record():
    idx = _AUTH.find("def _role_denied")
    body = _AUTH[idx:idx + 1500]
    assert "slog(" in body and "role_denied" in body


def test_f13_require_csrf_response_shape_is_forbidden_only():
    idx = _AUTH.find("def _require_csrf")
    assert idx >= 0
    end = _AUTH.find("\ndef ", idx + 1)
    body = _AUTH[idx:end if end > 0 else len(_AUTH)]
    assert '"error": "forbidden"' in body or "'error': 'forbidden'" in body


# F14

def test_f14_dsn_encrypt_helper_defined():
    assert "def _dsn_encrypt(" in _DBSQL
    assert "def _dsn_decrypt(" in _DBSQL


def test_f14_dsn_encryption_uses_fernet():
    assert "from cryptography.fernet" in _DBSQL
    assert "Fernet" in _DBSQL


def test_f14_dsn_encryption_prefix_is_versioned():
    assert "_DSN_ENC_PREFIX" in _DBSQL
    assert '"enc:v1:"' in _DBSQL or "'enc:v1:'" in _DBSQL


def test_f14_dsn_fernet_key_is_domain_separated():
    assert "agw-dsn-fernet-v1" in _DBSQL


def test_f14_db_switch_persists_dsn_via_set_secret_not_set_config():
    idx = _PH_SRC.find("def db_switch_endpoint")
    end = _PH_SRC.find("\nasync def ", idx + 1)
    body = _PH_SRC[idx:end if end > 0 else len(_PH_SRC)]
    assert 'set_secret' in body
    assert "_dsn_encrypt" in body


def test_f14_secrets_endpoint_encrypts_dsn_on_persist():
    assert "_dsn_encrypt" in _PH_SRC


def test_f14_load_path_decrypts_postgres_dsn():
    idx = _DBSQL.find("def db_load_secrets")
    end = _DBSQL.find("\ndef ", idx + 1)
    body = _DBSQL[idx:end if end > 0 else len(_DBSQL)]
    assert "_dsn_decrypt" in body
    assert "POSTGRES_DSN" in body


def test_f14_dsn_encrypt_round_trip():
    import sys
    fake_proxy = sys.modules.setdefault("proxy", type(sys)("proxy"))
    fake_proxy.SESSION_KEY = b"\x42" * 32
    sql = importlib.import_module("db.sqlite")
    try:
        from cryptography.fernet import Fernet  # noqa: F401
    except ImportError:
        import pytest
        pytest.skip("cryptography not in test env")
    plain = "postgresql://user:secret@pg.internal:5432/agw"
    token = sql._dsn_encrypt(plain)
    assert token.startswith("enc:v1:"), f"expected prefix, got {token[:20]!r}"
    assert plain not in token, "plaintext must not appear in ciphertext"
    round_trip = sql._dsn_decrypt(token)
    assert round_trip == plain


def test_f14_legacy_plaintext_passes_through_decrypt():
    import sys
    fake_proxy = sys.modules.setdefault("proxy", type(sys)("proxy"))
    fake_proxy.SESSION_KEY = b"\x42" * 32
    sql = importlib.import_module("db.sqlite")
    legacy = "postgresql://u:p@h/d"
    assert sql._dsn_decrypt(legacy) == legacy


# F15

def test_f15_validation_doc_has_operator_hardening_callout():
    assert "POSTGRES_DSN_ALLOWED_HOSTS" in _VALMD
    assert "Operator hardening" in _VALMD


def test_f15_validation_doc_documents_default_behaviour():
    assert "When unset" in _VALMD


def test_f15_validation_doc_links_finding_to_mitigation():
    assert "F2" in _VALMD


# TC3 — unused-imports lint test (Sherlock catches the next M9-shaped
# regression at PR time, not at runtime). Targets db.export / db.import /
# db.cli_helpers — the three modules most touched in the F8/L8/M9 work.
# Pylint-style: parse the imports, then assert every imported name has
# at least one non-import reference in the rest of the file.

def _unused_imports(src: str) -> list:
    import ast as _ast
    tree = _ast.parse(src)
    imported = []  # list of (name, lineno) where name is the local binding
    for node in _ast.walk(tree):
        if isinstance(node, _ast.ImportFrom):
            for n in node.names:
                if n.name == "*":
                    continue  # star imports — can't statically check
                local = n.asname or n.name
                imported.append((local, node.lineno))
        elif isinstance(node, _ast.Import):
            for n in node.names:
                local = n.asname or n.name.split(".")[0]
                imported.append((local, node.lineno))
    # Build a set of every Name / Attribute root used outside imports
    used = set()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.Import, _ast.ImportFrom)):
            continue
        if isinstance(node, _ast.Name):
            used.add(node.id)
        elif isinstance(node, _ast.Attribute):
            # walk to the root Name
            cur = node
            while isinstance(cur, _ast.Attribute):
                cur = cur.value
            if isinstance(cur, _ast.Name):
                used.add(cur.id)
    return [(name, ln) for (name, ln) in imported if name not in used]


# Names allow-listed in the unused-imports check:
#   _mask_dsn            — shared F401 re-export from db.cli_helpers
#   annotations          — `from __future__ import annotations` is a
#                          compiler directive, never referenced by name
_TC3_ALLOWLIST = {"_mask_dsn", "annotations"}


def test_tc3_db_export_no_unused_imports():
    src = (_ROOT / "db" / "export.py").read_text(encoding="utf-8")
    unused = [(n, ln) for (n, ln) in _unused_imports(src)
              if n not in _TC3_ALLOWLIST]
    assert not unused, f"db/export.py has unused imports: {unused}"


def test_tc3_db_import_no_unused_imports():
    src = (_ROOT / "db" / "import.py").read_text(encoding="utf-8")
    unused = [(n, ln) for (n, ln) in _unused_imports(src)
              if n not in _TC3_ALLOWLIST]
    assert not unused, f"db/import.py has unused imports: {unused}"


def test_tc3_db_cli_helpers_no_unused_imports():
    src = (_ROOT / "db" / "cli_helpers.py").read_text(encoding="utf-8")
    unused = [(n, ln) for (n, ln) in _unused_imports(src)
              if n not in _TC3_ALLOWLIST]
    assert not unused, f"db/cli_helpers.py has unused imports: {unused}"


# A5 — pg_schema_versions read-back at boot

_DBPG = (_ROOT / "db" / "postgres.py").read_text(encoding="utf-8")


def test_a5_check_pg_schema_version_function_defined():
    assert "def check_pg_schema_version(" in _DBPG
    assert "def _read_pg_schema_version(" in _DBPG


def test_a5_check_is_read_only_no_mutation():
    """A5 must NOT mutate pg_schema_versions or any other table — the
    operator's PG state is read-only at this stage. Reject any
    INSERT/UPDATE/DELETE/CREATE/ALTER/DROP token inside either helper."""
    import re as _re
    idx_check = _DBPG.find("def check_pg_schema_version(")
    idx_read  = _DBPG.find("def _read_pg_schema_version(")
    # Slice each helper body up to next top-level def
    def _body(start):
        nxt = _DBPG.find("\ndef ", start + 1)
        return _DBPG[start:nxt if nxt > 0 else len(_DBPG)]
    for body in (_body(idx_check), _body(idx_read)):
        # Strip docstring + comments before scanning (they discuss the
        # banned ops by name — false positive risk).
        scrub = _re.sub(r'"""[\s\S]*?"""', "", body)
        scrub = _re.sub(r"#.*", "", scrub)
        for verb in ("INSERT", "UPDATE", "DELETE", "CREATE",
                     "ALTER ", "DROP "):
            assert verb not in scrub.upper(), (
                f"A5 helper must be read-only — found {verb!r} in body"
            )


def test_a5_select_max_version_used():
    assert "SELECT MAX(version) FROM pg_schema_versions" in _DBPG


def test_a5_proxy_invokes_check_before_init():
    """on_startup must call check_pg_schema_version BEFORE
    db_init_postgres so the read sees the previous version (the init
    re-stamps it). Order matters."""
    src = (_ROOT / "proxy.py").read_text(encoding="utf-8")
    i_check = src.find("check_pg_schema_version()")
    i_init  = src.find("db_init_postgres()")
    assert i_check > 0 and i_init > 0
    assert i_check < i_init, (
        "check_pg_schema_version() must run BEFORE db_init_postgres()"
    )


def test_a5_drift_exit_code_distinct():
    """Exit code 5 (schema drift) must not collide with the existing
    1.9.0 codes 2 (psycopg missing), 3 (PG unreachable), 4 (init failed)."""
    assert "_PG_SCHEMA_DRIFT_EXIT_CODE = 5" in _DBPG


def test_a5_status_dict_shape():
    """check_pg_schema_version returns a dict with the documented keys."""
    import db.postgres as _pgmod
    # Force the pool-missing fast-path (no PG required for this test).
    orig = _pgmod._get_pool
    _pgmod._get_pool = lambda: None
    try:
        sv = _pgmod.check_pg_schema_version()
    finally:
        _pgmod._get_pool = orig
    assert isinstance(sv, dict)
    for k in ("ok", "current", "expected", "diff", "msg",
              "should_exit", "exit_code", "severity"):
        assert k in sv, f"status dict missing key {k!r}"
    # Pool-missing path must be a no-op success.
    assert sv["ok"] is True
    assert sv["should_exit"] is False
    assert sv["current"] is None
    assert sv["expected"] == _pgmod.PG_SCHEMA_VERSION


def test_a5_decision_matrix_logic():
    """Exercise the decision matrix via a fake pool/conn that returns
    canned MAX(version) values. No real PG required."""
    import db.postgres as _pgmod
    expected = _pgmod.PG_SCHEMA_VERSION

    class _FakeCur:
        def __init__(self, v): self._v = v
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, *a, **kw): return None
        def fetchone(self):
            return (self._v,) if self._v is not None else None

    class _FakeConn:
        def __init__(self, v): self._v = v
        def cursor(self): return _FakeCur(self._v)

    class _FakePool:
        def __init__(self, v): self._v = v
        def connection(self, timeout=None):
            class _CM:
                def __init__(s, c): s._c = c
                def __enter__(s): return s._c
                def __exit__(s, *a): return False
            return _CM(_FakeConn(self._v))

    cases = [
        # (max_version, expected_ok, expected_should_exit, expected_severity)
        (None,         True,  False, "info"),   # fresh DB
        (expected,     True,  False, "info"),   # match
        (expected - 1, True,  False, "info"),   # +1 upgrade
        (expected + 1, True,  False, "warn"),   # -1 downgrade
        (expected - 2, False, True,  "error"),  # major upgrade skip
        (expected + 2, False, True,  "error"),  # major downgrade
    ]
    orig = _pgmod._get_pool
    try:
        for max_v, ok, should_exit, sev in cases:
            _pgmod._get_pool = lambda v=max_v: _FakePool(v)
            sv = _pgmod.check_pg_schema_version()
            assert sv["ok"] is ok, (max_v, sv)
            assert sv["should_exit"] is should_exit, (max_v, sv)
            assert sv["severity"] == sev, (max_v, sv)
            if should_exit:
                assert sv["exit_code"] == 5
    finally:
        _pgmod._get_pool = orig


# L10 — execute() return-shape contract

def test_l10_conn_and_cursor_execute_return_same_interface():
    """Both conn.execute() and cursor.execute() must return objects with
    the SAME callable surface: .fetchone, .fetchall, __iter__, .rowcount.
    Callers depend on this — the original L10 finding was that the two
    wrappers' return shapes had drifted, so a future change to either
    could break code targeting the other."""
    from db.conn import _PgCursorWrapper, _PgConnWrapper  # noqa: F401
    for attr in ("fetchone", "fetchall", "__iter__", "rowcount", "execute"):
        assert hasattr(_PgCursorWrapper, attr), \
            f"_PgCursorWrapper must expose {attr!r}"
    src = (_ROOT / "db" / "conn.py").read_text(encoding="utf-8")
    # conn.execute() returns _PgCursorWrapper(cur)
    assert "return _PgCursorWrapper(cur)" in src
    # cursor.execute() returns self (a _PgCursorWrapper)
    idx = src.find("class _PgCursorWrapper")
    end = src.find("class _PgConnWrapper", idx)
    cur_body = src[idx:end]
    assert "        return self\n" in cur_body
    assert "L10 return contract" in cur_body
    assert "L10" in src[end:]


# TC1 — caller-managed-transaction autocommit contract

def test_tc1_db_import_sets_autocommit_false_before_dispatch():
    src = (_ROOT / "db" / "import.py").read_text(encoding="utf-8")
    i_ac = src.find("_import_conn.autocommit = False")
    i_dispatch = src.find("def dispatch(op, args, _c=_import_conn)")
    assert i_ac > 0, "db.import must set _import_conn.autocommit = False"
    assert i_dispatch > 0, "db.import must define dispatch closure"
    assert i_ac < i_dispatch, (
        "_import_conn.autocommit = False MUST precede the dispatch "
        "closure that captures _import_conn"
    )


def test_tc1_pg_mirror_kv_rejects_autocommit_true_conn():
    """Defensive runtime check — passing _conn= with autocommit=True
    raises AssertionError at the dispatch boundary, NOT silent partial
    write."""
    from db.postgres import _pg_mirror_kv

    class _AutocommitTrueConn:
        autocommit = True

        def cursor(self):
            raise AssertionError(
                "cursor() should NEVER be called — the autocommit "
                "guard must fire first"
            )

    try:
        _pg_mirror_kv("set_config", ("k", "v", 0),
                      _conn=_AutocommitTrueConn())
    except AssertionError as e:
        assert "autocommit=True" in str(e)
        assert "_conn=" in str(e)
    else:
        raise AssertionError(
            "_pg_mirror_kv must reject autocommit=True _conn="
        )


def test_tc1_pg_mirror_kv_accepts_autocommit_false_conn():
    """Symmetric — autocommit=False reaches dispatch."""
    from db.postgres import _pg_mirror_kv

    class _Cur:
        executed = []
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, sql, params=None):
            _Cur.executed.append((sql, params))
            return None

    class _AutocommitFalseConn:
        autocommit = False
        def cursor(self):
            return _Cur()

    _Cur.executed = []
    ok = _pg_mirror_kv("set_config", ("k", "v", 123),
                      _conn=_AutocommitFalseConn())
    assert ok is True
    assert len(_Cur.executed) == 1
    sql, params = _Cur.executed[0]
    assert "INSERT INTO config_kv" in sql
    assert params == ("k", "v", 123)


def test_tc1_autocommit_contract_documented():
    """The autocommit contract must appear in the _pg_mirror_kv body
    (forces future maintainers to read it before changing the dispatch)."""
    src = (_ROOT / "db" / "postgres.py").read_text(encoding="utf-8")
    idx = src.find("def _pg_mirror_kv(")
    end = src.find("\ndef ", idx + 1)
    body = src[idx:end if end > 0 else len(src)]
    assert "autocommit" in body, (
        "_pg_mirror_kv must document the autocommit contract"
    )
    assert "TC1" in body


# A4 — dispatch ladder → registry pattern

def test_a4_registry_defined():
    """_PG_OP_HANDLERS must be a module-level dict mapping op name to
    callable. Caught by `from db.postgres import _PG_OP_HANDLERS`
    failing if the refactor regresses."""
    import db.postgres as _pgmod
    assert hasattr(_pgmod, "_PG_OP_HANDLERS")
    reg = _pgmod._PG_OP_HANDLERS
    assert isinstance(reg, dict)
    assert reg, "_PG_OP_HANDLERS must be non-empty"
    for op, handler in reg.items():
        assert callable(handler), f"_PG_OP_HANDLERS[{op!r}] is not callable"
        assert handler.__name__.startswith("_h_"), (
            f"handler for {op!r} must follow `_h_<op>` naming "
            f"(got {handler.__name__!r})"
        )


def test_a4_registry_matches_op_arity_keys():
    """Every op in _PG_OP_HANDLERS must have an entry in _OP_ARITY and
    vice versa. The two tables MUST stay in lock-step — a handler
    without an arity entry skips the M11 boundary check; an arity entry
    without a handler returns False to a caller that expects True."""
    import db.postgres as _pgmod
    handlers_set = set(_pgmod._PG_OP_HANDLERS.keys())
    arity_set    = set(_pgmod._OP_ARITY.keys())
    missing_handlers = arity_set - handlers_set
    missing_arity    = handlers_set - arity_set
    assert not missing_handlers, (
        f"_OP_ARITY has these ops but _PG_OP_HANDLERS does not: "
        f"{sorted(missing_handlers)}"
    )
    assert not missing_arity, (
        f"_PG_OP_HANDLERS has these ops but _OP_ARITY does not: "
        f"{sorted(missing_arity)}"
    )


def test_a4_dispatch_is_now_registry_lookup():
    """The new _pg_dispatch_op body must be ~10 lines (arity + lookup
    + call) — not the 365-line ladder. Source-shape regression catches
    a contributor accidentally re-inlining a handler back into the
    dispatcher."""
    src = (_ROOT / "db" / "postgres.py").read_text(encoding="utf-8")
    idx = src.find("def _pg_dispatch_op(")
    end = src.find("\ndef ", idx + 1)
    body = src[idx:end if end > 0 else len(src)]
    # Registry lookup MUST be present
    assert "_PG_OP_HANDLERS.get(op)" in body, (
        "_pg_dispatch_op must dispatch via _PG_OP_HANDLERS.get(op)"
    )
    # No more if/elif chain of `if op ==` / `elif op ==`
    elif_op_count = body.count("elif op ==")
    assert elif_op_count == 0, (
        f"_pg_dispatch_op still has {elif_op_count} `elif op == ...` "
        f"branches — A4 refactor expects a registry lookup, not a ladder"
    )
    # And the body should be short — sanity bound at 80 lines
    lines = body.count("\n")
    assert lines < 80, (
        f"_pg_dispatch_op body is {lines} lines — A4 expects <80; "
        f"check if a handler is being inlined"
    )


def test_a4_all_handlers_have_h_prefix():
    """Every handler in the registry MUST be a function whose name starts
    with `_h_`. Enables grepping the op inventory with `grep -E
    '^def _h_' db/postgres.py`."""
    src = (_ROOT / "db" / "postgres.py").read_text(encoding="utf-8")
    import re as _re
    defs = _re.findall(r"^def (_h_\w+)\(", src, _re.MULTILINE)
    import db.postgres as _pgmod
    handlers_set = set(_pgmod._PG_OP_HANDLERS.keys())
    handler_fns  = {h.__name__ for h in _pgmod._PG_OP_HANDLERS.values()}
    src_h_defs   = set(defs)
    assert handler_fns <= src_h_defs, (
        f"_PG_OP_HANDLERS references handler fns not found as top-level "
        f"`def _h_*`: {handler_fns - src_h_defs}"
    )
    # Every op name in the registry should map to a handler whose
    # name is `_h_<op>` — strict convention. Catches typos in the
    # dict literal.
    mismatches = []
    for op, h in _pgmod._PG_OP_HANDLERS.items():
        if h.__name__ != f"_h_{op}":
            mismatches.append((op, h.__name__))
    assert not mismatches, (
        f"Handler name must follow `_h_<op>` convention; "
        f"mismatches: {mismatches}"
    )


def test_a4_unknown_op_still_returns_false():
    """Backward-compatible: unknown ops return False (NOT raise). The
    caller _pg_mirror_kv depends on this to silently no-op an op it
    doesn't recognise instead of crashing the writer loop."""
    from db.postgres import _pg_dispatch_op

    class _Cur:
        called = False
        def execute(self, *a, **kw):
            _Cur.called = True

    result = _pg_dispatch_op("this-op-does-not-exist", (), _Cur())
    assert result is False
    assert _Cur.called is False, (
        "unknown op must NOT touch the cursor"
    )
