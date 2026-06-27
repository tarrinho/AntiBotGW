"""
1.9.0 same-version iter-5 — bugs found during live dynamic DB testing.

The dynamic test harness (PG + Gateway containers, real /__db-switch
round-trip) surfaced 10 source-side defects that the unit/golden suites
missed because they don't exercise the live boot path. Source-inspection
tests below freeze every fix so a future regression fails CI.

Fixes covered (chronological order found):

  UI-1 — `/secured/honeypots` returned 502 (route not registered)
  UI-2 — `/assets/chart.umd.min.js` and `/assets/purify.min.js` decoyed
         to 404 for unauthenticated callers (login page can't render
         charts before the session cookie exists)

  B1   — `pg_test_roundtrip` reads `db.postgres.POSTGRES_DSN` but
         `db_test_endpoint` / `db_switch_endpoint` only set
         `core.proxy_handler` globals → probe always returned
         `POSTGRES_DSN not configured`
  B2   — `if POSTGRES_DSN:` boot block ran BEFORE `db_load_secrets()`
         → A5 schema-version check + `db_init_postgres` + F12
         boot-resume hook all silently skipped after a `/__db-switch`
         restart (env DSN empty, secrets_kv DSN not yet loaded)
  B3   — `_resume_pending_bg_migration` used `open_conn()` which
         routes via `active_backend()` → since DSN was now set, it hit
         PG `config_kv` (empty) instead of SQLite `config_kv` (has
         marker), and the F12 marker was never consumed
  B4   — `_runner()` marker clear used the writer-queue `del_config`
         op → mirrored the delete to PG, but the marker LIVED in
         SQLite → SQLite marker never cleared, would re-fire on every
         boot
  B5   — `await asyncio.sleep(0.5)` race — the writer queue's
         `set_config DB_BACKEND` op didn't always flush before
         `os._exit(0)` → post-restart gateway came up on the OLD
         backend, requiring a SECOND switch to take effect
  B6   — Same race for the F12 marker write — could be lost between
         queue and exit
  B7   — `admin/users.py:213` queued `user_session_create` with a
         7-tuple; M11 arity table declares 8 (trailing csrf_nonce slot)
         → live M11 guard fired `WARNING:root:[db-pg] kv mirror
         failed (op=user_session_create): AssertionError`

  Bonus — db_migration_status_endpoint + db_vacuum_history_endpoint +
  _vacuum_scheduler_loop missing in the working tree (proxy.py
  route table referenced them, container exited on import).
"""
import pathlib


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_PROXY    = (_ROOT / "proxy.py").read_text(encoding="utf-8")
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_CONFIG   = (_ROOT / "config.py").read_text(encoding="utf-8")
_USERS    = (_ROOT / "admin" / "users.py").read_text(encoding="utf-8")
_DASH_INIT = (_ROOT / "dashboards" / "__init__.py").read_text(encoding="utf-8")


# UI fixes

def test_ui1_honeypots_route_registered():
    """`/secured/honeypots` must map to honeypots_dashboard_endpoint
    AND `/secured/honeypots-data` must map to honeypots_data_endpoint
    in proxy.py's _ROUTES table."""
    assert '("honeypots",' in _PROXY and "honeypots_dashboard_endpoint" in _PROXY, (
        "proxy.py route table missing the honeypots entry; the dashboard "
        "tab returns 502 because no handler is registered"
    )
    assert '("honeypots-data",' in _PROXY and "honeypots_data_endpoint" in _PROXY, (
        "proxy.py route table missing the honeypots-data JSON endpoint"
    )


def test_ui1_honeypots_module_imported_into_dashboards_package():
    """`from dashboards import *` (line 43 of proxy.py) must surface
    `honeypots_dashboard_endpoint` + `honeypots_data_endpoint` so the
    _ROUTES table can name them at parse time."""
    assert "from dashboards.honeypots import" in _DASH_INIT or \
           "from dashboards.honeypots import *" in _DASH_INIT, (
        "dashboards/__init__.py must import dashboards.honeypots so the "
        "wildcard import in proxy.py surfaces the endpoint symbols"
    )


def test_ui2_chart_js_in_public_subpaths():
    """Chart.js + purify.min.js must reach the browser BEFORE login —
    the login page itself references them for the initial render, and
    blocking on the admin-key gate causes the user-facing graphs to
    silently fail when the session cookie isn't fresh."""
    assert "/assets/chart.umd.min.js" in _CONFIG, (
        "config.py:_ADMIN_PUBLIC_SUBPATHS missing chart.umd.min.js — the "
        "dashboard charts won't load until after auth, breaking the live "
        "service-metrics view for the user reported as 'graphs não estão "
        "a aparecer direito'"
    )
    assert "/assets/purify.min.js" in _CONFIG, (
        "config.py:_ADMIN_PUBLIC_SUBPATHS missing purify.min.js — the "
        "DOMPurify sanitiser must load alongside Chart.js or innerHTML "
        "calls in the dashboards trip on a missing global"
    )


# B1 — pg_test_roundtrip DSN propagation

def test_b1_db_switch_propagates_dsn_to_db_postgres_module():
    """db_switch_endpoint's probe must set `db.postgres.POSTGRES_DSN`
    (not just `core.proxy_handler.POSTGRES_DSN`) so `pg_test_roundtrip`
    — which reads its OWN module's globals — sees the candidate DSN."""
    idx = _PH_SRC.find("def db_switch_endpoint")
    end = _PH_SRC.find("\nasync def ", idx + 1)
    body = _PH_SRC[idx:end if end > 0 else len(_PH_SRC)]
    assert "import db.postgres" in body or "from db import postgres" in body, (
        "db_switch_endpoint must import db.postgres in the probe scope"
    )
    assert "_pg_for_probe.POSTGRES_DSN" in body, (
        "db_switch_endpoint must set db.postgres.POSTGRES_DSN around "
        "the pg_test_roundtrip() call so the probe reads the candidate "
        "DSN, not its import-time snapshot"
    )


def test_b1_db_test_endpoint_propagates_dsn_too():
    """Same fix on the GET /__db-test?dsn=... probe path."""
    idx = _PH_SRC.find("probe_dsn = request.query")
    block = _PH_SRC[idx:idx + 2000]
    assert "_pg_for_probe.POSTGRES_DSN" in block, (
        "db_test_endpoint's preflight probe must also propagate DSN to "
        "db.postgres so the candidate-DSN probe works without persisting"
    )


# B2 — db_load_secrets() ordering

def test_b2_db_load_secrets_runs_before_pg_init_block():
    """on_startup must load secrets BEFORE the `if POSTGRES_DSN_NOW:`
    PG-init block fires. After a /__db-switch restart, the env var is
    empty; the persisted DSN lives in secrets_kv. If the block uses the
    import-time POSTGRES_DSN, it skips A5 + db_init_postgres + F12
    resume — and the gateway boots on PG WITHOUT running schema init."""
    i_load = _PROXY.find("db_load_secrets()")
    i_block = _PROXY.find("if POSTGRES_DSN_NOW:")
    assert i_load > 0, (
        "proxy.py: db_load_secrets() must be called in on_startup"
    )
    assert i_block > 0, (
        "proxy.py: the PG-init block must guard on POSTGRES_DSN_NOW "
        "(the post-load value), not the import-time POSTGRES_DSN"
    )
    assert i_load < i_block, (
        f"proxy.py: db_load_secrets() MUST precede the PG-init block. "
        f"Found db_load_secrets at offset {i_load}, PG-init block at "
        f"offset {i_block}. iter-5 fix ordering is reversed."
    )


def test_b2_pg_init_block_uses_post_load_dsn():
    """The guard variable must be `POSTGRES_DSN_NOW` (re-read AFTER
    db_load_secrets), NOT the import-time `POSTGRES_DSN`."""
    assert "POSTGRES_DSN_NOW = globals().get(\"POSTGRES_DSN\"" in _PROXY, (
        "proxy.py iter-5: POSTGRES_DSN_NOW must be rebound from globals "
        "after db_load_secrets so the PG-init block sees the just-loaded "
        "value, not the import-time snapshot"
    )


# B3 + B4 — F12 marker IO via SQLite direct

def test_b3_f12_resume_reads_marker_from_sqlite_directly():
    """`_resume_pending_bg_migration` must use `sqlite3.connect(DB_PATH)`
    DIRECTLY, NOT `open_conn()` which routes via active_backend(). After
    db_load_secrets POSTGRES_DSN is set → active_backend() returns
    'postgres' → open_conn() returns a PG conn → queries empty PG
    config_kv → marker never consumed."""
    idx = _PROXY.find("async def _resume_pending_bg_migration")
    end = _PROXY.find("\nasync def ", idx + 1)
    body = _PROXY[idx:end if end > 0 else len(_PROXY)]
    # iter-7 review fix: switched from bare `import sqlite3` to
    # `from db.sqlite import _sqlite_connect` so the connection
    # inherits WAL + tuned pragmas. Either form satisfies the B3
    # contract (direct SQLite, bypassing open_conn / active_backend).
    assert "import sqlite3" in body or "_sqlite_connect" in body, (
        "_resume_pending_bg_migration must use sqlite3 directly to read the "
        "marker directly (NOT via open_conn / active_backend)"
    )
    assert ("sqlite3.connect" in body
            or "_sql_for_marker.connect" in body
            or "_mig_sq(" in body
            or "_sqlite_connect" in body), (
        "_resume_pending_bg_migration must open SQLite directly "
        "(sqlite3.connect or db.sqlite._sqlite_connect) so the marker "
        "query hits SQLite even when DSN is set"
    )


def test_b4_f12_marker_clear_uses_sqlite_directly():
    """The `_runner()` finally block must DELETE the marker from SQLite
    directly. Using the writer queue's `del_config` op would mirror the
    delete to PG (which doesn't have the marker) — SQLite copy of the
    marker would persist → re-fire the migration every boot."""
    idx = _PROXY.find("def _runner():")
    if idx == -1:
        # Fall back to scanning the resume function body
        idx = _PROXY.find("async def _resume_pending_bg_migration")
    end = _PROXY.find("\n\n", idx + 1500)
    body = _PROXY[idx:end if end > 0 else idx + 3000]
    assert "DELETE FROM config_kv" in body, (
        "_runner() must DELETE FROM config_kv directly (SQLite) to clear "
        "the pending_bg_migration marker after the COPY completes"
    )


# B5 + B6 — direct SQLite writes for switch persistence

def test_b5_db_backend_persisted_directly_to_sqlite():
    """db_switch_endpoint must write DB_BACKEND to SQLite SYNCHRONOUSLY
    (via direct sqlite3.connect + commit) — the writer-queue +
    asyncio.sleep(0.5) flush WAS lost under load, leaving the post-
    restart gateway on the wrong backend."""
    idx = _PH_SRC.find("def db_switch_endpoint")
    end = _PH_SRC.find("\nasync def ", idx + 1)
    body = _PH_SRC[idx:end if end > 0 else len(_PH_SRC)]
    assert "INSERT OR REPLACE INTO config_kv" in body, (
        "db_switch_endpoint must write DB_BACKEND directly to SQLite via "
        "INSERT OR REPLACE — the writer queue is async and races the "
        "os._exit(0) coroutine that follows"
    )
    assert "_sconn.commit()" in body or "_sconn.commit" in body, (
        "Direct sqlite3 write must COMMIT before the os._exit(0); "
        "without commit the WAL may discard the row on shutdown"
    )


def test_b6_f12_marker_persisted_directly_to_sqlite():
    """Same fix for the F12 marker write — must be durable before
    os._exit(0). Otherwise the bg migration is silently dropped."""
    idx = _PH_SRC.find("def db_switch_endpoint")
    end = _PH_SRC.find("\nasync def ", idx + 1)
    body = _PH_SRC[idx:end if end > 0 else len(_PH_SRC)]
    # The marker write block must use direct sqlite3 INSERT OR REPLACE
    # for pending_bg_migration. Two INSERT OR REPLACE statements in
    # db_switch_endpoint: one for DB_BACKEND (B5), one for the marker (B6).
    assert body.count("INSERT OR REPLACE INTO config_kv") >= 2, (
        "db_switch_endpoint must use TWO direct sqlite3 writes — one "
        "for DB_BACKEND (B5), one for the F12 pending_bg_migration "
        "marker (B6). Both must commit before os._exit(0)."
    )


# B7 — user_session_create arity

def test_b7_user_session_create_queues_8tuple():
    """admin/users.py must queue user_session_create with 8 args (sid,
    username, ip, ua, c_ts, l_ts, e_ts, csrf_nonce). The trailing slot
    is csrf_nonce — PG drops it, SQLite stores it. M11's arity guard
    fired live on this call site with the original 7-tuple."""
    idx = _USERS.find('"user_session_create"')
    assert idx > 0, "user_session_create op-name string not in admin/users.py"
    # Locate the inner args tuple — the next '(' after the op-name string.
    # The block has the shape:
    #   ((
    #       "user_session_create",
    #       # 8-tuple: trailing csrf_nonce slot. PG drops it; ...  ← optional comment
    #       (sid, username, ip or "", (user_agent or "")[:512],
    #        n, n, expires_ts, ""),
    #   ))
    # Read forward, skipping comments/whitespace, until the first '(' on
    # a line that's not a comment. That '(' opens the args tuple.
    cursor = _USERS.find('\n', idx) + 1  # skip past the op-name line
    while cursor < len(_USERS):
        line = _USERS[cursor:_USERS.find('\n', cursor)]
        stripped = line.lstrip()
        if stripped.startswith("#") or stripped == "":
            cursor = _USERS.find('\n', cursor) + 1
            continue
        # First non-comment, non-blank line must start the args tuple
        paren_idx = line.find("(")
        assert paren_idx >= 0, (
            f"expected args tuple opening '(' at {stripped[:60]!r}"
        )
        # Locate the matching close paren via depth scan from this point
        scan_start = cursor + paren_idx
        depth = 0
        end = -1
        for i in range(scan_start, len(_USERS)):
            ch = _USERS[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        assert end > scan_start, "could not find matching ')' for args tuple"
        args_str = _USERS[scan_start + 1:end]
        break
    else:  # pragma: no cover — loop should always find a line
        raise AssertionError("walked off end of file looking for args tuple")
    # Strip whitespace, count top-level commas (ignore nested parens)
    depth = 0
    commas = 0
    for ch in args_str:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            commas += 1
    # n args == commas + 1 (trailing comma counts as commas+1 too, but
    # both shapes give us the same count)
    n_args = commas + 1
    assert n_args == 8, (
        f"admin/users.py: user_session_create queued with {n_args} "
        f"args; M11 arity table expects 8 (trailing csrf_nonce slot). "
        f"Got: ({args_str.strip()[:80]}...)"
    )


# Bonus — missing endpoints referenced by proxy.py route table

def test_bonus_db_migration_status_endpoint_defined():
    """proxy.py:805 references db_migration_status_endpoint. Without it
    the container exits at import time with NameError."""
    assert "db_migration_status_endpoint" in _PH_SRC, (
        "core/proxy_handler.py must define db_migration_status_endpoint "
        "— route table references it"
    )


def test_bonus_db_vacuum_history_endpoint_defined():
    assert "async def db_vacuum_history_endpoint" in _PH_SRC, (
        "core/proxy_handler.py must define db_vacuum_history_endpoint "
        "— route table references it"
    )


def test_bonus_vacuum_scheduler_loop_defined():
    assert "_vacuum_scheduler_loop" in _PH_SRC, (
        "core/proxy_handler.py must define _vacuum_scheduler_loop — "
        "proxy.on_startup spawns it via asyncio.create_task"
    )


def test_bonus_db_vacuum_lock_module_level():
    """_DB_VACUUM_LOCK must be a module-level asyncio.Lock so the
    scheduler, the operator endpoint, and the migration guard share
    the SAME lock object."""
    assert "_DB_VACUUM_LOCK = asyncio.Lock()" in _PH_SRC, (
        "_DB_VACUUM_LOCK must be a module-level asyncio.Lock"
    )


# Bonus — dynamic-test bug count assertion

def test_count_dynamic_test_fixes_in_changelog():
    """If the changelog gets a 1.9.0 iter-5 section, ensure the 10 dyn-
    test fixes are mentioned by their identifiers. Skipped when no
    iter-5 changelog entry exists yet."""
    cl_path = _ROOT / "CHANGELOG.md"
    if not cl_path.exists():
        import pytest
        pytest.skip("CHANGELOG.md missing")
    cl = cl_path.read_text(encoding="utf-8")
    if "iter-5" not in cl.lower() and "iteration 5" not in cl.lower():
        import pytest
        pytest.skip("No iter-5 changelog entry yet")
    for marker in ("UI-1", "UI-2", "B1", "B2", "B3", "B4", "B5", "B6", "B7"):
        assert marker in cl, (
            f"CHANGELOG iter-5 section missing fix marker {marker!r}"
        )
