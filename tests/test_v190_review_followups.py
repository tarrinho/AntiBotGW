"""
1.9.0 same-version iteration — the 5 review-deferred items:

  F3  — db.conn:conn() context manager commits on clean exit, rolls back
        on exception (footgun fix; sqlite3-conn-like semantics)
  F4  — db.postgres:prune_gw_audit_postgres + dispatch in _prune_state_loop
        on active_backend(); PG-only deploys now bound their audit table
  F7  — db.export:--force on the live $DB_PATH requires
        --i-know-what-im-doing; existing file is backed up to
        .pre-export-<ts>.bak
  F8  — db.export / db.import never print the full DSN to stdout; only
        the masked form via _mask_dsn()
  F10 — db_switch_endpoint accepts full_migrate=true in body; schedules
        _full_migrate_background via _try_claim_bg_migration (single-flight);
        reports full_migrate_scheduled in the response
"""
import pathlib
import re


_ROOT      = pathlib.Path(__file__).resolve().parent.parent
_CONN_SRC  = (_ROOT / "db" / "conn.py").read_text(encoding="utf-8")
_PG_SRC    = (_ROOT / "db" / "postgres.py").read_text(encoding="utf-8")
_RL_SRC    = (_ROOT / "rate_limit.py").read_text(encoding="utf-8")
_EXP_SRC   = (_ROOT / "db" / "export.py").read_text(encoding="utf-8")
_IMP_SRC   = (_ROOT / "db" / "import.py").read_text(encoding="utf-8")
_PH_SRC    = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")


# ── F3 ─────────────────────────────────────────────────────────────────────

class TestF3ConnCommitOnExit:
    def test_conn_ctx_commits_on_clean_exit(self):
        idx = _CONN_SRC.find("def conn(")
        nxt = _CONN_SRC.find("\ndef ", idx + 1)
        block = _CONN_SRC[idx: nxt if nxt != -1 else idx + 3000]
        # Both backends must commit. The simplest test: at least 2 commit()
        # calls in the conn() body (PG + SQLite branches).
        commits = re.findall(r"\b(?:wrapped|c)\.commit\(\)", block)
        assert len(commits) >= 2, (
            f"conn() must commit on clean exit for BOTH backends; "
            f"found {len(commits)} commit() calls"
        )

    def test_conn_ctx_rollback_on_exception(self):
        idx = _CONN_SRC.find("def conn(")
        nxt = _CONN_SRC.find("\ndef ", idx + 1)
        block = _CONN_SRC[idx: nxt if nxt != -1 else idx + 3000]
        rollbacks = re.findall(r"\b(?:wrapped|c)\.rollback\(\)", block)
        assert len(rollbacks) >= 2, (
            f"conn() must rollback on exception for BOTH backends; "
            f"found {len(rollbacks)} rollback() calls"
        )

    def test_conn_ctx_race_raises_pgunavailable(self):
        """Mirror of F5 fix in open_conn() — conn() must also raise rather
        than silently downgrade."""
        # Take the conn() function body only — anchor on the @contextmanager
        # decorator that precedes the public conn().
        idx = _CONN_SRC.find("@contextmanager\ndef conn(")
        assert idx != -1, "public conn() context manager not found"
        # Skip past the def line; then find next top-level def
        body_start = _CONN_SRC.find("\n", idx + len("@contextmanager"))
        nxt = _CONN_SRC.find("\ndef ", body_start + 10)
        block = _CONN_SRC[body_start: nxt if nxt != -1 else body_start + 4000]
        # In the `if not POSTGRES_DSN:` branch inside the postgres path,
        # we must NOT see sqlite3.connect (silent downgrade) — must raise.
        if_not_dsn = block.find("if not POSTGRES_DSN:")
        assert if_not_dsn != -1
        ctx = block[if_not_dsn: if_not_dsn + 600]
        assert "raise PgUnavailableError" in ctx, (
            "conn() race branch must raise PgUnavailableError"
        )
        assert "sqlite3.connect" not in ctx, (
            "conn() race branch must NOT silently downgrade to sqlite3.connect"
        )


# ── F4 ─────────────────────────────────────────────────────────────────────

class TestF4PrunePostgres:
    def test_pg_helper_exists(self):
        assert "def prune_gw_audit_postgres(" in _PG_SRC, (
            "prune_gw_audit_postgres helper must exist in db/postgres.py"
        )

    def test_pg_helper_uses_parameterised_delete(self):
        idx = _PG_SRC.find("def prune_gw_audit_postgres(")
        nxt = _PG_SRC.find("\ndef ", idx + 1)
        block = _PG_SRC[idx: nxt if nxt != -1 else idx + 2000]
        assert "DELETE FROM gw_audit WHERE ts < %s" in block, (
            "PG prune must use parameterised %s placeholder, not f-string"
        )
        assert "retention_days <= 0" in block, (
            "retention_days <= 0 must early-return (disabled / unconfigured)"
        )

    def test_prune_loop_dispatches_on_backend(self):
        # rate_limit._prune_state_loop must consult active_backend() and
        # call the right helper
        assert "prune_gw_audit_postgres" in _RL_SRC, (
            "_prune_state_loop must call prune_gw_audit_postgres for PG"
        )
        # The dispatch may alias `active_backend as _ab` then call `_ab()`.
        assert "active_backend" in _RL_SRC, (
            "_prune_state_loop must import active_backend"
        )


# ── F7 ─────────────────────────────────────────────────────────────────────

class TestF7ExportForceSafety:
    def test_i_know_what_im_doing_flag_exists(self):
        assert "--i-know-what-im-doing" in _EXP_SRC, (
            "db.export must accept --i-know-what-im-doing flag for "
            "overriding the live-DB safety check"
        )

    def test_refuses_live_db_without_override(self):
        # The check must compare abspath of $DB_PATH to abspath of target
        assert "os.path.abspath(os.environ.get(\"DB_PATH\"" in _EXP_SRC or \
               "os.path.abspath(sqlite_path)" in _EXP_SRC, (
            "live-DB detection must use os.path.abspath for both sides"
        )
        assert "i_know_what_im_doing" in _EXP_SRC, (
            "Override flag name must be wired into the safety check"
        )

    def test_existing_file_backed_up_not_clobbered(self):
        assert "pre-export-" in _EXP_SRC, (
            "Existing target must be renamed to <path>.pre-export-<ts>.bak "
            "before being overwritten (recoverable --force)"
        )


# ── F8 ─────────────────────────────────────────────────────────────────────

class TestF8DsnMasking:
    def test_export_has_mask_helper(self):
        # L8 fix: _mask_dsn moved to db.cli_helpers (shared). Accept either
        # a local `def` (legacy) or the shared-import alias.
        has_local = "def _mask_dsn(" in _EXP_SRC
        has_shared = "from db.cli_helpers import mask_dsn as _mask_dsn" in _EXP_SRC
        assert has_local or has_shared, (
            "db.export must expose _mask_dsn (local def or shared import)"
        )

    def test_import_has_mask_helper(self):
        has_local = "def _mask_dsn(" in _IMP_SRC
        has_shared = "from db.cli_helpers import mask_dsn as _mask_dsn" in _IMP_SRC
        assert has_local or has_shared, (
            "db.import must expose _mask_dsn (local def or shared import)"
        )

    def test_export_uses_mask_on_stdout(self):
        # The previous unmasked print must be gone
        assert "[db.export] source: {pg_dsn}" not in _EXP_SRC, (
            "db.export must not print full DSN to stdout"
        )
        assert "_mask_dsn(pg_dsn)" in _EXP_SRC, (
            "db.export source line must call _mask_dsn"
        )

    def test_import_uses_mask_on_stdout(self):
        # The previous f-string had {pg_dsn} unmasked
        assert re.search(r"\[db\.import\] target:.*\{pg_dsn\}", _IMP_SRC) is None, (
            "db.import must not print full DSN unmasked"
        )
        assert "_mask_dsn(pg_dsn)" in _IMP_SRC, (
            "db.import target line must call _mask_dsn"
        )

    def test_mask_strips_password_only(self):
        """Verify _mask_dsn preserves host/user/scheme/port/db but strips
        the password."""
        import sys
        sys.path.insert(0, str(_ROOT))
        from db.export import _mask_dsn as me
        # `db.import` collides with the keyword; use importlib
        import importlib
        mi = importlib.import_module("db.import")
        masked = me("postgresql://alice:super-secret@dbhost:5433/audit")
        assert "super-secret" not in masked
        assert "alice" in masked
        assert "dbhost" in masked
        assert "5433" in masked
        assert "/audit" in masked
        assert "****" in masked
        # db.import's helper should produce the same output
        masked2 = mi._mask_dsn("postgresql://bob:secret@h:5/d")
        assert "secret" not in masked2
        assert "bob" in masked2 and "****" in masked2


# ── F10 ────────────────────────────────────────────────────────────────────

class TestF10FullMigrateWired:
    def test_full_migrate_parsed_from_body(self):
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert 'body.get("full_migrate"' in block, (
            "db_switch_endpoint must parse full_migrate from body"
        )

    def test_try_claim_bg_migration_called(self):
        """F12 (iter-4): the single-flight claim moved to the boot-time
        resumer in proxy.py — db_switch_endpoint now defers via a
        `pending_bg_migration` config_kv marker that on_startup consumes."""
        _PROXY_SRC = (_ROOT / "proxy.py").read_text(encoding="utf-8")
        assert "_try_claim_bg_migration" in _PROXY_SRC, (
            "Must single-flight via _try_claim_bg_migration (no double-schedule)"
        )

    def test_full_migrate_background_scheduled(self):
        """F12 (iter-4): the executor call moved to proxy._resume_pending_bg_migration."""
        _PROXY_SRC = (_ROOT / "proxy.py").read_text(encoding="utf-8")
        assert "_full_migrate_background" in _PROXY_SRC, (
            "Must schedule _full_migrate_background in executor (post-restart)"
        )
        assert "run_in_executor" in _PROXY_SRC, (
            "Must use run_in_executor — background, not event-loop-blocking"
        )
        # And the handler must persist the deferred-marker contract
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "pending_bg_migration" in block, (
            "Handler must persist pending_bg_migration marker (F12)"
        )

    def test_switch_ts_captured_before_recent_migration(self):
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        switch_ts_idx = block.find("switch_ts = _t.time()")
        # Find the CALL to _migrate_recent_events (run_in_executor arg), not
        # the function-reference earlier in the file
        recent_call_idx = block.find("_migrate_recent_events, target, 60")
        assert switch_ts_idx != -1 and recent_call_idx != -1
        assert switch_ts_idx < recent_call_idx, (
            "switch_ts MUST be captured before the recent-window migration "
            "call so bg cutoff_ts = switch_ts - 60 doesn't overlap"
        )

    def test_response_reports_full_migrate_scheduled(self):
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert '"full_migrate_scheduled":' in block, (
            "Response must include full_migrate_scheduled so the dashboard "
            "can show 'historical migration in progress'"
        )
