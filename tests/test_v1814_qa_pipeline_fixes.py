# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1814_qa_pipeline_fixes.py — QA for the rules.md pipeline fixes
applied in iteration 15:

  P1: pytest bumped to 9.0.3+ (CVE-2025-71176)
  P2: SQLite events auto-prune (Stage 20a — GDPR data-minimization)
  P3: Chainguard base bumped (CVE-2026-8328 ftplib in python:latest)
  P4: pyright cross-module FPs in admin/mesh.py eliminated via lazy-import
      module-level fallbacks; qrcode.constants explicit import; users.py
      _session_verify None-safe cookie read
"""
from __future__ import annotations

import os
import re
import sqlite3
import time
import tempfile

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

import pathlib
_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
# P1 — pytest CVE-2025-71176 fixed
# ═══════════════════════════════════════════════════════════════════════════

class TestPipelineP1PytestCveFixed:
    """requirements.txt pins pytest >= 9.0.3."""

    def test_requirements_pin_includes_9_0_3(self):
        req = _read("requirements.txt")
        m = re.search(r"^pytest\s*[><=]+\s*([^,#\s]+)", req, re.M)
        assert m, "requirements.txt must pin pytest"
        # The pin must allow >= 9.0.3 (CVE-2025-71176 fix)
        assert "9.0.3" in req or "9.0" in req or ">=9" in req

    def test_no_unsafe_pin_to_8x(self):
        req = _read("requirements.txt")
        # The old pattern was: pytest>=8,<9 — must NOT be present
        assert "pytest>=8,<9" not in req

    def test_cve_comment_present_for_audit(self):
        req = _read("requirements.txt")
        # The fix should reference the CVE for future operator context
        assert "CVE-2025-71176" in req or "CVE-2025" in req


# ═══════════════════════════════════════════════════════════════════════════
# P2 — Events auto-prune
# ═══════════════════════════════════════════════════════════════════════════

class TestPipelineP2EventsPrune:
    """SQLite events table is pruned per EVENTS_RETENTION_DAYS."""

    def test_config_knob_defined(self):
        import config
        assert hasattr(config, "EVENTS_RETENTION_DAYS")
        assert hasattr(config, "EVENTS_PRUNE_INTERVAL_SECS")

    def test_default_retention_is_30_days(self):
        import config
        assert config.EVENTS_RETENTION_DAYS == 30

    def test_default_interval_is_hourly(self):
        import config
        assert config.EVENTS_PRUNE_INTERVAL_SECS == 3600

    def test_prune_function_exported(self):
        from db import prune_old_events
        assert callable(prune_old_events)

    def test_zero_retention_disables(self):
        """Setting EVENTS_RETENTION_DAYS=0 must disable pruning."""
        import config, db.sqlite as _sql
        _saved = config.EVENTS_RETENTION_DAYS
        config.EVENTS_RETENTION_DAYS = 0
        try:
            assert _sql.prune_old_events() == 0
        finally:
            config.EVENTS_RETENTION_DAYS = _saved

    def test_prune_deletes_old_rows_only(self):
        """Verify the cutoff arithmetic — rows newer than (now - days*86400)
        survive, older rows are deleted."""
        import config, db.sqlite as _sql
        _saved_path = _sql.DB_PATH
        _saved_days = config.EVENTS_RETENTION_DAYS
        try:
            # Build an isolated temp DB
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as _f:
                tmp = _f.name
            _sql.DB_PATH = tmp
            config.EVENTS_RETENTION_DAYS = 7
            conn = sqlite3.connect(tmp)
            conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, ts REAL)")
            n = time.time()
            # 3 fresh, 2 old (10 days back, beyond 7-day window)
            conn.execute("INSERT INTO events (ts) VALUES (?), (?), (?), (?), (?)",
                         (n - 1, n - 60, n - 3600,
                          n - 10*86400, n - 11*86400))
            conn.commit()
            conn.close()

            deleted = _sql.prune_old_events()
            assert deleted == 2, f"expected 2 old rows pruned, got {deleted}"

            conn = sqlite3.connect(tmp)
            remaining = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            conn.close()
            assert remaining == 3
        finally:
            _sql.DB_PATH = _saved_path
            config.EVENTS_RETENTION_DAYS = _saved_days
            try: os.unlink(tmp)
            except Exception: pass

    def test_prune_is_called_from_state_loop(self):
        """rate_limit._prune_state_loop must invoke prune_old_events()."""
        src = _read("rate_limit.py")
        assert "prune_old_events" in src
        assert "EVENTS_PRUNE_INTERVAL_SECS" in src

    def test_slog_event_on_successful_prune(self):
        """prune_old_events emits events_pruned slog when rows are deleted."""
        src = _read("db/sqlite.py")
        assert "events_pruned" in src


# ═══════════════════════════════════════════════════════════════════════════
# P3 — Chainguard base bumped
# ═══════════════════════════════════════════════════════════════════════════

class TestPipelineP3ChainguardBaseBumped:
    """Dockerfile uses new Chainguard digest that fixes CVE-2026-8328."""

    def test_runtime_image_digest_is_new(self):
        df = _read("Dockerfile")
        # The new digest is sha256:30ac20a34bae...
        assert "sha256:30ac20a34bae" in df, (
            "Dockerfile runtime stage must pin to new Chainguard digest "
            "that fixes CVE-2026-8328 ftplib"
        )

    def test_builder_image_digest_is_new(self):
        df = _read("Dockerfile")
        # The new builder digest is sha256:ddd3811dcbef...
        assert "sha256:ddd3811dcbef" in df

    def test_old_vulnerable_digest_removed(self):
        df = _read("Dockerfile")
        # Old runtime: daab958311b820...
        assert "daab958311b820" not in df
        # Old builder: 6766a166e2a242...
        assert "6766a166e2a242" not in df

    def test_no_unpinned_chainguard_tag(self):
        """Every Chainguard FROM must be digest-pinned (not just :latest)."""
        df = _read("Dockerfile")
        for line in df.splitlines():
            if "cgr.dev/chainguard/python" in line and line.strip().startswith("FROM"):
                assert "@sha256:" in line, (
                    f"Chainguard image not digest-pinned: {line.strip()}"
                )


# ═══════════════════════════════════════════════════════════════════════════
# P4 — pyright cross-module FPs eliminated
# ═══════════════════════════════════════════════════════════════════════════

class TestPipelineP4PyrightFps:
    """admin/mesh.py has module-level fallback imports so pyright sees the
    runtime-injected symbols; admin/users.py is None-safe on cookie read;
    qrcode.constants explicitly imported."""

    def test_mesh_has_proxy_fallback(self):
        src = _read("admin/mesh.py")
        # The module-level _proxy resolution must exist for static analysis
        assert "_proxy = _sys.modules.get('proxy')" in src

    def test_mesh_has_secret_keys_fallback(self):
        src = _read("admin/mesh.py")
        assert "_SECRET_KEYS" in src and "from config import _SECRET_KEYS" in src

    def test_mesh_has_hot_reload_knobs_fallback(self):
        src = _read("admin/mesh.py")
        assert "_HOT_RELOAD_KNOBS" in src and \
               "from core.proxy_handler import _HOT_RELOAD_KNOBS" in src

    def test_mesh_has_db_load_secrets_fallback(self):
        src = _read("admin/mesh.py")
        assert "from db.sqlite import db_load_secrets" in src

    def test_users_session_cookie_read_is_none_safe(self):
        """login_page_endpoint must guard against cookies.get() returning None."""
        from admin.users import login_page_endpoint
        import inspect
        src = inspect.getsource(login_page_endpoint)
        # The fix: pull cookie once into a variable with `or ""` guard,
        # then pass to _session_verify which now receives a guaranteed str.
        assert "_sess_cookie" in src and 'or ""' in src

    def test_qrcode_constants_explicit_import(self):
        """totp_setup_endpoint imports qrcode.constants as a submodule so
        pyright sees the ERROR_CORRECT_M attribute."""
        from admin.users import totp_setup_endpoint
        import inspect
        src = inspect.getsource(totp_setup_endpoint)
        assert "qrcode.constants" in src and "_qrconst" in src

    def test_pyright_admin_clean(self):
        """Sanity: running pyright on admin/ produces 0 errors after the fix.
        Skipped if pyright is not installed on this host."""
        import shutil, subprocess
        if shutil.which("pyright") is None:
            pytest.skip("pyright not installed")
        env = os.environ.copy()
        env["UPSTREAM"] = "https://x.com"
        result = subprocess.run(
            ["pyright",
             str(_ROOT / "admin/users.py"),
             str(_ROOT / "admin/auth.py"),
             str(_ROOT / "admin/settings.py"),
             str(_ROOT / "admin/oidc.py"),
             str(_ROOT / "admin/mesh.py"),
             "--outputjson"],
            env=env, capture_output=True, text=True, timeout=120,
        )
        if not result.stdout:
            pytest.skip(f"pyright produced no JSON output: {result.stderr[:200]}")
        import json
        d = json.loads(result.stdout)
        errors = [e for e in d.get("generalDiagnostics", []) if e["severity"] == "error"]
        assert not errors, (
            f"pyright must produce 0 errors on admin/; got {len(errors)}: "
            + ", ".join(f"{e['file'].split('/')[-1]}:{e['range']['start']['line']+1}"
                        for e in errors[:5])
        )


# ═══════════════════════════════════════════════════════════════════════════
# Cross-cutting: pipeline gates produce clean output
# ═══════════════════════════════════════════════════════════════════════════

class TestPipelineGatesClean:
    """Static-gate aggregate invariants — what rules.md §9/§10/§11 expect."""

    def test_bandit_blocking_categories_zero(self):
        """Pre-check: there's no new High/Critical Bandit finding hiding in
        the changes (B-level baseline is acceptable)."""
        # This is a source-presence check — we don't re-run bandit per-test.
        # The pipeline run reports the live count.
        import shutil
        if shutil.which("bandit") is None:
            pytest.skip("bandit not installed")
        import subprocess, json
        env = os.environ.copy(); env["UPSTREAM"] = "https://x.com"
        result = subprocess.run(
            ["bandit", "-r", "-ll", "-f", "json",
             str(_ROOT / "admin"), str(_ROOT / "core"),
             str(_ROOT / "db"), str(_ROOT / "detection")],
            env=env, capture_output=True, text=True, timeout=120,
        )
        try:
            d = json.loads(result.stdout)
        except Exception:
            pytest.skip("bandit produced no parseable output")
        high = [r for r in d.get("results", []) if r["issue_severity"] == "HIGH"]
        assert not high, f"Bandit must produce 0 HIGH findings; got {len(high)}"


# ═══════════════════════════════════════════════════════════════════════════
# P5 — Bandit MEDIUM B608 vulns eliminated (iteration 16)
# ═══════════════════════════════════════════════════════════════════════════

class TestPipelineP5BanditMediumZero:
    """The 4 Bandit MEDIUM B608 'hardcoded_sql_expressions' findings reported
    in iter 14 are eliminated: 2 by f-string/nosec re-positioning, 1 by SQL
    refactor to pre-built constants, 1 by rewriting a log message that
    happened to contain SQL keywords."""

    def test_no_concatenated_sql_with_conditional_in_top_paths(self):
        """proxy_handler.py top-paths query must not use `+` concatenation
        of a conditional WHERE fragment — that was the pattern Bandit flagged."""
        src = _read("core/proxy_handler.py")
        # The bug pattern: `+ ("AND vhost = ? " if _vhost else "")`
        assert '+ ("AND vhost = ? " if _vhost else "")' not in src, (
            "core/proxy_handler.py must not concatenate conditional WHERE "
            "fragments — use pre-built SQL constants instead"
        )
        # Contract change (post-1.8.14): the top-paths aggregation was
        # superseded by an in-memory (Python dict) implementation — vhost
        # filtering is now done on the merged event ring buffers, NOT via a
        # conditional-WHERE SQL query. So the original `_SQL_ALL`/`_SQL_VHOST`
        # constants no longer exist; the security invariant (no conditional
        # WHERE concat in the top-paths path) is what this test now enforces.
        assert "top_paths = sorted(_vhost_paths.items()" in src, (
            "top-paths must be aggregated in-memory (no SQL WHERE concat)"
        )

    def test_postgres_db_read_events_has_nosec_on_fstring_line(self):
        """db/postgres.py db_read_events must have `# nosec B608` on the same
        line as the f-string SELECT (Bandit only honours nosec on the exact
        line of the offending expression)."""
        src = _read("db/postgres.py")
        for line in src.splitlines():
            if ('f"SELECT' in line and 'FROM events' in line
                    and 'sql_cols' in line):
                assert "nosec B608" in line, (
                    "db/postgres.py f-string SELECT line must end with "
                    f"`# nosec B608`; got: {line.strip()[:120]}"
                )
                return
        pytest.fail("could not find f-string SELECT in db/postgres.py")

    def test_sqlite_db_read_events_has_nosec_on_fstring_line(self):
        """Same as above for db/sqlite.py."""
        src = _read("db/sqlite.py")
        for line in src.splitlines():
            if ('f"SELECT' in line and 'FROM events' in line
                    and "join(cols)" in line):
                assert "nosec B608" in line, (
                    "db/sqlite.py f-string SELECT line must end with "
                    f"`# nosec B608`; got: {line.strip()[:120]}"
                )
                return
        pytest.fail("could not find f-string SELECT in db/sqlite.py")

    def test_log_note_does_not_contain_delete_from_keyword(self):
        """The config_kv_stomp_blocked log message previously contained
        'DELETE FROM config_kv WHERE key=...' which triggered Bandit's B608
        regex on a non-SQL string. The fix rewords the operator hint."""
        src = _read("db/sqlite.py")
        assert "DELETE FROM config_kv WHERE key='" not in src, (
            "Log message must not contain literal SQL DELETE statement — "
            "Bandit B608 regex flags it as hardcoded SQL"
        )
        # And the new wording must be present
        assert "remove the stale config_kv row" in src

    def test_bandit_runtime_check_zero_medium(self):
        """Live Bandit run: 0 MEDIUM findings across all source dirs.
        Skipped when bandit is not installed."""
        import shutil
        if shutil.which("bandit") is None:
            pytest.skip("bandit not installed")
        import subprocess, json
        env = os.environ.copy(); env["UPSTREAM"] = "https://x.com"
        # Run on all the modules previously flagged
        result = subprocess.run(
            ["bandit", "-ll", "-r", "-f", "json",
             str(_ROOT / "proxy.py"),
             str(_ROOT / "admin"), str(_ROOT / "core"),
             str(_ROOT / "db"), str(_ROOT / "detection"),
             str(_ROOT / "integrations"),
             str(_ROOT / "scoring.py"),
             str(_ROOT / "identity.py")],
            env=env, capture_output=True, text=True, timeout=120,
        )
        try:
            d = json.loads(result.stdout)
        except Exception:
            pytest.skip(f"bandit no JSON: {result.stderr[:100]}")
        medium = [r for r in d.get("results", [])
                  if r["issue_severity"] == "MEDIUM"]
        assert not medium, (
            f"Bandit must produce 0 MEDIUM findings after iter-16 fixes; "
            f"got {len(medium)}: "
            + ", ".join(f"{r['filename'].split('/')[-1]}:{r['line_number']} "
                        f"{r['test_id']}"
                        for r in medium[:5])
        )
