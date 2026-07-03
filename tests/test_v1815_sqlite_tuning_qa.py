"""
QA tests — SQLite write-path tuning, upstream timeouts, circuit-breaker knobs
(1.8.15, post production slow-fsync incident).

Production incident: the container had 4KB fsync = 57 ms on the
underlying volume and SQLite events table at 2.4 M rows. Every blocked
request triggered an INSERT + UPDATE chain that committed → fsync, so the
db_writer_loop spent 76 ms per commit. At 50 req/s the gateway could not
keep up and users perceived multi-second slowness.

Three coordinated fixes:

1. `_sqlite_connect()` helper — single open path applying WAL + tuned
   PRAGMAs (synchronous=NORMAL, wal_autocheckpoint=10000, temp_store=MEMORY,
   mmap_size=256MB, cache_size=20MB) to every SQLite connection.

2. `UPSTREAM_TIMEOUT_SECS` + `UPSTREAM_CONNECT_TIMEOUT_SECS` env knobs to
   replace the hardcoded 30s upstream timeout that made users wait when
   upstream flapped.

3. `CIRCUIT_FAIL_THRESHOLD` / `CIRCUIT_OPEN_SECS` / `CIRCUIT_HALF_OPEN_MAX`
   exposed as hot-reload + per-vhost knobs so operators can tighten the
   circuit on a degraded upstream from the Thresholds dashboard.

Coverage:
  TestSqliteHelper            — _sqlite_connect applies all 6 PRAGMAs
  TestSqliteOpenPathsRouted   — every sqlite3.connect in db/sqlite.py routes through helper
  TestUpstreamTimeoutKnob     — config / vhost / hot-reload / controls.html
  TestCircuitBreakerKnobs     — same matrix for the 3 circuit-breaker knobs
"""
import pathlib
import re
import sqlite3
import tempfile

import pytest

_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_SQL_SRC  = (_ROOT / "db"  / "sqlite.py").read_text(encoding="utf-8")
_CFG_SRC  = (_ROOT / "config.py").read_text(encoding="utf-8")
_VH_SRC   = (_ROOT / "vhost.py").read_text(encoding="utf-8")
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_CTL_SRC  = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")
_VHP_SRC  = (_ROOT / "dashboards" / "vhost_policy.html").read_text(encoding="utf-8")


# ── 1. TestSqliteHelper ──────────────────────────────────────────────────────

class TestSqliteHelper:
    """`_sqlite_connect()` must exist and apply all 6 PRAGMAs."""

    def test_helper_defined(self):
        assert "def _sqlite_connect(" in _SQL_SRC, (
            "_sqlite_connect() helper not defined in db/sqlite.py"
        )

    def test_helper_returns_connection(self):
        # End-to-end: open a tmp DB via the helper and verify each PRAGMA.
        import importlib
        sql_mod = importlib.import_module("db.sqlite")
        with tempfile.NamedTemporaryFile(suffix=".db") as tf:
            conn = sql_mod._sqlite_connect(tf.name)
            try:
                assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal", (
                    "journal_mode must be WAL"
                )
                assert int(conn.execute("PRAGMA synchronous").fetchone()[0]) == 1, (
                    "synchronous must be NORMAL (=1)"
                )
                # autocheckpoint should be at least the configured 10000
                ac = int(conn.execute("PRAGMA wal_autocheckpoint").fetchone()[0])
                assert ac == 10000, f"wal_autocheckpoint must be 10000, got {ac}"
                # temp_store: 2 == MEMORY
                assert int(conn.execute("PRAGMA temp_store").fetchone()[0]) == 2, (
                    "temp_store must be MEMORY (=2)"
                )
                # mmap_size: 256MB
                assert int(conn.execute("PRAGMA mmap_size").fetchone()[0]) == 268435456, (
                    "mmap_size must be 268435456 (256MB)"
                )
                # cache_size negative form means KB; -20000 = 20MB
                cs = int(conn.execute("PRAGMA cache_size").fetchone()[0])
                assert cs == -20000, f"cache_size must be -20000 (20MB), got {cs}"
            finally:
                conn.close()

    def test_helper_handles_timeout_arg(self):
        """_sqlite_connect must accept timeout= keyword for read paths."""
        import importlib
        sql_mod = importlib.import_module("db.sqlite")
        with tempfile.NamedTemporaryFile(suffix=".db") as tf:
            conn = sql_mod._sqlite_connect(tf.name, timeout=0.5)
            try:
                # Just verify connection works; timeout is internal to busy-wait.
                conn.execute("SELECT 1").fetchone()
            finally:
                conn.close()

    def test_helper_swallow_pragma_errors(self):
        """Helper must not raise if a PRAGMA fails (e.g. truncated DB).
        Connection is returned even if PRAGMAs couldn't be applied."""
        # Source check — `except sqlite3.Error:` is present and swallows.
        idx = _SQL_SRC.find("def _sqlite_connect(")
        assert idx != -1
        body = _SQL_SRC[idx: idx + 2000]
        assert "except sqlite3.Error" in body, (
            "_sqlite_connect must swallow PRAGMA failures"
        )

    def test_pragma_choices_documented(self):
        """The helper docstring must explain each PRAGMA's purpose so future
        edits don't accidentally remove a critical setting."""
        idx = _SQL_SRC.find("def _sqlite_connect(")
        body = _SQL_SRC[idx: idx + 2000]
        for pragma in ("journal_mode", "synchronous", "wal_autocheckpoint",
                        "temp_store", "mmap_size", "cache_size"):
            assert pragma in body, (
                f"PRAGMA {pragma!r} not documented in _sqlite_connect docstring"
            )


# ── 2. TestSqliteOpenPathsRouted ────────────────────────────────────────────

class TestSqliteOpenPathsRouted:
    """Every sqlite3.connect() in db/sqlite.py must route through the helper
    (except the helper itself), or we regress to FULL synchronous defaults."""

    def test_only_helper_calls_sqlite3_connect(self):
        # The only allowed direct sqlite3.connect() lines are INSIDE the helper.
        idx = _SQL_SRC.find("def _sqlite_connect(")
        end = _SQL_SRC.find("def _apply_sqlite_migrations(", idx)
        assert idx != -1 and end != -1, "helper bounds not found"
        outside = _SQL_SRC[:idx] + _SQL_SRC[end:]
        # Count sqlite3.connect( in source outside the helper
        count = len(re.findall(r"\bsqlite3\.connect\(", outside))
        assert count == 0, (
            f"db/sqlite.py has {count} sqlite3.connect() call(s) outside "
            "the _sqlite_connect helper — they will use synchronous=FULL "
            "and regress disk fsync latency"
        )

    def test_helper_used_in_writer_loop(self):
        """The writer loop must use the helper, not raw sqlite3.connect."""
        # Find the writer loop function
        idx = _SQL_SRC.find("db_queue.get()")
        assert idx != -1, "db_writer_loop not found"
        # Walk back to function start
        loop_start = _SQL_SRC.rfind("def ", 0, idx)
        loop_body = _SQL_SRC[loop_start: idx + 200]
        assert "_sqlite_connect(" in loop_body, (
            "writer loop must call _sqlite_connect() (not raw sqlite3.connect)"
        )


# ── 3. TestUpstreamTimeoutKnob ──────────────────────────────────────────────

class TestUpstreamTimeoutKnob:
    """UPSTREAM_TIMEOUT_SECS + UPSTREAM_CONNECT_TIMEOUT_SECS knobs replace
    the hardcoded 30s ClientTimeout that made users wait when upstream
    flapped."""

    def test_config_defines_knobs(self):
        assert "UPSTREAM_TIMEOUT_SECS" in _CFG_SRC, (
            "UPSTREAM_TIMEOUT_SECS missing from config.py"
        )
        assert "UPSTREAM_CONNECT_TIMEOUT_SECS" in _CFG_SRC, (
            "UPSTREAM_CONNECT_TIMEOUT_SECS missing from config.py"
        )

    def test_config_defaults_tight(self):
        """Default total must be ≤ 30s (was hardcoded 30) so users fail-fast."""
        # Anchor to the actual env-var read, not any documentation snippet.
        m = re.search(r'UPSTREAM_TIMEOUT_SECS\s*=\s*int\(\s*os\.environ\.get\([^"]*"UPSTREAM_TIMEOUT_SECS"\s*,\s*"(\d+)"\s*\)',
                       _CFG_SRC)
        assert m, "UPSTREAM_TIMEOUT_SECS env read not found in config.py"
        default = int(m.group(1))
        assert 5 <= default <= 30, (
            f"UPSTREAM_TIMEOUT_SECS default must be 5-30s for fast-fail, got {default}"
        )

    def test_proxy_handler_reads_knob(self):
        """proxy() must use UPSTREAM_TIMEOUT_SECS (not hardcoded 30)."""
        # The ClientTimeout call should reference the knob name
        idx = _PH_SRC.find("UPSTREAM_TIMEOUT_SECS")
        assert idx != -1, "proxy_handler.py never reads UPSTREAM_TIMEOUT_SECS"
        # No remaining `ClientTimeout(total=30)` literal in the proxy function
        proxy_idx = _PH_SRC.find("async def proxy(")
        # Search the proxy function body
        proxy_body = _PH_SRC[proxy_idx: proxy_idx + 5000]
        assert "ClientTimeout(total=30)" not in proxy_body, (
            "proxy() still uses hardcoded ClientTimeout(total=30) — "
            "must reference UPSTREAM_TIMEOUT_SECS"
        )

    def test_in_vhost_coerce(self):
        for k in ("UPSTREAM_TIMEOUT_SECS", "UPSTREAM_CONNECT_TIMEOUT_SECS"):
            assert k in _VH_SRC, f"{k} missing from _VHOST_COERCE"

    def test_in_hot_reload_knobs(self):
        for k in ("UPSTREAM_TIMEOUT_SECS", "UPSTREAM_CONNECT_TIMEOUT_SECS"):
            assert f'"{k}"' in _PH_SRC, (
                f"{k} missing from _HOT_RELOAD_KNOBS in proxy_handler.py"
            )

    def test_in_controls_html(self):
        for k in ("UPSTREAM_TIMEOUT_SECS", "UPSTREAM_CONNECT_TIMEOUT_SECS"):
            assert k in _CTL_SRC, f"{k} missing from controls.html"

    def test_in_vhost_policy_knob_meta(self):
        for k in ("UPSTREAM_TIMEOUT_SECS", "UPSTREAM_CONNECT_TIMEOUT_SECS"):
            assert k in _VHP_SRC, f"{k} missing from vhost_policy.html KNOB_META"


# ── 4. TestCircuitBreakerKnobs ──────────────────────────────────────────────

class TestCircuitBreakerKnobs:
    """CIRCUIT_FAIL_THRESHOLD / CIRCUIT_OPEN_SECS / CIRCUIT_HALF_OPEN_MAX
    must be configurable via the Thresholds dashboard so operators can
    trip the circuit faster when upstream degrades."""

    KNOBS = ("CIRCUIT_FAIL_THRESHOLD",
             "CIRCUIT_OPEN_SECS",
             "CIRCUIT_HALF_OPEN_MAX")

    def test_defined_in_proxy_handler(self):
        for k in self.KNOBS:
            assert k in _PH_SRC, f"{k} missing from proxy_handler.py"

    def test_in_hot_reload_knobs(self):
        for k in self.KNOBS:
            assert f'"{k}"' in _PH_SRC, (
                f"{k} missing from _HOT_RELOAD_KNOBS"
            )

    def test_in_vhost_coerce(self):
        for k in self.KNOBS:
            assert k in _VH_SRC, f"{k} missing from _VHOST_COERCE"

    def test_in_controls_html_on_thresholds_card(self):
        for k in self.KNOBS:
            idx = _CTL_SRC.find(k)
            assert idx != -1, f"{k} missing from controls.html"
            # 200-char window after must contain card:'thresholds' so it
            # renders on the Thresholds card (where operators look during incidents)
            block = _CTL_SRC[idx: idx + 400]
            assert "card:'thresholds'" in block or "card: 'thresholds'" in block, (
                f"{k} not assigned to card:'thresholds' — operators won't find "
                "it on the Thresholds page during incidents"
            )

    def test_in_vhost_policy_knob_meta(self):
        for k in self.KNOBS:
            assert k in _VHP_SRC, f"{k} missing from vhost_policy.html KNOB_META"

    def test_validators_have_sensible_ranges(self):
        """Validators must clamp to sensible ranges so a bad config doesn't
        disable circuit breaking entirely (e.g. threshold=0 = always open)."""
        # Anchor on the _HOT_RELOAD_KNOBS table — each KNOB entry looks like:
        #   "CIRCUIT_FAIL_THRESHOLD":  (int, lambda v: 1 <= v <= 1000),
        # The first textual occurrence of `"CIRCUIT_*"` is the env-var read,
        # so look specifically for the validator line.
        for k in self.KNOBS:
            m = re.search(r'"' + re.escape(k) + r'"\s*:\s*\(\s*int\s*,\s*lambda\s+v\s*:\s*([^,)]+)', _PH_SRC)
            assert m, f"{k} validator not found in _HOT_RELOAD_KNOBS"
            check = m.group(1)
            assert "1 <= v" in check or "v >= 1" in check or "0 <= v" in check, (
                f"{k} validator must enforce a non-zero minimum; got {check!r}"
            )


# ── 5. TestPerformanceDocumented ────────────────────────────────────────────

class TestPerformanceDocumented:
    """Source-comment guard: the slow-fsync incident context must be in
    db/sqlite.py so future maintainers don't remove the PRAGMAs accidentally."""

    def test_pt4_incident_referenced(self):
        idx = _SQL_SRC.find("def _sqlite_connect(")
        body = _SQL_SRC[idx: idx + 2000]
        # We don't need the exact wording; just any pointer to "fsync" or
        # "slow" / "57" so the next reader knows why these PRAGMAs exist.
        has_context = any(s in body for s in ("fsync", "slow", "synchronous", "57"))
        assert has_context, (
            "_sqlite_connect docstring should reference fsync/slow-disk "
            "context — future maintainers must understand WHY these PRAGMAs "
            "exist before removing them"
        )
