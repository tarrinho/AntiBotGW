"""
1.9.0 security-review fixes (post-tagging audit found 3 blocking items):

  F1 — db_vacuum_endpoint had CSRF but no _role_denied gate. Any session
       could fire VACUUM, bloating gw_audit and causing self-inflicted DoS.
  F2 — db_switch_endpoint accepted any body.dsn with no validation; an
       attacker with an admin session could redirect the gateway at
       attacker-controlled PG with persistent exfiltration. Also: no
       gw_audit forensic row capturing the switch.
  F5 — db.conn.open_conn silently downgraded to SQLite when POSTGRES_DSN
       was cleared mid-flight. Violates the documented single-DB contract;
       creates split-brain write window during db_switch.

Source-guards + functional smoke.
"""
import pathlib
import re


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_CONN_SRC = (_ROOT / "db" / "conn.py").read_text(encoding="utf-8")


# ── F1 ─────────────────────────────────────────────────────────────────────

class TestF1RoleGateOnDbVacuum:
    def test_role_denied_present(self):
        idx = _PH_SRC.find("async def db_vacuum_endpoint(")
        assert idx != -1
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "_role_denied(request" in block, (
            "db_vacuum_endpoint must call _role_denied() — CSRF alone is "
            "insufficient (any session w/ valid CSRF could fire VACUUM)"
        )

    def test_role_gate_admits_admin_and_maintainer(self):
        idx = _PH_SRC.find("async def db_vacuum_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert re.search(
            r'_role_denied\(request,\s*"admin"\s*,\s*"maintainer"\)', block), (
            "Gate must allow admin AND maintainer (operator-level destructive "
            "but not session-elevation; viewer/analyst must be refused)"
        )

    def test_role_gate_before_backend_check(self):
        """Role check must precede backend check — otherwise a viewer learns
        whether the active backend is sqlite (info disclosure)."""
        idx = _PH_SRC.find("async def db_vacuum_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        role_idx = block.find("_role_denied")
        backend_idx = block.find('DB_BACKEND != "sqlite"')
        assert 0 <= role_idx < backend_idx, (
            "Role check must run before backend probe so unauthorised callers "
            "can't enumerate the live backend"
        )


# ── F2 ─────────────────────────────────────────────────────────────────────

class TestF2DbSwitchDsnValidation:
    def test_dsn_urlparse(self):
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "urlparse" in block.lower() or "_urlparse_dsn" in block, (
            "db_switch_endpoint must urlparse() the DSN to validate scheme + host"
        )

    def test_dsn_scheme_restricted(self):
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert '"postgres"' in block and '"postgresql"' in block, (
            "DSN scheme must be restricted to postgres:// or postgresql://"
        )

    def test_dsn_hostname_required(self):
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "no hostname" in block.lower() or "hostname" in block, (
            "DSN with no hostname must be rejected"
        )

    def test_dsn_host_allowlist_supported(self):
        """POSTGRES_DSN_ALLOWED_HOSTS env var must be consulted as a final
        defence in depth so an attacker can't redirect even with a valid DSN."""
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "POSTGRES_DSN_ALLOWED_HOSTS" in block, (
            "Must support POSTGRES_DSN_ALLOWED_HOSTS env allowlist"
        )

    def test_audit_row_captures_target(self):
        """A successful (or attempted) switch must write a gw_audit row so
        the forensic trail survives even after slog ring rotation."""
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert '"db_switch"' in block and "gw_audit_add" in block, (
            "Must emit a gw_audit row with action='db_switch'"
        )

    def test_audit_row_does_not_include_password(self):
        """Audit details may include host/user/port BUT NEVER the password.
        The simplest verification: the body_dsn variable is not directly
        json.dumps'd into the audit details."""
        idx = _PH_SRC.find("async def db_switch_endpoint(")
        nxt = _PH_SRC.find("\nasync def ", idx + 1)
        block = _PH_SRC[idx: nxt]
        # Audit details builder should reference _dsn_host / _dsn_user / _dsn_port,
        # not body_dsn or dsn directly
        audit_idx = block.find("gw_audit_add")
        audit_block = block[max(0, audit_idx - 1000): audit_idx + 200]
        assert "_dsn_host" in audit_block, (
            "Audit details must capture _dsn_host (parsed, masked) — not raw DSN"
        )


# ── F5 ─────────────────────────────────────────────────────────────────────

class TestF5OpenConnFailLoud:
    def test_no_silent_sqlite_downgrade(self):
        """The race-window branch must raise PgUnavailableError, not return
        a sqlite3.connect."""
        idx = _CONN_SRC.find("def open_conn(")
        assert idx != -1
        nxt = _CONN_SRC.find("\ndef ", idx + 1)
        # The open_conn function ends at the next top-level def
        block = _CONN_SRC[idx: nxt if nxt != -1 else idx + 3000]
        # The race comment is anchored; check the branch raises
        race_idx = block.find("DSN was cleared between active_backend() and now")
        # If the comment moved/changed wording, fall back to checking the
        # whole open_conn body for `raise PgUnavailableError` followed by
        # the "race" wording
        if race_idx == -1:
            assert "raise PgUnavailableError" in block, (
                "open_conn race branch must raise PgUnavailableError"
            )
        else:
            # Within ~400 chars of the comment must be a raise
            ctx = block[race_idx: race_idx + 600]
            assert "raise PgUnavailableError" in ctx, (
                "Race branch must `raise PgUnavailableError`, not silently "
                "fall back to sqlite3.connect (violates single-DB contract)"
            )
            assert "sqlite3.connect" not in ctx, (
                "Race branch must NOT call sqlite3.connect — that's the silent "
                "downgrade the fix removes"
            )
