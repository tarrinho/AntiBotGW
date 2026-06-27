"""
tests/test_v1814_vacuum_endpoint_gates.py — server-side QA for the
SQLite-only contract of /secured/db-vacuum and /secured/db-vacuum-history.

Companion to test_v1814_vacuum_sqlite_only.py (which guards the UI). Even
when the dashboard hides the manual button, a stale browser tab, scripted
client, or compromised admin session could POST /db-vacuum directly while
DB_BACKEND=postgres. The backend MUST reject the call cleanly — never run
VACUUM against a SQLite file that is no longer the live event store.

Static + signature-level checks against core/proxy_handler.py and the
router wiring in proxy.py — no live server.
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
HANDLER = os.path.join(_REPO, "core", "proxy_handler.py")
PROXY = os.path.join(_REPO, "proxy.py")


def _src(path):
    return open(path, encoding="utf-8").read()


# ── Endpoint registration ────────────────────────────────────────────────

def test_vacuum_endpoint_registered():
    """Router must wire POST /secured/db-vacuum → db_vacuum_endpoint."""
    src = _src(PROXY)
    assert re.search(
        r'\(\s*"db-vacuum"\s*,\s*"POST"\s*,\s*db_vacuum_endpoint\s*,',
        src,
    ), "POST /db-vacuum must be registered with db_vacuum_endpoint"


def test_vacuum_history_endpoint_registered():
    """Router must wire GET /secured/db-vacuum-history → db_vacuum_history_endpoint."""
    src = _src(PROXY)
    assert re.search(
        r'\(\s*"db-vacuum-history"\s*,\s*"GET"\s*,\s*db_vacuum_history_endpoint\s*,',
        src,
    ), "GET /db-vacuum-history must be registered with db_vacuum_history_endpoint"


# ── Server-side gate: db-vacuum ──────────────────────────────────────────

def test_vacuum_endpoint_rejects_postgres():
    """The db_vacuum_endpoint must short-circuit when DB_BACKEND != 'sqlite'.
    A future refactor that forgets this check would corrupt expectations
    (operator thinks postgres VACUUMed; in reality SQLite file got hit)."""
    src = _src(HANDLER)
    m = re.search(r"async def db_vacuum_endpoint\b.*?\nasync def ",
                  src, re.DOTALL)
    assert m, "db_vacuum_endpoint must exist"
    body = m.group(0)
    # The very first guard inside the function must compare DB_BACKEND.
    assert re.search(
        r'if\s+DB_BACKEND\s*!=\s*[\'"]sqlite[\'"]\s*:\s*\n\s*return\s+web\.json_response',
        body,
    ), (
        "db_vacuum_endpoint must reject with web.json_response when "
        "DB_BACKEND != 'sqlite' — guard must be the first line of the body"
    )


def test_vacuum_endpoint_rejection_uses_400():
    """Reject must be a clean 400 (client should know its request was wrong),
    not 500 (server didn't even know it shouldn't run VACUUM)."""
    src = _src(HANDLER)
    m = re.search(r"async def db_vacuum_endpoint\b.*?\nasync def ",
                  src, re.DOTALL)
    body = m.group(0)
    region = body.split("DB_BACKEND", 1)[1][:400]
    assert "status=400" in region, (
        "DB_BACKEND mismatch must surface as HTTP 400 (operator error), "
        "not 500 (silent server-side failure)"
    )


def test_vacuum_endpoint_rejection_payload_explains():
    """Rejection payload must surface the reason in operator-readable form so
    a scripted client / dashboard can render the cause instead of 'failed'."""
    src = _src(HANDLER)
    m = re.search(r"async def db_vacuum_endpoint\b.*?\nasync def ",
                  src, re.DOTALL)
    body = m.group(0)
    region = body.split("DB_BACKEND", 1)[1][:400]
    assert '"ok": False' in region or "'ok': False" in region, (
        "rejection payload must include ok=False so the UI can branch on it"
    )
    assert "reason" in region.lower() and (
        "sqlite" in region.lower() or "backend" in region.lower()
    ), "rejection payload must name the backend mismatch in the reason"


# ── Server-side gate: db-vacuum-history ──────────────────────────────────

def test_vacuum_history_endpoint_safe_under_postgres():
    """History endpoint MUST NOT open a SQLite connection (or at least must
    short-circuit before doing so) when DB_BACKEND != 'sqlite'. Returning
    an empty list is the agreed contract — UI guards against missing data
    but expects history: [] not a 5xx."""
    src = _src(HANDLER)
    m = re.search(r"async def db_vacuum_history_endpoint\b.*?\nasync def ",
                  src, re.DOTALL)
    assert m, "db_vacuum_history_endpoint must exist"
    body = m.group(0)
    # Must contain a backend guard BEFORE any sqlite3.connect call.
    backend_idx = body.find("DB_BACKEND")
    connect_idx = body.find("sqlite3.connect")
    assert backend_idx != -1, (
        "db_vacuum_history_endpoint must check DB_BACKEND before connecting"
    )
    if connect_idx != -1:
        assert backend_idx < connect_idx, (
            "DB_BACKEND check must come BEFORE sqlite3.connect — otherwise "
            "postgres deployments still hit the SQLite event store path"
        )


def test_vacuum_history_returns_empty_list_on_postgres():
    """The contract is `{history: [], reason: ...}` — the UI render loop
    will gracefully show 'No previous runs' for an empty list."""
    src = _src(HANDLER)
    m = re.search(r"async def db_vacuum_history_endpoint\b.*?\nasync def ",
                  src, re.DOTALL)
    body = m.group(0)
    region = body.split("DB_BACKEND", 1)[1][:400]
    assert re.search(r'"history"\s*:\s*\[\s*\]', region), (
        "history-endpoint must return `history: []` for non-sqlite backends "
        "(NOT a 5xx, NOT a missing key)"
    )


# ── Authorisation hardening ─────────────────────────────────────────────

def test_vacuum_history_requires_role():
    """Even when the endpoint is sqlite-OK, GET /db-vacuum-history must
    enforce admin/maintainer role — otherwise stage history leaks operator
    identity (actor) + timestamps to anonymous callers."""
    src = _src(HANDLER)
    m = re.search(r"async def db_vacuum_history_endpoint\b.*?\nasync def ",
                  src, re.DOTALL)
    body = m.group(0)
    assert "_role_denied" in body, (
        "db_vacuum_history_endpoint must gate behind _role_denied(...)"
    )
    assert '"admin"' in body and '"maintainer"' in body, (
        "history endpoint role gate must accept admin AND maintainer"
    )


# ── Defence-in-depth: both endpoints share the same gate ────────────────

def test_both_endpoints_use_identical_backend_guard():
    """The two endpoints must use the SAME backend predicate so future
    refactors can't drift them apart (e.g. one starts allowing 'duckdb',
    the other doesn't — silent inconsistency)."""
    src = _src(HANDLER)
    guard_re = re.compile(r"if\s+DB_BACKEND\s*!=\s*['\"]sqlite['\"]\s*:")
    m_va = re.search(r"async def db_vacuum_endpoint\b.*?\nasync def ",
                     src, re.DOTALL)
    m_vh = re.search(r"async def db_vacuum_history_endpoint\b.*?\nasync def ",
                     src, re.DOTALL)
    assert m_va and m_vh, "both endpoints must be present"
    assert guard_re.search(m_va.group(0)), (
        "db_vacuum_endpoint must use the canonical guard"
    )
    assert guard_re.search(m_vh.group(0)), (
        "db_vacuum_history_endpoint must use the canonical guard"
    )
