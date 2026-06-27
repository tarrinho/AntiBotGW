"""
tests/test_v191_iter18_mirrored_table_guard.py — broad guard against
bare-`sqlite3.connect` reads of ANY PG-mirrored table.

The iter-17 guard only scanned `FROM events`. That left a blind spot:
~24 operational tables are mirrored to Postgres, and in PG-only mode the
writer "never touches SQLite" (db/sqlite.py db_writer_loop docstring) —
so a read of `svc_metrics`, `users`, `config_kv`, `gw_audit`, etc. via a
direct `sqlite3.connect(DB_PATH)` returns an EMPTY local file. No error,
just silently-blank dashboards (the iter-12 / iter-16 / iter-17 bug
class, repeated for every non-events table).

iter-18 fixed 5 such sites (svc_metrics history chart, OIDC SSO
provisioning, config_kv dismissed-hosts read + write, gw_audit log
viewer). This guard makes sure no NEW one slips in.

Detection: for every bare `sqlite3.connect(...)` / `_sq3.connect(...)`
in production code, look ±18 lines for a `FROM|INTO|UPDATE <table>`
where `<table>` is PG-mirrored. If found AND the connect isn't an
explicitly SQLite-only path (guarded by `DB_BACKEND != "sqlite"` or in
the documented allow-list), it's a finding.

To add a new SQLite-only read of a mirrored table (rare — e.g. a
VACUUM-history endpoint that is meaningless on PG), guard it with an
early `if DB_BACKEND != "sqlite": return …` OR add it to
`_SQLITE_ONLY_ALLOWLIST` with a comment.
"""

from __future__ import annotations

import os
import re


_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── PG-mirrored tables ─────────────────────────────────────────────────
# Source of truth: every table that has a write handler in
# db/postgres.py (`_h_*` → `INSERT INTO <t>` / `UPDATE <t>` / `DELETE
# FROM <t>`). Reading these via local SQLite is wrong in PG-only mode.
def _derive_mirrored_tables() -> set:
    pg = open(os.path.join(_REPO, "db", "postgres.py"), encoding="utf-8").read()
    tables = set()
    for m in re.finditer(
        r"\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+([a-z_]+)",
        pg, re.IGNORECASE,
    ):
        tables.add(m.group(1).lower())
    # Drop obvious non-tables / temp names if any slipped in.
    tables.discard("")
    return tables


# Computed once at import.
_MIRRORED = _derive_mirrored_tables()

# Files that legitimately do direct SQLite (the backend impl itself, the
# import/export CLIs whose source/target IS a SQLite file).
_SKIP_FILES = (
    "db/sqlite.py", "db/postgres.py", "db/import.py", "db/export.py",
    "db/conn.py", "db/cli_helpers.py",
)

# Explicit allow-list: (file, line-anchor-substring) sites that read a
# mirrored table via direct SQLite ON PURPOSE because they early-return
# when the active backend isn't SQLite. Each MUST have an
# `if DB_BACKEND != "sqlite"` (or equivalent) guard above the connect.
_SQLITE_ONLY_ALLOWLIST = {
    # db_vacuum_history: VACUUM is a SQLite-only maintenance op; the
    # endpoint returns `{"history": [], "reason": "active backend is not
    # SQLite"}` before the read when DB_BACKEND != "sqlite".
    ("core/proxy_handler.py", "db_vacuum_history"),
}


_CONN_RE = re.compile(
    r"(sqlite3\.connect|_sq3\.connect|_sq_imp\.connect)\s*\(",
)
_TBL_RE = re.compile(r"\b(?:FROM|INTO|UPDATE)\s+([a-z_]+)", re.IGNORECASE)
_BACKEND_GUARD_RE = re.compile(
    r'DB_BACKEND\s*!=\s*[\'"]sqlite[\'"]|'
    r'active_backend\(\)\s*!=\s*[\'"]sqlite[\'"]|'
    r'_be\w*\s*!=\s*[\'"]sqlite[\'"]',
)


def _iter_prod_files():
    for root, _dirs, files in os.walk(_REPO):
        rel_root = os.path.relpath(root, _REPO)
        if rel_root == ".":
            for fn in files:
                if fn in ("proxy.py", "rate_limit.py"):
                    yield fn, open(os.path.join(root, fn), encoding="utf-8").read()
            continue
        top = rel_root.split(os.sep, 1)[0]
        if top not in ("admin", "core", "dashboards", "scoring", "detection"):
            continue
        for fn in files:
            if fn.endswith(".py"):
                rel = os.path.relpath(os.path.join(root, fn), _REPO).replace(os.sep, "/")
                yield rel, open(os.path.join(root, fn), encoding="utf-8").read()


def _enclosing_func_has_backend_guard(lines, conn_idx) -> bool:
    """Walk backwards from the connect line to the enclosing `def`/`async
    def` and check whether a `DB_BACKEND != "sqlite"` early-return guard
    appears between the def and the connect."""
    i = conn_idx
    while i >= 0:
        stripped = lines[i].lstrip()
        if stripped.startswith("def ") or stripped.startswith("async def "):
            break
        i -= 1
    block = "\n".join(lines[i:conn_idx + 1])
    return bool(_BACKEND_GUARD_RE.search(block))


def _func_name_at(lines, conn_idx) -> str:
    i = conn_idx
    while i >= 0:
        m = re.match(r"\s*(?:async\s+)?def\s+([a-zA-Z_][\w]*)", lines[i])
        if m:
            return m.group(1)
        i -= 1
    return ""


# ── Tests ──────────────────────────────────────────────────────────────


def test_mirrored_table_set_is_sane():
    """Sanity: the derived mirrored-table set must include the core
    operational tables. If db/postgres.py is refactored such that these
    drop out, the guard would silently weaken."""
    for t in ("events", "users", "config_kv", "svc_metrics", "gw_audit",
              "clients", "timeline", "audit_events", "admin_ips", "bans"):
        assert t in _MIRRORED, (
            f"expected `{t}` in the PG-mirrored set derived from "
            f"db/postgres.py — guard would miss reads of it otherwise"
        )


def test_no_bare_sqlite_read_of_pg_mirrored_table():
    """The core guard: no production bare-sqlite connect may read a
    PG-mirrored table unless it's an explicitly SQLite-only path."""
    findings = []
    for rel, src in _iter_prod_files():
        if rel in _SKIP_FILES:
            continue
        lines = src.splitlines()
        for i, ln in enumerate(lines):
            if ln.lstrip().startswith("#"):
                continue
            if not _CONN_RE.search(ln):
                continue
            lo, hi = max(0, i - 18), min(len(lines), i + 25)
            window = "\n".join(
                x for x in lines[lo:hi] if not x.lstrip().startswith("#")
            )
            touched = {m.group(1).lower() for m in _TBL_RE.finditer(window)}
            mirrored_hit = touched & _MIRRORED
            if not mirrored_hit:
                continue
            # Allow if explicitly SQLite-only (backend guard in the
            # enclosing function) …
            if _enclosing_func_has_backend_guard(lines, i):
                continue
            # … or on the allow-list.
            fn = _func_name_at(lines, i)
            if any(rel == af and (anchor in fn or anchor in window)
                   for af, anchor in _SQLITE_ONLY_ALLOWLIST):
                continue
            findings.append(
                f"{rel}:{i + 1} (in {fn or '?'}): bare sqlite read of "
                f"PG-mirrored {sorted(mirrored_hit)} — returns EMPTY in "
                f"PG-only mode. Route through `open_conn()` or guard with "
                f"`if DB_BACKEND != 'sqlite': return`."
            )
    assert not findings, (
        "found bare-sqlite reads of PG-mirrored tables (silent-empty in "
        "PG-only mode):\n" + "\n".join(findings)
    )


def test_iter18_allowlist_entries_are_backend_guarded():
    """Every allow-list entry must actually have the backend guard it
    claims — so the allow-list can't be abused to silence a real bug."""
    for af, anchor in _SQLITE_ONLY_ALLOWLIST:
        src = open(os.path.join(_REPO, af), encoding="utf-8").read()
        # Find the function by anchor, confirm a backend guard precedes
        # its sqlite connect.
        idx = src.find(anchor)
        assert idx != -1, f"allow-list anchor `{anchor}` not found in {af}"
        # Look from the anchor to the next ~1500 chars for both the guard
        # and the connect.
        region = src[idx:idx + 1500]
        assert _BACKEND_GUARD_RE.search(region), (
            f"{af}:{anchor} is allow-listed but has no "
            f"`DB_BACKEND != 'sqlite'` guard — remove from allow-list or "
            f"add the guard"
        )


# ── iter-18 specific fix anchors ───────────────────────────────────────


def test_iter18_svc_metrics_history_uses_open_conn():
    src = open(os.path.join(_REPO, "dashboards", "service_metrics.py"),
               encoding="utf-8").read()
    blk = src[src.find("db_buckets: dict = {}"):
              src.find("[svc-metrics] db history error")]
    # Strip comment lines so our own "old code was `_sq3.connect`" note
    # doesn't trip the negative check below.
    code = "\n".join(l for l in blk.splitlines() if not l.lstrip().startswith("#"))
    assert "_open_conn_sm" in code or "open_conn(" in code, (
        "svc_metrics history read must route through open_conn (was bare "
        "_sq3.connect → empty Service-page chart in PG-only mode)"
    )
    assert "_sq3.connect(_DATA_PATH)" not in code, (
        "svc_metrics history must NOT fall back to bare local-SQLite connect"
    )


def test_iter18_oidc_sso_provisioning_branches_by_backend():
    src = open(os.path.join(_REPO, "admin", "oidc.py"), encoding="utf-8").read()
    # The SSO pending-provisioning write.
    idx = src.find("status='pending', sso_source='oidc'")
    assert idx != -1, "OIDC SSO provisioning comment anchor lost"
    blk = src[idx:idx + 1400]
    assert "_active_sso" in blk or "active_backend" in blk, (
        "OIDC SSO provisioning must check active_backend"
    )
    assert "ON CONFLICT (username) DO NOTHING" in blk, (
        "OIDC SSO provisioning PG branch must use ON CONFLICT — "
        "`INSERT OR IGNORE` is SQLite-only and fails on PG"
    )
    assert "open_conn" in blk, (
        "OIDC SSO provisioning must use open_conn, not bare sqlite3.connect "
        "(pending user row was written to the wrong DB in PG-only mode)"
    )
    # SQLite branch preserved.
    assert "INSERT OR IGNORE INTO users" in blk


def test_iter18_config_kv_dismissed_read_uses_open_conn():
    src = open(os.path.join(_REPO, "admin", "settings.py"),
               encoding="utf-8").read()
    # vhost-stats dismissed read.
    idx = src.find("_open_conn_ds")
    assert idx != -1, (
        "config_kv dismissed-hosts read must use open_conn alias _open_conn_ds"
    )


def test_iter18_config_kv_dismissed_write_branches_by_backend():
    src = open(os.path.join(_REPO, "admin", "settings.py"),
               encoding="utf-8").read()
    idx = src.find("_active_dw")
    assert idx != -1, "config_kv dismissed write must check active_backend"
    blk = src[idx:idx + 1200]
    assert "ON CONFLICT (key) DO UPDATE" in blk, (
        "config_kv dismissed-write PG branch must use ON CONFLICT — "
        "`INSERT OR REPLACE` is SQLite-only"
    )
    assert "INSERT OR REPLACE INTO config_kv" in blk, (
        "config_kv dismissed-write SQLite branch must be preserved"
    )


def test_iter18_gw_audit_log_viewer_uses_open_conn():
    src = open(os.path.join(_REPO, "admin", "settings.py"),
               encoding="utf-8").read()
    idx = src.find("_open_conn_ga")
    assert idx != -1, (
        "gw_audit log viewer must route through open_conn alias _open_conn_ga"
    )
    blk = src[idx:idx + 600]
    assert "FROM gw_audit" in blk, (
        "the _open_conn_ga connection must be the one reading gw_audit"
    )
