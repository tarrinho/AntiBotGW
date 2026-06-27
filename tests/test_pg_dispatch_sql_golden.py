"""
Golden-SQL harness for `db.postgres._pg_dispatch_op`.

Why this exists
---------------
The dispatch ladder is a 365-line if/elif chain that emits raw INSERT /
UPDATE / DELETE strings to PG. A refactor (A4: dispatch → registry pattern)
or an accidental edit to any handler can silently drop a column from an
INSERT, swap `DO UPDATE` for `DO NOTHING`, reorder args so the row stores
garbage, or break the `GREATEST()` semantic in `ip_ban`. The existing
coverage tests check that every op ROUTES to *some* arm — they do NOT
check that the arm emits the EXACT SQL.

This harness closes that gap. For every op in `_OP_ARITY`:
  1. Build a representative args tuple (one entry per op below).
  2. Run dispatch with a capturing cursor that records every
     `cur.execute(sql, params)` and `cur.executemany(sql, seq)` call.
  3. Normalise the captured SQL (collapse whitespace).
  4. Compare against a golden snapshot in `tests/golden/pg_dispatch_sql.json`.

When you intentionally change a handler, regenerate the golden:

    UPDATE_GOLDEN=1 pytest tests/test_pg_dispatch_sql_golden.py

Review the diff in the JSON file BEFORE committing — a one-character change
to an `ON CONFLICT` clause is the kind of thing a reviewer must consciously
sign off on, not something to autopilot through.

For the A4 refactor specifically, the workflow is:
  1. Before the refactor: golden is checked in (today's SQL).
  2. After the refactor: re-run the suite without `UPDATE_GOLDEN`.
  3. Identical output → refactor preserved semantics → safe to ship.
  4. Different output → manually audit every drift, then regenerate.
"""
import json
import os
import pathlib
import re

import pytest


_ROOT          = pathlib.Path(__file__).resolve().parent.parent
_GOLDEN_PATH   = _ROOT / "tests" / "golden" / "pg_dispatch_sql.json"
_UPDATE_GOLDEN = os.environ.get("UPDATE_GOLDEN", "").lower() in (
    "1", "true", "yes")


# ── Canonical sample args per op ────────────────────────────────────────────
#
# One entry per op in `_OP_ARITY` (db/postgres.py). Args must satisfy the
# arity check (M11) AND be plausibly real-shaped so the captured SQL looks
# like what production emits. Where an op accepts a variable dict
# (user_update, gw_registry_update), use the FULL whitelisted column set so
# the dynamic SQL shape is exercised end-to-end.

_SAMPLE_ARGS = {
    "set_config":                   ("knob_x", "\"on\"", 1700000000),
    "del_config":                   ("knob_x",),
    "set_secret":                   ("ABUSEIPDB_KEY", "k123", 1700000000),
    "del_secret":                   ("ABUSEIPDB_KEY",),
    "set_admin_ip":                 ("10.0.0.0/24", 1700000000, "office",
                                     "manual", "HQ office range"),
    "del_admin_ip":                 ("10.0.0.0/24",),
    "update_admin_ip_description":  ("new desc", "10.0.0.0/24"),
    "gw_audit_add":                 (1700000000, "db_switch", "gw-01",
                                     "alice", '{"target":"postgres"}'),
    "honey_fp_add":                 (1700000000, "trackkey",
                                     "203.0.113.5", "curl/8", "ja4-x",
                                     "AS64500", "/honeypot", "fp-x"),
    # user_create — 6-tuple, fixed shape
    "user_create":                  ("alice", "bcrypt$x", "admin",
                                     "active", 1700000000, 1700000000),
    # user_update — (username, full whitelist dict)
    "user_update":                  ("alice", {
        "password_hash":     "bcrypt$y",
        "role":              "maintainer",
        "status":            "disabled",
        "totp_secret":       "secret-x",
        "totp_enabled":      1,
        "totp_backup_codes": '["a","b"]',
        "oidc_sub":          "sub-x",
        "sso_source":        "okta",
        "updated_ts":        1700000000,
    }),
    "user_delete":                  ("alice",),
    "user_login_recorded":          (1700000000, "203.0.113.5", "alice"),
    "user_session_create":          ("sid-x", "alice", "203.0.113.5",
                                     "ua-x", 1700000000, 1700000000,
                                     1700000300, "csrf-x"),
    "user_session_touch":           (1700000300, "sid-x"),
    "user_session_revoke":          ("sid-x", "admin", 1700000400),
    "ban":                          ("203.0.113.5", 1700000600,
                                     "abusive_ja3", 1700000000),
    "ip_ban":                       ("203.0.113.5", 1700000600,
                                     "manual_ban", 1700000000),
    "ip_ban_del":                   ("203.0.113.5",),
    "ip_ban_vhost":                 ("203.0.113.5", "shop.example.com",
                                     1700000600, "manual_ban", 1700000000),
    "ip_ban_vhost_del":             ("203.0.113.5", "shop.example.com"),
    "dlp_add":                      ("ccn_re", "\\b\\d{16}\\b", "high",
                                     1700000000, "alice"),
    "dlp_toggle":                   (0, 42),
    "dlp_delete":                   (42,),
    "siem_alert_rule_add":          ("requests_per_min", ">", 1000.0,
                                     "burst", 1700000000, "alice", 300),
    "siem_alert_rule_del":          (7,),
    "siem_alert_fired":             (7, 1700000000, 1500.0),
    "siem_alert_toggle":            (1, 7),
    # gw_registry_add — 14-tuple
    "gw_registry_add":              ("gw-02", "node2.example.com",
                                     "eu-west", "prod", "active", 1,
                                     "pubkey-x", "privkey-x",
                                     1700000000, 1700000000, 1700000000,
                                     1700000000, 1700000000, 0),
    # gw_registry_update — (gw_id, full whitelist dict)
    "gw_registry_update":           ("gw-02", {
        "domain":         "node2.example.com",
        "region":         "eu-west",
        "environment":    "prod",
        "status":         "active",
        "can_distribute": 1,
        "public_key":     "pubkey-x",
        "private_key":    "privkey-x",
        "key_created_ts": 1700000000,
        "key_rotated_ts": 1700000000,
        "last_seen_ts":   1700000000,
        "updated_ts":     1700000000,
        "is_local":       0,
        "auto_apply":     1,
    }),
    "gw_registry_delete":           ("gw-02",),
    "gw_distribution_replace":      ([("gw-01", "gw-02"),
                                      ("gw-01", "gw-03")], 1700000000),
    "abuseipdb_set":                ("203.0.113.5", 50, "US", 1700000000),
    "audit_log":                    (1700000000, "login_success",
                                     "alice", "/dashboard",
                                     "203.0.113.5", "{}", "sid-x",
                                     "info"),
    "gw_registry_discover":         ("gw-04", 1700000000),
    "mesh_sync_pending_upsert":     (1700000000, "gw-01",
                                     "FEODO_ENABLED", "true"),
    "mesh_sync_status":             (15, "confirmed", 1700000000),
    "set_kv":                       ("total_requests", "12345"),
    # svc_metric — 35-tuple
    "svc_metric":                   (1700000000,) + tuple(
        range(1, 35)),
    "svc_metric_prune":             (1699900000,),
    "upsert_client":                ("203.0.113.5", 1700000000,
                                     1700000300, 50, 30, 20,
                                     1700000600, "ua-x", "/path",
                                     "vhost-x", '{"r":1}'),
    "upsert_timeline":              (28333333, 100, 80, 20, 5,
                                     '{"abusive":3}'),
}


def _normalise_sql(sql: str) -> str:
    """Collapse whitespace runs to a single space + strip. Stable across
    minor reformatting (the dispatch ladder has lots of multi-line SQL with
    indentation that shifts on edits). The golden cares about TOKENS, not
    formatting."""
    return re.sub(r"\s+", " ", sql).strip()


class _CapturingCursor:
    """Records every (sql, params) tuple emitted by an op's dispatch arm.
    Single-use per op (one cursor → one op → 1+ executes)."""

    def __init__(self):
        self.calls = []   # list of {"kind": "execute"|"executemany",
                          #          "sql": str, "params": <serialisable>}

    def execute(self, sql, params=None):
        self.calls.append({
            "kind":   "execute",
            "sql":    _normalise_sql(sql),
            "params": _to_jsonable(params),
        })

    def executemany(self, sql, seq_of_params):
        self.calls.append({
            "kind":   "executemany",
            "sql":    _normalise_sql(sql),
            "params": [_to_jsonable(p) for p in seq_of_params],
        })

    # Make `with conn.cursor() as cur:` work.
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _to_jsonable(p):
    """Convert psycopg params (tuples / lists / scalars) to a JSON-stable
    shape. Tuples → lists; dicts stay; everything else passes through if
    str/int/float/bool/None."""
    if p is None:
        return None
    if isinstance(p, (tuple, list)):
        return [_to_jsonable(x) for x in p]
    if isinstance(p, dict):
        return {k: _to_jsonable(v) for k, v in sorted(p.items())}
    if isinstance(p, (str, int, float, bool)):
        return p
    return repr(p)


def _capture_op(op, args):
    """Run `_pg_dispatch_op(op, args, cur)` against a capturing cursor and
    return the list of captured calls. Imports lazily so the module loads
    fine even when psycopg isn't installed (the dispatch is pure-Python)."""
    from db.postgres import _pg_dispatch_op
    cur = _CapturingCursor()
    ok = _pg_dispatch_op(op, args, cur)
    return {"dispatched": bool(ok), "calls": cur.calls}


def _build_full_snapshot() -> dict:
    """Dispatch every op in _SAMPLE_ARGS and assemble the snapshot."""
    snap = {}
    for op in sorted(_SAMPLE_ARGS.keys()):
        args = _SAMPLE_ARGS[op]
        snap[op] = _capture_op(op, args)
    return snap


# ── Tests ───────────────────────────────────────────────────────────────────

def test_sample_args_covers_every_dispatch_op():
    """Every op in `_OP_ARITY` (the M11 declared op table) must have a
    canonical sample in `_SAMPLE_ARGS`. New op added without a sample =
    test fail = forces the contributor to think about its SQL contract."""
    from db.postgres import _OP_ARITY
    declared = set(_OP_ARITY.keys())
    sampled  = set(_SAMPLE_ARGS.keys())
    missing  = declared - sampled
    extra    = sampled - declared
    assert not missing, (
        f"_SAMPLE_ARGS missing entries for ops declared in _OP_ARITY: "
        f"{sorted(missing)}. Add a representative args tuple."
    )
    assert not extra, (
        f"_SAMPLE_ARGS has entries for ops NOT in _OP_ARITY: "
        f"{sorted(extra)}. Either remove the sample or add the op to "
        f"_OP_ARITY."
    )


def test_dispatch_sql_matches_golden():
    """Golden-SQL regression: every op's dispatch arm must produce the
    SAME normalised SQL + params as the checked-in snapshot.

    If this fails:
      - You changed a handler intentionally → review the diff in the
        JSON file, then regenerate: `UPDATE_GOLDEN=1 pytest <this file>`
      - You did NOT change a handler → genuine regression. Audit your
        diff for an accidental SQL change.
    """
    snap = _build_full_snapshot()
    if _UPDATE_GOLDEN:
        _GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_GOLDEN_PATH, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2, sort_keys=True)
            f.write("\n")
        pytest.skip(
            f"UPDATE_GOLDEN=1 — wrote {_GOLDEN_PATH.relative_to(_ROOT)}; "
            f"re-run WITHOUT UPDATE_GOLDEN to verify the new snapshot."
        )
    if not _GOLDEN_PATH.exists():
        # First-ever run: write the golden + xfail with a clear message so
        # the contributor commits it.
        _GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_GOLDEN_PATH, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2, sort_keys=True)
            f.write("\n")
        pytest.fail(
            f"Golden snapshot did not exist; wrote initial baseline to "
            f"{_GOLDEN_PATH.relative_to(_ROOT)}. Commit it, then re-run."
        )
    with open(_GOLDEN_PATH, encoding="utf-8") as f:
        golden = json.load(f)
    # Compare per-op so the failure message points at the exact op that
    # drifted (a top-level dict equality assertion would dump the whole
    # 200-line snapshot).
    diffs = []
    for op in sorted(set(snap) | set(golden)):
        if snap.get(op) != golden.get(op):
            diffs.append(op)
    if diffs:
        # Build a focused diff message for the first few drifting ops.
        details = []
        for op in diffs[:5]:
            details.append(f"\n--- op: {op} ---")
            details.append(f"GOLDEN: {json.dumps(golden.get(op), indent=2)}")
            details.append(f"NOW:    {json.dumps(snap.get(op), indent=2)}")
        more = "" if len(diffs) <= 5 else (
            f"\n... and {len(diffs) - 5} more drifting ops not shown.")
        raise AssertionError(
            f"PG dispatch SQL drift detected in {len(diffs)} op(s): "
            f"{diffs}\n"
            f"If intentional, regenerate: UPDATE_GOLDEN=1 pytest "
            f"tests/test_pg_dispatch_sql_golden.py"
            + "".join(details) + more
        )


def test_every_op_emits_at_least_one_sql_call():
    """Sanity: no op should be a silent no-op. If a handler degenerates
    (e.g. an `if fields: ...` block fires zero rows on the sample args)
    that's a fail — the sample must exercise the handler."""
    snap = _build_full_snapshot()
    silent = [op for op, r in snap.items() if not r["calls"]]
    assert not silent, (
        f"These ops emitted no SQL calls — sample args probably don't "
        f"exercise the handler body: {silent}"
    )


def test_no_handler_uses_python_string_format_for_table_names():
    """Hygiene: no handler should be concatenating a user-controllable
    table or column name into the SQL via f-string or %-format. The two
    `f"UPDATE … {cols} WHERE …"` sites (in _h_user_update and
    _h_gw_registry_update) use WHITELISTED column names — but if a
    future refactor accidentally drops the whitelist, this test would
    NOT catch the regression (the SQL is still string-formatted, just
    from a now-untrusted source).

    A4 — post-refactor: the dispatch ladder is gone; SQL lives in
    per-op `_h_*` handler functions. Scan the whole module for f-string
    UPDATE writes and assert exactly the two known whitelisted sites
    survive. Any additional `f"...{var}..."` SQL concatenation gets
    surfaced for review."""
    src = (_ROOT / "db" / "postgres.py").read_text(encoding="utf-8")
    # Count f"...UPDATE {var} SET {var}..." style strings module-wide.
    fstr_writes = re.findall(
        r'f"UPDATE\s+\w+\s+SET\s+\{[^"]+\}\s+WHERE',
        src)
    assert len(fstr_writes) == 2, (
        f"Expected exactly 2 f-string UPDATE sites in db/postgres.py "
        f"(_h_user_update + _h_gw_registry_update, both column-"
        f"whitelisted via _USER_MUTABLE / _GW_MUTABLE), "
        f"found {len(fstr_writes)}: {fstr_writes}. A new site needs a "
        f"column whitelist + review."
    )
    # Defensive: those two sites must live inside _h_* handlers, NOT
    # somewhere unrelated.
    for site in ("_h_user_update", "_h_gw_registry_update"):
        i = src.find(f"def {site}(")
        assert i > 0, f"A4 handler {site} missing"
        j = src.find("\ndef ", i + 1)
        body = src[i:j if j > 0 else len(src)]
        assert re.search(
            r'f"UPDATE\s+\w+\s+SET\s+\{[^"]+\}\s+WHERE', body), (
            f"A4: expected f-string UPDATE inside {site}, not found"
        )


def test_golden_file_is_checked_in_and_nontrivial():
    """The golden file must exist in tree and cover a non-trivial number
    of ops. Catches the case where a contributor runs UPDATE_GOLDEN=1 by
    accident on an empty snapshot."""
    assert _GOLDEN_PATH.exists(), (
        f"Golden snapshot missing at {_GOLDEN_PATH.relative_to(_ROOT)}. "
        f"Generate with: UPDATE_GOLDEN=1 pytest "
        f"tests/test_pg_dispatch_sql_golden.py"
    )
    with open(_GOLDEN_PATH, encoding="utf-8") as f:
        golden = json.load(f)
    assert isinstance(golden, dict)
    assert len(golden) >= 30, (
        f"Golden has only {len(golden)} ops — likely truncated or "
        f"regenerated against a broken dispatch. Expect 39+."
    )
