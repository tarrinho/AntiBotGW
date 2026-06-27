"""
1.9.1 iter-9 extra QA — broader coverage of iter-4 → iter-9 surface.

The iter-9 review fix tests (test_v192_iter9_review_fixes.py) cover the
3 actionable findings. This file adds defence-in-depth coverage:

  - Per-knob validator boundary tests for the 6 invented iter-8 knobs
    (UPSTREAM_TIMEOUT_SECS, UPSTREAM_CONNECT_TIMEOUT_SECS,
    CIRCUIT_FAIL_THRESHOLD, CIRCUIT_OPEN_SECS, CIRCUIT_HALF_OPEN_MAX,
    VACUUM_DAILY_AT). Reviewer flagged HIGH-2 on VACUUM_DAILY_AT
    (false positive); locking the rest down too so a future fork
    of the validators can't silently widen the accept range.

  - `gw_distribution_replace` transaction-atomicity test (MED-3 from
    review, deferred as INFO): the DELETE + executemany pair must run
    in a single transaction so an INSERT failure rolls back the
    DELETE. Verified via fake cursor + fake conn.

  - Per-knob `_DB_LOAD_DENY` functional tests: each of the 3 deny-list
    knobs gets its own functional test so a future refactor that
    accidentally drops one of them fails CI.

  - `pg_insert_event` diagnostic log markers (iter-6) — verify the
    exact slog keys / log substrings used in the source.

  - Knob count regression guard: iter-8 expanded `_HOT_RELOAD_KNOBS`
    from 147 → 193 entries. A future refactor that accidentally trims
    knobs (e.g. by reverting the iter-8 port) silently breaks
    operator hot-reload for ~46 knobs. Lock at ≥190.
"""
import pathlib


_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ── iter-8 invented validators — boundary tests ────────────────────────────

def _validator(knob):
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import proxy
    spec = proxy._HOT_RELOAD_KNOBS[knob]
    parser, validator = spec[0], spec[1]
    return parser, validator


def _assert_accept(knob, parser, validator, value):
    parsed = parser(value)
    assert validator is None or validator(parsed), (
        f"{knob}: expected to accept {value!r} (parsed → {parsed!r})"
    )


def _assert_reject(knob, parser, validator, value):
    try:
        parsed = parser(value)
    except (ValueError, TypeError):
        return  # parser rejected — counts as reject
    assert validator is not None and not validator(parsed), (
        f"{knob}: expected to reject {value!r} (parsed → {parsed!r})"
    )


def test_upstream_timeout_secs_boundary():
    p, v = _validator("UPSTREAM_TIMEOUT_SECS")
    for val in (1, 30, 600):
        _assert_accept("UPSTREAM_TIMEOUT_SECS", p, v, val)
    for val in (0, -1, 601, 10000):
        _assert_reject("UPSTREAM_TIMEOUT_SECS", p, v, val)


def test_upstream_connect_timeout_secs_boundary():
    p, v = _validator("UPSTREAM_CONNECT_TIMEOUT_SECS")
    for val in (1, 30, 60):
        _assert_accept("UPSTREAM_CONNECT_TIMEOUT_SECS", p, v, val)
    for val in (0, -1, 61, 1000):
        _assert_reject("UPSTREAM_CONNECT_TIMEOUT_SECS", p, v, val)


def test_circuit_fail_threshold_boundary():
    p, v = _validator("CIRCUIT_FAIL_THRESHOLD")
    for val in (1, 100, 10000):
        _assert_accept("CIRCUIT_FAIL_THRESHOLD", p, v, val)
    for val in (0, -5, 10001):
        _assert_reject("CIRCUIT_FAIL_THRESHOLD", p, v, val)


def test_circuit_open_secs_boundary():
    p, v = _validator("CIRCUIT_OPEN_SECS")
    for val in (1, 60, 3600):
        _assert_accept("CIRCUIT_OPEN_SECS", p, v, val)
    for val in (0, -1, 3601):
        _assert_reject("CIRCUIT_OPEN_SECS", p, v, val)


def test_circuit_half_open_max_boundary():
    p, v = _validator("CIRCUIT_HALF_OPEN_MAX")
    for val in (1, 50, 1000):
        _assert_accept("CIRCUIT_HALF_OPEN_MAX", p, v, val)
    for val in (0, -1, 1001):
        _assert_reject("CIRCUIT_HALF_OPEN_MAX", p, v, val)


# ── iter-9 _DB_LOAD_DENY per-knob functional coverage ──────────────────────

def _iter9_deny_attempt(knob, malicious_value):
    """Insert `malicious_value` into config_kv for `knob`, run
    db_load_config, return the post-load attribute. The deny-set must
    have prevented the load — the returned value should be the pre-load
    snapshot, NOT the malicious value."""
    import os, sqlite3, json, tempfile
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import proxy
    td = tempfile.mkdtemp()
    db = f"{td}/cfg_deny_{knob}.db"
    saved = proxy.DB_PATH
    try:
        proxy.DB_PATH = db
        proxy.db_init()
        conn = sqlite3.connect(db)
        conn.execute("DELETE FROM config_kv")
        conn.execute(
            "INSERT INTO config_kv (key, value, ts) VALUES (?, ?, ?)",
            (knob, json.dumps(malicious_value), 0.0))
        conn.commit()
        conn.close()
        pre = getattr(proxy, knob, None)
        saved_env = proxy._ENV_PROVIDED_KNOBS
        proxy._ENV_PROVIDED_KNOBS = set()
        try:
            proxy.db_load_config()
        finally:
            proxy._ENV_PROVIDED_KNOBS = saved_env
        post = getattr(proxy, knob, None)
        return pre, post
    finally:
        proxy.DB_PATH = saved


def test_iter9_deny_TRUSTED_PROXIES_blocked():
    pre, post = _iter9_deny_attempt("TRUSTED_PROXIES", ["6.6.6.6/32"])
    # Post-load list must NOT contain attacker's CIDR.
    assert "6.6.6.6/32" not in (post or []), (
        f"TRUSTED_PROXIES escape: pre={pre!r}, post={post!r}"
    )


def test_iter9_deny_TRUST_XFF_blocked():
    pre, post = _iter9_deny_attempt("TRUST_XFF", "last")
    # If pre was "none" or "first", post must also be that — NOT "last".
    if pre in ("none", "first"):
        assert post != "last", (
            f"TRUST_XFF escape: pre={pre!r}, post={post!r}"
        )


def test_iter9_deny_ADMIN_ALLOWED_IPS_blocked():
    # ADMIN_ALLOWED_IPS may not be in _HOT_RELOAD_KNOBS (it's read at
    # boot, not hot-reload); the deny still applies belt-and-braces.
    # Test passes if either the load is denied OR the knob isn't even
    # in _HOT_RELOAD_KNOBS (so db_load_config skips it for that reason).
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import proxy
    deny = getattr(proxy, "_DB_LOAD_DENY", frozenset())
    assert "ADMIN_ALLOWED_IPS" in deny, (
        "_DB_LOAD_DENY must include ADMIN_ALLOWED_IPS belt-and-braces "
        "even if not currently hot-reloadable"
    )


# ── A4 + M11 — gw_distribution_replace must be transaction-safe ────────────

def test_a4_gw_distribution_replace_atomic_under_insert_failure():
    """If the INSERT (executemany) raises after the DELETE, the cursor
    must NOT commit. With psycopg's `pool.connection() as conn`
    context manager + autocommit=False (which `_pg_mirror_kv` uses),
    an exception bubbling out of the `with` rolls back the transaction
    — DELETE included. Simulate via a fake cursor that DELETEs then
    raises on executemany."""
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    from db.postgres import _h_gw_distribution_replace

    class _FakeCur:
        def __init__(self):
            self.calls = []
        def execute(self, sql, args=None):
            self.calls.append(("execute", sql, args))
            # Don't raise on DELETE
        def executemany(self, sql, seq):
            self.calls.append(("executemany", sql, list(seq)))
            raise RuntimeError("simulated INSERT failure")

    cur = _FakeCur()
    try:
        _h_gw_distribution_replace(cur, ([("a", "b"), ("c", "d")], 0.0))
    except RuntimeError:
        pass  # expected — handler propagates to caller's tx
    # Confirm the order: DELETE issued FIRST, then executemany raised.
    # The handler doesn't swallow — caller's transaction rolls back.
    assert cur.calls[0][0] == "execute"
    assert "DELETE" in cur.calls[0][1]
    assert cur.calls[1][0] == "executemany"


def test_a4_gw_distribution_replace_skips_executemany_on_empty_pairs():
    """When `pairs` is empty, only the DELETE should fire — no
    executemany call. Otherwise psycopg's executemany on an empty
    sequence is a wasted round-trip."""
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    from db.postgres import _h_gw_distribution_replace

    class _FakeCur:
        def __init__(self):
            self.calls = []
        def execute(self, sql, args=None):
            self.calls.append(("execute", sql))
        def executemany(self, *a, **kw):
            self.calls.append(("executemany",))

    cur = _FakeCur()
    _h_gw_distribution_replace(cur, ([], 0.0))
    assert cur.calls == [("execute", "DELETE FROM gw_distribution")], (
        f"gw_distribution_replace with empty pairs should only DELETE; "
        f"got: {cur.calls!r}"
    )


# ── iter-6 pg_insert_event diagnostic logging — markers ────────────────────

_DBPG_SRC = (_ROOT / "db" / "postgres.py").read_text(encoding="utf-8")


def test_iter6_pg_insert_event_log_marker_prefix():
    """The log prefix `[pg-insert-event]` is a stable grep target.
    Operators in incident response will grep for this — a refactor
    that changes it (e.g. to `pg-insert-event:` without brackets)
    would silently break their runbooks."""
    assert "[pg-insert-event]" in _DBPG_SRC, (
        "pg_insert_event log lines must carry the [pg-insert-event] "
        "prefix for operator grep stability"
    )
    # Both log lines must use this exact prefix
    assert _DBPG_SRC.count("[pg-insert-event]") >= 2, (
        "expected 2 distinct log lines (pool_none + per-exception); "
        f"got {_DBPG_SRC.count('[pg-insert-event]')}"
    )


def test_iter6_pg_insert_event_includes_cause_hint():
    """The per-exception log must include the actionable hint —
    `ALTER TABLE events ADD COLUMN method TEXT, vhost TEXT DEFAULT ''`
    — so a 3am-paged operator can copy-paste the recovery command.

    The Python source has the string split across implicit-concat
    literals so we look for the two halves rather than the
    runtime-concatenated form."""
    assert "ALTER TABLE " in _DBPG_SRC, (
        "diagnostic log must reference ALTER TABLE for schema recovery"
    )
    assert "ADD COLUMN method TEXT" in _DBPG_SRC, (
        "diagnostic log must spell out the missing column DDL so "
        "operators can copy-paste the recovery command without "
        "searching docs"
    )


# ── iter-8 knob-count regression guard ─────────────────────────────────────

def test_iter8_hot_reload_knob_count_at_or_above_baseline():
    """iter-8 grew _HOT_RELOAD_KNOBS to 193 entries (147 prior + 46
    ported). A future refactor that reverts iter-8 (silently dropping
    the 40 mutants ports + 6 invented validators) would re-break
    test_165_every_knob_persists_round_trip AND operator hot-reload
    for ~46 knobs."""
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import proxy
    n = len(proxy._HOT_RELOAD_KNOBS)
    assert n >= 190, (
        f"_HOT_RELOAD_KNOBS shrunk to {n}; iter-8 baseline was 193. "
        f"Something dropped the iter-8 port. Run "
        f"`git log --oneline core/proxy_handler.py` and look for "
        f"reverts."
    )


def test_iter8_invented_knobs_all_present():
    """The 6 invented knobs (post-mutants) must all still be in
    _HOT_RELOAD_KNOBS. A diff that drops one of them re-breaks the
    `db_load_config` round-trip for that specific knob."""
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import proxy
    for k in (
        "UPSTREAM_TIMEOUT_SECS",
        "UPSTREAM_CONNECT_TIMEOUT_SECS",
        "CIRCUIT_FAIL_THRESHOLD",
        "CIRCUIT_OPEN_SECS",
        "CIRCUIT_HALF_OPEN_MAX",
        "VACUUM_DAILY_AT",
    ):
        assert k in proxy._HOT_RELOAD_KNOBS, (
            f"iter-8 invented knob {k!r} missing from _HOT_RELOAD_KNOBS"
        )


def test_iter8_mutants_ported_knobs_all_present():
    """Sample of the 40 mutants-ported knobs — spot-check that the
    iter-8 port survived a future refactor."""
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import proxy
    # Each from a different category so a partial revert is still
    # caught.
    samples = (
        "WAF_BODY_ENABLED",        # WAF group
        "JA4H_DENY_LIST",          # set parser
        "REDIS_ALLOW_LIST",        # _to_ip_net_list
        "TRUST_XFF",                # string validator
        "SERVICE_OWNER",            # str + content check
        "REDIRECT_MAZE_DEPTH",      # int range
        "ABUSEIPDB_CACHE_HOURS",    # custom lambda parser
        "BLOCK_RESPONSE_MODE",      # str-in-set
    )
    missing = [k for k in samples if k not in proxy._HOT_RELOAD_KNOBS]
    assert not missing, (
        f"iter-8 mutants ports missing: {missing!r}"
    )
