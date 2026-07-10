"""
1.9.1 iter-11 — BAN_SCOPE per-vhost ban blast-radius.

A new knob `BAN_SCOPE` controls whether a behaviour-earned ban applies
fleet-wide (default "global", current behaviour) or only to the vhost
where the bad behaviour was observed ("vhost").

Approach B — a SEPARATE `ip_bans_vhost` table (composite PK (ip, vhost))
holds vhost-scoped bans; the legacy `ip_bans` table is untouched, so the
change is additive (no PK rebuild, safe rollback). PG schema bumps 1→2,
tolerated by the A5 ±1 check.

These tests lock:
  - knob registered in BOTH _HOT_RELOAD_KNOBS and _VHOST_COERCE
  - knob validator accepts global/vhost, rejects junk
  - new dispatch ops (ip_ban_vhost / ip_ban_vhost_del) wired with correct
    arity + handlers + dual-write membership + golden coverage
  - IpState carries banned_until_by_vhost
  - schema: ip_bans_vhost CREATE present in both backends; PG_SCHEMA_VERSION==2
  - check_ip_ban_vhost exported + functional (point lookup)
  - default is "global" → backward-compatible
"""
import pathlib


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC   = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_VH_SRC   = (_ROOT / "vhost.py").read_text(encoding="utf-8")
_DBSQ_SRC = (_ROOT / "db" / "sqlite.py").read_text(encoding="utf-8")
_DBPG_SRC = (_ROOT / "db" / "postgres.py").read_text(encoding="utf-8")
_STATE_SRC = (_ROOT / "state.py").read_text(encoding="utf-8")
_SCORING_SRC = (_ROOT / "scoring.py").read_text(encoding="utf-8")


# ── Knob registration ──────────────────────────────────────────────────────

def test_ban_scope_default_is_global():
    """Backward-compat: default MUST be 'global' so existing installs
    behave identically after upgrade until an operator opts in."""
    import os
    os.environ.pop("BAN_SCOPE", None)
    # Re-import config fresh-ish; value is module-level so read it directly.
    import importlib, config
    importlib.reload(config)
    assert config.BAN_SCOPE == "global", (
        f"BAN_SCOPE default must be 'global', got {config.BAN_SCOPE!r}"
    )


def test_ban_scope_in_hot_reload_knobs():
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import proxy
    assert "BAN_SCOPE" in proxy._HOT_RELOAD_KNOBS, (
        "BAN_SCOPE must be hot-reloadable via _HOT_RELOAD_KNOBS"
    )
    parser, validator = proxy._HOT_RELOAD_KNOBS["BAN_SCOPE"]
    assert validator(parser("global"))
    assert validator(parser("vhost"))
    assert validator(parser("VHOST"))          # case-insensitive
    assert not validator(parser("everywhere"))  # junk rejected
    assert not validator(parser(""))


def test_ban_scope_in_vhost_coerce():
    """Per-vhost overridable — operator can set BAN_SCOPE per hostname
    in the VHOSTS JSON."""
    assert '"BAN_SCOPE"' in _VH_SRC, (
        "BAN_SCOPE must be in vhost.py _VHOST_COERCE so it's per-vhost "
        "overridable"
    )


# ── State ──────────────────────────────────────────────────────────────────

def test_ipstate_has_banned_until_by_vhost():
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    from state import IpState
    s = IpState()
    assert hasattr(s, "banned_until_by_vhost"), (
        "IpState must carry banned_until_by_vhost for vhost-scoped bans"
    )
    assert isinstance(s.banned_until_by_vhost, dict)
    assert s.banned_until_by_vhost == {}, "must default to empty dict"


# ── Schema (both backends) ─────────────────────────────────────────────────

def test_sqlite_ip_bans_vhost_table_defined():
    assert "CREATE TABLE IF NOT EXISTS ip_bans_vhost" in _DBSQ_SRC, (
        "db/sqlite.py must CREATE the ip_bans_vhost table"
    )
    # Composite PK so same IP can be banned on one vhost, free on another.
    assert "PRIMARY KEY (ip, vhost)" in _DBSQ_SRC


def test_pg_ip_bans_vhost_table_defined():
    assert "CREATE TABLE IF NOT EXISTS ip_bans_vhost" in _DBPG_SRC, (
        "db/postgres.py must CREATE the ip_bans_vhost table"
    )
    assert "PRIMARY KEY (ip, vhost)" in _DBPG_SRC


def test_pg_schema_version_bumped_to_2():
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import db.postgres as pg
    assert pg.PG_SCHEMA_VERSION == 2, (
        "PG_SCHEMA_VERSION must bump 1→2 for the additive ip_bans_vhost "
        "table (A5 tolerates the ±1 skew on rollback)"
    )


def test_legacy_ip_bans_table_untouched():
    """Approach B invariant: the legacy ip_bans table keeps its single-
    column PK (ip). A change there would force a destructive rebuild."""
    assert "CREATE TABLE IF NOT EXISTS ip_bans (\n        ip            TEXT PRIMARY KEY" in _DBSQ_SRC, (
        "legacy ip_bans must keep `ip TEXT PRIMARY KEY` — approach B does "
        "NOT alter it (additive new table only)"
    )


# ── Dispatch ops ───────────────────────────────────────────────────────────

def test_ip_ban_vhost_ops_arity_and_handlers():
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import db.postgres as pg
    assert pg._OP_ARITY.get("ip_ban_vhost") == 5, (
        "ip_ban_vhost arity must be 5 (ip, vhost, banned_until, reason, ts)"
    )
    assert pg._OP_ARITY.get("ip_ban_vhost_del") == 2, (
        "ip_ban_vhost_del arity must be 2 (ip, vhost)"
    )
    assert "ip_ban_vhost" in pg._PG_OP_HANDLERS
    assert "ip_ban_vhost_del" in pg._PG_OP_HANDLERS


def test_ip_ban_vhost_in_dual_write_ops():
    """Both new ops must be in _PG_DUAL_WRITE_OPS so a SQLite-primary
    deployment still mirrors vhost bans to PG (and M3 coverage passes)."""
    assert '"ip_ban_vhost"' in _DBSQ_SRC, (
        "ip_ban_vhost must be in _PG_DUAL_WRITE_OPS"
    )
    assert '"ip_ban_vhost_del"' in _DBSQ_SRC


def test_sqlite_writer_handles_ip_ban_vhost():
    assert 'elif op == "ip_ban_vhost":' in _DBSQ_SRC, (
        "SQLite writer-loop must handle the ip_ban_vhost op"
    )
    assert "INSERT INTO ip_bans_vhost" in _DBSQ_SRC
    # Monotonic-max so a shorter ban never shrinks a longer one.
    assert "ON CONFLICT(ip,vhost) DO UPDATE" in _DBSQ_SRC


# ── check_ip_ban_vhost ─────────────────────────────────────────────────────

def test_check_ip_ban_vhost_exported():
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    from db import check_ip_ban_vhost
    assert callable(check_ip_ban_vhost)


def test_check_ip_ban_vhost_point_lookup():
    """Functional: insert a vhost ban, confirm the point lookup returns
    the expiry for the matching vhost and 0 for a different vhost."""
    import os, sqlite3, tempfile, time
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import db.sqlite as sq
    td = tempfile.mkdtemp()
    db = f"{td}/ipbv.db"
    saved = sq.DB_PATH
    try:
        sq.DB_PATH = db
        # Minimal schema for this table.
        conn = sqlite3.connect(db)
        conn.execute("""CREATE TABLE ip_bans_vhost (
            ip TEXT NOT NULL, vhost TEXT NOT NULL, banned_until REAL NOT NULL,
            reason TEXT, ts REAL NOT NULL, PRIMARY KEY(ip, vhost))""")
        future = time.time() + 3600
        conn.execute(
            "INSERT INTO ip_bans_vhost VALUES (?,?,?,?,?)",
            ("1.2.3.4", "shop.example.com", future, "test", time.time()))
        conn.commit()
        conn.close()
        # Banned on shop, free on api.
        assert sq.check_ip_ban_vhost("1.2.3.4", "shop.example.com") > 0
        assert sq.check_ip_ban_vhost("1.2.3.4", "api.example.com") == 0.0
        # Unknown IP free everywhere.
        assert sq.check_ip_ban_vhost("9.9.9.9", "shop.example.com") == 0.0
    finally:
        sq.DB_PATH = saved


def test_check_ip_ban_vhost_ignores_expired():
    import os, sqlite3, tempfile, time
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import db.sqlite as sq
    td = tempfile.mkdtemp()
    db = f"{td}/ipbv2.db"
    saved = sq.DB_PATH
    try:
        sq.DB_PATH = db
        conn = sqlite3.connect(db)
        conn.execute("""CREATE TABLE ip_bans_vhost (
            ip TEXT NOT NULL, vhost TEXT NOT NULL, banned_until REAL NOT NULL,
            reason TEXT, ts REAL NOT NULL, PRIMARY KEY(ip, vhost))""")
        past = time.time() - 10  # already expired
        conn.execute(
            "INSERT INTO ip_bans_vhost VALUES (?,?,?,?,?)",
            ("1.2.3.4", "shop.example.com", past, "test", time.time()))
        conn.commit()
        conn.close()
        assert sq.check_ip_ban_vhost("1.2.3.4", "shop.example.com") == 0.0, (
            "expired vhost ban must not block"
        )
    finally:
        sq.DB_PATH = saved


# ── Ban logic wiring ───────────────────────────────────────────────────────

def test_scoring_resolves_ban_scope():
    """scoring.py must have the _resolve_ban_scope helper that reads
    BAN_SCOPE via vc() and the current vhost."""
    assert "_resolve_ban_scope" in _SCORING_SRC, (
        "scoring.py must resolve ban scope per request"
    )
    # ban() + update_risk_and_maybe_ban() must both queue the vhost op.
    assert _SCORING_SRC.count("ip_ban_vhost") >= 2, (
        "both ban() and update_risk_and_maybe_ban() must queue ip_ban_vhost "
        "when scope is vhost"
    )


def test_is_banned_checks_vhost_map():
    """is_banned() must honour banned_until_by_vhost when scope=vhost."""
    assert "banned_until_by_vhost" in _SCORING_SRC, (
        "is_banned must consult the per-vhost ban map under BAN_SCOPE=vhost"
    )


def test_protect_gate_uses_check_ip_ban_vhost():
    """The protect() ban-gate must call check_ip_ban_vhost when
    BAN_SCOPE=vhost — but only after the global check (global ban always
    wins, backward-compatible)."""
    assert "check_ip_ban_vhost" in _PH_SRC, (
        "protect() ban-gate must consult check_ip_ban_vhost under "
        "BAN_SCOPE=vhost"
    )
    assert "vc('BAN_SCOPE') == 'vhost'" in _PH_SRC, (
        "the vhost ban lookup must be gated on the resolved BAN_SCOPE knob"
    )


def test_prune_ip_bans_also_prunes_vhost_table():
    """11b DoS fix: prune_ip_bans must also DELETE expired rows from
    ip_bans_vhost so vhost-scoped bans don't accumulate unbounded."""
    idx = _DBSQ_SRC.find("def prune_ip_bans")
    end = _DBSQ_SRC.find("\ndef ", idx + 1)
    body = _DBSQ_SRC[idx:end if end > 0 else len(_DBSQ_SRC)]
    assert "DELETE FROM ip_bans_vhost WHERE banned_until" in body, (
        "prune_ip_bans must also prune expired ip_bans_vhost rows "
        "(11b unbounded-growth finding)"
    )


def test_prune_ip_bans_vhost_functional():
    """Functional: an expired vhost ban is removed by prune_ip_bans;
    an active one survives."""
    import os, sqlite3, tempfile, time
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import db.sqlite as sq
    td = tempfile.mkdtemp()
    db = f"{td}/prune.db"
    saved = sq.DB_PATH
    try:
        sq.DB_PATH = db
        conn = sqlite3.connect(db)
        conn.execute("""CREATE TABLE ip_bans (ip TEXT PRIMARY KEY,
            banned_until REAL NOT NULL, reason TEXT, ts REAL NOT NULL)""")
        conn.execute("""CREATE TABLE ip_bans_vhost (ip TEXT NOT NULL,
            vhost TEXT NOT NULL, banned_until REAL NOT NULL, reason TEXT,
            ts REAL NOT NULL, PRIMARY KEY(ip, vhost))""")
        now = time.time()
        conn.execute("INSERT INTO ip_bans_vhost VALUES (?,?,?,?,?)",
                     ("1.1.1.1", "a.test", now - 10, "old", now))   # expired
        conn.execute("INSERT INTO ip_bans_vhost VALUES (?,?,?,?,?)",
                     ("2.2.2.2", "b.test", now + 3600, "live", now)) # active
        conn.commit()
        conn.close()
        sq.prune_ip_bans()
        conn = sqlite3.connect(db)
        rows = conn.execute("SELECT ip FROM ip_bans_vhost").fetchall()
        conn.close()
        ips = {r[0] for r in rows}
        assert "1.1.1.1" not in ips, "expired vhost ban must be pruned"
        assert "2.2.2.2" in ips, "active vhost ban must survive prune"
    finally:
        sq.DB_PATH = saved


def test_default_global_does_not_touch_vhost_table():
    """Belt-and-braces: with BAN_SCOPE unset (global), the scoring path
    must NOT emit ip_ban_vhost ops. Source check: the vhost queue is
    inside an `if _vhost_scoped:` branch."""
    assert "_vhost_scoped" in _SCORING_SRC, (
        "ip_ban_vhost emission must be guarded by a _vhost_scoped flag so "
        "the default global path never writes to ip_bans_vhost"
    )


# ── iter-11b: per-vhost risk accumulation (TRUE isolation) ──────────────────

def test_ipstate_has_risk_by_vhost():
    """The per-vhost risk accumulator field must exist on IpState; without it
    the ban decision falls back to the global score and carries over."""
    assert "risk_by_vhost" in _STATE_SRC, (
        "IpState must carry a risk_by_vhost accumulator for per-vhost isolation"
    )


def test_scoring_evaluates_per_vhost_score_when_scoped():
    """Under vhost scope the threshold must be checked against the per-vhost
    accumulator (_eval_score = risk_by_vhost[...]), NOT the global risk_score."""
    assert "risk_by_vhost" in _SCORING_SRC and "_eval_score" in _SCORING_SRC, (
        "vhost-scoped ban decision must use a per-vhost _eval_score"
    )


def _run_scoped_risk(hits):
    """Drive update_risk_and_maybe_ban under forced BAN_SCOPE=vhost.
    `hits` is a list of (vhost, reason). Returns the IpState after the run."""
    import os, asyncio
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import scoring
    from scoring import update_risk_and_maybe_ban, ip_state
    from vhost import _vhost_host_ctx, current_vhost_host
    tk = "iter11b-test-identity"
    ip = "203.0.113.7"
    ip_state.pop(tk, None)  # clean slate
    saved = scoring._resolve_ban_scope
    scoring._resolve_ban_scope = lambda: ("vhost", current_vhost_host() or "")

    async def run():
        for vh, reason in hits:
            _vhost_host_ctx.set(vh)
            await update_risk_and_maybe_ban(tk, reason, ip)
        return ip_state[tk]
    try:
        return asyncio.run(run())
    finally:
        scoring._resolve_ban_scope = saved
        ip_state.pop(tk, None)


def test_risk_does_not_carry_across_vhosts():
    """CORE isolation guarantee: an identity hammered to a ban on vhost A is
    NOT banned on vhost B after a few LIGHT hits whose per-vhost score stays
    below threshold — even though the global score is far above threshold."""
    FOO, BAR = "foo.test", "bar.test"
    # 8x suspicious-path(50) → foo banned, global score huge.
    # 3x behavior(8)=24 on bar → below the 50 threshold for bar alone.
    s = _run_scoped_risk(
        [(FOO, "suspicious-path")] * 8 + [(BAR, "behavior")] * 3
    )
    assert s.banned_until_by_vhost.get(FOO, 0.0) > 0, "foo must be banned"
    assert s.risk_score >= 50, "global score should be well above threshold"
    assert s.risk_by_vhost.get(BAR, 0.0) < 50, "bar per-vhost score must stay low"
    assert s.banned_until_by_vhost.get(BAR, 0.0) == 0.0, (
        "bar must NOT be banned: risk earned on foo must not carry over"
    )


def test_per_vhost_detection_still_bans_on_own_crossing():
    """Inverse guard: isolation must not blind a vhost — once a vhost's OWN
    per-vhost score crosses the threshold it bans normally."""
    FOO, BAR = "foo.test", "bar.test"
    # 7x behavior(8)=56 on bar ≥ 50 → bar bans on its own merit.
    s = _run_scoped_risk(
        [(FOO, "suspicious-path")] * 8 + [(BAR, "behavior")] * 7
    )
    assert s.risk_by_vhost.get(BAR, 0.0) >= 50
    assert s.banned_until_by_vhost.get(BAR, 0.0) > 0, (
        "bar must ban when its own per-vhost score crosses the threshold"
    )
