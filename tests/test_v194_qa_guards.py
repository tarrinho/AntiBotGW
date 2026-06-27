"""
1.9.4 QA regression guards
==========================

Turns this release's two real findings into durable guards:

A. CARDINALITY-CAP forward-guard — the OOM vector (rules.md §6e/§15f) was
   unbounded `metrics["by_path"]` / `by_ja4` / `by_path_by_cat[*]` counters keyed
   by attacker-controlled values. The existing v194 test pins the 3 known sites;
   THIS guard is forward-looking: it fails if anyone reintroduces a bare
   `<counter>[<key>] += …` instead of routing through `_bump_capped`.

B. PG SURROGATE behavioural — F1 (audit-log evasion): malformed-UTF-8 in a
   request made psycopg raise UnicodeEncodeError → the event was DROPPED. This
   drives `pg_insert_event` with a surrogate UA/path through a fake pool whose
   `execute()` encodes params EXACTLY like psycopg — so removing the `_pg_safe`
   sanitizer reproduces the original drop (returns False) and fails the test.
   No real Postgres required.
"""
import re
from pathlib import Path

_PROJ = Path(__file__).resolve().parent.parent


# ── A: cardinality-cap forward guard ─────────────────────────────────────────

def test_no_unbounded_attacker_keyed_counter():
    src = (_PROJ / "core" / "metrics.py").read_text(encoding="utf-8")
    # bare `+=` increments on the attacker-keyed counter families are forbidden —
    # they MUST go through _bump_capped (FIFO bound) to keep the OOM guard intact.
    # NB: the key segment uses `\[.+?\]` (not `[^\]]*`) so a nested-bracket key
    # like `by_ja4[ja4[:64]]` is still caught.
    bad_re = re.compile(
        r'(metrics\["by_(?:path|ja4)"\]|by_path_by_cat\[[^\]]+\])\[.+?\]\s*\+='
    )
    offenders = [ln for ln in src.splitlines() if bad_re.search(ln)]
    assert not offenders, (
        "unbounded increment on an attacker-keyed counter — route through "
        "_bump_capped (OOM guard):\n" + "\n".join(offenders)
    )
    # positive anchor: the cap helper is actually used at the known sites
    assert src.count("_bump_capped(") >= 3, \
        "the by_path / by_ja4 / by_path_by_cat counters must use _bump_capped"


# ── B: pg_insert_event sanitizes surrogates (behavioural, no real PG) ─────────

class _PsycopgLikeConn:
    """Fake conn whose execute() encodes every str param to UTF-8 exactly like
    psycopg — a lone surrogate raises UnicodeEncodeError, reproducing F1."""
    def __init__(self):
        self.params = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params):
        for p in params:
            if isinstance(p, str):
                p.encode("utf-8")        # raises on un-sanitized surrogate
        self.params = params
        return self


class _FakePool:
    def __init__(self):
        self.conn = _PsycopgLikeConn()

    def connection(self, timeout=None):
        return self.conn


def test_pg_insert_event_sanitizes_surrogates(proxy_module, monkeypatch):
    import db.postgres as pg
    monkeypatch.setattr(pg, "DB_BACKEND", "postgres")
    pool = _FakePool()
    monkeypatch.setattr(pg, "_get_pool", lambda: pool)

    # surrogate in UA + path — pre-fix this raised in execute → event dropped (False)
    ok = pg.pg_insert_event(
        1.0, "1.2.3.4", "\udcff\udcfe bad-ua", "/\udcfd/path",
        200, "ua-blocked", method="GET", vhost="evil\udcff.test")

    assert ok is True, \
        "surrogate-bearing event must be SANITIZED + written, not dropped"
    # every str param that reached execute is valid UTF-8 (no surrogate leaked)
    assert pool.conn.params is not None, "execute was never called"
    for p in pool.conn.params:
        if isinstance(p, str):
            p.encode("utf-8")            # must not raise
