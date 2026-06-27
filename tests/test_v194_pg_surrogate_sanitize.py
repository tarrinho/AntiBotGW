"""
1.9.4 — PG write-path surrogate / invalid-UTF-8 sanitization (F1 + F2)
=====================================================================

Dynamic fuzzing (rules.md §15f) found that a request carrying lone surrogates /
invalid UTF-8 in UA or path made psycopg raise UnicodeEncodeError when writing
the event (and the client upsert), so the row was DROPPED from the Postgres
store. Impact: an attacker could evade the PG audit log / SIEM by sending
malformed UTF-8 (F1); the same failure surfaced as a misleading
`db_pg_op_unhandled op='upsert_client'` warn (F2).

`_pg_safe` / `_pg_safe_args` replace un-encodable code points before the SQL
execute, at both PG-write entry points (`pg_insert_event` and `_pg_dispatch_op`).

Coverage
────────
B1  _pg_safe: surrogates → encodable; valid str / non-str / dict preserved
B2  _pg_safe_args: sanitizes a writer-op args tuple
B3  source: pg_insert_event applies _pg_safe to its string params
B4  source: _pg_dispatch_op applies _pg_safe_args before the handler
"""
from pathlib import Path

_PROJ = Path(__file__).resolve().parent.parent


def test_pg_safe_handles_surrogates(proxy_module):
    from db.postgres import _pg_safe
    bad = "\udcff\udcfe\x00evil"          # lone surrogates + null (what fuzzing makes)
    # precondition: raw value is NOT utf-8 encodable
    raised = False
    try:
        bad.encode("utf-8")
    except UnicodeEncodeError:
        raised = True
    assert raised, "test premise: raw surrogate string must be un-encodable"
    # after sanitize it IS encodable (no UnicodeEncodeError → no dropped row)
    safe = _pg_safe(bad)
    safe.encode("utf-8")                  # must not raise
    # valid / non-string / dict preserved
    assert _pg_safe("normal/path?a=1") == "normal/path?a=1"
    assert _pg_safe(200) == 200
    assert _pg_safe(None) is None
    assert _pg_safe({"ua": bad, "n": 5})["ua"].encode("utf-8") is not None


def test_pg_safe_args_sanitizes_tuple(proxy_module):
    from db.postgres import _pg_safe_args
    out = _pg_safe_args(("\udcff", 7, "ok", None))
    assert out[0].encode("utf-8") is not None   # surrogate cleaned
    assert out[1] == 7 and out[2] == "ok" and out[3] is None


def test_source_pg_insert_event_sanitizes():
    src = (_PROJ / "db" / "postgres.py").read_text(encoding="utf-8")
    fn = src[src.index("def pg_insert_event("):]
    fn = fn[:fn.index("\ndef ", 1)]
    assert "_pg_safe(ip)" in fn and "_pg_safe(reason" in fn, \
        "pg_insert_event must wrap its request-derived strings in _pg_safe"


def test_source_dispatch_sanitizes():
    src = (_PROJ / "db" / "postgres.py").read_text(encoding="utf-8")
    fn = src[src.index("def _pg_dispatch_op("):]
    fn = fn[:fn.index("\ndef ", 1) if "\ndef " in fn[1:] else len(fn)]
    assert "_pg_safe_args(args)" in fn, \
        "_pg_dispatch_op must sanitize args before calling the handler"
