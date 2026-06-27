"""1.9.2 iter-24 — geo_data_endpoint PG TIMESTAMPTZ projection guard.

Operator-reported bug: "in the Geomap I'm not seeing any events" (on a PG-mode
deployment). Root cause: geo_data_endpoint's WHERE clause was fixed in iter-17
to wrap epoch ints in `to_timestamp(?)`, but the SELECT projection still read
the raw `ts` column. On PG that column is TIMESTAMPTZ, so `r["ts"]` returned
a `datetime.datetime` object. Downstream code does
`int((float(r["ts"]) - start_epoch) / _anim_step)` — `float(datetime)` raises
`TypeError`, the outer except swallows it, and the endpoint returns an empty
points dict. Operator sees no events on the map.

This is the same bug class as the iter-17/18 PG-mirrored-table read sweep
(see memory `antibotproxy-pg-mirrored-table-reads.md`); the WHERE side was
patched, the SELECT side was missed.

Fix: PG branch projects `EXTRACT(EPOCH FROM ts) AS ts` so r["ts"] is a float
on both backends. SQLite branch unchanged.

These source-anchor tests pin the contract so a future refactor cannot revert
to the bare `SELECT ts, ip, reason FROM events` pattern on PG.
"""
import pathlib

_ROOT = pathlib.Path(__file__).parent.parent


def _slice(src: str, signature: str, max_chars: int = 6000) -> str:
    idx = src.find(signature)
    assert idx >= 0, f"{signature!r} not found"
    return src[idx:idx + max_chars]


def test_geo_data_pg_branch_projects_ts_as_epoch_float():
    """PG branch must `EXTRACT(EPOCH FROM ts) AS ts` so downstream
    `float(r["ts"])` works on both backends. Catches a regression that
    drops the projection back to bare `SELECT ts, ip, reason`."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def geo_data_endpoint")
    # Find the PG branch SQL string literal
    pg_idx = body.find('if _be_geo == "postgres":')
    assert pg_idx > 0, "PG branch marker missing in geo_data_endpoint"
    pg_block = body[pg_idx:pg_idx + 600]
    assert "EXTRACT(EPOCH FROM ts) AS ts" in pg_block, \
        "PG branch must project ts via EXTRACT(EPOCH FROM ts) AS ts; " \
        "see memory antibotproxy-pg-mirrored-table-reads"


def test_geo_data_sqlite_branch_unchanged_bare_ts():
    """SQLite branch keeps the bare `SELECT ts, ip, reason` since `ts` is
    REAL there. This pin makes it obvious the two branches diverge."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def geo_data_endpoint")
    else_idx = body.find('else:\n                _geo_sql')
    assert else_idx > 0, "SQLite-branch marker missing"
    else_block = body[else_idx:else_idx + 400]
    assert "SELECT ts, ip, reason FROM events" in else_block


def test_geo_data_pg_branch_wraps_bounds_with_to_timestamp():
    """iter-17 contract preserved: PG branch wraps bind parameters in
    to_timestamp(?). Together with the iter-24 projection fix, this is the
    pair of edits required for any read of `events.ts`."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def geo_data_endpoint")
    pg_idx = body.find('if _be_geo == "postgres":')
    pg_block = body[pg_idx:pg_idx + 600]
    assert "to_timestamp(?)" in pg_block


def test_geo_drill_pg_branch_was_already_correct():
    """Sibling endpoint geo_drill_endpoint had the EXTRACT projection from
    its iter-17 sweep — confirm it didn't regress while we were fixing
    geo_data_endpoint."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def geo_drill_endpoint")
    pg_idx = body.find('if _be_geom == "postgres":')
    pg_block = body[pg_idx:pg_idx + 600]
    assert "EXTRACT(EPOCH FROM ts) AS ts" in pg_block
    assert "to_timestamp(?)" in pg_block


def test_both_branches_use_open_conn_not_bare_sqlite_connect():
    """The bug class memory says: bare `sqlite3.connect(DB_PATH)` against a
    PG-mirrored table returns silently empty. Both geo endpoints must route
    through `open_conn()` so the backend-aware wrapper picks PG when active."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    for fn in ("async def geo_data_endpoint", "async def geo_drill_endpoint"):
        body = _slice(src, fn)
        # The string `conn = open_conn()` must appear inside the try block
        assert "conn = open_conn()" in body, \
            f"{fn} must call open_conn() — see memory antibotproxy-pg-mirrored-table-reads"
        # And NO bare sqlite3.connect( call should appear in this function body
        assert "sqlite3.connect(" not in body, \
            f"{fn} has a bare sqlite3.connect — would silent-empty in PG mode"
