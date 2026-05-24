"""
db/ — Database backend package.
Extracted from proxy.py as part of Phase 2 modular refactoring.

Re-exports the public API so callers can do:
    from db import db_init, db_writer_loop, db_load_secrets, ...
"""

from db.sqlite import (
    db_init,
    db_writer_loop,
    db_load_secrets,
    db_load_config,
    db_load_state,
    _SECRET_KEYS,
    _SCHEMA_MIGRATIONS,
    _apply_sqlite_migrations,
    _refresh_integration_state,
    check_ip_ban,
    prune_ip_bans,
)
from db.postgres import (
    db_init_postgres,
    pg_insert_event,
    pg_db_size,
    pg_test_roundtrip,
    _pg_mirror_kv,
    _migrate_recent_events,
    _apply_pg_migrations,
    _postgres_load_module,
)


# 1.8.8 — Backend-aware event reader. Dispatches to sqlite or postgres
# implementation based on DB_BACKEND + _postgres_available.
#
# Returns a list of dicts. The `ts` field is normalised to epoch float
# regardless of backend (Postgres stores TIMESTAMPTZ, SQLite stores REAL).
#
# Why this exists: every dashboard endpoint (geo-data, logs-data,
# agents-bucket-detail, metrics timeline, health-score) used to hardcode
# `sqlite3.connect(DB_PATH)` for event reads, even when DB_BACKEND=postgres.
# When dual-write failed on one side (slow armv7, transient pg outage, …)
# the dashboards would show stale data with no obvious cause.
#
# Gracefully degrades on Postgres:
#   - `vhost` and `method` filters/columns are skipped (Postgres events
#     schema doesn't carry those columns yet — separate migration).
#   - Falls back to SQLite if DB_BACKEND=postgres but _postgres_available=False.
def db_read_events(
    start_ts: float,
    end_ts: float,
    *,
    columns=None,
    vhost: str = "",
    path_like: str = "",
    reason_like: str = "",
    reason_in=None,
    ip_exact: str = "",
    order_by: str = "",
    limit: int = 0,
    offset: int = 0,
):
    """Backend-aware event reader. See module docstring above for details.

    `reason_like` is a substring (LIKE) match; `reason_in` is an exact-set
    match (`reason IN (...)`). Use `reason_in` when reasons share a prefix
    (e.g. "honeypot" vs "honeypot-silent") to avoid LIKE bleed.
    """
    from db.sqlite import _read_events_sql
    # Resolve backend lazily — DB_BACKEND lives on core.proxy_handler and is
    # mutated by db_switch_endpoint. _postgres_available comes from state.
    import sys as _sys
    _ph = _sys.modules.get("core.proxy_handler")
    backend = getattr(_ph, "DB_BACKEND", "sqlite") if _ph else "sqlite"
    pg_ok = False
    if backend == "postgres":
        _st = _sys.modules.get("state")
        pg_ok = bool(getattr(_st, "_postgres_available", False)) if _st else False
    if backend == "postgres" and pg_ok:
        try:
            from db.postgres import _read_events_pg
            return _read_events_pg(
                start_ts, end_ts,
                columns=columns, vhost=vhost,
                path_like=path_like, reason_like=reason_like,
                reason_in=reason_in,
                ip_exact=ip_exact, order_by=order_by,
                limit=limit, offset=offset,
            )
        except Exception as e:
            # Fall back to SQLite — never let a postgres read error
            # leave the dashboard with no data.
            from helpers import slog
            slog("db_read_events_pg_fallback", level="warn",
                 error=f"{type(e).__name__}: {str(e)[:120]}")
    return _read_events_sql(
        start_ts, end_ts,
        columns=columns, vhost=vhost,
        path_like=path_like, reason_like=reason_like,
        reason_in=reason_in,
        ip_exact=ip_exact, order_by=order_by,
        limit=limit, offset=offset,
    )


async def db_read_events_async(*args, **kwargs):
    """Async wrapper for db_read_events — runs the synchronous SQLite/Postgres
    read in a thread-pool executor so a large dashboard query (e.g. the 50k-row
    honeypot scan, every 30 s per open dashboard) never blocks the aiohttp event
    loop and stalls concurrent requests. Same signature/return as db_read_events.
    (Improvement #3: get blocking DB I/O off the event loop.)"""
    import asyncio
    import functools
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, functools.partial(db_read_events, *args, **kwargs))


# 1.8.8 — per-backend write-health probe.  Returns:
#   {
#     "sqlite":   {"last_event_ts": float|None, "events_rows": int, "ok": bool},
#     "postgres": {"last_event_ts": float|None, "events_rows": int, "ok": bool,
#                  "available": bool, "configured": bool},
#     "active_backend": "sqlite" | "postgres",
#     "lag_seconds": float | None,  # how far behind the trailing backend is
#     "healthy": bool,              # True iff lag_seconds < 60s OR only one backend in use
#   }
# Used by /db-test to surface silent dual-write breakage in the popup.
def db_health_snapshot() -> dict:
    """Probe both backends for write health. See module docstring."""
    import sys as _sys
    import time as _t
    from db.sqlite import _events_health_sql
    out = {
        "sqlite":   _events_health_sql(),
        "postgres": {"last_event_ts": None, "events_rows": 0,
                     "ok": False, "available": False, "configured": False},
        "active_backend": "sqlite",
        "lag_seconds": None,
        "healthy": True,
    }
    _ph = _sys.modules.get("core.proxy_handler")
    if _ph:
        out["active_backend"] = getattr(_ph, "DB_BACKEND", "sqlite")
    _st = _sys.modules.get("state")
    pg_avail = bool(getattr(_st, "_postgres_available", False)) if _st else False
    out["postgres"]["available"] = pg_avail
    out["postgres"]["configured"] = bool(getattr(_ph, "POSTGRES_DSN", "")) if _ph else False
    if pg_avail:
        try:
            from db.postgres import _events_health_pg
            out["postgres"].update(_events_health_pg())
        except Exception as e:
            from helpers import slog
            slog("db_health_pg_failed", level="warn",
                 error=f"{type(e).__name__}: {str(e)[:120]}")
    # Compute lag between backends — only meaningful when both have data.
    # 1.8.9 (L2) — use directional diff so we identify WHICH side is
    # trailing. abs() previously caused the popup to label the wrong
    # side as "behind" under host-clock skew. `trailing_backend` is the
    # side whose last_event_ts is older; `lag_seconds` is the absolute
    # difference (kept abs so the popup's threshold check is direction-
    # agnostic — what we care about is "how stale is the trailing side").
    s_ts = out["sqlite"].get("last_event_ts")
    p_ts = out["postgres"].get("last_event_ts")
    if s_ts is not None and p_ts is not None:
        lag = abs(s_ts - p_ts)
        out["lag_seconds"] = round(lag, 1)
        out["trailing_backend"] = "sqlite" if s_ts < p_ts else (
            "postgres" if p_ts < s_ts else None
        )
        out["healthy"] = lag < 60.0
    elif out["active_backend"] == "postgres" and not pg_avail:
        out["healthy"] = False
    return out
