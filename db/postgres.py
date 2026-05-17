"""
db/postgres.py — PostgreSQL / TimescaleDB integration.
Extracted from proxy.py as part of Phase 2 modular refactoring.

Dependency rule: imports from config.py and state.py only (plus stdlib).
"""

import logging as _logging
import os as _os
import queue as _queue
import sqlite3
import threading as _threading
import time as _t
from contextlib import contextmanager

from config import (
    DB_BACKEND,
    DB_PATH,
    POSTGRES_DSN,
)
import state as _state

# ── Pool configuration ─────────────────────────────────────────────────────
_PG_POOL_SIZE    = int(_os.environ.get("PG_POOL_SIZE",    "5"))
_PG_POOL_TIMEOUT = float(_os.environ.get("PG_POOL_TIMEOUT", "2.0"))

# ── Postgres module reference (lazy-loaded) ────────────────────────────────
# Mirror of the state.py attributes; accessed via _state module so
# all callers share one live reference.
#   _state._postgres          — the psycopg module, or None
#   _state._postgres_available — bool: psycopg loaded AND DSN set
#   _state._postgres_pool     — the _PgPool singleton (H3 fix)

# ── Schema migration registry ──────────────────────────────────────────────
# Imported here so _apply_pg_migrations can reference it.
# The list is defined in db/sqlite.py (single source of truth).
from db.sqlite import _SCHEMA_MIGRATIONS


def _postgres_load_module():
    """Import psycopg lazily so SQLite users don't take the import cost.
    Returns the module on success, None on failure."""
    if _state._postgres is not None:
        return _state._postgres
    try:
        import psycopg                                           # type: ignore
        _state._postgres = psycopg
        return _state._postgres
    except ImportError:
        return None


# ── Connection pool ────────────────────────────────────────────────────────

class _PgPool:
    """Thread-safe bounded connection pool (psycopg v3 sync, autocommit=True).

    Connections validated on acquire with a lightweight ping. Dead
    connections are discarded and replaced up to the pool size cap.
    Acquisition blocks at most PG_POOL_TIMEOUT seconds before raising.
    """

    def __init__(self, dsn: str, size: int, connect_timeout: float = 5.0):
        self._dsn = dsn
        self._connect_timeout = connect_timeout
        self._idle: _queue.LifoQueue = _queue.LifoQueue(maxsize=size)  # LIFO = warmest conn first
        self._lock = _threading.Lock()
        self._total = 0   # connections in pool + in use
        self._max = size

    def _connect(self):
        pg = _postgres_load_module()
        return pg.connect(self._dsn,
                          connect_timeout=self._connect_timeout,
                          autocommit=True)

    def _ping(self, conn) -> bool:
        try:
            conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    @contextmanager
    def connection(self, timeout: float = _PG_POOL_TIMEOUT):
        """Acquire a pooled connection; release on exit, discard on exception."""
        conn = self._acquire(timeout)
        try:
            yield conn
            self._release(conn)
        except Exception:
            self._discard(conn)
            raise

    def _acquire(self, timeout: float):
        # Fast path: take an idle connection.
        try:
            conn = self._idle.get_nowait()
            if self._ping(conn):
                return conn
            self._discard(conn)
        except _queue.Empty:
            pass

        # Under limit: create a fresh connection.
        with self._lock:
            if self._total < self._max:
                self._total += 1
                do_create = True
            else:
                do_create = False

        if do_create:
            try:
                return self._connect()
            except Exception:
                with self._lock:
                    self._total -= 1
                raise

        # At max: wait for one to be returned.
        try:
            conn = self._idle.get(timeout=timeout)
        except _queue.Empty:
            raise TimeoutError(
                f"PG pool exhausted (max={self._max}, timeout={timeout}s)"
            ) from None
        if self._ping(conn):
            return conn
        # Returned connection is dead — replace it inline.
        self._discard(conn)
        try:
            return self._connect()
        except Exception:
            with self._lock:
                self._total -= 1
            raise

    def _release(self, conn) -> None:
        """Return a healthy connection to the idle queue."""
        try:
            self._idle.put_nowait(conn)
        except _queue.Full:
            self._discard(conn)

    def _discard(self, conn) -> None:
        """Close a connection and free its slot."""
        with self._lock:
            self._total -= 1
        try:
            conn.close()
        except Exception:
            pass

    @property
    def stats(self) -> dict:
        return {"total": self._total, "idle": self._idle.qsize(), "max": self._max}


def _get_pool() -> "_PgPool | None":
    """Return the module-level pool, creating it on first call."""
    if _state._postgres_pool is not None:
        return _state._postgres_pool
    if not POSTGRES_DSN or _postgres_load_module() is None:
        return None
    pool = _PgPool(POSTGRES_DSN, size=_PG_POOL_SIZE)
    _state._postgres_pool = pool
    return pool


def pg_pool_reset() -> None:
    """Discard the current pool so the next _get_pool() creates a fresh one.

    Called after POSTGRES_DSN changes (hot-swap without restart) so stale
    connections are not reused with old credentials. In-flight callers holding
    a connection from the old pool complete normally; the old _PgPool object
    is GC'd once all references drop.
    """
    _state._postgres_pool = None


def _pg_mirror_kv(op: str, args: tuple) -> bool:
    """1.6.5 — best-effort dual-write of config / secret / admin-ip
    changes to Postgres (in addition to SQLite). Lets the standby
    backend stay in sync so a backend swap loses no configuration.

    Supported `op` values (mirrors the SQLite writer):
      set_config / del_config        (config_kv)
      set_secret / del_secret        (secrets_kv)
      set_admin_ip / del_admin_ip    (admin_ips)
    Anything else is a no-op.

    Failures log once and move on — the SQLite write already succeeded
    so the operator's intent is durable. Re-sync happens on the next
    successful Postgres write or on operator-triggered table reload.
    """
    pool = _get_pool()
    if pool is None:
        return False
    try:
        with pool.connection(timeout=2.0) as conn:
            with conn.cursor() as cur:
                if op == "set_config":
                    cur.execute(
                        "INSERT INTO config_kv (key, value, ts) "
                        "VALUES (%s, %s, %s) "
                        "ON CONFLICT (key) DO UPDATE SET "
                        "  value = EXCLUDED.value, ts = EXCLUDED.ts", args)
                elif op == "del_config":
                    cur.execute("DELETE FROM config_kv WHERE key = %s", args)
                elif op == "set_secret":
                    cur.execute(
                        "INSERT INTO secrets_kv (key, value, ts) "
                        "VALUES (%s, %s, %s) "
                        "ON CONFLICT (key) DO UPDATE SET "
                        "  value = EXCLUDED.value, ts = EXCLUDED.ts", args)
                elif op == "del_secret":
                    cur.execute("DELETE FROM secrets_kv WHERE key = %s", args)
                elif op == "set_admin_ip":
                    # SQLite arg order: (cidr, added_ts, note, source, description)
                    cur.execute(
                        "INSERT INTO admin_ips "
                        "  (cidr, added_ts, note, source, description) "
                        "VALUES (%s, %s, %s, %s, %s) "
                        "ON CONFLICT (cidr) DO UPDATE SET "
                        "  added_ts = EXCLUDED.added_ts, "
                        "  note = EXCLUDED.note, "
                        "  source = EXCLUDED.source, "
                        "  description = EXCLUDED.description", args)
                elif op == "del_admin_ip":
                    cur.execute("DELETE FROM admin_ips WHERE cidr = %s", args)
                elif op == "update_admin_ip_description":
                    # args = (description, cidr)  — same order as SQLite UPDATE
                    cur.execute(
                        "UPDATE admin_ips SET description = %s "
                        "WHERE cidr = %s", args)
                elif op == "gw_audit_add":
                    # args = (ts, action, gw_id, actor, details)
                    cur.execute(
                        "INSERT INTO gw_audit (ts, action, gw_id, actor, details) "
                        "VALUES (%s, %s, %s, %s, %s)", args)
                else:
                    return False
        return True
    except Exception as e:
        # Log once per minute to avoid spamming.
        last = getattr(_pg_mirror_kv, "_last_warn_min", -1)
        cur_min = int(_t.time()) // 60
        if last != cur_min:
            _logging.warning("[db-pg] kv mirror failed (op=%s): %s: %s",
                             op, type(e).__name__, str(e)[:120])
            _pg_mirror_kv._last_warn_min = cur_min
        return False


def _migrate_recent_events(target: str, window_secs: int = 60) -> dict:
    """1.6.5 — copy the last `window_secs` of events from the source
    backend to the target backend during a DB swap. Best-effort: a copy
    failure logs a warning but doesn't block the swap (the new backend
    will accumulate fresh events from boot).

    Direction:
      • target=postgres → read SQLite, INSERT into Postgres
      • target=sqlite   → read Postgres, INSERT into SQLite

    `config_kv`, `secrets_kv`, `admin_ips`, `clients`, `timeline` and
    `bans` ALL live in SQLite regardless of `DB_BACKEND` (the gateway's
    operational state — quotas, knobs, allow-lists), so they survive
    backend swaps automatically. Only the events table is split, and
    only for the very recent window.
    """
    pg = _postgres_load_module()
    if pg is None or not POSTGRES_DSN:
        return {"ok": False, "reason": "postgres unavailable"}
    cutoff = _t.time() - window_secs
    copied = 0
    try:
        if target == "postgres":
            # SQLite → Postgres
            src_conn = sqlite3.connect(DB_PATH)
            src_conn.row_factory = sqlite3.Row
            rows = src_conn.execute(
                "SELECT ts, ip, ua, path, status, reason "
                "FROM events WHERE ts >= ? ORDER BY ts ASC LIMIT 100000",
                (cutoff,)
            ).fetchall()
            src_conn.close()
            if not rows:
                return {"ok": True, "copied": 0, "direction": "sqlite->postgres"}
            with pg.connect(POSTGRES_DSN, connect_timeout=5,
                              autocommit=False) as dst:
                with dst.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO events (ts, ip, ua, path, status, reason) "
                        "VALUES (to_timestamp(%s), %s, %s, %s, %s, %s)",
                        [(r["ts"], r["ip"], (r["ua"] or "")[:500],
                          r["path"] or "", int(r["status"] or 0),
                          r["reason"] or "") for r in rows])
                dst.commit()
                copied = len(rows)
            return {"ok": True, "copied": copied,
                    "direction": "sqlite->postgres"}
        else:
            # Postgres → SQLite
            with pg.connect(POSTGRES_DSN, connect_timeout=5) as src:
                with src.cursor() as cur:
                    # ts is TIMESTAMPTZ in Postgres; convert to epoch float
                    # for the SQLite REAL column on the destination side.
                    cur.execute(
                        "SELECT EXTRACT(EPOCH FROM ts), ip, ua, path, status, reason "
                        "FROM events WHERE ts >= to_timestamp(%s) "
                        "ORDER BY ts ASC LIMIT 100000",
                        (cutoff,))
                    rows = cur.fetchall()
            if not rows:
                return {"ok": True, "copied": 0, "direction": "postgres->sqlite"}
            dst = sqlite3.connect(DB_PATH)
            try:
                dst.executemany(
                    "INSERT INTO events (ts, ip, ua, path, method, status, reason) "
                    "VALUES (?, ?, ?, ?, '', ?, ?)",
                    [(float(r[0]), r[1], (r[2] or "")[:500], r[3] or "",
                      int(r[4] or 0), r[5] or "") for r in rows])
                dst.commit()
                copied = len(rows)
            finally:
                dst.close()
            return {"ok": True, "copied": copied,
                    "direction": "postgres->sqlite"}
    except Exception as e:
        return {"ok": False,
                "reason": f"{type(e).__name__}: {str(e)[:160]}"}


# ── Background full-history migration ─────────────────────────────────────────
# Populated by _full_migrate_background(); polled via the status endpoint.
_BG_MIGRATION: dict = {
    "running":      False,
    "done":         False,
    "error":        None,
    "direction":    "",
    "total":        0,
    "copied":       0,
    "started_at":   0.0,
    "finished_at":  0.0,
}


def _bg_sqlite_to_pg(cutoff_ts: float, batch_size: int,
                     batch_sleep: float) -> None:
    """Copy all SQLite events with ts < cutoff_ts into Postgres in batches."""
    pg = _postgres_load_module()
    if pg is None or not POSTGRES_DSN:
        raise RuntimeError("psycopg/POSTGRES_DSN unavailable")

    src = sqlite3.connect(DB_PATH)
    try:
        total = src.execute(
            "SELECT COUNT(*) FROM events WHERE ts < ?", (cutoff_ts,)
        ).fetchone()[0]
    finally:
        src.close()

    _BG_MIGRATION["total"] = total
    if total == 0:
        return

    last_id = 0
    while True:
        src = sqlite3.connect(DB_PATH)
        src.row_factory = sqlite3.Row
        try:
            rows = src.execute(
                "SELECT id, ts, ip, ua, path, status, reason "
                "FROM events WHERE id > ? AND ts < ? ORDER BY id LIMIT ?",
                (last_id, cutoff_ts, batch_size)
            ).fetchall()
        finally:
            src.close()

        if not rows:
            break

        with pg.connect(POSTGRES_DSN, connect_timeout=5,
                        autocommit=False) as dst:
            with dst.cursor() as cur:
                cur.executemany(
                    "INSERT INTO events (ts, ip, ua, path, status, reason) "
                    "VALUES (to_timestamp(%s), %s, %s, %s, %s, %s)",
                    [(r["ts"], r["ip"], (r["ua"] or "")[:500],
                      r["path"] or "", int(r["status"] or 0),
                      r["reason"] or "") for r in rows])
            dst.commit()

        last_id = rows[-1]["id"]
        _BG_MIGRATION["copied"] += len(rows)

        if len(rows) < batch_size:
            break
        _t.sleep(batch_sleep)


def _bg_pg_to_sqlite(cutoff_ts: float, batch_size: int,
                     batch_sleep: float) -> None:
    """Copy all Postgres events with ts < cutoff_ts into SQLite in batches."""
    pg = _postgres_load_module()
    if pg is None or not POSTGRES_DSN:
        raise RuntimeError("psycopg/POSTGRES_DSN unavailable")

    with pg.connect(POSTGRES_DSN, connect_timeout=5, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM events WHERE ts < to_timestamp(%s)",
                (cutoff_ts,))
            total = cur.fetchone()[0]

    _BG_MIGRATION["total"] = total
    if total == 0:
        return

    last_id = 0
    while True:
        with pg.connect(POSTGRES_DSN, connect_timeout=5,
                        autocommit=True) as src:
            with src.cursor() as cur:
                cur.execute(
                    "SELECT id, EXTRACT(EPOCH FROM ts), ip, ua, path, "
                    "       status, reason "
                    "FROM events WHERE id > %s AND ts < to_timestamp(%s) "
                    "ORDER BY id LIMIT %s",
                    (last_id, cutoff_ts, batch_size))
                rows = cur.fetchall()

        if not rows:
            break

        dst = sqlite3.connect(DB_PATH)
        try:
            dst.executemany(
                "INSERT OR IGNORE INTO events "
                "(ts, ip, ua, path, method, status, reason) "
                "VALUES (?, ?, ?, ?, '', ?, ?)",
                [(float(r[1]), r[2], (r[3] or "")[:500], r[4] or "",
                  int(r[5] or 0), r[6] or "") for r in rows])
            dst.commit()
        finally:
            dst.close()

        last_id = rows[-1][0]
        _BG_MIGRATION["copied"] += len(rows)

        if len(rows) < batch_size:
            break
        _t.sleep(batch_sleep)


def _full_migrate_background(target: str, cutoff_ts: float,
                              batch_size: int = 500,
                              batch_sleep: float = 0.05) -> None:
    """Full historical migration of events from old backend → new backend.

    Runs in a thread-pool executor so the event loop is never blocked.
    Updates _BG_MIGRATION in-place; poll via the db-migration-status endpoint.

    cutoff_ts  — epoch seconds; only rows with ts < cutoff_ts are copied
                 (the recent 60-second window was already handled by
                 _migrate_recent_events at switch time).
    batch_size — rows per INSERT batch (default 500).
    batch_sleep — seconds to sleep between batches to reduce DB pressure.
    """
    direction = "sqlite->postgres" if target == "postgres" else "postgres->sqlite"
    _BG_MIGRATION.update({
        "running":     True,
        "done":        False,
        "error":       None,
        "direction":   direction,
        "total":       0,
        "copied":      0,
        "started_at":  _t.time(),
        "finished_at": 0.0,
    })
    _logging.info("[bg-migrate] started direction=%s cutoff_ts=%.0f", direction, cutoff_ts)
    try:
        if target == "postgres":
            _bg_sqlite_to_pg(cutoff_ts, batch_size, batch_sleep)
        else:
            _bg_pg_to_sqlite(cutoff_ts, batch_size, batch_sleep)
    except Exception as e:
        _BG_MIGRATION["error"] = f"{type(e).__name__}: {str(e)[:300]}"
        _logging.warning("[bg-migrate] error: %s", _BG_MIGRATION["error"])
    finally:
        _BG_MIGRATION["running"]     = False
        _BG_MIGRATION["done"]        = True
        _BG_MIGRATION["finished_at"] = _t.time()
        _logging.info("[bg-migrate] finished direction=%s copied=%d error=%s",
                      direction, _BG_MIGRATION["copied"], _BG_MIGRATION["error"])


def _apply_pg_migrations(cur) -> None:
    """Apply every applicable entry from `_SCHEMA_MIGRATIONS` to the
    given Postgres cursor. ADD COLUMN IF NOT EXISTS is built-in, so no
    pre-check needed; failures are swallowed (best-effort upgrade)."""
    for table, col, _sqlite_ddl, pg_ddl in _SCHEMA_MIGRATIONS:
        if pg_ddl is None:
            continue
        try:
            cur.execute(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {pg_ddl}"  # nosec B608
            )
        except Exception as _e:
            _logging.warning("[migrate-pg] %s.%s: %s", table, col, _e)


def db_init_postgres(max_attempts: int = 12, backoff_s: float = 1.0):
    """1.6.5 — initialise the Postgres event store. Called from on_startup
    when DB_BACKEND=postgres. Idempotent; safe to call on a Timescale-
    enabled DB (the create_hypertable call is left to the operator).

    Retries up to `max_attempts` with linear backoff to handle the common
    race where docker-compose / Kubernetes brings up the gateway before
    Postgres has finished accepting TCP connections (pg_isready can return
    yes while the listener is still binding)."""
    pg = _postgres_load_module()
    # 1.6.5 — initialise schema whenever a Postgres DSN is configured, even
    # if the active backend is SQLite. The standby tables must exist so the
    # dual-write `_pg_mirror_kv` calls can land config / secret / admin-ip
    # changes in both backends, and so an operator-driven backend swap to
    # postgres has the schema ready.
    if pg is None or not POSTGRES_DSN:
        return False
    last_err = None
    for attempt in range(1, max_attempts + 1):
        try:
            with pg.connect(POSTGRES_DSN, connect_timeout=5,
                              autocommit=True) as conn:
                with conn.cursor() as cur:
                    # 1.6.5 — `ts` is TIMESTAMPTZ (not DOUBLE PRECISION) so
                    # TimescaleDB's `create_hypertable` accepts it as the
                    # time dimension. Insert path uses `to_timestamp(epoch)`
                    # to convert from Python's _t.time() floats.
                    cur.execute("""
                      CREATE TABLE IF NOT EXISTS events (
                        id          BIGSERIAL,
                        ts          TIMESTAMPTZ NOT NULL,
                        ip          TEXT NOT NULL,
                        ua          TEXT,
                        path        TEXT,
                        status      INTEGER,
                        reason      TEXT,
                        track_key   TEXT,
                        sid         TEXT,
                        fp          TEXT,
                        ja4         TEXT,
                        request_id  TEXT,
                        PRIMARY KEY (ts, id)
                      );
                      CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
                      CREATE INDEX IF NOT EXISTS idx_events_ip      ON events(ip);
                      CREATE INDEX IF NOT EXISTS idx_events_reason  ON events(reason);
                      CREATE INDEX IF NOT EXISTS idx_events_path_ts ON events(path, ts);

                      -- 1.6.5 — operational KV tables mirrored from SQLite so
                      -- every config / secret / admin-IP change is persisted
                      -- in BOTH backends. Lets an operator swap the active
                      -- backend without losing any configuration.
                      CREATE TABLE IF NOT EXISTS config_kv (
                        key    TEXT PRIMARY KEY,
                        value  TEXT,
                        ts     DOUBLE PRECISION
                      );
                      CREATE TABLE IF NOT EXISTS secrets_kv (
                        key    TEXT PRIMARY KEY,
                        value  TEXT,
                        ts     DOUBLE PRECISION
                      );
                      CREATE TABLE IF NOT EXISTS admin_ips (
                        cidr        TEXT PRIMARY KEY,
                        added_ts    DOUBLE PRECISION,
                        note        TEXT,
                        source      TEXT,
                        description TEXT
                      );
                      -- 1.6.7: gateway-mesh registry mirror.
                      CREATE TABLE IF NOT EXISTS gw_registry (
                        gw_id          TEXT PRIMARY KEY,
                        domain         TEXT,
                        region         TEXT,
                        environment    TEXT,
                        status         TEXT NOT NULL DEFAULT 'active',
                        can_distribute INTEGER NOT NULL DEFAULT 1,
                        public_key     TEXT NOT NULL,
                        private_key    TEXT,
                        key_created_ts DOUBLE PRECISION NOT NULL,
                        key_rotated_ts DOUBLE PRECISION,
                        last_seen_ts   DOUBLE PRECISION,
                        created_ts     DOUBLE PRECISION NOT NULL,
                        updated_ts     DOUBLE PRECISION NOT NULL,
                        is_local       INTEGER NOT NULL DEFAULT 0,
                        auto_apply     INTEGER NOT NULL DEFAULT 0
                      );
                      CREATE TABLE IF NOT EXISTS gw_distribution (
                        source_gw_id TEXT NOT NULL,
                        target_gw_id TEXT NOT NULL,
                        ts           DOUBLE PRECISION NOT NULL,
                        PRIMARY KEY (source_gw_id, target_gw_id)
                      );
                      CREATE TABLE IF NOT EXISTS gw_audit (
                        id      BIGSERIAL PRIMARY KEY,
                        ts      DOUBLE PRECISION NOT NULL,
                        action  TEXT NOT NULL,
                        gw_id   TEXT,
                        actor   TEXT,
                        details TEXT
                      );
                      CREATE INDEX IF NOT EXISTS idx_gw_audit_ts    ON gw_audit(ts);
                      CREATE INDEX IF NOT EXISTS idx_gw_audit_gw_id ON gw_audit(gw_id);
                      CREATE TABLE IF NOT EXISTS users (
                        username       TEXT PRIMARY KEY,
                        password_hash  TEXT NOT NULL,
                        role           TEXT NOT NULL DEFAULT 'admin',
                        status         TEXT NOT NULL DEFAULT 'active',
                        created_ts     DOUBLE PRECISION NOT NULL,
                        updated_ts     DOUBLE PRECISION NOT NULL,
                        last_login_ts  DOUBLE PRECISION,
                        last_login_ip  TEXT
                      );
                      CREATE TABLE IF NOT EXISTS user_sessions (
                        sid          TEXT PRIMARY KEY,
                        username     TEXT NOT NULL,
                        ip           TEXT,
                        user_agent   TEXT,
                        created_ts   DOUBLE PRECISION NOT NULL,
                        last_seen_ts DOUBLE PRECISION NOT NULL,
                        expires_ts   DOUBLE PRECISION NOT NULL,
                        status       TEXT NOT NULL DEFAULT 'active',
                        revoked_ts   DOUBLE PRECISION,
                        revoked_by   TEXT
                      );
                      CREATE INDEX IF NOT EXISTS idx_user_sessions_user
                          ON user_sessions(username, status);
                      CREATE TABLE IF NOT EXISTS gw_sync_pending (
                        id           BIGSERIAL PRIMARY KEY,
                        received_ts  DOUBLE PRECISION NOT NULL,
                        source_gw_id TEXT NOT NULL,
                        key_name     TEXT NOT NULL,
                        value        TEXT NOT NULL,
                        status       TEXT NOT NULL DEFAULT 'pending',
                        confirmed_ts DOUBLE PRECISION,
                        UNIQUE(source_gw_id, key_name)
                      );
                      CREATE INDEX IF NOT EXISTS idx_gw_sync_pending_status
                          ON gw_sync_pending(status, received_ts);

                      -- 1.6.10: per-gateway signal activation-order overrides.
                      CREATE TABLE IF NOT EXISTS signal_orders (
                        gw_id            TEXT NOT NULL,
                        signal           TEXT NOT NULL,
                        activation_order INTEGER NOT NULL
                            CHECK (activation_order IN (1,2,3)),
                        updated_ts       DOUBLE PRECISION NOT NULL,
                        updated_by       TEXT,
                        PRIMARY KEY (gw_id, signal)
                      );
                      CREATE INDEX IF NOT EXISTS idx_signal_orders_gw
                          ON signal_orders(gw_id);

                      -- 1.8.6: server-side SIEM alert rules and fire history.
                      CREATE TABLE IF NOT EXISTS siem_alert_rules (
                        id            BIGSERIAL PRIMARY KEY,
                        metric        TEXT NOT NULL,
                        op            TEXT NOT NULL
                            CHECK(op IN ('>','>=','<','<=')),
                        threshold     DOUBLE PRECISION NOT NULL,
                        label         TEXT NOT NULL DEFAULT '',
                        enabled       INTEGER NOT NULL DEFAULT 1,
                        created_ts    DOUBLE PRECISION NOT NULL,
                        created_by    TEXT,
                        last_fired_ts DOUBLE PRECISION DEFAULT 0,
                        cooldown_s    INTEGER NOT NULL DEFAULT 300
                      );
                      CREATE TABLE IF NOT EXISTS siem_alert_fired (
                        id       BIGSERIAL PRIMARY KEY,
                        rule_id  BIGINT NOT NULL
                            REFERENCES siem_alert_rules(id) ON DELETE CASCADE,
                        ts       DOUBLE PRECISION NOT NULL,
                        value    DOUBLE PRECISION NOT NULL
                      );
                      CREATE INDEX IF NOT EXISTS idx_siem_alert_fired_rule
                          ON siem_alert_fired(rule_id, ts DESC);
                    """)
                    # 1.6.7+ — additive column upgrades from the central
                    # registry. Adds any missing column listed in
                    # `_SCHEMA_MIGRATIONS` (PG side). Idempotent.
                    _apply_pg_migrations(cur)
                    # Try to install Timescale hypertable if the extension exists.
                    # Best-effort: vanilla Postgres falls through silently.
                    # 1.6.5 — chunk_time_interval is an INTERVAL since `ts`
                    # is TIMESTAMPTZ (the integer-seconds form is rejected
                    # for non-bigint time columns).
                    try:
                        cur.execute("SELECT 1 FROM pg_extension WHERE extname='timescaledb'")
                        if cur.fetchone():
                            try:
                                cur.execute(
                                    "SELECT create_hypertable('events', 'ts', "
                                    " if_not_exists => TRUE, "
                                    " chunk_time_interval => INTERVAL '1 day')")
                                _logging.info("[db-pg] Timescale hypertable on events(ts)")
                            except Exception as _e:
                                # Already a hypertable, or older API.
                                pass
                    except Exception:
                        pass
            if attempt > 1:
                _logging.info("[db-pg] init succeeded on attempt %d", attempt)
            return True
        except Exception as e:
            last_err = e
            if attempt < max_attempts:
                _t.sleep(backoff_s * attempt)
                continue
    _logging.error("[db-pg] init failed after %d attempts: %s: %s",
                   max_attempts, type(last_err).__name__, last_err)
    return False


def pg_insert_event(ts: float, ip: str, ua: str, path: str,
                     status: int, reason: str, track_key: str = "",
                     sid: str = "", fp: str = "", ja4: str = "",
                     request_id: str = "") -> bool:
    """1.6.5 — append one event row to the Postgres backend. Returns True
    on success, False on transient failure (caller falls back to dropping
    silently — events are best-effort, never block the request path)."""
    if DB_BACKEND != "postgres":
        return False
    pool = _get_pool()
    if pool is None:
        return False
    try:
        with pool.connection(timeout=2.0) as conn:
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, status, reason, "
                "track_key, sid, fp, ja4, request_id) "
                "VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (ts, ip, (ua or "")[:500], path or "", int(status),
                 reason or "", track_key or "", sid or "",
                 fp or "", ja4 or "", request_id or ""))
        return True
    except Exception:
        # Don't spam — the dashboards' /__db-test endpoint surfaces health.
        return False


def pg_db_size() -> dict:
    """1.6.5 → 1.6.8 — Postgres / TimescaleDB stats snapshot. Single
    round-trip query so the per-minute sample stays cheap. Returns:
      db_bytes        — pg_database_size (data + indexes + bloat)
      events_rows     — row count in events table
      index_bytes     — sum of pg_indexes_size across user tables
      active_conns    — pg_stat_activity rows in 'active' state
      idle_conns      — pg_stat_activity rows in 'idle' state
      cache_hit_pct   — blks_hit / (blks_hit+blks_read), 0–100
      tx_total        — xact_commit + xact_rollback (monotonic counter;
                        graph deltas client-side for tx/s)
    Probes whenever POSTGRES_DSN is set, regardless of the active backend."""
    pool = _get_pool()
    if pool is None:
        return {"ok": False, "reason": "POSTGRES_DSN not configured"}
    try:
        with pool.connection(timeout=2.0) as conn:
            with conn.cursor() as cur:
                # Single round-trip — every sub-select runs once per call.
                cur.execute("""
                    SELECT
                      (SELECT pg_database_size(current_database())),
                      (SELECT COALESCE(SUM(pg_indexes_size(c.oid)), 0)
                         FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                         WHERE n.nspname = 'public' AND c.relkind = 'r'),
                      (SELECT COUNT(*) FROM pg_stat_activity
                         WHERE state = 'active'
                           AND datname = current_database()),
                      (SELECT COUNT(*) FROM pg_stat_activity
                         WHERE state = 'idle'
                           AND datname = current_database()),
                      (SELECT CASE WHEN SUM(blks_hit + blks_read) = 0 THEN 0
                                   ELSE ROUND(100.0 * SUM(blks_hit)
                                              / SUM(blks_hit + blks_read), 2) END
                         FROM pg_stat_database
                         WHERE datname = current_database()),
                      (SELECT COALESCE(SUM(xact_commit + xact_rollback), 0)
                         FROM pg_stat_database
                         WHERE datname = current_database())
                """)
                row = cur.fetchone() or (0, 0, 0, 0, 0, 0)
                # events_rows separately — table may not exist yet when
                # the standby is probed before the first switch.
                try:
                    cur.execute("SELECT COUNT(*) FROM events")
                    rows = int(cur.fetchone()[0])
                except Exception:
                    rows = 0
                return {
                    "ok":            True,
                    "db_bytes":      int(row[0] or 0),
                    "events_rows":   rows,
                    "index_bytes":   int(row[1] or 0),
                    "active_conns":  int(row[2] or 0),
                    "idle_conns":    int(row[3] or 0),
                    "cache_hit_pct": float(row[4] or 0.0),
                    "tx_total":      int(row[5] or 0),
                }
    except Exception as e:
        return {"ok": False, "reason": f"{type(e).__name__}: {str(e)[:80]}"}


def pg_test_roundtrip() -> dict:
    """1.6.5 — connectivity probe for the Controls dashboard. Inserts a
    canary 'pgtest' event, reads it back, deletes it, returns timing.

    Probes whenever POSTGRES_DSN is set, regardless of the active backend
    — lets the operator see "yes, Postgres is reachable" before clicking
    the switch. The events table is created on first probe (idempotent
    DDL via CREATE TABLE IF NOT EXISTS) so dashboards don't trip when
    pg_db_size is queried before any traffic has hit Postgres."""
    pg = _postgres_load_module()
    if pg is None:
        return {"ok": False, "reason": "psycopg not installed"}
    if not POSTGRES_DSN:
        return {"ok": False, "reason": "POSTGRES_DSN not configured"}
    t0 = _t.time()
    try:
        with pg.connect(POSTGRES_DSN, connect_timeout=3,
                          autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version(), current_database(), now()")
                ver, dbname, now_ts = cur.fetchone()
                # 1.6.5 — ensure the events schema exists (idempotent).
                # When DB_BACKEND=sqlite, the standby Postgres still gets
                # its schema ready so the dashboard shows real probe
                # results without needing the operator to flip the switch
                # first.
                cur.execute("""
                  CREATE TABLE IF NOT EXISTS events (
                    id          BIGSERIAL,
                    ts          TIMESTAMPTZ NOT NULL,
                    ip          TEXT NOT NULL,
                    ua          TEXT,
                    path        TEXT,
                    status      INTEGER,
                    reason      TEXT,
                    track_key   TEXT,
                    sid         TEXT,
                    fp          TEXT,
                    ja4         TEXT,
                    request_id  TEXT,
                    PRIMARY KEY (ts, id)
                  )""")
                # Test the events schema works
                ts = _t.time()
                cur.execute(
                    "INSERT INTO events (ts, ip, reason) "
                    "VALUES (to_timestamp(%s), '127.0.0.1', 'pgtest') RETURNING id", (ts,))
                test_id = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM events WHERE reason='pgtest'")
                cnt = int(cur.fetchone()[0])
                cur.execute("DELETE FROM events WHERE id = %s", (test_id,))
                return {"ok": True,
                        "version": str(ver)[:120],
                        "db": str(dbname),
                        "round_trip_ms": round((_t.time() - t0) * 1000, 1),
                        "events_rows_seen_during_test": cnt}
    except Exception as e:
        return {"ok": False,
                "reason": f"{type(e).__name__}: {str(e)[:160]}",
                "round_trip_ms": round((_t.time() - t0) * 1000, 1)}
