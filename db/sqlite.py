"""
db/sqlite.py — SQLite persistence, schema migrations, and DB writer loop.
Extracted from proxy.py as part of Phase 2 modular refactoring.

Dependency rule: imports from config.py, state.py, and helpers.py only
(plus stdlib). Cross-references to db/postgres.py are done via local
imports inside functions to avoid circular imports (postgres.py imports
_SCHEMA_MIGRATIONS from this module).
"""

import asyncio
import json
import os
import sqlite3
import time
import time as _t
from collections import defaultdict

from config import (
    DB_BACKEND,
    DB_PATH,
    POSTGRES_DSN,
    MAX_IDENTITIES,
    SERVICE_METRICS_RETENTION,
    WAL_CHECKPOINT_EVERY_SECS,
)
import state as _state
from state import (
    ip_state,
    metrics,
    events,
    timeline,
    SERVICE_METRICS_HISTORY,
)
from helpers import slog, now

# ── Schema-migration registry ─────────────────────────────────────────────
# Single source of truth for additive ALTER TABLE … ADD COLUMN
# upgrades. Any release that adds a column to an existing table appends
# one tuple here — never edit or remove old entries, they are the
# upgrade path that older deployments rely on at first boot under the
# new image.
#
# Format: (table, column, sqlite_ddl, pg_ddl)
#   - sqlite_ddl / pg_ddl: the DDL fragment that follows
#     "ALTER TABLE <t> ADD COLUMN <c> ". E.g. "TEXT" or
#     "INTEGER NOT NULL DEFAULT 0". Set to None to skip on that backend
#     (rare — happens when only one backend's older schema lacked the
#     column; e.g. admin_ips.note was added later only on PG).
#
# Both appliers are idempotent (PRAGMA / IF NOT EXISTS) and safe to run
# on every startup.
_SCHEMA_MIGRATIONS: list[tuple[str, str, str | None, str | None]] = [
    # 1.5.3
    ("admin_ips",   "description",     "TEXT",                          None),
    # 1.5.4 — `timeline` is SQLite-only (PG events table replaces it).
    ("timeline",    "missed",          "INTEGER DEFAULT 0",             None),
    # 1.6.5 — `svc_metrics` is SQLite-only (no PG mirror table).
    ("svc_metrics", "pg_db_bytes",     "INTEGER",                       None),
    ("svc_metrics", "pg_events_rows",  "INTEGER",                       None),
    # 1.6.7+ — historical sampling of identity count + request counter
    # so the Service dashboard can render click-to-zoom charts on those
    # cards (same UX as cpu/mem/disk).
    ("svc_metrics", "identities_count","INTEGER DEFAULT 0",             None),
    ("svc_metrics", "total_requests",  "INTEGER DEFAULT 0",             None),
    # 1.6.8 — TimescaleDB / Postgres health metrics. All sampled in a
    # single round-trip via pg_db_size() (renamed pg_stats internally).
    # Click-to-zoom on the Service dashboard's TimescaleDB section.
    ("svc_metrics", "pg_index_bytes",  "INTEGER DEFAULT 0",             None),
    ("svc_metrics", "pg_active_conns", "INTEGER DEFAULT 0",             None),
    ("svc_metrics", "pg_idle_conns",   "INTEGER DEFAULT 0",             None),
    ("svc_metrics", "pg_cache_hit_pct","REAL DEFAULT 0",                None),
    ("svc_metrics", "pg_tx_total",     "INTEGER DEFAULT 0",             None),
    # 1.6.5 — admin_ips.note added on PG only (SQLite schema had it from creation)
    ("admin_ips",   "note",            None,                            "TEXT"),
    # 1.6.7
    ("gw_registry", "domain",          "TEXT",                          "TEXT"),
    # 1.6.7+
    ("gw_registry", "auto_apply",      "INTEGER NOT NULL DEFAULT 0",    "INTEGER NOT NULL DEFAULT 0"),
]


def _apply_sqlite_migrations(conn) -> None:
    """Apply every applicable entry from `_SCHEMA_MIGRATIONS` to the
    given SQLite connection. Logs each ALTER. Per-table PRAGMA cache
    avoids re-querying when multiple columns target the same table."""
    pragma_cache: dict[str, set[str]] = {}
    for table, col, sqlite_ddl, _pg_ddl in _SCHEMA_MIGRATIONS:
        if sqlite_ddl is None:
            continue
        try:
            if table not in pragma_cache:
                pragma_cache[table] = {
                    r[1] for r in conn.execute(f"PRAGMA table_info({table})")  # nosec B608 — table from internal allowlist
                }
            if col in pragma_cache[table]:
                continue
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {sqlite_ddl}")  # nosec B608
            pragma_cache[table].add(col)
            slog("db_migrate_sqlite_add", level="info", table=table, col=col)
        except Exception as _e:
            slog("db_migrate_sqlite_err", level="warn", table=table, col=col, error=str(_e))


def db_init():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS events (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      REAL NOT NULL,
        ip      TEXT NOT NULL,
        ua      TEXT,
        path    TEXT,
        method  TEXT,
        status  INTEGER,
        reason  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
    CREATE INDEX IF NOT EXISTS idx_events_ip      ON events(ip);
    CREATE INDEX IF NOT EXISTS idx_events_reason  ON events(reason);
    CREATE INDEX IF NOT EXISTS idx_events_path_ts ON events(path, ts);

    CREATE TABLE IF NOT EXISTS clients (
        ip                TEXT PRIMARY KEY,
        first_seen        REAL,
        last_seen         REAL,
        request_count     INTEGER DEFAULT 0,
        allowed_count     INTEGER DEFAULT 0,
        blocked_count     INTEGER DEFAULT 0,
        banned_until_epoch REAL DEFAULT 0,
        last_user_agent   TEXT,
        last_path         TEXT,
        blocks_by_reason  TEXT  -- JSON
    );

    CREATE TABLE IF NOT EXISTS metrics_kv (
        key  TEXT PRIMARY KEY,
        val  TEXT
    );

    CREATE TABLE IF NOT EXISTS timeline (
        bucket_minute INTEGER PRIMARY KEY,
        total         INTEGER DEFAULT 0,
        allowed       INTEGER DEFAULT 0,
        blocked       INTEGER DEFAULT 0,
        missed        INTEGER DEFAULT 0,  -- 1.5.4: allowed but score in medium band
        by_reason     TEXT  -- JSON
    );

    CREATE TABLE IF NOT EXISTS bans (
        ip            TEXT PRIMARY KEY,
        banned_until  REAL,
        reason        TEXT,
        ts            REAL
    );

    CREATE TABLE IF NOT EXISTS admin_ips (
        cidr        TEXT PRIMARY KEY,
        added_ts    REAL NOT NULL,
        note        TEXT,
        source      TEXT,
        description TEXT  -- 1.5.3: free-text label visible in UI
    );

    CREATE TABLE IF NOT EXISTS abuseipdb_cache (
        ip       TEXT PRIMARY KEY,
        score    INTEGER NOT NULL,
        country  TEXT,
        ts       REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_abuseipdb_ts ON abuseipdb_cache(ts);

    CREATE TABLE IF NOT EXISTS svc_metrics (
        ts          REAL PRIMARY KEY,
        cpu_pct     REAL,
        load1       REAL, load5 REAL, load15 REAL,
        mem_used    INTEGER, mem_total INTEGER, mem_avail INTEGER, mem_pct REAL,
        swap_used   INTEGER, swap_total INTEGER,
        cg_used     INTEGER, cg_limit INTEGER, cg_pct REAL,
        disk_used   INTEGER, disk_total INTEGER, disk_avail INTEGER, disk_pct REAL,
        procs       INTEGER, open_fds INTEGER,
        net_rx_bps  INTEGER, net_tx_bps INTEGER,
        db_db       INTEGER, db_wal INTEGER, db_shm INTEGER, db_total INTEGER
    );

    -- 1.5.5: hot-reload knob persistence. Every change pushed via /__config
    -- is mirrored here so it survives container restart. Loaded AFTER env
    -- defaults at boot, so DB takes precedence over env.  `value` is JSON-
    -- encoded (covers ints / floats / bools / strings / arrays).
    CREATE TABLE IF NOT EXISTS config_kv (
        key    TEXT PRIMARY KEY,
        value  TEXT,
        ts     REAL
    );

    -- 1.5.5: runtime secret management. Operator can POST integration keys
    -- via /__secrets to enable Turnstile / AbuseIPDB / CrowdSec / MaxMind
    -- without redeploying. Stored separately from config_kv to make audit
    -- + rotation cleaner. NEVER returned via /__config GET; readable only
    -- by the in-process loader at startup.
    CREATE TABLE IF NOT EXISTS secrets_kv (
        key    TEXT PRIMARY KEY,
        value  TEXT,
        ts     REAL
    );

    -- 1.6.7: gateway-mesh registry. Each row is one gateway in the
    -- distributed mesh; the `private_key` is an HMAC secret used to sign
    -- block records before they are pushed to peers, and `public_key` is
    -- the SHA256-derived verification handle peers use to authenticate
    -- those records (HMAC public-handle scheme — see _gw_derive_pubkey).
    -- The `can_distribute` flag is the coarse gate; the per-pair sync
    -- topology lives in `gw_distribution` below.
    CREATE TABLE IF NOT EXISTS gw_registry (
        gw_id          TEXT PRIMARY KEY,
        domain         TEXT,                  -- 1.6.7: external hostname
        region         TEXT,
        environment    TEXT,
        status         TEXT NOT NULL DEFAULT 'active',
        can_distribute INTEGER NOT NULL DEFAULT 1,
        public_key     TEXT NOT NULL,
        private_key    TEXT,                  -- only set on the LOCAL gw row
        key_created_ts REAL NOT NULL,
        key_rotated_ts REAL,
        last_seen_ts   REAL,
        created_ts     REAL NOT NULL,
        updated_ts     REAL NOT NULL,
        is_local       INTEGER NOT NULL DEFAULT 0,
        auto_apply     INTEGER NOT NULL DEFAULT 0  -- 1.6.7+ trusted peer
    );

    -- 1.6.7: distribution rules — directional, source → target. Defaults
    -- to none when a new gw is added; operator must enable explicit pairs.
    CREATE TABLE IF NOT EXISTS gw_distribution (
        source_gw_id TEXT NOT NULL,
        target_gw_id TEXT NOT NULL,
        ts           REAL NOT NULL,
        PRIMARY KEY (source_gw_id, target_gw_id)
    );

    -- 1.6.7: append-only audit log of every registry mutation. Used by
    -- the Settings dashboard's audit-log view; never pruned by the
    -- gateway itself (operator-driven rotation).
    CREATE TABLE IF NOT EXISTS gw_audit (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        ts         REAL NOT NULL,
        action     TEXT NOT NULL,
        gw_id      TEXT,
        actor      TEXT,
        details    TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_gw_audit_ts    ON gw_audit(ts);
    CREATE INDEX IF NOT EXISTS idx_gw_audit_gw_id ON gw_audit(gw_id);

    -- 1.6.7: mesh-sync of integration secrets / config keys. Each row
    -- is an INBOUND offer received from a peer gateway via Redis. The
    -- destination operator must explicitly confirm to apply; until then
    -- the value sits in the pending state and the live integration is
    -- untouched. UNIQUE(source_gw_id, key_name) keeps each peer's
    -- last-offered value as one row (re-broadcast updates in place).
    CREATE TABLE IF NOT EXISTS gw_sync_pending (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        received_ts  REAL NOT NULL,
        source_gw_id TEXT NOT NULL,
        key_name     TEXT NOT NULL,
        value        TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'pending',
        confirmed_ts REAL,
        UNIQUE(source_gw_id, key_name)
    );
    CREATE INDEX IF NOT EXISTS idx_gw_sync_pending_status
        ON gw_sync_pending(status, received_ts);

    -- 1.6.7: dashboard user accounts. Replaces the prior shared-admin-key
    -- model (key-bearer auth still works for scripted clients — the new
    -- session cookie is checked alongside it). Passwords stored as
    -- scrypt(salt|password) base64-encoded; role is "admin" today, room
    -- to extend (viewer/editor) without schema churn.
    CREATE TABLE IF NOT EXISTS users (
        username       TEXT PRIMARY KEY,
        password_hash  TEXT NOT NULL,
        role           TEXT NOT NULL DEFAULT 'admin',
        status         TEXT NOT NULL DEFAULT 'active',
        created_ts     REAL NOT NULL,
        updated_ts     REAL NOT NULL,
        last_login_ts  REAL,
        last_login_ip  TEXT
    );

    -- 1.6.7: per-user session ledger. Each successful login mints a
    -- fresh `sid` (16-char URL-safe random), records the IP + UA, and
    -- the corresponding session cookie carries the sid as part of the
    -- HMAC payload. Lookup happens on every authenticated request via
    -- the in-memory _SESSION_CACHE; revocation drops the row's status
    -- to 'revoked' and the next request fails verification.
    CREATE TABLE IF NOT EXISTS user_sessions (
        sid          TEXT PRIMARY KEY,
        username     TEXT NOT NULL,
        ip           TEXT,
        user_agent   TEXT,
        created_ts   REAL NOT NULL,
        last_seen_ts REAL NOT NULL,
        expires_ts   REAL NOT NULL,
        status       TEXT NOT NULL DEFAULT 'active',
        revoked_ts   REAL,
        revoked_by   TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_user_sessions_user
        ON user_sessions(username, status);

    -- 1.6.10: per-gateway signal activation-order overrides. Each row
    -- records an operator's decision to run a named signal at order 1, 2,
    -- or 3, overriding the hardcoded defaults. Gateway-scoped so a future
    -- multi-gw mesh can carry different postures per instance.
    CREATE TABLE IF NOT EXISTS signal_orders (
        gw_id            TEXT NOT NULL
                           REFERENCES gw_registry(gw_id) ON DELETE CASCADE,
        signal           TEXT NOT NULL,
        activation_order INTEGER NOT NULL CHECK (activation_order IN (1,2,3)),
        updated_ts       REAL NOT NULL,
        updated_by       TEXT,
        PRIMARY KEY (gw_id, signal)
    );
    CREATE INDEX IF NOT EXISTS idx_signal_orders_gw ON signal_orders(gw_id);
    """)
    # 1.6.7+ — additive column upgrades driven by the central registry.
    # See `_SCHEMA_MIGRATIONS` above; new releases append entries there.
    _apply_sqlite_migrations(conn)
    conn.commit()
    conn.close()

    # Also initialise Postgres schema whenever POSTGRES_DSN is configured
    # (even when the active backend is SQLite — standby must be schema-ready
    # for dual-write and operator-driven backend swaps).
    if POSTGRES_DSN:
        # Local import to avoid circular dependency:
        # postgres.py imports _SCHEMA_MIGRATIONS from this module.
        from db.postgres import db_init_postgres
        db_init_postgres()


async def db_writer_loop():
    """Background coroutine: drains the queue and flushes to SQLite in batches.
    Periodically runs `wal_checkpoint(TRUNCATE)` so the WAL file stays small
    instead of inflating between auto-checkpoints (cosmetic + reduces the
    'shrinkage' visible in the SQLite-size chart at every restart)."""
    # Local import to avoid circular dependency at module load time.
    from db.postgres import _pg_mirror_kv

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")  # better concurrency
    conn.execute("PRAGMA synchronous=NORMAL")
    last_checkpoint = _t.time()
    last_vacuum = _t.time()
    while True:
        try:
            batch = [await _state.db_queue.get()]
            # Drain up to 100 more items if available (without waiting)
            while len(batch) < 100:
                try:
                    batch.append(_state.db_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            for op, args in batch:
                try:
                    if op == "event":
                        conn.execute(
                            "INSERT INTO events (ts,ip,ua,path,method,status,reason) "
                            "VALUES (?,?,?,?,?,?,?)", args)
                    elif op == "upsert_client":
                        conn.execute("""
                          INSERT INTO clients (ip, first_seen, last_seen, request_count,
                                               allowed_count, blocked_count, banned_until_epoch,
                                               last_user_agent, last_path, blocks_by_reason)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(ip) DO UPDATE SET
                            last_seen=excluded.last_seen,
                            request_count=excluded.request_count,
                            allowed_count=excluded.allowed_count,
                            blocked_count=excluded.blocked_count,
                            banned_until_epoch=excluded.banned_until_epoch,
                            last_user_agent=excluded.last_user_agent,
                            last_path=excluded.last_path,
                            blocks_by_reason=excluded.blocks_by_reason
                        """, args)
                    elif op == "upsert_timeline":
                        conn.execute("""
                          INSERT INTO timeline (bucket_minute,total,allowed,blocked,missed,by_reason)
                          VALUES (?, ?, ?, ?, ?, ?)
                          ON CONFLICT(bucket_minute) DO UPDATE SET
                            total=excluded.total, allowed=excluded.allowed,
                            blocked=excluded.blocked, missed=excluded.missed,
                            by_reason=excluded.by_reason
                        """, args)
                    elif op == "set_kv":
                        conn.execute("INSERT OR REPLACE INTO metrics_kv (key,val) VALUES (?,?)", args)
                    elif op == "set_config":
                        # 1.5.5 — hot-reload knob persistence.  args = (key, json_value, ts)
                        conn.execute("INSERT OR REPLACE INTO config_kv (key,value,ts) VALUES (?,?,?)", args)
                        # 1.6.5 — also mirror to Postgres so the standby
                        # backend sees the same configuration. Best-effort;
                        # SQLite is the source of truth.
                        try: _pg_mirror_kv("set_config", args)
                        except Exception: pass  # nosec B110 — best-effort Postgres mirror; SQLite is source of truth
                    elif op == "del_config":
                        conn.execute("DELETE FROM config_kv WHERE key = ?", args)
                        try: _pg_mirror_kv("del_config", args)
                        except Exception: pass  # nosec B110 — best-effort Postgres mirror; SQLite is source of truth
                    elif op == "set_secret":
                        # 1.5.5 — runtime integration-secret persistence.
                        conn.execute("INSERT OR REPLACE INTO secrets_kv (key,value,ts) VALUES (?,?,?)", args)
                        try: _pg_mirror_kv("set_secret", args)
                        except Exception: pass  # nosec B110 — best-effort Postgres mirror; SQLite is source of truth
                    elif op == "del_secret":
                        conn.execute("DELETE FROM secrets_kv WHERE key = ?", args)
                        try: _pg_mirror_kv("del_secret", args)
                        except Exception: pass  # nosec B110 — best-effort Postgres mirror; SQLite is source of truth
                    elif op == "ban":
                        conn.execute("""
                          INSERT INTO bans (ip,banned_until,reason,ts) VALUES (?,?,?,?)
                          ON CONFLICT(ip) DO UPDATE SET banned_until=excluded.banned_until,
                                                        reason=excluded.reason, ts=excluded.ts
                        """, args)
                    elif op == "svc_metric":
                        # args is a tuple of values matching the column order.
                        # 1.6.5: appended pg_db_bytes + pg_events_rows
                        conn.execute("""
                          INSERT OR REPLACE INTO svc_metrics
                          (ts, cpu_pct, load1, load5, load15,
                           mem_used, mem_total, mem_avail, mem_pct,
                           swap_used, swap_total, cg_used, cg_limit, cg_pct,
                           disk_used, disk_total, disk_avail, disk_pct,
                           procs, open_fds, net_rx_bps, net_tx_bps,
                           db_db, db_wal, db_shm, db_total,
                           pg_db_bytes, pg_events_rows,
                           identities_count, total_requests,
                           pg_index_bytes, pg_active_conns, pg_idle_conns,
                           pg_cache_hit_pct, pg_tx_total)
                          VALUES (?, ?, ?, ?, ?,
                                  ?, ?, ?, ?,
                                  ?, ?, ?, ?, ?,
                                  ?, ?, ?, ?,
                                  ?, ?, ?, ?,
                                  ?, ?, ?, ?,
                                  ?, ?,
                                  ?, ?,
                                  ?, ?, ?, ?, ?)
                        """, args)
                    elif op == "svc_metric_prune":
                        # args = (cutoff_ts,)
                        conn.execute("DELETE FROM svc_metrics WHERE ts < ?", args)
                    elif op == "admin_ip_add":
                        # args = (cidr, added_ts, note, source, description)
                        conn.execute(
                            "INSERT OR REPLACE INTO admin_ips "
                            "(cidr, added_ts, note, source, description) "
                            "VALUES (?, ?, ?, ?, ?)",
                            args)
                        try: _pg_mirror_kv("set_admin_ip", args)
                        except Exception: pass  # nosec B110 — best-effort Postgres mirror; SQLite is source of truth
                    elif op == "admin_ip_remove":
                        # args = (cidr,)
                        conn.execute("DELETE FROM admin_ips WHERE cidr = ?", args)
                        try: _pg_mirror_kv("del_admin_ip", args)
                        except Exception: pass  # nosec B110 — best-effort Postgres mirror; SQLite is source of truth
                    elif op == "admin_ip_update_description":
                        # args = (description, cidr)
                        conn.execute(
                            "UPDATE admin_ips SET description=? WHERE cidr=?",
                            args)
                        try: _pg_mirror_kv("update_admin_ip_description", args)
                        except Exception: pass  # nosec B110 — best-effort Postgres mirror; SQLite is source of truth
                    elif op == "abuseipdb_set":
                        # args = (ip, score, country, ts)
                        conn.execute(
                            "INSERT OR REPLACE INTO abuseipdb_cache "
                            "(ip, score, country, ts) VALUES (?, ?, ?, ?)",
                            args)
                    # 1.6.7 — Gateway Registry persistence ─────────────
                    elif op == "gw_registry_add":
                        # args = (gw_id, domain, region, environment, status,
                        #         can_distribute, public_key, private_key,
                        #         key_created_ts, key_rotated_ts,
                        #         last_seen_ts, created_ts, updated_ts,
                        #         is_local)
                        conn.execute(
                            "INSERT OR REPLACE INTO gw_registry "
                            "(gw_id, domain, region, environment, status, can_distribute, "
                            " public_key, private_key, key_created_ts, key_rotated_ts, "
                            " last_seen_ts, created_ts, updated_ts, is_local) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            args)
                    elif op == "gw_registry_update":
                        # args = (gw_id, {col: val, ...})
                        gw_id, fields = args
                        if fields:
                            _GW_MUTABLE = frozenset({
                                "domain", "region", "environment", "status",
                                "can_distribute", "public_key", "private_key",
                                "key_created_ts", "key_rotated_ts", "last_seen_ts",
                                "updated_ts", "is_local", "auto_apply",
                            })
                            bad = set(fields) - _GW_MUTABLE
                            if bad:
                                raise ValueError(f"gw_registry_update: unknown columns {bad}")
                            cols = ", ".join(f"{k}=?" for k in fields)
                            params = list(fields.values()) + [gw_id]
                            conn.execute(
                                f"UPDATE gw_registry SET {cols} WHERE gw_id=?",  # nosec B608 — cols keys validated against _GW_MUTABLE allowlist above
                                params)
                    elif op == "gw_registry_discover":
                        # 1.6.7+ — auto-discovery from mesh-sync. Inserts a
                        # placeholder row for an unknown peer that just
                        # published to Redis. status='untrusted' + auto_apply=0
                        # until the operator adopts the row in Settings.
                        # args = (gw_id, ts)
                        gw_id, ts = args
                        conn.execute(
                            "INSERT OR IGNORE INTO gw_registry "
                            "(gw_id, domain, region, environment, status, "
                            " can_distribute, public_key, private_key, "
                            " key_created_ts, last_seen_ts, "
                            " created_ts, updated_ts, is_local, auto_apply) "
                            "VALUES (?, NULL, NULL, NULL, 'untrusted', 0, "
                            "        '', NULL, ?, ?, ?, ?, 0, 0)",
                            (gw_id, ts, ts, ts, ts))
                        # Always refresh last_seen_ts so the Sync column
                        # picks up the contact even if the row pre-existed.
                        conn.execute(
                            "UPDATE gw_registry SET last_seen_ts=? "
                            "WHERE gw_id=?",
                            (ts, gw_id))
                    elif op == "gw_registry_delete":
                        # args = (gw_id,)
                        conn.execute("DELETE FROM gw_registry WHERE gw_id=?", args)
                        conn.execute(
                            "DELETE FROM gw_distribution "
                            "WHERE source_gw_id=? OR target_gw_id=?",
                            (args[0], args[0]))
                    elif op == "gw_distribution_replace":
                        # args = (cleaned_pairs, ts)  — full replace
                        pairs, ts = args
                        conn.execute("DELETE FROM gw_distribution")
                        if pairs:
                            conn.executemany(
                                "INSERT OR IGNORE INTO gw_distribution "
                                "(source_gw_id, target_gw_id, ts) VALUES (?, ?, ?)",
                                [(s, t, ts) for s, t in pairs])
                    elif op == "gw_audit_add":
                        # args = (ts, action, gw_id, actor, details)
                        conn.execute(
                            "INSERT INTO gw_audit "
                            "(ts, action, gw_id, actor, details) "
                            "VALUES (?, ?, ?, ?, ?)",
                            args)
                    # 1.6.7 — user accounts ───────────────────────────
                    elif op == "user_create":
                        # args = (username, password_hash, role, status,
                        #         created_ts, updated_ts)
                        conn.execute(
                            "INSERT OR REPLACE INTO users "
                            "(username, password_hash, role, status, "
                            " created_ts, updated_ts) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            args)
                    elif op == "user_update":
                        # args = (username, {col: val, ...})
                        username, fields = args
                        if fields:
                            cols   = ", ".join(f"{k}=?" for k in fields)
                            params = list(fields.values()) + [username]
                            conn.execute(
                                f"UPDATE users SET {cols} WHERE username=?",  # nosec B608
                                params)
                    elif op == "user_delete":
                        # args = (username,)
                        conn.execute("DELETE FROM users WHERE username=?", args)
                    elif op == "user_login_recorded":
                        # args = (ts, ip, username)
                        conn.execute(
                            "UPDATE users SET last_login_ts=?, last_login_ip=? "
                            "WHERE username=?",
                            args)
                    # 1.6.7 — per-session ledger writes ───────────────
                    elif op == "user_session_create":
                        # args = (sid, username, ip, ua, created_ts,
                        #         last_seen_ts, expires_ts)
                        conn.execute(
                            "INSERT INTO user_sessions "
                            "(sid, username, ip, user_agent, "
                            " created_ts, last_seen_ts, expires_ts, status) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, 'active')",
                            args)
                    elif op == "user_session_touch":
                        # args = (last_seen_ts, sid)
                        conn.execute(
                            "UPDATE user_sessions SET last_seen_ts=? "
                            "WHERE sid=?",
                            args)
                    elif op == "user_session_revoke":
                        # args = (sid, revoked_by, revoked_ts)
                        conn.execute(
                            "UPDATE user_sessions SET status='revoked', "
                            "revoked_by=?, revoked_ts=? WHERE sid=?",
                            (args[1], args[2], args[0]))
                    # 1.6.7 — mesh-sync pending offers ────────────────
                    elif op == "mesh_sync_pending_upsert":
                        # args = (received_ts, source_gw_id, key_name, value)
                        # Idempotent: the WHERE clause keeps a same-value
                        # re-broadcast from disturbing a previously
                        # confirmed/rejected row, and avoids no-op writes
                        # for unchanged pending rows.
                        conn.execute(
                            "INSERT INTO gw_sync_pending "
                            "(received_ts, source_gw_id, key_name, value, status) "
                            "VALUES (?, ?, ?, ?, 'pending') "
                            "ON CONFLICT(source_gw_id, key_name) DO UPDATE SET "
                            "  received_ts = excluded.received_ts, "
                            "  value       = excluded.value, "
                            "  status      = 'pending', "
                            "  confirmed_ts = NULL "
                            "WHERE excluded.value <> gw_sync_pending.value",
                            args)
                    elif op == "mesh_sync_status":
                        # args = (id, new_status, ts)
                        conn.execute(
                            "UPDATE gw_sync_pending "
                            "SET status = ?, confirmed_ts = ? WHERE id = ?",
                            (args[1], args[2], args[0]))
                except Exception as e:
                    slog("db_write_failed", level="error", error=str(e), op=op)
            conn.commit()
            for _ in batch:
                _state.db_queue.task_done()

            # Truncate the WAL on a timer so it doesn't accumulate between
            # auto-checkpoints. PASSIVE first (no locking); only TRUNCATE if
            # we get the chance.
            now_ts = _t.time()
            if now_ts - last_checkpoint > WAL_CHECKPOINT_EVERY_SECS:
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.OperationalError:
                    pass    # readers active, retry next tick
                last_checkpoint = now_ts
            if now_ts - last_vacuum > 86400:
                try:
                    conn.execute("VACUUM")
                except sqlite3.OperationalError:
                    pass    # readers active, skip this cycle
                last_vacuum = now_ts
        except asyncio.CancelledError:
            break
        except Exception as e:
            slog("db_loop_error", level="error", error=str(e))


# ── 1.5.5 — runtime integration-secret store ──────────────────────────────
# Each entry maps the public /__secrets endpoint key →
# (the proxy.py global that holds the value, the env var name we honour
#  as bootstrap fallback). Add new ones here.
_SECRET_KEYS = {
    "TURNSTILE_SITEKEY":   ("TURNSTILE_SITEKEY",   "TURNSTILE_SITEKEY"),
    "TURNSTILE_SECRET":    ("TURNSTILE_SECRET",    "TURNSTILE_SECRET"),
    "ABUSEIPDB_KEY":       ("ABUSEIPDB_KEY",       "ABUSEIPDB_KEY"),
    "CROWDSEC_LAPI_URL":   ("CROWDSEC_LAPI_URL",   "CROWDSEC_LAPI_URL"),
    "CROWDSEC_LAPI_KEY":   ("CROWDSEC_API_KEY",    "CROWDSEC_LAPI_KEY"),
    "MAXMIND_LICENSE_KEY": ("MAXMIND_LICENSE_KEY", "MAXMIND_LICENSE_KEY"),
}


def _refresh_integration_state(proxy_globals: dict) -> None:
    """Re-derive integration-enabled flags from current globals. Called
    after db_load_secrets() and after a successful /__secrets POST.

    Phase 2 note: `proxy_globals` must be the caller's globals() dict
    (i.e. proxy.py's module namespace) so the flags land in the right
    module. When called from proxy.py the caller passes globals()."""
    import sys as _sys_rs
    g = proxy_globals
    _prev_configured = g.get("_TURNSTILE_CONFIGURED", False)
    g["_TURNSTILE_CONFIGURED"] = bool(g.get("TURNSTILE_SITEKEY") and g.get("TURNSTILE_SECRET"))
    _ts_env = os.environ.get("TURNSTILE_ENABLED", "").strip().lower()
    # Auto-enable only when credentials first become available (prev=False →
    # now=True). If already configured, respect the operator's explicit
    # on/off choice set via /config or the Controls dashboard.
    if not _prev_configured and g["_TURNSTILE_CONFIGURED"] and _ts_env not in ("0", "false", "no"):
        g["TURNSTILE_ENABLED"] = True
    g["ABUSEIPDB_ENABLED"] = bool(g.get("ABUSEIPDB_KEY"))
    g["CROWDSEC_ENABLED"]  = bool(g.get("CROWDSEC_LAPI_URL") and g.get("CROWDSEC_API_KEY"))
    # Propagate secrets AND derived flags to all loaded modules so that:
    #   • db_load_config validators (which read proxy_handler globals) see the
    #     real credential values before validating ABUSEIPDB_ENABLED et al.
    #   • _read_hot_reload_state() in proxy_handler returns the live values,
    #     not the config.py defaults — fixes Controls showing stale state.
    _propagate = {
        "ABUSEIPDB_KEY":       g.get("ABUSEIPDB_KEY", ""),
        "ABUSEIPDB_ENABLED":   g["ABUSEIPDB_ENABLED"],
        "TURNSTILE_SITEKEY":   g.get("TURNSTILE_SITEKEY", ""),
        "TURNSTILE_SECRET":    g.get("TURNSTILE_SECRET", ""),
        "_TURNSTILE_CONFIGURED": g["_TURNSTILE_CONFIGURED"],
        "TURNSTILE_ENABLED":   g["TURNSTILE_ENABLED"],
        "CROWDSEC_LAPI_URL":   g.get("CROWDSEC_LAPI_URL", ""),
        "CROWDSEC_API_KEY":    g.get("CROWDSEC_API_KEY", ""),
        "CROWDSEC_ENABLED":    g["CROWDSEC_ENABLED"],
    }
    for _rs_m in list(_sys_rs.modules.values()):
        if _rs_m is None or _rs_m is _sys_rs.modules.get("db.sqlite"):
            continue
        for _k, _v in _propagate.items():
            if hasattr(_rs_m, _k):
                try:
                    setattr(_rs_m, _k, _v)
                except (AttributeError, TypeError):
                    pass


def db_load_secrets(proxy_globals: dict) -> None:
    """1.5.5 — load DB-persisted integration secrets at startup AFTER env
    reads. Env wins iff the env var is set AND non-empty (operator's
    deploy is authoritative); otherwise the DB-stored value populates the
    in-process global. After loading, runtime helpers re-init dependent
    integration state (e.g. _TURNSTILE_CONFIGURED, ABUSEIPDB_ENABLED).

    Phase 2 note: `proxy_globals` must be the caller's globals() dict
    (i.e. proxy.py's module namespace) so secrets land in the right
    module. When called from proxy.py the caller passes globals()."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT key, value FROM secrets_kv").fetchall()
        conn.close()
    except Exception as e:
        slog("db_secrets_load_failed", level="error", error=str(e))
        return
    g = proxy_globals
    applied, env_pinned = 0, 0
    for r in rows:
        public_name = r["key"]
        if public_name not in _SECRET_KEYS:
            continue
        global_name, env_name = _SECRET_KEYS[public_name]
        # Env wins if it's actually set (non-empty)
        if os.environ.get(env_name, "").strip():
            env_pinned += 1
            continue
        g[global_name] = r["value"]
        applied += 1
    # Re-derive "configured" / "enabled" markers
    _refresh_integration_state(proxy_globals)
    if applied or env_pinned:
        slog("db_secrets_loaded", level="info", applied=applied, env_pinned=env_pinned)


def db_load_config(proxy_globals: dict) -> None:
    """1.5.5 — load DB-persisted hot-reload knobs over env defaults.
    Called at boot AFTER env-driven globals are initialised; DB takes
    precedence so changes pushed via /__config survive restart.

    Skips entries whose value fails the per-knob validator (e.g. an
    operator manually edited the row to a bogus value) — the env default
    stays in effect and a warning logs.

    Phase 2 note: `proxy_globals` must be the caller's globals() dict
    (i.e. proxy.py's module namespace). `_HOT_RELOAD_KNOBS` and
    `_ENV_PROVIDED_KNOBS` live in proxy.py; pass them in via the globals
    dict. When called from proxy.py the caller passes globals()."""
    g = proxy_globals
    _db_path = g.get("DB_PATH") or os.environ.get("DB_PATH") or DB_PATH
    try:
        conn = sqlite3.connect(_db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT key, value FROM config_kv").fetchall()
        conn.close()
    except Exception as e:
        slog("db_config_load_failed", level="error", error=str(e))
        return
    _HOT_RELOAD_KNOBS = g.get("_HOT_RELOAD_KNOBS", {})
    _ENV_PROVIDED_KNOBS = g.get("_ENV_PROVIDED_KNOBS", set())
    import sys as _sys
    # Sync _city_reader from proxy_globals into reputation.maxmind so that
    # validators defined in core.proxy_handler (which call _city_reader_is_loaded)
    # can see the value even when the proxy module was loaded via importlib
    # and is not registered in sys.modules["proxy"].
    _city_reader_val = g.get("_city_reader")
    _mm = _sys.modules.get("reputation.maxmind")
    if _mm is not None and _city_reader_val is not None:
        _mm._city_reader = _city_reader_val
    # Propagate credential keys from g into core.proxy_handler so that
    # validators defined there (e.g. ABUSEIPDB_ENABLED's lambda, which calls
    # globals().get("ABUSEIPDB_KEY")) see the current values from the caller's
    # globals dict rather than the stale import-time snapshot.  This mirrors
    # what _refresh_integration_state does after db_load_secrets in the normal
    # startup path; the test exercises db_load_config in isolation and skips
    # the secrets-load step, so we must apply the same sync here.
    _ph = _sys.modules.get("core.proxy_handler")
    if _ph is not None:
        for _cred in ("ABUSEIPDB_KEY", "CROWDSEC_LAPI_URL", "CROWDSEC_API_KEY",
                      "TURNSTILE_SITEKEY", "TURNSTILE_SECRET"):
            if _cred in g:
                try:
                    _ph.__dict__[_cred] = g[_cred]
                except TypeError:
                    pass
    applied, skipped, env_pinned = 0, 0, 0
    for r in rows:
        key = r["key"]
        spec = _HOT_RELOAD_KNOBS.get(key)
        if spec is None:
            skipped += 1
            continue
        # 1.5.5 — env wins. If the operator explicitly set this knob in the
        # container env, treat that as authoritative (GitOps determinism).
        if key in _ENV_PROVIDED_KNOBS:
            env_pinned += 1
            continue
        parser, validator = spec
        try:
            raw = json.loads(r["value"])
            value = parser(raw)
            if validator is not None and not validator(value):
                slog("db_config_invalid", level="warn", key=key, reason="validator")
                skipped += 1
                continue
            g[key] = value
            applied += 1
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            slog("db_config_parse_err", level="warn", key=key, error=str(e))
            skipped += 1
    # Mutual exclusion: JS_CHAL_REQUIRE_JA4 + TURNSTILE_ENABLED cannot both be
    # active. TURNSTILE_ENABLED wins — Turnstile topology implies Cloudflare CDN
    # terminates TLS, making JA4 unavailable and causing every challenge to fail.
    if g.get("JS_CHAL_REQUIRE_JA4") and g.get("TURNSTILE_ENABLED"):
        g["JS_CHAL_REQUIRE_JA4"] = False
        slog("db_config_ja4_forced_off", level="warn",
             reason="incompatible with TURNSTILE_ENABLED")
    if applied or skipped or env_pinned:
        slog("db_config_loaded", level="info",
             applied=applied, skipped=skipped, env_pinned=env_pinned)


def db_load_state() -> None:
    """Load saved state at startup. Populates state-module objects
    (ip_state, metrics, events, timeline, SERVICE_METRICS_HISTORY)
    directly — these are mutable containers imported by reference."""
    # Reset in-memory identity state so stale entries from a previous startup
    # (or a prior test invocation) don't persist when the DB table is empty.
    # In production on_startup is called once on a fresh container so ip_state
    # is always empty here; in tests each make_app() / on_startup() call must
    # see a clean slate to avoid cross-test risk-score contamination.
    ip_state.clear()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # 1.5.4 — IpState.first_seen / last_seen are time.monotonic() values, but
    # the DB persists epoch-wallclock (time.time()).  Convert by computing
    # how-many-seconds-ago the timestamp was (epoch_now - epoch_value), then
    # mapping that back onto the monotonic clock.  Pre-fix the in-memory
    # values were epoch-wallclock and (now() - epoch) yielded a hugely
    # negative number on the dashboard.
    mono_now  = time.monotonic()
    epoch_now = _t.time()
    n = epoch_now  # used for ban-until comparison below
    # Load clients (cap to MAX_IDENTITIES, newest first)
    rows = conn.execute(
        "SELECT * FROM clients ORDER BY last_seen DESC LIMIT ?",
        (MAX_IDENTITIES,)
    ).fetchall()
    for r in rows:
        s = ip_state[r["ip"]]
        ago_first = max(0, epoch_now - (r["first_seen"] or epoch_now))
        ago_last  = max(0, epoch_now - (r["last_seen"]  or epoch_now))
        s.first_seen = mono_now - ago_first
        s.last_seen  = mono_now - ago_last
        s.request_count = r["request_count"] or 0
        s.allowed_count = r["allowed_count"] or 0
        s.blocked_count = r["blocked_count"] or 0
        # banned_until is monotonic; if epoch > now, restore offset
        if r["banned_until_epoch"] and r["banned_until_epoch"] > n:
            s.banned_until = now() + (r["banned_until_epoch"] - n)
        s.last_user_agent = r["last_user_agent"] or ""
        s.last_path = r["last_path"] or ""
        if r["blocks_by_reason"]:
            try: s.blocks_by_reason = defaultdict(int, json.loads(r["blocks_by_reason"]))
            except (ValueError, TypeError): pass

    # Compute global totals from events table (always accurate, beats stale KV)
    row = conn.execute("""
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN reason='' OR reason='OK' THEN 1 ELSE 0 END) AS allowed,
               SUM(CASE WHEN reason!='' AND reason!='OK' THEN 1 ELSE 0 END) AS blocked
          FROM events
    """).fetchone()
    metrics["total_requests"] = row["total"] or 0
    metrics["allowed"] = row["allowed"] or 0
    metrics["blocked"] = row["blocked"] or 0

    # Reason breakdown from events
    for r in conn.execute(
        "SELECT reason, COUNT(*) AS n FROM events WHERE reason!='' AND reason!='OK' GROUP BY reason"
    ):
        metrics["by_reason"][r["reason"]] = r["n"]

    # Status breakdown
    for r in conn.execute(
        "SELECT status, COUNT(*) AS n FROM events GROUP BY status"
    ):
        metrics["by_status"][int(r["status"])] = r["n"]

    # Path top counts (only top 100 to limit memory)
    for r in conn.execute(
        "SELECT path, COUNT(*) AS n FROM events GROUP BY path ORDER BY n DESC LIMIT 100"
    ):
        metrics["by_path"][r["path"] or ""] = r["n"]

    # Load timeline
    for row in conn.execute("SELECT * FROM timeline"):
        # row['missed'] only present after the 1.5.4 migration ran; fall back to 0
        try:
            missed_v = row["missed"] or 0
        except (IndexError, KeyError):
            missed_v = 0
        timeline[row["bucket_minute"]] = {
            "total": row["total"], "allowed": row["allowed"], "blocked": row["blocked"],
            "missed": missed_v,
            "by_reason": defaultdict(int, json.loads(row["by_reason"] or "{}")),
        }

    # Load recent events into the in-memory deque (last 200)
    for row in conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 200"):
        events.appendleft({
            "ts": row["ts"], "ip": row["ip"], "ua": row["ua"] or "",
            "path": row["path"] or "", "method": row["method"] or "",
            "status": row["status"] or 0, "reason": row["reason"] or "OK",
        })

    # Re-hydrate the service-metrics history (last RETENTION samples in time
    # order). Skips silently if the table doesn't exist yet (first boot
    # against an old DB).
    svc_loaded = 0
    try:
        cur = conn.execute(
            "SELECT * FROM svc_metrics ORDER BY ts DESC LIMIT ?",
            (SERVICE_METRICS_RETENTION,))
        rows_svc = cur.fetchall()
        for row in reversed(rows_svc):       # oldest-first into the deque
            SERVICE_METRICS_HISTORY.append({k: row[k] for k in row.keys()})
        svc_loaded = len(rows_svc)
    except Exception as e:
        slog("db_svc_metrics_not_loaded", level="warn", error=str(e))
    conn.close()
    slog("db_state_loaded", level="info",
         clients=len(rows), timeline_buckets=len(timeline),
         total_requests=metrics["total_requests"], svc_metrics=svc_loaded)
