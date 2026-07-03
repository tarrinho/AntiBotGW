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
    DB_PATH,
    DB_BACKEND,  # iter-6: writer-loop fork needs this to honour the
                 # operator-controlled backend choice (not just DSN)
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
    # 1.8.0 — per-event vhost hostname for multi-vhost dashboard filtering
    ("events",      "vhost",           "TEXT DEFAULT ''",               "TEXT DEFAULT ''"),
    # 1.8.6 — TOTP two-factor authentication columns for users table
    ("users",       "totp_secret",     "TEXT",                          "TEXT"),
    ("users",       "totp_enabled",    "INTEGER DEFAULT 0",             "INTEGER DEFAULT 0"),
    ("users",       "totp_backup_codes", "TEXT",                        "TEXT"),
    # 1.8.5 — SSO-provisioned users start in 'pending' status until an admin
    # authorises them. sso_source records the identity provider (e.g. 'oidc').
    ("users",       "sso_source",      "TEXT",                          "TEXT"),
    # 1.8.5 — IdP subject claim (sub) bound on first SSO login. Used to
    # detect username-collision attacks: an attacker cannot create a local
    # account named 'admin' and then log in as that user via SSO.
    ("users",       "oidc_sub",        "TEXT",                          "TEXT"),
    # 1.8.13 — HTTP method stored per-event for honeypots/events dashboards.
    # Base CREATE TABLE had this column from 1.8.x but no migration existed
    # for armv7/SQLite devices upgraded from older schemas — fixed here.
    ("events",      "method",          "TEXT",                          "TEXT"),
    # 1.8.14 — Per-session CSRF nonce (T0-2): random nonce decoupled from
    # SESSION_KEY so key rotation does not invalidate live CSRF tokens.
    ("user_sessions", "csrf_nonce",    "TEXT",                          "TEXT"),
    # 1.8.14 iter-21 — `last_vhost` was added to IpState in iter-15 (Domain
    # column in main.html Clients table) but never persisted. After a GW
    # restart, the Domain column showed "—" for every row until each client
    # made a fresh request. Added column lets identity-vhost survive restart.
    ("clients",       "last_vhost",    "TEXT DEFAULT ''",               None),
]


def _sqlite_connect(path: str = None, timeout: float = None) -> sqlite3.Connection:
    """1.8.15 — single SQLite open path with consistent performance tuning.

    Every place we open SQLite must go through this helper so the same
    PRAGMA set is applied — otherwise the connection inherits SQLite's
    `synchronous=FULL` default which causes a full-disk-fsync on every
    commit (57ms on slow / networked storage = throughput collapse).

    Pragmas:
      journal_mode=WAL          concurrent readers + write-ahead log
      synchronous=NORMAL        fsync the WAL only, not main DB on each commit
      wal_autocheckpoint=10000  checkpoint every 10000 WAL frames (~40MB at
                                default 4KB page; default is 1000 frames ≈ 4MB,
                                so 10× fewer fsyncs at the cost of larger WAL)
      temp_store=MEMORY         keep temp B-trees out of slow disk
      mmap_size=256MB           memory-map hot pages for fast reads
      cache_size=-20000         20MB page cache (negative = KB)
    """
    p = path if path is not None else DB_PATH
    if timeout is not None:
        conn = sqlite3.connect(p, timeout=timeout)
    else:
        conn = sqlite3.connect(p)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA wal_autocheckpoint=10000")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=268435456")
        conn.execute("PRAGMA cache_size=-20000")
    except sqlite3.Error:
        # PRAGMA failures (rare; e.g. truncated DB) must not block the
        # connection. The default settings still produce a correct
        # (just slower) SQLite session.
        pass
    return conn


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


def db_init(db_path_override: str = ""):
    """Create tables if they don't exist.

    A2 fix: `db_path_override` lets the export CLI initialise a target
    file without mutating the global DB_PATH env var (the previous hack
    used importlib.reload + os.environ mutation, which could redirect a
    live writer at the export target if invoked from inside the gateway
    process). Pass an absolute path to write the schema there instead
    of to the configured DB_PATH.
    """
    _target = db_path_override or DB_PATH
    conn = _sqlite_connect(_target)
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
        last_vhost        TEXT DEFAULT '',  -- 1.8.14 iter-21
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

    -- 1.8.12 M-4 — IP-keyed ban table that survives SESSION_KEY rotation.
    -- Hostile/long-duration bans (>= HOSTILE_BAN_SECS) are mirrored here
    -- keyed by raw client IP, not by track_key.  protect() checks this table
    -- before identity derivation so a rotated key cannot free a hostile ban.
    CREATE TABLE IF NOT EXISTS ip_bans (
        ip            TEXT PRIMARY KEY,
        banned_until  REAL NOT NULL,
        reason        TEXT,
        ts            REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_ip_bans_until ON ip_bans(banned_until);

    -- 1.9.1 iter-11 — per-vhost bans (BAN_SCOPE="vhost"). Composite PK so the
    -- same IP can be banned on one vhost and free on another. Separate table
    -- (approach B) keeps legacy ip_bans untouched → additive, no rebuild,
    -- safe rollback. Global bans (default) never touch this table.
    CREATE TABLE IF NOT EXISTS ip_bans_vhost (
        ip            TEXT NOT NULL,
        vhost         TEXT NOT NULL,
        banned_until  REAL NOT NULL,
        reason        TEXT,
        ts            REAL NOT NULL,
        PRIMARY KEY (ip, vhost)
    );
    CREATE INDEX IF NOT EXISTS idx_ip_bans_vhost_until
        ON ip_bans_vhost(banned_until);

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

    -- 1.8.6: DLP pattern versioning — operator-managed regex library.
    CREATE TABLE IF NOT EXISTS dlp_patterns (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        name      TEXT NOT NULL,
        pattern   TEXT NOT NULL,
        severity  TEXT NOT NULL DEFAULT 'high',
        enabled   INTEGER NOT NULL DEFAULT 1,
        added_ts  REAL,
        added_by  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_dlp_name ON dlp_patterns(name);

    -- 1.8.6: structured audit log for admin operations.
    CREATE TABLE IF NOT EXISTS audit_events (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ts          REAL NOT NULL,
        event_type  TEXT NOT NULL,
        actor       TEXT,
        target      TEXT,
        ip          TEXT,
        detail      TEXT,
        session_id  TEXT,
        severity    TEXT NOT NULL DEFAULT 'info'
    );
    CREATE INDEX IF NOT EXISTS idx_audit_ts         ON audit_events(ts);
    CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_audit_actor      ON audit_events(actor);

    -- 1.8.6: server-side SIEM alert rules and fire history.
    CREATE TABLE IF NOT EXISTS siem_alert_rules (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        metric        TEXT NOT NULL,
        op            TEXT NOT NULL CHECK(op IN ('>','>=','<','<=')),
        threshold     REAL NOT NULL,
        label         TEXT NOT NULL DEFAULT '',
        enabled       INTEGER NOT NULL DEFAULT 1,
        created_ts    REAL NOT NULL,
        created_by    TEXT,
        last_fired_ts REAL DEFAULT 0,
        cooldown_s    INTEGER NOT NULL DEFAULT 300
    );
    CREATE TABLE IF NOT EXISTS siem_alert_fired (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id  INTEGER NOT NULL REFERENCES siem_alert_rules(id) ON DELETE CASCADE,
        ts       REAL NOT NULL,
        value    REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_siem_alert_fired_rule
        ON siem_alert_fired(rule_id, ts DESC);

    -- 1.8.12: confirmed-attacker fingerprints from honeypot/honey-cred hits.
    -- Every honeypot-silent and honey-cred event writes the requester's
    -- JA4, UA, and ASN here so the WAF can soft-flag future requests that
    -- share those attributes before they touch any trap.
    CREATE TABLE IF NOT EXISTS honey_fingerprints (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        ts        REAL NOT NULL,
        track_key TEXT,
        ip        TEXT NOT NULL,
        ua        TEXT,
        ja4       TEXT,
        asn       TEXT,
        path      TEXT,
        reason    TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_honey_fp_ts  ON honey_fingerprints(ts);
    CREATE INDEX IF NOT EXISTS idx_honey_fp_ja4 ON honey_fingerprints(ja4);
    CREATE INDEX IF NOT EXISTS idx_honey_fp_ip  ON honey_fingerprints(ip);
    """)
    # 1.6.7+ — additive column upgrades driven by the central registry.
    # See `_SCHEMA_MIGRATIONS` above; new releases append entries there.
    _apply_sqlite_migrations(conn)
    conn.commit()
    conn.close()

    # Also initialise Postgres schema whenever POSTGRES_DSN is configured
    # (even when the active backend is SQLite — standby must be schema-ready
    # for dual-write and operator-driven backend swaps).
    #
    # H4 fix: skip the PG init tail when called with a db_path_override. The
    # override path is used by db.export to seed a SQLite snapshot file —
    # the caller doesn't want a side effect of re-initialising the
    # production PG schema (and may not even have PG running). Production
    # boot path always uses the default DB_PATH, so this guard is a no-op
    # there.
    if not db_path_override and POSTGRES_DSN:
        # Local import to avoid circular dependency:
        # postgres.py imports _SCHEMA_MIGRATIONS from this module.
        from db.postgres import db_init_postgres
        db_init_postgres()


async def db_writer_loop():
    """Background coroutine: drains the queue and flushes to the active
    backend in batches.

    PG-only migration Phase 5: when POSTGRES_DSN is set (PG primary), the
    loop dispatches every queued op directly to `_pg_mirror_kv` and never
    touches SQLite. When POSTGRES_DSN is unset, the legacy SQLite-primary
    code path runs unchanged (and there is no PG side, so the inline
    `_pg_mirror_bg` calls below become no-ops because POSTGRES_DSN is
    falsy and `_pg_mirror_kv` short-circuits).

    Periodically runs `wal_checkpoint(TRUNCATE)` (SQLite mode only) so
    the WAL file stays small."""
    # Local import to avoid circular dependency at module load time.
    from db.postgres import _pg_mirror_kv, pg_insert_event  # noqa: F401

    # REVIEW-PG-DUAL-WRITE (iter-18): every op listed here is mirrored to
    # Postgres post-commit. Ops that are mirrored INLINE in the per-op
    # branches further down (set_config, del_config, set_secret, del_secret,
    # set_admin_ip, del_admin_ip, update_admin_ip_description, gw_audit_add,
    # honey_fp_add) are NOT in this set — they're already handled.
    #
    # M3 fix: defined here (before the PG-primary branch) so the coverage
    # guard can reference it.
    _PG_DUAL_WRITE_OPS = frozenset({
        # User accounts
        "user_create", "user_update", "user_delete", "user_login_recorded",
        "user_session_create", "user_session_touch", "user_session_revoke",
        # Bans (per-track_key + persistent IP)
        "ban", "ip_ban", "ip_ban_del",
        "ip_ban_vhost", "ip_ban_vhost_del",   # iter-11 per-vhost bans
        # DLP catalog
        "dlp_add", "dlp_toggle", "dlp_delete",
        # SIEM alerting
        "siem_alert_rule_add", "siem_alert_rule_del",
        "siem_alert_fired",   "siem_alert_toggle",
        # Mesh registry
        "gw_registry_add", "gw_registry_update", "gw_registry_delete",
        "gw_distribution_replace",
        # PG-only migration Phase 2: 10 ops previously SQLite-only.
        "abuseipdb_set", "audit_log", "gw_registry_discover",
        "mesh_sync_pending_upsert", "mesh_sync_status",
        "set_kv", "svc_metric", "svc_metric_prune",
        "upsert_client", "upsert_timeline",
        # NOTE: upsert_client mirrors all live IpState columns including
        # last_vhost (iter-21). The SQLite ON CONFLICT clause sets
        # last_vhost=excluded.last_vhost — keep parity in pg_insert_client.
    })

    # ── PG-primary writer-loop ──────────────────────────────────────────
    # Drains the same queue but routes every op to PG. The SQLite file is
    # never opened. Ops whose name doesn't match a registered PG arm are
    # logged once and dropped (no SQLite fallback — that would defeat the
    # single-DB guarantee).
    #
    # iter-6 fix (events-persistence-after-upgrade): fork on the OPERATOR-
    # CONTROLLED `DB_BACKEND` value, not on the presence of POSTGRES_DSN.
    # Previously, switching from PG → SQLite via /__db-switch persisted
    # `DB_BACKEND="sqlite"` to config_kv but LEFT the encrypted DSN in
    # secrets_kv (intentionally — operator may switch back). On the next
    # boot, db_load_secrets re-bound POSTGRES_DSN; the writer loop then
    # took the PG-primary branch despite the operator having explicitly
    # chosen SQLite, and every queued event went to PG (which may be
    # empty / unreachable / deliberately set aside). The SQLite events
    # table stayed empty across restarts — surfaced to the operator as
    # "events aren't persisted after gw upgrades".
    if DB_BACKEND == "postgres" and POSTGRES_DSN:
        # Op name translation: some SQLite-side ops use a different name
        # than the PG-side handler (e.g. admin_ip_add → set_admin_ip).
        _OP_RENAME = {
            "admin_ip_add":                 "set_admin_ip",
            "admin_ip_remove":              "del_admin_ip",
            "admin_ip_update_description":  "update_admin_ip_description",
        }
        # M3 fix: cross-check that every op listed in _PG_DUAL_WRITE_OPS
        # has either a 1:1 PG handler OR an entry in _OP_RENAME pointing
        # at one. 1.9.0 — db.postgres dispatch was refactored from an
        # if/elif chain to a `_PG_OP_HANDLERS = {op: fn}` dict, so the
        # old "grep for elif op ==" check became a stale false-positive
        # on every PG-mode boot. Interrogate the live dict membership
        # instead — same single-source-of-truth contract, accurate.
        _missing = []
        try:
            from db.postgres import _PG_OP_HANDLERS as _pg_handlers
            _pg_keys = set(_pg_handlers.keys())
        except Exception:
            _pg_keys = set()
        for _op in _PG_DUAL_WRITE_OPS:
            _pg_op = _OP_RENAME.get(_op, _op)
            if _pg_op not in _pg_keys:
                _missing.append((_op, _pg_op))
        if _missing:
            # Critical: stop the writer before it loses writes. Loud log
            # so ops see it; SystemExit lets the orchestrator restart.
            slog("db_pg_writer_coverage_gap", level="error",
                 missing=str(_missing),
                 hint="add a handler to _PG_OP_HANDLERS in db/postgres.py "
                      "or add to _OP_RENAME map")
            print(f"FATAL: _PG_DUAL_WRITE_OPS contains ops with no "
                  f"PG mirror handler: {_missing}. Refusing to start "
                  f"writer in PG-primary mode — fix coverage or revert "
                  f"the op addition.", flush=True)
            raise SystemExit(5)
        _dropped_ops_seen = set()  # one warn per op-name per process
        # PG-primary branch: SQLite is not the primary writer target. Boot-time
        # smoke-test that _sqlite_connect() actually works against DB_PATH so
        # the optional KV-mirror code path doesn't fail much later under load.
        # The connection is closed immediately — this is just a liveness check.
        try:
            _sqlite_connect(DB_PATH).close()
        except Exception as _smoke_err:
            slog("sqlite_smoke_failed", level="warn", error=str(_smoke_err)[:120])

        def _drain_batch_pg(batch):
            """1.9.7 — process one queued batch against PG in a WORKER THREAD.

            pg_insert_event / _pg_mirror_kv are synchronous psycopg calls
            (pool.connection() + execute) — running them inline on the event
            loop meant a slow Postgres query (cold pool, checkpoint, lock,
            write-burst) froze the WHOLE loop: /live (healthcheck) and real
            requests timed out → front-proxy 502, even with CPU idle. Running
            the batch via asyncio.to_thread keeps the loop responsive; the
            psycopg pool is thread-safe and only one writer batch runs at a
            time (the caller awaits this), so _dropped_ops_seen.add is safe.
            Each op keeps its own try/except (one bad op can't abort the
            batch); task_done() stays on the loop in the caller's finally.
            """
            for op, args in batch:
                try:
                    if op == "event":
                        # SQLite event args: (ts, ip, ua, path, method,
                        # status, reason, vhost). PG signature differs.
                        try:
                            if len(args) >= 8:
                                _ts, _ip, _ua, _path, _method, \
                                    _status, _reason, _vhost = args[:8]
                            else:
                                _ts, _ip, _ua, _path, _method, \
                                    _status, _reason = args[:7]
                                _vhost = ""
                            pg_insert_event(
                                _ts, _ip, _ua, _path,
                                _status, _reason,
                                method=_method, vhost=_vhost)
                        except Exception as _e:
                            slog("db_write_failed", level="error",
                                 error=str(_e), op=op)
                        continue
                    pg_op = _OP_RENAME.get(op, op)
                    ok = _pg_mirror_kv(pg_op, args)
                    if not ok and op not in _dropped_ops_seen:
                        _dropped_ops_seen.add(op)
                        slog("db_pg_op_unhandled",
                             level="warn", op=op, pg_op=pg_op,
                             hint="no _pg_mirror_kv arm; add one in "
                                  "db/postgres.py")
                except Exception as e:
                    slog("db_write_failed", level="error",
                         error=str(e), op=op)

        while True:
            batch = []  # 1.9.6 — reset BEFORE the try. On CancelledError during
            try:        # `await get()` (shutdown/test teardown) a stale prior-
                        # iteration batch must not be re-task_done()'d in finally
                        # ("task_done() called too many times" → crashed the run).
                batch = [await _state.db_queue.get()]
                while len(batch) < 100:
                    try:
                        batch.append(_state.db_queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                # Run the batch's synchronous psycopg writes OFF the event loop
                # so a slow Postgres query can't freeze it (see _drain_batch_pg).
                await asyncio.to_thread(_drain_batch_pg, batch)
            finally:
                for _ in batch:
                    _state.db_queue.task_done()
        # unreachable — loop is infinite

    # ── SQLite-primary writer-loop (legacy / default) ───────────────────

    def _pg_mirror_bg(op, args):
        """REVIEW-H2: fire-and-forget the PG mirror so a degraded PG never
        blocks the event-loop-bound SQLite writer. `_pg_mirror_kv` uses a
        sync `pool.connection(timeout=2.0)` + sync execute — calling it
        directly stalled the event loop up to 2 s × mirrors-per-batch when
        PG was unreachable. SQLite write is the source of truth; PG mirror
        is best-effort, so dropping the result on error is fine.

        A1 fix: short-circuit when POSTGRES_DSN is unset — there's nothing
        to mirror to, and the asyncio.create_task spawn cost (~50µs each)
        adds up on a busy gateway with many config writes. With PG-only
        mode now the only mode that uses dual-write helpers, this guard
        keeps the SQLite-only path zero-overhead.
        """
        if not POSTGRES_DSN:
            return
        try:
            asyncio.get_running_loop().create_task(
                asyncio.to_thread(_pg_mirror_kv, op, args)
            )
        except RuntimeError:
            # No running loop (test harness or shutdown) — fall back to sync.
            try:
                _pg_mirror_kv(op, args)
            except Exception:
                pass

    # (frozenset moved to top of function for M3 coverage guard.)

    # 1.8.15 — single open path applies WAL + tuned pragmas (see _sqlite_connect).
    conn = _sqlite_connect(DB_PATH)
    last_checkpoint = _t.time()
    last_vacuum = _t.time()
    while True:
        batch = []  # 1.9.6 — reset before try (see PG-primary loop): avoid
        try:        # stale-batch double task_done() on CancelledError in get()
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
                            "INSERT INTO events (ts,ip,ua,path,method,status,reason,vhost) "
                            "VALUES (?,?,?,?,?,?,?,?)", args)
                    elif op == "upsert_client":
                        conn.execute("""
                          INSERT INTO clients (ip, first_seen, last_seen, request_count,
                                               allowed_count, blocked_count, banned_until_epoch,
                                               last_user_agent, last_path, last_vhost, blocks_by_reason)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(ip) DO UPDATE SET
                            last_seen=excluded.last_seen,
                            request_count=excluded.request_count,
                            allowed_count=excluded.allowed_count,
                            blocked_count=excluded.blocked_count,
                            banned_until_epoch=excluded.banned_until_epoch,
                            last_user_agent=excluded.last_user_agent,
                            last_path=excluded.last_path,
                            last_vhost=excluded.last_vhost,
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
                        _pg_mirror_bg("set_config", args)  # REVIEW-H2: off-loop
                    elif op == "del_config":
                        conn.execute("DELETE FROM config_kv WHERE key = ?", args)
                        _pg_mirror_bg("del_config", args)  # REVIEW-H2
                    elif op == "set_secret":
                        # 1.5.5 — runtime integration-secret persistence.
                        # 1.9.8 M6 (CWE-312) — encrypt EVERY secret at rest, not just
                        # POSTGRES_DSN. _dsn_encrypt is idempotent (prefix-guarded) so a
                        # pre-encrypted DSN is never double-wrapped; SQLite and the PG
                        # mirror store the identical ciphertext.
                        args = (args[0], _dsn_encrypt(args[1]), args[2])
                        conn.execute("INSERT OR REPLACE INTO secrets_kv (key,value,ts) VALUES (?,?,?)", args)
                        _pg_mirror_bg("set_secret", args)  # REVIEW-H2
                    elif op == "del_secret":
                        conn.execute("DELETE FROM secrets_kv WHERE key = ?", args)
                        _pg_mirror_bg("del_secret", args)  # REVIEW-H2
                    elif op == "ban":
                        conn.execute("""
                          INSERT INTO bans (ip,banned_until,reason,ts) VALUES (?,?,?,?)
                          ON CONFLICT(ip) DO UPDATE SET banned_until=excluded.banned_until,
                                                        reason=excluded.reason, ts=excluded.ts
                        """, args)
                    elif op == "ip_ban":
                        # 1.8.12 M-4 — args = (ip, banned_until, reason, ts)
                        conn.execute("""
                          INSERT INTO ip_bans (ip,banned_until,reason,ts) VALUES (?,?,?,?)
                          ON CONFLICT(ip) DO UPDATE SET
                            banned_until=CASE WHEN excluded.banned_until > banned_until
                                              THEN excluded.banned_until ELSE banned_until END,
                            reason=excluded.reason, ts=excluded.ts
                        """, args)
                        _ban_cache_invalidate(args[0])  # 1.9.5 #3 — enforce new ban now
                    elif op == "ip_ban_del":
                        # args = (ip,)
                        conn.execute("DELETE FROM ip_bans WHERE ip = ?", args)
                        _ban_cache_invalidate(args[0])
                    elif op == "ip_ban_vhost":
                        # iter-11 — args = (ip, vhost, banned_until, reason, ts).
                        # Monotonic-max so a shorter ban never shrinks a longer one.
                        conn.execute("""
                          INSERT INTO ip_bans_vhost (ip,vhost,banned_until,reason,ts)
                          VALUES (?,?,?,?,?)
                          ON CONFLICT(ip,vhost) DO UPDATE SET
                            banned_until=CASE WHEN excluded.banned_until > banned_until
                                              THEN excluded.banned_until ELSE banned_until END,
                            reason=excluded.reason, ts=excluded.ts
                        """, args)
                        _ban_cache_invalidate(args[0], args[1])
                    elif op == "ip_ban_vhost_del":
                        # args = (ip, vhost)
                        conn.execute(
                            "DELETE FROM ip_bans_vhost WHERE ip = ? AND vhost = ?",
                            args)
                        _ban_cache_invalidate(args[0], args[1])
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
                        _pg_mirror_bg("set_admin_ip", args)  # REVIEW-H2
                    elif op == "admin_ip_remove":
                        # args = (cidr,)
                        conn.execute("DELETE FROM admin_ips WHERE cidr = ?", args)
                        _pg_mirror_bg("del_admin_ip", args)  # REVIEW-H2
                    elif op == "admin_ip_update_description":
                        # args = (description, cidr)
                        conn.execute(
                            "UPDATE admin_ips SET description=? WHERE cidr=?",
                            args)
                        _pg_mirror_bg("update_admin_ip_description", args)  # REVIEW-H2
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
                        _pg_mirror_bg("gw_audit_add", args)  # REVIEW-H2
                    elif op == "honey_fp_add":
                        # args = (ts, track_key, ip, ua, ja4, asn, path, reason)
                        conn.execute(
                            "INSERT INTO honey_fingerprints "
                            "(ts, track_key, ip, ua, ja4, asn, path, reason) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            args)
                        _pg_mirror_bg("honey_fp_add", args)  # REVIEW-H2
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
                            _USER_MUTABLE = frozenset({
                                "password_hash", "role", "status",
                                "totp_secret", "totp_enabled", "totp_backup_codes",
                                "oidc_sub", "sso_source",
                                "updated_ts",
                            })
                            bad = set(fields) - _USER_MUTABLE
                            if bad:
                                raise ValueError(f"user_update: unknown columns {bad}")
                            cols   = ", ".join(f"{k}=?" for k in fields)
                            params = list(fields.values()) + [username]
                            conn.execute(
                                f"UPDATE users SET {cols} WHERE username=?",  # nosec B608 — cols validated against _USER_MUTABLE
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
                        #         last_seen_ts, expires_ts, csrf_nonce)
                        conn.execute(
                            "INSERT INTO user_sessions "
                            "(sid, username, ip, user_agent, "
                            " created_ts, last_seen_ts, expires_ts, status, csrf_nonce) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)",
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
                    # 1.8.6 — DLP pattern CRUD ───────────────────────
                    elif op == "dlp_add":
                        # args = (name, pattern, severity, added_ts, added_by)
                        conn.execute(
                            "INSERT OR IGNORE INTO dlp_patterns "
                            "(name, pattern, severity, added_ts, added_by) "
                            "VALUES (?, ?, ?, ?, ?)",
                            args)
                    elif op == "dlp_toggle":
                        # args = (enabled, id)
                        conn.execute(
                            "UPDATE dlp_patterns SET enabled=? WHERE id=?",
                            args)
                    elif op == "dlp_delete":
                        # args = (id,)
                        conn.execute("DELETE FROM dlp_patterns WHERE id=?", args)
                    # 1.8.6 — admin audit log ─────────────────────────
                    elif op == "audit_log":
                        ts, event_type, actor, target, ip, detail_json, session_id, severity = args
                        conn.execute(
                            "INSERT INTO audit_events "
                            "(ts, event_type, actor, target, ip, detail, session_id, severity) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (ts, event_type, actor, target, ip, detail_json, session_id, severity))
                    # 1.8.6 — SIEM server-side alert rules ────────────
                    elif op == "siem_alert_rule_add":
                        # args = (metric, op, threshold, label, created_ts, created_by, cooldown_s)
                        conn.execute(
                            "INSERT INTO siem_alert_rules "
                            "(metric, op, threshold, label, created_ts, created_by, cooldown_s) "
                            "VALUES (?,?,?,?,?,?,?)",
                            args)
                    elif op == "siem_alert_rule_del":
                        # args = (id,)
                        conn.execute("DELETE FROM siem_alert_rules WHERE id = ?", args)
                    elif op == "siem_alert_fired":
                        # args = (rule_id, ts, value)
                        conn.execute(
                            "INSERT INTO siem_alert_fired (rule_id, ts, value) VALUES (?,?,?)",
                            args)
                        conn.execute(
                            "UPDATE siem_alert_rules SET last_fired_ts = ? WHERE id = ?",
                            (args[1], args[0]))
                    elif op == "siem_alert_toggle":
                        # args = (enabled, id)
                        conn.execute(
                            "UPDATE siem_alert_rules SET enabled = ? WHERE id = ?",
                            args)
                except Exception as e:
                    slog("db_write_failed", level="error", error=str(e), op=op)
                else:
                    # REVIEW-PG-DUAL-WRITE (iter-18): mirror every supported
                    # op to Postgres so cold-start restore can rebuild SQLite
                    # from PG when /data is wiped. Existing mirrored ops
                    # (set_config/del_config/set_secret/del_secret/admin_ips/
                    # gw_audit_add/honey_fp_add) are handled inline above and
                    # skipped here; this block covers the rest.
                    if op in _PG_DUAL_WRITE_OPS:
                        _pg_mirror_bg(op, args)
            try:
                conn.commit()
            finally:
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
            # 1.8.15 — legacy 24h VACUUM removed. The new daily scheduler
            # (core/proxy_handler.py:_vacuum_scheduler_loop) owns this entirely:
            # it (a) runs on a separate connection wrapped in asyncio.to_thread
            # so the event loop stays responsive, (b) respects the migration
            # guard (_BG_MIGRATION) and single-flight lock (_DB_VACUUM_LOCK),
            # (c) records each run in gw_audit. Running VACUUM here ALSO
            # would race those guards on the writer-loop connection.
            # `last_vacuum` is retained but no longer used.
            _ = last_vacuum
        except asyncio.CancelledError:
            try:
                conn.close()
            except Exception:
                pass
            break
        except Exception as e:
            slog("db_loop_error", level="error", error=str(e))
            await asyncio.sleep(1)
            try:
                conn.close()
            except Exception:
                pass
            # 1.8.15 — recover via tuned helper (matches initial open)
            conn = _sqlite_connect(DB_PATH)


# ── 1.5.5 — runtime integration-secret store ──────────────────────────────
# Each entry maps the public /__secrets endpoint key →
# (the proxy.py global that holds the value, the env var name we honour
#  as bootstrap fallback). Add new ones here.

# 1.9.0 (F14) — Fernet encryption-at-rest for the operational DSN.
# secrets_kv stores credential material as TEXT. Moving POSTGRES_DSN from
# config_kv → secrets_kv hides it from /__config (GET never returns
# secrets_kv) but the value still sits in plaintext on disk. Wrap it in
# Fernet keyed off the on-host SESSION_KEY (cf. /data/.session_key) so a
# stolen DB file alone is not enough to recover the DSN.
#
# Caveat: rotating SESSION_KEY invalidates the on-disk ciphertext (and
# the live CSRF tokens). Operators must re-enter the DSN via /__db-switch
# after rotation. Acceptable because rotation already invalidates other
# bound state and is a deliberate operator action.
_DSN_ENC_PREFIX = "enc:v1:"

def _fernet_key_from_session() -> "bytes | None":
    """Derive a Fernet key from the on-host SESSION_KEY.

    Returns None when SESSION_KEY isn't reachable (early boot, tests
    without proxy module). Callers must treat None as "skip encryption"
    and fall back to plaintext storage — the move to secrets_kv (off the
    /__config GET path) is the load-bearing mitigation either way."""
    try:
        import base64, hashlib, sys as _sys
        sk = None
        for _name in ("proxy", "config"):
            _m = _sys.modules.get(_name)
            if _m is not None and hasattr(_m, "SESSION_KEY"):
                sk = getattr(_m, "SESSION_KEY")
                if sk:
                    break
        if not sk:
            return None
        if isinstance(sk, str):
            sk = sk.encode("utf-8")
        # Domain-separated derive — never reuse SESSION_KEY material verbatim.
        derived = hashlib.sha256(b"agw-dsn-fernet-v1\x00" + bytes(sk)).digest()
        return base64.urlsafe_b64encode(derived)
    except Exception:
        return None


def _dsn_encrypt(plaintext: str) -> str:
    """Encrypt a DSN string for at-rest storage in secrets_kv.

    Returns the original string unchanged when Fernet/cryptography is
    unavailable or SESSION_KEY isn't bound yet — load path tolerates
    both formats via the `enc:v1:` prefix probe."""
    if not plaintext:
        return plaintext
    if plaintext.startswith(_DSN_ENC_PREFIX):
        return plaintext  # already encrypted (defensive — idempotent)
    try:
        from cryptography.fernet import Fernet  # type: ignore
        key = _fernet_key_from_session()
        if not key:
            return plaintext
        token = Fernet(key).encrypt(plaintext.encode("utf-8")).decode("ascii")
        return _DSN_ENC_PREFIX + token
    except Exception as _e:
        slog("dsn_encrypt_failed", level="warn", error=str(_e)[:120])
        return plaintext


def _dsn_decrypt(value: str) -> str:
    """Reverse of _dsn_encrypt. Plaintext (no prefix) returned as-is so
    legacy rows written before F14 keep working until next /db-switch."""
    if not value or not value.startswith(_DSN_ENC_PREFIX):
        return value
    try:
        from cryptography.fernet import Fernet  # type: ignore
        key = _fernet_key_from_session()
        if not key:
            slog("dsn_decrypt_no_key", level="error",
                 note="SESSION_KEY missing; DSN cannot be decrypted")
            return ""
        token = value[len(_DSN_ENC_PREFIX):].encode("ascii")
        return Fernet(key).decrypt(token).decode("utf-8")
    except Exception as _e:
        slog("dsn_decrypt_failed", level="error",
             error=type(_e).__name__,
             note="ciphertext won't open with current SESSION_KEY — "
                  "re-enter the DSN via /__db-switch")
        return ""


_SECRET_KEYS = {
    "TURNSTILE_SITEKEY":   ("TURNSTILE_SITEKEY",   "TURNSTILE_SITEKEY"),
    "TURNSTILE_SECRET":    ("TURNSTILE_SECRET",    "TURNSTILE_SECRET"),
    "ABUSEIPDB_KEY":       ("ABUSEIPDB_KEY",       "ABUSEIPDB_KEY"),
    "CROWDSEC_LAPI_URL":   ("CROWDSEC_LAPI_URL",   "CROWDSEC_LAPI_URL"),
    "CROWDSEC_LAPI_KEY":   ("CROWDSEC_API_KEY",    "CROWDSEC_LAPI_KEY"),
    "MAXMIND_LICENSE_KEY": ("MAXMIND_LICENSE_KEY", "MAXMIND_LICENSE_KEY"),
    "OIDC_ISSUER":        ("OIDC_ISSUER",        "OIDC_ISSUER"),
    "OIDC_CLIENT_ID":     ("OIDC_CLIENT_ID",      "OIDC_CLIENT_ID"),
    "OIDC_CLIENT_SECRET": ("OIDC_CLIENT_SECRET",  "OIDC_CLIENT_SECRET"),
    "OIDC_DEFAULT_ROLE":  ("OIDC_DEFAULT_ROLE",   "OIDC_DEFAULT_ROLE"),
    "OIDC_SCOPES":        ("OIDC_SCOPES",         "OIDC_SCOPES"),
    "POSTGRES_DSN":       ("POSTGRES_DSN",        "POSTGRES_DSN"),
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
    g["OIDC_ENABLED"] = bool(
        g.get("OIDC_ISSUER") and g.get("OIDC_CLIENT_ID") and g.get("OIDC_CLIENT_SECRET")
    )
    # Propagate secrets AND derived flags to all loaded modules so that:
    #   • db_load_config validators (which read proxy_handler globals) see the
    #     real credential values before validating ABUSEIPDB_ENABLED et al.
    #   • _read_hot_reload_state() in proxy_handler returns the live values,
    #     not the config.py defaults — fixes Controls showing stale state.
    _propagate = {
        "POSTGRES_DSN":        g.get("POSTGRES_DSN", ""),
        "ABUSEIPDB_KEY":       g.get("ABUSEIPDB_KEY", ""),
        "ABUSEIPDB_ENABLED":   g["ABUSEIPDB_ENABLED"],
        "TURNSTILE_SITEKEY":   g.get("TURNSTILE_SITEKEY", ""),
        "TURNSTILE_SECRET":    g.get("TURNSTILE_SECRET", ""),
        "_TURNSTILE_CONFIGURED": g["_TURNSTILE_CONFIGURED"],
        "TURNSTILE_ENABLED":   g["TURNSTILE_ENABLED"],
        "CROWDSEC_LAPI_URL":   g.get("CROWDSEC_LAPI_URL", ""),
        "CROWDSEC_API_KEY":    g.get("CROWDSEC_API_KEY", ""),
        "CROWDSEC_ENABLED":    g["CROWDSEC_ENABLED"],
        "OIDC_ISSUER":        g.get("OIDC_ISSUER", ""),
        "OIDC_CLIENT_ID":     g.get("OIDC_CLIENT_ID", ""),
        "OIDC_CLIENT_SECRET": g.get("OIDC_CLIENT_SECRET", ""),
        "OIDC_DEFAULT_ROLE":  g.get("OIDC_DEFAULT_ROLE", "viewer"),
        "OIDC_SCOPES":        g.get("OIDC_SCOPES", "openid profile email"),
        "OIDC_ENABLED":       g["OIDC_ENABLED"],
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
    module. When called from proxy.py the caller passes globals().

    1.8.8 — also **propagate** each loaded secret across sys.modules. The
    historical bug: db_load_secrets would set `proxy.POSTGRES_DSN` but
    leave `core.proxy_handler.POSTGRES_DSN` and `db.postgres.POSTGRES_DSN`
    at their import-time empty value. /db-test then returned dsn_masked=""
    and the popup said "no saved DSN" even though the DB had the value.
    Mirrors the patch already in `secrets_endpoint` and `db_switch_endpoint`.
    """
    # iter-7 fix (1.8.x → 1.9.x upgrade): in 1.8.x POSTGRES_DSN was
    # stored as plaintext in config_kv. F14 (1.9.0 iter-4) moved it to
    # secrets_kv + Fernet-encrypted, but `db_load_config` now SKIPS any
    # _SECRET_KEYS row in config_kv (config_kv_stomp_blocked). Result:
    # an operator upgrading from 1.8.x to 1.9.x loses their persisted
    # DSN — db_load_secrets reads nothing from secrets_kv (no row yet),
    # config_kv has the row but it gets skipped, POSTGRES_DSN stays
    # empty, PG mode silently fails to start.
    #
    # One-shot lift: if secrets_kv has no POSTGRES_DSN row AND config_kv
    # has one (legacy plaintext), copy + encrypt + write to secrets_kv,
    # then DELETE the legacy config_kv row so the stomp-blocked warning
    # stops firing. Subsequent boots see the row in secrets_kv and skip
    # this block entirely.
    try:
        _mig_conn = _sqlite_connect(DB_PATH)
        _has_secret = _mig_conn.execute(
            "SELECT 1 FROM secrets_kv WHERE key = 'POSTGRES_DSN'"
        ).fetchone()
        if not _has_secret:
            _legacy = _mig_conn.execute(
                "SELECT value FROM config_kv WHERE key = 'POSTGRES_DSN'"
            ).fetchone()
            if _legacy and _legacy[0]:
                # Unquote — db_load_config stored config values as
                # json.dumps(str). The same str is needed verbatim
                # post-decrypt at runtime.
                _raw_dsn = _legacy[0]
                try:
                    import json as _json_mig
                    _raw_dsn = _json_mig.loads(_legacy[0])
                except (ValueError, TypeError):
                    pass  # already raw, accept as-is
                # iter-9 (code-review MED-2): validate the lifted value
                # looks like a real DSN before encrypting + persisting.
                # Without this, a partially-corrupted legacy row (e.g.
                # `'{"key": "value` — unterminated JSON) falls through
                # the json.loads `except: pass` and gets encrypted as
                # garbage. Operator's PG-init then fails silently on
                # next boot and the only diagnostic is `pg_test_roundtrip
                # not configured`. Refuse to migrate values that don't
                # parse as a postgres:// or postgresql:// URL — leave
                # the legacy row in place so the operator can inspect
                # and `/__db-switch` manually.
                _looks_valid = False
                if isinstance(_raw_dsn, str) and _raw_dsn:
                    try:
                        from urllib.parse import urlparse as _up_mig
                        _p = _up_mig(_raw_dsn)
                        _looks_valid = (
                            _p.scheme in ("postgres", "postgresql")
                            and bool(_p.hostname))
                    except Exception:
                        _looks_valid = False
                if _looks_valid:
                    _ct = _dsn_encrypt(_raw_dsn)
                    _mig_conn.execute(
                        "INSERT OR REPLACE INTO secrets_kv "
                        "(key, value, ts) VALUES (?, ?, ?)",
                        ("POSTGRES_DSN", _ct, time.time()))
                    _mig_conn.execute(
                        "DELETE FROM config_kv WHERE key = 'POSTGRES_DSN'")
                    _mig_conn.commit()
                    slog("legacy_dsn_lifted", level="warn",
                         note="1.8.x → 1.9.x upgrade: lifted plaintext "
                              "POSTGRES_DSN from config_kv to "
                              "secrets_kv (Fernet-encrypted); deleted "
                              "the legacy config_kv row")
                elif isinstance(_raw_dsn, str) and _raw_dsn:
                    slog("legacy_dsn_lift_skipped_malformed", level="error",
                         len=len(_raw_dsn),
                         note="config_kv has a POSTGRES_DSN row but it "
                              "doesn't parse as a postgres:// URL — "
                              "refused to migrate to avoid storing "
                              "corrupted ciphertext. Inspect the row "
                              "manually and re-enter the DSN via "
                              "/__db-switch.")
        _mig_conn.close()
    except Exception as _mig_e:
        slog("legacy_dsn_lift_failed", level="warn",
             error=str(_mig_e)[:200],
             note="1.8.x upgrade migration failed; operator may need "
                  "to re-enter POSTGRES_DSN via /__db-switch")
    try:
        # 1.9.2 iter — same backend-aware routing as db_load_config: when
        # POSTGRES_DSN is set, secrets_kv lives in PG. Without this, an
        # operator whose POSTGRES_DSN was saved via /__db-switch (Fernet-
        # encrypted in secrets_kv) would not see it loaded back on a fresh
        # /data deployment.
        from db.conn import active_backend
        _backend = active_backend()
        if _backend == "postgres":
            from db.conn import conn as _backend_conn
            with _backend_conn(timeout=5) as _bc:
                _bc.row_factory = sqlite3.Row
                rows = _bc.execute(
                    "SELECT key, value FROM secrets_kv").fetchall()
        else:
            conn = _sqlite_connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT key, value FROM secrets_kv").fetchall()
            conn.close()
    except Exception as e:
        slog("db_secrets_load_failed", level="error",
             backend=locals().get("_backend", "unknown"), error=str(e))
        return
    g = proxy_globals
    applied, env_pinned = 0, 0
    loaded: list[tuple[str, str]] = []  # (global_name, value) to propagate
    for r in rows:
        public_name = r["key"]
        if public_name not in _SECRET_KEYS:
            continue
        global_name, env_name = _SECRET_KEYS[public_name]
        # Env wins if it's actually set (non-empty)
        if os.environ.get(env_name, "").strip():
            env_pinned += 1
            continue
        # 1.9.8 M6 (CWE-312) — EVERY secret is stored Fernet-encrypted at rest
        # now (was POSTGRES_DSN only). _dsn_decrypt is a no-op on legacy plaintext
        # rows, so an in-place upgrade keeps booting; each row re-encrypts on its
        # next write. A "" result means prefixed-but-unreadable (lost SESSION_KEY).
        _value = _dsn_decrypt(r["value"])
        if public_name == "POSTGRES_DSN" and not _value:
            # Decrypt failed (lost SESSION_KEY). Skip rather than bind an
            # empty DSN that would silently disable PG.
            slog("db_secrets_dsn_skipped", level="error",
                 note="POSTGRES_DSN ciphertext unreadable; skipped")
            continue
        g[global_name] = _value
        loaded.append((global_name, _value))
        applied += 1
    # 1.8.8 — propagate each loaded secret to every module that already has
    # the same name bound. Critical for POSTGRES_DSN, which is referenced by
    # `core.proxy_handler` (the /db-test handler reads it for `dsn_masked`)
    # and `db.postgres` (pg_test_roundtrip + the migration helpers). Without
    # this step, the popup's "Load DSN" returns "no saved DSN" because the
    # only module that got the new value was proxy.py.
    import sys as _sys
    for global_name, value in loaded:
        for _m in list(_sys.modules.values()):
            if _m is None:
                continue
            if hasattr(_m, global_name):
                try:
                    setattr(_m, global_name, value)
                except (AttributeError, TypeError):
                    pass
    # Re-derive "configured" / "enabled" markers
    _refresh_integration_state(proxy_globals)
    if applied or env_pinned:
        slog("db_secrets_loaded", level="info",
             applied=applied, env_pinned=env_pinned,
             propagated=len(loaded))


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
    # 1.9.2 iter — backend-aware read. When POSTGRES_DSN is set, config_kv
    # lives in PG; previously this opened SQLite at DB_PATH directly, which
    # read an empty /data even when PG had the operator's settings. Symptom:
    # "all dashboard knobs reset on every upgrade" — the /data volume was
    # ephemeral on PG-backed deploys, and we were ignoring the canonical PG
    # state at load time. SQLite path keeps the per-call DB_PATH resolution
    # (g.get → env → module default) so tests that override DB_PATH at
    # runtime still work.
    try:
        from db.conn import active_backend
        _backend = active_backend()
        if _backend == "postgres":
            from db.conn import conn as _backend_conn
            with _backend_conn(timeout=5) as _bc:
                _bc.row_factory = sqlite3.Row
                rows = _bc.execute("SELECT key, value FROM config_kv").fetchall()
        else:
            _db_path = g.get("DB_PATH") or os.environ.get("DB_PATH") or DB_PATH
            conn = _sqlite_connect(_db_path)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT key, value FROM config_kv").fetchall()
            conn.close()
    except Exception as e:
        # Fail-loud: don't silently fall back to SQLite when PG was the
        # chosen backend (single-DB contract from 1.9.0). Operator sees env
        # defaults; the log line names the backend so triage is fast.
        slog("db_config_load_failed", level="error",
             backend=locals().get("_backend", "unknown"), error=str(e))
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
    applied, skipped, env_pinned, secret_skipped = 0, 0, 0, 0
    _stale_backend_row = False   # 1.9.3 — set when a sqlite DB_BACKEND row is coerced
    for r in rows:
        key = r["key"]
        spec = _HOT_RELOAD_KNOBS.get(key)
        if spec is None:
            skipped += 1
            continue
        # 1.9.2 iter-23 — PG-only authority. When POSTGRES_DSN is set, Postgres
        # IS the backend, full stop. A persisted config_kv DB_BACKEND="sqlite"
        # (a stale operator choice, or a pre-PG-only-migration /db-switch) must
        # NOT override it — otherwise the gateway silently runs SQLite while a
        # healthy Postgres sits idle and events split across two stores (the
        # exact production failure: 8.3M rows in PG, then a 1.5h gap in SQLite).
        # Coerce the row to postgres in-memory so the normal apply+propagate
        # path below forces DB_BACKEND=postgres everywhere.
        if key == "DB_BACKEND" and POSTGRES_DSN:
            try:
                _persisted_be = str(json.loads(r["value"])).lower()
            except Exception:
                _persisted_be = "?"
            if _persisted_be != "postgres":
                slog("db_backend_forced_pg_by_dsn", level="warn",
                     persisted=_persisted_be,
                     note="POSTGRES_DSN set → Postgres authoritative; persisted "
                          "DB_BACKEND override ignored — self-healing the row.")
                # 1.9.3 — mark for self-heal. iter-23 only forced the RUNTIME
                # value; the stale sqlite ROW survived in config_kv, so the
                # warning recurred every boot and any UI reading the persisted
                # value still showed sqlite. We rewrite it to postgres after the
                # loop (below) so it self-cleans — no manual DELETE needed.
                _stale_backend_row = True
            r = {"key": "DB_BACKEND", "value": json.dumps("postgres")}
        # 1.8.8 — secrets are owned by db_load_secrets (which reads
        # secrets_kv). If a key is in BOTH _HOT_RELOAD_KNOBS and
        # _SECRET_KEYS (notably POSTGRES_DSN), config_kv must NOT be
        # allowed to overwrite the secret value. Historical bug:
        # /db-switch wrote DSN to config_kv too, and if the in-memory
        # DSN happened to be empty at that moment, the empty got
        # persisted and silently stomped the real DSN on every restart.
        if key in _SECRET_KEYS:
            secret_skipped += 1
            # Emit a per-collision WARN so operators can see (a) which
            # secret keys have a stomper row in config_kv and (b) the
            # length of the would-be-applied value (0 == the stomp case).
            slog("config_kv_stomp_blocked", level="warn",
                 key=key,
                 stomper_value_len=len(r["value"] or ""),
                 note=("config_kv has a row for this key but it is also a "
                       "secret; the secrets_kv value (loaded by db_load_secrets) "
                       "wins. Operator: remove the stale config_kv row for key=%r." % key))
            continue
        # iter-9 (code-review HIGH-1): refuse to apply security-sensitive
        # trust-topology knobs from config_kv. An attacker with write
        # access to config_kv (admin auth bypass / SQL injection) would
        # otherwise be able to add their own IP to TRUSTED_PROXIES or
        # flip TRUST_XFF to 'last' → persistent IP-spoofing of every
        # IP-gated check. Set these via env at deploy time.
        _DB_LOAD_DENY = g.get("_DB_LOAD_DENY", frozenset())
        if key in _DB_LOAD_DENY:
            secret_skipped += 1
            slog("config_kv_security_knob_refused", level="warn",
                 key=key,
                 stomper_value_len=len(r["value"] or ""),
                 note=("config_kv contains a trust-topology knob; "
                       "ignored. Set %r via env (compose/k8s) and "
                       "restart. See _DB_LOAD_DENY in "
                       "core/proxy_handler.py for the rationale." % key))
            continue
        # 1.5.5 — env wins. If the operator explicitly set this knob in the
        # container env, treat that as authoritative (GitOps determinism).
        # 1.8.14 exception — DB_BACKEND has a dedicated operator-mediated
        # switch (/secured/db-switch) that runs a connectivity probe, schema
        # init, pool reset, and event-window migration before flipping the
        # runtime. The endpoint persists the choice to config_kv. If env still
        # won here, the operator's UI switch would silently revert on every
        # restart. Treat env DB_BACKEND as the COLD-START DEFAULT only — once
        # config_kv has a row for it, the persisted value is authoritative.
        if key in _ENV_PROVIDED_KNOBS and key != "DB_BACKEND":
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
            # Propagate to all loaded modules so request handlers (e.g.
            # core.proxy_handler) that hold their own copy of the global
            # see the DB-loaded value immediately — mirrors what the
            # hot-reload POST handler does at runtime.
            import sys as _sys_dbc
            for _hr_m in list(_sys_dbc.modules.values()):
                if (_hr_m is not None and _hr_m is not g
                        and hasattr(_hr_m, key)):
                    try:
                        setattr(_hr_m, key, value)
                    except (AttributeError, TypeError):
                        pass
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
    # 1.9.3 — self-heal a stale persisted DB_BACKEND row. The coercion above
    # forced the RUNTIME value to postgres; now make it PERMANENT by rewriting
    # the config_kv row, so the warning doesn't recur every boot and any UI
    # reading the persisted value is correct. Backend-aware write (`conn()`
    # routes to PG when POSTGRES_DSN is set, where config_kv lives). The boot
    # writer queue isn't running yet, so this is a direct synchronous UPDATE.
    # Best-effort: a failure never blocks boot — the runtime value is already
    # correct; only the persisted row would stay stale.
    if _stale_backend_row:
        try:
            from db.conn import conn as _bk_conn
            with _bk_conn(timeout=5) as _wc:
                _wc.execute(
                    "UPDATE config_kv SET value=? WHERE key=?",
                    (json.dumps("postgres"), "DB_BACKEND"))
                _wc.commit()
            slog("db_backend_row_self_healed", level="info",
                 note="persisted config_kv DB_BACKEND rewritten to postgres "
                      "(POSTGRES_DSN authoritative) — no manual cleanup needed")
        except Exception as _heal_err:
            slog("db_backend_self_heal_failed", level="warn",
                 error=str(_heal_err)[:160],
                 note="runtime backend is still postgres; only the persisted "
                      "row stayed stale. Safe to ignore or clear manually.")
    if applied or skipped or env_pinned or secret_skipped:
        slog("db_config_loaded", level="info",
             applied=applied, skipped=skipped, env_pinned=env_pinned,
             secret_skipped=secret_skipped)


def get_ui_theme(db_path: str) -> str:
    """Read the persisted UI theme preference from config_kv. Returns 'dark' or 'light'."""
    try:
        conn = _sqlite_connect(db_path, timeout=2)
        row = conn.execute("SELECT value FROM config_kv WHERE key='ui_theme'").fetchone()
        conn.close()
        if row:
            val = json.loads(row[0])
            return val if val in ("dark", "light") else "dark"
    except Exception:
        pass
    return "dark"


def set_ui_theme(db_path: str, theme: str) -> bool:
    """Persist the master UI theme to config_kv synchronously. Returns True on
    success, False on invalid theme or DB error. Written to SQLite config_kv
    (which `get_ui_theme`/`inject_theme` read directly via DB_PATH — config_kv
    is the SQLite-resident config store across both backends), so the change is
    visible to the next served page immediately, no async-flush wait."""
    if theme not in ("dark", "light"):
        return False
    try:
        conn = _sqlite_connect(db_path, timeout=2)
        conn.execute(
            "INSERT OR REPLACE INTO config_kv (key, value, ts) VALUES ('ui_theme', ?, ?)",
            (json.dumps(theme), time.time()),
        )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def inject_theme(html: str, db_path: str) -> str:
    """1.9.6 — bake the persisted UI theme into the served dashboard's <html>
    tag so EVERY page honours the saved choice on first paint.

    Previously only 5 of 11 dashboards did this; the other 6 (main, agents,
    siem, geo, logs, control_center) shipped without `data-theme`, so their
    in-<head> init script fell back to the OS `prefers-color-scheme` — making
    the background flip dark↔light when navigating between the two groups if
    the saved theme differed from the OS setting. Routing every dashboard
    through this single helper keeps them consistent (and the guard test
    asserts no dashboard endpoint forgets it). Best-effort: on any error the
    HTML is returned unchanged (the <head> fallback still applies)."""
    try:
        theme = get_ui_theme(db_path)
    except Exception:
        return html
    return html.replace('<html lang="en">',
                        f'<html lang="en" data-theme="{theme}">', 1)


def db_load_state(clear_first: bool = True) -> None:
    """Load saved state at startup. Populates state-module objects
    (ip_state, metrics, events, timeline, SERVICE_METRICS_HISTORY)
    directly — these are mutable containers imported by reference.

    1.9.7 — `clear_first` controls whether `ip_state` is wiped before load.
    Tests call with the default True (each make_app()/on_startup() must see a
    clean slate for cross-test isolation). The production *deferred* rehydrate
    path (proxy.on_startup, Option B) calls with False because by then
    `_rehydrate_bans()` has already run synchronously and may have populated
    live bans — a clear() here would wipe them. In merge mode we also never
    *downgrade* an already-active in-memory ban from the (possibly staler)
    clients table (see the banned_until guard below)."""
    # Reset in-memory identity state so stale entries from a previous startup
    # (or a prior test invocation) don't persist when the DB table is empty.
    # In production on_startup is called once on a fresh container so ip_state
    # is always empty here; in tests each make_app() / on_startup() call must
    # see a clean slate to avoid cross-test risk-score contamination.
    if clear_first:
        ip_state.clear()

    conn = _sqlite_connect(DB_PATH)
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
        # banned_until is monotonic; if epoch > now, restore offset.
        # 1.9.7 — in merge mode (clear_first=False, the deferred rehydrate
        # path) don't overwrite a ban already applied by _rehydrate_bans():
        # the bans table is authoritative and may be fresher than this row.
        if r["banned_until_epoch"] and r["banned_until_epoch"] > n:
            if clear_first or not (s.banned_until and s.banned_until > now()):
                s.banned_until = now() + (r["banned_until_epoch"] - n)
        s.last_user_agent = r["last_user_agent"] or ""
        s.last_path = r["last_path"] or ""
        # 1.8.14 iter-21 — restore last_vhost so the main.html Clients Domain
        # column survives a GW restart. Pre-iter-21 dbs may not have this
        # column (KeyError from sqlite3.Row); migration adds it but defensively
        # read with .keys() lookup so rolling upgrades don't blow up.
        try:
            s.last_vhost = (r["last_vhost"] if "last_vhost" in r.keys() else "") or ""
        except (IndexError, KeyError):
            s.last_vhost = ""
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
    #
    # 1.9.5 fix — read through open_conn() (backend-aware) instead of the local
    # SQLite `conn`. In PG-only mode the writer mirrors svc_metric rows to
    # Postgres and NEVER touches the local SQLite file, so the old
    # `conn.execute(...)` here loaded STALE, frozen samples (timestamps from
    # before the PG cut-over). Those old timestamps made the in-memory deque's
    # oldest entry look weeks old, which fooled service_metrics_data_endpoint's
    # `start_b < _buf_oldest` heuristic into taking the in-memory path (which
    # only spans the stale gap + the most-recent live samples) instead of the
    # DB path — so a 7-day window rendered only ~1 day of data. Reading from the
    # active backend gives a CONTIGUOUS recent buffer and the heuristic works.
    # Clear first so repeated on_startup() calls in tests don't accumulate.
    SERVICE_METRICS_HISTORY.clear()
    svc_loaded = 0
    try:
        from db import open_conn as _open_conn_svc
        _svc_conn = _open_conn_svc()
        try:
            _svc_conn.row_factory = sqlite3.Row
            cur = _svc_conn.execute(
                "SELECT * FROM svc_metrics ORDER BY ts DESC LIMIT ?",
                (SERVICE_METRICS_RETENTION,))
            rows_svc = cur.fetchall()
            for row in reversed(rows_svc):   # oldest-first into the deque
                SERVICE_METRICS_HISTORY.append({k: row[k] for k in row.keys()})
            svc_loaded = len(rows_svc)
        finally:
            _svc_conn.close()
    except Exception as e:
        slog("db_svc_metrics_not_loaded", level="warn", error=str(e))
    conn.close()
    slog("db_state_loaded", level="info",
         clients=len(rows), timeline_buckets=len(timeline),
         total_requests=metrics["total_requests"], svc_metrics=svc_loaded)


def _rehydrate_bans() -> int:
    """Load active bans from the `bans` table into ip_state at startup.
    Returns number of bans rehydrated."""
    from state import ip_state
    n = time.time()
    count = 0
    try:
        conn = _sqlite_connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT ip, banned_until, reason FROM bans WHERE banned_until > ?",
            (n,)).fetchall()
        conn.close()
        for row in rows:
            st = ip_state[row["ip"]]
            st.banned_until = float(row["banned_until"])
            count += 1
        slog("bans_rehydrated", level="info", count=count)
    except Exception as e:
        slog("bans_rehydrate_failed", level="warn", err=str(e)[:200])
    # iter-11 — also rehydrate per-vhost bans (BAN_SCOPE="vhost"). Separate
    # try/except so a missing ip_bans_vhost table (pre-iter-11 DB, mid-migration)
    # never aborts the global-ban rehydrate above.
    try:
        conn = _sqlite_connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        vrows = conn.execute(
            "SELECT ip, vhost, banned_until FROM ip_bans_vhost "
            "WHERE banned_until > ?", (n,)).fetchall()
        conn.close()
        vcount = 0
        for row in vrows:
            ip_state[row["ip"]].banned_until_by_vhost[row["vhost"]] = \
                float(row["banned_until"])
            vcount += 1
        if vcount:
            slog("vhost_bans_rehydrated", level="info", count=vcount)
    except Exception as e:
        slog("vhost_bans_rehydrate_failed", level="warn", err=str(e)[:200])
    return count


def _rehydrate_timeline() -> int:
    """1.9.4 — repopulate the in-memory `timeline` minute-bucket OrderedDict from
    the persisted `timeline` table at startup.

    Without this, after a restart the Live Feed timeline reads an EMPTY in-memory
    dict, and metrics_endpoint only consults the DB for windows older than
    TIMELINE_RETAIN_SECS — so the recent history that operators actually look at
    shows blank even though every event is safe in the DB. Rehydrating restores
    the structure the hot path expects, so the chart is correct immediately.

    Backend-aware: `timeline` is a PG-mirrored table, so a bare sqlite read would
    return an empty local file in PG-only mode (the recurring mirrored-table bug
    class). Route through `open_conn()` like the metrics-timeline DB fallback.
    bucket_minute is an integer epoch in both backends — no TIMESTAMPTZ wrap
    needed. Returns the number of buckets rehydrated."""
    from collections import defaultdict
    from state import timeline as _timeline
    from config import TIMELINE_RETAIN_SECS
    import json as _json
    count = 0
    try:
        from db import open_conn
        cutoff = int(time.time()) - TIMELINE_RETAIN_SECS
        conn = open_conn()
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT bucket_minute, total, allowed, blocked, missed, by_reason "
            "FROM timeline WHERE bucket_minute >= ? ORDER BY bucket_minute",
            (cutoff,)).fetchall()
        conn.close()
        # Rebuild in ascending bucket order so the OrderedDict head is the oldest
        # entry — matches the head-eviction assumption in core.metrics._timeline_bump.
        _timeline.clear()
        for row in rows:
            _br = row["by_reason"]
            try:
                br = _json.loads(_br) if isinstance(_br, str) and _br else (dict(_br) if _br else {})
            except Exception:
                br = {}
            _timeline[int(row["bucket_minute"])] = {
                "total":   int(row["total"]   or 0),
                "blocked": int(row["blocked"] or 0),
                "allowed": int(row["allowed"] or 0),
                "missed":  int(row["missed"]  or 0),
                # gwmgmt/challenged are not persisted to the timeline table;
                # _timeline_bump backfills them to 0 on the next write.
                "gwmgmt": 0, "challenged": 0,
                "by_reason": defaultdict(int, br),
            }
            count += 1
        slog("timeline_rehydrated", level="info", count=count)
    except Exception as e:
        slog("timeline_rehydrate_failed", level="warn", err=str(e)[:200])
    return count


def _rehydrate_events() -> int:
    """1.9.6 — repopulate the in-memory recent-event ring buffers from the
    persisted events table at startup so the dashboard's "recent events" list +
    by-reason/by-path breakdowns are not blank after a restart (companion to
    _rehydrate_timeline, which already restores the trend chart). Backend-aware
    via db_read_events; mirrors record()'s category mapping. Returns the number
    of events rehydrated."""
    import state as _st
    from config import ADMIN_NS
    try:
        from core.metrics import _PASSTHROUGH_REASONS as _PASS
    except Exception:
        _PASS = frozenset({"authorized-robot", "bypass-path",
                           "operator-passthrough", "admin-passthrough",
                           "operator-allowed", "operator-self"})
    from db import db_read_events
    from admin.auth import _is_admin_ip
    count = 0
    try:
        # newest 250 rows; reverse to oldest→newest so the bounded deques end
        # with the most-recent events last (same order record() appends).
        rows = db_read_events(
            0, 0,
            columns=["ts", "ip", "ua", "path", "method", "status", "reason", "vhost"],
            order_by="ts DESC", limit=250)
        for r in reversed(list(rows)):
            reason = (r.get("reason") or "")
            path = (r.get("path") or "")
            ip = (r.get("ip") or "")
            evt = {
                "ts": float(r.get("ts") or 0), "ip": ip,
                "is_admin_ip": _is_admin_ip(ip), "ua": (r.get("ua") or "")[:80],
                "path": path[:80], "method": r.get("method") or "",
                "status": r.get("status") or 0, "reason": reason or "OK",
                "ja4": "", "rid": "", "score": 0.0,
                "track_key": ip[:32], "vhost": r.get("vhost") or "",
            }
            if path.startswith(ADMIN_NS):
                cat = "gwmgmt"
            elif reason == "authorized-robot":
                cat = "authbots"
            elif reason and reason not in _PASS:
                cat = "ban"
            else:
                cat = "allowed"
            _st.events_by_cat[cat].append(evt)
            _st.events.append(evt)
            if path:
                _st.by_path_by_cat[cat][path] += 1   # ≤250 keys, well under cap
            count += 1
        slog("events_rehydrated", level="info", count=count)
    except Exception as e:
        slog("events_rehydrate_failed", level="warn", err=str(e)[:200])
    return count


def check_ip_ban(ip: str) -> float:
    """1.8.12 M-4 — Synchronous point-lookup in ip_bans.
    Returns banned_until epoch (> now) or 0.0 if not banned / table absent.
    Called from protect() before identity derivation so key rotation can never
    free a hostile ban.  Uses a short-lived connection — no shared state."""
    if not ip:
        return 0.0
    n = time.time()
    try:
        conn = _sqlite_connect(DB_PATH, timeout=0.1)
        row = conn.execute(
            "SELECT banned_until FROM ip_bans WHERE ip=? AND banned_until > ?",
            (ip, n)).fetchone()
        conn.close()
        return float(row[0]) if row else 0.0
    except Exception:
        return 0.0


def check_ip_bans_bulk() -> set:
    """Return the set of IPs currently in ip_bans (banned_until > now) in ONE
    short-lived connection.

    1.9.7 — for callers that would otherwise open a SQLite connection PER row
    (metrics_endpoint checked every tracked identity individually, doing N
    synchronous `_sqlite_connect`s on the event loop — on slow armv7 storage
    that froze the loop / `/live`, confirmed via a SIGUSR1 stack dump). Callers
    on the event loop MUST invoke this via `asyncio.to_thread` so the open/query
    never blocks the loop. Returns an empty set on any error (display hint)."""
    n = time.time()
    try:
        conn = _sqlite_connect(DB_PATH, timeout=0.5)
        rows = conn.execute(
            "SELECT ip FROM ip_bans WHERE banned_until > ?", (n,)).fetchall()
        conn.close()
        return {r[0] for r in rows}
    except Exception:
        return set()


def check_ip_ban_vhost(ip: str, vhost: str) -> float:
    """1.9.1 iter-11 — synchronous point-lookup in ip_bans_vhost for
    BAN_SCOPE="vhost". Returns banned_until epoch (> now) for this (ip, vhost)
    pair, or 0.0 if not banned / table absent. Same short-lived-connection
    pattern as check_ip_ban — never blocks the hot path."""
    if not ip or not vhost:
        return 0.0
    n = time.time()
    try:
        conn = _sqlite_connect(DB_PATH, timeout=0.1)
        row = conn.execute(
            "SELECT banned_until FROM ip_bans_vhost "
            "WHERE ip=? AND vhost=? AND banned_until > ?",
            (ip, vhost, n)).fetchone()
        conn.close()
        return float(row[0]) if row else 0.0
    except Exception:
        return 0.0


# 1.9.5 perf #3 — in-process TTL cache for the per-request IP-ban lookup.
# check_ip_ban()/check_ip_ban_vhost() each open a short-lived SQLite connection
# and run a point query ON THE EVENT LOOP for EVERY non-admin request. Under load
# that serialises the loop on disk I/O. This cache serves hot IPs from memory:
#   • a cached BAN (banned_until > now) is authoritative until it expires;
#   • a cached "clear" (0.0) is trusted only within a short TTL (default 5s);
#   • on any ban WRITE/DELETE the writer invalidates the IP's entry, so a freshly
#     banned IP is enforced immediately, not after the TTL — the TTL only ever
#     delays a *negative* result, and this lookup is defence-in-depth anyway
#     (identity + risk bans still apply).
_BAN_CACHE_TTL  = float(os.environ.get("BAN_CACHE_TTL_SECS", "5"))
_BAN_CACHE_MAX  = int(os.environ.get("BAN_CACHE_MAX", "50000"))
_ban_cache:       dict = {}   # ip            -> (banned_until, cached_at)
_ban_cache_vhost: dict = {}   # (ip, vhost)   -> (banned_until, cached_at)


def _ban_cache_invalidate(ip: str, vhost: str = "") -> None:
    """Drop cached ban state for `ip` (and optionally an (ip,vhost) pair) so the
    next lookup re-reads the DB. Called by the writer on every ban insert/delete."""
    if not ip:
        return
    _ban_cache.pop(ip, None)
    if vhost:
        _ban_cache_vhost.pop((ip, vhost), None)
    else:
        # global ban change → also clear any per-vhost entries for this IP
        for k in [k for k in _ban_cache_vhost if k[0] == ip]:
            _ban_cache_vhost.pop(k, None)


def check_ip_ban_cached(ip: str) -> float:
    """TTL-cached wrapper around check_ip_ban(). Same return contract."""
    if not ip:
        return 0.0
    n = time.time()
    ent = _ban_cache.get(ip)
    if ent is not None and (n - ent[1]) < _BAN_CACHE_TTL:
        bu = ent[0]
        if bu > n:
            return bu        # still-valid ban, from cache
        if bu == 0.0:
            return 0.0       # fresh "not banned", from cache
        # else: a ban that expired since caching → fall through and re-read
    bu = check_ip_ban(ip)
    if len(_ban_cache) >= _BAN_CACHE_MAX:
        _ban_cache.clear()
    _ban_cache[ip] = (bu, n)
    return bu


def check_ip_ban_vhost_cached(ip: str, vhost: str) -> float:
    """TTL-cached wrapper around check_ip_ban_vhost(). Same return contract."""
    if not ip or not vhost:
        return 0.0
    n = time.time()
    key = (ip, vhost)
    ent = _ban_cache_vhost.get(key)
    if ent is not None and (n - ent[1]) < _BAN_CACHE_TTL:
        bu = ent[0]
        if bu > n:
            return bu
        if bu == 0.0:
            return 0.0
    bu = check_ip_ban_vhost(ip, vhost)
    if len(_ban_cache_vhost) >= _BAN_CACHE_MAX:
        _ban_cache_vhost.clear()
    _ban_cache_vhost[key] = (bu, n)
    return bu


def prune_ip_bans() -> int:
    """Remove expired ip_bans rows. Called from _prune_state_loop.
    iter-11 — also prunes the per-vhost ip_bans_vhost table so expired
    vhost-scoped bans don't accumulate unbounded (11b DoS finding)."""
    n = time.time()
    count = 0
    try:
        conn = _sqlite_connect(DB_PATH)
        cur = conn.execute("DELETE FROM ip_bans WHERE banned_until <= ?", (n,))
        count = cur.rowcount
        try:
            cur2 = conn.execute(
                "DELETE FROM ip_bans_vhost WHERE banned_until <= ?", (n,))
            count += cur2.rowcount
        except Exception:
            pass  # nosec B110 — table may be absent mid-migration; ip_bans prune already counted
        conn.commit()
        conn.close()
        return count
    except Exception:
        return count


def prune_old_events() -> int:
    """Stage 20a (GDPR data-minimization): delete events older than
    EVENTS_RETENTION_DAYS from the SQLite events table. The Postgres mirror
    uses TimescaleDB drop_chunks for the same role; this is the SQLite-side
    retention enforcement for single-node deployments."""
    try:
        from config import EVENTS_RETENTION_DAYS
    except ImportError:
        return 0
    if EVENTS_RETENTION_DAYS <= 0:
        return 0  # 0 = retention disabled
    cutoff = time.time() - (EVENTS_RETENTION_DAYS * 86400)
    try:
        conn = _sqlite_connect(DB_PATH)
        cur = conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        count = cur.rowcount
        conn.commit()
        conn.close()
        if count > 0:
            slog("events_pruned", level="info", count=count,
                 retention_days=EVENTS_RETENTION_DAYS, cutoff_ts=cutoff)
        return count
    except Exception as e:
        slog("events_prune_failed", level="error", err=str(e)[:200])
        return 0


def prune_gw_audit(retention_days: int) -> int:
    """1.8.15 — prune gw_audit rows older than `retention_days`.
    Called from _prune_state_loop at the same cadence as events prune.
    Indexed by `ts` so this is cheap even on multi-year tables.
    Returns the number of rows deleted (0 on disabled / error / no rows)."""
    if retention_days <= 0:
        return 0
    cutoff = time.time() - (retention_days * 86400)
    try:
        conn = _sqlite_connect(DB_PATH)
        cur = conn.execute("DELETE FROM gw_audit WHERE ts < ?", (cutoff,))
        count = cur.rowcount
        conn.commit()
        conn.close()
        if count > 0:
            slog("gw_audit_pruned", level="info", count=count,
                 retention_days=retention_days, cutoff_ts=cutoff)
        return count
    except Exception as e:
        slog("gw_audit_prune_failed", level="error", err=str(e)[:200])
        return 0


# ────────────────────────────────────────────────────────────────────────────
# 1.8.8 — backend-aware event reader (sqlite side).
# Called via db.db_read_events() dispatcher when DB_BACKEND=sqlite or when
# postgres is configured but unavailable.
# ────────────────────────────────────────────────────────────────────────────

_VALID_EVENT_COLUMNS = frozenset({
    "id", "ts", "ip", "ua", "path", "method", "status", "reason", "vhost",
})

_VALID_ORDER_BY = {
    "ts": " ORDER BY ts ASC",
    "ts asc": " ORDER BY ts ASC",
    "ts desc": " ORDER BY ts DESC",
    "id": " ORDER BY id ASC",
    "id asc": " ORDER BY id ASC",
    "id desc": " ORDER BY id DESC",
}


def _read_events_sql(
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
) -> list:
    """SQLite implementation of db_read_events. Returns list of dicts.
    `ts` is epoch float (REAL column, returned as-is).

    start_ts=0 or end_ts=0 means "no bound on that side" — used by the
    logs endpoint to grab the latest N rows without a time range.
    """
    cols = list(columns) if columns else ["ts", "ip", "reason"]
    for c in cols:
        if c not in _VALID_EVENT_COLUMNS:
            raise ValueError(f"invalid event column: {c!r}")
    where = []
    params: list = []
    if start_ts and start_ts > 0:
        where.append("ts >= ?")
        params.append(float(start_ts))
    if end_ts and end_ts > 0:
        where.append("ts <= ?")
        params.append(float(end_ts))
    if vhost:
        where.append("vhost = ?")
        params.append(vhost)
    if path_like:
        where.append("LOWER(path) LIKE ?")
        params.append(f"%{path_like.lower()}%")
    if reason_like:
        where.append("LOWER(reason) LIKE ?")
        params.append(f"%{reason_like.lower()}%")
    if reason_in:
        # Exact-set match — avoids LIKE prefix bleed (e.g. "honeypot" matching
        # "honeypot-silent"). Placeholders are count-derived, values bound.
        _ph = ",".join("?" * len(reason_in))
        where.append(f"reason IN ({_ph})")  # nosec B608 — placeholders only
        params.extend(str(x) for x in reason_in)
    if ip_exact:
        where.append("ip = ?")
        params.append(ip_exact)
    order_clause = ""
    if order_by:
        ob = order_by.strip().lower()
        if ob not in _VALID_ORDER_BY:
            raise ValueError(f"invalid order_by: {order_by!r}")
        order_clause = _VALID_ORDER_BY[ob]
    limit_clause = ""
    if limit and limit > 0:
        limit_clause = f" LIMIT {int(limit)}"
        if offset and offset > 0:
            limit_clause += f" OFFSET {int(offset)}"
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    # cols / order_clause / limit_clause are all built from whitelisted
    # constants (_VALID_ORDER_BY, _VALID_EVENT_COLUMNS, int() coercion).
    # All actual values flow through `params` via ? placeholders below.
    sql = (
        f"SELECT {','.join(cols)} FROM events"  # nosec B608 — all interpolated fragments are whitelisted constants
        f"{where_sql}{order_clause}{limit_clause}"
    )
    conn = _sqlite_connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(sql, params)]
    finally:
        conn.close()


def _events_health_sql() -> dict:
    """SQLite events-table health probe — count + last_event_ts.

    Best-effort: returns ok=False with no counts if the DB or table is missing.
    Used by db.db_health_snapshot() to surface write-lag in the dashboard."""
    out = {"last_event_ts": None, "events_rows": 0, "ok": False}
    try:
        conn = _sqlite_connect(DB_PATH)
        try:
            r = conn.execute("SELECT COUNT(*), MAX(ts) FROM events").fetchone()
            if r:
                out["events_rows"]   = int(r[0] or 0)
                out["last_event_ts"] = float(r[1]) if r[1] is not None else None
            out["ok"] = True
        finally:
            conn.close()
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:120]}"
    return out
