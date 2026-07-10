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
from decimal import Decimal as _Decimal

from config import (
    DB_BACKEND,
    DB_PATH,
    POSTGRES_DSN,
)
import state as _state

# ── Pool configuration ─────────────────────────────────────────────────────
_PG_POOL_SIZE    = int(_os.environ.get("PG_POOL_SIZE",    "5"))
_PG_POOL_TIMEOUT = float(_os.environ.get("PG_POOL_TIMEOUT", "2.0"))

# A3 fix: monotonically-increasing schema version for the PG schema.
# Stamped into pg_schema_versions on every db_init_postgres() so
# operators can verify their PG matches the gateway release.
#
# Bump this whenever you add a new table or column to db_init_postgres()
# AND describe the change in CHANGELOG. The next release that adds, e.g.,
# a `rate_limit_buckets` table → bump to 2.
PG_SCHEMA_VERSION = 2  # iter-11: added ip_bans_vhost table (additive; A5 ±1 tolerated)

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
    Returns the module on success, None on failure.

    1.8.14 iter-19 — this function reports whether psycopg is *installed*
    only. Do NOT conflate "Postgres backend disabled this process" with
    "library missing" — the dashboard's db_switch_endpoint shows the
    user-visible message "psycopg not installed in this image" when this
    returns None, so suppression of post-failure connect attempts is done
    at the *connect* layer (_PgPool._connect + record() gating on
    _postgres_available), not here.
    """
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
        # 1.8.14 iter-18 — refuse new connections once Postgres auth has
        # already failed in this process. Without this, every pool acquire
        # attempt re-opens a doomed connection, which the DB rejects with a
        # log line. The flag is only cleared by restart (operator action).
        if _PG_AUTH_FAILED:
            raise RuntimeError(
                "Postgres backend disabled in this process: auth failed at "
                "startup; restart the gateway after fixing the credential "
                "mismatch (see Service dashboard for recovery command).")
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


def _pg_mirror_kv(op: str, args: tuple, _conn=None) -> bool:
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

    M6 fix: accepts an optional caller-managed connection via `_conn=`.
    When provided, the function uses that connection instead of pulling
    one from the pool — letting callers (db.import) wrap many ops in a
    single BEGIN/COMMIT transaction. Caller is responsible for commit
    + close + error handling. When `_conn=None`, behaviour is unchanged
    (pool + auto-commit via context-manager).
    """
    if _conn is not None:
        # Caller-managed transaction — use their connection. Errors
        # propagate so the caller can ROLLBACK.
        #
        # M10 — error-state contract: once any dispatch raises on `_conn`,
        # PG marks the transaction as `InFailedSqlTransaction`. EVERY
        # subsequent `_pg_mirror_kv(..., _conn=_conn)` call on the same
        # connection will also raise (psycopg refuses to issue more
        # statements in a failed tx). The caller MUST treat the first
        # exception as terminal: stop iterating, ROLLBACK, surface a
        # single root-cause error. Continuing the loop inflates the error
        # count and masks the real failure. db.import implements this
        # contract at db/import.py:212 (cascade-break) — see M8.
        #
        # TC1 — autocommit contract: the caller passes _conn= specifically
        # to wrap many ops in ONE BEGIN/COMMIT. That only works if the
        # connection has autocommit=False. A future contributor passing
        # a pool connection (autocommit=True by default in psycopg) would
        # silently lose transactional semantics: each cur.execute()
        # commits immediately, the caller's rollback() is a no-op, partial
        # state lands on PG. Fail loudly at the boundary instead of
        # silently corrupting state.
        try:
            _ac = bool(getattr(_conn, "autocommit", False))
        except Exception:
            _ac = False
        if _ac:
            raise AssertionError(
                "_pg_mirror_kv: caller passed _conn= with autocommit=True. "
                "The whole point of caller-managed transactions (M6) is "
                "to wrap multiple ops in ONE BEGIN/COMMIT. Set "
                "_conn.autocommit = False BEFORE the first dispatch call, "
                "or drop _conn= and let the pool handle commits."
            )
        with _conn.cursor() as cur:
            return _pg_dispatch_op(op, args, cur)
    pool = _get_pool()
    if pool is None:
        return False
    try:
        with pool.connection(timeout=2.0) as conn:
            with conn.cursor() as cur:
                return _pg_dispatch_op(op, args, cur)
    except Exception as e:
        # If the table doesn't exist the schema init must have failed at startup
        # (PG wasn't ready yet). Attempt a one-shot reinit and retry the write —
        # this self-heals when TimescaleDB becomes reachable after the gateway
        # boots (common in docker-compose environments without healthcheck deps).
        try:
            import psycopg as _psy
            if isinstance(e, _psy.errors.UndefinedTable) and not getattr(
                    _pg_mirror_kv, "_reinit_attempted", False):
                _pg_mirror_kv._reinit_attempted = True
                _logging.info("[db-pg] schema missing — attempting reinit")
                if db_init_postgres(max_attempts=3, backoff_s=0.5):
                    _pg_mirror_kv._reinit_attempted = False  # reset for future gaps
                    return _pg_mirror_kv(op, args)           # retry once
        except Exception:
            pass
        # Log once per minute to avoid spamming.
        last = getattr(_pg_mirror_kv, "_last_warn_min", -1)
        cur_min = int(_t.time()) // 60
        if last != cur_min:
            _logging.warning("[db-pg] kv mirror failed (op=%s): %s: %s",
                             op, type(e).__name__, str(e)[:120])
            _pg_mirror_kv._last_warn_min = cur_min
        return False


# M11 — per-op tuple-shape contract. Each entry is the EXACT positional
# arity that `_pg_dispatch_op(op, args, cur)` expects in `args`. Ops that
# unpack a dict for variable column writes (user_update, gw_registry_update)
# carry arity 2 — the outer (scalar, dict) shape is fixed even though the
# inner dict size varies. Ops absent from this table skip the check so a
# future op without an entry still dispatches (graceful — but every new
# handler SHOULD add an entry here at the same time as its elif branch).
_OP_ARITY = {
    "set_config":                  3,
    "del_config":                  1,
    "set_secret":                  3,
    "del_secret":                  1,
    "set_admin_ip":                5,
    "del_admin_ip":                1,
    "update_admin_ip_description": 2,
    "gw_audit_add":                5,
    "honey_fp_add":                8,
    "user_create":                 6,
    "user_update":                 2,
    "user_delete":                 1,
    "user_login_recorded":         3,
    "user_session_create":         8,
    "user_session_touch":          2,
    "user_session_revoke":         3,
    "ban":                         4,
    "ip_ban":                      4,
    "ip_ban_vhost":                5,
    "ip_ban_vhost_del":            2,
    "ip_ban_del":                  1,
    "dlp_add":                     5,
    "dlp_toggle":                  2,
    "dlp_delete":                  1,
    "siem_alert_rule_add":         7,
    "siem_alert_rule_del":         1,
    "siem_alert_fired":            3,
    "siem_alert_toggle":           2,
    "gw_registry_add":             14,
    "gw_registry_update":          2,
    "gw_registry_delete":          1,
    "gw_distribution_replace":     2,
    "abuseipdb_set":               4,
    "audit_log":                   8,
    "gw_registry_discover":        2,
    "mesh_sync_pending_upsert":    4,
    "mesh_sync_status":            3,
    "set_kv":                      2,
    "svc_metric":                  35,
    "svc_metric_prune":            1,
    "upsert_client":               11,
    "upsert_timeline":             6,
}


# A4 — dispatch ladder → registry pattern.
#
# Each op gets a small `_h_<name>(cur, args)` handler. The dispatcher
# below is a 1-line lookup. Benefits:
#   * Adding a new op = write a handler + add one line to _PG_OP_HANDLERS.
#     No central edit, no scrolling through a 365-line function.
#   * Each handler is independently testable / mockable.
#   * M3 coverage guard becomes a set-membership check.
#   * M11 arity table (above) stays the single source of truth for the
#     positional contract.
#
# Behaviour MUST be byte-identical to the prior dispatch — the
# golden-SQL harness (tests/test_pg_dispatch_sql_golden.py) freezes the
# exact SQL+params each op emits today, and re-runs after this refactor
# to detect any drift. If golden test fails: drift is real, audit the
# handler diff, do NOT silently regenerate.
#
# IMPORTANT: handler functions are intentionally lowercase + prefixed
# with `_h_` so a grep for `_h_(\w+)` finds the full op inventory at a
# glance, and so future ops follow the same naming convention.

# Column whitelists for the two ops that build dynamic SQL.
# Lifted from the prior in-handler `frozenset({…})` definitions; the only
# change is module-level scope so they're allocated once at import time.
_USER_MUTABLE = frozenset({
    "password_hash", "role", "status",
    "totp_secret", "totp_enabled", "totp_backup_codes",
    "oidc_sub", "sso_source",
    "updated_ts",
})
_GW_MUTABLE = frozenset({
    "domain", "region", "environment", "status",
    "can_distribute", "public_key", "private_key",
    "key_created_ts", "key_rotated_ts", "last_seen_ts",
    "updated_ts", "is_local", "auto_apply",
})


# ── config_kv / secrets_kv ─────────────────────────────────────────────────

def _h_set_config(cur, args):
    cur.execute(
        "INSERT INTO config_kv (key, value, ts) "
        "VALUES (%s, %s, %s) "
        "ON CONFLICT (key) DO UPDATE SET "
        "  value = EXCLUDED.value, ts = EXCLUDED.ts", args)


def _h_del_config(cur, args):
    cur.execute("DELETE FROM config_kv WHERE key = %s", args)


def _h_set_secret(cur, args):
    cur.execute(
        "INSERT INTO secrets_kv (key, value, ts) "
        "VALUES (%s, %s, %s) "
        "ON CONFLICT (key) DO UPDATE SET "
        "  value = EXCLUDED.value, ts = EXCLUDED.ts", args)


def _h_del_secret(cur, args):
    cur.execute("DELETE FROM secrets_kv WHERE key = %s", args)


# ── admin_ips ──────────────────────────────────────────────────────────────

def _h_set_admin_ip(cur, args):
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


def _h_del_admin_ip(cur, args):
    cur.execute("DELETE FROM admin_ips WHERE cidr = %s", args)


def _h_update_admin_ip_description(cur, args):
    # args = (description, cidr) — same order as SQLite UPDATE
    cur.execute(
        "UPDATE admin_ips SET description = %s "
        "WHERE cidr = %s", args)


# ── gw_audit / honey_fingerprints ──────────────────────────────────────────

def _h_gw_audit_add(cur, args):
    # args = (ts, action, gw_id, actor, details)
    cur.execute(
        "INSERT INTO gw_audit (ts, action, gw_id, actor, details) "
        "VALUES (%s, %s, %s, %s, %s)", args)


def _h_honey_fp_add(cur, args):
    # args = (ts, track_key, ip, ua, ja4, asn, path, reason)
    cur.execute(
        "INSERT INTO honey_fingerprints "
        "(ts, track_key, ip, ua, ja4, asn, path, reason) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", args)


# ── users / user_sessions ──────────────────────────────────────────────────
# iter-18 extended dual-write: tables that previously lived only in SQLite.
# Mirroring them to PG means a SQLite wipe + restart can be restored from
# the PG copy via db_restore_from_postgres().

def _h_user_create(cur, args):
    # SQLite arg order: (username, password_hash, role, status,
    #                    created_ts, updated_ts)
    cur.execute(
        "INSERT INTO users (username, password_hash, role, "
        "status, created_ts, updated_ts) "
        "VALUES (%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (username) DO UPDATE SET "
        "  password_hash=EXCLUDED.password_hash, "
        "  role=EXCLUDED.role, status=EXCLUDED.status, "
        "  updated_ts=EXCLUDED.updated_ts", args)


def _h_user_update(cur, args):
    # args = (username, {col:val, …}) — _USER_MUTABLE-whitelisted.
    username, fields = args
    if not fields:
        return  # no-op (preserved from prior `if not fields: pass`)
    bad = set(fields) - _USER_MUTABLE
    if bad:
        raise ValueError(f"user_update mirror: bad cols {bad}")
    cols   = ", ".join(f"{k}=%s" for k in fields)
    params = list(fields.values()) + [username]
    cur.execute(
        f"UPDATE users SET {cols} WHERE username=%s",  # nosec B608
        params)


def _h_user_delete(cur, args):
    # args = (username,)
    cur.execute("DELETE FROM users WHERE username=%s", args)


def _h_user_login_recorded(cur, args):
    # args = (ts, ip, username)
    cur.execute(
        "UPDATE users SET last_login_ts=%s, last_login_ip=%s "
        "WHERE username=%s", args)


def _h_user_session_create(cur, args):
    # args = (sid, username, ip, ua, created_ts, last_seen_ts,
    #         expires_ts, csrf_nonce). PG drops csrf_nonce (not stored).
    sid, username, ip, ua, c_ts, l_ts, e_ts, _csrf = args
    cur.execute(
        "INSERT INTO user_sessions (sid, username, ip, "
        "user_agent, created_ts, last_seen_ts, expires_ts, "
        "status) VALUES (%s,%s,%s,%s,%s,%s,%s,'active') "
        "ON CONFLICT (sid) DO NOTHING",
        (sid, username, ip, ua, c_ts, l_ts, e_ts))


def _h_user_session_touch(cur, args):
    # args = (last_seen_ts, sid)
    cur.execute(
        "UPDATE user_sessions SET last_seen_ts=%s WHERE sid=%s",
        args)


def _h_user_session_revoke(cur, args):
    # args = (sid, revoked_by, revoked_ts) ← SQLite uses (sid, by, ts) but
    # inserts in (by, ts, sid) order.
    cur.execute(
        "UPDATE user_sessions SET status='revoked', "
        "revoked_by=%s, revoked_ts=%s WHERE sid=%s",
        (args[1], args[2], args[0]))


# ── bans / ip_bans ─────────────────────────────────────────────────────────

def _h_ban(cur, args):
    # args = (ip, banned_until, reason, ts)
    cur.execute(
        "INSERT INTO bans (ip, banned_until, reason, ts) "
        "VALUES (%s,%s,%s,%s) "
        "ON CONFLICT (ip) DO UPDATE SET "
        "  banned_until=EXCLUDED.banned_until, "
        "  reason=EXCLUDED.reason, ts=EXCLUDED.ts", args)


def _h_ip_ban(cur, args):
    # args = (ip, banned_until, reason, ts). Monotonic-max via GREATEST().
    cur.execute(
        "INSERT INTO ip_bans (ip, banned_until, reason, ts) "
        "VALUES (%s,%s,%s,%s) "
        "ON CONFLICT (ip) DO UPDATE SET "
        "  banned_until=GREATEST(ip_bans.banned_until, "
        "                        EXCLUDED.banned_until), "
        "  reason=EXCLUDED.reason, ts=EXCLUDED.ts", args)


def _h_ip_ban_del(cur, args):
    # args = (ip,)
    cur.execute("DELETE FROM ip_bans WHERE ip=%s", args)


def _h_ip_ban_vhost(cur, args):
    # iter-11 — args = (ip, vhost, banned_until, reason, ts). Monotonic-max.
    cur.execute(
        "INSERT INTO ip_bans_vhost (ip, vhost, banned_until, reason, ts) "
        "VALUES (%s,%s,%s,%s,%s) "
        "ON CONFLICT (ip, vhost) DO UPDATE SET "
        "  banned_until=GREATEST(ip_bans_vhost.banned_until, "
        "                        EXCLUDED.banned_until), "
        "  reason=EXCLUDED.reason, ts=EXCLUDED.ts", args)


def _h_ip_ban_vhost_del(cur, args):
    # args = (ip, vhost)
    cur.execute("DELETE FROM ip_bans_vhost WHERE ip=%s AND vhost=%s", args)


# ── DLP patterns ───────────────────────────────────────────────────────────

def _h_dlp_add(cur, args):
    # args = (name, pattern, severity, added_ts, added_by)
    cur.execute(
        "INSERT INTO dlp_patterns (name, pattern, severity, "
        "added_ts, added_by) VALUES (%s,%s,%s,%s,%s) "
        "ON CONFLICT (name) DO NOTHING", args)


def _h_dlp_toggle(cur, args):
    # args = (enabled, id)
    cur.execute(
        "UPDATE dlp_patterns SET enabled=%s WHERE id=%s", args)


def _h_dlp_delete(cur, args):
    # args = (id,)
    cur.execute("DELETE FROM dlp_patterns WHERE id=%s", args)


# ── SIEM alert rules ───────────────────────────────────────────────────────

def _h_siem_alert_rule_add(cur, args):
    # args = (metric, op, threshold, label, created_ts, created_by, cooldown_s)
    cur.execute(
        "INSERT INTO siem_alert_rules (metric, op, threshold, "
        "label, created_ts, created_by, cooldown_s) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s)", args)


def _h_siem_alert_rule_del(cur, args):
    # args = (id,)
    cur.execute("DELETE FROM siem_alert_rules WHERE id=%s", args)


def _h_siem_alert_fired(cur, args):
    # args = (rule_id, ts, value) — TWO statements (insert + rule update).
    cur.execute(
        "INSERT INTO siem_alert_fired (rule_id, ts, value) "
        "VALUES (%s,%s,%s)", args)
    cur.execute(
        "UPDATE siem_alert_rules SET last_fired_ts=%s "
        "WHERE id=%s", (args[1], args[0]))


def _h_siem_alert_toggle(cur, args):
    # args = (enabled, id)
    cur.execute(
        "UPDATE siem_alert_rules SET enabled=%s WHERE id=%s", args)


# ── gw_registry / gw_distribution ──────────────────────────────────────────

def _h_gw_registry_add(cur, args):
    # 14-arg tuple — same column order as SQLite.
    cur.execute(
        "INSERT INTO gw_registry (gw_id, domain, region, "
        "environment, status, can_distribute, public_key, "
        "private_key, key_created_ts, key_rotated_ts, "
        "last_seen_ts, created_ts, updated_ts, is_local) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT (gw_id) DO UPDATE SET "
        "  domain=EXCLUDED.domain, region=EXCLUDED.region, "
        "  environment=EXCLUDED.environment, "
        "  status=EXCLUDED.status, "
        "  can_distribute=EXCLUDED.can_distribute, "
        "  public_key=EXCLUDED.public_key, "
        # Preserve PG-side private_key if SQLite mirror accidentally
        # sends blank (defensive).
        "  private_key=COALESCE(NULLIF(EXCLUDED.private_key,''),"
        "                       gw_registry.private_key), "
        "  key_rotated_ts=EXCLUDED.key_rotated_ts, "
        "  last_seen_ts=EXCLUDED.last_seen_ts, "
        "  updated_ts=EXCLUDED.updated_ts, "
        "  is_local=EXCLUDED.is_local", args)


def _h_gw_registry_update(cur, args):
    # args = (gw_id, {col:val, …}) — _GW_MUTABLE-whitelisted.
    gw_id, fields = args
    if not fields:
        return
    bad = set(fields) - _GW_MUTABLE
    if bad:
        raise ValueError(f"gw_registry_update mirror: bad cols {bad}")
    cols   = ", ".join(f"{k}=%s" for k in fields)
    params = list(fields.values()) + [gw_id]
    cur.execute(
        f"UPDATE gw_registry SET {cols} WHERE gw_id=%s",  # nosec B608
        params)


def _h_gw_registry_delete(cur, args):
    # args = (gw_id,) — TWO statements (registry + distribution cleanup).
    cur.execute(
        "DELETE FROM gw_registry WHERE gw_id=%s", args)
    cur.execute(
        "DELETE FROM gw_distribution "
        "WHERE source_gw_id=%s OR target_gw_id=%s",
        (args[0], args[0]))


def _h_gw_distribution_replace(cur, args):
    # args = (pairs, ts) — full replace via DELETE + executemany.
    pairs, ts = args
    cur.execute("DELETE FROM gw_distribution")
    if pairs:
        cur.executemany(
            "INSERT INTO gw_distribution (source_gw_id, "
            "target_gw_id, ts) VALUES (%s,%s,%s) "
            "ON CONFLICT DO NOTHING",
            [(s, t, ts) for s, t in pairs])


# ── PG-only Phase-2 ops (10 previously SQLite-only) ────────────────────────

def _h_abuseipdb_set(cur, args):
    # args = (ip, score, country, ts)
    cur.execute(
        "INSERT INTO abuseipdb_cache (ip, score, country, ts) "
        "VALUES (%s,%s,%s,%s) "
        "ON CONFLICT(ip) DO UPDATE SET "
        "  score=excluded.score, country=excluded.country, "
        "  ts=excluded.ts",
        args)


def _h_audit_log(cur, args):
    # args = (ts, event_type, actor, target, ip, detail_json,
    #         session_id, severity)
    cur.execute(
        "INSERT INTO audit_events "
        "(ts, event_type, actor, target, ip, detail, "
        " session_id, severity) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
        args)


def _h_gw_registry_discover(cur, args):
    # args = (gw_id, ts) — TWO statements (insert + last_seen update).
    gw_id, ts = args
    cur.execute(
        "INSERT INTO gw_registry "
        "(gw_id, domain, region, environment, status, "
        " can_distribute, public_key, private_key, "
        " key_created_ts, last_seen_ts, "
        " created_ts, updated_ts, is_local, auto_apply) "
        "VALUES (%s, NULL, NULL, NULL, 'untrusted', 0, "
        "        '', NULL, %s, %s, %s, %s, 0, 0) "
        "ON CONFLICT(gw_id) DO NOTHING",
        (gw_id, ts, ts, ts, ts))
    cur.execute(
        "UPDATE gw_registry SET last_seen_ts=%s "
        "WHERE gw_id=%s",
        (ts, gw_id))


def _h_mesh_sync_pending_upsert(cur, args):
    # args = (received_ts, source_gw_id, key_name, value).
    # Same idempotency contract as SQLite: only refresh on actual value change.
    cur.execute(
        "INSERT INTO gw_sync_pending "
        "(received_ts, source_gw_id, key_name, value, status) "
        "VALUES (%s,%s,%s,%s,'pending') "
        "ON CONFLICT(source_gw_id, key_name) DO UPDATE SET "
        "  received_ts = excluded.received_ts, "
        "  value       = excluded.value, "
        "  status      = 'pending', "
        "  confirmed_ts = NULL "
        "WHERE excluded.value <> gw_sync_pending.value",
        args)


def _h_mesh_sync_status(cur, args):
    # args = (id, new_status, ts)
    cur.execute(
        "UPDATE gw_sync_pending SET status=%s, "
        "confirmed_ts=%s WHERE id=%s",
        (args[1], args[2], args[0]))


def _h_set_kv(cur, args):
    # args = (key, val) — metrics_kv counter persistence.
    cur.execute(
        "INSERT INTO metrics_kv (key, val) VALUES (%s,%s) "
        "ON CONFLICT(key) DO UPDATE SET val=excluded.val",
        args)


def _h_svc_metric(cur, args):
    # args = 35-tuple matching SQLite column order (see db/sqlite.py
    # svc_metric handler). PG svc_metrics schema (Phase 1) carries the
    # same 35 columns.
    cur.execute(
        "INSERT INTO svc_metrics ("
        "  ts, cpu_pct, load1, load5, load15,"
        "  mem_used, mem_total, mem_avail, mem_pct,"
        "  swap_used, swap_total, cg_used, cg_limit, cg_pct,"
        "  disk_used, disk_total, disk_avail, disk_pct,"
        "  procs, open_fds, net_rx_bps, net_tx_bps,"
        "  db_db, db_wal, db_shm, db_total,"
        "  pg_db_bytes, pg_events_rows,"
        "  identities_count, total_requests,"
        "  pg_index_bytes, pg_active_conns, pg_idle_conns,"
        "  pg_cache_hit_pct, pg_tx_total) "
        "VALUES (%s,%s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s,%s,%s, "
        "        %s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s,%s, "
        "        %s,%s, %s,%s, %s,%s,%s,%s,%s) "
        "ON CONFLICT(ts) DO NOTHING",
        args)


def _h_svc_metric_prune(cur, args):
    # args = (cutoff_ts,)
    cur.execute("DELETE FROM svc_metrics WHERE ts < %s", args)


def _h_upsert_client(cur, args):
    # args = (ip, first_seen, last_seen, request_count, allowed_count,
    #         blocked_count, banned_until_epoch, last_user_agent,
    #         last_path, last_vhost, blocks_by_reason)
    cur.execute(
        "INSERT INTO clients "
        "(ip, first_seen, last_seen, request_count, "
        " allowed_count, blocked_count, banned_until_epoch, "
        " last_user_agent, last_path, last_vhost, blocks_by_reason) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT(ip) DO UPDATE SET "
        "  last_seen=excluded.last_seen, "
        "  request_count=excluded.request_count, "
        "  allowed_count=excluded.allowed_count, "
        "  blocked_count=excluded.blocked_count, "
        "  banned_until_epoch=excluded.banned_until_epoch, "
        "  last_user_agent=excluded.last_user_agent, "
        "  last_path=excluded.last_path, "
        "  last_vhost=excluded.last_vhost, "
        "  blocks_by_reason=excluded.blocks_by_reason",
        args)


def _h_upsert_timeline(cur, args):
    # args = (bucket_minute, total, allowed, blocked, missed, by_reason_json)
    cur.execute(
        "INSERT INTO timeline "
        "(bucket_minute, total, allowed, blocked, missed, by_reason) "
        "VALUES (%s,%s,%s,%s,%s,%s) "
        "ON CONFLICT(bucket_minute) DO UPDATE SET "
        "  total=excluded.total, allowed=excluded.allowed, "
        "  blocked=excluded.blocked, missed=excluded.missed, "
        "  by_reason=excluded.by_reason",
        args)


# ── Registry: op-name → handler. Single source of truth for which ops
# are dispatchable. Must stay in sync with _OP_ARITY (the M11 arity
# table) and _PG_DUAL_WRITE_OPS in db/sqlite.py — the M3 coverage
# runtime guard plus the iteration-4 sample-args test enforce this.
_PG_OP_HANDLERS = {
    "set_config":                  _h_set_config,
    "del_config":                  _h_del_config,
    "set_secret":                  _h_set_secret,
    "del_secret":                  _h_del_secret,
    "set_admin_ip":                _h_set_admin_ip,
    "del_admin_ip":                _h_del_admin_ip,
    "update_admin_ip_description": _h_update_admin_ip_description,
    "gw_audit_add":                _h_gw_audit_add,
    "honey_fp_add":                _h_honey_fp_add,
    "user_create":                 _h_user_create,
    "user_update":                 _h_user_update,
    "user_delete":                 _h_user_delete,
    "user_login_recorded":         _h_user_login_recorded,
    "user_session_create":         _h_user_session_create,
    "user_session_touch":          _h_user_session_touch,
    "user_session_revoke":         _h_user_session_revoke,
    "ban":                         _h_ban,
    "ip_ban":                      _h_ip_ban,
    "ip_ban_vhost":                _h_ip_ban_vhost,
    "ip_ban_vhost_del":            _h_ip_ban_vhost_del,
    "ip_ban_del":                  _h_ip_ban_del,
    "dlp_add":                     _h_dlp_add,
    "dlp_toggle":                  _h_dlp_toggle,
    "dlp_delete":                  _h_dlp_delete,
    "siem_alert_rule_add":         _h_siem_alert_rule_add,
    "siem_alert_rule_del":         _h_siem_alert_rule_del,
    "siem_alert_fired":            _h_siem_alert_fired,
    "siem_alert_toggle":           _h_siem_alert_toggle,
    "gw_registry_add":             _h_gw_registry_add,
    "gw_registry_update":          _h_gw_registry_update,
    "gw_registry_delete":          _h_gw_registry_delete,
    "gw_distribution_replace":     _h_gw_distribution_replace,
    "abuseipdb_set":               _h_abuseipdb_set,
    "audit_log":                   _h_audit_log,
    "gw_registry_discover":        _h_gw_registry_discover,
    "mesh_sync_pending_upsert":    _h_mesh_sync_pending_upsert,
    "mesh_sync_status":            _h_mesh_sync_status,
    "set_kv":                      _h_set_kv,
    "svc_metric":                  _h_svc_metric,
    "svc_metric_prune":            _h_svc_metric_prune,
    "upsert_client":               _h_upsert_client,
    "upsert_timeline":             _h_upsert_timeline,
}


def _pg_safe(v):
    """1.9.4 — make a value safe for psycopg's UTF-8 encoding. Request-derived
    strings (ip / ua / path / reason …) can carry lone surrogates or invalid
    code points (from latin-1 / surrogateescape-decoded request bytes). psycopg
    raises UnicodeEncodeError on those, which DROPS the event/client row — letting
    an attacker evade the Postgres audit log by sending malformed UTF-8. Replace
    the offending bytes; valid UTF-8 is returned unchanged on the fast path."""
    if isinstance(v, str):
        try:
            v.encode("utf-8")
            return v
        except UnicodeEncodeError:
            return v.encode("utf-8", "replace").decode("utf-8")
    if isinstance(v, dict):
        return {k: _pg_safe(val) for k, val in v.items()}
    return v


def _pg_safe_args(args):
    """Sanitize every element of a writer-op args tuple (see _pg_safe)."""
    try:
        return tuple(_pg_safe(a) for a in args)
    except Exception:
        return args


def _pg_dispatch_op(op, args, cur) -> bool:
    """Look up `op` in the registry, validate arg shape, dispatch.
    Returns True on a recognised op, False otherwise.

    H5 fix: no try/except wrapper. Exceptions propagate to the caller.
    In the pool path that's _pg_mirror_kv (UndefinedTable + warn-once);
    in the caller-managed-tx path (db.import) the import script rolls
    back.

    M11 fix: arity-asserts known ops at entry. A future caller passing
    a 3-tuple where the handler expects a 2-tuple raises a precise
    AssertionError at the dispatch boundary instead of a cryptic
    `ValueError: not enough values to unpack` deeper in the handler.

    A4 refactor: dispatch is now a registry lookup against
    _PG_OP_HANDLERS. SQL+params per op are frozen by the golden-SQL
    test (tests/test_pg_dispatch_sql_golden.py) — any drift between
    handlers and the golden file fails CI.
    """
    expected = _OP_ARITY.get(op)
    if expected is not None:
        try:
            got = len(args)
        except TypeError:
            raise AssertionError(
                f"_pg_dispatch_op: op={op!r} expects a tuple/list of "
                f"length {expected}, got non-sequence {type(args).__name__}"
            ) from None
        if got != expected:
            raise AssertionError(
                f"_pg_dispatch_op: op={op!r} expects args tuple of "
                f"length {expected}, got length {got} — fix the call "
                f"site (probably a writer-queue producer in db/sqlite.py)"
            )
    handler = _PG_OP_HANDLERS.get(op)
    if handler is None:
        return False
    handler(cur, _pg_safe_args(args))   # 1.9.4 — strip un-encodable surrogates
    return True



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


def _backfill_events_gap_from_sqlite(batch: int = 5000,
                                     max_rows: int = 5_000_000) -> dict:
    """1.9.2 iter-23 — on PG-mode boot, close any SQLite→Postgres event gap.

    If the gateway ran on SQLite while POSTGRES_DSN was set (e.g. a stale
    DB_BACKEND=sqlite), events piled up in the LOCAL SQLite store and never
    reached Postgres. This imports every SQLite event NEWER than Postgres's
    current max(ts), so the timeline becomes contiguous again — no manual
    `python -m db.import` needed.

    Hard safety guarantees (this runs on the boot path — it must NEVER crash):
      • POSTGRES_DSN unset / psycopg missing  → clean no-op.
      • Local SQLite file absent               → clean no-op (the "otherwise
        cannot crash" case the operator asked for).
      • SQLite has no events table             → clean no-op.
      • Idempotent: imports strictly ts > pg_max, so the next boot (pg_max now
        advanced) copies nothing. Composes safely with the first-boot
        auto-import (same ts > pg_max bound ⇒ no double-insert).
      • Batched + capped so a large backlog can't exhaust memory; if the cap is
        hit the remainder is reported so the operator can finish it manually.
    """
    pg = _postgres_load_module()
    if pg is None or not POSTGRES_DSN:
        return {"ok": False, "reason": "postgres unavailable", "copied": 0}
    if not _os.path.exists(DB_PATH):
        return {"ok": True, "reason": "no local sqlite file", "copied": 0}
    src = None
    try:
        # 1. Postgres high-water mark (epoch). Empty events table → 0.0.
        with pg.connect(POSTGRES_DSN, connect_timeout=5, autocommit=True) as c:
            cur = c.execute(
                "SELECT COALESCE(EXTRACT(EPOCH FROM MAX(ts)), 0) FROM events")
            pg_max = float((cur.fetchone() or [0])[0] or 0.0)
        # 2. SQLite gap rows. Tolerate a missing events table / missing
        #    method+vhost columns (older schemas) by falling back to the
        #    minimal proven column set.
        src = sqlite3.connect(DB_PATH)
        src.row_factory = sqlite3.Row
        try:
            gap_n = src.execute(
                "SELECT COUNT(*) FROM events WHERE ts > ?", (pg_max,)
            ).fetchone()[0]
        except sqlite3.OperationalError:
            return {"ok": True, "reason": "no sqlite events table", "copied": 0}
        if not gap_n:
            return {"ok": True, "reason": "no gap", "copied": 0, "pg_max": pg_max}
        _sel_full = ("SELECT ts, ip, ua, path, method, status, reason, "
                     "COALESCE(vhost,'') FROM events WHERE ts > ? "
                     "ORDER BY ts ASC LIMIT ?")
        _sel_min = ("SELECT ts, ip, ua, path, '', status, reason, '' "
                    "FROM events WHERE ts > ? ORDER BY ts ASC LIMIT ?")
        try:
            cursor = src.execute(_sel_full, (pg_max, max_rows))
        except sqlite3.OperationalError:
            cursor = src.execute(_sel_min, (pg_max, max_rows))
        copied = 0
        with pg.connect(POSTGRES_DSN, connect_timeout=10,
                          autocommit=False) as dst:
            with dst.cursor() as dcur:
                while True:
                    chunk = cursor.fetchmany(batch)
                    if not chunk:
                        break
                    dcur.executemany(
                        "INSERT INTO events "
                        "(ts, ip, ua, path, method, status, reason, vhost) "
                        "VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s)",
                        [(float(r[0]), (r[1] or ""), (r[2] or "")[:500],
                          (r[3] or ""), (r[4] or ""), int(r[5] or 0),
                          (r[6] or ""), (r[7] or "")) for r in chunk])
                    copied += len(chunk)
                dst.commit()
        return {"ok": True, "copied": copied, "gap_total": gap_n,
                "pg_max": pg_max, "capped": gap_n > max_rows}
    except Exception as e:
        return {"ok": False,
                "reason": f"{type(e).__name__}: {str(e)[:160]}", "copied": 0}
    finally:
        if src is not None:
            try:
                src.close()
            except Exception:
                pass


# ── Background full-history migration ─────────────────────────────────────────
# Populated by _full_migrate_background(); polled via the status endpoint.
#
# 1.8.9 — schedule lock. Without this, two near-simultaneous admin
# /db-switch?full_migrate=true requests can both pass the
# `not _BG_MIGRATION["running"]` guard AND both submit to the executor,
# producing duplicate rows in the target (since _bg_sqlite_to_pg's INSERT
# doesn't ON CONFLICT). The lock is held only across the check+flip in
# the endpoint, not for the migration itself.
_BG_MIGRATION_LOCK = _threading.Lock()

_BG_MIGRATION: dict = {
    "running":      False,
    "done":         False,
    "error":        None,
    "direction":    "",
    "total":        0,        # rows in source < cutoff_ts (before dedup)
    "copied":       0,        # rows actually inserted into target
    # 1.8.8 — idempotent migration (Approach A: watermark by MAX(ts) in target).
    # Re-runs of the same direction skip rows the target already has, so
    # interleaved hot-swaps don't pile up duplicates.
    "watermark":              0.0,   # target's MAX(ts) before this run started
    "skipped_already_present": 0,    # rows in source ≤ watermark (already migrated)
    "started_at":   0.0,
    "finished_at":  0.0,
}


def _bg_sqlite_to_pg(cutoff_ts: float, batch_size: int,
                     batch_sleep: float) -> None:
    """Copy SQLite events into Postgres in batches, idempotently.

    1.8.8 — two-sided watermark gap-fill:
      • forward watermark (MAX(ts) on target): skip rows already migrated
      • backfill watermark (MIN(ts) on target): copy rows older than target
        has — for "Postgres added mid-history" scenarios

    Copies source rows where: ts < min_target  OR  ts > max_target,
    bounded by ts < cutoff_ts (the dual-write era already mirrors).

    Limitation: this does NOT fix scattered interleaved gaps (rows missing
    from inside the target's range, e.g. from a past dual-write failure).
    A true composite-key dedup isn't viable: the events table contains
    legitimate same-microsecond duplicates by every meaningful column,
    a byproduct of HTTP/2 multiplexing. Operators with scattered gaps
    must backfill via a one-shot SQL job.
    """
    pg = _postgres_load_module()
    if pg is None or not POSTGRES_DSN:
        raise RuntimeError("psycopg/POSTGRES_DSN unavailable")

    # 1. Read postgres MIN(ts) and MAX(ts) — the bounds of "already covered" range.
    pg_min_ts = None
    pg_max_ts = None
    with pg.connect(POSTGRES_DSN, connect_timeout=5, autocommit=True) as wm_conn:
        with wm_conn.cursor() as wm_cur:
            wm_cur.execute(
                "SELECT EXTRACT(EPOCH FROM MIN(ts)), "
                "       EXTRACT(EPOCH FROM MAX(ts)) "
                "FROM events WHERE ts < to_timestamp(%s)", (cutoff_ts,)
            )
            row = wm_cur.fetchone()
            if row:
                if row[0] is not None: pg_min_ts = float(row[0])
                if row[1] is not None: pg_max_ts = float(row[1])
    # Watermark = forward bound (MAX); kept for backward compat with status field.
    watermark = pg_max_ts if pg_max_ts is not None else 0.0
    _BG_MIGRATION["watermark"] = watermark

    # 2. Decide what to copy.  Three regimes:
    #   A. Target empty (min=max=None): copy everything < cutoff (first migration)
    #   B. Target has data: copy where ts < pg_min OR ts > pg_max (gap-fill ends)
    src = sqlite3.connect(DB_PATH)
    try:
        if pg_min_ts is None and pg_max_ts is None:
            total = src.execute(
                "SELECT COUNT(*) FROM events WHERE ts < ?", (cutoff_ts,)
            ).fetchone()[0]
            skipped = 0
        else:
            total = src.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE ts < ? AND (ts < ? OR ts > ?)",
                (cutoff_ts, pg_min_ts, pg_max_ts)
            ).fetchone()[0]
            # Rows in [pg_min, pg_max] are skipped — assumed mirrored by dual-write.
            skipped = src.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE ts < ? AND ts >= ? AND ts <= ?",
                (cutoff_ts, pg_min_ts, pg_max_ts)
            ).fetchone()[0]
    finally:
        src.close()

    _BG_MIGRATION["total"] = total
    _BG_MIGRATION["skipped_already_present"] = skipped
    if total == 0:
        return

    last_id = 0
    while True:
        src = sqlite3.connect(DB_PATH)
        src.row_factory = sqlite3.Row
        try:
            if pg_min_ts is None and pg_max_ts is None:
                rows = src.execute(
                    "SELECT id, ts, ip, ua, path, status, reason "
                    "FROM events WHERE id > ? AND ts < ? "
                    "ORDER BY id LIMIT ?",
                    (last_id, cutoff_ts, batch_size)
                ).fetchall()
            else:
                rows = src.execute(
                    "SELECT id, ts, ip, ua, path, status, reason "
                    "FROM events WHERE id > ? AND ts < ? "
                    "  AND (ts < ? OR ts > ?) "
                    "ORDER BY id LIMIT ?",
                    (last_id, cutoff_ts, pg_min_ts, pg_max_ts, batch_size)
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
    """Copy Postgres events into SQLite in batches, idempotently.

    1.8.8 — symmetric two-sided watermark gap-fill.
    See _bg_sqlite_to_pg for rationale + limitations.
    """
    pg = _postgres_load_module()
    if pg is None or not POSTGRES_DSN:
        raise RuntimeError("psycopg/POSTGRES_DSN unavailable")

    # 1. Read sqlite MIN(ts) and MAX(ts) — target's covered range.
    sql_min_ts = None
    sql_max_ts = None
    wm_conn = sqlite3.connect(DB_PATH)
    try:
        row = wm_conn.execute(
            "SELECT MIN(ts), MAX(ts) FROM events WHERE ts < ?", (cutoff_ts,)
        ).fetchone()
        if row:
            if row[0] is not None: sql_min_ts = float(row[0])
            if row[1] is not None: sql_max_ts = float(row[1])
    finally:
        wm_conn.close()
    watermark = sql_max_ts if sql_max_ts is not None else 0.0
    _BG_MIGRATION["watermark"] = watermark

    # 2. Count source rows that fall outside [sql_min, sql_max].
    total = 0
    skipped = 0
    with pg.connect(POSTGRES_DSN, connect_timeout=5, autocommit=True) as conn:
        with conn.cursor() as cur:
            if sql_min_ts is None and sql_max_ts is None:
                cur.execute(
                    "SELECT COUNT(*) FROM events WHERE ts < to_timestamp(%s)",
                    (cutoff_ts,))
                total = cur.fetchone()[0]
                skipped = 0
            else:
                cur.execute(
                    "SELECT COUNT(*) FROM events "
                    "WHERE ts < to_timestamp(%s) "
                    "  AND (ts < to_timestamp(%s) OR ts > to_timestamp(%s))",
                    (cutoff_ts, sql_min_ts, sql_max_ts))
                total = cur.fetchone()[0]
                cur.execute(
                    "SELECT COUNT(*) FROM events "
                    "WHERE ts < to_timestamp(%s) "
                    "  AND ts >= to_timestamp(%s) "
                    "  AND ts <= to_timestamp(%s)",
                    (cutoff_ts, sql_min_ts, sql_max_ts))
                skipped = cur.fetchone()[0]

    _BG_MIGRATION["total"] = total
    _BG_MIGRATION["skipped_already_present"] = skipped
    if total == 0:
        return

    last_id = 0
    while True:
        with pg.connect(POSTGRES_DSN, connect_timeout=5,
                        autocommit=True) as src:
            with src.cursor() as cur:
                if sql_min_ts is None and sql_max_ts is None:
                    cur.execute(
                        "SELECT id, EXTRACT(EPOCH FROM ts), ip, ua, path, "
                        "       status, reason "
                        "FROM events WHERE id > %s AND ts < to_timestamp(%s) "
                        "ORDER BY id LIMIT %s",
                        (last_id, cutoff_ts, batch_size))
                else:
                    cur.execute(
                        "SELECT id, EXTRACT(EPOCH FROM ts), ip, ua, path, "
                        "       status, reason "
                        "FROM events WHERE id > %s "
                        "  AND ts < to_timestamp(%s) "
                        "  AND (ts < to_timestamp(%s) OR ts > to_timestamp(%s)) "
                        "ORDER BY id LIMIT %s",
                        (last_id, cutoff_ts, sql_min_ts, sql_max_ts, batch_size))
                rows = cur.fetchall()

        if not rows:
            break

        dst = sqlite3.connect(DB_PATH)
        try:
            before = dst.total_changes
            dst.executemany(
                "INSERT OR IGNORE INTO events "
                "(ts, ip, ua, path, method, status, reason) "
                "VALUES (?, ?, ?, ?, '', ?, ?)",
                [(float(r[1]), r[2], (r[3] or "")[:500], r[4] or "",
                  int(r[5] or 0), r[6] or "") for r in rows])
            dst.commit()
            # 1.8.9 (L1) — INSERT OR IGNORE silently drops UNIQUE-conflict
            # rows. `len(rows)` would overcount the migration; use the
            # actual sqlite3 changes-counter delta so the dashboard's
            # pct/ETA reflect real progress.
            inserted_now = dst.total_changes - before
        finally:
            dst.close()

        last_id = rows[-1][0]
        _BG_MIGRATION["copied"] += inserted_now

        if len(rows) < batch_size:
            break
        _t.sleep(batch_sleep)


def _try_claim_bg_migration(direction: str) -> bool:
    """1.8.9 — atomically check + flip `_BG_MIGRATION["running"]`. Returns
    True iff the caller now owns the slot (i.e. is allowed to spawn the
    background migration); False if another caller already owns it.

    Fixes the M1 TOCTOU where two concurrent /db-switch admin requests
    could each pass `not _BG_MIGRATION["running"]` and double-schedule
    the migrator. After this returns True, the caller MUST eventually
    set running=False (or _full_migrate_background's finally does so).
    """
    with _BG_MIGRATION_LOCK:
        if _BG_MIGRATION.get("running"):
            return False
        _BG_MIGRATION["running"]   = True
        _BG_MIGRATION["done"]      = False
        _BG_MIGRATION["error"]     = None
        _BG_MIGRATION["direction"] = direction
        return True


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
        "watermark":              0.0,
        "skipped_already_present": 0,
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


# 1.8.14 iter-17 — auth-failure diagnostic state. Set when Postgres init fails
# because the role's password in pg_authid doesn't match POSTGRES_DSN. Surfaced
# in /services so operators see the actionable recovery command without grepping
# logs. Reason: POSTGRES_PASSWORD only takes effect on first initdb; subsequent
# docker-compose edits are silently ignored, so a password drift between the
# compose file and the persisted volume looks identical to "Postgres is down".
_PG_AUTH_FAILED: bool = False
_PG_AUTH_FAILED_TS: float = 0.0
_PG_AUTH_FAILED_HINT: str = ""
# 1.9.2 iter-21 — Postgres auto-recovery. `_disable_postgres_for_process` historically
# latched the backend off until an operator restart. That means any transient
# blip (PG container restart, network hiccup, password drift later fixed) left
# the gateway stuck on SQLite — empty dashboards, geo-data/event reads dead —
# even after PG came back healthy. We now record WHY the backend was disabled
# (a failure, vs an intentional sqlite config) and run a background probe that
# re-enables PG the moment a `SELECT 1` succeeds again. No restart needed.
_PG_DISABLED_BY_FAILURE: bool = False     # set by _disable_postgres_for_process
_PG_DISABLED_TS: float = 0.0              # when the backend was last disabled
_PG_RECOVERED_COUNT: int = 0             # how many times auto-recovery fired
try:
    # Seconds between recovery probes while PG is disabled-by-failure. The probe
    # is a single short connect+SELECT 1, only runs while disabled, so the cost
    # is one cheap round-trip every interval (zero when PG is healthy).
    _PG_RECOVERY_PROBE_SECS: float = max(
        5.0, float(_os.environ.get("PG_RECOVERY_PROBE_SECS", "15")))
except (TypeError, ValueError):
    _PG_RECOVERY_PROBE_SECS = 15.0


def _is_pg_auth_failure(exc: Exception) -> bool:
    """True iff `exc` is a Postgres authentication failure (wrong password /
    unknown role / pg_hba.conf rejection). These can't recover from a retry —
    we stop the backoff loop and emit an actionable log instead."""
    msg = str(exc).lower()
    for needle in (
        "password authentication failed",
        "no password supplied",
        "role \"",  # role "appsec" does not exist
        "does not exist",
        "no pg_hba.conf entry",
        "ident authentication failed",
    ):
        if needle in msg:
            return True
    # psycopg-specific exception class names
    cls = type(exc).__name__
    return cls in ("InvalidPassword", "InvalidAuthorizationSpecification",
                   "InsufficientPrivilege")


def _is_pg_starting(exc: Exception) -> bool:
    """True iff `exc` is Postgres telling us it is up but NOT YET accepting
    connections — i.e. still in startup / WAL crash-recovery (SQLSTATE 57P03).

    This is a FREQUENT, self-healing transient: it happens whenever the DB
    was restarted uncleanly (power loss, OOM-kill, host reboot, `docker
    restart`) and is replaying its write-ahead log, or simply when the
    gateway races the DB during a `docker compose up` (both start together
    and the gateway dials before recovery finishes). Unlike an auth failure
    it WILL clear on its own once redo completes — so we keep retrying and
    log a calm, explanatory line instead of a scary stack trace."""
    msg = str(exc).lower()
    for needle in (
        "the database system is starting up",
        "not yet accepting connections",
        "consistent recovery state has not been yet reached",
        "the database system is in recovery",
        "cannot connect now",
    ):
        if needle in msg:
            return True
    # SQLSTATE 57P03 = cannot_connect_now (psycopg exposes .sqlstate)
    return getattr(exc, "sqlstate", None) == "57P03"


def _pg_auth_failure_hint(dsn: str) -> str:
    """Build a copy-pasteable recovery snippet for the operator. We do NOT
    include the password verbatim — log it as the literal `$POSTGRES_PASSWORD`
    placeholder so secret-scanners + the /services page don't leak it."""
    user = "appsec"
    try:
        # Best-effort: extract user from the DSN (postgresql://user:pw@host/db)
        import urllib.parse as _up
        u = _up.urlparse(dsn)
        if u.username:
            user = u.username
    except Exception:
        pass
    return (
        f"Postgres rejected the gateway's credentials. Most likely cause: the "
        f"TimescaleDB volume was initialised with a different password than "
        f"POSTGRES_DSN currently carries. POSTGRES_PASSWORD only takes effect "
        f"on first initdb; subsequent docker-compose edits are silently "
        f"ignored. Recovery (no data loss): "
        f"`docker exec -u postgres <pg-container> psql -c \"ALTER USER {user} "
        f"WITH PASSWORD '<value-from-docker-compose-or-DSN>';\"` then "
        f"`docker restart <gw-container>`. The gateway is running on the "
        f"SQLite fallback in the meantime; no traffic is being lost."
    )


# ── A5 — PG schema-version check (read-only) ────────────────────────────────
# Reads `pg_schema_versions` BEFORE db_init_postgres re-stamps the current
# version, so the gateway can compare the version that was last applied
# against PG_SCHEMA_VERSION it ships with.
#
# Critically NEVER mutates schema:
#   - Does NOT CREATE / ALTER / DROP any table.
#   - Does NOT INSERT/UPDATE/DELETE any row.
#   - Treats a missing `pg_schema_versions` table as "fresh DB, version=None"
#     (a real fresh-DB boot: db_init_postgres will create the table + stamp
#     v=PG_SCHEMA_VERSION later, exactly as today).
#
# Decision matrix (current = MAX(version) in pg_schema_versions):
#   current is None           → fresh DB or table missing  → OK (info log)
#   current == PG_SCHEMA_VERSION → match                    → OK (info log)
#   abs(diff) == 1            → adjacent version, allowed   → OK (info/warn log)
#   abs(diff)  > 1            → major drift, REFUSE         → SystemExit(5)
_PG_SCHEMA_DRIFT_EXIT_CODE = 5


def _read_pg_schema_version(conn) -> "int | None":
    """Pure read. Returns MAX(version) from pg_schema_versions, or None if
    the table doesn't exist yet (fresh DB) or has zero rows.

    Never raises on the missing-table case — that's the normal first-boot
    path and the caller must distinguish "fresh DB" from "operator error"."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT MAX(version) FROM pg_schema_versions"
            )
            row = cur.fetchone()
            if row is None:
                return None
            val = row[0] if not hasattr(row, "keys") else row["max"]
            if val is None:
                return None
            return int(val)
    except Exception as _e:
        # psycopg.errors.UndefinedTable is the fresh-DB case; any other
        # error here means the schema is in an unexpected state. We treat
        # both as "unknown" — the caller logs and lets db_init_postgres
        # create/repair on its next attempt.
        try:
            import psycopg as _psy
            if isinstance(_e, _psy.errors.UndefinedTable):
                return None
        except Exception:
            pass
        _logging.warning(
            "[db-pg] schema-version read failed (treating as unknown): "
            "%s: %s", type(_e).__name__, str(_e)[:160])
        return None


def check_pg_schema_version() -> dict:
    """A5 fix — read MAX(pg_schema_versions.version) and compare against
    PG_SCHEMA_VERSION. Returns a status dict; callers (proxy.on_startup)
    log + decide whether to refuse boot.

    Returns:
      {
        "ok":          bool,        # False only when should_exit=True
        "current":     int | None,  # MAX(version) in PG; None on fresh DB
        "expected":    int,         # PG_SCHEMA_VERSION
        "diff":        int | None,  # expected - current; None if no current
        "msg":         str,         # one-line human-readable summary
        "should_exit": bool,        # True iff abs(diff) > 1
        "exit_code":   int,         # process exit code if should_exit
        "severity":    str,         # 'info' | 'warn' | 'error'
      }

    Read-only — does NOT mutate pg_schema_versions or any other table."""
    result = {
        "ok": True, "current": None, "expected": PG_SCHEMA_VERSION,
        "diff": None, "msg": "", "should_exit": False,
        "exit_code": 0, "severity": "info",
    }
    pool = _get_pool()
    if pool is None:
        result["msg"] = ("schema-version check skipped: no PG pool "
                         "(POSTGRES_DSN unset or psycopg missing)")
        result["severity"] = "info"
        return result
    try:
        with pool.connection(timeout=2.0) as conn:
            current = _read_pg_schema_version(conn)
    except Exception as _e:
        result["msg"] = (f"schema-version check skipped: pool "
                         f"connect failed: {type(_e).__name__}: "
                         f"{str(_e)[:120]}")
        result["severity"] = "warn"
        return result
    result["current"] = current
    if current is None:
        result["msg"] = (f"PG schema is fresh (no pg_schema_versions "
                         f"row yet); db_init_postgres will stamp "
                         f"v={PG_SCHEMA_VERSION}")
        return result
    diff = PG_SCHEMA_VERSION - current
    result["diff"] = diff
    if diff == 0:
        result["msg"] = (f"PG schema version matches gateway "
                         f"(v={PG_SCHEMA_VERSION})")
        return result
    if abs(diff) > 1:
        # Major drift — refuse to boot. Two-version skip means the
        # operator likely missed an intermediate migration; running
        # writes against a schema we don't understand risks data loss.
        result["ok"] = False
        result["should_exit"] = True
        result["exit_code"] = _PG_SCHEMA_DRIFT_EXIT_CODE
        result["severity"] = "error"
        if diff > 0:
            result["msg"] = (
                f"FATAL: PG schema is v{current}, gateway expects "
                f"v{PG_SCHEMA_VERSION} (skip of {diff} versions). "
                f"Run intermediate migrations before booting this release.")
        else:
            result["msg"] = (
                f"FATAL: PG schema is v{current}, gateway expects "
                f"v{PG_SCHEMA_VERSION} (downgrade by {abs(diff)} versions). "
                f"This gateway release predates the PG schema; "
                f"upgrade the gateway or restore an older PG snapshot.")
        return result
    # Adjacent version (diff == ±1) — allowed but log.
    if diff > 0:
        # Gateway expects newer; db_init_postgres will run the upgrade DDL.
        result["msg"] = (f"PG schema v{current} → v{PG_SCHEMA_VERSION} "
                         f"(applying single-step upgrade)")
        result["severity"] = "info"
    else:
        # Downgrade — gateway is older than PG. Risky but allowed at ±1.
        result["msg"] = (f"WARN: PG schema is v{current}, gateway is "
                         f"v{PG_SCHEMA_VERSION} (downgrade-tolerated); "
                         f"new columns/tables in PG will be ignored by "
                         f"this release")
        result["severity"] = "warn"
    return result


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

                      CREATE TABLE IF NOT EXISTS honey_fingerprints (
                        id        BIGSERIAL PRIMARY KEY,
                        ts        DOUBLE PRECISION NOT NULL,
                        track_key TEXT,
                        ip        TEXT NOT NULL,
                        ua        TEXT,
                        ja4       TEXT,
                        asn       TEXT,
                        path      TEXT,
                        reason    TEXT
                      );
                      CREATE INDEX IF NOT EXISTS idx_honey_fp_ts
                          ON honey_fingerprints(ts);
                      CREATE INDEX IF NOT EXISTS idx_honey_fp_ja4
                          ON honey_fingerprints(ja4);
                      CREATE INDEX IF NOT EXISTS idx_honey_fp_ip
                          ON honey_fingerprints(ip);

                      -- iter-18: dual-write mirror tables. Whenever the
                      -- operator has POSTGRES_DSN configured, every SQLite
                      -- write to these tables is mirrored here so a SQLite
                      -- wipe + restart (or container redeploy with empty
                      -- /data) can restore operator-facing state from PG.
                      CREATE TABLE IF NOT EXISTS bans (
                        ip            TEXT PRIMARY KEY,
                        banned_until  DOUBLE PRECISION,
                        reason        TEXT,
                        ts            DOUBLE PRECISION
                      );
                      CREATE INDEX IF NOT EXISTS idx_bans_until ON bans(banned_until);

                      CREATE TABLE IF NOT EXISTS ip_bans (
                        ip            TEXT PRIMARY KEY,
                        banned_until  DOUBLE PRECISION NOT NULL,
                        reason        TEXT,
                        ts            DOUBLE PRECISION NOT NULL
                      );
                      CREATE INDEX IF NOT EXISTS idx_ip_bans_until ON ip_bans(banned_until);

                      -- 1.9.1 iter-11 — per-vhost bans (BAN_SCOPE="vhost").
                      -- Additive; legacy ip_bans untouched. Schema v2.
                      CREATE TABLE IF NOT EXISTS ip_bans_vhost (
                        ip            TEXT NOT NULL,
                        vhost         TEXT NOT NULL,
                        banned_until  DOUBLE PRECISION NOT NULL,
                        reason        TEXT,
                        ts            DOUBLE PRECISION NOT NULL,
                        PRIMARY KEY (ip, vhost)
                      );
                      CREATE INDEX IF NOT EXISTS idx_ip_bans_vhost_until
                        ON ip_bans_vhost(banned_until);

                      CREATE TABLE IF NOT EXISTS dlp_patterns (
                        id        BIGSERIAL PRIMARY KEY,
                        name      TEXT NOT NULL UNIQUE,
                        pattern   TEXT NOT NULL,
                        severity  TEXT,
                        enabled   INTEGER NOT NULL DEFAULT 1,
                        added_ts  DOUBLE PRECISION,
                        added_by  TEXT
                      );

                      -- ────────────────────────────────────────────────────
                      -- Phase 1 (PG-only migration): 6 SQLite tables that
                      -- previously had no PG counterpart. Required before
                      -- the dual-write code can fully mirror SQLite, and
                      -- before PG can become the sole backend.
                      -- ────────────────────────────────────────────────────

                      -- AbuseIPDB lookup cache (1 row per checked IP).
                      CREATE TABLE IF NOT EXISTS abuseipdb_cache (
                        ip       TEXT PRIMARY KEY,
                        score    INTEGER NOT NULL,
                        country  TEXT,
                        ts       DOUBLE PRECISION NOT NULL
                      );
                      CREATE INDEX IF NOT EXISTS idx_abuseipdb_ts ON abuseipdb_cache(ts);

                      -- Audit trail (immutable append-only event log of
                      -- admin actions / config mutations / security events).
                      CREATE TABLE IF NOT EXISTS audit_events (
                        id          BIGSERIAL PRIMARY KEY,
                        ts          DOUBLE PRECISION NOT NULL,
                        event_type  TEXT NOT NULL,
                        actor       TEXT,
                        target      TEXT,
                        ip          TEXT,
                        detail      TEXT,
                        session_id  TEXT,
                        severity    TEXT NOT NULL DEFAULT 'info'
                      );
                      CREATE INDEX IF NOT EXISTS idx_audit_ts        ON audit_events(ts);
                      CREATE INDEX IF NOT EXISTS idx_audit_eventtype ON audit_events(event_type);
                      CREATE INDEX IF NOT EXISTS idx_audit_actor     ON audit_events(actor);

                      -- Per-IP client roll-up (request counts, last UA/path,
                      -- ban-until, JSON map of blocks-by-reason). Hydrated
                      -- on startup into in-memory ip_state.
                      CREATE TABLE IF NOT EXISTS clients (
                        ip                  TEXT PRIMARY KEY,
                        first_seen          DOUBLE PRECISION,
                        last_seen           DOUBLE PRECISION,
                        request_count       BIGINT DEFAULT 0,
                        allowed_count       BIGINT DEFAULT 0,
                        blocked_count       BIGINT DEFAULT 0,
                        banned_until_epoch  DOUBLE PRECISION DEFAULT 0,
                        last_user_agent     TEXT,
                        last_path           TEXT,
                        last_vhost          TEXT DEFAULT '',
                        blocks_by_reason    TEXT  -- JSON
                      );
                      CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen);

                      -- Counter store mirroring SQLite metrics_kv. Holds
                      -- total_requests / allowed / blocked / by_reason etc.
                      -- across restarts.
                      CREATE TABLE IF NOT EXISTS metrics_kv (
                        key  TEXT PRIMARY KEY,
                        val  TEXT
                      );

                      -- Service-metric time series (CPU / mem / disk / net /
                      -- DB size + PG stats). Sampled at
                      -- SERVICE_METRICS_INTERVAL. Schema matches SQLite
                      -- including the columns added later via
                      -- _SCHEMA_MIGRATIONS (pg_*, identities_count,
                      -- total_requests) so the svc_metric INSERT can mirror.
                      CREATE TABLE IF NOT EXISTS svc_metrics (
                        ts                DOUBLE PRECISION PRIMARY KEY,
                        cpu_pct           DOUBLE PRECISION,
                        load1             DOUBLE PRECISION,
                        load5             DOUBLE PRECISION,
                        load15            DOUBLE PRECISION,
                        mem_used          BIGINT,
                        mem_total         BIGINT,
                        mem_avail         BIGINT,
                        mem_pct           DOUBLE PRECISION,
                        swap_used         BIGINT,
                        swap_total        BIGINT,
                        cg_used           BIGINT,
                        cg_limit          BIGINT,
                        cg_pct            DOUBLE PRECISION,
                        disk_used         BIGINT,
                        disk_total        BIGINT,
                        disk_avail        BIGINT,
                        disk_pct          DOUBLE PRECISION,
                        procs             BIGINT,
                        open_fds          BIGINT,
                        net_rx_bps        BIGINT,
                        net_tx_bps        BIGINT,
                        db_db             BIGINT,
                        db_wal            BIGINT,
                        db_shm            BIGINT,
                        db_total          BIGINT,
                        pg_db_bytes       BIGINT      DEFAULT 0,
                        pg_events_rows    BIGINT      DEFAULT 0,
                        identities_count  BIGINT      DEFAULT 0,
                        total_requests    BIGINT      DEFAULT 0,
                        pg_index_bytes    BIGINT      DEFAULT 0,
                        pg_active_conns   BIGINT      DEFAULT 0,
                        pg_idle_conns     BIGINT      DEFAULT 0,
                        pg_cache_hit_pct  DOUBLE PRECISION DEFAULT 0,
                        pg_tx_total       BIGINT      DEFAULT 0
                      );

                      -- Per-minute request roll-up for the dashboard
                      -- timeline panel.
                      CREATE TABLE IF NOT EXISTS timeline (
                        bucket_minute  BIGINT PRIMARY KEY,
                        total          BIGINT DEFAULT 0,
                        allowed        BIGINT DEFAULT 0,
                        blocked        BIGINT DEFAULT 0,
                        missed         BIGINT DEFAULT 0,
                        by_reason      TEXT  -- JSON
                      );

                      -- 2026 extension: users.totp_* + sso_source + oidc_sub
                      -- columns. These were added in 1.8.6 / 1.8.8 to the
                      -- SQLite users table via _SCHEMA_MIGRATIONS but the
                      -- PG users CREATE TABLE above predates them. Add
                      -- inline with ADD COLUMN IF NOT EXISTS so existing
                      -- PG deployments pick them up on next startup.
                    """)
                    for _col, _ddl in (
                        ("totp_secret",        "TEXT"),
                        ("totp_enabled",       "INTEGER NOT NULL DEFAULT 0"),
                        ("totp_backup_codes",  "TEXT"),
                        ("sso_source",         "TEXT"),
                        ("oidc_sub",           "TEXT"),
                    ):
                        try:
                            cur.execute(
                                f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {_col} {_ddl}")
                        except Exception:
                            pass  # nosec B110 — additive migration is best-effort
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

                    # A3 fix: schema-version tracking. Stamp the current
                    # version so operators (and migration scripts) can
                    # tell whether the PG schema matches the gateway
                    # release's expectations. Idempotent — upserts
                    # version=PG_SCHEMA_VERSION each boot.
                    try:
                        cur.execute("""
                          CREATE TABLE IF NOT EXISTS pg_schema_versions (
                            version       INTEGER PRIMARY KEY,
                            applied_ts    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                            applied_by    TEXT NOT NULL DEFAULT 'gateway',
                            note          TEXT
                          )
                        """)
                        cur.execute(
                            "INSERT INTO pg_schema_versions "
                            "(version, applied_ts, applied_by, note) "
                            "VALUES (%s, NOW(), 'gateway', %s) "
                            "ON CONFLICT (version) DO UPDATE SET "
                            "  applied_ts = NOW()",
                            (PG_SCHEMA_VERSION,
                             f"PG-only migration baseline "
                             f"(v={PG_SCHEMA_VERSION})"))
                    except Exception as _e:
                        _logging.warning(
                            "[db-pg] schema-version stamp failed: %s: %s",
                            type(_e).__name__, str(_e)[:120])
            if attempt > 1:
                _logging.info("[db-pg] init succeeded on attempt %d", attempt)
            return True
        except Exception as e:
            last_err = e
            # 1.8.14 iter-17 — auth failures will never self-heal from a retry
            # (the password is wrong; the next attempt will get the same
            # rejection). Short-circuit so we don't burn 12 attempts × backoff
            # seconds on an obvious mis-config that blocks SQLite-fallback
            # readiness. Caller (on_startup) treats `False` as "skip Postgres,
            # carry on with SQLite" — the gateway stays UP regardless.
            if _is_pg_auth_failure(e):
                global _PG_AUTH_FAILED, _PG_AUTH_FAILED_TS, _PG_AUTH_FAILED_HINT
                _PG_AUTH_FAILED = True
                _PG_AUTH_FAILED_TS = _t.time()
                _PG_AUTH_FAILED_HINT = _pg_auth_failure_hint(POSTGRES_DSN or "")
                # 1.8.14 iter-18 — also flip `_postgres_available` off and
                # auto-revert DB_BACKEND to sqlite so the service-metrics
                # sampler, /metrics readers, the connection pool, and the
                # event-write path all skip Postgres. Without this, every 5 s
                # sampler tick reopens a doomed connection — the operator's
                # Postgres log fills with `password authentication failed`.
                _disable_postgres_for_process(reason="auth-failure")
                _logging.error(
                    "[db-pg] AUTH FAILURE: %s: %s — STOPPING retry loop AND "
                    "disabling Postgres backend for this process. Gateway "
                    "will run on SQLite fallback only. %s",
                    type(e).__name__, e, _PG_AUTH_FAILED_HINT)
                return False
            # FREQUENT transient: the DB is up but still starting / replaying
            # WAL (57P03). Not an error — log a calm, explanatory line so the
            # operator doesn't mistake a normal boot race / post-restart
            # recovery for a real fault. Falls through to the retry below.
            if _is_pg_starting(e):
                _logging.warning(
                    "[db-pg] Postgres is still starting (crash/WAL recovery in "
                    "progress) — attempt %d/%d not ready yet: %s. This is a "
                    "common, self-healing transient after an unclean DB restart "
                    "or when the gateway races the DB on boot; retrying.",
                    attempt, max_attempts, str(e)[:120])
            if attempt < max_attempts:
                _t.sleep(backoff_s * attempt)
                continue
    if _is_pg_starting(last_err):
        # Recovery outlasted this init pass's retry budget. We return False; what
        # happens next is the CALLER's choice and differs by mode — so we don't
        # assert a single outcome here: on a PG-only boot, on_startup exits and
        # Docker restarts the gateway, which retries until recovery completes;
        # other call sites fall back to SQLite and the background recovery probe
        # (pg_maybe_recover) reconnects automatically. Either way it self-heals
        # once redo finishes — this is normal after a DB restart, not a fault.
        # Logged as a warning, not an error.
        _logging.warning(
            "[db-pg] Postgres still starting (crash/WAL recovery) after %d "
            "attempts (%s) — gave up this init pass; will keep retrying until "
            "recovery completes. Normal after an unclean DB restart; no action "
            "needed.",
            max_attempts, str(last_err)[:120])
    else:
        _logging.error("[db-pg] init failed after %d attempts: %s: %s",
                       max_attempts, type(last_err).__name__, last_err)
    # 1.8.14 iter-18 — non-auth failure (network, host down, timeout, etc.):
    # also flip _postgres_available = False so writes/reads/samplers skip
    # Postgres for the rest of this process. Without this, every sampler
    # tick (5 s) and every event insert would keep retrying a dead host,
    # logging an error each time. User-requested behaviour: "if Postgres
    # cannot connect at start, revert to SQLite."
    _disable_postgres_for_process(reason=f"init-failed:{type(last_err).__name__}")
    return False


def _disable_postgres_for_process(reason: str = "") -> None:
    """1.8.14 iter-18 — flip the global _postgres_available flag off and
    coerce the active DB_BACKEND back to sqlite so the gateway cleanly
    runs on SQLite for the remainder of this process. 1.9.2 iter-21 — no longer
    permanent: the background recovery probe (`pg_maybe_recover`) re-enables
    the backend automatically once Postgres is reachable + authable again.
    Idempotent."""
    global _PG_DISABLED_BY_FAILURE, _PG_DISABLED_TS
    try:
        _PG_DISABLED_BY_FAILURE = True
        _PG_DISABLED_TS = _t.time()
        _state._postgres_available = False
        import sys as _sys_pg
        for _m in list(_sys_pg.modules.values()):
            if _m is not None and hasattr(_m, '_postgres_available'):
                try:
                    setattr(_m, '_postgres_available', False)
                except (AttributeError, TypeError):
                    pass
        # Force DB_BACKEND back to sqlite on core.proxy_handler so writes
        # take the SQLite path (record() in core/metrics.py checks both
        # DB_BACKEND=='postgres' AND _postgres_available).
        _ph = _sys_pg.modules.get("core.proxy_handler")
        if _ph is not None and getattr(_ph, "DB_BACKEND", "sqlite") == "postgres":
            try:
                setattr(_ph, "DB_BACKEND", "sqlite")
                _logging.warning(
                    "[db-pg] active backend auto-reverted to SQLite (%s). "
                    "Operator must restart the gateway after fixing the "
                    "Postgres deployment.", reason)
            except (AttributeError, TypeError):
                pass
    except Exception:
        pass


def _reenable_postgres_for_process(reason: str = "") -> None:
    """1.9.2 iter-21 — reverse `_disable_postgres_for_process`: clear the auth latch,
    flip `_postgres_available` back on across every module that mirrors it, and
    restore DB_BACKEND=postgres on core.proxy_handler so writes/reads/samplers
    resume on Postgres. Stale pool connections are NOT force-closed here — the
    pool's `_acquire` pings every connection and discards dead ones, so the
    first post-recovery acquire transparently dials fresh sockets to the healed
    server. Idempotent."""
    global _PG_AUTH_FAILED, _PG_DISABLED_BY_FAILURE, _PG_RECOVERED_COUNT
    try:
        _PG_AUTH_FAILED = False
        _PG_DISABLED_BY_FAILURE = False
        _state._postgres_available = True
        import sys as _sys_pg
        for _m in list(_sys_pg.modules.values()):
            if _m is not None and hasattr(_m, '_postgres_available'):
                try:
                    setattr(_m, '_postgres_available', True)
                except (AttributeError, TypeError):
                    pass
        # Restore the active backend on core.proxy_handler. _disable only
        # reverts DB_BACKEND when it was "postgres", so recovery unconditionally
        # restores "postgres" — this path only runs when PG was the live backend.
        _ph = _sys_pg.modules.get("core.proxy_handler")
        if _ph is not None and hasattr(_ph, "DB_BACKEND"):
            try:
                setattr(_ph, "DB_BACKEND", "postgres")
            except (AttributeError, TypeError):
                pass
        _PG_RECOVERED_COUNT += 1
        _logging.warning(
            "[db-pg] AUTO-RECOVERY: Postgres reachable again (%s) — backend "
            "re-enabled, DB_BACKEND restored to postgres (recovery #%d). No "
            "gateway restart required.", reason or "probe ok", _PG_RECOVERED_COUNT)
    except Exception:
        pass


def pg_recovery_probe(timeout: float = 5.0) -> bool:
    """1.9.2 iter-21 — single direct connect + `SELECT 1`, bypassing the pool and the
    auth latch, to test whether Postgres is reachable AND authable again.
    Returns True only on a clean round-trip. Never raises."""
    dsn = POSTGRES_DSN or ""
    if not dsn:
        return False
    pg = _postgres_load_module()
    if pg is None:
        return False
    conn = None
    try:
        conn = pg.connect(dsn, connect_timeout=int(max(1, timeout)), autocommit=True)
        cur = conn.execute("SELECT 1")
        row = cur.fetchone()
        return bool(row)
    except Exception:
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def pg_maybe_recover() -> bool:
    """1.9.2 iter-21 — called periodically by the gateway's background recovery loop.
    Cheap no-op when Postgres is healthy (returns immediately). When the backend
    was disabled by a failure, it probes once; on success it re-enables Postgres
    for the whole process. Returns True only when a recovery actually fired."""
    if not _PG_DISABLED_BY_FAILURE:
        return False
    if not (POSTGRES_DSN or ""):
        return False
    if not pg_recovery_probe():
        return False
    # Reachable + authable again. Re-run the idempotent schema init (single
    # attempt — connectivity is already proven) so a Postgres that came back
    # with a FRESH volume gets its tables rebuilt before we resume writing.
    # On a normal restart with the volume intact this is a cheap CREATE TABLE
    # IF NOT EXISTS sweep. If init fails it re-latches via
    # _disable_postgres_for_process and we retry on the next probe tick.
    try:
        ok = db_init_postgres(max_attempts=1)
    except Exception:
        ok = False
    if ok:
        _reenable_postgres_for_process(reason="background recovery probe")
        return True
    return False


def pg_insert_event(ts: float, ip: str, ua: str, path: str,
                     status: int, reason: str, track_key: str = "",
                     sid: str = "", fp: str = "", ja4: str = "",
                     request_id: str = "", method: str = "",
                     vhost: str = "") -> bool:
    """1.6.5 — append one event row to the Postgres backend. Returns True
    on success, False on transient failure (caller falls back to dropping
    silently — events are best-effort, never block the request path).

    `vhost` (1.8.13 fix): the events table has a `vhost` column (added via
    _SCHEMA_MIGRATIONS); it must be written here for the per-vhost dashboard
    filters to work on a Postgres-active deployment — SQLite already stores it.
    """
    if DB_BACKEND != "postgres":
        return False
    pool = _get_pool()
    if pool is None:
        # iter-6: log once so the operator sees WHY events vanished.
        # Pool init failure → user reports "events disappear after upgrade".
        if not getattr(pg_insert_event, "_pool_none_logged", False):
            _logging.error(
                "[pg-insert-event] pool unavailable — every event is "
                "being dropped silently. Check the boot log for FATAL "
                "POSTGRES_DSN or pool-init lines.")
            pg_insert_event._pool_none_logged = True
        return False
    try:
        with pool.connection(timeout=2.0) as conn:
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, method, status, reason, "
                "track_key, sid, fp, ja4, request_id, vhost) "
                "VALUES (to_timestamp(%s), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (ts, _pg_safe(ip), _pg_safe((ua or "")[:500]),
                 _pg_safe(path or ""), _pg_safe(method or ""),
                 int(status), _pg_safe(reason or ""), _pg_safe(track_key or ""),
                 _pg_safe(sid or ""), _pg_safe(fp or ""), _pg_safe(ja4 or ""),
                 _pg_safe(request_id or ""), _pg_safe((vhost or "")[:253])))
        return True
    except Exception as _e:
        # iter-6 fix: previously this `except Exception: return False`
        # swallowed every failure with zero log, so a schema mismatch
        # (e.g. legacy events table without vhost/method columns on an
        # upgrade where _apply_pg_migrations didn't run) silently dropped
        # 100% of events. Operator saw "events disappearing after upgrade"
        # with no breadcrumb. Now: log the FIRST failure of each distinct
        # exception type with the message — enough to diagnose without
        # spamming on a sustained outage.
        _err_class = type(_e).__name__
        _seen = getattr(pg_insert_event, "_seen_err_classes", None)
        if _seen is None:
            _seen = set()
            pg_insert_event._seen_err_classes = _seen
        if _err_class not in _seen:
            _seen.add(_err_class)
            _logging.error(
                "[pg-insert-event] event DROPPED: %s: %s — first occurrence "
                "of this exception class; subsequent identical failures "
                "won't re-log to avoid spam. Common causes: legacy events "
                "schema missing method/vhost columns (fix: ALTER TABLE "
                "events ADD COLUMN method TEXT, vhost TEXT DEFAULT ''), "
                "PG temporarily unreachable, or FK violation.",
                _err_class, str(_e)[:240])
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
                # events_rows — planner ESTIMATE, not an exact COUNT(*).
                # 1.9.2 iter-22: on a large Timescale hypertable an unbounded
                # exact count over the events table full-scans every chunk — 40+ s
                # on the live example.com DB and, because db_test_endpoint runs
                # this on the event loop, froze the whole worker (concurrent
                # admin requests 502'd). reltuples summed over the table + its
                # inheritance children (Timescale chunks ARE inheritance
                # children of the hypertable root) is a catalog-only read:
                # instant, and accurate enough for a dashboard figure (kept
                # fresh by ANALYZE / autovacuum). Table may not exist yet when
                # the standby is probed before the first switch → 0.
                try:
                    cur.execute("""
                        SELECT COALESCE(SUM(c.reltuples)::bigint, 0)
                        FROM pg_class c
                        WHERE c.oid = 'events'::regclass
                           OR c.oid IN (SELECT inhrelid FROM pg_inherits
                                        WHERE inhparent = 'events'::regclass)
                    """)
                    rows = int(cur.fetchone()[0])
                    if rows < 0:
                        rows = 0
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
                    method      TEXT,
                    status      INTEGER,
                    reason      TEXT,
                    track_key   TEXT,
                    sid         TEXT,
                    fp          TEXT,
                    ja4         TEXT,
                    request_id  TEXT,
                    vhost       TEXT DEFAULT '',
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


# ────────────────────────────────────────────────────────────────────────────
# 1.8.8 — backend-aware event reader (postgres side).
# Called via db.db_read_events() dispatcher when DB_BACKEND=postgres and
# _postgres_available is True. ts in the returned rows is normalised to
# epoch float (Postgres stores TIMESTAMPTZ, so we EXTRACT(EPOCH FROM ts)).
#
# Schema parity (1.8.13): the Postgres `events` table now has real `method`
# and `vhost` columns, both added at startup via _SCHEMA_MIGRATIONS
# (ALTER TABLE ... ADD COLUMN IF NOT EXISTS). They are written by
# pg_insert_event and filterable here, matching SQLite. `_PG_MISSING_COLUMNS`
# is therefore empty.
# ────────────────────────────────────────────────────────────────────────────

_VALID_EVENT_COLUMNS_PG = frozenset({
    "id", "ts", "ip", "ua", "path", "method", "status", "reason",
    "track_key", "sid", "fp", "ja4", "request_id", "vhost",
})

_VALID_ORDER_BY_PG = {
    "ts": " ORDER BY ts ASC",
    "ts asc": " ORDER BY ts ASC",
    "ts desc": " ORDER BY ts DESC",
    "id": " ORDER BY id ASC",
    "id asc": " ORDER BY id ASC",
    "id desc": " ORDER BY id DESC",
}

# Columns previously absent from Postgres that were filled with "" so callers
# wouldn't see a KeyError. Both `vhost` (1.8.0) and `method` (1.8.13) are now
# real columns added via _SCHEMA_MIGRATIONS at startup — the set is empty.
_PG_MISSING_COLUMNS: frozenset[str] = frozenset()


def _read_events_pg(
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
    """Postgres implementation of db_read_events. Returns list of dicts.
    `ts` is normalised to epoch float via EXTRACT(EPOCH FROM ts)."""
    pg = _postgres_load_module()
    if pg is None:
        raise RuntimeError("psycopg not installed")
    if not POSTGRES_DSN:
        raise RuntimeError("POSTGRES_DSN not configured")
    requested = list(columns) if columns else ["ts", "ip", "reason"]
    for c in requested:
        if c not in _VALID_EVENT_COLUMNS_PG:
            raise ValueError(f"invalid event column: {c!r}")

    # Build the SELECT — replace ts with EXTRACT(EPOCH FROM ts).
    sql_cols = []
    real_cols = []  # column names actually fetched, for row mapping
    for c in requested:
        if c == "ts":
            sql_cols.append("EXTRACT(EPOCH FROM ts) AS ts")
            real_cols.append("ts")
        elif c in _PG_MISSING_COLUMNS:
            # Don't include in SELECT — fill with "" after fetch
            real_cols.append(c)
        else:
            sql_cols.append(c)
            real_cols.append(c)

    where = []
    params: list = []
    if start_ts and start_ts > 0:
        where.append("ts >= to_timestamp(%s)")
        params.append(float(start_ts))
    if end_ts and end_ts > 0:
        where.append("ts <= to_timestamp(%s)")
        params.append(float(end_ts))
    # vhost filter (1.8.13 fix) — the events table now has a real `vhost`
    # column (added via _SCHEMA_MIGRATIONS), so filter on it like SQLite does.
    if vhost:
        where.append("vhost = %s")
        params.append(vhost)
    if path_like:
        where.append("LOWER(path) LIKE %s")
        params.append(f"%{path_like.lower()}%")
    if reason_like:
        where.append("LOWER(reason) LIKE %s")
        params.append(f"%{reason_like.lower()}%")
    if reason_in:
        # Exact-set match — avoids LIKE prefix bleed (e.g. "honeypot" matching
        # "honeypot-silent"). Placeholders are count-derived, values bound.
        _ph = ",".join(["%s"] * len(reason_in))
        where.append(f"reason IN ({_ph})")  # nosec B608 — placeholders only
        params.extend(str(x) for x in reason_in)
    if ip_exact:
        where.append("ip = %s")
        params.append(ip_exact)
    order_clause = ""
    if order_by:
        ob = order_by.strip().lower()
        if ob not in _VALID_ORDER_BY_PG:
            raise ValueError(f"invalid order_by: {order_by!r}")
        order_clause = _VALID_ORDER_BY_PG[ob]
    limit_clause = ""
    if limit and limit > 0:
        limit_clause = f" LIMIT {int(limit)}"
        if offset and offset > 0:
            limit_clause += f" OFFSET {int(offset)}"
    # Edge case: requested columns are ALL in _PG_MISSING_COLUMNS — we still
    # need at least one real column in the SELECT (e.g. id) to get row count.
    if not sql_cols:
        sql_cols = ["id"]
    where_sql = (" WHERE " + " AND ".join(where)) if where else ""
    # sql_cols / order_clause / limit_clause are all built from whitelisted
    # constants (_VALID_ORDER_BY, _VALID_EVENT_COLUMNS, int() coercion) —
    # there is no path for caller-supplied bytes to reach the SQL text.
    # All actual values flow through `params` via %s placeholders below.
    sql = (
        f"SELECT {','.join(sql_cols)} FROM events"  # nosec B608 — all interpolated fragments are whitelisted constants
        f"{where_sql}{order_clause}{limit_clause}"
    )
    out = []
    try:
        with pg.connect(POSTGRES_DSN, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                # Map column names from the cursor description
                if cur.description:
                    fetched_names = [d[0] for d in cur.description]
                else:
                    fetched_names = []
                for row in cur.fetchall():
                    d = {}
                    for col_name, val in zip(fetched_names, row):
                        # psycopg returns numeric/EXTRACT(EPOCH …) as Decimal,
                        # which is not JSON-serializable — coerce to float so
                        # every db_read_events consumer (attack-playbook,
                        # honeypots-data, agents, …) can json_response the rows.
                        if isinstance(val, _Decimal):
                            val = float(val)
                        d[col_name] = val
                    # Inject empty strings for SQLite-only columns
                    for c in requested:
                        if c in _PG_MISSING_COLUMNS and c not in d:
                            d[c] = ""
                    out.append(d)
    except Exception:
        raise
    return out


def _events_health_pg() -> dict:
    """Postgres events-table health probe — count + last_event_ts (epoch).
    Returns same shape as _events_health_sql for symmetry."""
    out = {"last_event_ts": None, "events_rows": 0, "ok": False}
    pg = _postgres_load_module()
    if pg is None or not POSTGRES_DSN:
        out["error"] = "psycopg not installed or POSTGRES_DSN unset"
        return out
    try:
        with pg.connect(POSTGRES_DSN, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*), EXTRACT(EPOCH FROM MAX(ts)) FROM events"
                )
                r = cur.fetchone()
                if r:
                    out["events_rows"]   = int(r[0] or 0)
                    out["last_event_ts"] = float(r[1]) if r[1] is not None else None
                out["ok"] = True
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {str(e)[:120]}"
    return out


# ════════════════════════════════════════════════════════════════════════════
# REVIEW-PG-DUAL-WRITE (iter-18): cold-start restore.
#
# Runs once during on_startup, BEFORE db_load_config / db_load_secrets /
# db_load_admin_ips / _session_cache_load. If POSTGRES_DSN is configured AND
# Postgres is reachable AND the local SQLite users/config tables are empty,
# copies every dual-write table from PG → SQLite so the gateway boots with
# the operator state intact.
#
# Restore-from-PG is intentionally GUARDED on "SQLite is fresh-empty" — once
# any local row exists (operator already configured the gateway), the SQLite
# data wins and PG mirroring resumes after boot. This prevents an accidental
# PG mirror from overwriting good local state.
# ════════════════════════════════════════════════════════════════════════════

def db_restore_from_postgres(sqlite_path: str) -> dict:
    """Copy operator-facing rows from Postgres into a fresh-empty SQLite.

    Returns a stats dict: counts per restored table + reason if skipped.
    Idempotent — re-running after a successful restore is a no-op.
    """
    out = {"restored": False, "tables": {}, "reason": ""}
    pg = _postgres_load_module()
    if pg is None or not POSTGRES_DSN:
        out["reason"] = "no_dsn_or_psycopg"
        return out

    import sqlite3
    # ── Guard: only restore into a fresh-empty SQLite ───────────────────────
    try:
        s_conn = sqlite3.connect(sqlite_path, timeout=5)
    except Exception as e:
        out["reason"] = f"sqlite_open_failed: {e}"
        return out
    try:
        try:
            user_count = s_conn.execute(
                "SELECT COUNT(*) FROM users").fetchone()[0]
        except sqlite3.OperationalError:
            user_count = 0  # table missing → treat as empty
        try:
            config_count = s_conn.execute(
                "SELECT COUNT(*) FROM config_kv").fetchone()[0]
        except sqlite3.OperationalError:
            config_count = 0
        # If the local SQLite already has user accounts or persisted config,
        # the operator has been here before — SQLite wins.
        if user_count > 0 or config_count > 0:
            out["reason"] = (f"sqlite_not_empty "
                             f"(users={user_count}, config={config_count})")
            return out

        # ── Open PG ─────────────────────────────────────────────────────────
        try:
            pconn = pg.connect(POSTGRES_DSN, connect_timeout=5)
        except Exception as e:
            out["reason"] = f"pg_unreachable: {type(e).__name__}: {str(e)[:80]}"
            return out

        try:
            _logging.info("[db-restore] SQLite empty + PG reachable — "
                          "restoring operator state from PG")

            # Restore plan: (PG SELECT, SQLite INSERT, params-builder).
            # Each row is (table_label, pg_query, sqlite_insert).
            _PLAN = [
                ("config_kv",
                 "SELECT key, value, ts FROM config_kv",
                 "INSERT OR REPLACE INTO config_kv (key, value, ts) "
                 "VALUES (?, ?, ?)"),
                ("secrets_kv",
                 "SELECT key, value, ts FROM secrets_kv",
                 "INSERT OR REPLACE INTO secrets_kv (key, value, ts) "
                 "VALUES (?, ?, ?)"),
                ("admin_ips",
                 "SELECT cidr, added_ts, note, source, description "
                 "FROM admin_ips",
                 "INSERT OR REPLACE INTO admin_ips "
                 "(cidr, added_ts, note, source, description) "
                 "VALUES (?, ?, ?, ?, ?)"),
                ("users",
                 # PG might be missing the totp_* columns on legacy installs;
                 # use NULL fallback via the SELECT list.
                 "SELECT username, password_hash, role, status, created_ts, "
                 "updated_ts, last_login_ts, last_login_ip, "
                 "COALESCE(totp_secret, ''), COALESCE(totp_enabled, 0), "
                 "COALESCE(totp_backup_codes, ''), "
                 "COALESCE(sso_source, ''), COALESCE(oidc_sub, '') "
                 "FROM users",
                 "INSERT OR REPLACE INTO users "
                 "(username, password_hash, role, status, created_ts, "
                 "updated_ts, last_login_ts, last_login_ip, totp_secret, "
                 "totp_enabled, totp_backup_codes, sso_source, oidc_sub) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
                # user_sessions intentionally OMITTED — sessions expire on
                # their own and forcing operators to re-login after a wipe
                # is safer than mirroring tokens across DBs.
                ("bans",
                 "SELECT ip, banned_until, reason, ts FROM bans "
                 "WHERE banned_until > EXTRACT(EPOCH FROM NOW())",
                 "INSERT OR REPLACE INTO bans (ip, banned_until, reason, ts) "
                 "VALUES (?, ?, ?, ?)"),
                ("ip_bans",
                 "SELECT ip, banned_until, reason, ts FROM ip_bans "
                 "WHERE banned_until > EXTRACT(EPOCH FROM NOW())",
                 "INSERT OR REPLACE INTO ip_bans (ip, banned_until, reason, ts) "
                 "VALUES (?, ?, ?, ?)"),
                ("dlp_patterns",
                 "SELECT name, pattern, severity, enabled, added_ts, added_by "
                 "FROM dlp_patterns",
                 "INSERT OR IGNORE INTO dlp_patterns "
                 "(name, pattern, severity, enabled, added_ts, added_by) "
                 "VALUES (?, ?, ?, ?, ?, ?)"),
                ("siem_alert_rules",
                 "SELECT metric, op, threshold, label, enabled, created_ts, "
                 "created_by, last_fired_ts, cooldown_s FROM siem_alert_rules",
                 "INSERT INTO siem_alert_rules "
                 "(metric, op, threshold, label, enabled, created_ts, "
                 "created_by, last_fired_ts, cooldown_s) "
                 "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"),
                ("gw_registry",
                 "SELECT gw_id, domain, region, environment, status, "
                 "can_distribute, public_key, private_key, key_created_ts, "
                 "key_rotated_ts, last_seen_ts, created_ts, updated_ts, "
                 "is_local FROM gw_registry",
                 "INSERT OR REPLACE INTO gw_registry "
                 "(gw_id, domain, region, environment, status, "
                 "can_distribute, public_key, private_key, key_created_ts, "
                 "key_rotated_ts, last_seen_ts, created_ts, updated_ts, "
                 "is_local) VALUES "
                 "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
                ("gw_distribution",
                 "SELECT source_gw_id, target_gw_id, ts FROM gw_distribution",
                 "INSERT OR IGNORE INTO gw_distribution "
                 "(source_gw_id, target_gw_id, ts) VALUES (?, ?, ?)"),
            ]

            for label, pg_sql, sqlite_sql in _PLAN:
                try:
                    with pconn.cursor() as cur:
                        cur.execute(pg_sql)
                        rows = cur.fetchall()
                    if not rows:
                        out["tables"][label] = 0
                        continue
                    s_conn.executemany(sqlite_sql, rows)
                    s_conn.commit()
                    out["tables"][label] = len(rows)
                    _logging.info("[db-restore] %s: %d rows", label, len(rows))
                except Exception as e:
                    # Per-table failure shouldn't abort the rest of the restore.
                    out["tables"][label] = f"ERR: {type(e).__name__}: {str(e)[:80]}"
                    _logging.warning(
                        "[db-restore] %s failed: %s", label, e)

            out["restored"] = True
            _logging.info("[db-restore] complete: %s",
                          {k: v for k, v in out["tables"].items() if v})
        finally:
            try: pconn.close()
            except Exception: pass
    finally:
        try: s_conn.close()
        except Exception: pass
    return out


def prune_gw_audit_postgres(retention_days: int) -> int:
    """1.9.0 (F4) — prune gw_audit rows older than `retention_days` from the
    Postgres mirror. Companion to db/sqlite.py:prune_gw_audit; together they
    keep the audit table bounded in single-DB-PG mode (where SQLite gw_audit
    receives no inserts and the SQLite prune is a no-op).

    Indexed by ts so the DELETE is cheap even on multi-year tables.
    Returns the number of rows deleted (0 on disabled / error / no rows).
    """
    if retention_days <= 0:
        return 0
    pg = _postgres_load_module()
    if pg is None or not POSTGRES_DSN:
        return 0
    cutoff = _t.time() - (retention_days * 86400)
    try:
        with pg.connect(POSTGRES_DSN, connect_timeout=5,
                          autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM gw_audit WHERE ts < %s",
                             (cutoff,))
                count = cur.rowcount
        if count > 0:
            _logging.info(
                "[pg-prune] gw_audit: %d rows pruned "
                "(retention_days=%d, cutoff_ts=%.0f)",
                count, retention_days, cutoff)
        return count
    except Exception as e:
        _logging.warning("[pg-prune] gw_audit failed: %s: %s",
                          type(e).__name__, str(e)[:200])
        return 0
