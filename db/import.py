"""
db.import — one-shot SQLite → Postgres migration tool.

Reads every operator-state row from the local SQLite at $DB_PATH and inserts
it into Postgres via the same `_pg_mirror_kv` arms the runtime uses. Idempotent
(`INSERT ... ON CONFLICT DO UPDATE/NOTHING`) so safe to re-run.

Usage:
    python -m db.import                     # uses $DB_PATH + $POSTGRES_DSN
    python -m db.import /path/to/sqlite.db  # override SQLite source
    python -m db.import --dry-run           # report counts; no writes

Exit codes:
    0  success
    1  CLI / env error
    2  SQLite source missing
    3  PG unreachable
    4  one or more table copies failed (others may have succeeded)

Operator-critical tables (users / sessions / config / secrets / admin_ips /
bans / DLP / SIEM rules / mesh) are the priority. Observational data
(events / audit log / abuseipdb cache / client roll-up / timeline / svc-metrics)
follows. The tool prints a per-table line with the row count it copied.

The SQLite file is read-only opened — never modified.
"""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys


# M5 fix: every identifier (table + column) that lands in an f-string SQL
# must match this whitelist. Defence-in-depth — the list comes from a
# static plan, but a future contributor adding a user-supplied table
# parameter would inherit the unsafe pattern. Cheap to enforce, cheap to
# reason about.
_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def _ident(name: str) -> str:
    if not isinstance(name, str) or not _IDENT_RE.match(name):
        raise ValueError(
            f"invalid SQL identifier {name!r} — must match {_IDENT_RE.pattern}"
        )
    return name


class _TxAborted(Exception):
    """M8 fix: raised after the first dispatch failure in a caller-managed
    transaction. PG marks the whole transaction as
    `InFailedSqlTransaction` after one error → every subsequent op also
    raises (the cascade). We were counting each cascade as a fresh
    "error", inflating the final count and burying the real cause.

    Catching this in the main loop short-circuits ALL remaining tables
    and goes straight to ROLLBACK, with an accurate error count of 1.
    """


# L8 fix — _mask_dsn lives in db.cli_helpers so db.export and db.import
# share one implementation. Kept as `_mask_dsn` re-export for stability of
# the existing call sites in this file.
from db.cli_helpers import mask_dsn as _mask_dsn  # noqa: E402, F401


# ── Per-table dispatch ──────────────────────────────────────────────────────
#
# Each entry: (sqlite_table, pg_op, columns, row_to_args)
#   - sqlite_table: source table name
#   - pg_op: op name registered in _pg_mirror_kv
#   - columns: SELECT column list (must match row_to_args's input)
#   - row_to_args: callable(row_tuple) → tuple to pass as args to _pg_mirror_kv
#
# Order is significant: rows that have FK references (e.g. user_sessions →
# users) come AFTER their parent table.

def _identity(row):
    return tuple(row)


def _dispatch_plan():
    """Built lazily so config import happens after the SQLite file is verified."""
    return [
        # — Operator-critical, no dependencies —
        ("config_kv", "set_config",
            ["key", "value", "ts"], _identity),
        ("secrets_kv", "set_secret",
            ["key", "value", "ts"], _identity),
        ("admin_ips", "set_admin_ip",
            ["cidr", "added_ts", "note", "source", "description"], _identity),
        ("users", "user_create",
            # PG user_create accepts the base 6 cols only. Extension cols
            # (last_login_*, totp_*, sso_source, oidc_sub) are populated
            # later via user_login_recorded / user_update so the base
            # row exists first.
            ["username", "password_hash", "role", "status",
             "created_ts", "updated_ts"], _identity),
        # — Dependent on users —
        ("user_sessions", "user_session_create",
            # PG signature: (sid, username, ip, ua, c_ts, l_ts, e_ts, csrf).
            # SQLite column `user_agent` → renamed to `ua` for the dispatch;
            # csrf_nonce comes last. expires_ts may be NULL on older rows;
            # COALESCE shields the INSERT.
            ["sid", "username", "ip", "user_agent",
             "created_ts", "last_seen_ts", "expires_ts", "csrf_nonce"],
            _identity),
        # — Standalone state —
        ("bans", "ban",
            ["ip", "banned_until", "reason", "ts"], _identity),
        ("ip_bans", "ip_ban",
            ["ip", "banned_until", "reason", "ts"], _identity),
        ("dlp_patterns", "dlp_add",
            # PG arm: (name, pattern, severity, added_ts, added_by).
            ["name", "pattern", "severity", "added_ts", "added_by"],
            _identity),
        ("siem_alert_rules", "siem_alert_rule_add",
            # PG arm: (metric, op, threshold, label, created_ts,
            #          created_by, cooldown_s).
            ["metric", "op", "threshold", "label",
             "created_ts", "created_by", "cooldown_s"], _identity),
        ("siem_alert_fired", "siem_alert_fired",
            # PG arm: (rule_id, ts, value).
            ["rule_id", "ts", "value"], _identity),
        ("gw_audit", "gw_audit_add",
            # PG arm: (ts, action, gw_id, actor, details).
            ["ts", "action", "gw_id", "actor", "details"], _identity),
        ("honey_fingerprints", "honey_fp_add",
            # PG arm: (ts, track_key, ip, ua, ja4, asn, path, reason).
            ["ts", "track_key", "ip", "ua", "ja4", "asn", "path", "reason"],
            _identity),
        ("gw_registry", "gw_registry_add",
            # PG arm: 14-arg tuple matching SQLite column order.
            ["gw_id", "domain", "region", "environment", "status",
             "can_distribute", "public_key", "private_key",
             "key_created_ts", "key_rotated_ts", "last_seen_ts",
             "created_ts", "updated_ts", "is_local"], _identity),
        # — Observational —
        ("abuseipdb_cache", "abuseipdb_set",
            ["ip", "score", "country", "ts"], _identity),
        ("audit_events", "audit_log",
            ["ts", "event_type", "actor", "target", "ip",
             "detail", "session_id", "severity"], _identity),
        ("clients", "upsert_client",
            ["ip", "first_seen", "last_seen", "request_count",
             "allowed_count", "blocked_count", "banned_until_epoch",
             "last_user_agent", "last_path", "last_vhost",
             "blocks_by_reason"], _identity),
        ("metrics_kv", "set_kv",
            ["key", "val"], _identity),
        ("timeline", "upsert_timeline",
            ["bucket_minute", "total", "allowed", "blocked",
             "missed", "by_reason"], _identity),
        # svc_metrics has 35 columns — built dynamically below to keep this
        # table compact.
    ]


def _svc_metrics_columns():
    return [
        "ts", "cpu_pct", "load1", "load5", "load15",
        "mem_used", "mem_total", "mem_avail", "mem_pct",
        "swap_used", "swap_total", "cg_used", "cg_limit", "cg_pct",
        "disk_used", "disk_total", "disk_avail", "disk_pct",
        "procs", "open_fds", "net_rx_bps", "net_tx_bps",
        "db_db", "db_wal", "db_shm", "db_total",
        "pg_db_bytes", "pg_events_rows",
        "identities_count", "total_requests",
        "pg_index_bytes", "pg_active_conns", "pg_idle_conns",
        "pg_cache_hit_pct", "pg_tx_total",
    ]


def _copy_table(s_conn, table, pg_op, columns, row_to_args,
                dispatch, dry_run):
    """Copy one table from SQLite → PG. Returns (rows_seen, rows_copied,
    errors). dry_run skips the PG write."""
    # M5 fix: validate identifiers before f-string composition.
    tbl = _ident(table)
    cols_sql = ", ".join(_ident(c) for c in columns)
    try:
        rows = s_conn.execute(
            f"SELECT {cols_sql} FROM {tbl}"  # noqa: S608 — identifiers validated
        ).fetchall()
    except sqlite3.OperationalError as e:
        # Table doesn't exist on this SQLite (older deploy missing the
        # table) — skip silently.
        if "no such table" in str(e):
            return 0, 0, 0
        raise
    seen = len(rows)
    if dry_run or seen == 0:
        return seen, 0, 0
    copied = 0
    errors = 0
    for row in rows:
        args = row_to_args(row)
        try:
            if not dispatch(pg_op, args):
                errors += 1
            else:
                copied += 1
        except Exception as e:
            errors += 1
            print(f"  ! {table}: {type(e).__name__}: {str(e)[:120]}",
                  file=sys.stderr, flush=True)
            # M8 fix: in transactional mode, the first failure poisons
            # the whole transaction — every subsequent dispatch will
            # raise InFailedSqlTransaction. Bail out so the cascade
            # doesn't inflate the error count + spam stderr with
            # repetitive "current transaction is aborted" messages.
            raise _TxAborted(
                f"first failure in {table}: {type(e).__name__}: "
                f"{str(e)[:120]}") from e
    return seen, copied, errors


def _copy_events(s_conn, pg_insert_event, dry_run):
    """events has its own PG insert (pg_insert_event), different shape."""
    try:
        rows = s_conn.execute(
            "SELECT ts, ip, ua, path, method, status, reason, vhost "
            "FROM events"
        ).fetchall()
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            return 0, 0, 0
        raise
    seen = len(rows)
    if dry_run or seen == 0:
        return seen, 0, 0
    copied = 0
    errors = 0
    for ts, ip, ua, path, method, status, reason, vhost in rows:
        try:
            ok = pg_insert_event(ts, ip, ua, path, status, reason,
                                  method=method, vhost=vhost)
            copied += 1 if ok else 0
            errors += 0 if ok else 1
        except Exception as e:
            errors += 1
            print(f"  ! events: {type(e).__name__}: {str(e)[:120]}",
                  file=sys.stderr, flush=True)
    return seen, copied, errors


def _copy_svc_metrics(s_conn, dispatch, dry_run):
    """svc_metrics has 35 columns — special-cased to keep _dispatch_plan
    compact."""
    cols = _svc_metrics_columns()
    cols_sql = ", ".join(_ident(c) for c in cols)  # M5 fix
    try:
        rows = s_conn.execute(
            f"SELECT {cols_sql} FROM svc_metrics"  # noqa: S608 — identifiers validated
        ).fetchall()
    except sqlite3.OperationalError as e:
        if "no such table" in str(e):
            return 0, 0, 0
        raise
    seen = len(rows)
    if dry_run or seen == 0:
        return seen, 0, 0
    copied = 0
    errors = 0
    for row in rows:
        try:
            ok = dispatch("svc_metric", tuple(row))
            copied += 1 if ok else 0
            errors += 0 if ok else 1
        except Exception as e:
            errors += 1
            print(f"  ! svc_metrics: {type(e).__name__}: {str(e)[:120]}",
                  file=sys.stderr, flush=True)
    return seen, copied, errors


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m db.import",
                                      description=__doc__)
    parser.add_argument("sqlite_path", nargs="?",
                        help="Override SQLite source (defaults to $DB_PATH)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report row counts without writing to PG")
    parser.add_argument("--skip-events", action="store_true",
                        help="Skip the (potentially large) events table")
    args = parser.parse_args(argv)

    # Resolve SQLite path.
    if args.sqlite_path:
        sqlite_path = args.sqlite_path
    else:
        sqlite_path = os.environ.get("DB_PATH", "")
        if not sqlite_path:
            print("ERR: DB_PATH not set and no positional SQLite path given",
                  file=sys.stderr)
            return 1
    if not os.path.exists(sqlite_path):
        print(f"ERR: SQLite file not found: {sqlite_path}", file=sys.stderr)
        return 2

    # Resolve PG (unless --dry-run).
    pg_dsn = os.environ.get("POSTGRES_DSN", "").strip()
    if not args.dry_run and not pg_dsn:
        print("ERR: POSTGRES_DSN not set (required unless --dry-run)",
              file=sys.stderr)
        return 1

    print(f"[db.import] source: {sqlite_path}", flush=True)
    print(f"[db.import] target: {'(dry-run)' if args.dry_run else _mask_dsn(pg_dsn)}",
          flush=True)

    # Verify PG reachable.
    if not args.dry_run:
        try:
            from db.postgres import (
                _postgres_load_module, _pg_mirror_kv,
                pg_insert_event, db_init_postgres,
            )
            pg = _postgres_load_module()
            if pg is None:
                print("ERR: psycopg not installed", file=sys.stderr)
                return 3
            with pg.connect(pg_dsn, connect_timeout=5) as _probe:
                with _probe.cursor() as _cur:
                    _cur.execute("SELECT 1")
                    _cur.fetchone()
        except Exception as e:
            print(f"ERR: PG unreachable: {type(e).__name__}: {str(e)[:200]}",
                  file=sys.stderr)
            return 3
        # Ensure schema is present.
        if not db_init_postgres():
            print("ERR: db_init_postgres failed; aborting import",
                  file=sys.stderr)
            return 3
        # M6 fix: open ONE PG connection in autocommit=False and pass it
        # to every dispatch call. The whole import runs in a single
        # transaction — on partial failure the caller can ROLLBACK and
        # the operator's PG sees no half-applied state. Previously each
        # _pg_mirror_kv call pulled a fresh connection from the pool
        # and auto-committed, leaving partial rows on failure.
        _import_conn = pg.connect(pg_dsn, connect_timeout=10)
        _import_conn.autocommit = False
        def dispatch(op, args, _c=_import_conn):
            return _pg_mirror_kv(op, args, _conn=_c)
    else:
        _import_conn = None
        dispatch = lambda op, args: True  # noqa: E731 — dry-run stub
        pg_insert_event = lambda *a, **k: True  # noqa: E731

    # Open SQLite read-only (URI mode prevents accidental modifications).
    s_conn = sqlite3.connect(f"file:{sqlite_path}?mode=ro",
                              uri=True, timeout=10)

    total_seen = total_copied = total_err = 0
    plan = _dispatch_plan()
    # M8 fix: short-circuit on _TxAborted so the cascade-of-failures
    # doesn't inflate the error count after the first real failure.
    _tx_poisoned = False
    for table, pg_op, columns, row_to_args in plan:
        if _tx_poisoned:
            print(f"  {table:24} skip   (tx aborted; not attempted)",
                  flush=True)
            continue
        try:
            seen, copied, errs = _copy_table(
                s_conn, table, pg_op, columns, row_to_args,
                dispatch, args.dry_run)
        except _TxAborted as e:
            _tx_poisoned = True
            total_err += 1
            print(f"  {table:24} FAIL  ({e})", flush=True)
            continue
        total_seen += seen
        total_copied += copied
        total_err += errs
        status = "skip" if seen == 0 else ("dry" if args.dry_run else "ok")
        print(f"  {table:24} {status:5}  {seen:>8} rows"
              + (f"  {errs} errors" if errs else ""),
              flush=True)

    # svc_metrics (35-col special case) — also short-circuit on poison.
    if _tx_poisoned:
        print(f"  {'svc_metrics':24} skip   (tx aborted; not attempted)",
              flush=True)
    else:
        seen, copied, errs = _copy_svc_metrics(
            s_conn, dispatch, args.dry_run)
        total_seen += seen
        total_copied += copied
        total_err += errs
        status = "skip" if seen == 0 else ("dry" if args.dry_run else "ok")
        print(f"  {'svc_metrics':24} {status:5}  {seen:>8} rows"
              + (f"  {errs} errors" if errs else ""),
              flush=True)

    # User extension cols: PG's user_create only seeds the 6 base columns.
    # Replay last_login_* + totp_* + sso_source + oidc_sub via the matching
    # mirror ops (user_login_recorded + user_update with field dict).
    try:
        ext_rows = s_conn.execute(
            "SELECT username, last_login_ts, last_login_ip, "
            "totp_secret, totp_enabled, totp_backup_codes, "
            "sso_source, oidc_sub FROM users").fetchall()
    except sqlite3.OperationalError:
        ext_rows = []
    ext_seen = 0
    ext_copied = 0
    ext_err = 0
    if _tx_poisoned:
        ext_rows = []  # M8: skip this whole pass on poisoned tx
    for (uname, ll_ts, ll_ip, ts_sec, ts_en, ts_codes, sso, oidc) in ext_rows:
        ext_seen += 1
        if args.dry_run:
            continue
        try:
            if ll_ts is not None and ll_ip is not None:
                if dispatch("user_login_recorded", (ll_ts, ll_ip, uname)):
                    pass
            fields = {}
            if ts_sec:    fields["totp_secret"]        = ts_sec
            if ts_en:     fields["totp_enabled"]       = ts_en
            if ts_codes:  fields["totp_backup_codes"]  = ts_codes
            if sso:       fields["sso_source"]         = sso
            if oidc:      fields["oidc_sub"]           = oidc
            if fields:
                if dispatch("user_update", (uname, fields)):
                    ext_copied += 1
            elif ll_ts is not None:
                ext_copied += 1
        except Exception as e:
            ext_err += 1
            print(f"  ! users-extension {uname}: "
                  f"{type(e).__name__}: {str(e)[:120]}",
                  file=sys.stderr, flush=True)
            # M8: poison + bail out of the ext loop too.
            _tx_poisoned = True
            break
    if ext_seen:
        status = "dry" if args.dry_run else "ok"
        print(f"  {'users (last_login/totp)':24} {status:5}  "
              f"{ext_seen:>8} rows"
              + (f"  {ext_err} errors" if ext_err else ""),
              flush=True)
        total_seen += ext_seen
        total_copied += ext_copied
        total_err += ext_err

    # events (last — usually the largest)
    if _tx_poisoned:
        print(f"  {'events':24} skip   (tx aborted; not attempted)",
              flush=True)
    elif not args.skip_events:
        seen, copied, errs = _copy_events(s_conn, pg_insert_event,
                                            args.dry_run)
        total_seen += seen
        total_copied += copied
        total_err += errs
        status = "skip" if seen == 0 else ("dry" if args.dry_run else "ok")
        print(f"  {'events':24} {status:5}  {seen:>8} rows"
              + (f"  {errs} errors" if errs else ""),
              flush=True)
    else:
        print(f"  {'events':24} skip   (--skip-events)", flush=True)

    s_conn.close()

    # M6 fix: commit or rollback the import transaction. Errors during
    # individual row writes were already counted in `total_err`; if any
    # occurred, ROLLBACK so the operator's PG is unchanged. Otherwise
    # COMMIT — make the whole import atomic.
    if _import_conn is not None:
        try:
            if total_err:
                _import_conn.rollback()
                print(f"[db.import] ROLLED BACK ({total_err} errors) — "
                      f"PG unchanged. Re-run after fixing the source.",
                      flush=True)
            else:
                _import_conn.commit()
        except Exception as _e:
            print(f"[db.import] ERR: commit/rollback failed: "
                  f"{type(_e).__name__}: {str(_e)[:200]}",
                  file=sys.stderr)
            total_err = max(total_err, 1)
        finally:
            try:
                _import_conn.close()
            except Exception:
                pass  # nosec B110

    print(f"[db.import] done: seen={total_seen} copied={total_copied} "
          f"errors={total_err}", flush=True)
    return 4 if total_err else 0


if __name__ == "__main__":
    sys.exit(main())
