"""
db.export — one-shot Postgres → SQLite backup tool.

Reads every operator-state row from $POSTGRES_DSN and writes it into a
local SQLite file using the same schema as the running gateway. The output
SQLite file is the same on-disk format the legacy SQLite-only mode reads,
so it doubles as both a backup and a downgrade artifact.

Usage:
    python -m db.export                          # writes to $DB_PATH
    python -m db.export /path/to/backup.db       # override target
    python -m db.export --schema-only            # init schema, no rows

Exit codes:
    0  success
    1  CLI / env error
    2  PG unreachable
    3  one or more table copies failed
    4  target SQLite path already has data (use --force to overwrite)

Idempotent on table contents via `INSERT OR REPLACE`. The target SQLite is
opened in WAL mode and committed once at the end so a crash mid-export
leaves the file empty rather than half-populated.
"""
from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys


# M5 fix: validate every table/column identifier that lands in an f-string
# SQL — defence-in-depth even though the values come from a static plan.
_IDENT_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def _ident(name: str) -> str:
    if not isinstance(name, str) or not _IDENT_RE.match(name):
        raise ValueError(
            f"invalid SQL identifier {name!r} — must match {_IDENT_RE.pattern}"
        )
    return name


# L8 fix — _mask_dsn lives in db.cli_helpers so db.export and db.import
# share one implementation. Kept as `_mask_dsn` re-export for stability of
# the existing call sites in this file.
from db.cli_helpers import mask_dsn as _mask_dsn  # noqa: E402, F401


# Same column lists / table order as db.import, but reads from PG and writes
# to SQLite via raw INSERT (no writer-loop / op dispatch on the SQLite side
# — we're seeding a fresh file).
#
# Each entry: (table, columns, sqlite_insert_sql).

def _plan():
    return [
        ("config_kv",
            ["key", "value", "ts"],
            "INSERT OR REPLACE INTO config_kv (key,value,ts) VALUES (?,?,?)"),
        ("secrets_kv",
            ["key", "value", "ts"],
            "INSERT OR REPLACE INTO secrets_kv (key,value,ts) VALUES (?,?,?)"),
        ("admin_ips",
            ["cidr", "added_ts", "note", "source", "description"],
            "INSERT OR REPLACE INTO admin_ips "
            "(cidr,added_ts,note,source,description) VALUES (?,?,?,?,?)"),
        ("users",
            ["username", "password_hash", "role", "status",
             "created_ts", "updated_ts",
             "last_login_ts", "last_login_ip",
             "totp_secret", "totp_enabled", "totp_backup_codes",
             "sso_source", "oidc_sub"],
            "INSERT OR REPLACE INTO users "
            "(username,password_hash,role,status,created_ts,updated_ts,"
            "last_login_ts,last_login_ip,totp_secret,totp_enabled,"
            "totp_backup_codes,sso_source,oidc_sub) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"),
        ("user_sessions",
            ["sid", "username", "ip", "user_agent",
             "created_ts", "last_seen_ts", "expires_ts", "status",
             "revoked_ts", "revoked_by"],
            "INSERT OR REPLACE INTO user_sessions "
            "(sid,username,ip,user_agent,created_ts,last_seen_ts,"
            "expires_ts,status,revoked_ts,revoked_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)"),
        ("bans",
            ["ip", "banned_until", "reason", "ts"],
            "INSERT OR REPLACE INTO bans (ip,banned_until,reason,ts) "
            "VALUES (?,?,?,?)"),
        ("ip_bans",
            ["ip", "banned_until", "reason", "ts"],
            "INSERT OR REPLACE INTO ip_bans (ip,banned_until,reason,ts) "
            "VALUES (?,?,?,?)"),
        ("dlp_patterns",
            ["name", "pattern", "severity", "enabled", "added_ts", "added_by"],
            "INSERT OR REPLACE INTO dlp_patterns "
            "(name,pattern,severity,enabled,added_ts,added_by) "
            "VALUES (?,?,?,?,?,?)"),
        ("siem_alert_rules",
            ["metric", "op", "threshold", "label",
             "enabled", "created_ts", "created_by",
             "last_fired_ts", "cooldown_s"],
            "INSERT OR REPLACE INTO siem_alert_rules "
            "(metric,op,threshold,label,enabled,created_ts,created_by,"
            "last_fired_ts,cooldown_s) VALUES (?,?,?,?,?,?,?,?,?)"),
        ("siem_alert_fired",
            ["rule_id", "ts", "value"],
            "INSERT OR REPLACE INTO siem_alert_fired (rule_id,ts,value) "
            "VALUES (?,?,?)"),
        ("gw_audit",
            ["ts", "action", "gw_id", "actor", "details"],
            "INSERT OR REPLACE INTO gw_audit "
            "(ts,action,gw_id,actor,details) VALUES (?,?,?,?,?)"),
        ("honey_fingerprints",
            ["ts", "track_key", "ip", "ua", "ja4", "asn", "path", "reason"],
            "INSERT OR REPLACE INTO honey_fingerprints "
            "(ts,track_key,ip,ua,ja4,asn,path,reason) VALUES (?,?,?,?,?,?,?,?)"),
        ("gw_registry",
            ["gw_id", "domain", "region", "environment", "status",
             "can_distribute", "public_key", "private_key",
             "key_created_ts", "key_rotated_ts", "last_seen_ts",
             "created_ts", "updated_ts", "is_local"],
            "INSERT OR REPLACE INTO gw_registry "
            "(gw_id,domain,region,environment,status,can_distribute,"
            "public_key,private_key,key_created_ts,key_rotated_ts,"
            "last_seen_ts,created_ts,updated_ts,is_local) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"),
        ("abuseipdb_cache",
            ["ip", "score", "country", "ts"],
            "INSERT OR REPLACE INTO abuseipdb_cache (ip,score,country,ts) "
            "VALUES (?,?,?,?)"),
        ("audit_events",
            ["ts", "event_type", "actor", "target", "ip",
             "detail", "session_id", "severity"],
            "INSERT INTO audit_events "
            "(ts,event_type,actor,target,ip,detail,session_id,severity) "
            "VALUES (?,?,?,?,?,?,?,?)"),
        ("clients",
            ["ip", "first_seen", "last_seen", "request_count",
             "allowed_count", "blocked_count", "banned_until_epoch",
             "last_user_agent", "last_path", "last_vhost",
             "blocks_by_reason"],
            "INSERT OR REPLACE INTO clients "
            "(ip,first_seen,last_seen,request_count,allowed_count,"
            "blocked_count,banned_until_epoch,last_user_agent,last_path,"
            "last_vhost,blocks_by_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?)"),
        ("metrics_kv",
            ["key", "val"],
            "INSERT OR REPLACE INTO metrics_kv (key,val) VALUES (?,?)"),
        ("timeline",
            ["bucket_minute", "total", "allowed", "blocked",
             "missed", "by_reason"],
            "INSERT OR REPLACE INTO timeline "
            "(bucket_minute,total,allowed,blocked,missed,by_reason) "
            "VALUES (?,?,?,?,?,?)"),
        # L4 fix: 3 tables previously omitted from the export plan.
        # Without them, a PG → SQLite snapshot loses mesh-distribution
        # pairings, pending sync-confirmations, and per-gateway signal
        # activation overrides on downgrade.
        ("gw_distribution",
            ["source_gw_id", "target_gw_id", "ts"],
            "INSERT OR REPLACE INTO gw_distribution "
            "(source_gw_id, target_gw_id, ts) VALUES (?,?,?)"),
        ("gw_sync_pending",
            ["id", "received_ts", "source_gw_id", "key_name", "value",
             "status", "confirmed_ts"],
            "INSERT OR REPLACE INTO gw_sync_pending "
            "(id, received_ts, source_gw_id, key_name, value, "
            "status, confirmed_ts) VALUES (?,?,?,?,?,?,?)"),
        ("signal_orders",
            ["gw_id", "signal", "activation_order",
             "updated_ts", "updated_by"],
            "INSERT OR REPLACE INTO signal_orders "
            "(gw_id, signal, activation_order, updated_ts, updated_by) "
            "VALUES (?,?,?,?,?)"),
    ]


def _svc_metrics_export(pg_cur, s_conn):
    cols = ["ts", "cpu_pct", "load1", "load5", "load15",
            "mem_used", "mem_total", "mem_avail", "mem_pct",
            "swap_used", "swap_total", "cg_used", "cg_limit", "cg_pct",
            "disk_used", "disk_total", "disk_avail", "disk_pct",
            "procs", "open_fds", "net_rx_bps", "net_tx_bps",
            "db_db", "db_wal", "db_shm", "db_total",
            "pg_db_bytes", "pg_events_rows",
            "identities_count", "total_requests",
            "pg_index_bytes", "pg_active_conns", "pg_idle_conns",
            "pg_cache_hit_pct", "pg_tx_total"]
    cols_sql = ", ".join(_ident(c) for c in cols)  # M5 fix
    try:
        pg_cur.execute(
            f"SELECT {cols_sql} FROM svc_metrics")  # noqa: S608 — identifiers validated
        rows = pg_cur.fetchall()
    except Exception as e:
        return 0, 0, 1, str(e)
    if not rows:
        return 0, 0, 0, ""
    qs = ",".join("?" * len(cols))
    insert_sql = (f"INSERT OR REPLACE INTO svc_metrics ({cols_sql}) "
                   f"VALUES ({qs})")  # nosec B608
    seen = len(rows)
    copied = 0
    err = 0
    for row in rows:
        try:
            s_conn.execute(insert_sql, tuple(row))
            copied += 1
        except Exception:
            err += 1
    return seen, copied, err, ""


def _events_export(pg_cur, s_conn):
    """events has many optional columns on PG (track_key/sid/fp/ja4/...) that
    don't all live in SQLite. Copy only the columns SQLite has."""
    try:
        pg_cur.execute(
            "SELECT EXTRACT(EPOCH FROM ts), ip, ua, path, method, "
            "status, reason, vhost FROM events")
        rows = pg_cur.fetchall()
    except Exception as e:
        return 0, 0, 1, str(e)
    if not rows:
        return 0, 0, 0, ""
    insert_sql = ("INSERT INTO events "
                  "(ts,ip,ua,path,method,status,reason,vhost) "
                  "VALUES (?,?,?,?,?,?,?,?)")
    seen = len(rows)
    copied = 0
    err = 0
    err_msg = ""
    for row in rows:
        # PG's EXTRACT(EPOCH FROM ts) returns Decimal; SQLite refuses
        # Decimal — cast the first column to float here.
        normalised = (float(row[0]),) + tuple(row[1:])
        try:
            s_conn.execute(insert_sql, normalised)
            copied += 1
        except Exception as e:
            err += 1
            if not err_msg:  # capture first error for the summary
                err_msg = f"{type(e).__name__}: {str(e)[:80]}"
    return seen, copied, err, err_msg


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m db.export",
                                      description=__doc__)
    parser.add_argument("sqlite_path", nargs="?",
                        help="Target SQLite file (defaults to $DB_PATH)")
    parser.add_argument("--schema-only", action="store_true",
                        help="Create schema only; copy zero rows")
    parser.add_argument("--skip-events", action="store_true",
                        help="Skip the (potentially large) events table")
    parser.add_argument("--force", action="store_true",
                        help="Overwrite target file if it already exists "
                             "(existing file is renamed to "
                             "<path>.pre-export-<ts>.bak)")
    parser.add_argument("--i-know-what-im-doing", action="store_true",
                        dest="i_know_what_im_doing",
                        help="Required IN ADDITION to --force when the "
                             "target equals the live $DB_PATH. Without "
                             "this, --force refuses to clobber the running "
                             "gateway's DB.")
    args = parser.parse_args(argv)

    pg_dsn = os.environ.get("POSTGRES_DSN", "").strip()
    if not pg_dsn:
        print("ERR: POSTGRES_DSN not set", file=sys.stderr)
        return 1

    if args.sqlite_path:
        sqlite_path = args.sqlite_path
    else:
        sqlite_path = os.environ.get("DB_PATH", "")
        if not sqlite_path:
            print("ERR: DB_PATH not set and no positional path given",
                  file=sys.stderr)
            return 1

    if os.path.exists(sqlite_path) and not args.force:
        print(f"ERR: target {sqlite_path} already exists; use --force "
              "to overwrite", file=sys.stderr)
        return 4

    # 1.9.0 (F7) — refuse to clobber the gateway's LIVE DB unless the operator
    # explicitly opts in with --i-know-what-im-doing. The previous --force
    # could silently delete users/config/secrets if the operator pointed
    # `db.export` at the running gateway's $DB_PATH.
    if args.force and os.path.exists(sqlite_path):
        _live_path = os.path.abspath(os.environ.get("DB_PATH", "") or "")
        _target_path = os.path.abspath(sqlite_path)
        if _live_path and _live_path == _target_path:
            if not getattr(args, "i_know_what_im_doing", False):
                print(
                    f"ERR: --force on the live gateway DB ({sqlite_path}) "
                    "would destroy operator state if the gateway is running. "
                    "Stop the gateway first, OR pass --i-know-what-im-doing "
                    "to override. (Safer: --force against a different path.)",
                    file=sys.stderr,
                )
                return 4
        # Rename existing to a dated backup so --force is recoverable.
        try:
            import time as _tx
            _bak = f"{sqlite_path}.pre-export-{int(_tx.time())}.bak"
            os.replace(sqlite_path, _bak)
            print(f"[db.export] renamed existing target → {_bak}", flush=True)
        except Exception as _re:
            print(f"WARN: could not back up existing target: "
                  f"{type(_re).__name__}: {_re}", file=sys.stderr)

    print(f"[db.export] source: {_mask_dsn(pg_dsn)}", flush=True)
    print(f"[db.export] target: {sqlite_path}", flush=True)

    # Connect to PG.
    try:
        from db.postgres import _postgres_load_module
        pg = _postgres_load_module()
        if pg is None:
            print("ERR: psycopg not installed", file=sys.stderr)
            return 2
        pg_conn = pg.connect(pg_dsn, connect_timeout=5)
    except Exception as e:
        print(f"ERR: PG connect failed: {type(e).__name__}: {str(e)[:200]}",
              file=sys.stderr)
        return 2

    # A2 fix: initialise the target SQLite schema by invoking db_init
    # with an explicit path argument — no global env mutation, no
    # importlib.reload. This makes db.export safe to invoke from a
    # running gateway process (previously the reload mutated DB_PATH
    # globally and could redirect a live writer at the export target).
    from db.sqlite import db_init as _db_init
    _db_init(db_path_override=sqlite_path)

    s_conn = sqlite3.connect(sqlite_path, timeout=10)
    s_conn.execute("PRAGMA foreign_keys=OFF")  # FK ordering handled by _plan()

    total_seen = total_copied = total_err = 0
    pg_cur = pg_conn.cursor()

    if not args.schema_only:
        for table, cols, insert_sql in _plan():
            # M5 fix: validate identifiers.
            tbl = _ident(table)
            cols_sql = ", ".join(_ident(c) for c in cols)
            try:
                pg_cur.execute(
                    f"SELECT {cols_sql} FROM {tbl}")  # noqa: S608 — identifiers validated
                rows = pg_cur.fetchall()
            except Exception as e:
                print(f"  {table:24} ERR    {type(e).__name__}: "
                      f"{str(e)[:80]}", flush=True)
                total_err += 1
                continue
            seen = len(rows)
            if seen == 0:
                print(f"  {table:24} skip          0 rows", flush=True)
                continue
            copied = 0
            errs = 0
            for row in rows:
                try:
                    s_conn.execute(insert_sql, tuple(row))
                    copied += 1
                except Exception:
                    errs += 1
            total_seen += seen
            total_copied += copied
            total_err += errs
            print(f"  {table:24} ok     {seen:>8} rows"
                  + (f"  {errs} errors" if errs else ""), flush=True)

        # svc_metrics (35-col)
        seen, copied, errs, errmsg = _svc_metrics_export(pg_cur, s_conn)
        total_seen += seen; total_copied += copied; total_err += errs
        status = "skip" if seen == 0 else "ok"
        suffix = (f"  {errs} errors" if errs else
                  f"  ({errmsg[:60]})" if errmsg else "")
        print(f"  {'svc_metrics':24} {status:5}  {seen:>8} rows{suffix}",
              flush=True)

        # events (last, optional)
        if not args.skip_events:
            seen, copied, errs, errmsg = _events_export(pg_cur, s_conn)
            total_seen += seen; total_copied += copied; total_err += errs
            status = "skip" if seen == 0 else "ok"
            suffix = (f"  {errs} errors" if errs else
                      f"  ({errmsg[:60]})" if errmsg else "")
            print(f"  {'events':24} {status:5}  {seen:>8} rows{suffix}",
                  flush=True)
        else:
            print(f"  {'events':24} skip   (--skip-events)", flush=True)

    s_conn.commit()
    s_conn.close()
    pg_conn.close()

    print(f"[db.export] done: seen={total_seen} copied={total_copied} "
          f"errors={total_err}", flush=True)
    return 3 if total_err else 0


if __name__ == "__main__":
    sys.exit(main())
