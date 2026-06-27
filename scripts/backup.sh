#!/usr/bin/env bash
# scripts/backup.sh — online-consistent backup of the AntiBotWaf_GW data store.
#
# Backs up whichever backend is active:
#   • SQLite  — uses `sqlite3 .backup` (safe against a live writer; WAL-aware)
#   • Postgres — uses `pg_dump` when POSTGRES_DSN is set
#
# Usage:
#   ./scripts/backup.sh [OUT_DIR]
#
# Env:
#   DB_PATH        SQLite database path (default: /data/antibot.db)
#   POSTGRES_DSN   if set, a Postgres dump is taken instead of / in addition
#   BACKUP_DIR     default output root (default: ./backups)
#
# Restore:
#   SQLite : sqlite3 <new.db> ".restore '<backup.db>'"   (or just copy it back)
#   Postgres: psql "$POSTGRES_DSN" < <backup.sql>
set -euo pipefail

DB_PATH="${DB_PATH:-/data/antibot.db}"
OUT_ROOT="${1:-${BACKUP_DIR:-$(cd "$(dirname "$0")/.." && pwd)/backups}}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT_ROOT}/${TS}"

# Disk pre-check — refuse to run with < 1 GB free (project standard).
free_gb=$(df -BG "$OUT_ROOT" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$4); print $4}' \
          || df -BG . | awk 'NR==2{gsub(/G/,"",$4); print $4}')
if [[ -n "${free_gb:-}" ]] && [[ "${free_gb}" -lt 1 ]]; then
  echo "ALERT: insufficient disk space (${free_gb} GB free, need >= 1 GB). Aborting." >&2
  exit 1
fi

mkdir -p "$OUT"
took_any=0

# ── SQLite ──────────────────────────────────────────────────────────────────
if [[ -f "$DB_PATH" ]]; then
  dst="${OUT}/antibot-sqlite.db"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB_PATH" ".backup '${dst}'"
  else
    # Fallback: plain copy (less safe under a live writer, but better than nothing)
    cp -p "$DB_PATH" "$dst"
  fi
  # Verify the backup opens and carries the schema.
  if command -v sqlite3 >/dev/null 2>&1; then
    tables=$(sqlite3 "$dst" "SELECT count(*) FROM sqlite_master WHERE type='table';" 2>/dev/null || echo 0)
    echo "[ok] SQLite backup → ${dst} (${tables} tables, $(wc -c <"$dst") bytes)"
    [[ "${tables:-0}" -ge 1 ]] || { echo "ERROR: SQLite backup has no tables" >&2; exit 2; }
  else
    echo "[ok] SQLite copied → ${dst} ($(wc -c <"$dst") bytes; sqlite3 absent, integrity unchecked)"
  fi
  took_any=1
fi

# ── Postgres ──────────────────────────────────────────────────────────────────
if [[ -n "${POSTGRES_DSN:-}" ]]; then
  dst="${OUT}/antibot-postgres.sql"
  if command -v pg_dump >/dev/null 2>&1; then
    pg_dump "$POSTGRES_DSN" > "$dst"
    echo "[ok] Postgres dump → ${dst} ($(wc -c <"$dst") bytes)"
    took_any=1
  else
    echo "WARN: POSTGRES_DSN set but pg_dump not installed — skipping PG dump" >&2
  fi
fi

if [[ "$took_any" -eq 0 ]]; then
  echo "ERROR: nothing backed up — DB_PATH '${DB_PATH}' not found and POSTGRES_DSN unset." >&2
  exit 3
fi

echo "Backup complete: ${OUT}"
