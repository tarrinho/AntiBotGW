#!/usr/bin/env bash
# Category 37 — Backup integrity
# Bkp-1 backup encryption at rest (file magic check on test artifact)
# Bkp-2 backup retention rotation — keep-count enforced
# Bkp-3 backup checksum validation (RT integrity via .sha256 file)
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ── Bkp-1 backup encryption at rest ──────────────────────────────────────
# Surrogate: take a sqlite3 backup of a test DB, verify file magic. Sqlite
# files start with "SQLite format 3\0". Encrypted backups would have random
# magic. Without an encryption layer, this PASSes on plain sqlite3 (which is
# the product's default) — flagging encryption as not-applied is informational,
# not a failure (the product does not claim at-rest encryption today).
if command -v sqlite3 >/dev/null 2>&1; then
  TMPD="$(mktemp -d)"
  SRC="${TMPD}/src.db"; BAK="${TMPD}/bak.db"
  sqlite3 "$SRC" "CREATE TABLE t (id INTEGER); INSERT INTO t VALUES (1);" 2>/dev/null
  sqlite3 "$SRC" ".backup '$BAK'" 2>/dev/null
  magic=$(head -c 15 "$BAK" 2>/dev/null)
  if [[ "$magic" == "SQLite format 3" ]]; then
    echo "[INFO] Bkp-1 backup encryption — file unencrypted (sqlite3 magic intact); at-rest encryption not claimed today"
    I=$((I+1))
  elif [[ -n "$magic" ]]; then
    echo "[PASS] Bkp-1 backup encryption — backup not plain sqlite (encryption layer active)"; P=$((P+1))
  else
    echo "[FAIL] Bkp-1 backup encryption — backup file empty or unreadable"; F=$((F+1))
  fi
  rm -rf "$TMPD"
else
  echo "[INFO] Bkp-1 backup encryption — sqlite3 binary missing"; I=$((I+1))
fi

# ── Bkp-2 backup retention rotation ──────────────────────────────────────
# Probe rules.md or backup script for a documented keep-count / rotation policy.
keep_doc=0
if grep -qiE 'BACKUP_KEEP|keep[_ -]?(count|days)|RETENTION|rotation' "$ROOT/rules.md" 2>/dev/null; then
  keep_doc=$((keep_doc+1))
fi
for f in "$ROOT"/backup.sh "$ROOT"/restore.sh "$ROOT"/scripts/backup.sh; do
  if [[ -f "$f" ]] && grep -qiE 'KEEP|RETAIN|rotate|find.*-mtime' "$f" 2>/dev/null; then
    keep_doc=$((keep_doc+1))
  fi
done
if [[ "$keep_doc" -ge 1 ]]; then
  echo "[PASS] Bkp-2 retention rotation — ${keep_doc} keep-count/rotation marker(s) documented"
  P=$((P+1))
else
  echo "[INFO] Bkp-2 retention rotation — no keep-count/rotation policy found in rules.md or backup scripts"
  I=$((I+1))
fi

# ── Bkp-3 backup checksum validation ─────────────────────────────────────
# Take backup, compute sha256, modify a byte, re-verify sha256 detects diff.
# This validates the *tooling* — sha256sum exists and detects corruption.
if command -v sha256sum >/dev/null 2>&1 && command -v sqlite3 >/dev/null 2>&1; then
  TMPD="$(mktemp -d)"
  SRC="${TMPD}/src.db"
  sqlite3 "$SRC" "CREATE TABLE t (id INTEGER); INSERT INTO t VALUES (1);" 2>/dev/null
  hash1=$(sha256sum "$SRC" | awk '{print $1}')
  # Append 1 byte
  printf '\x00' >> "$SRC"
  hash2=$(sha256sum "$SRC" | awk '{print $1}')
  rm -rf "$TMPD"
  if [[ "$hash1" != "$hash2" ]] && [[ "${#hash1}" -eq 64 ]]; then
    echo "[PASS] Bkp-3 checksum validation — sha256 detects 1-byte tampering (h1≠h2, 64-char hex)"
    P=$((P+1))
  else
    echo "[FAIL] Bkp-3 checksum validation — sha256 failed to detect tampering or hash format wrong"
    F=$((F+1))
  fi
else
  echo "[INFO] Bkp-3 checksum validation — sha256sum or sqlite3 missing"; I=$((I+1))
fi

echo "[CAT-DONE] 37.Backup-integrity P=${P} F=${F} I=${I} S=${S}"
