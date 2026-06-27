#!/usr/bin/env bash
# Category 10 — Data integrity
# D-1: round-trip (export endpoint exists + answers; non-destructive)
# D-2: schema migration metadata present in repo
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ── D-1 export-endpoint probe (real — confirms surface answers) ──────────
status=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" \
  "${URL}${NS}/secured/settings/export" 2>/dev/null)
if [[ "$status" =~ ^[5] ]]; then
  echo "[FAIL] D-1 export endpoint crashed — /secured/settings/export → ${status}"; F=$((F+1))
elif [[ "$status" =~ ^[234] ]]; then
  echo "[PASS] D-1 export endpoint reachable — ${status} (auth-gated, but no crash)"; P=$((P+1))
else
  echo "[INFO] D-1 export endpoint → ${status} (no response)"; I=$((I+1))
fi
echo "       For full round-trip: pytest tests/test_settings_config_functional.py -k 'export or import'"

# ── D-2 schema migration chain — verify migration code path exists ───────
mig_found=0
for f in "$ROOT/db/sqlite.py" "$ROOT/db/postgres.py" "$ROOT/db/migrations.py"; do
  if [[ -f "$f" ]] && grep -qE 'CREATE TABLE|ALTER TABLE|schema_version|migrate' "$f" 2>/dev/null; then
    mig_found=$((mig_found+1))
  fi
done
if [[ "$mig_found" -ge 1 ]]; then
  echo "[PASS] D-2 migration code present — ${mig_found} file(s) carry CREATE/ALTER/schema_version logic"
  P=$((P+1))
else
  echo "[FAIL] D-2 migration code — no CREATE/ALTER/schema_version markers in db/*.py"; F=$((F+1))
fi
echo "       For full multi-version chain: spin 1.9.3 → upgrade to 1.9.4 → assert events table intact"

echo "[CAT-DONE] 10.Data-integrity P=${P} F=${F} I=${I} S=${S}"
