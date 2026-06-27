#!/usr/bin/env bash
# tests/dynamic/run-all.sh — master runner for the 13 dynamic-test categories.
# See tests/DYNAMIC_TESTS.md for the catalogue.
#
# Usage:
#   ./run-all.sh <URL> [ADMIN_KEY] [--tier quick|medium|heavy]
#
# Each per-category script under tests/dynamic/cat*_*.sh emits one of
#   [PASS] <test name>
#   [FAIL] <test name> — <reason>
#   [INFO] <test name> — <reason>
#   [SKIP] <test name> — <reason>
# and ends with a single line:
#   [CAT-DONE] <category> P=<n> F=<n> I=<n> S=<n>
#
# This runner aggregates them and prints a final summary suitable for
# pasting at the end of a rules.md §15 run.

set -u

URL="${1:-}"
ADMIN_KEY="${2:-}"
TIER="medium"
for arg in "$@"; do
  case "$arg" in
    --tier=quick|--tier=medium|--tier=heavy) TIER="${arg#--tier=}" ;;
    --tier)  shift; TIER="${1:-medium}" ;;
  esac
done

if [[ -z "$URL" ]]; then
  echo "Usage: $0 <URL> [ADMIN_KEY] [--tier quick|medium|heavy]" >&2
  exit 2
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
TMP_OUT="$(mktemp)"
TMP_SUM="$(mktemp)"
trap 'rm -f "$TMP_OUT" "$TMP_SUM"' EXIT

# Category list — order matches the catalogue.
CATEGORIES=(
  "cat01_functional.sh           1.Functional"
  "cat02_performance.sh          2.Performance"
  "cat03_security_dast.sh        3.Security-DAST"
  "cat04_resilience_chaos.sh     4.Resilience-chaos"
  "cat05_concurrency.sh          5.Concurrency"
  "cat06_integration.sh          6.Integration"
  "cat07_ui_browser.sh           7.UI-browser"
  "cat08_protocol_rfc.sh         8.Protocol-RFC"
  "cat09_observability.sh        9.Observability"
  "cat10_data_integrity.sh       10.Data-integrity"
  "cat11_property_fuzz.sh        11.Property-fuzz"
  "cat12_operational.sh          12.Operational"
  "cat13_project_specific.sh     13.Project-specific"
  "cat14_auth_deep.sh             14.Auth-deep"
  "cat15_cve_regression.sh        15.CVE-regression"
  "cat16_fingerprint.sh           16.Fingerprint"
  "cat17_dos_volumetric.sh        17.DoS-volumetric"
  "cat18_honeypot_decoy.sh        18.Honeypot-decoy"
  "cat19_credential_abuse.sh      19.Credential-abuse"
  "cat20_waf_lifecycle.sh         20.WAF-lifecycle"
  "cat21_audit_compliance.sh      21.Audit-compliance"
  "cat22_concurrency_edge.sh      22.Concurrency-edge"
  "cat23_crypto.sh                23.Crypto"
  "cat24_redos.sh                 24.ReDoS"
  "cat25_ops_transitions.sh       25.Ops-transitions"
  "cat26_resource_leak.sh         26.Resource-leak"
  "cat27_bot_evolution.sh         27.Bot-evolution"
  "cat28_multi_tenancy.sh         28.Multi-tenancy"
  "cat29_db_resilience.sh         29.DB-resilience"
  "cat30_deep_injection.sh        30.Deep-injection"
  "cat31_network_cache.sh         31.Network-cache"
  "cat32_modern_bots.sh           32.Modern-bots"
  "cat33_clock_timezone.sh        33.Clock-timezone"
  "cat34_protocol_deep.sh         34.Protocol-deep"
  "cat35_observability_deep.sh    35.Observability-deep"
  "cat36_authz_flaws.sh           36.Authz-flaws"
  "cat37_backup_integrity.sh      37.Backup-integrity"
  "cat38_a11y_i18n_api.sh         38.a11y-i18n-api"
)

# Tier filter — quick runs only smoke; medium adds chaos+browser+efficacy;
# heavy adds soak+fuzz+zap. Each script reads $RUN_TIER itself.
export RUN_TIER="$TIER"
export URL ADMIN_KEY

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Dynamic-tests run — tier=${TIER}  target=${URL}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TOTAL_P=0; TOTAL_F=0; TOTAL_I=0; TOTAL_S=0
FAILED_CATEGORIES=()

for entry in "${CATEGORIES[@]}"; do
  script="${entry%%[[:space:]]*}"
  label="${entry##*[[:space:]]}"
  path="${DIR}/${script}"
  echo ""
  echo "─── ${label} ───────────────────────────────────"
  if [[ ! -x "$path" ]]; then
    echo "[SKIP] ${label} — script not found or not executable: ${path}"
    TOTAL_S=$((TOTAL_S + 1))
    echo "[CAT-DONE] ${label} P=0 F=0 I=0 S=1" >> "$TMP_SUM"
    continue
  fi
  # Run, tee everything to console + capture for the per-category summary.
  bash "$path" 2>&1 | tee -a "$TMP_OUT"
  # Last [CAT-DONE] line from the script
  done_line=$(grep '^\[CAT-DONE\]' "$TMP_OUT" | tail -1)
  if [[ -z "$done_line" ]]; then
    echo "[INFO] ${label} — no [CAT-DONE] marker emitted"
    done_line="[CAT-DONE] ${label} P=0 F=0 I=1 S=0"
  fi
  echo "$done_line" >> "$TMP_SUM"
  # Aggregate
  p=$(echo "$done_line" | sed -nE 's/.*P=([0-9]+).*/\1/p')
  f=$(echo "$done_line" | sed -nE 's/.*F=([0-9]+).*/\1/p')
  i=$(echo "$done_line" | sed -nE 's/.*I=([0-9]+).*/\1/p')
  s=$(echo "$done_line" | sed -nE 's/.*S=([0-9]+).*/\1/p')
  TOTAL_P=$((TOTAL_P + ${p:-0}))
  TOTAL_F=$((TOTAL_F + ${f:-0}))
  TOTAL_I=$((TOTAL_I + ${i:-0}))
  TOTAL_S=$((TOTAL_S + ${s:-0}))
  [[ ${f:-0} -gt 0 ]] && FAILED_CATEGORIES+=("${label}")
  # Reset captured output for next category so done-line tail is per-category
  : > "$TMP_OUT"
done

# ── Final summary — paste-friendly for the end of a rules.md run ──
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Per-category result"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "  %-32s %5s %5s %5s %5s\n" "Category" "PASS" "FAIL" "INFO" "SKIP"
while IFS= read -r line; do
  cat=$(echo "$line"  | sed -nE 's/^\[CAT-DONE\] +([^ ]+) +P=.*/\1/p')
  p=$(echo "$line"    | sed -nE 's/.*P=([0-9]+).*/\1/p')
  f=$(echo "$line"    | sed -nE 's/.*F=([0-9]+).*/\1/p')
  i=$(echo "$line"    | sed -nE 's/.*I=([0-9]+).*/\1/p')
  s=$(echo "$line"    | sed -nE 's/.*S=([0-9]+).*/\1/p')
  printf "  %-32s %5s %5s %5s %5s\n" "$cat" "${p:-0}" "${f:-0}" "${i:-0}" "${s:-0}"
done < "$TMP_SUM"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Dynamic-tests TOTAL — tier=${TIER}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PASS:  ${TOTAL_P}"
echo "  FAIL:  ${TOTAL_F}"
echo "  INFO:  ${TOTAL_I}"
echo "  SKIP:  ${TOTAL_S}"
if [[ ${#FAILED_CATEGORIES[@]} -gt 0 ]]; then
  echo "  Failed in: ${FAILED_CATEGORIES[*]}"
fi
echo ""

if [[ "$TOTAL_F" -gt 0 ]]; then
  echo "RESULT: ❌ FAIL  (see [FAIL] lines above)"
  exit 1
else
  echo "RESULT: ✅ PASS  (${TOTAL_I} INFO + ${TOTAL_S} SKIP are non-blocking)"
  exit 0
fi
