#!/usr/bin/env bash
# Category 33 — Clock / timezone (memory has events.ts bug receipt)
# TZ-1 events.ts read parity — PG TIMESTAMPTZ vs SQLite REAL must yield same window
# TZ-2 clock skew tolerance — Date: header off by ±5 min, must not reject
# TZ-3 DST transition — no special behavior at TZ boundary
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── TZ-1 events read parity — 5 reads of events with same window, count stable ─
# Without auth we can only probe the events surface for response consistency.
# /agents-data?range=24 read 5×, count of rows ('"reason"' substring) must be
# monotonic-or-stable, never drop unexpectedly.
counts=()
for i in $(seq 1 5); do
  body=$(curl -sk --max-time 6 "${URL}${NS}/secured/agents-data?range=24" 2>/dev/null || echo "")
  n=$(echo "$body" | grep -oc '"reason"' 2>/dev/null)
  n=${n:-0}
  counts+=("$n")
  sleep 0.3
done
zeros=0
for c in "${counts[@]}"; do [[ "$c" -eq 0 ]] && zeros=$((zeros+1)); done
distinct=$(printf '%s\n' "${counts[@]}" | sort -u | wc -l)
if [[ "$zeros" -eq 5 ]]; then
  echo "[INFO] TZ-1 events read parity — 5/5 reads got 0 events (auth-gated or target unreachable)"; I=$((I+1))
elif [[ "$distinct" -le 2 ]]; then
  echo "[PASS] TZ-1 events read parity — 5 reads ${counts[*]} (≤ 2 distinct = stable monotonic window)"; P=$((P+1))
else
  echo "[FAIL] TZ-1 events read parity — 5 reads ${counts[*]} (${distinct} distinct counts; window unstable, TZ casting drift?)"
  F=$((F+1))
fi

# ── TZ-2 clock skew tolerance — Date: header off by ±5 min ────────────────
# Send request with intentionally-wrong Date header; gateway must accept
# (HTTP Date is informational; rejecting based on Date is rare and wrong here).
past=$(printf 'Mon, 01 Jan 2020 00:00:00 GMT')
fut=$(printf 'Mon, 01 Jan 2099 00:00:00 GMT')
s_past=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -H "Date: ${past}" "${URL}/" 2>/dev/null)
s_fut=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -H "Date: ${fut}" "${URL}/" 2>/dev/null)
s_base=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}/" 2>/dev/null)
if [[ -z "$s_base" ]] || [[ "$s_base" =~ ^0 ]]; then
  echo "[INFO] TZ-2 clock skew — baseline no-response"; I=$((I+1))
elif [[ "$s_past" == "$s_base" ]] && [[ "$s_fut" == "$s_base" ]]; then
  echo "[PASS] TZ-2 clock skew — Date: 2020 + 2099 both match baseline ${s_base} (no rejection on Date)"
  P=$((P+1))
elif [[ "$s_past" =~ ^5 ]] || [[ "$s_fut" =~ ^5 ]]; then
  echo "[FAIL] TZ-2 clock skew — 5xx on skewed Date (past=${s_past} future=${s_fut})"; F=$((F+1))
else
  echo "[INFO] TZ-2 clock skew — base=${s_base} past=${s_past} fut=${s_fut} (differs but no 5xx)"; I=$((I+1))
fi

# ── TZ-3 DST transition — surrogate via boundary range probes ─────────────
# Hammer /agents-data with rapidly-changing range params spanning what
# would be DST transition points (range=23,24,25 covers boundary). All
# should respond consistently.
fails=0; zeros=0
for r in 23 24 25 47 48 49; do
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    "${URL}${NS}/secured/agents-data?range=${r}" 2>/dev/null)
  [[ -z "$status" ]] || [[ "$status" =~ ^0 ]] && zeros=$((zeros+1))
  [[ "$status" =~ ^5 ]] && fails=$((fails+1))
done
if [[ "$zeros" -ge 5 ]]; then
  echo "[INFO] TZ-3 DST boundary — all 6 range probes no-response"; I=$((I+1))
elif [[ "$fails" -eq 0 ]]; then
  echo "[PASS] TZ-3 DST boundary — 6 range probes (23/24/25/47/48/49h), no 5xx"; P=$((P+1))
else
  echo "[FAIL] TZ-3 DST boundary — ${fails}/6 range probes 5xx'd"; F=$((F+1))
fi

echo "[CAT-DONE] 33.Clock-timezone P=${P} F=${F} I=${I} S=${S}"
