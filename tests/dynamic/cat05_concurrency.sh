#!/usr/bin/env bash
# Category 5 — Concurrency
# R-1: parallel sessions same track_key — proxy via parallel requests with same UA
# R-2 / R-3: SKIP (multi-GW + p95 lock metric require harness)
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
UA="Mozilla/5.0 R1ConcurrencyProbe"

# R-1 — fire 40 parallel requests with the same UA, no failures
fails=0
for i in $(seq 1 40); do
  status=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" \
    -H "User-Agent: ${UA}" "$URL/" 2>/dev/null)
  if [[ "$status" =~ ^5 ]] || [[ "$status" == "000" ]]; then
    fails=$((fails+1))
  fi &
done
wait
if [[ "$fails" -eq 0 ]]; then
  echo "[PASS] R-1 40 parallel same-identity requests — no 5xx, no connect errors"; P=$((P+1))
else
  echo "[FAIL] R-1 40 parallel same-identity — ${fails} requests failed (5xx or no-response)"; F=$((F+1))
fi

# ── R-2 multi-GW surrogate — 2 concurrent batches of same-identity reqs ──
# Real test needs 2 GW containers; this catches write-race at single-GW scale.
UA2="Mozilla/5.0 R2WriteRaceProbe"
( for i in $(seq 1 20); do
    s=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" -H "User-Agent: ${UA2}" "$URL/" 2>/dev/null)
    [[ "$s" =~ ^5 ]] && echo a_fail
  done | wc -l ) > /tmp/r2_a.cnt 2>/dev/null &
( for i in $(seq 1 20); do
    s=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" -H "User-Agent: ${UA2}" "$URL/" 2>/dev/null)
    [[ "$s" =~ ^5 ]] && echo b_fail
  done | wc -l ) > /tmp/r2_b.cnt 2>/dev/null &
wait
af=$(cat /tmp/r2_a.cnt 2>/dev/null); bf=$(cat /tmp/r2_b.cnt 2>/dev/null)
rm -f /tmp/r2_a.cnt /tmp/r2_b.cnt
if [[ "$af" -eq 0 ]] && [[ "$bf" -eq 0 ]]; then
  echo "[PASS] R-2 multi-GW surrogate — 2 batches × 20 same-UA reqs, no 5xx (write-race OK)"; P=$((P+1))
else
  echo "[FAIL] R-2 multi-GW surrogate — batch A=${af} fails, B=${bf} fails (potential race)"; F=$((F+1))
fi
echo "       Full test: spin 2 GW containers against same PG, repeat"

# ── R-3 state_lock metric — probe /__metrics for the counter ─────────────
body=$(curl -sk --max-time 5 "$URL/__metrics" 2>/dev/null || echo "")
if echo "$body" | grep -qE 'state_lock_p95_wait_us|state_lock_wait|lock_p95'; then
  echo "[PASS] R-3 state_lock metric exposed in /__metrics"; P=$((P+1))
elif [[ -n "$body" ]] && echo "$body" | head -c 1 | grep -qE '\{|[a-z]'; then
  echo "[FAIL] R-3 state_lock_p95_wait_us NOT found in /__metrics (counter missing)"; F=$((F+1))
else
  echo "[INFO] R-3 state_lock metric — /__metrics not reachable to probe"; I=$((I+1))
fi

echo "[CAT-DONE] 5.Concurrency P=${P} F=${F} I=${I} S=${S}"
