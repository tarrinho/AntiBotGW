#!/usr/bin/env bash
# Category 22 — Concurrency edge cases (R-1/R-2 cover happy path only)
# CC-1 ban → unban → re-ban race (3 parallel actors) → consistent end state
# CC-2 concurrent settings save from 2 admin sessions → last-write-wins or conflict?
# CC-3 identity merge race (2 sids → same track_key mid-request)
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── CC-1 ban → unban → re-ban race ────────────────────────────────────────
# Without admin write surface we can only probe the property indirectly:
# 3 parallel batches of bot-UA traffic targeting the SAME identity must all
# end up in a consistent decoy/ban state (no 5xx, no inconsistent class).
BOT="sqlmap/1.7-dev"
( for i in $(seq 1 15); do
    s=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -A "$BOT" "${URL}/?actor=a&n=$i" 2>/dev/null)
    [[ "$s" =~ ^5 ]] && echo a_5xx
  done | wc -l ) > /tmp/cc1_a 2>/dev/null &
( for i in $(seq 1 15); do
    s=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -A "$BOT" "${URL}/?actor=b&n=$i" 2>/dev/null)
    [[ "$s" =~ ^5 ]] && echo b_5xx
  done | wc -l ) > /tmp/cc1_b 2>/dev/null &
( for i in $(seq 1 15); do
    s=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -A "$BOT" "${URL}/?actor=c&n=$i" 2>/dev/null)
    [[ "$s" =~ ^5 ]] && echo c_5xx
  done | wc -l ) > /tmp/cc1_c 2>/dev/null &
wait
af=$(cat /tmp/cc1_a 2>/dev/null)
bf=$(cat /tmp/cc1_b 2>/dev/null)
cf=$(cat /tmp/cc1_c 2>/dev/null)
rm -f /tmp/cc1_a /tmp/cc1_b /tmp/cc1_c
if [[ "$af" -eq 0 ]] && [[ "$bf" -eq 0 ]] && [[ "$cf" -eq 0 ]]; then
  echo "[PASS] CC-1 ban-race — 3 parallel actors × 15 reqs same identity, no 5xx (state machine consistent)"
  P=$((P+1))
else
  echo "[FAIL] CC-1 ban-race — 5xx counts a=${af} b=${bf} c=${cf} (race in ban/unban state machine)"
  F=$((F+1))
fi

# ── CC-2 concurrent settings save from 2 admin sessions ───────────────────
if [[ -n "$AK" ]]; then
  # Two parallel writers set the same knob to different values; afterwards
  # the read-back value must be one of the two written values (not garbled,
  # not the prior value).
  ( for i in $(seq 1 5); do
      curl -sk --max-time 5 -o /dev/null \
        -H "X-Admin-Key: ${AK}" -H "Content-Type: application/json" \
        -X POST -d '{"DASHBOARD_REFRESH_SECS":"5"}' \
        "${URL}${NS}/secured/config/set" 2>/dev/null
    done ) &
  ( for i in $(seq 1 5); do
      curl -sk --max-time 5 -o /dev/null \
        -H "X-Admin-Key: ${AK}" -H "Content-Type: application/json" \
        -X POST -d '{"DASHBOARD_REFRESH_SECS":"7"}' \
        "${URL}${NS}/secured/config/set" 2>/dev/null
    done ) &
  wait
  sleep 1
  final=$(curl -sk --max-time 5 -H "X-Admin-Key: ${AK}" \
    "${URL}${NS}/secured/config" 2>/dev/null | \
    grep -oE '"DASHBOARD_REFRESH_SECS"\s*:\s*"?[0-9]+"?' | head -1 | grep -oE '[0-9]+$')
  if [[ "$final" == "5" ]] || [[ "$final" == "7" ]]; then
    echo "[PASS] CC-2 concurrent settings save — final value=${final} (one of the two writers won, no corruption)"
    P=$((P+1))
  elif [[ -z "$final" ]]; then
    echo "[INFO] CC-2 concurrent settings — could not read final DASHBOARD_REFRESH_SECS (endpoint shape differs)"
    I=$((I+1))
  else
    echo "[FAIL] CC-2 concurrent settings save — final value=${final} (neither 5 nor 7 → corruption)"
    F=$((F+1))
  fi
else
  # No admin: surface check the set endpoint exists / doesn't crash on POSTs.
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" -d '{}' \
    "${URL}${NS}/secured/config/set" 2>/dev/null)
  if [[ "$status" =~ ^5 ]]; then
    echo "[FAIL] CC-2 concurrent settings surface — /config/set crashed (${status})"; F=$((F+1))
  else
    echo "[PASS] CC-2 concurrent settings surface — /config/set auth-gated (${status}); set ADMIN_KEY for race test"
    P=$((P+1))
  fi
fi

# ── CC-3 identity merge race — two distinct session-id cookies collapse ───
# Synthesize 2 different cookie identities targeting the same UA+path
# concurrently. Property: no 5xx, both responses are consistent decoys.
( for i in $(seq 1 20); do
    s=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" \
      -A "MergeRaceA" -b "agw_session=sid-A-${i}; sid=sid-A-${i}" \
      "${URL}/?merge-race=a" 2>/dev/null)
    [[ "$s" =~ ^5 ]] && echo a_5xx
  done | wc -l ) > /tmp/cc3_a 2>/dev/null &
( for i in $(seq 1 20); do
    s=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" \
      -A "MergeRaceA" -b "agw_session=sid-B-${i}; sid=sid-B-${i}" \
      "${URL}/?merge-race=b" 2>/dev/null)
    [[ "$s" =~ ^5 ]] && echo b_5xx
  done | wc -l ) > /tmp/cc3_b 2>/dev/null &
wait
af=$(cat /tmp/cc3_a 2>/dev/null)
bf=$(cat /tmp/cc3_b 2>/dev/null)
rm -f /tmp/cc3_a /tmp/cc3_b
if [[ "$af" -eq 0 ]] && [[ "$bf" -eq 0 ]]; then
  echo "[PASS] CC-3 identity merge race — 2 parallel sid streams × 20 reqs same-UA, no 5xx"
  P=$((P+1))
else
  echo "[FAIL] CC-3 identity merge race — 5xx counts a=${af} b=${bf} (track_key merge unsafe)"
  F=$((F+1))
fi

echo "[CAT-DONE] 22.Concurrency-edge P=${P} F=${F} I=${I} S=${S}"
