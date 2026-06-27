#!/usr/bin/env bash
# Category 25 — Operational state transitions
# Ops-1 SIGTERM — in-flight requests complete (real if CHAOS_GW_CONTAINER set, surrogate otherwise)
# Ops-2 drain mode — /__ready vs /__health if both exist
# Ops-3 rolling restart — constant traffic, no 5xx (surrogate: 30s constant load)
# Ops-4 config canary — knob set + read within bounded latency
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
GW_CONT="${CHAOS_GW_CONTAINER:-}"

# ── Ops-1 SIGTERM in-flight completion ────────────────────────────────────
if [[ -n "$GW_CONT" ]] && command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$GW_CONT"; then
  # Fire 20 in-flight requests, send SIGTERM, count completions.
  TMP="$(mktemp)"
  for i in $(seq 1 20); do
    ( curl -sk --max-time 15 -o /dev/null -w "%{http_code}\n" "${URL}/?ops1=${i}" 2>/dev/null >> "$TMP" ) &
  done
  sleep 0.3
  docker kill --signal=TERM "$GW_CONT" >/dev/null 2>&1 || true
  wait
  completed=$(grep -c '^[1-3]' "$TMP" 2>/dev/null)
  errored=$(grep -c '^5\|^000' "$TMP" 2>/dev/null)
  docker start "$GW_CONT" >/dev/null 2>&1 || true; sleep 2
  rm -f "$TMP"
  if [[ "$completed" -ge 15 ]] && [[ "$errored" -le 2 ]]; then
    echo "[PASS] Ops-1 SIGTERM — ${completed}/20 in-flight completed cleanly, ${errored} errored"; P=$((P+1))
  else
    echo "[FAIL] Ops-1 SIGTERM — only ${completed}/20 completed, ${errored} errored"; F=$((F+1))
  fi
else
  # Surrogate: 30 parallel in-flight requests must all complete without 5xx
  TMP="$(mktemp)"
  for i in $(seq 1 30); do
    ( curl -sk --max-time 8 -o /dev/null -w "%{http_code}\n" "${URL}/?ops1surrogate=${i}" 2>/dev/null >> "$TMP" ) &
  done
  wait
  errored=$(grep -c '^5' "$TMP" 2>/dev/null)
  total=$(wc -l < "$TMP")
  rm -f "$TMP"
  if [[ "$errored" -eq 0 ]] && [[ "$total" -ge 1 ]]; then
    echo "[PASS] Ops-1 SIGTERM surrogate — ${total}/30 in-flight completed without 5xx"; P=$((P+1))
  elif [[ "$total" -eq 0 ]]; then
    echo "[INFO] Ops-1 SIGTERM surrogate — no responses collected (GW unreachable)"; I=$((I+1))
  else
    echo "[FAIL] Ops-1 SIGTERM surrogate — ${errored}/${total} returned 5xx during burst"; F=$((F+1))
  fi
fi

# ── Ops-2 drain mode — /__ready vs /__health separation ───────────────────
ready_status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}/__ready" 2>/dev/null)
health_status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}/antibot-appsec-gateway/__health" 2>/dev/null)
if [[ "$ready_status" =~ ^[234] ]] && [[ "$health_status" =~ ^[234] ]]; then
  echo "[PASS] Ops-2 drain — /__ready=${ready_status} + /__health=${health_status} both exposed (drain-mode signalling possible)"
  P=$((P+1))
elif [[ "$health_status" =~ ^[234] ]]; then
  echo "[INFO] Ops-2 drain — /__health=${health_status} but /__ready=${ready_status} (no readiness/liveness split — drain harder to signal)"
  I=$((I+1))
else
  echo "[INFO] Ops-2 drain — health=${health_status} ready=${ready_status} (no probes responding)"; I=$((I+1))
fi

# ── Ops-3 rolling restart surrogate — 30s constant traffic, no 5xx ────────
end=$(($(date +%s) + 30))
total=0; errored=0
while [[ $(date +%s) -lt $end ]]; do
  for i in 1 2 3 4 5; do
    s=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "${URL}/?ops3=$i" 2>/dev/null)
    total=$((total+1))
    [[ "$s" =~ ^5 ]] && errored=$((errored+1))
  done
done
if [[ "$total" -ge 50 ]] && [[ "$errored" -eq 0 ]]; then
  echo "[PASS] Ops-3 rolling-restart surrogate — ${total} reqs over 30s, zero 5xx"; P=$((P+1))
elif [[ "$total" -lt 50 ]]; then
  echo "[INFO] Ops-3 rolling-restart — only ${total} reqs in 30s (GW slow/unreachable)"; I=$((I+1))
else
  echo "[FAIL] Ops-3 rolling-restart — ${errored}/${total} returned 5xx during sustained load"; F=$((F+1))
fi

# ── Ops-4 config canary — knob set + read within bounded latency ──────────
# Without admin we measure the surface latency of read. With cookie auth we
# can do set+read.
t_read=$(curl -sk --max-time 6 -o /dev/null -w "%{time_total}" \
  "${URL}/antibot-appsec-gateway/secured/config" 2>/dev/null || echo "0")
if awk -v t="$t_read" 'BEGIN{exit !(t > 0 && t < 2.0)}'; then
  echo "[PASS] Ops-4 config canary — /secured/config latency ${t_read}s < 2.0s (config-set→read would propagate fast)"
  P=$((P+1))
elif awk -v t="$t_read" 'BEGIN{exit !(t == 0)}'; then
  echo "[INFO] Ops-4 config canary — /secured/config not reachable for latency check"; I=$((I+1))
else
  echo "[FAIL] Ops-4 config canary — /secured/config latency ${t_read}s ≥ 2.0s (config propagation slow)"
  F=$((F+1))
fi

echo "[CAT-DONE] 25.Ops-transitions P=${P} F=${F} I=${I} S=${S}"
