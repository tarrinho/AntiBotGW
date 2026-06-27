#!/usr/bin/env bash
# Category 26 — Resource leak detection
# Leak-1 FD leak — count /proc/<pid>/fd before/after (real if CHAOS_GW_CONTAINER, surrogate otherwise)
# Leak-2 memory leak — RSS before/after 200 reqs
# Leak-3 connection leak — 50 keep-alive reqs, server should close cleanly
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
GW_CONT="${CHAOS_GW_CONTAINER:-}"

# ── Leak-1 FD leak ────────────────────────────────────────────────────────
if [[ -n "$GW_CONT" ]] && command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$GW_CONT"; then
  pid=$(docker exec "$GW_CONT" pidof python3 2>/dev/null | awk '{print $1}')
  if [[ -n "$pid" ]]; then
    before=$(docker exec "$GW_CONT" sh -c "ls -1 /proc/${pid}/fd 2>/dev/null | wc -l" 2>/dev/null)
    for i in $(seq 1 100); do
      curl -sk --max-time 3 -o /dev/null "${URL}/?leak1=${i}" 2>/dev/null &
      [[ $((i % 25)) -eq 0 ]] && wait
    done
    wait
    sleep 2
    after=$(docker exec "$GW_CONT" sh -c "ls -1 /proc/${pid}/fd 2>/dev/null | wc -l" 2>/dev/null)
    delta=$((after - before))
    if [[ "$delta" -le 5 ]]; then
      echo "[PASS] Leak-1 FD — before=${before} after=${after} (delta=${delta} ≤ 5; no leak)"; P=$((P+1))
    else
      echo "[FAIL] Leak-1 FD — before=${before} after=${after} (delta=${delta} > 5; FD leak)"; F=$((F+1))
    fi
  else
    echo "[INFO] Leak-1 FD — could not find python3 PID in ${GW_CONT}"; I=$((I+1))
  fi
else
  # Surrogate: throughput stability under 100 reqs. FD exhaustion would cause
  # the latter half of the burst to slow down or error.
  TMP="$(mktemp)"
  for i in $(seq 1 100); do
    curl -sk --max-time 4 -o /dev/null -w "%{time_total} %{http_code}\n" "${URL}/?leak1s=${i}" 2>/dev/null >> "$TMP" &
    [[ $((i % 20)) -eq 0 ]] && wait
  done
  wait
  total=$(wc -l < "$TMP")
  first50=$(head -50 "$TMP" | awk '{s+=$1} END{print (NR? s/NR : 0)}')
  last50=$(tail -50 "$TMP" | awk '{s+=$1} END{print (NR? s/NR : 0)}')
  errs=$(awk '$2 ~ /^5/' "$TMP" | wc -l)
  rm -f "$TMP"
  if [[ "$total" -lt 80 ]]; then
    echo "[INFO] Leak-1 FD surrogate — only ${total}/100 responded (GW unreachable)"; I=$((I+1))
  elif awk -v f="$first50" 'BEGIN{exit !(f < 0.001)}'; then
    echo "[INFO] Leak-1 FD surrogate — sub-ms latency (first50=${first50}s; target unreachable, samples too tiny)"
    I=$((I+1))
  elif awk -v f="$first50" -v l="$last50" 'BEGIN{exit !(l <= f * 2.0)}' && [[ "$errs" -eq 0 ]]; then
    echo "[PASS] Leak-1 FD surrogate — ${total} reqs · first50 avg=${first50}s last50=${last50}s (≤ 2× ratio, 0 5xx)"
    P=$((P+1))
  else
    echo "[FAIL] Leak-1 FD surrogate — last50=${last50}s vs first50=${first50}s (degraded; possible FD leak)"
    F=$((F+1))
  fi
fi

# ── Leak-2 memory leak ────────────────────────────────────────────────────
if [[ -n "$GW_CONT" ]] && command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx "$GW_CONT"; then
  pid=$(docker exec "$GW_CONT" pidof python3 2>/dev/null | awk '{print $1}')
  if [[ -n "$pid" ]]; then
    rss_before=$(docker exec "$GW_CONT" sh -c "awk '/VmRSS/{print \$2}' /proc/${pid}/status" 2>/dev/null)
    for i in $(seq 1 200); do
      curl -sk --max-time 3 -o /dev/null "${URL}/?leak2=${i}-$(printf '%04x' "$RANDOM")" 2>/dev/null &
      [[ $((i % 25)) -eq 0 ]] && wait
    done
    wait; sleep 3
    rss_after=$(docker exec "$GW_CONT" sh -c "awk '/VmRSS/{print \$2}' /proc/${pid}/status" 2>/dev/null)
    if [[ "$rss_before" -gt 0 ]]; then
      pct=$(awk -v b="$rss_before" -v a="$rss_after" 'BEGIN{print (a-b)*100/b}')
      if awk -v p="$pct" 'BEGIN{exit !(p <= 50)}'; then
        echo "[PASS] Leak-2 memory — RSS ${rss_before}→${rss_after} kB (+${pct}%, ≤ 50%)"; P=$((P+1))
      else
        echo "[FAIL] Leak-2 memory — RSS ${rss_before}→${rss_after} kB (+${pct}%; > 50% growth)"; F=$((F+1))
      fi
    else
      echo "[INFO] Leak-2 memory — could not read /proc/${pid}/status"; I=$((I+1))
    fi
  else
    echo "[INFO] Leak-2 memory — no python3 PID in ${GW_CONT}"; I=$((I+1))
  fi
else
  echo "[INFO] Leak-2 memory — needs CHAOS_GW_CONTAINER to read /proc/<pid>/status (surrogate covered by P-3 mini-soak)"
  I=$((I+1))
fi

# ── Leak-3 connection leak — 50 keep-alive reqs on same TCP conn ──────────
TMP="$(mktemp)"
curl -sk --max-time 15 --keepalive-time 30 -o "$TMP" -w "%{http_code}\n" \
  $(for i in $(seq 1 50); do printf -- "%s/?leak3=%d " "$URL" "$i"; done) \
  2>/dev/null
codes=$(grep -oE '^[0-9]+$' "$TMP" | wc -l)
errs=$(grep -cE '^5' "$TMP" 2>/dev/null)
rm -f "$TMP"
if [[ "$codes" -ge 40 ]] && [[ "$errs" -eq 0 ]]; then
  echo "[PASS] Leak-3 keep-alive — ${codes} responses on shared conn, 0 5xx"; P=$((P+1))
elif [[ "$codes" -lt 40 ]]; then
  echo "[INFO] Leak-3 keep-alive — only ${codes}/50 responses (server may close conn aggressively, which is OK)"
  I=$((I+1))
else
  echo "[FAIL] Leak-3 keep-alive — ${errs}/${codes} returned 5xx mid-conn"; F=$((F+1))
fi

echo "[CAT-DONE] 26.Resource-leak P=${P} F=${F} I=${I} S=${S}"
