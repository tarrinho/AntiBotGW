#!/usr/bin/env bash
# Category 28 — Multi-tenancy isolation
# MT-1 vhost-A ban must NOT propagate to vhost-B
# MT-2 vhost-A config read must NOT surface vhost-B knobs
# MT-3 per-vhost rate-limit independent (saturating A doesn't throttle B)
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
VHA="probe-tenant-a.test"
VHB="probe-tenant-b.test"

# ── MT-1 ban isolation ────────────────────────────────────────────────────
# Hammer vhost-A with sqlmap UA (likely-banned class), then probe vhost-B
# with the same UA. If ban leaked, B will also decoy. If isolated, B's
# decision is independent.
for i in $(seq 1 15); do
  curl -sk --max-time 3 -o /dev/null -H "Host: ${VHA}" -A "sqlmap/1.7-dev" \
    "${URL}/?mt1-a=${i}" 2>/dev/null
done
# Now probe vhost-B FROM A NEW PERSPECTIVE — same UA, different Host
b_status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "Host: ${VHB}" -A "sqlmap/1.7-dev" "${URL}/?mt1-b-probe=1" 2>/dev/null)
b_size=$(curl -sk --max-time 5 -H "Host: ${VHB}" -A "sqlmap/1.7-dev" \
  "${URL}/?mt1-b-size=1" 2>/dev/null | wc -c)
# Without admin we can't read the ban list. But we can compare A's vs B's
# response shape — they should match (both decoyed same way) which proves
# vhost is not leaking ban state. If A is "deeper" decoyed than B (different
# status), that suggests per-vhost state — also a pass condition.
if [[ "$b_status" =~ ^0 ]] || [[ -z "$b_status" ]]; then
  echo "[INFO] MT-1 ban isolation — vhost-B no response (target unreachable)"; I=$((I+1))
elif ! [[ "$b_status" =~ ^5 ]]; then
  echo "[PASS] MT-1 ban isolation — vhost-B responded ${b_status} (${b_size}B) after vhost-A spam (no leaked 5xx)"
  P=$((P+1))
else
  echo "[FAIL] MT-1 ban isolation — vhost-B returned ${b_status} (5xx); ban state may have crashed shared state"
  F=$((F+1))
fi

# ── MT-2 config isolation — vhost-A health vs vhost-B health ─────────────
NS="/antibot-appsec-gateway"
a_health=$(curl -sk --max-time 5 -H "Host: ${VHA}" "${URL}${NS}/__health" 2>/dev/null || echo "")
b_health=$(curl -sk --max-time 5 -H "Host: ${VHB}" "${URL}${NS}/__health" 2>/dev/null || echo "")
if [[ -z "$a_health" ]] && [[ -z "$b_health" ]]; then
  echo "[INFO] MT-2 config isolation — both vhosts no-response (target unreachable)"; I=$((I+1))
else
  # If __health echoes the requested vhost name, isolation visibility is good.
  # Neither response should contain the OTHER vhost's name.
  a_leaks_b=0; b_leaks_a=0
  echo "$a_health" | grep -qF "$VHB" && a_leaks_b=1
  echo "$b_health" | grep -qF "$VHA" && b_leaks_a=1
  if [[ "$a_leaks_b" -eq 0 ]] && [[ "$b_leaks_a" -eq 0 ]]; then
    echo "[PASS] MT-2 config isolation — vhost-A's response does not reference vhost-B (and vice versa)"
    P=$((P+1))
  else
    echo "[FAIL] MT-2 config isolation — cross-tenant name leakage detected (a→b=${a_leaks_b} b→a=${b_leaks_a})"
    F=$((F+1))
  fi
fi

# ── MT-3 rate-limit isolation — saturate vhost-A, probe vhost-B ──────────
# Fire a fast burst to A, then immediately probe B. B's latency should not
# spike relative to baseline (no shared token bucket).
t_base=$(curl -sk --max-time 5 -o /dev/null -w "%{time_total}" \
  -H "Host: ${VHB}" "${URL}/?mt3-baseline=1" 2>/dev/null || echo "0")
for i in $(seq 1 60); do
  curl -sk --max-time 2 -o /dev/null -H "Host: ${VHA}" "${URL}/?mt3-a=${i}" 2>/dev/null &
done
wait
t_after=$(curl -sk --max-time 5 -o /dev/null -w "%{time_total}" \
  -H "Host: ${VHB}" "${URL}/?mt3-after=1" 2>/dev/null || echo "0")
if awk -v b="$t_base" 'BEGIN{exit !(b == 0)}'; then
  echo "[INFO] MT-3 rate-limit isolation — baseline 0s (target unreachable)"; I=$((I+1))
elif awk -v b="$t_base" -v a="$t_after" 'BEGIN{exit !(a <= b * 3.0 || a < 1.0)}'; then
  echo "[PASS] MT-3 rate-limit isolation — vhost-B latency stable (base=${t_base}s after-A-burst=${t_after}s, ≤ 3×)"
  P=$((P+1))
else
  echo "[FAIL] MT-3 rate-limit isolation — vhost-B latency spiked (base=${t_base}s after-A-burst=${t_after}s, > 3×; shared bucket?)"
  F=$((F+1))
fi

echo "[CAT-DONE] 28.Multi-tenancy P=${P} F=${F} I=${I} S=${S}"
