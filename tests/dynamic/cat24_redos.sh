#!/usr/bin/env bash
# Category 24 — ReDoS (Regex Denial of Service)
# ReDoS-1 catastrophic backtracking via long path — latency must stay bounded
# ReDoS-2 catastrophic backtracking via long header — latency must stay bounded
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0

# Baseline single request
base=$(curl -sk --max-time 6 -o /dev/null -w "%{time_total}" "${URL}/" 2>/dev/null || echo "0")
if ! awk -v b="$base" 'BEGIN{exit !(b > 0 && b < 10)}'; then
  echo "[INFO] ReDoS — baseline / latency=${base}s; skipping ReDoS-1/2 (GW unreachable or too slow)"
  I=$((I+1))
  echo "[INFO] ReDoS-2 skipped (baseline issue)"
  I=$((I+1))
  echo "[CAT-DONE] 24.ReDoS P=${P} F=${F} I=${I} S=${S}"
  exit 0
fi

# ── ReDoS-1 catastrophic backtracking via path payload ────────────────────
# Classic vulnerable patterns: `(a+)+$`, `(a|a)*`, `(.*)*`. We can't see the
# WAF's regex, so we send adversarial inputs that exercise common ReDoS shapes
# and assert latency doesn't blow up beyond 10x baseline.
PAYLOAD1=$(printf 'a%.0s' $(seq 1 40))!     # 40 'a' then '!'
PAYLOAD2=$(printf 'X%.0s' $(seq 1 50))      # 50 X
PAYLOAD3=$(printf 'aa%.0s' $(seq 1 30))b    # 60 'aa' then 'b'
fails=0; samples=0
for p in "$PAYLOAD1" "$PAYLOAD2" "$PAYLOAD3"; do
  t=$(curl -sk --max-time 12 -o /dev/null -w "%{time_total}" \
    "${URL}/${p}?q=${p}" 2>/dev/null || echo "0")
  samples=$((samples+1))
  if awk -v t="$t" -v b="$base" 'BEGIN{exit !(t > b * 10 && t > 2.0)}'; then
    fails=$((fails+1))
  fi
done
if [[ "$fails" -eq 0 ]]; then
  echo "[PASS] ReDoS-1 path payloads — ${samples}/${samples} stayed within 10× baseline ${base}s"
  P=$((P+1))
else
  echo "[FAIL] ReDoS-1 path payloads — ${fails}/${samples} exceeded 10× baseline (regex backtracking)"
  F=$((F+1))
fi

# ── ReDoS-2 catastrophic backtracking via header payload ──────────────────
# Long crafted header value targeting same classic ReDoS shapes
HV1=$(printf 'a%.0s' $(seq 1 80))!
HV2=$(printf 'ab%.0s' $(seq 1 60))c
hfails=0; hsamples=0
for hv in "$HV1" "$HV2"; do
  t=$(curl -sk --max-time 12 -o /dev/null -w "%{time_total}" \
    -H "X-Probe-ReDoS: ${hv}" -H "User-Agent: ${hv}" \
    "${URL}/" 2>/dev/null || echo "0")
  hsamples=$((hsamples+1))
  if awk -v t="$t" -v b="$base" 'BEGIN{exit !(t > b * 10 && t > 2.0)}'; then
    hfails=$((hfails+1))
  fi
done
if [[ "$hfails" -eq 0 ]]; then
  echo "[PASS] ReDoS-2 header payloads — ${hsamples}/${hsamples} stayed within 10× baseline"
  P=$((P+1))
else
  echo "[FAIL] ReDoS-2 header payloads — ${hfails}/${hsamples} exceeded 10× baseline (header regex backtracking)"
  F=$((F+1))
fi

echo "[CAT-DONE] 24.ReDoS P=${P} F=${F} I=${I} S=${S}"
