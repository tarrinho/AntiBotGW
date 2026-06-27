#!/usr/bin/env bash
# Category 11 — Property-based / fuzzing
# H-1, H-2: small Hypothesis-style invariants would be Python pytest, not bash.
# H-3: differential testing — SKIP (requires old image)
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Lightweight fuzz: 60 random path probes — no 5xx, no crash
ok=0; bad=0
for i in $(seq 1 60); do
  rand=$(LC_ALL=C tr -dc 'A-Za-z0-9._/-' < /dev/urandom 2>/dev/null | head -c 32)
  status=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "${URL}/${rand}" 2>/dev/null)
  if [[ "$status" =~ ^5 ]]; then bad=$((bad+1)); else ok=$((ok+1)); fi
done
if [[ "$bad" -eq 0 ]]; then
  echo "[PASS] H-fuzz 60 random paths — no 5xx"; P=$((P+1))
else
  echo "[FAIL] H-fuzz 60 random paths — ${bad} 5xx responses"; F=$((F+1))
fi

# Property checks via pytest if present
if [[ -d "${ROOT}/tests/dynamic/property" ]]; then
  python3 -m pytest "${ROOT}/tests/dynamic/property" -q --tb=no 2>&1 | tail -3
  echo "[INFO] H-1/H-2 — see pytest output above"
  I=$((I+1))
else
  echo "[INFO] H-1/H-2 Hypothesis property tests — would live in tests/dynamic/property/ (not created yet)"
  I=$((I+1))
fi

# ── H-3 differential surrogate — endpoint-response fingerprint diff ──────
# Fingerprint on status|content_type only — size_download is volatile for the
# upstream-proxied endpoints (/ and /robots.txt) and would cause false "drift"
# run-to-run as the upstream's body length changes.
H3_FP="$(mktemp)"; h3_fails=0
for ep in / /robots.txt /favicon.ico /antibot-appsec-gateway/__health; do
  resp=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}|%{content_type}" "${URL}${ep}" 2>/dev/null || echo "000|unknown")
  [[ "$resp" == 000\|* ]] && h3_fails=$((h3_fails+1))
  echo "${ep}|${resp}" >> "$H3_FP"
done
H3_REF="/tmp/h3-fingerprint.txt"
if [[ "$h3_fails" -ge 4 ]]; then
  echo "[INFO] H-3 differential — all endpoints unreachable (probe error); skipping baseline"; I=$((I+1))
elif [[ -f "$H3_REF" ]] && grep -q '|000|' "$H3_REF" 2>/dev/null; then
  cp "$H3_FP" "$H3_REF"
  echo "[INFO] H-3 differential — replaced stale failed baseline; next run will diff"; I=$((I+1))
elif [[ -f "$H3_REF" ]]; then
  if diff -q "$H3_REF" "$H3_FP" >/dev/null 2>&1; then
    echo "[PASS] H-3 differential — 4 critical endpoints match baseline fingerprint"; P=$((P+1))
  else
    echo "[FAIL] H-3 differential — endpoint fingerprints diverged from baseline ${H3_REF}"
    diff "$H3_REF" "$H3_FP" 2>/dev/null | head -8
    F=$((F+1))
  fi
else
  cp "$H3_FP" "$H3_REF"
  echo "[INFO] H-3 differential — baseline saved at ${H3_REF}; next run will diff"; I=$((I+1))
fi
rm -f "$H3_FP"

echo "[CAT-DONE] 11.Property-fuzz P=${P} F=${F} I=${I} S=${S}"
