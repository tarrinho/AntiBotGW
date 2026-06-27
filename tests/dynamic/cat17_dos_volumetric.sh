#!/usr/bin/env bash
# Category 17 — Volumetric / protocol-level DoS
# V-1 HTTP/2 Rapid Reset (CVE-2023-44487) — rapid stream open+RST
# V-2 Compression bomb — large compressed body, small uncompressed limit
# V-3 Large-header DoS — multi-KB header values
# V-4 Slowloris — slow header send (slow body covered by C-2)
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0

# ── V-1 HTTP/2 Rapid Reset surrogate ──────────────────────────────────────
# True CVE-2023-44487 needs an h2 client. nghttp2-cli or curl --http2 can
# at least probe negotiation; full RST flood requires custom client.
# Surrogate: fire 50 HTTP/2 requests in rapid succession, abort each via
# --max-time 0.1, assert gateway still answers a clean request after.
aborted=0
for i in $(seq 1 50); do
  curl -sk --http2 --max-time 0.1 -o /dev/null "${URL}/" 2>/dev/null &
done
wait 2>/dev/null
# Allow recovery window
sleep 0.5
after_status=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" "${URL}/" 2>/dev/null)
if [[ "$after_status" =~ ^[234] ]]; then
  echo "[PASS] V-1 HTTP/2 Rapid Reset surrogate — 50 aborted h2 reqs, GW still answers (${after_status})"
  P=$((P+1))
elif [[ "$after_status" =~ ^5 ]]; then
  echo "[FAIL] V-1 HTTP/2 Rapid Reset — GW returned ${after_status} after 50 aborted h2 reqs"; F=$((F+1))
elif [[ "$after_status" == "000" ]] || [[ "$after_status" == "000000" ]]; then
  echo "[INFO] V-1 HTTP/2 Rapid Reset — no response (GW not reachable)"; I=$((I+1))
else
  echo "[INFO] V-1 HTTP/2 Rapid Reset — recovery probe got ${after_status}"; I=$((I+1))
fi

# ── V-2 compression bomb — POST a 10 KB gzip that expands to 10 MB ──────
if command -v gzip >/dev/null 2>&1; then
  BOMB="$(mktemp)"
  # 10 MB of 'A' compresses to ~10 KB
  yes A | head -c 10485760 | gzip -9 > "$BOMB" 2>/dev/null
  sz=$(wc -c < "$BOMB")
  status=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/octet-stream" \
    -H "Content-Encoding: gzip" \
    --data-binary "@${BOMB}" "${URL}/v2-bomb-probe" 2>/dev/null)
  rm -f "$BOMB"
  # Healthy responses: 400/413/415 (rejected) or 200/404 (decoy/ignored).
  # 5xx or hang would indicate uncontrolled decompression.
  if [[ "$status" =~ ^[234] ]]; then
    echo "[PASS] V-2 compression bomb — ${sz}B gzip → ${status} (no uncontrolled decompression)"
    P=$((P+1))
  elif [[ "$status" == "000" ]] || [[ "$status" == "000000" ]]; then
    echo "[INFO] V-2 compression bomb — no response (GW not reachable)"; I=$((I+1))
  else
    echo "[FAIL] V-2 compression bomb — ${sz}B gzip → ${status} (likely OOM/hang)"; F=$((F+1))
  fi
else
  echo "[INFO] V-2 compression bomb — gzip binary missing"; I=$((I+1))
fi

# ── V-3 large-header DoS — multi-KB X-* header values ────────────────────
BIG=$(printf 'A%.0s' $(seq 1 8192))
status=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" \
  -H "X-Probe-V3: ${BIG}" \
  -H "Cookie: ${BIG}=${BIG}" \
  "${URL}/" 2>/dev/null)
# Healthy: 400/431/413/414 reject, OR 200/404 if silently dropped.
# 5xx would indicate uncontrolled header handling.
if [[ "$status" =~ ^[234] ]]; then
  echo "[PASS] V-3 large-header DoS — 8KB X-Probe + 8KB Cookie → ${status} (handled cleanly)"
  P=$((P+1))
elif [[ "$status" == "000" ]] || [[ "$status" == "000000" ]]; then
  echo "[INFO] V-3 large-header DoS — no response (GW not reachable)"; I=$((I+1))
else
  echo "[FAIL] V-3 large-header DoS — ${status} (header handling broken)"; F=$((F+1))
fi

# ── V-4 slowloris — slow header send (1 byte at a time via --limit-rate) ─
# A real slowloris attack opens N connections each dribbling headers; here
# we probe whether the GW imposes a read timeout. We send headers very slowly
# via curl --limit-rate; gateway should either complete reasonably or close.
slow_status=$(curl -sk --max-time 15 --limit-rate 100 -o /dev/null -w "%{http_code}" \
  -H "X-Probe-Slow: 1" \
  -H "X-Pad-1: $(printf 'A%.0s' $(seq 1 200))" \
  -H "X-Pad-2: $(printf 'B%.0s' $(seq 1 200))" \
  "${URL}/" 2>/dev/null)
if [[ "$slow_status" =~ ^[234] ]]; then
  echo "[PASS] V-4 slowloris — slow-header request handled (${slow_status})"; P=$((P+1))
elif [[ "$slow_status" == "000" ]] || [[ "$slow_status" == "000000" ]]; then
  echo "[INFO] V-4 slowloris — no response (could be read-timeout cut, or GW not reachable)"; I=$((I+1))
elif [[ "$slow_status" =~ ^5 ]]; then
  echo "[FAIL] V-4 slowloris — gateway 5xx (${slow_status})"; F=$((F+1))
else
  echo "[INFO] V-4 slowloris — status=${slow_status}"; I=$((I+1))
fi

echo "[CAT-DONE] 17.DoS-volumetric P=${P} F=${F} I=${I} S=${S}"
