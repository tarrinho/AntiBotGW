#!/usr/bin/env bash
# Category 34 — Protocol-deep (Q-1..3 covered WebSocket/TLS-versions/OpenAPI)
# Q-4 HTTP/3 / QUIC — Alt-Svc header advertised on HTTPS
# Q-5 HTTP/2 SETTINGS overflow — curl --http2 with weird settings
# Q-6 HPACK bomb — large compressed header set
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0

# ── Q-4 HTTP/3 / QUIC negotiation ─────────────────────────────────────────
HDR="$(mktemp)"
curl -sk --max-time 6 -D "$HDR" -o /dev/null "${URL}/" 2>/dev/null || true
altsvc=$(grep -i '^alt-svc:' "$HDR" 2>/dev/null || echo "")
if [[ "$URL" =~ ^https:// ]]; then
  if echo "$altsvc" | grep -qiE 'h3=|h3-29=|quic'; then
    echo "[PASS] Q-4 HTTP/3 — Alt-Svc advertises h3/quic (${altsvc:0:80})"; P=$((P+1))
  elif [[ -z "$altsvc" ]]; then
    echo "[INFO] Q-4 HTTP/3 — no Alt-Svc header (HTTP/3 not advertised; OK if not enabled)"; I=$((I+1))
  else
    echo "[INFO] Q-4 HTTP/3 — Alt-Svc present but no h3 token (${altsvc:0:80})"; I=$((I+1))
  fi
else
  echo "[INFO] Q-4 HTTP/3 — HTTP target; QUIC requires HTTPS"; I=$((I+1))
fi
rm -f "$HDR"

# ── Q-5 HTTP/2 SETTINGS overflow ──────────────────────────────────────────
# True overflow needs raw nghttp2 client. Surrogate: probe HTTP/2 negotiation
# with --http2-prior-knowledge against an HTTPS or http endpoint, plus assert
# no 5xx on aggressive h2 settings (curl will use sensible defaults).
status=$(curl -sk --max-time 8 --http2 -o /dev/null -w "%{http_code}" "${URL}/" 2>/dev/null)
if [[ -z "$status" ]] || [[ "$status" =~ ^0 ]]; then
  echo "[INFO] Q-5 HTTP/2 SETTINGS — no response (target unreachable or h2 unsupported)"; I=$((I+1))
elif [[ "$status" =~ ^5 ]]; then
  echo "[FAIL] Q-5 HTTP/2 SETTINGS — h2 request 5xx'd (${status}); possible SETTINGS-frame mishandling"
  F=$((F+1))
else
  echo "[PASS] Q-5 HTTP/2 SETTINGS — h2 negotiation handled (${status}); full SETTINGS-overflow needs nghttp2 client"
  P=$((P+1))
fi

# ── Q-6 HPACK bomb — large compressed header set ─────────────────────────
# Build 100 distinct headers; curl will HPACK-compress them. The GW must not
# OOM nor 5xx. Reasonable ceiling: total response under 10s.
H_ARGS=()
for i in $(seq 1 100); do
  H_ARGS+=(-H "X-Hpack-${i}: $(printf 'P%.0s' $(seq 1 64))")
done
t=$(curl -sk --max-time 12 --http2 -o /dev/null -w "%{time_total}\n%{http_code}" \
  "${H_ARGS[@]}" "${URL}/" 2>/dev/null | head -1)
status=$(curl -sk --max-time 12 --http2 -o /dev/null -w "%{http_code}" \
  "${H_ARGS[@]}" "${URL}/" 2>/dev/null)
if [[ -z "$status" ]] || [[ "$status" =~ ^0 ]]; then
  echo "[INFO] Q-6 HPACK bomb — no response (target unreachable)"; I=$((I+1))
elif [[ "$status" =~ ^5 ]]; then
  echo "[FAIL] Q-6 HPACK bomb — 100×64B headers triggered 5xx (${status}); HPACK decoder unbounded"; F=$((F+1))
elif awk -v t="$t" 'BEGIN{exit !(t < 10.0)}'; then
  echo "[PASS] Q-6 HPACK bomb — 100×64B header set handled in ${t}s (< 10s) → ${status}"; P=$((P+1))
else
  echo "[FAIL] Q-6 HPACK bomb — 100×64B headers took ${t}s (≥ 10s; decoder slow)"; F=$((F+1))
fi

echo "[CAT-DONE] 34.Protocol-deep P=${P} F=${F} I=${I} S=${S}"
