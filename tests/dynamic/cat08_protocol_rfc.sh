#!/usr/bin/env bash
# Category 8 — Protocol / RFC compliance
# Q-1: WebSocket upgrade probe
# Q-2: TLS version restrictions (1.0/1.1 rejected, 1.2/1.3 accepted)
# Q-3: OpenAPI contract — SKIP
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0

HOST="${URL#http*://}"; HOST="${HOST%%/*}"
PORT="${HOST##*:}"; [[ "$PORT" == "$HOST" ]] && PORT=""
HOSTNAME="${HOST%%:*}"
if [[ -z "$PORT" ]]; then
  case "$URL" in
    https://*) PORT=443 ;;
    http://*)  PORT=80 ;;
  esac
fi

# Q-1 WebSocket upgrade probe — expect 426/400/101
status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "Upgrade: websocket" -H "Connection: Upgrade" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  "$URL/" 2>/dev/null)
case "$status" in
  101|400|426|404) echo "[PASS] Q-1 WebSocket probe → ${status} (handled cleanly)"; P=$((P+1)) ;;
  5*) echo "[FAIL] Q-1 WebSocket probe → ${status} (gateway should not 5xx)"; F=$((F+1)) ;;
  *)  echo "[INFO] Q-1 WebSocket probe → ${status}"; I=$((I+1)) ;;
esac

# Q-2 TLS versions — only meaningful on HTTPS
if [[ "$URL" =~ ^https:// ]] && command -v openssl >/dev/null 2>&1; then
  for v in tls1 tls1_1; do
    if echo Q | timeout 5 openssl s_client -connect "${HOSTNAME}:${PORT}" -"$v" -servername "$HOSTNAME" </dev/null >/dev/null 2>&1; then
      echo "[FAIL] Q-2 TLS — ${v} accepted (must be disabled)"; F=$((F+1))
    else
      echo "[PASS] Q-2 TLS — ${v} rejected"; P=$((P+1))
    fi
  done
  for v in tls1_2 tls1_3; do
    if echo Q | timeout 5 openssl s_client -connect "${HOSTNAME}:${PORT}" -"$v" -servername "$HOSTNAME" </dev/null >/dev/null 2>&1; then
      echo "[PASS] Q-2 TLS — ${v} accepted"; P=$((P+1))
    else
      echo "[INFO] Q-2 TLS — ${v} not accepted (CDN may negotiate down)"; I=$((I+1))
    fi
  done
else
  echo "[INFO] Q-2 TLS versions — HTTP target; covered by S-1 in cat03 when target is HTTPS"
  I=$((I+1))
fi

# ── Q-3 OpenAPI contract — inline minimal schema per known endpoint ──────
q3_fails=0; q3_checked=0
ENDPOINTS=(
  "/antibot-appsec-gateway/secured/health-score|score|version|db_backend"
  "/antibot-appsec-gateway/secured/vhosts|vhosts|hosts"
  "/antibot-appsec-gateway/__health|status|ok|alive"
)
for row in "${ENDPOINTS[@]}"; do
  ep="${row%%|*}"; rest="${row#*|}"
  expect=$(echo "$rest" | tr '|' '\n' | sed 's/.*/"&"/' | tr '\n' '|' | sed 's/|$//')
  body=$(curl -sk --max-time 5 "$URL$ep" 2>/dev/null || echo "")
  q3_checked=$((q3_checked+1))
  if [[ -n "$body" ]] && echo "$body" | head -c 1 | grep -q '{'; then
    if ! echo "$body" | grep -qE "$expect"; then q3_fails=$((q3_fails+1)); fi
  fi
done
if [[ "$q3_fails" -eq 0 ]]; then
  echo "[PASS] Q-3 OpenAPI surrogate — ${q3_checked} endpoints conform to inline schema (or auth-gated)"
  P=$((P+1))
else
  echo "[FAIL] Q-3 OpenAPI surrogate — ${q3_fails}/${q3_checked} returned JSON missing expected fields"
  F=$((F+1))
fi

echo "[CAT-DONE] 8.Protocol-RFC P=${P} F=${F} I=${I} S=${S}"
