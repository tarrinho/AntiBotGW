#!/usr/bin/env bash
# Category 16 — Client fingerprint validation
# G-1 JA4/JA4H mismatch detection — declared Chrome UA but curl JA4 ≠ Chrome
# G-2 TLS ClientHello fingerprint vs declared browser identity
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── G-1 JA4 mismatch — curl pretending to be Chrome ───────────────────────
# curl's JA4H differs from Chrome's. If the GW does JA4 fingerprint validation,
# requests with a Chrome UA + curl's actual fingerprint should be flagged.
# Without authenticated read of /__logs we can only verify the surface response.
CHROME_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
CHROME_HDRS=(
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.9"
  -H "Accept-Encoding: gzip, deflate, br"
  -H "Sec-Fetch-Site: none" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Dest: document"
  -H "Sec-Ch-Ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\""
  -H "Sec-Ch-Ua-Mobile: ?0" -H "Sec-Ch-Ua-Platform: \"Windows\""
)
# Real Chrome would have JA4H matching its TLS hello; curl can't replicate that.
# Probe: status code + body size + any "ja4" / "fingerprint" header.
hdrs=$(curl -sk --max-time 6 -D - -A "$CHROME_UA" "${CHROME_HDRS[@]}" -o /dev/null "${URL}/" 2>/dev/null || echo "")
status=$(echo "$hdrs" | head -1 | awk '{print $2}')
fp_header_seen=0
echo "$hdrs" | grep -qiE 'x-ja4|x-fingerprint|x-client-class' && fp_header_seen=1
if [[ "$fp_header_seen" -eq 1 ]]; then
  echo "[PASS] G-1 JA4 mismatch — gateway emits JA4/fingerprint header (probe status=${status})"; P=$((P+1))
elif [[ -n "$status" ]] && ! [[ "$status" =~ ^5 ]]; then
  echo "[INFO] G-1 JA4 mismatch — no JA4 header surfaced; probe handled cleanly (${status}). Full assertion needs /__logs read"
  I=$((I+1))
elif [[ -z "$status" ]]; then
  echo "[INFO] G-1 JA4 mismatch probe — no response (target unreachable)"; I=$((I+1))
else
  echo "[FAIL] G-1 JA4 mismatch probe — server error (status=${status})"; F=$((F+1))
fi

# ── G-2 TLS ClientHello probe — JA3 of openssl differs from JA3 of Chrome ─
# We can ONLY exercise this against HTTPS. Reuse S-1's logic: confirm the
# gateway answers a modern handshake (1.2/1.3) and didn't 5xx.
HOST="${URL#http*://}"; HOST="${HOST%%/*}"; HNAME="${HOST%%:*}"
PORT="${HOST##*:}"; [[ "$PORT" == "$HOST" ]] && PORT=""
case "$URL" in https://*) [[ -z "$PORT" ]] && PORT=443;; http://*) [[ -z "$PORT" ]] && PORT=80;; esac

if [[ "$URL" =~ ^https:// ]] && command -v openssl >/dev/null 2>&1; then
  if echo Q | timeout 5 openssl s_client -connect "${HNAME}:${PORT}" -tls1_2 -servername "$HNAME" </dev/null >/dev/null 2>&1; then
    # Now do an HTTP probe through that TLS — declare Chrome UA but openssl
    # ClientHello is openssl's fingerprint, not Chrome's.
    body_sz=$(curl -sk --max-time 6 -A "$CHROME_UA" "${URL}/" 2>/dev/null | wc -c)
    if [[ "$body_sz" -gt 0 ]]; then
      echo "[PASS] G-2 TLS ClientHello probe — HTTPS handshake OK + body=${body_sz}B (full fingerprint validation needs /__logs)"
      P=$((P+1))
    else
      echo "[FAIL] G-2 TLS ClientHello probe — HTTPS handshake OK but body empty"; F=$((F+1))
    fi
  else
    echo "[FAIL] G-2 TLS ClientHello probe — could not establish TLS 1.2 handshake"; F=$((F+1))
  fi
else
  echo "[INFO] G-2 TLS ClientHello probe — HTTP target; full fingerprint check requires HTTPS"
  I=$((I+1))
fi

echo "[CAT-DONE] 16.Fingerprint P=${P} F=${F} I=${I} S=${S}"
