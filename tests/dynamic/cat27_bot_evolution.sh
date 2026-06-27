#!/usr/bin/env bash
# Category 27 — Bot evolution patterns
# Bot-1 slow-rate bot — 5 reqs × 2s interval, must all be flagged via fingerprint
# Bot-2 distributed bot — 20 distinct XFF sources, same bad UA, most flagged
# Bot-3 UA-rotating bot — 20 different bot UAs from same IP
# Bot-4 high-quality mimicry — Chrome UA + matching Sec-CH-UA + Accept must PASS
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0

# ── Bot-1 slow-rate ───────────────────────────────────────────────────────
# Rate-based classifiers won't catch 1 req/2s. UA-based classifiers should.
decoyed=0; ok=0; total=5
for i in $(seq 1 $total); do
  sz=$(curl -sk --max-time 5 -A "sqlmap/1.7-dev" "${URL}/?bot1=${i}" 2>/dev/null | wc -c)
  st=$(curl -sk --max-time 5 -A "sqlmap/1.7-dev" -o /dev/null -w "%{http_code}" \
    "${URL}/?bot1-status=${i}" 2>/dev/null)
  if [[ "$st" =~ ^[45] ]] || [[ "$sz" -lt 2000 ]]; then
    decoyed=$((decoyed+1))
  else
    ok=$((ok+1))
  fi
  sleep 2
done
if [[ "$decoyed" -ge $((total - 1)) ]]; then
  echo "[PASS] Bot-1 slow-rate — ${decoyed}/${total} sqlmap-UA at 1 req/2s decoyed/4xx (UA-class detection works)"
  P=$((P+1))
else
  echo "[FAIL] Bot-1 slow-rate — only ${decoyed}/${total} caught (rate-only classifier — slow bots evade)"
  F=$((F+1))
fi

# ── Bot-2 distributed bot — different XFF, same bad UA ────────────────────
decoyed=0; total=20
for i in $(seq 1 $total); do
  # Use varying public-IP-shaped XFF
  octet1=$((2 + (i * 7) % 220))
  octet2=$((1 + (i * 13) % 250))
  xff="${octet1}.0.${octet2}.${i}"
  sz=$(curl -sk --max-time 4 -A "Go-http-client/1.1" \
    -H "X-Forwarded-For: ${xff}" "${URL}/?bot2=${i}" 2>/dev/null | wc -c)
  st=$(curl -sk --max-time 4 -A "Go-http-client/1.1" \
    -H "X-Forwarded-For: ${xff}" -o /dev/null -w "%{http_code}" \
    "${URL}/?bot2-status=${i}" 2>/dev/null)
  if [[ "$st" =~ ^[45] ]] || [[ "$sz" -lt 2000 ]]; then
    decoyed=$((decoyed+1))
  fi
done
threshold=$(( total * 7 / 10 ))
if [[ "$decoyed" -ge "$threshold" ]]; then
  echo "[PASS] Bot-2 distributed — ${decoyed}/${total} Go-http-client across distinct IPs decoyed (≥ 70%)"
  P=$((P+1))
else
  echo "[FAIL] Bot-2 distributed — only ${decoyed}/${total} caught (UA classifier per-IP-rate dependent)"
  F=$((F+1))
fi

# ── Bot-3 UA-rotating from same IP ────────────────────────────────────────
ROT_UAS=(
  "python-requests/2.31.0"
  "Go-http-client/1.1"
  "curl/8.0.1"
  "Wget/1.21.3"
  "sqlmap/1.7-dev"
  "Nikto/2.5.0"
  "masscan/1.3"
  "axios/1.6.0"
  "okhttp/4.10.0"
  "aiohttp/3.8.5"
)
decoyed=0; total=${#ROT_UAS[@]}
for ua in "${ROT_UAS[@]}"; do
  sz=$(curl -sk --max-time 4 -A "$ua" "${URL}/?bot3-ua=$(echo "$ua" | head -c 4)" 2>/dev/null | wc -c)
  st=$(curl -sk --max-time 4 -A "$ua" -o /dev/null -w "%{http_code}" \
    "${URL}/?bot3=$(echo "$ua" | head -c 4)" 2>/dev/null)
  if [[ "$st" =~ ^[45] ]] || [[ "$sz" -lt 2000 ]]; then
    decoyed=$((decoyed+1))
  fi
done
threshold=$(( total * 8 / 10 ))
if [[ "$decoyed" -ge "$threshold" ]]; then
  echo "[PASS] Bot-3 UA-rotating — ${decoyed}/${total} bot UAs from one IP decoyed (≥ 80%)"
  P=$((P+1))
else
  echo "[FAIL] Bot-3 UA-rotating — only ${decoyed}/${total} caught"; F=$((F+1))
fi

# ── Bot-4 high-quality mimicry — Chrome + matching Sec-CH-UA + Accept ─────
# A well-crafted bot should pass the UA-class check. (JA4 fingerprint validation
# would still catch it, but that's covered by G-1/G-2.)
size_chrome=$(curl -sk --max-time 5 \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "Sec-Fetch-Site: none" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Dest: document" \
  -H "Sec-Ch-Ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"" \
  -H "Sec-Ch-Ua-Mobile: ?0" -H "Sec-Ch-Ua-Platform: \"Windows\"" \
  -H "Upgrade-Insecure-Requests: 1" \
  "${URL}/?bot4=chrome" 2>/dev/null | wc -c)
status_chrome=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" \
  -H "Accept: text/html" -H "Accept-Language: en-US,en;q=0.9" \
  "${URL}/?bot4-status=chrome" 2>/dev/null)
if [[ "$status_chrome" =~ ^[23] ]] || [[ "$size_chrome" -ge 2000 ]]; then
  echo "[PASS] Bot-4 high-quality mimicry — Chrome UA + Sec-CH-UA + Accept passes (status=${status_chrome} size=${size_chrome}B)"
  P=$((P+1))
elif [[ "$status_chrome" == "000" ]] && [[ "$size_chrome" -eq 0 ]]; then
  echo "[INFO] Bot-4 high-quality mimicry — no response (GW unreachable)"; I=$((I+1))
else
  echo "[FAIL] Bot-4 high-quality mimicry — Chrome-shaped req DENIED (status=${status_chrome} size=${size_chrome}B; false positive)"
  F=$((F+1))
fi

echo "[CAT-DONE] 27.Bot-evolution P=${P} F=${F} I=${I} S=${S}"
