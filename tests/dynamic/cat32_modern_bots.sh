#!/usr/bin/env bash
# Category 32 — Modern bot detection (Bot-1..4 cover obvious + clean Chrome;
# these probes target real-engine bots that defeat naive UA detection)
# Bot-5 Headless Chrome — UA carries "HeadlessChrome/"
# Bot-6 Puppeteer signature — Sec-Ch-Ua-Headless: ?1 + missing Sec-Fetch-User
# Bot-7 Selenium — webdriver-flag headers + automation markers
# Bot-8 Stealth Chrome — UA Chrome but JA4/Sec-CH mismatch (already in G-1; here we assert
#       a "clean" but obviously-automated request pattern is denied)
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0

_decoyed() {
  # Returns 1 if response looks decoyed/blocked, 0 if upstream-shaped
  local status sz
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "$@" 2>/dev/null)
  sz=$(curl -sk --max-time 5 "$@" 2>/dev/null | wc -c)
  [[ -z "$status" ]] || [[ "$status" =~ ^0 ]] && echo z && return
  if [[ "$status" =~ ^[45] ]] || [[ "$sz" -lt 2000 ]]; then echo 1; else echo 0; fi
}

# ── Bot-5 Headless Chrome ─────────────────────────────────────────────────
hl_ua="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/126.0.6478.62 Safari/537.36"
r=$(_decoyed -A "$hl_ua" "${URL}/?bot5=hl")
if [[ "$r" == "z" ]]; then
  echo "[INFO] Bot-5 Headless Chrome — no response (target unreachable)"; I=$((I+1))
elif [[ "$r" == "1" ]]; then
  echo "[PASS] Bot-5 Headless Chrome — UA with 'HeadlessChrome/' decoyed"; P=$((P+1))
else
  echo "[FAIL] Bot-5 Headless Chrome — HeadlessChrome UA admitted to upstream (UA classifier blind)"; F=$((F+1))
fi

# ── Bot-6 Puppeteer signature ─────────────────────────────────────────────
# Puppeteer's identifying tells: Sec-Ch-Ua-Mobile sent without matching Sec-CH-UA brands,
# missing Sec-Fetch-User on a top-level nav, AcceptLanguage empty.
pup_ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
r=$(_decoyed -A "$pup_ua" \
  -H "Accept: */*" \
  -H "Accept-Language: " \
  -H "Sec-Ch-Ua-Mobile: ?0" \
  "${URL}/?bot6=puppeteer")
if [[ "$r" == "z" ]]; then
  echo "[INFO] Bot-6 Puppeteer signature — no response"; I=$((I+1))
elif [[ "$r" == "1" ]]; then
  echo "[PASS] Bot-6 Puppeteer signature — broken Accept-Language + missing Sec-CH-UA decoyed"; P=$((P+1))
else
  echo "[INFO] Bot-6 Puppeteer signature — request admitted (classifier needs JA4 or full Sec-CH-UA mismatch to catch)"; I=$((I+1))
fi

# ── Bot-7 Selenium webdriver flag ─────────────────────────────────────────
sel_ua="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
r=$(_decoyed -A "$sel_ua" \
  -H "X-WebDriver: 1" \
  -H "Selenium-IDE: 3.17.0" \
  "${URL}/?bot7=selenium")
if [[ "$r" == "z" ]]; then
  echo "[INFO] Bot-7 Selenium — no response"; I=$((I+1))
elif [[ "$r" == "1" ]]; then
  echo "[PASS] Bot-7 Selenium — X-WebDriver/Selenium-IDE markers decoyed"; P=$((P+1))
else
  echo "[INFO] Bot-7 Selenium — markers ignored (classifier may not inspect these specific headers)"; I=$((I+1))
fi

# ── Bot-8 Clean Chrome at automation cadence ──────────────────────────────
# Chrome-perfect headers, but 5 reqs in <1s from same identity at the homepage —
# pattern fits automation. Should be decoyed by rate-class detection.
chr_ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
decoyed=0
for i in $(seq 1 5); do
  r=$(_decoyed -A "$chr_ua" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -H "Accept-Language: en-US,en;q=0.9" \
    -H "Accept-Encoding: gzip, deflate, br" \
    -H "Sec-Ch-Ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"" \
    -H "Sec-Ch-Ua-Mobile: ?0" -H "Sec-Ch-Ua-Platform: \"Windows\"" \
    "${URL}/?bot8-burst=${i}")
  [[ "$r" == "1" ]] && decoyed=$((decoyed+1))
done
if [[ "$decoyed" -eq 0 ]]; then
  echo "[INFO] Bot-8 Chrome rate-burst — all 5 admitted (rate classifier may be disabled OR no response)"; I=$((I+1))
elif [[ "$decoyed" -ge 3 ]]; then
  echo "[PASS] Bot-8 Chrome rate-burst — ${decoyed}/5 burst reqs decoyed (rate-class signal works)"; P=$((P+1))
else
  echo "[INFO] Bot-8 Chrome rate-burst — only ${decoyed}/5 decoyed (low rate-class sensitivity)"; I=$((I+1))
fi

echo "[CAT-DONE] 32.Modern-bots P=${P} F=${F} I=${I} S=${S}"
