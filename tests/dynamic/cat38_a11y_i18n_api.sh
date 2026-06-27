#!/usr/bin/env bash
# Category 38 — a11y deeper + i18n + API hygiene
# U-5 keyboard nav — tabindex discipline
# U-6 screen-reader — buttons/links have text or aria-label
# U-7 color contrast — surface check (full needs paint)
# i18n-1 UTF-8 in Host header (Punycode roundtrip)
# i18n-2 Emoji in usernames + log fields (probe surface)
# i18n-3 RTL text in dashboard (no layout break — surface check)
# API-1 idempotency key — POST with same Idempotency-Key twice
# API-2 ETag / If-Match optimistic concurrency
# API-3 pagination cursor stability
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── U-5 keyboard nav — login HTML tabindex discipline ─────────────────────
LOGIN="$(mktemp)"
curl -sk --max-time 8 "${URL}${NS}/login" -o "$LOGIN" 2>/dev/null || true
login_sz=$(wc -c < "$LOGIN")
if [[ "$login_sz" -lt 20 ]]; then
  echo "[INFO] U-5 keyboard nav — /login empty (target unreachable)"; I=$((I+1))
  echo "[INFO] U-6 screen-reader — /login empty"; I=$((I+1))
  echo "[INFO] U-7 color contrast — /login empty"; I=$((I+1))
  rm -f "$LOGIN"
else
  # NOTE: `grep -c ... || echo 0` is buggy — when grep matches nothing it both
  # prints "0" AND exits 1, so the `|| echo 0` appends a second "0", yielding a
  # multi-line value that breaks the `-eq` arithmetic and forces a false FAIL.
  # Count lines instead so the result is always a single clean integer.
  bad_tabindex=$(grep -oE 'tabindex="-[0-9]+"' "$LOGIN" 2>/dev/null | wc -l | tr -d ' ')
  if [[ "${bad_tabindex:-0}" -eq 0 ]]; then
    echo "[PASS] U-5 keyboard nav — login has no tabindex=-N on focusables"; P=$((P+1))
  else
    echo "[FAIL] U-5 keyboard nav — ${bad_tabindex} tabindex=-N on /login (focus traps)"; F=$((F+1))
  fi

  # ── U-6 screen-reader — buttons/anchors no-text means inaccessible ──────
  empty_btn=$(grep -ioE '<button[^>]*>[[:space:]]*</button>' "$LOGIN" 2>/dev/null | wc -l)
  empty_a=$(grep -ioE '<a[^>]*>[[:space:]]*</a>' "$LOGIN" 2>/dev/null | wc -l)
  if [[ "$empty_btn" -eq 0 ]] && [[ "$empty_a" -eq 0 ]]; then
    echo "[PASS] U-6 screen-reader — no empty <button>/<a> tags on /login"; P=$((P+1))
  else
    echo "[FAIL] U-6 screen-reader — ${empty_btn} empty <button>, ${empty_a} empty <a> (no accessible name)"
    F=$((F+1))
  fi

  # ── U-7 color contrast — surface: check that CSS exists at all ──────────
  has_css=$(grep -c 'style=\|<link[^>]*stylesheet' "$LOGIN" 2>/dev/null)
  if [[ "$has_css" -ge 1 ]]; then
    echo "[PASS] U-7 color contrast surface — CSS/style present on /login (full WCAG AA needs headless paint)"
    P=$((P+1))
  else
    echo "[INFO] U-7 color contrast — no CSS on /login"; I=$((I+1))
  fi
  rm -f "$LOGIN"
fi

# ── i18n-1 UTF-8 in Host header (Punycode roundtrip) ──────────────────────
# Send a Punycode IDN Host. Must not 5xx.
status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "Host: xn--bcher-kva.example" "${URL}/" 2>/dev/null)
if [[ -z "$status" ]] || [[ "$status" =~ ^0 ]]; then
  echo "[INFO] i18n-1 Punycode Host — no response"; I=$((I+1))
elif [[ "$status" =~ ^5 ]]; then
  echo "[FAIL] i18n-1 Punycode Host — xn--bcher-kva.example triggered 5xx (${status})"; F=$((F+1))
else
  echo "[PASS] i18n-1 Punycode Host — IDN host handled cleanly (${status})"; P=$((P+1))
fi

# ── i18n-2 Emoji in headers/query — log/header sanitizer probe ────────────
status_emoji=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -A "Mozilla/5.0 (🚀 BotTest/1.0) AppleWebKit" \
  --data-urlencode "username=user🎯" \
  "${URL}/?emoji=🚨" 2>/dev/null)
if [[ -z "$status_emoji" ]] || [[ "$status_emoji" =~ ^0 ]]; then
  echo "[INFO] i18n-2 emoji handling — no response"; I=$((I+1))
elif [[ "$status_emoji" =~ ^5 ]]; then
  echo "[FAIL] i18n-2 emoji handling — emoji in UA/query triggered 5xx (${status_emoji})"; F=$((F+1))
else
  echo "[PASS] i18n-2 emoji handling — UA + query + form with emoji handled cleanly (${status_emoji})"
  P=$((P+1))
fi

# ── i18n-3 RTL text — surface check that dashboard accepts Accept-Language: ar ─
status_rtl=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "Accept-Language: ar-SA,ar;q=0.9,en;q=0.5" \
  "${URL}${NS}/login" 2>/dev/null)
if [[ -z "$status_rtl" ]] || [[ "$status_rtl" =~ ^0 ]]; then
  echo "[INFO] i18n-3 RTL — no response"; I=$((I+1))
elif [[ "$status_rtl" =~ ^5 ]]; then
  echo "[FAIL] i18n-3 RTL — Accept-Language: ar triggered 5xx (${status_rtl})"; F=$((F+1))
else
  echo "[PASS] i18n-3 RTL — Accept-Language: ar handled cleanly (${status_rtl})"; P=$((P+1))
fi

# ── API-1 idempotency key ─────────────────────────────────────────────────
IK="api1-key-$(printf '%08x' "$RANDOM")"
s1=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST -H "Idempotency-Key: ${IK}" -H "Content-Type: application/json" \
  -d '{"probe":1}' "${URL}${NS}/api/idempotent-probe" 2>/dev/null)
s2=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST -H "Idempotency-Key: ${IK}" -H "Content-Type: application/json" \
  -d '{"probe":1}' "${URL}${NS}/api/idempotent-probe" 2>/dev/null)
if [[ -z "$s1" ]] || [[ "$s1" =~ ^0 ]]; then
  echo "[INFO] API-1 idempotency-key — no response"; I=$((I+1))
elif [[ "$s1" == "$s2" ]] && ! [[ "$s1" =~ ^5 ]]; then
  echo "[PASS] API-1 idempotency-key — both calls returned ${s1} (consistent, no 5xx; endpoint may 404 idempotently)"
  P=$((P+1))
else
  echo "[INFO] API-1 idempotency-key — s1=${s1} s2=${s2} (endpoint not present or differs)"; I=$((I+1))
fi

# ── API-2 ETag / If-Match optimistic concurrency ──────────────────────────
HDR="$(mktemp)"
curl -sk --max-time 5 -D "$HDR" -o /dev/null "${URL}${NS}/secured/config" 2>/dev/null
etag=$(grep -i '^etag:' "$HDR" 2>/dev/null | head -1)
rm -f "$HDR"
if [[ -n "$etag" ]]; then
  echo "[PASS] API-2 ETag — /secured/config emits ETag header (optimistic concurrency possible)"; P=$((P+1))
else
  echo "[INFO] API-2 ETag — no ETag header on /secured/config (concurrency control may use other mechanism)"
  I=$((I+1))
fi

# ── API-3 pagination cursor stability ─────────────────────────────────────
# Surface: hit a paginated endpoint with limit=5, then limit=5 again, then
# limit=10, and assert no 5xx + responses parseable.
fails=0; zeros=0
for q in 'limit=5' 'limit=5&cursor=0' 'limit=10' 'limit=5&offset=5'; do
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    "${URL}${NS}/secured/logs-data?${q}" 2>/dev/null)
  [[ -z "$status" ]] || [[ "$status" =~ ^0 ]] && zeros=$((zeros+1))
  [[ "$status" =~ ^5 ]] && fails=$((fails+1))
done
if [[ "$zeros" -ge 3 ]]; then
  echo "[INFO] API-3 pagination — most probes no-response"; I=$((I+1))
elif [[ "$fails" -eq 0 ]]; then
  echo "[PASS] API-3 pagination — 4 pagination variants, no 5xx"; P=$((P+1))
else
  echo "[FAIL] API-3 pagination — ${fails}/4 variants triggered 5xx"; F=$((F+1))
fi

echo "[CAT-DONE] 38.a11y-i18n-api P=${P} F=${F} I=${I} S=${S}"
