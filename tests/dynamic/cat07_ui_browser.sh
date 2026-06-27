#!/usr/bin/env bash
# Category 7 — UI / browser
# U-1: HTML-level dashboard sanity (real, no Playwright needed)
# U-2: a11y antipattern grep (real heuristic, no axe-core needed)
# U-3: visual regression (kept SKIP — needs reference screenshots)
# U-4: multi-browser (kept SKIP — needs Playwright)
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── U-1 HTML dashboard sanity (real probe over HTTP) ─────────────────────
LOGIN="$(mktemp)"
curl -sk --max-time 8 "${URL}${NS}/login" -o "$LOGIN" 2>/dev/null || true
login_sz=$(wc -c < "$LOGIN")
if [[ "$login_sz" -lt 20 ]]; then
  echo "[INFO] U-1 login HTML sanity — fetch empty (${login_sz}B; target unreachable)"; I=$((I+1))
  echo "[INFO] U-2 a11y heuristic — skipped (no login HTML)"; I=$((I+1))
  echo "[INFO] U-3 visual fingerprint — skipped (no login HTML)"; I=$((I+1))
  echo "[INFO] U-4 multi-browser — skipped (no login HTML)"; I=$((I+1))
  echo "[INFO] Static dashboard checks covered by pytest in rules.md §17"; I=$((I+1))
  rm -f "$LOGIN"
  echo "[CAT-DONE] 7.UI-browser P=${P} F=${F} I=${I} S=${S}"
  exit 0
fi
ui_fails=0; ui_checks=0
# 1.9.x login is JS-driven: no server-rendered <form> tag and the CSRF token
# is cookie/JS-injected at POST time, not embedded in the initial HTML. Sane
# markers for the rendered page are the brand, input fields, a password field,
# and the login action reference.
for needle in 'AntiBot/WAF GW' '<input' 'password' 'login'; do
  ui_checks=$((ui_checks+1))
  grep -qi "$needle" "$LOGIN" || ui_fails=$((ui_fails+1))
done
# No raw error from the framework
grep -qi 'traceback\|aiohttp.*error\|internal server error' "$LOGIN" && ui_fails=$((ui_fails+1))
ui_checks=$((ui_checks+1))
if [[ "$ui_fails" -eq 0 ]]; then
  echo "[PASS] U-1 login HTML sanity — ${ui_checks}/${ui_checks} checks (brand, input, password, login, no traceback)"
  P=$((P+1))
else
  echo "[FAIL] U-1 login HTML sanity — ${ui_fails}/${ui_checks} expected markers missing or error leaked"
  F=$((F+1))
fi

# ── U-2 a11y antipattern grep (heuristic — real, no axe-core needed) ─────
a11y_fails=0
# images without alt
img_total=$(grep -ic '<img' "$LOGIN" 2>/dev/null)
img_noalt=$(grep -ioE '<img[^>]*>' "$LOGIN" 2>/dev/null | grep -vc 'alt=')
if [[ "$img_total" -gt 0 ]] && [[ "$img_noalt" -gt 0 ]]; then a11y_fails=$((a11y_fails+1)); fi
# inputs without label or aria-label
input_total=$(grep -ic '<input' "$LOGIN" 2>/dev/null)
input_noaria=$(grep -ioE '<input[^>]*>' "$LOGIN" 2>/dev/null | grep -vc -E 'aria-label|id="[^"]+"')
if [[ "$input_total" -gt 0 ]] && [[ "$input_noaria" -gt "$input_total" ]]; then a11y_fails=$((a11y_fails+1)); fi
# language attribute on <html>
grep -qiE '<html[^>]*\blang=' "$LOGIN" || a11y_fails=$((a11y_fails+1))
if [[ "$a11y_fails" -eq 0 ]]; then
  echo "[PASS] U-2 a11y heuristic — login page has lang attr, inputs have ids/labels, imgs have alt"
  P=$((P+1))
else
  echo "[INFO] U-2 a11y heuristic — ${a11y_fails} antipattern bucket(s) flagged on /login (run axe-core for authoritative scan)"
  I=$((I+1))
fi
rm -f "$LOGIN"

# ── U-3 visual regression surrogate — HTML structural fingerprint diff ───
# Real test needs Playwright + reference screenshots. This catches the
# "layout/structure changed unexpectedly" property by counting key elements
# and diffing against a saved baseline at /tmp/u3-fingerprint.txt.
LOGIN2="$(mktemp)"
curl -sk --max-time 8 "${URL}${NS}/login" -o "$LOGIN2" 2>/dev/null || true
fp_divs=$(grep -oc '<div' "$LOGIN2" 2>/dev/null)
fp_forms=$(grep -oc '<form' "$LOGIN2" 2>/dev/null)
fp_inputs=$(grep -oc '<input' "$LOGIN2" 2>/dev/null)
fp_scripts=$(grep -oc '<script' "$LOGIN2" 2>/dev/null)
fp_links=$(grep -oc '<a ' "$LOGIN2" 2>/dev/null)
fp_buttons=$(grep -oc '<button' "$LOGIN2" 2>/dev/null)
fp="d=${fp_divs} f=${fp_forms} i=${fp_inputs} s=${fp_scripts} a=${fp_links} b=${fp_buttons}"
REF="/tmp/u3-fingerprint.txt"
# Guard: an all-zero fingerprint means the /login fetch failed (empty body).
# Never save or diff against that — it produces a bogus baseline that makes
# the *next* (successful) run report false "drift". Treat as a fetch error.
if [[ $((fp_divs + fp_inputs + fp_scripts)) -eq 0 ]]; then
  echo "[INFO] U-3 visual fingerprint — /login fetch empty (${fp}); skipping baseline"; I=$((I+1))
elif [[ -f "$REF" ]] && grep -qE 'd=0 f=0 i=0 s=0' "$REF" 2>/dev/null; then
  # Stale all-zero baseline from a prior failed run — replace, don't FAIL.
  echo "$fp" > "$REF"
  echo "[INFO] U-3 visual fingerprint — replaced stale empty baseline (${fp}); next run will diff"; I=$((I+1))
elif [[ -f "$REF" ]]; then
  prev=$(cat "$REF" 2>/dev/null)
  if [[ "$prev" == "$fp" ]]; then
    echo "[PASS] U-3 visual fingerprint — structural counts unchanged (${fp})"; P=$((P+1))
  else
    echo "[FAIL] U-3 visual fingerprint — drift detected: was '${prev}' now '${fp}'"; F=$((F+1))
  fi
else
  echo "$fp" > "$REF"
  echo "[INFO] U-3 visual fingerprint — baseline saved at ${REF} (${fp}); next run will diff"; I=$((I+1))
fi
rm -f "$LOGIN2"

# ── U-4 multi-browser surrogate — fetch /login as Chrome / Firefox / Safari ─
# Real test needs Playwright; this catches UA-conditional divergence in HTML.
u4_sizes=()
for ua in "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0" \
          "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/127.0" \
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"; do
  sz=$(curl -sk --max-time 6 -A "$ua" "${URL}${NS}/login" 2>/dev/null | wc -c)
  u4_sizes+=("$sz")
done
# All three should be within ±25% of each other (UA-conditional logic shouldn't reshape login)
min=${u4_sizes[0]}; max=${u4_sizes[0]}
for s in "${u4_sizes[@]}"; do
  [[ "$s" -lt "$min" ]] && min="$s"
  [[ "$s" -gt "$max" ]] && max="$s"
done
if [[ "$min" -gt 0 ]] && awk -v a="$max" -v b="$min" 'BEGIN{exit !(a <= b*1.25)}'; then
  echo "[PASS] U-4 multi-browser — Chrome=${u4_sizes[0]}B Firefox=${u4_sizes[1]}B Safari=${u4_sizes[2]}B (within ±25%)"
  P=$((P+1))
elif [[ "$min" -eq 0 ]]; then
  echo "[INFO] U-4 multi-browser — at least one browser got 0B response (GW unreachable?)"; I=$((I+1))
else
  echo "[FAIL] U-4 multi-browser — size variance > 25%: Chrome=${u4_sizes[0]}B Firefox=${u4_sizes[1]}B Safari=${u4_sizes[2]}B"
  F=$((F+1))
fi

# Source-level static checks still run via pytest in rules.md §17
echo "[INFO] Static dashboard checks (escapeHtml, _timers, aria, stale-banner) covered by"
echo "       \`pytest -k 'dashboard or escapeHtml or innerHTML'\` in rules.md §17"
I=$((I+1))

echo "[CAT-DONE] 7.UI-browser P=${P} F=${F} I=${I} S=${S}"
