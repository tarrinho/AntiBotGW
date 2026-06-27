#!/usr/bin/env bash
# Category 15 — Past-CVE regression battery
# B-1 1.9.2 maintainer priv-esc — anon must not be able to assume maintainer role
# B-2 admin key disclosure — admin key/related secrets must not leak in any response
# B-3 2FA bypass — login without TOTP must not yield an authed session
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── B-1 maintainer priv-esc — anon attempts to call maintainer-only endpoints ─
priv_2xx=0
for ep in /secured/maintainer /secured/admin /secured/users/promote \
          /secured/role/set /secured/users/list /secured/users/delete; do
  s=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" -d '{"role":"maintainer","user":"attacker"}' \
    "${URL}${NS}${ep}" 2>/dev/null)
  [[ "$s" =~ ^2 ]] && priv_2xx=$((priv_2xx+1))
done
if [[ "$priv_2xx" -eq 0 ]]; then
  echo "[PASS] B-1 maintainer priv-esc — anon POST to 6 maintainer endpoints all denied (no 2xx)"; P=$((P+1))
else
  echo "[FAIL] B-1 maintainer priv-esc — ${priv_2xx}/6 maintainer endpoints accepted anon write (REGRESSION!)"; F=$((F+1))
fi

# ── B-2 admin key disclosure — scan responses for secret leakage ──────────
LEAK="$(mktemp)"
for ep in / /robots.txt /antibot-appsec-gateway/__health \
          /antibot-appsec-gateway/login /antibot-appsec-gateway/.well-known/security.txt \
          /antibot-appsec-gateway/secured/whoami; do
  curl -sk --max-time 5 -D - "${URL}${ep}" 2>/dev/null >> "$LEAK"
  echo "---" >> "$LEAK"
done
# Look for telltale secret patterns. Avoid false positives on the word
# "admin_key" appearing in HTML labels — require a value-like string.
leaks=0
for pat in 'X-Admin-Key:[[:space:]]*[A-Za-z0-9_-]{16,}' \
           '"ADMIN_KEY"[[:space:]]*:[[:space:]]*"[A-Za-z0-9_-]{8,}' \
           'POSTGRES_DSN[[:space:]]*:[[:space:]]*postgres://[^"]+' \
           'TOTP_SECRET[[:space:]]*:[[:space:]]*"[A-Z0-9]{16,}' \
           'BasicAuth\s+[A-Za-z0-9+/]{20,}' \
           'AKIA[0-9A-Z]{16}' ; do
  if grep -qE "$pat" "$LEAK" 2>/dev/null; then leaks=$((leaks+1)); fi
done
rm -f "$LEAK"
if [[ "$leaks" -eq 0 ]]; then
  echo "[PASS] B-2 admin key disclosure — no secret patterns found in 6 public responses"; P=$((P+1))
else
  echo "[FAIL] B-2 admin key disclosure — ${leaks} secret pattern(s) leaked in public responses (REGRESSION!)"; F=$((F+1))
fi

# ── B-3 2FA bypass — login POST without TOTP must not produce a session ───
# Capture cookie state before/after; if a privileged-session cookie appears
# without a TOTP step, that's the bypass vector.
JAR="$(mktemp)"
curl -sk --max-time 6 -c "$JAR" "${URL}${NS}/login" -o /dev/null 2>/dev/null
csrf=$(curl -sk --max-time 5 -b "$JAR" "${URL}${NS}/login" 2>/dev/null | grep -oE 'name="csrf"[^>]*value="[^"]+"' | head -1 | sed -E 's/.*value="([^"]+)".*/\1/')
# Skip-TOTP attempt: post creds without any TOTP code
resp=$(curl -sk --max-time 8 -b "$JAR" -c "$JAR" -i \
  -X POST -d "csrf=${csrf:-x}&username=admin&password=admin&totp=" \
  "${URL}${NS}/login" 2>/dev/null || echo "")
# Look for elevated session cookie (one tied to admin) being set
elevated=0
if echo "$resp" | grep -qiE 'Set-Cookie: agw_session=[A-Za-z0-9._-]{20,}'; then
  # Check whether /secured/whoami now answers 200 with admin role using that cookie
  who_status=$(curl -sk --max-time 5 -b "$JAR" -o /dev/null -w "%{http_code}" \
    "${URL}${NS}/secured/whoami" 2>/dev/null)
  who_body=$(curl -sk --max-time 5 -b "$JAR" "${URL}${NS}/secured/whoami" 2>/dev/null || echo "")
  if [[ "$who_status" == "200" ]] && echo "$who_body" | grep -qiE '"role"\s*:\s*"(admin|maintainer|operator)"'; then
    elevated=1
  fi
fi
rm -f "$JAR"
if [[ "$elevated" -eq 0 ]]; then
  echo "[PASS] B-3 2FA bypass — login without TOTP did NOT yield an elevated session"; P=$((P+1))
else
  echo "[FAIL] B-3 2FA bypass — elevated session granted without TOTP (REGRESSION!)"; F=$((F+1))
fi

echo "[CAT-DONE] 15.CVE-regression P=${P} F=${F} I=${I} S=${S}"
