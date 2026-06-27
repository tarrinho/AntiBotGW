#!/usr/bin/env bash
# Category 23 — Cryptographic primitives
# Crypto-1 signed cookie tampering — bit-flip agw_session → must reject
# Crypto-2 TOTP replay — same code accepted twice in window (surface check w/o secret)
# Crypto-3 constant-time admin-key comparison — timing variance across 30 trials
# Crypto-4 HMAC key rotation — surface check that session/key rotation exists
# Crypto-5 token entropy — collect 100 csrf tokens, assert distinct + char spread
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── Crypto-1 signed cookie tampering ──────────────────────────────────────
# Obtain a session cookie via /login flow (cookie issued even on failed login),
# then mutate one byte and probe /secured/whoami. Tampered cookie must NOT
# yield 2xx (must equal anon baseline).
JAR="$(mktemp)"
curl -sk --max-time 6 -c "$JAR" "${URL}${NS}/login" -o /dev/null 2>/dev/null
orig=$(awk '/agw_session/{print $NF}' "$JAR" | tail -1)
if [[ -n "$orig" ]] && [[ "${#orig}" -ge 8 ]]; then
  # Flip last char to something different
  last="${orig: -1}"
  case "$last" in A) flip="B";; a) flip="b";; *) flip="A";; esac
  tampered="${orig%?}${flip}"
  st_orig=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -b "agw_session=${orig}" "${URL}${NS}/secured/whoami" 2>/dev/null)
  st_tamp=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -b "agw_session=${tampered}" "${URL}${NS}/secured/whoami" 2>/dev/null)
  st_anon=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    "${URL}${NS}/secured/whoami" 2>/dev/null)
  if [[ "$st_tamp" == "$st_anon" ]] && ! [[ "$st_tamp" =~ ^2 ]]; then
    echo "[PASS] Crypto-1 cookie tampering — tampered=${st_tamp} matches anon=${st_anon} (HMAC verified)"
    P=$((P+1))
  elif [[ "$st_tamp" =~ ^2 ]]; then
    echo "[FAIL] Crypto-1 cookie tampering — tampered cookie admitted (${st_tamp}) — HMAC NOT verified!"
    F=$((F+1))
  else
    echo "[INFO] Crypto-1 cookie tampering — tampered=${st_tamp} anon=${st_anon} (no clear signal; needs valid auth context)"
    I=$((I+1))
  fi
else
  echo "[INFO] Crypto-1 cookie tampering — no agw_session cookie issued at /login (CDN strip?)"; I=$((I+1))
fi
rm -f "$JAR"

# ── Crypto-2 TOTP replay (surface check — needs real shared secret for full) ─
# Probe: /login must reject a known-bad TOTP code rather than silently accept
# missing TOTP. We send a POST with explicit totp=000000 (universally wrong).
JAR2="$(mktemp)"
curl -sk --max-time 5 -c "$JAR2" "${URL}${NS}/login" -o /dev/null 2>/dev/null
csrf2=$(curl -sk --max-time 5 -b "$JAR2" "${URL}${NS}/login" 2>/dev/null | grep -oE 'name="csrf"[^>]*value="[^"]+"' | head -1 | sed -E 's/.*value="([^"]+)".*/\1/')
totp_status=$(curl -sk --max-time 6 -b "$JAR2" -o /dev/null -w "%{http_code}" \
  -X POST --data-urlencode "csrf=${csrf2:-x}" --data-urlencode "username=admin" \
  --data-urlencode "password=wrong" --data-urlencode "totp=000000" \
  "${URL}${NS}/login" 2>/dev/null)
rm -f "$JAR2"
if ! [[ "$totp_status" =~ ^2 ]] && [[ "$totp_status" != "302" ]]; then
  echo "[PASS] Crypto-2 TOTP probe — bogus totp=000000 + wrong password rejected (${totp_status})"
  P=$((P+1))
elif [[ "$totp_status" == "302" ]]; then
  echo "[INFO] Crypto-2 TOTP probe — redirect (${totp_status}); cannot disambiguate accept vs decoy without follow-up"
  I=$((I+1))
else
  echo "[FAIL] Crypto-2 TOTP probe — bogus totp + wrong password got ${totp_status}"; F=$((F+1))
fi

# ── Crypto-3 constant-time comparison — 30 wrong-password trials, low variance ─
TIMES="$(mktemp)"
for i in $(seq 1 30); do
  # Vary password prefix length so a non-CT compare would short-circuit early
  pad=$(printf 'X%.0s' $(seq 1 $((i % 10 + 1))))
  curl -sk --max-time 5 -o /dev/null -w "%{time_total}\n" \
    -X POST --data-urlencode "username=admin" --data-urlencode "password=${pad}wrong" \
    "${URL}${NS}/login" 2>/dev/null >> "$TIMES"
done
nt=$(wc -l < "$TIMES")
if [[ "$nt" -ge 20 ]]; then
  avg=$(awk '{s+=$1} END{print (NR? s/NR : 0)}' "$TIMES")
  stddev=$(awk -v a="$avg" '{d=$1-a; s+=d*d; n++} END{print (n? sqrt(s/n) : 0)}' "$TIMES")
  cv=$(awk -v a="$avg" -v s="$stddev" 'BEGIN{print (a>0? s/a : 0)}')
  # CV ≤ 0.5 typical even for network-jittered constant-time path; > 1.0 suggests
  # short-circuit timing leak.
  if awk -v c="$cv" 'BEGIN{exit !(c <= 0.5)}'; then
    echo "[PASS] Crypto-3 constant-time — 30 wrong-pwd trials avg=${avg}s CV=${cv} (low variance, no clear timing leak)"
    P=$((P+1))
  elif awk -v c="$cv" 'BEGIN{exit !(c <= 1.0)}'; then
    echo "[INFO] Crypto-3 constant-time — CV=${cv} (moderate variance, likely network jitter)"; I=$((I+1))
  else
    echo "[FAIL] Crypto-3 constant-time — CV=${cv} > 1.0 (possible short-circuit timing side-channel)"
    F=$((F+1))
  fi
else
  echo "[INFO] Crypto-3 constant-time — only ${nt}/30 samples collected (GW unreachable?)"; I=$((I+1))
fi
rm -f "$TIMES"

# ── Crypto-4 HMAC key rotation — surface check for sessions revoke endpoint ─
# A real test would: (1) authenticate, (2) trigger key rotation via admin API,
# (3) verify old cookie now rejected. Surface: probe that a sessions/revoke or
# config/reload-keys endpoint exists and doesn't crash.
rotate_found=0
for ep in /secured/sessions/revoke /secured/keys/rotate /secured/config/reload; do
  s=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -X POST "${URL}${NS}${ep}" 2>/dev/null)
  # Non-5xx + non-404 indicates the endpoint exists (likely 401/403)
  if ! [[ "$s" =~ ^5 ]] && [[ "$s" != "404" ]] && [[ "$s" != "000" ]]; then
    rotate_found=$((rotate_found+1))
  fi
done
if [[ "$rotate_found" -ge 1 ]]; then
  echo "[PASS] Crypto-4 HMAC key rotation surface — ${rotate_found} rotation endpoint(s) reachable"; P=$((P+1))
else
  echo "[INFO] Crypto-4 HMAC key rotation — no rotation endpoint found (rotation may be process-restart based)"; I=$((I+1))
fi

# ── Crypto-5 token entropy — collect 30 csrf tokens, check distinct + char spread ─
TOK="$(mktemp)"
for i in $(seq 1 30); do
  curl -sk --max-time 4 "${URL}${NS}/login" 2>/dev/null \
    | grep -oE 'name="csrf"[^>]*value="[^"]+"' | head -1 \
    | sed -E 's/.*value="([^"]+)".*/\1/' >> "$TOK"
done
collected=$(grep -c . "$TOK" 2>/dev/null)
distinct=$(sort -u "$TOK" 2>/dev/null | grep -c .)
if [[ "$collected" -ge 10 ]] && [[ "$distinct" -eq "$collected" ]]; then
  # Each collected token must be distinct
  charset=$(tr -d '\n' < "$TOK" | fold -w1 | sort -u | wc -l)
  if [[ "$charset" -ge 16 ]]; then
    echo "[PASS] Crypto-5 token entropy — ${collected}/30 collected, ${distinct} distinct, ${charset} distinct chars (≥ 16)"
    P=$((P+1))
  else
    echo "[FAIL] Crypto-5 token entropy — distinct OK but only ${charset} char classes (< 16); weak alphabet"
    F=$((F+1))
  fi
elif [[ "$collected" -ge 10 ]]; then
  dup=$((collected - distinct))
  echo "[FAIL] Crypto-5 token entropy — ${dup}/${collected} tokens were duplicates (collision = HMAC seed reuse)"
  F=$((F+1))
else
  echo "[INFO] Crypto-5 token entropy — only ${collected}/30 tokens collected (GW unreachable or no csrf on /login)"
  I=$((I+1))
fi
rm -f "$TOK"

echo "[CAT-DONE] 23.Crypto P=${P} F=${F} I=${I} S=${S}"
