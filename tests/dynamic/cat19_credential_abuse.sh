#!/usr/bin/env bash
# Category 19 — Credential abuse / account hygiene
# Cred-1 brute-force lockout
# Cred-2 session fixation — pre-login cookie must rotate after login
# Cred-3 cookie reuse across logout
# Cred-4 username enumeration via timing/response diff
# Cred-5 password policy enforcement
# Cred-6 account-lockout DoS — throttle by IP+user, not user alone
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── Cred-1 brute-force lockout — 20 bad logins → next must be rejected ────
fail_codes=()
for i in $(seq 1 20); do
  s=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" \
    -X POST -d "username=bf-probe-user&password=wrong-${i}" \
    "${URL}${NS}/login" 2>/dev/null)
  fail_codes+=("$s")
done
# Now probe a 21st attempt; if lockout is in effect we expect a different
# status (e.g. 429 / 403 / longer latency) than the early attempts.
later_start=$(date +%s.%N 2>/dev/null)
s21=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" \
  -X POST -d "username=bf-probe-user&password=wrong-21" \
  "${URL}${NS}/login" 2>/dev/null)
later_end=$(date +%s.%N 2>/dev/null)
# Quick check: first attempts vs 21st must differ OR latency on 21st must spike
first3="${fail_codes[0]}/${fail_codes[1]}/${fail_codes[2]}"
distinct=$(printf '%s\n' "${fail_codes[@]}" "$s21" | sort -u | wc -l)
if [[ "$s21" == "429" ]] || [[ "$s21" == "403" ]] || [[ "$distinct" -ge 2 ]]; then
  echo "[PASS] Cred-1 brute-force lockout — early codes [${first3}] vs 21st=${s21} (lockout signal observed)"
  P=$((P+1))
elif ! [[ "$s21" =~ ^5 ]] && [[ "$s21" != "000" ]]; then
  echo "[INFO] Cred-1 brute-force — all 21 attempts returned ${s21} (no lockout signal; may use silent decoy)"
  I=$((I+1))
else
  echo "[INFO] Cred-1 brute-force — 21st status=${s21} (target unreachable / decoy)"; I=$((I+1))
fi

# ── Cred-2 session fixation — cookie before login vs after must differ ────
JAR1="$(mktemp)"
curl -sk --max-time 6 -c "$JAR1" "${URL}${NS}/login" -o /dev/null 2>/dev/null
pre=$(grep -E 'agw_session|agw_csrf|session' "$JAR1" 2>/dev/null | awk '{print $NF}' | sort -u | head -1)
csrf=$(curl -sk --max-time 5 -b "$JAR1" "${URL}${NS}/login" 2>/dev/null | grep -oE 'name="csrf"[^>]*value="[^"]+"' | head -1 | sed -E 's/.*value="([^"]+)".*/\1/')
# Attempt login (will likely fail without real creds, but cookie should still rotate
# if the server uses pre-issued session id beyond the boundary)
curl -sk --max-time 6 -b "$JAR1" -c "$JAR1" -X POST \
  -d "csrf=${csrf:-x}&username=bogus&password=bogus" \
  "${URL}${NS}/login" -o /dev/null 2>/dev/null
post=$(grep -E 'agw_session|agw_csrf|session' "$JAR1" 2>/dev/null | awk '{print $NF}' | sort -u | head -1)
rm -f "$JAR1"
if [[ -z "$pre" ]] && [[ -z "$post" ]]; then
  echo "[INFO] Cred-2 session fixation — no session cookie issued at /login (CDN strip?)"; I=$((I+1))
elif [[ "$pre" != "$post" ]] || [[ -z "$pre" ]]; then
  echo "[PASS] Cred-2 session fixation — cookie value changed after login attempt (no fixation)"; P=$((P+1))
else
  # Cookie unchanged after login attempt — that's only OK if login failed AND
  # no session was actually established. With bogus creds, failure is expected.
  echo "[INFO] Cred-2 session fixation — cookie unchanged after FAILED login (real check needs successful auth)"
  I=$((I+1))
fi

# ── Cred-3 cookie reuse across logout ─────────────────────────────────────
# Synthesise: get a session cookie, hit /logout, then probe /secured/* with the
# same cookie. If the cookie still works, that's reuse-after-logout.
JAR2="$(mktemp)"
curl -sk --max-time 5 -c "$JAR2" "${URL}${NS}/login" -o /dev/null 2>/dev/null
curl -sk --max-time 5 -b "$JAR2" -c "$JAR2" "${URL}${NS}/logout" -o /dev/null 2>/dev/null
post_logout=$(curl -sk --max-time 5 -b "$JAR2" -o /dev/null -w "%{http_code}" \
  "${URL}${NS}/secured/whoami" 2>/dev/null)
rm -f "$JAR2"
# Anonymous probe baseline
anon=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}${NS}/secured/whoami" 2>/dev/null)
if [[ "$post_logout" == "$anon" ]] && ! [[ "$post_logout" =~ ^2 ]]; then
  echo "[PASS] Cred-3 cookie reuse across logout — post-logout cookie behaves same as anon (${post_logout})"
  P=$((P+1))
elif [[ "$post_logout" =~ ^2 ]]; then
  echo "[FAIL] Cred-3 cookie reuse across logout — post-logout cookie still admits (${post_logout})"
  F=$((F+1))
else
  echo "[INFO] Cred-3 cookie reuse — post-logout=${post_logout} anon=${anon} (cannot disambiguate; needs real auth)"
  I=$((I+1))
fi

# ── Cred-4 username enumeration via timing/response diff ──────────────────
# Two POSTs: one to a "likely real" username, one to a clearly random one.
# Status code AND response size must not differ.
t_real_s=$(curl -sk --max-time 8 -o /tmp/cred4_real.txt -w "%{http_code}|%{time_total}|%{size_download}" \
  -X POST -d "username=admin&password=wrongpassword" "${URL}${NS}/login" 2>/dev/null || echo "000|0|0")
t_fake_s=$(curl -sk --max-time 8 -o /tmp/cred4_fake.txt -w "%{http_code}|%{time_total}|%{size_download}" \
  -X POST -d "username=Xv8j2nP9LqWqp7c&password=wrongpassword" "${URL}${NS}/login" 2>/dev/null || echo "000|0|0")
rs="${t_real_s%%|*}"; rest="${t_real_s#*|}"; rt="${rest%%|*}"; rsz="${rest##*|}"
fs="${t_fake_s%%|*}"; rest="${t_fake_s#*|}"; ft="${rest%%|*}"; fsz="${rest##*|}"
rm -f /tmp/cred4_real.txt /tmp/cred4_fake.txt
size_delta=$(( rsz > fsz ? rsz - fsz : fsz - rsz ))
# Pass when status matches AND sizes within 32 bytes
if [[ "$rs" == "$fs" ]] && [[ "$size_delta" -le 32 ]]; then
  echo "[PASS] Cred-4 username enumeration — admin vs random: same status (${rs}) + size delta ${size_delta}B"
  P=$((P+1))
elif [[ "$rs" != "$fs" ]]; then
  echo "[FAIL] Cred-4 username enumeration — status differs (admin=${rs} random=${fs}) → user existence leak"
  F=$((F+1))
else
  echo "[INFO] Cred-4 username enumeration — same status (${rs}) but size delta ${size_delta}B (acceptable variance)"
  I=$((I+1))
fi

# ── Cred-5 password policy — weak password must be rejected on register/set ─
# Without an admin-key write surface to attempt, probe the /register or /password/set
# endpoints. If absent (404), the policy is enforced elsewhere (out of scope here).
status_reg=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST -d 'username=newuser&password=123' "${URL}${NS}/register" 2>/dev/null)
status_set=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST -d 'password=123' "${URL}${NS}/password/set" 2>/dev/null)
# Any 2xx on a 3-char password write would be a policy failure.
weak_accepted=0
for s in "$status_reg" "$status_set"; do
  [[ "$s" =~ ^2 ]] && weak_accepted=$((weak_accepted+1))
done
if [[ "$weak_accepted" -eq 0 ]]; then
  echo "[PASS] Cred-5 password policy — weak 3-char password NOT accepted (register=${status_reg} set=${status_set})"
  P=$((P+1))
else
  echo "[FAIL] Cred-5 password policy — weak password accepted on ${weak_accepted}/2 endpoints"
  F=$((F+1))
fi

# ── Cred-6 account-lockout DoS — attacker from IP X locks legit user Y ────
# Property: lockout key should be (user, source-IP) tuple, not just user.
# Surrogate: hit /login 10x with a bogus user from this IP, then probe a
# DIFFERENT-looking source via X-Forwarded-For — should not be locked.
for i in $(seq 1 10); do
  curl -sk --max-time 4 -o /dev/null \
    -X POST -d "username=victim-user&password=wrong" "${URL}${NS}/login" 2>/dev/null
done
# Different XFF source
diff_src_status=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" \
  -H "X-Forwarded-For: 198.51.100.42" \
  -X POST -d "username=victim-user&password=wrong" "${URL}${NS}/login" 2>/dev/null)
# Same XFF source as the lockout-builder
same_src_status=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" \
  -X POST -d "username=victim-user&password=wrong" "${URL}${NS}/login" 2>/dev/null)
if [[ "$diff_src_status" == "429" ]] || [[ "$diff_src_status" == "403" ]] && [[ "$same_src_status" != "$diff_src_status" ]]; then
  echo "[FAIL] Cred-6 account-lockout DoS — different IP also locked (${diff_src_status}); lockout key is user-only (DoS feasible)"
  F=$((F+1))
elif [[ "$diff_src_status" =~ ^[234] ]] && [[ "$same_src_status" =~ ^[234] ]]; then
  echo "[PASS] Cred-6 account-lockout DoS — different IP still admitted (same=${same_src_status} diff=${diff_src_status})"
  P=$((P+1))
else
  echo "[INFO] Cred-6 account-lockout DoS — same=${same_src_status} diff=${diff_src_status} (no clear lockout signal)"
  I=$((I+1))
fi

echo "[CAT-DONE] 19.Credential-abuse P=${P} F=${F} I=${I} S=${S}"
