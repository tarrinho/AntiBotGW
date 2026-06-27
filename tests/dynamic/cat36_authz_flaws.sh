#!/usr/bin/env bash
# Category 36 — Authorization flaws
# IDOR-1 direct object reference — anon attempts to GET user-scoped data by ID
# MA-1 mass assignment — POST with extra "role:maintainer" field, must be ignored
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── IDOR-1 direct object reference ────────────────────────────────────────
# Without auth, probe common ID-bearing endpoints with low-number IDs. Any 2xx
# from anon is a regression (B-1 catches admin-write IDOR; this catches read IDOR).
idor_2xx=0
for ep in "/secured/users/1" "/secured/users/2" "/secured/sessions/1" \
          "/secured/sessions/abc" "/secured/events/1" "/secured/bans/1" \
          "/secured/agent/1" "/secured/audit/1"; do
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}${NS}${ep}" 2>/dev/null)
  [[ "$status" =~ ^2 ]] && idor_2xx=$((idor_2xx+1))
done
if [[ "$idor_2xx" -eq 0 ]]; then
  echo "[PASS] IDOR-1 direct object reference — anon GET on 8 ID-bearing endpoints all denied (no 2xx)"; P=$((P+1))
else
  echo "[FAIL] IDOR-1 direct object reference — ${idor_2xx}/8 endpoints admit anon GET (data exposure!)"; F=$((F+1))
fi

# ── MA-1 mass assignment / over-posting ──────────────────────────────────
# Attempt to elevate role via JSON body field that the API shouldn't accept.
# Both anon and (if available) authed-with-user-role should be denied.
ma_2xx=0
for ep in "/secured/users/create" "/secured/users/update" "/secured/profile" \
          "/secured/account/update" "/register"; do
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"username":"victim","email":"v@v.com","role":"maintainer","is_admin":true,"privilege_level":99}' \
    "${URL}${NS}${ep}" 2>/dev/null)
  [[ "$status" =~ ^2 ]] && ma_2xx=$((ma_2xx+1))
done
# Anon probing user-create/update is the lowest bar — should never be 2xx
if [[ "$ma_2xx" -eq 0 ]]; then
  echo "[PASS] MA-1 mass assignment — anon over-posting with role:maintainer denied on 5 endpoints"; P=$((P+1))
else
  echo "[FAIL] MA-1 mass assignment — ${ma_2xx}/5 endpoints accepted anon over-post with role:maintainer"; F=$((F+1))
fi

echo "[CAT-DONE] 36.Authz-flaws P=${P} F=${F} I=${I} S=${S}"
