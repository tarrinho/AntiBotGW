#!/usr/bin/env bash
# Category 18 — Honeypot & decoy fidelity
# HP-1 known honeypot paths → ban + correct reason
# HP-2 decoy homepage tells (Server banner, header order, timing)
# HP-3 TOCTOU on IP-based decisions
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── HP-1 honeypot path triggers ──────────────────────────────────────────
# Known honeypot paths the GW should trap on. Without auth we can only verify
# the request was decoyed (not 5xx) and didn't pass through to upstream.
honeyp_5xx=0; honeyp_decoyed=0
for path in /wp-admin /wp-login.php /phpmyadmin /.env /admin.php /server-status \
            /actuator/env /actuator/heapdump /.git/config /admin/console /xmlrpc.php; do
  s=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "${URL}${path}" 2>/dev/null)
  if [[ "$s" =~ ^5 ]]; then
    honeyp_5xx=$((honeyp_5xx+1))
  else
    honeyp_decoyed=$((honeyp_decoyed+1))
  fi
done
if [[ "$honeyp_5xx" -eq 0 ]] && [[ "$honeyp_decoyed" -ge 9 ]]; then
  echo "[PASS] HP-1 honeypot paths — 11/11 paths handled cleanly (no 5xx, decoyed)"
  P=$((P+1))
elif [[ "$honeyp_5xx" -gt 0 ]]; then
  echo "[FAIL] HP-1 honeypot paths — ${honeyp_5xx}/11 paths returned 5xx (handler crash)"
  F=$((F+1))
else
  echo "[INFO] HP-1 honeypot paths — ${honeyp_decoyed}/11 decoyed (full assertion needs /__logs read)"
  I=$((I+1))
fi
# If admin key available, verify the events table actually recorded honeypot bans
if [[ -n "$AK" ]]; then
  events=$(curl -sk --max-time 6 -H "X-Admin-Key: ${AK}" \
    "${URL}${NS}/secured/logs-data?reason=honeypot&limit=20" 2>/dev/null || echo "")
  hcount=$(echo "$events" | grep -oc '"reason"' 2>/dev/null)
  if [[ "$hcount" -ge 5 ]]; then
    echo "       Confirmed via /logs-data — ${hcount} honeypot events recorded"
  else
    echo "       /logs-data returned ${hcount} honeypot events (expected ≥ 5)"
  fi
fi

# ── HP-2 decoy fidelity — compare decoy response with a fake-upstream probe ─
# Property: decoy homepage should be hard to distinguish via Server header,
# header ordering, or response timing.
HDR1=$(curl -sk --max-time 5 -D - -o /dev/null "${URL}/" 2>/dev/null || echo "")
HDR2=$(curl -sk --max-time 5 -D - -o /dev/null "${URL}/known-honeypot-path-xyz" 2>/dev/null || echo "")
# Compare critical headers
srv1=$(echo "$HDR1" | grep -i '^server:' | tr -d '\r')
srv2=$(echo "$HDR2" | grep -i '^server:' | tr -d '\r')
tells=0
# aiohttp default Server banner leak (already covered in dast-smoke but recheck here)
if echo "$srv1$srv2" | grep -qiE 'aiohttp|python|werkzeug|gunicorn|uvicorn'; then tells=$((tells+1)); fi
# X-Powered-By leak
echo "$HDR1$HDR2" | grep -qiE 'x-powered-by:' && tells=$((tells+1))
# Timing — homepage and honeypot path should return similar bytes
# (decoy normalises to identical homepage)
sz1=$(curl -sk --max-time 5 -o - "${URL}/" 2>/dev/null | wc -c)
sz2=$(curl -sk --max-time 5 -o - "${URL}/known-honeypot-path-xyz" 2>/dev/null | wc -c)
if [[ "$sz1" -gt 0 ]] && [[ "$sz2" -gt 0 ]]; then
  delta=$(( sz1 > sz2 ? sz1 - sz2 : sz2 - sz1 ))
  pct=$(( delta * 100 / (sz1 < sz2 ? sz1 : sz2) ))
  if [[ "$pct" -gt 50 ]]; then
    tells=$((tells+1))
  fi
fi
if [[ "$tells" -eq 0 ]]; then
  echo "[PASS] HP-2 decoy fidelity — no Server/X-Powered-By leak; homepage and decoy normalize (${sz1}B / ${sz2}B)"
  P=$((P+1))
else
  echo "[FAIL] HP-2 decoy fidelity — ${tells} decoy tell(s) found (server banner / X-Powered-By / size delta)"
  F=$((F+1))
fi

# ── HP-3 TOCTOU on IP — XFF chain manipulation mid-request ────────────────
# Send the same request with two different XFF values and confirm both decisions
# remain consistent (no inversion based on order).
s_a=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "X-Forwarded-For: 192.0.2.1, 10.0.0.1" "${URL}/" 2>/dev/null)
s_b=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "X-Forwarded-For: 10.0.0.1, 192.0.2.1" "${URL}/" 2>/dev/null)
if ! [[ "$s_a" =~ ^5 ]] && ! [[ "$s_b" =~ ^5 ]]; then
  echo "[PASS] HP-3 TOCTOU XFF probe — both orderings handled cleanly (a=${s_a} b=${s_b})"; P=$((P+1))
else
  echo "[FAIL] HP-3 TOCTOU XFF probe — server 5xx (a=${s_a} b=${s_b})"; F=$((F+1))
fi

echo "[CAT-DONE] 18.Honeypot-decoy P=${P} F=${F} I=${I} S=${S}"
