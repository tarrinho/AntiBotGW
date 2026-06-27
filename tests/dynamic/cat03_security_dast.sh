#!/usr/bin/env bash
# Category 3 — Security DAST
# Delegates to existing dast-smoke.sh + adds inline real probes for S-1…S-5.
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NS="/antibot-appsec-gateway"

# ── dast-smoke.sh §15a–§15u ───────────────────────────────────────────────
if [[ -x "$ROOT/dast-smoke.sh" ]]; then
  OUT="$(mktemp)"
  if [[ -n "$AK" ]]; then bash "$ROOT/dast-smoke.sh" "$URL" "$AK" > "$OUT" 2>&1 || true
  else bash "$ROOT/dast-smoke.sh" "$URL" > "$OUT" 2>&1 || true; fi
  DSP=$(grep -c 'PASS'  "$OUT" 2>/dev/null)
  DSF=$(grep -c 'FAIL'  "$OUT" 2>/dev/null)
  DSI=$(grep -c 'INFO'  "$OUT" 2>/dev/null)
  echo "[INFO] §15a–§15u via dast-smoke.sh — ${DSP} PASS / ${DSF} FAIL / ${DSI} INFO"
  P=$((P + DSP)); F=$((F + DSF)); I=$((I + DSI))
  rm -f "$OUT"
else
  echo "[INFO] dast-smoke.sh not found — skipping §15a–§15u block"; I=$((I+1))
fi

# ── S-1 TLS posture probe (inline, no testssl.sh required) ───────────────
HOST="${URL#http*://}"; HOST="${HOST%%/*}"
PORT="${HOST##*:}"; [[ "$PORT" == "$HOST" ]] && PORT=""
HNAME="${HOST%%:*}"
[[ -z "$PORT" ]] && case "$URL" in https://*) PORT=443;; http://*) PORT=80;; esac

if [[ "$URL" =~ ^https:// ]] && command -v openssl >/dev/null 2>&1; then
  # Reject old protocols, accept current
  weak_ok=0; current_ok=0
  for v in ssl3 tls1 tls1_1; do
    echo Q | timeout 4 openssl s_client -connect "${HNAME}:${PORT}" -"$v" -servername "$HNAME" </dev/null >/dev/null 2>&1 \
      && weak_ok=$((weak_ok+1))
  done
  for v in tls1_2 tls1_3; do
    echo Q | timeout 4 openssl s_client -connect "${HNAME}:${PORT}" -"$v" -servername "$HNAME" </dev/null >/dev/null 2>&1 \
      && current_ok=$((current_ok+1))
  done
  if [[ "$weak_ok" -eq 0 ]] && [[ "$current_ok" -ge 1 ]]; then
    echo "[PASS] S-1 TLS posture — weak protos all rejected, ${current_ok}/2 modern accepted"
    P=$((P+1))
  elif [[ "$weak_ok" -gt 0 ]]; then
    echo "[FAIL] S-1 TLS posture — ${weak_ok} weak protocol(s) accepted (sslv3/tls1.0/tls1.1)"
    F=$((F+1))
  else
    echo "[INFO] S-1 TLS posture — neither weak nor modern accepted (CDN downgrade or local TLS off)"
    I=$((I+1))
  fi
else
  echo "[INFO] S-1 TLS posture — HTTP target or openssl missing; HTTPS target needed for real check"
  I=$((I+1))
fi

# ── S-2 authn matrix (anonymous → admin endpoints must NOT return 200/JSON) ─
hits=0; misses=0
for ep in /secured/config /secured/controls /secured/metrics /secured/whoami /secured/agents-data /secured/logs-data /secured/vhosts /secured/db-test; do
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}${NS}${ep}" 2>/dev/null)
  if [[ "$status" =~ ^2 ]]; then
    # Got a 2xx anonymously? Bug.
    hits=$((hits+1))
  else
    misses=$((misses+1))
  fi
done
if [[ "$hits" -eq 0 ]]; then
  echo "[PASS] S-2 authn matrix — 8/8 admin endpoints denied anonymous access (no 2xx)"
  P=$((P+1))
else
  echo "[FAIL] S-2 authn matrix — ${hits} of 8 admin endpoints returned 2xx to anonymous caller"
  F=$((F+1))
fi

# ── S-3 fuzzing — random query-string + random header probes ─────────────
crashes=0
for i in $(seq 1 30); do
  q=$(LC_ALL=C tr -dc 'A-Za-z0-9._=&%-' < /dev/urandom 2>/dev/null | head -c 64)
  h=$(LC_ALL=C tr -dc 'A-Za-z0-9._-' < /dev/urandom 2>/dev/null | head -c 32)
  status=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" \
    -H "X-Fuzz: ${h}" "${URL}/?${q}" 2>/dev/null)
  [[ "$status" =~ ^5 ]] && crashes=$((crashes+1))
done
if [[ "$crashes" -eq 0 ]]; then
  echo "[PASS] S-3 fuzzing — 30 random query+header probes, no 5xx"
  P=$((P+1))
else
  echo "[FAIL] S-3 fuzzing — ${crashes}/30 fuzz probes produced 5xx"
  F=$((F+1))
fi

# ── S-4 ZAP-style baseline (inline — minimal OWASP-style assertions) ─────
zap_fails=0
# Robots.txt + .well-known reachable without 5xx
for path in /robots.txt /.well-known/security.txt /sitemap.xml; do
  st=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "${URL}${path}" 2>/dev/null)
  [[ "$st" =~ ^5 ]] && zap_fails=$((zap_fails+1))
done
# Verb tampering
for verb in TRACE TRACK CONNECT DEBUG; do
  st=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" -X "$verb" "${URL}/" 2>/dev/null)
  [[ "$st" =~ ^5 ]] && zap_fails=$((zap_fails+1))
done
if [[ "$zap_fails" -eq 0 ]]; then
  echo "[PASS] S-4 ZAP-style baseline — robots/well-known + verb tampering, no 5xx"
  P=$((P+1))
else
  echo "[FAIL] S-4 ZAP-style baseline — ${zap_fails} probes triggered 5xx"
  F=$((F+1))
fi

# ── S-5 inline bypass corpus (historical bypasses, must NOT 200 unprotected) ─
bypass_fails=0
BYPASS=(
  "/secured/config%2e"                                # path-suffix dot
  "/secured/config?_method=GET"                       # method override
  "/secured/config#"                                  # fragment trick
  "/secured//config"                                  # double slash
  "/secured/config..%2f"                              # traversal-out
  "/SECURED/config"                                   # case mismatch
)
for p in "${BYPASS[@]}"; do
  st=$(curl -sk --max-time 4 -o /dev/null -w "%{http_code}" "${URL}${NS}${p}" 2>/dev/null)
  # Any 2xx with admin path → potential bypass
  [[ "$st" =~ ^2 ]] && bypass_fails=$((bypass_fails+1))
done
if [[ "$bypass_fails" -eq 0 ]]; then
  echo "[PASS] S-5 bypass corpus — ${#BYPASS[@]} historical bypasses all denied"
  P=$((P+1))
else
  echo "[FAIL] S-5 bypass corpus — ${bypass_fails} of ${#BYPASS[@]} bypasses returned 2xx (potential auth bypass!)"
  F=$((F+1))
fi

echo "[CAT-DONE] 3.Security-DAST P=${P} F=${F} I=${I} S=${S}"
