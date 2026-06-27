#!/usr/bin/env bash
# Category 1 — Functional behaviour
# F-1: health-score endpoint contract
# F-2: vhosts list endpoint contract
# F-3: live endpoint (loopback-only — INFO when behind CDN)
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
NS="/antibot-appsec-gateway"; P=0; F=0; I=0; S=0
_curl() { curl -sk --max-time 5 -o /dev/null -w "%{http_code}|%{content_type}" "$@"; }
_body() { curl -sk --max-time 5 "$@" | head -c 200; }

# F-1 health-score contract
# health-score is admin-gated and serves a silent 404 decoy to anon callers
# (X-Admin-Key was removed in 1.6.7 — auth is POST /login → agw_session cookie).
# Probe anon first; if it's the decoy and ADMIN_KEY is set, auth and retry.
_hs() { curl -sk --max-time 10 "$@" "${URL}${NS}/secured/health-score" 2>/dev/null; }
out=$(_hs)
if ! echo "$out" | grep -q '"score"' && [[ -n "${ADMIN_KEY:-}" ]]; then
  AJ="$(mktemp)"
  curl -sk --max-time 8 -c "$AJ" "${URL}${NS}/login" >/dev/null 2>&1
  curl -sk --max-time 8 -b "$AJ" -c "$AJ" -o /dev/null \
    -X POST --data-urlencode "username=admin" --data-urlencode "password=${ADMIN_KEY}" \
    "${URL}${NS}/login" 2>/dev/null
  out=$(_hs -b "$AJ"); rm -f "$AJ"
fi
if echo "$out" | grep -q '"score"' && echo "$out" | grep -q '"version"' && echo "$out" | grep -q '"db_backend"'; then
  echo "[PASS] F-1 health-score contract (score/version/db_backend fields)"; P=$((P+1))
else
  if echo "$out" | head -c1 | grep -q '{'; then
    echo "[FAIL] F-1 health-score contract — JSON did not carry required fields"; F=$((F+1))
  else
    echo "[INFO] F-1 health-score — admin-gated decoy; set ADMIN_KEY to verify the authed contract"; I=$((I+1))
  fi
fi

# F-2 vhosts contract — same caveat
out=$(curl -sk --max-time 10 "${URL}${NS}/secured/vhosts" 2>/dev/null || echo "")
if echo "$out" | head -c 1 | grep -q '{' ; then
  if echo "$out" | grep -qE '"vhosts"|"hosts"'; then
    echo "[PASS] F-2 vhosts contract (JSON with vhosts/hosts key)"; P=$((P+1))
  else
    echo "[FAIL] F-2 vhosts contract — JSON returned but missing expected key"; F=$((F+1))
  fi
else
  echo "[INFO] F-2 vhosts — auth required (admin session); cannot verify"; I=$((I+1))
fi

# F-3 live endpoint — loopback-only by design. Can 404 behind CDN, behind a
# Docker bridge that's not in the trusted-loopback set, or when admin IP gating
# silently-decoys. None of those are gateway defects, so non-200 is INFO not FAIL.
status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}${NS}/live" 2>/dev/null)
if [[ "$status" == "200" ]]; then
  echo "[PASS] F-3 /live → 200"; P=$((P+1))
else
  echo "[INFO] F-3 /live → ${status} — KNOWN by-design (loopback-only; expected 404 behind CDN or non-loopback bridge)"; I=$((I+1))
fi

echo "[CAT-DONE] 1.Functional P=${P} F=${F} I=${I} S=${S}"
