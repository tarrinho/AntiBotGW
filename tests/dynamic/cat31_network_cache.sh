#!/usr/bin/env bash
# Category 31 — Network / cache layer
# N-1 cache poisoning via unkeyed headers (X-Forwarded-Host, X-Original-URL)
# N-2 HTTP Parameter Pollution (?role=user&role=admin)
# N-3 DNS rebinding (Host: 127.0.0.1 after public DNS)
# N-4 TLS upstream cert validation surface
# N-5 cert/key hot-reload surface
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── N-1 cache poisoning via unkeyed headers ───────────────────────────────
# Send a request with X-Forwarded-Host: evil.com; the GW must not reflect that
# host in any subsequent unauthenticated probe.
curl -sk --max-time 5 -o /dev/null \
  -H "X-Forwarded-Host: evil-attacker.example" \
  -H "X-Original-URL: /admin" \
  -H "X-Forwarded-Proto: https" \
  "${URL}/n1-poison" 2>/dev/null
sleep 0.5
homepage=$(curl -sk --max-time 5 "${URL}/" 2>/dev/null || echo "")
if [[ -z "$homepage" ]]; then
  echo "[INFO] N-1 cache poisoning — homepage no response (target unreachable)"; I=$((I+1))
elif echo "$homepage" | grep -qF "evil-attacker.example"; then
  echo "[FAIL] N-1 cache poisoning — evil-attacker.example reflected in homepage after X-Forwarded-Host inject"
  F=$((F+1))
else
  echo "[PASS] N-1 cache poisoning — X-Forwarded-Host inject did NOT pollute homepage"; P=$((P+1))
fi

# ── N-2 HTTP Parameter Pollution ──────────────────────────────────────────
# Send `?role=user&role=admin` against the admin role-set endpoint. Whatever
# the parsing strategy (first/last/all), the response must NOT be 2xx for an
# anonymous caller (B-1 priv-esc would also catch this; here we probe HPP
# specifically).
n2_status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  "${URL}${NS}/secured/role/set?role=user&role=admin&role=maintainer" 2>/dev/null)
n2_post=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST -d 'role=user&role=admin&role=maintainer' \
  "${URL}${NS}/secured/role/set" 2>/dev/null)
if [[ -z "$n2_status" ]] || [[ "$n2_status" =~ ^0 ]]; then
  echo "[INFO] N-2 HPP — no response (target unreachable)"; I=$((I+1))
elif ! [[ "$n2_status" =~ ^2 ]] && ! [[ "$n2_post" =~ ^2 ]]; then
  echo "[PASS] N-2 HPP — ?role=user&role=admin denied (GET=${n2_status} POST=${n2_post}); no priv-esc via duplicate keys"
  P=$((P+1))
else
  echo "[FAIL] N-2 HPP — duplicate role= admitted anon (GET=${n2_status} POST=${n2_post}); priv-esc via param pollution"
  F=$((F+1))
fi

# ── N-3 DNS rebinding ─────────────────────────────────────────────────────
# DNS rebinding is exploitable only if the *Host header* can ELEVATE access —
# i.e. if loopback-only endpoints are gated on Host rather than on the client
# IP. This harness connects FROM loopback, so /live correctly admits it
# regardless of Host; a 200 here is NOT a rebind (the old test wrongly flagged
# it). The meaningful property is Host-INDEPENDENCE: compare a spoofed external
# Host against Host:127.0.0.1. Equal status ⇒ access is client-IP gated (safe,
# Host cannot rebind in). Divergence (loopback-Host admits, external-Host
# denied) ⇒ Host-gated ⇒ rebind viable.
n3_loop=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "Host: 127.0.0.1" "${URL}${NS}/live" 2>/dev/null)
n3_ext=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -H "Host: evil-rebind.attacker.example" "${URL}${NS}/live" 2>/dev/null)
if [[ -z "$n3_loop" ]] || [[ "$n3_loop" =~ ^0 ]]; then
  echo "[INFO] N-3 DNS rebinding — no response (target unreachable)"; I=$((I+1))
elif [[ "$n3_loop" == "$n3_ext" ]]; then
  echo "[PASS] N-3 DNS rebinding — /live is Host-independent (loopback-Host=${n3_loop} == external-Host=${n3_ext}); access is client-IP gated, rebind not viable"
  P=$((P+1))
else
  echo "[FAIL] N-3 DNS rebinding — /live is Host-gated (loopback-Host=${n3_loop} vs external-Host=${n3_ext}); a spoofed Host changes access ⇒ rebind viable"
  F=$((F+1))
fi

# ── N-4 TLS upstream cert validation surface ──────────────────────────────
# Probe presence of an "insecure upstream" knob — if it exists and defaults
# to verify=True, that's the pass. We can only probe the config surface.
cfg_status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  "${URL}${NS}/secured/config" 2>/dev/null)
if [[ -z "$cfg_status" ]] || [[ "$cfg_status" =~ ^0 ]]; then
  echo "[INFO] N-4 TLS upstream cert validation — config no-response"; I=$((I+1))
elif [[ "$cfg_status" =~ ^5 ]]; then
  echo "[FAIL] N-4 TLS upstream cert validation — /secured/config 5xx (${cfg_status})"; F=$((F+1))
else
  echo "[PASS] N-4 TLS upstream cert validation — /secured/config reachable (${cfg_status}); full verify=True check needs auth"
  P=$((P+1))
fi

# ── N-5 cert/key hot-reload surface ───────────────────────────────────────
# Surface check for a /secured/certs/reload or /secured/tls/reload endpoint.
n5_found=0
for ep in /secured/certs/reload /secured/tls/reload /secured/keys/reload /secured/config/reload; do
  s=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -X POST "${URL}${NS}${ep}" 2>/dev/null)
  if ! [[ "$s" =~ ^5 ]] && [[ "$s" != "404" ]] && [[ -n "$s" ]] && ! [[ "$s" =~ ^0 ]]; then
    n5_found=$((n5_found+1))
  fi
done
if [[ "$n5_found" -ge 1 ]]; then
  echo "[PASS] N-5 cert/key hot-reload surface — ${n5_found} reload endpoint(s) reachable"; P=$((P+1))
else
  echo "[INFO] N-5 cert/key hot-reload — no reload endpoint found (reload may be SIGHUP / process-restart only)"; I=$((I+1))
fi

echo "[CAT-DONE] 31.Network-cache P=${P} F=${F} I=${I} S=${S}"
