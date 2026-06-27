#!/usr/bin/env bash
# Category 30 — Deeper injection (§15c covers 12 basics; S-1..S-5 added 5)
# S-6 SSTI — {{7*7}} / ${7*7} / <%= 7*7 %> / #{7*7} → must not return 49
# S-7 XXE — XML body with external entity → must not return /etc/passwd content
# S-8 LDAP — `*)(uid=*)(|(uid=*` → must not 5xx, no LDAP error leak
# S-9 NoSQL — `[$ne]=1`, `{"$gt":""}` → must not 5xx
# S-10 deserialization — pickle/Java magic bytes → must not 5xx or RCE
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0

# ── S-6 SSTI ──────────────────────────────────────────────────────────────
ssti_hits=0; ssti_5xx=0; ssti_zero=0
for payload in '{{7*7}}' '${7*7}' '<%=7*7%>' '#{7*7}' '${{7*7}}' '{{7*7}}' '@{7*7}'; do
  out=$(curl -sk --max-time 5 "${URL}/?q=${payload}" 2>/dev/null || echo "")
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}/?q=${payload}" 2>/dev/null)
  [[ -z "$status" ]] || [[ "$status" =~ ^0 ]] && ssti_zero=$((ssti_zero+1))
  [[ "$status" =~ ^5 ]] && ssti_5xx=$((ssti_5xx+1))
  # The product would expose SSTI by reflecting "49" in the response.
  echo "$out" | grep -q '49' && ssti_hits=$((ssti_hits+1))
done
if [[ "$ssti_zero" -ge 6 ]]; then
  echo "[INFO] S-6 SSTI — most payloads no-response (target unreachable)"; I=$((I+1))
elif [[ "$ssti_hits" -eq 0 ]] && [[ "$ssti_5xx" -eq 0 ]]; then
  echo "[PASS] S-6 SSTI — 7 template-injection payloads, no 49 reflection, no 5xx"; P=$((P+1))
elif [[ "$ssti_hits" -gt 0 ]]; then
  echo "[FAIL] S-6 SSTI — ${ssti_hits}/7 payloads reflected '49' (template engine evaluated input)"; F=$((F+1))
else
  echo "[FAIL] S-6 SSTI — ${ssti_5xx}/7 payloads triggered 5xx"; F=$((F+1))
fi

# ── S-7 XXE ───────────────────────────────────────────────────────────────
XXE_BODY='<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><cmd>&xxe;</cmd></root>'
out=$(curl -sk --max-time 6 -X POST -H "Content-Type: application/xml" \
  -d "$XXE_BODY" "${URL}/s7-xxe-probe" 2>/dev/null || echo "")
status=$(curl -sk --max-time 6 -o /dev/null -w "%{http_code}" \
  -X POST -H "Content-Type: application/xml" -d "$XXE_BODY" \
  "${URL}/s7-xxe-probe" 2>/dev/null)
if [[ -z "$status" ]] || [[ "$status" =~ ^0 ]]; then
  echo "[INFO] S-7 XXE — no response (target unreachable)"; I=$((I+1))
elif [[ "$status" =~ ^5 ]]; then
  echo "[FAIL] S-7 XXE — body parser 5xx'd (${status}); possible OOM or crash"; F=$((F+1))
elif echo "$out" | grep -qE 'root:x:0:|bin/bash|bin/sh'; then
  echo "[FAIL] S-7 XXE — /etc/passwd content reflected in response (XXE exfil!)"; F=$((F+1))
else
  echo "[PASS] S-7 XXE — XML body with external entity rejected/decoyed cleanly (${status})"; P=$((P+1))
fi

# ── S-8 LDAP injection ────────────────────────────────────────────────────
ldap_5xx=0; ldap_zero=0; ldap_leak=0
for payload in '*)(uid=*' ')(|(uid=*' 'admin)(&(password=*' '*))%00'; do
  enc=$(echo "$payload" | sed 's/ /%20/g;s/(/%28/g;s/)/%29/g;s/|/%7c/g;s/&/%26/g;s/\*/%2a/g;s/=/%3d/g')
  out=$(curl -sk --max-time 5 "${URL}/?username=${enc}" 2>/dev/null || echo "")
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}/?username=${enc}" 2>/dev/null)
  [[ -z "$status" ]] || [[ "$status" =~ ^0 ]] && ldap_zero=$((ldap_zero+1))
  [[ "$status" =~ ^5 ]] && ldap_5xx=$((ldap_5xx+1))
  # LDAP error leak markers
  echo "$out" | grep -qiE 'ldap_error|invalid dn|filter syntax|ldap_search' && ldap_leak=$((ldap_leak+1))
done
if [[ "$ldap_zero" -ge 3 ]]; then
  echo "[INFO] S-8 LDAP injection — most payloads no-response"; I=$((I+1))
elif [[ "$ldap_5xx" -eq 0 ]] && [[ "$ldap_leak" -eq 0 ]]; then
  echo "[PASS] S-8 LDAP injection — 4 payloads, no 5xx, no LDAP error leak"; P=$((P+1))
else
  echo "[FAIL] S-8 LDAP injection — ${ldap_5xx}/4 5xx · ${ldap_leak}/4 leak markers"; F=$((F+1))
fi

# ── S-9 NoSQL injection ───────────────────────────────────────────────────
nosql_5xx=0; nosql_zero=0
PAYLOADS=(
  '?id[$ne]=1'
  '?username[$gt]='
  '?id={"$gt":""}'
  '?where=this.password.length>0'
)
for p in "${PAYLOADS[@]}"; do
  status=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "${URL}${p}" 2>/dev/null)
  [[ -z "$status" ]] || [[ "$status" =~ ^0 ]] && nosql_zero=$((nosql_zero+1))
  [[ "$status" =~ ^5 ]] && nosql_5xx=$((nosql_5xx+1))
done
if [[ "$nosql_zero" -ge 3 ]]; then
  echo "[INFO] S-9 NoSQL injection — most payloads no-response"; I=$((I+1))
elif [[ "$nosql_5xx" -eq 0 ]]; then
  echo "[PASS] S-9 NoSQL injection — 4 operator payloads, no 5xx"; P=$((P+1))
else
  echo "[FAIL] S-9 NoSQL injection — ${nosql_5xx}/4 5xx (operator parsing crashed)"; F=$((F+1))
fi

# ── S-10 insecure deserialization ────────────────────────────────────────
# Python pickle magic (0x80 0x04), Java magic (0xAC 0xED), PHP serialize prefix.
TMP="$(mktemp)"
# Python pickle that builds a benign str
printf '\x80\x04\x95\x0c\x00\x00\x00\x00\x00\x00\x00\x8c\x08hello_w0\x94.' > "$TMP"
status_py=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST -H "Content-Type: application/octet-stream" \
  --data-binary "@${TMP}" "${URL}/s10-deserialize" 2>/dev/null)
# Java serialize header
printf '\xac\xed\x00\x05\x73\x72\x00\x10java.lang.Object\x00\x00\x00\x00\x00\x00\x00\x00' > "$TMP"
status_java=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST -H "Content-Type: application/x-java-serialized-object" \
  --data-binary "@${TMP}" "${URL}/s10-deserialize" 2>/dev/null)
# PHP serialize
echo 'O:8:"stdClass":1:{s:4:"prop";s:5:"value";}' > "$TMP"
status_php=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" \
  -X POST --data-binary "@${TMP}" "${URL}/s10-deserialize" 2>/dev/null)
rm -f "$TMP"
fivexx=0
for s in "$status_py" "$status_java" "$status_php"; do
  [[ "$s" =~ ^5 ]] && fivexx=$((fivexx+1))
done
allzero=0
for s in "$status_py" "$status_java" "$status_php"; do
  [[ -z "$s" ]] || [[ "$s" =~ ^0 ]] && allzero=$((allzero+1))
done
if [[ "$allzero" -eq 3 ]]; then
  echo "[INFO] S-10 deserialization — all payloads no-response"; I=$((I+1))
elif [[ "$fivexx" -eq 0 ]]; then
  echo "[PASS] S-10 deserialization — pickle+Java+PHP magic, no 5xx (py=${status_py} java=${status_java} php=${status_php})"
  P=$((P+1))
else
  echo "[FAIL] S-10 deserialization — ${fivexx}/3 payloads 5xx'd (possible deserializer crash)"; F=$((F+1))
fi

echo "[CAT-DONE] 30.Deep-injection P=${P} F=${F} I=${I} S=${S}"
