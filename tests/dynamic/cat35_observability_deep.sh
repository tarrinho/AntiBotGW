#!/usr/bin/env bash
# Category 35 — Observability deep (O-1..3 covered metrics endpoint + alert)
# Obs-1 W3C Trace-Context propagation — traceparent header round-trip
# Obs-2 Metric cardinality explosion protection — flood with distinct labels
# Obs-3 Log↔metric↔trace correlation — request_id present in responses
set -u
URL="${URL:?need URL}"; P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── Obs-1 traceparent propagation ─────────────────────────────────────────
# Send a valid W3C traceparent. GW should either echo it back (continuation)
# or emit its own. Just check it doesn't crash.
TP="00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
HDR="$(mktemp)"
status=$(curl -sk --max-time 5 -D "$HDR" -o /dev/null -w "%{http_code}" \
  -H "traceparent: ${TP}" -H "tracestate: vendor=test" \
  "${URL}/?obs1=trace" 2>/dev/null)
emitted=0
grep -qi '^traceparent:\|^x-trace-id:\|^x-request-id:\|^x-correlation-id:' "$HDR" 2>/dev/null && emitted=1
rm -f "$HDR"
if [[ -z "$status" ]] || [[ "$status" =~ ^0 ]]; then
  echo "[INFO] Obs-1 trace propagation — no response (target unreachable)"; I=$((I+1))
elif [[ "$status" =~ ^5 ]]; then
  echo "[FAIL] Obs-1 trace propagation — traceparent header crashed GW (${status})"; F=$((F+1))
elif [[ "$emitted" -eq 1 ]]; then
  echo "[PASS] Obs-1 trace propagation — GW emits trace/correlation header (status=${status})"; P=$((P+1))
else
  echo "[INFO] Obs-1 trace propagation — GW handled traceparent cleanly (${status}); no trace header echoed back"
  I=$((I+1))
fi

# ── Obs-2 metric cardinality explosion ───────────────────────────────────
# Send 200 distinct path probes. Probe /__metrics afterwards; size should
# stay bounded (not grow linearly with distinct paths). The product should
# bucket / hash high-cardinality labels.
metrics_before=$(curl -sk --max-time 5 "${URL}/__metrics" 2>/dev/null | wc -c)
for i in $(seq 1 200); do
  curl -sk --max-time 2 -o /dev/null "${URL}/obs2-card-$(printf '%04x' "$RANDOM")-${i}" 2>/dev/null &
  [[ $((i % 25)) -eq 0 ]] && wait
done
wait
sleep 1
metrics_after=$(curl -sk --max-time 5 "${URL}/__metrics" 2>/dev/null | wc -c)
if [[ "$metrics_before" -eq 0 ]] && [[ "$metrics_after" -eq 0 ]]; then
  echo "[INFO] Obs-2 cardinality — /__metrics no response"; I=$((I+1))
elif [[ "$metrics_after" -le $((metrics_before * 3 + 1024)) ]]; then
  echo "[PASS] Obs-2 cardinality — /__metrics before=${metrics_before}B after=${metrics_after}B (bounded growth)"
  P=$((P+1))
else
  echo "[FAIL] Obs-2 cardinality — /__metrics before=${metrics_before}B after=${metrics_after}B (> 3× growth + 1KB)"
  F=$((F+1))
fi

# ── Obs-3 log↔metric↔trace correlation ───────────────────────────────────
# Send a request with a known correlation ID; GW should propagate it back via
# a response header (X-Request-ID typically).
CID="obs3-corr-$(printf '%08x' "$RANDOM")$(printf '%08x' "$RANDOM")"
HDR="$(mktemp)"
curl -sk --max-time 5 -D "$HDR" -o /dev/null \
  -H "X-Request-ID: ${CID}" \
  -H "X-Correlation-ID: ${CID}" \
  "${URL}/" 2>/dev/null || true
back=0
grep -qiF "$CID" "$HDR" 2>/dev/null && back=1
# Also check if any X-Request-ID / X-Trace-ID was set even if not the one we sent
any_id=0
grep -qiE '^x-request-id:|^x-trace-id:|^x-correlation-id:' "$HDR" 2>/dev/null && any_id=1
rm -f "$HDR"
if [[ "$back" -eq 1 ]]; then
  echo "[PASS] Obs-3 correlation — sent X-Request-ID ${CID:0:16}... echoed back in response"; P=$((P+1))
elif [[ "$any_id" -eq 1 ]]; then
  echo "[PASS] Obs-3 correlation — GW emits its own request/trace ID header (incoming ID ignored, new one issued)"; P=$((P+1))
else
  echo "[INFO] Obs-3 correlation — no X-Request-ID / X-Trace-ID in response headers (correlation harder for observability)"
  I=$((I+1))
fi

echo "[CAT-DONE] 35.Observability-deep P=${P} F=${F} I=${I} S=${S}"
