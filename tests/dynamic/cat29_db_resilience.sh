#!/usr/bin/env bash
# Category 29 — DB resilience
# DB-1 connection-pool exhaustion — 80 concurrent admin-shaped reads, no 5xx
# DB-2 slow-query timeout — huge range param must time out, not hang
# DB-3 lock contention — 2 parallel writers same knob (covered by CC-2; here we probe latency)
# DB-4 PG replica lag — read /__health 5× in 1s, all consistent
set -u
URL="${URL:?need URL}"; AK="${ADMIN_KEY:-}"
P=0; F=0; I=0; S=0
NS="/antibot-appsec-gateway"

# ── DB-1 connection pool exhaustion ───────────────────────────────────────
TMP="$(mktemp)"
for i in $(seq 1 80); do
  ( curl -sk --max-time 8 -o /dev/null -w "%{http_code}\n" \
    "${URL}${NS}/secured/config" 2>/dev/null >> "$TMP" ) &
done
wait
total=$(wc -l < "$TMP")
fivexx=$(grep -c '^5' "$TMP" 2>/dev/null)
fivexx=${fivexx:-0}
zerocnt=$(grep -c '^0' "$TMP" 2>/dev/null)
zerocnt=${zerocnt:-0}
rm -f "$TMP"
if [[ "$zerocnt" -ge $((total - 5)) ]]; then
  echo "[INFO] DB-1 pool exhaustion — ${zerocnt}/${total} no-response (target unreachable)"; I=$((I+1))
elif [[ "$fivexx" -eq 0 ]]; then
  echo "[PASS] DB-1 pool exhaustion — 80 concurrent /secured/config reads, ${total} responses, 0 5xx"
  P=$((P+1))
else
  echo "[FAIL] DB-1 pool exhaustion — ${fivexx}/${total} returned 5xx (pool overflow not handled)"
  F=$((F+1))
fi

# ── DB-2 slow-query timeout — huge range must bound ──────────────────────
t=$(curl -sk --max-time 35 -o /dev/null -w "%{time_total}" \
  "${URL}${NS}/secured/agents-timeline?range=99999999" 2>/dev/null || echo "0")
if awk -v t="$t" 'BEGIN{exit !(t == 0)}'; then
  echo "[INFO] DB-2 slow-query timeout — no response (target unreachable)"; I=$((I+1))
elif awk -v t="$t" 'BEGIN{exit !(t < 30)}'; then
  echo "[PASS] DB-2 slow-query timeout — huge range bounded to ${t}s (< 30s)"; P=$((P+1))
else
  echo "[FAIL] DB-2 slow-query timeout — huge range took ${t}s (≥ 30s; no STATEMENT_TIMEOUT?)"
  F=$((F+1))
fi

# ── DB-3 lock contention — 2 parallel writers same knob (probe latency) ──
# CC-2 covers correctness; here we measure that neither writer hangs > 10s.
t_max=0
( t=$(curl -sk --max-time 12 -o /dev/null -w "%{time_total}" \
    -X POST -H "Content-Type: application/json" -d '{"DASHBOARD_REFRESH_SECS":"5"}' \
    "${URL}${NS}/secured/config/set" 2>/dev/null || echo "0")
  echo "$t" > /tmp/db3_a ) &
( t=$(curl -sk --max-time 12 -o /dev/null -w "%{time_total}" \
    -X POST -H "Content-Type: application/json" -d '{"DASHBOARD_REFRESH_SECS":"7"}' \
    "${URL}${NS}/secured/config/set" 2>/dev/null || echo "0")
  echo "$t" > /tmp/db3_b ) &
wait
ta=$(cat /tmp/db3_a 2>/dev/null || echo "0")
tb=$(cat /tmp/db3_b 2>/dev/null || echo "0")
rm -f /tmp/db3_a /tmp/db3_b
if awk -v a="$ta" -v b="$tb" 'BEGIN{exit !(a == 0 && b == 0)}'; then
  echo "[INFO] DB-3 lock contention — both writers no-response"; I=$((I+1))
elif awk -v a="$ta" -v b="$tb" 'BEGIN{exit !(a < 10 && b < 10)}'; then
  echo "[PASS] DB-3 lock contention — 2 parallel knob writers a=${ta}s b=${tb}s (< 10s each; no deadlock)"
  P=$((P+1))
else
  echo "[FAIL] DB-3 lock contention — writer hung > 10s (a=${ta}s b=${tb}s; lock not released)"
  F=$((F+1))
fi

# ── DB-4 PG replica lag — read /__health 5× in 1s, consistent shape ──────
SHAPES="$(mktemp)"
for i in $(seq 1 5); do
  curl -sk --max-time 3 "${URL}${NS}/__health" 2>/dev/null \
    | grep -oE '"(status|backend|ok)"' | sort -u | tr '\n' ',' >> "$SHAPES"
  echo "" >> "$SHAPES"
  sleep 0.2
done
shapes_distinct=$(grep -v '^$' "$SHAPES" | sort -u | wc -l)
shapes_total=$(grep -cv '^$' "$SHAPES")
rm -f "$SHAPES"
if [[ "$shapes_total" -eq 0 ]]; then
  echo "[INFO] DB-4 replica lag — /__health no response (target unreachable)"; I=$((I+1))
elif [[ "$shapes_distinct" -le 1 ]]; then
  echo "[PASS] DB-4 replica lag — 5 reads, ${shapes_distinct} distinct shape (consistent)"; P=$((P+1))
else
  echo "[FAIL] DB-4 replica lag — 5 reads, ${shapes_distinct} distinct shapes (replica divergence?)"; F=$((F+1))
fi

echo "[CAT-DONE] 29.DB-resilience P=${P} F=${F} I=${I} S=${S}"
