# AntiBot/WAF GW — Improvement Proposals

> **Historical snapshot — point-in-time review as of v1.8.9 (2026-05-22).**
> This is a dated proposals document, intentionally **not** maintained per release;
> some items may already be implemented in later versions. For current state see
> `CHANGELOG.md` and `MANUAL.md`.

Reviewed against v1.8.9. Organized by tier: **quick win** (1–2 days), **medium** (1 week),
**strategic** (2+ weeks). Within each tier, ordered by impact.

Author: Pedro Tarrinho · Reviewed: 2026-05-22

---

## Quick Wins (1–2 days each)

### QW-1 — Configurable honeypot path list

**Problem:** The 30+ trap paths (`/wp-admin`, `/phpmyadmin`, etc.) are hardcoded in
`config.py`. Adding a custom path requires a code change and image rebuild.

**Fix:** Accept a `HONEYPOT_EXTRA_PATHS` env var (JSON array, same format as
`AUTHORIZED_BOT_UAS`). Merge into the static list at startup. Register as a
`_HOT_RELOAD_KNOB` so operators can add paths live without restart.

**Impact:** Operators can target paths specific to their upstream stack (e.g.
`/admin/login`, `/strapi/admin`, `/wp-json/wp/v2/users`).

---

### QW-2 — In-memory favicon cache

**Problem:** `_favicon_handler`, `_apple_touch_icon_handler`, and `_favicon_svg_handler`
each call `read_bytes()` on disk for every browser request. The files (32KB ICO, 30KB PNG)
never change at runtime.

**Fix:** Cache all three as module-level `bytes` constants at `make_app()` time:
```python
_FAVICON_BYTES     = (_STATIC_DIR / "favicon.ico").read_bytes()
_APPLE_TOUCH_BYTES = (_STATIC_DIR / "apple-touch-icon.png").read_bytes()
_FAVICON_SVG_BYTES = (_STATIC_DIR / "favicon.svg").read_bytes()
```
Eliminates 3 disk reads per page load across all clients.

---

### QW-3 — Bulk unban endpoint

**Problem:** `POST /ban` and `GET /unban` operate per-IP only. After a false-positive
wave (e.g. a CDN egress block), unbanning 200 IPs requires 200 sequential API calls.

**Fix:** `DELETE /secured/bans?reason=<signal>` — unban all IPs whose primary ban reason
matches the given signal. Also: `DELETE /secured/bans?asn=<number>` (unban a whole ASN).
Emit one `event=bulk_unban` structured log line with `count=N`.

---

### QW-4 — Audit log CSV/JSON export

**Problem:** `/secured/audit-log` serves the log via paginated API only. Compliance
hand-off (SOC 2, ISO 27001 evidence) requires bulk export.

**Fix:** Add `GET /secured/audit-log-export?start=<ts>&end=<ts>&format=csv|json` mirroring
the existing `/secured/logs-export` pattern. Streams rows directly from the DB; no
in-memory accumulation.

---

### QW-5 — fnmatch support in SIEM alert rules

**Problem:** `siem_alert_rules` evaluate `reason == <value>` with exact-string matching.
Writing one rule per injection variant (`body-sqli`, `body-xss`, `body-lfi`, `body-rce`,
`body-cmd`, `body-ssrf`) requires 6 separate rules where one `body-*` glob would suffice.

**Fix:** Evaluate `reason` against the rule value using `fnmatch.fnmatch()` before falling
back to exact match. Backward-compatible (existing exact-match rules keep working). Add a
`match_mode: exact|glob` field to the rule schema for clarity.

---

### QW-6 — Behavioral window configurable

**Problem:** `BEHAVIOR_WINDOW=30` (seconds) and `BEHAVIOR_MAX_REGULAR=8` (requests) are
hardcoded constants in `config.py`. An attacker aware of these values paces at 7 req/30s
indefinitely without triggering the signal.

**Fix:** Expose as env vars with the existing defaults:
```
BEHAVIOR_WINDOW_SECS=30
BEHAVIOR_MAX_REGULAR=8
```
Register both in `_HOT_RELOAD_KNOBS`. Operators can tighten thresholds without a rebuild.

---

## Medium Impact (≈1 week each)

### M-1 — Per-vhost risk weight overrides

**Problem:** All 120+ signal weights are global. A `/api/health` route and a `/login`
route share the same sensitivity. Operators running multi-tenant backends or mixed-trust
endpoints can't tune signal weights per vhost.

**Fix:** Extend the vhost config schema with an optional `risk_overrides` dict:
```json
{"hostname": "app.example.com", "risk_overrides": {"ua-non-browser": 5, "behavior": 15}}
```
In the scoring pipeline, check `vc("risk_overrides")` and merge over the global
`RISK_WEIGHTS` for the current request's vhost. Persist overrides in `vhosts.json` /
vhost DB row. Expose per-vhost weight sliders in the vhost-policy dashboard.

---

### M-2 — DB-configurable signal weights (Controls UI)

**Problem:** `RISK_WEIGHTS` (120+ entries) is a hardcoded dict in `config.py`. Changing a
single weight requires modifying source code and rebuilding the image. The Controls
dashboard already hot-reloads knobs — the same mechanism could serve weight sliders.

**Fix:**
1. Store weight overrides in a new `signal_weights` SQLite/Postgres table
   (`key TEXT PRIMARY KEY, weight REAL, updated_at REAL`).
2. At startup, load overrides and merge over `RISK_WEIGHTS`.
3. `db_load_config()` propagates changes to all modules.
4. Add a "Signal Weights" panel to the Controls dashboard with a numeric input per signal,
   a Reset-to-default button, and an audit-log entry on every change.

**Impact:** Operators tune sensitivity without rebuilds. Weight history is auditable.

---

### M-3 — Complete the Detector protocol

**Problem:** `detection/base.py` and `detection/detectors.py` define a `Detector`
protocol and registry, but only `LlmHeuristicDetector` is registered. The other 17
detectors are still called as free functions scattered across `protect()`. This makes
adding, removing, or reordering detectors a surgical edit of the 3000-line proxy handler.

**Fix:** Wrap each detector as a `Detector` implementor with:
- `name: str` — matches the signal key
- `enabled() -> bool` — reads its kill-switch knob
- `check(request, state, ip) -> list[tuple[str, float]]` — returns `[(reason, score)]`
- `order: int` — existing signal order (1/2/3)

Replace the 17 direct call sites in `protect()` with a single registry loop:
```python
for det in DETECTOR_REGISTRY.enabled_for_order(order):
    for reason, score in det.check(request, s, ip):
        await update_risk(track_key, reason, ip, score)
```

Enables: hot-plug custom detectors, uniform enable/disable, easier unit testing.

---

### M-4 — IP-based ban persistence (survive key rotation)

**Problem:** Bans are stored by `track_key` (derived from session cookie + fingerprint).
Rotating `SESSION_KEY` via `/rotate-keys` invalidates all track_keys — a bot that was
`REALLY_BAN`ned (30 days) becomes unbanned immediately after a key rotation.

**Fix:** For bans at severity ≥ `HOSTILE_BAN_SECS`, also write `(ip, banned_until,
reason)` to a `ip_bans` SQLite/Postgres table. On each request, check the table for the
raw client IP *before* identity derivation. Key rotation no longer affects persistent bans.
The existing track_key ban path remains for short-duration soft bans.

---

### M-5 — Upstream latency alerting

**Problem:** The circuit breaker tracks upstream 5xx failures only. A slow upstream
(500ms p95 instead of 20ms p95) won't trigger any alert until it causes timeouts. By then,
real users are already experiencing degraded service.

**Fix:**
1. Record `upstream_latency_ms` on every proxied response (already measured as
   `resp.headers` parse delta — add it to the structured log line).
2. Add a `p95_latency_ms` field to `_sample_service_metrics_loop`.
3. Emit a `upstream_slow` WARN slog + webhook event when rolling p95 exceeds
   `UPSTREAM_LATENCY_WARN_MS` (default: 500ms, configurable).
4. Surface a "Latency" chart on the Service dashboard alongside the existing error-rate
   chart.

---

### M-6 — Redis ban retry queue

**Problem:** `_shared_ban_set()` fires once with a 0.5s timeout and swallows all errors.
If Redis is down or slow at the moment of a ban event, the ban won't propagate to other
replicas. There's no recovery path.

**Fix:** On Redis failure, push the ban to a local `_pending_redis_bans` deque (bounded at
1000 entries). A background coroutine retries the deque every 10s with exponential backoff.
On Redis reconnect, the pending bans drain. Emit `redis_ban_queued` / `redis_ban_flushed`
log events so operators can observe the backlog.

---

### M-7 — Dry-run / simulation mode for Controls

**Problem:** Operators can't safely test "what happens if I lower `RISK_BAN_THRESHOLD`
to 30?" without affecting live traffic. There's no way to evaluate a configuration change
before applying it.

**Fix:** Implement `POST /secured/controls-simulate` that accepts a synthetic request
profile (`{ip, ua, path, headers}`) and a config override dict, scores the request against
the overridden config without touching `ip_state`, and returns:
```json
{
  "signals": [{"name": "ua-non-browser", "score": 25}, ...],
  "total_score": 47,
  "verdict": "soft-challenge",
  "would_ban_with_threshold_30": true
}
```
Wire into the Controls dashboard as a "Test Request" panel (already sketched in
`rules.md §15d`).

---

## Strategic (2+ weeks)

### S-1 — Coordinated attack detection (cross-IP clustering)

**Problem:** The gateway bans per-identity. A distributed credential stuffing or
content-scraping attack from 200 IPs (each below the rate limit) is invisible — no single
IP trips any threshold.

**Fix:**
1. Maintain a sliding-window counter per `(ASN, path_prefix, 5-min bucket)`.
2. When `N` distinct IPs from the same ASN hit the same path prefix within the window,
   emit `asn-coordinated-scan` signal against all participating IPs simultaneously.
3. Thresholds: `COORD_ASN_IP_COUNT=20`, `COORD_WINDOW_SECS=300` (configurable).
4. Redis: share the counter across replicas so distributed attacks against a fleet are
   detected even when each replica sees only a fraction of the traffic.

This closes the "low-and-slow distributed" gap that single-IP behavioral detection
inherently misses.

---

### S-2 — Traffic baseline + anomaly alerting

**Problem:** The detector engine has no concept of expected traffic volume. A sudden 10×
request spike at 3AM is suspicious; the same spike at 2PM on a Monday is not. All
threshold-based detectors fire on absolute counts, not deviation from baseline.

**Fix:**
1. In `_sample_service_metrics_loop`, track a per-hour rolling baseline
   (EMA with α=0.1) of `requests_per_minute`, `unique_ips_per_minute`,
   `blocked_per_minute`.
2. Emit `traffic-anomaly` WARN slog + webhook event when current rate exceeds
   `N × baseline` (default: `ANOMALY_MULTIPLIER=5`).
3. Surface the baseline bands as a shaded region on the main dashboard traffic chart.
4. Expose `/secured/baseline-data` for operators to review learned baselines and
   manually reset them after planned traffic events (marketing campaign, load test).

---

### S-3 — Canary injection in CSS and SVG responses

**Problem:** `_inject_canary` runs only on `text/html` and `application/json`. LLM agents
that fetch full-page resources (stylesheets, inline SVGs, XML sitemaps) evade canary-echo
detection because those content types are not instrumented.

**Fix:**
- CSS: inject a hidden `content` property in a zero-size pseudo-element:
  ```css
  .agw-t::before{content:"agw-<token>";display:none;width:0;height:0}
  ```
- SVG: inject a `<desc>` element with the token.
- XML (non-SOAP): inject a `<!-- agw-<token> -->` comment.

The canary-echo detection in `_scan_request_for_canary` already checks all inbound
headers and bodies — extend the scan to CSS `content:` values and XML comment nodes.
Token TTL and signing logic are unchanged.

---

### S-4 — Adaptive PoW difficulty

**Problem:** `POW_DIFFICULTY=5` (~16M hashes, ≈2s on a mid-range phone) is fixed for all
clients. A botnet with GPU acceleration solves it in <10ms. A real user on a budget
Android phone struggles for 10+ seconds.

**Fix:**
1. Track observed `solve_time_ms` per challenge. Maintain a rolling p50 per UA class
   (mobile, desktop, headless).
2. Serve difficulty dynamically: `mobile p50 < 500ms → difficulty=4`;
   `headless UA → difficulty=7`; `default → difficulty=5`.
3. Encode the difficulty into the PoW token so the verifier knows what was asked.
4. Cap min/max: `POW_DIFFICULTY_MIN=3`, `POW_DIFFICULTY_MAX=8` (configurable).

**Impact:** Legitimate mobile users get a faster challenge; bots face a harder one.
Difficulty asymmetry improves as the model learns per-client-class solve times.

---

### S-5 — Detector protocol + custom detector hot-loading

**Depends on:** M-3 (complete Detector protocol)

**Problem:** Operators with domain-specific bot patterns (e.g. a known scraper UA prefix
for a competitor's data collection tool) currently need to fork the codebase or add custom
rules via the limited `CUSTOM_RULES` JSON DSL.

**Fix:** Once the Detector protocol is complete (M-3), add:
1. A `CUSTOM_DETECTORS_DIR` env var pointing to a directory of Python files.
2. At startup, `importlib.import_module` each file and register any class implementing
   `Detector` into `DETECTOR_REGISTRY`.
3. File changes trigger a `SIGHUP`-based reload (or a `/secured/reload-detectors` endpoint).

Operators write standard Python detectors with access to `request`, `ip_state`, and the
`slog` structured logger — no gateway source changes required.

---

### S-6 — Remove `import *` from proxy.py

**Problem:** `proxy.py` uses `from X import *` for 12 packages, landing 200+ symbols in
one namespace. Later stars silently shadow earlier ones. Any rename in a submodule can
break proxy.py at runtime without a compile-time error. The explicit re-exports at lines
47–152 already do the right thing for tests.

**Fix:** Convert all star imports to explicit named imports. The explicit re-export block
stays (for test-suite backward compatibility). This is a pure refactor — no behavior
change — but makes the dependency graph analyzable by IDEs, mypy, and ruff.

**Effort note:** ~200 import lines to enumerate. Feasible as a single focused PR; the test
suite provides full regression coverage.

---

## Security Hardening

### SH-1 — SSRF guard on webhook + reputation URLs

**Problem:** `_assert_upstream_public()` guards the upstream URL against SSRF. But
`WEBHOOK_URL`, `ABUSEIPDB_URL`, and `CROWDSEC_LAPI_URL` accept operator-controlled values
without the same check. An operator with DB write access (via Settings UI) could configure
a webhook pointing to `http://169.254.169.254/` or a private Redis endpoint.

**Fix:** Apply `_assert_upstream_public()` (or a variant that allows localhost for
CrowdSec's typical sidecar config) to all outbound HTTP URLs at the point they are
persisted to `secrets_kv`. Emit `ssrf_guard_blocked` WARN slog on rejection.

---

### SH-2 — Admin key query-string logging audit

**Problem:** `_strip_admin_key_from_qs()` removes `?key=` from proxied URLs and from
dashboard links. However, aiohttp's access logger (if enabled) records the raw
`request.path_qs` before the middleware strips it. Confirm the key never appears in
container stdout — if it does, the stripping must move to the server-level request hook
rather than middleware.

**Fix:** Add a `test_admin_key_not_in_access_log` regression test that enables aiohttp
access logging, sends a request with `?key=<ADMIN_KEY>`, and asserts the key does not
appear in the captured log output.

---

### SH-3 — Rate-limit the PoW solve endpoint

**Problem:** `GET /__pow` (issue challenge) and the solve verification path have no
per-IP rate limit beyond the general token bucket. An attacker can flood the challenge
issuance endpoint to enumerate token space or DoS the HMAC computation.

**Fix:** Apply a tight IP-level rate limit on `GET /__pow` (e.g. 5 req/min per IP,
separate from the main bucket). Challenges issued to the same IP within the window reuse
the same token (idempotent issue).

---

## Observability

### O-1 — OpenTelemetry traces

The gateway collects latency and signal data but exports none of it to a tracing backend.
Adding `opentelemetry-sdk` + `opentelemetry-instrumentation-aiohttp-server` would expose
per-request spans (detection pipeline latency, upstream latency, scoring time) to any
OTLP-compatible collector (Jaeger, Tempo, Datadog).

Trace data would make M-5 (upstream latency alerting) trivially implementable as a
Grafana alert rule instead of bespoke gateway code.

---

### O-2 — Structured startup summary

Currently, startup emits a mix of `print()` calls and `slog()` events. A single
`startup_complete` structured event with all active integrations, knob counts, risk
threshold values, and detected config warnings (e.g. `POSTGRES_DSN` empty, `ADMIN_KEY`
default) would make container log parsing in ELK / Loki trivial.

---

## Effort / Impact Matrix

| ID | Area | Effort | Impact |
|----|------|--------|--------|
| QW-1 | Configurable honeypot paths | XS | Medium |
| QW-2 | Favicon in-memory cache | XS | Low |
| QW-3 | Bulk unban endpoint | S | High |
| QW-4 | Audit log export | S | Medium |
| QW-5 | fnmatch in SIEM rules | S | Medium |
| QW-6 | Behavioral window configurable | XS | Medium |
| M-1 | Per-vhost risk weight overrides | M | High |
| M-2 | DB-configurable signal weights | M | High |
| M-3 | Complete Detector protocol | L | High |
| M-4 | IP-based ban persistence | M | High |
| M-5 | Upstream latency alerting | M | Medium |
| M-6 | Redis ban retry queue | S | Medium |
| M-7 | Dry-run simulation mode | M | High |
| S-1 | Coordinated attack detection | XL | Very High |
| S-2 | Traffic baseline + anomaly | L | High |
| S-3 | Canary in CSS/SVG | M | Medium |
| S-4 | Adaptive PoW difficulty | M | High |
| S-5 | Custom detector hot-loading | L | High |
| S-6 | Remove import * from proxy.py | M | Low |
| SH-1 | SSRF guard on webhook URLs | S | High |
| SH-2 | Admin key log audit | S | High |
| SH-3 | Rate-limit PoW endpoint | S | Medium |
| O-1 | OpenTelemetry traces | L | Medium |
| O-2 | Structured startup summary | S | Low |

**Effort key:** XS < 4h · S < 1d · M ≈ 3–5d · L ≈ 1–2w · XL > 2w

---

*This document is living — update as items are implemented or reprioritized.*
