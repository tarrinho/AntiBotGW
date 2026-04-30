# AppSecGW/1.5.2

**Hardened Reverse Proxy with Layered Anti-Automation Defenses**
**Implementation, Hardening & CVE-Patching Report**

| | |
|---|---|
| Author | Pedro Tarrinho |
| Date | 2026-04-28 |
| Stack | Python 3.14 / aiohttp 3.13 / SQLite WAL / Chainguard Wolfi (distroless) |
| Image | `appsec-antibot-gw:1.5.2` (79 MB, Trivy: 0 CVEs) |
| Document version | 1.3 — supersedes 1.0 / 1.1 / 1.2 |
| Print-ready PDF  | [AppSecGW-1.4-Report.pdf](AppSecGW-1.4-Report.pdf) |

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Architecture](#2-architecture)
3. [Protection layers](#3-protection-layers)
4. [New in 1.3](#4-new-in-13)
5. [CVE status (Trivy)](#5-cve-status-trivy)
6. [Security review history](#6-security-review-history)
7. [Configuration](#7-configuration)
8. [Appendix](#8-appendix)

---

## 1. Executive summary

**AppSecGW/1.5.2** is a hardened reverse HTTP proxy designed to sit in front of
arbitrary upstream applications. Version 1.3 adds full WebSocket bridging,
SSO-aware redirect rewriting, edge-injected security response headers, IP-based
admin gating, and a transition to a Chainguard Wolfi-based distroless container
that reports **zero CVEs** on Trivy scans.

| Property | v1.2 (Debian-slim) | v1.3 (Chainguard Wolfi) |
|---|---|---|
| Image size | 168 MB | **79 MB** (-53 %) |
| Trivy findings (any severity) | 35 (6 HIGH, 29 MEDIUM) | **0** |
| Python interpreter | 3.13.13 | 3.14.4 |
| aiohttp | 3.11 | 3.13.5 |
| OpenSSL | 3.0.x | 3.5.5 |
| Patch cadence | Debian release schedule | Chainguard SLA: HIGH < 48 h |
| WebSocket support | none | full bidirectional bridge |
| SSO redirect rewriting | none | Location + redirect_uri + Set-Cookie Domain |
| Admin IP allowlist | n/a | `ADMIN_ALLOWED_IPS` |
| Edge security headers | none | 9 headers injected on HTML |
| Static-asset RL exemption | n/a | per-identity bucket exempt for asset GETs |

---

## 2. Architecture

### 2.1 Topology

```
                  client (browser, HTTPS)
                    │
                    ▼
       ┌───────────────────────────┐
       │  TLS terminator           │   nginx / Cloudflared / Caddy
       └─────────────┬─────────────┘
                     │ HTTP loopback
                     ▼
       ┌─────────────────────────────────────┐
       │  AppSecGW/1.5.2  (Chainguard Wolfi)   │
       │   • read-only, non-root, cap-drop ALL│
       │   • aiohttp 3.13 + SQLite WAL       │
       │   • 13 detection layers + WS bridge │
       │   • SSO redirect rewriting          │
       │   • 9 edge-injected security hdrs   │
       │   • 2 admin dashboards (IP-gated)   │
       └─────────────┬───────────────────────┘
                     │ HTTPS w/ verified cert
                     ▼
              upstream service
       (configured exclusively via $UPSTREAM env)
```

### 2.2 Container hardening (verified)

| Control | Value | Why |
|---|---|---|
| `USER 65532:65532` | Chainguard `nonroot` | RCE inside Python lands as unprivileged user |
| `--read-only` | FS read-only | Tmpfs only on `/tmp` + named volume on `/data` |
| `--cap-drop ALL` | 0 capabilities | No raw sockets, ptrace, mount, ... |
| `--security-opt no-new-privileges` | true | Defeats setuid escalation |
| `--security-opt apparmor=docker-default` | applied | MAC profile |
| `--init` | tini PID 1 | Signal handling + zombie reaping |
| `--ipc=private` | own SHM/MQ namespace | No IPC leakage between containers |
| `--network antibot-net` | user-defined bridge | Off the default bridge metadata |
| `--pids-limit` | 200 | Fork-bomb resistance |
| `--memory / --memory-swap` | 256 M / 256 M | No swap; bounds memory exhaustion |
| `--cpus` | 1.0 | Bounds CPU exhaustion |
| `--ulimit nofile` | 4096:4096 | Bounds file-descriptor exhaustion |
| `--ulimit nproc` | 200:200 | Defence-in-depth alongside pids-limit |
| `--ulimit core` | 0:0 | No core dumps (no info leak via crash) |
| `--log-opt max-size, max-file` | 10 m, 3 files | Bounded log disk usage |
| `--tmpfs /tmp` | 8 m, nosuid, nodev, noexec | No exec from scratch dir |
| HEALTHCHECK | unauth `/__live` | Real liveness, not mistaken for decoy |
| Trivy CVE scan | 0 findings (any severity) | Wolfi base + active patching |

### 2.3 Main metrics dashboard — example screenshot

![AppSecGW main dashboard](../img/dashboard.png)

> Figure 1 — `/__dashboard`. New in v1.3: the timeline now plots three series
> (total / **allowed** in green / blocked in red), and the Live Events
> panel highlights allowed connections with a green left bar + green tag.
> Top-row counters (Total / Allowed / Blocked / Uptime) and Block-reason
> breakdown unchanged.

### 2.4 In-process state model

Per-identity tracking uses a hybrid key:

* Browser with valid signed cookie → `HMAC(SESSION_KEY, "sess|" + sid + "|" + fingerprint)`
* Cookieless client → `HMAC(SESSION_KEY, "anon|" + fingerprint + "|" + ip)`

The fingerprint excludes `Sec-Ch-Ua*` Client Hints (browsers omit them on
sub-resource fetches, which used to split a single browser into multiple
identities and cause false-positive bans on JS-heavy SPAs). A periodic prune
task evicts idle identities (> 24 h) and caps the dictionary at
`MAX_IDENTITIES` (default 100k) to bound memory.

---

## 3. Protection layers

13 ordered detection & mitigation layers. All non-PoW blocks return the silent
decoy (upstream homepage as `200 OK`) so an attacker cannot enumerate which
layer fired.

### 3.1 Layer 0 — Path / method / host gating

* Reject control bytes (`0x00`–`0x1F`, `0x7F`) in `request.path` /
  `query_string` → 400.
* Method allowlist (env `ALLOWED_METHODS`, default `GET,HEAD,POST,OPTIONS`)
  → 405 outside it.
* Optional Host allowlist (env `ALLOWED_HOSTS`) → silent decoy on mismatch.
* Admin endpoints (`/__*` except `/__live`): require admin key + (when set)
  source IP in `ADMIN_ALLOWED_IPS`.

### 3.2 Layer 1 — Identity ban

Banned identity → silent decoy. Bans expire automatically (1 h default).

### 3.3 Layer 2 — Honeypot paths

40+ scanner targets (`/wp-admin`, `/.env`, `/.git/config`, cloud metadata
IMDS, Spring `/actuator/*`, etc.). Hit → risk += 50.

### 3.4 Layer 3 — Suspicious-path patterns

26 boundary-anchored regex patterns. v1.3 tightened to file-only matches
(e.g. `(^|/)passwd(\.[a-z0-9]+|$)`) so legitimate module names like
`password-recovery` or `credentials-manager` no longer false-fire.

### 3.5 Layer 4 — User-Agent filter

UA empty / too short / blocklisted (60+ entries: HTTP libs, scanners, named
AI agents, headless browsers) / lacking a known browser token (Mozilla,
Safari, Chrome, ...).

### 3.6 Layer 5 — AI-probe paths

Direct denial of OpenAPI / Swagger / `llms.txt` / model-discovery probes.

### 3.7 Layer 6 — Header completeness scoring

Score 0–7 of `Accept-Language`, `Accept-Encoding`, `Accept`,
`Sec-Fetch-Site/Mode/Dest`, `Sec-Ch-Ua`. Score 0 with browser UA →
`ai-headers-empty`.

### 3.8 Layer 7 — Path-discipline

* Enumeration: more than `ENUM_THRESHOLD` (default 300) distinct paths from
  one identity → `ai-enumeration`.
* No-asset agent: ≥ 25 HTML loads with 0 static fetches → `ai-no-assets`.

### 3.9 Layer 8 — Socket-IP rate limit

Token bucket keyed strictly by `request.remote` (kernel-observed peer IP).
Default 60 burst / 8 tokens-per-sec. Static-asset GETs participate in this
layer (defends against UA-rotation flood).

### 3.10 Layer 9 — Per-identity rate limit

Secondary token bucket. Default 30 burst / 2 tokens-per-sec. v1.3 **exempts
static-asset GETs** (CSS/JS/img/font/media) so SPAs can burst-load 30+ assets
without exhausting the bucket.

### 3.11 Layer 10 — Behavioural timing

Three orthogonal tests on the last 16 inter-request intervals: σ/μ < 0.05,
lag-1 autocorrelation > 0.85, 50 ms-bin majority > 70 %. v1.3 **skips this
check** for sessions with valid cookies and for static-asset GETs (browsers
queue asset fetches with very regular timing and used to trip this layer).

### 3.12 Layer 11 — Proof-of-Work

Bound to `METHOD:path`; replay-protected via seen-set. v1.3 makes PoW
**opt-in per path**: `POW_REQUIRED_PATHS` env (default empty); legitimate
JS/REST traffic is no longer challenged. Set `POW_REQUIRE_ALL_WRITES=1` to
revert the previous "all writes need PoW" behaviour.

### 3.13 Layer 12 — Risk-score model

Weighted scoring; ban at threshold (50 normal, 100 NAT-like). v1.3 changed
two weights: `behavior` 25 → 10 (a single timing trip can no longer push to
ban) and `rate-limit` / `rate-limit-ip` 0 (throttling is mitigation, not
evidence of malice). Score decays with 1 h half-life.

### 3.14 Layer 13 — Honey-link injection (post-flight)

Hidden `<div>` with three honeypot links inserted before the document's
closing `</body>`. Now bails out if a `<script>` tag follows the chosen
`</body>` position (avoids corrupting JS string literals).

---

## 4. New in 1.4

Five additions on top of the v1.3 hardening base.

### 4.0.1 JS challenge (Turnstile-backed cookie gate)

Earlier iterations of this control stacked client-computed primitives — SHA-256 Proof-of-Work, browser-API probe with cross-validation, anchor-fetch proof, sub-second timing windows — to try to distinguish real browsers from scripted clients. Empirically every one of those layers was bypassable in pure Python in ~1 s per session. They were *bot-cost amplifiers*, not security boundaries, and have been removed.

The replacement is a Turnstile-backed cookie gate. Active only when `JS_CHALLENGE=1` AND both `TURNSTILE_SITEKEY` and `TURNSTILE_SECRET` are configured; without those keys the feature is a no-op and a startup banner notes the disabled state.

When the gate is active:

- Every non-static, non-admin, non-opted-out request must carry a valid `chal` cookie.
- The first HTML `GET` without one receives a challenge page that renders the Cloudflare Turnstile widget. On success the widget POSTs `cf-turnstile-response` to `/__challenge`; the gateway verifies it via Cloudflare's `siteverify` endpoint together with the source IP, and issues a 1 h cookie bound to **(UA + IP-tier hash + JA4 hash)**.
- Cookieless API / XHR / POST hits are silent-decoyed (200 OK with cached upstream `/`), keeping the gateway invisible to scanners.

The cookie's IP-tier (v4 /24, v6 /48) is carried as an opaque HMAC hash so the wire format never leaks RFC1918 / internal-pod IPs. The JA4 binding (`JS_CHAL_BIND_JA4=1`, opportunistic) ties the cookie to the TLS handshake observed by a trusted upstream (`JA4_TRUSTED_PEERS`); a leaked cookie cannot be replayed under a different TLS stack. `JS_CHAL_REQUIRE_JA4=1` turns JA4 presence into a hard requirement at `/__challenge`. The per-request JA4 is recorded in the event log so operators can populate `JA4_DENY_LIST` from real traffic.

The Turnstile token is the only check on this endpoint that scripted clients cannot fabricate locally — it is minted server-side by Cloudflare. That is the durable boundary; the rest of the gateway's layers (UA filter, header completeness, behavioral, rate-limits, risk-score, bot-trap, body-pattern matching, slowloris) remain active as cost amplifiers but no longer claim to be hard walls.

### 4.0.2 Body pattern matching

`BODY_PATTERN_MATCH=1` extends Layer 3's suspicious-path regex set to `POST/PUT/PATCH` bodies. Scans only text-ish content types (JSON / urlencoded / plain / XML), bounded at the first 64 KiB. Markers: SQLi (`UNION SELECT`, `OR 1=1`), XSS (`<script>`, `javascript:`, `onerror=`), SSTI (`{{...}}`, `{%...%}`), traversal, command injection.

### 4.0.3 Bot-trap form fields

`BOT_TRAP_FORMS=1` auto-injects a hidden `<input>` into every HTML `<form>` in proxied responses (`position:absolute;left:-9999px;visibility:hidden` + ARIA hidden + `tabindex=-1` + `autocomplete=off`). Field name is per-process random and rotates on every restart. On the matching POST, if that field is non-empty — humans cannot see or fill it — the identity is flagged with `risk += 50`.

### 4.0.4 Slowloris guard

Tightens the request-receive timeline: `HEADERS_TIMEOUT` (default 10 s) for full headers, `BODY_TIMEOUT` (default 30 s) for full body. Exceeded → `408 Request Timeout` + connection closed. Defends against attackers who hold sockets open with drip-fed bytes.

### 4.0.5 Service Metrics dashboard (`/__service`)

New admin dashboard with current values + 12 h history of:

- **CPU %** + load average (1 / 5 / 15 min)
- **Memory** (total / used / available / swap, plus cgroup container limit)
- **Disk** (`/data` total / used / available / %)
- **Processes** + open file-descriptor count
- **Network** throughput (rx / tx bytes-per-second across non-loopback ifaces)
- **SQLite size** — db, WAL, SHM files (sum + breakdown)
- **App counters** — uptime, total requests, allowed / blocked, identities tracked, IP buckets

Time-navigation controls (`‹ back / now / fwd ›` buttons + window selector 5 min – 12 h + bucket selector 5 s – 1 h) match the main dashboard's idiom. Sampling task runs every `SVC_METRICS_INTERVAL` seconds (default 5 s); ring buffer holds `SVC_METRICS_RETENTION` samples (default 8640 = 12 h). No `psutil` dependency — pure `/proc` + `os.statvfs()` reads.

The Stealth Agent Hunter timeline (`/__agents`) gained the same time-navigation controls.

### 4.0.6 Header-based controls (TLS fingerprint, Origin, custom headers)

Three opt-in checks added in v1.4.1:

* **`JA4_DENY_LIST`** — operator-curated set of TLS handshake fingerprints (JA3 / JA4) to block. Requires the upstream TLS terminator (cloudflared from 2024.x; nginx via `lua-resty-tls-fingerprint`; AWS ALB) to inject the fingerprint as a header. **`JA4_TRUSTED_PEERS`** pins the source IPs allowed to inject the header so a direct-port attacker cannot forge it.
* **`STRICT_ORIGIN=1`** — on `POST/PUT/PATCH/DELETE`, require the `Origin` header to match `ALLOWED_HOSTS`. Off by default (server-to-server clients often don't send `Origin`). `OPEN_ORIGIN_PATHS` provides per-path opt-out (e.g. webhooks).
* **`REQUIRED_HEADERS`** — comma-separated list of headers that must be present on every non-`/__/` non-static request (e.g. `X-Client-Version`). Skips admin and asset paths automatically.

All three feed the existing risk-score model:

| Reason | Risk weight |
|---|---|
| `tls-fingerprint` | 30 |
| `origin-mismatch` | 20 |
| `missing-required-header` | 15 |

### 4.0.7 Code-layout refactor

Dashboard HTML extracted from `proxy.py` into stand-alone files:

```
dashboards/
  main.html      ← was DASHBOARD_HTML literal
  agents.html    ← was AGENTS_DASHBOARD_HTML literal
  service.html   ← was SERVICE_DASHBOARD_HTML literal
```

Loaded once at module init via `Path(__file__).resolve().parent / "dashboards"`. Reduces `proxy.py` from ~4,250 to ~3,100 lines, lets dashboard JS be edited / linted with normal HTML/JS tooling. No runtime behaviour change, no new tests required (existing 102 still pass).

### 4.0.8 Service-metrics persistence

Service-metrics samples are now written to a new `svc_metrics` SQLite table on every sample (every `SVC_METRICS_INTERVAL` seconds), pruned to `SVC_DB_RETENTION_HOURS` (default 7 days) on disk. On startup, `db_load_state` rehydrates the in-memory deque from the most recent `SERVICE_METRICS_RETENTION` rows. Container restarts no longer wipe the chart history.

### 4.0.9 R7 — AI-canary echo detection (1.4.3)

LLM-driven agents summarise the page they fetched into the model's context window and re-emit fragments of that text in subsequent prompts. So a unique token planted in the HTML comes back to us in the next request from the same identity — something a real browser will never do, and a generic scraper has no reason to do either. Every HTML response (challenge page included) is stamped with a unique `agw-c-<16hex>` token in an HTML comment near `</head>` and the `X-Trace-Id` response header. Server-side, every incoming request is scanned (URL, headers, POST body up to 8 KiB) for any previously-issued token. Match → silent-decoy + `risk += 80` (single hit ≥ ban threshold) + entry added to the hostile pool (R8). Near-zero false-positive on browser traffic. Pentester-confirmed (R5/R6 lab): catches LLM agents that 16 layers of pure-protocol checks could not. Toggled by `CANARY_ECHO_DETECTION` (default `1`); window length tuned by `CANARY_TTL_S` (default 600 s).

### 4.0.10 R8 — 24 h hostile pool (1.4.3)

Generalisation of the existing risk-score ban. Reasons that are AI-agent-specific (`canary-echo`, `honeypot-silent`, `honeypot`, `ai-probe`, `suspicious-path`) trigger a longer ban duration (`HOSTILE_BAN_SECS`, default 86400 s = 24 h) instead of the standard `RISK_BAN_DURATION_SECS`. Generic bot bans stay at the shorter duration. The intent is asymmetric: short bans for accidental floods, long bans for confirmed automation, so AI-flagged identities are uneconomic to retry from.

### 4.0.11 No third-party dependency (1.4.4) + silent-decoy status mirroring

Earlier 1.4 builds tied the cookie gate to Turnstile (`JS_CHALLENGE=1` only engaged when `TURNSTILE_SITEKEY/SECRET` were configured). 1.4.4 decouples the two: the gate engages whenever `JS_CHALLENGE=1`, with two minting modes selected automatically:

- **Turnstile mode** (when keys present) — `/__challenge` accepts only Cloudflare-server-validated tokens. Production-grade boundary; nothing the attacker computes locally satisfies it.
- **Heuristic mode** (no keys) — cookie is auto-issued at the end of any allowed HTML GET that passed every other layer (UA filter, header completeness, behavioural, body-pattern, canary echo, rate limits). Bypass cost vs determined script: ~1 RTT; combined with the rest of the stack it raises bot cost without any third-party dependency.

The silent-decoy response now caches and **mirrors the upstream `/`'s actual HTTP status code** instead of hard-coding `200`. Closes the 200-with-404-page fingerprint that an agent could use to distinguish a blocked path from a forwarded one when upstream's `/` returns 404. The `_decoy_cache` schema gained a `status` field (falls back to 200 if upstream is unreachable on first fetch).

### 4.0.12 R10 — HMAC key rotation lever (1.4.5)

Closes the pentester finding *"old chal cookie still works after upgrade — HMAC secret not rotated"*. New admin endpoint `POST /__rotate-keys?key=…&scope=session|pow|all` regenerates `SESSION_KEY` (and/or `POW_HMAC_KEY`), persists to `/data/.session_key` / `.pow_key`, and the new key takes effect in-memory immediately. Every chal/session cookie issued before the call fails HMAC verification on the very next request. Operator playbook: rotate after upgrading the gateway image, after a credential incident, or on a schedule via cron.

Note: rotating while live browser tabs hold cookies will silent-decoy those tabs until they reload `/` (auto-mint mode) or solve Turnstile (Turnstile mode). Schedule rotation off-peak, or accept the brief disruption as the price of revocation.

### 4.0.13 SPA-friendly open paths (1.4.5)

The cookie gate is appropriate for navigation routes but breaks Single-Page-App XHRs against data-layer prefixes that authenticate with their own session (Keycloak, OAuth, JWT). `JS_CHAL_OPEN_PATHS` (comma-separated path prefixes) opts those prefixes out of the cookie gate while keeping every other layer (UA filter, header completeness, body-pattern, canary echo, rate limits, hostile pool) active. Example for the Spring Boot UFE stack used in the lab:

```
JS_CHAL_OPEN_PATHS=/bin/mvc.do/,/release-management/,/entity-management/,/content/
```

## 5. Carry-overs from 1.3

### 4.1 WebSocket bridging

Detects `Upgrade: websocket`, opens a server-side `WebSocketResponse`, dials
the upstream with `ClientSession.ws_connect()` (`https`→`wss` / `http`→`ws`
scheme conversion), and bridges messages with two concurrent pumps.
Sub-protocols (`Sec-WebSocket-Protocol`) negotiated through. Cookies stripped
of our `aid` session before forwarding. 30 s heartbeat + autoping on both
sides.

### 4.2 SSO-aware redirect rewriting

Three coordinated rewrites on responses:

1. `Location` headers in 3xx responses pointing at the upstream's host are
   rewritten to the gateway's public host so the browser keeps coming back
   through the gateway.
2. For **external IdP redirects** (different host), embedded references to
   the upstream URL inside query strings (typically `redirect_uri` /
   `state`) are rewritten too — with raw and percent-encoded forms — so the
   IdP sends the user back through the gateway. Requires the IdP to accept
   the gateway hostname as a valid redirect URI.
3. `Set-Cookie` headers preserved in a `CIMultiDict` (no more silent
   dropping of duplicate `Set-Cookie`) and the `Domain=` attribute is
   stripped so the browser accepts upstream-domain-scoped cookies on the
   gateway hostname.

### 4.3 Streaming body forwarding

Replaced one-shot `resp.content.read(N)` (which returns whatever is buffered
at that instant) with `iter_any()` chunk-loop and a hard size cap
(`UPSTREAM_MAX_RESP=8 MiB`). Same fix on request body forwarding
(`UPSTREAM_MAX_BODY=2 MiB`). Closes a truncation bug where chunked-transfer
JPEGs and JSON came through partial.

### 4.4 Origin / Referer / Host rewriting on outbound

The proxy replaces the client's `Origin` and `Referer` with the upstream's
canonical scheme://host before forwarding, and sets `Host` to the upstream's
vhost. Closes upstream CORS / origin-validation 403s that occur when the
gateway hostname differs from the upstream's expected origin.

### 4.5 Edge-injected security response headers

HTML responses now carry the following defaults (each overridable via env;
each only injected when the upstream did not already supply that header):

| Header | Default value | Env override |
|---|---|---|
| `X-Frame-Options` | `SAMEORIGIN` | `SEC_X_FRAME_OPTIONS` |
| `X-Content-Type-Options` | `nosniff` | `SEC_X_CONTENT_TYPE_OPTIONS` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `SEC_REFERRER_POLICY` |
| `Permissions-Policy` | cam/mic/geo/etc. all off | `SEC_PERMISSIONS_POLICY` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | `SEC_HSTS` |
| `Cross-Origin-Opener-Policy` | `same-origin` | `SEC_COOP` |
| `Cross-Origin-Resource-Policy` | `same-site` | `SEC_CORP` |
| `X-Permitted-Cross-Domain-Policies` | `none` | `SEC_X_PERMITTED_XDP` |
| `Content-Security-Policy` | (empty — opt-in) | `SEC_CSP` |

Master switch: `INJECT_SECURITY_HEADERS=0` disables them all.

### 4.6 Admin IP allowlist (`ADMIN_ALLOWED_IPS`)

Comma-separated IPs / CIDRs (IPv4 + IPv6). When set, source IP is matched in
addition to the admin key on every `/__*` request other than `/__live`.
Mismatch → silent decoy. Honors `TRUST_XFF=last` behind a trusted reverse
proxy. Validated at startup — container fails fast on malformed entries.

### 4.7 Stealth Agent Hunter dashboard

![Stealth Agent Hunter](../img/agents.png)

> Figure 2 — `/__agents`. Surfaces identities that passed every block but
> exhibit stealth-agent signals (low header completeness, no static asset
> fetches, regular timing below the block threshold, accumulated risk below
> ban threshold, etc.). The Detection-vs-Miss timeline charts blocked agents
> (red), missed agents (orange), clean allowed (green) per bucket.

### 4.8 Operator helper

`myip.sh` — auto-detects the operator's current public IP (multi-provider
fallback) and (re)launches the container with
`ADMIN_ALLOWED_IPS=<myip>,127.0.0.1`. All hardening flags preserved. Useful
for laptop / VPN-roaming workflows.

---

## 5. CVE status (Trivy)

| Image | HIGH | MEDIUM | LOW | Total | Fixable upstream |
|---|---|---|---|---|---|
| v1.0 (host-mode, Python 3.13) | — | — | — | — | — |
| v1.2 (Debian 13 slim) | 6 | 29 | (varied) | 35 | 0 |
| v1.2 distroless (Debian 13) | 27 | 78 | ~50 | ~155 | 0 |
| **v1.3 (Chainguard Wolfi)** | **0** | **0** | **0** | **0** | n/a |

The Wolfi base ships fixes for HIGH-severity OS CVEs typically within 48 h
of public disclosure (Chainguard's documented SLA). Re-run
`trivy image appsec-antibot-gw:1.5.2` on every rebuild to verify the posture
stays at zero.

---

## 6. Security review history

Three independent audits to date. All exploitable findings closed.

| Round | Findings | Verdict |
|---|---|---|
| 1 — pre-1.2 | 3 Critical / 7 High / 12 Medium / 12 Low | 34 / 34 closed |
| 2 — mid-1.2 | 8 (mixed Low + DiD) | 8 / 8 closed (N1–N8) |
| 3 — pre-1.3 pentest report | 5 "Critical" / 2 Mitigated / 3 Protected | 4 false-positive (stealth misclassified), 1 real (security headers) → fixed |

Round-3 detail:

* **"No rate limiting"** — FALSE POSITIVE. Stealth-mode returns 200 + decoy
  on blocks; `/__metrics` shows the `rate-limit*` counters firing on the
  same test traffic. Pentester only checked status codes.
* **"No auth on admin endpoints"** — FALSE POSITIVE. `/__*` requires both
  `ADMIN_KEY` and `ADMIN_ALLOWED_IPS`; `/__live` is the deliberately-open
  healthcheck.
* **"Bearer not validated"** — OUT OF SCOPE. The gateway is a reverse
  proxy, not an authentication proxy. JWT/Bearer validation belongs at the
  upstream auth server.
* **"POST allowed on sensitive endpoints"** — WORKING AS DESIGNED. POST is
  in the default allowlist for forms / APIs; operator can restrict via
  `ALLOWED_METHODS`.
* **"Missing security headers"** — REAL. Fixed (see §4.5).

---

## 7. Configuration

### 7.1 Required env

| Variable | Notes |
|---|---|
| `UPSTREAM` | **Required.** Fully-qualified URL of the backend to protect (e.g. `https://internal-app.svc`). Container fails fast if missing. |

### 7.2 Optional env

| Variable | Default | Notes |
|---|---|---|
| `ALLOWED_HOSTS` | (empty) | Comma-sep public hostnames the gateway accepts as Host header. |
| `ADMIN_ALLOWED_IPS` | (empty) | Comma-sep IPs/CIDRs that may reach `/__*`. |
| `ADMIN_KEY` | auto-generated | Always mirrored to `/data/.admin_key`. |
| `TRUST_XFF` | `last` | `last` behind a trusted proxy / cloudflared. |
| `BURST` / `REFILL` | 30 / 2.0 | Per-identity bucket. |
| `IP_BURST` / `IP_REFILL` | 60 / 8.0 | Socket-IP bucket. |
| `ALLOWED_METHODS` | `GET,HEAD,POST,OPTIONS` | Add PUT/PATCH/DELETE for REST APIs. |
| `POW_REQUIRED_PATHS` | (empty) | Path prefixes that demand a PoW solution. |
| `POW_REQUIRE_ALL_WRITES` | `0` | Set `1` to demand PoW on all POST/PUT/DELETE. |
| `UPSTREAM_MAX_BODY` | 2 MiB | Request body cap. |
| `UPSTREAM_MAX_RESP` | 8 MiB | Response body cap. |
| `MAX_IDENTITIES` | 100 000 | Memory bound. |
| `SESSION_SAMESITE` | `Lax` | `Lax \| Strict \| None` |
| `SESSION_SECURE` | `1` | Set `0` for HTTP-only test envs. |
| `INJECT_SECURITY_HEADERS` | `1` | Master switch for §4.5 headers. |
| `DEBUG` | `0` | Set `1` to expose `/__xff`. |
| `JS_CHALLENGE` | `0` | v1.4: invisible-CAPTCHA on first HTML hit. |
| `JS_CHALLENGE_TTL` | `86400` | v1.4: chal cookie lifetime in seconds. |
| `BODY_PATTERN_MATCH` | `0` | v1.4: SQLi/XSS/SSTI scan of POST/PUT/PATCH bodies. |
| `BOT_TRAP_FORMS` | `0` | v1.4: hidden-field auto-injection in `<form>`s. |
| `HEADERS_TIMEOUT` | `10` | v1.4: slowloris guard, max secs to receive headers. |
| `BODY_TIMEOUT` | `30` | v1.4: slowloris guard, max secs to receive body. |
| `SVC_METRICS_INTERVAL` | `5` | Seconds between samples on `/__service`. |
| `SVC_METRICS_RETENTION` | `8640` | Samples kept (8640 × 5 s = 12 h). |

### 7.3 Production launch (Harbor)

```bash
docker network create --driver bridge antibot-net 2>/dev/null
docker volume  create antibot-data 2>/dev/null

KEY="$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')"
MYIP="$(curl -s --max-time 4 https://api.ipify.org)"

docker run -d --name appsec-antibot-gw1.3 \
  --restart unless-stopped --init \
  --read-only --tmpfs /tmp:size=8m,mode=1777,nosuid,nodev,noexec \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt apparmor=docker-default \
  --pids-limit 200 --memory 256m --memory-swap 256m --cpus 1.0 \
  --ulimit nofile=4096:4096 --ulimit nproc=200:200 --ulimit core=0:0 \
  --ipc=private --network antibot-net \
  --log-opt max-size=10m --log-opt max-file=3 \
  -p 8443:8443 \
  -e UPSTREAM="https://internal-app.example.com" \
  -e ALLOWED_HOSTS="www.example.com" \
  -e ADMIN_ALLOWED_IPS="$MYIP,127.0.0.1" \
  -e ADMIN_KEY="$KEY" -e TRUST_XFF=last \
  -v antibot-data:/data \
  >harbor</antibotappsecgw/antibotappsecgw:1.3 \
&& echo "ADMIN_KEY: $KEY"
```

### 7.4 Operator endpoints

| Path | Auth | Purpose |
|---|---|---|
| `/__live` | none | Liveness probe (returns `ok`) |
| `/__dashboard` | admin | Main metrics dashboard |
| `/__metrics` | admin | JSON feed (clients, events, timeline) |
| `/__agents` | admin | Stealth Agent Hunter dashboard |
| `/__agents-data` | admin | Per-identity stealth-score JSON |
| `/__agents-timeline` | admin | Detected vs missed timeline JSON |
| `/__service` | admin | Service Metrics dashboard (CPU / mem / disk / procs / FDs / net / SQLite size) |
| `/__service-data` | admin | Service-metrics JSON (with windowed range/bucket/end navigation) |
| `/__pow` | admin | Mint a fresh PoW challenge bound to (method, path) |
| `/__solver` | admin | Browser-side PoW solver |
| `/__status` | admin | Per-identity bucket state snapshot |
| `/__unban` | admin | Clear ban + risk for an identity / IP / all |
| `/__xff` | admin + DEBUG=1 | Header debug (redacted) |

---

## 8. Appendix

### 8.1 Risk weights (current)

```python
RISK_WEIGHTS = {
    "honeypot":              50,    "honeypot-silent":     50,
    "suspicious-path":       40,    "host-not-allowed":    40,
    "ai-probe":              30,    "ai-enumeration":      30,
    "ua-empty":              25,    "ua-blocked":          20,
    "ua-non-browser":        20,    "ai-headers-empty":    15,
    "ua-too-short":          15,    "behavior":            10,
    "ai-headers-incomplete":  8,    "ai-no-assets":         5,
    "session-flood":          5,    "upstream-404":         4,
    "rate-limit":             0,    "rate-limit-ip":        0,
    "admin-ip-blocked":       0,
}
RISK_BAN_THRESHOLD       = 50
RISK_BAN_THRESHOLD_NAT   = 100
RISK_DECAY_HALFLIFE_SECS = 3600
RISK_BAN_DURATION_SECS   = 3600
```

### 8.2 Files in `/data` volume

| File | Purpose | UID |
|---|---|---|
| `antibot.db` | SQLite events / clients / timeline / bans (WAL) | 65532 |
| `.admin_key` | Operator key (mode 0600). Always mirrored from env or generated. | 65532 |
| `.session_key` | 32-byte HMAC key for session cookie signing | 65532 |
| `.pow_key` | 32-byte HMAC key for PoW challenge signing | 65532 |

### 8.3 Detected-vs-missed reasons set

Events whose reason is in the set below count as *detected* in the agents
timeline:

```
{ ua-blocked, ua-empty, ua-too-short, ua-non-browser,
  ai-probe, ai-headers-empty, ai-headers-incomplete,
  ai-enumeration, ai-no-assets, behavior,
  banned, banned-silent, honeypot, honeypot-silent,
  suspicious-path, session-flood,
  rate-limit, rate-limit-ip, host-not-allowed,
  admin-ip-blocked }
```

---

— *End of report* —

Image: `appsec-antibot-gw:1.5.2` · Author: Pedro Tarrinho · 2026-04-28
