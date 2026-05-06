# AppSecGW — Anti-Automation Reverse Proxy

A hardened reverse HTTP/WS gateway that sits in front of any web application
and applies **13 layered detection & mitigation controls** against automated
agents (CLI tools, scrapers, headless browsers, AI agents). Domain-agnostic:
the upstream is supplied exclusively via the `UPSTREAM` environment variable.

| Property | Value |
|---|---|
| Image | `appsec-antibot-gw:1.7.3` (~ 79 MB) |
| Base | Chainguard Wolfi distroless (`cgr.dev/chainguard/python:latest`) |
| Trivy CVE findings | **0** (Critical / High / Medium) |
| Stack | Python 3.14 / aiohttp 3.13 / SQLite WAL |
| User | non-root, UID 65532 |
| Architecture | linux/amd64, linux/arm64 |
| External intel | Cloudflare Turnstile · AbuseIPDB · CrowdSec · MaxMind GeoLite2 (ASN + City) |
| In-process detectors | 36 weighted signals · 13 hot-toggleable kill-switches · risk-score model with NAT-aware threshold + Anubis-mode strict PoW |
| Operator dashboards | `/antibot-appsec-gateway/secured/{dashboard, agents, service, controls, geo, logs, settings}` (DB-backed, click-to-drill) |

## Architecture (1.6.10)

```
                                ┌─────────────────────┐
   client ──── HTTP(S) ────────▶│  AppSecGW           │
                                │  ───────────────────│
                                │  middleware chain:  │
                                │   1. cost_meter     │  ← per-request wall-time
                                │   2. session cookie │
                                │   3. protect():     │
                                │      L0  TLS / JA4 fingerprint deny-list
                                │      L1  rate-limit: socket-IP + per-identity tokens
                                │      L1.5 host-not-allowed gate
                                │      L2  honeypot paths (silent decoy)
                                │      L2.5 suspicious-path / SQLi / XSS / LFI markers
                                │      L3  AI probe + AI-headers + AI-enumeration
                                │      L3.5 UA filter (empty / curl / GPTBot / mismatch)
                                │      L3.7 header completeness, accept:*/*, Origin
                                │      L4  bot-trap form fields, body-pattern match
                                │      L4.5 canary echo (R7 — token planted in HTML)
                                │      L5  behavioural (no-static-fetch / churn / 404 burst)
                                │      L6  external intel: AbuseIPDB · CrowdSec · MaxMind ASN
                                │      L7  cookie gate: JS_CHALLENGE / Turnstile / Anubis-mode PoW
                                │      L8  risk-score model (decay + NAT threshold + soft-tier)
                                │      ↓
                                │      decision = deny | soft-challenge | allow
                                │   4. forward to UPSTREAM if allowed
                                │   5. record() → SQLite (events, timeline, clients, bans)
                                └─────────────┬───────┘
                                              │
                          ┌───────────────────┼─────────────────────┐
                          ▼                   ▼                     ▼
                  ┌──────────────┐  ┌──────────────────┐   ┌─────────────────┐
                  │   /data      │  │  Redis (opt'l)   │   │  External APIs  │
                  │   antibot.db │  │  shared bans /   │   │ AbuseIPDB v2    │
                  │   (SQLite    │  │  canary tokens   │   │ CrowdSec LAPI   │
                  │   WAL)       │  │  for fleet mode  │   │ Turnstile sv    │
                  │   .pow_key   │  └──────────────────┘   │ MaxMind .mmdb   │
                  │   .session_… │                         │ (offline)       │
                  │   .admin_key │                         └─────────────────┘
                  │   GeoLite2-* │
                  └──────────────┘

  operator browser ──▶  /__dashboard  ─┐
                        /__agents      │  hot-tunable knobs via /__config (POST JSON);
                        /__service     │  click reasons → drill-down identities;
                        /__controls    │  click identity / risk → popover details;
                        /__geo  ───────┘  threshold sliders rewire risk model live.
```

The gateway is a single Python process. Persistent state (event log,
client snapshots, timeline, bans, admin-IP allowlist) lives in
`/data/antibot.db` (SQLite WAL); rotation keys live in `/data/.{pow,session,admin}_key`.
External integrations are best-effort: any one of them (AbuseIPDB,
CrowdSec, MaxMind ASN, MaxMind City, Turnstile, Anubis-mode PoW, Redis)
may be absent and the gate degrades gracefully — the in-process
detectors are sufficient on their own.

### Cookie-gate decision tree (Layer 7)

`JS_CHALLENGE=1` engages the cookie gate.  How a fresh client gets a
chal cookie depends on which extras are configured:

```
                    request without chal cookie
                              │
                ┌─────────────┼─────────────┐
                ▼             ▼             ▼
          path is in    path ends in     everything else
       JS_CHAL_OPEN_     static-asset
            PATHS         suffix
            │                 │              │
            │                 │              ▼
            │                 │       ┌──────────────┐
            │                 │       │ TURNSTILE_   │
            │                 │       │ ENABLED &&   │
            │                 │       │ identity     │
            │                 │       │ risk ≥       │
            │                 │       │ TURNSTILE_   │
            │                 │       │ RISK_THRESH  │
            │                 │       └──┬───────────┘
            │                 │          │ yes
            │                 │          ▼
            │                 │       Turnstile widget HTML
            │                 │       → siteverify
            │                 │       → mint chal cookie
            │                 │
            │                 │       no  ─▶  ANUBIS_ENABLED?
            │                 │                  │ yes
            │                 │                  ▼
            │                 │              PoW page (boosted
            │                 │              difficulty) → mint
            │                 │                  │ no
            │                 │                  ▼
            │                 │              HTML GET + Accept:
            │                 │              text/html?
            │                 │                  │ yes ─▶ heuristic auto-mint
            │                 │                  │ no  ─▶ silent decoy
            ▼                 ▼
      bypass cookie     bypass cookie
      gate (still       gate (still
      runs UA / risk    runs UA / risk
      detectors)        detectors)
```

The strictest configuration is **Turnstile + Anubis-mode + JS_CHAL_OPEN_PATHS = []**.  The most permissive is **JS_CHALLENGE=0** (gate disabled, downstream detectors only).

### MaxMind self-maintenance chain

In 1.5.5 the gateway maintains its own GeoLite2 mmdbs end-to-end:

```
docker build → COPY _seed/*.mmdb → /usr/local/share/maxmind/   (image-baked)
                          │
                          ▼
container start →  _maxmind_seed_from_image()  ──▶ if /data empty → copy
                          │
                          ▼
                  _maxmind_auto_fetch()
                  needs MAXMIND_LICENSE_KEY?
                          │ yes
                          ▼
                  https://download.maxmind.com → /data/GeoLite2-{ASN,City}.mmdb
                          │
                          ▼
                  _maxmind_refresh_loop() — every 24h, re-fetch if mmdb >30d old
                          │
                          └─── operator pushes "Fix now" on /__geo  ─┐
                                                                     ▼
                                                           POST /__maxmind-fetch
                                                                     │
                                                       runs seed + auto_fetch then
                                                       reopens reader handles
```

The image always ships seed mmdbs so a brand-new deploy works offline; `MAXMIND_LICENSE_KEY` enables fresh downloads + monthly self-refresh; the `/__maxmind-fetch` endpoint and the GeoMap "Fix now" button are operator-on-demand triggers.

### Risk-score lifecycle

Every detector that fires writes a weighted contribution into the per-identity `risk_score`.  The score then drives a three-tier decision model:

```
detectors fire ─▶ risk_score += RISK_WEIGHTS[reason]
                            │
                            ├─ score < SOFT_CHALLENGE_SCORE        ─▶ green (allowed)
                            │
                            ├─ SOFT ≤ score < BAN                  ─▶ orange "missed"
                            │     ├─ allowed but counted on the timeline
                            │     ├─ open-path bypass REVOKED — chal-required
                            │     └─ Turnstile widget shown if score ≥
                            │       TURNSTILE_RISK_THRESHOLD (default = mid-orange)
                            │
                            └─ score ≥ BAN  ─▶ red (banned-silent)
                                  │
                                  ├─ AI-flagged reasons → 24h hostile pool
                                  │   (HOSTILE_BAN_SECS, default 86400)
                                  │
                                  └─ Other reasons → standard ban duration
                                      (RISK_BAN_DURATION_SECS)

                  (continuously decayed)
                  score *= 0.5 every RISK_DECAY_HALFLIFE_SECS (1h)
                  per-reason contributions decay in lockstep so the
                  /__agents popover always shows the live breakdown.

NAT awareness:  if ≥ NAT_IDENTITIES_THRESHOLD (default 3) "legitimate-
looking" identities (≥1 static fetch AND ≥3 allowed reqs) are seen on
the same IP within 1h, the BAN threshold doubles (50 → 100) so a
shared-NAT office isn't carpet-banned by one bad apple.
```

The thresholds (`SOFT_CHALLENGE_SCORE`, `RISK_BAN_THRESHOLD`, `RISK_BAN_THRESHOLD_NAT`, `RISK_DECAY_HALFLIFE_SECS`, `HOSTILE_BAN_SECS`, `TURNSTILE_RISK_THRESHOLD`) are all hot-reloadable via `/__config` and live-tunable on `/__dashboard` (defense-thresholds slider) and `/__controls`.

---

## Quick start

```bash
docker network create --driver bridge antibot-net 2>/dev/null
docker volume  create antibot-data 2>/dev/null

KEY="$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')"
MYIP="$(curl -s https://api.ipify.org)"

docker run -d --name appsec-antibot-gw1.7.3 \
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
  -e UPSTREAM="https://your-internal-app.example.com" \
  -e ALLOWED_HOSTS="www.example.com" \
  -e ADMIN_ALLOWED_IPS="$MYIP,127.0.0.1" \
  -e ADMIN_KEY="$KEY" \
  -e TRUST_XFF=last \
  -v antibot-data:/data \
  appsec-antibot-gw:1.7.3 \
&& echo "ADMIN_KEY: $KEY"
```

Put TLS in front (`nginx`, `cloudflared`, `caddy` …). The proxy itself
listens HTTP-only on `:8443`.

---

## Docker Compose deployment (recommended)

The bundled `docker-compose.yml` launches a **full four-service stack** and is the
recommended way to run AppSecGW in production.

### What it starts

| Service | Image | Role | Host port |
|---|---|---|---|
| `appsec-antibot-gw` | `appsec-antibot-gw:1.7.3` | The gateway itself — proxies traffic, runs all detectors, serves operator dashboards | **8443** (only port exposed to host) |
| `appsec-timescaledb` | `timescale/timescaledb:latest-pg16` | Postgres 16 + TimescaleDB — optional persistent event store; switch from SQLite in one click via `/__controls` | none (internal only) |
| `appsecgw-redis` | `redis:7-alpine` | Shared ban store for fleet-mode (multi-replica) deployments; also backs canary token propagation | none (internal only) |
| `crowdsec` | `crowdsecurity/crowdsec:latest` | CrowdSec LAPI — subscribes to the community blocklist; gateway uses it as an external intel source | none (internal only) |

Only the gateway exposes a port to the host. TimescaleDB, Redis, and CrowdSec are
reachable only from the internal Docker network `antibot-net`, and each enforces
authentication within that network as defence-in-depth.

### Network topology

```
Internet / reverse-proxy
        │
        ▼  :8443
┌───────────────────────────────────────────────────────┐
│  Docker network: antibot-net                          │
│                                                       │
│  ┌─────────────────────┐                              │
│  │  appsec-antibot-gw  │                              │
│  │  (gateway)          │─────── Redis ban sync ──────▶│appsecgw-redis│
│  │                     │─── CrowdSec blocklist ──────▶│crowdsec      │
│  │                     │─── Postgres events ─────────▶│appsec-       │
│  │                     │    (when DB_BACKEND=postgres) │timescaledb   │
│  └─────────────────────┘                              │              │
│           │                                           └──────────────┘
│           ▼ UPSTREAM (env var)
│    your application
└───────────────────────────────────────────────────────┘
```

### Pre-requisites

```bash
# Create the shared network and persistent volumes once
docker network create --driver bridge antibot-net
docker volume create antibot-data
docker volume create appsec-timescaledb-data
docker volume create crowdsec-data
docker volume create crowdsec-conf
```

### Configuration

```bash
cp .env.example .env
```

Minimum required fields in `.env`:

| Variable | Example | Notes |
|---|---|---|
| `UPSTREAM` | `https://app.internal.example.com` | Target application — all non-admin traffic is forwarded here |
| `ADMIN_ALLOWED_IPS` | `203.0.113.10/32,127.0.0.1/32` | CIDR list of IPs allowed to reach admin dashboards |
| `TRUSTED_PROXIES` | `172.16.0.0/12` | IPs whose `X-Forwarded-For` the gateway trusts |
| `POSTGRES_PASSWORD` | *(strong random)* | TimescaleDB password — used by gateway DSN automatically |
| `REDIS_PASSWORD` | *(strong random)* | Redis `requirepass` value — used by gateway `REDIS_URL` automatically |

Optional but recommended:

| Variable | Purpose |
|---|---|
| `ADMIN_KEY` | Static Bearer token for admin API. Auto-generated on first boot if unset, but setting it explicitly makes key rotation predictable. |
| `TURNSTILE_SITEKEY` / `TURNSTILE_SECRET` | Enable Cloudflare Turnstile for real-browser gating |
| `ABUSEIPDB_KEY` | Enable AbuseIPDB IP-reputation lookups |
| `MAXMIND_LICENSE_KEY` | Enable weekly MaxMind GeoLite2 auto-refresh |

### Launch

```bash
docker compose up -d
```

This starts all four services with `unless-stopped` restart policy. The gateway
**waits for TimescaleDB and Redis to pass their healthchecks** before starting
(`depends_on: condition: service_healthy`), so there is no race on first boot.

Monitor startup:

```bash
docker compose logs -f appsec-antibot-gw
# Expect: "[js-challenge] active" and "AppSecGW_1.7.3 listening …" within 5 s
```

Check that all services are healthy:

```bash
docker compose ps
# All four services should show "healthy" or "running" (CrowdSec starts with "service_started")
```

### Post-up: register the CrowdSec bouncer

CrowdSec generates the bouncer API key at runtime. After the stack is up, run
these commands once:

```bash
BKEY=$(docker exec crowdsec cscli bouncers add appsecgw -o raw)
echo "CROWDSEC_LAPI_KEY=$BKEY" >> .env
echo "CROWDSEC_LAPI_URL=http://crowdsec:8080" >> .env
docker compose up -d --force-recreate appsec-antibot-gw
```

Without this step the gateway starts without CrowdSec intel (the integration is
gracefully skipped) and logs a warning at startup.

### Access the operator dashboards

All dashboards require the gateway to be reachable and the `X-Admin-Key` header
to match the configured key.

| Dashboard | URL | Description |
|---|---|---|
| Main | `http://host:8443/antibot-appsec-gateway/secured/dashboard` | Live counters, block-reason breakdown, event log |
| Controls | `http://host:8443/antibot-appsec-gateway/secured/controls` | Hot-toggle all knobs, tune thresholds, switch DB backend |
| Agents | `http://host:8443/antibot-appsec-gateway/secured/agents` | Stealth agent hunter — identities that passed every block |
| GeoMap | `http://host:8443/antibot-appsec-gateway/secured/geo` | MaxMind-backed geographic request distribution |
| Logs | `http://host:8443/antibot-appsec-gateway/secured/logs` | Structured event log with drill-down |

### Switching between SQLite and Postgres

The gateway ships with SQLite as the default backend (zero-deps, works on first
boot). Switch to TimescaleDB at any time without migration — events accumulate
fresh in the new backend:

1. Open `/__controls` → Backend pill toggle → click **postgres**.
2. The gateway restarts itself within ~2 s.
3. Confirm: `docker compose logs appsec-antibot-gw | grep "db_backend=postgres"`.

Switch back to SQLite the same way.

### Scaling to multiple replicas (fleet mode)

Add `REDIS_URL` to `.env` (defaults to the bundled sidecar). All replicas share
the same Redis instance — bans and canary tokens propagate within ~5 s across
the fleet. Each replica needs its own `ADMIN_KEY` or the same shared one pinned
in `.env`.

### Tear down

```bash
docker compose down          # stop + remove containers; volumes are preserved
docker compose down -v       # stop + remove containers AND volumes (destroys event data)
```

---

## Threat model & honest posture

Earlier iterations of this gateway shipped an in-process "JS challenge" that stacked client-computed primitives — SHA-256 Proof-of-Work, browser-API probe with cross-validation, anchor-fetch proof, sub-second timing windows — to try to distinguish real browsers from scripted clients. Empirically every one of those layers was bypassable in pure Python in ~1 s. They were *bot-cost amplifiers*, not security boundaries; they have been removed.

The gateway is now fully usable without any third-party service (1.4.4). Turnstile is one of two cookie-minting modes; the other is a heuristic auto-mint that runs entirely in-process. The honest posture differs by mode:

What remains:
- **Layered heuristics** — UA filter, header-completeness scoring, behavioral timing, rate limits (per-identity + per-socket-IP), risk-score model, bot-trap forms, body-pattern matching, slowloris guard, suspicious-path patterns, AI-probe path detection, honey-link injection. These are still cost amplifiers, but they're light-weight and they don't claim to be a hard wall.
- **Cookie-bound access (V8) + Turnstile minter** — opt-in via `JS_CHALLENGE=1` *and* `TURNSTILE_SITEKEY`/`TURNSTILE_SECRET`. The chal cookie is bound to (UA + IP-tier + opaque-hashed JA4 when present). The minter accepts only a Cloudflare Turnstile success token, which is generated server-side by Cloudflare and verified against `siteverify`; nothing the attacker computes locally satisfies it. Without Turnstile keys configured, this feature is disabled and a startup banner says so.
- **JA4 telemetry** — the per-request log records the TLS handshake fingerprint observed by a trusted upstream (`JA4_HEADER`, default `CF-JA4`), so operators can drive `JA4_DENY_LIST` from real traffic rather than heuristic guesses.

The cookie is therefore **also bound to the JA4 TLS fingerprint** when one is observed (V9.2). JA4 is the one signal in the stack the client *doesn't compute* — the network observes it during the TLS handshake. A cookie issued under one handshake cannot be replayed under another, so an attacker switching TLS stacks (e.g. Python urllib → curl → Chrome impersonate) loses every cookie they just paid PoW for. To use JA4 binding the gateway must sit behind a JA4-injecting front (cloudflared injects `CF-JA4`; nginx with the JA4 module also works); operator pins the trusted source via `JA4_TRUSTED_PEERS`.

For the strongest defense, **enable Cloudflare Turnstile** — `TURNSTILE_SITEKEY` + `TURNSTILE_SECRET`. The success token is minted by Cloudflare server-side and verified against `siteverify`; nothing the attacker computes locally satisfies it.

| Threat | Heuristics only (no Turnstile) | With Turnstile |
|---|---|---|
| Bare-UA `curl`/short UA | Blocked (UA filter) | Blocked |
| Empty `Accept-*` / no `Sec-Fetch-*` | Blocked (header completeness) | Blocked |
| Honey-pot path probe | Risk-score → ban + silent decoy | Same |
| Bot-trap form fill | Risk-score → ban | Same |
| Suspicious POST body (SQLi/XSS/SSTI) | Body-pattern match → silent decoy | Same |
| Single-host scripted bypass on API | Not blocked — gate is OFF | **Blocked** — Turnstile token required to mint cookie |
| Cookie replay across handshakes | n/a | Blocked (cookie bound to UA + IP-tier + JA4 hash) |

## What it does

Each incoming request passes through 13 ordered layers. Any non-PoW block
returns **the upstream homepage as `200 OK`** (silent decoy) so an attacker
cannot enumerate which layer fired.

| # | Layer | What it catches |
|---|---|---|
| 0 | Path / method / host gating | Control bytes, disallowed methods, mismatched Host, admin-IP allowlist |
| 1 | Identity ban | Previously-banned identity → silent decoy |
| 2 | Honeypot paths | `/wp-admin`, `/.env`, `/.git/config`, IMDS, `/actuator/*`, … |
| 3 | Suspicious-path patterns | CTF flag-hunting, traversal, SQLi/XSS markers, OS file paths |
| 4 | UA filter | Empty / too-short / blocklisted (60+ entries: HTTP libs, scanners, AI agents, headless browsers) |
| 5 | AI-probe paths | OpenAPI / Swagger / `llms.txt` / model discovery |
| 6 | Header completeness | Browser UA without `Sec-Ch-Ua` / `Sec-Fetch-*` |
| 7 | Path-discipline | Enumeration (>300 unique paths), HTML loads with no asset fetches |
| 8 | Socket-IP rate limit | Token bucket on kernel-observed peer IP (un-spoofable) |
| 9 | Per-identity rate limit | Token bucket on identity hash; static-asset GETs exempt |
| 10 | Behavioural timing | σ/μ < 0.05, lag-1 autocorr > 0.85, 50ms-bin majority > 70 % |
| 11 | Proof-of-Work | Bound to `METHOD:path`, replay-protected; opt-in per path |
| 12 | Risk-score model | Weighted scoring, NAT-aware threshold |
| 13 | Honey-link injection | Hidden links injected before `</body>` to trap HTML parsers |

Plus protocol-level support:

- **WebSocket bridging** — full bidirectional bridge with sub-protocol negotiation
- **SSO redirect rewriting** — `Location`, embedded `redirect_uri`, `Set-Cookie` `Domain=`
- **Origin / Referer / Host rewriting** to upstream's canonical origin
- **Streaming body forwarding** with hard size caps
- **Edge-injected security response headers** on HTML (XFO, nosniff, HSTS, COOP, CORP, Permissions-Policy with explicit Privacy-Sandbox opt-out, …)

### External integrations (1.5.4)

| Integration | Purpose | Effective weight |
|---|---|---|
| Cloudflare Turnstile | Real-browser challenge minted by `siteverify`. Shown only when identity's risk ≥ `TURNSTILE_RISK_THRESHOLD` | gates the chal cookie |
| AbuseIPDB | Crowdsourced IP reputation, 6h SQLite cache | `+50` (high) / `+15` (med) |
| CrowdSec LAPI | Self-hosted community blocklist, 60s cache | `+70` (instant ban) |
| MaxMind GeoLite2-ASN | Local ASN tagging — hosting-provider IPs | `+5` (soft) |
| MaxMind GeoLite2-City | Lat/lng for the GeoMap dashboard | telemetry only |
| Anubis-mode (PoW) | In-process strict PoW gate — raises difficulty by `ANUBIS_DIFFICULTY_BOOST` | gates failing-PoW requests |
| Redis (optional) | Cross-instance shared bans / canary tokens for fleet mode | shared state |

---

## Screenshots

### Main dashboard — `/__dashboard`
Real-time overview with live counters, the timeline (total / allowed / blocked), block-reason breakdown and the live event log.

![Main dashboard](img/dashboard.png)

### Stealth Agent Hunter — `/__agents`
Identities that passed every block but exhibit stealth signals. Per-identity stealth score 0–100 with component bars, plus the detection-vs-miss timeline.

![Stealth Agent Hunter](img/agents.png)

## Operator dashboards

Reachable from any IP in `ADMIN_ALLOWED_IPS` with the admin key:

| URL | Purpose |
|---|---|
| `/__live` | Unauthenticated liveness probe (returns `ok`) |
| `/__dashboard?key=…` | Main dashboard: timeline (total/allowed/blocked/**missed**), defense-threshold sliders, **cost-per-request graph**, **services panel**, **per-detector hits**, click-reason drill-down |
| `/__agents?key=…` | **Stealth Agent Hunter** — click identity for IP/UA/session popover; click risk score for per-signal breakdown; arrow-and-slider threshold widget |
| `/__service?key=…` | **Service Metrics** — CPU / memory / disk / processes / FDs / network / SQLite size with 12 h windowed history |
| `/__controls?key=…` | All hot-reload knobs (toggles, thresholds, lists) — Defenses & scoring merged table, Anubis toggle, admin-IP allowlist with click-to-edit description |
| `/__geo?key=…` | **Geo map** — world-map of accesses (green=clean / orange=missed / red=blocked, size ∝ hits) over a configurable time window; needs `GeoLite2-City.mmdb` |
| `/__service-data?key=…` | Service-metrics JSON feed (windowed) |
| `/__metrics?key=…` | JSON feed (now includes `services{}` + `detector_hits{}` + `missed`) |
| `/__cost-timeline?key=…` | Avg / max middleware wall-time per minute bucket |
| `/__geo-data?key=…` | Aggregated lat/lng/clean/missed/blocked points |
| `/__agents-data?key=…` | Per-identity stealth-score JSON (now includes `risk_breakdown` + `blocks_breakdown`) |
| `/__agents-timeline?key=…` | Detected-vs-missed timeline JSON |
| `/__scoring?key=…` | Per-signal weights + tier + cost (driven the scoring card) |
| `/__thresholds?key=…` | Min/max/current/impact-direction for every numeric knob |
| `/__external?key=…` | External-integration health (Turnstile / AbuseIPDB / CrowdSec / MaxMind) |
| `/__admin-ips?key=…` | Admin IP allowlist CRUD (GET/POST/PATCH/DELETE) |
| `/__config?key=…` | Read or update hot-reload knobs (POST JSON body) |
| `/__rotate-keys?key=…` | Rotate `SESSION_KEY` and/or `POW_HMAC_KEY` |
| `/__pow?key=…` | Mint a PoW challenge bound to (method, path) — reflects effective Anubis difficulty |
| `/__solver?key=…` | Browser-side PoW solver |
| `/__status?key=…` | Per-identity bucket state |
| `/__ban?key=…&id=…` | Manually ban an identity for `HOSTILE_BAN_SECS` |
| `/__unban?key=…&id=… \| ip=… \| all=1` | Clear ban + risk for an identity / IP / all |
| `/__challenge` | Cookie-mint endpoint (Turnstile siteverify / Anubis-mode PoW) |

---

## Configuration (env vars)

### Required

| Variable | Description |
|---|---|
| `UPSTREAM` | Fully-qualified URL of the backend to protect. Container fails fast if missing. |

### Frequently used

| Variable | Default | Description |
|---|---|---|
| `ALLOWED_HOSTS` | _(empty)_ | Comma-separated public hostnames the gateway accepts as Host header |
| `ADMIN_ALLOWED_IPS` | _(empty)_ | Comma-separated IPs/CIDRs allowed on `/__*` |
| `ADMIN_KEY` | auto-generated | Always mirrored to `/data/.admin_key` |
| `TRUST_XFF` | `first` | `first` / `last` / `none` — see XFF section below |
| `TRUSTED_PROXIES` | _(empty)_ | **Set in production.** CIDRs of upstream proxies allowed to set XFF (1.5.4) |
| `JS_CHALLENGE` | `0` | Cookie gate on every non-static path (Turnstile-backed when configured) |
| `JS_CHAL_OPEN_PATHS` | _(empty)_ | Path prefixes that bypass the cookie gate (SPA data layer / webhooks / S2S) |
| `SOFT_CHALLENGE_SCORE` | `4` | Risk-score threshold (orange band start) — hot-reloadable via `/__config` |
| `RISK_BAN_THRESHOLD` | `50` | Risk-score threshold (red band / ban) — hot-reloadable |
| `TURNSTILE_RISK_THRESHOLD` | `0` (auto = mid-orange) | Show Turnstile only when identity's risk crosses this. Below it, fresh clients fall through to cookie auto-mint — most users never see Turnstile, only suspected bots do (1.5.4) |

### Rate limiting

| Variable | Default |
|---|---|
| `BURST` / `REFILL` | `30` / `2.0` (per-identity) |
| `IP_BURST` / `IP_REFILL` | `60` / `8.0` (socket-IP) |

### Method allowlist

| Variable | Default |
|---|---|
| `ALLOWED_METHODS` | `GET,HEAD,POST,OPTIONS` |

Add `PUT,PATCH,DELETE` for REST APIs.

### Proof-of-Work

| Variable | Default |
|---|---|
| `POW_REQUIRED_PATHS` | _(empty)_ |
| `POW_REQUIRE_ALL_WRITES` | `0` |
| `ANUBIS_ENABLED` | `0` |
| `ANUBIS_DIFFICULTY_BOOST` | `1` |

PoW is **opt-in**. Set `POW_REQUIRED_PATHS=/login,/admin` to require PoW on
those paths only.

**Anubis-mode** (`ANUBIS_ENABLED=1`, hot-reloadable): forces the PoW gate on
*every* first-time request without a valid `chal` cookie, even when
`JS_CHALLENGE=0`. `ANUBIS_DIFFICULTY_BOOST` (0..6) adds extra leading hex
zeros to the SHA-256 challenge — each +1 makes scripted solving ~16× harder
(default `+1` → 6 leading zeros instead of 5). Inspired by
[github.com/TecharoHQ/anubis](https://github.com/TecharoHQ/anubis); useful
when the protected app is being actively scraped by LLM-driven agents.

### Trusted reverse-proxy / XFF spoofing protection (1.5.4)

| Variable | Default |
|---|---|
| `TRUST_XFF` | `first` |
| `TRUSTED_PROXIES` | _(empty — every peer trusted, back-compat)_ |

**Production deployments MUST set `TRUSTED_PROXIES`** to the IP / CIDR list of
the reverse-proxy or CDN immediately upstream (e.g. `TRUSTED_PROXIES=172.17.0.1/32,103.21.244.0/22,...`
for cloudflared / nginx). When set, `X-Forwarded-For` is honoured **only** if
the kernel-observed peer IP falls inside one of those CIDRs; everything else
falls back to the raw socket IP. Closes a pentest finding from 1.5.3 where
a client hitting the gateway directly could spoof XFF and impersonate any
source IP for ban-tracking and admin-allowlist purposes.

### Geo-map (1.5.4)

| Variable | Default |
|---|---|
| `MAXMIND_CITY_DB_PATH` | `/data/GeoLite2-City.mmdb` |

Drop a `GeoLite2-City.mmdb` (~65 MB) into the named volume to populate the
`/__geo` (GeoMap) dashboard. The bundled `maxmind-refresh.sh` cron script
downloads both `GeoLite2-ASN.mmdb` and `GeoLite2-City.mmdb` monthly using
`MAXMIND_LICENSE_KEY`. Map tiles are served from CARTO Dark Matter (no key,
no Referer requirement).

### External integrations

| Variable | Purpose |
|---|---|
| `ABUSEIPDB_KEY` | AbuseIPDB v2 API key — high-score IPs hit `+50` risk |
| `CROWDSEC_LAPI_URL` | URL of self-hosted CrowdSec LAPI (e.g. `http://crowdsec:8080`) |
| `CROWDSEC_LAPI_KEY` *or* `CROWDSEC_API_KEY` | CrowdSec bouncer API key — either name accepted (1.5.4) |
| `MAXMIND_ASN_DB_PATH` | Path to GeoLite2-ASN.mmdb (default `/data/GeoLite2-ASN.mmdb`) |
| `MAXMIND_CITY_DB_PATH` | Path to GeoLite2-City.mmdb (1.5.4) |
| `TURNSTILE_SITEKEY` / `TURNSTILE_SECRET` | Cloudflare Turnstile widget keys |

Each integration is best-effort — any one of them may be absent and the
gate degrades gracefully. Live status / cost / telemetry visible at
`/__external` (or click any card on the Controls dashboard for full
vendor docs + trigger criteria + data-egress info, 1.5.4).

### Hot-reloadable knobs (POST `/__config`)

All listed values can be changed at runtime without restart. The
`/__controls` dashboard exposes them as toggles / inputs / sliders / lists.

**Toggles (booleans):**
`JS_CHALLENGE`, `BOT_TRAP_FORMS`, `BODY_PATTERN_MATCH`, `CANARY_ECHO_DETECTION`,
`STRICT_ORIGIN`, `INJECT_SECURITY_HEADERS`, `JS_CHAL_BIND_JA4`,
`JS_CHAL_REQUIRE_JA4`, `JS_CHAL_STRICT_STATIC`, `ABUSEIPDB_ENABLED`,
`CROWDSEC_ENABLED`, `MAXMIND_ENABLED`, `TURNSTILE_ENABLED`,
`HONEYPOT_ENABLED`, `SUSPICIOUS_PATH_ENABLED`, `AI_PROBE_ENABLED`,
`UA_FILTER_ENABLED`, `UA_PLATFORM_CHECK_ENABLED`, `HEADER_COMPLETENESS_ENABLED`,
`BEHAVIORAL_CHECK_ENABLED`, `AI_ENUMERATION_ENABLED`, `AI_NO_ASSETS_ENABLED`,
`SESSION_FLOOD_ENABLED`, `UPSTREAM_404_TRACKING_ENABLED`, `ANUBIS_ENABLED`.

**Numeric thresholds:**
`RISK_BAN_THRESHOLD`, `SOFT_CHALLENGE_SCORE`, `TURNSTILE_RISK_THRESHOLD`,
`ANUBIS_DIFFICULTY_BOOST`, `RATE_LIMIT_BURST`, `RATE_LIMIT_REFILL`,
`IP_BURST`, `IP_REFILL`, `HOSTILE_BAN_SECS`, `CANARY_TTL_S`,
`GLOBAL_RPS_LIMIT`, `SESSION_CHURN_WINDOW_S`, `SESSION_CHURN_MAX`,
`JA4_AUTODENY_THRESHOLD`.

**Lists:** `JS_CHAL_OPEN_PATHS`, `JA4_DENY_LIST`.

**Logging:** `LOG_LEVEL` (`debug` / `info` / `warn` / `error`).

### Security response headers

| Variable | Default |
|---|---|
| `INJECT_SECURITY_HEADERS` | `1` |
| `SEC_X_FRAME_OPTIONS` | `SAMEORIGIN` |
| `SEC_X_CONTENT_TYPE_OPTIONS` | `nosniff` |
| `SEC_REFERRER_POLICY` | `strict-origin-when-cross-origin` |
| `SEC_HSTS` | `max-age=31536000; includeSubDomains` |
| `SEC_PERMISSIONS_POLICY` | minimal whitelist |
| `SEC_COOP` | `same-origin` |
| `SEC_CORP` | `same-site` |
| `SEC_X_PERMITTED_XDP` | `none` |
| `SEC_CSP` | _(empty)_ |

### Resource caps

| Variable | Default |
|---|---|
| `UPSTREAM_MAX_BODY` | `2 MiB` |
| `UPSTREAM_MAX_RESP` | `8 MiB` |
| `MAX_IDENTITIES` | `100000` |
| `ENUM_THRESHOLD` | `300` (unique paths/identity before enum block) |

### Service-metrics sampling

| Variable | Default | Description |
|---|---|---|
| `SVC_METRICS_INTERVAL` | `5` | Seconds between samples on the service dashboard. |
| `SVC_METRICS_RETENTION` | `8640` | Number of samples kept in memory (8640 × 5 s = 12 h). |

Each sample includes: CPU %, load average (1/5/15), memory total/used/available, swap, cgroup memory, disk total/used/available for `/data`, process count, open FDs, network rx/tx bps, and SQLite file sizes (db + WAL + SHM). Dashboard supports `prev / now / fwd` navigation, window selector (5 min – 12 h), bucket selector (5 s – 1 h).

### v1.4.2/3 header-based controls (all opt-in)

| Variable | Default | Description |
|---|---|---|
| `JA4_HEADER` | `CF-JA4` | Name of the header carrying the TLS fingerprint (cloudflared injects `CF-JA4` since 2024.x) |
| `JA4_DENY_LIST` | _(empty)_ | Comma-separated TLS fingerprints to block (e.g. `t13d_curl_8x,t13d_python_requests`) |
| `JA4_TRUSTED_PEERS` | _(empty)_ | Comma-separated IPs/CIDRs allowed to inject the JA4 header (the TLS terminator). Empty = trust all (assumes firewall blocks direct port access). |
| `STRICT_ORIGIN` | `0` | When `1`, POST/PUT/PATCH/DELETE requires `Origin` header host to match `ALLOWED_HOSTS` |
| `OPEN_ORIGIN_PATHS` | _(empty)_ | Path prefixes that bypass the Origin check (e.g. `/api/webhook`) |
| `REQUIRED_HEADERS` | _(empty)_ | Comma-separated header names that must be present on every non-`/__/` non-static request |

### v1.4 controls (all opt-in / safe defaults)

| Variable | Default | Description |
|---|---|---|
| `JS_CHALLENGE` | `0` | Cookie gate. With `=1`, every non-static, non-admin, non-opted-out request must carry a valid `chal` cookie. Two minting modes: (a) **Turnstile mode** when `TURNSTILE_SITEKEY` + `TURNSTILE_SECRET` are configured — Cloudflare's `siteverify` is the boundary, only widget-solved tokens validate. (b) **Heuristic mode** when no Turnstile keys — cookie is auto-issued on the first qualifying HTML GET (one that passes UA filter, header completeness, behavioural, body-pattern, canary-echo, etc.). Heuristic mode adds ~1 RTT of cost to scripted clients and forces them through every other layer; not a hard wall, but works without any third-party dependency. Cookieless API/XHR/POST hits are always silent-decoyed in either mode. |
| `JS_CHALLENGE_TTL` | `3600` | Cookie lifetime in seconds. |
| `JS_CHAL_OPEN_PATHS` | _(empty)_ | Comma-separated path prefixes that bypass the cookie gate. Use for legit non-browser clients (S2S, mobile apps, webhooks, e.g. `/webhook/,/s2s/`). |
| `JS_CHAL_STRICT_STATIC` | `1` | When ON, the static-asset bypass refuses paths containing API hints (`/api/`, `/graphql`, `/v1/`, ...). Closes `/api/v1/users.css` style probes against permissive backends. |
| `TURNSTILE_SITEKEY` | _(empty)_ | Cloudflare Turnstile public site key. Required to enable the gate. |
| `TURNSTILE_SECRET` | _(empty)_ | Cloudflare Turnstile secret. Used by `/__challenge` to call `siteverify`. |
| `JS_CHAL_BIND_JA4` | `1` | Bind the chal cookie to the JA4 fingerprint (opaque hash, never the raw value) when one is injected by a trusted peer. Cookie replay across TLS stacks fails. Opportunistic — clients with no JA4 still work. |
| `JS_CHAL_REQUIRE_JA4` | `0` | Hard requirement: `/__challenge` rejects (`403`) any submission without a JA4 from a trusted peer. Use only behind a JA4-injecting terminator (cloudflared / nginx-JA4). |
| `CANARY_ECHO_DETECTION` | `1` | **R7 (1.4.3)** — plant unique `agw-c-<16hex>` tokens in every HTML response (HTML comment + `X-Trace-Id` header). Any subsequent request from any identity that quotes one of those tokens back is silent-decoyed and ban-pooled. Targets LLM agents that summarise the page into the model's context and re-emit fragments in the next prompt. Near-zero false-positive on browser traffic. |
| `CANARY_TTL_S` | `600` | How long an issued canary stays valid for echo detection (sliding window). |
| `HOSTILE_BAN_SECS` | `86400` | **R8 (1.4.3)** — duration to keep AI-agent-flagged identities (canary-echo, honeypot, suspicious-path, ai-probe) silent-decoyed. Generic bans still use the shorter `RISK_BAN_DURATION_SECS`. |
| `BODY_PATTERN_MATCH` | `0` | Extends the suspicious-path regex set to POST/PUT/PATCH bodies (SQLi/XSS/SSTI/cmd-injection markers in form/JSON/XML). |
| `BOT_TRAP_FORMS` | `0` | Auto-injects a hidden `<input>` into every `<form>` in HTML responses; flags POSTs that fill it. |
| `HEADERS_TIMEOUT` | `10` | Slowloris: max seconds to receive full request headers. |
| `BODY_TIMEOUT` | `30` | Slowloris: max seconds to receive full request body. |

### Session cookie

| Variable | Default |
|---|---|
| `SESSION_SAMESITE` | `Lax` |
| `SESSION_SECURE` | `1` |

### Debug

| Variable | Default |
|---|---|
| `DEBUG` | `0` (set `1` to expose `/__xff`) |

---

## Container hardening

| Control | Value |
|---|---|
| Filesystem | `--read-only` rootfs + `--tmpfs /tmp:size=8m,nosuid,nodev,noexec` |
| Capabilities | `--cap-drop ALL` |
| Privilege escalation | `--security-opt no-new-privileges:true` |
| MAC | `--security-opt apparmor=docker-default` |
| PID 1 | `--init` (tini) |
| IPC | `--ipc=private` |
| Network | dedicated user-defined bridge (`--network antibot-net`) |
| Resources | `--memory 256m --memory-swap 256m --cpus 1.0 --pids-limit 200` |
| Ulimits | `nofile=4096 nproc=200 core=0` |
| Logs | `--log-opt max-size=10m --log-opt max-file=3` |
| User | non-root UID 65532 |
| CVEs (Trivy) | **0** |

---

## Multi-site fleet — one gateway per challenge / app

Designed so each protected site gets its own gateway *container*, while the
fleet shares state through one Redis. A flag on challenge **A** is silent-
decoyed on challenges **B…N** within seconds (read-through cache) and at
the TLS-handshake layer within 30 s (JA4 deny-list refresh). One operator
webhook rings once per ban, not N times.

### Topology

```
                    Internet
                       │
            ┌──────────┴──────────┐
            │  TLS terminator     │   nginx / Cloudflared / Caddy / ALB
            │  (host or per-app)  │   ← injects CF-JA4 if available
            └──────┬──────┬───────┘
                   │      │
                   ▼      ▼
         ┌──────────┐  ┌──────────┐  ┌──────────┐
         │ gw-app1  │  │ gw-app2  │  │ gw-appN  │  ← one container/site
         │ :8443    │  │ :8443    │  │ :8443    │
         └────┬─────┘  └────┬─────┘  └────┬─────┘
              │             │             │
              └────┬────────┴────┬────────┘
                   │             │
                   ▼             ▼
              ┌─────────┐   ┌──────────┐
              │  Redis  │   │ Webhook  │   ← Slack / Discord / SIEM
              │ (bans + │   │ receiver │
              │  JA4    │   └──────────┘
              │  shared)│
              └─────────┘
```

Each gateway forwards to **one** upstream (`UPSTREAM=https://app1.internal`),
isolates its own SQLite + chal-cookie HMAC, and writes ban events through
to the shared Redis. No gateway sees another's traffic — only its bans.

### Step 1 — start the shared Redis (once)

```bash
docker network create antibot-net 2>/dev/null
docker run -d --name antibot-redis --network antibot-net \
  --restart unless-stopped \
  -v antibot-redis-data:/data \
  redis:7-alpine redis-server --appendonly yes
```

### Step 2 — spin up one gateway per site

A small helper makes the per-site flags trivial. Save as `spawn-gw.sh`:

```bash
#!/usr/bin/env bash
# Usage: ./spawn-gw.sh <site-name> <upstream-url> <listen-port>
set -euo pipefail

NAME="$1"            # e.g. ctf-pwn1
UPSTREAM="$2"        # e.g. https://pwn1.internal:8000
PORT="${3:-8443}"
ADMIN_KEY="${ADMIN_KEY:-$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')}"
WEBHOOK_URL="${WEBHOOK_URL:-}"   # optional; same value on every container
WEBHOOK_SECRET="${WEBHOOK_SECRET:-}"
TURNSTILE_SITEKEY="${TURNSTILE_SITEKEY:-}"
TURNSTILE_SECRET="${TURNSTILE_SECRET:-}"

docker rm -f "appsec-gw-${NAME}" 2>/dev/null || true
docker run -d --name "appsec-gw-${NAME}" \
  --restart unless-stopped --init --network antibot-net \
  --read-only --tmpfs /tmp:size=8m,mode=1777,nosuid,nodev,noexec \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 200 --memory 256m --memory-swap 256m --cpus 1.0 \
  --ulimit nofile=4096:4096 --ulimit nproc=200:200 --ulimit core=0:0 \
  --ipc=private --log-opt max-size=10m --log-opt max-file=3 \
  -p "${PORT}:8443" \
  -e UPSTREAM="${UPSTREAM}" \
  -e ALLOWED_HOSTS="${NAME}.example.com,127.0.0.1" \
  -e ADMIN_ALLOWED_IPS="${ADMIN_ALLOWED_IPS:-127.0.0.1}" \
  -e ADMIN_KEY="${ADMIN_KEY}" \
  -e TRUST_XFF=last \
  -e JS_CHALLENGE=1 \
  -e CANARY_ECHO_DETECTION=1 \
  -e BOT_TRAP_FORMS=1 \
  -e BODY_PATTERN_MATCH=1 \
  -e LOG_FORMAT=json \
  -e LOG_LEVEL=info \
  -e REDIS_URL="redis://antibot-redis:6379/0" \
  -e REDIS_NS="appsecgw-${NAME}-shared" \
  -e WEBHOOK_URL="${WEBHOOK_URL}" \
  -e WEBHOOK_SECRET="${WEBHOOK_SECRET}" \
  -e TURNSTILE_SITEKEY="${TURNSTILE_SITEKEY}" \
  -e TURNSTILE_SECRET="${TURNSTILE_SECRET}" \
  -v "appsec-gw-${NAME}-data:/data" \
  appsec-antibot-gw:1.7.3
echo "  → ${NAME}: http://localhost:${PORT}    admin key: ${ADMIN_KEY}"
```

Then:

```bash
ADMIN_KEY=$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=') \
WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/X0 \
WEBHOOK_SECRET=$(openssl rand -hex 32) \
./spawn-gw.sh ctf-pwn1   https://pwn1.internal:8000   9001
./spawn-gw.sh ctf-web2   https://web2.internal:8000   9002
./spawn-gw.sh staff-app  https://staff.internal:8443  9003
```

Each gateway is independent for traffic; they share one ban list, one JA4
deny-list, one webhook channel.

### What's shared (1 Redis) vs. per-instance

| Across the fleet (Redis) | Per gateway (local SQLite + memory) |
|---|---|
| `appsecgw:ban:<track-key>` — sticky bans (24 h hostile-pool reasons) | events log (last 200 in dashboard, all in `/data/antibot.db`) |
| `appsecgw:ja4-bans:<ja4>` counter — drives auto-deny | per-identity rate-limit token buckets |
| `appsecgw:ja4-denylist` set — refreshed on each instance every 30 s | risk score, behavioural windowing, header-completeness scores |
| `appsecgw:wh:<reason>:<key>` — webhook dedup (5 min TTL) | service-metrics samples (CPU/mem/disk/proc/FDs) |
| `REDIS_NS` knob — namespace per environment (`prod`, `staging`, `ctf-2026`) | chal cookie HMAC (rotate via `/__rotate-keys` per instance, or fleet-wide via the loop below) |

`REDIS_NS` decides whether two clusters share or isolate state. Same value
across N instances → fleet-wide shared bans. Different values (`gw-prod`
vs `gw-staging`) → fully isolated.

### Operating the fleet

**Hot-reload one knob across every gateway** (controls dashboard works
per instance; for fleet-wide changes use a small loop):

```bash
APPLY='{"BODY_PATTERN_MATCH": true, "RISK_BAN_THRESHOLD": 60}'
for port in 9001 9002 9003; do
  curl -s -X POST "http://localhost:${port}/__config?key=${ADMIN_KEY}" \
       -H 'Content-Type: application/json' -d "$APPLY"
done
```

**Bump the throughput cap on every site simultaneously:**

```bash
for port in 9001 9002 9003; do
  curl -s -X POST "http://localhost:${port}/__config?key=${ADMIN_KEY}" \
       -H 'Content-Type: application/json' -d '{"GLOBAL_RPS_LIMIT": 50}'
done
```

**Rotate the HMAC key on every gateway after a credential incident:**

```bash
for port in 9001 9002 9003; do
  curl -s -X POST "http://localhost:${port}/__rotate-keys?key=${ADMIN_KEY}&scope=all"
done
# every chal/session cookie issued before this point fails on every gateway
```

**Ban an identity everywhere** (the local ban write also pushes through
Redis, so any gateway in the namespace will start silent-decoying):

```bash
curl "http://localhost:9001/__ban?key=${ADMIN_KEY}&id=<track-key>&secs=86400&reason=manual"
# subsequent traffic on 9002 + 9003 to that track-key → silent decoy
```

**Unban everywhere:**

```bash
curl "http://localhost:9001/__unban?key=${ADMIN_KEY}&id=<track-key>"
# Note: shared-store entries TTL out at the original ban duration. To
# force-clear cross-fleet *now*, also delete the Redis key:
docker exec antibot-redis redis-cli DEL "appsecgw-ctf-pwn1-shared:ban:<track-key>"
# (if REDIS_NS differs per instance, delete from each namespace)
```

### Per-site overrides

Different challenges need different open-paths and risk profiles. Set
overrides in the per-site env block:

| Knob | Why per site |
|---|---|
| `JS_CHAL_OPEN_PATHS` | Each SPA's data-layer prefixes (`/bin/mvc.do/`, `/api/v1/`, `/graphql`) |
| `ALLOWED_HOSTS` | Public hostname for that site |
| `RATE_LIMIT_BURST/REFILL`, `IP_BURST/REFILL` | A static-asset-heavy app needs higher buckets than a JSON API |
| `SESSION_CHURN_MAX` | API-only sites with legitimate fresh-session-per-call patterns may need a higher bound |
| `STRICT_ORIGIN`, `REQUIRED_HEADERS` | App-specific, opt-in |

Knobs you should keep **identical** across the fleet:

| Knob | Reason |
|---|---|
| `REDIS_URL`, `REDIS_NS` | Shared state requires aligned wiring |
| `WEBHOOK_URL`, `WEBHOOK_SECRET` | One channel for fleet-wide ops |
| `LOG_FORMAT=json`, `LOG_LEVEL` | Consistent ingestion downstream |
| `ADMIN_KEY` | Operator scripts work everywhere |
| `JA4_TRUSTED_PEERS`, `JA4_HEADER` | All instances read the same upstream JA4 |

### Centralised observability

With `LOG_FORMAT=json` set on every gateway, ship stdout to one collector:

```bash
# example: ship every container's stdout to Loki via promtail
docker run -d --name promtail \
  --network antibot-net \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $PWD/promtail.yaml:/etc/promtail/promtail.yaml \
  grafana/promtail:latest
```

Useful queries (LogQL / KQL / etc.):

```
{event="request", reason="canary-echo"}                — every R7 hit, fleet-wide
{event="ban"}                                          — every ban, all instances
{event="manual_ban"} | rid="<request-id>"              — single-request forensics
{event="config_changed"}                               — full audit of `/__config` POSTs
{event="session_churn"} | json | count > 5             — agent rotating sessions
```

The same `request_id` appears in the response's `X-Request-ID` header, so a
support ticket from a real user pasted with a request ID grep's directly to
the relevant log entries fleet-wide.

### Webhook payload shape

```json
{
  "event":     "ban",
  "ts":        1719918300,
  "reason":    "canary-echo",
  "risk_score": 80,
  "track_key": "8ef229cffad339b2",
  "ip":        "203.0.113.42",
  "ja4":       "t13d_8a44_python_urllib",
  "ua":        "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36",
  "duration_s": 86400,
  "hostile":   true
}
```

The `X-AppSecGW-Signature` HMAC-SHA-256 header is computed over the raw
body using `WEBHOOK_SECRET`. Receiver verifies before acting.

### Per-fleet incident playbook

| Symptom | Action | Where |
|---|---|---|
| Slack ping: `canary-echo` from `track-key=…`, `ja4=t13d_…python` | nothing — already silent-decoyed for 24 h fleet-wide | shared store auto-handled |
| Recurring `session_churn` from same `/24` | tighten `SESSION_CHURN_MAX` from 6 → 4 across fleet | controls dashboard or `/__config` loop |
| Legitimate user accidentally banned | unban via main dashboard or `/__unban?id=…`; consider raising `RISK_BAN_THRESHOLD` | per instance + delete Redis key |
| New SPA endpoint added to one challenge | append prefix to that gateway's `JS_CHAL_OPEN_PATHS` via `/__config` | per-site, hot-reload |
| Major bypass disclosed | rotate keys fleet-wide | `for-loop POST /__rotate-keys?scope=all` |
| Switching from heuristic mode to Turnstile | set `TURNSTILE_*` envs and restart that container; existing Redis state preserved | per instance |

---

## Operator helpers

### `myip.sh`

Auto-detects your public IP and (re)launches the container with
`ADMIN_ALLOWED_IPS=<ip>,127.0.0.1`. Re-run when your IP changes (laptop
roaming, VPN switch, ISP rotation).

```bash
UPSTREAM=https://your-app ALLOWED_HOSTS=www.example.com ./myip.sh --apply
```

### Pull from Harbor

```bash
docker login >harbor<
docker pull  >harbor</antibotappsecgw/antibotappsecgw:1.3
```

---

## Build from source

```bash
git clone https://github.com/<your-org>/appsec-antibot-gw.git
cd appsec-antibot-gw
docker build --pull -t appsec-antibot-gw:1.7.3 .
trivy image appsec-antibot-gw:1.7.3        # expect 0 findings
```

Multi-stage build:

1. **builder** — `cgr.dev/chainguard/python:latest-dev` installs the
   wheels into an isolated `/pydeps` prefix
2. **runtime** — `cgr.dev/chainguard/python:latest` (no shell, no apt) gets
   only the application files + the wheels

---

## Files in `/data` (named volume)

| File | Purpose |
|---|---|
| `antibot.db` | SQLite WAL: events / clients / timeline / bans |
| `.admin_key` | Operator admin key (mode 0600) |
| `.session_key` | 32-byte HMAC key for signed session cookies |
| `.pow_key` | 32-byte HMAC key for PoW challenge signing |

All owned by UID 65532 (`nonroot`).

---

## Repository layout

```
.
├── proxy.py                                    main reverse proxy (single file)
├── Dockerfile                                  multi-stage Wolfi distroless build
├── docker-compose.yml                          example compose deployment
├── myip.sh                                     auto-detect-IP launcher
├── maxmind-refresh.sh                          monthly cron — refreshes ASN+City mmdbs
├── README.md                                   this file
├── tests/
│   └── test_critical.py                        pytest unit suite (11 tests, all green)
├── sbom/
│   ├── sbom-1.5.4.cdx.json                     CycloneDX SBOM 1.5.4 (53 KB, generated by Trivy)
│   └── sbom-1.5.5.cdx.json                     CycloneDX SBOM 1.5.5 (53 KB, generated by Trivy)
├── _seed/
│   ├── GeoLite2-ASN.mmdb                       mmdbs baked into image at build time
│   └── GeoLite2-City.mmdb                       (1.5.5 — for offline-ready GeoMap)
├── .env.example                                turnkey env template (cp → .env, edit, compose up)
├── dashboards/                                 server-rendered operator UIs
│   ├── main.html                               /__dashboard
│   ├── agents.html                             /__agents
│   ├── service.html                            /__service
│   ├── controls.html                           /__controls
│   └── geo.html                                /__geo (1.5.4)
├── manual/manual-report-1.3.html               implementation report (HTML source)
├── AppSecGW-1.3-Report.pdf                     implementation report (PDF)
├── img/
│   ├── dashboard.png                           main dashboard screenshot
│   └── agents.png                              stealth-agent hunter screenshot
├── .dockerignore
└── .trivyignore                                kept for fallback / documentation
```

---

## License

Internal — see project owner.

## Author

Pedro Tarrinho

## Version history

| Version | Highlights |
|---|---|
| **1.7.3** | **4 AI-agent detection signals + path-sweep + admin bypass fix + DAST + post-release additions.** **(P1) Semantic honeypot credential injection** — `detection/honey_cred.py` injects fake `internal_api_key` comment in every HTML response; `/probe?k=<key>` endpoint fires `honey-cred` (+90) when AI agent hits it. **(P2) Risk-gated redirect maze** — `detection/redirect_maze.py`; HMAC-signed step tokens, `/maze` endpoint; completes all steps in < 800 ms → `redirect-maze-bot` (+55). **(P3) LLM no-subresource heuristic** — `detection/llm_heuristic.py`; ≥ 5 HTML GETs with 0 sub-resources in 120 s window → `llm-no-subresources` (+40). **(P4) Browser execution probe** — `<link rel="preload" as="fetch">` in every `<head>`; `/canary-probe/{token}` endpoint confirms browser execution; no fetch after ≥ 3 pages → `canary-probe-miss` (+35). **(Path-sweep)** `detection/path_sweep.py` fires `path-sweep` on ≥ 40 distinct non-static paths within 300 s — runs even for valid-cookied sessions. Global RPS / method-allowlist exemptions scoped to admin IPs only. Geo "No geo" card. JA4/Turnstile mutual exclusion (3-layer: startup + DB-load + hot-reload). **Post-release additions**: Three-tier ban durations — `REALLY_BAN_SECS` (30 d default) for definitive bot-proof signals (`canary-echo`, `honeypot-silent`, `honeypot`); `HOSTILE_BAN_SECS` (24 h) for hostile signals; ban-duration knobs in Controls dashboard. Storage card in Settings (disk usage + DB/WAL/SHM sizes + Vacuum button). Fixed `ALLOWED_HOSTS` URL parsing (`urlparse`-based normalisation). **Security review**: 13 findings fixed total. **Tests**: 215 pass; 0 failures. **DAST**: 15/15 PASS. **Bandit**: 0 H / 0 C. **Trivy**: 0 CVEs. Harbor: amd64 `sha256:eeb71292…` · arm64 `sha256:64fa6b48…` · armv7 `sha256:0b9ebd1c…` · manifest `sha256:5772e553…`. |
| **1.7.2** | **Geo dashboard overhaul + cost chart fix + admin IP tooltips + JS SyntaxError fixes.** Time-window navigation (← prev / next → / now) in geo dashboard; `endEpoch` appended to all geo-data requests. Drill scrubber-aware: passes `?end=&range=` when scrubbing. Denied-country visual on map circles (red border + ⛔ prefix). `is_admin_ip` returned by geo-drill endpoint; 🔒 icon with tooltip in drill panel. Country table allow buttons (no silent `COUNTRY_BLOCK_ENABLED:true` side-effect). `geo_data_endpoint` ORDER BY ts ASC. `_GEO_CACHE` LRU eviction fixed (was sorting by key value, not expiry). Cost chart `onClick` direct call — eliminates silent failure on bucket-boundary timestamp mismatch. `_adminLock` / `_ADMIN_IP_TIP` promoted to global scope in `main.html`; all five 🔒 occurrences across all panels now show full tooltip on hover. All dashboard version badges updated 1.7.1 → 1.7.2. JS SyntaxErrors fixed in `main.html`/`agents.html` (smart quotes U+2018/U+2019 + apostrophe in `_ADMIN_IP_TIP` caused all dashboard JS to fail silently). Chart.js moved CDN → local bundle (`chart.umd.min.js`). CI `docker-no-latest-tag` suppressed via `exceptions.yaml` (Chainguard has no public version-specific tags; images pinned by `@sha256`). **Tests**: 201 unit + 22 functional + 23 integration + 76 regression — all pass (+7 JS-syntax regression tests, +5 CSP-augmentation unit tests, +1 route-aware decoy regression test, 3 stale-assertion fixes). **Bandit**: 0 H / 0 C. **Trivy**: 0 CVEs. |
| **1.7.1** | **Browser automation probe + coordinated ASN clustering + user journey detection.** Self-hosted JS probe (`AUTOMATION_PROBE_ENABLED=1`) fires `webdriver-detected` (+30). Coordinated-ASN clustering (`COORDINATED_ATTACK_ENABLED=1`) fires `coordinated-probe` (+25) on cluster members. User journey / direct-API-probe (`JOURNEY_CHECK_ENABLED=1`) fires `direct-api-probe` (+15). Fixes: agents.html bucket popover max-height clipping; fetch error handling in openBucketDetail; main.html catch-block error display. **Tests**: 22 functional + 22 integration + regression — all pass. **Bandit**: 0 H / 0 C. **Trivy**: 0 CVEs. |
| **1.7.0** | **Modular refactor (Phase 5–8)** — 13,696-line `proxy.py` monolith split into 30+ modules (`config`, `state`, `helpers`, `identity`, `rate_limit`, `scoring`, `admin/*`, `challenge/*`, `core/*`, `dashboards/*`, `db/*`, `detection/*`, `integrations/*`, `reputation/*`). Public API and all behaviour unchanged. Fixes: Dockerfile missing COPY blocks, `_postgres_available` NameError, NaN/Inf injection in `end=` param, `_global_rps_window` / `_pow_seen` / `_canary_tokens` NameErrors, namespace-aware tarpit + get_ip wrappers, `_HOSTILE_REASONS` NameError, `db_load_config` test-isolation regression, `DB_PATH` resolution, credential propagation to validators. **Tests**: 309/309 (179 unit + 22 functional + 10 integration + 98 regression). **Bandit**: 0 H / 0 C. **Trivy**: 0 CVEs. |
| **1.6.9** | **AI Labyrinth + Controls kind badges + TimescaleDB stats.** **(1) TimescaleDB / Postgres health metrics** — `_pg_timescale_stats()` samples hypertable sizes, chunk counts, compression ratio, continuous-aggregate freshness, and Postgres cache-hit ratio every interval; surfaces on the Service dashboard under "PostgreSQL / TimescaleDB" with click-to-zoom chart modal. **(2) Controls dashboard — kind badges** — every detector entry in the scoring table now carries a `kind` badge (7 categories: `in-process` · `state` · `regex` · `mmdb` · `network` · `response` · `adversary`) with coloured micro-badges and a kind-legend strip above the table. Adversary entries (`slow-client`, `tarpit-walk`) display in blue with tooltip "0 ms for legit traffic". Cost values corrected for `suspicious-body` (0.8 ms typical) and `suspicious-path` (0.1 ms). Sort-by-cost column header click. **(3) AI Labyrinth (in-progress as 1.6.9)** — hidden `rel="nofollow"` block injected before `</body>` on every proxied HTML response; bot following a link enters a slow-drip fake-documentation maze; fires `tarpit-walk` (weight 100, instant ban). 4 hot-reloadable knobs: `LABYRINTH_ENABLED`, `LABYRINTH_SLOW_MS`, `LABYRINTH_MAX_DEPTH`, `LABYRINTH_LINKS_PER_PAGE`. **Validation fixes (found during build validation)**: tarpit endpoint added to `_ADMIN_PUBLIC_SUBPATHS` (was unreachable by non-admin IPs); `tarpit_endpoint` identity derivation fixed (`get_identity()` instead of non-existent helper stubs). **Tests**: 163 unit + 19 functional + 10 integration + 94 regression — **286/286 passing**. New tests (1.6.8): `test_168_labyrinth_knobs_in_hot_reload`, `test_168_labyrinth_tarpit_walk_in_risk_weights`, `test_168_labyrinth_tarpit_walk_high_weight`, `test_168_tarpit_token_roundtrip`, `test_168_tarpit_verify_rejects_tampered`, `test_168_tarpit_inject_html_adds_hidden_div`, `test_168_tarpit_inject_html_no_body_tag_passthrough`, `test_168_tarpit_page_html_has_fake_content`, `test_168_tarpit_public_subpath_registered`, `test_168_admin_path_is_public_tarpit` (unit); `test_labyrinth_links_injected_in_html_response`, `test_tarpit_endpoint_accessible_without_admin_auth`, `test_tarpit_endpoint_rejects_invalid_token`, `test_tarpit_endpoint_disabled_returns_404` (functional). **Bandit**: 0 H / 0 C, 13 Mediums (all classified). **Trivy**: 0 CVEs. |
| **1.6.7** | **Gateway Registry + multi-user auth + per-session ledger + mesh-sync.** **(1) Gateway Registry** in Settings (no new dashboard) — three tabs (list / distribution matrix / audit log) + 11 endpoints under `/antibot-appsec-gateway/secured/admin/gw-registry/...`; gw_id auto-derives from the domain (operator may override); production-environment edit warning; typed-confirm delete; "copy-once" private-key reveal modal. **(2) Multi-user auth + login flow** — bearer-key auth (`?key=` / `X-Admin-Key`) was **removed**; the only entry to `/secured/...` is signing in via `/antibot-appsec-gateway/login` and carrying the `agw_session` cookie. INTERNAL_KEY is now used **exclusively** as the bootstrap admin password. First-time-setup hint disappears from the login page once any user has logged in; the same hint is also printed to the container's startup log on a fresh `/data` volume. 5/min/IP login rate-limit; scrypt-hashed passwords (N=2¹⁴, random salt); STRICT_ORIGIN CSRF guard on `POST /login`. **(3) Per-session ledger** — every login mints a fresh sid embedded in the cookie HMAC payload (`username\|sid\|expiry\|HMAC`); the `user_sessions` table records source IP + User-Agent + created/last-seen/expires/status; click any username in the Users table → modal lists sessions with per-row Revoke; revoke marks `status=revoked` and the next request silent-decoys (cache-only verify post-boot). Logout revokes the current sid server-side. **(4) Mesh-sync of integration secrets** — small toggle next to each integration's value field in Controls (off by default); when on + REDIS_URL set, the gateway publishes the value to `appsecgw:mesh:offers:<gw_id>` every 30s with TTL 60s; peers scrape and land novel offers in `gw_sync_pending` with status=`pending` only when the local value is empty; nothing reaches the live integration without operator confirmation in Settings → Mesh sync. Allowlist excludes ADMIN_KEY/SESSION_KEY/INTERNAL_KEY. **(5) UX polish** — green ● LIVE pill normalised across every dashboard; portal footer (Antibot AppSec Gateway · © 2026 redacted, S.A. · Confidential) on every page; Sign-out link inline next to Settings in every topnav with a confirm prompt; Online column in Users table (60s in-memory TTL). **Tests**: 153 unit + 15 functional + 10 integration + 94 regression — **272/272 passing, 0 pre-existing failures**. New tests for 1.6.7: `test_167_gw_id_validator`, `test_167_gw_keypair_roundtrip`, `test_167_gw_row_to_dict_strips_private_key`, `test_167_registry_endpoints_registered`, `test_167_local_gw_id_resolves`, `test_167_gw_id_from_domain`, `test_167_mesh_sync_eligible_keys_allowlist`, `test_167_mesh_sync_endpoints_registered`, `test_167_session_revoke_invalidates_cookie`, `test_167_session_token_format_includes_sid`, `test_internal_authed_rejects_bearer_key_post_1_6_7`, `test_internal_authed_accepts_valid_session_cookie`, `test_internal_authed_rejects_tampered_cookie`. **Bandit**: 0 H / 0 C, 13 Mediums all classified (B104 / B608 / B310). **Trivy**: 0 CVEs. **Black-box pentest**: 8 attacks attempted (forged cookie, legacy 3-part token, cookie tampering, replay-after-revoke, login brute-force, CSRF-on-login, retired bearer-key × 2, mesh-sync without auth) — 8/8 blocked. |
| **1.6.6** | **Settings dashboard + endpoint-namespace migration + admin-IP & secrets dual-write.** **(1) Settings dashboard** (`/antibot-appsec-gateway/secured/settings`) — export every hot-reload knob + admin-IP allowlist (and optionally integration secrets) as a zipped XML archive (`appsecgw-config.xml`); import accepts the same archive with dry-run / overwrite-secrets toggles, validating each knob through the same parser/validator pair as `POST /…/secured/config` so an import can never sidestep bounds-checking. Identity strip on the page surfaces the gateway's domain (from `window.location.host`), upstream, version, DB backend, and start time. ZIP handling is hardened: 1 MiB upload cap + 4 MiB inflated cap + strict `appsecgw-config.xml` entry name (no path-traversal). **(2) Endpoint namespace** — every internal endpoint moves under a single `/antibot-appsec-gateway` namespace. Public sub-paths (`live`, `pow`, `solver`, `challenge`, `botd-report`, `assets/*`) live one level up; everything that needs the admin key sits under `/antibot-appsec-gateway/secured/...`. Legacy `/__*` aliases were removed once the new structure was confirmed working — they now silent-decoy 404 like any other unknown URL. Dockerfile + docker-compose HEALTHCHECK migrated to the new path. **(3) Dual-write of every config change** — `_pg_mirror_kv` lands every `set_config` / `del_config` / `set_secret` / `del_secret` / `admin_ip_add` / `admin_ip_remove` / `admin_ip_update_description` SQLite write into Postgres alongside, so an operator-driven backend swap loses no configuration. Standby Postgres schema is initialised at boot (idempotent ALTER for the upgrade path) regardless of the active backend. **(4) Health-score endpoint extended** with `upstream` / `db_backend` / `uptime_secs` so the Settings strip populates without a second request. **Tests**: 142 unit (3 new for 1.6.6) — `test_166_admin_namespace_constants`, `test_166_admin_path_classifier`, `test_166_settings_endpoints_registered`. Bandit: 0 H / 0 C, 12 Mediums all classified (B104 / B608 / B310 / B314 — the new B314 is the import endpoint's `ET.fromstring` call, mitigated by 1 MiB upload cap + admin auth gate). Trivy: 0 CVEs. |
| **1.6.5** | **Observability + escalation tier + pattern expansion.** **(1) Per-detector latency + chal-cookie counter** — every silent-decoy emission bumps `_detector_record(reason, ms)` (rolling 200-sample deque per reason). New `/__detector-stats` returns p50/p99 per signal + per-method-bucket aggregation + chal-cookie mint rate. **(2) Lists snapshot endpoint** (`/__lists-snapshot`) — sizes, last-updated timestamps, and enabled flags for every allow / deny / pattern list. **(3) Detection-method bucketing** — `_REASON_METHOD` maps every block reason into one of 10 method buckets. **(4) Dashboard** — three new cards: stacked-bar of methods, top-method ranking, rolling block-rate trend. **(5) Agents** — rule-inventory card + per-method latency table. **(6) Service** — per-detector p99 panel + cost-by-bucket bars. **(7) Controls** — active-rules table (% of blocks per rule), allow/block lists snapshot, endpoint-policies summary. **(8) Logs** — method-bucket + IP-type filters + CSV export (`/__logs-export`, up to 50 000 events). **(9) GeoMap** — bypass-rate proxy column. **(10) Detector escalation tier** — expensive / external detectors (AbuseIPDB / CrowdSec / MaxMind ASN / body-pattern / DLP) skipped on identities with `risk_score < ESCALATION_THRESHOLD`. New `ESCALATE_ONLY_REASONS` + `ESCALATION_THRESHOLD` hot-reload knob. **(11) Escalate icon** rendered next to escalate-only signals in the Controls table. **(12) Suspicious-body / suspicious-path pattern expansion** — body groups 6-12 patterns each, suspicious-path 70+ patterns (Portswigger / OWASP / PayloadsAllTheThings: Spring4Shell, Log4Shell, IMDS targeting, double-encoded traversal, reverse-shell idioms, NoSQL/LDAP injection, CRLF, every major templating engine). **(13) UI prefs persistence** — GeoMap + Logs filter state saved in sessionStorage. **Tests**: 130 unit pass (8 new for 1.6.5). |
| **1.6.4** | **Pluggable event store + GW health pill + Logs dashboard.** **(1) `DB_BACKEND` toggle** — `sqlite` (default, zero-deps) or `postgres` (future-ready slot for high-volume / multi-instance deployments backed by Postgres + Timescale). Switching requires a container restart and does NOT migrate data; when `DB_BACKEND=postgres` is set without `psycopg` available in the image, the gateway falls back to sqlite with a loud startup warning. Knob exposed in the Controls dashboard with an explicit "RESTART REQUIRED" warning. New env vars: `DB_BACKEND` + `POSTGRES_DSN`. **(2) GW status pill** — fixed top-right pill on every dashboard showing a 0–100 health score (red→yellow→green at the 50 / 80 thresholds). Click → modal with per-pillar breakdown: `disk` (free space at the data volume) / `memory` (RSS vs 256–1024 MiB ceilings) / `db` (SQLite size vs 2 GiB / 10 GiB ceilings) / `integrations` (configured-but-failing AbuseIPDB / CrowdSec / MaxMind) / `bans` (active count) / `block_rate` (last-hour block-to-total ratio). Score = 100 − Σ(weight) of any pillar that's `warn` or `bad`. New endpoint `/__health-score`. Refreshes every 15 s. **(3) Logs dashboard** (1.6.3, restated for completeness) — two tabs (Connection logs from SQLite events / Gateway logs from in-mem ring), level filter, search, pause/resume, segmented LOG_LEVEL push toggle. **Tests**: 64 unit (5 new for 1.6.4) — `test_164_db_backend_default_sqlite`, `test_164_db_backend_falls_back_when_psycopg_missing`, `test_164_postgres_dsn_knob_registered`, `test_164_health_score_endpoint_registered`, `test_164_health_score_payload_shape`. |
| **1.6.3** | **GeoMap upgrade — actionable triage view.** **(1) Country leaderboard** — side panel listing the top 12 countries by clean / missed / blocked counts. Each row has a one-click **deny** button that pushes the ISO code into `COUNTRY_DENYLIST` via `/__config` (also flips `COUNTRY_BLOCK_ENABLED=1` if it was off). The current denylist / allowlist is rendered live below the table. **(2) Click-circle drill modal** — clicking any map circle hits the new `/__geo-drill?lat=…&lng=…&range=…` endpoint and pops a modal with: top 25 IPs at that 0.5° cell (with country, city, ASN org, Tor / DC tags, hit count, blocked count, last reason), top 10 block reasons, top 10 paths. ESC / background click to close. **(3) Tor / DC overlay toggles** — checkboxes in the toolbar overlay distinct markers on top of the base circles: yellow triangles for IPs in `_tor_exits`, purple squares for IPs whose ASN matches `HOSTING_ASN_KEYWORDS`. Two new metric cards (Tor exits, DC / VPN). **(4) Animated time scrubber** — a 24-bucket replay control under the map. The new `/__geo-data` payload includes a sampled `events` array (capped at 5000); the front-end aggregates by bucket client-side and renders per-frame. Play / Pause / "jump to live" controls; auto-refresh pauses while playing so the cursor doesn't get yanked back. New `/__geo-drill` endpoint. `/__geo-data` payload extended with `countries`, `events`, `geo_state`, `tor_hits`, `dc_hits`, `total_tor`, `total_dc`, `start_epoch`. **Tests**: 59 unit (3 new for 1.6.3) — `test_163_geo_drill_endpoint_registered`, `test_163_geo_data_payload_shape`, `test_163_geo_drill_payload_shape`. |
| **1.6.2** | **Tier C — response-side DLP + operational webhook filtering.** **(1) Outbound DLP scanning** — `DLP_ENABLED=1` activates a response-body scanner that runs *after* the upstream replies (so the gateway can also detect data leaving misconfigured / compromised origins). 7 named groups: `cc` (Luhn-validated credit cards) · `aws` (`AKIA*` / `ASIA*` / labelled secrets) · `jwt` (`eyJ…` triple-segment) · `private-key` (PEM headers) · `api-key` (Slack / GitHub / OpenAI / labelled high-entropy secrets) · `pii-email` (off by default — noisy) · `pii-ssn` (US 3-2-4). Every group has its own kill-switch (`DLP_GROUP_*_ENABLED`) and a `dlp-<group>` event reason. Bounded by `DLP_MAX_BYTES` (default 256 KiB) so a single large response can't stall the request path. Optional in-flight redaction (`DLP_REDACT=1` substitutes `[REDACTED-<group>]` for matched bytes). DLP fires accrue **zero** risk on the requester (upstream leakage isn't client malice). When `WEBHOOK_URL` is set, every DLP hit also fires a `dlp_leak` webhook event with group breakdown + redaction status. **(2) Webhook event filter** — `WEBHOOK_EVENT_FILTER` (CSV) lets a SOC consumer subscribe to specific events instead of getting fire-hosed on every ban: e.g. `canary-echo,custom-rule-block,dlp-*` (fnmatch globs supported). Empty = legacy 1.5.0 behaviour (every webhook through). Filter applied *before* Redis dedup so filtered-out events don't burn a dedup token. 11 new hot-reloadable knobs (**88 total**). 7 new `RISK_WEIGHTS` entries (all weight 0). **Tests**: 56 unit (15 new for Tier C) — `test_162_dlp_aws_keys`, `test_162_dlp_jwt`, `test_162_dlp_private_key`, `test_162_dlp_credit_card_luhn`, `test_162_dlp_api_key`, `test_162_dlp_disabled_when_off`, `test_162_dlp_only_text_content_types`, `test_162_dlp_redact`, `test_162_dlp_max_bytes_bound`, `test_162_luhn_check_helper`, `test_162_webhook_filter_empty_passes_all`, `test_162_webhook_filter_exact_match`, `test_162_webhook_filter_glob_family`, `test_162_tier_c_hot_reload_knobs`, `test_162_tier_c_signals_in_risk_weights`. |
| **1.6.1** | **Tier B — operator-defined rules + per-endpoint controls + managed rulesets + JWT.** **(1) Custom rules engine** (`CUSTOM_RULES` JSON) — Cloudflare-Custom-Rules parity: `[{"if":{"path":"/api/*","method":"POST","header.X-Caller":"lambda","ip_cidr":"10.0.0.0/8","country":"PT","query.debug":"1","ua_contains":"corp"},"then":"allow|block|challenge|tag"}]`. First-match-wins, evaluated at L0.4 (before standard detectors) so an `allow` rule short-circuits the chain for legitimate internal traffic and a `block` rule fires `custom-rule-block` (weight 50 → ban). **(2) Per-endpoint rate limit** — extends `ENDPOINT_POLICIES` with optional `{rps, burst}` fields; `[{"path":"/login","policy":"challenge","rps":5,"burst":10}]` token-buckets per (path-glob, identity), fires `rate-limit-endpoint` on overage (zero risk added — pure throttle). **(3) Managed body-pattern rule groups** — split the legacy `BODY_PATTERN_MATCH` blanket into six named groups (`sqli`/`xss`/`lfi`/`rce`/`ssrf`/`cmd`) with per-group kill-switches (`BODY_GROUP_*_ENABLED`); each fires its own `body-<group>` reason (weights 40-50; rce + cmd at the ban threshold). Most-severe-first match order; legacy `suspicious-body` is the catch-all. **(4) JWT/Bearer signature validation** — `JWT_VALIDATE_PATHS` glob list + `JWT_HMAC_SECRET` (HS256, pure-stdlib, no PyJWT dep) with optional `JWT_REQUIRED_ISSUER` / `JWT_REQUIRED_AUDIENCE` and `JWT_LEEWAY_SECS` clock skew; mismatch fires `auth-jwt-invalid` (weight 25). All four features hot-reloadable via `/__config` (10 new knobs, **77 hot-reloadable knobs total**). 9 new `RISK_WEIGHTS` entries + descriptions + signal-knob mapping + cost rows. **Tests**: 41 unit (12 new for Tier B) — `test_161_custom_rules_parser`, `test_161_custom_rule_match_path_method_header`, `test_161_custom_rule_ip_cidr`, `test_161_endpoint_policies_rps_burst`, `test_161_endpoint_rule_lookup`, `test_161_body_groups_match`, `test_161_body_group_disabled`, `test_161_jwt_signature_verify`, `test_161_jwt_expiry_and_claims`, `test_161_jwt_required_for`, `test_161_tier_b_hot_reload_knobs`, `test_161_tier_b_signals_in_risk_weights`. |
| **1.6.0** | **Tier A — Akamai-Kona / Cloudflare-WAF parity feature set.** **(1) Country-level geo block / allowlist** — `COUNTRY_BLOCK_ENABLED=1` + `COUNTRY_DENYLIST=RU,CN,KP` (or `COUNTRY_ALLOWLIST=PT,ES,US` for whitelist mode) consumes the existing GeoLite2-City lookup, costs ~0.1 ms in-process, fires `country-blocked` (weight 50 → instant ban). Allowlist takes precedence over denylist. **(2) AI-crawler granular toggles** — split the legacy `UA_BLOCKLIST` AI section into six named groups (`AI_UA_OPENAI_ENABLED` / `AI_UA_ANTHROPIC_ENABLED` / `AI_UA_GOOGLE_ENABLED` / `AI_UA_PERPLEXITY_ENABLED` / `AI_UA_META_ENABLED` / `AI_UA_OTHER_ENABLED`); each group ships its own kill-switch and a per-vendor reason (`ua-ai-openai`, `ua-ai-anthropic`, …) so an enterprise can allowlist e.g. ClaudeBot for indexing while still blocking OpenAI / Perplexity. **(3) Network-list integration (Tor + DC/VPN)** — `TOR_BLOCK_ENABLED=1` enables auto-fetch of `https://check.torproject.org/torbulkexitlist` (refreshed weekly in-process), checks O(1) set membership, fires `tor-exit` (weight 50 → instant ban). `DC_VPN_BLOCK_ENABLED=1` layers a heavier `datacenter-vpn` (weight 30) on top of the existing `asn-hosting` (weight 5) hosting-ASN flag. **(4) Per-endpoint policy engine** — extends `JS_CHAL_OPEN_PATHS` into an `ENDPOINT_POLICIES` JSON spec with fnmatch globs and four policies: `bypass` / `challenge` / `strict` / `default` — operators express e.g. `[{"path":"/api/v1/*","policy":"bypass"},{"path":"/admin","policy":"strict"}]` and the JS-challenge gate honours per-route policy. All four features are hot-reloadable via `/__config` (12 new knobs added, **67 hot-reloadable knobs total**). 6 new `RISK_WEIGHTS` entries + descriptions + signal-knob mapping + cost rows so the dashboards render them like any other detector. **Tests**: 29 unit (8 new for Tier A) — `test_16_country_set_parser`, `test_16_country_signals_in_risk_weights`, `test_16_country_hot_reload_knobs`, `test_16_ai_groups_nonempty`, `test_16_ai_group_uas_are_lowercase`, `test_16_endpoint_policy_parser`, `test_16_endpoint_policy_match`, `test_16_descriptions_complete`. |
| **1.5.5** | **Turnkey deployment** — `docker-compose.yml` + `.env.example` lay out every env var (UPSTREAM, integrations, thresholds, hardening) so a fresh site can be brought up by `cp .env.example .env && edit && docker compose up -d`. **Bundled GeoLite2 mmdbs** in the image at `/usr/local/share/maxmind/` (seeded into `/data` on first boot) — GeoMap works offline out-of-the-box. **Auto-fetch GeoLite2 mmdbs** — when `MAXMIND_LICENSE_KEY` is set, the container pulls fresh `GeoLite2-ASN.mmdb` AND `GeoLite2-City.mmdb` AND auto-refreshes every 30 d. **Turnstile + Anubis off-by-default** — even with TURNSTILE_SITEKEY/SECRET set, `TURNSTILE_ENABLED` defaults to 0 (closes the deploy-time risk where leaving Cloudflare's public test keys in env silently activated the gate). **`config_kv` table** — every hot-reloadable knob change (toggles / thresholds / lists / log level) survives container restart by mirroring to SQLite; **env wins over DB** when an operator pins a knob via container env (GitOps determinism preserved, env-pinned mutations rejected at runtime with a clear error). **14 new promoted knobs** in `_HOT_RELOAD_KNOBS`: `JS_CHALLENGE_TTL`, `ENUM_THRESHOLD`, `HOSTILE_BAN_SECS`, `TIMELINE_RETAIN_SECS`, `SVC_DB_RETENTION_HOURS`, `COST_RETAIN_SECS`, `LOG_FORMAT`, `POW_REQUIRED_PATHS`, `ALLOWED_METHODS`, `ALLOWED_HOSTS`, `MAX_IDENTITIES`, `PRUNE_IDLE_SECS`, `UPSTREAM_MAX_BODY`, `UPSTREAM_MAX_RESP`. **30-day retention** for `events`, `timeline`, `svc_metrics` (was 24 h / 7 d). **Chart click drill-downs** — click any line/bar on the agents Detection-vs-Miss timeline OR the main dashboard timeline → modal showing IPs / identities for ALL categories (detected / missed / clean — or total / allowed / blocked / missed) with the clicked one highlighted. **GeoMap "Fix now" button** — `/__maxmind-fetch` admin endpoint runs seed + auto-fetch + reopens reader handles without restart. **Controls-dashboard reorder** — External integrations → Defenses & scoring → Unban → Thresholds → Lists → Logging → Apply → Admin IP allowlist → Audit log. **External-integration cards click-to-modal** with vendor / docs / trigger / weight / data-egress / live telemetry. **Risk-gated Turnstile** (`TURNSTILE_RISK_THRESHOLD`) — most legitimate users never see Turnstile, only suspected bots do. **Defense-thresholds slider** on main dashboard with numeric readouts under each handle. **Anubis as proper integration** in `/__external` (with toggle), not just a modifier. **Permissions-Policy opts out of Privacy Sandbox** (silences Cloudflare-edge browser warnings on `*.trycloudflare.com`). **Pentest round 3** (19 attack classes) — only finding was the public Turnstile test secret accepting any token; with real keys the cookie gate is sealed. **Tests**: 21 unit + 14 functional + 148 regression = **183/183 passing**. Bandit: 0 High / 0 Critical (11 Mediums all confirmed false-positives). Trivy: 0 CVE (Critical / High / Medium). SBOM: `sbom/sbom-1.5.5.cdx.json`. |
| **1.5.4** | **Defense thresholds slider** on main dashboard — drag the soft (orange) and ban (red) markers along a 0..200 track with live numeric readouts; releases POST to `/__config` so operators can re-tune the medium-vs-block band live during an attack. **Orange "missed" line** added to the timeline (allowed-but-medium-risk). **Cost-per-request graph** (`/__cost-timeline`) — outer middleware times every request and the dashboard graphs avg/max ms per bucket. **Reason drill-down** — click any block-reason → modal lists offending identities + IPs. **Identity & risk popovers** on the agents *and* main Clients table — click identity for IP/UA/session/JA4/timing/blocks-by-reason; click risk for per-signal contribution bars. **Agents threshold widget** — replaced the input field with up/down arrows + 0..100 range slider. **Anubis-mode** toggle in Controls — raises PoW difficulty by `ANUBIS_DIFFICULTY_BOOST` (default +1 → 16× harder per zero). **GeoMap dashboard** `/__geo` — Leaflet world-map with green=clean / orange=missed / red=blocked circles sized by hit count; CARTO Dark Matter tiles (no API key, no Referer issues); time-window controls. **Services panel + per-detector hits** in `/__metrics` — `services{}` (Redis, AbuseIPDB, CrowdSec, MaxMind, Turnstile, Anubis) and `detector_hits{}` (22 counters). **External-integration cards click-to-modal** — vendor / docs links, trigger criteria, weight, data-egress, live telemetry per integration. **Banned-identity tooltip** on Controls dashboard. **Detection-vs-Miss timeline drill-down** on agents dashboard — click any bar → modal listing the IPs / identities that contributed (`/__agents-bucket`). **11 new per-detector kill-switches** in `/__config`. **Cost column** in scoring table (cached / typical / p99 ms). **Bot-trap field variants** (multiple decoy fields, per-process random suffixes). **Mirrored upstream 404** for blocked admin endpoints. **Admin-IP description** PATCH endpoint + click-to-edit cell. **MaxMind GeoLite2-City** added (`/data/GeoLite2-City.mmdb`; refresh via `maxmind-refresh.sh`). **`Permissions-Policy`** explicitly opts-out of Privacy Sandbox features (silences Cloudflare-edge browser warnings). **`TURNSTILE_RISK_THRESHOLD`** (default = mid-orange band) — Turnstile is now shown only when an identity's risk crosses this threshold; below it, fresh clients fall through to cookie auto-mint. Most legitimate users never see Turnstile, only suspected bots do. **Pentest fix `TRUSTED_PROXIES`** — `X-Forwarded-For` is honoured only when the kernel-observed peer IP is inside the configured CIDRs; closes a 1.5.3 finding where any client hitting the gateway directly could spoof XFF and impersonate any source IP. **CrowdSec env-var alias** — accepts both `CROWDSEC_API_KEY` (original) and `CROWDSEC_LAPI_KEY` (the name CrowdSec's own docs use). **CrowdSec response hardening** — non-list LAPI responses no longer crash the lookup. **Last-seen units** in Clients table progressive (s → min > 1h → h > 4h → d > 48h); fixed an epoch / monotonic mix-up that made DB-loaded clients show negative ages. Unit tests: 11 / 11 passing. Bandit: 0 high / 0 critical. Trivy: 0 CVE (any severity). SBOM: `sbom/sbom-1.5.4.cdx.json`. |
| 1.5.3 | Hybrid identity (cookie+fp) for shared-NAT; soft-challenge tier (score 4–8 forces chal even on open paths); `signals[]` array in event log; UA↔Sec-Ch-Ua consistency, Accept:`*/*` HTML heuristic, JA4-required-missing soft penalty; `Defenses & scoring` merged table; `admin_ips` SQLite table; suspicious-path regex (flag/secret/passwd/credentials/`*.bak`/`*.swp`/`*.git/`/path traversal/SQLi/XSS/LFI markers); upstream-404 risk; risk-weights doc + UI; AbuseIPDB + CrowdSec integrations; MaxMind GeoLite2 ASN tagging. |
| 1.5.2 | **Hard stealth-score auto-ban knob (work-in-progress)** + uniform top-nav across every dashboard (`Dashboard / Agents / Service / Controls`, server-rendered `<a>` tags so the menu is visible without JS). Service dashboard stops crashing when legacy nav-link IDs are absent. Banner stamps `AppSecGW_1.5.2`. |
| 1.5.1 | **Controls dashboard `/__controls`** with on/off switch per toggleable control + number inputs for thresholds + textareas for lists; dirty-marker, **Apply** / **Reset**, audit-log of `config_changed` events, banned-identity table with 1-click unban. Main-dashboard **Throughput cap** card: live req/s + operator-set `GLOBAL_RPS_LIMIT` slider; over-limit traffic silent-decoyed as `traffic-threshold`. Inline **Unban** button next to every banned row in the clients table. Agents dashboard: ban/unban switch in the suspicious-agents table + new `/__ban` admin endpoint mirroring `/__unban`. |
| 1.5.0 | **Multi-instance shared state** (optional `REDIS_URL`): bans propagate across N gateways, JA4 deny-list auto-syncs every 30 s. **Session-churn-by-fingerprint** detector — same `(UA + IP-tier + JA4)` minting > N chal cookies in a window enters the 24 h hostile pool. **Webhook fan-out** (`WEBHOOK_URL` + optional `WEBHOOK_SECRET` HMAC) on every ban; deduplicated via Redis `SETNX`. **Auto-add-to-`JA4_DENY_LIST`** after `JA4_AUTODENY_THRESHOLD` (default 3) bans on the same JA4. |
| 1.4.7 | **Hot-reload admin endpoint** `GET/POST /__config` — read or update a whitelisted set of runtime knobs (toggles, thresholds, lists, log level) without container restart. Every change audited as `event=config_changed`. |
| 1.4.6 | **Structured JSON logs + request correlation IDs.** `LOG_FORMAT=json` emits one JSON document per line ready for Loki/Splunk/CloudWatch. Every request gets a short `r…` ID minted at the top of `protect()`, threaded through every decision and stamped on the response as `X-Request-ID`. Inbound `X-Request-ID` honoured (CDN trace propagation). |
| 1.4.5 | **HMAC key rotation lever.** New admin endpoint `POST /__rotate-keys?key=…&scope=session\|pow\|all` regenerates `SESSION_KEY` (and optionally `POW_HMAC_KEY`) atomically and persists to `/data/.session_key` / `.pow_key`. Every chal/session cookie issued before the call fails HMAC verification immediately. Closes the pentester finding "old chal cookie still works after upgrade — HMAC secret not rotated". `JS_CHAL_OPEN_PATHS` documented as the SPA-friendly knob for data-layer prefixes (`/bin/mvc.do/,/api/,…`). Dashboards stamp `AppSecGW_1.4.5`. |
| 1.4.4 | **No third-party dependency.** Cookie gate engages with `JS_CHALLENGE=1` regardless of Turnstile — when Turnstile keys are configured the cookie is minted by Cloudflare's `siteverify` (production-grade), otherwise the cookie is auto-minted on the first qualifying HTML GET (heuristic friction layer; ~1 RTT bypass cost vs determined script). Gateway is now fully usable without any external service. **Silent-decoy status code now mirrors upstream `/`** instead of hard-coded 200 — closes the 200-with-404-page fingerprint that an agent could use to distinguish blocked vs forwarded responses. |
| 1.4.3 | **AI-canary echo detection (R7) + 24 h hostile pool (R8).** Every HTML response (challenge page included) is stamped with a unique `agw-c-<16hex>` token in an HTML comment and the `X-Trace-Id` header. Subsequent requests from any identity that quotes one of those tokens back at the gateway — in URL, header, or POST body — are silent-decoyed and the identity is added to the hostile pool for `HOSTILE_BAN_SECS` (default 24 h). Pentester-confirmed: this catches LLM-driven agents whose model context treats server-issued strings as actionable text and re-emits them in subsequent prompts. Near-zero false-positive on browser traffic. |
| 1.4.2 | **JS challenge is now Turnstile-only.** PoW + browser-API probe + anchor-fetch proof + timing window were empirically bypassable in pure Python in ~1 s/session and have been removed. The cookie gate engages only when `TURNSTILE_SITEKEY` + `TURNSTILE_SECRET` are configured; the chal cookie is then minted by Cloudflare-server-validated tokens and bound to (UA + IP-tier-hash + JA4-hash). Cross-version pentest matrix and per-iteration verdicts published in this README. |
| 1.4.1 | slowloris guard · bot-trap forms · body pattern matching · service-metrics dashboard (CPU/mem/disk/procs/FDs/net/SQLite size) · windowed time-navigation on agents + service charts · TLS / JA4 fingerprint deny-list (`JA4_TRUSTED_PEERS` for source pinning) · `STRICT_ORIGIN` enforcement on state-changing methods · `REQUIRED_HEADERS` operator-defined header presence check · dashboard HTML extracted to `dashboards/` · service-metrics samples persisted to SQLite (restart-survivable) · **V8/F1-F4** chal cookie required on every non-static path (closes API bypass via Mozilla UA) · static-suffix bypass tightened against `/api/...css` style probes (`JS_CHAL_STRICT_STATIC`) · `/__challenge` rate-limited · stealth-block precedence (host/TLS/origin checks fire before challenge gate) · chal cookie bound to socket-IP /24 (v4) or /48 (v6) tier (opaque HMAC hash, no RFC1918 leak) · XFF-aware client-IP source · chal cookie bound to JA4 TLS fingerprint hash (`JS_CHAL_BIND_JA4`) when injected by a trusted peer · per-request JA4 surfaced in event log so operators can populate `JA4_DENY_LIST` from telemetry · cookie gate exposed across V9 → R3 iterations to be a bot-cost amplifier, not a hard wall (replaced in 1.4.2) |
| 1.3 | Wolfi distroless (zero CVEs) · WebSocket bridge · SSO 302 rewriting · admin IP allowlist · edge security headers · stealth-agent hunter · streaming body fix |
| 1.2 | hardening pass · 34/34 audit findings closed · timeline + agents dashboards · PoW replay protection |
| 1.0 | initial 6-layer prototype |

## Pentest results per version

Each row is a recorded post-release pentest of the deployed image. The "honest verdict" column is what the pentester (and we) *empirically observed* — not what the marketing claimed.

| Version | Configuration | Probe / scenario | Result | Honest verdict |
|---|---|---|---|---|
| 1.0 — 1.3 | n/a | Layered heuristics only (UA filter, header completeness, behavioral, rate-limits) | Bare-bot UAs (`curl`, short UA, `python-requests`) silent-decoyed; full-Chrome scripted clients forwarded | Bot-cost amplifier — never claimed to stop a determined scripted client |
| 1.4.1 (V8) | `JS_CHALLENGE=1`, no Turnstile | `Mozilla/5.0` + `Accept: application/json` straight to `/api/v1/users` | **Forwarded — bypass works** (V8 finding) | Cookie gate only checked HTML routes; API paths sailed through on a UA substring |
| 1.4.1 (V8 fix) | same, post-fix | Same as above | Silent-decoyed | Cookie now required on every non-static path |
| 1.4.1 (V9) | `+ CHAL_PROBE_STRICT=1`, `JS_CHAL_DIFFICULTY=5` | Solve PoW in Python, build matching probe, POST `/__challenge` | **Cookie issued in ~1.2 s** (V9 finding) | PoW + probe are client-computed → fully scriptable |
| 1.4.1 (V9.1) | + opaque tier-hash | inspect cookie wire format | No `172.17.0.0` / RFC1918 leak | Earlier V9.0 had leaked the docker bridge IP |
| 1.4.1 (V9.2) | + `JS_CHAL_BIND_JA4=1` | Cookie minted under Python urllib JA4 → replayed under different JA4 | Replay silent-decoyed; same-JA4 single-stack attacker still passes after 1.2 s PoW | Handshake binding closes cross-stack replay; doesn't stop a determined single-stack attacker |
| 1.4.1 (R1) | as V9.2, direct connection (no JA4 header) | Same Python PoC | **Cookie issued in 1.16 s** | JA4 binding disengages without a JA4-injecting front |
| 1.4.1 (R2) | + `JS_CHAL_REQUIRE_ANCHOR=1` (anchor-fetch proof) | Naïve Python script (no anchor) | Rejected `anchor missing` | Naïve bypass dies |
| 1.4.1 (R2 adapted) | same | Script parses HTML, fetches anchor, then POSTs | **Cookie issued in ~1.0 s** | +1 RTT cost; bypass scriptable in 4 lines |
| 1.4.1 (R3) | + dual anchor (`<img>` + `<script src=…&j=1>`) + 400 ms timing window | Script that fetches both anchors | **Cookie issued in ~1.4 s** | +1 more RTT; bypass scriptable in 1 more line |
| **1.4.2** | PoW + probe + anchor + timing **removed**; `JS_CHALLENGE=1` requires Turnstile keys to engage | Pure-Python `Mozilla/5.0` on `/api/...` | Forwarded (gate intentionally OFF without TS keys) | Pre-V8 layers active; honest about the gap |
| 1.4.2 (Turnstile, T1) | `TURNSTILE_SITEKEY=1x00…AA` + always-pass test secret | Empty token | 403 `missing turnstile` | Token-required check works |
| 1.4.2 (Turnstile, T1) | same | Dummy non-empty token | **Cookie issued** | Test sitekey is "always pass" by Cloudflare contract — not a finding |
| 1.4.2 (Turnstile, T1) | same | Cookie replay under a different `User-Agent` | Silent-decoyed | UA-binding works |
| 1.4.2 (Turnstile, T2) | always-fail test secret (`2x00…AA`) — mimics real-key rejection of fabricated tokens | Dummy non-empty token | **403 `turnstile rejected`** by Cloudflare `siteverify` | Bypass closed; only legitimately-solved widget tokens validate |
| 1.4.2 (Turnstile, T2) | same | Direct API without cookie | Silent-decoyed | Gate forwards nothing without a valid cookie |
| 1.4.3 (R7) | `CANARY_ECHO_DETECTION=1` (default), `+ Turnstile keys` | Pentester R5/R6 lab — built attacker C11 (110 LoC + `time.sleep(2)`) that bypasses 16 layers of pure-protocol checks | C11 still bypasses generic bot defenses; **but L7 honeypot caught their C5 and L8 canary-echo caught their C6** because LLM-driven agents follow `display:none` links and quote prior-response strings into next prompt | Built into 1.4.3 as the canary-echo detector. Targets only AI agents (low-FP); does NOT claim to stop a determined script-only attacker — that ceiling is the pure-HTTP protocol limit |
| 1.4.3 (R8) | `HOSTILE_BAN_SECS=86400` (default) | Trigger any of the AI-agent reasons (canary-echo, honeypot-silent, ai-probe, suspicious-path) | Identity is added to the hostile pool for 24 h | Generalisation of the existing risk-score ban so AI-flagged clients stay banned long enough to be uneconomic to retry |
| 1.4.4 | `JS_CHALLENGE=1`, **no Turnstile** | `GET /` from a real-Chrome client | Cookie auto-issued (`Set-Cookie: chal=...`); subsequent API calls forwarded to upstream | Heuristic-mint mode works without any third-party dependency |
| 1.4.4 | same | `GET /api/v1/items` directly without first visiting `/` (no cookie) | Silent-decoy with **upstream's actual status** (404 here, not 200) | Status-mismatch fingerprint closed |
| 1.4.4 | same | `POST /__challenge` (Turnstile path is dormant) | `503 challenge unavailable` | Challenge endpoint refuses to mint without Turnstile so it's not exploitable in heuristic mode |
| 1.4.4 | `+ TURNSTILE_SITEKEY/SECRET` | Same as 1.4.3 Turnstile mode | Cookie minted only by Cloudflare-verified token | Operator can opt-in to the Turnstile boundary; not required for the gateway to function |
| 1.4.5 | running container | `POST /__rotate-keys?key=…&scope=session` | **200** + `{"rotated":["session"], …}`; every chal/session cookie issued before the call fails verification | Closes the "HMAC secret not rotated" pentester finding |
| 1.4.5 | same | Replay an OLD chal cookie on `/api/v1/...` after rotation | Silent-decoyed (status mirrors upstream `/`) | Old cookie genuinely revoked, not just expired |
| 1.4.5 | same | Fresh `GET /` after rotation | New cookie minted; APIs accept it | System functional after rotation; legitimate browsers self-recover on next page load |
| 1.4.5 (SPA-friendly) | `JS_CHAL_OPEN_PATHS=/bin/mvc.do/,/release-management/,/entity-management/,/content/` | Single-Page-App XHRs against operator-listed prefixes | Forwarded to upstream regardless of cookie state | Operator decides which prefixes are SPA data-layer (auth-by-app) vs gated nav (auth-by-cookie); other layers (UA, body-pattern, canary echo, rate limits, hostile pool) still apply on open paths |

### Cross-version effectiveness matrix

Same attack battery executed against every locally-available image (`1.1`, `1.2`, `1.3`, `1.4` with `JS_CHALLENGE=1`, `1.4.2` without Turnstile keys, `1.4.2` with Cloudflare always-fail test keys), each container started fresh on port 8444 with a controlled local upstream that returns distinguishable markers. Verdicts:

- **forwarded** — request reached the upstream (no block)
- **silent_decoy** — gateway substituted its cached `/` decoy (200 OK, stealth block)
- **challenge_page** — gateway served the JS-challenge HTML (browser-recoverable block)
- **bad_request** — explicit 400 (control-byte / open-redirect filter)
- **rate_limited** — 429

| Attack | 1.1 | 1.2 | 1.3 | 1.4 | 1.4.2 (no TS) | 1.4.2 (TS) |
|---|---|---|---|---|---|---|
| T01 baseline: full-Chrome on `/landing` | forwarded | forwarded | forwarded | challenge_page | forwarded | challenge_page |
| T02 bare `curl/8.0` UA | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy |
| T03 empty UA | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy |
| T04 `python-requests` UA | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy |
| T05 Mozilla UA, no `Sec-Fetch-*` (header score = 0) | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy |
| T06 Mozilla on `/api/v1/users`, Accept `text/html,json` | forwarded | forwarded | forwarded | challenge_page | forwarded | challenge_page |
| T07 SQLi `UNION SELECT` in form body | silent_decoy | **forwarded** | **forwarded** | silent_decoy | silent_decoy | silent_decoy |
| T08 `<script>` XSS in JSON body | silent_decoy | **forwarded** | **forwarded** | silent_decoy | silent_decoy | silent_decoy |
| T09 honey-pot path `/.git/HEAD` | silent_decoy | silent_decoy | silent_decoy | challenge_page | silent_decoy | challenge_page |
| T10 AI-probe path `/openapi.json` | silent_decoy | silent_decoy | silent_decoy | challenge_page | silent_decoy | challenge_page |
| T11 open-redirect target `//evil.example.com/x` | silent_decoy | silent_decoy | silent_decoy | challenge_page | silent_decoy | challenge_page |
| T12 control byte: NUL in path | silent_decoy | bad_request | bad_request | bad_request | bad_request | bad_request |
| T13 honey-pot `/admin.php` | silent_decoy | silent_decoy | silent_decoy | challenge_page | silent_decoy | challenge_page |
| T14 `Mozilla/5.0 (compatible; Googlebot/2.1)` | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy | silent_decoy |
| T15 V8-sharp: API-only `Accept` on `/api/v1/...` ‡ | forwarded | forwarded | forwarded | **forwarded** | **forwarded** | silent_decoy |
| T16 browser HTML GET on `/landing` | silent_decoy | silent_decoy | silent_decoy | challenge_page | silent_decoy | challenge_page |

‡ T15 was re-tested in **fresh state** for 1.4 and 1.4.2 because risk-score accumulation from T01-T14 silent-decoyed late attacks during the in-order sweep. Fresh state is the honest verdict; the in-order matrix would show silent_decoy for these cells, masking the V8 leak.

**Control effectiveness, summarized:**

| Control | Introduced | Effective from | Notable gap |
|---|---|---|---|
| UA blocklist + length filter | 1.0 | 1.0 | None visible in test set |
| Header-completeness scoring | 1.0 | 1.0 | None visible in test set |
| Honey-pot path list | 1.0 | 1.0 | None |
| AI-probe path list | 1.0 | 1.0 | None |
| Control-byte path filter (`%00`, CR/LF) | 1.2 | 1.2 | 1.1 silent-decoyed instead of explicit `400` |
| Body-pattern matching (`BODY_PATTERN_MATCH`) | 1.4 | 1.4 | **1.2 + 1.3 forwarded SQLi/XSS payloads** — not regressed in 1.4+ |
| Cookie gate on HTML routes | 1.4 | 1.4 (HTML only) | **V8: API-only `Accept` paths slipped through** until 1.4.1 |
| Cookie gate on every non-static path | 1.4.1 | **1.4.2 (with Turnstile)** | Without Turnstile keys the gate is OFF in 1.4.2 — closes only when `TURNSTILE_*` configured |
| Turnstile minter | 1.4.2 | 1.4.2 (when configured) | Test keys are always-pass / always-fail by Cloudflare contract; production keys reject fabricated tokens |
| JA4 cookie binding | 1.4.1 | 1.4.2 (when JA4 header injected by trusted upstream) | Disengages on direct connections; only protects against cross-stack cookie replay |
