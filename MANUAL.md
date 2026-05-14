# AppSecGW — Operational Runbook

**Version**: 1.7.3  
**Author**: Pedro Tarrinho

---

## Contents

1. [Start](#1-start)
2. [Stop / restart](#2-stop--restart)
3. [Inspect logs](#3-inspect-logs)
4. [Tune knobs (hot-reload)](#4-tune-knobs-hot-reload)
5. [Admin login](#5-admin-login)
6. [Rotate keys](#6-rotate-keys)
7. [Unban an identity](#7-unban-an-identity)
8. [AI-agent detection (v1.7.3)](#8-ai-agent-detection-v173)
9. [DLP redaction](#9-dlp-redaction)
10. [GeoIP refresh](#10-geoip-refresh)
11. [Multi-instance (Redis fleet)](#11-multi-instance-redis-fleet)
12. [Tear down](#12-tear-down)
13. [Environment variable reference](#13-environment-variable-reference)

---

## 1. Start

### Minimal (development)

```bash
docker run -d \
  --name appsecgw \
  -p 8080:8080 \
  -e UPSTREAM=http://your-app:3000 \
  -e APPSECGW_KEY_DIR=/data \
  -v /srv/appsecgw-data:/data \
  appsec-antibot-gw:1.7.3
```

`UPSTREAM` is the only required variable. Keys are auto-generated under `/data` on first boot.

### Via docker-compose (production)

```bash
cp .env.example .env
# Edit .env — set UPSTREAM, optional integrations, secrets
docker compose up -d
```

### Key-directory requirement

The gateway writes three key files to `APPSECGW_KEY_DIR` (default: `/app`, which is read-only in the Chainguard distroless image). **Always mount a writable volume and set `APPSECGW_KEY_DIR=/data`**:

```bash
-e APPSECGW_KEY_DIR=/data -v /srv/gw:/data
```

The directory must be writable by the container user (UID 65532). If using a host-created directory: `chmod 777 /srv/gw` or `chown 65532 /srv/gw`.

### Verify startup

```bash
docker logs appsecgw | head -40
# Expect: [keys] loaded … [db] sqlite WAL … [start] AppSecGW_1.7.3 listening on :8080
curl -s http://localhost:8080/antibot-appsec-gateway/live
# Returns: ok  (plain text — loopback-only; no JSON)
```

> **Note — Cloudflare tunnel:** When `cloudflared tunnel` proxies the gateway, cloudflared connects from `127.0.0.1`, which is in `ADMIN_ALLOWED_NETS`. This means `/live` (and all admin endpoints) are reachable through the tunnel. This is expected behavior — restrict tunnel exposure via Cloudflare Access if public tunnel URLs must not expose admin surfaces.

---

## 2. Stop / restart

```bash
# Graceful stop
docker stop appsecgw

# Restart (preserves /data volume — no config loss)
docker restart appsecgw

# Force-recreate (e.g. after env change)
docker rm -f appsecgw && docker run ...
```

With compose:

```bash
docker compose restart appsecgw
docker compose down && docker compose up -d
```

---

## 3. Inspect logs

### Container stdout (structured JSON or text)

```bash
docker logs -f appsecgw
docker logs --since 5m appsecgw | grep '"level":"warn"'
```

Switch to JSON logs at runtime (no restart):

```bash
curl -s -b jar -X POST http://localhost:8080/antibot-appsec-gateway/secured/config \
  -H 'Content-Type: application/json' \
  -d '{"LOG_FORMAT":"json"}'
```

### Dashboard — Logs tab

`http://localhost:8080/antibot-appsec-gateway/secured/logs`

Tabs: **Connection logs** (SQLite events, last 10 000) · **Gateway logs** (in-memory ring, last 500).  
Filters: level, keyword search, pause/resume. CSV export (up to 50 000 rows) via the export button.

### Query SQLite directly

```bash
docker exec -it appsecgw sqlite3 /data/antibot.db \
  "SELECT ts, ip, reason, risk FROM events ORDER BY ts DESC LIMIT 20;"
```

---

## 4. Tune knobs (hot-reload)

All hot-reloadable knobs take effect immediately — no restart needed. Changes are persisted in the `config_kv` SQLite table and survive restarts. **ENV wins over DB**: if a knob is set via container env, it cannot be overridden at runtime.

### Via admin dashboard (Controls tab)

`http://localhost:8080/antibot-appsec-gateway/secured/controls`

Click **Apply** after adjusting sliders/toggles. Changes appear in the audit log.

### Via API

```bash
# Read current config
curl -s -b jar http://localhost:8080/antibot-appsec-gateway/secured/config | python3 -m json.tool

# Set a knob
curl -s -b jar -X POST http://localhost:8080/antibot-appsec-gateway/secured/config \
  -H 'Content-Type: application/json' \
  -d '{"RISK_BAN_THRESHOLD": 40}'

# Toggle a detector off
curl -s -b jar -X POST http://localhost:8080/antibot-appsec-gateway/secured/config \
  -H 'Content-Type: application/json' \
  -d '{"HONEY_CRED_ENABLED": "0"}'
```

### Common tuning scenarios

| Goal | Knob | Value |
|---|---|---|
| Tighten ban threshold | `RISK_BAN_THRESHOLD` | 30–40 (default 50) |
| Relax for NAT clients | `RISK_BAN_THRESHOLD_NAT` | 120 (default 100) |
| Shorten ban duration | `RISK_BAN_DURATION_SECS` | 1800 (default 3600) |
| Disable JS challenge | `JS_CHALLENGE` | `0` |
| Enable Anubis PoW mode | `ANUBIS_MODE` | `1` |
| Block specific country | `COUNTRY_DENYLIST` | `"RU,CN"` + `COUNTRY_BLOCK_ENABLED=1` |
| Reduce path-sweep sensitivity | `PATH_SWEEP_THRESHOLD` | 60 (default 40) |
| Extend path-sweep window | `PATH_SWEEP_WINDOW_SECS` | 600 (default 300) |
| Enable redirect maze | `REDIRECT_MAZE_ENABLED` | `1` |
| Tighten maze speed check | `REDIRECT_MAZE_MIN_MS` | 1200 (default 800) |
| Lower LLM heuristic page count | `LLM_HTML_MIN_COUNT` | 3 (default 5) |
| Lower canary-probe page count | `CANARY_PROBE_MIN_HTML` | 2 (default 3) |

---

## 5. Admin login

X-Admin-Key / bearer-key auth was removed in 1.6.7. The only entry point to `/antibot-appsec-gateway/secured/...` is a session cookie obtained via the login endpoint.

### Via browser

Navigate to `http://localhost:8080/antibot-appsec-gateway/login`.

Default admin credentials on a fresh `/data` volume are printed once to the container log:

```bash
docker logs appsecgw | grep -i "bootstrap\|admin password\|INTERNAL_KEY\|first.time"
```

### Via curl

```bash
# Log in (saves cookie to jar)
curl -s -c jar -X POST http://localhost:8080/antibot-appsec-gateway/login \
  -d "username=admin&password=<INTERNAL_KEY>"

# All subsequent admin requests use -b jar
curl -s -b jar http://localhost:8080/antibot-appsec-gateway/secured/control-center
```

### Override the bootstrap password

```bash
docker run ... -e ADMIN_KEY=my-strong-password ...
```

---

## 6. Rotate keys

Rotation regenerates the HMAC key for the specified scope and persists to `/data`. All previously-issued cookies/PoW tokens for that scope become invalid immediately.

```bash
# Rotate session cookies only (logs out all users)
curl -s -b jar -X POST \
  "http://localhost:8080/antibot-appsec-gateway/secured/rotate-keys?scope=session"

# Rotate PoW tokens only
curl -s -b jar -X POST \
  "http://localhost:8080/antibot-appsec-gateway/secured/rotate-keys?scope=pow"

# Rotate both
curl -s -b jar -X POST \
  "http://localhost:8080/antibot-appsec-gateway/secured/rotate-keys?scope=all"
```

**Note**: honey-cred keys (P1) are derived from `SESSION_KEY` via HMAC — rotating `session` scope also invalidates all in-flight honey credential probes.

---

## 7. Unban an identity

### Via dashboard

Controls tab → **Banned identities** section → click **Unban** next to the row.

### Via API

```bash
# Unban by identity hash
curl -s -b jar -X POST http://localhost:8080/antibot-appsec-gateway/secured/unban \
  -H 'Content-Type: application/json' \
  -d '{"identity": "<identity-hash>"}'
```

Identity hashes appear in the event log (`identity` field) and in the agents dashboard drill-down.

### Via SQLite

```bash
docker exec -it appsecgw sqlite3 /data/antibot.db \
  "DELETE FROM bans WHERE identity = '<hash>';"
```

The in-process `_ban_set` is not updated by direct DB writes; use the API or restart the container.

---

## 8. AI-agent detection (v1.7.3)

### P1 — Honey credential injection

Every proxied HTML response contains a hidden comment injected before `</body>`:

```html
<!-- internal_api_key = abc123...  debug_endpoint = /antibot-appsec-gateway/probe?k=abc123...  env = staging -->
```

Browsers ignore HTML comments. AI agents parsing page source extract the key and hit the probe endpoint.

**Probe endpoint**: `GET /antibot-appsec-gateway/probe?k=<key>`  
Returns `{"status":"ok"}` regardless. If key matches a known honey credential, fires `honey-cred` (+90 risk) on the issuing identity → near-instant ban.

**Knobs**:
```
HONEY_CRED_ENABLED   1|0   default 1
HONEY_CRED_SCORE     float default 90
```

**Verify injection**:
```bash
curl -s http://localhost:8080/ | grep "internal_api_key"
```

**Session warm-up required for ban propagation**: identity must be stable (≥ 3 requests establishing `agw_session` cookie) before extracting the honey key, otherwise anon-identity vs session-identity mismatch prevents the ban from being applied to followup requests.

### P2 — Redirect maze

For identities whose risk score exceeds `REDIRECT_MAZE_THRESHOLD`, subsequent requests are routed through a chain of HMAC-signed redirects. Off by default.

```
REDIRECT_MAZE_ENABLED    0|1    default 0
REDIRECT_MAZE_THRESHOLD  float  default 20  (risk score trigger)
REDIRECT_MAZE_DEPTH      int    default 4   (redirect hops)
REDIRECT_MAZE_MIN_MS     float  default 800 (minimum human latency ms)
REDIRECT_MAZE_SCORE      float  default 55  (risk added on speed violation)
```

**Maze endpoint**: `GET /antibot-appsec-gateway/maze?t=TOKEN&d=DEST`

### P3 — LLM no-subresource heuristic

Real browsers load CSS, JS, images alongside HTML. AI agents fetch only the HTML document.

```
LLM_HEURISTIC_ENABLED      1|0    default 1
LLM_HTML_MIN_COUNT         int    default 5   (HTML pages before eval)
LLM_SUBRES_RATIO_THRESHOLD float  default 0.0 (zero sub-resources → fire)
LLM_HEURISTIC_WINDOW_SECS  int    default 120
LLM_HEURISTIC_SCORE        float  default 40
```

### P4 — Browser execution probe (canary preload)

A `<link rel="preload" as="fetch">` token is injected into every HTML `<head>`. Browsers auto-fetch it in the background; AI agents do not.

```
CANARY_PROBE_ENABLED   1|0    default 1
CANARY_PROBE_TTL_SECS  int    default 30  (window after HTML fetch)
CANARY_PROBE_MIN_HTML  int    default 3   (HTML pages before eval)
CANARY_PROBE_SCORE     float  default 35
```

**Canary endpoint**: `GET /antibot-appsec-gateway/canary-probe/{token}`

### Path-sweep detector

Fires when a single identity visits ≥ `PATH_SWEEP_THRESHOLD` distinct non-static paths within the sliding window. Runs for **all** identities including valid-cookied sessions (unlike `behavioral.py`).

```
PATH_SWEEP_ENABLED      1|0  default 1
PATH_SWEEP_WINDOW_SECS  int  default 300  (5-min sliding window)
PATH_SWEEP_THRESHOLD    int  default 40   (distinct paths)
```

### Escalation gate

Body-pattern scanning (SQLi, CMDi, SSRF, Log4Shell, etc.) and expensive external lookups are gated by `ESCALATION_THRESHOLD`. Requests from identities with accumulated risk score below this value skip the expensive detectors.

```
ESCALATION_THRESHOLD  float  default 30
```

Set to `0` to disable the gate (useful in DAST / pentest environments to force body scan on every request).

---

## 9. DLP redaction

Response-body DLP (`DLP_ENABLED=1`) scans upstream responses for secrets, PII, and credentials.

**Enable**:
```bash
curl -s -b jar -X POST http://localhost:8080/antibot-appsec-gateway/secured/config \
  -H 'Content-Type: application/json' \
  -d '{"DLP_ENABLED":"1", "DLP_REDACT":"1"}'
```

**Knobs**:
```
DLP_ENABLED               1|0    default 0
DLP_REDACT                1|0    default 0  (replace matches with [REDACTED-<group>])
DLP_MAX_BYTES             int    default 262144 (256 KiB scan limit)
DLP_GROUP_CC_ENABLED      1|0    default 1  (Luhn-validated credit cards)
DLP_GROUP_AWS_ENABLED     1|0    default 1  (AKIA*/ASIA* + labelled AWS secrets)
DLP_GROUP_JWT_ENABLED     1|0    default 1  (eyJ… triple-segment tokens)
DLP_GROUP_PRIVATE_KEY_ENABLED 1|0 default 1 (PEM headers)
DLP_GROUP_API_KEY_ENABLED 1|0    default 1  (Slack/GitHub/OpenAI/labelled keys)
DLP_GROUP_PII_EMAIL_ENABLED 1|0  default 0  (email addresses — high FP rate)
DLP_GROUP_PII_SSN_ENABLED   1|0  default 0  (US SSN 3-2-4 — high FP rate)
```

DLP events accrue zero risk on the requester (upstream leakage is not client malice). When `WEBHOOK_URL` is set, each hit fires a `dlp_leak` webhook event.

---

## 10. GeoIP refresh

MaxMind GeoLite2 databases are seeded into the image at build time. To refresh:

```bash
# Automated (requires MAXMIND_LICENSE_KEY env var)
curl -s -b jar -X POST \
  http://localhost:8080/antibot-appsec-gateway/secured/maxmind-fetch

# Manual — copy new .mmdb files into the data volume
docker cp GeoLite2-ASN.mmdb  appsecgw:/data/GeoLite2-ASN.mmdb
docker cp GeoLite2-City.mmdb appsecgw:/data/GeoLite2-City.mmdb
# Reader handles are reloaded live — no restart needed after maxmind-fetch
```

Or use the helper script:

```bash
MAXMIND_LICENSE_KEY=<key> ./maxmind-refresh.sh
```

---

## 11. Multi-instance (Redis fleet)

Set `REDIS_URL` to share bans, JA4 deny-lists, and canary tokens across a gateway fleet:

```bash
docker run ... -e REDIS_URL=redis://redis-host:6379 ...
```

With docker-compose the bundled `redis` service in `docker-compose.yml` handles this automatically.

**Shared state**: active bans, JA4 deny-list, webhook dedup tokens, mesh-sync offers.

**Mesh sync** (Settings tab) — allows gateways to share integration secrets (AbuseIPDB key, CrowdSec key, etc.) with operator confirmation. Only values not set locally are offered for adoption.

---

## 12. Virtual Hosts (v1.8.0)

Virtual Hosts allow a single gateway container to front multiple upstream services, each identified by the inbound `Host` header. Per-vhost overrides apply only for requests matching that hostname; all other requests use the global configuration.

### Configure via environment variable

Pass a JSON object in `VHOSTS`:

```bash
docker run ... \
  -e VHOSTS='{"shop.example.com":{"UPSTREAM":"https://shop-backend.example.com","UA_FILTER_ENABLED":true},"api.example.com":{"UPSTREAM":"https://api-backend.example.com","RATE_LIMIT_BURST":200}}' \
  appsec-antibot-gw:1.8.1
```

### Manage at runtime (Settings UI)

Open **Settings → Virtual Hosts** in the admin dashboard. From there you can:

- **Add** — enter a hostname and upstream URL; any supported override key can be set.
- **Delete** — remove an existing entry; takes effect immediately.
- **List** — the table refreshes every 5 s automatically.

Changes are persisted to `/data/vhosts.json` and survive container restarts even if `VHOSTS` env is unchanged.

### Manage via API

```bash
# List all vhosts
curl -b session.cookie https://gw.example.com/antibot-appsec-gateway/secured/vhosts

# Add / update
curl -b session.cookie -X POST \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"shop.example.com","UPSTREAM":"https://shop.example.com"}' \
  https://gw.example.com/antibot-appsec-gateway/secured/vhosts

# Delete
curl -b session.cookie -X DELETE \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"shop.example.com"}' \
  https://gw.example.com/antibot-appsec-gateway/secured/vhosts
```

All endpoints require an authenticated admin session cookie.

### Supported override keys

| Key | Type | Description |
|---|---|---|
| `UPSTREAM` | string | Upstream base URL for this hostname (must be a public IP; RFC-1918/loopback blocked) |
| `UA_FILTER_ENABLED` | bool | Enable/disable UA-based bot filter |
| `UA_PLATFORM_CHECK_ENABLED` | bool | Enable/disable platform consistency check |
| `SUSPICIOUS_PATH_ENABLED` | bool | Enable/disable path injection detector |
| `HONEYPOT_ENABLED` | bool | Enable/disable honeypot paths |
| `HONEYPOT_PATHS` | list of strings | Override honeypot path list |
| `COUNTRY_BLOCK_ENABLED` | bool | Enable/disable geo blocking |
| `COUNTRY_DENYLIST` | list of ISO-3166-1 alpha-2 | Block listed countries |
| `COUNTRY_ALLOWLIST` | list of ISO-3166-1 alpha-2 | Allow only listed countries |
| `RATE_LIMIT_BURST` | int | Per-IP burst token bucket size |
| `RATE_LIMIT_REFILL` | float | Token refill rate (tokens/second) |
| `GLOBAL_RPS_LIMIT` | int | Global RPS cap for this vhost |
| `BYPASS_MODE` | bool | Pass all traffic without scoring |
| `BYPASS_PATHS` | list of strings | Path prefixes exempt from all detectors |
| `JS_CHALLENGE` | bool | Enable/disable JS challenge gate |
| `ANUBIS_ENABLED` | bool | Enable/disable Anubis PoW challenge |

### SSRF protection

The `UPSTREAM` value is DNS-resolved at configuration time. Any address resolving to RFC-1918, loopback (127.x/::1), link-local (169.254.x/fe80::), CGNAT (100.64/10), multicast, or other reserved ranges is rejected with an error. This prevents the gateway from being turned into an SSRF pivot via operator-controlled vhost configuration.

---

## 13. Control Center &amp; dashboard navigation (v1.8.1)

### Control Center

After login, operators land on the **Control Center** (`/antibot-appsec-gateway/secured/control-center`). It shows:

- **Vhost Traffic Summary** — per-vhost request counts (Total 1h, Allowed 1h, Blocked 1h, Block%, Total 24h, Blocked 24h, Banned IPs). Auto-refreshes every 30 s via `GET /secured/vhost-stats`.
- **Active ban overview** — count of IPs currently banned, with time-to-expiry distribution.
- **Gateway health stats** — total events, uptime indicator, detector status.

The Control Center is the entry point for all post-login admin work. Use the top-nav to reach:

| Page | URL slug | Purpose |
|---|---|---|
| Control Center | `control-center` | Post-login landing; vhost summary |
| Live Feed | `live-feed` | Real-time traffic chart + client table |
| Agents | `agents` | Bot/agent drill-down and identity view |
| Service | `service` | Per-vhost service health |
| Controls | `controls` | Knob tuning, bypass, JS-challenge |
| Geo | `geo` | Geographic block/allow and map |
| Logs | `logs` | Structured event log with category filter |
| Settings | `settings` | Import/export config, user management |
| Vhost Policy | `vhost-policy` | Per-vhost knob override inspector |

### Vhost filtering in metrics and logs (v1.8.1)

The metrics and log data endpoints accept an optional `?vhost=<hostname>` query parameter to scope results to a single virtual host:

```bash
# Metrics scoped to one vhost
curl -b session.cookie \
  "https://gw.example.com/antibot-appsec-gateway/secured/metrics?vhost=shop.example.com"

# Log events scoped to one vhost
curl -b session.cookie \
  "https://gw.example.com/antibot-appsec-gateway/secured/logs-data?vhost=api.example.com&limit=100"
```

The `vhost` value is validated through `_validate_vhost_hostname()` (RFC-1123: max 253 chars, labels ≤ 63 chars, `[a-z0-9-]` only, no leading/trailing hyphen) before being passed as a bound SQL parameter. Invalid hostnames are rejected with HTTP 400.

---

## 14. Tear down

```bash
# Stop and remove container; preserve data volume
docker rm -f appsecgw

# Full wipe including data (destroys keys + DB — IRREVERSIBLE)
docker rm -f appsecgw
docker volume rm appsecgw-data   # or: rm -rf /srv/appsecgw-data

# With compose
docker compose down
docker compose down -v  # also removes named volumes
```

**Warning**: removing the data volume destroys `antibot.db` (all event history, config), `.admin_key`, `.pow_key`, and `.session_key`. Back up the volume before wiping if audit history matters.

---

## 15. Environment variable reference

### Required

| Variable | Description |
|---|---|
| `UPSTREAM` | Fully-qualified URL of the upstream application (`https://app.example.com`) |

### Key management

| Variable | Default | Description |
|---|---|---|
| `APPSECGW_KEY_DIR` | `/app` | Writable directory for key files. **Must be overridden** when using distroless image — set to `/data` and mount a volume. |
| `ADMIN_KEY` | (auto-generated) | Bootstrap admin password / `INTERNAL_KEY`. Printed once to container log on a fresh data dir. |

### Network

| Variable | Default | Description |
|---|---|---|
| `LISTEN_PORT` | `8080` | Port the gateway listens on |
| `TRUST_XFF` | `""` | `"last"` — trust the last `X-Forwarded-For` hop from `TRUSTED_PROXIES` |
| `TRUSTED_PROXIES` | `""` | CIDR list of trusted reverse proxies (e.g. `10.0.0.0/8,172.16.0.0/12`) |

### Detection — v1.7.3

| Variable | Default | Description |
|---|---|---|
| `PATH_SWEEP_ENABLED` | `1` | Path-sweep detector on/off |
| `PATH_SWEEP_WINDOW_SECS` | `300` | Sliding window duration |
| `PATH_SWEEP_THRESHOLD` | `40` | Distinct non-static paths to trigger |
| `HONEY_CRED_ENABLED` | `1` | P1 honey-credential injection |
| `HONEY_CRED_SCORE` | `90` | Risk score added when probe hits |
| `REDIRECT_MAZE_ENABLED` | `0` | P2 redirect maze (default off) |
| `REDIRECT_MAZE_THRESHOLD` | `20` | Risk score to activate maze |
| `REDIRECT_MAZE_DEPTH` | `4` | Redirect hop count |
| `REDIRECT_MAZE_MIN_MS` | `800` | Minimum human traversal time (ms) |
| `REDIRECT_MAZE_SCORE` | `55` | Risk score on speed violation |
| `LLM_HEURISTIC_ENABLED` | `1` | P3 LLM no-subresource heuristic |
| `LLM_HTML_MIN_COUNT` | `5` | HTML pages before evaluation |
| `LLM_SUBRES_RATIO_THRESHOLD` | `0.0` | Sub-resource ratio threshold |
| `LLM_HEURISTIC_WINDOW_SECS` | `120` | Evaluation window |
| `LLM_HEURISTIC_SCORE` | `40` | Risk score on signal fire |
| `CANARY_PROBE_ENABLED` | `1` | P4 browser execution probe |
| `CANARY_PROBE_TTL_SECS` | `30` | Probe fetch window (seconds) |
| `CANARY_PROBE_MIN_HTML` | `3` | HTML pages before evaluation |
| `CANARY_PROBE_SCORE` | `35` | Risk score on probe miss |
| `ESCALATION_THRESHOLD` | `30` | Min risk score before body/external scan |

### Risk model

| Variable | Default | Description |
|---|---|---|
| `RISK_BAN_THRESHOLD` | `50` | Risk score → ban |
| `RISK_BAN_THRESHOLD_NAT` | `100` | Ban threshold for NAT/shared IP ranges |
| `RISK_BAN_DURATION_SECS` | `3600` | Ban duration (seconds) |

### Logging

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `LOG_FORMAT` | `text` | `text` or `json` (for log aggregators) |

### Integrations (all optional)

| Variable | Description |
|---|---|
| `REDIS_URL` | Redis connection string for fleet mode |
| `ABUSEIPDB_KEY` | AbuseIPDB v2 API key |
| `CROWDSEC_LAPI_KEY` | CrowdSec LAPI bouncer key |
| `CROWDSEC_LAPI_URL` | CrowdSec LAPI URL (default `http://crowdsec:8080`) |
| `MAXMIND_LICENSE_KEY` | GeoLite2 auto-refresh key |
| `TURNSTILE_SITEKEY` | Cloudflare Turnstile site key |
| `TURNSTILE_SECRET` | Cloudflare Turnstile secret |
| `WEBHOOK_URL` | Outbound webhook for ban/DLP events |
| `WEBHOOK_SECRET` | HMAC secret for webhook payloads |
