# AppSecGW — Operational Runbook

**Version**: 1.8.7  
**Author**: Pedro Tarrinho

---

## Contents

1. [Start](#1-start)
2. [Stop / restart](#2-stop--restart)
3. [Inspect logs](#3-inspect-logs)
4. [Tune knobs (hot-reload)](#4-tune-knobs-hot-reload)
5. [Admin login](#5-admin-login)
6. [Rotate keys](#6-rotate-keys)
0. [Production security checklist](#0-production-security-checklist)
7. [Unban an identity](#7-unban-an-identity)
8. [AI-agent detection (v1.7.3)](#8-ai-agent-detection-v173)
9. [DLP redaction](#9-dlp-redaction)
10. [GeoIP refresh](#10-geoip-refresh)
11. [Multi-instance (Redis fleet)](#11-multi-instance-redis-fleet)
12. [Virtual Hosts (v1.8.0)](#12-virtual-hosts-v180)
13. [Control Center & dashboard navigation (v1.8.1)](#13-control-center--dashboard-navigation-v181)
14. [Analytics & Control Center charts (v1.8.2)](#14-analytics--control-center-charts-v182)
15. [SIEM Security Event Center (v1.8.4)](#15-siem-security-event-center-v184)
16. [Tear down](#16-tear-down)
17. [Environment variable reference](#17-environment-variable-reference)

---

## 0. Production security checklist

Run through this before exposing the gateway to the internet. Items marked **REQUIRED** will leave the deployment insecure if skipped.

| # | Item | Variable / action | Status |
|---|------|-------------------|--------|
| 1 | **REQUIRED** — Restrict admin dashboard to known IPs | `ADMIN_ALLOWED_IPS=<your-ip>/32,127.0.0.1` | If unset, gateway logs `[SECURITY WARNING]` on every boot |
| 2 | **REQUIRED** — Set trusted proxy CIDRs | `TRUSTED_PROXIES=<load-balancer-cidr>` | Without this, `TRUST_XFF` falls back to `"none"` and client IP detection is disabled |
| 3 | **REQUIRED** — Mount writable data volume | `-e APPSECGW_KEY_DIR=/data -v /srv/gw:/data` | Keys stored in read-only image dir will be lost on restart |
| 4 | Rotate the bootstrap admin password | Settings → Users after first login | Default `INTERNAL_KEY` is printed in plaintext to container logs |
| 5 | Enable 2FA for all admin accounts | Settings → Users → TOTP | Admin session cookie is valid until expiry; 2FA limits blast radius of stolen cookie |
| 6 | Set `ALLOWED_HOSTS` | `ALLOWED_HOSTS=your-domain.com` | Without it the Host header is not validated against an allowlist |
| 7 | Set `UPSTREAM` to internal address only | `UPSTREAM=http://app:3000` (not a public URL) | SSRF protection filters localhost/RFC-1918 but the upstream itself should be internal |
| 8 | Review `CUSTOM_RULES` on upgrade | Controls → Endpoint Policies | Custom rules are evaluated before all detection signals |

> **How to verify #1:** If `ADMIN_ALLOWED_IPS` is unset the startup banner prints:
> ```
> [SECURITY WARNING] ADMIN_ALLOWED_IPS is not set.
>   The admin dashboard is reachable from any IP address.
>   Set ADMIN_ALLOWED_IPS=<your-ip>/32,127.0.0.1 before deploying to production.
> ```
> This line goes to **stderr**. Check with `docker logs appsecgw 2>&1 | grep SECURITY`.

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
  appsec-antibot-gw:1.8.7
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

## 14. Analytics & Control Center charts (v1.8.2)

The Control Center landing page (`/antibot-appsec-gateway/secured/control-center`) ships six analytics charts driven by four new backend endpoints. All endpoints require a valid `agw_session` cookie (unauthenticated requests are redirected to `/login`).

### Charts at a glance

| Chart | Canvas / DOM ID | Endpoint | Refresh |
|---|---|---|---|
| Traffic Pipeline | `#traffic-pipeline-chart` | `/secured/traffic-pipeline` | 60 s |
| Bot Score Distribution | `#score-dist-chart` | `/secured/score-distribution` | 30 s |
| Vhost Block Rate Heatmap | `#vhost-heatmap-body` | `/secured/vhost-heatmap` | via range/bucket change |
| Signal Performance Matrix | `#signal-perf-chart` | `/secured/signal-performance` | 60 s |
| Geo Top Countries | `#geo-country-chart` | `/secured/geo-data` | on Threat section open |
| Threat Category Donut | `#threat-donut-chart` | `/secured/detector-stats` | 30 s |

### Time-window controls

The Traffic Pipeline, Vhost Heatmap, and all other time-windowed charts accept three query parameters:

```
GET /antibot-appsec-gateway/secured/traffic-pipeline?range=120&bucket=300&end=1747350000
```

| Parameter | Description | Default |
|---|---|---|
| `range` | Window length in minutes | 120 |
| `bucket` | Bucket width in seconds | 300 |
| `end` | End epoch (UNIX seconds); omit or `0` = live mode | live |

When `end` is set, charts pause at that point in time (replay mode). The frontend time-range `<select>` and bucket `<select>` controls in the sidebar trigger `_loadTimeCharts()`, which rebuilds all time-windowed charts simultaneously.

### Endpoint reference

#### `GET /secured/score-distribution`

Returns an 8-bin histogram of all active client risk scores (scores decay — clients with expired TTL are excluded).

```json
{
  "bins": [
    {"label": "0–12", "count": 1240},
    {"label": "13–25", "count": 87},
    …
    {"label": "88–100", "count": 3}
  ],
  "threshold_soft": 25,
  "threshold_ban": 50,
  "total_ips": 1330
}
```

`threshold_soft` and `threshold_ban` are drawn as vertical reference lines on the histogram.

#### `GET /secured/traffic-pipeline`

Returns per-bucket request counts across four categories for the requested time window.

```json
{
  "timeline": [
    {"t": 1747348800, "allowed": 542, "challenged": 12, "blocked": 38, "bypassed": 0},
    …
  ],
  "totals": {"allowed": 9840, "challenged": 201, "blocked": 672, "bypassed": 0},
  "range_min": 120,
  "bucket_secs": 300
}
```

For windows exceeding ~12h the endpoint automatically falls back to SQLite aggregation (same `GROUP BY CAST(ts/bucket AS INTEGER)` pattern as `_svc_db_history`).

#### `GET /secured/vhost-heatmap`

Returns a sparse matrix of block-rate cells for the heatmap table.

```json
{
  "vhosts": ["api.example.com", "shop.example.com"],
  "buckets": [1747348800, 1747349100, …],
  "cells": {
    "api.example.com:1747348800": {"requests": 120, "blocked": 4, "block_rate": 0.033}
  }
}
```

Vhosts with no traffic in the selected window are flagged with a **SILENT** badge in the table header row.

#### `GET /secured/signal-performance`

Returns per-detector latency percentiles and block rates.

```json
{
  "signals": [
    {
      "reason": "suspicious-path",
      "method": "regex",
      "hits": 432,
      "blocks": 432,
      "p50_ms": 0.1,
      "p95_ms": 0.3,
      "p99_ms": 0.8,
      "block_rate": 1.0
    },
    …
  ],
  "method_totals": {"regex": 1240, "network": 87, …}
}
```

`p50/p95/p99` are computed from rolling 200-sample per-reason deques using linear interpolation. The Signal Performance Matrix chart plots `hits` and `blocks` as two horizontal bar series.

### Reading the heatmap

| Cell colour | Meaning |
|---|---|
| Red | ≥ 50% block rate |
| Orange | 20–49% block rate |
| Yellow | 5–19% block rate |
| Green | < 5% block rate |
| Grey / **SILENT** | No requests in the selected window |

### Querying the endpoints via curl

```bash
# Authenticate and save the session cookie
curl -c /tmp/session.cookie -X POST \
  -d "username=admin&password=<password>" \
  https://gw.example.com/antibot-appsec-gateway/login

# Fetch Traffic Pipeline for the last 2 hours, 5-min buckets
curl -b /tmp/session.cookie \
  "https://gw.example.com/antibot-appsec-gateway/secured/traffic-pipeline?range=120&bucket=300"

# Fetch Bot Score Distribution
curl -b /tmp/session.cookie \
  "https://gw.example.com/antibot-appsec-gateway/secured/score-distribution"

# Signal Performance
curl -b /tmp/session.cookie \
  "https://gw.example.com/antibot-appsec-gateway/secured/signal-performance"

# Vhost Heatmap (last 6 hours, 15-min buckets)
curl -b /tmp/session.cookie \
  "https://gw.example.com/antibot-appsec-gateway/secured/vhost-heatmap?range=360&bucket=900"
```

All four endpoints return `Cache-Control: no-store` and respond with `application/json`.

---

## 15. SIEM Security Event Center (v1.8.4)

The SIEM Security Event Center provides a single-pane view of all security events collected by the gateway. It is auth-gated and served from a dedicated dashboard.

### Access

| Route | Method | Auth | Response |
|---|---|---|---|
| `/antibot-appsec-gateway/secured/siem` | GET | session cookie | HTML dashboard |
| `/antibot-appsec-gateway/secured/siem-data` | GET | session cookie | JSON |

Both endpoints require a valid `agw_session` cookie. Unauthenticated requests receive HTTP 404 (silent decoy). The HTML page is served with `X-Frame-Options: DENY`, `Cache-Control: no-store`, and a restrictive CSP.

### Dashboard panels

| Panel | Description |
|---|---|
| Threat Index | 0–100 composite score (`block% × 0.5 + crit×5 + high×2`, capped at 100) |
| KPI bar | Total events, blocked, allowed, active bans, bypasses |
| Event Timeline | Stacked-area chart (blocked / allowed) from `state.timeline` |
| Threat Category Donut | Distribution across threat categories (`body`, `path`, `agent`, `rate`, `fingerprint`, etc.) |
| Event Table | Last 100 events, newest first — IP, path, reason, severity, score, JA4, rid |
| Top IPs | Top 25 identities by risk score — request count, block count, ban status, top reason |
| By Reason | Top 30 non-OK signal reasons with request count |

### Query parameters (`/secured/siem-data`)

| Parameter | Default | Clamp | Description |
|---|---|---|---|
| `mins` | `60` | 1–1440 | Time window in minutes |
| `vhost` | `""` | — | Filter events to a single virtual host (exact match, case-insensitive) |

Non-integer or out-of-range `mins` values are silently clamped; `"nan"`/`"inf"` are rejected by `int()` and fall back to the default.

### Response schema (`/secured/siem-data`)

```json
{
  "ts":           1747350000,
  "threat_index": 23,
  "stats": {
    "total":    412,
    "blocked":  87,
    "allowed":  325,
    "bans":     4,
    "bypasses": 2
  },
  "events": [
    {
      "ts": 1747349900, "ip": "1.2.3.4", "path": "/login",
      "method": "POST", "status": 429, "reason": "rate-limit",
      "score": 75, "ja4": "t13d1516h2_...", "rid": "abc123",
      "ua": "curl/7.x", "sev": "high", "admin": false,
      "track_key": "1.2.3.4|shop.example.com"
    }
  ],
  "timeline":    [{"t": 1747348800, "total": 50, "blocked": 12, "allowed": 38, "missed": 0}],
  "by_reason":   [{"reason": "rate-limit", "count": 45}],
  "threat_cats": [{"cat": "rate", "count": 45}],
  "top_ips":     [{"ip": "1.2.3.4", "requests": 130, "blocked": 87, "risk_score": 75.0, "banned": true, "ban_expires": 3540.0, "top_reason": "rate-limit"}],
  "vhosts":      ["api.example.com", "shop.example.com"],
  "mins":        60
}
```

Severity levels: `"critical"` · `"high"` · `"medium"` · `"low"` · `"info"`. Events are capped at 100; top IPs capped at 25; by_reason capped at 30.

### Example usage

```bash
# Fetch SIEM data — last 2 hours
curl -b /tmp/session.cookie \
  "https://gw.example.com/antibot-appsec-gateway/secured/siem-data?mins=120"

# Filter to a specific vhost
curl -b /tmp/session.cookie \
  "https://gw.example.com/antibot-appsec-gateway/secured/siem-data?mins=60&vhost=api.example.com"
```

---

## 16. Tear down  <!-- was §15 -->

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

## 17. Environment variable reference

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
| `TRUST_XFF` | `"none"` | `"none"` (default, fail-closed) · `"first"` · `"last"` — trust the named XFF hop; requires `TRUSTED_PROXIES` to be set or the proxy check fails closed |
| `TRUSTED_PROXIES` | `""` | CIDR list of trusted reverse proxies (e.g. `10.0.0.0/8,172.16.0.0/12`) |

---

### X-Forwarded-For and Trusted Proxies — configuration guide

#### How it works

Every incoming request has two IP addresses:

- **Socket peer** (`request.remote`) — the TCP connection source. This is always real and cannot be spoofed.
- **`X-Forwarded-For` header** — added/appended by each reverse proxy in the chain. This **can be forged** by a client unless the gateway validates who is allowed to inject it.

The gateway uses `TRUST_XFF` and `TRUSTED_PROXIES` together to decide which IP to use for risk scoring, geo lookups, admin-IP allowlist checks, and event recording:

```
Client → [Reverse Proxy / CDN] → [cloudflared / Docker bridge] → AppSecGW → Upstream
          adds XFF: <real-ip>      peer visible to gateway
```

The gateway only honours the `X-Forwarded-For` header when **both** conditions are true:

1. `TRUST_XFF` is set to `"first"` or `"last"` (not the default `"none"`)
2. The **immediate TCP peer** (the IP that opened the socket to the gateway) is listed in `TRUSTED_PROXIES`

If either condition fails the XFF header is ignored and the raw socket peer is used as the client IP.

#### `TRUST_XFF` modes

| Mode | Which XFF hop is used | When to use |
|---|---|---|
| `none` | XFF ignored entirely — raw socket peer used | Gateway exposed directly to the internet with no reverse proxy |
| `first` | Leftmost entry in `X-Forwarded-For` | **Insecure unless paired with `TRUSTED_PROXIES`** — a client can prepend any IP. Only use when the front proxy strips/rewrites XFF before forwarding. |
| `last` | Rightmost entry in `X-Forwarded-For` | **Correct for most deployments.** Each proxy appends the address it received the connection from. The rightmost entry is the IP the last trusted proxy saw — closest to the real client without being client-controlled. |

> **Rule of thumb:** use `TRUST_XFF=last` unless your CDN/load balancer explicitly documents that it puts the real client IP as the **first** entry and strips any client-supplied values.

#### `TRUSTED_PROXIES`

Comma-separated list of CIDRs. Only peers whose IP falls inside one of these networks are allowed to supply an `X-Forwarded-For` header that the gateway will trust.

**Fail-closed:** if `TRUSTED_PROXIES` is empty the gateway ignores all XFF headers regardless of `TRUST_XFF`. This prevents a spoofed-XFF bypass on deployments that have no reverse proxy.

#### Common deployment scenarios

**1. Cloudflare tunnel (`cloudflared`) in the same Docker Compose stack**

`cloudflared` connects from the Docker bridge (`172.18.0.0/16` by default). It injects the real visitor IP as the last `X-Forwarded-For` entry.

```env
TRUST_XFF=last
TRUSTED_PROXIES=172.18.0.0/16
```

Verify the bridge subnet with:
```bash
docker network inspect antibot-net --format '{{.IPAM.Config}}'
```

**2. Cloudflare tunnel running on the host (not in Docker)**

`cloudflared` connects from loopback (`127.0.0.1`):

```env
TRUST_XFF=last
TRUSTED_PROXIES=127.0.0.1/32
```

**3. Load balancer / nginx in front (same private network)**

```env
TRUST_XFF=last
TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

**4. Multiple hops (CDN → internal LB → gateway)**

Add all intermediate proxy CIDRs. The gateway only checks the **immediate peer** against `TRUSTED_PROXIES`; it does not walk the full XFF chain.

```env
TRUST_XFF=last
TRUSTED_PROXIES=10.10.0.5/32,10.10.0.6/32
```

**5. No reverse proxy (gateway exposed directly)**

```env
TRUST_XFF=none
# TRUSTED_PROXIES not needed
```

#### Warning: misconfiguration detection (v1.8.8)

When `TRUST_XFF` is `first` or `last` but a **private-range** (RFC1918) peer sends XFF without being in `TRUSTED_PROXIES`, the gateway logs a one-shot warning:

```json
{"event":"xff_ignored_proxy_untrusted","peer":"172.18.0.1","hint":"Peer is RFC1918 (likely a Docker sidecar) but not in TRUSTED_PROXIES; XFF will be ignored and all events will record this peer IP. Add the peer's subnet to TRUSTED_PROXIES to fix."}
```

This surfaces the most common misconfiguration: a sidecar (e.g. `cloudflared`, an nginx container) is forwarding traffic with XFF but the gateway doesn't recognise it as trusted — so every event in the dashboard shows the Docker bridge IP instead of the real visitor IP.

#### Security note

Never add `0.0.0.0/0` to `TRUSTED_PROXIES`. Doing so allows any host to inject an arbitrary `X-Forwarded-For` header, letting an attacker impersonate any IP for ban evasion, risk-score bypass, and admin-allowlist bypass.

The gateway always **overwrites** the `X-Forwarded-For` header it sends to the upstream with the gateway-computed real client IP, so the upstream cannot be manipulated by a client-supplied XFF value even if the gateway is misconfigured.

---

### Virtual hosts — v1.8.4

| Variable | Default | Description |
|---|---|---|
| `STRICT_VHOST` | `1` | When enabled (`1`) and at least one vhost is registered, requests whose `Host` header does not match any configured vhost receive a 404 decoy. Set to `0` to allow unknown hosts to fall through to the global `UPSTREAM`. |

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
| `OIDC_ISSUER` | Keycloak realm base URL (e.g. `https://kc.example.com/realms/myrealm`) — enables SSO login button |
| `OIDC_CLIENT_ID` | Keycloak client ID |
| `OIDC_CLIENT_SECRET` | Keycloak client secret |
| `OIDC_DEFAULT_ROLE` | Role assigned to new SSO users on first login (default `viewer`) |
| `OIDC_SCOPES` | Space-separated OIDC scopes (default `openid profile email`) |
