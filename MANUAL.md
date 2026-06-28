# AntiBot/WAF GW — Operational Runbook

**Version**: 1.9.9  
**Author**: Pedro Tarrinho

---

## Contents

0. [Production security checklist](#0-production-security-checklist)
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
12. [Virtual Hosts (v1.8.0)](#12-virtual-hosts-v180)
13. [Control Center & dashboard navigation (v1.8.1)](#13-control-center--dashboard-navigation-v181)
14. [Analytics & Control Center charts (v1.8.2)](#14-analytics--control-center-charts-v182)
15. [SIEM Security Event Center (v1.8.4)](#15-siem-security-event-center-v184)
16. [Features added 1.8.5 → 1.8.14](#16-features-added-185--1814)
17. [Tear down](#17-tear-down)
18. [Environment variable reference](#18-environment-variable-reference)

---

## 0. Production security checklist

Run through this before exposing the gateway to the internet. Items marked **REQUIRED** will leave the deployment insecure if skipped.

| # | Item | Variable / action | Status |
|---|------|-------------------|--------|
| 1 | **REQUIRED** — Restrict admin dashboard to known IPs | `ADMIN_ALLOWED_IPS=<your-ip>/32,127.0.0.1` | If unset, gateway logs `[SECURITY WARNING]` on every boot |
| 2 | **REQUIRED** — Set trusted proxy CIDRs | `TRUSTED_PROXIES=<load-balancer-cidr>` | Without this, `TRUST_XFF` falls back to `"none"` and client IP detection is disabled |
| 3 | **REQUIRED** — Mount writable data volume | `-e APPSECGW_KEY_DIR=/data -v /srv/gw:/data` | Keys stored in read-only image dir will be lost on restart |
| 4 | **REQUIRED** — Admin key / bootstrap password = **≥16-char random** secret | Generate: `python3 -c "import secrets,string;print(''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(16)))"` → set as `ADMIN_KEY`/`INTERNAL_KEY`; rotate again via Settings → Users after first login | Never use a guessable/dictionary key. Default `INTERNAL_KEY` is printed in plaintext to container logs. A short or word-based key is brute-forceable through the login form. |
| 5 | Enable 2FA for all admin accounts | Settings → Users → TOTP | Admin session cookie is valid until expiry; 2FA limits blast radius of stolen cookie |
| 6 | Set `ALLOWED_HOSTS` | `ALLOWED_HOSTS=your-domain.com` | Without it the Host header is not validated against an allowlist |
| 7 | Set `UPSTREAM` to internal address only | `UPSTREAM=http://app:3000` (not a public URL) | The upstream itself should be internal. **1.8.11: the SSRF guard is ON by default** (`ALLOW_PRIVATE_UPSTREAM=0`) — `UPSTREAM`/vhost upstreams that resolve to loopback/RFC-1918 are **rejected**. If your compose stack legitimately uses an internal upstream (`app:3000`, `host.docker.internal`, `192.168.x.x`), set `ALLOW_PRIVATE_UPSTREAM=1`. |
| 8 | Review `CUSTOM_RULES` on upgrade | Controls → Endpoint Policies | Custom rules are evaluated before all detection signals |
| 9 | OIDC: ensure the issuer JWKS is reachable | `OIDC_ISSUER=https://kc/realms/<r>` | **1.8.11**: the id_token signature is verified against `<OIDC_ISSUER>/protocol/openid-connect/certs` (RS256/ES\*; `none`/HS\* rejected). The gateway must be able to reach that JWKS endpoint, and `OIDC_ISSUER`/`OIDC_CLIENT_ID` must match the token `iss`/`aud`. Requires the `PyJWT` dependency (bundled in the image). |
| 10 | If raising `UPSTREAM_MAX_BODY`, raise `WAF_BODY_SCAN_BYTES` too | `WAF_BODY_SCAN_BYTES=<bytes>` | **1.8.11**: the body WAF scans `WAF_BODY_SCAN_BYTES` (default 2 MiB). If it is below `UPSTREAM_MAX_BODY`, a payload past the scan window bypasses the WAF — a startup warning fires. |

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
  appsec-antibot-gw:1.9.9
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
# Expect: [keys] loaded … [db] sqlite WAL … [start] AntiBotWaf_GW_1.9.9 listening on :8080
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

All hot-reloadable knobs take effect immediately — no restart needed. Changes are persisted in the `config_kv` SQLite table and survive restarts. **ENV wins over DB**: if a knob is set via container env, it cannot be overridden at runtime — **except** the env-pin-excluded knobs (`TURNSTILE_ENABLED`, `JS_CHALLENGE`, `UPSTREAM`, `ALLOW_PRIVATE_UPSTREAM`), where the env value is only the cold-start default and runtime changes are allowed and persist (DB-wins on restart). As of 1.8.10, `TRUST_XFF`, `TRUSTED_PROXIES`, and `ALLOW_PRIVATE_UPSTREAM` are hot-reloadable from **Settings → Infrastructure** (no restart). A knob shown read-only in Settings with a `REQUIRES RESTART` badge is not hot-reloadable; one shown with a 🔒 / env-pinned note was fixed via container env.

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

### Rate limiting — how it works

The gateway runs a **token bucket** rate limiter on every request. Each
visitor (IP + identity) gets a bucket with a fixed maximum size
(`BURST`) and a refill rate (`REFILL`, in tokens/second). Every request
costs one token. When the bucket is empty, the gateway responds with
HTTP 429 and a `Retry-After` header.

#### Bouncer & stamp-card mental model

- The bucket is a stamp card with `BURST` slots.
- Every request the bouncer (gateway) punches out one stamp.
- Stamps regenerate at `REFILL` per second.
- No stamps left → bouncer says "come back in `Retry-After` seconds."

| Term | What it controls |
|---|---|
| `BURST` | How many requests you can fire **fast** (short-window peak) |
| `REFILL` | How many requests you can sustain **per second** (long-window rate) |

Sustained max rate ≈ `REFILL` req/sec once the burst is spent. Bursting
above that is fine as long as the bucket has tokens — that's the whole
point of the burst capacity.

#### Two buckets per visitor

Every visitor gets TWO buckets:

| Bucket | Scope | Default knobs | Why |
|---|---|---|---|
| **IP bucket** | per raw socket IP | `IP_BURST=60`, `IP_REFILL=5.0` | Protects the gateway itself; runs before identity derivation so a flooder can't burn CPU on the challenge/identity path |
| **Identity bucket** | per `track_key` (IP + UA + JA4 + cookies) | `RATE_LIMIT_BURST=30`, `RATE_LIMIT_REFILL=3.0` | Catches bots that rotate IPs but keep the same browser/TLS fingerprint — their identity bucket stays empty even when the IP bucket is fresh |

Both must allow the request; either one empty → 429.

#### Retry-After formula

When the bucket is depleted (`tokens < 1.0`) the gateway computes:

```
Retry-After = ceil((1.0 - current_tokens) / REFILL)   # seconds
```

So a client hammering after burning through the burst gets
`Retry-After: 1` (it takes ~200ms at `REFILL=5` to regenerate one
token; round up to 1 sec). Lowering REFILL widens the retry window.

#### Tuning playbook

| If you see... | Try... | Why |
|---|---|---|
| Bot floods hitting the gateway hard | Lower `IP_REFILL` to `1.0` or `0.5` | Per-IP sustained rate drops to a trickle; legitimate users barely notice (their bursts are small), bots starve |
| Real users 429'd on a busy API | Raise `RATE_LIMIT_REFILL` to `10`–`20` | Identity-stable clients (browser + cookie) get more throughput; flooders still capped by `IP_REFILL` |
| One vhost is API-heavy, another is static-asset-heavy | Override per-vhost (see below) | Login form: `RATE_LIMIT_REFILL=0.5`; API: `RATE_LIMIT_REFILL=20`. Same gateway, different policy |
| You want to diagnose a 429 | Read the `Retry-After` header in the response | High value → bucket fully depleted + low refill rate. Lower the refill OR raise the burst to widen the cushion |
| Single user at NAT is hitting the IP bucket | Raise `IP_BURST` (e.g. `200`) | Multiple legit users behind one NAT each get their own identity bucket, but share the IP bucket — give IP bucket more headroom |

#### Per-vhost override

All four knobs (`RATE_LIMIT_BURST`, `RATE_LIMIT_REFILL`, `IP_BURST`,
`IP_REFILL`) are vhost-aware. Set per-host in the `VHOSTS` JSON:

```bash
docker run \
  -e VHOSTS='{
    "api.example.com": {
      "UPSTREAM": "https://api-backend",
      "RATE_LIMIT_BURST": 200, "RATE_LIMIT_REFILL": 20
    },
    "login.example.com": {
      "UPSTREAM": "https://login-backend",
      "RATE_LIMIT_BURST": 5, "RATE_LIMIT_REFILL": 0.5
    }
  }' \
  ...
```

The base globals serve as the fallback for any vhost that doesn't
override.

#### Ban blast-radius — `BAN_SCOPE` (1.9.1 iter-11)

By default a behaviour-earned ban is **fleet-wide**: an identity/IP that
trips the risk engine on one vhost is locked out across *every* vhost on
the gateway. `BAN_SCOPE` lets you scope the ban to the vhost where the
bad behaviour was actually observed.

| Value | Effect |
|---|---|
| `global` (default) | Ban applies across all vhosts — current behaviour, backward-compatible |
| `vhost` | Ban applies only to the vhost where it was earned; the same identity can still use other vhosts |

Per-vhost overridable, so you can run mixed policy on one gateway:

```bash
docker run \
  -e VHOSTS='{
    "api.example.com":   {"UPSTREAM":"...", "BAN_SCOPE":"vhost"},
    "admin.example.com": {"UPSTREAM":"...", "BAN_SCOPE":"global"}
  }' \
  ...
```

Implementation notes for operators:

- Global bans **always win** — if an IP carries a global ban it's blocked
  everywhere regardless of `BAN_SCOPE`. The vhost scope only *adds*
  per-vhost isolation for new bans.
- Vhost-scoped bans live in a separate `ip_bans_vhost` table
  (composite key `(ip, vhost)`); the legacy `ip_bans` table is untouched.
  The table is created automatically on first boot — **no migration step,
  no downtime, safe rollback** (an older gateway simply ignores it).
- Rehydrated into memory on restart (`vhost_bans_rehydrated` log line).

#### Default values (current source)

| Knob | Default (`config.py`) |
|---|---|
| `RATE_LIMIT_BURST` | `30` |
| `RATE_LIMIT_REFILL` | `3.0` |
| `IP_BURST` | `60` |
| `IP_REFILL` | `5.0` |

> Older docs (1.3-era `manual/README.md`, top-level `README.md`) list
> `RATE_LIMIT_REFILL=2.0` and `IP_REFILL=8.0` — those defaults drifted
> between 1.3 and 1.9. The values above are what the current build
> ships with; `config.py` is the single source of truth
> (`grep "REFILL\|BURST" config.py`).

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

### Find which control caused a block (1.8.10)

You don't have to guess which knob to tune. On the **Live Feed** (or **Agents**),
click an identity's risk score → the **Risk score breakdown** modal lists every
reason that fired with a **Control** column showing the exact knob that provokes
it, a live **on/off dot** (or value for thresholds/lists), and a **severity**
badge. Click the control name to jump straight to it (Controls or Settings,
scrolled + highlighted), or click its **dot to disable that detection in place**
(confirm → applied immediately). The live-feed **Top controls by blocks** panel
ranks controls by how many blocks they caused — the fastest way to spot an
over-aggressive detector banning legitimate users.

> Reasons map to controls via the server-side `SIGNAL_KNOB` table, surfaced by
> `GET /secured/scoring` (`signal_knob` / `knob_state` / `knob_page` /
> `signal_meta`). Admin-gate reasons (`admin-probe`, `operator-self`) show
> "always-on" — there is no toggle (admin auth is mandatory).

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

### CSRF token for state-mutating API calls (1.8.10)

State-mutating requests (`POST`/`PATCH`/`DELETE` to `/secured/...`) require an
`X-CSRF-Token` header = the `agw_csrf` cookie value (`HMAC(SESSION_KEY, sid)`).
The dashboard JS handles this automatically and **self-heals** a stale token: on
any `403` it re-fetches `GET /secured/csrf` and retries once — so operators never
have to clear cookies, even behind a CDN (e.g. Cloudflare) that rewrites the
cookie to `HttpOnly`. When **scripting** the admin API, send the header
explicitly:

```bash
# Fetch the current CSRF token (JSON; works regardless of cookie HttpOnly)
TOK=$(curl -s -b jar http://localhost:8080/antibot-appsec-gateway/secured/csrf \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["token"])')
curl -s -b jar -X POST http://localhost:8080/antibot-appsec-gateway/secured/config \
  -H "X-CSRF-Token: $TOK" -H 'Content-Type: application/json' -d '{"JS_CHALLENGE":"1"}'
```

> Symptom `{"error":"CSRF token invalid"}` on a valid session usually means a
> stale token; in the browser it self-heals on the next request. If it persists,
> the session itself lapsed — re-login.

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

**From the risk breakdown (1.8.10):** on the Live Feed / Agents, click a banned
identity's risk score → the modal shows a ban header ("Banned ≈Xh left; the live
risk decayed but the ban is a separate entry") and an **Unban this identity**
button. If the identity is an admin IP, a **self-ban guard** banner warns it is
"likely a self-ban from testing" — handy when you ban yourself with curl/replay.

### Via API

```bash
# Unban by identity hash
curl -s -b jar -X POST http://localhost:8080/antibot-appsec-gateway/secured/unban \
  -H 'Content-Type: application/json' \
  -d '{"id": "<identity-hash>"}'        # or {"ip": "1.2.3.4"} | {"all": true}
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
  appsec-antibot-gw:1.9.9
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

### Port-aware vhosts — `VHOST_PORT_AWARE` (v1.9.8)

By default the vhost identity is the **hostname only** — the port in the inbound `Host` header is stripped, so `challenges.site.com:8008` and `challenges.site.com:8009` are the *same* vhost. Set **`VHOST_PORT_AWARE=1`** to make the **`host:port`** the vhost key, so each port is a **distinct vhost** with its own upstream, policy, statistics, and ban scope.

**Why it exists:** CTFd serves *dynamic challenges* as separate instances on the **same hostname but different ports** (`challenges.site.com:8008`, `:8009`, …). With host-only keying every challenge collapses into one vhost, so you can't give each challenge instance its own upstream / per-vhost policy / ban scope. Port-aware keying is what lets a single gateway front per-instance CTFd dynamic challenges.

```bash
docker run ... \
  -e VHOST_PORT_AWARE=1 \
  -e VHOSTS='{
    "challenges.site.com:8008": {"UPSTREAM":"http://chal-a:80"},
    "challenges.site.com:8009": {"UPSTREAM":"http://chal-b:80"},
    "challenges.site.com":      {"UPSTREAM":"http://default:80", "BAN_SCOPE":"vhost"}
  }' \
  appsec-antibot-gw:1.9.9
```

**Lookup precedence** (most → least specific):

1. **exact `host:port`** — e.g. `challenges.site.com:8008`
2. **portless `host`** — an *all-ports fallback* (`challenges.site.com` serves any port that has no exact `host:port` entry)
3. **`*.parent` wildcards** — `*.site.com:8008` (port-specific) then `*.site.com` (all ports)

**Behaviour notes:**

- **Opt-in / backward-compatible.** Default `0` = exactly the historical host-only behaviour; existing vhost configs are unaffected. Hot-reloadable via **Settings → Controls** or `POST /secured/config` `{"VHOST_PORT_AWARE": true}` — no restart.
- **Stats & bans are port-distinct.** `events.vhost`, the dashboard vhost selectors, the per-vhost RPS windows, and `BAN_SCOPE=vhost` bans all key on the full `host:port` when this is on.
- **The `host:port` form is accepted** by the `VHOSTS` env, the Settings → Virtual Hosts add form, and the `/secured/vhosts` API only when `VHOST_PORT_AWARE` is on (the hostname validator otherwise rejects a port).

> **Deployment requirement:** the gateway binds a **single** `LISTEN_PORT`; it distinguishes the ports purely from the inbound **`Host` header**. The front (Cloudflare/nginx/reverse proxy, or a client connecting directly) **must forward the original `host:port`** in the `Host` header (or `X-Forwarded-Host`). A CDN that normalises the `Host` and drops the port will collapse the vhosts back together.

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

## 16. Features added 1.8.5 → 1.8.14

Cross-reference summary of operator-visible changes since the §15 SIEM section
above. Full per-release detail in `CHANGELOG.md`; this is the runbook angle.

### 1.8.5 — Detection / OIDC / TOTP
- **GraphQL detector** (`detection/graphql.py`): introspection/batch/depth limits;
  knob group `GRAPHQL_*`.
- **Interaction probe** (`detection/interaction.py`, 1.8.6): client-side
  mouse/scroll/keystroke entropy; collected on chal page.
- **OIDC login** (`admin/oidc.py`): Keycloak/Auth0/Okta SSO. Set `OIDC_ISSUER`,
  `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`. id_token JWKS-verified (1.8.11+).
- **TOTP 2FA** (`admin/users.py`): per-user TOTP via QR enrolment; partial-token
  pattern keeps password unverified until second factor (1.8.7).

### 1.8.7 — Database backend hot-swap
- **SQLite ↔ PostgreSQL hot-swap** via `/secured/db-switch` — no restart. Live
  migration of `events`, `clients`, `bans`, `metrics_kv`. Config persists via
  async `db_queue`; **wait for flush before restart/verify** or a "persistence
  bug" can be misdiagnosed.

### 1.8.8 — Mesh + Redis hardening
- **Ed25519 gateway mesh** (`admin/mesh.py`): per-gw private key for cross-GW
  signing. Allowlist via `gw_registry`. `REDIS_REQUIRE_TLS` enforces TLS.
- **JA4 / JA4H denylist** hot-reloadable; HMAC ban-signing in `bans`.
- **Settings split-pane subnav** (HTML/CSS/JS/regression suite).

### 1.8.9 — Sidebar collapse + knob kill-switches
- **Sidebar full-hide** + submenu accordion across 9 dashboards.
- **Controls/Settings icon-rail** (second-hide for narrow viewports).
- **Knob kill-switches** enforced (`*_ENABLED = false` short-circuits before
  detection cost).

### 1.8.10 — CSRF + restart-required UX + risk-breakdown
- **CSRF cookie + self-heal**: `agw_csrf` issued on session; client fetches
  `/csrf-token` if cookie missing. Global fetch-shim adds `X-Agw-Csrf` on
  state-mutating calls automatically across all dashboards.
- **`TRUSTED_PROXIES` / `TRUST_XFF` / `ALLOW_PRIVATE_UPSTREAM`** hot-reloadable
  from Settings → Infrastructure (no restart).
- **Per-vhost knob persistence** via `vc(...)` + `_to_bool` coercion.
- **Risk-breakdown "control" column**: each signal links to the knob that
  governs it. Modal action buttons for ban/unban from popover.
- **Session key persistence across restarts** (CSRF doesn't invalidate).
- **`@day` / `@night` theme** (`/secured/theme`): persisted in `config_kv`;
  CSS variables remapped via `html[data-theme]`.

### 1.8.11 — Security hardening (H1-H3, M1-M7)
- **WAF body window** scan capped (`WAF_BODY_SCAN_BYTES`, default 2 MiB);
  startup warns if `UPSTREAM_MAX_BODY > WAF_BODY_SCAN_BYTES`.
- **Central CSRF token** (`admin/auth.py::_csrf_token_valid`).
- **Semantic honey-cred** injection (1.7.3 P1, hardened in 1.8.11).
- **OIDC JWKS verification**: id_token signed RS256/ES\*; `none`/HS\* rejected.
  Issuer must match `OIDC_ISSUER`; aud must match `OIDC_CLIENT_ID`.
- **PoW floor** (minimum difficulty after re-issue).
- **Session-IP rebinding** check (anti-replay).
- **`SERVICE_OWNER` knob**: shown in footer + propagated to alerting.

### 1.8.12 — Honeypots dashboard
- **`/secured/honeypots`** dashboard: trap effectiveness leaderboard, attacker
  storyboard (per-IP journeys, expand-on-click), adaptive time-series buckets
  (≤2h: 5-min; ≤6h: 15-min; ≤2d: hourly; ≤10d: 6-hourly; else daily; cap 400
  buckets / 30-day window).
- **Attack playbook** card: predicted-probes per scanner tool (`SCANNER_SEQUENCES`
  minus already-trapped paths).

### 1.8.13 — Async DB + shared assets
- **Async DB writer** (`db_read_events_async`): event scans offloaded to executor
  to keep aiohttp event loop responsive on 50k-row reads.
- **Postgres `Decimal` coercion**: `EXTRACT(EPOCH FROM ts)` returns `Decimal`
  (not JSON-serializable); coerced to `float` in `_read_events_pg`.
- **Shared dashboard JS** (`dashboards/assets/dashboard-common.js`): first helper
  extracted is `escapeHtml` (was 3-variant drift across 14 dashboards).
- **`reason_in` query param** on `db_read_events`: exact-set filter, replaces
  `reason_like` substring matching (which caused honeypot/honeypot-silent
  double-count).

### 1.8.14 — Security release + observability + export contract
- **Session absolute timeout** (`SESSION_ABSOLUTE_TIMEOUT`, default 8h): hard
  cap on session age regardless of sliding-idle, restored across process
  restarts.
- **Per-session random CSRF nonce** (`user_sessions.csrf_nonce` column): key
  rotation no longer invalidates live sessions' CSRF protection.
- **OIDC state-dict cap** (500): bounded `_OIDC_STATE`; returns 503 Retry-After
  under flood.
- **eTLD+1 origin validation**: `host.endswith("." + allowed_host)` accepted,
  so `sub.example.com` allowed when `example.com` is in `ALLOWED_HOSTS`.
- **Upstream-latency tracking** in `/__metrics`: `upstream_latency.{p50_ms,
  p95_ms, sample_n, warn, warn_threshold_ms}`. `UPSTREAM_LATENCY_WARN_MS`
  (default 2000) triggers `warn:true` on p95 overshoot.
- **Webhook delivery health** in `/__metrics.services.webhook`:
  `{last_success_ts, consecutive_failures, circuit_open}`.
- **Bulk unban UI** (Agents dashboard): checkbox column + floating actions bar.
- **Ban → Logs drill-down**: "View requests →" button pre-filters Logs by IP
  via `sessionStorage`.
- **Full-backup export** (`/secured/settings/export`): now covers 11 sections
  (was 3) — `<knobs>` `<admin_ips>` `<vhosts>` `<siem_alert_rules>`
  `<dlp_patterns>` `<signal_orders>` (LOCAL gw only) `<honey_fingerprints>`
  (most-recent 1000) `<gw_registry>` `<gw_distribution>` `<users>` `<secrets>`.
  `?include_secrets=1` query param honours the operator UI checkbox; archive
  filename suffixed `-with-secrets`. `slog` records the flag for audit.
- **`JA4H_DENY_LIST` + `ABUSEIPDB_CACHE_HOURS`** promoted to hot-reload (survive
  export/import).
- **`agw_lc` HMAC token** (was static `"1"`): replay-protected, bound to IP /24
  tier and 1-hour rolling window (current + previous window for clock skew).
- **Per-identity ghost-detect jitter** (`randint(0, 2)`): unpredictable trip
  count per identity prevents timing oracle.
- **`sec-fetch-nav-absent` signal** (+20): Chrome/Edge `GET text/html` without
  `Sec-Fetch-Mode` scored as bot (curl-impersonate / Playwright spoof).
- **`PRESERVE_HOST` knob** (default `False`): when enabled, forwards the
  client's `Host`/`Origin`/`Referer` headers unchanged. Enable only when the
  upstream routes by the public hostname (CDN-style, multi-tenant apps).
  `X-Forwarded-Host` is set regardless. Per-vhost configurable; hot-reloadable.
- **`UPSTREAM_LATENCY_WARN_MS`**, **`SESSION_ABSOLUTE_TIMEOUT`**, plus the
  promoted hot-reload knobs above — all in §18 reference.

---

## 17. Tear down

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

## 18. Environment variable reference

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
Client → [Reverse Proxy / CDN] → [cloudflared / Docker bridge] → AntiBot/WAF GW → Upstream
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

### Postgres / single-DB mode (v1.9.0)

The gateway runs in **one** of two backend modes — never both at once.
The choice is made at startup from the value of `POSTGRES_DSN`:

| `POSTGRES_DSN` | Active backend |
|---|---|
| **unset / empty** (default) | SQLite at `$DB_PATH` |
| **set** | Postgres only — SQLite at `$DB_PATH` is preserved on disk but unused |

`DB_BACKEND` is **auto-derived** from `POSTGRES_DSN`. The legacy
`DB_BACKEND` env var is still honored when `POSTGRES_DSN` is unset
(SQLite-only deployments may read it for display), but setting
`DB_BACKEND=postgres` without a DSN is invalid and falls back to
sqlite with a warning.

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DSN` | `""` | Postgres connection string (`postgresql://user:pw@host:5432/db`). Set → PG-only mode. |
| `POSTGRES_BOOT_MAX_ATTEMPTS` | `30` | PG-mode only. How many times the boot guard retries `SELECT 1` before refusing to start. |
| `POSTGRES_BOOT_BACKOFF_S` | `1.0` | Seconds between boot-guard retries (uses `await asyncio.sleep` — non-blocking). |
| `PG_POOL_SIZE` | `5` | Max psycopg connections in the pool. |
| `PG_POOL_TIMEOUT` | `2.0` | Seconds a pool acquirer waits before raising. |
| `OFFLINE_BG_TASKS` | `0` | Set to `1` to skip every periodic refresh loop that issues outbound HTTPS (MaxMind / Tor / CrowdSec / feeds / mesh / Redis / JA4 / AI-crawler). Used by the test suite; almost never needed in production. |

#### Boot guard

When `POSTGRES_DSN` is set, on_startup probes Postgres with
`SELECT 1` up to `POSTGRES_BOOT_MAX_ATTEMPTS` times. If the probe
never succeeds the gateway exits non-zero (so the orchestrator
restarts) rather than silently degrading.

| Exit code | Meaning |
|---|---|
| `2` | `POSTGRES_DSN` set but `psycopg` not installed |
| `3` | `POSTGRES_DSN` set but Postgres unreachable after all retries |
| `4` | Postgres reachable but `db_init_postgres()` returned False (e.g. role lacks `CREATE TABLE` privilege) |

#### Upgrade banner

On the first boot after `POSTGRES_DSN` becomes set against a `/data`
volume that still holds an old SQLite database, the gateway prints a
one-shot banner pointing to recovery commands and **creates a marker
file at `<DB_PATH>.pg_migrated`** so subsequent boots stay quiet.
Delete the marker (`rm /data/antibot.db.pg_migrated`) to re-trigger
the banner if you need to re-validate.

```
[db-upgrade] POSTGRES_DSN is now set: PG is the sole backend. Local
SQLite at /data/antibot.db (N users, M events) is preserved but
unused. To downgrade, unset POSTGRES_DSN. To migrate SQLite data
into PG: `python -m db.import`. To back PG up to SQLite:
`python -m db.export`. (This banner won't repeat — see
/data/antibot.db.pg_migrated.)
```

#### Migration CLI tools

Two one-shot CLI tools ship with the gateway image. Both read the
runtime env vars (`POSTGRES_DSN`, `DB_PATH`) and exit non-zero on
failure so they can be wired into an automation pipeline:

```bash
# SQLite → Postgres — atomic transactional import (full rollback
# on first failure; cascading errors don't inflate the count).
python -m db.import                 # uses $DB_PATH + $POSTGRES_DSN
python -m db.import /path/to/src.db --skip-events
python -m db.import --dry-run       # report row counts without writing

# Postgres → SQLite — schema-preserving snapshot for backups /
# downgrades. Refuses to overwrite an existing target unless --force.
python -m db.export                          # writes to $DB_PATH
python -m db.export /path/to/backup.db --force
python -m db.export /path/to/schema.db --force --schema-only
```

| Exit code | Meaning |
|---|---|
| `0` | success |
| `1` | CLI / env error (missing path, missing DSN) |
| `2` | SQLite source missing / unreadable (import) · Postgres unreachable (export) |
| `3` | Postgres unreachable / `db_init` failed (import) · One or more table copies failed (export) |
| `4` | One or more table copies failed (import) · Target file exists without `--force` (export) |

#### Schema versioning

Every successful `db_init_postgres()` upserts a row into a
`pg_schema_versions` table stamping the gateway's `PG_SCHEMA_VERSION`
constant + `applied_ts`. Operators can verify their Postgres matches
the running gateway release with:

```sql
SELECT version, applied_ts, applied_by
  FROM pg_schema_versions
 ORDER BY version DESC LIMIT 5;
```

The current release stamps `version = 1`. Future releases that add
tables or columns will bump this and add a new row.

#### Downgrade

To switch a PG-primary deployment back to SQLite mode without
losing data:

1. (Optional) Snapshot Postgres to a SQLite file:
   `python -m db.export /data/antibot.db --force` (assumes the
   container has the env var pointing at the live PG and writes the
   snapshot into the volume).
2. Unset `POSTGRES_DSN` (env var or compose file) and restart the
   gateway.
3. Delete the `<DB_PATH>.pg_migrated` marker if you want the
   upgrade banner to surface again on a future re-flip.
