# AppSecGW — Anti-Automation Reverse Proxy

A hardened reverse HTTP/WS gateway that sits in front of any web application
and applies **13 layered detection & mitigation controls** against automated
agents (CLI tools, scrapers, headless browsers, AI agents). Domain-agnostic:
the upstream is supplied exclusively via the `UPSTREAM` environment variable.

| Property | Value |
|---|---|
| Image | `appsec-antibot-gw:1.4` (~ 79 MB) |
| Base | Chainguard Wolfi distroless (`cgr.dev/chainguard/python:latest`) |
| Trivy CVE findings | **0** (any severity) |
| Stack | Python 3.14 / aiohttp 3.13 / SQLite WAL |
| User | non-root, UID 65532 |
| Architecture | linux/amd64, linux/arm64 |

---

## Quick start

```bash
docker network create --driver bridge antibot-net 2>/dev/null
docker volume  create antibot-data 2>/dev/null

KEY="$(openssl rand -base64 24 | tr '+/' '-_' | tr -d '=')"
MYIP="$(curl -s https://api.ipify.org)"

docker run -d --name appsec-antibot-gw1.4 \
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
  appsec-antibot-gw:1.4 \
&& echo "ADMIN_KEY: $KEY"
```

Put TLS in front (`nginx`, `cloudflared`, `caddy` …). The proxy itself
listens HTTP-only on `:8443`.

---

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
- **Edge-injected security response headers** on HTML (XFO, nosniff, HSTS, COOP, CORP, Permissions-Policy, …)

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
| `/__dashboard?key=…` | Real-time metrics, timeline (total / allowed / blocked) |
| `/__agents?key=…` | **Stealth Agent Hunter** — identities that passed every block but exhibit stealth signals |
| `/__service?key=…` | **Service Metrics** — CPU / memory / disk / processes / FDs / network / SQLite size with 12 h windowed history |
| `/__service-data?key=…` | Service-metrics JSON feed (windowed) |
| `/__metrics?key=…` | JSON feed |
| `/__agents-data?key=…` | Per-identity stealth-score JSON |
| `/__agents-timeline?key=…` | Detected-vs-missed timeline JSON |
| `/__pow?key=…` | Mint a PoW challenge bound to (method, path) |
| `/__solver?key=…` | Browser-side PoW solver |
| `/__status?key=…` | Per-identity bucket state |
| `/__unban?key=…&id=… \| ip=… \| all=1` | Clear ban + risk for an identity / IP / all |

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
| `TRUST_XFF` | `last` | `last` behind a trusted proxy / cloudflared, `none` for direct exposure |

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

PoW is **opt-in**. Set `POW_REQUIRED_PATHS=/login,/admin` to require PoW on
those paths only.

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

### v1.4 controls (all opt-in / safe defaults)

| Variable | Default | Description |
|---|---|---|
| `JS_CHALLENGE` | `0` | Invisible CAPTCHA — first HTML hit returns a tiny JS that POSTs back a server-issued nonce, then sets a 24 h cookie. Blocks pure-HTTP scrapers. |
| `JS_CHALLENGE_TTL` | `86400` | Cookie lifetime in seconds. |
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
docker build --pull -t appsec-antibot-gw:1.4 .
trivy image appsec-antibot-gw:1.4        # expect 0 findings
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
├── README.md                                   this file
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
| 1.4 | JS challenge · slowloris guard · bot-trap forms · body pattern matching · service-metrics dashboard (CPU/mem/disk/procs/FDs/net/SQLite size) · windowed time-navigation on agents + service charts |
| 1.3 | Wolfi distroless (zero CVEs) · WebSocket bridge · SSO 302 rewriting · admin IP allowlist · edge security headers · stealth-agent hunter · streaming body fix |
| 1.2 | hardening pass · 34/34 audit findings closed · timeline + agents dashboards · PoW replay protection |
| 1.0 | initial 6-layer prototype |
