# Threat Model — AntiBot/WAF GW 1.6.7

> **Historical snapshot — point-in-time threat model as of v1.6.7 (2026-05-01).**
> The trust boundaries and STRIDE analysis here remain broadly valid, but
> version-specific layer references are not updated per release. Current controls
> live in `MANUAL.md` / `CONTROLS.md`; current residual-risk register is in the
> latest `validation/<version>.md` §11b.

Author: Pedro Tarrinho
Date: 2026-05-01
Scope: AntiBot/WAF GW 1.6.7 (post-1.6.7-revalidation cut)

---

## 1. Architecture & Trust Boundaries

```
                                                        Z2: Gateway container (trusted)
   Z0: Internet      Z1: CDN/edge        ┌──────────────────────────────────────────┐
   ─────────────────────────────────────►│ aiohttp ─► protect ─► detectors ─► proxy │
   anonymous   ─►   Cloudflare/         │                            │              │
   attackers,       cloudflared          │ Z3:  /secured/* (admin)   │  Z7: Upstream│
   real users                            │  ◄───── operator browser  │  ───────────►│
                                         │  ◄───── session cookie    │  trusted app │
                                         └──────┬──┬──────┬──────┬───┘
                                                │  │      │      │
                              Z4: Redis ◄───────┘  │      │      └───► Z5: external intel
                              (fleet mesh)          │      │             Turnstile/AbuseIPDB
                              semi-trusted          │      │             CrowdSec/MaxMind
                                                    │      │
                              Z6: TimescaleDB ◄─────┘      └───► /data volume
                              (compose sidecar)                  (secrets, db files)
```

**Trust zones** (lowest → highest):

- **Z0** Internet — every request hostile until proven otherwise
- **Z1** CDN/edge proxy — semi-trusted; XFF only honored from `TRUSTED_PROXIES` CIDRs
- **Z2** Gateway process — trusted root of trust
- **Z3** Operator browser — gated by username+password+session cookie+admin-IP allowlist
- **Z4** Redis — semi-trusted (peer gateways may be hostile); mesh data needs dest-side confirmation
- **Z5** External intel APIs — trusted services (TLS, fixed hostnames)
- **Z6** TimescaleDB — trusted (same compose, internal network)
- **Z7** Upstream app — trusted, the asset we're protecting

## 2. Asset Inventory & Sensitivity

| Asset | Where stored | Sensitivity | Failure mode |
|---|---|---|---|
| INTERNAL_KEY (bootstrap admin password) | `/data/.admin_key` + container env | **Critical** | Full admin takeover on first-boot window |
| SESSION_KEY | `/data/.session_key` | **Critical** | Forge any session cookie / chal cookie |
| POW_HMAC_KEY | `/data/.pow_key` | High | Forge JS-challenge tokens |
| User password hashes (scrypt) | `users` table | High | Offline crack → admin |
| Session ledger (sid→user) | `user_sessions` + in-mem cache | High | Session hijack if cache compromised |
| Integration secrets (TURNSTILE/ABUSEIPDB/CROWDSEC/MAXMIND/JWT) | `secrets_kv` | High | Vendor-API abuse, intel poisoning |
| Mesh keypairs (HMAC secrets per peer gw) | `gw_registry` | High | Forge inter-gw block records |
| Audit log | `gw_audit` | Medium | Cover tracks if mutated |
| Banlist, canary tokens | `bans` / in-mem | Medium | Bypass already-deployed blocks |
| Upstream content | Proxied | Per-app | Data exfiltration via gateway |

## 3. Top Threats by Category

### A. Client-side attacks (Z0 → Z2 → Z7)

| # | Threat | STRIDE | Current mitigation | Residual risk |
|---|---|---|---|---|
| A1 | Determined scripted client (full-Chrome headless w/ valid cookie) reaches upstream | T/E | 36 weighted detectors, risk-score model, NAT-aware threshold, Turnstile (when enabled), BotD, body-pattern, canary echo, PoW | **Medium** — empirically bypassable by skilled attackers (1.4.x pentest history); hard wall only with Turnstile + JA4 + canary stack |
| A2 | Forged JS-challenge cookie | S | HMAC-SHA256 on `(ua+iptier+ja4)`, key on disk + rotatable | Low |
| A3 | Replay of issued chal cookie across IPs / UAs | S | Cookie bound to ip-tier + UA + JA4 (when injected by trusted peer) | Low |
| A4 | Slowloris / connection-stall | D | Header-read timeout, body timeout, BODY_TIMEOUT, aiohttp's bounded read budget | Low |
| A5 | Per-endpoint flood beyond gateway capacity | D | GLOBAL_RPS_LIMIT (off by default), token-bucket per IP/identity, per-endpoint rate limit, hostile pool 24h ban | Medium — operator must opt into GLOBAL_RPS_LIMIT |
| A6 | XSS payload in URL/body reaches upstream | T | suspicious-path regex (70+ patterns), body-pattern groups; no XSS rendered in our HTML responses | Low — but upstream handling is upstream's responsibility |
| A7 | SSRF via Host or upstream redirect | I/E | ALLOWED_HOSTS check, Location-header rewrite | Low |
| A8 | DLP bypass (secret leaks via upstream response) | I | DLP_ENABLED scanner with 7 groups, capped at 256 KiB | Medium — bounded scan misses very large response bodies |

### B. Admin-plane attacks (Z0/Z3 → Z2)

| # | Threat | STRIDE | Current mitigation | Residual risk |
|---|---|---|---|---|
| B1 | Bootstrap password leaks before operator changes it | I/E | INTERNAL_KEY printed to stdout at boot **only** when no user has logged in; `/data/.admin_key` permission = container UID 65532 | **High** — boot logs are commonly shipped to log-aggregation systems (Loki/Splunk). Anyone reading stdout pre-first-login owns the gateway |
| B2 | Brute-force admin password | S | scrypt N=2¹⁴ + 5/min/IP login rate limit | Low — but rate limit is per source IP; rotating-IP attackers (Tor / botnet) bypass quickly. **No global lockout exists.** |
| B3 | Forge session cookie | S | HMAC-SHA256 on `username\|sid\|expiry`, sid must be in cache | Low |
| B4 | Replay revoked cookie | S | Server-side cache invalidation on revoke/logout | Low |
| B5 | Cookie hijack (XSS, MITM, log scraping) | S | HttpOnly + Secure-when-TLS + SameSite=Lax cookie | Medium — Secure flag depends on TLS_ENABLED env, which is **off by default**. Behind an HTTPS-terminating CDN this is fine; without TLS, cookies traverse plaintext on the loopback path. |
| B6 | CSRF on /secured/* via attacker-controlled site | T | STRICT_ORIGIN check on POST + SameSite=Lax cookie | Low |
| B7 | Operator misuse / malicious admin | T | Audit log captures actor IP + action; cannot delete last admin | Medium — single role (admin); no read-only/viewer role yet, no separation of duties |
| B8 | Session ledger lost on container restart | A | `_SESSION_CACHE` reloads from `user_sessions` table at boot | Low |
| B9 | Cold-cache replay window at startup | S | `_SESSION_CACHE_READY=False` accepts HMAC-only briefly during boot | Low — sub-second window; cache loads synchronously before serving |

### C. Mesh / Redis attacks (Z4 ↔ Z2)

| # | Threat | STRIDE | Current mitigation | Residual risk |
|---|---|---|---|---|
| C1 | Hostile peer publishes malicious mesh offer | T/E | Allowlist of syncable keys (excludes ADMIN_KEY/SESSION_KEY); pending state requires dest-operator confirm; existing values not overwritten | **Low-Medium** — requires both ends to be compromised/misconfigured; an operator confirming a hostile offer is the only path. No signature verification on offers themselves yet |
| C2 | Redis instance reachable by attacker | I/E | REDIS_URL is the operator's responsibility — gateway uses any URL passed; no auth enforcement at gateway side | High — if Redis is exposed, attacker can read banlist, canary tokens, mesh offers |
| C3 | Mesh-sync TLS / authn | S/T | None — gateway connects with whatever URL is given (typically `redis://...`) | High — no mTLS, no AUTH command enforced at gateway. **Must be deployed on a private network.** |
| C4 | Forged block records via HMAC-only mesh signing | S | Per-gw HMAC keypair stored in `gw_registry`; receivers verify with peer's "public key" (which is just SHA256(secret) — symmetric model) | **Medium** — symmetric HMAC means anyone with a peer's secret can forge as that peer. Asymmetric (Ed25519) would close this; documented as "until proper Ed25519 lands" |

### D. Data exposure (Z2 → Z0)

| # | Threat | STRIDE | Current mitigation | Residual risk |
|---|---|---|---|---|
| D1 | Admin probe leaks paths/tokens via timing | I | hmac.compare_digest everywhere; uniform 404 silent decoy on auth fail | Low |
| D2 | Error messages leak internal paths | I | All admin errors return `{"error":"..."}` with bounded strings; production logs bounded with `[:200]` truncation | Low |
| D3 | Private keys leaked via List endpoints | I | `_gw_row_to_dict(include_private=False)` default; `?reveal=1` only on local row + audit-logged | Low — caught and fixed during 1.6.7 validation chain |
| D4 | Audit log leaks PII (UA + IP indefinitely) | I | Audit table never auto-pruned; UA truncated to 512 chars | Medium — GDPR concern: IP+UA per session retained until operator deletion |

### E. Container / infrastructure

| # | Threat | STRIDE | Current mitigation | Residual risk |
|---|---|---|---|---|
| E1 | Container escape | E | Chainguard distroless (Wolfi), `read_only`, `cap_drop ALL`, `no-new-privileges`, `pids_limit 200`, mem 256M / cpu 1.0, non-root UID 65532 | Low |
| E2 | Volume access from host (theft of `/data`) | I | Operator-owned host security; no encryption-at-rest at gateway level | High — host root reads `/data/.admin_key`, `/data/antibot.db`. Standard for any container |
| E3 | Image supply chain | T | Trivy 0 CVEs verified; Chainguard pinned base; psycopg/aiohttp/redis-py from PyPI; FingerprintJS BotD bundled (esm.sh-bundled) | Medium — esm.sh CDN bundling pulled BotD source at build time; if compromised, payload is in image. Mitigated by image rebuild + Trivy. |
| E4 | DoS via expensive detector (scrypt on login) | D | Login rate limit 5/min/IP; scrypt budget 64 MB / 70 ms each | Low |

### F. Logging & privacy

| # | Threat | STRIDE | Current mitigation | Residual risk |
|---|---|---|---|---|
| F1 | Bootstrap password printed to stdout (B1 above) | I | Suppressed once any user has logged in | **High** — if logs are shipped before first login, leaked credential lives in cold storage |
| F2 | IP+UA in audit log retained indefinitely | I (GDPR) | Operator-driven rotation only | Medium |
| F3 | Webhook leaks event content to third-party | I | WEBHOOK_EVENT_FILTER allows scoping; HMAC-signed | Low — operator opts in |

## 4. Risk Register (sorted)

| Rank | Risk | Severity | Likelihood | Recommendation |
|---|---|---|---|---|
| 1 | **Bootstrap password leaks via stdout** (F1/B1) | **High** | Medium-High | Print only a SHA256 fingerprint of INTERNAL_KEY at boot, plus a one-time `cat /data/.admin_key` instruction. Force password rotation on first login. |
| 2 | **Symmetric HMAC mesh signing** (C4) | High | Low (requires peer compromise) | Migrate to Ed25519 (or use TLS-mTLS between peers). Document explicitly that current model is "shared-secret per peer." |
| 3 | **Volume theft = full compromise** (E2) | High | Low (depends on host) | Document encryption-at-rest expectation; consider sealed secrets / k8s secret-store integration. |
| 4 | **Redis no-auth deployment risk** (C2/C3) | High | Operator-dependent | Hard-fail at boot if `REDIS_URL` lacks AUTH/TLS in production-like configs (env flag). |
| 5 | **Login rate-limit per-IP only** (B2) | Medium | Medium | Add per-username global lockout (e.g. 20 fails in 1h → 15-min freeze) on top of per-IP. |
| 6 | **Cookie not Secure by default** (B5) | Medium | Medium | Make `Secure` flag default ON; set to OFF only when `TLS_ENABLED=0` AND a known-private-network env flag is set. |
| 7 | **No read-only role / SoD** (B7) | Medium | Low | Add `viewer` role for monitoring/SIEM use; restrict mutation endpoints to `admin`. |
| 8 | **Audit log retention unbounded** (F2/D4) | Medium (GDPR) | Operator-dependent | Add `AUDIT_RETENTION_DAYS` knob with default 365; auto-prune in db_writer_loop. |
| 9 | **Determined-script bypass without Turnstile** (A1) | Medium | Medium | Recommend Turnstile + canary + body-pattern stack in production guide; flag `TURNSTILE_ENABLED=0` deploys with a banner. |
| 10 | **DLP bounded at 256 KiB** (A8) | Low-Medium | Low | Document the bound; allow streaming-mode for very large responses. |
| 11 | **Mesh offer apply has no integrity link to source** (C1) | Low | Low | Sign offers with the source gw's keypair; verify before showing in pending. |
| 12 | **No HSTS header** | Low | Low | Add `Strict-Transport-Security` when `TLS_ENABLED=1`. |
| 13 | **Mesh-sync allowlist hard-coded** | Low | Low | Document the list in README + add a runtime audit endpoint listing eligible keys (already present at `/secured/admin/mesh-sync`). |

## 5. Quick Wins (≤1 release)

1. **Force first-login password rotation** — flag `admin.password_must_change=1` on bootstrap; refuse access to admin endpoints until rotated. Closes F1/B1.
2. **Per-username login lockout** — second-tier rate limit. Closes B2 partially.
3. **`Secure` cookie default ON** — invert the env logic. Closes B5.
4. **Audit retention knob** + auto-prune. Closes F2.
5. **Boot fail on Redis without AUTH** when not loopback. Closes C3.
6. **HSTS** when TLS_ENABLED=1.

## 6. Larger Investments

7. **Ed25519 for mesh signing** — replace HMAC. Closes C4.
8. **Read-only `viewer` role** — separation of duties. Closes B7.
9. **Encrypted-at-rest `/data`** — sealed-secrets / KMS integration. Closes E2.
10. **Streaming DLP** for large responses. Closes A8.

## 7. Out of Scope (Operator's Responsibility)

- Host-level security of `/data` volume
- TLS termination (whether via cloudflared, nginx, or built-in `TLS_ENABLED`)
- Redis network exposure
- Postgres credentials rotation
- Upstream app's own vulnerabilities

---

## 8. Top 3 Recommended Fixes (this week)

1. Force first-login password change (F1/B1)
2. Per-username login lockout (B2)
3. Invert `Secure` cookie default (B5)

All three are <50 LOC each, no schema migration.

---

## Appendix A — Recent Validation Posture (1.6.7)

- Tests: 153 unit + 15 functional + 10 integration + 94 regression = **272/272 passing**
- Bandit: 0 H / 0 C · 13 Mediums (B104 / B608 / B310, all classified)
- Trivy: 0 CVEs
- Black-box pentest: 8 attempted attacks (forged cookie, legacy 3-part token, cookie tampering, replay-after-revoke, login brute-force, CSRF-on-login, retired bearer-key × 2, mesh-sync no-auth) — 8/8 blocked
- Performance: p99 25 ms · 1000-burst 1000/1000 OK · RSS 107 MiB
