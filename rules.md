# Rules of Engagement — AppSecGW build pipeline

These rules are non-optional. After every Docker build of
`appsec-antibot-gw:<version>`, run the full 17-step validation chain
below **before announcing the build as done**. Every finding must be
fixed (or explicitly classified as pre-existing in the report) before
the version is considered released.

Author: Pedro Tarrinho · Last updated for: 1.7.5

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
pytest tests/test_control_regressions.py tests/test_v14.py tests/test_v142.py tests/test_v173.py -q
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

## 9. Static hardening (Bandit + Semgrep + SonarQube)

```
bandit -ll proxy.py
```
**Pass criterion (Bandit):** 0 High / 0 Critical. Mediums must each be classified
as confirmed false-positive in the report (B310 fixed-https / B104
intentional gateway binding / B608 numeric-controlled SQL are accepted).

```
semgrep scan --config p/python proxy.py core/ dashboards/*.py
```
Run in OSS mode — no token or login required. Do NOT use `--config=auto` (requires SEMGREP_APP_TOKEN), `semgrep mcp`, or set `SEMGREP_APP_TOKEN`. Use `--config p/python` which runs the curated Python ruleset without authentication.

**Pass criterion (Semgrep):** 0 ERROR / 0 WARNING findings not previously
classified. Any new finding must be triaged: confirmed false-positive → document
in report; real finding → fix before release. Use `# nosemgrep: <rule-id>` only
after explicit classification (never blanket-suppress).

Run a **SonarQube** analysis against the project (via `sonar-scanner` or the
SonarQube CI integration). Review the Quality Gate result in the SonarQube UI.

**Pass criterion (SonarQube):** Quality Gate = PASSED. No new BLOCKER or
CRITICAL issues introduced by this version. Major issues must be triaged;
accepted-risk items require a note in the validation record. Code smells and
info-level findings do not block release but should be noted.

## 10. Image CVE scan (Trivy + Aikido)

Run Trivy against **all three** built images:

```
# arm64
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity CRITICAL,HIGH,MEDIUM \
  --quiet appsec-antibot-gw:<version>-arm64

# armv7
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity CRITICAL,HIGH,MEDIUM \
  --quiet appsec-antibot-gw:<version>-armv7

# amd64
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity CRITICAL,HIGH,MEDIUM \
  --quiet appsec-antibot-gw:<version>-amd64
```
**Pass criterion (Trivy):** 0 CRITICAL / 0 HIGH / 0 MEDIUM CVEs on **each** arch. All three must pass.

Push the built image to Harbor and trigger an **Aikido Security** scan from the
Aikido dashboard (or via the Aikido CLI / CI integration). Aikido scans the
image for CVEs, secrets, misconfigurations, and SAST findings across the full
dependency tree.

**Pass criterion (Aikido):** 0 CRITICAL / 0 HIGH open findings. Mediums must be
triaged; accepted-risk items require a note in the validation record. Aikido
findings that duplicate Trivy CVEs already classified are inherited — do not
re-classify.

## 11. Automated code review (CodeRabbit)

Run CodeRabbit on all changes in this version using the `/coderabbit:coderabbit-review`
skill (or via the CodeRabbit GitHub integration on the release PR).

**Pass criterion:** All actionable findings resolved or explicitly classified as
false-positive in the report. Nitpicks may be deferred with a note. No finding
rated **high** or **critical** by CodeRabbit may be left open.

## 11a. Secure code review
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

**Step 0 — automated version bump (run this first):**
```bash
./bump-version.sh <prev-version> <new-version>
# e.g. ./bump-version.sh 1.7.10 1.7.11
```
`bump-version.sh` atomically updates every canonical version location:
`config.py` · `test_pure.py` (`_EXPECTED_VERSION` + stale-string regex) · `proxy.py` docstring ·
`docker-compose.yml` (image tag + container_name) · all `dashboards/*.html` ·
`README.md` quickstart refs · `tests/test_geo_dashboard.py`.
Run it **before** any manual checks below — then verify the output shows no `WARN: pattern not found` lines.

Before declaring documentation complete, verify:
- `config.py` `GW_VERSION` constant matches the release tag (e.g. `AppSecGW_1.7.0`).
- Run `pytest tests/test_pure.py::test_gw_version_constant tests/test_pure.py::test_no_stale_version_strings_in_source` — both must PASS.  The second test scans all `.py/.yml/.yaml/.sh/.md` source files for `AppSecGW_X.Y` strings that do not match the current release (excluding comments, CHANGELOG, README, rules.md, and the validation/ directory).
- `README.md` image tag in Quick Start, multi-site fleet examples, and
  `Build from source` block all reference the new version.
- `Dockerfile` and `docker-compose.yml` default image tags updated if needed.
- `Dockerfile.armv7` COPY block kept in sync with main `Dockerfile` whenever new modules are added.
- `copy-to-github.sh` MANIFEST includes every new file added in this version.
- Architecture diagram in `README.md` reflects the actual middleware chain;
  add any new detection layer or admin endpoint introduced since last release.
- `CHANGELOG.md` `[Unreleased]` section is empty (or absent) after the
  release entry is stamped — nothing left undocumented.

### 13b. Full version-string sweep
Run `./bump-version.sh PREV NEW` first (see §13a), then verify with the grep below.
Every file that embeds the version number must agree with the release tag — stale strings are a
support and audit liability.

```bash
VER=<version>   # e.g. 1.7.2
PREV=$(echo $VER | awk -F. '{printf "%d.%d.%d", $1, $2, $3-1}')  # e.g. 1.7.1

# Find any occurrence of the previous version (or any X.Y.Z that isn't $VER)
# across all tracked source files — exits non-zero if stale strings found.
grep -rn --include="*.py" --include="*.html" --include="*.yml" \
     --include="*.yaml" --include="*.sh" --include="*.md" \
     --include="Dockerfile*" \
     "$PREV" . \
  | grep -v "CHANGELOG\|README\|rules.md\|validation/" \
  | grep -v "^Binary"
```

**Checklist — every location the version string must be current:**

| File | What to check |
|------|--------------|
| `core/config.py` | `GW_VERSION = "AppSecGW_<version>"` |
| `Dockerfile` | `LABEL version=` and any `ARG VERSION=` line |
| `Dockerfile.armv7` | same as above |
| `docker-compose.yml` | `image: appsec-antibot-gw:<version>` and `container_name:` |
| `dashboards/main.html` | `<title>` and `<h1>` version string |
| `dashboards/agents.html` | `<h1>` version string |
| `dashboards/controls.html` | `<h1>` version string |
| `dashboards/geo.html` | `<h1>` version string |
| `dashboards/logs.html` | `<h1>` version string |
| `dashboards/service.html` | `<h1>` version string |
| `dashboards/settings.html` | `<h1>` version string |
| `README.md` | Quick Start `docker pull` tag, Version history table header row, Build from source example |
| `CHANGELOG.md` | Latest `## [<version>]` section header stamped (not `[Unreleased]`) |
| `MANUAL.md` | Any pinned image tags in example commands |
| `copy-to-github.sh` | `VERSION=` line or equivalent constant |

**Pass criterion:** Zero stale-version hits from the grep AND every row in
the checklist manually confirmed. Any mismatch must be corrected before step 14.

---

## 14. Multi-arch build + Harbor push
Run only after steps 1–13 all pass (or pre-existing failures are classified).

### 14a. Disk space pre-check
```
df -h /var/lib/docker
```
**Pass criterion:** At least **10 GB free** before starting builds. If below threshold, run
the following cleanup sequence in order until the threshold is met:

```
# 1. APT package cache (~900 MB typical)
apt clean

# 2. pip download cache (~100–200 MB)
pip cache purge

# 3. Unused APT packages — removes orphaned runtimes (golang, OpenJDK, etc.)
apt autoremove --purge -y

# 4. Docker buildx/BuildKit cache — largest single gain (~4 GB typical)
docker builder prune -f

# 5. Dangling images (stop here if threshold already met)
docker image prune -f
```

Re-check with `df -h /var/lib/docker` after each step. Stop once ≥ 10 GB is free.
Step 4 (`docker builder prune -f`) invalidates the layer cache — next build will be
slower but functionally identical.

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

### 14e. Orphaned image cleanup
After all three pushes succeed, remove dangling (untagged) images left by the build:
```bash
docker image prune -f
```
**Pass criterion:** Command exits 0. `docker images` shows no `<none>` entries for `appsec-antibot-gw`.

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

## 16. Post-Release Bug Watch

**Purpose**: capture every bug found after Step 15 (DAST) — whether from user reports,
production monitoring, or a subsequent code-review pass — with a regression test and a
documented fix before the next release is stamped.

### Protocol (mandatory for every bug that reaches this step)

1. **Reproduce** — confirm the bug with a minimal reproducer (curl, pytest, or log excerpt).
2. **Write the failing test first** — add a regression test to the appropriate suite
   (`test_pure.py` for static source checks, `test_critical.py` for pure unit logic,
   `test_async.py` for aiohttp integration). The test must **fail** before the fix.
3. **Fix** — apply the minimum-scope change. Do not bundle unrelated cleanup.
4. **Confirm green** — the new test must pass; no existing test may regress.
5. **Document below** — fill in the bug table entry with: severity, symptom, root cause,
   fix location, test name. Update `CHANGELOG.md` Fixed section and `validation/<ver>.md`.

### 16a. Bug registry (cumulative — append, never delete)

| # | Version | Severity | Symptom | Root Cause | Fix Location | Regression Test |
|---|---------|----------|---------|-----------|-------------|-----------------|
| 1 | 1.7.3 | HIGH | `NameError: name 's' is not defined` → HTTP 500 after ban expiry | `protect()` ai-no-assets deny branch referenced `s.html_loads` / `s.static_loads`; `s` is never assigned in that path — only `_s_early` is | `core/proxy_handler.py` (ai-no-assets block) | `test_ai_no_assets_deny_uses_s_early_not_s` |
| 2 | 1.7.3 | CRITICAL | P1/P2/P4 probe endpoints return upstream 404 decoy; detectors have zero effect in production | `/probe`, `/maze`, `/canary-probe/` absent from `_ADMIN_PUBLIC_SUBPATHS`; `protect()` intercepts every admin-namespace path not in that list before route dispatch | `config.py` (`_ADMIN_PUBLIC_SUBPATHS`) | `test_probe_endpoint_in_admin_public_subpaths`, `test_maze_endpoint_in_admin_public_subpaths`, `test_canary_probe_in_admin_public_subpaths` |
| 3 | 1.7.3 | HIGH | Turnstile shown to every first-time visitor regardless of risk score | `_js_challenge_applicable()` reads `request.get("_track_key")` which is always `None` at the JS challenge gate (set at `proxy_handler.py:2511`, gate runs at line 2282); threshold check never executes | `challenge/js_challenge.py` (`_js_challenge_applicable`) | `test_js_challenge_applicable_source_uses_get_identity_not_track_key` |
| 4 | 1.7.3 | MEDIUM | Soft-challenge tier never enforced on `JS_CHAL_OPEN_PATHS` — risky identities (SOFT_CHALLENGE_SCORE ≤ risk < BAN) bypass the cookie gate on open paths | Same `_track_key` ordering bug in `_js_challenge_required()` — `track_key` is always `None`; `if track_key:` branch skipped; open-path bypass always granted | `challenge/js_challenge.py` (`_js_challenge_required`) | `test_js_challenge_required_soft_challenge_uses_get_identity_not_track_key` |
| 5 | 1.7.4 | HIGH | All dashboard modals throw `ReferenceError: escHtml is not defined` | Local alias `escHtml` used in pill modal / account modal / popover render functions; global `escapeHtml` is the canonical name — `escHtml` was only defined as a local closure copy in some files and removed in §17 hardening, breaking callers outside the closure | All 5 affected dashboard HTML files | `test_no_local_eschtml_alias`, `test_no_eschtml_calls`, `test_single_escapehtmlt_definition`, `test_escapehtmlt_full_charset` (per file) |
| 6 | 1.7.4 | HIGH | `LOG_LEVEL` hot-reload has no effect — slog() keeps filtering at original startup level | `config_endpoint` propagated `LOG_LEVEL` string to all modules via generic `setattr` loop, but `_LOG_LEVEL_N` (the numeric sentinel used by `slog()` for level filtering) is not in `_HOT_RELOAD_KNOBS` and was not updated | `core/proxy_handler.py` (`config_endpoint`) | `test_log_level_n_propagated_on_hot_reload` |
| 7 | 1.7.4 | MEDIUM | `ip_intel_endpoint` raises `NameError` for all five reputation lookups at runtime | `admin/users.py` called `_city_lookup`, `_asn_lookup`, `_abuseipdb_lookup`, `_crowdsec_check`, `_tor_exits` without importing them — names exist in `proxy_handler.py` global scope but not in `admin/users.py` separate module namespace | `admin/users.py` (module-level imports) | `test_ip_intel_endpoint_imports_reputation_symbols` |
| 8 | 1.7.4 | MEDIUM | `logs.html` LOG_LEVEL POST handlers crash with JSON parse error on session expiry / 401 | `r.json()` called unconditionally before checking `r.ok` — a non-JSON 401/404 decoy response causes `SyntaxError: unexpected non-whitespace character` in the browser | `dashboards/logs.html` (both LOG_LEVEL handlers) | `test_logs_html_log_level_button_has_rok_guard`, `test_logs_html_log_level_handlers_no_unconditional_json` |
| 9 | 1.7.5 | HIGH | `Auth Bot` button reverts to Allow on every auto-tick | `agents_data_endpoint` in `dashboards/agents.py` did not include `is_authorized_bot` field — agents.html fetches from `/agents-data` (not `/metrics`), so `s.is_authorized_bot` was always `undefined`; `_authBotPatch` expiry race exacerbated the symptom | `dashboards/agents.py` (`agents_data_endpoint` `suspects.append()`) | `test_agents_data_endpoint_includes_is_authorized_bot_field` |
| 10 | 1.7.5 | HIGH | Moving from Auth Bot to Allow/Banned/Really Banned does not stick — next tick reverts | Auth-bot UA dedup `find()` used exact-match only (`b.ua === ua`), not substring; existing short-form entry (e.g. `UptimeRobot`) never found → `enabled:false` never applied → next tick still sees `is_authorized_bot=true` | `dashboards/agents.html`, `dashboards/main.html` (ban handler) | `test_agents_html_leaving_auth_bot_state_disables_bot_entry`, `test_agents_html_leaving_auth_bot_uses_substring_match_in_map`, `test_main_html_leaving_auth_bot_state_disables_bot_entry`, `test_main_html_leaving_auth_bot_uses_substring_match_in_map` |
| 11 | 1.7.5 | MEDIUM | `config_changed` log shows only key names for rejected changes, not the reason | `slog("config_changed")` passed `rejected=list(rejected.keys())` — operator log showed `rejected=['FOO_KNOB']` with no indication why; fully-rejected POSTs (applied empty) logged nothing (`if applied:` guard) | `core/proxy_handler.py` (`config_endpoint`) | `test_config_changed_slog_passes_rejected_dict_not_keylist`, `test_config_changed_slog_fires_on_pure_rejection` |

### 16b. Root-cause pattern: request lifecycle ordering

Bugs 3 and 4 share the same root cause: `request["_track_key"]` (and `_sid`, `_fp`, `_is_new`)
are set at `proxy_handler.py:2511`, inside `protect()`, **after** the JS challenge gate at
line 2282. Any code that runs at or before the gate and reads `request.get("_track_key")` will
always receive `None`.

**Canonical fix pattern** — replace `request.get("_track_key")` at the gate with a direct
identity derivation:

```python
# WRONG — _track_key not set yet at the JS challenge gate
track_key = request.get("_track_key")
if track_key:
    s = ip_state.get(track_key)
    ...

# CORRECT — derive identity directly
try:
    from identity import get_identity
    _id, *_ = get_identity(request)
    s = ip_state.get(_id)
except Exception:
    s = None
```

**Checklist when adding code that runs before `proxy_handler.py:2511`:**

- [ ] Does it read `request.get("_track_key")`? → replace with `get_identity(request)`
- [ ] Does it read `request.get("_sid")` or `request.get("_fp")`? → derive via `get_identity()`
- [ ] Does it mutate `ip_state` using the track_key? → re-derive first
- [ ] Does the new code have a unit test that exercises the `_track_key = None` path?

### 16c. Pass criteria

- All regression tests listed in §16a must be green.
- Full suite (`test_critical.py tests/test_pure.py tests/test_async.py`) must show 0 new failures.
- Every bug with severity ≥ MEDIUM must have an entry in `CHANGELOG.md` Fixed section.
- `validation/<version>.md` must document each finding: symptom, root cause, fix, test name.

---

## 17. Dashboard Security Standards

Every admin dashboard HTML file in `dashboards/` must comply with the standards below.
Run the checks as part of any release that touches those files.

### 17a. `escapeHtml` — canonical definition (mandatory in every file)

Each dashboard must define **exactly one** `escapeHtml` at the top of its first `<script>` block.
All other local aliases (`escHtml`, `escHtml2`, nested closures) are forbidden.

**Canonical form:**
```javascript
function escapeHtml(s){return String(s==null?'':s).replace(/[&<>"'`/]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;','/':'&#47;'}[c]))}
```

Requirements:
- Character set must include `&`, `<`, `>`, `"`, `'`, `` ` ``, `/` — no exceptions.
- Null/undefined guard: `String(s==null?'':s)` (not `(s||'')`).
- Function name: `escapeHtml` (not `escHtml`, `escHtml2`, `esc`, etc.).
- Must be at the file's global scope — **not** inside an IIFE or closure.

### 17b. `setInterval` leak prevention

Every `setInterval(...)` call must push its return value into a file-level `_timers` array.
A `beforeunload` listener must clear all timers on page exit.

**Canonical pattern (add once per file, right after `escapeHtml`):**
```javascript
const _timers=[];
// wrap every setInterval:
_timers.push(setInterval(fn, ms));
// add at end of LAST script block in the file:
window.addEventListener('beforeunload',()=>_timers.forEach(clearInterval));
```

No `setInterval` call may appear without `_timers.push(...)`.

### 17c. Redirect validation (login.html)

The `next` query-parameter must be validated against `location.origin` before use as a redirect target.

**Canonical validator:**
```javascript
function safeNext(raw) {
  if (!raw) return null;
  try { const u = new URL(raw, location.origin); return u.origin === location.origin ? u.pathname + u.search + u.hash : null; }
  catch { return null; }
}
```

`location.href` must never be set to an unvalidated user-supplied string.

### 17d. No unescaped data in `innerHTML`

Every `innerHTML` assignment that incorporates server-supplied or user-supplied data must wrap each field with `escapeHtml()`. Template literals are no exception:
```javascript
// WRONG
div.innerHTML = `<div>${data.message}</div>`;
// CORRECT
div.innerHTML = `<div>${escapeHtml(data.message)}</div>`;
```

`e.message` and any error string must be escaped before placement into `innerHTML`:
```javascript
// WRONG
el.innerHTML = '<span>load failed: ' + e.message + '</span>';
// CORRECT
el.innerHTML = '<span>load failed: ' + escapeHtml(String(e.message||e)) + '</span>';
```

### 17e. Structured error handling for `fetch`

Silent `.catch(()=>({}))` is forbidden on any fetch that populates UI state.
Use structured error objects instead:
```javascript
// WRONG
const j = await r.json().catch(() => ({}));
// CORRECT
let j; try { j = await r.json(); } catch { j = { _error: true }; }
if (j._error) { /* show error */ return; }
```

### 17f. Pass criteria

For each dashboard file in `dashboards/`:
- [ ] Exactly one `escapeHtml` definition at top-scope with full 7-char charset.
- [ ] Zero `escHtml`, `escHtml2`, or local `escapeHtml` aliases inside closures.
- [ ] Every `setInterval` wrapped with `_timers.push(...)`.
- [ ] `window.addEventListener('beforeunload', ...)` present in the file.
- [ ] `next` param validated in `login.html`.
- [ ] No `innerHTML` assignment with bare `e.message` or other unescaped strings.
- [ ] No silent `.catch(()=>({}))` on UI-state-populating fetches.

Regression tests in `test_pure.py` must verify §17a, §17c, §17d per file.

### 17g. Dashboard security bug registry

| # | File | Severity | Symptom | Fix | Regression Test |
|---|------|----------|---------|-----|----------------|
| D1 | `login.html` | HIGH | Open redirect via `?next=` parameter — server error → user-supplied URL used verbatim | `safeNext()` validator + origin check | `test_login_open_redirect_next_param_validated` |
| D2 | `service.html` | MEDIUM | XSS via `e.message` in `innerHTML` — server-controlled error message rendered as HTML | `escapeHtml(String(e.message\|\|e))` | `test_service_emessage_escaped_in_innerhtml` |
| D3 | `service.html` | MEDIUM | Missing global `escapeHtml` — calls outside local closures throw `ReferenceError` | Added canonical `escapeHtml` at top of first script block | `test_service_has_global_escapehtmlt` |
| D4 | All files | MEDIUM | Incomplete escape charset — `[&<>"']` missing backtick + `/` | Updated all definitions to `[&<>"'\`/]` | `test_*_escapehtmlt_full_charset` (per file) |
| D5 | All files | LOW | `setInterval` leaks — 30+ intervals never cleared on navigation | `_timers` array + `beforeunload` cleanup | `test_*_setinterval_tracked` (per file) |
| D6 | `login.html`, `settings.html` | LOW | Silent `.catch(()=>({}))` hides network/parse errors | Structured `try/catch` with `_error` flag | `test_login_no_silent_catch`, `test_settings_no_silent_catch` |

---

### 17h. AWS ELB / ALB health check pass-through

AWS Elastic Load Balancer health checkers use `User-Agent: ELB-HealthChecker/2.0`
and send only `Host`, `Connection: close`, and `Accept-Encoding` — no `Accept`,
`Accept-Language`, `Sec-Fetch-*`. Without the bypass:

| Signal | Score per hit |
|--------|---------------|
| `ua-non-browser` | 25 |
| `ai-headers-incomplete` | 20 |

Two requests → 90 pts → ban. The ELB marks the target **unhealthy** and drains traffic.

**Configuration (set in `.env` + AWS target group):**
```
ELB_HEALTH_CHECK_PATH=/your-secret-health-path   # must match AWS target group setting
ELB_HEALTH_CHECK_UA=ELB-HealthChecker            # matches ELB-HealthChecker/2.0 and future versions
```

**Security model:**
- Path **and** UA must both match — neither alone triggers the bypass.
- Use a non-obvious path value (the operator controls both the gateway env and the AWS console setting).
- ELB nodes always originate from within the VPC private address space (consistent with `TRUSTED_PROXIES`).
- The plaintext path is never logged — only a SHA-256 prefix is recorded in the structured log.

**Pass criteria:**
```
pytest tests/test_pure.py -k "elb"
```
Must produce `7 passed`. Verify the bypass is active in the live container:
```bash
curl -sk http://localhost:8443/$ELB_HEALTH_CHECK_PATH \
  -H "User-Agent: ELB-HealthChecker/2.0" \
  -H "Connection: close" \
  -H "Accept-Encoding: gzip, compressed"
# Expected: 200 OK, body "ok"
```

### 17i. Chart fill QA (dashboard visual integrity)

Every release that touches `dashboards/main.html`, `dashboards/service.html`, or
`dashboards/agents.html` must pass the chart fill static-analysis suite:

```
pytest tests/test_dashboard_charts.py -v
```

**What it checks (15 tests across 3 files):**

| Check | Rule |
|-------|------|
| `fill: 'origin'` count | ≥ 9 in main.html, ≥ 6 in service.html, ≥ 5 in agents.html |
| No gradient fills | `createLinearGradient` must not appear in any of the three files |
| No scriptable backgroundColor | `backgroundColor: function(` / arrow-function form is forbidden |
| rgba alpha ≥ 0.30 | All `backgroundColor: 'rgba(...)'` values must be visibly solid |
| rgba count ≥ fill:'origin' count | Every fill:'origin' dataset must have a matching backgroundColor |

**Pass criterion:** 15/15 green. Any failure blocks the release — it means either a
fill was accidentally removed, opacity was set too low (faint/invisible), or a gradient
was re-introduced.

**Context:** Threshold/dashed lines (`fill: false`, no backgroundColor) and stacked
db-chart datasets (`fill: true`, alpha 0.55) are not tested here — only data-series
fills to origin.

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

---

## Demo Environments

| # | Service | Tool | Notes |
|---|---------|------|-------|
| 1 | Demo Service 1 | ngrok | Subject to free-tier request limits |
| 2 | Demo Service 2 | Cloudflare Tunnel (trycloudflare) | No rate limits; quick tunnel, no account needed |

**trycloudflare quick start (arm64):**
```bash
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -O cloudflared
chmod +x cloudflared
./cloudflared tunnel --url http://localhost:8080
```
Produces a `*.trycloudflare.com` URL valid for the tunnel session.

---

## Live Demo Checklist

When asked for a **live demo** (any phrasing: "show me", "demo link", "give me access", "spin up the demo"):

### Step 1 — Verify latest version is running

```bash
docker ps --format "{{.Names}}\t{{.Status}}" | grep antibot
```

The container name must match the current release version (e.g. `appsec-antibot-gw1.8.4`).
Status must be `Up … (healthy)`. If not running or unhealthy — **start it before continuing**.

### Step 2 — Detect or start a tunnel

Check which tunnel tool is already running (prefer in this order):

```bash
pgrep -a cloudflared   # Option A: trycloudflare
pgrep -a ngrok         # Option B: ngrok
pgrep -a ssh           # Option C: localhost.run / serveo.net
pgrep -a bore          # Option D: bore
```

Extract the live public URL from whichever is active:

| Tool | How to get the URL |
|------|--------------------|
| **trycloudflare** | `grep -o 'https://[^"]*trycloudflare[^"]*' /tmp/cf-tunnel1.log \| tail -1` |
| **ngrok** | `curl -s http://localhost:4040/api/tunnels \| python3 -c "import sys,json; d=json.load(sys.stdin); print(d['tunnels'][0]['public_url'])"` |
| **localhost.run** | Extract from the ssh process output / log: look for `*.lhr.life` URL |
| **serveo.net** | Extract from the ssh process output / log: look for `*.serveo.net` URL |
| **bore** | Extract from bore process output / log: look for the public address |

If **no tunnel is running**, start one using whichever tool is available on the system:

**Option A — trycloudflare (no account needed)**
```bash
cloudflared tunnel --url http://localhost:8443 --logfile /tmp/cf-tunnel1.log &
sleep 8
grep -o 'https://[^"]*trycloudflare[^"]*' /tmp/cf-tunnel1.log | tail -1
```

**Option B — ngrok**
```bash
ngrok http 8443 --log /tmp/ngrok.log &
sleep 5
curl -s http://localhost:4040/api/tunnels | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['tunnels'][0]['public_url'])"
```

**Option C — localhost.run (no account)**
```bash
ssh -o StrictHostKeyChecking=no -R 80:localhost:8443 nokey@localhost.run 2>&1 | tee /tmp/lhr.log &
sleep 8
grep -o 'https://[^ ]*\.lhr\.life' /tmp/lhr.log | tail -1
```

**Option D — serveo.net (no account)**
```bash
ssh -o StrictHostKeyChecking=no -R 80:localhost:8443 serveo.net 2>&1 | tee /tmp/serveo.log &
sleep 8
grep -o 'https://[^ ]*\.serveo\.net' /tmp/serveo.log | tail -1
```

**Option E — bore**
```bash
bore local 8443 --to bore.pub 2>&1 | tee /tmp/bore.log &
sleep 5
grep -o 'bore.pub:[0-9]*' /tmp/bore.log | tail -1
# bore gives a TCP address — wrap it: https://bore.pub:<port>
```

### Step 3 — Verify 2 vhosts are configured and reachable

```bash
cat "/media/share/shared with kali-claude-code/anti-bot-proxy/data/vhosts.json"
```

There must be **exactly 2 vhost entries**. Each vhost hostname is a tunnel domain
(from one of the tools above) pointing to a demo service upstream.
The vhost hostnames are dynamic — they change whenever a new tunnel session starts.

For each existing vhost, verify the upstream is still reachable **directly** (not through the gateway,
to avoid triggering bot detection on curl):

```bash
curl -sk -o /dev/null -w "%{http_code}\n" <upstream-url>
```

Expected: `200` or `301/302` = upstream alive. Any `5xx` or connection refused = upstream is down.

**Do NOT remove or replace a vhost that is currently working** (upstream responds).
Only remove a vhost if its upstream is unreachable OR its hostname belongs to a tunnel
that is no longer running. Stale hostnames (tunnel gone, hostname no longer resolves
to this gateway) are safe to replace — working ones must be left intact.

If fewer than 2 vhosts exist, or a stale one was removed — **register the missing ones** via the API:

```bash
ADMIN_KEY=$(cat "/media/share/shared with kali-claude-code/anti-bot-proxy/data/.admin_key")
curl -s -X POST http://localhost:8443/antibot-appsec-gateway/secured/vhosts \
  -H "X-Admin-Key: $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"<vhost-hostname>","UPSTREAM":"<upstream-url>"}'
```

### Step 4 — Read the admin key

```bash
cat "/media/share/shared with kali-claude-code/anti-bot-proxy/data/.admin_key"
```

### Step 5 — Share everything in a single message

Provide all of the following:

```
Gateway admin login:
  URL:  https://<main-tunnel-hostname>/antibot-appsec-gateway/login
  Key:  <admin_key>

Demo service 1 (via gateway):
  URL:  https://<vhost-1-hostname>/

Demo service 2 (via gateway):
  URL:  https://<vhost-2-hostname>/
```

**Do not ask the user to do any of the above steps themselves.**
Run all checks silently and only share the final URLs + key.
