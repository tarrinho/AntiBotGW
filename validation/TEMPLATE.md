# AppSecGW build validation — v<VERSION>

| Field       | Value                          |
|-------------|--------------------------------|
| Version     | `appsec-antibot-gw:<VERSION>`  |
| Date        | YYYY-MM-DD                     |
| Builder     | Pedro Tarrinho                 |
| Platform    | amd64 · arm64 · armv7          |
| Pre-existing failures | _(none / list here)_ |

---

## Step 1 — Unit tests

```
pytest tests/test_critical.py tests/test_pure.py tests/test_async.py -q
```

| | |
|---|---|
| Result | PASS / FAIL |
| Passed | X |
| Failed | 0 |
| Notes  | |

---

## Step 2 — Functional tests

```
pytest tests/test_functional.py -q
```

| | |
|---|---|
| Result | PASS / FAIL |
| Passed | X |
| Failed | 0 (pre-existing: list any) |
| Notes  | |

---

## Step 3 — Integration tests

```
pytest tests/test_integration.py -q
```

| | |
|---|---|
| Result | PASS / FAIL |
| Passed | X |
| Failed | 0 |
| Flaky (pass in isolation) | none / list |
| Notes  | |

---

## Step 4 — Sufficient logs

| Check | Result |
|---|---|
| Every detector emits `event=request` with `rid` + `reason` | PASS / FAIL |
| Admin endpoints emit `event=config_changed` / `event=ban` | PASS / FAIL |
| Webhook fires on every ban + DLP hit | PASS / FAIL |
| Manual probe: all detectors appear in `docker logs` output | PASS / FAIL |

Notes:

---

## Step 5 — Regression tests

```
pytest tests/test_control_regressions.py tests/test_v14.py tests/test_v142.py -q
```

| | |
|---|---|
| Result | PASS / FAIL |
| Passed | X |
| New failures vs last release | 0 / list |
| Pre-existing inherited failures | none / list |
| Notes  | |

---

## Step 6 — Performance smoke

| Check | Target | Actual | Result |
|---|---|---|---|
| Cold-start time | < 5 s | Xs | PASS / FAIL |
| `/__metrics` p99 latency | < 50 ms | Xms | PASS / FAIL |
| 1000-req burst false-positive bans | 0 | 0 | PASS / FAIL |
| Memory after 1 h soak | < 200 MB RSS | X MB | PASS / FAIL |

Notes:

---

## Step 7 — Secret-leak scan

| Check | Result |
|---|---|
| `grep` for private keys / AKIA / sk- / ghp_ in source | PASS / FAIL |
| Live responses free of `.admin_key` / `SESSION_KEY` / `POW_HMAC_KEY` | PASS / FAIL |
| DLP self-test: `dlp-aws` fires + redaction works | PASS / FAIL |

Notes:

---

## Step 8 — Injection sanitisation

| Payload | Surface | Expected signal | Actual signal | Result |
|---|---|---|---|---|
| `<script>alert(1)</script>` | URL / body / header / cookie | unescaped blocked | | PASS / FAIL |
| `' OR 1=1 --` | POST body | `body-sqli` | | PASS / FAIL |
| `' OR 1=1 --` | URL | `suspicious-path` | | PASS / FAIL |
| `../../etc/passwd` | URL | `body-lfi` / `suspicious-path` | | PASS / FAIL |
| `; whoami` | body | `body-cmd` | | PASS / FAIL |
| `http://169.254.169.254/` | body | `body-ssrf` | | PASS / FAIL |
| `${jndi:ldap://x/a}` | body | `body-rce` | | PASS / FAIL |
| Admin endpoint from unauth IP | — | 404 silent-decoy | | PASS / FAIL |

Notes:

---

## Step 9 — Static hardening (Bandit + Semgrep)

```
bandit -ll proxy.py
```

| | |
|---|---|
| Result | PASS / FAIL |
| High | 0 |
| Critical | 0 |
| Mediums | X (all classified below) |

Medium classifications:

| ID | Finding | Classification |
|---|---|---|
| B310 | fixed-https | confirmed FP |
| B104 | intentional gateway binding | confirmed FP |
| B608 | numeric-controlled SQL | confirmed FP |
| _(others)_ | | |

```
semgrep scan --config=auto proxy.py dashboards/
```

| | |
|---|---|
| Result | PASS / FAIL |
| Errors | 0 |
| Warnings | 0 new (vs last release) |
| New findings classified | none / list |

Semgrep finding classifications:

| Rule ID | File | Finding | Classification |
|---|---|---|---|
| _(none)_ | | | |

### SonarQube

| | |
|---|---|
| Result | PASS / FAIL |
| Quality Gate | PASSED / FAILED |
| New Blockers / Criticals | 0 |
| New Majors triaged | none / list |

SonarQube finding classifications:

| Issue | Severity | Resolution |
|---|---|---|
| _(none)_ | | |

---

## Step 10 — Image CVE scan (Trivy + Aikido)

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity CRITICAL,HIGH,MEDIUM \
  --quiet appsec-antibot-gw:<VERSION>
```

### Trivy

| Arch | Critical | High | Medium | Result |
|---|---|---|---|---|
| amd64 | 0 | 0 | 0 | PASS / FAIL |
| arm64 | 0 | 0 | 0 | PASS / FAIL |
| armv7 | 0 | 0 | 0 | PASS / FAIL |

Notes / findings:

### Aikido

| | |
|---|---|
| Result | PASS / FAIL |
| Critical | 0 |
| High | 0 |
| Mediums triaged | none / list |

Aikido finding classifications:

| Finding | Severity | Resolution |
|---|---|---|
| _(none)_ | | |

---

## Step 11 — Automated code review (CodeRabbit)

| | |
|---|---|
| Result | PASS / FAIL |
| High / Critical findings | 0 |
| Actionable findings resolved | X / X |
| Deferred nitpicks | none / list |

Finding classifications:

| Finding | Severity | Resolution |
|---|---|---|
| _(none)_ | | |

---

## Step 11a — Secure code review

| Check | Result |
|---|---|
| No hardcoded credentials / keys / tokens | PASS / FAIL |
| No unbounded loops / buffers | PASS / FAIL |
| Input validation at all trust boundaries | PASS / FAIL |
| Constant-time compares on auth paths | PASS / FAIL |
| No races on shared mutable state | PASS / FAIL |
| No secrets in logs | PASS / FAIL |
| New external deps justified | PASS / FAIL / N/A |
| New deps in Dockerfile AND requirements.txt | PASS / FAIL / N/A |

Files reviewed:

Notes:

---

## Step 12 — Black-box pentest

Harness: `127.0.0.1:18443` with upstream stub.

| Probe | Expected reason | Actual reason | Result |
|---|---|---|---|
| XSS in body | blocked / decoy | | PASS / FAIL |
| SQLi in URL | `suspicious-path` | | PASS / FAIL |
| LFI in URL | `body-lfi` | | PASS / FAIL |
| Command injection in body | `body-cmd` | | PASS / FAIL |
| SSRF in body | `body-ssrf` | | PASS / FAIL |
| Log4Shell in body | `body-rce` | | PASS / FAIL |
| _(new detector 1)_ | | | PASS / FAIL |
| _(new detector 2)_ | | | PASS / FAIL |

Harness torn down: YES / NO

Notes:

---

## Step 13 — Documentation

| Artifact | Updated | Notes |
|---|---|---|
| `CHANGELOG.md` — new version block (Added/Changed/Fixed/Removed/Tests/Validation) | YES / NO | |
| `README.md` — version history row + arch diagram + config tables | YES / NO | |
| `MANUAL.md` — new knobs / endpoints / operational procedures | YES / NO | |
| `report.pdf` — generated via Chromium headless from `report.html` | YES / NO | |

### Step 13a — Consistency review

| Check | Result |
|---|---|
| Version string in `proxy.py` matches release tag | PASS / FAIL |
| `README.md` image tags all updated | PASS / FAIL |
| `Dockerfile` + `docker-compose.yml` tags updated | PASS / FAIL |
| `copy-to-github.sh` MANIFEST includes all new files | PASS / FAIL |
| Architecture diagram reflects actual middleware chain | PASS / FAIL |
| `CHANGELOG.md` `[Unreleased]` section empty after stamp | PASS / FAIL |

Notes:

---

## Step 14 — Multi-arch build + Harbor push

### 14a — Disk space pre-check

| | |
|---|---|
| Free space before build | X GB |
| Threshold | 10 GB |
| Result | PASS / FAIL |

### 14b — Build all three arches

| Arch | Exit code | Result |
|---|---|---|
| amd64 | 0 | PASS / FAIL |
| arm64 | 0 | PASS / FAIL |
| armv7 | 0 | PASS / FAIL |

### 14c — Tag and push to Harbor

| Arch | Digest | Result |
|---|---|---|
| amd64 | `sha256:` | PASS / FAIL |
| arm64 | `sha256:` | PASS / FAIL |
| armv7 | `sha256:` | PASS / FAIL |

### 14d — Manifest list

| | |
|---|---|
| Manifest digest | `sha256:` |
| Harbor multi-arch tag visible in UI | YES / NO |
| Result | PASS / FAIL |

---

## Step 15 — Dynamic Security Testing

### 15a — TLS / HTTP Fingerprint Behavioural Analysis

| Check | Result |
|---|---|
| Gateway log contains `ja3` / `tls_fp` field on TLS requests | PASS / FAIL / N/A |
| Known bot UA on HTTP/2 scores ≥ 1 on `http2-fp` signal | PASS / FAIL |
| 50-req burst within 2 s triggers `rate-burst` signal | PASS / FAIL |
| Fingerprint data absent from all user-visible responses | PASS / FAIL |

Notes:

### 15b — Active DAST Probe

| Probe | Expected outcome | Actual | Result |
|---|---|---|---|
| IDOR (`/api/users/1` with `X-User-Id: 2`) | blocked / flagged | | PASS / FAIL |
| Broken object-level auth | blocked / flagged | | PASS / FAIL |
| Mass assignment (`role:admin` in body) | blocked / flagged | | PASS / FAIL |
| Path traversal null-byte | blocked / flagged | | PASS / FAIL |
| XXE injection | blocked / flagged | | PASS / FAIL |
| Open redirect | `Location` NOT pointing to evil host | | PASS / FAIL |
| False-positive: 20 clean reqs after probe | all ≤ 3 score | | PASS / FAIL |

Notes:

### 15c — Adaptive Rate / Pattern Engine

| Test | Expected outcome | Actual | Result |
|---|---|---|---|
| 200 req / 5 s burst — IP banned within 10 s | ≥ 90 % of burst returns 429/403 | | PASS / FAIL |
| Low-and-slow (1 req/s, 120 s) — soft-challenge by req 60–80 | JS challenge issued | | PASS / FAIL |
| Distributed burst (5 IPs × 40 req) — global counter increments | ban propagates to Redis within 5 s | | PASS / FAIL |
| Auto-recovery after TTL expiry | clean req returns 200 | | PASS / FAIL |

Notes:

### 15d — Dashboard Test Console

| Check | Result |
|---|---|
| Test Console panel renders, no JS errors | PASS / FAIL |
| Bot profile (python-requests UA, `/admin`) scores ≥ 7 | PASS / FAIL |
| Clean profile (Chrome UA, `/index.html`) scores ≤ 3 | PASS / FAIL |
| Upstream receives 0 requests during dry-run | PASS / FAIL |
| Dry-run response contains `signals`, `total_score`, `verdict` | PASS / FAIL |

Notes:

### 15e — Honeypot / Canary Token Injection

| Check | Result |
|---|---|
| Canary token present in HTML (hidden, not user-visible) | PASS / FAIL |
| Token is HMAC-signed — tampering causes rejection | PASS / FAIL |
| Re-requesting canary URL within 60 s → ban with `reason=canary-hit` | PASS / FAIL |
| Tokens are unique per session (two fetches ≠ same token) | PASS / FAIL |
| Tokens absent from metrics / error pages / admin fields | PASS / FAIL |

Notes:

---

## Overall result

| | |
|---|---|
| **Verdict** | **PASS / FAIL** |
| Steps passed | X / 15 |
| Steps failed | 0 |
| Pre-existing failures | none / list |
| Blocker findings | none / list |

## Release announcement

```
**<VERSION> released — appsec-antibot-gw:<VERSION>**
- Tests:         X unit + Y functional + Z regression — N/N pass
- Bandit:        0 High / 0 Critical · M Mediums (all confirmed FP)
- Trivy:         0 Critical / 0 High / 0 Medium CVEs
- Pentest:       N probes, 0 bypasses
- Disk free:     X GB before build
- Harbor:        amd64 ✓ · arm64 ✓ · armv7 ✓ · manifest ✓
- Pre-existing failures: none
```
