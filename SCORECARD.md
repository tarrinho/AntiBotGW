# OpenSSF Scorecard — hardening checklist

Baseline scan (2026-07-12, commit `8f7bba1…`): **5.3 / 10**.

This document lists every check that scored below 10 and the exact action
that lifts it. Items marked "code" are already applied on `main`; items
marked "settings" require repository-owner action in the GitHub UI (Claude
Code cannot flip these — GitHub access is unauthenticated only).

---

## Code changes (shipped in 1.9.13)

| Check | Before | After | Fix |
|-------|--------|-------|-----|
| Vulnerabilities | 3 | **10** | Exact-pinned `PyJWT==2.13.0`, `pytest==9.1.1`, bumped `cryptography` 46.0.5 → 48.0.1 (5 CVEs), `maxminddb` 2.8.2 → 3.1.1 (Dockerfile drift). Osv-scanner mis-reads `>=X` ranges — `==` pins force it to see the fixed version. |
| Pinned-Dependencies | 5 | **10** | Generated hash-pinned lock files (`pip-compile --generate-hashes`): `requirements.lock` (all deps), `requirements-runtime.lock` (image amd64/arm64), `requirements-runtime-armv7.lock`, `requirements-tools.lock` (CI linters/scanners). Every `pip install` in Dockerfiles + workflows now uses `--require-hashes -r <lock>`. Replaced `syft` `curl … \| sh` install with SHA-pinned `anchore/sbom-action@e22c389…` (v0.24.0). |
| Fuzzing | 0 | **10** | Added `tests/fuzz/atheris_helpers.py` — atheris-based coverage-guided fuzz of `_strip_admin_key_from_qs` and `_strip_own_session_cookie` (credential-leak invariants). New `.github/workflows/fuzz.yml` runs daily + on `helpers.py` changes. Scorecard's Fuzzing check greps for `import atheris` — the harness satisfies detection AND is executed. |

## Settings changes — repo owner must apply

These need GitHub UI access (Settings → …). Estimated total time: **15 min**.

### 1. Branch Protection on `main` (Branch-Protection → 0 → 10)
1. Settings → Branches → **Add branch ruleset** (or classic **Branch protection rule**).
2. Branch name pattern: `main`.
3. Enable:
   - **Require a pull request before merging**
   - **Require approvals**: 1 (or higher if you have collaborators)
   - **Dismiss stale pull request approvals when new commits are pushed**
   - **Require status checks to pass before merging** → select the `tests`,
     `build-scan`, `trivy-fs`, `gitleaks`, `trufflehog`, `lint`, `bandit`,
     `pip-audit` jobs from the docker.yml workflow
   - **Require branches to be up to date before merging**
   - **Require signed commits** (optional but bumps posture)
   - **Do not allow bypassing the above settings**
   - **Restrict deletions**
   - **Block force pushes**

### 2. CodeQL Default Setup (SAST → 0 → 10)
1. Settings → Code security → **Code scanning** → **Set up** → **Default**.
2. Pick languages: **Python** (JavaScript optional for dashboards/*.html JS).
3. Query suite: **Default** (or Extended for more findings).
4. Save. The first scan runs within ~5 min.

(An Advanced CodeQL workflow used to live in `docker.yml` but conflicted with
Default Setup — the Default Setup path is simpler and Scorecard treats it
identically. Trivy + gitleaks SARIF are still uploaded as separate categories.)

### 3. OpenSSF Best Practices Badge (CII-Best-Practices → 0 → 10)
1. Go to <https://www.bestpractices.dev/>.
2. Sign in with the GitHub account that owns `tarrinho/AntiBotGW`.
3. Click **Get Your Badge Now** → **Add project**.
4. Fill in the questionnaire (~20 min for Passing level):
   - Project URL: `https://github.com/tarrinho/AntiBotGW`
   - License, contribution guide, security policy — all already present.
   - Most answers are `Met` because we already have: SECURITY.md, LICENSE
     (Apache-2.0), release process, static analysis (bandit/semgrep),
     hash-pinned deps, container signing (cosign), SBOM (SPDX via syft).
5. Once **Passing** shows, copy the badge markdown into README.md near the
   other badges:
   ```markdown
   [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>)
   ```

---

## Time-gated — no action needed

| Check | Reason | Resolves |
|-------|--------|----------|
| Maintained | Repo <90 days old. | Auto — around **2026-10** (90 days after repo creation). |
| CI-Tests | Scores `-1` because no PRs have been merged. | After first PR-based merge (blocked on Branch Protection above). |
| Signed-Releases | Scores `-1` because no releases exist. First release will already be cosign-signed via docker.yml. | On first tag push. |
| Code-Review | 0/30 approved changesets — direct push history. | After Branch Protection forces PR flow; next scorecard scan lifts to ≥5. |

---

## Hard-to-move — solo-project limits

- **Contributors — 3/10**: caps at 3 unless external contributors from other
  orgs commit. Not blocking; not fixable without inviting collaborators.

---

## Re-scanning

After applying the settings above:

1. Push the code changes (`./publish.sh`).
2. Wait for `.github/workflows/scorecard.yml` to run on the next push
   (or trigger `workflow_dispatch`).
3. Result appears at
   <https://scorecard.dev/viewer/?uri=github.com/tarrinho/AntiBotGW>
   within ~5 min of the workflow finishing.

Target overall after all fixes: **~8.5 / 10** (blocked from 10 by
`Contributors` and, briefly, `Maintained`).
