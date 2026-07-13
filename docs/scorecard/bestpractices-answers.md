# OpenSSF Best Practices — pre-filled answers

Copy each row's answer into the matching field at
<https://www.bestpractices.dev/en/projects/new>.

- **Project name**: `AntiBotGW`
- **Home page URL**: `https://github.com/tarrinho/AntiBotGW`
- **Source repository URL**: `https://github.com/tarrinho/AntiBotGW`
- **Description (short)**: `Reverse-proxy anti-bot / WAF gateway (Python 3.13, aiohttp) with challenge, risk-scoring, honeypots, admin dashboards, MaxMind geo, PostgreSQL/SQLite backends, and cosign-signed distroless container images.`
- **License**: `Apache-2.0`

The tables below cover every **Passing**-level criterion. Answer with the
first column (`Met` / `Unmet` / `N/A`) and paste the second column verbatim
into the justification field.

## Basics

| Criterion | Answer | Justification |
|---|---|---|
| `description_good` | Met | See the description above. |
| `interact` | Met | GitHub Issues + Discussions are enabled on the repository; `SECURITY.md` documents the private-disclosure channel. |
| `contribution` | Met | `CONTRIBUTING.md` at the repo root — describes fork-and-PR flow, rules.md coding standards, and the required per-release validation checklist. |
| `contribution_requirements` | Met | `CONTRIBUTING.md` states the Apache-2.0 licence, DCO/sign-off requirement, and the CI gates a PR must pass before merge. |
| `floss_license` | Met | `LICENSE` — Apache License 2.0. |
| `floss_license_osi` | Met | Apache-2.0 is on the OSI-approved list. |
| `license_location` | Met | `LICENSE` at the repository root. |
| `documentation_basics` | Met | `README.md` (features + architecture mermaid diagrams), `manual/README.md` (full operator manual), `CHANGELOG.md` (version history). |
| `documentation_interface` | Met | `manual/README.md` documents every environment variable, admin endpoint, and dashboard. `dast-smoke.sh` and `report.html` enumerate the HTTP surface. |
| `sites_https` | Met | `github.com` is HTTPS; any demo instance operators stand up is intended to be HTTPS-only with HSTS (see `manual/README.md` TLS section). |
| `discussion` | Met | GitHub Discussions is enabled on `tarrinho/AntiBotGW`. |
| `english` | Met | All committed docs, code comments, commit messages, and CHANGELOG entries are in English (enforced by `rules.md` §feedback-docs-english-only). |
| `maintenance_or_update` | Met | Semantic-versioned releases published via `docker.yml` auto-release; CHANGELOG.md shows continuous updates through 1.9.13. |

## Change Control

| Criterion | Answer | Justification |
|---|---|---|
| `repo_public` | Met | <https://github.com/tarrinho/AntiBotGW> is public. |
| `repo_track` | Met | Git — public GitHub. |
| `repo_interim` | Met | Every commit lives on `main`; interim changes are tracked via `[Unreleased]` sections in `CHANGELOG.md`. |
| `repo_distributed` | Met | Git is a DVCS. |
| `version_unique` | Met | `GW_VERSION` in `config.py` is the single source of truth; every release tag is unique. |
| `version_semver` | Met | Follows Semantic Versioning (major.minor.patch). |
| `version_tags` | Met | Every release is a signed git tag `vX.Y.Z` (auto-created by `docker.yml` when `config.py` version bumps). |
| `release_notes` | Met | `CHANGELOG.md` — grouped `[Unreleased]` + per-version entries with `Added / Changed / Security / Tests`. |
| `release_notes_vulns` | Met | Security-relevant CHANGELOG lines carry the CVE / GHSA / PYSEC id (see 1.9.13 pyjwt/cryptography entries). |

## Reporting

| Criterion | Answer | Justification |
|---|---|---|
| `report_process` | Met | `SECURITY.md` — private disclosure via GitHub Security Advisories + email fallback. |
| `report_tracker` | Met | GitHub Issues + GitHub Security Advisories (private for vulns). |
| `report_responses` | Met | `SECURITY.md` commits to first-response within 7 days, fix within 30 days for confirmed vulns. |
| `enhancement_responses` | Met | Feature-request issues receive triage within 7 days. |
| `report_archive` | Met | GitHub Issues + PRs are archived indefinitely on github.com. |
| `vulnerability_report_process` | Met | Documented in `SECURITY.md`. |
| `vulnerability_report_private` | Met | GitHub Security Advisories (private-by-default channel). |
| `vulnerability_report_response` | Met | `SECURITY.md` — first-response commitment ≤ 7 days. |

## Quality

| Criterion | Answer | Justification |
|---|---|---|
| `build` | Met | `Dockerfile` + `Dockerfile.armv7` + `docker.yml` build multi-arch images (`linux/amd64`, `linux/arm64`, `linux/arm/v7`); no manual build steps. |
| `build_common_tools` | Met | Docker BuildKit — universal. |
| `build_floss_tools` | Met | Docker BuildKit + Python are FLOSS. |
| `installation_common` | Met | `docker run ghcr.io/tarrinho/antibotgw:latest` — one command. |
| `installation_standard_variables` | Met | Deploy-shape env vars documented in `manual/README.md`; hot-reloadable knobs via `/__config`. |
| `installation_development_quick` | Met | `README.md` "Quickstart" — `docker compose up` from `compose.yml`. |
| `external_dependencies` | Met | `requirements-runtime.lock` + `requirements-runtime-armv7.lock` — exact-pinned, hash-verified. |
| `dependency_monitoring` | Met | `.github/dependabot.yml` monitors pip + GitHub Actions weekly. |
| `updateable_reused_components` | Met | Every dep is a pinned version in a `requirements*.lock`; refresh = `pip-compile --generate-hashes`. |
| `interfaces_current` | Met | Public admin API is documented in `manual/README.md`; deprecated endpoints removed at each major release. |
| `automated_test` | Met | 940+ pytest tests across `tests/`, run in `docker.yml` `tests` job on every push. |
| `automated_test_units` | Met | `tests/test_pure.py`, `tests/test_critical.py`, plus per-feature `test_v*_*.py` — mixture of unit + integration. |
| `automated_test_policy` | Met | `rules.md` §7 requires new features to ship with tests; per-release validation file (`validation/<version>.md`) confirms full suite green. |
| `tests_are_added` | Met | `rules.md` §7 + `CONTRIBUTING.md` require tests for every PR that adds functionality. |
| `tests_documentation_added` | Met | `GW-Tests-Full.md` documents every test file (mandatory per-section totals — see `rules.md` §4). |
| `warnings` | Met | `docker.yml` runs `ruff`, `bandit`, `semgrep`, `mypy`, `vulture`, `pip-audit`; warnings surfaced on PRs. |
| `warnings_fixed` | Met | Zero-tolerance codes (F841, S314, B904, F401 non-star) block merge; larger baseline documented in `rules.md` §11. |
| `warnings_strict` | Unmet | Baseline of ~165 accepted findings (E701, C901, S104, S608, F811) documented as intentional in `rules.md` §11. |

## Security

| Criterion | Answer | Justification |
|---|---|---|
| `know_secure_design` | Met | Threat model documented in `manual/README.md` §Threat model; STRIDE-lite review is part of every release (`rules.md` §11b). |
| `know_common_errors` | Met | `docs/scorecard/` + `report.html` cite OWASP Top 10, CWE mapping for admin surface; developer maintains active bug-hunter engagement notes. |
| `crypto_published` | Met | Uses `cryptography` 49.0.0 + `PyJWT` 2.13.0 (well-known FLOSS libs, no home-grown crypto). |
| `crypto_call` | Met | AES / RSA / ES256 done via `cryptography`; JWTs via PyJWT. No custom primitives. |
| `crypto_floss` | Met | `cryptography` (Apache-2.0 / BSD), PyJWT (MIT) — both FLOSS. |
| `crypto_keylength` | Met | Session cookies use 256-bit random secrets; RS256/ES256 keys ≥ 2048/256 bits. |
| `crypto_working` | Met | No known-broken algorithms (SHA-1, MD5, RC4 disabled at the TLS + JWT layer). |
| `crypto_pfs` | Met | TLS layer is fronted by Cloudflare / operator's reverse proxy — inherits PFS ciphers. |
| `crypto_password_storage` | Met | Admin secrets are cryptographically random API keys, not user passwords; stored as SHA-256-hashed values with per-instance salt. |
| `crypto_random` | Met | `secrets.token_urlsafe()` (Python's CSPRNG) for admin/session/PoW keys. |
| `delivery_mitm` | Met | Images published to `ghcr.io/tarrinho/antibotgw` are cosign-signed (keyless via Fulcio OIDC — see `docker.yml` sign job) and shipped over HTTPS. |
| `delivery_unsigned_email` | N/A | We do not use email delivery. |
| `vulnerabilities_fixed_60_days` | Met | Recent example — pyjwt CVEs closed in `1.9.13` within 24h of scorecard flagging. |
| `vulnerabilities_critical_fixed` | Met | Same. |

## Analysis

| Criterion | Answer | Justification |
|---|---|---|
| `static_analysis` | Met | `docker.yml` runs `ruff`, `bandit`, `semgrep` on every push. |
| `static_analysis_common_vulnerabilities` | Met | `semgrep p/python` + `bandit -ll` — cover OWASP + Aikido rulesets. |
| `static_analysis_fixed` | Met | Zero-tolerance codes (F841/S314/B904) block merge; findings triaged per release. |
| `static_analysis_often` | Met | Every push runs the SAST stage. |
| `dynamic_analysis` | Met | `dast-smoke.sh` runs post-build; Playwright cross-browser matrix (Chromium/Firefox/WebKit) in `docker.yml`. |
| `dynamic_analysis_unsafe` | Met | Base image is Chainguard Wolfi distroless — no shell, no coreutils, no CVE surface from system libs. |
| `dynamic_analysis_enable_assertions` | N/A | Python — assertions on by default outside `-O`. |
| `dynamic_analysis_fixed` | Met | Any DAST finding on `/live`, `/secured/*`, or admin dashboards blocks the release (`rules.md` §15). |

## Notes

- **`warnings_strict` is the only Unmet** — accepting it is fine for Passing.
  For Silver/Gold you'd need to walk down the ~165-item baseline; not worth
  it at this stage.
- Once you submit and the badge appears, the URL/id looks like
  `https://www.bestpractices.dev/projects/<ID>/badge`. Add to `README.md`:
  ```markdown
  [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/<ID>/badge)](https://www.bestpractices.dev/projects/<ID>)
  ```
