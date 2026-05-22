# Contributing to AppSecGW

Thanks for helping out! This guide covers how to contribute and the one
agreement you need to accept first.

## TL;DR

1. Sign off your commits: `git commit -s` (certifies the CLA — see below).
2. Fork → branch → PR. The maintainer reviews and merges.
3. Run the test suite before opening a PR.

## 1. Contributor License Agreement (required)

This project uses a **CLA** so the maintainer can keep the licensing clean and
relicense the project in the future if needed. **You keep ownership of your
contribution** — the CLA only grants a broad license. Read **[CLA.md](./CLA.md)**.

You accept the CLA in **one** of these ways:

- **Per-commit DCO sign-off (preferred):** add `-s` to every commit —
  `git commit -s -m "…"` — which appends a `Signed-off-by: Your Name <email>`
  line. That sign-off certifies the [Developer Certificate of Origin](https://developercertificate.org/)
  **and** your agreement to `CLA.md`. Use your real name and a real email.
- **One-time PR acknowledgement:** on your first PR, comment
  *"I have read the CLA and I agree to it. — <full name>, <date>"*.

Contributing on behalf of an **employer**? You must be authorized — see §5 of
`CLA.md` (Corporate CLA). Do **not** submit code, secrets, customer data, or
internal/confidential material you are not permitted to contribute.

## 2. License of contributions

The project is licensed under **Apache-2.0** (see [LICENSE](./LICENSE)).
Contributions come in under Apache-2.0 (inbound = outbound) **plus** the
additional grant in `CLA.md` that lets the maintainer relicense.

## 3. How to contribute

```bash
# 1. Fork on GitHub, then:
git clone https://github.com/<you>/anti-bot-proxy.git
cd anti-bot-proxy
git checkout -b my-change

# 2. Make your change, then run the relevant tests (see below)

# 3. Commit WITH sign-off, push, open a PR
git commit -s -m "feat: short description"
git push origin my-change
```

The maintainer (see [CODEOWNERS](./CODEOWNERS)) has final review/merge say.
Branch protection requires at least one maintainer approval before merge.

## 4. Before you open a PR

- **Tests pass.** Run the gates relevant to your change, e.g.:
  ```bash
  pytest tests/test_critical.py tests/test_pure.py tests/test_async.py -q   # unit
  pytest tests/ -q -k "v1810"                                               # current-release suite
  ```
  For larger changes, follow the full pipeline in **[rules.md](./rules.md)**
  (Gate 0a version consistency, Gate 0b admin-key strength, lint, Bandit/Semgrep,
  Trivy, etc.).
- **No secrets / internal data** in the diff or in git history (keys, `.env`,
  passwords, internal hostnames, customer data). PRs containing these will be
  rejected.
- **Match the surrounding style.** New detection signals: add the knob to both
  `SIGNAL_KNOB` and `_VHOST_COERCE` (a test enforces this).
- **Document it.** Update `CHANGELOG.md`, and `README.md` / `MANUAL.md` /
  `GW-Tests-Full.md` where relevant.

## 5. Reporting security issues

Do **not** open a public issue for vulnerabilities. Email the maintainer
(<tarrinho@gmail.com>) privately so a fix can ship before disclosure.

## 6. Code of conduct

Be respectful and constructive. Harassment or abuse is not tolerated.
