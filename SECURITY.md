# Security Policy

AntiBot/WAF GW is a reverse-proxy security control that sits in front of other
web applications. A vulnerability in it can weaken or bypass the protection it
provides, so security reports are taken seriously and handled with priority.

## Supported versions

Security fixes are released for the current minor series only. Upgrade to the
latest release before reporting, if you can — the issue may already be fixed.

| Version | Supported          |
|---------|--------------------|
| 1.9.x   | ✅ security fixes   |
| < 1.9   | ❌ end of life      |

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a security
problem.** Public disclosure before a fix is available puts every deployment at
risk.

Report privately through **either** channel:

1. **GitHub private vulnerability reporting (preferred).**
   Open <https://github.com/tarrinho/AntiBotGW/security/advisories/new>. This
   creates a private advisory only the maintainer can see, and lets us
   collaborate on the fix and a coordinated release in one place.
2. **Email:** [tarrinho@gmail.com](mailto:tarrinho@gmail.com). Use the subject
   line `SECURITY: <short summary>`. If you need encryption, say so and we will
   arrange a key exchange.

### What to include

A good report lets us reproduce and fix quickly:

- affected version(s) and, if known, the affected file/function or endpoint;
- a description of the impact (what an attacker gains — bypass, RCE, disclosure,
  privilege escalation, etc.);
- a **proof of concept**: the exact request(s), configuration, or steps to
  reproduce, plus expected vs. actual behaviour;
- any relevant configuration (env vars, `vhosts.json`, enabled controls) —
  **redact real secrets, hostnames, and IPs**.

## Response expectations

This is a maintainer-driven open-source project, handled on a best-effort basis:

| Stage                         | Target                                   |
|-------------------------------|------------------------------------------|
| Acknowledge your report       | within 9 business days                   |
| Initial severity assessment   | within 21 business days                  |
| Fix or mitigation plan        | depends on severity; Critical/High first |
| Coordinated public disclosure | after a fix is released, by agreement    |

We will keep you informed through triage, fix, and release. If you do not hear
back within two weeks, please re-send — a message may have been missed.

## Coordinated disclosure & credit

We follow coordinated disclosure. Please give us a reasonable window to release
a fix before publishing details. Unless you prefer to remain anonymous, we will
credit you in the release notes / advisory for the report.

## Scope

**In scope** — vulnerabilities in the gateway itself:

- the proxy / detection / challenge / scoring code and its packages;
- the operator dashboards and admin plane (auth, CSRF, session handling);
- the published container image and its default configuration;
- secret handling, log redaction, and data exposure by the gateway.

**Out of scope** — the operator's responsibility, or already-documented posture
(see [`threatmodel.md`](threatmodel.md) §7):

- the security of the **upstream application** the gateway protects;
- TLS termination, the host, the `/data` volume, and Redis/Postgres network
  exposure and credential rotation;
- operator **misconfiguration** (e.g. a weak `ADMIN_KEY`, disabling controls,
  binding the admin plane to the public internet);
- volumetric / network-layer denial of service (mitigate upstream, e.g. at a
  CDN or L3/L4);
- reports from automated scanners with no demonstrated, exploitable impact;
- social engineering, physical attacks, or issues requiring a
  already-compromised host.

## Safe harbor

We consider security research conducted in good faith — testing against your own
deployment, avoiding privacy violations and service degradation for others, and
not exploiting an issue beyond what is needed to prove it — to be authorized. We
will not pursue or support legal action against researchers who follow this
policy and report privately. Do not access, modify, or exfiltrate data that is
not yours, and stop and report as soon as a vulnerability is confirmed.

## Security posture

The project documents its own posture openly: see the
[threat model](threatmodel.md), the "Threat model & honest posture" section of
the [README](README.md), and the CI pipeline, which runs secret scanning
(gitleaks, TruffleHog), SAST (Bandit, Semgrep, ruff), dependency and image CVE
scanning (Trivy), and signs every published image (cosign) on each push.
