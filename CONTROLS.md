# AntiBot/WAF GW Controls

**Version**: 1.7.3 · **Author**: Pedro Tarrinho

---

## Challenge Gate

- **JS Challenge** — Intercepts every request that lacks a valid browser cookie. Real browsers solve the challenge transparently; bots and scripts never receive a real response.
- **Turnstile (Cloudflare CAPTCHA)** — Adds a visible human-verification step for identities that have already accumulated suspicious behaviour. Most users never see it.
- **Proof of Work** — Embeds a computational puzzle into the challenge page for the most suspicious identities. Makes mass automated solving expensive.
- **Service Worker Challenge** — Verifies that the browser can register and run a Service Worker. Headless and automation environments typically cannot.

---

## Risk Scoring

- **Soft threshold** — Identities above this score receive artificial response delays without being banned.
- **Ban threshold** — Identities above this score are banned for a configurable duration and silently sent to a decoy.
- **Ban duration** — How long a banned identity stays blocked.
- **Escalation threshold** — Score above which second-order behavioural signals begin accumulating.

---

## Rate Limiting

- **Per-session rate limit** — Caps how fast a single browser session can send requests.
- **Per-IP rate limit** — Caps total traffic from one IP address across all its sessions.
- **Global rate limit** — Caps the total request rate forwarded to the upstream application.
- **Session churn limit** — Detects an IP rapidly creating many new sessions (credential stuffing, rotating proxies).

---

## Traffic Admission

- **Host allowlist** — Only requests addressed to configured hostnames are accepted. All others are silently rejected.
- **Method allowlist** — Only configured HTTP methods are forwarded. Unusual methods from scanners are dropped.
- **Origin enforcement** — On state-changing requests, requires the `Origin` header to match the allowed hostnames. Blocks cross-site request forgery.
- **Required headers** — Custom headers that must be present on every request. Used to implement shared secrets between a CDN and the gateway.

---

## Detectors

### Path & URL

- **Suspicious path scanner** — Flags URLs matching known attack patterns: credential files, path traversal, SQL injection in URLs, shell meta-characters.
- **Honeypot endpoints** — Fake admin and sensitive-looking URLs that no real user would ever visit. Any hit is near-certain automation.
- **Bot-trap forms** — Hidden form fields injected into HTML pages. Automated form-fillers that submit them are flagged.
- **Robots.txt monitoring** — Flags clients that request paths explicitly disallowed for crawlers in `robots.txt`.

### User-Agent & Headers

- **User-Agent filter** — Blocks empty, very short, or deny-listed User-Agent strings and UAs that don't match any real browser.
- **Platform consistency check** — Compares the User-Agent OS claim against the `Sec-CH-UA-Platform` header sent by the OS. Spoofed UAs are flagged.
- **Header completeness** — Flags requests missing the set of headers that real browsers always include.
- **Header order fingerprint** — Fingerprints the HTTP/2 header order, which differs predictably between real browsers and automation tools.

### Body Injection Detection

- **SQL injection** — Scans request bodies for SQL injection payloads.
- **Cross-site scripting (XSS)** — Scans for script tags, event handlers, and JavaScript URI patterns.
- **Local file inclusion (LFI)** — Scans for path traversal sequences in POST bodies.
- **Remote code execution (RCE)** — Scans for JNDI/Log4Shell probes and template injection patterns.
- **Server-side request forgery (SSRF)** — Scans for internal metadata service addresses and internal hostnames.
- **OS command injection** — Scans for shell metacharacters in submitted data.

### Session & Behavioural

- **Session flood** — Detects a single IP rapidly creating many new sessions.
- **AI enumeration** — Detects identities visiting a large number of distinct paths without ever loading static assets.
- **AI crawler blocking** — Detects and blocks User-Agents from known AI companies (OpenAI, Anthropic, Google, Perplexity, Meta, others). Each vendor is independently configurable.

### Client-Side Probes

- **Browser automation probe** — Injects a JavaScript snippet that checks for headless browser indicators: `navigator.webdriver`, absent plugins, non-standard screen settings.
- **BotD** — Injects FingerprintJS's bot detection library. Returns a bot/not-bot verdict from the browser.
- **Browser fingerprint enrichment** — Collects canvas and WebGL rendering fingerprints. Headless browsers render differently and often lack hardware graphics.

### Second-Order & Behavioural

- **Canary echo detection** — Embeds a hidden unique token in every HTML page. If any subsequent request echoes that token back, an LLM agent has read and replayed the page content.
- **Cookie lifecycle** — Injects a JavaScript snippet that sets a marker cookie. If subsequent requests arrive without it, JavaScript is not executing in the client.
- **Cookie ghost** — Detects challenge cookies that were solved externally and injected, rather than earned by the browser itself.
- **Referer chain integrity** — Tracks which pages were actually served to each identity. A `Referer` pointing to a page that was never served is a spoofed header.
- **Impossible travel** — Flags a session (same cookie) appearing from two different countries within a short time window.
- **Coordinated probe detection** — Flags when multiple distinct identities from the same network hit the same path prefix within 60 seconds.
- **Direct API probe** — Flags identities that make API requests without ever loading an HTML page or static assets first.

---

## Geographic & IP Reputation

- **Country blocking** — Allows or denies traffic by source country, using a deny-list or allow-list.
- **Locale/geo mismatch** — Flags browsers whose declared language (`Accept-Language`) is inconsistent with their IP's country.
- **Tor blocking** — Blocks traffic from known Tor exit nodes.
- **Datacenter & VPN blocking** — Blocks traffic from cloud provider, hosting company, and commercial VPN IP ranges.
- **AbuseIPDB** — Checks the source IP against the AbuseIPDB community threat feed. Two confidence tiers: medium and high.
- **CrowdSec** — Checks the source IP against a self-hosted CrowdSec blocklist fed by community intelligence.
- **TLS fingerprint deny-list** — Blocks specific JA4 TLS fingerprints associated with known scanning tools or botnets, before any HTTP is processed.

---

## Deception

- **Tarpit** — Introduces artificial response delays for suspicious identities instead of blocking them outright. Makes automated tools slow without revealing detection.
- **AI Labyrinth** — An endless maze of plausible-looking fake pages. Once an automated crawler enters it, it is trapped and consumes resources indefinitely while the upstream is never reached.

---

## Data Loss Prevention

Scans upstream response bodies for sensitive data before forwarding to the browser. Each category is independently enabled:

- **Credit card numbers** — Detected with Luhn validation, not just pattern matching.
- **AWS credentials** — Access key IDs and secret formats.
- **JWT tokens** — Bearer tokens embedded in API responses.
- **Private keys** — PEM-encoded RSA/EC private keys.
- **API keys** — Common formats from major platforms.
- **Email addresses** — PII in API responses.
- **Social Security Numbers** — US SSN patterns.

Matches are logged and optionally redacted before the response reaches the browser.

---

## JWT Validation

Enforces that specific URL paths require a valid signed token before the request is forwarded. Adds an edge authentication layer without modifying application code.

---

## Custom Rules

Operator-defined IF/THEN rules that run before all built-in detectors. Can match on IP, CIDR range, URL path, HTTP method, User-Agent, headers, or current risk score. Actions: **allow** (bypass all detection), **block** (silent decoy), **challenge** (force CAPTCHA), or **tag** (label the log entry for SIEM correlation).

---

## Endpoint Policies

Per-path rate limit overrides. Applies tighter limits to high-value targets (login, registration, password reset) without affecting global defaults.

---

## Security Headers

Injects hardening headers onto upstream HTML pages that don't already set them. No application changes required:

- **HSTS** — Forces browsers to always use HTTPS.
- **X-Frame-Options** — Prevents the site from being embedded in iframes (clickjacking protection).
- **X-Content-Type-Options** — Prevents MIME-sniffing attacks.
- **Referrer-Policy** — Controls referrer information sent when navigating away.
- **Permissions-Policy** — Disables unused browser features (camera, microphone, geolocation, etc.).
- **Cross-Origin isolation headers** — Prevents cross-origin information leakage.
- **Content-Security-Policy** — Restricts which scripts and resources the browser may load.

---

## Alerting

Sends real-time event notifications (bans, DLP hits) to an external webhook URL. Filterable by event type for SIEM or incident response integration.

---

## Operational

- **Log format** — JSON (for log pipelines) or plain text (for terminal tailing).
- **Log level** — Verbosity from debug to error, adjustable without restart.
- **Database backend** — Embedded SQLite or PostgreSQL, switchable live without restart.
- **Data retention** — How long identity history, metrics, and health samples are kept.
