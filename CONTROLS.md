# AntiBot/WAF GW — Controls Reference

**Version**: 1.9.8 · **Author**: Pedro Tarrinho

> Auto-generated from the live control set. Every toggle/threshold the gateway exposes is listed below, grouped by request-pipeline stage. For the full code-grounded deep-dive (mechanics, CWE, when-to-disable) see `controls_details.pdf`; for live state use the Controls dashboard.


## Geo, Reputation & TLS Fingerprint  (7)

_Network-origin controls: country allow/deny (MaxMind GeoIP), Tor-exit and datacentre/VPN blocking, impossible-travel detection, and TLS-fingerprint (JA4/JA3) deny-listing with fail-open/closed selection._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `COUNTRY_BLOCK_ENABLED` | toggle | Off | Country-level geofencing using GeoLite2-City. Off → no-op. ⓘ Suggested deny list for most production gateways: <b>RU</b> (Russia), <b>KP</b> (North Korea), <b>CN</b> (China), <b>BY</b> (Belarus), <b>IR</b> (Iran). Tune to your threat model + compliance constraints (sanctions, export-control). Note: admin IPs ALWAYS bypass country block — you can never lock yourself out by adding your own country. |
| `TOR_BLOCK_ENABLED` | toggle | Off | Block Tor exit nodes — auto-fetches torbulkexitlist (weekly refresh). Fires tor-exit (+50 risk). |
| `DC_VPN_BLOCK_ENABLED` | toggle | Off | Block datacenter / commercial-VPN ASNs — heavier weight on top of asn-hosting. |
| `TLS_FP_BLOCK_ENABLED` | toggle | On | 1.8.9 — TLS fingerprint (JA4/JA3) deny-list enforcement. Only fires when JA4_DENY_LIST is non-empty. Disable to bypass TLS-fingerprint blocking without clearing the deny-list. |
| `COUNTRY_DENYLIST` | list | [] | ISO-3166-1 alpha-2 codes to deny. ⓘ Suggested production list: RU, KP, CN, BY, IR. Example: <code>RU,CN,KP</code>. Empty list = no country denied. Allowlist (next field) takes precedence: when COUNTRY_ALLOWLIST is non-empty, anything outside it is blocked even if not listed here. |
| `COUNTRY_ALLOWLIST` | list | [] | ISO-3166-1 alpha-2 codes to allow exclusively (whitelist mode). Empty → denylist mode. |
| `LOCALE_GEO_CHECK_ENABLED` | toggle | On | Accept-Language / GeoIP locale consistency (1.6.10) — fires (+10 soft) when the primary language tag in Accept-Language is implausible for the GeoIP country (e.g. Accept-Language: ru from a US IP). Only checks countries with a single dominant language; 'en' is never flagged as a mismatch. Escalate-gated (only runs on identities with accumulated risk). |

## Rate Limiting & Token Buckets  (12)

_Every identity and every source IP gets its own token bucket: it holds up to burst tokens and refills at refill tokens/second; each request spends one. An empty bucket throttles the client (silent decoy), smoothing bursts while capping sustained rate independent of any bot signal._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `GLOBAL_RPS_LIMIT` | number | 0 | Operator throttle: silent-decoy any request beyond N req/s globally. 0 = disabled. |
| `TRAFFIC_THRESHOLD_ENABLED` | toggle | On | 1.8.9 — Global RPS cap enforcement (GLOBAL_RPS_LIMIT). Only active when GLOBAL_RPS_LIMIT > 0. Disable to bypass the global cap without zeroing it. |
| `ENDPOINT_RATE_LIMIT_ENABLED` | toggle | On | 1.8.9 — Per-endpoint rate limits from ENDPOINT_POLICIES. Fires only when a matching policy has rps/burst set. Disable to bypass endpoint throttling without clearing policies. |
| `RATE_LIMIT_ENABLED` | toggle | On | 1.8.9 — Per-identity rate limiting (RATE_LIMIT_BURST / RATE_LIMIT_REFILL token bucket). Disable temporarily when a high-volume legitimate client is hitting the per-session cap. CAUTION: disabling removes a key DoS defence. |
| `RATE_LIMIT_IP_ENABLED` | toggle | On | 1.8.9 — Per-IP socket rate limiting (IP_BURST / IP_REFILL token bucket). Disable temporarily when legitimate clients behind NAT are hitting the per-IP cap. CAUTION: disabling removes a key DoS defence. |
| `SESSION_CHURN_ENABLED` | toggle | On | 1.8.9 — Session churn detection: flags identities that rotate cookies faster than SESSION_CHURN_MAX per SESSION_CHURN_WINDOW_S. Disable if a legitimate mobile app or SPA aggressively creates new sessions. |
| `SESSION_CHURN_WINDOW_S` | number | 120 | Window for fresh-session-rate detector. |
| `SESSION_CHURN_MAX` | number | 3 | Max chal cookies a single fingerprint may mint per window. |
| `RATE_LIMIT_BURST` | number | 20 | Per-identity token-bucket capacity. |
| `RATE_LIMIT_REFILL` | number | 3.0 | Per-identity tokens added per second. |
| `IP_BURST` | number | 30 | Per-socket-IP token-bucket capacity. |
| `IP_REFILL` | number | 5.0 | Per-socket-IP tokens added per second. |

## Core Bot-Detection Toggles  (3)

_The first-line heuristics every request passes: user-agent sanity, suspicious-path and path-sweep detection, Accept/header consistency, and the master bot-detection switch — each independently toggleable._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `BOT_DETECTION_ENABLED` | toggle | On | Master kill-switch for the heuristic bot detection pipeline. When off, all detector scoring is skipped for this vhost; existing bans and rate limits still apply. Use for trusted internal vhosts or staging environments. |
| `ACCEPT_WILDCARD_CHECK_ENABLED` | toggle | On | 1.8.9 — Accept: */* on HTML navigation (Sec-Fetch-Dest: document) risk-score bump. Real browsers always send a rich Accept on page loads; */* indicates a bot or HTTP library. Disable if a legitimate API client sends document navigation with */*. |
| `BOT_TRAP_FORMS` | toggle | Off | Inject a hidden honey field into every <form>. Filled = bot. |

## Fingerprinting & Canaries  (12)

_Active probes that separate real browsers from HTTP libraries: header/JSON canary tokens a replaying bot echoes back, browser-execution preload probes, Accept/header-order fingerprints, and JA4/JA4H TLS &amp; HTTP fingerprint enrichment._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `CANARY_TTL_S` | number | 600 | Canary token validity window. |
| `CANARY_ECHO_DETECTION` | toggle | On | R7 — plant agw-c-* canary in HTML; ban any client that echoes it back. |
| `HEADER_CANARY_ENABLED` | toggle | On | Header canary injection (1.6.10) — in addition to the HTML comment and X-Trace-Id, plants the per-identity HMAC-signed canary token in ETag (as \"agw-c-…\") and X-Request-Id response headers. AI frameworks such as LangChain and AutoGen that automatically replay full prior-response headers will echo the token back on the next request, triggering the canary-echo ban. Zero cost — only activates when CANARY_ECHO_DETECTION is also on. |
| `JSON_CANARY_ENABLED` | toggle | On | JSON API canary poisoning (1.6.10) — injects a \"_ref\":\"agw-c-…\" token into JSON object responses. LLM agents that cache and replay API responses will echo the _ref value back in a subsequent request body, triggering canary-echo detection (+40 ban). Zero visible effect on real users. Requires CANARY_ECHO_DETECTION=1. |
| `ACCEPT_FP_ENABLED` | toggle | On | Accept header fingerprint (1.6.10) — fires (+3 soft) when a browser-class UA navigates HTML (Sec-Fetch-Dest: document) but the Accept header lacks text/html entirely (e.g. application/json, text/plain). Real browsers always include text/html on document navigation. Catches bots that clone a Chrome UA string but forget the matching Accept profile. |
| `HEADER_ORDER_FP_ENABLED` | toggle | On | Header-order library fingerprint (1.6.10) — fires (+8 soft) when the ordered set of HTTP request header names matches a known library signature (python-requests, curl, Go net/http, httpx). Real browsers send 10+ headers in a consistent browser-defined order; bot libraries emit a predictable minimal set. Zero false-positive risk for real browsers. |
| `FP_ENRICHMENT_ENABLED` | toggle | On | Canvas/WebGL fingerprint enrichment (1.7.2) — injects ~1 KB of inline JS that draws a deterministic canvas scene and queries WebGL renderer info. Reports back via /antibot-appsec-gateway/fp-report (HMAC-bound to session). soft-renderer fires (+25) when the renderer string contains swiftshader/mesa/vmware/llvmpipe; webgl-missing fires (+15) when Chrome UA has no WebGL renderer (headless default). |
| `JA4H_DENY_ENABLED` | toggle | On | 1.8.9 — JA4H (HTTP request fingerprint) deny-list enforcement. Only fires when JA4H_DENY_LIST is non-empty. Disable to bypass the deny-list without clearing it. |
| `JA4_REQUIRED_ENABLED` | toggle | On | 1.8.9 — JA4 fingerprint required from trusted peer enforcement. Only fires when JA4_TRUSTED_NETS and JA4_HEADER are configured. Disable to bypass without clearing TLS fingerprint config. |
| `JA4_DENY_LIST` | list | set() | TLS handshake fingerprints to silent-decoy at Layer 0.5. |
| `JA4_FAIL_CLOSED` | toggle | Off | JA4 fail-closed (1.6.10) — when JA4_TRUSTED_NETS is configured, hard-deny (instead of soft-score) any non-static request that arrives without a JA4 header. Turns the soft ja4-required-missing signal into a hard block. Enable only after confirming all legitimate traffic paths inject the JA4 header. |
| `H2_FP_ENABLED` | toggle | Off | HTTP/2 fingerprint fallback (1.6.10, default OFF) — fires (+3 soft) when a modern-browser UA makes HTTP/1.1 requests via a TLS proxy (X-Forwarded-Proto: https). Real browsers always negotiate HTTP/2 on HTTPS; bot libraries default to HTTP/1.1. Disabled by default because TLS-terminating proxies may already normalise versions. |

## Behavioural & AI Detection  (15)

_Escalation-gated detectors that engage only once an identity already looks suspicious, keeping their cost off the hot path: enumeration patterns, LLM-scraper subresource behaviour, coordinated multi-identity attacks, automation/interaction probes._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `LLM_HEURISTIC_ENABLED` | toggle | On | LLM no-subresources heuristic: score identities that fetch HTML but never load its sub-resources (images/CSS/JS) — characteristic of LLM scrapers and headless pipelines. |
| `CANARY_PROBE_ENABLED` | toggle | On | Browser execution probe: inject a preload link that a real browser fetches; score identities that never fetch it. Disable if CSP or service-worker configuration suppresses the preload. |
| `BOTD_ENABLED` | toggle | Off | FingerprintJS BotD client-side detection (open-source). Injects /antibot-appsec-gateway/assets/botd.bundle.js into HTML responses; the in-browser library checks for headless / WebDriver / automation markers and POSTs an HMAC-bound report to /antibot-appsec-gateway/botd-report. Detected = +30 risk (med tier). Off by default — adds ~16 KB JS to every HTML response. |
| `JOURNEY_CHECK_ENABLED` | toggle | On | Journey / direct API probe detection: flag identities that call JSON API endpoints directly without ever loading the page that normally leads there. Disable if your API is intentionally public. |
| `REFERER_CHAIN_ENABLED` | toggle | On | Referer-ghost detection (1.7.2) — fires when a request's Referer header claims our domain but the referenced path was never served to this identity. Fabricated Referers are common in bot frameworks that copy headers from captured browser sessions. Fires referer-ghost (+10 risk). |
| `SW_CHALLENGE_ENABLED` | toggle | Off | Service Worker challenge (1.7.2, default OFF) — registers a SW at /antibot-appsec-gateway/sw.js that adds X-SW-Active: 1 to every intercepted gateway request. Absence of this header after the SW is expected to be registered is a strong headless-browser signal. Requires a browser that supports Service Workers. Disabled by default — enable when advanced headless evasion is confirmed. |
| `AUTOMATION_PROBE_ENABLED` | toggle | On | Automation probe: inject a JS snippet that detects navigator.webdriver and automation markers; flag identified automation. Disable if Playwright/Puppeteer test accounts must pass through. |
| `INTERACTION_PROBE_ENABLED` | toggle | On | Interaction analysis: score bot-like mouse/scroll/keyboard patterns (straight-line motion, uniform velocity, scripted keys, zero interaction). Disable if your JS challenge page does not collect interaction events. |
| `COORDINATED_ATTACK_ENABLED` | toggle | On | Coordinated attack detection: flag IPs from ASNs where many distinct identities are probing the same paths simultaneously. Requires MaxMind ASN data. |
| `COOKIE_GHOST_ENABLED` | toggle | On | Cookie-ghost detection (1.7.2) — fires when the gateway has set cookies for an identity but the client has never returned any of them across 3+ requests. Real browsers carry cookies automatically; pure-HTTP bots do not. Near-zero false-positive risk. Fires cookie-ghost (+20 risk). |
| `COOKIE_LIFECYCLE_ENABLED` | toggle | On | Lifecycle-miss detection (1.7.2) — injects a tiny JS snippet into HTML responses that sets the agw_lc cookie. If subsequent non-HTML requests from the same identity lack the cookie, JS is not executing (headless/curl). Fires lifecycle-miss (+12 risk). |
| `COOKIE_GHOST_MIN_REQUESTS` | number | 3 | Minimum total requests before cookie-ghost can fire. Prevents false positives on first-contact clients. |
| `COOKIE_GHOST_MISS_THRESHOLD` | number | 3 | Number of cookie-miss requests before cookie-ghost fires. Default 3. |
| `IMPOSSIBLE_TRAVEL_ENABLED` | toggle | On | Impossible-travel detection (1.7.2) — fires when the same session-keyed identity appears from a different country within IMPOSSIBLE_TRAVEL_WINDOW_SECS. Catches session hijacking and VPN-hopping bots. Requires MaxMind GeoLite2 City DB. Fires impossible-travel (+35 risk → ban). |
| `IMPOSSIBLE_TRAVEL_WINDOW_SECS` | number | 1800 | Window (seconds) in which the same identity must not appear from two different countries. Default 1800 = 30 min. |

## AI Crawler Controls  (7)

_Per-vendor switches for declared AI crawlers (OpenAI, Anthropic, Google, Perplexity, Meta, others) plus forward/reverse-DNS verification so a spoofed AI user-agent can't claim a real crawler's allowed behaviour._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `AI_CRAWLER_VERIFY_ENABLED` | toggle | On | AI crawler IP-range verification (1.6.10) — when a UA matches a declared AI crawler (OpenAI GPTBot etc.), verifies the source IP is in the vendor's published CIDR range. IP mismatch fires ai-ua-ip-mismatch (+30). Ranges fetched from openai.com/gptbot-ranges.txt at startup, cached 24 h. |
| `AI_UA_OPENAI_ENABLED` | toggle | On | Block OpenAI / GPTBot / ChatGPT-User crawlers (granular toggle). |
| `AI_UA_ANTHROPIC_ENABLED` | toggle | On | Block ClaudeBot / Claude-Web / anthropic-ai (granular toggle). |
| `AI_UA_GOOGLE_ENABLED` | toggle | On | Block Google-Extended / Bard / Gemini (granular toggle). |
| `AI_UA_PERPLEXITY_ENABLED` | toggle | On | Block PerplexityBot (granular toggle). |
| `AI_UA_META_ENABLED` | toggle | On | Block Meta-ExternalAgent / FacebookBot (granular toggle). |
| `AI_UA_OTHER_ENABLED` | toggle | On | Block Bytespider / CCBot / Cohere / Mistral / generic AI crawlers. |

## WAF & Body Scanning  (14)

_A request/response WAF independent of bot scoring: it inspects bodies and headers for SQLi, XSS, Log4Shell, SSRF/metadata, traversal, command injection, XXE and prototype pollution, plus smuggling, verb-override, GraphQL abuse, malicious uploads and slowloris. These fire regardless of escalation score._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `BODY_PATTERN_MATCH` | toggle | Off | Scan POST bodies for SQLi / XSS / SSTI / cmd-injection markers. |
| `WAF_BODY_ENABLED` | toggle | On | 1.8.9 — WAF body checks: critical SQLi (UNION SELECT), Log4Shell, SSRF/metadata IPs, path traversal, OS command injection, XXE, prototype pollution. Fires regardless of escalation score. Disable if a legitimate search or API endpoint triggers false positives. |
| `WAF_SMUGGLING_ENABLED` | toggle | On | 1.8.9 — HTTP request smuggling detection (CL-TE, TE-CL, TE-TE, invalid TE). Blocks requests with conflicting Content-Length/Transfer-Encoding headers. Disable only if upstream handles smuggling checks itself. |
| `WAF_VERB_OVERRIDE_ENABLED` | toggle | On | 1.8.9 — Verb/method override detection: blocks X-HTTP-Method-Override, X-Method-Override, _method tunnelling. Disable if your app legitimately uses method tunnelling. |
| `WAF_HEADER_INJECTION_ENABLED` | toggle | On | 1.8.9 — Header injection: SSTI payloads in attacker-controlled headers ({{7*7}}, ${7*7}) and Host header injection. Disable if your reverse-proxy chain sends unusual Host formats. |
| `WAF_GRAPHQL_ENABLED` | toggle | On | 1.8.9 — GraphQL protection: blocks introspection, batch abuse, and queries exceeding depth limits. Disable on dev environments that intentionally expose introspection. |
| `WAF_UPLOAD_ENABLED` | toggle | On | 1.8.9 — File upload validation: blocks dangerous extensions (.php, .jsp, .exe, .sh) and dangerous magic bytes (ELF, PE, PHP). Disable if your app must accept arbitrary binary uploads validated elsewhere. |
| `WAF_SLOWLORIS_ENABLED` | toggle | On | 1.8.9 — Slowloris / slow-body guard: when body upload exceeds BODY_TIMEOUT the request is risk-scored and returned a silent decoy. Disable to return a plain 408 without risk-scoring (no stealth, no ban accumulation). |
| `BODY_GROUP_SQLI_ENABLED` | toggle | On | Body-pattern group: SQL injection (UNION SELECT, OR 1=1, etc.). Fires body-sqli (+40 risk). |
| `BODY_GROUP_XSS_ENABLED` | toggle | On | Body-pattern group: cross-site-scripting (<script>, javascript:, on*=). Fires body-xss (+40 risk). |
| `BODY_GROUP_LFI_ENABLED` | toggle | On | Body-pattern group: local-file-inclusion / path traversal. Fires body-lfi (+40 risk). |
| `BODY_GROUP_RCE_ENABLED` | toggle | On | Body-pattern group: remote-code-execution incl. Log4Shell. Fires body-rce (+50 risk → ban). |
| `BODY_GROUP_SSRF_ENABLED` | toggle | On | Body-pattern group: server-side-request-forgery (loopback / IMDS / gopher). Fires body-ssrf (+40 risk). |
| `BODY_GROUP_CMD_ENABLED` | toggle | On | Body-pattern group: OS-command-injection (; cat / `whoami` / $()). Fires body-cmd (+50 risk → ban). |

## Authentication & Request Integrity  (11)

_Request-authenticity enforcement: JWT validation on selected paths (issuer/audience), mandatory-header enforcement, Host-header allow-listing, a custom-rule engine, and upstream auth-failure tracking that raises risk on repeated 401/403s._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `JWT_VALIDATION_ENABLED` | toggle | On | 1.8.9 — JWT Authorization header validation on paths in JWT_VALIDATE_PATHS. Fires only when JWT_VALIDATE_PATHS is configured. Disable during JWT key rotation or token debugging. |
| `REQUIRED_HEADERS_ENABLED` | toggle | On | 1.8.9 — REQUIRED_HEADERS enforcement: blocks requests missing operator-configured mandatory headers. Only fires when REQUIRED_HEADERS is configured. Disable to bypass without clearing the list. |
| `HOST_BLOCKING_ENABLED` | toggle | On | 1.8.9 — Host header enforcement against ALLOWED_HOSTS. Only fires when ALLOWED_HOSTS is configured. Disable to bypass host-based blocking without clearing the allowlist. |
| `UPSTREAM_AUTH_FAIL_ENABLED` | toggle | On | 1.8.9 — Upstream auth failure tracking: bumps risk when a session exceeds AUTH_FAIL_THRESHOLD upstream 401/403 responses. Disable during auth system debugging to suppress false positives. |
| `CUSTOM_RULES_ENABLED` | toggle | On | 1.8.9 — Custom rule engine: evaluates CUSTOM_RULES JSON against every request. Disable to pause all custom rules without clearing them — useful for incident debugging. |
| `CUSTOM_RULES` | list | [] | Custom IF/THEN JSON rules. [{"if":{"path":"/x","ip_cidr":"10.0/8"},"then":"allow"}]. Actions: allow\|block\|challenge\|tag\|authorized-robot. |
| `ENDPOINT_POLICIES` | list | [] | Per-endpoint policy + rate-limit JSON: [{"path":"/api/*","policy":"bypass","rps":5,"burst":10}]. |
| `STRICT_ORIGIN` | toggle | Off | On state-changing methods, require Origin to match ALLOWED_HOSTS. |
| `JWT_VALIDATE_PATHS` | list | [] | fnmatch globs requiring a valid HS256 JWT in Authorization: Bearer (verifies against JWT_HMAC_SECRET). |
| `JWT_REQUIRED_ISSUER` | text | — | Require the iss claim to equal this value (empty = no enforcement). |
| `JWT_REQUIRED_AUDIENCE` | text | — | Require the aud claim to contain this value (empty = no enforcement). |

## Ban Management & Escalation  (5)

_Detections feed a per-identity risk score; crossing the threshold bans the identity for a window sized to the strength of the proof — a soft hostile-signal ban, or a long really-ban for conclusive bot proof. Bans scope to cookie, IP or fingerprint._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `RISK_BAN_THRESHOLD` | number | 50 | Score that triggers a ban (1.4.7+). |
| `HOSTILE_BAN_SECS` | number | 86400 | Ban time — standard ban duration for hostile signals (default 86400 = 24 h). |
| `REALLY_BAN_SECS` | number | 2592000 | Really Ban — extended ban for definitive bot proof: canary-echo, honeypot, honeypot-silent (default 2592000 = 30 days). |
| `JA4_AUTODENY_THRESHOLD` | number | 3 | Distinct bans on a JA4 before auto-adding it to the deny list. |
| `FP_BAN_CHECK_ENABLED` | toggle | On | 1.8.9 — Fingerprint-based ban enforcement: blocks requests whose UA+IP-tier+JA4 hash is on the ban list. Disable to let fingerprint-banned clients through. CAUTION: disabling bypasses ban system for non-cookie-tracked clients. |

## JS Challenge, PoW & Turnstile  (11)

_Interstitial gates that demand proof the client runs JavaScript: a signed cookie gate, an Anubis-style proof-of-work (difficulty = leading hex zeros), and optional Turnstile. Challenges can bind to the client JA4 so a solved token can't be replayed._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `JS_CHALLENGE` | toggle | Off | Cookie gate engages on every non-static path; auto-mints on first qualifying GET (or via Turnstile when configured). |
| `ANUBIS_ENABLED` | toggle | Off | Anubis-mode (1.5.4) — strict PoW gate on every first request, even if JS_CHALLENGE=0. Raises difficulty by ANUBIS_DIFFICULTY_BOOST. |
| `ANUBIS_DIFFICULTY_BOOST` | number | 1 | Extra leading hex zeros required when Anubis-mode is on (1 ≈ 16× harder, 2 ≈ 256×). |
| `JS_CHAL_BIND_JA4` | toggle | On | Bind chal cookie to TLS handshake hash (when JA4 header injected). |
| `JS_CHAL_REQUIRE_JA4` | toggle | Off | Hard-require JA4 from a trusted peer at /antibot-appsec-gateway/challenge. |
| `JS_CHAL_STRICT_STATIC` | toggle | On | Refuse static-asset bypass on paths containing API hints (/api/, /v1/...). |
| `JS_CHAL_OPEN_PATHS` | list | [] | Path prefixes that bypass the cookie gate (SPA data layer, webhooks, S2S). |
| `TURNSTILE_RISK_THRESHOLD` | number | 0.0 | Risk score at or above which Turnstile CAPTCHA is presented (0 = auto = midpoint of orange band). Most users never see Turnstile; only suspected bots above this score do. |
| `JS_CHALLENGE_TTL` | number | 3600 | Seconds a solved JS challenge cookie remains valid before re-challenge. Default 3600 = 1 hour. |
| `POW_MIN_SOLVE_MS` | number | 200 | Minimum milliseconds the PoW solution must have taken (client-side). Solutions faster than this are rejected as pre-computed. Default 200. |
| `POW_CHAL_THRESHOLD` | number | 30.0 | Risk score at or above which the JS challenge page embeds a PoW puzzle (solved in a WebWorker alongside Turnstile). 0 = never embed PoW. Default 30 = embed on any soft-band identity. Raises bot solve cost without adding round-trips. |

## Honeypots, Labyrinths & Tarpits  (12)

_Active deception: trap paths and hidden form fields no human touches, fake credentials, and time-wasting mazes — labyrinth link-forests, redirect mazes and tarpits that feed slow, deep, jittered responses to clients already proven hostile._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `HONEY_CRED_ENABLED` | toggle | On | Credential honeypot: inject fake credentials into login forms; flag any client that submits them. Disable if the app already handles credential honeytraps server-side. |
| `LABYRINTH_ENABLED` | toggle | On | AI Labyrinth — banned/high-risk bots that crawl the tarpit path are trapped in an infinite maze of AI-generated plausible-looking pages linked with signed tokens. Each page is slow-streamed (LABYRINTH_SLOW_MS) to maximise crawler CPU/bandwidth burn. Toggle off to disable maze generation entirely. |
| `LABYRINTH_JITTER_ENABLED` | toggle | On | Tarpit timing jitter (1.6.10) — replaces the fixed LABYRINTH_SLOW_MS delay with a Gaussian-distributed random delay (200–3000 ms, σ=500 ms) per streamed chunk. A deterministic 600 ms cadence is trivially fingerprinted; jitter makes it indistinguishable from a slow upstream. |
| `REDIRECT_MAZE_ENABLED` | toggle | On | Redirect maze (1.7.3 P2) — DISTINCT from the AI Labyrinth. Identities already at risk ≥ REDIRECT_MAZE_THRESHOLD are bounced through REDIRECT_MAZE_DEPTH HMAC-signed 302 hops; a bot that races all hops in < REDIRECT_MAZE_MIN_MS fires the redirect-maze-bot signal. Detects bots by redirect *timing* (the Labyrinth traps link-following crawlers). Ships OFF — enabling reroutes suspected-bot traffic, so tune the threshold first. |
| `TARPIT_ENABLED` | toggle | Off | Tarpit mitigation — when an identity is in the soft-challenge band (SOFT_CHALLENGE_SCORE ≤ score < RISK_BAN_THRESHOLD), silent-decoy responses are delayed by TARPIT_DELAY_MS. Burns attacker iteration time without committing to a ban. |
| `TARPIT_DELAY_MS` | number | 1500 | Delay in ms before serving the silent decoy when tarpit fires. Default 1500. Per response — total time blow-up = delay × #soft-band hits. |
| `LABYRINTH_SLOW_MS` | number | 600 | Milliseconds to stream each labyrinth page chunk. Higher = more CPU/bandwidth burned per bot request. Default 600. Irrelevant when LABYRINTH_JITTER_ENABLED is on. |
| `LABYRINTH_MAX_DEPTH` | number | 5 | Maximum maze depth before looping back. Deeper = more total pages served per bot crawl session. |
| `LABYRINTH_LINKS_PER` | number | 3 | Signed links injected per labyrinth page. More links = faster branch explosion but larger pages. |
| `REDIRECT_MAZE_THRESHOLD` | number | 80.0 | Redirect maze (1.7.3 P2): risk score at/above which an identity is sent into the signed-302 redirect maze. Default 80 (high — only suspected bots). Requires REDIRECT_MAZE_ENABLED. |
| `REDIRECT_MAZE_DEPTH` | number | 3 | Redirect maze: number of signed 302 hops before landing on the real destination. Default 3. |
| `REDIRECT_MAZE_MIN_MS` | number | 800 | Redirect maze: if an identity completes all hops faster than this (ms total), it is flagged a bot (redirect-maze-bot). Humans add latency between redirects; bots race through. Default 800. |

## Upstream, Routing & Limits  (9)

_Proxy-side resilience and bounds: connect/read timeouts, a circuit breaker that trips on repeated upstream failure, request/response body caps, and the block-response mode that decides what a blocked client sees._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `UPSTREAM_MAX_BODY` | number | 2097152 | Max request body the gateway accepts and forwards to upstream (bytes). Default 2097152 (2 MiB). Keep WAF_BODY_SCAN_BYTES ≥ this value — raising body limit without raising the scan window re-opens a WAF bypass. |
| `UPSTREAM_MAX_RESP` | number | 8388608 | Max response body buffered from upstream (bytes). Default 8388608 (8 MiB). Responses exceeding this limit return 413 (Content Too Large) to the client. |
| `UPSTREAM_REWRITE_BASE` | text | — | Strip this base URL from response bodies and Location/Link headers, turning absolute upstream URLs into relative paths. Fixes CSP violations when the upstream embeds its own hostname. Per-vhost override supported. Hot-reloadable. |
| `BLOCK_RESPONSE_MODE` | choice | homepage | What blocked clients receive. "homepage" (default): upstream's / content — the block is invisible; the attacker sees a normal page load. "404": upstream's real 404 page — explicit rejection, status 404. API and admin paths always get a synthetic JSON 404 regardless of this setting. |
| `UPSTREAM_TIMEOUT_SECS` | number | 10 | Total upstream request timeout in seconds. When upstream is slow/flapping every user waits up to this value before getting the cached decoy. Default 10. Lower = faster fail when upstream degrades; circuit breaker (10 consecutive failures) takes over after that. |
| `UPSTREAM_CONNECT_TIMEOUT_SECS` | number | 3 | TCP connect timeout for upstream requests in seconds. Separate from the total request timeout. Default 3. |
| `CIRCUIT_FAIL_THRESHOLD` | number | 10 | Consecutive upstream failures that trip the circuit breaker open. Once open, requests bypass the upstream and serve the cached decoy for CIRCUIT_OPEN_SECS. Lower = trip faster on degraded upstream; higher = more tolerance for transient blips. Default 10. |
| `CIRCUIT_OPEN_SECS` | number | 30 | Seconds the circuit stays open after tripping. During this window requests skip upstream entirely (after CIRCUIT_HALF_OPEN_MAX probes) and return the cached decoy. Default 30. |
| `CIRCUIT_HALF_OPEN_MAX` | number | 3 | Number of probe requests allowed through while the circuit is open (to test if upstream has recovered). After this many, all requests bypass until CIRCUIT_OPEN_SECS expires. Default 3. |

## Security Response Headers  (11)

_Outbound HTTP hardening injected on responses: frame/MIME-sniffing protection, referrer policy, HSTS, Content-Security-Policy, COOP and CORP, plus a Server-header override that hides the real stack._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `INJECT_SECURITY_HEADERS` | toggle | On | Master toggle: inject edge security headers on every HTML response (proxied + gateway-own). Individual headers below are no-ops when this is OFF. |
| `SEC_SERVER_OVERRIDE` | text | AntiBot/WAF GW | Value for the Server: response header on every response. Hides the aiohttp/Python version. Empty = leave aiohttp default. |
| `SEC_X_FRAME_OPTIONS` | text | SAMEORIGIN | X-Frame-Options value injected when the upstream does not set it. Typical: SAMEORIGIN or DENY. Empty = skip. |
| `SEC_X_CONTENT_TYPE_OPTIONS` | text | nosniff | X-Content-Type-Options value. Standard value is nosniff (prevents MIME-sniffing attacks). Empty = skip. |
| `SEC_REFERRER_POLICY` | text | strict-origin-when-cross-origin | Referrer-Policy value. Default: strict-origin-when-cross-origin. Empty = skip. |
| `SEC_X_PERMITTED_XDP` | text | none | X-Permitted-Cross-Domain-Policies value. Blocks Flash/Acrobat cross-domain requests. Default: none. Empty = skip. |
| `SEC_PERMISSIONS_POLICY` | text | accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), m… | Permissions-Policy value controlling browser feature access (camera, mic, geolocation, etc.). Empty = skip. |
| `SEC_HSTS` | text | max-age=31536000; includeSubDomains | Strict-Transport-Security value. Only meaningful when the gateway is TLS-terminated. Default: max-age=31536000; includeSubDomains. Empty = skip. |
| `SEC_CSP` | text | upgrade-insecure-requests; frame-ancestors 'self' | Content-Security-Policy value injected when the upstream does not set one. Default is permissive (upgrade-insecure-requests; frame-ancestors self). Empty = skip. |
| `SEC_COOP` | text | same-origin | Cross-Origin-Opener-Policy value. Default: same-origin (isolates the browsing context). Empty = skip. |
| `SEC_CORP` | text | same-site | Cross-Origin-Resource-Policy value. Default: same-site. Empty = skip. |

## DLP & Secret Scanning  (10)

_Outbound data-loss prevention: response bodies are scanned for credit cards, AWS keys, JWTs, private keys, generic API keys and PII (email/SSN); matches can be redacted in flight, with a byte cap to bound cost._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `DLP_ENABLED` | toggle | Off | Outbound DLP — scan upstream response bodies for PII / API keys / JWTs / private keys leaving the gateway. Bounded by DLP_MAX_BYTES. |
| `DLP_REDACT` | toggle | Off | When DLP_ENABLED is on, replace matched bytes with [REDACTED-<group>] before forwarding. |
| `DLP_MAX_BYTES` | number | 262144 | Max bytes scanned per response (cost cap). Default 256 KiB. |
| `DLP_GROUP_CC_ENABLED` | toggle | On | DLP group: credit-card numbers (Luhn-validated to drop false positives). |
| `DLP_GROUP_AWS_ENABLED` | toggle | On | DLP group: AWS access-key IDs (AKIA* / ASIA*) and labelled aws_secret_access_key. |
| `DLP_GROUP_JWT_ENABLED` | toggle | On | DLP group: JWTs (eyJ…) leaking in upstream responses. |
| `DLP_GROUP_PRIVATE_KEY_ENABLED` | toggle | On | DLP group: PEM private keys (-----BEGIN ... PRIVATE KEY-----). |
| `DLP_GROUP_API_KEY_ENABLED` | toggle | On | DLP group: API-key shapes (Slack xoxb-, GitHub ghp_/gho_, OpenAI sk-, labelled high-entropy secrets). |
| `DLP_GROUP_PII_EMAIL_ENABLED` | toggle | Off | DLP group: email addresses (off by default — noisy on most upstreams). |
| `DLP_GROUP_PII_SSN_ENABLED` | toggle | On | DLP group: US SSNs (3-2-4 digit grouping). |

## Infrastructure, Scoring & Logging  (10)

_Operational plumbing and the scoring engine: storage backend (SQLite/Postgres), private-upstream and strict-vhost guards, risk-score weights and decay, SIEM/log format, and scheduled DB maintenance._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `DB_BACKEND` | choice | sqlite | Event-store backend. sqlite (default) is single-file zero-deps. postgres enables high-volume / multi-instance deployments backed by Postgres + Timescale (psycopg must be installed in the image). Switches instantly in-process — no restart needed. |
| `POSTGRES_DSN` | text | — | Postgres connection string (e.g. postgresql://user:pass@host/db). Only used when DB_BACKEND=postgres. Empty = sqlite enforced. |
| `ALLOW_PRIVATE_UPSTREAM` | toggle | Off | Allow upstream URLs that resolve to RFC-1918 / loopback addresses (e.g. host.docker.internal, 192.168.x.x). Disables the SSRF guard — only enable in trusted internal deployments. |
| `STRICT_VHOST` | toggle | On | Return 502 for any inbound Host not explicitly registered as a vhost. Prevents the global UPSTREAM from acting as a catch-all for unknown hostnames. |
| `ESCALATION_THRESHOLD` | number | 30.0 | Risk-score threshold above which 3rd-order expensive / external detectors run (AbuseIPDB / CrowdSec / MaxMind / body-pattern / DLP). 0 = run all on every request (legacy). |
| `SECOND_ORDER_THRESHOLD` | number | 15.0 | Risk-score threshold above which 2nd-order behavioral detectors run (ai-enumeration, ai-no-assets, locale-geo-mismatch, tls-fingerprint, ja4-required-missing). Default 15 = any single soft-tier hit activates them. 0 = always run (no gate). |
| `VACUUM_DAILY_AT` | text | 05:00 | Daily VACUUM schedule for the SQLite DB in HH:MM (24-h, container local time). Default "05:00" — runs every day at 5 AM. Empty string disables. Skipped (and slog'd) if a DB migration or a manual VACUUM is in flight at the scheduled time. No-op when DB_BACKEND != sqlite (Postgres has its own autovacuum daemon). |
| `SOFT_CHALLENGE_SCORE` | number | 4.0 | Risk score at or above which the JS challenge (cookie gate) is shown. Below this threshold, requests are allowed through. Default 4. |
| `LOG_LEVEL` | choice | info | Filter for stdout structured log emission. |
| `LOG_FORMAT` | choice | text | Log output format. text = human-readable (default); json = structured JSON lines for log aggregators (Loki, Splunk, etc.). |

## Additional Controls  (6)

_Bypass and operational tunables not grouped above._


| Control | Type | Default | What it does |
|---------|------|---------|--------------|
| `BYPASS_MODE` | toggle | Off | Emergency site-wide bypass: all detection and ban enforcement is skipped and every request is proxied unconditionally. Intended for incident response only — turn off as soon as possible. |
| `AUTHORIZED_BOT_UAS` | list | [{'name': 'UptimeRobot', 'ua': 'UptimeRobot', 'path': '/', 'ips': [], 'action… | Structured monitoring-bot pass-through rules. Each entry: UA substring + path (+ optional source IPs). Matched requests are recorded blue and passed through. |
| `BYPASS_PATHS` | list | [] | Paths that bypass ALL bot detection and are proxied directly. Use for static asset directories where bot signals are meaningless. Matching rules: entries ending with * are prefix/glob matches — "/blog/*" exempts /blog/ and everything under it (e.g. /blog/post, /blog/category/foo); entries without * are exact matches — "/blog/" exempts only that exact path and nothing below it. Examples: use "/static/*" to exempt a whole directory, use "/healthz" to exempt a single endpoint. All matched requests are exempt from all detectors, scoring, and rate limiting. |
| `WEBHOOK_EVENT_FILTER` | list | [] | CSV of reasons (fnmatch globs OK) the operator wants webhook calls for. Empty = every event fires the webhook. |
| `ROBOTS_MONITOR_ENABLED` | toggle | On | robots.txt compliance monitoring (1.6.10) — fires (+5 soft) when a declared AI-crawler UA (any ua-ai-* group) makes a request, since the gateway's robots.txt already says Disallow: / for all known AI bots. Serves as a robots.txt violation marker alongside the ua-ai-* block. Gateway robots.txt served at /robots.txt. |
| `ALLOW_BYPASS_SECS` | number | 300 | Grace window (seconds) granted to an identity when an operator clicks Allow / Unban. During this window heuristic detection is skipped so the identity can re-establish a session without being immediately re-banned. 0 = disable. Default 300 (5 min). |

---

**Total: 155 controls across 16 pipeline groups.**
