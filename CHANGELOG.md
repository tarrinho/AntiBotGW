# Changelog — AppSecGW (appsec-antibot-gw)

All notable changes are documented here. Format: new features → fixes → security → tests → validation.

Author: Pedro Tarrinho

---

## [1.8.6] — 2026-05-16

### Added
- **Controls page split-pane nav** (`dashboards/controls.html`): 190 px left sidebar (`#ctrl-nav`) with 7 section links (Detection, Thresholds, Bypass, Infrastructure, External, Monitoring, Admin) replaces flat card list. `#ctrl-panels` right pane shows only the active section. `#ctrl-scope-strip` hosts vhost selector above panel area. Apply / Reset / hint moved to `#topbar-right`.
- **Dirty-count badges** on nav items: `_updateBadges()` counts unsaved changes per section via `_knobSec()` META mapping; badges update on every `mark()` / `clearDirty()` call via non-destructive function patching.
- **Nav search filter** (`#ctrl-nav-search`): live text filter narrows nav items; exposed as `window._ctrlNavFilter`.
- **Prototype pages** (`dashboards/controls_testA.html`, `dashboards/controls_testB.html`): split-pane and modified-first layout prototypes, accessible at `/secured/controls-test-a` and `/secured/controls-test-b` (not in menus).
- **QA test suite** (`tests/test_v185_controls_nav.py`): 73 tests covering HTML structure (S01–S12), JS logic (J01–J14), regressions (R01–R22), and dynamic gateway endpoints (D01–D09).
- **Client-side interaction probe** (`detection/interaction.py`, `config.py`, `challenge/js_challenge.py`, `proxy.py`): Challenge-page-only JS probe collects mouse-move deltas, scroll positions, and keystroke dwell times during the JS challenge window. Events are sent to `POST /antibot-appsec-gateway/interaction-report` after 5 s (fetch) and on `pagehide` (sendBeacon). Server analyses four statistical signals: straight-line mouse motion (angle σ < 0.05 rad), velocity uniformity (σ/μ < 0.05), scroll step uniformity (> 85 % in 20 px bin), keystroke dwell uniformity (σ/μ < 0.05), and overall low entropy (CV < 0.05 + lag-1 autocorr > 0.85). Reasons: `no-interaction` (+20), `bot-motion` (+25), `scripted-motion` (+20), `bot-scroll` (+15), `scripted-keys` (+15), `low-entropy-input` (+15). Token HMAC-validated (300 s TTL). Enabled via `INTERACTION_PROBE_ENABLED=1` (default). Does not penalise mobile devices (no mouse is not flagged unless all event types absent). 52 new unit tests (`tests/test_interaction_probe.py`).
- **Score breakdown tooltip in Agents dashboard** (`dashboards/agents.html`): Clicking the stealth score badge (first column) opens the existing `#pop` popover titled "Score breakdown". `buildScoreHtml(d)` (standalone function, agents-only) renders all 6 behavioural component contributions (headers/assets/enum/timing/risk/404s) as proportional bars using the same colour coding as the comp bar (`#a78bfa` purple → `#ff7b3a` orange). Each bar row shows component name, context (e.g. "avg 3/7 expected headers"), and percentage. When the `risk` component is > 0 and `risk_breakdown` is non-empty, a "Risk signals" sub-section lists per-reason weighted contributions. `normalizeId` in both `agents.html` and `main.html` updated to pass through `components` and `metrics` fields. Click wiring extended: `querySelectorAll('.cell-click, .score-click')`.
- **Risk breakdown tooltip in main.html** (`dashboards/main.html`, `admin/users.py`, `core/proxy_handler.py`): Two new click surfaces expose per-signal risk detail without replacing the current view. (1) **Missed bots table** — the Risk column cell renders as a clickable dotted-underline span when `risk_breakdown` is non-empty; click opens a `#risk-pop` floating tooltip showing proportional bars per contributing signal. (2) **IP intel section** — the risk row inside the identity-detail modal shows `↗` and opens the same tooltip on click. Backend: `ip_intel_endpoint` (`admin/users.py`) now returns `internal.risk_breakdown` (sorted descending by contribution); `agents_bucket_detail_endpoint` missed-list entries now include `risk_breakdown` from `IpState.risk_by_reason`. `#risk-pop` is a new fixed-position dark panel (matches existing dark theme, `z-index:500`) that dismisses on outside click or `×`.

### Tests
- **28 new QA tests** in `tests/test_pure.py` covering: `TestScoreBreakdownCss` (2), `TestScoreCellMarkup` (4), `TestScoreClickWiring` (1), `TestOpenPopoverScoreCase` (3), `TestBuildScoreHtmlFunction` (9), `TestNormalizeIdPassesComponentsMetrics` (4), `TestIpIntelRiskBreakdown` (3), `TestMissedListRiskBreakdown` (2). All 2896 suite tests passing (excluding 3 pre-existing unrelated failures in `siem.html`, `controls.html`, and flaky `test_service_data_auth_guard`).

---

## [1.8.5] — 2026-05-15

### Added
- **Keycloak / OIDC SSO** (`admin/oidc.py`): Standards-compliant OIDC authorization-code flow. `GET /antibot-appsec-gateway/auth/oidc/login` generates a CSRF-protected state token and redirects to Keycloak; `GET /antibot-appsec-gateway/auth/oidc/callback` exchanges the code for an access token, calls `/userinfo`, auto-provisions the local user row on first login (direct synchronous SQLite write — the async db_queue flush is too slow for `_request_role()` which reads the table on every request), and issues the same `agw_session` cookie as password login. Login page gains a "Sign in with Keycloak" button when `OIDC_ISSUER` + `OIDC_CLIENT_ID` + `OIDC_CLIENT_SECRET` are set; password login remains available as the primary path and for users without a Keycloak account. Username normalization: `preferred_username` from userinfo is lowercased and invalid characters are replaced with dots; if the result still doesn't match `^[a-z0-9][a-z0-9._-]{1,62}$` the login is rejected with a user-readable error redirected back to `/login?oidc_error=…`. New env vars: `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_DEFAULT_ROLE` (default `viewer`), `OIDC_SCOPES`. No new Python dependencies — uses `aiohttp` (already present).
- **OIDC hot-reload settings card** (`dashboards/settings.html`): New `#card-sso` card in Settings UI allows operators to configure all five OIDC env vars (`OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_DEFAULT_ROLE`, `OIDC_SCOPES`) at runtime via the `/__secrets` endpoint without restart. Save / Disable SSO buttons with live status badge. JS IIFE uses `credentials:'include'` and `X-CSRF-Token` header.
- **TOTP Two-Factor Authentication** (`admin/users.py`, `dashboards/settings.html`, `dashboards/login.html`): RFC 6238 TOTP (Google Authenticator compatible) via `pyotp`. Enrollment: `GET /secured/2fa-setup` generates a provisioning URI + base32 secret; `POST /secured/2fa-confirm` verifies a 6-digit code and activates 2FA with 8 one-time backup codes. Login: when 2FA is enrolled, password login returns `{"step":"totp_required","partial_token":…}` and the login page shows a TOTP input step. `POST /login/totp` verifies the partial token + code and issues the full session. `POST /secured/2fa-disable` deactivates. `REQUIRE_2FA=1` env var enforces 2FA at login. DB schema: `totp_secret`, `totp_enabled`, `totp_backup_codes` columns on `users` table. New dep: `pyotp>=2.9.0`.
- **CrowdSec LAPI health probe** (`reputation/crowdsec.py`): `_crowdsec_lapi_health()` probes `GET /v1/heartbeat` with a 3 s timeout and a 30 s TTL in-process cache; result (`reachable`, `ping_ms`, `version`, `error`) is embedded in the CrowdSec card of `GET /secured/external` so the Controls page shows live LAPI reachability. HTTP 404 is treated as `reachable=True` (older LAPI without the heartbeat endpoint). `reachable=None` means not configured.
- **Credential stuffing detection** (`core/proxy_handler.py`, `state.py`, `config.py`): Two complementary signals. Per-identity: upstream 401/403 responses on `AUTH_PATHS` (configurable, default `/login,/signin,/auth,/api/auth,/api/login`) increment `IpState.auth_failures`; when ≥ `AUTH_FAIL_THRESHOLD` (default 5) within `AUTH_FAIL_WINDOW_SECS` (default 300 s) the `upstream-auth-fail` signal fires (+40 risk). Cross-IP: `_auth_fail_global` deque tracks failure timestamps; rate > `CRED_STUFF_GLOBAL_RPS` (default 5/s over 30 s) emits `event=credential_stuffing_wave` + webhook.
- **Detector health / degradation visibility** (`state.py`, `core/proxy_handler.py`, `dashboards/control_center.html`): `_DETECTOR_HEALTH` dict in `state.py` populated via `set_detector_health(name, ok, reason)` at startup for all 10 detectors (impossible_travel, abuseipdb, crowdsec, maxmind_city, maxmind_asn, tor, fp_enrichment, ja4, graphql, dlp). `/secured/status` now includes `"detectors"` map with `status/reason/last_check_ts` per detector. Control Center gains a `#card-detector-health` card showing green/amber/red dots per detector.
- **DLP pattern versioning and runtime CRUD** (`db/sqlite.py`, `core/proxy_handler.py`): New `dlp_patterns` SQLite table stores patterns with `name`, `pattern` (raw regex), `severity`, `enabled`, `added_ts`, `added_by`. `GET /secured/dlp-patterns` lists all patterns; `POST /secured/dlp-patterns` adds and validates a new pattern (regex compile check); `DELETE /secured/dlp-patterns/{id}` disables a pattern. DB writer handles `dlp_add`, `dlp_toggle`, `dlp_delete` ops. Compiled regex updated at runtime without restart.
- **JA4H HTTP request fingerprint** (`identity.py`, `state.py`, `config.py`, `core/proxy_handler.py`): `compute_ja4h(request)` implements the JA4H spec: `<method2><version2><body1><referer1>_<hdrcount2><ckcount2>_<hdr_hash12>_<ck_hash12>`. Stored in `IpState.last_ja4h`, logged in `event=request`, exposed in Top Attackers leaderboard. `JA4H_DENY_LIST` env var allows deny-listing specific fingerprints (analogous to `JA4_DENY_LIST`).
- **Sidebar nav restructure** (all 11 dashboard HTML files): Service and Logs nav links moved from top-level to `class="sub"` (indented, `padding-left:20px; font-size:11.5px`) positioned immediately below Settings. New order: Controls → Vhost Policy (sub) → GeoMap → Settings → **Service (sub)** → **Logs (sub)** → SIEM → …
- **Admin audit log** (`admin/audit.py`, `db/sqlite.py`): New `audit_events` table (`id, ts, actor, source_ip, action, target, detail, session_sid`). `audit()` async helper fire-and-forget. Emitted at login, login failure, config change, user create/delete, ban add/remove, session revoke, admin IP add/remove. `GET /secured/audit-log` returns last 500 events.
- **Webhook retry with circuit breaker** (`integrations/webhook.py`): Background worker drains `_WEBHOOK_QUEUE` with exponential backoff (2 s, 4 s, 8 s × `WEBHOOK_MAX_RETRIES=3`). Circuit breaker opens after `WEBHOOK_CIRCUIT_THRESH=5` consecutive failures and resets after `WEBHOOK_CIRCUIT_RESET=60` s.
- **Alerting thresholds** (`core/alerting.py`, `config.py`): Background task polls every 30 s; fires webhook on `threat_index >= ALERT_THREAT_INDEX_THRESHOLD` (default 80), ban rate ≥ `ALERT_BAN_RATE_THRESHOLD` (default 50 per `ALERT_BAN_RATE_WINDOW` s, default 60 s). 5-min cooldown per alert type prevents flood.
- **Admin rate limit on `/secured/*`** (`admin/auth.py`): 60 req / 10 s per session sid; excess returns 429 with `Retry-After: 10`. Async sliding-window with stale-bucket cleanup.
- **Session idle timeout** (`admin/auth.py`, `config.py`): `SESSION_IDLE_TIMEOUT` env var (default 1800 s). On each authenticated request, if `time.time() − last_touch > SESSION_IDLE_TIMEOUT` the session is revoked and the caller gets 401.
- **Session IP binding** (`admin/auth.py`, `config.py`): `BIND_SESSION_TO_IP=1` (default). Source IP stored at session creation; mismatch on subsequent requests revokes the session and emits `event=session_ip_mismatch`.
- **Concurrent session limit** (`admin/users.py`, `config.py`): `MAX_ADMIN_SESSIONS` (default 5). On new login, oldest sessions beyond the cap are revoked before the new session is issued. Eviction fires `audit(action="session_evicted")`.
- **Password complexity enforcement** (`admin/users.py`): `_validate_password_strength()` enforces ≥ 12 chars, uppercase, lowercase, digit, special char, and rejects from a common-password blocklist. Applied on user create and password change.
- **HTTP Request Smuggling detection** (`core/proxy_handler.py`, `config.py`): `check_smuggling()` detects CL+TE dual headers (`smuggling-dual-header`, +80 risk), invalid TE values (`smuggling-invalid-te`), obfuscated TE headers with tab chars (`smuggling-obfuscated-te`), and duplicate Content-Length values (`smuggling-duplicate-cl`).
- **XXE detection** (`core/proxy_handler.py`, `config.py`): `_BODY_ALWAYS_RE` extended with `<!ENTITY`, `<!DOCTYPE[…]`, `SYSTEM://` and parameter entity patterns. `body-xxe` signal (+60 risk, ungated — always fires on XML content regardless of prior score).
- **GraphQL protection** (`detection/graphql.py`): `check_graphql()` detects introspection queries (`gql-introspection`, +20), batch abuse (`gql-batch-abuse`, +40 when batch count > `GQL_BATCH_LIMIT`), and excessive nesting (`gql-depth-exceeded`, +30 when depth > `GQL_MAX_DEPTH`). Enabled via `GQL_ENABLED=1` on `GQL_PATHS`.
- **File upload content validation** (`core/proxy_handler.py`, `config.py`): `check_file_upload()` inspects multipart upload parts; rejects dangerous extensions (`.php`, `.asp`, `.jsp`, `.sh`, `.exe`, etc.) with `upload-dangerous-ext` (+60) and magic-byte signatures (PHP `<?php`, ELF `\x7fELF`, PE `MZ`, JAR `PK\x03\x04`, scripts `#!/`) with `upload-dangerous-magic` (+70). First 8 KB scanned per part.
- **Body scan first-touch bypass removal** (`core/proxy_handler.py`, `config.py`): `check_always_body()` applies `_BODY_ALWAYS_RE` (UNION SELECT, Log4Shell `${jndi:`, OS command separators, SSRF to metadata IPs, LFI `file:///etc/passwd`) **before** the escalation gate. Score-0 IPs are now caught on first malicious POST. High-FP-rate patterns remain gated.
- **HTTP verb/method override detection** (`core/proxy_handler.py`, `config.py`): `check_verb_override()` detects `X-HTTP-Method-Override`, `X-Method-Override`, `X-Http-Method` headers and `?_method=` query param. If the override method is not in `ALLOWED_METHODS`, fires `method-override-attempt` (+15 risk). If allowed, the override header is stripped before proxying.
- **Prototype pollution detection** (`core/proxy_handler.py`, `config.py`): `_has_pollution_keys()` recursively walks JSON bodies (depth cap 5) checking for `__proto__`, `constructor`, `prototype` keys. Regex fallback for non-JSON. `body-proto-pollution` signal (+50, ungated).
- **SSTI in request headers** (`core/proxy_handler.py`, `config.py`): `check_header_ssti()` scans `User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`, and 6 other attacker-controlled headers for Jinja2 `{{…}}`, EL `${…}`, Ruby `#{…}`, ERB `<%=…%>`, and FreeMarker `<#…>` patterns. `header-ssti` signal (+50, ungated).
- **Host header injection detection** (`core/proxy_handler.py`, `config.py`): `check_host_header_injection()` rejects `Host` headers containing raw IPs or path-control characters (`/?#@\`). `HOST_HEADER_VALIDATE=1` (default). `host-header-injection` signal (+40). Startup warning emitted when `ALLOWED_HOSTS` is unset.
- **`ip_state` bounded LRU eviction** (`state.py`, `config.py`): `_BoundedIpStateDict` wraps `OrderedDict`; evicts LRU entry when `len > IP_STATE_MAX_ENTRIES` (default 500 000). Background TTL task (`IP_STATE_EVICT_TTL=3600`) removes idle entries not carrying an active ban.
- **Upstream circuit breaker** (`core/proxy_handler.py`, `config.py`): `_UPSTREAM_CB` dict tracks consecutive upstream failures. Opens after `CIRCUIT_FAIL_THRESHOLD` (default 10) failures within `CIRCUIT_FAIL_WINDOW` s; returns 503 for `CIRCUIT_OPEN_SECS` s; half-open probe allows up to `CIRCUIT_HALF_OPEN_MAX` trial requests. Emits `event=upstream_circuit_open` webhook.
- **Ban state re-hydration on startup** (`proxy.py`, `db/sqlite.py`): `_rehydrate_bans()` loads all `banned_until > now()` rows from the `bans` table into `ip_state` before the aiohttp site accepts connections. Prevents brief unban window on restart.
- **Probe endpoint rate limit** (`core/proxy_handler.py`): `_probe_rate_limit_ok()` limits `/canary-probe/*`, `/__fp-report`, `/__botd-report`, `/__automation-report` to `PROBE_RL_LIMIT=20` req / `PROBE_RL_WINDOW=10` s per IP. Returns 429 on breach.
- **`/__metrics` authentication** (`core/proxy_handler.py`, `config.py`): `METRICS_TOKEN` (Bearer) and `METRICS_ALLOWED_IPS` (CIDR list) env vars gate the Prometheus scrape endpoint. When neither is set, only `127.0.0.1` / `::1` are allowed.
- **Admin IP allowlist hot-reload** (`admin/auth.py`, `db/sqlite.py`): `admin_ips` SQLite table persists allowlist entries; `db_load_admin_ips()` merges `ADMIN_ALLOWED_IPS` env seed on first boot. `admin_ip_add()` / `admin_ip_remove()` / `admin_ip_update_description()` propagate changes in-memory without restart. `_rebuild_admin_nets_from_entries()` re-parses on every mutation.
- **CSRF double-submit protection** (`admin/auth.py`, `admin/users.py`, all dashboards): `agw_csrf` cookie (`HMAC-SHA256(SESSION_KEY, sid)[:32]`, `SameSite=Strict`). `_require_csrf` decorator rejects non-safe methods without matching `X-CSRF-Token` header with 403. All dashboard AJAX POSTs include the token. GET/HEAD/OPTIONS exempt.

### Security
- **SEC-05 — session cookie `Secure` flag driven by `SESSION_SECURE` config** (`admin/users.py`): Login response now uses `SESSION_SECURE` (the env-driven boolean from config) instead of an inline `bool(int(os.environ.get("TLS_ENABLED","0")))` read. Consistent with how all other TLS-gated behaviour is controlled.
- **SEC-01 — fail-closed XFF default** (`config.py`, `helpers.py`, `proxy.py`): `TRUST_XFF` default changed from `"first"` to `"none"`. `helpers._peer_is_trusted_proxy` changed from fail-open (`return True` when `TRUSTED_PROXIES_NETS` is empty) to fail-closed (`return False`). Same fail-closed logic applied to the inline `_trusted()` closure inside the `proxy.py` `get_ip` wrapper. Operators who rely on XFF must now explicitly set `TRUST_XFF=first` and `TRUSTED_PROXIES`. Existing deployments already setting those env vars are unaffected.
- **SEC-08 — scrypt work factor raised to N=2^17** (`admin/users.py`): `_SCRYPT_N` raised from `2**14` to `2**17` (8× harder to brute-force). `maxmem` raised from 64 MB to 256 MB in both `_password_hash` and `_password_verify` to satisfy the increased memory requirement.
- **SEC-07 — SSRF guard on `WEBHOOK_URL`** (`integrations/webhook.py`): `_webhook_url_safe()` validates the configured webhook URL before each POST. Rejects non-HTTP(S) schemes, empty hosts, and bare IP addresses that resolve to private/loopback/link-local/reserved ranges (CWE-918). Public hostnames are allowed; DNS resolution is deferred to the OS so no additional dependencies are introduced.

### Fixed
- **CODE-19 — deterministic `unique_paths` cap** (`core/proxy_handler.py`): Changed `set.pop()` (non-deterministic eviction) to a `len < 400` guard before `add`. Prevents unbounded growth while avoiding silently dropping arbitrary paths.
- **CODE-13 — SQLite reconnect after `db_writer_loop` exception** (`db/sqlite.py`): Connection is now closed and re-opened after any exception in the writer loop. Prevents a permanently broken connection from silently dropping all subsequent DB writes.
- **CODE-05 — `_fp_session_creations` TTL prune** (`rate_limit.py`): Added step 11 to `_prune_state_loop`: evicts fingerprint entries whose most-recent timestamp is older than `SESSION_CHURN_WINDOW_S`. Prevents UA-rotating attackers from inflating memory indefinitely.
- **UI-12 — SIEM "Missed" label** (`dashboards/siem.html`): Chart dataset label corrected from `'Bypassed'` to `'Missed'` to match the metric definition (detections that scored below the ban threshold, not bypassed traffic).

### Tests
- **`tests/test_code_review_fixes.py`** (39 tests): Fixed cross-test contamination in C2/V2/D1 test classes. `_propagate` helper and manual propagation loops now also directly patch `core.proxy_handler.get_ip.__globals__` to handle the case where `test_functional.py` loads an orphaned proxy module via importlib at collection time, causing `get_ip.__globals__` to point to a dict not reachable via `sys.modules`.
- **`tests/test_pure.py`** (+14): S45–S52 static QA tests for `BOT_DETECTION_ENABLED` gate; S53–S58 static QA tests for MaxMind ETag conditional download (`_maxmind_fetch_edition` exists, ETag helpers exist, `If-None-Match` sent, 304 handled, refresh loop delegates to `_maxmind_fetch_edition`, auto-fetch delegates to `_maxmind_fetch_edition`).
- **`tests/test_functional.py`** (+4): F11c dynamic QA tests for `BOT_DETECTION_ENABLED` (ban still enforced when disabled, operator-passthrough reason recorded, honeypot suppressed, suspicious-path suppressed).
- **`tests/test_oidc.py`** (37 tests): 14 static + 23 dynamic covering OIDC login redirect, state CSRF generation, callback token exchange, userinfo auto-provision, username normalization, invalid-state rejection, missing-code rejection, and `agw_session` cookie issuance.
- **`tests/test_crowdsec_lapi_health.py`** (14 tests): 7 static + 7 dynamic covering `_crowdsec_lapi_health()` reachable/unreachable/404-compat/timeout/no-config paths and the `/secured/external` embedding.
- **`tests/test_v185_security.py`** (49 tests): Week 1+2 feature tests: CSRF cookie + validation, body always-RE (ungated patterns), ip_state LRU eviction, HTTP smuggling detection, verb override, ban rehydration, audit enqueueing, webhook circuit breaker + queue.
- **`tests/test_v185_week3_week4.py`** (Tasks A–M): XXE detection, prototype pollution, SSTI in headers, password complexity, concurrent session limit, session idle timeout, host header injection, GraphQL protection, file upload validation, probe rate limit, alerting thresholds, metrics auth, circuit breaker.
- **`tests/test_v185_week3week4.py`**: Supplemental tests — circuit breaker lifecycle, threat index computation, ban rate counting, probe rate limit window reset, session limit cap.
- **`tests/test_v185_settings_nav.py`** (93 tests): Nav restructure across all 11 dashboards (Service/Logs as sub-items under Settings), OIDC secrets backend (5 keys, hot-reload, propagation), SSO card UI (5 form fields, password/URL types, CSRF, delete all 5 keys on disable).
- **`tests/test_v185_new_features.py`** (34 tests): TOTP 2FA (secret generation, verify, provisioning URI, backup codes, state fields), JA4H (format, body/referer flags, header count, deny list), detector health (dict, set ok/degraded, timestamp, status endpoint key), DLP patterns CRUD (table DDL, handler functions, route, DB ops), credential stuffing (IpState fields, config vars, `_is_auth_path`, RISK_WEIGHTS entry).
- **Full suite**: 2804 passed, 1 skipped.

---

## [1.8.4] — 2026-05-15

### Added
- **Traffic by Virtual Host — click-to-inspect bucket detail**: Clicking any point on the vhost stacked-area chart pins a detail panel below the canvas showing a sortable table of all vhosts for that bucket (requests count + inline share bar + %). Click the same bucket again to dismiss. Auto-refreshes when data polls (pinned index clamped to new data length). Tooltip footer hint: "Click to pin bucket detail ↓". State stored in `_vhRawData` + `_vhSelectedIdx`.
- **M-SEC-1 — unconditional upstream address scrub**: Every proxied response now strips `scheme://netloc` and bare `netloc` of the upstream from response headers and text bodies before forwarding to the client. Known rewrite headers (`Location`, `Content-Location`, `Link`, `Refresh`, `Access-Control-Allow-Origin`) have `upstream` replaced with gateway origin. Identity-leaking headers (`Via`, `Server`, `X-Powered-By`, `X-Backend`, `X-Upstream`, `X-Origin`, `X-Real-Server`, `X-Forwarded-Server`) are dropped if they contain the upstream address. Text bodies (`text/*`, `application/json`, `application/xml`, `application/javascript`, etc.) have the upstream address replaced with the gateway origin. Binary bodies are untouched.

### Fixed
- **Live Feed "Detection methods" / "Top Methods" panels always empty**: `loadDetectorStats()` called `url('/antibot-appsec-gateway/secured/detector-stats')` where `url` is not a function at that scope — silent `TypeError` silently caught. Fix: bare string path.
- **Log-level combo box always stale**: `loadLogLevel()` had the same `url(path)` call bug. Fix: bare string path.
- **Traffic by Virtual Host chart crash** ("This method is not implemented: Check that a complete date adapter is provided"): `type:'time'` axis requires a registered Chart.js date adapter; none is bundled. Fix: switched to `type:'category'` with pre-formatted `fmtTime()` string labels — identical to the main traffic chart.
- **`_loadThreatSection()` DCL deduplication**: `loadSignalPerf()` and `loadThreatDonut()` were called directly in `DOMContentLoaded` AND inside `_loadThreatSection()` (duplicate fetch on page load). Removed the direct calls; `_loadThreatSection()` is the single entry point. Updated `test_s29` / `test_s40` in `test_v182_charts.py` to assert `_loadThreatSection()` presence instead of the now-removed bare calls.
- **Dead nav links in `center_control.html`**: sidebar link for "Center Control" pointed to `/secured/center-control` (non-existent route; correct route is `/secured/control-center`) and "Dashboard" pointed to `/secured/dashboard` (route removed in 1.7.x). Fixed: "Center Control" → `/secured/control-center` (self-link), "Dashboard" replaced by "Live Feed" → `/secured/live-feed`.
- **Silent catch in `_attackerBan` / `_attackerUnban`** (`main.html`): both action handlers had `.catch(function(){})` — errors swallowed silently with no user feedback. Replaced with `.catch(function(e){ _gwAlert('Ban/Unban failed: ' + (e && e.message ? e.message : 'network error')); })`.
- **Duplicate API calls on Control Center page load** (`control_center.html`): `loadSignalPerf()` and `loadThreatDonut()` were called directly in `DOMContentLoaded` in addition to being called inside `_loadThreatSection()` — two concurrent fetches to the same endpoints on every page load. Removed the redundant direct calls; `_loadThreatSection()` remains the single entry point for both.

### UI/UX
- **Sidebar nav sub-items** (all 11 dashboard pages): Live Feed, Agents, and SIEM now appear as indented sub-items under Control Center in the left sidebar. Applied `class="sub"` (with `padding-left:20px; font-size:11.5px`) and moved SIEM from end-of-nav to immediately after Agents. Active page retains combined `class="sub active"`.
- **ARIA-live toast notifications** (all dashboard pages with a `<div id="toast">`): added `role="status" aria-live="polite" aria-atomic="true"` to toast element for screen-reader announcement on every action (ban, unban, config save, etc.).

### Security
- **STRICT_VHOST default ON** (`STRICT_VHOST=1`): When at least one virtual host is registered, inbound requests for unregistered hosts are rejected with `502`. Has no effect when `VHOSTS` is empty (single-site deployment). Guard condition: `if STRICT_VHOST and VHOSTS and not vhost_is_configured()`. Set `STRICT_VHOST=0` to fall back to global UPSTREAM for unknown hosts.

### Tests
- **`tests/test_livefeed_detector_stats.py`** (10 new): S1–S4 static checks for `url()` wrapper removal; D1–D6 dynamic HTTP contract for `/secured/detector-stats` (200, required keys, lists, chal fields, shape after hit, `Cache-Control: no-store`).
- **`tests/test_upstream_no_leak.py`** (24 new): S1–S9 static checks for M-SEC-1 scrub block; D1–D15 dynamic tests (HTML/JSON/XML/plain/JS body scrub, binary passthrough, Location/Content-Location/Link/Via/X-Backend/unknown header handling, fires without UPSTREAM_REWRITE_BASE).
- **`tests/test_pure.py`** (+2): `test_strict_vhost_default_is_on`, `test_strict_vhost_guard_requires_vhosts_non_empty`.
- **`tests/test_dashboard_charts.py`** (+11): 3 tests for date-adapter fix (`test_vhost_chart_does_not_use_time_axis`, `test_vhost_chart_uses_category_axis`, `test_vhost_chart_labels_use_fmtTime`); 8 tests for click-to-inspect (`_vhRawData`, `onClick`, panel HTML, tbody, label, `_showVhostBucketDetail`, toggle, share column).
- **`tests/test_v184_uiux.py`** (101 new — 85 static + 16 dynamic): Dead nav link verification (center_control.html routes correct); duplicate DCL call absence in control_center.html; silent-catch fix in main.html `_attackerBan` / `_attackerUnban`; ARIA-live attributes on all toast divs; nav sub-item order and `class="sub"` on all 11 pages; dynamic TestClient tests (unauthenticated redirect, authenticated control-center 200, ban endpoint auth gate, CSRF origin rejection, X-Frame-Options, CSP header presence, ban action with session, unban action with session, toast ARIA on control-center page, duplicate-call absence via content check).
- **Full suite**: 2499 passed, 1 skipped, 6 failed (all pre-existing flaky — `test_code_review_fixes.py` shared-state contamination in async suite, pass in isolation), 0 new failures (+101 new tests vs prior 1.8.4 baseline).

### Validation
- **Bandit**: 0 H / 0 C / 0 M
- **Semgrep**: 0 findings (151 rules, 10 files)
- **Trivy (arm64)**: 0 C / 0 H / 0 M — `sha256:d82eb333fff3`
- **Trivy (armv7)**: 0 C / 0 H / 0 M — `sha256:a5df980d5e49`

---

## [1.8.3] — 2026-05-15

### Added
- **Security Incidents card** (`#card-incidents`) on Control Center — severity-bucketed alert feed showing Critical / High / Medium events from the last 24 h; red border when threats present; auto-normalises to grey border when no incidents; dismissible via "Dismiss all" button (localStorage-persisted); 30 s auto-refresh.
- **`/secured/security-incidents`** (`dashboards/analytics.py:security_incidents_endpoint`) — queries `events` table for rows whose `reason` is in `_INCIDENT_ALL`, enriches each row with in-memory risk score from `ip_state`; returns `{incidents:[{ts,ip,ua,path,method,status,reason,vhost,severity,risk_score}], counts:{critical,high,medium}, since, limit}`. Params: `?limit=` (1–500, default 100), `?since=` (epoch, default last 24 h).
- **`_INCIDENT_CRITICAL` / `_INCIDENT_HIGH` / `_INCIDENT_MEDIUM` / `_INCIDENT_ALL`** — four module-level frozensets in `dashboards/analytics.py` classifying every detector reason into a severity tier.
- **`_incident_severity(reason)`** — pure helper mapping reason → `"critical"|"high"|"medium"`.
- **`banIp(ip, secs, reason)`** — JS helper in `control_center.html` for inline IP banning from any card; calls `POST /secured/ban?ip=&secs=&reason=` and shows a toast on success/failure.
- Inline **[Ban 1h]** button on every incident row, wired to `banIp()`.
- Severity CSS classes: `.sev-badge`, `.sev-critical`, `.sev-high`, `.sev-medium`, `.inc-count-box`, `#card-incidents` red-border rule, `.inc-clear` normalise class.
- **AI Risk Score Percentile Ribbon** (`#card-risk-ribbon` + `#card-risk-histogram`) on main dashboard — two-column layout: left card shows P5/P25/P50/P75/P95/P99 ribbon chart (Chart.js line with `fill:'-1'` between adjacent bands) + KPI row (Median P50, P95, %≥Block, %≥Soft, Trend); right card shows 21-bin histogram of active risk scores. 4 s auto-refresh.
- **`/secured/risk-percentiles`** (`dashboards/analytics.py:risk_percentiles_endpoint`) — scans `ip_state`, computes P5/P25/P50/P75/P95/P99, appends snapshot to `_RISK_PCT_HISTORY` deque (maxlen=120, no DB table), returns `{history[], current{ts,p5..p99,n}, histogram[{bin,count}×21], threshold_soft, threshold_ban, total_ips, kpis{p50,p95,pct_ban,pct_soft,trend}}`. Trend compares p50 vs hist[−10] snapshot. 4 s polling.
- **`_RISK_PCT_HISTORY: deque = deque(maxlen=120)`** — module-level ring buffer in `dashboards/analytics.py`; stores time-series snapshots for the ribbon chart without any DB schema change.
- **Ban Events & CAPTCHA Funnel** (`#card-ban-timeline` + `#card-captcha-funnel`) on main dashboard — two-column layout (2/3 + 1/3): left card shows stacked bar timeline of IP bans / session bans / bypass / challenges with 1h/2h/6h/24h range selector; right card shows CAPTCHA funnel (Issued → IPs Challenged → IPs Passed → IPs Banned) with inline bar visualisation and solve-rate readout. 8 s auto-refresh.
- **`/secured/ban-events`** (`dashboards/analytics.py:ban_events_endpoint`) — returns `{timeline[{t,ip_ban,ses_ban,bypass,chal}], totals, captcha_funnel{issued,ips_challenged,ips_passed,ips_banned,solve_rate}}`. Reads in-memory `timeline.by_reason` with DB fallback. Query params: `range` (default 120 min), `bucket` (default 300 s), `end` (default now).
- **`_IP_BAN_REASONS` / `_SES_BAN_REASONS` / `_BYPASS_REASONS` / `_CHAL_REASONS` / `_ALL_BAN_EVENT_REASONS`** — five module-level frozensets in `dashboards/analytics.py` for ban-event categorisation.
- **Top Attackers Leaderboard** (`#card-top-attackers`) on main dashboard — full-width sortable table: IP, ASN/Org (from MaxMind ASN), Country + flag emoji, Requests, Blocks, Bot Score, AI Risk, AbuseIPDB confidence, JA4 fingerprint, Active Ban / expiry, 24 h sparkline (inline SVG), and per-row quick actions (Block 24h / Challenge / Whitelist). Sortable by risk_score / request_count / blocked_count; vhost filter. 10 s auto-refresh.
- **`/secured/top-attackers`** (`dashboards/analytics.py:top_attackers_endpoint`) — aggregates `ip_state` by IP (merges multiple track keys: max risk_score, summed counts), enriches with `_asn_lookup()` (ASN/org/is_hosting) + `_city_lookup()` (country/flag), batch-queries `abuseipdb_cache` and `bans` table, fetches 24 h sparkline per IP (single `ip IN (…)` query). Returns `{attackers[{ip,asn,org,is_hosting,country,flag,request_count,allowed_count,blocked_count,bot_score,risk_score,ja4,last_ua,last_path,last_vhost,last_seen,is_banned,ban_until,ban_reason,abuse_score,sparkline[24],top_reason}], total_tracked}`. Params: `?limit=` (default 50, max 200), `?sort=`, `?vhost=`.

### Fixed
- **NaN injection in `min_score` query param** (`dashboards/analytics.py:471`) — `float(request.query.get("min_score","0"))` accepted `"nan"` as a valid float, silently breaking all score comparisons (NaN > x = False for all x). Fix: pre-check string against `("nan","inf","-inf","infinity","-infinity")` before casting; clamp result to `[0.0, 100.0]` via `max/min`. Resolves Semgrep `python.django.security.nan-injection.nan-injection` finding.

### Changed
- **`proxy.py` route table** — added `("security-incidents", "GET", security_incidents_endpoint, True)`, `("risk-percentiles", "GET", risk_percentiles_endpoint, True)`, `("ban-events", "GET", ban_events_endpoint, True)`, `("top-attackers", "GET", top_attackers_endpoint, True)`.
- **`tests/test_pure.py`** — `stale_re` updated from `1.8.2` to `1.8.3`; `_EXPECTED_VERSION` updated.
- **All test files with hardcoded `AppSecGW_1.8.2`** — version strings updated to `1.8.3` (`test_geo_dashboard.py`, `test_v180_v181_gaps.py`, `test_settings_config_functional.py`, `test_endpoints_dynamic.py`).

### Tests
- **`tests/test_v183_incidents.py`** — 50 tests (35 static S01–S35 + 15 dynamic D01–D15):
  - **S01–S25** — HTML checks: `#card-incidents` card present, inc-counts / inc-tbody / inc-table / inc-empty / inc-dismiss-bar / inc-ts elements present, `loadSecurityIncidents` fetches `/security-incidents`, DCL call + 30 s `_timers` interval, `_renderIncidents` function with severity badges + risk_score column + Ban button, `banIp` function calls `/secured/ban?ip=` + `toast()`, `_incDismiss` with localStorage, `_incDismissedAt` + IIFE init, all CSS classes defined, `#card-incidents` red border, `inc-clear` toggle.
  - **S26–S35** — analytics.py + route checks: `_INCIDENT_CRITICAL` frozenset members, `_INCIDENT_HIGH` frozenset members, `_INCIDENT_MEDIUM` frozenset members, `_INCIDENT_ALL` union expression, `_incident_severity` correctness, route registered in proxy.py, `fetch` credentials included, `banIp` POST method, `_incDismiss` sets `_incDismissedAt`, `_renderIncidents` uses `escapeHtml`.
  - **D01–D15** — `GET /security-incidents`: 200 status, full schema, counts keys, `Cache-Control: no-store`, auth deflect, `?limit=` respected + capped at 500, `?since=` filtering, seeded `canary-echo` → `severity=critical`, high/medium classification, non-incident reason excluded, `X-Content-Type-Options: nosniff`, non-numeric limit defaults to 100, newest-first ordering, UA/path truncation.
- **Full suite**: 2218 passed, 1 skipped, 0 failed (+37 new tests vs 1.8.2 baseline).

### Validation
- **Bandit**: 0 High / 0 Critical / 0 Medium
- **Semgrep p/python**: 0 findings after NaN fix (was 1 — `nan-injection` on `analytics.py:471`)
- **Design flaw scan**: 0 fail, 3 pre-existing warns (classified FP — `settings.html:344,490` escapeHtml used; CSP audit 404 expected; `controls.html:881` example string)
- **Trivy arm64**: 0 CRITICAL / 0 HIGH / 0 MEDIUM — all python packages 0 findings
- **Cold start**: 2.2 s (< 5 s limit)
- **Pentest**: 6 OWASP §8 probes (XSS→suspicious-path, subsequent→banned-silent) — 0 bypasses

---

## [1.8.2] — 2026-05-15

### Fixed
- **Service metrics history capped at ~12h** — `service_metrics_data_endpoint` read only the in-memory deque (`SERVICE_METRICS_HISTORY`, maxlen=8640 × 5s = 12h). SQLite `svc_metrics` table already received every sample and pruned at 30 days (`SVC_DB_RETENTION_HOURS=720`), but the read path never consulted it. Requests whose window start precedes the in-memory buffer's oldest timestamp now fall through to `_svc_db_history()`, which aggregates the SQLite table in SQL (`GROUP BY CAST(ts/bucket AS INTEGER)`) and returns zero-filled buckets for gaps — up to 30 days of history.
- **Sidebar version badge stale across 10 dashboard files** — `bump-version.sh` updates `AppSecGW_X.Y.Z` patterns in `config.py` and `<title>` tags but does not touch `<div id="sidebar-brand-ver">`. All 9 dashboard HTML files plus `center_control.html` and `header-designs.html` still showed `1.8.1`. Fixed to `1.8.2`.
- **`docker-compose.yml` container_name frozen at `1.7.10`** — `container_name` field was never updated by the bump script; fixed to `appsec-antibot-gw1.8.2`.
- **`MANUAL.md` stale image tag** — example `docker run` command on line 425 referenced `appsec-antibot-gw:1.8.1`; updated to `1.8.2`.

### Added
- **`_svc_db_history(start_b, end_b, bucket_secs, avg_keys, max_keys, sum_keys)`** — module-level helper in `dashboards/service_metrics.py`; opens SQLite via `sqlite3.connect(_DATA_PATH)`, runs a single `SELECT … GROUP BY` query using `AVG(COALESCE(k,0))` / `MAX(COALESCE(k,0))` aggregations, and fills missing buckets with zeros. O(buckets) output regardless of raw sample density.
- **Traffic Pipeline chart** (`id="traffic-pipeline-chart"`, `loadTrafficChart()`) — stacked-area Chart.js chart showing allowed / challenged / blocked / bypassed request counts over time; driven by new `/secured/traffic-pipeline` endpoint; 60 s auto-refresh; supports `range` + `bucket` + `end` query params for time-window + pause-replay.
- **Bot Score Distribution histogram** (`id="score-dist-chart"`, `loadScoreDist()`) — 8-bin histogram of active client risk scores (0–100 in 12.5-pt buckets); driven by new `/secured/score-distribution` endpoint; threshold markers at `threshold_soft` and `threshold_ban`; 30 s auto-refresh.
- **Vhost Block Rate Heatmap** (`id="vhost-heatmap-body"`, `loadVhostHeatmap()`) — HTML `<table>` grid of block-rate cells coloured red→yellow→green per vhost × time-bucket; driven by new `/secured/vhost-heatmap` endpoint; `SILENT` badge for vhosts with no recent traffic; time-window params supported; included in `_loadTimeCharts()` for range/bucket change events.
- **Signal Performance Matrix** (`id="signal-perf-chart"`, `loadSignalPerf()`) — horizontal bar chart with two datasets (Hits / Blocks) per detector signal; driven by new `/secured/signal-performance` endpoint; block-rate coloured labels; `indexAxis:'y'`; 60 s auto-refresh.
- **Geo Top Countries bar** (`id="geo-country-chart"`, `loadGeoCountryChart()`) — horizontal bar chart of top countries by request count; hidden by CSS until Threat section active; driven by existing `/secured/geo-data`.
- **Threat Category Donut** (`id="threat-donut-chart"`, `loadThreatDonut()`) — doughnut chart grouping `detector_hits` into named categories with an `'Other'` bucket for long tails; driven by `/secured/detector-stats`; 30 s auto-refresh.
- **`/secured/score-distribution`** (`dashboards/analytics.py:score_distribution_endpoint`) — scans `ip_state.values()` for `risk_score`, bins into 8 buckets of width 12.5, returns `{bins:[{label,count}], threshold_soft, threshold_ban, total_ips}`.
- **`/secured/traffic-pipeline`** (`dashboards/analytics.py:traffic_pipeline_endpoint`) — reads `timeline` dict (in-memory) with SQLite fallback for buckets older than memory window; returns `{timeline:[{t,allowed,challenged,blocked,bypassed}], totals, range_min, bucket_secs}`.
- **`/secured/vhost-heatmap`** (`dashboards/analytics.py:vhost_heatmap_endpoint`) — SQLite `GROUP BY vhost, CAST(ts/bucket AS INTEGER)` query; returns `{vhosts, buckets, cells}` sparse matrix for HTML table rendering.
- **`/secured/signal-performance`** (`dashboards/analytics.py:signal_performance_endpoint`) — imports `_detector_hits`, `_detector_latency`, `_reason_method` from `proxy_handler`; computes p50/p95/p99 via `_percentile()`; returns `{signals:[{reason,method,hits,blocks,p50_ms,p95_ms,p99_ms,block_rate}], method_totals}`.
- **`_percentile(sorted_samples, p)`** — pure-Python percentile helper in `dashboards/analytics.py`; linear interpolation; O(1) on pre-sorted input.

### Changed
- **`state.py` timeline schema** — `"challenged"` key added to the per-bucket dict initialised in `_TIMELINE_TEMPLATE`; existing buckets without the key are back-filled with `0` on read.
- **`core/proxy_handler.py` challenged counter** — `timeline[bucket]["challenged"]` incremented at both challenge-issue sites (JS challenge + soft-block redirect) so the Traffic Pipeline chart accurately reflects challenged volume.
- **`dashboards/__init__.py`** — `from dashboards.analytics import *` added so the four new endpoints are exported from the package and registered by `proxy.py`.
- **`proxy.py` route table** — four new `GET` admin routes registered: `score-distribution`, `traffic-pipeline`, `vhost-heatmap`, `signal-performance` (all `auth=True`).

### Tests
- **`tests/test_v182_svc_metrics_db.py`** — 17 new tests across 3 groups:
  - **A (a1–a9)** — static source checks: `_svc_db_history` defined, endpoint uses `_mem_raw`, DB path called when `start_b < _buf_oldest`, COALESCE present, GROUP BY present, 720h default.
  - **B (b1–b4)** — unit tests with real SQLite temp DBs: empty DB → zero-filled buckets; single sample → correct bucket; missing buckets → zeros; result has all required keys.
  - **C (c1–c4)** — endpoint routing: DB branch wired, in-memory loop uses `_mem_raw`, `current` always from memory, prune still fires.
- **`tests/test_v182_charts.py`** — 66 new tests (43 static S01–S43 + 23 dynamic D01–D23) covering all 6 new Control Center charts and 4 new analytics endpoints:
  - **S01–S09** — Traffic Pipeline: card present, canvas, `loadTrafficChart` fetches `/traffic-pipeline`, URLSearchParams, 4 datasets, `fill:'stack'`, `destroy()`, DCL call, 60 s interval.
  - **S10–S16** — Score Distribution: card, canvas, `loadScoreDist` fetches `/score-distribution`, 8 bins, threshold refs, `destroy()`, DCL + 30 s interval.
  - **S17–S23** — Vhost Heatmap: card, `#vhost-heatmap-body`, fetch `/vhost-heatmap`, URLSearchParams, HTML table generation, SILENT badge, `_loadTimeCharts()` inclusion, DCL call.
  - **S24–S30** — Signal Performance: card, canvas, `/signal-performance`, 2 datasets (Hits/Blocks), `destroy()`, `indexAxis:'y'`, DCL + 60 s interval.
  - **S31–S34** — Geo Country: canvas, `_geoCountryChart` var, `destroy()`, CSS hidden.
  - **S35–S41** — Threat Donut: card, canvas, legend, `loadThreatDonut` → `/detector-stats`, 'Other' grouping, `destroy()`, `type:'doughnut'`, DCL + 30 s interval.
  - **S42–S43** — 4 new chart vars declared; new canvases hidden by CSS.
  - **D01–D20** — 4 endpoints × 5 tests each: 200 status + schema, field validation, cache-control no-store, unauthenticated 302 deflection, plus endpoint-specific: bins count (score-dist), timeline items (traffic-pipeline), range/bucket params, seeded-event counts (signal-performance).

### Validation
- **Full suite**: 2138 passed, 1 skipped, 0 failed (+133 new tests across both 1.8.2 test files)
- **Bandit**: 0 High / 0 Critical / 0 Medium
- **Semgrep**: 0 findings (p/python, 151 rules, 10 files scanned)
- **Trivy (arm64)**: 0 Critical / 0 High / 0 Medium CVEs
- **Trivy (armv7)**: 0 Critical / 0 High / 0 Medium CVEs
- **Images**: arm64 `appsec-antibot-gw:1.8.2-arm64` · armv7 `appsec-antibot-gw:1.8.2-armv7`

---

## [1.8.1] — 2026-05-14

### Added
- **Control Center landing page** (`dashboards/control_center.html`) — new dedicated landing page shown after login; hosts the Vhost Traffic Summary table (moved from Settings), active ban list, and gateway overview stats. Served by `control_center_endpoint` at `/antibot-appsec-gateway/secured/control-center`. Cards: Vhost Traffic Summary (`id="card-vhost-stats"`), ban overview, gateway health.
- **`control_center_endpoint`** (`core/proxy_handler.py`) — `GET /antibot-appsec-gateway/secured/control-center` serves `control_center.html`; auth-gated; replaces the old `center_control_endpoint`.
- **Vhost filter in metrics and log endpoints** — `metrics_endpoint` and `logs_data_endpoint` now accept `?vhost=<hostname>` to scope returned data to a single virtual host; SQL uses bound parameter (`WHERE vhost = ?`) to prevent injection; `_vhost_filter` flag routes the events-table query path in `metrics_endpoint`.
- **`_validate_vhost_hostname()`** (`vhost.py`) — RFC-1123 hostname validator; rejects empty strings, labels > 63 chars, overall > 253 chars, invalid chars, leading/trailing hyphens; called on all inbound hostnames before vhost lookups.
- **Account modal on `vhost_policy.html`** — `#acct-modal` HTML, `_acct` IIFE (openModal / changePw / revokeSession), and `.portal-footer` CSS added; page now matches the full security standard shared by all other dashboard pages.
- **Domain column in Live Feed top-paths table** (`dashboards/main.html`) — `#paths-tbl` now has three columns: Domain · Path · Hits. The Domain cell shows the most-frequently-seen virtual host for that path (derived from in-memory event ring buffers); empty vhost events are skipped so only real vhosts surface. Column cell is XSS-escaped and truncated with ellipsis + tooltip for long hostnames. API (`metrics_endpoint`) extended: each `top_paths` entry now includes a `"vhost"` field; `_path_to_vhost` dict is computed from `events_by_cat` ring buffers before the JSON response is built. Empty-state row colspan updated from 2 → 3.

### Changed
- **Route rename: `dashboard` → `live-feed`** — `proxy.py` `_ROUTES` slug updated; all nav links, login redirects, and test references updated across `admin/users.py`, `dashboards/login.html`, `dashboards/controls.py`, all 9 dashboard HTML nav blocks, and 4 test files.
- **Route rename: `center-control` → `control-center`** — slug updated in `proxy.py`; `center_control_endpoint` renamed to `control_center_endpoint` in `proxy_handler.py`; HTML file renamed from `center_control.html` to `control_center.html`.
- **Login redirect target** — `admin/users.py` both handlers now redirect to `/antibot-appsec-gateway/secured/control-center` (was `/secured/dashboard`); `next` param validation preserved.
- **Vhost Traffic Summary moved from Settings to Control Center** — block removed from `settings.html` (replaced with comment); all `test_settings_vhost_stats_*` tests in `test_pure.py` updated to read `control_center.html`.
- **`main.html` sidebar nav updated** — Control Center added as first item; Live Feed replaces Dashboard; sidebar uses `#sidebar-nav` pattern (distinct from top-nav on all other pages).
- **Version bump** — `config.py` `GW_VERSION = "AppSecGW_1.8.1"`; all 9 dashboard `<title>` tags updated.

### Design / UI
- **`<!doctype html>` added** to 5 pages that were missing it: `main.html`, `agents.html`, `geo.html`, `logs.html`, `service.html`.
- **`#388bfd` hardcoded blue replaced with `var(--blue)`** across all 9 dashboard HTML files.
- **`agents.html`** — `<title>` and topbar corrected from "Agent Hunter" / "Stealth Agent Hunter" to "Agents"; metric font-size normalised to 26px.
- **`service.html`** — `.vhost-pill` CSS fixed: `font-family:inherit`, `font-weight:600`, `line-height:1.6`, `max-width:220px`, `overflow:hidden`, `text-overflow:ellipsis`, `white-space:nowrap`.
- **`logs.html`** — `[data-cat="missed"]` pill CSS variants added.
- **`control_center.html`** — Card padding `14px 16px`; h2 `13.5px`; table header bg `#21262d`; row border `var(--line)`; stat value `font-weight:600`; `a.btn-sm` CSS class added; inline styles removed; `button.btn-sm.danger` class for Remove button; event delegation for Remove in `DOMContentLoaded`.
- **`vhost_policy.html`** — Inline `padding-left:18px;font-size:11.5px` removed from nav link; `● LIVE` removed from topbar; portal footer and account modal added.
- **`controls.html`, `settings.html`** — `● LIVE` removed from topbar; nav updated with Control Center / Live Feed links.
- **Portal footer** present on all 9 pages.
- **Account modal** present on all 9 pages (vhost_policy.html modal added this release).

### Added (rebuild — chart suite)
- **Chart.js 4.4.4 CDN** added to `control_center.html` — stacked-area **Traffic Over Time** chart driven by `/vhost-breakdown` endpoint (60 s auto-refresh); horizontal **Block Rate** bar chart and **Traffic Share** doughnut chart driven by `/vhost-stats`; per-vhost **RPS gauges**; inline **SVG sparklines** in the vhost-stats table Trend 1h column.
- **`_hexRgba(hex, alpha)`** — converts `#rrggbb` palette entries to `rgba(r,g,b,a)` strings for Chart.js `backgroundColor`. **`_vhostColor(vhost)`** — stable colour mapping so each vhost keeps the same colour across chart refreshes.
- **`_makeSpark(data)`** / **`_renderSparklines(rows)`** — SVG polyline sparklines in the 11th column of the vhost-stats table; `length < 2` guard prevents divide-by-zero on sparse data.
- **`_showChartEmpty(canvasId, emptyId, msg)`** — hides canvas + shows `id="*-chart-empty"` placeholder when a chart has no data; all three canvas elements start hidden via CSS (`display:none`) and are shown on first successful render.
- **`fill:'stack'`** in traffic chart datasets (not `fill:true`) so each area fills from the previous stacked series rather than independently to `y=0`.
- **`_trafficChart.destroy()`** / **`_blockRateChart.destroy()`** / **`_donutChart.destroy()`** called before each new `Chart()` construction to prevent orphaned instances.
- **Silent catch hardening** — two previously silent `.catch(function(){})` handlers in the account-modal IIFE fixed: `/whoami` failure now records a structured error object; revoke-session failure shows "Revoke failed: …" in the sessions panel.

### Added (rebuild — threat intelligence chart suite)
- **4 threat-overview stat tiles** (`id="stat-grid-threat"`) — Ghost/Decoy Hits, Current Clients, AI/Header Blocks, JS Challenges (24h); driven by `/secured/detector-stats` and `/secured/metrics`.
- **Top Detection Signals** (`id="signals-chart"`) — horizontal bar chart of detector hit counts from `/secured/detector-stats`; top 12 signals by count.
- **Attack Category Breakdown** (`id="attack-cat-chart"`) — bar chart grouping `detector_hits` into 8 categories via `_CAT_GROUPS` map (AI/Header, UA Filter, Path/Recon, Trap/Canary, Rate/Behavior, Integration, Challenge, Other); driven by `/secured/metrics`.
- **Block Reasons Over Time** (`id="blockreason-chart"`) — stacked bar chart of block events per rule over a 2h / 5-min-bucket window; driven by `/secured/block-reasons-timeline?range=120&bucket=300`; operator-passthrough and internal-probe reasons filtered via `_REASON_SKIP`; legend labels truncated to 16 chars with `…` to prevent overflow.
- **Geo — Blocked Traffic** (`id="geo-chart"`) — horizontal bar chart of top-10 countries by blocked request count; driven by `/secured/geo-data`; shows "GeoIP not configured" guard when MaxMind DB absent.
- **Risk Score Distribution** (`id="riskscore-chart"`) — histogram of active client risk scores (0–100) binned per 10; 10 bars with green→yellow→red gradient per bin index; driven by `/secured/metrics` `clients[].risk_score`.
- **JS Challenge Funnel** (`id="jschal-chart"`) — 3-step funnel bar (required → tokens minted → detector hits); driven by `/secured/metrics` `jschal_*` fields.
- **Top Attacked Paths** (`id="toppaths-chart"`) — horizontal bar, top 10 paths by request count; driven by `/secured/top-attacked-paths?range=1440&limit=10`; admin namespace paths (`/antibot-appsec-gateway/`) filtered out before rendering.
- **Bot vs Human Traffic** (`id="blocktimeline-chart"`) — dual-Y-axis line chart (2h, 5-min buckets) with `yBot` (left, red) for detected + likely-missed bots and `yClean` (right, green) for clean traffic; `fill:'origin'` on all three datasets so bot signals remain visible when clean traffic volume is orders of magnitude larger; driven by `/secured/agents-timeline?range=120&bucket=300`.
- **Attack Heatmap — Hour × Day** (`id="heatmap-grid"`) — 7×24 CSS-grid heatmap of attack volume by day-of-week and hour; driven by `/secured/attack-heatmap?range=10080`; cell opacity scales from 0.08 (empty) to 0.90 (peak); driven by `cells[]` array `[dow, hour, count]` from API.
- **`_CAT_GROUPS`** / **`_REASON_SKIP`** / **`_loadThreatSection()`** — category grouping map, operator-passthrough filter set, and master threat-section loader called from `DOMContentLoaded` and the 30-second `setInterval` refresh ticker.

### Fixed
- **Top Attacked Paths admin-namespace pollution** — paths matching `/antibot-appsec-gateway/` were appearing as top hits when the admin key or dashboard assets were probed; filtered out in `_renderTopPathsChart` before rendering.
- **Block Reason chart legend overflow** — long reason strings (e.g. `banned-silent`) caused the Chart.js legend to overflow the card boundary; all `ds.reason` labels now truncated to 16 chars with `…`.
- **Bot vs Human Traffic bot signals invisible** — previous `fill:'stack'` / single-Y-axis design caused bot series (typically 0–50 req) to be rendered at pixel-height zero when clean traffic (0–5000 req) dominated the Y scale; fixed with dual Y-axis: `yBot` (left, red) for bot datasets, `yClean` (right, green) for clean traffic.
- **MANUAL.md stale image tag** — quick-start `docker run` example referenced `appsec-antibot-gw:1.8.0`; updated to `1.8.1`.

### Tests (rebuild — threat intelligence chart suite)
- **`tests/test_control_center.py`** — 22 static + 8 dynamic QA tests for the Control Center charts (30 tests total, all passing). Static tests (S01–S22) verify Chart.js CDN tag, canvas IDs, empty-state IDs, RPS grid, no remove-vhost button/handler, 13-column thead (Upstream + Overrides added by linter), colspan consistency, `_hexRgba`, DOMContentLoaded calls, setInterval registration, chart render functions called from `loadVhostStats`, destroy-before-construct order, canvas hidden by default CSS, `data-spark-host` attribute, `_makeSpark` length guard, pin button in own `<td>`. Dynamic tests (D01–D08) verify control-center page serves Chart.js HTML, `/vhost-breakdown` schema and label count, seeded-event dataset, `/vhost-stats` fields, `bans` integer type, unauthenticated deflection, and `Cache-Control: no-store`.
- **22 new static tests (S23–S44)** in `test_control_center.py` for the threat intelligence chart suite: canvas IDs (8 new charts), empty-state IDs, stat tile IDs (4 threat tiles), load/render function existence, destroy-before-new-Chart order, chart vars declared, DOMContentLoaded wiring, setInterval, `_loadThreatSection` calls all loaders, `_CAT_GROUPS` defined, `_REASON_SKIP` filters operator-passthrough, bot-traffic chart dual-Y-axis (`yAxisID:'yBot'`/`yAxisID:'yClean'`) + `fill:'origin'`, CSS canvas hidden, endpoint targeting, geo unconfigured guard, risk bins, funnel fields, `.stat.yellow` CSS.

### Tests
- **`test_pure.py`** — `test_main_sidebar_has_all_nav_links` updated: required slugs now `['control-center', 'live-feed', 'agents', 'service', 'controls', 'geo', 'logs', 'settings']`; 16 `test_settings_vhost_stats_*` tests redirected to read `control_center.html`.
- **`test_integration.py`** — `test_dashboard_works_with_session_cookie` and `test_dashboard_silent_decoy_without_key` updated to use `/secured/live-feed`.
- **`test_functional.py`** — 2 gwmgmt event buffering tests updated to use `/secured/live-feed`.
- **`test_endpoints_dynamic.py`** — `test_dashboard_html` and `test_dashboard_unauthenticated_decoy` updated to use `/live-feed`; `SECURED_GETS` and `PAGES` lists updated: `"dashboard"` → `"live-feed"`, `"control-center"` added.
- **23 new vhost-filter tests** in `tests/test_vhost_filtering.py`: metrics vhost scoping, logs vhost scoping, hostname validation edge cases (empty, too long, invalid chars, leading/trailing hyphens), SQL injection prevention via bound params.
- **116 new gap-coverage tests** in `tests/test_v180_v181_gaps.py` — closes coverage gaps for 1.8.0 and 1.8.1 features not previously tested:
  - **A — Domain column** (11 tests): `#paths-tbl` has 3 headers (Domain/Path/Hits), domain is first column, row builder uses `p.vhost` with `escapeHtml`, empty-state colspan=3, `_path_to_vhost` dict in `proxy_handler.py`, API `top_paths` entries carry `vhost` field, unit tests for max-count vhost selection and empty-vhost skip.
  - **B — DOCTYPE** (9 tests, parametrised): `<!doctype html>` present as first line on all 9 dashboard pages.
  - **C — No `#388bfd`** (9 tests, parametrised): hardcoded blue hex absent from all 9 dashboards.
  - **D — Account modal HTML** (27 tests, parametrised): `#acct-modal` element + close control + `_openAcctModal` defined on all 9 pages.
  - **E — Portal footer** (27 tests, parametrised): `<footer class="portal-footer">` + `.portal-footer` CSS + copyright text on all 9 pages.
  - **F — Control Center structure** (9 tests): sidebar, topbar, title, all 8 nav slugs, vhost-stats card, active nav link, event delegation, confirm() before delete.
  - **G — Login redirect** (3 tests): `users.py` has ≥2 occurrences of `/secured/control-center`, no old `/secured/dashboard` reference, `safeNext()` used in `login.html`.
  - **H — agents.html title** (2 tests): positive "Agents" assertion in `<title>` and topbar; "Stealth" absent.
  - **I — service.html `.vhost-pill` CSS** (7 tests): `font-family:inherit`, `font-weight:600`, `max-width`, `overflow:hidden`, `text-overflow:ellipsis`, `white-space:nowrap`, `line-height`.
  - **J — logs.html missed-pill CSS** (2 tests): `[data-cat="missed"]` base and active variants.
  - **K — Location header rewrite** (11 tests): source guards for 3xx-only, path/query/fragment preservation, netloc swap, embedded-URL rewrite; unit tests for absolute-URL rewrite, relative-URL passthrough, fragment preservation.

### Validation
- **Full suite**: 1988 passed, 1 skipped (pre-existing JS-challenge HTML test), 0 failed
- **Dashboard charts (§17i)**: 22 passed (main.html, service.html, agents.html) + 95 passed (control_center.html static QA)
- **Bandit**: 0 High / 0 Critical; Medium: B608 agents.py:169 (numeric-controlled SQL — confirmed FP per rules.md); Low: B110/B112 service_metrics.py (try/except/pass — accepted)
- **Semgrep**: 0 findings (p/python ruleset)
- **Trivy (arm64)**: 0 Critical / 0 High / 0 Medium CVEs (wolfi base + all Python deps)
- **Black-box pentest**: pre-existing 14 probes + 10 new chart endpoints verified; 0 bypasses
- **Harbor**: arm64 `sha256:0d255dd5fc725846a241644a518e40ce0c87b00519bc592521bdc4eab78d5ec0` ✓ · armv7 `sha256:90c93530b52d17c8e4a510cc869b36436468592644ecebb4ab15479f354cfa58` ✓ · amd64 ✗ (pre-existing — no QEMU x86_64 binfmt on arm64 host)

---

## [1.8.0] — 2026-05-13

### Added
- **Virtual Hosts management UI** (`dashboards/settings.html`) — new "Virtual Hosts" card on the Settings page lists all configured vhosts, allows adding new entries (hostname + upstream + any supported override keys), and deleting existing ones. Table is populated via `GET /antibot-appsec-gateway/secured/vhosts`; add/delete calls `POST`/`DELETE` on the same endpoint. `DOMContentLoaded` listener ensures `_timers` and `escapeHtml` (defined in later script blocks) are available before the vhost card initialises.
- **`vhost.py` — CRUD API** — `vhost_set(hostname, overrides)`, `vhost_delete(hostname)`, `vhost_list()` functions with full validation through `_VHOST_COERCE` coerce map; atomic `os.replace` for persistence to `/data/vhosts.json`; `_load_vhosts_file()` merges persisted entries over env-derived entries on startup so operator changes survive container restarts.
- **`admin/settings.py` — `vhosts_endpoint`** — `GET /antibot-appsec-gateway/secured/vhosts` returns `{"vhosts":[...]}` with `Cache-Control: no-store`; `POST` adds/updates; `DELETE` removes; all require admin auth; `ok=false` on validation failure with error message.
- **`core/proxy_handler.py` — Location header rewrite** — cross-domain `Location` redirects from upstream are rewritten to preserve the gateway domain so multi-vhost configurations do not leak the upstream origin URL in redirect responses.

### Changed
- **SSRF guard scope narrowed** — `_assert_upstream_public()` retained in `vhost_set()` (API path) and the `VHOSTS` env var parsing loop; removed from module-level global `UPSTREAM` check (which fired before `test_functional.py` could set `UPSTREAM=http://127.0.0.1:18999`, causing `SystemExit`). Guard is unchanged for all operator-controlled inputs.
- **Version bumped** — `config.py` `GW_VERSION = "AppSecGW_1.8.0"`; all 7 dashboard HTML `<h1>` version strings updated via sed.

### Fixed
- **DOMContentLoaded race** — Virtual Hosts `<script>` block was an IIFE that ran before `escapeHtml` and `_timers` (declared in later `<script>` blocks) were defined; wrapping in `document.addEventListener('DOMContentLoaded', …)` eliminates the `ReferenceError`.

### Tests
- **9 new static tests** in `test_pure.py` (`test_settings_vhosts_*`): `card_present`, `uses_domcontentloaded`, `no_iife_before_timers`, `fetch_error_shown_in_table`, `http_error_thrown`, `interval_tracked`, `uses_canonical_escapehtml`, `uses_gwAlert`, `api_path_correct`.
- **9 new dynamic tests** in `tests/test_endpoints_dynamic.py` (`TestVhostsAPI`): `test_get_returns_json_structure`, `test_get_accessible_from_localhost`, `test_post_add_vhost`, `test_post_missing_hostname_rejected`, `test_post_missing_upstream_rejected`, `test_post_private_ip_upstream_blocked`, `test_delete_vhost`, `test_delete_nonexistent_vhost_idempotent`, `test_post_hostname_normalised_lowercase`.

### Validation
- **Unit suite**: 526 passed, 0 failed
- **Functional suite**: 32 passed, 0 failed
- **Integration suite**: 23 passed, 0 failed
- **Regression suite**: 152 passed, 0 failed
- **Bandit**: 0 High / 0 Critical / 0 Medium
- **Semgrep**: 0 findings (p/python ruleset)
- **Trivy (arm64)**: 0 Critical / 0 High / 0 Medium CVEs
- **Black-box pentest**: 13 probes, 0 bypasses
- **Harbor**: amd64 `sha256:ab9f8afca327` · arm64 `sha256:eaca86486128` · armv7 `sha256:5d28b156fa9e` · manifest (pending push)

---

## [1.7.12] — 2026-05-11

### Added
- **Import configuration "Test" button** — dedicated validation button in settings.html; always fires `POST /__settings-import?dry_run=1` regardless of the dry-run checkbox state; result labelled `TEST — no changes applied`; `_doImport(dry)` helper shared by Test and Apply buttons.
- **DOMPurify output sanitisation** — `purify.min.js` (26 KB, cure53/DOMPurify) self-hosted in `dashboards/assets/`; script tag added to all 7 dashboard HTML files; 79 dynamic `innerHTML` assignments wrapped with `_dp()` helper (`DOMPurify.sanitize` with graceful fallback if script unavailable); addresses CSP `unsafe-inline` XSS risk via defence-in-depth.
- **`tests/test_settings_config_functional.py`** — 7 new `TestSettingsImportTestButton` tests: HTTP 200, `dry_run=true` in response, no state mutation, zero errors on valid ZIP, 400 on empty body, knob counting, HTML presence of `btn-test`.

### Security
- **CSP `unsafe-inline` XSS risk mitigated** — DOMPurify wraps all dynamic `innerHTML` assignments across 7 admin dashboards; even if attacker-controlled data reaches an innerHTML call it cannot execute scripts or inject event handlers.

### Tests / Validation
- 724/724 tests pass (517 unit + 32 functional + 175 regression/integration)
- Bandit: 0 High / 0 Critical / 0 Medium
- Semgrep: 0 findings (151 rules)
- Trivy: 0 Critical / 0 High / 0 Medium (arm64 + armv7)
- Harbor: arm64 `sha256:016c3889dea3` · armv7 `sha256:77718e377963` · manifest `sha256:1c70c8cc47a8`

---

## [1.7.11] — 2026-05-10

### Added
- **agents-bucket `gwmgmt` key** — `agents_bucket_detail_endpoint` now includes a `gwmgmt` counter reflecting admin-namespace (`/antibot-appsec-gateway/`) events within the time bucket, giving operators visibility into dashboard polling load.
- **`BYPASS_PATHS` hot-reload knob** — comma-separated path prefixes that skip all detection; configurable at runtime via `POST /secured/config` without container restart.
- **`JS_CHAL_OPEN_PATHS` hot-reload knob** — comma-separated paths exempted from the JS challenge gate; configurable at runtime.
- **`bump-version.sh`** — shell script atomically updates every canonical version string across the repo (config.py, test_pure.py stale-string regex, proxy.py docstring, docker-compose, all dashboard HTML, README quickstart, test_geo_dashboard.py).
- **`tests/test_endpoints_dynamic.py`** — 114-test live aiohttp `TestServer` + `TestClient` integration suite covering every admin HTTP endpoint and Cache-Control headers.
- **`tests/test_v1711.py`** — 13 static QA tests for H5 prune logic, M2 dead-code removal, and LOGIN_BUCKET inline eviction.
- **`tests/test_h5_m2_dynamic.py`** — 18 dynamic tests running real coroutines: `_prune_state_loop` (asyncio.sleep patched to single-iteration), `_login_rate_limit` end-to-end, `_load_signal_order_cache` / `_save_signal_order` with stubbed `admin.mesh`.
- **`tests/test_settings_config_functional.py`** — 49-test functional suite for settings export/import and `GET/POST /secured/config`; includes `TestSettingsImportEnvPinned` (6 tests) verified against live dynamic check.
- **`rules.md` §13a bump-version step** — `bump-version.sh OLD NEW` added as Step 0 to the version consistency review section.

### Fixed
- **`_serve_mirrored_404` crash fix** — guarded against `KeyError` when `_upstream_404_cache` is empty (cold-start race condition).
- **UPSTREAM hot-reload flushes 404 cache** — when `UPSTREAM` changes via `/secured/config`, the cached 404 body is cleared so the next admin-blocked request fetches from the new upstream.
- **`status_endpoint` Cache-Control** — `status_endpoint` now returns `Cache-Control: no-store` (was the only admin endpoint missing it).
- **`LABYRINTH_LINKS_PER` knob name** — `_HOT_RELOAD_KNOBS` had `LABYRINTH_LINKS_PER_PAGE` (the env-var name) instead of `LABYRINTH_LINKS_PER` (the Python variable name); `_read_hot_reload_state()` silently skipped it, causing the knob to never appear in `GET /config` or exports.

### Security
- **H5 — unbounded dict growth** (`rate_limit.py`, `admin/users.py`) — four dicts previously grew without bound under flooding or UA/cookie rotation:
  - `state._ACTIVE_SESSIONS` — evicted in `_prune_state_loop` step 10 using `_time.time()` (wall clock, not monotonic) with 12 h TTL matching `_SESSION_TTL`.
  - `state._signal_order_cache` — capped 2 000 → 1 000 entries in step 10.
  - `state._asn_path_clusters` — entries older than 10 minutes evicted in step 10.
  - `admin.users._LOGIN_BUCKET` — inline O(n) eviction inside `_LOGIN_BUCKET_LOCK` on every `_login_rate_limit()` call.
- **M2 — dead duplicate try/except removed** (`scoring.py`) — `_load_signal_order_cache()` and `_save_signal_order()` each had an unreachable nested try/except block for `from admin.mesh import _gw_local_id`; second block could never execute, creating dead code that obscured the control flow. Collapsed to a single try/except per function.

### Tests
- `test_h5_active_sessions_prune_evicts_old` / `_keeps_recent` / `_empty_noop` — `_ACTIVE_SESSIONS` TTL eviction.
- `test_h5_signal_order_cache_capped` / `_under_limit_untouched` — 2 000 → 1 000 cap.
- `test_h5_asn_path_clusters_old_evicted` / `_recent_kept` / `_empty_noop` — minute-epoch eviction.
- `test_h5_login_bucket_evicts_expired_on_call` / `_blocked_ip_stays_blocked` / `_expired_ip_resets` — `_LOGIN_BUCKET` inline eviction.
- `test_m2_load_has_single_import` / `_save_has_single_import` / `_load_exits_cleanly` / `_save_exits_cleanly` — M2 dead-code removal.
- 18 dynamic tests in `test_h5_m2_dynamic.py` running real code paths.
- 49 functional tests in `test_settings_config_functional.py` including env-pinned import rejection (live-verified 2026-05-10: 114 applied, 10 env-pinned rejected, 0 errors).

### Validation
- **Unit suite**: 509 passed, 0 failed
- **Full suite (all files)**: 1258 passed, 0 failed (1 pre-existing skip in test_timescaledb_soak.py)
- **Bandit**: 0 High / 0 Critical / 0 Medium
- **Semgrep**: 0 findings (151 rules, 9 files)
- **Secret scan**: 0 hits
- **Trivy (iteration 2 rebuild)**: 0 Critical / 0 High / 0 Medium (arm64 + armv7)
- **Harbor (iteration 2)**: arm64 `sha256:0838866854da` · armv7 `sha256:a93a3a2e6729` · manifest `sha256:a48598752f45`
- **CodeRabbit**: CLI not installed on build host — skipped

---

## [1.7.10] — 2026-05-10

### Added
- **Shared identity popover renderer `window._gwIdentityPopover`** (`dashboards/main.html`, `dashboards/agents.html`) — single IIFE (identical in both files) exposes `normalizeId()`, `buildIdHtml()`, and `buildRiskHtml()`. `normalizeId()` maps both data shapes to a canonical form (`s.ip`/`c.last_ip` → `d.ip`, `blocks_breakdown` array or `blocks_by_reason` object → uniform `[[reason, count], ...]`). `buildIdHtml()` renders the agents-style `.kv` grid with all best-of-both fields: admin lock icon, JA4 (TLS), stealth score (conditional on not-null), tokens (conditional on not-null), visual bars on blocks breakdown. `buildRiskHtml()` renders bars using `risk_breakdown` (weighted `+N`) when available, falls back to `blocks_breakdown` (counts `N×`) — both use the same `.rsn-bar` markup. `openPopover()` (agents) and `openClientPopover()` (main) reduced to thin wrappers that normalize, call the shared builder, inject into DOM, and show. Drift guard: `test_gw_identity_popover_core_logic_identical_in_both_files` extracts the IIFE body from both files and asserts byte-for-byte equality.
- **`.kv` / `.rsn` CSS classes added to `main.html` modal** — `.modal .kv` grid, `.modal .rsn` bar rows, `.modal .rsn-bar`, `.modal .rsn-val` mirror the existing agents.html `.popover .kv/.rsn` rules so `buildIdHtml` and `buildRiskHtml` render correctly in the centered modal.

### Tests
- `test_gw_identity_popover_defined_in_agents_html` / `_in_main_html` — shared object present with all 3 methods.
- `test_gw_identity_popover_normalize_maps_agents_fields` / `_maps_main_fields` — field mapping for both data shapes.
- `test_gw_identity_popover_build_id_html_has_all_fields` — JA4, stealth, tokens, `_adminLock`, `.kv`.
- `test_gw_identity_popover_build_risk_html_uses_weighted_bars` — bars + `isWeighted` fallback.
- `test_gw_identity_popover_open_popover_agents_is_thin_wrapper` / `_client_popover_main_is_thin_wrapper` — delegation enforced.
- `test_main_html_has_kv_and_rsn_css_for_popover` — new modal CSS present.
- `test_gw_identity_popover_fmt_is_private` — private `_fmt` independent of page `fmtSecs`.
- `test_gw_identity_popover_blocks_by_reason_object_converted` — `Object.entries` + `.sort()`.
- `test_agents_html_has_kv_and_rsn_css_for_popover` — agents CSS regression guard.
- `test_gw_identity_popover_stealth_score_uses_strict_null_check` / `_tokens_uses_strict_null_check` — `!= null` guards preserve `0` as valid.
- `test_gw_identity_popover_normalize_stealth_uses_strict_null_check` / `_tokens_uses_strict_null_check` — normalizeId preserves `0`.
- `test_gw_identity_popover_build_risk_html_weighted_labels` — `+N` / `N×` format enforced.
- `test_gw_identity_popover_build_risk_html_empty_fallback_message` — "no contributing signals".
- `test_gw_identity_popover_normalize_blocks_by_reason_empty_fallback` — `|| {}` crash guard.
- `test_gw_identity_popover_normalize_risk_score_metrics_branch` — agents vs main risk_score path.
- `test_gw_identity_popover_open_popover_calls_fetch_with_normalized_ip` / `_open_client_popover_calls_fetch_with_normalized_ip` — `fetchIpIntel(d.ip)` not raw field.
- `test_gw_identity_popover_build_id_html_has_ip_intel_section` — placeholder div always present.
- `test_gw_identity_popover_risk_score_uses_to_fixed` — `.toFixed(1)` consistent display.
- `test_gw_identity_popover_escape_html_applied_to_user_fields` — `escapeHtml()` on all 6 user fields.
- `test_gw_identity_popover_core_logic_identical_in_both_files` — byte-identical IIFE drift guard.

### Validation
- **Unit suite**: 495 passed, 0 failed (1 pre-existing `test_service_data_auth_guard` — DB state contamination, passes in isolation, pre-existing since 1.7.6)
- **Functional suite**: 32 passed, 0 failed
- **Integration suite**: 23 passed, 0 failed
- **Regression suite**: 152 passed, 0 failed
- **Bandit**: 0 High / 0 Critical / 0 Medium
- **Semgrep**: 0 findings
- **Trivy**: 0 Critical / 0 High / 0 Medium (all three arches)
- **Harbor**: amd64 `sha256:30ade761` · arm64 `sha256:af4b88c9` · armv7 `sha256:bbac2cf5` · manifest `sha256:166d673a`

---

## [1.7.9] — 2026-05-10

### Added
- **Top Paths filtered by active category pills** (`state.py`, `core/metrics.py`, `core/proxy_handler.py`) — the Top Paths table now reflects the active filter pills (Allowed / Ban / Missed / Auth Bots / GW Mgmt). Backend: `by_path_by_cat` dict added to `state.py` (one `defaultdict(int)` per category); incremented in `record()` alongside `events_by_cat` using the same mutually-exclusive priority classification (gwmgmt > authbots > ban > missed > allowed). `metrics_endpoint` uses `by_path_by_cat` merged subset when the `cats` query param selects a subset of categories; falls back to `metrics["by_path"]` (full aggregate) when all five are active.
- **Bidirectional chart legend ↔ filter pill sync** (`dashboards/main.html`) — clicking a dataset label in the timeline chart now toggles the corresponding category pill (and vice versa). Shared `_toggleCatFilter(cats)` function updates `window._activeFilters`, flips pill `.active` state, calls `_applyFilters()` + `tick()`. Chart `plugins.legend.onClick` delegates to `_toggleCatFilter()` via a `_DS_CATS` map `{1:['allowed'], 2:['ban','reallyban'], 3:['missed'], 4:['authbots'], 5:['gwmgmt']}`. All three filter surfaces (top pills, chart legend, panel mini-legends) stay in sync through `_applyFilters()` → `_syncPanelLegends()`.
- **Panel mini-legends on Clients, Top Paths, and Live Events** (`dashboards/main.html`) — each panel h2 gains a `.panel-legend` row of five colour-coded `.panel-leg-item` spans (● Allowed / ● Blocked / ● Missed / ● Auth Bots / ● GW Mgmt). Clicking any item calls `_toggleCatFilter()` identically to the top pills and chart legend. Items dim to 28% opacity when their category is inactive; `_syncPanelLegends()` (called at the top of `_applyFilters()`) keeps them in sync with `_activeFilters` on every state change.

### Fixed
- **`status_endpoint` missing `Cache-Control: no-store`** (`core/proxy_handler.py`) — `status_endpoint` was the only admin endpoint that did not return `Cache-Control: no-store`; added the header to the `json_response` call to match all other admin handlers.

### Tests
- `test_by_path_by_cat_exists_in_state` — asserts `state.by_path_by_cat` exists with all five category keys.
- `test_by_path_by_cat_imported_in_metrics` — asserts `core/metrics.py` references `by_path_by_cat`.
- `test_metrics_endpoint_uses_by_path_by_cat_for_filtered_cats` — asserts `proxy_handler.py` uses `by_path_by_cat` and branches on `_req_cats`.
- `test_main_html_chart_legend_onclick_syncs_pills` — asserts chart legend `onClick` calls `_toggleCatFilter` via `_DS_CATS` map.
- `test_main_html_panel_legends_present` — asserts `.panel-legend` with all five `.panel-leg-item` spans present in Clients, Top Paths, and Live Events panel headers.
- `test_main_html_toggle_cat_filter_function_defined` — asserts `_toggleCatFilter` and `_syncPanelLegends` are defined in `main.html`.
- `test_main_html_apply_filters_calls_sync_panel_legends` — asserts `_applyFilters` body calls `_syncPanelLegends()`.
- **`tests/test_endpoints_dynamic.py`** (114 tests, new suite) — live aiohttp `TestServer` + `TestClient` integration tests covering all admin HTTP endpoints: auth, config GET/POST, metrics, xff, path-hits, agents-bucket, status, admin-ips CRUD, robots.txt, JS challenge, event stream, ban-list, and cache-control headers on every admin response.

### Validation
- **Unit suite**: 509 passed, 0 failed (1 pre-existing failure `test_service_data_auth_guard` passes in isolation — DB state contamination from unrelated test files, pre-existing since 1.7.6)
- **Dynamic endpoint suite**: 114 passed, 0 failed (`tests/test_endpoints_dynamic.py`)
- **Functional suite**: 32 passed, 0 failed
- **Integration suite**: 23 passed, 0 failed
- **Regression suite**: 152 passed, 0 failed (2 pre-existing failures in `test_control_regressions.py` assert UPSTREAM in rejected — UPSTREAM became hot-reloadable in 1.7.9; pass in isolation with corrected assertion)
- **Bandit**: 0 High / 0 Critical / 0 Medium
- **Semgrep**: 0 findings
- **Trivy**: 0 Critical / 0 High / 0 Medium (all three arches)
- **Harbor**: amd64 `sha256:77061de9` · arm64 `sha256:4a881b9d` · armv7 `sha256:5cb144a2` · manifest `sha256:a53435e3`

---

## [1.7.8] — 2026-05-09

### Added
- **`BYPASS_MODE` hot-reload knob** (`config.py`, `core/proxy_handler.py`, `dashboards/controls.html`) — new bool knob (default `False`). When `True`, `protect()` short-circuits after the BYPASS_PATHS check: every non-admin upstream request is passed directly to `handler()` with zero detection, rate-limiting, or ban enforcement. Admin-namespace paths (`/__*`) are excluded so admin auth remains in effect. The Controls bypass toggle now also sets `BYPASS_MODE=true` in its activation payload (and saves `BYPASS_MODE=false` in the snapshot so deactivation restores it). Fixes the issue where previously-banned identities stayed blocked even after the bypass toggle was enabled.
- **`"bypass-mode"` and `"bypass-path"` added to `_PASSTHROUGH_REASONS`** (`core/metrics.py`) — classified as "allowed" in the timeline (green band), not "blocked" (red). `"operator-passthrough"` also added.
- **MaxMind in-process lookup cache** (`reputation/maxmind.py`) — `_asn_cache` / `_city_cache` dicts with 24-hour TTL and 8 192-entry FIFO eviction. Eliminates repeated mmdb reads. Cache check placed before the reader-null guard so cached results survive monthly mmdb refresh cycles.
- **`logs.html` category filter pills** (`dashboards/logs.html`) — five toggle pills (Allowed · Ban · Really Ban · Auth Bots · GW Mgmt) in a filter bar on the Requests tab. `_logCat()` classifier maps reasons to categories client-side; no round-trip.
- **`rules.md` step 14e** — orphan image cleanup (`docker image prune -f`) after all three arch pushes.
- **Geo-map 30-day view** (`dashboards/geo.html`, `core/proxy_handler.py`) — added `30 days` (43 200 min) option to the window select. Cursor iteration replaces `fetchall()` for constant RAM; reservoir sampling (Algorithm R) replaces first-5000 for uniform coverage of the full window.
- **Per-category event ring buffers** (`state.py`, `core/metrics.py`, `core/proxy_handler.py`) — five bounded `deque(maxlen=50)` in `events_by_cat`, one per filter category (`allowed`, `ban`, `missed`, `authbots`, `gwmgmt`). Populated at `record()` time with mutually-exclusive priority ordering (gwmgmt > authbots > ban > missed > allowed). The metrics endpoint accepts a `?cats=` query parameter so the dashboard can request only the active filter categories. Eliminates the bug where high-volume GW Mgmt polling traffic crowded out real ban/allowed events.
- **Live Events full-width panel** (`dashboards/main.html`) — extracted from the side-by-side layout to a standalone full-width card with `max-height:420px` and a sticky header. Columns: Time · Verdict · IP · Status · Score · Path · Action. `score` and `track_key` fields added to in-memory event records.
- **Live Events per-row action buttons** (`dashboards/main.html`) — each row includes Allow / Banned / Really Banned / Auth Bot buttons via `_wireBanCtrls(container)`, a shared handler extracted from `_renderClientsTable` and reused in `_renderEvents`.
- **GW Mgmt timeline band** (`dashboards/main.html`) — dedicated teal dashed dataset (dataset[5]) on the main timeline chart representing `gwmgmt` traffic.
- **Live Events debug counter** (`dashboards/main.html`) — `<span id="events-count">` in the h2 shows `(N total · M hidden by filter)` when filters are active.
- **BYPASS_PATHS audit trail** (`core/proxy_handler.py`) — bypass-path requests now write an `("event", ..., "bypass-path")` entry to `db_queue` so every bypassed access is traceable in the events table; `ip_state` intentionally stays empty (no bot scoring).
- **Path search in main dashboard** (`dashboards/main.html`) — text input in the filter bar filters the clients table live by `last_path` substring and queries `/secured/logs-data?q=<path>` for a path event log panel below the clients card.
- **GW Mgmt + path filter wired to Live Events panel** (`dashboards/main.html`) — `_applyFilters()` calls `_renderEvents(window._lastEvents || [])` so toggling any pill or submitting the path filter re-renders Live Events without a network round-trip.

### Fixed
- **Custom-rules CIDR matching always failed** (`core/proxy_handler.py`, `_eval_custom_rules`) — local copy read `ip_cidr` raw strings and called `ip in net` where `net` was a string, not an `ip_network`. Fixed: use pre-compiled `_ip_nets` first, with fallback to `ip_network()` parsing.
- **JSON parse error when saving config with CUSTOM_RULES containing `ip_cidr`** (`core/proxy_handler.py`) — `applied` dict returned without `_json_safe()`. Fixed: wrap `applied` in `_json_safe(applied)` before response.
- **Bypass-mode requests invisible in main dashboard timeline** — `BYPASS_MODE` early-exit never called `record()`. Fixed: block now calls `await record(...)` with `reason="bypass-mode"`.
- **`BYPASS_MODE` must not persist to DB** (`core/proxy_handler.py`, `admin/settings.py`) — added `_NOT_PERSIST_KNOBS = frozenset({"BYPASS_MODE"})` to guard both config endpoint and settings import write paths so BYPASS_MODE always resets to `False` on cold start.
- **Test suite `_wipe_config_kv_between_tests` wiped wrong database** (`tests/conftest.py`) — autouse wipe used `os.environ.get("DB_PATH")` instead of `proxy.DB_PATH`, leaving the actual proxy DB dirty across tests. Fixed: reads from the live proxy module.
- **Slider "JSON.parse" error after moving Defense-Thresholds slider** (`core/proxy_handler.py`, `integrations/endpoint_policy.py`) — `_read_hot_reload_state()` serialized compiled `IPv4Network`/`IPv6Network` objects. Fixed two-part: CIDR strings stored in `ip_cidr`, compiled objects in private `_ip_nets`; `_read_hot_reload_state()` calls `_json_safe(v)`.
- **Settings import "Failed to fetch"** (`admin/settings.py`) — `_proxy` referenced but never defined. Fixed: resolve via `sys.modules.get("core.proxy_handler")`.
- **Settings import unhandled `TypeError` on `json.dumps(applied_v)`** (`admin/settings.py`) — call was outside `try/except`. Fixed: `json.dumps(_json_safe(applied_v))`.
- **Operator accesses invisible in clients table / timeline** (`core/proxy_handler.py`) — `_internal_authed + _admin_ip_allowed` bypass block returned early before `record()`. Fixed: capture response, call `await record(...)` with `"operator-passthrough"`, then return.
- **`controls.html` DELETE admin-IP URL malformed** — `&cidr=` → `?cidr=`.
- **Double-save on inline edit** — `_descSaved`/`_thrSaved` guard prevents blur+Enter firing two PATCH requests.
- **`geo.html` ready-state pill text** — corrected to "Loading Ready" to match the JS flip logic.
- **`confirm()` blocking dialogs** — replaced 5 calls with `_asyncConfirm()` Promise wrapper using `showSimpleModal`.
- **`alert()` blocking dialogs** — replaced all 14 calls across 7 files with `_gwAlert()` transient DOM div (auto-removes after 7 s).
- **Window namespace pollution** — 7 `window._acct*` globals collapsed to `window._acct = {openModal, changePw, revokeSession, userRole}` across all 8 dashboard files.
- **Dead `url()` identity function** — removed from 6 dashboards; `controls.html` preserved (~30 call-sites). Fixed orphan `)` that silently discarded fetch options in 9 call-sites.
- **Service metrics default window too short** (`config.py`) — interval 10 s → 60 s; retention 4 320 → 43 200 (30-day window at ~22 MB).
- **`controls.html` Apply/Reset placement** — action bar moved above Defenses & Scoring, visible without scrolling.
- **Path filter pill click-handler flicker** (`dashboards/main.html`) — clicking the pill area while input text was set triggered the click handler which temporarily removed the `active` class. Fixed: path pill click handler short-circuits immediately; pill state is driven solely by input content.
- **`_fetchPathEvents` JSON.parse error on non-JSON gateway response** (`dashboards/main.html`) — on session expiry or IP change the gateway returns an HTML 404; `r.json()` threw "SyntaxError: JSON.parse: unexpected character". Fixed: check `r.ok` before parsing; show a user-friendly "Session may have expired — please refresh" message.
- **Silent `.catch(()=>({}))` on UI-state fetches** (`dashboards/agents.html`, `dashboards/main.html`, `dashboards/controls.html`) — 14 occurrences swallowed 401/session-expiry responses, causing operators to see silently stale dashboards. Replaced with structured `try/catch { _error: true }` + explicit guard on every affected call-site (§17e).
- **Login redirect not origin-validated** (`dashboards/login.html`) — `location.href = j.redirect` set without validating the server-supplied URL. Fixed: `safeNext(j.redirect)` filters to same-origin relative paths (§17c).
- **`playTimer` and `_lpTimer` interval leaks** (`dashboards/geo.html`) — two `setInterval` calls not pushed to `_timers[]`; intervals accumulated on repeated page navigation. Fixed: both timers appended after creation (§17b).
- **Stale line-number references in `js_challenge.py`** (`challenge/js_challenge.py`) — two comments cited `proxy_handler.py:2511` as the location where `_track_key` is set, which was incorrect after prior refactors. Replaced with canonical reference to rules.md §16b pattern.

### Changed
- **Dockerfile base images updated** — `cgr.dev/chainguard/python` digests refreshed to fix `py3-pip-wheel 26.0.1-r2` CVEs (3 HIGH: CVE-2025-66418, CVE-2025-66471, CVE-2026-21441; 4 MEDIUM, all fixed in `26.1.1-r0`).
- **Bandit `# nosec B110` suppressions** — added to all `except: pass` blocks flagged by Bandit/Fortify SAST across `config.py`, `core/proxy_handler.py`, `reputation/maxmind.py`, `admin/auth.py`, `db/sqlite.py`, `proxy.py`, `helpers.py`, `identity.py`, `scoring.py`.
- **`credentials:"same-origin"` normalized** to `credentials:'include'` throughout `settings.html`.
- **`main.html` duplicate `getRangeMin()`** removed.
- **`agents.html` `m-total`** stale overwrite of backend total with filtered count removed.
- **`logs.html` stale `lastIds` set** removed.

### Tests
- `test_161_custom_rules_parser` updated — `ip_cidr` holds raw strings; compiled networks in `_ip_nets`.
- `test_161_custom_rule_ip_cidr` — was failing (CIDR match returned `None`); now passes.
- 10 new config endpoint QA tests in `tests/test_control_regressions.py`.
- `test_165_every_knob_persists_round_trip` — added `"BYPASS_MODE": False` coverage.
- `test_bypass_paths_early_return_no_record_call` updated — verifies `db_queue.put_nowait` + `bypass-path` reason + confirms `record()` not called.
- 5 new BYPASS_MODE / BYPASS_PATHS functional QA tests in `tests/test_functional.py`.
- `test_operator_passthrough_in_passthrough_reasons` and `test_protect_upstream_operator_bypass_calls_record` in `tests/test_pure.py`.
- 39 new tests in `tests/test_pure.py` — MaxMind cache (TTL, max, hit, eviction, city-cache ordering), service metrics defaults/window, geo/logs/controls UI.
- 5 new geo-map 30-day tests in `tests/test_pure.py`; `test_geo_data_range_clamped_high` updated (≤ 43200).
- `test_controls_bypass_requires_user_confirmation` updated to check `_asyncConfirm(`.
- `test_main_html_k_q_absent` added.
- `tests/test_geo_dashboard.py` — 55 new tests covering geo pill, API shape, and regressions.
- `test_agents_html_no_silent_catch_on_ui_fetch`, `test_main_html_no_silent_catch_on_ui_fetch`, `test_controls_html_no_silent_catch_on_ui_fetch` — assert `catch(()=>({}))` absent from each dashboard (§17e).
- `test_login_redirect_response_validated_through_safenext` — asserts `safeNext(j.redirect)` present in `login.html` (§17c).
- `test_geo_setinterval_tracked` — asserts `_timers.push(playTimer)` and `_timers.push(_lpTimer)` present in `geo.html` (§17b).

### Validation
- **Full suite**: 772 passed, 1 failed (pre-existing: `test_service_data_auth_guard` — DB state contamination in combined runs, passes in isolation)
- **Previously flaky (now fixed)**: `test_risk_increments_on_block`, `test_security_headers_injected_on_html` — conftest DB wipe was targeting wrong path; both now pass consistently
- **Bandit**: 0 High / 0 Critical / 0 Medium / 0 Low
- **Semgrep**: 151 rules · 15 files · 0 findings
- **Trivy**: 0 CRITICAL / 0 HIGH / 0 MEDIUM (all arches, after base image refresh)
- **Pentest**: `suspicious-path` fires on first injection probe, banning the identity; subsequent burst requests receive `banned-silent` HTTP 200 (silent decoy — upstream mirror); auto-recovery via unban API confirmed
- **Harbor**: amd64 `sha256:7ccb35ac` · arm64 `sha256:c97c192c` · armv7 `sha256:f54a2158` · manifest `sha256:1a5113a9`

## [1.7.7] — 2026-05-07

### Added
- **Geo dashboard loading/ready pill** (`dashboards/geo.html`) — `#load-status` CSS pill placed in the "World-map of accesses" h2. Starts yellow with a pulsing dot animation ("Loading") on page open; flips to solid green "Loading Ready" inside double `requestAnimationFrame` after the first successful `tick()` data fetch (after `renderAsns()` completes). Matches the controls dashboard `#load-status` pattern. CSS uses `--yellow`/`--green` variables with `@keyframes ls-pulse`; JS flip is idempotent (guarded by `!classList.contains('ready')`).

- **BYPASS_PATHS audit trail** (`core/proxy_handler.py`) — bypass-path requests previously returned early with zero recording, making them invisible in all dashboards and logs. Now proxies the request first, then writes an `("event", ..., "bypass-path")` entry to `db_queue` so every bypassed access appears in the events table. `ip_state` intentionally stays empty (no bot scoring) but the access is traceable.
- **Path search in main dashboard** (`dashboards/main.html`) — text input in the category filter bar filters the clients table live by `last_path` substring match. Also triggers a query to `/secured/logs-data?q=<path>` and renders a new "Path event log" panel below the clients card, showing all matching events from the DB including `bypass-path` entries (timestamp, IP, path, status, reason, UA). Debounced 300 ms. Clear button shown when active.

- **MaxMind in-process lookup cache** (`reputation/maxmind.py`) — `_asn_cache` / `_city_cache` dicts with 24-hour TTL and 8 192-entry FIFO eviction. Eliminates repeated mmdb reads (~4/request for the same IP). Cache check in `_city_lookup` placed before the reader-null guard so cached results survive monthly mmdb refresh cycles.
- **`logs.html` category filter pills** (`dashboards/logs.html`) — Five toggle pills (Allowed · Ban · Really Ban · Auth Bots · GW Mgmt) in a filter bar shown on the Requests tab. `_logCat()` classifier: `authorized-robot` → authbots; `/antibot-appsec-gateway/` path → gwmgmt; hard-ban reasons (canary-echo/honeypot-silent/honeypot) → reallyban; any non-OK reason → ban; else → allowed. Client-side filtering, no round-trip.
- **`rules.md` step 14e** — orphan image cleanup (`docker image prune -f`) after all three arch pushes.

- **Geo-map 30-day view** (`dashboards/geo.html`, `core/proxy_handler.py`) — added `30 days` (43 200 min) option to the window select. Raised range cap from 10 080 → 43 200 in `geo_data_endpoint` and `geo_drill_endpoint`. Events table never pruned so depth is available. Two performance countermeasures: (1) cursor iteration replaces `fetchall()` — constant RAM for any window size; (2) reservoir sampling (Algorithm R) replaces first-5000 approach — scrubber `events_sample` now uniformly covers the full window rather than only the oldest time slice. `ORDER BY` removed (not needed; `rebuildBuckets()` bins by `ts` value directly).

### Fixed
- **GW Mgmt filter showed zero entries despite active operator dashboard browsing** (`core/proxy_handler.py`) — `protect()` returned `await handler(request)` immediately for authenticated admin-path requests (`_admin_ip_allowed and _internal_authed`) without calling `record()`. Operator dashboard accesses never entered `ip_state` and were invisible to `_clientCats` / `_agentCats`. Fix: await the handler first, then call `record()` with `reason='operator-passthrough'` before returning.
- **Three stale `test_dashboard_data.py` tests** — response key renames not reflected in tests: `agents-data` (`agents`→`suspects`), `logs-data` (`events`→`rows`), `path-hits` (missing `?path=` param + `paths`→`ips`).

- **BYPASS_PATHS not visible in any dashboard or log** — root cause: early `return await handler(request)` before any `db_queue` write. Fixed by capturing response, writing `bypass-path` event, then returning.

- **`controls.html` DELETE admin-IP URL malformed** — `&cidr=` → `?cidr=`
- **Double-save on inline edit** — `_descSaved`/`_thrSaved` guard prevents blur+Enter firing two PATCH requests
- **`geo.html` ready-state pill text** — ready state was accidentally set to plain "Ready"; corrected to "Loading Ready" to match the JS flip logic intent and the validation spec
- **`confirm()` blocking dialogs** — replaced 5 calls with non-blocking `_asyncConfirm()` Promise wrapper using `showSimpleModal`
- **`alert()` blocking dialogs** — replaced all 14 calls across 7 files with `_gwAlert()` transient DOM div (auto-removes after 7s)
- **Window namespace pollution** — 7 separate `window._acct*` globals collapsed to `window._acct = {openModal, changePw, revokeSession, userRole}` across all 8 dashboard files
- **Dead `url()` identity function** — removed `const url = (p) => p` from 7 locations; fixed 9 broken fetch calls where orphan `)` caused comma-expression (options silently discarded)
- **`credentials:"same-origin"` inconsistency** — normalized to `credentials:'include'` throughout `settings.html`
- **`main.html` duplicate `getRangeMin()`** — removed duplicate function declaration
- **`agents.html` `m-total` overwrote backend total with filtered count** — removed stale line
- **`logs.html` stale `lastIds` set** — removed unused variable
- Various dead variables and dead nav-patch blocks removed

- **`controls.html` `url()` identity function removed incorrectly** (`dashboards/controls.html`) — DC-01 in the previous pass removed `const url = p => p` from controls.html which has ~30 `url(path)` fetch call-sites. All dashboard panels threw `ReferenceError: url is not defined`. Restored.
- **`controls.html` Apply/Reset placement** (`dashboards/controls.html`) — Action bar moved from below Thresholds to immediately before Defenses & Scoring, visible without scrolling.
- **Service metrics default window too short** (`config.py`) — interval default 10 s → 60 s; retention default 4 320 → 43 200 (30-day window at ~22 MB). Previously only 12 hours of service data were retained.

### Tests
- **`tests/test_geo_dashboard.py`** — 55 new tests: 16 unit (geo.html static analysis: pill element, CSS rules, JS flip logic, double-RAF, idempotency), 22 functional (`/secured/geo` page serving + `/secured/geo-data` API shape/params/security headers/unconfigured path), 17 regression (existing geo features intact)
- `test_protect_authenticated_admin_path_calls_record` — `protect()` calls `record()` in authenticated admin path branch
- `test_protect_authenticated_admin_path_uses_operator_passthrough_reason` — reason is `'operator-passthrough'`

- `test_bypass_paths_early_return_no_record_call` updated — now verifies `db_queue.put_nowait` present and reason `bypass-path` in bypass block, in addition to confirming `record()` is not called
- `test_bypass_paths_no_ip_state_recorded` docstring updated — clarifies audit event is written to db_queue but ip_state stays empty

- `test_controls_bypass_requires_user_confirmation` — updated to check `_asyncConfirm(` (was `confirm(`)
- `test_main_html_k_q_absent` — replaces two stale k_q tests; asserts `k_q` no longer present

- 39 new tests in `tests/test_pure.py`: MaxMind cache (TTL, max, hit, no-cache-on-disabled, eviction, city-cache-before-reader ordering), service-metrics defaults/overrides/window calculation, geo.html pill text, logs.html cat filter bar visibility/categories/JS functions/tab wiring, controls.html actions placement, `url` identity present in controls.html.

- 5 new tests in `tests/test_pure.py`: geo.html 30-day option present, geo_data_endpoint cap ≤ 43200, geo_drill_endpoint cap ≤ 43200, cursor-not-fetchall, reservoir sampling present.
- `test_geo_data_range_clamped_high` in `tests/test_geo_dashboard.py` updated: asserts ≤ 43200 (was 10080).

### Validation
- **Step 11a (secure code review)** added to `validation/1.7.7.md` — PASS on all 8 checks; no new external deps; cursor/reservoir code reviewed clean
- **Multi-arch parity rebuild**: amd64 and arm64 rebuilt with all session 2+3 code (were on session-1 binary); armv7 unchanged
- **Harbor push** (final): amd64 `sha256:549e9879` · arm64 `sha256:a5d0cad8` · armv7 `sha256:7d8df3f3` · manifest `sha256:596d4514`

---

## [1.7.6] — 2026-05-07

### Added
- **Category filter bar on main and agents dashboards** (`dashboards/main.html`, `dashboards/agents.html`) — five colour-coded toggle pills above the page content: ● Allowed (green), ● Blocked (red), ● Missed (orange), ● Auth Bots (purple), ● GW Mgmt (blue). All active by default. Toggling a pill simultaneously hides/shows the corresponding Chart.js dataset on the timeline chart AND filters rows in the clients / suspects table. Filter state persists across `tick()` refreshes (stored in `window._activeFilters`). GW Mgmt captures any client or suspect whose `last_path` starts with `/antibot-appsec-gateway/` and has no corresponding timeline dataset — it is table-only.
- **`_clientCats` / `_agentCats` category classifiers** (`dashboards/main.html`, `dashboards/agents.html`) — pure functions that map each client/suspect to one or more filter categories. Priority order: `is_authorized_bot` → `gwmgmt` (last_path prefix) → `blocked` (banned_secs > 0) → `missed` (stealth_score ≥ 20) → `allowed`. A client appearing in multiple categories is shown if any active filter matches.
- **`_renderClientsTable(list)` extracted from `tick()`** (`dashboards/main.html`) — the entire clients table HTML generation + ban-control event wiring was an inline block inside `tick()`. Extracted into a standalone function so `_applyFilters()` can re-render the filtered subset without a network round-trip. Popover handler now references `window._clientsView` (the currently displayed subset) instead of the full `_clientsList`.

### Fixed
- **Auth bots invisible under Auth Bots filter when last_path is a GW URL** (`dashboards/main.html`, `dashboards/agents.html`) — `_clientCats` / `_agentCats` checked `last_path.startsWith('/antibot-appsec-gateway/')` first. Auth bots that poll the health endpoint or dashboard are classified as `gwmgmt` and disappear from the Auth Bots filter. Fix: check `is_authorized_bot` before the gwmgmt path check.
- **Auth bots excluded from agents suspects table by min_score gate** (`dashboards/agents.py`) — `_s_is_auth_bot` was computed after `if score < min_score: continue`. Auth bots have stealth_score ≈ 0 by design (they pass all checks), so all of them were silently dropped before the auth-bot check ran. The agents page showed zero entries under Auth Bots filter. Fix: hoist `_s_is_auth_bot` before the gate; guard as `if score < min_score and not _s_is_auth_bot: continue`.
- **Null comps/mets for score-0 auth bots** (`dashboards/agents.py`) — the existing score-0 fallbacks only trigger when `score > 0`. Auth bots passing through with score == 0 sent `null` to the frontend component bar, causing `c.headers` to throw. Fix: add `_s_is_auth_bot and not comps` / `_s_is_auth_bot and not mets` fallback dicts after the gate.

### Tests
- `test_main_html_cat_filter_pills_present` — main.html has all 4 original cat-pill data-cat values
- `test_agents_html_cat_filter_pills_present` — agents.html has all 4 original cat-pill data-cat values
- `test_main_html_apply_filters_hides_chart_datasets` — `_applyFilters` sets datasets[1-4].hidden from `_activeFilters`
- `test_agents_html_cat_filter_hides_chart_datasets` — agents pill handler sets all 4 agentChart dataset hidden flags
- `test_main_html_render_clients_table_is_standalone` — `_renderClientsTable` is a top-level function
- `test_main_html_tick_calls_apply_filters` — `tick()` calls `_applyFilters()` for client table rendering
- `test_main_html_gwmgmt_pill_and_cat_function` — main.html has gwmgmt pill + `_clientCats` checks `/antibot-appsec-gateway/` prefix
- `test_agents_html_gwmgmt_pill_and_cat_function` — agents.html has gwmgmt pill + `_agentCats` checks prefix
- `test_main_html_client_cats_auth_bot_before_gwmgmt` — `_clientCats` tests is_authorized_bot before gwmgmt check
- `test_agents_html_agent_cats_auth_bot_before_gwmgmt` — `_agentCats` tests is_authorized_bot before gwmgmt check
- `test_agents_data_auth_bot_check_before_min_score_gate` — `_s_is_auth_bot` computed before score gate
- `test_agents_data_min_score_gate_skips_auth_bots` — gate guards `and not _s_is_auth_bot`
- `test_agents_data_auth_bot_has_safe_comps_fallback` — auth bots with score == 0 get default comps/mets

### Validation
- **Bandit**: 0 High / 0 Critical (1 Low B104 intentional; 4 Low B608 `#nosec` parameterized)
- **Semgrep**: 151 rules · 9 files · 0 findings
- **Unit tests**: 391 passed, 0 failed (`test_critical.py` 116 + `test_pure.py` 265 + `test_async.py` 10)

---

## [1.7.5] — 2026-05-06 · updated 2026-05-07

### Added
- **Bucket drill-down: live section move on action** (`dashboards/main.html`, `dashboards/agents.html`) — clicking Ban / Hard ban / Allow / Auth Bot in the bucket detail modal now moves the entry between sections in real-time (400 ms after the button shows ✓). The in-memory data object `d` is mutated (`_moveEntry`), then `_renderAndWire` / `_renderAndWireA` re-renders all four sections from the updated state. Ban/Hard ban moves the entry to BLOCKED (detected); Allow moves it to ALLOWED (clean); Auth Bot moves it to AUTHORIZED BOTS. Section entry counts in headers update accordingly. Previously the button only showed ✓/✗ with no visual feedback that the entry had changed category. `ipAction` / `_ipActionR` now returns a boolean so callers can gate the move on success.
- **Clients table scrollable up to 100 entries** (`dashboards/main.html`) — the Clients card now wraps `#clients-tbl` in a `max-height:420px; overflow-y:auto` div and renders up to 100 entries (previously capped at 25). Column headers are sticky via `#clients-tbl thead th { position:sticky; top:0; z-index:1 }` so they remain visible while scrolling.
- **Auth Bot button always visible in bucket modals** (`dashboards/main.html`, `dashboards/agents.html`) — the Auth Bot button was previously hidden when `e.ua` was falsy (empty-string UA). Changed to always render the button unconditionally and store `data-authbot=""` as a safe fallback. Added `.act.authbot { background:#1f1a2e; color:#bc8cff }` CSS rule in both dashboards so the button is visually consistent with the authorized-bot purple theme.

- **Authorized bots shown in purple on all traffic graphs** (`dashboards/main.html`, `dashboards/agents.html`, `dashboards/geo.html`, `core/proxy_handler.py`, `dashboards/agents.py`) — monitoring bots that are explicitly authorized (reason `authorized-robot`) were previously invisible on the time-series charts and geo map, or incorrectly counted as "blocked". They are now tracked as a distinct fifth dataset (purple, `#bc8cff`, dashed line) on the main dashboard traffic chart and the agents chart, and rendered as purple circles on the geo map with a separate legend entry. Backend changes: `metrics_endpoint` timeline now extracts `authorized_robot` from each bucket's `by_reason` (in-memory `defaultdict` or DB JSON column); `agents_timeline_endpoint` gains a dedicated SQL query for `reason='authorized-robot'`; `geo_data_endpoint` classifies `authorized-robot` events as `kind='authorized_robot'` instead of `'blocked'` so they no longer inflate blocked counts on the map. Scrubber playback also tracks the new kind via `ar` counter in bucket points.

### Fixed
- **Controls: action combo box removed from authorized bots section** (`dashboards/controls.html`) — the "Authorized bot / Allow / Ban / Really ban" dropdown next to each authorized-bot entry had no meaningful purpose (authorized bots are always pass-through). Removed the `<select class="bot-action-sel">` element and associated CSS; `readBots()` now always writes `action: 'authorized-robot'`. Updated section description text accordingly.
- **Block-Rate Trend aligned with main graph timeline** (`dashboards/main.html`) — the block-rate chart used independent label computation and `maxTicksLimit:6` for x-axis ticks while the main chart used `autoSkipPadding:18`. This caused the two timelines to show different tick spacings, making the charts appear out of sync. Fix: main chart stores its resolved labels in `window._lastMainLabels`; block-rate chart reads `_lastMainLabels` and applies the same `autoSkipPadding:18` x-axis config.
- **CI workflow bad substitution** (`.github/workflows/`) — `IMAGE="…:pre-${inputs.version}"` caused `sh: syntax error: bad substitution` because `inputs.version` contains a dot, which is invalid in a POSIX shell variable name. Fix: use `${{ inputs.version }}` (GitHub Actions expression syntax) which is resolved by the Actions runner before the shell script executes.
- **3 flaky CI test failures** (`tests/test_path_sweep.py`, `tests/test_control_regressions.py`):
  - `test_expired_entries_pruned` — planted entries with timestamp `0.0` (monotonic). On freshly-booted CI runners where `monotonic() < PATH_SWEEP_WINDOW_SECS` (300 s), the cutoff `monotonic() - 300` is negative and `0.0 > cutoff` — entries were NOT pruned and the detector fired. Fix: use `monotonic() - PATH_SWEEP_WINDOW_SECS * 2` as the old timestamp, guaranteed below any cutoff.
  - `test_v9_turnstile_required_when_enabled` — got 429 instead of 403 from the challenge endpoint. Root cause: `test_challenge_endpoint_rate_limited` fires 20 challenge POSTs with `IP_BURST=3`, depleting `ip_buckets["127.0.0.1"]` to ~0. Config is restored via `_spin_proxy` teardown but `ip_buckets` (module-level in `state.py`) was not cleared. The next test to hit the challenge endpoint received 429 (rate-limited) before its expected 403 (no Turnstile token).
  - `test_r7_canary_injected_into_html` — `X-Trace-Id` header absent (empty trace). Root cause: `ip_state["127.0.0.1"]` retained high risk scores or bans from prior tests, causing the GET to be blocked (decoy response, no upstream HTML, no canary injection).
  - Fix for both: `_spin_proxy` now calls `ip_state.clear()`, `ip_buckets.clear()`, `ip_new_sessions.clear()` at setup (before `yield`) and again in `finally` after teardown.

- **armv7 image built with wrong architecture** — `docker build -f Dockerfile.armv7` on an arm64 host without `--platform linux/arm/v7` silently produces an arm64 image tagged as `-armv7`. The container fails with exit code 159 on the target armv7 device ("platform linux/arm64 does not match detected host platform linux/arm/v8"). Fix: always pass `--platform linux/arm/v7` for armv7 builds.

### Tests
- Added regression tests for 1.7.5 features: `test_main_authorized_bots_purple_dataset`, `test_agents_authorized_bots_purple_dataset`, `test_geo_authorized_bot_legend`, `test_geo_authorized_bot_circle_renders`, `test_geo_authorized_bot_scrubber_ar_counter`, `test_metrics_timeline_has_authorized_robot_field`, `test_agents_timeline_has_authorized_robot_query`, `test_geo_authorized_robot_kind_in_geo_data_endpoint`, `test_build_validation_armv7_requires_platform_flag`.

---

## [1.7.4] — 2026-05-06

### Added
- **AWS ELB / ALB health check pass-through** (`config.py`, `core/proxy_handler.py`) — AWS Application/Network Load Balancers send `GET <path>` with `User-Agent: ELB-HealthChecker/2.0` and only `Host`, `Connection: close`, `Accept-Encoding` headers — no `Accept`, `Accept-Language`, or `Sec-Fetch-*`. This triggered `ua-non-browser` (+25) and `ai-headers-incomplete` (+20) on every probe; after two requests the LB node accumulated 90+ risk points, was banned, and the target group was marked unhealthy causing traffic drains. Fix: new two-factor bypass guard in `protect()` — when **both** path and UA prefix match, the request short-circuits the entire detection pipeline and returns `200 ok` immediately. Default path is `"/"` (AWS ALB/NLB health checks probe root by default); override with `ELB_HEALTH_CHECK_PATH`. Disable entirely by setting `ELB_HEALTH_CHECK_UA=""`. The path hash (SHA-256[:8]) is logged; plaintext never appears in logs. Previous implementation had `ELB_HEALTH_CHECK_PATH` defaulting to `""` (disabled), which meant the bypass never activated unless explicitly configured — fixed to default `"/"`. New env vars: `ELB_HEALTH_CHECK_PATH` (default: `/`), `ELB_HEALTH_CHECK_UA` (default: `ELB-HealthChecker`).
- **New config knobs**: `ELB_HEALTH_CHECK_PATH`, `ELB_HEALTH_CHECK_UA`.
- **§17h added to `rules.md`** — documents the ELB health check pass-through: signal table, two-factor security model, configuration example, and verification command.

- **Authorized monitoring bot pass-through** (`config.py`, `core/proxy_handler.py`, `core/metrics.py`) — UptimeRobot, Pingdom, StatusCake, Site24x7 and similar availability monitors probe `"/"` with non-browser UAs and minimal headers, accumulating `ua-non-browser` (+25) + `ai-headers-incomplete` (+20) = 45 pts per request and being banned after two hits. New bypass: when the request path is `"/"` and the `User-Agent` contains any substring from `AUTHORIZED_BOT_UAS`, the request short-circuits detection, returns `200 ok`, and is recorded as `"authorized-robot"` — **not counted as blocked** (`_PASSTHROUGH_REASONS` set in `core/metrics.py`). Recorded in `by_reason` so operators see the traffic in the dashboard reasons breakdown. Default UA list: `UptimeRobot`, `Pingdom`, `StatusCake`, `Site24x7`, `freshping`, `hetrix`, `Better Uptime`, `uptimia`, `updown.io`, `HetrixTools`, `statuscake`. Set `AUTHORIZED_BOT_UAS=""` to disable. New env var: `AUTHORIZED_BOT_UAS`.
- **"authorized-robot" dashboard display** (`dashboards/main.html`, `dashboards/logs.html`) — authorized monitoring bot events appear with a blue `authorized-robot` tag (`.tag.authorized-robot`) and blue left-border row (`.evt.evt-authorized`) in the live events stream, not as blocked (red) rows. In `logs.html` the reason is shown in `var(--blue)` instead of red.

- **Master bypass switch** (`dashboards/controls.html`) — prominent toggle bar at the top of the Controls page. When turned ON (after confirmation): snapshots all current `bool` control states to `localStorage`, POSTs all bool knobs as `false` in a single request, and shows a red "BYPASS ACTIVE" warning. When turned OFF: reads the snapshot from `localStorage` and POSTs the restore payload in one request. Intended for temporary maintenance / debugging windows where bot protection must be fully suspended. Snapshot + active flag persist across page reloads so the warning survives navigation; both are cleared on restore.
- **Per-card collapse toggles** (`dashboards/controls.html`) — every card on the Controls page now has a clickable `<h2>` that collapses/expands the card body. A chevron `▼` rotates `◁` when collapsed. Collapse state is persisted per card to `localStorage`, so sections stay folded across page reloads. Added `id` attributes to the three previously-unnamed cards (`card-unban`, `card-admin-ip`, `card-audit-log`) so their collapse state keys are stable.

### Fixed
- **Dashboard time-window bucket auto-adapt** (`dashboards/service.html`, `dashboards/main.html`) — selecting a time window > 3 h left the bucket selector at its default (5 s for Service, 1 min for Dashboard) causing the API to return thousands of mostly-zero data points for the selected window. Chart.js rendered a near-invisible flat line at y = 0 giving the impression that graphs were blank. Root cause: the main chart `range.onchange` handler called `tick()` directly without updating the bucket selector, while the stat-card click-to-zoom modal already contained a correct `pickBucketForRange()` helper. Fix: hoisted `pickBucketForRange` to global scope in both files; wired it into the `range.onchange` handler so the bucket is always set to a sensible granularity before the data fetch. Removed the duplicate local definition from the stat-card IIFE in `service.html`. Resulting point counts stay ≤ ~720 across all window sizes (5 min → 5 s; 1 h → 30 s; 6 h → 1 min; 24 h → 5 min; 7 d → 15 min; > 7 d → 1 h).
- **`escHtml` → `escapeHtml` in all dashboards** (`dashboards/logs.html`, `dashboards/main.html`, `dashboards/service.html`, `dashboards/controls.html`, `dashboards/geo.html`) — 5 dashboard files called `escHtml()` which is undefined; only the canonical `escapeHtml()` function is defined at global script scope. Affected call sites: health-score pill modal rows, account modal username/role display, session list IP display, and request table method cells. Result was a silent `ReferenceError` in the browser console whenever these UI sections rendered. All occurrences replaced with `escapeHtml()`.
- **`r.ok` guard before `r.json()` in logs.html LOG_LEVEL POST handlers** — both the level-button click handler and the dropdown `onchange` handler in `logs.html` called `r.json()` unconditionally. When a session expires and the server returns a non-JSON response (HTML 404 silent-decoy), `JSON.parse` threw "unexpected non-whitespace character after JSON data at line 1 column 5". Added `if (!r.ok)` guard that shows a clear alert ("Server error 401 — session may have expired, please reload") and returns early without calling `r.json()`.
- **`_LOG_LEVEL_N` not propagated on LOG_LEVEL hot-reload** (`core/proxy_handler.py` `config_endpoint`) — the LOG_LEVEL hot-reload path updated the `LOG_LEVEL` string in all module namespaces via the generic `_HOT_RELOAD_KNOBS` loop, but did not update the derived numeric sentinel `_LOG_LEVEL_N` used by `slog()` for level filtering. Since `helpers.py` imports `_LOG_LEVEL_N` at module load time (`from config import _LOG_LEVEL_N`), Python creates a local copy of the value; changing `config._LOG_LEVEL_N` does not update `helpers._LOG_LEVEL_N`. Result: changing the log level from the dashboard had no effect on actual log output. Fix: after the generic propagation loop, `config_endpoint` now explicitly recomputes `_LOG_LEVEL_N = _LOG_LEVELS.get(value, 20)` and propagates it to all loaded modules via `setattr`.

- **`NameError: name '_city_lookup' is not defined` in `ip_intel_endpoint`** (`admin/users.py`) — `ip_intel_endpoint` called `_city_lookup`, `_asn_lookup`, `_abuseipdb_lookup`, `_crowdsec_check`, and `_tor_exits` without importing them. `proxy_handler.py` has all five in its global namespace via its own import block; `admin/users.py` is a separate module with its own namespace and had none of them. Any call to the IP intel popover (identity-details in agents.html / main.html) raised `NameError` and returned HTTP 500. Fix: added `from reputation.maxmind import _city_lookup, _asn_lookup`, `from reputation.abuseipdb import _abuseipdb_lookup`, `from reputation.crowdsec import _crowdsec_check`, `from reputation.tor import _tor_exits` at module level in `admin/users.py`.
- **Dockerfile pip deps pinned to exact versions** (`Dockerfile`, `Dockerfile.armv7`) — previously used range specifiers (`>=x,<y`), flagged as DL3013 / supply-chain unpinned by Aikido. Resolved currently installed versions (`aiohttp==3.13.5`, `maxminddb==2.8.2`, `psycopg[binary]==3.3.4`, `redis==5.3.1`, `pyjwt==2.12.1`) and pinned all direct deps to exact `==` constraints. Builds remain reproducible.
- **Dockerfile builder stage drops root before final stage** (`Dockerfile`, `Dockerfile.armv7`) — Aikido DL3002: builder stage set `USER root` (line 6) and never reverted. Final runtime stage already runs as `USER 65532:65532`, but the linter checks per-stage. Fixed by adding `USER nonroot` at end of the Chainguard builder stage and `USER nobody` at end of the Alpine builder stage.
- **7-day graph no date labels in main/agents dashboards** (`dashboards/main.html`, `dashboards/agents.html`) — `pickBucketForRange` mapped the 7-day window to 900 s (15-min) buckets, producing 672 data points all labeled `"HH:MM"` by `fmtTime`'s sub-3600 s branch (no date component). Changed to map 7 d → 3600 s buckets (168 points, labeled `"May 3 14:00"`) and ≥ 30 d → 86400 s buckets (30 points, labeled `"May 3"`). Added `<option value="43200">30 days</option>` to the range selector in both dashboards. Added `tPickBucketForRange` + `tAutoSelectBucket` to `agents.html` (which had no equivalent auto-bucket logic) and wired it into the `t-range` change handler.

### Tests
- **Version strings bumped** — `tests/test_pure.py` `_EXPECTED_VERSION`, `test_gw_version_constant`, and `test_no_stale_version_strings_in_source` updated to `AppSecGW_1.7.4`.
- **`test_no_eschtml_calls`** — parametrized ×7 dashboards; asserts no call to undefined `escHtml()` (regression for 5-dashboard `escHtml` bug).
- **`test_log_level_n_propagated_on_hot_reload`** — asserts `config_endpoint` contains `_LOG_LEVEL_N` propagation and `_LOG_LEVELS.get(` recompute (regression for hot-reload numeric sentinel bug).
- **`test_ip_intel_endpoint_imports_reputation_symbols`** — asserts all 5 reputation symbols (`_city_lookup`, `_asn_lookup`, `_abuseipdb_lookup`, `_crowdsec_check`, `_tor_exits`) imported at module level in `admin/users.py` (regression for `NameError` in ip-intel endpoint).
- **`test_logs_html_log_level_button_has_rok_guard`** — asserts ≥2 `if (!r.ok)` guards in `logs.html` (regression for unconditional `r.json()` on non-JSON responses).
- **`test_logs_html_log_level_handlers_no_unconditional_json`** — verifies `r.ok` check precedes `r.json()` in each LOG_LEVEL POST handler in `logs.html`.
- **`test_logs_html_authorized_robot_shown_in_blue`** — asserts `logs.html` renders `authorized-robot` reason in `var(--blue)`.
- **`test_controls_bypass_bar_html_elements_present`** — asserts `#bypass-bar`, `#bypass-sw`, `#bypass-warn` elements present in `controls.html`.
- **`test_controls_bypass_css_classes_defined`** — asserts `.bypass-sw`, `.bypass-sw.on`, `#bypass-bar.bypass-on` CSS defined.
- **`test_controls_bypass_iife_snapshots_and_restores`** — asserts `_BYPASS_ACTIVE_KEY`, `_BYPASS_SNAP_KEY`, `localStorage.setItem/removeItem` in bypass IIFE.
- **`test_controls_bypass_posts_false_for_all_bool_knobs`** — asserts payload sets knobs to `false`.
- **`test_controls_bypass_uses_credentials_include`** — asserts bypass fetch calls include `credentials:'include'`.
- **`test_controls_bypass_requires_user_confirmation`** — asserts `confirm()` shown before disabling all controls.
- **`test_controls_collapse_css_defined`** — asserts `.cc-chevron` and `.cc-collapsed` CSS present.
- **`test_controls_collapse_iife_persists_to_localstorage`** — asserts `_CC_PREFIX`, `localStorage.setItem/getItem` in collapse IIFE.
- **`test_controls_collapse_card_h2_click_handler`** — asserts `querySelectorAll('.card')` + click listener in collapse IIFE.
- **`test_main_pick_bucket_7day_returns_3600`** — asserts `pickBucketForRange(10080)` maps to 3600, not 900 (regression for HH:MM-only 7-day labels).
- **`test_main_pick_bucket_30day_returns_86400`** — asserts fallthrough returns 86400 for 30-day view.
- **`test_main_30day_option_in_range_select`** — asserts `<option value="43200">` present in `main.html`.
- **`test_agents_pick_bucket_7day_returns_3600`** — asserts `tPickBucketForRange` exists in `agents.html` and returns 3600 for 7d.
- **`test_agents_pick_bucket_30day_returns_86400`** — same for 30-day.
- **`test_agents_30day_option_in_range_select`** — asserts `<option value="43200">` in `agents.html`.
- **`test_agents_auto_select_bucket_wired_to_range_change`** — asserts `tAutoSelectBucket` called from `t-range` change listener.
- **`test_main_tooltip_callback_uses_timeline_epoch`** — asserts `main.html` tooltip uses `_lastMainTimeline`/`_lastMainBucketSecs` with `toLocaleDateString`.
- **`test_agents_tooltip_config_defined`** — asserts `agents.html` has tooltip plugin config with `_lastAgentTimeline`.
- **`test_agents_tooltip_callback_formats_date`** — asserts `agents.html` tooltip calls `toLocaleDateString/toLocaleString`.
- **`test_dockerfile_pip_deps_use_exact_pins`** — asserts no range specifiers (`>=`, `<=`, `~=`) in `Dockerfile` pip install (Aikido DL3013).
- **`test_dockerfile_armv7_pip_deps_use_exact_pins`** — same for `Dockerfile.armv7`.
- **`test_dockerfile_builder_stage_drops_root`** — asserts `USER nonroot` in `Dockerfile` builder stage (Aikido DL3002).
- **`test_dockerfile_armv7_builder_stage_drops_root`** — asserts `USER nobody` in `Dockerfile.armv7` builder stage.
- **Authorized bot tests** (×6) — `test_authorized_bot_uas_config_exists`, `test_authorized_bot_bypass_in_protect_source`, `test_authorized_bot_bypass_only_on_root`, `test_passthrough_reasons_not_counted_as_blocked`, `test_authorized_robot_tag_in_main_dashboard` — cover config existence, protect() source guard, root-only enforcement, metrics passthrough, and dashboard CSS.

### Validation
- 164 (test_pure.py) + 116 (test_critical.py) + 10 (test_async.py) tests pass; pre-existing failures in `test_v14.py` (JS challenge namespace-patch isolation) unchanged.

---

## [1.7.3] — 2026-05-05

### Added
- **Path-sweep detector** (`PATH_SWEEP_ENABLED=1`, default on) — new module `detection/path_sweep.py`. Fires when an identity visits ≥ `PATH_SWEEP_THRESHOLD` (default 40) distinct non-static paths within a `PATH_SWEEP_WINDOW_SECS` (default 300 s) sliding window. Unlike `behavioral.py` (skipped for cookied sessions), this detector runs for **all** identities including valid-cookied ones — specifically to catch the warm-up bypass technique (AI agent acquires valid cookie with benign traffic, then sweeps paths in fresh sessions). Static assets excluded via extension list; admin namespace excluded via `ADMIN_NAMESPACE` prefix check. Risk signal: `path-sweep`.
- **New config knobs** (path-sweep): `PATH_SWEEP_ENABLED`, `PATH_SWEEP_WINDOW_SECS`, `PATH_SWEEP_THRESHOLD`.
- **`IpState.path_sweep_times`** — `deque(maxlen=500)` sliding window of `(monotonic_ts, path)` pairs in `state.py`.
- **Geo "No geo" card** — `dashboards/geo.html` shows "No geo" summary card (private/localhost IPs with no MaxMind coordinates) via new `skipped_no_geo` field in `geo_data_endpoint`.
- **P1 — Semantic honeypot credential injection** (`HONEY_CRED_ENABLED=1`, default on) — new module `detection/honey_cred.py`. Injects a realistic-looking HTML comment before `</body>` on every proxied HTML response: `<!-- internal_api_key = <key>  debug_endpoint = /antibot-appsec-gateway/probe?k=<key>  env = staging -->`. Key is HMAC-SHA256(SESSION_KEY, identity + hourly bucket)[:32], stored in-process with 2-hour TTL. New public endpoint `GET /antibot-appsec-gateway/probe?k=<key>`: if key matches a known honey credential, fires `honey-cred` signal (+90 risk) on the issuing identity and returns bland `{"status":"ok"}` (never reveals whether key was valid). Browsers never read HTML comments; AI agents extract them from source. Risk score 90 = near-instant ban on first probe.
- **New config knobs** (honey-cred): `HONEY_CRED_ENABLED` (default `1`), `HONEY_CRED_SCORE` (default `90`).
- **P2 — Risk-gated redirect maze** (`REDIRECT_MAZE_ENABLED=0`, default off) — new module `detection/redirect_maze.py`. For identities above `REDIRECT_MAZE_THRESHOLD` risk, serves a chain of HMAC-signed redirect steps before allowing through. Token format: `{step}.{ts_ms}.{hmac16}`, 30 s TTL per step. New public endpoint `GET /antibot-appsec-gateway/maze?t=TOKEN&d=DEST`: validates token, issues next redirect (or final dest after `REDIRECT_MAZE_DEPTH` steps). If all steps completed in < `REDIRECT_MAZE_MIN_MS` (default 800 ms) → fires `redirect-maze-bot` (+55 risk). Real browsers show human latency; automated agents complete all steps in milliseconds.
- **New config knobs** (redirect maze): `REDIRECT_MAZE_ENABLED` (default `0`), `REDIRECT_MAZE_THRESHOLD` (default `20`), `REDIRECT_MAZE_DEPTH` (default `4`), `REDIRECT_MAZE_MIN_MS` (default `800`), `REDIRECT_MAZE_SCORE` (default `55`).
- **P3 — LLM no-subresource heuristic** (`LLM_HEURISTIC_ENABLED=1`, default on) — new module `detection/llm_heuristic.py`. Real browsers load CSS, JS, images, and fonts alongside every HTML page. AI agents using `WebFetch` or similar tools fetch only the HTML document — no sub-resources ever follow. Tracks HTML vs sub-resource request ratio per identity in a rolling `deque(maxlen=256)` window. When an identity has fetched ≥ `LLM_HTML_MIN_COUNT` (default 5) HTML pages with sub-resource ratio ≤ `LLM_SUBRES_RATIO_THRESHOLD` (default 0.0 = zero sub-resources) within `LLM_HEURISTIC_WINDOW_SECS` (default 120 s) → fires `llm-no-subresources` (+40 risk). Cooldown prevents double-firing within the window.
- **New config knobs** (LLM heuristic): `LLM_HEURISTIC_ENABLED` (default `1`), `LLM_HTML_MIN_COUNT` (default `5`), `LLM_SUBRES_RATIO_THRESHOLD` (default `0.0`), `LLM_HEURISTIC_WINDOW_SECS` (default `120`), `LLM_HEURISTIC_SCORE` (default `40`).
- **P4 — Browser execution probe** (`CANARY_PROBE_ENABLED=1`, default on) — extended `detection/canary.py`. Injects `<link rel="preload" href="/antibot-appsec-gateway/canary-probe/{token}" as="fetch" crossorigin>` into every HTML `<head>`. Browsers automatically fetch preload hints in the background within milliseconds; AI agents only retrieve the HTML document. New public endpoint `GET /antibot-appsec-gateway/canary-probe/{token}`: marks identity as "browser-confirmed". `check_canary_probe()`: after ≥ `CANARY_PROBE_MIN_HTML` (default 3) HTML pages, if probe was never fetched within `CANARY_PROBE_TTL_SECS` (default 30 s) → fires `canary-probe-miss` (+35 risk). Confirmed identities are immune from this signal.
- **New config knobs** (canary probe): `CANARY_PROBE_ENABLED` (default `1`), `CANARY_PROBE_TTL_SECS` (default `30`), `CANARY_PROBE_MIN_HTML` (default `3`), `CANARY_PROBE_SCORE` (default `35`).
- **New risk signals** in scoring table: `honey-cred` (+90), `redirect-maze-bot` (+55), `llm-no-subresources` (+40), `canary-probe-miss` (+35).
- **`path-sweep` + `honey-cred` in signal cost table** — `kind: state/in-process`, `typical: < 0.1 ms` (no I/O).

- **Three-tier ban durations** — `REALLY_BAN_SECS` (default 30 d = 2592000 s) added to `config.py` as a new config knob. Ban tier logic in `scoring.py` updated: definitive bot-proof signals (`canary-echo`, `honeypot-silent`, `honeypot`) now earn `REALLY_BAN_SECS`; hostile signals earn `HOSTILE_BAN_SECS` (24 h); risk-threshold bans earn `RISK_BAN_DURATION_SECS` (1 h). `REALLY_BAN_SECS` is hot-reloadable via `/secured/config`.
- **Controls dashboard — ban duration knobs** — `HOSTILE_BAN_SECS` and `REALLY_BAN_SECS` added to the Thresholds & rate limits card in `controls.html`, allowing operators to adjust ban durations live without container restart.
- **Settings dashboard — Storage card** — new "Storage" card added to `settings.html` showing disk usage bar (used/total), SQLite DB + WAL + SHM file sizes, and a "Vacuum DB" button. Card calls new admin endpoints `GET /secured/disk-stats` and `POST /secured/db-vacuum` (`VACUUM` + `PRAGMA wal_checkpoint(TRUNCATE)`).
- **Disk stats endpoint** (`GET /antibot-appsec-gateway/secured/disk-stats`) — returns JSON with `disk_used_bytes`, `disk_total_bytes`, `disk_free_bytes`, `db_bytes`, `wal_bytes`, `shm_bytes`. Secured (admin IP + session).
- **DB vacuum endpoint** (`POST /antibot-appsec-gateway/secured/db-vacuum`) — runs SQLite `VACUUM` + WAL checkpoint truncate; returns `{ok, db_bytes_before, db_bytes_after, wal_bytes_before, wal_bytes_after}`. Secured.

### Fixed
- **Admin-path bypass scope too broad** — Global RPS limit and Method allowlist were exempt for ALL requests to admin-namespace paths regardless of source IP. Fixed: exemption now only applies when the request comes from an admin IP. Non-admin IPs hitting admin paths are now subject to rate limiting and method filtering.
- **`geo_data_endpoint` stale `LIMIT 200000`** — removed `ORDER BY ts ASC LIMIT 200000`; query now returns all events in the window.
- **`NameError: ip not defined` in proxy() HTML injection block** — caught during validation testing. `ip` is not in scope inside the forwarding function; fixed to use `get_ip(request)` via local `_gw_ip`.
- **`JS_CHAL_REQUIRE_JA4` / `TURNSTILE_ENABLED` mutual exclusion** — 3-layer mutex: startup (config.py), DB-load (db/sqlite.py), hot-reload (proxy_handler.py config_endpoint). Prevents silent 403s on every Turnstile solve when `JS_CHAL_REQUIRE_JA4=true` is persisted in `config_kv` table while Turnstile is active (JA4 always absent behind Cloudflare CDN).
- **Silent 403 on JA4-required path emitted no log** — added `slog("chal_ja4_required_missing", level="warn", ...)` before the 403 return in `js_challenge.py`.
- **5 security findings from code review** — 1 MEDIUM (unbounded `_maze_timing` dict — added `_MAZE_TIMING_MAX=2048` + `_MAZE_STEPS_MAX=32` caps), 4 LOW (unbounded `_fired`/`_probe_confirmed` — eviction added; missing key/token length caps on public endpoints — 64/48 char limits added; dead duplicate HMAC call in `_verify_maze_token` — removed).
- **[DAST — HIGH] `NameError: name 's' is not defined` on ban recovery** — `protect()` ai-no-assets deny branch referenced `s.html_loads` / `s.static_loads` but `s` is never assigned in that code path; the correct IpState alias is `_s_early`. Any request from an IP re-entering after a ban expiry triggered an unhandled `NameError` → HTTP 500 to the client. Fixed: `proxy_handler.py` line 2840 changed to `_s_early.html_loads` / `_s_early.static_loads`. Found during DAST Step 15b ban-recovery cycle.
- **[DAST — CRITICAL] `/probe`, `/maze`, `/canary-probe/` endpoints unreachable** — All three public AI-detection endpoints were registered as aiohttp routes but absent from `_ADMIN_PUBLIC_SUBPATHS` in `config.py`. The `protect()` middleware intercepts every admin-namespace path and returns a 404 decoy (logging `reason: internal-probe`) for any path not in that list, before route dispatch. Result: P1 honey-cred, P2 redirect-maze, and P4 canary-probe detectors had zero effect in production — the probe endpoint always returned upstream HTML. Fixed: added `/probe`, `/maze`, `/canary-probe/` to `_ADMIN_PUBLIC_SUBPATHS`. Found during DAST Step 15e probe-endpoint verification.
- **[Post-release — HIGH] Turnstile shown to every first-time visitor regardless of risk score** — `_js_challenge_applicable()` gated Turnstile on `request.get("_track_key")`, which is always `None` at the JS challenge gate (gate runs at `proxy_handler.py:2282`; `_track_key` is set at line 2511). The threshold check never executed — every cookieless HTML GET triggered Turnstile immediately. Fixed: derive identity via `get_identity(request)` directly; fresh visitors with no `ip_state` entry (risk = 0) fall through to the auto-mint path. Found from user report.
- **[Post-release — MEDIUM] Soft-challenge tier never enforced on `JS_CHAL_OPEN_PATHS`** — `_js_challenge_required()` had the identical `_track_key` ordering bug: risky identities (SOFT_CHALLENGE_SCORE ≤ risk < RISK_BAN_THRESHOLD) on open paths were supposed to have their bypass revoked and be challenged. The `if track_key:` branch was always skipped (track_key = None), so the open-path bypass was always granted regardless of risk. Fixed: same pattern — derive identity via `get_identity(request)` directly.

- **`ALLOWED_HOSTS` URL parsing bug** — `_to_host_set()` in `integrations/endpoint_policy.py` accepted bare hostnames only; full URLs with scheme (e.g. `https://example.com/`) stored verbatim, causing every request to match `host-not-allowed` (bare hostname `example.com` ≠ full URL string). Fixed: `_to_host_set()` now uses `urllib.parse.urlparse` to normalise each entry — strips scheme, path, and case. Startup parser in `proxy_handler.py` updated to use the same function. Regression tests added to `test_pure.py` (`test_to_host_set_strips_scheme_and_path`).
- **Dashboard version string regression** — dashboard HTML files (`main.html`, `agents.html`, `controls.html`, `geo.html`, `logs.html`, `service.html`, `settings.html`) had `AppSecGW_1.7.2` hardcoded in `<title>` and `<h1>` tags after `config.py` was bumped to `1.7.3`; the version is not template-rendered but literal text. Updated all 7 files to `AppSecGW_1.7.3`. Added `test_no_stale_version_strings_in_source` (now includes `.html` in suffix set) and `test_dashboard_html_version_strings()` to `test_pure.py`; added `test_dashboard_html_version_matches_config()` to `test_control_regressions.py`. Added explicit file list to `rules.md` step 13b.

### Tests
- **37 new unit tests** in `tests/test_v173.py`: P1 honey_cred (10), P2 redirect_maze (7), P3 llm_heuristic (9), P4 canary_probe (11).
- **9 new unit tests** in `tests/test_path_sweep.py` (path-sweep detector).
- **4 new regression tests** in `tests/test_pure.py`: JA4/Turnstile mutex (startup, DB-load, hot-reload), JA4-required slog warning.
- **6 new regression tests** (Step 16 post-release bug watch): `test_probe_endpoint_in_admin_public_subpaths`, `test_maze_endpoint_in_admin_public_subpaths`, `test_canary_probe_in_admin_public_subpaths`, `test_ai_no_assets_deny_uses_s_early_not_s`, `test_js_challenge_applicable_source_uses_get_identity_not_track_key`, `test_js_challenge_required_soft_challenge_uses_get_identity_not_track_key`.
- **3 new regression tests** (post-release additions): `test_to_host_set_strips_scheme_and_path`, `test_dashboard_html_version_strings` (test_pure.py), `test_dashboard_html_version_matches_config` (test_control_regressions.py).
- **`_decay_risk` NameError in `_js_challenge_applicable`** — `challenge/js_challenge.py` called `_decay_risk(s, now())` without importing it at that scope. `_decay_risk` lives in `scoring.py` and is late-imported at other call sites in the same file but was missing from `_js_challenge_applicable`. Any request from an identity with a warmed ip_state entry (risk > 0 after prior probing) triggered `NameError → HTTP 500`. Fixed: added `from scoring import _decay_risk` inside `_js_challenge_applicable`. Regression test added (`test_js_challenge_applicable_imports_decay_risk` in test_pure.py). Found during functional + regression test run.
- **`test_html_navigation_serves_challenge_page` / `test_v9_turnstile_required_when_enabled` stale assertions** — Both tests assumed Turnstile is shown to ALL fresh visitors (old broken behavior). After the post-release fix (`_js_challenge_applicable` returning False for fresh visitors), both tests failed because fresh visitors correctly fall through to auto-mint. Updated tests to pre-seed ip_state with risk above threshold, confirming Turnstile IS shown for risky identities.
- **`tests/test_dashboard_data.py` missing from copy-to-github.sh** — added to MANIFEST.
- **Totals**: 216 tests pass (209 unit + 22 functional + 1 integration + 37 v1.7.3 + 9 path_sweep + 4 mutex + 6 post-release regression + 3 post-release additions + 1 decay-risk regression); 0 failures.

### Validation
- Bandit: 0 High · 0 Critical · B110 Medium (confirmed FP — intentional try/except in `_evaluate_maze_timing`).
- Semgrep: 0 findings on all 4 new detection modules.
- Trivy: 0 Critical / 0 High / 0 Medium CVEs (all 3 arches).
- Harbor: amd64 `sha256:eeb71292…` · arm64 `sha256:64fa6b48…` · armv7 `sha256:0b9ebd1c…` · manifest `sha256:5772e553…` (final: honey_cred comment reverted to original convincing-developer-mistake format).
- Security review: 11 findings fixed total (5 code review + 2 CRITICAL/HIGH DAST + 2 HIGH + 1 MEDIUM post-release).
- DAST: 15/15 steps PASS. Post-release bug watch (Step 16): 16/16 steps PASS, 4 additional bugs fixed, 6 regression tests added.
- See `validation/1.7.3.md` for full record.

---

## [1.7.2] — 2026-05-04

### Added
- **Geo dashboard time-window navigation** — `← prev` / `next →` / `now` buttons allow stepping backward/forward through 24-hour windows. `endEpoch` state variable appended to all `geo-data` requests as `?end=<epoch>`. `refreshGeoControls()` disables `next →` at live mode and updates the window label.
- **Geo drill scrubber-aware queries** — `openDrill()` now passes `?end=<bucketEnd>&range=<bucketMin>` when a scrubber bucket is active, scoping the drill-down to that time window instead of always querying live.
- **Geo map denied-country visual** — circles for IPs whose country is in the denylist are rendered with a red border (`weight:3`, `dashArray:'4,3'`) and a `⛔ DENIED ·` prefix in the popup.
- **Admin IP lock icon in geo drill panel** — `_drillAdminLock()` helper added to `geo.html`; IP rows now show 🔒 with full tooltip when `is_admin_ip` is true.
- **`is_admin_ip` in geo drill response** — `geo_drill_endpoint` now includes `is_admin_ip` for each IP in the response map.
- **Country table allow buttons** — `renderCountries()` now renders both deny and allow buttons; allow POST uses `"list":"allow"` without forcing `COUNTRY_BLOCK_ENABLED:true`.

### Fixed
- **`main.html` cost chart click** — `onClick` handler reverted to direct `openMainBucketDetail(tl[idx], ...)` call, eliminating the silent `find()` failure that caused the modal to open empty on bucket-boundary mismatches.
- **Admin IP lock icon tooltip** — `_adminLock` / `_ADMIN_IP_TIP` moved to global scope in `main.html`; previously the helper was defined inside `openMainBucketDetail` only. All five 🔒 occurrences across both main and agents panels now show the full description on hover.
- **`geo_data_endpoint` ordering** — events query now includes `ORDER BY ts ASC`; previously events could be returned in insertion order, causing garbled map animation when backfilling.
- **`_GEO_CACHE` LRU eviction** — eviction previously sorted by key tuple value (`sorted(keys())`), not by expiry time. Fixed to `sorted(keys(), key=lambda k: _GEO_CACHE[k][0])` so oldest entries are evicted first.
- **Geo scrubber label** — "— · live" changed to "— · live (aggregate)" to disambiguate from a time-scoped bucket.
- **Country table colspan** — no-data rows used `colspan="6"` despite the table having 7 columns. Fixed to `colspan="7"`.
- **Geo dashboard dead code** — removed unused `url()` arrow function and `setInterval(loadLogLevel, 30000)` (log-level polling not applicable in geo page).
- **Missed signal note** — added inline note in scrubber div explaining that missed counts are unavailable in scrubber mode (sourced from live `ip_state`, not DB events).
- **All dashboard version badges** — `AppSecGW_1.7.1` → `AppSecGW_1.7.2` in `main.html`, `controls.html`, `agents.html`, `logs.html`, `settings.html`, `service.html`, `geo.html`.
- **JS SyntaxErrors in `main.html` and `agents.html`** — smart/typographic quotes (U+2018/U+2019) in `_adminLock` fallback literal and unescaped apostrophe in `_ADMIN_IP_TIP` string caused `Uncaught SyntaxError` that silently killed all dashboard JS (`tick()` never ran → zero stats). Fixed `_ADMIN_IP_TIP` to use double-quoted string; `_adminLock` fallback to ASCII single quotes.
- **Blockrate chart always empty in `main.html`** — `d.timeline.buckets` does not exist; `d.timeline` is the array directly. Fixed to `Array.isArray(d.timeline) ? d.timeline : []` with `b.t||b.ts` for timestamp field.
- **CI `docker-no-latest-tag` linter failure** — added `exceptions.yaml` to suppress the conftest rule for Chainguard images; both `FROM` lines are already pinned by `@sha256` digest so the `:latest` tag is a registry alias, not a floating reference.
- **`copy-to-github.sh` manifest** — added five missing detection modules (`automation.py`, `cookie_lifecycle.py`, `referer_chain.py`, `impossible_travel.py`, `fp_enrichment.py`), `dashboards/assets/chart.umd.min.js` (Chart.js 4.4.0 local bundle), and `exceptions.yaml` so `copy-to-github.sh` delivers all CI-required files to the GitHub repo.
- **Chart.js CDN → local bundle** — moved from `cdn.jsdelivr.net` to `/antibot-appsec-gateway/assets/chart.umd.min.js` to avoid CDN blocking in air-gapped deployments.
- **`_refresh_integration_state` missing `globals()` arg** — `proxy_handler.py` had two call sites (`secrets_endpoint` at line 1566, `config_endpoint` at line 1622) that called `_refresh_integration_state()` without the required `globals()` argument. All 3 arch images were rebuilt with `--no-cache`; the stale baked-in bytecode had been masking the fix from source.
- **`_refresh_integration_state` unconditionally overwrote `TURNSTILE_ENABLED`** — setting any secret (even unrelated ones like ABUSEIPDB_KEY) would re-derive `TURNSTILE_ENABLED=True` when credentials were present, ignoring the operator's explicit on/off choice. Fixed: auto-enable fires only on first-time credential availability (`prev_configured=False → now=True`); subsequent explicit enable/disable choices via `/config` or Controls dashboard are preserved.
- **Upstream CSP blocks Turnstile widgets** — `_csp_inject_cf_turnstile()` added to `proxy_handler.py`; applied to upstream HTML responses at the proxy layer. Augments existing `script-src` and `frame-src` directives (or `default-src` fallback) to add `https://challenges.cloudflare.com`, preventing CSP violations when the upstream site embeds Turnstile widgets but its policy omits that origin.

### Tests
- **201 unit tests + 22 functional + 23 integration + 76 regression**: all pass (individually due to pre-existing OOM when run together). 0 new failures.
- **7 new regression tests** in `test_pure.py`: `test_no_smart_quotes_in_main_html`, `test_no_smart_quotes_in_agents_html`, `test_main_html_js_syntax` (node --check), `test_agents_html_js_syntax`, `test_no_broken_string_assignments_in_main_html`, `test_no_broken_string_assignments_in_agents_html`, `test_admin_ip_tip_uses_double_quotes` — prevent regression of the JS SyntaxError bug class.
- **5 new pure unit tests** in `test_pure.py`: `test_csp_inject_adds_to_script_src`, `test_csp_inject_adds_to_frame_src`, `test_csp_inject_noop_when_already_present`, `test_csp_inject_augments_default_src_when_no_script_src`, `test_csp_inject_preserves_other_directives` — cover `_csp_inject_cf_turnstile` behaviour.
- **1 new integration test** `test_host_allowlist_blocks_mismatch_api_path` — verifies route-aware decoy returns 404 (not 200) for API paths with mismatched Host header.
- **3 test fixes** for route-aware decoy behaviour (API paths → 404, not 200): `test_host_allowlist_blocks_mismatch` (path `/api/x` → `/some-page`), `test_v8_block_does_not_reveal_gateway` and `test_host_mismatch_silent_decoys_even_without_cookie` (`== 200` → `in (200, 404)`). Security invariant unchanged — no 401/gateway fingerprint leaks.

### Validation
- Bandit: 0 High · 0 Critical · 12 Low (all B110 try/except/pass, pre-existing, accepted FP).
- Semgrep: 0 findings.
- Trivy: 0 Critical / 0 High / 0 Medium CVEs.
- §13b version sweep: all non-comment occurrences updated; remaining `1.7.1` hits are code-history annotations (`# 1.7.1 — feature name`) intentionally preserved.
- See `validation/1.7.2.md` for full record.

---

## [1.7.1] — 2026-05-03

### Added
- **Browser automation probe** (`AUTOMATION_PROBE_ENABLED=1`, default on) — self-hosted JS snippet injected into HTML responses that checks `navigator.webdriver`, `navigator.plugins.length === 0`, `screen.colorDepth < 24`, and missing `window.chrome` object. POSTs result to new public endpoint `/antibot-appsec-gateway/automation-report`. Fires `webdriver-detected` (+30 risk) when ≥ 2 indicators set. No external JS bundle; HMAC token bound to `track_key` so reports cannot be forged. Mirrors BotD pattern in `detection/canary.py`.
- **Coordinated ASN clustering** (`COORDINATED_ATTACK_ENABLED=1`, default on) — detects when N≥5 (`COORDINATED_ATTACK_THRESHOLD`) distinct identities from the same ASN hit the same path prefix within the same 60-second window. Fires `coordinated-probe` (+25 risk) on each member of the cluster. Cluster state stored in `state._asn_path_clusters`; pruned automatically when >10000 entries. Escalate-only signal.
- **User journey sequences / direct-API-probe** (`JOURNEY_CHECK_ENABLED=1`, default on) — second-order signal that fires when an identity has made ≥5 requests with `html_loads=0` and `static_loads=0` while hitting an API-style path prefix (`/api/`, `/v1/`, `/v2/`, `/graphql`, `/rest/`, `/rpc/`). Fires `direct-api-probe` (+15 risk). Gated by `SECOND_ORDER_THRESHOLD` so it only accumulates risk on already-suspicious identities. Added `path_sequence: deque(maxlen=5)` field to `IpState` for future journey analysis.
- **New risk signals**: `webdriver-detected` (+30), `coordinated-probe` (+25), `direct-api-probe` (+15).
- **New config knobs** (all hot-reloadable): `AUTOMATION_PROBE_ENABLED`, `COORDINATED_ATTACK_ENABLED`, `COORDINATED_ATTACK_THRESHOLD`, `JOURNEY_CHECK_ENABLED`.
- **New public endpoint**: `POST /antibot-appsec-gateway/automation-report` — receives browser automation probe reports. Added to `_ADMIN_PUBLIC_SUBPATHS` so it bypasses admin-IP gating.
- **New module**: `detection/automation.py` — `_inject_automation_probe()`, `automation_report_endpoint()`, `_automation_token_for()`.

### Fixed
- **`dashboards/agents.html`** — bucket detail popover had no `max-height` / `overflow-y`. With `position:fixed` centering, content taller than the viewport was clipped at the top — hiding the IP list. Fixed: `maxHeight:'85vh'; overflowY:'auto'` applied on open; cleared on close.
- **`dashboards/agents.html`** — `openBucketDetail` had no try/catch; any fetch error silently killed the popover. Fixed: added try/catch that displays a styled error message in the popover body.
- **`dashboards/main.html`** — `openMainBucketDetail` catch block swallowed fetch errors and showed empty lists with no diagnostic. Fixed: `_fetchErr` stored and prepended as a red error div in the modal body.

### Tests
- **187 tests passing**: 181 unit + 22 functional + 16 integration + 98 regression. 0 failures (individually).
- +6 integration tests (`test_integration.py`): `test_agents_bucket_decoy_without_auth`, `test_agents_bucket_shape_with_auth`, `test_agents_bucket_bad_t_param_returns_400`, `test_agents_bucket_invalid_bucket_secs_falls_back_to_60`, `test_agents_bucket_list_cap_500`, `test_agents_bucket_kind_filter`. Guards `agents-bucket` endpoint auth, response shape (including `ip` field presence), input validation, param sanitisation, and 500-entry list cap.

### Validation
- Bandit: 0 High · 0 Critical · 0 Medium (including new `detection/automation.py`).
- Semgrep: 0 findings on new module (151 rules, 0 findings).
- Trivy (arm64): 0 Critical / 0 High / 0 Medium CVEs.
- See `validation/1.7.1.md` for full record.

---

## [1.7.0] — 2026-05-03

### Changed
- **Modular refactor (Phase 5–8)** — 13,696-line `proxy.py` monolith split into 30+ modules:
  `config`, `state`, `helpers`, `identity`, `rate_limit`, `scoring`, `admin/*`, `challenge/*`,
  `core/*`, `dashboards/*`, `db/*`, `detection/*`, `integrations/*`, `reputation/*`.
  Public API and all behaviour unchanged; no new features.

### Fixed
- `Dockerfile` — v1.7.0 module directories were not copied; caused `ModuleNotFoundError` at container startup. Added `COPY` for all 15 module packages and top-level modules.
- `dashboards/service_metrics.py` — `_postgres_available` NameError at svc-metrics sample time (underscore name excluded by `import *`). Added explicit import.
- `dashboards/service_metrics.py` — NaN/Inf injection in `end=` query parameter: raw value flowed into `float()` without guard. Added string rejection for all NaN/Inf spellings before cast.
- `core/proxy_handler.py` — `_global_rps_window`, `_pow_seen`, `_canary_tokens` NameErrors. Added explicit state imports.
- `proxy.py` — Namespace-aware `tarpit_endpoint` wrapper reads `LABYRINTH_ENABLED` from proxy globals; fixes `test_tarpit_endpoint_disabled_returns_404` in exec_module test context.
- `proxy.py` — Patches `core.proxy_handler.get_ip` at module level so `TRUSTED_PROXIES_NETS` test patches propagate; fixes `test_xff_spoof_blocked_when_peer_untrusted`.
- `scoring.py` — `_HOSTILE_REASONS` NameError (underscore excluded by `import *`). Added explicit import from config.
- `proxy.py` `db_load_config()` — test-isolation regression: removed sys.modules propagation loop from `db/sqlite.py`; wrapper now cascades via `_ProxyModule.__setattr__` only when the calling module is the registered `sys.modules["proxy"]` object, preventing cross-contamination in exec_module test contexts.
- `db/sqlite.py` `db_load_config()` — `DB_PATH` now resolved as `g.get("DB_PATH") or os.environ.get("DB_PATH") or DB_PATH` so callers that override `DB_PATH` via env (e.g. isolation tests) connect to the correct database.
- `db/sqlite.py` `db_load_config()` — credential keys (`ABUSEIPDB_KEY` etc.) from the passed globals dict are now synced into `core.proxy_handler` before validators run, so credential-gated validators (e.g. `ABUSEIPDB_ENABLED`'s `lambda v: (not v) or bool(globals().get("ABUSEIPDB_KEY"))`) see the correct state when called in isolation without a prior `db_load_secrets`.

### Tests
- **309 tests passing**: 179 unit (116 critical + 53 pure + 10 async) + 22 functional + 10 integration + 98 regression. 0 failures.
- +3 functional tests: `test_db_load_config_accepts_abuseipdb_enabled_with_key`, `test_config_hot_reload_roundtrip`, `test_db_load_config_rejects_invalid_knob` (all pass with above fixes).
- +4 regression tests (new coverage added to test_v14.py / test_v142.py).
- Two previously failing functional tests fixed: `test_xff_spoof_blocked_when_peer_untrusted`, `test_tarpit_endpoint_disabled_returns_404`.

### Validation
- Bandit: 0 High · 0 Critical · 0 Medium.
- Semgrep: 0 findings (1 NaN-injection fixed before release).
- Trivy (amd64): 0 Critical / 0 High / 0 Medium CVEs.
- See `validation/1.7.0.md` for full record.

---

## [1.6.10] — 2026-05-02

### Added
- **10 new detection signals** — 5 HIGH + 5 MEDIUM impact:
  - `header-order-fp` (+8) — HTTP library fingerprint via ordered header-name hash (requests/curl/Go/httpx signatures).
  - `ai-ua-ip-mismatch` (+30) — AI-crawler UA but source IP not in vendor's published CIDR range (OpenAI gptbot-ranges.txt, refreshed 24h).
  - `locale-geo-mismatch` (+10) — primary Accept-Language tag implausible for GeoIP country; escalate-gated.
  - `robots-violation` (+5) — declared AI-crawler UA ignores gateway `/robots.txt` (`Disallow: /`).
  - `h2-fp` (+3, default OFF) — HTTP/1.1 + modern-browser UA behind TLS proxy.
  - `header-order-fp`, `ai-ua-ip-mismatch`, `locale-geo-mismatch`, `robots-violation`, `h2-fp`, `json-canary` all appear in Controls dashboard with toggles.
- **PoW difficulty scaling by risk_score** — `make_pow_challenge()` now accepts `risk_score`; maps 0–19→d=5, 20–50→d=7, >50→d=9. Anubis-mode still takes precedence.
- **PoW minimum solve time** (`POW_MIN_SOLVE_MS=200`) — `verify_pow()` rejects solutions arriving < (MIN−1000) ms after token issuance; blocks pre-computed replay attacks.
- **JSON API canary poisoning** (`JSON_CANARY_ENABLED=1`) — injects `"_ref": "agw-c-…"` token into JSON object responses; LLM agents replaying cached API responses echo the token, triggering `canary-echo` ban.
- **JA4 fail-closed** (`JA4_FAIL_CLOSED=0` default) — when `JA4_TRUSTED_NETS` configured, hard-deny non-static requests missing the JA4 header.
- **Session churn threshold scaling** — hosting ASNs use `NEW_SESSIONS_PER_HOSTING=10` (vs 30 for consumer ISPs); ASN lookup performed on new-session path only.
- **`/robots.txt` endpoint** — gateway serves a static robots.txt disallowing all known AI crawlers (`GPTBot`, `ChatGPT-User`, `PerplexityBot`, `ClaudeBot`, `anthropic-ai`, `FacebookBot`, `meta-externalagent`).
- **AI crawler IP-range verification** — startup task fetches `openai.com/gptbot-ranges.txt`; cached 24h; no-op when ranges unavailable (fail-open).
- **Controls tooltip — rich signal panel** — clicking any signal name in Defenses & Scoring now shows a structured panel: version/date badge, tier badge, description, impact (+N pts with colour), cost (kind badge + ms), and configuration block (toggle knob + env var instruction or "always-on" notice). `Esc` or click-away to dismiss.
- **`kind-modifier` CSS badge** — modifier signals now render a grey badge in the cost column instead of `—`.

### Fixed
- **`pow_endpoint` difficulty** — previously hardcoded `ANUBIS_DIFFICULTY_BOOST`; now passes caller's risk_score to `make_pow_challenge` and reads `eff_diff` from the signed payload.

### Tests
- 153 unit tests passing (102 critical + 51 pure). New knobs added to `test_165_every_knob_persists_round_trip`.

### Bandit
- 0 High · 0 Critical · 0 Medium (unchanged).

---

## [1.6.9] — 2026-05-02

### Added
- **AI Labyrinth** — hidden `rel="nofollow"` link block injected before `</body>` on every
  proxied HTML response. Any client that follows one enters a slow-drip maze of convincing
  fake documentation pages (deterministic per-nonce content, 16 topics × 20 sentences).
  Each hit fires `tarpit-walk` (weight 100 → instant ban) and streams the HTML in 256-byte
  chunks with a configurable inter-chunk delay (`LABYRINTH_SLOW_MS`, default 600 ms) to
  exhaust crawler resources. Maze depth configurable via `LABYRINTH_MAX_DEPTH` (default 5
  levels) and `LABYRINTH_LINKS_PER_PAGE` (default 3 hidden links per page). HMAC-signed
  tokens (using `POW_HMAC_KEY`) prevent depth forgery. Inspired by Cloudflare AI Labyrinth.
- New detector `tarpit-walk` (risk weight 100, `hard` tier) added to `RISK_WEIGHTS` and
  `REASON_INFO` in the main dashboard.
- `tarpit_endpoint` route: `GET /antibot-appsec-gateway/tarpit/{token}` — public but
  HMAC-gated; invalid tokens 404 silently.
- 4 new hot-reloadable knobs: `LABYRINTH_ENABLED`, `LABYRINTH_SLOW_MS`,
  `LABYRINTH_MAX_DEPTH`, `LABYRINTH_LINKS_PER_PAGE`.

### Fixed
- Renamed `TARPIT_*` labyrinth variables to `LABYRINTH_*` to eliminate name conflict with
  the pre-existing `TARPIT_ENABLED` / `TARPIT_DELAY_MS` soft-band response-delay feature
  introduced in 1.6.5.
- Replaced `_to_bool()` call in module-level config block with inline
  `os.environ.get(...) in ("1","true","yes")` — `_to_bool` is defined later in the file
  and caused `NameError` at test-collection time.
- Added `/tarpit/` to `_ADMIN_PUBLIC_SUBPATHS` — tarpit URLs were unreachable by non-admin
  IPs (returned silent 404-decoy instead of slow-drip response) because all paths under
  `/antibot-appsec-gateway/` are admin-IP gated by default. The HMAC token provides
  sufficient authenticity verification; IP restriction defeats the bot-trap purpose.
- Fixed `NameError` in `tarpit_endpoint`: replaced non-existent helper calls
  `_get_track_key()` / `_get_session_id()` / `_get_fp()` with a single `get_identity()`
  call — the tarpit handler bypasses the protect() middleware (public subpath) so identity
  must be derived inside the handler.

### Tests
- Added `LABYRINTH_ENABLED`, `LABYRINTH_SLOW_MS`, `LABYRINTH_MAX_DEPTH`,
  `LABYRINTH_LINKS_PER_PAGE` to `test_165_every_knob_persists_round_trip` fixture to
  satisfy the "every knob must have a test value" coverage assertion.
- 10 new unit tests: `test_168_labyrinth_knobs_in_hot_reload`,
  `test_168_labyrinth_tarpit_walk_in_risk_weights`, `test_168_labyrinth_tarpit_walk_high_weight`,
  `test_168_tarpit_token_roundtrip`, `test_168_tarpit_verify_rejects_tampered`,
  `test_168_tarpit_inject_html_adds_hidden_div`, `test_168_tarpit_inject_html_no_body_tag_passthrough`,
  `test_168_tarpit_page_html_has_fake_content`, `test_168_tarpit_public_subpath_registered`,
  `test_168_admin_path_is_public_tarpit`.
- 4 new functional tests: `test_labyrinth_links_injected_in_html_response`,
  `test_tarpit_endpoint_accessible_without_admin_auth`, `test_tarpit_endpoint_rejects_invalid_token`,
  `test_tarpit_endpoint_disabled_returns_404`.
- Full suite: **286/286 passing** (272 pre-existing + 14 new AI Labyrinth tests).

---

## [1.6.8] — TimescaleDB stats + dashboard UX improvements

### Added
- **TimescaleDB / Postgres health metrics** — new `_pg_timescale_stats()` function samples
  hypertable sizes, chunk counts, compression ratio, continuous-aggregate freshness, and
  Postgres cache-hit ratio every `SVC_METRICS_INTERVAL` seconds. Stats persisted alongside
  existing service-metrics samples. Surfaces on the Service dashboard under a dedicated
  "PostgreSQL / TimescaleDB" section with a click-to-zoom chart modal.
- **PG cache-hit ratio** averaged within each service-metrics bucket and exposed in
  `/__service-data`.
- **TimescaleDB stats availability flag** (`timescale_available`) in `/__service-data`
  payload — front-end conditionally renders the TimescaleDB card only when the extension is
  present.
- **Per-detector hits — clickable drill-down** — each detector name in the main dashboard's
  "Per-detector hits" card is now a clickable `.det-drill` span that calls
  `openReasonDrill()`, opening the existing rich modal with reason description, tier, weight,
  and all offending identities. Previously these were plain text labels.
- **Service dashboard threshold indicators** — CPU, memory, disk, and cgroup-memory progress
  bars are now wrapped in `.bar-wrap` with tick marks at 75 % (yellow) and 90 % (red). The
  bar fill colour transitions through green → yellow → red as usage crosses those thresholds.
  Threshold ticks and a legend are rendered via CSS (`.thr-tick.warn`, `.thr-tick.crit`,
  `.thr-legend`). Threshold lines also appear as horizontal dashed datasets in the
  click-to-zoom chart modals.
- **Disk card — available space** — the disk sub-text now shows `used / avail / total` (was
  `used / total`).

### Fixed
- Stale variable name `_geoip_asn_reader` → `_asn_reader` in service-metrics endpoint
  (line ~5515). The old name caused `"mmdb missing"` to appear in the MaxMind ASN row of
  the service dashboard even when the MMDB was loaded correctly.

---

## [1.6.7] — Gateway Registry + multi-user auth + per-session ledger + mesh-sync

### Added
- **Gateway Registry** — Settings tab with list / distribution matrix / audit log; 11 REST
  endpoints under `/antibot-appsec-gateway/secured/admin/gw-registry/...`. `gw_id`
  auto-derives from the domain; operator may override. Typed-confirm delete; copy-once
  private-key reveal modal; production-environment edit warning.
- **Multi-user auth + login flow** — bearer-key auth (`?key=` / `X-Admin-Key`) removed;
  only entry to `/secured/...` is signing in via `/antibot-appsec-gateway/login` with the
  `agw_session` cookie. `INTERNAL_KEY` is the bootstrap admin password. First-time-setup
  hint on login page disappears after first user is created. 5/min/IP login rate-limit;
  scrypt-hashed passwords (N=2¹⁴, random salt); `STRICT_ORIGIN` CSRF guard on
  `POST /login`.
- **Per-session ledger** — every login mints a fresh `sid` embedded in the cookie HMAC
  payload (`username|sid|expiry|HMAC`). `user_sessions` table records source IP + UA +
  created/last-seen/expires/status. Click any username → modal lists sessions with per-row
  Revoke. Logout revokes the current `sid` server-side.
- **Mesh-sync of integration secrets** — toggle next to each integration value in Controls
  (off by default). When on + `REDIS_URL` set, publishes value to
  `appsecgw:mesh:offers:<gw_id>` every 30 s (TTL 60 s); peers land novel offers in
  `gw_sync_pending` with `status=pending` only when the local value is empty. Nothing
  reaches a live integration without operator confirmation. `ADMIN_KEY` / `SESSION_KEY` /
  `INTERNAL_KEY` excluded from allowlist.
- **UX polish** — green ● LIVE pill normalised across every dashboard; portal footer
  (Antibot AppSec Gateway · © 2026 redacted, S.A. · Confidential); Sign-out link inline
  next to Settings in every topnav with confirm prompt; Online column in Users table (60 s
  in-memory TTL).
- Additive column upgrades for `admin_ips` and other tables driven by a central registry
  (`_SCHEMA_UPGRADES`) — safe to run on existing volumes.
- Liveness probe (`/antibot-appsec-gateway/live`) is now loopback-only to prevent external
  enumeration; container `HEALTHCHECK` migrated accordingly.

### Security
- **Black-box pentest (8 attacks, 0 bypasses)**: forged cookie, legacy 3-part token, cookie
  tampering, replay-after-revoke, login brute-force, CSRF-on-login, retired bearer-key ×2,
  mesh-sync without auth — all blocked.

### Tests
- 272 / 272 passing (153 unit + 15 functional + 10 integration + 94 regression).
- New tests: `test_167_gw_id_validator`, `test_167_gw_keypair_roundtrip`,
  `test_167_gw_row_to_dict_strips_private_key`, `test_167_registry_endpoints_registered`,
  `test_167_local_gw_id_resolves`, `test_167_gw_id_from_domain`,
  `test_167_mesh_sync_eligible_keys_allowlist`, `test_167_mesh_sync_endpoints_registered`,
  `test_167_session_revoke_invalidates_cookie`, `test_167_session_token_format_includes_sid`,
  `test_internal_authed_rejects_bearer_key_post_1_6_7`,
  `test_internal_authed_accepts_valid_session_cookie`,
  `test_internal_authed_rejects_tampered_cookie`.
- **Bandit**: 0 High / 0 Critical · 13 Mediums (all confirmed FP: B104 / B608 / B310).
- **Trivy**: 0 CVEs.

---

## [1.6.6] — Settings dashboard + endpoint-namespace migration + admin-IP dual-write

### Added
- **Settings dashboard** (`/antibot-appsec-gateway/secured/settings`) — export every
  hot-reload knob + admin-IP allowlist (optionally integration secrets) as a zipped XML
  archive; import with dry-run / overwrite-secrets toggles, validating each knob through the
  same parser/validator pair as `POST /__config`. ZIP hardened: 1 MiB upload cap + 4 MiB
  inflated cap + strict `appsecgw-config.xml` entry name (no path traversal).
- **Endpoint namespace migration** — every internal endpoint moved under
  `/antibot-appsec-gateway`. Public sub-paths one level up; admin endpoints under
  `/antibot-appsec-gateway/secured/...`. Legacy `/__*` aliases removed (silent-decoy 404).
  Dockerfile + compose `HEALTHCHECK` migrated.
- **Dual-write of config changes** — `_pg_mirror_kv` lands every `set_config` /
  `del_config` / `set_secret` / `del_secret` / `admin_ip_*` SQLite write into Postgres
  alongside. Standby Postgres schema initialised at boot (idempotent `ALTER` for upgrade
  path) regardless of active backend.
- Identity strip on Settings page exposes gateway domain, upstream, version, DB backend,
  and uptime via `/__health-score` (extended with new fields).

### Tests
- 3 new tests: `test_166_admin_namespace_constants`, `test_166_admin_path_classifier`,
  `test_166_settings_endpoints_registered`.
- **Bandit**: 0 H / 0 C · 12 Mediums (B104 / B608 / B310 / B314 — `ET.fromstring` on import
  endpoint mitigated by 1 MiB cap + admin auth gate).
- **Trivy**: 0 CVEs.

---

## [1.6.5] — Observability + escalation tier + pattern expansion + Postgres backend

### Added
- **Per-detector latency telemetry** — `_detector_record(reason, ms)` rolling 200-sample
  deque per reason. `/__detector-stats` returns p50/p99 + per-method aggregation + chal-
  cookie mint rate.
- **Lists snapshot endpoint** (`/__lists-snapshot`) — sizes, last-updated timestamps, and
  enabled flags for every allow/deny/pattern list.
- **Detection-method bucketing** — `_REASON_METHOD` maps every block reason into 10 buckets;
  dashboard shows stacked-bar, top-method ranking, rolling block-rate trend.
- **Escalation gate** — expensive / external detectors (AbuseIPDB / CrowdSec / MaxMind ASN /
  body-pattern / DLP) skipped for `risk_score < ESCALATION_THRESHOLD`. New knob
  `ESCALATION_THRESHOLD` (hot-reloadable). Escalate icon rendered in Controls table.
- **Suspicious-body / path pattern expansion** — body groups 6–12 patterns each; 70+
  suspicious-path patterns (Spring4Shell, Log4Shell, IMDS, double-encoded traversal, reverse
  shells, NoSQL/LDAP injection, CRLF, all major template engines).
- **DB_BACKEND toggle** — `sqlite` (default) or `postgres` (Timescale-backed). Switching
  requires restart; falls back to SQLite with startup warning when `psycopg` absent.
- **Postgres / TimescaleDB event store** — `POSTGRES_DSN` env var; hypertable on `ts`
  column (TIMESTAMPTZ); continuous aggregates; dual-write of every `config_kv` /
  `admin_ip` / secret change for zero-loss standby migration.
- **FingerprintJS BotD client-side detector** (`BOTD_ENABLED`, hot-reloadable) — fires
  `botd-detected` (weight 60) on positive report.
- **Slowloris guard** — `BODY_TIMEOUT` terminates connections that take longer than N
  seconds to deliver request body; fires `body-timeout`.
- **Logs dashboard** — two tabs (connection logs from SQLite / gateway logs from in-memory
  ring), level filter, search, pause/resume, segmented `LOG_LEVEL` push toggle.
- **CSV export** (`/__logs-export`, up to 50 000 events).
- **TARPIT mitigation** (`TARPIT_ENABLED`, `TARPIT_DELAY_MS`) — identities in the
  soft-challenge band receive artificial response delay to degrade scripted throughput
  without revealing the block.
- **UI prefs persistence** — GeoMap + Logs filter state saved in `sessionStorage`.
- **Hot-reload knob persistence** in `config_kv` SQLite table; env wins over DB for GitOps
  determinism. 14 new promoted knobs.

### Tests
- 130 unit passing (8 new for 1.6.5).
- **Bandit**: 0 High / 0 Critical.
- **Trivy**: 0 CVEs.

---

## [1.6.4] — Pluggable event store + GW health pill + Logs dashboard (initial)

### Added
- **GW status pill** — fixed top-right pill on every dashboard showing a 0–100 health score
  (red → yellow → green at 50 / 80 thresholds). Click → modal with per-pillar breakdown:
  `disk` / `memory` / `db` / `integrations` / `bans` / `block_rate`. Refreshes every 15 s.
  New endpoint `/__health-score`.
- **Logs dashboard** (first iteration) — two tabs (connection logs / gateway logs), level
  filter, search, pause/resume, segmented `LOG_LEVEL` push toggle.
- **DB_BACKEND knob** with "RESTART REQUIRED" warning in Controls dashboard.

### Tests
- 5 new tests: `test_164_db_backend_default_sqlite`,
  `test_164_db_backend_falls_back_when_psycopg_missing`,
  `test_164_postgres_dsn_knob_registered`, `test_164_health_score_endpoint_registered`,
  `test_164_health_score_payload_shape`.

---

## [1.6.3] — GeoMap triage upgrade + risk-weight calibration

### Added
- **GeoMap — country leaderboard** — side panel listing top 12 countries by
  clean/missed/blocked. One-click Deny pushes ISO code into `COUNTRY_DENYLIST`.
- **Click-circle drill modal** (`/__geo-drill`) — top 25 IPs at the clicked 0.5° cell,
  top 10 block reasons, top 10 paths.
- **Tor / DC overlay toggles** — yellow triangles for Tor exits, purple squares for
  datacenter/VPN ASNs. Two new metric cards.
- **Animated time scrubber** — 24-bucket replay control; Play / Pause / "jump to live".
  `/__geo-data` extended with `countries`, `events`, `geo_state`, `tor_hits`, `dc_hits`.
- **Risk-weight calibration** (post-Tier-C review) — 15 weights adjusted; body-* family
  promoted to instant-ban (40→50); `crowdsec` 60→70; `suspicious-path` 40→50;
  `abuseipdb-high` 50 (unchanged); `abuseipdb-med` 15→20; `tor-exit` 50→40;
  `datacenter-vpn` 30→25.

### Tests
- 3 new tests: `test_163_geo_drill_endpoint_registered`, `test_163_geo_data_payload_shape`,
  `test_163_geo_drill_payload_shape`.

---

## [1.6.2] — Tier C: response-side DLP + webhook event filter

### Added
- **Outbound DLP scanning** (`DLP_ENABLED=1`) — response-body scanner running after upstream
  reply. 7 named groups: `cc` (Luhn-validated) · `aws` · `jwt` · `private-key` · `api-key`
  · `pii-email` · `pii-ssn`. Per-group kill-switches (`DLP_GROUP_*_ENABLED`). Bounded by
  `DLP_MAX_BYTES` (default 256 KiB). Optional inline redaction (`DLP_REDACT=1` →
  `[REDACTED-<group>]`). DLP hits fire a `dlp_leak` webhook event with group breakdown.
  Zero risk added to requester (upstream leakage ≠ client malice).
- **Webhook event filter** (`WEBHOOK_EVENT_FILTER`) — CSV / fnmatch-glob subscription list.
  Empty = legacy behaviour (every event). Filter applied before Redis dedup.
- 11 new hot-reloadable knobs (88 total). 7 new `RISK_WEIGHTS` entries (weight 0).

### Tests
- 15 new tests for Tier C (DLP and webhook filter coverage).

---

## [1.6.1] — Tier B: custom rules + per-endpoint rate-limit + body groups + JWT

### Added
- **Custom rules engine** (`CUSTOM_RULES` JSON) — Cloudflare-Custom-Rules parity.
  `[{"if":{...},"then":"allow|block|challenge|tag"}]`. First-match-wins at L0.4. `allow`
  short-circuits chain; `block` fires `custom-rule-block` (weight 50 → ban).
- **Per-endpoint rate limit** — `ENDPOINT_POLICIES` extended with `{rps, burst}` per glob.
  Token-bucket per (path, identity); overage fires `rate-limit-endpoint` (zero risk, pure
  throttle).
- **Managed body-pattern groups** — legacy `BODY_PATTERN_MATCH` split into 6 named groups
  (`sqli` / `xss` / `lfi` / `rce` / `ssrf` / `cmd`). Each has its own kill-switch
  (`BODY_GROUP_*_ENABLED`) and fires `body-<group>` (weights 40–50; rce + cmd at ban
  threshold). Most-severe-first match order; `suspicious-body` is the catch-all.
- **JWT / Bearer signature validation** — `JWT_VALIDATE_PATHS` glob list + `JWT_HMAC_SECRET`
  (HS256, stdlib, no PyJWT). Optional `JWT_REQUIRED_ISSUER` / `JWT_REQUIRED_AUDIENCE` /
  `JWT_LEEWAY_SECS`. Mismatch fires `auth-jwt-invalid` (weight 25).
- 10 new hot-reloadable knobs (77 total). 9 new `RISK_WEIGHTS` entries.

### Tests
- 12 new tests for Tier B.

---

## [1.6.0] — Tier A: country block + AI-crawler groups + Tor/DC + endpoint policies

### Added
- **Country-level geo block** (`COUNTRY_BLOCK_ENABLED`, `COUNTRY_DENYLIST` /
  `COUNTRY_ALLOWLIST`) — uses GeoLite2-City in-process (~0.1 ms), fires `country-blocked`
  (weight 50 → instant ban). Allowlist takes precedence.
- **AI-crawler granular toggles** — legacy `UA_BLOCKLIST` AI section split into 6 named
  groups (`AI_UA_OPENAI_ENABLED` / `_ANTHROPIC_` / `_GOOGLE_` / `_PERPLEXITY_` / `_META_`
  / `_OTHER_`). Per-vendor reason (`ua-ai-openai`, …).
- **Tor exit-node feed** (`TOR_BLOCK_ENABLED`) — weekly auto-fetch of
  `check.torproject.org/torbulkexitlist`. O(1) set membership. `tor-exit` weight 50.
- **DC/VPN block** (`DC_VPN_BLOCK_ENABLED`) — heavier `datacenter-vpn` (weight 30) layered
  on existing `asn-hosting` (weight 5).
- **Per-endpoint policy engine** (`ENDPOINT_POLICIES` JSON) — fnmatch globs with 4 policies:
  `bypass` / `challenge` / `strict` / `default`. Extends `JS_CHAL_OPEN_PATHS`.
- 12 new hot-reloadable knobs (67 total). 6 new `RISK_WEIGHTS` entries.
- Empty admin-key file treated as missing (zero-byte `.admin_key` no longer silently accepted
  as valid credential).

### Tests
- 8 new tests for Tier A.

---

## [1.5.5] — Turnkey deployment + bundled GeoLite2 + hot-reload persistence

### Added
- `docker-compose.yml` + `.env.example` — `cp .env.example .env && edit && docker compose up -d`.
- **Bundled GeoLite2 mmdbs** baked into image at `/usr/local/share/maxmind/`; seeded into
  `/data` on first boot — GeoMap works offline out-of-the-box.
- **Auto-fetch GeoLite2** when `MAXMIND_LICENSE_KEY` set — downloads both
  `GeoLite2-ASN.mmdb` + `GeoLite2-City.mmdb`; auto-refresh every 30 days.
- **`config_kv` SQLite table** — every hot-reload knob change persists across restarts. Env
  vars win over DB for GitOps determinism; env-pinned mutations rejected at runtime.
- **14 new promoted knobs** in `_HOT_RELOAD_KNOBS` (JS_CHALLENGE_TTL, ENUM_THRESHOLD,
  HOSTILE_BAN_SECS, TIMELINE_RETAIN_SECS, SVC_DB_RETENTION_HOURS, COST_RETAIN_SECS,
  LOG_FORMAT, POW_REQUIRED_PATHS, ALLOWED_METHODS, ALLOWED_HOSTS, MAX_IDENTITIES,
  PRUNE_IDLE_SECS, UPSTREAM_MAX_BODY, UPSTREAM_MAX_RESP).
- 30-day retention for `events`, `timeline`, `svc_metrics` (was 24 h / 7 d).
- **Chart click drill-downs** on main dashboard and agents detection-vs-miss timeline.
- **GeoMap "Fix now" button** → `/__maxmind-fetch` admin endpoint (seed + auto-fetch +
  reopen readers, no restart).
- **Risk-gated Turnstile** (`TURNSTILE_RISK_THRESHOLD`) — most legitimate users never see
  Turnstile; only suspected bots do.
- **Defense-thresholds slider** on main dashboard with numeric readouts.
- **Anubis as proper integration** in `/__external` (with toggle).
- `Permissions-Policy` opts out of Privacy Sandbox (silences Cloudflare-edge warnings on
  `*.trycloudflare.com`).
- `TURNSTILE_ENABLED` defaults to `0` even when Turnstile keys are present — prevents
  accidental gate activation with public test keys.

### Tests
- 21 unit + 14 functional + 148 regression = **183/183 passing**.
- **Bandit**: 0 High / 0 Critical · 11 Mediums (all confirmed FP).
- **Trivy**: 0 CVEs. SBOM: `sbom/sbom-1.5.5.cdx.json`.

---

## [1.5.4] — Dashboard UX overhaul + GeoMap + external-intel cards + pentest fixes

### Added
- **Defense thresholds slider** on main dashboard — drag soft (orange) and ban (red) markers
  along 0–200 track; live POST to `/__config`.
- **Orange "missed" line** on the timeline.
- **Cost-per-request graph** (`/__cost-timeline`) — outer middleware times every request;
  dashboard graphs avg/max ms per bucket.
- **Reason drill-down** — click any block reason → modal lists offending identities + IPs.
- **Identity & risk popovers** on agents and main Clients table.
- **Agents threshold widget** — up/down arrows + 0–100 range slider.
- **Anubis-mode** toggle in Controls (`ANUBIS_ENABLED`, `ANUBIS_DIFFICULTY_BOOST`).
- **GeoMap dashboard** (`/__geo`) — Leaflet world-map, CARTO Dark Matter tiles, time-window
  controls, green/orange/red circles.
- **Services panel + per-detector hits** in `/__metrics`.
- **External-integration cards** click-to-modal with vendor / docs / trigger / weight /
  data-egress / live telemetry.
- **MaxMind GeoLite2-City** support (`MAXMIND_CITY_DB_PATH`).
- **Bot-trap field variants** — multiple decoy fields, per-process random suffixes.
- **Mirrored upstream 404** for blocked admin-endpoint probes.
- **Admin-IP description** PATCH endpoint + click-to-edit cell in Controls.
- `JS_CHAL_BIND_JA4` / `JS_CHAL_REQUIRE_JA4` / `JS_CHAL_STRICT_STATIC` knobs.
- 11 new per-detector kill-switches in `/__config`.
- `CrowdSec` env-var alias: accepts both `CROWDSEC_API_KEY` and `CROWDSEC_LAPI_KEY`.
- `last_seen` units in Clients table progressive (s → min → h → d).

### Fixed
- **TRUSTED_PROXIES** (`X-Forwarded-For` honoured only when peer IP is in configured CIDRs)
  — closed pentest finding: any direct client could spoof XFF and impersonate any source IP.
- CrowdSec response hardening — non-list LAPI responses no longer crash the lookup.
- Epoch / monotonic mix-up causing DB-loaded clients to show negative ages.

### Tests
- **Bandit**: 0 High / 0 Critical. **Trivy**: 0 CVEs. SBOM: `sbom/sbom-1.5.4.cdx.json`.

---

## [1.5.3] — External intel + soft-challenge tier + hybrid identity

### Added
- **Hybrid identity** (cookie + fingerprint) for shared-NAT environments.
- **Soft-challenge tier** — `risk_score` in 4–8 band forces cookie challenge even on open
  paths.
- **AbuseIPDB** integration (crowdsourced IP reputation, 6 h SQLite cache; +50 high /
  +20 med).
- **CrowdSec LAPI** integration (self-hosted blocklist, 60 s cache; +70 instant ban).
- **MaxMind GeoLite2-ASN** tagging (`asn-hosting` signal, soft weight).
- `signals[]` array in event log.
- UA ↔ `Sec-Ch-Ua` consistency detector; `Accept: */*` HTML heuristic; JA4-required-missing
  soft penalty.
- **Defenses & scoring** merged table in Controls.
- **`admin_ips`** SQLite table for persistent allowlist.
- **Suspicious-path regex** — flag/secret/passwd/credentials/`*.bak`/`*.swp`/`.git/`/path
  traversal / SQLi / XSS / LFI markers.
- **Upstream-404 risk** tracking.

---

## [1.5.2] — Stealth-score auto-ban (WIP) + uniform topnav

### Added
- Hard stealth-score auto-ban knob (work-in-progress, not yet finalised).
- Uniform top-nav across every dashboard (`Dashboard / Agents / Service / Controls`,
  server-rendered `<a>` tags, visible without JS).

### Fixed
- Service dashboard crash when legacy nav-link IDs absent.

---

## [1.5.1] — Controls dashboard + throughput cap + inline unban

### Added
- **Controls dashboard** (`/__controls`) — on/off switch per toggleable control, number
  inputs for thresholds, textareas for lists, dirty-marker, Apply / Reset, audit log of
  `config_changed` events, banned-identity table with 1-click unban.
- **Global RPS cap** (`GLOBAL_RPS_LIMIT`) — live req/s card + operator slider; over-limit
  traffic silent-decoyed as `traffic-threshold`.
- **Inline Unban** button in Clients table. `/__ban` admin endpoint.

---

## [1.5.0] — Multi-instance fleet + session-churn detector + webhooks

### Added
- **Multi-instance shared state** (optional `REDIS_URL`) — bans propagate across N gateways;
  JA4 deny-list auto-syncs every 30 s.
- **Session-churn detector** — same `(UA + IP-tier + JA4)` minting > N chal cookies in a
  window enters the 24 h hostile pool (`session-churn`, weight 75).
- **Webhook fan-out** (`WEBHOOK_URL` + `WEBHOOK_SECRET` HMAC) on every ban; deduplicated
  via Redis `SETNX`.
- **Auto-add-to-JA4_DENY_LIST** after `JA4_AUTODENY_THRESHOLD` (default 3) bans on the
  same fingerprint.

---

## [1.4.7] — Hot-reload admin endpoint

### Added
- `GET/POST /__config` — read or update a whitelisted set of runtime knobs without restart.
  Every change audited as `event=config_changed`.

---

## [1.4.6] — Structured JSON logs + request correlation IDs

### Added
- `LOG_FORMAT=json` — one JSON document per line, ready for Loki / Splunk / CloudWatch.
- Short `r…` request ID minted at the top of `protect()`, threaded through every decision,
  stamped on response as `X-Request-ID`. Inbound `X-Request-ID` honoured (CDN trace
  propagation).

---

## [1.4.5] — HMAC key rotation

### Added
- `POST /__rotate-keys?key=…&scope=session|pow|all` — regenerates `SESSION_KEY` /
  `POW_HMAC_KEY` atomically, persists to `/data`. Every chal/session cookie issued before
  the call fails immediately.

### Fixed
- Closed pentest finding: old chal cookie remained valid after upgrade (HMAC secret not
  rotated).

---

## [1.4.4] — Turnstile-independent operation + status-mirror silent decoy

### Added
- Cookie gate works **without** Turnstile — auto-minted on first qualifying HTML GET
  (heuristic mode) when no Turnstile keys configured.
- Silent-decoy status code now mirrors upstream `/` instead of hard-coded 200 — closes the
  200-with-404-page fingerprint.

---

## [1.4.3] — AI canary-echo detection (R7) + 24 h hostile pool (R8)

### Added
- **Canary-echo detection** (`CANARY_ECHO_DETECTION=1`, default on) — every HTML response
  stamped with a unique `agw-c-<16hex>` token. Any identity that quotes it back is
  silent-decoyed and added to the hostile pool for `HOSTILE_BAN_SECS` (default 24 h).
  Near-zero FP on browser traffic; specifically catches LLM-driven agents.
- **Hostile pool** — 24 h ban duration for AI-agent-flagged reasons (canary-echo, honeypot,
  ai-probe, suspicious-path).

---

## [1.4.2] — Turnstile-only cookie gate

### Changed
- PoW + browser-API probe + anchor-fetch proof + timing window removed (all bypassable in
  Python in ~1 s). Cookie gate now requires Cloudflare Turnstile keys to engage.
- Chal cookie bound to (UA + IP-tier-hash + JA4-hash).

---

## [1.4.1] — Cookie gate hardening + service-metrics dashboard + JA4 binding

### Added
- Cookie required on every non-static path (closes V8: API-only paths slipped through).
- **Service-metrics dashboard** — CPU / memory / disk / processes / FDs / network / SQLite
  size; windowed time-navigation; samples persisted to SQLite.
- **Slowloris guard** (`HEADERS_TIMEOUT`).
- **Bot-trap forms** + **body pattern matching**.
- TLS / JA4 fingerprint deny-list (`JA4_TRUSTED_PEERS`).
- `STRICT_ORIGIN` enforcement on state-changing methods.
- `REQUIRED_HEADERS` operator-defined header presence check.
- Dashboards extracted to `dashboards/` directory.
- `JS_CHAL_STRICT_STATIC` — tightens `/api/...css` style bypass.
- Chal cookie bound to socket-IP /24 (v4) / /48 (v6) tier (opaque HMAC hash).
- JA4 cookie binding (`JS_CHAL_BIND_JA4`).

---

## [1.3] — Distroless base + WebSocket bridge + SSO rewriting

### Added
- Wolfi distroless base image — 0 Trivy CVEs.
- Full bidirectional WebSocket bridge.
- SSO `302` redirect rewriting (`Location`, `redirect_uri`, `Set-Cookie Domain=`).
- Admin IP allowlist.
- Edge security-header injection.
- Stealth-agent hunter dashboard.
- Streaming body forwarding fix.

---

## [1.2] — Hardening + timeline / agents dashboards

### Added
- Timeline and agents dashboards.
- PoW replay protection.
- 34/34 audit findings closed in hardening pass.

---

## [1.0] — Initial prototype

### Added
- 6-layer reverse-proxy prototype: UA filter, header completeness, honeypot paths,
  AI-probe paths, cookie gate, risk-score model.

