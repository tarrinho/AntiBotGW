# Changelog — AppSecGW (appsec-antibot-gw)

All notable changes are documented here. Format: new features → fixes → security → tests → validation.

Author: Pedro Tarrinho

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

### Fixed
- **Admin-path bypass scope too broad** — Global RPS limit and Method allowlist were exempt for ALL requests to admin-namespace paths regardless of source IP. Fixed: exemption now only applies when the request comes from an admin IP. Non-admin IPs hitting admin paths are now subject to rate limiting and method filtering.
- **`geo_data_endpoint` stale `LIMIT 200000`** — removed `ORDER BY ts ASC LIMIT 200000`; query now returns all events in the window.
- **`NameError: ip not defined` in proxy() HTML injection block** — caught during validation testing. `ip` is not in scope inside the forwarding function; fixed to use `get_ip(request)` via local `_gw_ip`.
- **`JS_CHAL_REQUIRE_JA4` / `TURNSTILE_ENABLED` mutual exclusion** — 3-layer mutex: startup (config.py), DB-load (db/sqlite.py), hot-reload (proxy_handler.py config_endpoint). Prevents silent 403s on every Turnstile solve when `JS_CHAL_REQUIRE_JA4=true` is persisted in `config_kv` table while Turnstile is active (JA4 always absent behind Cloudflare CDN).
- **Silent 403 on JA4-required path emitted no log** — added `slog("chal_ja4_required_missing", level="warn", ...)` before the 403 return in `js_challenge.py`.
- **5 security findings from code review** — 1 MEDIUM (unbounded `_maze_timing` dict — added `_MAZE_TIMING_MAX=2048` + `_MAZE_STEPS_MAX=32` caps), 4 LOW (unbounded `_fired`/`_probe_confirmed` — eviction added; missing key/token length caps on public endpoints — 64/48 char limits added; dead duplicate HMAC call in `_verify_maze_token` — removed).

### Tests
- **37 new unit tests** in `tests/test_v173.py`: P1 honey_cred (10), P2 redirect_maze (7), P3 llm_heuristic (9), P4 canary_probe (11).
- **9 new unit tests** in `tests/test_path_sweep.py` (path-sweep detector).
- **4 new regression tests** in `tests/test_pure.py`: JA4/Turnstile mutex (startup, DB-load, hot-reload), JA4-required slog warning.
- **Totals**: 205 unit + 22 functional + 1 integration + 116 regression = **344 tests**; all pass individually.

### Validation
- Bandit: 0 High · 0 Critical · B110 Medium (confirmed FP — intentional try/except in `_evaluate_maze_timing`).
- Semgrep: 0 findings on all 4 new detection modules.
- Trivy: 0 Critical / 0 High / 0 Medium CVEs (all 3 arches).
- Harbor: amd64 `sha256:fa265209…` · arm64 `sha256:70904630…` · armv7 `sha256:98a07abb…` · manifest `sha256:2203ce72…`.
- Security review: 5 findings fixed before release.
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
