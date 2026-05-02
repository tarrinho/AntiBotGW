# Changelog — AppSecGW (appsec-antibot-gw)

All notable changes are documented here. Format: new features → fixes → security → tests → validation.

Author: Pedro Tarrinho

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
