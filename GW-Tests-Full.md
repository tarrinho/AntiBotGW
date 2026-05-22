# AppSecGW — Full Test Suite Reference

**Generated:** 2026-05-20  
**Version:** 1.8.10  
**Total test files:** 75  

---

## Table of Contents

| Version | File(s) |
|---------|---------|
| Core / multi-version | `test_pure.py`, `test_critical.py`, `test_async.py`, `test_integration.py`, `test_functional.py`, `test_endpoints_dynamic.py` |
| v1.4 | `test_v14.py` |
| v1.4.2 | `test_v142.py` |
| v1.4.x–1.5.x regressions | `test_control_regressions.py` |
| v1.6.5 | `test_timescaledb_soak.py` |
| v1.7.2 | `test_blockrate_regressions.py` |
| v1.7.3 | `test_v173.py`, `test_path_sweep.py` |
| v1.7.7 | `test_geo_dashboard.py` |
| v1.7.9 | `test_v179.py` |
| v1.7.10 | `test_v1710.py` |
| v1.7.11 | `test_v1711.py`, `test_h3_pg_pool.py`, `test_h4_pg_backend_switch.py`, `test_h5_m2_dynamic.py`, `test_settings_config_functional.py` |
| v1.7.12 | `test_v1712.py` |
| v1.8.0 | `test_v180.py`, `test_vhost_filtering.py` |
| v1.8.0–v1.8.1 | `test_v180_v181_gaps.py` |
| v1.8.1 | `test_v181_vhost_comparison.py`, `test_audit_trail.py` |
| v1.8.2 | `test_v182_charts.py`, `test_v182_svc_metrics_db.py`, `test_livefeed_detector_stats.py` |
| v1.8.3 | `test_v183_incidents.py` |
| v1.8.4 | `test_v184_siem.py`, `test_v184_uiux.py` |
| v1.8.5/1.8.6 | `test_v185_controls_nav.py`, `test_v185_new_features.py`, `test_v185_security.py`, `test_v185_settings_migration.py`, `test_v185_settings_nav.py`, `test_v185_week3_week4.py`, `test_v185_week3week4.py` |
| v1.8.6 | `test_interaction_probe.py`, `test_oidc.py` |
| v1.8.7 | `test_v187_login_2fa.py`, `test_v187_new_features.py`, `test_v187_security.py`, `test_v187_settings_vhost_strip.py`, `test_v187_ux_improvements.py`, `test_v187_controls_order.py`, `test_v187_db_switch_hotswap.py`, `test_v187_db_switch_roundtrip.py`, `test_v187_db_endpoints_dynamic.py`, `test_v188_db_settings_merge.py`, `test_v188_redis_security.py` |
| v1.8.8 | `test_v188_ed25519_mesh.py`, `test_v188_settings_subnav.py`, `test_performance.py`, `test_v188_backend_aware_reads.py`, `test_v188_session_fixes.py`, `test_v188_startup_fixes.py` |
| v1.8.9 | `test_live_gw.py`, `test_v189_knob_kill_switches.py` |
| v1.8.10 | `test_v189_sidebar_collapse.py`, `test_v189_ctrlnav_rail.py`, `test_v189_setnav_rail.py` |
| Cross-version | `test_admin_ip_list.py`, `test_code_review_fixes.py`, `test_control_center.py`, `test_crowdsec_lapi_health.py`, `test_dashboard_charts.py`, `test_dashboard_data.py`, `test_upstream_no_leak.py`, `test_upstream_rewrite.py` |

---

## Core Tests

### `test_pure.py` — Pure function / security-critical helpers
**Version added:** Core (updated continuously)  
**Type:** Static, no HTTP, no async  
**Purpose:** Tests security-critical pure functions that have caused real incidents.

| Test | Description |
|------|-------------|
| `test_strip_admin_key_from_qs` | Admin key must be stripped from query string before logging |
| `test_strip_own_session_cookie_removes_aid` | Session cookie strip removes agw_aid from cookie string |
| `test_strip_own_session_cookie_keeps_others` | Other cookies are preserved when stripping |
| `test_strip_own_session_cookie_empty_returns_empty` | Empty cookie string returns empty |
| `test_inject_honey_links_inserts_before_last_body_close` | Honey links injected before `</body>` |
| `test_inject_honey_links_skips_when_post_body_script` | N8: bail if `<script>` follows chosen `</body>` (avoids corrupting JS string literals) |
| `test_inject_honey_links_no_body_tag_returns_unchanged` | No `</body>` tag → passthrough |
| `test_sign_then_verify_round_trip` | HMAC sign → verify round-trip |
| `test_verify_session_rejects_empty_sid` | N3: HMAC-valid token over empty string must NOT authenticate |
| `test_verify_session_rejects_bad_charset` | Bad charset in session ID rejected |
| `test_verify_session_rejects_overlong_sid` | Overlong SID rejected |
| `test_verify_session_rejects_truncated_sig` | Truncated signature rejected |
| `test_verify_session_rejects_forged_sig` | Forged signature rejected |
| `test_pow_round_trip` | Proof-of-Work sign → verify round-trip |
| `test_pow_replay_rejected` | PoW replay attack rejected |
| `test_pow_wrong_method_rejected` | PoW with wrong method rejected |
| `test_pow_wrong_path_rejected` | PoW with wrong path rejected |
| `test_pow_legacy_unbound_rejected` | 4-segment legacy tokens (no METHOD:path bind) rejected |
| `test_pow_malformed_rejected` | Malformed PoW token rejected |
| `test_is_suspicious_path` | Suspicious path detection (CTF patterns, traversal, etc.) |
| `test_browser_fingerprint_stable_with_or_without_sec_ch_ua` | Fingerprint stable across navigation vs sub-resource (Sec-Ch-Ua split-identity bug) |
| `test_browser_fingerprint_differs_on_different_uas` | Different UAs produce different fingerprints |
| `test_admin_ip_allowed_open_when_unset` | No allowlist → all IPs allowed (key still required) |
| `test_admin_ip_allowed_single_ip` | Single IP allowlist match |
| `test_admin_ip_allowed_cidr` | CIDR allowlist match |
| `test_admin_ip_allowed_ipv6` | IPv6 allowlist match |
| `test_internal_authed_rejects_bearer_key_post_1_6_7` | Bearer key (1.6.7+: retired) ignored; session cookie is the only entry |
| `test_internal_authed_rejects_wrong_key` | Wrong key rejected |
| `test_internal_authed_rejects_empty` | Empty auth rejected |
| `test_internal_authed_accepts_valid_session_cookie` | Valid session cookie accepted |
| `test_internal_authed_rejects_tampered_cookie` | Tampered cookie rejected |
| `test_167_session_revoke_invalidates_cookie` | Revoked session cookie stops verifying even with valid HMAC |
| `test_main_html_k_q_absent` | Dead variable `k_q` no longer exists in main.html |
| `test_no_smart_quotes_in_main_html` | No smart quotes in main.html (break JS) |
| `test_no_smart_quotes_in_agents_html` | No smart quotes in agents.html |
| `test_main_html_js_syntax` | `node --check` validates main.html JS syntax |
| `test_agents_html_js_syntax` | `node --check` validates agents.html JS syntax |
| `test_no_broken_string_assignments_in_main_html` | Regression: apostrophe in single-quoted JS string splits assignment |
| `test_no_broken_string_assignments_in_agents_html` | Same check for agents.html |
| `test_admin_ip_tip_uses_double_quotes` | `_ADMIN_IP_TIP` must use double quotes (apostrophe safety) |
| `test_167_session_token_format_includes_sid` | Token is `username\|sid\|expiry\|HMAC` (old 3-part format rejected) |
| `test_gw_version_constant` | `GW_VERSION` in config.py matches expected release string |
| `test_no_stale_version_strings_in_source` | No source file contains a hardcoded stale version string |
| `test_to_host_set_strips_scheme_and_path` | `_to_host_set` normalises full URLs to bare hostnames |
| `test_dashboard_html_version_strings` | Every dashboard HTML displays current `GW_VERSION` |
| `test_inject_lifecycle_cookie_script_before_body` | Lifecycle cookie script injected before `</body>` |
| `test_inject_lifecycle_cookie_script_appends_when_no_tag` | Lifecycle cookie script appended when no `</body>` |
| `test_inject_lifecycle_cookie_script_empty_body_passthrough` | Empty body passes through |
| `test_is_soft_renderer_known_patterns` | Soft renderer detection (headless patterns) |
| `test_fp_probe_injected_before_body` | FingerprintJS probe injected before `</body>` |
| `test_fp_probe_skipped_when_disabled` | FP probe no-op when disabled |
| `test_fp_token_is_hmac_bound_to_track_key` | FP token HMAC-bound to track key |
| `test_referer_ghost_skips_static_suffixes` | Referer ghost check skips static asset extensions |
| `test_csp_inject_adds_to_script_src` | CSP inject adds nonce to script-src |
| `test_csp_inject_adds_to_frame_src` | CSP inject adds to frame-src |
| `test_csp_inject_noop_when_already_present` | CSP inject is idempotent |
| `test_csp_inject_augments_default_src_when_no_script_src` | Augments default-src when no script-src |
| `test_csp_inject_preserves_other_directives` | Other CSP directives preserved |
| `test_config_startup_mutex_ja4_off_when_turnstile_on` | `JS_CHAL_REQUIRE_JA4` disabled at startup when `TURNSTILE_ENABLED` |
| `test_db_load_config_mutex_clears_ja4_when_turnstile_active` | `db_load_config` forces `JS_CHAL_REQUIRE_JA4=False` when Turnstile active |
| `test_hotreload_mutex_disables_ja4_when_enabling_turnstile` | Enabling Turnstile via dashboard auto-clears JA4 requirement |
| `test_ja4_required_missing_logs_warning` | JA4-required 403 path emits slog warn |
| `test_probe_endpoint_in_admin_public_subpaths` | Honey-cred probe endpoint publicly reachable |
| `test_maze_endpoint_in_admin_public_subpaths` | Redirect-maze endpoint publicly reachable |
| `test_canary_probe_in_admin_public_subpaths` | Canary-probe endpoint publicly reachable |
| `test_ai_no_assets_deny_uses_s_early_not_s` | `protect()` ai-no-assets branch uses `_s_early`, not undefined `s` |
| `test_js_challenge_applicable_source_uses_get_identity_not_track_key` | `_js_challenge_applicable` derives identity via `get_identity()` |
| `test_js_challenge_required_soft_challenge_uses_get_identity_not_track_key` | Same for soft-challenge branch |
| `test_login_safenext_validator_defined` | `login.html` defines `safeNext()` |
| `test_login_safenext_checks_origin` | `safeNext()` compares URL origin against `location.origin` |
| `test_login_no_bare_location_href_next` | `login.html` does not use raw `?next=` without `safeNext` |
| `test_service_emessage_escaped_in_innerhtml` | `service.html` escapes `e.message` before innerHTML injection |
| `test_service_has_global_escapehtml` | `service.html` defines `escapeHtml` at global scope |
| `test_escapehtmlt_full_charset` | Every dashboard `escapeHtml` escapes backtick and slash |
| `test_no_local_eschtml_alias` | No dashboard defines local `escHtml` alias |
| `test_no_eschtml_calls` | No dashboard calls undefined `escHtml()` |
| `test_single_escapehtmlt_definition` | Each dashboard has exactly one `escapeHtml` definition |
| `test_escapehtmlt_null_guard` | `escapeHtml` handles `null`/`undefined` via `String(s==null?'':s)` |
| `test_setinterval_tracked_in_timers` | Every `setInterval` tracked via `_timers.push()` or named variable |
| `test_beforeunload_cleanup_present` | Every dashboard registers `beforeunload` to clear timers |
| `test_setinterval_has_numeric_delay` | Every `setInterval()` has a numeric delay argument |
| `test_settings_gw_registry_autorefresh_delay` | `settings.html` gw-registry auto-refresh is exactly 30000ms |
| `test_control_center_chartjs_local_asset` | `control_center.html` loads Chart.js from local assets, not CDN |
| `test_control_center_traffic_chart_canvas` | `control_center.html` contains traffic-chart canvas |
| `test_control_center_blockrate_chart_canvas` | `control_center.html` contains blockrate-chart canvas |
| `test_control_center_donut_chart_canvas` | `control_center.html` contains donut-chart canvas |
| `test_control_center_traffic_chart_fetches_vhost_breakdown` | Traffic chart fetches `/vhost-breakdown` |
| `test_control_center_traffic_chart_type_line` | Traffic chart is type `'line'` (stacked area) |
| `test_control_center_blockrate_chart_type_bar` | Block-rate chart is type `'bar'` with `indexAxis:'y'` |
| `test_control_center_donut_chart_type_doughnut` | Donut chart is type `'doughnut'` |
| `test_control_center_traffic_chart_autorefresh` | Traffic chart auto-refreshes at 60000ms |
| `test_control_center_timers_push_for_all_intervals` | All `setInterval` calls tracked in `_timers` |
| `test_control_center_beforeunload_cleanup` | `beforeunload` clears `_timers` |
| `test_control_center_escapehtml_used_in_dynamic_html` | `escapeHtml` used for all user-controlled values in innerHTML |
| `test_control_center_hexrgba_helper_defined` | `_hexRgba` helper defined for chart dataset colours |
| `test_control_center_vhost_stats_also_fetched` | `control_center.html` fetches `/vhost-stats` |
| `test_controls_actions_bar_before_scoring` | Apply/Reset in `#topbar-right` (v1.8.6 split-pane layout); standalone `div.actions` absent |
| `test_main_pick_bucket_7day_returns_3600` | `pickBucketForRange(10080)` returns 3600 (was incorrectly 900) |
| `test_main_pick_bucket_30day_returns_86400` | 30-day range returns 86400 (daily buckets) |
| `test_main_30day_option_in_range_select` | Range `<select>` includes 30-day option |
| `test_geo_html_has_30day_option` | `geo.html` window select includes 30-day option |
| `test_geo_data_endpoint_cap_allows_30days` | `geo_data_endpoint` range cap allows 43200 |
| `test_dockerfile_pip_deps_use_exact_pins` | Dockerfile pins all pip deps to exact versions |
| `test_dockerfile_armv7_pip_deps_use_exact_pins` | `Dockerfile.armv7` pins all pip deps to exact versions |
| `test_dockerfile_builder_stage_drops_root` | Dockerfile builder stage ends with `USER nonroot` |
| `test_dockerfile_armv7_builder_stage_drops_root` | `Dockerfile.armv7` builder stage ends with `USER nobody` |
| `test_gw_identity_popover_defined_in_agents_html` | `agents.html` defines `window._gwIdentityPopover` |
| `test_gw_identity_popover_defined_in_main_html` | `main.html` defines `window._gwIdentityPopover` |
| `test_gw_identity_popover_core_logic_identical_in_both_files` | `_gwIdentityPopover` IIFE is identical in both files |
| `test_build_validation_armv7_requires_platform_flag` | armv7 build requires `--platform linux/arm/v7` flag |
| `test_bypass_mode_not_persisted_to_db` | `BYPASS_MODE` in `_NOT_PERSIST_KNOBS` (resets on restart) |
| `test_bypass_mode_in_hot_reload_knobs` | `BYPASS_MODE` still hot-reloadable |
| `test_service_metrics_interval_default_60s` | `SVC_METRICS_INTERVAL` default is 60s |
| `test_service_metrics_retention_default_43200` | `SVC_METRICS_RETENTION` default covers 30 days |
| `test_maxmind_lookup_cache_ttl_is_86400` | MaxMind lookup cache TTL is 86400s |
| `test_maxmind_lookup_cache_max_is_8192` | MaxMind lookup cache max is 8192 |
| `test_logs_html_cat_filter_bar_exists` | `logs.html` has cat-filter-bar toolbar |
| `test_logs_html_cat_pills_all_present` | `logs.html` has all 5 category pills |
| *(+50 more in this file)* | Various dashboard structure, authorized-bot, vhost breakdown, panel legend, gwmgmt colour checks |

---

### `test_critical.py` — Critical path unit tests
**Version added:** Core (updated with each version)  
**Type:** Static, no HTTP  
**Purpose:** Unit tests for AppSecGW critical paths; covers signal weights, session signing, config validation, and feature flags from v1.6.0 through v1.6.10.

| Test | Description |
|------|-------------|
| `test_risk_weights_complete` | Every reason emitted by middleware has a registered weight |
| `test_risk_decay_halves_per_hour` | Score of 100 decays to ~50 after 1 hour |
| `test_risk_threshold_normal_vs_nat` | Risk threshold differs for normal vs NAT identities |
| `test_session_signing_roundtrip` | Session sign → verify round-trip |
| `test_browser_fingerprint_stable` | Fingerprint stable across same identity |
| `test_suspicious_path_catches_ctf` | Suspicious path detection fires on CTF patterns |
| `test_pow_challenge_signing` | PoW challenge signing |
| `test_admin_ip_validation` | Empty/malformed CIDRs rejected at helper level |
| `test_bot_trap_multiple_fields` | Bot trap fires when multiple hidden fields filled |
| `test_scoring_signals_have_cost` | Every signal in `/scoring` has a `cost_ms` triple |
| `test_15_promoted_knobs_in_hot_reload` | All Tier 1+2+3 knobs in `_HOT_RELOAD_KNOBS` |
| `test_method_set_parser` | `_to_method_set` normalises to upper-case |
| `test_host_set_parser` | `_to_host_set` lower-cases and strips |
| `test_method_validator_rejects_garbage` | `ALLOWED_METHODS` validator rejects non-HTTP methods |
| `test_threshold_bounds` | Numeric validators reject out-of-range values |
| `test_env_precedence_marker` | DB wins over env for hot-reload knobs by default |
| `test_config_kv_table_exists` | `db_init()` creates `config_kv` table |
| `test_turnstile_default_off` | `TURNSTILE_ENABLED` defaults off even with keys configured |
| `test_trusted_proxies_blocks_spoof` | `TRUSTED_PROXIES` set → XFF from untrusted peer ignored |
| `test_16_country_set_parser` | 2-letter alpha codes only for country denylist |
| `test_16_country_signals_in_risk_weights` | All Tier-A signals have registered weight |
| `test_16_ai_groups_nonempty` | Every AI group has at least one fragment |
| `test_16_ai_group_uas_are_lowercase` | AI group fragments all lowercase |
| `test_16_endpoint_policy_parser` | Endpoint policy accepts JSON string, list of dicts, or pairs |
| `test_16_endpoint_policy_match` | Glob `*` match; first match wins |
| `test_16_descriptions_complete` | Every 1.6.0 reason has a description for the dashboard |
| `test_161_custom_rules_parser` | Custom rules parser accepts JSON string and decoded list |
| `test_161_custom_rule_match_path_method_header` | Custom rule matches path, method, and header |
| `test_161_custom_rule_ip_cidr` | Custom rule matches IP CIDR |
| `test_161_body_groups_match` | Body injection groups catch target attack families |
| `test_161_jwt_signature_verify` | JWT signature verification |
| `test_161_tier_b_hot_reload_knobs` | All Tier-B toggles hot-reloadable |
| `test_162_dlp_aws_keys` | DLP detects AWS access key IDs |
| `test_162_dlp_jwt` | DLP detects JWTs in upstream responses |
| `test_162_dlp_credit_card_luhn` | Luhn check eliminates false positives for CC detection |
| `test_162_dlp_redact` | Redaction substitutes `[REDACTED-<group>]` |
| `test_162_dlp_max_bytes_bound` | DLP doesn't scan beyond `DLP_MAX_BYTES` |
| `test_163_geo_drill_endpoint_registered` | `/secured/geo-drill` wired in router |
| `test_163_geo_data_payload_shape` | `/geo-data` includes fields the dashboard reads |
| `test_164_db_backend_default_sqlite` | Default DB backend is SQLite |
| `test_164_db_backend_falls_back_when_psycopg_missing` | `DB_BACKEND=postgres` without psycopg falls back to SQLite |
| `test_165_detector_stats_endpoint_registered` | `/secured/detector-stats` exists |
| `test_165_botd_wired` | FingerprintJS BotD bundle wired in, knob hot-reloadable |
| `test_165_every_knob_persists_round_trip` | Comprehensive round-trip test for every `_HOT_RELOAD_KNOBS` entry; `test_values` updated for `BOT_DETECTION_ENABLED`, `TRUST_XFF`, `TRUSTED_PROXIES` (1.8.10); `finally` extends restoration to all `sys.modules` entries to prevent cross-test pollution from `db_load_config` propagation loop |
| `test_165_admin_ip_bypasses_country_block` | Admin-allowlisted IPs bypass `COUNTRY_BLOCK_ENABLED` |
| `test_165_tarpit_knobs_registered` | `TARPIT_ENABLED` + `TARPIT_DELAY_MS` hot-reloadable |
| `test_168_labyrinth_knobs_in_hot_reload` | `LABYRINTH_*` hot-reload knobs registered |
| `test_168_tarpit_token_roundtrip` | Tarpit token sign → verify round-trip |
| `test_168_tarpit_verify_rejects_tampered` | Tampered tarpit token rejected |
| `test_1610_second_order_threshold_default` | `SECOND_ORDER_THRESHOLD` defaults to 15 |
| `test_1610_escalation_threshold_default` | `ESCALATION_THRESHOLD` defaults to 30 |
| `test_1610_signal_runtime_order_hardcoded_sets` | `_signal_runtime_order` returns 3/2/1 for each tier |
| `test_1610_should_run_signal_1st_order_always_runs` | 1st-order signals run regardless of `esc_score` |
| `test_1610_should_run_signal_2nd_order_gated` | 2nd-order signals suppressed below threshold |
| `test_1610_should_run_signal_3rd_order_gated` | 3rd-order signals suppressed below escalation threshold |

---

### `test_async.py` — Rate-limit buckets, behavioural detector, identity pruning
**Version added:** Core  
**Type:** Plain asyncio (no pytest-aiohttp)

| Test | Description |
|------|-------------|
| `test_take_socket_ip_token_burst_then_block` | Token bucket bursts then blocks |
| `test_take_socket_ip_token_isolated_per_ip` | Per-IP token buckets are isolated |
| `test_take_token_burst_then_block` | Global bucket burst then block |
| `test_behavioral_detects_perfectly_regular_intervals` | Perfectly regular timing → bot signal |
| `test_behavioral_detects_quantised_jitter` | Quantised jitter → bot signal |
| `test_behavioral_passes_humanlike` | Human-like timing passes detection |
| `test_nat_detection_does_not_count_fake_identities` | Fake identities without static fetches don't inflate NAT count |
| `test_nat_detection_counts_legit_identities` | Legitimate identities counted in NAT detection |
| `test_stealth_score_zero_for_no_allowed` | Stealth score is 0 when no allowed traffic |
| `test_stealth_score_flags_low_header_completeness` | Low header completeness flagged in stealth score |

---

### `test_integration.py` — HTTP-level integration tests
**Version added:** Core  
**Type:** Full aiohttp app with in-process echo upstream

| Test | Description |
|------|-------------|
| `test_live_endpoint_open_no_auth` | `/live` probe accessible without auth |
| `test_dashboard_silent_decoy_without_key` | Dashboard returns silent decoy without key |
| `test_dashboard_works_with_session_cookie` | Session cookie grants dashboard access (bearer key retired in 1.6.7) |
| `test_method_not_allowed_returns_405` | Blocked HTTP methods return 405 |
| `test_method_allowed_passes_through` | Allowed methods proxied through |
| `test_control_byte_in_path_returns_400` | Control byte in path → 400 |
| `test_x_proxy_header_on_allowed_response` | `X-Proxy` header injected on allowed responses |
| `test_location_rewrite_and_set_cookie_domain_strip` | Location header rewritten; Set-Cookie domain stripped |
| `test_security_headers_injected_on_html` | Security headers injected on HTML responses |
| `test_host_allowlist_blocks_mismatch` | Mismatched Host header → silent decoy |
| `test_host_allowlist_blocks_mismatch_api_path` | API path + mismatched Host → silent 404 |
| `test_agents_bucket_decoy_without_auth` | Unauthenticated `/agents-bucket` → decoy (no `bucket_t` in response) |
| `test_agents_bucket_shape_with_auth` | Authenticated → JSON with `detected`/`missed`/`clean` lists |
| `test_agents_bucket_bad_t_param_returns_400` | Non-integer `t` param → 400 |
| `test_agents_bucket_invalid_bucket_secs_falls_back_to_60` | Invalid `bucket_secs` silently falls back to 60 |
| `test_agents_bucket_list_cap_500` | Each list capped at 500 server-side |
| `test_agents_bucket_kind_filter` | `?kind=detected` adds `'only':'detected'` to response |
| `test_fp_report_bad_token_returns_403` | Wrong FP token → 403 |
| `test_fp_report_disabled_returns_400` | FP report when disabled → 400 |
| `test_fp_report_stale_ts_returns_400` | Very old timestamp → 400 |
| `test_sw_js_disabled_returns_404` | SW challenge disabled → 404 |
| `test_sw_js_enabled_returns_javascript` | SW challenge enabled → 200 JS |
| `test_lifecycle_cookie_injected_in_html_response` | HTML responses get `agw_lc` cookie-setting script |

---

### `test_functional.py` — Functional startup/config tests
**Version added:** Core  
**Type:** Full aiohttp app

| Test | Description |
|------|-------------|
| `test_db_load_config_rejects_abuseipdb_enabled_without_key` | `ABUSEIPDB_ENABLED=true` rejected when key absent |
| `test_db_load_config_rejects_turnstile_enabled_without_creds` | `TURNSTILE_ENABLED=true` rejected when Turnstile creds absent |
| `test_db_load_config_accepts_abuseipdb_enabled_with_key` | `ABUSEIPDB_ENABLED=true` accepted when key present |

---

### `test_endpoints_dynamic.py` — Full endpoint regression suite
**Version added:** Core (covers rules.md §1–3)  
**Type:** Dynamic (in-process proxy)  
**Purpose:** Covers every admin endpoint + detection-pipeline feature.

**Classes:**

| Class | Tests | Description |
|-------|-------|-------------|
| `TestAuthGuard` | 5 | Unauthenticated requests return silent decoy, not 401/403 |
| `TestStatusEndpoint` | 2 | `/status` shape and auth |
| `TestMetricsEndpoint` | 5 | Metrics JSON shape, client row shape, timeline, category filter |
| `TestThresholdsEndpoint` | 4 | Thresholds list shape, `RISK_BAN` present |
| `TestScoringEndpoint` | 3 | Scoring shape, signal entry shape |
| `TestConfigEndpoint` | 5 | Config GET shape, POST apply/reject, non-hot-reloadable key rejected |
| `TestCostTimelineEndpoint` | 4 | Cost timeline shape, entry shape, invalid bucket fallback |
| `TestHealthScoreEndpoint` | 3 | Health score range, reasons list |
| `TestDetectorStatsEndpoint` | 3 | Detector stats shape, signal entry shape |
| `TestListsSnapshotEndpoint` | 3 | Snapshot required keys, version not empty |
| `TestExternalEndpoint` | 2 | External endpoint, `integrations` key present |
| `TestSignalOrdersEndpoint` | 5 | GET/POST signal orders, invalid order rejected |
| `TestPathHitsEndpoint` | 3 | Missing param → 400, shape, seeded events reflected |
| `TestWhoamiEndpoint` | 3 | Shape, username is `admin` |
| `TestBanUnbanLifecycle` | 5 | Ban/unban lifecycle, CSRF guard on GET unban |
| `TestSettingsExportEndpoint` | 3 | ZIP output, no secrets by default, auth guard |
| `TestDashboardHtmlPages` | 7 | All dashboard HTML pages return 200 |
| `TestAgentsDataEndpoint` | 5 | Agents data shape, timeline shape, `gwmgmt` in bucket |
| `TestServiceDataEndpoint` | 2 | Service data shape |
| `TestPublicEndpoints` | 6 | Live probe, robots.txt, PoW, login page, no open redirect |
| `TestDetectionPipeline` | 8 | Bot UA, honeypot path, SQLi, LFI, XSS, method allowlist, security headers |
| `TestAgentsBucketEndpoint` | 3 | Auth guard, shape, bad `t` → 400 |
| `TestLogsDataEndpoint` | 3 | Logs data 200, valid JSON, filter accepted |
| `TestGeoDataEndpoint` | 2 | Geo data shape |
| `TestAdminIPsEndpoint` | 4 | CRUD operations |
| `TestSecretsEndpoint` | 2 | GET 200, values never returned |
| `TestXffEndpoint` | 2 | Resolved IP shown |
| `TestProxyPassthrough` | 4 | Clean browser forwarded, `X-Proxy` header, admin path not forwarded, bypass mode |
| `TestCacheControlHeaders` | 7 | All JSON admin endpoints set `Cache-Control: no-store` |
| `TestAdminIPsValidation` | 1 | Invalid CIDR rejected |
| `TestVhostsAPI` | 10 | Full vhost CRUD, SSRF guard, hostname normalisation |
| `TestControlCenterCharts` | 12 | Control Center HTML, vhost-stats, vhost-breakdown endpoints |

---

## v1.4

### `test_v14.py` — v1.4 Controls
**Version added:** v1.4  
**Purpose:** Body-pattern matching, slowloris guard, bot-trap forms, JS challenge, challenge nonces/cookies.

| Test | Description |
|------|-------------|
| `test_is_suspicious_body` | Body pattern detection |
| `test_body_pattern_off_by_default` | Body pattern detection off by default |
| `test_body_pattern_decodes_percent_encoded_form` | SQLi in form-encoded body caught after percent-decoding |
| `test_inject_bot_trap_when_enabled` | Bot trap HTML injected when enabled |
| `test_no_bot_trap_when_disabled` | No bot trap when disabled |
| `test_bot_trap_triggered_on_filled_field` | Bot trap fires when hidden field filled (v1.5.4: returns `(triggered, matched_field)`) |
| `test_bot_trap_not_triggered_on_empty_field` | Empty hidden field does not trigger |
| `test_bot_trap_not_triggered_on_json` | JSON body ignored for bot trap |
| `test_make_and_verify_chal_nonce_round_trip` | Challenge nonce round-trip |
| `test_chal_nonce_rejects_forged` | Forged nonce rejected |
| `test_chal_nonce_rejects_expired` | Expired nonce (>120s) rejected |
| `test_chal_cookie_round_trip` | Challenge cookie round-trip |
| `test_chal_cookie_rejects_forged` | Forged cookie rejected |
| `test_chal_cookie_rejects_empty` | Empty cookie rejected |
| `test_chal_cookie_rejects_ua_mismatch` | Cookie issued for one UA doesn't validate under different UA |
| `test_js_challenge_applicable_off_by_default` | JS challenge off by default |
| `test_js_challenge_applies_on_html_get_no_cookie` | Challenge applies when identity risk ≥ threshold (v1.5.4) |
| `test_js_challenge_skips_static_assets` | Challenge skips static assets |
| `test_js_challenge_skips_admin` | Challenge skips admin paths |
| `test_js_challenge_skips_when_cookie_valid` | Challenge skips when valid chal cookie present |
| `test_js_challenge_skips_non_html_accept` | API clients (JSON Accept) skip HTML challenge |
| `test_js_challenge_skips_non_get` | Non-GET skips challenge |
| `test_js_challenge_required_on_api_no_cookie` | V8: API path without cookie requires challenge |
| `test_js_challenge_required_on_post_no_cookie` | V8: POST without cookie requires challenge |
| `test_js_challenge_not_required_when_cookie_valid_on_api` | Valid cookie passes API requests |
| `test_js_challenge_open_paths_opt_out` | Operator-defined open prefixes bypass cookie requirement |
| `test_js_challenge_html_served_when_enabled` | Challenge HTML served when JS challenge enabled |
| `test_js_challenge_endpoint_requires_turnstile_token` | `/challenge` only mints cookie with valid Turnstile token |
| `test_js_challenge_target_blocks_open_redirect` | M1: `//evil.com/` target blocked, falls back to `/` |
| `test_js_challenge_disabled_passes_through` | JS challenge disabled → fully no-op |
| `test_body_timeout_constant_is_set` | Slowloris guard constant wired in |

---

## v1.4.2

### `test_v142.py` — v1.4.2 Controls
**Version added:** v1.4.2  
**Purpose:** TLS fingerprint deny-list (JA3/JA4), STRICT_ORIGIN enforcement, REQUIRED_HEADERS.

| Test | Description |
|------|-------------|
| `test_tls_fingerprint_off_by_default` | TLS fingerprint deny-list off by default |
| `test_tls_fingerprint_blocks_listed` | Listed fingerprint blocked |
| `test_tls_fingerprint_missing_header_passes` | Missing fingerprint header passes |
| `test_tls_fp_blocked_when_unset_trusted_peers` | Empty `JA4_TRUSTED_NETS` = trust all peers |
| `test_tls_fp_ignored_from_untrusted_peer` | TLS-1 fix: header from outside trusted range ignored |
| `test_origin_check_off_by_default` | STRICT_ORIGIN off by default |
| `test_origin_check_get_always_passes` | GET always passes origin check |
| `test_origin_check_post_missing_origin_fails` | POST with missing origin fails |
| `test_origin_check_matching_origin_passes` | Matching origin passes |
| `test_origin_check_mismatched_origin_fails` | Mismatched origin fails |
| `test_origin_check_open_paths_bypass` | Open paths bypass origin check |
| `test_required_headers_off_by_default` | Required headers check off by default |
| `test_required_headers_passes_when_present` | Required headers pass when present |
| `test_required_headers_blocks_when_missing` | Missing required headers blocked |
| `test_required_headers_skip_admin_paths` | Admin paths skip required headers check |
| `test_required_headers_skip_static_assets` | Static assets skip required headers check |
| `test_required_headers_multi_all_required` | All headers in multi-header list required |

---

## v1.4.x–1.5.x Regressions

### `test_control_regressions.py` — V8/V9/V1.4–1.5 regression tests
**Version added:** v1.4.x+  
**Purpose:** Encodes specific past pentester findings so future refactors don't reintroduce them.

| Test | Description |
|------|-------------|
| `test_v8_api_path_blocked_without_chal_cookie` | Pentester finding: API path without cookie blocked (not forwarded) |
| `test_v8_api_post_blocked_without_chal_cookie` | POST without cookie blocked |
| `test_v8_block_does_not_reveal_gateway` | Silent decoy on cookieless API hit — no 401 fingerprinting |
| `test_f3_api_path_with_css_suffix_does_not_bypass` | Spring suffix matching bypass blocked (`.css` suffix on API path) |
| `test_f3_genuine_static_asset_still_bypasses` | Real static assets still bypass |
| `test_open_paths_opt_out_forwards_to_upstream` | Operator-defined open paths proxied |
| `test_html_navigation_serves_challenge_page` | Turnstile challenge page served for risky identities |
| `test_valid_chal_cookie_unlocks_api` | Valid chal cookie unlocks API requests |
| `test_challenge_endpoint_rate_limited` | `/challenge` endpoint rate-limited |
| `test_host_mismatch_silent_decoys_even_without_cookie` | `ALLOWED_HOSTS` mismatch → silent decoy regardless of cookie |
| `test_v91_chal_cookie_does_not_leak_ip` | V9.1: cookie must not contain raw network tier (RFC1918 IP exposure) |
| `test_v91_tier_hash_bind_still_works` | Opaque tier-hash still gates cross-network replay |
| `test_v9_chal_cookie_bound_to_ip_tier` | V9: cookie from one network tier doesn't validate from another |
| `test_v9_turnstile_required_when_enabled` | Turnstile required when enabled for risky identities |
| `test_v92_ja4_hash_binds_cookie` | V9.2: cookie minted under JA4 X doesn't validate under JA4 Y |
| `test_v92_cookie_does_not_leak_ja4` | V9.2: JA4 fingerprint not in cookie wire format |
| `test_v92_cookie_without_ja4_falls_back` | V9.2: empty JA4 → cookie validates from any handshake |
| `test_r7_canary_injected_into_html` | R7: HTML responses carry canary token in comment + `X-Trace-Id` |
| `test_r7_echoed_canary_blocks_followup` | R7: echoed canary in follow-up request → silent decoy |
| `test_r7_no_false_positive_without_echo` | Normal follow-up without echoed canary not flagged |
| `test_r8_canary_echo_is_in_hostile_reasons` | R8: canary-echo in hostile-pool reasons (24h ban) |
| `test_v145_key_rotation_invalidates_old_cookies` | 1.4.5: old SESSION_KEY cookies fail immediately after rotation |
| `test_v146_request_id_threaded_through_responses` | 1.4.6: every response carries `X-Request-ID` |
| `test_v146_inbound_request_id_honoured` | 1.4.6: CDN-tagged `X-Request-ID` honoured |
| `test_v146_inbound_request_id_rejected_if_unsafe` | 1.4.6: CRLF/control-byte trace ID discarded |
| `test_v147_config_get_returns_current_state` | 1.4.7: `/secured/config` GET returns current knob values |
| `test_v147_config_post_applies_and_rejects` | 1.4.7: POST applies whitelisted knobs, rejects everything else |
| `test_v147_config_unauth_silent_decoyed` | No key → `/secured/config` silently decoys |
| `test_v150_shared_ban_set_get_round_trip` | 1.5.0: cross-instance ban write/read via shared store |
| `test_v150_is_banned_consults_shared_store_on_local_miss` | 1.5.0: local cache miss → shared store consulted |
| `test_v150_session_churn_bans_fingerprint` | 1.5.0: `SESSION_CHURN_MAX` cookies from same fingerprint → ban |
| `test_v150_observe_ja4_ban_auto_adds_after_threshold` | 1.5.0: JA4 auto-added to deny-list after threshold |
| `test_v150_webhook_called_on_ban` | 1.5.0: `WEBHOOK_URL` → `_post_webhook` dispatched on ban |
| `test_defense_threshold_config_get_returns_numeric_soft_and_ban` | `/config` includes `SOFT_CHALLENGE_SCORE` and `RISK_BAN_THRESHOLD` |
| `test_mozilla_ua_alone_does_not_grant_access` | Mozilla UA alone doesn't grant access; cookie is the real boundary |
| `test_dashboard_html_version_matches_config` | Dashboard HTML version matches `config.GW_VERSION` |
| `test_bypass_paths_proxied_to_upstream` | `BYPASS_PATHS` prefix → direct proxy |
| `test_config_post_rate_limit_burst_applies` | `RATE_LIMIT_BURST` applies via config POST |
| `test_config_post_ip_burst_and_refill_apply` | `IP_BURST` and `IP_REFILL` apply |
| `test_config_post_custom_rules_ip_cidr_response_is_valid_json` | Custom rules with `ip_cidr` → valid JSON response |
| `test_config_post_bool_fields_apply` | Boolean knobs toggle correctly |
| `test_config_post_list_fields_apply` | List knobs apply and return valid JSON |
| `test_config_get_includes_rate_limit_fields` | Config GET includes all rate-limit fields |

---

## v1.6.5

### `test_timescaledb_soak.py` — TimescaleDB 60-second soak test
**Version added:** v1.6.5 · **Updated:** v1.8.7  
**Type:** Integration (requires Docker)

Skipped when Docker is unavailable or no `appsec-antibot-gw` image found. Image detection checks tags in order: `1.8.7` → `1.8.6` → `1.6.5`.

Gateway readiness detection accepts either `"active=postgres"` or `"postgres backend selected"` in container logs (both formats have appeared across versions).

ARM64 thresholds: ≥ 200 requests sent, ≥ 50 Postgres event rows, 10 s drain sleep (up from 3 s) to allow thread-pool inserts to flush.

**v1.8.7 root-cause fix:** `core/metrics.py` `record()` called `pg_insert_event` inside `run_in_executor` but never imported it. The resulting `NameError` was silently swallowed by `except Exception: pass`, producing 0 Postgres writes on every request. Fixed by adding `from db.postgres import pg_insert_event` to `core/metrics.py` imports.

| Test | Description |
|------|-------------|
| `test_timescaledb_60s_soak` | Spins up real TimescaleDB + nginx upstream + gateway (postgres backend), drives ≥ 200 requests over 60 s, asserts ≥ 50 event rows in Postgres and confirms Timescale hypertable created |

---

## v1.7.2

### `test_blockrate_regressions.py` — Block-rate chart regression guards
**Version added:** v1.7.2 (guards against 3 bugs fixed in this version)  
**Type:** Static source analysis

| Test | Description |
|------|-------------|
| `test_no_hardcoded_range_60_fetch_in_blockrate` | Bug 1: `paintBlockRate` must not fetch `metrics?range=60` internally |
| `test_no_fetch_call_in_paintblockrate` | Bug 1 (deeper): no `fetch()` inside `paintBlockRate` |
| `test_paintblockrate_reads_lastmaintimeline` | `paintBlockRate` reads `window._lastMainTimeline` |
| `test_paintblockrate_reads_lastmainbucketsecs` | `paintBlockRate` reads `window._lastMainBucketSecs` |
| `test_setinterval_does_not_call_loadblockrate` | Bug 2: `setInterval` must not include `loadBlockRate` (deduplicates HTTP) |
| `test_window_paintblockrate_exposed` | `paintBlockRate` exported as `window._paintBlockRate` |
| `test_tick_calls_window_paintblockrate` | `tick()` calls `window._paintBlockRate` |
| `test_uses_fmttime_for_labels` | Bug 3: labels use `fmtTime()` not `toISOString()` |
| `test_no_toisostring_in_paintblockrate` | Bug 3 (deeper): no `toISOString()` in `paintBlockRate` |
| `test_yaxis_min_0_max_100` | Y-axis bounded 0–100 (percentage chart) |
| `test_formula_includes_missed_bucket` | Block-rate formula accounts for `b.missed` |

---

## v1.7.3

### `test_v173.py` — v1.7.3 AI-agent detection
**Version added:** v1.7.3  
**Purpose:** P1 Honey-cred, P2 Redirect maze, P3 LLM heuristic, P4 Canary probe.

| Class | Tests | Description |
|-------|-------|-------------|
| `TestHoneyCred` | 10 | Honey credential injection and lookup; key format, injection logic, noop conditions |
| `TestRedirectMaze` | 7 | Token sign/verify, expiry, malformed, maze entry paths, step increment |
| `TestLLMHeuristic` | 9 | HTML-only requests trigger signal; mixed requests pass; below min-count passes; cooldown; subresource detection |
| `TestCanaryProbe` | 10 | Injection before `</head>`, noop conditions, TTL-gated firing, token storage |

### `test_path_sweep.py` — Path sweep detector
**Version added:** v1.7.3  
**Type:** Unit

| Test | Description |
|------|-------------|
| `test_static_exts_not_recorded` | Static asset paths never added to sweep counter |
| `test_non_static_paths_are_recorded` | Non-static paths recorded |
| `test_admin_ns_exact_not_recorded` | Admin namespace paths excluded |
| `test_check_fires_at_threshold` | Fires when distinct paths ≥ threshold |
| `test_check_does_not_fire_below_threshold` | Does not fire below threshold |
| `test_repeated_path_counts_as_one` | Same path many times = 1 distinct path |
| `test_expired_entries_pruned` | Entries older than window pruned on check |
| `test_check_on_unknown_key_returns_false` | Unknown key returns `False` safely |

---

## v1.7.7

### `test_geo_dashboard.py` — Geo dashboard and load-status pill
**Version added:** v1.7.7  
**Type:** Static + dynamic

| Class | Tests | Description |
|-------|-------|-------------|
| `TestGeoPillHTML` | 17 | Pill HTML, CSS, JS structure; initial state `loading` not `ready`; double-RAF flip; idempotent check |
| `TestGeoDashboardPage` | 6 | Auth guard, HTML served, pill present, no-store header, X-Frame-Options |
| `TestGeoDataAPI` | 21 | Auth guard, 200 with auth, `configured`/`points` keys, unconfigured shape, summary keys/types, range params |
| `TestGeoPillRegression` | 12 | Existing `#live` pill still present, map container, country section, tick/renderMap/renderAsns order |
| `TestGeoScrubberCumulativeCorrectness` | 7 | Events entry shape `[ts, lat, lng, kind]`, scrubber cap at 5000, `missed` kind excluded |

---

## v1.7.9

### `test_v179.py` — v1.7.9 fixes
**Version added:** v1.7.9

| Class | Tests | Description |
|-------|-------|-------------|
| `TestAgentsTimelineGwmgmt` | 7 | `gwmgmt` key in timeline buckets and totals; numeric; admin-namespace events counted |
| `TestLogsDataJsonSafety` | 5 | Regression: endpoint always returns `application/json`; path-filter doesn't trigger HTML error page |
| `TestPathHitsTotalRows` | 5 | `total_rows` key present; integer; `ips` list present; `total_rows >= len(ips)` |
| `TestBanUnbanEndpoints` | 8 | Auth guard; ban/unban 200; hard ban 31-day; ban by identity ID; response body contains IP |

---

## v1.7.10

### `test_v1710.py` — v1.7.10 fixes
**Version added:** v1.7.10

| Class | Tests | Description |
|-------|-------|-------------|
| `TestAgentsBucketGwmgmt` | 5 | `gwmgmt` key in bucket response; empty when no admin events; reflects admin-namespace events; excludes non-admin paths; required fields per entry |
| `TestServeMirrored404EmptyCache` | 4 | Post-UPSTREAM-change empty cache: no 500; sensible body; no crash; cache repopulated |
| `TestPathCategoryConfigToggle` | 5 | `BYPASS_PATHS` and `JS_CHAL_OPEN_PATHS` hot-reload via config POST; auth guard |

---

## v1.7.11

### `test_v1711.py` — v1.7.11 security hardening (M1/M4/M6/M7/H3/H5/M2)
**Version added:** v1.7.11

| Class | Tests | Description |
|-------|-------|-------------|
| `TestM4CookieGhostMissesReset` | 4 | Prune loop zeros `cookie_ghost_misses` for idle non-banned identities |
| `TestM6UniquePathsCleared` | 4 | Prune loop clears `unique_paths` for idle non-banned identities |
| `TestM7VacuumInWriterLoop` | 4 | `VACUUM` executes after 86400s; not before; source contains VACUUM |
| `TestM1PrintToSlog` | 8 | Critical paths use `slog()` not `print()`; affected modules: proxy_handler, rate_limit, sqlite, tor, maxmind, postgres, scoring |
| `TestH3PgPool` | 9 | Pool reuse, dead connection discarded, pool exhaustion raises timeout, broken conn discarded, stats correct |
| `TestH5PruneUnboundedDicts` | 6 | Stale `_ACTIVE_SESSIONS` evicted; `_signal_order_cache` capped at 2000→1000; `_asn_path_clusters` old minutes evicted |
| `TestH5LoginBucketEviction` | 3 | `_login_rate_limit` evicts expired entries; target IP intact after eviction |
| `TestM2DeadCodeRemoved` | 4 | `_load_signal_order_cache` / `_save_signal_order` have exactly one try/except for mesh import |

### `test_h3_pg_pool.py` — PostgreSQL connection pool
**Version added:** v1.7.11 (H3 fix)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestPgPoolUnit` | 21 | Pool init, stats, ping health, fast path, acquire/release, LIFO order, context manager, timeout error |
| `TestPgPoolRegression` | 11 | Concurrent acquires never exceed max; consistent after discard; unknown op returns False; no pool → False; pool slot freed on connect failure |
| `TestPgPoolFunctional` | 12 | `_get_pool` None when no DSN; singleton; stored in state; pool size/timeout env vars; source uses pool (not `pg.connect()`) |

### `test_h4_pg_backend_switch.py` — PostgreSQL backend switch endpoint
**Version added:** v1.7.11 (H4 fix — live DB backend switching)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestMigrateRecentEvents` | 7 | SQLite→Postgres copies rows within window; no rows → `{ok:True, copied:0}`; Postgres→SQLite copies rows; pg connect failure → `{ok:False}`; only window rows copied |
| `TestPgMirrorKvOps` | 14 | `_pg_mirror_kv` routes `set_config`/`del_config`/`set_secret`/`del_secret`/`set_admin_ip`/`del_admin_ip`/`update_admin_ip_description`/`gw_audit_add` to correct SQL; unknown op → False; pool timeout → False; no pool+no DSN → False; arg-count assertions for each op |
| `TestPgInsertEvent` | 8 | Returns True on success; executes INSERT SQL; UA truncated at 500 chars; None UA coerced to `''`; returns False on sqlite backend / pool None / execute exception; optional fields default to `''` |
| `TestKnownSqliteOnlyTables` | 5 | `dlp_patterns`, `audit_events`, `svc_metrics` absent from Postgres schema; all `svc_metrics` `_SCHEMA_MIGRATIONS` entries have `pg_ddl=None`; `dlp_patterns` DDL in sqlite.py but not postgres.py |
| `TestDbSwitchValidation` | 11 | Endpoint callable; rejects non-`{sqlite,postgres}` targets; verifies psycopg loadable; requires DSN for postgres; calls `pg_test_roundtrip()`; calls `_migrate_recent_events`; persists `DB_BACKEND` to `config_kv`; uses `os._exit(0)` for restart; returns JSON before exit; migration stats in response; route registered in router |
| `TestStartupPostgresPath` | 3 | `on_startup` calls `db_init_postgres()` when `DB_BACKEND=postgres`; `db_init_postgres` called regardless of backend (standby schema); `db_init_postgres` uses `CREATE TABLE IF NOT EXISTS` (idempotent) |

### `test_h5_m2_dynamic.py` — Dynamic tests for H5 + M2
**Version added:** v1.7.11

| Class | Tests | Description |
|-------|-------|-------------|
| `TestH5DynamicActiveSessions` | 3 | Stale sessions evicted; empty dict no-op; recent sessions survive |
| `TestH5DynamicSignalOrderCache` | 2 | Oversized cache trimmed to 1000; under-limit untouched |
| `TestH5DynamicAsnPathClusters` | 3 | Old clusters evicted; current minute preserved; empty no-op |
| `TestH5DynamicLoginBucket` | 4 | Expired entries evicted; blocked IP still blocked; mass eviction doesn't corrupt; expired IP gets fresh window |
| `TestM2DynamicScoringFunctions` | 6 | `_load_signal_order_cache` / `_save_signal_order` exit cleanly when mesh raises; no infinite retry; source has single import |

### `test_settings_config_functional.py` — Settings export/import + config endpoint
**Version added:** v1.7.11+  
**Type:** Full dynamic (in-process proxy)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestConfigGet` | 5 | 200 authenticated; `state` key; all knobs present; unauthenticated decoy; content-type JSON |
| `TestConfigPost` | 6 | Correct flat format applies; wrong `key`/`value` wrapper rejected; multiple knobs; unknown knob rejected; GET reflects change; unauthenticated decoy |
| `TestSettingsExportContent` | 10 | ZIP magic bytes; XML entry; root tag; knobs/admin-IPs/secrets sections; knob count matches hot-reload list; values match live state |
| `TestSettingsImportRoundTrip` | 4 | Round-trip 4 knobs; all knobs applied on fresh export; 200; summary keys |
| `TestSettingsImportDryRun` | 3 | Reports counts without applying; dry_run flag; zero errors on valid ZIP |
| `TestSettingsImportErrors` | 6 | Empty body; non-ZIP; missing XML; bad XML; wrong root tag; unauthenticated decoy |
| `TestSettingsImportAdminIPs` | 3 | Admin IPs round-trip; invalid CIDR → errors[]; env-sourced IPs not exported |
| `TestSettingsImportEnvPinned` | 6 | Env-pinned knob rejected with `env-pinned` reason; not in applied; live value unchanged; `applied + rejected == len(knobs)` |
| `TestControlsDashboard` | 6 | Controls and settings pages 200 authenticated; unauthenticated decoy; no-cache header |
| `TestSettingsImportTestButton` | 7 | Test button (dry_run=1): 200 on valid ZIP; doesn't mutate state; counts would-apply; error on empty body |
| `TestVhostPolicyDashboard` | 4 | Auth guard; HTML served; no-store; X-Frame-Options |
| `TestVhostPolicyDataEndpoint` | 8 | Auth guard; 200; required keys; vhost knobs list; global has upstream; no-store; hostname param; vhosts list |
| `TestDbConfigExportImport` | 11 | DB_BACKEND in state; default value 'sqlite'; POSTGRES_DSN in state; export XML has both knobs; exported value matches active backend; import DB_BACKEND applied + reflects in GET; import POSTGRES_DSN applied; export after change reflects new value; invalid backend 'mysql' rejected |

---

## v1.7.12

### `test_v1712.py` — v1.7.12 fixes
**Version added:** v1.7.12

| Class | Tests | Description |
|-------|-------|-------------|
| `TestQ2RefillDivByZeroGuard` | 8 | `RATE_LIMIT_REFILL` and `IP_REFILL` clamped to minimum 0.001 (prevents ZeroDivisionError) |
| `TestQ1SessionSecureBoolParsing` | 14 | `SESSION_SECURE` accepts all common falsy spellings: `FALSE`, `no`, `off`, `NO`, `OFF` etc. |
| `TestQ5EnvNameAlias` | 5 | `NEW_SESSIONS_PER_IP_PER_MIN_HOSTING` and legacy `NEW_SESSIONS_PER_HOSTING` both accepted |
| `TestQ4DeadInnerTryExcept` | 4 | `_load_signal_order_cache` / `_save_signal_order` have at most one mesh import |
| `TestP5BackgroundTasksAnchor` | 5 | `create_task()` calls anchored in `_background_tasks` set; done callback removes completed task |
| `TestL2LogoutPostOnly` | 5 | Logout is POST-only (CSRF guard on GET logout link); all dashboard logout forms use `<form method="post">` |
| `TestS2InternalKeyNotPrinted` | 5 | Boot banner shows only first 4 chars of `INTERNAL_KEY` |
| `TestP3AbuseIPDBNonBlockingSQLite` | 3 | AbuseIPDB cache lookup runs in thread-pool executor |
| `TestP4SharedHttpSession` | 12 | `abuseipdb`, `crowdsec`, `webhook` use shared `ClientSession`; sessions reused; closed sessions replaced |
| `TestOnIpToIdentitiesIndex` | 9 | NAT detection uses `ip_to_identities` O(m) index not O(N) full scan; index populated/updated on `last_ip` write; prune removes evicted identity |
| `TestOnIpToIdentitiesWriteSites` | 4 | All write sites for `last_ip` also maintain index; prune discards from index at eviction |
| `TestScoringDecayRisk` | 7 | Exponential decay: zero elapsed → no change; one halflife → 50%; `risk_by_reason` decays in lockstep; sub-0.5 entries pruned |
| `TestDOMPurifyIntegration` | 5 | Every dashboard loads `purify.min.js`; `_dp()` table-context fix; no `onclick` inside `_dp()` calls; session revoke uses `data-attribute` |

---

## v1.8.0

### `test_v180.py` — v1.8.0 Virtual Hosts multi-vhost selector
**Version added:** v1.8.0

| Class | Tests | Description |
|-------|-------|-------------|
| `TestU1VhostCRUD` | 8 | `vhost_set`/`vhost_delete`/`vhost_list` round-trip; hostname normalised to lowercase; empty hostname rejected; API uses `hostname` key |
| `TestU2VhostContextVar` | 5 | `set_vhost` / `current_vhost_host` per-task isolation via ContextVar |
| `TestU3SSRFGuard` | 8 | `_assert_upstream_public` rejects loopback, RFC-1918, localhost; accepts public HTTPS |
| `TestU4VhostCoercions` | 7 | `_VHOST_COERCE` converts env-parsed JSON to correct Python types |
| `TestU5IpStateLastVhost` | 3 | `IpState.last_vhost` field exists, defaults to `''` |
| `TestU6U7SqliteMigration` | 4 | `events` table has `vhost` column; INSERT with vhost; default `''`; migration listed |
| `TestF1F4MetricsVhostFilter` | 5 | Metrics `?vhost=` filters clients, timeline, recent events |
| `TestF5F6GeoVhostFilter` | 3 | `geo_data_endpoint` appends `AND vhost=?`; cache key differs by vhost; parameterised query |
| `TestF7AgentsDataVhostFilter` | 2 | `agents_data_endpoint` `?vhost=` filters by `s.last_vhost` |
| `TestF8AgentsTimelineVhostSQL` | 3 | All 5 SQL queries in agents timeline respect vhost filter |
| `TestF9F10VhostsAPI` | 4 | `/vhosts` GET/POST/DELETE; API uses `hostname` key; SSRF guard |
| `TestH1MainHtmlVhostSelector` | 10 | Vhost bar, pill CSS, `_vhostParam`, session storage, metrics/cost-timeline fetch, uses `v.hostname` not `v.host` |
| `TestH2AgentsHtmlVhostSelector` | 8 | Same as H1 for agents.html |
| `TestH3GeoHtmlVhostSelector` | 8 | Uses `v.hostname` (critical bug fix), `v.UPSTREAM` (was `v.upstream`) |
| `TestSourceLevelGuards` | 8 | Source-level checks: `record()` sets `last_vhost`, event dict/queue tuple includes vhost, endpoints read vhost param |

### `test_vhost_filtering.py` — Vhost-scoped filtering
**Version added:** v1.8.0

| Class | Tests | Description |
|-------|-------|-------------|
| `TestU1MetricsVhostFilter` | 5 | Timeline isolates by vhost; empty when no match; unauthenticated decoy |
| `TestU2CostTimelineVhostFilter` | 3 | Cost timeline intentionally global; `?vhost=` silently ignored |
| `TestU3AgentsDataVhostFilter` | 3 | `?vhost=` accepted; unauthenticated decoy |
| `TestU4AgentsTimelineVhostFilter` | 4 | SQL WHERE applied; detected total isolated; zero when no match |
| `TestU5GeoDataVhostFilter` | 4 | `?vhost=` accepted; reduces result set |
| `TestU6ServiceDataVhostFilter` | 4 | `app.vhost_filter` reflects in response; unauthenticated decoy |
| `TestU7LogsDataVhostFilter` | 5 | `WHERE vhost=?` for `kind=requests`; empty when no match; `kind=gw` ignores vhost (global) |
| `TestR1SourceGuards` | 7 | Source-level checks: all endpoints have vhost SQL clause; `logs.html` sends `_vhostParam`; `cost-timeline` does NOT send vhost param |

---

## v1.8.0–v1.8.1

### `test_v180_v181_gaps.py` — Coverage gaps for v1.8.0 and v1.8.1
**Version added:** v1.8.0–v1.8.1

| Test / Class | Description |
|------|-------------|
| `test_doctype_present` | All 9 dashboard pages start with `<!doctype html>` |
| `test_no_hardcoded_blue_388bfd` | `#388bfd` must not appear in canonical dashboards (use `var(--blue)`) |
| `test_acct_modal_html_element_present` | All dashboards have `#acct-modal` overlay |
| `test_portal_footer_element_present` | All dashboards have `<footer class="portal-footer">` |
| `TestTopPathsDomainColumn` | 11 | `#paths-tbl` has Domain/Path/Hits columns; domain cell XSS-escaped; `_path_to_vhost` selects most-seen vhost per path |
| `TestControlCenterPage` | 9 | Title, sidebar, topbar, nav links, vhost-stats card, active nav link; event delegation for pin handler |
| `TestLoginRedirect` | 3 | Default redirect to `/secured/control-center`; no dead `/secured/dashboard` redirect |
| `TestAgentsHtmlTitle` | 2 | `<title>` and topbar heading say `Agents` (not `Stealth Agent Hunter`) |
| `TestServiceVhostPillCSS` | 7 | `service.html` `.vhost-pill` full corrected CSS property set |
| `TestLogsMissedPillCSS` | 2 | `logs.html` has CSS for `data-cat="missed"` pill (base + active) |
| `TestLocationHeaderRewrite` | 9 | Location header rewritten only on 3xx; netloc replaced with gateway; relative URLs unchanged; fragment preserved |

---

## v1.8.1

### `test_audit_trail.py` — Admin Audit Trail
**Version added:** v1.8.1

| Class | Tests | Description |
|-------|-------|-------------|
| `TestU1AuditTableSchema` | 3 | `gw_audit` table exists with required columns and indexes |
| `TestU2GwAuditAddOp` | 6 | SQL insert creates row; stores action/actor; JSON details round-trip; autoincrement |
| `TestU3GwAuditHelper` | 7 | `_gw_audit()` enqueues correct op; noop when `db_queue=None`; queue-full does not raise |
| `TestU4RequestUsername` | 5 | Returns session user or `'unknown'` |
| `TestF1ConfigEndpointAudit` | 5 | Config POST writes audit row per applied knob; actor matches logged-in user; rejected knob writes no row |
| `TestF2VhostsEndpointAudit` | 6 | Vhost POST/DELETE writes audit rows |
| `TestF3SettingsImportAudit` | 3 | Non-dry-run writes `settings_import` row; dry-run writes no row |
| `TestF4AuditLogEndpoint` | 12 | Auth guard; rows/count keys; action/actor filters; limit; since filter; oversized limit capped at 1000 |
| `TestRSourceGuards` | 12 | Source-level: postgres has `gw_audit_add` case; old-value captured before assignment; config/vhosts/settings-import enqueue audit correctly; no SQL injection in audit log |

### `test_v181_vhost_comparison.py` — Vhost comparison endpoints
**Version added:** v1.8.1

| Class | Tests | Description |
|-------|-------|-------------|
| `TestU1–U17` (17 classes) | ~20 | Vhost-stats schema; empty DB; time windows; reason classification; excluded reasons; bans count; vhost-breakdown schema/slots/isolation; vhost-policy data schema/match/knob list |
| `TestF1F5VhostStatsEndpoint` | 5 | Unauthenticated decoy; 200; no-store; seeded events aggregate correctly; two vhosts sorted by `total_1h` desc |
| `TestF6F12VhostBreakdownEndpoint` | 7 | Unauthenticated decoy; 200; no-store; correct dataset; labels length; small range window; invalid range → 400 |
| `TestF13F17VhostPolicyEndpoints` | 5 | Auth guards; HTML served; data returned with all keys; no-store |
| `TestRegressions` | 7 | `/vhosts` GET still works; stats/breakdown POST → 405; bucket clamp ≥ 60; `ts` recent; labels are unix timestamps |
| `TestConfigVhostParam` | 8 | `/config?vhost=X` returns merged state; unknown vhost → base state; overridden keys sorted; no-store |
| `TestTVTopbarVhostOverlap` | 10 | `#vhost-select`, `#gw-status-pill`, `#gw-loglvl-wrap` all inside `#topbar-right`; no `position:fixed`; no duplicates; `max-width` set; correct order |
| `TestRVRefreshVhosts` | 12 | `refreshVhosts()` defined; uses `credentials:'include'`; called on DOMContentLoaded; 5s interval; `visibilitychange`; sync without length guard; removes stale options |
| `TestV1ValidateVhostHostname` | 18 | FQDN, wildcard, trailing dot, empty, port, bare IP, double wildcard, label length all validated |
| `TestV2VhostSetValidation` | 7 | API rejects invalid hostnames |
| `TestV3HostnameValidatorSourceGuards` | 4 | Validator always called in `vhost_set()` and env parse loop |
| `TestConfigVhostWrite` | 5 | POST `/config?vhost=X` writes to vhost, not global; non-overridable key rejected; global unaffected |

---

## v1.8.2

### `test_v182_charts.py` — v1.8.2 new/upgraded charts
**Version added:** v1.8.2  
**Type:** Static

Six new/upgraded charts: Traffic Pipeline, Bot Score Distribution, Vhost Heatmap, Signal Perf, Geo Country, Threat Donut.

| Tests | Description |
|-------|-------------|
| `test_s01–s09` | Traffic Pipeline card, canvas, KPI row, fetch params, 4 datasets, `fill:'stack'`, destroy-before-new, DOMContentLoaded, live-mode 60s interval |
| `test_s10–s16` | Bot Score Distribution card, canvas, empty state, 8-bin labels, destroy-before-new, 30s interval |
| `test_s17–s23` | Vhost Heatmap card, fetch, time params, HTML table, silent badge |
| `test_s24–s30` | Signal Performance card, canvas, 2 datasets, horizontal bars, 60s interval |
| `test_s31–s34` | Geo Country chart canvas, variable, destroy-before-new, CSS hidden |
| `test_s35–s43` | Threat Donut card, fetch, small-slices grouping into 'other', doughnut type, 30s interval; new chart vars and CSS |

### `test_v182_svc_metrics_db.py` — Service metrics 30-day DB read path
**Version added:** v1.8.2

| Class | Tests | Description |
|-------|-------|-------------|
| `TestA_StaticChecks` | 9 | `_svc_db_history` defined; endpoint uses `_mem_raw`; DB path called; COALESCE; GROUP BY bucket; 30-day retention default |
| `TestB_SvcDbHistory` | 4 | Empty DB → zero-filled buckets; sample in correct bucket; empty buckets filled with zeros; all required keys |
| `TestC_EndpointRouting` | 4 | DB path when range exceeds buffer; memory path for short ranges; current always from memory; retention used in prune |
| `TestS_StaticQA` | 9 | Closes connection; try/except; avg/max/sum keys; range/bucket query params; uses AVG/MAX; 30-day cap |
| `TestD_Dynamic` | 6 | 200 authenticated; required keys; DB path with seeded data; no secret keys; `samples_in_buffer` present; no-store |

### `test_livefeed_detector_stats.py` — Live Feed detection methods panel
**Version added:** v1.8.2 fix  
**Purpose:** Fixes `url()` wrapper bug in `loadDetectorStats()` and `loadLogLevel()`.

| Test | Description |
|------|-------------|
| `test_s1_loadDetectorStats_no_url_wrapper` | `loadDetectorStats()` fetches path directly, not via `url()` |
| `test_s2_loadDetectorStats_fetches_detector_stats` | Contains detector-stats path as bare string |
| `test_s3_loadLogLevel_no_url_wrapper` | `loadLogLevel()` fetches `/secured/config` without `url()` wrapper |
| `test_s4_no_global_url_function_calls` | No remaining `url()` calls with gateway paths |
| `test_d1–d6` | Dynamic: detector-stats 200; required keys; signals/methods are lists; chal fields; methods shape after hit; no-cache |

---

## v1.8.3

### `test_v183_incidents.py` — Security Incidents card
**Version added:** v1.8.3  
**Type:** Static

35 static tests covering:
- `#card-incidents` HTML structure, dismiss bar, incident table elements
- `loadSecurityIncidents()` function: fetch endpoint, DOMContentLoaded, 30s interval
- `renderIncidents()`: severity badges, risk score, ban button
- `_banIp()`, `_incDismiss()` functions and localStorage persistence
- CSS: `.sev-badge`, `.sev-critical/high/medium`, `.inc-count-box`, red border
- Python: `INCIDENT_CRITICAL/HIGH/MEDIUM` frozensets, `_incident_severity()` function
- Route registered in `proxy.py`; fetch uses credentials; ban uses POST; `escapeHtml` in render

---

## v1.8.4

### `test_v184_siem.py` — SIEM Security Event Center
**Version added:** v1.8.4  
**Type:** Static + dynamic

46 tests covering:
- Time-window scoping (`?mins=`, range buttons 15m/1h/6h/24h)
- Vhost filter, alert banners, alert rules panel, JA4 drawer
- `escapeHtml` global, no leaked `setInterval`, `_timers` array, `beforeunload`
- Chart.js local asset (no CDN), `tick()` sends credentials
- Severity CSS classes, KPI elements, table body elements, chart canvases
- SIEM nav link in all other dashboards, `escapeHtml` in render functions
- Severity classification (critical/high/medium/low/info), threat categories (11)
- Bypass reasons, SIEM routes in `proxy.py`, SIEM imported in dashboards init

### `test_v184_uiux.py` — v1.8.4 UI/UX improvements
**Version added:** v1.8.4  
**Type:** Static

| Class | Tests | Description |
|-------|-------|-------------|
| `TestP1BDeadLinks` | 4 | No dead `/center-control` self-link; no dead `/dashboard` link; active link to `/control-center`; `/live-feed` present |
| `TestP2BDuplicateFetch` | 5 | `loadSignalPerf()`/`loadThreatDonut()` not bare-called in DOMContentLoaded (called via `_loadThreatSection()` instead) |
| `TestP2CAriaToast` | 3 | Toast has `role=status`, `aria-live=polite`, `aria-atomic` |
| `TestActionErrorReporting` | 6 | Ban/unban catch calls `_gwAlert`; ban has confirm guard; no bare silent catch |
| `TestNavStructure` | 8 | Service/Agents/SIEM are sub-items; SIEM after Agents; SIEM not last; active class correct per page |

---

## v1.8.5 / v1.8.6 / v1.8.7

### `test_v185_controls_nav.py` — Controls split-pane navigation
**Version added:** v1.8.6 · **Updated:** v1.8.7  
**Purpose:** Split-pane nav with 190px `#ctrl-nav` sidebar, `#ctrl-panels` content, dirty-count badges, search filter.

**v1.8.7 changes:** Removed `infra` and `monitoring` sections from the controls nav. `SECTIONS` now has 5 entries (was 7). Removed card IDs: `card-infrastructure`, `card-active-rules`, `card-lists-snap`, `card-ep-policies`, `card-audit-log`. Also fixed DOMPurify stripping `onclick` in `settings.html` `renderInfra`/`renderCredentials` — replaced inline handlers with `data-*` attribute delegation.

| Class | Tests | Description |
|-------|-------|-------------|
| `TestStructure` | 12 | `#ctrl-split`, `#ctrl-nav`, `#ctrl-panels`, `#ctrl-scope-strip`, nav search input; no standalone `.actions` div; no `<main>` wrapper; Apply/Reset/Hint in `#topbar-right`; bypass-bar inside `#ctrl-panels`; vhost-scope-bar inside `#ctrl-scope-strip` |
| `TestJSLogic` | 14 | `CARD_SEC` mapping; all 5 section IDs in `SECTIONS` (infra and monitoring removed in v1.8.7); `_switch()`, `_buildNav()`, `_updateBadges()` defined; `window._ctrlNavFilter` and `window._ctrlNavUpdateBadges` exposed; DOMContentLoaded patches `mark()`/`clearDirty()`; `cni-dirty` CSS class; `_switch('detection')` as default |
| `TestRegressions` | 22 | 6 card IDs preserved (removed: `card-infrastructure`, `card-active-rules`, `card-lists-snap`, `card-ep-policies`, `card-audit-log`); `apply`/`reset`/`hint`/`bypass-bar`/`vhost-sel` IDs preserved; `loadScoring()`/`mark()`/`clearDirty()` still defined; CSS rules for `#ctrl-nav`, `#ctrl-panels`, `ctrl-nav-item`, `cni-dirty` present |

### `test_v185_new_features.py` — v1.8.6 new features
**Version added:** v1.8.6

| Class | Tests | Description |
|-------|-------|-------------|
| `TestTotp` | 8 | TOTP secret generation; verify valid/invalid code; provisioning URI; 8 backup codes; `_TOTP_PENDING` state dict; login returns step=`totp_required` when enabled |
| `TestJa4h` | 7 | `compute_ja4h()`: GET fingerprint 4-part; POST with body flag `y`; referer flag `r`; header count format; `JA4H_DENY_LIST` exists |
| `TestDetectorHealth` | 5 | `_DETECTOR_HEALTH` dict; `set_detector_health` ok/degraded; `last_check_ts` float; status endpoint includes `detectors` key |
| `TestDlpPatterns` | 6 | `dlp_patterns` table in db_init; GET/POST/DELETE functions importable; route registered; DB writer handles `dlp_add`/`dlp_toggle`/`dlp_delete` |
| `TestCredStuffing` | 8 | `auth_failures` on `IpState`; `_auth_fail_global` deque; `AUTH_FAIL_THRESHOLD`/`AUTH_FAIL_WINDOW_SECS`; `_is_auth_path` helper; `AUTH_PATHS` frozenset; `upstream-auth-fail` in `RISK_WEIGHTS`; `CRED_STUFF_GLOBAL_RPS` |

### `test_v185_security.py` — v1.8.6 security features
**Version added:** v1.8.6

| Class | Tests | Description |
|-------|-------|-------------|
| `TestCsrf` | 5 | Valid CSRF token accepted; wrong token rejected; GET bypasses check; missing session rejected; `agw_csrf` cookie set on login |
| `TestBodyAlwaysRe` | 10 | Ungated critical patterns (fire even at risk_score=0): UNION SELECT, Log4Shell, metadata IP, LFI `/etc/passwd`, `/proc/self`, cmd injection, shell binary; URL-encoded UNION SELECT; content-type gate |
| `TestBoundedIpStateDict` | 7 | LRU eviction at capacity; access promotes entry; TTL eviction; len; get returns None for missing; contains |
| `TestSmugglingDetection` | 6 | Dual `Transfer-Encoding`+`Content-Length` flagged; obfuscated TE flagged; clean request passes; chunked-only passes; invalid TE flagged; identity TE valid |
| `TestVerbOverride` | 6 | `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`, query param, clean request all detected/passed |
| `TestBanRehydration` | 2 | Active bans loaded on startup; expired bans ignored |
| `TestAuditLog` | 5 | Enqueues event; event types; noop without queue; warn severity for failed login; detail serialised |
| `TestWebhook` | 8 | URL safe/blocks private; filter drops unsubscribed; empty filter allows all; queue enqueues event; circuit breaker opens after failures; worker skips on no URL; `start_webhook_worker` creates task |

### `test_v185_settings_nav.py` — v1.8.6 nav restructure + OIDC settings
**Version added:** v1.8.6

| Test | Description |
|------|-------------|
| `test_nav_service_after_settings` | Service link appears after Settings in nav |
| `test_nav_logs_after_settings` | Logs link appears after Settings in nav |
| `test_nav_service_has_sub_class` | Service nav link carries class `'sub'` |
| `test_nav_logs_has_sub_class` | Logs nav link carries class `'sub'` |
| `test_nav_settings_has_nav_settings_id` | Settings nav retains `id='nav-settings'` |
| `test_service_html_nav_service_is_active` | Service page: Service sub-item is `active` |
| `test_logs_html_nav_logs_is_active` | Logs page: Logs sub-item is `active` |
| `test_sqlite_secret_keys_contains_oidc` | `db/sqlite.py` `_SECRET_KEYS` registers each OIDC config key |
| `test_sqlite_refresh_derives_oidc_enabled` | `_refresh_integration_state` derives `OIDC_ENABLED` from issuer+client_id+secret |
| `test_sqlite_refresh_propagates_oidc_vars` | `_refresh_integration_state` propagates OIDC vars to all modules |
| `test_proxy_handler_secrets_get_returns_oidc_enabled` | `/__secrets` GET includes `OIDC_ENABLED` in integration_state |
| `test_settings_sso_card_present` | `settings.html` has SSO/OIDC card `#card-sso` |
| `test_settings_sso_card_before_users_card` | SSO card appears before Users card |
| `test_settings_sso_client_secret_is_password_type` | Client-secret field type is `password` |
| `test_settings_sso_save_button_present` | `#sso-save` button present |
| `test_settings_sso_clear_button_present` | `#sso-clear` (Disable SSO) button present |
| `test_settings_sso_js_sends_csrf_token` | SSO JS POST includes `X-CSRF-Token` header |
| `test_settings_sso_js_clear_deletes_all_five_keys` | SSO clear handler DELETEs all 5 OIDC keys |
| `test_settings_sso_default_role_select_has_viewer_option` | SSO default-role select includes `viewer` |
| `test_settings_sso_issuer_field_is_url_type` | OIDC issuer field type is `url` |

### `test_v185_settings_migration.py` — Settings cards migrated from controls to settings
**Version added:** v1.8.6 · **Updated:** v1.8.7

Cards for DB backend, credentials, infrastructure, and logging moved from `controls.html` to `settings.html`. Controls page gains a guard (`_settingsCards`) to skip migrated card types.

| Class | Tests | Description |
|-------|-------|-------------|
| `TestSettingsDbCard` | 13 | `card-db` in settings; `btn-db-apply` POSTs to `/secured/db-switch` (not `/secured/config`); `DB_BACKEND` never sent to config; `target=` as query param; success checks `d.ok`; postgres switch includes DSN in body; sqlite needs no DSN; `loadDb()` GETs `/secured/config`; reads `(d.state\|\|d).DB_BACKEND`; toggle elements present; pg-fields section present; `pg-save-btn` POSTs `POSTGRES_DSN` to secrets; `pg-test-btn` calls integration-check |
| `TestSettingsCredentialsCard` | 12 | `card-credentials` in settings; `loadCreds()` single bulk GET `/secured/secrets`; parses `d.secrets`; checks `s.configured`; CREDS array has 7 keys; includes all `_SECRET_KEYS`; excludes env-only secrets; `_clearCred` DELETEs `?name=KEY`; save POSTs to secrets; skips blank fields; source badge distinguishes env from db; Save button present |
| `TestSettingsInfraCard` | 8 | `card-infrastructure` in settings.html; absent from controls.html; `INFRA_KNOBS` has 3 keys; `loadInfra()` GETs config; `btn-infra-apply` POSTs; bool knobs with `restart:true` show restart warning; `UPSTREAM_REWRITE_BASE` marked `restart:false`; infra nav section absent from controls `SECTIONS` |
| `TestSettingsLoggingCard` | 8 | `card-logging` in settings; `LOG_KNOBS` has 3 keys; `loadLogging()` GETs config; `btn-logging-apply` POSTs; `WEBHOOK_EVENT_FILTER` comma-split before POST; `LOG_LEVEL` has 5 options; `LOG_FORMAT` has text/json; logging card absent from controls |
| `TestControlsCleanup` | 9 | `_settingsCards` Set defined; contains `infrastructure`, `ext-misc`, `external-log`; `DB_BACKEND`/`POSTGRES_DSN` skipped in render loop; `_knobSec` returns null for migrated cards; settings link in external section mentions Credentials; `ext-misc` container removed; `card-infrastructure` absent from `CARD_SEC` map |

### `test_v185_week3_week4.py` — Week 3 & Week 4 feature tests (comprehensive)
**Version added:** v1.8.6

| Class | Tests | Description |
|-------|-------|-------------|
| `TestXxeBody` | 7 | Entity declaration, DOCTYPE, `SYSTEM http://`, XHTML, parameter entity detected; clean XML and wrong content-type pass |
| `TestProtoPollution` | 6 | `__proto__` key, `constructor`, nested prototype pollution; valid JSON and empty body pass; regex fallback |
| `TestHeaderSsti` | 6 | Jinja in UA, EL in cookie, ERB in referer, FreeMarker detected; clean headers and safe headers pass |
| `TestHostHeaderInjection` | 6 | Raw IP, path chars, question mark flagged; valid hostname, port suffix, disabled flag pass |
| `TestPasswordComplexity` | 9 | Too short, no uppercase/lowercase/digit/special, common password rejected; valid/12-char pass |
| `TestSessionLimit` | 2 | Session limit enforced; zero sessions ok |
| `TestSessionIdleTimeout` | 2 | Fresh session passes; stale session revoked |
| `TestGraphql` | 7 | Introspection flagged (and allowed when configured); batch over limit; depth exceeded; clean query; wrong path ignored; disabled |
| `TestFileUpload` | 7 | PHP extension, PHP magic bytes, ELF magic, ASP extension, MZ magic detected; valid JPEG and non-multipart pass |
| `TestCircuitBreaker` | 4 | Closed initially; opens after failures; resets on success; not open below threshold |
| `TestAlerting` | 4 | Threat index computation; zero-requests case; ban rate computation; ban rate excludes allowed |
| `TestProbeRateLimit` | 4 | Allows under limit; blocks over limit; different IPs independent; window resets |

### `test_v185_week3week4.py` — Week 3+4 features (parallel/earlier file)
**Version added:** v1.8.6  
**Note:** Similar coverage to `test_v185_week3_week4.py` but uses top-level functions instead of classes. Covers XXE, prototype pollution, SSTI, host header injection, GraphQL, file upload, password complexity, session limit, circuit breaker, alerting/threat index, probe rate limit.

---

## v1.8.6

### `test_interaction_probe.py` — Interaction probe detector
**Version added:** v1.8.6

| Class | Tests | Description |
|-------|-------|-------------|
| `TestInteractionToken` | 5 | Token is 32 hex chars; changes with IP/ts; deterministic; uses `SESSION_KEY` |
| `TestInjectInteractionProbe` | 9 | Injects `<script>` before `</body>`; appends when no body tag; token embedded; disabled → no-op; collects mouse/scroll/key events; sends on `pagehide` |
| `TestAnalyzeMouse` | 6 | Straight line → bot-motion; natural → pass; uniform velocity → scripted-motion; diagonal → bot-motion; detail string on detection |
| `TestAnalyzeScroll` | 4 | Uniform steps → bot-scroll; natural → pass; too few events → None; no movement → None |
| `TestAnalyzeKeys` | 4 | Uniform dwell → scripted-keys; natural typing → pass; too few events → None; zero dwell filtered |
| `TestAnalyzeEntropy` | 3 | Metronomic → low-entropy; random → pass; too few events → None |
| `TestInteractionAnalyze` | 10 | Long window with no events → no-interaction; short window passes; straight line/scroll/keys detected; invalid event types filtered; max events cap; disabled → None; returns tuple; reason is None or string |
| `TestInteractionConfig` | 10 | `INTERACTION_PROBE_ENABLED` exists; all 6 signals in `RISK_WEIGHTS`; token TTL positive; max events cap positive; report endpoint importable; route registered |

### `test_oidc.py` — OIDC SSO
**Version added:** v1.8.6  
**Type:** Static + dynamic (S01–S30, D01–D42)

| Class / Tests | Description |
|-------|-------------|
| `TestS_OIDCStatic` (S01–S14) | All 3 env vars required; state TTL 300s; disabled → 404; state popped (not peeked) on callback; redirect URI from request host; session_secure controls scheme; error param → redirect not 500; provisioning uses INSERT OR IGNORE; direct sqlite3 for provision; `httponly`+`samesite` cookie; default role falls back to `viewer`; `_safe_username` rejects invalid; OIDC button empty when disabled |
| `TestS_OIDCStaticAdditional` (S25–S30) | `_CALLBACK_PATH` uses `ADMIN_NS`; scope in auth params; provision failure → `_redirect_error`; `oidc_login_success` slog; db_queue audit event on success; `OIDC_ISSUER` strips trailing slash |
| `TestS_OIDCStaticExtra` (S15–S24) | Callback calls `_purge_expired_states`; timeout/aiohttp errors caught; ≥5 redirect error paths; default role env default is `viewer`; redirect error goes to `/login?oidc_error=`; login HTML has OIDC error placeholder and SSO CSS; proxy registers both routes; login page injects OIDC button |
| `test_d13–d42` (standalone) | OIDC paths in `_ADMIN_LOGIN_SUBPATHS`; config exports OIDC vars; `_VALID_ROLES` exactly `{admin, maintainer, viewer}`; `_safe_username` edge cases |

---

## v1.8.7

### `test_v187_login_2fa.py` — Two-step login + TOTP
**Version added:** v1.8.7

| Class | Tests | Description |
|-------|-------|-------------|
| `TestLoginHtmlTwoStepStructure` | 13 | Step-1 has username+password fields; step-2 panel and TOTP input exist; numeric input; step-2 hidden on load; step-1 visible on load; back control; step indicator; TOTP submit separate from main submit; JS transitions to step-2 on `totp_required`; JS calls `totp_verify` endpoint with partial token |
| `TestLoginSubmitTotpBranch` | 8 | `TOTP_ENABLED` check in source; `totp_required` step returned; partial token in response; partial token is HMAC-derived; sliced to 16 chars; `_TOTP_PENDING` state stored; partial token bound to time-window and username |
| `TestPartialTokenSecurity` | 5 | Token is 16 hex chars; different users produce different tokens; different windows produce different tokens; window-boundary cross-window accepted; stale token not in accepted windows |
| `TestTotpVerifyEndpointSource` | 12 | Success creates session; clears pending; wrong code → 401; missing token → 400; invalid token → 401; uses `hmac.compare_digest` for token check; backup codes accepted; backup code consumed after use; backup code uses constant-time compare; rate limit applied; logs success/failure events |
| `TestLogoutCsrfExemption` | 4 | `logout_endpoint` has no `@_require_csrf`; docstring documents exemption reason; `@_require_csrf` still on destructive endpoints; all sidebar logout forms use plain `<form method='post'>` |
| `TestSvgQrCodeWhiteBackground` | 8 | White `<rect>` injected inside `<svg>`; covers full SVG; inserted after opening tag; not before tag; uses SVG factory; output is SVG data URL; no Pillow import |
| `TestTotpUtils` | 6 | `totp_generate_secret` returns base32; `totp_verify` accepts current code; rejects wrong/empty code; `valid_window=1` (±30s); strips whitespace from code |

### `test_v187_new_features.py` — v1.8.7 new features
**Version added:** v1.8.7

| Class | Tests | Description |
|-------|-------|-------------|
| `TestMaxmind24hGateSource` | 11 | `_MAXMIND_CHECK_TS_PATH` constant; min interval 86400s; `_read_last_check`/`_write_last_check` defined; `_maxmind_auto_fetch` calls both; logs skip event; refresh loop calls both; wakes hourly; no 30-day check |
| `TestMaxmind24hGateFunctional` | 6 | `_read_last_check` handles missing/valid/corrupt file; `_write_last_check` writes parseable float; `_maxmind_auto_fetch` skips within 24h; proceeds when no timestamp |
| `TestLoginTotpFix` | 6 | Credential-fields wrapper present; username/password inside wrapper; TOTP hides credential fields by ID; no `closest('label')`; TOTP step hidden by default |
| `TestSettingsDbToggle` | 11 | DB track/thumb/lbl-sqlite/lbl-pg elements; `_dbSetTarget` and `_dbToggle` functions defined; `_dbSetTarget` moves thumb, shows/hides pg-fields, gates apply button; apply handler uses `dbTarget` variable; no radio inputs for DB backend |
| `TestMonitoringMovedToLogs` | 23 | `monitoring` absent from `SECTIONS`; `card-active-rules`/`card-lists-snap`/`card-ep-policies` absent from `CARD_SEC`; `loadActiveRules`/`loadLists` not in controls; their HTML absent from controls; `logs.html` has active-rules/lists-snap/ep-policies cards; `logs.html` defines `loadActiveRules`/`loadLists`; uses `_gwAlert`; refreshes every 7s; fetches detector-stats/lists-snapshot; monitoring cards appear after audit log |

### `test_v187_security.py` — v1.8.7 security fixes
**Version added:** v1.8.7

| Class | Tests | Description |
|-------|-------|-------------|
| `TestDET402MazeDestBinding` | 8 | `dest_hash` returns 16 hex chars; valid token verifies with same dest; swapped dest invalidates token; different step/identity/expired/malformed token all rejected; `make_maze_entry` includes dest in token |
| `TestDET403InteractionIdentityBinding` | 5 | Token uses `track_key` not IP; different track keys produce different tokens; same key+ts is deterministic; `inject_probe` uses `track_key` param and embeds token bound to it |
| `TestDET404IdenticalTimestampBypass` | 5 | All-same timestamps detected; fewer than 5 events not triggered; varying timestamps pass; clamped-all-zero detected; single unique offset among many detected |
| `TestPROXY401UpstreamValidator` | 8 | `upstream_safe_to_reload` exists; public HTTPS accepted; private IP rejected; wrong scheme rejected; too-long URL rejected; `ALLOW_PRIVATE_UPSTREAM` bypasses check; that flag not in hot-reload knobs; upstream knob uses safe validator |
| `TestPROXY402ClientHostValidation` | 4 | Legitimate Host passes unchanged; attacker-controlled Host falls back to upstream netloc; empty `ALLOWED_HOSTS` = no enforcement; Host with port stripped for comparison |
| `TestPROXY403PropagateNeverDenylist` | 6 | `PROPAGATE_NEVER` frozenset exists; built-in names in denylist; `SESSION_KEY` propagates for key rotation; `builtins` not propagated; ordinary config knobs still propagate; proxy module class is `proxy_module` |

### `test_v187_settings_vhost_strip.py` — Settings identity strip + vhost badge
**Version added:** v1.8.7

| Class | Tests | Description |
|-------|-------|-------------|
| `TestSettingsVhostStripHTML` | 8 | `gw-vhost`/`gw-upstream` elements present; vhost/upstream labels present; `gw-vhost` uses `display:flex`; `gw-upstream` has `text-overflow:ellipsis` and `title` attribute; identity strip card before Virtual Hosts card |
| `TestSettingsVhostStripJS` | 14 | IIFE fetches health-score and vhosts; hostname set before `await`; uses `textContent` not `innerHTML`; badge created as `<span>`; badge states: `vhost`/`global`/`unregistered`; vhost upstream from `entry.UPSTREAM`; global upstream fallback from `j.upstream`; upstream set on element and in `title`; badge appended to `gw-vhost`; errors logged via `console.error` |
| `TestHealthScoreUpstreamField` | 2 | `health_score_endpoint` includes `upstream` key; references `UPSTREAM` module variable |
| `TestVhostListFormat` | 5 | `/secured/vhosts` returns list; empty when no vhosts; entry has `hostname` key; entry has `UPSTREAM` key; response wrapped in `{"vhosts": [...]}` |

### `test_v187_ux_improvements.py` — v1.8.7 UX improvements
**Version added:** v1.8.7

| Class | Tests | Description |
|-------|-------|-------------|
| `TestGatewayHealthPillUX` | 15 | `KEY_LABELS` defined and maps `block_rate`/`integrations`; has all 6 keys; `STATUS_ORD` defined; pill `onclick` sorts by `status_ord`; `penalty` CSS class; 5-column grid; `gw-score-bar` element; score bar width set in `onclick`; ok-summary CSS; ok rows filtered to lists; pill text uses `Health N/100`; refresh note near pill; old 4-column grid removed |
| `TestScoreBreakdownRewrite` | 15 | `buildScoreHtml` defined; score header/color/label variables; score bar in header; block-count shows "Why Blocked" header and formula; empty comp rows not rendered; synthetic-score/stealth-score/bars-pct-contribution removed; risk-score case renders ban-threshold bar and filters to active components; `buildScoreHtml` returns header + body; block-count reason cards show share of total |

### `test_v187_controls_order.py` — Activation-order risk-score gate
**Version added:** v1.8.7

| Class | Tests | Description |
|-------|-------|-------------|
| `TestProxyHandlerDeadCode` | 4 | `_escalate`/`_second_order` removed from protect(); `_esc_score` still present; `_should_run_signal` imported |
| `TestSignalOrderDefaults` | 31 | Every signal in `SIGNAL_ORDER_DEFAULTS` maps to correct order (1/2/3) matching `config.py` sets — AI-UA signals order 1; SECOND_ORDER_REASONS order 2; ESCALATE_ONLY_REASONS order 3 |
| `TestBackendConfigConsistency` | 12 | `ESCALATE_ONLY_REASONS` contains body-attack signals; `SECOND_ORDER_REASONS` contains ai-enumeration/direct-api-probe/locale-geo; UA-AI signals not in either gated set |
| `TestControlsOrderUICopy` | 9 | Panel header "risk-score gate"; order-2 copy mentions `SECOND_ORDER_THRESHOLD`; order-3 copy mentions `ESCALATION_THRESHOLD`; badge tooltips describe gate condition for each order |

### `test_v187_db_switch_hotswap.py` — In-process DB backend hot-swap
**Version added:** v1.8.7

| Class | Tests | Description |
|-------|-------|-------------|
| `TestPropagateGlobal` | 3 | `_propagate_global` sets local globals; propagates to other sys.modules; skips modules without the attribute |
| `TestEndpointSourceGuards` | 5 | No `os._exit` in endpoint; no `_delayed_exit`; calls `_propagate_global`; calls `pg_pool_reset` |
| `TestPgPoolReset` | 3 | Clears pool to None; safe when already None; fresh pool created on next `_get_pool()` |
| `TestEventRoutingAfterHotSwap` | 2 | Postgres backend calls `pg_insert_event`; SQLite backend skips it |
| `TestMultiRoundTripPropagation` | 2 | 5× alternating backend switches propagate across proxy_handler, core.metrics, db.postgres; final state consistent |
| `TestConfigKvPersistence` | 2 | `DB_BACKEND` queued to config_kv on switch; `POSTGRES_DSN` queued only when DSN actually changed |
| `TestResponseMessage` | 2 | Response message says "active immediately"; no "restart" language |
| `TestSourceOrdering` | 2 | Migration called after propagation; postgres probe present in source |
| `TestControlsHtmlUI` | 5 | No `setTimeout(location.reload)`; no `location.reload()`; button label "Yes, switch"; no "Restart required" in modal; no `restart:true` on DB knob |
| `TestExports` | 2 | `pg_pool_reset` and `_propagate_global` exported/callable |

### `test_v187_db_switch_roundtrip.py` — DB switch endpoint validation + migration
**Version added:** v1.8.7

| Class | Tests | Description |
|-------|-------|-------------|
| `TestPgTestRoundtrip` | 3 | Returns `ok=False` when psycopg unavailable; when no DSN; on connect error |
| `TestDbSwitchEndpointValidation` | 5 | Invalid target → 400; postgres without psycopg → 400; postgres without DSN → 400; failed roundtrip → 400; viewer role denied |
| `TestHotSwapBehavior` | 4 | No `os._exit`; uses `_propagate_global`; returns directly (no `_delayed_exit`); `_propagate_global` called in source |
| `TestMigrationBehavior` | 3 | Migration runs on switch; migrate called; `decimal.Decimal` cast to float for SQLite binding |
| `TestConfigKvPersistence` | 3 | `set_config` called for `DB_BACKEND`; `POSTGRES_DSN` queued when DSN provided; config_kv queue checked |

### `test_v187_db_endpoints_dynamic.py` — DB migration-status and switch endpoint contract
**Version added:** v1.8.7

| Class | Tests | Description |
|-------|-------|-------------|
| `TestDbMigrationStatusEndpoint` | 7 | Unauthenticated → 404 decoy; authenticated → 200 JSON; never-run state; `Cache-Control: no-store`; pct/eta/rate zero when idle; running state has progress fields; done state fields present |
| `TestDbSwitchEndpoint` | 7 | Unauthenticated → 404 decoy; invalid target → 400; switch-to-sqlite has `full_migrate` key; `full_migrate=false` not scheduled; double-start prevented when migration running; viewer role denied; POST without `Content-Type` parsed |
| `TestDbRouteRegistration` | 2 | `db-migration-status` route registered; `db-switch` route registered as POST |
| `TestBgMigrationShape` | 1 | Background migration has required response keys |
| `TestFullMigrateBackground` | 1 | `_full_migrate_background` sets done flag on completion |
| `TestBgMigrationCutoff` | 2 | SQLite→Postgres cutoff direction; Postgres→SQLite cutoff logic |

### `test_v188_db_settings_merge.py` — DB backend section merge from Controls → Settings
**Version added:** v1.8.7 (feature drafted for v1.8.8 label; shipped in v1.8.7 image)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestDbActiveBadges` | 5 | `#db-badge-sqlite` and `#db-badge-pg` present; both hidden by default (`display:none`); both contain `active` label text |
| `TestDbMigStatusRow` | 2 | `#db-mig-status-row` present; inside `#card-db` |
| `TestDbJsFunctions` | 7 | `_renderMigStatusRow`, `_pollMigOnce`, `_startMigPoll`, `_openDbModal`, `_dbUpdateActiveBadges` all defined; `_dbSvcCache` and `_migPollTimer` declared |
| `TestDbLoadDbEnhanced` | 5 | `loadDb()` reads services from metrics endpoint; populates `_dbSvcCache`; calls `_dbUpdateActiveBadges`; polls migration on load; starts poll if running |
| `TestDbHoverTooltipLiveStats` | 6 | `_dbShowTip()` reads `_dbSvcCache`; shows `size_bytes` (SQLite); shows `events_rows` (Postgres); shows `available` status; old `#db-info-popover` removed; click wiring (`onclick`/`_dbSideClick`) present |
| `TestDbModal` | 12 | No `confirm()` in apply handler; `_openDbModal()` called; `impactLines` array present; `fullMigrate=true` always set; `full_migrate` flag sent; DSN override input; connection test button; Yes button disabled until test passes (`needsTest`); uses `showSimpleModal`; updates badges on success; checks `full_migrate_scheduled`; Cancel button present |
| `TestDbUpdateActiveBadges` | 2 | References both badge elements; uses `display:none` for inactive badge |
| `TestDbMigRenderRow` | 4 | Clears element when no migration; renders CSS width progress bar; displays `pct`; colour-codes error/running/done states |
| `TestDbPollHelpers` | 4 | `_pollMigOnce` fetches `db-migration-status`; `_startMigPoll` uses `setInterval`; `_startMigPoll` clears interval when not running; guard against double-start via `_migPollTimer` |
| `TestDbSettingsNoBrowserConfirm` | 1 | No `confirm()` in the DB Backend JS section |

### `test_v188_redis_security.py` — Redis allowlist, HMAC ban-signing, and settings card
**Version added:** v1.8.7 (feature drafted for v1.8.8 label; shipped in v1.8.7 image)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestIpNetListParser` | 10 | Comma/newline separated CIDRs; bare IP → /32; list input; invalid entry dropped; all-invalid → empty; host-bits normalised; empty string → empty; IPv6 CIDR; returns list of strings |
| `TestRedisAllowListKnob` | 7 | `REDIS_ALLOW_LIST` in hot-reload knobs; uses `_ip_net_list_parser`; drops invalid; no validator; default is empty list; attribute exists; parses newline input |
| `TestRedisBanHmac` | 9 | Sign adds pipe suffix; verify roundtrip; tampered value rejected; expired value rejected; wrong key rejected; different IPs produce different HMACs; signature is 64 hex chars; verify requires correct format; partial payload rejected |
| `TestJa4DenylistZadd` | 7 | `ZADD` used for JA4 denylist; score is epoch timestamp; key prefix correct; stored in Redis; expired entries not present; allows fingerprint lookup; TTL enforcement |
| `TestRedisAllowlistEnforce` | 9 | Allowed IP passes; disallowed IP blocked; empty list → all pass; CIDR range enforced; IPv6 enforcement; allowlist read from config; check on every request; bypass allowed CIDR; log event on block |
| `TestControlsRedisGuard` | 2 | Controls page has Redis section; `REDIS_ALLOW_LIST` referenced |
| `TestSettingsRedisCard` | 17 | Card element present; status pill/dot/text; URL display; `loadRedis` function defined; reads config endpoint; checks `connected` field; reads `REDIS_ALLOW_LIST` from state; apply posts `REDIS_ALLOW_LIST`; posts to `/secured/config`; `rediss://` TLS check; URL sanitiser; allowlist status element |

### `test_v188_ed25519_mesh.py` — Ed25519 gateway mesh signing + REDIS_REQUIRE_TLS
**Version added:** v1.8.8

| Class | Tests | Description |
|-------|-------|-------------|
| `TestRedisRequireTls` | 10 | `REDIS_REQUIRE_TLS` defaults True; env-var overrides (false/0/no/true/1); SystemExit(2) present in source when plaintext + TLS required; warn log path when TLS not required; secondary TLS check in `_shared_init` before allowlist check; secondary check logs `redis_blocked_no_tls` |
| `TestEd25519KeypairGeneration` | 10 | `_gw_generate_keypair` returns two 43-char base64url strings; random per call; `_gw_derive_pubkey` roundtrips; returns empty string on invalid input; private/public keys decode to exactly 32 bytes; `_gw_fingerprint` returns 12 hex chars |
| `TestCanonicalOfferBytes` | 8 | Returns bytes; excludes `_sig` field; output is stable sorted-key JSON; key-order independent; empty dict; single-key roundtrip; `_sig`-only → `b'{}'`; non-`_sig` keys survive |
| `TestGwSignOffers` | 7 | Returns non-empty string for valid keypair; valid base64url; signature is exactly 64 bytes (86 base64url chars); empty/garbage key → empty string; deterministic; different offers → different signatures |
| `TestGwVerifyOffers` | 10 | Valid sig + correct key → True; tampered value/wrong key/truncated sig/empty sig/invalid key → False; extra/removed field after signing → False (canonical payload); `_sig` excluded from payload; returns bool without raising |
| `TestMeshSyncLoopSource` | 10 | Loop fetches `private_key` from DB; calls `_gw_sign_offers`; adds `_sig` to publish dict; `trust_map` selects `public_key` column; trust_map is (auto_ok, public_key) tuple; inbound: pops `_sig`; rejects on absent sig (`mesh_sync_no_sig`); rejects on invalid sig; rejects on no pubkey; calls `_gw_verify_offers` |


### `test_v188_settings_subnav.py` — Settings page section nav (split-pane layout)
**Version added:** v1.8.8

| Class | Tests | Description |
|-------|-------|-------------|
| `TestSettingsSubnavHTML` | 23 | `#settings-split` wrapper, `#settings-nav`, `#settings-panels`, `#settings-id-strip` always-visible; id-strip before split; `card-export`/`card-import` IDs; all 15 `data-card-sec` targets exist |
| `TestSettingsSubnavCSS` | 5 | `#settings-split` flex layout; `#settings-nav` has fixed width; `#settings-panels` flex-grow; nav links have `data-sec` attr; `#settings-id-strip` CSS |
| `TestSettingsSubnavJS` | 25 | `SECTIONS` constant; `showSection` function; nav click handler; active-link class; hash routing; section mapping complete; `card-*` assignments; no duplicate card mappings; every section has ≥1 card |
| `TestSettingsSubnavRegression` | 12 | Existing cards intact (9 parametrized: vhosts/users/gw-registry/db/infrastructure/redis/sso/2fa/mesh); identity strip elements intact; no `#main-wrapper`; no page-content padding |
| Standalone | 6 | `test_d01`–`test_d06`: settings returns 200; has split; has nav; has panels; has card-sec; exposes switch |

---

### `test_performance.py` — Performance regression gates

**Version added:** v1.8.8

| Test | Description |
|------|-------------|
| `test_perf_p1_browser_fingerprint_throughput` | SHA256 fingerprint: ≥ 20 000 calls/s floor (5 000 iterations) |
| `test_perf_p2_header_order_sig_throughput` | Header-order SHA256: ≥ 20 000 calls/s floor (5 000 iterations) |
| `test_perf_p3_socket_ip_bucket_sequential` | `take_socket_ip_token` sequential: ≥ 2 000 ops/s (1 000 calls, single IP, lock-hold timing) |
| `test_perf_p4_identity_bucket_sequential` | `take_token` sequential: ≥ 2 000 ops/s (1 000 calls, single identity) |
| `test_perf_p5_socket_ip_bucket_concurrent` | `take_socket_ip_token` concurrent: 20 workers × 50 calls must finish in < 5 s (lock-contention check) |
| `test_perf_p6_live_endpoint_sequential_latency` | `/live` sequential: 50 requests < 15 s total; p95 < 500 ms (proxy overhead baseline, no upstream I/O) |
| `test_perf_p7_live_endpoint_concurrent` | `/live` concurrent: 20 simultaneous requests all return 200 in < 10 s (deadlock/starvation check) |
| `test_perf_p8_full_pipeline_distinct_ips` | Full pipeline with 30 distinct X-Forwarded-For IPs: < 20 s (rate-limit + identity + scoring per new IP) |
| `test_perf_p9_ip_state_insert_oi` | `ip_state` insert stays O(1): per-op time at n=5 000 must not exceed 3× per-op time at n=100 |

---

## Cross-version Tests

### `test_admin_ip_list.py` — Admin IP allowlist CRUD
**Version added:** Added to fill coverage gaps (multiple versions)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestAdminIPAuthUnit` | 11 | `_is_admin_ip()` with empty/match/no-match/invalid/empty-string/IPv6; `_rebuild_admin_nets()` parses/skips/clears/updates; object reference preserved |
| `TestAdminIPAddRemove` | 19 | Add success/duplicate/invalid/empty/note/overlong-note/single-host/IPv6; remove success/not-present/invalid/leaves-others; update description success/not-present/invalid/truncates |
| `TestAdminIPsEndpointGaps` | 14 | Full HTTP endpoint coverage: GET cache-control, unauthenticated; POST duplicate/empty; PATCH description/nonexistent/invalid; DELETE nonexistent/invalid/removes/response/no-param |
| `TestAdminIPEnforcement` | 6 | Blocked IP gets decoy (not real JSON, not 403); allowed IP retains access; empty list = open mode; login visible to allowed IP |

### `test_code_review_fixes.py` — Code review security fixes
**Version added:** Post-review fixes (multiple releases)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestC1RedisBanMonotonic` | 3 | Redis ban epoch → monotonic conversion; expired epoch not stored; Redis unavailable falls through |
| `TestC2AuthorizedBotBanMonotonic` | 3 | `AUTHORIZED_BOT_UAS` ban/really-ban uses `now()` not `time.time()` |
| `TestS1LoginGetRedirectValidation` | 4 | External URL rejected; protocol-relative rejected; valid internal `?next=` accepted; unauthenticated login page rendered |
| `TestS2Ipv4MappedIpv6SsrfGuard` | 7 | `::ffff:127.0.0.1`, `::ffff:10.0.0.1`, `::ffff:192.168.1.1`, `::ffff:172.16.0.1` all blocked; public IPv6 allowed; plain private still rejected |
| `TestR1TaskDoneOnCommitFailure` | 2 | `task_done()` called even when `commit()` raises |
| `TestV1CookieGhostDoubleIncrement` | 4 | `cookie_ghost_misses` increments by at most 1 per request; `elif` prevents double-increment |
| `TestV2CustomAllowRuleCallsRecord` | 3 | Custom `action=allow` rule calls `record()` so traffic is visible in dashboard |
| `TestV4VhostStatsAllowedCount` | 3 | `allowed_1h` counts events with `reason=''`; named allowed reasons also counted |
| `TestD1RecordMethodField` | 5 | `record()` accepts and stores HTTP method; default is `''`; end-to-end method stored in DB |
| `TestRegressions` | 5 | Cross-fix regression checks: ban uses monotonic; `vhost_stats` has `last_seen_ts`; C1+C2 coexist; SSRF guard intact; allow-rule traffic in `vhost-stats` |

### `test_control_center.py` — Control Center dashboard
**Version added:** Multiple (S01–S44 static, D01–D13 dynamic)

44 static tests (S01–S44) covering Chart.js local asset, 3 chart canvas IDs, empty states, RPS grid, vhost-stats thead, `hexRgba` helper, `loadTrafficChart` in DOMContentLoaded, 60s interval, destroy-before-new, CSS hidden canvases, signal/geo/risk-score/JS-chal-funnel/top-paths charts, threat tiles, and block-reason/block-timeline endpoints.

### `test_crowdsec_lapi_health.py` — CrowdSec LAPI health probe
**Version added:** Added alongside CrowdSec integration (exact version unclear)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestS_Static` | 13 | `_crowdsec_lapi_health` defined; cache dict and TTL; uses `/v1/heartbeat`; returns `reachable`/`version`/`ping_ms` keys; timeout ≥ 2s; handler imports health fn; external endpoint includes `lapi_health`; 404 fallback; not configured → `reachable=None` |
| Dynamic (`test_d01–d07`) | 7 | Full dynamic tests against running proxy (auth guard, shape verification) |

### `test_dashboard_charts.py` — Dashboard chart QA
**Version added:** Multiple versions

25 static tests covering: `fill:'origin'` minimum count across dashboards, no gradient backgrounds, no scriptable background functions, solid rgba alpha, agents popover max-height before rect, agents popover `overflow-y:auto`, agents gwmgmt pill active by default, main modal `max-height`, vhost chart orphan guard, category/time axis, `_vhRawData` stored, `onClick` handler, bucket detail panel, `_showVhostBucketDetail()`, toggle on same bucket, share column; service vhost share card, `loadVhostShare()` fetch/escapeHtml/win-toggle/percentage/interval; agents IP intel risk breakdown section, `.rsn` class, `escapeHtml` on reason, embedded in return.

### `test_dashboard_data.py` — Dashboard data API endpoints
**Version added:** Multiple versions

24 functional tests covering auth guards and response shapes for: metrics, cost-timeline, agents-data, agents-timeline (including `gwmgmt` key in buckets and totals), service-data, logs-data, health-score, detector-stats, geo-data, path-hits (including DB index check and response time under 500ms), whoami, cache-control headers.

### `test_upstream_no_leak.py` — Upstream address leak prevention
**Version added:** M-SEC-1 security fix

| Class | Tests | Description |
|-------|-------|-------------|
| `TestS_Static` | 10 | M-SEC-1 block present in source; scrub outside `UPSTREAM_REWRITE_BASE` branch; `_up_netloc` used; `via`/`server` in `_DROP_IF_LEAKS`; `text/` and `application/json` in text content-type check; `_REWRITE_HEADERS`/`_DROP_IF_LEAKS` defined; double-slash normalisation guard |
| `TestD_Dynamic` | 18 | HTML/JSON/XML/plain-text/JS body scrubbed; binary body unmodified; Location/Content-Location/Link/Via/X-Backend/unknown headers scrubbed; no header leaks; scrub works without `UPSTREAM_REWRITE_BASE`; body replaced with gateway host; double-slash normalised; protocol-relative URLs not collapsed |

### `test_upstream_rewrite.py` — UPSTREAM_REWRITE_BASE feature
**Version added:** Feature addition (exact version unclear)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestStaticConfigSchema` | 7 | Knob in `_HOT_RELOAD_KNOBS`; type is str; validator accepts URL/empty/rejects overlong/non-URL; default is empty string |
| `TestStaticRewriteLogic` | 16 | HTML/JSON/XML/plain-text rewrite; multiple occurrences; no match unchanged; empty body; different port not stripped; trailing slash; Location/Content-Location/Link headers; strip to empty suppressed; empty base is noop; CSP violation resolved |
| `TestDynamicRewriteDisabled` | 2 | Internal URL leaks in body; Location already rewritten to gateway |
| `TestDynamicRewriteEnabled` | 14 | HTML/JSON/XML/plain-text body stripped; Location on 3xx; Content-Location/Link headers; clean response unaffected; CSP violation resolved; trailing slash; status codes preserved; X-Proxy still injected; different port not stripped |

### `test_custom_rules_fuzzing.py` — Custom rules adversarial fuzzing
**Version added:** v1.8.7+ (P0.3 improvement)

| Class | Tests | Description |
|-------|-------|-------------|
| `TestFuzz01PathWildcard` | 4 | Exact match, wildcard `*`, no-match, root `/` |
| `TestFuzz02MethodCondition` | 3 | Method match (POST), method no-match (GET), method case-insensitive |
| `TestFuzz03UaCondition` | 3 | UA prefix match, UA no-match, empty UA |
| `TestFuzz04HeaderCondition` | 3 | Custom header match, header no-match, header substring |
| `TestFuzz05CidrCondition` | 4 | Single CIDR match, CIDR no-match, 1000-entry CIDR list with match, invalid IP falls through |
| `TestFuzz06MultipleConditions` | 3 | AND logic (path+method), partial match fails (only one condition), all-condition rule |
| `TestFuzz07MultipleRules` | 3 | First rule wins (allow before block), second rule fires when first misses, block then allow |
| `TestFuzz08AdversarialInputs` | 5 | Path traversal, null bytes, very long path (10k), Unicode path, SQLi string in path |
| `TestFuzz09EdgeCases` | 5 | Empty rules list, no conditions, action=allow on everything, `_to_custom_rules` with empty list, missing `then` key |
| `TestFuzz10ConcurrentRuleSwap` | 3 | Thread-safe swap while evaluating, 100 concurrent evals, rule change propagates |
| `TestFuzz11CountryCondition` | 3 | Country condition with MaxMind disabled (ep version); country no-match; SQLi string as country value |
| `TestFuzz12QueryCondition` | 3 | Query key present matches (ep version); missing key no-match; missing `value` sub-key no-match |

### `test_component.py` — Full-pipeline component tests
**Version added:** v1.8.7+ (P1.4 improvement)

Spins the complete gateway (on_startup → middleware → handler → on_cleanup) with all external collaborators stubbed (MaxMind, AbuseIPDB, CrowdSec, Redis disabled; in-process echo upstream). Catches wiring bugs between modules that unit tests miss.

| Class | Tests | Description |
|-------|-------|-------------|
| `TestComp01BootAndProxy` | 3 | `/live` → 200 ok after startup; clean browser request proxied without 5xx; security headers injected on `text/html` responses (not JSON) |
| `TestComp02RateLimiting` | 1 | 80 requests with bot UA → at least one 429 (rate-limited) or 404 (banned-silent) |
| `TestComp03SuspiciousPath` | 2 | Scanner paths (`/wp-login.php`, `/.env`, `/xmlrpc.php`, `/.git/config`, `/phpmyadmin/`) handled without 500; 5 × repeated scanner paths don't crash |
| `TestComp04AdminAuth` | 2 | Admin endpoints without session → decoy (no real dashboard content); login page reachable (200 or 302) |
| `TestComp05CustomRulesWiring` | 2 | `allow` custom rule bypasses detection; `block` custom rule fires before upstream (decoy, no 500) |
| `TestComp06Lifecycle` | 3 | Startup + shutdown completes cleanly; `db_queue` non-None after startup; `UPSTREAM` propagates to `core.proxy_handler` |
| `TestComp07UaClassification` | 1 | curl, python-requests, Go-http-client, empty, truncated, Log4Shell, SQLi UAs → no 500 |
| `TestComp08DetectorInterface` | 6 | `REGISTRY` non-empty after import; all entries satisfy `Detector` protocol; `LlmHeuristicDetector.NAME`/`ENABLED` types; `observe()` no-raise; `check()` returns float; `register()` appends to `REGISTRY` |

### `test_pentest_probes.py` — Automated pentest probes
**Version added:** v1.8.7+ (P1.5 improvement — automates manual step 12)

Replaces the manual §12 pentest checklist from BUILD_VALIDATION.md with automated assertions. Tests both static source analysis and live proxy behaviour.

| Class | Tests | Description |
|-------|-------|-------------|
| `TestProxy4_01_Ssrf` | 5 | `_upstream_safe_to_reload` rejects `127.0.0.1`, `localhost`, `10.x`, `192.168.x`, `0.0.0.0`; accepts public URL |
| `TestProxy4_02_HostHeader` | 3 | Host header forwarded to upstream; `X-Forwarded-For` injected; internal upstream hostname not leaked in response |
| `TestProxy4_03_PropagateNever` | 3 | `_PROPAGATE_NEVER` defined; blocks `SECRET_KEY`; blocks `DB_PATH` |
| `TestSec01XssInPath` | 3 | XSS path → no 500; security headers on HTML response; suspicious-path signal in source |
| `TestSec02PathTraversal` | 2 | `/../etc/passwd` → no 500; no path traversal in upstream request |
| `TestSec04SqliQuery` | 2 | SQLi in query string → no 500; DB error not in response body |
| `TestSec06BotUaDetection` | 3 | Scanner UA `python-requests` → no 500; cumulative bot UA requests → restricted (429 or 404); `KNOWN_BOT_UAS` non-empty |
| `TestSec08VersionDisclosure` | 3 | `1.8.7` version string not in 404 body; `Traceback` not in 404 body; `File "` not in 404 body |

**P3.2 additions to `TestProxy4_03_PropagateNever`:** 2 new methods — `test_all_dangerous_builtins_covered` enumerates exec/eval/compile/open/breakpoint/__import__/__builtins__ and asserts all are in `_PROPAGATE_NEVER`; `test_no_dead_entries_in_propagate_never` verifies every entry is a real builtin or proxy attribute (typo guard).

---

### `test_v188_backend_aware_reads.py` — Backend-aware event reader + write-health observability

**Version added:** v1.8.8

| Class | Tests | Description |
|-------|-------|-------------|
| `TestReadEventsSql` (Q01–Q19) | 19 | Functional tests against ephemeral SQLite: empty range, row return, column filter, default columns, ts normalisation, start/end_ts=0 bounds, vhost/path_like/reason_like/ip_exact filters, ASC/DESC ordering, limit/offset pagination, invalid column rejection, whitelist enforcement, empty-filter safety |
| `TestEventsHealthSql` (H01–H04) | 4 | `_events_health_sql` shape, `last_event_ts` = MAX(ts), `events_rows` = COUNT(*), ok=False when DB missing |
| `TestDbHealthSnapshot` (H05–H07) | 3 | `db_health_snapshot` top-level keys, `active_backend` reflects `DB_BACKEND`, `lag_seconds` None when single backend |
| `TestXffMisconfigAlert` | 6 | XFF misconfiguration alert structure, source, bounds |
| `TestConfigKvStompAlert` | 3 | config-kv stomp alert source exists, fires for each collision |
| Standalone | 27 | Dashboard endpoint static checks for geo-data, logs-data, agents-bucket-detail, metrics, health-score: `db_read_events` calls, column lists, backend-aware dispatch, health endpoint wiring |

---

### `test_v188_session_fixes.py` — 1.8.8 bug-fix regressions (Redis TLS, DB pin, DSN propagation, geo, settings)

**Version added:** v1.8.8

| Class | Tests | Description |
|-------|-------|-------------|
| `TestRedisTlsGracefulDegradation` (F01–F04) | 4 | `_REDIS_TLS_BLOCKED` flag presence, set on TLS error, gateway continues without Redis, flag cleared on reconnect |
| `TestDbBackendEnvPin` (D01–D05) | 5 | `DB_BACKEND` env-pin only for meaningful values; empty/None ignored; postgres/sqlite accepted |
| `TestPostgresDsnPropagation` (P01–P05) | 5 | `POSTGRES_DSN` always included in `_refresh_integration_state` propagation dict; non-empty value propagated; empty-string propagated without KeyError |
| `TestGeoDataFallback` (G01–G04) | 4 | `geo_data_endpoint` returns `{configured:false}` when `MAXMIND_CITY_ENABLED` is False |
| `TestSettingsLoadDsnButton` (S01–S04) | 4 | `btn-db-load-dsn` present in settings.html; click handler wired; DSN field populated; user-touched flag set |
| `TestPgStatusTileLiveUpdate` (T01–T03) | 3 | PG status tile `_tip-pg-status-val` updated after successful test; test-success handler updates span; cache updated |
| Standalone | 3 | Additional DSN hint and masking checks |

---

### `test_v188_startup_fixes.py` — Container-startup and test-button UX fixes

**Version added:** v1.8.8

| Class | Tests | Description |
|-------|-------|-------------|
| `TestDockerComposeTmpfs` (C01–C03) | 3 | `docker-compose.yml` has tmpfs entry; size ≥ 64 MiB (root cause: 16 MiB too small for SQLite startup temp-files in read-only container) |
| `TestPgTestPasswordRequired` (P01–P03) | 3 | `_tip-pg-test`: password only required when no stored creds (`credsOk2` path); no-param URL when password empty + creds saved |
| `TestPgTestNoParamUrl` (U01–U03) | 3 | no-param URL path when password empty + creds saved |
| `TestPgTestResponseShapes` (R01–R04) | 4 | Both `/db-test` response shapes handled: `j.probe` and `j.postgres` variants |
| `TestPgTestHttpErrorHandling` (H01–H04) | 4 | Soft HTTP-error branches: 404/403 → warning hint (not crash); network error catch present |

---

---

### `test_live_gw.py` — Black-box live gateway pentest suite

**Version added:** v1.8.9

| Class | Tests | Description |
|-------|-------|-------------|
| `TestALiveness` | — | Gateway liveness + UPSTREAM environment sanity |
| `TestBBotUADetection` | — | Bot UA signals score correctly |
| `TestCAdminLockdown` | — | Admin paths reject unauthed requests with silent decoy |
| `TestDSuspiciousPath` | — | Path traversal + injection payloads trigger detection |
| `TestEHeaderInjection` | — | Header SSTI + Host injection signals fire |
| `TestFFuzzingResilience` | — | Malformed requests do not cause 500 or crash |
| `TestGRateLimit` | — | Rate limiting fires on burst traffic |
| `TestHAdminAPI` | — | Admin API endpoints respond correctly for authed requests |
| `TestISessionBehaviour` | — | Session cookie lifecycle and churn detection |
| `TestJSecurityHeaders` | — | Security headers injected on HTML responses |
| `TestKChallengePage` | — | JS challenge page renders correctly |
| `TestLBodyInjection` | — | POST body injection payloads trigger WAF |
| `TestMNoInfoDisclosure` | — | Error responses do not leak version or stack traces |
| `TestNAdminPathConfusion` | — | Admin path confusion / partial-match attacks rejected |
| `TestOSessionLifecycle` | — | Session creation, touch, and expiry flow |
| `TestPConfigWriteResilience` | — | Config write endpoints resilient to invalid input |
| `TestQReflectedContent` | — | Reflected content XSS prevention in dashboard |
| `TestRMethodOverride` | — | HTTP verb override detection |
| `TestSCachePoisoning` | — | Cache poisoning via Host/X-Forwarded-Host rejected |
| `TestTAdminEnumeration` | — | Admin endpoint enumeration returns uniform 404 decoy |

*Requires `LIVE_GW_URL` + `LIVE_GW_ADMIN_KEY` env vars; skipped in CI without live gateway.*

---

### `test_v189_knob_kill_switches.py` — 1.8.9 kill-switch knob registry and gate tests

**Version added:** v1.8.9

| Class | Tests | Description |
|-------|-------|-------------|
| `TestRegistryCompleteness` | 5 | All 1.8.9 knobs in `_HOT_RELOAD_KNOBS`, default True, no None signals, every risk-weight signal has a knob, knob names in config namespace |
| `TestGateLogic` | 9 | WAF body/smuggling/verb-override/header/graphql/upload, session-churn, rate-limit, host-blocking gates in correct source file |
| `TestHotReloadRoundTrip` | 6 | Knob persistence: toggling to False persists, toggling back to True restores; all new knobs in hot-reload registry |
| `TestSignalKnobMapping` | 29 | Each signal maps to the expected kill-switch knob (parametrized) |
| `TestKnobDynamic` | 12 | Runtime hot-reload: disable each detector class, confirm signals suppressed; re-enable, confirm restored |

---

---

### `test_v189_sidebar_collapse.py` — Sidebar full-hide + submenu accordion (9 dashboards)

**Version added:** v1.8.10

| Class / group | Tests | Description |
|-------|-------|-------------|
| (parametrized, 9 dashboards) | 55 | Full-hide toggle + reopen wiring, desktop-gated CSS, `agw_sb_collapsed` restore, submenu accordion carets on the 3 parent groups, GeoMap has no caret, no icon-rail leftovers, restore-before-`#sidebar` ordering, brand version 1.8.10 |

---

### `test_v189_ctrlnav_rail.py` — Controls-page section icon-rail "second hide"

**Version added:** v1.8.10

| Class / group | Tests | Description |
|-------|-------|-------------|
| (module-level) | 6 | `#ctrl-nav` toggle wired to `_ctrlNavToggle`, `agw_ctrlnav_rail` persistence, rail keeps `.cni-icon` / hides `.cni-label` + search, item tooltips, main sidebar hide untouched (no `sb-rail` leak) |

---

### `test_v189_setnav_rail.py` — Settings-page section icon-rail "second hide"

**Version added:** v1.8.10

| Class / group | Tests | Description |
|-------|-------|-------------|
| (module-level) | 6 | `#settings-nav` toggle built in JS + wired, `agw_setnav_rail` persistence, rail keeps `.sni-icon` / hides `.sni-label`, restore-before-`_buildNav` (no flash), main sidebar hide untouched |

---

### `test_v1810_2fa_status_robust.py` — 2FA card + Health pill session-expiry robustness

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| (module-level) | 10 | `isAuthFail()` helper covers 401/403/404; `load2fa()` guards `.ok` before `.json()`; Health pill exposes `authErrorHook` + detects 404 auth failure; pill modal explains session expiry |

---

### `test_v1810_admin_key_strength.py` — Admin key strength (Gate 0b)

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| (module-level) | 4 | No weak/guessable admin key committed to env/compose/deploy; no committed key < 16 chars; compose uses env-passthrough (`${ADMIN_KEY}`) not a literal; the ≥16-char-random rule is documented in rules.md Gate 0b + MANUAL §0 |

---

### `test_v1810_admin_probe_classification.py` — Admin-path reason split (`admin-probe` / `operator-self`)

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestClassification` | 8 | Legacy `internal-probe` not emitted; unauthenticated → `admin-probe`, authenticated → `operator-self`; IP-blocked still distinct |
| `TestBlockedConsistency` | 2 | Metrics passthrough emits `operator-self` |

---

### `test_v1810_csrf_autorefresh.py` — CSRF token auto-refresh + retry-on-403

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestCsrfEndpoint` | 5 | `GET /secured/csrf` returns `{token}` from the live session HMAC; not `@_require_csrf`; 401 without session; route registered |
| `TestRetryShim` | 5 | every dashboard's fetch shim refreshes the token + retries once on 403; updates `window.__AGW_CSRF__`; no legacy non-retry shim left |

---

### `test_v1810_csrf_cookie.py` — CSRF cookie issuance and self-heal

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| (module-level) | 5 | OIDC/SSO login sets `agw_csrf`; password login sets `agw_csrf`; `protect()` re-issues stale/missing CSRF cookie; `record()` still called in authed branch; CSRF token round-trip |

---

### `test_v1810_csrf_session_regression.py` — Session key persistence across container restarts

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestSessionKeyPersistence` | 5 | Dockerfile and armv7 Dockerfile symlink `.session_key` → `/data`; docker-compose mounts named `data` volume and sets `APPSECGW_KEY_DIR=/data` |
| `TestCsrfTokenValidation` | 9 | HMAC structure; wrong key rejected; CSRF token format |
| `TestSsoOidcPath` | 8 | OIDC callback sets both session + CSRF cookies; shim coverage |
| `TestProtectMiddleware` | 12 | Protect middleware re-issues CSRF; CSRF check on POST |
| other | 12 | Edge cases |

---

### `test_v1810_csrf_shim_coverage.py` — Global `fetch` CSRF shim on all dashboards

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestShimPresence` | 12 | Shim present on vhost_policy, main, controls, geo, logs, agents, siem, service, settings dashboards |
| `TestShimBehaviour` | 8 | Shim intercepts POST/PATCH/DELETE; injects `X-CSRF-Token`; GET not intercepted |

---

### `test_v1810_infra_restart_knobs.py` — Infrastructure restart-required knob UX

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestInfraRestartKnobs` | 14 | `ALLOW_PRIVATE_UPSTREAM` and `STRICT_VHOST` in `INFRA_KNOBS`; no `data-ikey`; `render_infra` uses pointer cursor not `not-allowed` for restart knobs |

---

### `test_v1810_reason_descriptions.py` — Admin-namespace reason descriptions

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| (module-level) | 6 | Admin reasons (`admin-probe`, `operator-self`, `live-not-loopback`, `chal-required`) have descriptions, labels, and `admin` category with colour + action; legacy `internal-probe` split explained |

---

### `test_v1810_riskbreakdown_control_column.py` — Risk-score-breakdown "control" column

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestServerContract` | 6 | `SIGNAL_KNOB` maps reasons to knobs; scoring endpoint emits `toggle` per signal; synthetic reasons mapped; full `SIGNAL_KNOB` exposed |
| `TestRiskBreakdownColumn` | 5 | Frontend loads knob map from scoring endpoint; column rendered per row |

---

### `test_v1810_riskbreakdown_enrichment.py` — Risk-breakdown control column enrichments

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestServerEnrichment` | 5 | `admin-ip-blocked`→`ADMIN_ALLOWED_IPS`; scoring returns `knob_state` (on/kind/display), `knob_page`, `signal_meta` (weight/tier/desc) covering synthetic reasons |
| `TestUiEnrichment` | 7 | on/off dot + value badge, page-aware clickable deep-link, severity tier + description tooltip, refresh-on-modal-open |
| `TestControlsDeepLink` | 5 | controls.html `#knob=NAME` deep-link (switch section, scroll, flash); graceful toast when not on page |
| `TestRound2Improvements` | 6 | synthetic-reason descriptions, settings deep-link, non-bool value display |

---

### `test_v1810_riskmodal_actions.py` — In-modal ban actions + Top-controls panel

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestBanHeaderUnban` | 5 | ban-vs-score header, self-ban (admin IP) banner, Unban button + `wireRiskActions` wiring + confirm |
| `TestInlineQuickDisable` | 4 | bool control dot is a quick-toggle → `POST /config {knob:!on}` (bool-only) |
| `TestTopControlsPanel` | 4 | live-feed panel aggregates `by_reason`→control, ranked, page-aware links |

---

### `test_v1810_score_controls.py` — Score-breakdown "Controls governing this score"

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| (module-level) | 5 | JS `SIGNAL_KNOB` matches backend; `buildScoreHtml` helpers present; controls area uses live ON/OFF state; score popover refreshes control state |

---

### `test_v1810_topbar_overlap.py` — Topbar overlap fix (static)

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| (module-level) | 6 | Fixed-widget pages reserve right space; reserve is desktop-scoped; inflow pages keep widgets in topbar; collapsed topbar reserves left space |

---

### `test_v1810_topbar_overlap_dynamic.py` — Topbar overlap fix (headless Chromium)

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| (parametrized, 5 dashboards) | 15 | `getBoundingClientRect` verifies fixed Health pill + log selector do not overlap topbar buttons/title at 1400px viewport |

---

### `test_v1810_trusted_proxies_hotreload.py` — `TRUSTED_PROXIES` / `TRUST_XFF` hot-reload

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestRegistry` | 5 | `TRUSTED_PROXIES` + `TRUST_XFF` in `_HOT_RELOAD_KNOBS`; exported from config; `TRUSTED_PROXIES` is list; `ALLOW_PRIVATE_UPSTREAM` hot-reloadable |
| `TestHotReload` | 8 | Round-trip CIDR list; `get_ip()` honours `TRUST_XFF=first/last/none`; private-upstream guard trips with `ALLOW_PRIVATE_UPSTREAM=False` |
| other | 21 | Settings CSRF shim; controls sidebar removal; edge cases |

---

### `test_v1810_version_consistency.py` — Version single-source-of-truth (Gate 0a)

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| `TestVersionCanonical` | 1 | `config.GW_VERSION` is well-formed `AppSecGW_X.Y.Z` |
| `TestVersionSurfaces` | 6 | `proxy.py`, `docker-compose.yml` image tag + container name, and every served dashboard match `GW_VERSION`; no dashboard shows a different `AppSecGW_X.Y.Z`; no stale second compose image tag |

---

### `test_v1810_vhost_knob_persist.py` — Per-vhost knob persistence (`_to_bool` coercion)

**Version added:** v1.8.10 (bugfix iteration)

| Class / group | Tests | Description |
|-------|-------|-------------|
| (module-level) | 19 | `_to_bool` parses `"true"/"false"/"0"/"1"`; no bare `bool` coercer; `KNOB_META` completeness for WAF_* and 30 other knobs; vhost save/load round-trips bool knobs |

---

*Total test files: 93 | Approximate total test functions: ~2,494+*
