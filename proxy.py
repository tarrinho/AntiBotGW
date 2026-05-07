#!/usr/bin/env python3
"""
Anti-bot reverse proxy v1.7.5 — entry point only.

Domain-agnostic: the upstream target is supplied exclusively via the
UPSTREAM environment variable (no domain is baked in).

Listens on $LISTEN_HOST:$LISTEN_PORT and proxies traffic to $UPSTREAM.

All business logic lives in the package modules imported below.
See each module's docstring for the subsystem it owns.

Run:
  python3 proxy.py

Internal endpoints (not proxied to upstream):
  GET /__pow      → issue a fresh challenge to be solved
  GET /__solver   → in-browser JS PoW solver
  GET /__status   → rate-limiter state snapshot
"""

import asyncio
import json
import sqlite3

from aiohttp import web

# ── Package modules (import order = dependency order) ────────────────────────
from config import *        # noqa: F401,F403 — env vars, constants, key paths
from state import *         # noqa: F401,F403 — mutable globals, IpState, queues
from helpers import *       # noqa: F401,F403 — now(), slog(), get_ip(), etc.
from db import *            # noqa: F401,F403 — SQLite + Postgres persistence
from identity import *      # noqa: F401,F403 — session cookies, fingerprinting
from rate_limit import *    # noqa: F401,F403 — token buckets, prune loop
from detection import *     # noqa: F401,F403 — UA, paths, headers, behavioral, canary
from scoring import *       # noqa: F401,F403 — risk model, ban/unban, signal orders
from reputation import *    # noqa: F401,F403 — AbuseIPDB, CrowdSec, MaxMind, Tor
from challenge import *     # noqa: F401,F403 — PoW, JS challenge, tarpit
from integrations import *  # noqa: F401,F403 — Redis, webhook, JA4, JWT, endpoint policy
from admin import *         # noqa: F401,F403 — auth, users, mesh, settings
from dashboards import *    # noqa: F401,F403 — agents, service metrics, controls
from core import *          # noqa: F401,F403 — metrics, middleware, proxy handler

# Private symbols re-exported for test-suite compatibility
# (names starting with _ are not included in `import *`)
import time as _t
import secrets  # noqa: F401 — tests access proxy_module.secrets
from config import _DASHBOARDS_DIR  # noqa: F401 — leading underscore not in *
from config import _SESSION_COOKIE  # noqa: F401 — gateway session cookie name
from config import (  # noqa: F401 — underscore config vars for test access
    _TURNSTILE_CONFIGURED, _ADMIN_PUBLIC_SUBPATHS, _ADMIN_LOGIN_SUBPATHS,
)
from helpers import (  # noqa: F401
    _strip_admin_key_from_qs, _strip_own_session_cookie,
    _is_admin_path, _admin_path_is_public,
)
from identity import _sign_session, _verify_session
from detection.canary import (  # noqa: F401
    _inject_honey_links, _inject_botd, _botd_token_for,
    inject_canary_probe, canary_probe_endpoint, check_canary_probe,
)
from detection.honey_cred import inject_honey_creds, lookup_honey_key  # noqa: F401
from detection.redirect_maze import (  # noqa: F401
    should_maze, make_maze_entry, redirect_maze_endpoint,
)
import detection.llm_heuristic as _llm_heuristic  # noqa: F401
from core.proxy_handler import honey_probe_endpoint  # noqa: F401
from detection.automation import automation_report_endpoint  # noqa: F401
from detection.fp_enrichment import (  # noqa: F401
    fp_report_endpoint, _fp_token_for, _is_soft_renderer, _inject_fp_probe,
)
from challenge.js_challenge import sw_js_endpoint  # noqa: F401
from detection.cookie_lifecycle import (  # noqa: F401
    cookie_ghost_check, record_gateway_cookie_set, record_html_served,
    _inject_lifecycle_cookie_script, LIFECYCLE_COOKIE,
)
from detection.referer_chain import referer_ghost_check  # noqa: F401
from detection.impossible_travel import impossible_travel_check  # noqa: F401
from detection.paths import _bot_trap_triggered  # noqa: F401
from admin.auth import _internal_authed, _admin_ip_allowed
from admin.users import (  # noqa: F401
    _SESSION_CACHE, _SESSION_CACHE_READY, _SESSION_TTL,
    _new_sid, _session_sign, _session_parse, _session_revoke,
)
from state import (  # noqa: F401 — underscore state vars for test access
    _signal_order_cache, _pow_seen, _canary_tokens, _global_rps_window,
    _postgres_available,
)
from scoring import (  # noqa: F401 — underscore scoring helpers for tests
    _decay_risk, _escalation_score,
    _signal_runtime_order, _should_run_signal,
    _load_signal_order_cache, _save_signal_order,
)
from integrations.endpoint_policy import (  # noqa: F401 — underscore names
    _to_method_set, _to_host_set, _to_country_set,
    _to_endpoint_policies, _to_custom_rules, _eval_custom_rules,
    _endpoint_policy, _endpoint_rule,
)
from integrations.jwt import (  # noqa: F401
    _verify_jwt_hs256, _jwt_required_for,
)
from integrations.webhook import _webhook_event_allowed  # noqa: F401
from integrations.ja4 import _tls_fingerprint_blocked as _tls_fingerprint_blocked_base  # noqa: F401
from challenge.js_challenge import (  # noqa: F401
    _make_chal_cookie, _verify_chal_cookie, _ip_tier,
    _make_chal_nonce, _verify_chal_nonce,
    _turnstile_active_threshold,
    _js_challenge_applicable, _js_challenge_required,
    _serve_js_challenge,
)
from detection.paths import _inject_bot_trap  # noqa: F401
from config import _HOSTILE_REASONS  # noqa: F401
from integrations.redis import _redis, _shared_ban_set, _shared_ban_get  # noqa: F401
from integrations.ja4 import _observe_ja4_ban  # noqa: F401
from integrations.webhook import _post_webhook  # noqa: F401
from detection.canary import _scan_request_for_canary  # noqa: F401
from identity import _fp_hash, _fp_session_creations, _record_chal_mint  # noqa: F401
from challenge.tarpit import (  # noqa: F401
    _tarpit_token, _tarpit_verify, _tarpit_page_html,
)
from config import (  # noqa: F401 — body/DLP functions with leading _ not in *
    _luhn_check,
)
from integrations.jwt import JWT_VALIDATE_PATHS  # noqa: F401 — tests access proxy.JWT_VALIDATE_PATHS
from core.proxy_handler import (  # noqa: F401 — proxy handler private symbols
    _HOT_RELOAD_KNOBS, _ENV_PROVIDED_KNOBS,
    _detector_hits, _detector_latency, _detector_record,
    _reason_method,
)
from dashboards.service_metrics import _sample_service_metrics_loop  # noqa: F401
from rate_limit import _prune_state_loop  # noqa: F401 — called in on_startup
from reputation.maxmind import (  # noqa: F401
    _city_reader, _init_maxmind, _maxmind_refresh_loop, _refresh_ai_crawler_ranges,
)
from reputation.tor import _tor_refresh_loop  # noqa: F401
from integrations.ja4 import _refresh_ja4_denylist_loop  # noqa: F401
from integrations.redis import _shared_init  # noqa: F401
from dashboards.agents import _stealth_score  # noqa: F401 — tests access proxy._stealth_score
from core.proxy_handler import (  # noqa: F401
    _origin_check_failed, _missing_required_header,
    _fetch_upstream_404, _periodic_404_refresh_loop, _upstream_404_cache,
)
from admin.users import (  # noqa: F401 — called in on_startup
    _user_bootstrap, _user_count, _session_cache_load,
)
from admin.mesh import (  # noqa: F401 — gateway registry private symbols
    _gw_validate_id, _gw_generate_keypair, _gw_local_id, _gw_row_to_dict,
    _gw_derive_pubkey, _gw_fingerprint, _gw_id_from_domain,
    _GW_ID_RE, _MESH_SYNC_ELIGIBLE_KEYS, _mesh_sync_loop,
)

# ── Module __setattr__ hook: propagate test patches to all submodules ─────────
# When tests do `proxy_module.FLAG = value`, propagate to every loaded submodule
# that has the same attribute so late-bound reads in those modules see the change.
import sys as _sys_proxy
import types as _types_proxy

class _ProxyModule(_types_proxy.ModuleType):
    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        for _m in list(_sys_proxy.modules.values()):
            if (_m is not None
                    and _m is not _sys_proxy.modules.get(__name__)
                    and hasattr(_m, name)):
                try:
                    setattr(_m, name, value)
                except (AttributeError, TypeError):
                    pass

_this_proxy_mod = _sys_proxy.modules.get(__name__)
if _this_proxy_mod is not None:
    _this_proxy_mod.__class__ = _ProxyModule


# ── Startup / cleanup ──────────────────────────���──────────────────────────────

async def on_startup(app):
    """Initialise SQLite DB + spawn the async writer + load saved state."""
    global db_queue, db_writer_task, prune_task, service_metrics_task
    # Sync UPSTREAM to core.proxy_handler so startup functions (_fetch_upstream_404,
    # proxy(), etc.) see any value set by tests or hot-reload, not the import-time snapshot.
    import core.proxy_handler as _cph
    _cph.UPSTREAM = UPSTREAM
    db_init()
    db_load_state()
    # 1.6.5 — initialise MaxMind FIRST so that knob validators which gate on
    # `_city_reader is not None` (notably COUNTRY_BLOCK_ENABLED) see the
    # readers as loaded when db_load_config applies persisted values.
    # Previously the load order was reversed, which caused
    # COUNTRY_BLOCK_ENABLED=true to be silently rejected on restart and
    # snap back to false even though the DB held the right value.
    _init_maxmind()
    # Propagate MaxMind state to all loaded modules so proxy_handler (which
    # got MAXMIND_ENABLED=False at import time via `from reputation.maxmind
    # import *`) sees the live True value before db_load_config validators run.
    import sys as _sys_mm
    import reputation.maxmind as _mm_mod
    for _mm_attr in ("MAXMIND_ENABLED", "MAXMIND_CITY_ENABLED", "_asn_reader", "_city_reader"):
        _mm_val = getattr(_mm_mod, _mm_attr, None)
        for _mm_m in list(_sys_mm.modules.values()):
            if _mm_m is not None and _mm_m is not _mm_mod and hasattr(_mm_m, _mm_attr):
                try:
                    setattr(_mm_m, _mm_attr, _mm_val)
                except (AttributeError, TypeError):
                    pass
    # 1.6.5 — initialise the Postgres event store schema whenever
    # POSTGRES_DSN is configured. Even when SQLite is the active backend,
    # the standby Postgres has its schema ready so the operator can flip
    # the switch on the Controls dashboard without first running migrate
    # commands. Best-effort: a misconfigured DSN logs a warning but the
    # gateway boots fine.
    if POSTGRES_DSN and _postgres_available:
        if db_init_postgres():
            print(f"[db-pg] event store ready (active={DB_BACKEND})",
                  flush=True)
        else:
            print("[db-pg] init failed — events will only land in the "
                  "active backend (SQLite) until a fresh restart", flush=True)
    # Secrets first: credential-gated knob validators (e.g. ABUSEIPDB_ENABLED,
    # TURNSTILE_ENABLED) read globals() of core.proxy_handler to check whether
    # the matching API key is present. Loading secrets first + propagating via
    # _refresh_integration_state ensures those values are in every module
    # namespace before db_load_config runs its validators.
    db_load_secrets()
    # 1.5.5 — load DB-persisted hot-reload knobs over env defaults so live
    # changes pushed via /__config survive restart.
    db_load_config()
    # 1.6.10 — load per-gateway signal activation-order overrides from DB.
    _load_signal_order_cache()
    db_queue = asyncio.Queue(maxsize=10000)
    # Push the live Queue into every loaded module that has a db_queue
    # attribute (submodules did `from state import *` which cached
    # db_queue=None at import time; in tests on_startup is called multiple
    # times so we propagate unconditionally, not just when value is None).
    import sys as _sys
    for _m in list(_sys.modules.values()):
        if _m is not None and hasattr(_m, 'db_queue'):
            try:
                setattr(_m, 'db_queue', db_queue)
            except (AttributeError, TypeError):
                pass
    db_writer_task = asyncio.create_task(db_writer_loop())
    db_load_admin_ips()
    print(f"[admin-ips] {len(ADMIN_ALLOWED_ENTRIES)} entries loaded "
          f"({sum(1 for e in ADMIN_ALLOWED_ENTRIES if e['source']=='env')} env, "
          f"{sum(1 for e in ADMIN_ALLOWED_ENTRIES if e['source']=='manual')} manual)")
    # 1.6.7 — bootstrap an `admin` user from INTERNAL_KEY on first boot
    # so the dashboard login works out of the box.
    _user_bootstrap()
    print(f"[users] {_user_count()} dashboard user(s) registered", flush=True)
    # 1.6.7 — load the active sessions cache from `user_sessions`.
    _session_cache_load()
    # 1.6.7 — print first-time login instructions to the container log so
    # an operator running `docker compose up -d` can see how to sign in
    # without having to dig the auto-generated key out of /data. The
    # message disappears once any user has actually logged in (same
    # condition as the login-page bootstrap hint).
    try:
        conn = sqlite3.connect(DB_PATH)
        seen = conn.execute(
            "SELECT COUNT(*) FROM users WHERE last_login_ts IS NOT NULL"
        ).fetchone()[0]
        conn.close()
    except Exception:
        seen = 1
    if not seen:
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║ FIRST-TIME LOGIN                                         ║")
        print("  ║   open  /antibot-appsec-gateway/login                    ║")
        print("  ║   user: admin                                            ║")
        if ADMIN_KEY_FROM_ENV:
            _bootstrap_pw_line = "   pass: see your ADMIN_KEY env var"
        else:
            _bootstrap_pw_line = ("   pass: " + INTERNAL_KEY)
        print(f"  ║ {_bootstrap_pw_line:<57}║")
        print("  ║   then change the password in Settings → Users           ║")
        print("  ╚══════════════════════════════════════════════════════════╝",
              flush=True)
    if ABUSEIPDB_ENABLED:
        print(f"[abuseipdb] active — cache TTL {ABUSEIPDB_CACHE_HOURS} h, "
              f"thresholds high={ABUSEIPDB_HIGH_THRESHOLD} med={ABUSEIPDB_MED_THRESHOLD}",
              flush=True)
    if CROWDSEC_ENABLED:
        print(f"[crowdsec] active — LAPI {CROWDSEC_LAPI_URL}, "
              f"cache {CROWDSEC_CACHE_SECS}s", flush=True)
    # 1.5.4: prime upstream 404 cache so blocked admin requests mirror it
    if await _fetch_upstream_404():
        print(f"[upstream-404] cached: status={_upstream_404_cache['status']} "
              f"size={len(_upstream_404_cache['body'])}b "
              f"ctype={_upstream_404_cache['ctype'][:40]}", flush=True)
    else:
        print("[upstream-404] WARN: prime fetch failed; will retry hourly. "
              "Falling back to plain 'Not Found' until refreshed.", flush=True)
    asyncio.create_task(_periodic_404_refresh_loop())
    prune_task = asyncio.create_task(_prune_state_loop())
    service_metrics_task = asyncio.create_task(_sample_service_metrics_loop())
    # 1.5.4 — self-maintaining MaxMind dbs (no host-side cron needed when
    # MAXMIND_LICENSE_KEY is set; checks daily, refreshes when >30d old).
    asyncio.create_task(_maxmind_refresh_loop())
    # 1.6.0 — Tor exit-list weekly refresh (no-op until TOR_BLOCK_ENABLED=1).
    asyncio.create_task(_tor_refresh_loop())
    # 1.5.0: optional shared-state connect. Failures degrade to no-op so
    # an unreachable Redis never prevents the gateway from coming up.
    await _shared_init()
    # 1.5.0: poll the shared JA4_DENY_LIST every 30 s (no-op when no Redis).
    asyncio.create_task(_refresh_ja4_denylist_loop())
    # 1.6.10 — fetch AI crawler IP ranges (OpenAI gptbot-ranges.txt) at startup;
    # refreshes every 24 h. No-op when AI_CRAWLER_VERIFY_ENABLED=0.
    if AI_CRAWLER_VERIFY_ENABLED:
        asyncio.create_task(_refresh_ai_crawler_ranges())
    # 1.6.7 — mesh-sync of integration secrets (no-op without REDIS_URL).
    global _mesh_sync_task
    _mesh_sync_task = asyncio.create_task(_mesh_sync_loop())
    print(f"[db] persistence active → {DB_PATH}")
    print(f"[svc-metrics] sampling every {SERVICE_METRICS_INTERVAL}s, "
          f"keeping {SERVICE_METRICS_RETENTION} samples")
    if JS_CHALLENGE and not TURNSTILE_ENABLED:
        print("[js-challenge] active (heuristic mint, no third-party). "
              "Cookie gate engages on every non-static path; cookie is "
              "auto-issued on the first qualifying HTML GET. Bypass cost "
              "vs determined script: ~1 RTT — combine with R7 canary "
              "echo, body-pattern, UA filter, hostile pool. For a hard "
              "boundary set TURNSTILE_SITEKEY/SECRET (auto-enables on "
              "presence).", flush=True)
    elif JS_CHALLENGE and TURNSTILE_ENABLED:
        print("[js-challenge] active (Turnstile-backed cookie gate)",
              flush=True)


async def on_cleanup(app):
    """Flush queue and close DB writer cleanly."""
    global prune_task, service_metrics_task
    if prune_task:
        prune_task.cancel()
    if service_metrics_task:
        service_metrics_task.cancel()
    if db_writer_task:
        # Final global counters flush
        if db_queue is not None:
            await db_queue.put(("set_kv", ("total_requests", str(metrics["total_requests"]))))
            await db_queue.put(("set_kv", ("allowed", str(metrics["allowed"]))))
            await db_queue.put(("set_kv", ("blocked", str(metrics["blocked"]))))
            await db_queue.put(("set_kv", ("by_reason", json.dumps(dict(metrics["by_reason"])))))
            await db_queue.put(("set_kv", ("by_status", json.dumps({str(k): v for k, v in metrics["by_status"].items()}))))
            await db_queue.put(("set_kv", ("by_path", json.dumps(dict(metrics["by_path"])))))
            # Wait for queue to drain
            try:
                await asyncio.wait_for(db_queue.join() if hasattr(db_queue, 'join') else asyncio.sleep(0.5), timeout=3)
            except asyncio.TimeoutError:
                pass
        db_writer_task.cancel()


# ── Application factory ───────────────────────────────────────────────────────

def make_app() -> web.Application:
    app = web.Application(middlewares=[cost_meter, session_cookie_finalizer, protect])
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # ── 1.6.6: every internal endpoint lives under a single namespace.
    # Public sub-paths (liveness probe + JS-challenge plumbing + BotD
    # bundle/callback + dashboard assets) live directly under ADMIN_NS;
    # everything that requires the admin key is mounted under
    # ADMIN_NS_SECURED. The protect middleware enforces auth based on
    # path prefix — see _admin_path_is_public(). The legacy `/__*`
    # routes from earlier releases were removed in this cut once the
    # new structure was confirmed working in production.
    PUBLIC = ADMIN_NS                # /antibot-appsec-gateway
    SEC    = ADMIN_NS_SECURED        # /antibot-appsec-gateway/secured
    ASSETS = str(_DASHBOARDS_DIR / "assets")

    # (path_suffix, method, handler, secured?)
    _ROUTES = [
        # ── public (no admin-key required) ──────────────────────
        ("pow",                "GET",  pow_endpoint,                  False),
        ("solver",             "GET",  solver_endpoint,               False),
        ("botd-report",        "POST", botd_report_endpoint,          False),
        ("automation-report",  "POST", automation_report_endpoint,    False),
        # 1.7.2 — canvas/WebGL fingerprint report + Service Worker
        ("fp-report",          "POST", fp_report_endpoint,            False),
        ("sw.js",              "GET",  sw_js_endpoint,                False),
        # 1.6.9 — AI Labyrinth tarpit (public; HMAC-gated internally)
        ("tarpit/{token}",     "GET",  tarpit_endpoint,               False),
        # 1.7.3 — AI-agent detection probes (public, no auth)
        ("probe",                       "GET", honey_probe_endpoint,      False),
        ("maze",                        "GET", redirect_maze_endpoint,    False),
        ("canary-probe/{token}",        "GET", canary_probe_endpoint,     False),
        # ── secured (admin-IP + admin-key gated) ────────────────
        ("status",            "GET",    status_endpoint,                       True),
        ("dashboard",         "GET",    dashboard_endpoint,                    True),
        ("metrics",           "GET",    metrics_endpoint,                      True),
        ("unban",             "GET",    unban_endpoint,                        True),
        ("unban",             "POST",   unban_endpoint,                        True),
        ("ban",               "GET",    ban_endpoint,                          True),
        ("ban",               "POST",   ban_endpoint,                          True),
        ("scoring",           "GET",    scoring_endpoint,                      True),
        ("thresholds",        "GET",    thresholds_endpoint,                   True),
        ("cost-timeline",     "GET",    cost_timeline_endpoint,                True),
        ("agents-bucket",     "GET",    agents_bucket_detail_endpoint,         True),
        ("path-hits",         "GET",    path_hits_endpoint,                    True),
        ("geo",               "GET",    geo_dashboard_endpoint,                True),
        ("geo-data",          "GET",    geo_data_endpoint,                     True),
        ("geo-drill",         "GET",    geo_drill_endpoint,                    True),
        ("logs",              "GET",    logs_dashboard_endpoint,               True),
        ("logs-data",         "GET",    logs_data_endpoint,                    True),
        ("logs-export",       "GET",    logs_export_endpoint,                  True),
        ("health-score",      "GET",    health_score_endpoint,                 True),
        ("detector-stats",    "GET",    detector_stats_endpoint,               True),
        ("lists-snapshot",    "GET",    lists_snapshot_endpoint,               True),
        ("db-test",           "GET",    db_test_endpoint,                      True),
        ("db-switch",         "POST",   db_switch_endpoint,                    True),
        ("disk-stats",        "GET",    disk_stats_endpoint,                   True),
        ("db-vacuum",         "POST",   db_vacuum_endpoint,                    True),
        ("maxmind-fetch",     "POST",   maxmind_fetch_endpoint,                True),
        ("external",          "GET",    external_endpoint,                     True),
        ("integration-check", "GET",    integration_check_endpoint,            True),
        ("signal-orders",     "GET",    signal_orders_endpoint,                True),
        ("signal-orders",     "POST",   signal_orders_endpoint,                True),
        ("admin-ips",         "GET",    admin_ips_endpoint,                    True),
        ("admin-ips",         "POST",   admin_ips_endpoint,                    True),
        ("admin-ips",         "PATCH",  admin_ips_endpoint,                    True),
        ("admin-ips",         "DELETE", admin_ips_endpoint,                    True),
        ("rotate-keys",       "POST",   rotate_keys_endpoint,                  True),
        ("secrets",           "GET",    secrets_endpoint,                      True),
        ("secrets",           "POST",   secrets_endpoint,                      True),
        ("secrets",           "DELETE", secrets_endpoint,                      True),
        ("config",            "GET",    config_endpoint,                       True),
        ("config",            "POST",   config_endpoint,                       True),
        ("agents",            "GET",    agents_dashboard_endpoint,             True),
        ("agents-data",       "GET",    agents_data_endpoint,                  True),
        ("agents-timeline",   "GET",    agents_timeline_endpoint,              True),
        ("service",           "GET",    service_dashboard_endpoint,            True),
        ("service-data",      "GET",    service_metrics_data_endpoint,         True),
        ("controls",          "GET",    controls_dashboard_endpoint,           True),
        ("settings",          "GET",    settings_dashboard_endpoint,           True),
        ("settings-export",   "GET",    settings_export_endpoint,              True),
        ("settings-import",   "POST",   settings_import_endpoint,              True),
        ("xff",               "GET",    debug_xff,                             True),
    ]

    _METHOD_MAP = {
        "GET":    app.router.add_get,
        "POST":   app.router.add_post,
        "PATCH":  app.router.add_patch,
        "DELETE": app.router.add_delete,
    }
    for suffix, method, handler, secured in _ROUTES:
        canonical_root = SEC if secured else PUBLIC
        canonical = f"{canonical_root}/{suffix}"
        _METHOD_MAP[method](canonical, handler)

    # 1.6.7 — Gateway Registry routes (parameterised paths can't be
    # expressed in the flat _ROUTES table above, so they're wired
    # directly here. All admin-IP + admin-key gated by the protect
    # middleware via the SEC prefix.)
    GW = SEC + "/admin/gw-registry"
    app.router.add_get   (GW,                                       gw_registry_list_endpoint)
    app.router.add_post  (GW,                                       gw_registry_create_endpoint)
    app.router.add_get   (GW + "/distribution/matrix",              gw_registry_distribution_matrix_endpoint)
    app.router.add_post  (GW + "/distribution/rules",               gw_registry_distribution_rules_endpoint)
    app.router.add_get   (GW + "/audit-log",                        gw_registry_audit_log_endpoint)
    app.router.add_get   (GW + "/{gw_id}",                          gw_registry_get_endpoint)
    app.router.add_patch (GW + "/{gw_id}",                          gw_registry_update_endpoint)
    app.router.add_delete(GW + "/{gw_id}",                          gw_registry_delete_endpoint)
    app.router.add_patch (GW + "/{gw_id}/can-distribute",           gw_registry_can_distribute_endpoint)
    app.router.add_patch (GW + "/{gw_id}/auto-apply",               gw_registry_auto_apply_endpoint)
    app.router.add_post  (GW + "/{gw_id}/rotate-key",               gw_registry_rotate_key_endpoint)
    app.router.add_get   (GW + "/{gw_id}/sync-status",              gw_registry_sync_status_endpoint)

    # 1.6.7 — Login flow + Users CRUD ────────────────────────────────
    app.router.add_get  (PUBLIC + "/login",  login_page_endpoint)
    app.router.add_post (PUBLIC + "/login",  login_submit_endpoint)
    app.router.add_get  (PUBLIC + "/logout", logout_endpoint)
    app.router.add_get  (SEC    + "/whoami", whoami_endpoint)
    app.router.add_get  (SEC    + "/ip-intel/{ip}", ip_intel_endpoint)
    USERS = SEC + "/admin/users"
    app.router.add_get   (USERS,                  users_list_endpoint)
    app.router.add_post  (USERS,                  users_create_endpoint)
    app.router.add_get   (USERS + "/{username}",  users_get_endpoint)
    app.router.add_patch (USERS + "/{username}",  users_update_endpoint)
    app.router.add_delete(USERS + "/{username}",  users_delete_endpoint)
    app.router.add_get   (USERS + "/{username}/sessions",            user_sessions_list_endpoint)
    app.router.add_post  (USERS + "/{username}/sessions/{sid}/revoke", user_session_revoke_endpoint)

    # 1.6.7 — Mesh-sync of integration secrets / variables ───────────
    MESH = SEC + "/admin/mesh-sync"
    app.router.add_get  (MESH,                              mesh_sync_state_endpoint)
    app.router.add_post (MESH + "/{key}/toggle",            mesh_sync_toggle_endpoint)
    app.router.add_post (MESH + "/pending/{id}/confirm",    mesh_sync_confirm_endpoint)
    app.router.add_post (MESH + "/pending/{id}/reject",     mesh_sync_reject_endpoint)

    # Liveness probe — public, handled inline by protect(). We register
    # a stub route here only so URL reversal / router introspection
    # works; the middleware short-circuits before reaching the handler.
    async def _live_stub(_r):
        return web.Response(text="ok", content_type="text/plain")
    app.router.add_get(PUBLIC + "/live", _live_stub)

    # 1.6.10 — robots.txt: served before the catch-all proxy so the gateway
    # controls the content regardless of what the upstream serves at /robots.txt.
    app.router.add_get("/robots.txt", robots_txt_endpoint)

    # Static dashboard assets (botd.bundle.js, escalate.svg, …) —
    # browser-callable (BotD bundle is fetched by regular users).
    app.router.add_static(PUBLIC + "/assets/", path=ASSETS, show_index=False)

    # Catch-all upstream proxy MUST be last.
    app.router.add_route("*", "/{path:.*}", proxy)
    return app


# ── Namespace-aware wrappers ──────────────────────────────────────────────────
# These functions shadow the imported versions so that test-suite patches
# of proxy.* globals are honoured at call time.  Each wrapper reads config
# flags from proxy.py's own globals() dict (the module namespace) rather
# than from the originating submodule's globals, which is what `import X`
# bindings would read.

def db_load_config():
    """No-arg wrapper: calls db.sqlite.db_load_config with proxy globals."""
    from db.sqlite import db_load_config as _db_load_config
    _db_load_config(globals())
    # Cascade changed knobs to submodules via _ProxyModule.__setattr__ — but
    # only when this call originates from the registered proxy module (production
    # path). In test environments that load proxy via importlib, globals() belongs
    # to the importlib instance while sys.modules["proxy"] is a different object;
    # skipping the cascade prevents cross-contamination between the two instances.
    _me = _sys_proxy.modules.get(__name__)
    if _me is None or _me.__dict__ is not globals():
        return
    _knobs = globals().get("_HOT_RELOAD_KNOBS", {})
    for _k in _knobs:
        if _k in globals():
            try:
                type(_me).__setattr__(_me, _k, globals()[_k])
            except Exception:
                pass


def db_load_secrets():
    """No-arg wrapper: calls db.sqlite.db_load_secrets with proxy globals."""
    from db.sqlite import db_load_secrets as _db_load_secrets
    _db_load_secrets(globals())


def get_ip(request) -> str:
    """get_ip reading TRUST_XFF / TRUSTED_PROXIES_NETS from proxy globals."""
    import ipaddress as _ipa
    g = globals()
    _trust_xff = g.get("TRUST_XFF", "first")
    _nets = g.get("TRUSTED_PROXIES_NETS", [])
    xff = request.headers.get("X-Forwarded-For")
    def _trusted(remote):
        if not _nets:
            return True
        if not remote:
            return False
        try:
            ip = _ipa.ip_address(remote)
        except (ValueError, TypeError):
            return False
        return any(ip in net for net in _nets)
    if xff and _trust_xff != "none" and _trusted(request.remote or ""):
        parts = [p.strip() for p in xff.split(",")]
        return parts[0] if _trust_xff == "first" else parts[-1]
    return request.remote or "0.0.0.0"  # nosec B104


def _admin_ip_allowed(request) -> bool:
    """_admin_ip_allowed reading ADMIN_ALLOWED_NETS from proxy globals."""
    import ipaddress as _ipa
    from helpers import get_ip as _get_ip_helper
    nets = globals().get("ADMIN_ALLOWED_NETS", [])
    if not nets:
        return True
    try:
        ip = _ipa.ip_address(_get_ip_helper(request))
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in nets)


def _bot_trap_triggered(body: bytes, ctype: str) -> tuple:
    """_bot_trap_triggered reading BOT_TRAP_FORMS / BOT_TRAP_FIELDS from proxy globals."""
    g = globals()
    trap_forms = g.get("BOT_TRAP_FORMS", False)
    trap_fields = g.get("BOT_TRAP_FIELDS", [])
    if not trap_forms or not body:
        return (False, "")
    if "x-www-form-urlencoded" not in ctype.lower():
        return (False, "")
    sample = body[:65536]
    if not any((f + "=").encode() in sample for f in trap_fields):
        return (False, "")
    try:
        from urllib.parse import parse_qs
        q = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=False)
        for f in trap_fields:
            v = (q.get(f, [""])[0] or "").strip()
            if v:
                return (True, f)
    except Exception:
        return (False, "")
    return (False, "")


def _endpoint_policy(path: str) -> str:
    """_endpoint_policy reading ENDPOINT_POLICIES from proxy globals."""
    rule = _endpoint_rule(path)
    return rule["policy"] if rule else "default"


def _endpoint_rule(path: str):
    """_endpoint_rule reading ENDPOINT_POLICIES from proxy globals."""
    import fnmatch as _fnmatch
    policies = globals().get("ENDPOINT_POLICIES", [])
    if not policies:
        return None
    for item in policies:
        if isinstance(item, dict):
            if _fnmatch.fnmatchcase(path, item.get("path", "")):
                return item
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            if _fnmatch.fnmatchcase(path, item[0]):
                return {"path": item[0], "policy": item[1], "rps": None, "burst": None}
    return None


def _eval_custom_rules(request, ip: str):
    """_eval_custom_rules reading CUSTOM_RULES from proxy globals."""
    import fnmatch as _fnmatch
    import ipaddress as _ipa
    rules = globals().get("CUSTOM_RULES", [])
    if not rules:
        return None, ""
    path = request.path
    method = request.method.upper()
    ua = (request.headers.get("User-Agent") or "")
    ua_lower = ua.lower()
    headers = request.headers
    query = getattr(request, "query", {}) or {}
    for rule in rules:
        cond = rule.get("if") or {}
        ok = True
        p = cond.get("path")
        if p and not _fnmatch.fnmatchcase(path, str(p)):
            ok = False
        if ok:
            m = cond.get("method")
            if m:
                allowed_methods = (
                    [str(x).upper() for x in m] if isinstance(m, list)
                    else [str(m).upper()])
                if method not in allowed_methods:
                    ok = False
        if ok:
            uac = cond.get("ua_contains")
            if uac and str(uac).lower() not in ua_lower:
                ok = False
        if ok:
            for k, want in cond.items():
                if not k.startswith("header."):
                    continue
                hdr_name = k[7:]
                hdr_val = (headers.get(hdr_name) or "")
                if str(want).lower() not in hdr_val.lower():
                    ok = False
                    break
        if ok:
            cidr_list = cond.get("ip_cidr")
            if cidr_list is not None:
                try:
                    pip = _ipa.ip_address(ip)
                    if not any(pip in net for net in cidr_list):
                        ok = False
                except (ValueError, TypeError):
                    ok = False
        if ok:
            return rule.get("then"), rule.get("tag", "")
    return None, ""


def _verify_jwt_hs256(token: str) -> tuple:
    """_verify_jwt_hs256 reading JWT_* constants from proxy globals."""
    import base64 as _b64
    import hashlib, hmac as _hmac, json, time as _t
    g = globals()
    secret = g.get("JWT_HMAC_SECRET", "")
    req_iss = g.get("JWT_REQUIRED_ISSUER", "")
    req_aud = g.get("JWT_REQUIRED_AUDIENCE", "")
    leeway = g.get("JWT_LEEWAY_SECS", 10)
    if not secret:
        return False, "no-secret-configured"
    parts = token.split(".")
    if len(parts) != 3:
        return False, "malformed"
    header_b64, payload_b64, sig_b64 = parts
    def _b64u_decode(seg):
        pad = "=" * (-len(seg) % 4)
        return _b64.urlsafe_b64decode(seg + pad)
    try:
        header = json.loads(_b64u_decode(header_b64))
        payload = json.loads(_b64u_decode(payload_b64))
        sig = _b64u_decode(sig_b64)
    except (ValueError, KeyError, json.JSONDecodeError):
        return False, "malformed"
    if header.get("alg") != "HS256" or header.get("typ", "JWT") != "JWT":
        return False, "alg-not-hs256"
    msg = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = _hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    if not _hmac.compare_digest(expected, sig):
        return False, "bad-signature"
    n = int(_t.time())
    exp = payload.get("exp")
    if exp is not None and n > int(exp) + leeway:
        return False, "expired"
    nbf = payload.get("nbf")
    if nbf is not None and n + leeway < int(nbf):
        return False, "not-yet-valid"
    if req_iss and payload.get("iss") != req_iss:
        return False, "issuer-mismatch"
    if req_aud:
        aud = payload.get("aud")
        if isinstance(aud, list):
            if req_aud not in aud:
                return False, "audience-mismatch"
        elif aud != req_aud:
            return False, "audience-mismatch"
    return True, "ok"


def _jwt_required_for(path: str) -> bool:
    """_jwt_required_for reading JWT_VALIDATE_PATHS from proxy globals."""
    import fnmatch as _fnmatch
    paths = globals().get("JWT_VALIDATE_PATHS", [])
    if not paths:
        return False
    return any(_fnmatch.fnmatchcase(path, g) for g in paths)


def _webhook_event_allowed(event: dict) -> bool:
    """_webhook_event_allowed reading WEBHOOK_EVENT_FILTER from proxy globals."""
    import fnmatch as _fnmatch
    flt = globals().get("WEBHOOK_EVENT_FILTER", [])
    if not flt:
        return True
    candidates = [str(event.get("reason", "")), str(event.get("event", ""))]
    for cand in candidates:
        if not cand:
            continue
        for f in flt:
            if "*" in f or "?" in f:
                if _fnmatch.fnmatchcase(cand, f):
                    return True
            elif cand == f:
                return True
    return False


def match_body_group(body: bytes, ctype: str):
    """match_body_group reading BODY_PATTERN_MATCH / BODY_GROUP_*_ENABLED from proxy globals."""
    from urllib.parse import unquote_to_bytes as _uqb
    g = globals()
    if not g.get("BODY_PATTERN_MATCH") or not body:
        return None
    cl = ctype.lower()
    if not any(t in cl for t in ("application/json", "application/x-www-form-urlencoded",
                                  "text/plain", "text/xml", "application/xml")):
        return None
    sample = body[:65536]
    if "x-www-form-urlencoded" in cl:
        sample = _uqb(sample)
    from config import BODY_PATTERN_GROUPS
    enabled = {
        "rce":  g.get("BODY_GROUP_RCE_ENABLED",  True),
        "cmd":  g.get("BODY_GROUP_CMD_ENABLED",   True),
        "sqli": g.get("BODY_GROUP_SQLI_ENABLED",  True),
        "xss":  g.get("BODY_GROUP_XSS_ENABLED",   True),
        "lfi":  g.get("BODY_GROUP_LFI_ENABLED",   True),
        "ssrf": g.get("BODY_GROUP_SSRF_ENABLED",  True),
    }
    for grp in ("rce", "cmd", "sqli", "xss", "lfi", "ssrf"):
        if not enabled[grp]:
            continue
        for pat in BODY_PATTERN_GROUPS[grp]:
            if pat.search(sample):
                return grp
    return None


def dlp_scan(body: bytes, ctype: str):
    """dlp_scan reading DLP_* flags from proxy globals."""
    g = globals()
    if not g.get("DLP_ENABLED") or not body:
        return []
    cl = (ctype or "").lower()
    if not any(t in cl for t in (
            "application/json", "application/xml", "text/", "+xml", "+json")):
        return []
    max_bytes = g.get("DLP_MAX_BYTES", 256 * 1024)
    sample = body[:max_bytes]
    enabled = {
        "cc":          g.get("DLP_GROUP_CC_ENABLED",          True),
        "aws":         g.get("DLP_GROUP_AWS_ENABLED",         True),
        "jwt":         g.get("DLP_GROUP_JWT_ENABLED",         True),
        "private-key": g.get("DLP_GROUP_PRIVATE_KEY_ENABLED", True),
        "api-key":     g.get("DLP_GROUP_API_KEY_ENABLED",     True),
        "pii-email":   g.get("DLP_GROUP_PII_EMAIL_ENABLED",   False),
        "pii-ssn":     g.get("DLP_GROUP_PII_SSN_ENABLED",     True),
    }
    from config import DLP_PATTERN_GROUPS, _luhn_check as _lc
    hits = []
    for grp, pats in DLP_PATTERN_GROUPS.items():
        if not enabled.get(grp):
            continue
        for pat in pats:
            for m in pat.finditer(sample):
                raw = m.group(0)
                if grp == "cc":
                    digits = bytes(b for b in raw if 0x30 <= b <= 0x39)
                    if not (13 <= len(digits) <= 19) or not _lc(digits):
                        continue
                hits.append((grp, raw[:64]))
                if len(hits) >= 8:
                    return hits
    return hits


def _should_run_signal(sig: str, esc_score: float) -> bool:
    """_should_run_signal reading thresholds from proxy globals."""
    from scoring import _signal_runtime_order
    g = globals()
    o = _signal_runtime_order(sig)
    if o == 3:
        t = g.get("ESCALATION_THRESHOLD", 30.0)
        return (t <= 0) or (esc_score >= t)
    if o == 2:
        t = g.get("SECOND_ORDER_THRESHOLD", 20.0)
        return (t <= 0) or (esc_score >= t)
    return True


def _tls_fingerprint_blocked(request) -> bool:
    """Namespace-aware wrapper: reads JA4_DENY_LIST / JA4_HEADER / JA4_TRUSTED_NETS from proxy globals."""
    import ipaddress as _ipa
    g = globals()
    deny_list = g.get("JA4_DENY_LIST", set())
    if not deny_list:
        return False
    ja4_header = g.get("JA4_HEADER", "CF-JA4")
    trusted_nets = g.get("JA4_TRUSTED_NETS", [])
    if trusted_nets:
        try:
            ip = _ipa.ip_address(request.remote or "")
            if not any(ip in net for net in trusted_nets):
                return False
        except (ValueError, TypeError):
            return False
    fp = (request.headers.get(ja4_header) or "").strip()
    return bool(fp) and fp in deny_list


def _origin_check_failed(request) -> bool:
    """Namespace-aware wrapper: reads STRICT_ORIGIN / OPEN_ORIGIN_PATHS / ALLOWED_HOSTS from proxy globals."""
    g = globals()
    if not g.get("STRICT_ORIGIN", False):
        return False
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return False
    open_paths = g.get("OPEN_ORIGIN_PATHS", [])
    if any(request.path.startswith(p) for p in open_paths):
        return False
    origin = request.headers.get("Origin", "").strip()
    if not origin:
        return True
    try:
        from urllib.parse import urlparse
        host = (urlparse(origin).netloc or "").split(":", 1)[0].lower()
    except Exception:
        return True
    allowed = g.get("ALLOWED_HOSTS", set())
    if not allowed:
        return False
    return host not in allowed


def _missing_required_header(request) -> bool:
    """Namespace-aware wrapper: reads REQUIRED_HEADERS from proxy globals."""
    from helpers import _is_admin_path as _iap
    required = globals().get("REQUIRED_HEADERS", [])
    if not required:
        return False
    if _iap(request.path):
        return False
    if request.path.endswith((
            ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif",
            ".svg", ".webp", ".avif", ".ico", ".woff", ".woff2",
            ".ttf", ".otf", ".eot", ".map")):
        return False
    return any(h not in request.headers for h in required)


async def tarpit_endpoint(request):
    """Namespace-aware wrapper: checks LABYRINTH_ENABLED from proxy globals."""
    from aiohttp import web as _web
    if not globals().get("LABYRINTH_ENABLED", True):
        raise _web.HTTPNotFound()
    from challenge.tarpit import tarpit_endpoint as _te
    return await _te(request)


# Patch core.proxy_handler.get_ip to the namespace-aware version above so that
# test patches (proxy.TRUSTED_PROXIES_NETS = ...) propagate via globals().
# Guard: only override if core.proxy_handler.get_ip is still the original helpers
# version — this prevents test helper copies of proxy.py (e.g. _test_proxy_abuseipdb
# loaded via importlib in db_load tests) from hijacking the patch after the real
# proxy entry-point has already applied it.
import core.proxy_handler as _cph_gip
import helpers as _h_gip_patch
if _cph_gip.__dict__.get("get_ip") is _h_gip_patch.__dict__.get("get_ip"):
    _cph_gip.get_ip = get_ip


if __name__ == "__main__":
    if ADMIN_KEY_FROM_ENV:
        key_line = "supplied via ADMIN_KEY env"
    else:
        key_line = f"auto-generated; first 4 chars: {INTERNAL_KEY[:4]}***  (read /data/.admin_key)"
    print(f"  ╔══════════════════════════════════════════════════════════╗")
    print(f"  ║ {GW_VERSION:<10}     →  {UPSTREAM:<37} ║")
    print(f"  ║ Listen: http://{LISTEN_HOST}:{LISTEN_PORT}{' '*36}║")
    _ns_line = f"Admin namespace: {ADMIN_NS}"
    print(f"  ║ {_ns_line:<57}║")
    _pub_line = "Public sub-paths: /live /pow /solver /challenge /assets/"
    print(f"  ║ {_pub_line:<57}║")
    _sec_line = f"Secured: {ADMIN_NS_SECURED}/{{dashboard, ...}}"
    print(f"  ║ {_sec_line:<57}║")
    print(f"  ║ DB:    {DB_PATH:<50}║")
    print(f"  ║ Admin key: {key_line:<46}║")
    if ADMIN_ALLOWED_NETS:
        nets = ", ".join(str(n) for n in ADMIN_ALLOWED_NETS)[:46]
        print(f"  ║ Admin IPs: {nets:<46}║")
    else:
        print(f"  ║ Admin IPs: any (set ADMIN_ALLOWED_IPS to restrict)    ║")
    print(f"  ╚══════════════════════════════════════════════════════════╝")
    web.run_app(make_app(), host=LISTEN_HOST, port=LISTEN_PORT, print=None,
                keepalive_timeout=HEADERS_TIMEOUT)
