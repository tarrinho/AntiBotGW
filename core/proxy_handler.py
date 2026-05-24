"""core/proxy_handler.py — main proxy handler + gateway admin endpoints.

Extracted from proxy.py (Phase 9).  Contains:
  • Module-level proxy constants (ALLOWED_METHODS, HOP_BY_HOP_*, etc.)
  • _silent_decoy_response() / _fetch_upstream_404() / _serve_mirrored_404()
  • _is_ws_upgrade() / proxy_websocket() / proxy()  — the core forwarding layer
  • debug_xff()
  • Admin endpoint functions not yet in admin/ or dashboards/:
    thresholds_endpoint, external_endpoint, integration_check_endpoint,
    signal_orders_endpoint, admin_ips_endpoint, ban_endpoint,
    secrets_endpoint, rotate_keys_endpoint, config_endpoint, status_endpoint
  • _to_bool / _to_path_list / _to_ja4_set / _to_method_set / _to_host_set /
    _to_country_set / _to_endpoint_policies / _to_custom_rules /
    _eval_custom_rules  — already in integrations/endpoint_policy.py and
    re-exported here for backwards compatibility
  • _HOT_RELOAD_KNOBS / _ENV_PROVIDED_KNOBS / _read_hot_reload_state()
"""

import asyncio
import json
import os
import re
import secrets
import sqlite3
import random as _random
import time as _t

import aiohttp
from aiohttp import web, ClientSession, ClientTimeout

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from helpers import *  # noqa: F401,F403
from helpers import (  # noqa: F401 — underscore names not exported by import *
    _new_request_id, _is_admin_path, _admin_path_is_public,
    _strip_admin_key_from_qs, _strip_own_session_cookie,
)
from db import *       # noqa: F401,F403
from identity import *     # noqa: F401,F403
from rate_limit import *   # noqa: F401,F403
from detection import *    # noqa: F401,F403
from scoring import *      # noqa: F401,F403
from scoring import _escalation_score, _decay_risk  # noqa: F401 — underscore names not in import *
from reputation import *   # noqa: F401,F403
from challenge import *    # noqa: F401,F403
from integrations import * # noqa: F401,F403
# _to_* converter functions start with _ so are skipped by import *; import explicitly
from integrations.endpoint_policy import (  # noqa: F401
    _to_bool, _to_path_list, _to_ja4_set, _to_method_set,
    _to_host_set, _to_country_set, _to_endpoint_policies,
    _to_custom_rules, _eval_custom_rules, _to_ip_net_list,
)
from admin import *        # noqa: F401,F403
from vhost import vc, set_vhost, VHOSTS, get_vhost_rps_window, current_vhost_host, vhost_is_configured
from core.metrics import record, _timeline_bump, _bucket_now  # noqa: F401
from config import _DASHBOARDS_DIR  # noqa: F401 — leading underscore not in *
from config import _LOG_LEVELS, _LOG_LEVEL_N  # noqa: F401 — leading underscore not in *
from config import _REQUEST_ID_HEADER, _REQUEST_ID_RE  # noqa: F401 — leading underscore not in *
from config import _parse_authorized_bot_uas  # noqa: F401
from config import (  # noqa: F401 — more underscore config constants
    _CANARY_PREFIX, _CANARY_USED_MAX, _CANARY_RE,
    _ADMIN_PUBLIC_SUBPATHS, _ADMIN_LOGIN_SUBPATHS, _ADMIN_POLL_SUBPATHS,
    _HOSTILE_REASONS, _JS_CHAL_OPEN_PATHS_RAW,
    _TURNSTILE_CONFIGURED, _PROC,
)
from dashboards.agents import _stealth_score, AGENT_BLOCK_REASONS  # noqa: F401
# Underscore-prefixed functions not exported by import * — explicit imports required
from admin.auth import _internal_authed, _is_admin_ip, _admin_ip_allowed, _role_denied, _request_username, _require_csrf  # noqa: F401
from integrations.ja4 import _request_ja4, _tls_fingerprint_blocked  # noqa: F401
from integrations.redis import _shared_ban_set  # noqa: F401
from integrations.webhook import _post_webhook  # noqa: F401
from reputation.abuseipdb import _abuseipdb_lookup, _abuseipdb_stats  # noqa: F401
from reputation.maxmind import _asn_lookup, _city_lookup, _asn_stats, _city_reader, _asn_reader  # noqa: F401
from reputation.crowdsec import _crowdsec_check, _crowdsec_stats, _crowdsec_lapi_health  # noqa: F401
from reputation.tor import _tor_exits, _tor_feed_stats  # noqa: F401
from challenge.js_challenge import (  # noqa: F401
    _js_challenge_applicable, _js_challenge_required,
    _make_chal_cookie, _serve_js_challenge,
)
from db.postgres import (  # noqa: F401
    _postgres_load_module, _migrate_recent_events, pg_pool_reset,
    _full_migrate_background, _BG_MIGRATION,
)
from integrations.endpoint_policy import _endpoint_rate_consume  # noqa: F401
from identity import _sign_session, _verify_session, _record_chal_mint, _fp_hash  # noqa: F401
from detection.canary import (  # noqa: F401
    _new_canary, _inject_canary, _inject_honey_links, _inject_botd,
    _botd_token_for, _scan_request_for_canary,
    inject_canary_probe, canary_probe_endpoint, check_canary_probe,
)
from detection.honey_cred import inject_honey_creds, lookup_honey_key  # noqa: F401
import detection.llm_heuristic as _llm_heuristic  # noqa: F401
from detection.automation import _inject_automation_probe  # noqa: F401
from detection.cookie_lifecycle import (  # noqa: F401
    cookie_ghost_check, record_gateway_cookie_set,
    record_html_served, _inject_lifecycle_cookie_script, LIFECYCLE_COOKIE,
)
from detection.referer_chain import referer_ghost_check  # noqa: F401
from detection.impossible_travel import impossible_travel_check  # noqa: F401
from detection.path_sweep import path_sweep_record, path_sweep_check  # noqa: F401
from detection.fp_enrichment import _inject_fp_probe, fp_report_endpoint  # noqa: F401
from challenge.js_challenge import sw_js_endpoint  # noqa: F401
from state import _fp_canvas_store  # noqa: F401
from config import _DATA_PATH, _POW_KEY_FILE, _SESS_KEY_FILE  # noqa: F401
from config import check_always_body, check_verb_override, check_smuggling  # noqa: F401
from config import (check_xxe_body, check_proto_pollution, check_header_ssti,  # noqa: F401
                    check_host_header_injection, check_file_upload)  # noqa: F401
from state import _postgres_available, _redis, _global_rps_window, _pow_seen, _canary_tokens, _asn_path_clusters, _honeypot_ip_clusters, _GW_LOG_RING, events_by_cat, by_path_by_cat  # noqa: F401
from db.sqlite import _SECRET_KEYS  # noqa: F401
from admin.mesh import _gw_local_id  # noqa: F401
from dashboards.service_metrics import _disk_usage  # noqa: F401
from dashboards.controls import GEO_DASHBOARD_HTML, LOGS_DASHBOARD_HTML  # noqa: F401
from detection.paths import _bot_trap_triggered, _inject_bot_trap  # noqa: F401
from identity import _is_library_headers  # noqa: F401
from integrations.endpoint_policy import _endpoint_rule  # noqa: F401
from integrations.jwt import _jwt_required_for, _verify_jwt_hs256  # noqa: F401
from reputation.maxmind import (  # noqa: F401
    _ip_in_ai_range, _locale_geo_mismatch,
    _maxmind_auto_fetch, _maxmind_seed_from_image,
)
from scoring import _save_signal_order, _should_run_signal, _signal_runtime_order  # noqa: F401
from challenge.js_challenge import _ip_tier  # noqa: F401
from db.sqlite import _refresh_integration_state  # noqa: F401


# ── Task J: Probe endpoint rate limiter ───────────────────────────────────────
_PROBE_RL: dict = {}   # ip → [window_start, count]
PROBE_RL_LIMIT  = 20
PROBE_RL_WINDOW = 10.0

# ── 1.8.12: Honeypot fingerprint cross-reference cache ────────────────────────
# Loaded from honey_fingerprints DB table at startup; updated on every new hit.
# Contains JA4 hashes of confirmed-attacker identities (honeypot-silent / honey-cred).
# Used to apply a soft risk bump to future requests sharing the same TLS fingerprint.
_honey_fp_ja4_cache: set = set()

# SH-3 — PoW issue endpoint rate limiter + idempotent cache.
# Prevents CPU exhaustion from rapid challenge-farming (each challenge
# generation is cheap but at scale it adds up; more importantly the endpoint
# must not be used as an oracle to scan for solvable difficulties).
# Rate limit: POW_RL_LIMIT requests per POW_RL_WINDOW seconds per source IP.
# Within the window, the same challenge string is reused (idempotent).
_POW_RL: dict = {}        # ip → [window_start, count]
_POW_CHAL_CACHE: dict = {} # ip → (challenge_str, issued_at)
POW_RL_LIMIT  = int(os.environ.get("POW_ISSUE_RL_LIMIT",  "5"))
POW_RL_WINDOW = float(os.environ.get("POW_ISSUE_RL_WINDOW", "60.0"))


def _probe_rate_limit_ok(ip: str) -> bool:
    import time as _time
    n = _time.monotonic()
    entry = _PROBE_RL.get(ip)
    if entry is None or n - entry[0] > PROBE_RL_WINDOW:
        _PROBE_RL[ip] = [n, 1]
        return True
    if entry[1] >= PROBE_RL_LIMIT:
        return False
    entry[1] += 1
    return True


# ── Task M: Upstream circuit breaker ─────────────────────────────────────────
_UPSTREAM_CB = {
    "fail_count": 0,
    "open_until": 0.0,
    "half_open_attempts": 0,
}
CIRCUIT_FAIL_THRESHOLD = int(os.environ.get("CIRCUIT_FAIL_THRESHOLD", "10"))
CIRCUIT_OPEN_SECS      = int(os.environ.get("CIRCUIT_OPEN_SECS", "30"))
CIRCUIT_HALF_OPEN_MAX  = int(os.environ.get("CIRCUIT_HALF_OPEN_MAX", "3"))


def _circuit_is_open() -> bool:
    import time as _t
    return _t.monotonic() < _UPSTREAM_CB["open_until"]


def _is_auth_path(path: str) -> bool:
    """1.8.6 — True when path matches any configured AUTH_PATHS prefix."""
    from config import AUTH_PATHS
    return any(path == p or path.startswith(p + "/") for p in AUTH_PATHS)


# ── 1.8.6 — DLP Pattern CRUD endpoints ────────────────────────────────────────

async def dlp_patterns_get(request: web.Request):
    """GET /secured/dlp-patterns — list all DLP patterns."""
    if not _internal_authed(request):
        return web.json_response({"error": "auth"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name, pattern, severity, enabled, added_ts, added_by "
            "FROM dlp_patterns ORDER BY id"
        ).fetchall()
        conn.close()
        return web.json_response(
            {"patterns": [dict(r) for r in rows]},
            headers={"Cache-Control": "no-store"})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500,
                                  headers={"Cache-Control": "no-store"})


@_require_csrf
async def dlp_patterns_post(request: web.Request):
    """POST /secured/dlp-patterns — add a new DLP pattern."""
    if not _internal_authed(request):
        return web.json_response({"error": "auth"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    try:
        body = await request.json()
        name     = str(body.get("name", "")).strip()[:100]
        pattern  = str(body.get("pattern", "")).strip()[:2000]
        severity = str(body.get("severity", "high")).strip()
        if not name or not pattern:
            return web.json_response({"error": "name and pattern required"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        if severity not in ("critical", "high", "medium", "low"):
            severity = "high"
        import re as _re
        try:
            _re.compile(pattern)
        except Exception as e:
            return web.json_response({"error": f"invalid regex: {e}"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        actor = _request_username(request)
        if db_queue is not None:
            import time as _t_dlp
            db_queue.put_nowait(("dlp_add", (name, pattern, severity, _t_dlp.time(), actor)))
        return web.json_response({"ok": True}, headers={"Cache-Control": "no-store"})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500,
                                  headers={"Cache-Control": "no-store"})


@_require_csrf
async def dlp_patterns_delete(request: web.Request):
    """DELETE /secured/dlp-patterns?id=<id> — delete a DLP pattern."""
    if not _internal_authed(request):
        return web.json_response({"error": "auth"}, status=401,
                                  headers={"Cache-Control": "no-store"})
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    pid = request.query.get("id", "")
    if not pid:
        return web.json_response({"error": "id required"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    try:
        pid = int(pid)
    except (ValueError, TypeError):
        return web.json_response({"error": "invalid id"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    if db_queue is not None:
        db_queue.put_nowait(("dlp_delete", (pid,)))
    return web.json_response({"ok": True}, headers={"Cache-Control": "no-store"})


def _circuit_record_failure() -> None:
    import time as _t
    _UPSTREAM_CB["fail_count"] += 1
    if _UPSTREAM_CB["fail_count"] >= CIRCUIT_FAIL_THRESHOLD:
        _UPSTREAM_CB["open_until"] = _t.monotonic() + CIRCUIT_OPEN_SECS
        _UPSTREAM_CB["half_open_attempts"] = 0
        slog("upstream_circuit_open", level="warn",
             fails=_UPSTREAM_CB["fail_count"], open_secs=CIRCUIT_OPEN_SECS)


def _circuit_record_success() -> None:
    _UPSTREAM_CB["fail_count"] = 0
    _UPSTREAM_CB["open_until"] = 0.0
    _UPSTREAM_CB["half_open_attempts"] = 0


STRICT_ORIGIN = os.environ.get("STRICT_ORIGIN", "0") in ("1", "true", "yes")
_OPEN_ORIGIN_PATHS_RAW = os.environ.get("OPEN_ORIGIN_PATHS", "").strip()
OPEN_ORIGIN_PATHS = [p.strip() for p in _OPEN_ORIGIN_PATHS_RAW.split(",") if p.strip()]

_REQUIRED_HEADERS_RAW = os.environ.get("REQUIRED_HEADERS", "").strip()
REQUIRED_HEADERS = [h.strip() for h in _REQUIRED_HEADERS_RAW.split(",") if h.strip()]


def _origin_check_failed(request) -> bool:
    """Returns True iff STRICT_ORIGIN is on AND the request fails the check."""
    if not STRICT_ORIGIN:
        return False
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return False
    if any(request.path.startswith(p) for p in OPEN_ORIGIN_PATHS):
        return False
    origin = request.headers.get("Origin", "").strip()
    if not origin:
        return True   # missing Origin on a state-change → reject
    try:
        from urllib.parse import urlparse
        host = (urlparse(origin).netloc or "").split(":", 1)[0].lower()
    except Exception:
        return True
    if not ALLOWED_HOSTS:
        return False  # nothing to compare against; let it through
    return host not in ALLOWED_HOSTS


def _missing_required_header(request) -> bool:
    if not REQUIRED_HEADERS:
        return False
    if _is_admin_path(request.path):
        return False
    if request.path.endswith((
            ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif",
            ".svg", ".webp", ".avif", ".ico", ".woff", ".woff2",
            ".ttf", ".otf", ".eot", ".map")):
        return False
    return any(h not in request.headers for h in REQUIRED_HEADERS)


def _city_reader_is_loaded() -> bool:
    """Return True iff a MaxMind city reader is available in any known location.
    Checked in priority order: proxy module globals (test patches land here),
    then reputation.maxmind module, then this module's own _city_reader global.
    This avoids the lambda-captures-globals() problem where the validator
    only sees its defining module's namespace."""
    import sys
    # 1. Test patches / hot-reload knobs set it on proxy.
    _proxy = sys.modules.get("proxy")
    if _proxy is not None and getattr(_proxy, "_city_reader", None) is not None:
        return True
    # 2. Normal runtime: reputation.maxmind owns the reader.
    _mm = sys.modules.get("reputation.maxmind")
    if _mm is not None and getattr(_mm, "_city_reader", None) is not None:
        return True
    # 3. Fallback: check this module's own global (set by maxmind_fetch_endpoint).
    return globals().get("_city_reader") is not None


# ── Proxy constants ────────────────────────────────────────────────────────
# F3: tighten default to the safe-for-WAF set. Operators who proxy a REST API
# can opt-in via env (e.g. ALLOWED_METHODS=GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS).
_ALLOWED_METHODS_DEFAULT = "GET,HEAD,POST,OPTIONS"
ALLOWED_METHODS = {
    m.strip().upper()
    for m in os.environ.get("ALLOWED_METHODS", _ALLOWED_METHODS_DEFAULT).split(",")
    if m.strip()
}

# F1: optional Host header allowlist. Comma-sep hostnames; default empty
# (no enforcement, current behaviour). When set, Host headers outside the
# list get silent-decoyed at Layer 0 — defends against host-header attacks
# at OUR gate (in addition to the existing X-Forwarded-Host overwrite).
_allowed_hosts_raw = os.environ.get("ALLOWED_HOSTS", "").strip()
ALLOWED_HOSTS = _to_host_set(_allowed_hosts_raw) if _allowed_hosts_raw else set()

# Hop-by-hop headers (RFC 7230 §6.1) + ones the proxy must own.
HOP_BY_HOP_REQUEST = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "upgrade",
    # Path-rewrite / source-IP spoof headers — proxy sets its own values below.
    "x-forwarded-for", "x-real-ip", "x-forwarded-host", "x-forwarded-proto",
    "x-original-url", "x-rewrite-url", "x-original-host",
    "x-admin-key",  # never forward operator credential
}
HOP_BY_HOP_RESPONSE = {
    "transfer-encoding", "content-encoding", "content-length", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "upgrade",
}

UPSTREAM_MAX_BODY = int(os.environ.get("UPSTREAM_MAX_BODY", str(4 * 1024 * 1024)))  # 4 MiB
UPSTREAM_MAX_RESP = int(os.environ.get("UPSTREAM_MAX_RESP", str(17 * 1024 * 1024)))  # 17 MiB

# 1.8.11 (H1): if the WAF body-scan window is smaller than the body we accept
# and forward, an attacker can hide a payload past the scanned prefix. Warn so
# the operator notices the gap (defaults are equal, so this never fires unless
# UPSTREAM_MAX_BODY is raised without raising WAF_BODY_SCAN_BYTES).
if WAF_BODY_SCAN_BYTES < UPSTREAM_MAX_BODY:
    slog("waf_body_scan_window_too_small", level="warn",
         scan_bytes=WAF_BODY_SCAN_BYTES, max_body=UPSTREAM_MAX_BODY,
         note="payloads past the scan window bypass the body WAF; "
              "raise WAF_BODY_SCAN_BYTES to >= UPSTREAM_MAX_BODY")

_CF_TURNSTILE_ORIGIN = "https://challenges.cloudflare.com"

def _csp_inject_cf_turnstile(csp: str) -> str:
    """Add Cloudflare Turnstile origin to script-src and frame-src in an
    upstream Content-Security-Policy header so upstream Turnstile widgets
    (and the gateway's own challenge iframe) are not blocked by a
    restrictive upstream policy."""
    if _CF_TURNSTILE_ORIGIN in csp:
        return csp
    out = []
    injected_script = False
    injected_frame = False
    default_idx = None
    parts = csp.split(";")
    for i, part in enumerate(parts):
        s = part.strip().lower()
        if s.startswith("script-src ") or s == "script-src":
            part = part.rstrip() + " " + _CF_TURNSTILE_ORIGIN
            injected_script = True
        elif s.startswith("frame-src ") or s == "frame-src":
            part = part.rstrip() + " " + _CF_TURNSTILE_ORIGIN
            injected_frame = True
        elif s.startswith("default-src ") or s == "default-src":
            default_idx = i
        out.append(part)
    # When script-src / frame-src are absent, default-src governs them.
    # Augment default-src so those missing directives inherit the origin.
    if (not injected_script or not injected_frame) and default_idx is not None:
        out[default_idx] = out[default_idx].rstrip() + " " + _CF_TURNSTILE_ORIGIN
    return ";".join(out)


# ── v1.4: Slowloris guard (default ON with sensible timeouts) ────────────
HEADERS_TIMEOUT = float(os.environ.get("HEADERS_TIMEOUT", "10"))   # secs to receive full headers
BODY_TIMEOUT    = float(os.environ.get("BODY_TIMEOUT",    "30"))   # secs to receive full body

# ── App debug ───────────────────────────────────────────────────────────────
DEBUG_ENABLED = os.environ.get("DEBUG", "0") not in ("", "0", "false", "False", "no")
_REDACT_HEADERS = {"cookie", "authorization", "x-admin-key", "x-pow-token", "x-pow-solution"}


# ── Silent decoy: serves upstream / contents to banned attackers ───────────
# Cache also stores the upstream's HTTP status so the decoy mirrors it. A
# previous design hard-coded 200 OK while serving the upstream's 404 body —
# that status/content mismatch was a clean fingerprint for an agent to
# detect blocked vs forwarded responses. We now match upstream verbatim.
_decoy_cache = {"body": None, "ctype": None, "status": 200, "fetched_at": 0.0}
_DECOY_TTL = 60.0  # cache the homepage for 60s

# 1.5.4: upstream 404 mirror — blocked admin endpoints serve the upstream's
# real 404 page so the gateway is indistinguishable from "this path doesn't
# exist on the upstream". Refreshed hourly.
_upstream_404_cache = {
    "body":   None,
    "ctype":  "text/plain; charset=utf-8",
    "status": 404,
    "fetched_at": 0.0,
}
_UPSTREAM_404_TTL = 3600  # 1 h


async def _fetch_upstream_404() -> bool:
    """GET a guaranteed-non-existent path from upstream and cache the
    response. Returns True on success."""
    probe = f"/__appsecgw-probe-{secrets.token_hex(8)}"
    try:
        timeout = ClientTimeout(total=5)
        async with ClientSession(timeout=timeout) as session:
            async with session.get(UPSTREAM + probe,
                                    allow_redirects=False) as resp:
                _upstream_404_cache["body"]   = await resp.read()
                _upstream_404_cache["ctype"]  = resp.headers.get(
                    "Content-Type", "text/html; charset=utf-8")
                # Preserve actual upstream status (almost always 404; some
                # apps return 200 with an error template — we mirror).
                _upstream_404_cache["status"] = resp.status
                _upstream_404_cache["fetched_at"] = _t.time()
                return True
    except Exception as e:
        slog("upstream-404-fetch-failed", level="warn", error=str(e)[:120])
        return False


async def _periodic_404_refresh_loop():
    """Refresh the cached upstream 404 hourly."""
    while True:
        try:
            await asyncio.sleep(_UPSTREAM_404_TTL)
            await _fetch_upstream_404()
        except asyncio.CancelledError:
            break
        except Exception as e:
            slog("upstream-404-refresh-error", level="warn", error=str(e)[:120])


async def _serve_mirrored_404() -> web.Response:
    """Serve a 404 that matches the upstream's 404 page. On first call (cache
    cold) the upstream is fetched synchronously; on cache miss/expiry the
    serving path uses whatever's cached and a background refresh kicks in."""
    n = _t.time()
    if (not _upstream_404_cache.get("body")
            or n - _upstream_404_cache.get("fetched_at", 0) > _UPSTREAM_404_TTL):
        await _fetch_upstream_404()
    body   = _upstream_404_cache.get("body") or b"Not Found\n"
    ctype  = _upstream_404_cache.get("ctype") or "text/plain"
    status = _upstream_404_cache.get("status") or 404
    return web.Response(status=status, body=body, headers={
        "Content-Type": ctype,
        "Cache-Control": "no-store",
    })


_decoy_fetch_lock = asyncio.Lock()


async def _silent_decoy_response(ip: str, ua: str, path: str, reason: str,
                                  track_key: str = None, sid: str = "",
                                  fp: str = "", ja4: str = "",
                                  request_id: str = ""):
    """
    Stealth response for blocked clients.
    Returns upstream's `/` content with upstream's actual status code, so a
    blocked request looks indistinguishable from a forwarded request that
    happened to land on `/`. The block IS still recorded under the hybrid
    identity (track_key), keyed on the cookie+fingerprint so a single bad
    actor in a NAT pool doesn't poison all peers.
    1.6.5 — also bumps the per-reason hit/latency telemetry consumed by
    the Dashboard / Agents / Service surfaces.
    """
    import time
    _decoy_t0 = time.perf_counter()
    n = _t.time()
    # N2: serialize the upstream fetch — many concurrent blocked requests
    # mustn't fan out a thundering herd. Double-check inside the lock.
    if not _decoy_cache["body"] or (n - _decoy_cache["fetched_at"]) > _DECOY_TTL:
        async with _decoy_fetch_lock:
            n = _t.time()
            if not _decoy_cache["body"] or (n - _decoy_cache["fetched_at"]) > _DECOY_TTL:
                try:
                    async with ClientSession(timeout=ClientTimeout(total=10)) as session:
                        async with session.get(UPSTREAM + "/", allow_redirects=False) as resp:
                            _decoy_cache["body"] = await resp.read()
                            _decoy_cache["ctype"] = resp.headers.get("Content-Type", "text/html; charset=utf-8")
                            _decoy_cache["status"] = resp.status
                            _decoy_cache["fetched_at"] = n
                except Exception:
                    _decoy_cache["body"] = (
                        b"<!doctype html><html><head><title>Welcome</title></head>"
                        b"<body><h1>Welcome</h1><p>Service operational.</p></body></html>"
                    )
                    _decoy_cache["ctype"] = "text/html; charset=utf-8"
                    _decoy_cache["status"] = 200
                    _decoy_cache["fetched_at"] = n
    decoy_status = int(_decoy_cache.get("status") or 200)

    # ── Route-aware decoy body selection ────────────────────────────────────
    # Returning the identical cached homepage for every blocked path (API
    # endpoints, admin paths, SQLi probes, etc.) produces a uniform
    # body-hash fingerprint that automated scanners trivially detect as a
    # catch-all gate.  Instead, serve a path-appropriate synthetic response
    # so blocked requests look indistinguishable from a real upstream that
    # simply doesn't have that path:
    #   • API / JSON paths → synthetic JSON 404 (not the HTML homepage)
    #   • Admin / dot paths → synthetic JSON 404
    #   • Everything else   → homepage (existing behaviour)
    # Synthetic bodies are used (not _upstream_404_cache) because the cache
    # content is controlled by the upstream and may carry its own fingerprint.
    _decoy_body  = _decoy_cache["body"]
    _decoy_ctype = _decoy_cache["ctype"]
    _path = path or "/"
    _looks_like_api = (
        _path.startswith("/api/") or
        _path.startswith("/v1/") or _path.startswith("/v2/") or
        "/api/" in _path or
        _path.endswith(".json") or _path.endswith(".xml")
    )
    _looks_like_admin = (
        _path.startswith("/admin") or _path.startswith("/management") or
        _path.startswith("/.") or _path.startswith("/actuator") or
        _path.startswith("/debug") or _path.startswith("/console") or
        _path.startswith("/internal")
    )
    if _looks_like_api or _looks_like_admin:
        _decoy_body  = b'{"error":"not found","status":404}'
        _decoy_ctype = "application/json"
        decoy_status = 404

    await record(ip, ua, path, decoy_status, reason, track_key=track_key, sid=sid,
                 fp=fp, ja4=ja4, request_id=request_id)
    # 1.6.5 — TARPIT mitigation: identities in the soft-challenge band
    # (between SOFT_CHALLENGE_SCORE and RISK_BAN_THRESHOLD) get a
    # configurable delay before the silent-decoy response. Burns attacker
    # iteration time without committing to a ban. Skipped for the
    # requester's first contact (no track_key yet) so legitimate cold
    # browsers aren't tarpitted.
    if TARPIT_ENABLED and TARPIT_DELAY_MS > 0 and track_key:
        s = ip_state.get(track_key)
        if s is not None:
            try:
                _decay_risk(s, _t.time())
                if (SOFT_CHALLENGE_SCORE > 0 and
                        SOFT_CHALLENGE_SCORE <= s.risk_score < RISK_BAN_THRESHOLD):
                    await asyncio.sleep(TARPIT_DELAY_MS / 1000.0)
            except Exception:
                pass
    # 1.6.5 — per-detector hit + latency telemetry. Drives the Dashboard
    # "Top methods", Agents "rule inventory" and Service "detector latency"
    # surfaces. Cheap (deque append + dict bump).
    _detector_record(reason, (time.perf_counter() - _decoy_t0) * 1000.0)
    if reason == "chal-required":
        global _chal_required_count
        _chal_required_count += 1
        # Increment challenged counter in the current timeline bucket
        try:
            from core.metrics import _bucket_now as _bn
            _cb = _bn()
            if _cb in timeline:
                _tb = timeline[_cb]
                if "challenged" not in _tb:
                    _tb["challenged"] = 0
                _tb["challenged"] += 1
        except Exception:
            pass
    headers = {
        "Content-Type": _decoy_ctype,
        "Cache-Control": "no-store",
    }
    if request_id:
        headers[_REQUEST_ID_HEADER] = request_id
    return web.Response(
        status=decoy_status,
        body=_decoy_body,
        headers=headers,
    )


# ── WebSocket + main proxy ─────────────────────────────────────────────────

def _is_ws_upgrade(request: web.Request) -> bool:
    return (request.headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in request.headers.get("Connection", "").lower())


async def proxy_websocket(request: web.Request):
    """Bidirectional WebSocket bridge to upstream. Headers/cookies/origin
    rewrites match the HTTP path; aiohttp manages the Sec-WebSocket-* dance."""
    from urllib.parse import urlparse
    _vc_upstream = vc('UPSTREAM'); u = urlparse(_vc_upstream)
    upstream_host = u.netloc
    upstream_scheme_host = f"{u.scheme}://{u.netloc}"
    ws_scheme = "wss" if u.scheme == "https" else "ws"
    target = f"{ws_scheme}://{upstream_host}{_strip_admin_key_from_qs(request.path_qs)}"

    fwd_headers = {}
    for k, v in request.headers.items():
        kl = k.lower()
        # Hop-by-hop + WS-specific (aiohttp client sets its own).
        if kl in HOP_BY_HOP_REQUEST or kl.startswith("sec-websocket"):
            continue
        if kl == "cookie":
            cleaned = _strip_own_session_cookie(v)
            if cleaned:
                fwd_headers[k] = cleaned
            continue
        if kl == "origin":
            fwd_headers[k] = upstream_scheme_host
            continue
        if kl == "referer":
            try:
                rp = urlparse(v)
                if rp.scheme and rp.netloc:
                    new_ref = upstream_scheme_host + (rp.path or "/")
                    if rp.query:
                        new_ref += "?" + rp.query
                    fwd_headers[k] = new_ref
                    continue
            except Exception:
                pass
        fwd_headers[k] = v

    gw_ip = get_ip(request)
    fwd_headers["X-Forwarded-For"] = gw_ip
    fwd_headers["X-Real-IP"] = gw_ip
    fwd_headers["X-Forwarded-Proto"] = "https" if request.secure else "http"
    if request.host:
        fwd_headers["X-Forwarded-Host"] = request.host

    # Sub-protocol negotiation (e.g. STOMP, GraphQL-WS).
    proto_hdr = request.headers.get("Sec-WebSocket-Protocol", "")
    protocols = tuple(p.strip() for p in proto_hdr.split(",") if p.strip())

    ws_server = web.WebSocketResponse(protocols=protocols, heartbeat=30, autoping=True)
    await ws_server.prepare(request)

    try:
        async with ClientSession(timeout=ClientTimeout(total=None, sock_connect=10)) as session:
            async with session.ws_connect(
                target, headers=fwd_headers, protocols=protocols,
                heartbeat=30, autoping=True, max_msg_size=4 * 1024 * 1024,
            ) as ws_client:
                async def srv_to_up():
                    async for msg in ws_server:
                        t = msg.type
                        if t == aiohttp.WSMsgType.TEXT:
                            await ws_client.send_str(msg.data)
                        elif t == aiohttp.WSMsgType.BINARY:
                            await ws_client.send_bytes(msg.data)
                        elif t in (aiohttp.WSMsgType.CLOSE,
                                   aiohttp.WSMsgType.CLOSING,
                                   aiohttp.WSMsgType.CLOSED,
                                   aiohttp.WSMsgType.ERROR):
                            return
                async def up_to_srv():
                    async for msg in ws_client:
                        t = msg.type
                        if t == aiohttp.WSMsgType.TEXT:
                            await ws_server.send_str(msg.data)
                        elif t == aiohttp.WSMsgType.BINARY:
                            await ws_server.send_bytes(msg.data)
                        elif t in (aiohttp.WSMsgType.CLOSE,
                                   aiohttp.WSMsgType.CLOSING,
                                   aiohttp.WSMsgType.CLOSED,
                                   aiohttp.WSMsgType.ERROR):
                            return
                done, pending = await asyncio.wait(
                    [asyncio.create_task(srv_to_up()),
                     asyncio.create_task(up_to_srv())],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in pending:
                    t.cancel()
    except aiohttp.WSServerHandshakeError as e:
        if not ws_server.closed:
            await ws_server.close(code=1011,
                                  message=f"upstream handshake: {e.status}".encode())
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        if not ws_server.closed:
            await ws_server.close(code=1011, message=str(e)[:120].encode())
    finally:
        if not ws_server.closed:
            await ws_server.close()
    return ws_server


async def proxy(request: web.Request):
    # WebSocket upgrade — bridge to upstream.
    if _is_ws_upgrade(request):
        return await proxy_websocket(request)

    # M2: method allowlist — block TRACE/CONNECT/anything unusual.
    if request.method not in ALLOWED_METHODS:
        return web.Response(status=405, text="method not allowed\n")

    # 1.8.6 — HTTP smuggling signal detection; 1.8.9 — gated by WAF_SMUGGLING_ENABLED
    if WAF_SMUGGLING_ENABLED:
        _smuggling_signal = check_smuggling(request)
        if _smuggling_signal:
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                _smuggling_signal, get_ip(request))
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, _smuggling_signal,
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

    # 1.8.6 — verb override detection; 1.8.9 — gated by WAF_VERB_OVERRIDE_ENABLED
    if WAF_VERB_OVERRIDE_ENABLED and check_verb_override(request):
        await update_risk_and_maybe_ban(
            request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
            "method-override-attempt", get_ip(request))
        return await _silent_decoy_response(
            get_ip(request), request.headers.get("User-Agent", ""),
            request.path, "method-override-attempt",
            track_key=request.get("_track_key"),
            sid=request.get("_sid", ""),
            fp=request.get("_fp", ""))

    # 1.8.6 Week 3 — Task C: SSTI in attacker-controlled headers; 1.8.9 — gated by WAF_HEADER_INJECTION_ENABLED
    if WAF_HEADER_INJECTION_ENABLED and check_header_ssti(request):
        await update_risk_and_maybe_ban(
            request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
            "header-ssti", get_ip(request))
        return await _silent_decoy_response(
            get_ip(request), request.headers.get("User-Agent", ""),
            request.path, "header-ssti",
            track_key=request.get("_track_key"),
            sid=request.get("_sid", ""),
            fp=request.get("_fp", ""))

    # 1.8.6 Week 4 — Task G: Host header injection; 1.8.9 — gated by WAF_HEADER_INJECTION_ENABLED
    if WAF_HEADER_INJECTION_ENABLED and check_host_header_injection(request):
        await update_risk_and_maybe_ban(
            request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
            "host-header-injection", get_ip(request))
        return await _silent_decoy_response(
            get_ip(request), request.headers.get("User-Agent", ""),
            request.path, "host-header-injection",
            track_key=request.get("_track_key"),
            sid=request.get("_sid", ""),
            fp=request.get("_fp", ""))

    _vc_upstream = vc('UPSTREAM'); target = _vc_upstream + _strip_admin_key_from_qs(request.path_qs)

    # C3 + H5: build forwarded headers from an allowlist-by-exclusion list.
    # All hop-by-hop and source-spoof headers stripped. Cookie has our own
    # SESSION_COOKIE removed before forwarding so signed token never leaves us.
    fwd_headers = {}
    for k, v in request.headers.items():
        kl = k.lower()
        if kl in HOP_BY_HOP_REQUEST:
            continue
        if kl == "cookie":
            cleaned = _strip_own_session_cookie(v)
            if cleaned:
                fwd_headers[k] = cleaned
            continue
        fwd_headers[k] = v

    # Re-assert source-IP semantics: replace any client-supplied XFF with our
    # gateway-computed IP (defends against ACL bypass on backends that trust XFF).
    gw_ip = get_ip(request)
    fwd_headers["X-Forwarded-For"] = gw_ip
    fwd_headers["X-Real-IP"] = gw_ip
    fwd_headers["X-Forwarded-Proto"] = request.scheme or "http"
    if request.host:
        fwd_headers["X-Forwarded-Host"] = request.host

    # Rewrite Origin / Referer / Host so upstream's CSRF / origin-validation
    # sees its own canonical origin instead of the gateway's public hostname.
    # Without this, upstream reverse-proxy aware backends (Keycloak, UFE) 403
    # CORS preflight + auth POSTs because Origin != upstream's expected scheme://host.
    upstream_origin = _vc_upstream.rstrip("/")
    try:
        from urllib.parse import urlparse
        u = urlparse(upstream_origin)
        upstream_host = u.netloc
        upstream_scheme_host = f"{u.scheme}://{u.netloc}"
    except Exception:
        upstream_host, upstream_scheme_host = "", upstream_origin

    if upstream_host:
        # Host header MUST match upstream's expected vhost or TLS SNI fails / wrong vhost served.
        fwd_headers["Host"] = upstream_host
        if "origin" in {k.lower() for k in fwd_headers}:
            for k in list(fwd_headers):
                if k.lower() == "origin":
                    fwd_headers[k] = upstream_scheme_host
        if "referer" in {k.lower() for k in fwd_headers}:
            # Replace client-side scheme://host prefix with upstream's, keep the path
            for k in list(fwd_headers):
                if k.lower() == "referer":
                    ref = fwd_headers[k]
                    try:
                        rp = urlparse(ref)
                        if rp.scheme and rp.netloc:
                            new_ref = upstream_scheme_host + (rp.path or "/")
                            if rp.query:
                                new_ref += "?" + rp.query
                            fwd_headers[k] = new_ref
                    except Exception:
                        pass

    # H6+v1.4: stream the body, bound it, AND apply a slowloris timeout.
    # Reject if larger than UPSTREAM_MAX_BODY or if it takes longer than
    # BODY_TIMEOUT to fully arrive.
    # 1.6.5 — slow body now surfaces a discrete `slow-client` reason via
    # the silent-decoy path, so the dashboards count it like any other
    # detector and the operator sees how many requests stalled out.
    body = None
    if request.body_exists and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            async def _drain():
                chunks = []
                total = 0
                async for c in request.content.iter_any():
                    total += len(c)
                    if total > UPSTREAM_MAX_BODY:
                        raise web.HTTPRequestEntityTooLarge(
                            max_size=UPSTREAM_MAX_BODY, actual_size=total)
                    chunks.append(c)
                return b"".join(chunks) if chunks else None
            body = await asyncio.wait_for(_drain(), timeout=BODY_TIMEOUT)
        except asyncio.TimeoutError:
            # 1.6.5 — bump risk + surface as 'slow-client'. Silent decoy
            # so the attacker can't distinguish a slowloris-block from any
            # other 200/404 path. The risk model decides whether to ban.
            # 1.8.9 — gated by WAF_SLOWLORIS_ENABLED; off = plain 408 (no risk bump, no decoy).
            _ip = get_ip(request)
            _ua = request.headers.get("User-Agent", "")
            _tk = request.get("_track_key")
            if not WAF_SLOWLORIS_ENABLED:
                return web.Response(status=408, text="request timeout\n")
            if _tk:
                await update_risk_and_maybe_ban(_tk, "slow-client", _ip)
            return await _silent_decoy_response(
                _ip, _ua, request.path, "slow-client",
                track_key=_tk,
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""),
                ja4=_request_ja4(request),
                request_id=request.get("_rid", ""))
        except web.HTTPRequestEntityTooLarge:
            return web.Response(status=413, text="payload too large\n")
        except Exception:
            return web.Response(status=400, text="bad request\n")

    # 1.8.6 — ungated first-touch check: high-confidence patterns that bypass
    # the escalation threshold. Catches first-request injections (Log4Shell, SQLi).
    # 1.8.9 — gated by WAF_BODY_ENABLED (set to 0 to suppress false positives
    # on legitimate search/API endpoints whose payloads match these patterns).
    if WAF_BODY_ENABLED and body is not None:
        client_ctype = request.headers.get("Content-Type", "")
        if check_always_body(body, client_ctype):
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                "body-critical-injection", get_ip(request))
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, "body-critical-injection",
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

    # 1.8.6 Week 3 — Task A: XXE detection (ungated, XML-gated)
    if WAF_BODY_ENABLED and body is not None:
        client_ctype = request.headers.get("Content-Type", "")
        if check_xxe_body(body, client_ctype):
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                "body-xxe", get_ip(request))
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, "body-xxe",
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

    # 1.8.6 Week 3 — Task B: Prototype pollution detection
    if WAF_BODY_ENABLED and body is not None:
        client_ctype = request.headers.get("Content-Type", "")
        if check_proto_pollution(body, client_ctype):
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                "body-proto-pollution", get_ip(request))
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, "body-proto-pollution",
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

    # 1.8.6 Week 4 — Task H: GraphQL protection; 1.8.9 — gated by WAF_GRAPHQL_ENABLED
    if WAF_GRAPHQL_ENABLED and body is not None:
        client_ctype = request.headers.get("Content-Type", "")
        from detection.graphql import check_graphql
        for _gql_sig in check_graphql(request.path, body, client_ctype):
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                _gql_sig, get_ip(request))
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, _gql_sig,
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

    # 1.8.6 Week 4 — Task I: File upload content validation; 1.8.9 — gated by WAF_UPLOAD_ENABLED
    if WAF_UPLOAD_ENABLED and body is not None:
        client_ctype = request.headers.get("Content-Type", "")
        _upload_sig = check_file_upload(body, client_ctype)
        if _upload_sig:
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                _upload_sig, get_ip(request))
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, _upload_sig,
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

    # v1.4 #4 — body pattern matching (extends Layer 3 to bodies).
    # 1.6.1 — managed groups fire FIRST (per-group reason); the legacy
    # blanket `suspicious-body` is the catch-all for anything not covered
    # by a group OR when all groups are toggled off.
    # 1.6.10 — body scans are 3rd-order (escalate-only): re-read the
    # current score because protect() has already accumulated any 1st/2nd
    # order hits for this request. ESCALATION_THRESHOLD=0 disables the gate.
    _proxy_esc = (ESCALATION_THRESHOLD <= 0) or (
        _escalation_score(request.get("_track_key") or request.remote or "0.0.0.0")  # nosec B104
        >= ESCALATION_THRESHOLD
    )
    if body is not None and _proxy_esc:
        client_ctype = request.headers.get("Content-Type", "")
        _matched_group = match_body_group(body, client_ctype)
        if _matched_group:
            _reason = f"body-{_matched_group}"
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                _reason, get_ip(request))
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, _reason,
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))
        if is_suspicious_body(body, client_ctype):
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                "suspicious-body", get_ip(request))   # L1: was "suspicious-path"
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, "suspicious-body",
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

        # R7: also scan POST/PUT bodies for echoed canaries — LLM agents
        # frequently splice prior-response text into the new prompt, which
        # then becomes the request body.
        if CANARY_ECHO_DETECTION:
            echoed = _scan_request_for_canary(request, body_bytes=body)
            if echoed:
                await update_risk_and_maybe_ban(
                    request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                    "canary-echo", get_ip(request))
                return await _silent_decoy_response(
                    get_ip(request), request.headers.get("User-Agent", ""),
                    request.path, "canary-echo",
                    track_key=request.get("_track_key"),
                    sid=request.get("_sid", ""),
                    fp=request.get("_fp", ""))

        # v1.4 #6 — bot-trap form fields (multiple decoys since 1.5.4)
        _trap_hit, _trap_field = _bot_trap_triggered(body, client_ctype)
        if _trap_hit:
            slog("bot-trap-hit", level="warn",
                 rid=request.get("_rid", ""), field=_trap_field,
                 ip=get_ip(request))
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",  # nosec B104
                "bot-trap", get_ip(request))
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, "bot-trap",
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

    # 1.8.6 Week 4 — Task M: Circuit breaker: bail early if upstream is known-failing
    if _circuit_is_open():
        _UPSTREAM_CB["half_open_attempts"] += 1
        if _UPSTREAM_CB["half_open_attempts"] > CIRCUIT_HALF_OPEN_MAX:
            return web.Response(status=503, text="upstream circuit open\n",
                                headers={"Retry-After": str(CIRCUIT_OPEN_SECS)})
        # Half-open: allow this probe through

    try:
        async with ClientSession(timeout=ClientTimeout(total=30)) as session:
            async with session.request(
                request.method, target, headers=fwd_headers, data=body,
                allow_redirects=False,
            ) as resp:
                # H6: bound the upstream response body too — defends the proxy
                # itself against a malicious upstream sending unbounded data.
                # Stream-read in chunks so we don't truncate (a single
                # `read(N)` returns only what's in the buffer at that moment).
                chunks = []
                total = 0
                async for chunk in resp.content.iter_any():
                    total += len(chunk)
                    if total > UPSTREAM_MAX_RESP:
                        # 1.8.11: 413 Content Too Large (was 502) — the upstream
                        # responded fine; we refuse to relay because the body
                        # exceeds UPSTREAM_MAX_RESP. 413 distinguishes this size
                        # limit from a genuine upstream/gateway failure (502).
                        return web.Response(status=413,
                                            text="upstream response too large\n")
                    chunks.append(chunk)
                resp_body = b"".join(chunks)

                # 1.6.2 — Tier C: outbound DLP scan. Looks for sensitive
                # data leaving the upstream (PII / credentials / tokens).
                # Records `dlp-<group>` events and optionally redacts
                # matches before forwarding. Off by default (DLP_ENABLED=1).
                if DLP_ENABLED:
                    _dlp_ctype = resp.headers.get("Content-Type", "")
                    _dlp_hits = dlp_scan(resp_body, _dlp_ctype)
                    if _dlp_hits:
                        _ip = get_ip(request)
                        _ua = request.headers.get("User-Agent", "")
                        _hit_groups = sorted({h[0] for h in _dlp_hits})
                        for _grp in _hit_groups:
                            await record(_ip, _ua, request.path, resp.status,
                                         f"dlp-{_grp}",
                                         track_key=request.get("_track_key"),
                                         sid=request.get("_sid", ""),
                                         fp=request.get("_fp", ""),
                                         request_id=request.get("_rid", ""))
                        if WEBHOOK_URL:
                            asyncio.create_task(_post_webhook({
                                "event":  "dlp_leak",
                                "ts":     _t.time(),
                                "ip":     _ip,
                                "path":   request.path,
                                "status": resp.status,
                                "groups": _hit_groups,
                                "count":  len(_dlp_hits),
                                "redacted": DLP_REDACT,
                            }))
                        if DLP_REDACT:
                            resp_body = dlp_redact(resp_body, _dlp_hits)

                # L4: complete hop-by-hop response strip. Use a multidict so
                # repeated headers (notably Set-Cookie) survive intact.
                from multidict import CIMultiDict
                response_headers = CIMultiDict()
                from urllib.parse import urlparse as _urlparse
                up_parsed = _urlparse(_vc_upstream)
                client_scheme = (request.headers.get("X-Forwarded-Proto")
                                 or ("https" if request.secure else "http"))
                # PROXY4-02: validate Host header against ALLOWED_HOSTS before
                # using it in Location rewrites — prevents open-redirect via
                # attacker-controlled Host header.
                _req_host = (request.host or "").split(":")[0].lower()
                if ALLOWED_HOSTS and _req_host not in ALLOWED_HOSTS:
                    client_host = up_parsed.netloc
                else:
                    client_host = request.host or up_parsed.netloc

                for k, v in resp.headers.items():
                    kl = k.lower()
                    if kl in HOP_BY_HOP_RESPONSE:
                        continue

                    # Rewrite Location header in 3xx redirects so the browser
                    # always comes back through the gateway — both same-domain
                    # and cross-domain upstreams (e.g. upstream that 301s to a
                    # different hostname). Embedded upstream-URL references in
                    # OAuth redirect_uri params are also rewritten.
                    if kl == "location" and 300 <= resp.status < 400:
                        try:
                            lp = _urlparse(v)
                            if lp.scheme and lp.netloc:
                                # Always rewrite scheme+host to the gateway's inbound
                                # hostname; preserve path / query / fragment.
                                rewritten = f"{client_scheme}://{client_host}{lp.path or ''}"
                                if lp.query:    rewritten += "?" + lp.query
                                if lp.fragment: rewritten += "#" + lp.fragment
                                v = rewritten
                            # Also rewrite any embedded upstream-origin references
                            # in the (possibly already-rewritten) value so that
                            # OAuth redirect_uri params point back through the gateway.
                            if up_parsed.netloc:
                                up_url_raw = f"{up_parsed.scheme}://{up_parsed.netloc}"
                                gw_url_raw = f"{client_scheme}://{client_host}"
                                from urllib.parse import quote as _q
                                v = v.replace(up_url_raw, gw_url_raw)
                                v = v.replace(_q(up_url_raw, safe=""),
                                              _q(gw_url_raw, safe=""))
                                v = v.replace(_q(up_url_raw, safe=":/"),
                                              _q(gw_url_raw, safe=":/"))
                        except Exception:
                            pass

                    # SSO flow #2: strip the Domain= attribute from Set-Cookie
                    # — without this the browser rejects upstream-domain-scoped
                    # cookies when it's actually visiting our gateway hostname.
                    if kl == "set-cookie":
                        v = re.sub(r";\s*[Dd]omain=[^;]+", "", v)

                    response_headers.add(k, v)

                response_headers["X-Proxy"] = GW_VERSION

                # Inject baseline security response headers on HTML responses
                # (the upstream may not set them; we add them at the edge so
                # browser-side defenses kick in).  Each header can be disabled
                # individually via env or overridden by an upstream value
                # already present in the response.
                ctype = response_headers.get("Content-Type", "").lower().lstrip()
                if ctype.startswith("text/html") and INJECT_SECURITY_HEADERS:
                    for hk, hv in SECURITY_HEADERS.items():
                        if hv and hk.lower() not in {k.lower() for k in response_headers}:
                            response_headers[hk] = hv

                # ── Unconditional upstream-address scrub (M-SEC-1) ───────────
                # The upstream origin (scheme://netloc and bare netloc) must
                # NEVER appear in any response delivered to the client.  This
                # is enforced here regardless of UPSTREAM_REWRITE_BASE so that
                # the protection is always active, not opt-in.
                #
                # Headers: any header value that contains the upstream netloc
                #   is dropped entirely (safe-to-drop list) or has the netloc
                #   replaced with the gateway's inbound host.
                # Body: scheme://netloc is replaced byte-for-byte with the
                #   gateway origin for all text-type responses.  Binary types
                #   (image/*, application/octet-stream, etc.) are skipped to
                #   avoid corrupting non-text payloads.
                _up_netloc   = up_parsed.netloc          # e.g. "backend.int:8080"
                _up_origin   = f"{up_parsed.scheme}://{_up_netloc}"  # "http://backend.int:8080"
                _gw_origin   = f"{client_scheme}://{client_host}"
                if _up_netloc:
                    # --- Headers ---
                    # Headers whose value may validly contain an internal URL and
                    # should be rewritten to the gateway origin.
                    _REWRITE_HEADERS = {"location", "content-location", "link",
                                        "refresh", "access-control-allow-origin"}
                    # Headers that expose backend identity and should be dropped
                    # if they contain the upstream netloc.
                    _DROP_IF_LEAKS = {"via", "server", "x-powered-by",
                                      "x-backend", "x-upstream", "x-origin",
                                      "x-real-server", "x-forwarded-server"}
                    _to_drop: list = []
                    for _hk in list(response_headers.keys()):
                        _hkl = _hk.lower()
                        _hv  = response_headers[_hk]
                        if _up_netloc not in _hv:
                            continue
                        if _hkl in _REWRITE_HEADERS:
                            _rewritten_hv = _hv.replace(_up_origin, _gw_origin)
                            _rewritten_hv = _rewritten_hv.replace(_up_netloc, client_host)
                            response_headers[_hk] = _rewritten_hv
                        elif _hkl in _DROP_IF_LEAKS:
                            _to_drop.append(_hk)
                        else:
                            # Unknown header — drop it; never leak the upstream.
                            _to_drop.append(_hk)
                    for _hk in _to_drop:
                        try:
                            del response_headers[_hk]
                        except KeyError:
                            pass

                    # --- Body ---
                    # Only scrub text-type responses (HTML, JSON, XML, plain text,
                    # JavaScript).  Binary payloads are left untouched.
                    _text_ctype = any(ctype.startswith(p) for p in (
                        "text/", "application/json", "application/xml",
                        "application/xhtml", "application/javascript",
                        "application/ld+json", "application/manifest+json",
                    ))
                    if _text_ctype:
                        _up_origin_b = _up_origin.encode()
                        _up_netloc_b = _up_netloc.encode()
                        _gw_origin_b = _gw_origin.encode()
                        if _up_origin_b in resp_body:
                            resp_body = resp_body.replace(_up_origin_b, _gw_origin_b)
                            # Joomla (and some CMS) generate absolute URLs as
                            # scheme://host//path (origin with trailing slash + path
                            # starting with slash).  After the replace above that
                            # becomes gw_origin//path; collapse to gw_origin/path.
                            _gw_double = _gw_origin_b + b"//"
                            if _gw_double in resp_body:
                                resp_body = resp_body.replace(_gw_double,
                                                              _gw_origin_b + b"/")
                        if _up_netloc_b in resp_body:
                            resp_body = resp_body.replace(_up_netloc_b,
                                                          client_host.encode())

                # Rewrite absolute upstream URLs so the internal upstream origin is
                # never exposed to the browser — in response headers (Location,
                # Content-Location, Link) and in HTML/JSON/XML response bodies.
                # UPSTREAM_REWRITE_BASE allows operators to specify an alternate
                # base URL (e.g. an alias hostname) beyond the current upstream netloc.
                _rewrite_base = (vc("UPSTREAM_REWRITE_BASE") or "").rstrip("/")
                if _rewrite_base and _rewrite_base != _up_origin:
                    _rb_bytes = _rewrite_base.encode()
                    _rb_str   = _rewrite_base
                    # Scrub from forwarded response headers; skip if stripping
                    # would produce an empty value (invalid redirect / broken link).
                    for _hk in ("location", "content-location", "link"):
                        _hv = response_headers.get(_hk, "")
                        if _rb_str in _hv:
                            _rewritten = _hv.replace(_rb_str, "")
                            if _rewritten:
                                response_headers[_hk] = _rewritten
                    # Scrub from response body (HTML, JSON, XML, plain text)
                    if _rb_bytes in resp_body:
                        resp_body = resp_body.replace(_rb_bytes, b"")

                # Augment upstream CSP to allow Cloudflare Turnstile.  Upstream
                # sites that embed Turnstile widgets may have a script-src that
                # omits challenges.cloudflare.com; the gateway adds it so the
                # widget loads through the proxy without a CSP violation.
                if ctype.startswith("text/html"):
                    _csp_key = next(
                        (k for k in response_headers
                         if k.lower() == "content-security-policy"), None)
                    if _csp_key:
                        response_headers[_csp_key] = _csp_inject_cf_turnstile(
                            response_headers[_csp_key])

                # H7/N1: inject honey-links only when Content-Type begins with
                # text/html (rejects `application/text/html-foo` substrings).
                if ctype.startswith("text/html"):
                    resp_body = _inject_honey_links(resp_body)
                    # v1.4 #6 — bot-trap form fields (no-op when disabled).
                    resp_body = _inject_bot_trap(resp_body)
                    # R7: plant a unique canary so we can detect LLM-agent
                    # echo behaviour on subsequent requests from this client.
                    if CANARY_ECHO_DETECTION:
                        canary = _new_canary()
                        resp_body = _inject_canary(resp_body, canary)
                        response_headers["X-Trace-Id"] = canary
                        # 1.6.10: also plant in ETag + X-Request-Id so AI frameworks
                        # that replay full response headers (LangChain, AutoGen) echo
                        # the token back and trigger canary-echo detection.
                        if HEADER_CANARY_ENABLED:
                            response_headers["ETag"]        = f'"{canary}"'
                            response_headers["X-Request-Id"] = canary
                    # 1.6.5 — BotD client-side detection (FingerprintJS).
                    # No-op until BOTD_ENABLED=1. Token bound to the
                    # requester's track_key so reports cannot be forged.
                    if BOTD_ENABLED:
                        resp_body = _inject_botd(resp_body,
                                                  request.get("_track_key", ""))
                    # 1.7.1 — Self-hosted automation probe (navigator.webdriver
                    # + headless indicators). No external bundle; fires on ≥2
                    # indicators detected client-side.
                    if AUTOMATION_PROBE_ENABLED:
                        resp_body = _inject_automation_probe(
                            resp_body, request.get("_track_key", ""))
                    # 1.7.2 — cookie lifecycle JS marker (writes agw_lc cookie)
                    if COOKIE_LIFECYCLE_ENABLED:
                        resp_body = _inject_lifecycle_cookie_script(resp_body)
                    # 1.7.2 — canvas + WebGL fingerprint probe
                    if FP_ENRICHMENT_ENABLED:
                        resp_body = _inject_fp_probe(
                            resp_body, request.get("_track_key", ""))
                    # 1.7.2 — record HTML path for referer-ghost tracking
                    _tk_html = request.get("_track_key", "")
                    if _tk_html:
                        record_html_served(_tk_html, request.path)
                    # 1.7.3 P1 — semantic honeypot credential injection
                    resp_body = inject_honey_creds(resp_body, _tk_html)
                    # 1.7.3 P4 — browser execution probe (preload link)
                    resp_body = inject_canary_probe(resp_body, _tk_html)
                    # 1.7.3 P3/P4 — check after HTML response; use gw_ip (ip not in scope here)
                    if _tk_html:
                        _gw_ip = get_ip(request)
                        _probe_delta = check_canary_probe(_tk_html, _gw_ip)
                        if _probe_delta:
                            await update_risk_and_maybe_ban(_tk_html, "canary-probe-miss", _gw_ip)
                        _llm_sig = _llm_heuristic.check(_tk_html, _gw_ip)
                        if _llm_sig:
                            await update_risk_and_maybe_ban(_tk_html, "llm-no-subresources", _gw_ip)

                # 1.6.10 — JSON API canary: inject a "_ref" token into JSON
                # object responses. LLM agents that cache and replay API
                # responses will echo the token back, triggering canary-echo.
                elif ctype.startswith("application/json") and JSON_CANARY_ENABLED and CANARY_ECHO_DETECTION:
                    try:
                        _j = json.loads(resp_body)
                        if isinstance(_j, dict):
                            canary = _new_canary()
                            _j["_ref"] = canary
                            resp_body = json.dumps(_j).encode()
                            response_headers["X-Trace-Id"] = canary
                    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                        pass

                # 1.8.6 Week 4 — Task M: circuit breaker tracking
                if resp.status >= 500:
                    _circuit_record_failure()
                else:
                    _circuit_record_success()
                return web.Response(status=resp.status, body=resp_body, headers=response_headers)
    except aiohttp.ClientError:
        _circuit_record_failure()
        return web.Response(status=502, text="upstream error\n")
    except asyncio.TimeoutError:
        _circuit_record_failure()
        return web.Response(status=504, text="upstream timeout\n")


# ── Debug endpoint ──────────────────────────────────────────────────────────

async def debug_xff(request):
    if not DEBUG_ENABLED:
        return web.Response(status=404, text="not found\n")
    safe_headers = {
        k: ("<redacted>" if k.lower() in _REDACT_HEADERS else v)
        for k, v in request.headers.items()
    }
    return web.json_response({
        "remote": request.remote,
        "xff_raw": request.headers.get("X-Forwarded-For"),
        "trust_xff_mode": TRUST_XFF,
        "computed_ip": get_ip(request),
        "headers": safe_headers,
    }, headers={"Cache-Control": "no-store"})


# ── Admin / gateway endpoints ───────────────────────────────────────────────

async def thresholds_endpoint(request: web.Request):
    """Read-only enriched view of numeric thresholds: min/max/current + an
    'impact_direction' hint so the UI can colour the value bar (red = looser,
    green = stricter). 'lower-is-stricter' for ban triggers / burst caps;
    'higher-is-stricter' for ban duration."""
    SPECS = [
        # name, min, max, impact_direction, description
        ("RISK_BAN_THRESHOLD",     1,    1000,    "lower-is-stricter",
         "Score that triggers a ban for a normal IP"),
        ("RATE_LIMIT_BURST",       1,    500,     "lower-is-stricter",
         "Per-identity token-bucket capacity"),
        ("RATE_LIMIT_REFILL",      0.1,  100,     "lower-is-stricter",
         "Per-identity tokens added per second"),
        ("IP_BURST",               1,    500,     "lower-is-stricter",
         "Per-socket-IP token-bucket capacity"),
        ("IP_REFILL",              0.1,  100,     "lower-is-stricter",
         "Per-socket-IP tokens added per second"),
        ("HOSTILE_BAN_SECS",       60,   2678400,   "higher-is-stricter",
         "Ban time — standard ban duration (24 h default = 86400)"),
        ("REALLY_BAN_SECS",        3600, 31536000,  "higher-is-stricter",
         "Really Ban — extended ban for canary-echo/honeypot (30 d default = 2592000)"),
        ("CANARY_TTL_S",           30,   86400,   "higher-is-stricter",
         "Canary token validity window"),
        ("GLOBAL_RPS_LIMIT",       0,    10000,   "lower-is-stricter",
         "Global throttle (0 = disabled)"),
        ("SESSION_CHURN_WINDOW_S", 5,    3600,    "higher-is-stricter",
         "Window for session-rotation detector"),
        ("SESSION_CHURN_MAX",      1,    100,     "lower-is-stricter",
         "Max chal cookies per fingerprint per window"),
        ("JA4_AUTODENY_THRESHOLD", 1,    100,     "lower-is-stricter",
         "Distinct bans on a JA4 before auto-deny"),
        ("ANUBIS_DIFFICULTY_BOOST", 0,   6,       "higher-is-stricter",
         "Extra PoW leading zeros (Anubis mode)"),
        ("SECOND_ORDER_THRESHOLD", 0,    1000,    "higher-is-stricter",
         "Risk score above which 2nd-order detectors activate (0 = always)"),
        ("ESCALATION_THRESHOLD",   0,    1000,    "higher-is-stricter",
         "Risk score above which 3rd-order expensive detectors run (0 = always)"),
        ("TARPIT_DELAY_MS",        0,    30000,   "lower-is-stricter",
         "Delay (ms) added per soft-band response (tarpit)"),
        ("DLP_MAX_BYTES",          1024, 16777216,"lower-is-stricter",
         "Max response bytes scanned by DLP (cost cap)"),
        # ── 1.7.2 ──
        ("COOKIE_GHOST_MIN_REQUESTS",   1,   100,    "higher-is-stricter",
         "Minimum requests before cookie-ghost can fire"),
        ("COOKIE_GHOST_MISS_THRESHOLD", 1,   50,     "lower-is-stricter",
         "Cookie-miss count that triggers cookie-ghost"),
        ("IMPOSSIBLE_TRAVEL_WINDOW_SECS", 60, 604800, "higher-is-stricter",
         "Window (s) in which same identity must not span two countries"),
        ("POW_CHAL_THRESHOLD",          0,   100000, "lower-is-stricter",
         "Risk score at or above which JS challenge embeds a PoW puzzle (0 = never)"),
        ("UPSTREAM_MAX_BODY",  1024, 1073741824, "lower-is-stricter",
         "Max request body forwarded to upstream (bytes). Default 4194304 (4 MiB). "
         "Keep WAF_BODY_SCAN_BYTES >= this to avoid a WAF bypass."),
        ("UPSTREAM_MAX_RESP",  1024, 1073741824, "lower-is-stricter",
         "Max upstream response body buffered (bytes). Default 17825792 (17 MiB). "
         "Responses exceeding this limit return 413 to the client."),
    ]
    g = globals()
    out = []
    for name, lo, hi, direction, desc in SPECS:
        if name not in g:
            continue
        cur = g[name]
        # Normalised position 0.0..1.0 in [lo, hi]
        try:
            pos = max(0.0, min(1.0, (float(cur) - lo) / (hi - lo))) if hi > lo else 0.5
        except (TypeError, ValueError):
            pos = 0.5
        out.append({
            "name":             name,
            "current":          cur,
            "min":              lo,
            "max":              hi,
            "position":         round(pos, 4),
            "impact_direction": direction,    # for UI colour gradient
            "description":      desc,
        })
    return web.json_response({"thresholds": out},
                              headers={"Cache-Control": "no-store"})


async def external_endpoint(request: web.Request):
    """Status + cost telemetry of every external integration. Read-only —
    activation is via container env (the secrets must NOT be hot-reloadable
    via /__config because that would let an admin-key holder enable IP
    intel keys arbitrarily and burn quota)."""
    integrations = []

    # 1. Cloudflare Turnstile — already wired
    integrations.append({
        "name":         "Cloudflare Turnstile",
        "purpose":      "Real-browser challenge minted by Cloudflare's siteverify. The only chal-cookie path that's not client-computable.",
        "vendor_url":   "https://www.cloudflare.com/products/turnstile/",
        "docs_url":     "https://developers.cloudflare.com/turnstile/",
        "trigger":      "Shown only when identity's risk_score >= TURNSTILE_RISK_THRESHOLD (default = mid-orange band). Below that, fresh clients fall through to cookie auto-mint.",
        "weight":       "0 risk added directly — solving the challenge mints the chal cookie that bypasses the gate. Failing it = silent decoy.",
        "data_egress":  "Each verify POSTs the user's token + remote IP to challenges.cloudflare.com/turnstile/v0/siteverify",
        "status":       "configured" if TURNSTILE_ENABLED else "disabled",
        "enabled":      TURNSTILE_ENABLED,
        # 1.6.0 — distinguish "creds present, currently off" (toggleable from
        # the dashboard) from "creds missing" (cannot enable). Without this
        # the controls switch greys out the moment an operator turns it off.
        "credentials_present": _TURNSTILE_CONFIGURED,
        "envs_needed":  ["TURNSTILE_SITEKEY", "TURNSTILE_SECRET", "JS_CHALLENGE=1"],
        "free_tier":    "unlimited",
        "cost_typical_ms":  150.0,    # CF challenge widget round-trip
        "cost_p99_ms":      400.0,
        "cost_cached_ms":   0.0,      # cookie reuse — no per-request call
        "activation_order": 3,
        "telemetry": {
            "active": JS_CHALLENGE and TURNSTILE_ENABLED,
        },
    })

    # 2. AbuseIPDB
    integrations.append({
        "name":         "AbuseIPDB",
        "purpose":      "Crowdsourced IP reputation. High score -> +50 risk; medium -> +15.",
        "vendor_url":   "https://www.abuseipdb.com/",
        "docs_url":     "https://docs.abuseipdb.com/",
        "trigger":      "Every request — looks up the source IP. SQLite-cached for 6h to stay under the 1000 req/day free quota.",
        "weight":       f"abuseipdb-high (>={ABUSEIPDB_HIGH_THRESHOLD}) = +50 risk · abuseipdb-med (>={ABUSEIPDB_MED_THRESHOLD}) = +15 risk",
        "data_egress":  "Each uncached lookup sends the IP to api.abuseipdb.com/api/v2/check",
        "status":       "configured" if ABUSEIPDB_ENABLED else "disabled",
        "enabled":      ABUSEIPDB_ENABLED,
        "credentials_present": bool(ABUSEIPDB_KEY),
        "envs_needed":  ["ABUSEIPDB_KEY"],
        "free_tier":    "1000 lookups/day",
        "cost_typical_ms":  150.0,
        "cost_p99_ms":      450.0,
        "cost_cached_ms":   0.3,
        "telemetry": dict(_abuseipdb_stats, **{
            "cache_hit_rate": (
                round(100.0 * _abuseipdb_stats["lookups_cached"] /
                      max(1, _abuseipdb_stats["lookups_total"]), 1)),
            "thresholds": {
                "high": ABUSEIPDB_HIGH_THRESHOLD,
                "med":  ABUSEIPDB_MED_THRESHOLD,
            },
            "cache_hours": ABUSEIPDB_CACHE_HOURS,
        }),
    })

    # 3. CrowdSec
    _cs_health = await _crowdsec_lapi_health()
    integrations.append({
        "name":         "CrowdSec",
        "purpose":      "Community blocklist — IP listed in CrowdSec LAPI hits +70 risk (one-shot ban for normal IPs).",
        "vendor_url":   "https://www.crowdsec.net/",
        "docs_url":     "https://docs.crowdsec.net/docs/local_api/intro",
        "trigger":      "Every request — queries the local LAPI for an active decision on the source IP. In-process cached for CROWDSEC_CACHE_SECS (default 60s).",
        "weight":       "crowdsec-banned = +70 risk (above the 50 ban threshold -> instant 24h hostile pool)",
        "data_egress":  "Outbound to your self-hosted LAPI only — no internet calls.",
        "status":       "configured" if CROWDSEC_ENABLED else "disabled",
        "enabled":      CROWDSEC_ENABLED,
        "credentials_present": bool(CROWDSEC_LAPI_URL and CROWDSEC_API_KEY),
        "envs_needed":  ["CROWDSEC_LAPI_URL", "CROWDSEC_API_KEY"],
        "free_tier":    "open source (self-hosted LAPI)",
        "cost_typical_ms":  5.0,
        "cost_p99_ms":      20.0,
        "cost_cached_ms":   0.2,
        "lapi_health":  _cs_health,
        "telemetry": dict(_crowdsec_stats, **{
            "cache_hit_rate": (
                round(100.0 * _crowdsec_stats["lookups_cached"] /
                      max(1, _crowdsec_stats["lookups_total"]), 1)),
            "cache_secs": CROWDSEC_CACHE_SECS,
            "lapi_url": CROWDSEC_LAPI_URL or "",
        }),
    })

    # 4. MaxMind GeoLite2 ASN
    integrations.append({
        "name":         "MaxMind GeoLite2 ASN",
        "purpose":      "Local ASN tagging — IPs from hosting providers get +5 risk (soft signal).",
        "vendor_url":   "https://www.maxmind.com/",
        "docs_url":     "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
        "trigger":      "Every request — looks up the ASN of the source IP in the local mmdb. Pure-local, ~0.1ms.",
        "weight":       "asn-hosting = +5 risk (soft — just a hint that the IP isn't residential)",
        "data_egress":  "None. Reads from /data/GeoLite2-ASN.mmdb. Refresh script downloads from MaxMind monthly via cron.",
        "status":       ("configured" if MAXMIND_ENABLED
                         else ("missing-db" if not os.path.exists(MAXMIND_ASN_DB_PATH)
                               else "disabled")),
        "enabled":      MAXMIND_ENABLED,
        "credentials_present": os.path.exists(MAXMIND_ASN_DB_PATH),
        "envs_needed":  ["MAXMIND_ASN_DB_PATH (DB file at /data/GeoLite2-ASN.mmdb)"],
        "free_tier":    "free DB download — monthly refresh",
        "cost_typical_ms":  0.1,
        "cost_p99_ms":      0.5,
        "cost_cached_ms":   0.1,
        "telemetry": dict(_asn_stats, **{
            "db_path": MAXMIND_ASN_DB_PATH,
            "hosting_keywords": list(HOSTING_ASN_KEYWORDS),
        }),
    })

    # 5. Anubis-mode — in-process strict PoW gate (1.5.4)
    eff_diff = POW_DIFFICULTY + (ANUBIS_DIFFICULTY_BOOST if ANUBIS_ENABLED else 0)
    integrations.append({
        "name":         "Anubis-mode (PoW)",
        "purpose":      "In-process strict PoW gate inspired by github.com/TecharoHQ/anubis. When enabled, raises PoW difficulty by ANUBIS_DIFFICULTY_BOOST (each +1 ~= 16x harder). Scrapers / LLM agents tank, humans pass after one round trip.",
        "vendor_url":   "https://github.com/TecharoHQ/anubis",
        "docs_url":     "https://anubis.techaro.lol/docs",
        "trigger":      f"When ANUBIS_ENABLED=1, the existing PoW challenges (/__pow + verify) require {eff_diff} leading hex zeros (base {POW_DIFFICULTY} + boost {ANUBIS_DIFFICULTY_BOOST if ANUBIS_ENABLED else 0}).",
        "weight":       "0 risk added — failing PoW returns 402 with a fresh challenge; no ban accrual.",
        "data_egress":  "None. Pure SHA-256 challenge / verify in-process.",
        "status":       "configured",   # always available — no external service
        "enabled":      ANUBIS_ENABLED,
        "credentials_present": True,
        "envs_needed":  ["ANUBIS_ENABLED=1", "ANUBIS_DIFFICULTY_BOOST (0..6)"],
        "free_tier":    "in-process — no external service",
        "cost_typical_ms":  0.05,    # SHA-256 verify on cookie path
        "cost_p99_ms":      0.5,
        "cost_cached_ms":   0.0,
        "activation_order": 3,
        "telemetry": {
            "base_difficulty":   POW_DIFFICULTY,
            "boost":             ANUBIS_DIFFICULTY_BOOST if ANUBIS_ENABLED else 0,
            "effective_diff":    eff_diff,
            "leading_zeros_req": eff_diff,
            "active":            ANUBIS_ENABLED,
        },
    })

    # 6. SQLite event store — always present (the gateway can't run without it)
    try:
        sqlite_size = os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0
    except Exception:
        sqlite_size = 0
    sqlite_rows = 0
    try:
        if os.path.exists(DB_PATH):
            _c = sqlite3.connect(DB_PATH)
            sqlite_rows = int(_c.execute("SELECT COUNT(*) FROM events").fetchone()[0])
            _c.close()
    except Exception:
        pass
    integrations.append({
        "name":         "SQLite event store",
        "purpose":      "Default event store. Single-file zero-deps; correct for <=100 RPS sustained.",
        "vendor_url":   "https://www.sqlite.org/",
        "docs_url":     "https://www.sqlite.org/docs.html",
        "trigger":      "Every request — events table append + per-client snapshot upsert. WAL mode.",
        "weight":       "0 risk added — pure persistence.",
        "data_egress":  "None. Lives on the /data Docker volume.",
        "status":       "configured" if DB_BACKEND == "sqlite" else "disabled",
        "enabled":      DB_BACKEND == "sqlite",
        "credentials_present": True,                   # always available
        "envs_needed":  ["DB_PATH (default /data/antibot.db)"],
        "free_tier":    "free / open source",
        "cost_typical_ms":  0.05,
        "cost_p99_ms":      1.0,
        "cost_cached_ms":   0.0,
        "telemetry": {
            "active":      DB_BACKEND == "sqlite",
            "endpoint":    DB_PATH,
            "size_bytes":  sqlite_size,
            "events_rows": sqlite_rows,
        },
    })

    # 7. PostgreSQL / TimescaleDB event store — opt-in via DB_BACKEND=postgres
    pg_status = ("configured" if (DB_BACKEND == "postgres" and _postgres_available)
                 else ("disabled" if DB_BACKEND != "postgres"
                        else "missing-driver"))
    pg_telemetry = {"active": DB_BACKEND == "postgres" and _postgres_available}
    if DB_BACKEND == "postgres" and _postgres_available:
        size = pg_db_size()
        if size.get("ok"):
            pg_telemetry["size_bytes"]  = size["db_bytes"]
            pg_telemetry["events_rows"] = size["events_rows"]
    if POSTGRES_DSN:
        try:
            from urllib.parse import urlparse
            p = urlparse(POSTGRES_DSN)
            pg_telemetry["endpoint"] = (
                f"{p.scheme}://{p.username or '<user>'}:>update password<@"
                f"{p.hostname or '<host>'}{':'+str(p.port) if p.port else ''}"
                f"{p.path or ''}")
        except Exception:
            pg_telemetry["endpoint"] = "(redacted)"
    integrations.append({
        "name":         "PostgreSQL / TimescaleDB",
        "purpose":      "High-volume event store backed by Postgres + the TimescaleDB extension (compression + continuous aggregates + hypertable). Required for >100 RPS sustained or multi-instance fleet mode.",
        "vendor_url":   "https://www.timescale.com/",
        "docs_url":     "https://docs.timescale.com/",
        "trigger":      "Every request when DB_BACKEND=postgres — events row inserted via psycopg, fire-and-forget.",
        "weight":       "0 risk added — pure persistence.",
        "data_egress":  "Outbound to your Postgres / Timescale instance (POSTGRES_DSN).",
        "status":       pg_status,
        "enabled":      DB_BACKEND == "postgres" and _postgres_available,
        "credentials_present": bool(POSTGRES_DSN),
        "envs_needed":  ["DB_BACKEND=postgres", "POSTGRES_DSN"],
        "free_tier":    "free / open source (self-hosted)",
        "cost_typical_ms":  2.0,
        "cost_p99_ms":      10.0,
        "cost_cached_ms":   0.0,
        "telemetry": pg_telemetry,
    })

    # ── 1.7.2 ────────────────────────────────────────────────────────────────
    # 8. Canvas/WebGL fingerprint enrichment — self-hosted JS probe
    integrations.append({
        "name":         "Canvas/WebGL Fingerprint",
        "purpose":      "Injects ~1 KB inline JS that draws a canvas scene and queries WebGL renderer info. Detects headless browsers (SwiftShader/Mesa/LLVMPipe renderer) and Chrome with WebGL blocked.",
        "vendor_url":   "",
        "docs_url":     "",
        "trigger":      "Injected into every HTML response. Browser POSTs result to /antibot-appsec-gateway/fp-report (HMAC-bound to session, 300 s TTL).",
        "weight":       "soft-renderer = +25 risk (med) · webgl-missing = +15 risk (soft)",
        "data_egress":  "None — report endpoint is self-hosted at /antibot-appsec-gateway/fp-report.",
        "status":       "configured" if FP_ENRICHMENT_ENABLED else "disabled",
        "enabled":      FP_ENRICHMENT_ENABLED,
        "credentials_present": True,
        "envs_needed":  ["FP_ENRICHMENT_ENABLED=1 (default on)"],
        "free_tier":    "in-process — no external service",
        "cost_typical_ms":  0.1,
        "cost_p99_ms":      0.3,
        "cost_cached_ms":   0.0,
        "activation_order": 1,
        "telemetry": {"active": FP_ENRICHMENT_ENABLED},
    })

    # 9. Service Worker challenge — self-hosted SW header probe
    integrations.append({
        "name":         "Service Worker Challenge",
        "purpose":      "Registers a SW at /antibot-appsec-gateway/sw.js that adds X-SW-Active: 1 to intercepted gateway requests. Absence after registration is expected = strong headless-browser signal.",
        "vendor_url":   "",
        "docs_url":     "",
        "trigger":      "SW is registered by the JS challenge page when SW_CHALLENGE_ENABLED=1. X-SW-Active header expected on all subsequent /antibot-appsec-gateway/* requests.",
        "weight":       "No direct risk score — absence is a signal context used by other detectors.",
        "data_egress":  "None — purely in-browser service worker, no network call.",
        "status":       "configured" if SW_CHALLENGE_ENABLED else "disabled",
        "enabled":      SW_CHALLENGE_ENABLED,
        "credentials_present": True,
        "envs_needed":  ["SW_CHALLENGE_ENABLED=1 (default off)"],
        "free_tier":    "in-process — no external service",
        "cost_typical_ms":  0.0,
        "cost_p99_ms":      0.0,
        "cost_cached_ms":   0.0,
        "activation_order": 2,
        "telemetry": {"active": SW_CHALLENGE_ENABLED},
    })

    # 10. MaxMind GeoLite2 City — impossible-travel detection
    from reputation.maxmind import _city_reader as _city_reader_ref
    _city_db_ok = _city_reader_ref is not None
    integrations.append({
        "name":         "MaxMind GeoLite2 City",
        "purpose":      "City-level geolocation DB used for impossible-travel detection: same session appearing from two different countries within IMPOSSIBLE_TRAVEL_WINDOW_SECS fires +35 risk (hard-ban default).",
        "vendor_url":   "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
        "docs_url":     "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
        "trigger":      "Every request for session-keyed identities when IMPOSSIBLE_TRAVEL_ENABLED=1 and City DB is loaded.",
        "weight":       "impossible-travel = +35 risk (hard, triggers ban)",
        "data_egress":  "None — in-memory DB lookup at /data/GeoLite2-City.mmdb.",
        "status":       ("configured" if (_city_db_ok and IMPOSSIBLE_TRAVEL_ENABLED)
                         else ("missing-db" if (not _city_db_ok and IMPOSSIBLE_TRAVEL_ENABLED)
                               else "disabled")),
        "enabled":      _city_db_ok and IMPOSSIBLE_TRAVEL_ENABLED,
        "credentials_present": _city_db_ok,
        "envs_needed":  ["IMPOSSIBLE_TRAVEL_ENABLED=1", "MAXMIND_LICENSE_KEY (for auto-download)"],
        "free_tier":    "free DB download — monthly refresh",
        "cost_typical_ms":  0.1,
        "cost_p99_ms":      0.5,
        "cost_cached_ms":   0.1,
        "telemetry": {
            "active": _city_db_ok and IMPOSSIBLE_TRAVEL_ENABLED,
            "db_path": "/data/GeoLite2-City.mmdb",
        },
    })

    return web.json_response({"integrations": integrations},
                              headers={"Cache-Control": "no-store"})


# 1.6.10 — Integration live health-check.
# GET /secured/integration-check?name=<name>
# Returns {ok, latency_ms, detail} without side effects.
async def integration_check_endpoint(request: web.Request):
    name = (request.rel_url.query.get("name") or "").strip()
    import time as _chk_time
    async def _check() -> dict:
        if name == "AbuseIPDB":
            if not ABUSEIPDB_ENABLED:
                return {"ok": False, "detail": "not configured — ABUSEIPDB_KEY missing"}
            t0 = _chk_time.monotonic()
            try:
                import aiohttp as _aiohttp
                async with _aiohttp.ClientSession() as sess:
                    async with sess.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": "127.0.0.1", "maxAgeInDays": "90"},
                        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                        timeout=_aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        ok = resp.status in (200, 422)   # 422 = valid key, invalid IP ok
                        return {"ok": ok, "detail": f"HTTP {resp.status}"}
            except Exception as e:
                return {"ok": False, "detail": str(e)}
            finally:
                pass
        if name == "CrowdSec":
            if not CROWDSEC_ENABLED:
                return {"ok": False, "detail": "not configured — CROWDSEC_LAPI_URL / CROWDSEC_API_KEY missing"}
            t0 = _chk_time.monotonic()
            try:
                import aiohttp as _aiohttp
                async with _aiohttp.ClientSession() as sess:
                    async with sess.get(
                        CROWDSEC_LAPI_URL.rstrip("/") + "/v1/decisions",
                        params={"ip": "127.0.0.1"},
                        headers={"X-Api-Key": CROWDSEC_API_KEY},
                        timeout=_aiohttp.ClientTimeout(total=5),
                    ) as resp:
                        ok = resp.status in (200, 204)
                        return {"ok": ok, "detail": f"HTTP {resp.status}"}
            except Exception as e:
                return {"ok": False, "detail": str(e)}
            finally:
                pass
        if name in ("MaxMind GeoLite2 ASN", "MaxMind"):
            if _asn_reader is None:
                path = MAXMIND_ASN_DB_PATH
                exists = os.path.exists(path)
                return {"ok": False, "detail": f"reader not loaded — DB {'missing' if not exists else 'exists but not initialised'}"}
            return {"ok": True, "detail": f"reader loaded · {MAXMIND_ASN_DB_PATH}"}
        if name in ("Cloudflare Turnstile", "Turnstile"):
            return {"ok": _TURNSTILE_CONFIGURED,
                    "detail": "credentials present" if _TURNSTILE_CONFIGURED else "TURNSTILE_SITEKEY / TURNSTILE_SECRET not configured"}
        if name in ("SQLite event store", "SQLite"):
            exists = os.path.exists(DB_PATH)
            return {"ok": exists, "detail": f"{DB_PATH} {'found' if exists else 'not found'}"}
        if name in ("PostgreSQL / TimescaleDB", "PostgreSQL"):
            if not POSTGRES_DSN:
                return {"ok": False, "detail": "POSTGRES_DSN not set"}
            pg = _postgres_load_module()
            if not pg:
                return {"ok": False, "detail": "psycopg driver not installed"}
            t0 = _chk_time.monotonic()
            try:
                with pg.connect(POSTGRES_DSN, connect_timeout=5) as conn:
                    conn.execute("SELECT 1")
                return {"ok": True, "detail": f"connected in {(_chk_time.monotonic()-t0)*1000:.0f} ms"}
            except Exception as e:
                return {"ok": False, "detail": str(e)}
        if name in ("Canvas/WebGL Fingerprint", "Canvas/WebGL"):
            return {"ok": FP_ENRICHMENT_ENABLED,
                    "detail": "probe enabled" if FP_ENRICHMENT_ENABLED else "FP_ENRICHMENT_ENABLED=0"}
        if name in ("Service Worker Challenge", "Service Worker"):
            return {"ok": SW_CHALLENGE_ENABLED,
                    "detail": "SW challenge enabled" if SW_CHALLENGE_ENABLED else "SW_CHALLENGE_ENABLED=0 (default off)"}
        if name in ("MaxMind GeoLite2 City", "MaxMind City"):
            _city_ok = _city_reader_is_loaded()
            if not _city_ok:
                return {"ok": False, "detail": "City DB not loaded — set MAXMIND_LICENSE_KEY for auto-download"}
            if not IMPOSSIBLE_TRAVEL_ENABLED:
                return {"ok": False, "detail": "DB loaded but IMPOSSIBLE_TRAVEL_ENABLED=0"}
            return {"ok": True, "detail": "City DB loaded · impossible-travel active"}
        return {"ok": None, "detail": f"no health-check defined for '{name}'"}

    t_start = _chk_time.monotonic()
    result = await _check()
    result["latency_ms"] = round((_chk_time.monotonic() - t_start) * 1000, 1)
    return web.json_response(result, headers={"Cache-Control": "no-store"})


# 1.6.10 — Signal activation-order API.
# GET  /secured/signal-orders  -> {orders: {sig: n, ...}, gw_id: "..."}
# POST /secured/signal-orders  body: {signal: "...", order: 1|2|3}
async def signal_orders_endpoint(request: web.Request):
    gw_id = _gw_local_id()
    if request.method == "GET":
        try:
            conn = sqlite3.connect(DB_PATH)
            rows = conn.execute(
                "SELECT signal, activation_order, updated_ts, updated_by "
                "FROM signal_orders WHERE gw_id = ?", (gw_id,)
            ).fetchall()
            conn.close()
        except Exception:
            rows = []
        orders = {sig: {"order": n, "updated_ts": ts, "updated_by": by}
                  for sig, n, ts, by in rows}
        return web.json_response(
            {"orders": orders, "gw_id": gw_id},
            headers={"Cache-Control": "no-store"})
    if request.method == "POST":
        if denied := _role_denied(request, "admin", "maintainer"):
            return denied
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"ok": False, "error": "invalid JSON"}, status=400)
        sig   = (body or {}).get("signal", "")
        order = (body or {}).get("order")
        if not sig:
            return web.json_response({"ok": False, "error": "signal required"}, status=400)
        if order not in (1, 2, 3):
            return web.json_response({"ok": False, "error": "order must be 1, 2 or 3"}, status=400)
        actor = _request_username(request)  # PROXY4-09: use session-verified identity, not forgeable header
        _save_signal_order(sig, order, actor)
        return web.json_response(
            {"ok": True, "signal": sig, "order": order, "gw_id": gw_id},
            headers={"Cache-Control": "no-store"})
    return web.Response(status=405)


async def admin_ips_endpoint(request: web.Request):
    """Admin: read / add / remove entries from the admin-IP allowlist.

      GET    /__admin-ips?key=...
                 -> {entries: [{cidr, description, source, added_ts}, ...]}
      POST   /__admin-ips?key=...   body: {cidr, description}
                 -> {ok, message, entries}
      PATCH  /__admin-ips?key=...   body: {cidr, description}
                 -> {ok, message, entries}    (in-place description update)
      DELETE /__admin-ips?key=...&cidr=...
                 -> {ok, message, entries}

    Persisted to the `admin_ips` table; hot-reloaded into ADMIN_ALLOWED_NETS.
    Env-seeded entries are persisted on first boot and CAN be removed via
    this endpoint (DB authoritative after first boot).
    """
    if request.method == "GET":
        return web.json_response(
            {"entries": list(ADMIN_ALLOWED_ENTRIES),
             "env_seed": ADMIN_ENV_SEED},
            headers={"Cache-Control": "no-store"})
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            body = {}
        cidr = (body or {}).get("cidr", "")
        note = (body or {}).get("note", "")
        description = (body or {}).get("description", "")
        ok, msg = await admin_ip_add(cidr, note, source="manual",
                                      description=description)
        return web.json_response(
            {"ok": ok, "message": msg, "entries": list(ADMIN_ALLOWED_ENTRIES)},
            status=200 if ok else 400,
            headers={"Cache-Control": "no-store"})
    if request.method == "PATCH":
        try:
            body = await request.json()
        except Exception:
            body = {}
        cidr = (body or {}).get("cidr", "")
        description = (body or {}).get("description", "")
        ok, msg = await admin_ip_update_description(cidr, description)
        return web.json_response(
            {"ok": ok, "message": msg, "entries": list(ADMIN_ALLOWED_ENTRIES)},
            status=200 if ok else 400,
            headers={"Cache-Control": "no-store"})
    if request.method == "DELETE":
        cidr = request.query.get("cidr", "")
        ok, msg = await admin_ip_remove(cidr)
        return web.json_response(
            {"ok": ok, "message": msg, "entries": list(ADMIN_ALLOWED_ENTRIES)},
            status=200 if ok else 400,
            headers={"Cache-Control": "no-store"})
    return web.json_response({"error": "method not allowed"}, status=405)


@_require_csrf
async def ban_endpoint(request: web.Request):
    """Admin: ban a single identity (track-key) or all identities behind an
    IP for `secs` seconds. Mirror of /__unban so the controls/agents
    dashboards can drive bans without restarting or rewriting state.

    Query params:
      ?id=<identity>   — ban one identity (track_key)
      ?ip=<ip>         — ban every identity whose last_ip matches
      &secs=<int>      — ban duration (default HOSTILE_BAN_SECS, max 31 d)
      &reason=<text>   — recorded in audit log + risk-score reasons
    """
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    target_id = request.query.get("id")
    target_ip = request.query.get("ip")
    try:
        secs = int(request.query.get("secs", str(HOSTILE_BAN_SECS)))
    except ValueError:
        secs = HOSTILE_BAN_SECS
    secs = max(60, min(secs, 31 * 86400))
    reason = (request.query.get("reason", "manual-ban") or "manual-ban")[:64]
    if not target_id and not target_ip:
        return web.json_response({"error": "provide id= or ip="},
                                  status=400,
                                  headers={"Cache-Control": "no-store"})
    banned_count = 0
    async with state_lock:
        n = now()
        for k, s in ip_state.items():
            if (target_id and k == target_id) or (
                    target_ip and s.last_ip == target_ip):
                s.banned_until = n + secs
                banned_count += 1
    # Propagate to shared store + write to DB.
    ts = _t.time()
    if target_id and banned_count:
        await _shared_ban_set(target_id, ts + secs, reason)
        if db_queue is not None:
            try:
                db_queue.put_nowait(("ban", (target_id, ts + secs, reason, ts)))
            except asyncio.QueueFull:
                pass
    elif target_ip and banned_count:
        # ip-scoped: write a row per matched identity. Best effort.
        async with state_lock:
            matched_ids = [k for k, s in ip_state.items()
                           if s.last_ip == target_ip]
        for tk in matched_ids:
            await _shared_ban_set(tk, ts + secs, reason)
            if db_queue is not None:
                try:
                    db_queue.put_nowait(("ban", (tk, ts + secs, reason, ts)))
                except asyncio.QueueFull:
                    pass
    slog("manual_ban", level="warn", rid=request.get("_rid", ""),
         id=target_id or "", ip=target_ip or "", secs=secs,
         reason=reason, count=banned_count)
    return web.json_response(
        {"banned": banned_count, "secs": secs, "reason": reason,
         "scope": ("id=" + target_id if target_id else "ip=" + target_ip)},
        headers={"Cache-Control": "no-store"})


async def secrets_endpoint(request: web.Request):
    """1.5.5 — runtime integration secret management (admin-gated).

      GET   /__secrets?key=...  -> write-only status (which keys are
                                 configured, never the values themselves)
      POST  /__secrets?key=...   body: JSON object with any subset of:
                                {TURNSTILE_SITEKEY, TURNSTILE_SECRET,
                                 ABUSEIPDB_KEY, CROWDSEC_LAPI_URL,
                                 CROWDSEC_LAPI_KEY, MAXMIND_LICENSE_KEY,
                                 OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET,
                                 OIDC_DEFAULT_ROLE, OIDC_SCOPES}
      DELETE /__secrets?key=...&name=KEY  -> clear one secret + revert to
                                 env (which may also be empty).

    Persists to `secrets_kv`. Re-applies dependent state immediately
    (e.g. flips ABUSEIPDB_ENABLED true when ABUSEIPDB_KEY is set).
    Env vars STILL win at boot — the DB value is only used when env is
    empty for that key.

    The values are NEVER returned via GET — operators must read them from
    the SQLite DB directly if they need to recover one. That keeps the
    dashboard non-leaky on a captured admin session.
    """
    g = globals()
    if request.method == "GET":
        out = {}
        for public_name, (global_name, env_name) in _SECRET_KEYS.items():
            cur = g.get(global_name) or ""
            out[public_name] = {
                "configured": bool(cur),
                "source":     ("env" if os.environ.get(env_name, "").strip()
                               else ("db" if cur else "unset")),
                "length":     len(cur),
            }
        return web.json_response(
            {"secrets": out,
             "integration_state": {
                 "_TURNSTILE_CONFIGURED": _TURNSTILE_CONFIGURED,
                 "TURNSTILE_ENABLED":     TURNSTILE_ENABLED,
                 "ABUSEIPDB_ENABLED":     ABUSEIPDB_ENABLED,
                 "CROWDSEC_ENABLED":      CROWDSEC_ENABLED,
                 "MAXMIND_ENABLED":       MAXMIND_ENABLED,
                 "MAXMIND_CITY_ENABLED":  MAXMIND_CITY_ENABLED,
                 "OIDC_ENABLED":          g.get("OIDC_ENABLED", False),
             }},
            headers={"Cache-Control": "no-store"})

    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    if request.method == "DELETE":
        public_name = request.query.get("name", "")
        if public_name not in _SECRET_KEYS:
            return web.json_response({"error": "unknown secret name"},
                                      status=400, headers={"Cache-Control":"no-store"})
        global_name, env_name = _SECRET_KEYS[public_name]
        # Clear DB
        if db_queue is not None:
            try: db_queue.put_nowait(("del_secret", (public_name,)))
            except asyncio.QueueFull: pass  # nosec B110 — best-effort DB sync; in-memory state already updated
        # Revert global to env (or empty)
        g[global_name] = os.environ.get(env_name, "").strip()
        _refresh_integration_state(globals())
        # Special: license-key clear -> don't re-fetch on next request
        if public_name == "MAXMIND_LICENSE_KEY":
            pass   # mmdbs persist on disk; nothing to undo
        slog("secret_deleted", level="warn", rid=request.get("_rid", ""),
             name=public_name)
        return web.json_response(
            {"ok": True, "deleted": public_name, "now_source": "env" if g[global_name] else "unset"},
            headers={"Cache-Control": "no-store"})

    if request.method != "POST":
        return web.json_response({"error": "method not allowed"}, status=405)

    try:
        raw = await asyncio.wait_for(request.content.read(64 * 1024),
                                      timeout=BODY_TIMEOUT)
        updates = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(updates, dict):
            raise ValueError("body must be a JSON object")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"},
                                  status=400, headers={"Cache-Control":"no-store"})

    applied, rejected = {}, {}
    for k, raw_v in updates.items():
        if k not in _SECRET_KEYS:
            rejected[k] = "unknown secret name"
            continue
        v = (str(raw_v) if raw_v is not None else "").strip()
        if v == "":
            rejected[k] = "empty value (use DELETE to clear)"
            continue
        if len(v) > 1024:
            rejected[k] = "value too long (max 1024 bytes)"
            continue
        # SH-1: SSRF guard on URL-type secrets.
        if k in _URL_SECRET_GUARDS:
            try:
                _ssrf_guard_url(v, label=k, allow_loopback=_URL_SECRET_GUARDS[k])
            except ValueError as _ssrf_err:
                rejected[k] = str(_ssrf_err)[:200]
                continue
        global_name, _env_name = _SECRET_KEYS[k]
        # POSTGRES_DSN sentinel: if the password component is ">update password<",
        # substitute the password from the currently stored DSN so callers can
        # update host/port/db/user without re-entering the password.
        if k == "POSTGRES_DSN" and ":>update password<@" in v:
            try:
                from urllib.parse import urlparse as _up
                _cur_pass = (_up(g.get("POSTGRES_DSN") or "")).password or ""
                if _cur_pass:
                    v = v.replace(":>update password<@", f":{_cur_pass}@", 1)
            except Exception:
                pass
        g[global_name] = v
        # 1.8.8 — hot-apply POSTGRES_DSN: propagate to every module that holds
        # its own POSTGRES_DSN binding (notably db.postgres) so pg_test_roundtrip
        # and the event-store writer see the new value without a container
        # restart. Without this, /secrets would only patch proxy_handler's
        # global; db.postgres.POSTGRES_DSN would stay stale until reboot.
        if global_name == "POSTGRES_DSN":
            _propagate_global("POSTGRES_DSN", v)
            # Re-run schema init in a background thread so tables are
            # created immediately (when DSN was empty at boot) and
            # _postgres_available is set True so db_read_events routes
            # to Postgres without needing a container restart.
            try:
                _loop = asyncio.get_running_loop()
                _loop.run_in_executor(None, _pg_init_and_activate)
            except Exception:
                pass
        applied[k] = {"length": len(v)}
        if db_queue is not None:
            try:
                db_queue.put_nowait(("set_secret", (k, v, _t.time())))
            except asyncio.QueueFull:
                pass

    if applied:
        _refresh_integration_state(globals())
        # If MaxMind license was newly set, kick off a fetch (returns fast;
        # the actual download runs async in the executor).
        if "MAXMIND_LICENSE_KEY" in applied:
            try:
                loop = asyncio.get_running_loop()
                loop.run_in_executor(None, _maxmind_auto_fetch)
            except Exception:
                pass
        slog("secrets_changed", level="warn", rid=request.get("_rid", ""),
             applied=list(applied.keys()),
             rejected=list(rejected.keys()))

    return web.json_response({
        "ok":       len(applied) > 0 and len(rejected) == 0,
        "applied":  applied, "rejected": rejected,
        "integration_state": {
            "_TURNSTILE_CONFIGURED": _TURNSTILE_CONFIGURED,
            "TURNSTILE_ENABLED":     TURNSTILE_ENABLED,
            "ABUSEIPDB_ENABLED":     ABUSEIPDB_ENABLED,
            "CROWDSEC_ENABLED":      CROWDSEC_ENABLED,
            "MAXMIND_ENABLED":       MAXMIND_ENABLED,
        },
    }, headers={"Cache-Control": "no-store"})


async def rotate_keys_endpoint(request: web.Request):
    """1.4.5: rotate the SESSION_KEY (and optionally POW key) atomically.

    Every cookie HMAC-signed under the old key fails verification immediately
    after this returns. Useful after upgrading the gateway, after an
    incident, or on a schedule via cron. The new key is persisted to disk
    (`.session_key` / `.pow_key`) so subsequent restarts pick it up.

    Query params:
      ?scope=session  (default) — rotate SESSION_KEY only (chal + session
                                  cookies invalidated; PoW challenges still
                                  validate against existing pow key).
      ?scope=pow                — rotate POW_HMAC_KEY only (PoW challenges
                                  in flight invalidated).
      ?scope=all                — rotate both.
    """
    if denied := _role_denied(request, "admin"):
        return denied
    global SESSION_KEY, POW_HMAC_KEY
    scope = request.query.get("scope", "session").lower()
    rotated = []
    if scope in ("session", "all"):
        new_sess = secrets.token_bytes(32)
        try:
            with open(_SESS_KEY_FILE, "w") as f:
                f.write(new_sess.hex())
            try:
                os.chmod(_SESS_KEY_FILE, 0o600)
            except OSError:
                pass
        except OSError as e:
            return web.json_response(
                {"error": f"persist failed: {e}"}, status=500,
                headers={"Cache-Control": "no-store"})
        SESSION_KEY = new_sess
        rotated.append("session")
    if scope in ("pow", "all"):
        new_pow = secrets.token_bytes(32)
        try:
            with open(_POW_KEY_FILE, "w") as f:
                f.write(new_pow.hex())
            try:
                os.chmod(_POW_KEY_FILE, 0o600)
            except OSError:
                pass
        except OSError as e:
            return web.json_response(
                {"error": f"persist failed: {e}"}, status=500,
                headers={"Cache-Control": "no-store"})
        POW_HMAC_KEY = new_pow
        rotated.append("pow")
    if not rotated:
        return web.json_response(
            {"error": "scope must be one of: session, pow, all"},
            status=400, headers={"Cache-Control": "no-store"})
    print(f"[rotate-keys] rotated: {','.join(rotated)} "
          f"(every cookie issued before this point now fails HMAC)",
          flush=True)
    return web.json_response(
        {"rotated": rotated,
         "note": "all chal/session cookies issued before this call now fail "
                 "HMAC verification. The next legitimate visitor will be "
                 "issued a fresh cookie."},
        headers={"Cache-Control": "no-store"})


# ── 1.4.7 — hot-reload admin endpoint ─────────────────────────────────────
# A small whitelist of runtime knobs that ops can read or update without
# bouncing the container. Each entry is (parser, validator). Anything not
# on this list is rejected explicitly so the endpoint can never be used to
# clobber the SESSION_KEY, alter the upstream URL, or otherwise reach into
# state that is intentionally bound at startup.
# NOTE: _to_bool / _to_path_list / _to_ja4_set etc. come from integrations.*

def _to_bot_uas_list(v):
    """Convert AUTHORIZED_BOT_UAS — accepts list-of-dicts (JSON POST) or string."""
    return _parse_authorized_bot_uas(v)


def _upstream_safe_to_reload(v: str) -> bool:
    # PROXY4-01: hot-reload UPSTREAM must pass the same public-IP check as the
    # startup validator — not just a scheme/length check.
    if not v.startswith(("http://", "https://")) or len(v) > 2048:
        return False
    if globals().get("ALLOW_PRIVATE_UPSTREAM"):
        return True
    # Inline private-IP guard so the check honours the LOCAL flag, not
    # vhost._cfg.ALLOW_PRIVATE_UPSTREAM (a separate module-level copy).
    try:
        import urllib.parse as _up
        import socket as _sock
        import ipaddress as _ipa
        from vhost import _PRIVATE_NETS
        _host = _up.urlparse(v).hostname
        if not _host:
            return False
        try:
            _addrs = {r[4][0] for r in _sock.getaddrinfo(_host, None)}
        except _sock.gaierror:
            return True  # DNS failure — let runtime handle
        for _a in _addrs:
            try:
                _ip = _ipa.ip_address(_a)
                if isinstance(_ip, _ipa.IPv6Address) and _ip.ipv4_mapped:
                    _ip = _ip.ipv4_mapped
            except ValueError:
                continue
            for _net in _PRIVATE_NETS:
                if _ip in _net:
                    return False
        return True
    except Exception:
        return True


def _ssrf_guard_url(url: str, label: str = "", allow_loopback: bool = False) -> None:
    """Raise ValueError if *url* resolves to a private / cloud-metadata address.

    Used to guard URL-type secrets (CROWDSEC_LAPI_URL, OIDC_ISSUER) so an
    authenticated operator cannot weaponise the gateway as an SSRF vector by
    pointing a reputation URL at http://169.254.169.254/ or an internal service.

    allow_loopback=True exempts 127.0.0.0/8 and ::1 (CrowdSec sidecar pattern).
    Skipped entirely when ALLOW_PRIVATE_UPSTREAM=1 for parity with upstream guard.
    """
    if globals().get("ALLOW_PRIVATE_UPSTREAM"):
        return
    import urllib.parse as _up2
    import socket as _sock2
    import ipaddress as _ipa2
    from vhost import _PRIVATE_NETS as _PN
    parsed = _up2.urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"SSRF guard: {label or 'url'!r} has no hostname")
    try:
        addrs = {r[4][0] for r in _sock2.getaddrinfo(host, None)}
    except _sock2.gaierror:
        return  # DNS failure — let runtime handle
    for addr_str in addrs:
        try:
            ip = _ipa2.ip_address(addr_str)
            if isinstance(ip, _ipa2.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
        except ValueError:
            continue
        for net in _PN:
            if allow_loopback and net.overlaps(_ipa2.ip_network("127.0.0.0/8")):
                continue
            if allow_loopback and net.overlaps(_ipa2.ip_network("::1/128")):
                continue
            if ip in net:
                slog("ssrf_guard_blocked", level="warn",
                     label=label or url[:60], ip=str(ip), net=str(net))
                raise ValueError(
                    f"SSRF guard: {label or url[:60]!r} resolves to private "
                    f"address {ip} ({net}). Use ALLOW_PRIVATE_UPSTREAM=1 to permit.")


# Secrets that carry HTTP URLs and need an SSRF check on write.
# allow_loopback=True: CrowdSec LAPI may legitimately run as a sidecar on 127.x.
_URL_SECRET_GUARDS: dict = {
    "CROWDSEC_LAPI_URL": True,   # allow_loopback=True
    "OIDC_ISSUER":       False,  # public OIDC provider expected; block all private IPs
}


# name -> (parser, optional validator returning bool)
_HOT_RELOAD_KNOBS = {
    # Toggles (booleans)
    "JS_CHALLENGE":            (_to_bool, None),
    "BOT_TRAP_FORMS":          (_to_bool, None),
    "BODY_PATTERN_MATCH":      (_to_bool, None),
    "CANARY_ECHO_DETECTION":   (_to_bool, None),
    "STRICT_ORIGIN":           (_to_bool, None),
    "INJECT_SECURITY_HEADERS": (_to_bool, None),
    "JS_CHAL_BIND_JA4":        (_to_bool, None),
    "JS_CHAL_REQUIRE_JA4":     (_to_bool, None),
    "JS_CHAL_STRICT_STATIC":   (_to_bool, None),
    # 1.5.4: external integration kill-switches. Setting to True is rejected
    # when the underlying credentials/files aren't configured (no point
    # enabling an integration whose required env is missing). Setting False
    # is always accepted — operator can disable a live integration without
    # restart.
    "ABUSEIPDB_ENABLED":  (_to_bool, lambda v: (not v) or bool(globals().get("ABUSEIPDB_KEY"))),
    "CROWDSEC_ENABLED":   (_to_bool, lambda v: (not v) or bool(globals().get("CROWDSEC_LAPI_URL") and globals().get("CROWDSEC_API_KEY"))),
    "MAXMIND_ENABLED":    (_to_bool, lambda v: (not v) or globals().get("_asn_reader") is not None),
    "TURNSTILE_ENABLED":  (_to_bool, lambda v: (not v) or bool(globals().get("TURNSTILE_SITEKEY") and globals().get("TURNSTILE_SECRET"))),
    # 1.5.4: per-detector kill-switches (default ON). Operator can mute a
    # noisy heuristic without a container restart.
    "WAF_BODY_ENABLED":             (_to_bool, None),
    "WAF_SMUGGLING_ENABLED":           (_to_bool, None),
    "WAF_VERB_OVERRIDE_ENABLED":       (_to_bool, None),
    "WAF_HEADER_INJECTION_ENABLED":    (_to_bool, None),
    "WAF_GRAPHQL_ENABLED":             (_to_bool, None),
    "WAF_UPLOAD_ENABLED":              (_to_bool, None),
    "WAF_SLOWLORIS_ENABLED":           (_to_bool, None),
    "ACCEPT_WILDCARD_CHECK_ENABLED":   (_to_bool, None),
    "SESSION_CHURN_ENABLED":           (_to_bool, None),
    "JA4H_DENY_ENABLED":               (_to_bool, None),
    "HOST_BLOCKING_ENABLED":           (_to_bool, None),
    "REQUIRED_HEADERS_ENABLED":        (_to_bool, None),
    "JA4_REQUIRED_ENABLED":            (_to_bool, None),
    "UPSTREAM_AUTH_FAIL_ENABLED":      (_to_bool, None),
    "RATE_LIMIT_IP_ENABLED":           (_to_bool, None),
    "RATE_LIMIT_ENABLED":              (_to_bool, None),
    "FP_BAN_CHECK_ENABLED":            (_to_bool, None),
    "TRAFFIC_THRESHOLD_ENABLED":       (_to_bool, None),
    "TLS_FP_BLOCK_ENABLED":            (_to_bool, None),
    "JWT_VALIDATION_ENABLED":          (_to_bool, None),
    "CUSTOM_RULES_ENABLED":            (_to_bool, None),
    "ENDPOINT_RATE_LIMIT_ENABLED":     (_to_bool, None),
    "HONEY_CRED_ENABLED":              (_to_bool, None),
    "CANARY_PROBE_ENABLED":            (_to_bool, None),
    "LLM_HEURISTIC_ENABLED":           (_to_bool, None),
    "AUTOMATION_PROBE_ENABLED":        (_to_bool, None),
    "INTERACTION_PROBE_ENABLED":       (_to_bool, None),
    "COORDINATED_ATTACK_ENABLED":      (_to_bool, None),
    "JOURNEY_CHECK_ENABLED":           (_to_bool, None),
    "HONEYPOT_ENABLED":                (_to_bool, None),
    "SUSPICIOUS_PATH_ENABLED":     (_to_bool, None),
    "AI_PROBE_ENABLED":            (_to_bool, None),
    "UA_FILTER_ENABLED":           (_to_bool, None),
    "UA_PLATFORM_CHECK_ENABLED":   (_to_bool, None),
    "HEADER_COMPLETENESS_ENABLED": (_to_bool, None),
    "BEHAVIORAL_CHECK_ENABLED":    (_to_bool, None),
    "AI_ENUMERATION_ENABLED":      (_to_bool, None),
    "AI_NO_ASSETS_ENABLED":        (_to_bool, None),
    "SESSION_FLOOD_ENABLED":       (_to_bool, None),
    "UPSTREAM_404_TRACKING_ENABLED": (_to_bool, None),
    # 1.5.4 Anubis-mode (strict PoW gate)
    "ANUBIS_ENABLED":              (_to_bool, None),
    "ANUBIS_DIFFICULTY_BOOST":     (int,   lambda v: 0 <= v <= 6),
    # 1.5.4 — risk threshold (>=this) above which Turnstile is shown to a
    # cookieless client. 0 = auto = midpoint of orange band.
    "TURNSTILE_RISK_THRESHOLD":    (float, lambda v: 0.0 <= v <= 100000.0),
    # Numeric thresholds (with sane bounds)
    "RISK_BAN_THRESHOLD":     (int,   lambda v: 1 <= v <= 100000),
    "SOFT_CHALLENGE_SCORE":   (float, lambda v: 0.0 <= v <= 100000.0),
    "RATE_LIMIT_BURST":       (int,   lambda v: 1 <= v <= 100000),
    "RATE_LIMIT_REFILL":      (float, lambda v: 0.0 < v <= 10000.0),
    "IP_BURST":               (int,   lambda v: 1 <= v <= 100000),
    "IP_REFILL":              (float, lambda v: 0.0 < v <= 10000.0),
    "HOSTILE_BAN_SECS":       (int,   lambda v: 60 <= v <= 31 * 86400),
    "REALLY_BAN_SECS":        (int,   lambda v: 60 <= v <= 365 * 86400),
    "CANARY_TTL_S":           (int,   lambda v: 30 <= v <= 86400),
    "GLOBAL_RPS_LIMIT":       (int,   lambda v: 0 <= v <= 1000000),
    "SESSION_CHURN_WINDOW_S": (int,   lambda v: 5 <= v <= 86400),
    "SESSION_CHURN_MAX":      (int,   lambda v: 1 <= v <= 10000),
    "JA4_AUTODENY_THRESHOLD": (int,   lambda v: 1 <= v <= 1000),
    # Lists (comma-separated str -> list/set)
    "AUTHORIZED_BOT_UAS":     (_to_bot_uas_list, None),
    "BYPASS_PATHS":           (_to_path_list, None),
    "JS_CHAL_OPEN_PATHS":     (_to_path_list, None),
    "JA4_DENY_LIST":          (_to_ja4_set,   None),
    # 1.6.0 — country-level geo block (requires GeoLite2-City)
    "COUNTRY_BLOCK_ENABLED":  (_to_bool,
                                lambda v: (not v) or _city_reader_is_loaded()),
    "COUNTRY_DENYLIST":       (_to_country_set, None),
    "COUNTRY_ALLOWLIST":      (_to_country_set, None),
    # 1.6.0 — AI-crawler granular groups
    "AI_UA_OPENAI_ENABLED":     (_to_bool, None),
    "AI_UA_ANTHROPIC_ENABLED":  (_to_bool, None),
    "AI_UA_GOOGLE_ENABLED":     (_to_bool, None),
    "AI_UA_PERPLEXITY_ENABLED": (_to_bool, None),
    "AI_UA_META_ENABLED":       (_to_bool, None),
    "AI_UA_OTHER_ENABLED":      (_to_bool, None),
    # 1.6.0 — network-list integration (Tor + DC/VPN)
    "TOR_BLOCK_ENABLED":      (_to_bool, None),
    "DC_VPN_BLOCK_ENABLED":   (_to_bool, None),
    # 1.6.0 — per-endpoint policy engine (JSON array)
    "ENDPOINT_POLICIES":      (_to_endpoint_policies, None),
    # 1.6.1 — Tier-B knobs
    "CUSTOM_RULES":           (_to_custom_rules, None),
    "BODY_GROUP_SQLI_ENABLED":(_to_bool, None),
    "BODY_GROUP_XSS_ENABLED": (_to_bool, None),
    "BODY_GROUP_LFI_ENABLED": (_to_bool, None),
    "BODY_GROUP_RCE_ENABLED": (_to_bool, None),
    "BODY_GROUP_SSRF_ENABLED":(_to_bool, None),
    "BODY_GROUP_CMD_ENABLED": (_to_bool, None),
    "JWT_VALIDATE_PATHS":     (_to_path_list, None),
    "JWT_REQUIRED_ISSUER":    (str, lambda v: len(v) <= 256),
    "JWT_REQUIRED_AUDIENCE":  (str, lambda v: len(v) <= 256),
    # 1.6.2 — Tier-C: outbound DLP knobs
    "DLP_ENABLED":            (_to_bool, None),
    "DLP_REDACT":             (_to_bool, None),
    "DLP_MAX_BYTES":          (int, lambda v: 1024 <= v <= 16 * 1024 * 1024),
    "DLP_GROUP_CC_ENABLED":           (_to_bool, None),
    "DLP_GROUP_AWS_ENABLED":          (_to_bool, None),
    "DLP_GROUP_JWT_ENABLED":          (_to_bool, None),
    "DLP_GROUP_PRIVATE_KEY_ENABLED":  (_to_bool, None),
    "DLP_GROUP_API_KEY_ENABLED":      (_to_bool, None),
    "DLP_GROUP_PII_EMAIL_ENABLED":    (_to_bool, None),
    "DLP_GROUP_PII_SSN_ENABLED":      (_to_bool, None),
    # 1.6.2 — webhook event filter (CSV of reasons)
    "WEBHOOK_EVENT_FILTER":   (_to_path_list, None),
    # 1.6.4 — event-store backend selector. The runtime knob is REFLECTED
    # in /__config but the backend itself is bound at startup; mutating
    # this value at runtime updates the displayed setting (useful for
    # operators staging a migration) but won't switch live connections
    # until the container restarts.
    "STRICT_VHOST":            (_to_bool, None),
    "UPSTREAM_REWRITE_BASE":   (str, lambda v: len(v) <= 2048 and (v == "" or v.startswith(("http://", "https://")))),
    "SERVICE_OWNER":          (str, lambda v: len(v) <= 128),
    "DB_BACKEND":             (str, lambda v: v in ("sqlite", "postgres")),
    "POSTGRES_DSN":           (str, lambda v: len(v) <= 1024),
    # 1.6.5 — escalation threshold (cost gate for expensive / 3rd-order detectors)
    "ESCALATION_THRESHOLD":   (float, lambda v: 0.0 <= v <= 100000.0),
    # 1.6.10 — 2nd-order gate threshold (behavioral / enumeration detectors)
    "SECOND_ORDER_THRESHOLD": (float, lambda v: 0.0 <= v <= 100000.0),
    # 1.6.5 — tarpit (artificial slowdown for soft-band identities)
    "TARPIT_ENABLED":         (_to_bool, None),
    "TARPIT_DELAY_MS":        (int, lambda v: 0 <= v <= 30000),
    # 1.6.8 — AI Labyrinth (hidden nofollow maze for bots)
    "LABYRINTH_ENABLED":        (_to_bool, None),
    "LABYRINTH_SLOW_MS":        (int, lambda v: 0 <= v <= 30000),
    "LABYRINTH_MAX_DEPTH":      (int, lambda v: 1 <= v <= 20),
    "LABYRINTH_LINKS_PER":      (int, lambda v: 1 <= v <= 10),
    "LABYRINTH_JITTER_ENABLED": (_to_bool, None),
    "ACCEPT_FP_ENABLED":        (_to_bool, None),
    "HEADER_CANARY_ENABLED":    (_to_bool, None),
    # 1.6.10 — new detection knobs
    "HEADER_ORDER_FP_ENABLED":   (_to_bool, None),
    "AI_CRAWLER_VERIFY_ENABLED": (_to_bool, None),
    "JA4_FAIL_CLOSED":           (_to_bool, None),
    "JSON_CANARY_ENABLED":       (_to_bool, None),
    "LOCALE_GEO_CHECK_ENABLED":  (_to_bool, lambda v: (not v) or _city_reader_is_loaded()),
    "ROBOTS_MONITOR_ENABLED":    (_to_bool, None),
    "H2_FP_ENABLED":             (_to_bool, None),
    "POW_MIN_SOLVE_MS":          (int, lambda v: 0 <= v <= 5000),
    # 1.6.5 — FingerprintJS BotD client-side detection
    "BOTD_ENABLED":           (_to_bool, None),
    # 1.7.8 — Dashboard bypass mode (all detection + ban enforcement off).
    # Listed as NOT_PERSIST so it resets to False on container restart.
    "BYPASS_MODE":            (_to_bool, None),
    # 1.8.10 — Global bot-detection master switch (per-vhost via vc(); global via hot-reload).
    "BOT_DETECTION_ENABLED":  (_to_bool, None),
    # Logging
    "LOG_LEVEL":              (str,   lambda v: v.lower() in _LOG_LEVELS),
    # 1.5.5 — Tier 1 promotions (high operational value, often tuned during incidents)
    "JS_CHALLENGE_TTL":       (int,   lambda v: 60 <= v <= 86400 * 7),
    "ENUM_THRESHOLD":         (int,   lambda v: 10 <= v <= 100000),
    "TIMELINE_RETAIN_SECS":   (int,   lambda v: 60 <= v <= 31536000),     # up to 1 year
    "SVC_DB_RETENTION_HOURS": (int,   lambda v: 1 <= v <= 8760),          # up to 1 year
    # 1.5.5 — Tier 2 promotions (lower frequency but useful)
    "COST_RETAIN_SECS":       (int,   lambda v: 60 <= v <= 2592000),
    "LOG_FORMAT":             (str,   lambda v: v.lower() in ("json", "text")),
    "POW_REQUIRED_PATHS":     (_to_path_list, None),
    "ALLOWED_METHODS":        (_to_method_set,
                               lambda v: bool(v) and all(m in {"GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"} for m in v)),
    # 1.5.5 — Tier 3 promotions (advanced — change with care)
    "ALLOWED_HOSTS":          (_to_host_set, None),   # empty set = no enforcement
    "MAX_IDENTITIES":         (int,   lambda v: 100 <= v <= 10000000),
    "PRUNE_IDLE_SECS":        (int,   lambda v: 60 <= v <= 31 * 86400),
    "UPSTREAM_MAX_BODY":      (int,   lambda v: 1024 <= v <= 1024 * 1024 * 1024),  # up to 1 GiB
    "UPSTREAM_MAX_RESP":      (int,   lambda v: 1024 <= v <= 1024 * 1024 * 1024),
    # ── 1.7.2 ──
    "COOKIE_GHOST_ENABLED":         (_to_bool, None),
    "COOKIE_LIFECYCLE_ENABLED":     (_to_bool, None),
    "COOKIE_GHOST_MIN_REQUESTS":    (int,   lambda v: 1 <= v <= 1000),
    "COOKIE_GHOST_MISS_THRESHOLD":  (int,   lambda v: 1 <= v <= 100),
    "REFERER_CHAIN_ENABLED":        (_to_bool, None),
    "IMPOSSIBLE_TRAVEL_ENABLED":    (_to_bool,
                                     lambda v: (not v) or _city_reader_is_loaded()),
    "IMPOSSIBLE_TRAVEL_WINDOW_SECS":(int,   lambda v: 60 <= v <= 86400 * 7),
    "FP_ENRICHMENT_ENABLED":        (_to_bool, None),
    "SW_CHALLENGE_ENABLED":         (_to_bool, None),
    "POW_CHAL_THRESHOLD":           (float, lambda v: 0.0 <= v <= 100000.0),
    # 1.7.9 — runtime upstream switch (always overrideable regardless of env pin)
    # PROXY4-01: validator now calls _assert_upstream_public to prevent SSRF.
    "UPSTREAM": (lambda v: str(v).rstrip("/"), _upstream_safe_to_reload),
    # 1.8.8 — Redis IP allowlist (comma/newline-separated CIDRs).
    # Empty = no restriction. When set, the gateway refuses to use a Redis
    # connection whose resolved host IP falls outside the list. Takes effect
    # on the next ban read/write after hot-reload (no reconnect required).
    "REDIS_ALLOW_LIST": (_to_ip_net_list, None),
    # XFF trust — hot-reload updates both TRUST_XFF and TRUSTED_PROXIES_NETS
    "TRUST_XFF":       (lambda v: str(v).lower(), lambda v: v in ("none", "first", "last")),
    "TRUSTED_PROXIES": (_to_ip_net_list, None),
    "ALLOW_PRIVATE_UPSTREAM": (_to_bool, None),
    # 1.8.11 QW-1 — extra honeypot paths (JSON array of strings).
    # Stored as the *extra* paths only; the post-apply hook below merges
    # them into HONEYPOT_PATHS so the live detection set is updated.
    "HONEYPOT_EXTRA_PATHS": (_to_path_list, None),
    # 1.8.12 — honeypot learning subsystem knobs
    "HONEYPOT_CLUSTER_THRESHOLD": (int, lambda v: 2 <= v <= 100),
    # 1.8.11 QW-6 — behavioral detector thresholds
    "BEHAVIORAL_SAMPLE_N":          (int,   lambda v: 4 <= v <= 100),
    "BEHAVIORAL_COV_THRESHOLD":     (float, lambda v: 0.0 < v <= 1.0),
    "BEHAVIORAL_R1_THRESHOLD":      (float, lambda v: 0.0 < v <= 1.0),
    "BEHAVIORAL_BIN_PCT_THRESHOLD": (float, lambda v: 0.0 < v <= 1.0),
    "BEHAVIORAL_MAX_INTERVAL_S":    (float, lambda v: 0.1 <= v <= 60.0),
    "BEHAVIORAL_SKIP_INTERVAL_S":   (float, lambda v: 0.1 <= v <= 300.0),
}

# 1.5.5 — env-override detection.  By default the DB takes precedence over
# env (operators tuning live via /__config get their changes back on
# restart).  Set `CONFIG_KV_STRICT_ENV=1` for GitOps-style determinism
# where env values are authoritative and dashboard mutations are rejected
# at runtime.
# Any knob explicitly set to a non-empty value in the environment is pinned:
# the DB config_kv row from a previous run cannot silently override operator
# intent expressed in .env / container env.  CONFIG_KV_STRICT_ENV=1 extends
# this to knobs that are present in the environment even with an empty value
# (full GitOps-style lock-out of dashboard mutations).
# TURNSTILE_ENABLED and JS_CHALLENGE are intentionally excluded: the env sets
# the startup default but the dashboard must be able to toggle them at runtime
# (e.g. disabling Turnstile for a maintenance window without a container restart).
# ALLOW_PRIVATE_UPSTREAM is excluded by operator request: the env value is the
# cold-start default, but the SSRF guard can be toggled at runtime from Settings
# and the change persists (DB-wins on restart). NOTE: this lets an admin disable
# the SSRF guard without a container restart — acceptable for trusted internal
# deployments where operational flexibility outweighs the GitOps lock.
# Knobs that are NOT persisted to the config_kv DB table. They remain
# session-only and always reset to their default on container restart.
# BYPASS_MODE is intentionally here: it's an incident-response toggle that
# must default to False on every cold start for safety.
_NOT_PERSIST_KNOBS: frozenset = frozenset({"BYPASS_MODE"})

_ENV_PIN_EXCLUDE = {"TURNSTILE_ENABLED", "JS_CHALLENGE", "UPSTREAM",
                    "ALLOW_PRIVATE_UPSTREAM", "SERVICE_OWNER"}


def _env_knob_is_provided(k: str) -> bool:
    """Return True if env var k should pin its knob.

    For boolean knobs (parser is _to_bool): "0"/"false"/"no"/"off" returns
    False so the DB can still re-enable the feature (DB-wins by default in
    non-strict mode).  For all other knobs (int, float, str, list parsers):
    any non-empty value counts as "operator provided this" and pins it.
    """
    val = os.environ.get(k, "")
    if not val.strip():
        return False
    spec = _HOT_RELOAD_KNOBS.get(k)
    if spec is not None and spec[0] is _to_bool:
        try:
            return _to_bool(val)
        except ValueError:
            return False
    return True


_ENV_PROVIDED_KNOBS = {
    k for k in _HOT_RELOAD_KNOBS
    if k not in _ENV_PIN_EXCLUDE and _env_knob_is_provided(k)
}
if os.environ.get("CONFIG_KV_STRICT_ENV", "0") in ("1", "true", "yes"):
    _ENV_PROVIDED_KNOBS |= {k for k in _HOT_RELOAD_KNOBS
                             if k not in _ENV_PIN_EXCLUDE and k in os.environ}
# DB_BACKEND is env-pinned only when set to a meaningful value ("sqlite" or
# "postgres"). An empty-string env var (compose default when operator omits it)
# is NOT treated as authoritative so the DB-persisted backend survives restart.
if os.environ.get("DB_BACKEND", "").strip() in ("sqlite", "postgres"):
    _ENV_PROVIDED_KNOBS = _ENV_PROVIDED_KNOBS | {"DB_BACKEND"}
if "STRICT_VHOST" in os.environ:
    _ENV_PROVIDED_KNOBS = _ENV_PROVIDED_KNOBS | {"STRICT_VHOST"}
if "UPSTREAM_REWRITE_BASE" in os.environ:
    _ENV_PROVIDED_KNOBS = _ENV_PROVIDED_KNOBS | {"UPSTREAM_REWRITE_BASE"}


def _json_safe(v):
    """Recursively strip private _ keys from dicts (e.g. compiled ip_network
    objects stored in CUSTOM_RULES._ip_nets) so the state is always
    JSON-serialisable without a custom encoder."""
    if isinstance(v, list):
        return [_json_safe(i) for i in v]
    if isinstance(v, dict):
        return {k: _json_safe(val) for k, val in v.items()
                if not k.startswith("_")}
    return v


def _read_hot_reload_state() -> dict:
    out = {}
    g = globals()
    for k in _HOT_RELOAD_KNOBS:
        if k not in g:
            continue
        v = g[k]
        # Sets are not JSON-serialisable directly.
        if isinstance(v, set):
            v = sorted(v)
        out[k] = _json_safe(v)
    return out


async def ui_theme_endpoint(request: web.Request):
    """GET  /secured/ui-theme  → {"theme": "dark"|"light"}
    POST /secured/ui-theme  {"theme": "dark"|"light"} → persist to config_kv (SQLite + Postgres)."""
    from db.sqlite import get_ui_theme as _get_theme
    if request.method == "GET":
        theme = _get_theme(DB_PATH)
        return web.json_response({"theme": theme}, headers={"Cache-Control": "no-store"})
    if request.method != "POST":
        return web.json_response({"error": "method not allowed"}, status=405,
                                  headers={"Cache-Control": "no-store"})
    try:
        raw = await asyncio.wait_for(request.content.read(256), timeout=BODY_TIMEOUT)
        body = json.loads(raw.decode("utf-8") or "{}")
        theme = body.get("theme", "dark")
        if theme not in ("dark", "light"):
            return web.json_response({"error": "theme must be 'dark' or 'light'"}, status=400,
                                      headers={"Cache-Control": "no-store"})
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    if db_queue is not None:
        try:
            db_queue.put_nowait(("set_config", ("ui_theme", json.dumps(theme), _t.time())))
        except asyncio.QueueFull:
            pass
    return web.json_response({"theme": theme}, headers={"Cache-Control": "no-store"})


async def csrf_endpoint(request: web.Request):
    """GET <NS>/secured/csrf — return the CURRENT CSRF token for the caller's
    session as JSON: {"token": "<hex>"}.

    The token is HMAC(SESSION_KEY, sid)[:32], derived from the live agw_session
    cookie — so it is always correct even when:
      • a CDN (e.g. Cloudflare) rewrote agw_csrf to HttpOnly (JS can't read it);
      • the session rotated after page load, leaving the injected
        window.__AGW_CSRF__ global stale.
    The dashboard fetch shim calls this on a 403 to self-heal the token and
    retry once, so operators never have to clear cookies. Auth is enforced by
    the protect middleware (admin path); GET needs no CSRF of its own.
    """
    sid = request.get("_session_sid", "") if hasattr(request, "get") else ""
    if not sid:
        from admin.users import _session_parse, _SESSION_COOKIE
        _ck = request.cookies.get(_SESSION_COOKIE, "") if getattr(request, "cookies", None) else ""
        _p = _session_parse(_ck) if _ck else None
        sid = _p[1] if _p else ""
    if not sid:
        return web.json_response({"error": "auth"}, status=401,
                                 headers={"Cache-Control": "no-store"})
    import hmac as _hm_c
    import hashlib as _hh_c
    token = _hm_c.new(SESSION_KEY, sid.encode(), _hh_c.sha256).hexdigest()[:32]
    return web.json_response({"token": token}, headers={"Cache-Control": "no-store"})


@_require_csrf
async def config_endpoint(request: web.Request):
    """GET  /__config?key=...              -> current state of all hot-reloadable knobs.
    POST /__config?key=...  + JSON body -> apply updates, return {applied,rejected,state}.
    POST body must be a JSON object whose keys are knob names; values are
    type-coerced and bounds-checked. Anything not in the whitelist is
    rejected (explicit allowlist — never an attribute-write attack)."""
    if request.method == "GET":
        _vhost_q = request.query.get("vhost", "").strip().lower()
        _base = _read_hot_reload_state()
        try:
            from vhost import VHOSTS as _VH, _json_safe as _vjs
        except Exception:
            _VH, _vjs = {}, lambda x: x  # noqa: E731
        _all_vhosts = sorted(_VH.keys())
        # 1.8.9 — surface env-pinned knobs so the Controls UI can render them
        # read-only with a badge instead of letting the operator edit and
        # then bounce off "env-pinned" rejection from POST /config.
        _env_pinned = sorted(_ENV_PROVIDED_KNOBS)
        if _vhost_q:
            _ov_raw = _VH.get(_vhost_q, {})
            _merged = dict(_base)
            _overridden: list = []
            for _k, _v in _ov_raw.items():
                _ku = _k.upper()
                _merged[_ku] = _vjs(_v)
                _overridden.append(_ku)
            return web.json_response(
                {"state": _merged, "vhost": _vhost_q,
                 "overridden": sorted(_overridden), "vhosts": _all_vhosts,
                 "env_pinned": _env_pinned},
                headers={"Cache-Control": "no-store"})
        return web.json_response(
            {"state": _base, "vhost": "", "overridden": [], "vhosts": _all_vhosts,
             "env_pinned": _env_pinned},
            headers={"Cache-Control": "no-store"})
    if request.method != "POST":
        return web.json_response({"error": "method not allowed"}, status=405,
                                  headers={"Cache-Control": "no-store"})
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    try:
        raw = await asyncio.wait_for(request.content.read(64 * 1024),
                                      timeout=BODY_TIMEOUT)
        updates = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(updates, dict):
            raise ValueError("body must be a JSON object")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})

    # Per-vhost override writes — ?vhost=<host> routes through vhost_set()
    _vhost_target = request.query.get("vhost", "").strip().lower()
    if _vhost_target:
        try:
            from vhost import vhost_set as _vhost_set_fn, _VHOST_COERCE as _VHC
        except ImportError as _imp_e:
            return web.json_response({"error": f"vhost module unavailable: {_imp_e}"},
                                      status=500, headers={"Cache-Control": "no-store"})
        _vhost_overrides: dict = {}
        _vhost_rejected: dict = {}
        for _k, _raw_v in updates.items():
            _ku = _k.upper()
            _coerce = _VHC.get(_ku)
            if _coerce is None:
                _vhost_rejected[_k] = "not-vhost-overridable"
                continue
            try:
                _vhost_overrides[_ku] = _coerce(_raw_v)
            except (ValueError, TypeError) as _ce:
                _vhost_rejected[_k] = str(_ce)[:120]
        _vhost_applied: dict = {}
        if _vhost_overrides:
            _ok, _err = _vhost_set_fn(_vhost_target, _vhost_overrides)
            if not _ok:
                return web.json_response({"error": _err}, status=400,
                                          headers={"Cache-Control": "no-store"})
            _vhost_applied = {
                k: (sorted(v) if isinstance(v, (frozenset, set)) else v)
                for k, v in _vhost_overrides.items()
            }
            slog("config_vhost_changed", level="warn",
                 rid=request.get("_rid", ""), actor=_request_username(request),
                 vhost=_vhost_target,
                 applied=list(_vhost_applied.keys()), rejected=_vhost_rejected)
            if db_queue is not None:
                _det = json.dumps(
                    {"vhost": _vhost_target, "applied": list(_vhost_applied.keys())},
                    separators=(",", ":"), default=str)
                try:
                    db_queue.put_nowait((
                        "gw_audit_add",
                        (_t.time(), "config_vhost_change", _gw_local_id(),
                         _request_username(request), _det),
                    ))
                except asyncio.QueueFull:
                    pass
        return web.json_response(
            {"applied": _vhost_applied, "rejected": _vhost_rejected, "warnings": [],
             "vhost": _vhost_target, "state": _read_hot_reload_state()},
            headers={"Cache-Control": "no-store"})

    applied, rejected, warnings = {}, {}, []
    g = globals()
    for k, raw_v in updates.items():
        spec = _HOT_RELOAD_KNOBS.get(k)
        if spec is None:
            rejected[k] = "not-hot-reloadable"
            continue
        # 1.5.5 — env precedence. If the operator pinned this knob in
        # the container env, reject runtime mutations so GitOps-managed
        # deploys stay deterministic.
        if k in _ENV_PROVIDED_KNOBS:
            rejected[k] = "env-pinned (set via container env, not mutable at runtime)"
            continue
        parser, validator = spec
        try:
            old_v = g.get(k)
            value = parser(raw_v)
            if validator is not None and not validator(value):
                rejected[k] = "validation failed"
                continue
            g[k] = value
            # Propagate to all loaded modules (including proxy) so test patches
            # and hot-reload state are visible everywhere that reads this flag.
            import sys as _sys_hr
            for _hr_m in list(_sys_hr.modules.values()):
                if (_hr_m is not None and _hr_m is not _sys_hr.modules.get(__name__)
                        and hasattr(_hr_m, k)):
                    try:
                        setattr(_hr_m, k, value)
                    except (AttributeError, TypeError):
                        pass
            # LOG_LEVEL change must also update the derived numeric sentinel
            # _LOG_LEVEL_N that slog() uses for level filtering — it is not
            # in _HOT_RELOAD_KNOBS and not updated by the generic loop above.
            if k == "LOG_LEVEL":
                _new_level_n = _LOG_LEVELS.get(value, 20)
                g["_LOG_LEVEL_N"] = _new_level_n
                for _hr_m in list(_sys_hr.modules.values()):
                    if _hr_m is not None and hasattr(_hr_m, "_LOG_LEVEL_N"):
                        try:
                            setattr(_hr_m, "_LOG_LEVEL_N", _new_level_n)
                        except (AttributeError, TypeError):
                            pass
            # TRUSTED_PROXIES stores normalised CIDR strings; TRUSTED_PROXIES_NETS
            # holds ip_network objects used by helpers._peer_is_trusted_proxy.
            # Update both so in-flight requests immediately use the new list.
            if k == "TRUSTED_PROXIES":
                import ipaddress as _ipa_tp_hr
                _nets_hr = []
                for _c in value:
                    try:
                        _nets_hr.append(_ipa_tp_hr.ip_network(_c, strict=False))
                    except ValueError:
                        pass
                g["TRUSTED_PROXIES_NETS"] = _nets_hr
                for _hr_m in list(_sys_hr.modules.values()):
                    if _hr_m is not None and hasattr(_hr_m, "TRUSTED_PROXIES_NETS"):
                        try:
                            setattr(_hr_m, "TRUSTED_PROXIES_NETS", _nets_hr)
                        except (AttributeError, TypeError):
                            pass
            # 1.8.11 QW-1 — when extra honeypot paths change, rebuild the live
            # detection set by merging the new extras into the base set.
            if k == "HONEYPOT_EXTRA_PATHS":
                from config import HONEYPOT_PATHS as _HP_BASE
                _new_hp = _HP_BASE | set(value)
                g["HONEYPOT_PATHS"] = _new_hp
                for _hr_m in list(_sys_hr.modules.values()):
                    if _hr_m is not None and hasattr(_hr_m, "HONEYPOT_PATHS"):
                        try:
                            setattr(_hr_m, "HONEYPOT_PATHS", _new_hp)
                        except (AttributeError, TypeError):
                            pass
            applied[k] = sorted(value) if isinstance(value, set) else value
            if db_queue is not None:
                _old_safe = sorted(old_v) if isinstance(old_v, set) else old_v
                _det = json.dumps({"key": k, "old": _old_safe, "new": applied[k]},
                                   separators=(",", ":"), default=str)
                try:
                    db_queue.put_nowait((
                        "gw_audit_add",
                        (_t.time(), "config_change", _gw_local_id(),
                         _request_username(request), _det),
                    ))
                except asyncio.QueueFull:
                    pass
            # 1.7.9 — when UPSTREAM changes, flush the 404-body cache so the
            # new upstream gets a fresh probe on the next non-matching request.
            if k == "UPSTREAM":
                # .clear() keeps the same dict object so importers that held
                # `from core.proxy_handler import _upstream_404_cache` still
                # have a valid reference (= {} rebinds the name here, leaving
                # importers on the stale object → KeyError on next access).
                _upstream_404_cache.clear()  # mutating, not rebinding — no global needed
                slog("config_upstream_changed", level="info", new_upstream=value)
            # 1.5.5 — persist to DB so the change survives container restart.
            # JSON-encode so ints / floats / bools / strings / lists round-trip.
            # _NOT_PERSIST_KNOBS are session-only and intentionally not stored.
            if db_queue is not None and k not in _NOT_PERSIST_KNOBS:
                try:
                    db_queue.put_nowait((
                        "set_config",
                        (k, json.dumps(applied[k]), _t.time()),
                    ))
                except asyncio.QueueFull:
                    pass
        except (ValueError, TypeError) as e:
            rejected[k] = str(e)[:120]

    # Mutual exclusion: JS_CHAL_REQUIRE_JA4 and TURNSTILE_ENABLED cannot both
    # be active. Enforce after all updates are applied so that setting both
    # in one POST is also caught.
    def _mutex_propagate(key, val):
        g[key] = val
        import sys as _sys_mx
        for _m in list(_sys_mx.modules.values()):
            if _m is not None and hasattr(_m, key):
                try:
                    setattr(_m, key, val)
                except (AttributeError, TypeError):
                    pass
        applied[key] = val
        if db_queue is not None:
            try:
                db_queue.put_nowait(("set_config", (key, json.dumps(val), _t.time())))
            except asyncio.QueueFull:
                pass

    if applied.get("JS_CHAL_REQUIRE_JA4") is True and g.get("TURNSTILE_ENABLED"):
        _mutex_propagate("JS_CHAL_REQUIRE_JA4", False)
        warnings.append("JS_CHAL_REQUIRE_JA4 auto-disabled: "
                        "incompatible with TURNSTILE_ENABLED — "
                        "JA4 is unavailable when TLS is terminated by Cloudflare CDN")
        slog("config_mutex", level="warn", reason="ja4-required-blocked-by-turnstile")
    elif applied.get("TURNSTILE_ENABLED") is True and g.get("JS_CHAL_REQUIRE_JA4"):
        _mutex_propagate("JS_CHAL_REQUIRE_JA4", False)
        warnings.append("JS_CHAL_REQUIRE_JA4 auto-disabled: "
                        "incompatible with TURNSTILE_ENABLED")
        slog("config_mutex", level="warn", reason="turnstile-cleared-ja4-required")

    if applied or rejected:
        slog("config_changed", level="warn",
             rid=request.get("_rid", ""), actor=_request_username(request),
             applied=list(applied.keys()), rejected=rejected)
    return web.json_response(
        {"applied": _json_safe(applied), "rejected": rejected, "warnings": warnings,
         "state": _read_hot_reload_state()},
        headers={"Cache-Control": "no-store"})


async def status_endpoint(request: web.Request):
    async with state_lock:
        out = {}
        n = now()
        for ip, s in ip_state.items():
            elapsed = n - s.last_refill
            tokens = min(RATE_LIMIT_BURST, s.tokens + elapsed * RATE_LIMIT_REFILL)
            out[ip] = {
                "tokens": round(tokens, 2),
                "request_count": s.request_count,
                "banned_until": max(0, round(s.banned_until - n, 1)),
                "first_seen_secs_ago": round(n - s.first_seen, 1),
            }
    from state import _DETECTOR_HEALTH
    return web.json_response({"clients": out, "config": {
        "burst": RATE_LIMIT_BURST, "refill_per_sec": RATE_LIMIT_REFILL,
        "pow_difficulty": POW_DIFFICULTY, "honeypot_ban_secs": HONEYPOT_BAN_SECS,
    }, "detectors": _DETECTOR_HEALTH}, headers={"Cache-Control": "no-store"})
@web.middleware
async def protect(request: web.Request, handler):
    # 1.4.6 — request correlation. Honour an inbound X-Request-ID if it's
    # safe-looking (so a CDN / front-proxy / load balancer that already
    # tagged the request keeps its trace), otherwise mint a fresh short id.
    inbound_rid = request.headers.get(_REQUEST_ID_HEADER, "").strip()
    rid = (inbound_rid if inbound_rid and _REQUEST_ID_RE.match(inbound_rid)
           else _new_request_id())
    request["_rid"] = rid
    set_vhost(request.host or "")

    # L3+N5: reject paths/query with ANY ASCII control byte (0x00-0x1F or 0x7F).
    # CR/LF would enable header injection on legacy backends; NUL truncates
    # in C parsers; other control chars confuse normalisers. Whitespace stays
    # outside this range (0x20+) so legitimate URLs are unaffected.
    def _has_ctrl(s: str) -> bool:
        return any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)
    if _has_ctrl(request.path) or _has_ctrl(request.query_string or ""):
        return web.Response(status=400, text="bad request\n",
                            headers={_REQUEST_ID_HEADER: rid})

    # 1.6.7+: liveness probe is loopback-only. The container's HEALTHCHECK
    # connects via the container's own loopback (request.remote=127.0.0.1),
    # which is the only legitimate caller. Anyone else gets the upstream
    # 404 silent decoy — same as every other locked admin path.
    if request.path == ADMIN_NS + "/live":
        src = get_ip(request) or ""
        if src in ("127.0.0.1", "::1"):
            return web.Response(text="ok",
                                headers={"Cache-Control": "no-store",
                                         "Content-Type": "text/plain; charset=utf-8",
                                         _REQUEST_ID_HEADER: rid})
        ua = request.headers.get("User-Agent", "")
        await record(src, ua, request.path,
                      _upstream_404_cache.get("status") or 404,
                      "live-not-loopback", request_id=rid)
        return await _serve_mirrored_404()

    # v1.4 #1 — JS challenge: solver POSTs back here. Rate-limit by socket-IP
    # FIRST so an attacker can't burn proxy CPU (sha256 + JSON parse + dict
    # ops) hammering the challenge endpoint with bogus solutions.
    if request.path == ADMIN_NS + "/challenge":
        socket_ip = request.remote or "0.0.0.0"  # nosec B104 — fallback sentinel, not a bind address
        sip_ok, sip_retry = await take_socket_ip_token(socket_ip)
        if not sip_ok:
            return web.Response(
                status=429, text="rate limit\n",
                headers={"Retry-After": str(int(sip_retry) + 1),
                         "Cache-Control": "no-store"})
        return await js_challenge_endpoint(request)

    # NOTE: JS challenge gate moved BELOW the stealth-block checks (host /
    # TLS / origin / required-headers). Reason: on those checks we already
    # silent-decoy without revealing the gateway, and the challenge gate
    # must not preempt them with an explicit response.

    # 1.7.4 — AWS ELB / ALB health check pass-through.
    # ELB-HealthChecker/2.0 sends only Host + Connection + Accept-Encoding —
    # no Accept, Accept-Language, Sec-Fetch-* — which triggers ua-non-browser
    # (25 pts) and ai-headers-incomplete (20 pts) on every request. After two
    # hits the LB node accumulates 90+ pts and is banned, causing the target
    # to be marked unhealthy and traffic to be drained.
    #
    # Default path is "/" (AWS ALB/NLB default health-check target).  Override
    # with ELB_HEALTH_CHECK_PATH for custom target-group paths.  Disable by
    # setting ELB_HEALTH_CHECK_UA="" — UA match is required in all cases so
    # arbitrary external clients hitting "/" are NOT exempt.
    if ELB_HEALTH_CHECK_PATH and request.path == ELB_HEALTH_CHECK_PATH:
        _elb_ua = request.headers.get("User-Agent", "")
        if ELB_HEALTH_CHECK_UA and ELB_HEALTH_CHECK_UA in _elb_ua:
            import hashlib as _hl
            _path_tag = _hl.sha256(request.path.encode()).hexdigest()[:8]
            slog("elb-health-check", level="info",
                 ip=request.remote or "", path_tag=_path_tag,
                 ua=_elb_ua, request_id=rid)
            return web.Response(
                status=200, text="ok",
                headers={"Content-Type": "text/plain; charset=utf-8",
                         "Cache-Control": "no-store",
                         _REQUEST_ID_HEADER: rid})

    # 1.8.9 — Dashboard bypass mode (raised in priority).
    # When BYPASS_MODE=True every non-admin upstream request is passed
    # through with zero detection, zero ban enforcement, AND zero
    # AUTHORIZED_BOT_UAS evaluation. Previously this check sat below
    # AUTHORIZED_BOT_UAS at line 2932, which let `action=ban` /
    # `action=really-ban` entries still block traffic in bypass mode
    # — contradicting the operator's "all controls disabled" intent.
    # The check is intentionally placed AFTER protocol-level safety
    # (control-byte path reject @2789) so CRLF injection is still
    # blocked at the wire, but BEFORE every operator-policy branch.
    if vc('BYPASS_MODE') and not _is_admin_path(request.path):
        resp = await handler(request)
        _bm_ip = get_ip(request) or request.remote or ""
        await record(_bm_ip, request.headers.get("User-Agent", ""),
                     request.path, resp.status, "",
                     track_key=_bm_ip, request_id=rid, method=request.method)
        return resp

    # 1.8.12 M-4 — IP ban persistence: block raw IPs that earned a hostile ban
    # across SESSION_KEY rotations. check_ip_ban() is a synchronous SQLite
    # point-lookup with a 0.1 s timeout — effectively zero overhead on the hot
    # path because SQLite WAL reads never block the writer.
    if not _is_admin_path(request.path):
        _raw_ip_check = get_ip(request) or request.remote or ""
        if _raw_ip_check:
            try:
                from db import check_ip_ban
                _ip_ban_until = check_ip_ban(_raw_ip_check)
                if _ip_ban_until > 0:
                    _ua_ipb = request.headers.get("User-Agent", "")
                    return await _silent_decoy_response(
                        _raw_ip_check, _ua_ipb, request.path,
                        "ip-ban", ja4=_request_ja4(request), request_id=rid)
            except Exception:
                pass  # nosec B110 — ip_bans check is defence-in-depth; never blocks on error

    # 1.7.4 — Authorized monitoring bot pass-through.
    # Each entry in AUTHORIZED_BOT_UAS is a dict: {name, ua, path, ips, action, enabled}.
    # UA substring + path must match; ips (when non-empty) restricts source IPs.
    # action: authorized-robot → 200 ok + blue recording; allow → silent pass-through;
    # ban / really-ban → immediate ban + decoy response.
    if AUTHORIZED_BOT_UAS:
        _mon_ua = request.headers.get("User-Agent", "")
        _req_ip = get_ip(request) or request.remote or ""
        for _bot in AUTHORIZED_BOT_UAS:
            if isinstance(_bot, dict):
                if not _bot.get("enabled", True):
                    continue
                _ua_sub   = str(_bot.get("ua", "")).strip()
                _bot_path = str(_bot.get("path", "/")).strip() or "/"
                _bot_ips  = _bot.get("ips") or []
                _bot_act  = str(_bot.get("action", "authorized-robot")).strip().lower()
            else:
                # Legacy string "UA:path"
                _s = str(_bot)
                _c = _s.find(":")
                _ua_sub   = (_s[:_c] if _c > 0 else _s).strip()
                _bot_path = (_s[_c + 1:] if _c > 0 else "/").strip() or "/"
                _bot_ips  = []
                _bot_act  = "authorized-robot"
            if not _ua_sub or _ua_sub not in _mon_ua:
                continue
            if request.path != _bot_path:
                continue
            if _bot_ips and _req_ip not in _bot_ips:
                continue
            # Match — apply action
            if _bot_act == "authorized-robot":
                await record(_req_ip, _mon_ua, request.path, 200, "authorized-robot",
                             request_id=rid)
                slog("authorized-robot", level="info",
                     ip=_req_ip, ua=_mon_ua, request_id=rid)
                return web.Response(
                    status=200, text="ok",
                    headers={"Content-Type": "text/plain; charset=utf-8",
                             "Cache-Control": "no-store",
                             _REQUEST_ID_HEADER: rid})
            elif _bot_act == "allow":
                request["_custom_rule_allow"] = True
                break   # exit bot loop; continue to normal proxy
            elif _bot_act in ("ban", "really-ban"):
                _ban_secs = REALLY_BAN_SECS if _bot_act == "really-ban" else HONEYPOT_BAN_SECS
                _ban_reason = f"bot-rule-{'really-ban' if _bot_act == 'really-ban' else 'ban'}"
                async with state_lock:
                    _bs = ip_state[_req_ip]
                    _bs.banned_until = now() + _ban_secs
                    ip_to_identities[_req_ip].add(_req_ip)
                    _bs.last_ip = _req_ip
                await _shared_ban_set(_req_ip, _t.time() + _ban_secs, _ban_reason)
                if db_queue is not None:
                    try:
                        db_queue.put_nowait(("ban", (
                            _req_ip, _t.time() + _ban_secs, _ban_reason, _t.time())))
                    except asyncio.QueueFull:
                        pass
                return await _silent_decoy_response(
                    _req_ip, _mon_ua, request.path, _ban_reason,
                    ja4=_request_ja4(request), request_id=rid)

    # Operator-defined detection bypass paths — prefix match, skips detection.
    # Calls record() with empty reason so traffic appears in the dashboard timeline
    # and clients table as clean allowed traffic. All bypass-path requests from the
    # same IP update the same single ip_state entry — no fan-out per request.
    if vc('BYPASS_PATHS') and any(request.path.startswith(p) for p in vc('BYPASS_PATHS')):
        resp = await handler(request)
        _bp_ip = get_ip(request) or request.remote or ""
        await record(_bp_ip, request.headers.get("User-Agent", ""),
                     request.path, resp.status, "",
                     track_key=_bp_ip, request_id=rid, method=request.method)
        return resp

    # 1.8.9 — BYPASS_MODE was moved to line ~2855 (above AUTHORIZED_BOT_UAS)
    # so that operator-policy branches like `action=ban` can't fire when
    # the operator has explicitly disabled all controls.

    # 1.5.1: operator-controlled global throughput limit. When the rolling
    # 1-second request count is over GLOBAL_RPS_LIMIT, silent-decoy this
    # request. Internal admin paths are exempt so health-checks and admin
    # tools keep working under load. Operator drives this via the main
    # dashboard slider (or POST <NS>/secured/config GLOBAL_RPS_LIMIT=N).
    _vrps_limit = vc('GLOBAL_RPS_LIMIT')
    if _vrps_limit > 0 and (not _is_admin_path(request.path) or not _admin_ip_allowed(request)):
        n_ts = _t.time()
        cutoff = n_ts - 1.0
        _vrps_win = get_vhost_rps_window(current_vhost_host()) or _global_rps_window
        while _vrps_win and _vrps_win[0] < cutoff:
            _vrps_win.popleft()
        if TRAFFIC_THRESHOLD_ENABLED and len(_vrps_win) >= _vrps_limit:
            ip = get_ip(request)
            ua = request.headers.get("User-Agent", "")
            return await _silent_decoy_response(
                ip, ua, request.path, "traffic-threshold",
                ja4=_request_ja4(request), request_id=rid)
        _vrps_win.append(n_ts)

    # F3: method allowlist at Layer 0 — short-circuits before PoW / rate
    # limit / behavioral could preempt with their own response. Internal
    # admin routes accept any method (HEAD probes, OPTIONS preflight).
    if (not _is_admin_path(request.path) or not _admin_ip_allowed(request)) and request.method not in ALLOWED_METHODS:
        return web.Response(status=405, text="method not allowed\n",
                            headers={"Allow": ", ".join(sorted(ALLOWED_METHODS))})

    # F1: Host header allowlist (D-i-D). When ALLOWED_HOSTS is configured,
    # silently decoy any request whose Host header is not on the list. This
    # complements the existing X-Forwarded-Host strip+overwrite by also
    # blocking host-header-based reconnaissance / cache poisoning attempts at
    # OUR gate. The hostname-only comparison strips the port (request.host
    # may be "example.com:8443").
    if ALLOWED_HOSTS:
        host = (request.host or "").split(":", 1)[0].lower()
        if HOST_BLOCKING_ENABLED and host not in ALLOWED_HOSTS:
            ip = get_ip(request)
            ua = request.headers.get("User-Agent", "")
            return await _silent_decoy_response(ip, ua, request.path,
                                                "host-not-allowed",
                                                ja4=_request_ja4(request), request_id=rid)

    # ── 1.6.1 Layer 0.4: Custom rules engine (Tier B). Operator-defined
    # IF/THEN runs *before* standard detectors so an `allow` rule can
    # short-circuit the chain (legitimate internal callers / IP-pinned
    # automation), and a `block` rule can deny on operator-specific
    # conditions the built-in detectors don't cover.
    if CUSTOM_RULES_ENABLED and CUSTOM_RULES:
        _ip = get_ip(request)
        _action, _tag = _eval_custom_rules(request, _ip)
        if _action == "allow":
            request["_custom_rule_allow"] = True
            _allow_resp = await handler(request)
            await record(_ip, request.headers.get("User-Agent", ""),
                         request.path, _allow_resp.status, "",
                         request_id=rid, method=request.method)
            return _allow_resp
        if _action == "authorized-robot":
            _ar_ua = request.headers.get("User-Agent", "")
            await record(_ip, _ar_ua, request.path, 200, "authorized-robot",
                         request_id=rid)
            slog("authorized-robot", level="info", ip=_ip, ua=_ar_ua, request_id=rid)
            return web.Response(
                status=200, text="ok",
                headers={"Content-Type": "text/plain; charset=utf-8",
                         "Cache-Control": "no-store",
                         _REQUEST_ID_HEADER: rid})
        if _action == "block":
            _ua = request.headers.get("User-Agent", "")
            return await _silent_decoy_response(_ip, _ua, request.path,
                                                "custom-rule-block",
                                                ja4=_request_ja4(request),
                                                request_id=rid)
        if _action == "challenge":
            request["_custom_rule_force_challenge"] = True
        elif _action == "tag":
            request["_custom_rule_tag"] = _tag

    # ── 1.6.1 Layer 0.45: JWT/Bearer validation (Tier B). When the path
    # matches JWT_VALIDATE_PATHS, the request must carry a valid HS256
    # JWT in `Authorization: Bearer …`. Mismatches fire `auth-jwt-invalid`
    # (weight 25) and silent-decoy. Doesn't replace upstream auth — adds
    # an edge gate so probing this route without a token never reaches
    # the application.
    if JWT_VALIDATION_ENABLED and JWT_VALIDATE_PATHS and _jwt_required_for(request.path):
        _auth = request.headers.get("Authorization", "")
        _ok = False
        if _auth.lower().startswith("bearer "):
            _ok, _ = _verify_jwt_hs256(_auth[7:].strip())
        if not _ok:
            _ip = get_ip(request)
            _ua = request.headers.get("User-Agent", "")
            return await _silent_decoy_response(_ip, _ua, request.path,
                                                "auth-jwt-invalid",
                                                ja4=_request_ja4(request),
                                                request_id=rid)

    # ── v1.4.2 Layer 0.5: TLS fingerprint deny-list (JA3/JA4) ─────────────
    # The upstream TLS terminator (cloudflared, nginx, ALB) injects the
    # client's handshake fingerprint as a header. Off by default — operator
    # opts in via JA4_DENY_LIST.
    if TLS_FP_BLOCK_ENABLED and _tls_fingerprint_blocked(request):
        ip = get_ip(request)
        ua = request.headers.get("User-Agent", "")
        return await _silent_decoy_response(ip, ua, request.path,
                                            "tls-fingerprint",
                                            ja4=_request_ja4(request), request_id=rid)

    # ── v1.4.2 Layer 0.6: Strict Origin / Referer enforcement ─────────────
    # On state-changing methods, require the Origin header to match
    # ALLOWED_HOSTS. Off by default (STRICT_ORIGIN=1 to enable).
    if _origin_check_failed(request):
        ip = get_ip(request)
        ua = request.headers.get("User-Agent", "")
        return await _silent_decoy_response(ip, ua, request.path,
                                            "origin-mismatch",
                                            ja4=_request_ja4(request), request_id=rid)

    # ── v1.4.2 Layer 0.7: Required custom-header presence ───────────────
    # Operator-defined headers (REQUIRED_HEADERS=X-Client-Version,...) must
    # be present on every non-/__/  /  non-static request.
    if REQUIRED_HEADERS_ENABLED and _missing_required_header(request):
        ip = get_ip(request)
        ua = request.headers.get("User-Agent", "")
        return await _silent_decoy_response(ip, ua, request.path,
                                            "missing-required-header",
                                            ja4=_request_ja4(request), request_id=rid)

    # ── v1.4 #1 — JS challenge gate (V8 fix) ────────────────────────────
    # The chal cookie is REQUIRED on every non-static, non-admin, non-opted-
    # -out path — not only HTML. Browsers carry the cookie on XHR/fetch
    # transparently; pure-HTTP bots don't and get blocked.
    #   - HTML GET without cookie → serve interactive challenge page.
    #   - Everything else without cookie → silent decoy (preserves stealth;
    #     does NOT leak that the gateway exists by returning 401).
    # Placed AFTER host/TLS/origin/required-header stealth checks so those
    # block paths take precedence and remain undetectable.
    if _js_challenge_required(request):
        if _js_challenge_applicable(request):
            _pow_chal_str = ""
            if POW_CHAL_THRESHOLD > 0:
                _early_id, *_ = get_identity(request)
                _s_pow = ip_state.get(_early_id)
                if _s_pow and _s_pow.risk_score >= POW_CHAL_THRESHOLD:
                    _pow_chal_str = make_pow_challenge("*", "*",
                                                       risk_score=int(_s_pow.risk_score))
            # Increment challenged counter in the current timeline bucket
            try:
                from core.metrics import _bucket_now as _bn_jsc
                _cb_jsc = _bn_jsc()
                if _cb_jsc in timeline:
                    _tb_jsc = timeline[_cb_jsc]
                    if "challenged" not in _tb_jsc:
                        _tb_jsc["challenged"] = 0
                    _tb_jsc["challenged"] += 1
            except Exception:
                pass
            return _serve_js_challenge(request, pow_challenge=_pow_chal_str)
        # 1.4.4: heuristic auto-mint mode (no Turnstile). HTML GETs are
        # allowed through; the response gets the cookie set after the
        # request completes the rest of the layered checks. Non-HTML or
        # non-GET requests without a cookie still silent-decoy so APIs
        # cannot be used directly without first visiting an HTML page.
        # 1.5.4 — when Turnstile is configured but the identity's risk
        # hasn't crossed `_turnstile_active_threshold()`, also fall through
        # to auto-mint (most users never see Turnstile, only suspected bots).
        if (request.method == "GET"
                and "text/html" in request.headers.get("Accept", "")):
            request["_auto_mint_chal"] = True
            # fall through to the rest of the middleware so UA filter,
            # header completeness, behavioural, body-pattern, canary echo
            # etc. still apply before we hand back a cookie.
        else:
            ip = get_ip(request)
            ua = request.headers.get("User-Agent", "")
            return await _silent_decoy_response(ip, ua, request.path,
                                                "chal-required",
                                                ja4=_request_ja4(request), request_id=rid)

    # Internal endpoints: only authenticated operator gets through.
    # Anyone else sees the silent decoy — they don't even learn that the
    # admin namespace exists. When ADMIN_ALLOWED_IPS is configured, the
    # source IP MUST also match — silent decoy on IP mismatch (no leak
    # that the IP check is what blocked).
    if _is_admin_path(request.path):
        # Public sub-paths (liveness, JS-challenge plumbing, BotD callback,
        # asset bundle) are always reachable. The BotD bundle is fetched
        # by browsers when the injected <script> runs and the report
        # endpoint validates its own HMAC bound to the requester's
        # track_key — no admin-IP / admin-key gating needed there.
        if _admin_path_is_public(request.path):
            return await handler(request)
        # 1.6.7+: /login + /logout require the admin-IP allowlist but
        # do NOT require a session cookie (there's no cookie until
        # after login). Hides the login form entirely from anyone
        # whose source IP isn't allowed — the form 404-decoys like
        # any other admin path on un-allowed IPs.
        sub = request.path[len(ADMIN_NS):]
        if sub in _ADMIN_LOGIN_SUBPATHS:
            if _admin_ip_allowed(request):
                return await handler(request)
            # else: fall through to silent decoy
        elif _admin_ip_allowed(request) and _internal_authed(request):
            # 1.8.11 (H2): central CSRF gate. Every state-changing request to
            # the authenticated admin namespace must carry a valid X-CSRF-Token,
            # so coverage can't silently drift as handlers are added (the
            # per-handler @_require_csrf decorator stays as defence-in-depth).
            # Login / logout / 2FA-login and public admin paths are handled in
            # the branches above and never reach here; every dashboard mutation
            # goes through the fetch CSRF shim, so the header is always present.
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                from admin.auth import _csrf_token_valid as _ctv
                if not _ctv(request):
                    return web.json_response(
                        {"error": "CSRF token invalid"}, status=403,
                        headers={"Cache-Control": "no-store"})
            _adm_resp = await handler(request)
            if sub not in _ADMIN_POLL_SUBPATHS:
                _adm_ip = get_ip(request)
                _adm_ua = request.headers.get("User-Agent", "")
                await record(_adm_ip, _adm_ua, request.path,
                              _adm_resp.status, "operator-passthrough", request_id=rid)
            # 1.8.10 — self-heal the CSRF cookie. agw_csrf is only set at login,
            # so a session whose csrf cookie expired (it lives 12 h while the
            # session can be refreshed), was never set (SSO), or went stale would
            # fail every state-mutating POST with "CSRF token invalid". Re-issue
            # the correct value on any authed response where it's missing/wrong,
            # so simply loading a page restores it — no re-login needed.
            try:
                _sid_csrf = request.get("_session_sid", "")
                if _sid_csrf and hasattr(_adm_resp, "set_cookie"):
                    import hmac as _hm_csrf
                    import hashlib as _hh_csrf
                    from admin.users import _SESSION_TTL as _sttl_csrf
                    _want_csrf = _hm_csrf.new(SESSION_KEY, _sid_csrf.encode(),
                                              _hh_csrf.sha256).hexdigest()[:32]
                    if request.cookies.get("agw_csrf", "") != _want_csrf:
                        # 1.8.11 (M1): scope to ADMIN_NS so the readable CSRF
                        # token is never sent to the proxied upstream surface.
                        _adm_resp.set_cookie("agw_csrf", _want_csrf,
                                             max_age=_sttl_csrf, httponly=False,
                                             samesite="Strict", path=ADMIN_NS,
                                             secure=SESSION_SECURE)
            except Exception:  # nosec B110 — best-effort cookie refresh; never break the response
                pass
            return _adm_resp
        ip = get_ip(request)
        ua = request.headers.get("User-Agent", "")
        if not _admin_ip_allowed(request):
            reason = "admin-ip-blocked"
        else:
            # 1.8.10 — IP allowed but not an authenticated operator. Split the
            # legacy catch-all "internal-probe" into two so metrics are honest:
            #   • operator-self — a genuinely-issued agw_session that lapsed
            #     server-side (expired/revoked/cache-evicted). This is the
            #     operator's own browser making XHRs after the session dropped —
            #     benign self-noise, excluded from blocked counts.
            #   • admin-probe   — no valid session cookie at all: anonymous /
            #     external reconnaissance of the admin namespace. Counted as a
            #     block so recon shows up in threat metrics.
            # _session_parse validates the HMAC, so a forged cookie cannot
            # masquerade as operator-self — it falls through to admin-probe.
            try:
                from admin.users import (_session_parse as _sp_cls,
                                         _SESSION_COOKIE as _sc_cls)
                _cookie_cls = request.cookies.get(_sc_cls, "")
                _operator_self = bool(_cookie_cls) and _sp_cls(_cookie_cls) is not None
            except Exception:
                _operator_self = False
            reason = "operator-self" if _operator_self else "admin-probe"
        # 1.5.4: serve the upstream's actual 404 page (cached at startup,
        # refreshed hourly). An attacker probing the admin namespace sees
        # the same response as if they'd hit any non-existent path on the
        # upstream.
        await record(ip, ua, request.path,
                      _upstream_404_cache.get("status") or 404,
                      reason, request_id=rid)
        return await _serve_mirrored_404()

    # STRICT_VHOST: reject unconfigured inbound hosts before any proxy logic.
    # Only enforced when at least one vhost is registered — if VHOSTS is empty
    # the operator hasn't configured multi-vhost mode and the global UPSTREAM
    # acts as the single upstream (single-site deployment).
    if STRICT_VHOST and VHOSTS and not vhost_is_configured():
        return web.Response(status=502, text="no upstream configured for this host\n",
                            headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})

    # ── Hybrid identity (primary tracking key) ──
    # 'identity' = HMAC(session_cookie + browser_fingerprint) for browser flow,
    # OR HMAC(fp + ip) for cookieless scripts (still stable per device).
    identity, sid, fp, is_new_session, id_mode = get_identity(request)
    ip = get_ip(request)            # IP for session-creation guard + display

    # Stamp arrival time + path/asset telemetry on the track_key entry NOW,
    # before any detector may return early. Without this, blocked identities
    # never accumulate html_loads / static_loads / unique_paths / request_times
    # and all agents-dashboard columns show 0 for everything except risk_score.
    # (rate_limit.py only stamps ip_state[ip], a separate entry from track_key.)
    async with state_lock:
        _s_early = ip_state[identity]
        _s_early.request_times.append(now())
        if len(_s_early.unique_paths) < 400:
            _s_early.unique_paths.add(request.path)
        _early_unique_n = len(_s_early.unique_paths)
        _s_early.path_sequence.append(request.path)  # 1.7.1: journey tracking
        # 1.7.3 — path-sweep window record (non-static, non-admin paths only;
        # inline inside the held lock — path_sweep_check() reads this later).
        if PATH_SWEEP_ENABLED and not _is_admin_path(request.path) and \
                not request.path.endswith((".css", ".js", ".mjs", ".png", ".jpg",
                    ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".woff",
                    ".woff2", ".ttf", ".otf", ".eot", ".map", ".mp4", ".webm",
                    ".mp3", ".ogg", ".pdf", ".zip")):
            _s_early.path_sweep_times.append((now(), request.path))
        if request.headers.get("X-SW-Active") == "1":  # 1.7.2: SW seen
            _s_early.sw_seen = True
        if request.method == "GET":
            if request.path.endswith((".css", ".js", ".png", ".jpg", ".jpeg",
                                      ".gif", ".svg", ".webp", ".woff", ".woff2",
                                      ".ttf", ".ico", ".map")):
                _s_early.static_loads += 1
            elif request.path == "/" or request.path.endswith((".html", ".htm")):
                _s_early.html_loads += 1
        _early_no_static = (_s_early.html_loads >= 25 and _s_early.static_loads == 0)
        _early_html_loads   = _s_early.html_loads
        _early_static_loads = _s_early.static_loads
        _early_req_count    = _s_early.request_count

    # 1.6.5 — escalation gate: skip the expensive / external intel layer
    # for identities with zero accumulated risk. ESCALATION_THRESHOLD=0
    # reverts to legacy "run on every request" behaviour. Saves AbuseIPDB
    # quota + CrowdSec round-trip on the 99% of requests that are clean.
    _esc_score = _escalation_score(identity)

    # ── 1.5.3: external IP-intel layer (AbuseIPDB) — escalate-only ──
    # Cached in SQLite — typical cost is ~0.1ms cached, 100-300ms uncached
    # (CloudFront RTT). Bumps risk but never blocks outright.
    if ABUSEIPDB_ENABLED and _should_run_signal("abuseipdb-high", _esc_score):
        ab_score, ab_country, ab_source = await _abuseipdb_lookup(ip)
        if ab_score >= ABUSEIPDB_HIGH_THRESHOLD:
            await update_risk_and_maybe_ban(identity, "abuseipdb-high", ip)
        elif ab_score >= ABUSEIPDB_MED_THRESHOLD:
            await update_risk_and_maybe_ban(identity, "abuseipdb-med", ip)

    # 1.5.3: CrowdSec community-blocklist check — escalate-only (~5ms LAPI)
    if CROWDSEC_ENABLED and _should_run_signal("crowdsec-banned", _esc_score):
        cs_decision, cs_source = await _crowdsec_check(ip)
        if cs_decision:  # any active decision = community-vetted bad actor
            await update_risk_and_maybe_ban(identity, "crowdsec-banned", ip)

    # 1.5.3: MaxMind ASN tagging — escalate-only (cheap but only useful on
    # suspects; soft signal anyway).
    if MAXMIND_ENABLED and _should_run_signal("asn-hosting", _esc_score):
        asn, asn_org, is_hosting, _src = _asn_lookup(ip)
        if is_hosting:
            await update_risk_and_maybe_ban(identity, "asn-hosting", ip)
            # 1.6.0 — heavier `datacenter-vpn` tag when explicit toggle is on.
            if DC_VPN_BLOCK_ENABLED:
                await update_risk_and_maybe_ban(identity, "datacenter-vpn", ip)
        # 1.7.1 — Coordinated-attack clustering: N≥THRESHOLD distinct identities
        # from the same ASN hitting the same path prefix within the same minute.
        if COORDINATED_ATTACK_ENABLED and asn and _should_run_signal("coordinated-probe", _esc_score):
            _minute = int(_t.time() / 60)
            _prefix = request.path.split("/")[1] if "/" in request.path else request.path
            _ck = (asn, _prefix, _minute)
            _cluster = _asn_path_clusters.setdefault(_ck, set())
            _cluster.add(identity)
            if len(_cluster) >= COORDINATED_ATTACK_THRESHOLD:
                await update_risk_and_maybe_ban(identity, "coordinated-probe", ip)
            # Prune stale cluster keys (older than 2 minutes)
            if len(_asn_path_clusters) > 10000:
                _now_min = int(_t.time() / 60)
                _stale_ck = [k for k in list(_asn_path_clusters) if k[2] < _now_min - 2]
                for _k in _stale_ck:
                    _asn_path_clusters.pop(_k, None)

    # 1.6.0 — Tor exit-node check (Tier A). O(1) set membership; the feed
    # is refreshed weekly in `_tor_refresh_loop`. Tor exits are not blocked
    # outright (some legitimate users) — they get a +50 risk tag which is
    # the ban threshold, so a single hit silent-decoys + bans by default.
    if TOR_BLOCK_ENABLED and ip in _tor_exits:
        await update_risk_and_maybe_ban(identity, "tor-exit", ip)
        return await _silent_decoy_response(
            ip, request.headers.get("User-Agent", ""), request.path,
            "tor-exit", track_key=identity, sid=sid, fp=fp,
            ja4=_request_ja4(request), request_id=rid)

    # 1.6.0 — Country-level geo block (Tier A, Akamai Kona-style geofencing).
    # Uses existing GeoLite2-City lookup (~0.1ms). Allowlist beats denylist:
    # if COUNTRY_ALLOWLIST is non-empty, anything outside it is blocked even
    # when the country isn't explicitly listed in COUNTRY_DENYLIST.
    # 1.6.5 — admin IPs ALWAYS bypass country block. Prevents the operator
    # from locking themselves out by accidentally adding their own country
    # to the denylist (the lesson learned from a stale test entry on
    # 2026-05-01 — PT was added during a probe and persisted in
    # config_kv, silent-decoying the operator's own browser).
    if (vc('COUNTRY_BLOCK_ENABLED') and _city_reader is not None
            and not _admin_ip_allowed(request)):
        _geo = _city_lookup(ip)
        if _geo:
            _, _, _cc, _ = _geo
            _cc_u = (_cc or "").upper()
            _block = False
            _vc_al = vc('COUNTRY_ALLOWLIST')
            _vc_dl = vc('COUNTRY_DENYLIST')
            if _vc_al and _cc_u and _cc_u not in _vc_al:
                _block = True
            elif _cc_u and _cc_u in _vc_dl:
                _block = True
            if _block:
                await update_risk_and_maybe_ban(identity, "country-blocked", ip)
                return await _silent_decoy_response(
                    ip, request.headers.get("User-Agent", ""), request.path,
                    "country-blocked", track_key=identity, sid=sid, fp=fp,
                    ja4=_request_ja4(request), request_id=rid)
    request["_sid"]    = sid
    request["_is_new"] = is_new_session
    request["_id_mode"] = id_mode
    request["_fp"]     = fp                   # v1.4: expose to proxy() body checks
    request["_track_key"] = identity          # v1.4: same

    # Anti cookie-rotation: limit how many DISTINCT new identities one IP can
    # spawn per minute. Counts unique identities (not requests), so parallel
    # cookieless SPA sub-resource fetches that all share one fp+ip identity
    # register as 1.
    if is_new_session:
        # 1.6.10 — use tighter threshold for hosting ASNs (bots in datacenters
        # spin up many sessions faster than consumer ISPs).
        _session_is_hosting = False
        if MAXMIND_ENABLED and _asn_reader is not None:
            _, _, _session_is_hosting, _ = _asn_lookup(ip)
        async with state_lock:
            now_ts = now()
            id_map = ip_new_sessions[ip]
            # Evict identities older than 60s
            stale = [k for k, ts in id_map.items() if ts < now_ts - 60]
            for k in stale:
                del id_map[k]
            id_map[identity] = now_ts
            new_session_rate = len(id_map)
        _flood_threshold = (NEW_SESSIONS_PER_IP_PER_MIN_HOSTING
                            if _session_is_hosting
                            else NEW_SESSIONS_PER_IP_PER_MIN)
        if SESSION_FLOOD_ENABLED and new_session_rate > _flood_threshold:
            return await _silent_decoy_response(
                ip, request.headers.get("User-Agent",""), request.path, "session-flood"
            )

    ua = request.headers.get("User-Agent", "")
    path = request.path
    # R0: capture JA4 once for the whole decision path (telemetry only).
    ja4 = _request_ja4(request)
    # From here on, all per-client tracking uses 'identity' as the key.
    # 'ip' is recorded as the last-seen IP for dashboard display only.
    track_key = identity

    # 1.8.6 — JA4H: HTTP request fingerprint (compute once, store, check deny-list)
    from identity import compute_ja4h as _compute_ja4h
    ja4h = _compute_ja4h(request)
    if ja4h and ja4h != "error":
        async with state_lock:
            ip_state[track_key].last_ja4h = ja4h
        if JA4H_DENY_ENABLED and ja4h in JA4H_DENY_LIST:
            await update_risk_and_maybe_ban(track_key, "ja4h-deny", ip)
            # Flag for inclusion in request_signals later (appended after request_signals is init'd)
            request["_ja4h_deny"] = True

    # 1.7.3 P3 — LLM no-subresource heuristic: record every request
    if track_key:
        _llm_heuristic.observe(
            track_key,
            request.method,
            request.path,
            request.headers.get("Accept", ""),
        )

    async def deny(status, reason, body, extra_headers=None):
        """
        STEALTH MODE: every block returns the upstream homepage as 200 OK,
        EXCEPT for pow-required which must return 402 + JSON challenge so
        the legitimate client can solve and retry. Risk-score still bumps.
        """
        await update_risk_and_maybe_ban(track_key, reason, ip)
        if reason == "pow-required":
            await record(ip, ua, path, status, reason,
                         track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid)
            return web.json_response(
                body, status=status,
                headers={**(extra_headers or {}), "Cache-Control": "no-store",
                         _REQUEST_ID_HEADER: rid},
            )
        return await _silent_decoy_response(
            ip, ua, path, reason, track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid
        )

    # 1. Banned check (per-identity, not per-IP) → SILENT decoy
    banned, remaining = await is_banned(track_key)
    if banned:
        return await _silent_decoy_response(
            ip, ua, path, "banned-silent", track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid
        )

    # 1b. 1.5.0 — fingerprint-level ban check. The session-churn detector
    # bans by `_fp_hash(ua,ip_tier,ja4)`, not by track_key — because the
    # offender's pattern is to rotate cookies (and therefore track_keys)
    # while keeping the fingerprint stable. Future requests with the same
    # fingerprint hit this gate even if they carry a fresh chal cookie.
    fp_hash_key = _fp_hash(ua, _ip_tier(ip), ja4)
    fp_banned, _ = await is_banned(fp_hash_key)
    if FP_BAN_CHECK_ENABLED and fp_banned:
        return await _silent_decoy_response(
            ip, ua, path, "fp-banned", track_key=track_key, sid=sid,
            fp=fp, ja4=ja4, request_id=rid)

    # 1.6.1 — Layer 1.7: per-endpoint rate-limit (Tier B). When an
    # ENDPOINT_POLICIES rule has rps/burst set, run a token-bucket per
    # (path_glob, identity). Over-budget requests return the silent decoy
    # but accrue zero risk (throttle is not a malicious signal).
    _ep_rule = _endpoint_rule(request.path)
    if ENDPOINT_RATE_LIMIT_ENABLED and _ep_rule and _ep_rule.get("rps"):
        if not await _endpoint_rate_consume(_ep_rule, track_key):
            return await _silent_decoy_response(
                ip, ua, path, "rate-limit-endpoint",
                track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid)

    # BOT_DETECTION_ENABLED=false (per-vhost): skip all heuristic detectors.
    # Existing bans and rate limits above still apply — this gate only bypasses
    # the scoring/detection pipeline. Intended for trusted internal vhosts or
    # staging hosts where bot-detection false-positives block legitimate traffic.
    if not vc('BOT_DETECTION_ENABLED'):
        resp = await handler(request)
        await record(ip, ua, path, resp.status, "operator-passthrough",
                     track_key=track_key, sid=sid, fp=fp, ja4=ja4,
                     request_id=rid, method=request.method)
        return resp

    # 1.8.12 F3 — Honey fingerprint cross-reference: soft-flag requests whose JA4
    # TLS fingerprint matches a previously confirmed attacker (honeypot-silent /
    # honey-cred hit). Low weight (15) — it's a soft signal, not a ban on its own.
    if _honey_fp_ja4_cache and ja4 and ja4 in _honey_fp_ja4_cache:
        await update_risk_and_maybe_ban(track_key, "honey-fp-match", ip)

    # 2. Honeypot → risk_score += 50 (potential ban). Silent decoy regardless.
    #    Threshold-based: at NAT-like IPs, requires accumulated badness.
    if vc('HONEYPOT_ENABLED') and request.path in vc('HONEYPOT_PATHS'):
        await update_risk_and_maybe_ban(track_key, "honeypot-silent", ip)
        # 1.8.12 F2 — Cross-identity clustering: N distinct IPs on same trap path
        # within a 5-minute window → coordinated scan signal on the latest hitter.
        _hp_bucket = int(_t.time() / 300)
        _hp_ck = (request.path, _hp_bucket)
        _hp_cluster = _honeypot_ip_clusters.setdefault(_hp_ck, set())
        _hp_cluster.add(ip)
        if len(_hp_cluster) >= vc('HONEYPOT_CLUSTER_THRESHOLD'):
            await update_risk_and_maybe_ban(track_key, "coordinated-honeypot", ip)
        if len(_honeypot_ip_clusters) > 5000:
            _hp_now_bucket = int(_t.time() / 300)
            for _hp_k in list(_honeypot_ip_clusters):
                if _hp_k[1] < _hp_now_bucket - 3:
                    _honeypot_ip_clusters.pop(_hp_k, None)
        # 1.8.12 F3 — Persist attacker fingerprint for cross-reference.
        if db_queue is not None:
            _hp_asn = locals().get("asn", "") or ""
            try:
                db_queue.put_nowait(("honey_fp_add",
                    (_t.time(), track_key, ip, ua, ja4 or "", str(_hp_asn),
                     request.path, "honeypot-silent")))
            except Exception:
                pass
        if ja4:
            _honey_fp_ja4_cache.add(ja4)
        return await _silent_decoy_response(
            ip, ua, path, "honeypot-silent", track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid
        )

    # 2b. Suspicious path PATTERN (flag-hunting, file-hunting, CTF recon).
    #     Catches /flag.txt, /myflag, /backup.sql, /id_rsa, /.git/HEAD, etc.
    if vc('SUSPICIOUS_PATH_ENABLED') and is_suspicious_path(request.path_qs):
        await update_risk_and_maybe_ban(track_key, "suspicious-path", ip)
        return await _silent_decoy_response(
            ip, ua, path, "suspicious-path", track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid
        )

    # 2c. R7 — AI-canary echo. The agent has quoted our prior response back
    # at us (URL, header, or body), which is something only an LLM-driven
    # client does (it summarises the previous page into its prompt context
    # and re-emits fragments). Big risk bump + immediate silent decoy.
    # Body scanning is deferred to the proxy() function for POSTs since the
    # body isn't read yet here; the URL + headers cover the common case.
    if CANARY_ECHO_DETECTION:
        echoed = _scan_request_for_canary(request)
        if echoed:
            await update_risk_and_maybe_ban(track_key, "canary-echo", ip)
            return await _silent_decoy_response(
                ip, ua, path, "canary-echo",
                track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid)

    # 3a-c. UA filter family (gated by UA_FILTER_ENABLED)
    request_signals = []                       # collected for log
    ua_stripped = ua.strip()
    ua_lower = ua_stripped.lower()
    if vc('UA_FILTER_ENABLED'):
        if not ua_stripped:
            return await deny(403, "ua-empty",
                              {"error": "missing User-Agent header"})
        if len(ua_stripped) < 12:
            return await deny(403, "ua-too-short",
                              {"error": "User-Agent too short", "ua": ua_stripped})
        # 1.6.0 — AI-crawler granular groups (Tier A). Per-group toggle lets
        # an enterprise allowlist a specific vendor's crawler. Checked BEFORE
        # the legacy UA_BLOCKLIST so a disabled group can pass through.
        _ai_group_state = {
            "openai":     AI_UA_OPENAI_ENABLED,
            "anthropic":  AI_UA_ANTHROPIC_ENABLED,
            "google":     AI_UA_GOOGLE_ENABLED,
            "perplexity": AI_UA_PERPLEXITY_ENABLED,
            "meta":       AI_UA_META_ENABLED,
            "other":      AI_UA_OTHER_ENABLED,
        }
        for _grp, _frags in AI_UA_GROUPS.items():
            if not _ai_group_state.get(_grp, True):
                continue
            for _f in _frags:
                if _f in ua_lower:
                    # 1.6.10 — robots.txt compliance: declared AI bot = robots.txt violation
                    if ROBOTS_MONITOR_ENABLED:
                        await update_risk_and_maybe_ban(track_key, "robots-violation", ip)
                        request_signals.append("robots-violation")
                    # 1.6.10 — IP-range verification: flag when IP not in vendor's
                    # published CIDR range (spoof detection).
                    if AI_CRAWLER_VERIFY_ENABLED and not _ip_in_ai_range(ip, _grp):
                        await update_risk_and_maybe_ban(track_key, "ai-ua-ip-mismatch", ip)
                        request_signals.append("ai-ua-ip-mismatch")
                    return await deny(403, f"ua-ai-{_grp}",
                                      {"error": "AI crawler blocked",
                                       "vendor": _grp, "matched": _f})
        for blocked in UA_BLOCKLIST:
            if blocked in ua_lower:
                return await deny(403, "ua-blocked",
                                  {"error": "user-agent blocked", "matched": blocked})
        if not any(t in ua_lower for t in ("mozilla", "safari", "chrome", "firefox", "edge", "opera", "trident")):
            return await deny(403, "ua-non-browser",
                              {"error": "User-Agent does not look like a browser",
                               "ua": ua_stripped[:80]})

    # 3d. AI agent probe paths → risk_score += 30 (no immediate ban)
    if AI_PROBE_ENABLED and request.path in AI_PROBE_PATHS:
        await update_risk_and_maybe_ban(track_key, "ai-probe", ip)
        return await deny(403, "ai-probe",
                          {"error": "AI-probe endpoint requested"})

    # 3e. Header completeness — real browsers send rich headers, agents are minimal
    accept_lang = request.headers.get("Accept-Language", "")
    accept_enc  = request.headers.get("Accept-Encoding", "")
    accept_hdr  = request.headers.get("Accept", "")
    sec_fetch_site = request.headers.get("Sec-Fetch-Site")
    sec_fetch_mode = request.headers.get("Sec-Fetch-Mode")
    sec_fetch_dest = request.headers.get("Sec-Fetch-Dest")
    sec_ch_ua      = request.headers.get("Sec-Ch-Ua")

    # Score header completeness (0-7) — gated by HEADER_COMPLETENESS_ENABLED
    score = (
        bool(accept_lang) + bool(accept_enc) + bool(accept_hdr)
        + bool(sec_fetch_site) + bool(sec_fetch_mode)
        + bool(sec_fetch_dest) + bool(sec_ch_ua)
    )
    if HEADER_COMPLETENESS_ENABLED:
        if score < 2 and "chrome" in ua_lower:
            return await deny(403, "ai-headers-incomplete",
                              {"error": "Chrome UA without browser headers",
                               "header_score": score})
        if score == 0:
            return await deny(403, "ai-headers-empty",
                              {"error": "no Accept-* nor Sec-Fetch-* headers — not a real browser",
                               "header_score": score})

    # ── 1.5.3: soft signals (article alignment) ───────────────────────────
    # These don't deny — they bump the risk score and feed signals[] in logs.
    sec_ch_ua_plat = request.headers.get("Sec-Ch-Ua-Platform", "")

    # 3e2. UA <-> Sec-Ch-Ua consistency
    # Chrome ≥ 89 sends Sec-Ch-Ua; Firefox / Safari don't. A forged Chrome UA
    # without Sec-Ch-Ua, or non-Chrome UA emitting Sec-Ch-Ua, is a strong tell.
    is_chrome_ua = "chrome" in ua_lower and "edg" not in ua_lower
    is_firefox_ua = "firefox" in ua_lower
    is_safari_ua = "safari" in ua_lower and not is_chrome_ua
    if UA_PLATFORM_CHECK_ENABLED and is_chrome_ua and not sec_ch_ua:
        await update_risk_and_maybe_ban(track_key, "ua-platform-mismatch", ip)
        request_signals.append("ua-platform-mismatch")
    elif UA_PLATFORM_CHECK_ENABLED and (is_firefox_ua or is_safari_ua) and sec_ch_ua:
        await update_risk_and_maybe_ban(track_key, "ua-platform-mismatch", ip)
        request_signals.append("ua-platform-mismatch")
    elif UA_PLATFORM_CHECK_ENABLED and is_chrome_ua and sec_ch_ua and sec_ch_ua_plat:
        # Cross-check OS hint: UA "Windows NT 10.0" vs Sec-Ch-Ua-Platform
        plat_norm = sec_ch_ua_plat.strip('"').lower()
        ua_lower_check = ua_lower
        if plat_norm == "windows" and "windows" not in ua_lower_check:
            await update_risk_and_maybe_ban(track_key, "ua-platform-mismatch", ip)
            request_signals.append("ua-platform-mismatch")
        elif plat_norm == "macos" and ("mac os" not in ua_lower_check and "macintosh" not in ua_lower_check):
            await update_risk_and_maybe_ban(track_key, "ua-platform-mismatch", ip)
            request_signals.append("ua-platform-mismatch")
        elif plat_norm == "linux" and "linux" not in ua_lower_check and "android" not in ua_lower_check:
            await update_risk_and_maybe_ban(track_key, "ua-platform-mismatch", ip)
            request_signals.append("ua-platform-mismatch")

    # 3e3. Accept: */* on what looks like HTML nav (Sec-Fetch-Dest=document)
    # Browsers always send a richer Accept on document navigation.
    # 1.8.9 — gated by ACCEPT_WILDCARD_CHECK_ENABLED.
    if (ACCEPT_WILDCARD_CHECK_ENABLED and sec_fetch_dest == "document" and accept_hdr.strip() == "*/*"):
        await update_risk_and_maybe_ban(track_key, "accept-wildcard-html", ip)
        request_signals.append("accept-wildcard-html")

    # 3e3b. 1.6.10 — Accept header fingerprint.
    # Real browsers always include text/html in Accept on HTML navigation.
    # Bots faking a Chrome UA but using application/json or similar reveal
    # themselves here. */* is already handled above; skip to avoid double-score.
    if (ACCEPT_FP_ENABLED and sec_fetch_dest == "document" and accept_hdr):
        _ac = accept_hdr.strip()
        if _ac != "*/*" and "text/html" not in _ac.lower():
            await update_risk_and_maybe_ban(track_key, "accept-fp", ip)
            request_signals.append("accept-fp")

    # 3e4. JA4 required but missing.
    # 1.6.10 — JA4_FAIL_CLOSED: when the operator configures trusted JA4 peers,
    # they can opt-in to hard-deny (instead of soft-score) when the header is
    # absent. Static assets are exempt so CDN pre-fetch doesn't break.
    if JA4_REQUIRED_ENABLED and JA4_TRUSTED_NETS and JA4_HEADER and not request.headers.get(JA4_HEADER):
        if JA4_FAIL_CLOSED and not path.endswith(
                (".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                 ".svg", ".webp", ".woff", ".woff2", ".ttf", ".ico",
                 ".map", ".txt", ".xml", ".json")):
            return await deny(403, "ja4-required-missing",
                              {"error": "JA4 fingerprint required from trusted peer"})
        else:
            await update_risk_and_maybe_ban(track_key, "ja4-required-missing", ip)
            request_signals.append("ja4-required-missing")

    # 3e5. 1.6.10 — Header-order library fingerprint.
    # Real browsers send 10+ diverse headers in a well-known browser order.
    # Common HTTP libraries (requests, curl, Go net/http, httpx) emit a
    # predictable minimal set with a characteristic ordering. Fires only when
    # the exact ordered-name hash matches a known library signature.
    if HEADER_ORDER_FP_ENABLED and _is_library_headers(request):
        await update_risk_and_maybe_ban(track_key, "header-order-fp", ip)
        request_signals.append("header-order-fp")

    # 3e6. 1.6.10 — HTTP/2 fingerprint fallback.
    # Modern browsers always use HTTP/2 on HTTPS. HTTP/1.1 + TLS + modern UA
    # is a mild signal that a library/tool is spoofing a browser UA.
    # X-Forwarded-Proto is injected by the TLS-terminating front proxy;
    # H2_FP_ENABLED=0 by default since the signal is weak without TLS context.
    if H2_FP_ENABLED:
        _proto = (request.headers.get("X-Forwarded-Proto") or "").lower()
        if (_proto == "https" and request.version.major == 1
                and any(t in ua_lower for t in ("chrome/", "firefox/", "safari/", "edg/"))):
            await update_risk_and_maybe_ban(track_key, "h2-fp", ip)
            request_signals.append("h2-fp")

    # 3e7. 1.6.10 — Accept-Language / GeoIP locale consistency.
    # Escalate-gated (cheap MMDB lookup but want to skip zero-risk clean traffic).
    if LOCALE_GEO_CHECK_ENABLED and _city_reader is not None and _should_run_signal("locale-geo-mismatch", _esc_score):
        _geo_lc = _city_lookup(ip)
        if _geo_lc:
            _, _, _lc_country, _ = _geo_lc
            if _locale_geo_mismatch(_lc_country, accept_lang):
                await update_risk_and_maybe_ban(track_key, "locale-geo-mismatch", ip)
                request_signals.append("locale-geo-mismatch")

    # 1.7.1 — Direct-API-probe: browser UA that only hits API paths, never
    # loads HTML or static assets. Fires when request_count≥5, html_loads=0,
    # static_loads=0, and this path looks like an API endpoint. Second-order
    # signal — only adds risk when identity has existing suspicion.
    _api_prefixes = ("/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/rpc/")
    if (JOURNEY_CHECK_ENABLED
            and _should_run_signal("direct-api-probe", _esc_score)
            and _early_html_loads == 0
            and _early_static_loads == 0
            and _early_req_count >= 5
            and any(path.startswith(p) for p in _api_prefixes)):
        await update_risk_and_maybe_ban(track_key, "direct-api-probe", ip)
        request_signals.append("direct-api-probe")

    # 1.8.6 — JA4H deny signal (computed above, before request_signals was initialized)
    if request.get("_ja4h_deny"):
        request_signals.append("ja4h-deny")
    # Stash request_signals for the response wrapper to log
    request["_signals"] = request_signals

    # 3f. Path-discovery rate: too many distinct paths from same identity = enumeration
    # (values already computed in the early tracking block above)
    unique_n = _early_unique_n
    no_static = _early_no_static

    # >300 distinct paths from same identity = enumeration scan.
    # SPAs (Angular/React UFE-style apps) routinely load 50–200 chunked JS
    # modules on one page; the previous 50 threshold was a false-positive
    # magnet for legit users. Operator can override via env if needed.
    if AI_ENUMERATION_ENABLED and _should_run_signal("ai-enumeration", _esc_score) and unique_n > ENUM_THRESHOLD:
        return await deny(403, "ai-enumeration",
                          {"error": "too many distinct paths from this identity",
                           "unique_paths": unique_n})
    if AI_NO_ASSETS_ENABLED and _should_run_signal("ai-no-assets", _esc_score) and no_static:
        return await deny(403, "ai-no-assets",
                          {"error": "browser UA but never fetched any asset — likely AI agent",
                           "html_loads": _s_early.html_loads, "static_loads": _s_early.static_loads})

    # 4a. H4: Socket-IP rate limit — keyed strictly by kernel-observed peer IP,
    #     defeats "rotate UA every request to get a fresh identity bucket"
    #     bypass. This bucket is INDEPENDENT from any client-supplied header.
    socket_ip = request.remote or "0.0.0.0"  # nosec B104 — fallback sentinel, not a bind address
    sip_ok, sip_retry = (True, 0) if not RATE_LIMIT_IP_ENABLED else await take_socket_ip_token(socket_ip)
    if not sip_ok:
        return await deny(429, "rate-limit-ip",
                          {"error": "ip rate limit exceeded",
                           "retry_after": int(sip_retry) + 1},
                          extra_headers={
                              "Retry-After": str(int(sip_retry) + 1),
                              "X-RateLimit-Limit": str(IP_BURST),
                              "X-RateLimit-Remaining": "0",
                          })

    # 4b. Per-identity bucket (one user in the office doesn't consume the
    #     whole company's tokens — secondary, finer-grained limit).
    #     Skip for static-asset GETs: browsers burst-load CSS/JS/img/font on
    #     every page render, exhausting the bucket and breaking the page UI.
    #     Socket-IP bucket (Layer 8) still throttles flooders.
    is_static_asset_get = (request.method == "GET" and request.path.endswith((
        ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".otf",
        ".eot", ".map", ".mp4", ".webm", ".mp3", ".ogg")))
    if RATE_LIMIT_ENABLED and not is_static_asset_get:
        allowed, retry, remaining_tokens = await take_token(track_key)
        if not allowed:
            return await deny(429, "rate-limit",
                              {"error": "rate limit exceeded", "retry_after": int(retry) + 1},
                              extra_headers={
                                  "Retry-After": str(int(retry) + 1),
                                  "X-RateLimit-Limit": str(vc('RATE_LIMIT_BURST')),
                                  "X-RateLimit-Remaining": "0",
                              })

    # 5. Behavioral (per-identity).
    #    Skip for established (cookied) sessions — once a browser has accepted
    #    our HMAC-signed session cookie it is NOT a cookieless bot. Skip for
    #    static-asset GETs because SPA frameworks queue them with very regular
    #    timing (false positive on legitimate users).
    if id_mode != "session" and not is_static_asset_get:
        suspicious, reason = (False, "")
        if BEHAVIORAL_CHECK_ENABLED:
            suspicious, reason = await behavioral_check(track_key)
        if suspicious:
            return await deny(403, "behavior",
                              {"error": "suspicious behavior", "reason": reason})

    # 5b. 1.7.2 — cookie-ghost / lifecycle-miss
    if not is_static_asset_get and (COOKIE_GHOST_ENABLED or COOKIE_LIFECYCLE_ENABLED):
        _cg_hit, _cg_why = await cookie_ghost_check(track_key, request)
        if _cg_hit:
            _cg_reason = "lifecycle-miss" if "lifecycle" in _cg_why else "cookie-ghost"
            return await deny(403, _cg_reason, {"error": "cookie anomaly"})

    # 5c. 1.7.2 — referer-ghost
    if REFERER_CHAIN_ENABLED and not is_static_asset_get:
        _rg_hit, _rg_why = await referer_ghost_check(track_key, request)
        if _rg_hit:
            return await deny(403, "referer-ghost", {"error": "referrer anomaly"})

    # 5d. 1.7.2 — impossible travel (session-keyed only; requires MaxMind city DB)
    if IMPOSSIBLE_TRAVEL_ENABLED and MAXMIND_CITY_ENABLED:
        _it_hit, _it_why = await impossible_travel_check(track_key, ip)
        if _it_hit:
            return await deny(403, "impossible-travel", {"error": "location anomaly"})

    # 5e. 1.7.3 — path-sweep: post-challenge content-discovery detector.
    # Runs for ALL identities including session-cookied ones (warm-up bypass
    # acquires a valid cookie THEN sweeps paths). Skips static assets and
    # admin namespace (recorded at the early-telemetry stage above).
    if PATH_SWEEP_ENABLED and not is_static_asset_get:
        _ps_hit, _ps_why = await path_sweep_check(track_key)
        if _ps_hit:
            await update_risk_and_maybe_ban(track_key, "path-sweep", ip)
            request_signals.append("path-sweep")

    # 6. PoW
    if needs_pow(request):
        token = request.headers.get("X-PoW-Token", "")
        solution = request.headers.get("X-PoW-Solution", "")
        ok, why = verify_pow(token, solution, request.method, request.path)
        if not ok:
            # 1.6.10 — pass current risk_score so difficulty scales with threat level
            async with state_lock:
                _pow_risk = int(ip_state[track_key].risk_score)
            challenge = make_pow_challenge(request.method, request.path, risk_score=_pow_risk)
            eff_diff = int(challenge.split("|")[2])   # diff is baked into the signed payload
            return await deny(402, "pow-required",
                              {"error": "Proof-of-Work required",
                               "reason": why,
                               "challenge": challenge,
                               "difficulty": eff_diff,
                               "valid_for_seconds": POW_VALID_SECS,
                               "instructions": "Use /__solver"},
                              extra_headers={
                                  "X-PoW-Challenge": challenge,
                                  "X-PoW-Difficulty": str(eff_diff),
                              })

    # Allowed → forward upstream and record under the identity
    response = await handler(request)

    # 1.4.4: heuristic auto-mint of the chal cookie. The request reached
    # this point because (a) JS_CHALLENGE=1, (b) Turnstile is OFF, (c) it
    # was an HTML GET without a valid chal cookie, and (d) every layer
    # above (UA filter, header completeness, behavioural, body pattern,
    # canary echo, rate limits, ...) has waved it through. Issue a cookie
    # bound to UA + IP-tier-hash + JA4-hash so subsequent API/XHR calls
    # from this client carry a session marker. NOT a hard wall — the
    # gate is a friction layer that combined with the heuristic stack
    # raises bot cost without any third-party dependency.
    if request.get("_auto_mint_chal"):
        ip_tier_h = _ip_tier(get_ip(request))
        bind_ja4 = ja4 if (JS_CHAL_BIND_JA4 and ja4) else ""
        cookie = _make_chal_cookie(ua, "", ip_tier_h, bind_ja4)
        response.set_cookie(
            CHAL_COOKIE, cookie,
            httponly=True,
            samesite=SESSION_SAMESITE,
            secure=SESSION_SECURE,
            path="/", max_age=JS_CHALLENGE_TTL)
        record_gateway_cookie_set(track_key)
        # 1.5.0: log this mint into the per-fingerprint churn detector. If
        # the same UA+IP-tier+JA4 has minted > SESSION_CHURN_MAX cookies in
        # the last SESSION_CHURN_WINDOW_S seconds, the fingerprint enters
        # the hostile pool (24 h shared ban).
        await _record_chal_mint(ua, ip_tier_h, ja4, ip, rid=rid)

    # Pull current risk score for this identity to log alongside signals[].
    _score_now = 0.0
    async with state_lock:
        _s = ip_state.get(track_key)
        if _s:
            _decay_risk(_s, now())
            _score_now = _s.risk_score
    await record(ip, ua, path, response.status, "",
                 track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid,
                 signals=request.get("_signals", []),
                 score=_score_now, method=request.method)
    # 1.8.6 — JA4H telemetry appended to slog separately (record() predates ja4h)
    if ja4h and ja4h != "error":
        slog("request_ja4h", level="debug", rid=rid, ja4h=ja4h, ip=ip, path=path)
    # Stealth-agent telemetry (only on allowed traffic — feeds /__agents).
    async with state_lock:
        st = ip_state[track_key]
        st.header_scores.append(score)
        st.last_allowed_paths.append({
            "ts": _t.time(), "path": path[:120], "status": response.status,
            "header_score": score,
        })
        if response.status == 404 and not request.path.endswith((
            ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".css", ".js", ".webp", ".woff", ".woff2", ".ttf", ".map")):
            st.upstream_404_count += 1
    # Treat upstream 404 as a small enumeration signal — repeated misses
    # accumulate risk until ban (legitimate users rarely hit many 404s).
    # Skip for static asset extensions (favicon misses are normal).
    if UPSTREAM_404_TRACKING_ENABLED and response.status == 404:
        if not request.path.endswith((".ico", ".png", ".jpg", ".jpeg", ".gif",
                                      ".svg", ".css", ".js", ".webp",
                                      ".woff", ".woff2", ".ttf", ".map")):
            await update_risk_and_maybe_ban(track_key, "upstream-404", ip)

    # 1.8.6 — Credential stuffing: track upstream 401/403 on auth paths
    if response.status in (401, 403) and _is_auth_path(request.path):
        import time as _t_cs
        from state import _auth_fail_global
        from config import AUTH_FAIL_THRESHOLD, AUTH_FAIL_WINDOW_SECS, CRED_STUFF_GLOBAL_RPS
        _cs_now = _t_cs.monotonic()
        async with state_lock:
            _cs_s = ip_state[track_key]
            if _cs_now - _cs_s.auth_failure_window_start > AUTH_FAIL_WINDOW_SECS:
                _cs_s.auth_failures = 0
                _cs_s.auth_failure_window_start = _cs_now
            _cs_s.auth_failures += 1
            _cs_af = _cs_s.auth_failures
        if UPSTREAM_AUTH_FAIL_ENABLED and _cs_af >= AUTH_FAIL_THRESHOLD:
            await update_risk_and_maybe_ban(track_key, "upstream-auth-fail", ip)
        # Global clustering: measure recent auth-fail rate
        _auth_fail_global.append(_cs_now)
        _cs_window_start = _cs_now - 30.0
        _cs_recent = sum(1 for _ts in _auth_fail_global if _ts > _cs_window_start)
        if _cs_recent / 30.0 >= CRED_STUFF_GLOBAL_RPS:
            slog("credential_stuffing_wave", level="warn",
                 rate=round(_cs_recent / 30.0, 2), window_recent=_cs_recent)

    # 1.4.6: stamp the response with the request id so the client can grep
    # logs from this side using the same id.
    if rid and _REQUEST_ID_HEADER not in response.headers:
        response.headers[_REQUEST_ID_HEADER] = rid
    return response

# ── Internal endpoints ─────────────────────────────────────────────────────
async def pow_endpoint(request: web.Request):
    """Issue a fresh PoW challenge bound to (method, path) supplied via query.
    Example: /__pow?method=POST&path=/login

    SH-3: rate-limited per source IP (POW_RL_LIMIT req / POW_RL_WINDOW s).
    Returns the cached challenge string when the same IP calls within the window
    so multiple rapid calls do not burn extra server CPU (idempotent issuance).
    """
    method = (request.query.get("method", "POST") or "POST").upper()
    path = request.query.get("path", "/") or "/"

    # Rate-limit by socket IP (not X-Forwarded-For — prevents header spoofing).
    _pow_src_ip = request.remote or "0.0.0.0"  # nosec B104 — fallback sentinel
    import time as _t_pow
    _now_pow = _t_pow.monotonic()
    _rl_entry = _POW_RL.get(_pow_src_ip)
    if _rl_entry is None or _now_pow - _rl_entry[0] > POW_RL_WINDOW:
        _POW_RL[_pow_src_ip] = [_now_pow, 1]
    elif _rl_entry[1] >= POW_RL_LIMIT:
        return web.Response(
            status=429, text="rate limit\n",
            headers={"Retry-After": str(int(POW_RL_WINDOW)),
                     "Cache-Control": "no-store"})
    else:
        _rl_entry[1] += 1

    # Idempotent: reuse cached challenge if within the window.
    _cached = _POW_CHAL_CACHE.get(_pow_src_ip)
    if _cached and _now_pow - _cached[1] < POW_RL_WINDOW:
        challenge = _cached[0]
    else:
        # 1.6.10 — pass caller's current risk_score for difficulty scaling
        identity, _, _, _, _ = get_identity(request)
        async with state_lock:
            _risk = int(ip_state[identity].risk_score)
        challenge = make_pow_challenge(method, path, risk_score=_risk)
        _POW_CHAL_CACHE[_pow_src_ip] = (challenge, _now_pow)

    eff_diff = int(challenge.split("|")[2])
    return web.json_response({
        "challenge": challenge,
        "difficulty": eff_diff,
        "valid_for_seconds": POW_VALID_SECS,
        "bound_to": {"method": method, "path": path},
        "anubis_mode": ANUBIS_ENABLED,
    }, headers={"Cache-Control": "no-store"})

async def honey_probe_endpoint(request: web.Request):
    """1.7.3 P1 — AI agent honey credential probe.
    GET /antibot-appsec-gateway/probe?k=<key>
    If the key matches a previously injected honey credential, flag the
    REQUESTER as a bot. Always return 200 so the agent thinks the endpoint
    is live.

    False-positive guard: real browsers have a valid chal cookie (auto-minted
    on first HTML GET or issued after Turnstile). AI agents scraping HTML via
    WebFetch/urllib have no cookie. Skip the ban when the requester carries a
    valid chal cookie — they are almost certainly a human who noticed the
    comment in DevTools and curiosity-clicked the URL.

    1.8.11 security fix: previously this banned the identity the key was
    *issued to*, with no rate limit — so anyone who obtained a victim's honey
    key (shared NAT, a cached/archived page, the key is printed in the victim's
    HTML) could ban that victim at will (cross-identity DoS / ban amplification).
    Now we (a) rate-limit per source IP and (b) penalise the REQUESTER'S OWN
    identity, never a third party. Submitting a *valid* honey credential is
    itself the bot signal; the chal-cookie guard still shields real browsers
    (so an attacker can't <img>-trick a logged-in victim into self-banning)."""
    ip = get_ip(request)
    key = request.rel_url.query.get("k", "")
    if key and len(key) <= 64 and _probe_rate_limit_ok(ip):
        # lookup validates the key is a real injected honey credential.
        if lookup_honey_key(key):
            # Skip ban if requester has a valid JS-challenge cookie — real browser.
            ua       = request.headers.get("User-Agent", "")
            cookie   = request.cookies.get(CHAL_COOKIE, "")
            has_chal = bool(cookie and _verify_chal_cookie(
                cookie, ua, _ip_tier(ip), _request_ja4(request)))
            if not has_chal:
                # Ban the requester's own identity, NOT the issued-for identity.
                req_identity = request.get("_track_key") or get_identity(request)[0]
                await update_risk_and_maybe_ban(req_identity, "honey-cred", ip)
                # 1.8.12 F3 — Persist attacker fingerprint; cross-reference future requests.
                _hc_ja4 = _request_ja4(request)
                if db_queue is not None:
                    try:
                        db_queue.put_nowait(("honey_fp_add",
                            (_t.time(), req_identity, ip, ua, _hc_ja4 or "", "",
                             request.path, "honey-cred")))
                    except Exception:
                        pass
                if _hc_ja4:
                    _honey_fp_ja4_cache.add(_hc_ja4)
    # Bland 200 response — never 403/404, would tell the agent its probe failed
    return web.Response(
        status=200,
        text='{"status":"ok"}',
        content_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


# 1.6.10 — robots.txt endpoint: serve a gateway-controlled robots.txt that
# disallows all known AI crawlers. When ROBOTS_MONITOR_ENABLED=1, any request
# from a declared AI crawler UA fires robots-violation (+5) alongside ua-ai-*.
_ROBOTS_TXT_CONTENT = """\
User-agent: *
Disallow: /api/
Disallow: /admin
Disallow: /_internal/
Disallow: /staff/
Allow: /

User-agent: GPTBot
Disallow: /

User-agent: ChatGPT-User
Disallow: /

User-agent: OAI-SearchBot
Disallow: /

User-agent: PerplexityBot
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: anthropic-ai
Disallow: /

User-agent: Googlebot-Extended
Disallow: /

User-agent: FacebookBot
Disallow: /

User-agent: meta-externalagent
Disallow: /
"""

async def robots_txt_endpoint(request: web.Request):
    return web.Response(
        text=_ROBOTS_TXT_CONTENT,
        content_type="text/plain",
        headers={"Cache-Control": "public, max-age=86400", "X-Robots-Tag": "noindex"},
    )

async def solver_endpoint(request: web.Request):
    return web.Response(
        text=r"""<!doctype html><meta charset=utf-8>
<title>PoW solver</title><h2>Anti-bot PoW solver</h2>
<form id=f><label>Challenge: <input id=c size=80></label>
<button>Solve</button></form><pre id=o></pre>
<script>
async function sha256(s){const b=new TextEncoder().encode(s);
  const h=await crypto.subtle.digest('SHA-256',b);
  return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,'0')).join('')}
document.getElementById('f').onsubmit=async e=>{e.preventDefault();
  const c=document.getElementById('c').value.trim(),o=document.getElementById('o');
  const [nonce,,d]=c.split('|');const z='0'.repeat(parseInt(d)||5);
  const t0=performance.now();
  for(let i=0;;i++){const x=i.toString();
    const h=await sha256(nonce+x);
    if(h.startsWith(z)){
      o.textContent=`Found: X=${x}\nhash=${h}\ntook ${(performance.now()-t0).toFixed(0)}ms (${i} attempts)
\nUse:\nX-PoW-Token: ${c}\nX-PoW-Solution: ${x}`;break}
    if(i%1000===0)o.textContent=`tried ${i}…`}}
</script>""",
        content_type="text/html",
    )

async def detector_stats_endpoint(request: web.Request):
    """1.6.5 — per-detector latency & hit count, plus method-bucket
    aggregation. Used by:
      • Dashboard "Top detection methods" + bot/AI breakdown
      • Agents "Per-method latency" panel
      • Service "Detector-latency / cost-by-bucket" panels

    Latency is computed from the rolling 200-sample deque per reason
    (recorded in _detector_record on every fire). Cost bucket totals
    are cumulative since process start.
    """
    out_signals = []
    for reason, dq in _detector_latency.items():
        samples = list(dq) if dq else []
        if not samples:
            typical = p99 = 0.0
        else:
            ss = sorted(samples)
            n = len(ss)
            typical = ss[n // 2]
            p99 = ss[max(0, int(n * 0.99) - 1)]
        out_signals.append({
            "reason":  reason,
            "method":  _reason_method(reason),
            "hits":    _detector_hits.get(reason, 0),
            "p50_ms":  round(typical, 3),
            "p99_ms":  round(p99, 3),
            "samples": len(samples),
        })
    out_signals.sort(key=lambda x: -x["hits"])

    # Per-method aggregation (sum hits + worst p99 per bucket)
    by_method = {}
    for s in out_signals:
        m = s["method"]
        by_method.setdefault(m, {"method": m, "hits": 0, "p99_ms": 0.0,
                                  "reasons": 0})
        by_method[m]["hits"]   += s["hits"]
        by_method[m]["p99_ms"]  = max(by_method[m]["p99_ms"], s["p99_ms"])
        by_method[m]["reasons"] += 1
    methods = sorted(by_method.values(), key=lambda x: -x["hits"])

    return web.json_response({
        "signals": out_signals,
        "methods": methods,
        "chal":    {"required":   _chal_required_count,
                     "minted":     _chal_mint_count,
                     "mint_rate":  (round(_chal_mint_count / _chal_required_count * 100.0, 1)
                                    if _chal_required_count else 0.0)},
    }, headers={"Cache-Control": "no-store"})


def _propagate_global(key: str, value) -> None:
    """Set `key = value` on every loaded module that exposes that name.

    Same pattern as the _mutex_propagate helper in the hot-reload config
    endpoint — iterates sys.modules so all `from X import *` bindings in
    other modules (metrics.py, postgres.py, …) see the new value immediately.
    """
    import sys as _sys_prop
    globals()[key] = value
    for _m in list(_sys_prop.modules.values()):
        if _m is not None and hasattr(_m, key):
            try:
                setattr(_m, key, value)
            except (AttributeError, TypeError):
                pass


def _pg_init_and_activate() -> bool:
    """Run db_init_postgres() and, on success, set _postgres_available=True
    across all loaded modules so db_read_events dispatches to Postgres.

    Called from a thread-pool executor (never blocks the event loop).
    Safe to call multiple times — db_init_postgres is idempotent."""
    if not db_init_postgres():
        return False
    import sys as _sys_pg
    import state as _state_pg
    try:
        _state_pg._postgres_available = True
    except Exception:
        pass
    for _m in list(_sys_pg.modules.values()):
        if _m is not None and hasattr(_m, "_postgres_available"):
            try:
                setattr(_m, "_postgres_available", True)
            except (AttributeError, TypeError):
                pass
    return True


async def db_switch_endpoint(request: web.Request):
    """1.6.5 / 1.8.7 — operator-triggered hot-swap of the active DB backend.

    POST /secured/db-switch?target=sqlite|postgres

    Hot-swaps DB_BACKEND in-process without container restart:
      1. Pre-flight probe (postgres only) — roundtrip connectivity check
      2. Propagate DB_BACKEND to every loaded module via sys.modules
      3. If DSN changed — propagate POSTGRES_DSN + reset pool so next
         _get_pool() creates fresh connections with the new credentials
      4. Migrate last 60 s of events (best-effort continuity)
      5. Persist to config_kv (survives restart)

    SQLite writer loop is always running and is unaffected — it handles
    config/bans/state regardless of which backend is active for events.
    """
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    target = (request.query.get("target", "") or "").strip().lower()
    if target not in ("sqlite", "postgres"):
        return web.json_response(
            {"ok": False, "reason": "target must be sqlite or postgres"},
            status=400, headers={"Cache-Control": "no-store"})

    # On switch-to-postgres we may receive a fresh DSN in the body.
    # full_migrate=true schedules a background historical migration after the switch.
    body_dsn = ""
    full_migrate = False
    if request.method == "POST":
        try:
            raw = await asyncio.wait_for(request.content.read(8192),
                                          timeout=BODY_TIMEOUT)
            body = json.loads(raw.decode("utf-8") or "{}")
            if isinstance(body, dict):
                body_dsn     = str(body.get("dsn", "")).strip()
                full_migrate = bool(body.get("full_migrate", True))
        except (asyncio.TimeoutError, ValueError, json.JSONDecodeError):
            return web.json_response(
                {"ok": False, "reason": "bad json body"},
                status=400, headers={"Cache-Control": "no-store"})

    if target == "postgres":
        if _postgres_load_module() is None:
            return web.json_response(
                {"ok": False,
                 "reason": "psycopg not installed in this image"},
                status=400, headers={"Cache-Control": "no-store"})
        dsn = body_dsn or POSTGRES_DSN
        if not dsn:
            return web.json_response(
                {"ok": False,
                 "reason": "no POSTGRES_DSN configured (set it before switching)"},
                status=400, headers={"Cache-Control": "no-store"})
        # Probe end-to-end with a temporary globals override — does NOT
        # commit anything; restored in the finally block on failure.
        # Must also patch db.postgres module directly: pg_test_roundtrip()
        # reads its own module-level POSTGRES_DSN, not this module's.
        import sys as _sys_probe
        _pg_mod = _sys_probe.modules.get("db.postgres")
        try:
            saved_dsn = globals().get("POSTGRES_DSN", "")
            globals()["POSTGRES_DSN"] = dsn
            globals()["DB_BACKEND"]   = "postgres"
            if _pg_mod is not None:
                _pg_mod_saved_dsn = getattr(_pg_mod, "POSTGRES_DSN", "")
                _pg_mod.POSTGRES_DSN = dsn
            probe = pg_test_roundtrip()
        finally:
            globals()["POSTGRES_DSN"] = saved_dsn
            globals()["DB_BACKEND"]   = DB_BACKEND  # noqa
            if _pg_mod is not None:
                _pg_mod.POSTGRES_DSN = _pg_mod_saved_dsn
        if not probe.get("ok"):
            return web.json_response(
                {"ok": False,
                 "reason": f"DB connectivity probe failed: {probe.get('reason')}"},
                status=400, headers={"Cache-Control": "no-store"})

    # ── Hot-swap: propagate DB_BACKEND + POSTGRES_DSN to all modules ──────
    # Order matters: DSN first (so _get_pool() in postgres.py sees the new
    # value when the first event write triggers lazy pool creation), then
    # DB_BACKEND so event routing in metrics.py flips atomically after
    # the pool is ready.
    old_dsn = globals().get("POSTGRES_DSN", "")
    effective_dsn = body_dsn or old_dsn
    dsn_changed = bool(body_dsn and body_dsn != old_dsn)

    if target == "postgres" and effective_dsn:
        # Always propagate POSTGRES_DSN to all modules so background migration
        # threads (which read db.postgres.POSTGRES_DSN directly) see the live
        # value even when the DSN was saved via /secrets earlier and the switch
        # body carries no dsn (dsn_changed=False but db.postgres still has stale import).
        _propagate_global("POSTGRES_DSN", effective_dsn)
        if dsn_changed:
            # Discard stale pool — next _get_pool() creates fresh connections
            # with the new DSN. When DSN is unchanged, existing connections are
            # still valid; no pool reset needed.
            pg_pool_reset()

    _propagate_global("DB_BACKEND", target)

    # ── Ensure schema exists + mark postgres available before migration ───
    # _pg_init_and_activate is idempotent (CREATE TABLE IF NOT EXISTS) and
    # sets _postgres_available=True so db_read_events routes to Postgres.
    # If the container started with no DSN and the operator configured one
    # via /secrets, the startup init was skipped; run it now so migration
    # threads and dashboard reads don't race against a missing schema.
    if target == "postgres":
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _pg_init_and_activate)

    # ── Migrate last 60 s of events for dashboard timeline continuity ─────
    # Capture switch_ts before the 60-s migration so the bg migration can
    # copy everything strictly older (ts < switch_ts - 60) without overlap.
    switch_ts = _t.time()
    loop = asyncio.get_running_loop()
    migration = await loop.run_in_executor(
        None, _migrate_recent_events, target, 60)
    slog("db_switch_migration", level="warn", **migration, target=target)

    # ── Persist to config_kv (survives container restart) ─────────────────
    if db_queue is not None:
        n = _t.time()
        try:
            db_queue.put_nowait(("set_config",
                                  ("DB_BACKEND", json.dumps(target), n)))
            if dsn_changed:
                db_queue.put_nowait(("set_config",
                                      ("POSTGRES_DSN", json.dumps(effective_dsn), n)))
        except asyncio.QueueFull:
            return web.json_response(
                {"ok": False, "reason": "config_kv queue full"},
                status=503, headers={"Cache-Control": "no-store"})
        await asyncio.sleep(0.1)

    slog("db_switch", level="warn", target=target,
         dsn_changed=dsn_changed, rid=request.get("_rid", ""))

    # ── Optional: background full-history migration ────────────────────────
    # Copies all records older than the 60-s window in a thread-pool
    # executor — never blocks the event loop. Poll /__db-migration-status.
    # 1.8.9 — _try_claim_bg_migration is atomic (check + flip running=True
    # under a lock) so two concurrent admin /db-switch requests can't both
    # schedule the migrator and produce duplicate INSERTs.
    bg_scheduled = False
    if full_migrate:
        direction = "sqlite->postgres" if target == "postgres" else "postgres->sqlite"
        from db.postgres import _try_claim_bg_migration
        if _try_claim_bg_migration(direction):
            cutoff_ts = switch_ts - 60
            loop.run_in_executor(
                None, _full_migrate_background, target, cutoff_ts)
            bg_scheduled = True
            slog("db_switch_bg_migrate_scheduled", level="info",
                 target=target, cutoff_ts=cutoff_ts)
        else:
            slog("db_switch_bg_migrate_skipped_concurrent", level="warn",
                 target=target,
                 note="another migration is already running; skipping double-schedule")

    return web.json_response(
        {"ok": True, "target": target,
         "events_copied": migration.get("copied", 0),
         "events_copy_direction": migration.get("direction", ""),
         "events_copy_ok": migration.get("ok", False),
         "events_copy_reason": migration.get("reason", ""),
         "full_migrate_scheduled": bg_scheduled,
         "message": f"switched to {target} — active immediately, no restart needed"},
        headers={"Cache-Control": "no-store"})


async def db_migration_status_endpoint(request: web.Request):
    """1.8.7 — Poll the background full-history DB migration started by
    db_switch_endpoint when full_migrate=true.

    GET /secured/db-migration-status

    Returns a snapshot of _BG_MIGRATION with derived fields:
      pct          — completion percentage (0-100)
      elapsed_secs — seconds since migration started
      eta_secs     — estimated seconds to completion (null when unknown)
      rate_per_sec — rows copied per second (running average)
    """
    if denied := _role_denied(request, "admin", "maintainer", "viewer"):
        return denied

    status = dict(_BG_MIGRATION)  # shallow copy — readers never block writers
    now = _t.time()

    if status["running"] and status["started_at"]:
        elapsed = now - status["started_at"]
        status["elapsed_secs"] = round(elapsed, 1)
        if status["total"] > 0:
            status["pct"] = round(status["copied"] / status["total"] * 100, 1)
            rate = status["copied"] / elapsed if elapsed > 0 else 0
            status["rate_per_sec"] = round(rate, 1)
            remaining = status["total"] - status["copied"]
            status["eta_secs"] = round(remaining / rate) if rate > 0 else None
        else:
            status["pct"] = 0.0
            status["rate_per_sec"] = 0.0
            status["eta_secs"] = None
    elif status["done"]:
        elapsed = status["finished_at"] - status["started_at"]
        status["elapsed_secs"] = round(elapsed, 1)
        status["pct"] = 100.0 if not status["error"] else round(
            status["copied"] / status["total"] * 100, 1
        ) if status["total"] > 0 else 0.0
        status["rate_per_sec"] = round(
            status["copied"] / elapsed, 1
        ) if elapsed > 0 else 0.0
        status["eta_secs"] = 0
    else:
        # Never started
        status["elapsed_secs"] = 0.0
        status["pct"] = 0.0
        status["rate_per_sec"] = 0.0
        status["eta_secs"] = None

    return web.json_response(status, headers={"Cache-Control": "no-store"})


async def db_test_endpoint(request: web.Request):
    """1.6.5 — DB connectivity probe used by the Controls dashboard
    'External integrations · Postgres / TimescaleDB' card.
    Returns a structured payload describing both backends:
      • sqlite:    file size, row counts, WAL state
      • postgres:  version, db name, round-trip ms, events row count
                    (or `ok=false` + reason when not configured / unreachable)

    1.6.10 — optional `?dsn=<url>` query param probes a candidate DSN without
    committing to it.  Returns only `{ok, probe}` so the switch modal can gate
    the confirm button on a successful connectivity check before the user
    triggers the destructive restart.

    1.8.8 — top-level try/except ensures the endpoint always returns JSON even
    when an unexpected exception occurs; prevents the browser from receiving an
    HTML 500 page that causes JSON.parse to fail in the dashboard."""
    try:
        return await _db_test_endpoint_inner(request)
    except Exception as exc:
        return web.json_response(
            {"ok": False,
             "reason": f"{type(exc).__name__}: {str(exc)[:200]}",
             "error": "internal"},
            status=200, headers={"Cache-Control": "no-store"})


async def _db_test_endpoint_inner(request: web.Request):
    # 1.6.10 — pre-flight probe mode: caller supplies a candidate DSN.
    probe_dsn = request.query.get("dsn", "").strip()
    if probe_dsn:
        if _postgres_load_module() is None:
            return web.json_response(
                {"ok": False, "reason": "psycopg not installed in this image"},
                status=200, headers={"Cache-Control": "no-store"})
        import sys as _sys_dbt
        _pg_mod_dbt = _sys_dbt.modules.get("db.postgres")
        saved_dsn     = globals().get("POSTGRES_DSN", "")
        saved_backend = globals().get("DB_BACKEND", DB_BACKEND)
        try:
            globals()["POSTGRES_DSN"] = probe_dsn
            globals()["DB_BACKEND"]   = "postgres"
            if _pg_mod_dbt is not None:
                _pg_mod_dbt_saved_dsn = getattr(_pg_mod_dbt, "POSTGRES_DSN", "")
                _pg_mod_dbt.POSTGRES_DSN = probe_dsn
            probe = pg_test_roundtrip()
        finally:
            globals()["POSTGRES_DSN"] = saved_dsn
            globals()["DB_BACKEND"]   = saved_backend
            if _pg_mod_dbt is not None:
                _pg_mod_dbt.POSTGRES_DSN = _pg_mod_dbt_saved_dsn
        try:
            from urllib.parse import urlparse
            p = urlparse(probe_dsn)
            masked = f"{p.scheme}://{p.username or '<user>'}:>update password<@{p.hostname or '<host>'}{':'+str(p.port) if p.port else ''}{p.path or ''}"
        except Exception:
            masked = "(redacted)"
        return web.json_response(
            {"ok": probe.get("ok", False),
             "reason": probe.get("reason", ""),
             "probe": {**probe, "dsn_masked": masked}},
            headers={"Cache-Control": "no-store"})

    sqlite_info = {"ok": False}
    try:
        if os.path.exists(DB_PATH):
            sqlite_info["ok"] = True
            sqlite_info["path"] = DB_PATH
            sqlite_info["size_bytes"] = os.path.getsize(DB_PATH)
            wal = DB_PATH + "-wal"
            if os.path.exists(wal):
                sqlite_info["wal_size_bytes"] = os.path.getsize(wal)
            try:
                conn = sqlite3.connect(DB_PATH)
                cur = conn.execute("SELECT COUNT(*) FROM events")
                sqlite_info["events_rows"] = int(cur.fetchone()[0])
                conn.close()
            except Exception as e:
                sqlite_info["events_rows_error"] = str(e)[:120]
    except Exception as e:
        sqlite_info["error"] = f"{type(e).__name__}: {str(e)[:120]}"

    postgres_info = pg_test_roundtrip()
    if postgres_info.get("ok"):
        size = pg_db_size()
        if size.get("ok"):
            postgres_info["db_bytes"] = size["db_bytes"]
            postgres_info["events_rows"] = size["events_rows"]
    # Mask credentials in the DSN so the endpoint can be shown in dashboards.
    masked_dsn = ""
    if POSTGRES_DSN:
        try:
            from urllib.parse import urlparse
            p = urlparse(POSTGRES_DSN)
            masked_dsn = f"{p.scheme}://{p.username or '<user>'}:>update password<@{p.hostname or '<host>'}{':'+str(p.port) if p.port else ''}{p.path or ''}"
        except Exception:
            masked_dsn = "(redacted)"
    # 1.8.8 — per-backend write health.  Compares last_event_ts and event
    # row counts between SQLite and Postgres so the popup can surface
    # silent dual-write breakage.  Cheap (two COUNT/MAX queries).
    try:
        from db import db_health_snapshot
        write_health = db_health_snapshot()
    except Exception as e:
        write_health = {"error": f"{type(e).__name__}: {str(e)[:120]}"}
    return web.json_response({
        "active_backend": DB_BACKEND,
        "sqlite":   sqlite_info,
        "postgres": {**postgres_info,
                      "dsn_masked": masked_dsn,
                      "available": _postgres_available},
        "write_health": write_health,
        "ts": _t.time(),
    }, headers={"Cache-Control": "no-store"})


async def disk_stats_endpoint(request: web.Request):
    """1.7.3 — disk and DB storage stats for the Settings dashboard storage card.
    Returns host disk usage (statvfs on /data) plus SQLite file sizes so
    operators can spot a filling disk before it causes DB write errors."""
    from dashboards.service_metrics import _disk_usage
    disk = _disk_usage(os.path.dirname(DB_PATH) or "/")
    db_bytes  = os.path.getsize(DB_PATH)        if os.path.exists(DB_PATH)           else 0
    wal_bytes = os.path.getsize(DB_PATH + "-wal") if os.path.exists(DB_PATH + "-wal") else 0
    shm_bytes = os.path.getsize(DB_PATH + "-shm") if os.path.exists(DB_PATH + "-shm") else 0
    return web.json_response({
        "disk":      disk,
        "db_bytes":  db_bytes,
        "wal_bytes": wal_bytes,
        "shm_bytes": shm_bytes,
        "db_path":   DB_PATH,
        "ts":        _t.time(),
    }, headers={"Cache-Control": "no-store"})


async def db_vacuum_endpoint(request: web.Request):
    """1.7.3 — trigger a SQLite VACUUM + WAL checkpoint from the Settings page.
    Shrinks the DB file by reclaiming deleted-row pages and truncates the WAL
    so the on-disk footprint drops immediately.  Safe to run at any time;
    VACUUM obtains an exclusive lock briefly but releases it before returning."""
    if DB_BACKEND != "sqlite":
        return web.json_response(
            {"ok": False, "reason": "active backend is not SQLite"},
            status=400, headers={"Cache-Control": "no-store"})
    try:
        before_db  = os.path.getsize(DB_PATH)        if os.path.exists(DB_PATH)           else 0
        before_wal = os.path.getsize(DB_PATH + "-wal") if os.path.exists(DB_PATH + "-wal") else 0
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        conn.close()
        after_db  = os.path.getsize(DB_PATH)        if os.path.exists(DB_PATH)           else 0
        after_wal = os.path.getsize(DB_PATH + "-wal") if os.path.exists(DB_PATH + "-wal") else 0
        return web.json_response({
            "ok": True,
            "before": {"db_bytes": before_db, "wal_bytes": before_wal},
            "after":  {"db_bytes": after_db,  "wal_bytes": after_wal},
            "saved_bytes": (before_db + before_wal) - (after_db + after_wal),
        }, headers={"Cache-Control": "no-store"})
    except Exception as e:
        return web.json_response(
            {"ok": False, "reason": f"{type(e).__name__}: {e}"},
            status=500, headers={"Cache-Control": "no-store"})


async def lists_snapshot_endpoint(request: web.Request):
    """1.6.5 — static-config snapshot: sizes of every allow / deny / pattern
    list, with last-updated timestamps where available. Powers the Controls
    dashboard's 'Allow/block list sizes' card and the Agents 'rule inventory'."""
    n = _t.time()
    snapshot = {
        # UA blocklist (legacy + AI groups)
        "ua_blocklist_size":      len(UA_BLOCKLIST),
        "ai_ua_groups": {
            grp: {"frags": len(frags),
                   "enabled": bool(globals().get(f"AI_UA_{grp.upper()}_ENABLED"))}
            for grp, frags in AI_UA_GROUPS.items()
        },
        # Country lists
        "country_block_enabled":  bool(COUNTRY_BLOCK_ENABLED),
        "country_denylist_size":  len(COUNTRY_DENYLIST or set()),
        "country_allowlist_size": len(COUNTRY_ALLOWLIST or set()),
        "country_denylist":       sorted(COUNTRY_DENYLIST or set()),
        "country_allowlist":      sorted(COUNTRY_ALLOWLIST or set()),
        # JA4 deny-list
        "ja4_deny_size":          len(globals().get("JA4_DENY_LIST") or set()),
        # Tor exits + DC
        "tor_block_enabled":      bool(TOR_BLOCK_ENABLED),
        "tor_exits_size":         len(_tor_exits),
        "tor_loaded_at":          _tor_feed_stats.get("loaded_at", 0),
        "tor_age_secs":           int(n - _tor_feed_stats["loaded_at"]) if _tor_feed_stats.get("loaded_at") else None,
        "dc_vpn_block_enabled":   bool(DC_VPN_BLOCK_ENABLED),
        "hosting_keywords_size":  len(HOSTING_ASN_KEYWORDS),
        # Honeypot paths
        "honeypot_paths_size":    len(HONEYPOT_PATHS),
        # Body groups
        "body_groups": {
            grp: {"patterns": len(pats),
                   "enabled": bool(globals().get(f"BODY_GROUP_{grp.upper()}_ENABLED"))}
            for grp, pats in BODY_PATTERN_GROUPS.items()
        },
        # Suspicious-path patterns
        "suspicious_path_patterns": len(SUSPICIOUS_PATH_PATTERNS),
        # Custom rules
        "custom_rules_size":      len(CUSTOM_RULES),
        # Endpoint policies (with rate-limit summary)
        "endpoint_policies":      [
            {"path": p["path"] if isinstance(p, dict) else p[0],
             "policy": p["policy"] if isinstance(p, dict) else p[1],
             "rps":    (p.get("rps")   if isinstance(p, dict) else None),
             "burst":  (p.get("burst") if isinstance(p, dict) else None)}
            for p in (ENDPOINT_POLICIES or [])
        ],
        # JWT
        "jwt_paths":              list(JWT_VALIDATE_PATHS or []),
        # DLP groups
        "dlp_groups": {
            grp: {"patterns": len(pats),
                   "enabled": bool(globals().get(f"DLP_GROUP_{grp.upper().replace('-','_')}_ENABLED"))}
            for grp, pats in DLP_PATTERN_GROUPS.items()
        },
        # Webhook event filter
        "webhook_event_filter":   list(WEBHOOK_EVENT_FILTER or []),
        # Admin IPs
        "admin_ip_count":         len(globals().get("ADMIN_ALLOWED_NETS") or []),
        # Versions
        "version":                GW_VERSION,
        "ts":                     n,
    }
    return web.json_response(snapshot, headers={"Cache-Control":"no-store"})


async def health_score_endpoint(request: web.Request):
    """1.6.4 — single-number gateway health (0..100, green at 100, red at 0)
    with a per-reason breakdown so operators can see what's pulling the
    score down. Composed of:
      • disk         : free space % at the data volume        (penalty if <30%)
      • memory       : RSS vs system memory ceiling           (penalty if >70%)
      • db           : SQLite file size vs sane ceiling       (penalty >2 GiB)
      • integrations : configured external integrations green (penalty if any
                       configured-but-failing AbuseIPDB / CrowdSec / MaxMind)
      • bans         : count of currently-banned identities    (info only)
      • errors       : recent block-rate vs total              (info only)
    Each reason returns: {key, status (ok/warn/bad), value, weight, detail}.
    The score is 100 minus the sum of weights of `bad`/`warn` reasons,
    floored at 0."""
    n = now()
    reasons = []
    score = 100

    # 1. Disk free
    disk = _disk_usage(os.path.dirname(_DATA_PATH) or "/")
    free_pct = max(0, 100 - disk.get("pct", 0)) if disk else 0
    if disk:
        if free_pct < 5:
            status, weight = "bad", 30
        elif free_pct < 15:
            status, weight = "warn", 15
        elif free_pct < 30:
            status, weight = "warn", 5
        else:
            status, weight = "ok", 0
        reasons.append({
            "key": "disk", "status": status, "weight": weight,
            "value": f"{free_pct:.1f}% free",
            "detail": f"{(disk.get('avail',0)/(1024**3)):.2f} GiB free of "
                       f"{(disk.get('total',0)/(1024**3)):.2f} GiB on "
                       f"{os.path.dirname(_DATA_PATH) or '/'}",
        })
        score -= weight
    else:
        reasons.append({"key": "disk", "status": "warn", "weight": 5,
                        "value": "unknown", "detail": "statvfs failed"})
        score -= 5

    # 2. Memory (RSS) — soft ceiling at 256 MiB, hard at 1 GiB
    rss = 0
    try:
        with open(f"{_PROC}/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1]) * 1024
                    break
    except Exception:
        pass
    rss_mib = rss / (1024 * 1024) if rss else 0
    if rss_mib == 0:
        status, weight = "warn", 3
        detail = "could not read /proc/self/status"
    elif rss_mib > 1024:
        status, weight = "bad", 25
        detail = f"RSS {rss_mib:.0f} MiB (>1 GiB) — investigate"
    elif rss_mib > 512:
        status, weight = "warn", 10
        detail = f"RSS {rss_mib:.0f} MiB (>512 MiB)"
    elif rss_mib > 256:
        status, weight = "warn", 3
        detail = f"RSS {rss_mib:.0f} MiB (>256 MiB)"
    else:
        status, weight = "ok", 0
        detail = f"RSS {rss_mib:.0f} MiB"
    reasons.append({"key": "memory", "status": status, "weight": weight,
                    "value": f"{rss_mib:.0f} MiB", "detail": detail})
    score -= weight

    # 3. DB file size — soft ceiling 2 GiB, hard ceiling 10 GiB on SQLite
    db_size = 0
    try:
        if os.path.exists(DB_PATH):
            db_size = os.path.getsize(DB_PATH)
    except Exception:
        pass
    db_mib = db_size / (1024 * 1024)
    if db_mib > 10240:
        status, weight = "bad", 20
        detail = f"DB {db_mib:.0f} MiB — consider DB_BACKEND=postgres"
    elif db_mib > 2048:
        status, weight = "warn", 8
        detail = f"DB {db_mib:.0f} MiB — approaching SQLite comfort limit"
    else:
        status, weight = "ok", 0
        detail = f"DB {db_mib:.0f} MiB on {DB_BACKEND}"
    reasons.append({"key": "db", "status": status, "weight": weight,
                    "value": f"{db_mib:.0f} MiB", "detail": detail})
    score -= weight

    # 4. Integrations — penalty when something is CONFIGURED but failing
    int_problems = []
    if ABUSEIPDB_KEY and _abuseipdb_stats.get("last_error"):
        int_problems.append(f"AbuseIPDB: {_abuseipdb_stats['last_error'][:80]}")
    if CROWDSEC_LAPI_URL and _crowdsec_stats.get("last_error"):
        int_problems.append(f"CrowdSec: {_crowdsec_stats['last_error'][:80]}")
    if not MAXMIND_CITY_ENABLED and os.environ.get("MAXMIND_LICENSE_KEY", "").strip():
        int_problems.append("MaxMind: license key set but City DB not loaded")
    if int_problems:
        if len(int_problems) >= 2:
            status, weight = "bad", 20
        else:
            status, weight = "warn", 8
        detail = " · ".join(int_problems)
    else:
        status, weight = "ok", 0
        detail = "all configured integrations healthy"
    reasons.append({
        "key": "integrations", "status": status, "weight": weight,
        "value": f"{len(int_problems)} problem(s)" if int_problems else "OK",
        "detail": detail,
    })
    score -= weight

    # 5. Active bans (informational — large numbers can mean we're under
    # attack, which is the gateway working as designed; flag yellow only
    # when the ban list is unusually large to surface NAT-style bans)
    async with state_lock:
        banned_now = sum(1 for s in ip_state.values() if s.banned_until > n)
    if banned_now > 1000:
        status, weight = "warn", 5
        detail = f"{banned_now} active bans (large — review NAT bans)"
    else:
        status, weight = "ok", 0
        detail = f"{banned_now} active bans"
    reasons.append({"key": "bans", "status": status, "weight": weight,
                    "value": str(banned_now), "detail": detail})
    score -= weight

    # 6. Recent error / block ratio (last hour)
    blocked = clean = 0
    try:
        cutoff = _t.time() - 3600
        # 1.8.8 — backend-aware read (was sqlite3.connect(DB_PATH) hardcoded).
        # Group-by is done in Python (helper returns rows, not aggregates).
        # Acceptable for 1h windows; row count bounded.
        from db import db_read_events as _db_read_events_hs
        for r in _db_read_events_hs(
            cutoff, 0,
            columns=["reason"],
            limit=200000,
        ):
            reason = r.get("reason") or ""
            if reason and reason != "OK":
                blocked += 1
            else:
                clean += 1
    except Exception:
        pass  # nosec B110 — best-effort health score; missing data acceptable
    total = blocked + clean
    block_ratio = blocked / total if total else 0
    if total < 100:
        status, weight = "ok", 0
        detail = f"only {total} requests in last hour (low traffic)"
    elif block_ratio > 0.95:
        status, weight = "warn", 5
        detail = (f"{block_ratio*100:.0f}% blocks "
                  f"({blocked}/{total}) — likely under sustained attack")
    elif block_ratio > 0.50:
        status, weight = "warn", 3
        detail = f"{block_ratio*100:.0f}% blocks ({blocked}/{total})"
    else:
        status, weight = "ok", 0
        detail = f"{block_ratio*100:.0f}% blocks ({blocked}/{total})"
    reasons.append({"key": "block_rate", "status": status, "weight": weight,
                    "value": f"{block_ratio*100:.0f}%", "detail": detail})
    score -= weight

    score = max(0, min(100, score))
    return web.json_response({
        "score":       score,
        "reasons":     reasons,
        "version":     GW_VERSION,
        "upstream":    UPSTREAM,
        "db_backend":  DB_BACKEND,
        "uptime_secs": int(_t.time() - START_EPOCH),
        "ts":          _t.time(),
    }, headers={"Cache-Control": "no-store"})


async def _metrics_auth_ok(request) -> bool:
    """Return True if the request is allowed to access /__metrics."""
    from config import METRICS_TOKEN, METRICS_ALLOWED_IPS_RAW
    import ipaddress
    client_ip = get_ip(request)
    # Always allow localhost
    try:
        ip_obj = ipaddress.ip_address(client_ip)
        if ip_obj.is_loopback:
            return True
    except ValueError:
        pass
    # IP allowlist (if configured)
    if METRICS_ALLOWED_IPS_RAW:
        allowed = False
        for cidr in METRICS_ALLOWED_IPS_RAW.split(","):
            cidr = cidr.strip()
            if not cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if ip_obj in net:
                    allowed = True
                    break
            except ValueError:
                continue
        if not allowed:
            return False
    # Bearer token check
    if METRICS_TOKEN:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        import hmac as _hmac
        if not _hmac.compare_digest(auth[7:], METRICS_TOKEN):
            return False
    return True


async def metrics_endpoint(request: web.Request):
    """JSON metrics dump consumed by the dashboard."""
    # 1.8.6 Week 4 — Task L: authenticate /__metrics
    if not await _metrics_auth_ok(request):
        return web.Response(status=401,
                            headers={"WWW-Authenticate": 'Bearer realm="metrics"'})
    _vhost_pre = request.query.get("vhost", "").strip().lower()
    async with state_lock:
        n = now()
        clients = []
        for key, s in sorted(ip_state.items(),
                             key=lambda kv: kv[1].request_count, reverse=True):
            elapsed = n - s.last_refill
            tokens = min(RATE_LIMIT_BURST, s.tokens + elapsed * RATE_LIMIT_REFILL)
            # Apply decay before reporting current score
            _decay_risk(s, n)
            # 1.5.5 — also compute stealth_score so the main-dashboard
            # Clients table can show it (synthetic fallback from
            # risk_score / blocked_count when no allowed-traffic signal).
            _ssc, _, _ = _stealth_score(s)
            if _ssc == 0:
                if s.risk_score > 0:
                    _ssc = min(100, int(s.risk_score))
                elif s.blocked_count > 0:
                    _ssc = min(100, 30 + min(50, s.blocked_count * 2))
            _cli_ua = s.last_user_agent or ""
            _is_auth_bot = any(
                isinstance(_b, dict) and _b.get("enabled", True)
                and _b.get("action", "authorized-robot") == "authorized-robot"
                and _b.get("ua", "") and _b["ua"] in _cli_ua
                for _b in AUTHORIZED_BOT_UAS
            )
            if _vhost_pre and s.last_vhost != _vhost_pre:
                continue
            clients.append({
                "id": key,
                "ip": key,
                "last_ip": s.last_ip or key,
                "last_session": s.last_session,
                "last_fingerprint": s.last_fingerprint,
                "tokens": round(tokens, 1),
                "requests": s.request_count,
                "allowed": s.allowed_count,
                "blocked": s.blocked_count,
                "blocks_by_reason": dict(s.blocks_by_reason),
                "banned_secs": max(0, round(s.banned_until - n, 0)),
                "last_seen_secs_ago": round(n - s.last_seen, 1),
                "first_seen_secs_ago": round(n - s.first_seen, 1),
                "last_ua": s.last_user_agent,
                "last_path": s.last_path,
                "risk_score": round(s.risk_score, 1),
                "stealth_score": _ssc,
                "is_admin_ip": _is_admin_ip(s.last_ip or key),
                "is_authorized_bot": _is_auth_bot,
                "vhost": s.last_vhost,
            })
        # Merge per-category ring buffers. ?cats=allowed,ban,missed,authbots,gwmgmt
        # selects which buckets to include; defaults to all five.
        # ?vhost=<hostname> filters to events from that vhost only (1.8.0).
        _valid_cats = {"allowed", "ban", "missed", "authbots", "gwmgmt"}
        _cats_param = request.query.get("cats", "")
        _req_cats = {c for c in _cats_param.split(",") if c in _valid_cats} if _cats_param else _valid_cats
        _vhost_filter = _vhost_pre
        _merged: list = []
        for _cat in _req_cats:
            _merged.extend(events_by_cat[_cat])
        if _vhost_filter:
            _merged = [e for e in _merged if e.get("vhost", "") == _vhost_filter]
        _merged.sort(key=lambda e: e["ts"], reverse=True)
        recent_events = _merged[:50]
        if _vhost_filter:
            _vhost_paths: dict = {}
            for e in _merged:
                _vhost_paths[e["path"]] = _vhost_paths.get(e["path"], 0) + 1
            top_paths = sorted(_vhost_paths.items(), key=lambda kv: kv[1], reverse=True)[:10]
        elif _req_cats == _valid_cats:
            top_paths = sorted(metrics["by_path"].items(),
                               key=lambda kv: kv[1], reverse=True)[:10]
        else:
            _merged_paths: dict = {}
            for _cat in _req_cats:
                for _p, _n in by_path_by_cat[_cat].items():
                    _merged_paths[_p] = _merged_paths.get(_p, 0) + _n
            top_paths = sorted(_merged_paths.items(), key=lambda kv: kv[1], reverse=True)[:10]

        # Build path→most-common-vhost from event ring buffers for display in dashboard
        _pv_counts: dict = {}
        for _cat_evts in events_by_cat.values():
            for _e in _cat_evts:
                _ep = _e.get("path", "")
                _ev = _e.get("vhost", "")
                if _ep and _ev:
                    _pv_counts.setdefault(_ep, {})
                    _pv_counts[_ep][_ev] = _pv_counts[_ep].get(_ev, 0) + 1
        _path_to_vhost: dict = {
            _p: max(_vc, key=_vc.get)
            for _p, _vc in _pv_counts.items()
        }

        # Build a timeline window with configurable granularity + scroll position.
        #   ?range=N    → window length in minutes (5..1440)
        #   ?bucket=S   → bucket width in seconds (60, 300, 900, 3600, 86400)
        #   ?end=EPOCH  → right edge of the window (defaults to now)
        try:
            range_min = max(5, min(10080, int(request.query.get("range", "60"))))  # up to 7 days
        except ValueError:
            range_min = 60
        try:
            bucket_secs = int(request.query.get("bucket", "60"))
            if bucket_secs not in (60, 300, 900, 3600, 86400):
                bucket_secs = 60
        except ValueError:
            bucket_secs = 60
        try:
            end_epoch = int(request.query.get("end", str(int(_t.time()))))
        except ValueError:
            end_epoch = int(_t.time())
        path_q = (request.query.get("path") or "").strip().lower()

        # Round end to bucket boundary for stable X-axis ticks
        end_b = (end_epoch // bucket_secs) * bucket_secs
        window_secs = range_min * 60
        # Cap number of points at ~250 to avoid mega-payloads
        bucket_count = min(250, max(2, window_secs // bucket_secs))
        start_b = end_b - (bucket_count - 1) * bucket_secs

        # If bucket >= 1m, aggregate the in-memory minute buckets into coarser ones.
        # For older data outside in-memory retention, query the DB.
        timeline_out = []

        if path_q or _vhost_filter:
            # Filtered timeline: query events table and aggregate into buckets.
            # Covers three modes: path only, vhost only, or both together.
            _passthrough = {"", "ok", "operator-passthrough", "bypass-mode",
                            "bypass-path", "authorized-robot"}
            _admin_pfx   = ADMIN_NS.lower()
            try:
                # 1.8.8 — backend-aware read (was sqlite3.connect(DB_PATH) hardcoded)
                from db import db_read_events as _db_read_events_m1
                rows = _db_read_events_m1(
                    start_b, end_b + bucket_secs,
                    columns=["ts", "path", "reason"],
                    vhost=_vhost_filter,
                    path_like=path_q,
                    order_by="ts asc",
                )
                # Also scan in-memory events (recent, not yet flushed to DB)
                from state import events as _mem_events
                mem_rows = [
                    {"ts": e["ts"], "path": e.get("path", ""), "reason": e.get("reason", "")}
                    for e in _mem_events
                    if start_b <= e["ts"] <= end_b + bucket_secs
                    and (not path_q or path_q in (e.get("path") or "").lower())
                    and (not _vhost_filter or (e.get("vhost") or "") == _vhost_filter)
                ]
                # Bucket all rows
                path_buckets: dict = {}
                for row in list(rows) + mem_rows:
                    slot = (int(row["ts"]) // bucket_secs) * bucket_secs
                    b = path_buckets.setdefault(slot, {"total": 0, "allowed": 0, "blocked": 0,
                                                       "missed": 0, "authorized_robot": 0, "gwmgmt": 0})
                    b["total"] += 1
                    r = (row["reason"] or "").lower()
                    p = (row["path"] or "").lower()
                    if p.startswith(_admin_pfx):
                        b["gwmgmt"] += 1
                    if r == "authorized-robot":
                        b["authorized_robot"] += 1
                    if r and r not in _passthrough:
                        b["blocked"] += 1
                    else:
                        b["allowed"] += 1
                for slot in range(start_b, end_b + 1, bucket_secs):
                    timeline_out.append({"t": slot, **path_buckets.get(slot,
                        {"total": 0, "allowed": 0, "blocked": 0,
                         "missed": 0, "authorized_robot": 0, "gwmgmt": 0})})
            except Exception:
                path_q = ""
                _vhost_filter = ""  # fall through to unfiltered on error

        if not path_q and not _vhost_filter:
            # In-memory available range
            in_mem_oldest = end_b - TIMELINE_RETAIN_SECS
            # DB fallback only if needed
            db_buckets = {}
            if start_b < in_mem_oldest:
                try:
                    conn = sqlite3.connect(DB_PATH)
                    conn.row_factory = sqlite3.Row
                    for row in conn.execute(
                        "SELECT bucket_minute, total, allowed, blocked, missed, by_reason FROM timeline "
                        "WHERE bucket_minute >= ? AND bucket_minute <= ? ORDER BY bucket_minute",
                        (start_b, end_b + 60)
                    ):
                        db_buckets[row["bucket_minute"]] = row
                    conn.close()
                except Exception:
                    pass

            for slot in range(start_b, end_b + 1, bucket_secs):
                agg = {"total": 0, "allowed": 0, "blocked": 0, "missed": 0, "authorized_robot": 0, "gwmgmt": 0}
                for m in range(slot, slot + bucket_secs, 60):
                    d = timeline.get(m)
                    if not d:
                        d = db_buckets.get(m)
                    if d:
                        agg["total"] += d["total"]
                        agg["allowed"] += d["allowed"]
                        agg["blocked"] += d["blocked"]
                        try:
                            agg["missed"] += (d["missed"] if d["missed"] is not None else 0)
                        except (IndexError, KeyError):
                            pass
                        try:
                            agg["gwmgmt"] += (d["gwmgmt"] if d.get("gwmgmt") is not None else 0)
                        except (IndexError, KeyError):
                            pass
                        try:
                            br = d["by_reason"]
                            if isinstance(br, str):
                                agg["authorized_robot"] += json.loads(br or "{}").get("authorized-robot", 0)
                            elif hasattr(br, "get"):
                                agg["authorized_robot"] += br.get("authorized-robot", 0)
                        except (KeyError, IndexError, TypeError):
                            pass
                timeline_out.append({"t": slot, **agg})

        # 1.5.1: live throughput from the rolling 1-second window. Used by
        # the main-dashboard threshold slider to show current load vs limit.
        cur_n = _t.time()
        live_rps = sum(1 for ts in _global_rps_window if ts > cur_n - 1.0)

        # 1.5.4 — services / external integrations health.
        # We surface lightweight counters here so the dashboard can show the
        # operator at a glance which extras are wired up + their hit/miss.
        services = {
            "redis": {
                "url":       REDIS_URL or None,
                "connected": _redis is not None,
                "allowlist":  REDIS_ALLOW_LIST,
                "hmac_signing": bool(REDIS_URL),
            },
            # 1.5.5 — SQLite persistence layer status
            "db": {
                "backend":   DB_BACKEND,         # 1.6.5 — active selection
                "path":      DB_PATH,
                "exists":    os.path.exists(DB_PATH),
                "size_bytes": (os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0),
                "wal_size_bytes": (os.path.getsize(DB_PATH + "-wal") if os.path.exists(DB_PATH + "-wal") else 0),
                "configured": True,
                "enabled":    DB_BACKEND == "sqlite",
            },
            # 1.6.5 — Postgres / TimescaleDB persistence layer status
            "db_postgres": {
                "configured": bool(POSTGRES_DSN),
                "enabled":    DB_BACKEND == "postgres" and _postgres_available,
                "available":  _postgres_available,
                **({"db_bytes":  pg_db_size().get("db_bytes"),
                    "events_rows": pg_db_size().get("events_rows")}
                   if (DB_BACKEND == "postgres" and _postgres_available) else {}),
            },
            "abuseipdb": {
                "configured": bool(ABUSEIPDB_KEY),
                "enabled":    ABUSEIPDB_ENABLED,
            },
            "crowdsec": {
                "configured": bool(globals().get("CROWDSEC_LAPI_URL", "")),
                "enabled":    bool(globals().get("CROWDSEC_ENABLED", False)),
            },
            "maxmind": {
                "loaded":  globals().get("_asn_reader") is not None,
                "enabled": bool(globals().get("MAXMIND_ENABLED", False)),
            },
            "turnstile": {
                "configured": _TURNSTILE_CONFIGURED,
                "enabled":    TURNSTILE_ENABLED and JS_CHALLENGE,
            },
            "anubis": {
                "enabled":          ANUBIS_ENABLED,
                "difficulty_boost": ANUBIS_DIFFICULTY_BOOST,
                "effective_diff":   POW_DIFFICULTY + (ANUBIS_DIFFICULTY_BOOST if ANUBIS_ENABLED else 0),
            },
        }

        # 1.5.4 — per-detector hit counts (derived from blocks_by_reason on
        # global metrics). The dashboard renders these alongside services so
        # the operator sees which detectors are actually firing.
        detector_hits = {
            "honeypot":            metrics["by_reason"].get("honeypot-silent", 0) + metrics["by_reason"].get("honeypot", 0),
            "suspicious_path":     metrics["by_reason"].get("suspicious-path", 0),
            "ai_probe":            metrics["by_reason"].get("ai-probe", 0),
            "ai_enumeration":      metrics["by_reason"].get("ai-enumeration", 0),
            "ai_no_assets":        metrics["by_reason"].get("ai-no-assets", 0),
            "ua_filter":           sum(metrics["by_reason"].get(k, 0) for k in
                                       ("ua-empty","ua-too-short","ua-blocked","ua-non-browser")),
            "ua_platform_check":   metrics["by_reason"].get("ua-platform-mismatch", 0),
            "header_completeness": sum(metrics["by_reason"].get(k, 0) for k in
                                       ("ai-headers-empty","ai-headers-incomplete","missing-required-header")),
            "behavioral_check":    metrics["by_reason"].get("behavior", 0),
            "session_flood":       metrics["by_reason"].get("session-flood", 0),
            "upstream_404":        metrics["by_reason"].get("upstream-404", 0),
            "rate_limit_ip":       metrics["by_reason"].get("rate-limit-ip", 0),
            "rate_limit_session":  metrics["by_reason"].get("rate-limit", 0),
            "bot_trap":            metrics["by_reason"].get("bot-trap", 0),
            "canary_echo":         metrics["by_reason"].get("canary-echo", 0),
            "ja4_banned":          metrics["by_reason"].get("fp-banned", 0),
            "host_not_allowed":    metrics["by_reason"].get("host-not-allowed", 0),
            "abuseipdb":           sum(metrics["by_reason"].get(k, 0) for k in
                                       ("abuseipdb-high","abuseipdb-med")),
            "crowdsec":            metrics["by_reason"].get("crowdsec-banned", 0),
            "asn_hosting":         metrics["by_reason"].get("asn-hosting", 0),
            "js_challenge":        metrics["by_reason"].get("chal-required", 0),
            "missed_medium_risk":  metrics.get("missed", 0),
        }

        return web.json_response({
            "uptime_secs": int(_t.time() - START_EPOCH),
            "total": metrics["total_requests"],
            "allowed": metrics["allowed"],
            "blocked": metrics["blocked"],
            "missed": metrics.get("missed", 0),
            "by_reason": dict(metrics["by_reason"]),
            "by_status": {str(k): v for k, v in metrics["by_status"].items()},
            "top_paths": [{"path": p, "count": c, "vhost": _path_to_vhost.get(p, "")} for p, c in top_paths],
            "clients": clients,
            "events": recent_events,
            "live_rps": live_rps,
            "global_rps_limit": GLOBAL_RPS_LIMIT,
            "timeline": timeline_out,
            "timeline_range_min": range_min,
            "timeline_bucket_secs": bucket_secs,
            "timeline_end_epoch": end_b,
            "timeline_is_live": end_epoch >= int(_t.time()) - 30,
            "services":      services,
            "detector_hits": detector_hits,
            "config": {
                "burst": RATE_LIMIT_BURST,
                "refill": RATE_LIMIT_REFILL,
                "trust_xff": TRUST_XFF,
                "upstream": UPSTREAM,
                "honeypot_ban_secs": HONEYPOT_BAN_SECS,
                "pow_difficulty": POW_DIFFICULTY,
            },
        }, headers={"Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff"})

async def dashboard_endpoint(request: web.Request):
    """HTML dashboard page (auto-refreshes every 2s via fetch /__metrics)."""
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    body = DASHBOARD_HTML.replace('<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1)
    return web.Response(
        text=body,
        content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'"
            ),
        },
    )

DASHBOARD_HTML         = (_DASHBOARDS_DIR / "main.html").read_text(encoding="utf-8")
CONTROL_CENTER_HTML    = (_DASHBOARDS_DIR / "control_center.html").read_text(encoding="utf-8")


async def control_center_endpoint(request: web.Request):
    """Control Center — landing page after login; shows vhost traffic summary."""
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    return web.Response(
        text=CONTROL_CENTER_HTML.replace('<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1),
        content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'"
            ),
        },
    )

@_require_csrf
async def unban_endpoint(request: web.Request):
    """Admin: clear ban + risk score for an identity (or all). Useful when a
    false-positive pushed someone over threshold.
      POST body JSON: {"id":"<identity>"} | {"ip":"<ip>"} | {"all":true}
      GET query (legacy, read-only ops only): ?id=... | ?ip=...
      ?all=1 via GET is rejected — use POST {"all":true} for destructive op.
    """
    if request.method == "POST":
        if denied := _role_denied(request, "admin", "maintainer"):
            return denied
        try:
            data = await request.json()
        except Exception:
            data = {}
        target_id = data.get("id")
        target_ip = data.get("ip")
        do_all = bool(data.get("all"))
    else:
        target_id = request.query.get("id")
        target_ip = request.query.get("ip")
        # Reject all=1 via GET (CSRF-safe: destructive ops require POST)
        if request.query.get("all") in ("1", "true", "yes"):
            return web.json_response({"error": "Use POST {\"all\":true} for unban-all"},
                                     status=405, headers={"Cache-Control": "no-store"})
        do_all = False
    cleared = 0
    async with state_lock:
        n = now()
        for k, s in ip_state.items():
            match = (do_all
                     or (target_id and k == target_id)
                     or (target_ip and s.last_ip == target_ip))
            if match:
                if s.banned_until > n:
                    s.banned_until = 0.0
                s.risk_score = 0.0
                cleared += 1
        # Also clear DB bans table + ip_bans for matched IPs (best-effort).
        try:
            conn = sqlite3.connect(DB_PATH)
            if do_all:
                conn.execute("DELETE FROM bans")
                conn.execute("DELETE FROM ip_bans")
                conn.execute("UPDATE clients SET banned_until_epoch=0")
            elif target_ip:
                conn.execute("DELETE FROM bans WHERE ip=?", (target_ip,))
                conn.execute("DELETE FROM ip_bans WHERE ip=?", (target_ip,))
                conn.execute("UPDATE clients SET banned_until_epoch=0 WHERE ip=?",
                             (target_ip,))
            elif target_id:
                conn.execute("DELETE FROM bans WHERE ip=?", (target_id,))
                conn.execute("DELETE FROM ip_bans WHERE ip=?", (target_id,))
                conn.execute("UPDATE clients SET banned_until_epoch=0 WHERE ip=?",
                             (target_id,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[unban] db error: {e}")
    return web.json_response({"cleared": cleared, "scope":
        "all" if do_all else (f"id={target_id}" if target_id else f"ip={target_ip}")},
        headers={"Cache-Control": "no-store"})

@_require_csrf
async def bulk_unban_endpoint(request: web.Request):
    """Admin: bulk-clear bans matching a reason glob or ASN.

    DELETE /secured/bans?reason=<glob>
        Clears in-memory risk scores and DB bans whose reason fnmatch-matches
        the glob (e.g. reason=honeypot* or reason=ua-ai-*).

    DELETE /secured/bans?asn=<number>
        Clears bans for all identities last seen on the given ASN (requires
        in-memory last_asn field; no-op if ASN tracking not active).

    DELETE /secured/bans?reason=<glob>&asn=<number>
        Intersection — reason AND asn must both match.

    POST body may also supply {"reason":"<glob>","asn":<int>} for symmetry
    with unban_endpoint; method must be POST or DELETE.

    Returns {"cleared": N, "reason_glob": str, "asn": int|null}.
    """
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied

    import fnmatch as _fnm

    if request.method == "POST":
        try:
            data = await request.json()
        except Exception:
            data = {}
        reason_glob = str(data.get("reason", "") or "").strip()
        asn_str     = str(data.get("asn", "") or "").strip()
    else:
        reason_glob = request.query.get("reason", "").strip()
        asn_str     = request.query.get("asn", "").strip()

    if not reason_glob and not asn_str:
        return web.json_response(
            {"error": "Provide ?reason=<glob> and/or ?asn=<number>"},
            status=400, headers={"Cache-Control": "no-store"},
        )

    target_asn: int | None = None
    if asn_str:
        try:
            target_asn = int(asn_str)
        except ValueError:
            return web.json_response(
                {"error": "asn must be an integer"},
                status=400, headers={"Cache-Control": "no-store"},
            )

    cleared = 0
    matched_ips: list[str] = []
    async with state_lock:
        n = now()
        for k, s in ip_state.items():
            if s.banned_until <= n:
                continue
            reason_match = (
                not reason_glob
                or any(_fnm.fnmatch(r, reason_glob) for r in s.risk_by_reason)
            )
            asn_match = (
                target_asn is None
                or getattr(s, "last_asn", None) == target_asn
            )
            if reason_match and asn_match:
                s.banned_until = 0.0
                s.risk_score   = 0.0
                matched_ips.append(s.last_ip or k)
                cleared += 1

    # Best-effort DB cleanup (bans + ip_bans)
    if matched_ips or reason_glob:
        try:
            conn = sqlite3.connect(DB_PATH)
            if reason_glob and not matched_ips:
                # glob-only: delete matching DB rows directly (db may have
                # rows whose in-memory state already expired)
                all_bans = conn.execute(
                    "SELECT ip, reason FROM bans"
                ).fetchall()
                db_del = [
                    row[0] for row in all_bans
                    if _fnm.fnmatch(str(row[1] or ""), reason_glob)
                ]
                for ip in db_del:
                    conn.execute("DELETE FROM bans WHERE ip=?", (ip,))
                    conn.execute("DELETE FROM ip_bans WHERE ip=?", (ip,))
                    conn.execute(
                        "UPDATE clients SET banned_until_epoch=0 WHERE ip=?",
                        (ip,),
                    )
            else:
                for ip in matched_ips:
                    conn.execute("DELETE FROM bans WHERE ip=?", (ip,))
                    conn.execute("DELETE FROM ip_bans WHERE ip=?", (ip,))
                    conn.execute(
                        "UPDATE clients SET banned_until_epoch=0 WHERE ip=?",
                        (ip,),
                    )
            conn.commit()
            conn.close()
        except Exception as _e:
            print(f"[bulk_unban] db error: {_e}")

    print(
        f"event=bulk_unban reason_glob={reason_glob!r} asn={target_asn} count={cleared}",
        flush=True,
    )
    return web.json_response(
        {"cleared": cleared, "reason_glob": reason_glob, "asn": target_asn},
        headers={"Cache-Control": "no-store"},
    )


# ── 1.8.12: Honeypot learning subsystem ──────────────────────────────────────

async def _load_honey_fp_cache() -> None:
    """Load confirmed-attacker JA4 fingerprints from honey_fingerprints table
    into the in-process cache at startup. Best-effort; failures are non-fatal."""
    try:
        import sqlite3 as _sq
        from config import DB_PATH as _DBPATH
        conn = _sq.connect(_DBPATH)
        rows = conn.execute(
            "SELECT DISTINCT ja4 FROM honey_fingerprints "
            "WHERE ja4 IS NOT NULL AND ja4 != ''"
        ).fetchall()
        conn.close()
        for (j,) in rows:
            if j:
                _honey_fp_ja4_cache.add(j)
        if _honey_fp_ja4_cache:
            slog("honey_fp_cache_loaded", count=len(_honey_fp_ja4_cache))
    except Exception:
        pass


# Known scanner probe sequences. If an IP's honeypot hits cover ≥2 of a
# scanner's signature paths, we label it in the Attack Playbook view.
_SCANNER_SEQUENCES: dict = {
    "nuclei":         {"/.git/config", "/.git/HEAD", "/phpinfo.php",
                       "/.env", "/actuator/health", "/server-status"},
    "wpscan":         {"/wp-login.php", "/wp-json/wp/v2/users",
                       "/xmlrpc.php", "/wp-includes/", "/wp-admin/"},
    "spring-boot":    {"/actuator/env", "/actuator/health",
                       "/actuator/mappings", "/actuator/beans"},
    "dirbuster":      {"/.htaccess", "/.htpasswd", "/backup.sql",
                       "/config.php", "/db.sql", "/dump.sql"},
    "generic-recon":  {"/phpmyadmin/", "/manager/html", "/console/",
                       "/admin.php", "/administrator/", "/cpanel/"},
}

# 1.8.11 — Attack Playbook: honeypot/trap catches grouped by technique, for the
# educational panel at the bottom of the Agents dashboard.
_PLAYBOOK_REASONS = [
    "honeypot", "honeypot-silent", "bot-trap",
    "honey-cred", "canary-echo", "canary-probe-miss",
]
_PLAYBOOK_REASON_SET = frozenset(_PLAYBOOK_REASONS)
_PLAYBOOK_ROW_CAP = 6000   # whole-query cap across all reasons


async def attack_playbook_endpoint(request: web.Request):
    """GET /secured/attack-playbook?mins=1440 — honeypot/trap hits grouped by
    technique, each with example caught requests (METHOD path). Read-only
    teaching view; auth enforced by the admin dispatch gate."""
    from collections import defaultdict as _dd
    try:
        mins = int(request.query.get("mins", "1440"))
    except (TypeError, ValueError):
        mins = 1440
    mins = max(5, min(mins, 10080))   # 5 min … 7 days
    now = _t.time()
    start = now - mins * 60

    # Single exact-set query (reason IN …) — avoids the LIKE prefix bleed where
    # "honeypot" also matched "honeypot-silent", and the per-reason round-trips.
    try:
        rows = await db_read_events_async(   # #3: off the event loop
            start, now,
            columns=["ts", "ip", "method", "path", "reason"],
            reason_in=_PLAYBOOK_REASONS, order_by="ts DESC",
            limit=_PLAYBOOK_ROW_CAP,
        )
    except Exception:
        rows = []
    capped = len(rows) >= _PLAYBOOK_ROW_CAP

    groups_by_reason: dict = {}
    ip_paths: dict = _dd(set)   # full per-IP path set (all rows, for scanner match)
    for r in rows:
        rs = r.get("reason")
        if rs not in _PLAYBOOK_REASON_SET:   # belt-and-suspenders vs SQL filter
            continue
        m = (r.get("method") or "GET").upper()
        p = (r.get("path") or "/")[:200]
        ip = r.get("ip", "")
        if ip and p:
            ip_paths[ip].add(p)
        g = groups_by_reason.get(rs)
        if g is None:                        # first row is newest (ts DESC)
            g = groups_by_reason[rs] = {
                "reason": rs, "count": 0, "capped": capped,
                "examples": [], "last_ts": r.get("ts", 0), "_seen": set(),
            }
        g["count"] += 1
        if (m, p) not in g["_seen"] and len(g["examples"]) < 6:
            g["_seen"].add((m, p))
            g["examples"].append({"method": m, "path": p,
                                  "ip": ip, "ts": r.get("ts", 0)})
    groups = []
    for g in groups_by_reason.values():
        g.pop("_seen", None)
        groups.append(g)
    groups.sort(key=lambda g: -g["count"])

    # 1.8.12 F4 — Probe sequence analysis: detect known scanner tools by matching
    # each IP's *complete* honeypot path set against signature path sets.
    scanner_hits = []
    for sip, spaths in ip_paths.items():
        for sname, ssigs in _SCANNER_SEQUENCES.items():
            matched = sorted(spaths & ssigs)
            if len(matched) >= 2:
                scanner_hits.append({"ip": sip, "scanner": sname,
                                     "matched": matched})

    # 1.8.12 F5 — Predicted next probes: once a tool is fingerprinted, the
    # signature paths it has NOT hit yet are what it will likely request next.
    # Surface them (minus paths already trapped) so the operator can trap ahead
    # of the scan. A path implied by more tools ranks higher.
    try:
        _active_traps = set(vc("HONEYPOT_PATHS") or [])
    except Exception:
        _active_traps = set()
    _pred: dict = {}
    for _sh in scanner_hits:
        _remaining = _SCANNER_SEQUENCES.get(_sh["scanner"], set()) - ip_paths.get(_sh["ip"], set())
        for _p in _remaining:
            if _p in _active_traps:
                continue
            _pred.setdefault(_p, set()).add(_sh["scanner"])
    predicted_probes = sorted(
        ({"path": p, "tools": sorted(t)} for p, t in _pred.items()),
        key=lambda x: (-len(x["tools"]), x["path"]))

    return web.json_response(
        {"groups": groups, "scanner_hits": scanner_hits,
         "predicted_probes": predicted_probes,
         "mins": mins, "ts": int(now)},
        headers={"Cache-Control": "no-store"})


async def honey_suggest_endpoint(request: web.Request):
    """1.8.12 F1 — GET /secured/honey-suggest?mins=10080&limit=20&min_hits=3
    Returns the top-N paths frequently probed by scanners (any event type)
    that are NOT already in the active honeypot trap set. Operators can
    one-click promote a suggestion into HONEYPOT_EXTRA_PATHS via the UI."""
    import time as _ht
    try:
        mins  = max(60, min(int(request.query.get("mins",  "10080")), 43200))
        limit = max(5,  min(int(request.query.get("limit", "20")),    100))
        min_hits = max(1, min(int(request.query.get("min_hits", "3")), 1000))
    except (TypeError, ValueError):
        mins, limit, min_hits = 10080, 20, 3

    now_ts = _ht.time()
    start_ts = now_ts - mins * 60
    current_traps = vc("HONEYPOT_PATHS") | set()   # copy

    candidates: list = []
    try:
        import sqlite3 as _sq
        from config import DB_PATH as _DBPATH
        conn = _sq.connect(_DBPATH)
        rows = conn.execute(
            "SELECT path, COUNT(*) AS n FROM events "
            "WHERE ts >= ? AND path != '' "
            "GROUP BY path ORDER BY n DESC LIMIT 500",
            (start_ts,),
        ).fetchall()
        conn.close()
        for path_val, cnt in rows:
            if not path_val or path_val in current_traps:
                continue
            if cnt < min_hits:
                break
            candidates.append({"path": path_val, "hits": cnt})
            if len(candidates) >= limit:
                break
    except Exception as _e:
        slog("honey_suggest_error", level="warn", error=str(_e))

    return web.json_response(
        {"candidates": candidates, "current_trap_count": len(current_traps),
         "mins": mins, "ts": int(now_ts)},
        headers={"Cache-Control": "no-store"},
    )


# Each entry annotated with the runtime-toggle knob (if any) that
# controls whether the detector runs. UI uses this to render a switch
# next to the weight, merging the old "Toggles" and "Bot scoring
# weights" cards into a single table.
SIGNAL_KNOB = {
    # Operator-toggleable detectors → runtime ON/OFF switch
    "js-challenge":       "JS_CHALLENGE",
    "bot-trap":           "BOT_TRAP_FORMS",
    "suspicious-body":    "BODY_PATTERN_MATCH",
    "canary-echo":        "CANARY_ECHO_DETECTION",
    "accept-fp":          "ACCEPT_FP_ENABLED",
    "labyrinth-jitter":   "LABYRINTH_JITTER_ENABLED",
    "header-canary":      "HEADER_CANARY_ENABLED",
    "origin-mismatch":    "STRICT_ORIGIN",
    "tls-fingerprint":    "TLS_FP_BLOCK_ENABLED",
    "abuseipdb-high":     "ABUSEIPDB_ENABLED",
    "abuseipdb-med":      "ABUSEIPDB_ENABLED",
    "crowdsec-banned":    "CROWDSEC_ENABLED",
    "asn-hosting":        "MAXMIND_ENABLED",
    # 1.6.0 — Tier-A toggles
    "country-blocked":    "COUNTRY_BLOCK_ENABLED",
    "tor-exit":           "TOR_BLOCK_ENABLED",
    "datacenter-vpn":     "DC_VPN_BLOCK_ENABLED",
    "ua-ai-openai":       "AI_UA_OPENAI_ENABLED",
    "ua-ai-anthropic":    "AI_UA_ANTHROPIC_ENABLED",
    "ua-ai-google":       "AI_UA_GOOGLE_ENABLED",
    "ua-ai-perplexity":   "AI_UA_PERPLEXITY_ENABLED",
    "ua-ai-meta":         "AI_UA_META_ENABLED",
    "ua-ai-other":        "AI_UA_OTHER_ENABLED",
    # 1.6.1 — Tier-B toggles
    "custom-rule-block":  "CUSTOM_RULES_ENABLED",
    "rate-limit-endpoint": "ENDPOINT_RATE_LIMIT_ENABLED",
    "body-sqli":          "BODY_GROUP_SQLI_ENABLED",
    "body-xss":           "BODY_GROUP_XSS_ENABLED",
    "body-lfi":           "BODY_GROUP_LFI_ENABLED",
    "body-rce":           "BODY_GROUP_RCE_ENABLED",
    "body-ssrf":          "BODY_GROUP_SSRF_ENABLED",
    "body-cmd":           "BODY_GROUP_CMD_ENABLED",
    "auth-jwt-invalid":   "JWT_VALIDATION_ENABLED",
    "slow-client":        "WAF_SLOWLORIS_ENABLED",
    "botd-detected":      "BOTD_ENABLED",              # 1.6.5 — client-side fingerprintjs/botd
    # 1.6.2 — Tier-C DLP toggles
    "dlp-cc":             "DLP_GROUP_CC_ENABLED",
    "dlp-aws":            "DLP_GROUP_AWS_ENABLED",
    "dlp-jwt":            "DLP_GROUP_JWT_ENABLED",
    "dlp-private-key":    "DLP_GROUP_PRIVATE_KEY_ENABLED",
    "dlp-api-key":        "DLP_GROUP_API_KEY_ENABLED",
    "dlp-pii-email":      "DLP_GROUP_PII_EMAIL_ENABLED",
    "dlp-pii-ssn":        "DLP_GROUP_PII_SSN_ENABLED",
    # 1.6.9 — AI Labyrinth
    "tarpit-walk":        "LABYRINTH_ENABLED",
    # 1.6.10
    "header-order-fp":    "HEADER_ORDER_FP_ENABLED",
    "ai-ua-ip-mismatch":  "AI_CRAWLER_VERIFY_ENABLED",
    "locale-geo-mismatch":"LOCALE_GEO_CHECK_ENABLED",
    "robots-violation":   "ROBOTS_MONITOR_ENABLED",
    "h2-fp":              "H2_FP_ENABLED",
    "json-canary":        "JSON_CANARY_ENABLED",
    # 1.5.4: 11 new per-detector kill-switches
    "honeypot":           "HONEYPOT_ENABLED",
    "honeypot-silent":    "HONEYPOT_ENABLED",
    # 1.8.12 — honeypot learning subsystem (both gated by HONEYPOT_ENABLED)
    "coordinated-honeypot": "HONEYPOT_ENABLED",
    "honey-fp-match":       "HONEYPOT_ENABLED",
    "suspicious-path":    "SUSPICIOUS_PATH_ENABLED",
    "ai-probe":           "AI_PROBE_ENABLED",
    "ua-empty":           "UA_FILTER_ENABLED",
    "ua-blocked":         "UA_FILTER_ENABLED",
    "ua-too-short":       "UA_FILTER_ENABLED",
    "ua-non-browser":     "UA_FILTER_ENABLED",
    "ua-platform-mismatch": "UA_PLATFORM_CHECK_ENABLED",
    "ai-headers-empty":   "HEADER_COMPLETENESS_ENABLED",
    "ai-headers-incomplete": "HEADER_COMPLETENESS_ENABLED",
    "behavior":           "BEHAVIORAL_CHECK_ENABLED",
    "ai-enumeration":     "AI_ENUMERATION_ENABLED",
    "ai-no-assets":       "AI_NO_ASSETS_ENABLED",
    "session-flood":      "SESSION_FLOOD_ENABLED",
    "upstream-404":       "UPSTREAM_404_TRACKING_ENABLED",
    # ── 1.7.2 ──
    "cookie-ghost":       "COOKIE_GHOST_ENABLED",
    "lifecycle-miss":     "COOKIE_LIFECYCLE_ENABLED",
    "referer-ghost":      "REFERER_CHAIN_ENABLED",
    "impossible-travel":  "IMPOSSIBLE_TRAVEL_ENABLED",
    "soft-renderer":      "FP_ENRICHMENT_ENABLED",
    "webgl-missing":      "FP_ENRICHMENT_ENABLED",
    # ── 1.7.3 ──
    "path-sweep":         "PATH_SWEEP_ENABLED",
    # ── 1.8.9 — WAF always-on knobs (now toggleable) ──
    "accept-wildcard-html":   "ACCEPT_WILDCARD_CHECK_ENABLED",
    "body-critical-injection": "WAF_BODY_ENABLED",
    "body-xxe":               "WAF_BODY_ENABLED",
    "body-proto-pollution":   "WAF_BODY_ENABLED",
    "smuggling-cl-te":        "WAF_SMUGGLING_ENABLED",
    "smuggling-te-cl":        "WAF_SMUGGLING_ENABLED",
    "smuggling-te-te":        "WAF_SMUGGLING_ENABLED",
    "smuggling-invalid-te":   "WAF_SMUGGLING_ENABLED",
    "method-override-attempt":"WAF_VERB_OVERRIDE_ENABLED",
    "header-ssti":            "WAF_HEADER_INJECTION_ENABLED",
    "host-header-injection":  "WAF_HEADER_INJECTION_ENABLED",
    "gql-introspection":      "WAF_GRAPHQL_ENABLED",
    "gql-batch-abuse":        "WAF_GRAPHQL_ENABLED",
    "gql-depth-exceeded":     "WAF_GRAPHQL_ENABLED",
    "upload-dangerous-ext":   "WAF_UPLOAD_ENABLED",
    "upload-dangerous-magic": "WAF_UPLOAD_ENABLED",
    # ── 1.8.9 — Remaining always-on controls now toggleable ──
    "smuggling-dual-header":    "WAF_SMUGGLING_ENABLED",
    "smuggling-obfuscated-te":  "WAF_SMUGGLING_ENABLED",
    "smuggling-duplicate-cl":   "WAF_SMUGGLING_ENABLED",
    "honey-cred":               "HONEY_CRED_ENABLED",
    "canary-probe-miss":        "CANARY_PROBE_ENABLED",
    "llm-no-subresources":      "LLM_HEURISTIC_ENABLED",
    "webdriver-detected":       "AUTOMATION_PROBE_ENABLED",
    "bot-motion":               "INTERACTION_PROBE_ENABLED",
    "no-interaction":           "INTERACTION_PROBE_ENABLED",
    "scripted-motion":          "INTERACTION_PROBE_ENABLED",
    "bot-scroll":               "INTERACTION_PROBE_ENABLED",
    "scripted-keys":            "INTERACTION_PROBE_ENABLED",
    "low-entropy-input":        "INTERACTION_PROBE_ENABLED",
    "coordinated-probe":        "COORDINATED_ATTACK_ENABLED",
    "direct-api-probe":         "JOURNEY_CHECK_ENABLED",
    "session-churn":            "SESSION_CHURN_ENABLED",
    "ja4h-deny":                "JA4H_DENY_ENABLED",
    "host-not-allowed":         "HOST_BLOCKING_ENABLED",
    "missing-required-header":  "REQUIRED_HEADERS_ENABLED",
    "ja4-required-missing":     "JA4_REQUIRED_ENABLED",
    "upstream-auth-fail":       "UPSTREAM_AUTH_FAIL_ENABLED",
    "headers-suspicious":       "HEADER_COMPLETENESS_ENABLED",
    "rate-limit-ip":            "RATE_LIMIT_IP_ENABLED",
    "rate-limit":               "RATE_LIMIT_ENABLED",
    "fp-banned":                "FP_BAN_CHECK_ENABLED",
    "traffic-threshold":        "TRAFFIC_THRESHOLD_ENABLED",
    # 1.8.10 — synthetic reasons emitted directly by middleware (not in
    # RISK_WEIGHTS). Mapped so the Risk-breakdown "control" column shows the
    # knob that governs them instead of "—". Admin-namespace gates are
    # mandatory (no on/off) → None = always-on.
    "chal-required":            "JS_CHALLENGE",
    "pow-required":             "POW_REQUIRED_PATHS",
    "admin-ip-blocked":         "ADMIN_ALLOWED_IPS",  # source IP not on the allowlist
    "banned-silent":            "RISK_BAN_THRESHOLD",
    "banned":                   "RISK_BAN_THRESHOLD",
    "admin-probe":              None,   # admin auth is always-on (not toggleable)
    "operator-self":            None,   # admin auth is always-on
    "internal-probe":           None,   # legacy admin-gate reason; always-on
}

async def scoring_endpoint(request: web.Request):
    """Read-only view of the bot scoring config: per-signal weight, ban
    thresholds, decay, and a short description per signal so the operator
    can reason about why a given identity got banned."""
    DESCRIPTIONS = {
        "honeypot":              ("hard", "Hit a honeypot path (/.git/HEAD, /.env, /wp-admin, …)"),
        "honeypot-silent":       ("hard", "Honeypot hit — silently decoyed (same severity)"),
        "suspicious-path":       ("hard", "Path matches CTF/file-hunting/SQLi/LFI regex"),
        "ai-probe":              ("med",  "Hit an AI-probe endpoint (/openapi.json, /llms.txt, …)"),
        "ai-enumeration":        ("med",  ">300 distinct paths per identity (scanner)"),
        "behavior":              ("soft", "Inter-arrival σ/μ < 0.05 — robotic timing"),
        "ua-empty":              ("med",  "User-Agent header missing"),
        "ua-blocked":            ("med",  "UA matched blocklist (curl, python-requests, sqlmap, …)"),
        "ua-non-browser":        ("med",  "UA does not look like a browser"),
        "ai-headers-empty":      ("med",  "No Accept-* nor Sec-Fetch-* headers"),
        "ua-too-short":          ("soft", "UA suspiciously short (< 12 chars)"),
        "ai-headers-incomplete": ("soft", "Browser UA but Sec-Ch-Ua / Sec-Fetch-* absent"),
        "upstream-404":          ("soft", "Upstream returned 404 (small enumeration tick)"),
        "ai-no-assets":          ("soft", "≥25 HTML loads, 0 static asset fetches"),
        "session-flood":         ("soft", "Many distinct identities minted from same IP"),
        "rate-limit-ip":         ("soft", "Per-IP rate limit hit (no risk; just throttle)"),
        "rate-limit":            ("soft", "Per-identity rate limit hit (no risk; just throttle)"),
        "host-not-allowed":      ("med",  "Host header not in ALLOWED_HOSTS"),
        "suspicious-body":       ("med",  "POST body matches SQLi/XSS/SSTI/cmd patterns"),
        "bot-trap":              ("hard", "Hidden honey field in form was filled"),
        "canary-echo":           ("hard", "Echoed back an agw-c-* canary token (LLM agent)"),
        "session-churn":         ("hard", "Same UA+IP-tier+JA4 minted N cookies in window"),
        "fp-banned":             ("info", "Already-banned fingerprint hit (counter only)"),
        "traffic-threshold":     ("info", "Operator-set GLOBAL_RPS_LIMIT cap"),
        "js-challenge":          ("soft", "Unsolved JS challenge attempt"),
        "tls-fingerprint":       ("med",  "JA3/JA4 in JA4_DENY_LIST"),
        "origin-mismatch":       ("med",  "STRICT_ORIGIN: Origin header mismatch"),
        "missing-required-header": ("med", "REQUIRED_HEADERS not all present"),
        "ua-platform-mismatch":  ("med",  "UA / Sec-Ch-Ua / platform headers contradict"),
        "accept-wildcard-html":  ("soft", "Accept: */* on HTML navigation request"),
        "accept-fp":             ("soft", "Accept header fingerprint mismatch — browser UA on HTML navigation but Accept lacks text/html (e.g. application/json). Real browsers always include text/html on document navigation."),
        "labyrinth-jitter":      ("modifier", "Tarpit timing jitter — Gaussian-distributed random delay (200–3000 ms, σ=500 ms) per chunk instead of fixed LABYRINTH_SLOW_MS. Makes it harder for bots to fingerprint the gateway by timing the delay cadence."),
        "header-canary":         ("modifier", "Header canary injection — plants a per-identity HMAC-signed token in ETag and X-Request-Id response headers. AI frameworks that replay full response headers (LangChain, AutoGen) echo the token back, triggering the canary-echo ban."),
        # ── 1.6.10 ──
        "header-order-fp":       ("soft",     "Header-order library fingerprint (+8) — the ordered set of HTTP header names matches a known library pattern (python-requests, curl, Go net/http, httpx). Real browsers send 10+ headers in a consistent browser-defined order."),
        "ai-ua-ip-mismatch":     ("med",      "AI-crawler UA / IP mismatch (+30) — claimed to be an OpenAI/Perplexity crawler but source IP is not in the vendor's published CIDR range. Strong spoof indicator."),
        "locale-geo-mismatch":   ("soft",     "Accept-Language / GeoIP mismatch (+10) — primary language tag in Accept-Language is implausible for the GeoIP country (e.g. Accept-Language: ru from a US IP). Fires only for countries with a single dominant language."),
        "robots-violation":      ("soft",     "robots.txt violation (+5) — declared AI-crawler UA ignored the gateway's robots.txt (Disallow: / for all known AI bots). Fires alongside ua-ai-* to add violation context to the event log."),
        "h2-fp":                 ("soft",     "HTTP/2 fingerprint fallback (+3) — HTTP/1.1 request from a modern-browser UA behind a TLS proxy. Real browsers always negotiate HTTP/2 on HTTPS; libraries default to HTTP/1.1. Requires H2_FP_ENABLED=1."),
        "json-canary":           ("modifier", "JSON canary injection — plants a \"_ref\" token in JSON object responses. LLM agents that cache and replay API responses echo the token back, triggering canary-echo detection."),
        "ja4-required-missing":  ("soft", "JA4 expected from trusted peer but absent"),
        "headers-suspicious":    ("soft", "Generic header-shape anomaly"),
        "abuseipdb-high":        ("hard", "AbuseIPDB confidence ≥ 80 — community-vetted bad IP"),
        "abuseipdb-med":         ("med",  "AbuseIPDB confidence in [40,80)"),
        "crowdsec-banned":       ("hard", "CrowdSec LAPI returned an active decision for this IP"),
        "asn-hosting":           ("soft", "Source IP belongs to a hosting/cloud provider ASN"),
        # ── 1.6.0: Tier-A signals ──
        "country-blocked":       ("hard", "Source country in COUNTRY_DENYLIST (or outside COUNTRY_ALLOWLIST)"),
        "tor-exit":              ("hard", "Source IP is a known Tor exit node"),
        "datacenter-vpn":        ("med",  "Source IP is in a known datacenter/VPN feed"),
        "ua-ai-openai":          ("med",  "AI-crawler UA: OpenAI / GPTBot / ChatGPT-User / OAI-SearchBot"),
        "ua-ai-anthropic":       ("med",  "AI-crawler UA: ClaudeBot / Claude-Web / anthropic-ai"),
        "ua-ai-google":          ("med",  "AI-crawler UA: Google-Extended / Bard / Gemini"),
        "ua-ai-perplexity":      ("med",  "AI-crawler UA: PerplexityBot"),
        "ua-ai-meta":            ("med",  "AI-crawler UA: Meta-ExternalAgent / FacebookBot"),
        "ua-ai-other":           ("med",  "Other AI-crawler UAs (Bytespider, CCBot, Cohere, etc.)"),
        # ── 1.6.1: Tier-B signals ──
        "custom-rule-block":     ("hard", "Operator-defined CUSTOM_RULES IF/THEN block matched"),
        "rate-limit-endpoint":   ("info", "Per-endpoint rate limit hit (no risk; just throttle)"),
        "body-sqli":             ("hard", "Body matched SQL-injection pattern group"),
        "body-xss":              ("hard", "Body matched cross-site-scripting pattern group"),
        "body-lfi":              ("hard", "Body matched local-file-inclusion pattern group"),
        "body-rce":              ("hard", "Body matched remote-code-execution pattern group"),
        "body-ssrf":             ("hard", "Body matched server-side-request-forgery pattern group"),
        "body-cmd":              ("hard", "Body matched OS-command-injection pattern group"),
        "auth-jwt-invalid":      ("med",  "JWT missing / invalid signature on JWT_VALIDATE_PATHS route"),
        "slow-client":           ("soft", "Body upload exceeded BODY_TIMEOUT (slowloris guard)"),
        "botd-detected":         ("med",  "FingerprintJS BotD client-side library reported the visitor as a bot (headless / WebDriver / automation markers)"),
        # ── 1.6.2: Tier-C DLP (response-side) ──
        # 1.6.3 — promoted from "info" to "intel" tier. DLP fires aren't
        # operational chatter (rate-limit) — they're upstream leaks the
        # operator must investigate. Distinct tier + colour in dashboards.
        "dlp-cc":                ("intel", "Upstream response contained a Luhn-valid credit-card number"),
        "dlp-aws":               ("intel", "Upstream response contained an AWS access-key / secret"),
        "dlp-jwt":               ("intel", "Upstream response contained a JWT (eyJ…)"),
        "dlp-private-key":       ("intel", "Upstream response contained a PEM private key"),
        "dlp-api-key":           ("intel", "Upstream response contained an API-key-shaped token (Slack / GitHub / OpenAI / labelled)"),
        "dlp-pii-email":         ("intel", "Upstream response contained an email address (off by default — noisy)"),
        "dlp-pii-ssn":           ("intel", "Upstream response contained a US SSN (3-2-4 grouped digits)"),
        # ── 1.6.9: AI Labyrinth ──
        "tarpit-walk":           ("hard",  "Client followed a hidden rel=nofollow link injected into proxied HTML — only automated crawlers traverse invisible links. Near-zero FP; instant ban + response deliberately slow-dripped to exhaust crawler resources."),
        # ── 1.7.2 ──
        "cookie-ghost":          ("med",   "Gateway set cookies but client never returned them across 3+ requests — pure-HTTP bot not running a real browser cookie jar."),
        "lifecycle-miss":        ("soft",  "HTML page was served (lifecycle JS injected), but agw_lc cookie absent on subsequent non-HTML requests — JS not executing or bot stripping cookies."),
        "referer-ghost":         ("soft",  "Referer claims our domain but the referenced path was never served to this identity — fabricated Referer (common in automated requests)."),
        "impossible-travel":     ("hard",  "Same session-keyed identity appeared from different countries within the impossible-travel window — session hijack or account-sharing across VPN hops."),
        "soft-renderer":         ("med",   "WebGL renderer/vendor string contains a known software-renderer pattern (swiftshader, mesa, llvmpipe, vmware) — virtual or headless environment."),
        "webgl-missing":         ("soft",  "Chrome UA but no WebGL renderer returned — headless Chrome with WebGL blocked or disabled (common in Puppeteer/Playwright default configs)."),
        # ── 1.7.3 ──
        "path-sweep":            ("hard",  "Identity visited too many distinct non-static paths in a short window (PATH_SWEEP_THRESHOLD in PATH_SWEEP_WINDOW_SECS s) — automated content discovery / directory enumeration after warm-up bypass."),
        # ── 1.8.10 — synthetic reasons (emitted by middleware, weight 0) ──
        "chal-required":         ("info", "JS-challenge gate (JS_CHALLENGE): the request lacked a valid `chal` cookie. A real browser solves Turnstile / the heuristic challenge to obtain it; pure-HTTP bots are silent-decoyed."),
        "pow-required":          ("info", "Proof-of-Work gate (POW_REQUIRED_PATHS): this path requires a valid PoW token/solution. Returns 402 with a fresh challenge until solved."),
        "admin-probe":           ("info", "Unauthenticated request to an admin path — anonymous reconnaissance of /secured/*, /__config, etc. Served the upstream 404 decoy. Admin auth is mandatory (no toggle)."),
        "operator-self":         ("info", "The operator's OWN browser hitting an admin path with a lapsed (expired/revoked) session — benign self-noise; decoyed but NOT counted as a block. Re-login clears it."),
        "internal-probe":        ("info", "Legacy (pre-1.8.10) unauthenticated admin-path reason; now split into operator-self (benign) and admin-probe (recon)."),
        "admin-ip-blocked":      ("info", "Source IP is not in ADMIN_ALLOWED_IPS. Admin endpoints return the upstream 404 (mirrors a real not-found — no leak)."),
        "banned-silent":         ("info", "Identity is in the 24h hostile pool (risk crossed RISK_BAN_THRESHOLD, or a really-ban signal like canary-echo/honeypot fired). Every request returns the upstream homepage so the bot can't tell it was caught."),
        "banned":                ("info", "Identity is currently banned (risk ≥ RISK_BAN_THRESHOLD)."),
    }
    # Per-signal latency cost (typical / cached / p99 in ms) + impact kind.
    #
    # kind values:
    #   "in-process" — pure string/header checks, O(1) set/dict ops (µs range)
    #   "state"      — accesses shared mutable state (rate buckets, risk scores, sets)
    #   "regex"      — regex scan on path or body content (scales with body size)
    #   "mmdb"       — in-memory MaxMind DB lookup (never network; sub-ms always)
    #   "network"    — outbound API call to AbuseIPDB / CrowdSec LAPI
    #   "response"   — scans upstream response body (DLP); adds to response latency, not request
    #   "adversary"  — intentional delay; never fires for legitimate traffic
    #
    # For "adversary" kind, typical/p99 represent the forced adversary delay,
    # NOT gateway overhead on normal traffic (which is 0).
    SIGNAL_COST = {
        # ── External integrations (network call) ─────────────────────────
        "abuseipdb-high":       {"kind": "network",     "cached": 0.3,  "typical": 150,   "p99": 450},
        "abuseipdb-med":        {"kind": "network",     "cached": 0.3,  "typical": 150,   "p99": 450},
        "crowdsec-banned":      {"kind": "network",     "cached": 0.2,  "typical": 5,     "p99": 20},
        # ── MaxMind in-memory DB lookups ──────────────────────────────────
        "asn-hosting":          {"kind": "mmdb",        "cached": 0.1,  "typical": 0.1,   "p99": 0.5},
        "country-blocked":      {"kind": "mmdb",        "cached": 0,    "typical": 0.1,   "p99": 0.5},
        "datacenter-vpn":       {"kind": "mmdb",        "cached": 0,    "typical": 0.1,   "p99": 0.5},
        # ── Regex scans on request path / body ───────────────────────────
        # suspicious-path: 70+ patterns (1.6.5 expansion) applied to URL path
        "suspicious-path":      {"kind": "regex",       "cached": 0,    "typical": 0.1,   "p99": 0.5},
        # suspicious-body: 70+ patterns across POST body; scales with UPSTREAM_MAX_BODY
        "suspicious-body":      {"kind": "regex",       "cached": 0,    "typical": 0.8,   "p99": 5},
        # body group scanners — separate regex families, applied on POST/PUT/PATCH bodies
        "body-sqli":            {"kind": "regex",       "cached": 0,    "typical": 0.3,   "p99": 2.0},
        "body-xss":             {"kind": "regex",       "cached": 0,    "typical": 0.3,   "p99": 2.0},
        "body-lfi":             {"kind": "regex",       "cached": 0,    "typical": 0.2,   "p99": 1.0},
        "body-rce":             {"kind": "regex",       "cached": 0,    "typical": 0.2,   "p99": 1.0},
        "body-ssrf":            {"kind": "regex",       "cached": 0,    "typical": 0.2,   "p99": 1.0},
        "body-cmd":             {"kind": "regex",       "cached": 0,    "typical": 0.2,   "p99": 1.0},
        # canary-echo: dict lookup + header scan + body scan
        "canary-echo":          {"kind": "regex",       "cached": 0,    "typical": 0.2,   "p99": 1.5},
        # bot-trap: scan form body for hidden field value
        "bot-trap":             {"kind": "regex",       "cached": 0,    "typical": 0.1,   "p99": 1},
        # ── In-process checks (O(1), no I/O) ─────────────────────────────
        "honeypot":             {"kind": "in-process",  "cached": 0,    "typical": 0.005, "p99": 0.05},
        "honeypot-silent":      {"kind": "in-process",  "cached": 0,    "typical": 0.005, "p99": 0.05},
        "ai-probe":             {"kind": "in-process",  "cached": 0,    "typical": 0.005, "p99": 0.05},
        "ua-empty":             {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.01},
        "ua-too-short":         {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.01},
        # ua-blocked: substring scan across 60+ UA entries (lowercase)
        "ua-blocked":           {"kind": "in-process",  "cached": 0,    "typical": 0.02,  "p99": 0.1},
        "ua-non-browser":       {"kind": "in-process",  "cached": 0,    "typical": 0.005, "p99": 0.02},
        "ua-platform-mismatch": {"kind": "in-process",  "cached": 0,    "typical": 0.005, "p99": 0.02},
        "ua-ai-openai":         {"kind": "in-process",  "cached": 0,    "typical": 0.02,  "p99": 0.1},
        "ua-ai-anthropic":      {"kind": "in-process",  "cached": 0,    "typical": 0.02,  "p99": 0.1},
        "ua-ai-google":         {"kind": "in-process",  "cached": 0,    "typical": 0.02,  "p99": 0.1},
        "ua-ai-perplexity":     {"kind": "in-process",  "cached": 0,    "typical": 0.02,  "p99": 0.1},
        "ua-ai-meta":           {"kind": "in-process",  "cached": 0,    "typical": 0.02,  "p99": 0.1},
        "ua-ai-other":          {"kind": "in-process",  "cached": 0,    "typical": 0.02,  "p99": 0.1},
        "ai-headers-empty":     {"kind": "in-process",  "cached": 0,    "typical": 0.005, "p99": 0.01},
        "ai-headers-incomplete":{"kind": "in-process",  "cached": 0,    "typical": 0.005, "p99": 0.01},
        "accept-wildcard-html": {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.005},
        "accept-fp":            {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.005},
        "labyrinth-jitter":     {"kind": "modifier",    "cached": 0,    "typical": 0,     "p99": 0},
        "header-canary":        {"kind": "modifier",    "cached": 0,    "typical": 0,     "p99": 0},
        # 1.6.10
        "header-order-fp":      {"kind": "in-process",  "cached": 0,    "typical": 0.01,  "p99": 0.05},
        "ai-ua-ip-mismatch":    {"kind": "in-process",  "cached": 0,    "typical": 0.02,  "p99": 0.1},
        "locale-geo-mismatch":  {"kind": "mmdb",        "cached": 0.1,  "typical": 0.1,   "p99": 0.5},
        "robots-violation":     {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.005},
        "h2-fp":                {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.005},
        "json-canary":          {"kind": "modifier",    "cached": 0,    "typical": 0,     "p99": 0},
        "headers-suspicious":   {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.005},
        "host-not-allowed":     {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.005},
        "tls-fingerprint":      {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.005},
        "ja4-required-missing": {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.005},
        "missing-required-header":{"kind":"in-process", "cached": 0,    "typical": 0.005, "p99": 0.01},
        "origin-mismatch":      {"kind": "in-process",  "cached": 0,    "typical": 0.005, "p99": 0.02},
        "tor-exit":             {"kind": "in-process",  "cached": 0,    "typical": 0.001, "p99": 0.005},
        # custom-rule-block: fnmatch + dict ops on CUSTOM_RULES list
        "custom-rule-block":    {"kind": "in-process",  "cached": 0,    "typical": 0.05,  "p99": 0.5},
        # auth-jwt-invalid: base64 decode + HMAC-SHA-256 verify
        "auth-jwt-invalid":     {"kind": "in-process",  "cached": 0,    "typical": 0.5,   "p99": 2.0},
        # ── Shared-state access (rate buckets, risk counters, behavioral windows) ──
        "behavior":             {"kind": "state",        "cached": 0,    "typical": 0.005, "p99": 0.02},
        "ai-enumeration":       {"kind": "state",        "cached": 0,    "typical": 0.001, "p99": 0.005},
        "ai-no-assets":         {"kind": "state",        "cached": 0,    "typical": 0.001, "p99": 0.005},
        "session-flood":        {"kind": "state",        "cached": 0,    "typical": 0.01,  "p99": 0.05},
        "session-churn":        {"kind": "state",        "cached": 0,    "typical": 0.05,  "p99": 0.2},
        "upstream-404":         {"kind": "state",        "cached": 0,    "typical": 0.001, "p99": 0.005},
        "js-challenge":         {"kind": "state",        "cached": 0,    "typical": 0.05,  "p99": 0.3},
        "rate-limit-ip":        {"kind": "state",        "cached": 0,    "typical": 0.005, "p99": 0.02},
        "rate-limit":           {"kind": "state",        "cached": 0,    "typical": 0.005, "p99": 0.02},
        "rate-limit-endpoint":  {"kind": "state",        "cached": 0,    "typical": 0.005, "p99": 0.02},
        "fp-banned":            {"kind": "state",        "cached": 0,    "typical": 0.001, "p99": 0.005},
        "traffic-threshold":    {"kind": "state",        "cached": 0,    "typical": 0.001, "p99": 0.005},
        # botd-detected: receive POST report from browser-side FingerprintJS; gateway cost = JSON parse + ban
        "botd-detected":        {"kind": "state",        "cached": 0,    "typical": 0.1,   "p99": 0.5},
        # path-sweep: prune deque + set comprehension over maxlen=500 window (no I/O)
        "path-sweep":           {"kind": "state",        "cached": 0,    "typical": 0.05,  "p99": 0.2},
        # ── Response-side (DLP) — added to response latency, not request latency ──
        "dlp-cc":               {"kind": "response",     "cached": 0,    "typical": 0.5,   "p99": 3.0},
        "dlp-aws":              {"kind": "response",     "cached": 0,    "typical": 0.3,   "p99": 1.5},
        "dlp-jwt":              {"kind": "response",     "cached": 0,    "typical": 0.3,   "p99": 1.5},
        "dlp-private-key":      {"kind": "response",     "cached": 0,    "typical": 0.05,  "p99": 0.5},
        "dlp-api-key":          {"kind": "response",     "cached": 0,    "typical": 0.5,   "p99": 2.0},
        "dlp-pii-email":        {"kind": "response",     "cached": 0,    "typical": 0.5,   "p99": 2.0},
        "dlp-pii-ssn":          {"kind": "response",     "cached": 0,    "typical": 0.2,   "p99": 1.0},
        # ── Adversary delay — intentional; never fires for legitimate traffic ──
        # slow-client: gateway holds connection until BODY_TIMEOUT; forces slowloris cost on attacker
        "slow-client":          {"kind": "adversary",    "cached": 0,    "typical": 30000, "p99": 30000},
        # tarpit-walk: HMAC verify + ban (<0.5ms) then slow-drip HTML to waste crawler resources
        # typical = LABYRINTH_SLOW_MS × ~10 chunks; p99 = full 20-chunk page
        "tarpit-walk":          {"kind": "adversary",    "cached": 0,    "typical": 6000,  "p99": 12000},
    }
    SIGNAL_LABELS = {
        "tarpit-walk":        "AI Labyrinth",
        "labyrinth-jitter":   "AI Labyrinth Jitter",
        "header-canary":      "Header Canary Inject",
        "accept-fp":          "Accept Fingerprint",
        "header-order-fp":    "Header Order Fingerprint",
        "ai-ua-ip-mismatch":  "AI Crawler IP Mismatch",
        "locale-geo-mismatch":"Locale / GeoIP Mismatch",
        "robots-violation":   "robots.txt Violation",
        "h2-fp":              "HTTP/2 Fingerprint",
        "json-canary":        "JSON Canary Inject",
    }
    weights = []
    for sig, w in sorted(RISK_WEIGHTS.items(), key=lambda kv: -kv[1]):
        tier, desc = DESCRIPTIONS.get(sig, ("?", ""))
        cost = SIGNAL_COST.get(sig, {"cached": 0, "typical": 0.001, "p99": 0.01})
        weights.append({
            "signal":      sig,
            "label":       SIGNAL_LABELS.get(sig, sig),
            "weight":      w,
            "tier":        tier,
            "description": desc,
            "toggle":      SIGNAL_KNOB.get(sig),    # None = always-on
            "cost_ms":     cost,
            "escalate_only": sig in ESCALATE_ONLY_REASONS,   # 1.6.5
            "activation_order": _signal_runtime_order(sig),      # 1.6.10
        })
    # Modifier-only toggles — no weight, but operator-tunable.
    # Surface them at the bottom of the merged table.
    modifiers = [
        ("INJECT_SECURITY_HEADERS", "Inject HSTS/XFO/CSP/etc. on HTML responses"),
        ("JS_CHAL_BIND_JA4",        "Bind chal cookie to JA4 fingerprint (when injected)"),
        ("JS_CHAL_REQUIRE_JA4",     "Hard-require JA4 from a trusted peer at /__challenge"),
        ("JS_CHAL_STRICT_STATIC",   "Refuse static-asset bypass on API-shaped paths"),
        ("ANUBIS_ENABLED",          "Anubis-mode (1.5.4): strict PoW gate on every first request, raises difficulty by ANUBIS_DIFFICULTY_BOOST"),
        ("DLP_ENABLED",             "Outbound DLP — scan upstream response bodies for PII / secrets. Bounded by DLP_MAX_BYTES. Affects DLP group signals (dlp-cc, dlp-aws, …)."),
        ("DLP_REDACT",              "Replace DLP matches with [REDACTED-<group>] before forwarding response to client."),
        ("TARPIT_ENABLED",          "Add TARPIT_DELAY_MS slowdown to every soft-band response (tarpit-walk flow). Maximises attacker CPU/bandwidth cost without blocking."),
        ("SW_CHALLENGE_ENABLED",    "Register a Service Worker at /antibot-appsec-gateway/sw.js that stamps X-SW-Active: 1 on intercepted requests. Absence after expected registration = headless-browser signal."),
    ]
    # 1.8.10 — enrich the Risk-breakdown "control" column:
    #   knob_state  : current enabled state of every controlling knob (on/off dot)
    #   signal_meta : per-reason {weight, tier, desc} covering scored AND
    #                 synthetic reasons (for the severity badge + tooltip)
    _g = globals()
    # Controls that live on the Settings page (not the Controls page) — used to
    # route the Risk-breakdown "control" deep-link to the right page.
    _SETTINGS_KNOBS = {"ADMIN_ALLOWED_IPS", "ALLOW_PRIVATE_UPSTREAM", "STRICT_VHOST",
                       "UPSTREAM_REWRITE_BASE", "TRUST_XFF", "TRUSTED_PROXIES"}
    knob_state = {}   # {knob: {on, kind, display}}  — kind drives dot-vs-value UI
    knob_page  = {}   # {knob: "controls"|"settings"} — deep-link target page
    for _kn in {v for v in SIGNAL_KNOB.values() if v}:
        _v = _g.get(_kn)
        if isinstance(_v, bool):
            _info = {"on": _v, "kind": "bool", "display": "on" if _v else "off"}
        elif isinstance(_v, (int, float)):
            _info = {"on": bool(_v), "kind": "num", "display": str(_v)}
        elif isinstance(_v, (list, tuple, set, frozenset)):
            _n = len(_v)
            _info = {"on": _n > 0, "kind": "list",
                     "display": "none" if _n == 0 else f"{_n} set"}
        elif isinstance(_v, str):
            _info = {"on": bool(_v), "kind": "str", "display": (_v[:32] if _v else "—")}
        else:
            _info = {"on": bool(_v), "kind": "other", "display": "on" if _v else "off"}
        knob_state[_kn] = _info
        knob_page[_kn] = "settings" if _kn in _SETTINGS_KNOBS else "controls"
    signal_meta = {}
    for _rsn, _kn in SIGNAL_KNOB.items():
        _tier, _desc = DESCRIPTIONS.get(_rsn, ("", ""))
        signal_meta[_rsn] = {
            "weight": RISK_WEIGHTS.get(_rsn, 0),
            "tier":   _tier,
            "desc":   _desc,
        }
    return web.json_response({
        "weights":   weights,
        # Full reason→knob map (incl. synthetic reasons not in RISK_WEIGHTS) so
        # the Risk-breakdown "control" column can resolve every reason. null = a
        # mandatory/always-on gate with no toggle.
        "signal_knob":  dict(SIGNAL_KNOB),
        "knob_state":   knob_state,    # {knob: {on, kind, display}} live state
        "knob_page":    knob_page,     # {knob: "controls"|"settings"} link target
        "signal_meta":  signal_meta,   # {reason: {weight, tier, desc}}
        "modifiers": [{"toggle": k, "description": d} for k, d in modifiers],
        "thresholds": {
            "RISK_BAN_THRESHOLD":      RISK_BAN_THRESHOLD,
            "RISK_BAN_THRESHOLD_NAT":  RISK_BAN_THRESHOLD_NAT,
            "NAT_IDENTITIES_THRESHOLD": NAT_IDENTITIES_THRESHOLD,
            "RISK_BAN_DURATION_SECS":  RISK_BAN_DURATION_SECS,
            "RISK_DECAY_HALFLIFE_SECS": RISK_DECAY_HALFLIFE_SECS,
            "SOFT_CHALLENGE_SCORE":    SOFT_CHALLENGE_SCORE,
        },
    }, headers={"Cache-Control": "no-store"})

async def maxmind_fetch_endpoint(request: web.Request):
    """1.5.5 — operator-triggered MaxMind DB load. POST /__maxmind-fetch:
    (1) copies the image-bundled mmdbs into /data if missing (no internet
    needed); (2) if MAXMIND_LICENSE_KEY is set, also runs a fresh fetch
    from MaxMind. Used by the GeoMap "Refresh DB" button so operators
    never have to drop into a shell."""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    global _asn_reader, _city_reader, MAXMIND_ENABLED, MAXMIND_CITY_ENABLED
    try:
        # Step 1 — seed from image always works offline.
        _maxmind_seed_from_image()
        # Step 2 — license-keyed fetch only if env var present.
        if os.environ.get("MAXMIND_LICENSE_KEY", "").strip():
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _maxmind_auto_fetch)
        # Re-open readers in place.
        try:
            import maxminddb
            if os.path.exists(MAXMIND_ASN_DB_PATH):
                _asn_reader = maxminddb.open_database(MAXMIND_ASN_DB_PATH)
                MAXMIND_ENABLED = True
            if os.path.exists(MAXMIND_CITY_DB_PATH):
                _city_reader = maxminddb.open_database(MAXMIND_CITY_DB_PATH)
                MAXMIND_CITY_ENABLED = True
        except Exception as e:
            return web.json_response(
                {"ok": False, "error": f"reader reload failed: {e}"},
                status=500, headers={"Cache-Control": "no-store"})
        return web.json_response({
            "ok": True,
            "asn_loaded":  MAXMIND_ENABLED,
            "city_loaded": MAXMIND_CITY_ENABLED,
            "asn_path":    MAXMIND_ASN_DB_PATH if MAXMIND_ENABLED else None,
            "city_path":   MAXMIND_CITY_DB_PATH if MAXMIND_CITY_ENABLED else None,
        }, headers={"Cache-Control": "no-store"})
    except Exception as e:
        return web.json_response(
            {"ok": False, "error": str(e)[:200]},
            status=500, headers={"Cache-Control": "no-store"})


# 1.6.5 — per-detector latency observability. Every entry in deny() hot path
# bumps the corresponding counter + records a wall-time sample. The /__detector-stats
# endpoint exposes this for the Service / Agents / Dashboard surfaces. Bounded
# at 200 samples per reason (rolling window) so memory stays trivial.
_detector_latency: dict = {}   # reason → deque(ms samples, maxlen=200)
_detector_hits:    dict = {}   # reason → int

def _detector_record(reason: str, elapsed_ms: float) -> None:
    """1.6.5 — internal: add a per-reason latency sample. Called from every
    detector's deny() / silent-decoy emission. Never raises."""
    try:
        _detector_hits[reason] = _detector_hits.get(reason, 0) + 1
        dq = _detector_latency.get(reason)
        if dq is None:
            from collections import deque as _dq
            _detector_latency[reason] = _dq(maxlen=200)
            dq = _detector_latency[reason]
        dq.append(float(elapsed_ms))
    except Exception:
        pass

# 1.6.5 — challenge-cookie mint counters. Lets the Controls dashboard show
# the chal-cookie success rate (mints / chal-required hits).
_chal_mint_count = 0
_chal_required_count = 0


# 1.6.4 — categorise each block reason into a "method bucket" so the GeoMap
# can show WHICH detection layer is firing per region. Anti-bot focus per the
# user roadmap: UA filter / body group / external intel / behavioural /
# cookie gate / TLS fingerprint / canary / operator-defined / other.
_REASON_METHOD = {
    # UA filter family
    "ua-empty": "ua", "ua-blocked": "ua", "ua-too-short": "ua",
    "ua-non-browser": "ua", "ua-platform-mismatch": "ua",
    "ua-ai-openai": "ua", "ua-ai-anthropic": "ua", "ua-ai-google": "ua",
    "ua-ai-perplexity": "ua", "ua-ai-meta": "ua", "ua-ai-other": "ua",
    # Body / payload signature groups
    "body-sqli": "body", "body-xss": "body", "body-lfi": "body",
    "body-rce": "body", "body-ssrf": "body", "body-cmd": "body",
    "suspicious-body": "body",
    # External intel layer
    "abuseipdb-high": "intel", "abuseipdb-med": "intel",
    "crowdsec-banned": "intel", "country-blocked": "intel",
    "tor-exit": "intel", "datacenter-vpn": "intel", "asn-hosting": "intel",
    # Behavioural / fingerprint
    "behavior": "behavior", "ai-enumeration": "behavior",
    "ai-no-assets": "behavior", "ai-headers-empty": "behavior",
    "ai-headers-incomplete": "behavior",
    "session-flood": "behavior", "session-churn": "behavior",
    "upstream-404": "behavior",
    # 1.6.5 — slowloris signal (slow body upload) lives in the behavioral bucket
    "slow-client": "behavior",
    # 1.6.5 — FingerprintJS BotD client-side detection
    "botd-detected": "behavior",
    # Cookie / challenge gate
    "chal-required": "cookie", "js-challenge": "cookie",
    # TLS fingerprint
    "tls-fingerprint": "tls", "ja4-required-missing": "tls",
    # Canary echo (R7) — distinct family
    "canary-echo": "canary",
    # Operator-defined / structural rules
    "custom-rule-block": "operator", "host-not-allowed": "operator",
    "suspicious-path": "operator", "ai-probe": "operator",
    "auth-jwt-invalid": "operator", "rate-limit-endpoint": "operator",
    "honeypot": "honeypot", "honeypot-silent": "honeypot",
    "bot-trap": "honeypot",
}
def _reason_method(reason: str) -> str:
    """Return the method bucket for a reason or 'other' for unknowns."""
    return _REASON_METHOD.get(reason, "other")


async def geo_data_endpoint(request: web.Request):
    """1.5.4 — geo aggregation for the world-map dashboard.
    Returns counts per (lat,lng) split into kind=clean/missed/blocked.
    Time-window controls mirror /__metrics.

    Source: events table (SQLite). Each event row is bucketed by IP →
    (lat,lng) via the GeoLite2-City mmdb. Cached in-process for 60s to
    avoid hammering both SQLite + the mmdb on every dashboard tick.
    """
    if not MAXMIND_CITY_ENABLED:
        return web.json_response(
            {"points": [], "configured": False,
             "hint": "drop GeoLite2-City.mmdb into /data and restart, "
                     "or set MAXMIND_CITY_DB_PATH"},
            headers={"Cache-Control": "no-store"})
    try:
        range_min = max(5, min(43200, int(request.query.get("range", "60"))))
    except ValueError:
        range_min = 60
    try:
        end_epoch = int(request.query.get("end", str(int(_t.time()))))
    except ValueError:
        end_epoch = int(_t.time())
    start_epoch = end_epoch - range_min * 60

    _geo_vhost = request.query.get("vhost", "").strip().lower()
    # In-process cache key: bucket the params on a 60s grain so live mode
    # doesn't run a fresh SQL query per dashboard tick.
    cache_key = (range_min, end_epoch // 60, _geo_vhost)
    cached = _GEO_CACHE.get(cache_key)
    if cached and cached[0] > _t.time():
        return web.json_response(
            cached[1], headers={"Cache-Control": "no-store"})

    # Pull events. We need: ts, ip, reason. Allowed = reason='' or 'OK'.
    # Risk-bin classification (clean / missed / blocked) is done from the
    # current per-identity risk_score for that IP — best-effort.
    # 1.6.3 — also fetch ts so the front-end scrubber can replay frames.
    points = {}  # {(lat_round, lng_round): {"country","city","clean","missed","blocked","tor_hits","dc_hits"}}
    countries = {}  # {iso: {"clean","missed","blocked"}}
    events_sample = []  # for the time scrubber (capped)
    # Resolve each unique IP only once. 1.6.3 — also flag Tor exits and
    # hosting ASNs so the dashboard can render them with distinct markers.
    # 1.6.4 — also resolve ASN org so we can rank top providers globally.
    ip_geo = {}
    ip_flags = {}   # ip → {"tor": bool, "dc": bool, "asn_org": str}
    asn_totals = {}  # asn_org → {clean, blocked}
    skipped_no_geo = 0  # events dropped because IP has no geoip record (private/unresolvable)
    _sample_seen = 0   # geo-resolved row count — denominator for reservoir sampling
    _SCRUBBER_CAP = 5000
    N_ANIM = 24
    _anim_step = max(1.0, (end_epoch - start_epoch) / N_ANIM)
    anim_buckets = [
        {"ts": start_epoch + (i + 1) * _anim_step, "points": {}}
        for i in range(N_ANIM)
    ]
    try:
        # 1.8.8 — backend-aware read.  Was: sqlite3.connect(DB_PATH) hardcoded,
        # which left GeoMap showing stale SQLite data on Postgres-active
        # deployments where SQLite dual-write had silently lagged or stopped.
        # Now dispatches to whichever backend is live.  vhost filter is
        # skipped on Postgres (schema gap — see db/postgres.py docstring).
        from db import db_read_events
        try:
            cursor = db_read_events(
                start_epoch, end_epoch,
                columns=["ts", "ip", "reason"],
                vhost=_geo_vhost,
            )
        except Exception:
            cursor = []
        try:
            for r in cursor:
                ip = r["ip"]
                if not ip:
                    continue
                if ip not in ip_geo:
                    ip_geo[ip] = _city_lookup(ip)
                    tor_hit = ip in _tor_exits
                    dc_hit = False
                    asn_org = ""
                    if MAXMIND_ENABLED:
                        _asn, _org, _is_hosting, _ = _asn_lookup(ip)
                        dc_hit = bool(_is_hosting)
                        asn_org = (_org or "")[:80]
                    ip_flags[ip] = {"tor": tor_hit, "dc": dc_hit, "asn_org": asn_org}
                loc = ip_geo[ip]
                if loc is None:
                    skipped_no_geo += 1
                    continue
                lat, lng, country, city = loc
                # Round to 0.5° to merge nearby cities into a single bubble
                key = (round(lat * 2) / 2, round(lng * 2) / 2)
                if key not in points:
                    # 1.6.4 — `methods` counts blocks per detection-method bucket
                    # at this cell. Operators see WHICH layer is doing the work.
                    points[key] = {"country": country, "city": city,
                                   "clean": 0, "missed": 0, "blocked": 0,
                                   "authorized_robot": 0,
                                   "tor_hits": 0, "dc_hits": 0,
                                   "methods": {}}
                reason = (r["reason"] or "")
                if reason == "authorized-robot":
                    kind = "authorized_robot"
                elif reason and reason != "OK":
                    kind = "blocked"
                else:
                    kind = "clean"
                points[key][kind] += 1
                # Server-side animation bucket — exact count, no sampling loss.
                _bidx = min(N_ANIM - 1, max(0, int((float(r["ts"]) - start_epoch) / _anim_step)))
                _bkey = f"{key[0]},{key[1]}"
                _bp = anim_buckets[_bidx]["points"]
                if _bkey not in _bp:
                    _bp[_bkey] = {"c": 0, "m": 0, "b": 0, "ar": 0}
                _bp[_bkey]["c" if kind == "clean" else "ar" if kind == "authorized_robot" else "b"] += 1
                # 1.6.4 — bucket the block reason by method
                if kind == "blocked":
                    method = _reason_method(reason)
                    points[key]["methods"][method] = points[key]["methods"].get(method, 0) + 1
                # Country aggregation (also methods + asn_org per country)
                if country:
                    if country not in countries:
                        countries[country] = {"clean": 0, "missed": 0, "blocked": 0,
                                               "authorized_robot": 0, "methods": {}}
                    countries[country][kind] += 1
                    if kind == "blocked":
                        method = _reason_method(reason)
                        countries[country]["methods"][method] = (
                            countries[country]["methods"].get(method, 0) + 1)
                # Tor / DC counts at this point
                flags = ip_flags.get(ip) or {}
                if flags.get("tor"):
                    points[key]["tor_hits"] += 1
                if flags.get("dc"):
                    points[key]["dc_hits"] += 1
                # 1.6.4 — global ASN totals (top providers per range)
                org = (flags.get("asn_org") or "").strip()
                if org:
                    asn_totals.setdefault(org, {"clean": 0, "blocked": 0, "authorized_robot": 0})
                    asn_totals[org][kind] = asn_totals[org].get(kind, 0) + 1
                # Reservoir sampling (Algorithm R) — uniform sample across the full
                # window so the scrubber replay represents all 30 days, not just the
                # first 5 000 events (which would all fall in the oldest time slice).
                _sample_seen += 1
                if _sample_seen <= _SCRUBBER_CAP:
                    events_sample.append([float(r["ts"]), lat, lng, kind])
                else:
                    j = _random.randint(0, _sample_seen - 1)  # noqa: S311 — reservoir sampling, not crypto
                    if j < _SCRUBBER_CAP:
                        events_sample[j] = [float(r["ts"]), lat, lng, kind]
        except Exception:
            pass  # nosec B110 — per-row failures swallowed; aggregation continues
    except Exception as e:
        return web.json_response(
            {"error": f"db: {e}", "points": []}, status=500,
            headers={"Cache-Control": "no-store"})

    # We don't have per-event "missed" classification in the events table.
    # Approximate "missed" via current per-identity risk band: any client
    # whose risk_score is in the medium band contributes to missed at its
    # current location.
    async with state_lock:
        for key_id, s in ip_state.items():
            ip = s.last_ip or key_id
            if ip not in ip_geo:
                ip_geo[ip] = _city_lookup(ip)
            loc = ip_geo.get(ip)
            if not loc:
                continue
            if not (SOFT_CHALLENGE_SCORE > 0 and
                    SOFT_CHALLENGE_SCORE <= s.risk_score < RISK_BAN_THRESHOLD):
                continue
            lat, lng, country, city = loc
            key = (round(lat * 2) / 2, round(lng * 2) / 2)
            if key not in points:
                points[key] = {"country": country, "city": city,
                               "clean": 0, "missed": 0, "blocked": 0,
                               "authorized_robot": 0,
                               "tor_hits": 0, "dc_hits": 0, "methods": {}}
            points[key]["missed"] += s.allowed_count

    # 1.6.4 — classify each cell into a "pin type" so the front-end can
    # filter by behaviour family:
    #   bot-ai          — UA / canary / behaviour blocks dominate
    #   high-risk       — external intel (AbuseIPDB / CrowdSec / Tor / DC) dominates
    #   fp-suspect      — high block ratio AND most blocks are "soft" (cookie / behaviour)
    #   normal          — clean traffic dominates (default)
    def _classify(p):
        m = p.get("methods") or {}
        total = sum(m.values())
        if not total:
            return "normal"
        ai_share   = (m.get("ua", 0) + m.get("canary", 0) + m.get("behavior", 0)) / total
        intel_sh   = m.get("intel", 0) / total
        soft_sh    = (m.get("cookie", 0) + m.get("behavior", 0)) / total
        block_rat  = p["blocked"] / max(1, p["blocked"] + p["clean"])
        if intel_sh >= 0.5:
            return "high-risk"
        if ai_share >= 0.5:
            return "bot-ai"
        if block_rat >= 0.7 and soft_sh >= 0.6:
            return "fp-suspect"
        return "normal"

    # Project to a flat list
    out_points = [
        {"lat": lat, "lng": lng,
         "country": p["country"], "city": p["city"],
         "clean": p["clean"], "missed": p["missed"], "blocked": p["blocked"],
         "authorized_robot": p.get("authorized_robot", 0),
         "tor_hits": p["tor_hits"], "dc_hits": p["dc_hits"],
         "methods":  p.get("methods") or {},                # 1.6.4
         "pin_type": _classify(p),                          # 1.6.4
         "total": p["clean"] + p["missed"] + p["blocked"] + p.get("authorized_robot", 0)}
        for (lat, lng), p in points.items()
    ]
    out_points.sort(key=lambda d: d["total"], reverse=True)
    out_points = out_points[:1000]  # cap payload

    # 1.6.3 — country leaderboard (top 30)
    # 1.6.4 — also include methods + block_effectiveness per country
    out_countries = []
    for cc, counts in countries.items():
        clean   = counts["clean"]
        missed  = counts["missed"]
        blocked = counts["blocked"]
        seen    = clean + missed + blocked
        # block-effectiveness = blocked / (blocked + missed) — i.e., when
        # we suspected something, did we actually stop it? When missed=0,
        # effectiveness = 100% if there were any blocks (perfect), else N/A.
        susp = blocked + missed
        eff  = (blocked / susp * 100.0) if susp > 0 else None
        out_countries.append({
            "country":   cc,
            "clean":     clean,
            "missed":    missed,
            "blocked":   blocked,
            "total":     seen,
            "methods":   counts.get("methods") or {},      # 1.6.4
            "effectiveness_pct": eff,                       # 1.6.4
            # 1.6.5 — bypass-rate proxy: missed / (blocked + missed) — i.e.,
            # of suspicious traffic, what fraction got through (fell into the
            # soft-challenge "missed" band rather than triggering a ban).
            "bypass_pct": ((missed / susp * 100.0) if susp > 0 else None),
        })
    out_countries.sort(key=lambda d: d["total"], reverse=True)
    out_countries = out_countries[:30]

    # 1.6.4 — top ASN providers (by block + total) globally
    out_asns = sorted(
        ({"asn_org": org,
          "blocked": v["blocked"], "clean": v["clean"],
          "total":   v["blocked"] + v["clean"]}
         for org, v in asn_totals.items()),
        key=lambda d: d["blocked"], reverse=True)[:20]

    # 1.6.3 — read-only snapshot of geo-block list state for the UI
    geo_state = {
        "country_block_enabled": bool(globals().get("COUNTRY_BLOCK_ENABLED")),
        "country_denylist":  sorted(globals().get("COUNTRY_DENYLIST")  or []),
        "country_allowlist": sorted(globals().get("COUNTRY_ALLOWLIST") or []),
    }

    # 1.6.4 — global method totals across all blocks
    method_totals = {}
    for p in out_points:
        for k, v in (p.get("methods") or {}).items():
            method_totals[k] = method_totals.get(k, 0) + v

    payload = {
        "configured": True,
        "points":     out_points,
        "countries":  out_countries,                     # 1.6.3 + 1.6.4 (methods, eff)
        "asns":       out_asns,                          # 1.6.4 — top ASN providers
        "anim_buckets": anim_buckets,                    # exact server-side animation buckets
        "events":     events_sample,                     # legacy reservoir sample (fallback)
        "geo_state":  geo_state,                         # 1.6.3
        "summary": {
            "total_points":  len(out_points),
            "total_events":  sum(p["total"] for p in out_points),
            "total_blocked": sum(p["blocked"] for p in out_points),
            "total_missed":  sum(p["missed"]  for p in out_points),
            "total_clean":   sum(p["clean"]   for p in out_points),
            "total_tor":     sum(p["tor_hits"] for p in out_points),
            "total_dc":      sum(p["dc_hits"] for p in out_points),
            "method_totals":   method_totals,              # 1.6.4
            "skipped_no_geo":  skipped_no_geo,             # events with no geoip (private/unresolvable IPs)
            "range_min":       range_min,
            "end_epoch":       end_epoch,
            "start_epoch":     start_epoch,
        },
    }
    _GEO_CACHE[cache_key] = (_t.time() + 60, payload)
    if len(_GEO_CACHE) > 64:
        # evict entries with the earliest expiry (oldest inserted)
        for k in sorted(_GEO_CACHE.keys(), key=lambda k: _GEO_CACHE[k][0])[:16]:
            _GEO_CACHE.pop(k, None)
    return web.json_response(payload, headers={"Cache-Control": "no-store"})


_GEO_CACHE: dict = {}


async def geo_drill_endpoint(request: web.Request):
    """1.6.3 — click-circle drill-down. Given a (lat, lng) cell and the
    same time window as the geo-data view, return:
      • top 25 IPs at that cell (with country, city, asn_org, tor/dc flags, hits)
      • top 10 block reasons (count desc)
      • top 10 paths (count desc)
    The cell granularity matches geo_data_endpoint (0.5° rounding)."""
    if not MAXMIND_CITY_ENABLED:
        return web.json_response(
            {"error": "MaxMind City DB not loaded"}, status=503,
            headers={"Cache-Control": "no-store"})
    try:
        lat = float(request.query.get("lat", "nan"))
        lng = float(request.query.get("lng", "nan"))
        range_min = max(5, min(43200, int(request.query.get("range", "60"))))
        end_epoch = int(request.query.get("end", str(int(_t.time()))))
    except (ValueError, TypeError):
        return web.json_response(
            {"error": "bad lat/lng/range"}, status=400,
            headers={"Cache-Control": "no-store"})
    if lat != lat or lng != lng:    # NaN check
        return web.json_response({"error": "lat/lng required"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    start_epoch = end_epoch - range_min * 60
    target_key = (round(lat * 2) / 2, round(lng * 2) / 2)

    try:
        # 1.8.8 — backend-aware read (was sqlite3.connect(DB_PATH) hardcoded)
        from db import db_read_events_async
        rows = await db_read_events_async(   # #3: off the event loop
            start_epoch, end_epoch,
            columns=["ip", "ua", "path", "reason", "ts"],
            limit=200000,
        )
    except Exception as e:
        return web.json_response(
            {"error": f"db: {e}"}, status=500,
            headers={"Cache-Control": "no-store"})

    ip_map = {}              # ip → {country, city, asn_org, tor, dc, hits, last_seen, last_reason}
    reasons: dict = defaultdict(int)
    paths:   dict = defaultdict(int)
    ip_geo_cache: dict = {}
    asn_cache: dict = {}
    for r in rows:
        ip = r["ip"]
        if not ip:
            continue
        if ip not in ip_geo_cache:
            ip_geo_cache[ip] = _city_lookup(ip)
        loc = ip_geo_cache[ip]
        if not loc:
            continue
        ilat, ilng, country, city = loc
        key = (round(ilat * 2) / 2, round(ilng * 2) / 2)
        if key != target_key:
            continue
        # In-cell event — accumulate.
        reason = (r["reason"] or "OK")
        reasons[reason] += 1
        path = r["path"] or "/"
        paths[path] += 1
        if ip not in ip_map:
            asn_org = ""
            is_hosting = False
            if MAXMIND_ENABLED:
                if ip not in asn_cache:
                    _, _org, _h, _ = _asn_lookup(ip)
                    asn_cache[ip] = (_org, _h)
                asn_org, is_hosting = asn_cache[ip]
            ip_map[ip] = {
                "ip": ip, "country": country, "city": city,
                "asn_org": asn_org,
                "tor": (ip in _tor_exits),
                "dc":  is_hosting,
                "is_admin_ip": _is_admin_ip(ip),
                "hits": 0, "blocked": 0,
                "last_seen": 0.0, "last_reason": "",
            }
        rec = ip_map[ip]
        rec["hits"] += 1
        if reason and reason != "OK":
            rec["blocked"] += 1
        rec["last_seen"] = float(r["ts"])
        rec["last_reason"] = reason

    top_ips = sorted(ip_map.values(), key=lambda d: d["hits"],
                      reverse=True)[:25]
    top_reasons = sorted(reasons.items(), key=lambda kv: -kv[1])[:10]
    top_paths   = sorted(paths.items(),   key=lambda kv: -kv[1])[:10]

    return web.json_response({
        "lat": target_key[0], "lng": target_key[1],
        "range_min": range_min, "end_epoch": end_epoch,
        "ip_count":   len(ip_map),
        "event_count": sum(reasons.values()),
        "top_ips":    top_ips,
        "top_reasons":[{"reason": r, "count": c} for r, c in top_reasons],
        "top_paths":  [{"path":   p, "count": c} for p, c in top_paths],
    }, headers={"Cache-Control": "no-store"})


async def geo_dashboard_endpoint(request: web.Request):
    """HTML dashboard rendering the world-map geo view."""
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    body = GEO_DASHBOARD_HTML.replace('<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1)
    return web.Response(
        text=body, content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com 'unsafe-inline'; "
                "style-src 'self' https://unpkg.com 'unsafe-inline'; "
                "img-src 'self' data: https://*.basemaps.cartocdn.com; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'"
            ),
        },
    )


# ── 1.6.3: Logs dashboard endpoints ──────────────────────────────────────
async def logs_data_endpoint(request: web.Request):
    """Live log feed for the Logs dashboard.

    Query:
      kind=requests | gw                (default: requests)
      level=debug|info|warn|error|critical  (filter; default: debug = all)
      limit=N                            (default: 200, max: 2000)
      q=<substring>                      (optional case-insensitive search)

    `requests` reads the SQLite `events` table (full history, paginated).
    `gw` reads the in-memory `_GW_LOG_RING` (last 2000 non-request events).
    """
    kind  = (request.query.get("kind", "requests") or "requests").lower()
    if kind not in ("requests", "gw"):
        return web.json_response({"error": "kind must be requests|gw"},
                                  status=400, headers={"Cache-Control":"no-store"})
    level = (request.query.get("level", "debug") or "debug").lower()
    if level not in _LOG_LEVELS:
        level = "debug"
    level_n = _LOG_LEVELS[level]
    try:
        limit = max(1, min(2000, int(request.query.get("limit", "200"))))
    except ValueError:
        limit = 200
    q = (request.query.get("q", "") or "").strip().lower()

    if kind == "requests":
        # 1.6.5 — extra filters
        method_filter = (request.query.get("method", "all") or "all").lower()
        iptype_filter = (request.query.get("ip_type", "all") or "all").lower()
        vhost_filter  = (request.query.get("vhost", "") or "").strip().lower()
        try:
            # 1.8.8 — backend-aware read (was sqlite3.connect(DB_PATH) hardcoded)
            from db import db_read_events
            # 1.6.5 — pull more rows than `limit` so we can post-filter
            # (method/ip_type) without paginating multiple SQL queries.
            sql_cap = max(limit * 4, 1000) if (method_filter != "all" or
                                                 iptype_filter != "all") else limit
            rows = await db_read_events_async(   # #3: off the event loop
                0, 0,  # no time bound — latest N rows
                columns=["id", "ts", "ip", "ua", "path", "status", "reason"],
                vhost=vhost_filter,
                order_by="id desc",
                limit=sql_cap,
            )
        except Exception as e:
            return web.json_response({"error": f"db: {e}"}, status=500,
                                      headers={"Cache-Control":"no-store"})
        out = []
        for r in rows:
            reason = (r["reason"] or "")
            row_level = "warn" if (reason and reason != "OK") else "info"
            if _LOG_LEVELS[row_level] < level_n:
                continue
            # 1.6.5 — method bucket filter (via _reason_method)
            if method_filter != "all" and _reason_method(reason) != method_filter:
                continue
            # 1.6.5 — IP-type filter: tor / dc / residential
            if iptype_filter != "all":
                ip_v = r["ip"] or ""
                is_tor = ip_v in _tor_exits
                is_dc = False
                if MAXMIND_ENABLED:
                    _, _, _is_hosting, _ = _asn_lookup(ip_v)
                    is_dc = bool(_is_hosting)
                if iptype_filter == "tor" and not is_tor: continue
                if iptype_filter == "dc"  and not is_dc:  continue
                if iptype_filter == "residential" and (is_tor or is_dc): continue
            blob = f"{r['ip']} {r['ua']} {r['path']} {r['status']} {reason}".lower()
            if q and q not in blob:
                continue
            out.append({
                "id":          r["id"],
                "ts":          r["ts"],
                "level":       row_level,
                "ip":          r["ip"],
                "is_admin_ip": _is_admin_ip(r["ip"] or ""),
                "ua":          (r["ua"] or "")[:200],
                "path":        r["path"] or "",
                "status":      r["status"],
                "reason":      reason,
                "method":      _reason_method(reason),  # 1.6.5
            })
            if len(out) >= limit:
                break
        return web.json_response(
            {"kind": "requests", "level": level, "limit": limit,
             "count": len(out), "rows": out},
            headers={"Cache-Control":"no-store"})

    # kind == "gw" — in-memory ring buffer.
    out = []
    # Iterate newest-first.
    for entry in list(_GW_LOG_RING)[::-1]:
        if _LOG_LEVELS.get(entry.get("level"), 20) < level_n:
            continue
        if q:
            blob = " ".join(f"{k}={v}" for k, v in entry.items()).lower()
            if q not in blob:
                continue
        out.append(entry)
        if len(out) >= limit:
            break
    return web.json_response(
        {"kind": "gw", "level": level, "limit": limit,
         "count": len(out), "rows": out,
         "ring_size": len(_GW_LOG_RING)},
        headers={"Cache-Control":"no-store"})


async def logs_export_endpoint(request: web.Request):
    """1.6.5 — stream the events table as CSV. Honours the same
    method/ip_type/level/q filters as /__logs-data. Capped at 100 000 rows
    for safety. Used by the Logs dashboard 'Download CSV' button."""
    level = (request.query.get("level", "debug") or "debug").lower()
    if level not in _LOG_LEVELS: level = "debug"
    level_n = _LOG_LEVELS[level]
    method_filter = (request.query.get("method", "all") or "all").lower()
    iptype_filter = (request.query.get("ip_type", "all") or "all").lower()
    q = (request.query.get("q", "") or "").strip().lower()
    try:
        cap = max(1, min(100000, int(request.query.get("limit", "10000"))))
    except ValueError:
        cap = 10000
    resp = web.StreamResponse(status=200, headers={
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": "attachment; filename=appsecgw_events.csv",
        "Cache-Control": "no-store",
    })
    await resp.prepare(request)
    await resp.write(b"id,ts,iso_ts,ip,ua,path,status,reason,method,ip_type\r\n")
    written = 0
    try:
        # 1.8.8 — backend-aware read (was sqlite3.connect(DB_PATH) hardcoded).
        # Note: for very large exports this loses cursor streaming (helper
        # returns a list) — acceptable trade-off for backend correctness.
        from db import db_read_events
        for r in db_read_events(
            0, 0,
            columns=["id", "ts", "ip", "ua", "path", "status", "reason"],
            order_by="id desc",
            limit=cap * 2,
        ):
            reason = (r["reason"] or "")
            row_level = "warn" if (reason and reason != "OK") else "info"
            if _LOG_LEVELS[row_level] < level_n:
                continue
            if method_filter != "all" and _reason_method(reason) != method_filter:
                continue
            ip_v = r["ip"] or ""
            ip_type = "residential"
            if ip_v in _tor_exits:
                ip_type = "tor"
            elif MAXMIND_ENABLED:
                _, _, _is_hosting, _ = _asn_lookup(ip_v)
                if _is_hosting: ip_type = "dc"
            if iptype_filter != "all" and ip_type != iptype_filter:
                continue
            blob = f"{r['ip']} {r['ua']} {r['path']} {r['status']} {reason}".lower()
            if q and q not in blob:
                continue
            iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["ts"]))
            # CSV escape: wrap in double-quotes if needed, double up internal quotes
            def esc(v):
                s = "" if v is None else str(v)
                if any(c in s for c in ',"\r\n'):
                    return '"' + s.replace('"', '""') + '"'
                return s
            line = ",".join([
                esc(r["id"]), esc(round(r["ts"], 3)), iso,
                esc(r["ip"]), esc((r["ua"] or "")[:200]),
                esc(r["path"]), esc(r["status"]),
                esc(reason), esc(_reason_method(reason)), ip_type,
            ]) + "\r\n"
            await resp.write(line.encode("utf-8"))
            written += 1
            if written >= cap:
                break
    except Exception as e:
        await resp.write(f"# error: {e}\r\n".encode("utf-8"))
    await resp.write_eof()
    return resp


async def logs_dashboard_endpoint(request: web.Request):
    """HTML dashboard for the Logs viewer (request log + GW log + level toggle)."""
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    body = LOGS_DASHBOARD_HTML.replace('<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1)
    return web.Response(
        text=body, content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'"
            ),
        },
    )


async def path_hits_endpoint(request: web.Request):
    """1.5.5 — drill-down for the Top-paths table on the main dashboard.
    Returns the IPs / identities that hit a given path, grouped, with
    their per-path hit count, last-seen, and recorded reason (if any).
    Reads from the `events` SQLite table (full history) so even pruned
    in-memory identities still show up.

    Query:
      ?path=<exact path>     (required)
      ?range=<minutes>       (default 1440 = 24h)
      ?limit=<n>             (default 100, max 1000)
    """
    p = request.query.get("path", "").strip()
    if not p or len(p) > 512:
        return web.json_response({"error": "missing or invalid 'path' param"},
                                  status=400, headers={"Cache-Control":"no-store"})
    try:
        range_min = max(1, min(43200, int(request.query.get("range", "1440"))))
        limit = max(1, min(1000, int(request.query.get("limit", "500"))))
    except ValueError:
        range_min, limit = 1440, 100
    start_epoch = _t.time() - range_min * 60

    def _fetch_path_rows(db_path, path_val, since):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        result = conn.execute(
            "SELECT ip, ua, reason, status, ts FROM events "
            "WHERE path = ? AND ts >= ? ORDER BY ts DESC LIMIT 50000",
            (path_val, since),
        ).fetchall()
        conn.close()
        return result

    rows = []
    try:
        loop = asyncio.get_running_loop()
        rows = await loop.run_in_executor(None, _fetch_path_rows, DB_PATH, p, start_epoch)
    except Exception as e:
        return web.json_response({"error": f"db: {e}"}, status=500,
                                  headers={"Cache-Control":"no-store"})

    # Group by IP
    by_ip = {}
    for r in rows:
        ip = r["ip"] or "?"
        e = by_ip.setdefault(ip, {
            "ip": ip, "ua": r["ua"] or "", "count": 0,
            "is_admin_ip": _is_admin_ip(ip),
            "last_seen_secs_ago": None, "reasons": {}, "statuses": {},
            "first_ts": r["ts"], "last_ts": r["ts"],
        })
        e["count"] += 1
        e["last_ts"] = max(e["last_ts"], r["ts"])
        e["first_ts"] = min(e["first_ts"], r["ts"])
        rsn = r["reason"] or "OK"
        e["reasons"][rsn] = e["reasons"].get(rsn, 0) + 1
        st = str(r["status"] or "?")
        e["statuses"][st] = e["statuses"].get(st, 0) + 1

    # Add per-IP identities from in-memory ip_state (best-effort — multiple
    # identities can share an IP via NAT)
    async with state_lock:
        ip_to_idents = {}
        for k, st in ip_state.items():
            if st.last_ip:
                ip_to_idents.setdefault(st.last_ip, []).append({
                    "id":      k,
                    "ua":      st.last_user_agent,
                    "risk":    round(st.risk_score, 1),
                    "blocked": st.blocked_count,
                    "allowed": st.allowed_count,
                    "banned":  st.banned_until > now(),
                })

    now_epoch = _t.time()
    for ip, e in by_ip.items():
        e["last_seen_secs_ago"] = round(now_epoch - e["last_ts"], 1)
        e["first_seen_secs_ago"] = round(now_epoch - e["first_ts"], 1)
        e["identities"] = ip_to_idents.get(ip, [])
        # Compact statuses + reasons → top-3 for display
        e["top_reason"] = max(e["reasons"].items(), key=lambda kv: kv[1])[0] if e["reasons"] else "OK"
        del e["first_ts"]; del e["last_ts"]

    out = sorted(by_ip.values(), key=lambda d: d["count"], reverse=True)[:limit]
    return web.json_response({
        "path":       p,
        "range_min":  range_min,
        "total_rows": len(rows),
        "ips":        out,
    }, headers={"Cache-Control":"no-store"})


async def agents_bucket_detail_endpoint(request: web.Request):
    """1.5.4 — drill-down for the agents-dashboard timeline.
    Given a bucket epoch + width, return the IPs / identities active during
    that window, classified as detected / missed / clean.
    Query params:
      ?t=<epoch>           bucket left edge (rounded to width)
      ?bucket_secs=<int>   bucket width (60 / 300 / 900 / 3600 / 86400)
      ?kind=detected|missed|clean|all   filter (default 'all')
    """
    try:
        t       = int(request.query.get("t", "0"))
        bucket  = int(request.query.get("bucket_secs", "60"))
    except ValueError:
        return web.json_response({"error":"bad params"}, status=400)
    if bucket not in (60, 300, 900, 3600, 86400):
        bucket = 60
    kind = request.query.get("kind", "all")
    end = t + bucket

    # 1.5.4 — best-effort IP→identity lookup so the drill-down shows the same
    # `id` (HMAC track_key) used everywhere else, not only the IP. Multiple
    # identities may share an IP (NAT) — we attach all of them.
    ip_to_idents: dict = {}
    async with state_lock:
        for k, st in ip_state.items():
            if st.last_ip:
                ip_to_idents.setdefault(st.last_ip, []).append({
                    "id": k, "ua": st.last_user_agent,
                    "session": st.last_session, "fingerprint": st.last_fingerprint,
                    "ja4": st.last_ja4,
                    "risk_score": round(st.risk_score, 1),
                    "allowed": st.allowed_count, "blocked": st.blocked_count,
                })

    # all_blocks=1 → include every non-OK reason (for main dashboard).
    # Default (agents page) → only AGENT_BLOCK_REASONS.
    all_blocks = request.query.get("all_blocks", "0") == "1"
    detected_set, clean_set, auth_robot_set = {}, {}, {}
    try:
        # 1.8.8 — single backend-aware fetch + Python filtering replaces 3 separate
        # SQLite queries (was: sqlite3.connect(DB_PATH) hardcoded × 3 with
        # different WHERE clauses). One bucket window is typically ~60s wide
        # so row count is bounded.
        from db import db_read_events_async
        all_rows = await db_read_events_async(   # #3: off the event loop
            t, end,
            columns=["ip", "ua", "path", "reason", "status"],
            limit=60000,
        )
        agent_block_set = set(AGENT_BLOCK_REASONS)
        for r in all_rows:
            ip = r["ip"] or "?"
            reason = (r["reason"] or "")
            # Classify
            if all_blocks:
                is_block = reason != "" and reason != "OK"
            else:
                is_block = reason in agent_block_set
            is_clean = (reason == "" or reason == "OK")
            is_authorized_robot = (reason == "authorized-robot")
            if is_block:
                entry = detected_set.setdefault(ip, {
                    "ip": ip, "ua": r["ua"] or "", "count": 0,
                    "is_admin_ip": _is_admin_ip(ip),
                    "reasons": {}, "last_path": r["path"] or "",
                    "identities": ip_to_idents.get(ip, []),
                })
                entry["count"] += 1
                entry["reasons"][reason] = entry["reasons"].get(reason, 0) + 1
                entry["last_path"] = r["path"] or entry["last_path"]
            elif is_clean and len(clean_set) < 20000:
                entry = clean_set.setdefault(ip, {
                    "ip": ip, "ua": r["ua"] or "", "count": 0,
                    "is_admin_ip": _is_admin_ip(ip),
                    "last_path": r["path"] or "",
                    "identities": ip_to_idents.get(ip, []),
                })
                entry["count"] += 1
                entry["last_path"] = r["path"] or entry["last_path"]
            if is_authorized_robot and len(auth_robot_set) < 20000:
                entry = auth_robot_set.setdefault(ip, {
                    "ip": ip, "ua": r["ua"] or "", "count": 0,
                    "is_admin_ip": _is_admin_ip(ip),
                    "last_path": r["path"] or "",
                    "identities": ip_to_idents.get(ip, []),
                })
                entry["count"] += 1
                entry["last_path"] = r["path"] or entry["last_path"]
    except Exception as e:
        return web.json_response({"error": f"db: {e}"}, status=500)

    # `missed` IPs = currently have stealth_score >= MIN and were last_seen
    # inside this bucket window. Best-effort using live state.
    missed_list = []
    try:
        min_score = max(0, min(100, int(request.query.get("min_score", "20"))))
    except ValueError:
        min_score = 20
    async with state_lock:
        n_now = now()
        for key, s in ip_state.items():
            if s.allowed_count == 0:
                continue
            score, _comps, _mets = _stealth_score(s)
            if score < min_score:
                continue
            seen_epoch = _t.time() - (n_now - s.last_seen)
            if t <= seen_epoch < end:
                _mip = s.last_ip or key
                _rb = sorted(
                    ((r, round(v, 1)) for r, v in s.risk_by_reason.items() if v >= 0.5),
                    key=lambda x: x[1], reverse=True,
                )
                missed_list.append({
                    "id": key, "ip": _mip,
                    "ua": s.last_user_agent, "stealth_score": score,
                    "risk_score": round(s.risk_score, 1),
                    "risk_breakdown": _rb,
                    "components": _comps,
                    "metrics": _mets,
                    "is_admin_ip": _is_admin_ip(_mip),
                    "allowed": s.allowed_count, "blocked": s.blocked_count,
                    "last_path": s.last_path,
                })

    gwmgmt_set: dict = {}
    try:
        # 1.8.8 — backend-aware read (was sqlite3.connect(DB_PATH) hardcoded)
        from db import db_read_events as _db_read_events_gwm
        for r in _db_read_events_gwm(
            t, end,
            columns=["ip", "ua", "path"],
            path_like="/antibot-appsec-gateway/",
            limit=20000,
        ):
            ip = r["ip"] or "?"
            entry = gwmgmt_set.setdefault(ip, {
                "ip": ip, "ua": r["ua"] or "", "count": 0,
                "is_admin_ip": _is_admin_ip(ip),
                "last_path": r["path"] or "",
                "identities": ip_to_idents.get(ip, []),
            })
            entry["count"] += 1
            entry["last_path"] = r["path"] or entry["last_path"]
    except Exception:
        pass  # nosec B110 — gwmgmt summary is best-effort; missing data acceptable

    payload = {
        "bucket_t":         t,
        "bucket_secs":      bucket,
        "detected":         sorted(detected_set.values(),    key=lambda r: r["count"], reverse=True)[:500],
        "missed":           sorted(missed_list,              key=lambda r: r["stealth_score"], reverse=True)[:500],
        "clean":            sorted(clean_set.values(),       key=lambda r: r["count"], reverse=True)[:500],
        "authorized_robot": sorted(auth_robot_set.values(),  key=lambda r: r["count"], reverse=True)[:500],
        "gwmgmt":           sorted(gwmgmt_set.values(),      key=lambda r: r["count"], reverse=True)[:500],
    }
    if kind in ("detected","missed","clean"):
        payload["only"] = kind
    return web.json_response(payload, headers={"Cache-Control":"no-store"})


async def cost_timeline_endpoint(request: web.Request):
    """1.5.4 — timeline of avg/p99 middleware wall-time (ms) per minute bucket.
    Mirrors the params of /__metrics so the dashboard can drive both with the
    same time-window controls.
    Query params:
      ?range=N    window in minutes (5..43200 = up to 30 d, default 60)
      ?bucket=S   bucket width in seconds (60,300,900,3600 — default 60)
      ?end=EPOCH  right edge (default now)
    1.6.5 — range cap raised from 720 → 43200 minutes (30 d) so the
    Service dashboard can graph long Postgres / DB-size trends.
    """
    try:
        range_min = max(5, min(43200, int(request.query.get("range", "60"))))
    except ValueError:
        range_min = 60
    try:
        bucket_secs = int(request.query.get("bucket", "60"))
        if bucket_secs not in (60, 300, 900, 3600):
            bucket_secs = 60
    except ValueError:
        bucket_secs = 60
    try:
        end_epoch = int(request.query.get("end", str(int(_t.time()))))
    except ValueError:
        end_epoch = int(_t.time())

    end_b = (end_epoch // bucket_secs) * bucket_secs
    bucket_count = min(250, max(2, (range_min * 60) // bucket_secs))
    start_b = end_b - (bucket_count - 1) * bucket_secs

    out = []
    async with state_lock:
        for slot in range(start_b, end_b + 1, bucket_secs):
            agg_sum, agg_count, agg_max = 0.0, 0, 0.0
            for m in range(slot, slot + bucket_secs, 60):
                d = cost_timeline.get(m)
                if d:
                    agg_sum   += d["sum_ms"]
                    agg_count += d["count"]
                    if d["max_ms"] > agg_max:
                        agg_max = d["max_ms"]
            avg_ms = (agg_sum / agg_count) if agg_count else 0.0
            out.append({
                "t": slot,
                "avg_ms": round(avg_ms, 2),
                "max_ms": round(agg_max, 2),
                "count":  agg_count,
            })

    # Headline figures across the whole window
    total_count = sum(b["count"] for b in out)
    total_sum   = sum(b["avg_ms"] * b["count"] for b in out)
    overall_avg = (total_sum / total_count) if total_count else 0.0
    overall_max = max((b["max_ms"] for b in out), default=0.0)

    return web.json_response({
        "timeline":            out,
        "timeline_bucket_secs": bucket_secs,
        "timeline_range_min":   range_min,
        "timeline_end_epoch":   end_b,
        "summary": {
            "overall_avg_ms": round(overall_avg, 2),
            "overall_max_ms": round(overall_max, 2),
            "total_requests": total_count,
        },
    }, headers={"Cache-Control": "no-store"})


