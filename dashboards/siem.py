# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
# dashboards/siem.py — SIEM Security Event Center (1.8.4)
from collections import defaultdict
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR  # noqa: F401 — leading-underscore not in *
from state import *    # noqa: F401,F403
from helpers import slog, now  # noqa: F401
from admin.auth import _internal_authed, _is_admin_ip  # noqa: F401
from aiohttp import web

# ── Severity classification ──────────────────────────────────────────────────
_SEV_CRITICAL = {
    "canary-echo", "honey-cred", "redirect-maze-bot",
    "canary-probe-miss", "honeypot", "honeypot-silent",
}
_SEV_HIGH = {
    "body-rce", "body-ssrf", "body-sqli", "tor-exit",
    "banned", "really-banned", "bot-rule-ban", "bot-rule-really-ban",
    "crowdsec-block", "peer-sync-ban",
}
_SEV_MEDIUM = {
    "body-lfi", "body-xss", "body-cmd",
    "rate-burst", "ua-blocked", "ua-empty", "ua-too-short", "ua-non-browser",
    "ai-probe", "ai-headers-empty", "ai-headers-incomplete",
    "ai-enumeration", "ai-no-assets", "bot-trap", "suspicious-body",
}
_SEV_LOW = {
    "suspicious-path", "rate-limit", "rate-limit-ip", "session-flood",
    "missing-required-header", "origin-mismatch", "host-not-allowed",
    "tls-fingerprint", "behavior", "admin-ip-blocked",
}

_BYPASS_REASONS = {"bypass-mode", "bypass-path", "authorized-robot"}
_OK_REASONS     = {"", "ok"}


def _severity(reason: str) -> str:
    if reason in _SEV_CRITICAL:
        return "critical"
    if reason in _SEV_HIGH:
        return "high"
    if reason in _SEV_MEDIUM:
        return "medium"
    if reason in _SEV_LOW:
        return "low"
    return "info"


# ── Threat category mapping ──────────────────────────────────────────────────
_CAT_MAP: dict[str, str] = {}
for _r in ("body-sqli", "body-xss", "body-lfi", "body-cmd",
           "body-rce", "body-ssrf", "suspicious-body"):
    _CAT_MAP[_r] = "Injection"
for _r in ("honeypot", "honeypot-silent", "honey-cred", "bot-trap"):
    _CAT_MAP[_r] = "Honeypot"
for _r in ("canary-echo", "canary-probe-miss", "redirect-maze-bot"):
    _CAT_MAP[_r] = "Canary"
for _r in ("banned", "really-banned", "banned-silent",
           "bot-rule-ban", "bot-rule-really-ban", "peer-sync-ban"):
    _CAT_MAP[_r] = "Ban"
for _r in ("crowdsec-block", "tor-exit"):
    _CAT_MAP[_r] = "Threat Intel"
for _r in ("ua-blocked", "ua-empty", "ua-too-short", "ua-non-browser",
           "ai-probe", "ai-headers-empty", "ai-headers-incomplete",
           "ai-enumeration", "ai-no-assets"):
    _CAT_MAP[_r] = "Bot/Scraper"
for _r in ("rate-limit", "rate-limit-ip", "rate-burst", "session-flood"):
    _CAT_MAP[_r] = "Rate Abuse"
for _r in ("suspicious-path",):
    _CAT_MAP[_r] = "Recon"
for _r in ("tls-fingerprint", "missing-required-header",
           "origin-mismatch", "behavior"):
    _CAT_MAP[_r] = "Fingerprint"
for _r in ("bypass-mode", "bypass-path", "authorized-robot"):
    _CAT_MAP[_r] = "Bypass"


def _threat_cat(reason: str) -> str:
    return _CAT_MAP.get(reason, "Other")


# ── Endpoint: SIEM JSON data ──────────────────────────────────────────────────
async def siem_data_endpoint(request: web.Request) -> web.Response:
    """GET /antibot-appsec-gateway/secured/siem-data
    Query params:
      ?mins=<int>   time window in minutes (default 60, clamped 1-1440)
      ?vhost=<str>  optional vhost filter (default "")
    """
    try:
        mins = max(1, min(1440, int(request.query.get("mins", "60"))))
    except (ValueError, TypeError):
        mins = 60
    vhost_filter = request.query.get("vhost", "").strip().lower()

    now_ts = now()
    cutoff = now_ts - mins * 60

    # ── Filter events from deque ─────────────────────────────────────────────
    async with state_lock:
        raw_events = list(events)  # snapshot under lock
        ip_snap    = {k: v for k, v in ip_state.items()}  # shallow copy
        tl_snap    = {k: v for k, v in timeline.items()}

    filtered: list[dict] = []
    for ev in raw_events:
        if ev.get("ts", 0) < cutoff:
            continue
        if vhost_filter:
            tk = ev.get("track_key", "") or ""
            parts = tk.split("|")
            ev_vhost = parts[-1].lower() if len(parts) > 1 else ""
            if ev_vhost != vhost_filter:
                continue
        filtered.append(ev)

    total = len(filtered)
    blocked = sum(
        1 for ev in filtered
        if ev.get("reason", "") not in _OK_REASONS
        and ev.get("reason", "") not in _BYPASS_REASONS
    )
    allowed = total - blocked
    bypasses = sum(
        1 for ev in filtered
        if ev.get("reason", "") in _BYPASS_REASONS
    )

    # Count active bans from ip_state snapshot (already taken under lock)
    n_active_bans = sum(
        1 for s in ip_snap.values()
        if getattr(s, "banned_until", 0) > now_ts
    )

    # Reason counts
    reason_counts: dict[str, int] = defaultdict(int)
    for ev in filtered:
        rsn = ev.get("reason", "") or ""
        reason_counts[rsn] += 1

    # Category counts
    cat_counts: dict[str, int] = defaultdict(int)
    for ev in filtered:
        rsn = ev.get("reason", "") or ""
        if rsn and rsn not in _OK_REASONS:
            cat_counts[_threat_cat(rsn)] += 1

    # Severity counts for threat_index
    crit_n = sum(
        1 for ev in filtered
        if ev.get("reason", "") in _SEV_CRITICAL
    )
    high_n = sum(
        1 for ev in filtered
        if ev.get("reason", "") in _SEV_HIGH
    )
    block_pct = (blocked / total * 100) if total > 0 else 0.0
    threat_index = min(100, int(block_pct * 0.5 + crit_n * 5 + high_n * 2))

    # ── Enriched events (last 100, reversed so newest first) ────────────────
    enriched_events: list[dict] = []
    for ev in reversed(filtered):
        if len(enriched_events) >= 100:
            break
        rsn = ev.get("reason", "") or ""
        enriched_events.append({
            "ts":         ev.get("ts", 0),
            "ip":         ev.get("ip", ""),
            "path":       ev.get("path", ""),
            "method":     ev.get("method", ""),
            "status":     ev.get("status", 0),
            "reason":     rsn,
            "score":      ev.get("score", 0),
            "ja4":        ev.get("ja4", ""),
            "rid":        ev.get("rid", ""),
            "ua":         ev.get("ua", ""),
            "sev":        _severity(rsn),
            "admin":      bool(ev.get("is_admin_ip", False)),
            "track_key":  ev.get("track_key", ""),
        })

    # ── Timeline from state.timeline ─────────────────────────────────────────
    tl_out: list[dict] = []
    for ts_b in sorted(tl_snap.keys()):
        if ts_b < cutoff:
            continue
        bucket = tl_snap[ts_b]
        tl_out.append({
            "t":       ts_b,
            "total":   bucket.get("total", 0),
            "blocked": bucket.get("blocked", 0),
            "allowed": bucket.get("allowed", 0),
            "missed":  0,
        })

    # ── Top IPs / identities ─────────────────────────────────────────────────
    # Aggregate ip_state entries; if vhost filter: only include matching entries
    ip_agg: dict[str, dict] = {}
    for key, s in ip_snap.items():
        # Vhost filtering on track_key (ip|vhost format) or last_vhost
        if vhost_filter:
            parts = key.split("|")
            entry_vhost = parts[-1].lower() if len(parts) > 1 else ""
            if not entry_vhost:
                entry_vhost = (getattr(s, "last_vhost", "") or "").lower()
            if entry_vhost != vhost_filter:
                continue

        ip = getattr(s, "last_ip", "") or key
        risk  = getattr(s, "risk_score", 0.0) or 0.0
        reqs  = getattr(s, "request_count", 0) or 0
        blk   = getattr(s, "blocked_count", 0) or 0
        alw   = getattr(s, "allowed_count", 0) or 0
        ban_u = getattr(s, "banned_until", 0) or 0
        ja4   = getattr(s, "last_ja4", "") or ""
        ua    = getattr(s, "last_user_agent", "") or ""
        ls    = getattr(s, "last_seen", 0) or 0

        # Top reason for this identity
        bbr = getattr(s, "blocks_by_reason", {}) or {}
        top_rsn = max(bbr, key=lambda r: bbr[r], default="") if bbr else ""

        if ip not in ip_agg:
            ip_agg[ip] = {
                "ip":         ip,
                "requests":   reqs,
                "blocked":    blk,
                "allowed":    alw,
                "risk_score": risk,
                "country":    "",
                "ja4":        ja4,
                "ua":         ua,
                "banned":     ban_u > now_ts,
                "ban_expires": max(0.0, ban_u - now_ts) if ban_u > now_ts else 0.0,
                "last_seen":  ls,
                "top_reason": top_rsn,
            }
        else:
            agg = ip_agg[ip]
            agg["requests"]  += reqs
            agg["blocked"]   += blk
            agg["allowed"]   += alw
            if risk > agg["risk_score"]:
                agg["risk_score"] = risk
            if ban_u > now_ts:
                agg["banned"]     = True
                agg["ban_expires"] = max(0.0, ban_u - now_ts)
            if ls > agg["last_seen"]:
                agg["last_seen"] = ls
                agg["ja4"]       = ja4
                agg["ua"]        = ua
            if top_rsn and not agg["top_reason"]:
                agg["top_reason"] = top_rsn

    top_ips = sorted(ip_agg.values(), key=lambda r: r["risk_score"], reverse=True)[:25]

    # ── Vhosts list from ip_state keys ──────────────────────────────────────
    vhost_set: set[str] = set()
    for key in ip_snap:
        parts = key.split("|")
        if len(parts) > 1:
            vh = parts[-1].strip().lower()
            if vh:
                vhost_set.add(vh)
        lv = getattr(ip_snap[key], "last_vhost", "") or ""
        if lv.strip():
            vhost_set.add(lv.strip().lower())
    vhosts = sorted(vhost_set)

    # ── by_reason: top 30 excluding ok/empty ─────────────────────────────────
    by_reason = sorted(
        [{"reason": r, "count": c} for r, c in reason_counts.items()
         if r not in _OK_REASONS],
        key=lambda x: x["count"], reverse=True
    )[:30]

    # ── threat_cats: categories with count > 0, sorted desc ──────────────────
    threat_cats = sorted(
        [{"cat": c, "count": n} for c, n in cat_counts.items() if n > 0],
        key=lambda x: x["count"], reverse=True
    )

    body = {
        "ts":           now_ts,
        "threat_index": threat_index,
        "stats": {
            "total":    total,
            "blocked":  blocked,
            "allowed":  allowed,
            "bans":     n_active_bans,
            "bypasses": bypasses,
        },
        "events":      enriched_events,
        "timeline":    tl_out,
        "by_reason":   by_reason,
        "threat_cats": threat_cats,
        "top_ips":     top_ips,
        "vhosts":      vhosts,
        "mins":        mins,
    }
    return web.json_response(
        body,
        headers={
            "Cache-Control":        "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


# ── Pre-load dashboard HTML ───────────────────────────────────────────────────
SIEM_DASHBOARD_HTML = (_DASHBOARDS_DIR / "siem.html").read_text(encoding="utf-8")


async def siem_dashboard_endpoint(request: web.Request) -> web.Response:
    """Serve the SIEM Security Event Center dashboard."""
    return web.Response(
        text=SIEM_DASHBOARD_HTML,
        content_type="text/html",
        headers={
            "Cache-Control":        "no-store",
            "X-Frame-Options":      "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy":      "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'; "
                "object-src 'none'; form-action 'self'"
            ),
        },
    )
