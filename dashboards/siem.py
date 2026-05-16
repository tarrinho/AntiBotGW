# dashboards/siem.py — SIEM Security Event Center (1.8.6)
import asyncio
import csv
import io
import json as _json
import sqlite3 as _sqlite3
from collections import defaultdict
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR, DB_PATH  # noqa: F401 — leading-underscore not in *
from state import *    # noqa: F401,F403
from state import _asn_path_clusters  # noqa: F401 — underscore not in *
from helpers import slog, now  # noqa: F401
from admin.auth import _internal_authed, _is_admin_ip, _require_csrf  # noqa: F401
from aiohttp import web

_CSV_FORMULA_CHARS = frozenset("=+-@\t\r")


def _csv_safe(v: object) -> object:
    """FE4-05: prefix formula-triggering strings with a tab to prevent CSV injection."""
    if not isinstance(v, str):
        return v
    if v and v[0] in _CSV_FORMULA_CHARS:
        return "\t" + v
    return v


# ── Alert rule constants ──────────────────────────────────────────────────────
_ALERT_COOLDOWN_S = 300
_VALID_METRICS = frozenset({"block_pct", "blocked", "bans", "threat_index", "crit_count", "high_count"})
_VALID_OPS     = frozenset({">", ">=", "<", "<="})

# ── Server-side rules in-memory cache (avoids DB hit on every 5s poll) ───────
_rules_cache: list = []
_rules_cache_ts: float = 0.0
_RULES_CACHE_TTL = 30.0


def _get_cached_rules() -> list:
    global _rules_cache, _rules_cache_ts
    if now() - _rules_cache_ts > _RULES_CACHE_TTL:
        try:
            conn = _sqlite3.connect(DB_PATH)
            conn.row_factory = _sqlite3.Row
            rows = conn.execute(
                "SELECT id, metric, op, threshold, label, "
                "last_fired_ts, cooldown_s "
                "FROM siem_alert_rules WHERE enabled = 1"
            ).fetchall()
            conn.close()
            _rules_cache = [{k: row[k] for k in row.keys()} for row in rows]
            _rules_cache_ts = now()
        except Exception:
            pass
    return _rules_cache


async def _eval_server_alert_rules(
        stats: dict, threat_index: int, crit_n: int, high_n: int) -> list:
    """Evaluate enabled DB rules; fire webhooks + persist fire records on trigger.
    Returns list of currently-firing rule dicts for the UI."""
    rules = _get_cached_rules()
    if not rules:
        return []

    now_ts = now()
    metric_vals = {
        "block_pct":    (stats["blocked"] / stats["total"] * 100)
                        if stats["total"] > 0 else 0.0,
        "blocked":      float(stats["blocked"]),
        "bans":         float(stats["bans"]),
        "threat_index": float(threat_index),
        "crit_count":   float(crit_n),
        "high_count":   float(high_n),
    }

    firing: list = []
    for rule in rules:
        op  = rule["op"]
        val = metric_vals.get(rule["metric"], 0.0)
        thr = float(rule["threshold"])
        triggered = (
            (op == ">"  and val > thr) or
            (op == ">=" and val >= thr) or
            (op == "<"  and val < thr) or
            (op == "<=" and val <= thr)
        )
        if triggered:
            firing.append({
                "id":        rule["id"],
                "label":     rule["label"],
                "metric":    rule["metric"],
                "op":        op,
                "threshold": thr,
                "value":     round(val, 2),
            })
            last = float(rule.get("last_fired_ts") or 0)
            cooldown = int(rule.get("cooldown_s") or _ALERT_COOLDOWN_S)
            if now_ts - last >= cooldown:
                db_queue.put_nowait(("siem_alert_fired", (rule["id"], now_ts, val)))
                # Reset cache so next poll sees updated last_fired_ts
                global _rules_cache_ts
                _rules_cache_ts = 0.0
                try:
                    from integrations.webhook import _post_webhook  # noqa: PLC0415
                    asyncio.ensure_future(_post_webhook({
                        "event":      "siem_alert",
                        "rule_id":    rule["id"],
                        "rule_label": rule["label"],
                        "metric":     rule["metric"],
                        "op":         op,
                        "threshold":  thr,
                        "value":      val,
                        "ts":         now_ts,
                    }))
                except Exception:
                    pass
    return firing

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

    # ── Server-side alert rules evaluation ───────────────────────────────────
    stats_snap = {
        "total":   total,
        "blocked": blocked,
        "allowed": allowed,
        "bans":    n_active_bans,
        "bypasses": bypasses,
    }
    firing_rules = await _eval_server_alert_rules(stats_snap, threat_index, crit_n, high_n)

    # ── Coordinated attack clusters ──────────────────────────────────────────
    clusters_out: list[dict] = []
    for (asn, prefix, minute), members in list(_asn_path_clusters.items()):
        if len(members) >= 3:
            clusters_out.append({
                "asn":    asn,
                "prefix": prefix,
                "minute": minute,
                "size":   len(members),
            })
    clusters_out.sort(key=lambda x: x["size"], reverse=True)
    clusters_out = clusters_out[:20]

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
        "events":        enriched_events,
        "timeline":      tl_out,
        "by_reason":     by_reason,
        "threat_cats":   threat_cats,
        "top_ips":       top_ips,
        "vhosts":        vhosts,
        "mins":          mins,
        "clusters":      clusters_out,
        "firing_rules":  firing_rules,
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


# ── SSE real-time push ────────────────────────────────────────────────────────
async def siem_stream_endpoint(request: web.Request) -> web.Response:
    """GET /…/siem-stream — SSE push of critical/high events."""
    resp = web.StreamResponse(status=200, headers={
        "Content-Type":      "text/event-stream",
        "Cache-Control":     "no-store",
        "X-Accel-Buffering": "no",
    })
    await resp.prepare(request)
    last_ts = now()
    ticks = 0
    try:
        while True:
            await asyncio.sleep(2)
            ticks += 1
            async with state_lock:
                raw = list(events)
            new_high = [
                ev for ev in raw
                if ev.get("ts", 0) > last_ts
                and _severity(ev.get("reason", "")) in {"critical", "high"}
            ]
            if new_high:
                last_ts = max(ev["ts"] for ev in new_high)
                for ev in sorted(new_high, key=lambda e: e.get("ts", 0)):
                    rsn = ev.get("reason", "") or ""
                    data = _json.dumps({
                        "ts":     ev.get("ts", 0),
                        "ip":     ev.get("ip", ""),
                        "path":   ev.get("path", ""),
                        "reason": rsn,
                        "sev":    _severity(rsn),
                        "score":  ev.get("score", 0),
                    }, default=str)
                    await resp.write(f"event: alert\ndata: {data}\n\n".encode())
            elif ticks % 15 == 0:
                await resp.write(b": heartbeat\n\n")
    except (ConnectionResetError, asyncio.CancelledError):
        pass
    return resp


# ── Server-side alert rules CRUD ──────────────────────────────────────────────
@_require_csrf
async def siem_alert_rules_endpoint(request: web.Request) -> web.Response:
    """GET/POST/DELETE/PATCH /…/siem-alert-rules"""
    global _rules_cache_ts
    method = request.method

    if method == "GET":
        try:
            conn = _sqlite3.connect(DB_PATH)
            conn.row_factory = _sqlite3.Row
            rows = conn.execute(
                "SELECT id, metric, op, threshold, label, enabled, "
                "created_ts, created_by, last_fired_ts, cooldown_s "
                "FROM siem_alert_rules ORDER BY id ASC"
            ).fetchall()
            conn.close()
            rules = [{k: row[k] for k in row.keys()} for row in rows]
            # Also fetch last 50 fire events for history
            conn2 = _sqlite3.connect(DB_PATH)
            conn2.row_factory = _sqlite3.Row
            history = conn2.execute(
                "SELECT f.id, f.rule_id, f.ts, f.value, r.label "
                "FROM siem_alert_fired f "
                "JOIN siem_alert_rules r ON r.id = f.rule_id "
                "ORDER BY f.ts DESC LIMIT 50"
            ).fetchall()
            conn2.close()
            fired = [{k: row[k] for k in row.keys()} for row in history]
            return web.json_response(
                {"rules": rules, "history": fired},
                headers={"Cache-Control": "no-store"},
            )
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    elif method == "POST":
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        metric = str(body.get("metric", "")).strip()
        op     = str(body.get("op", "")).strip()
        try:
            threshold = float(body.get("threshold", 0))
        except (ValueError, TypeError):
            return web.json_response({"error": "invalid threshold"}, status=400)
        label      = str(body.get("label", "")).strip()[:120]
        try:
            cooldown_s = max(0, min(86400, int(body.get("cooldown_s", _ALERT_COOLDOWN_S))))
        except (ValueError, TypeError):
            cooldown_s = _ALERT_COOLDOWN_S
        if metric not in _VALID_METRICS:
            return web.json_response(
                {"error": f"invalid metric; valid: {sorted(_VALID_METRICS)}"}, status=400)
        if op not in _VALID_OPS:
            return web.json_response(
                {"error": f"invalid op; valid: {sorted(_VALID_OPS)}"}, status=400)
        created_by = getattr(request, "username", None)
        db_queue.put_nowait(("siem_alert_rule_add",
                             (metric, op, threshold, label, now(), created_by, cooldown_s)))
        _rules_cache_ts = 0.0
        return web.json_response({"ok": True}, status=201)

    elif method == "DELETE":
        try:
            rule_id = int(request.query.get("id", "0"))
        except (ValueError, TypeError):
            rule_id = 0
        if rule_id <= 0:
            return web.json_response({"error": "missing id"}, status=400)
        db_queue.put_nowait(("siem_alert_rule_del", (rule_id,)))
        _rules_cache_ts = 0.0
        return web.json_response({"ok": True})

    elif method == "PATCH":
        try:
            body = await request.json()
            rule_id = int(body.get("id", 0))
            enabled = int(bool(body.get("enabled", True)))
        except Exception:
            return web.json_response({"error": "invalid payload"}, status=400)
        if rule_id <= 0:
            return web.json_response({"error": "missing id"}, status=400)
        db_queue.put_nowait(("siem_alert_toggle", (enabled, rule_id)))
        _rules_cache_ts = 0.0
        return web.json_response({"ok": True})

    return web.json_response({"error": "method not allowed"}, status=405)


# ── Attacker dossier ──────────────────────────────────────────────────────────
async def siem_dossier_endpoint(request: web.Request) -> web.Response:
    """GET /…/siem-dossier?ip=<ip> — per-IP intelligence dossier."""
    ip = request.query.get("ip", "").strip()
    if not ip:
        return web.json_response({"error": "missing ip"}, status=400)

    now_ts = now()
    async with state_lock:
        ip_snap        = {k: v for k, v in ip_state.items()}
        raw_events_snap = list(events)

    entries = {
        k: v for k, v in ip_snap.items()
        if (getattr(v, "last_ip", k) or k).split("|")[0] == ip
        or k.split("|")[0] == ip
    }

    total_reqs = sum(getattr(s, "request_count", 0) or 0 for s in entries.values())
    total_blk  = sum(getattr(s, "blocked_count",  0) or 0 for s in entries.values())
    total_alw  = sum(getattr(s, "allowed_count",  0) or 0 for s in entries.values())
    risk       = max((getattr(s, "risk_score", 0) or 0 for s in entries.values()), default=0.0)
    banned     = any(getattr(s, "banned_until", 0) > now_ts for s in entries.values())
    ban_exp    = max(
        (max(0.0, getattr(s, "banned_until", 0) - now_ts) for s in entries.values()),
        default=0.0,
    )

    last_ua = last_ja4 = last_path = ""
    for s in entries.values():
        if getattr(s, "last_ja4", ""):        last_ja4  = s.last_ja4
        if getattr(s, "last_user_agent", ""): last_ua   = s.last_user_agent
        if getattr(s, "last_path", ""):       last_path = s.last_path

    all_reasons: dict[str, int] = {}
    for s in entries.values():
        for rsn, cnt in (getattr(s, "blocks_by_reason", {}) or {}).items():
            all_reasons[rsn] = all_reasons.get(rsn, 0) + cnt

    ip_events = [ev for ev in raw_events_snap if ev.get("ip", "") == ip][-50:]

    path_counts: dict[str, int] = {}
    for ev in ip_events:
        p = ev.get("path", "") or ""
        path_counts[p] = path_counts.get(p, 0) + 1
    top_paths = sorted(path_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    ja4_peers: list[str] = []
    if last_ja4:
        for k, s in ip_snap.items():
            peer_ip = (getattr(s, "last_ip", k) or k).split("|")[0]
            if peer_ip != ip and (getattr(s, "last_ja4", "") or "") == last_ja4:
                if peer_ip not in ja4_peers:
                    ja4_peers.append(peer_ip)

    clusters: list[dict] = []
    for key, members in list(_asn_path_clusters.items()):
        if ip in members:
            clusters.append({"asn": key[0], "prefix": key[1],
                             "minute": key[2], "size": len(members)})

    return web.json_response({
        "ip":          ip,
        "requests":    total_reqs,
        "blocked":     total_blk,
        "allowed":     total_alw,
        "risk_score":  risk,
        "banned":      banned,
        "ban_expires": ban_exp,
        "last_ua":     last_ua,
        "last_ja4":    last_ja4,
        "last_path":   last_path,
        "reasons":     sorted(all_reasons.items(), key=lambda x: x[1], reverse=True),
        "recent_events": [
            {
                "ts":     ev.get("ts", 0),
                "path":   ev.get("path", ""),
                "reason": ev.get("reason", ""),
                "sev":    _severity(ev.get("reason", "") or ""),
                "status": ev.get("status", 0),
            }
            for ev in reversed(ip_events)
        ],
        "top_paths":  [{"path": p, "count": c} for p, c in top_paths],
        "ja4_peers":  ja4_peers[:20],
        "clusters":   clusters,
    }, headers={"Cache-Control": "no-store"})


# ── CSV export ────────────────────────────────────────────────────────────────
async def siem_export_endpoint(request: web.Request) -> web.Response:
    """GET /…/siem-export — download filtered events as CSV."""
    try:
        mins = max(1, min(1440, int(request.query.get("mins", "60"))))
    except (ValueError, TypeError):
        mins = 60
    vhost_filter = request.query.get("vhost", "").strip().lower()

    now_ts = now()
    cutoff = now_ts - mins * 60

    async with state_lock:
        raw_events = list(events)

    filtered = []
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

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ts", "ip", "path", "method", "status", "reason", "sev", "score", "ja4", "ua"])
    for ev in sorted(filtered, key=lambda e: e.get("ts", 0), reverse=True):
        rsn = ev.get("reason", "") or ""
        writer.writerow([
            ev.get("ts", ""), _csv_safe(ev.get("ip", "")), _csv_safe(ev.get("path", "")),
            ev.get("method", ""), ev.get("status", ""), _csv_safe(rsn),
            _csv_safe(_severity(rsn)), ev.get("score", ""), _csv_safe(ev.get("ja4", "")),
            _csv_safe(ev.get("ua", "")),
        ])

    return web.Response(
        body=buf.getvalue().encode("utf-8"),
        content_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="siem-events-{int(now_ts)}.csv"',
            "Cache-Control": "no-store",
        },
    )
