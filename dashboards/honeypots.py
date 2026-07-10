# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
# dashboards/honeypots.py — 1.8.12: Honeypots dashboard backend
# Serves honeypots.html and provides honeypots-data JSON endpoint.
import time as _t
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR  # noqa: F401 — leading-underscore not in *
from state import *    # noqa: F401,F403
from helpers import slog  # noqa: F401
from aiohttp import web
from db import db_read_events, db_read_events_async  # noqa: F401
_PLAYBOOK_REASONS = [
    "honeypot", "honeypot-silent", "bot-trap",
    "honey-cred", "canary-echo", "canary-probe-miss",
]


async def honeypots_data_endpoint(request: web.Request):
    """GET /secured/honeypots-data?mins=1440

    Returns JSON with honeypot/trap catch analytics:
      - total            — total honeypot-reason hits in window
      - unique_ips       — count of distinct IPs caught
      - by_technique     — {reason: count} dict
      - top_ips          — top 10 IPs by hit count
      - hourly           — 24 hourly buckets for the last 24 h
      - active_trap_paths — currently active honeypot paths
      - mins / ts        — query metadata
    """
    try:
        mins = int(request.query.get("mins", "1440"))
    except (TypeError, ValueError):
        mins = 1440
    mins = max(5, min(mins, 43200))   # 5 min … 30 days
    # vhost filter — empty = all vhosts. Stored lowercase; match convention
    # used by the agents/siem dashboards.
    _vhost = request.query.get("vhost", "").strip().lower()

    now = _t.time()
    start = now - mins * 60

    try:
        rows = await db_read_events_async(   # #3: 50k-row scan off the event loop
            start, now,
            columns=["ts", "ip", "method", "path", "reason"],
            reason_in=_PLAYBOOK_REASONS,
            vhost=_vhost,
            order_by="ts DESC",
            limit=50000,
        )
    except Exception as e:
        slog("honeypots_data_err", level="warn", error=str(e)[:120])
        rows = []

    # ── Aggregate totals and by-technique ─────────────────────────────────
    by_technique: dict = {}
    ip_counts: dict = {}
    ip_reasons: dict = {}
    ip_last_ts: dict = {}
    ip_steps: dict = {}          # ip -> recent steps (ts DESC, capped)
    path_counts: dict = {}       # trap path -> hit count
    path_last: dict = {}         # trap path -> most-recent ts
    path_reasons: dict = {}      # trap path -> set(reason)

    for r in rows:
        reason = r.get("reason") or ""
        ip = r.get("ip") or ""
        ts_val = r.get("ts") or 0.0
        path = r.get("path") or ""
        method = (r.get("method") or "").upper() or "GET"

        if reason:
            by_technique[reason] = by_technique.get(reason, 0) + 1

        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            if ip not in ip_reasons:
                ip_reasons[ip] = set()
            ip_reasons[ip].add(reason)
            # rows are ts DESC so first occurrence is most recent
            if ip not in ip_last_ts:
                ip_last_ts[ip] = ts_val
            steps = ip_steps.setdefault(ip, [])
            if len(steps) < 12:     # keep up to 12 most-recent steps per IP
                steps.append({"ts": ts_val, "method": method,
                              "path": path[:200], "reason": reason})

        # trap effectiveness — which trap paths are pulling the most hits
        if path:
            p = path[:200]
            path_counts[p] = path_counts.get(p, 0) + 1
            if p not in path_last:
                path_last[p] = ts_val
            path_reasons.setdefault(p, set()).add(reason)

    total = len(rows)
    unique_ips = len(ip_counts)

    # ── Trap effectiveness — top trap paths by hits ───────────────────────
    trap_effectiveness = [
        {
            "path": p,
            "hits": c,
            "last_ts": path_last.get(p, 0.0),
            "reasons": sorted(path_reasons.get(p, set())),
        }
        for p, c in sorted(path_counts.items(), key=lambda kv: -kv[1])[:20]
    ]

    # ── Attacker storyboard — per-IP request journeys (top by hits) ────────
    attackers = []
    for ip, cnt in sorted(ip_counts.items(), key=lambda kv: -kv[1])[:15]:
        steps_desc = ip_steps.get(ip, [])
        steps_chrono = list(reversed(steps_desc))   # oldest → newest
        attackers.append({
            "ip": ip,
            "count": cnt,
            "first_ts": steps_chrono[0]["ts"] if steps_chrono else 0.0,
            "last_ts": ip_last_ts.get(ip, 0.0),
            "reasons": sorted(ip_reasons.get(ip, set())),
            "steps": steps_chrono,
        })

    # ── Top 10 IPs ────────────────────────────────────────────────────────
    top_ips_sorted = sorted(ip_counts.items(), key=lambda kv: -kv[1])[:10]
    top_ips = [
        {
            "ip": ip,
            "count": cnt,
            "reasons": sorted(ip_reasons.get(ip, set())),
            "last_ts": ip_last_ts.get(ip, 0.0),
        }
        for ip, cnt in top_ips_sorted
    ]

    # ── Time-series buckets (adaptive to the selected window) ─────────────
    # Bucket size scales with the window so the chart stays ~12-30 bars wide,
    # whether the operator picked 1h or 30d.
    window_secs = mins * 60
    if   window_secs <= 2 * 3600:    bucket_secs = 300     # ≤2h  → 5-min
    elif window_secs <= 6 * 3600:    bucket_secs = 900     # ≤6h  → 15-min
    elif window_secs <= 2 * 86400:   bucket_secs = 3600    # ≤2d  → hourly
    elif window_secs <= 10 * 86400:  bucket_secs = 21600   # ≤10d → 6-hourly
    else:                            bucket_secs = 86400    # else → daily
    last_bucket = int(now // bucket_secs) * bucket_secs
    n_buckets = max(1, min(400, int(window_secs // bucket_secs) + 1))
    series_map: dict = {}
    for i in range(n_buckets):
        series_map[last_bucket - (n_buckets - 1 - i) * bucket_secs] = 0
    for r in rows:
        ts_val = r.get("ts") or 0.0
        b = int(ts_val // bucket_secs) * bucket_secs
        if b in series_map:
            series_map[b] += 1
    series = [{"t": k, "count": v} for k, v in sorted(series_map.items())]

    # ── Active trap paths ─────────────────────────────────────────────────
    active_trap_paths: list = []
    try:
        from vhost import vc as _vc
        _paths = _vc("HONEYPOT_PATHS")
        if _paths:
            active_trap_paths = sorted(_paths)
    except Exception:
        try:
            # Fallback: read directly from config
            _paths = HONEYPOT_PATHS  # noqa: F821 — from config import *
            if _paths:
                active_trap_paths = sorted(_paths)
        except Exception:
            pass

    return web.json_response(
        {
            "total": total,
            "unique_ips": unique_ips,
            "by_technique": by_technique,
            "top_ips": top_ips,
            "trap_effectiveness": trap_effectiveness,
            "attackers": attackers,
            "series": series,
            "bucket_secs": bucket_secs,
            "active_trap_paths": active_trap_paths,
            "mins": mins,
            "ts": now,
        },
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


HONEYPOTS_DASHBOARD_HTML = (_DASHBOARDS_DIR / "honeypots.html").read_text(encoding="utf-8")


async def honeypots_dashboard_endpoint(request: web.Request):
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    body = HONEYPOTS_DASHBOARD_HTML.replace(
        '<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1
    )
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
                "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'"
            ),
        },
    )
