# dashboards/agents.py — Phase 8: stealth-agent analytics dashboard
# Extracted from proxy.py lines 10853–11150
import time as _t       # noqa: F401
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR  # noqa: F401 — leading-underscore not in *
from state import *    # noqa: F401,F403
from helpers import slog, now  # noqa: F401
from admin.auth import _internal_authed, _is_admin_ip  # noqa: F401
from aiohttp import web

# ── Stealth-agent (allowed-but-suspicious) analytics ───────────────────────
def _stealth_score(s) -> tuple[int, dict, dict]:
    """Score allowed-traffic identity for stealth-agent likelihood (0-100).
    Returns (total, components_dict, metrics_dict)."""
    if s.allowed_count == 0:
        return 0, {}, {}
    # Header-completeness component (avg over recent allowed; fewer = bot-like).
    if s.header_scores:
        avg_h = sum(s.header_scores) / len(s.header_scores)
    else:
        avg_h = 7.0
    h_pts = max(0, int((7 - avg_h) * 4))                       # 0..28
    # Asset-discipline component: many HTML, no/little static.
    a_pts = 0
    if s.html_loads >= 5:
        ratio = s.static_loads / max(1, s.html_loads)
        a_pts = max(0, int((1 - min(1, ratio * 3)) * 20))      # 0..20
    # Path-enumeration component.
    e_pts = 0
    diversity = 0.0
    if s.allowed_count >= 8 and s.unique_paths:
        diversity = len(s.unique_paths) / max(1, s.allowed_count)
        if diversity > 0.5:
            e_pts = min(15, int(diversity * 18))               # 0..15
    # Behavioral-timing component (sub-block but suspicious).
    b_pts, cov = 0, None
    if len(s.request_times) >= 8:
        recent = list(s.request_times)[-16:]
        intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
        if intervals and all(iv > 0 for iv in intervals):
            mean_iv = sum(intervals) / len(intervals)
            if 0 < mean_iv < 5.0:
                std = (sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)) ** 0.5
                cov = std / mean_iv
                if cov < 0.20:
                    b_pts = min(20, int((0.20 - cov) * 200))    # 0..20
    # Risk-score component (sub-threshold).
    r_pts = min(15, int(s.risk_score / 4))                      # 0..15
    # Upstream 404 component (probing without ban).
    f_pts = min(10, s.upstream_404_count // 2)                  # 0..10

    total = min(100, h_pts + a_pts + e_pts + b_pts + r_pts + f_pts)
    components = {
        "headers": h_pts, "assets": a_pts, "enum": e_pts,
        "timing": b_pts, "risk": r_pts, "404s": f_pts,
    }
    metrics = {
        "avg_header_score": round(avg_h, 2),
        "html_loads": s.html_loads,
        "static_loads": s.static_loads,
        "unique_paths": len(s.unique_paths),
        "path_diversity": round(diversity, 3),
        "behavioral_cov": round(cov, 3) if cov is not None else None,
        "upstream_404_count": s.upstream_404_count,
        "risk_score": round(s.risk_score, 1),
        "samples": len(s.header_scores),
    }
    return total, components, metrics


AGENT_BLOCK_REASONS = (
    "ua-blocked", "ua-empty", "ua-too-short", "ua-non-browser",
    "ai-probe", "ai-headers-empty", "ai-headers-incomplete",
    "ai-enumeration", "ai-no-assets", "behavior",
    "banned", "banned-silent", "honeypot", "honeypot-silent",
    "suspicious-path", "session-flood",
    "rate-limit-ip", "rate-limit", "host-not-allowed",
    "admin-ip-blocked",
    "suspicious-body", "bot-trap", "js-challenge",
    "tls-fingerprint", "origin-mismatch", "missing-required-header",
)


async def agents_timeline_endpoint(request: web.Request):
    """Per-bucket counts of:
      - detected:       requests blocked because they tripped an agent-signal layer
      - missed:         requests ALLOWED but originating from an identity whose
                        current stealth_score >= min_score (likely-AI bot we
                        couldn't catch at request-time)
      - clean_allowed:  remaining allowed traffic (best estimate of humans)
    Query: ?range=<minutes>&bucket=<secs>&min_score=<n>
    """
    try:
        range_min = max(5, min(10080, int(request.query.get("range", "60"))))
    except ValueError:
        range_min = 60
    try:
        bucket_secs = int(request.query.get("bucket", "60"))
        if bucket_secs not in (60, 300, 900, 3600, 86400):
            bucket_secs = 60
    except ValueError:
        bucket_secs = 60
    try:
        min_score = max(0, min(100, int(request.query.get("min_score", "20"))))
    except ValueError:
        min_score = 20

    async with state_lock:
        stealth_ips = set()
        for k, s in ip_state.items():
            if s.allowed_count and _stealth_score(s)[0] >= min_score:
                if s.last_ip:
                    stealth_ips.add(s.last_ip)

    end_b = (int(_t.time()) // bucket_secs) * bucket_secs
    bucket_count = min(250, max(2, (range_min * 60) // bucket_secs))
    start_b = end_b - (bucket_count - 1) * bucket_secs

    detected, allowed_total, missed = {}, {}, {}
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        agent_q = ",".join("?" * len(AGENT_BLOCK_REASONS))
        for r in conn.execute(
            f"SELECT (CAST(ts/{bucket_secs} AS INTEGER)*{bucket_secs}) AS b, "  # nosec B608 — bucket_secs is int constant; agent_q is "?,?,?" placeholders
            f"COUNT(*) AS n FROM events "
            f"WHERE ts >= ? AND ts <= ? AND reason IN ({agent_q}) "
            f"GROUP BY b",
            (start_b, end_b + bucket_secs, *AGENT_BLOCK_REASONS),
        ):
            detected[int(r["b"])] = r["n"]

        for r in conn.execute(
            f"SELECT (CAST(ts/{bucket_secs} AS INTEGER)*{bucket_secs}) AS b, "  # nosec B608 — bucket_secs is int constant
            f"COUNT(*) AS n FROM events "
            f"WHERE ts >= ? AND ts <= ? AND (reason='' OR reason='OK') "
            f"GROUP BY b",
            (start_b, end_b + bucket_secs),
        ):
            allowed_total[int(r["b"])] = r["n"]

        if stealth_ips:
            ip_q = ",".join("?" * len(stealth_ips))
            for r in conn.execute(
                f"SELECT (CAST(ts/{bucket_secs} AS INTEGER)*{bucket_secs}) AS b, "  # nosec B608 — bucket_secs is int constant; ip_q is "?,?,?" placeholders
                f"COUNT(*) AS n FROM events "
                f"WHERE ts >= ? AND ts <= ? AND (reason='' OR reason='OK') "
                f"AND ip IN ({ip_q}) GROUP BY b",
                (start_b, end_b + bucket_secs, *stealth_ips),
            ):
                missed[int(r["b"])] = r["n"]
        conn.close()
    except Exception as e:
        print(f"[agents-timeline] db error: {e}")

    series = []
    tot_d = tot_m = tot_c = 0
    for b in range(start_b, end_b + 1, bucket_secs):
        d = detected.get(b, 0)
        m = missed.get(b, 0)
        a = allowed_total.get(b, 0)
        c = max(0, a - m)
        tot_d += d; tot_m += m; tot_c += c
        series.append({"t": b, "detected": d, "missed": m, "clean_allowed": c})

    return web.json_response({
        "timeline": series,
        "totals": {"detected": tot_d, "missed": tot_m, "clean_allowed": tot_c},
        "stealth_ips_count": len(stealth_ips),
        "range_min": range_min,
        "bucket_secs": bucket_secs,
        "min_score": min_score,
    }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


async def agents_data_endpoint(request: web.Request):
    """JSON feed for the stealth-agents dashboard.

    Query params:
      ?min_score=N    only return suspects with score >= N (default 20)
      ?limit=N        cap result rows (default 100, max 500)
    """
    try:
        min_score = max(0, min(100, int(request.query.get("min_score", "20"))))
    except ValueError:
        min_score = 20
    try:
        limit = max(1, min(500, int(request.query.get("limit", "100"))))
    except ValueError:
        limit = 100

    async with state_lock:
        n = now()
        suspects = []
        clean = 0
        total_allowed_identities = 0
        for key, s in ip_state.items():
            # 1.5.5 — broaden criteria.  Old logic skipped any identity
            # with allowed_count==0, hiding hard-blocked bots entirely.
            # New: include identities that EITHER have allowed traffic OR
            # have meaningful risk/blocks.  Pure admin-poll identities
            # (allowed_count > 0, risk=0, blocks=0, samples=0) are still
            # filtered as "clean" via the score threshold.
            has_signal = (
                s.allowed_count > 0
                or s.risk_score >= 1.0
                or s.blocked_count > 0
            )
            if not has_signal:
                continue
            total_allowed_identities += 1
            score, comps, mets = _stealth_score(s)
            # 1.5.5 — when the identity has been blocked / has risk but
            # zero "allowed" stealth signal, surface a synthetic score so
            # it shows up in the table.  Order: live risk_score first
            # (most signal-rich), then blocked_count (bot was banned in
            # the past, decayed away but the receipts remain).
            if score == 0:
                if s.risk_score > 0:
                    score = min(100, int(s.risk_score))
                elif s.blocked_count > 0:
                    score = min(100, 30 + min(50, s.blocked_count * 2))
            if score and not comps:
                comps = {"headers":0,"assets":0,"enum":0,"timing":0,
                         "risk":score,"404s":0}
            if score and not mets:
                mets = {
                    "avg_header_score": 0, "html_loads": 0, "static_loads": 0,
                    "unique_paths": len(s.unique_paths),
                    "path_diversity": 0, "behavioral_cov": None,
                    "upstream_404_count": s.upstream_404_count,
                    "risk_score": round(s.risk_score, 1), "samples": 0,
                }
            if score < min_score:
                clean += 1
                continue
            # Per-reason risk breakdown (decayed in lockstep with risk_score)
            risk_breakdown = sorted(
                ((r, round(v, 1)) for r, v in s.risk_by_reason.items() if v >= 0.5),
                key=lambda kv: kv[1], reverse=True,
            )
            blocks_breakdown = sorted(
                ((r, c) for r, c in s.blocks_by_reason.items() if c > 0),
                key=lambda kv: kv[1], reverse=True,
            )
            suspects.append({
                "id": key,
                "ip": s.last_ip or key,
                "is_admin_ip": _is_admin_ip(s.last_ip or key),
                "session": s.last_session,
                "fingerprint": s.last_fingerprint,
                "ja4": s.last_ja4,
                "ua": s.last_user_agent,
                "last_path": s.last_path,
                "last_seen_secs_ago": round(n - s.last_seen, 1),
                "first_seen_secs_ago": round(n - s.first_seen, 1),
                "requests": s.request_count,
                "allowed": s.allowed_count,
                "blocked": s.blocked_count,
                "banned_secs": max(0, round(s.banned_until - n, 0)),
                "stealth_score": score,
                "components": comps,
                "metrics": mets,
                "recent_paths": list(s.last_allowed_paths),
                "risk_breakdown":   risk_breakdown,    # [[reason, weighted], …]
                "blocks_breakdown": blocks_breakdown,  # [[reason, count],   …]
            })
        suspects.sort(key=lambda r: r["stealth_score"], reverse=True)
        suspects = suspects[:limit]
        # Aggregate by score bucket for the bar chart.
        buckets = {"low(20-39)": 0, "med(40-59)": 0, "high(60-79)": 0, "critical(80+)": 0}
        for r in suspects:
            sc = r["stealth_score"]
            if sc >= 80:   buckets["critical(80+)"] += 1
            elif sc >= 60: buckets["high(60-79)"] += 1
            elif sc >= 40: buckets["med(40-59)"] += 1
            else:          buckets["low(20-39)"] += 1

    return web.json_response({
        "summary": {
            "total_with_allowed": total_allowed_identities,
            "suspicious": len(suspects),
            "clean": clean,
            "min_score": min_score,
        },
        "buckets": buckets,
        "suspects": suspects,
    }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


AGENTS_DASHBOARD_HTML = (_DASHBOARDS_DIR / "agents.html").read_text(encoding="utf-8")


async def agents_dashboard_endpoint(request: web.Request):
    body = AGENTS_DASHBOARD_HTML
    return web.Response(
        text=body, content_type="text/html",
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
