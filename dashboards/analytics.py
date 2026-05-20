# dashboards/analytics.py — analytics endpoints
#
#   GET /secured/score-distribution    — risk-score histogram across all IpState objects
#   GET /secured/traffic-pipeline      — allowed/challenged/blocked/bypassed timeline
#   GET /secured/vhost-heatmap         — per-vhost per-bucket event counts from DB
#   GET /secured/signal-performance    — per-detector hits / block-rate / latency percentiles
#   GET /secured/security-incidents    — recent high-severity events bucketed by severity tier
#   GET /secured/risk-percentiles      — 1.8.3: P5/P25/P50/P75/P95/P99 ribbon + histogram + KPIs
#   GET /secured/ban-events            — 1.8.3: ban event timeline + CAPTCHA funnel
#   GET /secured/top-attackers         — 1.8.3: enriched IP leaderboard (ASN / AbuseIPDB / sparkline)

import sqlite3
import time as _t
from collections import defaultdict, deque

from config import *   # noqa: F401,F403
from config import _DATA_PATH  # noqa: F401
from state import *    # noqa: F401,F403
from helpers import now  # noqa: F401
from aiohttp import web


# ── helpers ────────────────────────────────────────────────────────────────────

def _percentile(sorted_samples: list, p: float) -> float:
    """Return the p-th percentile (0–100) of a pre-sorted list.  Returns 0.0 if empty."""
    if not sorted_samples:
        return 0.0
    idx = max(0, int(len(sorted_samples) * p / 100.0) - 1)
    return round(float(sorted_samples[idx]), 3)


# ── Endpoint A: /secured/score-distribution ─────────────────────────────────

async def score_distribution_endpoint(request: web.Request):
    """Bucket current risk_score values of all tracked IpState objects into 8 bins.
    Also returns soft-challenge threshold and ban threshold from config.
    """
    try:
        bins = {
            "0":      0,
            "1–9":    0,
            "10–29":  0,
            "30–49":  0,
            "50–69":  0,
            "70–89":  0,
            "90–99":  0,
            "100+":   0,
        }
        async with state_lock:
            scores = [s.risk_score for s in ip_state.values()]

        for score in scores:
            if score == 0:
                bins["0"] += 1
            elif score < 10:
                bins["1–9"] += 1
            elif score < 30:
                bins["10–29"] += 1
            elif score < 50:
                bins["30–49"] += 1
            elif score < 70:
                bins["50–69"] += 1
            elif score < 90:
                bins["70–89"] += 1
            elif score < 100:
                bins["90–99"] += 1
            else:
                bins["100+"] += 1

        bin_list = [{"label": label, "count": count} for label, count in bins.items()]

        return web.json_response({
            "bins": bin_list,
            "threshold_soft": SOFT_CHALLENGE_SCORE,
            "threshold_ban":  RISK_BAN_THRESHOLD,
            "total_ips": len(scores),
        }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    except Exception as exc:
        return web.json_response(
            {"error": str(exc)[:200]},
            status=500, headers={"Cache-Control": "no-store"})


# ── Endpoint B: /secured/traffic-pipeline ───────────────────────────────────

async def traffic_pipeline_endpoint(request: web.Request):
    """Aggregate allowed/challenged/blocked/bypassed counts per time bucket.

    Query params:
      ?range=<minutes>   window length (default 120, max 10080)
      ?bucket=<secs>     bucket width  (default 300; must be 60|300|900|3600|86400)
      ?end=<epoch>       right edge of window (defaults to now)
    """
    try:
        try:
            range_min = max(5, min(10080, int(request.query.get("range", "120"))))
        except (ValueError, TypeError):
            range_min = 120
        try:
            bucket_secs = int(request.query.get("bucket", "300"))
            if bucket_secs not in (60, 300, 900, 3600, 86400):
                bucket_secs = 300
        except (ValueError, TypeError):
            bucket_secs = 300
        try:
            end_epoch = int(request.query.get("end", str(int(_t.time()))))
        except (ValueError, TypeError):
            end_epoch = int(_t.time())

        end_b = (end_epoch // bucket_secs) * bucket_secs
        bucket_count = min(250, max(2, (range_min * 60) // bucket_secs))
        start_b = end_b - (bucket_count - 1) * bucket_secs

        # Collect per-minute in-memory timeline data and aggregate into coarser buckets
        agg: dict = {}  # bucket_epoch → {"allowed":0,"challenged":0,"blocked":0,"bypassed":0}

        # We need the set of IPs currently in the "bypassed" band (allowed but score >= SOFT_CHALLENGE_SCORE)
        async with state_lock:
            bypassed_ips: set = set()
            for s in ip_state.values():
                if (SOFT_CHALLENGE_SCORE > 0
                        and SOFT_CHALLENGE_SCORE <= s.risk_score < RISK_BAN_THRESHOLD
                        and s.last_ip):
                    bypassed_ips.add(s.last_ip)

        def _get_slot(ts: int) -> int:
            return (ts // bucket_secs) * bucket_secs

        # Walk in-memory minute buckets
        in_mem_oldest = int(_t.time()) - TIMELINE_RETAIN_SECS
        for minute_epoch, tb in list(timeline.items()):
            if minute_epoch < start_b or minute_epoch > end_b + bucket_secs:
                continue
            slot = _get_slot(minute_epoch)
            if slot not in agg:
                agg[slot] = {"allowed": 0, "challenged": 0, "blocked": 0, "bypassed": 0}
            agg[slot]["allowed"]    += tb.get("allowed", 0)
            agg[slot]["challenged"] += tb.get("challenged", 0)
            agg[slot]["blocked"]    += tb.get("blocked", 0)
            agg[slot]["bypassed"]   += tb.get("missed", 0)  # "missed" = allowed-but-risky

        # Fill DB data for older ranges not in memory
        if start_b < in_mem_oldest:
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                for row in conn.execute(
                    "SELECT bucket_minute, total, allowed, blocked, missed "
                    "FROM timeline WHERE bucket_minute >= ? AND bucket_minute < ?",
                    (start_b, in_mem_oldest),
                ):
                    m = int(row["bucket_minute"])
                    slot = _get_slot(m)
                    if slot not in agg:
                        agg[slot] = {"allowed": 0, "challenged": 0, "blocked": 0, "bypassed": 0}
                    agg[slot]["allowed"]  += int(row["allowed"] or 0)
                    agg[slot]["blocked"]  += int(row["blocked"] or 0)
                    agg[slot]["bypassed"] += int(row["missed"]  or 0)
                conn.close()
            except Exception:
                pass  # DB unavailable — use memory-only data

        series = []
        tot = {"allowed": 0, "challenged": 0, "blocked": 0, "bypassed": 0}
        for b in range(start_b, end_b + 1, bucket_secs):
            d = agg.get(b, {"allowed": 0, "challenged": 0, "blocked": 0, "bypassed": 0})
            series.append({
                "t":          b,
                "allowed":    d["allowed"],
                "challenged": d["challenged"],
                "blocked":    d["blocked"],
                "bypassed":   d["bypassed"],
            })
            for k in tot:
                tot[k] += d[k]

        return web.json_response({
            "timeline":    series,
            "totals":      tot,
            "range_min":   range_min,
            "bucket_secs": bucket_secs,
        }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    except Exception as exc:
        return web.json_response(
            {"error": str(exc)[:200]},
            status=500, headers={"Cache-Control": "no-store"})


# ── Endpoint C: /secured/vhost-heatmap ──────────────────────────────────────

async def vhost_heatmap_endpoint(request: web.Request):
    """Per-vhost per-bucket event counts from the SQLite events table.

    Query params:
      ?range=<minutes>   window length (default 120)
      ?bucket=<secs>     bucket width  (default 300)
      ?end=<epoch>       right edge of window (defaults to now)

    Falls back to empty data if DB is unavailable.
    """
    try:
        try:
            range_min = max(5, min(10080, int(request.query.get("range", "120"))))
        except (ValueError, TypeError):
            range_min = 120
        try:
            bucket_secs = max(60, min(86400, int(request.query.get("bucket", "300"))))
        except (ValueError, TypeError):
            bucket_secs = 300
        try:
            end_epoch = int(request.query.get("end", str(int(_t.time()))))
        except (ValueError, TypeError):
            end_epoch = int(_t.time())

        end_b   = (end_epoch // bucket_secs) * bucket_secs
        bucket_count = min(250, max(2, (range_min * 60) // bucket_secs))
        start_b = end_b - (bucket_count - 1) * bucket_secs

        buckets_list = list(range(start_b, end_b + 1, bucket_secs))
        n_buckets = len(buckets_list)
        bucket_index = {b: i for i, b in enumerate(buckets_list)}

        # Per-vhost, per-bucket accumulators
        vhost_totals:   dict = {}  # vhost → [{"total":0,"blocked":0}] × n_buckets
        vhosts_ordered: list = []

        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row

            # All events rows in window, grouped by vhost + bucket
            _PASSTHROUGH = {"", "ok", "operator-passthrough", "bypass-path",
                            "authorized-robot", "bypass-mode"}
            rows = conn.execute(
                "SELECT vhost, "
                "  CAST(ts / ? AS INTEGER) * ? AS slot, "
                "  COUNT(*) AS total, "
                "  SUM(CASE WHEN reason IS NOT NULL AND reason != '' "
                "           AND LOWER(reason) NOT IN "
                "           ('ok','authorized-robot','operator-passthrough','bypass-path','bypass-mode') "
                "      THEN 1 ELSE 0 END) AS blocked "
                "FROM events "
                "WHERE ts >= ? AND ts <= ? AND vhost != '' "
                "GROUP BY vhost, slot",
                (bucket_secs, bucket_secs, start_b, end_b + bucket_secs),
            ).fetchall()
            conn.close()

            for row in rows:
                vh   = row["vhost"] or ""
                slot = int(row["slot"])
                if slot not in bucket_index:
                    continue
                if vh not in vhost_totals:
                    vhost_totals[vh] = [{"total": 0, "blocked": 0} for _ in range(n_buckets)]
                    vhosts_ordered.append(vh)
                idx = bucket_index[slot]
                vhost_totals[vh][idx]["total"]   += int(row["total"]   or 0)
                vhost_totals[vh][idx]["blocked"]  += int(row["blocked"] or 0)

        except Exception:
            pass  # DB unavailable — return empty cells

        return web.json_response({
            "vhosts":  vhosts_ordered,
            "buckets": buckets_list,
            "cells":   vhost_totals,
        }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    except Exception as exc:
        return web.json_response(
            {"error": str(exc)[:200]},
            status=500, headers={"Cache-Control": "no-store"})


# ── Endpoint D: /secured/signal-performance ─────────────────────────────────

async def signal_performance_endpoint(request: web.Request):
    """Per-signal hit/block counts and latency percentiles.

    Uses:
      _detector_hits      — reason → int hit count (from proxy_handler)
      _detector_latency   — reason → deque(ms float)  (from proxy_handler)
      metrics["by_reason"]— reason → blocked count
    Also groups signals by method category via _reason_method.
    """
    try:
        # Import the private dicts from core.proxy_handler at call time
        # (they are module-level singletons, same reference across imports)
        from core.proxy_handler import (
            _detector_hits, _detector_latency, _reason_method,
        )

        # Snapshot to avoid mutation during iteration
        hits_snap    = dict(_detector_hits)
        latency_snap = {r: list(dq) for r, dq in _detector_latency.items()}
        blocks_snap  = dict(metrics.get("by_reason", {}))

        signals_out = []
        for reason, hit_count in hits_snap.items():
            samples = sorted(latency_snap.get(reason, []))
            p50 = _percentile(samples, 50)
            p95 = _percentile(samples, 95)
            p99 = _percentile(samples, 99)
            blocks    = blocks_snap.get(reason, 0)
            block_rate = round(blocks / hit_count * 100.0, 1) if hit_count else 0.0
            signals_out.append({
                "reason":     reason,
                "method":     _reason_method(reason),
                "hits":       hit_count,
                "blocks":     blocks,
                "p50_ms":     p50,
                "p95_ms":     p95,
                "p99_ms":     p99,
                "block_rate": block_rate,
            })

        # Also include reasons that appear in blocks but had no latency sample
        for reason, blocks in blocks_snap.items():
            if reason not in hits_snap and blocks > 0:
                signals_out.append({
                    "reason":     reason,
                    "method":     _reason_method(reason),
                    "hits":       blocks,
                    "blocks":     blocks,
                    "p50_ms":     0.0,
                    "p95_ms":     0.0,
                    "p99_ms":     0.0,
                    "block_rate": 100.0,
                })

        signals_out.sort(key=lambda x: -x["hits"])

        # Method-level totals
        method_totals: dict = defaultdict(lambda: {"hits": 0, "blocks": 0})
        for sig in signals_out:
            m = sig["method"]
            method_totals[m]["hits"]   += sig["hits"]
            method_totals[m]["blocks"] += sig["blocks"]

        return web.json_response({
            "signals":       signals_out,
            "method_totals": dict(method_totals),
        }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    except Exception as exc:
        return web.json_response(
            {"error": str(exc)[:200]},
            status=500, headers={"Cache-Control": "no-store"})


# ── Endpoint E: /secured/security-incidents ─────────────────────────────────

_INCIDENT_CRITICAL = frozenset({
    "canary-echo", "honey-cred", "canary-probe-miss",
})
_INCIDENT_HIGH = frozenset({
    "honeypot", "honeypot-silent", "body-rce", "body-ssrf", "body-cmd",
    "body-sqli", "path-sweep", "coordinated-probe", "tor-exit",
})
_INCIDENT_MEDIUM = frozenset({
    "body-lfi", "body-xss", "rate-burst", "session-churn",
    "suspicious-path", "rate-limit-endpoint",
})
_INCIDENT_ALL = _INCIDENT_CRITICAL | _INCIDENT_HIGH | _INCIDENT_MEDIUM

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2}


def _incident_severity(reason: str) -> str:
    if reason in _INCIDENT_CRITICAL:
        return "critical"
    if reason in _INCIDENT_HIGH:
        return "high"
    return "medium"


async def security_incidents_endpoint(request: web.Request):
    """Recent high-severity events from the events table, enriched with
    in-memory risk scores.

    Query params:
      ?limit=<int>    max rows returned (default 100, max 500)
      ?since=<epoch>  only events newer than this timestamp (default: last 24 h)
    """
    try:
        try:
            limit = max(1, min(500, int(request.query.get("limit", "100"))))
        except (ValueError, TypeError):
            limit = 100
        try:
            since = int(request.query.get("since", str(int(_t.time()) - 86400)))
        except (ValueError, TypeError):
            since = int(_t.time()) - 86400

        # Snapshot ip → max risk_score from in-memory state
        async with state_lock:
            ip_risk: dict = {}
            for s in ip_state.values():
                ip = s.last_ip
                if ip:
                    ip_risk[ip] = max(ip_risk.get(ip, 0.0), s.risk_score)

        # Fetch matching events from DB
        events_out: list = []
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            placeholders = ",".join("?" * len(_INCIDENT_ALL))
            rows = conn.execute(
                f"SELECT ts, ip, ua, path, method, status, reason, vhost "
                f"FROM events "
                f"WHERE ts >= ? AND reason IN ({placeholders}) "
                f"ORDER BY ts DESC LIMIT ?",
                (since, *_INCIDENT_ALL, limit),
            ).fetchall()
            conn.close()

            for row in rows:
                ip = row["ip"] or ""
                reason = row["reason"] or ""
                events_out.append({
                    "ts":         float(row["ts"]),
                    "ip":         ip,
                    "ua":         (row["ua"] or "")[:200],
                    "path":       (row["path"] or "")[:300],
                    "method":     row["method"] or "",
                    "status":     int(row["status"] or 0),
                    "reason":     reason,
                    "vhost":      row["vhost"] or "",
                    "severity":   _incident_severity(reason),
                    "risk_score": round(ip_risk.get(ip, 0.0), 1),
                })
        except Exception:
            pass  # DB unavailable — return empty list

        # Count by severity
        counts = {"critical": 0, "high": 0, "medium": 0}
        for ev in events_out:
            counts[ev["severity"]] += 1

        return web.json_response({
            "incidents": events_out,
            "counts":    counts,
            "since":     since,
            "limit":     limit,
        }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    except Exception as exc:
        return web.json_response(
            {"error": str(exc)[:200]},
            status=500, headers={"Cache-Control": "no-store"})


# ── Endpoint F: /secured/risk-percentiles ────────────────────────────────────
# Module-level ring buffer — stores snapshots so the ribbon chart has a history
# to display. Each poll appends one entry; maxlen=120 keeps ~4 minutes at 2s.

_RISK_PCT_HISTORY: deque = deque(maxlen=120)


async def risk_percentiles_endpoint(request: web.Request):
    """Compute P5/P25/P50/P75/P95/P99 of all tracked IP risk scores.

    Appends a snapshot to the module-level history deque so callers can render
    a time-series ribbon without a dedicated DB table.

    Query params:
      ?min_score=<float>   filter out IPs below this score (default 0)
    """
    try:
        try:
            _raw = request.query.get("min_score", "0")
            if _raw.strip().lower() in ("nan", "inf", "-inf", "infinity", "-infinity"):
                raise ValueError("non-finite score")
            min_score = max(0.0, min(100.0, float(_raw)))
        except (ValueError, TypeError, OverflowError):
            min_score = 0.0

        async with state_lock:
            scores = [
                s.risk_score for s in ip_state.values()
                if s.risk_score >= min_score
            ]

        scores_sorted = sorted(scores)
        n = len(scores_sorted)

        p5  = _percentile(scores_sorted, 5)
        p25 = _percentile(scores_sorted, 25)
        p50 = _percentile(scores_sorted, 50)
        p75 = _percentile(scores_sorted, 75)
        p95 = _percentile(scores_sorted, 95)
        p99 = _percentile(scores_sorted, 99)

        snap = {
            "ts": round(_t.time(), 1),
            "p5": p5, "p25": p25, "p50": p50,
            "p75": p75, "p95": p95, "p99": p99,
            "n": n,
        }
        _RISK_PCT_HISTORY.append(snap)

        # 20-bin histogram (bins: 0-4, 5-9, …, 95-99, 100+)
        hist = [0] * 21
        for sc in scores_sorted:
            idx = min(20, int(sc / 5))
            hist[idx] = hist[idx] + 1

        # KPIs
        above_ban  = sum(1 for sc in scores_sorted if sc >= RISK_BAN_THRESHOLD)
        above_soft = sum(1 for sc in scores_sorted if sc >= SOFT_CHALLENGE_SCORE)
        pct_ban  = round(above_ban  / max(n, 1) * 100, 1)
        pct_soft = round(above_soft / max(n, 1) * 100, 1)

        # Trend: compare current median to 10 snapshots ago
        hist_list = list(_RISK_PCT_HISTORY)
        trend = "flat"
        if len(hist_list) >= 10:
            prev_p50 = hist_list[-10]["p50"]
            delta = p50 - prev_p50
            if delta > 1:
                trend = "up"
            elif delta < -1:
                trend = "down"

        return web.json_response({
            "history":        hist_list,
            "current":        snap,
            "histogram":      [{"bin": i * 5, "count": c} for i, c in enumerate(hist)],
            "threshold_soft": SOFT_CHALLENGE_SCORE,
            "threshold_ban":  RISK_BAN_THRESHOLD,
            "total_ips":      n,
            "kpis": {
                "p50":       p50,
                "p95":       p95,
                "pct_ban":   pct_ban,
                "pct_soft":  pct_soft,
                "trend":     trend,
            },
        }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    except Exception as exc:
        return web.json_response(
            {"error": str(exc)[:200]},
            status=500, headers={"Cache-Control": "no-store"})


# ── Endpoint G: /secured/ban-events ──────────────────────────────────────────

_IP_BAN_REASONS  = frozenset({
    "banned", "really-banned", "bot-rule-ban", "bot-rule-really-ban",
    "crowdsec-block", "peer-sync-ban", "canary-echo", "honey-cred",
})
_SES_BAN_REASONS = frozenset({
    "banned-silent", "honeypot-silent",
})
_BYPASS_REASONS  = frozenset({
    "bypass-mode", "bypass-path", "authorized-robot",
})
_CHAL_REASONS    = frozenset({"chal-required"})

_ALL_BAN_EVENT_REASONS = _IP_BAN_REASONS | _SES_BAN_REASONS | _BYPASS_REASONS | _CHAL_REASONS


async def ban_events_endpoint(request: web.Request):
    """Time-bucketed ban event timeline + CAPTCHA funnel totals.

    Query params:
      ?range=<minutes>   window (default 120, max 10080)
      ?bucket=<secs>     bucket width (default 300)
      ?end=<epoch>       right edge (defaults to now)
    """
    try:
        try:
            range_min = max(5, min(10080, int(request.query.get("range", "120"))))
        except (ValueError, TypeError):
            range_min = 120
        try:
            bucket_secs = int(request.query.get("bucket", "300"))
            if bucket_secs not in (60, 300, 900, 3600, 86400):
                bucket_secs = 300
        except (ValueError, TypeError):
            bucket_secs = 300
        try:
            end_epoch = int(request.query.get("end", str(int(_t.time()))))
        except (ValueError, TypeError):
            end_epoch = int(_t.time())

        end_b = (end_epoch // bucket_secs) * bucket_secs
        bucket_count = min(250, max(2, (range_min * 60) // bucket_secs))
        start_b = end_b - (bucket_count - 1) * bucket_secs

        agg: dict = {}

        def _slot(ts: int) -> int:
            return (ts // bucket_secs) * bucket_secs

        def _ensure(slot: int):
            if slot not in agg:
                agg[slot] = {"ip_ban": 0, "ses_ban": 0, "bypass": 0, "chal": 0}

        for minute_epoch, tb in list(timeline.items()):
            if minute_epoch < start_b or minute_epoch > end_b + bucket_secs:
                continue
            slot = _slot(minute_epoch)
            _ensure(slot)
            by_r = tb.get("by_reason", {})
            for reason, cnt in by_r.items():
                if reason in _IP_BAN_REASONS:
                    agg[slot]["ip_ban"] = agg[slot]["ip_ban"] + cnt
                elif reason in _SES_BAN_REASONS:
                    agg[slot]["ses_ban"] = agg[slot]["ses_ban"] + cnt
                elif reason in _BYPASS_REASONS:
                    agg[slot]["bypass"] = agg[slot]["bypass"] + cnt
                elif reason in _CHAL_REASONS:
                    agg[slot]["chal"] = agg[slot]["chal"] + cnt

        in_mem_oldest = int(_t.time()) - TIMELINE_RETAIN_SECS
        if start_b < in_mem_oldest:
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                placeholders = ",".join("?" * len(_ALL_BAN_EVENT_REASONS))
                rows = conn.execute(
                    f"SELECT ts, reason FROM events "
                    f"WHERE ts >= ? AND ts < ? AND reason IN ({placeholders})",
                    (start_b, in_mem_oldest, *_ALL_BAN_EVENT_REASONS),
                ).fetchall()
                conn.close()
                for row in rows:
                    slot = _slot(int(row["ts"]))
                    if slot < start_b or slot > end_b:
                        continue
                    _ensure(slot)
                    reason = row["reason"] or ""
                    if reason in _IP_BAN_REASONS:
                        agg[slot]["ip_ban"] = agg[slot]["ip_ban"] + 1
                    elif reason in _SES_BAN_REASONS:
                        agg[slot]["ses_ban"] = agg[slot]["ses_ban"] + 1
                    elif reason in _BYPASS_REASONS:
                        agg[slot]["bypass"] = agg[slot]["bypass"] + 1
                    elif reason in _CHAL_REASONS:
                        agg[slot]["chal"] = agg[slot]["chal"] + 1
            except Exception:
                pass

        series = []
        totals = {"ip_ban": 0, "ses_ban": 0, "bypass": 0, "chal": 0}
        for b in range(start_b, end_b + 1, bucket_secs):
            d = agg.get(b, {"ip_ban": 0, "ses_ban": 0, "bypass": 0, "chal": 0})
            series.append({"t": b, **d})
            for k in totals:
                totals[k] = totals[k] + d[k]

        chal_issued = metrics.get("by_reason", {}).get("chal-required", 0)
        async with state_lock:
            n_chal_ips     = sum(1 for s in ip_state.values()
                                 if s.blocks_by_reason.get("chal-required", 0) > 0)
            n_chal_allowed = sum(1 for s in ip_state.values()
                                 if s.blocks_by_reason.get("chal-required", 0) > 0
                                 and s.allowed_count > 0)
            n_still_banned = sum(1 for s in ip_state.values()
                                 if s.blocks_by_reason.get("chal-required", 0) > 0
                                 and s.banned_until > _t.monotonic())

        solve_rate = round(n_chal_allowed / max(n_chal_ips, 1) * 100.0, 1) if n_chal_ips else 0.0

        return web.json_response({
            "timeline":    series,
            "totals":      totals,
            "range_min":   range_min,
            "bucket_secs": bucket_secs,
            "captcha_funnel": {
                "issued":          chal_issued,
                "ips_challenged":  n_chal_ips,
                "ips_passed":      n_chal_allowed,
                "ips_banned":      n_still_banned,
                "solve_rate":      solve_rate,
            },
        }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    except Exception as exc:
        return web.json_response(
            {"error": str(exc)[:200]},
            status=500, headers={"Cache-Control": "no-store"})


# ── Endpoint H: /secured/top-attackers ───────────────────────────────────────

async def top_attackers_endpoint(request: web.Request):
    """Enriched per-IP attacker leaderboard.

    Returns the top N IPs by risk_score, enriched with:
      - ASN / organisation (MaxMind)
      - Country code + flag emoji (MaxMind / in-memory last_country)
      - AbuseIPDB confidence score (DB cache)
      - Active ban state + expiry epoch
      - 24-hour per-hour request sparkline (DB events)
      - JA4 fingerprint

    Query params:
      ?limit=<int>    rows (default 50, max 200)
      ?sort=<field>   risk_score|request_count|blocked_count (default risk_score)
      ?vhost=<str>    filter by last seen vhost (optional)
    """
    try:
        try:
            limit = max(1, min(200, int(request.query.get("limit", "50"))))
        except (ValueError, TypeError):
            limit = 50
        sort_field = request.query.get("sort", "risk_score")
        if sort_field not in ("risk_score", "request_count", "blocked_count"):
            sort_field = "risk_score"
        vhost_filter = (request.query.get("vhost") or "").strip()

        async with state_lock:
            ip_agg: dict = {}
            for _tk, s in ip_state.items():
                ip = s.last_ip
                if not ip:
                    continue
                if vhost_filter and s.last_vhost != vhost_filter:
                    continue
                if ip not in ip_agg:
                    ip_agg[ip] = {
                        "ip":             ip,
                        "risk_score":     0.0,
                        "request_count":  0,
                        "allowed_count":  0,
                        "blocked_count":  0,
                        "suspicion_score": 0,
                        "banned_until":   0.0,
                        "last_seen":      0.0,
                        "last_ua":        "",
                        "last_path":      "",
                        "last_ja4":       "",
                        "last_country":   "",
                        "last_vhost":     "",
                        "blocks_by_reason": {},
                    }
                rec = ip_agg[ip]
                rec["risk_score"]      = max(rec["risk_score"],     s.risk_score)
                rec["request_count"]   = rec["request_count"]       + s.request_count
                rec["allowed_count"]   = rec["allowed_count"]       + s.allowed_count
                rec["blocked_count"]   = rec["blocked_count"]       + s.blocked_count
                rec["suspicion_score"] = max(rec["suspicion_score"], s.suspicion_score)
                rec["last_seen"]       = max(rec["last_seen"],      s.last_seen)
                if s.banned_until > rec["banned_until"]:
                    rec["banned_until"] = s.banned_until
                if s.last_user_agent:
                    rec["last_ua"] = s.last_user_agent[:120]
                if s.last_path:
                    rec["last_path"] = s.last_path[:120]
                if s.last_ja4:
                    rec["last_ja4"] = s.last_ja4
                if s.last_country:
                    rec["last_country"] = s.last_country
                if s.last_vhost:
                    rec["last_vhost"] = s.last_vhost
                for reason, cnt in s.blocks_by_reason.items():
                    old = rec["blocks_by_reason"].get(reason, 0)
                    rec["blocks_by_reason"][reason] = old + cnt

        top_ips = sorted(ip_agg.values(), key=lambda r: -r[sort_field])[:limit]

        if not top_ips:
            return web.json_response({
                "attackers": [], "total_tracked": 0,
            }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

        try:
            from reputation.maxmind import _asn_lookup, _city_lookup
        except ImportError:
            def _asn_lookup(ip):  # noqa: F811
                return None, "", False, "disabled"
            def _city_lookup(ip):  # noqa: F811
                return None

        ip_list = [r["ip"] for r in top_ips]
        abuse_scores: dict = {}
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            placeholders = ",".join("?" * len(ip_list))
            for row in conn.execute(
                f"SELECT ip, score FROM abuseipdb_cache WHERE ip IN ({placeholders})",
                ip_list,
            ).fetchall():
                abuse_scores[row["ip"]] = int(row["score"])
            conn.close()
        except Exception:
            pass

        sparklines: dict = {ip: [0] * 24 for ip in ip_list}
        now_epoch = int(_t.time())
        sparkline_start = now_epoch - 86400
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            placeholders = ",".join("?" * len(ip_list))
            rows = conn.execute(
                f"SELECT ip, ts FROM events "
                f"WHERE ts >= ? AND ip IN ({placeholders})",
                (sparkline_start, *ip_list),
            ).fetchall()
            conn.close()
            for row in rows:
                ip = row["ip"]
                if ip in sparklines:
                    hour_idx = min(23, int((int(row["ts"]) - sparkline_start) // 3600))
                    sparklines[ip][hour_idx] = sparklines[ip][hour_idx] + 1
        except Exception:
            pass

        ban_expiry: dict = {}
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            placeholders = ",".join("?" * len(ip_list))
            for row in conn.execute(
                f"SELECT ip, banned_until, reason FROM bans "
                f"WHERE ip IN ({placeholders}) AND banned_until > ?",
                (*ip_list, now_epoch),
            ).fetchall():
                ban_expiry[row["ip"]] = {
                    "until":  float(row["banned_until"]),
                    "reason": row["reason"] or "",
                }
            conn.close()
        except Exception:
            pass

        _FLAG_MAP = {
            "AF": "🇦🇫", "AL": "🇦🇱", "DZ": "🇩🇿", "AR": "🇦🇷", "AU": "🇦🇺",
            "AT": "🇦🇹", "BE": "🇧🇪", "BR": "🇧🇷", "BG": "🇧🇬", "CA": "🇨🇦",
            "CN": "🇨🇳", "CO": "🇨🇴", "HR": "🇭🇷", "CZ": "🇨🇿", "DK": "🇩🇰",
            "EG": "🇪🇬", "FI": "🇫🇮", "FR": "🇫🇷", "DE": "🇩🇪", "GR": "🇬🇷",
            "HK": "🇭🇰", "HU": "🇭🇺", "IN": "🇮🇳", "ID": "🇮🇩", "IR": "🇮🇷",
            "IE": "🇮🇪", "IL": "🇮🇱", "IT": "🇮🇹", "JP": "🇯🇵", "KZ": "🇰🇿",
            "KE": "🇰🇪", "KR": "🇰🇷", "MX": "🇲🇽", "NL": "🇳🇱", "NZ": "🇳🇿",
            "NG": "🇳🇬", "NO": "🇳🇴", "PK": "🇵🇰", "PL": "🇵🇱", "PT": "🇵🇹",
            "RO": "🇷🇴", "RU": "🇷🇺", "SA": "🇸🇦", "SG": "🇸🇬", "ZA": "🇿🇦",
            "ES": "🇪🇸", "SE": "🇸🇪", "CH": "🇨🇭", "TH": "🇹🇭", "TN": "🇹🇳",
            "TR": "🇹🇷", "UA": "🇺🇦", "GB": "🇬🇧", "US": "🇺🇸", "VN": "🇻🇳",
        }

        def _flag(cc: str) -> str:
            return _FLAG_MAP.get((cc or "").upper(), "")

        monotonic_now = _t.monotonic()
        attackers = []
        for rec in top_ips:
            ip = rec["ip"]
            asn_num, org, is_hosting, _ = _asn_lookup(ip)
            country = rec["last_country"] or ""
            if not country:
                geo = _city_lookup(ip)
                if geo:
                    country = geo[2] or ""

            ban_info = ban_expiry.get(ip)
            in_mem_ban = rec["banned_until"]
            is_banned = bool(ban_info) or (in_mem_ban > monotonic_now)
            ban_until_epoch = ban_info["until"] if ban_info else (
                now_epoch + (in_mem_ban - monotonic_now) if in_mem_ban > monotonic_now else 0
            )

            attackers.append({
                "ip":            ip,
                "asn":           asn_num,
                "org":           org[:80] if org else "",
                "is_hosting":    is_hosting,
                "country":       country,
                "flag":          _flag(country),
                "request_count": rec["request_count"],
                "allowed_count": rec["allowed_count"],
                "blocked_count": rec["blocked_count"],
                "bot_score":     rec["suspicion_score"],
                "risk_score":    round(rec["risk_score"], 1),
                "ja4":           rec["last_ja4"],
                "last_ua":       rec["last_ua"],
                "last_path":     rec["last_path"],
                "last_vhost":    rec["last_vhost"],
                "last_seen":     round(rec["last_seen"], 1),
                "is_banned":     is_banned,
                "ban_until":     round(ban_until_epoch, 0) if ban_until_epoch else 0,
                "ban_reason":    ban_info["reason"] if ban_info else "",
                "abuse_score":   abuse_scores.get(ip, -1),
                "sparkline":     sparklines.get(ip, [0] * 24),
                "top_reason":    max(rec["blocks_by_reason"], key=rec["blocks_by_reason"].get)
                                 if rec["blocks_by_reason"] else "",
            })

        return web.json_response({
            "attackers":     attackers,
            "total_tracked": len(ip_agg),
            "sort_field":    sort_field,
            "limit":         limit,
        }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    except Exception as exc:
        return web.json_response(
            {"error": str(exc)[:200]},
            status=500, headers={"Cache-Control": "no-store"})
