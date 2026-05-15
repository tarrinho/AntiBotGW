# dashboards/analytics.py — analytics endpoints
#
#   GET /secured/score-distribution    — risk-score histogram across all IpState objects
#   GET /secured/traffic-pipeline      — allowed/challenged/blocked/bypassed timeline
#   GET /secured/vhost-heatmap         — per-vhost per-bucket event counts from DB
#   GET /secured/signal-performance    — per-detector hits / block-rate / latency percentiles
#   GET /secured/security-incidents    — recent high-severity events bucketed by severity tier

import sqlite3
import time as _t
from collections import defaultdict

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
    "canary-echo", "honey-cred", "redirect-maze-bot", "canary-probe-miss",
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
