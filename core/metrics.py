"""core/metrics.py — per-minute timeline + cost-buffer helpers.

Extracted from proxy.py (Phase 9).  All symbols here were previously
defined globally in proxy.py.  They depend only on:
  • config.*  (TIMELINE_RETAIN_SECS / COST_RETAIN_SECS from env)
  • state.*   (timeline, cost_timeline, metrics, ip_state, state_lock,
               db_queue, events, …)
  • helpers.now / slog
  • db.*      (db_queue is a state global)
  • scoring._decay_risk
"""

import asyncio
import json
import time as _t

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from state import _postgres_available, events_by_cat, by_path_by_cat  # noqa: F401 — underscores/explicit not exported by *
from helpers import now, slog  # noqa: F401
from admin.auth import _is_admin_ip  # noqa: F401


# ── Timeline: per-minute buckets ───────────────────────────────────────────

def _bucket_now() -> int:
    """Return the current minute bucket (epoch seconds rounded to the minute)."""
    return int(_t.time() // 60) * 60


def _cost_bump(elapsed_ms: float):
    """Record a single request's middleware wall-time into the current bucket."""
    b = _bucket_now()
    if b not in cost_timeline:
        cost_timeline[b] = {"sum_ms": 0.0, "count": 0, "max_ms": 0.0}
        cutoff = b - COST_RETAIN_SECS
        for k in [k for k in cost_timeline if k < cutoff]:
            del cost_timeline[k]
    bucket = cost_timeline[b]
    bucket["sum_ms"] += elapsed_ms
    bucket["count"] += 1
    if elapsed_ms > bucket["max_ms"]:
        bucket["max_ms"] = elapsed_ms


# Reasons that bypass detection but are still recorded — not counted as blocked.
_PASSTHROUGH_REASONS: frozenset = frozenset({
    "authorized-robot",
    "bypass-path",         # BYPASS_PATHS prefix match — allowed, no detection
    "operator-passthrough",# authenticated operator accessing upstream — allowed
})


def _timeline_bump(reason: str, missed: bool = False, path: str = ""):
    """Update the current minute bucket.  Caller must hold state_lock.
    `missed` = allowed AND identity score >= SOFT_CHALLENGE_SCORE (medium band).
    `path`   = request path, used to count gwmgmt (admin-namespace) hits."""
    from collections import defaultdict
    b = _bucket_now()
    if b not in timeline:
        timeline[b] = {"total": 0, "blocked": 0, "allowed": 0, "missed": 0,
                       "gwmgmt": 0, "by_reason": defaultdict(int)}
        # cleanup buckets older than retention
        cutoff = b - TIMELINE_RETAIN_SECS
        for k in [k for k in timeline if k < cutoff]:
            del timeline[k]
    bucket = timeline[b]
    # Backfill fields on buckets restored from older snapshots that lacked them
    if "missed"  not in bucket: bucket["missed"]  = 0
    if "gwmgmt"  not in bucket: bucket["gwmgmt"]  = 0
    bucket["total"] += 1
    if path and path.startswith(ADMIN_NS):
        bucket["gwmgmt"] += 1
    if reason and reason not in _PASSTHROUGH_REASONS:
        bucket["blocked"] += 1
        bucket["by_reason"][reason] += 1
    elif reason:  # passthrough — allowed, still tracked in by_reason
        bucket["allowed"] += 1
        bucket["by_reason"][reason] += 1
    else:
        bucket["allowed"] += 1
        if missed:
            bucket["missed"] += 1


# ── Main record function ────────────────────────────────────────────────────

async def record(ip: str, ua: str, path: str, status: int, reason: str,
                 track_key: str = None, sid: str = "", fp: str = "",
                 ja4: str = "", request_id: str = "",
                 signals: list = None, score: float = 0.0):
    """Record one request decision into global metrics + per-identity state +
    event log + DB.
    track_key (identity) is the primary key.  ip is stored on IpState for
    display only.
    `ja4` (R0): TLS handshake fingerprint observed by the trusted upstream
    terminator — surfaced in the event log so the operator can see what
    fingerprints bots are using and populate JA4_DENY_LIST from telemetry.
    """
    from scoring import _decay_risk  # avoid circular at module level
    async with state_lock:
        metrics["total_requests"] += 1
        metrics["by_status"][status] += 1
        metrics["by_path"][path] += 1
        if ja4:
            metrics["by_ja4"][ja4[:64]] += 1
        # Default to ip if no track_key (back-compat for internal/probe paths)
        key = track_key or ip
        s = ip_state[key]
        # 1.5.4: classify "missed" — request was allowed but identity sits
        # in the medium-risk band (>= SOFT_CHALLENGE_SCORE, < RISK_BAN_THRESHOLD).
        # Apply decay before checking so the band reflects the live score.
        _decay_risk(s, now())
        is_missed = (not reason) and SOFT_CHALLENGE_SCORE > 0 and \
                    SOFT_CHALLENGE_SCORE <= s.risk_score < RISK_BAN_THRESHOLD
        _timeline_bump(reason, missed=is_missed, path=path)
        s.last_seen = now()
        s.last_user_agent = ua[:120]
        s.last_path = path[:120]
        if s.last_ip and s.last_ip != ip:
            ip_to_identities[s.last_ip].discard(key)
        s.last_ip = ip
        ip_to_identities[ip].add(key)
        if sid: s.last_session = sid[:24]
        if fp:  s.last_fingerprint = fp
        if ja4: s.last_ja4 = ja4[:64]
        s.request_count += 1
        if reason and reason not in _PASSTHROUGH_REASONS:
            metrics["blocked"] += 1
            metrics["by_reason"][reason] += 1
            s.blocked_count += 1
            s.blocks_by_reason[reason] += 1
        elif reason:  # passthrough — allowed, still tracked in by_reason
            metrics["by_reason"][reason] += 1
            metrics["allowed"] += 1
            s.allowed_count += 1
        else:
            metrics["allowed"] += 1
            s.allowed_count += 1
            if is_missed:
                metrics["missed"] = metrics.get("missed", 0) + 1
        # Persist to DB (non-blocking — drops in queue)
        if db_queue is not None:
            event_ts = _t.time()
            # 1.6.5 — when DB_BACKEND=postgres, fire-and-forget the event
            # write to Postgres alongside the SQLite path so dashboards on
            # both backends see the row. The Postgres write is best-effort.
            if DB_BACKEND == "postgres" and _postgres_available:
                try:
                    asyncio.get_running_loop().run_in_executor(
                        None, pg_insert_event,
                        event_ts, ip, ua[:200], path[:200],
                        status, reason or "",
                        track_key or "", sid or "", fp or "",
                        ja4 or "", request_id or "")
                except Exception:
                    pass
            try:
                db_queue.put_nowait(("event",
                    (event_ts, ip, ua[:200], path[:200], "", status, reason or "")))
                # Persist this client's snapshot
                banned_until_epoch = (
                    event_ts + (s.banned_until - now()) if s.banned_until > now() else 0
                )
                db_queue.put_nowait(("upsert_client", (
                    ip,
                    event_ts - (now() - s.first_seen),
                    event_ts,
                    s.request_count, s.allowed_count, s.blocked_count,
                    banned_until_epoch,
                    s.last_user_agent, s.last_path,
                    json.dumps(dict(s.blocks_by_reason)),
                )))
                # Persist timeline bucket
                b = _bucket_now()
                if b in timeline:
                    tb = timeline[b]
                    db_queue.put_nowait(("upsert_timeline", (
                        b, tb["total"], tb["allowed"], tb["blocked"],
                        tb.get("missed", 0),
                        json.dumps(dict(tb["by_reason"])),
                    )))
                # Periodic global counters flush (every ~50 events)
                if metrics["total_requests"] % 50 == 0:
                    db_queue.put_nowait(("set_kv", ("total_requests", str(metrics["total_requests"]))))
                    db_queue.put_nowait(("set_kv", ("allowed", str(metrics["allowed"]))))
                    db_queue.put_nowait(("set_kv", ("blocked", str(metrics["blocked"]))))
                    db_queue.put_nowait(("set_kv", ("by_reason", json.dumps(dict(metrics["by_reason"])))))
                    db_queue.put_nowait(("set_kv", ("by_status", json.dumps({str(k): v for k, v in metrics["by_status"].items()}))))
                    db_queue.put_nowait(("set_kv", ("by_path", json.dumps(dict(metrics["by_path"])))))
            except asyncio.QueueFull:
                pass  # drop on overload, not critical
        _evt = {
            "ts": _t.time(),
            "ip": ip,
            "is_admin_ip": _is_admin_ip(ip or ""),
            "ua": ua[:80],
            "path": path[:80],
            "method": "",   # filled by caller via closure (kept simple here)
            "status": status,
            "reason": reason or "OK",
            "ja4": ja4[:64] if ja4 else "",
            "rid": request_id[:32] if request_id else "",
            "score": round(float(score or 0.0), 1),
            "track_key": (track_key or ip or "")[:32],
        }
        events.append(_evt)
        # Per-category ring buffers — categories are mutually exclusive, priority order:
        # gwmgmt > authbots > ban > missed > allowed
        if path and path.startswith(ADMIN_NS):
            _req_cat = "gwmgmt"
        elif reason == "authorized-robot":
            _req_cat = "authbots"
        elif reason and reason not in _PASSTHROUGH_REASONS:
            _req_cat = "ban"
        elif is_missed:
            _req_cat = "missed"
        else:
            _req_cat = "allowed"
        events_by_cat[_req_cat].append(_evt)
        by_path_by_cat[_req_cat][path] += 1
        # 1.4.6: emit one structured log line per recorded request so the
        # full forensic record (request_id, verdict, ja4, identity) lands
        # in stdout for downstream ingestion.
        slog("request",
             level="info" if not reason else "warn",
             rid=request_id, ip=ip, ja4=ja4 or "", ua=ua[:120],
             method="", path=path[:200], status=status,
             reason=reason or "ok", track_key=(track_key or "")[:32],
             signals=signals or [], score=round(float(score or 0.0), 1))
