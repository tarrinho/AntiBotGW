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
from vhost import current_vhost_host

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from state import _postgres_available, events_by_cat, by_path_by_cat  # noqa: F401 — underscores/explicit not exported by *
from helpers import now, slog  # noqa: F401
from admin.auth import _is_admin_ip  # noqa: F401
from db.postgres import pg_insert_event  # noqa: F401


# ── Cardinality cap for attacker-influenced counters ───────────────────────
# `metrics["by_path"]`, `by_path_by_cat[*]` (keyed by raw request path) and
# `metrics["by_ja4"]` (keyed by the TLS fingerprint) are all client-controllable
# and were previously unbounded. A path-enumeration or TLS-churn flood — exactly
# the bot traffic this gateway targets — would grow them without limit until the
# process is OOM-killed (which also blanks the in-memory dashboards on restart).
# Bound them FIFO: when adding a NEW key would exceed the cap, evict the
# oldest-inserted key first. Mirrors _DETECTOR_REASONS_CAP for the reason dicts.
_PATH_CARD_CAP = 2048

def _bump_capped(d: dict, key: str, cap: int = _PATH_CARD_CAP) -> None:
    """Increment d[key] by 1, evicting the oldest-inserted key when adding a new
    key would push the dict past `cap`. Keeps len(d) <= cap. Caller holds the
    relevant lock (these dicts are mutated under state_lock)."""
    if key not in d and len(d) >= cap:
        try:
            del d[next(iter(d))]   # dict preserves insertion order → FIFO
        except (StopIteration, KeyError):
            pass
    d[key] = d.get(key, 0) + 1


# ── Timeline: per-minute buckets ───────────────────────────────────────────

def _bucket_now() -> int:
    """Return the current minute bucket (epoch seconds rounded to the minute)."""
    return int(_t.time() // 60) * 60


def _cost_bump(elapsed_ms: float):
    """Record a single request's middleware wall-time into the current bucket."""
    b = _bucket_now()
    if b not in cost_timeline:
        cost_timeline[b] = {"sum_ms": 0.0, "count": 0, "max_ms": 0.0}
        # 1.8.14 (perf) — cost_timeline is an OrderedDict (insertion-ordered =
        # monotonic-time-ordered); evict from the head until the oldest bucket
        # is within retention. O(buckets-to-evict) vs O(all-buckets) for the
        # old `[k for k in d if k < cutoff]` scan.
        cutoff = b - COST_RETAIN_SECS
        while cost_timeline:
            _oldest = next(iter(cost_timeline))
            if _oldest >= cutoff:
                break
            del cost_timeline[_oldest]
    bucket = cost_timeline[b]
    bucket["sum_ms"] += elapsed_ms
    bucket["count"] += 1
    if elapsed_ms > bucket["max_ms"]:
        bucket["max_ms"] = elapsed_ms


# Reasons that bypass detection but are still recorded — not counted as blocked.
_PASSTHROUGH_REASONS: frozenset = frozenset({
    "authorized-robot",
    "bypass-path",         # BYPASS_PATHS prefix match — allowed, no detection
    "operator-passthrough",# BOT_DETECTION_ENABLED=false vhost — allowed, no detection
    "admin-passthrough",   # admin IP + valid session on upstream path — skip scoring
    "operator-allowed",    # 1.8.15 — operator unban grace window; detection bypassed
    "operator-self",       # 1.8.10 — operator's own lapsed-session XHR noise on
                           # admin paths; decoyed but benign, not a block.
                           # (admin-probe = anonymous recon stays OUT → counted.)
})


def _timeline_bump(reason: str, missed: bool = False, path: str = ""):
    """Update the current minute bucket.  Caller must hold state_lock.
    `missed` = allowed AND identity score >= SOFT_CHALLENGE_SCORE (medium band).
    `path`   = request path, used to count gwmgmt (admin-namespace) hits."""
    from collections import defaultdict
    b = _bucket_now()
    if b not in timeline:
        timeline[b] = {"total": 0, "blocked": 0, "allowed": 0, "missed": 0,
                       "gwmgmt": 0, "challenged": 0, "by_reason": defaultdict(int)}
        # 1.8.14 (perf) — timeline is an OrderedDict; evict the oldest entries
        # from the head until the head's key is within retention. Hot-path is
        # called per request; the cleanup runs once per minute roll, but the
        # old list-comprehension scan was O(N) over the full bucket count.
        cutoff = b - TIMELINE_RETAIN_SECS
        while timeline:
            _oldest = next(iter(timeline))
            if _oldest >= cutoff:
                break
            del timeline[_oldest]
    bucket = timeline[b]
    # Backfill fields on buckets restored from older snapshots that lacked them
    if "missed"      not in bucket: bucket["missed"]      = 0
    if "gwmgmt"      not in bucket: bucket["gwmgmt"]      = 0
    if "challenged"  not in bucket: bucket["challenged"]  = 0
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
                 signals: list = None, score: float = 0.0,
                 method: str = ""):
    """Record one request decision into global metrics + per-identity state +
    event log + DB.
    track_key (identity) is the primary key.  ip is stored on IpState for
    display only.
    `ja4` (R0): TLS handshake fingerprint observed by the trusted upstream
    terminator — surfaced in the event log so the operator can see what
    fingerprints bots are using and populate JA4_DENY_LIST from telemetry.
    """
    from scoring import _decay_risk  # avoid circular at module level
    # 1.8.15 perf — cache vhost lookup once instead of 3 ContextVar reads.
    _vhost = current_vhost_host()
    # Snapshots populated inside the lock; json.dumps + db_queue.put_nowait
    # happen AFTER releasing the lock so concurrent requests aren't blocked
    # on serialisation work. (Profile pre-fix: ~2.5ms/req @ 50 rps held lock
    # during 5 json.dumps calls per recorded event.)
    _persist_payload = None
    _evt = None
    _req_cat = None
    async with state_lock:
        metrics["total_requests"] += 1
        metrics["by_status"][status] += 1
        _bump_capped(metrics["by_path"], path)
        if ja4:
            _bump_capped(metrics["by_ja4"], ja4[:64])
        # Default to ip if no track_key (back-compat for internal/probe paths)
        key = track_key or ip
        s = ip_state[key]
        # 1.5.4: classify "missed" — request was allowed but identity sits
        # in the medium-risk band (>= SOFT_CHALLENGE_SCORE, < RISK_BAN_THRESHOLD).
        # 1.8.15 perf — skip decay when score is 0 AND no per-reason history;
        # decay math is a no-op on zero and skipping saves ~2µs/req on clean traffic.
        if s.risk_score > 0 or s.risk_by_reason:
            _decay_risk(s, now())
        is_missed = (not reason) and SOFT_CHALLENGE_SCORE > 0 and \
                    SOFT_CHALLENGE_SCORE <= s.risk_score < RISK_BAN_THRESHOLD
        _timeline_bump(reason, missed=is_missed, path=path)
        s.last_seen = now()
        s.last_user_agent = ua[:120]
        s.last_path = path[:120]
        # 1.8.14 iter-22 — secure-review F-1: cap Host header at 120 chars
        # (matches last_path / last_user_agent). Attacker-supplied Host can
        # be up to aiohttp's max header size (~8 KiB); without this cap, an
        # 8 KiB Host header would persist into both ip_state (memory) and
        # the clients table (disk), and surface in the dashboard.
        s.last_vhost = (_vhost or "")[:120]
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
        # 1.8.15 perf — snapshot dict references for json.dumps OUTSIDE the lock.
        # Tuples + ints are immutable; only dicts/sets need copying.
        if db_queue is not None:
            event_ts = _t.time()
            banned_until_epoch = (
                event_ts + (s.banned_until - now()) if s.banned_until > now() else 0
            )
            b = _bucket_now()
            tb = timeline.get(b)
            _is_50th = (metrics["total_requests"] % 50 == 0)
            _persist_payload = {
                "event_ts":           event_ts,
                "ip":                 ip,
                "ua":                 ua[:200],
                "path":               path[:200],
                "method":             method,
                "status":             status,
                "reason":             reason or "",
                "track_key":          track_key or "",
                "sid":                sid or "",
                "fp":                 fp or "",
                "ja4":                ja4 or "",
                "request_id":         request_id or "",
                "vhost":              _vhost,
                "first_seen":         s.first_seen,
                "now":                now(),
                "request_count":      s.request_count,
                "allowed_count":      s.allowed_count,
                "blocked_count":      s.blocked_count,
                "banned_until_epoch": banned_until_epoch,
                "last_ua":            s.last_user_agent,
                "last_path":          s.last_path,
                "last_vhost":         s.last_vhost,  # 1.8.14 iter-21
                "blocks_by_reason":   dict(s.blocks_by_reason),   # snapshot
                "bucket_id":          b,
                "bucket":             dict(tb) if tb else None,
                "is_50th":            _is_50th,
                "by_reason_snap":     dict(metrics["by_reason"]) if _is_50th else None,
                "by_status_snap":     {str(k): v for k, v in metrics["by_status"].items()} if _is_50th else None,
                "by_path_snap":       dict(metrics["by_path"]) if _is_50th else None,
                "total_requests":     metrics["total_requests"]   if _is_50th else None,
                "metric_allowed":     metrics["allowed"]          if _is_50th else None,
                "metric_blocked":     metrics["blocked"]          if _is_50th else None,
            }
        _evt = {
            "ts": _t.time(),
            "ip": ip,
            "is_admin_ip": _is_admin_ip(ip or ""),
            "ua": ua[:80],
            "path": path[:80],
            "method": method,
            "status": status,
            "reason": reason or "OK",
            "ja4": ja4[:64] if ja4 else "",
            "rid": request_id[:32] if request_id else "",
            "score": round(float(score or 0.0), 1),
            "track_key": (track_key or ip or "")[:32],
            "vhost": _vhost,
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
        _bump_capped(by_path_by_cat[_req_cat], path)
    # ── End of locked region ───────────────────────────────────────────────
    # 1.8.15 perf — slog (stdout JSON write) + json.dumps + db_queue puts
    # ALL run with the lock released. None of them mutate ip_state / metrics /
    # timeline; db_queue.put_nowait is itself thread-safe (asyncio.Queue).
    # 1.4.6: structured log line per recorded request.
    slog("request",
         level="info" if not reason else "warn",
         rid=request_id, ip=ip, ja4=ja4 or "", ua=ua[:120],
         method=method, path=path[:200], status=status,
         reason=reason or "ok", track_key=(track_key or "")[:32],
         signals=signals or [], score=round(float(score or 0.0), 1))
    # Postgres mirror fire-and-forget (outside lock — was already off-loop).
    if _persist_payload is not None and DB_BACKEND == "postgres" and _postgres_available:
        try:
            p = _persist_payload
            asyncio.get_running_loop().run_in_executor(
                None, pg_insert_event,
                p["event_ts"], p["ip"], p["ua"], p["path"],
                p["status"], p["reason"],
                p["track_key"], p["sid"], p["fp"],
                p["ja4"], p["request_id"], p["method"],
                p["vhost"])
        except Exception:
            pass
    # SQLite write-queue. json.dumps now runs OUTSIDE state_lock.
    if _persist_payload is not None and db_queue is not None:
        p = _persist_payload
        try:
            db_queue.put_nowait(("event",
                (p["event_ts"], p["ip"], p["ua"], p["path"], p["method"],
                 p["status"], p["reason"], p["vhost"])))
            db_queue.put_nowait(("upsert_client", (
                p["ip"],
                p["event_ts"] - (p["now"] - p["first_seen"]),
                p["event_ts"],
                p["request_count"], p["allowed_count"], p["blocked_count"],
                p["banned_until_epoch"],
                p["last_ua"], p["last_path"],
                p["last_vhost"],  # 1.8.14 iter-21 — persist for Domain col
                json.dumps(p["blocks_by_reason"]),
            )))
            if p["bucket"] is not None:
                tb = p["bucket"]
                db_queue.put_nowait(("upsert_timeline", (
                    p["bucket_id"], tb["total"], tb["allowed"], tb["blocked"],
                    tb.get("missed", 0),
                    json.dumps(dict(tb["by_reason"])),
                )))
            if p["is_50th"]:
                db_queue.put_nowait(("set_kv", ("total_requests", str(p["total_requests"]))))
                db_queue.put_nowait(("set_kv", ("allowed", str(p["metric_allowed"]))))
                db_queue.put_nowait(("set_kv", ("blocked", str(p["metric_blocked"]))))
                db_queue.put_nowait(("set_kv", ("by_reason", json.dumps(p["by_reason_snap"]))))
                db_queue.put_nowait(("set_kv", ("by_status", json.dumps(p["by_status_snap"]))))
                db_queue.put_nowait(("set_kv", ("by_path", json.dumps(p["by_path_snap"]))))
        except asyncio.QueueFull:
            pass  # drop on overload, not critical
