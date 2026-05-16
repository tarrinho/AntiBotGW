"""
rate_limit.py — Token-bucket rate limiting + background prune loop.
Extracted from proxy.py as part of Phase 3 modular refactoring.

Dependency rule: imports from config, state, helpers only.
"""

import asyncio
import os as _os
import time as _time

from config import (
    RATE_LIMIT_BURST,
    RATE_LIMIT_REFILL,
)
from state import (
    ip_state,
    ip_buckets,
    ip_new_sessions,
    ip_to_identities,
    state_lock,
    metrics,
    by_path_by_cat,
    _canary_tokens,
    _fp_canvas_store,
    _ACTIVE_SESSIONS,
    _signal_order_cache,
    _asn_path_clusters,
    _TOTP_PENDING,
)
from helpers import slog, now
from vhost import vc as _vc_rl

# ── Socket-IP bucket constants ─────────────────────────────────────────────
# H4: socket-IP secondary bucket — runs BEFORE per-identity bucket so an
# attacker rotating UAs/cookies from the same source IP cannot multiply their
# rate by spawning new identities. Keyed strictly by request.remote (the
# kernel-observed peer IP), independent of any client-supplied header.

IP_BURST  = int(_os.environ.get("IP_BURST",  "30"))
IP_REFILL = float(_os.environ.get("IP_REFILL", "5.0"))

# ── Prune-loop constants ───────────────────────────────────────────────────

MAX_IDENTITIES     = int(_os.environ.get("MAX_IDENTITIES", "100000"))
PRUNE_IDLE_SECS    = int(_os.environ.get("PRUNE_IDLE_SECS", "86400"))   # 24 h
ENUM_THRESHOLD     = int(_os.environ.get("ENUM_THRESHOLD", "300"))      # >N unique paths → ai-enumeration
PRUNE_INTERVAL_SECS = 600  # run every 10 min


# ── Token-bucket: socket-IP ────────────────────────────────────────────────

async def take_socket_ip_token(socket_ip: str) -> tuple:
    """Atomic token-bucket per kernel-observed peer IP. Returns (allowed, retry_after).
    N6: no inline O(n) eviction — _prune_state_loop trims this dict periodically.
    Hard cap is enforced by REJECTING new IPs only when over 2× MAX_IDENTITIES
    (which means the prune cycle hasn't run yet under extreme flooding)."""
    async with state_lock:
        n = now()
        b = ip_buckets.get(socket_ip)
        if b is None:
            if len(ip_buckets) > MAX_IDENTITIES * 2:
                # Hard backpressure under extreme flood — block this new IP
                # rather than do O(n) eviction synchronously.
                return False, 1.0
            b = {"tokens": float(IP_BURST), "last": n}
            ip_buckets[socket_ip] = b
        elapsed = n - b["last"]
        b["tokens"] = min(IP_BURST, b["tokens"] + elapsed * IP_REFILL)
        b["last"] = n
        if b["tokens"] >= 1.0:
            b["tokens"] -= 1.0
            return True, 0.0
        retry = (1.0 - b["tokens"]) / IP_REFILL
        return False, retry


# ── Token-bucket: per-identity ─────────────────────────────────────────────

async def take_token(ip: str) -> tuple:
    """Returns (allowed, retry_after_secs, tokens_remaining)."""
    async with state_lock:
        s = ip_state[ip]
        n = now()
        elapsed = n - s.last_refill
        _rl_burst = _vc_rl('RATE_LIMIT_BURST')
        _rl_refill = _vc_rl('RATE_LIMIT_REFILL')
        s.tokens = min(_rl_burst, s.tokens + elapsed * _rl_refill)
        s.last_refill = n
        s.request_count += 1
        s.request_times.append(n)
        if s.tokens >= 1.0:
            s.tokens -= 1.0
            return True, 0.0, int(s.tokens)
        retry = (1.0 - s.tokens) / _rl_refill
        return False, retry, 0


# ── Background prune loop ──────────────────────────────────────────────────

async def _prune_state_loop():
    """Background coroutine: evict idle identities + cap total count.
    Defends against unbounded growth from XFF spoofing or UA rotation."""
    while True:
        try:
            await asyncio.sleep(PRUNE_INTERVAL_SECS)
            async with state_lock:
                n = now()
                # 1. Evict by idle time
                idle = [k for k, s in ip_state.items()
                        if s.banned_until <= n
                        and (n - s.last_seen) > PRUNE_IDLE_SECS]
                for k in idle:
                    _old_ip = ip_state[k].last_ip
                    if _old_ip:
                        ip_to_identities[_old_ip].discard(k)
                    del ip_state[k]
                # 2. Cap total count — drop oldest-last-seen first
                if len(ip_state) > MAX_IDENTITIES:
                    overflow = len(ip_state) - MAX_IDENTITIES
                    candidates = sorted(
                        ((k, s.last_seen) for k, s in ip_state.items()
                         if s.banned_until <= n),
                        key=lambda kv: kv[1],
                    )[:overflow]
                    for k, _ in candidates:
                        _old_ip = ip_state[k].last_ip
                        if _old_ip:
                            ip_to_identities[_old_ip].discard(k)
                        del ip_state[k]
                # 2b. Prune now-empty ip_to_identities buckets.
                _stale_ip_idx = [_ip for _ip, _s in ip_to_identities.items() if not _s]
                for _ip in _stale_ip_idx:
                    del ip_to_identities[_ip]
                # 3. Prune the per-IP new-session identity map
                stale_ips = [ip for ip, m in ip_new_sessions.items()
                             if not m or max(m.values()) < n - 3600]
                for ip in stale_ips:
                    del ip_new_sessions[ip]
                # 4. N7: prune the socket-IP token-bucket dict (idle > 1h).
                stale_buckets = [ip for ip, b in ip_buckets.items()
                                 if (n - b["last"]) > 3600]
                for ip in stale_buckets:
                    del ip_buckets[ip]
                # 4b. Hard cap on ip_buckets — trim oldest if still over.
                if len(ip_buckets) > MAX_IDENTITIES:
                    overflow = len(ip_buckets) - MAX_IDENTITIES
                    candidates = sorted(ip_buckets.items(),
                                        key=lambda kv: kv[1]["last"])[:overflow]
                    for k, _ in candidates:
                        del ip_buckets[k]
                # 4c. M4/M6: reset cookie_ghost_misses + clear unique_paths for
                # surviving non-banned identities idle > 1h (prevents indefinite
                # accumulation without a full eviction).
                for _s in ip_state.values():
                    if _s.banned_until <= n and (n - _s.last_seen) > 3600:
                        _s.cookie_ghost_misses = 0
                        _s.unique_paths.clear()
                # 5. Evict expired canary tokens (value IS the expiry epoch).
                expired_canary = [k for k, exp in list(_canary_tokens.items()) if exp < n]
                for k in expired_canary:
                    _canary_tokens.pop(k, None)
                # 6. Evict stale canvas fingerprints (older than 2h).
                stale_canvas = [k for k, v in list(_fp_canvas_store.items())
                                if v.get("ts", 0) < n - 7200]
                for k in stale_canvas:
                    _fp_canvas_store.pop(k, None)
                # 7. Cap by_path and by_ja4 — keep top 2500 by count.
                _BY_PATH_MAX = 5000
                if len(metrics["by_path"]) > _BY_PATH_MAX:
                    keep = sorted(metrics["by_path"].items(),
                                  key=lambda kv: kv[1], reverse=True)[:2500]
                    metrics["by_path"].clear()
                    metrics["by_path"].update(keep)
                if len(metrics.get("by_ja4", {})) > _BY_PATH_MAX:
                    keep = sorted(metrics["by_ja4"].items(),
                                  key=lambda kv: kv[1], reverse=True)[:2500]
                    metrics["by_ja4"].clear()
                    metrics["by_ja4"].update(keep)
                # 8. Cap per-category path counters (1000 each).
                _BY_CAT_MAX = 1000
                for _cat_dict in by_path_by_cat.values():
                    if len(_cat_dict) > _BY_CAT_MAX:
                        keep = sorted(_cat_dict.items(),
                                      key=lambda kv: kv[1], reverse=True)[:500]
                        _cat_dict.clear()
                        _cat_dict.update(keep)
                # 9. Prune expired CrowdSec cache entries + recount active_bans.
                try:
                    from reputation.crowdsec import _crowdsec_cache, _crowdsec_stats
                    _cs_now = _time.time()
                    _cs_expired = [_ip for _ip, (_, _exp) in list(_crowdsec_cache.items())
                                   if _exp < _cs_now]
                    for _ip in _cs_expired:
                        _crowdsec_cache.pop(_ip, None)
                    _crowdsec_stats["active_bans"] = sum(
                        1 for _v in _crowdsec_cache.values()
                        if _v[0] is not None and _v[1] > _cs_now)
                except ImportError:
                    pass
                # 10. H5: prune remaining unbounded dicts.
                # _ACTIVE_SESSIONS: username → last_seen_ts (wall clock from _t.time()).
                # Use _time.time() not n (which is monotonic) for the comparison.
                _AS_PRUNE_TTL = 43200  # 12 h — matches _SESSION_TTL in admin/users.py
                _wall_now = _time.time()
                _stale_as = [_u for _u, _ts in list(_ACTIVE_SESSIONS.items())
                             if _wall_now - _ts > _AS_PRUNE_TTL]
                for _u in _stale_as:
                    _ACTIVE_SESSIONS.pop(_u, None)
                # _signal_order_cache: signal → order int. Bounded by distinct DB
                # rows, but cap defensively so a signal-orders table explosion
                # cannot bloat memory indefinitely.
                if len(_signal_order_cache) > 2000:
                    _surplus = len(_signal_order_cache) - 1000
                    for _sk in list(_signal_order_cache)[:_surplus]:
                        _signal_order_cache.pop(_sk, None)
                # _asn_path_clusters: (asn, path_prefix, minute) → set.
                # proxy_handler prunes by size when >10 k; add time-based prune
                # here to expire clusters older than 10 minutes regardless of size.
                _now_min = int(_time.time() // 60)
                _stale_ck = [_ck for _ck in list(_asn_path_clusters)
                             if _ck[2] < _now_min - 10]
                for _ck in _stale_ck:
                    _asn_path_clusters.pop(_ck, None)
                # 11. _fp_session_creations: fingerprint → deque[timestamps].
                # Never pruned elsewhere; evict stale fingerprints (all timestamps
                # older than SESSION_CHURN_WINDOW_S) to prevent UA-rotating attackers
                # from inflating memory indefinitely.
                try:
                    from identity import _fp_session_creations, SESSION_CHURN_WINDOW_S
                    _fp_cutoff = _time.time() - SESSION_CHURN_WINDOW_S
                    _stale_fp = [_fp for _fp, _dq in list(_fp_session_creations.items())
                                 if not _dq or _dq[-1] < _fp_cutoff]
                    for _fp in _stale_fp:
                        _fp_session_creations.pop(_fp, None)
                except ImportError:
                    pass
                # 12. PROXY4-07: _PROBE_RL — ip → [window_start, count].
                # Entries are never evicted by the hot path; prune when the
                # window_start is older than the rate-limit window so stale IPs
                # do not accumulate indefinitely.
                try:
                    from core.proxy_handler import _PROBE_RL, PROBE_RL_WINDOW
                    _probe_cutoff = _time.time() - PROBE_RL_WINDOW
                    _stale_probe = [_ip for _ip, _e in list(_PROBE_RL.items())
                                    if not _e or _e[0] < _probe_cutoff]
                    for _ip in _stale_probe:
                        _PROBE_RL.pop(_ip, None)
                except ImportError:
                    pass
                # 13. PROXY4-10: _TOTP_PENDING — username → {ts, step/secret, …}.
                # Scratch dict for the TOTP login / provisioning flow; prune entries
                # older than 10 minutes to prevent unbounded growth from abandoned flows.
                _totp_cutoff = _time.time() - 600
                _stale_totp = [_u for _u, _p in list(_TOTP_PENDING.items())
                               if isinstance(_p, dict) and _p.get("ts", 0) < _totp_cutoff]
                for _u in _stale_totp:
                    _TOTP_PENDING.pop(_u, None)
        except asyncio.CancelledError:
            break
        except Exception as e:
            slog("prune_loop_error", level="error", error=str(e))
