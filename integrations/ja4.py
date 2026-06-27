"""
integrations/ja4.py — JA4 TLS fingerprint deny-list + auto-deny logic.

Canonical home for all JA4-related helpers. challenge/js_challenge.py
imports _request_ja4, _ja4_hash, and _ja4_peer_trusted from here instead
of maintaining its own copies.

Features:
  • Static deny-list (JA4_DENY_LIST env var)
  • Trusted-peer pinning (JA4_TRUSTED_PEERS env var)
  • Auto-deny: fingerprints seen on >= JA4_AUTODENY_THRESHOLD distinct
    ban events within JA4_AUTODENY_WINDOW_S are added to the live set
    (and synced to Redis so every instance picks it up).
  • Refresh loop: merges the shared Redis ja4-denylist every 30 s.

Extracted from proxy.py as part of Phase 7 modular refactoring.

Depends on:
  config.py  — SESSION_KEY, JA4_HEADER, JA4_DENY_LIST, JA4_TRUSTED_NETS,
                JA4_AUTODENY_THRESHOLD, JA4_AUTODENY_WINDOW_S,
                REDIS_NS, REDIS_TIMEOUT
  integrations/redis.py — _redis (singleton)
  helpers.py — slog
"""

import asyncio
import hashlib
import hmac
import time as _t

from config import *   # noqa: F401,F403
from helpers import slog

# ── Local ban-count fallback (used when Redis is unavailable) ─────────────
_JA4_BAN_COUNTS: dict = {}  # ja4 → [timestamp, ...]


async def _observe_ja4_ban(ja4: str) -> None:
    """Track a ban event against a JA4 fingerprint. When the same fingerprint
    accumulates >= JA4_AUTODENY_THRESHOLD bans within the window, add it to
    the live deny-list (and to the shared Redis set for cross-instance sync)."""
    if not ja4:
        return
    from integrations.redis import _redis  # noqa — late to avoid circular
    if _redis is not None:
        try:
            key = f"{REDIS_NS}:ja4-bans:{ja4}"
            n = await asyncio.wait_for(_redis.incr(key),
                                        timeout=REDIS_TIMEOUT)
            await asyncio.wait_for(_redis.expire(key, JA4_AUTODENY_WINDOW_S),
                                    timeout=REDIS_TIMEOUT)
            if int(n) >= JA4_AUTODENY_THRESHOLD:
                # Use a sorted set (score = epoch) so entries age out automatically.
                # The refresh loop prunes entries older than JA4_AUTODENY_WINDOW_S.
                await asyncio.wait_for(
                    _redis.zadd(f"{REDIS_NS}:ja4-denylist", {ja4: _t.time()}),
                    timeout=REDIS_TIMEOUT)
                if ja4 not in JA4_DENY_LIST:
                    JA4_DENY_LIST.add(ja4)
                    slog("ja4_auto_denied", level="warn", ja4=ja4,
                         observed_bans=int(n))
        except Exception as e:
            slog("ja4_observe_failed", level="warn", ja4=ja4,
                 error=str(e)[:80])
        return
    # Single-instance fallback: count locally with sliding window pruning.
    now_ts = _t.time()
    bucket = _JA4_BAN_COUNTS.setdefault(ja4, [])
    bucket.append(now_ts)
    bucket[:] = [ts for ts in bucket if ts > now_ts - JA4_AUTODENY_WINDOW_S]
    if len(bucket) >= JA4_AUTODENY_THRESHOLD and ja4 not in JA4_DENY_LIST:
        JA4_DENY_LIST.add(ja4)
        slog("ja4_auto_denied", level="warn", ja4=ja4,
             observed_bans=len(bucket), backend="local")


async def _refresh_ja4_denylist_loop():
    """Pull the shared JA4_DENY_LIST from Redis every 30 s and merge into
    the local set. Lets a JA4 banned on instance A propagate to B/C/...
    within half a minute, and keeps any locally-added entries."""
    from integrations.redis import _redis  # noqa — late to avoid circular
    while True:
        try:
            await asyncio.sleep(30)
            if _redis is None:
                continue
            # Read live entries (score >= now - window) and prune expired ones.
            min_score = _t.time() - JA4_AUTODENY_WINDOW_S
            await asyncio.wait_for(
                _redis.zremrangebyscore(f"{REDIS_NS}:ja4-denylist", 0, min_score),
                timeout=REDIS_TIMEOUT)
            shared = await asyncio.wait_for(
                _redis.zrangebyscore(f"{REDIS_NS}:ja4-denylist", min_score, "+inf"),
                timeout=REDIS_TIMEOUT)
            new = {j for j in shared if j and j not in JA4_DENY_LIST}
            if new:
                JA4_DENY_LIST.update(new)
                slog("ja4_denylist_refreshed", level="info",
                     added=sorted(new))
        except asyncio.CancelledError:
            return
        except Exception:
            pass


def _ja4_peer_trusted(request) -> bool:
    """True if the kernel-observed peer IP may inject the JA4 header."""
    if not JA4_TRUSTED_NETS:
        return False  # no pinned nets — deny by default; set JA4_TRUSTED_NETS to enable
    import ipaddress as _ipaddress
    try:
        ip = _ipaddress.ip_address(request.remote or "")
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in JA4_TRUSTED_NETS)


def _request_ja4(request) -> str:
    """V9.2: return the JA4 fingerprint observed by the trusted TLS
    terminator for this request, or "" if absent / untrusted. Pure read
    of an upstream-injected header; the attacker can't fabricate it from
    a direct connection because JA4_TRUSTED_PEERS pins the source."""
    if not _ja4_peer_trusted(request):
        return ""
    return (request.headers.get(JA4_HEADER) or "").strip()


def _ja4_hash(ja4: str) -> str:
    """Opaque hash of the JA4 fingerprint for the cookie value (same
    pattern as `_tier_hash`). Empty input → empty output (no binding)."""
    if not ja4:
        return ""
    return hmac.new(SESSION_KEY, b"ja4|" + ja4.encode(),
                    hashlib.sha256).hexdigest()[:16]


def _tls_fingerprint_blocked(request) -> bool:
    """Apply the deny-list ONLY when the JA4 header arrives from a trusted
    peer (the TLS terminator). Untrusted sources are ignored so a direct
    attacker cannot bypass by forging a 'good' fingerprint."""
    if not JA4_DENY_LIST:
        return False
    if not _ja4_peer_trusted(request):
        return False
    fp = (request.headers.get(JA4_HEADER) or "").strip()
    return bool(fp) and fp in JA4_DENY_LIST
