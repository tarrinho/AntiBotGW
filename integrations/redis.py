"""
integrations/redis.py — Optional Redis-backed shared state across N instances.

When REDIS_URL is set, bans and canary tokens are shared so ALL gateway
instances see them (key insight for "every challenge behind its own
gateway" topology — a bot banned on challenge #3 is silent-decoyed on
every other challenge instantly). When REDIS_URL is empty, the gateway
stays purely in-process + SQLite (backward compatible, single-host).

Extracted from proxy.py as part of Phase 7 modular refactoring.

Depends on:
  config.py  — REDIS_URL, REDIS_NS, REDIS_TIMEOUT
  helpers.py — slog
"""

import asyncio
import time as _t

from config import *   # noqa: F401,F403
from helpers import slog

# ── Module-level Redis singleton ──────────────────────────────────────────
_redis = None  # lazy-initialised singleton; None if disabled or unavailable

# INT4-04: warn operators who forget to enable TLS for cross-host Redis traffic
if REDIS_URL and not REDIS_URL.startswith("rediss://"):
    slog("redis_no_tls", level="warn",
         msg="REDIS_URL uses plaintext — use rediss:// in production to protect credentials")


async def _shared_init():
    """Lazy-import redis.asyncio at startup if REDIS_URL is configured.
    Failures degrade to no-op (we never block traffic on a Redis outage)."""
    global _redis
    if not REDIS_URL or _redis is not None:
        return
    try:
        import redis.asyncio as _r
        client = _r.from_url(REDIS_URL, decode_responses=True,
                             socket_timeout=REDIS_TIMEOUT,
                             socket_connect_timeout=REDIS_TIMEOUT)
        await asyncio.wait_for(client.ping(), timeout=REDIS_TIMEOUT * 2)
        _redis = client
        slog("shared_store", level="info", backend="redis", url=REDIS_URL,
             namespace=REDIS_NS)
    except Exception as e:
        slog("shared_store_unavailable", level="warn",
             url=REDIS_URL, error=str(e)[:120])
        _redis = None
    # Propagate to modules that cached _redis=None via `from integrations.redis import _redis`.
    import sys as _sys
    for _m in list(_sys.modules.values()):
        if (_m is not None
                and hasattr(_m, '_redis')
                and getattr(_m, '_redis') is None
                and _redis is not None):
            try:
                setattr(_m, '_redis', _redis)
            except (AttributeError, TypeError):
                pass


async def _shared_ban_set(track_key: str, until_epoch: float, reason: str):
    """Write-through ban entry to Redis (best-effort; never raises)."""
    if _redis is None or not track_key:
        return
    ttl = max(1, int(until_epoch - _t.time()))
    try:
        await asyncio.wait_for(
            _redis.set(f"{REDIS_NS}:ban:{track_key}",
                       f"{int(until_epoch)}|{reason[:32]}", ex=ttl),
            timeout=REDIS_TIMEOUT)
    except Exception as e:
        slog("shared_ban_set_failed", level="warn",
             track_key=track_key[:32], error=str(e)[:80])


async def _shared_ban_get(track_key: str) -> float:
    """Read-through. Returns 0.0 if not banned or Redis unreachable."""
    if _redis is None or not track_key:
        return 0.0
    try:
        v = await asyncio.wait_for(
            _redis.get(f"{REDIS_NS}:ban:{track_key}"),
            timeout=REDIS_TIMEOUT)
        if not v:
            return 0.0
        return float(v.split("|", 1)[0])
    except Exception:
        return 0.0
