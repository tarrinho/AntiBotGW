"""
reputation/crowdsec.py — CrowdSec LAPI integration (open-source community blocklist).
Extracted from proxy.py as part of Phase 5 modular refactoring.

Polls the CrowdSec Local API per request to check whether the IP is on the
community-vetted ban list. Cached in-process for CROWDSEC_CACHE_SECS to
avoid hammering LAPI.
"""
from __future__ import annotations

import asyncio
import time as _t
from collections import deque

import aiohttp
import ipaddress as _ipaddress
from aiohttp import ClientSession, ClientTimeout

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from helpers import slog, now

import os

# ── Constants ──────────────────────────────────────────────────────────────

CROWDSEC_LAPI_URL  = os.environ.get("CROWDSEC_LAPI_URL", "").rstrip("/")
# Accept both CROWDSEC_API_KEY (our original name) and CROWDSEC_LAPI_KEY
# (the name CrowdSec's own docs use). Either works.
CROWDSEC_API_KEY   = (os.environ.get("CROWDSEC_API_KEY", "").strip()
                      or os.environ.get("CROWDSEC_LAPI_KEY", "").strip())
CROWDSEC_ENABLED   = bool(CROWDSEC_LAPI_URL and CROWDSEC_API_KEY)
CROWDSEC_CACHE_SECS = int(os.environ.get("CROWDSEC_CACHE_SECS", "60"))
CROWDSEC_TIMEOUT_S = float(os.environ.get("CROWDSEC_TIMEOUT_S", "1.0"))

# ── Telemetry ──────────────────────────────────────────────────────────────

_crowdsec_stats = {
    "lookups_total": 0, "lookups_cached": 0, "lookups_api": 0,
    "errors": 0, "last_error": "",
    "last_latency_ms": 0.0, "avg_latency_ms": 0.0, "p99_latency_ms": 0.0,
    "active_bans": 0,
}
_crowdsec_recent_latencies: deque = deque(maxlen=200)
_crowdsec_cache: dict = {}        # ip → (decision_type, expires_ts)


async def _crowdsec_check(ip: str):
    """Returns (decision:str|None, source:str). decision is the action
    type from CrowdSec ('ban', 'captcha', …) or None when clean.
    source ∈ ('cache','api','disabled','private','error')."""
    if not CROWDSEC_ENABLED:
        return None, "disabled"
    try:
        ipa = _ipaddress.ip_address(ip)
        if ipa.is_private or ipa.is_loopback or ipa.is_link_local:
            return None, "private"
    except (ValueError, TypeError):
        return None, "invalid"
    _crowdsec_stats["lookups_total"] += 1
    n = _t.time()
    cached = _crowdsec_cache.get(ip)
    if cached and cached[1] > n:
        _crowdsec_stats["lookups_cached"] += 1
        return cached[0], "cache"
    t0 = _t.time()
    try:
        timeout = ClientTimeout(total=CROWDSEC_TIMEOUT_S)
        async with ClientSession(timeout=timeout) as session:
            async with session.get(
                f"{CROWDSEC_LAPI_URL}/v1/decisions",
                params={"ip": ip},
                headers={"X-Api-Key": CROWDSEC_API_KEY,
                          "Accept": "application/json"}) as resp:
                if resp.status == 404 or resp.status == 200:
                    pass
                elif resp.status >= 500:
                    _crowdsec_stats["errors"] += 1
                    _crowdsec_stats["last_error"] = f"HTTP {resp.status}"
                    return None, "error"
                data = await resp.json()
        # data is None / [] / {} when no active decisions
        if not data or not isinstance(data, list):
            _crowdsec_cache[ip] = (None, n + CROWDSEC_CACHE_SECS)
            return None, "api"
        # take first decision (CrowdSec returns priority-sorted)
        first = data[0] if isinstance(data[0], dict) else {}
        decision_type = first.get("type", "ban")
        _crowdsec_cache[ip] = (decision_type, n + CROWDSEC_CACHE_SECS)
        return decision_type, "api"
    except (asyncio.TimeoutError, aiohttp.ClientError, ValueError) as e:
        _crowdsec_stats["errors"] += 1
        _crowdsec_stats["last_error"] = f"{type(e).__name__}: {str(e)[:120]}"
        return None, "error"
    finally:
        latency_ms = (_t.time() - t0) * 1000.0
        _crowdsec_stats["last_latency_ms"] = round(latency_ms, 1)
        _crowdsec_recent_latencies.append(latency_ms)
        if _crowdsec_recent_latencies:
            _crowdsec_stats["avg_latency_ms"] = round(
                sum(_crowdsec_recent_latencies) / len(_crowdsec_recent_latencies), 1)
            _s = sorted(_crowdsec_recent_latencies)
            _crowdsec_stats["p99_latency_ms"] = round(
                _s[max(0, int(len(_s) * 0.99) - 1)], 1)
        _crowdsec_stats["lookups_api"] += 1
        _crowdsec_stats["active_bans"] = sum(
            1 for v in _crowdsec_cache.values() if v[0] is not None and v[1] > _t.time())
