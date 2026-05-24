# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
reputation/abuseipdb.py — AbuseIPDB integration (free tier 1000 lookups/day).
Extracted from proxy.py as part of Phase 5 modular refactoring.

Looks up the source IP against AbuseIPDB's reputation DB. Result cached in
SQLite for ABUSEIPDB_CACHE_HOURS so a single bad IP doesn't burn the quota.
Score is fed into the risk model as `abuseipdb-high` / `abuseipdb-med`.
"""
from __future__ import annotations

import asyncio
import sqlite3
import time as _t
from collections import deque

import aiohttp
import ipaddress as _ipaddress
from aiohttp import ClientSession, ClientTimeout

# Shared session — avoids a new TCP handshake per AbuseIPDB API call.
_http_session: "ClientSession | None" = None

def _get_session() -> ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = ClientSession()
    return _http_session

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from helpers import slog, now


# ── Constants ──────────────────────────────────────────────────────────────

ABUSEIPDB_KEY            = __import__("os").environ.get("ABUSEIPDB_KEY", "").strip()
ABUSEIPDB_ENABLED        = bool(ABUSEIPDB_KEY)
ABUSEIPDB_HIGH_THRESHOLD = int(__import__("os").environ.get("ABUSEIPDB_HIGH_THRESHOLD", "80"))
ABUSEIPDB_MED_THRESHOLD  = int(__import__("os").environ.get("ABUSEIPDB_MED_THRESHOLD",  "40"))
ABUSEIPDB_CACHE_HOURS    = int(__import__("os").environ.get("ABUSEIPDB_CACHE_HOURS",    "6"))
ABUSEIPDB_TIMEOUT_S      = float(__import__("os").environ.get("ABUSEIPDB_TIMEOUT_S", "3.0"))
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# ── Telemetry — exposed via /__external ────────────────────────────────────

_abuseipdb_stats = {
    "lookups_total": 0,
    "lookups_cached": 0,
    "lookups_api": 0,
    "errors": 0,
    "rate_limited": 0,        # 429 from AbuseIPDB
    "last_error": "",
    "last_latency_ms": 0.0,
    "avg_latency_ms": 0.0,
    "p99_latency_ms": 0.0,
}
_abuseipdb_recent_latencies: deque = deque(maxlen=200)


async def _abuseipdb_lookup(ip: str):
    """Returns (score:int 0-100, country:str, source:str). source ∈
    ('cache','api','disabled','error'). Never raises — failures degrade
    gracefully so a downed AbuseIPDB never breaks the gateway."""
    if not ABUSEIPDB_ENABLED:
        return 0, "", "disabled"
    # Skip private / loopback / docker bridge lookups
    try:
        ipa = _ipaddress.ip_address(ip)
        if ipa.is_private or ipa.is_loopback or ipa.is_link_local:
            return 0, "", "private"
    except (ValueError, TypeError):
        return 0, "", "invalid"
    _abuseipdb_stats["lookups_total"] += 1
    n = _t.time()
    # Cache check — run in executor so sqlite3 does not block the event loop
    def _cache_lookup():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(
                "SELECT score, country, ts FROM abuseipdb_cache WHERE ip = ?",
                (ip,)).fetchone()
        finally:
            conn.close()
    try:
        row = await asyncio.get_event_loop().run_in_executor(None, _cache_lookup)
        if row and (n - (row["ts"] or 0)) < ABUSEIPDB_CACHE_HOURS * 3600:
            _abuseipdb_stats["lookups_cached"] += 1
            return int(row["score"] or 0), row["country"] or "", "cache"
    except Exception as e:
        _abuseipdb_stats["errors"] += 1
        _abuseipdb_stats["last_error"] = f"cache: {e}"[:200]
    # API call — reuse shared session to avoid per-call TCP handshake
    t0 = _t.time()
    try:
        timeout = ClientTimeout(total=ABUSEIPDB_TIMEOUT_S)
        session = _get_session()
        async with session.get(
                ABUSEIPDB_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_KEY,
                          "Accept": "application/json"},
                timeout=timeout) as resp:
            if resp.status == 429:
                _abuseipdb_stats["rate_limited"] += 1
                _abuseipdb_stats["last_error"] = "API quota exceeded"
                return 0, "", "rate-limited"
            if resp.status != 200:
                _abuseipdb_stats["errors"] += 1
                _abuseipdb_stats["last_error"] = f"HTTP {resp.status}"
                return 0, "", "error"
            data = await resp.json()
        score   = int((data.get("data") or {}).get("abuseConfidenceScore") or 0)
        country = ((data.get("data") or {}).get("countryCode") or "")[:8]
    except (asyncio.TimeoutError, aiohttp.ClientError, ValueError) as e:
        _abuseipdb_stats["errors"] += 1
        _abuseipdb_stats["last_error"] = f"api: {type(e).__name__}: {str(e)[:120]}"
        return 0, "", "error"
    finally:
        latency_ms = (_t.time() - t0) * 1000.0
        _abuseipdb_stats["last_latency_ms"] = round(latency_ms, 1)
        _abuseipdb_recent_latencies.append(latency_ms)
        if _abuseipdb_recent_latencies:
            _abuseipdb_stats["avg_latency_ms"] = round(
                sum(_abuseipdb_recent_latencies) / len(_abuseipdb_recent_latencies), 1)
            _s = sorted(_abuseipdb_recent_latencies)
            p99 = _s[max(0, int(len(_s) * 0.99) - 1)]
            _abuseipdb_stats["p99_latency_ms"] = round(p99, 1)
    _abuseipdb_stats["lookups_api"] += 1
    # Persist via DB writer
    if db_queue is not None:
        try:
            db_queue.put_nowait(("abuseipdb_set", (ip, score, country, n)))
        except asyncio.QueueFull:
            pass
    return score, country, "api"
