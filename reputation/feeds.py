# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
reputation/feeds.py — Threat-intelligence feed auto-refresh (1.8.14).

Three lightweight, free, community-maintained blocklists fetched in the
background and kept in memory as IP sets for O(1) per-request lookup:

  • Feodo Tracker  (abuse.ch)  — botnet C2 IPs (recommended refresh: 1 h)
    https://feodotracker.abuse.ch/downloads/ipblocklist.txt

  • CINS Army                  — rogue / scan-origin IPs (refresh: 1 h)
    https://cinsscore.com/list/ci-badguys.txt

  • URLhaus        (abuse.ch)  — active malware-hosting IPs (refresh: 4 h)
    https://urlhaus.abuse.ch/downloads/text_online/

Each feed has an independent enable knob and refresh interval so operators
can turn them on selectively.  All three are **escalate-only** (checked only
after a previous signal has already raised suspicion) to keep false-positive
rates low.

Signal → RISK_WEIGHT mapping (in config.py):
  feodo-c2       : 60  (botnet C2 — strong signal)
  cins-rogue     : 30  (rogue/scan host — moderate, higher FP rate)
  urlhaus-malware: 45  (active malware host — high signal)
"""
from __future__ import annotations

import asyncio
import ipaddress as _ipa
import os
import time as _t
import urllib.request
import ssl

from helpers import slog

# ── Config knobs (env-configurable, hot-reload NOT supported — restart needed) ──

FEODO_ENABLED      = os.environ.get("FEODO_ENABLED",   "0") in ("1", "true", "yes")
CINS_ENABLED       = os.environ.get("CINS_ENABLED",    "0") in ("1", "true", "yes")
URLHAUS_ENABLED    = os.environ.get("URLHAUS_ENABLED", "0") in ("1", "true", "yes")

FEODO_REFRESH_SECS   = int(os.environ.get("FEODO_REFRESH_SECS",   str(3600)))
CINS_REFRESH_SECS    = int(os.environ.get("CINS_REFRESH_SECS",    str(3600)))
URLHAUS_REFRESH_SECS = int(os.environ.get("URLHAUS_REFRESH_SECS", str(4 * 3600)))

FEODO_URL   = os.environ.get(
    "FEODO_URL",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
CINS_URL    = os.environ.get(
    "CINS_URL",
    "https://cinsscore.com/list/ci-badguys.txt")
URLHAUS_URL = os.environ.get(
    "URLHAUS_URL",
    "https://urlhaus.abuse.ch/downloads/text_online/")

_FEED_UA = "AntiBotWaf_GW/1.8.14 (threat-intel-feed; +https://github.com/appsec-gw)"
_FETCH_TIMEOUT = 30

# ── Mutable state (in-process, no persistence needed — rebuilt on restart) ──

_feodo_ips:   set[str] = set()
_cins_ips:    set[str] = set()
_urlhaus_ips: set[str] = set()

_feodo_stats   = {"loaded_at": 0.0, "size": 0, "last_error": "", "fetches": 0}
_cins_stats    = {"loaded_at": 0.0, "size": 0, "last_error": "", "fetches": 0}
_urlhaus_stats = {"loaded_at": 0.0, "size": 0, "last_error": "", "fetches": 0}


# ── Generic fetch helpers ──────────────────────────────────────────────────────

def _ssl_ctx() -> ssl.SSLContext:
    return ssl.create_default_context()


def _fetch_ip_lines(url: str) -> set[str]:
    """Fetch a URL and return the set of IPv4/IPv6 address strings found,
    one per line, ignoring comment lines (# …) and blank lines."""
    req = urllib.request.Request(url, headers={"User-Agent": _FEED_UA})
    result: set[str] = set()
    with urllib.request.urlopen(  # nosec B310 — only https:// URLs used
            req, timeout=_FETCH_TIMEOUT, context=_ssl_ctx()) as resp:
        for raw in resp.read().decode("utf-8", "replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Some feeds include CIDR notation — take only the host part
            candidate = line.split("/")[0].strip()
            try:
                _ipa.ip_address(candidate)   # validate
                result.add(candidate)
            except ValueError:
                pass
    return result


def _update_stats(stats: dict, new_set: set[str]) -> None:
    stats["loaded_at"] = _t.time()
    stats["size"]      = len(new_set)
    stats["last_error"] = ""
    stats["fetches"]   += 1


# ── Per-feed fetch functions (synchronous — called in executor) ──────────────

def _feodo_fetch() -> None:
    global _feodo_ips
    try:
        new = _fetch_ip_lines(FEODO_URL)
        _feodo_ips = new
        _update_stats(_feodo_stats, new)
        slog("feodo_feed_loaded", level="info", count=len(new), url=FEODO_URL)
    except Exception as exc:
        _feodo_stats["last_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        slog("feodo_feed_failed", level="warn", error=_feodo_stats["last_error"])


def _cins_fetch() -> None:
    global _cins_ips
    try:
        new = _fetch_ip_lines(CINS_URL)
        _cins_ips = new
        _update_stats(_cins_stats, new)
        slog("cins_feed_loaded", level="info", count=len(new), url=CINS_URL)
    except Exception as exc:
        _cins_stats["last_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        slog("cins_feed_failed", level="warn", error=_cins_stats["last_error"])


def _urlhaus_fetch() -> None:
    global _urlhaus_ips
    try:
        new = _fetch_ip_lines(URLHAUS_URL)
        _urlhaus_ips = new
        _update_stats(_urlhaus_stats, new)
        slog("urlhaus_feed_loaded", level="info", count=len(new), url=URLHAUS_URL)
    except Exception as exc:
        _urlhaus_stats["last_error"] = f"{type(exc).__name__}: {str(exc)[:160]}"
        slog("urlhaus_feed_failed", level="warn", error=_urlhaus_stats["last_error"])


# ── Background refresh coroutines ─────────────────────────────────────────────

async def _feodo_refresh_loop() -> None:
    """Refresh the Feodo C2 blocklist every FEODO_REFRESH_SECS seconds."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            if FEODO_ENABLED:
                await loop.run_in_executor(None, _feodo_fetch)
        except Exception as exc:
            slog("feodo_loop_error", level="error", error=str(exc))
        await asyncio.sleep(FEODO_REFRESH_SECS)


async def _cins_refresh_loop() -> None:
    """Refresh the CINS rogue-IP list every CINS_REFRESH_SECS seconds."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            if CINS_ENABLED:
                await loop.run_in_executor(None, _cins_fetch)
        except Exception as exc:
            slog("cins_loop_error", level="error", error=str(exc))
        await asyncio.sleep(CINS_REFRESH_SECS)


async def _urlhaus_refresh_loop() -> None:
    """Refresh the URLhaus malware-hosting IP list every URLHAUS_REFRESH_SECS seconds."""
    loop = asyncio.get_running_loop()
    while True:
        try:
            if URLHAUS_ENABLED:
                await loop.run_in_executor(None, _urlhaus_fetch)
        except Exception as exc:
            slog("urlhaus_loop_error", level="error", error=str(exc))
        await asyncio.sleep(URLHAUS_REFRESH_SECS)


# ── Per-request lookup (O(1) set membership) ─────────────────────────────────

def feeds_check(ip: str) -> list[str]:
    """Return a list of triggered signal names for *ip*.

    Returns zero, one, or multiple signals depending on which feeds are
    enabled and which sets contain the IP.  An empty list means clean.

    Called from the per-request scoring path in proxy_handler.py.
    Private/loopback IPs are skipped immediately.
    """
    try:
        ipa = _ipa.ip_address(ip)
        if ipa.is_private or ipa.is_loopback or ipa.is_link_local:
            return []
    except ValueError:
        return []

    hits: list[str] = []
    if FEODO_ENABLED   and ip in _feodo_ips:
        hits.append("feodo-c2")
    if CINS_ENABLED    and ip in _cins_ips:
        hits.append("cins-rogue")
    if URLHAUS_ENABLED and ip in _urlhaus_ips:
        hits.append("urlhaus-malware")
    return hits


# ── Feed stats (exposed in /__metrics) ───────────────────────────────────────

def feeds_stats() -> dict:
    """Return a metrics dict for the /__metrics endpoint."""
    return {
        "feodo":   {**_feodo_stats,   "enabled": FEODO_ENABLED},
        "cins":    {**_cins_stats,    "enabled": CINS_ENABLED},
        "urlhaus": {**_urlhaus_stats, "enabled": URLHAUS_ENABLED},
    }
