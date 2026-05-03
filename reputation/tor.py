"""
reputation/tor.py — Tor exit-node feed + DC/VPN block flag.
Extracted from proxy.py as part of Phase 5 modular refactoring.

Tor exit list: https://check.torproject.org/torbulkexitlist (one IP per line)
Refreshed once per week. In-memory set keeps the membership check at O(1).
"""
from __future__ import annotations

import asyncio
import os
import time as _t

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from helpers import slog, now


# ── Constants ──────────────────────────────────────────────────────────────

TOR_BLOCK_ENABLED = os.environ.get("TOR_BLOCK_ENABLED", "0") in ("1", "true", "yes")
TOR_FEED_URL = os.environ.get(
    "TOR_FEED_URL", "https://check.torproject.org/torbulkexitlist")
TOR_REFRESH_SECS = int(os.environ.get("TOR_REFRESH_SECS", str(7 * 86400)))

# DC / commercial-VPN check is layered on top of the existing GeoLite2-ASN
# `is_hosting` flag. When DC_VPN_BLOCK_ENABLED is true a hosting-ASN hit
# triggers the heavier `datacenter-vpn` reason (weight 25) in addition to
# `asn-hosting` (weight 5).
DC_VPN_BLOCK_ENABLED = os.environ.get("DC_VPN_BLOCK_ENABLED", "0") in ("1", "true", "yes")

# ── Mutable state ──────────────────────────────────────────────────────────

_tor_exits: set = set()
_tor_feed_stats = {
    "loaded_at": 0.0, "size": 0, "last_error": "", "fetches": 0,
}


# ── Fetch / refresh ────────────────────────────────────────────────────────

def _tor_fetch():
    """Pull the current Tor exit list. Synchronous — runs in executor."""
    import urllib.request, ssl
    if not TOR_FEED_URL.startswith(("https://", "http://")):
        return
    ctx = ssl.create_default_context()
    req = urllib.request.Request(TOR_FEED_URL, headers={
        "User-Agent": "AppSecGW/1.6.7 (anti-bot-gw)"
    })
    new_set = set()
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as resp:  # nosec B310 — fixed https URL
            for line in resp.read().decode("utf-8", "replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    new_set.add(line)
        _tor_exits.clear()
        _tor_exits.update(new_set)
        _tor_feed_stats["loaded_at"] = _t.time()
        _tor_feed_stats["size"] = len(_tor_exits)
        _tor_feed_stats["last_error"] = ""
        _tor_feed_stats["fetches"] += 1
        print(f"[tor] loaded {len(_tor_exits)} exit nodes from {TOR_FEED_URL}",
              flush=True)
    except Exception as e:
        _tor_feed_stats["last_error"] = f"{type(e).__name__}: {str(e)[:160]}"
        print(f"[tor] fetch failed: {_tor_feed_stats['last_error']}",
              flush=True)


async def _tor_refresh_loop():
    """Background coroutine — refreshes the Tor exit list weekly."""
    while True:
        try:
            if TOR_BLOCK_ENABLED:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, _tor_fetch)
        except Exception as e:
            print(f"[tor] refresh loop error: {e}", flush=True)
        await asyncio.sleep(TOR_REFRESH_SECS)
