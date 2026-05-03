"""
integrations/webhook.py — Webhook fan-out (operator awareness across N gateways).

Fires a signed HTTP POST to WEBHOOK_URL on ban/detection events.
Includes HMAC-SHA-256 signature in X-AppSecGW-Signature when WEBHOOK_SECRET
is set so the receiver can authenticate the gateway. Cross-instance dedup
via Redis SETNX when available. Best-effort: failures never block traffic.

Extracted from proxy.py as part of Phase 7 modular refactoring.

Depends on:
  config.py  — WEBHOOK_URL, WEBHOOK_SECRET, WEBHOOK_EVENT_FILTER,
                REDIS_NS, REDIS_TIMEOUT
  integrations/redis.py — _redis (singleton, imported at call-time)
  helpers.py — slog
"""

import asyncio
import fnmatch as _fnmatch
import hashlib
import hmac
import json

from aiohttp import ClientSession, ClientTimeout

from config import *   # noqa: F401,F403
from helpers import slog


def _webhook_event_allowed(event: dict) -> bool:
    """1.6.2 — apply WEBHOOK_EVENT_FILTER. The list is matched against:
      • event['reason']  (typical for ban events)
      • event['event']   (typical for non-ban events like dlp_leak)
    fnmatch glob entries (`dlp-*`, `body-*`) match a whole family."""
    if not WEBHOOK_EVENT_FILTER:
        return True
    candidates = [str(event.get("reason", "")), str(event.get("event", ""))]
    for cand in candidates:
        if not cand:
            continue
        for filt in WEBHOOK_EVENT_FILTER:
            if "*" in filt or "?" in filt:
                if _fnmatch.fnmatchcase(cand, filt):
                    return True
            elif cand == filt:
                return True
    return False


async def _post_webhook(event: dict) -> None:
    """Fire-and-forget POST to the operator's webhook (Slack-/Discord-/
    PagerDuty-/custom-shaped consumer). Includes an HMAC-SHA-256 of the
    body in `X-AppSecGW-Signature` when WEBHOOK_SECRET is set so the
    receiver can authenticate the gateway. Best-effort: failures are
    logged but never block the request path."""
    if not WEBHOOK_URL:
        return
    # 1.6.2 — drop the event silently when the operator subscribed to a
    # narrower set of reasons. Done BEFORE Redis dedup so a filtered-out
    # event doesn't burn a dedup token.
    if not _webhook_event_allowed(event):
        return
    try:
        body = json.dumps(event, separators=(",", ":"),
                          default=str, ensure_ascii=False).encode()
    except Exception:
        return
    headers = {"Content-Type": "application/json"}
    if WEBHOOK_SECRET:
        headers["X-AppSecGW-Signature"] = hmac.new(
            WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    # Cross-instance dedup: the same ban observed from N gateways shouldn't
    # spam the channel N times. SETNX with a short TTL = first-instance-wins.
    # Late import: _redis lives in integrations.redis to avoid circular deps.
    from integrations.redis import _redis  # noqa
    if _redis is not None:
        try:
            dedup_key = (f"{REDIS_NS}:wh:{event.get('reason','')}:"
                         f"{event.get('track_key','')}")
            ok = await asyncio.wait_for(
                _redis.set(dedup_key, "1", ex=300, nx=True),
                timeout=REDIS_TIMEOUT)
            if not ok:
                return  # another instance already fired this webhook
        except Exception:
            pass
    try:
        async with ClientSession(
                timeout=ClientTimeout(total=5)) as session:
            async with session.post(WEBHOOK_URL, data=body,
                                     headers=headers) as r:
                await r.read()
    except Exception as e:
        slog("webhook_failed", level="warn", url=WEBHOOK_URL,
             error=str(e)[:120])
