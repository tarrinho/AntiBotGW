"""
integrations/webhook.py — Webhook fan-out (operator awareness across N gateways).

Fires a signed HTTP POST to WEBHOOK_URL on ban/detection events.
Includes HMAC-SHA-256 signature in X-AppSecGW-Signature when WEBHOOK_SECRET
is set so the receiver can authenticate the gateway. Cross-instance dedup
via Redis SETNX when available. Best-effort: failures never block traffic.

1.8.6 — rewrote to use asyncio.Queue worker with exponential backoff and
circuit breaker instead of fire-and-forget to avoid silent delivery failures.

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

_http_session: "ClientSession | None" = None

def _get_session() -> ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = ClientSession()
    return _http_session

from config import *   # noqa: F401,F403
from helpers import slog

_WEBHOOK_QUEUE: asyncio.Queue = asyncio.Queue(maxsize=500)
_WEBHOOK_WORKER_TASK = None

_CB_FAILURES = 0
_CB_OPEN_UNTIL = 0.0
_CB_THRESHOLD = 5
_CB_RESET_SECS = 60.0


def _webhook_event_allowed(event: dict) -> bool:
    """1.6.2 — apply WEBHOOK_EVENT_FILTER."""
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


def _webhook_url_safe(url: str) -> bool:
    """Reject URLs that could SSRF to private/loopback addresses (CWE-918)."""
    from urllib.parse import urlparse
    import ipaddress
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname or ""
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except ValueError:
            pass  # hostname, not a bare IP — allowed
        return True
    except Exception:
        return False


async def _webhook_worker() -> None:
    """Background worker: dequeues events and POSTs with retry + circuit breaker."""
    global _CB_FAILURES, _CB_OPEN_UNTIL
    while True:
        try:
            event = await _WEBHOOK_QUEUE.get()
        except Exception:
            continue
        if not WEBHOOK_URL:
            _WEBHOOK_QUEUE.task_done()
            continue
        now = asyncio.get_event_loop().time()
        if _CB_OPEN_UNTIL > now:
            _WEBHOOK_QUEUE.task_done()
            continue
        delays = [0, 2, 4]
        success = False
        for attempt, delay in enumerate(delays):
            if delay > 0:
                await asyncio.sleep(delay)
            try:
                body = json.dumps(event, separators=(",", ":"),
                                  default=str, ensure_ascii=False).encode()
                headers = {"Content-Type": "application/json"}
                if WEBHOOK_SECRET:
                    headers["X-AppSecGW-Signature"] = hmac.new(
                        WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
                async with _get_session().post(
                        WEBHOOK_URL, data=body, headers=headers,
                        timeout=ClientTimeout(total=5)) as r:
                    await r.read()
                    if r.status < 500:
                        success = True
                        _CB_FAILURES = 0
                        break
            except Exception as e:
                slog("webhook_attempt_failed", level="warn", attempt=attempt,
                     url=WEBHOOK_URL, error=str(e)[:120])
        if not success:
            _CB_FAILURES += 1
            if _CB_FAILURES >= _CB_THRESHOLD:
                _CB_OPEN_UNTIL = asyncio.get_event_loop().time() + _CB_RESET_SECS
                slog("webhook_circuit_open", level="warn",
                     failures=_CB_FAILURES, reset_secs=_CB_RESET_SECS)
        _WEBHOOK_QUEUE.task_done()


async def _post_webhook(event: dict) -> None:
    """Enqueue event for fire-with-retry delivery. Non-blocking."""
    if not WEBHOOK_URL:
        return
    if not _webhook_url_safe(WEBHOOK_URL):
        slog("webhook_blocked_ssrf", level="warn", url=WEBHOOK_URL,
             reason="WEBHOOK_URL resolves to a private/loopback address — set a public endpoint")
        return
    if not _webhook_event_allowed(event):
        return
    from integrations.redis import _redis  # noqa
    if _redis is not None:
        try:
            dedup_key = (f"{REDIS_NS}:wh:{event.get('reason','')}:"
                         f"{event.get('track_key','')}")
            ok = await asyncio.wait_for(
                _redis.set(dedup_key, "1", ex=300, nx=True),
                timeout=REDIS_TIMEOUT)
            if not ok:
                return
        except Exception:
            pass
    try:
        _WEBHOOK_QUEUE.put_nowait(event)
    except asyncio.QueueFull:
        slog("webhook_queue_full", level="warn")


async def start_webhook_worker() -> None:
    """Start the background webhook worker. Call from on_startup()."""
    global _WEBHOOK_WORKER_TASK
    if _WEBHOOK_WORKER_TASK is None or _WEBHOOK_WORKER_TASK.done():
        _WEBHOOK_WORKER_TASK = asyncio.create_task(_webhook_worker())
