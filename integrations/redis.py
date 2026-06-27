"""
integrations/redis.py — Optional Redis-backed shared state across N instances.

When REDIS_URL is set, bans and canary tokens are shared so ALL gateway
instances see them (key insight for "every challenge behind its own
gateway" topology — a bot banned on challenge #3 is silent-decoyed on
every other challenge instantly). When REDIS_URL is empty, the gateway
stays purely in-process + SQLite (backward compatible, single-host).

Extracted from proxy.py as part of Phase 7 modular refactoring.

Depends on:
  config.py  — REDIS_URL, REDIS_NS, REDIS_TIMEOUT, REDIS_ALLOW_LIST, REDIS_REQUIRE_TLS
  helpers.py — slog

Security controls:
  • REDIS_REQUIRE_TLS (default true) — Redis is disabled (not fatal) at import time if
    REDIS_URL is not rediss://. Gateway continues in SQLite-only mode.
    Set REDIS_REQUIRE_TLS=false to allow plaintext redis:// (isolated dev only).
  • REDIS_ALLOW_LIST — gateway refuses to connect if resolved Redis host IP
    is not in the configured CIDR list. Empty = no restriction.
  • HMAC ban signing — ban values are signed using the Redis password so
    forged Redis entries are rejected at read time.
"""

import asyncio
import collections
import hashlib
import hmac as _hmac
import ipaddress
import socket
import time as _t
from urllib.parse import urlparse as _urlparse

from config import *   # noqa: F401,F403
from helpers import slog

# ── Module-level Redis singleton ──────────────────────────────────────────
_redis = None          # lazy-initialised singleton; None if disabled or unavailable
_redis_host_ip = None  # resolved IP of the Redis server (cached at connect time)

# M-6 — pending ban queue: bans that could not be written to Redis (transient
# failure) are buffered here and flushed by _redis_ban_flush_loop(). Bounded
# at 1000 entries so a prolonged Redis outage never inflates memory; the oldest
# entry is silently dropped when the deque is full (FIFO eviction).
_pending_redis_bans: collections.deque = collections.deque(maxlen=1000)

# INT4-04: enforce TLS for Redis connections (REDIS_REQUIRE_TLS=true by default).
# Plaintext redis:// with TLS enforcement active → Redis disabled, gateway continues
# in SQLite-only mode. Not fatal: Redis is optional shared-state, never a hard dep.
# Override with REDIS_REQUIRE_TLS=false to allow plaintext in isolated dev environments.
_REDIS_TLS_BLOCKED = False
if REDIS_URL and not REDIS_URL.startswith("rediss://"):
    if REDIS_REQUIRE_TLS:
        slog("redis_tls_required", level="error",
             msg="REDIS_URL uses plaintext redis:// but REDIS_REQUIRE_TLS=true — "
                 "Redis disabled. Use rediss:// or set REDIS_REQUIRE_TLS=false for local dev.")
        _REDIS_TLS_BLOCKED = True
    else:
        slog("redis_no_tls", level="warn",
             msg="REDIS_URL uses plaintext — use rediss:// in production (REDIS_REQUIRE_TLS=false set)")

# ── HMAC signing ───────────────────────────────────────────────────────────
# Derive signing key from the Redis password embedded in REDIS_URL.
# All instances that can connect to Redis share the same password, so no
# extra env var is needed. Empty password = no signing (logs a warning).
_REDIS_HMAC_KEY: bytes = b""
if REDIS_URL and not _REDIS_TLS_BLOCKED:
    _parsed_url = _urlparse(REDIS_URL)
    _pw = _parsed_url.password or ""
    if _pw:
        _REDIS_HMAC_KEY = _pw.encode()
    else:
        slog("redis_no_hmac_key", level="warn",
             msg="REDIS_URL has no password — ban-value HMAC signing disabled. "
                 "Set requirepass on Redis and include it in REDIS_URL.")


def _hmac_sign(value: str) -> str:
    """Append a 32-char (128-bit) HMAC-SHA256 signature to a ban value string."""
    if not _REDIS_HMAC_KEY:
        return value
    sig = _hmac.new(_REDIS_HMAC_KEY, value.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{value}|{sig}"


def _hmac_verify(raw: str) -> str | None:
    """Verify and strip the HMAC suffix. Returns the inner value, or None on failure."""
    if not _REDIS_HMAC_KEY:
        return raw  # signing not configured — accept as-is (backward compat)
    parts = raw.rsplit("|", 1)
    if len(parts) != 2:
        return None
    value, sig = parts
    # Accept both 32-char (current, 128-bit) and legacy 16-char (64-bit) signatures
    # so existing signed entries survive a rolling upgrade without a Redis flush.
    full = _hmac.new(_REDIS_HMAC_KEY, value.encode(), hashlib.sha256).hexdigest()
    expected = full[:len(sig)] if len(sig) in (16, 32) else full[:32]
    if len(sig) not in (16, 32):
        return None  # unexpected sig length — reject
    if _hmac.compare_digest(sig, expected):
        return value
    slog("redis_ban_hmac_mismatch", level="warn",
         msg="Ban entry failed HMAC verification — possible Redis tampering, entry rejected")
    return None


# ── Allowlist enforcement ──────────────────────────────────────────────────

def _get_current_allowlist() -> list:
    """Return the live REDIS_ALLOW_LIST (honours hot-reload via proxy_handler globals)."""
    import sys as _sys
    _ph = _sys.modules.get("core.proxy_handler")
    if _ph is not None and hasattr(_ph, "REDIS_ALLOW_LIST"):
        return getattr(_ph, "REDIS_ALLOW_LIST") or []
    return REDIS_ALLOW_LIST


def _resolve_redis_host_ip(url: str) -> str | None:
    """Synchronously resolve the Redis hostname → dotted-decimal IP string."""
    try:
        host = _urlparse(url).hostname or "localhost"
        return socket.gethostbyname(host)
    except Exception as e:
        slog("redis_host_resolve_failed", level="warn", error=str(e)[:80])
        return None


def _check_redis_allowed(host_ip: str | None) -> bool:
    """Return True if host_ip is within any CIDR in the current allowlist.
    Always returns True when the allowlist is empty (no restriction)."""
    nets = _get_current_allowlist()
    if not nets:
        return True
    if host_ip is None:
        return False
    try:
        addr = ipaddress.ip_address(host_ip)
        return any(addr in ipaddress.ip_network(n, strict=False) for n in nets)
    except Exception:
        return False


async def _shared_init():
    """Lazy-import redis.asyncio at startup if REDIS_URL is configured.
    Failures degrade to no-op (we never block traffic on a Redis outage)."""
    global _redis, _redis_host_ip
    if not REDIS_URL or _redis is not None or _REDIS_TLS_BLOCKED:
        return

    # ── Allowlist check ──────────────────────────────────────────────────
    resolved_ip = await asyncio.get_event_loop().run_in_executor(
        None, _resolve_redis_host_ip, REDIS_URL)
    _redis_host_ip = resolved_ip

    if not _check_redis_allowed(resolved_ip):
        slog("redis_blocked_by_allowlist", level="error",
             resolved_ip=resolved_ip,
             allowlist=_get_current_allowlist(),
             msg="Redis host IP not in REDIS_ALLOW_LIST — connection refused by gateway policy")
        return

    try:
        import redis.asyncio as _r
        client = _r.from_url(REDIS_URL, decode_responses=True,
                             socket_timeout=REDIS_TIMEOUT,
                             socket_connect_timeout=REDIS_TIMEOUT)
        await asyncio.wait_for(client.ping(), timeout=REDIS_TIMEOUT * 2)
        _redis = client
        slog("shared_store", level="info", backend="redis", url=REDIS_URL,
             namespace=REDIS_NS,
             allowlist_active=bool(_get_current_allowlist()),
             hmac_signing=bool(_REDIS_HMAC_KEY))
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
    """Write-through ban entry to Redis (best-effort; never raises).
    Ban value is HMAC-signed to detect tampering."""
    if _redis is None or not track_key:
        return
    if not _check_redis_allowed(_redis_host_ip):
        return
    ttl = max(1, int(until_epoch - _t.time()))
    raw_value = f"{int(until_epoch)}|{reason[:32]}"
    signed = _hmac_sign(raw_value)
    try:
        await asyncio.wait_for(
            _redis.set(f"{REDIS_NS}:ban:{track_key}", signed, ex=ttl),
            timeout=REDIS_TIMEOUT)
    except Exception as e:
        slog("shared_ban_set_failed", level="warn",
             track_key=track_key[:32], error=str(e)[:80])
        # M-6: queue for retry — _redis_ban_flush_loop will retry until Redis recovers.
        _pending_redis_bans.append((track_key, until_epoch, reason))
        slog("redis_ban_queued", level="info",
             track_key=track_key[:32], pending=len(_pending_redis_bans))


async def _shared_ban_get(track_key: str) -> float:
    """Read-through. Returns 0.0 if not banned, Redis unreachable, or HMAC invalid."""
    if _redis is None or not track_key:
        return 0.0
    if not _check_redis_allowed(_redis_host_ip):
        return 0.0
    try:
        raw = await asyncio.wait_for(
            _redis.get(f"{REDIS_NS}:ban:{track_key}"),
            timeout=REDIS_TIMEOUT)
        if not raw:
            return 0.0
        verified = _hmac_verify(raw)
        if verified is None:
            return 0.0
        return float(verified.split("|", 1)[0])
    except Exception:
        return 0.0


async def _redis_ban_flush_loop() -> None:
    """M-6 — Background coroutine: retry pending Redis bans after transient failures.

    Runs every 10 s when the queue is empty. When items are present, attempts to
    flush all of them in a single pass and backs off exponentially (up to 120 s)
    if Redis is still unreachable. Emits redis_ban_flushed / redis_ban_flush_failed
    structured logs so operators can track recovery.
    """
    _BASE_INTERVAL = 10.0
    _MAX_BACKOFF   = 120.0
    _backoff       = _BASE_INTERVAL
    while True:
        try:
            if not _pending_redis_bans:
                await asyncio.sleep(_BASE_INTERVAL)
                _backoff = _BASE_INTERVAL
                continue
            if _redis is None or not _check_redis_allowed(_redis_host_ip):
                await asyncio.sleep(_backoff)
                _backoff = min(_backoff * 2, _MAX_BACKOFF)
                continue
            n_pending = len(_pending_redis_bans)
            flushed = 0
            failed  = 0
            # Drain the deque in a single pass; on failure stop and back off.
            while _pending_redis_bans:
                entry = _pending_redis_bans[0]
                track_key, until_epoch, reason = entry
                ttl = max(1, int(until_epoch - _t.time()))
                if ttl <= 0:
                    _pending_redis_bans.popleft()
                    continue
                raw_value = f"{int(until_epoch)}|{reason[:32]}"
                signed = _hmac_sign(raw_value)
                try:
                    await asyncio.wait_for(
                        _redis.set(f"{REDIS_NS}:ban:{track_key}", signed, ex=ttl),
                        timeout=REDIS_TIMEOUT)
                    _pending_redis_bans.popleft()
                    flushed += 1
                except Exception as e:
                    slog("redis_ban_flush_failed", level="warn",
                         track_key=track_key[:32], error=str(e)[:80],
                         remaining=len(_pending_redis_bans))
                    failed += 1
                    break
            if flushed:
                slog("redis_ban_flushed", level="info",
                     flushed=flushed, failed=failed, was_pending=n_pending)
            if failed:
                _backoff = min(_backoff * 2, _MAX_BACKOFF)
                await asyncio.sleep(_backoff)
            else:
                _backoff = _BASE_INTERVAL
                await asyncio.sleep(_BASE_INTERVAL)
        except asyncio.CancelledError:
            break
        except Exception as e:
            slog("redis_flush_loop_error", level="error", error=str(e)[:120])
            await asyncio.sleep(_BASE_INTERVAL)
