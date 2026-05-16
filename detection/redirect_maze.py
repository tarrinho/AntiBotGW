"""
detection/redirect_maze.py — P2: Risk-gated redirect maze (1.7.3).

For identities above REDIRECT_MAZE_THRESHOLD, serve a chain of signed
redirects before allowing through. Real browsers show human latency between
steps; automated agents complete all steps in milliseconds.

Token format: {step}.{ts_ms}.{hmac16}
  step   — current step index (0-based)
  ts_ms  — millisecond timestamp when this step was issued
  hmac16 — HMAC-SHA256(SESSION_KEY, "maze|identity|step|ts_ms|dest_hash16")[:16]
           dest_hash16 = SHA256(dest)[:16] — binds destination to prevent
           open-redirect within the trusted host (DET4-02).

Flow:
  1. Request arrives, identity has risk >= threshold → redirect to maze step 0
  2. Agent/browser follows redirect to /antibot-appsec-gateway/maze?t=TOKEN&d=DEST
  3. Gateway validates token, issues next step redirect (or final redirect to dest)
  4. After REDIRECT_MAZE_DEPTH steps, redirect to original dest
  5. If all steps completed in < REDIRECT_MAZE_MIN_MS total → bot signal
"""

import hashlib
import hmac
import time as _t
from collections import defaultdict
from urllib.parse import quote, unquote

from aiohttp import web

from config import (
    SESSION_KEY,
    REDIRECT_MAZE_ENABLED,
    REDIRECT_MAZE_DEPTH,
    REDIRECT_MAZE_MIN_MS,
    REDIRECT_MAZE_SCORE,
    ADMIN_NS,
)
from helpers import slog, get_ip

# identity → [(step, ts_ms), ...]  — tracks timing per maze run
_maze_timing: dict = defaultdict(list)
_MAZE_TOKEN_TTL_MS = 30_000  # token valid for 30 s
_MAZE_TIMING_MAX = 2048      # max identities tracked simultaneously
_MAZE_STEPS_MAX  = 32        # max recorded steps per identity (prevents replay amplification)


def _dest_hash(dest: str) -> str:
    """SHA-256 of the destination path — first 16 hex chars, bound into HMAC."""
    return hashlib.sha256(dest.encode()).hexdigest()[:16]


def _sign_maze_token(identity: str, step: int, ts_ms: int, dest: str) -> str:
    # DET4-02: bind dest to the token so the destination cannot be swapped
    # without invalidating the signature.
    msg = f"maze|{identity}|{step}|{ts_ms}|{_dest_hash(dest)}".encode()
    sig = hmac.new(SESSION_KEY, msg, hashlib.sha256).hexdigest()[:16]
    return f"{step}.{ts_ms}.{sig}"


def _verify_maze_token(token: str, identity: str, dest: str) -> tuple:
    """Returns (ok: bool, step: int, ts_ms: int)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False, 0, 0
        step, ts_ms, sig = int(parts[0]), int(parts[1]), parts[2]
    except (ValueError, IndexError):
        return False, 0, 0
    now_ms = int(_t.time() * 1000)
    if now_ms - ts_ms > _MAZE_TOKEN_TTL_MS or ts_ms > now_ms + 5000:
        return False, 0, 0
    full = _sign_maze_token(identity, step, ts_ms, dest)
    expected_sig = full.rsplit(".", 1)[-1]
    if not hmac.compare_digest(sig, expected_sig):
        return False, 0, 0
    return True, step, ts_ms


def should_maze(risk_score: float, has_maze_token: bool) -> bool:
    """True if this request should enter/continue the redirect maze."""
    return (REDIRECT_MAZE_ENABLED
            and risk_score >= REDIRECT_MAZE_THRESHOLD  # noqa: F821
            and not has_maze_token)


def make_maze_entry(identity: str, dest: str) -> str:
    """Return the URL for maze step 0."""
    ts_ms = int(_t.time() * 1000)
    token = _sign_maze_token(identity, 0, ts_ms, dest)
    safe_dest = quote(dest, safe="")
    return f"{ADMIN_NS}/maze?t={token}&d={safe_dest}"


async def redirect_maze_endpoint(request: web.Request):
    """Handle a maze step — validate token, issue next redirect or final dest."""
    from identity import get_identity
    identity, _sid, _fp, _is_new, _mode = get_identity(request)
    ip = get_ip(request)

    token = request.rel_url.query.get("t", "")
    dest  = unquote(request.rel_url.query.get("d", "/"))

    # Sanitise dest: must be a relative path on this host
    if not dest.startswith("/") or dest.startswith("//"):
        dest = "/"

    ok, step, ts_ms = _verify_maze_token(token, identity, dest)
    if not ok:
        # Invalid/expired token — restart maze
        slog("maze_bad_token", level="warn", ip=ip, identity=identity[:8])
        entry = make_maze_entry(identity, dest)
        return web.Response(status=302, headers={"Location": entry,
                                                  "Cache-Control": "no-store"})

    # Record step timing — cap per-identity list to prevent replay amplification
    steps_list = _maze_timing[identity]
    if len(steps_list) < _MAZE_STEPS_MAX:
        steps_list.append((step, ts_ms))
    # Evict oldest entries when global dict grows too large
    if len(_maze_timing) > _MAZE_TIMING_MAX:
        for _k in list(_maze_timing.keys())[:_MAZE_TIMING_MAX // 4]:
            _maze_timing.pop(_k, None)

    if step + 1 >= REDIRECT_MAZE_DEPTH:
        # Last step — check timing and redirect to dest
        await _evaluate_maze_timing(identity, ip)
        _maze_timing.pop(identity, None)
        return web.Response(status=302, headers={"Location": dest,
                                                  "Cache-Control": "no-store",
                                                  "X-Robots-Tag": "noindex"})

    # Issue next step
    next_ts = int(_t.time() * 1000)
    next_token = _sign_maze_token(identity, step + 1, next_ts, dest)
    safe_dest = quote(dest, safe="")
    next_url = f"{ADMIN_NS}/maze?t={next_token}&d={safe_dest}"
    return web.Response(status=302, headers={"Location": next_url,
                                              "Cache-Control": "no-store",
                                              "X-Robots-Tag": "noindex"})


async def _evaluate_maze_timing(identity: str, ip: str) -> None:
    steps = _maze_timing.get(identity, [])
    if len(steps) < REDIRECT_MAZE_DEPTH:
        return
    ts_values = [ts for _, ts in steps]
    total_ms = max(ts_values) - min(ts_values)
    if total_ms < REDIRECT_MAZE_MIN_MS:
        slog("maze_timing_bot", level="warn", ip=ip, identity=identity[:8],
             total_ms=total_ms, threshold_ms=REDIRECT_MAZE_MIN_MS,
             steps=len(steps))
        try:
            from scoring import update_risk_and_maybe_ban
            await update_risk_and_maybe_ban(identity, "redirect-maze-bot", ip)
        except Exception:
            pass


# import after config is loaded to avoid circular
from config import REDIRECT_MAZE_THRESHOLD  # noqa: E402

__all__ = [
    "should_maze", "make_maze_entry", "redirect_maze_endpoint",
]
