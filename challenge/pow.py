"""
challenge/pow.py — Proof-of-Work challenge generation and verification.
Extracted from proxy.py as part of Phase 6 modular refactoring.

Depends on:
  config.py  — POW_DIFFICULTY, POW_VALID_SECS, POW_MIN_SOLVE_MS,
                POW_HMAC_KEY, POW_REQUIRED_PATHS, POW_REQUIRE_ALL_WRITES,
                ANUBIS_ENABLED, ANUBIS_DIFFICULTY_BOOST
  state.py   — _pow_seen (Dict[tuple, float])
"""

import hashlib
import hmac
import secrets
import time
from typing import Dict

from aiohttp import web

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from state import _pow_seen  # explicit: underscore not exported by import *


# ── PoW nonce bind helper ─────────────────────────────────────────────────

def _pow_bind(method: str, path: str) -> str:
    return f"{method.upper()}:{path}"


# _pow_seen is declared in state.py; the module-level constant below is kept
# here for co-location with the logic that uses it.
_POW_SEEN_MAX = 10000


# ── Challenge generation ──────────────────────────────────────────────────

def make_pow_challenge(method: str = "*", path: str = "*", risk_score: int = 0) -> str:
    nonce  = secrets.token_hex(8)
    issued = str(int(time.time()))
    bind = _pow_bind(method, path)
    # 1.6.10 — risk-score-scaled difficulty: higher accumulated risk → more work.
    # Anubis-mode (global strict gate) takes precedence over per-identity scaling.
    # 1.5.4 — base: Anubis-mode boost makes scripted solving ~16× harder per
    # additional zero (default boost=1 → 6 leading zeros instead of 5).
    if ANUBIS_ENABLED:
        diff = POW_DIFFICULTY + ANUBIS_DIFFICULTY_BOOST
    elif risk_score >= 50:
        diff = 9   # high risk  → 9 leading zeros
    elif risk_score >= 20:
        diff = 7   # medium risk → 7 leading zeros
    else:
        diff = max(POW_DIFFICULTY, 5)   # low risk → at least 5
    payload = f"{nonce}|{issued}|{diff}|{bind}"
    sig = hmac.new(POW_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


# ── Challenge verification ────────────────────────────────────────────────

def verify_pow(token: str, solution: str,
               method: str = "*", path: str = "*") -> tuple[bool, str]:
    if not token or not solution:
        return False, "missing token or solution"
    parts = token.split("|")
    if len(parts) == 5:
        nonce, issued, diff, bind, sig = parts
    elif len(parts) == 4:
        # Legacy challenge (no bind) — reject; the challenge MUST be bound.
        return False, "legacy unbound token; obtain a fresh challenge"
    else:
        return False, "malformed token"
    payload = f"{nonce}|{issued}|{diff}|{bind}"
    expected_sig = hmac.new(POW_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False, "bad signature"
    if not hmac.compare_digest(bind, _pow_bind(method, path)):
        return False, "token not bound to this method+path"
    now_float = time.time()
    age = int(now_float) - int(issued)
    if age > POW_VALID_SECS:
        return False, f"expired ({age}s old)"
    # 1.6.10 — minimum solve time: a pre-computed or replayed solution arrives
    # before any real CPU work could have completed. Clocks can drift ~1s so
    # we tolerate up to 1s slack below POW_MIN_SOLVE_MS.
    elapsed_ms = (now_float - float(issued)) * 1000
    if elapsed_ms < max(0.0, POW_MIN_SOLVE_MS - 1000):
        return False, f"solved too quickly ({elapsed_ms:.0f} ms < {POW_MIN_SOLVE_MS} ms minimum)"
    try:
        diff_int = int(diff)
    except ValueError:
        return False, "bad difficulty"
    h = hashlib.sha256(f"{nonce}{solution}".encode()).hexdigest()
    if not h.startswith("0" * diff_int):
        return False, f"hash {h[:8]} does not start with {diff_int} zeros"
    # Replay protection: each (token, solution) usable exactly once within
    # the validity window. Lazy prune of expired pairs.
    now_ts = time.time()
    if len(_pow_seen) > _POW_SEEN_MAX:
        for k in [k for k, exp in _pow_seen.items() if exp < now_ts]:
            _pow_seen.pop(k, None)
        if len(_pow_seen) > _POW_SEEN_MAX:
            # Hard cap: drop oldest half — replay protection degrades but
            # memory stays bounded. (Should never happen at sane volumes.)
            for k in list(_pow_seen.keys())[:len(_pow_seen)//2]:
                _pow_seen.pop(k, None)
    pair_key = (token, solution)
    if pair_key in _pow_seen:
        return False, "solution already used (replay)"
    _pow_seen[pair_key] = now_ts + POW_VALID_SECS
    return True, "ok"


# ── Gate check ────────────────────────────────────────────────────────────

def needs_pow(request: web.Request) -> bool:
    if POW_REQUIRE_ALL_WRITES and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    return any(request.path.startswith(p) for p in POW_REQUIRED_PATHS)
