# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
scoring.py — Risk scoring, ban management, and signal-order helpers.
Extracted from proxy.py as part of Phase 5 modular refactoring.

Layer 2: depends on config, state, helpers, db (Layer 1).
"""
from __future__ import annotations

import asyncio
import sqlite3
import time as _t

from config import *   # noqa: F401,F403
from config import _HOSTILE_REASONS  # noqa: F401 — underscore not in import *
from config import REALLY_BAN_SECS   # noqa: F401 — hot-reload propagated via proxy __setattr__

# Signals that are definitive proof of an automated agent — earn REALLY_BAN_SECS.
# Subset of _HOSTILE_REASONS; other hostile reasons earn HOSTILE_BAN_SECS.
_REALLY_BAN_REASONS = {"canary-echo", "honeypot-silent", "honeypot"}

# Prevents fire-and-forget tasks from being GC'd before completion.
_background_tasks: set = set()

from state import *    # noqa: F401,F403
from state import _signal_order_cache  # explicit: underscore not exported by import *
from helpers import slog, now


# ── Signal-order helpers ────────────────────────────────────────────────────

def _signal_runtime_order(sig: str) -> int:
    """Effective activation order for `sig`: DB override → set defaults → 1."""
    o = _signal_order_cache.get(sig)
    if o:
        return o
    if sig in ESCALATE_ONLY_REASONS:
        return 3
    if sig in SECOND_ORDER_REASONS:
        return 2
    return 1


def _should_run_signal(sig: str, esc_score: float) -> bool:
    """Return True iff the signal's order gate is satisfied at `esc_score`."""
    o = _signal_runtime_order(sig)
    if o == 3:
        return (ESCALATION_THRESHOLD <= 0) or (esc_score >= ESCALATION_THRESHOLD)
    if o == 2:
        return (SECOND_ORDER_THRESHOLD <= 0) or (esc_score >= SECOND_ORDER_THRESHOLD)
    return True  # order 1 — always run


def _load_signal_order_cache() -> None:
    """Load per-gateway signal-order overrides from SQLite into _signal_order_cache."""
    global _signal_order_cache
    try:
        from admin.mesh import _gw_local_id
        gw_id = _gw_local_id()
    except Exception:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT signal, activation_order FROM signal_orders WHERE gw_id = ?",
            (gw_id,),
        ).fetchall()
        conn.close()
        _signal_order_cache.update({sig: n for sig, n in rows if n in (1, 2, 3)})
        if _signal_order_cache:
            slog("signal_orders_loaded", level="info",
                 count=len(_signal_order_cache), gw_id=gw_id)
    except Exception as exc:
        slog("signal_orders_load_failed", level="warn", error=str(exc))


def _save_signal_order(sig: str, order: int, actor: str) -> None:
    """Persist a single signal-order override to SQLite (and mirror to PG)."""
    global _signal_order_cache
    try:
        from admin.mesh import _gw_local_id
        gw_id = _gw_local_id()
    except Exception:
        return
    ts = _t.time()
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            """INSERT INTO signal_orders (gw_id, signal, activation_order, updated_ts, updated_by)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(gw_id, signal) DO UPDATE SET
                   activation_order = excluded.activation_order,
                   updated_ts       = excluded.updated_ts,
                   updated_by       = excluded.updated_by""",
            (gw_id, sig, order, ts, actor),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        slog("signal_orders_save_failed", level="warn", error=str(exc))
        return
    _signal_order_cache[sig] = order
    # Mirror to Postgres if available
    try:
        from db.postgres import _postgres_load_module
        pg = _postgres_load_module()
    except Exception:
        pg = None
    if pg and POSTGRES_DSN:
        try:
            with pg.connect(POSTGRES_DSN, connect_timeout=3, autocommit=True) as pgc:
                with pgc.cursor() as cur:
                    cur.execute(
                        """INSERT INTO signal_orders
                               (gw_id, signal, activation_order, updated_ts, updated_by)
                           VALUES (%s, %s, %s, %s, %s)
                           ON CONFLICT (gw_id, signal) DO UPDATE SET
                               activation_order = EXCLUDED.activation_order,
                               updated_ts       = EXCLUDED.updated_ts,
                               updated_by       = EXCLUDED.updated_by""",
                        (gw_id, sig, order, ts, actor),
                    )
        except Exception:
            pass  # nosec B110 — PG mirror is best-effort; SQLite is authoritative


# ── Escalation score helper ────────────────────────────────────────────────

def _escalation_score(track_key: str) -> float:
    """Return the current decayed risk_score for `track_key`, or 0 when no
    state exists. No lock — read of float is atomic in CPython."""
    s = ip_state.get(track_key)
    if s is None:
        return 0.0
    return float(s.risk_score or 0.0)


# ── Risk decay ─────────────────────────────────────────────────────────────

def _decay_risk(state, now_ts: float):
    """Apply exponential decay to risk_score based on elapsed time."""
    elapsed = max(0.0, now_ts - state.last_risk_update)
    if elapsed > 0 and state.risk_score > 0:
        factor = 0.5 ** (elapsed / RISK_DECAY_HALFLIFE_SECS)
        state.risk_score *= factor
        # Decay per-reason contributions in lockstep so the breakdown stays
        # proportional to the live score. Drop entries that fall below noise.
        if getattr(state, "risk_by_reason", None):
            for r in list(state.risk_by_reason.keys()):
                state.risk_by_reason[r] *= factor
                if state.risk_by_reason[r] < 0.5:
                    del state.risk_by_reason[r]
        if state.risk_score < 0.5:
            state.risk_score = 0.0
            if getattr(state, "risk_by_reason", None):
                state.risk_by_reason.clear()
    state.last_risk_update = now_ts


# ── Ban primitives ─────────────────────────────────────────────────────────

async def is_banned(ip: str) -> tuple[bool, float]:
    """Fast local check first (zero-RTT for the hot path), Redis only when
    local says 'no'. The Redis check piggy-backs the operator's intent of
    sharing bans across instances."""
    async with state_lock:
        s = ip_state[ip]
        n = now()
        if s.banned_until > n:
            return True, s.banned_until - n
    # Ask the shared store (Redis integration)
    try:
        from integrations.redis import _shared_ban_get
        until = await _shared_ban_get(ip)
    except Exception:
        until = 0.0
    if until > _t.time():
        remaining = until - _t.time()
        async with state_lock:
            ip_state[ip].banned_until = max(ip_state[ip].banned_until, now() + remaining)
        return True, remaining
    return False, 0.0


async def ban(ip: str, secs: int = HONEYPOT_BAN_SECS, reason: str = "honeypot"):
    until = now() + secs
    async with state_lock:
        ip_state[ip].banned_until = until
    if db_queue is not None:
        try:
            db_queue.put_nowait(("ban", (ip, _t.time() + secs, reason, _t.time())))
        except asyncio.QueueFull:
            pass
    # Propagate to shared store (best-effort, never blocks)
    try:
        from integrations.redis import _shared_ban_set
        await _shared_ban_set(ip, _t.time() + secs, reason)
    except Exception:
        pass  # nosec B110 — Redis integration is optional; ban is already recorded locally


# ── Core risk-score + ban function ────────────────────────────────────────

async def update_risk_and_maybe_ban(track_key: str, reason: str, ip: str) -> bool:
    """
    Add risk for this reason. Ban only if accumulated score crosses threshold,
    using a higher threshold when the IP appears to be a NAT (many identities).
    Returns True if a ban was applied.
    """
    weight = RISK_WEIGHTS.get(reason, 0)
    if weight == 0:
        return False
    async with state_lock:
        n = now()
        s = ip_state[track_key]
        _decay_risk(s, n)
        s.risk_score += weight
        s.risk_by_reason[reason] = s.risk_by_reason.get(reason, 0.0) + weight
        # Count only "legitimate-looking" identities at this IP toward NAT detection.
        # O(m) via inverted index instead of O(N) full ip_state scan.
        identities_at_ip = sum(
            1 for k in ip_to_identities.get(ip, ())
            if (st := ip_state.get(k)) is not None
            and st.last_ip == ip        # guard against stale index entries
            and (n - st.last_seen) < 3600
            and st.static_loads >= 1
            and st.allowed_count >= 3
        )
        threshold = (
            RISK_BAN_THRESHOLD_NAT if identities_at_ip >= NAT_IDENTITIES_THRESHOLD
            else RISK_BAN_THRESHOLD
        )
        if s.risk_score >= threshold and s.banned_until <= n:
            ban_secs = (REALLY_BAN_SECS  if reason in _REALLY_BAN_REASONS
                        else HOSTILE_BAN_SECS if reason in _HOSTILE_REASONS
                        else RISK_BAN_DURATION_SECS)
            s.banned_until = n + ban_secs
            triggered = True
            ban_dur = ban_secs
        else:
            triggered = False
            ban_dur = 0
    if triggered and db_queue is not None:
        try:
            db_queue.put_nowait(("ban",
                (track_key, _t.time() + ban_dur,
                 f"risk-score:{int(s.risk_score)}:{reason}", _t.time())))
        except asyncio.QueueFull:
            pass
    if triggered:
        # Propagate risk-driven bans to the shared store (cross-instance)
        try:
            from integrations.redis import _shared_ban_set
            from integrations.ja4 import _observe_ja4_ban
            from integrations.webhook import _post_webhook
            await _shared_ban_set(
                track_key, _t.time() + ban_dur,
                f"risk-score:{int(s.risk_score)}:{reason}")
            last_ja4 = (s.last_ja4 or "")
            if last_ja4:
                _t1 = asyncio.create_task(_observe_ja4_ban(last_ja4))
                _background_tasks.add(_t1)
                _t1.add_done_callback(_background_tasks.discard)
            if WEBHOOK_URL:
                _t2 = asyncio.create_task(_post_webhook({
                    "event":      "ban",
                    "ts":         int(_t.time()),
                    "reason":     reason,
                    "risk_score": int(s.risk_score),
                    "track_key":  track_key[:32],
                    "ip":         ip,
                    "ja4":        last_ja4,
                    "ua":         (s.last_user_agent or "")[:120],
                    "duration_s": ban_dur,
                    "hostile":    reason in _HOSTILE_REASONS,
                }))
                _background_tasks.add(_t2)
                _t2.add_done_callback(_background_tasks.discard)
        except Exception:
            pass  # nosec B110 — webhook dispatch is best-effort; ban was already applied
    return triggered
