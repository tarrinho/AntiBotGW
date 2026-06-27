"""
scoring.py — Risk scoring, ban management, and signal-order helpers.
Extracted from proxy.py as part of Phase 5 modular refactoring.

Layer 2: depends on config, state, helpers, db (Layer 1).
"""
from __future__ import annotations

import asyncio
import contextvars
import sqlite3
import time as _t

from config import *   # noqa: F401,F403
from config import _HOSTILE_REASONS  # noqa: F401 — underscore not in import *
from config import REALLY_BAN_SECS   # noqa: F401 — hot-reload propagated via proxy __setattr__

# 1.8.14 M-1: per-vhost RISK_OVERRIDES. protect() reads the matched vhost's
# RISK_OVERRIDES dict (signal → weight) via vc() and stashes it here for the
# duration of the request; update_risk_and_maybe_ban() prefers an override
# weight over the global RISK_WEIGHTS one. Task-scoped, so concurrent requests
# on different vhosts never see each other's overrides. Default None = use
# the global weights unchanged.
_vhost_risk_ctx: contextvars.ContextVar = contextvars.ContextVar(
    "_vhost_risk_ctx", default=None)

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
    """Load per-gateway signal-order overrides into _signal_order_cache.
    Uses sqlite3.connect(DB_PATH) directly so the loader can be patched
    in tests via monkeypatch on the module-level `sqlite3` and `DB_PATH`."""
    global _signal_order_cache
    try:
        from admin.mesh import _gw_local_id
        gw_id = _gw_local_id()
    except Exception as exc:
        slog("signal_orders_load_failed", level="warn", error=str(exc))
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
    """Persist a single signal-order override to SQLite (and mirror to PG).
    Uses sqlite3.connect(DB_PATH) directly + psycopg.connect(POSTGRES_DSN)
    so the helper is fully monkeypatchable in tests."""
    global _signal_order_cache
    try:
        from admin.mesh import _gw_local_id
        gw_id = _gw_local_id()
    except Exception as exc:
        slog("signal_orders_save_failed", level="warn", error=str(exc))
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
    # Mirror to Postgres if available + configured. Loaded via
    # `db.postgres._postgres_load_module` so tests can swap it via
    # `monkeypatch.setitem(sys.modules, 'db.postgres', ...)`.
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
            pass  # nosec B110 — PG mirror best-effort; SQLite is authoritative


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
        # iter-11b: decay per-vhost accumulators in lockstep too.
        if getattr(state, "risk_by_vhost", None):
            for v in list(state.risk_by_vhost.keys()):
                state.risk_by_vhost[v] *= factor
                if state.risk_by_vhost[v] < 0.5:
                    del state.risk_by_vhost[v]
        if state.risk_score < 0.5:
            state.risk_score = 0.0
            if getattr(state, "risk_by_reason", None):
                state.risk_by_reason.clear()
    # iter-11b: per-vhost scores decay independently of the global score; a vhost
    # whose accumulator alone fell below noise is pruned even if other vhosts (or
    # the global score) are still hot.
    elif elapsed > 0 and getattr(state, "risk_by_vhost", None):
        factor = 0.5 ** (elapsed / RISK_DECAY_HALFLIFE_SECS)
        for v in list(state.risk_by_vhost.keys()):
            state.risk_by_vhost[v] *= factor
            if state.risk_by_vhost[v] < 0.5:
                del state.risk_by_vhost[v]
    state.last_risk_update = now_ts


# ── Ban primitives ─────────────────────────────────────────────────────────

async def is_banned(ip: str) -> tuple[bool, float]:
    """Fast local check first (zero-RTT for the hot path), Redis only when
    local says 'no'. The Redis check piggy-backs the operator's intent of
    sharing bans across instances."""
    # iter-11 — when BAN_SCOPE="vhost", an identity banned on the CURRENT vhost
    # is blocked here too. The global scalar ban still wins if set (a global
    # ban always applies); the per-vhost map only gates the matching hostname.
    _scope, _bvhost = _resolve_ban_scope()
    async with state_lock:
        s = ip_state[ip]
        n = now()
        if s.banned_until > n:
            return True, s.banned_until - n
        if _scope == "vhost" and _bvhost:
            _vu = s.banned_until_by_vhost.get(_bvhost, 0.0)
            if _vu > n:
                return True, _vu - n
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


def _resolve_ban_scope() -> tuple:
    """iter-11 — return (ban_scope, vhost) for the current request context.
    ban_scope ∈ {"global","vhost"} resolved via vc() so a per-vhost override
    wins over the global default; vhost is the current request's hostname.
    Falls back to ("global","") if the vhost module isn't importable (test
    harness / early boot) so the default behaviour is never broken."""
    try:
        from vhost import vc as _vc, current_vhost_host as _cvh
        return (_vc("BAN_SCOPE") or "global"), (_cvh() or "")
    except Exception:
        return "global", ""


async def ban(ip: str, secs: int = HONEYPOT_BAN_SECS, reason: str = "honeypot"):
    until = now() + secs
    # iter-11 — resolve ban blast-radius for the current request's vhost.
    # "vhost" → record the ban against (raw_ip, vhost) only; "global" (default)
    # → fleet-wide, unchanged. vc() reads the per-vhost override if present.
    _scope, _bvhost = _resolve_ban_scope()
    _vhost_scoped = (_scope == "vhost" and _bvhost)
    async with state_lock:
        if _vhost_scoped:
            ip_state[ip].banned_until_by_vhost[_bvhost] = until
        else:
            ip_state[ip].banned_until = until
        _raw_ip = ip_state[ip].last_ip or ip
    if db_queue is not None:
        if _vhost_scoped:
            try:
                db_queue.put_nowait(("ip_ban_vhost",
                    (_raw_ip, _bvhost, _t.time() + secs, reason, _t.time())))
            except asyncio.QueueFull:
                pass
        else:
            try:
                db_queue.put_nowait(("ban", (ip, _t.time() + secs, reason, _t.time())))
            except asyncio.QueueFull:
                pass
            if secs >= HOSTILE_BAN_SECS:
                try:
                    db_queue.put_nowait(("ip_ban", (_raw_ip, _t.time() + secs, reason, _t.time())))
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
    # Per-vhost override (1.8.14 M-1) wins over the global weight when present;
    # a 0 override deliberately suppresses the signal on that vhost.
    _overrides = _vhost_risk_ctx.get()
    weight = (_overrides.get(reason, RISK_WEIGHTS.get(reason, 0))
              if _overrides else RISK_WEIGHTS.get(reason, 0))
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
        # iter-11 — resolve blast-radius. For BAN_SCOPE="vhost" the "already
        # banned?" gate checks the per-vhost expiry for THIS vhost, so the
        # same identity can independently trip on different vhosts.
        _scope, _bvhost = _resolve_ban_scope()
        _vhost_scoped = (_scope == "vhost" and _bvhost)
        # iter-11b — TRUE isolation: under vhost scope the ban decision is driven
        # by the risk EARNED ON THIS VHOST, not the global score. Otherwise an
        # identity that built up risk on vhost A would be banned on vhost B the
        # moment it touches it (carry-over), defeating per-vhost isolation.
        if _vhost_scoped:
            s.risk_by_vhost[_bvhost] = s.risk_by_vhost.get(_bvhost, 0.0) + weight
            _eval_score = s.risk_by_vhost[_bvhost]
        else:
            _eval_score = s.risk_score
        _gate_open = (
            (s.banned_until_by_vhost.get(_bvhost, 0.0) <= n) if _vhost_scoped
            else (s.banned_until <= n))
        if _eval_score >= threshold and _gate_open:
            ban_secs = (REALLY_BAN_SECS  if reason in _REALLY_BAN_REASONS
                        else HOSTILE_BAN_SECS if reason in _HOSTILE_REASONS
                        else RISK_BAN_DURATION_SECS)
            if _vhost_scoped:
                s.banned_until_by_vhost[_bvhost] = n + ban_secs
            else:
                s.banned_until = n + ban_secs
            triggered = True
            ban_dur = ban_secs
        else:
            triggered = False
            ban_dur = 0
    if triggered and db_queue is not None:
        if _vhost_scoped:
            try:
                db_queue.put_nowait(("ip_ban_vhost",
                    (ip, _bvhost, _t.time() + ban_dur,
                     f"risk-score:{int(_eval_score)}:{reason}", _t.time())))
            except asyncio.QueueFull:
                pass
        else:
            try:
                db_queue.put_nowait(("ban",
                    (track_key, _t.time() + ban_dur,
                     f"risk-score:{int(s.risk_score)}:{reason}", _t.time())))
            except asyncio.QueueFull:
                pass
            if ban_dur >= HOSTILE_BAN_SECS:
                try:
                    db_queue.put_nowait(("ip_ban",
                        (ip, _t.time() + ban_dur,
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
