"""core/alerting.py — Background alerting task for threat_index and ban rate."""
import asyncio
import os
import time

ALERT_THREAT_INDEX_THRESHOLD = int(os.environ.get("ALERT_THREAT_INDEX", "80"))
ALERT_BAN_RATE_WINDOW_SEC    = int(os.environ.get("ALERT_BAN_RATE_WINDOW", "60"))
ALERT_BAN_RATE_THRESHOLD     = int(os.environ.get("ALERT_BAN_RATE_THRESHOLD", "50"))
ALERT_UPSTREAM_ERROR_RATE    = float(os.environ.get("ALERT_UPSTREAM_ERROR_RATE", "0.1"))
ALERT_COOLDOWN_SECS          = 300

_prev_alerted: dict = {}


def _compute_threat_index() -> float:
    from state import metrics
    total = metrics.get("total_requests", 0)
    blocked = metrics.get("blocked", 0)
    if not total:
        return 0.0
    return min(100.0, (blocked / total) * 100.0)


def _count_bans_in_window(window_secs: float) -> int:
    from state import events
    cutoff = time.time() - window_secs
    return sum(1 for e in events if e.get("reason") and e.get("ts", 0) >= cutoff
               and e.get("reason") not in ("allowed", "missed"))


async def _alerting_loop():
    """Runs every 30s, fires webhook on threshold breach."""
    from integrations.webhook import _post_webhook
    while True:
        await asyncio.sleep(30)
        now_t = time.time()
        try:
            ti = _compute_threat_index()
            if ti >= ALERT_THREAT_INDEX_THRESHOLD:
                if now_t - _prev_alerted.get("threat_index", 0) > ALERT_COOLDOWN_SECS:
                    await _post_webhook({
                        "event": "alert_threat_index",
                        "threat_index": round(ti, 1),
                        "threshold": ALERT_THREAT_INDEX_THRESHOLD,
                        "ts": now_t,
                    })
                    _prev_alerted["threat_index"] = now_t

            recent_bans = _count_bans_in_window(ALERT_BAN_RATE_WINDOW_SEC)
            if recent_bans >= ALERT_BAN_RATE_THRESHOLD:
                if now_t - _prev_alerted.get("ban_rate", 0) > ALERT_COOLDOWN_SECS:
                    await _post_webhook({
                        "event": "alert_ban_rate",
                        "bans_in_window": recent_bans,
                        "window_secs": ALERT_BAN_RATE_WINDOW_SEC,
                        "threshold": ALERT_BAN_RATE_THRESHOLD,
                        "ts": now_t,
                    })
                    _prev_alerted["ban_rate"] = now_t
        except Exception:
            pass  # never crash the alerting loop
