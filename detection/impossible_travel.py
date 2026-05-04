# detection/impossible_travel.py — 1.7.2
#
# impossible-travel: the same session is used from geographically implausible
# locations within IMPOSSIBLE_TRAVEL_WINDOW_SECS (default 30 min).
#
# Scoped to session-keyed identities (track_key.startswith("session:")) only.
# IP-keyed identities naturally change IPs (NAT, mobile, CDN) and would
# generate too many false positives. Session-keyed means the same signed
# admin/user session cookie appears from two different countries — a strong
# signal for session theft or bot infrastructure spanning multiple regions.
#
# Requires MaxMind City DB (_city_lookup must return a country code).
# Silently skips (returns False) when MaxMind is unavailable.

import time as _t

from config import IMPOSSIBLE_TRAVEL_ENABLED, IMPOSSIBLE_TRAVEL_WINDOW_SECS
from state import state_lock, ip_state


async def impossible_travel_check(track_key: str, ip: str) -> tuple[bool, str]:
    """Return (True, reason) when the session has moved countries too fast."""
    if not IMPOSSIBLE_TRAVEL_ENABLED:
        return False, ""

    # Only fire on session-keyed identities
    if not track_key.startswith("session:"):
        return False, ""

    try:
        from reputation.maxmind import _city_lookup, _city_reader
        if _city_reader is None:
            return False, ""
        result = _city_lookup(ip)
        if not result:
            return False, ""
        _lat, _lng, country, _city = result
        if not country:
            return False, ""
    except Exception:
        return False, ""

    now_ts = _t.time()
    async with state_lock:
        s = ip_state[track_key]
        last_c  = s.last_country
        last_ts = s.last_country_ts
        s.last_country    = country
        s.last_country_ts = now_ts

    if last_c and last_c != country:
        elapsed = now_ts - last_ts
        if 0 < elapsed < IMPOSSIBLE_TRAVEL_WINDOW_SECS:
            return True, f"impossible-travel: {last_c}→{country} in {int(elapsed)}s"

    return False, ""


__all__ = ["impossible_travel_check"]
