# detection/behavioral.py — Phase 4 extraction
# behavioral_check() extracted from proxy.py (line 4051).
# Uses state.state_lock + state.ip_state, both from state.py.

from collections import defaultdict

from config import BEHAVIORAL_CHECK_ENABLED
from state import state_lock, ip_state


async def behavioral_check(ip: str) -> tuple[bool, str]:
    """M5: stronger bot timing detection. Three orthogonal tests; any one
    triggers. Tests look at the last 16 request intervals.

      1. Coefficient of variation σ/μ < 0.05  (near-deterministic spacing)
      2. Autocorrelation lag-1 > 0.85 (each interval mirrors the previous one;
         common with sleep-based bot loops including jittered ones)
      3. Same-bin majority: >70% of intervals fall in a single 50-ms bin
         (sleep loops with quantised jitter)
    """
    async with state_lock:
        s = ip_state[ip]
        N = 16
        if len(s.request_times) < N:
            return False, ""
        recent = list(s.request_times)[-N:]
        intervals = [recent[i+1] - recent[i] for i in range(len(recent) - 1)]
        if not intervals or any(iv <= 0 for iv in intervals):
            return False, ""
        mean_iv = sum(intervals) / len(intervals)
        if mean_iv > 5.0:
            # Slow human-paced clicks — don't bother analysing.
            return False, ""
        var = sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)
        std = var ** 0.5
        cov = std / mean_iv if mean_iv > 0 else 0
        # Lag-1 autocorrelation
        if var > 0:
            num = sum((intervals[i] - mean_iv) * (intervals[i+1] - mean_iv)
                      for i in range(len(intervals) - 1))
            den = var * len(intervals)
            r1 = num / den if den > 0 else 0
        else:
            r1 = 1.0
        # 50-ms bin majority
        bins = defaultdict(int)
        for iv in intervals:
            bins[int(iv * 1000) // 50] += 1
        max_bin_pct = max(bins.values()) / len(intervals)

        if cov < 0.05 and mean_iv < 2.0:
            return True, f"timing too regular (σ/μ={cov:.3f}, μ={mean_iv*1000:.1f}ms)"
        if r1 > 0.85 and mean_iv < 2.0:
            return True, f"autocorrelated intervals (r₁={r1:.2f})"
        if max_bin_pct > 0.70:
            return True, f"quantised intervals ({max_bin_pct*100:.0f}% in one 50ms bin)"
    return False, ""


__all__ = [
    "BEHAVIORAL_CHECK_ENABLED",
    "behavioral_check",
]
