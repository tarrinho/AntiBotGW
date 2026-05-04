# detection/path_sweep.py — 1.7.3
#
# Post-challenge path-sweep detector.
# Fires when a post-challenge identity (valid cookie) visits too many distinct
# non-static paths in a rolling time window — the hallmark of automated
# content-discovery / directory enumeration after warm-up bypass.
#
# Unlike behavioral.py (which is skipped for cookied sessions), this detector
# runs for ALL identities including session-cookied ones — specifically because
# the warm-up bypass technique first acquires a valid cookie then sweeps paths.

import time as _t

from config import PATH_SWEEP_WINDOW_SECS, PATH_SWEEP_THRESHOLD
from state import ip_state, state_lock

_STATIC_EXTS = frozenset({
    ".css", ".js", ".mjs", ".ts", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".webm", ".mp3", ".ogg",
    ".pdf", ".zip",
})


def _is_static_path(path: str) -> bool:
    dot = path.rfind(".")
    if dot < 0:
        return False
    return path[dot:].lower() in _STATIC_EXTS


async def path_sweep_record(track_key: str, path: str, admin_ns: str) -> None:
    """Record a path visit into the sliding window.
    Call this in the early-telemetry section so all requests are captured.
    Skips static assets and the admin namespace (operators browse many dashboard pages).
    """
    if _is_static_path(path) or path == admin_ns or path.startswith(admin_ns + "/"):
        return
    async with state_lock:
        ip_state[track_key].path_sweep_times.append((_t.monotonic(), path))


async def path_sweep_check(track_key: str) -> tuple:
    """Prune the window and count distinct paths. Returns (fired, detail_str)."""
    async with state_lock:
        s = ip_state[track_key]
        cutoff = _t.monotonic() - PATH_SWEEP_WINDOW_SECS
        # Prune expired entries
        while s.path_sweep_times and s.path_sweep_times[0][0] < cutoff:
            s.path_sweep_times.popleft()
        distinct = len({p for _, p in s.path_sweep_times})
    if distinct >= PATH_SWEEP_THRESHOLD:
        return True, f"{distinct} distinct paths in {PATH_SWEEP_WINDOW_SECS}s"
    return False, ""
