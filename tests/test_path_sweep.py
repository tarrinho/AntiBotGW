"""
Unit tests for detection/path_sweep.py (1.7.3).

Tests the sliding-window distinct-path counter:
  - static assets are skipped
  - admin namespace is skipped
  - distinct-path counting fires at threshold
  - repeated visits to the same path don't inflate count
  - window expiry prunes old entries
  - check is safe to call before any record calls
"""
import asyncio
import time


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── helpers ────────────────────────────────────────────────────────────────

def _make_module():
    """Import detection.path_sweep with a clean state on each call."""
    import importlib
    import sys
    # Force reload so ip_state is fresh for each test
    for mod in list(sys.modules.keys()):
        if mod in ("state", "detection.path_sweep"):
            del sys.modules[mod]
    import state
    import detection.path_sweep as ps
    return ps, state


# ── static-asset filtering ─────────────────────────────────────────────────

def test_static_exts_not_recorded(proxy_module):
    """Static asset paths must never be added to path_sweep_times."""
    from detection.path_sweep import path_sweep_record
    from state import ip_state

    ip_state.clear()
    key = "test-static"
    static_paths = [
        "/style.css", "/app.js", "/logo.png", "/font.woff2",
        "/video.mp4", "/doc.pdf", "/bundle.mjs", "/map.map",
    ]

    async def go():
        for p in static_paths:
            await path_sweep_record(key, p, "/__gw")

    _run(go())
    assert len(ip_state[key].path_sweep_times) == 0, \
        "static assets must not be recorded"


def test_non_static_paths_are_recorded(proxy_module):
    """Non-static paths must be recorded."""
    from detection.path_sweep import path_sweep_record
    from state import ip_state

    ip_state.clear()
    key = "test-nonstatic"

    async def go():
        for p in ["/page1", "/api/data", "/search?q=foo", "/login"]:
            await path_sweep_record(key, p, "/__gw")

    _run(go())
    assert len(ip_state[key].path_sweep_times) == 4


# ── admin namespace filtering ──────────────────────────────────────────────

def test_admin_ns_exact_not_recorded(proxy_module):
    from detection.path_sweep import path_sweep_record
    from state import ip_state

    ip_state.clear()
    key = "test-admin-exact"

    async def go():
        await path_sweep_record(key, "/__gw", "/__gw")

    _run(go())
    assert len(ip_state[key].path_sweep_times) == 0


def test_admin_ns_subpath_not_recorded(proxy_module):
    from detection.path_sweep import path_sweep_record
    from state import ip_state

    ip_state.clear()
    key = "test-admin-sub"

    async def go():
        await path_sweep_record(key, "/__gw/rules", "/__gw")
        await path_sweep_record(key, "/__gw/events", "/__gw")
        await path_sweep_record(key, "/__gw/agents", "/__gw")

    _run(go())
    assert len(ip_state[key].path_sweep_times) == 0


# ── threshold detection ────────────────────────────────────────────────────

def test_check_fires_at_threshold(proxy_module):
    """path_sweep_check must return True when distinct paths >= threshold."""
    from detection.path_sweep import path_sweep_record, path_sweep_check
    from state import ip_state
    import config

    ip_state.clear()
    threshold = config.PATH_SWEEP_THRESHOLD
    key = "test-threshold"

    async def go():
        for i in range(threshold):
            await path_sweep_record(key, f"/path-{i}", "/__gw")
        fired, detail = await path_sweep_check(key)
        return fired, detail

    fired, detail = _run(go())
    assert fired is True
    assert str(threshold) in detail or "paths" in detail


def test_check_does_not_fire_below_threshold(proxy_module):
    from detection.path_sweep import path_sweep_record, path_sweep_check
    from state import ip_state
    import config

    ip_state.clear()
    threshold = config.PATH_SWEEP_THRESHOLD
    key = "test-below"

    async def go():
        for i in range(threshold - 1):
            await path_sweep_record(key, f"/page-{i}", "/__gw")
        fired, _ = await path_sweep_check(key)
        return fired

    assert _run(go()) is False


def test_repeated_path_counts_as_one(proxy_module):
    """Visiting the same path many times must not inflate the distinct count."""
    from detection.path_sweep import path_sweep_record, path_sweep_check
    from state import ip_state
    import config

    ip_state.clear()
    threshold = config.PATH_SWEEP_THRESHOLD
    key = "test-repeat"

    async def go():
        # Visit a single path threshold * 3 times
        for _ in range(threshold * 3):
            await path_sweep_record(key, "/same-path", "/__gw")
        fired, _ = await path_sweep_check(key)
        return fired

    assert _run(go()) is False, \
        "repeated visits to the same path must not trigger path-sweep"


# ── window expiry ──────────────────────────────────────────────────────────

def test_expired_entries_pruned(proxy_module, monkeypatch):
    """Entries older than PATH_SWEEP_WINDOW_SECS must be pruned on check."""
    from detection import path_sweep as ps_mod
    from state import ip_state
    import config

    ip_state.clear()
    threshold = config.PATH_SWEEP_THRESHOLD
    key = "test-expiry"

    # Manually insert old entries (guaranteed outside window regardless of
    # how long the system has been running — monotonic() - window * 2 is
    # always < cutoff = monotonic() - window).
    import time as _time
    old_ts = _time.monotonic() - config.PATH_SWEEP_WINDOW_SECS * 2
    from state import state_lock
    async def plant_old():
        async with state_lock:
            for i in range(threshold):
                ip_state[key].path_sweep_times.append((old_ts, f"/old-{i}"))

    _run(plant_old())

    async def go():
        fired, _ = await ps_mod.path_sweep_check(key)
        return fired

    # Old entries should be pruned — detector must NOT fire
    assert _run(go()) is False, \
        "entries outside the window must be pruned and not trigger detection"

    # Also verify the deque is actually empty after prune
    assert len(ip_state[key].path_sweep_times) == 0


# ── safe initial state ─────────────────────────────────────────────────────

def test_check_on_unknown_key_returns_false(proxy_module):
    """Calling check on a key with no history must return False safely."""
    from detection.path_sweep import path_sweep_check
    from state import ip_state

    ip_state.clear()

    async def go():
        fired, detail = await path_sweep_check("brand-new-identity-xyz")
        return fired, detail

    fired, detail = _run(go())
    assert fired is False
    assert detail == ""
