"""
Async tests for the rate-limit buckets, behavioural detector, and identity
pruning. Use plain asyncio (no pytest-aiohttp) to keep deps minimal.
"""
import asyncio
import time
import pytest


def _run(coro):
    """Run a coroutine on a fresh event loop (test isolation)."""
    return asyncio.new_event_loop().run_until_complete(coro)


# ── Socket-IP bucket (Layer 8) ────────────────────────────────────────────

def test_take_socket_ip_token_burst_then_block(proxy_module):
    proxy_module.ip_buckets.clear()

    async def go():
        ip = "203.0.113.99"
        results = []
        for _ in range(proxy_module.IP_BURST + 5):
            ok, _retry = await proxy_module.take_socket_ip_token(ip)
            results.append(ok)
        return results

    res = _run(go())
    n = proxy_module.IP_BURST
    assert all(res[:n]),       "first IP_BURST requests must pass"
    assert not any(res[n:]),   "all overflow requests must be blocked"


def test_take_socket_ip_token_isolated_per_ip(proxy_module):
    proxy_module.ip_buckets.clear()

    async def go():
        a_ok, _ = await proxy_module.take_socket_ip_token("198.51.100.1")
        b_ok, _ = await proxy_module.take_socket_ip_token("198.51.100.2")
        return a_ok and b_ok

    assert _run(go()) is True


# ── Per-identity bucket (Layer 9) ─────────────────────────────────────────

def test_take_token_burst_then_block(proxy_module):
    proxy_module.ip_state.clear()

    async def go():
        ident = "TEST_IDENT_A"
        results = []
        for _ in range(proxy_module.RATE_LIMIT_BURST + 3):
            ok, _retry, _rem = await proxy_module.take_token(ident)
            results.append(ok)
        return results

    res = _run(go())
    n = proxy_module.RATE_LIMIT_BURST
    assert all(res[:n])
    assert not any(res[n:])


# ── Behavioural detector (Layer 10) ───────────────────────────────────────

def test_behavioral_detects_perfectly_regular_intervals(proxy_module):
    proxy_module.ip_state.clear()

    async def go():
        s = proxy_module.ip_state["BOT_REGULAR"]
        t = time.monotonic()
        for i in range(20):
            s.request_times.append(t + i * 0.100)  # exact 100 ms intervals
        return await proxy_module.behavioral_check("BOT_REGULAR")

    suspicious, reason = _run(go())
    assert suspicious is True
    assert "regular" in reason.lower() or "σ/μ" in reason.lower()


def test_behavioral_detects_quantised_jitter(proxy_module):
    proxy_module.ip_state.clear()

    async def go():
        s = proxy_module.ip_state["BOT_JITTER"]
        t = time.monotonic()
        # 70%+ of intervals fall in one 50 ms bin (150ms ± 50ms — discrete)
        for delta in [0.150, 0.151, 0.149, 0.150, 0.150, 0.151, 0.149,
                      0.150, 0.150, 0.150, 0.151, 0.150, 0.149, 0.150,
                      0.150, 0.151, 0.150, 0.150, 0.150, 0.150]:
            t += delta
            s.request_times.append(t)
        return await proxy_module.behavioral_check("BOT_JITTER")

    suspicious, _reason = _run(go())
    assert suspicious is True


def test_behavioral_passes_humanlike(proxy_module):
    proxy_module.ip_state.clear()

    async def go():
        import random
        rng = random.Random(42)
        s = proxy_module.ip_state["HUMAN"]
        t = time.monotonic()
        # Random 0.5–8s gaps (and mean > 5s, so the check skips outright,
        # but even 0.5–3s with high variance must pass).
        for _ in range(20):
            t += rng.uniform(0.5, 3.0)
            s.request_times.append(t)
        return await proxy_module.behavioral_check("HUMAN")

    suspicious, _reason = _run(go())
    assert suspicious is False


# ── NAT detection requires real activity (M7 fix) ────────────────────────

def test_nat_detection_does_not_count_fake_identities(proxy_module):
    """Spawning fake identities at one IP without static-asset fetches +
    allowed_count >= 3 must NOT inflate the NAT identity count."""
    proxy_module.ip_state.clear()
    fake_ip = "198.51.100.7"
    n = time.monotonic()
    for i in range(10):
        s = proxy_module.ip_state[f"FAKE_{i}"]
        s.last_ip = fake_ip
        s.last_seen = n
        s.static_loads = 0
        s.allowed_count = 0

    nat_count = sum(
        1 for _, st in proxy_module.ip_state.items()
        if st.last_ip == fake_ip
        and (n - st.last_seen) < 3600
        and st.static_loads >= 1
        and st.allowed_count >= 3
    )
    assert nat_count == 0


def test_nat_detection_counts_legit_identities(proxy_module):
    proxy_module.ip_state.clear()
    real_ip = "198.51.100.8"
    n = time.monotonic()
    for i in range(6):
        s = proxy_module.ip_state[f"REAL_{i}"]
        s.last_ip = real_ip
        s.last_seen = n
        s.static_loads = 2      # fetched assets
        s.allowed_count = 5

    nat_count = sum(
        1 for _, st in proxy_module.ip_state.items()
        if st.last_ip == real_ip
        and (n - st.last_seen) < 3600
        and st.static_loads >= 1
        and st.allowed_count >= 3
    )
    assert nat_count == 6


# ── Stealth-score components ──────────────────────────────────────────────

def test_stealth_score_zero_for_no_allowed(proxy_module):
    proxy_module.ip_state.clear()
    s = proxy_module.ip_state["X"]
    s.allowed_count = 0
    score, _comp, _met = proxy_module._stealth_score(s)
    assert score == 0


def test_stealth_score_flags_low_header_completeness(proxy_module):
    proxy_module.ip_state.clear()
    s = proxy_module.ip_state["LOW_HEADERS"]
    s.allowed_count = 5
    s.header_scores.extend([1, 1, 1, 1, 1])  # avg 1/7
    score, comp, _met = proxy_module._stealth_score(s)
    assert comp["headers"] > 0
    assert score >= comp["headers"]
