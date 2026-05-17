"""
Performance regression gates for appsec-antibot-gw hot paths.

These tests catch algorithmic regressions — O(n²) bucket drift, lock
contention, SHA-256 overhead spikes — not absolute benchmarks.  Every
threshold has a ≥10× margin over the slowest ARM64 Kali measurement so a
single noisy CI run will not flip them; a real regression will.

Threshold rationale
-------------------
  P1/P2  SHA256 on ≤300 bytes.  Measured ~200k calls/s on ARM64 Python 3.12.
         Floor 20 000 calls/s = 10× margin.
  P3/P4  asyncio.Lock + dict + float math.  Measured ~30k ops/s sequential.
         Floor 2 000 ops/s = 15× margin.
  P5     asyncio.gather(20 coroutines × 50 lock ops) — concurrent contention.
         Floor: must finish in < 5 s (generous for a single-threaded loop).
  P6     aiohttp TestServer, /live endpoint (no upstream needed).
         Measured 800–1500 req/s.  Floor 50 req / 15 s = 3.3 req/s.
  P7     Same TestServer, 20 concurrent /live requests via gather.
         Floor: all 20 complete without error in < 10 s.
  P8     Full pipeline (rate-limit + identity + scoring) via TestServer.
         30 requests from distinct virtual IPs via X-Forwarded-For.
         Floor 30 req / 20 s = 1.5 req/s (conservative for scoring DB writes).
"""

import asyncio
import statistics
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

# identity.py is not re-exported wholesale by proxy — access directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import identity as _identity_mod


# ── helpers shared with test_integration.py ──────────────────────────────

def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _assert_rate(label: str, calls: int, elapsed: float, floor: float) -> None:
    rate = calls / elapsed
    assert rate >= floor, (
        f"{label}: {rate:.0f} calls/s — below floor {floor:.0f} calls/s "
        f"({calls} calls in {elapsed:.3f}s)"
    )


class _FakeReq:
    """Minimal request-like object for pure-function benchmarks."""
    def __init__(self, headers: dict):
        self.headers = headers
        self.cookies: dict = {}

    def __getattr__(self, name):
        raise AttributeError(f"_FakeReq has no attribute {name!r}")


_BROWSER_HEADERS = {
    "User-Agent":       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept-Language":  "en-GB,en;q=0.9",
    "Accept-Encoding":  "gzip, deflate, br",
    "Accept":           "text/html,application/xhtml+xml",
    "Sec-Ch-Ua":        '"Chromium";v="124"',
    "Sec-Fetch-Site":   "none",
    "Sec-Fetch-Mode":   "navigate",
    "Connection":       "keep-alive",
}


@asynccontextmanager
async def _spin_proxy_only(proxy_module):
    """TestServer for /live — no upstream needed; just measuring proxy overhead."""
    proxy_module.UPSTREAM = "http://127.0.0.1:1"   # unreachable; /live never proxies
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()


@asynccontextmanager
async def _spin_with_echo(proxy_module):
    """TestServer backed by an in-process echo upstream — full pipeline."""
    async def _echo(req: web.Request):
        return web.Response(text="echo-ok", content_type="text/plain")

    upstream_app = web.Application()
    upstream_app.router.add_route("*", "/{tail:.*}", _echo)
    upstream_runner = web.AppRunner(upstream_app)
    await upstream_runner.setup()
    upstream_site = web.TCPSite(upstream_runner, "127.0.0.1", 0)
    await upstream_site.start()
    port = upstream_site._server.sockets[0].getsockname()[1]
    upstream_url = f"http://127.0.0.1:{port}"

    proxy_module.UPSTREAM = upstream_url
    proxy_app = proxy_module.make_app()
    server = TestServer(proxy_app)
    client = TestClient(server)
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()
        await upstream_runner.cleanup()


# ═══════════════════════════════════════════════════════════════════════════
# P1 — browser_fingerprint throughput
# ═══════════════════════════════════════════════════════════════════════════

_PERF_N_HASH = 5_000
_PERF_FLOOR_HASH = 20_000   # calls / second


def test_perf_p1_browser_fingerprint_throughput(proxy_module):
    req = _FakeReq(_BROWSER_HEADERS)
    t0 = time.perf_counter()
    for _ in range(_PERF_N_HASH):
        proxy_module.browser_fingerprint(req)
    elapsed = time.perf_counter() - t0
    _assert_rate("browser_fingerprint", _PERF_N_HASH, elapsed, _PERF_FLOOR_HASH)


# ═══════════════════════════════════════════════════════════════════════════
# P2 — _header_order_sig throughput
# ═══════════════════════════════════════════════════════════════════════════

def test_perf_p2_header_order_sig_throughput(proxy_module):
    req = _FakeReq(_BROWSER_HEADERS)
    t0 = time.perf_counter()
    for _ in range(_PERF_N_HASH):
        _identity_mod._header_order_sig(req)
    elapsed = time.perf_counter() - t0
    _assert_rate("_header_order_sig", _PERF_N_HASH, elapsed, _PERF_FLOOR_HASH)


# ═══════════════════════════════════════════════════════════════════════════
# P3 — take_socket_ip_token sequential throughput
# ═══════════════════════════════════════════════════════════════════════════

_PERF_N_BUCKET = 1_000
_PERF_FLOOR_BUCKET = 2_000   # ops / second


def test_perf_p3_socket_ip_bucket_sequential(proxy_module):
    proxy_module.ip_buckets.clear()
    # Single IP so tokens drain — refill happens via elapsed-time math
    # (no time.sleep; elapsed ≈ 0 so tokens stay drained after burst,
    # which exercises the retry-after branch too).
    async def go():
        t0 = time.perf_counter()
        for _ in range(_PERF_N_BUCKET):
            await proxy_module.take_socket_ip_token("203.0.113.1")
        return time.perf_counter() - t0

    elapsed = _run(go())
    _assert_rate("take_socket_ip_token/sequential", _PERF_N_BUCKET, elapsed, _PERF_FLOOR_BUCKET)


# ═══════════════════════════════════════════════════════════════════════════
# P4 — take_token (per-identity bucket) sequential throughput
# ═══════════════════════════════════════════════════════════════════════════

def test_perf_p4_identity_bucket_sequential(proxy_module):
    proxy_module.ip_state.clear()

    async def go():
        t0 = time.perf_counter()
        for _ in range(_PERF_N_BUCKET):
            await proxy_module.take_token("PERF-IDENTITY-A")
        return time.perf_counter() - t0

    elapsed = _run(go())
    _assert_rate("take_token/sequential", _PERF_N_BUCKET, elapsed, _PERF_FLOOR_BUCKET)


# ═══════════════════════════════════════════════════════════════════════════
# P5 — take_socket_ip_token under concurrent load (lock-contention check)
# ═══════════════════════════════════════════════════════════════════════════

_PERF_P5_WORKERS   = 20
_PERF_P5_CALLS_EA  = 50
_PERF_P5_DEADLINE  = 5.0   # seconds


def test_perf_p5_socket_ip_bucket_concurrent(proxy_module):
    proxy_module.ip_buckets.clear()

    async def worker(ip: str):
        for _ in range(_PERF_P5_CALLS_EA):
            await proxy_module.take_socket_ip_token(ip)

    async def go():
        t0 = time.perf_counter()
        await asyncio.gather(*[
            worker(f"10.0.{i // 256}.{i % 256}")
            for i in range(_PERF_P5_WORKERS)
        ])
        return time.perf_counter() - t0

    elapsed = _run(go())
    total = _PERF_P5_WORKERS * _PERF_P5_CALLS_EA
    assert elapsed < _PERF_P5_DEADLINE, (
        f"take_socket_ip_token concurrent: {total} ops across "
        f"{_PERF_P5_WORKERS} workers took {elapsed:.2f}s (limit {_PERF_P5_DEADLINE}s)"
    )


# ═══════════════════════════════════════════════════════════════════════════
# P6 — /live endpoint throughput (proxy overhead baseline, no upstream I/O)
# ═══════════════════════════════════════════════════════════════════════════

_PERF_P6_N        = 50
_PERF_P6_DEADLINE = 15.0   # seconds  →  floor 3.3 req/s
_PERF_P6_P95_MS   = 500    # ms  p95 single-request latency


def test_perf_p6_live_endpoint_sequential_latency(proxy_module):
    latencies: list[float] = []

    async def go():
        async with _spin_proxy_only(proxy_module) as client:
            t_total = time.perf_counter()
            for _ in range(_PERF_P6_N):
                t0 = time.perf_counter()
                r = await client.get("/antibot-appsec-gateway/live")
                latencies.append((time.perf_counter() - t0) * 1000)
                assert r.status == 200
            return time.perf_counter() - t_total

    elapsed = _run(go())
    p95 = statistics.quantiles(latencies, n=20)[18]   # 95th percentile

    assert elapsed < _PERF_P6_DEADLINE, (
        f"/live sequential: {_PERF_P6_N} requests took {elapsed:.2f}s "
        f"(limit {_PERF_P6_DEADLINE}s)"
    )
    assert p95 < _PERF_P6_P95_MS, (
        f"/live p95 latency {p95:.1f}ms exceeds {_PERF_P6_P95_MS}ms"
    )


# ═══════════════════════════════════════════════════════════════════════════
# P7 — /live endpoint concurrent (no deadlock / starvation check)
# ═══════════════════════════════════════════════════════════════════════════

_PERF_P7_CONCURRENT = 20
_PERF_P7_DEADLINE   = 10.0  # seconds


def test_perf_p7_live_endpoint_concurrent(proxy_module):
    errors: list[int] = []

    async def go():
        async with _spin_proxy_only(proxy_module) as client:
            async def one_req():
                r = await client.get("/antibot-appsec-gateway/live")
                if r.status != 200:
                    errors.append(r.status)

            t0 = time.perf_counter()
            await asyncio.gather(*[one_req() for _ in range(_PERF_P7_CONCURRENT)])
            return time.perf_counter() - t0

    elapsed = _run(go())
    assert not errors, f"/live concurrent: unexpected status codes {errors}"
    assert elapsed < _PERF_P7_DEADLINE, (
        f"/live {_PERF_P7_CONCURRENT}-concurrent took {elapsed:.2f}s "
        f"(limit {_PERF_P7_DEADLINE}s)"
    )


# ═══════════════════════════════════════════════════════════════════════════
# P8 — Full pipeline throughput via distinct virtual IPs (no rate-limit hit)
#      Exercises: XFF parsing → IP bucket → identity → fingerprint → scoring
# ═══════════════════════════════════════════════════════════════════════════

_PERF_P8_N        = 30
_PERF_P8_DEADLINE = 20.0   # seconds  →  floor 1.5 req/s


def test_perf_p8_full_pipeline_distinct_ips(proxy_module):
    """Send requests from N distinct IPs so the rate limiter never fires.
    Validates that per-IP state initialisation (defaultdict + bucket create)
    stays O(1) and doesn't degrade as the ip_state dict grows."""
    proxy_module.ip_buckets.clear()
    proxy_module.ip_state.clear()

    async def go():
        async with _spin_with_echo(proxy_module) as client:
            t0 = time.perf_counter()
            for i in range(_PERF_P8_N):
                ip = f"198.51.100.{i % 254 + 1}"
                r = await client.get(
                    "/test-path",
                    headers={
                        **_BROWSER_HEADERS,
                        "X-Forwarded-For": ip,
                    },
                )
                # Proxy may return 200 (passed), 202 (challenge), 429 (rate
                # limited), or 403 (banned).  Any is acceptable — we measure
                # throughput, not correctness (correctness is test_integration).
                assert r.status in {200, 202, 403, 429, 502}, (
                    f"unexpected status {r.status} for IP {ip}"
                )
            return time.perf_counter() - t0

    elapsed = _run(go())
    assert elapsed < _PERF_P8_DEADLINE, (
        f"full pipeline: {_PERF_P8_N} distinct-IP requests took "
        f"{elapsed:.2f}s (limit {_PERF_P8_DEADLINE}s)"
    )


# ═══════════════════════════════════════════════════════════════════════════
# P9 — ip_state defaultdict growth — O(1) insert check
#      Adding N identities must not slow down proportionally.
# ═══════════════════════════════════════════════════════════════════════════

_PERF_P9_SMALL  = 100
_PERF_P9_LARGE  = 5_000
_PERF_P9_RATIO  = 3.0   # large-batch must be ≤ 3× slower per-op than small


def test_perf_p9_ip_state_insert_oi(proxy_module):
    """Inserting into ip_state must stay O(1) — not O(n) or O(n log n)."""
    proxy_module.ip_state.clear()

    async def _insert_n(n: int) -> float:
        t0 = time.perf_counter()
        for i in range(n):
            _ = proxy_module.ip_state[f"10.0.{i // 256 % 256}.{i % 256}"]
        return time.perf_counter() - t0

    t_small = _run(_insert_n(_PERF_P9_SMALL))
    proxy_module.ip_state.clear()
    t_large = _run(_insert_n(_PERF_P9_LARGE))

    # per-op time must not grow beyond _PERF_P9_RATIO when n × 50
    scale = _PERF_P9_LARGE / _PERF_P9_SMALL
    ratio = (t_large / _PERF_P9_LARGE) / max(t_small / _PERF_P9_SMALL, 1e-9)
    assert ratio < _PERF_P9_RATIO, (
        f"ip_state insert not O(1): per-op at n={_PERF_P9_SMALL} = "
        f"{t_small/_PERF_P9_SMALL*1e6:.2f}µs, "
        f"at n={_PERF_P9_LARGE} = {t_large/_PERF_P9_LARGE*1e6:.2f}µs "
        f"(ratio {ratio:.1f}× > limit {_PERF_P9_RATIO}×; scale {scale}×)"
    )
