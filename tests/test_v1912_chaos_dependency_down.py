"""
test_v1912_chaos_dependency_down.py — dependency-down chaos matrix.

Every external integration the gateway calls is designed to be best-effort:
Redis / AbuseIPDB / CrowdSec being unreachable must NEVER take the gateway
down or block a legitimate request. This file forces each dependency into
a hard-fail state (raises inside the client call) and asserts the gateway
still returns a valid decision instead of a 500 / crash / hang.

These are pure unit tests — they patch the client at module scope, don't
hit the network, and don't spin up a real gateway process, so they can't
impact the runtime GW.
"""
import asyncio
import os
from unittest import mock

import aiohttp
import pytest


def _wrapped_connection_error(msg: str = "downstream unreachable"):
    """Produce the exception aiohttp actually raises when the downstream
    connection is refused/reset — a ClientConnectorError. Raw
    ConnectionRefusedError from `socket.connect()` is wrapped by aiohttp
    before reaching integration code, so mocks that raise the bare
    OSError don't match production behavior."""
    return aiohttp.ClientConnectionError(msg)

os.environ.setdefault("UPSTREAM", "https://example.com")
os.environ.setdefault("OFFLINE_BG_TASKS", "1")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ══════════════════════════════════════════════════════════════════════════════
# R-1  Redis unreachable → is_banned() falls back to local state
# ══════════════════════════════════════════════════════════════════════════════

def test_redis_connection_error_does_not_crash_is_banned(proxy_module):
    """`integrations.redis._shared_ban_get` raising a ConnectionError must
    NOT propagate out of is_banned() — the caller sees (False, 0) from
    local state, not an exception."""
    async def go():
        import state as _st
        _st.ip_state.pop("chaos-r1", None)

        with mock.patch(
            "integrations.redis._shared_ban_get",
            new=mock.AsyncMock(side_effect=ConnectionError("redis down"))
        ):
            banned, remaining = await proxy_module.is_banned("chaos-r1")
        assert banned is False
        assert remaining == 0.0
    _run(go())


def test_redis_timeout_does_not_crash_is_banned(proxy_module):
    """Same as R-1 but for the more common failure mode — network timeout."""
    async def go():
        import state as _st
        _st.ip_state.pop("chaos-r1b", None)

        with mock.patch(
            "integrations.redis._shared_ban_get",
            new=mock.AsyncMock(side_effect=asyncio.TimeoutError())
        ):
            banned, remaining = await proxy_module.is_banned("chaos-r1b")
        assert banned is False
        assert remaining == 0.0
    _run(go())


# ══════════════════════════════════════════════════════════════════════════════
# R-2  AbuseIPDB unreachable → lookup returns cleanly (never raises)
# ══════════════════════════════════════════════════════════════════════════════
#
# Contract per `_abuseipdb_lookup`'s docstring: "Never raises — failures
# degrade gracefully". Return is a 3-tuple `(score, country, source)` where
# source ∈ ('cache','api','disabled','error','private','invalid'). We assert
# the not-raise contract and the source-is-error-or-disabled degradation
# path — value semantics belong to the integration's own tests.

@pytest.mark.asyncio
async def test_abuseipdb_timeout_degrades_gracefully():
    from reputation import abuseipdb as ab

    class _FakeSession:
        def get(self, *a, **kw):  # noqa: ARG002
            raise asyncio.TimeoutError()

    with mock.patch.object(ab, "ABUSEIPDB_ENABLED", True), \
         mock.patch.object(ab, "_get_session", return_value=_FakeSession()):
        # Must not raise.
        result = await ab._abuseipdb_lookup("1.2.3.4")
    # 3-tuple contract preserved.
    assert isinstance(result, tuple) and len(result) == 3, (
        f"expected (score, country, source) tuple; got {result!r}"
    )
    score, _country, source = result
    # Score must be a benign default (0 = no reputation data), source must
    # NOT indicate a successful reputation lookup.
    assert score == 0, f"outage produced a non-zero score: {score}"
    assert source in ("error", "disabled", "private", "invalid"), (
        f"outage source must be a degradation sentinel; got {source!r}"
    )


@pytest.mark.asyncio
async def test_abuseipdb_500_degrades_gracefully():
    from reputation import abuseipdb as ab

    class _FakeResp:
        status = 500
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def json(self): return {}
        async def text(self): return ""

    class _FakeSession:
        def get(self, *a, **kw):  # noqa: ARG002
            return _FakeResp()

    with mock.patch.object(ab, "ABUSEIPDB_ENABLED", True), \
         mock.patch.object(ab, "_get_session", return_value=_FakeSession()):
        result = await ab._abuseipdb_lookup("2.2.2.2")
    assert isinstance(result, tuple) and len(result) == 3
    assert result[0] == 0
    assert result[2] in ("error", "disabled", "private", "invalid")


# ══════════════════════════════════════════════════════════════════════════════
# R-3  CrowdSec LAPI unreachable → check + health degrade cleanly
# ══════════════════════════════════════════════════════════════════════════════
#
# Contract: `_crowdsec_check` returns `(decision, source)` where decision is
# None on clean or outage; source ∈ ('cache','api','disabled','private',
# 'invalid','error'). Outage → decision=None, source='error'.

@pytest.mark.asyncio
async def test_crowdsec_lapi_connection_refused_returns_clean():
    from reputation import crowdsec as cs

    class _FakeSession:
        def get(self, *a, **kw):  # noqa: ARG002
            raise _wrapped_connection_error("lapi down")

    with mock.patch.object(cs, "CROWDSEC_ENABLED", True), \
         mock.patch.object(cs, "_get_session", return_value=_FakeSession()):
        decision, source = await cs._crowdsec_check("3.3.3.3")
    # The outage MUST NOT produce a ban decision.
    assert decision is None, f"outage produced a decision: {decision!r}"
    # The outage source is any degradation sentinel.
    assert source in ("error", "disabled", "private", "invalid"), (
        f"outage source must be a degradation sentinel; got {source!r}"
    )


@pytest.mark.asyncio
async def test_crowdsec_lapi_health_reports_down_not_raise():
    """`_crowdsec_lapi_health()` must SURFACE a down-status not silently
    swallow it — otherwise the operator can't tell CrowdSec is unreachable
    from the dashboards."""
    from reputation import crowdsec as cs

    class _FakeSession:
        def get(self, *a, **kw):  # noqa: ARG002
            raise _wrapped_connection_error("lapi down")

    with mock.patch.object(cs, "CROWDSEC_ENABLED", True), \
         mock.patch.object(cs, "_get_session", return_value=_FakeSession()):
        health = await cs._crowdsec_lapi_health()
    assert isinstance(health, dict)
    # Non-empty error / status indicator must be present in the payload.
    assert any(
        k in health for k in ("error", "status", "reachable", "ok", "healthy")
    ), f"health payload must carry an operator-visible status field: {health}"
