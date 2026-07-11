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

import pytest

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
# R-2  AbuseIPDB unreachable → lookup returns falsy / doesn't crash callers
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_abuseipdb_timeout_returns_none_or_empty():
    """`_abuseipdb_lookup` on a timeout must not raise — the caller checks
    truthiness on the return, so None / empty-dict is the graceful fall-back."""
    from reputation import abuseipdb as ab

    class _FakeSession:
        def get(self, *a, **kw):  # noqa: ARG002
            raise asyncio.TimeoutError()

    with mock.patch.object(ab, "_get_session", return_value=_FakeSession()):
        # Must not raise. Whatever it returns, callers treat as "no data".
        result = await ab._abuseipdb_lookup("1.2.3.4")
    # None or empty dict — anything falsy — is acceptable.
    assert not result or isinstance(result, dict)


@pytest.mark.asyncio
async def test_abuseipdb_500_returns_none_or_empty():
    """HTTP 500 from AbuseIPDB is a transient service outage — treat as
    'no reputation data' and let downstream detectors decide."""
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

    with mock.patch.object(ab, "_get_session", return_value=_FakeSession()):
        result = await ab._abuseipdb_lookup("2.2.2.2")
    assert not result or isinstance(result, dict)


# ══════════════════════════════════════════════════════════════════════════════
# R-3  CrowdSec LAPI unreachable → check returns clean, health surfaces error
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_crowdsec_lapi_connection_refused_returns_clean():
    """`_crowdsec_check` on ConnectionRefusedError (LAPI container down) must
    return a benign result — no ban decision produced from the outage."""
    from reputation import crowdsec as cs

    class _FakeSession:
        def get(self, *a, **kw):  # noqa: ARG002
            raise ConnectionRefusedError("lapi down")

    with mock.patch.object(cs, "_get_session", return_value=_FakeSession()):
        result = await cs._crowdsec_check("3.3.3.3")
    # Any falsy return or a dict without 'ban' is acceptable — the point
    # is that the outage doesn't itself produce a ban.
    if isinstance(result, dict):
        assert not result.get("ban") and not result.get("banned")
    else:
        assert not result


@pytest.mark.asyncio
async def test_crowdsec_lapi_health_reports_down_not_raise():
    """The health-check endpoint must SURFACE a down-status rather than
    silently swallow it — otherwise the operator can't tell CrowdSec is
    unreachable from the dashboards."""
    from reputation import crowdsec as cs

    class _FakeSession:
        def get(self, *a, **kw):  # noqa: ARG002
            raise ConnectionRefusedError("lapi down")

    with mock.patch.object(cs, "_get_session", return_value=_FakeSession()):
        health = await cs._crowdsec_lapi_health()
    # Health should return a dict with an error / status field, not raise.
    assert isinstance(health, dict)
    # Some non-empty error / status indicator must be present.
    assert any(
        k in health for k in ("error", "status", "reachable", "ok")
    ), f"health payload must carry an operator-visible status field: {health}"
