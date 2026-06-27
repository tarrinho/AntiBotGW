"""
1.8.15 — Full-scrub regression: operator Allow / Unban must zero ALL ban-state
fields on the identity, not just the scalar risk_score. Prior behaviour left
risk_by_reason + blocks_by_reason + blocked_count populated, so the dashboard
"Risk score breakdown" popover continued showing the pre-ban reasons (e.g.
"80 from ua-ai-curl") even though the scalar showed 0. Reset decay clock so
the next scoring window starts from `now`, not from a back-dated timestamp.

Source guards (TestUnbanFullScrubSourceGuards):
  - unban_endpoint match block clears risk_by_reason + blocks_by_reason
  - unban_endpoint match block sets blocked_count = 0
  - unban_endpoint match block sets last_risk_update = n
  - bulk_unban_endpoint match block has the same scrub
  - dashboards/agents.html and dashboards/main.html have Reset risk button
  - dashboards/agents.html and dashboards/main.html wire .gw-reset-risk handler

Functional (TestUnbanFullScrubFunctional):
  - Seed identity w/ risk_score, breakdown, blocks → POST /unban → all scrubbed
  - Seed identity w/ matching reason → POST/DELETE /secured/bans → all scrubbed
"""
import asyncio
import pathlib
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


_ROOT     = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC   = (_ROOT / "core"  / "proxy_handler.py").read_text(encoding="utf-8")
_AG_SRC   = (_ROOT / "dashboards" / "agents.html").read_text(encoding="utf-8")
_MN_SRC   = (_ROOT / "dashboards" / "main.html").read_text(encoding="utf-8")


@asynccontextmanager
async def _spin_upstream():
    async def _echo(req):
        return web.Response(text="upstream-ok", status=200)
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _echo)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url, **overrides):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    for k, v in overrides.items():
        setattr(proxy_module, k, v)
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()
    for _s in list(proxy_module.ip_state.values()):
        _s.banned_until = 0.0
        _s.bypass_until = 0.0
        _s.risk_score = 0.0
        try: _s.risk_by_reason.clear()
        except Exception: pass
        try: _s.blocks_by_reason.clear()
        except Exception: pass
        _s.blocked_count = 0


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── Source guards ────────────────────────────────────────────────────────────

class TestUnbanFullScrubSourceGuards:
    """Static checks: the unban handlers fully scrub identity state."""

    def _unban_block(self) -> str:
        ub = _PH_SRC.find("async def unban_endpoint(")
        assert ub != -1
        nxt = _PH_SRC.find("async def bulk_unban_endpoint(", ub)
        return _PH_SRC[ub: nxt if nxt != -1 else ub + 4000]

    def _bulk_block(self) -> str:
        ub = _PH_SRC.find("async def bulk_unban_endpoint(")
        assert ub != -1
        nxt = _PH_SRC.find("async def ", ub + 1)
        return _PH_SRC[ub: nxt if nxt != -1 else ub + 4000]

    def test_unban_clears_risk_by_reason(self):
        blk = self._unban_block()
        assert "risk_by_reason.clear()" in blk, (
            "unban_endpoint must clear s.risk_by_reason — stale breakdown "
            "betrays operator's Allow intent"
        )

    def test_unban_clears_blocks_by_reason(self):
        blk = self._unban_block()
        assert "blocks_by_reason.clear()" in blk, (
            "unban_endpoint must clear s.blocks_by_reason — dashboard column "
            "would still misleadingly show block-reason histogram"
        )

    def test_unban_resets_blocked_count(self):
        blk = self._unban_block()
        assert "blocked_count = 0" in blk, (
            "unban_endpoint must set s.blocked_count = 0 — operator gave Allow"
        )

    def test_unban_resets_last_risk_update(self):
        blk = self._unban_block()
        assert "last_risk_update = n" in blk, (
            "unban_endpoint must reset s.last_risk_update so the next decay "
            "window starts from now, not back-dated"
        )

    def test_bulk_unban_clears_risk_by_reason(self):
        blk = self._bulk_block()
        assert "risk_by_reason.clear()" in blk, (
            "bulk_unban_endpoint must clear s.risk_by_reason (parity with unban)"
        )

    def test_bulk_unban_clears_blocks_by_reason(self):
        blk = self._bulk_block()
        assert "blocks_by_reason.clear()" in blk, (
            "bulk_unban_endpoint must clear s.blocks_by_reason (parity with unban)"
        )

    def test_bulk_unban_resets_blocked_count(self):
        blk = self._bulk_block()
        assert "blocked_count = 0" in blk, (
            "bulk_unban_endpoint must reset s.blocked_count (parity with unban)"
        )

    def test_bulk_unban_grants_bypass(self):
        """bulk_unban must grant ALLOW_BYPASS_SECS grace too (parity with unban)."""
        blk = self._bulk_block()
        assert "bypass_until" in blk and "ALLOW_BYPASS_SECS" in blk, (
            "bulk_unban_endpoint must grant grace window like unban_endpoint"
        )

    def test_unban_emits_audit_slog(self):
        blk = self._unban_block()
        assert 'slog("manual_unban"' in blk, (
            "unban_endpoint must emit slog('manual_unban', ...) for SIEM audit"
        )

    def test_bulk_unban_emits_audit_slog(self):
        blk = self._bulk_block()
        assert 'slog("manual_bulk_unban"' in blk, (
            "bulk_unban_endpoint must emit slog('manual_bulk_unban', ...) for SIEM"
        )

    def test_agents_html_has_reset_risk_button(self):
        assert "gw-reset-risk" in _AG_SRC, (
            "dashboards/agents.html must declare .gw-reset-risk button class"
        )
        assert "Reset risk" in _AG_SRC, (
            "dashboards/agents.html must show 'Reset risk' label on breakdown popover"
        )
        assert "data-reset-id" in _AG_SRC, (
            "dashboards/agents.html Reset risk button must carry data-reset-id"
        )

    def test_agents_html_wires_reset_handler(self):
        assert "querySelectorAll('.gw-reset-risk')" in _AG_SRC, (
            "dashboards/agents.html wireRiskActions must attach a click handler "
            "to .gw-reset-risk buttons"
        )

    def test_main_html_has_reset_risk_button(self):
        assert "gw-reset-risk" in _MN_SRC, (
            "dashboards/main.html must declare .gw-reset-risk button class"
        )
        assert "Reset risk" in _MN_SRC, (
            "dashboards/main.html must show 'Reset risk' label on breakdown popover"
        )

    def test_main_html_wires_reset_handler(self):
        assert "querySelectorAll('.gw-reset-risk')" in _MN_SRC, (
            "dashboards/main.html wireRiskActions must attach a click handler "
            "to .gw-reset-risk buttons"
        )


# ── Functional ──────────────────────────────────────────────────────────────

class TestUnbanFullScrubFunctional:
    """Live proxy: confirm scrub really clears in-memory IpState fields."""

    def _seed_admin(self, proxy_module):
        sid = proxy_module._new_sid()
        proxy_module._SESSION_CACHE[sid] = {
            "username":   "admin",
            "expires_ts": time.time() + proxy_module._SESSION_TTL,
            "revoked":    False,
        }
        proxy_module._SESSION_CACHE_READY = True
        cookie = proxy_module._session_sign("admin", sid=sid)
        return {proxy_module._SESSION_COOKIE: cookie}

    def test_unban_full_scrub(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up,
                                       ALLOW_BYPASS_SECS=600) as client:
                    key = "192.0.2.50"
                    s = proxy_module.ip_state[key]
                    s.last_ip = key
                    s.banned_until = time.time() + 3600
                    s.risk_score = 80.0
                    s.risk_by_reason["ua-ai-curl"] = 50.0
                    s.risk_by_reason["honeypot-silent"] = 30.0
                    s.blocks_by_reason["honeypot-silent"] = 4
                    s.blocked_count = 7
                    s.last_risk_update = 0.0  # stale (now() is monotonic — 0 = ancient)

                    ck = self._seed_admin(proxy_module)
                    import admin.auth as _auth
                    import ipaddress
                    old_nets = list(_auth.ADMIN_ALLOWED_NETS)
                    _auth.ADMIN_ALLOWED_NETS.clear()
                    _auth.ADMIN_ALLOWED_NETS.append(ipaddress.ip_network("127.0.0.1/32"))
                    try:
                        r = await client.post(
                            "/antibot-appsec-gateway/secured/unban",
                            cookies=ck,
                            json={"ip": key},
                            headers={"Content-Type": "application/json"},
                        )
                        body = await r.json()
                    finally:
                        _auth.ADMIN_ALLOWED_NETS.clear()
                        _auth.ADMIN_ALLOWED_NETS.extend(old_nets)

                    assert r.status == 200, f"unban failed: {body}"
                    assert body.get("cleared", 0) >= 1, body

                    # Full scrub assertions
                    assert s.banned_until == 0.0, "ban not cleared"
                    assert s.risk_score == 0.0, "risk_score not reset"
                    assert dict(s.risk_by_reason) == {}, (
                        f"risk_by_reason must be empty after Allow; got {dict(s.risk_by_reason)}"
                    )
                    assert dict(s.blocks_by_reason) == {}, (
                        f"blocks_by_reason must be empty after Allow; got {dict(s.blocks_by_reason)}"
                    )
                    assert s.blocked_count == 0, (
                        f"blocked_count must be 0 after Allow; got {s.blocked_count}"
                    )
                    # last_risk_update is monotonic-clock based (helpers.now()).
                    # Must be reset from the seeded 0.0 to ~monotonic-now.
                    import time as _t
                    age = _t.monotonic() - s.last_risk_update
                    assert s.last_risk_update > 0.0, (
                        "last_risk_update must be reset away from seeded 0.0"
                    )
                    assert age < 60, (
                        f"last_risk_update must be reset to ~now (monotonic); age={age:.1f}s"
                    )
                    # Grace window granted
                    assert s.bypass_until > _t.monotonic(), (
                        "bypass_until must be set into the future"
                    )
        _run(go())

    def test_bulk_unban_full_scrub_by_reason_glob(self, proxy_module):
        """DELETE /secured/bans?reason=ua-ai-* must fully scrub matching identities."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up,
                                       ALLOW_BYPASS_SECS=600) as client:
                    key = "192.0.2.77"
                    s = proxy_module.ip_state[key]
                    s.last_ip = key
                    s.banned_until = time.time() + 3600
                    s.risk_score = 60.0
                    s.risk_by_reason["ua-ai-curl"] = 60.0
                    s.blocks_by_reason["ua-ai-curl"] = 3
                    s.blocked_count = 3

                    ck = self._seed_admin(proxy_module)
                    import admin.auth as _auth
                    import ipaddress
                    old_nets = list(_auth.ADMIN_ALLOWED_NETS)
                    _auth.ADMIN_ALLOWED_NETS.clear()
                    _auth.ADMIN_ALLOWED_NETS.append(ipaddress.ip_network("127.0.0.1/32"))
                    try:
                        r = await client.delete(
                            "/antibot-appsec-gateway/secured/bans?reason=ua-ai-*",
                            cookies=ck,
                        )
                        body = await r.json()
                    finally:
                        _auth.ADMIN_ALLOWED_NETS.clear()
                        _auth.ADMIN_ALLOWED_NETS.extend(old_nets)

                    assert r.status == 200, f"bulk unban failed: {body}"
                    assert body.get("cleared", 0) >= 1, body

                    assert s.banned_until == 0.0
                    assert s.risk_score == 0.0
                    assert dict(s.risk_by_reason) == {}, (
                        f"bulk: risk_by_reason must be empty; got {dict(s.risk_by_reason)}"
                    )
                    assert dict(s.blocks_by_reason) == {}, (
                        f"bulk: blocks_by_reason must be empty; got {dict(s.blocks_by_reason)}"
                    )
                    assert s.blocked_count == 0
                    import time as _t
                    assert s.bypass_until > _t.monotonic(), (
                        "bulk unban must grant grace window"
                    )
        _run(go())
