"""
QA tests — operator Allow grace window + unban GET auth fix (1.8.15).

Two related fixes:

1. **Grace window** — when operator clicks Allow/Unban, set `bypass_until`
   on IpState to `monotonic() + ALLOW_BYPASS_SECS`. protect() skips heuristic
   detection while `monotonic() < bypass_until`, so a freshly-unbanned identity
   can re-establish a session without being immediately re-banned by accumulated
   signals (session-churn, header-order-fp, ai-headers-incomplete, etc.).

2. **GET auth fix** — `unban_endpoint` previously gated only the POST branch
   with `_role_denied`. The GET branch (used by Allow buttons in the UI)
   was reachable without authentication. Fixed: auth check now applies to
   both methods before any dispatch.

Coverage:
  TestAllowBypassSourceGuards   — source-code checks
  TestAllowBypassFunctional     — live-proxy: bypass active during grace, expires
  TestUnbanAuthGet              — GET /unban requires auth
"""
import asyncio
import pathlib
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

# ── Source text ───────────────────────────────────────────────────────────────
_ROOT    = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC  = (_ROOT / "core"  / "proxy_handler.py").read_text(encoding="utf-8")
_MET_SRC = (_ROOT / "core"  / "metrics.py").read_text(encoding="utf-8")
_STATE   = (_ROOT / "state.py").read_text(encoding="utf-8")
_CFG_SRC = (_ROOT / "config.py").read_text(encoding="utf-8")
_VH_SRC  = (_ROOT / "vhost.py").read_text(encoding="utf-8")
_CTL_SRC = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")
_VHP_SRC = (_ROOT / "dashboards" / "vhost_policy.html").read_text(encoding="utf-8")
_MN_SRC  = (_ROOT / "dashboards" / "main.html").read_text(encoding="utf-8")


# ── Shared helpers ────────────────────────────────────────────────────────────

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
    # Cleanup: clear bans + bypass on all identities so other tests aren't polluted
    for _s in list(proxy_module.ip_state.values()):
        _s.banned_until = 0.0
        _s.bypass_until = 0.0
        _s.risk_score = 0.0


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── 1. TestAllowBypassSourceGuards ────────────────────────────────────────────

class TestAllowBypassSourceGuards:
    """Static checks: ALLOW_BYPASS_SECS wired through all required files."""

    def test_bypass_until_field_on_ipstate(self):
        """state.IpState must declare bypass_until field."""
        assert "bypass_until" in _STATE, (
            "IpState must declare bypass_until: float field"
        )

    def test_allow_bypass_secs_in_config(self):
        """config.ALLOW_BYPASS_SECS must be defined."""
        assert "ALLOW_BYPASS_SECS" in _CFG_SRC, (
            "ALLOW_BYPASS_SECS missing from config.py"
        )

    def test_allow_bypass_default_300(self):
        """Default ALLOW_BYPASS_SECS must be 300 (5 min)."""
        idx = _CFG_SRC.find("ALLOW_BYPASS_SECS = ")
        block = _CFG_SRC[idx: idx + 200]
        assert '"300"' in block or "'300'" in block, (
            "Default ALLOW_BYPASS_SECS must be 300 seconds"
        )

    def test_allow_bypass_in_vhost_coerce(self):
        """ALLOW_BYPASS_SECS must be per-vhost overridable."""
        assert "ALLOW_BYPASS_SECS" in _VH_SRC, (
            "ALLOW_BYPASS_SECS missing from _VHOST_COERCE"
        )

    def test_allow_bypass_in_hot_reload_knobs(self):
        """ALLOW_BYPASS_SECS must be hot-reloadable with validator."""
        idx = _PH_SRC.find('"ALLOW_BYPASS_SECS"')
        assert idx != -1, "ALLOW_BYPASS_SECS not registered in _HOT_RELOAD_KNOBS"
        block = _PH_SRC[idx: idx + 80]
        assert "int" in block and "86400" in block, (
            "Validator must accept int values in [0, 86400]"
        )

    def test_unban_sets_bypass_until(self):
        """unban_endpoint must set bypass_until when ALLOW_BYPASS_SECS > 0."""
        idx = _PH_SRC.find("s.risk_score = 0.0")
        assert idx != -1
        # Widened window — unban block also scrubs risk_by_reason / blocks_by_reason
        # / blocked_count / last_risk_update before setting bypass_until.
        block = _PH_SRC[idx: idx + 700]
        assert "bypass_until" in block, (
            "unban_endpoint must set s.bypass_until after clearing risk"
        )
        assert "ALLOW_BYPASS_SECS" in block, (
            "bypass_until set must be gated by ALLOW_BYPASS_SECS > 0"
        )
        assert "_t.monotonic()" in block or "monotonic()" in block, (
            "bypass_until must use monotonic time (not wall clock)"
        )

    def test_protect_has_bypass_gate(self):
        """protect() must have a bypass gate that skips detection during grace."""
        # Should appear AFTER admin_authed_bypass, BEFORE heuristic detectors
        admin_idx = _PH_SRC.find("if _admin_authed_bypass:")
        assert admin_idx != -1
        # Honey FP cross-reference is the first heuristic check
        honey_idx = _PH_SRC.find("Honey fingerprint cross-reference", admin_idx)
        assert honey_idx != -1
        block = _PH_SRC[admin_idx: honey_idx]
        assert "bypass_until" in block, (
            "protect() must have bypass_until gate before heuristic detectors"
        )
        assert "operator-allowed" in block, (
            "Bypass gate must record 'operator-allowed' reason via record()"
        )

    def test_operator_allowed_in_passthrough_reasons(self):
        """'operator-allowed' must be in metrics _PASSTHROUGH_REASONS."""
        idx = _MET_SRC.find("_PASSTHROUGH_REASONS")
        block = _MET_SRC[idx: idx + 600]
        assert "operator-allowed" in block, (
            "'operator-allowed' missing from _PASSTHROUGH_REASONS"
        )

    def test_operator_allowed_in_timeline_passthrough(self):
        """'operator-allowed' must be in the _passthrough timeline set."""
        idx = _PH_SRC.find("_passthrough = {")
        assert idx != -1, "_passthrough set not found"
        block = _PH_SRC[idx: idx + 300]
        assert "operator-allowed" in block, (
            "'operator-allowed' missing from _passthrough timeline filter"
        )

    def test_metrics_clients_includes_bypass_secs(self):
        """clients.append() must include bypass_secs for the dashboard."""
        ca_idx = _PH_SRC.find("clients.append({")
        ca_block = _PH_SRC[ca_idx: ca_idx + 1500]
        assert "bypass_secs" in ca_block, (
            "clients.append() must include bypass_secs field"
        )

    def test_controls_knob_registered(self):
        """controls.html must register ALLOW_BYPASS_SECS as a num knob."""
        assert "ALLOW_BYPASS_SECS" in _CTL_SRC, (
            "ALLOW_BYPASS_SECS missing from controls.html"
        )

    def test_vhost_policy_knob_meta(self):
        """vhost_policy.html KNOB_META must include ALLOW_BYPASS_SECS."""
        assert "ALLOW_BYPASS_SECS" in _VHP_SRC, (
            "ALLOW_BYPASS_SECS missing from vhost_policy.html KNOB_META"
        )

    def test_main_html_shows_bypass_in_popover(self):
        """main.html identity popover must display the grace window."""
        assert "bypass_secs" in _MN_SRC, (
            "main.html must read bypass_secs to display grace window"
        )
        assert "grace window" in _MN_SRC or "detection bypassed" in _MN_SRC, (
            "Identity popover must show grace-window text when bypass active"
        )


# ── 2. TestUnbanAuthGet ──────────────────────────────────────────────────────

class TestUnbanAuthGet:
    """The GET branch of unban_endpoint must also require auth."""

    def test_get_branch_has_auth_check(self):
        """unban_endpoint must call _role_denied BEFORE the method dispatch."""
        ub_idx = _PH_SRC.find("async def unban_endpoint(")
        assert ub_idx != -1
        body = _PH_SRC[ub_idx: ub_idx + 1500]
        # Find auth check position
        auth_idx = body.find("_role_denied")
        assert auth_idx != -1, "_role_denied must be called in unban_endpoint"
        # Find first method-branch position
        post_idx = body.find('request.method == "POST"')
        assert post_idx != -1
        assert auth_idx < post_idx, (
            "_role_denied check must precede the request.method == 'POST' branch — "
            "otherwise GET path is unauthenticated"
        )

    def test_get_branch_not_separately_guarded(self):
        """The auth check must be unified — no separate POST-only guard."""
        ub_idx = _PH_SRC.find("async def unban_endpoint(")
        body = _PH_SRC[ub_idx: ub_idx + 1500]
        # The (broken) old pattern was: if request.method == "POST": / if denied :=
        # The fix moves the if denied := outside the POST branch.
        post_idx = body.find('if request.method == "POST":')
        assert post_idx != -1
        post_block = body[post_idx: post_idx + 200]
        assert "_role_denied" not in post_block, (
            "Auth check must NOT be nested inside the POST-only branch — "
            "it must run for both GET and POST"
        )


# ── 3. TestAllowBypassFunctional ─────────────────────────────────────────────

class TestAllowBypassFunctional:
    """Live proxy: bypass is active during grace, expires after."""

    def test_unban_endpoint_sets_bypass_until(self, proxy_module):
        """Calling /unban via POST sets bypass_until on the identity."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up,
                                       ALLOW_BYPASS_SECS=600) as client:
                    # Seed an identity with a ban + risk
                    key = "192.0.2.1"
                    s = proxy_module.ip_state[key]
                    s.banned_until = time.time() + 3600
                    s.risk_score = 75.0
                    s.last_ip = key

                    # Forge admin session so unban auth passes
                    sid = proxy_module._new_sid()
                    proxy_module._SESSION_CACHE[sid] = {
                        "username":   "admin",
                        "expires_ts": time.time() + proxy_module._SESSION_TTL,
                        "revoked":    False,
                    }
                    proxy_module._SESSION_CACHE_READY = True
                    cookie = proxy_module._session_sign("admin", sid=sid)
                    ck = {proxy_module._SESSION_COOKIE: cookie}

                    # Patch admin nets so the call is authorised
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

                    assert r.status == 200, f"unban must succeed; got {r.status}: {body}"
                    assert body.get("cleared", 0) >= 1, (
                        f"Expected cleared >= 1; got {body}"
                    )
                    # Verify state
                    assert s.banned_until == 0.0, "Ban must be cleared"
                    assert s.risk_score == 0.0, "Risk score must be reset"
                    import time as _t
                    assert s.bypass_until > _t.monotonic(), (
                        "bypass_until must be set into the future after unban"
                    )
        _run(go())

    def test_bypass_zero_means_no_grace(self, proxy_module):
        """ALLOW_BYPASS_SECS=0 disables the grace window — bypass_until stays 0."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up,
                                       ALLOW_BYPASS_SECS=0) as client:
                    key = "192.0.2.99"
                    s = proxy_module.ip_state[key]
                    s.banned_until = time.time() + 3600
                    s.risk_score = 50.0
                    s.last_ip = key

                    sid = proxy_module._new_sid()
                    proxy_module._SESSION_CACHE[sid] = {
                        "username":   "admin",
                        "expires_ts": time.time() + proxy_module._SESSION_TTL,
                        "revoked":    False,
                    }
                    proxy_module._SESSION_CACHE_READY = True
                    cookie = proxy_module._session_sign("admin", sid=sid)
                    ck = {proxy_module._SESSION_COOKIE: cookie}

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
                        await r.json()
                    finally:
                        _auth.ADMIN_ALLOWED_NETS.clear()
                        _auth.ADMIN_ALLOWED_NETS.extend(old_nets)

                    assert s.bypass_until == 0.0, (
                        "ALLOW_BYPASS_SECS=0 must not set any bypass grace"
                    )
                    assert s.risk_score == 0.0, (
                        "Risk score is still reset even when bypass disabled"
                    )
        _run(go())

    def test_bypass_secs_in_metrics_response(self, proxy_module):
        """bypass_secs appears in /metrics clients list and counts down."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    import time as _t
                    key = "192.0.2.7"
                    s = proxy_module.ip_state[key]
                    s.bypass_until = _t.monotonic() + 120
                    s.last_ip = key

                    # /metrics requires either admin auth or METRICS_TOKEN; use a forged session
                    sid = proxy_module._new_sid()
                    proxy_module._SESSION_CACHE[sid] = {
                        "username":   "admin",
                        "expires_ts": time.time() + proxy_module._SESSION_TTL,
                        "revoked":    False,
                    }
                    proxy_module._SESSION_CACHE_READY = True
                    cookie = proxy_module._session_sign("admin", sid=sid)
                    ck = {proxy_module._SESSION_COOKIE: cookie}

                    import admin.auth as _auth
                    import ipaddress
                    old_nets = list(_auth.ADMIN_ALLOWED_NETS)
                    _auth.ADMIN_ALLOWED_NETS.clear()
                    _auth.ADMIN_ALLOWED_NETS.append(ipaddress.ip_network("127.0.0.1/32"))
                    try:
                        r = await client.get("/antibot-appsec-gateway/secured/metrics",
                                             cookies=ck)
                        body = await r.json()
                    finally:
                        _auth.ADMIN_ALLOWED_NETS.clear()
                        _auth.ADMIN_ALLOWED_NETS.extend(old_nets)

                    clients = body.get("clients", [])
                    seeded = [c for c in clients if c.get("id") == key]
                    assert seeded, f"Seeded identity {key} missing from clients list"
                    bp = seeded[0].get("bypass_secs", -1)
                    assert 0 < bp <= 120, (
                        f"bypass_secs must reflect remaining grace; got {bp}"
                    )
        _run(go())
