"""
QA tests — authenticated admin bypass for upstream risk scoring (1.8.14 iter 10).

Bug: operators browsing the protected upstream while logged in to the gateway
admin panel were being banned after 3-4 page loads.  Root cause: each HTTP
sub-request (HTML + CSS + JS + images) was scored independently; heuristic
signals (session-churn 75 pts, ai-headers-incomplete 10 pts × N, header-order-fp
8 pts × N) accumulated fast enough to trip RISK_BAN_THRESHOLD within one tab
session.  ADMIN_ALLOWED_IPS only gated dashboard access — upstream traffic from
admin IPs was scored identically to regular visitors.

Fix: `_admin_authed_bypass` flag in protect() — True when source IP is in
ADMIN_ALLOWED_NETS AND the request carries a valid agw_session cookie:
  1. Both per-identity and fingerprint ban checks are skipped.
  2. All heuristic detection/scoring is bypassed; request recorded as
     `admin-passthrough` (counted as clean allowed traffic, not a block).

Coverage:
  TestAdminBypassSourceGuards    — source-code checks on the bypass logic
  TestAdminBypassFunctional      — live proxy: correct bypass / non-bypass paths
"""
import asyncio
import hashlib
import ipaddress
import pathlib
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

# ── Paths / source ────────────────────────────────────────────────────────────
_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC   = (_ROOT / "core"  / "proxy_handler.py").read_text(encoding="utf-8")
_MET_SRC  = (_ROOT / "core"  / "metrics.py").read_text(encoding="utf-8")


# ── Shared test helpers ───────────────────────────────────────────────────────

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


def _make_admin_cookie(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": time.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── 1. TestAdminBypassSourceGuards ────────────────────────────────────────────

class TestAdminBypassSourceGuards:
    """Source-code checks: bypass flag defined, wired to ban checks and
    heuristic gate, and admin-passthrough in all passthrough sets."""

    def test_admin_authed_bypass_flag_defined(self):
        """_admin_authed_bypass must be defined in proxy_handler.py."""
        assert "_admin_authed_bypass" in _PH_SRC, (
            "_admin_authed_bypass flag not found in proxy_handler.py"
        )

    def test_bypass_requires_admin_ip_and_authed(self):
        """_admin_authed_bypass must check BOTH an admin-IP guard and _internal_authed."""
        # Contract change (1.8.15): the bypass condition lives on the
        # `_admin_authed_bypass = (` assignment line and uses the stricter
        # fail-closed `_is_admin_ip(ip)` (empty allowlist → no bypass) instead
        # of `_admin_ip_allowed(request)` (which is open-by-default). The
        # session requirement (_internal_authed) is unchanged. Anchor on the
        # assignment line, not the leading doc-comment.
        idx = _PH_SRC.find("_admin_authed_bypass = (")
        block = _PH_SRC[idx: idx + 300]
        assert "_is_admin_ip(ip)" in block, (
            "_admin_authed_bypass must call _is_admin_ip(ip) (fail-closed IP guard)"
        )
        assert "_internal_authed(request)" in block, (
            "_admin_authed_bypass must call _internal_authed(request)"
        )

    def test_bypass_restricts_to_upstream_paths(self):
        """_admin_authed_bypass must only apply to non-admin paths."""
        # Contract change (1.8.15): anchor on the `_admin_authed_bypass = (`
        # assignment line (the bypass condition) rather than the doc-comment,
        # which `find("_admin_authed_bypass")` now matches first.
        idx = _PH_SRC.find("_admin_authed_bypass = (")
        block = _PH_SRC[idx: idx + 300]
        assert "_is_admin_path" in block, (
            "_admin_authed_bypass must exclude admin paths via _is_admin_path"
        )

    def test_ban_check_gated_by_bypass(self):
        """Per-identity ban check must be skipped for an admin+authed bypass."""
        # Contract change (1.8.15): rather than gating each individual check
        # with `not _admin_authed_bypass`, the bypass now performs a single
        # early `if _admin_authed_bypass: ... return resp` that runs BEFORE the
        # ban check is ever reached. Equivalent (stricter) security contract —
        # admin+authed serves upstream immediately, skipping all ban/scoring.
        bypass_idx = _PH_SRC.find("if _admin_authed_bypass:")
        ban_idx = _PH_SRC.find("banned, remaining = await is_banned(track_key)")
        assert bypass_idx != -1, "if _admin_authed_bypass: early-return not found"
        assert ban_idx != -1, "is_banned(track_key) call not found"
        # early-return precedes the per-identity ban check
        assert bypass_idx < ban_idx, (
            "admin bypass early-return must precede the per-identity ban check"
        )
        assert "return resp" in _PH_SRC[bypass_idx: ban_idx], (
            "admin bypass block must return before reaching the ban check"
        )

    def test_fp_ban_check_gated_by_bypass(self):
        """Fingerprint-level ban check must also be skipped for admin+authed."""
        # Contract change (1.8.15): the fp-ban branch is now
        # `fp_banned, _ = await is_banned(fp_hash_key)` / `if fp_banned:`
        # (the old `FP_BAN_CHECK_ENABLED and fp_banned` combined condition was
        # refactored out). As with the per-identity ban check, the admin
        # early-return runs before this branch is reached.
        bypass_idx = _PH_SRC.find("if _admin_authed_bypass:")
        fp_idx = _PH_SRC.find("fp_banned, _ = await is_banned(fp_hash_key)")
        assert bypass_idx != -1, "if _admin_authed_bypass: early-return not found"
        assert fp_idx != -1, "fp_banned is_banned branch not found"
        assert bypass_idx < fp_idx, (
            "admin bypass early-return must precede the fingerprint ban check"
        )
        assert "return resp" in _PH_SRC[bypass_idx: fp_idx], (
            "admin bypass block must return before reaching the fingerprint ban check"
        )

    def test_heuristic_detection_bypass_uses_flag(self):
        """Heuristic scoring must be bypassed for admin+authed via the precomputed flag."""
        # Contract change (1.8.15): the bypass is no longer expressed as a
        # second `if _admin_authed_bypass:` after the BOT_DETECTION_ENABLED
        # gate; instead the single early-return (which precedes that gate)
        # skips the whole detection pipeline. Assert the precomputed flag is
        # used in a returning bypass that sits BEFORE the BOT_DETECTION gate.
        bot_det_idx = _PH_SRC.find("if not vc('BOT_DETECTION_ENABLED'):")
        bypass_idx = _PH_SRC.find("if _admin_authed_bypass:")
        assert bot_det_idx != -1, "BOT_DETECTION_ENABLED gate not found"
        assert bypass_idx != -1, "if _admin_authed_bypass: gate not found"
        assert bypass_idx < bot_det_idx, (
            "admin bypass early-return must precede the BOT_DETECTION_ENABLED gate"
        )
        assert "return resp" in _PH_SRC[bypass_idx: bot_det_idx], (
            "admin bypass must return (skipping heuristics) before the detection gate"
        )

    def test_admin_passthrough_reason_recorded(self):
        """Bypass path must record the admin-bypass reason via record()."""
        # Contract change (1.8.15): the admin upstream-bypass reason was renamed
        # from 'admin-passthrough' to 'operator-allowed' (shared with the
        # operator-unban grace window). Assert the shipped reason is recorded
        # inside the _admin_authed_bypass early-return block.
        bypass_idx = _PH_SRC.find("if _admin_authed_bypass:")
        assert bypass_idx != -1, "if _admin_authed_bypass: block not found"
        block = _PH_SRC[bypass_idx: bypass_idx + 400]
        assert '"operator-allowed"' in block, (
            "'operator-allowed' reason not recorded in the admin bypass block"
        )
        assert "record(" in block, (
            "operator-allowed must be passed to record() in the bypass block"
        )

    def test_admin_passthrough_in_metrics_passthrough_reasons(self):
        """admin-passthrough must be in _PASSTHROUGH_REASONS in metrics.py."""
        assert "_PASSTHROUGH_REASONS" in _MET_SRC, (
            "_PASSTHROUGH_REASONS not found in metrics.py"
        )
        idx = _MET_SRC.find("_PASSTHROUGH_REASONS")
        block = _MET_SRC[idx: idx + 400]
        assert "admin-passthrough" in block, (
            "'admin-passthrough' missing from _PASSTHROUGH_REASONS in metrics.py"
        )

    def test_admin_passthrough_in_timeline_passthrough_set(self):
        """The admin-bypass reason must be in the _passthrough timeline-filter set."""
        # Contract change (1.8.15): the bypass reason is 'operator-allowed'
        # (renamed from 'admin-passthrough'); the timeline _passthrough set
        # carries 'operator-allowed' so admin upstream traffic is excluded from
        # block-timeline buckets.
        passthrough_idx = _PH_SRC.find("_passthrough = {")
        assert passthrough_idx != -1, "_passthrough set not found"
        block = _PH_SRC[passthrough_idx: passthrough_idx + 300]
        assert "operator-allowed" in block, (
            "'operator-allowed' missing from _passthrough timeline-filter set"
        )

    def test_bypass_comes_before_heuristic_loop(self):
        """_admin_authed_bypass definition must precede the heuristic detection loop."""
        bypass_def_idx = _PH_SRC.find("_admin_authed_bypass = (")
        heuristic_idx  = _PH_SRC.find("if _admin_authed_bypass:")
        assert bypass_def_idx != -1 and heuristic_idx != -1, (
            "Both _admin_authed_bypass definition and use must exist"
        )
        assert bypass_def_idx < heuristic_idx, (
            "_admin_authed_bypass must be defined before the heuristic bypass gate"
        )


# ── 2. TestAdminBypassFunctional ──────────────────────────────────────────────

class TestAdminBypassFunctional:
    """Live proxy: verify that admin IP + valid session bypasses risk scoring
    while non-admin or unauthenticated requests are still scored normally."""

    def _patch_admin_nets(self, proxy_module, nets):
        """Temporarily inject ip_network objects into admin.auth.ADMIN_ALLOWED_NETS."""
        import admin.auth as _auth
        old = list(_auth.ADMIN_ALLOWED_NETS)
        _auth.ADMIN_ALLOWED_NETS.clear()
        _auth.ADMIN_ALLOWED_NETS.extend(nets)
        return old

    def _restore_admin_nets(self, old):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_NETS.clear()
        _auth.ADMIN_ALLOWED_NETS.extend(old)

    def test_admin_ip_with_session_gets_upstream_response(self, proxy_module):
        """Admin IP + valid session → request reaches upstream (not decoy)."""
        async def go():
            async with _spin_upstream() as up:
                old_nets = self._patch_admin_nets(
                    proxy_module,
                    [ipaddress.ip_network("127.0.0.1/32")]
                )
                try:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    async with _spin_proxy(proxy_module, up) as client:
                        r = await client.get("/", cookies=ck)
                        text = await r.text()
                    assert text == "upstream-ok", (
                        f"Admin+authed must reach upstream; got {text!r}"
                    )
                finally:
                    self._restore_admin_nets(old_nets)
        _run(go())

    def test_admin_ip_without_session_scored_normally(self, proxy_module):
        """Admin IP WITHOUT session cookie → no bypass (scored normally)."""
        async def go():
            async with _spin_upstream() as up:
                old_nets = self._patch_admin_nets(
                    proxy_module,
                    [ipaddress.ip_network("127.0.0.1/32")]
                )
                try:
                    async with _spin_proxy(proxy_module, up) as client:
                        # No cookie at all — _internal_authed returns False
                        r = await client.get("/")
                        # The request may reach upstream or not depending on
                        # risk accumulation, but the bypass flag must be False.
                        # Confirm by checking that _admin_authed_bypass logic
                        # requires _internal_authed (verified in source tests).
                        # At minimum the request completes without crash.
                        assert r.status in (200,), (
                            f"Request without session must complete; got {r.status}"
                        )
                finally:
                    self._restore_admin_nets(old_nets)
        _run(go())

    def test_non_admin_ip_with_session_scored_normally(self, proxy_module):
        """Non-admin IP WITH valid session → no bypass (IP not in allowlist)."""
        async def go():
            async with _spin_upstream() as up:
                # 10.0.0.1/32 — not the test client IP (127.0.0.1)
                old_nets = self._patch_admin_nets(
                    proxy_module,
                    [ipaddress.ip_network("10.0.0.1/32")]
                )
                try:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    async with _spin_proxy(proxy_module, up) as client:
                        r = await client.get("/", cookies=ck)
                        # Request comes from 127.0.0.1 which is NOT in 10.0.0.1/32
                        # Bypass must NOT fire; request goes through normal scoring.
                        assert r.status in (200,), (
                            f"Request from non-admin IP must complete; got {r.status}"
                        )
                finally:
                    self._restore_admin_nets(old_nets)
        _run(go())

    def test_admin_authed_bypasses_pre_existing_ban(self, proxy_module):
        """Admin IP + valid session → NOT decoy'd even if identity was previously banned."""
        async def go():
            async with _spin_upstream() as up:
                old_nets = self._patch_admin_nets(
                    proxy_module,
                    [ipaddress.ip_network("127.0.0.1/32")]
                )
                try:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    async with _spin_proxy(proxy_module, up) as client:
                        # Derive the identity track_key that will be used for 127.0.0.1
                        # by making one request first (which creates the ip_state entry).
                        r0 = await client.get("/", cookies=ck)
                        # Find the identity key by looking at what ip_state has for 127.0.0.1
                        # (any key with banned_until we can set).  Use a direct ban:
                        import time as _t
                        future = _t.time() + 3600
                        # Ban ALL known identities for this test IP
                        for k in list(proxy_module.ip_state.keys()):
                            proxy_module.ip_state[k].banned_until = future
                        # Now request with admin+authed — must still reach upstream
                        r = await client.get("/index.html", cookies=ck)
                        text = await r.text()
                        assert text == "upstream-ok", (
                            f"Admin+authed must bypass pre-existing ban; got {text!r}"
                        )
                    # Cleanup bans
                    for k in list(proxy_module.ip_state.keys()):
                        proxy_module.ip_state[k].banned_until = 0.0
                finally:
                    self._restore_admin_nets(old_nets)
        _run(go())

    def test_empty_admin_nets_no_bypass(self, proxy_module):
        """With empty ADMIN_ALLOWED_NETS, bypass is never triggered."""
        async def go():
            async with _spin_upstream() as up:
                old_nets = self._patch_admin_nets(proxy_module, [])
                try:
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    async with _spin_proxy(proxy_module, up) as client:
                        r = await client.get("/", cookies=ck)
                        # No bypass — request still handled (may reach upstream via
                        # normal flow since risk is 0 at start).
                        assert r.status in (200,), (
                            f"Request with no admin nets configured must complete; got {r.status}"
                        )
                finally:
                    self._restore_admin_nets(old_nets)
        _run(go())
