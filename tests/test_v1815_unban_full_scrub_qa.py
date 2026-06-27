"""
1.8.15 — QA coverage for the full-scrub Allow/Unban path.

Companion to test_v1815_unban_full_scrub.py (which proves the scrub itself).
This file widens the test surface:

  TestUnbanAuthGuards      — auth + CSRF rejection paths
  TestUnbanScopeGuards     — invalid args / method combos
  TestScrubVariants        — all=true, multi-identity, idempotency, bypass=0
  TestGraceSkipsScoring    — bypass window actually skips the scoring pipeline
  TestDBRowDeletion        — bans + ip_bans rows + clients.banned_until_epoch
  TestDashboardUXVisibility — Reset risk button visibility/wiring guards
"""
import asyncio
import pathlib
import sqlite3
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


_ROOT   = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_AG_SRC = (_ROOT / "dashboards" / "agents.html").read_text(encoding="utf-8")
_MN_SRC = (_ROOT / "dashboards" / "main.html").read_text(encoding="utf-8")


# ── Shared harness ──────────────────────────────────────────────────────────

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


def _seed_admin(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": time.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    cookie = proxy_module._session_sign("admin", sid=sid)
    return {proxy_module._SESSION_COOKIE: cookie}


@asynccontextmanager
async def _admin_ip_allowed(proxy_module):
    import admin.auth as _auth
    import ipaddress
    old_nets = list(_auth.ADMIN_ALLOWED_NETS)
    _auth.ADMIN_ALLOWED_NETS.clear()
    _auth.ADMIN_ALLOWED_NETS.append(ipaddress.ip_network("127.0.0.1/32"))
    try:
        yield
    finally:
        _auth.ADMIN_ALLOWED_NETS.clear()
        _auth.ADMIN_ALLOWED_NETS.extend(old_nets)


# ── 1. Auth + CSRF guards ───────────────────────────────────────────────────

class TestUnbanAuthGuards:
    """Allow/Unban endpoints must reject unauthenticated + bad-CSRF callers."""

    def test_post_with_wrong_csrf_rejected(self, proxy_module):
        """Authenticated session + wrong X-CSRF-Token → 403 CSRF."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.post(
                            "/antibot-appsec-gateway/secured/unban",
                            cookies=ck,
                            json={"all": True},
                            headers={"Content-Type": "application/json",
                                     "X-CSRF-Token": "wrong-value"},
                        )
                    assert r.status == 403, (
                        f"Bad CSRF must return 403; got {r.status}"
                    )
                    body = await r.json()
                    assert "CSRF" in (body.get("error") or ""), body
        _run(go())

    def test_bulk_unban_with_wrong_csrf_rejected(self, proxy_module):
        """Authenticated session + wrong CSRF on bulk endpoint → 403."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.post(
                            "/antibot-appsec-gateway/secured/bans",
                            cookies=ck,
                            json={"reason": "*"},
                            headers={"Content-Type": "application/json",
                                     "X-CSRF-Token": "wrong"},
                        )
                    assert r.status == 403, (
                        f"Bad CSRF on bulk must be 403; got {r.status}"
                    )
        _run(go())


# ── 2. Scope guards ─────────────────────────────────────────────────────────

class TestUnbanScopeGuards:
    """Argument-validation paths."""

    def test_get_all_rejected(self, proxy_module):
        """?all=1 via GET must return 405 (destructive op must be POST)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.get(
                            "/antibot-appsec-gateway/secured/unban?all=1",
                            cookies=ck,
                        )
                    assert r.status == 405, (
                        f"GET ?all=1 must be 405; got {r.status}"
                    )
                    body = await r.json()
                    assert "POST" in (body.get("error") or ""), body
        _run(go())

    def test_bulk_no_args_returns_400(self, proxy_module):
        """bulk unban with no reason and no asn → 400."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.delete(
                            "/antibot-appsec-gateway/secured/bans",
                            cookies=ck,
                        )
                    assert r.status == 400, (
                        f"empty args must be 400; got {r.status}"
                    )
                    body = await r.json()
                    assert "reason" in (body.get("error") or "").lower() or \
                           "asn" in (body.get("error") or "").lower(), body
        _run(go())

    def test_bulk_bad_asn_returns_400(self, proxy_module):
        """bulk unban with non-integer asn → 400."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.delete(
                            "/antibot-appsec-gateway/secured/bans?asn=not-a-number",
                            cookies=ck,
                        )
                    assert r.status == 400, (
                        f"bad asn must be 400; got {r.status}"
                    )
        _run(go())

    def test_unban_no_match_cleared_zero(self, proxy_module):
        """Unbanning an unknown id → cleared=0, no error."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.post(
                            "/antibot-appsec-gateway/secured/unban",
                            cookies=ck,
                            json={"id": "no-such-identity"},
                            headers={"Content-Type": "application/json"},
                        )
                        body = await r.json()
                    assert r.status == 200, body
                    assert body.get("cleared", -1) == 0, (
                        f"Unknown id must return cleared=0; got {body}"
                    )
        _run(go())


# ── 3. Scrub variants ───────────────────────────────────────────────────────

class TestScrubVariants:
    """Edge cases: all-scope, multi-identity, idempotency, bypass=0."""

    def test_all_true_scrubs_every_identity(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up,
                                       ALLOW_BYPASS_SECS=300) as client:
                    keys = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
                    for k in keys:
                        s = proxy_module.ip_state[k]
                        s.last_ip = k
                        s.banned_until = time.time() + 1800
                        s.risk_score = 90.0
                        s.risk_by_reason["ua-ai-curl"] = 90.0
                        s.blocks_by_reason["ua-ai-curl"] = 5
                        s.blocked_count = 5

                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.post(
                            "/antibot-appsec-gateway/secured/unban",
                            cookies=ck,
                            json={"all": True},
                            headers={"Content-Type": "application/json"},
                        )
                        body = await r.json()
                    assert r.status == 200, body
                    assert body.get("cleared", 0) >= 3, (
                        f"all=true must scrub every identity; cleared={body.get('cleared')}"
                    )
                    for k in keys:
                        s = proxy_module.ip_state[k]
                        assert s.risk_score == 0.0, f"{k}: risk_score not reset"
                        assert dict(s.risk_by_reason) == {}, (
                            f"{k}: risk_by_reason not cleared"
                        )
                        assert dict(s.blocks_by_reason) == {}, (
                            f"{k}: blocks_by_reason not cleared"
                        )
                        assert s.blocked_count == 0, f"{k}: blocked_count not reset"
        _run(go())

    def test_ip_scope_scrubs_multi_identity(self, proxy_module):
        """Unban by IP must scrub ALL identities whose last_ip matches."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    ip = "203.0.113.42"
                    id_keys = ["id-alpha", "id-beta", "id-gamma"]
                    for k in id_keys:
                        s = proxy_module.ip_state[k]
                        s.last_ip = ip
                        s.banned_until = time.time() + 600
                        s.risk_score = 70.0
                        s.risk_by_reason["fp-mismatch"] = 70.0
                        s.blocks_by_reason["fp-mismatch"] = 2
                        s.blocked_count = 2

                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.post(
                            "/antibot-appsec-gateway/secured/unban",
                            cookies=ck,
                            json={"ip": ip},
                            headers={"Content-Type": "application/json"},
                        )
                        body = await r.json()
                    assert r.status == 200, body
                    assert body.get("cleared", 0) >= 3, (
                        f"ip scope must match all 3 identities; got {body}"
                    )
                    for k in id_keys:
                        s = proxy_module.ip_state[k]
                        assert s.risk_score == 0.0
                        assert dict(s.risk_by_reason) == {}
                        assert dict(s.blocks_by_reason) == {}
                        assert s.blocked_count == 0
        _run(go())

    def test_idempotent_double_unban(self, proxy_module):
        """Calling unban twice → first cleared=1, second cleared=1 (idempotent
        — same id is still in ip_state, just already-zero). State stays scrubbed."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    key = "192.0.2.200"
                    s = proxy_module.ip_state[key]
                    s.last_ip = key
                    s.banned_until = time.time() + 600
                    s.risk_score = 65.0
                    s.risk_by_reason["honey-cred"] = 65.0

                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        for _ in range(2):
                            r = await client.post(
                                "/antibot-appsec-gateway/secured/unban",
                                cookies=ck,
                                json={"ip": key},
                                headers={"Content-Type": "application/json"},
                            )
                            body = await r.json()
                            assert r.status == 200, body
                            # ip-scope match doesn't depend on banned_until,
                            # so second call still matches the identity.
                            assert body.get("cleared", 0) >= 1, body
                            assert s.risk_score == 0.0
                            assert dict(s.risk_by_reason) == {}
        _run(go())

    def test_bypass_zero_still_scrubs_breakdown(self, proxy_module):
        """ALLOW_BYPASS_SECS=0 disables grace but MUST still scrub reasons."""
        async def go():
            # unban_endpoint reads core.proxy_handler.ALLOW_BYPASS_SECS, which is
            # a DIFFERENT module binding from proxy.ALLOW_BYPASS_SECS that
            # _spin_proxy's setattr(proxy_module, ...) mutates. Set the value on
            # the module the endpoint actually reads (and restore after) so the
            # ALLOW_BYPASS_SECS=0 override is honoured.
            import core.proxy_handler as _ph
            _old_bypass = _ph.ALLOW_BYPASS_SECS
            _ph.ALLOW_BYPASS_SECS = 0
            try:
                await _go_inner()
            finally:
                _ph.ALLOW_BYPASS_SECS = _old_bypass

        async def _go_inner():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up,
                                       ALLOW_BYPASS_SECS=0) as client:
                    key = "192.0.2.201"
                    s = proxy_module.ip_state[key]
                    s.last_ip = key
                    s.banned_until = time.time() + 600
                    s.risk_score = 55.0
                    s.risk_by_reason["redirect-maze"] = 55.0
                    s.blocks_by_reason["redirect-maze"] = 4
                    s.blocked_count = 4

                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.post(
                            "/antibot-appsec-gateway/secured/unban",
                            cookies=ck,
                            json={"ip": key},
                            headers={"Content-Type": "application/json"},
                        )
                        body = await r.json()
                    assert r.status == 200, body
                    assert body.get("bypass_secs") == 0, (
                        f"bypass_secs must be 0 when ALLOW_BYPASS_SECS=0; got {body}"
                    )
                    # Scrub still happens regardless of bypass setting
                    assert s.risk_score == 0.0
                    assert dict(s.risk_by_reason) == {}
                    assert dict(s.blocks_by_reason) == {}
                    assert s.blocked_count == 0
                    assert s.bypass_until == 0.0, (
                        "bypass_until must NOT be set when ALLOW_BYPASS_SECS=0"
                    )
        _run(go())


# ── 4. Grace window actually skips scoring pipeline ─────────────────────────

class TestGraceSkipsScoring:
    """After unban grants a grace window, scoring pipeline is skipped in
    protect() — verified via the source-code structure (the functional path
    requires a full request lifecycle which is covered elsewhere)."""

    def test_protect_checks_bypass_before_scoring(self):
        """protect() must check bypass_until BEFORE the scoring detectors fire."""
        # Locate the protect() bypass gate
        bg_idx = _PH_SRC.find("operator-granted bypass window")
        assert bg_idx != -1, "Bypass-window comment missing in protect()"
        # Find first scoring call after the bypass gate
        scoring_idx = _PH_SRC.find("update_risk_and_maybe_ban", bg_idx)
        assert scoring_idx != -1
        # The gate must be physically before the first scoring call
        gate_check = _PH_SRC.find("bypass_until", bg_idx)
        assert gate_check < scoring_idx, (
            "bypass_until gate must precede the scoring pipeline in protect()"
        )

    def test_operator_allowed_recorded_during_bypass(self):
        """During bypass, record() must log reason='operator-allowed'."""
        bg_idx = _PH_SRC.find("operator-granted bypass window")
        nxt    = _PH_SRC.find("update_risk_and_maybe_ban", bg_idx)
        block  = _PH_SRC[bg_idx:nxt]
        assert "operator-allowed" in block, (
            "Bypass path must record reason='operator-allowed' so SIEM/missed "
            "dashboards can distinguish operator-allowed traffic from organic"
        )


# ── 5. DB row deletion ─────────────────────────────────────────────────────

class TestDBRowDeletion:
    """unban must wipe DB rows: bans, ip_bans, clients.banned_until_epoch."""

    def test_db_rows_deleted_after_ip_unban(self, proxy_module, tmp_path):
        """Seed bans + ip_bans + clients rows for an IP, unban, assert all gone."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as client:
                    ip = "192.0.2.123"

                    # Seed DB rows through the gateway's own backend-aware
                    # connection. The unban endpoint scrubs via db.open_conn()
                    # (PG in PG-only mode, SQLite otherwise), so the test must
                    # seed + verify against the SAME backend — a raw
                    # sqlite3.connect(DB_PATH) seeds an unused local file in
                    # PG-only mode and the assertions never reflect the real
                    # scrub. (1.9.1 iter-18 backend-aware reads.)
                    from db import open_conn as _open_conn
                    # Clear any pre-existing rows first (INSERT OR REPLACE is
                    # SQLite-only; explicit DELETE+INSERT is dialect-neutral and
                    # the open_conn wrapper rewrites ? → %s on PG).
                    conn = _open_conn()
                    for _tbl in ("bans", "ip_bans"):
                        conn.execute(f"DELETE FROM {_tbl} WHERE ip=?", (ip,))
                    conn.execute("DELETE FROM clients WHERE ip=?", (ip,))
                    conn.execute(
                        "INSERT INTO bans(ip, banned_until, reason, ts) "
                        "VALUES (?, ?, ?, ?)",
                        (ip, time.time() + 3600, "manual-ban", time.time()),
                    )
                    conn.execute(
                        "INSERT INTO ip_bans(ip, banned_until, reason, ts) "
                        "VALUES (?, ?, ?, ?)",
                        (ip, time.time() + 3600, "hard-ban", time.time()),
                    )
                    conn.execute(
                        "INSERT INTO clients(ip, first_seen, last_seen, "
                        "banned_until_epoch) VALUES (?, ?, ?, ?)",
                        (ip, time.time(), time.time(), time.time() + 3600),
                    )
                    conn.commit()
                    conn.close()

                    # Also seed in-memory so match by ip works
                    s = proxy_module.ip_state[ip]
                    s.last_ip = ip
                    s.banned_until = time.time() + 3600
                    s.risk_score = 75.0

                    ck = _seed_admin(proxy_module)
                    async with _admin_ip_allowed(proxy_module):
                        r = await client.post(
                            "/antibot-appsec-gateway/secured/unban",
                            cookies=ck,
                            json={"ip": ip},
                            headers={"Content-Type": "application/json"},
                        )
                    assert r.status == 200, await r.text()

                    # Verify DB rows wiped — read back via the SAME backend.
                    conn = _open_conn()
                    bans_rows = conn.execute(
                        "SELECT 1 FROM bans WHERE ip=?", (ip,)
                    ).fetchall()
                    ipbans_rows = conn.execute(
                        "SELECT 1 FROM ip_bans WHERE ip=?", (ip,)
                    ).fetchall()
                    client_row = conn.execute(
                        "SELECT banned_until_epoch FROM clients WHERE ip=?", (ip,)
                    ).fetchone()
                    conn.close()

                    assert bans_rows == [], f"bans row not deleted for {ip}"
                    assert ipbans_rows == [], f"ip_bans row not deleted for {ip}"
                    assert client_row is not None
                    assert client_row[0] == 0, (
                        f"clients.banned_until_epoch must be 0; got {client_row[0]}"
                    )
        _run(go())


# ── 6. Dashboard UX visibility guards ───────────────────────────────────────

class TestDashboardUXVisibility:
    """The Reset risk button must only render when risk_score > 0 and must
    fall back to ip when id is absent (data-reset-ip path)."""

    def test_agents_button_gated_on_positive_risk(self):
        """agents.html buildRiskHtml must gate Reset button on risk_score > 0."""
        # data-reset-id appears only in the JS template literal, not CSS.
        idx = _AG_SRC.find("data-reset-id")
        assert idx != -1, "data-reset-id template missing"
        ctx_start = max(0, idx - 400)
        ctx = _AG_SRC[ctx_start: idx]
        assert "risk_score > 0" in ctx or "risk_score>0" in ctx, (
            "agents.html Reset button must be gated on d.risk_score > 0"
        )

    def test_main_button_gated_on_positive_risk(self):
        idx = _MN_SRC.find("data-reset-id")
        assert idx != -1, "data-reset-id template missing"
        ctx_start = max(0, idx - 400)
        ctx = _MN_SRC[ctx_start: idx]
        assert "risk_score > 0" in ctx or "risk_score>0" in ctx, (
            "main.html Reset button must be gated on d.risk_score > 0"
        )

    def test_agents_button_has_ip_fallback(self):
        """Reset button must carry data-reset-ip for id-less identities."""
        assert "data-reset-ip" in _AG_SRC, (
            "agents.html Reset button must include data-reset-ip fallback"
        )

    def test_main_button_has_ip_fallback(self):
        assert "data-reset-ip" in _MN_SRC, (
            "main.html Reset button must include data-reset-ip fallback"
        )

    def test_agents_handler_falls_back_to_ip(self):
        """Handler must POST {id} if id present else {ip} (parity w/ Unban)."""
        idx = _AG_SRC.find("querySelectorAll('.gw-reset-risk')")
        assert idx != -1
        block = _AG_SRC[idx: idx + 2000]
        assert "data-reset-id" in block, "Handler must read data-reset-id"
        assert "data-reset-ip" in block, "Handler must read data-reset-ip"
        assert "id ? {id:id}" in block or "{id:id}" in block, (
            "Handler must build {id} payload when id present"
        )
        assert "{ip:ip}" in block, (
            "Handler must build {ip} payload as fallback"
        )

    def test_agents_handler_confirm_prompt(self):
        """Handler must confirm() before destructive call (UX guardrail)."""
        idx = _AG_SRC.find("querySelectorAll('.gw-reset-risk')")
        block = _AG_SRC[idx: idx + 2000]
        assert "window.confirm" in block, (
            "Reset risk must require window.confirm() — destructive op"
        )

    def test_main_handler_confirm_prompt(self):
        idx = _MN_SRC.find("querySelectorAll('.gw-reset-risk')")
        block = _MN_SRC[idx: idx + 2000]
        assert "window.confirm" in block, (
            "main.html Reset risk must require window.confirm() — destructive op"
        )

    def test_css_class_declared_both_dashboards(self):
        """.gw-reset-risk CSS rule present (for visual affordance)."""
        for src, name in [(_AG_SRC, "agents.html"), (_MN_SRC, "main.html")]:
            assert ".gw-reset-risk{" in src, (
                f"{name} must declare .gw-reset-risk CSS rule"
            )
            assert ".gw-reset-risk:hover" in src, (
                f"{name} must declare .gw-reset-risk:hover for affordance"
            )
            assert ".gw-reset-risk:disabled" in src, (
                f"{name} must declare .gw-reset-risk:disabled for in-flight state"
            )
