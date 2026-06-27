"""
1.9.7 — Vhost Policy apply-flow QA
==================================

Broader QA around the "Apply changes" → POST /__vhosts write path, beyond the
core regression in `test_v197_vhost_policy_upstream_inherit.py`:

  Q1 frontend: the global-UPSTREAM inherit is CONDITIONAL — an explicit UPSTREAM
     override must be preserved, not clobbered by the global default.
  Q2 multiple policy knobs in a single Apply all persist (the "N unsaved
     changes" case from the dashboard).
  Q3 the exact reported scenario: a vhost with NO overrides + a Bot Detection
     toggle (carrying the inherited UPSTREAM) is accepted end-to-end.
  Q4 the remove-override path keeps the registry entry valid (still inherits
     UPSTREAM) and drops only the targeted knob.
  Q5 a policy override round-trips: POST it, then read it back via vhost_list.
  Q6 frontend: Apply posts to /__vhosts and the unsaved-changes bar is wired to
     the Apply handler (the surface the user clicked).
"""
import asyncio
import re
from contextlib import asynccontextmanager
from pathlib import Path

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

NS = "/antibot-appsec-gateway/secured"
_VP = (Path(__file__).resolve().parent.parent / "dashboards" / "vhost_policy.html").read_text(encoding="utf-8")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _echo(request):
    return web.json_response({"ok": True})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_route("*", "/{t:.*}", _echo)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    client = TestClient(TestServer(proxy_module.make_app()))
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()


def _admin_cookie(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


async def _post_vhost(proxy_module, client, payload):
    return await client.post(
        f"{NS}/vhosts", json=payload,
        cookies={proxy_module._SESSION_COOKIE: _admin_cookie(proxy_module)},
    )


def _fn_body(name):
    i = _VP.index("function " + name + "(")
    seg, depth = _VP[i:], 0
    for j, ch in enumerate(seg):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return seg[: j + 1]
    return seg


# ── Q1 — explicit UPSTREAM override preserved (inherit only fills when absent) ─
def test_q1_inherit_is_conditional_not_clobbering():
    body = _fn_body("_buildVhostPayload")
    # Must be guarded by `if(!merged.UPSTREAM)` — an unconditional assignment
    # would overwrite a user's explicit per-vhost upstream with the global.
    assert re.search(r"if\s*\(\s*!\s*merged\.UPSTREAM\s*\)\s*merged\.UPSTREAM\s*=\s*_globalVals\.UPSTREAM", body), \
        "the global-UPSTREAM inherit must be conditional (if(!merged.UPSTREAM)), never clobber an explicit override"


def test_q1b_explicit_upstream_override_is_stored(proxy_module):
    async def go():
        import vhost as _v
        _v.VHOSTS.pop("explicit.example.com", None)
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await _post_vhost(proxy_module, c, {
                    "hostname": "explicit.example.com",
                    "UPSTREAM": "https://explicit-upstream.example.com",
                    "BOT_DETECTION_ENABLED": False})
                assert r.status in (200, 201), await r.text()
                assert _v.VHOSTS["explicit.example.com"]["UPSTREAM"] == "https://explicit-upstream.example.com"
        _v.VHOSTS.pop("explicit.example.com", None)
    _run(go())


# ── Q2 — multiple policy knobs in one Apply all persist ───────────────────────
def test_q2_multiple_policy_knobs_persist(proxy_module):
    async def go():
        import vhost as _v
        _v.VHOSTS.pop("multi.example.com", None)
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await _post_vhost(proxy_module, c, {
                    "hostname": "multi.example.com",
                    "UPSTREAM": "https://example.com",
                    "BOT_DETECTION_ENABLED": False,
                    "BYPASS_MODE": True})
                assert r.status in (200, 201), await r.text()
                ov = _v.VHOSTS["multi.example.com"]
                assert ov.get("BOT_DETECTION_ENABLED") is False
                assert ov.get("BYPASS_MODE") is True
        _v.VHOSTS.pop("multi.example.com", None)
    _run(go())


# ── Q3 — the exact reported scenario: no-override vhost + bot toggle ──────────
def test_q3_reported_scenario_policy_only_with_inherited_upstream(proxy_module):
    """A vhost with NO prior overrides + a Bot Detection toggle, carrying the
    inherited global UPSTREAM (what the fixed Apply button sends) → accepted."""
    async def go():
        import vhost as _v
        host = "may-challenge.example.com"
        _v.VHOSTS.pop(host, None)
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                # _globalVals.UPSTREAM carries the PUBLIC global default
                # (e.g. the demo's https://www.celfocus.com) — use a public value,
                # not the loopback test upstream (which is correctly rejected as
                # private when ALLOW_PRIVATE_UPSTREAM=0).
                r = await _post_vhost(proxy_module, c, {
                    "hostname": host,
                    "UPSTREAM": "https://example.com",
                    "BOT_DETECTION_ENABLED": False})
                assert r.status in (200, 201), await r.text()
                assert host in _v.VHOSTS
        _v.VHOSTS.pop(host, None)
    _run(go())


# ── Q4 — remove-override path keeps the entry valid ───────────────────────────
def test_q4_remove_override_keeps_entry_valid(proxy_module):
    """Mirrors _saveRemove(): re-POST the remaining overrides (+ inherited
    UPSTREAM) without the removed knob → vhost still valid, knob gone."""
    async def go():
        import vhost as _v
        host = "removal.example.com"
        _v.VHOSTS.pop(host, None)
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                # start with two overrides
                r = await _post_vhost(proxy_module, c, {
                    "hostname": host, "UPSTREAM": "https://example.com",
                    "BOT_DETECTION_ENABLED": False, "BYPASS_MODE": True})
                assert r.status in (200, 201), await r.text()
                # "remove" BYPASS_MODE → re-post remaining + inherited UPSTREAM
                r2 = await _post_vhost(proxy_module, c, {
                    "hostname": host, "UPSTREAM": "https://example.com",
                    "BOT_DETECTION_ENABLED": False})
                assert r2.status in (200, 201), await r2.text()
                ov = _v.VHOSTS[host]
                assert ov.get("BOT_DETECTION_ENABLED") is False
                assert "BYPASS_MODE" not in ov, "removed knob must be gone"
        _v.VHOSTS.pop(host, None)
    _run(go())


# ── Q5 — round-trip: POST then read back via list ─────────────────────────────
def test_q5_policy_override_roundtrips_through_list(proxy_module):
    async def go():
        import vhost as _v
        host = "roundtrip.example.com"
        _v.VHOSTS.pop(host, None)
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                cookie = _admin_cookie(proxy_module)
                r = await _post_vhost(proxy_module, c, {
                    "hostname": host, "UPSTREAM": "https://example.com",
                    "BOT_DETECTION_ENABLED": False})
                assert r.status in (200, 201), await r.text()
                g = await c.get(f"{NS}/vhosts",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert g.status == 200
                listing = (await g.json()).get("vhosts", [])
                item = next((x for x in listing if x.get("hostname") == host), None)
                assert item is not None, "posted vhost must appear in the list"
                assert item.get("BOT_DETECTION_ENABLED") is False
        _v.VHOSTS.pop(host, None)
    _run(go())


# ── Q6 — the surface the user clicked is wired to /__vhosts ────────────────────
def test_q6_apply_button_wired_to_vhosts_post():
    assert "getElementById('btn-apply').addEventListener('click',_applyChanges)" in _VP, \
        "the Apply button must invoke _applyChanges"
    apply_body = _fn_body("_applyChanges")
    assert "ADMIN_NS+'/vhosts'" in apply_body and "_buildVhostPayload()" in apply_body, \
        "_applyChanges must POST _buildVhostPayload() to /__vhosts"
