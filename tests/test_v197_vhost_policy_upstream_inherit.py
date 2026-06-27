"""
1.9.7 — Vhost Policy "Apply changes" must inherit the global UPSTREAM
====================================================================

Bug: applying a POLICY-ONLY override (e.g. a Bot Detection toggle) on a vhost
with no upstream override raised **"UPSTREAM required"**. The `/__vhosts` POST
requires an UPSTREAM on every write; the dashboard's two save paths handled this
inconsistently — `_saveRemove()` inherited the global UPSTREAM, but
`_buildVhostPayload()` (used by the Apply button) did not, so its payload had no
UPSTREAM and the backend rejected it.

Fix: `_buildVhostPayload()` now defaults `merged.UPSTREAM = _globalVals.UPSTREAM`
when absent, mirroring `_saveRemove()`.

Coverage
────────
Frontend (source-anchor):
  • both save paths inherit the global UPSTREAM (no asymmetry can return).
Backend contract (functional, HTTP):
  • POST /secured/vhosts WITHOUT UPSTREAM → 400 "UPSTREAM required"
    (documents why the frontend MUST inherit).
  • POST WITH UPSTREAM + a policy knob (what the fixed frontend sends) → ok,
    and the policy override is stored on the vhost.
"""
import asyncio
import re
import sqlite3  # noqa: F401  (parity with sibling vhost tests / fixture env)
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


# ── frontend source-anchor ───────────────────────────────────────────────────
def _fn_body(name):
    i = _VP.index("function " + name + "(")
    seg = _VP[i:]
    # crude brace match to the function's closing brace
    depth = 0
    for j, ch in enumerate(seg):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return seg[: j + 1]
    return seg


def test_buildvhostpayload_inherits_global_upstream():
    body = _fn_body("_buildVhostPayload")
    assert re.search(r"UPSTREAM\s*=\s*_globalVals\.UPSTREAM", body), \
        "_buildVhostPayload must default UPSTREAM to the global value (else policy-only Apply → 'UPSTREAM required')"


def test_both_save_paths_inherit_consistently():
    # The bug was an asymmetry: _saveRemove inherited, _buildVhostPayload did not.
    for fn in ("_buildVhostPayload", "_saveRemove"):
        assert re.search(r"UPSTREAM\s*=\s*_globalVals\.UPSTREAM", _fn_body(fn)), \
            f"{fn} must inherit the global UPSTREAM so every /__vhosts write stays valid"


# ── backend contract (functional) ────────────────────────────────────────────
def test_vhosts_post_without_upstream_rejected(proxy_module):
    """Documents the rule the frontend must satisfy: a vhost write with no
    UPSTREAM is rejected with the exact 'UPSTREAM required' error."""
    async def go():
        import vhost as _v
        _v.VHOSTS.pop("policyonly.example.com", None)
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.post(
                    f"{NS}/vhosts",
                    json={"hostname": "policyonly.example.com",
                          "BOT_DETECTION_ENABLED": False},  # policy knob, no UPSTREAM
                    cookies={proxy_module._SESSION_COOKIE: _admin_cookie(proxy_module)},
                )
                assert r.status == 400, f"expected 400, got {r.status}"
                d = await r.json()
                assert d.get("error") == "UPSTREAM required", d
    _run(go())


def test_vhosts_post_with_inherited_upstream_and_policy_succeeds(proxy_module):
    """What the FIXED frontend sends: the policy knob + the inherited global
    UPSTREAM → accepted, and the policy override is stored on the vhost."""
    async def go():
        import vhost as _v
        _v.VHOSTS.pop("policyok.example.com", None)
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.post(
                    f"{NS}/vhosts",
                    json={"hostname": "policyok.example.com",
                          "UPSTREAM": "https://example.com",      # inherited global
                          "BOT_DETECTION_ENABLED": False},
                    cookies={proxy_module._SESSION_COOKIE: _admin_cookie(proxy_module)},
                )
                assert r.status in (200, 201), f"expected ok, got {r.status}: {await r.text()}"
                assert "policyok.example.com" in _v.VHOSTS
                assert _v.VHOSTS["policyok.example.com"].get("BOT_DETECTION_ENABLED") is False
        _v.VHOSTS.pop("policyok.example.com", None)
    _run(go())
