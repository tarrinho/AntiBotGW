"""
tests/test_v198_tier1_security_qa.py — functional QA for the 1.9.8 Tier-1
security hardening.

The existing test_v1814_qa_security.py / test_v1814_review_fixes.py assertions
are SOURCE-INSPECTION (they grep the source for the control). These are
BEHAVIOURAL: they spin a real gateway and prove the control actually fires —
viewer gets 403, an unauthenticated caller gets 401, a CSRF-less POST is
rejected, the readable CSRF cookie is scoped off the upstream surface, and an
oversized 2FA token is refused. Scrypt-bound + partial-token UNIT coverage lives
in test_v1814_qa_security_runtime.py; this file adds the end-to-end view.

Reuses the standard functional scaffold from test_control_regressions.
"""
import os

os.environ.setdefault("UPSTREAM", "http://localhost")

from aiohttp.test_utils import make_mocked_request

from tests.test_control_regressions import (  # noqa: E402
    _spin_proxy, _spin_upstream, _run, _admin_cookie, _csrf_hdr,
)

_NS = "/antibot-appsec-gateway"
_SEC = _NS + "/secured"


# ── helper: mint a session for an arbitrary username/role ─────────────────────
def _session_cookie(proxy_module, username):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": username,
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return sid, {proxy_module._SESSION_COOKIE: proxy_module._session_sign(username, sid=sid)}


# ═══════════════════════════════════════════════════════════════════════════
# S-W2 — mesh-sync state requires admin/maintainer (viewers blocked)
# ═══════════════════════════════════════════════════════════════════════════
class TestMeshSyncRbacBehavioral:
    def test_viewer_gets_403(self, proxy_module):
        # _request_role does `from admin.users import _user_load` at call time,
        # so the role source to stub is admin.users._user_load.
        import admin.users as _u
        orig = _u._user_load

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    sid, ck = _session_cookie(proxy_module, "viewer-user")
                    _u._user_load = lambda u: ({"role": "viewer"}
                                               if u == "viewer-user" else None)
                    try:
                        r = await c.get(_SEC + "/admin/mesh-sync", cookies=ck)
                        assert r.status == 403, f"viewer must be 403, got {r.status}"
                    finally:
                        _u._user_load = orig
                        proxy_module._SESSION_CACHE.pop(sid, None)
        _run(go())

    def test_admin_gets_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = _admin_cookie(proxy_module)   # no _user_load row → role 'admin'
                    r = await c.get(_SEC + "/admin/mesh-sync", cookies=ck)
                    assert r.status == 200, f"admin must reach mesh-sync, got {r.status}"
                    body = await r.json()
                    assert "enabled_keys" in body
        _run(go())

    def test_maintainer_gets_200(self, proxy_module):
        import admin.users as _u
        orig = _u._user_load

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    sid, ck = _session_cookie(proxy_module, "maint-user")
                    _u._user_load = lambda u: ({"role": "maintainer"}
                                               if u == "maint-user" else None)
                    try:
                        r = await c.get(_SEC + "/admin/mesh-sync", cookies=ck)
                        assert r.status == 200, f"maintainer must reach mesh-sync, got {r.status}"
                    finally:
                        _u._user_load = orig
                        proxy_module._SESSION_CACHE.pop(sid, None)
        _run(go())


# ═══════════════════════════════════════════════════════════════════════════
# LIVE-1 / LIVE-2 — ip-intel + whoami enforce _internal_authed
# ═══════════════════════════════════════════════════════════════════════════
class TestInternalAuthGatesBehavioral:
    def test_whoami_handler_rejects_unauthenticated(self):
        """Direct handler call with no session cookie → 401 (the in-handler
        defence-in-depth gate, independent of the protect() middleware)."""
        from admin.users import whoami_endpoint
        req = make_mocked_request("GET", _SEC + "/whoami")
        resp = _run(whoami_endpoint(req))
        assert resp.status == 401

    def test_ip_intel_handler_rejects_unauthenticated(self):
        from admin.users import ip_intel_endpoint
        req = make_mocked_request("GET", _SEC + "/ip-intel/1.2.3.4",
                                  match_info={"ip": "1.2.3.4"})
        resp = _run(ip_intel_endpoint(req))
        assert resp.status == 401, "auth gate must fire before IP parsing"

    def test_whoami_authed_admin_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = _admin_cookie(proxy_module)
                    r = await c.get(_SEC + "/whoami", cookies=ck)
                    assert r.status == 200, f"authed whoami got {r.status}"
        _run(go())

    def test_ip_intel_authed_admin_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = _admin_cookie(proxy_module)
                    r = await c.get(_SEC + "/ip-intel/8.8.8.8", cookies=ck)
                    assert r.status == 200, f"authed ip-intel got {r.status}"
                    body = await r.json()
                    assert body.get("ip") == "8.8.8.8"
        _run(go())


# ═══════════════════════════════════════════════════════════════════════════
# M4 — 2FA setup requires POST + CSRF (was an unrouted GET)
# ═══════════════════════════════════════════════════════════════════════════
class TestTotpSetupCsrfBehavioral:
    def test_post_with_invalid_csrf_rejected(self, proxy_module):
        # The autouse conftest shim auto-injects a VALID X-CSRF-Token when none
        # is present, so to exercise the @_require_csrf rejection path we send an
        # explicitly bogus token (the shim leaves an existing header untouched).
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = _admin_cookie(proxy_module)
                    r = await c.post(_SEC + "/2fa-setup", cookies=ck,
                                     headers={"X-CSRF-Token": "definitely-not-valid"})
                    assert r.status == 403, f"invalid-CSRF POST must be 403, got {r.status}"
        _run(go())

    def test_post_with_csrf_succeeds(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = _admin_cookie(proxy_module)
                    hdr = _csrf_hdr(proxy_module, ck)
                    r = await c.post(_SEC + "/2fa-setup", cookies=ck, headers=hdr)
                    assert r.status == 200, f"authed+csrf POST got {r.status}"
                    body = await r.json()
                    assert "qr_data_url" in body
        _run(go())

    def test_get_does_not_serve_the_secret(self, proxy_module):
        """Route is POST-only now. A GET is not handled by totp_setup_endpoint
        (the gateway treats it as a normal passthrough), so it must never return
        a provisioning URI / QR — i.e. no TOTP secret is generated via GET."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = _admin_cookie(proxy_module)
                    r = await c.get(_SEC + "/2fa-setup", cookies=ck)
                    text = await r.text()
                    assert "qr_data_url" not in text and "provisioning_uri" not in text, \
                        "GET /2fa-setup must not generate/leak a TOTP secret"
        _run(go())


# ═══════════════════════════════════════════════════════════════════════════
# M1 — agw_csrf readable cookie scoped to ADMIN_NS (off the upstream surface)
# ═══════════════════════════════════════════════════════════════════════════
class TestAgwCsrfCookieScopeBehavioral:
    def test_logout_scopes_agw_csrf_to_admin_ns(self, proxy_module):
        """logout deletes agw_csrf with Path=ADMIN_NS, never Path=/, so the
        readable token never travels to the proxied upstream."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = _admin_cookie(proxy_module)
                    hdr = _csrf_hdr(proxy_module, ck)
                    r = await c.post(_NS + "/logout", cookies=ck, headers=hdr,
                                     allow_redirects=False)
                    setc = "\n".join(r.headers.getall("Set-Cookie", []))
                    agw = [ln for ln in setc.splitlines() if ln.startswith("agw_csrf")]
                    assert agw, f"no agw_csrf Set-Cookie on logout: {setc!r}"
                    line = agw[0]
                    assert "/antibot-appsec-gateway" in line, \
                        f"agw_csrf must be scoped to ADMIN_NS: {line!r}"
                    # must NOT be the root path (would reach the upstream)
                    assert "Path=/;" not in line and not line.rstrip().endswith("Path=/"), \
                        f"agw_csrf must not use Path=/: {line!r}"
        _run(go())


# ═══════════════════════════════════════════════════════════════════════════
# S-W5 — oversized 2FA partial_token refused end-to-end (400)
# ═══════════════════════════════════════════════════════════════════════════
class TestPartialTokenLengthBehavioral:
    def test_oversized_token_returns_400_invalid_format(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.post(_NS + "/login/totp",
                                     json={"partial_token": "A" * 65, "code": "123456"})
                    assert r.status == 400, f"oversized token must be 400, got {r.status}"
                    body = await r.json()
                    assert "invalid token format" in (body.get("error") or "")
        _run(go())
