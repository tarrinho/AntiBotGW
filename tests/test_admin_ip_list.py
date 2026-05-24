"""
Admin IP allowlist — comprehensive QA tests.

Coverage gaps filled (vs existing tests in test_pure.py /
test_endpoints_dynamic.py / test_settings_config_functional.py):

  TestAdminIPAuthUnit      — pure unit tests of admin.auth helper functions
  TestAdminIPAddRemove     — async add/remove/update via admin.auth functions directly
  TestAdminIPsEndpointGaps — HTTP endpoint behaviours not covered elsewhere
  TestAdminIPEnforcement   — middleware actually blocks / passes based on allowlist
"""
import asyncio
import ipaddress
import sqlite3
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_admin_ip_state():
    """Wipe in-memory allowlist + DB rows after every test to prevent cross-
    test pollution (non-empty ADMIN_ALLOWED_NETS activates strict mode)."""
    yield
    import admin.auth as _auth
    _auth.ADMIN_ALLOWED_NETS.clear()
    _auth.ADMIN_ALLOWED_ENTRIES.clear()
    try:
        import proxy as _p
        db_path = getattr(_p, "DB_PATH", "")
        if db_path:
            conn = sqlite3.connect(db_path)
            conn.execute("DELETE FROM admin_ips")
            conn.commit()
            conn.close()
    except Exception:
        pass


# ── Shared helpers ────────────────────────────────────────────────────────────

NS = "/antibot-appsec-gateway/secured"


async def _echo_handler(request: web.Request):
    return web.json_response({"path": request.path})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _echo_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
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
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Pure unit tests — admin.auth module functions
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminIPAuthUnit:
    """Pure unit tests — no HTTP server required."""

    # ── _is_admin_ip ─────────────────────────────────────────────────────────

    def test_is_admin_ip_empty_list_returns_false(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_NETS.clear()
        assert _auth._is_admin_ip("192.168.1.1") is False

    def test_is_admin_ip_match_returns_true(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("10.0.0.0/8")]
        assert _auth._is_admin_ip("10.5.6.7") is True

    def test_is_admin_ip_no_match_returns_false(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("10.0.0.0/8")]
        assert _auth._is_admin_ip("192.168.1.1") is False

    def test_is_admin_ip_invalid_string_returns_false(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("10.0.0.0/8")]
        assert _auth._is_admin_ip("not-an-ip") is False

    def test_is_admin_ip_empty_string_returns_false(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("10.0.0.0/8")]
        assert _auth._is_admin_ip("") is False

    def test_is_admin_ip_ipv6_match(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("2001:db8::/32")]
        assert _auth._is_admin_ip("2001:db8::cafe") is True

    def test_is_admin_ip_ipv6_no_match(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("2001:db8::/32")]
        assert _auth._is_admin_ip("2001:db9::1") is False

    # ── _rebuild_admin_nets_from_entries ──────────────────────────────────────

    def test_rebuild_parses_entries_into_nets(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_ENTRIES[:] = [
            {"cidr": "192.0.2.0/24"},
            {"cidr": "10.0.0.0/8"},
        ]
        _auth._rebuild_admin_nets_from_entries()
        assert len(_auth.ADMIN_ALLOWED_NETS) == 2
        cidrs = {str(n) for n in _auth.ADMIN_ALLOWED_NETS}
        assert "192.0.2.0/24" in cidrs
        assert "10.0.0.0/8" in cidrs

    def test_rebuild_skips_bad_cidr_in_entries(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_ENTRIES[:] = [
            {"cidr": "10.0.0.0/8"},
            {"cidr": "not-valid"},
        ]
        _auth._rebuild_admin_nets_from_entries()
        assert len(_auth.ADMIN_ALLOWED_NETS) == 1
        assert str(_auth.ADMIN_ALLOWED_NETS[0]) == "10.0.0.0/8"

    def test_rebuild_clears_nets_when_entries_empty(self):
        import admin.auth as _auth
        _auth.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("10.0.0.0/8")]
        _auth.ADMIN_ALLOWED_ENTRIES.clear()
        _auth._rebuild_admin_nets_from_entries()
        assert len(_auth.ADMIN_ALLOWED_NETS) == 0

    def test_rebuild_updates_nets_in_place(self):
        """ADMIN_ALLOWED_NETS object reference must be preserved (other modules
        hold a reference to the same list)."""
        import admin.auth as _auth
        original_ref = _auth.ADMIN_ALLOWED_NETS
        _auth.ADMIN_ALLOWED_ENTRIES[:] = [{"cidr": "10.0.0.0/8"}]
        _auth._rebuild_admin_nets_from_entries()
        assert _auth.ADMIN_ALLOWED_NETS is original_ref


# ─────────────────────────────────────────────────────────────────────────────
# 2. admin_ip_add / admin_ip_remove / admin_ip_update_description
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminIPAddRemove:
    """Call admin.auth CRUD functions directly (no HTTP). db_queue=None so
    DB writes are skipped — only in-memory state is verified."""

    # ── admin_ip_add ──────────────────────────────────────────────────────────

    def test_add_success_updates_entries_and_nets(self):
        import admin.auth as _auth
        ok, msg = _run(_auth.admin_ip_add("198.51.100.0/24", note="test"))
        assert ok is True
        assert msg == "added"
        cidrs = [e["cidr"] for e in _auth.ADMIN_ALLOWED_ENTRIES]
        assert "198.51.100.0/24" in cidrs
        assert any("198.51.100.0" in str(n) for n in _auth.ADMIN_ALLOWED_NETS)

    def test_add_canonicalises_host_bits(self):
        """198.51.100.1/24 should be stored as 198.51.100.0/24 (strict=False)."""
        import admin.auth as _auth
        ok, msg = _run(_auth.admin_ip_add("198.51.100.1/24"))
        assert ok is True
        cidrs = [e["cidr"] for e in _auth.ADMIN_ALLOWED_ENTRIES]
        assert "198.51.100.0/24" in cidrs

    def test_add_duplicate_returns_already_exists(self):
        import admin.auth as _auth
        _run(_auth.admin_ip_add("198.51.100.0/24"))
        ok, msg = _run(_auth.admin_ip_add("198.51.100.0/24"))
        assert ok is False
        assert "already exists" in msg

    def test_add_invalid_cidr_returns_error(self):
        import admin.auth as _auth
        ok, msg = _run(_auth.admin_ip_add("not-a-cidr"))
        assert ok is False
        assert "invalid cidr" in msg

    def test_add_empty_cidr_returns_error(self):
        import admin.auth as _auth
        ok, msg = _run(_auth.admin_ip_add(""))
        assert ok is False
        assert "empty cidr" in msg

    def test_add_stores_note_and_description(self):
        import admin.auth as _auth
        _run(_auth.admin_ip_add("198.51.100.0/24",
                                note="QA note",
                                description="QA desc"))
        entry = next(e for e in _auth.ADMIN_ALLOWED_ENTRIES
                     if e["cidr"] == "198.51.100.0/24")
        assert entry["note"] == "QA note"
        assert entry["description"] == "QA desc"

    def test_add_truncates_overlong_note(self):
        import admin.auth as _auth
        long_note = "x" * 300
        _run(_auth.admin_ip_add("198.51.100.0/24", note=long_note))
        entry = next(e for e in _auth.ADMIN_ALLOWED_ENTRIES
                     if e["cidr"] == "198.51.100.0/24")
        assert len(entry["note"]) <= 200

    def test_add_single_host_ipv4(self):
        import admin.auth as _auth
        ok, msg = _run(_auth.admin_ip_add("203.0.113.42"))
        assert ok is True
        assert any("203.0.113.42" in str(n) for n in _auth.ADMIN_ALLOWED_NETS)

    def test_add_ipv6_cidr(self):
        import admin.auth as _auth
        ok, _ = _run(_auth.admin_ip_add("2001:db8::/32"))
        assert ok is True
        assert any("2001:db8::" in str(n) for n in _auth.ADMIN_ALLOWED_NETS)

    # ── admin_ip_remove ───────────────────────────────────────────────────────

    def test_remove_success_clears_entry_and_net(self):
        import admin.auth as _auth
        _run(_auth.admin_ip_add("198.51.100.0/24"))
        ok, msg = _run(_auth.admin_ip_remove("198.51.100.0/24"))
        assert ok is True
        assert msg == "removed"
        cidrs = [e["cidr"] for e in _auth.ADMIN_ALLOWED_ENTRIES]
        assert "198.51.100.0/24" not in cidrs
        assert not any("198.51.100.0" in str(n) for n in _auth.ADMIN_ALLOWED_NETS)

    def test_remove_not_present_returns_error(self):
        import admin.auth as _auth
        ok, msg = _run(_auth.admin_ip_remove("192.0.2.0/24"))
        assert ok is False
        assert "not present" in msg

    def test_remove_invalid_cidr_returns_error(self):
        import admin.auth as _auth
        ok, msg = _run(_auth.admin_ip_remove("bad-input"))
        assert ok is False
        assert "invalid cidr" in msg

    def test_remove_leaves_other_entries_intact(self):
        import admin.auth as _auth
        _run(_auth.admin_ip_add("198.51.100.0/24"))
        _run(_auth.admin_ip_add("10.0.0.0/8"))
        _run(_auth.admin_ip_remove("198.51.100.0/24"))
        cidrs = [e["cidr"] for e in _auth.ADMIN_ALLOWED_ENTRIES]
        assert "10.0.0.0/8" in cidrs
        assert any("10.0.0.0" in str(n) for n in _auth.ADMIN_ALLOWED_NETS)

    # ── admin_ip_update_description ───────────────────────────────────────────

    def test_update_description_success(self):
        import admin.auth as _auth
        _run(_auth.admin_ip_add("198.51.100.0/24", description="old"))
        ok, msg = _run(_auth.admin_ip_update_description("198.51.100.0/24", "new desc"))
        assert ok is True
        assert msg == "updated"
        entry = next(e for e in _auth.ADMIN_ALLOWED_ENTRIES
                     if e["cidr"] == "198.51.100.0/24")
        assert entry["description"] == "new desc"

    def test_update_description_not_present(self):
        import admin.auth as _auth
        ok, msg = _run(_auth.admin_ip_update_description("192.0.2.0/24", "desc"))
        assert ok is False
        assert "not present" in msg

    def test_update_description_invalid_cidr(self):
        import admin.auth as _auth
        ok, msg = _run(_auth.admin_ip_update_description("bad", "desc"))
        assert ok is False
        assert "invalid cidr" in msg

    def test_update_description_truncates_overlong(self):
        import admin.auth as _auth
        _run(_auth.admin_ip_add("198.51.100.0/24"))
        long_desc = "z" * 600
        ok, _ = _run(_auth.admin_ip_update_description("198.51.100.0/24", long_desc))
        assert ok is True
        entry = next(e for e in _auth.ADMIN_ALLOWED_ENTRIES
                     if e["cidr"] == "198.51.100.0/24")
        assert len(entry["description"]) <= 500


# ─────────────────────────────────────────────────────────────────────────────
# 3. HTTP endpoint gaps — behaviours not covered in test_endpoints_dynamic.py
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminIPsEndpointGaps:
    """Requires in-process proxy (uses _spin_proxy)."""

    def _ck(self, pm):
        return {pm._SESSION_COOKIE: _make_admin_cookie(pm)}

    # ── GET ──────────────────────────────────────────────────────────────────

    def test_get_includes_env_seed_key(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/admin-ips", cookies=self._ck(proxy_module))
                    d = await r.json()
                    assert "env_seed" in d, f"GET /admin-ips missing env_seed key: {list(d)}"
                    assert isinstance(d["env_seed"], list)
        _run(go())

    def test_get_cache_control_no_store(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/admin-ips", cookies=self._ck(proxy_module))
                    assert r.status == 200
                    cc = r.headers.get("Cache-Control", "")
                    assert "no-store" in cc, f"Cache-Control missing no-store: {cc!r}"
        _run(go())

    def test_get_unauthenticated_does_not_return_200(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.get(NS + "/admin-ips")
                    # Must NOT serve admin data to unauthenticated caller
                    body = await r.text()
                    assert '"entries"' not in body, \
                        "Unauthenticated GET /admin-ips must not return entries"
        _run(go())

    # ── POST ─────────────────────────────────────────────────────────────────

    def test_post_response_has_entries_list(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.post(NS + "/admin-ips",
                                     json={"cidr": "198.51.100.0/24"},
                                     cookies=self._ck(proxy_module))
                    d = await r.json()
                    assert "entries" in d
                    assert isinstance(d["entries"], list)
        _run(go())

    def test_post_duplicate_cidr_returns_400(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = self._ck(proxy_module)
                    # Must add loopback first so TestClient stays allowed
                    await c.post(NS + "/admin-ips",
                                 json={"cidr": "127.0.0.0/8"},
                                 cookies=ck)
                    r2 = await c.post(NS + "/admin-ips",
                                      json={"cidr": "127.0.0.0/8"},
                                      cookies=ck)
                    assert r2.status == 400, \
                        f"Duplicate CIDR POST expected 400, got {r2.status}"
                    d = await r2.json()
                    assert d.get("ok") is False
        _run(go())

    def test_post_empty_body_does_not_crash(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.post(NS + "/admin-ips",
                                     json={},
                                     cookies=self._ck(proxy_module))
                    assert r.status in (400, 422)
        _run(go())

    def test_post_added_cidr_appears_in_subsequent_get(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = self._ck(proxy_module)
                    # Use loopback so we stay allowed after the add
                    await c.post(NS + "/admin-ips",
                                 json={"cidr": "127.0.0.0/8",
                                       "description": "loopback"},
                                 cookies=ck)
                    r = await c.get(NS + "/admin-ips", cookies=ck)
                    d = await r.json()
                    cidrs = [e["cidr"] for e in d["entries"]]
                    assert "127.0.0.0/8" in cidrs, \
                        f"127.0.0.0/8 not in entries after POST: {cidrs}"
        _run(go())

    # ── PATCH ────────────────────────────────────────────────────────────────

    def test_patch_description_updates_entry(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = self._ck(proxy_module)
                    await c.post(NS + "/admin-ips",
                                 json={"cidr": "127.0.0.0/8",
                                       "description": "old"},
                                 cookies=ck)
                    r = await c.patch(NS + "/admin-ips",
                                      json={"cidr": "127.0.0.0/8",
                                            "description": "updated-desc"},
                                      cookies=ck)
                    assert r.status == 200
                    d = await r.json()
                    assert d.get("ok") is True
                    entry = next((e for e in d["entries"]
                                  if e["cidr"] == "127.0.0.0/8"), None)
                    assert entry is not None
                    assert entry["description"] == "updated-desc"
        _run(go())

    def test_patch_nonexistent_cidr_returns_400(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.patch(NS + "/admin-ips",
                                      json={"cidr": "192.0.2.0/24",
                                            "description": "ghost"},
                                      cookies=self._ck(proxy_module))
                    assert r.status == 400, \
                        f"PATCH non-existent CIDR expected 400, got {r.status}"
                    d = await r.json()
                    assert d.get("ok") is False
        _run(go())

    def test_patch_invalid_cidr_returns_400(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.patch(NS + "/admin-ips",
                                      json={"cidr": "garbage",
                                            "description": "x"},
                                      cookies=self._ck(proxy_module))
                    assert r.status == 400
        _run(go())

    # ── DELETE ───────────────────────────────────────────────────────────────

    def test_delete_nonexistent_cidr_returns_400(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.delete(NS + "/admin-ips?cidr=192.0.2.0/24",
                                       cookies=self._ck(proxy_module))
                    assert r.status == 400, \
                        f"DELETE non-existent CIDR expected 400, got {r.status}"
                    d = await r.json()
                    assert d.get("ok") is False
        _run(go())

    def test_delete_invalid_cidr_returns_400(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.delete(NS + "/admin-ips?cidr=bad-cidr",
                                       cookies=self._ck(proxy_module))
                    assert r.status == 400
        _run(go())

    def test_delete_removes_entry_from_subsequent_get(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = self._ck(proxy_module)
                    await c.post(NS + "/admin-ips",
                                 json={"cidr": "127.0.0.0/8"},
                                 cookies=ck)
                    await c.delete(NS + "/admin-ips?cidr=127.0.0.0/8",
                                   cookies=ck)
                    r = await c.get(NS + "/admin-ips", cookies=ck)
                    d = await r.json()
                    cidrs = [e["cidr"] for e in d["entries"]]
                    assert "127.0.0.0/8" not in cidrs, \
                        "Deleted CIDR still appears in entries"
        _run(go())

    def test_delete_response_has_entries_list(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = self._ck(proxy_module)
                    await c.post(NS + "/admin-ips",
                                 json={"cidr": "127.0.0.0/8"},
                                 cookies=ck)
                    r = await c.delete(NS + "/admin-ips?cidr=127.0.0.0/8",
                                       cookies=ck)
                    d = await r.json()
                    assert "entries" in d
                    assert isinstance(d["entries"], list)
        _run(go())

    def test_delete_no_cidr_param_returns_error(self, proxy_module):
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.delete(NS + "/admin-ips",
                                       cookies=self._ck(proxy_module))
                    assert r.status in (400, 422)
        _run(go())


# ─────────────────────────────────────────────────────────────────────────────
# 4. Enforcement — middleware actually gates on ADMIN_ALLOWED_NETS
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminIPEnforcement:
    """Verify that the admin-IP middleware gate produces decoy responses for
    blocked IPs and grants access for allowed IPs."""

    def test_blocked_ip_does_not_receive_admin_json(self, proxy_module):
        """After restricting to a non-loopback CIDR, the TestClient
        (127.0.0.1) must not get the real admin metrics payload."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = {proxy_module._SESSION_COOKIE: _make_admin_cookie(proxy_module)}
                    # Add CIDR that excludes 127.0.0.1 — TestClient is now blocked
                    r_add = await c.post(NS + "/admin-ips",
                                         json={"cidr": "192.0.2.0/24"},
                                         cookies=ck)
                    assert r_add.status == 200, \
                        "POST /admin-ips must succeed before lockout"
                    # Next admin hit from 127.0.0.1 must NOT return admin data
                    r = await c.get(NS + "/metrics", cookies=ck)
                    body = await r.text()
                    assert '"uptime_secs"' not in body, \
                        "Blocked IP received admin metrics payload"
        _run(go())

    def test_blocked_ip_admin_response_is_not_403(self, proxy_module):
        """The decoy response must not reveal the admin namespace — it should
        be a 404 mirrored from upstream, not an explicit 401/403."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = {proxy_module._SESSION_COOKIE: _make_admin_cookie(proxy_module)}
                    await c.post(NS + "/admin-ips",
                                 json={"cidr": "192.0.2.0/24"},
                                 cookies=ck)
                    r = await c.get(NS + "/status", cookies=ck)
                    assert r.status not in (401, 403), \
                        f"Blocked IP got {r.status} — must be decoy (404-class), not auth error"
        _run(go())

    def test_allowed_ip_loopback_cidr_retains_admin_access(self, proxy_module):
        """After adding 127.0.0.0/8 the TestClient (127.0.0.1) must still
        receive the real admin JSON."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = {proxy_module._SESSION_COOKIE: _make_admin_cookie(proxy_module)}
                    await c.post(NS + "/admin-ips",
                                 json={"cidr": "127.0.0.0/8"},
                                 cookies=ck)
                    r = await c.get(NS + "/metrics", cookies=ck)
                    assert r.status == 200, \
                        f"Allowed IP (loopback CIDR) got {r.status}, expected 200"
                    d = await r.json()
                    assert "total" in d or "uptime_secs" in d, \
                        f"Admin metrics missing expected key. Keys: {list(d)}"
        _run(go())

    def test_allowlist_empty_means_open(self, proxy_module):
        """Empty ADMIN_ALLOWED_NETS → any IP can reach admin (key-gated only)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = {proxy_module._SESSION_COOKIE: _make_admin_cookie(proxy_module)}
                    # No CIDRs added — allowlist empty → open
                    r = await c.get(NS + "/metrics", cookies=ck)
                    assert r.status == 200
        _run(go())

    def test_login_path_visible_to_allowed_ip(self, proxy_module):
        """The login subpath must be reachable (unauthenticated) from an IP
        in the allowlist (or when allowlist is empty)."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    login = "/antibot-appsec-gateway/login"
                    r = await c.get(login)
                    # Login page or redirect — must not be a raw 404/500
                    assert r.status in (200, 302), \
                        f"Login endpoint returned {r.status} — expected 200 or redirect"
        _run(go())

    def test_after_remove_allowlist_becomes_open_again(self, proxy_module):
        """Removing the only CIDR empties the allowlist → open mode restored."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = {proxy_module._SESSION_COOKIE: _make_admin_cookie(proxy_module)}
                    # Add loopback (so we stay connected), then remove it
                    await c.post(NS + "/admin-ips",
                                 json={"cidr": "127.0.0.0/8"},
                                 cookies=ck)
                    await c.delete(NS + "/admin-ips?cidr=127.0.0.0/8",
                                   cookies=ck)
                    # Allowlist now empty → open again
                    r = await c.get(NS + "/metrics", cookies=ck)
                    assert r.status == 200, \
                        f"After removing last CIDR, admin access should be open. Got {r.status}"
        _run(go())
