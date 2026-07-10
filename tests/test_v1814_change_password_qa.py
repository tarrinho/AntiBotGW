"""
QA tests — change-password flow (1.8.14 iteration 8 fix).

Bug: `changeUserPassword()` in settings.html (admin Users panel) had no
"Current password" field and sent `{ password: a }` without
`current_password`.  The backend requires `current_password` when
`is_self=True` (caller == target username), so an admin changing their own
password via the user table received a 400 error.

Coverage:
  TestChangePasswordUI           — source-code tests: settings.html modal HTML/JS
  TestChangePasswordEndpoint     — functional: PATCH /secured/admin/users/{username}
"""
import asyncio
import hashlib
import json
import pathlib
import sqlite3
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

# ── Paths ────────────────────────────────────────────────────────────────────
_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SETTINGS_SRC = (_ROOT / "dashboards" / "settings.html").read_text(encoding="utf-8")

NS = "/antibot-appsec-gateway/secured"
USERS_NS = NS + "/admin/users"

# ── Shared helpers (mirror test_settings_config_functional.py) ────────────────

@asynccontextmanager
async def _spin_upstream():
    async def _echo(req):
        return web.Response(text="ok")
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
async def _spin_proxy(proxy_module, upstream_url):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


def _make_admin_cookie(proxy_module):
    import time as _t
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": _t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _make_user_cookie(proxy_module, username):
    import time as _t
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   username,
        "expires_ts": _t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign(username, sid=sid)


def _csrf_hdr(proxy_module, cookie):
    import hmac as _hmac
    if isinstance(cookie, dict):
        cookie = next(iter(cookie.values()))
    sid = cookie.split("|")[1]
    token = _hmac.new(proxy_module.SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
    return {"X-CSRF-Token": token}


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _seed_user(proxy_module, username, password, role="admin"):
    """Insert a test user with a known password hash into the proxy DB."""
    from admin.users import _password_hash
    pw_hash = _password_hash(password)
    import time as _t
    n = _t.time()
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO users "
        "(username, password_hash, role, status, created_ts, updated_ts) "
        "VALUES (?, ?, ?, 'active', ?, ?)",
        (username, pw_hash, role, n, n),
    )
    conn.commit()
    conn.close()


# ── 1. TestChangePasswordUI — settings.html source-code checks ───────────────

class TestChangePasswordUI:
    """settings.html changeUserPassword() must have current-password field
    and conditionally include it in the API request body."""

    def _fn_src(self):
        """Extract the changeUserPassword function source from settings.html."""
        start = _SETTINGS_SRC.find("function changeUserPassword(username)")
        assert start != -1, "changeUserPassword not found in settings.html"
        # Find the matching closing brace (function ends at the top-level `}`)
        end = _SETTINGS_SRC.find("\n}\n", start)
        assert end != -1, "changeUserPassword closing brace not found"
        return _SETTINGS_SRC[start:end + 3]

    def test_modal_has_current_password_input(self):
        """changeUserPassword modal HTML must include id='u-pw-cur'."""
        src = self._fn_src()
        assert 'id="u-pw-cur"' in src, (
            "changeUserPassword modal missing id='u-pw-cur' input for current password"
        )

    def test_current_password_input_is_password_type(self):
        """u-pw-cur must be type=password."""
        src = self._fn_src()
        idx = src.find('id="u-pw-cur"')
        assert idx != -1
        snippet = src[max(0, idx - 80): idx + 80]
        assert 'type="password"' in snippet or "type='password'" in snippet, (
            "u-pw-cur must be type=password"
        )

    def test_current_password_label_present(self):
        """Modal must have a 'Current password' label."""
        src = self._fn_src()
        assert "Current password" in src, (
            "changeUserPassword modal missing 'Current password' label"
        )

    def test_reads_u_pw_cur_value(self):
        """JS handler must read u-pw-cur element value into curPw."""
        src = self._fn_src()
        assert 'getElementById("u-pw-cur").value' in src or \
               "getElementById('u-pw-cur').value" in src, (
            "changeUserPassword handler must read u-pw-cur.value"
        )

    def test_conditional_current_password_in_body(self):
        """current_password added to body only when curPw is non-empty (if guard)."""
        src = self._fn_src()
        # The pattern: `if (curPw) body.current_password = curPw`
        assert "body.current_password" in src, (
            "changeUserPassword handler must set body.current_password"
        )
        assert "if (curPw)" in src or "if(curPw)" in src, (
            "current_password must be guarded by `if (curPw)` — "
            "admin must be able to change other users' passwords without entering a current password"
        )

    def test_new_password_confirm_fields_still_present(self):
        """New password and confirm fields must still exist."""
        src = self._fn_src()
        assert 'id="u-pw-new"' in src, "u-pw-new field missing"
        assert 'id="u-pw-confirm"' in src, "u-pw-confirm field missing"

    def test_password_mismatch_validation_present(self):
        """Handler must validate that new === confirm before submitting."""
        src = self._fn_src()
        assert "passwords do not match" in src, (
            "changeUserPassword handler must validate password match"
        )

    def test_password_min_length_validation_present(self):
        """Handler must enforce min-8-char requirement."""
        src = self._fn_src()
        assert "a.length < 8" in src or "length < 8" in src, (
            "changeUserPassword handler must enforce min-length check"
        )


# ── 2. TestChangePasswordEndpoint — functional backend tests ─────────────────

class TestChangePasswordEndpoint:
    """PATCH /secured/admin/users/{username} with password change.

    Backend rule: current_password required when caller == target (is_self).
    Admin can change other users' passwords without current_password."""

    def test_self_change_without_current_password_returns_400(self, proxy_module):
        """Self-change omitting current_password must return 400."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_user(proxy_module, "self_test_admin", "OldPass1!", "admin")
                    cookie = _make_user_cookie(proxy_module, "self_test_admin")
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    r = await c.patch(
                        USERS_NS + "/self_test_admin",
                        json={"password": "NewPassword2!!"},
                        headers={"Content-Type": "application/json", **csrf},
                        cookies=ck,
                    )
                    d = await r.json()
                    assert r.status == 400, (
                        f"Self-change without current_password must return 400; got {r.status}: {d}"
                    )
                    assert "current_password" in (d.get("error") or "").lower(), (
                        f"Error must mention 'current_password'; got: {d.get('error')}"
                    )
        _run(go())

    def test_self_change_with_wrong_current_password_returns_403(self, proxy_module):
        """Self-change with wrong current_password must return 403."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_user(proxy_module, "self_test_wrong", "CorrectOldPwd1!", "admin")
                    cookie = _make_user_cookie(proxy_module, "self_test_wrong")
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    r = await c.patch(
                        USERS_NS + "/self_test_wrong",
                        json={"password": "NewPassword2!!", "current_password": "WrongOldPwd1!"},
                        headers={"Content-Type": "application/json", **csrf},
                        cookies=ck,
                    )
                    d = await r.json()
                    assert r.status == 403, (
                        f"Wrong current_password must return 403; got {r.status}: {d}"
                    )
                    assert "incorrect" in (d.get("error") or "").lower(), (
                        f"Error must say 'incorrect'; got: {d.get('error')}"
                    )
        _run(go())

    def test_self_change_with_correct_current_password_succeeds(self, proxy_module):
        """Self-change with correct current_password must return 200."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_user(proxy_module, "self_test_ok", "GoodOldPass1!", "admin")
                    cookie = _make_user_cookie(proxy_module, "self_test_ok")
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    r = await c.patch(
                        USERS_NS + "/self_test_ok",
                        json={"password": "GoodNewPass1!", "current_password": "GoodOldPass1!"},
                        headers={"Content-Type": "application/json", **csrf},
                        cookies=ck,
                    )
                    d = await r.json()
                    assert r.status == 200, (
                        f"Self-change with correct current_password must return 200; got {r.status}: {d}"
                    )
        _run(go())

    def test_admin_change_other_user_without_current_password_succeeds(self, proxy_module):
        """Admin changing another user's password must NOT require current_password."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_user(proxy_module, "other_user_pw", "AnyOldPass1!", "viewer")
                    cookie = _make_admin_cookie(proxy_module)
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    r = await c.patch(
                        USERS_NS + "/other_user_pw",
                        json={"password": "AnyNewPass2!!"},
                        headers={"Content-Type": "application/json", **csrf},
                        cookies=ck,
                    )
                    d = await r.json()
                    assert r.status == 200, (
                        f"Admin changing other user must succeed without current_password; "
                        f"got {r.status}: {d}"
                    )
        _run(go())

    def test_viewer_self_change_without_current_password_returns_400(self, proxy_module):
        """Viewer changing own password without current_password must get 400."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_user(proxy_module, "viewer_pw_test", "ViewOldPass1!", "viewer")
                    cookie = _make_user_cookie(proxy_module, "viewer_pw_test")
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    r = await c.patch(
                        USERS_NS + "/viewer_pw_test",
                        json={"password": "ViewNewPass2!!"},
                        headers={"Content-Type": "application/json", **csrf},
                        cookies=ck,
                    )
                    assert r.status == 400, (
                        f"Viewer self-change without current_password must return 400; got {r.status}"
                    )
        _run(go())

    def test_viewer_cannot_change_another_users_password(self, proxy_module):
        """Viewer attempting to change another user's password must be forbidden."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_user(proxy_module, "viewer_forbidden", "ViewOldPass1!", "viewer")
                    _seed_user(proxy_module, "target_user_pv", "TargetOldPwd1!", "admin")
                    cookie = _make_user_cookie(proxy_module, "viewer_forbidden")
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    r = await c.patch(
                        USERS_NS + "/target_user_pv",
                        json={"password": "TargetNewPwd2!", "current_password": "anything"},
                        headers={"Content-Type": "application/json", **csrf},
                        cookies=ck,
                    )
                    assert r.status == 403, (
                        f"Viewer changing another user must return 403; got {r.status}"
                    )
        _run(go())

    def test_unauthenticated_patch_returns_decoy(self, proxy_module):
        """Unauthenticated PATCH must serve silent decoy — NOT the real admin JSON."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    r = await c.patch(
                        USERS_NS + "/admin",
                        json={"password": "HackAttempt1!"},
                        headers={"Content-Type": "application/json"},
                    )
                    # Gateway serves the upstream's mirrored-404 as a decoy; the real
                    # admin endpoint always returns application/json. So the content-type
                    # distinguishes a real response from the decoy.
                    ct = r.content_type or ""
                    assert "application/json" not in ct, (
                        f"Unauthenticated PATCH must serve decoy (not admin JSON); "
                        f"got status={r.status} content-type={ct}"
                    )
        _run(go())

    def test_weak_new_password_rejected(self, proxy_module):
        """Passwords that fail strength validation must be rejected with 400."""
        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    _seed_user(proxy_module, "strength_test", "StrongOldPwd1!", "admin")
                    cookie = _make_user_cookie(proxy_module, "strength_test")
                    ck = {proxy_module._SESSION_COOKIE: cookie}
                    csrf = _csrf_hdr(proxy_module, cookie)
                    r = await c.patch(
                        USERS_NS + "/strength_test",
                        json={"password": "weak", "current_password": "StrongOldPwd1!"},
                        headers={"Content-Type": "application/json", **csrf},
                        cookies=ck,
                    )
                    assert r.status == 400, (
                        f"Weak new password must return 400; got {r.status}"
                    )
        _run(go())
