"""
tests/test_v1810_csrf_session_regression.py — regression guards for the
recurrent "CSRF token invalid" / "auth" failures after a container redeploy.

Background (the recurrent problem):
  After redeploying the gateway, the dashboard started rejecting every
  state-mutating POST with 403 {"error":"CSRF token invalid"} and GETs with
  401 {"error":"auth"}.  Two independent root causes were found:

  1. SESSION INVALIDATION ON REDEPLOY — if SESSION_KEY is not persisted to the
     /data volume, every container start regenerates it, invalidating all
     existing agw_session cookies (→ 401 auth) and all agw_csrf tokens
     (→ 403 CSRF). The shipped Dockerfile + compose persist .session_key on
     the named /data volume; these tests lock that wiring in.

  2. STALE agw_csrf NOT SELF-HEALED — agw_session and agw_csrf are independent
     cookies. A stale agw_csrf (left by a logout that only cleared the session,
     an SSO login, or a re-login where the browser kept the old token) makes
     every POST fail even though the session is valid. Fix: re-issue the
     correct agw_csrf on every response via session_cookie_finalizer, and clear
     it on logout.

Token contract (must stay consistent across the codebase):
     agw_csrf value == HMAC(SESSION_KEY, sid)[:32]   (hex)
  set at  : admin/users.py login + admin/oidc.py SSO
  healed  : core/middleware.py session_cookie_finalizer
  checked : admin/auth.py _csrf_token_valid

Test groups
  K — SESSION_KEY persistence wiring (prevents 401 auth on redeploy)
  R — CSRF token round-trip consistency (set == healed == validated)
  H — self-heal middleware behaviour (the fix)
  L — logout clears agw_csrf
"""
import os
import re
import hmac
import hashlib
import importlib

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")

def _read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()


# ── K: SESSION_KEY persistence wiring ────────────────────────────────────────

class TestSessionKeyPersistence:
    """If these break, every redeploy logs everyone out — the recurrent bug."""

    def test_k01_dockerfile_symlinks_session_key_to_data(self):
        df = _read("Dockerfile")
        assert re.search(r"ln -sf?\s+/data/\.session_key\s+\S*/\.session_key", df), (
            "Dockerfile must symlink .session_key onto the persistent /data volume"
        )

    def test_k02_dockerfile_armv7_symlinks_session_key_to_data(self):
        df = _read("Dockerfile.armv7")
        assert "/data/.session_key" in df, (
            "Dockerfile.armv7 must also persist .session_key on /data "
            "(armv7 is the arch that exhibited the recurrent logout bug)"
        )

    def test_k03_compose_mounts_data_named_volume(self):
        c = _read("docker-compose.yml")
        assert re.search(r"antibot-data:/data", c), (
            "docker-compose must mount the antibot-data named volume at /data"
        )

    def test_k04_compose_declares_data_volume(self):
        c = _read("docker-compose.yml")
        assert re.search(r"^volumes:", c, re.M) and "antibot-data:" in c, (
            "docker-compose must DECLARE the antibot-data named volume "
            "(a bind/tmpfs or missing declaration would not persist the key)"
        )

    def test_k05_compose_sets_key_dir_to_data(self):
        c = _read("docker-compose.yml")
        assert re.search(r"APPSECGW_KEY_DIR:\s*/data", c), (
            "docker-compose must set APPSECGW_KEY_DIR=/data so keys land on the volume"
        )

    def test_k06_config_loads_session_key_if_file_exists(self):
        cfg = _read("config.py")
        # The load-if-exists branch must precede the generate branch so an
        # existing key is reused (not regenerated) on restart.
        assert "if os.path.exists(_SESS_KEY_FILE):" in cfg, (
            "config.py must load SESSION_KEY from .session_key when it exists"
        )
        assert "bytes.fromhex(open(_SESS_KEY_FILE).read().strip())" in cfg, (
            "config.py must read the persisted SESSION_KEY hex from the file"
        )


# ── R: CSRF token round-trip consistency ─────────────────────────────────────

class TestCsrfTokenRoundTrip:
    def _expected(self, key, sid):
        return hmac.new(key, sid.encode(), hashlib.sha256).hexdigest()[:32]

    def test_r01_login_and_validation_use_same_formula(self):
        users = _read("admin/users.py")
        auth  = _read("admin/auth.py")
        formula = "hmac.new(SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]"
        assert formula in users, "login must set csrf = HMAC(SESSION_KEY, sid)[:32]"
        assert formula in auth,  "validation must expect HMAC(SESSION_KEY, sid)[:32]"

    def test_r02_oidc_uses_same_formula(self):
        oidc = _read("admin/oidc.py")
        assert "hexdigest()[:32]" in oidc and "SESSION_KEY" in oidc, (
            "OIDC login must mint the csrf token with the same HMAC formula"
        )

    def test_r03_csrf_token_valid_accepts_matching_token(self, monkeypatch):
        from admin import auth as _auth
        from admin import users as _users
        sid = "TESTSID_ABCdef0123456789"
        token = _users._session_sign("admin", sid=sid)
        good = self._expected(_auth.SESSION_KEY, sid)

        class _Req:
            method = "POST"
            cookies = {_users._SESSION_COOKIE: token}
            headers = {"X-CSRF-Token": good}
        assert _auth._csrf_token_valid(_Req()) is True, (
            "A token matching HMAC(SESSION_KEY, sid) must validate"
        )

    def test_r04_csrf_token_valid_rejects_wrong_token(self, monkeypatch):
        from admin import auth as _auth
        from admin import users as _users
        sid = "TESTSID_ABCdef0123456789"
        token = _users._session_sign("admin", sid=sid)

        class _Req:
            method = "POST"
            cookies = {_users._SESSION_COOKIE: token}
            headers = {"X-CSRF-Token": "deadbeefdeadbeefdeadbeefdeadbeef"}
        assert _auth._csrf_token_valid(_Req()) is False, (
            "A non-matching token must be rejected"
        )

    def test_r05_csrf_token_valid_rejects_missing_session(self):
        from admin import auth as _auth
        class _Req:
            method = "POST"
            cookies = {}
            headers = {"X-CSRF-Token": "anything"}
        assert _auth._csrf_token_valid(_Req()) is False, (
            "No session cookie → CSRF must fail closed"
        )


# ── H: self-heal middleware behaviour (the fix) ──────────────────────────────

class _FakeResp:
    def __init__(self, content_type=None, body=None):
        self.cookies_set = {}
        self.content_type = content_type
        self.body = body
    def set_cookie(self, name, value, **kw):
        self.cookies_set[name] = (value, kw)

class _FakeReq:
    def __init__(self, cookies, path="/antibot-appsec-gateway/secured/settings"):
        self.cookies = cookies
        self.path = path

class TestCsrfSelfHeal:
    def _make(self, csrf_cookie=None):
        from admin import users as _users
        from core import middleware as _mw
        sid = "HEALSID_xyz0123456789ABCD"
        token = _users._session_sign("admin", sid=sid)
        want = hmac.new(_mw.SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
        cookies = {_users._SESSION_COOKIE: token}
        if csrf_cookie is not None:
            cookies["agw_csrf"] = csrf_cookie
        return _users, _mw, sid, token, want, cookies

    def test_h01_self_heal_function_exists(self):
        from core import middleware as _mw
        assert hasattr(_mw, "_csrf_self_heal"), (
            "middleware must define _csrf_self_heal"
        )

    def test_h02_finalizer_calls_self_heal(self):
        mw = _read("core/middleware.py")
        assert "_csrf_self_heal(request, response)" in mw, (
            "session_cookie_finalizer must invoke _csrf_self_heal on every response"
        )

    def test_h03_reissues_when_csrf_missing(self):
        _users, _mw, sid, token, want, cookies = self._make(csrf_cookie=None)
        req, resp = _FakeReq(cookies), _FakeResp()
        _mw._csrf_self_heal(req, resp)
        assert "agw_csrf" in resp.cookies_set, "missing csrf must be re-issued"
        assert resp.cookies_set["agw_csrf"][0] == want, (
            "re-issued csrf must equal HMAC(SESSION_KEY, sid)[:32]"
        )

    def test_h04_reissues_when_csrf_stale(self):
        _users, _mw, sid, token, want, cookies = self._make(csrf_cookie="STALEWRONGVALUE")
        req, resp = _FakeReq(cookies), _FakeResp()
        _mw._csrf_self_heal(req, resp)
        assert "agw_csrf" in resp.cookies_set, "stale csrf must be corrected"
        assert resp.cookies_set["agw_csrf"][0] == want

    def test_h05_no_reissue_when_csrf_correct(self):
        _users, _mw, sid, token, want, cookies = self._make(csrf_cookie=None)
        cookies["agw_csrf"] = want  # already correct
        req, resp = _FakeReq(cookies), _FakeResp()
        _mw._csrf_self_heal(req, resp)
        assert "agw_csrf" not in resp.cookies_set, (
            "a correct csrf cookie must NOT be redundantly re-set (idempotent)"
        )

    def test_h06_no_action_without_session(self):
        from core import middleware as _mw
        req, resp = _FakeReq({"agw_csrf": "whatever"}), _FakeResp()
        _mw._csrf_self_heal(req, resp)
        assert "agw_csrf" not in resp.cookies_set, (
            "no session cookie → must not set a csrf cookie"
        )

    def test_h07_reissued_token_passes_validation(self):
        # End-to-end: the healed token must satisfy _csrf_token_valid.
        from admin import auth as _auth
        _users, _mw, sid, token, want, cookies = self._make(csrf_cookie="STALE")
        req, resp = _FakeReq(cookies), _FakeResp()
        _mw._csrf_self_heal(req, resp)
        healed = resp.cookies_set["agw_csrf"][0]

        class _Req:
            method = "POST"
            cookies = {_users._SESSION_COOKIE: token}
            headers = {"X-CSRF-Token": healed}
        assert _auth._csrf_token_valid(_Req()) is True, (
            "the self-healed csrf token must pass server-side validation"
        )

    def test_h08_csrf_cookie_not_httponly(self):
        # The dashboard JS reads agw_csrf via document.cookie → must be readable.
        _users, _mw, sid, token, want, cookies = self._make(csrf_cookie=None)
        req, resp = _FakeReq(cookies), _FakeResp()
        _mw._csrf_self_heal(req, resp)
        kw = resp.cookies_set["agw_csrf"][1]
        assert kw.get("httponly") is False, (
            "agw_csrf must NOT be httponly — the JS shim reads it from document.cookie"
        )
        # 1.8.11 (M1): scoped to the admin namespace so the readable CSRF token
        # is never delivered to the proxied upstream surface (XSS-to-admin guard).
        assert kw.get("path") == "/antibot-appsec-gateway", (
            "agw_csrf must be scoped to the admin namespace, not path=/")


# ── L: logout clears agw_csrf ────────────────────────────────────────────────

class TestLogoutClearsCsrf:
    def test_l01_logout_deletes_session_and_csrf(self):
        users = _read("admin/users.py")
        # Within the logout endpoint, both cookies must be cleared.
        idx = users.find("async def logout_endpoint")
        assert idx != -1, "logout_endpoint must exist"
        # Slice up to the next endpoint definition so the whole body is covered.
        nxt = users.find("async def ", idx + 1)
        body = users[idx:nxt if nxt != -1 else idx + 2000]
        assert re.search(r"del_cookie\(_SESSION_COOKIE", body), (
            "logout must clear the session cookie"
        )
        assert re.search(r"del_cookie\(\"agw_csrf\"", body), (
            "logout must ALSO clear agw_csrf so a stale token can't survive re-login"
        )


# ── G: CDN-proof CSRF token global (Cloudflare adds HttpOnly to agw_csrf) ─────
#
# Observed behind Cloudflare: the CDN rewrites Set-Cookie to add
# HttpOnly, making agw_csrf unreadable by document.cookie → the JS shim sends an
# empty token → 403 on every POST. Fix: the gateway injects the token into the
# dashboard HTML as window.__AGW_CSRF__, and the shim reads that first.

class TestCsrfGlobalInjection:
    def _make(self, path="/antibot-appsec-gateway/secured/settings",
              ctype="text/html", body=b"<html><head><title>x</title></head><body></body></html>"):
        from admin import users as _users
        from core import middleware as _mw
        sid = "GLOBSID_xyz0123456789ABCD"
        token = _users._session_sign("admin", sid=sid)
        want = hmac.new(_mw.SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
        cookies = {_users._SESSION_COOKIE: token}
        return _mw, want, _FakeReq(cookies, path=path), _FakeResp(content_type=ctype, body=body)

    def test_g01_inject_function_exists(self):
        from core import middleware as _mw
        assert hasattr(_mw, "_inject_csrf_global"), (
            "middleware must define _inject_csrf_global"
        )

    def test_g02_injects_global_into_dashboard_html(self):
        _mw, want, req, resp = self._make()
        _mw._csrf_self_heal(req, resp)
        out = resp.body.decode()
        assert "window.__AGW_CSRF__" in out, (
            "dashboard HTML must get the window.__AGW_CSRF__ global injected"
        )
        assert want in out, "injected global must carry the correct token value"
        assert "</head>" in out, "injection must keep the document well-formed"

    def test_g03_injected_token_matches_validation(self):
        # The injected token must be exactly what _csrf_token_valid expects.
        _mw, want, req, resp = self._make()
        _mw._csrf_self_heal(req, resp)
        out = resp.body.decode()
        m = re.search(r'window\.__AGW_CSRF__="([0-9a-f]{32})"', out)
        assert m, "injected global must be a 32-char hex token literal"
        assert m.group(1) == want

    def test_g04_no_injection_for_non_dashboard_path(self):
        # The proxied site (not under /secured) must NOT be rewritten.
        _mw, want, req, resp = self._make(path="/some/upstream/page")
        original = resp.body
        _mw._csrf_self_heal(req, resp)
        assert resp.body == original, (
            "non-dashboard responses must not be HTML-rewritten"
        )

    def test_g05_no_injection_for_non_html(self):
        _mw, want, req, resp = self._make(ctype="application/json", body=b'{"ok":true}')
        original = resp.body
        _mw._csrf_self_heal(req, resp)
        assert resp.body == original, "non-HTML responses must not be rewritten"

    def test_g06_idempotent_no_double_injection(self):
        # Already-injected page (carries the data-agw-csrf marker) → no re-inject.
        _mw, want, req, resp = self._make(
            body=b'<html><head><script data-agw-csrf>window.__AGW_CSRF__="x"</script></head><body></body></html>')
        before = resp.body
        _mw._csrf_self_heal(req, resp)
        assert resp.body == before, (
            "must not inject a second global if the data-agw-csrf marker is present"
        )

    def test_g09_injects_even_when_shim_references_global(self):
        # REGRESSION (CDN-fronted): a real dashboard page contains the fetch shim,
        # which references `window.__AGW_CSRF__` (the || fallback). The injection
        # idempotency check must NOT treat that as 'already injected' — otherwise
        # the global is never DEFINED and the shim falls back to the (CDN-broken)
        # cookie. The injection MUST still fire here.
        shim_body = (
            b'<html><head><title>x</title></head><body>'
            b"<script>fetch('/x',{headers:{'X-CSRF-Token':(window.__AGW_CSRF__||"
            b"(document.cookie.match(/agw_csrf=([^;]+)/)||[])[1]||'')}})</script>"
            b'</body></html>'
        )
        _mw, want, req, resp = self._make(body=shim_body)
        _mw._csrf_self_heal(req, resp)
        out = resp.body.decode()
        assert 'data-agw-csrf' in out, (
            "injection must fire even when the shim already references the global name"
        )
        assert ('window.__AGW_CSRF__=' + '"' + want + '"') in out, (
            "the global must be DEFINED with the correct token, not just referenced"
        )

    def test_g07_all_dashboard_shims_prefer_global(self):
        # Every dashboard page's token read must consult window.__AGW_CSRF__,
        # otherwise a CDN-HttpOnly'd cookie still breaks that page.
        import glob
        offenders = []
        for f in glob.glob(os.path.join(_REPO, "dashboards", "*.html")):
            html = open(f, encoding="utf-8").read()
            if "agw_csrf=([^;]+)" not in html:
                continue  # page has no csrf read at all
            # Any cookie read NOT preceded by the global fallback is an offender.
            for mm in re.finditer(r"document\.cookie\.match\(/agw_csrf", html):
                window_start = max(0, mm.start() - 40)
                if "window.__AGW_CSRF__" not in html[window_start:mm.start()]:
                    offenders.append(os.path.basename(f))
                    break
        assert not offenders, (
            "these dashboards still read agw_csrf from the cookie without the "
            "window.__AGW_CSRF__ fallback: " + ", ".join(sorted(set(offenders)))
        )

    def test_g08_finalizer_injects_via_self_heal(self):
        mw = _read("core/middleware.py")
        assert "_inject_csrf_global(request, response, want)" in mw, (
            "_csrf_self_heal must call _inject_csrf_global with the computed token"
        )


# ── P: CSP must allow the injected inline script (silent-failure guard) ───────
#
# The CSRF token is delivered via an injected <script data-agw-csrf>...</script>.
# If any dashboard page's Content-Security-Policy tightens script-src to drop
# 'unsafe-inline' (and adds no matching nonce/hash), that inline script is
# blocked by the browser, window.__AGW_CSRF__ is never defined, and the fix
# silently reverts to the broken (CDN-HttpOnly cookie) behaviour. These tests
# lock the CSP contract that keeps the injection executable.

class TestCspAllowsInjection:
    # Source files that build a CSP for an authenticated dashboard HTML page.
    _CSP_SOURCES = [
        "admin/settings.py",        # settings + vhost-policy
        "dashboards/controls.py",   # controls + geo + logs
        "dashboards/agents.py",
        "dashboards/siem.py",
        "dashboards/service_metrics.py",
        "core/proxy_handler.py",    # main dashboard + control-center
    ]

    def _script_src_directives(self, text):
        # Match literal CSP "script-src 'self' ... ;" directives. Requiring the
        # 'self' source keyword avoids matching prose in comments (e.g.
        # "...script-src that omits challenges.cloudflare.com;").
        return re.findall(r"script-src 'self'[^\";]*;", text)

    def test_p01_every_dashboard_csp_allows_inline_script(self):
        offenders = []
        found_any = False
        for rel in self._CSP_SOURCES:
            text = _read(rel)
            for directive in self._script_src_directives(text):
                found_any = True
                if "'unsafe-inline'" not in directive:
                    offenders.append(f"{rel}: {directive.strip()}")
        assert found_any, "no script-src directives found — test wiring broken"
        assert not offenders, (
            "these dashboard CSP script-src directives drop 'unsafe-inline', which "
            "would block the injected window.__AGW_CSRF__ script: " + " | ".join(offenders)
        )

    def test_p02_injected_tag_is_plain_inline_script(self):
        # The injection uses a plain inline <script> (no nonce). If it ever
        # gained a nonce, the CSP would need to carry that nonce — guard that
        # the current implementation stays nonce-free + inline.
        mw = _read("core/middleware.py")
        assert "<script data-agw-csrf>window.__AGW_CSRF__=" in mw, (
            "injection must emit a plain inline <script data-agw-csrf> tag"
        )
        assert "nonce" not in mw.split("_inject_csrf_global", 1)[-1][:600], (
            "injection must not depend on a CSP nonce (CSP uses 'unsafe-inline')"
        )


# ── M: per-path injection coverage ───────────────────────────────────────────

class TestInjectionPathCoverage:
    DASHBOARD_PATHS = [
        "/antibot-appsec-gateway/secured/settings",
        "/antibot-appsec-gateway/secured/controls",
        "/antibot-appsec-gateway/secured/vhost-policy",
        "/antibot-appsec-gateway/secured/agents",
        "/antibot-appsec-gateway/secured/siem",
        "/antibot-appsec-gateway/secured/geo",
        "/antibot-appsec-gateway/secured/logs",
        "/antibot-appsec-gateway/secured/service",
        "/antibot-appsec-gateway/secured/control-center",
    ]

    def _make(self, path):
        from admin import users as _users
        from core import middleware as _mw
        sid = "PATHSID_abc0123456789XYZ"
        token = _users._session_sign("admin", sid=sid)
        want = hmac.new(_mw.SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()[:32]
        body = b"<html><head><title>x</title></head><body></body></html>"
        return _mw, want, _FakeReq({_users._SESSION_COOKIE: token}, path=path), \
               _FakeResp(content_type="text/html", body=body)

    @pytest.mark.parametrize("path", DASHBOARD_PATHS)
    def test_m01_injection_fires_for_each_dashboard_path(self, path):
        _mw, want, req, resp = self._make(path)
        _mw._csrf_self_heal(req, resp)
        out = resp.body.decode()
        assert "data-agw-csrf" in out and want in out, (
            f"injection must fire for dashboard path {path}"
        )

    def test_m02_no_injection_for_login_page(self):
        # /login is under the namespace but is pre-auth (no valid session) →
        # _session_parse fails → no injection (and no token leak pre-auth).
        from admin import users as _users
        from core import middleware as _mw
        req = _FakeReq({}, path="/antibot-appsec-gateway/login")
        resp = _FakeResp(content_type="text/html",
                         body=b"<html><head></head><body>login</body></html>")
        original = resp.body
        _mw._csrf_self_heal(req, resp)
        assert resp.body == original, "no session → must not inject a token"

    def test_m03_no_injection_for_upstream_root(self):
        from admin import users as _users
        from core import middleware as _mw
        sid = "PATHSID_abc0123456789XYZ"
        token = _users._session_sign("admin", sid=sid)
        req = _FakeReq({_users._SESSION_COOKIE: token}, path="/")
        resp = _FakeResp(content_type="text/html",
                         body=b"<html><head></head><body>site</body></html>")
        original = resp.body
        _mw._csrf_self_heal(req, resp)
        assert resp.body == original, (
            "the proxied site root (not /secured) must never be rewritten"
        )


# ── W: WAF 'Disable all' CSRF delivery (controls.html bulk toggle) ────────────

class TestWafDisableAllCsrf:
    _HTML = _read("dashboards/controls.html")

    def test_w01_apply_bool_uses_fetch(self):
        # The per-knob apply (driven by 'Disable all' / 'Enable all') must POST
        # via fetch so the global CSRF shim attaches the token.
        assert "async function _applyBool" in self._HTML, "_applyBool must exist"
        idx = self._HTML.find("async function _applyBool")
        block = self._HTML[idx:idx + 500]
        assert "fetch(" in block and "method:'POST'" in block, (
            "_applyBool must POST to /config via fetch (shim adds CSRF)"
        )

    def test_w02_controls_shim_prefers_global(self):
        assert "window.__AGW_CSRF__||" in self._HTML or "window.__AGW_CSRF__ ||" in self._HTML, (
            "controls.html shim must read window.__AGW_CSRF__ first"
        )

    def test_w03_group_toggle_all_drives_apply_bool(self):
        # The 'Disable all' button (data-grp-toggle) loops over bools calling
        # _applyBool — the path the user hit when all WAF knobs 403'd. Anchor on
        # the toggle-all handler comment, not the collapse handler that also
        # references [data-grp-toggle].
        assert "data-grp-toggle" in self._HTML, "group toggle-all button must exist"
        idx = self._HTML.find("Group toggle-all button")
        assert idx != -1, "group toggle-all handler must exist"
        block = self._HTML[idx:idx + 900]
        assert "_applyBool(" in block, (
            "the group 'Disable all' handler must call _applyBool for each knob"
        )

    def test_w04_apply_bool_no_manual_csrf(self):
        # It must rely on the shim (which reads the global), not a manual cookie
        # read — a manual cookie read would break behind a CDN that HttpOnly's it.
        idx = self._HTML.find("async function _applyBool")
        block = self._HTML[idx:idx + 500]
        assert "X-CSRF-Token" not in block, (
            "_applyBool must NOT manually set X-CSRF-Token — rely on the global shim"
        )
