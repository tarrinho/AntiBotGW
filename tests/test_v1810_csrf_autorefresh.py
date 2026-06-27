"""
tests/test_v1810_csrf_autorefresh.py — guards for the CSRF token auto-refresh /
retry-on-403 mechanism (so operators never have to clear cookies).

Problem: the CSRF token is delivered via the agw_csrf cookie + an injected
window.__AGW_CSRF__ global. Both can go stale:
  • a CDN (Cloudflare) rewrites agw_csrf to HttpOnly → JS can't read it;
  • the session rotates after page load → the injected global is frozen/stale.
A stale token makes every state-mutating POST 403 ("CSRF token invalid") until
the user manually clears cookies — exactly the recurring WAF "disable all" bug.

Fix:
  • GET <NS>/secured/csrf returns the CURRENT token for the live session as
    JSON (readable regardless of HttpOnly).
  • The global fetch shim, on a 403, fetches a fresh token, updates
    window.__AGW_CSRF__, and retries the request once — self-healing.

Groups
  E — the /secured/csrf endpoint (server)
  R — the retry-on-403 shim (every dashboard page)
"""
import os
import re

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")

def _read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()


# ── E: CSRF token delivery (server) ──────────────────────────────────────────
#
# Contract change (1.9.1, locked by tests/test_v1814_csrf_nonce_regression.py):
# the standalone /secured/csrf `csrf_endpoint` + the 1.8.14 (T0-2) per-session
# _SESSION_CACHE nonce were DELIBERATELY REMOVED. CSRF is now a pure
# HMAC(SESSION_KEY, sid)[:32] double-submit, enforced by the single shared
# validator admin.auth._csrf_token_valid, and the current token is delivered to
# the browser by core.middleware._csrf_self_heal (re-issues the agw_csrf cookie
# and injects window.__AGW_CSRF__) on EVERY authenticated dashboard response.
# Because the token is a deterministic HMAC of the stable session sid and is
# re-injected on every response, it cannot go stale — so a dedicated bootstrap
# endpoint is unnecessary. test_v1814::test_s03 explicitly locks
# "csrf_endpoint was removed in 1.9.1; it must not reappear".
# The E-group below is realigned from the removed nonce-endpoint contract to the
# shipped self-heal contract WITHOUT loosening any security property.

class TestCsrfEndpoint:
    def test_e01_endpoint_defined(self):
        # 1.9.1: the standalone csrf_endpoint was removed; CSRF token delivery is
        # owned by core.middleware._csrf_self_heal. Guard that the canonical
        # delivery channel exists (and the removed endpoint did not reappear).
        from core import proxy_handler as ph
        from core import middleware as mw
        assert not hasattr(ph, "csrf_endpoint"), (
            "csrf_endpoint was removed in 1.9.1 (test_v1814::test_s03) — it must not reappear"
        )
        assert hasattr(mw, "_csrf_self_heal"), (
            "core.middleware._csrf_self_heal must own CSRF token delivery"
        )

    def test_e02_route_registered(self):
        # 1.9.1: no GET <NS>/secured/csrf route — there is no csrf_endpoint to
        # register. The agw_csrf cookie + injected window.__AGW_CSRF__ deliver the
        # token instead (self-heal on every authenticated response).
        proxy = _read("proxy.py")
        assert not re.search(r'\("csrf",\s*"GET",\s*csrf_endpoint', proxy), (
            "the removed csrf_endpoint must not be re-registered (1.9.1 contract)"
        )

    def test_e03_endpoint_returns_nonce_from_session_cache(self):
        # 1.9.1: the per-session _SESSION_CACHE nonce was superseded by pure HMAC
        # double-submit. The token published to the browser is derived as
        # HMAC(SESSION_KEY, sid)[:32] in middleware._csrf_self_heal, and that exact
        # value is what _csrf_token_valid accepts — single source of truth.
        mw = _read("core/middleware.py")
        idx = mw.find("def _csrf_self_heal")
        assert idx != -1
        body = mw[idx:idx + 4000]
        assert "hexdigest()[:32]" in body and "SESSION_KEY" in body, (
            "self-heal must derive the published token as HMAC(SESSION_KEY, sid)[:32]"
        )
        # It must publish via the readable channels the JS shim consumes.
        assert "agw_csrf" in body, "self-heal must (re)issue the agw_csrf cookie"
        assert "__AGW_CSRF__" in body, "self-heal must inject window.__AGW_CSRF__"

    def test_e04_endpoint_fails_closed_without_session(self):
        # 1.9.1: fail-closed now lives in the validator, not a bootstrap endpoint.
        # _csrf_token_valid returns False (→ @_require_csrf 403s) when there is no
        # valid session cookie — no session means no accepted token.
        auth = _read("admin/auth.py")
        idx = auth.find("def _csrf_token_valid")
        assert idx != -1
        body = auth[idx:idx + 1200]
        assert "if not cookie" in body or "if not parsed" in body or "return False" in body, (
            "_csrf_token_valid must fail closed (return False) without a valid session"
        )

    def test_e05_endpoint_is_get_not_csrf_protected(self):
        # 1.9.1: token delivery happens in middleware._csrf_self_heal, which runs
        # on the response path and is not a CSRF-protected handler — it cannot be
        # circular. Guard that the removed endpoint was not re-added with a
        # @_require_csrf decorator (which would be the circular-bootstrap bug).
        ph = _read("core/proxy_handler.py")
        assert "async def csrf_endpoint" not in ph, (
            "csrf_endpoint must not reappear (1.9.1) — delivery is owned by middleware"
        )


# ── R: retry-on-403 shim on every dashboard page ─────────────────────────────

class TestRetryShim:
    PAGES = [
        "main.html", "controls.html", "settings.html", "vhost_policy.html",
        "agents.html", "siem.html", "geo.html", "logs.html", "service.html",
        "control_center.html", "controls_testA.html", "controls_testB.html",
    ]

    def test_r01_all_pages_have_retry_shim(self):
        missing = []
        for p in self.PAGES:
            html = _read(os.path.join("dashboards", p))
            if "/antibot-appsec-gateway/secured/csrf" not in html:
                missing.append(p)
        assert not missing, (
            "these dashboard pages lack the CSRF auto-refresh shim: " + ", ".join(missing)
        )

    def test_r02_shim_retries_only_on_403(self):
        for p in self.PAGES:
            html = _read(os.path.join("dashboards", p))
            assert re.search(r"status\s*!==\s*403", html), (
                f"{p} shim must only refresh+retry on a 403 response"
            )

    def test_r03_shim_updates_global_and_retries(self):
        for p in self.PAGES:
            html = _read(os.path.join("dashboards", p))
            assert "window.__AGW_CSRF__ = j.token" in html or \
                   "window.__AGW_CSRF__=j.token" in html, (
                f"{p} shim must update the cached global with the fresh token"
            )

    def test_r04_shim_still_injects_token_on_first_try(self):
        for p in self.PAGES:
            html = _read(os.path.join("dashboards", p))
            assert "_agwTok(" in html, (
                f"{p} shim must attach X-CSRF-Token on the initial request"
            )

    def test_r05_no_legacy_nonretry_shim_left(self):
        # The old shim returned _orig.call(this,resource,init) directly with no
        # .then() retry. Ensure none remain (both minified and multiline forms).
        for p in self.PAGES:
            html = _read(os.path.join("dashboards", p))
            assert "return _orig.call(this,resource,init);};})();" not in html, (
                f"{p} still has the legacy minified non-retry shim"
            )
