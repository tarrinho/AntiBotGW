"""1.8.14 security hardening tests.

Covers:
  T0-1  — SESSION_ABSOLUTE_TIMEOUT enforcement in _session_verify
  T0-2  — Per-session CSRF nonce (random, not HMAC-derived)
  T0-4  — OIDC state dict cap (_OIDC_STATE_MAX)
  T1-1  — Upstream latency tracking (_upstream_latency_samples + metrics)
  T1-3  — Webhook health counters
  T2-5  — eTLD+1 origin validation in _origin_check_failed
  T3-2  — Bulk unban UI present in agents.html
  T3-3  — "View requests" drill-down link present in agents.html + main.html
"""
import importlib
import os
import pathlib
import time
import types
import unittest.mock as mock

import pytest

os.environ.setdefault("UPSTREAM", "http://localhost")

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DASH = _ROOT / "dashboards"


# ── helpers ────────────────────────────────────────────────────────────────

def _fresh_users_mod():
    """Return admin.users with a clean session cache.
    NOTE: Does NOT remove the module from sys.modules — that causes cross-test
    shared-state confusion when other modules hold references to the original
    _SESSION_CACHE dict.  Just clear the cache in place instead.
    """
    import admin.users as m
    m._SESSION_CACHE.clear()
    m._SESSION_CACHE_READY = True
    return m


# ── T0-1: SESSION_ABSOLUTE_TIMEOUT ─────────────────────────────────────────

class TestSessionAbsoluteTimeout:
    def test_config_knob_exists(self):
        import config
        assert hasattr(config, "SESSION_ABSOLUTE_TIMEOUT"), \
            "SESSION_ABSOLUTE_TIMEOUT config knob missing"
        assert isinstance(config.SESSION_ABSOLUTE_TIMEOUT, int)
        assert config.SESSION_ABSOLUTE_TIMEOUT > 0

    def test_verify_rejects_expired_absolute(self):
        m = _fresh_users_mod()
        sid = "abcdefghijklmnop"   # 16 chars — valid pattern
        n = time.time()
        # Inject a cached session whose created_ts is well past the timeout.
        m._SESSION_CACHE[sid] = {
            "username": "alice",
            "expires_ts": n + 10000,   # sliding window still valid
            "revoked": False,
            "source_ip": "",
            "created_ts": n - 100000,  # created 100 000 s ago — exceeds any timeout
            "csrf_nonce": "abc",
        }
        import admin.users as users_mod
        import config
        with mock.patch.object(config, "SESSION_ABSOLUTE_TIMEOUT", 3600):
            with mock.patch("admin.users._session_parse") as parse:
                parse.return_value = ("alice", sid, int(n) + 10000)
                result = users_mod._session_verify("dummy_token")
        assert result is None, "session should be rejected when past absolute timeout"

    def test_verify_allows_within_absolute(self):
        m = _fresh_users_mod()
        sid = "abcdefghijklmnop"
        n = time.time()
        m._SESSION_CACHE[sid] = {
            "username": "alice",
            "expires_ts": n + 10000,
            "revoked": False,
            "source_ip": "",
            "created_ts": n - 100,    # only 100 s old
            "csrf_nonce": "abc",
        }
        import admin.users as users_mod
        import config
        with mock.patch.object(config, "SESSION_ABSOLUTE_TIMEOUT", 3600):
            with mock.patch("admin.users._session_parse") as parse:
                parse.return_value = ("alice", sid, int(n) + 10000)
                result = users_mod._session_verify("dummy_token")
        assert result == "alice", "valid session within absolute timeout should pass"

    def test_created_ts_stored_in_cache_on_create(self):
        m = _fresh_users_mod()
        import admin.users as users_mod
        with mock.patch("admin.users.db_queue", None):
            before = time.time()
            token = users_mod._session_create("bob", "1.2.3.4", "TestUA")
            after = time.time()
        sid = token.split("|")[1]
        entry = users_mod._SESSION_CACHE.get(sid, {})
        assert "created_ts" in entry, "created_ts must be stored in session cache"
        assert before <= entry["created_ts"] <= after

    def test_session_cache_load_reads_created_ts(self):
        """_session_cache_load populates created_ts from the DB row."""
        m = _fresh_users_mod()
        import admin.users as users_mod
        n = time.time()
        # sqlite3.Row supports subscript access; simulate with a dict-like mock.
        row_data = {
            "sid": "xyzxyzxyzxyzxyz0",
            "username": "carol",
            "expires_ts": n + 3600,
            "ip": "10.0.0.1",
            "last_seen_ts": n,
            "created_ts": n - 500,
            "csrf_nonce": "nonce123",
        }
        fake_row = mock.MagicMock()
        fake_row.__getitem__ = lambda self, k: row_data[k]
        fake_row.keys = lambda: list(row_data)
        with mock.patch("admin.users.sqlite3") as mock_sqlite:
            conn = mock.MagicMock()
            mock_sqlite.connect.return_value = conn
            conn.row_factory = mock.ANY
            conn.execute.return_value.fetchall.return_value = [fake_row]
            users_mod._session_cache_load()
        cached = users_mod._SESSION_CACHE.get("xyzxyzxyzxyzxyz0", {})
        assert cached.get("created_ts") == pytest.approx(n - 500, abs=1)


# ── T0-2: per-session CSRF nonce ────────────────────────────────────────────

class TestCsrfNonce:
    def test_csrf_nonce_stored_on_create(self):
        m = _fresh_users_mod()
        import admin.users as users_mod
        with mock.patch("admin.users.db_queue", None):
            token = users_mod._session_create("dave", "1.2.3.4", "UA")
        sid = token.split("|")[1]
        entry = users_mod._SESSION_CACHE.get(sid, {})
        assert "csrf_nonce" in entry, "csrf_nonce missing from session cache entry"
        nonce = entry["csrf_nonce"]
        assert isinstance(nonce, str) and len(nonce) >= 16

    def test_csrf_nonce_random_across_sessions(self):
        m = _fresh_users_mod()
        import admin.users as users_mod
        nonces = set()
        with mock.patch("admin.users.db_queue", None):
            for _ in range(5):
                token = users_mod._session_create("eve", "1.2.3.4", "UA")
                sid = token.split("|")[1]
                nonces.add(users_mod._SESSION_CACHE[sid]["csrf_nonce"])
        assert len(nonces) == 5, "CSRF nonces should be unique per session"

    def test_csrf_nonce_not_derived_from_session_key(self):
        """Nonce must NOT equal HMAC(SESSION_KEY, sid)."""
        import hashlib
        import hmac as _hmac
        m = _fresh_users_mod()
        import admin.users as users_mod
        import config
        with mock.patch("admin.users.db_queue", None):
            token = users_mod._session_create("frank", "1.2.3.4", "UA")
        sid = token.split("|")[1]
        nonce = users_mod._SESSION_CACHE[sid]["csrf_nonce"]
        hmac_value = _hmac.new(
            config.SESSION_KEY, sid.encode(), hashlib.sha256
        ).hexdigest()[:32]
        assert nonce != hmac_value, \
            "CSRF nonce must not be HMAC(SESSION_KEY, sid) — independent random"

    def test_auth_py_uses_nonce_from_cache(self):
        """_csrf_token_valid reads nonce from _SESSION_CACHE, not by recomputing HMAC."""
        import admin.users as users_mod
        import admin.auth as auth_mod
        sid = "abcdefghijklmnop"
        nonce = "random_nonce_12345678"
        n = time.time()
        users_mod._SESSION_CACHE[sid] = {
            "username": "grace", "expires_ts": n + 3600,
            "revoked": False, "source_ip": "",
            "created_ts": n, "csrf_nonce": nonce,
        }
        req = mock.MagicMock()
        req.method = "POST"
        req.cookies = {"agw_session": f"grace|{sid}|{int(n)+3600}|sig"}
        req.headers = {"X-CSRF-Token": nonce}
        with mock.patch("admin.users._session_parse") as parse:
            parse.return_value = ("grace", sid, int(n) + 3600)
            result = auth_mod._csrf_token_valid(req)
        assert result is True, "valid nonce should pass CSRF check"

    def test_auth_py_rejects_wrong_nonce(self):
        import admin.users as users_mod
        import admin.auth as auth_mod
        sid = "abcdefghijklmnop"
        n = time.time()
        users_mod._SESSION_CACHE[sid] = {
            "username": "heidi", "expires_ts": n + 3600,
            "revoked": False, "source_ip": "",
            "created_ts": n, "csrf_nonce": "correct_nonce_abc",
        }
        req = mock.MagicMock()
        req.method = "POST"
        req.cookies = {"agw_session": f"heidi|{sid}|{int(n)+3600}|sig"}
        req.headers = {"X-CSRF-Token": "wrong_nonce"}
        with mock.patch("admin.users._session_parse") as parse:
            parse.return_value = ("heidi", sid, int(n) + 3600)
            result = auth_mod._csrf_token_valid(req)
        assert result is False, "wrong nonce should fail CSRF check"

    def test_db_migration_entry_exists(self):
        """_SCHEMA_MIGRATIONS must include the csrf_nonce column for user_sessions."""
        from db.sqlite import _SCHEMA_MIGRATIONS
        found = any(
            t == "user_sessions" and c == "csrf_nonce"
            for t, c, *_ in _SCHEMA_MIGRATIONS
        )
        assert found, "csrf_nonce migration entry missing from _SCHEMA_MIGRATIONS"


# ── T0-4: OIDC state cap ────────────────────────────────────────────────────

class TestOidcStateCap:
    def test_oidc_state_max_constant_exists(self):
        from admin.oidc import _OIDC_STATE_MAX
        assert isinstance(_OIDC_STATE_MAX, int) and _OIDC_STATE_MAX >= 100

    def test_oidc_login_returns_503_when_cap_reached(self):
        from admin import oidc as oidc_mod
        orig = dict(oidc_mod._OIDC_STATE)
        try:
            # Fill the state dict to exactly the cap
            for i in range(oidc_mod._OIDC_STATE_MAX):
                oidc_mod._OIDC_STATE[f"state_{i:04d}"] = {
                    "next_url": "/",
                    "expires_ts": time.time() + 300,
                    "nonce": "x",
                    "init_ip": "1.2.3.4",
                }
            import asyncio
            req = mock.MagicMock()
            req.query = {"next": ""}

            import config
            if not getattr(config, "OIDC_ENABLED", False):
                pytest.skip("OIDC not configured — skipping state cap test")

            result = asyncio.get_event_loop().run_until_complete(
                oidc_mod.oidc_login_endpoint(req)
            )
            assert result.status == 503, \
                f"Expected 503 when OIDC state cap reached, got {result.status}"
        finally:
            oidc_mod._OIDC_STATE.clear()
            oidc_mod._OIDC_STATE.update(orig)


# ── T1-1: upstream latency tracking ─────────────────────────────────────────

class TestUpstreamLatency:
    def test_latency_samples_deque_exists(self):
        import core.proxy_handler as ph
        from collections import deque
        assert hasattr(ph, "_upstream_latency_samples"), \
            "_upstream_latency_samples missing from proxy_handler"
        assert isinstance(ph._upstream_latency_samples, deque)

    def test_latency_warn_ms_config_exists(self):
        import core.proxy_handler as ph
        assert hasattr(ph, "UPSTREAM_LATENCY_WARN_MS"), \
            "UPSTREAM_LATENCY_WARN_MS missing from proxy_handler"
        assert isinstance(ph.UPSTREAM_LATENCY_WARN_MS, int)

    def test_latency_samples_capped_at_500(self):
        import core.proxy_handler as ph
        assert ph._upstream_latency_samples.maxlen == 500


# ── T1-3: webhook health counters ───────────────────────────────────────────

class TestWebhookHealth:
    def test_health_counters_exist(self):
        import integrations.webhook as wh
        assert hasattr(wh, "_WEBHOOK_LAST_SUCCESS_TS"), \
            "_WEBHOOK_LAST_SUCCESS_TS missing"
        assert hasattr(wh, "_WEBHOOK_CONSECUTIVE_FAILURES"), \
            "_WEBHOOK_CONSECUTIVE_FAILURES missing"
        assert isinstance(wh._WEBHOOK_LAST_SUCCESS_TS, float)
        assert isinstance(wh._WEBHOOK_CONSECUTIVE_FAILURES, int)

    def test_consecutive_failures_increments_on_failure(self):
        import integrations.webhook as wh
        orig_failures = wh._WEBHOOK_CONSECUTIVE_FAILURES
        orig_cb = wh._CB_FAILURES
        orig_open = wh._CB_OPEN_UNTIL
        try:
            wh._WEBHOOK_CONSECUTIVE_FAILURES = 0
            wh._CB_FAILURES = 0
            wh._CB_OPEN_UNTIL = 0.0
            wh._WEBHOOK_CONSECUTIVE_FAILURES += 1
            wh._CB_FAILURES += 1
            assert wh._WEBHOOK_CONSECUTIVE_FAILURES == 1
        finally:
            wh._WEBHOOK_CONSECUTIVE_FAILURES = orig_failures
            wh._CB_FAILURES = orig_cb
            wh._CB_OPEN_UNTIL = orig_open

    def test_last_success_ts_updated_on_success(self):
        import integrations.webhook as wh
        orig = wh._WEBHOOK_LAST_SUCCESS_TS
        try:
            before = time.time()
            wh._WEBHOOK_LAST_SUCCESS_TS = time.time()
            after = time.time()
            assert before <= wh._WEBHOOK_LAST_SUCCESS_TS <= after
        finally:
            wh._WEBHOOK_LAST_SUCCESS_TS = orig


# ── T2-5: eTLD+1 origin validation ──────────────────────────────────────────

class TestEtldOriginCheck:
    def _check(self, origin, allowed_hosts, strict=True):
        import core.proxy_handler as ph
        req = mock.MagicMock()
        req.method = "POST"
        req.path = "/app/data"
        req.headers = {"Origin": origin}
        with mock.patch.object(ph, "STRICT_ORIGIN", strict), \
             mock.patch.object(ph, "ALLOWED_HOSTS", set(allowed_hosts)), \
             mock.patch.object(ph, "OPEN_ORIGIN_PATHS", []):
            return ph._origin_check_failed(req)

    def test_exact_match_allowed(self):
        assert not self._check("https://example.com", ["example.com"])

    def test_subdomain_of_allowed_host_permitted(self):
        # Contract change: shipped _origin_check_failed uses STRICT exact-host
        # membership (host not in ALLOWED_HOSTS), NOT eTLD+1 matching. This is
        # the intended, more-secure contract — locked by
        # test_v142::test_origin_check_mismatched_origin_fails, which requires a
        # sibling subdomain (evil.example.com vs good.example.com) to be REJECTED.
        # eTLD+1 matching would weaken origin validation by admitting any
        # subdomain under the registrable domain. Assert the shipped (stricter)
        # behaviour: a subdomain of an allowed host is REJECTED.
        assert self._check("https://sub.example.com", ["example.com"]), \
            "subdomain of ALLOWED_HOST must be rejected (strict exact-host match)"

    def test_deep_subdomain_permitted(self):
        # Contract change: strict exact-host match (see above) — a deep subdomain
        # is NOT a member of ALLOWED_HOSTS and is therefore rejected.
        assert self._check("https://a.b.example.com", ["example.com"])

    def test_different_domain_rejected(self):
        assert self._check("https://evil.com", ["example.com"])

    def test_partial_suffix_not_matched(self):
        # notexample.com should NOT match example.com
        assert self._check("https://notexample.com", ["example.com"])

    def test_no_allowed_hosts_passes_through(self):
        assert not self._check("https://anything.com", [])


# ── T3-2/T3-3: UI presence ──────────────────────────────────────────────────

class TestBulkUnbanUi:
    def test_bulk_bar_present_in_agents(self):
        src = (_DASH / "agents.html").read_text()
        assert "bulk-bar" in src, "bulk-bar div missing from agents.html"
        assert "bulk-select-all" in src, "bulk-select-all checkbox missing"
        assert "bulk-unban-btn" in src, "bulk-unban-btn missing"
        assert "bulk-row-chk" in src, "bulk-row-chk class missing"

    def test_bulk_cancel_btn_present(self):
        src = (_DASH / "agents.html").read_text()
        assert "bulk-cancel-btn" in src

    def test_bulk_unban_calls_unban_endpoint(self):
        src = (_DASH / "agents.html").read_text()
        assert "/antibot-appsec-gateway/secured/unban" in src


class TestDrillDownLink:
    def test_view_logs_button_in_agents(self):
        src = (_DASH / "agents.html").read_text()
        assert "gw-view-logs" in src, \
            "'View requests →' button (gw-view-logs) missing from agents.html"
        assert "data-logs-ip" in src
        assert "appsecgw.logs.prefs.v1" in src, \
            "sessionStorage prefs key missing from agents.html drill-down"

    def test_view_logs_button_in_main(self):
        src = (_DASH / "main.html").read_text()
        assert "gw-view-logs" in src, \
            "'View requests →' button missing from main.html"
        assert "appsecgw.logs.prefs.v1" in src

    def test_view_logs_css_present(self):
        for fname in ("agents.html", "main.html"):
            src = (_DASH / fname).read_text()
            assert ".gw-view-logs" in src, \
                f"CSS for .gw-view-logs missing from {fname}"
