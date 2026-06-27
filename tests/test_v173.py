"""
Tests for v1.7.3 AI-agent detection features:
  P1 — Semantic honeypot credential injection (honey_cred)
  P3 — LLM no-subresource heuristic (llm_heuristic)
  P4 — Browser execution probe (canary_probe via canary.py)
"""
import hashlib
import hmac
import os
import time
import pytest


# ── P1: Honeypot credential injection ────────────────────────────────────────

class TestHoneyCred:
    def test_inject_adds_comment_before_body(self):
        from detection.honey_cred import inject_honey_creds
        body = b"<html><body><p>hello</p></body></html>"
        identity = "testidentity"
        result = inject_honey_creds(body, identity)
        assert b"internal_api_key" in result
        assert b"debug_endpoint" in result
        # Comment must appear before </body>
        comment_idx = result.find(b"internal_api_key")
        body_tag_idx = result.find(b"</body>")
        assert comment_idx < body_tag_idx

    def test_inject_appends_when_no_body_tag(self):
        from detection.honey_cred import inject_honey_creds
        body = b"<html><p>no body tag</p></html>"
        result = inject_honey_creds(body, "id123")
        assert b"internal_api_key" in result

    def test_inject_noop_when_disabled(self, monkeypatch):
        import detection.honey_cred as hc
        monkeypatch.setattr(hc, "HONEY_CRED_ENABLED", False)
        body = b"<html><body></body></html>"
        assert hc.inject_honey_creds(body, "id") == body

    def test_inject_noop_on_empty_body(self):
        from detection.honey_cred import inject_honey_creds
        assert inject_honey_creds(b"", "id") == b""

    def test_inject_noop_on_empty_identity(self):
        from detection.honey_cred import inject_honey_creds
        body = b"<html><body></body></html>"
        assert inject_honey_creds(body, "") == body

    def test_lookup_returns_identity_for_valid_key(self):
        from detection.honey_cred import inject_honey_creds, lookup_honey_key, _honey_key_store
        body = b"<html><body></body></html>"
        identity = "user_abc"
        inject_honey_creds(body, identity)
        # Find the key that was stored for this identity
        found_key = next(
            (k for k, (ident, _) in _honey_key_store.items() if ident == identity),
            None,
        )
        assert found_key is not None
        assert lookup_honey_key(found_key) == identity

    def test_lookup_returns_empty_for_unknown_key(self):
        from detection.honey_cred import lookup_honey_key
        assert lookup_honey_key("not-a-real-key") == ""

    def test_lookup_returns_empty_for_empty_key(self):
        from detection.honey_cred import lookup_honey_key
        assert lookup_honey_key("") == ""

    def test_key_contains_probe_url(self):
        from detection.honey_cred import inject_honey_creds
        body = b"<html><body></body></html>"
        result = inject_honey_creds(body, "probe_test")
        assert b"/probe?k=" in result

    def test_key_format_hex32(self):
        """Honey key must be 32 hex characters."""
        from detection.honey_cred import _make_honey_key
        key = _make_honey_key("some_identity")
        assert len(key) == 32
        assert all(c in "0123456789abcdef" for c in key)


# ── P3: LLM no-subresource heuristic ─────────────────────────────────────────

class TestLLMHeuristic:
    def _fresh_module(self):
        """Import a fresh instance with cleared state."""
        import detection.llm_heuristic as m
        m._req_log.clear()
        m._fired.clear()
        return m

    def test_html_only_requests_trigger_signal(self):
        m = self._fresh_module()
        identity = "llmbot"
        for _ in range(6):
            m.observe(identity, "GET", "/page", "text/html,application/xhtml+xml")
        score = m.check(identity, "1.2.3.4")
        assert score > 0

    def test_mixed_requests_do_not_trigger(self):
        m = self._fresh_module()
        identity = "realbrowser"
        # 5 HTML + 5 CSS = ratio 1.0 > threshold 0.0
        for _ in range(5):
            m.observe(identity, "GET", "/page", "text/html")
        for _ in range(5):
            m.observe(identity, "GET", "/style.css", "text/css")
        score = m.check(identity, "1.2.3.4")
        assert score == 0.0

    def test_below_min_count_no_signal(self):
        m = self._fresh_module()
        identity = "few_pages"
        for _ in range(3):  # LLM_HTML_MIN_COUNT=5
            m.observe(identity, "GET", "/page", "text/html")
        score = m.check(identity, "1.2.3.4")
        assert score == 0.0

    def test_cooldown_prevents_double_fire(self):
        m = self._fresh_module()
        identity = "cooldown_test"
        for _ in range(10):
            m.observe(identity, "GET", "/page", "text/html")
        first = m.check(identity, "1.2.3.4")
        second = m.check(identity, "1.2.3.4")
        assert first > 0
        assert second == 0.0  # cooldown

    def test_is_subresource_css(self):
        from detection.llm_heuristic import _is_subresource
        assert _is_subresource("/style.css", "") is True
        assert _is_subresource("/main.js", "") is True
        assert _is_subresource("/logo.png", "") is True
        assert _is_subresource("/font.woff2", "") is True

    def test_is_subresource_json_api(self):
        from detection.llm_heuristic import _is_subresource
        assert _is_subresource("/api/data", "application/json") is True
        # text/html wins: not a sub-resource
        assert _is_subresource("/page", "text/html,application/json") is False

    def test_is_html_request(self):
        from detection.llm_heuristic import _is_html_request
        assert _is_html_request("GET", "text/html", "/page") is True
        assert _is_html_request("GET", "*/*", "/") is True
        assert _is_html_request("POST", "text/html", "/submit") is False
        assert _is_html_request("GET", "text/html", "/file.css") is False

    def test_post_requests_not_recorded(self):
        m = self._fresh_module()
        identity = "post_only"
        for _ in range(10):
            m.observe(identity, "POST", "/api/submit", "application/json")
        score = m.check(identity, "1.2.3.4")
        assert score == 0.0

    def test_disabled_returns_zero(self, monkeypatch):
        import detection.llm_heuristic as m
        monkeypatch.setattr(m, "LLM_HEURISTIC_ENABLED", False)
        m._req_log.clear()
        m._fired.clear()
        for _ in range(10):
            m.observe("id", "GET", "/page", "text/html")
        assert m.check("id", "1.2.3.4") == 0.0


# ── P4: Browser execution probe ───────────────────────────────────────────────

class TestCanaryProbe:
    def _fresh(self):
        import detection.canary as c
        c._probe_token_store.clear()
        c._probe_html_counts.clear()
        c._probe_confirmed.clear()
        return c

    def test_inject_adds_preload_link(self):
        c = self._fresh()
        body = b"<html><head></head><body></body></html>"
        result = c.inject_canary_probe(body, "browserId")
        assert b'rel="preload"' in result
        assert b'as="fetch"' in result
        assert b"canary-probe" in result

    def test_inject_before_head_close(self):
        c = self._fresh()
        body = b"<html><head><title>T</title></head><body></body></html>"
        result = c.inject_canary_probe(body, "bid")
        head_close = result.find(b"</head>")
        link_pos = result.find(b"preload")
        assert link_pos < head_close

    def test_inject_noop_when_disabled(self, monkeypatch):
        import detection.canary as c
        c._probe_token_store.clear()
        c._probe_html_counts.clear()
        c._probe_confirmed.clear()
        monkeypatch.setattr(c, "CANARY_PROBE_ENABLED", False)
        body = b"<html><head></head><body></body></html>"
        assert c.inject_canary_probe(body, "id") == body

    def test_inject_noop_on_empty_body(self):
        c = self._fresh()
        assert c.inject_canary_probe(b"", "id") == b""

    def test_inject_noop_on_empty_identity(self):
        c = self._fresh()
        body = b"<html><head></head><body></body></html>"
        assert c.inject_canary_probe(body, "") == body

    def test_check_returns_zero_before_min_count(self):
        c = self._fresh()
        body = b"<html><head></head><body></body></html>"
        for _ in range(2):  # CANARY_PROBE_MIN_HTML=3
            c.inject_canary_probe(body, "shortid")
        score = c.check_canary_probe("shortid", "1.2.3.4")
        assert score == 0.0

    def test_check_returns_zero_before_ttl_elapsed(self):
        c = self._fresh()
        body = b"<html><head></head><body></body></html>"
        for _ in range(5):
            c.inject_canary_probe(body, "fastid")
        # TTL hasn't elapsed yet (inject sets first_seen_ts to now)
        score = c.check_canary_probe("fastid", "1.2.3.4")
        assert score == 0.0

    def test_check_fires_after_ttl_elapsed(self, monkeypatch):
        import detection.canary as c
        c._probe_token_store.clear()
        c._probe_html_counts.clear()
        c._probe_confirmed.clear()
        body = b"<html><head></head><body></body></html>"
        for _ in range(5):
            c.inject_canary_probe(body, "slowid")
        # Simulate TTL elapsed by backdating first_seen_ts
        c._probe_html_counts["slowid"][0] -= c.CANARY_PROBE_TTL_SECS + 5
        score = c.check_canary_probe("slowid", "1.2.3.4")
        assert score > 0

    def test_check_returns_zero_when_confirmed(self, monkeypatch):
        import detection.canary as c
        c._probe_token_store.clear()
        c._probe_html_counts.clear()
        c._probe_confirmed.clear()
        body = b"<html><head></head><body></body></html>"
        for _ in range(5):
            c.inject_canary_probe(body, "browserid")
        c._probe_html_counts["browserid"][0] -= c.CANARY_PROBE_TTL_SECS + 5
        # Mark as browser-confirmed
        c._probe_confirmed["browserid"] = time.time()
        score = c.check_canary_probe("browserid", "1.2.3.4")
        assert score == 0.0

    def test_token_stored_and_retrievable(self):
        c = self._fresh()
        body = b"<html><head></head><body></body></html>"
        c.inject_canary_probe(body, "tok_id")
        # Some token for tok_id should now be in store
        found = any(ident == "tok_id" for (ident, _) in c._probe_token_store.values())
        assert found

    def test_probe_token_format(self):
        from detection.canary import _make_canary_probe_token
        token = _make_canary_probe_token("any_identity")
        assert len(token) == 24
        assert all(c in "0123456789abcdef" for c in token)
