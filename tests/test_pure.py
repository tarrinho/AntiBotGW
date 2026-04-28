"""
Pure-function tests — no HTTP, no async. Fast and isolated.

Covers the security-critical helpers that have caused real incidents:
  - admin-key strip from query string
  - session cookie strip from forwarded Cookie
  - honey-link injection (mis-injection bug in 1.0/1.1)
  - session-cookie HMAC sign + verify (incl. empty-sid rejection from N3)
  - PoW issue + verify (including replay protection from N4)
  - suspicious-path regex anchoring (the password-recovery false positive)
  - control-byte path rejection (N5)
  - browser fingerprint stability (the Sec-Ch-Ua split-identity bug)
  - admin IP allowlist semantics (CIDR + single IP + IPv6)
"""
import re
import hashlib
import time
import pytest


# ── _strip_admin_key_from_qs ──────────────────────────────────────────────

@pytest.mark.parametrize("inp,expected", [
    ("/foo",                                      "/foo"),
    ("/foo?bar=1",                                "/foo?bar=1"),
    ("/foo?key=SECRET",                           "/foo"),
    ("/foo?key=SECRET&bar=1",                     "/foo?bar=1"),
    ("/foo?bar=1&key=SECRET",                     "/foo?bar=1"),
    ("/foo?bar=1&key=SECRET&baz=2",               "/foo?bar=1&baz=2"),
    ("/foo?keyword=ok",                           "/foo?keyword=ok"),  # no false strip
    ("/foo?key=A&key=B",                          "/foo"),             # both stripped
    ("/foo?key=",                                 "/foo"),
])
def test_strip_admin_key_from_qs(proxy_module, inp, expected):
    assert proxy_module._strip_admin_key_from_qs(inp) == expected


# ── _strip_own_session_cookie ─────────────────────────────────────────────

def test_strip_own_session_cookie_removes_aid(proxy_module):
    raw = "aid=session.sig; KEYCLOAK=foo; tracker=bar"
    out = proxy_module._strip_own_session_cookie(raw)
    assert "aid=" not in out
    assert "KEYCLOAK=foo" in out
    assert "tracker=bar" in out


def test_strip_own_session_cookie_keeps_others(proxy_module):
    raw = "KEYCLOAK=abc"
    assert proxy_module._strip_own_session_cookie(raw) == "KEYCLOAK=abc"


def test_strip_own_session_cookie_empty_returns_empty(proxy_module):
    assert proxy_module._strip_own_session_cookie("") == ""


# ── honey-link injection ─────────────────────────────────────────────────

def test_inject_honey_links_inserts_before_last_body_close(proxy_module):
    body = b"<html><body>hello</body></html>"
    out = proxy_module._inject_honey_links(body)
    assert b"_internal/audit-log" in out
    assert out.endswith(b"</body></html>")


def test_inject_honey_links_skips_when_post_body_script(proxy_module):
    """N8: bail out if a <script> follows the chosen </body> in the tail —
    avoids corrupting JS string literals inside post-body scripts."""
    body = b"<html><body>x</body><script>var s='</body>'</script></html>"
    out = proxy_module._inject_honey_links(body)
    # No injection (output unchanged).
    assert out == body


def test_inject_honey_links_no_body_tag_returns_unchanged(proxy_module):
    body = b'{"json": "no html here"}'
    assert proxy_module._inject_honey_links(body) == body


# ── session HMAC sign / verify ───────────────────────────────────────────

def test_sign_then_verify_round_trip(proxy_module):
    sid = proxy_module.secrets.token_urlsafe(12)
    token = proxy_module._sign_session(sid)
    assert proxy_module._verify_session(token) == sid


def test_verify_session_rejects_empty_sid(proxy_module):
    """N3: an HMAC-valid token over the empty string must NOT authenticate."""
    import hmac as _hmac
    import hashlib as _hashlib
    sig = _hmac.new(proxy_module.SESSION_KEY, b"", _hashlib.sha256).hexdigest()
    assert proxy_module._verify_session("." + sig) is None


def test_verify_session_rejects_bad_charset(proxy_module):
    sid = "bad/sid+with*chars"
    sig = "a" * 64
    assert proxy_module._verify_session(sid + "." + sig) is None


def test_verify_session_rejects_overlong_sid(proxy_module):
    sid = "A" * 65
    sig = "a" * 64
    assert proxy_module._verify_session(sid + "." + sig) is None


def test_verify_session_rejects_truncated_sig(proxy_module):
    sid = "abc"
    assert proxy_module._verify_session(sid + ".short") is None


def test_verify_session_rejects_forged_sig(proxy_module):
    assert proxy_module._verify_session("abc." + "0" * 64) is None


# ── PoW issue + verify (N4: bind + replay) ───────────────────────────────

def _solve(nonce: str, difficulty: int) -> str:
    target = "0" * difficulty
    for i in range(10_000_000):
        if hashlib.sha256(f"{nonce}{i}".encode()).hexdigest().startswith(target):
            return str(i)
    raise RuntimeError("did not find solution in time")


def test_pow_round_trip(proxy_module):
    ch = proxy_module.make_pow_challenge("POST", "/login")
    nonce, _issued, diff, _bind, _sig = ch.split("|")
    sol = _solve(nonce, int(diff))
    ok, _why = proxy_module.verify_pow(ch, sol, "POST", "/login")
    assert ok


def test_pow_replay_rejected(proxy_module):
    ch = proxy_module.make_pow_challenge("POST", "/login")
    nonce, _issued, diff, _bind, _sig = ch.split("|")
    sol = _solve(nonce, int(diff))
    assert proxy_module.verify_pow(ch, sol, "POST", "/login")[0]
    ok, why = proxy_module.verify_pow(ch, sol, "POST", "/login")
    assert not ok
    assert "replay" in why.lower()


def test_pow_wrong_method_rejected(proxy_module):
    ch = proxy_module.make_pow_challenge("POST", "/login")
    nonce, _issued, diff, _bind, _sig = ch.split("|")
    sol = _solve(nonce, int(diff))
    ok, why = proxy_module.verify_pow(ch, sol, "GET", "/login")
    assert not ok
    assert "bind" in why.lower() or "not bound" in why.lower()


def test_pow_wrong_path_rejected(proxy_module):
    ch = proxy_module.make_pow_challenge("POST", "/login")
    nonce, _issued, diff, _bind, _sig = ch.split("|")
    sol = _solve(nonce, int(diff))
    ok, why = proxy_module.verify_pow(ch, sol, "POST", "/admin")
    assert not ok
    assert "bind" in why.lower() or "not bound" in why.lower()


def test_pow_legacy_unbound_rejected(proxy_module):
    """4-segment legacy tokens (no METHOD:path bind) must be rejected."""
    ok, why = proxy_module.verify_pow("nonce|123|5|abc", "1", "POST", "/")
    assert not ok


def test_pow_malformed_rejected(proxy_module):
    ok, why = proxy_module.verify_pow("garbage", "1", "POST", "/")
    assert not ok


# ── is_suspicious_path (the password-recovery regression) ────────────────

@pytest.mark.parametrize("path,expected", [
    # Real attack patterns — must match
    ("/etc/passwd",                      True),
    ("/.git/HEAD",                       True),
    ("/foo/passwd.bak",                  True),
    ("/api/secrets.yaml",                True),
    ("/.aws/credentials",                False),  # in HONEYPOT_PATHS, not pattern
    ("/foo/../../../etc/passwd",         True),
    ("/path?q=union+select+*",           True),
    # Legitimate paths previously false-flagged by `passw[do]` — must NOT match
    ("/content/productcatalogue/ufe/v5/micro-frontends/password-recovery/passwordRecovery.js",
                                          False),
    ("/api/v1/credentials-manager/list", False),
    ("/static/private-key-icon.svg",     False),
    ("/health",                           False),
])
def test_is_suspicious_path(proxy_module, path, expected):
    assert proxy_module.is_suspicious_path(path) is expected


# ── browser_fingerprint stability across sub-resource fetches ────────────

class _FakeReq:
    def __init__(self, headers):
        self.headers = headers


def test_browser_fingerprint_stable_with_or_without_sec_ch_ua(proxy_module):
    """The Sec-Ch-Ua split-identity bug: navigation has Sec-Ch-Ua, sub-resource
    fetches don't. Fingerprint MUST stay stable across both."""
    nav = _FakeReq({
        "User-Agent":      "Mozilla/5.0 Chrome/120 Safari/537.36",
        "Accept-Language": "en-GB",
        "Accept-Encoding": "gzip",
        "Sec-Ch-Ua":       '"Chromium";v="120"',
    })
    fetch = _FakeReq({
        "User-Agent":      "Mozilla/5.0 Chrome/120 Safari/537.36",
        "Accept-Language": "en-GB",
        "Accept-Encoding": "gzip",
        # no Sec-Ch-Ua sent on sub-resource
    })
    assert proxy_module.browser_fingerprint(nav) == proxy_module.browser_fingerprint(fetch)


def test_browser_fingerprint_differs_on_different_uas(proxy_module):
    a = _FakeReq({"User-Agent": "X", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    b = _FakeReq({"User-Agent": "Y", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    assert proxy_module.browser_fingerprint(a) != proxy_module.browser_fingerprint(b)


# ── _admin_ip_allowed semantics ──────────────────────────────────────────

class _IPReq:
    def __init__(self, ip):
        self.headers = {}
        self.remote = ip
        self.scheme = "http"
        self.host = "x"
        self.query_string = ""
        self.path = "/"


def test_admin_ip_allowed_open_when_unset(proxy_module):
    """No allowlist → all IPs allowed (admin key still required)."""
    proxy_module.ADMIN_ALLOWED_NETS.clear()
    assert proxy_module._admin_ip_allowed(_IPReq("8.8.8.8")) is True


def test_admin_ip_allowed_single_ip(proxy_module):
    import ipaddress
    proxy_module.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("203.0.113.5")]
    assert proxy_module._admin_ip_allowed(_IPReq("203.0.113.5")) is True
    assert proxy_module._admin_ip_allowed(_IPReq("203.0.113.6")) is False


def test_admin_ip_allowed_cidr(proxy_module):
    import ipaddress
    proxy_module.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("10.0.0.0/8")]
    assert proxy_module._admin_ip_allowed(_IPReq("10.42.42.42")) is True
    assert proxy_module._admin_ip_allowed(_IPReq("11.0.0.1")) is False


def test_admin_ip_allowed_ipv6(proxy_module):
    import ipaddress
    proxy_module.ADMIN_ALLOWED_NETS[:] = [ipaddress.ip_network("2001:db8::/64")]
    assert proxy_module._admin_ip_allowed(_IPReq("2001:db8::1")) is True
    assert proxy_module._admin_ip_allowed(_IPReq("2001:db9::1")) is False


# ── _internal_authed (constant-time admin-key compare) ───────────────────

class _AuthReq:
    def __init__(self, header=None, query=None):
        self.headers = {"X-Admin-Key": header} if header is not None else {}
        self.query = {"key": query} if query is not None else {}


def test_internal_authed_accepts_correct_header(proxy_module):
    assert proxy_module._internal_authed(_AuthReq(header=proxy_module.INTERNAL_KEY))


def test_internal_authed_accepts_correct_query(proxy_module):
    assert proxy_module._internal_authed(_AuthReq(query=proxy_module.INTERNAL_KEY))


def test_internal_authed_rejects_wrong_key(proxy_module):
    assert not proxy_module._internal_authed(_AuthReq(header="WRONG-KEY"))


def test_internal_authed_rejects_empty(proxy_module):
    assert not proxy_module._internal_authed(_AuthReq())
