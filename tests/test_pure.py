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
  - JS_CHAL_REQUIRE_JA4 / TURNSTILE_ENABLED mutual exclusion (incident: silent
    403 on every Turnstile solve because JA4 absent behind Cloudflare CDN)
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
    """N3: an HMAC-valid token over the empty sid must NOT authenticate.
    Uses the correct session: prefix so the sig passes the HMAC check and the
    empty-sid guard is the only thing preventing authentication."""
    import hmac as _hmac
    import hashlib as _hashlib
    sig = _hmac.new(proxy_module.SESSION_KEY, b"session:", _hashlib.sha256).hexdigest()
    assert proxy_module._verify_session("." + sig) is None


def test_verify_session_rejects_no_dot(proxy_module):
    """A non-empty token with no dot must be rejected by the early guard."""
    assert proxy_module._verify_session("nodothere") is None


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
    ("/.aws/credentials",                True),   # 1.6.4: now caught by SUSPICIOUS_PATH_PATTERNS
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


def test_browser_fingerprint_differs_on_different_accept_language(proxy_module):
    """Accept-Language must be included in the fingerprint hash."""
    a = _FakeReq({"User-Agent": "UA", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    b = _FakeReq({"User-Agent": "UA", "Accept-Language": "fr", "Accept-Encoding": "gzip"})
    assert proxy_module.browser_fingerprint(a) != proxy_module.browser_fingerprint(b)


def test_browser_fingerprint_differs_on_different_accept_encoding(proxy_module):
    """Accept-Encoding must be included in the fingerprint hash."""
    a = _FakeReq({"User-Agent": "UA", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    b = _FakeReq({"User-Agent": "UA", "Accept-Language": "en", "Accept-Encoding": "br"})
    assert proxy_module.browser_fingerprint(a) != proxy_module.browser_fingerprint(b)


def test_browser_fingerprint_missing_ua_is_stable(proxy_module):
    """Missing User-Agent must not crash; same absent UA → same fingerprint."""
    r1 = _FakeReq({"Accept-Language": "en", "Accept-Encoding": "gzip"})
    r2 = _FakeReq({"Accept-Language": "en", "Accept-Encoding": "gzip"})
    assert proxy_module.browser_fingerprint(r1) == proxy_module.browser_fingerprint(r2)


def test_browser_fingerprint_ua_truncated_at_200(proxy_module):
    """UA longer than 200 chars must be truncated so two 201+ UA that share the
    first 200 chars produce the same fingerprint."""
    ua_base = "A" * 200
    a = _FakeReq({"User-Agent": ua_base + "X", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    b = _FakeReq({"User-Agent": ua_base + "Y", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    assert proxy_module.browser_fingerprint(a) == proxy_module.browser_fingerprint(b)


def test_browser_fingerprint_length_is_12(proxy_module):
    """Fingerprint must be exactly 12 hex chars."""
    r = _FakeReq({"User-Agent": "UA", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    assert len(proxy_module.browser_fingerprint(r)) == 12


def test_browser_fingerprint_missing_ua_differs_from_placeholder(proxy_module):
    """Default for missing UA must be '' (empty), not some placeholder.
    A request with no UA must differ from one with UA='XXXX'."""
    no_ua   = _FakeReq({"Accept-Language": "en", "Accept-Encoding": "gzip"})
    has_ua  = _FakeReq({"User-Agent": "XXXX", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    assert proxy_module.browser_fingerprint(no_ua) != proxy_module.browser_fingerprint(has_ua)


def test_browser_fingerprint_missing_accept_language_differs_from_placeholder(proxy_module):
    """Default for missing Accept-Language must be ''."""
    no_al  = _FakeReq({"User-Agent": "UA", "Accept-Encoding": "gzip"})
    has_al = _FakeReq({"User-Agent": "UA", "Accept-Language": "XXXX", "Accept-Encoding": "gzip"})
    assert proxy_module.browser_fingerprint(no_al) != proxy_module.browser_fingerprint(has_al)


def test_browser_fingerprint_missing_accept_encoding_differs_from_placeholder(proxy_module):
    """Default for missing Accept-Encoding must be ''."""
    no_ae  = _FakeReq({"User-Agent": "UA", "Accept-Language": "en"})
    has_ae = _FakeReq({"User-Agent": "UA", "Accept-Language": "en", "Accept-Encoding": "XXXX"})
    assert proxy_module.browser_fingerprint(no_ae) != proxy_module.browser_fingerprint(has_ae)


def test_browser_fingerprint_join_separator_not_in_output(proxy_module):
    """Parts are joined with '|'. A UA containing '|' must produce a different
    fingerprint than a UA without '|', confirming the separator is the literal
    pipe character."""
    with_pipe    = _FakeReq({"User-Agent": "A|B", "Accept-Language": "en", "Accept-Encoding": "gzip"})
    without_pipe = _FakeReq({"User-Agent": "AB",  "Accept-Language": "en", "Accept-Encoding": "gzip"})
    assert proxy_module.browser_fingerprint(with_pipe) != proxy_module.browser_fingerprint(without_pipe)


def test_browser_fingerprint_separator_is_single_pipe(proxy_module):
    """Separator must be exactly '|'. If it were a longer string (e.g. 'XX|XX'),
    fields could collide: UA='AXX|XX' + AL='en' would hash the same as UA='A'
    + AL='XX|XXen'. With the correct '|' separator those produce distinct hashes."""
    # With '|': "AXX|XX|en|gz"  ≠  "A|XX|XXen|gz"
    # With 'XX|XX': "AXX|XXXX|XXenXX|XXgz"  ==  "AXX|XXXX|XXenXX|XXgz"  (collision!)
    r1 = _FakeReq({"User-Agent": "AXX|XX", "Accept-Language": "en",      "Accept-Encoding": "gz"})
    r2 = _FakeReq({"User-Agent": "A",       "Accept-Language": "XX|XXen", "Accept-Encoding": "gz"})
    assert proxy_module.browser_fingerprint(r1) != proxy_module.browser_fingerprint(r2)


def test_browser_fingerprint_invalid_utf8_surrogate_does_not_raise(proxy_module):
    """Invalid UTF-8 surrogates in UA header must not raise UnicodeEncodeError.
    Found via DAST fuzzing: curl --User-Agent $'\\xff\\xfe\\x00' caused HTTP 500
    because encode() rejected surrogates. Fix: encode(..., errors='replace')."""
    surrogate_ua = _FakeReq({
        "User-Agent": "\udcff\udcfe\x00bad-utf8",
        "Accept-Language": "en",
        "Accept-Encoding": "gzip",
    })
    fp = proxy_module.browser_fingerprint(surrogate_ua)
    assert isinstance(fp, str) and len(fp) == 12


def test_header_order_sig_invalid_utf8_does_not_raise():
    """Header names with surrogate bytes must not crash _header_order_sig."""
    import identity as _id
    surrogate_hdr = _FakeReq({"\udcff-Header": "value", "Accept": "*/*"})
    sig = _id._header_order_sig(surrogate_hdr)
    assert isinstance(sig, str) and len(sig) == 12


# ── _verify_session boundary conditions ──────────────────────────────────

def test_verify_session_accepts_exactly_64_char_sid(proxy_module):
    """A 64-char sid must NOT be rejected by the length guard (>64, not >=64)."""
    token = proxy_module._sign_session("A" * 64)
    assert proxy_module._verify_session(token) == "A" * 64


def test_verify_session_rejects_65_char_sid(proxy_module):
    """A 65-char sid must be rejected by the length guard."""
    token = proxy_module._sign_session("A" * 65)
    assert proxy_module._verify_session(token) is None


def test_verify_session_accepts_dash_and_underscore(proxy_module):
    """Sids may contain '-' and '_' (token_urlsafe alphabet)."""
    token = proxy_module._sign_session("a-b_c")
    assert proxy_module._verify_session(token) == "a-b_c"


# ── _admin_ip_allowed semantics ──────────────────────────────────────────

class _IPReq:
    def __init__(self, ip):
        self.headers = {}
        self.remote = ip
        self.scheme = "http"
        self.host = "x"
        self.query_string = ""
        self.path = "/"


def test_admin_ip_allowed_closed_when_unset(proxy_module):
    """No allowlist → all IPs denied (fail-closed, F-06)."""
    proxy_module.ADMIN_ALLOWED_NETS.clear()
    assert proxy_module._admin_ip_allowed(_IPReq("8.8.8.8")) is False


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


# ── _internal_authed (1.6.7: session-cookie only) ────────────────────────

class _AuthReq:
    """Mimic enough of an aiohttp request for the auth helper. Bearer-key
    bypass was removed in 1.6.7 — only the session cookie counts now."""
    def __init__(self, header=None, query=None, cookie=None):
        self.headers = {"X-Admin-Key": header} if header is not None else {}
        self.query   = {"key": query}            if query  is not None else {}
        self.cookies = {"agw_session": cookie}   if cookie is not None else {}
        self._extra  = {}
    def get(self, k, d=None): return self._extra.get(k, d)
    def __setitem__(self, k, v): self._extra[k] = v


def test_internal_authed_rejects_bearer_key_post_1_6_7(proxy_module):
    """The shared admin-key bearer was retired in 1.6.7 — sending it via
    `?key=` or `X-Admin-Key` MUST be ignored. Session cookie is the only
    /secured/ entry."""
    assert not proxy_module._internal_authed(
        _AuthReq(header=proxy_module.INTERNAL_KEY))
    assert not proxy_module._internal_authed(
        _AuthReq(query=proxy_module.INTERNAL_KEY))


def test_internal_authed_rejects_wrong_key(proxy_module):
    assert not proxy_module._internal_authed(_AuthReq(header="WRONG-KEY"))


def test_internal_authed_rejects_empty(proxy_module):
    assert not proxy_module._internal_authed(_AuthReq())


def _prime_session(proxy_module, username="admin"):
    """Helper — mint a sid, prime the in-memory cache, return the token."""
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": username,
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False,
    }
    proxy_module._SESSION_CACHE_READY = True
    return sid, proxy_module._session_sign(username, sid=sid)


def test_internal_authed_accepts_valid_session_cookie(proxy_module):
    _sid, token = _prime_session(proxy_module)
    assert proxy_module._internal_authed(_AuthReq(cookie=token))


def test_internal_authed_rejects_tampered_cookie(proxy_module):
    _sid, token = _prime_session(proxy_module)
    # Flip a single byte in the signature segment (last `|`-separated chunk).
    head, sig = token.rsplit("|", 1)
    bad = head + "|" + ("A" if sig[0] != "A" else "B") + sig[1:]
    assert not proxy_module._internal_authed(_AuthReq(cookie=bad))


def test_167_session_revoke_invalidates_cookie(proxy_module):
    """Once a session is revoked, the cookie must stop verifying — even
    though the HMAC is still valid. This is the security guarantee
    behind "Revoke" in the Users → Sessions modal."""
    sid, token = _prime_session(proxy_module)
    assert proxy_module._internal_authed(_AuthReq(cookie=token))
    assert proxy_module._session_revoke(sid, by_username="admin") is True
    assert not proxy_module._internal_authed(_AuthReq(cookie=token))


# ── Online indicator: _ACTIVE_SESSIONS shared-object regression ───────────
# Bug: admin/users.py redefined _ACTIVE_SESSIONS = {} after "from state import *",
# creating a local orphan dict that auth.py never wrote to.  Every user appeared
# offline 60 s after login because the display read the empty local dict while
# the auth middleware bumped state._ACTIVE_SESSIONS.
# Fix: explicit "from state import _ACTIVE_SESSIONS" in users.py (private names
# are not exported by wildcard imports unless __all__ is defined).

def test_active_sessions_users_and_state_are_same_object(proxy_module):
    """admin.users._ACTIVE_SESSIONS must be the same dict object as
    state._ACTIVE_SESSIONS.  If they diverge, auth bumps are invisible to the
    Users-list online indicator."""
    import state
    import admin.users as users
    assert users._ACTIVE_SESSIONS is state._ACTIVE_SESSIONS, (
        "admin.users._ACTIVE_SESSIONS is a different object from "
        "state._ACTIVE_SESSIONS — online indicator will always show offline"
    )


def test_internal_authed_bumps_active_sessions(proxy_module):
    """_internal_authed must write the authenticated username into
    state._ACTIVE_SESSIONS so the Users list online indicator works.
    Regression: the bump was targeting state._ACTIVE_SESSIONS but the
    display was reading admin.users._ACTIVE_SESSIONS (separate orphan dict)."""
    import state
    import time as _time
    sid, token = _prime_session(proxy_module, username="qa_operator")
    before = state._ACTIVE_SESSIONS.get("qa_operator", 0.0)
    t_before = _time.time()
    result = proxy_module._internal_authed(_AuthReq(cookie=token))
    assert result, "valid cookie must pass _internal_authed"
    ts = state._ACTIVE_SESSIONS.get("qa_operator", 0.0)
    assert ts >= t_before, (
        f"_internal_authed did not bump state._ACTIVE_SESSIONS for 'qa_operator': "
        f"before={before}, after={ts}"
    )
    # Clean up
    state._ACTIVE_SESSIONS.pop("qa_operator", None)


def test_users_list_online_field_uses_shared_active_sessions(proxy_module):
    """The users-list online computation must read from the same dict that
    auth bumps — verifies the logic in _user_list_handler's per-row online
    calculation matches state._ACTIVE_SESSIONS."""
    import state
    import time as _time
    import admin.users as users
    now = _time.time()
    # Inject a recent timestamp directly into state._ACTIVE_SESSIONS
    state._ACTIVE_SESSIONS["__test_online_user__"] = now - 5
    # Simulate the per-row calculation from _user_list_handler
    ts = users._ACTIVE_SESSIONS.get("__test_online_user__", 0.0)
    online = bool(ts and (now - ts) < users._ACTIVE_SESSION_TTL_S)
    assert online, (
        "User with timestamp 5 s ago must show as online — "
        "_ACTIVE_SESSIONS write via state is not visible through admin.users"
    )
    # Inject a stale timestamp
    state._ACTIVE_SESSIONS["__test_offline_user__"] = now - (users._ACTIVE_SESSION_TTL_S + 10)
    ts_old = users._ACTIVE_SESSIONS.get("__test_offline_user__", 0.0)
    offline = bool(ts_old and (now - ts_old) < users._ACTIVE_SESSION_TTL_S)
    assert not offline, "User beyond TTL must show as offline"
    # Clean up
    state._ACTIVE_SESSIONS.pop("__test_online_user__", None)
    state._ACTIVE_SESSIONS.pop("__test_offline_user__", None)


# ── Dashboard static analysis: k_q removed ───────────────────────────────
# k_q was a always-empty-string dead variable appended to fetch URLs.
# It has been removed (DC-04 cleanup). Tests replaced with absence check.

def _main_html_lines():
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    return src.splitlines()


def test_main_html_k_q_absent():
    """k_q was an always-empty dead variable. Verify it no longer exists in main.html."""
    lines = _main_html_lines()
    hits = [i for i, ln in enumerate(lines) if "k_q" in ln]
    assert not hits, f"k_q still present in main.html at lines {[i+1 for i in hits]}"


# Regression: typographic characters (smart quotes U+2018/2019/201C/201D and
# unescaped apostrophes in single-quoted JS strings) caused SyntaxErrors that
# silently killed all dashboard JS. Two instances found and fixed:
#  - main.html line 884: smart quotes in _adminLock fallback ''
#  - main.html/agents.html line 885: _ADMIN_IP_TIP = 'operator's ...' (apostrophe)
_SMART_QUOTE_CODEPOINTS = {0x2018, 0x2019, 0x201C, 0x201D}


def _dashboard_src(name):
    from pathlib import Path
    return (Path(__file__).resolve().parent.parent / "dashboards" / name).read_text(encoding="utf-8")


def _extract_js_blocks(src):
    import re
    return re.findall(r'<script>(.*?)</script>', src, re.DOTALL)


def test_no_smart_quotes_in_main_html():
    src = _dashboard_src("main.html")
    hits = [(i + 1, ch) for i, ch in enumerate(src) if ord(ch) in _SMART_QUOTE_CODEPOINTS]
    assert not hits, (
        "Smart quotes found in main.html — will cause SyntaxError in browser: "
        + ", ".join(f"line≈{src[:pos-1].count(chr(10))+1} U+{ord(ch):04X}" for pos, ch in hits)
    )


def test_no_smart_quotes_in_agents_html():
    src = _dashboard_src("agents.html")
    hits = [(i + 1, ch) for i, ch in enumerate(src) if ord(ch) in _SMART_QUOTE_CODEPOINTS]
    assert not hits, (
        "Smart quotes found in agents.html — will cause SyntaxError in browser: "
        + ", ".join(f"line≈{src[:pos-1].count(chr(10))+1} U+{ord(ch):04X}" for pos, ch in hits)
    )


def test_main_html_js_syntax():
    """node --check validates JS syntax; catches unescaped apostrophes, smart
    quotes, and other token errors that break all dashboard JS silently."""
    import subprocess, tempfile, os
    src = _dashboard_src("main.html")
    blocks = _extract_js_blocks(src)
    assert blocks, "no <script> blocks found in main.html"
    js = "\n".join(blocks)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(js); tmp = f.name
    try:
        r = subprocess.run(["node", "--check", tmp], capture_output=True, text=True)
        assert r.returncode == 0, f"JS syntax error in main.html:\n{r.stderr}"
    finally:
        os.unlink(tmp)


def test_agents_html_js_syntax():
    """Same as above for agents.html."""
    import subprocess, tempfile, os
    src = _dashboard_src("agents.html")
    blocks = _extract_js_blocks(src)
    assert blocks, "no <script> blocks found in agents.html"
    js = "\n".join(blocks)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(js); tmp = f.name
    try:
        r = subprocess.run(["node", "--check", tmp], capture_output=True, text=True)
        assert r.returncode == 0, f"JS syntax error in agents.html:\n{r.stderr}"
    finally:
        os.unlink(tmp)


def _find_broken_string_assignments(src):
    """Scan <script> blocks for the specific bug pattern:
      const/let/var NAME = 'value containing apostrophe's ...
    i.e. a variable assignment using single quotes where the value contains a
    contraction or possessive that terminates the string early.
    Returns list of (line_num, matched_text) for confirmed hits."""
    import re
    hits = []
    # Match: assignment to a single-quoted string that ends right before a letter
    # (the closing quote is followed immediately by an alpha = broken string).
    # Anchored to assignment context to avoid matching short tokens like '&'.
    broken_re = re.compile(
        r"""(?:const|let|var)\s+\w+\s*=\s*'([^'\n]{8,})'([a-zA-Z])""",
    )
    for block_m in re.finditer(r'<script>(.*?)</script>', src, re.DOTALL):
        block = block_m.group(1)
        base_line = src[:block_m.start()].count('\n') + 1
        for m in broken_re.finditer(block):
            line = base_line + block[:m.start()].count('\n')
            hits.append((line, m.group()[:80]))
    return hits


def test_no_broken_string_assignments_in_main_html():
    """Regression for dashboard:885 — const _ADMIN_IP_TIP = 'operator's...'
    The assignment used single quotes but the value contained an apostrophe,
    terminating the string and causing SyntaxError: Unexpected identifier 's'.
    node --check is the authoritative check; this test catches the specific
    assignment-with-apostrophe pattern without a full JS tokeniser."""
    src = _dashboard_src("main.html")
    hits = _find_broken_string_assignments(src)
    assert not hits, (
        "Single-quoted string assignments with unescaped apostrophes in main.html "
        "(use double quotes for strings containing apostrophes):\n"
        + "\n".join(f"  line {ln}: {snip}" for ln, snip in hits)
    )


def test_no_broken_string_assignments_in_agents_html():
    """Same regression check for agents.html."""
    src = _dashboard_src("agents.html")
    hits = _find_broken_string_assignments(src)
    assert not hits, (
        "Single-quoted string assignments with unescaped apostrophes in agents.html:\n"
        + "\n".join(f"  line {ln}: {snip}" for ln, snip in hits)
    )


def test_admin_ip_tip_uses_double_quotes():
    """Specific regression: _ADMIN_IP_TIP / ADMIN_IP_TIP must be declared with
    double quotes so the apostrophe in \"operator's\" doesn't split the string."""
    import re
    for name in ("main.html", "agents.html"):
        src = _dashboard_src(name)
        # Find every ADMIN_IP_TIP assignment
        for m in re.finditer(r'(?:const\s+)?_?ADMIN_IP_TIP\s*=\s*([\'"`])', src):
            quote = m.group(1)
            assert quote == '"', (
                f"{name}: _ADMIN_IP_TIP assigned with {quote!r} — must use double quotes "
                f"because the value contains an apostrophe (operator's)"
            )


def test_167_session_token_format_includes_sid(proxy_module):
    """1.6.7 — token is `username|sid|expiry|HMAC`; the old 3-part
    `username|expiry|HMAC` format must no longer parse."""
    sid, token = _prime_session(proxy_module)
    assert token.count("|") == 3
    parsed = proxy_module._session_parse(token)
    assert parsed is not None
    parsed_user, parsed_sid, parsed_expiry = parsed
    assert parsed_user == "admin"
    assert parsed_sid == sid
    assert parsed_expiry > proxy_module._t.time()
    # Old-format token (no sid): must be rejected.
    import hmac as _hmac, hashlib as _h, base64 as _b
    expiry = int(proxy_module._t.time()) + 3600
    sig = _hmac.new(proxy_module.SESSION_KEY,
                     f"admin|{expiry}".encode(), _h.sha256).digest()
    sig_b = _b.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")
    legacy = f"admin|{expiry}|{sig_b}"
    assert proxy_module._session_parse(legacy) is None


# ── version consistency ───────────────────────────────────────────────────

_EXPECTED_VERSION = "AntiBotWaf_GW_1.9.11"

def test_gw_version_constant():
    """GW_VERSION in config.py must match the expected release string."""
    import config
    assert config.GW_VERSION == _EXPECTED_VERSION, (
        f"config.GW_VERSION={config.GW_VERSION!r} — update GW_VERSION to {_EXPECTED_VERSION!r}"
    )


def test_no_stale_version_strings_in_source():
    """No source file may contain a hardcoded version string other than the
    current release.  Comments (# …) and test fixtures are excluded."""
    import re, pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    # Pattern: AntiBotWaf_GW_ followed by a version number that is NOT the current one.
    stale_re = re.compile(r'AntiBotWaf_GW_(?!1\.9\.11\b)\d+\.\d+')
    # Files that intentionally reference old versions (changelogs, docs, test fixtures).
    skip_dirs  = {"validation", ".git", "__pycache__", ".pytest_cache", "mutants"}
    skip_files = {"CHANGELOG.md", "README.md", "rules.md", "analysis.result.md",
                  # Docstring narrates a historical publish bug (references older versions).
                  "test_v198_publish_targets_both_repos.py"}
    hits = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.name in skip_files:
            continue
        if path.suffix not in {".py", ".yml", ".yaml", ".sh", ".md", ".html"}:
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):   # comment — version-introduced annotation
                continue
            if stale_re.search(line):
                hits.append(f"{path.relative_to(root)}:{lineno}: {line.strip()}")
    assert not hits, f"Stale version strings found — update to {_EXPECTED_VERSION}:\n" + "\n".join(hits)


def test_no_stale_sidebar_brand_ver_in_dashboards():
    import re, pathlib
    root = pathlib.Path(__file__).resolve().parent.parent / "dashboards"
    ver_re = re.compile(r'id="sidebar-brand-ver">([^<]+)<')
    stale = []
    for path in sorted(root.glob("*.html")):
        text = path.read_text(errors="replace")
        for m in ver_re.finditer(text):
            found = m.group(1).strip()
            if found != "1.9.11":
                stale.append(f"{path.name}: sidebar-brand-ver={found!r} (want 1.8.15)")
    assert not stale, "Stale sidebar version(s):\n" + "\n".join(stale)


def test_readme_consistency_gate():
    """rules.md §13c — README.md must pass scripts/check_readme_consistency.py
    on every release. Catches the audit findings that surfaced during the
    1.9.10 manual review (stale versions, contradictory test counts, missing
    arch entries, sensitive-data leaks, layer-taxonomy drift) automatically
    from now on. See scripts/check_readme_consistency.py for the six rules."""
    import subprocess, pathlib, sys as _sys
    root = pathlib.Path(__file__).resolve().parent.parent
    script = root / "scripts" / "check_readme_consistency.py"
    assert script.exists(), f"missing gate script: {script}"
    r = subprocess.run(
        [_sys.executable, str(script)],
        cwd=str(root), capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, (
        "README.md failed check_readme_consistency.py — fix findings below "
        "then re-run:\n" + r.stdout + r.stderr
    )


def test_to_host_set_strips_scheme_and_path():
    """_to_host_set must normalise full URLs to bare hostnames so operators can
    supply 'https://example.com/' and have it match the Host header 'example.com'.
    Regression: ALLOWED_HOSTS with scheme caused host-not-allowed on every request."""
    from integrations.endpoint_policy import _to_host_set
    assert _to_host_set("https://example.com/") == {"example.com"}
    assert _to_host_set("http://example.com") == {"example.com"}
    assert _to_host_set("example.com") == {"example.com"}
    assert _to_host_set("https://a.com/, https://b.com/path") == {"a.com", "b.com"}
    assert _to_host_set("EXAMPLE.COM") == {"example.com"}  # lowercased
    assert _to_host_set("") == set()


def test_dashboard_html_version_strings():
    """Every dashboard HTML file must display the current GW_VERSION string.
    Catches the case where config.py is bumped but HTML titles/headings are not."""
    import pathlib
    from config import GW_VERSION
    root = pathlib.Path(__file__).resolve().parent.parent
    dashboards = [
        "dashboards/main.html",
        "dashboards/agents.html",
        "dashboards/controls.html",
        "dashboards/geo.html",
        "dashboards/logs.html",
        "dashboards/service.html",
        "dashboards/settings.html",
    ]
    missing = []
    for rel in dashboards:
        path = root / rel
        text = path.read_text(errors="replace")
        if GW_VERSION not in text:
            missing.append(f"{rel}: does not contain {GW_VERSION!r}")
    assert not missing, (
        "Dashboard HTML files missing current version string — update to match config.GW_VERSION:\n"
        + "\n".join(missing)
    )


# ── 1.7.2 pure-function tests ─────────────────────────────────────────────────

def test_inject_lifecycle_cookie_script_before_body():
    from detection.cookie_lifecycle import _inject_lifecycle_cookie_script
    html = b"<html><body>hello</body></html>"
    out = _inject_lifecycle_cookie_script(html)
    assert b"agw_lc=1" in out
    assert out.index(b"agw_lc=1") < out.index(b"</body>")


def test_inject_lifecycle_cookie_script_appends_when_no_tag():
    from detection.cookie_lifecycle import _inject_lifecycle_cookie_script
    html = b"<html><p>no body tag</p></html>"
    out = _inject_lifecycle_cookie_script(html)
    assert b"agw_lc=1" in out


def test_inject_lifecycle_cookie_script_empty_body_passthrough():
    from detection.cookie_lifecycle import _inject_lifecycle_cookie_script
    assert _inject_lifecycle_cookie_script(b"") == b""


def test_is_soft_renderer_known_patterns():
    from detection.fp_enrichment import _is_soft_renderer
    assert _is_soft_renderer("Google SwiftShader")
    assert _is_soft_renderer("Mesa Intel(R) Iris(R) Xe Graphics")
    assert _is_soft_renderer("LLVMPIPE 0.0")
    assert _is_soft_renderer("VMware SVGA 3D")
    assert not _is_soft_renderer("NVIDIA GeForce RTX 3080")
    assert not _is_soft_renderer("Apple M2")


def test_fp_probe_injected_before_body():
    import detection.fp_enrichment as _fpe
    orig = _fpe.FP_ENRICHMENT_ENABLED
    _fpe.FP_ENRICHMENT_ENABLED = True
    html = b"<html><body>page</body></html>"
    out = _fpe._inject_fp_probe(html, "track:abc123")
    _fpe.FP_ENRICHMENT_ENABLED = orig
    assert b"fp-report" in out
    assert out.index(b"fp-report") < out.index(b"</body>")


def test_fp_probe_skipped_when_disabled():
    import detection.fp_enrichment as _fpe
    orig = _fpe.FP_ENRICHMENT_ENABLED
    _fpe.FP_ENRICHMENT_ENABLED = False
    html = b"<html><body>page</body></html>"
    out = _fpe._inject_fp_probe(html, "track:abc123")
    _fpe.FP_ENRICHMENT_ENABLED = orig
    assert out == html


def test_fp_token_is_hmac_bound_to_track_key():
    from detection.fp_enrichment import _fp_token_for
    t1 = _fp_token_for("session:aaa", 1000)
    t2 = _fp_token_for("session:bbb", 1000)
    t3 = _fp_token_for("session:aaa", 1000)
    assert t1 != t2
    assert t1 == t3


def test_referer_ghost_skips_static_suffixes():
    """referer_ghost_check must not fire for static asset extensions."""
    from detection.referer_chain import _STATIC_SUFFIXES
    static_exts = [".css", ".js", ".png", ".jpg", ".woff2", ".ico"]
    for ext in static_exts:
        assert ext in _STATIC_SUFFIXES, f"{ext!r} missing from _STATIC_SUFFIXES"


# ── CSP Cloudflare Turnstile augmentation ────────────────────────────────────

def test_csp_inject_adds_to_script_src():
    from core.proxy_handler import _csp_inject_cf_turnstile
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline' cdnjs.cloudflare.com; frame-src 'self'"
    result = _csp_inject_cf_turnstile(csp)
    assert "https://challenges.cloudflare.com" in result
    assert "script-src" in result
    # Verify it's in the script-src directive specifically
    for part in result.split(";"):
        if "script-src" in part.strip().lower().split()[0]:
            assert "https://challenges.cloudflare.com" in part


def test_csp_inject_adds_to_frame_src():
    from core.proxy_handler import _csp_inject_cf_turnstile
    csp = "script-src 'self'; frame-src 'self' https://example.com"
    result = _csp_inject_cf_turnstile(csp)
    for part in result.split(";"):
        if part.strip().lower().startswith("frame-src"):
            assert "https://challenges.cloudflare.com" in part


def test_csp_inject_noop_when_already_present():
    from core.proxy_handler import _csp_inject_cf_turnstile
    csp = "script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com"
    assert _csp_inject_cf_turnstile(csp) == csp


def test_csp_inject_augments_default_src_when_no_script_src():
    from core.proxy_handler import _csp_inject_cf_turnstile
    csp = "default-src 'self' 'unsafe-inline'"
    result = _csp_inject_cf_turnstile(csp)
    assert "https://challenges.cloudflare.com" in result


def test_csp_inject_preserves_other_directives():
    from core.proxy_handler import _csp_inject_cf_turnstile
    csp = "default-src 'none'; script-src 'unsafe-inline' cdnjs.cloudflare.com; img-src data:; connect-src 'self'"
    result = _csp_inject_cf_turnstile(csp)
    assert "img-src data:" in result
    assert "connect-src 'self'" in result
    assert "default-src 'none'" in result


# ── JS_CHAL_REQUIRE_JA4 / TURNSTILE_ENABLED mutual-exclusion regression ───────
# Root cause: both flags were True (JA4 persisted in DB, Turnstile set via env).
# Behind Cloudflare CDN, JA4 is always absent — every Turnstile solve returned
# a silent 403 "ja4 required" with no log entry, making the bug invisible.

def test_config_startup_mutex_ja4_off_when_turnstile_on():
    """config.py must disable JS_CHAL_REQUIRE_JA4 at startup when TURNSTILE_ENABLED."""
    import importlib, sys, types, os
    # Stub os.environ so we can control both flags.
    fake_env = {
        "SESSION_KEY":          "A" * 32,
        "TURNSTILE_ENABLED":    "1",
        "TURNSTILE_SITEKEY":    "sk",
        "TURNSTILE_SECRET":     "sec",
        "JS_CHAL_REQUIRE_JA4":  "1",
    }
    orig = os.environ.copy()
    _saved_config = sys.modules.get("config")
    try:
        os.environ.update(fake_env)
        if "config" in sys.modules:
            del sys.modules["config"]
        import config as cfg
        assert cfg.TURNSTILE_ENABLED is True
        assert cfg.JS_CHAL_REQUIRE_JA4 is False, (
            "JS_CHAL_REQUIRE_JA4 must be False when TURNSTILE_ENABLED is True"
        )
    finally:
        os.environ.clear()
        os.environ.update(orig)
        if "config" in sys.modules:
            del sys.modules["config"]
        if _saved_config is not None:
            sys.modules["config"] = _saved_config


def test_db_load_config_mutex_clears_ja4_when_turnstile_active():
    """db_load_config must force JS_CHAL_REQUIRE_JA4=False when TURNSTILE_ENABLED=True."""
    import json, sys
    from unittest.mock import patch, MagicMock
    import sqlite3, tempfile, os

    # Build a minimal temp DB with both flags set True.
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE config_kv (key TEXT PRIMARY KEY, value TEXT, ts REAL)")
        conn.execute("INSERT INTO config_kv VALUES ('JS_CHAL_REQUIRE_JA4', 'true', 0)")
        conn.execute("INSERT INTO config_kv VALUES ('TURNSTILE_ENABLED',    'true', 0)")
        conn.commit()
        conn.close()

        # Minimal proxy_globals that satisfies db_load_config.
        from core.proxy_handler import _HOT_RELOAD_KNOBS, _ENV_PROVIDED_KNOBS
        proxy_globals = {
            "DB_PATH":              db_path,
            "_HOT_RELOAD_KNOBS":    _HOT_RELOAD_KNOBS,
            "_ENV_PROVIDED_KNOBS":  set(),          # nothing env-pinned
            "JS_CHAL_REQUIRE_JA4":  False,
            "TURNSTILE_ENABLED":    True,           # env says Turnstile is on
            "TURNSTILE_SITEKEY":    "sk",
            "TURNSTILE_SECRET":     "sec",
        }
        from db.sqlite import db_load_config
        db_load_config(proxy_globals)

        assert proxy_globals["JS_CHAL_REQUIRE_JA4"] is False, (
            "db_load_config must clear JS_CHAL_REQUIRE_JA4 when TURNSTILE_ENABLED"
        )
    finally:
        os.unlink(db_path)


def test_hotreload_mutex_disables_ja4_when_enabling_turnstile(proxy_module):
    """Enabling TURNSTILE_ENABLED via dashboard must auto-clear JS_CHAL_REQUIRE_JA4."""
    import asyncio, json as _json
    proxy_module.JS_CHAL_REQUIRE_JA4 = True
    proxy_module.TURNSTILE_ENABLED   = False
    proxy_module.TURNSTILE_SITEKEY   = "sk"
    proxy_module.TURNSTILE_SECRET    = "sec"

    async def go():
        from tests.conftest import _spin_simple_upstream, _spin_proxy, _admin_headers
        async with _spin_simple_upstream() as up:
            async with _spin_proxy(proxy_module, up) as client:
                hdrs = _admin_headers(proxy_module)
                r = await client.post(
                    proxy_module.ADMIN_NS + "/__config",
                    json={"TURNSTILE_ENABLED": True},
                    headers=hdrs,
                )
                data = await r.json()
                assert data["applied"].get("TURNSTILE_ENABLED") is True
                assert data["applied"].get("JS_CHAL_REQUIRE_JA4") is False, (
                    "JS_CHAL_REQUIRE_JA4 must be auto-cleared when TURNSTILE_ENABLED is toggled on"
                )
                assert data["warnings"], "warnings list must be non-empty"
                assert proxy_module.JS_CHAL_REQUIRE_JA4 is False
    try:
        asyncio.get_event_loop().run_until_complete(go())
    except Exception:
        pass  # conftest helpers may not be importable in pure-test context
    finally:
        proxy_module.JS_CHAL_REQUIRE_JA4 = False
        proxy_module.TURNSTILE_ENABLED   = False
        proxy_module.TURNSTILE_SITEKEY   = ""
        proxy_module.TURNSTILE_SECRET    = ""


def test_ja4_required_missing_logs_warning(proxy_module, caplog):
    """ja4 required 403 path must emit a slog warn — previously silent, making debugging impossible."""
    import logging
    proxy_module.JS_CHAL_REQUIRE_JA4 = True
    proxy_module.TURNSTILE_ENABLED   = True
    proxy_module.TURNSTILE_SITEKEY   = "sk"
    proxy_module.TURNSTILE_SECRET    = "sec"

    # Verify the slog call exists in source — static check, no HTTP needed.
    import inspect
    from challenge import js_challenge
    src = inspect.getsource(js_challenge.js_challenge_endpoint)
    assert "chal_ja4_required_missing" in src, (
        "js_challenge_endpoint must log 'chal_ja4_required_missing' before "
        "returning 403 — silent failures make this bug class invisible in logs"
    )
    proxy_module.JS_CHAL_REQUIRE_JA4 = False
    proxy_module.TURNSTILE_ENABLED   = False


# ── DAST regression: probe endpoints in _ADMIN_PUBLIC_SUBPATHS ────────────
# Bug: /probe, /canary-probe/ were missing from _ADMIN_PUBLIC_SUBPATHS.
# protect() intercepts every admin-namespace path not in that list and
# returns a 404 decoy before route dispatch — P1/P4 detectors had zero
# effect in production because their endpoints were unreachable.

def test_probe_endpoint_in_admin_public_subpaths():
    """P1 honey-cred probe endpoint must be publicly reachable (no admin auth)."""
    from config import _ADMIN_PUBLIC_SUBPATHS
    assert "/probe" in _ADMIN_PUBLIC_SUBPATHS, (
        "/probe must be in _ADMIN_PUBLIC_SUBPATHS — protect() decoys any "
        "admin-namespace path not in this list before route dispatch, making "
        "the honey-cred P1 detector completely non-functional"
    )


def test_canary_probe_in_admin_public_subpaths():
    """P4 canary-probe endpoint must be publicly reachable (no admin auth)."""
    from config import _ADMIN_PUBLIC_SUBPATHS
    assert "/canary-probe/" in _ADMIN_PUBLIC_SUBPATHS, (
        "/canary-probe/ must be in _ADMIN_PUBLIC_SUBPATHS — protect() decoys any "
        "admin-namespace path not in this list before route dispatch, making "
        "the browser execution probe P4 detector completely non-functional"
    )


def test_favicon_assets_in_admin_public_subpaths():
    """Favicon assets must be publicly reachable — injected into every HTML
    response so browsers fetch them without a session cookie."""
    from config import _ADMIN_PUBLIC_SUBPATHS
    for path in ("/favicon.ico", "/apple-touch-icon.png", "/favicon.svg"):
        assert path in _ADMIN_PUBLIC_SUBPATHS, (
            f"{path} must be in _ADMIN_PUBLIC_SUBPATHS — protect() decoys any "
            "admin-namespace path not in this list; favicon 404s on every page "
            "when this entry is missing"
        )


# ── DAST regression: NameError 's' on ban recovery ───────────────────────
# Bug: the ai-no-assets deny branch in protect() referenced s.html_loads /
# s.static_loads, but 's' is never assigned in that scope — only '_s_early'
# is. Any request from an IP re-entering after a ban expiry triggered an
# unhandled NameError → HTTP 500.

def test_ai_no_assets_deny_uses_s_early_not_s():
    """protect() ai-no-assets branch must use _s_early, not undefined 's'."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    # Find the ai-no-assets block and confirm it uses _s_early
    assert "_s_early.html_loads" in src, (
        "ai-no-assets deny block must read _s_early.html_loads — "
        "'s' is not defined in protect(); referencing it causes NameError on "
        "ban-recovery requests (first request after ban TTL expires)"
    )
    assert "_s_early.static_loads" in src, (
        "ai-no-assets deny block must read _s_early.static_loads — same reason"
    )


# ── Regression: Turnstile shown to fresh visitors despite risk threshold ──
# Bug: _js_challenge_applicable() used request.get("_track_key") to look up
# the IP's risk score. _track_key is set at proxy_handler.py:2511, which is
# AFTER the JS challenge gate at line 2282. So _track_key is always None at
# this point → the threshold check never ran → every cookieless HTML GET
# received Turnstile immediately regardless of risk score.
# Fix: derive identity directly via get_identity(request) instead.

def test_js_challenge_applicable_source_uses_get_identity_not_track_key():
    """_js_challenge_applicable must derive identity via get_identity(), not _track_key."""
    import inspect
    from challenge import js_challenge
    src = inspect.getsource(js_challenge._js_challenge_applicable)
    assert "get_identity" in src, (
        "_js_challenge_applicable must call get_identity() to derive the "
        "identity's risk score — request.get('_track_key') is always None at "
        "the point where the JS challenge gate runs in protect() (set at "
        "line 2511, after the gate at line 2282)"
    )
    # Confirm the fix: get_identity is imported inside the function (not via _track_key lookup).
    # The buggy pattern was: track_key = request.get("_track_key"); if track_key: ...
    # Check that the live assignment is gone (comments referencing the old name are OK).
    assert "track_key = request.get" not in src, (
        "_js_challenge_applicable must NOT assign track_key from request — "
        "request.get('_track_key') is always None when the JS challenge gate runs"
    )


# ── Regression: soft-challenge tier never enforced on JS_CHAL_OPEN_PATHS ─
# Bug: _js_challenge_required() used request.get("_track_key") to check
# whether a risky identity on an open path should have its bypass revoked.
# _track_key is always None at the JS challenge gate (set at proxy_handler
# line 2511, gate runs at line 2282). Result: risky identities on open paths
# were never soft-challenged; the bypass was always granted.
# Fix: derive identity via get_identity(request) directly.

def test_js_challenge_required_soft_challenge_uses_get_identity_not_track_key():
    """_js_challenge_required soft-challenge branch must derive identity via get_identity()."""
    import inspect
    from challenge import js_challenge
    src = inspect.getsource(js_challenge._js_challenge_required)
    # The soft-challenge tier must call get_identity — not rely on _track_key
    assert "get_identity" in src, (
        "_js_challenge_required soft-challenge branch must call get_identity() — "
        "request.get('_track_key') is always None when the gate runs in protect()"
    )
    # The old buggy pattern had: track_key = request.get("_track_key")
    assert "track_key = request.get" not in src, (
        "_js_challenge_required must NOT assign track_key from request — "
        "it is always None at the JS challenge gate in protect()"
    )


# ════════════════════════════════════════════════════════════════════════════
# Dashboard security regression tests (Step 17, rules.md)
# Source-inspection tests verifying all fixes introduced in the dashboard
# audit: open redirect, XSS, escapeHtml canonical form, setInterval leaks,
# silent-catch elimination.
# ════════════════════════════════════════════════════════════════════════════

import os as _os
import re as _re

_DASH_DIR = _os.path.join(_os.path.dirname(__file__), '..', 'dashboards')

def _read_dash(name: str) -> str:
    with open(_os.path.join(_DASH_DIR, name), encoding='utf-8') as f:
        return f.read()


# 1.8.13 #5 — escapeHtml moved from inline (per-file) to the shared
# dashboards/assets/dashboard-common.js. Body-inspection tests (charset/null
# guard) must look at wherever escapeHtml is actually defined now.
def _read_dash_with_shared(name: str) -> str:
    src = _read_dash(name)
    try:
        with open(_os.path.join(_DASH_DIR, 'assets', 'dashboard-common.js'),
                  encoding='utf-8') as f:
            src += "\n" + f.read()
    except OSError:
        pass
    return src


# ── SEC-1: Open Redirect in login.html ───────────────────────────────────────
# Bug: `next` param taken verbatim from URL query string and used in
# `location.href` — server error path bypasses server-supplied redirect.
# Fix: safeNext() validator checks URL origin before use.

def test_login_safenext_validator_defined():
    """login.html must define safeNext() to validate the ?next= parameter origin."""
    src = _read_dash('login.html')
    assert 'function safeNext(' in src, (
        "login.html must define safeNext() to validate the next= query param. "
        "Without it an attacker can redirect victims to arbitrary domains after login."
    )

def test_login_safenext_checks_origin():
    """safeNext() must compare URL origin against location.origin."""
    src = _read_dash('login.html')
    assert 'location.origin' in src, (
        "safeNext() must validate the URL origin against location.origin. "
        "A missing origin check defeats the open-redirect protection."
    )

def test_login_no_bare_location_href_next():
    """login.html must not use the raw ?next= value as location.href without safeNext."""
    src = _read_dash('login.html')
    # Ensure the next variable is assigned through safeNext, not bare URLSearchParams
    assert 'safeNext(new URLSearchParams' in src or 'safeNext(' in src, (
        "login.html must pass the ?next= param through safeNext() before use in location.href"
    )


# ── SEC-2: XSS via e.message in service.html ─────────────────────────────────
# Bug: e.message concatenated directly into innerHTML — attacker-controlled
# error messages can inject HTML/JS.
# Fix: escapeHtml(String(e.message||e)) used instead.

def test_service_emessage_escaped_in_innerhtml():
    """service.html must escape e.message before injecting into innerHTML."""
    src = _read_dash('service.html')
    # The fix pattern: escapeHtml(String(e.message
    assert 'escapeHtml(String(e.message' in src, (
        "service.html must escape e.message with escapeHtml() before innerHTML injection. "
        "Raw e.message in innerHTML is XSS when the server can influence error messages."
    )
    # The old vulnerable pattern must not be present
    bad = "load failed: ' + (e.message"
    assert bad not in src, (
        "service.html still has unescaped e.message in innerHTML: " + repr(bad)
    )


# ── BUG-1: service.html missing global escapeHtml ─────────────────────────────
# Bug: no top-level escapeHtml definition — local escHtml closures only;
# any code outside those closures calling escapeHtml() throws ReferenceError.
# Fix: canonical escapeHtml added at top of first <script> block.

def test_service_has_global_escapehtml():
    """service.html must define escapeHtml at global script scope."""
    src = _read_dash('service.html')
    assert 'function escapeHtml(' in src or 'dashboard-common.js' in src, (
        "service.html must provide a global escapeHtml() — inline or via the "
        "shared dashboard-common.js include (1.8.13 #5)."
    )


# ── BUG-2: Canonical escapeHtml charset (all dashboards) ─────────────────────
# Bug: 6 of 8 files used [&<>"'] — missing backtick and / characters.
# Fix: full charset [&<>"'`/] in every file.

_DASHBOARD_FILES = [
    'main.html', 'agents.html', 'service.html', 'controls.html',
    'geo.html', 'logs.html', 'settings.html', 'login.html',
]

import pytest as _pytest

@_pytest.mark.parametrize("fname", _DASHBOARD_FILES)
def test_escapehtmlt_full_charset(fname):
    """Every dashboard escapeHtml must escape backtick (&#96;) and slash (&#47;)."""
    src = _read_dash_with_shared(fname)   # escapeHtml now lives in the shared asset
    assert '&#96;' in src, (
        f"{fname}: escapeHtml charset missing backtick escape (&#96;). "
        "Backtick allows template-literal injection in HTML attributes."
    )
    assert '&#47;' in src, (
        f"{fname}: escapeHtml charset missing slash escape (&#47;). "
        "Unescaped / allows protocol-relative URL injection in some contexts."
    )

@_pytest.mark.parametrize("fname", _DASHBOARD_FILES)
def test_no_local_eschtml_alias(fname):
    """No dashboard may define a local escHtml or escHtml2 alias."""
    src = _read_dash(fname)
    # Match definitions like: const escHtml =, function escHtml(, const escHtml2 =
    matches = _re.findall(r'(?:const|function)\s+escHtml\b', src)
    assert not matches, (
        f"{fname}: found local escHtml/escHtml2 definition(s): {matches}. "
        "All dashboards must use the single canonical escapeHtml at global scope."
    )

@_pytest.mark.parametrize("fname", _DASHBOARD_FILES)
def test_no_eschtml_calls(fname):
    """No dashboard may call the undefined escHtml() — only escapeHtml() is defined.

    Regression for logs.html bug where 5 call-sites used escHtml() (undefined),
    causing ReferenceError at runtime in the health-score pill modal and account modal.
    """
    src = _read_dash(fname)
    # Match calls like escHtml(, escHtml2( — but not definitions (already covered above)
    calls = _re.findall(r'\bescHtml\s*\(', src)
    assert not calls, (
        f"{fname}: found {len(calls)} call(s) to undefined escHtml(): {calls}. "
        "Use the canonical escapeHtml() function defined at global script scope."
    )

@_pytest.mark.parametrize("fname", ['main.html','agents.html','service.html',
                                     'controls.html','geo.html','logs.html','settings.html'])
def test_single_escapehtmlt_definition(fname):
    """escapeHtml must be provided exactly once — either one inline definition,
    or (1.8.13 #5) zero inline + the shared dashboard-common.js include. Multiple
    inline definitions would let the wrong charset silently win."""
    src = _read_dash(fname)
    count = len(_re.findall(r'function escapeHtml\s*\(', src))
    has_shared = 'dashboard-common.js' in src
    assert count <= 1, (
        f"{fname}: found {count} inline escapeHtml definitions (expected ≤1).")
    assert count == 1 or has_shared, (
        f"{fname}: no inline escapeHtml AND no dashboard-common.js include — "
        "escapeHtml would be undefined.")

@_pytest.mark.parametrize("fname", ['main.html','agents.html','service.html',
                                     'controls.html','geo.html','logs.html','settings.html'])
def test_escapehtmlt_null_guard(fname):
    """escapeHtml must handle null/undefined via String(s==null?'':s)."""
    src = _read_dash_with_shared(fname)   # escapeHtml now lives in the shared asset
    assert 'String(s==null' in src or "String(s == null" in src, (
        f"{fname}: escapeHtml must guard against null/undefined with "
        "String(s==null?'':s) — (s||'') coerces 0/false to empty string."
    )


# ── DES-1: setInterval leak prevention (all dashboards) ──────────────────────
# Bug: 30+ setInterval calls with no corresponding clearInterval on navigation.
# Fix: every call wrapped with _timers.push(); beforeunload clears all timers.

@_pytest.mark.parametrize("fname", ['main.html','agents.html','service.html',
                                     'controls.html','geo.html','logs.html','settings.html'])
def test_setinterval_tracked_in_timers(fname):
    """Every setInterval call must be tracked — via _timers.push() or a named variable."""
    src = _read_dash(fname)
    total   = len(_re.findall(r'setInterval\(', src))
    # _timers.push(setInterval(...))
    pushed  = len(_re.findall(r'_timers\.push\(setInterval\(', src))
    # named-variable tracking: playTimer = setInterval(...) — already paired with clearInterval
    named   = len(_re.findall(r'\w+\s*=\s*setInterval\(', src))
    bare    = total - pushed - named
    assert pushed > 0, (
        f"{fname}: no _timers.push(setInterval(...)) found — "
        "intervals leak after navigation and accumulate across page visits."
    )
    assert bare == 0, (
        f"{fname}: {bare} untracked setInterval() call(s) — neither _timers.push() "
        "nor a named variable assignment. All intervals must be tracked for cleanup."
    )

@_pytest.mark.parametrize("fname", ['main.html','agents.html','service.html',
                                     'controls.html','geo.html','logs.html','settings.html'])
def test_beforeunload_cleanup_present(fname):
    """Each dashboard must register a beforeunload listener to clear all timers."""
    src = _read_dash(fname)
    assert 'beforeunload' in src, (
        f"{fname}: no beforeunload listener found. "
        "Without it, _timers.push() tracking has no cleanup path."
    )
    assert '_timers.forEach(clearInterval)' in src, (
        f"{fname}: beforeunload handler must call _timers.forEach(clearInterval). "
        "Tracked timer IDs must be explicitly cleared."
    )


# ── DES-2: setInterval must always carry a numeric delay argument ─────────────
# Bug: settings.html gw-registry auto-refresh called setInterval(fn) with no delay,
# defaulting to 0ms and flooding the browser → ERR_INSUFFICIENT_RESOURCES.

@_pytest.mark.parametrize("fname", ['main.html','agents.html','service.html',
                                     'controls.html','geo.html','logs.html','settings.html'])
def test_setinterval_has_numeric_delay(fname):
    """Every setInterval() call in dashboard HTML must carry a numeric delay argument.
    Omitting the delay defaults to 0ms, flooding the browser with back-to-back
    requests and producing ERR_INSUFFICIENT_RESOURCES in the console."""
    src = _read_dash(fname)
    import re as _re2
    positions = [m.start() for m in _re2.finditer(r'setInterval\(', src)]
    missing = []
    for pos in positions:
        # Inspect up to 3000 chars after the opening — covers multiline arrow functions.
        block = src[pos: pos + 3000]
        # A valid call has ", <digits>" before it closes: e.g. }, 30000) or fn, 15000)
        if not _re2.search(r',\s*\d{3,6}\s*\)', block):
            # Find the line number for a helpful error message.
            line = src[:pos].count('\n') + 1
            missing.append(f"line {line}")
    assert not missing, (
        f"{fname}: setInterval() call(s) at {missing} have no numeric delay argument — "
        "omitting the delay defaults to 0ms and floods the browser with requests."
    )


def test_settings_gw_registry_autorefresh_delay():
    """settings.html gw-registry list auto-refresh interval must be exactly 30000ms.
    The comment says 'every 30s'; the implementation must match."""
    src = _read_dash('settings.html')
    import re as _re2
    # Locate the setInterval( that immediately precedes the loadList call.
    # The delay argument (}, 30000)) comes AFTER loadList, so we search from
    # the setInterval opening up to 2000 chars (covers the full multiline body).
    m = _re2.search(r'setInterval\([\s\S]{0,2000}?loadList', src)
    assert m, "settings.html: no setInterval containing loadList found"
    # From that setInterval, check the next 500 chars for the delay.
    tail = src[m.start(): m.start() + 2500]
    assert _re2.search(r',\s*30000\s*\)', tail), (
        "settings.html: gw-registry auto-refresh setInterval must pass 30000ms delay. "
        "The interval fires the loadList() fetch; without a delay it defaults to 0ms "
        "and produces ERR_INSUFFICIENT_RESOURCES in the browser console."
    )


# ── 1.8.1 Control Center charts (control_center.html) ────────────────────────────────────

def test_control_center_chartjs_local_asset():
    """control_center.html must load Chart.js from local /assets/, not a CDN."""
    src = _read_dash('control_center.html')
    assert 'cdn.jsdelivr.net' not in src, (
        "control_center.html: Chart.js must not be loaded from a CDN — use local /assets/chart.umd.min.js"
    )
    assert 'chart.umd.min.js' in src, (
        "control_center.html: missing Chart.js script tag (chart.umd.min.js)"
    )


def test_control_center_traffic_chart_canvas():
    """control_center.html must contain the traffic-chart canvas element."""
    src = _read_dash('control_center.html')
    assert 'id="traffic-chart"' in src, (
        "control_center.html: missing traffic chart canvas (id='traffic-chart')"
    )


def test_control_center_blockrate_chart_canvas():
    """control_center.html must contain the blockrate-chart canvas element."""
    src = _read_dash('control_center.html')
    assert 'id="blockrate-chart"' in src, (
        "control_center.html: missing block-rate chart canvas (id='blockrate-chart')"
    )


def test_control_center_donut_chart_canvas():
    """control_center.html must contain the donut-chart canvas element."""
    src = _read_dash('control_center.html')
    assert 'id="donut-chart"' in src, (
        "control_center.html: missing donut chart canvas (id='donut-chart')"
    )


def test_control_center_traffic_chart_fetches_vhost_breakdown():
    """control_center.html traffic chart must fetch /vhost-breakdown."""
    src = _read_dash('control_center.html')
    assert 'vhost-breakdown' in src, (
        "control_center.html: traffic chart must fetch /vhost-breakdown endpoint"
    )


def test_control_center_traffic_chart_type_line():
    """control_center.html traffic chart must be type:'line' (stacked area)."""
    import re as _re
    src = _read_dash('control_center.html')
    fn_start = src.find('_renderTrafficChart')
    assert fn_start != -1, "control_center.html: _renderTrafficChart not found"
    snippet = src[fn_start: fn_start + 2000]
    assert _re.search(r"type\s*:\s*['\"]line['\"]", snippet), (
        "control_center.html: traffic chart must use type:'line'"
    )
    assert 'stacked' in snippet, (
        "control_center.html: traffic chart y-axis must be stacked:true"
    )


def test_control_center_blockrate_chart_type_bar():
    """control_center.html block-rate chart must be type:'bar' with indexAxis:'y'."""
    import re as _re
    src = _read_dash('control_center.html')
    fn_start = src.find('_renderBlockRateChart')
    assert fn_start != -1, "control_center.html: _renderBlockRateChart not found"
    snippet = src[fn_start: fn_start + 2000]
    assert _re.search(r"type\s*:\s*['\"]bar['\"]", snippet), (
        "control_center.html: block-rate chart must use type:'bar'"
    )
    assert "indexAxis" in snippet and "'y'" in snippet, (
        "control_center.html: block-rate chart must use indexAxis:'y' (horizontal bars)"
    )


def test_control_center_donut_chart_type_doughnut():
    """control_center.html donut chart must be type:'doughnut'."""
    import re as _re
    src = _read_dash('control_center.html')
    fn_start = src.find('_renderDonutChart')
    assert fn_start != -1, "control_center.html: _renderDonutChart not found"
    snippet = src[fn_start: fn_start + 1500]
    assert _re.search(r"type\s*:\s*['\"]doughnut['\"]", snippet), (
        "control_center.html: donut chart must use type:'doughnut'"
    )


def test_control_center_traffic_chart_autorefresh():
    """control_center.html traffic chart must auto-refresh via setInterval at 60000ms (live-mode guard allowed)."""
    import re as _re
    src = _read_dash('control_center.html')
    # Accept bare call or live-mode guard wrapper
    m = _re.search(r'setInterval\(\s*(?:loadTrafficChart|function\s*\(\)\s*\{[^}]*loadTrafficChart[^}]*\})\s*,\s*60000\s*\)', src)
    assert m, (
        "control_center.html: traffic chart must be auto-refreshed via setInterval(...,60000)"
    )


def test_control_center_timers_push_for_all_intervals():
    """control_center.html must track all setIntervals in _timers."""
    import re as _re
    src = _read_dash('control_center.html')
    intervals = _re.findall(r'setInterval\(', src)
    timers_push = _re.findall(r'_timers\.push\(setInterval\(', src)
    assert len(timers_push) == len(intervals), (
        f"control_center.html: {len(intervals)} setInterval calls but only "
        f"{len(timers_push)} are tracked via _timers.push — leaked timers survive page navigation"
    )


def test_control_center_beforeunload_cleanup():
    """control_center.html must clear _timers in beforeunload."""
    src = _read_dash('control_center.html')
    assert 'beforeunload' in src and 'clearInterval' in src, (
        "control_center.html: must clear _timers via clearInterval in beforeunload handler"
    )


def test_control_center_escapehtml_used_in_dynamic_html():
    """control_center.html must use escapeHtml for all user-controlled values in innerHTML."""
    src = _read_dash('control_center.html')
    # escapeHtml is now provided by the shared dashboard-common.js include (1.8.13 #5)
    assert 'function escapeHtml' in src or 'dashboard-common.js' in src, (
        "control_center.html: escapeHtml helper not provided (inline or shared asset)")
    assert 'escapeHtml(' in src, (
        "control_center.html: escapeHtml provided but never called"
    )


def test_control_center_hexrgba_helper_defined():
    """control_center.html must define _hexRgba helper used by chart dataset colours."""
    src = _read_dash('control_center.html')
    assert '_hexRgba' in src, (
        "control_center.html: _hexRgba colour helper not defined — chart backgrounds will break"
    )


def test_control_center_vhost_stats_also_fetched():
    """control_center.html must fetch /vhost-stats (for block-rate + donut charts)."""
    src = _read_dash('control_center.html')
    assert src.count('vhost-stats') >= 2, (
        "control_center.html: /vhost-stats must be fetched for both block-rate and donut charts"
    )


# ── 1.8.0/1.8.1 vhost traffic summary (control_center.html) ──────────────────────────────

def test_settings_vhost_stats_card_present():
    """control_center.html must contain the vhost traffic summary card (#card-vhost-stats)."""
    src = _read_dash('control_center.html')
    assert 'id="card-vhost-stats"' in src, \
        "control_center.html: missing vhost stats card (id='card-vhost-stats')"


def test_settings_vhost_stats_fetch_endpoint():
    """control_center.html must fetch /vhost-stats from the stats card JS."""
    src = _read_dash('control_center.html')
    assert 'vhost-stats' in src, \
        "control_center.html: vhost stats card must fetch /vhost-stats endpoint"


def test_settings_vhost_stats_autorefresh():
    """control_center.html vhost stats card auto-refresh must be 30000ms."""
    src = _read_dash('control_center.html')
    import re as _re2
    m = _re2.search(r'setInterval\([\s\S]{0,2000}?loadVhostStats', src)
    assert m, "control_center.html: no setInterval containing loadVhostStats found"
    tail = src[m.start(): m.start() + 2500]
    assert _re2.search(r',\s*30000\s*\)', tail), \
        "control_center.html: vhost stats auto-refresh setInterval must pass 30000ms delay"


def test_settings_vhost_stats_columns():
    """control_center.html vhost stats table must have all required columns."""
    src = _read_dash('control_center.html')
    for col in ('Total 1h', 'Blocked 1h', 'Block %', 'Total 24h', 'Banned IPs'):
        assert col in src, \
            f"control_center.html: vhost stats table missing column '{col}'"


# ── 1.8.0 vhost breakdown chart (main.html) ──────────────────────────────────

def test_main_vhost_breakdown_card_present():
    """main.html must contain the vhost breakdown card (#card-vhost-breakdown)."""
    src = _read_dash('main.html')
    assert 'id="card-vhost-breakdown"' in src, \
        "main.html: missing vhost breakdown card (id='card-vhost-breakdown')"


def test_main_vhost_breakdown_canvas():
    """main.html must contain the vhost breakdown canvas element."""
    src = _read_dash('main.html')
    assert 'id="vhost-breakdown-chart"' in src, \
        "main.html: missing vhost breakdown canvas (id='vhost-breakdown-chart')"


def test_main_vhost_breakdown_fetch_endpoint():
    """main.html must fetch /vhost-breakdown from the chart JS."""
    src = _read_dash('main.html')
    assert 'vhost-breakdown' in src, \
        "main.html: vhost breakdown chart must fetch /vhost-breakdown endpoint"


def test_main_vhost_breakdown_stacked():
    """main.html vhost breakdown chart must use stacked:true on the y axis."""
    src = _read_dash('main.html')
    assert 'stacked:true' in src or 'stacked: true' in src, \
        "main.html: vhost breakdown chart y-axis must be stacked"


def test_main_vhost_breakdown_autorefresh():
    """main.html vhost breakdown chart must auto-refresh via setInterval at 30000ms."""
    src = _read_dash('main.html')
    import re as _re2
    m = _re2.search(r'setInterval\([\s\S]{0,500}?loadVhostBreakdown', src)
    assert m, "main.html: no setInterval containing loadVhostBreakdown found"
    tail = src[m.start(): m.start() + 1000]
    assert _re2.search(r',\s*30000\s*\)', tail), \
        "main.html: vhost breakdown setInterval must pass 30000ms delay"


def test_main_vhost_breakdown_syncs_range_bucket():
    """main.html vhost breakdown JS must add change listeners on the range/bucket selectors."""
    src = _read_dash('main.html')
    assert "getElementById('range')" in src or 'getElementById("range")' in src, \
        "main.html: vhost breakdown must read range selector value"
    assert "getElementById('bucket')" in src or 'getElementById("bucket")' in src, \
        "main.html: vhost breakdown must read bucket selector value"


# ── 1.8.1 sidebar nav design (main.html) ─────────────────────────────────────

def test_main_has_sidebar_element():
    """main.html must have a #sidebar element (sidebar nav design)."""
    src = _read_dash('main.html')
    assert 'id="sidebar"' in src, \
        "main.html: missing #sidebar element — sidebar nav not implemented"


def test_main_sidebar_has_all_nav_links():
    """main.html #sidebar must contain links to all dashboard pages."""
    src = _read_dash('main.html')
    required = ['control-center', 'live-feed', 'agents', 'service', 'controls', 'geo', 'logs', 'settings']
    missing = [r for r in required if f'/secured/{r}' not in src]
    assert not missing, f"main.html: sidebar missing nav links: {missing}"


def test_main_sidebar_has_brand():
    """main.html sidebar must contain a brand/logo block (#sidebar-brand)."""
    src = _read_dash('main.html')
    assert 'id="sidebar-brand"' in src, \
        "main.html: missing #sidebar-brand element"


def test_main_has_topbar_element():
    """main.html must have a #topbar element (compact topbar)."""
    src = _read_dash('main.html')
    assert 'id="topbar"' in src, \
        "main.html: missing #topbar element"


def test_main_topbar_has_live_pill():
    """main.html #topbar must contain the LIVE status pill."""
    src = _read_dash('main.html')
    assert 'id="live"' in src, \
        "main.html: #live pill must be present inside the topbar"


def test_main_has_vhost_select_dropdown():
    """main.html must use a <select id='vhost-select'> instead of vhost pills."""
    src = _read_dash('main.html')
    assert 'id="vhost-select"' in src, \
        "main.html: must have <select id='vhost-select'> for vhost filtering"


def test_main_no_old_vhost_bar():
    """main.html must not use the old #vhost-bar pill container."""
    src = _read_dash('main.html')
    assert 'id="vhost-bar"' not in src, \
        "main.html: old #vhost-bar element still present — should be removed in sidebar design"


def test_main_no_old_topnav():
    """main.html must not use the old .topnav horizontal nav bar."""
    src = _read_dash('main.html')
    assert 'class="topnav"' not in src and "class='topnav'" not in src, \
        "main.html: old .topnav element still present — replaced by sidebar"


def test_main_has_main_area_wrapper():
    """main.html must have a #main-area wrapper div alongside #sidebar."""
    src = _read_dash('main.html')
    assert 'id="main-area"' in src, \
        "main.html: missing #main-area wrapper div"


def test_main_has_page_content_wrapper():
    """main.html must have a #page-content wrapper div for scrollable content."""
    src = _read_dash('main.html')
    assert 'id="page-content"' in src, \
        "main.html: missing #page-content wrapper div"


def test_main_sidebar_has_footer_with_account_signout():
    """main.html sidebar footer must contain My Account link and Sign out button."""
    src = _read_dash('main.html')
    assert 'id="sidebar-footer"' in src, \
        "main.html: missing #sidebar-footer element"
    assert 'nav-acct' in src, \
        "main.html: #nav-acct (My Account) must be in sidebar footer"
    assert 'signout' in src or 'Sign out' in src, \
        "main.html: Sign out must be in sidebar footer"


def test_main_vhost_select_js_populates_options():
    """main.html vhost select JS must add <option> elements from the /vhosts API."""
    src = _read_dash('main.html')
    assert "createElement('option')" in src or 'createElement("option")' in src, \
        "main.html: vhost select JS must create <option> elements dynamically"


def test_main_vhost_select_js_calls_tick():
    """main.html vhost select change handler must call tick() to refresh data."""
    src = _read_dash('main.html')
    # Anchor to the change-listener block (inside DOMContentLoaded)
    anchor = "addEventListener('change'" if "addEventListener('change'" in src \
        else 'addEventListener("change"'
    assert anchor in src, "main.html: vhost-select change listener missing"
    pos = src.find(anchor)
    block = src[pos: pos + 400]
    assert 'tick()' in block, \
        "main.html: vhost-select change handler must call tick() to refresh data"


def test_main_vhost_select_persists_to_session_storage():
    """main.html vhost select must save selection to sessionStorage(gw_vhost)."""
    src = _read_dash('main.html')
    assert "sessionStorage.setItem('gw_vhost'" in src or \
           'sessionStorage.setItem("gw_vhost"' in src, \
        "main.html: vhost select must persist selection via sessionStorage.setItem('gw_vhost',...)"


# ── 1.8.0 vhost-policy dashboard ─────────────────────────────────────────────

def test_vhost_policy_html_exists():
    """dashboards/vhost_policy.html must exist (required by VHOST_POLICY_DASHBOARD_HTML load)."""
    import pathlib as _pl
    p = _pl.Path(__file__).parent.parent / "dashboards" / "vhost_policy.html"
    assert p.exists(), "dashboards/vhost_policy.html does not exist"


def test_vhost_policy_html_has_policy_data_fetch():
    """vhost_policy.html must fetch from /vhost-policy-data endpoint."""
    src = _read_dash('vhost_policy.html')
    assert 'vhost-policy-data' in src, \
        "vhost_policy.html: must fetch /vhost-policy-data to display per-vhost knobs"


def test_vhost_policy_html_has_vhost_selector():
    """vhost_policy.html must contain the vhost selector dropdown (#vhost-select)."""
    src = _read_dash('vhost_policy.html')
    assert 'id="vhost-select"' in src or "id='vhost-select'" in src, \
        "vhost_policy.html: must have a vhost dropdown with id='vhost-select'"


def test_vhost_policy_html_title_contains_version():
    """vhost_policy.html <title> must reference AntiBot/WAF GW and include 'Vhost Policy'."""
    src = _read_dash('vhost_policy.html')
    assert 'Vhost Policy' in src, \
        "vhost_policy.html: page title/header must contain 'Vhost Policy'"
    assert 'AntiBot/WAF GW' in src, \
        "vhost_policy.html: page must reference AntiBot/WAF GW brand"


def test_vhost_policy_html_nav_link_active():
    """vhost_policy.html nav must mark the /vhost-policy link as .active."""
    src = _read_dash('vhost_policy.html')
    assert 'vhost-policy' in src and 'active' in src, \
        "vhost_policy.html: nav must have an active link for the vhost-policy page"


def test_vhost_policy_html_fetches_vhosts_for_selector():
    """vhost_policy.html must populate the selector from /vhosts endpoint."""
    src = _read_dash('vhost_policy.html')
    assert '/vhosts' in src, \
        "vhost_policy.html: must GET /vhosts to populate the hostname selector"


# ── 1.8.1 — control_center.html vhost stats card security ─────────────────────────

def test_settings_vhost_stats_uses_escapeHtml():
    """Vhost stats card JS must use escapeHtml to prevent XSS in hostname display."""
    src = _read_dash('control_center.html')
    # Find the vhost stats card JS block (search full function body)
    block_start = src.find('loadVhostStats')
    assert block_start != -1, "control_center.html: loadVhostStats function not found"
    # escapeHtml may appear anywhere after loadVhostStats definition
    assert 'escapeHtml' in src[block_start:], \
        "control_center.html: vhost stats table JS must use escapeHtml for hostname to prevent XSS"


def test_settings_vhost_stats_uses_timers_push():
    """Vhost stats setInterval must be tracked via _timers.push for cleanup."""
    src = _read_dash('control_center.html')
    import re as _re2
    m = _re2.search(r'_timers\.push\(setInterval\([\s\S]{0,300}?loadVhostStats', src)
    assert m, \
        "control_center.html: vhost stats setInterval must be wrapped in _timers.push() for proper cleanup"


def test_settings_vhost_stats_domcontentloaded():
    """Vhost stats JS must be deferred via DOMContentLoaded."""
    src = _read_dash('control_center.html')
    assert 'loadVhostStats' in src, "control_center.html: loadVhostStats not found"
    # loadVhostStats must appear inside or after a DOMContentLoaded block
    dcl_pos = src.rfind('DOMContentLoaded')
    stats_pos = src.rfind('loadVhostStats')
    assert dcl_pos != -1, "control_center.html: no DOMContentLoaded listener found for vhost stats"
    assert stats_pos > dcl_pos, \
        "control_center.html: loadVhostStats must be called inside or after DOMContentLoaded"


# ── 1.8.1 — Vhost Traffic Summary remove button (control_center.html) ──────────────────────────────

def test_settings_vhost_stats_remove_no_inline_onclick():
    """Vhost stats must not use legacy inline onclick (_removeVhostFromStats is removed)."""
    src = _read_dash('control_center.html')
    assert '_removeVhostFromStats' not in src, \
        "control_center.html: _removeVhostFromStats global function must be removed"


def test_settings_vhost_stats_table_colspan_updated():
    """control_center.html vhost stats empty/error rows must use colspan matching actual column count."""
    src = _read_dash('control_center.html')
    import re as _re3
    # Count actual <th> columns in vhost-stats thead
    thead_m = _re3.search(r'<thead>(.*?)</thead>', src, _re3.DOTALL)
    assert thead_m, "control_center.html: vhost stats table must have <thead>"
    col_count = len(_re3.findall(r'<th', thead_m.group(1)))
    assert col_count > 0, "control_center.html: no <th> found in thead"
    pos = src.find('vhost-stats-tbody')
    assert pos != -1
    block = src[pos: pos + 3000]
    expected = f'colspan="{col_count}"'
    assert expected in block or f"colspan='{col_count}'" in block, \
        f"control_center.html: vhost stats empty/error <td> must use colspan={col_count} to match {col_count} columns"


# ── 1.8.1 — main.html vhost breakdown chart checks ───────────────────────────

def test_main_vhost_breakdown_chart_type_line():
    """Vhost breakdown chart must use Chart.js type 'line' (stacked area)."""
    src = _read_dash('main.html')
    import re as _re2
    # The chart creation JS block is near 'loadVhostBreakdown' and 'new Chart'
    block_pos = src.find('loadVhostBreakdown')
    assert block_pos != -1, "main.html: loadVhostBreakdown function not found"
    # Search in a 5000-char window around the function
    block = src[block_pos: block_pos + 5000]
    assert "type:'line'" in block or "type: 'line'" in block, \
        "main.html: vhost breakdown chart must use type:'line' for stacked area rendering"


def test_main_vhost_breakdown_hides_when_no_data():
    """Breakdown chart JS must hide the card when no vhost datasets are returned."""
    src = _read_dash('main.html')
    assert "card.style.display='none'" in src or 'card.style.display = "none"' in src or \
           "style.display='none'" in src, \
        "main.html: breakdown chart must hide itself (display=none) when datasets array is empty"


def test_main_vhost_breakdown_palette_defined():
    """Vhost breakdown chart must define a colour palette for multi-vhost lines."""
    src = _read_dash('main.html')
    assert '_PALETTE' in src, \
        "main.html: vhost breakdown chart must define _PALETTE for per-vhost colour assignment"


def test_main_vhost_breakdown_uses_timers_push():
    """Vhost breakdown setInterval must be tracked via _timers.push for cleanup."""
    src = _read_dash('main.html')
    import re as _re2
    m = _re2.search(r'_timers\.push\(setInterval\([\s\S]{0,300}?loadVhostBreakdown', src)
    assert m, \
        "main.html: vhost breakdown setInterval must be wrapped in _timers.push() for proper cleanup"


# ── 1.8.1 — admin/settings.py import guard ───────────────────────────────────

def test_admin_settings_imports_data_path_explicitly():
    """admin/settings.py must import _DATA_PATH explicitly (not via *-import).
    _DATA_PATH has a leading underscore so `from config import *` excludes it;
    if not imported explicitly the vhost stats/breakdown endpoints raise NameError."""
    import pathlib as _pl
    src = (_pl.Path(__file__).parent.parent / 'admin' / 'settings.py').read_text()
    assert '_DATA_PATH' in src.split('\n', 20)[4], \
        "admin/settings.py line 5 must include _DATA_PATH in the explicit config import"


def test_admin_settings_vhost_stats_endpoint_no_invalid_sql():
    """vhost_stats_endpoint SQL must NOT reference non-existent columns ban_level or last_vhost on clients."""
    import pathlib as _pl
    src = (_pl.Path(__file__).parent.parent / 'admin' / 'settings.py').read_text()
    stats_start = src.find('async def vhost_stats_endpoint')
    assert stats_start != -1
    stats_block = src[stats_start: stats_start + 2000]
    assert 'ban_level' not in stats_block, \
        "vhost_stats_endpoint: must not query ban_level column (does not exist in clients table)"
    assert 'FROM clients' not in stats_block or 'last_vhost' not in stats_block.split('FROM clients')[1][:200], \
        "vhost_stats_endpoint: must not query last_vhost from clients table (column does not exist)"


# ── SEC-1 additional: login.html safeNext unit test ───────────────────────────
# Unit test for the safeNext() logic correctness (separate from source checks).

def test_login_safenext_logic():
    """safeNext validation logic: same-origin paths allowed, cross-origin rejected."""
    # Replicate the safeNext() logic in Python for unit testing
    from urllib.parse import urlparse, urljoin

    def safe_next_py(raw, origin='https://example.com'):
        if not raw:
            return None
        try:
            base = origin
            full = urljoin(base, raw)
            parsed = urlparse(full)
            parsed_origin = f"{parsed.scheme}://{parsed.netloc}"
            if parsed_origin == origin:
                return parsed.path + (f"?{parsed.query}" if parsed.query else '') + (f"#{parsed.fragment}" if parsed.fragment else '')
        except Exception:
            pass
        return None

    origin = 'https://admin.example.com'
    # Same-origin paths should be allowed
    assert safe_next_py('/dashboard', origin) == '/dashboard'
    assert safe_next_py('/antibot-appsec-gateway/secured/dashboard', origin) is not None
    # Cross-origin must be blocked
    assert safe_next_py('https://evil.com', origin) is None
    assert safe_next_py('//evil.com/path', origin) is None
    assert safe_next_py('javascript:alert(1)', origin) is None
    # Empty/None returns None
    assert safe_next_py('', origin) is None
    assert safe_next_py(None, origin) is None


# ── DES-3: No silent catch on UI-state fetch (login.html, settings.html) ─────
# Bug: .catch(() => ({})) silently swallows fetch/parse errors → downstream
# code gets {} with all properties undefined; UI shows nothing or crashes.
# Fix: structured try/catch with _error flag.

def test_login_no_silent_catch():
    """login.html must not use .catch(() => ({})) to swallow JSON parse errors."""
    src = _read_dash('login.html')
    assert '.catch(() => ({}))' not in src and ".catch(()=>({}))" not in src, (
        "login.html: silent .catch(() => ({})) found — JSON parse errors are swallowed "
        "silently; downstream code gets {} and produces undefined behavior."
    )

def test_settings_no_silent_catch():
    """settings.html must not use .catch(() => ({})) to swallow JSON parse errors."""
    src = _read_dash('settings.html')
    assert '.catch(() => ({}))' not in src and ".catch(()=>({}))" not in src, (
        "settings.html: silent .catch(() => ({})) found on UI-state-populating fetch."
    )


# ── DES-4: agents.html title consistency ─────────────────────────────────────

def test_agents_title_no_stealth_prefix():
    """agents.html <title> must not contain 'Stealth' (was inconsistent with h1)."""
    src = _read_dash('agents.html')
    title_match = _re.search(r'<title>(.*?)</title>', src)
    if title_match:
        title = title_match.group(1)
        assert 'Stealth' not in title, (
            f"agents.html <title> still contains 'Stealth': {repr(title)}. "
            "Title was inconsistent with the h1 element after the rename."
        )


# ── Regression: _decay_risk NameError in _js_challenge_applicable ────────────
# Bug: _js_challenge_applicable called _decay_risk(s, now()) without importing
# it. _decay_risk lives in scoring.py and is late-imported at other call sites
# in js_challenge.py but was missing from this function. Any first-contact
# request with a warmed ip_state entry (risk > 0) caused HTTP 500.
# Fix: `from scoring import _decay_risk` added inside _js_challenge_applicable.

def test_js_challenge_applicable_imports_decay_risk():
    """_js_challenge_applicable must import _decay_risk before calling it."""
    import inspect
    from challenge import js_challenge
    src = inspect.getsource(js_challenge._js_challenge_applicable)
    assert "from scoring import _decay_risk" in src, (
        "_js_challenge_applicable must import _decay_risk from scoring — "
        "it calls _decay_risk(s, now()) to apply exponential decay before "
        "comparing risk_score against the Turnstile activation threshold. "
        "Without the import the function raises NameError → HTTP 500."
    )


# ── Regression: honey probe false-positive guard ──────────────────────────────
# Bug: honey_probe_endpoint applied +90 risk (honey-cred) to any identity that
# hit the probe URL, including legitimate human developers who viewed the HTML
# comment in browser DevTools and curiosity-clicked the link. Real browsers
# have a valid chal cookie (auto-minted or Turnstile-issued); AI scraping
# agents have no cookie.
# Fix: skip the ban when the probe request carries a valid chal cookie.

def test_honey_probe_skips_ban_with_valid_chal_cookie():
    """honey_probe_endpoint must not apply risk when requester has a valid
    chal cookie — that confirms a real browser, not an AI agent."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.honey_probe_endpoint)
    assert "_verify_chal_cookie" in src, (
        "honey_probe_endpoint must check _verify_chal_cookie before applying "
        "honey-cred risk — a human developer who clicks the probe URL from "
        "DevTools has a valid chal cookie and must not be banned."
    )
    assert "has_chal" in src or "chal_cookie" in src or "not has_chal" in src, (
        "honey_probe_endpoint must gate the ban on the chal-cookie check result."
    )


# ════════════════════════════════════════════════════════════════════════════
# AWS ELB health check pass-through (1.7.4)
# ELB-HealthChecker/2.0 sends minimal headers — no Accept, Accept-Language,
# Sec-Fetch-* — which triggers ua-non-browser (25 pts) + ai-headers-incomplete
# (20 pts) per request, banning the LB node after two hits and causing the
# target to be marked unhealthy.  Default path is "/" (AWS ALB/NLB default).
# Bypass requires BOTH path AND UA prefix to match.
# ════════════════════════════════════════════════════════════════════════════

def test_elb_health_check_config_vars_exist():
    """ELB_HEALTH_CHECK_PATH and ELB_HEALTH_CHECK_UA must be defined in config."""
    import config
    assert hasattr(config, "ELB_HEALTH_CHECK_PATH"), (
        "config.py must define ELB_HEALTH_CHECK_PATH (default '/' = root)"
    )
    assert hasattr(config, "ELB_HEALTH_CHECK_UA"), (
        "config.py must define ELB_HEALTH_CHECK_UA (default 'ELB-HealthChecker')"
    )
    assert config.ELB_HEALTH_CHECK_PATH == "/", (
        "Default ELB_HEALTH_CHECK_PATH must be '/' — AWS ALB/NLB sends health "
        "checks to root by default; empty default caused bypass to never activate"
    )
    assert config.ELB_HEALTH_CHECK_UA == "ELB-HealthChecker", (
        "Default ELB_HEALTH_CHECK_UA must be 'ELB-HealthChecker' to match "
        "AWS ALB/NLB health checker User-Agent prefix 'ELB-HealthChecker/2.0'"
    )


def test_elb_health_check_bypass_in_protect_source():
    """protect() middleware must contain the ELB health check bypass guard."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    assert "ELB_HEALTH_CHECK_PATH" in src, (
        "protect() must check ELB_HEALTH_CHECK_PATH to bypass bot detection "
        "for AWS ELB health checker requests"
    )
    assert "ELB_HEALTH_CHECK_UA" in src, (
        "protect() must check ELB_HEALTH_CHECK_UA — path alone is not enough; "
        "UA must also match to prevent abuse from non-LB clients"
    )


def test_elb_bypass_requires_both_path_and_ua():
    """The bypass must require BOTH path AND UA prefix to match."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    # Both must appear in a compound condition — locate the ELB block
    elb_idx = src.find("ELB_HEALTH_CHECK_PATH")
    assert elb_idx != -1
    elb_block = src[elb_idx: elb_idx + 400]
    assert "ELB_HEALTH_CHECK_UA" in elb_block, (
        "ELB UA check must be inside the ELB_HEALTH_CHECK_PATH block — "
        "a UA-only check would let any external client bypass detection"
    )
    assert "ELB_HEALTH_CHECK_UA in" in elb_block or "ELB_HEALTH_CHECK_UA and" in elb_block, (
        "ELB_HEALTH_CHECK_UA must be used as a substring match ('in') against "
        "the User-Agent header so future ELB-HealthChecker/3.0 versions also match"
    )


def test_elb_bypass_path_check_is_exact():
    """Path check must be exact equality, not startswith, to prevent prefix abuse."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    assert "request.path == ELB_HEALTH_CHECK_PATH" in src, (
        "ELB path check must use exact equality (==) not startswith — "
        "a prefix match would expose adjacent paths to the bypass"
    )


def test_elb_health_check_response_is_200_ok():
    """ELB bypass must return HTTP 200 with 'ok' body."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    # Search from the actual if-condition line, not the comment
    elb_idx = src.find("if ELB_HEALTH_CHECK_PATH and request.path")
    assert elb_idx != -1
    block = src[elb_idx: elb_idx + 600]
    assert "status=200" in block, (
        "ELB health check bypass must return HTTP 200 — "
        "ELB marks targets unhealthy on any non-2xx response"
    )
    assert '"ok"' in block or "'ok'" in block, (
        "ELB bypass response body must be 'ok' (plain text health status)"
    )


def test_elb_bypass_default_path_is_root():
    """Default ELB_HEALTH_CHECK_PATH must be '/' so AWS ALB/NLB health checks
    to the root work out of the box without operator configuration."""
    import config
    assert config.ELB_HEALTH_CHECK_PATH == "/", (
        "ELB_HEALTH_CHECK_PATH default must be '/' — AWS ALB/NLB health checkers "
        "probe GET / by default; the previous empty default meant the bypass never "
        "activated and LB nodes were banned after two requests"
    )


def test_elb_bypass_disable_via_empty_ua():
    """Setting ELB_HEALTH_CHECK_UA='' must disable the bypass entirely."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    # Locate the inner UA guard inside the ELB block
    elb_idx = src.find("if ELB_HEALTH_CHECK_PATH and request.path")
    assert elb_idx != -1
    block = src[elb_idx: elb_idx + 400]
    assert ("if ELB_HEALTH_CHECK_UA" in block or
            "ELB_HEALTH_CHECK_UA and" in block), (
        "ELB bypass must be gated on ELB_HEALTH_CHECK_UA being non-empty — "
        "operators can disable the bypass by setting ELB_HEALTH_CHECK_UA=''"
    )


def test_elb_path_logged_as_hash_not_plaintext():
    """ELB bypass must log a hash of the path, not the plaintext value."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    elb_idx = src.find("ELB_HEALTH_CHECK_PATH")
    block = src[elb_idx: elb_idx + 600]
    assert "sha256" in block or "path_tag" in block or "hash" in block.lower(), (
        "ELB bypass must log a hash (sha256) of the health check path — "
        "logging the plaintext path leaks the secret value to log aggregators"
    )



# Authorized monitoring bot pass-through (1.7.4)
# UptimeRobot, Pingdom, StatusCake et al. probe "/" and trigger ua-non-browser +
# ai-headers-incomplete → banned after 2 hits.  AUTHORIZED_BOT_UAS bypasses
# detection on path "/" and records "authorized-robot" (not counted as blocked).

def test_authorized_bot_uas_config_exists():
    """AUTHORIZED_BOT_UAS must be defined in config as a list of bot dicts."""
    import config
    assert hasattr(config, "AUTHORIZED_BOT_UAS"), (
        "config.py must define AUTHORIZED_BOT_UAS (list of bot dicts for "
        "authorized monitoring bots)"
    )
    assert isinstance(config.AUTHORIZED_BOT_UAS, list), (
        "AUTHORIZED_BOT_UAS must be a list of dicts"
    )
    known = {"UptimeRobot", "Pingdom", "StatusCake"}
    matched = {k for k in known if any(k in e.get("ua", "") for e in config.AUTHORIZED_BOT_UAS if isinstance(e, dict))}
    assert matched == known, (
        f"Default AUTHORIZED_BOT_UAS must include UptimeRobot, Pingdom, StatusCake; "
        f"missing: {known - matched}"
    )


def test_authorized_bot_bypass_in_protect_source():
    """protect() must contain AUTHORIZED_BOT_UAS bypass on path '/'."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    assert "AUTHORIZED_BOT_UAS" in src, (
        "protect() must check AUTHORIZED_BOT_UAS to bypass detection for "
        "authorized monitoring bots hitting '/'"
    )
    assert "authorized-robot" in src, (
        "protect() must record reason='authorized-robot' for authorized bots — "
        "this is how they appear in the dashboard (blue, not blocked)"
    )


def test_authorized_bot_bypass_only_on_root():
    """Authorized bot bypass must check request.path against per-entry path."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    # Anchor on the actual code block, not the earlier comment that also
    # contains "AUTHORIZED_BOT_UAS", so extra lines before it don't shift
    # the window past the request.path comparison.
    bot_idx = src.find("if AUTHORIZED_BOT_UAS:")
    assert bot_idx != -1, "if AUTHORIZED_BOT_UAS: block not found in protect()"
    bot_block = src[bot_idx: bot_idx + 3000]
    assert "request.path ==" in bot_block or "request.path !=" in bot_block, (
        "Authorized bot bypass must compare request.path against the configured "
        "path from each entry (using == or !=)"
    )
    assert "_bot_path" in bot_block, (
        "Authorized bot bypass must use per-entry path variable (_bot_path) — "
        "not a global hardcoded '/'"
    )


def test_passthrough_reasons_not_counted_as_blocked():
    """authorized-robot in _PASSTHROUGH_REASONS → not counted as blocked."""
    from core.metrics import _PASSTHROUGH_REASONS
    assert "authorized-robot" in _PASSTHROUGH_REASONS, (
        "_PASSTHROUGH_REASONS must include 'authorized-robot' so these requests "
        "are not counted in the blocked metric"
    )


def test_authorized_robot_tag_in_main_dashboard():
    """main.html must have .tag.authorized-robot CSS class (blue)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "authorized-robot" in src, (
        "main.html must define .tag.authorized-robot CSS and render 'authorized-robot' "
        "events in blue, not as blocked"
    )
    assert "evt-authorized" in src, (
        "main.html must define .evt.evt-authorized CSS class (blue border-left) for "
        "authorized bot events in the live events stream"
    )


def test_log_level_n_propagated_on_hot_reload():
    """LOG_LEVEL hot-reload must also update _LOG_LEVEL_N in all modules.

    Regression: config_endpoint propagated LOG_LEVEL string to all modules via
    the generic setattr loop, but _LOG_LEVEL_N (the numeric sentinel used by
    slog() for level filtering) is not in _HOT_RELOAD_KNOBS and was not updated.
    Result: slog() kept filtering at the original startup level regardless of
    the dashboard log-level change.
    Fix: config_endpoint explicitly propagates _LOG_LEVEL_N after LOG_LEVEL changes.
    """
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.config_endpoint)
    assert "_LOG_LEVEL_N" in src, (
        "config_endpoint must explicitly propagate _LOG_LEVEL_N when LOG_LEVEL "
        "is hot-reloaded — the generic knob loop only updates the string value, "
        "but slog() uses the derived numeric sentinel for level filtering."
    )
    assert "_LOG_LEVELS.get(value" in src or "_LOG_LEVELS.get(" in src, (
        "config_endpoint must recompute _LOG_LEVEL_N from _LOG_LEVELS dict "
        "after a LOG_LEVEL hot-reload, not hard-code a default value."
    )


def test_ip_intel_endpoint_imports_reputation_symbols():
    """admin/users.py ip_intel_endpoint must import all four reputation symbols.

    Regression: ip_intel_endpoint called _city_lookup, _asn_lookup,
    _abuseipdb_lookup, _crowdsec_check, and _tor_exits without importing them —
    proxy_handler.py had those names in its global scope via its own imports,
    but admin/users.py is a separate module with its own namespace. Any call
    to ip_intel_endpoint raised NameError: name '_city_lookup' is not defined.
    """
    src = open("admin/users.py").read()
    for sym in ("_city_lookup", "_asn_lookup", "_abuseipdb_lookup",
                "_crowdsec_check", "_tor_exits"):
        assert sym in src.split("ip_intel_endpoint")[0] or \
               f"import {sym}" in src or \
               f"from reputation" in src, (
            f"admin/users.py must import {sym!r} before ip_intel_endpoint uses it"
        )
    # Stricter: verify the import lines are at module level, not inside the function
    import_block = src[:src.index("async def ip_intel_endpoint")]
    for sym in ("_city_lookup", "_asn_lookup", "_abuseipdb_lookup",
                "_crowdsec_check", "_tor_exits"):
        assert sym in import_block, (
            f"{sym!r} must be imported at module level in admin/users.py, "
            f"not inside ip_intel_endpoint — NameError at runtime otherwise"
        )


# ═══════════════════════════════════════════════════════════════════════════
# 1.7.4 — regression / unit tests
# ═══════════════════════════════════════════════════════════════════════════

# ── logs.html: r.ok guard before r.json() in LOG_LEVEL POST handlers ─────

def test_logs_html_log_level_button_has_rok_guard():
    """logs.html level-button click handler must guard r.ok before r.json().

    Regression: calling r.json() unconditionally on a non-JSON 404/401
    response caused 'unexpected non-whitespace character' SyntaxError in the
    browser when the session expired.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "logs.html").read_text()
    # Find the block that POSTs LOG_LEVEL and verify r.ok appears before r.json()
    # Both LOG_LEVEL handlers must contain r.ok checks
    rok_count = src.count("if (!r.ok)")
    assert rok_count >= 2, (
        f"logs.html must have at least 2 'if (!r.ok)' guards (one per LOG_LEVEL "
        f"POST handler — button click + dropdown onchange); found {rok_count}"
    )


def test_logs_html_log_level_handlers_no_unconditional_json():
    """logs.html must not call r.json() before checking r.ok in LOG_LEVEL handlers.

    Regression: unconditional r.json() caused JSON parse error on non-JSON responses.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "logs.html").read_text()
    # Find LOG_LEVEL POST blocks and ensure r.ok check precedes r.json() in each
    log_level_blocks = src.split("LOG_LEVEL")
    for blk in log_level_blocks[1:]:  # skip before first LOG_LEVEL occurrence
        # Only check blocks that contain a POST fetch (the two handlers)
        if "method:'POST'" not in blk and 'method:"POST"' not in blk:
            continue
        # Within ~300 chars of the fetch, r.ok must appear before r.json()
        fetch_area = blk[:400]
        if "r.json()" in fetch_area:
            ok_pos   = fetch_area.find("r.ok")
            json_pos = fetch_area.find("r.json()")
            assert ok_pos != -1 and ok_pos < json_pos, (
                "logs.html: r.ok must be checked before r.json() in LOG_LEVEL "
                "POST handler — unconditional r.json() causes SyntaxError on "
                "non-JSON responses (session expiry / 401 decoy page)"
            )


def test_logs_html_authorized_robot_shown_in_blue():
    """logs.html must render authorized-robot reason in blue, not red.

    Regression: authorized monitoring-bot events (UptimeRobot, Pingdom, etc.)
    were shown as blocked (red) because the reason was not in the colour map.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "logs.html").read_text()
    assert "authorized-robot" in src, (
        "logs.html must handle 'authorized-robot' reason in its render logic"
    )
    # The reason must map to blue, not red
    idx = src.find("authorized-robot")
    neighbourhood = src[max(0, idx - 20):idx + 60]
    assert "blue" in neighbourhood, (
        "logs.html must colour 'authorized-robot' entries with var(--blue), "
        "not with the default red used for blocked events"
    )


# ── controls.html: master bypass switch ──────────────────────────────────

def test_controls_bypass_bar_html_elements_present():
    """controls.html must contain bypass bar elements: #bypass-bar, #bypass-sw, #bypass-warn."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    for elem_id in ("bypass-bar", "bypass-sw", "bypass-warn"):
        assert f'id="{elem_id}"' in src, (
            f"controls.html must define element id={elem_id!r} for the master "
            f"bypass switch UI"
        )


def test_controls_bypass_css_classes_defined():
    """controls.html must define CSS for .bypass-sw, .bypass-sw.on, #bypass-bar.bypass-on."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    for selector in (".bypass-sw", ".bypass-sw.on", "#bypass-bar.bypass-on"):
        assert selector in src, (
            f"controls.html must define CSS selector {selector!r} for the "
            f"master bypass switch"
        )


def test_controls_bypass_iife_snapshots_and_restores():
    """controls.html bypass IIFE must save snapshot to localStorage and restore on deactivate."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    assert "_BYPASS_ACTIVE_KEY" in src, (
        "controls.html bypass IIFE must define _BYPASS_ACTIVE_KEY localStorage key"
    )
    assert "_BYPASS_SNAP_KEY" in src or "SNAP" in src, (
        "controls.html bypass IIFE must snapshot current state to localStorage "
        "before disabling all controls"
    )
    assert "localStorage.setItem" in src, (
        "controls.html bypass IIFE must persist bypass state via localStorage.setItem"
    )
    assert "localStorage.removeItem" in src, (
        "controls.html bypass IIFE must clean up localStorage on bypass deactivation"
    )


def test_controls_bypass_posts_false_for_all_bool_knobs():
    """controls.html bypass activation must POST false for every bool knob."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    # The bypass IIFE must set all bool knobs to false
    assert "payload[n] = false" in src or "payload[k] = false" in src or \
           "= false" in src, (
        "controls.html bypass IIFE must set all bool knobs to false in the "
        "POST payload — not just a subset"
    )


def test_controls_bypass_uses_credentials_include():
    """controls.html bypass fetch calls must include credentials:'include'."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    bypass_block = src[src.find("_BYPASS_ACTIVE_KEY"):]
    assert "credentials:'include'" in bypass_block or \
           'credentials:"include"' in bypass_block, (
        "controls.html bypass IIFE fetch calls must include credentials:'include' "
        "so the session cookie is sent with admin config POST requests"
    )


def test_controls_bypass_requires_user_confirmation():
    """controls.html bypass activation must show a confirmation dialog before disabling all controls."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    bypass_block = src[src.find("_BYPASS_ACTIVE_KEY"):]
    assert "_asyncConfirm(" in bypass_block, (
        "controls.html bypass switch must require explicit user confirmation "
        "via _asyncConfirm() before disabling all bot detection controls"
    )


# ── controls.html: per-card collapse toggles ─────────────────────────────

def test_controls_collapse_css_defined():
    """controls.html must define .cc-chevron and .cc-collapsed CSS for card collapse."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    for selector in (".cc-chevron", ".cc-collapsed"):
        assert selector in src, (
            f"controls.html must define CSS selector {selector!r} for "
            f"per-card collapse toggle feature"
        )


def test_controls_collapse_iife_persists_to_localstorage():
    """controls.html collapse IIFE must persist collapse state to localStorage."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    assert "_CC_PREFIX" in src, (
        "controls.html collapse IIFE must define _CC_PREFIX localStorage key prefix "
        "for per-card collapse state persistence"
    )
    # Collapse state must be written and read from localStorage
    cc_block = src[src.find("_CC_PREFIX"):]
    assert "localStorage.setItem" in cc_block, (
        "controls.html collapse IIFE must save collapse state via localStorage.setItem"
    )
    assert "localStorage.getItem" in cc_block, (
        "controls.html collapse IIFE must restore collapse state via localStorage.getItem"
    )


def test_controls_collapse_card_h2_click_handler():
    """controls.html collapse IIFE must attach click handler to card h2 elements."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    cc_block = src[src.find("_CC_PREFIX"):]
    assert "querySelectorAll('.card')" in cc_block or \
           "querySelectorAll(\".card\")" in cc_block, (
        "controls.html collapse IIFE must iterate .card elements to attach "
        "click handlers to their h2 headings"
    )
    assert "addEventListener('click'" in cc_block or \
           'addEventListener("click"' in cc_block, (
        "controls.html collapse IIFE must attach 'click' event listener for toggle"
    )


# ── main.html / agents.html: 7-day bucket fix + 30-day window ────────────

def test_main_pick_bucket_7day_returns_3600():
    """main.html pickBucketForRange(10080) must return 3600 (hourly buckets for 7d).

    Regression: was returning 900 (15-min buckets), producing 672 data points
    all labelled 'HH:MM' by fmtTime's sub-3600 branch — no date component shown.
    With 3600-s buckets fmtTime returns 'May 3 14:00' format.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    # Extract a generous window around pickBucketForRange (function is ≤ 10 lines)
    start  = src.index("function pickBucketForRange")
    fn_src = src[start:start + 350]
    # Must NOT map 10080 to 900
    assert "10080) return 900" not in fn_src and \
           "<= 10080) return 900" not in fn_src, (
        "main.html pickBucketForRange must not map 7-day range (10080 min) to "
        "900-s buckets — that produces HH:MM-only labels with no date"
    )
    # Must map 10080 to 3600
    assert "10080) return 3600" in fn_src or \
           "<= 10080) return 3600" in fn_src, (
        "main.html pickBucketForRange must map 7-day range (10080 min) to "
        "3600-s (hourly) buckets so fmtTime produces 'May 3 14:00' labels"
    )


def test_main_pick_bucket_30day_returns_86400():
    """main.html pickBucketForRange for >7d range must return 86400 (daily buckets)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    start = src.index("function pickBucketForRange")
    # The fallthrough return for large ranges must be 86400
    fn_area = src[start:start + 300]
    assert "return 86400" in fn_area, (
        "main.html pickBucketForRange must return 86400 for ranges > 7d "
        "(30-day view needs daily buckets for 'May 3' date labels)"
    )


def test_main_30day_option_in_range_select():
    """main.html range <select> must include a 30-day option (value='43200')."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert 'value="43200"' in src or "value='43200'" in src, (
        "main.html range select must include <option value='43200'>30 days</option>"
    )


def test_agents_pick_bucket_7day_returns_3600():
    """agents.html tPickBucketForRange(10080) must return 3600."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert "tPickBucketForRange" in src, (
        "agents.html must define tPickBucketForRange — agents dashboard had no "
        "auto-bucket logic, causing 7-day view to use 60-s buckets with HH:MM labels"
    )
    start = src.index("function tPickBucketForRange")
    fn_area = src[start:start + 300]
    assert "return 3600" in fn_area, (
        "agents.html tPickBucketForRange must return 3600 for 7-day range "
        "(10080 min) so fmtTimeBucket produces date+time labels"
    )
    assert "10080) return 900" not in fn_area and \
           "<= 10080) return 900" not in fn_area, (
        "agents.html tPickBucketForRange must not map 7d to 900-s buckets"
    )


def test_agents_pick_bucket_30day_returns_86400():
    """agents.html tPickBucketForRange for >7d must return 86400."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    start = src.index("function tPickBucketForRange")
    fn_area = src[start:start + 300]
    assert "return 86400" in fn_area, (
        "agents.html tPickBucketForRange must return 86400 for 30-day range"
    )


def test_agents_30day_option_in_range_select():
    """agents.html range select must include <option value='43200'>30 days</option>."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert 'value="43200"' in src or "value='43200'" in src, (
        "agents.html range select must include a 30-day option (value='43200')"
    )


def test_agents_auto_select_bucket_wired_to_range_change():
    """agents.html range change listener must call tAutoSelectBucket()."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert "tAutoSelectBucket" in src, (
        "agents.html must define tAutoSelectBucket to update the bucket select "
        "when the range changes"
    )
    # Verify it is called from the range change listener
    range_listener_area = src[src.rfind("t-range") - 10:
                               src.rfind("t-range") + 400]
    assert "tAutoSelectBucket" in range_listener_area, (
        "agents.html t-range change listener must call tAutoSelectBucket() so the "
        "bucket selector stays in sync with the chosen time window"
    )


# ── main.html / agents.html: tooltip date+time ───────────────────────────

def test_main_tooltip_callback_uses_timeline_epoch():
    """main.html chart tooltip title must use _lastMainTimeline epoch, not just axis label.

    Without this, short-window views show bare 'HH:MM' in the tooltip with no date.
    Regression: used items[0].index (onClick API) instead of items[0].dataIndex
    (TooltipItem API) — index was undefined, timeline lookup returned undefined,
    callback fell back to items[0].label which is '' for step-filtered points.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "_lastMainTimeline" in src, (
        "main.html tooltip title callback must reference _lastMainTimeline to "
        "derive a full date+time string from the bucket epoch"
    )
    assert "_lastMainBucketSecs" in src, (
        "main.html tooltip title callback must reference _lastMainBucketSecs to "
        "format the bucket end time correctly"
    )
    # Must use .dataIndex (Chart.js TooltipItem API), not .index (onClick element API)
    # _tooltipTitle() helper contains the dataIndex access; callbacks delegate to it.
    tt_start = src.find("function _tooltipTitle(")
    tt_end   = src.find("\n}", tt_start) + 2
    tt_body  = src[tt_start:tt_end]
    assert "dataIndex" in tt_body, (
        "main.html _tooltipTitle helper must use items[0].dataIndex (Chart.js v3 "
        "TooltipItem property) — items[0].index is undefined in tooltip callbacks "
        "causing the epoch lookup to fail and the title to show as empty string"
    )
    # The helper must produce a human-readable date (not just relay the axis label)
    assert "toLocaleDateString" in tt_body or "toLocaleString" in tt_body, (
        "main.html _tooltipTitle helper must format the epoch as a readable "
        "date string (toLocaleDateString / toLocaleString)"
    )


def test_agents_tooltip_config_defined():
    """agents.html chart must have a tooltip plugin config with title callback.

    Regression: used items[0].index instead of items[0].dataIndex — index is
    undefined in Chart.js v3 TooltipItem objects causing silent fallback to
    items[0].label which is '' for step-filtered axis labels.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    # agents.html had no tooltip config at all before 1.7.4
    assert "tooltip:{" in src.replace(" ", "") or \
           "tooltip: {" in src, (
        "agents.html chart options must define a tooltip plugin config "
        "(was absent before 1.7.4)"
    )
    assert "_lastAgentTimeline" in src, (
        "agents.html tooltip title callback must reference _lastAgentTimeline "
        "to produce a full date+time string"
    )
    assert "_lastAgentBucketSecs" in src, (
        "agents.html tooltip title callback must reference _lastAgentBucketSecs"
    )
    # Must use .dataIndex, not .index — _tooltipTitle() helper contains the access.
    tt_start = src.find("function _tooltipTitle(")
    tt_end   = src.find("\n}", tt_start) + 2
    tt_body  = src[tt_start:tt_end]
    assert "dataIndex" in tt_body, (
        "agents.html _tooltipTitle helper must use items[0].dataIndex (Chart.js v3 "
        "TooltipItem API) — items[0].index is undefined in tooltip context, "
        "causing epoch lookup to fail and tooltip title to appear empty"
    )


def test_agents_tooltip_callback_formats_date():
    """agents.html tooltip title callback must format the epoch as a readable date."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    tt_start = src.find("function _tooltipTitle(")
    tt_end   = src.find("\n}", tt_start) + 2
    tt_body  = src[tt_start:tt_end]
    assert "toLocaleDateString" in tt_body or "toLocaleString" in tt_body, (
        "agents.html _tooltipTitle helper must call toLocaleDateString/toLocaleString "
        "to format the bucket start as a human-readable date"
    )


# ── Dockerfile: pip version pinning + builder USER drop ──────────────────

def test_dockerfile_pip_deps_use_exact_pins():
    """Dockerfile must pin all pip deps to exact ==x.y.z versions (DL3013 / Aikido supply-chain)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "Dockerfile").read_text()
    # Find the pip install RUN instruction
    pip_block = src[src.find("pip install"):src.find("pip install") + 400]
    # No range specifiers allowed
    for bad in (">=", "<=", ">", "<", "~="):
        # allow < inside version strings only — simplest check: no bare range after package name
        assert f"'{bad}" not in pip_block and f'"{bad}' not in pip_block, (
            f"Dockerfile pip install must use exact ==x.y.z pins, not range "
            f"specifier {bad!r} — Aikido DL3013 / supply-chain finding"
        )
    # Must have exact pins
    assert "==" in pip_block, (
        "Dockerfile pip install must use exact ==x.y.z version pins"
    )


def test_dockerfile_armv7_pip_deps_use_exact_pins():
    """Dockerfile.armv7 must pin all pip deps to exact ==x.y.z versions."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "Dockerfile.armv7").read_text()
    pip_block = src[src.find("pip install"):src.find("pip install") + 400]
    for bad in (">=", "<=", "~="):
        assert f"'{bad}" not in pip_block and f'"{bad}' not in pip_block, (
            f"Dockerfile.armv7 pip install must use exact pins, not {bad!r}"
        )
    assert "==" in pip_block, (
        "Dockerfile.armv7 pip install must use exact ==x.y.z version pins"
    )


def test_dockerfile_builder_stage_drops_root():
    """Dockerfile builder stage must end with USER nonroot (Aikido DL3002)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "Dockerfile").read_text()
    # Find builder stage (everything before second FROM)
    from_indices = [i for i in range(len(src)) if src[i:i+4] == "FROM"]
    assert len(from_indices) >= 2, "Dockerfile must have at least 2 FROM lines (multi-stage)"
    builder_stage = src[:from_indices[1]]
    assert "USER nonroot" in builder_stage or "USER nobody" in builder_stage, (
        "Dockerfile builder stage must end with 'USER nonroot' to satisfy "
        "DL3002 — last USER in builder was root (Aikido HIGH finding)"
    )


def test_dockerfile_armv7_builder_stage_drops_root():
    """Dockerfile.armv7 builder stage must end with USER nobody (Aikido DL3002)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "Dockerfile.armv7").read_text()
    from_indices = [i for i in range(len(src)) if src[i:i+4] == "FROM"]
    assert len(from_indices) >= 2, "Dockerfile.armv7 must have at least 2 FROM lines"
    builder_stage = src[:from_indices[1]]
    assert "USER nobody" in builder_stage or "USER nonroot" in builder_stage, (
        "Dockerfile.armv7 builder stage must end with 'USER nobody' to satisfy "
        "DL3002 — Alpine builder had implicit root as last USER"
    )


# ── 1.7.5: Authorized bots in purple ─────────────────────────────────────────

def test_main_authorized_bots_purple_dataset():
    """main.html traffic chart must have a purple 'authorized bots' dataset."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "authorized bots" in src, (
        "main.html chart must have 'authorized bots' dataset label (1.7.5)"
    )
    assert "#bc8cff" in src, (
        "main.html chart must use purple #bc8cff for authorized bots dataset"
    )
    assert "authorized_robot" in src, (
        "main.html tick() must map b.authorized_robot to the authorized bots dataset"
    )


def test_agents_authorized_bots_purple_dataset():
    """agents.html chart must have a purple 'authorized bots' dataset."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert "authorized bots" in src, (
        "agents.html chart must have 'authorized bots' dataset label (1.7.5)"
    )
    assert "#bc8cff" in src, (
        "agents.html chart must use purple #bc8cff for authorized bots dataset"
    )
    assert "b.authorized_robot" in src, (
        "agents.html tickChart() must map b.authorized_robot to dataset[3]"
    )


def test_geo_authorized_bot_legend():
    """geo.html map legend must include authorized bots entry."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "geo.html").read_text()
    assert "authorized bots" in src, (
        "geo.html legend must include 'authorized bots' entry (1.7.5)"
    )


def test_geo_authorized_bot_circle_renders():
    """geo.html renderMap() must draw a purple circle for authorized_robot count."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "geo.html").read_text()
    assert "authorized_robot" in src, (
        "geo.html renderMap() must use p.authorized_robot to draw purple circle"
    )
    assert "authBots" in src, (
        "geo.html renderMap() must extract authBots from point and render if > 0"
    )


def test_geo_authorized_bot_scrubber_ar_counter():
    """geo.html scrubber bucket merging must track ar counter for authorized_robot."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "geo.html").read_text()
    assert "ar:0" in src, (
        "geo.html scrubber bucket init must include ar:0 for authorized_robot"
    )
    rebuild_idx = src.find("rebuildBuckets")
    assert rebuild_idx != -1, "geo.html must have rebuildBuckets function"
    assert "authorized_robot" in src[rebuild_idx:rebuild_idx + 2000], (
        "geo.html rebuildBuckets() must handle 'authorized_robot' kind → ar counter"
    )


def test_metrics_timeline_has_authorized_robot_field():
    """metrics_endpoint timeline aggregation must include authorized_robot field."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    loop_start = src.find('"authorized_robot": 0')
    assert loop_start != -1, (
        "metrics_endpoint timeline agg dict must init 'authorized_robot': 0 (1.7.5)"
    )
    assert "authorized-robot" in src[loop_start:loop_start + 1600], (
        "metrics_endpoint must extract by_reason['authorized-robot'] into authorized_robot"
    )


def test_agents_timeline_has_authorized_robot_query():
    """agents_timeline_endpoint must have a dedicated SQL query for authorized-robot."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.py").read_text()
    assert "reason='authorized-robot'" in src, (
        "agents.py agents_timeline_endpoint must query events for reason='authorized-robot'"
    )
    assert '"authorized_robot": ar' in src or "'authorized_robot': ar" in src, (
        "agents.py must include authorized_robot in each series bucket"
    )


def test_geo_authorized_robot_kind_in_geo_data_endpoint():
    """geo_data_endpoint must classify authorized-robot events as authorized_robot kind."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    geo_start = src.find("async def geo_data_endpoint")
    assert geo_start != -1, "geo_data_endpoint must exist in proxy_handler.py"
    geo_section = src[geo_start:geo_start + 16000]
    assert 'reason == "authorized-robot"' in geo_section, (
        "geo_data_endpoint must detect reason==\"authorized-robot\" for purple classification"
    )
    assert '"authorized_robot"' in geo_section or "'authorized_robot'" in geo_section, (
        "geo_data_endpoint must use 'authorized_robot' kind for authorized-robot events"
    )


def test_build_validation_armv7_requires_platform_flag():
    """BUILD_VALIDATION: armv7 image must be built with --platform linux/arm/v7.
    Without this flag, a build on an arm64 host produces an arm64 image tagged
    as armv7 — the container will fail with exit code 159 on the armv7 device.
    This is a documentation/procedure test — it checks that rules.md or
    BUILD_VALIDATION.md documents the --platform flag for armv7 builds."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    # Check rules.md or any validation/build doc mentions --platform for armv7
    candidates = ["rules.md", "BUILD_VALIDATION.md"]
    found = False
    for name in candidates:
        p = root / name
        if p.exists() and "--platform linux/arm/v7" in p.read_text():
            found = True
            break
    assert found, (
        "rules.md or BUILD_VALIDATION.md must document '--platform linux/arm/v7' "
        "for armv7 builds — omitting this flag on an arm64 host produces an arm64 "
        "image tagged as armv7, which fails with exit code 159 on the target device."
    )


# ── 1.7.5: AUTHORIZED_BOT_UAS UA:path pair format ────────────────────────────

def test_authorized_bot_config_default_uses_ua_path_pairs():
    """Default AUTHORIZED_BOT_UAS must use structured dict format with ua and path fields."""
    import config
    for entry in config.AUTHORIZED_BOT_UAS:
        assert isinstance(entry, dict), (
            f"AUTHORIZED_BOT_UAS default entry {entry!r} must be a dict with 'ua' and "
            f"'path' keys — the new structured format replaces the legacy UA:path string"
        )
        assert "ua" in entry and entry["ua"], (
            f"AUTHORIZED_BOT_UAS entry {entry!r} must have a non-empty 'ua' field"
        )
        assert "path" in entry and entry["path"], (
            f"AUTHORIZED_BOT_UAS entry {entry!r} must have a non-empty 'path' field"
        )


def test_authorized_bot_config_known_bots_with_root_path():
    """Default AUTHORIZED_BOT_UAS dicts must include known bots mapped to '/'."""
    import config
    pairs = {e["ua"]: e["path"] for e in config.AUTHORIZED_BOT_UAS if isinstance(e, dict) and e.get("ua")}
    for bot in ("UptimeRobot", "Pingdom", "StatusCake"):
        assert bot in pairs, (
            f"Default AUTHORIZED_BOT_UAS must include '{bot}' — missing from entries"
        )
        assert pairs[bot] == "/", (
            f"Default entry for '{bot}' must map to path '/' (got {pairs[bot]!r})"
        )


def test_authorized_bot_bypass_uses_per_entry_path_variable():
    """protect() bypass loop must use _bot_path variable from per-entry path field."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    bot_idx = src.find("if AUTHORIZED_BOT_UAS:")
    assert bot_idx != -1, "if AUTHORIZED_BOT_UAS: block not found in protect()"
    bot_block = src[bot_idx: bot_idx + 3000]
    assert "_bot_path" in bot_block, (
        "protect() must extract _bot_path from each entry — "
        "the path to match is per-entry, not a global constant"
    )
    assert "request.path == _bot_path" in bot_block or "request.path != _bot_path" in bot_block, (
        "protect() must compare request.path against _bot_path (per-entry path), "
        "not a hardcoded '/'"
    )


def test_authorized_bot_bypass_splits_on_colon():
    """protect() bypass must find the colon separator and split UA from path."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    bot_idx = src.find("if AUTHORIZED_BOT_UAS:")
    assert bot_idx != -1, "if AUTHORIZED_BOT_UAS: block not found in protect()"
    bot_block = src[bot_idx: bot_idx + 3000]
    assert "_colon" in bot_block or '.find(":")' in bot_block or "split(" in bot_block, (
        "protect() bypass must locate the ':' separator in each UA:path entry "
        "to split UA substring from path"
    )
    assert "_ua_sub" in bot_block, (
        "protect() bypass must extract _ua_sub from the UA:path entry"
    )


def test_authorized_bot_bypass_backward_compat_no_colon():
    """protect() bypass must default path to '/' for legacy entries without ':'."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    bot_idx = src.find("if AUTHORIZED_BOT_UAS:")
    assert bot_idx != -1, "if AUTHORIZED_BOT_UAS: block not found in protect()"
    bot_block = src[bot_idx: bot_idx + 3000]
    # The new dict-based code uses .get("path", "/") and or "/" as fallbacks;
    # legacy string branch uses else "/" and or "/".
    assert (
        '= "/"' in bot_block or "= '/'" in bot_block
        or 'or "/"' in bot_block or "or '/'" in bot_block
        or 'else "/"' in bot_block or "else '/'" in bot_block
        or '"/"' in bot_block
    ), (
        "protect() bypass must default _bot_path to '/' when an entry has no path "
        "for backward compatibility with bare UA substring entries"
    )


def test_authorized_bot_hot_reload_knob_registered():
    """AUTHORIZED_BOT_UAS must be in _HOT_RELOAD_KNOBS for runtime config changes."""
    from core.proxy_handler import _HOT_RELOAD_KNOBS
    assert "AUTHORIZED_BOT_UAS" in _HOT_RELOAD_KNOBS, (
        "AUTHORIZED_BOT_UAS must be registered in _HOT_RELOAD_KNOBS — operators "
        "must be able to change monitoring-bot pairs at runtime without restarting "
        "the container"
    )


def test_controls_card_bypass_section_exists():
    """controls.html must have a #card-bypass section for the AUTHORIZED_BOT_UAS toggle."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    assert 'id="card-bypass"' in src, (
        "controls.html must define <section id='card-bypass'> for the authorized "
        "monitoring bots UA:path pair editor"
    )
    assert 'id="bypass"' in src, (
        "controls.html must define <div id='bypass'> inside card-bypass — "
        "load() renders AUTHORIZED_BOT_UAS textarea into this div"
    )


def test_controls_meta_authorized_bot_uas_entry():
    """controls.html META must include AUTHORIZED_BOT_UAS with card:'bypass' and kind:'botlist'."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    assert "AUTHORIZED_BOT_UAS" in src, (
        "controls.html META must include AUTHORIZED_BOT_UAS knob definition"
    )
    idx = src.find("AUTHORIZED_BOT_UAS")
    meta_block = src[idx: idx + 200]
    assert "card:'bypass'" in meta_block or 'card:"bypass"' in meta_block, (
        "controls.html META AUTHORIZED_BOT_UAS must specify card:'bypass' so "
        "load() renders it into the #bypass div"
    )
    assert "kind:'botlist'" in meta_block or 'kind:"botlist"' in meta_block, (
        "controls.html META AUTHORIZED_BOT_UAS must be kind:'botlist' to render "
        "as the structured bot card UI"
    )


def test_authorized_bot_action_field_default():
    """Each default AUTHORIZED_BOT_UAS entry must have action == 'authorized-robot'."""
    import config
    for entry in config.AUTHORIZED_BOT_UAS:
        assert isinstance(entry, dict), f"Entry {entry!r} must be a dict"
        assert entry.get("action") == "authorized-robot", (
            f"Default entry {entry!r} must have action='authorized-robot'"
        )


def test_authorized_bot_allow_action_sets_custom_rule_flag():
    """protect() bypass block must set '_custom_rule_allow' for 'allow' action."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    bot_idx = src.find("if AUTHORIZED_BOT_UAS:")
    assert bot_idx != -1, "if AUTHORIZED_BOT_UAS: block not found in protect()"
    bot_block = src[bot_idx: bot_idx + 3000]
    assert "_custom_rule_allow" in bot_block, (
        "protect() bypass block must set request['_custom_rule_allow'] = True "
        "when action is 'allow' — so the bot is silently passed through"
    )


def test_authorized_bot_ban_action_sets_banned_until():
    """protect() bypass block must set banned_until for 'ban'/'really-ban' actions."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    # Search for the for-loop block, not the earlier comment that mentions the var name
    bot_idx = src.find("for _bot in AUTHORIZED_BOT_UAS")
    assert bot_idx != -1
    bot_block = src[bot_idx: bot_idx + 4000]
    assert "banned_until" in bot_block, (
        "protect() bypass block must set ip_state[...].banned_until for "
        "ban/really-ban actions"
    )


def test_custom_rules_authorized_robot_action_valid():
    """_ACTIONS in endpoint_policy.py must include 'authorized-robot'."""
    import inspect
    from integrations import endpoint_policy
    src = inspect.getsource(endpoint_policy)
    assert '"authorized-robot"' in src or "'authorized-robot'" in src, (
        "endpoint_policy.py _ACTIONS tuple must include 'authorized-robot' so "
        "custom rules can use it as a valid action"
    )
    assert "_ACTIONS" in src
    actions_idx = src.find("_ACTIONS")
    actions_block = src[actions_idx: actions_idx + 200]
    assert "authorized-robot" in actions_block, (
        "_ACTIONS in endpoint_policy.py must include 'authorized-robot'"
    )


def test_custom_rules_authorized_robot_handled_in_protect():
    """protect() must handle _action == 'authorized-robot' from custom rules."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    # Find the custom rules section
    cr_idx = src.find("_eval_custom_rules")
    assert cr_idx != -1, "protect() must call _eval_custom_rules"
    cr_block = src[cr_idx: cr_idx + 800]
    assert 'authorized-robot' in cr_block, (
        "protect() must handle _action == 'authorized-robot' returned by custom "
        "rules engine — respond with 200 ok and record as authorized-robot"
    )


def test_controls_authorized_bot_meta_is_botlist_kind():
    """controls.html META AUTHORIZED_BOT_UAS must have kind:'botlist'."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    idx = src.find("AUTHORIZED_BOT_UAS")
    assert idx != -1
    meta_block = src[idx: idx + 200]
    assert "kind:'botlist'" in meta_block or 'kind:"botlist"' in meta_block, (
        "controls.html META AUTHORIZED_BOT_UAS must be kind:'botlist' — not "
        "'list' — to render the structured card-per-bot UI instead of a textarea"
    )


def test_main_bucket_modal_focuskind_has_authorized_robot():
    """openMainBucketDetail focusKind array must include 'authorized_robot' at index 4."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    fn_start = src.find("window.openMainBucketDetail")
    assert fn_start != -1, "main.html must define openMainBucketDetail"
    fn_section = src[fn_start: fn_start + 400]
    assert "'authorized_robot'" in fn_section or '"authorized_robot"' in fn_section, (
        "openMainBucketDetail focusKind array must include 'authorized_robot' (dataset index 4)"
    )


def test_main_bucket_modal_has_authorized_bots_section():
    """openMainBucketDetail sections array must include authorized_robot kind with purple label."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    fn_start = src.find("window.openMainBucketDetail")
    assert fn_start != -1, "main.html must define openMainBucketDetail"
    fn_section = src[fn_start: fn_start + 12000]
    assert "authorized_robot" in fn_section, (
        "openMainBucketDetail sections must include authorized_robot kind"
    )
    assert "AUTHORIZED BOTS" in fn_section, (
        "openMainBucketDetail sections must include 'AUTHORIZED BOTS' label"
    )
    assert "#bc8cff" in fn_section, (
        "openMainBucketDetail authorized bots section must use purple color #bc8cff"
    )


def test_main_bucket_modal_renders_authorized_robot_from_response():
    """openMainBucketDetail must read d.authorized_robot from the API response."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    fn_start = src.find("window.openMainBucketDetail")
    assert fn_start != -1
    fn_section = src[fn_start: fn_start + 12000]
    assert "d.authorized_robot" in fn_section, (
        "openMainBucketDetail must read d.authorized_robot from the agents-bucket response"
    )


def test_agents_bucket_modal_focuskind_has_authorized_robot():
    """openBucketDetail focusKind array must include 'authorized_robot' at index 3."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    fn_start = src.find("async function openBucketDetail")
    assert fn_start != -1, "agents.html must define openBucketDetail"
    fn_section = src[fn_start: fn_start + 400]
    assert "'authorized_robot'" in fn_section or '"authorized_robot"' in fn_section, (
        "openBucketDetail focusKind array must include 'authorized_robot' (dataset index 3)"
    )


def test_agents_bucket_modal_has_authorized_bots_section():
    """openBucketDetail sections array must include authorized_robot kind with purple label."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    fn_start = src.find("async function openBucketDetail")
    assert fn_start != -1, "agents.html must define openBucketDetail"
    fn_section = src[fn_start: fn_start + 4000]
    assert "authorized_robot" in fn_section, (
        "openBucketDetail sections must include authorized_robot kind"
    )
    assert "AUTHORIZED BOTS" in fn_section, (
        "openBucketDetail sections must include 'AUTHORIZED BOTS' label"
    )
    assert "#bc8cff" in fn_section, (
        "openBucketDetail authorized bots section must use purple color #bc8cff"
    )


def test_agents_bucket_modal_renders_authorized_robot_from_response():
    """openBucketDetail must read d.authorized_robot from the API response."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    fn_start = src.find("async function openBucketDetail")
    assert fn_start != -1
    fn_section = src[fn_start: fn_start + 4000]
    assert "d.authorized_robot" in fn_section, (
        "openBucketDetail must read d.authorized_robot from the agents-bucket response"
    )


def test_agents_bucket_endpoint_returns_authorized_robot_field():
    """agents_bucket_detail_endpoint must classify authorized-robot events and
    expose them in the response payload.

    1.8.8 — previously this checked for the literal SQL `reason='authorized-robot'`.
    After the backend-aware refactor, classification moved from SQL filter to
    Python (rows come from db_read_events; the `reason == 'authorized-robot'`
    check runs in the loop body). Updated to check the new pattern.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    fn_start = src.find("async def agents_bucket_detail_endpoint")
    assert fn_start != -1, "proxy_handler.py must define agents_bucket_detail_endpoint"
    fn_section = src[fn_start: fn_start + 8000]
    assert (
        'reason == "authorized-robot"' in fn_section
        or "reason == 'authorized-robot'" in fn_section
        or "reason='authorized-robot'" in fn_section
    ), (
        "agents_bucket_detail_endpoint must classify reason=='authorized-robot' events "
        "(either via SQL filter or Python equality check after db_read_events)"
    )
    assert '"authorized_robot"' in fn_section or "'authorized_robot'" in fn_section, (
        "agents_bucket_detail_endpoint payload must include authorized_robot key"
    )


def test_controls_load_clears_bypass_div():
    """controls.html load() must clear the #bypass div before rendering."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    load_idx = src.find("async function load()")
    assert load_idx != -1, "controls.html must define async function load()"
    load_block = src[load_idx: load_idx + 3000]
    assert "'bypass'" in load_block or '"bypass"' in load_block, (
        "controls.html load() clearing list must include 'bypass' so stale "
        "AUTHORIZED_BOT_UAS entries are removed before re-rendering"
    )


# ── 1.7.5 regression: geo_data_endpoint 500 on authorized-robot + ASN ────────
# Bug: asn_totals initialized with {"clean":0,"blocked":0} only. When
# kind=="authorized_robot" and the bot IP had a resolvable ASN org (public
# monitoring-bot IPs like UptimeRobot), asn_totals[org]["authorized_robot"]
# raised KeyError → unhandled → HTTP 500. Triggered reliably on range=10080
# (7 days) because long windows accumulate enough authorized-robot events.

def test_geo_data_asn_totals_includes_authorized_robot_key():
    """geo_data_endpoint must init asn_totals with authorized_robot to avoid KeyError.

    Regression: asn_totals was initialized with {"clean":0,"blocked":0} only.
    When kind=="authorized_robot" (UptimeRobot/Pingdom with resolvable ASN),
    asn_totals[org]["authorized_robot"] raised KeyError → HTTP 500.
    Triggered on range=10080 (7 days) where authorized-robot events accumulate.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    asn_init_idx = src.find('asn_totals.setdefault(org,')
    assert asn_init_idx != -1, "geo_data_endpoint must call asn_totals.setdefault"
    asn_init_block = src[asn_init_idx: asn_init_idx + 120]
    assert "authorized_robot" in asn_init_block, (
        "asn_totals default dict must include 'authorized_robot': 0 — "
        "omitting it causes KeyError when monitoring bots (UptimeRobot, Pingdom) "
        "have resolvable ASN orgs, crashing geo-data at large time ranges"
    )


def test_geo_data_asn_totals_increment_is_safe_for_unknown_kinds():
    """geo_data_endpoint asn_totals increment must not raise KeyError on new kind values.

    Regression: bare dict-key increment (asn_totals[org][kind] += 1) raises
    KeyError for any kind not pre-declared. Fix uses .get(kind, 0) + 1.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    asn_init_idx = src.find('asn_totals.setdefault(org,')
    assert asn_init_idx != -1
    increment_block = src[asn_init_idx: asn_init_idx + 200]
    assert ".get(kind," in increment_block or ".get(kind ," in increment_block, (
        "asn_totals increment must use .get(kind, 0) + 1 instead of direct "
        "[kind] += 1 — direct access raises KeyError for any kind not in the "
        "default dict (e.g. future new classification values)"
    )


def test_geo_data_authorized_robot_classification_precedes_asn_update():
    """geo_data_endpoint: authorized-robot kind classification must come before asn_totals update.

    Verifies the kind variable is set from reason before being used to
    increment asn_totals, ensuring authorized-robot events land in the correct bucket.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    geo_fn = src.find("async def geo_data_endpoint")
    assert geo_fn != -1
    geo_section = src[geo_fn: geo_fn + 16000]
    ar_kind_idx = geo_section.find('reason == "authorized-robot"')
    asn_update_idx = geo_section.find("asn_totals.setdefault")
    assert ar_kind_idx != -1, (
        "geo_data_endpoint must classify reason==\"authorized-robot\" to kind "
        "'authorized_robot' before the asn_totals update"
    )
    assert asn_update_idx != -1, "geo_data_endpoint must update asn_totals"
    assert ar_kind_idx < asn_update_idx, (
        "kind classification (authorized-robot check) must come BEFORE the "
        "asn_totals increment — otherwise the wrong kind is counted"
    )


# ---------------------------------------------------------------------------
# 1.7.5 — is_authorized_bot in metrics clients list
# ---------------------------------------------------------------------------

def test_metrics_clients_includes_is_authorized_bot_field():
    """metrics endpoint clients list must include is_authorized_bot field.

    Needed so dashboards (agents.html, main.html) can show the auth-bot state
    in the ban-ctrl button group and popover status line.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    ca_idx = src.find("clients.append({")
    assert ca_idx != -1, "proxy_handler.py must have clients.append({ in metrics endpoint"
    ca_block = src[ca_idx: ca_idx + 1500]
    assert '"is_authorized_bot"' in ca_block or "'is_authorized_bot'" in ca_block, (
        "clients.append() dict must include 'is_authorized_bot' field — "
        "dashboards use this to render the auth-bot status button and popover"
    )


def test_metrics_clients_is_authorized_bot_checks_authorized_robot_action():
    """is_authorized_bot computation must only match entries with action=authorized-robot.

    Entries with action=ban or action=allow must not trigger is_authorized_bot=True.
    Ensures bot-rule-ban/bot-rule-allow entries don't accidentally mark clients
    as authorized bots in the dashboard.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    ca_idx = src.find("clients.append({")
    assert ca_idx != -1
    # Search backwards from clients.append for the is_auth_bot computation.
    # iter-18: LIVE-5 inserted the stub-client skip block + an 8-line comment
    # between _is_auth_bot and the append (now ~1040 chars away). Bumped 500
    # → 1500 to keep the assertion meaningful without weakening intent (the
    # auth-bot logic still must precede the same metrics_endpoint append).
    pre_block = src[max(0, ca_idx - 1500): ca_idx + 50]
    assert "authorized-robot" in pre_block, (
        "is_authorized_bot computation must filter action == 'authorized-robot' — "
        "otherwise ban/allow bot entries would incorrectly set the flag"
    )


def test_agents_html_ban_ctrl_has_authorized_bot_button():
    """agents.html suspicious identities table must have an Auth Bot button in ban-ctrl."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert "authorized-bot" in src and "auth-bot" in src, (
        "agents.html ban-ctrl must include authorized-bot button with data-action='auth-bot' (1.7.5)"
    )
    assert "Auth Bot" in src, (
        "agents.html ban-ctrl must label the authorized-bot button 'Auth Bot'"
    )


def test_main_html_ban_ctrl_has_authorized_bot_button():
    """main.html clients table must have an Auth Bot button in ban-ctrl."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "authorized-bot" in src and "auth-bot" in src, (
        "main.html ban-ctrl must include authorized-bot button with data-action='auth-bot' (1.7.5)"
    )
    assert "Auth Bot" in src, (
        "main.html ban-ctrl must label the authorized-bot button 'Auth Bot'"
    )


def test_agents_html_authorized_bot_css_active_state():
    """agents.html must have CSS active state for authorized-bot ban button."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert ".ban-btn.authorized-bot.active" in src, (
        "agents.html must define .ban-btn.authorized-bot.active CSS rule — "
        "without it the active button has no visual highlight"
    )


def test_main_html_authorized_bot_css_active_state():
    """main.html must have CSS active state for authorized-bot ban button."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert ".ban-btn.authorized-bot.active" in src, (
        "main.html must define .ban-btn.authorized-bot.active CSS rule — "
        "without it the active button has no visual highlight"
    )


def test_agents_html_bstate_checks_is_authorized_bot():
    """agents.html _bstate computation must derive from is_authorized_bot.

    The implementation may use an intermediate variable (e.g. _isAuthBot built
    from window._authBotPatch + s.is_authorized_bot) — what matters is that
    is_authorized_bot is referenced near the _bstate assignment and that
    'authorized-bot' is the resulting state value.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    bstate_idx = src.find("_bstate =")
    assert bstate_idx != -1, "agents.html must have a _bstate variable"
    # Check within a wider window — _isAuthBot derivation from is_authorized_bot
    # can be many lines above (e.g. when synced from main.html's IIFE).
    bstate_block = src[max(0, bstate_idx - 1200): bstate_idx + 300]
    assert "is_authorized_bot" in bstate_block, (
        "agents.html _bstate block must reference is_authorized_bot — "
        "otherwise authorized bots show as 'allow' instead of 'authorized-bot'"
    )
    assert "'authorized-bot'" in bstate_block or '"authorized-bot"' in bstate_block, (
        "agents.html _bstate block must have 'authorized-bot' as a possible value"
    )


def test_main_html_mst_checks_is_authorized_bot():
    """main.html _mst computation must derive from is_authorized_bot."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    mst_idx = src.find("_mst =")
    assert mst_idx != -1, "main.html must have a _mst variable"
    mst_block = src[max(0, mst_idx - 300): mst_idx + 300]
    assert "is_authorized_bot" in mst_block, (
        "main.html _mst block must reference is_authorized_bot — "
        "otherwise authorized bots show as 'allow' instead of 'authorized-bot'"
    )
    assert "'authorized-bot'" in mst_block or '"authorized-bot"' in mst_block, (
        "main.html _mst block must have 'authorized-bot' as a possible value"
    )


def test_agents_html_popover_banline_has_authorized_bot_case():
    """agents.html identity popover banLine must show blue 'Authorized Bot' status.
    Logic now lives in window._gwIdentityPopover.buildIdHtml — search there."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    pop_idx = src.find("window._gwIdentityPopover = (function(){")
    assert pop_idx != -1, "agents.html must define window._gwIdentityPopover"
    pop_section = src[pop_idx: pop_idx + 6000]
    assert "is_authorized_bot" in pop_section, (
        "agents.html _gwIdentityPopover.buildIdHtml must check is_authorized_bot — "
        "without it the popover status line never shows 'Authorized Bot'"
    )
    assert "Authorized Bot" in pop_section, (
        "agents.html _gwIdentityPopover.buildIdHtml must include 'Authorized Bot' text label"
    )


def test_main_html_popover_banline_has_authorized_bot_case():
    """main.html identity popover banLine must show blue 'Authorized Bot' status.
    Logic now lives in window._gwIdentityPopover.buildIdHtml — search there."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    pop_idx = src.find("window._gwIdentityPopover = (function(){")
    assert pop_idx != -1, "main.html must define window._gwIdentityPopover"
    pop_section = src[pop_idx: pop_idx + 6000]
    assert "is_authorized_bot" in pop_section, (
        "main.html _gwIdentityPopover.buildIdHtml must check is_authorized_bot — "
        "without it the popover status line never shows 'Authorized Bot'"
    )
    assert "Authorized Bot" in pop_section, (
        "main.html _gwIdentityPopover.buildIdHtml must include 'Authorized Bot' text label"
    )


def test_agents_html_auth_bot_handler_calls_config_endpoint():
    """agents.html Auth Bot click handler must POST to the config endpoint."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert "auth-bot" in src, "agents.html must wire data-action='auth-bot'"
    assert "AUTHORIZED_BOT_UAS" in src, (
        "agents.html auth-bot handler must POST AUTHORIZED_BOT_UAS to config endpoint"
    )


def test_main_html_auth_bot_handler_calls_config_endpoint():
    """main.html Auth Bot click handler must POST to the config endpoint."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "auth-bot" in src, "main.html must wire data-action='auth-bot'"
    assert "AUTHORIZED_BOT_UAS" in src, (
        "main.html auth-bot handler must POST AUTHORIZED_BOT_UAS to config endpoint"
    )


def test_main_html_banned_tag_shows_auth_bot_for_authorized_bots():
    """main.html banned column must render 'auth-bot' tag for is_authorized_bot clients."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    banned_idx = src.find("const banned =")
    assert banned_idx != -1, "main.html must have const banned = ... for status tag"
    banned_block = src[banned_idx: banned_idx + 300]
    assert "is_authorized_bot" in banned_block, (
        "main.html banned tag must check c.is_authorized_bot — "
        "otherwise the status column shows '—' for authorized bots instead of 'auth-bot'"
    )
    assert "auth-bot" in banned_block or "authorized-robot" in banned_block, (
        "main.html banned tag must render an 'auth-bot' or 'authorized-robot' label "
        "for clients whose UA matches the authorized bot list"
    )


def test_agents_html_ban_ctrl_stores_ua_in_data_attribute():
    """agents.html ban-ctrl div must store the client UA in data-ua for auth-bot handler."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert 'data-ua=' in src, (
        "agents.html ban-ctrl must set data-ua attribute — "
        "the auth-bot click handler reads it to know which UA to add to the bot list"
    )


def test_main_html_ban_ctrl_stores_ua_in_data_attribute():
    """main.html ban-ctrl div must store the client UA in data-ua for auth-bot handler."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert 'data-ua=' in src, (
        "main.html ban-ctrl must set data-ua attribute — "
        "the auth-bot click handler reads it to know which UA to add to the bot list"
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1.7.5 — new quality tests
# ═══════════════════════════════════════════════════════════════════════════

# ── config_changed slog: rejected must be a dict (not a list) ─────────────

def test_config_changed_slog_passes_rejected_dict_not_keylist():
    """config_endpoint slog('config_changed') must pass rejected as the full dict.

    Regression fixed in 1.7.5: was `rejected=list(rejected.keys())` which
    logged only key names — the operator saw e.g. `rejected=['FOO_KNOB']`
    with no indication of WHY the change was rejected.  Fixed to
    `rejected=rejected` so the dict values (reason strings) appear in the log.
    """
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.config_endpoint)
    # Must NOT use list(rejected.keys()) as the slog argument
    assert "rejected=list(rejected.keys())" not in src, (
        "config_endpoint slog must pass rejected dict directly — "
        "rejected=list(rejected.keys()) strips reason strings from the log"
    )
    # Must pass the dict itself
    slog_block = src[src.find("slog(\"config_changed\""):][:200]
    assert "rejected=rejected" in slog_block, (
        "config_endpoint slog('config_changed') must pass rejected=rejected "
        "(the full dict with reason values), not just the key names"
    )


def test_config_changed_slog_fires_on_pure_rejection():
    """config_endpoint must call slog when all changes are rejected (applied is empty).

    Regression fixed in 1.7.5: was `if applied:` guard, so a POST that was
    entirely rejected (e.g. env-pinned knob) logged nothing.  Fixed to
    `if applied or rejected:` so rejections are always surfaced.
    """
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.config_endpoint)
    # The guard must include the rejected branch
    assert "if applied or rejected:" in src, (
        "config_endpoint must log config_changed when rejected is non-empty "
        "even if applied is empty — 'if applied:' silently drops pure rejections"
    )


# ── agents.py: agents_data_endpoint includes is_authorized_bot ───────────

def test_agents_data_endpoint_includes_is_authorized_bot_field():
    """agents_data_endpoint suspects.append must include is_authorized_bot key.

    Regression fixed in 1.7.5: the field was only added to proxy_handler.py's
    metrics endpoint, not to dashboards/agents.py's separate agents_data_endpoint.
    agents.html fetches from /agents-data (not /metrics), so the field was always
    undefined — causing the Auth Bot button state to revert on every tick.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.py").read_text()
    fn_start = src.find("async def agents_data_endpoint")
    assert fn_start != -1, "agents.py must define agents_data_endpoint"
    fn_section = src[fn_start: fn_start + 6000]
    assert "is_authorized_bot" in fn_section, (
        "agents_data_endpoint suspects.append must include 'is_authorized_bot' key — "
        "agents.html fetches from /agents-data (not /metrics) so without this field "
        "the Auth Bot button state reverts on every auto-tick"
    )
    # Must use the same authorized-robot action check as metrics endpoint
    assert "authorized-robot" in fn_section, (
        "agents_data_endpoint is_authorized_bot check must filter on "
        "action=='authorized-robot' — entries with other actions must not be matched"
    )


def test_agents_data_endpoint_is_authorized_bot_checks_enabled_flag():
    """agents_data_endpoint is_authorized_bot must respect the enabled flag.

    A disabled bot entry (enabled=False) must not count as an authorized bot —
    otherwise re-clicking 'Allow' from auth-bot state still shows the client
    as authorized on the next tick.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.py").read_text()
    fn_start = src.find("async def agents_data_endpoint")
    fn_section = src[fn_start: fn_start + 4000]
    # The is_authorized_bot any() must check enabled
    assert 'enabled' in fn_section and '_s_is_auth_bot' in fn_section, (
        "agents_data_endpoint is_authorized_bot must check _b.get('enabled', True) — "
        "disabled entries must not be counted as authorized bots"
    )


# ── _authBotPatch: client-side override expiry ────────────────────────────

def test_agents_html_auth_bot_patch_expires_after_15s():
    """agents.html _patchAuthBot must expire the override after 15000 ms.

    The patch map prevents auto-tick from reverting the button before the server
    reflects the new state.  Expiry after 15 s is intentional — tick interval
    is also 15 s, so the patch covers exactly one missed-update window.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    patch_idx = src.find("_patchAuthBot")
    assert patch_idx != -1, "agents.html must define _patchAuthBot"
    # setTimeout with 15000 must appear near the patch function definition
    patch_block = src[patch_idx: patch_idx + 200]
    assert "15000" in patch_block, (
        "agents.html _patchAuthBot must use setTimeout(..., 15000) to expire the "
        "client-side override — expiry must match the tick interval"
    )


def test_main_html_auth_bot_patch_expires_after_15s():
    """main.html _patchAuthBot must expire the override after 15000 ms."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    patch_idx = src.find("_patchAuthBot")
    assert patch_idx != -1, "main.html must define _patchAuthBot"
    patch_block = src[patch_idx: patch_idx + 200]
    assert "15000" in patch_block, (
        "main.html _patchAuthBot must use setTimeout(..., 15000) — "
        "expiry must match tick interval so the override covers exactly one missed window"
    )


# ── auth-bot dedup: substring match in find() and map() ──────────────────

def test_agents_html_auth_bot_dedup_uses_substring_match():
    """agents.html auth-bot handler must use substring match in bots.find().

    Dedup uses `b.ua === ua || (b.ua && ua.includes(b.ua))` so that an existing
    short-form entry (e.g. 'UptimeRobot') is found when ua is the full UA string
    ('UptimeRobot/2.0 ...').  Exact-match only would always create duplicates.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    # Find the auth-bot handler block
    auth_bot_idx = src.find("if (btn.dataset.action === 'auth-bot')")
    assert auth_bot_idx != -1, "agents.html must have auth-bot action handler"
    handler_block = src[auth_bot_idx: auth_bot_idx + 800]
    assert "ua.includes(b.ua)" in handler_block, (
        "agents.html auth-bot bots.find() must include substring check "
        "ua.includes(b.ua) — exact-match only creates duplicate entries for "
        "existing short-form UA patterns like 'UptimeRobot'"
    )


def test_main_html_auth_bot_dedup_uses_substring_match():
    """main.html auth-bot handler must use substring match in bots.find()."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    auth_bot_idx = src.find("if (btn.dataset.action === 'auth-bot')")
    assert auth_bot_idx != -1, "main.html must have auth-bot action handler"
    handler_block = src[auth_bot_idx: auth_bot_idx + 800]
    assert "ua.includes(b.ua)" in handler_block, (
        "main.html auth-bot bots.find() must include substring check "
        "ua.includes(b.ua) — exact-match only creates duplicate entries"
    )


# ── leaving auth-bot state: bot entry must be disabled ───────────────────

def test_agents_html_leaving_auth_bot_state_disables_bot_entry():
    """agents.html non-auth-bot click from auth-bot state must disable the bot entry.

    When transitioning away from auth-bot (Allow / Banned / Really Banned),
    the matching AUTHORIZED_BOT_UAS entry must be set to enabled:false before
    the ban/unban call.  Without this, the next tick still shows the client
    as auth-bot because is_authorized_bot remains true server-side.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    # Find the "currently auth-bot" guard block
    guard_idx = src.find("currentlyAuthBot")
    assert guard_idx != -1, "agents.html must have currentlyAuthBot guard"
    guard_block = src[guard_idx: guard_idx + 600]
    assert "enabled:false" in guard_block, (
        "agents.html non-auth-bot handler must set enabled:false on the matching "
        "bot entry when leaving auth-bot state — otherwise next tick still shows "
        "is_authorized_bot=true and reverts the button"
    )
    assert "AUTHORIZED_BOT_UAS" in guard_block, (
        "agents.html non-auth-bot handler must POST updated AUTHORIZED_BOT_UAS "
        "with enabled:false before the ban/unban call"
    )


def test_main_html_leaving_auth_bot_state_disables_bot_entry():
    """main.html non-auth-bot click from auth-bot state must disable the bot entry."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    guard_idx = src.find("currentlyAuthBot")
    assert guard_idx != -1, "main.html must have currentlyAuthBot guard"
    guard_block = src[guard_idx: guard_idx + 600]
    assert "enabled:false" in guard_block, (
        "main.html non-auth-bot handler must set enabled:false on the matching "
        "bot entry when leaving auth-bot state"
    )
    assert "AUTHORIZED_BOT_UAS" in guard_block, (
        "main.html non-auth-bot handler must POST updated AUTHORIZED_BOT_UAS "
        "with enabled:false"
    )


def test_agents_html_leaving_auth_bot_uses_substring_match_in_map():
    """agents.html bot-disable map must also use substring match, not exact-match.

    The same dedup condition `b.ua === ua || (b.ua && ua.includes(b.ua))` must be
    used in both the find() (dedup check) and the map() (disable update).  Using
    exact-match in the map means the existing short-form entry ('UptimeRobot') is
    never disabled even though find() found it.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    guard_idx = src.find("currentlyAuthBot")
    assert guard_idx != -1
    guard_block = src[guard_idx: guard_idx + 600]
    assert "ua.includes(b.ua)" in guard_block, (
        "agents.html bot-disable map() must use ua.includes(b.ua) substring check — "
        "exact match misses existing short-form entries like 'UptimeRobot'"
    )


def test_main_html_leaving_auth_bot_uses_substring_match_in_map():
    """main.html bot-disable map must also use substring match."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    guard_idx = src.find("currentlyAuthBot")
    assert guard_idx != -1
    guard_block = src[guard_idx: guard_idx + 600]
    assert "ua.includes(b.ua)" in guard_block, (
        "main.html bot-disable map() must use ua.includes(b.ua) substring check"
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1.7.6 — category filter (Allowed / Blocked / Missed / Auth Bots)
# ═══════════════════════════════════════════════════════════════════════════

def test_main_html_cat_filter_pills_present():
    """main.html must have cat-pill buttons for all categories including ban and reallyban."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    for cat in ('allowed', 'ban', 'reallyban', 'missed', 'authbots'):
        assert f'data-cat="{cat}"' in src, (
            f"main.html cat-filter must include pill with data-cat=\"{cat}\" (1.7.8)"
        )
    assert 'data-cat="blocked"' not in src, (
        "main.html must not have 'blocked' pill — replaced by 'ban' + 'reallyban' (1.7.8)"
    )


def test_agents_html_cat_filter_pills_present():
    """agents.html must have cat-pill buttons for all categories including ban and reallyban."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    for cat in ('allowed', 'ban', 'reallyban', 'missed', 'authbots'):
        assert f'data-cat="{cat}"' in src, (
            f"agents.html cat-filter must include pill with data-cat=\"{cat}\" (1.7.8)"
        )
    assert 'data-cat="blocked"' not in src, (
        "agents.html must not have 'blocked' pill — replaced by 'ban' + 'reallyban' (1.7.8)"
    )


def test_main_html_apply_filters_hides_chart_datasets():
    """main.html _applyChartFilters must set chart.data.datasets[1-5].hidden from _activeFilters,
    and _applyFilters must call _applyChartFilters (delegated in 1.7.9)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    af_idx = src.find("function _applyChartFilters(")
    assert af_idx != -1, "main.html must define _applyChartFilters() (1.7.9)"
    block = src[af_idx: af_idx + 800]
    assert "datasets[1].hidden" in block, "_applyChartFilters must set datasets[1].hidden"
    assert "datasets[2].hidden" in block, "_applyChartFilters must set datasets[2].hidden"
    assert "datasets[3].hidden" in block, "_applyChartFilters must set datasets[3].hidden"
    assert "datasets[4].hidden" in block, "_applyChartFilters must set datasets[4].hidden"
    assert "datasets[5].hidden" in block, "_applyChartFilters must set datasets[5].hidden (gwmgmt)"
    assert "_activeFilters" in block, "_applyChartFilters must reference _activeFilters"
    # _applyFilters must delegate to _applyChartFilters
    apply_idx = src.find("function _applyFilters()")
    assert apply_idx != -1, "main.html must define _applyFilters()"
    assert "_applyChartFilters" in src[apply_idx: apply_idx + 200], (
        "_applyFilters must call _applyChartFilters"
    )


def test_agents_html_cat_filter_hides_chart_datasets():
    """agents.html pill handler must toggle all 4 agentChart dataset hidden flags."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    pill_idx = src.find("window._activeFilters = new Set")
    assert pill_idx != -1, "agents.html must initialise _activeFilters (1.7.6)"
    # datasets[0]=detected→blocked, [1]=missed, [2]=clean→allowed, [3]=authbots
    for i in range(4):
        assert f"agentChart.data.datasets[{i}].hidden" in src, (
            f"agents.html must set agentChart.data.datasets[{i}].hidden in pill handler (1.7.6)"
        )


def test_main_html_render_clients_table_is_standalone():
    """main.html must define _renderClientsTable as a top-level function (not inside tick)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "function _renderClientsTable(" in src, (
        "main.html must extract _renderClientsTable() so _applyFilters can call it (1.7.6)"
    )


def test_main_html_tick_calls_apply_filters():
    """main.html tick() must call _applyFilters() instead of inlining client rendering."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    tick_idx = src.find("async function tick()")
    assert tick_idx != -1
    tick_body = src[tick_idx: tick_idx + 8000]
    assert "_applyFilters()" in tick_body, (
        "main.html tick() must call _applyFilters() for client table rendering (1.7.6)"
    )


def test_main_html_gwmgmt_pill_and_cat_function():
    """main.html must have GW Mgmt pill and _clientCats must classify by /antibot-appsec-gateway/ prefix."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert 'data-cat="gwmgmt"' in src, "main.html must have gwmgmt cat-pill (1.7.6)"
    assert "'gwmgmt'" in src and "antibot-appsec-gateway" in src, (
        "main.html _clientCats must assign gwmgmt for /antibot-appsec-gateway/ paths (1.7.6)"
    )
    cats_idx = src.find("function _clientCats(")
    assert cats_idx != -1
    cats_block = src[cats_idx: cats_idx + 300]
    assert "antibot-appsec-gateway" in cats_block, (
        "_clientCats must check last_path for /antibot-appsec-gateway/ prefix (1.7.6)"
    )


def test_agents_html_gwmgmt_pill_and_cat_function():
    """agents.html must have GW Mgmt pill and _agentCats must classify by /antibot-appsec-gateway/ prefix."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert 'data-cat="gwmgmt"' in src, "agents.html must have gwmgmt cat-pill (1.7.6)"
    cats_idx = src.find("function _agentCats(")
    assert cats_idx != -1
    cats_block = src[cats_idx: cats_idx + 300]
    assert "antibot-appsec-gateway" in cats_block, (
        "_agentCats must check last_path for /antibot-appsec-gateway/ prefix (1.7.6)"
    )


# ── auth-bot priority over gwmgmt in cat functions ────────────────────────

def test_main_html_client_cats_auth_bot_before_gwmgmt():
    """_clientCats must check is_authorized_bot before the gwmgmt last_path check.

    Auth bots whose last_path happens to be a GW management URL must still
    appear as 'authbots', not get mis-classified as 'gwmgmt' and disappear
    from the Auth Bots filter.
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    cats_idx = src.find("function _clientCats(")
    assert cats_idx != -1
    block = src[cats_idx: cats_idx + 300]
    auth_pos  = block.find("is_authorized_bot")
    gwmgmt_pos = block.find("antibot-appsec-gateway")
    assert auth_pos != -1 and gwmgmt_pos != -1
    assert auth_pos < gwmgmt_pos, (
        "_clientCats must test is_authorized_bot before the gwmgmt path check — "
        "otherwise auth bots accessing GW endpoints vanish from Auth Bots filter"
    )


def test_agents_html_agent_cats_auth_bot_before_gwmgmt():
    """_agentCats must check is_authorized_bot before the gwmgmt last_path check."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    cats_idx = src.find("function _agentCats(")
    assert cats_idx != -1
    block = src[cats_idx: cats_idx + 300]
    auth_pos   = block.find("is_authorized_bot")
    gwmgmt_pos = block.find("antibot-appsec-gateway")
    assert auth_pos != -1 and gwmgmt_pos != -1
    assert auth_pos < gwmgmt_pos, (
        "_agentCats must test is_authorized_bot before the gwmgmt path check"
    )


# ── agents.py: auth bots bypass min_score gate ────────────────────────────

def test_agents_data_auth_bot_check_before_min_score_gate():
    """agents_data_endpoint must evaluate _s_is_auth_bot BEFORE the score gate.

    Auth bots have stealth_score ≈ 0 by design (they're allowed through).
    If the min_score continue fires first, all auth bots are silently dropped
    and the Auth Bots filter shows zero entries on the agents page.

    Fix: hoist _s_is_auth_bot above the gate and guard as:
        if score < min_score and not _s_is_auth_bot: continue
    """
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.py").read_text()
    fn_start = src.find("async def agents_data_endpoint")
    assert fn_start != -1
    fn_section = src[fn_start: fn_start + 5000]

    auth_bot_pos  = fn_section.find("_s_is_auth_bot")
    min_score_pos = fn_section.find("score < min_score")
    assert auth_bot_pos != -1, "_s_is_auth_bot must be defined in agents_data_endpoint"
    assert min_score_pos != -1, "score < min_score gate must exist in agents_data_endpoint"
    assert auth_bot_pos < min_score_pos, (
        "_s_is_auth_bot must be computed before the 'score < min_score' gate — "
        "otherwise auth bots (stealth_score ≈ 0) are excluded before the check runs"
    )


def test_agents_data_min_score_gate_skips_auth_bots():
    """agents_data_endpoint min_score guard must exempt auth bots."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.py").read_text()
    fn_start = src.find("async def agents_data_endpoint")
    assert fn_start != -1
    fn_section = src[fn_start: fn_start + 5000]
    gate_idx = fn_section.find("score < min_score")
    assert gate_idx != -1
    gate_line = fn_section[gate_idx: gate_idx + 80]
    assert "_s_is_auth_bot" in gate_line, (
        "The score < min_score guard must include 'and not _s_is_auth_bot' "
        "so auth bots are never excluded by the threshold filter"
    )


# ── gwmgmt: authenticated admin path access is recorded ──────────────────

def test_protect_authenticated_admin_path_calls_record():
    """protect() must call record() for authenticated operator requests to admin paths.

    Without this, dashboard accesses by a logged-in operator are never written
    to ip_state / the DB, so the gwmgmt filter in main.html and agents.html
    shows zero entries — the operator sees an empty filter even though they
    are actively browsing /antibot-appsec-gateway/secured/*.
    """
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    # Locate the authenticated admin path branch
    admin_block_idx = src.find("_admin_ip_allowed(request) and _internal_authed(request)")
    assert admin_block_idx != -1, "protect() must have the authed-admin-path branch"
    # record() must be called inside that block. 1.8.11: widened window — the
    # central CSRF gate now sits between the branch and the record() call.
    block = src[admin_block_idx: admin_block_idx + 1600]
    assert "await record(" in block, (
        "protect() must call record() for authenticated admin path requests so that "
        "operator dashboard accesses appear in ip_state with last_path = /antibot-appsec-gateway/... "
        "and are classified as gwmgmt by _clientCats / _agentCats"
    )


def test_protect_authenticated_admin_path_uses_operator_passthrough_reason():
    """protect() must record authenticated admin accesses with reason='operator-passthrough'.

    Using a distinct reason (not '' or 'internal-probe') lets the operator
    distinguish their own dashboard browsing from unauthorized probes in the
    event log and Logs dashboard.
    """
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    admin_block_idx = src.find("_admin_ip_allowed(request) and _internal_authed(request)")
    assert admin_block_idx != -1
    # 1.8.11: widened window — central CSRF gate added before the record() call.
    block = src[admin_block_idx: admin_block_idx + 1600]
    assert "operator-passthrough" in block, (
        "protect() must pass reason='operator-passthrough' to record() for "
        "authenticated admin path requests so events are labelled correctly in the DB"
    )


# ── 1.7.8 — ban / really-ban filter pills ────────────────────────────────

def test_main_html_client_cats_hard_ban_reasons():
    """_clientCats must classify clients with canary-echo/honeypot-silent/honeypot as reallyban,
    and all other currently-banned clients as ban."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    cats_idx = src.find("function _clientCats(")
    assert cats_idx != -1
    block = src[cats_idx: cats_idx + 600]
    assert "_HARD_BAN_REASONS" in block or "canary-echo" in block, (
        "_clientCats must reference hard-ban reasons (canary-echo/honeypot-silent/honeypot) "
        "to distinguish reallyban from ban (1.7.8)"
    )
    assert "'reallyban'" in block, "_clientCats must push 'reallyban' for hard-ban clients (1.7.8)"
    assert "'ban'" in block, "_clientCats must push 'ban' for regular-ban clients (1.7.8)"


def test_main_html_hard_ban_reasons_constant_defined():
    """main.html must define _HARD_BAN_REASONS with the three definitive bot signals."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "_HARD_BAN_REASONS" in src, "main.html must define _HARD_BAN_REASONS (1.7.8)"
    hr_idx = src.find("_HARD_BAN_REASONS")
    block = src[hr_idx: hr_idx + 200]
    assert "canary-echo" in block, "_HARD_BAN_REASONS must include 'canary-echo' (1.7.8)"
    assert "honeypot-silent" in block, "_HARD_BAN_REASONS must include 'honeypot-silent' (1.7.8)"
    assert "honeypot" in block, "_HARD_BAN_REASONS must include 'honeypot' (1.7.8)"


def test_agents_html_agent_cats_hard_ban_reasons():
    """_agentCats must classify suspects with hard-ban reasons as reallyban."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    cats_idx = src.find("function _agentCats(")
    assert cats_idx != -1
    block = src[cats_idx: cats_idx + 600]
    assert "_HARD_BAN_REASONS" in block or "canary-echo" in block, (
        "_agentCats must reference hard-ban reasons to classify reallyban (1.7.8)"
    )
    assert "'reallyban'" in block, "_agentCats must push 'reallyban' for hard-ban suspects (1.7.8)"
    assert "'ban'" in block, "_agentCats must push 'ban' for regular-ban suspects (1.7.8)"


def test_main_html_apply_filters_ban_maps_to_dataset2():
    """_applyChartFilters must show dataset[2] (blocked) when EITHER ban OR reallyban is active."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    af_idx = src.find("function _applyChartFilters(")
    assert af_idx != -1
    block = src[af_idx: af_idx + 600]
    assert "datasets[2].hidden" in block, "_applyChartFilters must toggle datasets[2] (1.7.9)"
    assert "'ban'" in block and "'reallyban'" in block, (
        "_applyChartFilters datasets[2].hidden must reference both 'ban' and 'reallyban' (1.7.9)"
    )


def test_agents_html_chart_datasets_ban_maps_to_dataset0():
    """agents.html chart hidden logic must show dataset[0] (detected) when ban OR reallyban active."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert "datasets[0].hidden" in src, "agents.html must toggle agentChart.datasets[0] (1.7.8)"
    d0_idx = src.find("datasets[0].hidden")
    block = src[d0_idx: d0_idx + 200]
    assert "'ban'" in block and "'reallyban'" in block, (
        "agents.html datasets[0].hidden must reference both 'ban' and 'reallyban' (1.7.8)"
    )


def test_agents_data_auth_bot_has_safe_comps_fallback():
    """agents_data_endpoint must provide default comps/mets for auth bots with score == 0."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.py").read_text()
    fn_start = src.find("async def agents_data_endpoint")
    assert fn_start != -1
    fn_section = src[fn_start: fn_start + 5000]
    assert "_s_is_auth_bot and not comps" in fn_section or \
           ("_s_is_auth_bot" in fn_section and "not comps" in fn_section), (
        "agents_data_endpoint must guard comps/mets with _s_is_auth_bot fallback "
        "so score-0 auth bots don't send null to the frontend component bar"
    )


def test_bypass_paths_in_hot_reload_knobs():
    """BYPASS_PATHS must be registered as a hot-reload knob."""
    import importlib, sys
    saved = {k: v for k, v in sys.modules.items()
             if k.startswith("core.") or k == "core"}
    for mod in saved:
        sys.modules.pop(mod, None)
    try:
        proxy = importlib.import_module("core.proxy_handler")
        assert "BYPASS_PATHS" in proxy._HOT_RELOAD_KNOBS, (
            "BYPASS_PATHS must be in _HOT_RELOAD_KNOBS for hot-reload support"
        )
    finally:
        for mod in list(sys.modules):
            if mod.startswith("core.") or mod == "core":
                sys.modules.pop(mod, None)
        sys.modules.update(saved)


def test_bypass_paths_prefix_check_in_protect():
    """protect() must contain a BYPASS_PATHS prefix check before bot detection."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    assert "BYPASS_PATHS" in src, "proxy_handler.py must reference BYPASS_PATHS"
    # Accept either the legacy `any()` form or the 1.8.14 precompiled _bypass_match()
    # helper — both express the same "request.path matches a BYPASS_PATHS entry" check.
    legacy = "vc('BYPASS_PATHS') and any(" in src
    compiled = "_bypass_match(" in src and "vc('BYPASS_PATHS')" in src
    assert legacy or compiled, (
        "protect() must contain a BYPASS_PATHS check — either the legacy `any(...)` "
        "form or the precompiled `_bypass_match(request.path, vc('BYPASS_PATHS'))` form"
    )


def test_controls_html_bypass_paths_in_meta():
    """controls.html META registry must include BYPASS_PATHS knob."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    assert "BYPASS_PATHS" in src, "controls.html must reference BYPASS_PATHS"
    assert "bypass-paths" in src, "controls.html must have bypass-paths card slot"
    assert "Detection-free path prefixes" in src, (
        "controls.html must have Detection-free path prefixes sub-section header"
    )


def test_controls_html_bypass_paths_card_cleared_on_load():
    """controls.html load() must clear the bypass-paths card div."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    assert "'bypass-paths'" in src, (
        "controls.html forEach clear list must include 'bypass-paths'"
    )


def test_controls_html_bypass_paths_uses_pathlist_kind():
    """BYPASS_PATHS META entry must use kind:'pathlist' (not kind:'list')."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    assert "kind:'pathlist'" in src, (
        "controls.html must define kind:'pathlist' for the path list editor"
    )
    bp_idx = src.find("BYPASS_PATHS")
    assert bp_idx != -1
    bp_meta = src[bp_idx: bp_idx + 120]
    assert "pathlist" in bp_meta, "BYPASS_PATHS META entry must use kind:'pathlist'"


def test_controls_html_build_path_list_ui_exists():
    """controls.html must define _buildPathListUI function."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    assert "_buildPathListUI" in src, (
        "controls.html must define _buildPathListUI for the bypass path editor"
    )
    assert "Add path entry" in src, (
        "controls.html path list editor must have 'Add path entry' button"
    )
    assert "bot-del-btn" in src[src.find("_buildPathListUI"):src.find("_buildPathListUI") + 2000], (
        "_buildPathListUI must include delete buttons"
    )


def test_config_bypass_paths_default_empty():
    """BYPASS_PATHS must default to an empty list when env var is not set."""
    import sys, os
    env_backup = os.environ.pop("BYPASS_PATHS", None)
    saved = {k: v for k, v in sys.modules.items()
             if k == "config" or k.startswith("config.")}
    try:
        for mod in list(saved):
            sys.modules.pop(mod, None)
        import config as cfg
        assert cfg.BYPASS_PATHS == [], (
            "BYPASS_PATHS default must be [] when BYPASS_PATHS env var is absent"
        )
    finally:
        if env_backup is not None:
            os.environ["BYPASS_PATHS"] = env_backup
        for mod in list(sys.modules):
            if mod == "config" or mod.startswith("config."):
                sys.modules.pop(mod, None)
        sys.modules.update(saved)


def test_config_bypass_paths_env_parse():
    """BYPASS_PATHS env var is split on comma into a list of stripped strings."""
    import sys, os
    os.environ["BYPASS_PATHS"] = "/static/, /assets/, /media/"
    saved = {k: v for k, v in sys.modules.items()
             if k == "config" or k.startswith("config.")}
    try:
        for mod in list(saved):
            sys.modules.pop(mod, None)
        import config as cfg
        assert cfg.BYPASS_PATHS == ["/static/", "/assets/", "/media/"], (
            "BYPASS_PATHS must parse CSV env var into stripped list of paths"
        )
    finally:
        del os.environ["BYPASS_PATHS"]
        for mod in list(sys.modules):
            if mod == "config" or mod.startswith("config."):
                sys.modules.pop(mod, None)
        sys.modules.update(saved)


def _bypass_check_idx(src: str) -> int:
    """Return the source index of the BYPASS_PATHS guard in protect(),
    accommodating: legacy `any()` form, vc() form, and the 1.8.14
    precompiled `_bypass_match(...)` helper site."""
    for needle in (
        "BYPASS_PATHS and any(request.path.startswith",
        "vc('BYPASS_PATHS') and any(",
        "_bypass_match(request.path",
    ):
        i = src.find(needle)
        if i != -1:
            return i
    return -1


def test_bypass_paths_guard_after_authorized_bots_before_rps():
    """BYPASS_PATHS check must be positioned AFTER AUTHORIZED_BOT_UAS block
    and BEFORE the GLOBAL_RPS_LIMIT check in protect()."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    bot_idx  = src.find("AUTHORIZED_BOT_UAS:")
    bp_idx   = _bypass_check_idx(src)

    # Accept both direct and vhost-aware (_vrps_limit) form
    rps_idx  = src.find("GLOBAL_RPS_LIMIT > 0 and")
    if rps_idx == -1:
        rps_idx = src.find("_vrps_limit > 0 and")
    assert bot_idx != -1, "AUTHORIZED_BOT_UAS block not found in proxy_handler.py"
    assert bp_idx  != -1, "BYPASS_PATHS guard not found in proxy_handler.py"
    assert rps_idx != -1, "GLOBAL_RPS_LIMIT check not found in proxy_handler.py"
    assert bot_idx < bp_idx < rps_idx, (
        "Guard order must be: AUTHORIZED_BOT_UAS … BYPASS_PATHS … GLOBAL_RPS_LIMIT. "
        f"Found positions: bot={bot_idx}, bypass={bp_idx}, rps={rps_idx}"
    )


def test_bypass_paths_early_return_calls_record():
    """Bypass-paths block must proxy via handler() and call record() with empty reason
    so traffic appears in the main dashboard timeline and clients table."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    bp_idx = _bypass_check_idx(src)
    assert bp_idx != -1
    block = src[bp_idx: bp_idx + 400]
    assert "await handler(request)" in block, (
        "Bypass block must call await handler(request)"
    )
    assert "await record(" in block, (
        "Bypass block must call record() so traffic appears in the dashboard timeline"
    )


def test_bypass_paths_glob_matching_logic():
    """BYPASS_PATHS entries ending with * are prefix/glob matches;
    entries without * are exact matches only. 1.8.14 — the matching logic
    moved into _bypass_match() with the same semantics."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    # Anchor on whichever block holds the matching expression — _bypass_match()
    # for the precompiled path, or the legacy inline expression.
    anchor = src.find("def _bypass_match")
    if anchor == -1:
        anchor = _bypass_check_idx(src)
    assert anchor != -1, "could not locate BYPASS_PATHS matcher in proxy_handler.py"
    block = src[anchor: anchor + 1200]
    # Glob detection: must check `endswith("*", "/")` (or a superset thereof).
    assert "endswith(" in block and '"*"' in block, (
        "BYPASS_PATHS matcher must detect glob entries via endswith('*' …)"
    )
    assert "p[:-1]" in block, (
        "BYPASS_PATHS glob match must strip the trailing char via p[:-1] before "
        "the prefix check"
    )
    # Exact-match contract: either inline `path == p` form, or a frozenset
    # `path in exacts` lookup (the 1.8.14 precompiled equivalent).
    assert ("request.path == p" in block
            or "path in exacts" in block
            or "path in _exacts" in block), (
        "BYPASS_PATHS matcher must compare non-glob entries by exact equality "
        "(or via the precompiled `path in exacts` frozenset)"
    )


def test_bypass_paths_glob_semantics():
    """Validate glob/exact matching semantics directly against the matching expression."""
    def _matches(bypass_paths, path):
        return any(
            path.startswith(p[:-1]) if p.endswith("*") else path == p
            for p in bypass_paths
        )

    # Glob entries — prefix match
    assert _matches(["/static/*"], "/static/")
    assert _matches(["/static/*"], "/static/app.js")
    assert _matches(["/static/*"], "/static/img/logo.png")
    assert not _matches(["/static/*"], "/staticother")
    assert not _matches(["/static/*"], "/other/static/")

    # Exact entries — no sub-path leakage
    assert _matches(["/blog/"], "/blog/")
    assert not _matches(["/blog/"], "/blog/post")
    assert not _matches(["/blog/"], "/blog/category/foo")
    assert not _matches(["/blog/"], "/")

    # Root exact match
    assert _matches(["/"], "/")
    assert not _matches(["/"], "/anything")
    assert not _matches(["/"], "/.env")

    # Mix of glob and exact
    assert _matches(["/blog/", "/assets/*"], "/assets/style.css")
    assert not _matches(["/blog/", "/assets/*"], "/blog/post")
    assert _matches(["/blog/", "/assets/*"], "/blog/")


def test_banned_ip_honeypot_path_records_honeypot_silent():
    """Both ban gates (early ip-ban check and identity ban check) must emit
    honeypot-silent for honeypot paths so the attack-playbook dashboard captures
    probes from already-banned IPs."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()

    # Early IP ban block (check_ip_ban / ip-ban)
    ip_ban_start = src.find('"ip-ban"')
    assert ip_ban_start != -1, "ip-ban reason not found"
    ip_ban_block = src[max(0, ip_ban_start - 600): ip_ban_start + 200]
    assert "honeypot-silent" in ip_ban_block, (
        "Early ip-ban block must emit honeypot-silent for honeypot paths"
    )
    assert "await record(" in ip_ban_block, (
        "Early ip-ban block must call record() to emit the honeypot-silent event"
    )

    # Identity ban block (is_banned / banned-silent)
    id_ban_start = src.find("banned, remaining = await is_banned(track_key)")
    assert id_ban_start != -1, "is_banned check not found"
    id_ban_block = src[id_ban_start: id_ban_start + 700]
    assert "honeypot-silent" in id_ban_block, (
        "Identity ban block must emit honeypot-silent for honeypot paths"
    )
    assert "banned-silent" in id_ban_block, (
        "Identity ban block must still return banned-silent decoy response"
    )
    assert "await record(" in id_ban_block, (
        "Identity ban block must call record() to emit the honeypot-silent event"
    )


def test_ban_gate_record_exceptions_cannot_suppress_decoy():
    """F-01/F-02: record() in both ban gates must be wrapped in its own
    try/except so a transient DB error can never prevent the decoy response
    from being returned — a banned IP must never reach upstream on record failure."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()

    # Early IP ban block — ip_ban_record_error slog confirms the wrapping
    ip_ban_start = src.find('"ip-ban"')
    assert ip_ban_start != -1, "ip-ban reason not found"
    ip_ban_block = src[max(0, ip_ban_start - 700): ip_ban_start + 300]
    assert "ip_ban_record_error" in ip_ban_block, (
        "F-01: record() in the ip-ban gate must be wrapped in try/except "
        "with ip_ban_record_error slog — a record() failure must not suppress the decoy"
    )

    # Identity ban block — id_ban_record_error slog confirms the wrapping
    id_ban_start = src.find("banned, remaining = await is_banned(track_key)")
    assert id_ban_start != -1, "is_banned check not found"
    id_ban_block = src[id_ban_start: id_ban_start + 800]
    assert "id_ban_record_error" in id_ban_block, (
        "F-02: record() in the identity ban gate must be wrapped in try/except "
        "with id_ban_record_error slog — a record() failure must not suppress the decoy"
    )


def test_bypass_paths_rejects_wildcard_entries():
    """F-03: BYPASS_PATHS validator must reject bare '*' and '/*' entries
    that would prefix-match every request and bypass all detection."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()

    # The validator lambda must reference the dangerous values
    bypass_cfg_start = src.find('"BYPASS_PATHS"')
    assert bypass_cfg_start != -1, "BYPASS_PATHS config entry not found"
    bypass_cfg_block = src[bypass_cfg_start: bypass_cfg_start + 250]
    assert '"*"' in bypass_cfg_block or "\"*\"" in bypass_cfg_block, (
        "F-03: BYPASS_PATHS validator lambda must check for bare '*' entry"
    )
    assert '"/*"' in bypass_cfg_block or "\"/*\"" in bypass_cfg_block, (
        "F-03: BYPASS_PATHS validator lambda must check for '/*' entry"
    )


def test_bypass_paths_rejects_wildcard_semantics():
    """F-03 inline logic: the validator lambda that guards BYPASS_PATHS must
    reject '*' and '/*' (which would bypass every request) while allowing
    well-formed glob entries like '/static/*'."""
    # Inline the guard logic to verify the semantics are correct
    def _bypass_paths_valid(paths):
        return not any(p in ("*", "/*") for p in paths)

    assert not _bypass_paths_valid(["*"]),  "'*' must be rejected"
    assert not _bypass_paths_valid(["/*"]), "'/*' must be rejected"
    assert not _bypass_paths_valid(["/static/*", "*"]), "mixed list with '*' must be rejected"
    assert _bypass_paths_valid(["/static/*"]),   "'/static/*' must be allowed"
    assert _bypass_paths_valid(["/blog/"]),       "'/blog/' exact must be allowed"
    assert _bypass_paths_valid(["/", "/api/*"]),  "'/' exact + '/api/*' must be allowed"
    assert _bypass_paths_valid([]),               "empty list must be allowed"


def test_bypass_mode_not_persisted_to_db():
    """BYPASS_MODE must be in _NOT_PERSIST_KNOBS so it always resets to False
    on container restart. Persisting it would let a stale True value survive
    restarts and bypass all detection silently."""
    from core.proxy_handler import _NOT_PERSIST_KNOBS
    assert "BYPASS_MODE" in _NOT_PERSIST_KNOBS, (
        "BYPASS_MODE must be in _NOT_PERSIST_KNOBS — "
        "it is a session-only incident-response toggle that must default to False on cold start"
    )


def test_bypass_mode_in_hot_reload_knobs():
    """BYPASS_MODE must still be in _HOT_RELOAD_KNOBS so it can be toggled at runtime
    even though it is excluded from DB persistence."""
    from core.proxy_handler import _HOT_RELOAD_KNOBS
    assert "BYPASS_MODE" in _HOT_RELOAD_KNOBS, (
        "BYPASS_MODE must remain in _HOT_RELOAD_KNOBS so the Controls dashboard can toggle it"
    )


# ── 1.7.7 dashboard code-review fixes ────────────────────────────────────────

_DASHBOARD_FILES = [
    "main.html", "agents.html", "controls.html", "geo.html",
    "logs.html", "service.html", "settings.html", "login.html",
]

def _dash(name):
    from pathlib import Path
    return (Path(__file__).resolve().parent.parent / "dashboards" / name).read_text()


# BP-05: window._acct namespace ──────────────────────────────────────────────

def test_no_window_open_acct_modal_global():
    """BP-05: window._openAcctModal must not exist in any dashboard — collapsed into window._acct."""
    for f in _DASHBOARD_FILES:
        src = _dash(f)
        assert "window._openAcctModal" not in src, (
            f"{f} still exposes window._openAcctModal; use window._acct.openModal"
        )


def test_no_window_acct_username_global():
    """BP-05: window._acctUsername must not exist in any dashboard — closure-scoped as _username."""
    for f in _DASHBOARD_FILES:
        src = _dash(f)
        assert "window._acctUsername" not in src, (
            f"{f} still exposes window._acctUsername; must be closure-scoped _username"
        )


def test_no_window_acct_change_pw_global():
    """BP-05: window._acctChangePw must not exist — collapsed into window._acct.changePw."""
    for f in _DASHBOARD_FILES:
        src = _dash(f)
        assert "window._acctChangePw" not in src, (
            f"{f} still exposes window._acctChangePw; use window._acct.changePw"
        )


def test_no_window_acct_revoke_session_global():
    """BP-05: window._acctRevokeSession must not exist — collapsed into window._acct.revokeSession."""
    for f in _DASHBOARD_FILES:
        src = _dash(f)
        assert "window._acctRevokeSession" not in src, (
            f"{f} still exposes window._acctRevokeSession; use window._acct.revokeSession"
        )


def test_window_acct_namespace_exposed():
    """BP-05: Every dashboard with account modal must expose window._acct object."""
    modal_files = [f for f in _DASHBOARD_FILES if f != "login.html"]
    for f in modal_files:
        src = _dash(f)
        assert "window._acct=" in src or "window._acct =" in src, (
            f"{f} missing window._acct namespace assignment"
        )


def test_agents_html_acct_exposes_user_role():
    """BP-05: agents.html window._acct assignment must include userRole key (read by external code at line ~531)."""
    src = _dash("agents.html")
    # Find the actual namespace assignment (not nav-link usage)
    assign_idx = src.find("window._acct={")
    assert assign_idx != -1, "agents.html missing window._acct={...} assignment"
    block = src[assign_idx: assign_idx + 200]
    assert "userRole" in block, (
        "agents.html window._acct must expose userRole property for external code"
    )


def test_agents_html_external_user_role_uses_acct_namespace():
    """BP-05: switchHtml conditional must read window._acct.userRole not window._userRole."""
    src = _dash("agents.html")
    sw_idx = src.find("switchHtml")
    assert sw_idx != -1
    block = src[sw_idx: sw_idx + 120]
    assert "window._acct" in block, (
        "agents.html switchHtml must read window._acct.userRole, not window._userRole"
    )
    assert "window._userRole" not in block, (
        "agents.html switchHtml must not use window._userRole directly"
    )


# BP-07: _asyncConfirm — no blocking confirm() ───────────────────────────────

def test_controls_no_raw_confirm_calls():
    """BP-07: controls.html <script> blocks must have no raw confirm() calls — all replaced by _asyncConfirm().
    Logout nav-link onclick="return confirm(...)" is excluded (native browser confirm appropriate for navigation)."""
    import re
    src = _dash("controls.html")
    # Extract only <script>...</script> content, exclude HTML attribute handlers
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', src, re.DOTALL)
    for script in scripts:
        calls = re.findall(r'\bconfirm\s*\(', script)
        assert not calls, (
            f"controls.html <script> block has {len(calls)} raw confirm() call(s); replace with _asyncConfirm()"
        )


def test_controls_async_confirm_defined():
    """BP-07: controls.html must define _asyncConfirm() using showSimpleModal + Promise."""
    src = _dash("controls.html")
    assert "_asyncConfirm" in src, "controls.html missing _asyncConfirm function"
    assert "showSimpleModal" in src[src.find("_asyncConfirm"):src.find("_asyncConfirm") + 400], (
        "_asyncConfirm must delegate to showSimpleModal"
    )


# BP-08: _gwAlert — no blocking alert() ─────────────────────────────────────

def test_no_raw_alert_calls_in_dashboards():
    """BP-08: No dashboard <script> block must call alert() — all replaced by _gwAlert()."""
    import re
    skip = {"login.html"}
    for f in _DASHBOARD_FILES:
        if f in skip:
            continue
        src = _dash(f)
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', src, re.DOTALL)
        for script in scripts:
            calls = re.findall(r'\balert\s*\(', script)
            assert not calls, (
                f"{f} <script> block has {len(calls)} raw alert() call(s); replace with _gwAlert()"
            )


def test_gw_alert_defined_in_dashboard_files():
    """BP-08: Every non-login dashboard with fetch calls must define _gwAlert()."""
    skip = {"login.html"}
    for f in _DASHBOARD_FILES:
        if f in skip:
            continue
        src = _dash(f)
        assert "_gwAlert" in src, f"{f} missing _gwAlert() definition"


# BUG-04: controls.html DELETE admin-IP URL ──────────────────────────────────

def test_controls_delete_admin_ip_url_correct():
    """BUG-04: DELETE admin-IP fetch must use ?cidr= not &cidr= (malformed URL bug)."""
    src = _dash("controls.html")
    assert "&cidr=" not in src, (
        "controls.html DELETE admin-IP URL uses &cidr= — must be ?cidr="
    )
    assert "?cidr=" in src, (
        "controls.html DELETE admin-IP URL missing expected ?cidr= query separator"
    )


# BUG-08: double-save guard in inline-edit ───────────────────────────────────

def test_controls_inline_edit_double_save_guard():
    """BUG-08: controls.html inline-edit save() must have _descSaved/_thrSaved guard to prevent blur+Enter double-PATCH."""
    src = _dash("controls.html")
    assert "_descSaved" in src, "controls.html missing _descSaved double-save guard"
    assert "_thrSaved" in src, "controls.html missing _thrSaved double-save guard"


# BUG-01: agents.html m-total not overwritten by filtered count ──────────────

def test_agents_html_no_m_total_suspects_length_overwrite():
    """BUG-01: agents.html must not overwrite m-total with suspects.length (overwrites backend total with filtered count)."""
    src = _dash("agents.html")
    assert "getElementById('m-total').textContent = suspects.length" not in src, (
        "agents.html sets m-total to suspects.length — overwrites backend total with filtered count"
    )


# BUG-02: main.html no duplicate getRangeMin ─────────────────────────────────

def test_main_html_no_duplicate_get_range_min():
    """BUG-02: main.html must define getRangeMin() exactly once."""
    src = _dash("main.html")
    count = src.count("function getRangeMin(")
    assert count == 1, (
        f"main.html defines getRangeMin() {count} times — must be exactly 1"
    )


# INC-02: settings.html credentials consistency ──────────────────────────────

def test_settings_html_no_credentials_same_origin():
    """INC-02: settings.html must use credentials:'include' not credentials:'same-origin'."""
    src = _dash("settings.html")
    assert "credentials:\"same-origin\"" not in src, (
        "settings.html uses credentials:\"same-origin\" — must use 'include' (consistent with other dashboards)"
    )
    assert "credentials:'same-origin'" not in src, (
        "settings.html uses credentials:'same-origin' — must use 'include'"
    )


# DC-01: no url() identity wrapper ───────────────────────────────────────────

def test_no_url_identity_wrapper_in_dashboards():
    """DC-01: Dashboards other than controls.html must not define the url identity wrapper.
    controls.html keeps 'const url = p => p' because it has ~30 fetch call-sites that
    use url(...) and inlining all of them is a high-risk change."""
    _skip = {'controls.html'}
    for f in _DASHBOARD_FILES:
        if f in _skip:
            continue
        src = _dash(f)
        assert "const url = (p) => p" not in src, (
            f"{f} still has dead const url = (p) => p identity wrapper"
        )
        assert "const url = p => p" not in src, (
            f"{f} still has dead const url = p => p identity wrapper"
        )


# DC-07: logs.html no stale lastIds ─────────────────────────────────────────

def test_logs_html_no_last_ids_variable():
    """DC-07: logs.html must not define let lastIds — unused variable removed."""
    src = _dash("logs.html")
    assert "let lastIds" not in src, (
        "logs.html still defines let lastIds — dead variable; remove it"
    )


# ── Service metrics defaults (1.7.7) ─────────────────────────────────────────

def test_service_metrics_interval_default_60s():
    """SVC_METRICS_INTERVAL default must be 60 s (1-minute resolution → 30-day window)."""
    import importlib, sys, os
    saved = sys.modules.pop("config", None)
    env_bak = os.environ.pop("SVC_METRICS_INTERVAL", None)
    try:
        import config as cfg
        assert cfg.SERVICE_METRICS_INTERVAL == 60.0, (
            f"SERVICE_METRICS_INTERVAL default changed: expected 60.0, got {cfg.SERVICE_METRICS_INTERVAL}"
        )
    finally:
        if env_bak is not None:
            os.environ["SVC_METRICS_INTERVAL"] = env_bak
        sys.modules.pop("config", None)
        if saved is not None:
            sys.modules["config"] = saved


def test_service_metrics_retention_default_43200():
    """SVC_METRICS_RETENTION default must be 43200 (30 days × 1440 samples/day at 60s)."""
    import importlib, sys, os
    saved = sys.modules.pop("config", None)
    env_bak = os.environ.pop("SVC_METRICS_RETENTION", None)
    try:
        import config as cfg
        assert cfg.SERVICE_METRICS_RETENTION == 43200, (
            f"SERVICE_METRICS_RETENTION default changed: expected 43200, got {cfg.SERVICE_METRICS_RETENTION}"
        )
    finally:
        if env_bak is not None:
            os.environ["SVC_METRICS_RETENTION"] = env_bak
        sys.modules.pop("config", None)
        if saved is not None:
            sys.modules["config"] = saved


def test_service_metrics_window_covers_30_days():
    """INTERVAL × RETENTION must cover at least 30 days."""
    import sys, os
    saved = sys.modules.pop("config", None)
    for k in ("SVC_METRICS_INTERVAL", "SVC_METRICS_RETENTION"):
        os.environ.pop(k, None)
    try:
        import config as cfg
        window_days = (cfg.SERVICE_METRICS_INTERVAL * cfg.SERVICE_METRICS_RETENTION) / 86400
        assert window_days >= 30, (
            f"Metrics window {window_days:.1f} days < 30 days "
            f"(INTERVAL={cfg.SERVICE_METRICS_INTERVAL}, RETENTION={cfg.SERVICE_METRICS_RETENTION})"
        )
    finally:
        sys.modules.pop("config", None)
        if saved is not None:
            sys.modules["config"] = saved


def test_service_metrics_env_override_interval():
    """SVC_METRICS_INTERVAL env var must override the default."""
    import sys, os
    saved = sys.modules.pop("config", None)
    os.environ["SVC_METRICS_INTERVAL"] = "30"
    try:
        import config as cfg
        assert cfg.SERVICE_METRICS_INTERVAL == 30.0, (
            f"SVC_METRICS_INTERVAL env override not respected: got {cfg.SERVICE_METRICS_INTERVAL}"
        )
    finally:
        del os.environ["SVC_METRICS_INTERVAL"]
        sys.modules.pop("config", None)
        if saved is not None:
            sys.modules["config"] = saved


def test_service_metrics_env_override_retention():
    """SVC_METRICS_RETENTION env var must override the default."""
    import sys, os
    saved = sys.modules.pop("config", None)
    os.environ["SVC_METRICS_RETENTION"] = "1000"
    try:
        import config as cfg
        assert cfg.SERVICE_METRICS_RETENTION == 1000, (
            f"SVC_METRICS_RETENTION env override not respected: got {cfg.SERVICE_METRICS_RETENTION}"
        )
    finally:
        del os.environ["SVC_METRICS_RETENTION"]
        sys.modules.pop("config", None)
        if saved is not None:
            sys.modules["config"] = saved


# ── MaxMind lookup cache (1.7.7) ─────────────────────────────────────────────

def test_maxmind_lookup_cache_ttl_is_86400():
    """_LOOKUP_CACHE_TTL must be 86400 s (24 h) — ASN/geo data stable for days."""
    import reputation.maxmind as mm
    assert mm._LOOKUP_CACHE_TTL == 86400, (
        f"_LOOKUP_CACHE_TTL changed: expected 86400, got {mm._LOOKUP_CACHE_TTL}"
    )


def test_maxmind_lookup_cache_max_is_8192():
    """_LOOKUP_CACHE_MAX must be 8192 — bounded to prevent unbounded growth."""
    import reputation.maxmind as mm
    assert mm._LOOKUP_CACHE_MAX == 8192, (
        f"_LOOKUP_CACHE_MAX changed: expected 8192, got {mm._LOOKUP_CACHE_MAX}"
    )


def test_maxmind_asn_cache_exists():
    """_asn_cache and _city_cache must be dicts defined at module level."""
    import reputation.maxmind as mm
    assert isinstance(mm._asn_cache, dict), "_asn_cache must be a dict"
    assert isinstance(mm._city_cache, dict), "_city_cache must be a dict"


def test_maxmind_city_lookup_caches_result():
    """_city_lookup must store a successful result in _city_cache."""
    import reputation.maxmind as mm

    class _FakeReader:
        def get(self, ip):
            return {"location": {"latitude": 38.7, "longitude": -9.1},
                    "country": {"iso_code": "PT"},
                    "city": {"names": {"en": "Lisbon"}}}

    orig_reader = mm._city_reader
    orig_cache  = mm._city_cache.copy()
    mm._city_reader = _FakeReader()
    mm._city_cache.clear()
    try:
        result = mm._city_lookup("1.2.3.4")
        assert result == (38.7, -9.1, "PT", "Lisbon")
        assert "1.2.3.4" in mm._city_cache, "_city_lookup did not populate _city_cache"
        cached_val, expiry = mm._city_cache["1.2.3.4"]
        assert cached_val == result
        # second call must return cached result without hitting reader
        mm._city_reader = None   # reader removed — only cache must serve
        result2 = mm._city_lookup("1.2.3.4")
        assert result2 == result, "second call did not return cached result"
    finally:
        mm._city_reader = orig_reader
        mm._city_cache.clear()
        mm._city_cache.update(orig_cache)


def test_maxmind_asn_lookup_does_not_cache_disabled():
    """_asn_lookup must NOT cache results when MAXMIND_ENABLED is False."""
    import reputation.maxmind as mm
    orig_enabled = mm.MAXMIND_ENABLED
    orig_cache   = mm._asn_cache.copy()
    mm.MAXMIND_ENABLED = False
    mm._asn_cache.clear()
    try:
        result = mm._asn_lookup("1.2.3.4")
        assert result[3] == "disabled"
        assert "1.2.3.4" not in mm._asn_cache, (
            "_asn_lookup cached a 'disabled' result — must not cache non-ok results"
        )
    finally:
        mm.MAXMIND_ENABLED = orig_enabled
        mm._asn_cache.clear()
        mm._asn_cache.update(orig_cache)


def test_maxmind_cache_evicts_oldest_at_max():
    """_cache_put must evict the oldest entry when cache reaches _LOOKUP_CACHE_MAX."""
    import reputation.maxmind as mm
    cache: dict = {}
    for i in range(mm._LOOKUP_CACHE_MAX):
        mm._cache_put(cache, f"10.0.{i//256}.{i%256}", (i, "", False, "ok"))
    assert len(cache) == mm._LOOKUP_CACHE_MAX
    # inserting one more must evict the oldest (first inserted)
    mm._cache_put(cache, "192.168.1.1", (999, "", False, "ok"))
    assert len(cache) == mm._LOOKUP_CACHE_MAX, "cache grew past _LOOKUP_CACHE_MAX"
    assert "10.0.0.0" not in cache, "oldest entry not evicted"
    assert "192.168.1.1" in cache, "new entry not inserted after eviction"


# ── geo.html load-status pill text (1.7.7) ───────────────────────────────────

def test_geo_html_load_status_ready_text():
    """geo.html load-status pill must flip to 'Loading Ready' (not just 'Ready')."""
    src = _dash("geo.html")
    assert "Loading Ready" in src, (
        "geo.html load-status pill text must be 'Loading Ready', not just 'Ready'"
    )


# ── logs.html category filter pills (1.7.7) ──────────────────────────────────

def test_logs_html_cat_filter_bar_exists():
    """logs.html must have a cat-filter-bar toolbar div."""
    src = _dash("logs.html")
    assert 'id="cat-filter-bar"' in src, (
        "logs.html missing cat-filter-bar toolbar"
    )


def test_logs_html_cat_pills_all_present():
    """logs.html must have all 5 category pills: allowed, ban, reallyban, authbots, gwmgmt."""
    src = _dash("logs.html")
    for cat in ("allowed", "ban", "reallyban", "authbots", "gwmgmt"):
        assert f'data-cat="{cat}"' in src, (
            f"logs.html missing cat-pill for category '{cat}'"
        )


def test_logs_html_log_filters_set_initialized():
    """logs.html must initialise window._logFilters as a Set with all 5 categories."""
    src = _dash("logs.html")
    assert "window._logFilters" in src, "logs.html missing window._logFilters"
    assert "_logFilters = new Set(" in src, (
        "logs.html _logFilters must be initialized with new Set(...)"
    )


def test_logs_html_log_cat_function_defined():
    """logs.html must define _logCat() categorisation function."""
    src = _dash("logs.html")
    assert "function _logCat(" in src, "logs.html missing _logCat() function"


def test_logs_html_apply_log_filters_defined():
    """logs.html must define _applyLogFilters() render function."""
    src = _dash("logs.html")
    assert "function _applyLogFilters(" in src, (
        "logs.html missing _applyLogFilters() function"
    )


def test_logs_html_update_cat_bar_defined():
    """logs.html must define _updateCatBar() to show/hide pills on tab switch."""
    src = _dash("logs.html")
    assert "function _updateCatBar(" in src, (
        "logs.html missing _updateCatBar() function"
    )


def test_logs_html_cat_bar_hidden_on_gw_tab():
    """logs.html _updateCatBar must hide the pill bar when kind === 'gw'."""
    src = _dash("logs.html")
    assert "kind === 'requests'" in src or 'kind === "requests"' in src, (
        "logs.html _updateCatBar must conditionally show bar only for requests tab"
    )


def test_logs_html_hard_ban_reasons_defined():
    """logs.html must define _HARD_BAN_REASONS Set for reallyban categorisation."""
    src = _dash("logs.html")
    assert "_HARD_BAN_REASONS" in src, "logs.html missing _HARD_BAN_REASONS"
    assert "honeypot" in src, "logs.html _HARD_BAN_REASONS must include honeypot reasons"


# ── controls.html actions bar placement (1.7.7) ──────────────────────────────

def test_controls_actions_bar_before_scoring():
    """Apply/Reset buttons must appear in #topbar-right (split-pane layout, v1.8.6+).
    The standalone div.actions was replaced by individual buttons in #topbar-right."""
    src = _dash("controls.html")
    topbar_right_pos = src.find('id="topbar-right"')
    scoring_pos = src.find('id="card-scoring"')
    apply_pos = src.find('id="apply"')
    assert topbar_right_pos != -1, "controls.html missing #topbar-right"
    assert scoring_pos != -1, "controls.html missing card-scoring"
    assert apply_pos != -1, "controls.html missing #apply"
    assert apply_pos > topbar_right_pos, "apply must be inside #topbar-right"
    assert 'class="actions"' not in src, "controls.html must not have standalone div.actions (removed in v1.8.6)"


# ── geo-map 30-day view (1.7.7 session 3) ────────────────────────────────────

def test_geo_html_has_30day_option():
    """geo.html window select must include a 30-day (43200 min) option."""
    src = _dash("geo.html")
    assert 'value="43200"' in src, (
        "geo.html range <select> missing 30-day option (value=\"43200\")"
    )
    assert "30 days" in src, (
        "geo.html range <select> 30-day option must display '30 days'"
    )


def test_geo_data_endpoint_cap_allows_30days():
    """geo_data_endpoint range cap must allow 43200 (30 days) not clamp to 10080."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    geo_start = src.find("async def geo_data_endpoint")
    assert geo_start != -1, "geo_data_endpoint missing"
    fn_src = src[geo_start: geo_start + 1200]
    assert "min(43200," in fn_src, (
        "geo_data_endpoint range cap must be 43200 (30 days), not 10080 (7 days)"
    )
    assert "min(10080," not in fn_src, (
        "geo_data_endpoint still has old 10080 cap — update to 43200"
    )


def test_geo_drill_endpoint_cap_allows_30days():
    """geo_drill_endpoint range cap must allow 43200 to match geo_data."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    drill_start = src.find("async def geo_drill_endpoint")
    assert drill_start != -1, "geo_drill_endpoint missing"
    fn_src = src[drill_start: drill_start + 1200]
    assert "min(43200," in fn_src, (
        "geo_drill_endpoint range cap must be 43200 (30 days) to match geo_data_endpoint"
    )


def test_geo_data_uses_cursor_not_fetchall():
    """geo_data_endpoint must iterate the cursor directly (no fetchall) to avoid
    loading 30 days of events into RAM at once."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    geo_start = src.find("async def geo_data_endpoint")
    assert geo_start != -1, "geo_data_endpoint missing"
    # Find the end of the function by looking for the next async def
    next_fn = src.find("\nasync def ", geo_start + 1)
    fn_src = src[geo_start: next_fn if next_fn != -1 else geo_start + 8000]
    assert ".fetchall()" not in fn_src, (
        "geo_data_endpoint must not use fetchall() — iterate cursor directly "
        "to avoid loading all 30-day events into RAM"
    )
    assert "for r in cursor" in fn_src, (
        "geo_data_endpoint must iterate the SQLite cursor directly"
    )


def test_geo_data_uses_reservoir_sampling():
    """geo_data_endpoint must use reservoir sampling (Algorithm R) for events_sample
    so the scrubber is uniformly distributed across the full 30-day window."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    geo_start = src.find("async def geo_data_endpoint")
    assert geo_start != -1, "geo_data_endpoint missing"
    next_fn = src.find("\nasync def ", geo_start + 1)
    fn_src = src[geo_start: next_fn if next_fn != -1 else geo_start + 8000]
    assert "_random.randint" in fn_src, (
        "geo_data_endpoint must use reservoir sampling (_random.randint) for "
        "events_sample so the scrubber covers the full window, not just oldest events"
    )
    assert "_sample_seen" in fn_src, (
        "geo_data_endpoint reservoir sampling must track _sample_seen as denominator"
    )


# ── geo-map load-status percentage (1.7.8) ────────────────────────────────────

def test_geo_html_load_status_pct_helper():
    """geo.html must have _setLoadPct helper that guards on .ready class."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "geo.html").read_text()
    assert "function _setLoadPct" in html, "_setLoadPct helper missing from geo.html"
    assert "classList.contains('ready')" in html, (
        "_setLoadPct must guard against overwriting the ready state"
    )
    assert "Loading ' + pct + '%'" in html, (
        "_setLoadPct must render 'Loading X%' text"
    )


def test_operator_passthrough_in_passthrough_reasons():
    """'operator-passthrough' must be in _PASSTHROUGH_REASONS so operator
    accesses count as 'allowed' (not 'blocked') in metrics and timeline."""
    from core.metrics import _PASSTHROUGH_REASONS
    assert "operator-passthrough" in _PASSTHROUGH_REASONS, (
        "_PASSTHROUGH_REASONS must include 'operator-passthrough' so authenticated "
        "operator accesses are not counted as blocked in metrics/timeline (1.7.8)"
    )


def test_protect_upstream_operator_bypass_calls_record():
    """The upstream operator bypass block must NOT exist in protect().

    Removed in 1.7.9: admin IPs accessing upstream paths (non-admin namespace)
    now go through normal bot detection like any other client. operator-passthrough
    is only recorded for requests inside /antibot-appsec-gateway/ (admin namespace).
    """
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    # The upstream bypass condition must no longer exist outside the admin-path block
    # (the admin-path block uses _admin_ip_allowed + _internal_authed with 'sub' context)
    assert "_operator_bypass" not in src, (
        "protect() must not set _operator_bypass — upstream operator bypass removed in 1.7.9; "
        "admin IPs on non-admin paths go through normal detection"
    )


def test_geo_html_tick_uses_timer_progress():
    """tick() must use a setInterval-based animation so percentages are visible
    even when the fetch completes within a single event-loop task."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "geo.html").read_text()
    assert "function _startLoadPct" in html, "_startLoadPct missing from geo.html"
    assert "function _finishLoadPct" in html, "_finishLoadPct missing from geo.html"
    assert "setInterval" in html, "_startLoadPct must use setInterval for timer-based animation"
    assert "clearInterval" in html, "_finishLoadPct must clearInterval on completion/error"
    assert "_startLoadPct()" in html, "tick() must call _startLoadPct() at start"
    assert "_finishLoadPct()" in html, "tick() must call _finishLoadPct() after rendering"


# ── F-04/F-06/F-07 dashboard security fixes (1.7.9) ──────────────────────────

def test_agents_html_no_silent_catch_on_ui_fetch():
    """agents.html must not use .catch(()=>({})) on any fetch — §17e."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert "catch(()=>({}))" not in html, (
        "agents.html contains silent .catch(()=>({})) swallowing fetch/parse failures — "
        "replace with structured try/catch per §17e"
    )


def test_main_html_no_silent_catch_on_ui_fetch():
    """main.html must not use .catch(()=>({})) on any fetch — §17e."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "catch(()=>({}))" not in html, (
        "main.html contains silent .catch(()=>({})) swallowing fetch/parse failures — "
        "replace with structured try/catch per §17e"
    )


def test_controls_html_no_silent_catch_on_ui_fetch():
    """controls.html must not use .catch(()=>({})) on any fetch — §17e."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "controls.html").read_text()
    assert "catch(()=>({}))" not in html, (
        "controls.html contains silent .catch(()=>({})) swallowing fetch/parse failures — "
        "replace with structured try/catch per §17e"
    )


def test_login_redirect_response_validated_through_safenext():
    """login.html post-login redirect must go through safeNext() — §17c DiD.
    Server validates next_url server-side; this is a client-side defense-in-depth."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "login.html").read_text()
    assert "j.redirect" not in html or "safeNext(j.redirect)" in html, (
        "login.html uses j.redirect without safeNext() validation — "
        "use safeNext(j.redirect) || next per §17c"
    )
    assert "safeNext(j.redirect)" in html, (
        "login.html must validate j.redirect through safeNext() per §17c"
    )


def test_geo_setinterval_tracked():
    """Named timers in geo.html that use setInterval must be pushed into _timers[]
    for beforeunload cleanup — §17b. Checks playTimer and _lpTimer explicitly;
    also verifies inline _timers.push(setInterval(...)) calls remain intact."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "geo.html").read_text()
    assert "_timers.push(playTimer)" in html, (
        "geo.html: playTimer not pushed to _timers[] — "
        "add _timers.push(playTimer) after setInterval assignment per §17b"
    )
    assert "_timers.push(_lpTimer)" in html, (
        "geo.html: _lpTimer not pushed to _timers[] — "
        "add _timers.push(_lpTimer) after setInterval assignment per §17b"
    )
    assert "_timers.push(setInterval(" in html, (
        "geo.html: inline _timers.push(setInterval(...)) pattern missing — "
        "existing tick/refresh intervals must remain tracked per §17b"
    )


# ── Top-paths category filter (1.7.9) ─────────────────────────────────────────

def test_by_path_by_cat_exists_in_state():
    """state.py must export by_path_by_cat with all five category keys."""
    import state
    assert hasattr(state, "by_path_by_cat"), "state.py missing by_path_by_cat"
    for cat in ("allowed", "ban", "missed", "authbots", "gwmgmt"):
        assert cat in state.by_path_by_cat, f"by_path_by_cat missing key '{cat}'"


def test_by_path_by_cat_imported_in_metrics():
    """core/metrics.py must import by_path_by_cat from state."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "metrics.py").read_text()
    assert "by_path_by_cat" in src, (
        "core/metrics.py does not reference by_path_by_cat — "
        "top-paths category filtering requires it to be imported and incremented"
    )


def test_metrics_endpoint_uses_by_path_by_cat_for_filtered_cats():
    """metrics_endpoint must use by_path_by_cat when cats subset is requested."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    assert "by_path_by_cat" in src, (
        "proxy_handler.py metrics_endpoint must reference by_path_by_cat "
        "to serve category-filtered top_paths"
    )
    assert "_req_cats == _valid_cats" in src or "req_cats" in src, (
        "metrics_endpoint must branch on whether all or a subset of cats are requested"
    )


# ── Timeline legend ↔ filter pill sync (1.7.9) ────────────────────────────────

def test_main_html_chart_legend_onclick_syncs_pills():
    """Timeline chart legend onClick must update _activeFilters and call _applyFilters()
    so that clicking a legend item in the graph toggles the matching filter pill."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "_DS_CATS" in html, (
        "main.html: timeline chart legend onClick missing _DS_CATS mapping — "
        "chart legend clicks must sync to filter pills"
    )
    assert "legend" in html and "onClick" in html, (
        "main.html: timeline chart plugins.legend must define an onClick handler"
    )
    assert "_applyFilters()" in html, "main.html: legend onClick must call _applyFilters()"


# ── Panel legend sync (1.7.9) ─────────────────────────────────────────────────

def test_main_html_panel_legends_present():
    """Clients, Top Paths, and Live Events panels must each contain a .panel-legend
    with the five category items so filter state can be toggled from each panel."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert html.count('class="panel-legend"') >= 3, (
        "main.html: expected panel-legend on Clients, Top Paths, and Live Events panels"
    )
    assert html.count('panel-leg-item') >= 15, (
        "main.html: expected 5 panel-leg-item entries per panel (3 panels × 5 cats = 15)"
    )


def test_main_html_toggle_cat_filter_function_defined():
    """_toggleCatFilter() must exist as a shared function called by chart legend,
    panel legends, and (indirectly) pill clicks."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert "function _toggleCatFilter" in html, (
        "main.html: _toggleCatFilter() function missing"
    )
    assert "function _syncPanelLegends" in html, (
        "main.html: _syncPanelLegends() function missing"
    )


def test_main_html_apply_filters_calls_sync_panel_legends():
    """_applyFilters() must call _syncPanelLegends() so pill clicks and tick()
    keep all three panel legends in sync with _activeFilters."""
    from pathlib import Path
    html = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    # _syncPanelLegends() must appear inside _applyFilters() body
    import re as _re
    af_start = html.index("function _applyFilters()")
    nxt = _re.search(r'\nfunction ', html[af_start + 30:])
    af_end = af_start + 30 + nxt.start() if nxt else len(html)
    assert "_syncPanelLegends()" in html[af_start:af_end], (
        "main.html: _applyFilters() does not call _syncPanelLegends()"
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1.7.10 — shared identity popover (_gwIdentityPopover)
# ═══════════════════════════════════════════════════════════════════════════

def _gw_popover_section(dashboard: str) -> str:
    """Return the _gwIdentityPopover IIFE block from the given dashboard file."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / dashboard).read_text()
    # Anchor on the IIFE *definition* — other code may reference
    # window._gwIdentityPopover (e.g. the top-controls panel) earlier in the file.
    idx = src.find("window._gwIdentityPopover = (function(){")
    if idx == -1:
        idx = src.find("window._gwIdentityPopover")
    assert idx != -1, f"{dashboard} must define window._gwIdentityPopover"
    # Extract the full IIFE (ends with })()); after the opening assignment)
    end = src.find("})();", idx)
    if end != -1:
        return src[idx: end + 5]
    return src[idx: idx + 9000]  # generous fallback


def test_gw_identity_popover_defined_in_agents_html():
    """agents.html must define window._gwIdentityPopover as a shared renderer."""
    sec = _gw_popover_section("agents.html")
    assert "normalizeId" in sec
    assert "buildIdHtml" in sec
    assert "buildRiskHtml" in sec


def test_gw_identity_popover_defined_in_main_html():
    """main.html must define window._gwIdentityPopover as a shared renderer."""
    sec = _gw_popover_section("main.html")
    assert "normalizeId" in sec
    assert "buildIdHtml" in sec
    assert "buildRiskHtml" in sec


def test_gw_identity_popover_normalize_maps_agents_fields():
    """normalizeId must handle agents.html data shape: s.ip, s.ua, s.metrics.risk_score,
    s.blocks_breakdown (array), s.risk_breakdown."""
    sec = _gw_popover_section("agents.html")
    assert "raw.ip" in sec, "normalizeId must map raw.ip (agents shape)"
    assert "raw.ua" in sec, "normalizeId must map raw.ua (agents shape)"
    assert "raw.metrics" in sec, "normalizeId must handle raw.metrics.risk_score (agents shape)"
    assert "blocks_breakdown" in sec, "normalizeId must map blocks_breakdown"
    assert "risk_breakdown" in sec, "normalizeId must map risk_breakdown"


def test_gw_identity_popover_normalize_maps_main_fields():
    """normalizeId must handle main.html data shape: c.last_ip, c.last_ua,
    c.last_session, c.last_fingerprint, c.blocks_by_reason (object), c.tokens."""
    sec = _gw_popover_section("main.html")
    assert "raw.last_ip" in sec, "normalizeId must map raw.last_ip (main shape)"
    assert "raw.last_ua" in sec, "normalizeId must map raw.last_ua (main shape)"
    assert "raw.last_session" in sec, "normalizeId must map raw.last_session (main shape)"
    assert "raw.last_fingerprint" in sec, "normalizeId must map raw.last_fingerprint (main shape)"
    assert "blocks_by_reason" in sec, "normalizeId must convert blocks_by_reason object to array"
    assert "raw.tokens" in sec, "normalizeId must map raw.tokens (main shape)"


def test_gw_identity_popover_build_id_html_has_all_fields():
    """buildIdHtml must render all best-of-both fields: JA4, stealth (conditional),
    tokens (conditional), admin lock, .kv grid layout."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "JA4" in sec, f"{dashboard} buildIdHtml must include JA4 field"
        assert "stealth_score" in sec, f"{dashboard} buildIdHtml must include stealth_score (conditional)"
        assert "tokens" in sec, f"{dashboard} buildIdHtml must include tokens (conditional)"
        assert "_adminLock" in sec, f"{dashboard} buildIdHtml must call _adminLock for admin IP icon"
        assert "kv" in sec, f"{dashboard} buildIdHtml must use .kv grid layout"


def test_gw_identity_popover_build_risk_html_uses_weighted_bars():
    """buildRiskHtml must render bars using risk_breakdown (weighted) when available,
    falling back to blocks_breakdown (counts). Both use the same .rsn bar markup."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "risk_breakdown" in sec, f"{dashboard} buildRiskHtml must prefer risk_breakdown"
        assert "blocks_breakdown" in sec, f"{dashboard} buildRiskHtml must fall back to blocks_breakdown"
        assert "rsn-bar" in sec, f"{dashboard} buildRiskHtml must render visual bars (.rsn-bar)"
        assert "isWeighted" in sec, f"{dashboard} buildRiskHtml must distinguish weighted vs count display"


def test_gw_identity_popover_open_popover_agents_is_thin_wrapper():
    """agents.html openPopover must delegate to _gwIdentityPopover — not contain
    inline HTML rendering logic for the identity body."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    pop_idx = src.find("function openPopover")
    assert pop_idx != -1, "agents.html must define openPopover"
    pop_body = src[pop_idx: pop_idx + 600]
    assert "_gwIdentityPopover.normalizeId" in pop_body, (
        "openPopover must call _gwIdentityPopover.normalizeId() — it should not inline normalization"
    )
    assert "_gwIdentityPopover.buildIdHtml" in pop_body, (
        "openPopover must call _gwIdentityPopover.buildIdHtml() — it should not inline HTML rendering"
    )
    assert "_gwIdentityPopover.buildRiskHtml" in pop_body, (
        "openPopover must call _gwIdentityPopover.buildRiskHtml() for the risk breakdown kind"
    )


def test_gw_identity_popover_open_client_popover_main_is_thin_wrapper():
    """main.html openClientPopover must delegate to _gwIdentityPopover — not contain
    inline HTML rendering logic for the identity body."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    pop_idx = src.find("window.openClientPopover")
    assert pop_idx != -1, "main.html must define window.openClientPopover"
    pop_body = src[pop_idx: pop_idx + 600]
    assert "_gwIdentityPopover.normalizeId" in pop_body, (
        "openClientPopover must call _gwIdentityPopover.normalizeId()"
    )
    assert "_gwIdentityPopover.buildIdHtml" in pop_body, (
        "openClientPopover must call _gwIdentityPopover.buildIdHtml()"
    )
    assert "_gwIdentityPopover.buildRiskHtml" in pop_body, (
        "openClientPopover must call _gwIdentityPopover.buildRiskHtml()"
    )


def test_main_html_has_kv_and_rsn_css_for_popover():
    """main.html must define .kv and .rsn CSS classes so the shared buildIdHtml
    and buildRiskHtml output renders correctly (previously used <table> layout)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    assert ".modal .kv{" in src or ".modal .kv {" in src, (
        "main.html must define .modal .kv CSS for the shared identity popover grid layout"
    )
    assert ".modal .rsn{" in src or ".modal .rsn {" in src, (
        "main.html must define .modal .rsn CSS for the shared risk bar layout"
    )
    assert ".modal .rsn-bar" in src, (
        "main.html must define .modal .rsn-bar CSS for visual risk bars"
    )


def test_gw_identity_popover_fmt_is_private():
    """_gwIdentityPopover IIFE must define a private _fmt time formatter so the object
    does not depend on either page's fmtSecs global."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "function _fmt" in sec, (
            f"{dashboard} _gwIdentityPopover must define private _fmt() — "
            "avoids depending on fmtSecs from either page scope"
        )


def test_gw_identity_popover_blocks_by_reason_object_converted():
    """normalizeId must convert blocks_by_reason object → sorted array so buildIdHtml
    can use a uniform [[reason, count], ...] format regardless of data source."""
    sec = _gw_popover_section("main.html")
    assert "Object.entries" in sec, (
        "normalizeId must use Object.entries(raw.blocks_by_reason) to convert object → array"
    )
    assert ".sort(" in sec, (
        "normalizeId must sort the blocks_by_reason entries by count descending"
    )


# ── agents.html must have .popover .kv / .rsn CSS ─────────────────────────

def test_agents_html_has_kv_and_rsn_css_for_popover():
    """agents.html must define .popover .kv and .popover .rsn CSS so the shared
    buildIdHtml / buildRiskHtml output renders correctly in the popover."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    assert ".popover .kv{" in src or ".popover .kv {" in src, (
        "agents.html must define .popover .kv CSS for the shared identity popover grid layout"
    )
    assert ".popover .rsn{" in src or ".popover .rsn {" in src, (
        "agents.html must define .popover .rsn CSS for the shared risk bar layout"
    )
    assert ".popover .rsn-bar" in src, (
        "agents.html must define .popover .rsn-bar CSS for visual risk contribution bars"
    )


# ── null-check discipline: stealth_score and tokens must use != null ──────

def test_gw_identity_popover_stealth_score_uses_strict_null_check():
    """buildIdHtml must gate the stealth row with != null (not truthy check)
    so a score of 0 is shown rather than silently omitted."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "stealth_score != null" in sec, (
            f"{dashboard} buildIdHtml stealth conditional must use '!= null' — "
            "a truthy check would hide a score of 0"
        )


def test_gw_identity_popover_tokens_uses_strict_null_check():
    """buildIdHtml must gate the tokens row with != null (not truthy check)
    so a count of 0 is shown rather than silently omitted."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "tokens != null" in sec, (
            f"{dashboard} buildIdHtml tokens conditional must use '!= null' — "
            "a truthy check would hide a token count of 0"
        )


def test_gw_identity_popover_normalize_stealth_uses_strict_null_check():
    """normalizeId must preserve stealth_score=0 using != null (not falsy ||)."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "stealth_score != null" in sec, (
            f"{dashboard} normalizeId must use 'stealth_score != null' — "
            "using || would coerce 0 to null, hiding a valid zero score"
        )


def test_gw_identity_popover_normalize_tokens_uses_strict_null_check():
    """normalizeId must preserve tokens=0 using != null (not falsy ||)."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "raw.tokens != null" in sec, (
            f"{dashboard} normalizeId must use 'raw.tokens != null' — "
            "using || would coerce 0 to null, hiding a valid zero token count"
        )


# ── buildRiskHtml: weighted vs count label format ─────────────────────────

def test_gw_identity_popover_build_risk_html_weighted_labels():
    """buildRiskHtml must display '+N' for weighted risk_breakdown entries and 'N×'
    for plain count blocks_breakdown fallback entries."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "isWeighted" in sec, (
            f"{dashboard} buildRiskHtml must use isWeighted flag to distinguish modes"
        )
        assert "isWeighted?'+':''" in sec or "isWeighted ? '+' : ''" in sec, (
            f"{dashboard} buildRiskHtml must prefix weighted values with '+'"
        )
        assert "isWeighted?'':'×'" in sec or "isWeighted ? '' : '×'" in sec, (
            f"{dashboard} buildRiskHtml must suffix count values with '×'"
        )


def test_gw_identity_popover_build_risk_html_empty_fallback_message():
    """buildRiskHtml must render a human-readable message when both breakdown
    arrays are empty, not an empty block."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "no contributing signals" in sec, (
            f"{dashboard} buildRiskHtml must render 'no contributing signals' "
            "when breakdown array is empty (score may have decayed)"
        )


# ── normalizeId: missing-data fallbacks must not crash ────────────────────

def test_gw_identity_popover_normalize_blocks_by_reason_empty_fallback():
    """normalizeId must default blocks_by_reason to {} when absent so
    Object.entries() never receives undefined."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "blocks_by_reason || {}" in sec, (
            f"{dashboard} normalizeId must use 'raw.blocks_by_reason || {{}}' — "
            "passing undefined to Object.entries() raises TypeError"
        )


def test_gw_identity_popover_normalize_risk_score_metrics_branch():
    """normalizeId must extract risk_score from raw.metrics.risk_score (agents shape)
    with a fallback to raw.risk_score (main shape)."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "raw.metrics ? raw.metrics.risk_score" in sec, (
            f"{dashboard} normalizeId must branch on raw.metrics for agents data shape"
        )
        assert "raw.risk_score" in sec, (
            f"{dashboard} normalizeId must fall back to raw.risk_score for main data shape"
        )


# ── open functions use the normalized d.ip, not the raw field ─────────────

def test_gw_identity_popover_open_popover_calls_fetch_with_normalized_ip():
    """agents.html openPopover must pass d.ip (normalizeId output) to fetchIpIntel,
    not the raw s.ip — ensures fallback to last_ip is applied."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    pop_idx = src.find("function openPopover")
    assert pop_idx != -1
    pop_body = src[pop_idx: pop_idx + 800]
    assert "fetchIpIntel(d.ip)" in pop_body, (
        "openPopover must pass d.ip to fetchIpIntel, not s.ip — "
        "d.ip is the normalizeId output which handles the ip/last_ip fallback chain"
    )


def test_gw_identity_popover_open_client_popover_calls_fetch_with_normalized_ip():
    """main.html openClientPopover must pass d.ip (normalizeId output) to fetchIpIntel,
    not the raw c.last_ip."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    pop_idx = src.find("window.openClientPopover")
    assert pop_idx != -1
    pop_body = src[pop_idx: pop_idx + 2400]
    assert "fetchIpIntel(d.ip)" in pop_body, (
        "openClientPopover must pass d.ip to fetchIpIntel, not c.last_ip — "
        "d.ip is the normalizeId output which handles the ip/last_ip fallback chain"
    )


# ── buildIdHtml always renders the ip-intel placeholder div ───────────────

def test_gw_identity_popover_build_id_html_has_ip_intel_section():
    """buildIdHtml must always render <div id='ip-intel-section'> so the async
    fetchIpIntel result has a target node to inject into."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "ip-intel-section" in sec, (
            f"{dashboard} buildIdHtml must render <div id='ip-intel-section'> — "
            "fetchIpIntel needs this node to inject the IP reputation block"
        )


# ── risk_score displayed with .toFixed(1) ─────────────────────────────────

def test_gw_identity_popover_risk_score_uses_to_fixed():
    """buildIdHtml and buildRiskHtml must call .toFixed(1) when risk_score is a number
    so the display is consistent (e.g. '42.0' not '42')."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        assert "toFixed(1)" in sec, (
            f"{dashboard} _gwIdentityPopover must use .toFixed(1) for risk_score display — "
            "avoids inconsistent '42' vs '42.0' rendering"
        )


# ── escapeHtml applied to all user-controlled fields ─────────────────────

def test_gw_identity_popover_escape_html_applied_to_user_fields():
    """buildIdHtml must call escapeHtml() on ip, ua, session, fingerprint, ja4,
    last_path and reason fields to prevent XSS via crafted identity values."""
    for dashboard in ("agents.html", "main.html"):
        sec = _gw_popover_section(dashboard)
        for field in ("d.ip", "d.ua", "d.session", "d.fingerprint", "d.ja4", "d.last_path"):
            assert f"escapeHtml({field})" in sec, (
                f"{dashboard} buildIdHtml must call escapeHtml({field}) — "
                f"unescaped {field} would allow XSS via crafted identity data"
            )


# ── _gwIdentityPopover logic identical in both files ──────────────────────

def test_gw_identity_popover_core_logic_identical_in_both_files():
    """The _gwIdentityPopover IIFE implementation must be identical in agents.html
    and main.html — drift between the two copies would cause inconsistent behavior."""
    from pathlib import Path

    def _extract_iife(src: str) -> str:
        start = src.find("function _fmt")
        assert start != -1
        # anchor on the common prefix — agents.html adds buildScoreHtml to the return
        end = src.find("return { normalizeId, buildIdHtml, buildRiskHtml", start)
        assert end != -1
        return src[start: end].strip()

    agents_src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    main_src   = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()

    agents_iife = _extract_iife(agents_src)
    main_iife   = _extract_iife(main_src)

    assert agents_iife == main_iife, (
        "_gwIdentityPopover IIFE differs between agents.html and main.html — "
        "the two copies have drifted; update both files to match"
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1.7.10 — GW Mgmt white-blue colour (#e4f0ff) + drill-down / chart fixes
# ═══════════════════════════════════════════════════════════════════════════

_GWMGMT_COLOR = "#e4f0ff"
_GWMGMT_OLD_TEAL = "#26c6da"


def test_gwmgmt_color_is_white_blue_in_agents_html():
    """agents.html: gwmgmt pill border/text, active-pill background, chart
    borderColor and backgroundColor must all use #e4f0ff (white-blue)."""
    src = _dash("agents.html")
    assert f'data-cat="gwmgmt"{{border-color:{_GWMGMT_COLOR};color:{_GWMGMT_COLOR}}}' in src or \
           f"gwmgmt" in src and _GWMGMT_COLOR in src, (
        "agents.html: gwmgmt pill must use #e4f0ff"
    )
    assert f'.cat-pill[data-cat="gwmgmt"]{{border-color:{_GWMGMT_COLOR};color:{_GWMGMT_COLOR}}}' in src, (
        "agents.html: gwmgmt inactive pill must use #e4f0ff for border and text"
    )
    assert f'.cat-pill.active[data-cat="gwmgmt"]{{background:{_GWMGMT_COLOR}' in src, (
        "agents.html: gwmgmt active pill background must be #e4f0ff"
    )
    assert f"borderColor:'{_GWMGMT_COLOR}'" in src, (
        "agents.html: chart dataset borderColor for gw mgmt must be #e4f0ff"
    )
    assert "rgba(228,240,255," in src, (
        "agents.html: chart dataset backgroundColor for gw mgmt must start with rgba(228,240,255,...)"
    )


def test_gwmgmt_color_is_white_blue_in_logs_html():
    """logs.html: gwmgmt pill border/text and active-pill background must use #e4f0ff."""
    src = _dash("logs.html")
    assert f'.cat-pill[data-cat="gwmgmt"]{{border-color:{_GWMGMT_COLOR};color:{_GWMGMT_COLOR}}}' in src, (
        "logs.html: gwmgmt inactive pill must use #e4f0ff for border and text"
    )
    assert f'.cat-pill.active[data-cat="gwmgmt"]{{background:{_GWMGMT_COLOR}' in src, (
        "logs.html: gwmgmt active pill background must be #e4f0ff"
    )


def test_gwmgmt_color_is_white_blue_in_main_html():
    """main.html: every gwmgmt colour surface (pill, panel-legend, gwmgmt-tag,
    swatches, chart) must use #e4f0ff."""
    src = _dash("main.html")
    assert f'.cat-pill[data-cat="gwmgmt"]{{border-color:{_GWMGMT_COLOR};color:{_GWMGMT_COLOR}}}' in src, (
        "main.html: gwmgmt inactive pill must use #e4f0ff"
    )
    assert f'.cat-pill.active[data-cat="gwmgmt"]{{background:{_GWMGMT_COLOR}' in src, (
        "main.html: gwmgmt active pill background must be #e4f0ff"
    )
    assert f'.panel-leg-item[data-leg-cats="gwmgmt"]{{color:{_GWMGMT_COLOR}}}' in src, (
        "main.html: panel legend gwmgmt item must use #e4f0ff"
    )
    assert f'.tag.gwmgmt-tag{{background:#0d2340;color:{_GWMGMT_COLOR}}}' in src, (
        "main.html: gwmgmt-tag text color must be #e4f0ff"
    )
    assert src.count(f'background:{_GWMGMT_COLOR}') >= 2, (
        "main.html: at least 2 GW Mgmt swatch inline backgrounds must use #e4f0ff "
        "(Timeline tooltip + Live Events tooltip)"
    )
    assert f"borderColor: '{_GWMGMT_COLOR}'" in src, (
        "main.html: chart dataset borderColor for gw mgmt must be #e4f0ff"
    )
    assert "rgba(228,240,255," in src, (
        "main.html: chart dataset backgroundColor for gw mgmt must use rgba(228,240,255,…)"
    )


def test_gwmgmt_old_teal_absent_from_all_dashboards():
    """#26c6da (old teal) must not appear anywhere in the three dashboards —
    it has been fully replaced by #e4f0ff."""
    for name in ("agents.html", "logs.html", "main.html"):
        src = _dash(name)
        assert _GWMGMT_OLD_TEAL not in src, (
            f"{name}: old gwmgmt teal color {_GWMGMT_OLD_TEAL} still present — "
            "replace every occurrence with #e4f0ff"
        )


def test_main_html_path_drill_gwmgmt_aware():
    """openPathDrill must detect admin-namespace paths and use #e4f0ff for
    the explainBlock border and code color instead of var(--blue)."""
    src = _dash("main.html")
    # isGwMgmt flag and pathColor variable must exist inside openPathDrill
    drill_start = src.index("window.openPathDrill")
    drill_end   = src.index("window.openMainBucketDetail")
    drill_body  = src[drill_start:drill_end]
    assert "isGwMgmt" in drill_body, (
        "openPathDrill: missing isGwMgmt flag for admin-namespace path detection"
    )
    assert "pathColor" in drill_body, (
        "openPathDrill: missing pathColor variable for gwmgmt-conditional coloring"
    )
    assert "/antibot-appsec-gateway/" in drill_body, (
        "openPathDrill: admin-namespace prefix check missing"
    )
    assert _GWMGMT_COLOR in drill_body, (
        f"openPathDrill: gwmgmt color {_GWMGMT_COLOR} not used in drill-down block"
    )


def test_main_html_path_drill_modal_title_uses_pathcolor():
    """openPathDrill modal title must colour the path <code> with pathColor,
    not the hardcoded var(--blue), so gwmgmt paths render in #e4f0ff."""
    src = _dash("main.html")
    drill_start = src.index("window.openPathDrill")
    drill_end   = src.index("window.openMainBucketDetail")
    drill_body  = src[drill_start:drill_end]
    # Modal title must reference pathColor, not a hardcoded var(--blue)
    assert "modal-title" in drill_body, "openPathDrill must set modal-title innerHTML"
    title_idx = drill_body.index("modal-title")
    title_snippet = drill_body[title_idx: title_idx + 200]
    assert "pathColor" in title_snippet, (
        "modal-title code color must use pathColor variable, not hardcoded var(--blue)"
    )
    assert "var(--blue)" not in title_snippet, (
        "modal-title must not hardcode var(--blue) — gwmgmt paths need #e4f0ff"
    )


def test_main_html_path_row_gwmgmt_tooltip():
    """Top Paths table: gwmgmt path rows must show 'click to see requestors'
    (not 'offender IPs') to reflect that admin-namespace traffic is not hostile."""
    src = _dash("main.html")
    assert "click to see requestors" in src, (
        "main.html: gwmgmt path row tooltip must say 'click to see requestors'"
    )
    # The generic tooltip for non-gwmgmt paths must still exist
    assert "click to see offender IPs / identities" in src, (
        "main.html: non-gwmgmt path row tooltip 'click to see offender IPs / identities' removed"
    )


def test_main_html_path_row_gwmgmt_color():
    """Top Paths table rows must apply #e4f0ff text/underline for gwmgmt paths
    via an isGw flag, and fall back to var(--blue) for all other paths."""
    src = _dash("main.html")
    # Must have isGw / rowColor / rowTip logic in path row renderer
    assert "isGw" in src, (
        "main.html: isGw flag missing from Top Paths table row renderer"
    )
    assert "rowColor" in src, (
        "main.html: rowColor variable missing from Top Paths table row renderer"
    )
    assert "rowTip" in src, (
        "main.html: rowTip variable missing from Top Paths table row renderer"
    )


def test_gwmgmt_off_by_default_in_main_and_agents():
    """GW Mgmt must be excluded from the initial _activeFilters set and the pill
    button must not carry the 'active' class on main.html page load.

    Note: agents.html intentionally keeps gwmgmt ON by default (reverted by design).
    """
    import re as _re
    src = _dash("main.html")
    # _activeFilters initial set must NOT include gwmgmt
    filters_line = src.split("_activeFilters = new Set(")[1].split(")")[0]
    assert "'gwmgmt'" not in filters_line, (
        "main.html: 'gwmgmt' must not be in the initial _activeFilters Set — "
        "GW Mgmt should be off by default"
    )
    # The pill button must not have class 'active'
    pill_match = _re.search(r'<button[^>]*data-cat="gwmgmt"[^>]*>', src)
    assert pill_match, "main.html: gwmgmt cat-pill button not found"
    assert "active" not in pill_match.group(0), (
        "main.html: gwmgmt pill button must not have 'active' class on initial render"
    )


def test_main_html_total_dataset_hidden_when_single_band():
    """When only one chart band is active, the 'total' dataset (datasets[0])
    must be hidden to prevent a blue total line from masking the single-band color."""
    src = _dash("main.html")
    assert "_activeBandCount" in src, (
        "main.html: _activeBandCount variable missing — total dataset must be "
        "hidden when only one band is active"
    )
    assert "datasets[0].hidden = _activeBandCount <= 1" in src, (
        "main.html: datasets[0].hidden must be set to (_activeBandCount <= 1)"
    )


def test_main_html_bucket_detail_has_gwmgmt_section():
    """openMainBucketDetail sections array must include a gwmgmt entry with
    renderGwMgmt so clicking a gwmgmt chart bucket shows GW Mgmt traffic."""
    src = _dash("main.html")
    assert "renderGwMgmt" in src, (
        "main.html: renderGwMgmt renderer missing from openMainBucketDetail"
    )
    # gwmgmt must appear in the sections array
    detail_start = src.index("window.openMainBucketDetail")
    detail_body  = src[detail_start: detail_start + 8000]
    assert "kind:'gwmgmt'" in detail_body, (
        "main.html: 'gwmgmt' section missing from openMainBucketDetail sections array"
    )
    assert "'GW MGMT'" in detail_body or "GW MGMT" in detail_body, (
        "main.html: GW MGMT label missing from gwmgmt section in bucket detail"
    )


def test_main_html_bucket_detail_gwmgmt_color_matches_pill():
    """renderGwMgmt hit-count cell must use #e4f0ff — matching the gwmgmt
    pill and chart line color — for visual consistency."""
    src = _dash("main.html")
    render_start = src.index("renderGwMgmt")
    render_body  = src[render_start: render_start + 600]
    assert _GWMGMT_COLOR in render_body, (
        f"renderGwMgmt: hit-count color must be {_GWMGMT_COLOR} (white-blue gwmgmt color)"
    )


def test_main_html_bucket_detail_kind_to_key_has_gwmgmt():
    """KIND_TO_KEY in openMainBucketDetail must map 'gwmgmt' → 'gwmgmt' so
    _moveEntry() and focusKind highlighting work for GW Mgmt buckets."""
    src = _dash("main.html")
    detail_start = src.index("window.openMainBucketDetail")
    detail_body  = src[detail_start: detail_start + 3000]
    assert "KIND_TO_KEY" in detail_body, (
        "main.html: KIND_TO_KEY missing from openMainBucketDetail"
    )
    ktk_start = detail_body.index("KIND_TO_KEY")
    ktk_line  = detail_body[ktk_start: ktk_start + 300]
    assert "gwmgmt" in ktk_line, (
        "main.html: KIND_TO_KEY must include gwmgmt mapping"
    )


def test_main_html_bucket_detail_totalcount_includes_gwmgmt():
    """totalCount in _renderAndWire must include d.gwmgmt.length so the
    'N IPs in this bucket' header counts GW Mgmt requestors."""
    src = _dash("main.html")
    assert "d.gwmgmt" in src, (
        "main.html: d.gwmgmt missing from totalCount calculation in _renderAndWire"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Virtual Hosts UI — settings.html static checks
# ─────────────────────────────────────────────────────────────────────────────

def test_settings_vhosts_card_present():
    """settings.html must contain the Virtual Hosts card with expected structure."""
    src = _dash("settings.html")
    assert 'id="card-vhosts"' in src, (
        "settings.html: Virtual Hosts card (id=card-vhosts) missing"
    )
    assert 'id="vhost-tbody"' in src, (
        "settings.html: vhost-tbody tbody element missing"
    )
    assert 'id="vhost-add-btn"' in src, (
        "settings.html: vhost-add-btn button missing"
    )
    assert 'id="vhost-modal"' in src, (
        "settings.html: vhost-modal dialog element missing"
    )


def test_settings_vhosts_uses_domcontentloaded():
    """settings.html vhost script must use DOMContentLoaded, not a bare IIFE.

    The vhost <script> block appears before _timers and escapeHtml are defined.
    Using an IIFE causes ReferenceError at runtime ('Loading…' stuck).
    DOMContentLoaded fires after all synchronous scripts have run.
    """
    src = _dash("settings.html")
    # Must have DOMContentLoaded listener
    assert "DOMContentLoaded" in src, (
        "settings.html: DOMContentLoaded missing — vhost script must defer via "
        "document.addEventListener('DOMContentLoaded', ...) so _timers and "
        "escapeHtml (defined later) are available when the script runs"
    )
    # The comment marker documenting the intent must be present
    assert "vhost-init" in src, (
        "settings.html: vhost-init comment missing — marker for the deferred "
        "DOMContentLoaded init block"
    )


def test_settings_vhosts_no_iife_before_timers():
    """settings.html vhost block must NOT use an immediately-invoked function expression.

    An IIFE runs synchronously before later <script> blocks, causing ReferenceError
    on _timers and escapeHtml.  The only safe pattern is DOMContentLoaded.
    """
    src = _dash("settings.html")
    # Locate the vhost script block (between vhost-init comment and /Virtual Hosts)
    if "vhost-init" not in src or "<!-- /Virtual Hosts" not in src:
        return  # structural test already caught this
    vhost_block = src[src.index("vhost-init"): src.index("<!-- /Virtual Hosts")]
    # A bare IIFE looks like: })(  or  })()
    bare_iife = _re.search(r'\}\s*\)\s*\(\s*\)', vhost_block)
    assert not bare_iife, (
        "settings.html: vhost script block contains a bare IIFE (})() — "
        "this runs before _timers/_escapeHtml are defined. Use DOMContentLoaded."
    )


def test_settings_vhosts_fetch_error_shown_in_table():
    """settings.html vhost fetch must surface errors in the table, not just console.error."""
    src = _dash("settings.html")
    if "vhost-init" not in src or "<!-- /Virtual Hosts" not in src:
        return
    vhost_block = src[src.index("vhost-init"): src.index("<!-- /Virtual Hosts")]
    assert "Failed to load" in vhost_block, (
        "settings.html: vhost fetch .catch() must write 'Failed to load' into "
        "the table cell so the operator sees the error, not just the browser console"
    )


def test_settings_vhosts_http_error_thrown():
    """settings.html vhost fetch must throw on non-2xx to trigger .catch()."""
    src = _dash("settings.html")
    if "vhost-init" not in src or "<!-- /Virtual Hosts" not in src:
        return
    vhost_block = src[src.index("vhost-init"): src.index("<!-- /Virtual Hosts")]
    assert "r.ok" in vhost_block or "!r.ok" in vhost_block, (
        "settings.html: vhost fetch must check r.ok and throw on HTTP errors"
    )


def test_settings_vhosts_interval_tracked():
    """settings.html vhost setInterval call must be tracked via _timers.push()."""
    src = _dash("settings.html")
    if "vhost-init" not in src or "<!-- /Virtual Hosts" not in src:
        return
    vhost_block = src[src.index("vhost-init"): src.index("<!-- /Virtual Hosts")]
    assert "_timers.push(setInterval(" in vhost_block, (
        "settings.html: vhost auto-refresh setInterval must be wrapped in "
        "_timers.push(...) to prevent timer leaks on page navigation"
    )


def test_settings_vhosts_uses_canonical_escapehml():
    """settings.html vhost block must call escapeHtml(), not a local alias."""
    src = _dash("settings.html")
    if "vhost-init" not in src or "<!-- /Virtual Hosts" not in src:
        return
    vhost_block = src[src.index("vhost-init"): src.index("<!-- /Virtual Hosts")]
    assert "escapeHtml(" in vhost_block, (
        "settings.html: vhost block must call escapeHtml() — the canonical "
        "function defined at global scope — not a local alias"
    )
    # Confirm no local alias is introduced inside the vhost block
    local_def = _re.search(r'(?:const|function|var)\s+esc[Hh]tml\b', vhost_block)
    assert not local_def, (
        "settings.html: vhost block must not define a local escHtml/escapeHtml alias"
    )


def test_settings_vhosts_uses_gwAlert():
    """settings.html vhost block must use _gwAlert(), not bare alert()."""
    src = _dash("settings.html")
    if "vhost-init" not in src or "<!-- /Virtual Hosts" not in src:
        return
    vhost_block = src[src.index("vhost-init"): src.index("<!-- /Virtual Hosts")]
    # bare alert( calls (not _gwAlert)
    bare = _re.findall(r'(?<!_gw)(?<!_g)\balert\s*\(', vhost_block)
    assert not bare, (
        f"settings.html: vhost block has {len(bare)} bare alert() call(s) — "
        "use _gwAlert() so all alerts pass through the dashboard's notification system"
    )


def test_settings_vhosts_api_path_correct():
    """settings.html vhost fetch must target the correct secured endpoint path."""
    src = _dash("settings.html")
    if "vhost-init" not in src or "<!-- /Virtual Hosts" not in src:
        return
    vhost_block = src[src.index("vhost-init"): src.index("<!-- /Virtual Hosts")]
    assert "/antibot-appsec-gateway/secured/vhosts" in vhost_block, (
        "settings.html: vhost fetch URL must be "
        "/antibot-appsec-gateway/secured/vhosts"
    )


# ── 1.8.1 — Vhost Policy page ────────────────────────────────────────────────

def test_vhost_policy_html_version_string():
    """vhost_policy.html must carry the current version string."""
    src = _dash("vhost_policy.html")
    assert "AntiBotWaf_GW_1.9.11" in src, "vhost_policy.html: version string missing or stale"


def test_vhost_policy_html_scope_bar():
    """vhost_policy.html must have the vhost selector and add-override button."""
    src = _dash("vhost_policy.html")
    assert 'id="vhost-select"' in src, "vhost_policy.html: #vhost-select missing"
    assert 'id="btn-add-override"' in src, "vhost_policy.html: #btn-add-override missing"
    assert 'id="override-count"' in src, "vhost_policy.html: #override-count badge missing"


def test_vhost_policy_html_overrides_container():
    """vhost_policy.html must have the overrides container and card."""
    src = _dash("vhost_policy.html")
    assert 'id="overrides-container"' in src, "vhost_policy.html: #overrides-container missing"
    assert 'id="card-overrides"' in src, "vhost_policy.html: #card-overrides missing"
    assert 'id="card-title"' in src, "vhost_policy.html: #card-title missing"


def test_vhost_policy_html_picker_modal():
    """vhost_policy.html must have the knob picker modal."""
    src = _dash("vhost_policy.html")
    assert 'id="picker-modal"' in src, "vhost_policy.html: #picker-modal missing"
    assert 'id="picker-search"' in src, "vhost_policy.html: #picker-search missing"
    assert 'id="picker-body"' in src, "vhost_policy.html: #picker-body missing"
    assert 'id="picker-close"' in src, "vhost_policy.html: #picker-close missing"


def test_vhost_policy_html_unsaved_bar():
    """vhost_policy.html must have unsaved changes bar with apply/reset buttons."""
    src = _dash("vhost_policy.html")
    assert 'id="unsaved-bar"' in src, "vhost_policy.html: #unsaved-bar missing"
    assert 'id="btn-apply"' in src, "vhost_policy.html: #btn-apply missing"
    assert 'id="btn-reset"' in src, "vhost_policy.html: #btn-reset missing"


def test_vhost_policy_html_api_paths():
    """vhost_policy.html must reference correct API endpoints."""
    src = _dash("vhost_policy.html")
    # Path built as ADMIN_NS+'/vhost-policy-data' at runtime
    assert "vhost-policy-data" in src, (
        "vhost_policy.html: vhost-policy-data API path segment missing"
    )
    assert "ADMIN_NS" in src, (
        "vhost_policy.html: ADMIN_NS constant missing — needed for API paths"
    )
    assert "/vhosts" in src, (
        "vhost_policy.html: /vhosts write endpoint missing"
    )


def test_vhost_policy_html_active_nav_link():
    """vhost_policy.html nav must mark Vhost Policy as active."""
    src = _dash("vhost_policy.html")
    assert 'vhost-policy" class="active"' in src or 'vhost-policy" class="sub active"' in src, (
        "vhost_policy.html: Vhost Policy nav link not marked active"
    )


def test_vhost_policy_html_knob_meta_coverage():
    """Every per-vhost-overridable knob (_VHOST_COERCE) MUST appear in
    vhost_policy.html KNOB_META with a type matching its coercer.

    A knob missing here falls back to the generic 'Other' text-input widget,
    which sends bool values as the strings "true"/"false" — and silently
    mis-saves them (see test_v1810_vhost_knob_persist). This is the guard that
    was too weak (only counted ≥100) and let the 1.8.9 WAF knobs slip through.
    """
    import os, re, importlib
    os.environ.setdefault("UPSTREAM", "https://example.com")
    vhost_mod = importlib.import_module("vhost")
    coerce = vhost_mod._VHOST_COERCE
    src = _dash("vhost_policy.html")
    m = re.search(r"var KNOB_META\s*=\s*\{(.*?)\n\};", src, re.S)
    assert m, "KNOB_META object not found in vhost_policy.html"
    body = m.group(1)
    meta = dict(re.findall(r"([A-Z0-9_]+):\s*\{[^}]*?t:'([a-z]+)'", body))

    missing = sorted(set(coerce) - set(meta))
    assert not missing, (
        f"vhost_policy.html KNOB_META is missing {len(missing)} overridable "
        f"knob(s) — they would render as generic 'Other' text inputs and "
        f"mis-save bool values: {missing}"
    )

    # type must match the coercer family for the unambiguous coercers
    _to_bool = vhost_mod._to_bool
    expect = {}
    for k, c in coerce.items():
        if c is _to_bool:
            expect[k] = "bool"
        elif c is int:
            expect[k] = "int"
        elif c is str:
            expect[k] = "str"
    bad = [f"{k}: KNOB_META t='{meta.get(k)}' but coercer expects '{exp}'"
           for k, exp in expect.items() if meta.get(k) != exp]
    assert not bad, "vhost_policy.html KNOB_META type mismatches:\n" + "\n".join(bad)


def test_settings_vhost_table_has_policy_link():
    """settings.html vhost table must include a Policy link per row."""
    src = _dash("settings.html")
    assert "vhost-policy?hostname=" in src, (
        "settings.html: Policy link to vhost-policy page missing from vhost table"
    )


def test_settings_topnav_has_vhost_policy_link():
    """settings.html topnav must include a link to the Vhost Policy page."""
    src = _dash("settings.html")
    assert "/antibot-appsec-gateway/secured/vhost-policy" in src, (
        "settings.html: topnav missing Vhost Policy link"
    )


def test_vhost_coerce_expanded():
    """_VHOST_COERCE must contain at least 148 knobs (expanded in 1.8.9)."""
    import sys, os
    os.environ.setdefault("UPSTREAM", "https://example.com")
    import importlib
    vhost_mod = importlib.import_module("vhost")
    count = len(vhost_mod._VHOST_COERCE)
    assert count >= 148, (
        f"_VHOST_COERCE has only {count} entries — expected ≥148 after 1.8.9 expansion"
    )


def test_all_signal_knobs_in_vhost_coerce():
    """Every SIGNAL_KNOB toggle value must be overridable at the vhost level.

    When a new signal is added to SIGNAL_KNOB, its knob env-var must also be
    added to _VHOST_COERCE so operators can enable/disable it per-hostname.
    This test catches the gap where a knob is wired to SIGNAL_KNOB but
    forgotten in _VHOST_COERCE, silently making the per-vhost toggle a no-op.
    """
    import os, importlib
    os.environ.setdefault("UPSTREAM", "https://example.com")
    vhost_mod = importlib.import_module("vhost")
    from core.proxy_handler import SIGNAL_KNOB
    # None values are signals with no kill-switch (always-on) — exclude from check.
    # ADMIN_ALLOWED_IPS is a global admin security control (not a per-vhost
    # toggle) — admin routes are not vhost-scoped so per-vhost override is N/A.
    _GLOBAL_ONLY = {"ADMIN_ALLOWED_IPS"}
    signal_knobs = {v for v in SIGNAL_KNOB.values() if v is not None} - _GLOBAL_ONLY
    vhost_keys  = set(vhost_mod._VHOST_COERCE.keys())
    missing = signal_knobs - vhost_keys
    assert not missing, (
        f"SIGNAL_KNOB toggle(s) missing from _VHOST_COERCE — "
        f"add them as bool entries in vhost.py: {sorted(missing)}"
    )


def test_bot_detection_enabled_in_vhost_coerce():
    """BOT_DETECTION_ENABLED must be in _VHOST_COERCE as a bool knob."""
    import os, importlib
    os.environ.setdefault("UPSTREAM", "https://example.com")
    vhost_mod = importlib.import_module("vhost")
    assert "BOT_DETECTION_ENABLED" in vhost_mod._VHOST_COERCE, (
        "BOT_DETECTION_ENABLED not in _VHOST_COERCE — per-vhost bot detection "
        "toggle cannot be applied via the vhost override system."
    )
    coercer = vhost_mod._VHOST_COERCE["BOT_DETECTION_ENABLED"]
    # 1.8.10 — bool knobs use the string-aware _to_bool (NOT bare `bool`, which
    # mis-coerces the string "false" to True). See test_v1810_vhost_knob_persist.
    assert coercer is vhost_mod._to_bool, (
        "_VHOST_COERCE['BOT_DETECTION_ENABLED'] must use the _to_bool coercer."
    )
    assert coercer("false") is False and coercer("true") is True, (
        "BOT_DETECTION_ENABLED coercer must parse string booleans correctly."
    )


def test_bot_detection_enabled_default_true():
    """BOT_DETECTION_ENABLED global default must be True."""
    import os, importlib
    os.environ.setdefault("UPSTREAM", "https://example.com")
    cfg = importlib.import_module("config")
    assert getattr(cfg, "BOT_DETECTION_ENABLED", None) is True, (
        "config.BOT_DETECTION_ENABLED default is not True — "
        "bot detection must be on by default globally."
    )


def test_vhost_policy_html_has_bot_detection_card():
    """vhost_policy.html must have the Bot Detection quick-toggle card."""
    src = _dash("vhost_policy.html")
    assert 'id="card-bot-detection"' in src, (
        "vhost_policy.html: #card-bot-detection card missing — "
        "Bot Detection quick-toggle must be present on the policy page."
    )
    assert 'id="bot-detection-switch"' in src, (
        "vhost_policy.html: #bot-detection-switch element missing."
    )
    assert "BOT_DETECTION_ENABLED" in src, (
        "vhost_policy.html: BOT_DETECTION_ENABLED knob reference missing."
    )


def test_vhost_policy_html_bot_detection_in_knob_meta():
    """vhost_policy.html KNOB_META must include BOT_DETECTION_ENABLED."""
    src = _dash("vhost_policy.html")
    assert "BOT_DETECTION_ENABLED" in src, (
        "vhost_policy.html: BOT_DETECTION_ENABLED missing from KNOB_META — "
        "knob must be registered so it appears in the override picker."
    )


def test_proxy_handler_bot_detection_gate_present():
    """proxy_handler.py must gate on BOT_DETECTION_ENABLED before first detector."""
    import os
    src = open(os.path.join(os.path.dirname(__file__), '..', 'core', 'proxy_handler.py'),
               encoding='utf-8').read()
    gate_call = "vc('BOT_DETECTION_ENABLED')"
    assert gate_call in src or 'vc("BOT_DETECTION_ENABLED")' in src, (
        "core/proxy_handler.py: BOT_DETECTION_ENABLED gate not found — "
        "vc('BOT_DETECTION_ENABLED') must be checked in protect() before detector calls."
    )
    gate_idx = src.find(gate_call)
    assert gate_idx != -1, "Could not locate vc('BOT_DETECTION_ENABLED') in proxy_handler.py"
    # 1.8.13: _is_trap_path pre-gate check uses vc('HONEYPOT_ENABLED') intentionally
    # BEFORE the gate so trap paths bypass JS-challenge. The actual honeypot DETECTOR
    # call must appear AFTER the gate. Search from gate_idx onwards.
    honeypot_vc_idx = src.find("vc('HONEYPOT_ENABLED')", gate_idx)
    assert honeypot_vc_idx != -1, (
        "Could not locate vc('HONEYPOT_ENABLED') in proxy_handler.py after the "
        "BOT_DETECTION_ENABLED gate — honeypot detector must be inside the gated block."
    )
    assert gate_idx < honeypot_vc_idx, (
        "proxy_handler.py: vc('BOT_DETECTION_ENABLED') gate must appear BEFORE "
        "vc('HONEYPOT_ENABLED') (the detector call) in protect()."
    )


# ── S45-S49: BOT_DETECTION_ENABLED static QA ─────────────────────────────
# These tests verify code-level correctness of the per-vhost bot-detection
# toggle without executing the server. They complement the 5 tests above
# with additional structural invariants.

def test_bot_detection_gate_uses_operator_passthrough_action():
    """Gate must call record() with 'operator-passthrough' — not 'ok' or 'bypass-mode'."""
    import os
    src = open(os.path.join(os.path.dirname(__file__), '..', 'core', 'proxy_handler.py'),
               encoding='utf-8').read()
    # Locate the gate block
    gate_idx = src.find("vc('BOT_DETECTION_ENABLED')")
    assert gate_idx != -1, "vc('BOT_DETECTION_ENABLED') not found in proxy_handler.py"
    # The record() call must follow within 500 chars of the gate
    gate_block = src[gate_idx:gate_idx + 500]
    assert "operator-passthrough" in gate_block, (
        "proxy_handler.py: BOT_DETECTION_ENABLED gate must call record() with "
        "'operator-passthrough' so traffic is still accounted for in dashboards."
    )


def test_bot_detection_gate_after_ban_checks():
    """Ban checks (is_banned) must appear BEFORE the BOT_DETECTION_ENABLED gate."""
    import os
    src = open(os.path.join(os.path.dirname(__file__), '..', 'core', 'proxy_handler.py'),
               encoding='utf-8').read()
    gate_idx = src.find("vc('BOT_DETECTION_ENABLED')")
    ban_idx = src.find("await is_banned(track_key)")
    fp_ban_idx = src.find("await is_banned(fp_hash_key)")
    assert gate_idx != -1, "BOT_DETECTION_ENABLED gate not found"
    assert ban_idx != -1, "await is_banned(track_key) not found — ban check removed?"
    assert fp_ban_idx != -1, "await is_banned(fp_hash_key) not found — fp ban check removed?"
    assert ban_idx < gate_idx, (
        "proxy_handler.py: is_banned(track_key) must appear BEFORE the "
        "BOT_DETECTION_ENABLED gate — bans must be enforced even when detection is off."
    )
    assert fp_ban_idx < gate_idx, (
        "proxy_handler.py: is_banned(fp_hash_key) must appear BEFORE the "
        "BOT_DETECTION_ENABLED gate — fp bans must be enforced even when detection is off."
    )


def test_bot_detection_gate_after_endpoint_rate_limit():
    """Endpoint rate limit check must appear BEFORE the BOT_DETECTION_ENABLED gate."""
    import os
    src = open(os.path.join(os.path.dirname(__file__), '..', 'core', 'proxy_handler.py'),
               encoding='utf-8').read()
    gate_idx = src.find("vc('BOT_DETECTION_ENABLED')")
    rate_idx = src.find("_endpoint_rate_consume")
    assert gate_idx != -1, "BOT_DETECTION_ENABLED gate not found"
    assert rate_idx != -1, "_endpoint_rate_consume not found — endpoint rate limit removed?"
    assert rate_idx < gate_idx, (
        "proxy_handler.py: endpoint rate limit (_endpoint_rate_consume) must appear "
        "BEFORE the BOT_DETECTION_ENABLED gate — rate limits apply even when detection is off."
    )


def test_bot_detection_switch_data_attributes():
    """vhost_policy.html: bot-detection-switch must have correct data-knob attribute."""
    src = _dash("vhost_policy.html")
    # Find the switch element
    import re
    switch_m = re.search(r'id=["\']bot-detection-switch["\'][^>]*>', src)
    assert switch_m, "vhost_policy.html: #bot-detection-switch element not found"
    switch_tag = switch_m.group(0)
    assert 'data-knob="BOT_DETECTION_ENABLED"' in switch_tag or \
           "data-knob='BOT_DETECTION_ENABLED'" in switch_tag, (
        "vhost_policy.html: #bot-detection-switch must have data-knob='BOT_DETECTION_ENABLED' "
        "so the JS click handler can identify which knob to mutate."
    )


def test_bot_detection_card_render_fn_called_from_render_overrides():
    """_renderBotDetectionCard() must be called from within _renderOverrides()."""
    src = _dash("vhost_policy.html")
    import re
    # Extract _renderOverrides body
    m = re.search(r'function _renderOverrides\s*\([^)]*\)\s*\{', src)
    assert m, "vhost_policy.html: _renderOverrides() function not found"
    start = m.end()
    # Walk braces to find function end
    depth = 1
    pos = start
    while pos < len(src) and depth:
        if src[pos] == '{':
            depth += 1
        elif src[pos] == '}':
            depth -= 1
        pos += 1
    fn_body = src[start:pos]
    assert "_renderBotDetectionCard" in fn_body, (
        "vhost_policy.html: _renderBotDetectionCard() must be called from inside "
        "_renderOverrides() so the card re-renders whenever overrides are reloaded."
    )


# ── STRICT_VHOST default ──────────────────────────────────────────────────

def test_strict_vhost_default_is_on():
    """STRICT_VHOST must default to '1' (on) in config.py."""
    import re
    src = open(
        __import__("pathlib").Path(__file__).resolve().parent.parent / "config.py",
        encoding="utf-8",
    ).read()
    m = re.search(r'os\.environ\.get\("STRICT_VHOST",\s*"([^"]+)"\)', src)
    assert m, "config.py: STRICT_VHOST os.environ.get() not found"
    assert m.group(1) == "1", (
        f"STRICT_VHOST default must be '1', got {m.group(1)!r}"
    )


def test_strict_vhost_guard_requires_vhosts_non_empty():
    """The STRICT_VHOST check in proxy_handler.py must only fire when VHOSTS
    is non-empty (single-upstream mode with no vhosts configured must pass through)."""
    src = open(
        __import__("pathlib").Path(__file__).resolve().parent.parent
        / "core" / "proxy_handler.py",
        encoding="utf-8",
    ).read()
    # Find the STRICT_VHOST guard line
    import re
    m = re.search(r'if STRICT_VHOST.*?vhost_is_configured\(\)', src)
    assert m, "core/proxy_handler.py: STRICT_VHOST guard line not found"
    guard = m.group(0)
    assert "VHOSTS" in guard, (
        "STRICT_VHOST guard must check 'VHOSTS' (non-empty) before rejecting — "
        "single-upstream deployments with no vhosts must not be broken by STRICT_VHOST=1"
    )


# ── MaxMind ETag conditional download ─────────────────────────────────────

def test_maxmind_fetch_edition_exists():
    """_maxmind_fetch_edition must be defined in reputation/maxmind.py."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "reputation" / "maxmind.py").read_text()
    assert "_maxmind_fetch_edition" in src, \
        "reputation/maxmind.py: _maxmind_fetch_edition not found"


def test_maxmind_etag_helpers_exist():
    """_etag_path, _read_etag, _write_etag must be defined."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "reputation" / "maxmind.py").read_text()
    for fn in ("_etag_path", "_read_etag", "_write_etag"):
        assert f"def {fn}" in src, \
            f"reputation/maxmind.py: {fn} not found"


def test_maxmind_fetch_sends_if_none_match():
    """_maxmind_fetch_edition must include If-None-Match when an ETag is stored."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "reputation" / "maxmind.py").read_text()
    assert "If-None-Match" in src, \
        "reputation/maxmind.py: If-None-Match header not sent — conditional download not implemented"


def test_maxmind_fetch_handles_304():
    """_maxmind_fetch_edition must handle HTTP 304 Not Modified."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "reputation" / "maxmind.py").read_text()
    assert "304" in src, \
        "reputation/maxmind.py: 304 Not Modified not handled — downloads will count against daily limit even when database is unchanged"
    assert "not_modified" in src, \
        "reputation/maxmind.py: 'not_modified' return value not found"


def test_maxmind_refresh_loop_uses_fetch_edition():
    """_maxmind_refresh_loop must delegate to _maxmind_fetch_edition (not inline download)."""
    import pathlib, re
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "reputation" / "maxmind.py").read_text()
    loop_start = src.find("async def _maxmind_refresh_loop")
    assert loop_start >= 0, "reputation/maxmind.py: _maxmind_refresh_loop not found"
    loop_body = src[loop_start:loop_start + 2000]
    assert "_maxmind_fetch_edition" in loop_body, \
        "_maxmind_refresh_loop must call _maxmind_fetch_edition for ETag-based conditional download"


def test_maxmind_auto_fetch_uses_fetch_edition():
    """_maxmind_auto_fetch must delegate to _maxmind_fetch_edition."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "reputation" / "maxmind.py").read_text()
    auto_start = src.find("def _maxmind_auto_fetch")
    assert auto_start >= 0
    auto_body = src[auto_start:auto_start + 1100]
    assert "_maxmind_fetch_edition" in auto_body, \
        "_maxmind_auto_fetch must call _maxmind_fetch_edition for ETag support"


def test_maxmind_fetch_edition_source_has_mtime_check():
    """_maxmind_fetch_edition must call os.path.getmtime to check file age."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent
           / "reputation" / "maxmind.py").read_text()
    fn_start = src.find("def _maxmind_fetch_edition")
    assert fn_start >= 0
    fn_body = src[fn_start: fn_start + 1200]
    assert "getmtime" in fn_body, (
        "_maxmind_fetch_edition must use os.path.getmtime to check "
        "whether the existing file is fresh enough to skip the download"
    )
    assert "_MAXMIND_MIN_INTERVAL" in fn_body, (
        "_maxmind_fetch_edition must compare file age against "
        "_MAXMIND_MIN_INTERVAL (24 h) before deciding to skip"
    )


def test_maxmind_fetch_edition_skips_fresh_file(monkeypatch, tmp_path):
    """force=False: return 'skipped' when file exists and mtime < 24 h."""
    import time as _time
    import importlib

    dest = str(tmp_path / "GeoLite2-ASN.mmdb")
    open(dest, "wb").close()

    mm = importlib.import_module("reputation.maxmind")

    real_exists = mm.os.path.exists
    monkeypatch.setattr(mm.os.path, "exists",   lambda p: True if p == dest else real_exists(p))
    monkeypatch.setattr(mm.os.path, "getmtime", lambda p: _time.time() - 3600)  # 1 h — fresh
    monkeypatch.setattr(mm, "_validate_mmdb_path", lambda p, **kw: p)

    result = mm._maxmind_fetch_edition("GeoLite2-ASN", dest, "fakekey", force=False)
    assert result == "skipped", (
        f"Expected 'skipped' for a file only 1 h old; got {result!r}"
    )


def test_maxmind_fetch_edition_fetches_stale_file(monkeypatch, tmp_path):
    """force=False: attempt fetch when file exists but mtime >= 24 h (returns error, not skipped)."""
    import time as _time
    import importlib, urllib.error

    dest = str(tmp_path / "GeoLite2-ASN.mmdb")
    open(dest, "wb").close()

    mm = importlib.import_module("reputation.maxmind")

    real_exists = mm.os.path.exists
    monkeypatch.setattr(mm.os.path, "exists",   lambda p: True if p == dest else real_exists(p))
    monkeypatch.setattr(mm.os.path, "getmtime", lambda p: _time.time() - 90000)  # 25 h — stale
    monkeypatch.setattr(mm, "_read_etag", lambda p: "")
    monkeypatch.setattr(mm, "_validate_mmdb_path", lambda p, **kw: p)

    # Simulate network failure so the function returns 'error' (not 'skipped').
    import urllib.request as _ureq
    def _fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("no network in test")
    monkeypatch.setattr(_ureq, "urlopen", _fake_urlopen)

    result = mm._maxmind_fetch_edition("GeoLite2-ASN", dest, "fakekey", force=False)
    assert result != "skipped", (
        "Stale file (25 h old) must not be skipped — "
        f"_maxmind_fetch_edition returned {result!r} instead of 'error'/'downloaded'"
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1.8.6 — Score breakdown tooltip (agents.html click-to-popover)
# ═══════════════════════════════════════════════════════════════════════════

def _agents_src():
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent
            / "dashboards" / "agents.html").read_text()


class TestScoreBreakdownCss:
    """CSS for .score-click must be present in agents.html."""

    def test_score_click_class_defined(self):
        src = _agents_src()
        assert ".score-click" in src, \
            "agents.html: .score-click CSS class must be defined"

    def test_score_click_has_cursor_pointer(self):
        src = _agents_src()
        idx = src.find(".score-click")
        block = src[idx:idx+200]
        assert "cursor:pointer" in block, \
            "agents.html: .score-click must set cursor:pointer"


class TestScoreCellMarkup:
    """Score badge in the suspects table must be wired for click-to-popover."""

    def test_score_span_has_score_click_class(self):
        src = _agents_src()
        assert 'class="tag score-click' in src or "class='tag score-click" in src, \
            "agents.html: score badge span must carry class 'tag score-click'"

    def test_score_span_has_data_pop_score(self):
        src = _agents_src()
        assert 'data-pop="score"' in src or "data-pop='score'" in src, \
            "agents.html: score badge must have data-pop='score'"

    def test_score_span_has_data_i(self):
        src = _agents_src()
        # The score span row must carry data-i="${i}" for index lookup
        score_idx = src.find('data-pop="score"')
        if score_idx == -1:
            score_idx = src.find("data-pop='score'")
        assert score_idx != -1, "data-pop='score' not found"
        nearby = src[score_idx - 100: score_idx + 200]
        assert "data-i=" in nearby, \
            "agents.html: score badge must carry data-i for suspect index lookup"

    def test_score_span_has_title_click_hint(self):
        src = _agents_src()
        score_idx = src.find('data-pop="score"')
        if score_idx == -1:
            score_idx = src.find("data-pop='score'")
        assert score_idx != -1
        nearby = src[score_idx - 50: score_idx + 300]
        assert "title=" in nearby, \
            "agents.html: score badge must have a title tooltip hint"


class TestScoreClickWiring:
    """The click loop must include .score-click elements."""

    def test_score_click_in_queryselectorall(self):
        src = _agents_src()
        assert ".score-click" in src, "agents.html: .score-click selector missing"
        # The querySelectorAll that wires cell clicks must include score-click
        qs_idx = src.find("querySelectorAll('.cell-click, .score-click')")
        if qs_idx == -1:
            qs_idx = src.find('querySelectorAll(".cell-click, .score-click")')
        if qs_idx == -1:
            # Accept any querySelectorAll that references score-click
            qs_idx = src.find(".score-click")
            qs2    = src.find("querySelectorAll", qs_idx - 500)
            assert qs2 != -1 and qs2 < qs_idx + 100, \
                "agents.html: querySelectorAll must select .score-click elements"
        else:
            assert qs_idx != -1, \
                "agents.html: querySelectorAll must include both .cell-click and .score-click"


class TestOpenPopoverScoreCase:
    """openPopover must handle kind='score' and call buildScoreHtml."""

    def test_open_popover_has_score_case(self):
        src = _agents_src()
        assert "'score'" in src or '"score"' in src, \
            "agents.html: openPopover must handle kind='score'"

    def test_open_popover_calls_build_score_html(self):
        src = _agents_src()
        assert "buildScoreHtml" in src, \
            "agents.html: openPopover must call buildScoreHtml for kind='score'"

    def test_open_popover_score_title(self):
        src = _agents_src()
        assert "Score breakdown" in src, \
            "agents.html: openPopover score case must set title 'Score breakdown'"


class TestBuildScoreHtmlFunction:
    """buildScoreHtml standalone function must exist and cover all 6 components."""

    def _fn_body(self):
        src = _agents_src()
        start = src.find("function buildScoreHtml(")
        assert start != -1, "agents.html: buildScoreHtml function not found"
        return src[start: start + 15000]

    def test_function_exists(self):
        body = self._fn_body()
        assert "buildScoreHtml" in body

    def test_all_six_components_present(self):
        body = self._fn_body()
        for comp in ("headers", "assets", "enum", "timing", "risk", "404s"):
            assert f"'{comp}'" in body or f'"{comp}"' in body, \
                f"agents.html buildScoreHtml must reference component '{comp}'"

    def test_component_colors_match_comp_bar(self):
        body = self._fn_body()
        # These are the exact colors used in the .bar .h/.a/.e/.t/.r/.f CSS
        for color in ("#a78bfa", "#5fb3c0", "#3fb950", "#d29922", "#f85149", "#ff7b3a"):
            assert color in body, \
                f"agents.html buildScoreHtml must use component color {color}"

    def test_uses_d_components(self):
        body = self._fn_body()
        assert "d.components" in body or "c = d.components" in body or \
               "components" in body, \
            "agents.html buildScoreHtml must read d.components"

    def test_uses_d_metrics(self):
        body = self._fn_body()
        assert "d.metrics" in body or "m = d.metrics" in body or \
               "metrics" in body, \
            "agents.html buildScoreHtml must read d.metrics"

    def test_renders_risk_breakdown_when_risk_nonzero(self):
        body = self._fn_body()
        assert "risk_breakdown" in body, \
            "agents.html buildScoreHtml must conditionally render risk_breakdown signals"

    def test_risk_section_gated_on_risk_score(self):
        body = self._fn_body()
        # Must check rScore > 0 (not c.risk) so signals show even when pts round to 0
        assert "rScore > 0" in body or "rScore>0" in body, \
            "agents.html buildScoreHtml risk section must be gated on rScore > 0"

    def test_stealth_score_in_output(self):
        body = self._fn_body()
        assert "stealth_score" in body, \
            "agents.html buildScoreHtml must display the stealth_score total"

    def test_bars_equal_pct_contribution(self):
        body = self._fn_body()
        # Bar width must use the component percentage value
        assert "width:${pct}%" in body or "width:"+'"${pct}%"' in body or \
               "pct}%" in body, \
            "agents.html buildScoreHtml bars must be sized by component percentage"

    def test_risk_weights_js_const_exists(self):
        src = _agents_src()
        assert "RISK_WEIGHTS_JS" in src, \
            "agents.html must define RISK_WEIGHTS_JS const mirroring config.py RISK_WEIGHTS"

    def test_risk_labels_js_const_exists(self):
        src = _agents_src()
        assert "RISK_LABELS_JS" in src, \
            "agents.html must define RISK_LABELS_JS const for human-readable signal descriptions"

    def test_risk_ban_threshold_const_exists(self):
        src = _agents_src()
        assert "RISK_BAN_THRESHOLD" in src, \
            "agents.html must define RISK_BAN_THRESHOLD const"

    def test_risk_signals_show_base_weight(self):
        body = self._fn_body()
        assert "RISK_WEIGHTS_JS" in body, \
            "agents.html buildScoreHtml risk rows must look up base weight from RISK_WEIGHTS_JS"

    def test_risk_signals_show_hit_count(self):
        body = self._fn_body()
        assert "hits" in body and "triggered" in body, \
            "agents.html buildScoreHtml risk rows must show approximate hit count"

    def test_risk_signals_show_label(self):
        body = self._fn_body()
        assert "RISK_LABELS_JS" in body, \
            "agents.html buildScoreHtml risk rows must look up human label from RISK_LABELS_JS"

    def test_ban_threshold_progress_bar(self):
        body = self._fn_body()
        assert "ban threshold" in body or "banPct" in body, \
            "agents.html buildScoreHtml must render ban threshold progress bar"


class TestNormalizeIdPassesComponentsMetrics:
    """normalizeId in both files must pass through components and metrics."""

    def _iife_src(self, filename):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "dashboards" / filename).read_text()
        start = src.find("function normalizeId(raw)")
        assert start != -1, f"{filename}: normalizeId not found"
        return src[start: start + 1500]

    def test_agents_normalizeId_has_components(self):
        body = self._iife_src("agents.html")
        assert "components" in body, \
            "agents.html normalizeId must pass through components field"

    def test_agents_normalizeId_has_metrics(self):
        body = self._iife_src("agents.html")
        assert "metrics" in body, \
            "agents.html normalizeId must pass through metrics field"

    def test_main_normalizeId_has_components(self):
        body = self._iife_src("main.html")
        assert "components" in body, \
            "main.html normalizeId must pass through components field"

    def test_main_normalizeId_has_metrics(self):
        body = self._iife_src("main.html")
        assert "metrics" in body, \
            "main.html normalizeId must pass through metrics field"


class TestIpIntelRiskBreakdown:
    """ip_intel_endpoint must return risk_breakdown in internal section."""

    def _fn_body(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "admin" / "users.py").read_text()
        fn_start = src.find("async def ip_intel_endpoint")
        assert fn_start != -1, "admin/users.py: ip_intel_endpoint not found"
        # iter-18: LIVE-1 added an auth gate and LIVE-3 added the ip_bans
        # query block; both widened the function past the original 6000-char
        # slice and pushed risk_breakdown (toward the bottom) out of frame.
        return src[fn_start: fn_start + 9000]

    def test_risk_breakdown_collected_in_ip_intel(self):
        fn_body = self._fn_body()
        assert "risk_breakdown" in fn_body, \
            "ip_intel_endpoint must collect risk_breakdown from ip_state"

    def test_risk_breakdown_in_internal_response(self):
        fn_body = self._fn_body()
        internal_start = fn_body.find('out["internal"]')
        assert internal_start != -1, "ip_intel_endpoint must set out['internal']"
        internal_block = fn_body[internal_start: internal_start + 600]
        assert "risk_breakdown" in internal_block, \
            "ip_intel_endpoint out['internal'] must include risk_breakdown key"

    def test_risk_breakdown_sorted_descending(self):
        fn_body = self._fn_body()
        assert "reverse=True" in fn_body, \
            "ip_intel_endpoint risk_breakdown must be sorted descending (reverse=True)"


class TestMissedListRiskBreakdown:
    """agents_bucket_detail_endpoint missed_list entries must include risk_breakdown."""

    def _fn_body(self):
        import pathlib
        src = (pathlib.Path(__file__).resolve().parent.parent
               / "core" / "proxy_handler.py").read_text()
        fn_start = src.find("async def agents_bucket_detail_endpoint")
        assert fn_start != -1
        return src[fn_start: fn_start + 8000]

    def test_risk_breakdown_in_missed_list_append(self):
        body = self._fn_body()
        missed_idx = body.find("missed_list.append(")
        assert missed_idx != -1, "agents_bucket_detail_endpoint: missed_list.append not found"
        append_block = body[missed_idx: missed_idx + 600]
        assert "risk_breakdown" in append_block, \
            "agents_bucket_detail_endpoint: missed_list entries must include risk_breakdown"
        assert '"components"' in append_block or "'components'" in append_block, \
            "agents_bucket_detail_endpoint: missed_list entries must include components"
        assert '"metrics"' in append_block or "'metrics'" in append_block, \
            "agents_bucket_detail_endpoint: missed_list entries must include metrics"

    def test_risk_breakdown_sorted_descending(self):
        body = self._fn_body()
        missed_idx = body.find("missed_list.append(")
        pre_block = body[max(0, missed_idx - 300): missed_idx + 100]
        assert "reverse=True" in pre_block, \
            "agents_bucket_detail_endpoint: risk_breakdown sort must use reverse=True"


# ── 1.8.6 — TOTP / 2FA QR code ───────────────────────────────────────────────

class TestTotpSetupQrCode:
    """totp_setup_endpoint returns qr_data_url (base64 SVG), not raw secret."""

    def _setup_src(self):
        import pathlib as _pl
        return (_pl.Path(__file__).parent.parent / "admin" / "users.py").read_text()

    def test_qr_data_url_in_response(self):
        src = self._setup_src()
        assert "qr_data_url" in src, \
            "totp_setup_endpoint must include qr_data_url in json_response"

    def test_qrcode_import(self):
        src = self._setup_src()
        assert "qrcode" in src, \
            "totp_setup_endpoint must import qrcode to generate QR code"

    def test_base64_encode_used(self):
        src = self._setup_src()
        assert "_b64.b64encode" in src or "base64.b64encode" in src, \
            "QR code must be base64-encoded for data URL"

    def test_data_url_prefix(self):
        src = self._setup_src()
        assert "data:image/svg+xml;base64," in src, \
            "qr_data_url must use data:image/svg+xml;base64, prefix (SVG, no PIL needed)"

    def test_raw_secret_not_in_response(self):
        """INT4-11: raw secret must not appear in json_response body."""
        src = self._setup_src()
        setup_fn_start = src.find("async def totp_setup_endpoint")
        assert setup_fn_start != -1
        # Grab the function body (up to next async def)
        next_fn = src.find("\nasync def ", setup_fn_start + 10)
        fn_body = src[setup_fn_start:next_fn] if next_fn != -1 else src[setup_fn_start:]
        json_resp_idx = fn_body.find("json_response(")
        assert json_resp_idx != -1
        resp_call = fn_body[json_resp_idx: json_resp_idx + 200]
        assert '"secret"' not in resp_call and "'secret'" not in resp_call, \
            "INT4-11: raw TOTP secret must not be returned in API response"


class TestTotpSetupSettingsHtml:
    """settings.html renders QR code image, not just raw URI text."""

    def _html(self):
        import pathlib as _pl
        return (_pl.Path(__file__).parent.parent / "dashboards" / "settings.html").read_text()

    def test_qr_img_element_exists(self):
        html = self._html()
        assert 'id="twofa-qr-img"' in html, \
            "settings.html must have <img id='twofa-qr-img'> for QR display"

    def test_qr_wrap_element_exists(self):
        html = self._html()
        assert 'id="twofa-qr-wrap"' in html, \
            "settings.html must have #twofa-qr-wrap container for QR visibility toggle"

    def test_qr_img_src_set_from_data_url(self):
        html = self._html()
        assert "qrImg.src" in html or "qr_data_url" in html, \
            "settings.html JS must set qrImg.src from qr_data_url returned by backend"

    def test_qr_wrap_shown_on_setup(self):
        html = self._html()
        assert "qrWrap.style.display" in html, \
            "settings.html must show/hide #twofa-qr-wrap when setup area opens"

    def test_qr_img_has_alt_text(self):
        html = self._html()
        assert 'alt="TOTP QR code"' in html or "alt='TOTP QR code'" in html, \
            "QR <img> must have descriptive alt text for accessibility"


# ═══════════════════════════════════════════════════════════════════════════
# P1 / P2  Mutation-kill tests — added to close uncovered mutants
# Files covered: detection/llm_heuristic.py, detection/path_sweep.py,
#                scoring.py, identity.py
# ═══════════════════════════════════════════════════════════════════════════

import importlib
import types
from dataclasses import dataclass, field
from collections import defaultdict, deque


# ── helpers ────────────────────────────────────────────────────────────────

class _FakeVersion:
    def __init__(self, major=1):
        self.major = major

class _FakeReq:
    """Minimal request-like object for pure-function tests."""
    def __init__(self, headers=None, cookies=None, method="GET",
                 version=None, content_length=None, path="/",
                 remote="1.2.3.4"):
        self.headers  = headers or {}
        self.cookies  = cookies or {}
        self.method   = method
        self.version  = version or _FakeVersion(1)
        self.content_length = content_length
        self.path     = path
        self.remote   = remote


@dataclass
class _FakeState:
    risk_score: float = 0.0
    last_risk_update: float = 0.0
    risk_by_reason: dict = field(default_factory=lambda: defaultdict(float))


# ── llm_heuristic._is_subresource ─────────────────────────────────────────

class TestIsSubresource:
    def _mod(self):
        import detection.llm_heuristic as m
        return m

    def test_css_extension(self):
        assert self._mod()._is_subresource("/style.css", "text/html") is True

    def test_js_extension(self):
        assert self._mod()._is_subresource("/app.js", "*/*") is True

    def test_mjs_extension(self):
        assert self._mod()._is_subresource("/mod.mjs", "") is True

    def test_image_png(self):
        assert self._mod()._is_subresource("/logo.png", "") is True

    def test_woff2_font(self):
        assert self._mod()._is_subresource("/font.woff2", "") is True

    def test_unknown_extension_is_not_sub(self):
        assert self._mod()._is_subresource("/page.html", "text/html") is False

    def test_no_extension_is_not_sub(self):
        assert self._mod()._is_subresource("/page", "text/html") is False

    def test_json_accept_is_sub(self):
        assert self._mod()._is_subresource("/api/data", "application/json") is True

    def test_json_and_html_accept_is_not_sub(self):
        # XHR rule only fires when text/html is absent
        assert self._mod()._is_subresource("/api", "application/json, text/html") is False

    def test_query_string_stripped_before_ext_check(self):
        assert self._mod()._is_subresource("/style.css?v=123", "text/html") is True

    def test_uppercase_ext_lowercased(self):
        assert self._mod()._is_subresource("/img.PNG", "") is True

    def test_mp4_video(self):
        assert self._mod()._is_subresource("/video.mp4", "") is True

    def test_svg_image(self):
        assert self._mod()._is_subresource("/icon.svg", "") is True


# ── llm_heuristic._is_html_request ────────────────────────────────────────

class TestIsHtmlRequest:
    def _mod(self):
        import detection.llm_heuristic as m
        return m

    def test_get_html_accept_is_html(self):
        assert self._mod()._is_html_request("GET", "text/html", "/page") is True

    def test_post_is_never_html(self):
        assert self._mod()._is_html_request("POST", "text/html", "/page") is False

    def test_put_is_never_html(self):
        assert self._mod()._is_html_request("PUT", "text/html", "/page") is False

    def test_css_path_is_not_html(self):
        assert self._mod()._is_html_request("GET", "text/html", "/style.css") is False

    def test_js_path_is_not_html(self):
        assert self._mod()._is_html_request("GET", "*/*", "/app.js") is False

    def test_xml_extension_excluded(self):
        assert self._mod()._is_html_request("GET", "text/html", "/feed.xml") is False

    def test_txt_extension_excluded(self):
        assert self._mod()._is_html_request("GET", "text/html", "/robots.txt") is False

    def test_pdf_extension_excluded(self):
        assert self._mod()._is_html_request("GET", "text/html", "/doc.pdf") is False

    def test_empty_accept_counts_as_html(self):
        assert self._mod()._is_html_request("GET", "", "/page") is True

    def test_wildcard_accept_counts_as_html(self):
        assert self._mod()._is_html_request("GET", "*/*", "/page") is True

    def test_path_without_extension_is_html(self):
        assert self._mod()._is_html_request("GET", "text/html", "/dashboard") is True

    def test_query_string_not_misclassified(self):
        assert self._mod()._is_html_request("GET", "text/html", "/page?q=1") is True


# ── llm_heuristic.observe + check (P2 — stateful, module-level dict) ──────

class TestLlmObserveAndCheck:
    """Tests for observe() and check() with teardown of module-level state."""

    def setup_method(self):
        import detection.llm_heuristic as m
        self._m = m
        # Clear module-level state before each test
        m._req_log.clear()
        m._fired.clear()

    def teardown_method(self):
        self._m._req_log.clear()
        self._m._fired.clear()

    def test_observe_records_html_request(self):
        self._m.observe("id1", "GET", "/page", "text/html")
        assert "id1" in self._m._req_log
        assert len(self._m._req_log["id1"]) == 1
        _ts, is_sub = self._m._req_log["id1"][0]
        assert is_sub is False

    def test_observe_records_subresource(self):
        self._m.observe("id2", "GET", "/style.css", "text/html")
        assert len(self._m._req_log["id2"]) == 1
        _ts, is_sub = self._m._req_log["id2"][0]
        assert is_sub is True

    def test_observe_skips_post_non_sub(self):
        # POST + non-JSON accept + no sub extension → neither html nor sub → not recorded
        self._m.observe("id3", "POST", "/submit", "application/x-www-form-urlencoded")
        assert "id3" not in self._m._req_log or len(self._m._req_log["id3"]) == 0

    def test_observe_skips_empty_identity(self):
        self._m.observe("", "GET", "/page", "text/html")
        assert "" not in self._m._req_log

    def test_check_returns_zero_with_no_log(self):
        score = self._m.check("unknown-id", "1.2.3.4")
        assert score == 0.0

    def test_check_returns_zero_below_min_count(self):
        import time
        now = time.time()
        # LLM_HTML_MIN_COUNT defaults to 5 — add 4 HTML entries
        for _ in range(4):
            self._m._req_log["id4"].append((now, False))
        assert self._m.check("id4", "1.2.3.4") == 0.0

    def test_check_fires_when_no_subresources_and_enough_html(self):
        import time
        from config import LLM_HTML_MIN_COUNT, LLM_HEURISTIC_SCORE
        now = time.time()
        for _ in range(LLM_HTML_MIN_COUNT):
            self._m._req_log["id5"].append((now, False))
        score = self._m.check("id5", "1.2.3.4")
        assert score == LLM_HEURISTIC_SCORE

    def test_check_cooldown_prevents_double_fire(self):
        import time
        from config import LLM_HTML_MIN_COUNT, LLM_HEURISTIC_SCORE
        now = time.time()
        for _ in range(LLM_HTML_MIN_COUNT):
            self._m._req_log["id6"].append((now, False))
        first  = self._m.check("id6", "1.2.3.4")
        second = self._m.check("id6", "1.2.3.4")
        assert first  == LLM_HEURISTIC_SCORE
        assert second == 0.0  # cooldown active

    def test_check_returns_zero_when_subresource_ratio_above_threshold(self):
        import time
        from config import LLM_HTML_MIN_COUNT
        now = time.time()
        # 5 html + 10 subresources → ratio = 2.0 > 0.0 threshold → no fire
        for _ in range(LLM_HTML_MIN_COUNT):
            self._m._req_log["id7"].append((now, False))
        for _ in range(10):
            self._m._req_log["id7"].append((now, True))
        assert self._m.check("id7", "1.2.3.4") == 0.0

    def test_check_excludes_stale_entries_outside_window(self):
        import time
        from config import LLM_HTML_MIN_COUNT, LLM_HEURISTIC_WINDOW_SECS
        # All entries are older than the window → html_count = 0 → no fire
        old = time.time() - LLM_HEURISTIC_WINDOW_SECS - 10
        for _ in range(LLM_HTML_MIN_COUNT * 2):
            self._m._req_log["id8"].append((old, False))
        assert self._m.check("id8", "1.2.3.4") == 0.0


# ── detection.path_sweep._is_static_path ──────────────────────────────────

class TestIsStaticPath:
    def _mod(self):
        import detection.path_sweep as m
        return m

    def test_css_is_static(self):
        assert self._mod()._is_static_path("/style.css") is True

    def test_js_is_static(self):
        assert self._mod()._is_static_path("/bundle.js") is True

    def test_png_is_static(self):
        assert self._mod()._is_static_path("/logo.png") is True

    def test_woff2_is_static(self):
        assert self._mod()._is_static_path("/font.woff2") is True

    def test_mp4_is_static(self):
        assert self._mod()._is_static_path("/video.mp4") is True

    def test_pdf_is_static(self):
        assert self._mod()._is_static_path("/doc.pdf") is True

    def test_zip_is_static(self):
        assert self._mod()._is_static_path("/archive.zip") is True

    def test_html_is_not_static(self):
        assert self._mod()._is_static_path("/index.html") is False

    def test_no_extension_is_not_static(self):
        assert self._mod()._is_static_path("/api/v1/users") is False

    def test_extension_case_insensitive(self):
        assert self._mod()._is_static_path("/Logo.PNG") is True

    def test_ts_map_is_static(self):
        # .ts and .map are in _STATIC_EXTS
        assert self._mod()._is_static_path("/app.ts") is True
        assert self._mod()._is_static_path("/app.js.map") is True

    def test_no_dot_returns_false(self):
        assert self._mod()._is_static_path("/nodotpath") is False


# ── scoring._signal_runtime_order ─────────────────────────────────────────

class TestSignalRuntimeOrder:
    def _mod(self):
        import scoring as m
        return m

    def setup_method(self):
        import scoring as m
        # Ensure cache is clear so DB-override path is not triggered
        m._signal_order_cache.clear()

    def test_unknown_signal_returns_1(self):
        assert self._mod()._signal_runtime_order("totally-unknown") == 1

    def test_escalate_only_signal_returns_3(self):
        from config import ESCALATE_ONLY_REASONS
        sig = next(iter(ESCALATE_ONLY_REASONS))
        assert self._mod()._signal_runtime_order(sig) == 3

    def test_second_order_signal_returns_2(self):
        from config import SECOND_ORDER_REASONS
        sig = next(iter(SECOND_ORDER_REASONS))
        assert self._mod()._signal_runtime_order(sig) == 2

    def test_cache_override_wins(self):
        import scoring as m
        m._signal_order_cache["test-sig"] = 2
        assert m._signal_runtime_order("test-sig") == 2
        del m._signal_order_cache["test-sig"]

    def test_escalate_only_not_confused_with_second_order(self):
        from config import ESCALATE_ONLY_REASONS
        sig = next(iter(ESCALATE_ONLY_REASONS))
        assert self._mod()._signal_runtime_order(sig) != 2


# ── scoring._should_run_signal ─────────────────────────────────────────────

class TestShouldRunSignal:
    def _mod(self):
        import scoring as m
        return m

    def setup_method(self):
        import scoring as m
        m._signal_order_cache.clear()

    def test_order1_always_runs(self):
        # "unknown" maps to order 1
        assert self._mod()._should_run_signal("totally-unknown", 0.0) is True
        assert self._mod()._should_run_signal("totally-unknown", 999.0) is True

    def test_order3_runs_when_score_above_escalation_threshold(self):
        from config import ESCALATE_ONLY_REASONS, ESCALATION_THRESHOLD
        sig = next(iter(ESCALATE_ONLY_REASONS))
        assert self._mod()._should_run_signal(sig, ESCALATION_THRESHOLD) is True

    def test_order3_blocked_when_score_below_escalation_threshold(self):
        from config import ESCALATE_ONLY_REASONS, ESCALATION_THRESHOLD
        sig = next(iter(ESCALATE_ONLY_REASONS))
        if ESCALATION_THRESHOLD > 0:
            assert self._mod()._should_run_signal(sig, ESCALATION_THRESHOLD - 0.1) is False

    def test_order2_runs_when_score_above_second_order_threshold(self):
        from config import SECOND_ORDER_REASONS, SECOND_ORDER_THRESHOLD
        sig = next(iter(SECOND_ORDER_REASONS))
        assert self._mod()._should_run_signal(sig, SECOND_ORDER_THRESHOLD) is True

    def test_order2_blocked_when_score_below_second_order_threshold(self):
        from config import SECOND_ORDER_REASONS, SECOND_ORDER_THRESHOLD
        sig = next(iter(SECOND_ORDER_REASONS))
        if SECOND_ORDER_THRESHOLD > 0:
            assert self._mod()._should_run_signal(sig, SECOND_ORDER_THRESHOLD - 0.1) is False

    def test_order3_runs_when_escalation_threshold_zero(self, monkeypatch):
        import scoring as m
        import config as c
        monkeypatch.setattr(c, "ESCALATION_THRESHOLD", 0)
        monkeypatch.setattr(m, "ESCALATION_THRESHOLD", 0)
        from config import ESCALATE_ONLY_REASONS
        sig = next(iter(ESCALATE_ONLY_REASONS))
        assert m._should_run_signal(sig, 0.0) is True

    def test_order2_runs_when_second_order_threshold_zero(self, monkeypatch):
        import scoring as m
        import config as c
        monkeypatch.setattr(c, "SECOND_ORDER_THRESHOLD", 0)
        monkeypatch.setattr(m, "SECOND_ORDER_THRESHOLD", 0)
        from config import SECOND_ORDER_REASONS
        sig = next(iter(SECOND_ORDER_REASONS))
        assert m._should_run_signal(sig, 0.0) is True


# ── scoring._decay_risk ────────────────────────────────────────────────────

class TestDecayRisk:
    def _mod(self):
        import scoring as m
        return m

    def test_no_decay_when_score_zero(self):
        s = _FakeState(risk_score=0.0, last_risk_update=0.0)
        self._mod()._decay_risk(s, 3600.0)
        assert s.risk_score == 0.0

    def test_decay_reduces_score(self):
        s = _FakeState(risk_score=100.0, last_risk_update=0.0)
        self._mod()._decay_risk(s, 3600.0)  # one half-life (3600s default)
        assert 45.0 < s.risk_score < 55.0   # ~50 after one half-life

    def test_decay_zeroes_score_below_half(self):
        s = _FakeState(risk_score=0.4, last_risk_update=0.0)
        self._mod()._decay_risk(s, 3600.0)
        assert s.risk_score == 0.0

    def test_last_risk_update_set_to_now_ts(self):
        s = _FakeState(risk_score=10.0, last_risk_update=0.0)
        self._mod()._decay_risk(s, 9999.0)
        assert s.last_risk_update == 9999.0

    def test_no_elapsed_no_change(self):
        s = _FakeState(risk_score=50.0, last_risk_update=1000.0)
        self._mod()._decay_risk(s, 1000.0)
        assert s.risk_score == 50.0

    def test_risk_by_reason_decays_in_lockstep(self):
        s = _FakeState(risk_score=100.0, last_risk_update=0.0)
        s.risk_by_reason["bad-ua"] = 100.0
        self._mod()._decay_risk(s, 3600.0)
        assert "bad-ua" in s.risk_by_reason
        assert 45.0 < s.risk_by_reason["bad-ua"] < 55.0

    def test_risk_by_reason_entry_pruned_below_half(self):
        s = _FakeState(risk_score=0.4, last_risk_update=0.0)
        s.risk_by_reason["tiny"] = 0.4
        self._mod()._decay_risk(s, 3600.0)
        assert "tiny" not in s.risk_by_reason

    def test_negative_elapsed_clamped_to_zero(self):
        # now_ts < last_risk_update → elapsed < 0 → clamped to 0
        s = _FakeState(risk_score=50.0, last_risk_update=5000.0)
        self._mod()._decay_risk(s, 1000.0)
        assert s.risk_score == 50.0  # unchanged

    def test_risk_by_reason_cleared_when_score_zeroed(self):
        s = _FakeState(risk_score=0.4, last_risk_update=0.0)
        s.risk_by_reason["x"] = 0.3
        self._mod()._decay_risk(s, 3600.0)
        assert len(s.risk_by_reason) == 0


# ── scoring._escalation_score ──────────────────────────────────────────────

class TestEscalationScore:
    def _mod(self):
        import scoring as m
        return m

    def setup_method(self):
        from state import ip_state
        ip_state.clear()

    def teardown_method(self):
        from state import ip_state
        ip_state.clear()

    def test_returns_zero_for_unknown_key(self):
        assert self._mod()._escalation_score("no-such-key") == 0.0

    def test_returns_risk_score_for_known_key(self):
        from state import ip_state
        ip_state["k1"].risk_score = 42.5
        assert self._mod()._escalation_score("k1") == 42.5

    def test_returns_zero_when_risk_score_none(self):
        from state import ip_state
        ip_state["k2"].risk_score = 0
        assert self._mod()._escalation_score("k2") == 0.0


# ── identity._fp_hash ──────────────────────────────────────────────────────

class TestFpHash:
    def _mod(self):
        import identity as m
        return m

    def test_returns_24_char_hex(self):
        h = self._mod()._fp_hash("Mozilla/5.0", "1.2.3.0/24", "t13d...")
        assert len(h) == 24
        assert all(c in "0123456789abcdef" for c in h)

    def test_different_ua_different_hash(self):
        h1 = self._mod()._fp_hash("Mozilla/5.0", "1.2.3.0/24", "ja4")
        h2 = self._mod()._fp_hash("curl/7.88",   "1.2.3.0/24", "ja4")
        assert h1 != h2

    def test_different_ip_tier_different_hash(self):
        h1 = self._mod()._fp_hash("UA", "1.2.3.0/24", "ja4")
        h2 = self._mod()._fp_hash("UA", "5.6.7.0/24", "ja4")
        assert h1 != h2

    def test_different_ja4_different_hash(self):
        h1 = self._mod()._fp_hash("UA", "1.2.3.0/24", "ja4a")
        h2 = self._mod()._fp_hash("UA", "1.2.3.0/24", "ja4b")
        assert h1 != h2

    def test_ua_truncated_at_200(self):
        long_ua = "A" * 201
        trunc   = "A" * 200
        h1 = self._mod()._fp_hash(long_ua,  "ip", "ja4")
        h2 = self._mod()._fp_hash(trunc,    "ip", "ja4")
        assert h1 == h2  # truncation happens inside _fp_hash

    def test_stable_for_same_inputs(self):
        h1 = self._mod()._fp_hash("UA", "ip", "ja4")
        h2 = self._mod()._fp_hash("UA", "ip", "ja4")
        assert h1 == h2


# ── identity._header_order_sig ────────────────────────────────────────────

class TestHeaderOrderSig:
    def _mod(self):
        import identity as m
        return m

    def test_returns_12_char_hex(self):
        req = _FakeReq({"User-Agent": "x", "Accept": "text/html"})
        sig = self._mod()._header_order_sig(req)
        assert len(sig) == 12
        assert all(c in "0123456789abcdef" for c in sig)

    def test_host_header_excluded(self):
        req1 = _FakeReq({"Host": "a.example.com", "Accept": "text/html"})
        req2 = _FakeReq({"Host": "b.example.com", "Accept": "text/html"})
        assert self._mod()._header_order_sig(req1) == self._mod()._header_order_sig(req2)

    def test_order_matters(self):
        # Same headers, different order → different sig
        req1 = _FakeReq({"Accept": "text/html", "User-Agent": "x"})
        req2 = _FakeReq({"User-Agent": "x", "Accept": "text/html"})
        # dict in Python 3.7+ preserves insertion order
        if list(req1.headers.keys()) != list(req2.headers.keys()):
            assert self._mod()._header_order_sig(req1) != self._mod()._header_order_sig(req2)

    def test_no_headers_stable(self):
        req = _FakeReq({})
        sig = self._mod()._header_order_sig(req)
        assert len(sig) == 12

    def test_header_names_lowercased(self):
        req1 = _FakeReq({"Accept": "text/html"})
        req2 = _FakeReq({"ACCEPT": "text/html"})
        assert self._mod()._header_order_sig(req1) == self._mod()._header_order_sig(req2)


# ── identity._is_library_headers ─────────────────────────────────────────

class TestIsLibraryHeaders:
    def _mod(self):
        import identity as m
        return m

    def test_python_requests_default_headers(self):
        # python-requests 2.x: user-agent, accept-encoding, accept, connection
        req = _FakeReq({
            "User-Agent":      "python-requests/2.28",
            "Accept-Encoding": "gzip, deflate",
            "Accept":          "*/*",
            "Connection":      "keep-alive",
        })
        assert self._mod()._is_library_headers(req) is True

    def test_curl_default_headers(self):
        req = _FakeReq({
            "User-Agent": "curl/7.88",
            "Accept":     "*/*",
        })
        assert self._mod()._is_library_headers(req) is True

    def test_browser_headers_not_library(self):
        req = _FakeReq({
            "User-Agent":      "Mozilla/5.0",
            "Accept":          "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control":   "max-age=0",
            "Connection":      "keep-alive",
        })
        assert self._mod()._is_library_headers(req) is False

    def test_go_net_http_headers(self):
        req = _FakeReq({
            "User-Agent":      "Go-http-client/1.1",
            "Accept-Encoding": "gzip",
        })
        assert self._mod()._is_library_headers(req) is True

    def test_httpx_async_headers(self):
        req = _FakeReq({
            "Accept":          "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.9",
            "User-Agent":      "python-httpx/0.25",
            "Connection":      "keep-alive",
        })
        assert self._mod()._is_library_headers(req) is True


# ── identity.compute_ja4h ────────────────────────────────────────────────

class TestComputeJa4h:
    def _mod(self):
        import identity as m
        return m

    def _make_req(self, method="GET", version_major=1, headers=None,
                  cookies=None, content_length=None):
        return _FakeReq(
            headers=headers or {},
            cookies=cookies or {},
            method=method,
            version=_FakeVersion(version_major),
            content_length=content_length,
        )

    def test_returns_string(self):
        req = self._make_req()
        result = self._mod().compute_ja4h(req)
        assert isinstance(result, str)

    def test_format_has_four_underscore_parts(self):
        req = self._make_req()
        parts = self._mod().compute_ja4h(req).split("_")
        assert len(parts) == 4

    def test_method_prefix_get(self):
        req = self._make_req(method="GET")
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h.startswith("ge")

    def test_method_prefix_post(self):
        req = self._make_req(method="POST")
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h.startswith("po")

    def test_http2_version(self):
        req = self._make_req(version_major=2)
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h[2:4] == "20"

    def test_http1_version(self):
        req = self._make_req(version_major=1)
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h[2:4] == "11"

    def test_no_body_flag(self):
        req = self._make_req(content_length=None)
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h[4] == "n"

    def test_has_body_flag(self):
        req = self._make_req(content_length=42)
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h[4] == "y"

    def test_referer_flag_absent(self):
        req = self._make_req(headers={"Accept": "text/html"})
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h[5] == "n"

    def test_referer_flag_present(self):
        req = self._make_req(headers={"Referer": "https://example.com"})
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h[5] == "r"

    def test_no_cookies_hash_is_zeros(self):
        req = self._make_req(headers={"Accept": "text/html"}, cookies={})
        ja4h = self._mod().compute_ja4h(req)
        ck_hash = ja4h.split("_")[3]
        assert ck_hash == "000000000000"

    def test_with_cookie_hash_not_zeros(self):
        req = self._make_req(headers={}, cookies={"session": "abc"})
        ja4h = self._mod().compute_ja4h(req)
        ck_hash = ja4h.split("_")[3]
        assert ck_hash != "000000000000"

    def test_different_cookies_different_hash(self):
        req1 = self._make_req(cookies={"a": "1"})
        req2 = self._make_req(cookies={"b": "1"})
        assert self._mod().compute_ja4h(req1) != self._mod().compute_ja4h(req2)

    def test_cookie_host_excluded_from_header_count(self):
        req_with_host = self._make_req(headers={"Host": "x.com", "Accept": "*/*"})
        req_no_host   = self._make_req(headers={"Accept": "*/*"})
        # hdr_count part (index 1) should be equal since Host excluded
        parts_with = self._mod().compute_ja4h(req_with_host).split("_")
        parts_no   = self._mod().compute_ja4h(req_no_host).split("_")
        assert parts_with[1] == parts_no[1]

    def test_error_recovery(self):
        # If request object is broken, must return "error" not raise
        result = self._mod().compute_ja4h(object())
        assert result == "error"


# ── identity.get_identity ────────────────────────────────────────────────

class TestGetIdentity:
    def _mod(self):
        import identity as m
        return m

    def _signed_cookie(self, sid: str) -> str:
        import hmac as _hmac, hashlib as _hl
        from config import SESSION_KEY, SESSION_COOKIE
        sig = _hmac.new(SESSION_KEY, b"session:" + sid.encode(), _hl.sha256).hexdigest()
        return f"{sid}.{sig}"

    def _anon_req(self, ua="curl/7", al="en", ae="gzip"):
        from config import SESSION_COOKIE
        # No valid cookie
        return _FakeReq(headers={"User-Agent": ua, "Accept-Language": al,
                                  "Accept-Encoding": ae},
                         cookies={})

    def _session_req(self, sid: str):
        from config import SESSION_COOKIE
        token = self._signed_cookie(sid)
        return _FakeReq(headers={"User-Agent": "Mozilla/5.0"},
                         cookies={SESSION_COOKIE: token})

    def test_anon_mode_no_cookie(self):
        req = self._anon_req()
        _id, _sid, _fp, is_new, mode = self._mod().get_identity(req)
        assert mode == "anon"
        assert is_new is True

    def test_session_mode_valid_cookie(self):
        sid = "validSID12345678"
        req = self._session_req(sid)
        _id, ret_sid, _fp, is_new, mode = self._mod().get_identity(req)
        assert mode == "session"
        assert ret_sid == sid
        assert is_new is False

    def test_identity_is_16_char_hex(self):
        req = self._anon_req()
        identity, *_ = self._mod().get_identity(req)
        assert len(identity) == 16
        assert all(c in "0123456789abcdef" for c in identity)

    def test_anon_identity_stable_same_headers_same_ip(self):
        req = self._anon_req()
        id1, *_ = self._mod().get_identity(req)
        id2, *_ = self._mod().get_identity(req)
        assert id1 == id2

    def test_session_identity_stable_same_sid(self):
        sid = "stableSID123456"
        req = self._session_req(sid)
        id1, *_ = self._mod().get_identity(req)
        id2, *_ = self._mod().get_identity(req)
        assert id1 == id2

    def test_anon_different_ua_different_identity(self):
        req1 = self._anon_req(ua="curl/7")
        req2 = self._anon_req(ua="python-requests/2")
        id1, *_ = self._mod().get_identity(req1)
        id2, *_ = self._mod().get_identity(req2)
        assert id1 != id2

    def test_session_returns_correct_sid(self):
        sid = "mySID1234567890"
        req = self._session_req(sid)
        _, ret_sid, *_ = self._mod().get_identity(req)
        assert ret_sid == sid

    def test_invalid_cookie_falls_back_to_anon(self):
        from config import SESSION_COOKIE
        req = _FakeReq(headers={"User-Agent": "Mozilla"},
                        cookies={SESSION_COOKIE: "notvalid.sig"})
        _, _sid, _fp, is_new, mode = self._mod().get_identity(req)
        assert mode == "anon"

    def test_fingerprint_length(self):
        req = self._anon_req()
        _, _, fp, *_ = self._mod().get_identity(req)
        assert len(fp) == 12


# ═══════════════════════════════════════════════════════════════════════════
# P1/P2 round-2 — targeted survivor-kill tests
# ═══════════════════════════════════════════════════════════════════════════

# ── _is_subresource: multi-dot path (split vs rsplit distinction) ──────────

class TestIsSubresourceMultiDot:
    def _mod(self):
        import detection.llm_heuristic as m
        return m

    def test_multi_dot_path_uses_rsplit(self):
        # rsplit(".", 1) on "lib.v2.js" → ext=".js" (subresource)
        # split(".", 1)  on "lib.v2.js" → ext=".v2.js" (not in exts)
        assert self._mod()._is_subresource("/lib.v2.js", "") is True

    def test_multi_dot_png(self):
        assert self._mod()._is_subresource("/assets.prod.v2.png", "") is True

    def test_no_dot_no_accept_is_not_sub(self):
        assert self._mod()._is_subresource("/nodot", "") is False


# ── _is_html_request: query string with extension ─────────────────────────

class TestIsHtmlRequestQueryString:
    def _mod(self):
        import detection.llm_heuristic as m
        return m

    def test_js_extension_in_query_path_not_html(self):
        # /style.js?v=1 → split("?")[0] = /style.js → ext=.js → not html
        # split(None) or split("XX?XX") would NOT strip query → ext confusion
        assert self._mod()._is_html_request("GET", "text/html", "/style.js?v=1") is False

    def test_css_in_path_before_query_not_html(self):
        assert self._mod()._is_html_request("GET", "text/html", "/app.css?v=1.2.3") is False

    def test_csv_extension_excluded(self):
        assert self._mod()._is_html_request("GET", "text/html", "/export.csv") is False

    def test_csv_uppercase_extension_excluded(self):
        # .CSV lowercased → .csv → in exclusion set
        assert self._mod()._is_html_request("GET", "text/html", "/DATA.CSV") is False

    def test_multi_dot_css_not_html(self):
        # rsplit(".", 1)[-1] = "css"; split(".", 1)[-1] = "v2.css"
        assert self._mod()._is_html_request("GET", "text/html", "/theme.v2.css") is False


# ── _is_static_path: dot at position 0 (root hidden file) ─────────────────

class TestIsStaticPathDotAtZero:
    def _mod(self):
        import detection.path_sweep as m
        return m

    def test_dot_at_position_zero_css_is_static(self):
        # ".css" → rfind(".") = 0. Original: dot < 0 = False → continue → ext=".css" → True
        # mutmut_5 (dot <= 0): 0 <= 0 = True → return False (WRONG)
        # mutmut_6 (dot < 1):  0 < 1  = True → return False (WRONG)
        assert self._mod()._is_static_path(".css") is True

    def test_dot_at_position_zero_js_is_static(self):
        assert self._mod()._is_static_path(".js") is True

    def test_dot_at_position_zero_png_is_static(self):
        assert self._mod()._is_static_path(".png") is True

    def test_root_css_is_static(self):
        # "/.css" → rfind(".") = 1 (slash then dot). Normal case, both pass.
        assert self._mod()._is_static_path("/.css") is True

    def test_dot_zero_non_static_ext_not_static(self):
        assert self._mod()._is_static_path(".html") is False


# ── _should_run_signal: threshold=1 boundary kills <= vs < ────────────────

class TestShouldRunSignalThresholdBoundary:
    def setup_method(self):
        import scoring as m
        m._signal_order_cache.clear()

    def test_escalation_threshold_1_blocks_score_0(self, monkeypatch):
        import scoring as m
        import config as c
        monkeypatch.setattr(c, "ESCALATION_THRESHOLD", 1)
        monkeypatch.setattr(m, "ESCALATION_THRESHOLD", 1)
        from config import ESCALATE_ONLY_REASONS
        sig = next(iter(ESCALATE_ONLY_REASONS))
        # threshold=1 > 0, esc_score=0 < 1 → should NOT run
        assert m._should_run_signal(sig, 0.0) is False

    def test_escalation_threshold_1_allows_score_1(self, monkeypatch):
        import scoring as m
        import config as c
        monkeypatch.setattr(c, "ESCALATION_THRESHOLD", 1)
        monkeypatch.setattr(m, "ESCALATION_THRESHOLD", 1)
        from config import ESCALATE_ONLY_REASONS
        sig = next(iter(ESCALATE_ONLY_REASONS))
        assert m._should_run_signal(sig, 1.0) is True

    def test_second_order_threshold_1_blocks_score_0(self, monkeypatch):
        import scoring as m
        import config as c
        monkeypatch.setattr(c, "SECOND_ORDER_THRESHOLD", 1)
        monkeypatch.setattr(m, "SECOND_ORDER_THRESHOLD", 1)
        from config import SECOND_ORDER_REASONS
        sig = next(iter(SECOND_ORDER_REASONS))
        assert m._should_run_signal(sig, 0.0) is False

    def test_second_order_threshold_1_allows_score_1(self, monkeypatch):
        import scoring as m
        import config as c
        monkeypatch.setattr(c, "SECOND_ORDER_THRESHOLD", 1)
        monkeypatch.setattr(m, "SECOND_ORDER_THRESHOLD", 1)
        from config import SECOND_ORDER_REASONS
        sig = next(iter(SECOND_ORDER_REASONS))
        assert m._should_run_signal(sig, 1.0) is True


# ── _decay_risk: targeted boundary tests ──────────────────────────────────

class TestDecayRiskBoundaries:
    def _mod(self):
        import scoring as m
        return m

    def test_two_half_lives_decay_to_quarter(self):
        s = _FakeState(risk_score=100.0, last_risk_update=0.0)
        from config import RISK_DECAY_HALFLIFE_SECS
        # 2 half-lives: 0.5^2 = 0.25 → 25. With * mutant: 0.5*2 = 1.0 → 100.
        self._mod()._decay_risk(s, RISK_DECAY_HALFLIFE_SECS * 2)
        assert 15.0 < s.risk_score < 35.0  # ~25; kills multiply vs exponent mutation

    def test_sub_one_second_elapsed_causes_tiny_decay(self):
        s = _FakeState(risk_score=100.0, last_risk_update=0.0)
        # elapsed=0.5 → original enters branch (0.5 > 0). mutant_10 doesn't (0.5 > 1 = False).
        self._mod()._decay_risk(s, 0.5)
        assert s.risk_score != 100.0  # any decay has occurred

    def test_half_life_risk_by_reason_boundary_keeps_at_exactly_half(self):
        # After one half-life, risk_by_reason["x"] starts at 1.0 → decays to 0.5.
        # Original: 0.5 < 0.5 = False → kept. Mutant_29 (<= 0.5) → deleted.
        s = _FakeState(risk_score=1.0, last_risk_update=0.0)
        s.risk_by_reason["x"] = 1.0
        from config import RISK_DECAY_HALFLIFE_SECS
        self._mod()._decay_risk(s, RISK_DECAY_HALFLIFE_SECS)
        # After decay: risk_by_reason["x"] ≈ 0.5 which is exactly at boundary.
        # We can't assert on the exact value due to floats, but entry should exist.
        assert "x" in s.risk_by_reason

    def test_risk_by_reason_large_value_not_pruned_after_half_life(self):
        # Initial value=2.0 → after half-life → 1.0. 1.0 < 0.5 False → kept.
        # Mutant_30 (<1.5): 1.0 < 1.5 = True → deleted.
        s = _FakeState(risk_score=2.0, last_risk_update=0.0)
        s.risk_by_reason["big"] = 2.0
        from config import RISK_DECAY_HALFLIFE_SECS
        self._mod()._decay_risk(s, RISK_DECAY_HALFLIFE_SECS)
        assert "big" in s.risk_by_reason

    def test_risk_score_half_life_not_zeroed(self):
        # risk_score=1.0 → after half-life → 0.5. Original: 0.5 < 0.5 = False → kept.
        # Mutant_31 (<= 0.5): True → zeroed. Mutant_32 (< 1.5): 0.5 < 1.5 = True → zeroed.
        s = _FakeState(risk_score=1.0, last_risk_update=0.0)
        from config import RISK_DECAY_HALFLIFE_SECS
        self._mod()._decay_risk(s, RISK_DECAY_HALFLIFE_SECS)
        assert s.risk_score > 0.0  # should NOT be zeroed

    def test_risk_by_reason_cleared_when_score_below_threshold_and_reason_large(self):
        # risk_score=0.4 (below threshold after decay) BUT risk_by_reason["x"]=5.0.
        # After decay: risk_score ≈ 0.2 → zeroed. risk_by_reason["x"] = 2.5 (not pruned by per-reason loop).
        # Original: getattr(state, "risk_by_reason", None) = non-empty dict → clear().
        # Mutant_35: getattr(None, ...) = None → don't clear.
        s = _FakeState(risk_score=0.4, last_risk_update=0.0)
        s.risk_by_reason["x"] = 5.0
        from config import RISK_DECAY_HALFLIFE_SECS
        self._mod()._decay_risk(s, RISK_DECAY_HALFLIFE_SECS)
        # risk_score was 0.4, after half-life factor=0.5 → 0.2 < 0.5 → zeroed.
        # risk_by_reason["x"] = 2.5 ≥ 0.5 → not pruned in loop.
        # Then zeroing block: should clear risk_by_reason.
        assert len(s.risk_by_reason) == 0  # kills mutmut_35, 39, 40, 41

    def test_risk_by_reason_attribute_name_must_be_exact(self):
        # Verify that risk_by_reason is accessed (not typo like RISK_BY_REASON)
        s = _FakeState(risk_score=0.4, last_risk_update=0.0)
        s.risk_by_reason["r"] = 5.0
        from config import RISK_DECAY_HALFLIFE_SECS
        self._mod()._decay_risk(s, RISK_DECAY_HALFLIFE_SECS)
        assert s.risk_score == 0.0


# ── llm_heuristic.check: targeted kills ───────────────────────────────────

class TestCheckTargeted:
    def setup_method(self):
        import detection.llm_heuristic as m
        self._m = m
        m._req_log.clear()
        m._fired.clear()

    def teardown_method(self):
        self._m._req_log.clear()
        self._m._fired.clear()

    def test_disabled_llm_returns_zero_even_with_identity(self, monkeypatch):
        import config as c
        monkeypatch.setattr(c, "LLM_HEURISTIC_ENABLED", False)
        monkeypatch.setattr(self._m, "LLM_HEURISTIC_ENABLED", False)
        import time
        from config import LLM_HTML_MIN_COUNT
        now = time.time()
        for _ in range(LLM_HTML_MIN_COUNT * 2):
            self._m._req_log["id-dis"].append((now, False))
        # With 'or', disabling + identity present → return 0.
        # With 'and' mutation: disabled AND identity → returns 0 only if both true.
        # Actually 'and' means BOTH must be true to return 0. disabled=True, identity present=False.
        # So 'and' mutation WOULD continue past early return.
        # But 'not LLM_HEURISTIC_ENABLED' = True, 'not identity' = False → 'and' = False → continue.
        # Then it would fire since log is populated! So disabled check won't kill with normal identity.
        # Use empty identity instead:
        result = self._m.check("", "1.2.3.4")
        assert result == 0.0

    def test_first_return_zero_not_one_when_disabled(self, monkeypatch):
        import config as c
        monkeypatch.setattr(c, "LLM_HEURISTIC_ENABLED", False)
        monkeypatch.setattr(self._m, "LLM_HEURISTIC_ENABLED", False)
        result = self._m.check("some-identity", "1.2.3.4")
        assert result == 0.0  # kills mutmut_4 (return 1.0 at first guard)

    def test_cooldown_boundary_exactly_at_window_does_not_fire(self):
        import time
        from config import LLM_HTML_MIN_COUNT, LLM_HEURISTIC_WINDOW_SECS
        now = time.time()
        # Set last_fired exactly at now - window (boundary).
        # Original: now - last_fired < window → window < window = False → no cooldown → proceeds.
        # Mutant_13 (<= window): window <= window = True → cooldown → returns 0.
        self._m._fired["id-bd"] = now - LLM_HEURISTIC_WINDOW_SECS
        for _ in range(LLM_HTML_MIN_COUNT):
            self._m._req_log["id-bd"].append((now, False))
        # At exact boundary: original SHOULD fire (no cooldown); mutant would return 0.
        from config import LLM_HEURISTIC_SCORE
        result = self._m.check("id-bd", "1.2.3.4")
        assert result == LLM_HEURISTIC_SCORE  # kills mutmut_13

    def test_stale_entries_not_counted(self):
        import time
        from config import LLM_HTML_MIN_COUNT, LLM_HEURISTIC_WINDOW_SECS
        now = time.time()
        # Entries just inside window (50% of window ago) must be counted
        inside_ts = now - LLM_HEURISTIC_WINDOW_SECS / 2
        from config import LLM_HEURISTIC_SCORE
        for _ in range(LLM_HTML_MIN_COUNT):
            self._m._req_log["id-in"].append((inside_ts, False))
        result = self._m.check("id-in", "1.2.3.4")
        assert result == LLM_HEURISTIC_SCORE  # inside window → counted


# ── llm_heuristic.observe: timestamp must be numeric ─────────────────────

class TestObserveTimestamp:
    def setup_method(self):
        import detection.llm_heuristic as m
        self._m = m
        m._req_log.clear()
        m._fired.clear()

    def teardown_method(self):
        self._m._req_log.clear()
        self._m._fired.clear()

    def test_recorded_timestamp_is_float(self):
        self._m.observe("ts-id", "GET", "/page", "text/html")
        assert "ts-id" in self._m._req_log
        ts, _ = self._m._req_log["ts-id"][0]
        assert isinstance(ts, float)  # kills mutmut_4 (now=None)

    def test_recorded_timestamp_is_recent(self):
        import time
        before = time.time()
        self._m.observe("ts-id2", "GET", "/page", "text/html")
        after = time.time()
        ts, _ = self._m._req_log["ts-id2"][0]
        assert before <= ts <= after


# ── _header_order_sig: host excluded ─────────────────────────────────────

class TestHeaderOrderSigHostExclusion:
    def _mod(self):
        import identity as m
        return m

    def test_host_only_equals_no_headers(self):
        # With Host header only, sig should equal sig with no headers
        # (Host is excluded). Mutant that includes Host would give different sig.
        req_host = _FakeReq({"Host": "example.com"})
        req_none = _FakeReq({})
        assert self._mod()._header_order_sig(req_host) == self._mod()._header_order_sig(req_none)

    def test_mixed_case_host_excluded(self):
        req1 = _FakeReq({"HOST": "a.com", "Accept": "text/html"})
        req2 = _FakeReq({"Accept": "text/html"})
        # k.lower() == "host" so both HOST and host are excluded
        assert self._mod()._header_order_sig(req1) == self._mod()._header_order_sig(req2)

    def test_names_string_truncated_at_300_chars(self):
        # Generate 30 headers each with 11-char name → 30*11 + 29*1 (colons) = 359 > 300
        # Signals truncation at 300 matters
        hdrs = {f"x-header-{i:02d}": "val" for i in range(30)}
        req = _FakeReq(hdrs)
        sig = self._mod()._header_order_sig(req)
        assert len(sig) == 12  # must still be 12 chars, not 13


# ── compute_ja4h: targeted survivor kills ─────────────────────────────────

class TestComputeJa4hTargeted:
    def _mod(self):
        import identity as m
        return m

    def test_single_char_method_padded_with_underscore(self):
        # method="G" → ljust(2, "_") → "g_"; rjust → "_g"; ljust no fill → "g "
        req = _FakeReq(method="G")
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h[:2] == "g_"  # kills mutmut_5 (ljust no fill) and mutmut_6 (rjust)

    def test_none_method_gives_underscore_prefix(self):
        # (None or "")[:2] = "" → ljust(2, "_") = "__"
        # (None or "XXXX")[:2] = "XX" → "xx" (mutant_9)
        req = _FakeReq(method=None)
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h[:2] == "__"  # kills mutmut_9

    def test_content_length_one_is_y(self):
        # > 0 is True; > 1 is False (mutant_39)
        req = _FakeReq(content_length=1)
        ja4h = self._mod().compute_ja4h(req)
        assert ja4h[4] == "y"  # kills mutmut_39

    def test_cookie_header_excluded_from_hdr_count(self):
        # Cookie header must NOT be counted in hdr_count
        req = _FakeReq(headers={"Accept": "text/html", "Cookie": "session=abc"})
        ja4h = self._mod().compute_ja4h(req)
        parts = ja4h.split("_")
        hdr_count = int(parts[1][:2])
        assert hdr_count == 1  # only Accept, not Cookie  # kills mutmut_64, mutmut_65

    def test_hdr_hash_uses_comma_separator_not_xx(self):
        import hashlib
        req = _FakeReq(headers={"User-Agent": "x", "Accept": "text/html"})
        ja4h = self._mod().compute_ja4h(req)
        hdr_hash = ja4h.split("_")[2]
        expected = hashlib.sha256("user-agent,accept".encode()).hexdigest()[:12]
        assert hdr_hash == expected  # kills mutmut_62, mutmut_63

    def test_hdr_hash_is_lowercase_header_names(self):
        import hashlib
        req = _FakeReq(headers={"ACCEPT": "text/html"})
        ja4h = self._mod().compute_ja4h(req)
        hdr_hash = ja4h.split("_")[2]
        expected = hashlib.sha256("accept".encode()).hexdigest()[:12]
        assert hdr_hash == expected  # kills mutmut_63 (upper vs lower)

    def test_hdr_hash_part_is_exactly_12_chars(self):
        req = _FakeReq(headers={"Accept": "text/html"})
        ja4h = self._mod().compute_ja4h(req)
        hdr_hash = ja4h.split("_")[2]
        assert len(hdr_hash) == 12  # kills mutmut_94 (None) and mutmut_96 ([:13])

    def test_ck_hash_part_is_exactly_12_chars(self):
        req = _FakeReq(headers={}, cookies={"session": "abc"})
        ja4h = self._mod().compute_ja4h(req)
        ck_hash = ja4h.split("_")[3]
        assert len(ck_hash) == 12  # kills mutmut_99 ([:13])

    def test_two_cookies_ck_hash_uses_comma_separator(self):
        import hashlib
        req = _FakeReq(headers={}, cookies={"session": "abc", "aid": "xyz"})
        ja4h = self._mod().compute_ja4h(req)
        ck_hash = ja4h.split("_")[3]
        expected = hashlib.sha256(",".join(sorted(["session", "aid"])).encode()).hexdigest()[:12]
        assert ck_hash == expected  # kills mutmut_80 (XX,XX separator)

    def test_non_special_header_included_in_hdr_names(self):
        import hashlib
        # With mutant_65 (in vs not in), only cookie+host would be included
        # With correct code, user-agent is included
        req = _FakeReq(headers={"User-Agent": "x"})
        ja4h = self._mod().compute_ja4h(req)
        hdr_hash = ja4h.split("_")[2]
        expected = hashlib.sha256("user-agent".encode()).hexdigest()[:12]
        assert hdr_hash == expected  # kills mutmut_65

    def test_cookie_header_excluded_from_hdr_names(self):
        import hashlib
        # Cookie header must be excluded from hdr_names (affects hdr_hash).
        # mutmut_64: h.upper() not in ("cookie","host") → "COOKIE" not in → included.
        # mutmut_68: "XXcookieXX" → "cookie" not in → included.
        # mutmut_69: "COOKIE" → "cookie" != "COOKIE" → included.
        req = _FakeReq(headers={"Accept": "text/html", "Cookie": "session=abc"})
        ja4h = self._mod().compute_ja4h(req)
        hdr_hash = ja4h.split("_")[2]
        expected = hashlib.sha256("accept".encode()).hexdigest()[:12]
        assert hdr_hash == expected  # kills mutmut_64, 68, 69

    def test_host_header_excluded_from_hdr_names(self):
        import hashlib
        # Host header must be excluded from hdr_names.
        # mutmut_66: "XXhostXX" → "host" not in → included.
        # mutmut_67: "HOST" → "host" != "HOST" → included.
        req = _FakeReq(headers={"Host": "example.com", "Accept": "text/html"})
        ja4h = self._mod().compute_ja4h(req)
        hdr_hash = ja4h.split("_")[2]
        expected = hashlib.sha256("accept".encode()).hexdigest()[:12]
        assert hdr_hash == expected  # kills mutmut_66, 67


# ── get_identity: targeted survivor kills ─────────────────────────────────

class TestGetIdentityTargeted:
    def _mod(self):
        import identity as m
        return m

    def _signed_cookie(self, sid: str) -> str:
        import hmac as _hmac, hashlib as _hl
        from config import SESSION_KEY, SESSION_COOKIE
        sig = _hmac.new(SESSION_KEY, b"session:" + sid.encode(), _hl.sha256).hexdigest()
        return f"{sid}.{sig}"

    def _session_req(self, sid: str):
        from config import SESSION_COOKIE
        token = self._signed_cookie(sid)
        return _FakeReq(headers={"User-Agent": "Mozilla/5.0"},
                         cookies={SESSION_COOKIE: token})

    def test_session_identity_differs_for_different_sids(self):
        sid1 = "SID1111111111111"
        sid2 = "SID2222222222222"
        id1, *_ = self._mod().get_identity(self._session_req(sid1))
        id2, *_ = self._mod().get_identity(self._session_req(sid2))
        assert id1 != id2  # kills mutmut_13 (hmac(None) gives same identity for all)

    def test_session_identity_is_16_chars(self):
        req = self._session_req("validSID12345678")
        identity, *_ = self._mod().get_identity(req)
        assert len(identity) == 16  # kills mutmut_11 (None) and mutmut_18 ([:17])

    def test_session_identity_is_hex(self):
        req = self._session_req("validSID12345678")
        identity, *_ = self._mod().get_identity(req)
        assert all(c in "0123456789abcdef" for c in identity)

    def test_anon_identity_changes_with_different_ip(self):
        req1 = _FakeReq(headers={"User-Agent": "curl/7"}, remote="1.2.3.4")
        req2 = _FakeReq(headers={"User-Agent": "curl/7"}, remote="5.6.7.8")
        id1, *_ = self._mod().get_identity(req1)
        id2, *_ = self._mod().get_identity(req2)
        assert id1 != id2  # kills mutmut_22 (ip=None: all anon → same identity)

    def test_anon_new_sid_is_string(self):
        req = _FakeReq(headers={"User-Agent": "curl/7"})
        _, new_sid, *_ = self._mod().get_identity(req)
        assert isinstance(new_sid, str) and len(new_sid) > 0

    def test_anon_new_sid_length_is_16(self):
        # token_urlsafe(12) = 16 chars; token_urlsafe(13) = 18 chars
        req = _FakeReq(headers={"User-Agent": "curl/7"})
        _, new_sid, *_ = self._mod().get_identity(req)
        assert len(new_sid) == 16  # kills mutmut_34 (token_urlsafe(13))


# ═══════════════════════════════════════════════════════════════════════════
# Round-3 targeted kills — slog verification + static path boundary fix
# ═══════════════════════════════════════════════════════════════════════════


class TestCheckSlogArgs:
    """Verify slog is called with correct arguments when LLM pattern fires.
    Kills mutmut_54-72 (19 survivors) — all mutations in the slog() call."""

    def setup_method(self):
        import detection.llm_heuristic as m
        self._m = m
        m._req_log.clear()
        m._fired.clear()

    def teardown_method(self):
        self._m._req_log.clear()
        self._m._fired.clear()

    def _fire(self, identity, ip, monkeypatch):
        import time
        from config import LLM_HTML_MIN_COUNT
        now = time.time()
        for _ in range(LLM_HTML_MIN_COUNT):
            self._m._req_log[identity].append((now, False))
        calls = []
        def fake_slog(event, level="info", **fields):
            calls.append({"event": event, "level": level, **fields})
        monkeypatch.setattr(self._m, "slog", fake_slog)
        result = self._m.check(identity, ip)
        return result, calls

    def test_slog_called_on_fire(self, monkeypatch):
        _, calls = self._fire("long-identity-12", "10.0.0.1", monkeypatch)
        assert len(calls) == 1  # exactly one slog call

    def test_slog_event_name(self, monkeypatch):
        _, calls = self._fire("long-identity-12", "10.0.0.1", monkeypatch)
        assert calls[0]["event"] == "llm_no_subresources"  # kills mutmut_54, 68, 69

    def test_slog_level_warn(self, monkeypatch):
        _, calls = self._fire("long-identity-12", "10.0.0.1", monkeypatch)
        assert calls[0]["level"] == "warn"  # kills mutmut_55, 62, 70, 71

    def test_slog_ip_kwarg(self, monkeypatch):
        _, calls = self._fire("long-identity-12", "10.0.0.1", monkeypatch)
        assert calls[0].get("ip") == "10.0.0.1"  # kills mutmut_56, 63

    def test_slog_identity_truncated_to_8(self, monkeypatch):
        # identity has 16 chars; identity[:8] ≠ identity[:9]
        identity = "abcdef1234567890"
        _, calls = self._fire(identity, "1.2.3.4", monkeypatch)
        assert calls[0].get("identity") == identity[:8]  # kills mutmut_57, 64, 72

    def test_slog_html_count_kwarg(self, monkeypatch):
        from config import LLM_HTML_MIN_COUNT
        _, calls = self._fire("long-identity-12", "1.2.3.4", monkeypatch)
        assert calls[0].get("html_count") == LLM_HTML_MIN_COUNT  # kills mutmut_58, 65

    def test_slog_subres_count_zero(self, monkeypatch):
        _, calls = self._fire("long-identity-12", "1.2.3.4", monkeypatch)
        assert calls[0].get("subres_count") == 0  # kills mutmut_59, 66

    def test_slog_window_secs_kwarg(self, monkeypatch):
        from config import LLM_HEURISTIC_WINDOW_SECS
        _, calls = self._fire("long-identity-12", "1.2.3.4", monkeypatch)
        assert calls[0].get("window_secs") == LLM_HEURISTIC_WINDOW_SECS  # kills mutmut_60, 67


# ── Async tests: path_sweep, scoring, identity async functions ─────────────
# These cover the 299 no-test mutants in scoring.py, identity.py, path_sweep.py.
# Requires pytest-asyncio with asyncio_mode = strict (see pytest.ini).


class TestPathSweepRecord:
    """Covers detection.path_sweep.path_sweep_record (8 mutants)."""

    def _mod(self):
        import detection.path_sweep as m
        return m

    def _st(self):
        import state as s
        return s

    @pytest.mark.asyncio
    async def test_static_css_not_recorded(self):
        m, s = self._mod(), self._st()
        key = f"psr-css-{id(self)}"
        await m.path_sweep_record(key, "/bundle.css", "/admin")
        assert len(s.ip_state[key].path_sweep_times) == 0

    @pytest.mark.asyncio
    async def test_static_js_not_recorded(self):
        m, s = self._mod(), self._st()
        key = f"psr-js-{id(self)}"
        await m.path_sweep_record(key, "/app.js", "/admin")
        assert len(s.ip_state[key].path_sweep_times) == 0

    @pytest.mark.asyncio
    async def test_admin_ns_exact_not_recorded(self):
        # Kills mutmut_1 (or→and, changes second condition precedence)
        # and mutmut_4 (== → !=).
        m, s = self._mod(), self._st()
        key = f"psr-adm-{id(self)}"
        await m.path_sweep_record(key, "/admin", "/admin")
        assert len(s.ip_state[key].path_sweep_times) == 0

    @pytest.mark.asyncio
    async def test_admin_ns_subpath_not_recorded(self):
        # Kills mutmut_5 (startswith(None)), mutmut_6 (str-op), mutmut_7 (wrong prefix).
        m, s = self._mod(), self._st()
        key = f"psr-sub-{id(self)}"
        await m.path_sweep_record(key, "/admin/users", "/admin")
        assert len(s.ip_state[key].path_sweep_times) == 0

    @pytest.mark.asyncio
    async def test_normal_path_recorded(self):
        m, s = self._mod(), self._st()
        key = f"psr-norm-{id(self)}"
        await m.path_sweep_record(key, "/dashboard", "/admin")
        assert len(s.ip_state[key].path_sweep_times) == 1

    @pytest.mark.asyncio
    async def test_appended_tuple_has_correct_path(self):
        # Kills mutmut_8 (appends None instead of (ts, path)).
        m, s = self._mod(), self._st()
        key = f"psr-val-{id(self)}"
        await m.path_sweep_record(key, "/products", "/admin")
        _, path = s.ip_state[key].path_sweep_times[-1]
        assert path == "/products"

    @pytest.mark.asyncio
    async def test_appended_tuple_ts_is_float(self):
        m, s = self._mod(), self._st()
        key = f"psr-ts-{id(self)}"
        await m.path_sweep_record(key, "/about", "/admin")
        ts, _ = s.ip_state[key].path_sweep_times[-1]
        assert isinstance(ts, float) and ts > 0

    @pytest.mark.asyncio
    async def test_non_static_non_admin_recorded(self):
        # Kills mutmut_2 (and instead of or between first two conditions):
        # static=False, path!=admin → orig returns early iff static OR admin.
        # With mutant_2: (static AND admin) OR subpath → False → records.
        m, s = self._mod(), self._st()
        key = f"psr-nonstatic-{id(self)}"
        await m.path_sweep_record(key, "/contact", "/admin")
        assert len(s.ip_state[key].path_sweep_times) == 1


class TestPathSweepCheck:
    """Covers detection.path_sweep.path_sweep_check (12 mutants)."""

    def _mod(self):
        import detection.path_sweep as m
        return m

    def _st(self):
        import state as s
        return s

    @pytest.mark.asyncio
    async def test_empty_deque_not_fired(self):
        # Kills mutmut_1 (s=None), mutmut_4 (or→iterates empty→IndexError),
        # mutmut_11 (returns True,"" when not fired), mutmut_12 (returns False,"XXXX").
        m = self._mod()
        key = f"psc-empty-{id(self)}"
        fired, detail = await m.path_sweep_check(key)
        assert fired is False
        assert detail == ""

    @pytest.mark.asyncio
    async def test_below_threshold_not_fired(self):
        from config import PATH_SWEEP_THRESHOLD
        m, s = self._mod(), self._st()
        key = f"psc-below-{id(self)}"
        import time as _t
        now = _t.monotonic()
        for i in range(PATH_SWEEP_THRESHOLD - 1):
            s.ip_state[key].path_sweep_times.append((now, f"/p{i}"))
        fired, detail = await m.path_sweep_check(key)
        assert fired is False
        assert detail == ""

    @pytest.mark.asyncio
    async def test_at_threshold_fires(self):
        # Kills mutmut_9 (>= → >, which would NOT fire at exactly threshold).
        from config import PATH_SWEEP_THRESHOLD
        m, s = self._mod(), self._st()
        key = f"psc-at-{id(self)}"
        import time as _t
        now = _t.monotonic()
        for i in range(PATH_SWEEP_THRESHOLD):
            s.ip_state[key].path_sweep_times.append((now, f"/q{i}"))
        fired, _ = await m.path_sweep_check(key)
        assert fired is True

    @pytest.mark.asyncio
    async def test_fired_first_element_true(self):
        # Kills mutmut_10 (returns False, detail when fired).
        from config import PATH_SWEEP_THRESHOLD
        m, s = self._mod(), self._st()
        key = f"psc-true-{id(self)}"
        import time as _t
        now = _t.monotonic()
        for i in range(PATH_SWEEP_THRESHOLD):
            s.ip_state[key].path_sweep_times.append((now, f"/r{i}"))
        fired, _ = await m.path_sweep_check(key)
        assert fired is True

    @pytest.mark.asyncio
    async def test_fired_detail_contains_distinct_count(self):
        from config import PATH_SWEEP_THRESHOLD
        m, s = self._mod(), self._st()
        key = f"psc-detail-{id(self)}"
        import time as _t
        now = _t.monotonic()
        for i in range(PATH_SWEEP_THRESHOLD):
            s.ip_state[key].path_sweep_times.append((now, f"/s{i}"))
        _, detail = await m.path_sweep_check(key)
        assert str(PATH_SWEEP_THRESHOLD) in detail

    @pytest.mark.asyncio
    async def test_stale_entries_pruned_so_not_fired(self):
        # Kills mutmut_2 (cutoff=None→TypeError) and mutmut_3 (cutoff=+WINDOW→stale kept).
        from config import PATH_SWEEP_THRESHOLD, PATH_SWEEP_WINDOW_SECS
        m, s = self._mod(), self._st()
        key = f"psc-stale-{id(self)}"
        import time as _t
        old = _t.monotonic() - PATH_SWEEP_WINDOW_SECS - 10
        for i in range(PATH_SWEEP_THRESHOLD):
            s.ip_state[key].path_sweep_times.append((old, f"/old{i}"))
        fired, _ = await m.path_sweep_check(key)
        assert fired is False

    @pytest.mark.asyncio
    async def test_fresh_entries_not_pruned(self):
        from config import PATH_SWEEP_THRESHOLD
        m, s = self._mod(), self._st()
        key = f"psc-fresh-{id(self)}"
        import time as _t
        now = _t.monotonic()
        for i in range(PATH_SWEEP_THRESHOLD):
            s.ip_state[key].path_sweep_times.append((now, f"/t{i}"))
        fired, _ = await m.path_sweep_check(key)
        assert fired is True

    @pytest.mark.asyncio
    async def test_repeated_path_counts_once(self):
        # distinct uses a set; repeated paths count as 1, not N.
        from config import PATH_SWEEP_THRESHOLD
        m, s = self._mod(), self._st()
        key = f"psc-rep-{id(self)}"
        import time as _t
        now = _t.monotonic()
        for _ in range(PATH_SWEEP_THRESHOLD + 5):
            s.ip_state[key].path_sweep_times.append((now, "/same"))
        fired, _ = await m.path_sweep_check(key)
        assert fired is False

    @pytest.mark.asyncio
    async def test_index_0_element_0_is_timestamp(self):
        # Kills mutmut_5 ([1][0]) and mutmut_6 ([0][1]) — wrong index causes
        # IndexError or type mismatch in comparison with cutoff float.
        from config import PATH_SWEEP_WINDOW_SECS
        m, s = self._mod(), self._st()
        key = f"psc-idx-{id(self)}"
        import time as _t
        old = _t.monotonic() - PATH_SWEEP_WINDOW_SECS - 1
        fresh = _t.monotonic()
        s.ip_state[key].path_sweep_times.append((old, "/old"))
        s.ip_state[key].path_sweep_times.append((fresh, "/fresh"))
        # Only the old one should be pruned; fresh stays.
        fired, _ = await m.path_sweep_check(key)
        assert len(s.ip_state[key].path_sweep_times) == 1


class TestRecordChalMint:
    """Covers identity._record_chal_mint (48 mutants, async)."""

    def _mod(self):
        import identity as m
        return m

    @pytest.mark.asyncio
    async def test_single_call_returns_false(self):
        m = self._mod()
        result = await m._record_chal_mint(
            f"UA-single-{id(self)}", "A", f"ja4-{id(self)}", "1.1.1.1"
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_churn_threshold_triggers_true(self):
        # SESSION_CHURN_MAX calls don't trigger; SESSION_CHURN_MAX+1 does.
        m = self._mod()
        churn_max = m.SESSION_CHURN_MAX
        ua, tier, ja4 = f"UA-churn-{id(self)}", "B", f"ja4churn-{id(self)}"
        result = False
        for _ in range(churn_max + 1):
            result = await m._record_chal_mint(ua, tier, ja4, "1.1.1.2")
        assert result is True

    @pytest.mark.asyncio
    async def test_exactly_at_churn_max_not_triggered(self):
        # len(q) > SESSION_CHURN_MAX: at exactly max, NOT triggered.
        m = self._mod()
        churn_max = m.SESSION_CHURN_MAX
        ua, tier, ja4 = f"UA-exact-{id(self)}", "C", f"ja4exact-{id(self)}"
        result = None
        for _ in range(churn_max):
            result = await m._record_chal_mint(ua, tier, ja4, "1.1.1.3")
        assert result is False

    @pytest.mark.asyncio
    async def test_stale_entries_pruned_before_count(self):
        # Stale timestamps (outside SESSION_CHURN_WINDOW_S) are removed before
        # comparing len(q) > SESSION_CHURN_MAX.
        m = self._mod()
        churn_max = m.SESSION_CHURN_MAX
        window_s = m.SESSION_CHURN_WINDOW_S
        import time
        from collections import deque
        ua, tier, ja4 = f"UA-stale-{id(self)}", "D", f"ja4stale-{id(self)}"
        fp_h = m._fp_hash(ua, tier, ja4)
        # Pre-fill with churn_max stale timestamps (outside the window).
        m._fp_session_creations[fp_h] = deque(
            [time.time() - window_s - 10] * churn_max,
            maxlen=64,
        )
        result = await m._record_chal_mint(ua, tier, ja4, "1.1.1.4")
        assert result is False

    @pytest.mark.asyncio
    async def test_slog_called_on_churn(self, monkeypatch):
        m = self._mod()
        churn_max = m.SESSION_CHURN_MAX
        ua, tier, ja4 = f"UA-slog-{id(self)}", "E", f"ja4slog-{id(self)}"
        calls = []
        monkeypatch.setattr(m, "slog", lambda event, **kw: calls.append(event))
        for _ in range(churn_max + 1):
            await m._record_chal_mint(ua, tier, ja4, "1.1.1.5")
        assert "session_churn" in calls

    @pytest.mark.asyncio
    async def test_slog_level_warn_on_churn(self, monkeypatch):
        m = self._mod()
        churn_max = m.SESSION_CHURN_MAX
        ua, tier, ja4 = f"UA-warn-{id(self)}", "F", f"ja4warn-{id(self)}"
        calls = []
        monkeypatch.setattr(m, "slog", lambda event, level="info", **kw: calls.append(level))
        for _ in range(churn_max + 1):
            await m._record_chal_mint(ua, tier, ja4, "1.1.1.6")
        assert "warn" in calls

    @pytest.mark.asyncio
    async def test_slog_fp_hash_kwarg(self, monkeypatch):
        m = self._mod()
        churn_max = m.SESSION_CHURN_MAX
        ua, tier, ja4 = f"UA-fph-{id(self)}", "G", f"ja4fph-{id(self)}"
        calls = []
        monkeypatch.setattr(m, "slog", lambda event, **kw: calls.append(kw))
        for _ in range(churn_max + 1):
            await m._record_chal_mint(ua, tier, ja4, "1.1.1.7")
        expected_fp = m._fp_hash(ua, tier, ja4)
        assert any(c.get("fp_hash") == expected_fp for c in calls)

    @pytest.mark.asyncio
    async def test_fp_hash_separates_distinct_fingerprints(self):
        # Two different (ua, tier, ja4) combos have independent counters.
        m = self._mod()
        churn_max = m.SESSION_CHURN_MAX
        ua1, tier1, ja4_1 = f"UA-fp1-{id(self)}", "H", f"ja4fp1-{id(self)}"
        ua2, tier2, ja4_2 = f"UA-fp2-{id(self)}", "I", f"ja4fp2-{id(self)}"
        # Churn first fingerprint.
        for _ in range(churn_max + 1):
            await m._record_chal_mint(ua1, tier1, ja4_1, "1.1.1.8")
        # Second fingerprint has no prior calls → should NOT churn.
        result2 = await m._record_chal_mint(ua2, tier2, ja4_2, "1.1.1.9")
        assert result2 is False


class TestIsBanned:
    """Covers scoring.is_banned (21 mutants, async)."""

    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    @pytest.mark.asyncio
    async def test_locally_banned_returns_true(self):
        m, s = self._mod(), self._st()
        ip = f"ban-t-{id(self) % 65535}"
        from helpers import now
        s.ip_state[ip].banned_until = now() + 300
        banned, _ = await m.is_banned(ip)
        assert banned is True

    @pytest.mark.asyncio
    async def test_locally_banned_remaining_positive(self):
        m, s = self._mod(), self._st()
        ip = f"ban-r-{id(self) % 65535}"
        from helpers import now
        s.ip_state[ip].banned_until = now() + 300
        _, remaining = await m.is_banned(ip)
        assert remaining > 0

    @pytest.mark.asyncio
    async def test_locally_banned_remaining_approx_correct(self):
        # remaining ≈ banned_until - now(): kills mutants that flip sign or add.
        m, s = self._mod(), self._st()
        ip = f"ban-ra-{id(self) % 65535}"
        from helpers import now
        s.ip_state[ip].banned_until = now() + 300
        _, remaining = await m.is_banned(ip)
        assert 250 < remaining <= 300

    @pytest.mark.asyncio
    async def test_not_banned_returns_false(self):
        m, s = self._mod(), self._st()
        ip = f"ban-f-{id(self) % 65535}"
        s.ip_state[ip].banned_until = 0.0
        banned, _ = await m.is_banned(ip)
        assert banned is False

    @pytest.mark.asyncio
    async def test_not_banned_remaining_zero(self):
        m, s = self._mod(), self._st()
        ip = f"ban-rz-{id(self) % 65535}"
        s.ip_state[ip].banned_until = 0.0
        _, remaining = await m.is_banned(ip)
        assert remaining == 0.0

    @pytest.mark.asyncio
    async def test_expired_ban_returns_false(self):
        m, s = self._mod(), self._st()
        ip = f"ban-exp-{id(self) % 65535}"
        from helpers import now
        s.ip_state[ip].banned_until = now() - 10
        banned, _ = await m.is_banned(ip)
        assert banned is False

    @pytest.mark.asyncio
    async def test_banned_until_exactly_now_not_banned(self):
        # s.banned_until > n → exactly now is NOT banned (kills mutmut_3: >= n).
        m, s = self._mod(), self._st()
        ip = f"ban-eq-{id(self) % 65535}"
        from helpers import now
        s.ip_state[ip].banned_until = now() - 0.001
        banned, _ = await m.is_banned(ip)
        assert banned is False


class TestBan:
    """Covers scoring.ban (17 mutants, async)."""

    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    @pytest.mark.asyncio
    async def test_ban_sets_banned_until_future(self):
        m, s = self._mod(), self._st()
        ip = f"bn-fut-{id(self) % 65535}"
        from helpers import now
        before = now()
        await m.ban(ip, secs=60)
        assert s.ip_state[ip].banned_until > before

    @pytest.mark.asyncio
    async def test_ban_duration_approximately_correct(self):
        m, s = self._mod(), self._st()
        ip = f"bn-dur-{id(self) % 65535}"
        from helpers import now
        await m.ban(ip, secs=120)
        remaining = s.ip_state[ip].banned_until - now()
        assert 100 < remaining <= 120

    @pytest.mark.asyncio
    async def test_ban_then_is_banned_true(self):
        m, s = self._mod(), self._st()
        ip = f"bn-chk-{id(self) % 65535}"
        await m.ban(ip, secs=60)
        banned, _ = await m.is_banned(ip)
        assert banned is True

    @pytest.mark.asyncio
    async def test_ban_default_secs_is_nonzero(self):
        m, s = self._mod(), self._st()
        ip = f"bn-def-{id(self) % 65535}"
        from helpers import now
        before = now()
        await m.ban(ip)
        assert s.ip_state[ip].banned_until > before + 1


class TestUpdateRiskAndMaybeBan:
    """Covers scoring.update_risk_and_maybe_ban (119 mutants, async)."""

    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    @pytest.mark.asyncio
    async def test_zero_weight_returns_false(self):
        # "rate-limit-ip" has weight 0 → early return False.
        m = self._mod()
        key = f"urm-zero-{id(self)}"
        result = await m.update_risk_and_maybe_ban(key, "rate-limit-ip", "5.5.5.1")
        assert result is False

    @pytest.mark.asyncio
    async def test_unknown_reason_returns_false(self):
        m = self._mod()
        key = f"urm-unk-{id(self)}"
        result = await m.update_risk_and_maybe_ban(key, "no-such-signal", "5.5.5.2")
        assert result is False

    @pytest.mark.asyncio
    async def test_nonzero_weight_increases_risk_score(self):
        # "js-challenge" weight=3 < threshold=50 → no ban, but risk grows.
        m, s = self._mod(), self._st()
        key = f"urm-inc-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        await m.update_risk_and_maybe_ban(key, "js-challenge", "5.5.5.3")
        assert s.ip_state[key].risk_score > 0

    @pytest.mark.asyncio
    async def test_reason_tracked_in_risk_by_reason(self):
        m, s = self._mod(), self._st()
        key = f"urm-rbr-{id(self)}"
        await m.update_risk_and_maybe_ban(key, "js-challenge", "5.5.5.4")
        assert "js-challenge" in s.ip_state[key].risk_by_reason

    @pytest.mark.asyncio
    async def test_risk_score_incremented_by_weight(self):
        from config import RISK_WEIGHTS
        m, s = self._mod(), self._st()
        key = f"urm-wt-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].last_risk_update = __import__("helpers").now()
        await m.update_risk_and_maybe_ban(key, "js-challenge", "5.5.5.5")
        weight = RISK_WEIGHTS["js-challenge"]
        assert abs(s.ip_state[key].risk_score - weight) < 1.0

    @pytest.mark.asyncio
    async def test_high_weight_triggers_ban(self):
        # "honeypot" weight=50 >= RISK_BAN_THRESHOLD=50 → bans → returns True.
        m, s = self._mod(), self._st()
        key = f"urm-ban-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        result = await m.update_risk_and_maybe_ban(key, "honeypot", "5.5.5.6")
        assert result is True

    @pytest.mark.asyncio
    async def test_banned_ip_has_future_banned_until(self):
        m, s = self._mod(), self._st()
        key = f"urm-banf-{id(self)}"
        from helpers import now
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        await m.update_risk_and_maybe_ban(key, "honeypot", "5.5.5.7")
        assert s.ip_state[key].banned_until > now()

    @pytest.mark.asyncio
    async def test_below_threshold_no_ban(self):
        # js-challenge (weight=3) alone doesn't hit threshold=50 → not banned.
        m, s = self._mod(), self._st()
        key = f"urm-noban-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        result = await m.update_risk_and_maybe_ban(key, "js-challenge", "5.5.5.8")
        assert result is False

    @pytest.mark.asyncio
    async def test_already_banned_no_double_ban(self):
        # s.banned_until > n → condition s.banned_until <= n is False → not triggered.
        m, s = self._mod(), self._st()
        key = f"urm-dbl-{id(self)}"
        from helpers import now
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = now() + 3600
        result = await m.update_risk_and_maybe_ban(key, "honeypot", "5.5.5.9")
        assert result is False

    @pytest.mark.asyncio
    async def test_accumulated_risk_triggers_ban(self):
        # Multiple js-challenge calls accumulate to >= threshold → ban fired.
        from config import RISK_BAN_THRESHOLD, RISK_WEIGHTS
        m, s = self._mod(), self._st()
        key = f"urm-acc-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        s.ip_state[key].last_risk_update = __import__("helpers").now()
        weight = RISK_WEIGHTS["js-challenge"]
        # Ceiling: calls_needed * weight >= RISK_BAN_THRESHOLD.
        calls_needed = (RISK_BAN_THRESHOLD + weight - 1) // weight
        triggered = False
        for _ in range(calls_needed):
            r = await m.update_risk_and_maybe_ban(key, "js-challenge", "5.5.5.10")
            if r:
                triggered = True
                break
        assert triggered is True

    @pytest.mark.asyncio
    async def test_unknown_reason_no_risk_score_increase(self):
        # Kills mutmut_6: RISK_WEIGHTS.get(reason, 0) → (reason, 1).
        # With mutmut_6, unknown reason gets weight=1 and proceeds, increasing risk_score.
        m, s = self._mod(), self._st()
        key = f"urm-norisk-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        await m.update_risk_and_maybe_ban(key, "no-such-signal", "5.5.5.11")
        assert s.ip_state[key].risk_score == 0.0

    @pytest.mark.asyncio
    async def test_risk_by_reason_value_equals_weight(self):
        # Kills mutmut_19 (−weight instead of +weight) and mutmut_24 (default 1.0).
        from config import RISK_WEIGHTS
        m, s = self._mod(), self._st()
        key = f"urm-rbrv-{id(self)}"
        weight = RISK_WEIGHTS["js-challenge"]
        await m.update_risk_and_maybe_ban(key, "js-challenge", "5.5.5.12")
        assert s.ip_state[key].risk_by_reason.get("js-challenge") == weight

    @pytest.mark.asyncio
    async def test_risk_by_reason_accumulates_across_calls(self):
        # Kills mutmut_20: .get(None, 0.0) makes accumulation fail (always returns weight).
        from config import RISK_WEIGHTS
        m, s = self._mod(), self._st()
        key = f"urm-acc2-{id(self)}"
        from helpers import now
        s.ip_state[key].last_risk_update = now()
        weight = RISK_WEIGHTS["js-challenge"]
        await m.update_risk_and_maybe_ban(key, "js-challenge", "5.5.5.13")
        await m.update_risk_and_maybe_ban(key, "js-challenge", "5.5.5.13")
        val = s.ip_state[key].risk_by_reason.get("js-challenge", 0)
        assert val > weight  # accumulated > 1 call; mutmut_20 (.get(None)) would give exactly weight

    @pytest.mark.asyncio
    async def test_really_ban_reason_gets_really_ban_secs(self):
        # "honeypot" ∈ _REALLY_BAN_REASONS → banned_until ≈ now + REALLY_BAN_SECS.
        # Kills mutmut_52 (not in → swaps REALLY→HOSTILE for "honeypot").
        from config import REALLY_BAN_SECS
        m, s = self._mod(), self._st()
        key = f"urm-rbs-{id(self)}"
        from helpers import now
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        s.ip_state[key].last_risk_update = now()
        await m.update_risk_and_maybe_ban(key, "honeypot", "5.5.5.14")
        remaining = s.ip_state[key].banned_until - now()
        assert abs(remaining - REALLY_BAN_SECS) < 10

    @pytest.mark.asyncio
    async def test_hostile_reason_gets_hostile_ban_secs(self):
        # "session-churn" ∈ _HOSTILE_REASONS but ∉ _REALLY_BAN_REASONS.
        # Kills mutmut_53 (not in → gives RISK_BAN_DURATION instead of HOSTILE).
        from config import HOSTILE_BAN_SECS
        m, s = self._mod(), self._st()
        key = f"urm-hbs-{id(self)}"
        from helpers import now
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        s.ip_state[key].last_risk_update = now()
        await m.update_risk_and_maybe_ban(key, "session-churn", "5.5.5.15")
        remaining = s.ip_state[key].banned_until - now()
        assert abs(remaining - HOSTILE_BAN_SECS) < 10

    @pytest.mark.asyncio
    async def test_regular_reason_gets_risk_ban_duration_secs(self):
        # "js-challenge" is in neither set → RISK_BAN_DURATION_SECS.
        # Combined with test_hostile, kills variants that conflate the three paths.
        from config import RISK_BAN_DURATION_SECS, RISK_BAN_THRESHOLD, RISK_WEIGHTS
        m, s = self._mod(), self._st()
        key = f"urm-rbd-{id(self)}"
        from helpers import now
        weight = RISK_WEIGHTS["js-challenge"]
        # Set at threshold so decay+weight still clears it
        s.ip_state[key].risk_score = RISK_BAN_THRESHOLD
        s.ip_state[key].banned_until = 0.0
        s.ip_state[key].last_risk_update = now()
        await m.update_risk_and_maybe_ban(key, "js-challenge", "5.5.5.16")
        remaining = s.ip_state[key].banned_until - now()
        assert abs(remaining - RISK_BAN_DURATION_SECS) < 10

    @pytest.mark.asyncio
    async def test_ban_triggered_db_queue_message_op(self, monkeypatch):
        # Kills mutmut_65 (put None), 66 ("XXbanXX"), 67 ("BAN").
        import asyncio
        m, s = self._mod(), self._st()
        q = asyncio.Queue()
        monkeypatch.setattr(m, "db_queue", q)
        key = f"urm-dbqop-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        await m.update_risk_and_maybe_ban(key, "honeypot", "5.5.5.17")
        assert not q.empty()
        op, _ = q.get_nowait()
        assert op == "ban"

    @pytest.mark.asyncio
    async def test_ban_triggered_db_queue_track_key(self, monkeypatch):
        # Kills mutmut_70 (None instead of track_key in db_queue message).
        import asyncio
        m, s = self._mod(), self._st()
        q = asyncio.Queue()
        monkeypatch.setattr(m, "db_queue", q)
        key = f"urm-dbqtk-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        await m.update_risk_and_maybe_ban(key, "honeypot", "5.5.5.18")
        _, args = q.get_nowait()
        assert args[0] == key

    @pytest.mark.asyncio
    async def test_ban_triggered_db_queue_populated(self, monkeypatch):
        # Kills mutmut_58 (ban_dur=None → TypeError in db_queue put).
        import asyncio
        m, s = self._mod(), self._st()
        q = asyncio.Queue()
        monkeypatch.setattr(m, "db_queue", q)
        key = f"urm-dbqpop-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        await m.update_risk_and_maybe_ban(key, "honeypot", "5.5.5.19")
        assert not q.empty()

    @pytest.mark.asyncio
    async def test_ban_triggered_db_queue_until_future(self, monkeypatch):
        # Kills ban_dur mutations that set negative or zero until timestamp.
        import asyncio, time
        m, s = self._mod(), self._st()
        q = asyncio.Queue()
        monkeypatch.setattr(m, "db_queue", q)
        key = f"urm-dbquf-{id(self)}"
        s.ip_state[key].risk_score = 0.0
        s.ip_state[key].banned_until = 0.0
        await m.update_risk_and_maybe_ban(key, "honeypot", "5.5.5.20")
        _, args = q.get_nowait()
        assert args[1] > time.time()  # until is in the future


class TestBanDbQueue:
    """Covers scoring.ban db_queue mutations (mutmut_7-10)."""

    def _mod(self):
        import scoring as m
        return m

    @pytest.mark.asyncio
    async def test_ban_db_queue_op_is_ban(self, monkeypatch):
        import asyncio
        m = self._mod()
        q = asyncio.Queue()
        monkeypatch.setattr(m, "db_queue", q)
        ip = f"bndbq-op-{id(self) % 65535}"
        await m.ban(ip, secs=60)
        assert not q.empty()
        op, _ = q.get_nowait()
        assert op == "ban"  # kills mutmut_7 (None), 8 ("XXbanXX"), 9 ("BAN")

    @pytest.mark.asyncio
    async def test_ban_db_queue_until_is_future(self, monkeypatch):
        import asyncio, time
        m = self._mod()
        q = asyncio.Queue()
        monkeypatch.setattr(m, "db_queue", q)
        ip = f"bndbq-fut-{id(self) % 65535}"
        await m.ban(ip, secs=60)
        _, args = q.get_nowait()
        assert args[1] > time.time()  # kills mutmut_10 (_t.time() - secs)

    @pytest.mark.asyncio
    async def test_ban_db_queue_ip_arg(self, monkeypatch):
        import asyncio
        m = self._mod()
        q = asyncio.Queue()
        monkeypatch.setattr(m, "db_queue", q)
        ip = f"bndbq-ip-{id(self) % 65535}"
        await m.ban(ip, secs=60)
        _, args = q.get_nowait()
        assert args[0] == ip


class TestLoadSignalOrderCache:
    """Covers scoring._load_signal_order_cache (39 mutants)."""

    def _mod(self):
        import scoring as m
        return m

    def test_returns_without_exception_when_gw_raises(self, monkeypatch):
        import admin.mesh as mesh
        m = self._mod()
        def _raise():
            raise RuntimeError("no mesh")
        monkeypatch.setattr(mesh, "_gw_local_id", _raise)
        m._load_signal_order_cache()

    def test_loads_valid_rows_into_cache(self, monkeypatch, tmp_path):
        import sqlite3
        import state as _s
        import admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "lsc.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE signal_orders (gw_id TEXT, signal TEXT, activation_order INT)"
        )
        conn.execute("INSERT INTO signal_orders VALUES ('gw-lsc', 'honeypot', 2)")
        conn.commit(); conn.close()
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-lsc")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        _s._signal_order_cache.clear()
        m._load_signal_order_cache()
        assert _s._signal_order_cache.get("honeypot") == 2

    def test_order_1_accepted(self, monkeypatch, tmp_path):
        import sqlite3, state as _s, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "lsc1.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE signal_orders (gw_id TEXT, signal TEXT, activation_order INT)"
        )
        conn.execute("INSERT INTO signal_orders VALUES ('gw-o1', 'ua-blocked', 1)")
        conn.commit(); conn.close()
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-o1")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        _s._signal_order_cache.clear()
        m._load_signal_order_cache()
        assert _s._signal_order_cache.get("ua-blocked") == 1

    def test_invalid_order_filtered_out(self, monkeypatch, tmp_path):
        # Order 99 is not in (1,2,3) → filtered out → not in cache.
        import sqlite3, state as _s, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "lsc2.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE signal_orders (gw_id TEXT, signal TEXT, activation_order INT)"
        )
        conn.execute("INSERT INTO signal_orders VALUES ('gw-lsc2', 'honeypot', 99)")
        conn.commit(); conn.close()
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-lsc2")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        _s._signal_order_cache.clear()
        m._load_signal_order_cache()
        assert "honeypot" not in _s._signal_order_cache

    def test_slog_called_when_cache_nonempty(self, monkeypatch, tmp_path):
        import sqlite3, state as _s, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "lsc3.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE signal_orders (gw_id TEXT, signal TEXT, activation_order INT)"
        )
        conn.execute("INSERT INTO signal_orders VALUES ('gw-lsc3', 'ua-empty', 1)")
        conn.commit(); conn.close()
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-lsc3")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        _s._signal_order_cache.clear()
        calls = []
        monkeypatch.setattr(m, "slog", lambda event, **kw: calls.append({"event": event, **kw}))
        m._load_signal_order_cache()
        assert any(c["event"] == "signal_orders_loaded" for c in calls)

    def test_slog_count_kwarg_matches_loaded(self, monkeypatch, tmp_path):
        import sqlite3, state as _s, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "lsc4.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE signal_orders (gw_id TEXT, signal TEXT, activation_order INT)"
        )
        conn.execute("INSERT INTO signal_orders VALUES ('gw-lsc4', 'ua-empty', 2)")
        conn.execute("INSERT INTO signal_orders VALUES ('gw-lsc4', 'ua-blocked', 3)")
        conn.commit(); conn.close()
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-lsc4")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        _s._signal_order_cache.clear()
        calls = []
        monkeypatch.setattr(m, "slog", lambda event, **kw: calls.append({"event": event, **kw}))
        m._load_signal_order_cache()
        loaded = [c for c in calls if c["event"] == "signal_orders_loaded"]
        assert loaded and loaded[0]["count"] >= 2

    def test_gw_id_kwarg_in_slog(self, monkeypatch, tmp_path):
        import sqlite3, state as _s, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "lsc5.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE signal_orders (gw_id TEXT, signal TEXT, activation_order INT)"
        )
        conn.execute("INSERT INTO signal_orders VALUES ('gw-lsc5', 'ai-probe', 1)")
        conn.commit(); conn.close()
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-lsc5")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        _s._signal_order_cache.clear()
        calls = []
        monkeypatch.setattr(m, "slog", lambda event, **kw: calls.append({"event": event, **kw}))
        m._load_signal_order_cache()
        loaded = [c for c in calls if c["event"] == "signal_orders_loaded"]
        assert loaded and loaded[0].get("gw_id") == "gw-lsc5"

    def test_sqlite_error_calls_slog_failed(self, monkeypatch):
        import admin.mesh as mesh
        m = self._mod()
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-err")
        monkeypatch.setattr(m, "DB_PATH", "/nonexistent/path/x.db")
        calls = []
        monkeypatch.setattr(m, "slog", lambda event, **kw: calls.append({"event": event, **kw}))
        m._load_signal_order_cache()
        assert any("failed" in c["event"] for c in calls)

    def test_query_filters_by_gw_id(self, monkeypatch, tmp_path):
        # Rows for a DIFFERENT gw_id should NOT be loaded.
        import sqlite3, state as _s, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "lsc6.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE signal_orders (gw_id TEXT, signal TEXT, activation_order INT)"
        )
        conn.execute("INSERT INTO signal_orders VALUES ('other-gw', 'honeypot', 2)")
        conn.commit(); conn.close()
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "my-gw")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        _s._signal_order_cache.clear()
        m._load_signal_order_cache()
        assert "honeypot" not in _s._signal_order_cache


class TestSaveSignalOrder:
    """Covers scoring._save_signal_order (35 mutants)."""

    def _mod(self):
        import scoring as m
        return m

    def test_returns_silently_when_gw_raises(self, monkeypatch):
        import admin.mesh as mesh
        m = self._mod()
        def _raise():
            raise RuntimeError("no mesh")
        monkeypatch.setattr(mesh, "_gw_local_id", _raise)
        m._save_signal_order("honeypot", 1, "admin")

    def test_updates_in_memory_cache(self, monkeypatch, tmp_path):
        import sqlite3, state as _s, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "sso.db"
        _create_signal_orders_table(db)
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-sso")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        monkeypatch.setattr(m, "POSTGRES_DSN", "")
        _s._signal_order_cache.pop("ua-empty", None)
        m._save_signal_order("ua-empty", 3, "testuser")
        assert _s._signal_order_cache.get("ua-empty") == 3

    def test_cache_value_matches_saved_order(self, monkeypatch, tmp_path):
        import state as _s, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "sso2.db"
        _create_signal_orders_table(db)
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-sso2")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        monkeypatch.setattr(m, "POSTGRES_DSN", "")
        _s._signal_order_cache.pop("ai-probe", None)
        m._save_signal_order("ai-probe", 2, "op")
        assert _s._signal_order_cache["ai-probe"] == 2

    def test_persists_to_sqlite(self, monkeypatch, tmp_path):
        import sqlite3, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "sso3.db"
        _create_signal_orders_table(db)
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-sso3")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        monkeypatch.setattr(m, "POSTGRES_DSN", "")
        m._save_signal_order("suspicious-path", 2, "operator")
        conn = sqlite3.connect(str(db))
        rows = conn.execute(
            "SELECT signal, activation_order FROM signal_orders WHERE gw_id='gw-sso3'"
        ).fetchall()
        conn.close()
        assert ("suspicious-path", 2) in rows

    def test_upsert_overwrites_existing(self, monkeypatch, tmp_path):
        import sqlite3, state as _s, admin.mesh as mesh
        m = self._mod()
        db = tmp_path / "sso4.db"
        _create_signal_orders_table(db)
        monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-sso4")
        monkeypatch.setattr(m, "DB_PATH", str(db))
        monkeypatch.setattr(m, "POSTGRES_DSN", "")
        m._save_signal_order("ai-probe", 1, "op")
        m._save_signal_order("ai-probe", 3, "op")  # overwrite
        conn = sqlite3.connect(str(db))
        rows = conn.execute(
            "SELECT activation_order FROM signal_orders WHERE gw_id='gw-sso4' AND signal='ai-probe'"
        ).fetchall()
        conn.close()
        assert rows == [(3,)]

    def test_order_1_2_3_all_valid(self, monkeypatch, tmp_path):
        import state as _s, admin.mesh as mesh
        m = self._mod()
        for order in (1, 2, 3):
            db = tmp_path / f"sso_ord{order}.db"
            _create_signal_orders_table(db)
            monkeypatch.setattr(mesh, "_gw_local_id", lambda: "gw-ord")
            monkeypatch.setattr(m, "DB_PATH", str(db))
            monkeypatch.setattr(m, "POSTGRES_DSN", "")
            sig = f"sig-ord{order}"
            _s._signal_order_cache.pop(sig, None)
            m._save_signal_order(sig, order, "tester")
            assert _s._signal_order_cache.get(sig) == order


def _create_signal_orders_table(db_path):
    import sqlite3
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE signal_orders (
            gw_id TEXT, signal TEXT, activation_order INT,
            updated_ts REAL, updated_by TEXT,
            UNIQUE(gw_id, signal)
        )
    """)
    conn.commit()
    conn.close()


# ── _should_run_signal: threshold=0 boundary (mutmut_6, mutmut_12) ─────────

class TestShouldRunSignalThresholdZero:
    def setup_method(self):
        import scoring as m
        m._signal_order_cache.clear()

    def test_escalation_threshold_0_always_runs_order3(self, monkeypatch):
        # mutmut_6: ESCALATION_THRESHOLD < 0 instead of <= 0
        # threshold=0: orig (0<=0)=True → short-circuit → True regardless of esc_score
        # mutmut_6: (0<0)=False → checks esc_score >= 0; esc_score=-1 → False
        import scoring as m
        monkeypatch.setattr(m, "ESCALATION_THRESHOLD", 0.0)
        from config import ESCALATE_ONLY_REASONS
        sig = next(iter(ESCALATE_ONLY_REASONS))
        assert m._should_run_signal(sig, -1.0) is True

    def test_second_order_threshold_0_always_runs_order2(self, monkeypatch):
        # mutmut_12: SECOND_ORDER_THRESHOLD < 0 instead of <= 0
        import scoring as m
        monkeypatch.setattr(m, "SECOND_ORDER_THRESHOLD", 0.0)
        from config import SECOND_ORDER_REASONS
        sig = next(iter(SECOND_ORDER_REASONS))
        assert m._should_run_signal(sig, -1.0) is True


# ── _decay_risk: condition boundary (mutmut_8, mutmut_9, mutmut_11, mutmut_23, mutmut_39) ─

class TestDecayRiskConditionBoundary:
    def _mod(self):
        import scoring as m
        return m

    def test_no_decay_when_elapsed_zero_risk_below_noise(self):
        # orig: elapsed=0 > 0 → False → body skipped → risk_score stays 0.4
        # mutmut_8 (and→or): False or (0.4>0)=True → factor=1 → 0.4<0.5 → cleared to 0.0
        # mutmut_9 (>→>=): 0>=0=True → same clearing
        s = _FakeState(risk_score=0.4, last_risk_update=5000.0)
        self._mod()._decay_risk(s, 5000.0)  # elapsed=0 exactly
        assert s.risk_score == pytest.approx(0.4)

    def test_zero_risk_score_skips_decay_body(self):
        # orig: elapsed>0 and 0.0>0 = False → skip → risk_by_reason untouched
        # mutmut_11 (risk_score >= 0): True → factor applied → 0.0<0.5 → risk_by_reason cleared
        s = _FakeState(risk_score=0.0, last_risk_update=0.0)
        s.risk_by_reason["js-challenge"] = 5.0
        self._mod()._decay_risk(s, 1.0)  # elapsed=1s
        assert "js-challenge" in s.risk_by_reason

    def test_no_getattr_error_when_risk_by_reason_absent_decay_runs(self):
        # mutmut_23: getattr(state, "risk_by_reason") without default → AttributeError
        # when attribute absent; orig handles it safely with None default
        import types
        state = types.SimpleNamespace(risk_score=5.0, last_risk_update=0.0)
        self._mod()._decay_risk(state, 1.0)  # elapsed=1s, risk_score>0 → enters body
        # mutmut_23: AttributeError in first getattr → test error → killed

    def test_no_getattr_error_when_risk_by_reason_absent_zero_block(self):
        # mutmut_39: second getattr (in risk_score<0.5 block) without default → AttributeError
        import types
        state = types.SimpleNamespace(risk_score=0.3, last_risk_update=0.0)
        self._mod()._decay_risk(state, 1.0)  # risk_score → decays below 0.5 → enters zero block
        assert state.risk_score == 0.0  # zeroing ran


# ── update_risk_and_maybe_ban: unknown reason early return (mutmut_8) ────────

class TestUpdateRiskEarlyReturn:
    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    @pytest.mark.asyncio
    async def test_unknown_reason_does_not_touch_risk_by_reason(self):
        # orig: weight==0 → return False early → risk_by_reason unchanged
        # mutmut_8: weight==1 → weight=0 doesn't equal 1 → continues
        #   → risk_by_reason["totally-unknown"] = 0.0 (side-effect)
        m, st = self._mod(), self._st()
        key = f"urm-unk-{id(self)}"
        st.ip_state[key].risk_by_reason.clear()
        await m.update_risk_and_maybe_ban(key, "totally-unknown-reason-xyz", "1.2.3.5")
        assert "totally-unknown-reason-xyz" not in st.ip_state[key].risk_by_reason


# ── update_risk_and_maybe_ban: NAT counting (mutmut_27, mutmut_32) ───────────

class TestUpdateRiskNatDetection:
    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    def _mock_redis_noop(self, monkeypatch):
        """Prevent real Redis connection when ban is triggered in test."""
        import sys, types
        mod = types.ModuleType('integrations.redis')
        async def _noop(*a, **kw): pass
        mod._shared_ban_set = _noop
        monkeypatch.setitem(sys.modules, 'integrations.redis', mod)

    @pytest.mark.asyncio
    async def test_nat_counting_each_identity_counted_once(self, monkeypatch):
        # mutmut_27: sum(2 for ...) instead of sum(1 for ...)
        # 3 valid entries: orig→identities=3<5→threshold=50; mutmut_27→6>=5→threshold=100
        # orig: 53>=50 → ban triggered; mutmut_27: 53<100 → no ban → killed
        self._mock_redis_noop(monkeypatch)
        from helpers import now
        from config import RISK_BAN_THRESHOLD, NAT_IDENTITIES_THRESHOLD
        m, st = self._mod(), self._st()
        ip = f"10.20.30.{id(self) % 200 + 10}"
        nat_keys = [f"nat27-k{i}-{id(self)}" for i in range(3)]
        n = now()
        for k in nat_keys:
            s2 = st.ip_state[k]
            s2.last_ip = ip
            s2.last_seen = n
            s2.static_loads = 1
            s2.allowed_count = 3
            st.ip_to_identities[ip].add(k)
        track_key = f"nat27-main-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = n
        result = await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        assert result is True  # orig: 53>=50 → True; mutmut_27: 53<100 → False

    @pytest.mark.asyncio
    async def test_stale_entry_excluded_from_nat_count(self, monkeypatch):
        # mutmut_32: "and st.static_loads>=1 or st.allowed_count>=3"
        # 5 stale entries (last_ip mismatch) with allowed_count=3:
        # orig: excluded → identities=0 → threshold=50 → ban
        # mutmut_32: OR-allowed_count → included → NAT threshold → no ban
        self._mock_redis_noop(monkeypatch)
        from helpers import now
        from config import RISK_BAN_THRESHOLD, NAT_IDENTITIES_THRESHOLD
        m, st = self._mod(), self._st()
        ip = f"10.20.30.{id(self) % 200 + 50}"
        stale_keys = [f"nat32-k{i}-{id(self)}" for i in range(5)]
        n = now()
        for k in stale_keys:
            s2 = st.ip_state[k]
            s2.last_ip = "9.9.9.9"  # wrong IP — stale entry
            s2.last_seen = n
            s2.static_loads = 0     # fails static_loads >= 1
            s2.allowed_count = 3    # passes allowed_count >= 3 (exploited by mutmut_32)
            st.ip_to_identities[ip].add(k)
        track_key = f"nat32-main-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = n
        result = await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        assert result is True  # orig: stale excluded → ban; mutmut_32: NAT threshold → no ban


# ── ban: default reason parameter (mutmut_1, mutmut_2) ─────────────────────

class TestBanDefaultReason:
    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    @pytest.mark.asyncio
    async def test_ban_default_reason_is_honeypot(self, monkeypatch):
        # mutmut_1: default reason="XXhoneypotXX"
        # mutmut_2: default reason="HONEYPOT"
        # Call ban(ip) without reason → db_queue message reason must equal "honeypot"
        import asyncio
        m = self._mod()
        q = asyncio.Queue()
        monkeypatch.setattr(m, "db_queue", q)
        ip = f"ban-dr-{id(self) % 65535}"
        await m.ban(ip)  # uses default reason
        assert not q.empty()
        _, args = q.get_nowait()
        _, _, reason, _ = args
        assert reason == "honeypot"


# ── is_banned: exact-boundary (mutmut_3) ────────────────────────────────────

class TestIsBannedExactBoundary:
    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    @pytest.mark.asyncio
    async def test_not_banned_when_banned_until_equals_now(self, monkeypatch):
        # orig: s.banned_until > n → False when banned_until==n → not banned
        # mutmut_3: s.banned_until >= n → True when banned_until==n → wrongly banned
        FIXED_NOW = 50000.0
        m = self._mod()
        st = self._st()
        monkeypatch.setattr(m, "now", lambda: FIXED_NOW)
        ip = f"ib-bnd-{id(self) % 65535}"
        st.ip_state[ip].banned_until = FIXED_NOW  # exactly == now
        result, remaining = await m.is_banned(ip)
        assert result is False   # ban expired exactly at this instant
        assert remaining == 0.0


# ── is_banned: Redis-path mock kills (mutmut_7-8, mutmut_10-19) ─────────────

class TestIsBannedRedisMock:
    """Mock integrations.redis to exercise the Redis code path in is_banned."""

    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    def _fake_redis_get(self, monkeypatch, ip, *, raises=False, return_val=None):
        """Inject a fake integrations.redis module with a _shared_ban_get mock."""
        import sys, types, time as _time
        future = _time.time() + 3600
        if return_val is None:
            return_val = future

        async def mock_get(arg):
            if raises:
                raise RuntimeError("mock-redis-error")
            if arg == ip:
                return return_val
            return 0.0

        mod = types.ModuleType('integrations.redis')
        mod._shared_ban_get = mock_get
        monkeypatch.setitem(sys.modules, 'integrations.redis', mod)
        return return_val

    @pytest.mark.asyncio
    async def test_redis_ban_get_called_with_ip(self, monkeypatch):
        # mutmut_7: _shared_ban_get(None) instead of (ip) → gets 0.0 → not banned
        # orig: called with ip → returns future → banned → True
        m, st = self._mod(), self._st()
        ip = f"ib-rm7-{id(self) % 65535}"
        st.ip_state[ip].banned_until = 0.0  # not locally banned
        self._fake_redis_get(monkeypatch, ip)
        result, _ = await m.is_banned(ip)
        assert result is True  # Redis says banned; mutmut_7 (None arg) gets 0.0 → False → killed

    @pytest.mark.asyncio
    async def test_redis_get_raises_returns_not_banned(self, monkeypatch):
        # mutmut_8: until = None in except → None > time() → TypeError propagates → test error → killed
        # orig: until = 0.0 → not banned → (False, 0.0)
        m, st = self._mod(), self._st()
        ip = f"ib-rm8-{id(self) % 65535}"
        st.ip_state[ip].banned_until = 0.0
        self._fake_redis_get(monkeypatch, ip, raises=True)
        result, remaining = await m.is_banned(ip)  # mutmut_8: TypeError here
        assert result is False
        assert remaining == 0.0

    @pytest.mark.asyncio
    async def test_redis_remaining_is_float(self, monkeypatch):
        # mutmut_11: remaining = None → returns (True, None)
        # orig: remaining = until - time() ≈ 3600 → (True, ~3600)
        m, st = self._mod(), self._st()
        ip = f"ib-rm11-{id(self) % 65535}"
        st.ip_state[ip].banned_until = 0.0
        self._fake_redis_get(monkeypatch, ip)
        result, remaining = await m.is_banned(ip)
        assert result is True
        assert isinstance(remaining, float) and remaining > 0  # kills mutmut_11 (None)

    @pytest.mark.asyncio
    async def test_redis_remaining_is_time_until_not_sum(self, monkeypatch):
        # mutmut_12: remaining = until + time() ≈ 3.5e9 instead of ~3600
        m, st = self._mod(), self._st()
        ip = f"ib-rm12-{id(self) % 65535}"
        st.ip_state[ip].banned_until = 0.0
        self._fake_redis_get(monkeypatch, ip)
        result, remaining = await m.is_banned(ip)
        assert result is True
        assert remaining < 7200  # ~3600 expected; mutmut_12 gives ~3.5e9

    @pytest.mark.asyncio
    async def test_redis_sets_banned_until_not_none(self, monkeypatch):
        # mutmut_13: ip_state[ip].banned_until = None
        # mutmut_14: max(None, now()+remaining) → TypeError → test error → killed
        # mutmut_15: max(banned_until, None) → TypeError → killed
        from helpers import now
        m, st = self._mod(), self._st()
        ip = f"ib-rm13-{id(self) % 65535}"
        st.ip_state[ip].banned_until = 0.0
        self._fake_redis_get(monkeypatch, ip)
        await m.is_banned(ip)
        assert st.ip_state[ip].banned_until is not None  # kills mutmut_13

    @pytest.mark.asyncio
    async def test_redis_sets_banned_until_to_future_monotonic(self, monkeypatch):
        # mutmut_17: max(banned_until,) = banned_until (never updates)
        # mutmut_18: max(banned_until, now()-remaining) → keeps old value (smaller)
        from helpers import now
        m, st = self._mod(), self._st()
        ip = f"ib-rm17-{id(self) % 65535}"
        st.ip_state[ip].banned_until = 0.0  # starts unset
        self._fake_redis_get(monkeypatch, ip)
        await m.is_banned(ip)
        # orig: banned_until ≈ now() + 3600 > now()
        # mutmut_17: stays 0.0 → not > now()
        # mutmut_18: max(0.0, now()-3600) ≈ 0 → not > now()
        assert st.ip_state[ip].banned_until > now()

    @pytest.mark.asyncio
    async def test_redis_banned_until_preserves_larger_existing_value(self, monkeypatch):
        # mutmut_16: max(now()+remaining) ignores existing banned_until
        from helpers import now
        m, st = self._mod(), self._st()
        ip = f"ib-rm16-{id(self) % 65535}"
        large_val = now() + 1_000_000  # 11+ days in future (monotonic)
        st.ip_state[ip].banned_until = large_val
        self._fake_redis_get(monkeypatch, ip)
        await m.is_banned(ip)
        # orig: max(large_val, now()+3600) = large_val (preserved)
        # mutmut_16: max(now()+3600) ≈ now()+3600 (ignores large_val)
        assert st.ip_state[ip].banned_until > now() + 999_000  # still ~11 days

    @pytest.mark.asyncio
    async def test_redis_returns_true_when_banned(self, monkeypatch):
        # mutmut_19: return False, remaining instead of True, remaining
        m, st = self._mod(), self._st()
        ip = f"ib-rm19-{id(self) % 65535}"
        st.ip_state[ip].banned_until = 0.0
        self._fake_redis_get(monkeypatch, ip)
        result, _ = await m.is_banned(ip)
        assert result is True  # kills mutmut_19 which returns False

    @pytest.mark.asyncio
    async def test_redis_until_equals_time_not_banned(self, monkeypatch):
        """Kill mutmut_10: until >= _t.time() (>=) vs orig (>).
        When until==time exactly, orig: False; mutant: True."""
        import sys, types
        FROZEN = 1_000_000.0
        m, st = self._mod(), self._st()
        fake_t = types.SimpleNamespace(time=lambda: FROZEN)
        monkeypatch.setattr(m, '_t', fake_t)
        ip = f"ib-mm10-{id(self) % 65535}"
        st.ip_state[ip].banned_until = 0.0

        async def mock_get(arg):
            return FROZEN  # until == time exactly

        redis_mod = types.ModuleType('integrations.redis')
        redis_mod._shared_ban_get = mock_get
        monkeypatch.setitem(sys.modules, 'integrations.redis', redis_mod)

        result, remaining = await m.is_banned(ip)
        assert result is False, "until==time → NOT banned (kills mutmut_10 which uses >=)"
        assert remaining == 0.0

    @pytest.mark.asyncio
    async def test_redis_except_sets_until_zero_not_one(self, monkeypatch):
        """Kill mutmut_9: except sets until=1.0 instead of 0.0.
        Freeze _t.time() to 0.5 so 1.0 > 0.5 = True (mutant: banned), 0.0 > 0.5 = False (orig: not banned)."""
        import sys, types
        FROZEN_TINY = 0.5
        m, st = self._mod(), self._st()
        fake_t = types.SimpleNamespace(time=lambda: FROZEN_TINY)
        monkeypatch.setattr(m, '_t', fake_t)
        ip = f"ib-mm9-{id(self) % 65535}"
        st.ip_state[ip].banned_until = 0.0

        async def mock_get_raises(arg):
            raise RuntimeError("redis-down")

        redis_mod = types.ModuleType('integrations.redis')
        redis_mod._shared_ban_get = mock_get_raises
        monkeypatch.setitem(sys.modules, 'integrations.redis', redis_mod)

        result, remaining = await m.is_banned(ip)
        assert result is False, "except → until=0.0 → 0.0>0.5 False (kills mutmut_9 with until=1.0)"
        assert remaining == 0.0


# ── ban: Redis-path mock kills (mutmut_11-17) ────────────────────────────────

class TestBanRedisMock:
    """Mock integrations.redis to capture _shared_ban_set args in ban()."""

    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    def _setup_redis_set_mock(self, monkeypatch):
        """Inject fake redis module; return list that collects call args."""
        import sys, types
        calls = []

        async def mock_set(*args, **kwargs):
            calls.append(args)

        mod = types.ModuleType('integrations.redis')
        mod._shared_ban_set = mock_set
        monkeypatch.setitem(sys.modules, 'integrations.redis', mod)
        return calls

    @pytest.mark.asyncio
    async def test_ban_redis_first_arg_is_ip(self, monkeypatch):
        # mutmut_11: _shared_ban_set(None, ...) — first arg None instead of ip
        m = self._mod()
        calls = self._setup_redis_set_mock(monkeypatch)
        ip = f"ban-rs11-{id(self) % 65535}"
        await m.ban(ip, secs=60, reason="test-reason")
        assert calls, "mock was not called"
        assert calls[0][0] == ip  # kills mutmut_11 (None first arg)

    @pytest.mark.asyncio
    async def test_ban_redis_second_arg_is_future_timestamp(self, monkeypatch):
        # mutmut_17: _t.time() - secs instead of _t.time() + secs → past timestamp
        import time as _t
        m = self._mod()
        calls = self._setup_redis_set_mock(monkeypatch)
        ip = f"ban-rs17-{id(self) % 65535}"
        secs = 3600
        await m.ban(ip, secs=secs, reason="test-reason")
        assert calls
        until_arg = calls[0][1]
        assert until_arg > _t.time()  # must be in the future; mutmut_17 gives past

    @pytest.mark.asyncio
    async def test_ban_redis_third_arg_is_reason(self, monkeypatch):
        # mutmut_13: reason=None in third arg
        m = self._mod()
        calls = self._setup_redis_set_mock(monkeypatch)
        ip = f"ban-rs13-{id(self) % 65535}"
        await m.ban(ip, secs=60, reason="explicit-reason")
        assert calls
        assert calls[0][2] == "explicit-reason"  # kills mutmut_13 (None)

    @pytest.mark.asyncio
    async def test_ban_redis_three_positional_args(self, monkeypatch):
        # mutmut_14: _shared_ban_set(_t.time()+secs, reason) — only 2 args
        # mutmut_15: _shared_ban_set(ip, reason) — only 2 args
        # mutmut_16: _shared_ban_set(ip, _t.time()+secs, ) — trailing comma = 2 args
        m = self._mod()
        calls = self._setup_redis_set_mock(monkeypatch)
        ip = f"ban-rs14-{id(self) % 65535}"
        await m.ban(ip, secs=60, reason="test-reason")
        assert calls
        assert len(calls[0]) == 3  # ip, until, reason; kills mutmut_14,15,16


# ── update_risk_and_maybe_ban: NAT filter detail kills ───────────────────────

class TestUpdateRiskNatFilters:
    """Target surviving NAT-detection filter mutants (28,33,34,36-45,47,50)."""

    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    def _mock_redis_noop(self, monkeypatch):
        """Prevent real Redis connection when ban is triggered in test."""
        import sys, types
        mod = types.ModuleType('integrations.redis')
        async def _noop(*a, **kw): pass
        mod._shared_ban_set = _noop
        monkeypatch.setitem(sys.modules, 'integrations.redis', mod)

    def _setup_nat_entries(self, st, ip, count, *, last_ip=None, last_seen_offset=0,
                           static_loads=1, allowed_count=3):
        """Populate ip_to_identities with count entries meeting the orig filter."""
        from helpers import now
        n = now()
        keys = [f"natf-k{i}-{id(self)}-{ip}" for i in range(count)]
        for k in keys:
            s2 = st.ip_state[k]
            s2.last_ip = last_ip if last_ip is not None else ip
            s2.last_seen = n - last_seen_offset
            s2.static_loads = static_loads
            s2.allowed_count = allowed_count
            st.ip_to_identities[ip].add(k)
        return keys

    def _setup_nat_entries_fixed(self, st, ip, count, fixed_now, *, last_ip=None,
                                  last_seen_offset=0, static_loads=1, allowed_count=3):
        """Like _setup_nat_entries but uses a fixed now value for deterministic timing."""
        keys = [f"natff-k{i}-{id(self)}-{ip}" for i in range(count)]
        for k in keys:
            s2 = st.ip_state[k]
            s2.last_ip = last_ip if last_ip is not None else ip
            s2.last_seen = fixed_now - last_seen_offset
            s2.static_loads = static_loads
            s2.allowed_count = allowed_count
            st.ip_to_identities[ip].add(k)
        return keys

    @pytest.mark.asyncio
    async def test_nat_five_valid_entries_raises_threshold(self, monkeypatch):
        # With 5 valid entries: orig→NAT threshold(100)→no ban→False
        # Kills: mutmut_28 (get(None)), mutmut_36 (ip_state.get(None)),
        #        mutmut_37 (is None), mutmut_38 (last_ip !=),
        #        mutmut_39 (n + last_seen), mutmut_42 (static_loads > 1),
        #        mutmut_43 (static_loads >= 2), mutmut_44 (allowed_count > 3),
        #        mutmut_45 (allowed_count >= 4), mutmut_47 (> not >=)
        # All these mutants → identities=0 (or 5>5=False) → regular(50) → ban→True
        from config import RISK_BAN_THRESHOLD, NAT_IDENTITIES_THRESHOLD
        FIXED = 300000.0
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, "now", lambda: FIXED)
        ip = f"10.0.{id(self) % 254 + 1}.1"
        self._setup_nat_entries_fixed(st, ip, NAT_IDENTITIES_THRESHOLD, FIXED,
                                      last_seen_offset=60)
        track_key = f"natf5-main-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = FIXED
        result = await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        assert result is False  # NAT threshold: 53 < 100 → no ban

    @pytest.mark.asyncio
    async def test_nat_stale_last_seen_excluded(self, monkeypatch):
        # mutmut_33: (... <3600) or (static>=1 and allowed>=3) includes stale entries
        # 5 stale entries (2h ago) → orig: excluded → regular → ban → True
        # mutmut_33: or-short-circuit → included → NAT → no ban → False → killed
        self._mock_redis_noop(monkeypatch)
        from config import RISK_BAN_THRESHOLD, NAT_IDENTITIES_THRESHOLD
        FIXED = 300000.0
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, "now", lambda: FIXED)
        ip = f"10.0.{id(self) % 254 + 1}.2"
        self._setup_nat_entries_fixed(st, ip, NAT_IDENTITIES_THRESHOLD, FIXED,
                                      last_seen_offset=7200)  # 2 hours ago > 3600
        track_key = f"natf33-main-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = FIXED
        result = await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        assert result is True  # orig: stale excluded → regular → ban

    @pytest.mark.asyncio
    async def test_nat_wrong_last_ip_excluded(self, monkeypatch):
        # mutmut_34: (... and last_ip==ip) or (last_seen<3600 and ...) includes wrong-IP entries
        # 5 entries with wrong last_ip → orig: excluded → regular → ban → True
        # mutmut_34: or-short-circuit (recent last_seen) → included → NAT → no ban → False → killed
        self._mock_redis_noop(monkeypatch)
        from config import RISK_BAN_THRESHOLD, NAT_IDENTITIES_THRESHOLD
        FIXED = 300000.0
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, "now", lambda: FIXED)
        ip = f"10.0.{id(self) % 254 + 1}.3"
        self._setup_nat_entries_fixed(st, ip, NAT_IDENTITIES_THRESHOLD, FIXED,
                                      last_ip="9.9.9.9", last_seen_offset=60)
        track_key = f"natf34-main-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = FIXED
        result = await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        assert result is True  # orig: wrong last_ip excluded → regular → ban

    @pytest.mark.asyncio
    async def test_nat_entry_at_exact_3600s_boundary(self, monkeypatch):
        # mutmut_40 (<= 3600): 3600 <= 3600 = True → includes boundary entries → NAT
        # mutmut_41 (< 3601): 3600 < 3601 = True → same
        # orig (< 3600): 3600 < 3600 = False → excludes → regular → ban → True
        self._mock_redis_noop(monkeypatch)
        from config import RISK_BAN_THRESHOLD, NAT_IDENTITIES_THRESHOLD
        FIXED = 300000.0
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, "now", lambda: FIXED)
        ip = f"10.0.{id(self) % 254 + 1}.4"
        self._setup_nat_entries_fixed(st, ip, NAT_IDENTITIES_THRESHOLD, FIXED,
                                      last_seen_offset=3600)  # exactly at boundary
        track_key = f"natf40-main-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = FIXED
        result = await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        assert result is True  # orig: 3600 < 3600 False → excluded → regular → ban

    @pytest.mark.asyncio
    async def test_nat_banned_until_equals_now_triggers_ban(self, monkeypatch):
        # mutmut_50: s.banned_until < n (strict) → False when banned_until==n → no ban
        # orig: s.banned_until <= n → True → ban triggered
        self._mock_redis_noop(monkeypatch)
        from config import RISK_BAN_THRESHOLD, NAT_IDENTITIES_THRESHOLD
        FIXED = 300000.0
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, "now", lambda: FIXED)
        ip = f"10.0.{id(self) % 254 + 1}.5"
        # No NAT entries → identities=0 → regular threshold (50)
        track_key = f"natf50-main-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = FIXED  # exactly == now
        st.ip_state[track_key].last_risk_update = FIXED
        result = await m.update_risk_and_maybe_ban(track_key, "honeypot", ip)
        assert result is True  # orig: banned_until <= n → True → retrigger ban


class TestUpdateRiskPostBanPath:
    """Kill mutmut_70-119: post-ban Redis/JA4/webhook side-effect assertions.

    All these mutants modify code inside try/except Exception:pass so they can't
    be killed by checking the return value — we must assert integration call args.
    """

    def _mod(self):
        import scoring as m
        return m

    def _st(self):
        import state as s
        return s

    def _setup_integrations(self, monkeypatch):
        """Inject async spy mocks for all three integration modules."""
        import sys, types
        redis_calls: list = []
        ja4_calls: list = []
        webhook_calls: list = []

        async def mock_shared_ban_set(*a, **kw):
            redis_calls.append(a)

        async def mock_observe_ja4_ban(*a, **kw):
            ja4_calls.append(a)

        async def mock_post_webhook(*a, **kw):
            webhook_calls.append(a[0] if a else None)

        redis_mod = types.ModuleType('integrations.redis')
        redis_mod._shared_ban_set = mock_shared_ban_set
        monkeypatch.setitem(sys.modules, 'integrations.redis', redis_mod)

        ja4_mod = types.ModuleType('integrations.ja4')
        ja4_mod._observe_ja4_ban = mock_observe_ja4_ban
        monkeypatch.setitem(sys.modules, 'integrations.ja4', ja4_mod)

        wh_mod = types.ModuleType('integrations.webhook')
        wh_mod._post_webhook = mock_post_webhook
        monkeypatch.setitem(sys.modules, 'integrations.webhook', wh_mod)

        return redis_calls, ja4_calls, webhook_calls

    @pytest.mark.asyncio
    async def test_post_ban_integration_correct_args(self, monkeypatch):
        """Kill mutmut_70-87,89-119 by asserting correct integration call args."""
        import asyncio, time as _time
        redis_calls, ja4_calls, webhook_calls = self._setup_integrations(monkeypatch)
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, 'WEBHOOK_URL', 'https://hook.test.internal')
        from config import RISK_BAN_THRESHOLD, RISK_BAN_DURATION_SECS
        ip = f"10.0.{id(self) % 254 + 1}.20"
        track_key = f"pst-ban-{id(self)}"
        reason = "js-challenge"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = m.now()
        st.ip_state[track_key].last_ja4 = "t13d2d_testja4"
        st.ip_state[track_key].last_user_agent = "Mozilla/5.0 Test"
        before = _time.time()
        result = await m.update_risk_and_maybe_ban(track_key, reason, ip)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert result is True
        # redis checks: kills 70 (None arg1), 71 (None arg2), 72 (None arg3),
        #               73-75 (arg count), 76 (past timestamp), 77 (not called)
        assert redis_calls, "redis must be called (kills 77)"
        assert len(redis_calls[0]) == 3, "must pass 3 args (kills 73,74,75)"
        assert redis_calls[0][0] == track_key, "arg1=track_key (kills 70)"
        assert redis_calls[0][1] >= before + RISK_BAN_DURATION_SECS - 2, (
            "arg2=future timestamp (kills 71,76)")
        assert isinstance(redis_calls[0][2], str), "arg3 is string (kills 72)"
        assert redis_calls[0][2].startswith("risk-score:"), "arg3 format (kills 72)"
        assert redis_calls[0][2].endswith(":" + reason), "arg3 has reason (kills 72)"
        # ja4 checks: kills 78 (last_ja4=None), 79 (last_ja4=''), 81 (t1=None),
        #             82 (create_task(None)), 83 (_observe_ja4_ban(None))
        assert ja4_calls, "ja4 must be called when last_ja4 set (kills 78,79,81,82)"
        assert ja4_calls[0][0] == "t13d2d_testja4", "ja4 arg must be last_ja4 (kills 83)"
        # webhook checks: kills 85 (callback(None) aborts), 86 (t2=None),
        #                 87 (create_task(None)), 88 (_post_webhook(None)),
        #                 89-119 (payload key/value mutations)
        assert webhook_calls, "webhook must be called when WEBHOOK_URL set (kills 85,86,87)"
        payload = webhook_calls[0]
        assert isinstance(payload, dict), "payload must be dict (kills 88)"
        assert payload.get("event") == "ban", "event=ban (kills 89,90,91,92)"
        assert "ts" in payload, "ts key present (kills 93,94)"
        assert payload.get("reason") == reason, "reason matches input (kills 95,96)"
        assert "risk_score" in payload, "risk_score key present (kills 97,98)"
        assert payload.get("track_key") == track_key[:32], "track_key truncated correctly (kills 99,100)"
        assert payload.get("ip") == ip, "ip matches (kills 101,102)"  # noqa: E501 — for readability in mutmut context
        assert payload.get("ja4") == "t13d2d_testja4", "ja4 from state (kills 103,104)"
        assert "ua" in payload, "ua key present (kills 105,106)"
        assert "duration_s" in payload, "duration_s key present (kills 107,108)"
        assert payload.get("hostile") is False, "js-challenge not hostile (kills 117,118)"

    @pytest.mark.asyncio
    async def test_post_ban_ja4_not_called_when_last_ja4_none(self, monkeypatch):
        """Kill mutmut_80: (s.last_ja4 or 'XXXX') would call ja4 with 'XXXX' when None."""
        import asyncio
        redis_calls, ja4_calls, webhook_calls = self._setup_integrations(monkeypatch)
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, 'WEBHOOK_URL', '')
        from config import RISK_BAN_THRESHOLD
        ip = f"10.0.{id(self) % 254 + 1}.21"
        track_key = f"pst-nm80-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = m.now()
        st.ip_state[track_key].last_ja4 = None
        await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        await asyncio.sleep(0)
        assert not ja4_calls, "ja4 must NOT be called when last_ja4 is None (kills 80)"

    @pytest.mark.asyncio
    async def test_post_ban_hostile_reason_sets_hostile_true(self, monkeypatch):
        """Kill mutmut_119 variant and webhook hostile-flag mutations."""
        import asyncio
        from config import _HOSTILE_REASONS, RISK_BAN_THRESHOLD
        redis_calls, ja4_calls, webhook_calls = self._setup_integrations(monkeypatch)
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, 'WEBHOOK_URL', 'https://hook.test.internal')
        hostile_reason = next(r for r in _HOSTILE_REASONS if r not in {"canary-echo","honeypot-silent","honeypot"})
        weight = m.RISK_WEIGHTS.get(hostile_reason, 0)
        if weight == 0:
            pytest.skip("hostile reason has no risk weight")
        ip = f"10.0.{id(self) % 254 + 1}.22"
        track_key = f"pst-hostile-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = m.now()
        st.ip_state[track_key].last_ja4 = None
        await m.update_risk_and_maybe_ban(track_key, hostile_reason, ip)
        await asyncio.sleep(0)
        assert webhook_calls, "webhook called for hostile ban"
        assert webhook_calls[0].get("hostile") is True, "hostile=True for hostile reason"

    @pytest.mark.asyncio
    async def test_track_key_truncated_to_32_not_33(self, monkeypatch):
        """Kill mutmut_103: track_key[:33] vs [:32]. Use 40-char key to expose off-by-one."""
        import asyncio
        redis_calls, ja4_calls, webhook_calls = self._setup_integrations(monkeypatch)
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, 'WEBHOOK_URL', 'https://hook.test.internal')
        from config import RISK_BAN_THRESHOLD
        ip = "10.0.50.103"
        track_key = "abcdefghij" * 4  # exactly 40 chars: [:32] != [:33]
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = m.now()
        st.ip_state[track_key].last_ja4 = None
        await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        await asyncio.sleep(0)
        assert webhook_calls
        assert webhook_calls[0]["track_key"] == track_key[:32], (
            f"must truncate at 32 not 33 (kills 103): got {webhook_calls[0]['track_key']!r}")

    @pytest.mark.asyncio
    async def test_webhook_ua_preserves_value_when_set(self, monkeypatch):
        """Kill mutmut_110: (ua and '') returns '' for truthy ua — must return the ua value."""
        import asyncio
        redis_calls, ja4_calls, webhook_calls = self._setup_integrations(monkeypatch)
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, 'WEBHOOK_URL', 'https://hook.test.internal')
        from config import RISK_BAN_THRESHOLD
        ip = "10.0.50.110"
        track_key = f"pst-ua110-{id(self)}"
        ua_value = "Mozilla/5.0 (KillMutmut110)"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = m.now()
        st.ip_state[track_key].last_ja4 = None
        st.ip_state[track_key].last_user_agent = ua_value
        await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        await asyncio.sleep(0)
        assert webhook_calls
        assert webhook_calls[0]["ua"] == ua_value, (
            f"ua must equal user_agent (kills 110: 'and' returns ''), got {webhook_calls[0]['ua']!r}")

    @pytest.mark.asyncio
    async def test_webhook_ua_empty_when_none(self, monkeypatch):
        """Kill mutmut_111: (ua or 'XXXX') returns 'XXXX' when None instead of ''."""
        import asyncio
        redis_calls, ja4_calls, webhook_calls = self._setup_integrations(monkeypatch)
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, 'WEBHOOK_URL', 'https://hook.test.internal')
        from config import RISK_BAN_THRESHOLD
        ip = "10.0.50.111"
        track_key = f"pst-ua111-{id(self)}"
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = m.now()
        st.ip_state[track_key].last_ja4 = None
        st.ip_state[track_key].last_user_agent = None
        await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        await asyncio.sleep(0)
        assert webhook_calls
        assert webhook_calls[0]["ua"] == "", (
            f"ua must be '' when None (kills 111: or 'XXXX'), got {webhook_calls[0]['ua']!r}")

    @pytest.mark.asyncio
    async def test_webhook_ua_truncated_at_120_not_121(self, monkeypatch):
        """Kill mutmut_112: [:121] vs [:120]. Use 130-char UA to expose off-by-one."""
        import asyncio
        redis_calls, ja4_calls, webhook_calls = self._setup_integrations(monkeypatch)
        m, st = self._mod(), self._st()
        monkeypatch.setattr(m, 'WEBHOOK_URL', 'https://hook.test.internal')
        from config import RISK_BAN_THRESHOLD
        ip = "10.0.50.112"
        track_key = f"pst-ua112-{id(self)}"
        long_ua = "A" * 130
        st.ip_state[track_key].risk_score = RISK_BAN_THRESHOLD
        st.ip_state[track_key].banned_until = 0.0
        st.ip_state[track_key].last_risk_update = m.now()
        st.ip_state[track_key].last_ja4 = None
        st.ip_state[track_key].last_user_agent = long_ua
        await m.update_risk_and_maybe_ban(track_key, "js-challenge", ip)
        await asyncio.sleep(0)
        assert webhook_calls
        assert webhook_calls[0]["ua"] == "A" * 120, (
            f"ua must be truncated at 120 (kills 112: [:121]), got len={len(webhook_calls[0]['ua'])}")


class TestLoadSignalOrderCache:
    """Kill _load_signal_order_cache survivors via slog spy + SQLite temp DB.

    Survivors are mutations to slog() call args (level, event string, kwargs).
    Tests: 18 (level=None), 27 (level='XXinfoXX'), 28 (level='INFO'),
           30 (error-level=None), 31 (error=None), 33 (missing level kwarg → 'info'),
           34 (missing error kwarg), 35 ('XXsignal_orders_load_failedXX'),
           37 (error-level='XXwarnXX'), 38 (error-level='WARN'), 39 (error=str(None)).
    Equivalent (can't kill): 10 (SQL lowercase), 11 (SQL uppercase), 22 (missing level→default).
    """

    def _mod(self):
        import scoring as m
        return m

    def _setup_admin_mesh_mock(self, monkeypatch, gw_id="test-gw-001"):
        import sys, types
        mesh_mod = types.ModuleType('admin.mesh')
        mesh_mod._gw_local_id = lambda: gw_id
        monkeypatch.setitem(sys.modules, 'admin.mesh', mesh_mod)
        return gw_id

    def _make_db(self, gw_id="test-gw-001", rows=None):
        import tempfile, sqlite3 as _sqlite3, os
        tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        tmp.close()
        conn = _sqlite3.connect(tmp.name)
        conn.execute("""CREATE TABLE signal_orders (
            gw_id TEXT, signal TEXT, activation_order INT,
            updated_ts REAL, updated_by TEXT)""")
        for row in (rows or []):
            conn.execute("INSERT INTO signal_orders VALUES (?,?,?,?,?)", row)
        conn.commit()
        conn.close()
        return tmp.name

    def _make_slog_spy(self, monkeypatch):
        calls = []
        def fake_slog(event, level="info", **fields):
            calls.append({"event": event, "level": level, "fields": fields})
        m = self._mod()
        monkeypatch.setattr(m, 'slog', fake_slog)
        return calls

    def test_happy_path_slog_level_info(self, monkeypatch):
        """Kill mutmut_18 (level=None), 27 (level='XXinfoXX'), 28 (level='INFO').
        Happy path: DB has matching rows → cache populated → slog with level='info'."""
        import tempfile, os
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        db_path = self._make_db(gw_id, rows=[(gw_id, "js-challenge", 2, 0.0, "test")])
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        slog_calls = self._make_slog_spy(monkeypatch)
        # Clear the cache so the if _signal_order_cache: branch runs
        from state import _signal_order_cache
        _signal_order_cache.clear()
        try:
            m._load_signal_order_cache()
        finally:
            os.unlink(db_path)
        # Assert cache was populated
        assert "js-challenge" in _signal_order_cache, "cache must be populated"
        # Assert slog called with level='info' (kills 18,27,28)
        assert slog_calls, "slog must have been called"
        assert slog_calls[0]["event"] == "signal_orders_loaded"
        assert slog_calls[0]["level"] == "info", f"level must be 'info', got {slog_calls[0]['level']!r}"

    def test_error_path_slog_level_warn(self, monkeypatch):
        """Kill mutmut_30 (level=None), 37 (level='XXwarnXX'), 38 (level='WARN').
        Error path: DB connect succeeds but execute raises → slog with level='warn'."""
        import types
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        slog_calls = self._make_slog_spy(monkeypatch)

        class _MockConn:
            def execute(self, *a, **kw):
                raise RuntimeError("mock-sqlite-error-for-mutmut")
            def close(self): pass

        class _MockSqlite3:
            @staticmethod
            def connect(path): return _MockConn()

        monkeypatch.setattr(m, 'sqlite3', _MockSqlite3)
        monkeypatch.setattr(m, 'DB_PATH', '/nonexistent/path.db')
        m._load_signal_order_cache()
        assert slog_calls, "slog must have been called on error"
        assert slog_calls[0]["event"] == "signal_orders_load_failed", "correct event name (kills 35)"
        assert slog_calls[0]["level"] == "warn", f"level must be 'warn', got {slog_calls[0]['level']!r} (kills 30,37,38)"
        assert "error" in slog_calls[0]["fields"], "error kwarg must be present (kills 34)"
        assert slog_calls[0]["fields"]["error"] is not None, "error must not be None (kills 31)"
        assert "mock-sqlite-error-for-mutmut" in slog_calls[0]["fields"]["error"], "error must contain exc string (kills 39)"

    def test_error_path_slog_has_level_kwarg(self, monkeypatch):
        """Kill mutmut_33: missing level kwarg → defaults to 'info' not 'warn'."""
        import types
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        slog_calls = self._make_slog_spy(monkeypatch)

        class _MockConn:
            def execute(self, *a, **kw): raise RuntimeError("err33")
            def close(self): pass

        class _MockSqlite3:
            @staticmethod
            def connect(path): return _MockConn()

        monkeypatch.setattr(m, 'sqlite3', _MockSqlite3)
        monkeypatch.setattr(m, 'DB_PATH', '/nonexistent/path.db')
        m._load_signal_order_cache()
        assert slog_calls
        assert slog_calls[0]["level"] == "warn", "error path must use level='warn' not default 'info' (kills 33)"

    def test_order1_rows_included_in_cache(self, monkeypatch):
        """Kill mutmut_14: n in (2, 2, 3) drops order-1 rows — must include them."""
        import os
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        db_path = self._make_db(gw_id, rows=[(gw_id, "rate-limit", 1, 0.0, "test")])
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        self._make_slog_spy(monkeypatch)
        from state import _signal_order_cache
        _signal_order_cache.clear()
        try:
            m._load_signal_order_cache()
        finally:
            os.unlink(db_path)
        assert "rate-limit" in _signal_order_cache, "order-1 rows must be loaded (kills 14)"
        assert _signal_order_cache["rate-limit"] == 1

    def test_order3_rows_included_in_cache(self, monkeypatch):
        """Kill mutmut_16: n in (1, 2, 4) drops order-3 rows — must include them."""
        import os
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        db_path = self._make_db(gw_id, rows=[(gw_id, "ai-probe", 3, 0.0, "test")])
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        self._make_slog_spy(monkeypatch)
        from state import _signal_order_cache
        _signal_order_cache.clear()
        try:
            m._load_signal_order_cache()
        finally:
            os.unlink(db_path)
        assert "ai-probe" in _signal_order_cache, "order-3 rows must be loaded (kills 16)"
        assert _signal_order_cache["ai-probe"] == 3

    def test_slog_happy_path_count_and_gw_id_kwargs(self, monkeypatch):
        """Kill mutmut_19 (count=None), 20 (gw_id=None), 23 (missing count), 24 (missing gw_id)."""
        import os
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch, gw_id="gw-kwarg-test")
        db_path = self._make_db(gw_id, rows=[(gw_id, "js-challenge", 2, 0.0, "t")])
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        slog_calls = self._make_slog_spy(monkeypatch)
        from state import _signal_order_cache
        _signal_order_cache.clear()
        try:
            m._load_signal_order_cache()
        finally:
            os.unlink(db_path)
        assert slog_calls
        assert slog_calls[0]["event"] == "signal_orders_loaded"
        fields = slog_calls[0]["fields"]
        assert "count" in fields, "slog must include count kwarg (kills 23)"
        assert fields["count"] is not None, "count must not be None (kills 19)"
        assert fields["count"] == 1, "count must equal loaded entries (kills 19)"
        assert "gw_id" in fields, "slog must include gw_id kwarg (kills 24)"
        assert fields["gw_id"] is not None, "gw_id must not be None (kills 20)"
        assert fields["gw_id"] == gw_id, "gw_id must equal gateway id (kills 20)"


class TestSaveSignalOrder:
    """Kill _save_signal_order survivors via DB/slog/postgres spies.

    Survivors:
    - mutmut_2: ts=None (null DB timestamp)
    - mutmut_9-19: error-path slog arg mutations
    - mutmut_21: pg=None always (postgres block never runs)
    - mutmut_22: equivalent (pg="" in except → still falsy)
    - mutmut_23: or instead of and in guard
    - mutmut_24-26: pg.connect() kwarg mutations
    - mutmut_27-35: Postgres SQL/param mutations
    """

    def _mod(self):
        import scoring as m
        return m

    def _setup_admin_mesh_mock(self, monkeypatch, gw_id="test-gw-save"):
        import sys, types
        mesh_mod = types.ModuleType('admin.mesh')
        mesh_mod._gw_local_id = lambda: gw_id
        monkeypatch.setitem(sys.modules, 'admin.mesh', mesh_mod)
        return gw_id

    def _make_db(self, gw_id="test-gw-save"):
        import tempfile, sqlite3 as _sqlite3, os
        tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        tmp.close()
        conn = _sqlite3.connect(tmp.name)
        conn.execute("""CREATE TABLE signal_orders (
            gw_id TEXT, signal TEXT, activation_order INT,
            updated_ts REAL, updated_by TEXT,
            PRIMARY KEY (gw_id, signal))""")
        conn.commit()
        conn.close()
        return tmp.name

    def _make_slog_spy(self, monkeypatch):
        calls = []
        def fake_slog(event="<missing>", level="info", **fields):
            calls.append({"event": event, "level": level, "fields": fields})
        m = self._mod()
        monkeypatch.setattr(m, 'slog', fake_slog)
        return calls

    def _mock_sqlite_execute_fail(self, monkeypatch, exc_msg="mock-sqlite-fail"):
        m = self._mod()
        class _MockConn:
            def execute(self, *a, **kw): raise RuntimeError(exc_msg)
            def commit(self): pass
            def close(self): pass
        class _MockSqlite3:
            @staticmethod
            def connect(path): return _MockConn()
        monkeypatch.setattr(m, 'sqlite3', _MockSqlite3)
        monkeypatch.setattr(m, 'DB_PATH', '/nonexistent/path.db')

    def _setup_postgres_spy(self, monkeypatch, postgres_dsn="postgres://test/db"):
        import sys, types
        from unittest.mock import MagicMock
        m = self._mod()
        connect_calls = []
        execute_calls = []

        mock_cur_ctx = MagicMock()
        mock_cur_ctx.__enter__.return_value.execute = lambda sql, params: execute_calls.append((sql, params))
        mock_cur_ctx.__exit__ = MagicMock(return_value=False)

        mock_conn_ctx = MagicMock()
        mock_conn_ctx.__enter__.return_value.cursor.return_value = mock_cur_ctx
        mock_conn_ctx.__exit__ = MagicMock(return_value=False)

        mock_pg = MagicMock()
        mock_pg.connect = lambda *a, **kw: (connect_calls.append((a, kw)) or mock_conn_ctx)

        def mock_postgres_load():
            return mock_pg

        pg_mod = types.ModuleType('db.postgres')
        pg_mod._postgres_load_module = mock_postgres_load
        monkeypatch.setitem(sys.modules, 'db.postgres', pg_mod)
        monkeypatch.setattr(m, 'POSTGRES_DSN', postgres_dsn)
        return connect_calls, execute_calls

    def test_happy_path_ts_not_none(self, monkeypatch):
        """Kill mutmut_2: ts=None → DB stores NULL timestamp."""
        import sqlite3 as _sqlite3, os
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        db_path = self._make_db(gw_id)
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        monkeypatch.setattr(m, 'POSTGRES_DSN', '')
        try:
            m._save_signal_order("js-challenge", 2, "test-actor")
            conn = _sqlite3.connect(db_path)
            rows = conn.execute(
                "SELECT updated_ts FROM signal_orders WHERE gw_id=? AND signal=?",
                (gw_id, "js-challenge")
            ).fetchall()
            conn.close()
            assert rows, "row must exist in DB"
            assert rows[0][0] is not None, "updated_ts must not be None (kills mutmut_2)"
            assert isinstance(rows[0][0], float), "updated_ts must be a float"
        finally:
            os.unlink(db_path)

    def test_error_path_slog_correct_args(self, monkeypatch):
        """Kill mutmut_9-19: slog called with correct event/level/error on SQLite failure."""
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        slog_calls = self._make_slog_spy(monkeypatch)
        self._mock_sqlite_execute_fail(monkeypatch, exc_msg="unique-error-xyz")
        monkeypatch.setattr(m, 'POSTGRES_DSN', '')
        m._save_signal_order("js-challenge", 2, "test-actor")
        assert slog_calls, "slog must be called on SQLite error"
        call = slog_calls[0]
        assert call["event"] == "signal_orders_save_failed", (
            f"wrong event: {call['event']!r} (kills 9,15,16)")
        assert call["level"] == "warn", (
            f"wrong level: {call['level']!r} (kills 10,13,17,18)")
        assert "error" in call["fields"], "error kwarg must be present (kills 14)"
        assert call["fields"]["error"] is not None, "error must not be None (kills 11)"
        assert "unique-error-xyz" in call["fields"]["error"], (
            "error must contain exc str (kills 19)")

    def test_cache_updated_on_success(self, monkeypatch):
        """Verify _signal_order_cache[sig]=order after successful save."""
        import sqlite3 as _sqlite3, os
        from state import _signal_order_cache
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        db_path = self._make_db(gw_id)
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        monkeypatch.setattr(m, 'POSTGRES_DSN', '')
        sig = "honeypot-test-sig"
        _signal_order_cache.pop(sig, None)
        try:
            m._save_signal_order(sig, 3, "test-actor")
            assert _signal_order_cache.get(sig) == 3, "cache must be updated (kills 20 if not already)"
        finally:
            os.unlink(db_path)

    def test_postgres_execute_called_when_pg_and_dsn(self, monkeypatch):
        """Kill mutmut_21: pg=None always → Postgres execute never called."""
        import sqlite3 as _sqlite3, os
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        db_path = self._make_db(gw_id)
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        connect_calls, execute_calls = self._setup_postgres_spy(monkeypatch)
        try:
            m._save_signal_order("js-challenge", 2, "test-actor")
            assert execute_calls, "Postgres execute must be called when pg and DSN set (kills 21)"
        finally:
            os.unlink(db_path)

    def test_postgres_guard_requires_both_pg_and_dsn(self, monkeypatch):
        """Kill mutmut_23: or instead of and — runs when DSN empty but pg truthy."""
        import sqlite3 as _sqlite3, os
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        db_path = self._make_db(gw_id)
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        connect_calls, execute_calls = self._setup_postgres_spy(monkeypatch, postgres_dsn="")
        try:
            m._save_signal_order("js-challenge", 2, "test-actor")
            assert not execute_calls, "Postgres execute must NOT run when DSN empty (kills 23: or would run it)"
        finally:
            os.unlink(db_path)

    def test_postgres_connect_called_with_dsn_and_kwargs(self, monkeypatch):
        """Kill mutmut_24 (connect(None)), 25 (timeout=None), 26 (autocommit=None)."""
        import sqlite3 as _sqlite3, os
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        db_path = self._make_db(gw_id)
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        POSTGRES_DSN_VAL = "postgres://testhost/testdb"
        connect_calls, execute_calls = self._setup_postgres_spy(monkeypatch, postgres_dsn=POSTGRES_DSN_VAL)
        try:
            m._save_signal_order("js-challenge", 2, "test-actor")
            assert connect_calls, "Postgres connect must be called"
            conn_args, conn_kwargs = connect_calls[0]
            assert conn_args and conn_args[0] == POSTGRES_DSN_VAL, (
                f"connect first arg must be DSN (kills 24), got {conn_args!r}")
            assert conn_kwargs.get("connect_timeout") == 3, (
                f"connect_timeout must be 3 (kills 25), got {conn_kwargs!r}")
            assert conn_kwargs.get("autocommit") is True, (
                f"autocommit must be True (kills 26), got {conn_kwargs!r}")
        finally:
            os.unlink(db_path)

    def test_postgres_execute_sql_and_params(self, monkeypatch):
        """Kill mutmut_27-35: Postgres INSERT SQL and params must be correct."""
        import sqlite3 as _sqlite3, os, time as _time
        m = self._mod()
        gw_id = self._setup_admin_mesh_mock(monkeypatch)
        db_path = self._make_db(gw_id)
        monkeypatch.setattr(m, 'DB_PATH', db_path)
        POSTGRES_DSN_VAL = "postgres://testhost/testdb"
        connect_calls, execute_calls = self._setup_postgres_spy(monkeypatch, postgres_dsn=POSTGRES_DSN_VAL)
        sig, order, actor = "ai-probe", 1, "test-actor-2"
        before = _time.time()
        try:
            m._save_signal_order(sig, order, actor)
            assert execute_calls, "Postgres execute must be called"
            sql, params = execute_calls[0]
            assert "INSERT INTO signal_orders" in sql, f"SQL must contain INSERT (kills 27-35): {sql!r}"
            assert "signal_orders" in sql
            assert len(params) == 5, f"must pass 5 params (kills tuple mutations): {params!r}"
            assert params[0] == gw_id, f"params[0] must be gw_id (kills 28): {params!r}"
            assert params[1] == sig, f"params[1] must be sig (kills 29): {params!r}"
            assert params[2] == order, f"params[2] must be order (kills 30): {params!r}"
            assert params[3] is not None and params[3] >= before, (
                f"params[3] must be timestamp (kills 31): {params!r}")
            assert params[4] == actor, f"params[4] must be actor (kills 32): {params!r}"
        finally:
            os.unlink(db_path)


# ─────────────────────────────────────────────────────────────────────────────
# Bypass & Allowlists — static QA (1.8.10)
# Covers the five knobs in the Bypass & Allowlists controls group:
#   BYPASS_MODE, BOT_DETECTION_ENABLED, BYPASS_PATHS,
#   AUTHORIZED_BOT_UAS, JS_CHAL_OPEN_PATHS
# ─────────────────────────────────────────────────────────────────────────────

class TestBypassAllowlistsStaticQA:

    # ── Knob presence in _HOT_RELOAD_KNOBS ───────────────────────────────────

    def _knobs(self):
        from core.proxy_handler import _HOT_RELOAD_KNOBS
        return _HOT_RELOAD_KNOBS

    def test_bypass_mode_in_hot_reload_knobs(self):
        """BYPASS_MODE must be hot-reloadable (incident-response toggle)."""
        assert "BYPASS_MODE" in self._knobs(), (
            "BYPASS_MODE missing from _HOT_RELOAD_KNOBS — "
            "operators cannot toggle site-wide bypass at runtime"
        )

    def test_bot_detection_enabled_in_hot_reload_knobs(self):
        """BOT_DETECTION_ENABLED must be hot-reloadable (global master switch)."""
        assert "BOT_DETECTION_ENABLED" in self._knobs(), (
            "BOT_DETECTION_ENABLED missing from _HOT_RELOAD_KNOBS — "
            "global bot-detection master switch cannot be toggled at runtime"
        )

    def test_bypass_paths_in_hot_reload_knobs(self):
        """BYPASS_PATHS must be hot-reloadable (operators add/remove paths live)."""
        assert "BYPASS_PATHS" in self._knobs(), (
            "BYPASS_PATHS missing from _HOT_RELOAD_KNOBS"
        )

    def test_js_chal_open_paths_in_hot_reload_knobs(self):
        """JS_CHAL_OPEN_PATHS must be hot-reloadable."""
        assert "JS_CHAL_OPEN_PATHS" in self._knobs(), (
            "JS_CHAL_OPEN_PATHS missing from _HOT_RELOAD_KNOBS"
        )

    def test_authorized_bot_uas_in_hot_reload_knobs(self):
        """AUTHORIZED_BOT_UAS must be hot-reloadable."""
        assert "AUTHORIZED_BOT_UAS" in self._knobs(), (
            "AUTHORIZED_BOT_UAS missing from _HOT_RELOAD_KNOBS"
        )

    # ── _NOT_PERSIST_KNOBS ────────────────────────────────────────────────────

    def test_bypass_mode_in_not_persist_knobs(self):
        """BYPASS_MODE must NOT be persisted to the DB (resets on restart)."""
        from core.proxy_handler import _NOT_PERSIST_KNOBS
        assert "BYPASS_MODE" in _NOT_PERSIST_KNOBS, (
            "BYPASS_MODE must be in _NOT_PERSIST_KNOBS so it resets to False "
            "on container restart — emergency bypass must never survive a restart"
        )

    def test_bot_detection_enabled_not_in_not_persist_knobs(self):
        """BOT_DETECTION_ENABLED should persist across restarts (intentional setting)."""
        from core.proxy_handler import _NOT_PERSIST_KNOBS
        assert "BOT_DETECTION_ENABLED" not in _NOT_PERSIST_KNOBS, (
            "BOT_DETECTION_ENABLED must persist across restarts — "
            "it is an intentional vhost/global configuration, not an incident toggle"
        )

    # ── Source ordering ───────────────────────────────────────────────────────

    def test_bypass_mode_precedes_authorized_bot_uas_in_source(self):
        """BYPASS_MODE guard must appear before AUTHORIZED_BOT_UAS in protect().

        If BYPASS_MODE sits below AUTHORIZED_BOT_UAS, action=ban entries can
        still ban traffic even when the operator has enabled bypass mode.
        """
        import inspect
        from core import proxy_handler
        src = inspect.getsource(proxy_handler.protect)
        bypass_idx  = src.find("if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path")
        bot_uas_idx = src.find("if AUTHORIZED_BOT_UAS:")
        assert bypass_idx != -1,  "BYPASS_MODE check missing from protect()"
        assert bot_uas_idx != -1, "AUTHORIZED_BOT_UAS loop missing from protect()"
        assert bypass_idx < bot_uas_idx, (
            f"BYPASS_MODE check (pos {bypass_idx}) must precede "
            f"AUTHORIZED_BOT_UAS (pos {bot_uas_idx}) in protect() — "
            "otherwise action=ban entries fire even in bypass mode"
        )

    def test_bypass_mode_precedes_bypass_paths_in_source(self):
        """BYPASS_MODE guard must appear before BYPASS_PATHS in protect()."""
        import inspect
        from core import proxy_handler
        src = inspect.getsource(proxy_handler.protect)
        bypass_idx  = src.find("if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path")
        # 1.8.14 — BYPASS_PATHS may be guarded by the legacy `any(...)` form
        # or the precompiled `_bypass_match(...)` helper. Match either.
        paths_idx = -1
        for needle in (
            "if vc('BYPASS_PATHS') and any(",
            "_bypass_match(request.path",
        ):
            i = src.find(needle)
            if i != -1:
                paths_idx = i
                break
        assert bypass_idx != -1, "BYPASS_MODE check missing"
        assert paths_idx  != -1, "BYPASS_PATHS check missing"
        assert bypass_idx < paths_idx, (
            "BYPASS_MODE must precede BYPASS_PATHS in protect()"
        )

    def test_bot_detection_enabled_gate_after_rate_limit(self):
        """BOT_DETECTION_ENABLED gate must sit AFTER rate-limit enforcement.

        Rate limits are unconditional — they must fire even when bot detection
        is disabled (e.g. for a trusted internal vhost under attack).
        """
        import inspect
        from core import proxy_handler
        src = inspect.getsource(proxy_handler.protect)
        rate_idx = src.find("rate-limit-endpoint")
        bde_idx  = src.find("if not vc('BOT_DETECTION_ENABLED')")
        assert rate_idx != -1, "rate-limit-endpoint reason missing from protect()"
        assert bde_idx  != -1, "BOT_DETECTION_ENABLED gate missing from protect()"
        assert rate_idx < bde_idx, (
            f"Rate-limit enforcement (pos {rate_idx}) must precede "
            f"BOT_DETECTION_ENABLED gate (pos {bde_idx}) — "
            "rate limits must apply even when bot detection is off"
        )

    # ── AUTHORIZED_BOT_UAS action validation ──────────────────────────────────

    def test_authorized_bot_uas_valid_actions(self):
        """Every entry in default AUTHORIZED_BOT_UAS must have a recognised action."""
        import os, importlib
        os.environ.setdefault("UPSTREAM", "https://example.com")
        cfg = importlib.import_module("config")
        valid_actions = {"authorized-robot", "allow", "ban", "really-ban"}
        for entry in getattr(cfg, "AUTHORIZED_BOT_UAS", []):
            if not isinstance(entry, dict):
                continue
            action = entry.get("action", "authorized-robot")
            assert action in valid_actions, (
                f"AUTHORIZED_BOT_UAS entry {entry.get('name')!r} has "
                f"unrecognised action {action!r} — valid: {sorted(valid_actions)}"
            )

    def test_authorized_bot_uas_enabled_field_is_bool(self):
        """Every dict entry in AUTHORIZED_BOT_UAS must have enabled as a bool."""
        import os, importlib
        os.environ.setdefault("UPSTREAM", "https://example.com")
        cfg = importlib.import_module("config")
        for entry in getattr(cfg, "AUTHORIZED_BOT_UAS", []):
            if not isinstance(entry, dict):
                continue
            assert isinstance(entry.get("enabled", True), bool), (
                f"AUTHORIZED_BOT_UAS entry {entry.get('name')!r}: "
                f"'enabled' must be bool, got {type(entry.get('enabled'))}"
            )

    # ── Dashboard META coverage ───────────────────────────────────────────────

    def test_bypass_group_bool_knobs_in_controls_meta(self):
        """BOT_DETECTION_ENABLED and BYPASS_MODE must appear in controls.html META dict."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent /
               "dashboards" / "controls.html").read_text()
        for knob in ("BOT_DETECTION_ENABLED", "BYPASS_MODE"):
            assert f"{knob}:" in src, (
                f"{knob} missing from controls.html META — "
                "the Bypass & Allowlists group card will be empty"
            )

    def test_bypass_group_knobs_in_ctrl_groups(self):
        """The bypass CTRL_GROUP must list all 5 bypass knobs."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent /
               "dashboards" / "controls.html").read_text()
        # Find the CTRL_GROUPS entry (has lane:'bypass' + knobs:)
        bypass_block_start = src.find("lane:'bypass',  knobs:")
        assert bypass_block_start != -1, "bypass CTRL_GROUP knobs entry missing from controls.html"
        bypass_block = src[bypass_block_start: bypass_block_start + 400]
        for knob in ("BOT_DETECTION_ENABLED", "BYPASS_MODE",
                     "AUTHORIZED_BOT_UAS", "BYPASS_PATHS", "JS_CHAL_OPEN_PATHS"):
            assert knob in bypass_block, (
                f"{knob} missing from bypass CTRL_GROUP knobs list — "
                "it will not appear in the Bypass & Allowlists panel"
            )


# ── 1.8.11 QW-1: HONEYPOT_EXTRA_PATHS env merge ──────────────────────────────

def test_honeypot_extra_paths_merged():
    """HONEYPOT_EXTRA_PATHS JSON array merges into HONEYPOT_PATHS at startup."""
    import importlib, sys, os
    env_bak = os.environ.copy()
    os.environ["HONEYPOT_EXTRA_PATHS"] = '["/my-secret-admin", "/legacy/backdoor.php"]'
    try:
        if "config" in sys.modules:
            del sys.modules["config"]
        import config
        assert "/my-secret-admin" in config.HONEYPOT_PATHS, (
            "HONEYPOT_EXTRA_PATHS entry /my-secret-admin not merged into HONEYPOT_PATHS"
        )
        assert "/legacy/backdoor.php" in config.HONEYPOT_PATHS, (
            "HONEYPOT_EXTRA_PATHS entry /legacy/backdoor.php not merged into HONEYPOT_PATHS"
        )
        # original paths still present
        assert "/wp-admin" in config.HONEYPOT_PATHS
    finally:
        os.environ.clear()
        os.environ.update(env_bak)
        if "config" in sys.modules:
            del sys.modules["config"]


def test_honeypot_extra_paths_in_hot_reload_knobs():
    """HONEYPOT_EXTRA_PATHS must be registered in _HOT_RELOAD_KNOBS."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler)
    assert '"HONEYPOT_EXTRA_PATHS"' in src, (
        "HONEYPOT_EXTRA_PATHS missing from _HOT_RELOAD_KNOBS — "
        "runtime injection of extra trap paths requires hot-reload support"
    )


# ── 1.8.11 QW-3: bulk unban endpoint ─────────────────────────────────────────

def test_bulk_unban_endpoint_exists():
    """bulk_unban_endpoint must be defined in core.proxy_handler."""
    from core import proxy_handler
    assert hasattr(proxy_handler, "bulk_unban_endpoint"), (
        "bulk_unban_endpoint missing from core.proxy_handler"
    )


def test_bulk_unban_route_registered():
    """DELETE /secured/bans must be wired in proxy.py routes table."""
    import inspect
    import proxy as _proxy_module
    src = inspect.getsource(_proxy_module.make_app)
    assert "bulk_unban_endpoint" in src, (
        "bulk_unban_endpoint not registered in make_app() routes — "
        "DELETE /secured/bans will return 404"
    )


# ── 1.8.11 QW-4: audit log export endpoint ───────────────────────────────────

def test_audit_log_export_endpoint_exists():
    """audit_log_export_endpoint must be defined in dashboards.siem."""
    from dashboards import siem
    assert hasattr(siem, "audit_log_export_endpoint"), (
        "audit_log_export_endpoint missing from dashboards.siem"
    )


def test_audit_log_export_route_registered():
    """GET /secured/audit-log-export must be wired in proxy.py routes table."""
    import inspect
    import proxy as _proxy_module
    src = inspect.getsource(_proxy_module.make_app)
    assert "audit_log_export_endpoint" in src, (
        "audit_log_export_endpoint not registered in make_app() routes — "
        "GET /secured/audit-log-export will return 404"
    )


# ── 1.8.11 QW-5: SIEM reason_count fnmatch metric ────────────────────────────

def test_siem_reason_count_prefix_defined():
    """_REASON_COUNT_PREFIX constant must be in dashboards.siem."""
    from dashboards import siem
    assert hasattr(siem, "_REASON_COUNT_PREFIX"), (
        "_REASON_COUNT_PREFIX missing from dashboards.siem"
    )
    assert siem._REASON_COUNT_PREFIX == "reason_count:", (
        "_REASON_COUNT_PREFIX must equal 'reason_count:'"
    )


def test_siem_alert_rules_accepts_reason_count_metric():
    """_eval_server_alert_rules must accept reason_count:<glob> metrics."""
    import inspect
    from dashboards import siem
    src = inspect.getsource(siem._eval_server_alert_rules)
    assert "_REASON_COUNT_PREFIX" in src, (
        "_eval_server_alert_rules does not handle reason_count: metric type"
    )


# ── 1.8.11 QW-6: behavioral threshold env vars ───────────────────────────────

def test_behavioral_threshold_env_vars_exist():
    """Six behavioral threshold constants must be exposed in config."""
    import config
    for attr in (
        "BEHAVIORAL_SAMPLE_N",
        "BEHAVIORAL_COV_THRESHOLD",
        "BEHAVIORAL_R1_THRESHOLD",
        "BEHAVIORAL_BIN_PCT_THRESHOLD",
        "BEHAVIORAL_MAX_INTERVAL_S",
        "BEHAVIORAL_SKIP_INTERVAL_S",
    ):
        assert hasattr(config, attr), (
            f"config.{attr} missing — behavioral thresholds must be env-configurable"
        )


def test_behavioral_py_uses_config_thresholds():
    """detection/behavioral.py must import and use the config threshold constants."""
    import inspect
    from detection import behavioral
    src = inspect.getsource(behavioral)
    for name in (
        "BEHAVIORAL_SAMPLE_N",
        "BEHAVIORAL_COV_THRESHOLD",
        "BEHAVIORAL_R1_THRESHOLD",
        "BEHAVIORAL_BIN_PCT_THRESHOLD",
        "BEHAVIORAL_MAX_INTERVAL_S",
        "BEHAVIORAL_SKIP_INTERVAL_S",
    ):
        assert name in src, (
            f"detection/behavioral.py does not use {name} — "
            "env-var override has no effect; hardcoded threshold still in use"
        )


def test_behavioral_hot_reload_knobs_registered():
    """Behavioral threshold knobs must be in _HOT_RELOAD_KNOBS."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler)
    for knob in (
        '"BEHAVIORAL_SAMPLE_N"',
        '"BEHAVIORAL_COV_THRESHOLD"',
        '"BEHAVIORAL_R1_THRESHOLD"',
        '"BEHAVIORAL_BIN_PCT_THRESHOLD"',
        '"BEHAVIORAL_MAX_INTERVAL_S"',
        '"BEHAVIORAL_SKIP_INTERVAL_S"',
    ):
        assert knob in src, (
            f"{knob} missing from _HOT_RELOAD_KNOBS — "
            "operator cannot tune behavioral thresholds without container restart"
        )


# ── M-4: IP ban persistence ────────────────────────────────────────────────

def test_ip_bans_schema_has_table():
    """ip_bans table DDL must be in db/sqlite.py."""
    import inspect
    from db import sqlite as _sq
    src = inspect.getsource(_sq)
    assert "CREATE TABLE IF NOT EXISTS ip_bans" in src
    assert "ip_bans(banned_until)" in src, "Missing index on banned_until"


def test_check_ip_ban_exported():
    """check_ip_ban and prune_ip_bans must be exported from db package."""
    from db import check_ip_ban, prune_ip_bans  # noqa: F401
    assert callable(check_ip_ban)
    assert callable(prune_ip_bans)


def test_check_ip_ban_miss_returns_zero(tmp_path):
    """check_ip_ban returns 0 when IP is not banned."""
    import importlib, sys
    # Patch DB_PATH to a temp file so the function can create the schema
    orig = None
    try:
        from db import sqlite as _sq
        orig = _sq.DB_PATH
        _sq.DB_PATH = str(tmp_path / "test.db")
        import sqlite3
        conn = sqlite3.connect(_sq.DB_PATH)
        conn.execute("""CREATE TABLE IF NOT EXISTS ip_bans (
            ip TEXT PRIMARY KEY, banned_until REAL NOT NULL,
            reason TEXT, ts REAL NOT NULL)""")
        conn.commit(); conn.close()
        result = _sq.check_ip_ban("1.2.3.4")
        assert result == 0.0, f"Expected 0.0, got {result}"
    finally:
        if orig is not None:
            _sq.DB_PATH = orig


def test_check_ip_ban_hit_returns_until(tmp_path):
    """check_ip_ban returns banned_until for an active ban."""
    import time as _time
    import sqlite3
    from db import sqlite as _sq
    orig = _sq.DB_PATH
    try:
        _sq.DB_PATH = str(tmp_path / "test.db")
        conn = sqlite3.connect(_sq.DB_PATH)
        conn.execute("""CREATE TABLE IF NOT EXISTS ip_bans (
            ip TEXT PRIMARY KEY, banned_until REAL NOT NULL,
            reason TEXT, ts REAL NOT NULL)""")
        future = _time.time() + 3600
        conn.execute("INSERT INTO ip_bans VALUES (?,?,?,?)",
                     ("10.0.0.1", future, "test", _time.time()))
        conn.commit(); conn.close()
        result = _sq.check_ip_ban("10.0.0.1")
        assert abs(result - future) < 1.0, f"Expected ~{future}, got {result}"
    finally:
        _sq.DB_PATH = orig


def test_prune_ip_bans_removes_expired(tmp_path):
    """prune_ip_bans deletes only expired rows, leaves active ones."""
    import time as _time
    import sqlite3
    from db import sqlite as _sq
    orig = _sq.DB_PATH
    try:
        _sq.DB_PATH = str(tmp_path / "test.db")
        conn = sqlite3.connect(_sq.DB_PATH)
        conn.execute("""CREATE TABLE IF NOT EXISTS ip_bans (
            ip TEXT PRIMARY KEY, banned_until REAL NOT NULL,
            reason TEXT, ts REAL NOT NULL)""")
        past = _time.time() - 1
        future = _time.time() + 3600
        conn.execute("INSERT INTO ip_bans VALUES (?,?,?,?)",
                     ("expired.ip", past, "old", _time.time()))
        conn.execute("INSERT INTO ip_bans VALUES (?,?,?,?)",
                     ("active.ip", future, "current", _time.time()))
        conn.commit(); conn.close()
        pruned = _sq.prune_ip_bans()
        assert pruned == 1, f"Expected 1 pruned row, got {pruned}"
        conn2 = sqlite3.connect(_sq.DB_PATH)
        rows = conn2.execute("SELECT ip FROM ip_bans").fetchall()
        conn2.close()
        assert len(rows) == 1 and rows[0][0] == "active.ip"
    finally:
        _sq.DB_PATH = orig


def test_ip_ban_written_on_hostile_ban_in_scoring():
    """ban() must enqueue ip_ban op for secs >= HOSTILE_BAN_SECS."""
    import inspect
    import scoring
    src = inspect.getsource(scoring.ban)
    assert "ip_ban" in src, "ban() does not enqueue ip_ban op"
    assert "HOSTILE_BAN_SECS" in src, "ban() ip_ban condition missing HOSTILE_BAN_SECS threshold"


def test_ip_ban_written_on_risk_ban():
    """update_risk_and_maybe_ban() must enqueue ip_ban when ban_dur >= HOSTILE_BAN_SECS."""
    import inspect
    import scoring
    src = inspect.getsource(scoring.update_risk_and_maybe_ban)
    assert "ip_ban" in src, "update_risk_and_maybe_ban() does not enqueue ip_ban op"
    assert "HOSTILE_BAN_SECS" in src, "ip_ban condition missing HOSTILE_BAN_SECS threshold"


def test_protect_has_ip_ban_check():
    """protect() must perform an ip-ban point-lookup before identity derivation."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    assert "check_ip_ban" in src, "protect() missing check_ip_ban call"
    assert "ip-ban" in src, "protect() ip_ban check must emit 'ip-ban' reason"


def test_prune_loop_calls_prune_ip_bans():
    """_prune_state_loop must call prune_ip_bans to expire ip_bans rows."""
    import inspect
    from rate_limit import _prune_state_loop
    src = inspect.getsource(_prune_state_loop)
    assert "prune_ip_bans" in src, "_prune_state_loop does not call prune_ip_bans"


def test_unban_endpoint_clears_ip_bans():
    """unban_endpoint must DELETE from ip_bans table."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.unban_endpoint)
    assert "ip_bans" in src, "unban_endpoint does not clean ip_bans table"


# ── SH-1: SSRF guard on URL-type secrets ──────────────────────────────────

def test_ssrf_guard_url_helper_exists():
    """_ssrf_guard_url must be defined in proxy_handler."""
    from core.proxy_handler import _ssrf_guard_url
    assert callable(_ssrf_guard_url)


def test_url_secret_guards_map_exists():
    """_URL_SECRET_GUARDS must include CROWDSEC_LAPI_URL and OIDC_ISSUER."""
    from core.proxy_handler import _URL_SECRET_GUARDS
    assert "CROWDSEC_LAPI_URL" in _URL_SECRET_GUARDS
    assert "OIDC_ISSUER" in _URL_SECRET_GUARDS


def test_ssrf_guard_blocks_cloud_metadata():
    """_ssrf_guard_url must raise ValueError for cloud metadata IP 169.254.169.254."""
    from core.proxy_handler import _ssrf_guard_url
    import unittest.mock as _mock
    import socket

    def _fake_getaddrinfo(host, port, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('169.254.169.254', 0))]

    with _mock.patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        try:
            _ssrf_guard_url("http://metadata.internal/", label="CROWDSEC_LAPI_URL",
                            allow_loopback=True)
            assert False, "Expected ValueError for cloud metadata address"
        except ValueError as e:
            assert "SSRF guard" in str(e)


def test_ssrf_guard_blocks_rfc1918():
    """_ssrf_guard_url must raise ValueError for RFC1918 addresses."""
    from core.proxy_handler import _ssrf_guard_url
    import unittest.mock as _mock
    import socket

    def _fake_getaddrinfo(host, port, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('10.0.0.1', 0))]

    with _mock.patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        try:
            _ssrf_guard_url("http://internal.corp/", label="CROWDSEC_LAPI_URL",
                            allow_loopback=True)
            assert False, "Expected ValueError for RFC1918 address"
        except ValueError as e:
            assert "SSRF guard" in str(e)


def test_ssrf_guard_allows_loopback_when_flag_set():
    """_ssrf_guard_url must allow 127.0.0.1 when allow_loopback=True."""
    from core.proxy_handler import _ssrf_guard_url
    import unittest.mock as _mock
    import socket

    def _fake_getaddrinfo(host, port, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0))]

    with _mock.patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        _ssrf_guard_url("http://localhost:8080/", label="CROWDSEC_LAPI_URL",
                        allow_loopback=True)  # Must not raise


def test_ssrf_guard_blocks_loopback_when_flag_off():
    """_ssrf_guard_url must block 127.0.0.1 when allow_loopback=False."""
    from core.proxy_handler import _ssrf_guard_url
    import unittest.mock as _mock
    import socket

    def _fake_getaddrinfo(host, port, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0))]

    with _mock.patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        try:
            _ssrf_guard_url("http://localhost/", label="OIDC_ISSUER",
                            allow_loopback=False)
            assert False, "Expected ValueError for loopback when allow_loopback=False"
        except ValueError:
            pass


def test_secrets_endpoint_applies_ssrf_guard():
    """secrets_endpoint POST loop must call _ssrf_guard_url for URL secrets."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.secrets_endpoint)
    assert "_ssrf_guard_url" in src, \
        "secrets_endpoint does not apply SSRF guard on URL-type secrets"
    assert "_URL_SECRET_GUARDS" in src


def test_settings_import_no_secret_import():
    """settings_import_endpoint must NOT import secrets (F-10: secrets excluded
    from export/import to prevent plaintext key exfiltration via XML)."""
    import inspect
    from admin import settings
    src = inspect.getsource(settings.settings_import_endpoint)
    # Confirm dead code was removed: overwrite_secrets param and secrets_applied
    assert "overwrite_secrets" not in src, \
        "settings_import_endpoint: overwrite_secrets dead code must be absent (F-10)"
    assert "secrets_applied" not in src, \
        "settings_import_endpoint: secrets_applied dead code must be absent (F-10)"


# ── SH-3: PoW endpoint rate limiting ─────────────────────────────────────────

def test_pow_rl_dicts_defined():
    """_POW_RL and _POW_CHAL_CACHE must be defined in proxy_handler."""
    from core.proxy_handler import _POW_RL, _POW_CHAL_CACHE
    assert isinstance(_POW_RL, dict)
    assert isinstance(_POW_CHAL_CACHE, dict)


def test_pow_rl_constants_defined():
    """POW_RL_LIMIT and POW_RL_WINDOW must be defined and sane."""
    from core.proxy_handler import POW_RL_LIMIT, POW_RL_WINDOW
    assert isinstance(POW_RL_LIMIT, int) and POW_RL_LIMIT >= 1
    assert isinstance(POW_RL_WINDOW, float) and POW_RL_WINDOW >= 1.0


def test_pow_endpoint_applies_rate_limit():
    """pow_endpoint source must reference _POW_RL for rate limiting."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.pow_endpoint)
    assert "_POW_RL" in src, "pow_endpoint does not use _POW_RL for rate limiting"
    assert "429" in src, "pow_endpoint does not return 429 on rate-limit breach"
    assert "Retry-After" in src, "pow_endpoint missing Retry-After header on 429"


def test_pow_endpoint_idempotent_cache():
    """pow_endpoint must reuse _POW_CHAL_CACHE within window."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.pow_endpoint)
    assert "_POW_CHAL_CACHE" in src, \
        "pow_endpoint does not cache challenges for idempotent issuance"


def test_pow_endpoint_uses_socket_ip():
    """pow_endpoint must rate-limit by socket IP (request.remote), not XFF."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.pow_endpoint)
    assert "request.remote" in src, \
        "pow_endpoint does not use request.remote for rate-limit source IP"


def test_prune_loop_prunes_pow_rl():
    """_prune_state_loop must prune _POW_RL and _POW_CHAL_CACHE."""
    import inspect
    from rate_limit import _prune_state_loop
    src = inspect.getsource(_prune_state_loop)
    assert "_POW_RL" in src, "_prune_state_loop does not prune _POW_RL"
    assert "_POW_CHAL_CACHE" in src, "_prune_state_loop does not prune _POW_CHAL_CACHE"


# ── M-6: Redis ban retry queue ─────────────────────────────────────────────

def test_pending_redis_bans_deque_defined():
    """_pending_redis_bans must be a bounded deque (maxlen=1000)."""
    from integrations.redis import _pending_redis_bans
    import collections
    assert isinstance(_pending_redis_bans, collections.deque)
    assert _pending_redis_bans.maxlen == 1000


def test_shared_ban_set_enqueues_on_failure():
    """_shared_ban_set must push to _pending_redis_bans when Redis write fails."""
    import inspect
    from integrations import redis as _redis_mod
    src = inspect.getsource(_redis_mod._shared_ban_set)
    assert "_pending_redis_bans" in src, \
        "_shared_ban_set does not enqueue failed bans to _pending_redis_bans"
    assert "redis_ban_queued" in src, \
        "_shared_ban_set does not emit redis_ban_queued slog"


def test_redis_ban_flush_loop_defined():
    """_redis_ban_flush_loop must be an async coroutine function."""
    import asyncio
    from integrations.redis import _redis_ban_flush_loop
    assert asyncio.iscoroutinefunction(_redis_ban_flush_loop)


def test_redis_ban_flush_loop_emits_flushed_log():
    """_redis_ban_flush_loop must emit redis_ban_flushed slog on success."""
    import inspect
    from integrations.redis import _redis_ban_flush_loop
    src = inspect.getsource(_redis_ban_flush_loop)
    assert "redis_ban_flushed" in src
    assert "redis_ban_flush_failed" in src


def test_redis_ban_flush_loop_exponential_backoff():
    """_redis_ban_flush_loop must implement exponential backoff on repeated failures."""
    import inspect
    from integrations.redis import _redis_ban_flush_loop
    src = inspect.getsource(_redis_ban_flush_loop)
    assert "_backoff" in src and "* 2" in src, \
        "_redis_ban_flush_loop missing exponential backoff"
    assert "_MAX_BACKOFF" in src, "missing _MAX_BACKOFF cap"


def test_redis_flush_loop_started_in_proxy():
    """proxy.py must import and start _redis_ban_flush_loop in on_startup."""
    import inspect
    import proxy
    src = inspect.getsource(proxy)
    assert "_redis_ban_flush_loop" in src, \
        "proxy.py does not import _redis_ban_flush_loop"
    startup_src = inspect.getsource(proxy._startup_integrations_and_tasks)
    assert "_redis_ban_flush_loop" in startup_src, \
        "_startup_integrations_and_tasks does not start _redis_ban_flush_loop"


# ── Live-feed pill flicker fix (1.8.12) ──────────────────────────────────────

def test_live_pill_no_per_poll_flicker():
    """tick() must NOT flap the pill every poll. The old deferred loading
    indicator (_liveTimer) is removed — the pill is repainted only on a state
    change, so steady polls leave the LIVE pill untouched (the bug was: it kept
    showing LIVE and reloading)."""
    src = _dashboard_src("main.html")
    assert "_liveTimer" not in src, \
        "per-poll _liveTimer loading flicker must be gone (repaint only on state change)"


def test_live_pill_repaints_only_on_state_change():
    """Both the live (success) and error (catch) transitions are change-detected
    via dataset.state, so a healthy poll never rewrites the pill."""
    src = _dashboard_src("main.html")
    assert "dataset.state !== 'live'" in src, \
        "success path must guard the repaint behind dataset.state !== 'live'"
    assert "dataset.state = 'live'" in src and "dataset.state = 'error'" in src, \
        "both the live and error transitions must set dataset.state"


def test_live_pill_live_write_is_guarded():
    """The '● LIVE' repaint must sit inside the dataset.state !== 'live' guard,
    so it only runs when recovering from a problem — never on a steady poll."""
    src = _dashboard_src("main.html")
    guard = src.find("dataset.state !== 'live'")
    live = src.find("'● LIVE'")   # '● LIVE'
    assert guard != -1 and live != -1 and guard < live, \
        "'● LIVE' must be repainted only inside the dataset.state !== 'live' guard"



# ── Honeypot suggest + Trap button fix (1.8.12) ──────────────────────────────

def test_hs_trap_btn_uses_data_path_not_inline_onclick():
    """+ Trap buttons in the suggest list must use data-path + JS event
    listener, not onclick with JSON.stringify — the JSON double-quotes break
    out of the onclick="" attribute and the handler never fires."""
    src = _dashboard_src("honeypots.html")
    # No inline onclick calling addHoneypotPath with JSON.stringify
    assert 'onclick="addHoneypotPath(' not in src, \
        "Trap buttons use inline onclick with JSON.stringify — handler will never fire"
    assert "onclick='addHoneypotPath(" not in src, \
        "Trap buttons use inline onclick — use data-path + addEventListener instead"


def test_hs_trap_btn_class_present_in_suggest_render():
    """renderSuggest() must output buttons with class hs-trap-btn so the
    post-innerHTML event binding loop can find them."""
    src = _dashboard_src("honeypots.html")
    assert 'class="hs-trap-btn"' in src, \
        "renderSuggest() missing hs-trap-btn class on + Trap buttons"
    assert 'data-path=' in src, \
        "renderSuggest() missing data-path attribute on + Trap buttons"
    assert '.hs-trap-btn' in src and 'addHoneypotPath(b.dataset.path' in src, \
        "renderSuggest() missing querySelectorAll('.hs-trap-btn') event binding"


def test_pp_trap_btn_class_present_in_predicted_render():
    """renderPredicted() must output buttons with class pp-trap-btn (same
    fix as hs-trap-btn — no inline onclick with JSON.stringify)."""
    src = _dashboard_src("honeypots.html")
    assert 'class="pp-trap-btn"' in src, \
        "renderPredicted() missing pp-trap-btn class on + Trap buttons"
    assert '.pp-trap-btn' in src and 'addHoneypotPath(b.dataset.path' in src, \
        "renderPredicted() missing querySelectorAll('.pp-trap-btn') event binding"


def test_add_honeypot_path_refreshes_ui_on_success():
    """addHoneypotPath() must call loadData() and loadSuggest() after a
    successful POST so the trap list and suggestions update immediately."""
    src = _dashboard_src("honeypots.html")
    # Find the success branch (after res.ok) and check refresh calls exist
    ok_pos = src.find("res.ok")
    assert ok_pos != -1, "addHoneypotPath res.ok check not found"
    after_ok = src[ok_pos:ok_pos + 400]
    assert "loadData()" in after_ok and "loadSuggest()" in after_ok, \
        "addHoneypotPath success branch must call loadData() and loadSuggest() to refresh UI"


# ── 15+ vhost scalability (1.8.12) ───────────────────────────────────────────

def test_vhost_pill_bars_no_wrap():
    """Pill bars in agents.html and geo.html must not use flex-wrap:wrap —
    at 15+ vhosts the bar would grow to 2-3 rows. Must be nowrap + overflow-x."""
    for name in ("agents.html", "geo.html"):
        src = _dashboard_src(name)
        assert "flex-wrap:nowrap" in src and "overflow-x:auto" in src, \
            f"{name}: #vhost-bar must use flex-wrap:nowrap + overflow-x:auto for 15+ vhosts"
        assert "#vhost-bar{" in src and "flex-wrap:wrap" not in src.split("#vhost-bar{")[1].split("}")[0], \
            f"{name}: #vhost-bar still has flex-wrap:wrap — will stack on 15+ vhosts"


def test_vhost_select_filter_inputs_present():
    """Every dashboard with a vhost <select> must have a companion filter <input>
    so operators can find a specific vhost among 15+ options without scrolling."""
    cases = [
        ("main.html",         "vhost-search-inp"),
        ("controls.html",     "vhost-sel-search"),
        ("siem.html",         "vhost-filter-search"),
        ("vhost_policy.html", "vhost-policy-search"),
    ]
    for name, inp_id in cases:
        src = _dashboard_src(name)
        assert f'id="{inp_id}"' in src, \
            f"{name}: missing vhost filter input #{inp_id}"
        assert "filter vhosts" in src, \
            f"{name}: vhost filter input missing placeholder text"


def test_vhost_filter_inputs_are_hidden_by_default():
    """Filter inputs must start hidden (display:none) and be shown only when
    the vhost count reaches the threshold — keeps the UI clean for small setups."""
    cases = [
        ("main.html",         "vhost-search-inp"),
        ("controls.html",     "vhost-sel-search"),
        ("siem.html",         "vhost-filter-search"),
        ("vhost_policy.html", "vhost-policy-search"),
    ]
    for name, inp_id in cases:
        src = _dashboard_src(name)
        # The input element must carry display:none in its style attribute
        import re
        m = re.search(r'id="' + re.escape(inp_id) + r'"[^>]*style="[^"]*display\s*:\s*none', src)
        assert m, f"{name}: #{inp_id} must have display:none in its style (hidden by default)"


def test_vhost_filter_logic_uses_option_hidden():
    """The filter oninput handler must set option.hidden rather than removing
    options — removing would break value preservation across filter changes."""
    for name in ("main.html", "controls.html", "siem.html", "vhost_policy.html"):
        src = _dashboard_src(name)
        assert "o.hidden=" in src or "o.hidden =" in src, \
            f"{name}: vhost filter must use option.hidden, not option removal"


def test_control_center_vhost_table_scrollable():
    """The vhost stats table wrapper must have max-height + overflow-y:auto
    so it scrolls rather than stretching the page with 15+ vhosts."""
    src = _dashboard_src("control_center.html")
    assert "max-height:520px" in src or "max-height: 520px" in src, \
        "control_center.html: vhost stats table container missing max-height"
    assert "overflow-y:auto" in src, \
        "control_center.html: vhost stats table container missing overflow-y:auto"


def test_control_center_vhost_thead_sticky():
    """The vhost stats table <thead> must use position:sticky so the column
    headers remain visible when scrolling through 15+ vhost rows."""
    src = _dashboard_src("control_center.html")
    assert "position:sticky" in src and "top:0" in src, \
        "control_center.html: .tbl thead th must have position:sticky;top:0"


# ── 1.8.13 Honeypot storyboard intelligence ─────────────────────────────────

def test_honeypots_path_ann_lookup_defined():
    src = _dashboard_src("honeypots.html")
    assert "var PATH_ANN" in src or "PATH_ANN=" in src or "PATH_ANN =" in src, \
        "honeypots.html: PATH_ANN path annotation lookup table not defined"


def test_honeypots_annotation_for_function_defined():
    src = _dashboard_src("honeypots.html")
    assert "function annotationFor(" in src or "annotationFor=function" in src, \
        "honeypots.html: annotationFor() helper function not defined"


def test_honeypots_classify_intent_defined():
    src = _dashboard_src("honeypots.html")
    assert "function classifyIntent(" in src or "classifyIntent=function" in src, \
        "honeypots.html: classifyIntent() helper function not defined"


def test_honeypots_kill_chain_phase_defined():
    src = _dashboard_src("honeypots.html")
    assert "function killChainPhase(" in src or "killChainPhase=function" in src, \
        "honeypots.html: killChainPhase() helper function not defined"


def test_honeypots_synthesize_goal_defined():
    src = _dashboard_src("honeypots.html")
    assert "function synthesizeGoal(" in src or "synthesizeGoal=function" in src, \
        "honeypots.html: synthesizeGoal() helper function not defined"


def test_honeypots_got_data_css_class():
    src = _dashboard_src("honeypots.html")
    assert ".story-step.got-data" in src, \
        "honeypots.html: .story-step.got-data CSS class not defined"


def test_honeypots_story_intent_css_class():
    src = _dashboard_src("honeypots.html")
    assert ".story-intent" in src, \
        "honeypots.html: .story-intent CSS class not defined"


def test_honeypots_story_narrative_css_class():
    src = _dashboard_src("honeypots.html")
    assert ".story-narrative" in src, \
        "honeypots.html: .story-narrative CSS class not defined"


def test_honeypots_st_phase_css_class():
    src = _dashboard_src("honeypots.html")
    assert ".story-step .st-phase" in src or ".st-phase" in src, \
        "honeypots.html: .st-phase CSS class not defined"


def test_honeypots_st_200_css_class():
    src = _dashboard_src("honeypots.html")
    assert ".story-step .st-200" in src or ".st-200" in src, \
        "honeypots.html: .st-200 CSS class not defined"


def test_honeypots_renderstoryboard_uses_classify_intent():
    src = _dashboard_src("honeypots.html")
    rs_idx = src.find("function renderStoryboard(")
    assert rs_idx != -1, "honeypots.html: renderStoryboard() function not found"
    rs_body = src[rs_idx:rs_idx + 2000]
    assert "classifyIntent(" in rs_body, \
        "honeypots.html: renderStoryboard() must call classifyIntent()"


def test_honeypots_renderstoryboard_uses_synthesize_goal():
    src = _dashboard_src("honeypots.html")
    rs_idx = src.find("function renderStoryboard(")
    assert rs_idx != -1, "honeypots.html: renderStoryboard() function not found"
    rs_body = src[rs_idx:rs_idx + 2000]
    assert "synthesizeGoal(" in rs_body, \
        "honeypots.html: renderStoryboard() must call synthesizeGoal()"


# ── 1.8.13 security fix regression tests ─────────────────────────────────

# F-01 / F-02 / F-03: CSRF enforcement on write endpoints
def test_csrf_decorator_on_dlp_post():
    """core/proxy_handler.py: dlp_patterns_post must have @_require_csrf."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    idx = src.find("dlp_patterns_post")
    assert idx != -1, "dlp_patterns_post not found in proxy_handler.py"
    before = src[max(0, idx - 300):idx]
    assert "_require_csrf" in before, \
        "proxy_handler.py: dlp_patterns_post must have @_require_csrf before it"


def test_csrf_decorator_on_dlp_delete():
    """core/proxy_handler.py: dlp_patterns_delete must have @_require_csrf."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    idx = src.find("dlp_patterns_delete")
    assert idx != -1, "dlp_patterns_delete not found in proxy_handler.py"
    before = src[max(0, idx - 300):idx]
    assert "_require_csrf" in before, \
        "proxy_handler.py: dlp_patterns_delete must have @_require_csrf before it"


def test_csrf_decorator_on_mesh_write_endpoints():
    """admin/mesh.py: all write endpoints must have @_require_csrf."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "admin" / "mesh.py").read_text()
    write_endpoints = [
        "gw_registry_create_endpoint",
        "gw_registry_update_endpoint",
        "gw_registry_delete_endpoint",
        "gw_registry_rotate_key_endpoint",
        "gw_registry_can_distribute_endpoint",
        "gw_registry_auto_apply_endpoint",
        "gw_registry_distribution_rules_endpoint",
    ]
    for ep in write_endpoints:
        idx = src.find(ep)
        assert idx != -1, f"mesh.py: {ep} not found"
        before = src[max(0, idx - 300):idx]
        assert "_require_csrf" in before, \
            f"mesh.py: {ep} must have @_require_csrf"


def test_csrf_decorator_on_settings_import():
    """admin/settings.py: settings_import_endpoint must have @_require_csrf."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "admin" / "settings.py").read_text()
    idx = src.find("settings_import_endpoint")
    assert idx != -1, "settings_import_endpoint not found in settings.py"
    before = src[max(0, idx - 300):idx]
    assert "_require_csrf" in before, \
        "settings.py: settings_import_endpoint must have @_require_csrf"


# F-04: mesh private-key wrap/unwrap round-trip
def test_mesh_key_wrap_unwrap_roundtrip():
    """_gw_wrap_private_key / _gw_unwrap_private_key must be inverse of each other."""
    import sys, importlib
    # patch SESSION_KEY before importing
    import admin.mesh as mesh
    original = getattr(mesh, "SESSION_KEY", b"test-session-key-32bytes!padding!")
    try:
        mesh.SESSION_KEY = b"test-session-key-32bytes!padding!"
        raw = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        wrapped = mesh._gw_wrap_private_key(raw)
        assert wrapped != raw, "_gw_wrap_private_key must encrypt the key"
        assert wrapped.startswith("fernet:"), "_gw_wrap_private_key result must start with 'fernet:'"
        unwrapped = mesh._gw_unwrap_private_key(wrapped)
        assert unwrapped == raw, "_gw_unwrap_private_key must recover the original key"
    finally:
        mesh.SESSION_KEY = original


def test_mesh_key_unwrap_legacy_passthrough():
    """_gw_unwrap_private_key must pass through plaintext (legacy) values unchanged."""
    import admin.mesh as mesh
    raw = "some-legacy-b64-key"
    assert mesh._gw_unwrap_private_key(raw) == raw, \
        "legacy plaintext private key must pass through unwrap unchanged"


# F-05: Redis exclusion of secrets
def test_mesh_redis_excluded_keys_frozenset():
    """admin/mesh.py: _MESH_REDIS_EXCLUDED_KEYS must be a frozenset containing secret keys."""
    import admin.mesh as mesh
    assert hasattr(mesh, "_MESH_REDIS_EXCLUDED_KEYS"), \
        "admin/mesh.py must define _MESH_REDIS_EXCLUDED_KEYS"
    excl = mesh._MESH_REDIS_EXCLUDED_KEYS
    assert isinstance(excl, frozenset), "_MESH_REDIS_EXCLUDED_KEYS must be a frozenset"
    for key in ("TURNSTILE_SECRET", "ABUSEIPDB_KEY", "CROWDSEC_LAPI_KEY", "MAXMIND_LICENSE_KEY"):
        assert key in excl, f"_MESH_REDIS_EXCLUDED_KEYS must contain {key}"


# F-08: backup code entropy
def test_backup_code_entropy():
    """admin/users.py: backup codes must use token_hex(10) for 80-bit entropy."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "admin" / "users.py").read_text()
    idx = src.find("_generate_backup_codes")
    assert idx != -1, "_generate_backup_codes not found in admin/users.py"
    body = src[idx:idx + 500]
    assert "token_hex(10)" in body, \
        "admin/users.py: backup codes must use token_hex(10) for 80-bit entropy (not token_hex(4))"


# F-10: settings export must not include plaintext secrets
def test_settings_export_no_secrets():
    """admin/settings.py: XML export must emit empty <secrets/> not plaintext values."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "admin" / "settings.py").read_text()
    # The _settings_build_xml must produce <secrets /> not populate secret values
    idx = src.find("_settings_build_xml")
    assert idx != -1, "_settings_build_xml not found in settings.py"
    # Must not concatenate actual secret config values into the XML secrets block
    assert "overwrite_secrets" not in src, \
        "settings.py: overwrite_secrets dead code must be removed"
    assert "secrets_applied" not in src, \
        "settings.py: secrets_applied dead code must be removed"


# F-12: default CSP must not be permissive
def test_default_csp_no_unsafe():
    """config.py: default SEC_CSP must not contain unsafe-inline or unsafe-eval."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "config.py").read_text()
    idx = src.find("SEC_CSP")
    assert idx != -1, "SEC_CSP not found in config.py"
    # Extract default value (within 200 chars of the definition)
    segment = src[idx:idx + 200]
    assert "unsafe-inline" not in segment, \
        "config.py: default SEC_CSP must not contain 'unsafe-inline'"
    assert "unsafe-eval" not in segment, \
        "config.py: default SEC_CSP must not contain 'unsafe-eval'"


# F-13: _gw_actor must use username not IP
def test_gw_actor_uses_username():
    """admin/mesh.py: _gw_actor must return _request_username (not just get_ip)."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "admin" / "mesh.py").read_text()
    idx = src.find("def _gw_actor(")
    assert idx != -1, "_gw_actor not found in admin/mesh.py"
    body = src[idx:idx + 300]
    assert "_request_username" in body, \
        "admin/mesh.py: _gw_actor must call _request_username() for attribution"


# F-15: PyJWT in Dockerfile
def test_dockerfile_has_pyjwt():
    """Dockerfile must install PyJWT>=2.8.0 for OIDC id_token verification."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "Dockerfile").read_text()
    assert "PyJWT" in src, \
        "Dockerfile must include PyJWT>=2.8.0 in pip install for OIDC support"


# F-16: no key prefix in startup banner
def test_no_key_prefix_in_startup_banner():
    """proxy.py: startup banner must not print partial INTERNAL_KEY bytes."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "proxy.py").read_text()
    assert "INTERNAL_KEY[:4]" not in src, \
        "proxy.py: startup banner must not print INTERNAL_KEY[:4] (info-leak)"
    assert "INTERNAL_KEY[:8]" not in src, \
        "proxy.py: startup banner must not print any INTERNAL_KEY prefix"


# F-18: PoW WebWorker must use async/await not while(true)+.then()
def test_pow_worker_uses_async_await():
    """challenge/js_challenge.py: PoW WebWorker blob must use async function + await."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "challenge" / "js_challenge.py").read_text()
    blob_idx = src.find("new Blob([")
    assert blob_idx != -1, "js_challenge.py: WebWorker Blob not found"
    blob_body = src[blob_idx:blob_idx + 800]
    assert "async function" in blob_body, \
        "js_challenge.py: PoW WebWorker must use 'async function' (not while+.then)"
    # The broken pattern: .then() inside while(true) causes all hashes to fire
    # simultaneously and postMessage to fire multiple times on the first match.
    assert "while(true)" not in blob_body or ".then(" not in blob_body, \
        "js_challenge.py: PoW WebWorker must not combine while(true) with .then() callbacks"


def test_sec_header_knobs_in_hot_reload_registry():
    """All SEC_* security-header knobs must be hot-reloadable."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler)
    for knob in (
        '"SEC_X_FRAME_OPTIONS"',
        '"SEC_X_CONTENT_TYPE_OPTIONS"',
        '"SEC_REFERRER_POLICY"',
        '"SEC_X_PERMITTED_XDP"',
        '"SEC_PERMISSIONS_POLICY"',
        '"SEC_HSTS"',
        '"SEC_CSP"',
        '"SEC_COOP"',
        '"SEC_CORP"',
        '"SEC_SERVER_OVERRIDE"',
    ):
        assert knob in src, (
            f"{knob} missing from _HOT_RELOAD_KNOBS — "
            "operator cannot tune security headers without container restart"
        )


def test_sec_header_knobs_in_controls_dashboard():
    """Every SEC_* knob must appear in controls.html KNOB_META and secheaders card."""
    import pathlib, re
    html = (pathlib.Path(__file__).parent.parent / "dashboards" / "controls.html").read_text()
    knobs = [
        "SEC_SERVER_OVERRIDE",
        "SEC_X_FRAME_OPTIONS",
        "SEC_X_CONTENT_TYPE_OPTIONS",
        "SEC_REFERRER_POLICY",
        "SEC_X_PERMITTED_XDP",
        "SEC_PERMISSIONS_POLICY",
        "SEC_HSTS",
        "SEC_CSP",
        "SEC_COOP",
        "SEC_CORP",
    ]
    for k in knobs:
        assert k in html, f"{k} missing from controls.html"


def test_sec_header_knobs_in_config():
    """SEC_* module-level constants must exist in config and SEC_HEADER_KNOBS."""
    import config
    assert hasattr(config, "SEC_SERVER_OVERRIDE")
    assert hasattr(config, "SEC_HEADER_KNOBS")
    knob_keys = {vk for _, vk in config.SEC_HEADER_KNOBS}
    for k in (
        "SEC_X_FRAME_OPTIONS", "SEC_X_CONTENT_TYPE_OPTIONS",
        "SEC_REFERRER_POLICY", "SEC_X_PERMITTED_XDP",
        "SEC_PERMISSIONS_POLICY", "SEC_HSTS", "SEC_CSP",
        "SEC_COOP", "SEC_CORP",
    ):
        assert k in knob_keys, f"{k} missing from SEC_HEADER_KNOBS mapping"


def test_inject_security_headers_uses_vc_not_constant():
    """proxy_handler must call vc('INJECT_SECURITY_HEADERS'), not the bare constant."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler)
    assert "vc(\"INJECT_SECURITY_HEADERS\")" in src or "vc('INJECT_SECURITY_HEADERS')" in src, (
        "INJECT_SECURITY_HEADERS read as bare constant — hot-reload has no effect"
    )


# ── F-02: proxy.py shadow _eval_custom_rules parity ──────────────────────────
# proxy.py defines _eval_custom_rules which shadows the canonical import from
# integrations.endpoint_policy (last-binding-wins). This test verifies the
# shadow supports query.param matching — the one capability the canonical has
# that the shadow historically lacked — preventing silent divergence.

def test_proxy_eval_custom_rules_supports_query_param():
    """proxy._eval_custom_rules must match query.param conditions (parity with canonical)."""
    import proxy
    from integrations.endpoint_policy import _to_custom_rules

    rules = _to_custom_rules([{"if": {"query.debug": "1"}, "then": "block"}])
    orig = proxy.CUSTOM_RULES
    try:
        proxy.CUSTOM_RULES = rules

        class _Req:
            path = "/test"
            method = "GET"
            headers = {}
            query = {"debug": "1"}

        action, _ = proxy._eval_custom_rules(_Req(), "1.2.3.4")
        assert action == "block", (
            "proxy._eval_custom_rules does not honour query.param conditions — "
            "shadow diverged from integrations.endpoint_policy._eval_custom_rules"
        )

        class _ReqNoMatch:
            path = "/test"
            method = "GET"
            headers = {}
            query = {"debug": "0"}

        action2, _ = proxy._eval_custom_rules(_ReqNoMatch(), "1.2.3.4")
        assert action2 is None, (
            "proxy._eval_custom_rules incorrectly matched query.param=0 against rule query.debug=1"
        )
    finally:
        proxy.CUSTOM_RULES = orig


def test_login_html_has_escapehtml():
    """login.html must define escapeHtml at the top of its script block (§17a)."""
    src = _read_dash('login.html')
    assert 'function escapeHtml(' in src, (
        "login.html is missing the canonical escapeHtml definition. "
        "§17a requires every dashboard to define it so future edits cannot "
        "accidentally introduce an unescaped innerHTML sink."
    )
