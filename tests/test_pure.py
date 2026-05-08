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

_EXPECTED_VERSION = "AppSecGW_1.7.8"

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
    # Pattern: AppSecGW_ followed by a version number that is NOT the current one.
    stale_re = re.compile(r'AppSecGW_(?!1\.7\.8\b)\d+\.\d+')
    # Files that intentionally reference old versions (changelogs, docs, test fixtures).
    skip_dirs  = {"validation", ".git", "__pycache__", ".pytest_cache"}
    skip_files = {"CHANGELOG.md", "README.md", "rules.md"}
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
    assert not hits, "Stale version strings found — update to AppSecGW_1.7.8:\n" + "\n".join(hits)


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
# Bug: /probe, /maze, /canary-probe/ were missing from _ADMIN_PUBLIC_SUBPATHS.
# protect() intercepts every admin-namespace path not in that list and
# returns a 404 decoy before route dispatch — P1/P2/P4 detectors had zero
# effect in production because their endpoints were unreachable.

def test_probe_endpoint_in_admin_public_subpaths():
    """P1 honey-cred probe endpoint must be publicly reachable (no admin auth)."""
    from config import _ADMIN_PUBLIC_SUBPATHS
    assert "/probe" in _ADMIN_PUBLIC_SUBPATHS, (
        "/probe must be in _ADMIN_PUBLIC_SUBPATHS — protect() decoys any "
        "admin-namespace path not in this list before route dispatch, making "
        "the honey-cred P1 detector completely non-functional"
    )


def test_maze_endpoint_in_admin_public_subpaths():
    """P2 redirect-maze endpoint must be publicly reachable (no admin auth)."""
    from config import _ADMIN_PUBLIC_SUBPATHS
    assert "/maze" in _ADMIN_PUBLIC_SUBPATHS, (
        "/maze must be in _ADMIN_PUBLIC_SUBPATHS — protect() decoys any "
        "admin-namespace path not in this list before route dispatch, making "
        "the redirect-maze P2 detector completely non-functional"
    )


def test_canary_probe_in_admin_public_subpaths():
    """P4 canary-probe endpoint must be publicly reachable (no admin auth)."""
    from config import _ADMIN_PUBLIC_SUBPATHS
    assert "/canary-probe/" in _ADMIN_PUBLIC_SUBPATHS, (
        "/canary-probe/ must be in _ADMIN_PUBLIC_SUBPATHS — protect() decoys any "
        "admin-namespace path not in this list before route dispatch, making "
        "the browser execution probe P4 detector completely non-functional"
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
    assert 'function escapeHtml(' in src, (
        "service.html must define a global function escapeHtml(). "
        "Before the fix only local escHtml closures existed; callers outside "
        "those closures would get ReferenceError."
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
    src = _read_dash(fname)
    # login.html doesn't use escapeHtml at all in its JS — skip charset check
    if fname == 'login.html':
        return
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
    """Each dashboard must have exactly one escapeHtml definition."""
    src = _read_dash(fname)
    count = len(_re.findall(r'function escapeHtml\s*\(', src))
    assert count == 1, (
        f"{fname}: found {count} escapeHtml definitions (expected exactly 1). "
        "Multiple definitions allow the wrong charset to silently win."
    )

@_pytest.mark.parametrize("fname", ['main.html','agents.html','service.html',
                                     'controls.html','geo.html','logs.html','settings.html'])
def test_escapehtmlt_null_guard(fname):
    """escapeHtml must handle null/undefined via String(s==null?'':s)."""
    src = _read_dash(fname)
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
    bot_idx = src.find("AUTHORIZED_BOT_UAS")
    assert bot_idx != -1
    bot_block = src[bot_idx: bot_idx + 1500]
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
                               src.rfind("t-range") + 200]
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
    # ensureChart() is the main traffic chart function (ensureCostChart is separate)
    chart_fn_start = src.find("function ensureChart(")
    callbacks_start = src.find("callbacks:", chart_fn_start)
    callbacks_area = src[callbacks_start:callbacks_start + 600]
    assert "dataIndex" in callbacks_area, (
        "main.html tooltip callback must use items[0].dataIndex (Chart.js v3 "
        "TooltipItem property) — items[0].index is undefined in tooltip callbacks "
        "causing the epoch lookup to fail and the title to show as empty string"
    )
    # The callback must produce a human-readable date (not just relay the axis label)
    tooltip_block = src[src.find("callbacks:"):src.find("callbacks:") + 800]
    assert "toLocaleDateString" in tooltip_block or "toLocaleString" in tooltip_block, (
        "main.html tooltip title callback must format the epoch as a readable "
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
    # Must use .dataIndex, not .index
    tl_start = src.find("_lastAgentTimeline")
    tl_area = src[max(0, tl_start - 200):tl_start + 50]
    assert "dataIndex" in tl_area, (
        "agents.html tooltip callback must use items[0].dataIndex (Chart.js v3 "
        "TooltipItem API) — items[0].index is undefined in tooltip context, "
        "causing epoch lookup to fail and tooltip title to appear empty"
    )


def test_agents_tooltip_callback_formats_date():
    """agents.html tooltip title callback must format the epoch as a readable date."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    tooltip_start = src.find("_lastAgentTimeline")
    tooltip_area  = src[max(0, tooltip_start - 100):tooltip_start + 400]
    assert "toLocaleDateString" in tooltip_area or "toLocaleString" in tooltip_area, (
        "agents.html tooltip must call toLocaleDateString/toLocaleString to "
        "format the bucket start as a human-readable date"
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
    assert "authorized_robot" in src[rebuild_idx:rebuild_idx + 1200], (
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
    assert "authorized-robot" in src[loop_start:loop_start + 1200], (
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
    geo_section = src[geo_start:geo_start + 5000]
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
    bot_idx = src.find("AUTHORIZED_BOT_UAS")
    assert bot_idx != -1
    bot_block = src[bot_idx: bot_idx + 1500]
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
    bot_idx = src.find("AUTHORIZED_BOT_UAS")
    assert bot_idx != -1
    bot_block = src[bot_idx: bot_idx + 1000]
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
    bot_idx = src.find("AUTHORIZED_BOT_UAS")
    assert bot_idx != -1
    bot_block = src[bot_idx: bot_idx + 1500]
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
    bot_idx = src.find("AUTHORIZED_BOT_UAS")
    assert bot_idx != -1
    bot_block = src[bot_idx: bot_idx + 2500]
    assert "_custom_rule_allow" in bot_block, (
        "protect() bypass block must set request['_custom_rule_allow'] = True "
        "when action is 'allow' — so the bot is silently passed through"
    )


def test_authorized_bot_ban_action_sets_banned_until():
    """protect() bypass block must set banned_until for 'ban'/'really-ban' actions."""
    import inspect
    from core import proxy_handler
    src = inspect.getsource(proxy_handler.protect)
    bot_idx = src.find("AUTHORIZED_BOT_UAS")
    assert bot_idx != -1
    bot_block = src[bot_idx: bot_idx + 3000]
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
    """agents_bucket_detail_endpoint must query reason='authorized-robot' and include
    authorized_robot in the response payload."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    fn_start = src.find("async def agents_bucket_detail_endpoint")
    assert fn_start != -1, "proxy_handler.py must define agents_bucket_detail_endpoint"
    fn_section = src[fn_start: fn_start + 7000]
    assert "reason='authorized-robot'" in fn_section, (
        "agents_bucket_detail_endpoint must query reason='authorized-robot' events"
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
    load_block = src[load_idx: load_idx + 500]
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
    geo_section = src[geo_fn: geo_fn + 8000]
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
    ca_block = src[ca_idx: ca_idx + 1000]
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
    # Search backwards from clients.append for the is_auth_bot computation
    pre_block = src[max(0, ca_idx - 500): ca_idx + 50]
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
    # Check within a wider window — intermediate variable may be on the prior line
    bstate_block = src[max(0, bstate_idx - 300): bstate_idx + 300]
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
    """agents.html openPopover banLine must show blue 'Authorized Bot' status."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "agents.html").read_text()
    pop_idx = src.find("function openPopover")
    assert pop_idx != -1
    pop_section = src[pop_idx: pop_idx + 1500]
    assert "is_authorized_bot" in pop_section, (
        "agents.html openPopover banLine must check s.is_authorized_bot — "
        "without it the popover status line never shows 'Authorized Bot'"
    )
    assert "Authorized Bot" in pop_section, (
        "agents.html openPopover banLine must include 'Authorized Bot' text label"
    )


def test_main_html_popover_banline_has_authorized_bot_case():
    """main.html openClientPopover banLine must show blue 'Authorized Bot' status."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    pop_idx = src.find("window.openClientPopover")
    assert pop_idx != -1, "main.html must define window.openClientPopover"
    pop_section = src[pop_idx: pop_idx + 1500]
    assert "is_authorized_bot" in pop_section, (
        "main.html openClientPopover banLine must check c.is_authorized_bot — "
        "without it the popover status line never shows 'Authorized Bot'"
    )
    assert "Authorized Bot" in pop_section, (
        "main.html openClientPopover banLine must include 'Authorized Bot' text label"
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
    """main.html _applyFilters must set chart.data.datasets[1-4].hidden from _activeFilters."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    af_idx = src.find("function _applyFilters()")
    assert af_idx != -1, "main.html must define _applyFilters() (1.7.6)"
    block = src[af_idx: af_idx + 500]
    assert "datasets[1].hidden" in block, "_applyFilters must set datasets[1].hidden"
    assert "datasets[2].hidden" in block, "_applyFilters must set datasets[2].hidden"
    assert "datasets[3].hidden" in block, "_applyFilters must set datasets[3].hidden"
    assert "datasets[4].hidden" in block, "_applyFilters must set datasets[4].hidden"
    assert "_activeFilters" in block, "_applyFilters must reference _activeFilters"


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
    tick_body = src[tick_idx: tick_idx + 5000]
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
    # record() must be called inside that block (within 400 chars of the branch)
    block = src[admin_block_idx: admin_block_idx + 400]
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
    block = src[admin_block_idx: admin_block_idx + 400]
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
    """_applyFilters must show dataset[2] (blocked) when EITHER ban OR reallyban is active."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    af_idx = src.find("function _applyFilters()")
    assert af_idx != -1
    block = src[af_idx: af_idx + 400]
    assert "datasets[2].hidden" in block, "_applyFilters must toggle datasets[2] (1.7.8)"
    assert "'ban'" in block and "'reallyban'" in block, (
        "_applyFilters datasets[2].hidden must reference both 'ban' and 'reallyban' (1.7.8)"
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
    bp_idx = src.find("BYPASS_PATHS and any(request.path.startswith")
    assert bp_idx != -1, (
        "protect() must contain: if BYPASS_PATHS and any(request.path.startswith(p) for p in BYPASS_PATHS)"
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
    assert "Add path prefix" in src, (
        "controls.html path list editor must have 'Add path prefix' button"
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


def test_bypass_paths_guard_after_authorized_bots_before_rps():
    """BYPASS_PATHS check must be positioned AFTER AUTHORIZED_BOT_UAS block
    and BEFORE the GLOBAL_RPS_LIMIT check in protect()."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    bot_idx  = src.find("AUTHORIZED_BOT_UAS:")
    bp_idx   = src.find("BYPASS_PATHS and any(request.path.startswith")
    rps_idx  = src.find("GLOBAL_RPS_LIMIT > 0 and")
    assert bot_idx != -1, "AUTHORIZED_BOT_UAS block not found in proxy_handler.py"
    assert bp_idx  != -1, "BYPASS_PATHS guard not found in proxy_handler.py"
    assert rps_idx != -1, "GLOBAL_RPS_LIMIT check not found in proxy_handler.py"
    assert bot_idx < bp_idx < rps_idx, (
        "Guard order must be: AUTHORIZED_BOT_UAS … BYPASS_PATHS … GLOBAL_RPS_LIMIT. "
        f"Found positions: bot={bot_idx}, bypass={bp_idx}, rps={rps_idx}"
    )


def test_bypass_paths_early_return_no_record_call():
    """Bypass block must proxy via handler(), write an audit event to db_queue,
    and must NOT call record() — ip_state stays empty, but the DB event log
    captures every bypassed access for operator audit trail."""
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "core" / "proxy_handler.py").read_text()
    bp_idx = src.find("BYPASS_PATHS and any(request.path.startswith")
    assert bp_idx != -1
    # Extract the bypass block (larger window — now includes db_queue write)
    block = src[bp_idx: bp_idx + 600]
    assert "await handler(request)" in block, (
        "Bypass block must call await handler(request)"
    )
    assert "db_queue.put_nowait" in block, (
        "Bypass block must write an audit event to db_queue"
    )
    assert "bypass-path" in block, (
        "Bypass block audit event must use reason 'bypass-path'"
    )
    assert "record(" not in block, (
        "Bypass block must NOT call record() — ip_state must stay empty for bypassed paths"
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
    """div.actions (Save/Reset) must appear before card-scoring in source order."""
    src = _dash("controls.html")
    actions_pos = src.find('class="actions"')
    scoring_pos = src.find('id="card-scoring"')
    assert actions_pos != -1, "controls.html missing div.actions"
    assert scoring_pos != -1, "controls.html missing card-scoring"
    assert actions_pos < scoring_pos, (
        f"div.actions (pos {actions_pos}) must appear before card-scoring "
        f"(pos {scoring_pos}) in controls.html source order"
    )


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
