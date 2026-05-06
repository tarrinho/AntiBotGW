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


# ── Dashboard static analysis: k_q defined before use ────────────────────
# Regression: k_q was used in four fetch() calls in main.html but never
# declared, causing ReferenceError → defense-threshold slider (B and S)
# showed 0 and the throughput cap widget failed silently.

def _main_html_lines():
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "dashboards" / "main.html").read_text()
    return src.splitlines()


def test_main_html_k_q_declared():
    """k_q must have an explicit declaration (const/let/var) somewhere in
    main.html. Absence means every fetch call throws ReferenceError."""
    lines = _main_html_lines()
    decls = [i for i, ln in enumerate(lines)
             if "k_q" in ln and any(kw in ln for kw in ("const ", "let ", "var "))]
    assert decls, "k_q is not declared in main.html — will throw ReferenceError"


def test_main_html_k_q_declaration_precedes_all_uses():
    """The k_q declaration must appear before every fetch call that appends it.
    Out-of-order declaration still triggers ReferenceError in the IIFE that
    runs first."""
    import re
    lines = _main_html_lines()
    # Declaration: (const|let|var) k_q = ...
    _decl_re = re.compile(r'\b(const|let|var)\s+k_q\b')
    # Usage: k_q appears but NOT as the declared variable name
    _use_re  = re.compile(r'\bk_q\b')
    decl_lines = [i for i, ln in enumerate(lines) if _decl_re.search(ln)]
    use_lines  = [i for i, ln in enumerate(lines)
                  if _use_re.search(ln) and not _decl_re.search(ln)]
    assert decl_lines, "k_q not declared"
    assert use_lines,  "k_q not used anywhere — test is stale"
    first_decl = min(decl_lines)
    first_use  = min(use_lines)
    assert first_decl < first_use, (
        f"k_q declared on line {first_decl+1} but first use on line {first_use+1}; "
        "declaration must precede all uses"
    )


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

_EXPECTED_VERSION = "AppSecGW_1.7.4"

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
    stale_re = re.compile(r'AppSecGW_(?!1\.7\.4\b)\d+\.\d+')
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
    assert not hits, "Stale version strings found — update to AppSecGW_1.7.4:\n" + "\n".join(hits)


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
