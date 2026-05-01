"""
Tests for the v1.4.2 controls:
  • TLS fingerprint deny-list (JA3 / JA4)
  • STRICT_ORIGIN enforcement on state-changing methods
  • REQUIRED_HEADERS presence check
"""
import pytest


class _Req:
    """Minimal request stand-in for the helper-function unit tests."""
    def __init__(self, method="GET", path="/", headers=None, remote="172.20.0.5"):
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.host = headers.get("Host", "") if headers else ""
        self.remote = remote


# ── TLS fingerprint deny-list ────────────────────────────────────────────

def test_tls_fingerprint_off_by_default(proxy_module):
    proxy_module.JA4_DENY_LIST = set()
    assert proxy_module._tls_fingerprint_blocked(
        _Req(headers={"CF-JA4": "any-value"})) is False


def test_tls_fingerprint_blocks_listed(proxy_module):
    proxy_module.JA4_DENY_LIST = {"t13d_curl_8x", "t13d_python_requests"}
    proxy_module.JA4_HEADER = "CF-JA4"
    try:
        assert proxy_module._tls_fingerprint_blocked(
            _Req(headers={"CF-JA4": "t13d_curl_8x"})) is True
        assert proxy_module._tls_fingerprint_blocked(
            _Req(headers={"CF-JA4": "t13d_chrome_120"})) is False
    finally:
        proxy_module.JA4_DENY_LIST = set()


def test_tls_fingerprint_missing_header_passes(proxy_module):
    proxy_module.JA4_DENY_LIST = {"t13d_curl_8x"}
    try:
        assert proxy_module._tls_fingerprint_blocked(_Req(headers={})) is False
    finally:
        proxy_module.JA4_DENY_LIST = set()


# ── v1.4.3 TLS-1 fix: trusted-peer gating on JA4 header ─────────────────

def test_tls_fp_blocked_when_unset_trusted_peers(proxy_module):
    """Back-compat: empty JA4_TRUSTED_NETS = trust all peers."""
    import ipaddress
    proxy_module.JA4_DENY_LIST = {"bot_fp"}
    proxy_module.JA4_TRUSTED_NETS = []
    try:
        assert proxy_module._tls_fingerprint_blocked(
            _Req(headers={"CF-JA4": "bot_fp"}, remote="8.8.8.8")) is True
    finally:
        proxy_module.JA4_DENY_LIST = set()


def test_tls_fp_ignored_from_untrusted_peer(proxy_module):
    """TLS-1 fix: when JA4_TRUSTED_PEERS is set, headers from outside the
    range are ignored (would-be evader can't bypass by forging the header)."""
    import ipaddress
    proxy_module.JA4_DENY_LIST = {"bot_fp"}
    proxy_module.JA4_TRUSTED_NETS = [ipaddress.ip_network("172.20.0.0/16")]
    try:
        # Inside the trusted range — header is honoured (block fires)
        assert proxy_module._tls_fingerprint_blocked(
            _Req(headers={"CF-JA4": "bot_fp"}, remote="172.20.5.1")) is True
        # Outside the trusted range — header is ignored (no block)
        assert proxy_module._tls_fingerprint_blocked(
            _Req(headers={"CF-JA4": "bot_fp"}, remote="8.8.8.8")) is False
    finally:
        proxy_module.JA4_DENY_LIST = set()
        proxy_module.JA4_TRUSTED_NETS = []


def test_tls_fp_invalid_remote_ip_treated_as_untrusted(proxy_module):
    import ipaddress
    proxy_module.JA4_DENY_LIST = {"bot_fp"}
    proxy_module.JA4_TRUSTED_NETS = [ipaddress.ip_network("172.20.0.0/16")]
    try:
        assert proxy_module._tls_fingerprint_blocked(
            _Req(headers={"CF-JA4": "bot_fp"}, remote=None)) is False
        assert proxy_module._tls_fingerprint_blocked(
            _Req(headers={"CF-JA4": "bot_fp"}, remote="not-an-ip")) is False
    finally:
        proxy_module.JA4_DENY_LIST = set()
        proxy_module.JA4_TRUSTED_NETS = []


# ── STRICT_ORIGIN ───────────────────────────────────────────────────────

def test_origin_check_off_by_default(proxy_module):
    proxy_module.STRICT_ORIGIN = False
    assert proxy_module._origin_check_failed(
        _Req(method="POST", headers={"Origin": "https://evil.com"})) is False


def test_origin_check_get_always_passes(proxy_module):
    proxy_module.STRICT_ORIGIN = True
    proxy_module.ALLOWED_HOSTS = {"good.example.com"}
    try:
        assert proxy_module._origin_check_failed(
            _Req(method="GET", headers={})) is False
    finally:
        proxy_module.STRICT_ORIGIN = False
        proxy_module.ALLOWED_HOSTS = set()


def test_origin_check_post_missing_origin_fails(proxy_module):
    proxy_module.STRICT_ORIGIN = True
    proxy_module.ALLOWED_HOSTS = {"good.example.com"}
    try:
        assert proxy_module._origin_check_failed(
            _Req(method="POST", headers={})) is True
    finally:
        proxy_module.STRICT_ORIGIN = False
        proxy_module.ALLOWED_HOSTS = set()


def test_origin_check_matching_origin_passes(proxy_module):
    proxy_module.STRICT_ORIGIN = True
    proxy_module.ALLOWED_HOSTS = {"good.example.com"}
    try:
        assert proxy_module._origin_check_failed(_Req(
            method="POST",
            headers={"Origin": "https://good.example.com"})) is False
    finally:
        proxy_module.STRICT_ORIGIN = False
        proxy_module.ALLOWED_HOSTS = set()


def test_origin_check_mismatched_origin_fails(proxy_module):
    proxy_module.STRICT_ORIGIN = True
    proxy_module.ALLOWED_HOSTS = {"good.example.com"}
    try:
        assert proxy_module._origin_check_failed(_Req(
            method="POST",
            headers={"Origin": "https://evil.example.com"})) is True
    finally:
        proxy_module.STRICT_ORIGIN = False
        proxy_module.ALLOWED_HOSTS = set()


def test_origin_check_open_paths_bypass(proxy_module):
    proxy_module.STRICT_ORIGIN = True
    proxy_module.ALLOWED_HOSTS = {"good.example.com"}
    proxy_module.OPEN_ORIGIN_PATHS = ["/api/webhook"]
    try:
        # Webhook path: even with no Origin, must pass.
        assert proxy_module._origin_check_failed(_Req(
            method="POST", path="/api/webhook/foo", headers={})) is False
        # Other paths still enforced.
        assert proxy_module._origin_check_failed(_Req(
            method="POST", path="/api/login", headers={})) is True
    finally:
        proxy_module.STRICT_ORIGIN = False
        proxy_module.ALLOWED_HOSTS = set()
        proxy_module.OPEN_ORIGIN_PATHS = []


# ── REQUIRED_HEADERS ────────────────────────────────────────────────────

def test_required_headers_off_by_default(proxy_module):
    proxy_module.REQUIRED_HEADERS = []
    assert proxy_module._missing_required_header(_Req(headers={})) is False


def test_required_headers_passes_when_present(proxy_module):
    proxy_module.REQUIRED_HEADERS = ["X-Client-Version"]
    try:
        assert proxy_module._missing_required_header(
            _Req(headers={"X-Client-Version": "1.0"})) is False
    finally:
        proxy_module.REQUIRED_HEADERS = []


def test_required_headers_blocks_when_missing(proxy_module):
    proxy_module.REQUIRED_HEADERS = ["X-Client-Version"]
    try:
        assert proxy_module._missing_required_header(_Req(headers={})) is True
    finally:
        proxy_module.REQUIRED_HEADERS = []


def test_required_headers_skip_admin_paths(proxy_module):
    proxy_module.REQUIRED_HEADERS = ["X-Client-Version"]
    try:
        # /__* admin endpoints don't need the marker.
        assert proxy_module._missing_required_header(
            _Req(path="/antibot-appsec-gateway/live", headers={})) is False
        assert proxy_module._missing_required_header(
            _Req(path="/antibot-appsec-gateway/secured/dashboard", headers={})) is False
    finally:
        proxy_module.REQUIRED_HEADERS = []


def test_required_headers_skip_static_assets(proxy_module):
    proxy_module.REQUIRED_HEADERS = ["X-Client-Version"]
    try:
        for asset in ("/style.css", "/app.js", "/logo.png", "/font.woff2"):
            assert proxy_module._missing_required_header(
                _Req(path=asset, headers={})) is False, asset
    finally:
        proxy_module.REQUIRED_HEADERS = []


def test_required_headers_multi_all_required(proxy_module):
    proxy_module.REQUIRED_HEADERS = ["X-Client-Version", "X-API-Key"]
    try:
        # Only one present → still fails.
        assert proxy_module._missing_required_header(
            _Req(headers={"X-Client-Version": "1"})) is True
        assert proxy_module._missing_required_header(
            _Req(headers={"X-API-Key": "abc"})) is True
        # Both present → passes.
        assert proxy_module._missing_required_header(_Req(headers={
            "X-Client-Version": "1", "X-API-Key": "abc"})) is False
    finally:
        proxy_module.REQUIRED_HEADERS = []
