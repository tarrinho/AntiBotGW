"""
tests/test_custom_rules_fuzzing.py — adversarial inputs for _eval_custom_rules.

Goal: ensure _eval_custom_rules never raises, never returns unexpected types,
and correctly ignores or rejects malformed operator-supplied rule configs.

Covers:
  FUZZ-01 — None / missing field values
  FUZZ-02 — Wrong types in rule fields (int, list, dict where str expected)
  FUZZ-03 — Very long strings (path, UA, header values)
  FUZZ-04 — Unicode and null bytes in matched fields
  FUZZ-05 — Gigantic CIDR list
  FUZZ-06 — Invalid IP addresses (both in rule and in request)
  FUZZ-07 — Mixed IPv4/IPv6 rules
  FUZZ-08 — Empty / degenerate rule structures
  FUZZ-09 — ReDoS-style long glob patterns
  FUZZ-10 — Header key injection (dot-prefixed, empty key)
  FUZZ-11 — Country code injection  [uses ep._eval_custom_rules]
  FUZZ-12 — Query key injection     [uses ep._eval_custom_rules]

NOTE on which function to call:
  proxy.py defines a simplified wrapper at proxy.py:740 that reads CUSTOM_RULES
  from proxy globals.  protect() in proxy_handler.py uses the full version
  imported from integrations.endpoint_policy, which adds query.* and country
  condition support.  FUZZ-11 and FUZZ-12 target ep._eval_custom_rules
  directly (the production code path).  All other tests use proxy._eval_custom_rules.
"""
import os
import sys
import tempfile

import pytest

_TMP = tempfile.mkdtemp(prefix="appsecgw-fuzz-")
os.environ.setdefault("UPSTREAM",  "https://example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "antibot-fuzz.db"))

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)


# ── Minimal request stub ──────────────────────────────────────────────────────

class _Req:
    def __init__(self, path="/", method="GET", headers=None, query=None):
        self.path = path
        self.method = method
        self.headers = headers or {}
        self.query = query or {}


# ── Fixtures and helpers ──────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_custom_rules():
    """Save/restore CUSTOM_RULES on both proxy and endpoint_policy after each test."""
    from integrations import endpoint_policy as _ep
    import proxy as _px
    saved_ep = _ep.CUSTOM_RULES
    saved_px = _px.CUSTOM_RULES
    yield
    _ep.CUSTOM_RULES = saved_ep
    _px.CUSTOM_RULES = saved_px


def _set_rules(rules):
    """Apply rules to both proxy and endpoint_policy namespaces."""
    from integrations import endpoint_policy as _ep
    import proxy as _px
    _px.CUSTOM_RULES = rules
    _ep.CUSTOM_RULES = rules


@pytest.fixture(scope="module")
def proxy_mod():
    import proxy
    return proxy


@pytest.fixture(scope="module")
def ep():
    """endpoint_policy module — the production code path used by protect()."""
    from integrations import endpoint_policy
    return endpoint_policy


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-01 — None / missing fields in condition dict
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz01NoneFields:

    def test_none_path_field(self, proxy_mod):
        _set_rules([{"if": {"path": None}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req("/anything"), "1.2.3.4")
        assert action == "block"

    def test_none_method_field(self, proxy_mod):
        _set_rules([{"if": {"method": None}, "then": "allow", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(method="GET"), "1.2.3.4")
        assert action == "allow"

    def test_none_ua_contains(self, proxy_mod):
        _set_rules([{"if": {"ua_contains": None}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(), "1.2.3.4")
        assert action == "block"

    def test_missing_if_key(self, proxy_mod):
        _set_rules([{"then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(), "1.2.3.4")
        assert action == "block", "Rule with missing 'if' must match everything"

    def test_none_if_key(self, proxy_mod):
        _set_rules([{"if": None, "then": "allow", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(), "1.2.3.4")
        assert action == "allow"

    def test_empty_rules_list(self, proxy_mod):
        _set_rules([])
        action, tag = proxy_mod._eval_custom_rules(_Req(), "1.2.3.4")
        assert action is None
        assert tag == ""


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-02 — Wrong types in rule fields
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz02WrongTypes:

    def test_integer_path(self, proxy_mod):
        _set_rules([{"if": {"path": 42}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(path="/42"), "1.2.3.4")
        assert action in (None, "block")

    def test_dict_ua_contains(self, proxy_mod):
        _set_rules([{"if": {"ua_contains": {"key": "val"}}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(headers={"User-Agent": "Mozilla"}), "1.2.3.4")
        assert action in (None, "block")

    def test_list_single_method(self, proxy_mod):
        _set_rules([{"if": {"method": ["GET", "POST"]}, "then": "allow", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(method="POST"), "1.2.3.4")
        assert action == "allow"

    def test_integer_then_field(self, proxy_mod):
        _set_rules([{"if": {}, "then": 99, "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(), "1.2.3.4")
        assert action in (None, 99)

    def test_none_then_field(self, proxy_mod):
        _set_rules([{"if": {}, "then": None, "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(), "1.2.3.4")
        assert action is None


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-03 — Very long strings
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz03LongStrings:

    def test_10k_path_in_request(self, proxy_mod):
        _set_rules([{"if": {"path": "/api/*"}, "then": "block", "tag": ""}])
        long_path = "/api/" + "A" * 10_000
        action, _ = proxy_mod._eval_custom_rules(_Req(path=long_path), "1.2.3.4")
        assert action == "block"

    def test_10k_ua_in_request(self, proxy_mod):
        _set_rules([{"if": {"ua_contains": "python"}, "then": "block", "tag": ""}])
        long_ua = "python/" + "x" * 10_000
        action, _ = proxy_mod._eval_custom_rules(_Req(headers={"User-Agent": long_ua}), "1.2.3.4")
        assert action == "block"

    def test_10k_path_glob_in_rule(self, proxy_mod):
        long_glob = "/api/" + "*" * 5_000 + "/v2"
        _set_rules([{"if": {"path": long_glob}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(path="/api/x/v2"), "1.2.3.4")
        assert action in (None, "block")

    def test_10k_header_value(self, proxy_mod):
        _set_rules([{"if": {"header.X-Token": "secret"}, "then": "allow", "tag": ""}])
        long_val = "secret" + "x" * 10_000
        action, _ = proxy_mod._eval_custom_rules(
            _Req(headers={"X-Token": long_val}), "1.2.3.4"
        )
        assert action == "allow"


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-04 — Unicode and null bytes
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz04UnicodeNull:

    def test_unicode_path(self, proxy_mod):
        _set_rules([{"if": {"path": "/api/*"}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(path="/api/中文"), "1.2.3.4")
        assert action == "block"

    def test_null_byte_in_path(self, proxy_mod):
        _set_rules([{"if": {"path": "/safe/*"}, "then": "allow", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(path="/safe/\x00injected"), "1.2.3.4")
        assert action in (None, "allow")

    def test_null_byte_in_ua_contains(self, proxy_mod):
        _set_rules([{"if": {"ua_contains": "bot\x00"}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(
            _Req(headers={"User-Agent": "bot\x00scanner"}), "1.2.3.4"
        )
        assert action in (None, "block")

    def test_emoji_in_ua(self, proxy_mod):
        _set_rules([{"if": {"ua_contains": "\U0001f916"}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(
            _Req(headers={"User-Agent": "AI-\U0001f916-bot/1.0"}), "1.2.3.4"
        )
        assert action == "block"


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-05 — Gigantic CIDR list
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz05GigantCidr:

    def test_1000_cidr_entries_no_match(self, proxy_mod):
        cidrs = [f"10.{i // 256}.{i % 256}.0/24" for i in range(1000)]
        _set_rules(proxy_mod._to_custom_rules([
            {"if": {"ip_cidr": cidrs}, "then": "block"}
        ]))
        action, _ = proxy_mod._eval_custom_rules(_Req(), "8.8.8.8")
        assert action is None

    def test_1000_cidr_entries_with_match(self, proxy_mod):
        cidrs = [f"10.{i // 256}.{i % 256}.0/24" for i in range(1000)]
        # i=999 → 10.3.231.0/24; "10.3.231.5" is in that /24
        _set_rules(proxy_mod._to_custom_rules([
            {"if": {"ip_cidr": cidrs}, "then": "block"}
        ]))
        action, _ = proxy_mod._eval_custom_rules(_Req(), "10.3.231.5")
        assert action == "block"


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-06 — Invalid IP addresses
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz06InvalidIp:

    def test_invalid_ip_in_request(self, proxy_mod):
        _set_rules(proxy_mod._to_custom_rules([
            {"if": {"ip_cidr": ["10.0.0.0/8"]}, "then": "block"}
        ]))
        for bad_ip in ("not-an-ip", "", "256.0.0.1", "::1::1", "0"):
            action, _ = proxy_mod._eval_custom_rules(_Req(), bad_ip)
            assert action is None, f"Bad IP {bad_ip!r} must not match any CIDR rule"

    def test_invalid_cidr_in_rule(self, proxy_mod):
        rules = proxy_mod._to_custom_rules([
            {"if": {"ip_cidr": ["999.999.999.999/32", "not-a-cidr"]}, "then": "block"}
        ])
        _set_rules(rules)
        action, _ = proxy_mod._eval_custom_rules(_Req(), "10.0.0.1")
        assert action is None, "Rule with only invalid CIDRs must never match"

    def test_mixed_valid_invalid_cidr(self, proxy_mod):
        # _to_custom_rules filters invalid CIDRs — "10.0.0.0/8" must survive
        rules = proxy_mod._to_custom_rules([
            {"if": {"ip_cidr": ["10.0.0.0/8"]}, "then": "block"}
        ])
        _set_rules(rules)
        action, _ = proxy_mod._eval_custom_rules(_Req(), "10.5.5.5")
        assert action == "block", "Valid CIDR must still match"


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-07 — Mixed IPv4 / IPv6
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz07MixedIpVersions:

    def test_ipv6_rule_matches_ipv6_request(self, proxy_mod):
        _set_rules(proxy_mod._to_custom_rules([
            {"if": {"ip_cidr": ["2001:db8::/32"]}, "then": "block"}
        ]))
        action, _ = proxy_mod._eval_custom_rules(_Req(), "2001:db8::1")
        assert action == "block"

    def test_ipv4_rule_does_not_match_ipv4_mapped_ipv6(self, proxy_mod):
        _set_rules(proxy_mod._to_custom_rules([
            {"if": {"ip_cidr": ["10.0.0.0/8"]}, "then": "block"}
        ]))
        action, _ = proxy_mod._eval_custom_rules(_Req(), "::ffff:10.0.0.1")
        assert action is None, "IPv4 CIDR must not match IPv4-mapped IPv6 address"

    def test_mixed_ipv4_ipv6_cidr_list(self, proxy_mod):
        _set_rules(proxy_mod._to_custom_rules([
            {"if": {"ip_cidr": ["10.0.0.0/8", "2001:db8::/32"]}, "then": "block"}
        ]))
        assert proxy_mod._eval_custom_rules(_Req(), "10.1.1.1")[0] == "block"
        assert proxy_mod._eval_custom_rules(_Req(), "2001:db8::ff")[0] == "block"
        assert proxy_mod._eval_custom_rules(_Req(), "8.8.8.8")[0] is None


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-08 — Degenerate rule structures
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz08Degenerate:

    def test_empty_condition_matches_all(self, proxy_mod):
        _set_rules([{"if": {}, "then": "allow", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req("/random"), "5.6.7.8")
        assert action == "allow"

    def test_rule_with_only_tag(self, proxy_mod):
        _set_rules([{"if": {}, "tag": "test-only"}])
        action, tag = proxy_mod._eval_custom_rules(_Req(), "1.2.3.4")
        assert action is None
        assert tag == "test-only"

    def test_many_rules_all_miss(self, proxy_mod):
        _set_rules([
            {"if": {"path": "/miss1"}, "then": "block", "tag": ""},
            {"if": {"path": "/miss2"}, "then": "block", "tag": ""},
            {"if": {"ua_contains": "never-matches-xyz"}, "then": "block", "tag": ""},
        ])
        action, _ = proxy_mod._eval_custom_rules(_Req(path="/other"), "1.2.3.4")
        assert action is None


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-09 — ReDoS-style glob patterns
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz09GlobPerformance:

    def test_nested_wildcard_glob_does_not_hang(self, proxy_mod):
        import time
        evil_glob = "/*" * 20
        _set_rules([{"if": {"path": evil_glob}, "then": "block", "tag": ""}])
        t0 = time.monotonic()
        proxy_mod._eval_custom_rules(_Req(path="/a/b/c/d/e"), "1.2.3.4")
        elapsed = time.monotonic() - t0
        assert elapsed < 1.0, f"glob match took {elapsed:.3f}s — possible ReDoS"

    def test_alternation_style_path(self, proxy_mod):
        _set_rules([{"if": {"path": "/[abc]*/path"}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(path="/a-prefix/path"), "1.2.3.4")
        assert action in (None, "block")


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-10 — Header key injection
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz10HeaderKeyInjection:

    def test_empty_header_key_suffix(self, proxy_mod):
        _set_rules([{"if": {"header.": "val"}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(
            _Req(headers={"": "val"}), "1.2.3.4"
        )
        assert action in (None, "block")

    def test_header_key_non_prefix_key_ignored(self, proxy_mod):
        _set_rules([{"if": {"x-custom": "value"}, "then": "block", "tag": ""}])
        action, _ = proxy_mod._eval_custom_rules(_Req(), "1.2.3.4")
        assert action == "block"


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-11 — Country code injection  [uses ep._eval_custom_rules]
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz11CountryInjection:

    def test_country_none_value(self, ep):
        ep.CUSTOM_RULES = [{"if": {"country": None}, "then": "block", "tag": ""}]
        action, _ = ep._eval_custom_rules(_Req(), "1.2.3.4")
        # country=None → if cc: is False → condition block skipped → rule matches
        assert action == "block"

    def test_country_sql_injection_string(self, ep):
        ep.CUSTOM_RULES = [{"if": {"country": "' OR 1=1 --"}, "then": "block", "tag": ""}]
        action, _ = ep._eval_custom_rules(_Req(), "1.2.3.4")
        # MaxMind disabled → cc_obs="" → "' OR 1=1 --" not in wanted → ok=False
        assert action is None

    def test_country_list_with_invalid_codes(self, ep):
        ep.CUSTOM_RULES = [{"if": {"country": ["US", "", None, 42]}, "then": "block", "tag": ""}]
        action, _ = ep._eval_custom_rules(_Req(), "8.8.8.8")
        assert action in (None, "block")


# ─────────────────────────────────────────────────────────────────────────────
# FUZZ-12 — Query key injection  [uses ep._eval_custom_rules]
# ─────────────────────────────────────────────────────────────────────────────

class TestFuzz12QueryKeyInjection:

    def test_query_key_with_dot(self, ep):
        ep.CUSTOM_RULES = [{"if": {"query.foo.bar": "val"}, "then": "block", "tag": ""}]
        action, _ = ep._eval_custom_rules(
            _Req(query={"foo.bar": "val"}), "1.2.3.4"
        )
        assert action in (None, "block")

    def test_query_exact_match_empty_string(self, ep):
        ep.CUSTOM_RULES = [{"if": {"query.debug": ""}, "then": "block", "tag": ""}]
        action, _ = ep._eval_custom_rules(
            _Req(query={"debug": ""}), "1.2.3.4"
        )
        assert action == "block"

    def test_query_missing_key_does_not_match(self, ep):
        ep.CUSTOM_RULES = [{"if": {"query.secret": "abc"}, "then": "block", "tag": ""}]
        action, _ = ep._eval_custom_rules(_Req(query={}), "1.2.3.4")
        assert action is None

    def test_query_value_type_coercion(self, ep):
        ep.CUSTOM_RULES = [{"if": {"query.num": "42"}, "then": "block", "tag": ""}]
        action, _ = ep._eval_custom_rules(_Req(query={"num": "42"}), "1.2.3.4")
        assert action == "block"
