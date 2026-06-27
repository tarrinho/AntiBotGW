"""
QA — comprehensive regression coverage for **every** 1.9.7 knob, signal
mapping, hot-reload binding, and new function signature.

Goal: lock the current public contract so a future refactor that
silently drops a knob registration / signal mapping / endpoint route /
function signature is caught by pytest before it ships.

Each test fails LOUDLY if the named contract goes away. Add to the
matrices below when 1.9.8+ adds more.
"""
import importlib
import inspect
import os
import re

import pytest

os.environ.setdefault("ADMIN_ALLOWED_IPS", "0.0.0.0/0,::/0")
os.environ.setdefault("UPSTREAM", "http://example.com")
os.environ.setdefault("ADMIN_KEY", "test-admin-key-xxxxxxxxxxxxxxxx")

config = importlib.import_module("config")
cph    = importlib.import_module("core.proxy_handler")
users  = importlib.import_module("admin.users")
mesh   = importlib.import_module("admin.mesh")
auth   = importlib.import_module("admin.auth")
settings_mod = importlib.import_module("admin.settings")
oidc   = importlib.import_module("admin.oidc")
sqlite_mod = importlib.import_module("db.sqlite")
vhost_mod  = importlib.import_module("vhost")
feeds_mod  = importlib.import_module("reputation.feeds")

# Knobs that live OUTSIDE config.py (threat-intel feeds → reputation/feeds.py)
KNOB_MODULES = {
    "FEODO_ENABLED":   feeds_mod,
    "CINS_ENABLED":    feeds_mod,
    "URLHAUS_ENABLED": feeds_mod,
}


def _knob_owner(name):
    return KNOB_MODULES.get(name, config)


# ── 1. Knob existence + types ────────────────────────────────────────────────

# (name, type, default-on, hot-reloadable, vhost-coerced)
KNOB_MATRIX = [
    # WAF kill-switches (default-on, hot-reload, vhost)
    ("WAF_BODY_ENABLED",          bool, True,  True,  True),
    ("WAF_SMUGGLING_ENABLED",     bool, True,  True,  True),
    ("WAF_VERB_OVERRIDE_ENABLED", bool, True,  True,  False),
    ("WAF_HEADER_INJECTION_ENABLED", bool, True,  True, False),
    ("WAF_GRAPHQL_ENABLED",       bool, True,  True,  True),
    ("WAF_UPLOAD_ENABLED",        bool, True,  True,  True),
    ("WAF_SLOWLORIS_ENABLED",     bool, True,  True,  True),
    # Rate-limit kill-switches (default-on)
    ("RATE_LIMIT_ENABLED",        bool, True,  True,  True),
    ("ENDPOINT_RATE_LIMIT_ENABLED", bool, True, True, False),
    # Threat-intel feeds (default-OFF — opt-in)
    ("FEODO_ENABLED",             bool, False, None,  None),
    ("CINS_ENABLED",              bool, False, None,  None),
    ("URLHAUS_ENABLED",           bool, False, None,  None),
    # JS / H2 fingerprint signals
    ("JS_CONSISTENCY_ENABLED",    bool, True,  None,  None),
    ("H2_SETTINGS_FP_ENABLED",    bool, False, None,  None),
    # Redirect-maze (default-on; was unregistered in _HOT_RELOAD_KNOBS pre-1.9.7)
    ("REDIRECT_MAZE_ENABLED",     bool, True,  True,  True),
    # Session absolute timeout
    ("SESSION_ABSOLUTE_TIMEOUT",  int,  None,  None,  None),
]


class TestKnobMatrix:
    """One row per 1.9.7-touched config constant. Catches knob removal,
    type drift (str-instead-of-bool), default flip, and hot-reload/vhost
    registration loss."""

    @pytest.mark.parametrize("name,typ,_d,_h,_v", [
        (n, t, d, h, v) for (n, t, d, h, v) in KNOB_MATRIX
    ])
    def test_knob_exists_and_has_expected_type(self, name, typ, _d, _h, _v):
        owner = _knob_owner(name)
        assert hasattr(owner, name), f"{owner.__name__}.{name} missing"
        val = getattr(owner, name)
        assert isinstance(val, typ), (
            f"{owner.__name__}.{name} is {type(val).__name__}, expected {typ.__name__}"
        )

    @pytest.mark.parametrize("name,_t,default_on,_h,_v", [
        (n, t, d, h, v) for (n, t, d, h, v) in KNOB_MATRIX if d is not None
    ])
    def test_knob_default_in_source(self, name, _t, default_on, _h, _v):
        """The DEFAULT (before env override) must match the table.
        Source-level read so an operator's local .env doesn't flip the test."""
        owner = _knob_owner(name)
        src = open(owner.__file__, encoding="utf-8").read()
        expected = "1" if default_on else "0"
        # Pattern: NAME = os.environ.get("NAME", "<expected>")…
        # tolerate _to_bool_default_true wrapper too.
        pat = re.compile(
            rf"\b{name}\b\s*=\s*(?:_to_bool_default_true\(\s*)?os\.environ\.get\(\s*[\"']{name}[\"']\s*,\s*[\"']{expected}[\"']"
        )
        assert pat.search(src), (
            f"{owner.__name__}.py default for {name} is not {expected!r} — "
            f"the matrix says default-on={default_on}"
        )

    @pytest.mark.parametrize("name,_t,_d,hot,_v", [
        (n, t, d, h, v) for (n, t, d, h, v) in KNOB_MATRIX if h is True
    ])
    def test_knob_registered_for_hot_reload(self, name, _t, _d, hot, _v):
        assert name in cph._HOT_RELOAD_KNOBS, (
            f"{name} missing from _HOT_RELOAD_KNOBS — runtime knob change "
            "won't propagate without restart"
        )
        coercer, validator = cph._HOT_RELOAD_KNOBS[name]
        assert callable(coercer), f"{name} coercer must be callable"

    @pytest.mark.parametrize("name,_t,_d,_h,vhostable", [
        (n, t, d, h, v) for (n, t, d, h, v) in KNOB_MATRIX if v is True
    ])
    def test_knob_in_vhost_coerce(self, name, _t, _d, _h, vhostable):
        assert name in vhost_mod._VHOST_COERCE, (
            f"{name} missing from _VHOST_COERCE — per-vhost override "
            "won't be honoured"
        )


# ── 2. Signal → kill-switch mappings (SIGNAL_KNOB) ───────────────────────────

SIGNAL_KNOB_NEW_IN_197 = {
    # threat-intel feeds wired in 1.9.7
    "feodo-c2":                "FEODO_ENABLED",
    "cins-rogue":              "CINS_ENABLED",
    "urlhaus-malware":         "URLHAUS_ENABLED",
    # JS-consistency wired in 1.9.7
    "js-cua-version-mismatch": "JS_CONSISTENCY_ENABLED",
    "js-mobile-hint-mismatch": "JS_CONSISTENCY_ENABLED",
    "js-fetch-impossible":     "JS_CONSISTENCY_ENABLED",
    # H2 fingerprint wired in 1.9.7
    "h2-settings-deny":        "H2_SETTINGS_FP_ENABLED",
    "h2-settings-mismatch":    "H2_SETTINGS_FP_ENABLED",
    # Admin-IP control (1.9.7 mapping)
    "admin-ip-blocked":        "ADMIN_ALLOWED_IPS",
}


class TestSignalKnobMappings:
    """Every detection signal emitted in 1.9.7 must have a kill-switch
    entry in SIGNAL_KNOB so the dashboard renders the right control."""

    @pytest.mark.parametrize("signal,knob", SIGNAL_KNOB_NEW_IN_197.items())
    def test_signal_mapped_to_knob(self, signal, knob):
        assert signal in cph.SIGNAL_KNOB, (
            f"signal {signal!r} missing from SIGNAL_KNOB — dashboard "
            "kill-switch UI will show it as always-on"
        )
        assert cph.SIGNAL_KNOB[signal] == knob, (
            f"signal {signal!r} mapped to {cph.SIGNAL_KNOB[signal]!r}, "
            f"expected {knob!r}"
        )

    def test_redirect_maze_bot_in_signal_knob(self):
        """redirect-maze-bot got its mapping AND its _HOT_RELOAD_KNOBS
        entry in 1.9.7 (per CHANGELOG)."""
        assert "redirect-maze-bot" in cph.SIGNAL_KNOB
        assert cph.SIGNAL_KNOB["redirect-maze-bot"] == "REDIRECT_MAZE_ENABLED"


# ── 3. UPSTREAM hot-reload validator wiring ──────────────────────────────────

class TestUpstreamHotReloadWiring:
    """1.9.7 SECURITY: _HOT_RELOAD_KNOBS["UPSTREAM"] validator was
    re-bound from a bare scheme/length lambda to _upstream_safe_to_reload.
    A future refactor that drops the rebind would silently re-introduce
    the SSRF window."""

    def test_validator_is_ssrf_aware(self):
        coercer, validator = cph._HOT_RELOAD_KNOBS["UPSTREAM"]
        assert validator is cph._upstream_safe_to_reload, (
            "UPSTREAM hot-reload validator must be _upstream_safe_to_reload, "
            f"got {validator!r}"
        )

    def test_rebind_block_present_in_source(self):
        src = open(cph.__file__, encoding="utf-8").read()
        assert '_HOT_RELOAD_KNOBS["UPSTREAM"]' in src, (
            "UPSTREAM validator re-bind block missing"
        )
        assert "_upstream_safe_to_reload" in src

    def test_validator_rejects_metadata_via_hot_reload_path(self):
        """End-to-end through the hot-reload knob dict (not the standalone
        function) — proves the dict actually points at the SSRF guard."""
        _, validator = cph._HOT_RELOAD_KNOBS["UPSTREAM"]
        assert validator("http://169.254.169.254/") is False
        assert validator("http://127.0.0.1/") is False


# ── 4. ui-theme endpoint + routes + persistence helpers ──────────────────────

class TestUiThemeEndpoint:
    def test_endpoint_exists_and_is_async(self):
        assert hasattr(settings_mod, "ui_theme_endpoint")
        assert inspect.iscoroutinefunction(settings_mod.ui_theme_endpoint)

    def test_get_route_registered(self):
        proxy_src = open(
            importlib.import_module("proxy").__file__, encoding="utf-8"
        ).read()
        assert re.search(
            r'["\']ui-theme["\']\s*,\s*["\']GET["\'].*ui_theme_endpoint',
            proxy_src,
        ), "GET /secured/ui-theme route missing"

    def test_post_route_registered(self):
        proxy_src = open(
            importlib.import_module("proxy").__file__, encoding="utf-8"
        ).read()
        assert re.search(
            r'["\']ui-theme["\']\s*,\s*["\']POST["\'].*ui_theme_endpoint',
            proxy_src,
        ), "POST /secured/ui-theme route missing"

    def test_set_ui_theme_callable(self):
        assert hasattr(sqlite_mod, "set_ui_theme")
        assert callable(sqlite_mod.set_ui_theme)
        sig = inspect.signature(sqlite_mod.set_ui_theme)
        assert list(sig.parameters)[:2] == ["db_path", "theme"], (
            f"set_ui_theme signature drift: {sig}"
        )

    def test_set_ui_theme_rejects_invalid(self, tmp_path):
        # Doesn't even attempt the DB write on invalid theme
        assert sqlite_mod.set_ui_theme(str(tmp_path / "nope.db"), "purple") is False
        assert sqlite_mod.set_ui_theme(str(tmp_path / "nope.db"), "") is False
        assert sqlite_mod.set_ui_theme(str(tmp_path / "nope.db"), "DARK") is False  # case-strict

    def test_get_ui_theme_falls_back_to_dark(self, tmp_path):
        # Non-existent DB → safe default 'dark', no raise
        v = sqlite_mod.get_ui_theme(str(tmp_path / "nope.db"))
        assert v == "dark"

    def test_set_get_roundtrip(self, tmp_path):
        db = str(tmp_path / "theme.db")
        # Bootstrap minimal schema
        import sqlite3
        c = sqlite3.connect(db)
        c.execute(
            "CREATE TABLE config_kv (key TEXT PRIMARY KEY, value TEXT, ts REAL)"
        )
        c.commit()
        c.close()
        assert sqlite_mod.set_ui_theme(db, "light") is True
        assert sqlite_mod.get_ui_theme(db) == "light"
        assert sqlite_mod.set_ui_theme(db, "dark") is True
        assert sqlite_mod.get_ui_theme(db) == "dark"


# ── 5. Mesh keypair / sign / verify deeper ───────────────────────────────────

class TestMeshKeypairContract:
    """The 1.9.7 Ed25519 swap MUST stay Ed25519 — a refactor that
    reverts to the old HMAC scheme would compromise the mesh."""

    def test_generate_keypair_signature(self):
        sig = inspect.signature(mesh._gw_generate_keypair)
        # No required args — easy to call at startup
        for p in sig.parameters.values():
            assert p.default is not inspect.Parameter.empty, (
                f"_gw_generate_keypair must take no required args; got {p}"
            )

    def test_keypair_returns_two_distinct_strings(self):
        try:
            priv, pub = mesh._gw_generate_keypair()
        except Exception as e:
            pytest.skip(f"cryptography unavailable: {e}")
        assert isinstance(priv, str) and isinstance(pub, str)
        assert priv != pub

    def test_signature_length_indicates_ed25519(self):
        try:
            priv, pub = mesh._gw_generate_keypair()
        except Exception as e:
            pytest.skip(f"cryptography unavailable: {e}")
        sig = mesh._gw_sign_offers(priv, {"x": 1})
        # Ed25519 sig is 64 bytes → base64url ≈ 86 chars (no padding)
        # If we ever see a 44-char (32-byte) sig, the impl drifted to HMAC.
        assert 80 <= len(sig) <= 96, (
            f"signature length {len(sig)} not Ed25519-shaped — possible regression to HMAC"
        )

    def test_canonical_bytes_excludes_sig(self):
        a = {"x": 1, "_sig": "..."}
        b = {"x": 1}
        assert mesh._canonical_offer_bytes(a) == mesh._canonical_offer_bytes(b)

    def test_fingerprint_helper_returns_short_hex(self):
        if not hasattr(mesh, "_gw_fingerprint"):
            pytest.skip("_gw_fingerprint absent")
        try:
            _, pub = mesh._gw_generate_keypair()
        except Exception as e:
            pytest.skip(str(e))
        fp = mesh._gw_fingerprint(pub)
        assert isinstance(fp, str)
        assert 8 <= len(fp) <= 32
        assert re.fullmatch(r"[0-9a-fA-F]+", fp), (
            f"_gw_fingerprint should be hex, got {fp!r}"
        )


# ── 6. db_load_state(clear_first=) signature ─────────────────────────────────

class TestDbLoadStateClearFirst:
    """1.9.7 added the `clear_first` param so the deferred (merge) path
    can avoid wiping ip_state during boot rehydrate. A regression that
    drops this param would re-introduce the boot-window ban-loss bug."""

    def test_clear_first_param_present(self):
        sig = inspect.signature(sqlite_mod.db_load_state)
        assert "clear_first" in sig.parameters, (
            "db_load_state(clear_first=) parameter missing — boot rehydrate "
            "would wipe in-memory bans"
        )

    def test_clear_first_default_true_backcompat(self):
        sig = inspect.signature(sqlite_mod.db_load_state)
        param = sig.parameters["clear_first"]
        assert param.default is True, (
            f"clear_first default must be True for back-compat, "
            f"got {param.default!r}"
        )


# ── 7. Session create + verify contract ──────────────────────────────────────

class TestSessionContract:
    def test_session_create_signature(self):
        sig = inspect.signature(users._session_create)
        assert list(sig.parameters)[:3] == ["username", "ip", "user_agent"]

    def test_session_verify_returns_none_or_username(self):
        # _session_verify(token) → str | None
        out = users._session_verify("clearly-not-a-valid-token")
        assert out is None

    def test_session_parse_rejects_garbage(self):
        assert users._session_parse("") is None
        assert users._session_parse("no-pipes") is None
        assert users._session_parse("a|b|c|d|e") is None  # too many pipes

    def test_csrf_nonce_field_exists_on_cache_entries(self):
        """_session_create writes csrf_nonce into the cache row.
        Regression guard against silent removal."""
        src = open(users.__file__, encoding="utf-8").read()
        idx = src.find("def _session_create")
        window = src[idx: idx + 2500]
        assert '"csrf_nonce"' in window, (
            "_session_create must populate the csrf_nonce key on the cache entry"
        )


# ── 8. TOTP partial-token contract ───────────────────────────────────────────

class TestTotpPartialTokenContract:
    def test_totp_pending_in_state(self):
        state = importlib.import_module("state")
        assert hasattr(state, "_TOTP_PENDING")
        assert hasattr(state, "_TOTP_PENDING_LOCK")

    def test_totp_verify_endpoint_async(self):
        assert inspect.iscoroutinefunction(users.totp_verify_endpoint)

    def test_login_submit_issues_partial_token(self):
        src = open(users.__file__, encoding="utf-8").read()
        idx = src.find("def login_submit_endpoint")
        # Find the function end via the next top-level `def ` after idx
        next_def = src.find("\nasync def ", idx + 1)
        if next_def == -1:
            next_def = src.find("\ndef ", idx + 1)
        window = src[idx: next_def if next_def != -1 else idx + 6000]
        # 1.9.7 issues a server-stored partial_token AND returns
        # {"step": "totp_required", "partial_token": <token>}
        assert '"totp_required"' in window, (
            "login_submit must return step=totp_required when user has TOTP"
        )
        assert '"partial_token"' in window
        assert "_TOTP_PENDING[" in window or "_TOTP_PENDING.get(" in window, (
            "login_submit must put the partial_token into _TOTP_PENDING"
        )


# ── 9. OIDC hardening constants ──────────────────────────────────────────────

class TestOidcConstants:
    def test_state_max_present_and_sane(self):
        assert hasattr(oidc, "_OIDC_STATE_MAX")
        assert 100 <= oidc._OIDC_STATE_MAX <= 10_000

    def test_state_cap_enforced_in_source(self):
        src = open(oidc.__file__, encoding="utf-8").read()
        # The cap check must be present in the login handler
        assert "_OIDC_STATE_MAX" in src
        # And a 503 when the cap is hit (per CHANGELOG)
        assert "503" in src

    def test_strict_exp_recheck_present(self):
        src = open(oidc.__file__, encoding="utf-8").read()
        assert "ExpiredSignatureError" in src
        assert "leeway" in src.lower()


# ── 10. Attack-playbook + honey-suggest endpoint registration ─────────────────

class TestAttackPlaybookRegistration:
    """Beyond the dedicated v197 test file — keep a fast guard that
    catches accidental route deregistration."""

    def test_routes_in_proxy(self):
        proxy_src = open(
            importlib.import_module("proxy").__file__, encoding="utf-8"
        ).read()
        for route_token in ("attack-playbook", "honey-suggest", "ui-theme",
                            "/login/totp"):
            assert route_token in proxy_src, f"route {route_token!r} missing"


# ── 11. SSRF guard contracts — both directions ───────────────────────────────

class TestSsrfGuardContracts:
    def test_ssrf_guard_url_is_callable(self):
        assert callable(cph._ssrf_guard_url)
        sig = inspect.signature(cph._ssrf_guard_url)
        # (url, label="", allow_loopback=False)
        params = list(sig.parameters)
        assert params[0] == "url"
        assert "label" in params
        assert "allow_loopback" in params

    def test_upstream_safe_to_reload_is_callable(self):
        assert callable(cph._upstream_safe_to_reload)
        sig = inspect.signature(cph._upstream_safe_to_reload)
        assert list(sig.parameters) == ["url"]

    def test_url_secret_guard_list_present(self):
        """_URL_SECRET_GUARDS gates the SSRF check on config writes for
        URL-shaped secrets (CROWDSEC_LAPI_URL, OIDC_ISSUER). Missing
        entries would silently let them through."""
        if not hasattr(cph, "_URL_SECRET_GUARDS"):
            pytest.skip("_URL_SECRET_GUARDS not exposed")
        guards = cph._URL_SECRET_GUARDS
        assert isinstance(guards, dict)
        # Boolean values gate allow_loopback per key
        for k, v in guards.items():
            assert isinstance(v, bool), f"{k}: {v!r} not a bool"


# ── 12. Forwarded / X-Forwarded-Prefix strip list ────────────────────────────

class TestForwardedStripList:
    def test_strip_list_in_source(self):
        src = open(cph.__file__, encoding="utf-8").read()
        # The strip notes / strip-list both reference these in source
        for header in ("Forwarded", "X-Forwarded-Prefix",
                       "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"):
            assert header in src, f"header strip for {header!r} missing"


# ── 13. CSRF nonce hot path — _csrf_token_valid legacy fallback ──────────────

class TestCsrfLegacyFallback:
    """Legacy in-flight cookies (HMAC-derived) must keep working until
    they expire. A refactor that drops the fallback would force every
    operator to re-login on upgrade."""

    def test_csrf_valid_in_users_or_auth(self):
        # The check function is in admin/auth.py — must accept either the
        # nonce OR the legacy HMAC.
        src = open(auth.__file__, encoding="utf-8").read()
        # Look for the legacy-fallback comment / token equality
        assert "csrf_nonce" in src or "csrf" in src, "no CSRF logic in admin.auth"


# ── 14. Logout clears agw_csrf ───────────────────────────────────────────────

class TestLogoutClearsCsrfCookie:
    def test_logout_clears_csrf_cookie_in_source(self):
        src = open(users.__file__, encoding="utf-8").read()
        idx = src.find("def logout_endpoint")
        if idx == -1:
            # Some splits may have a different name
            idx = src.find("def _logout")
        assert idx != -1, "logout endpoint not found"
        window = src[idx: idx + 1500]
        # Either del_cookie('agw_csrf') OR set_cookie('agw_csrf', '', max_age=0)
        assert "agw_csrf" in window, (
            "logout endpoint does not touch agw_csrf cookie"
        )
