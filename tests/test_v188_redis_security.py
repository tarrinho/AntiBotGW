"""
tests/test_v188_redis_security.py — QA tests for the Redis security controls (v1.8.8).

Covers:
  TestIpNetListParser        — _to_ip_net_list: valid CIDRs, invalid entries dropped, newline sep
  TestRedisAllowListKnob     — REDIS_ALLOW_LIST in _HOT_RELOAD_KNOBS + config.py default
  TestRedisBanHmac           — _hmac_sign / _hmac_verify: roundtrip, tamper detection, no-key fallback
  TestRedisAllowlistEnforce  — _check_redis_allowed: CIDR match, miss, empty=open, None host
  TestJa4DenylistZadd        — ja4-denylist uses ZADD/ZRANGEBYSCORE (not SADD/SMEMBERS)
  TestSettingsRedisCard      — settings.html card-redis HTML + JS present
  TestControlsRedisGuard     — controls.html skips REDIS_ALLOW_LIST in render loop

All tests are source-level static assertions + in-process unit checks.
No running server or Docker required.
"""
import inspect
import ipaddress
import pathlib
import sys
import types

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SETTINGS = (_ROOT / "dashboards" / "settings.html").read_text(encoding="utf-8")
_CONTROLS = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")

# ── lazy module helpers (avoid importing heavy proxy_handler at collection time)
def _ep():
    """Return integrations.endpoint_policy module."""
    import integrations.endpoint_policy as m
    return m

def _ri():
    """Return integrations.redis module (with test HMAC key injected)."""
    import integrations.redis as m
    return m

def _ja4():
    import integrations.ja4 as m
    return m

def _ph():
    import core.proxy_handler as m
    return m


# ─────────────────────────────────────────────────────────────────────────────
# TestIpNetListParser
# ─────────────────────────────────────────────────────────────────────────────
class TestIpNetListParser:
    """_to_ip_net_list must normalise CIDRs, drop invalid entries, accept multiple separators."""

    def test_comma_separated_cidrs(self):
        result = _ep()._to_ip_net_list("172.18.0.0/16,10.0.0.5/32")
        assert result == ["172.18.0.0/16", "10.0.0.5/32"]

    def test_newline_separated_cidrs(self):
        result = _ep()._to_ip_net_list("172.18.0.0/16\n10.0.0.5/32")
        assert result == ["172.18.0.0/16", "10.0.0.5/32"]

    def test_bare_ip_normalised_to_slash32(self):
        result = _ep()._to_ip_net_list("10.0.0.1")
        assert result == ["10.0.0.1/32"]

    def test_list_input_accepted(self):
        result = _ep()._to_ip_net_list(["192.168.1.0/24", "10.0.0.1"])
        assert result == ["192.168.1.0/24", "10.0.0.1/32"]

    def test_invalid_entry_silently_dropped(self):
        result = _ep()._to_ip_net_list("BADIP,192.168.1.1/32")
        assert result == ["192.168.1.1/32"], f"got {result}"

    def test_all_invalid_returns_empty(self):
        result = _ep()._to_ip_net_list("not-an-ip, also-bad")
        assert result == []

    def test_strict_false_host_bits_normalised(self):
        """192.168.1.5/24 → 192.168.1.0/24 (strict=False)."""
        result = _ep()._to_ip_net_list("192.168.1.5/24")
        assert result == ["192.168.1.0/24"]

    def test_empty_string_returns_empty(self):
        assert _ep()._to_ip_net_list("") == []

    def test_ipv6_cidr_accepted(self):
        result = _ep()._to_ip_net_list("::1/128")
        assert result == ["::1/128"]

    def test_returns_list_of_strings(self):
        result = _ep()._to_ip_net_list("10.0.0.0/8")
        assert isinstance(result, list)
        assert all(isinstance(x, str) for x in result)


# ─────────────────────────────────────────────────────────────────────────────
# TestRedisAllowListKnob
# ─────────────────────────────────────────────────────────────────────────────
class TestRedisAllowListKnob:
    """REDIS_ALLOW_LIST must be a hot-reload knob and default to empty in config."""

    def test_knob_registered_in_hot_reload_knobs(self):
        assert "REDIS_ALLOW_LIST" in _ph()._HOT_RELOAD_KNOBS, \
            "REDIS_ALLOW_LIST missing from _HOT_RELOAD_KNOBS"

    def test_knob_uses_ip_net_list_parser(self):
        parser, _ = _ph()._HOT_RELOAD_KNOBS["REDIS_ALLOW_LIST"]
        result = parser("172.18.0.0/16,10.0.0.5/32")
        assert result == ["172.18.0.0/16", "10.0.0.5/32"]

    def test_knob_parser_drops_invalid(self):
        parser, _ = _ph()._HOT_RELOAD_KNOBS["REDIS_ALLOW_LIST"]
        result = parser("BADENTRY,10.0.0.1/32")
        assert result == ["10.0.0.1/32"]

    def test_knob_validator_is_none(self):
        _, validator = _ph()._HOT_RELOAD_KNOBS["REDIS_ALLOW_LIST"]
        assert validator is None

    def test_config_default_is_empty_list(self):
        import config
        assert config.REDIS_ALLOW_LIST == [], \
            f"Expected [] but got {config.REDIS_ALLOW_LIST}"

    def test_config_has_redis_allow_list_attribute(self):
        import config
        assert hasattr(config, "REDIS_ALLOW_LIST"), "REDIS_ALLOW_LIST missing from config.py"

    def test_knob_parses_newline_input(self):
        parser, _ = _ph()._HOT_RELOAD_KNOBS["REDIS_ALLOW_LIST"]
        result = parser("172.18.0.0/16\n10.0.0.1/32")
        assert "172.18.0.0/16" in result
        assert "10.0.0.1/32" in result


# ─────────────────────────────────────────────────────────────────────────────
# TestRedisBanHmac
# ─────────────────────────────────────────────────────────────────────────────
class TestRedisBanHmac:
    """HMAC signing of ban values: roundtrip, tamper rejection, no-key fallback."""

    def _with_key(self, key: bytes):
        m = _ri()
        m._REDIS_HMAC_KEY = key
        return m

    def test_sign_adds_pipe_suffix(self):
        m = self._with_key(b"secret")
        signed = m._hmac_sign("1748000000|reason")
        parts = signed.rsplit("|", 1)
        assert len(parts) == 2
        assert len(parts[1]) == 32, f"sig should be 32 hex chars (F-09: 128-bit), got {parts[1]!r}"

    def test_verify_roundtrip(self):
        m = self._with_key(b"secret")
        inner = "1748000000|ban_reason"
        signed = m._hmac_sign(inner)
        assert m._hmac_verify(signed) == inner

    def test_tampered_value_rejected(self):
        m = self._with_key(b"secret")
        signed = m._hmac_sign("1748000000|reason")
        tampered = signed[:-3] + "xyz"
        assert m._hmac_verify(tampered) is None

    def test_wrong_key_rejected(self):
        m = _ri()
        m._REDIS_HMAC_KEY = b"key-a"
        signed = m._hmac_sign("1748000000|reason")
        m._REDIS_HMAC_KEY = b"key-b"
        assert m._hmac_verify(signed) is None

    def test_no_key_passthrough(self):
        """When _REDIS_HMAC_KEY is empty, sign returns value unchanged and verify accepts anything."""
        m = _ri()
        m._REDIS_HMAC_KEY = b""
        raw = "1748000000|reason"
        assert m._hmac_sign(raw) == raw
        assert m._hmac_verify(raw) == raw

    def test_epoch_extractable_after_verify(self):
        m = self._with_key(b"secret")
        signed = m._hmac_sign("1748000000|some-reason")
        inner = m._hmac_verify(signed)
        epoch = float(inner.split("|", 1)[0])
        assert epoch == 1748000000.0

    def test_sign_is_deterministic(self):
        m = self._with_key(b"secret")
        a = m._hmac_sign("1748000000|reason")
        b = m._hmac_sign("1748000000|reason")
        assert a == b

    def test_sign_uses_sha256(self):
        """Verify the function exists and references sha256 in source."""
        src = inspect.getsource(_ri()._hmac_sign)
        assert "sha256" in src

    def test_hmac_compare_digest_used(self):
        """compare_digest prevents timing attacks."""
        src = inspect.getsource(_ri()._hmac_verify)
        assert "compare_digest" in src


# ─────────────────────────────────────────────────────────────────────────────
# TestRedisAllowlistEnforce
# ─────────────────────────────────────────────────────────────────────────────
class TestRedisAllowlistEnforce:
    """_check_redis_allowed must enforce CIDR matching against host IP."""

    def _set_allowlist(self, nets: list):
        """Inject a mock proxy_handler module with REDIS_ALLOW_LIST set."""
        self._orig_ph = sys.modules.get("core.proxy_handler")
        mock_ph = types.ModuleType("core.proxy_handler")
        mock_ph.REDIS_ALLOW_LIST = nets
        sys.modules["core.proxy_handler"] = mock_ph
        return mock_ph

    def teardown_method(self, _):
        orig = getattr(self, "_orig_ph", None)
        if orig is not None:
            sys.modules["core.proxy_handler"] = orig
        else:
            sys.modules.pop("core.proxy_handler", None)

    def test_ip_inside_cidr_allowed(self):
        self._set_allowlist(["172.18.0.0/16"])
        assert _ri()._check_redis_allowed("172.18.0.5") is True

    def test_ip_outside_cidr_blocked(self):
        self._set_allowlist(["10.0.0.0/8"])
        assert _ri()._check_redis_allowed("172.18.0.5") is False

    def test_exact_ip_allowed(self):
        self._set_allowlist(["10.0.0.5/32"])
        assert _ri()._check_redis_allowed("10.0.0.5") is True

    def test_exact_ip_wrong_address_blocked(self):
        self._set_allowlist(["10.0.0.5/32"])
        assert _ri()._check_redis_allowed("10.0.0.6") is False

    def test_empty_allowlist_is_unrestricted(self):
        self._set_allowlist([])
        assert _ri()._check_redis_allowed("1.2.3.4") is True

    def test_none_host_ip_blocked(self):
        self._set_allowlist(["172.18.0.0/16"])
        assert _ri()._check_redis_allowed(None) is False

    def test_multiple_cidrs_any_match_allowed(self):
        self._set_allowlist(["10.0.0.0/8", "172.18.0.0/16"])
        assert _ri()._check_redis_allowed("172.18.1.1") is True
        assert _ri()._check_redis_allowed("10.255.0.1") is True

    def test_multiple_cidrs_no_match_blocked(self):
        self._set_allowlist(["10.0.0.0/8", "172.18.0.0/16"])
        assert _ri()._check_redis_allowed("192.168.1.1") is False

    def test_function_reads_live_allowlist_per_call(self):
        """Hot-reload: changing the list takes effect on the next call."""
        mock_ph = self._set_allowlist(["10.0.0.0/8"])
        assert _ri()._check_redis_allowed("10.0.0.1") is True
        mock_ph.REDIS_ALLOW_LIST = ["192.168.0.0/16"]   # simulate hot-reload
        assert _ri()._check_redis_allowed("10.0.0.1") is False


# ─────────────────────────────────────────────────────────────────────────────
# TestJa4DenylistZadd
# ─────────────────────────────────────────────────────────────────────────────
class TestJa4DenylistZadd:
    """JA4 denylist Redis ops must use sorted-set commands, not SADD/SMEMBERS."""

    def _ban_src(self):
        return inspect.getsource(_ja4()._observe_ja4_ban)

    def _refresh_src(self):
        return inspect.getsource(_ja4()._refresh_ja4_denylist_loop)

    def test_observe_uses_zadd(self):
        assert "zadd" in self._ban_src(), "_observe_ja4_ban must use ZADD"

    def test_observe_does_not_use_sadd(self):
        assert "sadd" not in self._ban_src(), "_observe_ja4_ban must NOT use SADD"

    def test_refresh_uses_zrangebyscore(self):
        assert "zrangebyscore" in self._refresh_src()

    def test_refresh_uses_zremrangebyscore(self):
        assert "zremrangebyscore" in self._refresh_src()

    def test_refresh_does_not_use_smembers(self):
        assert "smembers" not in self._refresh_src(), \
            "refresh loop must NOT use SMEMBERS (use ZRANGEBYSCORE)"

    def test_zadd_uses_epoch_score(self):
        """Score must be current time so old entries age out."""
        src = self._ban_src()
        assert "_t.time()" in src or "time()" in src, \
            "ZADD score must be the current epoch timestamp"

    def test_refresh_prunes_before_reading(self):
        """ZREMRANGEBYSCORE must appear before ZRANGEBYSCORE in the refresh source."""
        src = self._refresh_src()
        zrem_pos = src.find("zremrangebyscore")
        zrange_pos = src.find("zrangebyscore")
        assert zrem_pos != -1 and zrange_pos != -1
        assert zrem_pos < zrange_pos, \
            "Prune (ZREMRANGEBYSCORE) must happen before read (ZRANGEBYSCORE)"


# ─────────────────────────────────────────────────────────────────────────────
# TestSettingsRedisCard
# ─────────────────────────────────────────────────────────────────────────────
class TestSettingsRedisCard:
    """settings.html must contain a card-redis section with required UI elements."""

    def test_card_redis_present(self):
        assert 'id="card-redis"' in _SETTINGS, "card-redis not found in settings.html"

    def test_redis_status_pill_present(self):
        assert 'id="redis-status-pill"' in _SETTINGS
        assert 'id="redis-status-text"' in _SETTINGS

    def test_redis_url_display_present(self):
        assert 'id="redis-url-display"' in _SETTINGS

    def test_redis_sec_flags_present(self):
        assert 'id="redis-sec-flags"' in _SETTINGS

    def test_allowlist_textarea_present(self):
        assert 'id="redis-allowlist-input"' in _SETTINGS

    def test_apply_button_present(self):
        assert 'id="btn-redis-apply"' in _SETTINGS

    def test_reset_button_present(self):
        assert 'id="btn-redis-reset"' in _SETTINGS

    def test_redis_msg_span_present(self):
        assert 'id="redis-msg"' in _SETTINGS

    def test_load_redis_function_defined(self):
        assert "loadRedis" in _SETTINGS

    def test_load_redis_reads_config_endpoint(self):
        idx = _SETTINGS.find("loadRedis")
        chunk = _SETTINGS[idx:idx + 800]
        assert "/secured/config" in chunk, "loadRedis must GET /secured/config"

    def test_load_redis_checks_connected_field(self):
        idx = _SETTINGS.find("loadRedis")
        chunk = _SETTINGS[idx:idx + 800]
        assert "connected" in chunk, "loadRedis must check services.redis.connected"

    def test_load_redis_reads_redis_allow_list(self):
        idx = _SETTINGS.find("loadRedis")
        chunk = _SETTINGS[idx:idx + 2200]
        assert "REDIS_ALLOW_LIST" in chunk, "loadRedis must read REDIS_ALLOW_LIST from state"

    def test_apply_posts_redis_allow_list(self):
        # anchor on the addEventListener block for the apply button
        idx = _SETTINGS.find("btn-redis-apply').addEventListener")
        assert idx != -1, "addEventListener block for btn-redis-apply not found"
        chunk = _SETTINGS[idx:idx + 1000]
        assert "REDIS_ALLOW_LIST" in chunk, "apply handler must POST REDIS_ALLOW_LIST"

    def test_apply_posts_to_config_endpoint(self):
        idx = _SETTINGS.find("btn-redis-apply').addEventListener")
        assert idx != -1
        chunk = _SETTINGS[idx:idx + 1000]
        assert "/secured/config" in chunk

    def test_tls_flag_checks_rediss_scheme(self):
        idx = _SETTINGS.find("loadRedis")
        chunk = _SETTINGS[idx:idx + 2200]
        assert "rediss://" in chunk, "security flags must check for rediss:// TLS scheme"

    def test_sanitise_url_hides_password(self):
        assert "_sanitiseUrl" in _SETTINGS or "sanitiseUrl" in _SETTINGS, \
            "URL display must sanitise password from REDIS_URL"

    def test_allowlist_status_element_present(self):
        assert 'id="redis-allowlist-status"' in _SETTINGS


# ─────────────────────────────────────────────────────────────────────────────
# TestControlsRedisGuard
# ─────────────────────────────────────────────────────────────────────────────
class TestControlsRedisGuard:
    """controls.html must skip REDIS_ALLOW_LIST in the knob render loop."""

    def test_redis_allow_list_skipped_in_render_loop(self):
        assert "REDIS_ALLOW_LIST" in _CONTROLS, \
            "REDIS_ALLOW_LIST skip guard missing from controls.html"
        idx = _CONTROLS.find("REDIS_ALLOW_LIST")
        chunk = _CONTROLS[idx - 30:idx + 80]
        assert "continue" in chunk, \
            "REDIS_ALLOW_LIST must be skipped with 'continue' in render loop"

    def test_redis_allow_list_skip_near_db_backend_skip(self):
        """The skip must be in the same render-loop guard block as DB_BACKEND."""
        db_idx = _CONTROLS.find("'DB_BACKEND' || name === 'POSTGRES_DSN'")
        redis_idx = _CONTROLS.find("REDIS_ALLOW_LIST")
        assert db_idx != -1 and redis_idx != -1
        assert abs(db_idx - redis_idx) < 300, \
            "REDIS_ALLOW_LIST skip should be adjacent to DB_BACKEND skip"
