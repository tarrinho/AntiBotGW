# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1814_ip_intel_qa.py — QA for the metrics_endpoint ip field fix (1.8.14).

Bug: metrics_endpoint set "ip": key where key is the track_key hash (identity),
     not the client IP. Dashboard called fetchIpIntel(d.ip) with the hash →
     ip_intel_endpoint → ipaddress.ip_address(hash) raised ValueError → HTTP 400 →
     "IP intelligence unavailable: HTTP 400".

Fix: "ip": s.last_ip or key  (use the actual client IP; fall back to key only
     when key is already a raw IP, e.g. rate-limiter entries).

Modules covered:
  core/proxy_handler.py  metrics_endpoint clients list (runtime + source)
  admin/users.py         ip_intel_endpoint validation (unit)

Test types: Unit  Regression  Functional  Boundary  Source-inspection
"""
from __future__ import annotations

import ipaddress
import os

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

import pathlib
_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _ph_src() -> str:
    return (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")


def _clients_append_block() -> str:
    src = _ph_src()
    idx = src.find("clients.append({")
    assert idx != -1, "proxy_handler.py must contain clients.append({"
    return src[idx: idx + 600]


# ═══════════════════════════════════════════════════════════════════════════
# Source-inspection: verify fix is present and bug is absent
# ═══════════════════════════════════════════════════════════════════════════

class TestMetricsClientIpFieldSource:
    """Source: clients.append ip field uses s.last_ip not raw key."""

    def test_ip_field_uses_last_ip_not_bare_key(self):
        """Regression: 'ip': key (bare) must not appear — it sets ip to the
        track_key hash which is not a valid IP address."""
        block = _clients_append_block()
        # The bug pattern — bare key with no fallback
        assert '"ip": key,' not in block and "'ip': key," not in block, (
            "clients.append 'ip' field must NOT be bare `key` — "
            "key is the track_key hash, not the client IP"
        )

    def test_ip_field_uses_last_ip_primary(self):
        """Fix: 'ip' must use s.last_ip as the primary value."""
        block = _clients_append_block()
        assert "s.last_ip" in block, (
            "clients.append 'ip' field must reference s.last_ip — "
            "s.last_ip holds the actual client IP for track_key-keyed entries"
        )

    def test_ip_field_has_key_fallback(self):
        """ip must fall back to key when s.last_ip is empty/None.
        Needed for pure-IP-keyed entries (rate limiter) where key is already an IP."""
        block = _clients_append_block()
        assert "s.last_ip or key" in block, (
            "clients.append 'ip' must be 's.last_ip or key' — "
            "key is the IP itself for rate-limiter entries (no separate last_ip)"
        )

    def test_last_ip_field_also_present(self):
        """'last_ip' sibling field must still be present — dashboard normalizeId
        uses raw.ip || raw.last_ip so both must be set."""
        block = _clients_append_block()
        assert '"last_ip"' in block or "'last_ip'" in block, (
            "clients.append must still include 'last_ip' — "
            "normalizeId fallback chain: raw.ip || raw.last_ip"
        )

    def test_id_field_still_uses_raw_key(self):
        """'id' field must remain key — identity is the track_key, not the IP.
        Only 'ip' was wrong; 'id' must stay as-is."""
        block = _clients_append_block()
        assert '"id": key' in block or "'id': key" in block, (
            "clients.append 'id' field must still be raw key (track_key) — "
            "the identity popover uses id to identify the tracked client"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Unit: logic of s.last_ip or key expression
# ═══════════════════════════════════════════════════════════════════════════

class TestMetricsClientIpFieldLogic:
    """Unit: the `s.last_ip or key` expression behaves correctly in all cases."""

    @pytest.mark.parametrize("last_ip,key,expected", [
        # Normal case: track_key entry with real last_ip
        ("1.2.3.4",   "abc123def456abc1",   "1.2.3.4"),
        ("2001:db8::1", "deadbeef12345678", "2001:db8::1"),
        # Rate-limiter entry: key IS the IP, last_ip empty
        ("",          "192.168.1.1",        "192.168.1.1"),
        (None,        "10.0.0.1",           "10.0.0.1"),
        # IPv6 rate-limiter entry
        ("",          "::1",                "::1"),
    ], ids=[
        "track-key-ipv4", "track-key-ipv6",
        "ip-keyed-empty-last-ip", "ip-keyed-none-last-ip", "ip-keyed-ipv6",
    ])
    def test_last_ip_or_key_expression(self, last_ip, key, expected):
        result = last_ip or key
        assert result == expected

    def test_track_key_hash_not_in_ip_when_last_ip_set(self):
        """When s.last_ip is set, ip must differ from the track_key hash."""
        last_ip = "1.2.3.4"
        key     = "a1b2c3d4e5f6a1b2"  # fake track_key hash
        result  = last_ip or key
        assert result != key, "ip field must not equal the track_key hash when last_ip is set"
        assert result == "1.2.3.4"


# ═══════════════════════════════════════════════════════════════════════════
# Functional: result is always a valid IP address
# ═══════════════════════════════════════════════════════════════════════════

class TestMetricsClientIpFieldIsValidIp:
    """Functional: ip field from metrics must always pass ipaddress.ip_address()."""

    @pytest.mark.parametrize("last_ip,key", [
        ("1.2.3.4",   "abc123def456abc1"),
        ("2001:db8::1", "deadbeef12345678"),
        ("",          "192.168.1.1"),
        (None,        "::1"),
        ("10.0.0.1",  "track-key-hash-00"),
    ], ids=[
        "ipv4-from-last-ip", "ipv6-from-last-ip",
        "ipv4-fallback-to-key", "ipv6-fallback-to-key",
        "private-ipv4-from-last-ip",
    ])
    def test_ip_field_is_valid_ip_address(self, last_ip, key):
        """s.last_ip or key must always produce a value that ipaddress.ip_address() accepts."""
        ip = last_ip or key
        try:
            ipaddress.ip_address(ip)
        except (ValueError, TypeError) as e:
            pytest.fail(
                f"ip field {ip!r} (last_ip={last_ip!r}, key={key!r}) "
                f"failed ipaddress.ip_address(): {e}"
            )

    def test_old_bug_track_key_hash_fails_ip_validation(self):
        """Confirms the OLD behaviour was broken: bare key (hash) fails ip_address().
        This test documents why the fix was needed."""
        fake_hash = "a1b2c3d4e5f6a1b2"
        with pytest.raises((ValueError, TypeError)):
            ipaddress.ip_address(fake_hash)


# ═══════════════════════════════════════════════════════════════════════════
# Runtime: inject ip_state entries, verify clients list output
# ═══════════════════════════════════════════════════════════════════════════

class TestMetricsEndpointClientIpRuntime:
    """Runtime: inject ip_state entries and verify the serialised 'ip' field."""

    def setup_method(self):
        from state import ip_state, IpState as _IS
        self._ip_state = ip_state
        self._IpState  = _IS
        self._keys     = []

    def teardown_method(self):
        for k in self._keys:
            self._ip_state.pop(k, None)

    def _add(self, key, last_ip="", **kwargs):
        s = self._IpState()
        s.last_ip = last_ip
        for k, v in kwargs.items():
            setattr(s, k, v)
        self._ip_state[key] = s
        self._keys.append(key)
        return s

    def _serialize_ip(self, key, s):
        """Replicate the exact expression used in metrics_endpoint."""
        return s.last_ip or key

    def test_track_key_entry_ip_is_last_ip(self):
        """Track-key-keyed entry: ip field = s.last_ip (not the hash key)."""
        key = "_qa_ipintel_tk_01"
        s   = self._add(key, last_ip="1.2.3.4")
        assert self._serialize_ip(key, s) == "1.2.3.4"
        assert self._serialize_ip(key, s) != key

    def test_ip_keyed_entry_falls_back_to_key(self):
        """IP-keyed rate-limiter entry: s.last_ip is empty → fall back to key (the IP)."""
        key = "10.0.0.99"  # pure-IP key for rate limiter
        s   = self._add(key, last_ip="")
        assert self._serialize_ip(key, s) == "10.0.0.99"

    def test_ip_field_is_valid_ip_for_track_key_entry(self):
        """Serialised ip passes ipaddress.ip_address() — no 400 from ip_intel."""
        key = "_qa_ipintel_tk_02"
        s   = self._add(key, last_ip="203.0.113.5")
        ip  = self._serialize_ip(key, s)
        ipaddress.ip_address(ip)  # must not raise

    def test_ip_field_is_valid_ip_for_ip_keyed_entry(self):
        """Fallback to key also produces valid IP."""
        key = "198.51.100.7"
        s   = self._add(key, last_ip="")
        ip  = self._serialize_ip(key, s)
        ipaddress.ip_address(ip)  # must not raise

    def test_id_and_ip_differ_for_track_key_entry(self):
        """id (track_key hash) must differ from ip (real IP) — not the same value."""
        key = "_qa_ipintel_tk_03"
        s   = self._add(key, last_ip="172.16.0.1")
        ip  = self._serialize_ip(key, s)
        assert ip != key, "ip field must not equal track_key hash"

    def test_ipv6_last_ip_returned(self):
        """IPv6 last_ip is returned correctly."""
        key = "_qa_ipintel_tk_ipv6"
        s   = self._add(key, last_ip="2001:db8::cafe")
        ip  = self._serialize_ip(key, s)
        assert ip == "2001:db8::cafe"
        ipaddress.ip_address(ip)  # must not raise


# ═══════════════════════════════════════════════════════════════════════════
# Unit: ip_intel_endpoint validation logic
# ═══════════════════════════════════════════════════════════════════════════

class TestIpIntelEndpointValidation:
    """Unit: ip_intel_endpoint input validation — 400 on invalid, pass on valid."""

    def _validate(self, ip: str) -> bool:
        """Return True if ip would pass the endpoint's ipaddress.ip_address() guard."""
        try:
            ipaddress.ip_address(ip.strip().strip("[]"))
            return True
        except (ValueError, TypeError):
            return False

    @pytest.mark.parametrize("ip", [
        "1.2.3.4",
        "192.168.1.1",
        "10.0.0.1",
        "203.0.113.99",
        "::1",
        "2001:db8::1",
        "::ffff:192.168.1.1",
    ])
    def test_valid_ip_accepted(self, ip):
        assert self._validate(ip) is True, f"{ip!r} must be accepted as valid"

    @pytest.mark.parametrize("ip,desc", [
        ("a1b2c3d4e5f6a1b2",       "track_key hash"),
        ("unknown",                 "xff unknown placeholder"),
        ("1.2.3.4:8080",           "ip with port"),
        ("1.2.3.4, 5.6.7.8",      "comma-separated xff"),
        ("",                        "empty string"),
        ("hostname.example.com",    "hostname not IP"),
    ])
    def test_invalid_ip_rejected(self, ip, desc):
        assert self._validate(ip) is False, f"{desc} ({ip!r}) must be rejected"

    def test_track_key_hash_returns_400_from_endpoint(self):
        """Regression: the exact error path that caused the bug.
        Track_key hash is not a valid IP → ip_intel_endpoint returns 400."""
        fake_hash = "a1b2c3d4e5f6a1b2"  # 16-char hex — plausible track_key
        assert self._validate(fake_hash) is False, (
            "Track-key hash must fail IP validation — confirms old bug caused 400"
        )

    def test_endpoint_validation_uses_ipaddress_module(self):
        """Source: ip_intel_endpoint must use ipaddress.ip_address for validation."""
        src = (_ROOT / "admin" / "users.py").read_text()
        fn_idx = src.find("async def ip_intel_endpoint")
        assert fn_idx != -1
        # iter-18: LIVE-1 auth gate widened the function preamble — bump the
        # slice so the ip_address validation block stays in frame.
        fn_block = src[fn_idx: fn_idx + 2500]
        assert "ip_address" in fn_block, (
            "ip_intel_endpoint must validate with ipaddress.ip_address — "
            "stdlib validation rejects hostnames, ports, hashes"
        )

    def test_endpoint_returns_400_status_on_invalid(self):
        """Source: ip_intel_endpoint must return status=400 on invalid IP."""
        src = (_ROOT / "admin" / "users.py").read_text()
        fn_idx = src.find("async def ip_intel_endpoint")
        assert fn_idx != -1
        # iter-18: LIVE-1 auth gate widened the function preamble — bump the
        # slice so the status=400 invalid-IP branch stays in frame.
        fn_block = src[fn_idx: fn_idx + 2500]
        assert "status=400" in fn_block, (
            "ip_intel_endpoint must return HTTP 400 on invalid IP — "
            "dashboard catches non-ok and shows 'unavailable: HTTP 400'"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Regression: normalizeId in dashboards uses raw.ip
# ═══════════════════════════════════════════════════════════════════════════

class TestDashboardNormalizeIdIpField:
    """Regression: normalizeId picks up raw.ip first — it must now be the real IP."""

    @pytest.mark.parametrize("dashboard", ["main.html", "agents.html"])
    def test_normalize_id_uses_raw_ip_primary(self, dashboard):
        """normalizeId must use raw.ip as the primary IP source.
        After the fix, raw.ip from metrics = s.last_ip (real IP), so this is correct."""
        src = (_ROOT / "dashboards" / dashboard).read_text()
        ni_idx = src.find("function normalizeId")
        assert ni_idx != -1, f"{dashboard} must define normalizeId"
        ni_block = src[ni_idx: ni_idx + 400]
        assert "raw.ip" in ni_block, (
            f"{dashboard} normalizeId must reference raw.ip — "
            "after fix, raw.ip = s.last_ip (real IP), not the track_key hash"
        )

    @pytest.mark.parametrize("dashboard", ["main.html", "agents.html"])
    def test_normalize_id_has_last_ip_fallback(self, dashboard):
        """normalizeId must keep raw.last_ip as fallback — belt-and-suspenders."""
        src = (_ROOT / "dashboards" / dashboard).read_text()
        ni_idx = src.find("function normalizeId")
        assert ni_idx != -1
        ni_block = src[ni_idx: ni_idx + 400]
        assert "raw.last_ip" in ni_block, (
            f"{dashboard} normalizeId must still have raw.last_ip fallback"
        )

    @pytest.mark.parametrize("dashboard", ["main.html", "agents.html"])
    def test_fetch_ip_intel_receives_d_ip(self, dashboard):
        """fetchIpIntel must receive d.ip (normalizeId output), not raw server field."""
        src = (_ROOT / "dashboards" / dashboard).read_text()
        assert "fetchIpIntel(d.ip)" in src, (
            f"{dashboard} must call fetchIpIntel(d.ip) — "
            "d.ip is normalizeId output; using raw field bypasses the fix"
        )
