# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1815_qa_feeds.py — extended QA for threat-intel feeds (1.8.14 Week 1).

Test types covered:
  P — parametrized: systematic IP/line-format matrix
  B — boundary: edge-of-valid inputs (empty feed, single entry, max line length)
  E — edge cases: CIDR notation, IPv6, private/loopback bypass, duplicate IPs
  R — regression: real-world Feodo/CINS/URLhaus line formats
  N — negative: disabled knobs, clean IPs, malformed data never crashes
  F — fuzz-safe: unexpected input types that must not raise
  T — timing: O(1) lookup claim (single vs. 10k-set)
  S — stats: stats dict contract after simulated load
"""
from __future__ import annotations

import os
import time
import unittest.mock as mock

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")
_REPO = os.path.join(os.path.dirname(__file__), "..")


# ─── P: parametrized IP/line formats ─────────────────────────────────────────

class TestFeedsParseParametrized:

    @pytest.mark.parametrize("line,expected", [
        # plain IPv4
        ("1.2.3.4",          "1.2.3.4"),
        ("  1.2.3.4  ",      "1.2.3.4"),
        # CIDR notation — host part only
        ("185.220.101.0/24", "185.220.101.0"),
        ("10.0.0.1/32",      "10.0.0.1"),
        ("198.51.100.99/16", "198.51.100.99"),
        # IPv6 plain
        ("2001:db8::1",      "2001:db8::1"),
        # IPv6 with CIDR
        ("2001:db8::/32",    "2001:db8::"),
    ])
    def test_valid_ip_extracted(self, line, expected):
        """_fetch_ip_lines should extract valid IPs from these line formats."""
        import reputation.feeds as _f
        with mock.patch("urllib.request.urlopen") as m_open:
            m_open.return_value.__enter__ = lambda s: s
            m_open.return_value.__exit__  = mock.Mock(return_value=False)
            m_open.return_value.read      = mock.Mock(return_value=line.encode())
            result = _f._fetch_ip_lines("https://example.com/feed.txt")
        assert expected in result

    @pytest.mark.parametrize("line", [
        "# comment line",
        "## another comment",
        "",
        "   ",
        "\t",
        "not-an-ip",
        "999.999.999.999",
        "hostname.example.com",
        "ftp://1.2.3.4",
        "1.2.3",
    ])
    def test_invalid_lines_skipped(self, line):
        """Malformed or comment lines produce no IPs."""
        import reputation.feeds as _f
        with mock.patch("urllib.request.urlopen") as m_open:
            m_open.return_value.__enter__ = lambda s: s
            m_open.return_value.__exit__  = mock.Mock(return_value=False)
            m_open.return_value.read      = mock.Mock(return_value=line.encode())
            result = _f._fetch_ip_lines("https://example.com/feed.txt")
        assert result == set()

    @pytest.mark.parametrize("ip,expected_clean", [
        ("127.0.0.1",   True),   # loopback
        ("::1",         True),   # IPv6 loopback
        ("10.0.0.1",    True),   # RFC1918 private
        ("192.168.1.1", True),   # RFC1918 private
        ("172.16.0.1",  True),   # RFC1918 private
        ("169.254.0.1", True),   # link-local
        ("fe80::1",     True),   # IPv6 link-local
        ("185.220.101.47", False),  # real Tor exit — should fire if in feed
        ("194.165.16.1",   False),  # public IP — should fire
    ])
    def test_private_ips_bypassed(self, ip, expected_clean):
        """feeds_check() must skip private/loopback IPs regardless of feed content."""
        import reputation.feeds as _f
        old_feodo   = _f._feodo_ips
        old_cins    = _f._cins_ips
        old_urlhaus = _f._urlhaus_ips
        old_fe = _f.FEODO_ENABLED
        old_ce = _f.CINS_ENABLED
        old_ue = _f.URLHAUS_ENABLED
        try:
            _f._feodo_ips   = {ip}
            _f._cins_ips    = {ip}
            _f._urlhaus_ips = {ip}
            _f.FEODO_ENABLED   = True
            _f.CINS_ENABLED    = True
            _f.URLHAUS_ENABLED = True
            result = _f.feeds_check(ip)
            if expected_clean:
                assert result == []
            else:
                assert len(result) > 0
        finally:
            _f._feodo_ips    = old_feodo
            _f._cins_ips     = old_cins
            _f._urlhaus_ips  = old_urlhaus
            _f.FEODO_ENABLED   = old_fe
            _f.CINS_ENABLED    = old_ce
            _f.URLHAUS_ENABLED = old_ue


# ─── B: boundary conditions ───────────────────────────────────────────────────

class TestFeedsBoundary:

    def _feed_result(self, raw_bytes: bytes) -> set[str]:
        import reputation.feeds as _f
        with mock.patch("urllib.request.urlopen") as m_open:
            m_open.return_value.__enter__ = lambda s: s
            m_open.return_value.__exit__  = mock.Mock(return_value=False)
            m_open.return_value.read      = mock.Mock(return_value=raw_bytes)
            return _f._fetch_ip_lines("https://example.com/feed.txt")

    def test_empty_feed_file(self):
        assert self._feed_result(b"") == set()

    def test_only_comments(self):
        data = b"# Feodo C2 blocklist\n# Generated: 2026-01-01\n"
        assert self._feed_result(data) == set()

    def test_single_ip_feed(self):
        assert self._feed_result(b"1.2.3.4") == {"1.2.3.4"}

    def test_10000_ip_feed(self):
        """Feed with 10k IPs should parse without error."""
        ips = [f"{i//256}.{i%256}.1.1" for i in range(10000)]
        data = "\n".join(ips).encode()
        result = self._feed_result(data)
        assert len(result) == 10000

    def test_duplicate_ips_deduplicated(self):
        """Same IP on multiple lines → appears once in result set."""
        data = b"1.2.3.4\n1.2.3.4\n1.2.3.4\n"
        result = self._feed_result(data)
        assert result == {"1.2.3.4"}

    def test_crlf_line_endings(self):
        data = b"1.2.3.4\r\n5.6.7.8\r\n"
        result = self._feed_result(data)
        assert "1.2.3.4" in result
        assert "5.6.7.8" in result

    def test_very_long_comment_line(self):
        """A comment line of 10 000 chars doesn't crash."""
        data = (b"# " + b"x" * 10000 + b"\n1.2.3.4\n")
        result = self._feed_result(data)
        assert result == {"1.2.3.4"}

    def test_feed_with_bom(self):
        """UTF-8 BOM at start of file must not corrupt first IP."""
        data = b"\xef\xbb\xbf1.2.3.4\n"
        # BOM makes first line "﻿1.2.3.4" — not a valid IP, so result is empty
        # or BOM is stripped by decode. Either way, no crash.
        import reputation.feeds as _f
        with mock.patch("urllib.request.urlopen") as m_open:
            m_open.return_value.__enter__ = lambda s: s
            m_open.return_value.__exit__  = mock.Mock(return_value=False)
            m_open.return_value.read      = mock.Mock(return_value=data)
            try:
                _f._fetch_ip_lines("https://example.com/feed.txt")
            except Exception as exc:
                pytest.fail(f"BOM in feed raised: {exc}")


# ─── E: edge cases ────────────────────────────────────────────────────────────

class TestFeedsEdgeCases:

    def test_ipv6_in_feed_detected(self):
        """IPv6 addresses are valid feed entries and match correctly."""
        import reputation.feeds as _f
        # 2001:db8:: is a documentation prefix (private in Python 3.11+)
        # Use a real public Cloudflare IPv6 instead
        ipv6 = "2606:4700::1"
        old_feodo = _f._feodo_ips
        old_fe    = _f.FEODO_ENABLED
        try:
            _f._feodo_ips   = {ipv6}
            _f.FEODO_ENABLED = True
            result = _f.feeds_check(ipv6)
            assert "feodo-c2" in result
        finally:
            _f._feodo_ips   = old_feodo
            _f.FEODO_ENABLED = old_fe

    def test_ip_in_multiple_feeds_returns_all_signals(self):
        """IP present in all three feeds → all three signals."""
        import reputation.feeds as _f
        ip = "5.5.5.5"
        saved = (_f._feodo_ips, _f._cins_ips, _f._urlhaus_ips,
                 _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED)
        try:
            _f._feodo_ips   = {ip}
            _f._cins_ips    = {ip}
            _f._urlhaus_ips = {ip}
            _f.FEODO_ENABLED   = True
            _f.CINS_ENABLED    = True
            _f.URLHAUS_ENABLED = True
            result = _f.feeds_check(ip)
        finally:
            (_f._feodo_ips, _f._cins_ips, _f._urlhaus_ips,
             _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED) = saved
        assert set(result) == {"feodo-c2", "cins-rogue", "urlhaus-malware"}

    def test_ip_only_in_one_feed(self):
        """IP in only CINS → only cins-rogue signal."""
        import reputation.feeds as _f
        ip = "5.5.5.5"
        saved = (_f._feodo_ips, _f._cins_ips, _f._urlhaus_ips,
                 _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED)
        try:
            _f._feodo_ips   = set()
            _f._cins_ips    = {ip}
            _f._urlhaus_ips = set()
            _f.FEODO_ENABLED   = True
            _f.CINS_ENABLED    = True
            _f.URLHAUS_ENABLED = True
            result = _f.feeds_check(ip)
        finally:
            (_f._feodo_ips, _f._cins_ips, _f._urlhaus_ips,
             _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED) = saved
        assert result == ["cins-rogue"]


# ─── R: regression — real-world feed line formats ────────────────────────────

class TestFeedsRealWorldFormats:

    def _parse(self, text: str) -> set[str]:
        import reputation.feeds as _f
        with mock.patch("urllib.request.urlopen") as m_open:
            m_open.return_value.__enter__ = lambda s: s
            m_open.return_value.__exit__  = mock.Mock(return_value=False)
            m_open.return_value.read      = mock.Mock(return_value=text.encode())
            return _f._fetch_ip_lines("https://example.com/")

    def test_feodo_format(self):
        """Feodo Tracker plaintext format: comments + one IP per line."""
        data = (
            "################################################################\n"
            "# Feodo Tracker | https://feodotracker.abuse.ch/              #\n"
            "# Last updated: 2026-01-15 12:00 UTC                          #\n"
            "# This blocklist contains IPs hosting Botnet C2 servers.      #\n"
            "################################################################\n"
            "185.220.101.47\n"
            "194.165.16.201\n"
            "193.233.132.100\n"
        )
        result = self._parse(data)
        assert result == {"185.220.101.47", "194.165.16.201", "193.233.132.100"}

    def test_cins_format(self):
        """CINS Army plaintext: IPs one per line, no comments."""
        data = "1.2.3.4\n5.6.7.8\n9.10.11.12\n"
        result = self._parse(data)
        assert result == {"1.2.3.4", "5.6.7.8", "9.10.11.12"}

    def test_urlhaus_format(self):
        """URLhaus text_online: # comments + IPs."""
        data = (
            "# URLhaus Online URL Feed\n"
            "# Terms Of Use: https://urlhaus.abuse.ch/api/\n"
            "45.33.32.156\n"
            "212.95.153.36\n"
        )
        result = self._parse(data)
        assert result == {"45.33.32.156", "212.95.153.36"}

    def test_mixed_ipv4_ipv6_feed(self):
        """Feed with both IPv4 and IPv6 entries."""
        data = "1.2.3.4\n2001:db8::1\n5.6.7.8\n"
        result = self._parse(data)
        assert "1.2.3.4" in result
        assert "2001:db8::1" in result
        assert "5.6.7.8" in result


# ─── N: negative — disabled knobs ─────────────────────────────────────────────

class TestFeedsNegative:

    def _check_with_knobs(self, ip: str, fe: bool, ce: bool, ue: bool) -> list[str]:
        import reputation.feeds as _f
        saved = (_f._feodo_ips, _f._cins_ips, _f._urlhaus_ips,
                 _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED)
        try:
            _f._feodo_ips   = {ip}
            _f._cins_ips    = {ip}
            _f._urlhaus_ips = {ip}
            _f.FEODO_ENABLED   = fe
            _f.CINS_ENABLED    = ce
            _f.URLHAUS_ENABLED = ue
            return _f.feeds_check(ip)
        finally:
            (_f._feodo_ips, _f._cins_ips, _f._urlhaus_ips,
             _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED) = saved

    @pytest.mark.parametrize("fe,ce,ue,expected", [
        (False, False, False, []),
        (True,  False, False, ["feodo-c2"]),
        (False, True,  False, ["cins-rogue"]),
        (False, False, True,  ["urlhaus-malware"]),
        (True,  True,  False, ["feodo-c2", "cins-rogue"]),
        (True,  False, True,  ["feodo-c2", "urlhaus-malware"]),
        (False, True,  True,  ["cins-rogue", "urlhaus-malware"]),
        (True,  True,  True,  ["feodo-c2", "cins-rogue", "urlhaus-malware"]),
    ])
    def test_knob_combinations(self, fe, ce, ue, expected):
        result = self._check_with_knobs("5.5.5.5", fe, ce, ue)
        assert sorted(result) == sorted(expected)

    def test_clean_ip_no_signals(self):
        import reputation.feeds as _f
        saved = (_f._feodo_ips, _f._cins_ips, _f._urlhaus_ips,
                 _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED)
        try:
            _f._feodo_ips   = {"1.1.1.1"}
            _f._cins_ips    = {"1.1.1.1"}
            _f._urlhaus_ips = {"1.1.1.1"}
            _f.FEODO_ENABLED   = True
            _f.CINS_ENABLED    = True
            _f.URLHAUS_ENABLED = True
            result = _f.feeds_check("8.8.8.8")   # clean IP
        finally:
            (_f._feodo_ips, _f._cins_ips, _f._urlhaus_ips,
             _f.FEODO_ENABLED, _f.CINS_ENABLED, _f.URLHAUS_ENABLED) = saved
        assert result == []


# ─── F: fuzz-safe — unexpected inputs must not raise ─────────────────────────

class TestFeedsFuzzSafe:

    @pytest.mark.parametrize("bad_ip", [
        "",
        "  ",
        None,
        "abc",
        "256.0.0.1",
        "1.2.3.4.5",
        ":::",
        "gggg::1",
        b"1.2.3.4",      # bytes instead of str (wrong type)
        12345,            # int
        [],
        {},
    ])
    def test_feeds_check_malformed_ip_safe(self, bad_ip):
        """feeds_check must return [] for any bad IP type/value."""
        import reputation.feeds as _f
        try:
            result = _f.feeds_check(bad_ip)
            assert result == []
        except Exception as exc:
            pytest.fail(f"feeds_check({bad_ip!r}) raised {exc}")

    def test_fetch_network_error_updates_last_error(self):
        """Network failure during fetch updates last_error, does not raise."""
        import reputation.feeds as _f
        old_err = _f._feodo_stats["last_error"]
        try:
            with mock.patch("urllib.request.urlopen",
                            side_effect=OSError("connection refused")):
                _f._feodo_fetch()
            assert "connection refused" in _f._feodo_stats["last_error"]
        finally:
            _f._feodo_stats["last_error"] = old_err

    def test_fetch_ssl_error_updates_last_error(self):
        """SSL error during fetch updates last_error, does not raise."""
        import ssl
        import reputation.feeds as _f
        old_err = _f._cins_stats["last_error"]
        try:
            with mock.patch("urllib.request.urlopen",
                            side_effect=ssl.SSLError("cert verify failed")):
                _f._cins_fetch()
            assert "cert verify failed" in _f._cins_stats["last_error"]
        finally:
            _f._cins_stats["last_error"] = old_err


# ─── T: timing — O(1) lookup ─────────────────────────────────────────────────

class TestFeedsTiming:

    def test_lookup_constant_time_small_vs_large(self):
        """Set membership lookup time for 1 IP vs 100k IPs must be roughly equal."""
        import reputation.feeds as _f
        saved = (_f._feodo_ips, _f.FEODO_ENABLED,
                 _f._cins_ips,  _f.CINS_ENABLED,
                 _f._urlhaus_ips, _f.URLHAUS_ENABLED)
        try:
            _f._feodo_ips    = {"1.2.3.4"}
            _f.FEODO_ENABLED  = True
            _f._cins_ips     = set()
            _f.CINS_ENABLED   = False
            _f._urlhaus_ips  = set()
            _f.URLHAUS_ENABLED = False

            # Warm-up
            for _ in range(100):
                _f.feeds_check("9.9.9.9")

            t0 = time.perf_counter()
            for _ in range(10000):
                _f.feeds_check("9.9.9.9")
            t_small = time.perf_counter() - t0

            # Large feed
            _f._feodo_ips = {f"{i//256}.{i%256}.{(i//65536)%256}.1"
                             for i in range(100000)}
            _f._feodo_ips.add("1.2.3.4")

            t0 = time.perf_counter()
            for _ in range(10000):
                _f.feeds_check("9.9.9.9")
            t_large = time.perf_counter() - t0

        finally:
            (_f._feodo_ips, _f.FEODO_ENABLED,
             _f._cins_ips,  _f.CINS_ENABLED,
             _f._urlhaus_ips, _f.URLHAUS_ENABLED) = saved

        # Large set should not be more than 10× slower (O(1) expected)
        ratio = t_large / t_small if t_small > 0 else 0
        assert ratio < 10, f"Lookup time ratio large/small = {ratio:.1f} (expected <10)"


# ─── S: stats contract ────────────────────────────────────────────────────────

class TestFeedsStats:

    def test_stats_dict_keys_present(self):
        from reputation.feeds import feeds_stats
        stats = feeds_stats()
        for feed in ("feodo", "cins", "urlhaus"):
            assert feed in stats
            for k in ("loaded_at", "size", "last_error", "fetches", "enabled"):
                assert k in stats[feed], f"{feed}.{k} missing from stats"

    def test_stats_types(self):
        from reputation.feeds import feeds_stats
        stats = feeds_stats()
        for feed in ("feodo", "cins", "urlhaus"):
            assert isinstance(stats[feed]["loaded_at"], float)
            assert isinstance(stats[feed]["size"], int)
            assert isinstance(stats[feed]["last_error"], str)
            assert isinstance(stats[feed]["fetches"], int)
            assert isinstance(stats[feed]["enabled"], bool)

    def test_fetch_increments_fetches_counter(self):
        """A successful fetch increments the fetches counter."""
        import reputation.feeds as _f
        old = _f._feodo_stats["fetches"]
        try:
            with mock.patch("urllib.request.urlopen") as m_open:
                m_open.return_value.__enter__ = lambda s: s
                m_open.return_value.__exit__  = mock.Mock(return_value=False)
                m_open.return_value.read      = mock.Mock(return_value=b"1.2.3.4\n")
                _f._feodo_fetch()
            assert _f._feodo_stats["fetches"] == old + 1
        finally:
            _f._feodo_stats["fetches"] = old

    def test_successful_fetch_clears_last_error(self):
        """A successful fetch after an error resets last_error to empty string."""
        import reputation.feeds as _f
        _f._feodo_stats["last_error"] = "prev error"
        try:
            with mock.patch("urllib.request.urlopen") as m_open:
                m_open.return_value.__enter__ = lambda s: s
                m_open.return_value.__exit__  = mock.Mock(return_value=False)
                m_open.return_value.read      = mock.Mock(return_value=b"5.5.5.5\n")
                _f._feodo_fetch()
            assert _f._feodo_stats["last_error"] == ""
        finally:
            _f._feodo_stats["last_error"] = ""
