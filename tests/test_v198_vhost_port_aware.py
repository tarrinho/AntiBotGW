"""
tests/test_v198_vhost_port_aware.py — 1.9.8 VHOST_PORT_AWARE.

When VHOST_PORT_AWARE is on, the inbound Host's PORT is part of the vhost
identity, so `challenges.site.com:8008` and `challenges.site.com:8009` are
DISTINCT vhosts (separate config / upstream / stats / bans). Default OFF keeps
the historical host-only behaviour (port stripped).

Required because CTFd serves DYNAMIC challenges as separate instances on the
same hostname but different ports — host-only keying would collapse every
challenge into one vhost, so per-instance upstream / policy / ban scope is
impossible without port-aware keying.

Lookup precedence (most → least specific):
  exact `host:port` → portless `host` (all-ports fallback) → `*.<parent>` wildcards.
"""
import os

os.environ.setdefault("UPSTREAM", "http://localhost")

import pytest
import vhost
import config
import core.proxy_handler as _cph


def _set_port_aware(v: bool) -> None:
    # _port_aware() reads core.proxy_handler first, then config.
    _cph.VHOST_PORT_AWARE = v
    config.VHOST_PORT_AWARE = v


@pytest.fixture(autouse=True)
def _isolate():
    """Each test gets a clean VHOSTS table + knob, restored afterwards."""
    _saved = dict(vhost.VHOSTS)
    vhost.VHOSTS.clear()
    vhost.set_vhost("")
    yield
    vhost.VHOSTS.clear()
    vhost.VHOSTS.update(_saved)
    _set_port_aware(False)
    vhost.set_vhost("")


# ── default OFF: historical host-only behaviour ───────────────────────────────

def test_default_off_strips_port():
    _set_port_aware(False)
    vhost.VHOSTS["challenges.site.com"] = {"UPSTREAM": "https://a.example"}
    vhost.set_vhost("challenges.site.com:8008")
    assert vhost.current_vhost_host() == "challenges.site.com", "port must be stripped when OFF"
    assert vhost.vc("UPSTREAM") == "https://a.example"


def test_default_off_hostport_entry_never_matches():
    """With the knob OFF a host:port entry can't be reached (port is stripped)."""
    _set_port_aware(False)
    vhost.VHOSTS["challenges.site.com:8008"] = {"UPSTREAM": "https://eight.example"}
    vhost.set_vhost("challenges.site.com:8008")
    assert vhost.current_vhost_host() == "challenges.site.com"
    assert vhost.vc("UPSTREAM") != "https://eight.example"  # no match → global UPSTREAM


# ── ON: port-distinct vhosts ──────────────────────────────────────────────────

def test_port_aware_distinct_vhosts():
    _set_port_aware(True)
    vhost.VHOSTS["challenges.site.com:8008"] = {"UPSTREAM": "https://eight.example"}
    vhost.VHOSTS["challenges.site.com:8009"] = {"UPSTREAM": "https://nine.example"}

    vhost.set_vhost("challenges.site.com:8008")
    assert vhost.current_vhost_host() == "challenges.site.com:8008"
    assert vhost.vc("UPSTREAM") == "https://eight.example"

    vhost.set_vhost("challenges.site.com:8009")
    assert vhost.current_vhost_host() == "challenges.site.com:8009"
    assert vhost.vc("UPSTREAM") == "https://nine.example"


def test_portless_entry_is_all_ports_fallback():
    _set_port_aware(True)
    vhost.VHOSTS["challenges.site.com"] = {"UPSTREAM": "https://any.example"}
    vhost.set_vhost("challenges.site.com:7000")
    # key keeps the port (for stats/bans) but config falls back to the portless entry
    assert vhost.current_vhost_host() == "challenges.site.com:7000"
    assert vhost.vc("UPSTREAM") == "https://any.example"


def test_exact_hostport_wins_over_portless():
    _set_port_aware(True)
    vhost.VHOSTS["challenges.site.com"] = {"UPSTREAM": "https://fallback.example"}
    vhost.VHOSTS["challenges.site.com:8008"] = {"UPSTREAM": "https://exact.example"}

    vhost.set_vhost("challenges.site.com:8008")
    assert vhost.vc("UPSTREAM") == "https://exact.example", "exact host:port must win"

    vhost.set_vhost("challenges.site.com:9999")
    assert vhost.vc("UPSTREAM") == "https://fallback.example", "unmatched port → portless fallback"


def test_wildcard_matches_ported_subdomain():
    _set_port_aware(True)
    vhost.VHOSTS["*.site.com"] = {"UPSTREAM": "https://wild.example"}
    vhost.set_vhost("a.site.com:8008")
    assert vhost.vc("UPSTREAM") == "https://wild.example"


def test_port_specific_wildcard_wins_over_portless_wildcard():
    _set_port_aware(True)
    vhost.VHOSTS["*.site.com"] = {"UPSTREAM": "https://wild-any.example"}
    vhost.VHOSTS["*.site.com:8008"] = {"UPSTREAM": "https://wild-8008.example"}
    vhost.set_vhost("a.site.com:8008")
    assert vhost.vc("UPSTREAM") == "https://wild-8008.example"
    vhost.set_vhost("a.site.com:9000")
    assert vhost.vc("UPSTREAM") == "https://wild-any.example"


def test_portless_request_still_matches_portless_entry_when_on():
    _set_port_aware(True)
    vhost.VHOSTS["challenges.site.com"] = {"UPSTREAM": "https://plain.example"}
    vhost.set_vhost("challenges.site.com")  # client used the default port (no :port in Host)
    assert vhost.current_vhost_host() == "challenges.site.com"
    assert vhost.vc("UPSTREAM") == "https://plain.example"


# ── hostname validation ───────────────────────────────────────────────────────

def test_validator_accepts_port_only_when_allowed():
    ok, _ = vhost._validate_vhost_hostname("challenges.site.com:8008", allow_port=True)
    assert ok
    rej, err = vhost._validate_vhost_hostname("challenges.site.com:8008", allow_port=False)
    assert not rej and "port" in err.lower(), "default must still reject ports"


def test_validator_rejects_bad_port():
    bad, _ = vhost._validate_vhost_hostname("challenges.site.com:99999", allow_port=True)
    assert not bad
    bad2, _ = vhost._validate_vhost_hostname("challenges.site.com:abc", allow_port=True)
    assert not bad2
    bad3, _ = vhost._validate_vhost_hostname(":8008", allow_port=True)
    assert not bad3  # no host part


def test_vhost_set_accepts_hostport_when_aware(monkeypatch):
    _set_port_aware(True)
    monkeypatch.setattr(vhost, "_save_vhosts_file", lambda: None)
    monkeypatch.setattr(vhost, "_assert_upstream_public", lambda *a, **k: None)
    ok, err = vhost.vhost_set("challenges.site.com:8008", {"UPSTREAM": "https://example.com"})
    assert ok, err
    assert "challenges.site.com:8008" in vhost.VHOSTS


def test_vhost_set_rejects_hostport_when_off(monkeypatch):
    _set_port_aware(False)
    monkeypatch.setattr(vhost, "_save_vhosts_file", lambda: None)
    ok, err = vhost.vhost_set("challenges.site.com:8008", {"UPSTREAM": "https://example.com"})
    assert not ok and "port" in err.lower()


# ── 1.9.8: default ports (:80 / :443) normalised to portless ───────────────────

def test_default_port_inbound_matches_portless_entry():
    """A browser/Cloudflare Host of `site.com:443` (or :80) must match a portless
    `site.com` vhost — the default port is treated as no port."""
    _set_port_aware(True)
    vhost.VHOSTS["site.com"] = {"UPSTREAM": "https://portless.example"}
    for ported in ("site.com:443", "site.com:80"):
        vhost.set_vhost(ported)
        assert vhost.current_vhost_host() == "site.com", f"{ported} must normalise to portless"
        assert vhost.vc("UPSTREAM") == "https://portless.example"


def test_default_port_config_key_stored_portless(monkeypatch):
    """Configuring `site.com:443` stores it under the portless key, so the
    `Host: site.com` that real traffic sends matches it."""
    _set_port_aware(True)
    monkeypatch.setattr(vhost, "_save_vhosts_file", lambda: None)
    monkeypatch.setattr(vhost, "_assert_upstream_public", lambda *a, **k: None)
    ok, err = vhost.vhost_set("site.com:443", {"UPSTREAM": "https://example.com"})
    assert ok, err
    assert "site.com" in vhost.VHOSTS and "site.com:443" not in vhost.VHOSTS
    vhost.set_vhost("site.com")          # default-port traffic, no port in Host
    assert vhost.vc("UPSTREAM") == "https://example.com"


def test_default_port_delete_matches_normalised_key(monkeypatch):
    _set_port_aware(True)
    monkeypatch.setattr(vhost, "_save_vhosts_file", lambda: None)
    monkeypatch.setattr(vhost, "_assert_upstream_public", lambda *a, **k: None)
    vhost.vhost_set("site.com:443", {"UPSTREAM": "https://example.com"})
    assert vhost.vhost_delete("site.com") is True      # delete by portless name
    assert "site.com" not in vhost.VHOSTS


def test_nondefault_port_not_normalised():
    """Regression guard: only :80/:443 collapse — :8008 stays a distinct vhost."""
    _set_port_aware(True)
    assert vhost._strip_default_port("site.com:8008") == "site.com:8008"
    assert vhost._strip_default_port("site.com:443") == "site.com"
    assert vhost._strip_default_port("site.com:80") == "site.com"
    assert vhost._strip_default_port("site.com") == "site.com"
    vhost.VHOSTS["site.com:8008"] = {"UPSTREAM": "https://eight.example"}
    vhost.set_vhost("site.com:8008")
    assert vhost.current_vhost_host() == "site.com:8008"
    assert vhost.vc("UPSTREAM") == "https://eight.example"
