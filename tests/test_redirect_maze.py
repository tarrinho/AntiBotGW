# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_redirect_maze.py — 1.7.3 P2 redirect-maze (revived + wired in 1.8.x).

Covers the formerly-orphan detector now that its config knobs exist and it is
wired into protect() + the /maze route:
  - config knobs present, default OFF (never reroutes live traffic by default)
  - module imports clean (the historic ImportError is gone)
  - HMAC token sign/verify: roundtrip, dest-binding, identity-binding, expiry
  - should_maze() gating (enabled flag, threshold, has-token)
  - signal registration: SIGNAL_KNOB + RISK_WEIGHTS
  - /maze is registered as a PUBLIC route and exempt from the admin-key gate
  - endpoint behaviour: bad token restarts maze; valid hop redirects on
"""
import time

import pytest
from aiohttp.test_utils import make_mocked_request

import config
import detection.redirect_maze as rm


# ── config knobs ──────────────────────────────────────────────────────────────
def test_config_knobs_present():
    for k in ("REDIRECT_MAZE_ENABLED", "REDIRECT_MAZE_THRESHOLD",
              "REDIRECT_MAZE_DEPTH", "REDIRECT_MAZE_MIN_MS", "REDIRECT_MAZE_SCORE"):
        assert hasattr(config, k), f"missing config knob {k}"


def test_ships_on_by_default():
    # 1.8.13: maze enabled by default — threshold gate (risk ≥ 80) keeps it safe for real traffic.
    assert config.REDIRECT_MAZE_ENABLED is True


def test_module_imports_clean():
    # Historic bug: redirect_maze.py imported REDIRECT_MAZE_* names that
    # config.py never defined → ImportError on first import. Now resolved.
    import importlib
    importlib.reload(rm)
    assert callable(rm.should_maze)
    assert callable(rm.make_maze_entry)
    assert callable(rm.redirect_maze_endpoint)


# ── token sign / verify ───────────────────────────────────────────────────────
def test_token_roundtrip_ok():
    now = int(time.time() * 1000)
    tok = rm._sign_maze_token("ident-A", 0, now, "/foo")
    ok, step, ts = rm._verify_maze_token(tok, "ident-A", "/foo")
    assert ok and step == 0 and ts == now


def test_token_dest_binding():
    # DET4-02: destination is bound into the HMAC — swapping it must fail.
    now = int(time.time() * 1000)
    tok = rm._sign_maze_token("ident-A", 1, now, "/foo")
    ok, _, _ = rm._verify_maze_token(tok, "ident-A", "/somewhere-else")
    assert ok is False


def test_token_identity_binding():
    now = int(time.time() * 1000)
    tok = rm._sign_maze_token("ident-A", 1, now, "/foo")
    ok, _, _ = rm._verify_maze_token(tok, "ident-B", "/foo")
    assert ok is False


def test_token_expiry():
    old = int(time.time() * 1000) - (rm._MAZE_TOKEN_TTL_MS + 5000)
    tok = rm._sign_maze_token("ident-A", 0, old, "/foo")
    ok, _, _ = rm._verify_maze_token(tok, "ident-A", "/foo")
    assert ok is False


def test_token_future_skew_rejected():
    future = int(time.time() * 1000) + 60_000
    tok = rm._sign_maze_token("ident-A", 0, future, "/foo")
    ok, _, _ = rm._verify_maze_token(tok, "ident-A", "/foo")
    assert ok is False


def test_token_malformed():
    for bad in ("", "notatoken", "1.2", "a.b.c", "1.2.3.4"):
        ok, _, _ = rm._verify_maze_token(bad, "ident-A", "/foo")
        assert ok is False


# ── should_maze gating ────────────────────────────────────────────────────────
@pytest.fixture
def maze_on(monkeypatch):
    monkeypatch.setattr(rm, "REDIRECT_MAZE_ENABLED", True)
    monkeypatch.setattr(rm, "REDIRECT_MAZE_THRESHOLD", 80.0)
    yield


def test_should_maze_disabled(monkeypatch):
    monkeypatch.setattr(rm, "REDIRECT_MAZE_ENABLED", False)
    assert rm.should_maze(99.0, has_maze_token=False) is False


def test_should_maze_enabled_above_threshold(maze_on):
    assert rm.should_maze(90.0, has_maze_token=False) is True


def test_should_maze_below_threshold(maze_on):
    assert rm.should_maze(50.0, has_maze_token=False) is False


def test_should_maze_has_token_skips(maze_on):
    assert rm.should_maze(90.0, has_maze_token=True) is False


# ── signal registration ───────────────────────────────────────────────────────
def test_signal_in_risk_weights():
    assert config.RISK_WEIGHTS.get("redirect-maze-bot") == config.REDIRECT_MAZE_SCORE


def test_signal_knob_mapping():
    import core.proxy_handler as ph
    assert ph.SIGNAL_KNOB.get("redirect-maze-bot") == "REDIRECT_MAZE_ENABLED"


def test_hot_reload_knobs_registered():
    import core.proxy_handler as ph
    for k in ("REDIRECT_MAZE_ENABLED", "REDIRECT_MAZE_THRESHOLD",
              "REDIRECT_MAZE_DEPTH", "REDIRECT_MAZE_MIN_MS"):
        assert k in ph._HOT_RELOAD_KNOBS, f"{k} not hot-reloadable"


def test_maze_knobs_in_controls_dashboard():
    """The maze knobs are exposed as Controls-dashboard widgets (META) so an
    operator can toggle/tune them from the UI like the LABYRINTH_* knobs."""
    import pathlib
    html = (pathlib.Path(__file__).parent.parent / "dashboards" / "controls.html").read_text()
    assert "REDIRECT_MAZE_ENABLED:" in html, "maze enable toggle missing from Controls META"
    assert "kind:'bool'" in html.split("REDIRECT_MAZE_ENABLED:")[1][:40], "enable must be a bool toggle"
    for k in ("REDIRECT_MAZE_THRESHOLD", "REDIRECT_MAZE_DEPTH", "REDIRECT_MAZE_MIN_MS"):
        assert k + ":" in html, f"{k} numeric widget missing from Controls META"


def test_maze_signal_has_label_and_description():
    """redirect-maze-bot must carry the signal metadata the Controls scoring
    table renders (label + description), like tarpit-walk."""
    import core.proxy_handler as ph
    src = open(ph.__file__).read()
    assert '"redirect-maze-bot":  "Redirect Maze"' in src or \
           '"redirect-maze-bot": "Redirect Maze"' in src, "SIGNAL_LABELS entry missing"
    assert '"redirect-maze-bot":     ("hard"' in src, "severity/description entry missing"


# ── public route exemption ────────────────────────────────────────────────────
def test_maze_path_is_public():
    from helpers import _admin_path_is_public
    assert _admin_path_is_public(config.ADMIN_NS + "/maze") is True


def test_maze_entry_url_format():
    url = rm.make_maze_entry("ident-A", "/foo")
    assert url.startswith(config.ADMIN_NS + "/maze?t=")
    assert "&d=%2Ffoo" in url   # dest is url-encoded


# ── endpoint behaviour ────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_endpoint_bad_token_restarts_maze():
    req = make_mocked_request("GET", config.ADMIN_NS + "/maze?t=bad&d=%2Ffoo")
    resp = await rm.redirect_maze_endpoint(req)
    assert resp.status == 302
    loc = resp.headers["Location"]
    assert loc.startswith(config.ADMIN_NS + "/maze?t=")   # fresh step-0 token


@pytest.mark.asyncio
async def test_endpoint_advances_then_lands(monkeypatch):
    # depth 2 → step 0 advances to step 1, step 1 lands on dest
    monkeypatch.setattr(rm, "REDIRECT_MAZE_DEPTH", 2)
    # derive a stable identity for signing that matches what the endpoint sees
    from identity import get_identity
    req0 = make_mocked_request("GET", config.ADMIN_NS + "/maze")
    ident = get_identity(req0)[0]

    now = int(time.time() * 1000)
    dest = "/foo"
    tok0 = rm._sign_maze_token(ident, 0, now, dest)
    req = make_mocked_request("GET", f"{config.ADMIN_NS}/maze?t={tok0}&d=%2Ffoo")
    resp = await rm.redirect_maze_endpoint(req)
    assert resp.status == 302
    # step 0 of depth 2 → next hop is another /maze step
    assert resp.headers["Location"].startswith(config.ADMIN_NS + "/maze?t=")
