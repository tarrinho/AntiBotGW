"""
tests/test_v1814_ban_duration_dynamic.py — guard the
operator-configurable ban durations in the dashboard.

Pre-fix: the Banned / Really Banned buttons in agents.html + main.html
hardcoded `data-secs="86400"` / `data-secs="2592000"` and the
'really-banned' badge classifier compared against the literal `86400`.
Operator changes to HOSTILE_BAN_SECS / REALLY_BAN_SECS in the Thresholds
card had no effect — clicks still applied the historical defaults.

Fix: a window-level cache `_gwBanCfg = {banSecs, reallyBanSecs}` is
populated from /secured/config (HOSTILE_BAN_SECS + REALLY_BAN_SECS) at
page load + every 60 s. The buttons + classifier read from the cache so
the dashboard reflects the operator's configuration.
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
AGENTS = os.path.join(_REPO, "dashboards", "agents.html")
MAIN = os.path.join(_REPO, "dashboards", "main.html")


def _src(path):
    return open(path, encoding="utf-8").read()


# ── Cache + loader are declared in both pages ────────────────────────────

def test_agents_declares_ban_cfg_cache():
    src = _src(AGENTS)
    assert "window._gwBanCfg" in src, (
        "agents.html must declare a window._gwBanCfg cache for ban durations"
    )
    assert "banSecs" in src and "reallyBanSecs" in src, (
        "cache must carry banSecs + reallyBanSecs fields"
    )


def test_agents_declares_ban_cfg_loader():
    src = _src(AGENTS)
    assert "_gwLoadBanCfg" in src, (
        "agents.html must define _gwLoadBanCfg() to populate the cache "
        "from /secured/config"
    )
    # Loader must fetch /secured/config and parse HOSTILE_BAN_SECS + REALLY_BAN_SECS.
    m = re.search(r"async\s+function\s+_gwLoadBanCfg\b.*?\n\}",
                  src, re.DOTALL)
    assert m, "_gwLoadBanCfg must be an async function"
    body = m.group(0)
    assert "/secured/config" in body, (
        "loader must hit /secured/config"
    )
    assert "HOSTILE_BAN_SECS" in body and "REALLY_BAN_SECS" in body, (
        "loader must read HOSTILE_BAN_SECS + REALLY_BAN_SECS from state"
    )


def test_main_declares_ban_cfg_cache_and_loader():
    src = _src(MAIN)
    assert "window._gwBanCfg" in src and "_gwLoadBanCfg" in src, (
        "main.html must declare the same _gwBanCfg cache + loader as agents.html"
    )


# ── Loader is invoked before first render + on a refresh timer ──────────

def test_agents_warms_cache_before_first_tick():
    src = _src(AGENTS)
    assert re.search(
        r"_gwLoadBanCfg\(\)\.then\(\s*\(\s*\)?\s*=>\s*\{?\s*tick\(\)",
        src,
    ), (
        "agents.html must warm _gwLoadBanCfg() BEFORE the initial tick() so "
        "the first render shows operator-configured durations"
    )


def test_main_warms_cache_before_first_tick():
    src = _src(MAIN)
    assert re.search(r"_gwLoadBanCfg\(\)\.then\(\s*\(\s*\)?\s*=>\s*tick\(\)",
                     src), (
        "main.html must warm _gwLoadBanCfg() before the initial tick()"
    )


def test_agents_refreshes_cache_on_timer():
    src = _src(AGENTS)
    assert re.search(
        r"setInterval\s*\(\s*_gwLoadBanCfg\s*,\s*60000\s*\)", src
    ), (
        "agents.html must refresh _gwBanCfg every 60 s so an in-tab "
        "Thresholds change picks up without a full page reload"
    )


def test_main_refreshes_cache_on_timer():
    src = _src(MAIN)
    assert re.search(
        r"setInterval\s*\(\s*_gwLoadBanCfg\s*,\s*60000\s*\)", src
    ), "main.html must refresh _gwBanCfg every 60 s"


# ── Hardcoded button durations are gone ─────────────────────────────────

def test_no_hardcoded_data_secs_86400():
    """No surviving `data-secs="86400"` literal — the Banned button must
    interpolate the cached value."""
    for path in (AGENTS, MAIN):
        src = _src(path)
        assert 'data-secs="86400"' not in src, (
            f"{os.path.basename(path)} must not hardcode data-secs=\"86400\" "
            "— interpolate window._gwBanCfg.banSecs instead"
        )


def test_no_hardcoded_data_secs_2592000():
    """No surviving `data-secs="2592000"` literal — Really Banned button
    must interpolate the cached value."""
    for path in (AGENTS, MAIN):
        src = _src(path)
        assert 'data-secs="2592000"' not in src, (
            f"{os.path.basename(path)} must not hardcode data-secs=\"2592000\" "
            "— interpolate window._gwBanCfg.reallyBanSecs instead"
        )


# ── 'really-banned' classifier reads the cache ──────────────────────────

def test_agents_really_banned_threshold_uses_cache():
    """Every `> 86400` comparison in ban-state classification must be
    replaced with the cached HOSTILE_BAN_SECS."""
    src = _src(AGENTS)
    # No banned-comparison against literal 86400 should remain.
    assert not re.search(
        r"banned_secs\s*>\s*86400|_bs\s*>\s*86400|bsec\s*>\s*86400|b\s*>\s*86400(?!\d)",
        src,
    ), (
        "agents.html must classify 'really-banned' against the live "
        "HOSTILE_BAN_SECS, not the literal 86400"
    )
    # And the cache reference must actually appear in the classifier paths.
    assert "_gwBanCfg.banSecs" in src, (
        "agents.html classifier must reference window._gwBanCfg.banSecs"
    )


def test_main_really_banned_threshold_uses_cache():
    src = _src(MAIN)
    assert not re.search(
        r"banned_secs\s*>\s*86400|_bsec\s*>\s*86400|_mbs\s*>\s*86400|bsec\s*>\s*86400",
        src,
    ), (
        "main.html must classify 'really-banned' against the live "
        "HOSTILE_BAN_SECS, not the literal 86400"
    )
    assert "_gwBanCfg.banSecs" in src, (
        "main.html classifier must reference window._gwBanCfg.banSecs"
    )


# ── Fallback safety ─────────────────────────────────────────────────────

def test_cache_has_defaults_for_pre_load_render():
    """If the first render fires before the fetch resolves, the cache
    must still expose sensible defaults — buttons can't ship `secs=undefined`."""
    for path in (AGENTS, MAIN):
        src = _src(path)
        # The declaration must include both numeric fallbacks.
        m = re.search(r"window\._gwBanCfg\s*=\s*window\._gwBanCfg\s*\|\|\s*\{[^}]*\}",
                      src, re.DOTALL)
        assert m, (
            f"{os.path.basename(path)} cache declaration must include "
            "fallback defaults"
        )
        decl = m.group(0)
        assert "86400" in decl, "cache must default banSecs to 86400"
        assert "2592000" in decl, "cache must default reallyBanSecs to 2592000"
