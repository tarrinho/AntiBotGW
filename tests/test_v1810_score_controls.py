"""1.8.10 — score breakdown shows the controls governing an identity's score.

A new "Controls governing this score" area in agents.html's buildScoreHtml maps
each active signal/block reason to its control knob (mirror of
core/proxy_handler.py SIGNAL_KNOB) and shows the live ON/OFF state with a link to
the Controls page.
"""
import os
import re
import pathlib
import importlib

AGENTS = (pathlib.Path(__file__).resolve().parent.parent /
          "dashboards" / "agents.html").read_text(encoding="utf-8")


def _signal_knob_js():
    m = re.search(r"const SIGNAL_KNOB_JS\s*=\s*\{(.*?)\n\};", AGENTS, re.S)
    assert m, "SIGNAL_KNOB_JS not found in agents.html"
    return dict(re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', m.group(1)))


def test_signal_knob_js_matches_backend():
    """The dashboard mirror must match the backend SIGNAL_KNOB exactly, so the
    breakdown never shows a wrong/missing control for a signal."""
    os.environ.setdefault("UPSTREAM", "https://example.com")
    p = importlib.import_module("core.proxy_handler")
    # Only signals WITH a toggleable knob belong in the dashboard map; None means
    # always-on / no control (e.g. internal-probe, banned) — excluded by design.
    backend = {k: v for k, v in p.SIGNAL_KNOB.items() if v is not None}
    js = _signal_knob_js()
    missing = {k: v for k, v in backend.items() if js.get(k) != v}
    extra = {k: v for k, v in js.items() if k not in backend}
    assert not missing, f"SIGNAL_KNOB_JS out of sync — missing/wrong: {missing}"
    assert not extra, f"SIGNAL_KNOB_JS has stale entries not in backend: {extra}"


def test_controls_section_helpers_present():
    assert "function _gwControlsSection(d)" in AGENTS
    assert "async function _gwLoadKnobState()" in AGENTS
    assert "window._gwKnobState" in AGENTS


def test_breakdown_renders_controls_area():
    assert 'id="gw-score-controls"' in AGENTS
    assert "_gwControlsSection(d)" in AGENTS
    assert "Controls governing this score" in AGENTS


def test_controls_area_uses_live_state_and_links():
    sec = re.search(r"function _gwControlsSection\(d\)\{.*?\n\}", AGENTS, re.S).group(0)
    # reads cached knob state for ON/OFF
    assert "window._gwKnobState" in sec
    assert "'ON'" in sec and "'OFF'" in sec
    # links to the Controls page
    assert "/antibot-appsec-gateway/secured/controls" in sec
    # collects reasons from BOTH block + risk breakdowns
    assert "blocks_breakdown" in sec and "risk_breakdown" in sec


def test_score_popover_refreshes_control_state():
    """Opening the score popover must re-fetch config and re-render the area."""
    assert re.search(r"kind === 'score'[\s\S]*?_gwLoadKnobState\(\)[\s\S]*?gw-score-controls", AGENTS), (
        "openPopover must refresh knob state and re-render gw-score-controls for the score popover"
    )
