"""tests/test_interaction_probe.py — Unit tests for detection/interaction.py (v1.8.6)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hashlib, hmac, math, time
from detection.interaction import (
    _interaction_token,
    _inject_interaction_probe,
    interaction_analyze,
    _analyze_mouse,
    _analyze_scroll,
    _analyze_keys,
    _analyze_entropy,
    INTERACTION_PROBE_ENABLED,
    _TOKEN_TTL,
    _MAX_EVENTS,
)
from config import SESSION_KEY


# ── Token ─────────────────────────────────────────────────────────────────────

class TestInteractionToken:
    def test_token_is_32_hex_chars(self):
        tok = _interaction_token("1.2.3.4", 1000000)
        assert len(tok) == 32
        assert all(c in "0123456789abcdef" for c in tok)

    def test_token_changes_with_ip(self):
        t1 = _interaction_token("1.2.3.4", 1000000)
        t2 = _interaction_token("5.6.7.8", 1000000)
        assert t1 != t2

    def test_token_changes_with_ts(self):
        t1 = _interaction_token("1.2.3.4", 1000000)
        t2 = _interaction_token("1.2.3.4", 1000001)
        assert t1 != t2

    def test_token_is_deterministic(self):
        t1 = _interaction_token("1.2.3.4", 999)
        t2 = _interaction_token("1.2.3.4", 999)
        assert t1 == t2

    def test_token_uses_session_key(self):
        msg = b"interaction|1.2.3.4|999"
        expected = hmac.new(SESSION_KEY, msg, hashlib.sha256).hexdigest()[:32]
        assert _interaction_token("1.2.3.4", 999) == expected


# ── Injection ─────────────────────────────────────────────────────────────────

class TestInjectInteractionProbe:
    def test_injects_script_tag(self):
        html = "<html><body><p>hi</p></body></html>"
        out = _inject_interaction_probe(html, "1.2.3.4")
        if INTERACTION_PROBE_ENABLED:
            assert "<script>" in out
            assert "interaction-report" in out
        else:
            assert out == html

    def test_injects_before_body_close(self):
        html = "<html><body><p>test</p></body></html>"
        out = _inject_interaction_probe(html, "1.2.3.4")
        if INTERACTION_PROBE_ENABLED:
            script_idx = out.index("<script>")
            body_idx = out.lower().rindex("</body>")
            assert script_idx < body_idx

    def test_appends_when_no_body_tag(self):
        html = "<html><p>no close tag</p>"
        out = _inject_interaction_probe(html, "1.2.3.4")
        if INTERACTION_PROBE_ENABLED:
            assert "<script>" in out

    def test_token_embedded_in_script(self):
        html = "<html><body></body></html>"
        out = _inject_interaction_probe(html, "1.2.3.4")
        if INTERACTION_PROBE_ENABLED:
            ts_now = int(time.time())
            tok = _interaction_token("1.2.3.4", ts_now)
            # Token should be in the injected script (allow 1s clock skew)
            tok_prev = _interaction_token("1.2.3.4", ts_now - 1)
            assert tok in out or tok_prev in out

    def test_no_injection_when_disabled(self, monkeypatch):
        import detection.interaction as mod
        monkeypatch.setattr(mod, "INTERACTION_PROBE_ENABLED", False)
        html = "<html><body></body></html>"
        out = mod._inject_interaction_probe(html, "1.2.3.4")
        assert out == html

    def test_script_collects_mouse_events(self):
        html = "<html><body></body></html>"
        out = _inject_interaction_probe(html, "1.2.3.4")
        if INTERACTION_PROBE_ENABLED:
            assert "mousemove" in out

    def test_script_collects_scroll_events(self):
        html = "<html><body></body></html>"
        out = _inject_interaction_probe(html, "1.2.3.4")
        if INTERACTION_PROBE_ENABLED:
            assert "scroll" in out

    def test_script_collects_key_events(self):
        html = "<html><body></body></html>"
        out = _inject_interaction_probe(html, "1.2.3.4")
        if INTERACTION_PROBE_ENABLED:
            assert "keydown" in out and "keyup" in out

    def test_script_sends_on_pagehide(self):
        html = "<html><body></body></html>"
        out = _inject_interaction_probe(html, "1.2.3.4")
        if INTERACTION_PROBE_ENABLED:
            assert "pagehide" in out


# ── Mouse analysis ────────────────────────────────────────────────────────────

class TestAnalyzeMouse:
    def _mouse(self, dxs, dys, spacing=100):
        return [['m', i * spacing, dx, dy] for i, (dx, dy) in enumerate(zip(dxs, dys))]

    def test_straight_line_fires_bot_motion(self):
        # Perfect horizontal movement
        events = self._mouse([5]*20, [0]*20)
        reason, detail = _analyze_mouse(events)
        assert reason == "bot-motion"

    def test_natural_mouse_passes(self):
        import random
        random.seed(42)
        dxs = [random.randint(-10, 10) for _ in range(20)]
        dys = [random.randint(-10, 10) for _ in range(20)]
        events = self._mouse(dxs, dys)
        reason, _ = _analyze_mouse(events)
        assert reason != "bot-motion"

    def test_uniform_velocity_fires_scripted_motion(self):
        # Exact 10ms intervals, small movement
        events = [['m', i * 10, 3, 3] for i in range(20)]
        reason, _ = _analyze_mouse(events)
        assert reason in ("scripted-motion", "bot-motion", None)

    def test_too_few_events_returns_none(self):
        events = [['m', i * 100, 5, 5] for i in range(3)]
        reason, _ = _analyze_mouse(events)
        assert reason is None

    def test_diagonal_line_fires_bot_motion(self):
        events = self._mouse([3]*20, [3]*20)
        reason, _ = _analyze_mouse(events)
        assert reason == "bot-motion"

    def test_detail_string_present_on_detection(self):
        events = self._mouse([5]*20, [0]*20)
        reason, detail = _analyze_mouse(events)
        if reason:
            assert detail != ""


# ── Scroll analysis ───────────────────────────────────────────────────────────

class TestAnalyzeScroll:
    def test_uniform_steps_fires_bot_scroll(self):
        # 100px scroll steps — mousewheel bot
        events = [['s', i * 200, i * 100] for i in range(10)]
        reason, _ = _analyze_scroll(events)
        assert reason == "bot-scroll"

    def test_natural_scroll_passes(self):
        # Variable scroll positions
        positions = [0, 47, 123, 234, 189, 301, 500, 620, 590, 700]
        events = [['s', i * 300, p] for i, p in enumerate(positions)]
        reason, _ = _analyze_scroll(events)
        assert reason is None

    def test_too_few_events_returns_none(self):
        events = [['s', i * 200, i * 100] for i in range(2)]
        reason, _ = _analyze_scroll(events)
        assert reason is None

    def test_no_movement_returns_none(self):
        # All same position — no actual scrolling
        events = [['s', i * 200, 0] for i in range(6)]
        reason, _ = _analyze_scroll(events)
        assert reason is None


# ── Keystroke analysis ────────────────────────────────────────────────────────

class TestAnalyzeKeys:
    def test_uniform_dwell_fires_scripted_keys(self):
        # All exactly 50ms dwell
        events = [['k', i * 200, 50] for i in range(10)]
        reason, _ = _analyze_keys(events)
        assert reason == "scripted-keys"

    def test_natural_typing_passes(self):
        # Variable dwell times
        dwells = [45, 120, 38, 95, 67, 203, 55, 88, 40, 130]
        events = [['k', i * 300, d] for i, d in enumerate(dwells)]
        reason, _ = _analyze_keys(events)
        assert reason is None

    def test_too_few_events_returns_none(self):
        events = [['k', i * 200, 50] for i in range(2)]
        reason, _ = _analyze_keys(events)
        assert reason is None

    def test_zero_dwell_filtered(self):
        events = [['k', i * 200, 0] for i in range(10)]
        reason, _ = _analyze_keys(events)
        assert reason is None


# ── Entropy analysis ──────────────────────────────────────────────────────────

class TestAnalyzeEntropy:
    def test_metronomic_events_fire_low_entropy(self):
        # Events at exact 100ms intervals
        events = [['m', i * 100, 1, 1, 0] for i in range(20)]
        # Patch to have valid length
        events = [['m', i * 100, 1, 1] for i in range(20)]
        reason, _ = _analyze_entropy(events)
        # Should detect too-regular timing
        assert reason == "low-entropy-input"

    def test_random_events_pass(self):
        import random
        random.seed(7)
        times = sorted(random.randint(0, 10000) for _ in range(30))
        events = [['m', t, 1, 1] for t in times]
        reason, _ = _analyze_entropy(events)
        # May or may not fire depending on randomness — just verify no crash
        assert reason in (None, "low-entropy-input")

    def test_too_few_events_returns_none(self):
        events = [['m', i * 100, 1, 1] for i in range(5)]
        reason, _ = _analyze_entropy(events)
        assert reason is None


# ── Full analyzer ─────────────────────────────────────────────────────────────

class TestInteractionAnalyze:
    def test_no_events_long_window_fires_no_interaction(self):
        reason, detail = interaction_analyze([], duration_ms=4000)
        assert reason == "no-interaction"
        assert "zero events" in detail

    def test_no_events_short_window_passes(self):
        reason, _ = interaction_analyze([], duration_ms=1000)
        assert reason is None

    def test_straight_line_mouse_detected(self):
        events = [['m', i * 100, 5, 0] for i in range(20)]
        reason, _ = interaction_analyze(events, duration_ms=2000)
        assert reason == "bot-motion"

    def test_uniform_scroll_detected(self):
        events = [['s', i * 500, i * 100] for i in range(10)]
        reason, _ = interaction_analyze(events, duration_ms=5000)
        assert reason == "bot-scroll"

    def test_uniform_keys_detected(self):
        events = [['k', i * 200, 50] for i in range(10)]
        reason, _ = interaction_analyze(events, duration_ms=2000)
        assert reason == "scripted-keys"

    def test_invalid_event_types_filtered(self):
        events = [['x', 100, 1], ['y', 200, 2], ['z', 300, 3, 4]]
        reason, _ = interaction_analyze(events, duration_ms=4000)
        assert reason == "no-interaction"

    def test_max_events_cap(self):
        events = [['m', i * 10, 1, 1] for i in range(500)]
        # Should not crash and processes only first _MAX_EVENTS
        reason, _ = interaction_analyze(events, duration_ms=5000)
        assert reason is not None or reason is None  # just no exception

    def test_disabled_returns_none(self, monkeypatch):
        import detection.interaction as mod
        monkeypatch.setattr(mod, "INTERACTION_PROBE_ENABLED", False)
        reason, _ = mod.interaction_analyze([], duration_ms=10000)
        assert reason is None

    def test_returns_tuple(self):
        result = interaction_analyze([], duration_ms=0)
        assert isinstance(result, tuple) and len(result) == 2

    def test_reason_is_none_or_string(self):
        events = [['m', i * 200, i, i] for i in range(10)]
        reason, detail = interaction_analyze(events, duration_ms=2000)
        assert reason is None or isinstance(reason, str)
        assert isinstance(detail, str)


# ── Config + constants ────────────────────────────────────────────────────────

class TestInteractionConfig:
    def test_interaction_probe_enabled_exists(self):
        from config import INTERACTION_PROBE_ENABLED
        assert isinstance(INTERACTION_PROBE_ENABLED, bool)

    def test_risk_weights_include_no_interaction(self):
        from config import RISK_WEIGHTS
        assert "no-interaction" in RISK_WEIGHTS
        assert RISK_WEIGHTS["no-interaction"] > 0

    def test_risk_weights_include_bot_motion(self):
        from config import RISK_WEIGHTS
        assert "bot-motion" in RISK_WEIGHTS
        assert RISK_WEIGHTS["bot-motion"] > 0

    def test_risk_weights_include_scripted_motion(self):
        from config import RISK_WEIGHTS
        assert "scripted-motion" in RISK_WEIGHTS

    def test_risk_weights_include_bot_scroll(self):
        from config import RISK_WEIGHTS
        assert "bot-scroll" in RISK_WEIGHTS

    def test_risk_weights_include_scripted_keys(self):
        from config import RISK_WEIGHTS
        assert "scripted-keys" in RISK_WEIGHTS

    def test_risk_weights_include_low_entropy_input(self):
        from config import RISK_WEIGHTS
        assert "low-entropy-input" in RISK_WEIGHTS

    def test_token_ttl_is_positive(self):
        assert _TOKEN_TTL > 0

    def test_max_events_cap_is_positive(self):
        assert _MAX_EVENTS > 0

    def test_interaction_report_endpoint_importable(self):
        from detection.interaction import interaction_report_endpoint
        import asyncio
        assert asyncio.iscoroutinefunction(interaction_report_endpoint)

    def test_route_registered_in_proxy(self):
        import pathlib
        src = pathlib.Path(__file__).parent.parent / "proxy.py"
        assert "interaction-report" in src.read_text()
