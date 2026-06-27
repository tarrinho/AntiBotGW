# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1815_qa_overrides.py — extended QA for per-vhost risk weight overrides (1.8.14 M-1).

Test types covered:
  P — parametrized: override weight values (0=suppress, 1=min, 200=high, global default)
  B — boundary: zero-weight suppresses, max int, non-existent signal, empty overrides
  E — edge cases: override keys with spaces, numeric string keys, partial override
  C — concurrent: ContextVar isolation per asyncio Task
  N — negative: no override falls back to RISK_WEIGHTS global
  I — integration: ContextVar set → scoring function picks up correct weight
  V — validation: coercer rejects/normalises invalid override entries
"""
from __future__ import annotations

import asyncio
import contextvars
import os

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")
_REPO = os.path.join(os.path.dirname(__file__), "..")


# ─── P: parametrized weight values ───────────────────────────────────────────

class TestOverridesWeightParametrized:

    def _weight_for(self, reason: str, overrides: dict | None) -> int:
        """Read the effective weight via the same logic used in scoring.py."""
        from config import RISK_WEIGHTS
        from scoring import _vhost_risk_ctx
        token = _vhost_risk_ctx.set(overrides)
        try:
            _overrides = _vhost_risk_ctx.get()
            return (
                _overrides.get(reason, RISK_WEIGHTS.get(reason, 0))
                if _overrides
                else RISK_WEIGHTS.get(reason, 0)
            )
        finally:
            _vhost_risk_ctx.reset(token)

    @pytest.mark.parametrize("override_weight,reason,expected", [
        # Suppress signal to 0
        (0,   "ua-empty",           0),
        # Minimum non-zero override
        (1,   "ua-empty",           1),
        # Override matches global
        (10,  "ua-empty",           10),
        # Very high override
        (200, "ua-empty",           200),
        # Override for unknown signal
        (50,  "totally-fake-signal", 50),
    ])
    def test_weight_from_override(self, override_weight, reason, expected):
        actual = self._weight_for(reason, {reason: override_weight})
        assert actual == expected

    @pytest.mark.parametrize("reason", [
        "ua-empty",
        "ua-blocked",
        "behavior",
        "ua-non-browser",
        "js-mobile-hint-mismatch",
        "js-fetch-impossible",
    ])
    def test_no_override_uses_global(self, reason):
        """No override → RISK_WEIGHTS global value used."""
        from config import RISK_WEIGHTS
        actual = self._weight_for(reason, None)
        assert actual == RISK_WEIGHTS.get(reason, 0)


# ─── B: boundary conditions ───────────────────────────────────────────────────

class TestOverridesBoundary:

    def _coerce(self, v):
        from vhost import _VHOST_COERCE
        return _VHOST_COERCE["RISK_OVERRIDES"](v)

    def test_zero_weight_coerced(self):
        """Weight 0 is valid and suppresses the signal."""
        result = self._coerce({"ua-empty": 0})
        assert result == {"ua-empty": 0}

    def test_max_int_weight_coerced(self):
        """Very large weight is valid (no upper bound enforced)."""
        result = self._coerce({"ua-empty": 999999})
        assert result["ua-empty"] == 999999

    def test_negative_weight_excluded(self):
        """Negative weight is invalid — entry must be excluded."""
        result = self._coerce({"ua-empty": -1, "ua-blocked": 10})
        assert "ua-empty" not in result
        assert result.get("ua-blocked") == 10

    def test_empty_dict_returns_empty(self):
        assert self._coerce({}) == {}

    def test_none_input_returns_empty(self):
        assert self._coerce(None) == {}

    def test_override_for_unknown_signal_allowed(self):
        """Unknown signal names are allowed (future signals)."""
        result = self._coerce({"future-signal-x": 99})
        assert result.get("future-signal-x") == 99

    def test_partial_override_leaves_others_at_global(self):
        """Overriding one signal doesn't affect others."""
        from config import RISK_WEIGHTS
        from scoring import _vhost_risk_ctx
        overrides = {"ua-empty": 1}   # only override ua-empty
        token = _vhost_risk_ctx.set(overrides)
        try:
            _o = _vhost_risk_ctx.get()
            # ua-empty → overridden to 1
            w_overridden = _o.get("ua-empty", RISK_WEIGHTS.get("ua-empty", 0))
            # ua-blocked → falls through to global
            w_global = _o.get("ua-blocked", RISK_WEIGHTS.get("ua-blocked", 0))
            assert w_overridden == 1
            assert w_global == RISK_WEIGHTS.get("ua-blocked", 0)
        finally:
            _vhost_risk_ctx.reset(token)


# ─── E: edge cases ────────────────────────────────────────────────────────────

class TestOverridesEdgeCases:

    def _coerce(self, v):
        from vhost import _VHOST_COERCE
        return _VHOST_COERCE["RISK_OVERRIDES"](v)

    def test_string_int_values_coerced(self):
        """String integer values must be coerced to int."""
        result = self._coerce({"ua-empty": "10", "ua-blocked": "50"})
        assert result == {"ua-empty": 10, "ua-blocked": 50}

    def test_string_zero_weight(self):
        result = self._coerce({"ua-empty": "0"})
        assert result == {"ua-empty": 0}

    def test_non_dict_input(self):
        """Non-dict inputs → empty dict."""
        for bad in ("string", 42, [1, 2, 3], True):
            result = self._coerce(bad)
            assert result == {}, f"Expected empty for {bad!r}"

    def test_mixed_valid_invalid_values(self):
        """Mix of valid and negative-weight entries — invalid excluded."""
        result = self._coerce({
            "signal-a": 10,
            "signal-b": -5,    # excluded
            "signal-c": 0,
            "signal-d": 999,
        })
        assert "signal-a" in result
        assert "signal-b" not in result
        assert "signal-c" in result
        assert "signal-d" in result


# ─── C: concurrent ContextVar isolation ──────────────────────────────────────

class TestOverridesConcurrentIsolation:

    def test_contextvar_isolated_across_tasks(self):
        """ContextVar must be isolated per asyncio Task; overrides must not bleed."""
        from scoring import _vhost_risk_ctx
        from config import RISK_WEIGHTS

        async def task_a():
            """Task A uses override ua-empty=1."""
            token = _vhost_risk_ctx.set({"ua-empty": 1})
            try:
                await asyncio.sleep(0)   # yield to let task B run
                o = _vhost_risk_ctx.get()
                return o.get("ua-empty", RISK_WEIGHTS.get("ua-empty", 0))
            finally:
                _vhost_risk_ctx.reset(token)

        async def task_b():
            """Task B uses override ua-empty=99."""
            token = _vhost_risk_ctx.set({"ua-empty": 99})
            try:
                await asyncio.sleep(0)
                o = _vhost_risk_ctx.get()
                return o.get("ua-empty", RISK_WEIGHTS.get("ua-empty", 0))
            finally:
                _vhost_risk_ctx.reset(token)

        async def main():
            results = await asyncio.gather(task_a(), task_b())
            return results

        wa, wb = asyncio.run(main())
        assert wa == 1,  f"Task A got weight={wa}, expected 1"
        assert wb == 99, f"Task B got weight={wb}, expected 99"

    def test_contextvar_isolated_50_tasks(self):
        """50 concurrent tasks each with unique override — no bleed."""
        from scoring import _vhost_risk_ctx
        from config import RISK_WEIGHTS

        async def one_task(tid: int):
            token = _vhost_risk_ctx.set({"ua-empty": tid})
            try:
                await asyncio.sleep(0)
                o = _vhost_risk_ctx.get()
                return tid, o.get("ua-empty", -1)
            finally:
                _vhost_risk_ctx.reset(token)

        async def main():
            return await asyncio.gather(*[one_task(i) for i in range(50)])

        results = asyncio.run(main())
        for tid, weight in results:
            assert weight == tid, f"Task {tid} got weight={weight}"

    def test_task_without_override_sees_none(self):
        """Task that never sets ContextVar gets None (no bleed from sibling)."""
        from scoring import _vhost_risk_ctx

        async def setter():
            token = _vhost_risk_ctx.set({"ua-empty": 42})
            await asyncio.sleep(0)
            _vhost_risk_ctx.reset(token)

        async def reader():
            await asyncio.sleep(0)
            return _vhost_risk_ctx.get()

        async def main():
            return await asyncio.gather(setter(), reader())

        _, val = asyncio.run(main())
        # reader task was spawned before setter could pollute it
        assert val is None, f"Expected None, got {val}"


# ─── N: negative — no override context ───────────────────────────────────────

class TestOverridesNegative:

    def test_no_override_context_uses_global_weight(self):
        """No ContextVar set → RISK_WEIGHTS global weight unchanged."""
        from scoring import _vhost_risk_ctx
        from config import RISK_WEIGHTS
        # Ensure no value is set in this context
        token = _vhost_risk_ctx.set(None)
        try:
            o = _vhost_risk_ctx.get()
            expected = RISK_WEIGHTS.get("ua-empty", 0)
            actual = o.get("ua-empty", expected) if o else expected
            assert actual == expected
        finally:
            _vhost_risk_ctx.reset(token)

    def test_empty_overrides_dict_uses_global(self):
        """Empty overrides dict → falls through to global for every signal."""
        from scoring import _vhost_risk_ctx
        from config import RISK_WEIGHTS
        token = _vhost_risk_ctx.set({})
        try:
            o = _vhost_risk_ctx.get()
            for reason in ("ua-empty", "ua-blocked", "behavior"):
                expected = RISK_WEIGHTS.get(reason, 0)
                actual = o.get(reason, expected) if o else expected
                assert actual == expected
        finally:
            _vhost_risk_ctx.reset(token)


# ─── I: integration — suppress a live signal via override weight=0 ────────────

class TestOverridesIntegration:

    @pytest.mark.parametrize("override_weight,expect_suppressed", [
        (0,  True),   # weight=0 → returns False immediately, no risk added
        (10, False),  # weight=10 → risk added
    ])
    def test_zero_weight_suppresses_scoring(self, override_weight, expect_suppressed):
        """update_risk_and_maybe_ban with weight=0 override adds 0 risk."""
        import asyncio
        from scoring import update_risk_and_maybe_ban, _vhost_risk_ctx
        from state import ip_state

        track_key = f"qa-override-test-{override_weight}"
        ip        = f"99.{override_weight}.0.1"
        reason    = "ua-empty"

        async def run():
            # Clean slate
            try: del ip_state[track_key]
            except KeyError: pass
            token = _vhost_risk_ctx.set({reason: override_weight})
            try:
                await update_risk_and_maybe_ban(track_key, reason, ip)
                s = ip_state.get(track_key)
                return float(s.risk_score) if s else 0.0
            finally:
                _vhost_risk_ctx.reset(token)
                try: del ip_state[track_key]
                except KeyError: pass

        risk = asyncio.run(run())
        if expect_suppressed:
            assert risk == 0.0, f"Expected risk=0 with weight=0 override, got {risk}"
        else:
            assert risk == float(override_weight), f"Expected risk={override_weight}, got {risk}"
