"""
tests/test_v1814_signal_knob_hotreload_qa.py — QA for five SIGNAL_KNOB entries
added to _HOT_RELOAD_KNOBS in 1.8.14 iteration 4.

The five knobs were present in SIGNAL_KNOB since 1.8.13/1.8.15 but missing from
_HOT_RELOAD_KNOBS, causing the Controls dashboard "→ Controls" link to error on
those signals.  This file guards against regression.

Groups:
  F — Feed reputation knobs  (FEODO_ENABLED, CINS_ENABLED, URLHAUS_ENABLED)
  S — Sidecar fingerprint    (H2_SETTINGS_FP_ENABLED)
  J — JS consistency         (JS_CONSISTENCY_ENABLED)
"""
import os
import pathlib

os.environ.setdefault("UPSTREAM", "http://localhost")

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


def _hot_reload_knobs():
    from core.proxy_handler import _HOT_RELOAD_KNOBS
    return _HOT_RELOAD_KNOBS


def _signal_knob():
    from core.proxy_handler import SIGNAL_KNOB
    return SIGNAL_KNOB


def _to_bool_ref():
    from core.proxy_handler import _to_bool
    return _to_bool


def _assert_bool_knob(name, default_val, signal=None, gate_file=None, gate_str=None):
    """Shared assertion bundle for bool knobs whose default lives in config.py."""
    tb = _to_bool_ref()
    hrk = _hot_reload_knobs()

    assert name in hrk, f"{name} missing from _HOT_RELOAD_KNOBS"
    parser, _ = hrk[name]
    assert parser is tb, (
        f"{name} must use _to_bool as parser (got {parser!r}); "
        "changing the parser type is a breaking hot-reload contract change"
    )

    import config
    actual = getattr(config, name)
    assert actual == default_val, (
        f"config.{name} default is {actual!r}, expected {default_val!r}; "
        "update config.py or this test together"
    )

    if signal is not None:
        sk = _signal_knob()
        assert signal in sk, f"SIGNAL_KNOB missing key {signal!r}"
        assert sk[signal] == name, (
            f"SIGNAL_KNOB[{signal!r}] = {sk[signal]!r}, expected {name!r}"
        )

    if gate_file is not None and gate_str is not None:
        src = _read(gate_file)
        assert gate_str in src, (
            f"Source gate {gate_str!r} not found in {gate_file}; "
            f"{name} gate must be checked in the detection hot-path"
        )


# ── F: Feed reputation knobs ──────────────────────────────────────────────────

class TestFeedReputationKnobs:
    """FEODO_ENABLED, CINS_ENABLED, URLHAUS_ENABLED — defaults live in
    reputation/feeds.py (not config.py); custom assertions used."""

    def _hrk_assert(self, name: str, signal_key: str) -> None:
        """Membership + parser + signal mapping for a feed knob."""
        tb = _to_bool_ref()
        hrk = _hot_reload_knobs()
        assert name in hrk, f"{name} missing from _HOT_RELOAD_KNOBS"
        parser, _ = hrk[name]
        assert parser is tb, f"{name} must use _to_bool parser"
        sk = _signal_knob()
        assert signal_key in sk, f"SIGNAL_KNOB missing {signal_key!r}"
        assert sk[signal_key] == name, f"SIGNAL_KNOB[{signal_key!r}] expected {name!r}"

    def test_f01_feodo_enabled_in_hot_reload(self):
        self._hrk_assert("FEODO_ENABLED", "feodo-c2")

    def test_f01_feodo_enabled_defaults_false(self):
        from reputation.feeds import FEODO_ENABLED
        assert FEODO_ENABLED is False, (
            "FEODO_ENABLED must default False — opt-in only; "
            "enabling without a configured feed would fire on empty sets"
        )

    def test_f01_feodo_gate_in_feeds(self):
        src = _read("reputation/feeds.py")
        assert "if FEODO_ENABLED" in src, (
            "reputation/feeds.py must gate feed lookup on FEODO_ENABLED"
        )

    def test_f02_cins_enabled_in_hot_reload(self):
        self._hrk_assert("CINS_ENABLED", "cins-rogue")

    def test_f02_cins_enabled_defaults_false(self):
        from reputation.feeds import CINS_ENABLED
        assert CINS_ENABLED is False, (
            "CINS_ENABLED must default False — opt-in only"
        )

    def test_f02_cins_gate_in_feeds(self):
        src = _read("reputation/feeds.py")
        assert "if CINS_ENABLED" in src

    def test_f03_urlhaus_enabled_in_hot_reload(self):
        self._hrk_assert("URLHAUS_ENABLED", "urlhaus-malware")

    def test_f03_urlhaus_enabled_defaults_false(self):
        from reputation.feeds import URLHAUS_ENABLED
        assert URLHAUS_ENABLED is False, (
            "URLHAUS_ENABLED must default False — opt-in only"
        )

    def test_f03_urlhaus_gate_in_feeds(self):
        src = _read("reputation/feeds.py")
        assert "if URLHAUS_ENABLED" in src

    def test_f04_feeds_any_combo_gate_present(self):
        src = _read("core/proxy_handler.py")
        assert "_feeds_any = FEODO_ENABLED or CINS_ENABLED or URLHAUS_ENABLED" in src, (
            "proxy_handler must short-circuit feed lookup with the combined "
            "_feeds_any guard (FEODO_ENABLED or CINS_ENABLED or URLHAUS_ENABLED); "
            "avoids per-request overhead when all feeds are disabled"
        )

    def test_f04_feeds_any_guards_lookup(self):
        src = _read("core/proxy_handler.py")
        assert "if _feeds_any" in src, (
            "_feeds_any must gate the reputation lookup block; "
            "without it every request pays the feed-check cost even when all feeds are off"
        )


# ── S: H2 settings fingerprint knob ──────────────────────────────────────────

class TestH2SettingsFpKnob:
    """H2_SETTINGS_FP_ENABLED — opt-in sidecar-dependent; two SIGNAL_KNOB entries."""

    def test_s01_h2_settings_fp_in_hot_reload(self):
        _assert_bool_knob(
            "H2_SETTINGS_FP_ENABLED",
            default_val=False,
            signal="h2-settings-deny",
            gate_file="core/proxy_handler.py",
            gate_str="if H2_SETTINGS_FP_ENABLED",
        )

    def test_s01_h2_settings_mismatch_signal_mapped(self):
        sk = _signal_knob()
        assert "h2-settings-mismatch" in sk, "SIGNAL_KNOB missing h2-settings-mismatch"
        assert sk["h2-settings-mismatch"] == "H2_SETTINGS_FP_ENABLED", (
            "h2-settings-mismatch and h2-settings-deny both require the same "
            "sidecar gate (H2_SETTINGS_FP_ENABLED) — both must map to it"
        )

    def test_s01_h2_settings_fp_is_opt_in(self):
        import config
        assert config.H2_SETTINGS_FP_ENABLED is False, (
            "H2_SETTINGS_FP_ENABLED must default False — requires fingerproxy "
            "sidecar injecting X-H2-FP header; enabling without the sidecar "
            "produces no signals but wastes an attribute lookup per request"
        )


# ── J: JS consistency knob ────────────────────────────────────────────────────

class TestJsConsistencyKnob:
    """JS_CONSISTENCY_ENABLED — three SIGNAL_KNOB entries; defaults True."""

    def test_j01_js_consistency_in_hot_reload(self):
        _assert_bool_knob(
            "JS_CONSISTENCY_ENABLED",
            default_val=True,
            signal="js-cua-version-mismatch",
            gate_file="detection/js_consistency.py",
            gate_str="JS_CONSISTENCY_ENABLED",
        )

    def test_j01_js_mobile_hint_signal_mapped(self):
        sk = _signal_knob()
        assert "js-mobile-hint-mismatch" in sk, "SIGNAL_KNOB missing js-mobile-hint-mismatch"
        assert sk["js-mobile-hint-mismatch"] == "JS_CONSISTENCY_ENABLED"

    def test_j01_js_fetch_impossible_signal_mapped(self):
        sk = _signal_knob()
        assert "js-fetch-impossible" in sk, "SIGNAL_KNOB missing js-fetch-impossible"
        assert sk["js-fetch-impossible"] == "JS_CONSISTENCY_ENABLED"

    def test_j01_js_consistency_defaults_true(self):
        import config
        assert config.JS_CONSISTENCY_ENABLED is True, (
            "JS_CONSISTENCY_ENABLED must default True — signals are low-risk "
            "JS metadata checks; opt-out to disable rather than opt-in"
        )

    def test_j01_js_consistency_gate_is_early_exit(self):
        src = _read("detection/js_consistency.py")
        assert "if not JS_CONSISTENCY_ENABLED" in src, (
            "detection/js_consistency.py must guard the check with "
            "`if not JS_CONSISTENCY_ENABLED: return []` early-exit pattern"
        )
