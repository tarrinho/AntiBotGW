"""1.8.10 — guards for the per-vhost knob persistence bug.

Symptom: WAF_*_ENABLED (and 30 other 1.8.9 knobs) could not be saved from the
Vhost Policy page — toggling them and reloading showed the old value.

Root causes:
  1. `_VHOST_COERCE` used the builtin `bool` as the coercer. `bool("false")` is
     `True`, so an override sent as the string "false" by the policy UI was
     stored as `True` — i.e. the change vanished.
  2. Those knobs were missing from vhost_policy.html `KNOB_META`, so they
     rendered as generic text inputs (string values) instead of toggles (real
     booleans), which is what triggered (1).

These tests lock in both fixes. (KNOB_META coverage/type is enforced in
test_pure.py::test_vhost_policy_html_knob_meta_coverage.)
"""
import os
import importlib

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")
vhost = importlib.import_module("vhost")


# ── coercion correctness ─────────────────────────────────────────────────────

def test_no_bare_bool_coercer():
    """No knob may use the builtin `bool` — it mis-coerces string "false"."""
    offenders = [k for k, c in vhost._VHOST_COERCE.items() if c is bool]
    assert not offenders, (
        "These knobs use bare `bool` (bool('false') is True!); use _to_bool: "
        f"{sorted(offenders)}"
    )


@pytest.mark.parametrize("raw,expected", [
    ("false", False), ("true", True), ("0", False), ("1", True),
    ("off", False), ("on", True), ("", False), ("False", False), ("TRUE", True),
    (False, False), (True, True), (0, False), (1, True), (None, False),
])
def test_to_bool_parses(raw, expected):
    assert vhost._to_bool(raw) is expected


def test_every_bool_knob_roundtrips_string_false():
    """Every _to_bool-coerced knob must turn the string "false" into False."""
    bad = []
    for k, c in vhost._VHOST_COERCE.items():
        if c is vhost._to_bool:
            if c("false") is not False or c("true") is not True:
                bad.append(k)
    assert not bad, f"bool coercer mis-parsed string values for: {bad}"


# ── end-to-end override persistence (dynamic) ────────────────────────────────

@pytest.fixture
def isolated_vhosts(monkeypatch):
    """Run vhost_set against an in-memory store with disk writes stubbed out."""
    monkeypatch.setattr(vhost, "_save_vhosts_file", lambda: None)
    monkeypatch.setattr(vhost, "VHOSTS", {}, raising=False)
    return vhost


def test_string_false_override_persists_as_false(isolated_vhosts):
    v = isolated_vhosts
    ok, msg = v.vhost_set("qa-false.example.com", {"WAF_GRAPHQL_ENABLED": "false"})
    assert ok, msg
    stored = v.VHOSTS["qa-false.example.com"]["WAF_GRAPHQL_ENABLED"]
    assert stored is False, (
        f"string 'false' override stored as {stored!r} — regression of "
        "bool('false')==True"
    )


def test_string_true_override_persists_as_true(isolated_vhosts):
    v = isolated_vhosts
    ok, msg = v.vhost_set("qa-true.example.com", {"WAF_SLOWLORIS_ENABLED": "true"})
    assert ok, msg
    assert v.VHOSTS["qa-true.example.com"]["WAF_SLOWLORIS_ENABLED"] is True


def test_real_bool_override_persists(isolated_vhosts):
    """Toggle widgets send real booleans — those must round-trip too."""
    v = isolated_vhosts
    ok, _ = v.vhost_set("qa-bool.example.com", {"WAF_UPLOAD_ENABLED": False})
    assert ok
    assert v.VHOSTS["qa-bool.example.com"]["WAF_UPLOAD_ENABLED"] is False
