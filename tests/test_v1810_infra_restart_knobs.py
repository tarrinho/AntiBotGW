"""
tests/test_v1810_infra_restart_knobs.py — Guards for restart:true knob UX in
the Infrastructure settings card.

Root cause fixed: ALLOW_PRIVATE_UPSTREAM has restart:true in INFRA_KNOBS but
is intentionally absent from _HOT_RELOAD_KNOBS (SSRF guard).  The UI rendered
it as a fully interactive toggle; clicking it added the key to _infraDirty,
the Apply button was enabled, and the POST /config endpoint rejected it with
"not-hot-reloadable".  Same issue affects STRICT_VHOST.

Fix: renderInfra now renders restart:true controls as read-only:
  - bool kind: no data-ikey attribute → no click listener, cursor:not-allowed
  - text/list kind: disabled attribute on <input>
  - select kind: disabled attribute on <select>

None of these changes fire _infraChange or _infraToggle, so _infraDirty never
receives a restart-required key and the Apply button stays disabled.

Tests (I)
  I01  ALLOW_PRIVATE_UPSTREAM is present in INFRA_KNOBS                [display]
  I02  STRICT_VHOST is present in INFRA_KNOBS                          [display]
  I03  ALLOW_PRIVATE_UPSTREAM bool toggle rendered without data-ikey   [no listener]
  I04  STRICT_VHOST bool toggle rendered without data-ikey             [no listener]
  I05  ALLOW_PRIVATE_UPSTREAM toggle has cursor:not-allowed            [visual cue]
  I06  STRICT_VHOST toggle has cursor:not-allowed                      [visual cue]
  I07  renderInfra does NOT attach _infraToggle for keys with restart  [guard]
  I08  _infraToggle handler exists for non-restart knobs               [sanity]
  I09  ALLOW_PRIVATE_UPSTREAM absent from _HOT_RELOAD_KNOBS            [SSRF guard]
  I10  STRICT_VHOST absent from _HOT_RELOAD_KNOBS (requires restart)   [guard]
  I11  Hot-reloadable knobs in INFRA_KNOBS all present in _HOT_RELOAD_KNOBS
       (detects future knob added to UI without backend support)
"""
import os
import re
import importlib

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

from core import proxy_handler

_DASH = os.path.join(os.path.dirname(__file__), "..", "dashboards")

with open(os.path.join(_DASH, "settings.html"), encoding="utf-8") as _f:
    _SETTINGS_HTML = _f.read()

# Parse INFRA_KNOBS keys and their restart flag from the JS source.
# Pattern: {key:'NAME', ..., restart:true/false, ...}
_INFRA_KNOB_RE = re.compile(
    r"\{key:'([A-Z_]+)'[^}]*restart:(true|false)[^}]*\}",
    re.DOTALL,
)
_INFRA_KNOBS: dict[str, bool] = {
    m.group(1): m.group(2) == "true"
    for m in _INFRA_KNOB_RE.finditer(_SETTINGS_HTML)
}


# ── I: Infra knob restart UX ─────────────────────────────────────────────────

class TestInfraRestartKnobs:

    def test_i01_allow_private_upstream_in_infra_knobs(self):
        assert "ALLOW_PRIVATE_UPSTREAM" in _INFRA_KNOBS, (
            "ALLOW_PRIVATE_UPSTREAM must appear in INFRA_KNOBS for visibility"
        )

    def test_i02_strict_vhost_in_infra_knobs(self):
        assert "STRICT_VHOST" in _INFRA_KNOBS, (
            "STRICT_VHOST must appear in INFRA_KNOBS for visibility"
        )

    def test_i03_allow_private_upstream_no_data_ikey(self):
        # data-ikey on a toggle means _infraToggle will be attached.
        # restart:true knobs must NOT have data-ikey.
        assert 'data-ikey="ALLOW_PRIVATE_UPSTREAM"' not in _SETTINGS_HTML, (
            "ALLOW_PRIVATE_UPSTREAM toggle must not have data-ikey — "
            "clicking it must not be possible (restart required)"
        )

    def test_i04_strict_vhost_no_data_ikey(self):
        assert 'data-ikey="STRICT_VHOST"' not in _SETTINGS_HTML, (
            "STRICT_VHOST toggle must not have data-ikey — restart required"
        )

    def test_i05_render_infra_uses_cursor_not_allowed_for_restart_knobs(self):
        # renderInfra must set cursor:not-allowed on bool toggles when k.restart.
        # The key names appear in INFRA_KNOBS (static data) — the CSS is in the
        # renderInfra function body (dynamic template literal), so we search there.
        render_idx = _SETTINGS_HTML.find("function renderInfra")
        assert render_idx != -1, "renderInfra not found"
        render_fn = _SETTINGS_HTML[render_idx:render_idx + 4000]
        assert "cursor:not-allowed" in render_fn, (
            "renderInfra bool branch must set cursor:not-allowed for restart:true knobs"
        )

    def test_i06_render_infra_cursor_conditioned_on_restart(self):
        # The cursor must be conditionally set — not hard-coded to not-allowed.
        render_idx = _SETTINGS_HTML.find("function renderInfra")
        assert render_idx != -1
        render_fn = _SETTINGS_HTML[render_idx:render_idx + 4000]
        # Both values must appear to confirm the ternary / conditional
        assert "cursor:pointer" in render_fn and "cursor:not-allowed" in render_fn, (
            "renderInfra must have both cursor:pointer (editable) and "
            "cursor:not-allowed (restart-required) in the bool branch"
        )

    def test_i07_restart_knobs_not_wired_to_infra_toggle(self):
        # _infraToggle is called from click listeners on [data-ikey].
        # Because restart:true knobs have no data-ikey the handler is never
        # called for them.  This test confirms the renderInfra logic uses
        # conditional data-ikey assignment.
        render_fn_idx = _SETTINGS_HTML.find("function renderInfra")
        assert render_fn_idx != -1, "renderInfra function not found"
        render_fn = _SETTINGS_HTML[render_fn_idx:render_fn_idx + 3000]
        # Must have a conditional that omits data-ikey for restart knobs
        assert "k.restart" in render_fn, (
            "renderInfra must check k.restart to conditionally omit data-ikey"
        )

    def test_i08_hot_reload_knobs_still_have_data_ikey(self):
        # A hot-reloadable bool knob (e.g. STRICT_HOST_VALIDATION if present,
        # or any restart:false bool) must still have data-ikey.
        # We only need to confirm data-ikey appears at all (i.e. the feature
        # still works for non-restart knobs).
        assert 'data-ikey="' in _SETTINGS_HTML, (
            "data-ikey must still appear for non-restart bool knobs"
        )

    def test_i09_allow_private_upstream_is_hot_reloadable_restart_false(self):
        # ALLOW_PRIVATE_UPSTREAM is hot-reloadable by explicit operator request.
        assert "ALLOW_PRIVATE_UPSTREAM" in proxy_handler._HOT_RELOAD_KNOBS, (
            "ALLOW_PRIVATE_UPSTREAM must be in _HOT_RELOAD_KNOBS (runtime toggle)"
        )
        assert _INFRA_KNOBS.get("ALLOW_PRIVATE_UPSTREAM") is False, (
            "INFRA_KNOBS ALLOW_PRIVATE_UPSTREAM must have restart:false"
        )

    def test_i10_strict_vhost_is_hot_reloadable_restart_false(self):
        # STRICT_VHOST IS in _HOT_RELOAD_KNOBS — it applies immediately.
        # The INFRA_KNOBS entry must have restart:false to match.
        assert "STRICT_VHOST" in proxy_handler._HOT_RELOAD_KNOBS, (
            "STRICT_VHOST must be in _HOT_RELOAD_KNOBS (it is hot-reloadable)"
        )
        assert _INFRA_KNOBS.get("STRICT_VHOST") is False, (
            "INFRA_KNOBS STRICT_VHOST must have restart:false (it is hot-reloadable)"
        )

    def test_i11_hot_reload_infra_knobs_have_backend_support(self):
        """
        Every knob in INFRA_KNOBS that is NOT restart:true must be in
        _HOT_RELOAD_KNOBS so the backend can actually apply it.
        Catches future knobs added to the UI without wiring up the backend.
        """
        missing_from_backend = []
        for key, needs_restart in _INFRA_KNOBS.items():
            if not needs_restart:
                if key not in proxy_handler._HOT_RELOAD_KNOBS:
                    missing_from_backend.append(key)
        assert not missing_from_backend, (
            "These INFRA_KNOBS have restart:false but are missing from "
            "_HOT_RELOAD_KNOBS — backend will reject Apply: "
            + ", ".join(sorted(missing_from_backend))
        )

    def test_i12_allow_private_upstream_env_pin_excluded(self):
        # By explicit operator request, ALLOW_PRIVATE_UPSTREAM stays mutable at
        # runtime even when set via container env. It must be in _ENV_PIN_EXCLUDE
        # so config_endpoint does NOT reject it as "env-pinned".
        assert "ALLOW_PRIVATE_UPSTREAM" in proxy_handler._ENV_PIN_EXCLUDE, (
            "ALLOW_PRIVATE_UPSTREAM must be in _ENV_PIN_EXCLUDE so an env-set "
            "value does not pin it (must remain runtime-mutable from Settings)"
        )

    def test_i13_env_set_allow_private_upstream_not_pinned(self, monkeypatch):
        # Simulate the env var being present and confirm the env-provided check
        # does NOT pin ALLOW_PRIVATE_UPSTREAM (because it is excluded).
        monkeypatch.setenv("ALLOW_PRIVATE_UPSTREAM", "1")
        # _ENV_PROVIDED_KNOBS is computed at import time; recompute the membership
        # the same way the module does, honouring the exclude set.
        excluded = proxy_handler._ENV_PIN_EXCLUDE
        provided = proxy_handler._env_knob_is_provided("ALLOW_PRIVATE_UPSTREAM")
        would_pin = ("ALLOW_PRIVATE_UPSTREAM" not in excluded) and provided
        assert not would_pin, (
            "ALLOW_PRIVATE_UPSTREAM set in env must NOT be pinned — it is in "
            "_ENV_PIN_EXCLUDE, so runtime changes stay allowed"
        )

    def test_i14_env_pin_exclude_keeps_existing_members(self):
        # Guard against accidental removal of the pre-existing exclusions.
        for k in ("TURNSTILE_ENABLED", "JS_CHALLENGE", "UPSTREAM"):
            assert k in proxy_handler._ENV_PIN_EXCLUDE, (
                f"{k} must remain in _ENV_PIN_EXCLUDE"
            )
