"""
tests/test_v191_iter15_global_posture_wizard.py — guard the global posture
wizard embedded on dashboards/controls.html in iter-15.

Operator request was "shouldnt i be able to see this in the thresholds
page?" — so the per-vhost wizard's preset bundle + impact radar got a
sibling on the Controls page that targets global defaults instead of
per-vhost overrides.

Both wizards share the same preset registry (Lax / Balanced / Strict /
Paranoid) and the same 5-axis impact math. Differences:

  - Class suffix `-g` (e.g. `.posture-card-g`) so styles don't collide
    with the per-vhost wizard if both pages are open in tabs
  - Apply target is `/secured/config` with NO `?vhost=` param
  - Card defaults to visible (no hostname dependency)

These tests assert the markup is present, the JS contract is intact, and
the Apply path is global-only (no vhost query string).
"""

import os
import re


_REPO = os.path.join(os.path.dirname(__file__), "..")
HTML = os.path.join(_REPO, "dashboards", "controls.html")


def _src():
    return open(HTML, encoding="utf-8").read()


# ── Card structure ─────────────────────────────────────────────────────

def test_global_wizard_card_present():
    src = _src()
    assert 'id="card-posture-global"' in src, (
        "controls.html must declare #card-posture-global (the global wizard "
        "card) — operators looking for threshold tuning land on Controls"
    )


def test_global_wizard_radar_svg_present():
    src = _src()
    assert 'id="posture-radar-global"' in src, (
        "#posture-radar-global SVG container must be embedded above the "
        "preset cards"
    )


def test_global_wizard_has_four_preset_cards():
    src = _src()
    for prof in ("lax", "balanced", "strict", "paranoid"):
        assert f'data-posture-g="{prof}"' in src, (
            f"global wizard must have a card with data-posture-g=\"{prof}\""
        )
        assert (f'class="posture-preview-g" data-posture-g="{prof}"' in src), (
            f"global wizard '{prof}' must have a Preview button"
        )
        assert (f'class="posture-apply-g" data-posture-g="{prof}"' in src), (
            f"global wizard '{prof}' must have an Apply globally button"
        )


def test_global_wizard_card_default_visible():
    """Unlike the per-vhost card (display:none until hostname selected),
    the global card must be visible immediately — operators expect the
    wizard the moment they land on Controls."""
    src = _src()
    # Locate the card-posture-global section and confirm there's no
    # `style="display:none"` on it.
    m = re.search(
        r'<section[^>]*id="card-posture-global"[^>]*>',
        src,
    )
    assert m, "card-posture-global section must be present"
    tag = m.group(0)
    assert "display:none" not in tag, (
        "global wizard must be visible by default — no `display:none` on the "
        "card itself (operators expect it immediately on Controls)"
    )


# ── Preset registry parity with per-vhost wizard ───────────────────────

def test_global_preset_registry_defined():
    src = _src()
    assert "POSTURE_PRESETS_G" in src, (
        "controls.html must define POSTURE_PRESETS_G (the global wizard's "
        "preset registry, suffixed -G to avoid clash with the per-vhost "
        "POSTURE_PRESETS if both pages are open simultaneously)"
    )


def test_global_presets_have_all_four_profiles():
    src = _src()
    # Match each profile inside the POSTURE_PRESETS_G object.
    m = re.search(r"POSTURE_PRESETS_G\s*=\s*\{(.*?)^\s*\};", src, re.DOTALL | re.M)
    assert m, "POSTURE_PRESETS_G object literal must be present"
    body = m.group(1)
    for prof in ("lax", "balanced", "strict", "paranoid"):
        assert re.search(rf"\b{prof}\s*:\s*\{{", body), (
            f"POSTURE_PRESETS_G must include the '{prof}' profile"
        )


def test_global_profile_impact_function_defined():
    src = _src()
    assert re.search(r"function\s+_profileImpactG\s*\(\s*knobs\s*\)", src), (
        "must define _profileImpactG(knobs) — same 5-axis math as the "
        "per-vhost _profileImpact but namespaced to avoid collision"
    )


def test_global_radar_render_function_defined():
    src = _src()
    assert re.search(r"function\s+_renderProfileRadarG\b", src), (
        "must define _renderProfileRadarG() — populates #posture-radar-global"
    )


def test_global_radar_covers_five_axes():
    src = _src()
    m = re.search(r"function\s+_renderProfileRadarG\b.*?^  }",
                  src, re.DOTALL | re.M)
    assert m, "_renderProfileRadarG must be defined"
    body = m.group(0)
    for label in ("Bot block strength", "User friction", "Threat coverage",
                  "Rate-limit tightness", "Response strictness"):
        assert label in body, f"global radar must label the '{label}' axis"


# ── Apply target — GLOBAL only (no ?vhost= param) ──────────────────────

def test_global_apply_posts_to_secured_config_without_vhost_param():
    """The whole point of this wizard vs the per-vhost one is that Apply
    writes to global defaults. The POST must NOT carry a `?vhost=` query
    string — that would re-introduce the per-vhost coupling we're trying
    to avoid."""
    src = _src()
    # Grab from `async function _applyG` to the end of the next sibling
    # function (`document.addEventListener`) — captures the whole body.
    m = re.search(
        r"async function\s+_applyG\b.*?(?=\n\s*document\.addEventListener)",
        src, re.DOTALL,
    )
    assert m, "_applyG must be defined"
    body = m.group(0)
    # Must POST to /secured/config — and crucially NOT include vhost= in
    # the URL.
    assert "'/antibot-appsec-gateway/secured/config'" in body, (
        "_applyG must POST to /secured/config (no vhost qualifier)"
    )
    assert "vhost=" not in body, (
        "_applyG must NOT include a vhost= query parameter — the global "
        "wizard sets defaults; per-vhost lives at /secured/vhost-policy"
    )
    assert "method: 'POST'" in body or 'method:"POST"' in body or "method: \"POST\"" in body, (
        "_applyG must use method:POST"
    )


def test_global_apply_requires_confirmation():
    """Same destructive-confirmation guard as the per-vhost wizard — silent
    apply across global defaults would be too easy to mis-click.

    Accept either the raw `window.confirm` or the project's async wrapper
    `_asyncConfirm` (a UX consistency layer some pages route through)."""
    src = _src()
    m = re.search(
        r"async function\s+_applyG\b.*?(?=\n\s*document\.addEventListener)",
        src, re.DOTALL,
    )
    assert m
    body = m.group(0)
    assert ("window.confirm" in body) or ("_asyncConfirm" in body), (
        "_applyG must call window.confirm() (or the _asyncConfirm UX "
        "wrapper) — global apply must be operator-explicit"
    )


def test_global_apply_sends_csrf_header():
    src = _src()
    m = re.search(
        r"async function\s+_applyG\b.*?(?=\n\s*document\.addEventListener)",
        src, re.DOTALL,
    )
    body = m.group(0)
    assert "X-CSRF-Token" in body, (
        "_applyG must send the X-CSRF-Token header — the /secured/config "
        "POST is CSRF-gated (LIVE-3 fix)"
    )


# ── Preview diff vs current global state ───────────────────────────────


def test_global_diff_function_defined():
    src = _src()
    assert re.search(r"function\s+_diffG\b", src), (
        "must define _diffG(profile) — computes deltas vs current global "
        "state (no _pending / _overrides — those are vhost-specific)"
    )


def test_global_diff_uses_current_global_baseline():
    """_diffG must compare against the global config, not an empty
    baseline (which would always show every knob as a change)."""
    src = _src()
    m = re.search(r"function\s+_diffG\b.*?\n  \}", src, re.DOTALL)
    assert m, "_diffG must be defined"
    body = m.group(0)
    assert "_currentGlobal" in body, (
        "_diffG must reference _currentGlobal — that's the baseline the "
        "preview diff is computed against"
    )


def test_global_wizard_links_to_per_vhost():
    """The global card header must link to /secured/vhost-policy so an
    operator who wants per-vhost tuning isn't dead-ended."""
    src = _src()
    # Sanity: link should appear somewhere in the card-posture-global
    # section between its opening tag and the diff panel.
    m = re.search(
        r'<section[^>]*id="card-posture-global".*?</section>',
        src, re.DOTALL,
    )
    assert m, "card-posture-global section must be present"
    section = m.group(0)
    assert '/secured/vhost-policy' in section, (
        "global wizard card must link to /secured/vhost-policy so operators "
        "can jump to per-vhost overrides"
    )
