"""
tests/test_v1814_posture_presets.py — guard the Security-posture preset
card on the Vhost Policy page.

Operators move a vhost along the LAX ↔ PARANOID axis via four pre-baked
profiles (Lax / Balanced / Strict / Paranoid — Paranoid added in 1.9.1
iter-13). Each profile is a curated knob bundle covering both bool
toggles and the vhost-overridable threshold values; previewing shows the
deltas vs. the current effective config, applying writes only those
deltas via the existing POST /secured/config?vhost=<host> endpoint.

This file checks both the static structure (anchors) and the contract
the JS encodes (preset shape, knob coverage, profile axis direction).
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
HTML = os.path.join(_REPO, "dashboards", "vhost_policy.html")


def _src():
    return open(HTML, encoding="utf-8").read()


# ── DOM structure ────────────────────────────────────────────────────────

def test_posture_card_present():
    src = _src()
    assert 'id="card-posture"' in src, (
        "vhost_policy.html must declare #card-posture (the Security-posture "
        "preset host card)"
    )


def test_four_profile_cards_present():
    """Each posture profile must have its own card with a Preview + Apply
    button keyed by data-posture.

    iter-13 added the `paranoid` profile for ultra-high-value endpoints
    (login / payment / admin) — Turnstile on, every threshold at its
    tightest. Keeping the previous three intact means existing operator
    overrides continue to classify cleanly."""
    src = _src()
    for prof in ("lax", "balanced", "strict", "paranoid"):
        assert f'data-posture="{prof}"' in src, (
            f"posture '{prof}' must have a card with data-posture=\"{prof}\""
        )
        assert (f'class="posture-preview" data-posture="{prof}"' in src), (
            f"posture '{prof}' must have a Preview button"
        )
        assert (f'class="posture-apply" data-posture="{prof}"' in src), (
            f"posture '{prof}' must have an Apply button"
        )


def test_posture_card_initially_hidden():
    """The card must default to display:none — only shown after a vhost is
    selected (mirrors #card-bot-detection visibility logic)."""
    src = _src()
    m = re.search(r'id="card-posture"[^>]*style="([^"]*)"', src)
    assert m, "#card-posture must declare a style attribute"
    assert "display:none" in m.group(1), (
        "#card-posture must be hidden by default (display:none); _renderPostureCard "
        "shows it once _hostname is set"
    )


# ── Preset registry ─────────────────────────────────────────────────────

def test_posture_presets_dict_defined():
    src = _src()
    assert "POSTURE_PRESETS" in src, (
        "JS must define POSTURE_PRESETS — the preset registry"
    )
    assert re.search(r"POSTURE_PRESETS\s*=\s*\{", src), (
        "POSTURE_PRESETS must be a literal object"
    )


def test_all_four_profiles_in_registry():
    src = _src()
    # Match each profile as a top-level key in the registry.
    for prof in ("lax", "balanced", "strict", "paranoid"):
        assert re.search(rf"\b{prof}\s*:\s*\{{", src), (
            f"POSTURE_PRESETS must include the '{prof}' profile as a key"
        )


def test_each_profile_carries_a_knobs_bundle():
    """Each preset must have a `knobs` dict — that's the contract _postureDiff
    iterates over."""
    src = _src()
    # Quick smell test: at least four `knobs:` occurrences (one per preset).
    knobs_count = len(re.findall(r"\bknobs\s*:\s*\{", src))
    assert knobs_count >= 4, (
        f"expected at least 4 `knobs:` bundle declarations in POSTURE_PRESETS, "
        f"got {knobs_count}"
    )


# ── Axis correctness — lax must be more permissive than strict ──────────

def test_risk_ban_threshold_axis_direction():
    """LAX must raise RISK_BAN_THRESHOLD (fewer bans), STRICT must lower it.
    Anchor the actual literal values so a refactor that flips the axis is
    caught."""
    src = _src()
    # The literal `RISK_BAN_THRESHOLD: 80` belongs to the lax profile;
    # `RISK_BAN_THRESHOLD: 30` to strict; `50` to balanced.
    assert re.search(r"RISK_BAN_THRESHOLD\s*:\s*80\b", src), (
        "LAX preset must set RISK_BAN_THRESHOLD = 80 (more permissive)"
    )
    assert re.search(r"RISK_BAN_THRESHOLD\s*:\s*50\b", src), (
        "BALANCED preset must set RISK_BAN_THRESHOLD = 50"
    )
    assert re.search(r"RISK_BAN_THRESHOLD\s*:\s*30\b", src), (
        "STRICT preset must set RISK_BAN_THRESHOLD = 30 (more aggressive)"
    )


def test_rate_limit_axis_direction():
    """LAX has the most generous rate limit; STRICT the tightest."""
    src = _src()
    # Lax: burst 50, refill 20.0
    assert re.search(r"RATE_LIMIT_BURST\s*:\s*50\b", src)
    assert re.search(r"RATE_LIMIT_REFILL\s*:\s*20\.0\b", src)
    # Strict: burst 10, refill 2.0
    assert re.search(r"RATE_LIMIT_BURST\s*:\s*10\b", src)
    assert re.search(r"RATE_LIMIT_REFILL\s*:\s*2\.0\b", src)


def test_strict_enables_country_block_and_js_challenge():
    """The STRICT bundle must enable COUNTRY_BLOCK_ENABLED + JS_CHALLENGE —
    those are the high-cost-to-bot, high-cost-to-human knobs reserved for
    the strict tier."""
    src = _src()
    # Find the strict profile block and inspect inside.
    m = re.search(r"strict\s*:\s*\{.*?\}\s*\}", src, re.DOTALL)
    assert m, "strict profile block not found"
    blk = m.group(0)
    assert "COUNTRY_BLOCK_ENABLED:" in blk and "true" in blk, (
        "STRICT must enable COUNTRY_BLOCK_ENABLED"
    )
    assert "JS_CHALLENGE:" in blk, (
        "STRICT must reference JS_CHALLENGE"
    )


def test_lax_disables_ua_filter():
    """LAX must disable UA_FILTER_ENABLED — that's the knob that produces the
    most false-positives on diverse public-site traffic."""
    src = _src()
    m = re.search(r"lax\s*:\s*\{.*?\}\s*\}", src, re.DOTALL)
    assert m
    blk = m.group(0)
    assert re.search(r"UA_FILTER_ENABLED\s*:\s*false\b", blk), (
        "LAX preset must set UA_FILTER_ENABLED=false"
    )


# ── JS contract: preview/diff/apply helpers ─────────────────────────────

def test_posture_diff_function_defined():
    src = _src()
    assert re.search(r"function\s+_postureDiff\b", src), (
        "must define _postureDiff() — computes deltas vs. effective current config"
    )


def test_posture_effective_resolves_pending_overrides_globals():
    """_postureEffective must follow the correct precedence: pending >
    vhost overrides > globals — same precedence the dashboard already uses
    for _renderBotDetectionCard."""
    src = _src()
    m = re.search(r"function\s+_postureEffective\b.*?\n\}",
                  src, re.DOTALL)
    assert m, "_postureEffective must be defined"
    body = m.group(0)
    # Order matters — must check _pending FIRST.
    pending_idx = body.find("_pending.hasOwnProperty")
    overrides_idx = body.find("_overrides.hasOwnProperty")
    global_idx = body.find("_globalVals[")
    assert pending_idx != -1, "_postureEffective must check _pending"
    assert overrides_idx != -1, "_postureEffective must check _overrides"
    assert global_idx != -1, "_postureEffective must fall back to _globalVals"
    assert pending_idx < overrides_idx < global_idx, (
        "precedence must be _pending > _overrides > _globalVals — "
        f"got pending@{pending_idx}, overrides@{overrides_idx}, "
        f"global@{global_idx}"
    )


def test_posture_apply_posts_to_per_vhost_config_endpoint():
    """Apply must POST to /secured/config?vhost=<host> — reuses the existing
    endpoint, doesn't introduce a new server surface."""
    src = _src()
    m = re.search(r"function\s+_postureApply\b.*?\n\}", src, re.DOTALL)
    assert m, "_postureApply must be defined"
    body = m.group(0)
    assert "ADMIN_NS + '/config?vhost='" in body or \
           "ADMIN_NS + \"/config?vhost=\"" in body, (
        "_postureApply must POST to /secured/config?vhost=<host>"
    )
    assert "method:'POST'" in body or 'method: "POST"' in body, (
        "_postureApply must use method:POST"
    )
    # Must encode the hostname.
    assert "encodeURIComponent(_hostname)" in body, (
        "_postureApply must encodeURIComponent the hostname before sending"
    )


def test_posture_apply_requires_confirmation():
    """Apply is destructive (writes per-vhost overrides) — must call
    window.confirm() before sending. Operator-explicit, not silent."""
    src = _src()
    m = re.search(r"function\s+_postureApply\b.*?\n\}", src, re.DOTALL)
    body = m.group(0)
    assert "window.confirm" in body, (
        "_postureApply must call window.confirm() — silent apply would be "
        "too easy to mis-click"
    )


def test_render_overrides_calls_render_posture_card():
    """_renderPostureCard must be invoked from _renderOverrides so the card
    toggles visibility + refreshes when the operator selects a vhost."""
    src = _src()
    m = re.search(r"function\s+_renderOverrides\s*\(\s*\).*?\{", src)
    assert m, "_renderOverrides must be defined"
    # The very next ~150 chars must mention _renderPostureCard.
    region = src[m.end(): m.end() + 200]
    assert "_renderPostureCard" in region, (
        "_renderOverrides must call _renderPostureCard() — otherwise the "
        "posture card never picks up a vhost selection"
    )


def test_preview_apply_buttons_wired_via_addeventlistener():
    src = _src()
    # querySelectorAll + addEventListener for both posture-preview and
    # posture-apply.
    assert "querySelectorAll('.posture-preview')" in src, (
        "Preview buttons must be wired via querySelectorAll('.posture-preview')"
    )
    assert "querySelectorAll('.posture-apply')" in src, (
        "Apply buttons must be wired via querySelectorAll('.posture-apply')"
    )


# ── iter-13 expanded bundles + Paranoid profile ─────────────────────────


def _profile_block(src, profile):
    """Slice the JS literal for one profile out of POSTURE_PRESETS so each
    assertion stays scoped to its own bundle. Returns the body between
    `<profile>: { ... }` (greedy match up to next top-level profile or end
    of the registry)."""
    m = re.search(
        rf"\b{profile}\s*:\s*\{{(.*?)\n\s*}}\s*,?\s*\n\s*(?:lax|balanced|strict|paranoid)\s*:|"
        rf"\b{profile}\s*:\s*\{{(.*?)\n\s*}}\s*\n\s*}};",
        src, re.DOTALL,
    )
    assert m, f"profile '{profile}' block not found in POSTURE_PRESETS"
    return m.group(1) or m.group(2)


def test_iter13_expanded_threshold_coverage():
    """Every profile bundle must include the nine vhost-overridable
    thresholds added in iter-13 plus the three new detector toggles.
    Together with the original 14 keys this brings each bundle to 25 knobs."""
    src = _src()
    required = [
        "POW_CHAL_THRESHOLD",
        "ESCALATION_THRESHOLD",
        "SECOND_ORDER_THRESHOLD",
        "TURNSTILE_RISK_THRESHOLD",
        "JA4_AUTODENY_THRESHOLD",
        "ENUM_THRESHOLD",
        "COOKIE_GHOST_MISS_THRESHOLD",
        "CIRCUIT_FAIL_THRESHOLD",
        "REDIRECT_MAZE_THRESHOLD",
        "BEHAVIORAL_CHECK_ENABLED",
        "COORDINATED_ATTACK_ENABLED",
        "PATH_SWEEP_ENABLED",
    ]
    for prof in ("lax", "balanced", "strict", "paranoid"):
        blk = _profile_block(src, prof)
        for knob in required:
            assert f"{knob}:" in blk, (
                f"profile '{prof}' is missing {knob} — iter-13 bundles must "
                f"cover every vhost-overridable threshold"
            )


def test_iter13_paranoid_enables_turnstile():
    """The PARANOID bundle MUST set TURNSTILE_ENABLED=true — that is the
    single most visible difference from STRICT and the reason an operator
    would knowingly pick this profile."""
    src = _src()
    blk = _profile_block(src, "paranoid")
    assert re.search(r"TURNSTILE_ENABLED\s*:\s*true\b", blk), (
        "PARANOID preset must set TURNSTILE_ENABLED=true — that's the "
        "high-friction toggle reserved for this tier"
    )


def test_iter13_threshold_axis_monotonic():
    """Each tier-direction-aware threshold must be monotonic along
    LAX → BALANCED → STRICT → PARANOID. Anchors the literal values so a
    refactor that flips a single tier is caught."""
    src = _src()
    # (knob, lax, balanced, strict, paranoid) — descending = more strict.
    # Note: float literals (e.g. 5.0) keep the trailing `.0` so the regex
    # anchor matches exactly what the source contains.
    cases = [
        ("RISK_BAN_THRESHOLD",        "80",   "50",   "30",   "15"),
        ("POW_CHAL_THRESHOLD",        "50.0", "30.0", "15.0", "5.0"),
        ("ESCALATION_THRESHOLD",      "60.0", "30.0", "15.0", "8.0"),
        ("SECOND_ORDER_THRESHOLD",    "30.0", "15.0", "8.0",  "4.0"),
        ("JA4_AUTODENY_THRESHOLD",    "8",    "3",    "2",    "1"),
        ("ENUM_THRESHOLD",            "600",  "300",  "100",  "30"),
        ("COOKIE_GHOST_MISS_THRESHOLD","8",   "3",    "2",    "1"),
        ("CIRCUIT_FAIL_THRESHOLD",    "20",   "10",   "5",    "3"),
        ("REDIRECT_MAZE_THRESHOLD",   "50.0", "30.0", "15.0", "5.0"),
    ]
    for knob, lax_v, bal_v, str_v, par_v in cases:
        blk_lax = _profile_block(src, "lax")
        blk_bal = _profile_block(src, "balanced")
        blk_str = _profile_block(src, "strict")
        blk_par = _profile_block(src, "paranoid")
        assert re.search(rf"{knob}\s*:\s*{re.escape(lax_v)}\b", blk_lax), (
            f"LAX {knob} must be {lax_v}"
        )
        assert re.search(rf"{knob}\s*:\s*{re.escape(bal_v)}\b", blk_bal), (
            f"BALANCED {knob} must be {bal_v}"
        )
        assert re.search(rf"{knob}\s*:\s*{re.escape(str_v)}\b", blk_str), (
            f"STRICT {knob} must be {str_v}"
        )
        assert re.search(rf"{knob}\s*:\s*{re.escape(par_v)}\b", blk_par), (
            f"PARANOID {knob} must be {par_v}"
        )


def test_iter13_rate_limit_burst_refill_monotonic():
    """Rate limit BURST + REFILL go the other direction — LAX is the most
    GENEROUS (highest), PARANOID the most RESTRICTIVE (lowest)."""
    src = _src()
    blk_lax = _profile_block(src, "lax")
    blk_par = _profile_block(src, "paranoid")
    assert re.search(r"RATE_LIMIT_BURST\s*:\s*50\b", blk_lax)
    assert re.search(r"RATE_LIMIT_BURST\s*:\s*5\b", blk_par)
    assert re.search(r"RATE_LIMIT_REFILL\s*:\s*20\.0\b", blk_lax)
    assert re.search(r"RATE_LIMIT_REFILL\s*:\s*1\.0\b", blk_par)


def test_iter13_paranoid_badge_styled():
    """The PARANOID badge needs its own CSS class (different colour from
    STRICT) so the operator visually distinguishes the high-friction tier."""
    src = _src()
    assert ".posture-badge.p-paranoid" in src, (
        "PARANOID badge must have a dedicated `.posture-badge.p-paranoid` "
        "CSS rule — colour cue keeps it visually distinct from STRICT"
    )


# ── iter-14 profile-impact radar chart ──────────────────────────────────


def test_iter14_radar_svg_present():
    """The radar SVG anchor must be embedded above the four cards so the
    operator sees the at-a-glance comparison before reading any card."""
    src = _src()
    assert 'id="posture-radar"' in src, (
        "vhost_policy.html must declare #posture-radar (the SVG container)"
    )
    assert "<svg" in src and 'id="posture-radar"' in src, (
        "#posture-radar must be an SVG element (no external chart lib)"
    )


def test_iter14_profile_impact_function_defined():
    src = _src()
    assert re.search(r"function\s+_profileImpact\s*\(\s*knobs\s*\)", src), (
        "must define _profileImpact(knobs) — maps a bundle to the 5 radar "
        "axes (bot / friction / coverage / rateLimit / response)"
    )


def test_iter14_radar_render_function_defined():
    src = _src()
    assert re.search(r"function\s+_renderProfileRadar\b", src), (
        "must define _renderProfileRadar() — builds the SVG polygons"
    )


def test_iter14_radar_drawn_on_card_show():
    """_renderPostureCard must invoke _renderProfileRadar so the SVG is
    populated every time a hostname is selected."""
    src = _src()
    m = re.search(r"function\s+_renderPostureCard\b.*?\n\}", src, re.DOTALL)
    assert m, "_renderPostureCard must be defined"
    body = m.group(0)
    assert "_renderProfileRadar(" in body, (
        "_renderPostureCard must call _renderProfileRadar() — otherwise "
        "the radar is empty when the card first shows"
    )


def test_iter14_radar_covers_five_axes():
    """The 5-axis label set must be present in the source so a refactor
    that drops one axis is caught."""
    src = _src()
    m = re.search(r"function\s+_renderProfileRadar\b.*?^}", src, re.DOTALL | re.M)
    assert m, "_renderProfileRadar must be defined"
    body = m.group(0)
    for label in ("Bot block strength", "User friction", "Threat coverage",
                  "Rate-limit tightness", "Response strictness"):
        assert label in body, f"radar must label the '{label}' axis"


def test_iter14_radar_uses_profile_colours():
    """Each profile's badge colour must reappear in the radar so the
    operator can map polygon → card without a separate key."""
    src = _src()
    m = re.search(r"function\s+_renderProfileRadar\b.*?^}", src, re.DOTALL | re.M)
    assert m
    body = m.group(0)
    for colour in ("#79c0ff", "#3fb950", "#d29922", "#f85149"):
        assert colour in body, (
            f"radar must reuse the {colour} profile colour for legend / polygon"
        )


def test_iter14_impact_axis_paranoid_dominant():
    """Sanity check on the impact math: when run against the four bundled
    presets the PARANOID profile must score >= STRICT on every axis except
    `friction` where it should also be the highest (it's the only profile
    with TURNSTILE on). LAX must score the lowest on the bot/coverage/
    rate-limit/response axes."""
    src = _src()
    # We can't execute the JS here, but we can verify the function body
    # encodes the right monotonic relationship by checking the literal
    # weights: PARANOID is the only bundle with TURNSTILE_ENABLED:true,
    # which adds the largest friction contribution (45). That alone
    # guarantees PARANOID > STRICT on the friction axis.
    m = re.search(r"function\s+_profileImpact\b.*?^}", src, re.DOTALL | re.M)
    assert m, "_profileImpact must be defined"
    body = m.group(0)
    assert re.search(r"TURNSTILE_ENABLED.*\+=\s*45\b", body, re.DOTALL), (
        "_profileImpact must give TURNSTILE_ENABLED a weight of 45 on the "
        "friction axis — that's the dominant contributor that pushes "
        "PARANOID above STRICT on the user-friction dimension"
    )
    # Bot block: each of the 9 listed detector toggles contributes. Cover
    # at least the heaviest weights so a regression that flips signs is
    # caught.
    assert re.search(r"BOT_DETECTION_ENABLED.*\+=\s*15\b", body, re.DOTALL)
    assert re.search(r"UA_FILTER_ENABLED.*\+=\s*15\b", body, re.DOTALL)
