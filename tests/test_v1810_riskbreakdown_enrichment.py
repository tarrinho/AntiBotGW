"""
tests/test_v1810_riskbreakdown_enrichment.py — guards for the enriched
Risk-score-breakdown control column:
  1. control on/off state dot      (server: knob_state ; UI: rsn-dot)
  2. clickable control → Controls   (UI: <a ...#knob=> ; controls.html deep-link)
  3. reason severity + description  (server: signal_meta ; UI: rsn-tier + tooltip)
  4. admin-ip-blocked → ADMIN_ALLOWED_IPS (correctness fix)
"""
import os
import re

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")

def _read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()

_DASH = ["dashboards/main.html", "dashboards/agents.html"]


# ── 1. server: knob_state + signal_meta + admin-ip-blocked fix ────────────────

class TestServerEnrichment:
    def test_admin_ip_blocked_maps_to_allowlist(self):
        from core import proxy_handler as ph
        assert ph.SIGNAL_KNOB.get("admin-ip-blocked") == "ADMIN_ALLOWED_IPS", (
            "admin-ip-blocked must resolve to its real control ADMIN_ALLOWED_IPS"
        )

    def test_scoring_returns_knob_state(self):
        ph = _read("core/proxy_handler.py")
        assert '"knob_state":' in ph, "scoring endpoint must return knob_state"
        # rich object: {on, kind, display} so the UI can show a dot OR a value
        idx = ph.find("knob_state = {}")
        block = ph[idx:idx + 1200]
        for key in ('"on":', '"kind":', '"display":'):
            assert key in block, f"knob_state entries must include {key}"

    def test_scoring_returns_knob_page(self):
        ph = _read("core/proxy_handler.py")
        assert '"knob_page":' in ph, "scoring endpoint must return knob_page (deep-link target)"
        assert "_SETTINGS_KNOBS" in ph, "must classify settings-resident knobs"

    def test_scoring_returns_signal_meta(self):
        ph = _read("core/proxy_handler.py")
        assert '"signal_meta":' in ph, "scoring endpoint must return signal_meta"
        # must carry weight + tier + desc per reason
        idx = ph.find("signal_meta = {}")
        assert idx != -1
        block = ph[idx:idx + 400]
        for key in ('"weight"', '"tier"', '"desc"'):
            assert key in block, f"signal_meta entries must include {key}"

    def test_signal_meta_covers_synthetic_reasons(self):
        # signal_meta is built from SIGNAL_KNOB (scored + synthetic), so
        # chal-required etc. get a meta entry too.
        ph = _read("core/proxy_handler.py")
        idx = ph.find("for _rsn, _kn in SIGNAL_KNOB.items():")
        assert idx != -1, "signal_meta must iterate the full SIGNAL_KNOB map"


# ── 2. UI: state dot + clickable link + severity badge + tooltip ──────────────

class TestUiEnrichment:
    def test_loadknobs_stores_state_and_meta(self):
        for p in _DASH:
            html = _read(p)
            assert "_knobState" in html and "d.knob_state" in html, (
                f"{p} must read knob_state from the scoring response"
            )
            assert "_signalMeta" in html and "d.signal_meta" in html, (
                f"{p} must read signal_meta from the scoring response"
            )

    def test_ctrlcell_returns_knob_and_state(self):
        for p in _DASH:
            html = _read(p)
            assert "on: !!st.on" in html, (
                f"{p} _ctrlCell must read on/kind/display from the knob_state object"
            )
            assert "kind: st.kind" in html and "page: _knobPage[knob]" in html, (
                f"{p} _ctrlCell must expose kind + page for the row builder"
            )

    def test_control_is_clickable_deep_link(self):
        for p in _DASH:
            html = _read(p)
            # page-aware link: /secured/<page>#knob=<encoded>
            assert "secured/' + page + '#knob='" in html, (
                f"{p} control link must target the knob's actual page (controls/settings)"
            )
            assert "encodeURIComponent(ctrl.knob)" in html, (
                f"{p} must URL-encode the knob name in the deep link"
            )

    def test_refresh_on_modal_open(self):
        # On opening the risk breakdown, the page must refetch control state so
        # the dots/values are live (not frozen at page load).
        for p in _DASH:
            html = _read(p)
            assert "refreshKnobs" in html, f"{p} must expose/call refreshKnobs"
            assert "_loadKnobs(true)" in html, (
                f"{p} refreshKnobs must force a re-fetch (bypass cache)"
            )

    def test_value_badge_for_non_bool(self):
        for p in _DASH:
            html = _read(p)
            assert "rsn-kv" in html, (
                f"{p} must render a value badge (rsn-kv) for non-bool controls"
            )
            assert "ctrl.kind === 'bool'" in html, (
                f"{p} must branch on control kind (dot for bool, value otherwise)"
            )

    def test_state_dot_rendered(self):
        for p in _DASH:
            html = _read(p)
            assert "rsn-dot" in html, f"{p} must render the on/off state dot"
            assert "ctrl.on?'on':'off'" in html or 'ctrl.on?"on":"off"' in html, (
                f"{p} dot must reflect the control's enabled state"
            )

    def test_tier_badge_and_tooltip(self):
        for p in _DASH:
            html = _read(p)
            assert "rsn-tier t-" in html, f"{p} must render the severity tier badge"
            assert "_reasonMeta(reason)" in html, (
                f"{p} must look up per-reason meta for the badge/tooltip"
            )
            # description tooltip on the reason name
            assert 'class="rsn-name" title="${rdesc}"' in html, (
                f"{p} reason name must carry a description tooltip"
            )

    def test_tier_css_present(self):
        for p in _DASH:
            html = _read(p)
            for cls in ("rsn-tier.t-info", "rsn-tier.t-hard", "rsn-dot.on", "a.rsn-ctrl"):
                assert cls in html, f"{p} missing CSS rule for .{cls}"


# ── 3. controls.html deep-link target ────────────────────────────────────────

class TestControlsDeepLink:
    _HTML = _read("dashboards/controls.html")

    def test_deeplink_function_exists(self):
        assert "_deepLinkToKnob" in self._HTML, "controls.html must define _deepLinkToKnob"

    def test_deeplink_reads_hash(self):
        assert re.search(r"location\.hash[^\n]*knob=", self._HTML), (
            "deep-link must parse #knob=NAME from location.hash"
        )

    def test_deeplink_switches_section_and_scrolls(self):
        idx = self._HTML.find("function _deepLinkToKnob")
        body = self._HTML[idx:idx + 1200]
        assert "_knobSec(" in body and "_switch(" in body, (
            "deep-link must switch to the knob's section"
        )
        assert "scrollIntoView" in body, "deep-link must scroll the knob into view"
        assert "knob-deeplink-flash" in body, "deep-link must flash-highlight the knob"

    def test_deeplink_invoked_on_load_and_hashchange(self):
        assert "_deepLinkToKnob();" in self._HTML, "deep-link must run on init"
        assert "addEventListener('hashchange', _deepLinkToKnob)" in self._HTML, (
            "deep-link must also run on hashchange"
        )

    def test_flash_css_present(self):
        assert "knob-deeplink-flash" in self._HTML and "@keyframes knobFlash" in self._HTML, (
            "controls.html must define the deep-link flash highlight CSS"
        )


# ── 4. round-2 improvements: descriptions, settings deep-link, graceful toast ─

class TestRound2Improvements:
    def test_synthetic_reasons_have_descriptions(self):
        # signal_meta pulls tier+desc from DESCRIPTIONS — synthetic reasons must
        # now have entries so the tooltip isn't empty.
        ph = _read("core/proxy_handler.py")
        di = ph.find("DESCRIPTIONS = {")
        de = ph.find("SIGNAL_COST = {", di)
        block = ph[di:de]
        for r in ("chal-required", "pow-required", "admin-probe", "operator-self",
                  "admin-ip-blocked", "banned-silent"):
            assert f'"{r}":' in block, f"DESCRIPTIONS must describe synthetic reason {r}"

    def test_settings_has_deeplink_handler(self):
        s = _read("dashboards/settings.html")
        assert "_settingsDeepLink" in s, "settings.html must handle #knob= deep-links"
        assert re.search(r"location\.hash[^\n]*knob=", s), (
            "settings deep-link must parse #knob=NAME"
        )
        assert "data-ikey=" in s, "settings deep-link targets infra rows by data-ikey"
        assert "knob-deeplink-flash" in s and "@keyframes knobFlash" in s, (
            "settings.html must define the flash highlight"
        )

    def test_settings_routes_admin_allowlist(self):
        s = _read("dashboards/settings.html")
        assert "ADMIN_ALLOWED_IPS" in s and "admin-ips" in s, (
            "settings deep-link must handle ADMIN_ALLOWED_IPS → admin-ips card"
        )

    def test_controls_deeplink_graceful_when_missing(self):
        c = _read("dashboards/controls.html")
        idx = c.find("function _deepLinkToKnob")
        body = c[idx:idx + 1400]
        assert "showToast(" in body, (
            "controls deep-link must toast (not silently no-op) when the knob "
            "isn't a Controls toggle"
        )

    def test_non_bool_knob_state_classified(self):
        # bool / num / list knobs get distinct kind so the UI shows dot vs value.
        ph = _read("core/proxy_handler.py")
        idx = ph.find("knob_state = {}")
        block = ph[idx:idx + 1200]
        for kind in ('"bool"', '"num"', '"list"'):
            assert kind in block, f"knob_state must classify {kind} controls"
