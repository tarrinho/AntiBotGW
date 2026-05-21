"""
tests/test_v1810_riskbreakdown_control_column.py — guards for the "control"
column added to the Risk-score-breakdown tooltip (live feed + agents).

Feature: each reason row in the Risk-score-breakdown popover now shows WHICH
control (knob) provokes that reason — sourced from the scoring endpoint's
per-signal `toggle` field (backed by SIGNAL_KNOB). Reasons with no kill-switch
show "always-on"; non-detection outcomes (e.g. banned-silent) show "—".

Groups
  S — server contract (SIGNAL_KNOB + scoring endpoint expose reason→toggle)
  U — UI: buildRiskHtml renders the control column + header, fed by the
      scoring endpoint, in BOTH main.html (live feed) and agents.html
"""
import os
import re

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")

def _read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()


# ── S: server contract ───────────────────────────────────────────────────────

class TestServerContract:
    def test_s01_signal_knob_maps_reasons_to_knobs(self):
        from core import proxy_handler as ph
        assert isinstance(ph.SIGNAL_KNOB, dict) and ph.SIGNAL_KNOB, (
            "SIGNAL_KNOB must be a non-empty reason→knob map"
        )
        # spot-check a couple of known mappings
        assert ph.SIGNAL_KNOB.get("referer-ghost") == "REFERER_CHAIN_ENABLED"
        assert ph.SIGNAL_KNOB.get("json-canary") == "JSON_CANARY_ENABLED"

    def test_s02_scoring_endpoint_emits_toggle_per_signal(self):
        # The UI reads `toggle` from each weights[] entry. Lock that the
        # endpoint still attaches SIGNAL_KNOB.get(sig) as "toggle".
        ph = _read("core/proxy_handler.py")
        assert '"toggle":' in ph and "SIGNAL_KNOB.get(sig)" in ph, (
            "scoring_endpoint must expose each signal's controlling knob as 'toggle'"
        )

    def test_s03_synthetic_reasons_mapped_to_controls(self):
        # Synthetic reasons (emitted by middleware, not in RISK_WEIGHTS) must
        # still resolve a control instead of "—" in the breakdown column.
        from core import proxy_handler as ph
        assert ph.SIGNAL_KNOB.get("chal-required") == "JS_CHALLENGE", (
            "chal-required must map to its JS_CHALLENGE control"
        )
        assert ph.SIGNAL_KNOB.get("pow-required") == "POW_REQUIRED_PATHS"
        # These reasons must RESOLVE (be present in the map) so the column shows
        # a control or "always-on" instead of "—". The exact value is the
        # operator's call (a knob name, or None for a mandatory/always-on gate).
        for r in ("admin-ip-blocked", "admin-probe", "operator-self"):
            assert r in ph.SIGNAL_KNOB, f"{r} must be present in SIGNAL_KNOB (no '—')"

    def test_s04_scoring_endpoint_exposes_full_signal_knob(self):
        # The weights[] array only covers RISK_WEIGHTS signals; the full
        # SIGNAL_KNOB map must be exposed so synthetic reasons resolve too.
        ph = _read("core/proxy_handler.py")
        assert re.search(r'"signal_knob":\s*dict\(SIGNAL_KNOB\)', ph), (
            "scoring_endpoint must return the full SIGNAL_KNOB map as signal_knob"
        )


# ── U: UI control column ─────────────────────────────────────────────────────

class TestRiskBreakdownColumn:
    PAGES = ["dashboards/main.html", "dashboards/agents.html"]

    def test_u01_loads_knob_map_from_scoring_endpoint(self):
        for p in self.PAGES:
            html = _read(p)
            assert "/antibot-appsec-gateway/secured/scoring" in html, (
                f"{p} must fetch the scoring endpoint for the reason→control map"
            )
            assert "_loadKnobs(" in html, f"{p} must define/call _loadKnobs"
            assert "w.toggle" in html, (
                f"{p} must read each signal's toggle (controlling knob)"
            )

    def test_u01b_prefers_full_signal_knob_map(self):
        # Must prefer the full signal_knob map (covers synthetic reasons) over
        # the weights-only fallback.
        for p in self.PAGES:
            html = _read(p)
            assert "d.signal_knob" in html, (
                f"{p} must build the control map from the full signal_knob map"
            )

    def test_u02_buildriskhtml_renders_control_cell(self):
        for p in self.PAGES:
            html = _read(p)
            assert "_ctrlCell(" in html, f"{p} must compute a control cell per row"
            assert 'class="rsn-ctrl' in html, f"{p} must render the rsn-ctrl column"

    def test_u03_has_control_header(self):
        for p in self.PAGES:
            html = _read(p)
            assert "rsn-head" in html, f"{p} must render a header row for the columns"
            assert ">control<" in html, f"{p} header must label the control column"

    def test_u04_always_on_and_dash_fallbacks(self):
        # Reasons with a null toggle → 'always-on'; reasons absent from the map
        # (ban outcomes etc.) → '—'. Both fallbacks must be present.
        for p in self.PAGES:
            html = _read(p)
            assert "'always-on'" in html, f"{p} must label no-kill-switch signals 'always-on'"
            assert "text: '—'" in html, f"{p} must fall back to '—' for non-detection reasons"

    def test_u05_grid_has_four_columns(self):
        # The .rsn grid must now have 4 tracks (name, control, bar, value) — the
        # original 3-track '1fr 60px 50px' must be gone.
        main = _read("dashboards/main.html")
        agents = _read("dashboards/agents.html")
        # main: .modal .rsn and #risk-pop .rsn
        for sel in [r"\.modal \.rsn\{[^}]*grid-template-columns:[^;]+;",
                    r"#risk-pop \.rsn\{[^}]*grid-template-columns:[^;]+;"]:
            m = re.search(sel, main)
            assert m, f"grid rule not found for {sel}"
            tracks = m.group()
            assert "rsn-ctrl" or "minmax" in tracks
            assert tracks.count("minmax(0,") >= 2, (
                f"main.html .rsn grid must have a control track (4 cols): {tracks}"
            )
        # agents: .popover .rsn
        m = re.search(r"\.popover \.rsn\{[^}]*grid-template-columns:[^;]+;", agents)
        assert m, "agents .popover .rsn grid rule not found"
        assert m.group().count("minmax(0,") >= 2, (
            "agents.html .rsn grid must have a control track (4 cols)"
        )

    def test_u06_old_three_col_grid_removed(self):
        # Ensure the legacy 3-track grid literal isn't left behind on these rows.
        for p in self.PAGES:
            html = _read(p)
            assert "grid-template-columns:1fr 60px 50px" not in html, (
                f"{p} still has the old 3-column .rsn grid"
            )
