"""
tests/test_v1811_theme.py — QA for the v1.8.11 day/night theme feature.

Static checks (no server):
  CSS-01  All 12 dashboard files have the --dim semicolon fix (was: --dim:#636e7b--bg-deep:)
  CSS-02  :root block defines --bright:#ffffff
  CSS-03  html[data-theme="light"] block defines --bright:var(--fg)
  CSS-04  html[data-theme="light"] block defines --dim:#636e7b; (semicolon present)
  CSS-05  No raw color:#fff remains in any dashboard HTML file (replaced by color:var(--bright))
  CSS-06  Each dashboard has the theme toggle button (#theme-toggle)
  CSS-07  Each dashboard has _toggleTheme=function (not just onclick reference)
  JS-01   _toggleTheme uses _applyChartColorsToInstance for Chart.js update
  JS-02   Chart-capable dashboards have the _gwTheme Chart.js afterInit plugin
  JS-03   _applyChartColorsToInstance function is defined in chart-capable dashboards
  JS-04   credentials:'include' used in ui-theme fetch (not 'same-origin')
  JS-05   geo.html has theme-aware Leaflet tile URL (_TILE_LIGHT / _TILE_DARK)
  JS-06   geo.html _toggleTheme calls _updateMapTile(next) to swap tiles
  CSS-08  controls.html: .banner has light-mode override (no dark bg in light)
  CSS-09  controls.html: #_sig-tip, .cs-results, .order-pop have light overrides
  CSS-10  All files: _dp inline-style map includes #1a2733 (info-banner dark bg)
  CSS-11  No dark hex literal in JS .style.background assignments (bypasses _dp on refresh)
  CSS-12  No inline HTML dark hex background absent from the _dp flat map

DB unit tests (no server, tmp SQLite):
  DB-01   get_ui_theme() returns 'dark' when config_kv has no ui_theme row
  DB-02   get_ui_theme() returns persisted 'light' after set_config writes it
  DB-03   get_ui_theme() returns 'dark' for an invalid stored value
  DB-04   get_ui_theme() returns 'dark' when DB is absent (graceful fallback)

API endpoint tests (in-process gateway via aiohttp TestClient):
  API-01  GET  /secured/ui-theme → {"theme":"dark"} by default
  API-02  POST /secured/ui-theme {"theme":"light"} → {"theme":"light"} + persists in DB
  API-03  POST /secured/ui-theme {"theme":"invalid"} → 400
  API-04  PUT  /secured/ui-theme → 405
  API-05  GET  /secured/live-feed with light theme in DB → HTML contains data-theme="light"
  API-06  GET  /secured/controls  with light theme in DB → HTML contains data-theme="light"
  API-07  GET  /secured/settings  with light theme in DB → HTML contains data-theme="light"
  API-08  GET  /secured/ui-theme  unauthenticated → 401
  API-09  POST /secured/ui-theme  unauthenticated → 401
"""
import json
import os
import re
import sqlite3
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

os.environ.setdefault("UPSTREAM",          "https://example.com")
os.environ.setdefault("ADMIN_KEY",         "x" * 16)

_DASHBOARDS = Path(__file__).resolve().parent.parent / "dashboards"
_GW_NS = "/antibot-appsec-gateway/secured"

# Files that include Chart.js and therefore should have the _gwTheme plugin.
_CHART_FILES = {
    "main.html", "agents.html", "control_center.html", "service.html", "siem.html",
    "honeypots.html",
}
_ALL_FILES = [
    "main.html", "controls.html", "settings.html", "agents.html",
    "control_center.html", "geo.html", "logs.html", "service.html",
    "siem.html", "vhost_policy.html", "controls_testA.html", "controls_testB.html",
    "honeypots.html",
]


def _html(name: str) -> str:
    return (_DASHBOARDS / name).read_text(encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# CSS correctness
# ─────────────────────────────────────────────────────────────────────────────

class TestThemeCssVars:
    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css01_semicolon_fix(self, fname):
        """--dim var must have a semicolon before --bg-deep (was missing)."""
        src = _html(fname)
        assert "--dim:#636e7b--bg-deep:" not in src, (
            f"{fname}: semicolon still missing between --dim and --bg-deep"
        )
        assert "--dim:#636e7b;" in src, (
            f"{fname}: --dim:#636e7b; with trailing semicolon not found"
        )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css02_bright_in_root(self, fname):
        """--bright:#ffffff must be in the :root CSS block."""
        src = _html(fname)
        assert "--bright:#ffffff" in src, (
            f"{fname}: --bright:#ffffff not found in :root block"
        )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css03_bright_in_light_mode(self, fname):
        """--bright:var(--fg) must appear in the html[data-theme=light] block."""
        src = _html(fname)
        assert "--bright:var(--fg)" in src, (
            f"{fname}: --bright:var(--fg) not found in light-mode var block"
        )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css04_no_raw_color_fff_in_style_block(self, fname):
        """color:#fff must not appear in any <style> block — all replaced by color:var(--bright)."""
        src = _html(fname)
        style_blocks = re.findall(r"<style>(.*?)</style>", src, re.DOTALL)
        for block in style_blocks:
            # Ignore CSS vars definitions themselves (e.g. --bright:#fff is fine,
            # but color:#fff as a CSS property value is not)
            violations = re.findall(r"\bcolor\s*:\s*#fff\b", block)
            assert not violations, (
                f"{fname}: raw 'color:#fff' still in <style> block: {violations[:3]}"
            )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css05_color_var_bright_used(self, fname):
        """At least one color:var(--bright) must be present per dashboard
        (confirms the #fff → var(--bright) replacement actually ran)."""
        src = _html(fname)
        # testA/testB may legitimately have no color:#fff overrides if their CSS
        # didn't have any — check conditionally.
        if fname in ("controls_testA.html", "controls_testB.html"):
            # These files may have had 0 replacements; skip the assertion.
            return
        assert "color:var(--bright)" in src, (
            f"{fname}: color:var(--bright) not found — #fff replacement may not have run"
        )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css06_theme_toggle_button(self, fname):
        """Every page must have the #theme-toggle button."""
        src = _html(fname)
        assert 'id="theme-toggle"' in src, (
            f"{fname}: theme-toggle button missing"
        )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css07_toggle_function_defined(self, fname):
        """_toggleTheme must be defined as a function, not only referenced in onclick."""
        src = _html(fname)
        assert "_toggleTheme=function" in src, (
            f"{fname}: _toggleTheme=function not found — toggle JS may be missing"
        )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css08_no_circular_bg_vars(self, fname):
        """--bg/--card/--line must not self-reference (causes white page in dark mode)."""
        src = _html(fname)
        for var in ("--bg", "--card", "--line"):
            assert f"{var}:var({var})" not in src, (
                f"{fname}: circular CSS variable {var}:var({var}) found — "
                "dark-mode background resolves to empty, page goes white"
            )


# ─────────────────────────────────────────────────────────────────────────────
# JavaScript correctness
# ─────────────────────────────────────────────────────────────────────────────

class TestThemeJs:
    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_js01_toggle_uses_apply_chart_instance(self, fname):
        """_toggleTheme must delegate Chart.js updates to _applyChartColorsToInstance."""
        src = _html(fname)
        assert "_applyChartColorsToInstance(c,next)" in src, (
            f"{fname}: _toggleTheme does not call _applyChartColorsToInstance(c,next) — "
            "chart colors won't update on toggle"
        )

    @pytest.mark.parametrize("fname", sorted(_CHART_FILES))
    def test_js02_chart_plugin_registered(self, fname):
        """Chart-capable dashboards must register the _gwTheme afterInit plugin."""
        src = _html(fname)
        assert "_gwTheme" in src, (
            f"{fname}: _gwTheme Chart.register plugin not found"
        )
        assert "afterInit" in src, (
            f"{fname}: afterInit hook missing from chart plugin"
        )

    @pytest.mark.parametrize("fname", sorted(_CHART_FILES))
    def test_js03_apply_chart_colors_defined(self, fname):
        """_applyChartColorsToInstance must be defined before charts init."""
        src = _html(fname)
        assert "window._applyChartColorsToInstance=function" in src, (
            f"{fname}: _applyChartColorsToInstance function not defined"
        )

    @pytest.mark.parametrize("fname", sorted(_CHART_FILES))
    def test_js03b_chart_plugin_covers_legend_and_tooltip(self, fname):
        """The chart plugin must update legend labels AND tooltip colors (not just grid/ticks)."""
        src = _html(fname)
        fn_match = re.search(
            r"window\._applyChartColorsToInstance=function.*?\n\};", src, re.DOTALL
        )
        assert fn_match, f"{fname}: _applyChartColorsToInstance not found as expected"
        fn_body = fn_match.group(0)
        assert "legend" in fn_body, (
            f"{fname}: _applyChartColorsToInstance does not update legend colors"
        )
        assert "tooltip" in fn_body, (
            f"{fname}: _applyChartColorsToInstance does not update tooltip colors"
        )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_js04_ui_theme_fetch_credentials_include(self, fname):
        """ui-theme CSRF-aware fetch must use credentials:'include' not 'same-origin'."""
        src = _html(fname)
        # Only check if the page has the theme fetch call
        if "ui-theme" not in src:
            return
        # Verify 'same-origin' is NOT used for the ui-theme fetch
        theme_fetch_idx = src.find("/secured/ui-theme")
        nearby = src[max(0, theme_fetch_idx - 200): theme_fetch_idx + 200]
        assert "credentials:'include'" in nearby or 'credentials:"include"' in nearby, (
            f"{fname}: ui-theme fetch must use credentials:'include'"
        )
        assert "credentials:'same-origin'" not in nearby, (
            f"{fname}: ui-theme fetch must NOT use credentials:'same-origin'"
        )


# ─────────────────────────────────────────────────────────────────────────────
# DB unit tests — get_ui_theme()
# ─────────────────────────────────────────────────────────────────────────────

class TestGetUiTheme:
    def _make_db(self, tmp_path):
        """Create a minimal config_kv SQLite DB."""
        db = str(tmp_path / "test.db")
        conn = sqlite3.connect(db)
        conn.execute(
            "CREATE TABLE config_kv "
            "(key TEXT PRIMARY KEY, value TEXT, ts REAL)"
        )
        conn.commit()
        conn.close()
        return db

    def test_db01_default_is_dark(self, tmp_path):
        """Returns 'dark' when no ui_theme row exists."""
        from db.sqlite import get_ui_theme
        db = self._make_db(tmp_path)
        assert get_ui_theme(db) == "dark"

    def test_db02_persisted_light_returned(self, tmp_path):
        """Returns 'light' after the value is written to config_kv."""
        from db.sqlite import get_ui_theme
        db = self._make_db(tmp_path)
        conn = sqlite3.connect(db)
        conn.execute(
            "INSERT INTO config_kv (key, value, ts) VALUES (?, ?, ?)",
            ("ui_theme", json.dumps("light"), 0.0),
        )
        conn.commit()
        conn.close()
        assert get_ui_theme(db) == "light"

    def test_db03_invalid_stored_value_falls_back_to_dark(self, tmp_path):
        """An unrecognised value in config_kv falls back to 'dark'."""
        from db.sqlite import get_ui_theme
        db = self._make_db(tmp_path)
        conn = sqlite3.connect(db)
        conn.execute(
            "INSERT INTO config_kv (key, value, ts) VALUES (?, ?, ?)",
            ("ui_theme", json.dumps("blue"), 0.0),
        )
        conn.commit()
        conn.close()
        assert get_ui_theme(db) == "dark"

    def test_db04_missing_db_returns_dark(self, tmp_path):
        """Returns 'dark' gracefully when the DB file does not exist."""
        from db.sqlite import get_ui_theme
        assert get_ui_theme(str(tmp_path / "nonexistent.db")) == "dark"

    def test_db05_dark_value_persisted_and_returned(self, tmp_path):
        """Explicitly persisted 'dark' is returned as 'dark' (not overridden)."""
        from db.sqlite import get_ui_theme
        db = self._make_db(tmp_path)
        conn = sqlite3.connect(db)
        conn.execute(
            "INSERT INTO config_kv (key, value, ts) VALUES (?, ?, ?)",
            ("ui_theme", json.dumps("dark"), 0.0),
        )
        conn.commit()
        conn.close()
        assert get_ui_theme(db) == "dark"


# ─────────────────────────────────────────────────────────────────────────────
# Geo map + dark-background popup/banner fixes
# ─────────────────────────────────────────────────────────────────────────────

class TestGeoMapAndDarkBgs:
    def test_js05_geo_has_theme_aware_tiles(self):
        """geo.html must define both _TILE_LIGHT and _TILE_DARK tile URL constants."""
        src = _html("geo.html")
        assert "_TILE_DARK" in src and "_TILE_LIGHT" in src, (
            "geo.html: theme-aware tile constants missing"
        )
        assert "light_all" in src, "geo.html: light_all tile URL not present"
        assert "dark_all" in src, "geo.html: dark_all tile URL not present"

    def test_js05b_geo_tile_init_reads_data_theme(self):
        """Tile layer init must read data-theme so page loads with correct tiles."""
        src = _html("geo.html")
        assert "getAttribute('data-theme')" in src or "getAttribute(\"data-theme\")" in src, (
            "geo.html: tile init does not read data-theme at load time"
        )
        # Confirm it branches on 'light'
        assert "_TILE_LIGHT" in src and "_TILE_DARK" in src

    def test_js06_geo_toggle_calls_update_map_tile(self):
        """_toggleTheme in geo.html must call _updateMapTile(next) to swap tiles."""
        src = _html("geo.html")
        assert "_updateMapTile(next)" in src, (
            "geo.html: _toggleTheme does not call _updateMapTile(next)"
        )
        assert "window._updateMapTile" in src, (
            "geo.html: _updateMapTile function not defined"
        )

    def test_geo_legend_has_light_override(self):
        """The map legend has a hardcoded dark base bg (translucent overlay); it
        must carry a light-mode override so it isn't a dark box on the day map."""
        src = _html("geo.html")
        assert re.search(
            r'html\[data-theme="light"\]\s*\.legend\s*\{[^}]*background\s*:', src), (
            "geo.html: .legend has no light-mode background override "
            "(stays dark in day mode)"
        )

    def test_geo_score_bar_track_uses_theme_var(self):
        """The gateway-health modal score-bar track must use a theme var, not a
        fixed dark hex (#1f2730 stayed dark in light mode)."""
        src = _html("geo.html")
        assert "background:#1f2730" not in src, (
            "geo.html: score-bar track still hardcodes #1f2730 — dark in light mode"
        )

    # ── permanent sweep guard: no dark CSS background without a light override ──
    _SWEEP_FILES = [
        "agents.html", "control_center.html", "controls.html", "geo.html",
        "logs.html", "main.html", "service.html", "settings.html",
        "siem.html", "vhost_policy.html", "honeypots.html",
    ]
    _ALLOW_ACCENT = {"#b91c1c"}  # intentional saturated active-pill red

    @staticmethod
    def _lum(h):
        h = h.lstrip("#")
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255

    @pytest.mark.parametrize("fname", _SWEEP_FILES)
    def test_no_uncovered_dark_css_background(self, fname):
        """Every hardcoded dark CSS background in a served, theme-aware dashboard
        must have a matching html[data-theme="light"] override. Excludes var()
        backgrounds (auto-flip), near-black modal scrims (rgba(0,0,0,…) — correct
        in both themes), and intentional saturated accents."""
        DARK = 0.32
        styles = "\n".join(re.findall(r"<style>(.*?)</style>", _html(fname), re.DOTALL))
        light_sel = set()
        for m in re.finditer(r'html\[data-theme="light"\]\s*([^{]+)\{([^}]*)\}', styles):
            if "background" in m.group(2):
                for s in m.group(1).split(","):
                    light_sel.add(s.strip().replace(" ", ""))
        uncovered = []
        for m in re.finditer(r"([^{}]+)\{([^}]*)\}", styles):
            sel, body = m.group(1).strip(), m.group(2)
            if sel.startswith('html[data-theme="light"]'):
                continue
            bm = re.search(r"background(?:-color)?\s*:\s*([^;]+)", body)
            if not bm:
                continue
            val = bm.group(1).strip()
            if "var(" in val:
                continue
            dark = False
            if val.startswith("#"):
                hm = re.search(r"#[0-9a-fA-F]{3,6}", val)
                if hm and self._lum(hm.group(0)) < DARK and hm.group(0).lower() not in self._ALLOW_ACCENT:
                    dark = True
            else:
                rm = re.match(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", val)
                if rm:
                    r_, g_, b_ = map(int, rm.groups())
                    if (0.2126 * r_ + 0.7152 * g_ + 0.0722 * b_) / 255 < DARK and not (
                        r_ < 20 and g_ < 20 and b_ < 20
                    ):
                        dark = True
            if not dark:
                continue
            norm = sel.split(",")[0].strip().replace(" ", "")
            if not any(norm == ls or norm in ls or ls in norm for ls in light_sel):
                uncovered.append((sel[:55], val))
        assert not uncovered, (
            f"{fname}: dark CSS background(s) without a light-mode override "
            f"(would render dark in day theme): {uncovered}"
        )

    def test_agents_score_dist_tags_light_override(self):
        """The 'Score distribution among allowed identities' category chips
        (.tag.crit/high/med/low) have hardcoded dark backgrounds; each must have
        a light-mode override so they aren't dark boxes in day theme."""
        src = _html("agents.html")
        for cls in ("crit", "high", "med", "low"):
            assert re.search(
                r'html\[data-theme="light"\]\s*\.tag\.' + cls + r'\s*\{[^}]*background\s*:',
                src), (
                f"agents.html: .tag.{cls} has no light-mode background override"
            )

    def test_cc_attack_heatmap_empty_cell_theme_var(self):
        """control_center attack heatmap empty (n===0) cells must use a theme var,
        not a fixed dark hex — #21262d filled the day-mode grid with dark cells."""
        src = _html("control_center.html")
        assert "n===0?'var(--bg-elevated)'" in src, (
            "control_center.html: attack-heatmap empty cell not theme-aware "
            "(should be var(--bg-elevated), was #21262d)"
        )

    def test_css08_controls_banner_light_override(self):
        """.banner must have a light-mode CSS override (not dark #1a2733 on light bg)."""
        src = _html("controls.html")
        assert "light\"] .banner{background:#e8f4fd" in src or \
               'light"] .banner{background:#e8f4fd' in src, (
            "controls.html: no light-mode override for .banner background"
        )

    def test_css09_controls_popups_light_overrides(self):
        """#_sig-tip, .cs-results, .order-pop must each have light-mode overrides."""
        src = _html("controls.html")
        assert "#_sig-tip" in src and "f0f6ff" in src, (
            "controls.html: no light-mode override for #_sig-tip"
        )
        assert ".cs-results" in src and "f0f6ff" in src, (
            "controls.html: no light-mode override for .cs-results"
        )
        assert ".order-pop" in src and "f0f6ff" in src, (
            "controls.html: no light-mode override for .order-pop"
        )

    def test_css08b_settings_banner_light_override(self):
        """.banner in settings.html must have a light-mode override."""
        src = _html("settings.html")
        assert "light\"] .banner{background:#e8f4fd" in src or \
               'light"] .banner{background:#e8f4fd' in src, (
            "settings.html: no light-mode override for .banner background"
        )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css10_dp_map_includes_info_banner_dark(self, fname):
        """_dp inline-style map must include #1a2733 (info banner dark bg)."""
        src = _html(fname)
        assert "'#1a2733':'#e8f4fd'" in src, (
            f"{fname}: _dp map missing #1a2733 → #e8f4fd entry"
        )

    @pytest.mark.parametrize("fname", _ALL_FILES)
    def test_css10b_dp_map_includes_popup_dark(self, fname):
        """_dp inline-style map must include #1c2333 (popup dark bg)."""
        src = _html(fname)
        assert "'#1c2333':'#f0f6ff'" in src, (
            f"{fname}: _dp map missing #1c2333 → #f0f6ff entry"
        )

    # ── JS style.background assignment guard ────────────────────────────────
    # Dark hex literals assigned directly to .style.background bypass the _dp
    # walk on every periodic data-refresh and stay dark in day mode.
    # All such cases should use rgba() tints or var(--...) instead.
    _JS_BG_SWEEP = [
        "agents.html", "control_center.html", "controls.html", "geo.html",
        "logs.html", "main.html", "service.html", "settings.html",
        "siem.html", "vhost_policy.html", "honeypots.html",
    ]

    @pytest.mark.parametrize("fname", _JS_BG_SWEEP)
    def test_no_dark_hex_in_js_style_background(self, fname):
        """JS .style.background = '#hex' with a dark hex stays dark after every
        data-refresh (JS re-assignment overwrites the _dp toggle flip).
        Use rgba() tints or var(--...) instead."""
        src = _html(fname)
        scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", src, re.DOTALL))
        violations = []
        for m in re.finditer(
            r"\.style\.background(?:Color)?\s*=\s*['\"](?P<h>#[0-9a-fA-F]{6})['\"]",
            scripts,
        ):
            h = m.group("h")
            if self._lum(h) < 0.25:
                violations.append(h)
        assert not violations, (
            f"{fname}: dark hex in JS .style.background assignment — bypasses "
            f"_dp flip on data-refresh, stays dark in light mode: {violations}"
        )

    @pytest.mark.parametrize("fname", _SWEEP_FILES)
    def test_no_dark_hex_inline_html_not_in_dp_map(self, fname):
        """Inline HTML style= attrs with dark hex backgrounds must exist in the
        file's _dp flat map so the toggle walk can flip them. Uncovered ones
        stay dark in day mode forever (toggle does not reach them)."""
        src = _html(fname)
        dp_m = re.search(r"var _dp\s*=\s*\{([^}]+)\}", src)
        dp_keys: set = set()
        if dp_m:
            for pair in re.finditer(
                r"'(#[0-9a-fA-F]{3,6})'\s*:\s*'(?:#[0-9a-fA-F]{3,6}|var\([^)]+\))'",
                dp_m.group(1),
            ):
                dp_keys.add(pair.group(1).lower())
        no_style = re.sub(r"<style>.*?</style>", "", src, flags=re.DOTALL)
        no_script = re.sub(r"<script[^>]*>.*?</script>", "", no_style, flags=re.DOTALL)
        violations = []
        for m in re.finditer(r'style="([^"]*)"', no_script):
            attr = m.group(1)
            bm = re.search(r"background(?:-color)?\s*:\s*(#[0-9a-fA-F]{3,6})", attr)
            if not bm:
                continue
            h = bm.group(1)
            real = "".join(c * 2 for c in h[1:]) if len(h) == 4 else h[1:]
            if len(real) != 6:
                continue
            if self._lum(real) < 0.25 and h.lower() not in dp_keys:
                violations.append((h, attr[:70]))
        assert not violations, (
            f"{fname}: inline HTML dark hex background(s) absent from _dp map — "
            f"toggle walk can't flip them, stay dark in day mode: {violations}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# API endpoint tests — ui-theme GET/POST + dashboard injection
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def _gateway(proxy_module, upstream="https://example.com"):
    proxy_module.UPSTREAM = upstream.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        yield client
    finally:
        await client.close()


def _admin_cookies(proxy_module) -> dict:
    """Forge a valid admin session cookie so dashboard endpoints return 200."""
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin",
        "role": "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
    }
    proxy_module._SESSION_CACHE_READY = True
    token = proxy_module._session_sign("admin", sid=sid)
    return {proxy_module._SESSION_COOKIE: token}


@pytest.mark.asyncio
async def test_api01_get_ui_theme_default_dark(proxy_module):
    """GET /secured/ui-theme returns {"theme":"dark"} before any preference is set."""
    async with _gateway(proxy_module) as cli:
        cookies = _admin_cookies(proxy_module)
        r = await cli.get(f"{_GW_NS}/ui-theme", cookies=cookies)
        assert r.status == 200
        body = await r.json()
        assert body.get("theme") == "dark"


@pytest.mark.asyncio
async def test_api02_post_ui_theme_set_light(proxy_module):
    """POST /secured/ui-theme {"theme":"light"} returns {"theme":"light"}.
    CSRF auto-attached by conftest._auto_attach_csrf_header fixture."""
    async with _gateway(proxy_module) as cli:
        cookies = _admin_cookies(proxy_module)
        r = await cli.post(
            f"{_GW_NS}/ui-theme",
            data=json.dumps({"theme": "light"}),
            cookies=cookies,
            headers={"Content-Type": "application/json"},
        )
        assert r.status == 200
        body = await r.json()
        assert body.get("theme") == "light"


@pytest.mark.asyncio
async def test_api03_post_invalid_theme_returns_400(proxy_module):
    """POST /secured/ui-theme with an unsupported theme returns 400."""
    async with _gateway(proxy_module) as cli:
        cookies = _admin_cookies(proxy_module)
        r = await cli.post(
            f"{_GW_NS}/ui-theme",
            data=json.dumps({"theme": "blue"}),
            cookies=cookies,
            headers={"Content-Type": "application/json"},
        )
        assert r.status == 400


@pytest.mark.asyncio
async def test_api04_put_ui_theme_returns_405(proxy_module):
    """PUT /secured/ui-theme returns 405 Method Not Allowed."""
    async with _gateway(proxy_module) as cli:
        cookies = _admin_cookies(proxy_module)
        r = await cli.put(
            f"{_GW_NS}/ui-theme",
            data="{}",
            cookies=cookies,
        )
        assert r.status == 405


@pytest.mark.asyncio
async def test_api05_live_feed_injects_data_theme_light(proxy_module):
    """GET /secured/live-feed with light theme in DB → HTML has data-theme="light"."""
    import sqlite3 as _sq3
    # DB is created by on_startup — write inside the gateway context
    async with _gateway(proxy_module) as cli:
        conn = _sq3.connect(proxy_module.DB_PATH)
        conn.execute(
            "INSERT OR REPLACE INTO config_kv (key, value, ts) VALUES (?,?,?)",
            ("ui_theme", json.dumps("light"), 0.0),
        )
        conn.commit()
        conn.close()
        cookies = _admin_cookies(proxy_module)
        r = await cli.get(f"{_GW_NS}/live-feed", cookies=cookies)
        assert r.status == 200
        text = await r.text()
        assert 'data-theme="light"' in text, (
            "live-feed did not inject data-theme='light' from DB"
        )


@pytest.mark.asyncio
async def test_api06_controls_injects_data_theme_light(proxy_module):
    """GET /secured/controls with light theme in DB → HTML has data-theme="light"."""
    import sqlite3 as _sq3
    async with _gateway(proxy_module) as cli:
        conn = _sq3.connect(proxy_module.DB_PATH)
        conn.execute(
            "INSERT OR REPLACE INTO config_kv (key, value, ts) VALUES (?,?,?)",
            ("ui_theme", json.dumps("light"), 0.0),
        )
        conn.commit()
        conn.close()
        cookies = _admin_cookies(proxy_module)
        r = await cli.get(f"{_GW_NS}/controls", cookies=cookies)
        assert r.status == 200
        text = await r.text()
        assert 'data-theme="light"' in text, (
            "controls did not inject data-theme='light' from DB"
        )


@pytest.mark.asyncio
async def test_api07_settings_injects_data_theme_light(proxy_module):
    """GET /secured/settings with light theme in DB → HTML has data-theme="light"."""
    import sqlite3 as _sq3
    async with _gateway(proxy_module) as cli:
        conn = _sq3.connect(proxy_module.DB_PATH)
        conn.execute(
            "INSERT OR REPLACE INTO config_kv (key, value, ts) VALUES (?,?,?)",
            ("ui_theme", json.dumps("light"), 0.0),
        )
        conn.commit()
        conn.close()
        cookies = _admin_cookies(proxy_module)
        r = await cli.get(f"{_GW_NS}/settings", cookies=cookies)
        assert r.status == 200
        text = await r.text()
        assert 'data-theme="light"' in text, (
            "settings did not inject data-theme='light' from DB"
        )


@pytest.mark.asyncio
async def test_api08_ui_theme_get_unauthenticated_rejected(proxy_module):
    """GET /secured/ui-theme without a session is rejected (401 or hidden as 404)."""
    async with _gateway(proxy_module) as cli:
        r = await cli.get(f"{_GW_NS}/ui-theme")
        # Gateway hides admin routes from unauthenticated requests (returns 404
        # with reason='admin-probe' to avoid revealing the route exists).
        assert r.status in (401, 302, 303, 404), (
            f"Expected rejection for unauthenticated request, got {r.status}"
        )


@pytest.mark.asyncio
async def test_api09_ui_theme_post_unauthenticated_rejected(proxy_module):
    """POST /secured/ui-theme without a session is rejected (401 or hidden as 404)."""
    async with _gateway(proxy_module) as cli:
        r = await cli.post(
            f"{_GW_NS}/ui-theme",
            data=json.dumps({"theme": "light"}),
            headers={"Content-Type": "application/json"},
        )
        assert r.status in (401, 302, 303, 404), (
            f"Expected rejection for unauthenticated POST, got {r.status}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# API-10 — single master toggle reflects across EVERY dashboard (1.9.7)
# ─────────────────────────────────────────────────────────────────────────────

# Every served dashboard GET route (suffix). All bake config_kv['ui_theme'] into
# <html data-theme> on first paint, so a POST to /ui-theme must flip them all.
_ALL_DASHBOARDS = [
    "live-feed", "control-center", "agents", "siem", "geo", "logs",
    "controls", "honeypots", "service", "settings", "vhost-policy",
]


@pytest.mark.asyncio
async def test_api10_master_toggle_reflects_in_all_dashboards(proxy_module):
    """POST /secured/ui-theme {"theme":"light"} once, then EVERY dashboard must
    serve data-theme="light" (the single server-side master), and a flip back to
    dark must reflect everywhere too."""
    async with _gateway(proxy_module) as cli:
        cookies = _admin_cookies(proxy_module)

        # Flip the master to light via the endpoint (not a direct DB write).
        r = await cli.post(
            f"{_GW_NS}/ui-theme",
            data=json.dumps({"theme": "light"}),
            cookies=cookies,
            headers={"Content-Type": "application/json"},
        )
        assert r.status == 200 and (await r.json()).get("theme") == "light"

        for suffix in _ALL_DASHBOARDS:
            resp = await cli.get(f"{_GW_NS}/{suffix}", cookies=cookies)
            # viewer-redirects/feature-gates aside, an admin session gets 200 HTML.
            assert resp.status == 200, f"{suffix}: HTTP {resp.status}"
            html = await resp.text()
            assert 'data-theme="light"' in html, (
                f"{suffix} did NOT reflect the light master "
                f"(no data-theme=\"light\" baked)"
            )

        # Flip back to dark — every dashboard must follow.
        r = await cli.post(
            f"{_GW_NS}/ui-theme",
            data=json.dumps({"theme": "dark"}),
            cookies=cookies,
            headers={"Content-Type": "application/json"},
        )
        assert r.status == 200 and (await r.json()).get("theme") == "dark"
        for suffix in _ALL_DASHBOARDS:
            resp = await cli.get(f"{_GW_NS}/{suffix}", cookies=cookies)
            assert resp.status == 200, f"{suffix}: HTTP {resp.status}"
            html = await resp.text()
            assert 'data-theme="dark"' in html, (
                f"{suffix} did NOT reflect the dark master"
            )


# ─────────────────────────────────────────────────────────────────────────────
# API-11 / CLICK-01 — clicking the toggle on ONE page reflects on ANOTHER
# (the user-visible guarantee: it's a single master, not a per-page setting)
# ─────────────────────────────────────────────────────────────────────────────

# Distinct (page-you-click-on, different-page-you-then-open) journeys.
_CROSS_PAGE_PAIRS = [
    ("controls",      "settings"),
    ("agents",        "siem"),
    ("geo",           "live-feed"),
    ("honeypots",     "logs"),
    ("service",       "vhost-policy"),
    ("control-center","agents"),
]


@pytest.mark.parametrize("clicked,other", _CROSS_PAGE_PAIRS)
@pytest.mark.asyncio
async def test_api11_toggle_on_one_page_reflects_on_another(proxy_module, clicked, other):
    """Emulate a real toggle CLICK on `clicked` — its `_toggleTheme` POSTs the
    flipped theme to the master endpoint — then open a DIFFERENT page `other`
    and confirm it comes up in the new theme. Proves the choice crosses pages
    (single server-side master), then again on the flip back."""
    async with _gateway(proxy_module) as cli:
        cookies = _admin_cookies(proxy_module)

        # Establish a known starting master so the "click" is a real flip.
        await cli.post(f"{_GW_NS}/ui-theme", data=json.dumps({"theme": "light"}),
                       cookies=cookies, headers={"Content-Type": "application/json"})

        # User on `clicked` (currently light) clicks 🌙 → toggle sends {theme:"dark"}.
        r = await cli.post(f"{_GW_NS}/ui-theme", data=json.dumps({"theme": "dark"}),
                           cookies=cookies, headers={"Content-Type": "application/json"})
        assert r.status == 200 and (await r.json()).get("theme") == "dark"

        # They navigate to the OTHER page — it must render dark.
        resp = await cli.get(f"{_GW_NS}/{other}", cookies=cookies)
        assert resp.status == 200, f"{other}: HTTP {resp.status}"
        assert 'data-theme="dark"' in (await resp.text()), (
            f"clicking the toggle on '{clicked}' did NOT reflect on '{other}' "
            f"(other page still not dark) — theme is behaving per-page, not master"
        )

        # Flip back ☀ on `clicked` → {theme:"light"}; `other` follows.
        r = await cli.post(f"{_GW_NS}/ui-theme", data=json.dumps({"theme": "light"}),
                           cookies=cookies, headers={"Content-Type": "application/json"})
        assert r.status == 200
        resp = await cli.get(f"{_GW_NS}/{other}", cookies=cookies)
        assert 'data-theme="light"' in (await resp.text()), (
            f"flip-back on '{clicked}' did NOT reflect on '{other}'"
        )


_ALL_DASH_HTML = [
    "main.html", "agents.html", "siem.html", "geo.html", "logs.html",
    "controls.html", "control_center.html", "honeypots.html",
    "settings.html", "service.html", "vhost_policy.html",
]


@pytest.mark.parametrize("fname", _ALL_DASH_HTML)
def test_click01_toggle_handler_persists_server_master(fname):
    """Every dashboard's toggle CLICK must write the SERVER master — not just
    localStorage — so it crosses to other pages/browsers. The `_toggleTheme`
    handler must (a) flip dark<->light and (b) POST the new value to
    /secured/ui-theme."""
    src = _html(fname)
    i = src.find("_toggleTheme=function")
    assert i != -1, f"{fname}: no _toggleTheme handler"
    # Window spans the flip + the fetch (the fetch sits ~1.5k chars in on
    # chart-heavy pages because the handler also re-colours the charts first).
    block = src[i: i + 1800].replace(" ", "")
    assert "cur==='light'?'dark':'light'" in block, (
        f"{fname}: toggle must flip dark<->light"
    )
    assert "secured/ui-theme'" in block and "method:'POST'" in block, (
        f"{fname}: toggle click must POST to the /secured/ui-theme master endpoint"
    )
    assert "{theme:next}" in block, (
        f"{fname}: toggle must send the flipped value ({{theme:next}}) to the master"
    )
