"""
QA tests — day-theme (light) color regressions (1.8.14 iteration 9 fix).

Bug: three elements in settings.html used hardcoded background:#21262d
(the dark-theme --bg-elevated value) in JS-generated HTML strings.
Because they are created dynamically (after the _dp theme-toggle scan
runs, or on a page already in light mode), the theme-toggle palette
replacement never fires for them.  In the day theme those elements
showed a black box instead of the expected light-gray surface.

Affected elements:
  • "Test" button  (id="_tip-pg-test")  — DB connection tip popup
  • "Load DSN" button (id="_tip-pg-load") — DB connection tip popup
  • "not set" badge — integration-credentials section (AbuseIPDB, etc.)

Fix: all three now use var(--bg-elevated), which CSS resolves to
     #21262d (dark) or #eaeef2 (light) per the active theme.

Coverage:
  TestDayThemeSpecificElements  — targeted checks on the three fixed elements
  TestDayThemeNoDarkHardcoded   — regression guard: no new #21262d in
                                  JS-generated HTML outside CSS/dp definitions
"""
import pathlib
import re

# ── Source ────────────────────────────────────────────────────────────────────
_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SETTINGS_SRC = (_ROOT / "dashboards" / "settings.html").read_text(encoding="utf-8")

_DARK_HEX_BG = "#21262d"  # --bg-elevated value in dark theme


# ── Helpers ───────────────────────────────────────────────────────────────────

def _snippet_around(marker: str, before: int = 30, after: int = 300) -> str:
    idx = _SETTINGS_SRC.find(marker)
    assert idx != -1, f"Marker not found in settings.html: {marker!r}"
    return _SETTINGS_SRC[max(0, idx - before): idx + after]


# ── 1. TestDayThemeSpecificElements ──────────────────────────────────────────

class TestDayThemeSpecificElements:
    """The three elements that were broken in the day theme must now use
    var(--bg-elevated) instead of hardcoded #21262d."""

    # ── _tip-pg-test button ───────────────────────────────────────────────────

    def test_tip_pg_test_button_present(self):
        """_tip-pg-test button must exist in settings.html."""
        assert 'id="_tip-pg-test"' in _SETTINGS_SRC, (
            "_tip-pg-test button not found in settings.html"
        )

    def test_tip_pg_test_button_no_hardcoded_dark_bg(self):
        """_tip-pg-test button must not use hardcoded background:#21262d."""
        snippet = _snippet_around('id="_tip-pg-test"')
        assert _DARK_HEX_BG not in snippet.lower(), (
            f"_tip-pg-test button still uses hardcoded {_DARK_HEX_BG} — "
            "breaks day theme; use var(--bg-elevated)"
        )

    def test_tip_pg_test_button_uses_bg_elevated(self):
        """_tip-pg-test button background must be var(--bg-elevated)."""
        snippet = _snippet_around('id="_tip-pg-test"')
        assert "var(--bg-elevated)" in snippet, (
            "_tip-pg-test button must use var(--bg-elevated) for background"
        )

    # ── _tip-pg-load button ───────────────────────────────────────────────────

    def test_tip_pg_load_button_present(self):
        """_tip-pg-load button must exist in settings.html."""
        assert 'id="_tip-pg-load"' in _SETTINGS_SRC, (
            "_tip-pg-load button not found in settings.html"
        )

    def test_tip_pg_load_button_no_hardcoded_dark_bg(self):
        """_tip-pg-load button must not use hardcoded background:#21262d."""
        snippet = _snippet_around('id="_tip-pg-load"', before=50, after=400)
        assert _DARK_HEX_BG not in snippet.lower(), (
            f"_tip-pg-load button still uses hardcoded {_DARK_HEX_BG} — "
            "breaks day theme; use var(--bg-elevated)"
        )

    def test_tip_pg_load_button_uses_bg_elevated(self):
        """_tip-pg-load button background must be var(--bg-elevated)."""
        snippet = _snippet_around('id="_tip-pg-load"', before=50, after=400)
        assert "var(--bg-elevated)" in snippet, (
            "_tip-pg-load button must use var(--bg-elevated) for background"
        )

    # ── "not set" credential badge ────────────────────────────────────────────

    def test_not_set_badge_present(self):
        """'not set' badge span must exist in settings.html."""
        assert ">not set<" in _SETTINGS_SRC, (
            "'not set' badge span not found in settings.html"
        )

    def test_not_set_badge_no_hardcoded_dark_bg(self):
        """'not set' badge must not use hardcoded background:#21262d."""
        snippet = _snippet_around(">not set<", before=350, after=10)
        assert _DARK_HEX_BG not in snippet.lower(), (
            f"'not set' badge still uses hardcoded {_DARK_HEX_BG} — "
            "breaks day theme; use var(--bg-elevated)"
        )

    def test_not_set_badge_uses_bg_elevated(self):
        """'not set' badge background must be var(--bg-elevated)."""
        snippet = _snippet_around(">not set<", before=350, after=10)
        assert "var(--bg-elevated)" in snippet, (
            "'not set' badge must use var(--bg-elevated) for background"
        )

    def test_not_set_badge_color_uses_css_var(self):
        """'not set' badge text color must use a CSS variable, not a hardcoded hex."""
        snippet = _snippet_around(">not set<", before=350, after=10)
        assert "color:var(" in snippet, (
            "'not set' badge must use a CSS variable for text color"
        )


# ── 2. TestDayThemeNoDarkHardcoded ────────────────────────────────────────────

class TestDayThemeNoDarkHardcoded:
    """Regression guard: no hardcoded dark-theme hex colors may appear in
    JS-generated HTML strings (template literals / string concatenations).

    The _dp palette-swap only fires on elements already in the DOM at the
    moment the theme toggle runs.  Dynamically-created elements that embed
    hardcoded dark colors are invisible to _dp and break the day theme."""

    # Known hex values for dark-mode CSS variables that must NOT appear in
    # inline-style strings outside of: the :root CSS definition block, and
    # the _dp palette-map literal.
    _DARK_BG_VARS = {
        "#21262d": "--bg-elevated",  # the primary offender; others below as regression guards
    }

    def _lines_with_color_outside_allowed(self, hex_val: str) -> list:
        """Return lines that contain hex_val outside the two allowed contexts."""
        results = []
        for i, line in enumerate(_SETTINGS_SRC.split("\n"), 1):
            if hex_val not in line.lower():
                continue
            # Allowed: CSS :root variable definition  (e.g. --bg-elevated:#21262d)
            if f"--bg-elevated:{hex_val}" in line:
                continue
            # Allowed: _dp palette map  (e.g. '#21262d':'#eaeef2')
            if f"'{hex_val}'" in line or f'"{hex_val}"' in line:
                continue
            results.append((i, line.rstrip()))
        return results

    def test_no_21262d_in_js_html_strings(self):
        """#21262d must not appear in JS-generated HTML (only in :root and _dp map)."""
        violations = self._lines_with_color_outside_allowed(_DARK_HEX_BG)
        assert not violations, (
            f"Hardcoded {_DARK_HEX_BG} found outside CSS/:root and _dp definitions — "
            "use var(--bg-elevated) instead:\n"
            + "\n".join(f"  line {n}: {txt[:120]}" for n, txt in violations)
        )

    def test_dp_map_covers_bg_elevated(self):
        """_dp day-palette map must include a light equivalent for #21262d."""
        assert f"'{_DARK_HEX_BG}'" in _SETTINGS_SRC or f'"{_DARK_HEX_BG}"' in _SETTINGS_SRC, (
            f"_dp palette map must contain {_DARK_HEX_BG} as a key so static "
            "inline-style elements get replaced on theme toggle"
        )

    def test_bg_elevated_var_defined_in_root(self):
        """--bg-elevated must be defined in :root for dark theme."""
        assert f"--bg-elevated:{_DARK_HEX_BG}" in _SETTINGS_SRC, (
            f"CSS :root must define --bg-elevated as {_DARK_HEX_BG} for the dark theme"
        )

    def test_bg_elevated_var_defined_in_light_theme(self):
        """--bg-elevated must be overridden in [data-theme=light]."""
        light_section = _SETTINGS_SRC[
            _SETTINGS_SRC.find('data-theme="light"'):
            _SETTINGS_SRC.find('data-theme="light"') + 500
        ]
        assert "--bg-elevated:" in light_section, (
            "[data-theme=light] must override --bg-elevated with a light color"
        )

    def test_light_bg_elevated_is_not_dark(self):
        """--bg-elevated in light theme must not be the dark value #21262d."""
        m = re.search(r'data-theme="light"\}\{[^}]*--bg-elevated:([^;,}]+)', _SETTINGS_SRC)
        if not m:
            # try multiline form
            idx = _SETTINGS_SRC.find('data-theme="light"')
            end = _SETTINGS_SRC.find("}", idx) + 1
            section = _SETTINGS_SRC[idx:end + 200]
            m2 = re.search(r'--bg-elevated:([^;,}"\s]+)', section)
            assert m2, "Could not extract --bg-elevated value from light theme block"
            val = m2.group(1).strip()
        else:
            val = m.group(1).strip()
        assert val.lower() != _DARK_HEX_BG, (
            f"--bg-elevated in light theme must not be the dark value {_DARK_HEX_BG}; got {val!r}"
        )
