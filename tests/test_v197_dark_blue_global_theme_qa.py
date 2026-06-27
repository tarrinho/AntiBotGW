"""
QA tests — dark-mode blue lightened + global theme persistence (1.9.7 iter).

Two related UX regressions that this test guards:

  1. Blue text colour `#58a6ff` was too dim against the dark background
     (`#0d1117`). Bumped to GitHub's standard dark-mode link blue
     `#79c0ff` (rgb 121,192,255 — ~30% lighter). Both the hex literal
     and the matching rgba(88,166,255,…) tints were swept across all
     dashboards + `dashboards/assets/dashboard-common.js`.

  2. The light/dark toggle was per-page: flipping it on one dashboard
     did not propagate to the next dashboard you opened. Server-side
     persistence (`POST /secured/ui-theme`) still works for authed
     users but the very first paint of the next page always rendered
     dark before any fetch could resolve, causing the visible flash
     and "per-page" feel. Fix: also persist via `localStorage` (key
     `agw-theme`) and read it in the inline `<head>` init script BEFORE
     first paint.

Coverage:
  TestNoOldBlue        — no remaining `#58a6ff` literal or
                         `rgba(88, 166, 255, …)` triplet anywhere in
                         dashboards/ (incl. assets).
  TestNewBlue          — `--blue:#79c0ff` is the active token in every
                         dashboard that defines it; `rgba(121,192,255,…)`
                         is the corresponding tint shape.
  TestThemeInitScript  — every dashboard with a `<head>` carries an
                         inline script that reads `localStorage.getItem
                         ('agw-theme')` and applies it to
                         `document.documentElement` before first paint.
  TestThemeTogglePersist
                       — every page that defines `window._toggleTheme`
                         also calls `localStorage.setItem('agw-theme',
                         next)` so subsequent pages inherit the choice.
"""
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DASHBOARDS = _ROOT / "dashboards"

# Files that have a `<head>` and therefore need the localStorage init.
# `header-designs.html` is a design-preview scratchpad — no theme button,
# no theming logic, so we don't require the init there either; exclude it
# explicitly to keep the test focused on production pages.
_DESIGN_PREVIEW = {"header-designs.html"}


def _dash_files():
    return sorted(
        p for p in _DASHBOARDS.glob("*.html")
        if p.name not in _DESIGN_PREVIEW
    )


def _all_color_files():
    files = list(_DASHBOARDS.glob("*.html"))
    files.append(_DASHBOARDS / "assets" / "dashboard-common.js")
    return sorted(files)


# ── 1. TestNoOldBlue ─────────────────────────────────────────────────────────

class TestNoOldBlue:
    """Regression guard: the old `#58a6ff` literal and matching
    `rgba(88,166,255,…)` tint must not reappear anywhere in dashboards."""

    OLD_HEX = re.compile(r"#58a6ff", re.IGNORECASE)
    OLD_RGB = re.compile(r"rgba\(\s*88\s*,\s*166\s*,\s*255")

    def test_no_old_hex(self):
        offenders = []
        for f in _all_color_files():
            if not f.exists():
                continue
            txt = f.read_text(encoding="utf-8", errors="ignore")
            if self.OLD_HEX.search(txt):
                offenders.append(f.name)
        assert not offenders, (
            f"Old dark-blue #58a6ff found in {offenders} — must be #79c0ff"
        )

    def test_no_old_rgb_tint(self):
        offenders = []
        for f in _all_color_files():
            if not f.exists():
                continue
            txt = f.read_text(encoding="utf-8", errors="ignore")
            if self.OLD_RGB.search(txt):
                offenders.append(f.name)
        assert not offenders, (
            f"Old rgba(88,166,255,…) tint found in {offenders} — "
            "must be rgba(121,192,255,…)"
        )


# ── 2. TestNewBlue ───────────────────────────────────────────────────────────

class TestNewBlue:
    """Confirm the new token is in place on every page that defines `--blue`."""

    NEW_TOKEN = re.compile(r"--blue\s*:\s*#79c0ff", re.IGNORECASE)
    LEGACY_TOKEN = re.compile(r"--blue\s*:\s*#[0-9a-f]{6}", re.IGNORECASE)

    def test_blue_token_is_new_hex(self):
        broken = []
        for f in _DASHBOARDS.glob("*.html"):
            txt = f.read_text(encoding="utf-8", errors="ignore")
            tokens = self.LEGACY_TOKEN.findall(txt)
            if not tokens:
                continue  # page does not define --blue
            for t in tokens:
                if "#79c0ff" not in t.lower():
                    broken.append((f.name, t))
        assert not broken, (
            f"--blue token not on the new hex (#79c0ff) in: {broken}"
        )

    def test_dashboard_common_js_fallback_is_new_hex(self):
        js = (_DASHBOARDS / "assets" / "dashboard-common.js").read_text(
            encoding="utf-8"
        )
        assert "#79c0ff" in js.lower(), (
            "dashboard-common.js still references the old --blue fallback"
        )


# ── 3. TestThemeInitScript ───────────────────────────────────────────────────

class TestThemeInitScript:
    """Every production dashboard must read `localStorage.agw-theme`
    BEFORE first paint so the theme is consistent across pages and a
    re-visit doesn't flash dark before any JS resolves."""

    INIT_PAT = re.compile(
        r"localStorage\.getItem\(\s*['\"]agw-theme['\"]\s*\)",
    )

    def test_each_dashboard_has_inline_localstorage_init(self):
        missing = []
        for f in _dash_files():
            txt = f.read_text(encoding="utf-8", errors="ignore")
            head_end = txt.lower().find("</head>")
            head = txt[: head_end if head_end != -1 else len(txt)]
            if not self.INIT_PAT.search(head):
                missing.append(f.name)
        assert not missing, (
            f"Dashboards missing localStorage theme init in <head>: {missing}"
        )

    def test_init_runs_before_anything_renders(self):
        """The init script must come BEFORE any <style> block — otherwise
        the browser may paint the default theme first."""
        offenders = []
        for f in _dash_files():
            txt = f.read_text(encoding="utf-8", errors="ignore")
            init_at = -1
            for m in self.INIT_PAT.finditer(txt):
                init_at = m.start()
                break
            style_at = txt.lower().find("<style")
            if init_at == -1:
                continue  # caught by the missing-init test above
            if style_at == -1:
                continue  # no <style> in this page — fine
            if init_at > style_at:
                offenders.append((f.name, init_at, style_at))
        assert not offenders, (
            "localStorage theme init appears AFTER first <style> block "
            f"(would cause flash): {offenders}"
        )


# ── 4. TestThemeTogglePersist ────────────────────────────────────────────────

class TestThemeTogglePersist:
    """Every page that defines `window._toggleTheme` must also call
    `localStorage.setItem('agw-theme', next)` so the choice survives a
    page navigation."""

    TOGGLE_DEF = re.compile(r"window\._toggleTheme\s*=\s*function")
    SETITEM_PAT = re.compile(
        r"localStorage\.setItem\(\s*['\"]agw-theme['\"]"
    )

    def _pages_with_toggle(self):
        for f in _DASHBOARDS.glob("*.html"):
            txt = f.read_text(encoding="utf-8", errors="ignore")
            if self.TOGGLE_DEF.search(txt):
                yield f, txt

    def test_each_toggle_writes_to_localstorage(self):
        missing = []
        for f, txt in self._pages_with_toggle():
            if not self.SETITEM_PAT.search(txt):
                missing.append(f.name)
        assert not missing, (
            f"Pages defining _toggleTheme without localStorage.setItem: {missing}"
        )

    def test_setitem_is_inside_toggle_function(self):
        """setItem must be near the `_toggleTheme` body, not somewhere
        unrelated. Heuristic: the first setItem-for-agw-theme must occur
        within 800 chars of the `_toggleTheme=function` opening."""
        offenders = []
        for f, txt in self._pages_with_toggle():
            mdef = self.TOGGLE_DEF.search(txt)
            mset = self.SETITEM_PAT.search(txt)
            if not (mdef and mset):
                continue  # caught by other tests
            if mset.start() - mdef.start() > 800 or mset.start() < mdef.start():
                offenders.append(
                    (f.name, mdef.start(), mset.start())
                )
        assert not offenders, (
            f"localStorage.setItem('agw-theme') not inside _toggleTheme body: "
            f"{offenders}"
        )
