"""
tests/test_v1813_control_toggles.py — enabling a control from the dashboard must
never error.

Two ways enabling a control can fail, both guarded here:

  1. not-hot-reloadable — a control toggled in controls.html POSTs its knob to
     /secured/config, which only accepts names in _HOT_RELOAD_KNOBS; anything
     else is rejected. (PATH_SWEEP_ENABLED was missing; controls.html had the
     typo LABYRINTH_LINKS_PER_PAGE for LABYRINTH_LINKS_PER.)

  2. CSRF token invalid — behind Cloudflare the agw_csrf cookie is HttpOnly, so
     dashboard JS must read the token from the injected window.__AGW_CSRF__; a
     cookie-only read returns 403.

Static parse (AST + regex) — no import side-effects.
"""
import ast
import glob
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
# SIGNAL_KNOB values that name config managed OUTSIDE the hot-reload API (the
# admin-IP allowlist is edited in Settings) — shown in the risk-breakdown
# "control" column for context, never POSTed as a toggle.
_DISPLAY_ONLY = {"ADMIN_ALLOWED_IPS"}


def _dict_node(path, name):
    tree = ast.parse(open(os.path.join(_REPO, path), encoding="utf-8").read())
    for n in ast.walk(tree):
        if (isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
                and isinstance(n.value, ast.Dict)):
            return n.value
    raise AssertionError(f"{name} dict not found in {path}")


def _hot_reload_knobs():
    d = _dict_node("core/proxy_handler.py", "_HOT_RELOAD_KNOBS")
    return {k.value for k in d.keys if isinstance(k, ast.Constant)}


def _signal_knob():
    d = _dict_node("core/proxy_handler.py", "SIGNAL_KNOB")
    return {k.value: (v.value if isinstance(v, ast.Constant) else None)
            for k, v in zip(d.keys, d.values) if isinstance(k, ast.Constant)}


def _controls_toggles():
    """{KNOB: kind} for every control controls.html exposes (KNOB:{kind:'...'})."""
    html = open(os.path.join(_REPO, "dashboards/controls.html"), encoding="utf-8").read()
    return dict(re.findall(r"\b([A-Z][A-Z0-9_]{3,}):\s*\{kind:\s*'([a-z]+)'", html))


def test_controls_dashboard_toggles_are_settable():
    hot = _hot_reload_knobs()
    toggles = _controls_toggles()
    assert toggles, "no toggles parsed from controls.html — structure changed?"
    broken = sorted(k for k in toggles if k not in hot)
    assert not broken, (
        "controls.html exposes toggles whose knob is NOT in _HOT_RELOAD_KNOBS — "
        f"enabling them returns 'not-hot-reloadable': {broken}")


def test_signal_knob_toggles_are_settable():
    hot = _hot_reload_knobs()
    broken = sorted({kn for kn in _signal_knob().values()
                     if isinstance(kn, str) and kn and kn not in hot and kn not in _DISPLAY_ONLY})
    assert not broken, (
        "SIGNAL_KNOB maps a control to a knob that isn't settable via the config "
        f"API (the breakdown '→ Controls' link errors): {broken}")


def test_path_sweep_enabled_is_hot_reloadable():
    # regression: PATH_SWEEP_ENABLED is a real detector toggle that was missing.
    assert "PATH_SWEEP_ENABLED" in _hot_reload_knobs()


def test_no_labyrinth_links_per_page_typo():
    # regression: controls.html POSTed LABYRINTH_LINKS_PER_PAGE; the knob is
    # LABYRINTH_LINKS_PER.
    toggles = _controls_toggles()
    assert "LABYRINTH_LINKS_PER_PAGE" not in toggles, "stale knob name reintroduced"
    assert "LABYRINTH_LINKS_PER" in toggles and "LABYRINTH_LINKS_PER" in _hot_reload_knobs()


def test_no_dashboard_csrf_cookie_only_read():
    """Behind Cloudflare agw_csrf is HttpOnly — every cookie read must fall back
    to the injected window.__AGW_CSRF__, else config POSTs 403 'CSRF token invalid'."""
    offenders = []
    for path in sorted(glob.glob(os.path.join(_REPO, "dashboards", "*.html"))):
        lines = open(path, encoding="utf-8").readlines()
        for i, line in enumerate(lines, 1):
            if "document.cookie" in line and "agw_csrf" in line and "__AGW_CSRF__" not in line:
                # contract change (v1.8.13+): the shipped `window.__AGW_CSRF__ || cookie`
                # fallback idiom is sometimes wrapped across two lines (e.g.
                # controls.html _agwTokG()), so the injected-token primary source lands
                # on the PREVIOUS line. Only flag a cookie read that has no
                # __AGW_CSRF__ fallback in its immediate block (prev line), which is a
                # genuine cookie-only read.
                prev = lines[i - 2] if i >= 2 else ""
                if "__AGW_CSRF__" not in prev:
                    offenders.append(f"{os.path.basename(path)}:{i}")
    assert not offenders, (
        "dashboard reads the agw_csrf cookie without the window.__AGW_CSRF__ "
        f"fallback (breaks behind Cloudflare HttpOnly): {offenders}")
