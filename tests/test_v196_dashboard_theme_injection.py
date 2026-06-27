"""
1.9.6 — every dashboard endpoint must bake the persisted UI theme into the
served <html> tag, so navigating between dashboards never flips dark↔light.

Bug: only 5 of 11 dashboards injected `data-theme`; the other 6 (main, agents,
siem, geo, logs, control_center) shipped without it, so their <head> init script
fell back to the OS `prefers-color-scheme`. Fixed by routing every dashboard
through `db.sqlite.inject_theme`. This guard fails if ANY dashboard HTML
constant is ever served raw (no theme injection) — inline `.replace(… data-theme …)`
or `inject_theme(` both count as injected.
"""
import os
import re
import pathlib

os.environ.setdefault("UPSTREAM", "https://example.com")
_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Files that serve dashboard HTML.
_SERVE_FILES = [
    "core/proxy_handler.py", "dashboards/agents.py", "dashboards/siem.py",
    "dashboards/controls.py", "dashboards/honeypots.py",
    "dashboards/service_metrics.py", "admin/settings.py",
]
# Matches a SERVE of a dashboard HTML constant: `text=X_HTML` / `body = X_HTML`
# where X is a *_DASHBOARD_HTML or CONTROL_CENTER_HTML constant served raw.
_RAW_SERVE = re.compile(
    r'(?:text=|body\s*=\s*)([A-Z_]*(?:DASHBOARD_HTML|CONTROL_CENTER_HTML))\b')


def test_helper_injects_theme():
    from db.sqlite import inject_theme
    out = inject_theme('<html lang="en"><head></head></html>', "/nonexistent.db")
    assert 'data-theme="dark"' in out          # default when no DB
    assert inject_theme("<html>no-match</html>", "/x.db") == "<html>no-match</html>"


def test_no_dashboard_served_without_theme_injection():
    bad = []
    for rel in _SERVE_FILES:
        p = _ROOT / rel
        if not p.exists():
            continue
        for i, line in enumerate(p.read_text().splitlines(), 1):
            if not _RAW_SERVE.search(line):
                continue
            # Injected if the serve wraps in inject_theme(...) or does the
            # inline data-theme replace on the same statement.
            if "inject_theme(" in line or "data-theme" in line:
                continue
            bad.append(f"{rel}:{i}: {line.strip()}")
    assert not bad, "dashboard(s) served WITHOUT theme injection:\n" + "\n".join(bad)


def test_six_fixed_dashboards_use_helper():
    """The previously-broken 6 now route through inject_theme()."""
    ph = (_ROOT / "core/proxy_handler.py").read_text()
    for fn in ("dashboard_endpoint", "control_center_endpoint",
               "geo_dashboard_endpoint", "logs_dashboard_endpoint"):
        seg = ph.split(f"async def {fn}", 1)[1][:600]
        assert "inject_theme(" in seg, f"{fn} must inject the theme"
    assert "inject_theme(AGENTS_DASHBOARD_HTML" in (_ROOT / "dashboards/agents.py").read_text()
    assert "inject_theme(SIEM_DASHBOARD_HTML" in (_ROOT / "dashboards/siem.py").read_text()
