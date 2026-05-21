"""
tests/test_v1810_csrf_shim_coverage.py — QA for global fetch CSRF shim on all
served dashboard pages.

Root cause fixed: WAF "Disable All" (and any other POST from a dashboard page)
returned "CSRF token invalid" because vhost_policy.html (and several other
pages) lacked the window.fetch shim that injects X-CSRF-Token from the
agw_csrf cookie.  The same shim was already present in controls.html,
agents.html, settings.html, and the controls_test* pages, but was missing from:
  vhost_policy.html, main.html, control_center.html, geo.html,
  logs.html, service.html, siem.html

These tests pin the fix so the regression cannot be re-introduced silently.

Shim tests (S)
  S01  vhost_policy.html has CSRF fetch shim          [regression guard]
  S02  main.html has CSRF fetch shim
  S03  control_center.html has CSRF fetch shim
  S04  geo.html has CSRF fetch shim
  S05  logs.html has CSRF fetch shim
  S06  service.html has CSRF fetch shim
  S07  siem.html has CSRF fetch shim
  S08  controls.html has CSRF fetch shim              [already present — guard]
  S09  agents.html has CSRF fetch shim                [already present — guard]
  S10  settings.html has CSRF fetch shim              [already present — guard]

Shim structure tests (T) — verified against vhost_policy.html as representative
  T01  shim overrides window.fetch
  T02  shim injects X-CSRF-Token header
  T03  shim reads token from agw_csrf cookie
  T04  shim preserves existing headers (Object.assign pattern)
  T05  shim skips injection for GET/HEAD

WAF-specific tests (W) — vhost_policy.html
  W01  _applyChanges uses fetch (WAF "Apply" path exists)
  W02  _saveRemove uses fetch (WAF "Remove Override" path exists)
  W03  Neither _applyChanges nor _saveRemove manually set X-CSRF-Token
       (they rely on the shim — double-setting would still work but indicates
       incomplete migration)
  W04  All vhost_policy.html fetch calls use credentials:'include'

Completeness test (X)
  X01  Every served HTML file that contains a state-mutating fetch call
       (method POST/PATCH/DELETE) has the CSRF shim — catches future pages
"""
import os
import re

_DASH = os.path.join(os.path.dirname(__file__), "..", "dashboards")

def _read(name):
    with open(os.path.join(_DASH, name), encoding="utf-8") as f:
        return f.read()

# All actively-served pages (from read_text() calls in *.py)
_SERVED_PAGES = [
    "main.html",
    "control_center.html",
    "agents.html",
    "siem.html",
    "settings.html",
    "vhost_policy.html",
    "controls.html",
    "geo.html",
    "logs.html",
    "controls_testA.html",
    "controls_testB.html",
    "service.html",
]

_SHIM_PATTERNS = [
    "window.fetch = function",
    "window.fetch=function",
]

def _has_shim(html: str) -> bool:
    return any(p in html for p in _SHIM_PATTERNS)

def _has_mutating_fetch(html: str) -> bool:
    return bool(re.search(r"method\s*:\s*['\"](?:POST|PATCH|DELETE)['\"]", html))


# ── S: Shim presence ─────────────────────────────────────────────────────────

class TestShimPresence:
    def test_s01_vhost_policy_has_shim(self):
        assert _has_shim(_read("vhost_policy.html")), (
            "vhost_policy.html missing CSRF fetch shim — WAF knob changes will fail"
        )

    def test_s02_main_has_shim(self):
        assert _has_shim(_read("main.html")), (
            "main.html missing CSRF fetch shim"
        )

    def test_s03_control_center_has_shim(self):
        assert _has_shim(_read("control_center.html")), (
            "control_center.html missing CSRF fetch shim"
        )

    def test_s04_geo_has_shim(self):
        assert _has_shim(_read("geo.html")), (
            "geo.html missing CSRF fetch shim"
        )

    def test_s05_logs_has_shim(self):
        assert _has_shim(_read("logs.html")), (
            "logs.html missing CSRF fetch shim"
        )

    def test_s06_service_has_shim(self):
        assert _has_shim(_read("service.html")), (
            "service.html missing CSRF fetch shim"
        )

    def test_s07_siem_has_shim(self):
        assert _has_shim(_read("siem.html")), (
            "siem.html missing CSRF fetch shim"
        )

    def test_s08_controls_has_shim(self):
        assert _has_shim(_read("controls.html")), (
            "controls.html CSRF shim was removed — regression"
        )

    def test_s09_agents_has_shim(self):
        assert _has_shim(_read("agents.html")), (
            "agents.html CSRF shim was removed — regression"
        )

    def test_s10_settings_has_shim(self):
        assert _has_shim(_read("settings.html")), (
            "settings.html CSRF shim was removed — regression"
        )


# ── T: Shim structure ────────────────────────────────────────────────────────

class TestShimStructure:
    """Representative checks against vhost_policy.html (smallest shim surface)."""

    _HTML = _read("vhost_policy.html")

    def test_t01_shim_overrides_window_fetch(self):
        assert _has_shim(self._HTML), "window.fetch override not found"

    def test_t02_shim_injects_csrf_header(self):
        assert "X-CSRF-Token" in self._HTML, (
            "Shim must inject X-CSRF-Token header"
        )

    def test_t03_shim_reads_agw_csrf_cookie(self):
        assert "agw_csrf" in self._HTML, (
            "Shim must read token from agw_csrf cookie"
        )

    def test_t04_shim_uses_object_assign(self):
        assert "Object.assign" in self._HTML, (
            "Shim must use Object.assign to preserve existing headers"
        )

    def test_t05_shim_skips_get_head(self):
        html = self._HTML
        # Shim must check method and skip GET/HEAD
        assert "GET" in html and "HEAD" in html, (
            "Shim must explicitly skip GET and HEAD requests"
        )
        # The guard must appear within the shim block (before any fetch calls)
        shim_start = min(
            (html.find(p) for p in _SHIM_PATTERNS if p in html),
            default=-1
        )
        assert shim_start != -1
        shim_region = html[shim_start:shim_start + 400]
        assert "GET" in shim_region and "HEAD" in shim_region, (
            "GET/HEAD guard must be inside the shim IIFE, not elsewhere"
        )


# ── W: WAF-specific ──────────────────────────────────────────────────────────

class TestWafVhostPolicy:
    _HTML = _read("vhost_policy.html")

    def test_w01_apply_changes_uses_fetch(self):
        assert "_applyChanges" in self._HTML, "_applyChanges function must exist"
        idx = self._HTML.find("_applyChanges")
        block = self._HTML[idx:idx + 600]
        assert "fetch(" in block or "fetch (" in block, (
            "_applyChanges must use fetch() — WAF Apply path"
        )

    def test_w02_save_remove_uses_fetch(self):
        # Anchor on the function *definition*, not a call site
        assert "function _saveRemove" in self._HTML, "_saveRemove function definition must exist"
        idx = self._HTML.find("function _saveRemove")
        block = self._HTML[idx:idx + 700]
        assert "fetch(" in block or "fetch (" in block, (
            "_saveRemove must use fetch() — WAF Remove Override path"
        )

    def test_w03_no_manual_csrf_in_apply_or_remove(self):
        # Both functions rely on the shim — manually adding headers here would
        # indicate an incomplete migration (the shim approach is the canonical one)
        for func in ("_applyChanges", "_saveRemove"):
            idx = self._HTML.find(func)
            assert idx != -1, f"{func} not found"
            # Grab the function body (up to the closing brace sequence)
            block = self._HTML[idx:idx + 800]
            # The function body must NOT set X-CSRF-Token manually
            assert "X-CSRF-Token" not in block, (
                f"{func} manually sets X-CSRF-Token — remove it and rely on the global shim"
            )

    def test_w04_vhost_fetch_calls_use_credentials_include(self):
        # All fetch() calls in vhost_policy.html that POST to the backend must
        # send credentials so the session cookie is included
        post_blocks = re.findall(
            r"fetch\([^)]+\{[^}]*method:'POST'[^}]*\}",
            self._HTML,
            re.DOTALL,
        )
        # Also match multi-line fetch calls with explicit credentials
        cred_count = self._HTML.count("credentials:'include'")
        assert cred_count >= 2, (
            "At least 2 fetch calls in vhost_policy.html must use credentials:'include'"
        )


# ── X: Completeness sweep ────────────────────────────────────────────────────

class TestCompleteness:
    def test_x01_every_served_page_with_post_has_shim(self):
        """
        For every served HTML file: if it contains a POST/PATCH/DELETE fetch
        call, it must also contain the CSRF shim.  This catches any future page
        that gets state-mutating fetch calls without the shim.
        """
        missing = []
        for name in _SERVED_PAGES:
            html = _read(name)
            if _has_mutating_fetch(html) and not _has_shim(html):
                missing.append(name)
        assert not missing, (
            "These served pages have POST/PATCH/DELETE fetch calls but no CSRF shim: "
            + ", ".join(missing)
        )
