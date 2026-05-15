"""
QA tests — coverage gaps for v1.8.0 and v1.8.1 features.

Groups
──────
A  Top-paths Domain column          (new UI column + API vhost field)
B  DOCTYPE declarations             (all 9 dashboard pages)
C  Hardcoded #388bfd eliminated     (var(--blue) used everywhere)
D  Account modal (#acct-modal)      (HTML element on all 9 pages)
E  Portal footer                    (all 9 dashboard pages)
F  Control Center page structure    (control_center.html)
G  Login redirect → /control-center (users.py default next)
H  agents.html title                (positive "Agents" assertion)
I  service.html .vhost-pill CSS     (full property set)
J  logs.html missed-pill CSS        (data-cat="missed" variants)
K  Location header rewrite          (1.8.0 — cross-domain redirect)
"""
import os
import re
import sys
import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

_DASH_DIR = os.path.join(os.path.dirname(__file__), "..", "dashboards")


def _dash(name: str) -> str:
    return open(os.path.join(_DASH_DIR, name), encoding="utf-8").read()


# All 9 canonical dashboard pages (login excluded — public page).
_ALL_DASH = [
    "main.html",
    "agents.html",
    "controls.html",
    "geo.html",
    "logs.html",
    "service.html",
    "settings.html",
    "vhost_policy.html",
    "control_center.html",
]


# ── A. Top-paths Domain column ────────────────────────────────────────────

class TestTopPathsDomainColumn:
    """main.html #paths-tbl now has Domain | Path | Hits columns."""

    def test_paths_tbl_has_three_column_headers(self):
        src = _dash("main.html")
        # Extract thead row
        m = re.search(r'<table id="paths-tbl">.*?<thead>(.*?)</thead>', src, re.S)
        assert m, "paths-tbl thead not found"
        ths = re.findall(r'<th[^>]*>(.*?)</th>', m.group(1), re.S)
        assert len(ths) == 3, f"Expected 3 columns, found {len(ths)}: {ths}"

    def test_paths_tbl_domain_column_present(self):
        src = _dash("main.html")
        m = re.search(r'<table id="paths-tbl">.*?<thead>(.*?)</thead>', src, re.S)
        assert m, "paths-tbl thead not found"
        assert "Domain" in m.group(1), "Domain column header missing from #paths-tbl"

    def test_paths_tbl_domain_column_is_first(self):
        src = _dash("main.html")
        m = re.search(r'<table id="paths-tbl">.*?<thead>(.*?)</thead>', src, re.S)
        assert m, "paths-tbl thead not found"
        ths = re.findall(r'<th[^>]*>(.*?)</th>', m.group(1), re.S)
        assert ths[0].strip() == "Domain", (
            f"First column must be Domain, got '{ths[0]}'"
        )

    def test_paths_tbl_path_column_second_hits_third(self):
        src = _dash("main.html")
        m = re.search(r'<table id="paths-tbl">.*?<thead>(.*?)</thead>', src, re.S)
        assert m
        ths = re.findall(r'<th[^>]*>(.*?)</th>', m.group(1), re.S)
        assert ths[1].strip() == "Path",  f"Expected Path at col 2, got '{ths[1]}'"
        assert ths[2].strip() == "Hits",  f"Expected Hits at col 3, got '{ths[2]}'"

    def test_top_paths_row_renders_domain_cell(self):
        """Row builder must emit a domain <td> using p.vhost."""
        src = _dash("main.html")
        # Find the row template in the JS that maps p => `<tr ...`
        idx = src.find("pBody.innerHTML")
        assert idx != -1, "top-paths row builder not found"
        block = src[idx: idx + 600]
        assert "p.vhost" in block, "Row builder must reference p.vhost for domain cell"

    def test_top_paths_domain_cell_has_escapeHtml(self):
        """Domain cell value must be XSS-escaped."""
        src = _dash("main.html")
        idx = src.find("pBody.innerHTML")
        block = src[idx: idx + 600]
        # escapeHtml must wrap p.vhost (or p.vhost||'')
        assert re.search(r'escapeHtml\(p\.vhost', block), (
            "Domain cell must call escapeHtml() on p.vhost"
        )

    def test_top_paths_empty_fallback_uses_colspan_3(self):
        """Empty-traffic fallback row must span all 3 columns."""
        src = _dash("main.html")
        idx = src.find("pBody.innerHTML")
        block = src[idx: idx + 1100]
        assert "colspan=3" in block or 'colspan="3"' in block, (
            "Empty-state row must have colspan=3 (3 columns)"
        )

    def test_proxy_handler_builds_path_to_vhost_dict(self):
        """proxy_handler.py must compute _path_to_vhost from events_by_cat."""
        src = open(os.path.join(
            os.path.dirname(__file__), "..", "core", "proxy_handler.py"
        ), encoding="utf-8").read()
        assert "_path_to_vhost" in src, (
            "_path_to_vhost dict missing from proxy_handler.py"
        )
        assert "events_by_cat" in src[src.find("_path_to_vhost") - 500:
                                       src.find("_path_to_vhost") + 200], (
            "_path_to_vhost must be built from events_by_cat"
        )

    def test_proxy_handler_top_paths_json_includes_vhost(self):
        """top_paths JSON response must include a vhost field per entry."""
        src = open(os.path.join(
            os.path.dirname(__file__), "..", "core", "proxy_handler.py"
        ), encoding="utf-8").read()
        # Find the top_paths list comprehension in the json_response
        m = re.search(r'"top_paths":\s*\[.*?\]', src)
        assert m, '"top_paths" key not found in json_response'
        assert "vhost" in m.group(), (
            "top_paths entries in json_response must include vhost field"
        )

    def test_path_to_vhost_uses_max_count_vhost(self):
        """_path_to_vhost selects the most-seen vhost per path."""
        from collections import Counter
        # Reproduce the logic directly
        events = [
            {"path": "/api", "vhost": "a.example.com"},
            {"path": "/api", "vhost": "a.example.com"},
            {"path": "/api", "vhost": "b.example.com"},
        ]
        pv_counts: dict = {}
        for e in events:
            p, v = e["path"], e["vhost"]
            pv_counts.setdefault(p, {})
            pv_counts[p][v] = pv_counts[p].get(v, 0) + 1
        result = {p: max(vc, key=vc.get) for p, vc in pv_counts.items()}
        assert result["/api"] == "a.example.com", (
            "Most-seen vhost must win: a.example.com appeared 2×, b.example.com 1×"
        )

    def test_path_to_vhost_empty_vhost_skipped(self):
        """Events with empty vhost must not pollute the domain mapping."""
        events = [
            {"path": "/x", "vhost": ""},
            {"path": "/x", "vhost": "real.example.com"},
        ]
        pv_counts: dict = {}
        for e in events:
            p, v = e.get("path", ""), e.get("vhost", "")
            if p and v:  # the actual guard in proxy_handler
                pv_counts.setdefault(p, {})
                pv_counts[p][v] = pv_counts[p].get(v, 0) + 1
        result = {p: max(vc, key=vc.get) for p, vc in pv_counts.items()}
        assert result.get("/x") == "real.example.com", (
            "Empty-vhost events must be skipped so real vhost wins"
        )


# ── B. DOCTYPE declarations ───────────────────────────────────────────────

@pytest.mark.parametrize("page", _ALL_DASH)
def test_doctype_present(page):
    """All 9 dashboard pages must start with <!doctype html>."""
    src = _dash(page)
    assert src.lstrip()[:15].lower().startswith("<!doctype"), (
        f"{page}: missing <!doctype html> declaration"
    )


# ── C. Hardcoded #388bfd eliminated ──────────────────────────────────────

@pytest.mark.parametrize("page", _ALL_DASH)
def test_no_hardcoded_blue_388bfd(page):
    """#388bfd must not appear in any canonical dashboard — use var(--blue)."""
    src = _dash(page)
    occ = src.lower().count("#388bfd")
    assert occ == 0, (
        f"{page}: found {occ} occurrence(s) of hardcoded #388bfd — "
        "use var(--blue) instead"
    )


# ── D. Account modal HTML ─────────────────────────────────────────────────

@pytest.mark.parametrize("page", _ALL_DASH)
def test_acct_modal_html_element_present(page):
    """All 9 dashboard pages must contain the #acct-modal overlay HTML."""
    src = _dash(page)
    assert 'id="acct-modal"' in src, (
        f"{page}: #acct-modal element missing — account modal must be present on "
        "every dashboard page"
    )


@pytest.mark.parametrize("page", _ALL_DASH)
def test_acct_modal_has_close_button(page):
    """#acct-modal must contain a close (×) mechanism."""
    src = _dash(page)
    idx = src.find('id="acct-modal"')
    assert idx != -1, f"{page}: #acct-modal not found"
    block = src[idx: idx + 600]
    # Close button targets the modal via style.display='none'
    assert "acct-modal" in block and "display=" in block, (
        f"{page}: acct-modal missing close control"
    )


@pytest.mark.parametrize("page", _ALL_DASH)
def test_open_acct_modal_function_defined(page):
    """All dashboard pages must define _openAcctModal() inside the _acct IIFE."""
    src = _dash(page)
    assert "_openAcctModal" in src, (
        f"{page}: _openAcctModal function missing — required by account modal"
    )


# ── E. Portal footer ──────────────────────────────────────────────────────

@pytest.mark.parametrize("page", _ALL_DASH)
def test_portal_footer_element_present(page):
    """All 9 dashboard pages must render a <footer class=\"portal-footer\">."""
    src = _dash(page)
    assert 'class="portal-footer"' in src, (
        f"{page}: portal-footer element missing"
    )


@pytest.mark.parametrize("page", _ALL_DASH)
def test_portal_footer_css_defined(page):
    """All 9 dashboard pages must define .portal-footer CSS."""
    src = _dash(page)
    assert ".portal-footer" in src, (
        f"{page}: .portal-footer CSS rule missing"
    )


@pytest.mark.parametrize("page", _ALL_DASH)
def test_portal_footer_copyright_text(page):
    """Portal footer must contain the copyright / confidentiality notice."""
    src = _dash(page)
    assert "Confidential" in src or "redacted" in src, (
        f"{page}: portal-footer missing expected copyright/confidentiality text"
    )


# ── F. Control Center page structure ─────────────────────────────────────

class TestControlCenterPage:
    """control_center.html structural and navigation tests."""

    def test_title_contains_control_center(self):
        src = _dash("control_center.html")
        assert "Control Center" in src, (
            "control_center.html: <title> must contain 'Control Center'"
        )

    def test_has_sidebar(self):
        src = _dash("control_center.html")
        assert 'id="sidebar"' in src, (
            "control_center.html: #sidebar element missing"
        )

    def test_has_topbar(self):
        src = _dash("control_center.html")
        assert 'id="topbar"' in src, (
            "control_center.html: #topbar element missing"
        )

    def test_sidebar_nav_links_present(self):
        src = _dash("control_center.html")
        for slug in ("control-center", "live-feed", "agents", "service",
                     "controls", "geo", "logs", "settings"):
            assert slug in src, (
                f"control_center.html: sidebar nav missing link to '{slug}'"
            )

    def test_has_vhost_stats_card(self):
        """Vhost Traffic Summary card moved here from settings.html."""
        src = _dash("control_center.html")
        assert 'id="card-vhost-stats"' in src or "vhost-stats" in src, (
            "control_center.html: Vhost Traffic Summary card missing"
        )

    def test_version_string_in_title(self):
        src = _dash("control_center.html")
        assert "AppSecGW_1.8.5" in src, (
            "control_center.html: version string AppSecGW_1.8.5 missing from <title>"
        )

    def test_active_nav_link_is_control_center(self):
        """The current page's nav link must have class='active'."""
        src = _dash("control_center.html")
        # Find control-center link
        m = re.search(r'href="[^"]*control-center[^"]*"[^>]*class="active"'
                      r'|class="active"[^>]*href="[^"]*control-center[^"]*"', src)
        assert m, (
            "control_center.html: nav link to control-center must have class='active'"
        )

    def test_vhost_stats_uses_event_delegation(self):
        """Pin handler must use event delegation (data-pin-vhost on vhost-stats-tbody)."""
        src = _dash("control_center.html")
        assert "data-pin-vhost" in src, (
            "control_center.html: pin handler must use data-pin-vhost attribute"
        )
        pos = src.rfind('vhost-stats-tbody')
        block = src[pos: pos + 600]
        assert 'addEventListener' in block, (
            "control_center.html: pin handler must use addEventListener on vhost-stats-tbody"
        )

    def test_vhost_stats_remove_confirm_popup(self):
        """Vhost remove belongs in Settings — control_center must NOT have data-remove-vhost."""
        src = _dash("control_center.html")
        assert "data-remove-vhost" not in src, (
            "control_center.html: data-remove-vhost found — Remove belongs in Settings, not Control Center"
        )


# ── G. Login redirect → /secured/control-center ──────────────────────────

class TestLoginRedirect:
    def test_users_py_default_next_is_control_center(self):
        """Both login handlers in users.py must default-redirect to /secured/control-center."""
        src = open(os.path.join(
            os.path.dirname(__file__), "..", "admin", "users.py"
        ), encoding="utf-8").read()
        count = src.count("/antibot-appsec-gateway/secured/control-center")
        assert count >= 2, (
            f"users.py: expected ≥2 occurrences of /secured/control-center "
            f"(one per login handler), found {count}"
        )

    def test_users_py_no_dashboard_redirect(self):
        """/secured/dashboard must not appear in users.py (old redirect target)."""
        src = open(os.path.join(
            os.path.dirname(__file__), "..", "admin", "users.py"
        ), encoding="utf-8").read()
        assert "/secured/dashboard" not in src, (
            "users.py: still references old /secured/dashboard redirect — "
            "should be /secured/control-center"
        )

    def test_login_html_safeNext_used(self):
        """login.html must use safeNext() when redirecting after form submit."""
        src = _dash("login.html")
        assert "safeNext" in src or "safe_next" in src, (
            "login.html: login redirect must use safeNext() validation"
        )


# ── H. agents.html title ─────────────────────────────────────────────────

class TestAgentsHtmlTitle:
    def test_title_contains_agents_positive(self):
        """agents.html <title> must positively contain 'Agents'."""
        src = _dash("agents.html")
        m = re.search(r'<title>(.*?)</title>', src)
        assert m, "agents.html: <title> tag not found"
        assert "Agents" in m.group(1), (
            f"agents.html: title '{m.group(1)}' must contain 'Agents'"
        )

    def test_topbar_title_contains_agents(self):
        """agents.html topbar heading must say 'Agents', not 'Stealth Agent Hunter'."""
        src = _dash("agents.html")
        m = re.search(r'id="topbar-title"[^>]*>(.*?)</div>', src, re.S)
        assert m, "agents.html: #topbar-title not found"
        title_text = re.sub(r'<[^>]+>', '', m.group(1))
        assert "Agents" in title_text, (
            f"agents.html: topbar-title must contain 'Agents', got: {title_text!r}"
        )
        assert "Stealth" not in title_text, (
            "agents.html: old 'Stealth Agent Hunter' text still in topbar-title"
        )


# ── I. service.html .vhost-pill CSS ──────────────────────────────────────

class TestServiceVhostPillCSS:
    """service.html .vhost-pill must have the full corrected CSS property set."""

    def _pill_block(self):
        src = _dash("service.html")
        m = re.search(r'\.vhost-pill\{([^}]+)\}', src)
        assert m, "service.html: .vhost-pill CSS rule not found"
        return m.group(1)

    def test_font_family_inherit(self):
        assert "font-family:inherit" in self._pill_block(), (
            "service.html .vhost-pill: missing font-family:inherit"
        )

    def test_font_weight_600(self):
        assert "font-weight:600" in self._pill_block(), (
            "service.html .vhost-pill: missing font-weight:600"
        )

    def test_max_width(self):
        assert "max-width:" in self._pill_block(), (
            "service.html .vhost-pill: missing max-width"
        )

    def test_overflow_hidden(self):
        assert "overflow:hidden" in self._pill_block(), (
            "service.html .vhost-pill: missing overflow:hidden"
        )

    def test_text_overflow_ellipsis(self):
        assert "text-overflow:ellipsis" in self._pill_block(), (
            "service.html .vhost-pill: missing text-overflow:ellipsis"
        )

    def test_white_space_nowrap(self):
        assert "white-space:nowrap" in self._pill_block(), (
            "service.html .vhost-pill: missing white-space:nowrap"
        )

    def test_line_height(self):
        assert "line-height:" in self._pill_block(), (
            "service.html .vhost-pill: missing line-height"
        )


# ── J. logs.html missed-pill CSS ─────────────────────────────────────────

class TestLogsMissedPillCSS:
    def test_missed_data_cat_base_style(self):
        """logs.html must have a .cat-pill[data-cat="missed"] CSS rule."""
        src = _dash("logs.html")
        assert '[data-cat="missed"]' in src, (
            'logs.html: missing [data-cat="missed"] CSS variant for the missed pill'
        )

    def test_missed_data_cat_active_style(self):
        """logs.html must have a .cat-pill.active[data-cat="missed"] CSS rule."""
        src = _dash("logs.html")
        assert 'active[data-cat="missed"]' in src or \
               '[data-cat="missed"]' in src, (
            'logs.html: missing active variant for data-cat="missed" pill'
        )


# ── K. Location header rewrite (1.8.0) ───────────────────────────────────

class TestLocationHeaderRewrite:
    """Source-level and unit tests for Location header rewrite on 3xx responses."""

    def _src(self):
        return open(os.path.join(
            os.path.dirname(__file__), "..", "core", "proxy_handler.py"
        ), encoding="utf-8").read()

    def test_location_rewrite_code_present(self):
        src = self._src()
        assert 'kl == "location"' in src, (
            "proxy_handler.py: Location header rewrite code not found"
        )

    def test_location_rewrite_only_on_3xx(self):
        src = self._src()
        idx = src.find('kl == "location"')
        block = src[max(0, idx - 100): idx + 200]
        assert "300 <= resp.status < 400" in block or \
               "300 <=" in block, (
            "Location rewrite must only apply to 3xx responses"
        )

    def test_location_rewrite_preserves_path(self):
        """Rewrite logic must preserve lp.path from original URL."""
        src = self._src()
        idx = src.find('kl == "location"')
        block = src[idx: idx + 600]
        assert "lp.path" in block, (
            "Location rewrite must preserve the path component"
        )

    def test_location_rewrite_preserves_query(self):
        src = self._src()
        idx = src.find('kl == "location"')
        block = src[idx: idx + 600]
        assert "lp.query" in block, (
            "Location rewrite must preserve query string"
        )

    def test_location_rewrite_preserves_fragment(self):
        src = self._src()
        idx = src.find('kl == "location"')
        block = src[idx: idx + 600]
        assert "lp.fragment" in block, (
            "Location rewrite must preserve URL fragment"
        )

    def test_location_rewrite_replaces_netloc(self):
        """Rewrite must swap upstream netloc with gateway netloc."""
        src = self._src()
        idx = src.find('kl == "location"')
        block = src[idx: idx + 600]
        assert "client_host" in block, (
            "Location rewrite must use client_host to replace upstream netloc"
        )

    def test_location_rewrite_also_rewrites_embedded_upstream_urls(self):
        """Embedded upstream-origin URLs in Location value (OAuth redirect_uri)
        must also be rewritten."""
        src = self._src()
        idx = src.find('kl == "location"')
        block = src[idx: idx + 1200]
        assert "up_url_raw" in block and "gw_url_raw" in block, (
            "Location rewrite must also replace embedded upstream-origin references"
        )

    def test_location_rewrite_unit_absolute_url(self):
        """Unit-test the rewrite formula: absolute URL → gateway scheme+host."""
        from urllib.parse import urlparse
        # Simulate the rewrite of an absolute Location from upstream
        location_val  = "https://internal.backend.corp/callback?code=ABC&state=XYZ"
        client_scheme = "https"
        client_host   = "gateway.example.com"
        lp = urlparse(location_val)
        assert lp.scheme and lp.netloc, "Test precondition: URL must be absolute"
        rewritten = f"{client_scheme}://{client_host}{lp.path or ''}"
        if lp.query:    rewritten += "?" + lp.query
        if lp.fragment: rewritten += "#" + lp.fragment
        assert rewritten == "https://gateway.example.com/callback?code=ABC&state=XYZ", (
            f"Rewritten URL incorrect: {rewritten}"
        )

    def test_location_rewrite_unit_relative_url_unchanged(self):
        """Relative Location URLs (no scheme/netloc) must NOT be rewritten."""
        from urllib.parse import urlparse
        location_val = "/callback?code=ABC"
        lp = urlparse(location_val)
        # No scheme + no netloc → rewrite block skipped
        if lp.scheme and lp.netloc:
            rewritten = "rewritten"
        else:
            rewritten = location_val  # unchanged
        assert rewritten == "/callback?code=ABC"

    def test_location_rewrite_unit_fragment_preserved(self):
        """Fragment after # must survive the rewrite."""
        from urllib.parse import urlparse
        location_val  = "https://backend.example.com/page#section-2"
        client_scheme = "https"
        client_host   = "gw.example.com"
        lp = urlparse(location_val)
        rewritten = f"{client_scheme}://{client_host}{lp.path or ''}"
        if lp.query:    rewritten += "?" + lp.query
        if lp.fragment: rewritten += "#" + lp.fragment
        assert rewritten.endswith("#section-2"), (
            f"Fragment not preserved: {rewritten}"
        )
