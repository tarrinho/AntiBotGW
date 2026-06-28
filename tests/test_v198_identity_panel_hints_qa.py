"""
QA — Identity panel "n/a · <reason>" hints (1.9.8 UX).

Before 1.9.8 the panel showed a bare `—` whenever session / fingerprint
/ JA4 (TLS) were absent, and IP-intelligence sub-systems printed a
cryptic `(disabled)` / `(private)` / `(error)` token. The operator had
to guess WHY data was missing. This iteration substitutes:

  - session/fingerprint/JA4 empty → "n/a · <reason>" tailored to the
    client class (cookieless monitor vs human/JS) and the deployment
    (fingerproxy sidecar present or not).
  - sub-system source token → human label + per-layer "how to enable"
    hint (e.g. `set ABUSEIPDB_KEY env to enable`).
  - whole /ip-intel fetch failure → message + diagnosis (401 →
    "session expired or idle-timed-out · re-login to refresh").

These tests are source-level grep guards — they fail loudly if a
refactor drops the helper or wires the wrong field.
"""
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_AGENTS = (_ROOT / "dashboards" / "agents.html").read_text(encoding="utf-8")
_MAIN   = (_ROOT / "dashboards" / "main.html").read_text(encoding="utf-8")

DASHBOARDS = [("agents.html", _AGENTS), ("main.html", _MAIN)]


class TestNaHintHelper:
    """Every dashboard with the Identity panel ships `_naHint(field, value, ua)`."""

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_helper_defined(self, name, src):
        assert "function _naHint(" in src, f"{name}: _naHint helper missing"

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_helper_handles_known_bot_uas(self, name, src):
        """Cookieless-monitor regex must cover the canonical bot list."""
        idx = src.find("function _naHint(")
        window = src[idx: idx + 1500]
        for needle in ("uptimerobot", "pingdom", "statuscake",
                       "site24x7", "curl\\/", "python-requests"):
            assert needle in window.lower(), (
                f"{name}: _naHint regex missing bot UA token {needle!r}"
            )

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_helper_emits_contextual_session_reason(self, name, src):
        idx = src.find("function _naHint(")
        window = src[idx: idx + 1500]
        assert "cookieless monitor" in window
        assert "no agw_session" in window

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_helper_emits_fingerprint_reason(self, name, src):
        idx = src.find("function _naHint(")
        window = src[idx: idx + 1500]
        assert "no JS executed" in window

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_helper_emits_ja4_reason(self, name, src):
        idx = src.find("function _naHint(")
        window = src[idx: idx + 1500]
        assert "fingerproxy sidecar not deployed" in window


class TestIdentityCellsUseNaHint:
    """The session/fingerprint/JA4 cells must call _naHint, not escapeHtml."""

    PATS = (
        re.compile(r"k\"\s*>\s*session\s*</span>\s*<span\s+class=\"v\">\s*\$\{_naHint\('session',"),
        re.compile(r"k\"\s*>\s*fingerprint\s*</span>\s*<span\s+class=\"v\">\s*\$\{_naHint\('fingerprint',"),
        re.compile(r"k\"\s*>\s*JA4 \(TLS\)\s*</span>\s*<span\s+class=\"v\">\s*\$\{_naHint\('ja4',"),
    )

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_each_cell_uses_helper(self, name, src):
        for pat in self.PATS:
            assert pat.search(src), (
                f"{name}: identity cell still calls escapeHtml directly — "
                f"missing _naHint wiring for /{pat.pattern[:40]}…/"
            )


class TestSubSystemSrcLabels:
    """Sub-system source token (disabled/private/error/ok/stale) must
    be rendered through `_src(...)` + `_hint(layer, source)` so the
    operator sees a human label and a per-layer "how to enable" hint."""

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_src_helper_defined(self, name, src):
        assert "_srcLabel" in src and "const _src = " in src, (
            f"{name}: _src(source) helper missing"
        )

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_src_label_map_covers_all_sources(self, name, src):
        """The endpoint emits these tokens — every one must have a label."""
        idx = src.find("_srcLabel")
        window = src[idx: idx + 1500]
        for token in ("ok", "stale", "cached", "disabled",
                      "private", "invalid", "error"):
            assert f"'{token}'" in window, (
                f"{name}: _srcLabel missing {token!r}"
            )

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_explain_map_has_actionable_hints(self, name, src):
        """For 'disabled' source the operator must see how to enable."""
        idx = src.find("_explain")
        window = src[idx: idx + 1500]
        for needle in ("ABUSEIPDB_KEY", "CROWDSEC_LAPI_URL",
                       "GeoLite2-ASN.mmdb", "GeoLite2-City.mmdb"):
            assert needle in window, (
                f"{name}: _explain missing actionable hint {needle!r}"
            )


class TestAbuseIpdbAndCrowdSecRowsRewired:
    """The AbuseIPDB / CrowdSec rows must now go through `_src(...)` +
    `_hint('abuseipdb'|'crowdsec', ...)` — NOT the old bare token."""

    OLD_PATS = (
        re.compile(r"escapeHtml\(ab\.source\|\|'\?'\)"),
        re.compile(r"escapeHtml\(cs\.source\|\|'\?'\)"),
    )

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_old_cryptic_token_removed(self, name, src):
        for pat in self.OLD_PATS:
            assert not pat.search(src), (
                f"{name}: still emits the old cryptic ab/cs source token"
            )

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_new_helpers_wired_for_abuseipdb(self, name, src):
        assert "_src(ab.source)" in src
        assert "_hint('abuseipdb'" in src

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_new_helpers_wired_for_crowdsec(self, name, src):
        assert "_src(cs.source)" in src
        assert "_hint('crowdsec'" in src


class TestIpIntelFetchErrorMessage:
    """When /ip-intel itself fails (401/403/404/5xx), the error line
    must carry a one-sentence diagnosis — not just a bare HTTP code."""

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_401_diagnosis_present(self, name, src):
        assert "session expired or idle-timed-out" in src, (
            f"{name}: 401 diagnosis missing — operator will see bare HTTP 401"
        )

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_403_diagnosis_present(self, name, src):
        assert "role lacks admin" in src

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_404_diagnosis_present(self, name, src):
        assert "endpoint not deployed" in src


class TestDataInitPreservesEmptyForRenderer:
    """`raw.session/fingerprint/ja4` falling-back-to '' (not '—') so
    the renderer can detect "no data" and substitute the hint."""

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_session_default_is_empty_string(self, name, src):
        assert re.search(
            r"session:\s+raw\.session\s+\|\|\s+raw\.last_session\s+\|\|\s+''",
            src,
        ), f"{name}: session field still defaults to '—' — renderer can't hint"

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_fingerprint_default_is_empty_string(self, name, src):
        assert re.search(
            r"fingerprint:\s+raw\.fingerprint\|\|\s+raw\.last_fingerprint\|\|\s+''",
            src,
        )

    @pytest.mark.parametrize("name,src", DASHBOARDS, ids=[d[0] for d in DASHBOARDS])
    def test_ja4_default_is_empty_string(self, name, src):
        assert re.search(r"ja4:\s+raw\.ja4\s+\|\|\s+''", src)
