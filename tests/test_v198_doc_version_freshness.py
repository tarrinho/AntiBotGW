"""
Doc version-freshness guard (1.9.8).

Prevents the recurrence found 2026-06-27: several markdown docs carried stale
version banners/examples while the gateway had moved on — README pinned to
1.8.15, CONTROLS.md to 1.7.3, analysis.result.md to 1.7.8 — so the public docs
lied about the shipped version.

Rules enforced:
  1. "Living" docs (README/MANUAL/CONTROLS/analysis/manual-README) must carry
     the CURRENT GW version in every gateway-version banner/example, and nowhere
     reference a *different* gateway version in those banner forms. (Historical
     "feature added in 1.8.x" annotations in prose are NOT banner forms and are
     allowed.)
  2. Explicitly historical docs (IMPROVEMENTS / threatmodel) must carry a
     "point-in-time" / "historical snapshot" marker so they are not mistaken for
     current.
  3. No tracked markdown may reference a gateway version NEWER than current
     (typo / premature-bump guard).

The version source of truth is config.py GW_VERSION.
"""
import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent


def _current_version():
    m = re.search(r'GW_VERSION\s*=\s*"AntiBotWaf_GW_([0-9]+\.[0-9]+\.[0-9]+)"',
                  (_REPO / "config.py").read_text(encoding="utf-8"))
    assert m, "could not read GW_VERSION from config.py"
    return m.group(1)


CUR = _current_version()

# Gateway-version banner/example forms (NOT bare prose feature tags like "(1.8.14)").
_BANNER_PATTERNS = [
    r'appsec-antibot-gw1?:?([0-9]+\.[0-9]+\.[0-9]+)',          # image / container tag
    r'AntiBotWaf_GW[/_]([0-9]+\.[0-9]+\.[0-9]+)',              # GW_VERSION string forms
    r'AppSecGW[/_]([0-9]+\.[0-9]+\.[0-9]+)',                   # legacy name form (must not reappear)
    r'\*\*Version\*\*:\s*([0-9]+\.[0-9]+\.[0-9]+)',            # **Version**: X
    r'Architecture \(([0-9]+\.[0-9]+\.[0-9]+)\)',              # ## Architecture (X)
]

# Docs that MUST track the current version.
LIVING = ["README.md", "MANUAL.md", "CONTROLS.md", "analysis.result.md", "manual/README.md"]
# Docs that are intentionally point-in-time (must say so).
HISTORICAL = ["IMPROVEMENTS.md", "threatmodel.md"]


def _vt(s):
    return tuple(int(x) for x in s.split("."))


@pytest.mark.parametrize("rel", LIVING)
def test_living_doc_banners_are_current(rel):
    text = (_REPO / rel).read_text(encoding="utf-8")
    found = []
    for pat in _BANNER_PATTERNS:
        found += re.findall(pat, text)
    assert found, f"{rel}: no gateway-version banner/example found — should carry v{CUR}"
    stale = sorted({v for v in found if v != CUR})
    assert not stale, (
        f"{rel}: stale gateway-version banner(s) {stale} — must all be {CUR}. "
        f"Bump the doc (or regenerate it) when GW_VERSION changes.")


@pytest.mark.parametrize("rel", HISTORICAL)
def test_historical_doc_is_marked_point_in_time(rel):
    text = (_REPO / rel).read_text(encoding="utf-8").lower()
    assert ("point-in-time" in text or "historical snapshot" in text), (
        f"{rel}: a non-current doc must carry a 'point-in-time' / 'historical "
        f"snapshot' marker so it isn't mistaken for the current release.")


def test_no_doc_references_a_future_version():
    cur = _vt(CUR)
    offenders = {}
    for md in _REPO.glob("*.md"):
        text = md.read_text(encoding="utf-8")
        for pat in _BANNER_PATTERNS:
            for v in re.findall(pat, text):
                if _vt(v) > cur:
                    offenders.setdefault(md.name, set()).add(v)
    assert not offenders, f"docs reference a gateway version newer than {CUR}: {offenders}"
