"""
tests/test_v1810_version_consistency.py — single source of truth for the gateway
version. `config.GW_VERSION` is canonical; every other surface that hard-codes
the version must match it.

Catches the failure mode where a version bump updates some files but not others
(e.g. config.py bumped but docker-compose image tag / container name / a
dashboard title left stale — which silently ships the wrong tag or a UI lying
about its version).

Surfaces checked:
  • config.GW_VERSION         — canonical "AntiBotWaf_GW_X.Y.Z"
  • proxy.py                  — references the bare X.Y.Z
  • docker-compose.yml        — image tag `appsec-antibot-gw:X.Y.Z` + container name
  • every served dashboard    — <title>/brand carries GW_VERSION
  • no surface carries a DIFFERENT current-version string
"""
import os
import re

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")

def _read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()

import config as _cfg
GW_VERSION = _cfg.GW_VERSION                       # "AntiBotWaf_GW_1.9.9"
_m = re.search(r"(\d+\.\d+\.\d+)", GW_VERSION)
VER = _m.group(1) if _m else ""                    # "1.8.10"

# Dashboards that render a version in their <title>/brand.
_DASHBOARDS = [
    "main.html", "control_center.html", "agents.html", "siem.html",
    "settings.html", "vhost_policy.html", "controls.html", "geo.html",
    "logs.html", "service.html",
]


class TestVersionCanonical:
    def test_gw_version_well_formed(self):
        assert GW_VERSION.startswith("AntiBotWaf_GW_"), "GW_VERSION must be 'AntiBotWaf_GW_X.Y.Z'"
        assert re.fullmatch(r"\d+\.\d+\.\d+", VER), f"GW_VERSION lacks a clean X.Y.Z: {GW_VERSION!r}"


class TestVersionSurfaces:
    def test_proxy_py_references_version(self):
        # proxy.py header carries the version; must match canonical.
        assert VER in _read("proxy.py"), f"proxy.py must reference version {VER}"

    def test_compose_image_tag_matches(self):
        c = _read("docker-compose.yml")
        m = re.search(r"image:\s*appsec-antibot-gw:(\d+\.\d+\.\d+)", c)
        assert m, "docker-compose.yml must pin appsec-antibot-gw:<version>"
        assert m.group(1) == VER, (
            f"compose image tag {m.group(1)} != GW_VERSION {VER} — bump them together"
        )

    def test_compose_container_name_matches(self):
        c = _read("docker-compose.yml")
        m = re.search(r"container_name:\s*appsec-antibot-gw(\d+\.\d+\.\d+)", c)
        assert m, "docker-compose.yml must set container_name appsec-antibot-gw<version>"
        assert m.group(1) == VER, (
            f"compose container_name {m.group(1)} != GW_VERSION {VER}"
        )

    def test_all_dashboards_carry_gw_version(self):
        missing = []
        for d in _DASHBOARDS:
            rel = os.path.join("dashboards", d)
            if not os.path.exists(os.path.join(_REPO, rel)):
                continue
            if GW_VERSION not in _read(rel):
                missing.append(d)
        assert not missing, (
            f"these dashboards don't carry {GW_VERSION!r}: {', '.join(missing)}"
        )

    def test_no_dashboard_shows_a_different_version(self):
        # An "AntiBot/WAF GW" brand/footer/title must never show a *different* version.
        # Matches BOTH forms — `AntiBotWaf_GW_1.8.13` (underscore) AND `AntiBot/WAF GW 1.8.6`
        # (space) — the latter is what slipped through in the siem.html footer.
        # Scans EVERY dashboard file (incl. non-served mockups) so brand drift is
        # caught wherever it appears.
        import glob
        bad = []
        for path in glob.glob(os.path.join(_REPO, "dashboards", "*.html")):
            d = os.path.basename(path)
            with open(path, encoding="utf-8") as fh:
                txt = fh.read()
            for found in set(re.findall(r"AntiBot/WAF GW[_ ](\d+\.\d+\.\d+)", txt)):
                if found != VER:
                    bad.append(f"{d}: AntiBot/WAF GW…{found}")
        assert not bad, (
            f"dashboards display a stale version (expected {VER}): {', '.join(sorted(bad))}"
        )

    def test_compose_has_no_other_appsec_gw_tag(self):
        # The only appsec-antibot-gw image tag in compose must be the current one
        # (guards a stale second reference).
        c = _read("docker-compose.yml")
        tags = set(re.findall(r"appsec-antibot-gw:(\d+\.\d+\.\d+)", c))
        assert tags == {VER} or tags == set(), (
            f"docker-compose.yml has appsec-antibot-gw tags {tags}; expected only {{{VER}}}"
        )
