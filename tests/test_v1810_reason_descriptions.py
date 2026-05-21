"""1.8.10 — the score-breakdown reason maps must describe the gateway's own
admin-namespace reasons instead of showing the generic "No description
registered…" fallback.

These reasons (set in core/proxy_handler.py when a request hits the admin
namespace) were never registered in agents.html's BLOCK_DETAIL_JS, so the
identity score-breakdown rendered them as category OTHER with no explanation.
`internal-probe` in particular is the legacy (pre-1.8.10) label still present in
historical data; 1.8.10 split it into operator-self / admin-probe.
"""
import re
import pathlib

AGENTS = (pathlib.Path(__file__).resolve().parent.parent /
          "dashboards" / "agents.html").read_text(encoding="utf-8")

ADMIN_REASONS = ["internal-probe", "admin-probe", "operator-self",
                 "operator-passthrough", "admin-ip-blocked"]


def _map_block(name):
    """Return the JS object literal body for `const NAME = { ... };`."""
    m = re.search(r"const " + re.escape(name) + r"\s*=\s*\{(.*?)\n\};", AGENTS, re.S)
    assert m, f"{name} map not found in agents.html"
    return m.group(1)


def test_admin_reasons_have_descriptions():
    detail = _map_block("BLOCK_DETAIL_JS")
    for r in ADMIN_REASONS:
        assert f'"{r}":' in detail, f"BLOCK_DETAIL_JS missing description for {r!r}"


def test_admin_reasons_have_labels():
    labels = _map_block("BLOCK_LABELS_JS")
    for r in ADMIN_REASONS:
        assert f'"{r}":' in labels, f"BLOCK_LABELS_JS missing label for {r!r}"


def test_admin_reasons_categorised_as_admin():
    cat = _map_block("RISK_CATEGORY_JS")
    for r in ADMIN_REASONS:
        assert f'"{r}":"ADMIN"' in cat.replace(" ", ""), \
            f"RISK_CATEGORY_JS must map {r!r} to ADMIN (not OTHER)"


def test_admin_category_has_color_and_action():
    assert '"ADMIN":' in _map_block("RISK_CAT_COLORS"), "ADMIN missing from RISK_CAT_COLORS"
    assert '"ADMIN":' in _map_block("RISK_ACTION_JS"), "ADMIN missing from RISK_ACTION_JS"


def test_internal_probe_description_explains_legacy_split():
    detail = _map_block("BLOCK_DETAIL_JS")
    m = re.search(r'"internal-probe":\s*"([^"]+)"', detail)
    assert m, "internal-probe description not found"
    desc = m.group(1).lower()
    # must actually explain it, not be a placeholder
    assert "admin" in desc and ("legacy" in desc or "operator-self" in desc or "decoy" in desc), (
        f"internal-probe description is not informative: {m.group(1)!r}"
    )
    assert "no description registered" not in desc


def test_no_admin_reason_falls_through_to_placeholder():
    """Belt-and-braces: simulate the agents.html lookup chain for each reason and
    assert none resolves to the 'No description registered' fallback."""
    detail = _map_block("BLOCK_DETAIL_JS")
    keys = set(re.findall(r'"([a-z0-9-]+)":', detail))
    for r in ADMIN_REASONS:
        assert r in keys, f"{r!r} would hit the 'No description registered' fallback"
