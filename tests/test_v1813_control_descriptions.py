"""
tests/test_v1813_control_descriptions.py — every detection control must carry a
defined tier AND a non-empty description.

The Controls / Risk-score-breakdown UI iterates `RISK_WEIGHTS` and looks each
reason up in `scoring_endpoint`'s `DESCRIPTIONS` map (reason -> (tier, description)),
falling back to `("?", "")` when a reason is absent. A control with no entry
therefore renders with an unknown tier and a blank description.

These guards fail if any control in RISK_WEIGHTS lacks a DESCRIPTIONS entry, or
if any entry is malformed / empty / uses an unrecognised tier — so a new control
can't ship without a tier + description.
"""
import ast
import os

_REPO = os.path.join(os.path.dirname(__file__), "..")
_VALID_TIERS = {"hard", "med", "soft", "info", "intel", "modifier"}


def _dict_literal(path, name):
    """{key: ast_value_node} for the first `name = { ... }` assignment in `path`.

    Static parse — no import side-effects (config writes .admin_key on import).
    Finds the dict even when it's a function-local (e.g. DESCRIPTIONS lives
    inside scoring_endpoint).
    """
    tree = ast.parse(open(os.path.join(_REPO, path), encoding="utf-8").read())
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)
                and isinstance(node.value, ast.Dict)):
            return {k.value: v for k, v in zip(node.value.keys, node.value.values)
                    if isinstance(k, ast.Constant)}
    raise AssertionError(f"{name} dict literal not found in {path}")


def _risk_weights():
    return _dict_literal("config.py", "RISK_WEIGHTS")


def _descriptions():
    return _dict_literal("core/proxy_handler.py", "DESCRIPTIONS")


def test_every_control_has_tier_and_description():
    """Every RISK_WEIGHTS control must have a DESCRIPTIONS entry."""
    rw, desc = _risk_weights(), _descriptions()
    missing = sorted(r for r in rw if r not in desc)
    assert not missing, (
        "controls in RISK_WEIGHTS with no DESCRIPTIONS entry (they render '?'/'' "
        f"on the Controls dashboard) — add a (tier, description) for: {missing}")


def test_no_description_entry_is_malformed():
    """Every DESCRIPTIONS value is a (tier, description) with a valid tier and
    a non-empty description string."""
    bad = []
    for reason, node in _descriptions().items():
        if not (isinstance(node, ast.Tuple) and len(node.elts) == 2
                and all(isinstance(e, ast.Constant) for e in node.elts)):
            bad.append((reason, "not a (tier, description) tuple"))
            continue
        tier, descr = node.elts[0].value, node.elts[1].value
        if tier not in _VALID_TIERS:
            bad.append((reason, f"unrecognised tier {tier!r}"))
        if not (isinstance(descr, str) and descr.strip()):
            bad.append((reason, "empty description"))
    assert not bad, f"malformed DESCRIPTIONS entries: {bad}"


def test_descriptions_use_only_known_tiers():
    tiers = {n.elts[0].value for n in _descriptions().values()
             if isinstance(n, ast.Tuple) and n.elts and isinstance(n.elts[0], ast.Constant)}
    unknown = tiers - _VALID_TIERS
    assert not unknown, (
        f"DESCRIPTIONS uses tiers outside the known set {sorted(_VALID_TIERS)}: {sorted(unknown)}")


def test_scoring_endpoint_sources_tier_desc_from_descriptions():
    """Lock the contract this guard relies on: the scoring endpoint iterates
    RISK_WEIGHTS and resolves tier/description via DESCRIPTIONS."""
    src = open(os.path.join(_REPO, "core/proxy_handler.py"), encoding="utf-8").read()
    assert "for sig, w in sorted(RISK_WEIGHTS.items()" in src, (
        "scoring_endpoint must iterate RISK_WEIGHTS as the canonical control set")
    assert "DESCRIPTIONS.get(sig" in src, (
        "scoring_endpoint must resolve tier/description from DESCRIPTIONS")
