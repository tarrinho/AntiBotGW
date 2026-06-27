"""
tests/test_v1810_admin_key_strength.py — Gate 0b enforcement: the admin key /
bootstrap password must be a strong (≥16-char random) secret, and no weak or
hard-coded admin key may be committed to env/compose/deploy files.

The runtime key is operator-supplied (env), so we can't test the live key here —
but we CAN guarantee the repo never ships a guessable/default/demo admin key,
and that compose uses env-passthrough rather than a baked-in value.
"""
import os
import re
import glob

_REPO = os.path.join(os.path.dirname(__file__), "..")

# Files that could carry a deploy-time admin key.
_CANDIDATES = (
    glob.glob(os.path.join(_REPO, ".env*"))
    + glob.glob(os.path.join(_REPO, "docker-compose*.yml"))
    + glob.glob(os.path.join(_REPO, "deploy*", "**", "*"), recursive=True)
)

_KEY_LINE = re.compile(r"^\s*(ADMIN_KEY|INTERNAL_KEY)\s*[:=]\s*(.+?)\s*$")
_WEAK = re.compile(r"(admin|password|passwd|test|changeme|1234|secret|local|qwerty)", re.I)


def _key_assignments():
    """Yield (file, keyname, value) for real (non-comment) ADMIN/INTERNAL_KEY
    assignments with a concrete value (not env-passthrough / blank / template)."""
    for path in _CANDIDATES:
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.lstrip().startswith("#"):
                    continue
                m = _KEY_LINE.match(line)
                if not m:
                    continue
                val = m.group(2).strip().strip('"').strip("'")
                # skip env-passthrough, blank, or templated placeholders
                if not val or val.startswith("${") or val.startswith("<"):
                    continue
                yield os.path.basename(path), m.group(1), val


def test_no_weak_admin_key_committed():
    weak = [(f, k, v) for f, k, v in _key_assignments() if _WEAK.search(v)]
    assert not weak, (
        "Weak/guessable admin key committed (Gate 0b): "
        + "; ".join(f"{f}:{k}={v!r}" for f, k, v in weak)
    )


def test_no_short_admin_key_committed():
    short = [(f, k, v) for f, k, v in _key_assignments() if len(v) < 16]
    assert not short, (
        "Committed admin key shorter than 16 chars (Gate 0b): "
        + "; ".join(f"{f}:{k}={v!r} (len {len(v)})" for f, k, v in short)
    )


def test_compose_uses_env_passthrough_for_admin_key():
    """docker-compose must NOT bake a literal admin key — it should pass the env
    through (e.g. `ADMIN_KEY: ${ADMIN_KEY:-}`) so the secret stays out of git."""
    bad = []
    for path in glob.glob(os.path.join(_REPO, "docker-compose*.yml")):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.lstrip().startswith("#"):
                    continue
                m = re.match(r"\s*(ADMIN_KEY|INTERNAL_KEY)\s*:\s*(.+?)\s*$", line)
                if not m:
                    continue
                val = m.group(2).strip()
                if val and not val.startswith("${"):
                    bad.append(f"{os.path.basename(path)}: {m.group(1)}: {val}")
    assert not bad, (
        "docker-compose must use env-passthrough for the admin key, not a literal: "
        + "; ".join(bad)
    )


def test_rule_documented_in_rules_and_manual():
    """The 16-char-random key rule must be codified (Gate 0b + MANUAL §0)."""
    with open(os.path.join(_REPO, "rules.md"), encoding="utf-8") as fh:
        rules = fh.read()
    with open(os.path.join(_REPO, "MANUAL.md"), encoding="utf-8") as fh:
        manual = fh.read()
    assert "0b" in rules and re.search(r"16[- ]char", rules), (
        "rules.md must define Gate 0b with the ≥16-char admin-key rule"
    )
    assert re.search(r"16[- ]char", manual), (
        "MANUAL §0 production checklist must require a ≥16-char random admin key"
    )
