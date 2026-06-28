"""
Regression guards for the publish pipeline — both-repo coverage (1.9.8).

Root cause found 2026-06-27: `copy-to-github.sh` hard-assigned `DEST=…corporate`
*unconditionally*, so it ignored the `DEST=` override that `publish.sh` passes
per repo. Every copy — including publish.sh's "personal" pass — silently landed
in the corporate repo, so the personal repo (`AntiBotGW`) drifted ~13 versions
behind (stuck at AppSecGW_1.8.5 while corporate was AntiBotWaf_GW_1.9.9).

These are static source-inspection guards (the scripts are Mac-pathed and not
executed in CI) so the regressions cannot silently return.
"""
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_COPY = (_REPO / "copy-to-github.sh").read_text(encoding="utf-8")
_PUBLISH = (_REPO / "publish.sh").read_text(encoding="utf-8")


# ── copy-to-github.sh must HONOR the DEST override (the actual bug) ────────────
def test_copy_script_honors_dest_override():
    assert re.search(r'^DEST="\$\{DEST:-', _COPY, re.M), \
        "copy-to-github.sh must default DEST via ${DEST:-…}; an unconditional " \
        "DEST=… clobbers the override and sends every copy to one repo"


def test_copy_script_has_no_unconditional_dest_assignment():
    # a bare  DEST="/abs/path"  (no ${DEST:-) at line start is the regression
    bad = re.search(r'^DEST="/[^"]*"\s*$', _COPY, re.M)
    assert bad is None, f"copy-to-github.sh has an unconditional DEST assignment: {bad.group(0)!r}"


def test_copy_script_next_steps_version_not_hardcoded():
    # the "git commit -m 'vX'" hint must be derived, never a frozen literal
    assert "git commit -m 'v1.8.7'" not in _COPY, "stale hardcoded version in Next-steps hint"
    assert "_CTG_VER" in _COPY and "config.py" in _COPY, \
        "Next-steps commit hint must derive the version from the copied config.py"


# ── publish.sh must target BOTH repos in every mutating stage ─────────────────
def test_publish_defines_both_repos():
    assert re.search(r'^CORP=', _PUBLISH, re.M) and re.search(r'^PERS=', _PUBLISH, re.M)


def test_publish_runs_every_stage_for_both_repos():
    for fn in ("preflight_one", "prepare_one", "apply_one"):
        assert re.search(rf'{fn} "corporate"', _PUBLISH), f"{fn} must run for corporate"
        assert re.search(rf'{fn} "personal"', _PUBLISH), f"{fn} must run for personal"


def test_publish_passes_per_repo_dest_to_copy():
    assert 'DEST="$dst"' in _PUBLISH, \
        "prepare_one must pass the per-repo DEST to copy-to-github.sh"


# ── apply_one must push when local is ahead, not only on new staged changes ───
def test_apply_pushes_when_ahead_of_origin():
    i = _PUBLISH.index("apply_one()")
    body = _PUBLISH[i: _PUBLISH.index("\n}", i)]
    assert "rev-list" in body and "..HEAD" in body, \
        "apply_one must compare origin..HEAD and push when ahead (self-heal a " \
        "prior failed push), not only when this run produced a staged change"


# ── cross-repo parity control must exist ──────────────────────────────────────
def test_publish_has_cross_repo_parity_check():
    assert "parity" in _PUBLISH.lower() and "ls-files" in _PUBLISH, \
        "publish.sh must compare the two repos' staged trees so a divergence " \
        "(one repo missing updates) is surfaced before push"
