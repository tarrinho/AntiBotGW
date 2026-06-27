"""
QA tests — `.last-publish.json` marker contract (rules.md §13c).

`publish.sh` writes this file at the repo root after every successful push to
both GitHub origins. The pre-flight gate before §14 (build + Harbor push) needs
to know the public docs/code are in sync with the version about to be shipped,
otherwise the GitHub history drifts behind (5+ versions silently slipped past
the May 25 / 1.8.13 tag in the wild — see screenshot 2026-06-27).

Pass criterion enforced here:
  1. `.last-publish.json` exists at repo root
  2. JSON parses + has the documented keys
  3. `version` field == current `GW_VERSION` (minus the `AntiBotWaf_GW_` prefix)
  4. `timestamp` is ≤ 14 days old (ISO-8601 UTC)
  5. Both repos have a non-`unknown` HEAD sha

If the marker is missing (first-ever check on a host where publish.sh has not
yet been run), the suite is XFAILed with `MARKER_NOT_PRESENT` so the absence is
visible without breaking unrelated CI. Override with
`AGW_REQUIRE_PUBLISH_MARKER=1` to turn that XFAIL into a hard FAIL.

Skip the freshness window with `AGW_SKIP_PUBLISH_FRESHNESS=1` (useful while
working offline / no Mac access). The version + structural checks always run.
"""
import datetime as _dt
import json
import os
import pathlib
import re

import pytest

# ── Source ───────────────────────────────────────────────────────────────────
_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MARKER = _ROOT / ".last-publish.json"
_CONFIG = _ROOT / "config.py"

_FRESH_DAYS = int(os.environ.get("AGW_PUBLISH_FRESH_DAYS", "14"))
_REQUIRE_MARKER = os.environ.get("AGW_REQUIRE_PUBLISH_MARKER") == "1"
_SKIP_FRESHNESS = os.environ.get("AGW_SKIP_PUBLISH_FRESHNESS") == "1"


def _current_version() -> str:
    txt = _CONFIG.read_text(encoding="utf-8")
    m = re.search(r"AntiBotWaf_GW_([0-9]+\.[0-9]+\.[0-9]+)", txt)
    assert m, "could not parse GW_VERSION from config.py"
    return m.group(1)


def _load_marker():
    if not _MARKER.exists():
        if _REQUIRE_MARKER:
            pytest.fail(
                f"MARKER_NOT_PRESENT: {_MARKER} missing — publish.sh has not "
                "been run, or .last-publish.json got deleted. Run publish.sh "
                "on the Mac, or unset AGW_REQUIRE_PUBLISH_MARKER to soft-skip."
            )
        pytest.xfail(
            "MARKER_NOT_PRESENT: .last-publish.json absent — publish.sh has "
            "never been run on this checkout. Run publish.sh on the Mac to "
            "create it. Set AGW_REQUIRE_PUBLISH_MARKER=1 to make this a hard "
            "FAIL."
        )
    return json.loads(_MARKER.read_text(encoding="utf-8"))


# ── 1. Structural ────────────────────────────────────────────────────────────

class TestMarkerStructure:
    """Marker file exists, parses as JSON, and has the documented schema."""

    def test_marker_is_valid_json(self):
        data = _load_marker()
        assert isinstance(data, dict), "marker must be a JSON object"

    def test_marker_has_required_keys(self):
        data = _load_marker()
        required = {"timestamp", "version", "tag", "released", "corporate", "personal"}
        missing = required - set(data)
        assert not missing, f"marker missing keys: {sorted(missing)}"

    def test_per_repo_blocks_have_head_and_remote(self):
        data = _load_marker()
        for repo in ("corporate", "personal"):
            block = data.get(repo, {})
            assert isinstance(block, dict), f"{repo} entry must be an object"
            assert "head" in block, f"{repo}.head missing"
            assert "remote" in block, f"{repo}.remote missing"

    def test_heads_are_non_unknown_sha(self):
        data = _load_marker()
        bad = []
        for repo in ("corporate", "personal"):
            head = data[repo]["head"]
            if head == "unknown" or len(head) < 7 or not re.fullmatch(r"[0-9a-f]+", head):
                bad.append((repo, head))
        assert not bad, (
            f"per-repo HEAD shas missing or 'unknown' — publish.sh could "
            f"not read git rev-parse: {bad}"
        )


# ── 2. Version match ─────────────────────────────────────────────────────────

class TestMarkerVersion:
    """The version stamped on the marker must equal the current
    `GW_VERSION` constant — otherwise the docs/code on GitHub are
    stale (or the marker is stale)."""

    def test_marker_version_matches_gw_version(self):
        data = _load_marker()
        current = _current_version()
        marker_v = data.get("version", "")
        assert marker_v == current, (
            f"VERSION_DRIFT: marker says {marker_v!r}, GW_VERSION says "
            f"{current!r}. Either run publish.sh on the Mac (preferred) "
            f"or bump-version.sh if the marker is the correct one."
        )

    def test_tag_matches_version(self):
        data = _load_marker()
        ver = data.get("version", "")
        tag = data.get("tag", "")
        assert tag == f"v{ver}", (
            f"tag {tag!r} does not match version {ver!r} (expected v{ver})"
        )


# ── 3. Freshness ─────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    _SKIP_FRESHNESS,
    reason="AGW_SKIP_PUBLISH_FRESHNESS=1 (offline / no Mac access)",
)
class TestMarkerFreshness:
    """The marker timestamp must be within the last 14 days. A longer
    gap means the GitHub repos have silently drifted from the local
    working tree (the symptom reported on 2026-06-27 — 5 releases
    silently slipped past 1.8.13 / May 25)."""

    def test_timestamp_parses_as_iso8601_utc(self):
        data = _load_marker()
        ts = data.get("timestamp", "")
        # Accept trailing Z (Zulu) and optional fractional seconds.
        cleaned = ts.rstrip("Z")
        try:
            _dt.datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            try:
                _dt.datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S.%f")
            except ValueError as e:
                pytest.fail(f"timestamp {ts!r} not ISO-8601 UTC: {e}")

    def test_timestamp_within_window(self):
        data = _load_marker()
        cleaned = data["timestamp"].rstrip("Z")
        try:
            ts = _dt.datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            ts = _dt.datetime.strptime(cleaned, "%Y-%m-%dT%H:%M:%S.%f")
        age_days = (_dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None) - ts).days
        assert age_days <= _FRESH_DAYS, (
            f"STALE_PUBLISH: marker is {age_days}d old (> {_FRESH_DAYS}d "
            "threshold). Run publish.sh on the Mac to push current state, "
            "or set AGW_PUBLISH_FRESH_DAYS to a higher value if you really "
            "want to skip a release."
        )
