"""
tests/test_v1814_vhost_policy_picker.py — guard the Vhost Policy picker
fix.

Pre-1.8.14 the dropdown sourced hosts only from `vhost-policy-data.vhosts`
(VHOSTS dict — operator-configured overrides). A host served by the
default UPSTREAM (e.g. pt4.tech with no per-vhost overrides yet) was
invisible, so the operator could not add the FIRST override to it.

Fix merges configured + recently-seen (vhost-stats) so the picker shows
every known host. Static + behavioural checks against
dashboards/vhost_policy.html and the backend wiring.
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
HTML = os.path.join(_REPO, "dashboards", "vhost_policy.html")
SETTINGS_PY = os.path.join(_REPO, "admin", "settings.py")
PROXY_PY = os.path.join(_REPO, "proxy.py")


def _src(path=HTML):
    return open(path, encoding="utf-8").read()


# ── core merge contract ──────────────────────────────────────────────────

def test_picker_merges_stats_into_dropdown():
    src = _src()
    # The merge uses a _hostSet keyed by hostname populated from BOTH sources.
    assert "_hostSet" in src, "picker must build a merged host set"
    assert "_hostSet[vh]={cfg:true}" in src, (
        "configured vhosts must be flagged cfg=true in the merge set")
    assert "_hostSet[s.hostname]" in src and "{cfg:false}" in src, (
        "stats-only vhosts must be added with cfg=false")


def test_picker_iterates_merged_set_not_only_configured():
    """The dropdown loop must iterate the merged keyset, not d.vhosts."""
    src = _src()
    assert "Object.keys(_hostSet).sort()" in src, (
        "merged keyset must be the iteration source")
    loop_block = src.split("_allHosts.forEach", 1)
    assert len(loop_block) == 2, "dropdown must iterate _allHosts.forEach(...)"


def test_picker_marks_stats_only_hosts_visibly():
    """Stats-only hosts (no overrides yet) should be visibly tagged so the
    operator knows they exist on traffic alone, not as policy entries."""
    src = _src()
    assert "no overrides" in src, (
        "stats-only host labels must carry a visible 'no overrides' hint")


# ── merge invariants ─────────────────────────────────────────────────────

def test_configured_wins_over_stats_on_collision():
    """If a host appears in BOTH d.vhosts and sd.stats, the configured flag
    must win — operator must see it as configured, not stats-only."""
    src = _src()
    # Stats loop must NOT overwrite the cfg flag — it must only add the
    # entry if not already present, and may attach `last_seen`.
    stats_block = re.search(
        r'sd\.stats[\s\S]{0,400}?if\s*\(\s*!_hostSet\[s\.hostname\]\s*\)\s*'
        r'_hostSet\[s\.hostname\]\s*=\s*\{cfg:false\};', src)
    assert stats_block is not None, (
        "stats loop must use `if (!_hostSet[host])` guard so a configured "
        "host can't be downgraded to cfg:false")


def test_picker_sorts_hosts_alphabetically():
    """A wall of unsorted hosts is unreadable; sorted output is the contract."""
    src = _src()
    assert ".sort()" in src.split("_hostSet", 1)[1].split("_allHosts.forEach", 1)[0], (
        "merged keyset must be sorted before iteration")


def test_picker_clears_options_before_repopulating():
    """Re-load must not append duplicates onto an already-populated select."""
    src = _src()
    # Look for the explicit clear: keep option 0 (the placeholder), drop rest.
    assert "while(sel.options.length>1) sel.remove(1)" in src, (
        "select must be cleared (except the placeholder) before re-populating")


def test_picker_preserves_selected_host():
    """When _loadData is called with a hostname, the matching option must be
    pre-selected so the operator's choice survives a re-load."""
    src = _src()
    # the new option-creation loop must compare value to the hostname param
    assert "if(vh===hostname) opt.selected=true" in src, (
        "matching option must be pre-selected when hostname param given")


def test_stats_endpoint_failure_is_swallowed():
    """A failing /vhost-stats fetch must not break the picker — it falls back
    to an empty stats array so the configured vhosts still render."""
    src = _src()
    # The fetch chain must defend with .catch returning a safe shape.
    assert re.search(
        r'/vhost-stats[\s\S]{0,300}?\.catch\([\s\S]{0,80}?\{stats:\[\]\}', src), (
        "vhost-stats fetch must .catch into a {stats:[]} fallback")


# ── backend wiring ───────────────────────────────────────────────────────

def test_vhost_stats_endpoint_registered_in_router():
    """The picker depends on /antibot-appsec-gateway/secured/vhost-stats —
    if the route disappears, the merge silently degrades to configured-only."""
    src = _src(PROXY_PY)
    assert re.search(r'\(\s*"vhost-stats"\s*,\s*"GET"', src), (
        "vhost-stats route must remain registered")


def test_vhost_policy_data_endpoint_lowercases_hostname():
    """admin/settings.py:1117 normalises hostname to lowercase before the
    VHOSTS lookup — otherwise an operator typing `PT4.tech` would silently
    miss the entry."""
    src = _src(SETTINGS_PY)
    block = src.split("vhost_policy_data_endpoint", 1)[1][:1500]
    assert ".strip().lower()" in block, (
        "vhost-policy-data must lowercase the hostname param before VHOSTS lookup")


def test_vhost_policy_data_returns_all_configured_vhosts():
    """Backend contract: response.vhosts must come from vhost_list() (full
    VHOSTS dict), never a filtered subset."""
    src = _src(SETTINGS_PY)
    block = src.split("vhost_policy_data_endpoint", 1)[1][:4000]
    assert 'from vhost import' in block and "vhost_list" in block, (
        "endpoint must import vhost_list, not a stats-derived helper")
    # vhosts payload must be hostname extraction from vhost_list() output.
    assert re.search(
        r'"vhosts"\s*:\s*\[\s*v\["hostname"\]\s*for\s+v\s+in\s+vhost_list\(\)\s*\]',
        block), (
        "response.vhosts must be [v['hostname'] for v in vhost_list()] — "
        "raw, full dict, no filtering")


def test_vhost_list_iterates_full_vhosts_dict():
    """vhost.py:vhost_list() must iterate the whole VHOSTS dict — a partial
    iteration would silently truncate the picker's source-of-truth."""
    src = _src(os.path.join(_REPO, "vhost.py"))
    block = src.split("def vhost_list", 1)[1][:400]
    assert "VHOSTS.items()" in block, (
        "vhost_list() must yield from VHOSTS.items(), no prefix filter")


# ── empty / edge cases ──────────────────────────────────────────────────

def test_picker_handles_empty_both_sources():
    """When neither configured nor stats exist (cold start), the dropdown
    must still render with the placeholder, not crash."""
    src = _src()
    # The merge logic must default to empty arrays so the .forEach is safe.
    assert "(d.vhosts||[])" in src, "d.vhosts access must default to []"
    assert "(sd.stats||[])"  in src, "sd.stats access must default to []"


def test_picker_search_box_threshold():
    """Search box only useful when the list is long. Confirm threshold ≥8
    so a small fleet doesn't get extra UI clutter."""
    src = _src()
    assert re.search(r"_visCount\s*>=\s*8", src), (
        "search input must only appear when _visCount >= 8")


# ── SILENT badge (matches control_center heatmap >30min convention) ────

def test_picker_marks_silent_vhosts():
    """Configured vhosts with no traffic in the last 30 min must carry a
    visible SILENT marker so the operator can spot stale entries — matches
    the control_center heatmap convention (`SILENT badge = no traffic for
    >30 min`)."""
    src = _src()
    assert "_SILENT_THRESHOLD_S" in src and "1800" in src, (
        "picker must use a 30-min (1800s) threshold matching control_center")
    assert "— SILENT" in src, "picker labels must visibly tag silent vhosts"


def test_silent_threshold_uses_last_seen_age():
    """The badge must be computed from last_seen age (not a static flag) so
    a vhost that was silent yesterday but received traffic 5 min ago
    correctly drops the badge."""
    src = _src()
    # Compare (now - last_seen) > threshold; treat missing last_seen as silent.
    assert re.search(r"_now\s*-\s*_ls.*_SILENT_THRESHOLD_S", src), (
        "silent decision must compare (now - last_seen) > _SILENT_THRESHOLD_S")
    assert re.search(r"_ls\s*===?\s*0", src), (
        "missing last_seen (0) must count as silent")


def test_silent_badge_orthogonal_to_overrides_badge():
    """A configured-silent host shows just `— SILENT`; a stats-only-silent
    host shows `— no overrides — SILENT`. The two markers are independent."""
    src = _src()
    # Both markers must be append-only — no early returns that skip one.
    block = src.split("_allHosts.forEach", 1)[1][:800]
    assert "_parts.push('— no overrides')" in block, (
        "no-overrides label must be additive, not exclusive")
    assert "_parts.push('— SILENT')" in block, (
        "SILENT label must be additive, not exclusive")


# ── seen_vhosts (historical merge) ───────────────────────────────────────

def test_picker_merges_historical_seen_vhosts():
    """Dropdown must also surface d.seen_vhosts (30-day historical set) so
    quiet hosts outside the 24h /vhost-stats window remain pickable."""
    src = _src()
    assert "d.seen_vhosts" in src, (
        "dashboards/vhost_policy.html must consume d.seen_vhosts from "
        "/secured/vhost-policy-data")
    # The merge step must add them with cfg=false (same shape as stats-only).
    # Find the JS forEach that iterates d.seen_vhosts (not the comment line).
    m = re.search(r"\(d\.seen_vhosts\|\|\[\]\)\.forEach.*?\}\);",
                  src, re.DOTALL)
    assert m, (
        "dashboards/vhost_policy.html must call "
        "(d.seen_vhosts||[]).forEach(...) to merge historical hosts")
    assert "_hostSet[vh]={cfg:false}" in m.group(0), (
        "seen_vhosts entries must be added to _hostSet as cfg=false when "
        "not already present from VHOSTS overrides")


def test_vhost_policy_data_endpoint_returns_seen_vhosts():
    """Backend /vhost-policy-data must expose seen_vhosts (DISTINCT vhost
    over the last 30 days from the events table)."""
    src = _src(SETTINGS_PY)
    assert "\"seen_vhosts\":" in src, (
        "vhost_policy_data_endpoint must include 'seen_vhosts' in JSON body")
    assert re.search(
        r"SELECT DISTINCT vhost FROM events.*WHERE vhost\s*!=\s*''.*ts\s*>=",
        src, re.DOTALL,
    ), (
        "seen_vhosts must come from DISTINCT vhost on the events table with "
        "a non-empty filter and a time-bound cutoff"
    )
