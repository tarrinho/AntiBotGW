"""
tests/test_v191_iter17_pg_events_read_guard.py — comprehensive guard
against SQLite-only `FROM events WHERE ts <op> ?` SQL strings.

After the iter-16 sweep we discovered the codebase still has ~10
production sites that compare `events.ts` against an epoch int without
wrapping the bound in `to_timestamp(?)` — these silently return empty
results (or raise) in PG-only mode. The previous tests caught the four
sites we fixed; this file enforces the bigger picture:

  1) **Strict guard**: every NEW production SQL containing
     `FROM events` + a `ts <op> ?` comparison MUST either include a
     `to_timestamp(?)` form somewhere in the same function OR route
     through `db_read_events`.

  2) **Known-broken inventory**: this file ALSO records the set of
     pre-existing offenders that the iter-16 sweep missed. The test
     asserts EVERY offender is in the inventory — so a refactor that
     fixes one prunes the inventory (catches accidental regressions
     in the same file) and a new offender lands as a test failure.

How to add a new event-read endpoint without breaking this test:

  - Preferred: route through `db.db_read_events(start_ts, end_ts, …)`.
    The helper handles the cross-backend wrapping.

  - Acceptable: branch by `active_backend()`. In the PG branch use
    `WHERE ts >= to_timestamp(?)` and (for arithmetic) project ts via
    `EXTRACT(EPOCH FROM ts)`. In the SQLite branch keep the SQLite
    form. See `dashboards/service_metrics.py` (iter-16) for the pattern.

  - Last-resort exemption: append a `(filename, line_number, reason)`
    tuple to `_KNOWN_OFFENDERS_TODO_ITER17` below with a TODO comment
    in the source explaining why this site is SQLite-only.
"""

import os
import re

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Production directories that must be PG-aware.
_PROD_DIRS = ("admin", "core", "dashboards", "scoring", "detection", "rate_limit.py", "proxy.py")

# Files that are SQLite-only by design (writer queue, settings export
# bundle, PG→SQLite migration target). These are not bugs.
_SQLITE_ONLY_OK = {
    "db/sqlite.py",          # the SQLite implementation itself
    "db/postgres.py",        # PG↔SQLite migration target uses local SQLite
    "db/import.py",          # CLI tool: source is always a SQLite file
    "db/export.py",          # CLI tool: target is always a SQLite file
}

# Pre-existing SQLite-only event reads. A dedicated iter-17 sweep will
# fix each of these by adding a backend-aware PG branch; until then
# they're documented here so this test fails the moment a NEW offender
# lands or a documented one disappears (= got fixed).
#
# Each entry: (filename, normalised first-100-char SQL fingerprint).
# Generated from the live source — see CONTRIBUTING.md for the
# regenerate snippet. To prune an entry after fixing the site, simply
# delete the tuple; the test asserts every fingerprint still matches
# code so stale entries fail loudly.
_KNOWN_OFFENDERS_TODO_ITER17: set = set()
# iter-17 sweep complete (2026-06-11) — all 17 sites previously listed here
# now have backend-aware PG branches. Categories swept:
#   - core/proxy_handler.py × 7: geo-bucket cursor, geo-target-points,
#     path-detail rows, agents bucket-detail (block/clean/authorized-
#     robot/gwmgmt)
#   - admin/settings.py × 2: per-vhost slot read, DISTINCT vhost scan
#   - dashboards/agents.py × 5: detected/allowed/authorized/missed/gwmgmt
#     bucketed COUNT(*) reads
#   - dashboards/analytics.py × 3: vhost block-rate heatmap, incident
#     feed, ban-event timeline aggregator
# The set being empty is the goal — the main guard test now ensures NO
# new SQL slips in without a PG branch. To document a new exemption,
# add it back with a (file, fingerprint) tuple and a comment explaining
# why the SQLite-only path is intentional.


def _sql_fingerprint(sql):
    """Stable 100-char prefix of the joined SQL, whitespace collapsed.
    Long enough to disambiguate sibling SQLs in the same file (e.g. the
    5 bucket reads in `dashboards/agents.py`)."""
    return re.sub(r"\s+", " ", sql).strip()[:100]


_RE_FROM_EVENTS = re.compile(r"FROM\s+events\b", re.IGNORECASE)
# UNWRAPPED ts comparison: `ts >= ?` (or `<=`, `<`, `>`, `=`) NOT followed
# by `to_timestamp(`. This is the actual broken form that fails on PG.
_RE_TS_UNWRAPPED = re.compile(
    r"\bts\s*[<>=]+\s*(?!to_timestamp\s*\()(?:\?|\$\d+)",
    re.IGNORECASE,
)
# A "PG-aware sibling SQL" is one where every ts comparison IS wrapped.
# We look for `ts <op> to_timestamp(...)` as the positive signal.
_RE_TS_WRAPPED = re.compile(
    r"\bts\s*[<>=]+\s*to_timestamp\s*\(",
    re.IGNORECASE,
)
_RE_STRFTIME_TS = re.compile(
    r"strftime\s*\(\s*['\"]%[wHd]['\"][^,)]*,\s*ts\b",
    re.IGNORECASE,
)


def _iter_prod_py_files():
    """Yield (relpath, source) for every production .py file."""
    for root, _dirs, files in os.walk(_REPO):
        # Stay inside production directories. Top-level files (proxy.py
        # etc.) are included via the explicit names.
        rel_root = os.path.relpath(root, _REPO)
        if rel_root == ".":
            for fn in files:
                if fn == "proxy.py" or fn == "rate_limit.py":
                    rel = fn
                    yield rel, open(os.path.join(root, fn), encoding="utf-8").read()
            continue
        top = rel_root.split(os.sep, 1)[0]
        if top not in ("admin", "core", "dashboards", "scoring", "detection"):
            continue
        for fn in files:
            if not fn.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(root, fn), _REPO).replace(os.sep, "/")
            yield rel, open(os.path.join(root, fn), encoding="utf-8").read()


def _extract_sql_strings(src):
    """Concatenate adjacent string literals on the same logical statement
    so multi-line SQL like

        conn.execute(
            "SELECT … "
            "FROM events "
            "WHERE ts >= ? AND …"
        )

    matches as a single fingerprint. We don't need a full parser — a
    line-by-line concat of consecutive double/single-quoted literals
    inside the same parenthesised group is enough for the static grep
    pattern this test relies on.

    Operates on the original source so `m.start()` aligns with the
    line numbering callers compute via `src.count("\\n", 0, offset)`."""
    pat = re.compile(
        r'((?:[fr]?"[^"\\]*(?:\\.[^"\\]*)*"\s*)+)',
        re.DOTALL,
    )
    out = []
    for m in pat.finditer(src):
        chunks = re.findall(r'[fr]?"([^"\\]*(?:\\.[^"\\]*)*)"', m.group(0))
        joined = "".join(chunks)
        if "FROM events" in joined or "From events" in joined or "from events" in joined:
            out.append((m.start(), joined))
    return out


def _line_no_at(src, offset):
    return src.count("\n", 0, offset) + 1


def _surrounding_text(src, offset, span=400):
    """Return ±span chars around offset — used to detect a sibling PG
    branch in the same function/code block."""
    return src[max(0, offset - span):min(len(src), offset + span)]


def _has_pg_branch_or_helper(src, offset, sql_text=""):
    """The site is OK if EITHER:
      - the SQL literal itself wraps EVERY `ts <op> ?` comparison in
        `to_timestamp(...)` (= it IS the PG branch), OR
      - the SQL is the SQLite branch of a backend-aware `if/else` and the
        PG sibling SQL lives in the SAME if/else block, OR
      - the call routes through `db_read_events` (the helper handles
        backend coercion internally).

    Sibling detection: walk backwards from the SQL offset until we hit
    an `if … postgres` line; if that block contains `to_timestamp(?)`
    within the slice between the `if` and the SQL we treat it as the
    sibling PG branch of a real if/else. Crucially we DO NOT fall back
    to a fixed-radius source window — that produced false negatives
    where a `to_timestamp` in an unrelated nearby function falsely
    cleared a broken site (caught by iter-17 sweep QA).

    Note: `EXTRACT(EPOCH FROM ts)` alone does NOT count — that projects
    the column for arithmetic but doesn't fix the broken WHERE bound."""
    # If the SQL itself has any unwrapped `ts <op> ?`, it's NOT OK on its
    # own. To be the PG branch, every comparison must be wrapped.
    if sql_text:
        if not _RE_TS_UNWRAPPED.search(sql_text):
            return True
        if _RE_TS_WRAPPED.search(sql_text) and not _RE_TS_UNWRAPPED.search(sql_text):
            return True

    # db_read_events routes through the backend-aware helper — count it.
    window = _surrounding_text(src, offset, span=1500)
    if "db_read_events" in window:
        return True

    # Walk back to the nearest backend-check line (`if _be_X == "postgres":`
    # or `if backend == "postgres":` or `if active_backend() == "postgres":`).
    # If found, the if/else block is the boundary — to_timestamp(?) on
    # the PG side must be PRESENT (between the `if` and the SQL slice
    # if we're in the SQLite-branch else, OR before the `else:` if we're
    # in the PG branch slice — but we already handled "we are the PG
    # branch" above).
    look_back = src[max(0, offset - 4000):offset]
    if_match = list(re.finditer(
        r'if\s+(?:_be(?:_\w+)?|backend|active_backend\(\))\s*==\s*[\'"]postgres[\'"]\s*:',
        look_back,
    ))
    if not if_match:
        return False
    # Slice from the `if` to the SQL — if a to_timestamp(?) exists there,
    # this IS the SQLite else-branch of a real if/else block.
    if_pos = if_match[-1].start()  # nearest preceding `if`
    block = src[max(0, offset - 4000) + if_pos:offset]
    return bool(_RE_TS_WRAPPED.search(block))


def _offender_key_for(rel_path, sql_text):
    """Inventory key for a SQL match — just (path, 100-char fingerprint)."""
    return (rel_path, _sql_fingerprint(sql_text))


# ── Tests ──────────────────────────────────────────────────────────────


def test_all_pg_unsafe_event_reads_are_known_or_branched():
    """Every production SQL that compares events.ts to an epoch int must
    either (a) include a PG-aware branch (to_timestamp / EXTRACT) within
    the same code block, (b) route through db_read_events, OR (c) be in
    the known-offender inventory awaiting iter-17 sweep.

    A new SQL that satisfies none of these fails the test — that's how
    we prevent the iter-16-class bug from recurring."""
    unexpected = []
    for rel, src in _iter_prod_py_files():
        if rel in _SQLITE_ONLY_OK:
            continue
        for offset, sql in _extract_sql_strings(src):
            if not (_RE_FROM_EVENTS.search(sql) and _RE_TS_UNWRAPPED.search(sql)):
                continue
            if _has_pg_branch_or_helper(src, offset, sql_text=sql):
                continue
            key = _offender_key_for(rel, sql)
            if key not in _KNOWN_OFFENDERS_TODO_ITER17:
                unexpected.append(
                    f"{rel}:{_line_no_at(src, offset)}: "
                    f"SQL has `ts <op> ?` against events but no PG branch — "
                    f"either add `to_timestamp(?)` PG branch, route through "
                    f"db_read_events, or add this fingerprint to "
                    f"_KNOWN_OFFENDERS_TODO_ITER17 with a TODO. Inventory "
                    f"key would be: {key!r}"
                )
    assert not unexpected, (
        "found PG-unsafe event reads NOT in the known-offender inventory:\n"
        + "\n".join(unexpected)
    )


def test_known_offenders_inventory_still_present():
    """Sanity check: every fingerprint in the inventory must still match
    a SQL in the corresponding file. A refactor that fixes an offender
    should also prune its entry — otherwise the inventory rots and the
    main check above becomes a false sense of coverage."""
    found_keys = set()
    for rel, src in _iter_prod_py_files():
        if rel in _SQLITE_ONLY_OK:
            continue
        for offset, sql in _extract_sql_strings(src):
            if not (_RE_FROM_EVENTS.search(sql) and _RE_TS_UNWRAPPED.search(sql)):
                continue
            if _has_pg_branch_or_helper(src, offset, sql_text=sql):
                continue
            key = _offender_key_for(rel, sql)
            if key in _KNOWN_OFFENDERS_TODO_ITER17:
                found_keys.add(key)
    stale = _KNOWN_OFFENDERS_TODO_ITER17 - found_keys
    assert not stale, (
        "_KNOWN_OFFENDERS_TODO_ITER17 has stale entries — the corresponding "
        "SQL was either fixed (prune the entry) or its fingerprint changed "
        "(regenerate from the live source). "
        f"Stale: {sorted(stale)}"
    )


def test_no_strftime_on_events_ts_in_production_code():
    """SQLite's `strftime('%w', ts, 'unixepoch')` and friends are SQLite-
    only — PG uses `EXTRACT(DOW/HOUR/...)`. Any production occurrence
    that isn't inside a PG-branched else must be explicitly handled
    (iter-16 fixed the dow×hour heatmap; this guards against new
    regressions)."""
    bad = []
    for rel, src in _iter_prod_py_files():
        if rel in _SQLITE_ONLY_OK:
            continue
        for m in _RE_STRFTIME_TS.finditer(src):
            # Allow if the same function also contains EXTRACT(... FROM ts)
            # — that means the SQLite-only call lives in the SQLite branch
            # of a backend-aware if/else.
            window = src[max(0, m.start() - 600):m.start() + 600]
            if re.search(r"EXTRACT\s*\(\s*(?:DOW|HOUR|DAY|MONTH|YEAR|EPOCH)\s+FROM\s+ts",
                         window, re.IGNORECASE):
                continue
            bad.append(f"{rel}:{src.count(chr(10), 0, m.start()) + 1}: "
                       f"strftime(...) on `ts` without sibling EXTRACT() PG branch")
    assert not bad, (
        "found strftime() on events.ts without a PG-mode EXTRACT() branch:\n"
        + "\n".join(bad)
    )


def test_iter16_fixed_sites_still_have_pg_branch():
    """Regression guard for the four sites the iter-16 sweep fixed —
    ensures a future refactor doesn't accidentally drop the PG branch."""
    expected = [
        ("dashboards/analytics.py",
         "sparklines: dict =",
         "ban_expiry: dict",
         "EXTRACT(EPOCH FROM ts) AS ts"),
        ("admin/settings.py",
         "skip_ph  = \",\".join(\"?\" * len(_SKIP_REASONS))",
         "reasons_seen: dict",
         "EXTRACT(EPOCH FROM ts)"),
        ("admin/settings.py",
         "start_ts = _t.time() - range_min * 60",
         "cells   = [[int(r",
         "EXTRACT(DOW"),
        ("dashboards/service_metrics.py",
         "Per-vhost traffic counters from events table",
         "app_info = {",
         "to_timestamp(?)"),
    ]
    for rel, start_anchor, end_anchor, must_contain in expected:
        src = open(os.path.join(_REPO, rel), encoding="utf-8").read()
        si = src.find(start_anchor)
        assert si != -1, f"start anchor lost in {rel}: '{start_anchor}'"
        ei = src.find(end_anchor, si)
        assert ei != -1, f"end anchor lost in {rel}: '{end_anchor}'"
        block = src[si:ei]
        assert must_contain in block, (
            f"{rel}: iter-16 fix lost — block between '{start_anchor}' "
            f"and '{end_anchor}' must contain '{must_contain}'"
        )


def test_inventory_is_non_empty_set_of_tuples():
    """Every entry must be a (file, fingerprint) pair with both parts
    non-trivial. Stops a future contributor from accidentally adding a
    bare string or empty tuple."""
    assert isinstance(_KNOWN_OFFENDERS_TODO_ITER17, set), (
        "_KNOWN_OFFENDERS_TODO_ITER17 must be a set so membership lookup "
        "in the main check is O(1)"
    )
    for entry in _KNOWN_OFFENDERS_TODO_ITER17:
        assert isinstance(entry, tuple) and len(entry) == 2, (
            f"inventory entry must be a (path, fingerprint) tuple; got {entry!r}"
        )
        path, fp = entry
        assert path and "/" in path, f"{path!r}: path must be a relpath"
        assert fp and len(fp) >= 30, (
            f"{fp!r}: fingerprint must be ≥30 chars to disambiguate sibling "
            f"SQLs in the same file"
        )
