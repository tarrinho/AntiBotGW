"""
tests/test_v1814_vacuum_sqlite_only.py — guard the
Vacuum-DB-is-SQLite-only contract in the Settings page.

The Vacuum DB button + VACUUM history table apply only to the SQLite event
store. Postgres / TimescaleDB has its own autovacuum daemon, so showing the
manual control next to a Postgres-active deployment was misleading.

Fix: wrap the vacuum controls + history in dedicated IDs and toggle their
visibility via _dbUpdateActiveBadges(), which already runs on initial load
and after every /db-switch. A Postgres-only note replaces them.
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
HTML = os.path.join(_REPO, "dashboards", "settings.html")


def _src():
    return open(HTML, encoding="utf-8").read()


def test_vacuum_controls_wrapped_with_id():
    """Manual VACUUM button + status must live inside #vacuum-controls-row
    so a single element toggle can hide both at once."""
    src = _src()
    assert 'id="vacuum-controls-row"' in src, (
        "VACUUM button row must carry id='vacuum-controls-row' for "
        "backend-aware visibility toggling"
    )
    # Must contain the button (otherwise wrap is unrelated to vacuum).
    block = src.split('id="vacuum-controls-row"', 1)[1][:300]
    assert 'id="btn-vacuum"' in block, (
        "#vacuum-controls-row must wrap the Vacuum DB button"
    )


def test_vacuum_history_wrapped_with_id():
    """VACUUM history (#vacuum-history) must live inside a wrap div so the
    'Last 5 VACUUM runs' header is hidden together with the body."""
    src = _src()
    assert 'id="vacuum-history-wrap"' in src, (
        "VACUUM history must be wrapped in id='vacuum-history-wrap'"
    )


def test_postgres_note_block_present():
    """A short note must replace the vacuum controls when Postgres is
    active — explains that Postgres has its own autovacuum."""
    src = _src()
    assert 'id="vacuum-pg-note"' in src, (
        "must declare id='vacuum-pg-note' for the postgres-active hint"
    )
    block = src.split('id="vacuum-pg-note"', 1)[1][:600]
    assert "autovacuum" in block.lower(), (
        "postgres note must explain that Postgres has its own autovacuum daemon"
    )


def test_db_update_active_badges_toggles_vacuum_visibility():
    """_dbUpdateActiveBadges() — the function called on initial load AND
    after a /db-switch — must toggle all three vacuum elements based on
    whether the active backend is sqlite."""
    src = _src()
    m = re.search(r"function\s+_dbUpdateActiveBadges\b.*?\n\s*\}",
                  src, re.DOTALL)
    assert m, "must define _dbUpdateActiveBadges()"
    body = m.group(0)
    for el_id in ("vacuum-controls-row",
                  "vacuum-history-wrap",
                  "vacuum-pg-note"):
        assert el_id in body, (
            f"_dbUpdateActiveBadges must reference #{el_id} so it toggles "
            "alongside the sqlite/postgres backend badges"
        )
    # Must key on whether backend is postgres (NOT a literal string match).
    assert "backend !== 'postgres'" in body or "backend === 'sqlite'" in body, (
        "toggle predicate must be a real backend check, not hardcoded"
    )


def test_loadvacuumhistory_skips_when_postgres():
    """The history endpoint should not be fetched when Postgres is active —
    avoids a needless round-trip per page load. Two acceptable patterns:
      (a) loadVacuumHistory() early-returns if the wrap is hidden, OR
      (b) loadDb() only calls loadVacuumHistory() when sqlite is active."""
    src = _src()
    has_guard_a = ("vacuum-history-wrap" in src
                   and "style.display === 'none'" in src
                   and "return" in src)
    has_guard_b = re.search(
        r"_dbOrig\s*===?\s*['\"]sqlite['\"][^{]*loadVacuumHistory",
        src, re.DOTALL,
    ) is not None
    assert has_guard_a or has_guard_b, (
        "loadVacuumHistory must NOT fire when DB_BACKEND=postgres — either "
        "guard the function or only call it from loadDb() when sqlite"
    )


def test_initial_loadvacuumhistory_call_removed_or_guarded():
    """The unconditional top-level loadVacuumHistory() call must be removed
    (loadDb() drives it conditionally) — otherwise postgres deployments
    still fetch on every page load."""
    src = _src()
    # Find the "Initial load." block and look for an unguarded call.
    m = re.search(r"// Initial load\.[\s\S]{0,500}", src)
    if m:
        block = m.group(0)
        # An unguarded `loadVacuumHistory();` line in the initial block is
        # what we want to NOT exist.
        assert not re.search(r"^\s*loadVacuumHistory\(\);\s*$",
                             block, re.MULTILINE), (
            "Unconditional loadVacuumHistory() in the 'Initial load.' block "
            "defeats the postgres-skip optimisation — drop it; let loadDb() "
            "call it only when sqlite is active"
        )


def test_switch_to_sqlite_refreshes_vacuum_history():
    """After a /db-switch that activates sqlite, loadVacuumHistory() must
    run so the newly-revealed wrap doesn't stay on 'Loading…'."""
    src = _src()
    # The post-switch handler is a one-shot. Look for the pattern around the
    # db-switch onclick where target is 'sqlite'.
    assert re.search(
        r"target\s*===?\s*['\"]sqlite['\"][^{]*loadVacuumHistory",
        src, re.DOTALL,
    ), (
        "post-switch handler must call loadVacuumHistory() when switching "
        "TO sqlite so the wrap populates immediately"
    )
