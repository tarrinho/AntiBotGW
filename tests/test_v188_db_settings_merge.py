"""
test_v188_db_settings_merge.py
─────────────────────────────────────────────────────────────────────────────
QA tests for the DB-backend section merge from Controls → Settings (v1.8.8).

Merged features:
  - Active badges (● active) on the toggle side that is currently in use
  - Migration status row (#db-mig-status-row) with progress bar + poll helpers
  - Rich confirmation modal (_openDbModal) replacing browser confirm()
  - Live stats in ℹ popover via _dbSvcCache
  - _dbUpdateActiveBadges() drives the badge spans
"""

import re
import pathlib

SETTINGS = pathlib.Path(__file__).parent.parent / "dashboards" / "settings.html"
CONTROLS = pathlib.Path(__file__).parent.parent / "dashboards" / "controls.html"

_SRC   = SETTINGS.read_text(encoding="utf-8")
_CTRL  = CONTROLS.read_text(encoding="utf-8")


# ── HTML structure ────────────────────────────────────────────────────────────

class TestDbActiveBadges:
    """Active-badge spans are present in the settings card-db HTML."""

    def test_badge_sqlite_element_present(self):
        assert 'id="db-badge-sqlite"' in _SRC, \
            "settings.html must have #db-badge-sqlite span for active indicator"

    def test_badge_pg_element_present(self):
        assert 'id="db-badge-pg"' in _SRC, \
            "settings.html must have #db-badge-pg span for active indicator"

    def test_badge_sqlite_default_hidden(self):
        idx = _SRC.find('id="db-badge-sqlite"')
        assert idx != -1
        snippet = _SRC[idx:idx+200]
        assert "display:none" in snippet, \
            "#db-badge-sqlite must start hidden (display:none)"

    def test_badge_pg_default_hidden(self):
        idx = _SRC.find('id="db-badge-pg"')
        assert idx != -1
        snippet = _SRC[idx:idx+200]
        assert "display:none" in snippet, \
            "#db-badge-pg must start hidden (display:none)"

    def test_badge_active_text(self):
        assert "active" in _SRC[_SRC.find('id="db-badge-sqlite"'):_SRC.find('id="db-badge-sqlite"')+400], \
            "db-badge-sqlite must contain 'active' label text"
        assert "active" in _SRC[_SRC.find('id="db-badge-pg"'):_SRC.find('id="db-badge-pg"')+400], \
            "db-badge-pg must contain 'active' label text"


class TestDbMigStatusRow:
    """Migration status row HTML and JS present in settings."""

    def test_mig_row_element_present(self):
        assert 'id="db-mig-status-row"' in _SRC, \
            "settings.html must have #db-mig-status-row element for migration progress"

    def test_mig_row_inside_card_db(self):
        card_start = _SRC.find('id="card-db"')
        card_end   = _SRC.find('id="card-storage"')   # next card
        assert card_start != -1 and card_end != -1
        section = _SRC[card_start:card_end]
        assert 'id="db-mig-status-row"' in section, \
            "#db-mig-status-row must be inside #card-db"


class TestDbJsFunctions:
    """All new JS helper functions present in settings.html."""

    def test_render_mig_status_row_defined(self):
        assert "function _renderMigStatusRow" in _SRC, \
            "_renderMigStatusRow() must be defined in settings.html"

    def test_poll_mig_once_defined(self):
        assert "async function _pollMigOnce" in _SRC, \
            "_pollMigOnce() must be defined in settings.html"

    def test_start_mig_poll_defined(self):
        assert "function _startMigPoll" in _SRC, \
            "_startMigPoll() must be defined in settings.html"

    def test_open_db_modal_defined(self):
        assert "function _openDbModal" in _SRC, \
            "_openDbModal() must be defined in settings.html"

    def test_db_update_active_badges_defined(self):
        assert "function _dbUpdateActiveBadges" in _SRC, \
            "_dbUpdateActiveBadges() must be defined in settings.html"

    def test_db_svc_cache_declared(self):
        assert "_dbSvcCache" in _SRC, \
            "_dbSvcCache variable must be declared for live stats caching"

    def test_mig_poll_timer_declared(self):
        assert "_migPollTimer" in _SRC, \
            "_migPollTimer variable must be declared for interval management"


class TestDbLoadDbEnhanced:
    """loadDb() reads services.db and services.db_postgres from config endpoint."""

    def test_load_db_reads_services(self):
        idx = _SRC.find("async function loadDb")
        assert idx != -1
        snippet = _SRC[idx:idx+600]
        assert "services" in snippet, \
            "loadDb() must read services from config response"

    def test_load_db_populates_svc_cache(self):
        idx = _SRC.find("async function loadDb")
        assert idx != -1
        snippet = _SRC[idx:idx+600]
        assert "_dbSvcCache" in snippet, \
            "loadDb() must update _dbSvcCache with services.db / services.db_postgres"

    def test_load_db_calls_update_badges(self):
        idx = _SRC.find("async function loadDb")
        assert idx != -1
        snippet = _SRC[idx:idx+700]
        assert "_dbUpdateActiveBadges" in snippet, \
            "loadDb() must call _dbUpdateActiveBadges() with the active backend"

    def test_load_db_checks_migration_on_load(self):
        idx = _SRC.find("async function loadDb")
        assert idx != -1
        # iter-18: 1.8.14-era VACUUM history block was inserted into loadDb()
        # before the migration-poll call (loadVacuumHistory + comments now
        # occupy ~250 extra chars). Bumped 800 → 1500 so `_pollMigOnce`
        # stays in frame; intent (must poll on initial load) preserved.
        snippet = _SRC[idx:idx+1500]
        assert "_pollMigOnce" in snippet, \
            "loadDb() must poll migration status on initial load"

    def test_load_db_starts_poll_if_running(self):
        idx = _SRC.find("async function loadDb")
        assert idx != -1
        # iter-18: same widening as test_load_db_checks_migration_on_load.
        snippet = _SRC[idx:idx+1500]
        assert "_startMigPoll" in snippet, \
            "loadDb() must start the migration poll if mig.running is true"


class TestDbHoverTooltipLiveStats:
    """_dbShowTip() click-popover shows live stats from _dbSvcCache."""

    def test_show_tip_reads_svc_cache(self):
        # Use the function definition (window._dbShowTip = function) not the call site
        idx = _SRC.find("window._dbShowTip = function")
        assert idx != -1
        snippet = _SRC[idx:idx+1400]
        assert "_dbSvcCache" in snippet, \
            "_dbShowTip() must read _dbSvcCache to show live stats"

    def test_show_tip_shows_sqlite_stats(self):
        idx = _SRC.find("window._dbShowTip = function")
        assert idx != -1
        snippet = _SRC[idx:idx+1400]
        assert "size_bytes" in snippet, \
            "_dbShowTip() must display size_bytes for SQLite side"

    def test_show_tip_shows_pg_stats(self):
        idx = _SRC.find("window._dbShowTip = function")
        assert idx != -1
        snippet = _SRC[idx:idx+2200]
        assert "events_rows" in snippet, \
            "_dbShowTip() must display events_rows for PostgreSQL side"

    def test_show_tip_shows_pg_availability(self):
        idx = _SRC.find("window._dbShowTip = function")
        assert idx != -1
        snippet = _SRC[idx:idx+2400]
        assert "available" in snippet, \
            "_dbShowTip() must show PostgreSQL availability status"

    def test_no_info_button_in_db_card(self):
        card_start = _SRC.find('id="card-db"')
        card_end   = _SRC.find('id="card-storage"')
        assert card_start != -1 and card_end != -1
        section = _SRC[card_start:card_end]
        assert 'id="db-info-popover"' not in section, \
            "Old hover popover must be removed from card-db — uses click popover"

    def test_click_wired_on_db_sides(self):
        # Implementation uses click popover (_dbSideClick) not hover tooltip
        assert "onclick" in _SRC and "_dbSideClick" in _SRC, \
            "DB side panels must wire onclick to _dbSideClick"
        assert "_dbShowTip" in _SRC, \
            "_dbShowTip must be defined (called from _dbSideClick)"


class TestDbModal:
    """Rich confirmation modal replaces browser confirm()."""

    def test_no_native_confirm_in_apply(self):
        idx = _SRC.find("'btn-db-apply').addEventListener")
        assert idx != -1
        snippet = _SRC[idx:idx+400]
        assert "confirm(" not in snippet, \
            "btn-db-apply handler must not use browser confirm() — use _openDbModal()"

    def test_apply_calls_open_modal(self):
        idx = _SRC.find("'btn-db-apply').addEventListener")
        assert idx != -1
        snippet = _SRC[idx:idx+400]
        assert "_openDbModal" in snippet, \
            "btn-db-apply handler must call _openDbModal()"

    def test_modal_has_impact_lines(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+4000]
        assert "impactLines" in snippet, \
            "_openDbModal must define impactLines array with switch impact description"

    def test_modal_always_full_migrate(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+16000]
        assert "fullMigrate = true" in snippet, \
            "_openDbModal must always send fullMigrate=true (no opt-out checkbox)"

    def test_modal_sends_full_migrate_flag(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+16000]
        assert "full_migrate" in snippet, \
            "_openDbModal must send full_migrate flag to /secured/db-switch"

    def test_modal_has_postgres_dsn_override(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+4000]
        assert "db-switch-dsn" in snippet, \
            "_openDbModal must include optional DSN override input for postgres target"

    def test_modal_has_connection_test_button(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+4000]
        assert "db-test-btn" in snippet, \
            "_openDbModal must include a connection test button for postgres"

    def test_modal_pg_ok_btn_disabled_until_tested(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+4000]
        assert "disabled" in snippet and "needsTest" in snippet, \
            "_openDbModal must disable Yes-switch button until connection test passes for postgres"

    def test_modal_uses_show_simple_modal(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+4000]
        assert "showSimpleModal" in snippet, \
            "_openDbModal must use showSimpleModal() helper"

    def test_modal_updates_badges_on_success(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+16000]
        assert "_dbUpdateActiveBadges" in snippet, \
            "_openDbModal must call _dbUpdateActiveBadges() after a successful switch"

    def test_modal_starts_poll_when_full_migrate_scheduled(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+16000]
        assert "full_migrate_scheduled" in snippet, \
            "_openDbModal must check j.full_migrate_scheduled and start migration poll"

    def test_modal_cancel_button_present(self):
        idx = _SRC.find("function _openDbModal")
        assert idx != -1
        snippet = _SRC[idx:idx+4000]
        assert "db-switch-cancel" in snippet, \
            "_openDbModal must have Cancel button that closes the modal"


class TestDbUpdateActiveBadges:
    """_dbUpdateActiveBadges drives badge visibility correctly."""

    def test_sqlite_badge_shown_for_sqlite(self):
        idx = _SRC.find("function _dbUpdateActiveBadges")
        assert idx != -1
        snippet = _SRC[idx:idx+300]
        # When isSql=true, db-badge-sqlite must be shown (display = '')
        assert "db-badge-sqlite" in snippet, \
            "_dbUpdateActiveBadges must reference db-badge-sqlite"
        assert "db-badge-pg" in snippet, \
            "_dbUpdateActiveBadges must reference db-badge-pg"

    def test_badges_are_mutually_exclusive(self):
        idx = _SRC.find("function _dbUpdateActiveBadges")
        assert idx != -1
        snippet = _SRC[idx:idx+300]
        # One 'none', one '' → mutually exclusive
        assert "'none'" in snippet or '"none"' in snippet, \
            "_dbUpdateActiveBadges must hide the inactive badge with display:none"


class TestDbMigRenderRow:
    """_renderMigStatusRow renders progress bar and handles edge cases."""

    def test_render_mig_row_clears_on_no_mig(self):
        idx = _SRC.find("function _renderMigStatusRow")
        assert idx != -1
        snippet = _SRC[idx:idx+400]
        assert "innerHTML = ''" in snippet or "innerHTML=''" in snippet, \
            "_renderMigStatusRow must clear the element when mig is null/not active"

    def test_render_mig_row_shows_progress_bar(self):
        idx = _SRC.find("function _renderMigStatusRow")
        assert idx != -1
        snippet = _SRC[idx:idx+1400]
        assert "width:" in snippet and "%" in snippet, \
            "_renderMigStatusRow must render a CSS width-based progress bar"

    def test_render_mig_row_shows_pct(self):
        idx = _SRC.find("function _renderMigStatusRow")
        assert idx != -1
        snippet = _SRC[idx:idx+600]
        assert "pct" in snippet, \
            "_renderMigStatusRow must display percentage"

    def test_render_mig_row_colour_codes_states(self):
        idx = _SRC.find("function _renderMigStatusRow")
        assert idx != -1
        snippet = _SRC[idx:idx+500]
        # running=blue, done=green, error=red
        assert "var(--red)" in snippet and "var(--green)" in snippet and "var(--blue)" in snippet, \
            "_renderMigStatusRow must colour-code error/running/done states"


class TestDbPollHelpers:
    """_pollMigOnce and _startMigPoll wiring."""

    def test_poll_mig_fetches_migration_status_endpoint(self):
        idx = _SRC.find("async function _pollMigOnce")
        assert idx != -1
        snippet = _SRC[idx:idx+300]
        assert "db-migration-status" in snippet, \
            "_pollMigOnce must fetch /secured/db-migration-status"

    def test_start_mig_poll_uses_interval(self):
        idx = _SRC.find("function _startMigPoll")
        assert idx != -1
        snippet = _SRC[idx:idx+400]
        assert "setInterval" in snippet, \
            "_startMigPoll must use setInterval for periodic polling"

    def test_start_mig_poll_stops_when_not_running(self):
        idx = _SRC.find("function _startMigPoll")
        assert idx != -1
        snippet = _SRC[idx:idx+400]
        assert "clearInterval" in snippet, \
            "_startMigPoll must clearInterval when migration is no longer running"

    def test_start_mig_poll_deduplicates(self):
        idx = _SRC.find("function _startMigPoll")
        assert idx != -1
        snippet = _SRC[idx:idx+200]
        assert "_migPollTimer" in snippet, \
            "_startMigPoll must guard against double-start via _migPollTimer"


class TestDbSettingsNoBrowserConfirm:
    """No browser confirm() anywhere in the DB Backend JS block."""

    def test_db_section_uses_modal_not_confirm(self):
        # Find the DB section start
        db_start = _SRC.find("// ── DB Backend")
        # Find next major section
        db_end   = _SRC.find("// ── Integration credentials")
        assert db_start != -1 and db_end != -1
        section = _SRC[db_start:db_end]
        assert "confirm(" not in section, \
            "DB Backend JS section must not use browser confirm() — rich modal only"


class TestDbModalDsnHintLogic:
    """
    Regression tests for the 'no DSN configured' false-positive bug (v1.8.8 fix).

    Root cause: the IIFE else-branch hint ternary used `masked && !_dsnUserTouched`
    to show "no DSN configured", which fires when a DSN IS stored — the condition
    was inverted.  Fix: gate the message on `!masked` instead.

    Companion fix: autocomplete="off" on #db-switch-dsn prevents browser autofill
    from pre-populating the field, which would cause the if-condition to fail and
    fall into the wrong else branch.
    """

    # ── locate the IIFE inside _openDbModal ──────────────────────────────────

    @staticmethod
    def _iife_snippet(size=600):
        idx = _SRC.find("// Auto-check stored DSN on modal open")
        assert idx != -1, "IIFE comment anchor not found in settings.html"
        return _SRC[idx:idx + size]

    @staticmethod
    def _else_branch_snippet(size=400):
        idx = _SRC.find("} else {\n            if (hintEl) hintEl.innerHTML = _dsnUserTouched")
        assert idx != -1, "else-branch hint block not found in settings.html"
        return _SRC[idx:idx + size]

    # ── autocomplete guard ────────────────────────────────────────────────────

    def test_dsn_input_has_autocomplete_off(self):
        idx = _SRC.find('id="db-switch-dsn"')
        assert idx != -1
        snippet = _SRC[idx:idx + 300]
        assert 'autocomplete="off"' in snippet, \
            '#db-switch-dsn must have autocomplete="off" to prevent browser ' \
            'autofill pre-filling the field before the IIFE runs'

    # ── hint: "no DSN configured" only when masked is falsy ──────────────────

    def test_no_dsn_hint_gated_on_not_masked(self):
        snippet = self._else_branch_snippet()
        assert "? 'no DSN configured — enter one below'" in snippet, \
            "else-branch must contain the 'no DSN configured' hint string"
        # The guard must be `!masked`, never `masked` (which is the inverted bug)
        assert ": !masked\n" in snippet or ": !masked\r\n" in snippet, \
            "hint must use '!masked' (no DSN) — not 'masked' — to trigger " \
            "'no DSN configured'; using 'masked' fires when DSN IS present"

    def test_no_dsn_hint_not_gated_on_masked_truthy(self):
        snippet = self._else_branch_snippet()
        # The inverted condition `masked && !_dsnUserTouched` must not appear
        assert "masked && !_dsnUserTouched" not in snippet, \
            "Inverted bug condition 'masked && !_dsnUserTouched → no DSN configured' " \
            "must not be present; it fires when DSN IS configured"

    # ── hint ordering: _dsnUserTouched checked first ──────────────────────────

    def test_user_touched_hint_checked_before_masked(self):
        snippet = self._else_branch_snippet()
        touched_pos = snippet.find("_dsnUserTouched")
        masked_pos  = snippet.find("!masked")
        assert touched_pos != -1 and masked_pos != -1
        assert touched_pos < masked_pos, \
            "_dsnUserTouched branch must be evaluated before !masked branch so " \
            "user-typed values always show 'custom DSN' regardless of stored state"

    # ── hint: "current value shown masked" is the fallback when DSN exists ────

    def test_masked_set_and_not_touched_shows_current_value_hint(self):
        snippet = self._else_branch_snippet(size=600)
        assert "current value shown masked" in snippet, \
            "else-branch must fall back to 'current value shown masked' hint when " \
            "masked is set and user has not touched the field"

    # ── IIFE if-condition: both masked and !dsnField.value must hold ──────────

    def test_iife_if_guards_field_value_before_populate(self):
        snippet = self._iife_snippet(size=1200)
        assert "!dsnField.value" in snippet, \
            "IIFE if-condition must check !dsnField.value to avoid overwriting " \
            "a pre-existing field value (e.g. from a stale modal re-open)"

    def test_iife_if_guards_user_touched_flag(self):
        snippet = self._iife_snippet(size=1200)
        assert "!_dsnUserTouched" in snippet, \
            "IIFE if-condition must check !_dsnUserTouched so async auto-fill " \
            "never overwrites a value the operator has already started typing"
