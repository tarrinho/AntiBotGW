"""
tests/test_v185_settings_migration.py — QA tests for the Controls→Settings migration.

Covers:
  TestSettingsDbCard         — card-db uses /secured/db-switch, not /secured/config
  TestSettingsCredentialsCard — loadCreds() bulk-GETs /secured/secrets, parses d.secrets
  TestSettingsInfraCard      — card-infrastructure present in settings, absent in controls
  TestSettingsLoggingCard    — card-logging: LOG_LEVEL/LOG_FORMAT/WEBHOOK_EVENT_FILTER
  TestControlsCleanup        — controls.html no longer renders infra/db/log/cred knobs

All tests are source-level static assertions (read HTML/JS, grep for patterns).
No test server or Docker required.
"""
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SETTINGS = (_ROOT / "dashboards" / "settings.html").read_text(encoding="utf-8")
_CONTROLS = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")
_NS = "/antibot-appsec-gateway"


# ─────────────────────────────────────────────────────────────────────────────
# TestSettingsDbCard — card-db JS correctness after fix
# ─────────────────────────────────────────────────────────────────────────────

class TestSettingsDbCard:
    """card-db in settings.html must use the dedicated db-switch endpoint."""

    def test_db_card_present(self):
        """card-db section must exist in settings.html."""
        assert 'id="card-db"' in _SETTINGS, "card-db not found in settings.html"

    def test_db_apply_uses_db_switch_endpoint(self):
        """btn-db-apply must POST to /secured/db-switch, not /secured/config."""
        assert f"{_NS}/secured/db-switch" in _SETTINGS, (
            "btn-db-apply must fetch /secured/db-switch — "
            "config endpoint does not persist backend or trigger container restart"
        )

    def test_db_apply_does_not_post_db_backend_to_config(self):
        """DB_BACKEND must never be sent to /secured/config (env-pinned, would be rejected).

        iter-18: anchor on the JS CLICK HANDLER (`addEventListener('click'`)
        not the first text-match of `btn-db-apply` — the first match in
        iter-15+ source is the HTML button markup followed by a long
        operator-facing comment block that legitimately mentions DB_BACKEND
        but is unrelated to the POST body of the click handler.
        """
        # Find the click-handler registration line for btn-db-apply.
        idx = _SETTINGS.find("$('btn-db-apply').addEventListener('click'")
        assert idx != -1, \
            "could not locate btn-db-apply click handler — selector changed?"
        # Scan the handler body forward (~1200 chars covers full handler).
        chunk = _SETTINGS[idx: idx + 1200]
        assert "DB_BACKEND" not in chunk or "db-switch" in chunk, (
            "btn-db-apply CLICK HANDLER must not send {DB_BACKEND:val} to "
            "/secured/config — use /secured/db-switch?target= instead. "
            "Handler chunk: " + chunk[:200]
        )

    def test_db_apply_passes_target_as_query_param(self):
        """db-switch URL must carry target= as a query parameter."""
        assert "db-switch?target=" in _SETTINGS, (
            "db-switch URL must use ?target= query parameter "
            "(endpoint reads request.query.get('target'))"
        )

    def test_db_apply_checks_d_ok_not_d_applied(self):
        """Success check must test j.ok (not j.applied) — db-switch returns {ok, target, message}."""
        # The fetch is now inside _openDbModal; anchor on db-switch-ok handler.
        idx = _SETTINGS.find("db-switch?target=")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 600]
        # Accept either variable name (j.ok or d.ok) but not j.applied / d.applied
        assert ".ok" in chunk, (
            "db-switch handler must check .ok on the response — "
            "db_switch_endpoint returns {ok, target, message}, not {applied}"
        )
        assert "d.applied" not in chunk and "j.applied" not in chunk, (
            "db-switch handler must not check .applied — "
            "db-switch response has no 'applied' key"
        )

    def test_db_apply_postgres_includes_dsn_in_body(self):
        """When switching to postgres, DSN must go in the fetch body."""
        # In the rich modal (_openDbModal), dsn is passed via JSON.stringify({dsn, ...}).
        # 1.8.8 — function grew with hot-apply impact lines; use 10000-char window.
        idx = _SETTINGS.find("function _openDbModal")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 10000]
        assert "dsn" in chunk and "JSON.stringify" in chunk, (
            "_openDbModal must include dsn in body when switching to postgres "
            "so db_switch_endpoint can probe connectivity before committing"
        )

    def test_db_apply_sqlite_no_dsn_required(self):
        """DSN override input is only shown for the postgres target (not sqlite)."""
        # The modal uses needsTest = target === 'postgres' to gate the DSN input.
        idx = _SETTINGS.find("function _openDbModal")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 4000]
        assert "needsTest" in chunk and "=== 'postgres'" in chunk, (
            "_openDbModal must gate DSN input on needsTest (target === 'postgres') only"
        )

    def test_load_db_reads_from_config_endpoint(self):
        """loadDb() must GET /secured/config to determine current backend."""
        idx = _SETTINGS.find("async function loadDb")
        assert idx != -1, "loadDb function not found in settings.html"
        chunk = _SETTINGS[idx: idx + 300]
        assert "/secured/config" in chunk, (
            "loadDb() must read current DB_BACKEND from GET /secured/config"
        )

    def test_load_db_reads_state_db_backend(self):
        """loadDb() must read (d.state||d).DB_BACKEND from the config response."""
        idx = _SETTINGS.find("async function loadDb")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 600]  # function is ~480 chars with parallel fetch URL
        assert "DB_BACKEND" in chunk, (
            "loadDb() must read DB_BACKEND from the config state"
        )

    def test_db_toggle_html_present(self):
        """card-db must have toggle track/thumb and label elements on both sides."""
        for eid in ("db-track", "db-thumb", "db-lbl-sqlite", "db-lbl-pg"):
            assert f'id="{eid}"' in _SETTINGS, f"Toggle element #{eid} missing from card-db"
        assert "dbToggle" in _SETTINGS, "dbToggle function not present"

    def test_db_hover_tooltip_present(self):
        """card-db uses click popover (_dbSideClick) — click either side panel to open stats."""
        assert "_dbSideClick" in _SETTINGS, "_dbSideClick click-popover function not defined"
        assert "db-hover-tip" in _SETTINGS, "#db-hover-tip popover element not defined"
        assert "_dbHideTip" in _SETTINGS, "_dbHideTip close function not defined"
        assert "_DB_INFO" in _SETTINGS, "_DB_INFO content map not defined"

    def test_db_info_contains_sqlite_details(self):
        """_DB_INFO.sqlite must mention key SQLite facts."""
        idx = _SETTINGS.find("_DB_INFO")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 2000]
        for term in ("WAL", "zero-dependency", "TimescaleDB", "antibot.db"):
            assert term in chunk, f"_DB_INFO.sqlite missing detail: {term}"

    def test_db_info_contains_postgres_details(self):
        """_DB_INFO.postgres must mention key PostgreSQL/TimescaleDB facts."""
        idx = _SETTINGS.find("_DB_INFO")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 3000]  # postgres entry follows sqlite — needs wider window
        for term in ("hypertable", "psycopg", "POSTGRES_DSN", "retention"):
            assert term in chunk, f"_DB_INFO.postgres missing detail: {term}"

    def test_db_pg_fields_section_present(self):
        """card-db modal must have DSN text input and test/confirm buttons for postgres target."""
        assert 'id="db-switch-dsn"' in _SETTINGS, "db-switch-dsn DSN input not found in DB modal"
        assert 'id="db-test-btn"' in _SETTINGS, "db-test-btn connection test button not found in DB modal"
        assert 'id="db-switch-ok"' in _SETTINGS, "db-switch-ok confirm button not found in DB modal"

    def test_pg_save_posts_postgres_dsn_to_secrets(self):
        """DB modal must send DSN via /secured/db-switch when confirming postgres target."""
        # db-switch-ok handler posts to /secured/db-switch with dsn from db-switch-dsn input
        idx = _SETTINGS.find("db-switch-ok")
        assert idx != -1, "db-switch-ok confirm button not found in settings.html"
        # Find the ok handler which calls /secured/db-switch
        idx2 = _SETTINGS.find("/secured/db-switch")
        assert idx2 != -1, "/secured/db-switch endpoint not called in settings.html"
        chunk = _SETTINGS[idx2: idx2 + 200]
        assert "dsn" in chunk.lower() or "POSTGRES_DSN" in chunk, (
            "db-switch call must include DSN from the modal input"
        )

    def test_pg_test_calls_integration_check(self):
        """db-test-btn must call /secured/db-test to probe the postgres DSN.

        1.8.8 — the first /secured/db-test in the file is the live-probe IIFE
        added on popup-open (no ?dsn= probe). The Test BUTTON handler is the
        one that probes a candidate DSN via ?dsn=... — locate it via the
        _tip-pg-test onclick marker instead of grabbing the first occurrence.
        """
        marker = "document.getElementById('_tip-pg-test').onclick"
        idx = _SETTINGS.find(marker)
        assert idx != -1, "_tip-pg-test onclick handler not found in settings.html"
        chunk = _SETTINGS[idx: idx + 3500]
        assert "/secured/db-test?dsn=" in chunk, (
            "_tip-pg-test handler must call /secured/db-test?dsn=<encoded> "
            "to probe a candidate DSN before saving"
        )
        # Handler must read postgres / probe / DSN-related fields from response
        assert "p.ok" in chunk or "j.probe" in chunk or "postgres" in chunk.lower(), (
            "db-test probe handler must read the probe response sub-object"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TestSettingsCredentialsCard — loadCreds() API contract
# ─────────────────────────────────────────────────────────────────────────────

class TestSettingsCredentialsCard:
    """card-credentials in settings.html must use the correct secrets endpoint API."""

    def test_credentials_card_present(self):
        """card-credentials section must exist in settings.html."""
        assert 'id="card-credentials"' in _SETTINGS, (
            "card-credentials not found in settings.html"
        )

    def test_load_creds_single_bulk_get(self):
        """loadCreds() must do a single GET /secured/secrets, not one per key."""
        idx = _SETTINGS.find("async function loadCreds")
        assert idx != -1, "loadCreds function not found in settings.html"
        chunk = _SETTINGS[idx: idx + 400]
        # Should fetch secrets once.
        assert "/secured/secrets" in chunk, (
            "loadCreds() must GET /secured/secrets"
        )
        # The old broken pattern sent ?name=KEY per credential.
        assert "?name=" not in chunk, (
            "loadCreds() must not use ?name= query param on GET — "
            "the secrets endpoint ignores it; fetch all at once and parse d.secrets"
        )

    def test_load_creds_parses_d_secrets(self):
        """loadCreds() must parse d.secrets, not d.is_set or d.set."""
        idx = _SETTINGS.find("async function loadCreds")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 600]
        assert "d.secrets" in chunk or "d.secrets||" in chunk, (
            "loadCreds() must read d.secrets from the bulk GET response"
        )

    def test_load_creds_checks_configured_field(self):
        """loadCreds() must check s.configured, not s.is_set."""
        idx = _SETTINGS.find("async function loadCreds")
        assert idx != -1
        # Extend window to cover renderHTML inline in loadCreds.
        chunk = _SETTINGS[idx: idx + 1500]
        assert "configured" in chunk, (
            "loadCreds() must check the 'configured' field from the secrets response"
        )
        assert "is_set" not in chunk, (
            "loadCreds() must not check 'is_set' — the endpoint uses 'configured'"
        )

    def test_creds_list_has_six_keys(self):
        """CREDS array defines the 6 integration-credential keys.

        1.8.13: POSTGRES_DSN was dropped from CREDS — it is managed in the
        dedicated Database-backend card (with structured host/port/user/pass
        form, mig-status, test-roundtrip). Surfacing it in both would mean two
        Save buttons for the same secret.
        """
        idx = _SETTINGS.find("const CREDS = [")
        assert idx != -1, "CREDS array not found in settings.html"
        end = _SETTINGS.find("];", idx)
        chunk = _SETTINGS[idx:end]
        keys = re.findall(r"key:'([A-Z0-9_]+)'", chunk)
        assert len(keys) == 6, (
            f"CREDS array must have 6 keys (POSTGRES_DSN moved to Database "
            f"backend card); found {len(keys)}: {keys}"
        )

    def test_creds_includes_expected_keys(self):
        """CREDS must contain all integration secrets that aren't owned by another card."""
        idx = _SETTINGS.find("const CREDS = [")
        assert idx != -1
        end = _SETTINGS.find("];", idx)
        chunk = _SETTINGS[idx:end]
        expected = [
            "TURNSTILE_SITEKEY", "TURNSTILE_SECRET", "ABUSEIPDB_KEY",
            "CROWDSEC_LAPI_URL", "CROWDSEC_LAPI_KEY", "MAXMIND_LICENSE_KEY",
        ]
        for key in expected:
            assert key in chunk, f"CREDS array missing expected key: {key}"

    def test_creds_excludes_postgres_dsn(self):
        """POSTGRES_DSN must NOT live in CREDS — it is managed in the
        Database-backend card (structured form, test-roundtrip, mig-status)."""
        idx = _SETTINGS.find("const CREDS = [")
        end = _SETTINGS.find("];", idx)
        chunk = _SETTINGS[idx:end]
        assert "POSTGRES_DSN" not in chunk, (
            "POSTGRES_DSN must not appear in the Integration credentials list — "
            "it is owned by the Database backend card to avoid two save surfaces"
        )

    def test_env_pinned_credential_inputs_are_disabled(self):
        """When a credential's source is 'env', its input must be disabled and
        the Save handler must skip it (the env var wins, secrets_kv write is a
        misleading no-op)."""
        # Read the loadCreds render block.
        idx = _SETTINGS.find("async function loadCreds()")
        assert idx != -1, "loadCreds() not found"
        end = _SETTINGS.find("\n  }\n", idx)
        chunk = _SETTINGS[idx:end]
        assert "isEnv" in chunk or "source==='env'" in chunk, \
            "loadCreds must detect source==='env'"
        assert "disabled" in chunk, \
            "env-pinned input must render with `disabled`"
        # Save handler must skip disabled inputs.
        sidx = _SETTINGS.find("$('btn-creds-save')")
        send = _SETTINGS.find("\n  });\n", sidx)
        schunk = _SETTINGS[sidx:send]
        assert "f.disabled" in schunk or "!f.disabled" in schunk, \
            "btn-creds-save must skip disabled inputs (env-pinned values)"

    def test_creds_excludes_env_only_secrets(self):
        """WEBHOOK_URL/WEBHOOK_SECRET/JWT_HMAC_SECRET are env-only, not in _SECRET_KEYS."""
        idx = _SETTINGS.find("const CREDS = [")
        assert idx != -1
        end = _SETTINGS.find("];", idx)
        chunk = _SETTINGS[idx:end]
        for key in ("WEBHOOK_URL", "WEBHOOK_SECRET", "JWT_HMAC_SECRET"):
            assert key not in chunk, (
                f"CREDS must not include {key} — it is not in _SECRET_KEYS "
                "and cannot be managed via the secrets endpoint"
            )

    def test_clear_cred_uses_delete_with_name_param(self):
        """_clearCred must DELETE /secured/secrets?name=KEY."""
        assert "_clearCred" in _SETTINGS, "_clearCred function not found"
        idx = _SETTINGS.find("window._clearCred")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 400]
        assert "DELETE" in chunk, "_clearCred must use DELETE method"
        assert "?name=" in chunk or "secrets?name=" in chunk, (
            "_clearCred must pass the key as ?name= query parameter"
        )

    def test_save_creds_posts_to_secrets_endpoint(self):
        """btn-creds-save must POST the filled values to /secured/secrets."""
        # Find the addEventListener block, not the HTML button element.
        idx = _SETTINGS.find("$('btn-creds-save')")
        assert idx != -1, "btn-creds-save addEventListener not found in settings.html"
        # Window widened from 500 → 900 because the handler grew (env-pinned
        # skip + explanatory comment); the POST line now sits past the old window.
        chunk = _SETTINGS[idx: idx + 900]
        assert "POST" in chunk and "/secured/secrets" in chunk, (
            "btn-creds-save must POST to /secured/secrets"
        )

    def test_save_creds_only_sends_non_empty_fields(self):
        """Save must skip fields the user left blank (placeholder-only)."""
        idx = _SETTINGS.find("$('btn-creds-save')")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 500]
        # The payload must be filtered — either .trim() check or data-cred iteration.
        assert "trim()" in chunk or "value.trim" in chunk, (
            "btn-creds-save must only include fields the user has typed into "
            "(skip empty inputs to avoid overwriting existing credentials with blanks)"
        )

    def test_source_badge_distinguishes_env_from_db(self):
        """Source badge in rendered credentials must distinguish env-pinned from db-saved."""
        assert "'env'" in _SETTINGS or "==='env'" in _SETTINGS or "source==='env'" in _SETTINGS, (
            "loadCreds() must show different badge for env-pinned vs db-saved credentials "
            "(check s.source === 'env')"
        )

    def test_creds_card_has_save_button(self):
        """card-credentials must have a visible Save button."""
        assert 'id="btn-creds-save"' in _SETTINGS, (
            "btn-creds-save button not found in card-credentials"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TestSettingsInfraCard — card-infrastructure
# ─────────────────────────────────────────────────────────────────────────────

class TestSettingsInfraCard:
    """card-infrastructure must live in settings.html, not controls.html."""

    def test_infra_card_present_in_settings(self):
        """card-infrastructure section must exist in settings.html."""
        assert 'id="card-infrastructure"' in _SETTINGS, (
            "card-infrastructure not found in settings.html"
        )

    def test_infra_card_absent_from_controls(self):
        """card-infrastructure section must NOT be a rendered <div class='card'> in controls.html."""
        # The META still defines the knobs with card:'infrastructure',
        # but the rendered <section> or <div id="card-infrastructure"> must be gone.
        assert '<section class="card" id="card-infrastructure">' not in _CONTROLS, (
            "card-infrastructure section still present as a rendered card in controls.html — "
            "it was moved to settings.html"
        )
        assert '<div class="card" id="card-infrastructure">' not in _CONTROLS, (
            "card-infrastructure div still present as a rendered card in controls.html"
        )

    def test_infra_knobs_defined_in_settings(self):
        """INFRA_KNOBS must define the core infrastructure keys."""
        idx = _SETTINGS.find("INFRA_KNOBS")
        assert idx != -1, "INFRA_KNOBS not defined in settings.html"
        chunk = _SETTINGS[idx: idx + 1200]
        for key in ("ALLOW_PRIVATE_UPSTREAM", "STRICT_VHOST", "PRESERVE_HOST", "UPSTREAM_REWRITE_BASE"):
            assert key in chunk, f"INFRA_KNOBS missing key: {key}"

    def test_infra_load_reads_config_endpoint(self):
        """loadInfra() must GET /secured/config."""
        idx = _SETTINGS.find("async function loadInfra")
        assert idx != -1, "loadInfra function not found in settings.html"
        chunk = _SETTINGS[idx: idx + 300]
        assert "/secured/config" in chunk, (
            "loadInfra() must read knob values from GET /secured/config"
        )

    def test_infra_apply_posts_to_config(self):
        """btn-infra-apply must POST dirty knobs to /secured/config."""
        # Search for the addEventListener call specifically (not the earlier disabled= references).
        idx = _SETTINGS.find("$('btn-infra-apply').addEventListener")
        assert idx != -1, "btn-infra-apply addEventListener not found in settings.html"
        chunk = _SETTINGS[idx: idx + 600]
        assert "POST" in chunk and "/secured/config" in chunk, (
            "btn-infra-apply must POST to /secured/config with the dirty knob values"
        )

    def test_infra_restart_badge_on_bool_knobs(self):
        """1.8.x — ALLOW_PRIVATE_UPSTREAM and STRICT_VHOST are now hot-reloadable
        (restart:false), by operator request, so they no longer require a restart.
        The infra render still SUPPORTS a restart badge for any future
        restart:true knob (the `k.restart` disabled-input path)."""
        assert "key:'ALLOW_PRIVATE_UPSTREAM', kind:'bool', restart:false" in _SETTINGS, (
            "ALLOW_PRIVATE_UPSTREAM is hot-reloadable now (restart:false)"
        )
        assert "key:'STRICT_VHOST', kind:'bool', restart:false" in _SETTINGS, (
            "STRICT_VHOST is hot-reloadable now (restart:false)"
        )
        # restart-badge render path is still present for any restart:true knob
        assert "const restart = k.restart" in _SETTINGS, (
            "infra render must still support a restart badge for restart:true knobs"
        )

    def test_infra_rewrite_base_is_hot_reloadable(self):
        """UPSTREAM_REWRITE_BASE must be marked restart:false (hot-reloadable)."""
        idx = _SETTINGS.find("UPSTREAM_REWRITE_BASE")
        assert idx != -1
        # Look just after the key to find its restart flag.
        chunk = _SETTINGS[idx: idx + 200]
        assert "restart:false" in chunk, (
            "UPSTREAM_REWRITE_BASE is hot-reloadable — must be marked restart:false"
        )

    def test_infra_nav_section_absent_from_controls(self):
        """Infrastructure nav section must be removed from controls.html SECTIONS array."""
        # Find the SECTIONS array in controls.html.
        idx = _CONTROLS.find("const SECTIONS = [")
        assert idx != -1
        end = _CONTROLS.find("];", idx)
        chunk = _CONTROLS[idx:end]
        assert "infra" not in chunk, (
            "controls.html SECTIONS still contains an 'infra' entry — "
            "the Infrastructure section was moved to settings.html"
        )
        assert "Infrastructure" not in chunk, (
            "controls.html SECTIONS still contains 'Infrastructure' label"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TestSettingsLoggingCard — card-logging
# ─────────────────────────────────────────────────────────────────────────────

class TestSettingsLoggingCard:
    """card-logging in settings.html must manage LOG_LEVEL/LOG_FORMAT/WEBHOOK_EVENT_FILTER."""

    def test_logging_card_present(self):
        """card-logging section must exist in settings.html."""
        assert 'id="card-logging"' in _SETTINGS, (
            "card-logging not found in settings.html"
        )

    def test_log_knobs_defined(self):
        """LOG_KNOBS must include all three logging keys."""
        idx = _SETTINGS.find("LOG_KNOBS")
        assert idx != -1, "LOG_KNOBS not defined in settings.html"
        chunk = _SETTINGS[idx: idx + 400]
        for key in ("LOG_LEVEL", "LOG_FORMAT", "WEBHOOK_EVENT_FILTER"):
            assert key in chunk, f"LOG_KNOBS missing key: {key}"

    def test_load_logging_reads_config(self):
        """loadLogging() must GET /secured/config."""
        idx = _SETTINGS.find("async function loadLogging")
        assert idx != -1, "loadLogging function not found in settings.html"
        chunk = _SETTINGS[idx: idx + 300]
        assert "/secured/config" in chunk, (
            "loadLogging() must read current values from GET /secured/config"
        )

    def test_logging_apply_posts_to_config(self):
        """btn-logging-apply must POST changes to /secured/config."""
        idx = _SETTINGS.find("$('btn-logging-apply').addEventListener")
        assert idx != -1, "btn-logging-apply addEventListener not found in settings.html"
        chunk = _SETTINGS[idx: idx + 600]
        assert "POST" in chunk and "/secured/config" in chunk, (
            "btn-logging-apply must POST to /secured/config"
        )

    def test_webhook_filter_split_by_comma_before_post(self):
        """WEBHOOK_EVENT_FILTER value must be split by comma into a list before POST."""
        # Anchor on the addEventListener to get into the save handler.
        idx = _SETTINGS.find("$('btn-logging-apply').addEventListener")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 800]
        assert "split(','" in chunk or ".split(',')" in chunk, (
            "WEBHOOK_EVENT_FILTER (kind:'list') must be split by comma before "
            "POST — the server expects a list, not a raw CSV string"
        )

    def test_log_level_has_all_five_options(self):
        """LOG_LEVEL select must offer debug/info/warn/error/critical."""
        # Anchor on the LOG_KNOBS array definition, not the earlier status-bar select.
        idx = _SETTINGS.find("{key:'LOG_LEVEL'")
        assert idx != -1, "LOG_LEVEL entry in LOG_KNOBS not found"
        chunk = _SETTINGS[idx: idx + 300]
        for opt in ("debug", "info", "warn", "error", "critical"):
            assert opt in chunk, f"LOG_LEVEL options missing: {opt}"

    def test_log_format_has_text_and_json(self):
        """LOG_FORMAT select must offer text and json."""
        idx = _SETTINGS.find("LOG_FORMAT")
        assert idx != -1
        chunk = _SETTINGS[idx: idx + 200]
        assert "text" in chunk and "json" in chunk, (
            "LOG_FORMAT must have 'text' and 'json' options"
        )

    def test_logging_card_absent_from_controls_external(self):
        """external-log div must no longer be a rendered section in controls.html."""
        # The rendered container div must be gone.
        assert '<div id="external-log">' not in _CONTROLS, (
            "external-log rendered container still in controls.html — "
            "LOG_LEVEL/LOG_FORMAT moved to settings.html card-logging"
        )


# ─────────────────────────────────────────────────────────────────────────────
# TestControlsCleanup — controls.html no longer renders migrated knobs
# ─────────────────────────────────────────────────────────────────────────────

class TestControlsCleanup:
    """controls.html must skip knobs/cards that were migrated to settings.html."""

    def test_settings_cards_guard_defined(self):
        """_settingsCards Set must be defined to skip migrated card types in render loop."""
        assert "_settingsCards" in _CONTROLS, (
            "_settingsCards guard not found in controls.html — "
            "migrated cards (infrastructure/ext-misc/external-log) "
            "must be skipped in the rendering loop"
        )

    def test_settings_cards_guard_has_all_three_card_types(self):
        """_settingsCards must contain infrastructure, ext-misc, external-log."""
        idx = _CONTROLS.find("_settingsCards")
        assert idx != -1
        chunk = _CONTROLS[idx: idx + 200]
        for card_type in ("infrastructure", "ext-misc", "external-log"):
            assert card_type in chunk, (
                f"_settingsCards guard missing: '{card_type}'"
            )

    def test_db_backend_skipped_in_render_loop(self):
        """DB_BACKEND must be skipped in the controls.html rendering loop."""
        assert "DB_BACKEND" in _CONTROLS, "DB_BACKEND entry not found in controls META"
        # The skip guard for the rendering loop.
        assert ("DB_BACKEND" in _CONTROLS and
                ("DB_BACKEND' || name === 'POSTGRES_DSN') continue" in _CONTROLS
                 or "DB_BACKEND.*continue" in _CONTROLS
                 or "DB_BACKEND" in _CONTROLS and "continue" in _CONTROLS)), (
            "controls.html render loop must skip DB_BACKEND (moved to settings.html card-db)"
        )

    def test_postgres_dsn_skipped_in_render_loop(self):
        """POSTGRES_DSN must be skipped in the controls.html rendering loop."""
        assert "POSTGRES_DSN" in _CONTROLS, "POSTGRES_DSN reference not found in controls.html"
        # The guard line contains both DB_BACKEND and POSTGRES_DSN.
        assert ("POSTGRES_DSN" in _CONTROLS
                and "continue" in _CONTROLS), (
            "controls.html render loop must skip POSTGRES_DSN (moved to settings.html card-db)"
        )

    def test_knob_sec_returns_null_for_infra_cards(self):
        """_knobSec must return null for infrastructure/ext-misc/external-log cards."""
        idx = _CONTROLS.find("function _knobSec")
        assert idx != -1, "_knobSec function not found in controls.html"
        chunk = _CONTROLS[idx: idx + 600]
        assert "return null" in chunk, "_knobSec must have a null return path"
        assert "infrastructure" in chunk, (
            "_knobSec must explicitly handle card:'infrastructure' → null"
        )

    def test_settings_link_in_external_section(self):
        """controls.html external section must have a link to settings.html."""
        assert f"{_NS}/secured/settings" in _CONTROLS, (
            "controls.html must link to the Settings page (where migrated knobs now live)"
        )

    def test_settings_link_mentions_credentials(self):
        """The settings redirect hint must mention 'Credentials'."""
        assert "Credentials" in _CONTROLS, (
            "controls.html external section must mention 'Credentials' to direct operators "
            "to the correct settings card"
        )

    def test_ext_misc_container_absent(self):
        """ext-misc rendered container must be removed from controls.html."""
        assert '<div id="ext-misc">' not in _CONTROLS, (
            "ext-misc rendered container still present in controls.html — "
            "WEBHOOK_EVENT_FILTER moved to settings.html card-logging"
        )

    def test_infra_section_id_absent_from_card_sec(self):
        """CARD_SEC map must not contain 'card-infrastructure' → 'infra' mapping."""
        idx = _CONTROLS.find("const CARD_SEC")
        assert idx != -1, "CARD_SEC not found in controls.html"
        end = _CONTROLS.find("};", idx)
        chunk = _CONTROLS[idx:end]
        assert "'card-infrastructure'" not in chunk and '"card-infrastructure"' not in chunk, (
            "CARD_SEC still maps 'card-infrastructure' → 'infra' — "
            "this section no longer exists in controls.html"
        )
