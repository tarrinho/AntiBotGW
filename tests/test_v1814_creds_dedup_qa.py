# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1814_creds_dedup_qa.py

QA for the credentials-dedup + env-pinned UX (1.8.14 iteration 9):

  • POSTGRES_DSN is owned by the Database-backend card alone (no longer in the
    Integration credentials list).
  • Integration credentials list holds exactly the 6 expected keys.
  • Env-pinned credentials render disabled, hide their Clear button, carry an
    inline "managed via env" hint + title= tooltip; the Save handler filters
    disabled inputs and explains the env-pinned read-only case to operators.
  • No other dashboard reintroduces an editable POSTGRES_DSN surface (anti-
    regression — if someone wires one up later this test catches it).
  • The env-only secret family (WEBHOOK_URL / WEBHOOK_SECRET / JWT_HMAC_SECRET)
    stays out of CREDS.
"""
from __future__ import annotations
import pathlib
import re

_ROOT = pathlib.Path(__file__).parent.parent
_SETTINGS = (_ROOT / "dashboards" / "settings.html").read_text(encoding="utf-8")
_CONTROLS = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")


# Helpers ─────────────────────────────────────────────────────────────────────
def _creds_block() -> str:
    """The contents between `const CREDS = [` and the closing `];`."""
    idx = _SETTINGS.find("const CREDS = [")
    assert idx != -1, "CREDS array not found in settings.html"
    end = _SETTINGS.find("];", idx)
    return _SETTINGS[idx:end]


def _loadcreds_block() -> str:
    """The body of `async function loadCreds()` — up to (but not including)
    `window._clearCred`, which is the next top-level definition."""
    i = _SETTINGS.find("async function loadCreds()")
    assert i != -1, "loadCreds() not found"
    e = _SETTINGS.find("window._clearCred", i)
    assert e != -1, "window._clearCred not found after loadCreds()"
    return _SETTINGS[i:e]


def _save_handler_block() -> str:
    """The body of the `$('btn-creds-save').addEventListener(...)` block."""
    i = _SETTINGS.find("$('btn-creds-save')")
    assert i != -1, "btn-creds-save addEventListener not found"
    e = _SETTINGS.find("\n  });\n", i)
    assert e != -1, "closing of btn-creds-save handler not found"
    return _SETTINGS[i:e]


# ── A. Database-backend card OWNS POSTGRES_DSN (anti-regression) ─────────────
def test_db_backend_card_has_structured_postgres_form():
    """The DB backend card is the SOLE owner of POSTGRES_DSN — must keep its
    host/port/user/pass structured form so dropping it from CREDS didn't
    strand operators without any way to set the DSN."""
    for el in ("_tip-pg-host", "_tip-pg-user", "_tip-pg-pass",
               "_tip-pg-save", "_tip-pg-test"):
        assert el in _SETTINGS, f"Database backend card missing required element: {el!r}"


def test_db_backend_save_handler_posts_postgres_dsn_to_secrets():
    """The DB backend `_tip-pg-save` handler must still POST `{POSTGRES_DSN: …}`
    to `/secured/secrets`. If this disappears, operators have no way to save."""
    idx = _SETTINGS.find("'_tip-pg-save'")
    assert idx != -1
    chunk = _SETTINGS[idx: idx + 1800]
    assert "POSTGRES_DSN" in chunk, "DB backend save handler must reference POSTGRES_DSN"
    assert "/secured/secrets" in chunk, "DB backend save handler must POST to /secured/secrets"
    assert "POST" in chunk, "DB backend save handler must use POST"


# ── B. Integration credentials card EXCLUDES POSTGRES_DSN ────────────────────
def test_postgres_dsn_not_in_integration_creds_array():
    """The exact regression: POSTGRES_DSN must not appear in CREDS."""
    assert "POSTGRES_DSN" not in _creds_block(), (
        "POSTGRES_DSN reintroduced into the Integration credentials list — "
        "it is owned by the Database backend card to avoid two save surfaces"
    )


def test_integration_creds_array_is_the_expected_six_keys():
    """Pin the contract: exactly these 6 keys, in this order, no more no less."""
    keys = re.findall(r"key:'([A-Z0-9_]+)'", _creds_block())
    assert keys == [
        "TURNSTILE_SITEKEY", "TURNSTILE_SECRET", "ABUSEIPDB_KEY",
        "CROWDSEC_LAPI_URL", "CROWDSEC_LAPI_KEY", "MAXMIND_LICENSE_KEY",
    ], f"CREDS array drifted from the expected 6-key contract: {keys}"


def test_creds_card_explains_postgres_dsn_lives_elsewhere():
    """A code-comment near the CREDS array should make the ownership boundary
    obvious to the next person editing this file — otherwise someone will
    eventually re-add POSTGRES_DSN here."""
    idx = _SETTINGS.find("const CREDS = [")
    pre = _SETTINGS[max(0, idx - 600): idx]
    assert "POSTGRES_DSN" in pre and ("Database" in pre or "backend" in pre.lower()), (
        "Add a code comment above `const CREDS = [` saying that POSTGRES_DSN "
        "is managed in the Database-backend card, so future edits don't re-add it"
    )


# ── C. Env-pinned UX in the cred render ──────────────────────────────────────
def test_loadcreds_detects_env_source():
    blk = _loadcreds_block()
    assert "isEnv" in blk, "loadCreds must compute an isEnv flag for env-sourced values"
    assert "source==='env'" in blk or "source === 'env'" in blk, (
        "loadCreds must check the credential's source against the literal 'env'"
    )


def test_env_pinned_input_is_disabled():
    blk = _loadcreds_block()
    assert "disabled" in blk, "env-pinned input must render with the `disabled` attribute"
    assert "aria-disabled" in blk, (
        "env-pinned input should also set aria-disabled for screen-reader users"
    )


def test_env_pinned_input_shows_inline_hint():
    blk = _loadcreds_block()
    assert "env var" in blk and ("immutable" in blk or "Set via env" in blk), (
        "env-pinned row must include an inline hint explaining the read-only "
        "state — otherwise the disabled input looks like a UI bug"
    )


def test_env_pinned_input_carries_title_tooltip():
    blk = _loadcreds_block()
    assert "title=" in blk and "Set via env" in blk, (
        "env-pinned input should carry a title= tooltip so a hover surfaces the reason"
    )


def test_env_pinned_input_hides_clear_button():
    blk = _loadcreds_block()
    # Clear button is conditional on `isSet && !isEnv` — there's nothing in
    # secrets_kv to clear when the value is sourced from env.
    assert "isSet && !isEnv" in blk or "isSet&&!isEnv" in blk, (
        "Clear button must be hidden when source==='env' (no secrets_kv row to remove)"
    )


def test_save_handler_skips_disabled_inputs():
    blk = _save_handler_block()
    assert "!f.disabled" in blk, (
        "btn-creds-save must filter out disabled (env-pinned) inputs from the payload"
    )


def test_save_handler_no_values_message_explains_env_pinned():
    """When every field is env-pinned (or blank), the 'No values entered'
    toast must explain WHY — otherwise an operator who only sees env-pinned
    rows gets a confusing error."""
    blk = _save_handler_block()
    msg_line = next((l for l in blk.splitlines() if "No values entered" in l), "")
    assert msg_line, "'No values entered' toast not found in btn-creds-save handler"
    assert "env-pinned" in msg_line.lower() or "read-only" in msg_line.lower(), (
        "'No values entered' toast must mention env-pinned/read-only fields"
    )


# ── D. Cross-dashboard guard — no duplicate POSTGRES_DSN edit surface ────────
def test_controls_html_does_not_render_postgres_dsn_input():
    """controls.html may *reference* POSTGRES_DSN in copy/tooltips, but must not
    render an `<input>` bound to it. A bound input would resurrect the original
    duplicate-save-surface problem."""
    if "POSTGRES_DSN" not in _CONTROLS:
        return  # not referenced at all — perfectly fine
    bad_patterns = [
        r'data-cred=["\']POSTGRES_DSN["\']',
        r'data-name=["\']POSTGRES_DSN["\']',
        r'name=["\']POSTGRES_DSN["\']',
        r'<input[^>]*POSTGRES_DSN',
    ]
    for pat in bad_patterns:
        assert not re.search(pat, _CONTROLS), (
            f"controls.html must not render an editable surface for POSTGRES_DSN "
            f"(matched pattern: {pat!r}); it is owned by the Database backend card"
        )


# ── E. Env-only secret family stays out of CREDS ─────────────────────────────
def test_creds_does_not_resurrect_env_only_secrets():
    """WEBHOOK_URL / WEBHOOK_SECRET / JWT_HMAC_SECRET are not in `_SECRET_KEYS`
    on the server — they're env-var-only — so surfacing them in the cred form
    would let an operator "save" a value that has no effect."""
    chunk = _creds_block()
    for k in ("WEBHOOK_URL", "WEBHOOK_SECRET", "JWT_HMAC_SECRET"):
        assert k not in chunk, (
            f"{k} is env-only (not in _SECRET_KEYS) — must not appear in CREDS"
        )
