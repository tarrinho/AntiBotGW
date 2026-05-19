"""
tests/test_v185_settings_nav.py — 1.8.6 nav restructure + OIDC settings tests.

Covers:
  - Service and Logs moved to sub-items under Settings in all 11 dashboard nav bars
  - OIDC keys registered in _SECRET_KEYS (db/sqlite.py)
  - _refresh_integration_state derives + propagates OIDC_ENABLED
  - /__secrets GET exposes OIDC_ENABLED in integration_state
  - settings.html SSO/OIDC card: presence, fields, JS behaviour
"""
import os
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DASH_DIR = _ROOT / "dashboards"
_NS = "/antibot-appsec-gateway"


def _dash(name: str) -> str:
    return (_DASH_DIR / name).read_text(encoding="utf-8")


def _src(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


# ── Nav: all dashboards that carry a sidebar nav ──────────────────────────────

_NAV_FILES = [
    "main.html",
    "agents.html",
    "siem.html",
    "center_control.html",
    "vhost_policy.html",
    "geo.html",
    "service.html",
    "logs.html",
    "controls.html",
    "control_center.html",
    "settings.html",
]


@pytest.mark.parametrize("fname", _NAV_FILES)
def test_nav_service_after_settings(fname):
    """Service link must appear AFTER the Settings link in the nav."""
    src = _dash(fname)
    idx_settings = src.find(f'{_NS}/secured/settings')
    idx_service  = src.find(f'{_NS}/secured/service')
    assert idx_settings != -1, f"{fname}: Settings nav link not found"
    assert idx_service  != -1, f"{fname}: Service nav link not found"
    assert idx_service > idx_settings, (
        f"{fname}: Service nav link appears BEFORE Settings — must be after (as a sub-item)"
    )


@pytest.mark.parametrize("fname", _NAV_FILES)
def test_nav_logs_after_settings(fname):
    """Logs link must appear AFTER the Settings link in the nav."""
    src = _dash(fname)
    idx_settings = src.find(f'{_NS}/secured/settings')
    idx_logs     = src.find(f'{_NS}/secured/logs"')
    assert idx_settings != -1, f"{fname}: Settings nav link not found"
    assert idx_logs     != -1, f"{fname}: Logs nav link not found"
    assert idx_logs > idx_settings, (
        f"{fname}: Logs nav link appears BEFORE Settings — must be after (as a sub-item)"
    )


@pytest.mark.parametrize("fname", _NAV_FILES)
def test_nav_service_has_sub_class(fname):
    """Service nav link must carry class='sub'."""
    src = _dash(fname)
    # Find the nav anchor for service
    m = re.search(r'<a [^>]*href="[^"]*secured/service"[^>]*>', src)
    assert m, f"{fname}: Service nav anchor not found"
    tag = m.group(0)
    assert 'class=' in tag and 'sub' in tag, (
        f"{fname}: Service nav link missing class='sub' — got: {tag!r}"
    )


@pytest.mark.parametrize("fname", _NAV_FILES)
def test_nav_logs_has_sub_class(fname):
    """Logs nav link must carry class='sub'."""
    src = _dash(fname)
    m = re.search(r'<a [^>]*href="[^"]*secured/logs"[^>]*>', src)
    assert m, f"{fname}: Logs nav anchor not found"
    tag = m.group(0)
    assert 'class=' in tag and 'sub' in tag, (
        f"{fname}: Logs nav link missing class='sub' — got: {tag!r}"
    )


@pytest.mark.parametrize("fname", [
    "main.html", "agents.html", "center_control.html",
    "vhost_policy.html", "geo.html", "service.html",
    "logs.html", "controls.html", "control_center.html", "settings.html",
])
def test_nav_settings_has_nav_settings_id(fname):
    """Settings nav link must retain id='nav-settings' (used by JS to mark active)."""
    src = _dash(fname)
    m = re.search(r'<a [^>]*href="[^"]*secured/settings"[^>]*>', src)
    assert m, f"{fname}: Settings nav anchor not found"
    tag = m.group(0)
    assert 'id="nav-settings"' in tag or "id='nav-settings'" in tag, (
        f"{fname}: Settings nav link must have id='nav-settings' — got: {tag!r}"
    )


def test_service_html_nav_service_is_active():
    """service.html: Service sub-item must carry 'active' class."""
    src = _dash("service.html")
    m = re.search(r'<a [^>]*href="[^"]*secured/service"[^>]*>', src)
    assert m, "service.html: Service nav anchor not found"
    tag = m.group(0)
    assert 'active' in tag, (
        f"service.html: Service nav link must have 'active' class — got: {tag!r}"
    )


def test_logs_html_nav_logs_is_active():
    """logs.html: Logs sub-item must carry 'active' class."""
    src = _dash("logs.html")
    m = re.search(r'<a [^>]*href="[^"]*secured/logs"[^>]*>', src)
    assert m, "logs.html: Logs nav anchor not found"
    tag = m.group(0)
    assert 'active' in tag, (
        f"logs.html: Logs nav link must have 'active' class — got: {tag!r}"
    )


def test_settings_html_nav_settings_is_active():
    """settings.html: Settings nav link must carry 'active' class."""
    src = _dash("settings.html")
    m = re.search(r'<a [^>]*href="[^"]*secured/settings"[^>]*>', src)
    assert m, "settings.html: Settings nav anchor not found"
    tag = m.group(0)
    assert 'active' in tag, (
        f"settings.html: Settings nav link must have 'active' class — got: {tag!r}"
    )


def test_nav_service_not_top_level_in_main():
    """main.html: Service must not be a top-level nav item (no bare href without sub class)."""
    src = _dash("main.html")
    m = re.search(r'<a [^>]*href="[^"]*secured/service"[^>]*>', src)
    assert m, "main.html: Service nav anchor not found"
    tag = m.group(0)
    assert 'sub' in tag, (
        "main.html: Service must be a sub-item (class='sub') — it was moved under Settings"
    )


def test_nav_logs_not_top_level_in_main():
    """main.html: Logs must not be a top-level nav item (must have sub class)."""
    src = _dash("main.html")
    m = re.search(r'<a [^>]*href="[^"]*secured/logs"[^>]*>', src)
    assert m, "main.html: Logs nav anchor not found"
    tag = m.group(0)
    assert 'sub' in tag, (
        "main.html: Logs must be a sub-item (class='sub') — it was moved under Settings"
    )


# ── OIDC: db/sqlite.py _SECRET_KEYS registration ─────────────────────────────

_SQLITE_SRC = _src("db/sqlite.py")

_OIDC_SECRET_KEYS = [
    "OIDC_ISSUER",
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "OIDC_DEFAULT_ROLE",
    "OIDC_SCOPES",
]


@pytest.mark.parametrize("key", _OIDC_SECRET_KEYS)
def test_sqlite_secret_keys_contains_oidc(key):
    """db/sqlite.py _SECRET_KEYS must register each OIDC config key."""
    assert f'"{key}"' in _SQLITE_SRC, (
        f"db/sqlite.py: _SECRET_KEYS must contain '{key}' for hot-reload OIDC config"
    )


def test_sqlite_refresh_derives_oidc_enabled():
    """_refresh_integration_state must derive OIDC_ENABLED from issuer+client_id+secret."""
    src = _SQLITE_SRC
    fn_start = src.find("def _refresh_integration_state(")
    assert fn_start != -1, "db/sqlite.py: _refresh_integration_state not found"
    fn_body = src[fn_start:fn_start + 3000]
    assert "OIDC_ENABLED" in fn_body, (
        "db/sqlite.py: _refresh_integration_state must set g['OIDC_ENABLED']"
    )
    assert "OIDC_ISSUER" in fn_body and "OIDC_CLIENT_ID" in fn_body and "OIDC_CLIENT_SECRET" in fn_body, (
        "db/sqlite.py: OIDC_ENABLED derivation must reference all three required vars"
    )


def test_sqlite_refresh_propagates_oidc_enabled():
    """_refresh_integration_state must include OIDC_ENABLED in _propagate dict."""
    src = _SQLITE_SRC
    fn_start = src.find("def _refresh_integration_state(")
    fn_body = src[fn_start:fn_start + 3000]
    prop_start = fn_body.find("_propagate")
    assert prop_start != -1, "db/sqlite.py: _propagate dict not found in _refresh_integration_state"
    prop_block = fn_body[prop_start:prop_start + 1000]
    assert '"OIDC_ENABLED"' in prop_block or "'OIDC_ENABLED'" in prop_block, (
        "db/sqlite.py: _propagate must include OIDC_ENABLED so oidc.py sees live state"
    )


@pytest.mark.parametrize("key", _OIDC_SECRET_KEYS)
def test_sqlite_refresh_propagates_oidc_vars(key):
    """_refresh_integration_state must propagate each OIDC var to all loaded modules."""
    src = _SQLITE_SRC
    fn_start = src.find("def _refresh_integration_state(")
    fn_body = src[fn_start:fn_start + 3000]
    prop_start = fn_body.find("_propagate")
    prop_block = fn_body[prop_start:prop_start + 1000]
    assert f'"{key}"' in prop_block or f"'{key}'" in prop_block, (
        f"db/sqlite.py: _propagate must include '{key}' so all modules get the live value"
    )


# ── OIDC: proxy_handler.py /__secrets endpoint ───────────────────────────────

_PH_SRC = _src("core/proxy_handler.py")


def test_proxy_handler_secrets_get_returns_oidc_enabled():
    """/__secrets GET integration_state must include OIDC_ENABLED."""
    assert '"OIDC_ENABLED"' in _PH_SRC or "'OIDC_ENABLED'" in _PH_SRC, (
        "core/proxy_handler.py: integration_state in /__secrets GET must expose OIDC_ENABLED"
    )


def test_proxy_handler_secrets_docstring_mentions_oidc():
    """/__secrets endpoint docstring must list OIDC keys in accepted body."""
    assert "OIDC_ISSUER" in _PH_SRC and "OIDC_CLIENT_SECRET" in _PH_SRC, (
        "core/proxy_handler.py: /__secrets docstring must document OIDC keys"
    )


# ── OIDC: settings.html SSO card ─────────────────────────────────────────────

_SETTINGS_SRC = _dash("settings.html")


def test_settings_sso_card_present():
    """settings.html must have the SSO/OIDC card (#card-sso)."""
    assert 'id="card-sso"' in _SETTINGS_SRC, (
        "settings.html: missing SSO card (#card-sso) — OIDC config not exposed in Settings page"
    )


def test_settings_users_card_before_sso_card():
    """settings.html: Users card must appear before the SSO card.

    1.8.9 — Identity & Auth section reordered so local-auth basics
    (Users, Two-FA) precede SSO/OIDC config (which is opt-in). Most
    operators only ever touch Users; surfacing it first reduces clicks.
    """
    idx_users = _SETTINGS_SRC.find('id="card-users"')
    idx_2fa   = _SETTINGS_SRC.find('id="card-2fa"')
    idx_sso   = _SETTINGS_SRC.find('id="card-sso"')
    idx_pend  = _SETTINGS_SRC.find('id="card-sso-pending"')
    assert idx_users != -1, "settings.html: Users card not found"
    assert idx_2fa   != -1, "settings.html: 2FA card not found"
    assert idx_sso   != -1, "settings.html: SSO card not found"
    assert idx_pend  != -1, "settings.html: SSO-pending card not found"
    # Expected order: Users → 2FA → SSO → SSO Pending
    assert idx_users < idx_2fa < idx_sso < idx_pend, (
        "settings.html: Identity & Auth order must be Users → 2FA → SSO → SSO-pending. "
        f"Got positions users={idx_users}, 2fa={idx_2fa}, sso={idx_sso}, pending={idx_pend}"
    )


@pytest.mark.parametrize("field_id", [
    "sso-issuer", "sso-client-id", "sso-client-secret",
    "sso-default-role", "sso-scopes",
])
def test_settings_sso_form_field_present(field_id):
    """settings.html SSO card must contain all required form fields."""
    assert f'id="{field_id}"' in _SETTINGS_SRC, (
        f"settings.html: SSO form missing field #{field_id}"
    )


def test_settings_sso_client_secret_is_password_type():
    """settings.html: client-secret field must be type=password to mask input."""
    m = re.search(r'<input[^>]*id="sso-client-secret"[^>]*>', _SETTINGS_SRC)
    assert m, "settings.html: sso-client-secret input not found"
    tag = m.group(0)
    assert 'type="password"' in tag or "type='password'" in tag, (
        f"settings.html: sso-client-secret must be type=password — got: {tag!r}"
    )


def test_settings_sso_save_button_present():
    """settings.html: SSO card must have a Save button (#sso-save)."""
    assert 'id="sso-save"' in _SETTINGS_SRC, (
        "settings.html: missing #sso-save button in SSO card"
    )


def test_settings_sso_clear_button_present():
    """settings.html: SSO card must have a Disable SSO button (#sso-clear)."""
    assert 'id="sso-clear"' in _SETTINGS_SRC, (
        "settings.html: missing #sso-clear button in SSO card"
    )


def test_settings_sso_status_badge_present():
    """settings.html: SSO card must have a status badge (#sso-status-badge)."""
    assert 'id="sso-status-badge"' in _SETTINGS_SRC, (
        "settings.html: missing #sso-status-badge in SSO card"
    )


def test_settings_sso_js_fetches_secrets_endpoint():
    """settings.html SSO JS must fetch the /__secrets endpoint."""
    assert "/secured/secrets" in _SETTINGS_SRC, (
        "settings.html: SSO JS must fetch /secured/secrets to load/save OIDC config"
    )


def test_settings_sso_js_no_same_origin_credentials():
    """settings.html SSO JS must not use credentials:'same-origin' (use 'include')."""
    # The test_settings_html_no_credentials_same_origin in test_pure.py already
    # guards the whole file — this test is SSO-section-specific for clarity.
    sso_start = _SETTINGS_SRC.find("// ── SSO / OIDC")
    assert sso_start != -1, "settings.html: SSO JS block not found"
    sso_block = _SETTINGS_SRC[sso_start:]
    assert "credentials:'same-origin'" not in sso_block, (
        "settings.html SSO JS uses credentials:'same-origin' — must use 'include'"
    )
    assert 'credentials:"same-origin"' not in sso_block, (
        "settings.html SSO JS uses credentials:\"same-origin\" — must use 'include'"
    )


def test_settings_sso_js_uses_include_credentials():
    """settings.html SSO JS must use credentials:'include' for fetch calls."""
    sso_start = _SETTINGS_SRC.find("// ── SSO / OIDC")
    assert sso_start != -1, "settings.html: SSO JS block not found"
    sso_block = _SETTINGS_SRC[sso_start:]
    assert "credentials:'include'" in sso_block or 'credentials:"include"' in sso_block, (
        "settings.html SSO JS must use credentials:'include'"
    )


def test_settings_sso_js_sends_csrf_token():
    """settings.html SSO JS POST must include X-CSRF-Token header."""
    sso_start = _SETTINGS_SRC.find("// ── SSO / OIDC")
    assert sso_start != -1, "settings.html: SSO JS block not found"
    sso_block = _SETTINGS_SRC[sso_start:]
    assert "X-CSRF-Token" in sso_block, (
        "settings.html SSO JS must send X-CSRF-Token header on POST/DELETE"
    )


def test_settings_sso_js_clear_deletes_all_five_keys():
    """settings.html SSO clear handler must DELETE all 5 OIDC keys."""
    sso_start = _SETTINGS_SRC.find("// ── SSO / OIDC")
    assert sso_start != -1, "settings.html: SSO JS block not found"
    sso_block = _SETTINGS_SRC[sso_start:]
    for key in _OIDC_SECRET_KEYS:
        assert key in sso_block, (
            f"settings.html SSO clear handler must reference '{key}' for deletion"
        )


def test_settings_sso_js_updates_badge_on_load():
    """settings.html SSO JS must update the status badge after fetching state."""
    sso_start = _SETTINGS_SRC.find("// ── SSO / OIDC")
    assert sso_start != -1, "settings.html: SSO JS block not found"
    sso_block = _SETTINGS_SRC[sso_start:]
    assert "OIDC_ENABLED" in sso_block, (
        "settings.html SSO JS must read OIDC_ENABLED from integration_state to update badge"
    )
    assert "setBadge" in sso_block or "sso-status-badge" in sso_block, (
        "settings.html SSO JS must update the status badge element"
    )


def test_settings_sso_default_role_select_has_viewer_option():
    """settings.html SSO default-role select must include 'viewer' option."""
    assert 'value="viewer"' in _SETTINGS_SRC or "value='viewer'" in _SETTINGS_SRC, (
        "settings.html: SSO default-role select must have a 'viewer' option"
    )


def test_settings_sso_default_role_select_has_admin_option():
    """settings.html SSO default-role select must include 'admin' option."""
    assert 'value="admin"' in _SETTINGS_SRC or "value='admin'" in _SETTINGS_SRC, (
        "settings.html: SSO default-role select must have an 'admin' option"
    )


def test_settings_sso_issuer_field_is_url_type():
    """settings.html: OIDC issuer field should be type=url for browser validation."""
    m = re.search(r'<input[^>]*id="sso-issuer"[^>]*>', _SETTINGS_SRC)
    assert m, "settings.html: sso-issuer input not found"
    tag = m.group(0)
    assert 'type="url"' in tag or "type='url'" in tag, (
        f"settings.html: sso-issuer input should be type=url — got: {tag!r}"
    )
