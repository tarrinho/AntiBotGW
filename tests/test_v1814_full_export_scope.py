"""
tests/test_v1814_full_export_scope.py — guard the 1.8.14 "full export"
contract.

Before 1.8.14 the export captured only knobs + admin_ips + vhosts; a
backup → reset → restore cycle silently dropped SIEM rules, DLP patterns,
signal orders, honey fingerprints, the gateway-mesh registry+distribution,
user accounts, and integration secrets. 1.8.14 makes the export *full*
and adds an honest `include_secrets` flag (previously a UI lie — the
backend deleted the param).

Static AST + integration probe against a fixture SQLite DB; no live HTTP.
"""
import ast
import importlib.util
import os
import sqlite3
import sys
import types
import xml.etree.ElementTree as ET

import pytest

_REPO = os.path.join(os.path.dirname(__file__), "..")
SETTINGS_PY = os.path.join(_REPO, "admin", "settings.py")


# ── Static contract checks ───────────────────────────────────────────────

def _src():
    return open(SETTINGS_PY, encoding="utf-8").read()


def test_export_endpoint_honors_include_secrets_param():
    """The endpoint must read the query param — previously it was ignored
    and the checkbox in settings.html was misleading the operator."""
    src = _src()
    assert 'request.query.get("include_secrets"' in src, (
        "settings_export_endpoint must read ?include_secrets= from the request")
    assert "include_secrets=include_secrets" in src, (
        "the parsed value must be forwarded to _settings_build_xml(include_secrets=...)")


def test_build_xml_does_not_silently_drop_include_secrets():
    """1.8.13 had `del include_secrets` at the top of the function — a
    silent override that made the operator's choice meaningless."""
    src = _src()
    assert "del include_secrets" not in src, (
        "_settings_build_xml must honour its include_secrets param, not delete it")


def test_export_covers_all_eleven_sections():
    """Static scan: the new exporter must emit every required XML section."""
    src = _src()
    required = [
        '"knobs"', '"admin_ips"', '"vhosts"',
        '"siem_alert_rules"', '"dlp_patterns"', '"signal_orders"',
        '"honey_fingerprints"', '"gw_registry"', '"gw_distribution"',
        '"users"', '"secrets"',
    ]
    missing = [s for s in required if s not in src]
    assert not missing, f"_settings_build_xml is missing sections: {missing}"


def test_import_summary_counts_all_new_sections():
    """The import response must report counts for every new section so an
    operator can verify the restore landed everything."""
    src = _src()
    required = [
        '"siem_rules_added"', '"dlp_patterns_added"',
        '"signal_orders_restored"', '"honey_fps_restored"',
        '"gw_registry_restored"', '"gw_distribution_restored"',
        '"users_restored"', '"secrets_restored"',
    ]
    missing = [k for k in required if k not in src]
    assert not missing, f"import summary is missing counters: {missing}"


def test_local_private_key_protected_on_import():
    """The mesh HMAC private_key on the LOCAL row must NEVER be overwritten
    by a vanilla import (it's the live secret that pins the operator's
    fleet identity). COALESCE keeps the existing value if present."""
    src = _src()
    assert "private_key=COALESCE(gw_registry.private_key" in src, (
        "gw_registry UPSERT must protect the existing local private_key")


def test_users_import_uses_insert_or_ignore():
    """User import must not silently overwrite an existing account — that
    would let a stale archive demote / lock out a current admin."""
    src = _src()
    assert "INSERT OR IGNORE INTO users" in src, (
        "users import must merge, never replace, existing accounts")


# ── Integration probe — call _settings_build_xml against a fixture DB ────

@pytest.fixture
def _fixture_db(tmp_path):
    p = tmp_path / "fixture.db"
    conn = sqlite3.connect(str(p))
    conn.executescript("""
      CREATE TABLE siem_alert_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        metric TEXT NOT NULL, op TEXT NOT NULL, threshold REAL NOT NULL,
        label TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1,
        created_ts REAL NOT NULL, created_by TEXT,
        last_fired_ts REAL DEFAULT 0, cooldown_s INTEGER NOT NULL DEFAULT 300);
      CREATE TABLE dlp_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL, pattern TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'high',
        enabled INTEGER NOT NULL DEFAULT 1,
        added_ts REAL, added_by TEXT);
      CREATE TABLE gw_registry (
        gw_id TEXT PRIMARY KEY, domain TEXT, region TEXT, environment TEXT,
        status TEXT NOT NULL DEFAULT 'active',
        can_distribute INTEGER NOT NULL DEFAULT 1,
        public_key TEXT NOT NULL, private_key TEXT,
        key_created_ts REAL NOT NULL, key_rotated_ts REAL,
        last_seen_ts REAL, created_ts REAL NOT NULL, updated_ts REAL NOT NULL,
        is_local INTEGER NOT NULL DEFAULT 0,
        auto_apply INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE gw_distribution (
        source_gw_id TEXT NOT NULL, target_gw_id TEXT NOT NULL, ts REAL NOT NULL,
        PRIMARY KEY (source_gw_id, target_gw_id));
      CREATE TABLE signal_orders (
        gw_id TEXT NOT NULL, signal TEXT NOT NULL,
        activation_order INTEGER NOT NULL CHECK (activation_order IN (1,2,3)),
        updated_ts REAL NOT NULL, updated_by TEXT,
        PRIMARY KEY (gw_id, signal));
      CREATE TABLE users (
        username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin', status TEXT NOT NULL DEFAULT 'active',
        created_ts REAL NOT NULL, updated_ts REAL NOT NULL,
        last_login_ts REAL, last_login_ip TEXT);
      CREATE TABLE secrets_kv (key TEXT PRIMARY KEY, value TEXT, ts REAL);
      CREATE TABLE honey_fingerprints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL, track_key TEXT, ip TEXT NOT NULL,
        ua TEXT, ja4 TEXT, asn TEXT, path TEXT, reason TEXT);
      INSERT INTO gw_registry (gw_id, public_key, private_key, key_created_ts,
                               created_ts, updated_ts, is_local)
                       VALUES ('local-gw', 'pub_xyz', 'PRIVATE_KEY_SECRET',
                               1700000000.0, 1700000000.0, 1700000000.0, 1);
      INSERT INTO gw_registry (gw_id, public_key, key_created_ts,
                               created_ts, updated_ts, is_local)
                       VALUES ('peer-gw', 'pub_abc',
                               1700000000.0, 1700000000.0, 1700000000.0, 0);
      INSERT INTO gw_distribution VALUES ('local-gw', 'peer-gw', 1700000000.0);
      INSERT INTO signal_orders VALUES
        ('local-gw', 'js-challenge', 1, 1700000000.0, 'op'),
        ('local-gw', 'bot-trap',     2, 1700000000.0, 'op');
      INSERT INTO users (username, password_hash, created_ts, updated_ts)
        VALUES ('alice', 'argon2id$v=19$...$abcdef', 1700000000.0, 1700000000.0);
      INSERT INTO secrets_kv VALUES ('ABUSEIPDB_KEY', 'sk_live_real_key', 1700000000.0);
      INSERT INTO secrets_kv VALUES ('TURNSTILE_SECRET', '0x_secret', 1700000000.0);
      INSERT INTO siem_alert_rules (metric, op, threshold, created_ts)
        VALUES ('blocked_per_min', '>', 100.0, 1700000000.0);
      INSERT INTO dlp_patterns (name, pattern) VALUES ('ssn', '\\d{3}-\\d{2}-\\d{4}');
      INSERT INTO honey_fingerprints (ts, ip, ja4, reason)
        VALUES (1700000000.0, '1.2.3.4', 'ja4hash', 'honey-cred');
    """)
    conn.commit()
    conn.close()
    return str(p)


@pytest.fixture
def _stub_proxy_handler():
    """Replace core.proxy_handler in sys.modules with a JSON-safe stub for
    the duration of the test, then restore the real module."""
    saved = sys.modules.get("core.proxy_handler")
    m = types.ModuleType("core.proxy_handler")
    m._read_hot_reload_state = lambda: {"DEMO_KNOB": 1, "OTHER": [1, 2]}
    sys.modules["core.proxy_handler"] = m
    if "core" not in sys.modules:
        sys.modules["core"] = types.ModuleType("core")
    yield m
    if saved is not None:
        sys.modules["core.proxy_handler"] = saved
    else:
        sys.modules.pop("core.proxy_handler", None)


def _load_settings_module(db_path):
    """Load admin/settings.py in isolation. Caller must hold the
    _stub_proxy_handler fixture so the stub is in place when
    _settings_build_xml does its inner `from core.proxy_handler import …`."""
    os.environ.setdefault("UPSTREAM", "https://example.com")
    os.environ["DB_PATH"] = db_path
    spec = importlib.util.spec_from_file_location(
        f"admin_settings_v1814_{id(db_path)}", SETTINGS_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.DB_PATH = db_path
    return mod


def test_export_no_secrets_strips_sensitive_fields(_fixture_db, _stub_proxy_handler):
    mod = _load_settings_module(_fixture_db)
    xml = mod._settings_build_xml(include_secrets=False)
    root = ET.fromstring(xml)
    assert root.attrib["includes_secrets"] == "0"
    # secrets section empty
    assert len(root.find("secrets").findall("secret")) == 0
    # users present but no password_hash
    users = root.find("users").findall("user")
    assert len(users) == 1
    assert "password_hash" not in users[0].attrib, (
        "password_hash must be stripped without include_secrets")
    # gw_registry: NO private_key on any row
    for gw in root.find("gw_registry").findall("gw"):
        assert "private_key" not in gw.attrib, (
            "private_key must be stripped without include_secrets")


def test_export_with_secrets_includes_everything_explicit(_fixture_db, _stub_proxy_handler):
    mod = _load_settings_module(_fixture_db)
    xml = mod._settings_build_xml(include_secrets=True)
    root = ET.fromstring(xml)
    assert root.attrib["includes_secrets"] == "1"
    # secrets populated
    secs = {s.attrib["key"]: (s.text or "") for s in root.find("secrets").findall("secret")}
    assert "ABUSEIPDB_KEY" in secs and secs["ABUSEIPDB_KEY"] == "sk_live_real_key"
    # users carry password_hash
    users = root.find("users").findall("user")
    assert any(u.attrib.get("password_hash", "").startswith("argon2id$") for u in users)
    # gw_registry: private_key ONLY on the local row
    rows = {gw.attrib["gw_id"]: gw.attrib for gw in root.find("gw_registry").findall("gw")}
    assert rows["local-gw"].get("private_key") == "PRIVATE_KEY_SECRET"
    assert "private_key" not in rows["peer-gw"], (
        "peer gw rows must never carry a private_key")


def test_export_emits_all_eleven_sections(_fixture_db, _stub_proxy_handler):
    mod = _load_settings_module(_fixture_db)
    root = ET.fromstring(mod._settings_build_xml(include_secrets=False))
    tags = {el.tag for el in root}
    expected = {"knobs", "admin_ips", "vhosts", "siem_alert_rules",
                "dlp_patterns", "signal_orders", "honey_fingerprints",
                "gw_registry", "gw_distribution", "users", "secrets"}
    missing = expected - tags
    assert not missing, f"missing sections in export: {missing}"


def test_export_skips_missing_table_gracefully(tmp_path, _stub_proxy_handler):
    """Defensive: a fresh DB without the new tables must still produce a
    valid XML (with empty containers), not crash the endpoint."""
    p = tmp_path / "empty.db"
    sqlite3.connect(str(p)).close()  # empty DB, no tables
    mod = _load_settings_module(str(p))
    xml = mod._settings_build_xml(include_secrets=False)
    root = ET.fromstring(xml)
    # all 11 sections must still be present (just empty)
    assert {el.tag for el in root} >= {
        "siem_alert_rules", "dlp_patterns", "signal_orders",
        "honey_fingerprints", "gw_registry", "gw_distribution",
        "users", "secrets",
    }


# ── _HOT_RELOAD_KNOBS promotions ─────────────────────────────────────────

def test_jA4H_DENY_LIST_now_hot_reloadable():
    """1.8.14: JA4H_DENY_LIST promoted from env-only to hot-reload so the
    full-export round-trip covers it (sibling of JA4_DENY_LIST)."""
    src = open(os.path.join(_REPO, "core/proxy_handler.py"), encoding="utf-8").read()
    assert '"JA4H_DENY_LIST"' in src and '"JA4H_DENY_LIST":' in src


def test_ABUSEIPDB_CACHE_HOURS_now_hot_reloadable():
    src = open(os.path.join(_REPO, "core/proxy_handler.py"), encoding="utf-8").read()
    assert '"ABUSEIPDB_CACHE_HOURS"' in src and '"ABUSEIPDB_CACHE_HOURS":' in src
