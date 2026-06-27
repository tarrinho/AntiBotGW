"""
tests/test_v1814_full_export_qa.py — QA-grade regression guards for the
1.8.14 full-export surface.

Complementary to `test_v1814_full_export_scope.py` (which guards the
contract). This file targets edge cases, invariants, and UX traps:
  · honey_fingerprints LIMIT 1000 cap
  · signal_orders filtered to LOCAL gw_id only (foreign gw_ids stripped)
  · peer gw_registry rows NEVER carry a private_key (even with secrets ON)
  · filename suffix `-with-secrets` only when include_secrets is honoured
  · slog records the include_secrets flag for auditability
  · UI checkbox actually appends ?include_secrets=1 to the export URL
  · JA4H_DENY_LIST is a `set` (not frozenset) so JSON serialisation works
  · Round-trip structural integrity (export → re-export → compare)
  · Empty include_secrets attribute defaults to disabled (don't leak)
  · DB-path errors don't crash; the XML still emits empty containers

Integration probes against a fixture SQLite DB. Static AST checks against
the file sources. No live HTTP needed.
"""
import importlib.util
import os
import re
import sqlite3
import sys
import types
import xml.etree.ElementTree as ET

import pytest

_REPO = os.path.join(os.path.dirname(__file__), "..")
SETTINGS_PY = os.path.join(_REPO, "admin", "settings.py")
CONFIG_PY   = os.path.join(_REPO, "config.py")
SETTINGS_HTML = os.path.join(_REPO, "dashboards", "settings.html")


# ── shared fixture infrastructure (re-implemented for isolation) ─────────

@pytest.fixture
def _stub_proxy_handler():
    saved = sys.modules.get("core.proxy_handler")
    m = types.ModuleType("core.proxy_handler")
    m._read_hot_reload_state = lambda: {"DEMO_KNOB": 1, "BOOL_KNOB": True}
    sys.modules["core.proxy_handler"] = m
    if "core" not in sys.modules:
        sys.modules["core"] = types.ModuleType("core")
    yield m
    if saved is not None:
        sys.modules["core.proxy_handler"] = saved
    else:
        sys.modules.pop("core.proxy_handler", None)


def _seeded_db(tmp_path, *,
               honey_count: int = 0,
               local_orders: int = 0,
               peer_orders: int = 0,
               peer_with_private_key: bool = False):
    """Create a fixture DB matching the live schema, optionally over-seeded
    so the QA tests can probe caps + filters."""
    p = tmp_path / f"db_{honey_count}_{local_orders}_{peer_orders}.db"
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
    """)
    # always seed a LOCAL gw row so signal_orders has a parent
    conn.execute(
        "INSERT INTO gw_registry (gw_id, public_key, private_key, "
        "key_created_ts, created_ts, updated_ts, is_local) "
        "VALUES ('local-gw', 'pub_local', 'LOCAL_PRIVATE_KEY', "
        "1700000000, 1700000000, 1700000000, 1)")
    # peer row, optionally with a private_key planted to verify it's stripped
    conn.execute(
        "INSERT INTO gw_registry (gw_id, public_key, private_key, "
        "key_created_ts, created_ts, updated_ts, is_local) "
        "VALUES ('peer-gw', 'pub_peer', ?, "
        "1700000000, 1700000000, 1700000000, 0)",
        ("PEER_PRIVATE_KEY_SHOULD_NEVER_LEAK" if peer_with_private_key else None,))

    # honey_fingerprints — write `honey_count` rows
    for i in range(honey_count):
        conn.execute(
            "INSERT INTO honey_fingerprints (ts, ip, ja4, reason) "
            "VALUES (?, ?, ?, ?)",
            (1700000000.0 + i, f"10.0.{i // 256}.{i % 256}", f"ja4_{i}", "honey-cred"))

    # signal_orders — split between LOCAL and a foreign gw
    for i in range(local_orders):
        conn.execute(
            "INSERT INTO signal_orders VALUES (?, ?, ?, ?, ?)",
            ("local-gw", f"sig-local-{i}", (i % 3) + 1, 1700000000.0, "op"))
    for i in range(peer_orders):
        # NOTE: peer_orders SHOULD be invisible in the export
        conn.execute(
            "INSERT INTO signal_orders VALUES (?, ?, ?, ?, ?)",
            ("peer-gw", f"sig-peer-{i}", (i % 3) + 1, 1700000000.0, "op"))
    conn.commit()
    conn.close()
    return str(p)


def _load_settings(db_path):
    os.environ.setdefault("UPSTREAM", "https://example.com")
    os.environ["DB_PATH"] = db_path
    spec = importlib.util.spec_from_file_location(
        f"admin_settings_qa_{id(db_path)}", SETTINGS_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.DB_PATH = db_path
    return mod


# ── 1) honey_fingerprints 1000-row cap ───────────────────────────────────

def test_honey_fingerprints_capped_at_1000(tmp_path, _stub_proxy_handler):
    """A noisy demo can accumulate tens of thousands of honey_fingerprints
    rows; the export caps at the most-recent 1000 so the archive stays
    under the 1 MiB import upload limit."""
    db = _seeded_db(tmp_path, honey_count=1500)
    mod = _load_settings(db)
    root = ET.fromstring(mod._settings_build_xml(include_secrets=False))
    fps = root.find("honey_fingerprints").findall("fp")
    assert len(fps) == 1000, f"expected cap at 1000, got {len(fps)}"
    # And the cap takes the most-recent (highest ts) — not the oldest.
    ts_vals = sorted(float(fp.attrib["ts"]) for fp in fps)
    # We wrote ts = 1700000000 + i for i in 0..1499. Most recent 1000 = 500..1499.
    assert ts_vals[0]  == 1_700_000_500.0, "should be oldest of recent 1000"
    assert ts_vals[-1] == 1_700_001_499.0, "should be newest"


# ── 2) signal_orders filtered to LOCAL gw_id ─────────────────────────────

def test_signal_orders_only_local_gw_id(tmp_path, _stub_proxy_handler):
    """A foreign gw_id in `signal_orders` is meaningless on a restored
    instance and would only confuse the operator. The export must filter
    them out."""
    db = _seeded_db(tmp_path, local_orders=5, peer_orders=7)
    mod = _load_settings(db)
    root = ET.fromstring(mod._settings_build_xml(include_secrets=True))
    orders = root.find("signal_orders").findall("order")
    sigs = {o.attrib["signal"] for o in orders}
    assert len(orders) == 5, f"only LOCAL signal_orders should be exported, got {len(orders)}"
    assert all(s.startswith("sig-local-") for s in sigs), (
        f"foreign gw signals leaked into export: {sorted(sigs)}")


# ── 3) peer gw rows never carry a private_key, even with secrets ON ──────

def test_peer_gw_private_key_never_exported(tmp_path, _stub_proxy_handler):
    """The export must NEVER serialise a peer gw row's private_key, even
    when include_secrets=True. Only the LOCAL row owns its private key;
    a peer row with a populated private_key column is operationally
    nonsensical and probably hostile (e.g. a key planted into the DB)."""
    db = _seeded_db(tmp_path, peer_with_private_key=True)
    mod = _load_settings(db)
    root = ET.fromstring(mod._settings_build_xml(include_secrets=True))
    rows = {gw.attrib["gw_id"]: gw.attrib
            for gw in root.find("gw_registry").findall("gw")}
    assert "private_key" in rows["local-gw"], "LOCAL row should carry its private_key when include_secrets=True"
    assert "private_key" not in rows["peer-gw"], (
        "peer gw row leaked a private_key into the export")


# ── 4) Filename suffix `-with-secrets` only when actually included ───────

def test_filename_suffix_marks_secrets_inclusion():
    """`-with-secrets` in the filename is the operator's at-a-glance cue
    that the archive is credential material and must be stored securely."""
    src = open(SETTINGS_PY, encoding="utf-8").read()
    assert "'-with-secrets' if include_secrets else ''" in src, (
        "filename must be suffixed only when include_secrets=1")


# ── 5) slog records include_secrets for auditability ────────────────────

def test_export_slog_records_include_secrets_flag():
    src = open(SETTINGS_PY, encoding="utf-8").read()
    # Take the 600 chars immediately after the slog name — covers the full
    # multi-line kwargs block without false splits on parens inside the call.
    i = src.find('"config_exported"')
    assert i >= 0, "config_exported slog event not found"
    block = src[i:i + 600]
    assert "include_secrets=include_secrets" in block, (
        "config_exported slog event must record the include_secrets flag "
        "so the audit trail captures whether a secrets-bearing archive left the gateway")


# ── 6) UI checkbox actually forwards to the endpoint ─────────────────────

def test_settings_html_checkbox_appends_query_param():
    """The export button's JS must read the checkbox and append
    ?include_secrets=1 — if it doesn't, the operator's tick is dropped on
    the floor and we're back to the pre-1.8.14 lie."""
    html = open(SETTINGS_HTML, encoding="utf-8").read()
    assert 'id="export-include-secrets"' in html, "checkbox element id missing"
    # JS must read the checkbox and put it on the URL.
    js_window = re.search(
        r'export-include-secrets[\s\S]{0,800}include_secrets=', html)
    assert js_window is not None, (
        "JS must wire the include-secrets checkbox into the export URL")


# ── 7) JA4H_DENY_LIST default type — set, not frozenset ─────────────────

def test_ja4h_deny_list_default_is_set_not_frozenset():
    """`_read_hot_reload_state`'s `isinstance(v, set)` branch must catch
    JA4H_DENY_LIST. A frozenset slips through and breaks json.dumps in
    the export (the pre-1.8.14 latent bug)."""
    src = open(CONFIG_PY, encoding="utf-8").read()
    # Match the actual line in config.py (post-1.8.14)
    assert re.search(r"^JA4H_DENY_LIST\s*:\s*set\s*=\s*\{", src, re.M), (
        "JA4H_DENY_LIST must default to `set`, not `frozenset`, "
        "to match its sibling JA4_DENY_LIST and stay JSON-serialisable")
    assert not re.search(r"^JA4H_DENY_LIST.*frozenset", src, re.M), (
        "JA4H_DENY_LIST must not be declared as frozenset")


# ── 8) Round-trip structural integrity ──────────────────────────────────

def test_round_trip_preserves_section_topology(tmp_path, _stub_proxy_handler):
    """Export → parse → re-export against the SAME DB → both XMLs must
    have the same section layout and per-section element counts. (Knob
    text differs because timestamps re-render, so we compare topology.)"""
    db = _seeded_db(tmp_path, honey_count=3, local_orders=2, peer_orders=4)
    mod = _load_settings(db)
    xml_a = mod._settings_build_xml(include_secrets=True)
    xml_b = mod._settings_build_xml(include_secrets=True)
    ra, rb = ET.fromstring(xml_a), ET.fromstring(xml_b)
    counts_a = {el.tag: len(list(el)) for el in ra}
    counts_b = {el.tag: len(list(el)) for el in rb}
    assert counts_a == counts_b, (
        f"section topology drifted between repeated exports: {counts_a} vs {counts_b}")


# ── 9) include_secrets="" defaults to disabled (don't leak) ──────────────

def test_export_endpoint_defaults_to_secrets_off():
    """Any unrecognised value of `?include_secrets=` (empty, garbage,
    anything that isn't in the allow-list) must default to OFF.
    Operator can only opt in with a known-truthy value."""
    src = open(SETTINGS_PY, encoding="utf-8").read()
    # The truthy allow-list must be an explicit, small set. The whole
    # parsing expression is on one line in the endpoint.
    assert re.search(
        r'request\.query\.get\("include_secrets".*?\.lower\(\)\s*in\s*'
        r'\("1",\s*"true",\s*"yes",\s*"on"\)', src), (
        "endpoint must allow-list explicit truthy values for include_secrets, "
        "not coerce by truthiness")


# ── 10) Defensive — DB path that doesn't exist still emits all containers ─

def test_missing_db_path_emits_empty_containers(tmp_path, _stub_proxy_handler):
    """If DB_PATH points at a fresh / unmigrated DB the export must NOT
    crash. Each DB-backed section runs in its own try/except so a missing
    table leaves the container empty but valid."""
    nonexistent = tmp_path / "does_not_exist_yet.db"
    # touch an empty DB (no schema) so sqlite3.connect doesn't error
    sqlite3.connect(str(nonexistent)).close()
    mod = _load_settings(str(nonexistent))
    xml = mod._settings_build_xml(include_secrets=True)
    root = ET.fromstring(xml)
    expected = {"knobs", "admin_ips", "vhosts", "siem_alert_rules",
                "dlp_patterns", "signal_orders", "honey_fingerprints",
                "gw_registry", "gw_distribution", "users", "secrets"}
    assert {el.tag for el in root} >= expected, (
        f"sections lost on missing tables: {expected - {el.tag for el in root}}")
    # And the sensitive containers must be empty (no data to leak).
    assert len(root.find("secrets").findall("secret")) == 0
    assert len(root.find("users").findall("user")) == 0


# ── 11) Import side: error isolation across sections ─────────────────────

def test_importer_isolates_errors_per_section():
    """A malformed row in one section must not abort the others. The
    importer logs into `summary['errors']` and keeps going. We assert the
    source contains per-section try/except so a SQL error in (say) DLP
    can't kill the SIEM import."""
    src = open(SETTINGS_PY, encoding="utf-8").read()
    body = src.split("settings_import_endpoint", 1)[1]
    # Count per-section try blocks inside the importer body — must be ≥ 7
    # (one for each of siem, dlp, signal_orders, honey, gw_reg, gw_dist, users, secrets).
    n_try = body.count("try:")
    n_summary_errors = body.count('summary["errors"].append')
    assert n_try >= 7, (
        f"importer must wrap each new section in try/except; only found {n_try} try blocks")
    assert n_summary_errors >= 7, (
        f"importer must surface per-section errors into summary; only found {n_summary_errors} append sites")


# ── 12) Hot-reload knob promotion durability ─────────────────────────────

def test_new_hot_reload_knobs_have_parser_and_validator():
    """Promoted knobs (JA4H_DENY_LIST, ABUSEIPDB_CACHE_HOURS) must be
    declared as 2-tuples in _HOT_RELOAD_KNOBS (parser, validator)."""
    src = open(os.path.join(_REPO, "core/proxy_handler.py"), encoding="utf-8").read()
    for k in ("JA4H_DENY_LIST", "ABUSEIPDB_CACHE_HOURS"):
        # match `"K": (parser, validator),` style — accepts lambdas too
        m = re.search(rf'"{k}"\s*:\s*\(\s*[^,]+,\s*[^)]+\)', src)
        assert m is not None, (
            f"{k} must be wired into _HOT_RELOAD_KNOBS as (parser, validator)")
