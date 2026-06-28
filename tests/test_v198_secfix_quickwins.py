"""
Regression guards for the 1.9.8 security-review quick-win fixes.

From the whitebox assessment (analysis.result.md):
  M1/M2 (CWE-862) — mesh registry auto-apply / distribution-rules / topology-read
                    endpoints were missing role authorization (a viewer could
                    alter fleet trust/topology).
  M6   (CWE-312)  — only POSTGRES_DSN was encrypted at rest; all other secrets_kv
                    values were plaintext. Now every secret is Fernet-wrapped.
  M8   (CWE-1357) — the armv7 Dockerfile used a floating base tag; now digest-pinned.
"""
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_MESH = (_REPO / "admin" / "mesh.py").read_text(encoding="utf-8")
_SQLITE = (_REPO / "db" / "sqlite.py").read_text(encoding="utf-8")


def _func_body(src, name):
    i = src.index(f"async def {name}(")
    nxt = src.find("\nasync def ", i + 1)
    return src[i: nxt if nxt != -1 else len(src)]


# ── M1 / M2: every previously-ungated mesh endpoint now calls _role_denied ─────
import pytest


@pytest.mark.parametrize("fn", [
    "gw_registry_auto_apply_endpoint",            # M1 (write)
    "gw_registry_distribution_rules_endpoint",    # M2 (write)
    "gw_registry_distribution_matrix_endpoint",   # M2 (topology read)
    "gw_registry_sync_status_endpoint",           # M2 (topology read)
])
def test_mesh_endpoint_has_role_gate(fn):
    body = _func_body(_MESH, fn)
    assert re.search(r'_role_denied\(request,\s*"admin"', body), \
        f"{fn} must call _role_denied (CWE-862 broken access control)"


# ── M6: secrets encrypted at rest (writer encrypts, reader decrypts, all keys) ─
def test_writer_encrypts_every_secret_at_rest():
    i = _SQLITE.index('elif op == "set_secret":')
    branch = _SQLITE[i: i + 600]
    assert "_dsn_encrypt(args[1])" in branch, \
        "set_secret writer must Fernet-encrypt the value before persisting (M6)"


def test_reader_decrypts_all_secrets_not_just_dsn():
    # decrypt is applied to the row value generally, not gated on POSTGRES_DSN
    assert '_dsn_decrypt(r["value"])' in _SQLITE, \
        "db_load_secrets must decrypt every secret value (M6), not only POSTGRES_DSN"
    assert 'if public_name == "POSTGRES_DSN":\n            _value = _dsn_decrypt' not in _SQLITE, \
        "decrypt must no longer be special-cased to POSTGRES_DSN only"


def test_secret_encrypt_roundtrip_and_idempotent():
    import db.sqlite as s
    # Works regardless of cryptography/SESSION_KEY availability: when crypto is
    # unavailable _dsn_encrypt returns plaintext, and _dsn_decrypt round-trips it.
    for secret in ("turnstile-secret-xyz", "abuseipdb_KEY_123", "", "sk-test-aaa"):
        enc = s._dsn_encrypt(secret)
        assert s._dsn_decrypt(enc) == secret, f"round-trip failed for {secret!r}"
        # idempotent: encrypting an already-encrypted value does not double-wrap
        assert s._dsn_encrypt(enc) == enc, "encryption must be idempotent"
        if enc and enc != secret:                      # crypto active
            assert enc.startswith(s._DSN_ENC_PREFIX) and secret not in enc, \
                "ciphertext must be prefixed and not contain the plaintext"


def test_m6_secret_persistence_roundtrip_encrypted_at_rest(tmp_path, monkeypatch):
    """End-to-end: a secret stored the way the set_secret writer now stores it
    (Fernet via _dsn_encrypt) is ciphertext at rest, and db_load_secrets returns
    the decrypted plaintext into the module globals — for a NON-DSN secret."""
    import sqlite3
    import db.sqlite as s
    import db.conn as dbconn
    dbf = str(tmp_path / "secrets.db")
    con = sqlite3.connect(dbf)
    con.execute("CREATE TABLE secrets_kv (key TEXT PRIMARY KEY, value TEXT, ts REAL)")
    secret = "turnstile-supersecret-xyz"
    stored = s._dsn_encrypt(secret)            # exact transform the writer applies
    con.execute("INSERT INTO secrets_kv (key,value,ts) VALUES (?,?,?)",
                ("TURNSTILE_SECRET", stored, 1.0))
    con.commit(); con.close()
    monkeypatch.setattr(s, "DB_PATH", dbf, raising=False)
    monkeypatch.setattr(dbconn, "active_backend", lambda: "sqlite", raising=False)
    monkeypatch.delenv("TURNSTILE_SECRET", raising=False)
    # post-load integration refresh expects a fully-populated module globals dict;
    # neutralize it so this test focuses on the load+decrypt path (the M6 concern).
    monkeypatch.setattr(s, "_refresh_integration_state", lambda *a, **k: None, raising=False)
    g = {}
    s.db_load_secrets(g)
    assert g.get("TURNSTILE_SECRET") == secret, \
        "db_load_secrets must decrypt every stored secret (M6), not only POSTGRES_DSN"
    if stored != secret:                       # cryptography + SESSION_KEY available
        assert stored.startswith(s._DSN_ENC_PREFIX) and secret not in stored, \
            "secret must be ciphertext at rest, plaintext absent"


# ── M8: armv7 base image is digest-pinned on both stages ──────────────────────
def test_armv7_base_is_digest_pinned():
    df = (_REPO / "Dockerfile.armv7").read_text(encoding="utf-8")
    froms = re.findall(r'^FROM\s+(\S+)', df, re.M)
    assert froms, "no FROM lines in Dockerfile.armv7"
    for ref in froms:
        assert "@sha256:" in ref, f"armv7 FROM not digest-pinned: {ref} (M8 / CWE-1357)"
