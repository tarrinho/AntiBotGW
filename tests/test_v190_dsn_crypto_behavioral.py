"""
tests/test_v190_dsn_crypto_behavioral.py — behavioral gaps for the F14
DSN-at-rest encryption that the existing v190 anchor tests don't cover.

What's already covered (test_v190_iteration4_fixes.py):
  • _dsn_encrypt / _dsn_decrypt helpers exist
  • Fernet used with the agw-dsn-fernet-v1 domain-separated key
  • Versioned prefix `enc:v1:`
  • Round-trip encrypt → decrypt
  • Legacy plaintext passes through decrypt unchanged

This file adds:
  • Idempotency — encrypt(encrypt(plain)) === encrypt(plain) (the explicit
    "already encrypted (defensive — idempotent)" branch).
  • Empty / None DSN safe — encrypt("") returns "" without raising.
  • SESSION_KEY rotation — ciphertext written under key A is unreadable
    under key B; _dsn_decrypt returns "" (callers must treat as "skip").
  • _fernet_key_from_session returns None when SESSION_KEY is unset (no
    plaintext leak via silent encryption with a degenerate key).
  • _dsn_encrypt no-op when cryptography lib is mocked unavailable — caller
    must get the plaintext back so the move to secrets_kv (off /__config)
    remains the load-bearing mitigation.
"""
import importlib
import sys

import pytest


def _sql():
    """Lazy import — db.sqlite touches a lot of state."""
    return importlib.import_module("db.sqlite")


def _set_session_key(value):
    """Stamp a SESSION_KEY into a stub proxy module so _fernet_key_from_session
    finds it. Returns the prior value (or sentinel) so callers can restore."""
    mod = sys.modules.setdefault("proxy", type(sys)("proxy"))
    prev = getattr(mod, "SESSION_KEY", _SENTINEL)
    mod.SESSION_KEY = value
    return prev


def _restore_session_key(prev):
    mod = sys.modules.get("proxy")
    if mod is None:
        return
    if prev is _SENTINEL:
        try:
            del mod.SESSION_KEY
        except AttributeError:
            pass
    else:
        mod.SESSION_KEY = prev


_SENTINEL = object()


def _require_cryptography():
    try:
        import cryptography.fernet  # noqa: F401
    except ImportError:
        pytest.skip("cryptography not installed in test env")


# ── Idempotency ─────────────────────────────────────────────────────────

def test_encrypt_twice_returns_same_token():
    """Re-encrypting an already-encrypted DSN must return it unchanged —
    the explicit `if plaintext.startswith(_DSN_ENC_PREFIX): return plaintext`
    branch in _dsn_encrypt. Without this, a write path that ran through
    encrypt twice would double-wrap and the decrypt path could never
    recover the original."""
    _require_cryptography()
    sql = _sql()
    prev = _set_session_key(b"\x42" * 32)
    try:
        plain = "postgresql://u:p@h/d"
        once = sql._dsn_encrypt(plain)
        assert once.startswith(sql._DSN_ENC_PREFIX)
        twice = sql._dsn_encrypt(once)
        assert twice == once, (
            "encrypting an already-encrypted DSN must be a no-op — "
            "the _DSN_ENC_PREFIX guard is load-bearing for double-write paths"
        )
    finally:
        _restore_session_key(prev)


# ── Empty / None safety ─────────────────────────────────────────────────

def test_encrypt_empty_string_returns_empty():
    """A path that calls encrypt("") (e.g. operator cleared the DSN field)
    must NOT produce a non-empty ciphertext — that would silently "save"
    a meaningless token. Empty → empty is the contract."""
    sql = _sql()
    prev = _set_session_key(b"\x42" * 32)
    try:
        assert sql._dsn_encrypt("") == ""
    finally:
        _restore_session_key(prev)


def test_decrypt_empty_string_returns_empty():
    sql = _sql()
    prev = _set_session_key(b"\x42" * 32)
    try:
        # Decrypt of empty must not raise and must not return None.
        assert sql._dsn_decrypt("") == ""
    finally:
        _restore_session_key(prev)


# ── SESSION_KEY rotation ────────────────────────────────────────────────

def test_decrypt_with_rotated_session_key_returns_empty():
    """The whole point of SESSION_KEY-binding is that rotating it makes the
    ciphertext unreadable. Decrypt under a different key MUST return "" (so
    the load path skips, per the load_secrets contract) — NOT silently
    return the plaintext-looking ciphertext (which would then be treated
    as a malformed DSN)."""
    _require_cryptography()
    sql = _sql()
    # Encrypt under key A.
    prev = _set_session_key(b"A" * 32)
    try:
        plain = "postgresql://u:p@host/db"
        token = sql._dsn_encrypt(plain)
        assert token.startswith(sql._DSN_ENC_PREFIX)
    finally:
        _restore_session_key(prev)
    # Now rotate to key B and try to decrypt.
    prev = _set_session_key(b"B" * 32)
    try:
        decoded = sql._dsn_decrypt(token)
        assert decoded == "", (
            "decrypt under a rotated SESSION_KEY must return empty string — "
            "the load path treats empty as 'skip' and emits db_secrets_dsn_skipped"
        )
    finally:
        _restore_session_key(prev)


# ── Fernet key derivation safety ────────────────────────────────────────

def test_fernet_key_returns_none_when_session_key_unset():
    """If SESSION_KEY isn't bound anywhere reachable (very early boot, or
    tests stripping it from every candidate module), _fernet_key_from_session
    must return None — _dsn_encrypt then falls back to plaintext-pass-through.
    Returning a degenerate "0"-derived key would let a second process with
    the same code path 'decrypt' the token to garbage.

    The function scans both `proxy` and `config` module globals, so we
    must clear both to exercise the None-return branch."""
    sql = _sql()
    prev_proxy = _set_session_key("")  # falsy
    import config as _cfg_mod
    prev_cfg = getattr(_cfg_mod, "SESSION_KEY", _SENTINEL)
    try:
        # Force config's SESSION_KEY to a falsy value too.
        _cfg_mod.SESSION_KEY = ""
        key = sql._fernet_key_from_session()
        assert key is None, (
            "_fernet_key_from_session must return None when SESSION_KEY "
            "is falsy in every candidate module — never derive a key "
            "from empty bytes"
        )
    finally:
        _restore_session_key(prev_proxy)
        if prev_cfg is _SENTINEL:
            try: del _cfg_mod.SESSION_KEY
            except AttributeError: pass
        else:
            _cfg_mod.SESSION_KEY = prev_cfg


def test_fernet_key_handles_string_session_key():
    """SESSION_KEY may arrive as either bytes or str; the derive function
    must accept both. Without this, a str-typed SESSION_KEY (the most
    common form when loaded from .session_key file as text) would raise
    TypeError on hashlib.sha256(..."""
    sql = _sql()
    prev = _set_session_key("a string session key")
    try:
        key = sql._fernet_key_from_session()
        assert key is not None, "must accept str SESSION_KEY"
        assert isinstance(key, bytes), (
            "_fernet_key_from_session must return bytes (a base64-encoded "
            "32-byte key)"
        )
    finally:
        _restore_session_key(prev)


# ── Cryptography unavailable — encrypt no-op (plaintext pass-through) ──

def test_encrypt_falls_back_to_plaintext_when_cryptography_missing(monkeypatch):
    """When the cryptography lib import fails (slim image, broken env),
    _dsn_encrypt must return the plaintext unchanged — the move to
    secrets_kv (off /__config) is the load-bearing mitigation either way.
    A silent failure mode that returned None or empty would lose the DSN."""
    sql = _sql()
    prev = _set_session_key(b"\x42" * 32)
    # Force `from cryptography.fernet import Fernet` to raise at runtime.
    import builtins as _b
    real_import = _b.__import__
    def fake_import(name, *a, **kw):
        if name == "cryptography.fernet" or name == "cryptography":
            raise ImportError("simulated: cryptography unavailable")
        return real_import(name, *a, **kw)
    monkeypatch.setattr(_b, "__import__", fake_import)
    try:
        plain = "postgresql://u:p@h/d"
        out = sql._dsn_encrypt(plain)
        assert out == plain, (
            "with cryptography unavailable, _dsn_encrypt must pass the "
            "plaintext through unchanged (NOT return None or empty)"
        )
    finally:
        _restore_session_key(prev)


# ── End-to-end load contract ────────────────────────────────────────────

def test_load_path_treats_unreadable_dsn_as_skip(monkeypatch):
    """If _dsn_decrypt returns "" (rotated key, corrupted ciphertext),
    db_load_secrets must SKIP the POSTGRES_DSN entry rather than bind an
    empty DSN that would silently disable PG. Source-anchor + emitted
    slog event are the contract."""
    sql = _sql()
    src = open(sql.__file__, encoding="utf-8").read()
    # Anchor on the db_load_secrets function body (NOT the _SECRET_KEYS
    # registry, which also contains the string "POSTGRES_DSN"). Slice from
    # `def db_load_secrets` to the next top-level def.
    import re
    m = re.search(r"def db_load_secrets\b.*?(?=\ndef |\nasync def )",
                  src, re.DOTALL)
    assert m, "db_load_secrets must be defined"
    region = m.group(0)
    assert "_dsn_decrypt" in region, (
        "db_load_secrets must call _dsn_decrypt on the secrets_kv POSTGRES_DSN row"
    )
    assert "db_secrets_dsn_skipped" in region, (
        "unreadable DSN must emit db_secrets_dsn_skipped slog before continue"
    )
    assert "continue" in region, (
        "load path must `continue` on decrypt failure — never bind empty DSN"
    )
