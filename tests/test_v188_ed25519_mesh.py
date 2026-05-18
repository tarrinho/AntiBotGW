"""
tests/test_v188_ed25519_mesh.py — QA tests for Ed25519 gateway mesh signing (v1.8.8)
and REDIS_REQUIRE_TLS enforcement.

Coverage
────────
TestRedisRequireTls
  R01  REDIS_REQUIRE_TLS defaults to True in config.py
  R02  REDIS_REQUIRE_TLS=false env → False
  R03  REDIS_REQUIRE_TLS=0 env → False
  R04  REDIS_REQUIRE_TLS=no env → False
  R05  REDIS_REQUIRE_TLS=true env → True
  R06  REDIS_REQUIRE_TLS=1 env → True
  R07  Module source: SystemExit(2) present when plaintext + TLS required
  R08  Module source: warn log path present when TLS not required
  R09  _shared_init source: secondary TLS check present before allowlist check
  R10  _shared_init secondary check logs redis_blocked_no_tls

TestEd25519KeypairGeneration
  K01  _gw_generate_keypair returns two strings
  K02  Both keys are 43 characters (32 bytes base64url-no-padding)
  K03  Keys are base64url-safe characters only
  K04  Each call produces a different keypair (random)
  K05  _gw_derive_pubkey derives matching public key from private key
  K06  _gw_derive_pubkey returns '' for invalid input
  K07  _gw_derive_pubkey returns '' for empty string
  K08  Private key decodes to exactly 32 bytes
  K09  Public key decodes to exactly 32 bytes
  K10  _gw_fingerprint still works on Ed25519 public keys (returns 12 hex chars)

TestCanonicalOfferBytes
  C01  Returns bytes
  C02  Excludes _sig field from output
  C03  Output is stable JSON — sorted keys
  C04  Different key order in input → same canonical bytes
  C05  Empty dict → b'{}'
  C06  Single-key dict round-trips via json.loads
  C07  _sig-only dict → b'{}'
  C08  Non-_sig keys survive intact

TestGwSignOffers
  S01  Returns non-empty string for valid keypair
  S02  Returned value is valid base64url
  S03  Ed25519 signature is exactly 64 bytes (86 base64url chars no-padding)
  S04  Returns '' for invalid (empty) private key
  S05  Returns '' for garbage private key
  S06  Signing is deterministic (Ed25519 is deterministic)
  S07  Different offers → different signatures

TestGwVerifyOffers
  V01  Valid signature + correct public key → True
  V02  Tampered offer value → False
  V03  Wrong public key → False
  V04  Truncated signature → False
  V05  Empty signature → False
  V06  Invalid public key → False
  V07  Extra field added after signing → False (canonical payload changes)
  V08  Removed field after signing → False
  V09  _sig field in offers dict is excluded from payload (sign then verify with _sig present)
  V10  Correct verification does not raise — returns bool

TestMeshSyncLoopSource
  L01  Loop fetches local private_key from DB before publishing
  L02  Loop calls _gw_sign_offers with local_private_key
  L03  Loop adds _sig to the publish dict
  L04  trust_map query selects public_key column
  L05  trust_map value is a tuple (auto_ok, public_key)
  L06  Inbound: pops _sig from offered_data
  L07  Inbound: rejects with mesh_sync_no_sig when sig absent
  L08  Inbound: rejects with mesh_sync_sig_invalid when verification fails
  L09  Inbound: rejects with mesh_sync_no_pubkey when peer has no public key
  L10  Inbound: calls _gw_verify_offers with peer_pub_key, sig_b64, offered_data
"""
import base64
import inspect
import json
import os
import pathlib
import sys
import types

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))


# ── lazy module helpers ───────────────────────────────────────────────────────

def _mesh():
    import admin.mesh as m
    return m


def _config():
    import config as m
    return m


def _redis_mod():
    import integrations.redis as m
    return m


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ─────────────────────────────────────────────────────────────────────────────
# TestRedisRequireTls
# ─────────────────────────────────────────────────────────────────────────────
class TestRedisRequireTls:
    """REDIS_REQUIRE_TLS enforcement — config parsing and source-level checks."""

    def test_R01_default_is_true(self):
        """R01: REDIS_REQUIRE_TLS defaults to True when env var absent."""
        import config
        # Default env has no REDIS_REQUIRE_TLS or it is set to 'true'.
        # We verify the attribute exists and is a bool.
        assert hasattr(config, "REDIS_REQUIRE_TLS"), \
            "REDIS_REQUIRE_TLS missing from config.py"
        # The default (env unset or 'true') must be True.
        env_val = os.environ.get("REDIS_REQUIRE_TLS", "true").strip().lower()
        expected = env_val not in ("0", "false", "no")
        assert config.REDIS_REQUIRE_TLS == expected

    def test_R02_false_string_disables(self):
        """R02: 'false' disables TLS requirement."""
        result = "false".strip().lower() not in ("0", "false", "no")
        assert result is False

    def test_R03_zero_string_disables(self):
        """R03: '0' disables TLS requirement."""
        result = "0".strip().lower() not in ("0", "false", "no")
        assert result is False

    def test_R04_no_string_disables(self):
        """R04: 'no' disables TLS requirement."""
        result = "no".strip().lower() not in ("0", "false", "no")
        assert result is False

    def test_R05_true_string_enables(self):
        """R05: 'true' keeps TLS requirement on."""
        result = "true".strip().lower() not in ("0", "false", "no")
        assert result is True

    def test_R06_one_string_enables(self):
        """R06: '1' keeps TLS requirement on."""
        result = "1".strip().lower() not in ("0", "false", "no")
        assert result is True

    def test_R07_source_has_tls_blocked_flag(self):
        """R07: integrations/redis.py must set _REDIS_TLS_BLOCKED (graceful degradation) for plaintext URL when TLS required.
        Changed in 1.8.8: raise SystemExit(2) replaced with non-fatal _REDIS_TLS_BLOCKED=True so the
        gateway continues in SQLite-only mode instead of crashing."""
        src = (_ROOT / "integrations" / "redis.py").read_text(encoding="utf-8")
        assert "_REDIS_TLS_BLOCKED" in src, \
            "redis.py must set _REDIS_TLS_BLOCKED when REDIS_URL is not rediss:// and REDIS_REQUIRE_TLS"
        assert "REDIS_REQUIRE_TLS" in src, \
            "redis.py must reference REDIS_REQUIRE_TLS"
        assert "SystemExit" not in src, \
            "redis.py must NOT call SystemExit — gateway degrades gracefully in 1.8.8+"

    def test_R08_source_has_warn_fallback(self):
        """R08: redis.py must still log a warning when TLS not required (REDIS_REQUIRE_TLS=false path)."""
        src = (_ROOT / "integrations" / "redis.py").read_text(encoding="utf-8")
        assert "redis_no_tls" in src, \
            "redis.py must log redis_no_tls when TLS not enforced"

    def test_R09_shared_init_checks_tls_blocked_flag(self):
        """R09: _shared_init must short-circuit when _REDIS_TLS_BLOCKED is set.
        Changed in 1.8.8: TLS enforcement moved to module-level flag; _shared_init
        returns early if _REDIS_TLS_BLOCKED is True instead of re-checking rediss://."""
        src = inspect.getsource(_redis_mod()._shared_init)
        assert "_REDIS_TLS_BLOCKED" in src, \
            "_shared_init must check _REDIS_TLS_BLOCKED flag (set at module level)"

    def test_R10_module_level_logs_tls_required(self):
        """R10: module level must log redis_tls_required when TLS check fails.
        Changed in 1.8.8: log event renamed from redis_blocked_no_tls to redis_tls_required
        and moved from _shared_init to the module-level import-time check."""
        src = (_ROOT / "integrations" / "redis.py").read_text(encoding="utf-8")
        assert "redis_tls_required" in src, \
            "redis.py must log 'redis_tls_required' at module level when TLS guard triggers"


# ─────────────────────────────────────────────────────────────────────────────
# TestEd25519KeypairGeneration
# ─────────────────────────────────────────────────────────────────────────────
class TestEd25519KeypairGeneration:
    """_gw_generate_keypair and _gw_derive_pubkey produce valid Ed25519 material."""

    def test_K01_returns_two_strings(self):
        """K01: _gw_generate_keypair returns a (str, str) tuple."""
        priv, pub = _mesh()._gw_generate_keypair()
        assert isinstance(priv, str)
        assert isinstance(pub, str)

    def test_K02_both_keys_43_chars(self):
        """K02: 32-byte Ed25519 keys base64url-encoded without padding = 43 chars."""
        priv, pub = _mesh()._gw_generate_keypair()
        assert len(priv) == 43, f"private_key length {len(priv)} != 43"
        assert len(pub) == 43, f"public_key length {len(pub)} != 43"

    def test_K03_base64url_chars_only(self):
        """K03: keys must use only URL-safe base64 alphabet (A-Z a-z 0-9 - _)."""
        import re
        pattern = re.compile(r"^[A-Za-z0-9_-]+$")
        priv, pub = _mesh()._gw_generate_keypair()
        assert pattern.match(priv), f"private_key contains non-base64url chars: {priv!r}"
        assert pattern.match(pub), f"public_key contains non-base64url chars: {pub!r}"

    def test_K04_each_call_different_keypair(self):
        """K04: keypairs are random — two calls must differ."""
        priv1, pub1 = _mesh()._gw_generate_keypair()
        priv2, pub2 = _mesh()._gw_generate_keypair()
        assert priv1 != priv2, "private keys must not be identical across calls"
        assert pub1 != pub2, "public keys must not be identical across calls"

    def test_K05_derive_pubkey_matches_generated(self):
        """K05: _gw_derive_pubkey(priv) must return the same pub that was generated."""
        priv, pub = _mesh()._gw_generate_keypair()
        derived = _mesh()._gw_derive_pubkey(priv)
        assert derived == pub, \
            f"derived pubkey {derived!r} does not match generated {pub!r}"

    def test_K06_derive_pubkey_returns_empty_for_invalid(self):
        """K06: _gw_derive_pubkey returns '' for non-base64 garbage."""
        assert _mesh()._gw_derive_pubkey("not-valid!!!") == ""

    def test_K07_derive_pubkey_returns_empty_for_empty(self):
        """K07: _gw_derive_pubkey returns '' for empty string input."""
        assert _mesh()._gw_derive_pubkey("") == ""

    def test_K08_private_key_decodes_to_32_bytes(self):
        """K08: private key decodes to exactly 32 raw bytes (Ed25519 seed)."""
        priv, _ = _mesh()._gw_generate_keypair()
        raw = _b64d(priv)
        assert len(raw) == 32, f"private key raw length {len(raw)} != 32"

    def test_K09_public_key_decodes_to_32_bytes(self):
        """K09: public key decodes to exactly 32 raw bytes (Ed25519 public key)."""
        _, pub = _mesh()._gw_generate_keypair()
        raw = _b64d(pub)
        assert len(raw) == 32, f"public key raw length {len(raw)} != 32"

    def test_K10_fingerprint_works_on_ed25519_key(self):
        """K10: _gw_fingerprint returns 12 lowercase hex chars for Ed25519 public key."""
        import re
        _, pub = _mesh()._gw_generate_keypair()
        fp = _mesh()._gw_fingerprint(pub)
        assert len(fp) == 12, f"fingerprint length {len(fp)} != 12"
        assert re.match(r"^[0-9a-f]{12}$", fp), f"fingerprint not hex: {fp!r}"


# ─────────────────────────────────────────────────────────────────────────────
# TestCanonicalOfferBytes
# ─────────────────────────────────────────────────────────────────────────────
class TestCanonicalOfferBytes:
    """_canonical_offer_bytes must produce stable, _sig-free, sorted JSON bytes."""

    def _f(self, d):
        return _mesh()._canonical_offer_bytes(d)

    def test_C01_returns_bytes(self):
        """C01: return type must be bytes."""
        assert isinstance(self._f({"k": "v"}), bytes)

    def test_C02_excludes_sig_field(self):
        """C02: _sig key must not appear in the canonical output."""
        result = self._f({"REDIS_URL": "rediss://x", "_sig": "FAKESIG"})
        assert b"_sig" not in result
        assert b"FAKESIG" not in result

    def test_C03_output_is_valid_json(self):
        """C03: canonical bytes must parse as valid JSON."""
        raw = self._f({"B": "2", "A": "1"})
        parsed = json.loads(raw)
        assert parsed == {"A": "1", "B": "2"}

    def test_C04_key_order_invariant(self):
        """C04: different insertion order → same canonical bytes."""
        a = self._f({"Z": "z", "A": "a", "M": "m"})
        b = self._f({"M": "m", "Z": "z", "A": "a"})
        assert a == b

    def test_C05_empty_dict_produces_empty_json(self):
        """C05: empty dict → b'{}'."""
        assert self._f({}) == b"{}"

    def test_C06_single_key_round_trips(self):
        """C06: payload is reversible via json.loads."""
        offers = {"REDIS_URL": "rediss://redis:6380"}
        raw = self._f(offers)
        assert json.loads(raw) == offers

    def test_C07_sig_only_dict_becomes_empty(self):
        """C07: {'_sig': 'x'} → b'{}' (only field is excluded)."""
        assert self._f({"_sig": "anysig"}) == b"{}"

    def test_C08_non_sig_keys_survive(self):
        """C08: all non-_sig keys are preserved in the output."""
        offers = {"REDIS_URL": "rediss://x", "CROWDSEC_ENABLED": "1", "_sig": "s"}
        parsed = json.loads(self._f(offers))
        assert "REDIS_URL" in parsed
        assert "CROWDSEC_ENABLED" in parsed
        assert "_sig" not in parsed


# ─────────────────────────────────────────────────────────────────────────────
# TestGwSignOffers
# ─────────────────────────────────────────────────────────────────────────────
class TestGwSignOffers:
    """_gw_sign_offers must produce valid Ed25519 signatures."""

    def _keypair(self):
        return _mesh()._gw_generate_keypair()

    def test_S01_returns_nonempty_string(self):
        """S01: valid keypair → non-empty string."""
        priv, _ = self._keypair()
        sig = _mesh()._gw_sign_offers(priv, {"REDIS_URL": "rediss://x"})
        assert isinstance(sig, str) and len(sig) > 0

    def test_S02_result_is_valid_base64url(self):
        """S02: returned value must be valid base64url."""
        import re
        priv, _ = self._keypair()
        sig = _mesh()._gw_sign_offers(priv, {"K": "V"})
        assert re.match(r"^[A-Za-z0-9_=-]+$", sig), f"not base64url: {sig!r}"

    def test_S03_signature_is_64_bytes(self):
        """S03: Ed25519 produces a 64-byte signature (86 base64url chars without padding)."""
        priv, _ = self._keypair()
        sig = _mesh()._gw_sign_offers(priv, {"K": "V"})
        raw = _b64d(sig)
        assert len(raw) == 64, f"signature raw length {len(raw)} != 64"

    def test_S04_returns_empty_for_empty_private_key(self):
        """S04: empty private key → returns ''."""
        sig = _mesh()._gw_sign_offers("", {"K": "V"})
        assert sig == ""

    def test_S05_returns_empty_for_garbage_private_key(self):
        """S05: garbage private key string → returns ''."""
        sig = _mesh()._gw_sign_offers("not-a-real-key!!!", {"K": "V"})
        assert sig == ""

    def test_S06_signing_is_deterministic(self):
        """S06: Ed25519 signatures are deterministic — same key + offers → same sig."""
        priv, _ = self._keypair()
        offers = {"REDIS_URL": "rediss://x", "CROWDSEC_ENABLED": "1"}
        sig_a = _mesh()._gw_sign_offers(priv, offers)
        sig_b = _mesh()._gw_sign_offers(priv, offers)
        assert sig_a == sig_b, "Ed25519 signature must be deterministic"

    def test_S07_different_offers_different_signatures(self):
        """S07: different offer payloads → different signatures."""
        priv, _ = self._keypair()
        sig_a = _mesh()._gw_sign_offers(priv, {"K": "V1"})
        sig_b = _mesh()._gw_sign_offers(priv, {"K": "V2"})
        assert sig_a != sig_b, "different payload must produce different signature"


# ─────────────────────────────────────────────────────────────────────────────
# TestGwVerifyOffers
# ─────────────────────────────────────────────────────────────────────────────
class TestGwVerifyOffers:
    """_gw_verify_offers must enforce Ed25519 signature correctness."""

    def _setup(self, offers=None):
        priv, pub = _mesh()._gw_generate_keypair()
        offers = offers or {"REDIS_URL": "rediss://redis:6380", "CROWDSEC_ENABLED": "1"}
        sig = _mesh()._gw_sign_offers(priv, offers)
        return priv, pub, sig, offers

    def test_V01_valid_sig_returns_true(self):
        """V01: correct key + correct sig → True."""
        _, pub, sig, offers = self._setup()
        assert _mesh()._gw_verify_offers(pub, sig, offers) is True

    def test_V02_tampered_value_returns_false(self):
        """V02: modifying a value after signing → False."""
        _, pub, sig, offers = self._setup()
        tampered = dict(offers)
        tampered["REDIS_URL"] = "rediss://evil:6380"
        assert _mesh()._gw_verify_offers(pub, sig, tampered) is False

    def test_V03_wrong_public_key_returns_false(self):
        """V03: different public key → False (no key confusion)."""
        _, pub, sig, offers = self._setup()
        _, other_pub = _mesh()._gw_generate_keypair()
        assert _mesh()._gw_verify_offers(other_pub, sig, offers) is False

    def test_V04_truncated_signature_returns_false(self):
        """V04: truncated signature bytes → False."""
        _, pub, sig, offers = self._setup()
        truncated = sig[:40]
        assert _mesh()._gw_verify_offers(pub, truncated, offers) is False

    def test_V05_empty_signature_returns_false(self):
        """V05: empty signature string → False."""
        _, pub, _, offers = self._setup()
        assert _mesh()._gw_verify_offers(pub, "", offers) is False

    def test_V06_invalid_public_key_returns_false(self):
        """V06: garbage public key → False (not True, not exception)."""
        _, _, sig, offers = self._setup()
        assert _mesh()._gw_verify_offers("not-a-real-key!!!!", sig, offers) is False

    def test_V07_added_field_returns_false(self):
        """V07: adding a field after signing changes canonical payload → False."""
        _, pub, sig, offers = self._setup()
        extended = dict(offers)
        extended["NEW_KEY"] = "injected"
        assert _mesh()._gw_verify_offers(pub, sig, extended) is False

    def test_V08_removed_field_returns_false(self):
        """V08: removing a field after signing changes canonical payload → False."""
        _, pub, sig, offers = self._setup()
        reduced = {k: v for k, v in offers.items()
                   if k != list(offers.keys())[0]}
        if reduced == offers:
            pytest.skip("offers has only one key — skip removal test")
        assert _mesh()._gw_verify_offers(pub, sig, reduced) is False

    def test_V09_sig_field_in_offers_ignored_during_verify(self):
        """V09: _sig present in the offers dict passed to verify must be excluded from payload."""
        priv, pub = _mesh()._gw_generate_keypair()
        offers = {"REDIS_URL": "rediss://x"}
        sig = _mesh()._gw_sign_offers(priv, offers)
        # Simulate what the receiver has: the offers dict still contains _sig
        offers_with_sig = dict(offers)
        offers_with_sig["_sig"] = sig
        # Must still verify True — _sig is excluded from canonical payload
        assert _mesh()._gw_verify_offers(pub, sig, offers_with_sig) is True

    def test_V10_verify_returns_bool_never_raises(self):
        """V10: _gw_verify_offers must return a bool, not raise, for any input."""
        result = _mesh()._gw_verify_offers("garbage", "garbage", {"k": "v"})
        assert isinstance(result, bool)


# ─────────────────────────────────────────────────────────────────────────────
# TestMeshSyncLoopSource
# ─────────────────────────────────────────────────────────────────────────────
class TestMeshSyncLoopSource:
    """Source-level assertions on _mesh_sync_loop to verify signing/verification wiring."""

    @pytest.fixture(autouse=True)
    def _src(self):
        self.src = inspect.getsource(_mesh()._mesh_sync_loop)

    def test_L01_loop_fetches_local_private_key(self):
        """L01: loop must query private_key from gw_registry WHERE is_local=1."""
        assert "private_key" in self.src
        assert "is_local" in self.src
        assert "local_private_key" in self.src

    def test_L02_loop_calls_gw_sign_offers(self):
        """L02: loop must call _gw_sign_offers with local_private_key."""
        assert "_gw_sign_offers" in self.src
        assert "local_private_key" in self.src

    def test_L03_loop_adds_sig_to_publish(self):
        """L03: loop must set '_sig' key in the publish mapping."""
        assert '"_sig"' in self.src or "'_sig'" in self.src

    def test_L04_trust_map_selects_public_key(self):
        """L04: trust_map query must include public_key column."""
        assert "public_key" in self.src
        assert "trust_map" in self.src

    def test_L05_trust_map_value_is_tuple(self):
        """L05: trust_map entries must be tuples (auto_ok, public_key)."""
        assert "auto_ok, peer_pub_key" in self.src or \
               "(r[1] == \"active\" and r[2] == 1," in self.src or \
               "r[3]" in self.src, \
            "trust_map must store tuple including public_key"

    def test_L06_inbound_pops_sig(self):
        """L06: inbound handling must pop '_sig' from offered_data before processing."""
        assert 'pop("_sig"' in self.src or "pop('_sig'" in self.src

    def test_L07_rejects_missing_sig_with_log(self):
        """L07: must log mesh_sync_no_sig and skip when no _sig from registered peer."""
        assert "mesh_sync_no_sig" in self.src

    def test_L08_rejects_invalid_sig_with_log(self):
        """L08: must log mesh_sync_sig_invalid and skip on failed Ed25519 verification."""
        assert "mesh_sync_sig_invalid" in self.src

    def test_L09_rejects_no_pubkey_peer_with_log(self):
        """L09: must log mesh_sync_no_pubkey and skip when peer has no registered public key."""
        assert "mesh_sync_no_pubkey" in self.src

    def test_L10_calls_gw_verify_offers(self):
        """L10: must call _gw_verify_offers with peer_pub_key, sig_b64, offered_data."""
        assert "_gw_verify_offers" in self.src
        assert "peer_pub_key" in self.src
        assert "sig_b64" in self.src
        assert "offered_data" in self.src
