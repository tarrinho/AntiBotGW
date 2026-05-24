# admin/mesh.py — Phase 8: gateway registry + mesh-sync
# Extracted from proxy.py lines 11914–13539
import base64 as _b64  # noqa: F401
import time as _t       # noqa: F401
from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from helpers import slog, now  # noqa: F401
from admin.auth import _internal_authed, _request_username, _role_denied, _require_csrf  # noqa: F401
from integrations.redis import _redis  # noqa: F401 — lazy singleton, may be None
from aiohttp import web

# ── Gateway-mesh registry ─────────────────────────────────────────────────
_GW_ID_RE     = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
# 1.6.7 — operator-supplied external hostname (e.g. "gw-prod.example.com").
# Subset of RFC 1035 hostname grammar — labels of [a-z0-9-]{1,63} joined
# by dots, no trailing dot, no IP-literal forms. Empty is allowed (no
# domain published yet).
_GW_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$")
_GW_REGIONS   = ("eu-west", "eu-central", "us-east", "us-west", "ap-south",
                 "ap-northeast", "sa-east", "af-south", "me-central", "global")
_GW_ENVS      = ("production", "staging", "test")
_GW_STATUSES  = ("active", "inactive", "decommissioned")

# Cache of the local gateway's id. Resolved lazily — falls back to
# host.id() then "gw-local" if no row is yet stored.
_LOCAL_GW_ID: str = ""


def _gw_validate_id(gw_id: str) -> tuple[bool, str]:
    if not gw_id or not isinstance(gw_id, str):
        return False, "gw_id required"
    if len(gw_id) > 64:
        return False, "gw_id too long (max 64)"
    if not _GW_ID_RE.match(gw_id):
        return False, "gw_id must be lowercase alphanumeric + hyphens, 2-64 chars"
    return True, ""


def _gw_id_from_domain(domain: str) -> str:
    """1.6.7 — derive a valid gw_id from a hostname. Lowercase, replace
    every non-[a-z0-9-] char with '-', collapse runs of '-', trim leading
    /trailing hyphens, cap at 63 chars (the validator's upper bound).
    Returns "" if the input collapses to nothing valid (caller falls
    back to operator-supplied gw_id)."""
    if not domain:
        return ""
    s = re.sub(r"[^a-z0-9-]+", "-", domain.lower().strip())
    s = re.sub(r"-+", "-", s).strip("-")
    if not s:
        return ""
    # _GW_ID_RE caps at 63 chars (1 leading alphanumeric + up to 62 more).
    s = s[:63].rstrip("-")
    if not s or not s[0].isalnum():
        s = re.sub(r"^[^a-z0-9]+", "", s)
    return s if (s and _GW_ID_RE.match(s)) else ""


def _gw_generate_keypair() -> tuple[str, str]:
    """Mint a new Ed25519 keypair. Both halves are base64url-encoded without
    padding (43 chars each — 32 raw bytes) so they round-trip in JSON cleanly.
    The private key never leaves the local gateway's DB row.
    Raises RuntimeError on platforms where the cryptography package is absent
    (e.g. armv7 — single-instance deployments do not need mesh signing)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption)
    except ImportError:
        raise RuntimeError(
            "Ed25519 keypair generation requires the 'cryptography' package. "
            "Not available on this platform (armv7). Mesh signing unsupported.") from None
    priv      = Ed25519PrivateKey.generate()
    priv_raw  = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_raw   = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    private_key = _b64.urlsafe_b64encode(priv_raw).rstrip(b"=").decode("ascii")
    public_key  = _b64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode("ascii")
    return private_key, public_key


def _gw_derive_pubkey(private_key_b64: str) -> str:
    """Derive the Ed25519 public key from a base64url-encoded private key.
    Used to validate manually-supplied keypairs in the create endpoint.
    Returns '' when cryptography package is absent or key is invalid."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError:
        return ""
    try:
        priv_raw = _b64.urlsafe_b64decode(private_key_b64 + "=" * (-len(private_key_b64) % 4))
        priv     = Ed25519PrivateKey.from_private_bytes(priv_raw)
        pub_raw  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return _b64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode("ascii")
    except Exception:
        return ""


def _gw_wrap_private_key(raw_b64: str) -> str:
    """Encrypt an Ed25519 private key for at-rest storage.
    Returns 'fernet:<ciphertext>' using Fernet keyed from SESSION_KEY.
    Falls back to plaintext when the cryptography package is absent (armv7)."""
    if not raw_b64:
        return raw_b64
    try:
        from cryptography.fernet import Fernet as _Fernet
        import base64 as _b64x, hashlib as _hs
        fk = _b64x.urlsafe_b64encode(_hs.sha256(SESSION_KEY + b":mesh-key").digest())
        return "fernet:" + _Fernet(fk).encrypt(raw_b64.encode()).decode()
    except ImportError:
        return raw_b64  # cryptography absent — armv7 single-instance, no mesh signing


def _gw_unwrap_private_key(stored: str) -> str:
    """Decrypt a private key stored by _gw_wrap_private_key.
    Accepts legacy plaintext rows (no 'fernet:' prefix) for backward compat."""
    if not stored:
        return ""
    if not stored.startswith("fernet:"):
        return stored  # legacy plaintext row — still usable
    try:
        from cryptography.fernet import Fernet as _Fernet, InvalidToken
        import base64 as _b64x, hashlib as _hs
        fk = _b64x.urlsafe_b64encode(_hs.sha256(SESSION_KEY + b":mesh-key").digest())
        return _Fernet(fk).decrypt(stored[7:].encode()).decode()
    except Exception as _e:
        slog("gw_key_unwrap_failed", level="error", err=str(_e)[:80])
        return ""


def _gw_fingerprint(public_key: str, length: int = 12) -> str:
    """Short fingerprint for the dashboard. SHA256 of the public key,
    hex-encoded, truncated to `length` chars."""
    h = hashlib.sha256(public_key.encode("utf-8")).hexdigest()
    return h[:length]


# ── Mesh-offer signing (Ed25519) ───────────────────────────────────────────

def _canonical_offer_bytes(offers: dict) -> bytes:
    """Stable canonical serialisation of an offers dict for signing/verification.
    '_sig' is always excluded so the signature covers only payload keys."""
    clean = {k: v for k, v in offers.items() if k != "_sig"}
    return json.dumps(clean, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _gw_sign_offers(private_key_b64: str, offers: dict) -> str:
    """Sign the canonical offer payload with the local Ed25519 private key.
    Returns base64url-encoded 64-byte signature, or '' on failure or when
    the cryptography package is absent (armv7 single-instance deployments)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption)
    except ImportError:
        return ""
    try:
        pad      = "=" * (-len(private_key_b64) % 4)
        priv_raw = _b64.urlsafe_b64decode(private_key_b64 + pad)
        priv     = Ed25519PrivateKey.from_private_bytes(priv_raw)
        sig      = priv.sign(_canonical_offer_bytes(offers))
        return _b64.urlsafe_b64encode(sig).decode("ascii")
    except Exception as e:
        slog("mesh_sign_failed", level="error", err=str(e)[:80])
        return ""


def _gw_verify_offers(public_key_b64: str, sig_b64: str, offers: dict) -> bool:
    """Verify an inbound offer signature against the peer's Ed25519 public key.
    Returns False on any failure (wrong key format, invalid sig, missing package)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return False
    try:
        pub_raw = _b64.urlsafe_b64decode(public_key_b64 + "=" * (-len(public_key_b64) % 4))
        pub     = Ed25519PublicKey.from_public_bytes(pub_raw)
        sig     = _b64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        pub.verify(sig, _canonical_offer_bytes(offers))
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        slog("mesh_verify_failed", level="warn", err=str(e)[:80])
        return False


def _gw_local_id() -> str:
    """Lazy resolver for the LOCAL gateway's id. Falls back to the
    container hostname / 'gw-local' until the operator registers one."""
    global _LOCAL_GW_ID
    if _LOCAL_GW_ID:
        return _LOCAL_GW_ID
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute(
            "SELECT gw_id FROM gw_registry WHERE is_local = 1 LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            _LOCAL_GW_ID = row[0]
            return _LOCAL_GW_ID
    except Exception:
        pass
    # Fall back to hostname-derived id.
    try:
        hostname = os.uname().nodename or "gw-local"
    except Exception:
        hostname = "gw-local"
    safe = re.sub(r"[^a-z0-9-]", "-", hostname.lower())[:32] or "gw-local"
    _LOCAL_GW_ID = safe if _GW_ID_RE.match(safe) else "gw-local"
    return _LOCAL_GW_ID


def _gw_audit(action: str, gw_id: str, actor: str, **details) -> None:
    """Append-only audit record. Mirrors to Postgres via _pg_mirror_kv-
    style best-effort write. Never raises."""
    if db_queue is None:
        return
    payload = json.dumps(details, separators=(",", ":"), default=str) if details else ""
    try:
        db_queue.put_nowait((
            "gw_audit_add",
            (_t.time(), action, gw_id, actor, payload),
        ))
    except asyncio.QueueFull:
        pass
    slog("gw_registry_event", level="warn",
         action=action, gw_id=gw_id, actor=actor or "unknown")


def _gw_actor(request: web.Request) -> str:
    """Identify the operator — authenticated username preferred, IP as fallback."""
    from helpers import get_ip  # noqa: F401
    return _request_username(request) or get_ip(request) or "unknown"


def _gw_load_one(gw_id: str, include_private: bool = False) -> dict | None:
    """Fetch one row from gw_registry as a dict, or None if not found.
    Detail GETs may opt in to seeing the local row's private key by
    passing `include_private=True`."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM gw_registry WHERE gw_id = ?", (gw_id,)
        ).fetchone()
        conn.close()
    except Exception as e:
        slog("gw_registry_load_failed", level="error",
             err=str(e)[:200], gw_id=gw_id)
        return None
    if row is None:
        return None
    return _gw_row_to_dict(dict(row), include_private=include_private)


def _gw_row_to_dict(r: dict, include_private: bool = False) -> dict:
    """Normalise a SQLite row → JSON-serialisable dict. Adds the
    public-key fingerprint. The private_key is stripped UNLESS
    `include_private=True` AND the row is the local gateway — list
    views always pass False, single-row detail GETs pass True so the
    operator can reveal the local secret on demand."""
    out = dict(r)
    out["can_distribute"] = bool(out.get("can_distribute", 0))
    out["is_local"]       = bool(out.get("is_local", 0))
    out["auto_apply"]     = bool(out.get("auto_apply", 0))
    out["fingerprint"]    = _gw_fingerprint(out.get("public_key") or "")
    # Never leak another gateway's private key (defence-in-depth —
    # the column is also normally NULL for non-local rows). For the
    # local row, only return it on explicit detail fetches.
    if not (include_private and out["is_local"]):
        out["private_key"] = None
    else:
        # F-04: decrypt before returning to the operator.
        out["private_key"] = _gw_unwrap_private_key(out.get("private_key") or "")
    return out


def _gw_load_all() -> list[dict]:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM gw_registry ORDER BY created_ts ASC"
        ).fetchall()
        conn.close()
    except Exception as e:
        slog("gw_registry_load_failed", level="error", err=str(e)[:200])
        return []
    return [_gw_row_to_dict(dict(r)) for r in rows]


def _gw_load_distribution() -> list[tuple[str, str]]:
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT source_gw_id, target_gw_id FROM gw_distribution"
        ).fetchall()
        conn.close()
    except Exception:
        return []
    return [(r[0], r[1]) for r in rows]


# ── Endpoints ────────────────────────────────────────────────────────────
async def _gw_sync_state(gw_id: str, is_local: bool, can_distribute: bool,
                          last_seen_ts: float | None) -> dict:
    """1.6.7 — compute live Redis-presence + persisted last-seen status
    for a peer gateway. Surfaced as the `sync` column in the Settings →
    Gateway Registry table.

    state values:
      local       — this is the local gw (★)
      no-redis    — REDIS_URL not set or Redis unreachable
      disabled    — peer marked can_distribute=0 (we wouldn't sync to it
                    anyway; informational)
      live        — Redis has a fresh `mesh:offers:<gw_id>` hash for this
                    peer (publishing within the 60 s TTL window)
      stale       — last_seen_ts within the last hour but no current
                    Redis presence (peer paused or briefly offline)
      offline     — never seen, or last_seen > 1 h ago
    """
    if is_local:
        return {"state": "local", "live_offers": None, "age_secs": 0}
    if not REDIS_URL or _redis is None:
        return {"state": "no-redis", "live_offers": None, "age_secs": None}
    if not can_distribute:
        return {"state": "disabled", "live_offers": 0, "age_secs": None}
    n = _t.time()
    age = (n - last_seen_ts) if last_seen_ts else None
    # Live check — does Redis have an offer hash from this peer right now?
    live_count = 0
    try:
        key = f"{REDIS_NS}:{_MESH_REDIS_NS}:{gw_id}"
        live_count = await asyncio.wait_for(_redis.hlen(key),
                                             timeout=REDIS_TIMEOUT)
    except Exception:
        live_count = 0
    if live_count > 0:
        return {"state": "live", "live_offers": int(live_count),
                "age_secs": 0 if age is None else age}
    if age is not None and age < 3600:
        return {"state": "stale", "live_offers": 0, "age_secs": age}
    return {"state": "offline", "live_offers": 0, "age_secs": age}


async def gw_registry_list_endpoint(request: web.Request):
    """GET <NS>/secured/admin/gw-registry — list all gateways with live
    sync state per row (computed from Redis at request time)."""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    rows = _gw_load_all()
    local_id = _gw_local_id()
    redis_available = bool(REDIS_URL and _redis is not None)
    for r in rows:
        sync = await _gw_sync_state(
            r["gw_id"], bool(r.get("is_local")),
            bool(r.get("can_distribute")),
            r.get("last_seen_ts"))
        r["sync"] = sync
    return web.json_response(
        {"local_gw_id": local_id, "gateways": rows,
         "regions": list(_GW_REGIONS), "environments": list(_GW_ENVS),
         "statuses": list(_GW_STATUSES),
         "redis_available": redis_available},
        headers={"Cache-Control": "no-store"})


async def gw_registry_get_endpoint(request: web.Request):
    """GET <NS>/secured/admin/gw-registry/{gw_id}[?reveal=1]
    The local row's private_key is included only when the caller
    explicitly opts in via `?reveal=1`. The FE Settings dashboard's
    "Reveal" button is the only path that sets this flag — every
    other consumer (list, edit, sync-status) leaves it absent."""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    gw_id = request.match_info.get("gw_id", "").strip().lower()
    ok, msg = _gw_validate_id(gw_id)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    reveal = (request.query.get("reveal") or "").lower() in ("1", "true", "yes")
    row = _gw_load_one(gw_id, include_private=reveal)
    if row is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    if reveal and row.get("is_local"):
        _gw_audit("private_key_revealed", gw_id, _gw_actor(request))
    return web.json_response(row, headers={"Cache-Control": "no-store"})


@_require_csrf
async def gw_registry_create_endpoint(request: web.Request):
    """POST <NS>/secured/admin/gw-registry"""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    try:
        body = await asyncio.wait_for(request.content.read(64 * 1024),
                                       timeout=BODY_TIMEOUT)
        data = json.loads(body.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    gw_id  = (data.get("gw_id") or "").strip().lower()
    domain = (data.get("domain") or "").strip().lower()[:253]
    region = (data.get("region") or "").strip()
    env    = (data.get("environment") or "").strip()
    can_distribute = 1 if data.get("can_distribute", env == "production") else 0
    auto_keys = bool(data.get("auto_generate_keys", True))
    is_local  = 1 if data.get("is_local") else 0
    if domain and not _GW_DOMAIN_RE.match(domain):
        return web.json_response(
            {"error": "domain must be a valid hostname (a-z, 0-9, dots, hyphens)"},
            status=400, headers={"Cache-Control": "no-store"})
    # 1.6.7 — auto-derive gw_id from domain when caller didn't supply one.
    # Operators can still pass an explicit gw_id to override the derivation.
    if not gw_id and domain:
        gw_id = _gw_id_from_domain(domain)

    ok, msg = _gw_validate_id(gw_id)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    if region not in _GW_REGIONS:
        return web.json_response({"error": f"region must be one of {list(_GW_REGIONS)}"},
                                  status=400, headers={"Cache-Control": "no-store"})
    if env not in _GW_ENVS:
        return web.json_response({"error": f"environment must be one of {list(_GW_ENVS)}"},
                                  status=400, headers={"Cache-Control": "no-store"})
    if _gw_load_one(gw_id) is not None:
        return web.json_response({"error": "gw_id already exists"}, status=409,
                                  headers={"Cache-Control": "no-store"})

    private_key = ""
    if auto_keys:
        private_key, public_key = _gw_generate_keypair()
    else:
        # Manual entry — caller MUST provide both halves and they must match.
        private_key = (data.get("private_key") or "").strip()
        public_key  = (data.get("public_key") or "").strip()
        if not private_key or not public_key:
            return web.json_response(
                {"error": "manual key entry requires private_key + public_key"},
                status=400, headers={"Cache-Control": "no-store"})
        if _gw_derive_pubkey(private_key) != public_key:
            return web.json_response(
                {"error": "public_key does not match private_key"},
                status=400, headers={"Cache-Control": "no-store"})
    # Operators registering a remote peer should NOT have its private key
    # — the local gateway only holds private material for the LOCAL row.
    stored_private = _gw_wrap_private_key(private_key) if is_local else None
    n = _t.time()
    args = (gw_id, domain or None, region, env, "active", can_distribute,
            public_key, stored_private, n, None, None, n, n, is_local)
    if db_queue is not None:
        try:
            db_queue.put_nowait(("gw_registry_add", args))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    _gw_audit("gw_registered", gw_id, _gw_actor(request),
              domain=domain or None, region=region, environment=env,
              can_distribute=bool(can_distribute), is_local=bool(is_local))
    # Echo back the row including private_key ONLY when it was just
    # auto-generated AND this is the local gw — operator must copy it now.
    out = {
        "gw_id": gw_id, "domain": domain or None,
        "region": region, "environment": env,
        "status": "active", "can_distribute": bool(can_distribute),
        "public_key": public_key,
        "private_key": private_key if (is_local and auto_keys) else None,
        "fingerprint": _gw_fingerprint(public_key),
        "is_local": bool(is_local),
        "created_ts": n,
    }
    return web.json_response(out, status=201,
                              headers={"Cache-Control": "no-store"})


@_require_csrf
async def gw_registry_update_endpoint(request: web.Request):
    """PATCH <NS>/secured/admin/gw-registry/{gw_id}"""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    gw_id = request.match_info.get("gw_id", "").strip().lower()
    ok, msg = _gw_validate_id(gw_id)
    if not ok:
        return web.json_response({"error": msg}, status=400,
                                  headers={"Cache-Control": "no-store"})
    cur = _gw_load_one(gw_id)
    if cur is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    try:
        body = await asyncio.wait_for(request.content.read(8 * 1024),
                                       timeout=BODY_TIMEOUT)
        data = json.loads(body.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})

    updates: dict = {}
    if "domain" in data:
        d = (data.get("domain") or "").strip().lower()
        if d and not _GW_DOMAIN_RE.match(d):
            return web.json_response({"error": "invalid domain"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        updates["domain"] = d or None
    if "region" in data:
        if data["region"] not in _GW_REGIONS:
            return web.json_response({"error": "invalid region"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        updates["region"] = data["region"]
    if "environment" in data:
        if data["environment"] not in _GW_ENVS:
            return web.json_response({"error": "invalid environment"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        updates["environment"] = data["environment"]
    if "status" in data:
        if data["status"] not in _GW_STATUSES:
            return web.json_response({"error": "invalid status"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        updates["status"] = data["status"]
    if "can_distribute" in data:
        updates["can_distribute"] = 1 if data["can_distribute"] else 0
    if not updates:
        return web.json_response({"error": "no updates supplied"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    updates["updated_ts"] = _t.time()
    if db_queue is not None:
        try:
            db_queue.put_nowait(("gw_registry_update", (gw_id, updates)))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    _gw_audit("gw_updated", gw_id, _gw_actor(request), **updates)
    return web.json_response({"gw_id": gw_id, "updates": updates},
                              headers={"Cache-Control": "no-store"})


@_require_csrf
async def gw_registry_can_distribute_endpoint(request: web.Request):
    """PATCH <NS>/secured/admin/gw-registry/{gw_id}/can-distribute"""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    gw_id = request.match_info.get("gw_id", "").strip().lower()
    cur = _gw_load_one(gw_id)
    if cur is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    try:
        body = await asyncio.wait_for(request.content.read(1024),
                                       timeout=BODY_TIMEOUT)
        data = json.loads(body.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    new_val = 1 if data.get("can_distribute") else 0
    n = _t.time()
    if db_queue is not None:
        try:
            db_queue.put_nowait((
                "gw_registry_update",
                (gw_id, {"can_distribute": new_val, "updated_ts": n}),
            ))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    _gw_audit("can_distribute_toggled", gw_id, _gw_actor(request),
              can_distribute=bool(new_val))
    return web.json_response({"gw_id": gw_id, "can_distribute": bool(new_val)},
                              headers={"Cache-Control": "no-store"})


@_require_csrf
async def gw_registry_auto_apply_endpoint(request: web.Request):
    """PATCH <NS>/secured/admin/gw-registry/{gw_id}/auto-apply

    Toggle the trusted-peer flag. When ON, inbound mesh-sync offers from
    this peer skip the pending queue and apply straight to the live
    integration. Only meaningful for non-local rows; rejected on the
    local row to keep the audit story clean."""
    if denied := _role_denied(request, "admin"):  # AUTH4-03: admin-only write
        return denied
    gw_id = request.match_info.get("gw_id", "").strip().lower()
    cur = _gw_load_one(gw_id)
    if cur is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    if cur.get("is_local"):
        return web.json_response(
            {"error": "auto-apply only meaningful on remote peers"},
            status=400, headers={"Cache-Control": "no-store"})
    try:
        body = await asyncio.wait_for(request.content.read(1024),
                                       timeout=BODY_TIMEOUT)
        data = json.loads(body.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    new_val = 1 if data.get("auto_apply") else 0
    n = _t.time()
    if db_queue is not None:
        try:
            db_queue.put_nowait((
                "gw_registry_update",
                (gw_id, {"auto_apply": new_val, "updated_ts": n}),
            ))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    _gw_audit("auto_apply_toggled", gw_id, _gw_actor(request),
              auto_apply=bool(new_val))
    return web.json_response({"gw_id": gw_id, "auto_apply": bool(new_val)},
                              headers={"Cache-Control": "no-store"})


@_require_csrf
async def gw_registry_rotate_key_endpoint(request: web.Request):
    """POST <NS>/secured/admin/gw-registry/{gw_id}/rotate-key"""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    gw_id = request.match_info.get("gw_id", "").strip().lower()
    cur = _gw_load_one(gw_id)
    if cur is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    try:
        body = await asyncio.wait_for(request.content.read(8 * 1024),
                                       timeout=BODY_TIMEOUT)
        data = json.loads(body.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError):
        data = {}
    reason = (data.get("reason") or "").strip()[:500]
    private_key, public_key = _gw_generate_keypair()
    stored_private = _gw_wrap_private_key(private_key) if cur.get("is_local") else None
    n = _t.time()
    upd = {"public_key": public_key, "private_key": stored_private,
           "key_rotated_ts": n, "updated_ts": n}
    if db_queue is not None:
        try:
            db_queue.put_nowait(("gw_registry_update", (gw_id, upd)))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    _gw_audit("key_rotated", gw_id, _gw_actor(request),
              fingerprint=_gw_fingerprint(public_key),
              reason=reason or None)
    out = {"gw_id": gw_id, "public_key": public_key,
           "fingerprint": _gw_fingerprint(public_key),
           "key_rotated_ts": n}
    if cur.get("is_local"):
        # Operator must copy this once — do not return again.
        out["private_key"] = private_key
    return web.json_response(out, headers={"Cache-Control": "no-store"})


@_require_csrf
async def gw_registry_delete_endpoint(request: web.Request):
    """DELETE <NS>/secured/admin/gw-registry/{gw_id}"""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    gw_id = request.match_info.get("gw_id", "").strip().lower()
    cur = _gw_load_one(gw_id)
    if cur is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    if cur.get("is_local"):
        return web.json_response(
            {"error": "cannot delete the local gateway row"},
            status=400, headers={"Cache-Control": "no-store"})
    # Refuse if this is the last gateway in the registry — there must
    # always be at least one row (the local one) for the dashboard to
    # function.
    if len(_gw_load_all()) <= 1:
        return web.json_response(
            {"error": "cannot delete the last gateway in the registry"},
            status=400, headers={"Cache-Control": "no-store"})
    if db_queue is not None:
        try:
            db_queue.put_nowait(("gw_registry_delete", (gw_id,)))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    _gw_audit("gw_deleted", gw_id, _gw_actor(request))
    return web.json_response({"gw_id": gw_id, "deleted": True},
                              headers={"Cache-Control": "no-store"})


async def gw_registry_distribution_matrix_endpoint(request: web.Request):
    """GET <NS>/secured/admin/gw-registry/distribution/matrix"""
    if denied := _role_denied(request, "admin", "maintainer"):  # AUTH4-03
        return denied
    rows = _gw_load_all()
    pairs = _gw_load_distribution()
    by_pair = dict.fromkeys(pairs, True)
    return web.json_response({
        "gateways": [{"gw_id": r["gw_id"], "region": r["region"],
                       "environment": r["environment"],
                       "status": r["status"],
                       "can_distribute": r["can_distribute"]} for r in rows],
        "rules": [{"source": s, "target": t} for s, t in pairs],
        "matrix": {f"{s}|{t}": True for (s, t) in by_pair},
        "local_gw_id": _gw_local_id(),
    }, headers={"Cache-Control": "no-store"})


@_require_csrf
async def gw_registry_distribution_rules_endpoint(request: web.Request):
    """POST <NS>/secured/admin/gw-registry/distribution/rules
    Body: {"rules": [{"source": "gw-a", "target": "gw-b"}, ...]}
    Replaces the entire rule set in one transaction (idempotent)."""
    if denied := _role_denied(request, "admin", "maintainer"):  # AUTH4-03
        return denied
    try:
        body = await asyncio.wait_for(request.content.read(64 * 1024),
                                       timeout=BODY_TIMEOUT)
        data = json.loads(body.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    rules = data.get("rules") or []
    if not isinstance(rules, list):
        return web.json_response({"error": "rules must be a list"},
                                  status=400, headers={"Cache-Control": "no-store"})
    # Validate every (source, target) refers to a registered gateway.
    known = {r["gw_id"] for r in _gw_load_all()}
    cleaned: list[tuple[str, str]] = []
    for entry in rules:
        if not isinstance(entry, dict):
            return web.json_response({"error": "rules entries must be objects"},
                                      status=400, headers={"Cache-Control": "no-store"})
        s = (entry.get("source") or "").strip().lower()
        t = (entry.get("target") or "").strip().lower()
        if s == t:
            return web.json_response({"error": f"self-loop rejected: {s}"},
                                      status=400, headers={"Cache-Control": "no-store"})
        if s not in known or t not in known:
            return web.json_response(
                {"error": f"unknown gw in rule: source={s} target={t}"},
                status=400, headers={"Cache-Control": "no-store"})
        cleaned.append((s, t))
    if db_queue is not None:
        try:
            db_queue.put_nowait(("gw_distribution_replace", (cleaned, _t.time())))
        except asyncio.QueueFull:
            return web.json_response({"error": "db queue full"}, status=503,
                                      headers={"Cache-Control": "no-store"})
    _gw_audit("distribution_rules_updated", "*", _gw_actor(request),
              count=len(cleaned))
    return web.json_response({"rules": [{"source": s, "target": t}
                                         for s, t in cleaned]},
                              headers={"Cache-Control": "no-store"})


async def gw_registry_audit_log_endpoint(request: web.Request):
    """GET <NS>/secured/admin/gw-registry/audit-log
    Query: ?limit=50&offset=0&action=...&gw_id=...&since=<epoch>&until=<epoch>
    """
    # AUTH4-03: audit log is read-only but sensitive — restrict to admin/maintainer
    from admin.auth import _role_denied
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    try:
        limit  = max(1,  min(int(request.query.get("limit",  "50")),  500))
        offset = max(0,  min(int(request.query.get("offset", "0")), 100000))
    except ValueError:
        return web.json_response({"error": "limit/offset must be ints"},
                                  status=400, headers={"Cache-Control": "no-store"})
    action = (request.query.get("action") or "").strip()
    gw_id  = (request.query.get("gw_id") or "").strip().lower()
    since  = request.query.get("since")
    until  = request.query.get("until")
    where, args = ["1=1"], []
    if action:
        where.append("action = ?"); args.append(action)
    if gw_id:
        where.append("gw_id = ?"); args.append(gw_id)
    try:
        if since:
            where.append("ts >= ?"); args.append(float(since))
        if until:
            where.append("ts <= ?"); args.append(float(until))
    except ValueError:
        return web.json_response({"error": "since/until must be epoch floats"},
                                  status=400, headers={"Cache-Control": "no-store"})
    # B608 false-positive: the WHERE fragments are hard-coded literal
    # template strings (e.g. "action = ?") joined with AND; operator-
    # supplied values are bound exclusively via `?` placeholders in
    # `args`. No user-controlled text reaches the SQL string.
    sql = (f"SELECT id, ts, action, gw_id, actor, details "       # nosec B608
           f"FROM gw_audit WHERE {' AND '.join(where)} "
           f"ORDER BY ts DESC LIMIT ? OFFSET ?")
    args.extend([limit, offset])
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, args).fetchall()
        total = conn.execute("SELECT COUNT(*) FROM gw_audit").fetchone()[0]
        conn.close()
    except Exception as e:
        slog("gw_audit_query_failed", level="error", err=str(e)[:200])
        return web.json_response({"error": "audit query failed"}, status=500,
                                  headers={"Cache-Control": "no-store"})
    return web.json_response({
        "total":   total,
        "limit":   limit,
        "offset":  offset,
        "entries": [dict(r) for r in rows],
    }, headers={"Cache-Control": "no-store"})


async def gw_registry_sync_status_endpoint(request: web.Request):
    """GET <NS>/secured/admin/gw-registry/{gw_id}/sync-status — synthetic
    health view: how recently the gateway was seen + active distribution
    pairs sourced from / targeted at it."""
    # AUTH4-03: sync-status reveals topology — restrict to admin/maintainer
    from admin.auth import _role_denied
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    gw_id = request.match_info.get("gw_id", "").strip().lower()
    cur = _gw_load_one(gw_id)
    if cur is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    pairs = _gw_load_distribution()
    out_targets = sorted({t for s, t in pairs if s == gw_id})
    in_sources  = sorted({s for s, t in pairs if t == gw_id})
    n = _t.time()
    last_seen = cur.get("last_seen_ts") or 0.0
    age_s = (n - last_seen) if last_seen else None
    if cur.get("is_local"):
        # Local gateway is always live (we are it).
        health = "live"
    elif age_s is None:
        health = "unknown"
    elif age_s < 90:
        health = "live"
    elif age_s < 600:
        health = "stale"
    else:
        health = "lost"
    return web.json_response({
        "gw_id": gw_id, "health": health, "last_seen_ts": last_seen,
        "age_secs": age_s, "is_local": cur.get("is_local"),
        "distribution_targets": out_targets,
        "distribution_sources": in_sources,
        "can_distribute": cur.get("can_distribute"),
    }, headers={"Cache-Control": "no-store"})


# ── 1.6.7: mesh-sync of integration secrets / variables ────────────────
_MESH_SYNC_ELIGIBLE_KEYS = (
    # Integration secrets (live in `secrets_kv` + module globals).
    "TURNSTILE_SITEKEY", "TURNSTILE_SECRET",
    "ABUSEIPDB_KEY",
    "CROWDSEC_LAPI_URL", "CROWDSEC_LAPI_KEY",
    "MAXMIND_LICENSE_KEY",
    # Integration on/off knobs (config_kv) — sharing the toggle state
    # with peers lets a fleet-wide "all integrations active" deploy be
    # achieved by enabling once and confirming on each peer.
    "TURNSTILE_ENABLED", "ABUSEIPDB_ENABLED",
    "CROWDSEC_ENABLED", "MAXMIND_ENABLED",
    "ANUBIS_ENABLED",   "BOTD_ENABLED",
)
# F-05: secrets that must NOT be auto-published to the Redis mesh hash.
# These contain API keys / tokens — Redis is an untrusted channel.
# They can still be enabled for mesh sync in the DB/pending queue, but
# they must be applied manually via the admin UI, not via Redis broadcast.
_MESH_REDIS_EXCLUDED_KEYS = frozenset({
    "TURNSTILE_SECRET",
    "ABUSEIPDB_KEY",
    "CROWDSEC_LAPI_KEY",
    "MAXMIND_LICENSE_KEY",
})
_MESH_REDIS_NS = "mesh:offers"          # full key: appsecgw:mesh:offers:<gw_id>
_MESH_OFFER_TTL_S = 60
_MESH_LOOP_INTERVAL_S = 30
_MESH_SYNC_ENABLED_KEY = "_MESH_SYNC_ENABLED_KEYS"   # config_kv slot
_mesh_sync_task = None


def _mesh_sync_enabled_set() -> set[str]:
    """Read the live enabled-keys set from config_kv. JSON list → set."""
    import admin.mesh as _self_mod
    raw = getattr(_self_mod, _MESH_SYNC_ENABLED_KEY, None)
    if raw is None:
        # Fall back to proxy globals during transition
        try:
            raw = getattr(_proxy, _MESH_SYNC_ENABLED_KEY, None)
        except Exception:
            raw = None
    if raw is None:
        return set()
    if isinstance(raw, set):
        return set(raw)
    if isinstance(raw, list):
        return {str(k) for k in raw if isinstance(k, str)}
    return set()


def _mesh_sync_set_enabled(key: str, enabled: bool) -> set[str]:
    """Mutate the in-memory set + persist to config_kv (mirrored to
    Postgres via the existing dual-write path). Returns the new set."""
    import admin.mesh as _self_mod
    cur = _mesh_sync_enabled_set()
    if enabled:
        cur.add(key)
    else:
        cur.discard(key)
    setattr(_self_mod, _MESH_SYNC_ENABLED_KEY, sorted(cur))
    if db_queue is not None:
        try:
            db_queue.put_nowait((
                "set_config",
                (_MESH_SYNC_ENABLED_KEY, json.dumps(sorted(cur)), _t.time()),
            ))
        except asyncio.QueueFull:
            pass
    return cur


def _mesh_sync_get_value(key: str) -> str:
    """Return the live value of a syncable key. Pulls from proxy globals
    (works for both secret and config knobs)."""
    try:
        v = getattr(_proxy, key, None)
    except Exception:
        v = None
    if v is None:
        return ""
    if isinstance(v, bool):
        return "1" if v else "0"
    return str(v)


def _mesh_sync_apply_value(key: str, value: str) -> None:
    """Apply an inbound value to the live store. Secrets land in
    `secrets_kv` (which the secrets loader re-derives from); booleans
    flip the matching config knob. Audit happens in the calling
    confirm endpoint.

    Uses setattr on the proxy module instead of globals() so the
    assignment reaches the module-level variables in proxy.py that
    the running application reads."""
    import sys as _sys
    _proxy = _sys.modules.get('proxy')
    if key in _SECRET_KEYS:
        global_name, _env = _SECRET_KEYS[key]
        if _proxy is not None:
            setattr(_proxy, global_name, value)
        if db_queue is not None:
            try:
                db_queue.put_nowait(("set_secret", (key, value, _t.time())))
            except asyncio.QueueFull:
                pass
        # Re-derive `_TURNSTILE_CONFIGURED` etc. by calling the loader.
        try:
            db_load_secrets()
        except Exception:
            pass
        return
    # Config knob — coerce to bool/int via the existing parser if registered.
    spec = _HOT_RELOAD_KNOBS.get(key)
    if spec is not None:
        parser, validator = spec
        try:
            v = parser(value)
            if validator is None or validator(v):
                if _proxy is not None:
                    setattr(_proxy, key, v)
                if db_queue is not None:
                    try:
                        db_queue.put_nowait((
                            "set_config", (key, json.dumps(v), _t.time())))
                    except asyncio.QueueFull:
                        pass
        except (ValueError, TypeError):
            pass


def _mesh_load_pending(status: str = "pending") -> list[dict]:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, received_ts, source_gw_id, key_name, value, "
            "status, confirmed_ts FROM gw_sync_pending "
            "WHERE status = ? ORDER BY received_ts DESC",
            (status,)).fetchall()
        conn.close()
    except Exception:
        return []
    # Mask the value — operator clicks Apply to actually use it; we only
    # show its length + a 4-char prefix for identification.
    out = []
    for r in rows:
        d = dict(r)
        v = d.get("value") or ""
        d["value_preview"] = (v[:4] + "…") if v else ""
        d["value_length"]  = len(v)
        del d["value"]
        out.append(d)
    return out


# ── Mesh-sync endpoints ─────────────────────────────────────────────
async def mesh_sync_state_endpoint(request: web.Request):
    """GET <NS>/secured/admin/mesh-sync — current state."""
    enabled = sorted(_mesh_sync_enabled_set())
    pending = _mesh_load_pending("pending")
    return web.json_response({
        "eligible_keys": list(_MESH_SYNC_ELIGIBLE_KEYS),
        "enabled_keys":  enabled,
        "pending":       pending,
        "redis_available": bool(REDIS_URL and _redis is not None),
        "local_gw_id":   _gw_local_id(),
    }, headers={"Cache-Control": "no-store"})


@_require_csrf
async def mesh_sync_toggle_endpoint(request: web.Request):
    """POST <NS>/secured/admin/mesh-sync/{key}/toggle — body {enabled}."""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    key = request.match_info.get("key", "").strip()
    if key not in _MESH_SYNC_ELIGIBLE_KEYS:
        return web.json_response({"error": "key not eligible for mesh sync"},
                                  status=400, headers={"Cache-Control": "no-store"})
    try:
        body = await asyncio.wait_for(request.content.read(1024),
                                       timeout=BODY_TIMEOUT)
        data = json.loads(body.decode("utf-8") or "{}")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError) as e:
        return web.json_response({"error": f"bad request: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    enabled = bool(data.get("enabled"))
    cur = _mesh_sync_set_enabled(key, enabled)
    _gw_audit("mesh_sync_toggled", key, _request_username(request),
              enabled=enabled)
    return web.json_response(
        {"key": key, "enabled": enabled, "all_enabled": sorted(cur)},
        headers={"Cache-Control": "no-store"})


@_require_csrf
async def mesh_sync_confirm_endpoint(request: web.Request):
    """POST <NS>/secured/admin/mesh-sync/pending/{id}/confirm — apply
    a pending offer's value to the live integration."""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    try:
        pid = int(request.match_info.get("id", "0"))
    except ValueError:
        return web.json_response({"error": "id must be an integer"},
                                  status=400, headers={"Cache-Control": "no-store"})
    if pid <= 0:
        return web.json_response({"error": "bad id"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    # Fetch the row so we can apply the actual value (not echoed in the
    # listing endpoint to avoid casual leaks).
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, source_gw_id, key_name, value, status "
            "FROM gw_sync_pending WHERE id = ?", (pid,)).fetchone()
        conn.close()
    except Exception:
        row = None
    if row is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    if row["status"] != "pending":
        return web.json_response({"error": f"already {row['status']}"},
                                  status=409, headers={"Cache-Control": "no-store"})
    if row["key_name"] not in _MESH_SYNC_ELIGIBLE_KEYS:
        return web.json_response({"error": "key not eligible (allowlist drift)"},
                                  status=400, headers={"Cache-Control": "no-store"})
    _mesh_sync_apply_value(row["key_name"], row["value"])
    if db_queue is not None:
        try:
            db_queue.put_nowait((
                "mesh_sync_status",
                (pid, "confirmed", _t.time()),
            ))
        except asyncio.QueueFull:
            pass
    _gw_audit("mesh_sync_confirmed", row["key_name"],
              _request_username(request),
              source_gw=row["source_gw_id"], pending_id=pid)
    return web.json_response({"id": pid, "status": "confirmed",
                               "key": row["key_name"]},
                              headers={"Cache-Control": "no-store"})


@_require_csrf
async def mesh_sync_reject_endpoint(request: web.Request):
    """POST <NS>/secured/admin/mesh-sync/pending/{id}/reject"""
    if denied := _role_denied(request, "admin", "maintainer"):
        return denied
    try:
        pid = int(request.match_info.get("id", "0"))
    except ValueError:
        return web.json_response({"error": "id must be an integer"},
                                  status=400, headers={"Cache-Control": "no-store"})
    if pid <= 0:
        return web.json_response({"error": "bad id"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT key_name, source_gw_id, status FROM gw_sync_pending "
            "WHERE id = ?", (pid,)).fetchone()
        conn.close()
    except Exception:
        row = None
    if row is None:
        return web.json_response({"error": "not found"}, status=404,
                                  headers={"Cache-Control": "no-store"})
    if row["status"] != "pending":
        return web.json_response({"error": f"already {row['status']}"},
                                  status=409, headers={"Cache-Control": "no-store"})
    if db_queue is not None:
        try:
            db_queue.put_nowait((
                "mesh_sync_status",
                (pid, "rejected", _t.time()),
            ))
        except asyncio.QueueFull:
            pass
    _gw_audit("mesh_sync_rejected", row["key_name"],
              _request_username(request),
              source_gw=row["source_gw_id"], pending_id=pid)
    return web.json_response({"id": pid, "status": "rejected",
                               "key": row["key_name"]},
                              headers={"Cache-Control": "no-store"})


# ── Background loop: publish + scrape via Redis ─────────────────────
async def _mesh_sync_loop():
    """Every 30s when REDIS_URL is set:
      1. Publish enabled-key values to `mesh:offers:<gw_id>` (TTL 60s).
      2. Snapshot peer trust state from gw_registry (one query/cycle).
      3. Scan peer hashes; for each:
           - queue gw_registry_discover (INSERT OR IGNORE + bump last_seen)
           - per offered eligible key:
               - skip if local value is already set
               - if peer is trusted (status=active + auto_apply=1):
                     apply directly + audit
               - else: queue mesh_sync_pending_upsert (handler dedupes via
                     ON CONFLICT WHERE value differs)
    All Redis/DB I/O is best-effort."""
    while True:
        try:
            if _redis is not None:
                src = _gw_local_id() or "gw-local"
                # 0. fetch local private key for signing offers (one DB
                # round-trip per cycle; cached in local var).
                local_private_key = ""
                try:
                    _lconn = sqlite3.connect(DB_PATH)
                    _lrow  = _lconn.execute(
                        "SELECT private_key FROM gw_registry WHERE is_local=1 LIMIT 1"
                    ).fetchone()
                    _lconn.close()
                    if _lrow and _lrow[0]:
                        local_private_key = _gw_unwrap_private_key(_lrow[0])
                except Exception:
                    pass
                # 1. publish own offers, Ed25519-signed.
                # F-05: exclude API secrets from the Redis hash — Redis is
                # not an encrypted channel. Secrets must be applied manually.
                offers = {k: _mesh_sync_get_value(k)
                          for k in _mesh_sync_enabled_set()
                          if _mesh_sync_get_value(k)
                          and k not in _MESH_REDIS_EXCLUDED_KEYS}
                key = f"{REDIS_NS}:{_MESH_REDIS_NS}:{src}"
                if offers:
                    publish = dict(offers)
                    if local_private_key:
                        sig = _gw_sign_offers(local_private_key, offers)
                        if sig:
                            publish["_sig"] = sig
                    try:
                        await asyncio.wait_for(_redis.delete(key),
                                                timeout=REDIS_TIMEOUT)
                        await asyncio.wait_for(
                            _redis.hset(key, mapping=publish),
                            timeout=REDIS_TIMEOUT)
                        await asyncio.wait_for(
                            _redis.expire(key, _MESH_OFFER_TTL_S),
                            timeout=REDIS_TIMEOUT)
                    except Exception as e:
                        slog("mesh_sync_publish_failed", level="warn",
                             err=str(e)[:120])
                # 2. snapshot peer trust state once per cycle. Includes
                # public_key so we can verify Ed25519 signatures inbound.
                # peer_gw -> (auto_apply: bool, public_key: str)
                trust_map: dict = {}
                try:
                    conn = sqlite3.connect(DB_PATH)
                    for r in conn.execute(
                            "SELECT gw_id, status, auto_apply, public_key "
                            "FROM gw_registry WHERE is_local = 0"):
                        trust_map[r[0]] = (r[1] == "active" and r[2] == 1,
                                           r[3] or "")
                    conn.close()
                except Exception:
                    pass
                # 3. scrape peers
                try:
                    pattern = f"{REDIS_NS}:{_MESH_REDIS_NS}:*"
                    peer_keys = []
                    async for k in _redis.scan_iter(match=pattern, count=100):
                        peer_keys.append(k)
                except Exception as e:
                    slog("mesh_sync_scan_failed", level="warn",
                         err=str(e)[:120])
                    peer_keys = []
                now_ts = _t.time()
                for pk in peer_keys:
                    peer_gw = pk.rsplit(":", 1)[-1]
                    if peer_gw == src:
                        continue
                    try:
                        offered = await asyncio.wait_for(_redis.hgetall(pk),
                                                          timeout=REDIS_TIMEOUT)
                    except Exception:
                        continue
                    # Auto-discover: insert placeholder if missing + bump
                    # last_seen_ts. Idempotent — handler does INSERT OR
                    # IGNORE then UPDATE.
                    if db_queue is not None:
                        try:
                            db_queue.put_nowait((
                                "gw_registry_discover", (peer_gw, now_ts),
                            ))
                        except asyncio.QueueFull:
                            pass
                    auto_ok, peer_pub_key = trust_map.get(peer_gw, (False, ""))
                    # Extract Ed25519 signature from the offer hash. The
                    # '_sig' field is not part of the payload — pop it before
                    # iterating so it never reaches _MESH_SYNC_ELIGIBLE_KEYS.
                    offered_data = dict(offered or {})
                    sig_b64 = offered_data.pop("_sig", "")
                    if peer_pub_key:
                        # Peer is registered — verify the signature.
                        # Fail-closed: reject the entire offer batch on any
                        # verification failure (bad sig, old non-Ed25519 key,
                        # missing sig). The peer must rotate to Ed25519 if
                        # their public key predates this release.
                        if not sig_b64:
                            slog("mesh_sync_no_sig", level="warn",
                                 peer_gw=peer_gw,
                                 msg="Offer rejected — no Ed25519 signature. "
                                     "Peer must rotate key to Ed25519.")
                            continue
                        if not _gw_verify_offers(peer_pub_key, sig_b64, offered_data):
                            slog("mesh_sync_sig_invalid", level="warn",
                                 peer_gw=peer_gw,
                                 msg="Offer rejected — Ed25519 signature invalid.")
                            continue
                    else:
                        # Auto-discovered peer (no public_key yet) — cannot
                        # verify, skip until operator registers their key.
                        slog("mesh_sync_no_pubkey", level="warn",
                             peer_gw=peer_gw,
                             msg="Offer skipped — peer has no registered public key.")
                        continue
                    for kname, kval in offered_data.items():
                        if kname not in _MESH_SYNC_ELIGIBLE_KEYS:
                            continue
                        if not kval:
                            continue
                        if _mesh_sync_get_value(kname):
                            continue
                        if auto_ok:
                            # Trusted peer — apply directly. No pending.
                            try:
                                _mesh_sync_apply_value(kname, kval)
                            except Exception as e:
                                slog("mesh_sync_auto_apply_failed",
                                     level="error",
                                     source_gw=peer_gw, key=kname,
                                     err=str(e)[:120])
                                continue
                            slog("mesh_sync_auto_applied", level="warn",
                                 source_gw=peer_gw, key=kname,
                                 value_length=len(kval))
                            _gw_audit("mesh_sync_auto_applied", kname,
                                      "system", source_gw=peer_gw)
                            continue
                        # Untrusted peer — UPSERT pending. Dedup happens
                        # in the handler via ON CONFLICT WHERE value differs.
                        if db_queue is not None:
                            try:
                                db_queue.put_nowait((
                                    "mesh_sync_pending_upsert",
                                    (now_ts, peer_gw, kname, kval),
                                ))
                            except asyncio.QueueFull:
                                pass
                        slog("mesh_sync_received", level="warn",
                             source_gw=peer_gw, key=kname,
                             value_length=len(kval))
        except asyncio.CancelledError:
            return
        except Exception as e:
            slog("mesh_sync_loop_error", level="error", err=str(e)[:200])
        try:
            await asyncio.sleep(_MESH_LOOP_INTERVAL_S)
        except asyncio.CancelledError:
            return
