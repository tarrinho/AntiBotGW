# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
integrations/jwt.py — JWT/Bearer signature validation (Tier B).

JWT_VALIDATE_PATHS: comma-sep fnmatch globs. Requests matching any glob
must carry `Authorization: Bearer <jwt>` whose HS256 signature verifies
against JWT_HMAC_SECRET. Optional issuer/audience claim enforcement.

Extracted from proxy.py as part of Phase 7 modular refactoring.

Depends on:
  config.py  — JWT_VALIDATE_PATHS, JWT_HMAC_SECRET, JWT_REQUIRED_ISSUER,
                JWT_REQUIRED_AUDIENCE, JWT_LEEWAY_SECS
  helpers.py — slog
"""

import base64 as _b64
import fnmatch as _fnmatch
import hashlib
import hmac
import json
import time as _t

from config import *   # noqa: F401,F403
from helpers import slog


def _jwt_b64url_decode(seg: str) -> bytes:
    """RFC 7515 — URL-safe base64 with padding stripped. Re-add padding
    before decoding so the stdlib accepts it."""
    pad = "=" * (-len(seg) % 4)
    return _b64.urlsafe_b64decode(seg + pad)


def _verify_jwt_hs256(token: str) -> tuple:
    """Pure-stdlib HS256 verify. Returns (ok: bool, error: str).
    Validates: signature, exp/nbf (with JWT_LEEWAY_SECS), iss, aud
    (when configured). Constant-time signature compare."""
    if not JWT_HMAC_SECRET:
        return False, "no-secret-configured"
    parts = token.split(".")
    if len(parts) != 3:
        return False, "malformed"
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_jwt_b64url_decode(header_b64))
        payload = json.loads(_jwt_b64url_decode(payload_b64))
        sig = _jwt_b64url_decode(sig_b64)
    except (ValueError, KeyError, json.JSONDecodeError):
        return False, "malformed"
    if header.get("alg") != "HS256" or header.get("typ", "JWT") != "JWT":
        return False, "alg-not-hs256"
    msg = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(JWT_HMAC_SECRET.encode("utf-8"), msg, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        return False, "bad-signature"
    n = int(_t.time())
    exp = payload.get("exp")
    if exp is not None and n > int(exp) + JWT_LEEWAY_SECS:
        return False, "expired"
    nbf = payload.get("nbf")
    if nbf is not None and n + JWT_LEEWAY_SECS < int(nbf):
        return False, "not-yet-valid"
    if JWT_REQUIRED_ISSUER and payload.get("iss") != JWT_REQUIRED_ISSUER:
        return False, "issuer-mismatch"
    if JWT_REQUIRED_AUDIENCE:
        aud = payload.get("aud")
        if isinstance(aud, list):
            if JWT_REQUIRED_AUDIENCE not in aud:
                return False, "audience-mismatch"
        elif aud != JWT_REQUIRED_AUDIENCE:
            return False, "audience-mismatch"
    return True, "ok"


def _jwt_required_for(path: str) -> bool:
    """True iff this path matches any glob in JWT_VALIDATE_PATHS."""
    if not JWT_VALIDATE_PATHS:
        return False
    return any(_fnmatch.fnmatchcase(path, g) for g in JWT_VALIDATE_PATHS)
