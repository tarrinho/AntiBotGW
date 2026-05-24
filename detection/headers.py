# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
# detection/headers.py — Phase 4 extraction
# Header-based bot-signal functions extracted from proxy.py.
#
# HEADER_COMPLETENESS_ENABLED lives in config.py (Phase 1); imported here.
# The header-order fingerprint logic (_header_order_sig, _LIBRARY_HEADER_SIGS,
# _is_library_headers) is defined here — these were standalone functions in
# proxy.py at lines 418-437.

import hashlib
from config import (
    HEADER_COMPLETENESS_ENABLED,
    UA_PLATFORM_CHECK_ENABLED,
)


def _header_order_sig(request) -> str:
    names = ":".join(k.lower() for k in request.headers.keys() if k.lower() != "host")
    return hashlib.sha256(names[:300].encode()).hexdigest()[:12]


_LIBRARY_HEADER_SIGS: frozenset = frozenset({
    # python-requests 2.x (default: UA, Accept-Encoding, Accept, Connection)
    hashlib.sha256(b"user-agent:accept-encoding:accept:connection").hexdigest()[:12],
    hashlib.sha256(b"user-agent:accept-encoding:accept").hexdigest()[:12],
    # curl default (UA + Accept only)
    hashlib.sha256(b"user-agent:accept").hexdigest()[:12],
    # Go net/http (UA + Accept-Encoding)
    hashlib.sha256(b"user-agent:accept-encoding").hexdigest()[:12],
    # httpx async (Python) — Accept first, then UA
    hashlib.sha256(b"accept:accept-encoding:accept-language:user-agent:connection").hexdigest()[:12],
    hashlib.sha256(b"accept:accept-encoding:accept-language:user-agent").hexdigest()[:12],
})


def _is_library_headers(request) -> bool:
    """True when header order matches a known HTTP library signature."""
    return _header_order_sig(request) in _LIBRARY_HEADER_SIGS


__all__ = [
    "HEADER_COMPLETENESS_ENABLED",
    "UA_PLATFORM_CHECK_ENABLED",
    "_header_order_sig",
    "_LIBRARY_HEADER_SIGS",
    "_is_library_headers",
]
