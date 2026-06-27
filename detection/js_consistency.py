# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
detection/js_consistency.py — JS multi-vector consistency checker (1.8.14 Week 3).

Legitimate browsers generate a set of request headers that are internally
consistent across multiple "vectors" (User-Agent, Sec-Ch-Ua client hints,
Sec-Fetch-* fetch metadata).  A bot spoofing a browser UA typically copies
the UA string but fails to reproduce the full cross-vector consistency.

Three signals:

  js-cua-version-mismatch (+20, escalate-only)
    Chrome major version extracted from the UA string does not match the
    major version in the Sec-Ch-Ua header.  Example: UA "Chrome/120" but
    Sec-Ch-Ua says v="90".  Bots often hardcode an old Sec-Ch-Ua or copy
    it from a different version's captured traffic.

  js-mobile-hint-mismatch (+20)
    Sec-Ch-Ua-Mobile: ?1 (mobile) but UA string indicates a desktop
    platform (Windows / Macintosh / X11), or Sec-Ch-Ua-Mobile: ?0
    (non-mobile) but UA string says Android / iPhone / iPad / Mobile.
    Real Chrome always keeps these in sync; mismatches reveal a bot that
    set one but not the other.

  js-fetch-impossible (+30)
    A Sec-Fetch-Mode / Sec-Fetch-Dest combination that real browsers never
    produce.  Impossible combos arise when a bot sets some Sec-Fetch-*
    headers (to look more browser-like) but doesn't understand the W3C
    spec governing their allowed combinations (RFC 9218 / Fetch spec).

    Known impossible combos (source: Fetch Living Standard §5.4):
      mode=navigate  + dest=empty         — navigation always has a dest
      mode=navigate  + dest=worker        — navigate never loads workers
      mode=navigate  + dest=sharedworker  —   "
      mode=navigate  + dest=serviceworker —   "
      mode=cors      + dest=document      — CORS never navigates
      mode=no-cors   + dest=document      — no-cors never navigates
      mode=same-origin + dest=document    — same-origin fetch ≠ navigation

Enable knobs (all default 1):
  JS_CONSISTENCY_ENABLED            — master switch
  JS_CUA_VERSION_CHECK_ENABLED      — Sec-Ch-Ua version check
  JS_MOBILE_HINT_CHECK_ENABLED      — Sec-Ch-Ua-Mobile check
  JS_FETCH_IMPOSSIBLE_CHECK_ENABLED — impossible Sec-Fetch-* check

Called from core/proxy_handler.py soft-signals section (order 1, pre-escalation).
"""
from __future__ import annotations

import re as _re

from config import (
    JS_CONSISTENCY_ENABLED,
    JS_CUA_VERSION_CHECK_ENABLED,
    JS_MOBILE_HINT_CHECK_ENABLED,
    JS_FETCH_IMPOSSIBLE_CHECK_ENABLED,
)

# ── Regexes ───────────────────────────────────────────────────────────────────

# Chrome major version from UA: "Chrome/120.0.6099.109" → "120"
_CHROME_VER_UA_RE = _re.compile(r"Chrome/(\d+)\.", _re.IGNORECASE)

# Sec-Ch-Ua brand version: '"Google Chrome";v="120"' or '"Chromium";v="120"'
_CHROME_VER_CUA_RE = _re.compile(
    r'"(?:Google Chrome|Chromium)"\s*;\s*v\s*=\s*"(\d+)"', _re.IGNORECASE
)

# Mobile UA patterns
_UA_MOBILE_RE  = _re.compile(r"Android|iPhone|iPad|Mobile|CriOS|FxiOS", _re.IGNORECASE)
_UA_DESKTOP_RE = _re.compile(r"Windows NT|Macintosh|X11", _re.IGNORECASE)

# Impossible (mode, dest) pairs — browsers never produce these
_IMPOSSIBLE_FETCH_COMBOS: frozenset[tuple[str, str]] = frozenset({
    ("navigate",    "empty"),
    ("navigate",    "worker"),
    ("navigate",    "sharedworker"),
    ("navigate",    "serviceworker"),
    ("cors",        "document"),
    ("no-cors",     "document"),
    ("same-origin", "document"),
})


def js_consistency_signals(headers) -> list[str]:
    """Return triggered signal names for this request.

    ``headers`` is anything supporting ``.get(name, default)`` — compatible
    with both aiohttp CIMultiDictProxy and plain dicts (for tests).

    Returns an empty list when JS_CONSISTENCY_ENABLED is False or when no
    signals fire.  Safe to call on every request — all checks are O(1).
    """
    if not JS_CONSISTENCY_ENABLED:
        return []

    ua = headers.get("User-Agent", "") or ""
    signals: list[str] = []

    # ── 1. Sec-Ch-Ua version vs Chrome UA version ─────────────────────────────
    if JS_CUA_VERSION_CHECK_ENABLED:
        sec_ch_ua = headers.get("Sec-Ch-Ua", "") or ""
        if sec_ch_ua:
            ua_m = _CHROME_VER_UA_RE.search(ua)
            cua_m = _CHROME_VER_CUA_RE.search(sec_ch_ua)
            if ua_m and cua_m:
                ua_ver = int(ua_m.group(1))
                cua_ver = int(cua_m.group(1))
                if ua_ver != cua_ver:
                    signals.append("js-cua-version-mismatch")

    # ── 2. Sec-Ch-Ua-Mobile vs UA platform ───────────────────────────────────
    if JS_MOBILE_HINT_CHECK_ENABLED:
        mobile_hint = (headers.get("Sec-Ch-Ua-Mobile", "") or "").strip()
        if mobile_hint in ("?0", "?1"):
            hint_is_mobile = mobile_hint == "?1"
            ua_says_mobile  = bool(_UA_MOBILE_RE.search(ua))
            ua_says_desktop = bool(_UA_DESKTOP_RE.search(ua))
            if hint_is_mobile and ua_says_desktop:
                signals.append("js-mobile-hint-mismatch")
            elif not hint_is_mobile and ua_says_mobile:
                signals.append("js-mobile-hint-mismatch")

    # ── 3. Sec-Fetch-* impossible combination ────────────────────────────────
    if JS_FETCH_IMPOSSIBLE_CHECK_ENABLED:
        mode = (headers.get("Sec-Fetch-Mode", "") or "").lower().strip()
        dest = (headers.get("Sec-Fetch-Dest", "") or "").lower().strip()
        if mode and dest and (mode, dest) in _IMPOSSIBLE_FETCH_COMBOS:
            signals.append("js-fetch-impossible")

    return signals
