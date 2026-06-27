# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
integrations/fingerproxy.py — fingerproxy sidecar H2 SETTINGS fingerprint integration (1.8.14).

fingerproxy (https://github.com/wi-fi-analyzer/fingerproxy or compatible) is a
TLS-terminating reverse proxy that captures HTTP/2 SETTINGS frames from the client
TLS handshake and injects them as request headers before forwarding to the gateway.

Two headers are consumed:
  X-H2-FP         — opaque fingerprint hash (hex) identifying the SETTINGS combination.
                    Matches against H2_FP_DENY_LIST for known-bad tool signatures.
                    → signal: h2-settings-deny (+25)

  X-H2-Settings   — parsed SETTINGS frame values as "type_id:value" pairs separated
                    by semicolons, e.g. "1:65536;3:1000;4:6291456;5:16384".
                    Compared against known browser profiles (Chrome/Firefox) using the
                    claimed User-Agent. A mismatch fires when the UA says "Chrome" but
                    the INITIAL_WINDOW_SIZE does not match Chrome's known value.
                    → signal: h2-settings-mismatch (+15, escalate-only)

Header name overrides (env vars — must match fingerproxy config):
  H2_FP_HEADER          (default: X-H2-FP)
  H2_SETTINGS_HEADER    (default: X-H2-Settings)

Enable knobs:
  H2_SETTINGS_FP_ENABLED       — master switch (default 0; enable when sidecar active)
  H2_FP_DENY_ENABLED           — check X-H2-FP against H2_FP_DENY_LIST (default 1)
  H2_SETTINGS_MISMATCH_ENABLED — UA-vs-SETTINGS consistency check (default 1)

Known H2 SETTINGS profiles (INITIAL_WINDOW_SIZE is the strongest differentiator):
  Chrome 100+  : type 4 (INITIAL_WINDOW_SIZE) = 6 291 456
  Firefox 117+ : type 4 (INITIAL_WINDOW_SIZE) = 131 072
  Safari 16+   : type 4 (INITIAL_WINDOW_SIZE) = 65 535 (overlaps curl — no signal)
  curl/libcurl : type 4 (INITIAL_WINDOW_SIZE) = 65 535
  python-httpx : type 4 (INITIAL_WINDOW_SIZE) = 65 535

Only Chrome and Firefox have INITIAL_WINDOW_SIZE values that are unambiguously
distinct from curl / library defaults, so UA mismatch detection is restricted to
those two browser families to keep the false-positive rate near zero.

docker-compose sidecar snippet (see FINGERPROXY_SETUP.md for full instructions):
  fingerproxy:
    image: sleeyax/fingerproxy:latest
    command:
      - --listen=:443
      - --target=http://antibot-gw:8080
      - --inject-h2-fp-header=X-H2-FP
      - --inject-h2-settings-header=X-H2-Settings
      - --cert=/certs/tls.crt
      - --key=/certs/tls.key
    ports: ["443:443"]
"""
from __future__ import annotations

import re as _re

from config import (
    H2_SETTINGS_FP_ENABLED, H2_FP_DENY_ENABLED, H2_SETTINGS_MISMATCH_ENABLED,
    H2_FP_HEADER, H2_SETTINGS_HEADER, H2_FP_DENY_LIST,
)

# ── H2 SETTINGS type identifiers (RFC 7540 §6.5) ─────────────────────────────
_H2_TYPE_HEADER_TABLE_SIZE      = 1
_H2_TYPE_ENABLE_PUSH            = 2
_H2_TYPE_MAX_CONCURRENT_STREAMS = 3
_H2_TYPE_INITIAL_WINDOW_SIZE    = 4
_H2_TYPE_MAX_FRAME_SIZE         = 5
_H2_TYPE_MAX_HEADER_LIST_SIZE   = 6

# ── Browser UA patterns ───────────────────────────────────────────────────────
_CHROME_UA_RE  = _re.compile(r"chrome/\d", _re.IGNORECASE)
_FIREFOX_UA_RE = _re.compile(r"firefox/\d", _re.IGNORECASE)
# Chromium-family (Edge, Brave) shares Chrome's SETTINGS — treat as Chrome
_CHROMIUM_UA_RE = _re.compile(r"(?:chrome/|edg/|brave/)\d", _re.IGNORECASE)

# ── Known browser INITIAL_WINDOW_SIZE values ──────────────────────────────────
# Only check INITIAL_WINDOW_SIZE — it's the strongest differentiator and has
# no false-positive overlap between Chrome/Firefox and curl-class tools.
_CHROME_INITIAL_WINDOW_SIZE  = 6_291_456   # 6 MB — Chrome 100+ sends this
_FIREFOX_INITIAL_WINDOW_SIZE = 131_072     # 128 KB — Firefox 117+ sends this

_SETTINGS_HEADER_RE = _re.compile(r"^[\d:;]+$")


def parse_h2_settings(header_value: str) -> dict[int, int]:
    """Parse "1:65536;3:1000;4:6291456;5:16384" → {1: 65536, 3: 1000, 4: 6291456, 5: 16384}.

    Returns an empty dict on any parse error so callers can treat it as
    "no settings data available" rather than an error.
    """
    result: dict[int, int] = {}
    if not header_value or not _SETTINGS_HEADER_RE.match(header_value):
        return result
    for part in header_value.split(";"):
        part = part.strip()
        if not part:
            continue
        if ":" not in part:
            return {}
        key_s, _, val_s = part.partition(":")
        try:
            result[int(key_s)] = int(val_s)
        except ValueError:
            return {}
    return result


def _ua_is_chrome(ua: str) -> bool:
    return bool(_CHROMIUM_UA_RE.search(ua))


def _ua_is_firefox(ua: str) -> bool:
    return bool(_FIREFOX_UA_RE.search(ua))


def h2fp_signals(request) -> list[str]:
    """Return triggered signal names for this request based on fingerproxy headers.

    Called from the per-request scoring path in proxy_handler.py.
    Returns an empty list when H2_SETTINGS_FP_ENABLED is False or headers absent.

    Signals returned:
      "h2-settings-deny"    — X-H2-FP value is in H2_FP_DENY_LIST
      "h2-settings-mismatch"— X-H2-Settings INITIAL_WINDOW_SIZE contradicts UA
    """
    if not H2_SETTINGS_FP_ENABLED:
        return []

    signals: list[str] = []
    headers = request.headers

    # ── Deny-list check ───────────────────────────────────────────────────────
    if H2_FP_DENY_ENABLED and H2_FP_DENY_LIST:
        fp = headers.get(H2_FP_HEADER, "").strip()
        if fp and fp in H2_FP_DENY_LIST:
            signals.append("h2-settings-deny")

    # ── UA-vs-SETTINGS consistency ────────────────────────────────────────────
    if H2_SETTINGS_MISMATCH_ENABLED:
        raw_settings = headers.get(H2_SETTINGS_HEADER, "").strip()
        if raw_settings:
            settings = parse_h2_settings(raw_settings)
            if settings:
                iws = settings.get(_H2_TYPE_INITIAL_WINDOW_SIZE)
                if iws is not None:
                    ua = headers.get("User-Agent", "")
                    if _ua_is_chrome(ua) and iws != _CHROME_INITIAL_WINDOW_SIZE:
                        signals.append("h2-settings-mismatch")
                    elif _ua_is_firefox(ua) and iws != _FIREFOX_INITIAL_WINDOW_SIZE:
                        signals.append("h2-settings-mismatch")

    return signals


def h2fp_stats() -> dict:
    """Return a metrics dict for /__metrics."""
    return {
        "enabled":                 H2_SETTINGS_FP_ENABLED,
        "deny_enabled":            H2_FP_DENY_ENABLED,
        "mismatch_enabled":        H2_SETTINGS_MISMATCH_ENABLED,
        "deny_list_size":          len(H2_FP_DENY_LIST),
        "fp_header":               H2_FP_HEADER,
        "settings_header":         H2_SETTINGS_HEADER,
    }
