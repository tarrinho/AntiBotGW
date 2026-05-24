# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
helpers.py — Pure utility functions used across the proxy.
Extracted from proxy.py as part of Phase 1 modular refactoring.

Dependency rule: imports from config.py and state.py only.
"""

import json
import re
import secrets
import time

import ipaddress as _ipaddress

from config import (
    TRUST_XFF,
    TRUSTED_PROXIES_NETS,
    LOG_FORMAT,
    _LOG_LEVELS,
    _LOG_LEVEL_N,
    SESSION_COOKIE,
    ADMIN_NS,
    _ADMIN_PUBLIC_SUBPATHS,
)
from state import (
    _GW_LOG_RING,
)
import time as _t


def now() -> float:
    return time.monotonic()


def _new_request_id() -> str:
    """Short, sortable-by-time, easy to grep request id."""
    return f"r{int(time.time())%100000:05d}{secrets.token_hex(4)}"


def slog(event: str, level: str = "info", **fields) -> None:
    """Structured log line. In `text` mode prints a compact key=value form;
    in `json` mode emits one JSON document per line (no embedded newlines).

    1.6.3 — also captures non-request events into _GW_LOG_RING so the
    /__logs dashboard can tail config_changed / ban / webhook_failed / etc.
    Capture happens BEFORE the level filter so the ring keeps a richer
    history than stdout (operators rarely run the gateway at debug level)."""
    # Capture into the ring first — full fidelity.
    if event != "request":
        try:
            _GW_LOG_RING.append({
                "ts":    _t.time(),
                "level": level,
                "event": event,
                **fields,
            })
        except Exception:
            pass  # nosec B110 — log ring is best-effort; drop on overflow or dict errors
    if _LOG_LEVELS.get(level, 20) < _LOG_LEVEL_N:
        return
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if LOG_FORMAT == "json":
        try:
            line = json.dumps({"ts": ts, "level": level, "event": event,
                               **fields}, separators=(",", ":"),
                              default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            # Defensive: never raise from a log call.
            line = json.dumps({"ts": ts, "level": level, "event": event,
                               "_log_error": "unserialisable_field"})
        print(line, flush=True)
    else:
        kv = " ".join(f"{k}={v!r}" for k, v in fields.items())
        print(f"[{ts}] {level} {event} {kv}", flush=True)


def _peer_is_trusted_proxy(remote: str) -> bool:
    """Return True iff `remote` is in TRUSTED_PROXIES_NETS, OR no allowlist
    is configured (back-compat). 1.5.4 — closes the spoofed-XFF bypass found
    by the pentest: when the gateway is exposed directly (no real reverse
    proxy in front), an attacker can set X-Forwarded-For to any value and
    impersonate any IP for ban-tracking / risk / admin-allowlist purposes."""
    if not TRUSTED_PROXIES_NETS:
        return False  # fail-closed: require explicit TRUSTED_PROXIES env var
    if not remote:
        return False
    try:
        ip = _ipaddress.ip_address(remote)
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in TRUSTED_PROXIES_NETS)


def get_ip(request) -> str:
    """
    TRUST_XFF=first  → vulnerable: attacker-controlled (default, for bypass demos)
    TRUST_XFF=last   → secure: trusts only the last hop (ngrok-injected real IP)
    TRUST_XFF=none   → ignore XFF, use raw socket peer

    1.5.4 — XFF is now ONLY honoured when the immediate peer is in
    TRUSTED_PROXIES (otherwise we fall back to the raw socket IP, ignoring
    any client-supplied X-Forwarded-For header).
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff and TRUST_XFF != "none" and _peer_is_trusted_proxy(request.remote or ""):
        parts = [p.strip() for p in xff.split(",")]
        return parts[0] if TRUST_XFF == "first" else parts[-1]
    return request.remote or "0.0.0.0"  # nosec B104 — fallback sentinel, not a bind address


def _is_admin_path(p: str) -> bool:
    """True iff `p` lands on any internal endpoint (anything under the
    admin namespace). Used by the protect middleware to skip detector
    layers (RPS limit, method allowlist) on operator paths."""
    return p == ADMIN_NS or p.startswith(ADMIN_NS + "/")


def _admin_path_is_public(p: str) -> bool:
    """True iff this admin path is exempt from the admin-key gate
    (liveness, challenge plumbing, browser-callable BotD endpoints)."""
    if not p.startswith(ADMIN_NS + "/"):
        return False
    sub = p[len(ADMIN_NS):]
    for entry in _ADMIN_PUBLIC_SUBPATHS:
        if entry.endswith("/"):
            if sub.startswith(entry):
                return True
        elif sub == entry:
            return True
    return False


def _strip_admin_key_from_qs(path_qs: str) -> str:
    """Remove `key=` query parameter so ADMIN_KEY never leaks into upstream logs."""
    if "?" not in path_qs or "key=" not in path_qs:
        return path_qs
    path, _, qs = path_qs.partition("?")
    kept = [p for p in qs.split("&") if p and not p.startswith("key=")]
    return path + ("?" + "&".join(kept) if kept else "")


def _strip_own_session_cookie(cookie_header: str) -> str:
    """Remove our own SESSION_COOKIE from a forwarded Cookie header."""
    if not cookie_header:
        return ""
    parts = [p.strip() for p in cookie_header.split(";")]
    kept = [p for p in parts if p and not p.lower().startswith(SESSION_COOKIE.lower() + "=")]
    return "; ".join(kept)


def _to_bool_default_true(v):
    if v is None: return True
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "on")
