"""
helpers.py — Pure utility functions used across the proxy.
Extracted from proxy.py as part of Phase 1 modular refactoring.

Dependency rule: imports from config.py and state.py only.
"""

import json
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
    # Capture into the ring — redact fields that may carry secrets so
    # viewer-role users cannot extract credentials from /__logs (F-17).
    if event != "request":
        try:
            _ring_fields = {}
            for _k, _v in fields.items():
                if _k in ("url", "allowed_list") and isinstance(_v, str):
                    # Strip credentials from URLs (e.g. WEBHOOK_URL, REDIS_URL)
                    try:
                        from urllib.parse import urlparse, urlunparse
                        _p = urlparse(_v)
                        if _p.password:
                            _p = _p._replace(netloc=f"{_p.hostname}:{_p.port}" if _p.port
                                             else _p.hostname)
                            _v = urlunparse(_p)
                    except Exception:
                        _v = "<redacted-url>"
                elif _k == "error" and isinstance(_v, str) and ("://" in _v or "password" in _v.lower()):
                    _v = "<redacted>"
                _ring_fields[_k] = _v
            _GW_LOG_RING.append({
                "ts":    _t.time(),
                "level": level,
                "event": event,
                **_ring_fields,
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


# 1.8.8 — one-shot log de-dup for `xff_ignored_proxy_untrusted` warnings.
# Without this, every request from an untrusted-but-private peer would
# spam the log. Set is bounded to ~256 unique peers before reset.
_XFF_UNTRUSTED_PEERS_WARNED: set = set()


def get_ip(request) -> str:
    """
    TRUST_XFF=first  → vulnerable: attacker-controlled (default, for bypass demos)
    TRUST_XFF=last   → secure: trusts only the last hop (ngrok-injected real IP)
    TRUST_XFF=none   → ignore XFF, use raw socket peer

    1.5.4 — XFF is now ONLY honoured when the immediate peer is in
    TRUSTED_PROXIES (otherwise we fall back to the raw socket IP, ignoring
    any client-supplied X-Forwarded-For header).

    1.8.8 — when XFF is present but the peer is **private** RFC1918 AND
    not in TRUSTED_PROXIES, slog `xff_ignored_proxy_untrusted` once per
    peer. Catches the operator misconfiguration where a sidecar (e.g.
    cloudflared on the Docker bridge) is forwarding traffic with XFF but
    the gateway doesn't recognise it as trusted, so every event gets
    recorded with the bridge gateway IP and dashboards lose all geo.
    """
    xff = request.headers.get("X-Forwarded-For")
    remote = request.remote or ""
    if xff and TRUST_XFF != "none" and _peer_is_trusted_proxy(remote):
        parts = [p.strip() for p in xff.split(",")]
        return parts[0] if TRUST_XFF == "first" else parts[-1]
    # 1.8.8 — alert path: XFF present but peer untrusted. Only fire for
    # private-range peers (RFC1918) since seeing this from a public IP is
    # a normal proxy-spoofing rejection, not a misconfig.
    if xff and TRUST_XFF != "none" and remote and remote not in _XFF_UNTRUSTED_PEERS_WARNED:
        try:
            import ipaddress as _ipa
            ip = _ipa.ip_address(remote)
            if ip.is_private:
                if len(_XFF_UNTRUSTED_PEERS_WARNED) >= 256:
                    _XFF_UNTRUSTED_PEERS_WARNED.clear()
                _XFF_UNTRUSTED_PEERS_WARNED.add(remote)
                slog("xff_ignored_proxy_untrusted",
                     level="warn",
                     peer=remote,
                     xff_sample=xff[:80],
                     hint=("Peer is RFC1918 (likely a Docker sidecar) but not in "
                           "TRUSTED_PROXIES; XFF will be ignored and all events "
                           "will record this peer IP. Add the peer's subnet to "
                           "TRUSTED_PROXIES to fix."))
        except (ValueError, TypeError):
            pass  # nosec B110 — non-IP remote (unix socket?); silently skip
    return remote or "0.0.0.0"  # nosec B104 — fallback sentinel, not a bind address


def _ua_of(request) -> str:
    """1.8.15 perf — cached User-Agent fetch.

    aiohttp's CIMultiDictProxy.get() is O(1) but still costs ~100ns/call due to
    case-folding + bytes-to-str conversion. The request hot path reads
    User-Agent ~7× per request (decoy callsites, signal records, deny-list
    matches). Stash the captured string on request["_ua"] so subsequent calls
    are a dict lookup. Net saving ~700ns/req on hot path.

    Idempotent and safe to call anywhere — first call captures, subsequent
    calls return the cached value.
    """
    if "_ua" not in request:
        request["_ua"] = request.headers.get("User-Agent", "")
    return request["_ua"]


def _is_admin_path(p: str) -> bool:
    """True iff `p` lands on any internal endpoint (anything under the
    admin namespace). Used by the protect middleware to skip detector
    layers (RPS limit, method allowlist) on operator paths."""
    return p == ADMIN_NS or p.startswith(ADMIN_NS + "/")


# 1.8.15 perf — static-asset extensions. Single source of truth; previously
# inlined in 3 separate hot-path tuples. `endswith()` over this tuple is C-fast.
_STATIC_ASSET_EXTS = (
    ".css", ".js", ".mjs",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".map", ".mp4", ".webm", ".mp3", ".ogg", ".pdf", ".zip",
)


def _is_static_asset_path(p: str) -> bool:
    """True iff `p` looks like a static asset (CSS/JS/image/font/media).
    Used in hot path to skip per-request heuristics that can't trigger on
    sub-resource fetches (e.g. LLM-no-subresource probe)."""
    return p.endswith(_STATIC_ASSET_EXTS)


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
