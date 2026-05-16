"""
identity.py — Session cookie + browser fingerprint identity logic.
Extracted from proxy.py as part of Phase 3 modular refactoring.

Dependency rule: imports from config, state, helpers only.
Functions that depend on update_risk_and_maybe_ban (still in proxy.py during
this phase) use a lazy import to avoid a circular-import at module load time.
"""

import hashlib
import hmac
import secrets
import time as _t
from collections import defaultdict, deque

from config import (
    SESSION_KEY,
    SESSION_COOKIE,
    SESSION_TTL_SECS,
    SESSION_SAMESITE,
    SESSION_SECURE,
    NEW_SESSIONS_PER_IP_PER_MIN,
)
from state import (
    state_lock,
    ip_state,
    ip_new_sessions,
    db_queue,
)
from helpers import slog, get_ip, now

# ── Session HMAC helpers ───────────────────────────────────────────────────


def _sign_session(sid: str) -> str:
    sig = hmac.new(SESSION_KEY, b"session:" + sid.encode(), hashlib.sha256).hexdigest()
    return f"{sid}.{sig}"


def _verify_session(token: str):
    if not token or "." not in token:
        return None
    try:
        sid, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    # N3: reject empty sid (would otherwise yield a stable identity for every
    # client that presents a valid HMAC of the empty string).
    if not sid or len(sig) != 64:
        return None
    # N3: also clamp sid length and charset (token_urlsafe alphabet only).
    if len(sid) > 64 or not all(c.isalnum() or c in "-_" for c in sid):
        return None
    expected = hmac.new(SESSION_KEY, b"session:" + sid.encode(), hashlib.sha256).hexdigest()
    return sid if hmac.compare_digest(sig, expected) else None


# ── Browser fingerprint ────────────────────────────────────────────────────


def browser_fingerprint(request) -> str:
    """Stable hash of browser-identifying headers. Excludes Sec-Ch-Ua* — these
    Client Hints are only sent on top-level navigation by default; including
    them here splits one browser into multiple identities across navigation
    vs sub-resource fetches and causes false-positive bans on SPAs with many
    JS modules."""
    parts = [
        request.headers.get("User-Agent", "")[:200],
        request.headers.get("Accept-Language", ""),
        request.headers.get("Accept-Encoding", ""),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


# ── Header-order library fingerprint helpers ───────────────────────────────
# 1.6.10 — sha256[:12] of ":"-joined lowercase non-host header names in
# request order. Covers common HTTP bot libraries that send a predictable
# minimal header set.


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


# ── Composite identity ─────────────────────────────────────────────────────


def get_identity(request):
    """
    Returns (identity, session_id, fingerprint, is_new_session, mode).
    Identity strategy:
      • Browser with valid cookie  → identity = HMAC("sess|" + sid + "|" + fp)
                                      stable per session, survives header changes
      • Cookieless / invalid cookie → identity = HMAC("anon|" + fp + "|" + ip)
                                      STABLE per (fingerprint, IP) tuple — so all
                                      requests from a Python bot with the same UA
                                      share the same identity and the same rate-limit
                                      bucket. The bot CANNOT escape by simply
                                      not storing cookies.
      • Bot rotating fp+ip on every request → still caught by IP session-flood guard
                                              (max 30 new identities/min/IP)
    Returns mode="session"|"anon" so the dashboard can display.
    """
    cookie_token = request.cookies.get(SESSION_COOKIE, "")
    sid = _verify_session(cookie_token)
    fp = browser_fingerprint(request)

    if sid:
        # Cookie-bound identity (proper browser)
        identity = hmac.new(
            SESSION_KEY, f"sess|{sid}|{fp}".encode(), hashlib.sha256
        ).hexdigest()[:16]
        return identity, sid, fp, False, "session"
    else:
        # No (valid) cookie — bind identity to fingerprint+IP for stability.
        # Bot reusing the same UA from same IP sees the SAME identity → caught.
        ip = get_ip(request)
        identity = hmac.new(
            SESSION_KEY, f"anon|{fp}|{ip}".encode(), hashlib.sha256
        ).hexdigest()[:16]
        # Still issue a fresh sid in case they DO start accepting cookies later
        new_sid = secrets.token_urlsafe(12)
        return identity, new_sid, fp, True, "anon"


# ── Session-churn fingerprint tracking ────────────────────────────────────
# Track per-fingerprint cookie minting. A real user mints one cookie per
# visit; an automation tool minting > SESSION_CHURN_MAX cookies in
# SESSION_CHURN_WINDOW_S seconds is the strongest agent signature available
# without inspecting application semantics.
# On hit: risk += 75 (single-hit ≥ ban) + 24 h hostile-pool (R8) — and via
# the shared store the ban propagates across every other gateway instance.

import os as _os
SESSION_CHURN_WINDOW_S = int(_os.environ.get("SESSION_CHURN_WINDOW_S", "60"))
SESSION_CHURN_MAX      = int(_os.environ.get("SESSION_CHURN_MAX",      "6"))
_fp_session_creations: dict = defaultdict(lambda: deque(maxlen=64))


def _fp_hash(ua: str, ip_tier: str, ja4: str) -> str:
    """Opaque hash of the request's (UA + IP-tier + JA4) — used as the
    ban-keying identity for fingerprints that are minting many cookies."""
    return hmac.new(SESSION_KEY,
                    f"fp|{ua[:200]}|{ip_tier}|{ja4}".encode(),
                    hashlib.sha256).hexdigest()[:24]


def compute_ja4h(request) -> str:
    """JA4H: HTTP request fingerprint.
    Format: <method2><version><body><referer>_<hdr_count><ck_count>_<hdr_hash>_<ck_hash>
    """
    import hashlib as _hl
    try:
        method  = (request.method or "")[:2].lower().ljust(2, "_")
        ver     = request.version
        version = "20" if (hasattr(ver, "major") and ver.major == 2) else "11"
        has_body = "y" if (getattr(request, "content_length", None) or 0) > 0 else "n"
        hdrs    = dict(request.headers) if hasattr(request, "headers") else {}
        has_ref = "r" if any(h.lower() == "referer" for h in hdrs) else "n"
        # Header names (exclude cookie and host, lowercase, original order)
        hdr_names = ",".join(
            h.lower() for h in hdrs
            if h.lower() not in ("cookie", "host")
        )
        # Cookie names
        cookies = dict(request.cookies) if hasattr(request, "cookies") else {}
        ck_names = ",".join(sorted(cookies.keys()))
        hdr_count = min(len([h for h in hdrs if h.lower() not in ("cookie", "host")]), 99)
        ck_count  = min(len(cookies), 99)
        hdr_hash  = _hl.sha256(hdr_names.encode()).hexdigest()[:12]
        ck_hash   = _hl.sha256(ck_names.encode()).hexdigest()[:12] if ck_names else "000000000000"
        return f"{method}{version}{has_body}{has_ref}_{hdr_count:02d}{ck_count:02d}_{hdr_hash}_{ck_hash}"
    except Exception:
        return "error"


async def _record_chal_mint(ua: str, ip_tier: str, ja4: str, ip: str,
                              rid: str = "") -> bool:
    """Track a chal-cookie mint. Returns True if the fingerprint just
    crossed the churn threshold (caller should propagate the verdict)."""
    fp_h = _fp_hash(ua, ip_tier, ja4)
    n = _t.time()
    q = _fp_session_creations[fp_h]
    q.append(n)
    while q and q[0] < n - SESSION_CHURN_WINDOW_S:
        q.popleft()
    if len(q) > SESSION_CHURN_MAX:
        slog("session_churn", level="warn", rid=rid, fp_hash=fp_h,
             ip_tier=ip_tier, ja4=ja4, count=len(q),
             window_s=SESSION_CHURN_WINDOW_S)
        # Lazy import to avoid circular import during Phase 3 (function is
        # still defined in proxy.py; will be extracted in a later phase).
        try:
            import proxy as _proxy
            await _proxy.update_risk_and_maybe_ban(fp_h, "session-churn", ip)
        except (ImportError, AttributeError):
            pass
        # Accumulate JA4-level ban signal: a bot rotating sessions while
        # keeping the same TLS fingerprint (JA4) should be auto-denied even
        # if each individual session never crosses RISK_BAN_THRESHOLD.
        if ja4:
            try:
                from integrations.ja4 import _observe_ja4_ban
                import asyncio as _asyncio
                _asyncio.create_task(_observe_ja4_ban(ja4))
            except Exception:
                pass  # nosec B110 — JA4 ban task is best-effort; integration may be absent
        return True
    return False
