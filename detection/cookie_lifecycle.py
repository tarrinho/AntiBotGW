# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
# detection/cookie_lifecycle.py — 1.7.2
#
# Two orthogonal signals:
#   cookie-ghost   : gateway has set cookies for this identity but the client
#                    returns none of them across 3+ consecutive requests.
#                    Cookieless automated scrapers trip this immediately.
#   lifecycle-miss : gateway has served at least one HTML page (injecting the
#                    agw_lc lifecycle marker via JS), but the client still
#                    presents no agw_lc cookie on subsequent non-HTML requests.
#                    JS didn't execute → headless without JS execution.
#
# HTML injection:
#   _inject_lifecycle_cookie_script(body) inserts a one-liner <script> that
#   writes document.cookie = "agw_lc=1" before </body>.

import hashlib
import hmac as _hmac
import time as _t
from aiohttp import web

from config import (
    COOKIE_GHOST_ENABLED, COOKIE_LIFECYCLE_ENABLED,
    CHAL_COOKIE, SESSION_COOKIE,
    COOKIE_GHOST_MIN_REQUESTS, COOKIE_GHOST_MISS_THRESHOLD,
    SESSION_KEY,
)
from state import state_lock, ip_state

LIFECYCLE_COOKIE = "agw_lc"
_SERVED_HTML_PATHS_MAX = 50


def _make_lc_token(ip_tier: str) -> str:
    """Return a 16-char HMAC token for the lifecycle cookie.
    Bound to IP tier and a 1-hour time window so static replay attacks
    (B-04: bot prefills agw_lc=1) fail signature verification."""
    window = int(_t.time() / 3600)
    payload = f"lc|{ip_tier}|{window}".encode()
    return _hmac.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()[:16]


def _verify_lc_token(value: str, ip_tier: str) -> bool:
    """Accept current and previous 1-hour window to survive hour boundaries."""
    if not value or len(value) != 16:
        return False
    window = int(_t.time() / 3600)
    for w in (window, window - 1):
        payload = f"lc|{ip_tier}|{w}".encode()
        expected = _hmac.new(SESSION_KEY, payload, hashlib.sha256).hexdigest()[:16]
        if _hmac.compare_digest(value, expected):
            return True
    return False


def _inject_lifecycle_cookie_script(body: bytes, lc_token: str = "1") -> bytes:
    """Inject a tiny <script> that writes a JS-accessible cookie.
    Headless runtimes that don't execute JS won't write agw_lc;
    subsequent requests without it accumulate lifecycle-miss score."""
    if not COOKIE_LIFECYCLE_ENABLED or not body:
        return body
    snippet = (
        f'<script>(function(){{try{{document.cookie="agw_lc={lc_token};path=/;SameSite=Lax";'
        f'}}catch(e){{}}}})()</script>'
    ).encode()
    lower = body.lower()
    for needle in (b"</body>", b"</html>"):
        idx = lower.find(needle)
        if idx >= 0:
            return body[:idx] + snippet + body[idx:]
    return body + snippet


async def cookie_ghost_check(track_key: str, request: web.Request, ip_tier: str = "") -> tuple[bool, str]:
    """Return (True, reason) if gateway cookies were set but never returned.

    cookie-ghost fires after COOKIE_GHOST_MISS_THRESHOLD consecutive requests
    where CHAL_COOKIE, SESSION_COOKIE, and agw_lc are all absent, and the
    gateway has already set at least one cookie for this identity.

    lifecycle-miss fires (at a higher threshold) when HTML was served —
    so the lifecycle script was injected — but agw_lc is still absent or
    carries an invalid HMAC token on non-HTML (API/XHR) requests.

    ip_tier is used to verify the HMAC-signed agw_lc token (B-04 hardening).
    The threshold is jittered per identity (B-08 hardening) to prevent
    attackers from knowing the exact request count that triggers detection."""
    if not COOKIE_GHOST_ENABLED and not COOKIE_LIFECYCLE_ENABLED:
        return False, ""

    async with state_lock:
        s = ip_state[track_key]
        req_count = s.request_count
        jitter = s.cookie_ghost_threshold_jitter
        effective_min = COOKIE_GHOST_MIN_REQUESTS + jitter

        # cookie-ghost
        if COOKIE_GHOST_ENABLED and s.gateway_cookies_set > 0 and req_count >= effective_min:
            has_any = (
                CHAL_COOKIE      in request.cookies
                or SESSION_COOKIE in request.cookies
                or LIFECYCLE_COOKIE in request.cookies
            )
            if not has_any:
                s.cookie_ghost_misses += 1
                if s.cookie_ghost_misses >= COOKIE_GHOST_MISS_THRESHOLD + jitter:
                    return True, f"cookie-ghost: 0/{s.gateway_cookies_set} cookies returned"

        # lifecycle-miss — higher threshold, non-HTML requests only.
        # B-04: verify HMAC token, not just presence — agw_lc=1 (static replay) fails here.
        # elif: prevents double-increment when both signals fire on the same request.
        elif (COOKIE_LIFECYCLE_ENABLED
                and s.html_loads > 0
                and req_count >= effective_min):
            lc_val = request.cookies.get(LIFECYCLE_COOKIE, "")
            lc_valid = _verify_lc_token(lc_val, ip_tier) if ip_tier else bool(lc_val)
            if not lc_valid:
                accept = request.headers.get("Accept", "")
                if "text/html" not in accept:
                    s.cookie_ghost_misses += 1
                    if s.cookie_ghost_misses >= COOKIE_GHOST_MISS_THRESHOLD + 2 + jitter:
                        return True, "lifecycle-miss: JS did not execute"

    return False, ""


def record_gateway_cookie_set(track_key: str) -> None:
    """Increment gateway_cookies_set when the gateway sets a cookie for
    this identity. Called from the response pipeline (sync, asyncio loop)."""
    ip_state[track_key].gateway_cookies_set += 1


def record_html_served(track_key: str, path: str) -> None:
    """Record an HTML path as served to this identity for referer-ghost checks.
    Bounded to _SERVED_HTML_PATHS_MAX to prevent unbounded memory growth."""
    s = ip_state[track_key]
    if len(s.served_html_paths) < _SERVED_HTML_PATHS_MAX:
        s.served_html_paths.add(path)


__all__ = [
    "LIFECYCLE_COOKIE",
    "_make_lc_token",
    "_verify_lc_token",
    "_inject_lifecycle_cookie_script",
    "cookie_ghost_check",
    "record_gateway_cookie_set",
    "record_html_served",
]
