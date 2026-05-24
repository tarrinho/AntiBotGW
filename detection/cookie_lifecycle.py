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

import time as _t
from aiohttp import web

from config import (
    COOKIE_GHOST_ENABLED, COOKIE_LIFECYCLE_ENABLED,
    CHAL_COOKIE, SESSION_COOKIE,
    COOKIE_GHOST_MIN_REQUESTS, COOKIE_GHOST_MISS_THRESHOLD,
)
from state import state_lock, ip_state

LIFECYCLE_COOKIE = "agw_lc"
_SERVED_HTML_PATHS_MAX = 50

_LIFECYCLE_SNIPPET = (
    b'<script>(function(){try{document.cookie="agw_lc=1;path=/;SameSite=Lax";}catch(e){}})();</script>'
)


def _inject_lifecycle_cookie_script(body: bytes) -> bytes:
    """Inject a tiny <script> that writes a JS-accessible cookie.
    Headless runtimes that don't execute JS won't write agw_lc;
    subsequent requests without it accumulate lifecycle-miss score."""
    if not COOKIE_LIFECYCLE_ENABLED or not body:
        return body
    lower = body.lower()
    for needle in (b"</body>", b"</html>"):
        idx = lower.find(needle)
        if idx >= 0:
            return body[:idx] + _LIFECYCLE_SNIPPET + body[idx:]
    return body + _LIFECYCLE_SNIPPET


async def cookie_ghost_check(track_key: str, request: web.Request) -> tuple[bool, str]:
    """Return (True, reason) if gateway cookies were set but never returned.

    cookie-ghost fires after COOKIE_GHOST_MISS_THRESHOLD consecutive requests
    where CHAL_COOKIE, SESSION_COOKIE, and agw_lc are all absent, and the
    gateway has already set at least one cookie for this identity.

    lifecycle-miss fires (at a higher threshold) when HTML was served —
    so the lifecycle script was injected — but agw_lc is still absent on
    non-HTML (API/XHR) requests."""
    if not COOKIE_GHOST_ENABLED and not COOKIE_LIFECYCLE_ENABLED:
        return False, ""

    async with state_lock:
        s = ip_state[track_key]
        req_count = s.request_count

        # cookie-ghost
        if COOKIE_GHOST_ENABLED and s.gateway_cookies_set > 0 and req_count >= COOKIE_GHOST_MIN_REQUESTS:
            has_any = (
                CHAL_COOKIE      in request.cookies
                or SESSION_COOKIE in request.cookies
                or LIFECYCLE_COOKIE in request.cookies
            )
            if not has_any:
                s.cookie_ghost_misses += 1
                if s.cookie_ghost_misses >= COOKIE_GHOST_MISS_THRESHOLD:
                    return True, f"cookie-ghost: 0/{s.gateway_cookies_set} cookies returned"

        # lifecycle-miss — higher threshold, non-HTML requests only.
        # elif: prevents double-increment when both signals fire on the same request.
        elif (COOKIE_LIFECYCLE_ENABLED
                and s.html_loads > 0
                and LIFECYCLE_COOKIE not in request.cookies
                and req_count >= COOKIE_GHOST_MIN_REQUESTS):
            accept = request.headers.get("Accept", "")
            if "text/html" not in accept:
                s.cookie_ghost_misses += 1
                if s.cookie_ghost_misses >= COOKIE_GHOST_MISS_THRESHOLD + 2:
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
    "_inject_lifecycle_cookie_script",
    "cookie_ghost_check",
    "record_gateway_cookie_set",
    "record_html_served",
]
