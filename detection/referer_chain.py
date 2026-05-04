# detection/referer_chain.py — 1.7.2
#
# referer-ghost: the client sends a Referer that claims to be a page under
# our own domain that we have never actually served to this identity.
#
# Real browsers build Referer from actual navigation history. Bots inject
# a static or invented Referer to appear legitimate. Firing condition:
#   1. Referer is present and claims our own hostname.
#   2. The referer path is not a static asset (bots legitimately fetch CSS
#      with Referer = their loading page, even for unseen pages).
#   3. We have already served at least one HTML page to this identity
#      (avoids false positives on deep-link first visits).
#   4. The referer path is not in served_html_paths for this identity.

from urllib.parse import urlparse

from aiohttp import web

from config import REFERER_CHAIN_ENABLED
from state import state_lock, ip_state

_STATIC_SUFFIXES = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".otf",
    ".eot", ".map", ".mp4", ".webm", ".mp3", ".ogg",
)


async def referer_ghost_check(track_key: str, request: web.Request) -> tuple[bool, str]:
    """Return (True, reason) when Referer claims a path we never served."""
    if not REFERER_CHAIN_ENABLED:
        return False, ""

    referer = request.headers.get("Referer", "").strip()
    if not referer:
        return False, ""

    # Skip static asset fetches — legitimately loaded with an unseen referrer
    if request.path.endswith(_STATIC_SUFFIXES):
        return False, ""

    try:
        rp = urlparse(referer)
        ref_path = rp.path or "/"
        ref_host = (rp.netloc or "").split(":")[0].lower()
    except Exception:
        return False, ""

    if not ref_host:
        return False, ""

    # Only fire when Referer claims to be our own host
    own_host = (request.host or "").split(":")[0].lower()
    if ref_host != own_host:
        return False, ""

    # Skip if the referer path itself is a static asset
    if ref_path.endswith(_STATIC_SUFFIXES):
        return False, ""

    async with state_lock:
        s = ip_state[track_key]
        # Skip first-time visitors — deep links are legitimate
        if s.html_loads < 1:
            return False, ""
        if ref_path not in s.served_html_paths:
            return True, f"referer-ghost: {ref_path!r} never served to this identity"

    return False, ""


__all__ = ["referer_ghost_check"]
