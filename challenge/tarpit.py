"""
challenge/tarpit.py — AI-labyrinth / tarpit maze endpoint.
Extracted from proxy.py as part of Phase 6 modular refactoring.

Depends on:
  config.py  — POW_HMAC_KEY, LABYRINTH_ENABLED, LABYRINTH_MAX_DEPTH,
                LABYRINTH_LINKS_PER, LABYRINTH_SLOW_MS, LABYRINTH_JITTER_ENABLED,
                _TARPIT_TOPICS, _TARPIT_SENTENCES
  state.py   — (no direct state; banning done via scoring functions)
  helpers.py — slog, now, get_ip
  proxy.py   — get_identity, update_risk_and_maybe_ban, record, _new_request_id
               (late imports to avoid circular dependency)
"""

import asyncio
import hashlib
import hmac
import random
import secrets

from aiohttp import web

from config import *   # noqa: F401,F403
from config import _TARPIT_TOPICS, _TARPIT_SENTENCES  # noqa: F401 — leading _ not in *
from state import *    # noqa: F401,F403
from helpers import slog, now, get_ip


# ── Token helpers ─────────────────────────────────────────────────────────

def _tarpit_token(depth: int) -> str:
    """Mint a signed tarpit token encoding maze depth."""
    nonce = secrets.token_urlsafe(8)
    sig = hmac.new(POW_HMAC_KEY,
                   f"tarpit:{depth}:{nonce}".encode(),
                   hashlib.sha256).hexdigest()[:16]
    return f"{depth}.{nonce}.{sig}"


def _tarpit_verify(token: str) -> "int | None":
    """Return depth if token is valid and depth ≤ LABYRINTH_MAX_DEPTH, else None."""
    parts = token.split(".", 2)
    if len(parts) != 3:
        return None
    depth_s, nonce, sig = parts
    try:
        depth = int(depth_s)
    except ValueError:
        return None
    if depth < 0 or depth > LABYRINTH_MAX_DEPTH:
        return None
    expected = hmac.new(POW_HMAC_KEY,
                        f"tarpit:{depth}:{nonce}".encode(),
                        hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected):
        return None
    return depth


# ── HTML generator ────────────────────────────────────────────────────────

def _tarpit_page_html(depth: int, nonce: str) -> str:
    """Generate a plausible-looking fake documentation page for the tarpit."""
    import hashlib as _h
    seed = int(_h.sha256(nonce.encode()).hexdigest(), 16)
    topic_title, topic_slug = _TARPIT_TOPICS[seed % len(_TARPIT_TOPICS)]
    # Pick 6 sentences pseudo-randomly from the pool
    body_sentences = [
        _TARPIT_SENTENCES[(seed + i * 7) % len(_TARPIT_SENTENCES)]
        for i in range(6)
    ]
    # Build more tarpit links for the next depth level
    link_html = ""
    if depth < LABYRINTH_MAX_DEPTH and LABYRINTH_ENABLED:
        links = [
            f'<a href="/antibot-appsec-gateway/tarpit/{_tarpit_token(depth + 1)}" '
            f'rel="nofollow noopener" style="display:none!important;visibility:hidden;'
            f'position:absolute;left:-99999px" aria-hidden="true">{topic_slug}-{i}</a>'
            for i in range(LABYRINTH_LINKS_PER)
        ]
        link_html = (
            '<div style="display:none!important;visibility:hidden;height:0;width:0;'
            'overflow:hidden;position:absolute;left:-99999px" aria-hidden="true">'
            + "".join(links) + "</div>"
        )
    paras = "".join(f"<p>{s}</p>" for s in body_sentences)
    return (
        f"<!DOCTYPE html><html lang='en'><head>"
        f"<meta charset='utf-8'><title>{topic_title}</title>"
        f"<meta name='robots' content='noindex,nofollow'>"
        f"</head><body>"
        f"<h1>{topic_title}</h1>"
        f"<p><em>Internal reference document — depth {depth}</em></p>"
        f"{paras}"
        f"{link_html}"
        f"</body></html>"
    )


# ── Endpoint ──────────────────────────────────────────────────────────────

async def tarpit_endpoint(request: web.Request) -> web.Response:
    """GET /antibot-appsec-gateway/tarpit/{token}
    Any client that reaches this endpoint followed a hidden nofollow link —
    almost certainly a bot.  We:
      1. Validate the HMAC token (invalid → 404, no signal leak).
      2. Record tarpit-walk + instant ban.
      3. Slow-drip a fake HTML page to waste crawler resources.
      4. Embed new links for the next maze depth.
    """
    if not LABYRINTH_ENABLED:
        raise web.HTTPNotFound()

    token = request.match_info.get("token", "")
    depth = _tarpit_verify(token)
    if depth is None:
        raise web.HTTPNotFound()

    ip     = get_ip(request)
    ua     = request.headers.get("User-Agent", "")
    # Late imports to avoid circular dependency (these live in proxy.py still)
    from identity import get_identity
    from scoring import update_risk_and_maybe_ban
    from core.metrics import record
    from helpers import _new_request_id
    tk, sid, fp, _, _ = get_identity(request)
    ja4    = request.headers.get("X-JA4", "")
    rid    = _new_request_id()

    # Record + ban — tarpit-walk is near-zero FP; one hit = instant ban
    await update_risk_and_maybe_ban(tk, "tarpit-walk", ip)
    await record(ip, ua, request.path, 200, "tarpit-walk",
                 track_key=tk, sid=sid, fp=fp, ja4=ja4, request_id=rid)

    # Extract nonce for deterministic page content
    nonce = token.split(".", 2)[1] if "." in token else token
    html_bytes = _tarpit_page_html(depth, nonce).encode("utf-8")

    # Slow-drip: split into 256-byte chunks with a per-chunk delay.
    # 1.6.10: Gaussian jitter (σ=500ms, clipped to [200,3000ms]) when enabled
    # so bots cannot fingerprint the gateway by timing the fixed 600ms cadence.
    chunk_size = 256
    chunks = [html_bytes[i:i + chunk_size]
              for i in range(0, len(html_bytes), chunk_size)]
    if LABYRINTH_JITTER_ENABLED:
        _mean = LABYRINTH_SLOW_MS / 1000.0
        delay = max(0.2, min(3.0, random.gauss(_mean, 0.5)))
    else:
        delay = LABYRINTH_SLOW_MS / 1000.0

    response = web.StreamResponse(
        status=200,
        headers={"Content-Type": "text/html; charset=utf-8",
                 "Cache-Control": "no-store",
                 "X-Robots-Tag": "noindex,nofollow"}
    )
    await response.prepare(request)
    for chunk in chunks:
        await response.write(chunk)
        await asyncio.sleep(delay)
    await response.write_eof()
    return response
