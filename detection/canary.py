# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
# detection/canary.py — Phase 4 extraction
# Canary token injection/scanning, BotD reporter, tarpit link injection,
# and honey-link injection extracted from proxy.py (lines 10049–10239).
#
# Constants already in config.py (Phase 1) are imported, not re-defined:
#   CANARY_ECHO_DETECTION, CANARY_TTL_S, _CANARY_PREFIX, _CANARY_USED_MAX,
#   _CANARY_RE, BOTD_ENABLED, _BOTD_REPORT_TTL, LABYRINTH_*, POW_HMAC_KEY,
#   SESSION_KEY, HONEY_LINK_HTML
#
# _canary_tokens dict lives in state.py (line 111) — imported from there.
#
# Late imports used in this module:
#   update_risk_and_maybe_ban  — will be in scoring.py (Phase 5); imported
#                                inside botd_report_endpoint() body to avoid
#                                a circular import.
#   record                     — same reason; imported inside function body.
#   _request_ja4               — stays in proxy.py until a future phase;
#                                imported inside function body.

import asyncio
import hashlib
import hmac
import json
import secrets
import time as _t
from collections import defaultdict

from aiohttp import web

from config import (
    CANARY_ECHO_DETECTION,
    CANARY_TTL_S,
    _CANARY_PREFIX,
    _CANARY_USED_MAX,
    _CANARY_RE,
    BOTD_ENABLED,
    _BOTD_REPORT_TTL,
    LABYRINTH_ENABLED,
    LABYRINTH_LINKS_PER,
    LABYRINTH_MAX_DEPTH,
    POW_HMAC_KEY,
    SESSION_KEY,
    HONEY_LINK_HTML,
    ADMIN_NS,
    CANARY_PROBE_ENABLED,
    CANARY_PROBE_TTL_SECS,
    CANARY_PROBE_MIN_HTML,
    CANARY_PROBE_SCORE,
)
# BODY_TIMEOUT lives in proxy.py (not yet promoted to config); late-imported
# inside botd_report_endpoint() to avoid a circular import at module load time.
from state import _canary_tokens
from helpers import get_ip, slog
from identity import get_identity


# ── Canary token management ───────────────────────────────────────────────────

def _new_canary() -> str:
    tok = f"{_CANARY_PREFIX}{secrets.token_hex(8)}"
    now_ts = _t.time()
    if len(_canary_tokens) > _CANARY_USED_MAX:
        for k in [k for k, exp in _canary_tokens.items() if exp < now_ts]:
            _canary_tokens.pop(k, None)
        if len(_canary_tokens) > _CANARY_USED_MAX:
            drop_n = max(1, _CANARY_USED_MAX // 10)
            for k in list(_canary_tokens.keys())[:drop_n]:
                _canary_tokens.pop(k, None)
    _canary_tokens[tok] = now_ts + CANARY_TTL_S
    return tok


def _inject_canary(body: bytes, token: str) -> bytes:
    """Plant the canary token as an HTML comment so the LLM's summariser
    reads it as part of the document. Prefers </head>, falls back to
    </body>, then to prepending. Pages without any HTML structure still
    receive the canary so the X-Trace-Id header isn't the only carrier."""
    blob = f"<!-- {token} -->".encode()
    if not body:
        return blob
    lower = body.lower()
    for needle in (b"</head>", b"</body>", b"</html>"):
        idx = lower.find(needle)
        if idx >= 0:
            return body[:idx] + blob + body[idx:]
    return blob + body


def _scan_request_for_canary(request: web.Request, body_bytes: bytes = b"") -> str:
    """Return the first canary token that appears on the incoming request
    (URL, headers, or body), only counting tokens we previously issued and
    that haven't expired. Empty string if none."""
    if not CANARY_ECHO_DETECTION or not _canary_tokens:
        return ""
    now_ts = _t.time()
    candidates = []
    candidates.append(request.path_qs or "")
    for k, v in request.headers.items():
        # Skip our own session/chal/admin cookies — never contain canaries
        # unless echoed, but the cookies themselves shouldn't false-match
        # the regex anyway. Skip Cookie header to avoid scanning irrelevant
        # large blobs.
        if k.lower() == "cookie":
            continue
        candidates.append(v[:512])
    if body_bytes:
        candidates.append(body_bytes[:8192].decode("utf-8", errors="replace"))
    for blob in candidates:
        for m in _CANARY_RE.findall(blob):
            exp = _canary_tokens.get(m)
            if exp and exp > now_ts:
                return m
    return ""


# ── BotD (FingerprintJS open-source) client-side reporter ────────────────────

def _botd_token_for(track_key: str, ts: int) -> str:
    """Per-page HMAC over (track_key, ts). Bound to track_key so an
    attacker cannot craft a 'detected=false' report for someone else."""
    msg = f"botd|{track_key}|{ts}".encode()
    return hmac.new(SESSION_KEY, msg, hashlib.sha256).hexdigest()[:32]


def _inject_botd(body: bytes, track_key: str) -> bytes:
    """Inject a tiny `<script type="module">` snippet right before </body>
    that loads botd.bundle.js, runs the in-browser detector, and POSTs
    the result to /__botd-report. The token argument lets the report
    endpoint reject forged claims. No-op when track_key is empty
    (cookieless requests have nothing to bind to)."""
    if not body or not track_key:
        return body
    n = int(_t.time())
    tok = _botd_token_for(track_key, n)
    snippet = (
        f'<script type="module">'
        f'(async function(){{'
        f'try{{'
        f'const m=await import("/antibot-appsec-gateway/assets/botd.bundle.js");'
        f'const det=await m.default.load({{}});'
        f'const r=await det.detect();'
        f'await fetch("/antibot-appsec-gateway/botd-report",{{method:"POST",'
        f'headers:{{"Content-Type":"application/json"}},'
        f'credentials:"include",body:JSON.stringify({{'
        f'token:"{tok}",ts:{n},'
        f'bot:!!(r&&r.bot&&r.bot.result),'
        f'type:(r&&r.bot&&r.bot.type)||""}})}});'
        f'}}catch(e){{}}'
        f'}})();'
        f'</script>'
    ).encode()
    lower = body.lower()
    for needle in (b"</body>", b"</html>"):
        idx = lower.find(needle)
        if idx >= 0:
            return body[:idx] + snippet + body[idx:]
    return body + snippet


async def botd_report_endpoint(request: web.Request):
    """1.6.5 — receive a BotD client-side report. Validates the HMAC
    token (bound to the requester's track_key) so an attacker can't
    POST 'detected=false' for someone else, and bumps risk on
    detected=true. Idempotent per (track_key, ts) — we don't re-bump
    on duplicate posts (browser may retry).
    """
    # Task J — probe rate limiter
    from core.proxy_handler import _probe_rate_limit_ok
    from helpers import get_ip as _get_ip
    if not _probe_rate_limit_ok(_get_ip(request)):
        return web.Response(status=429, text="rate limit",
                            headers={"Retry-After": "10"})
    if not BOTD_ENABLED:
        return web.json_response({"ok": False, "reason": "disabled"},
                                  status=400)
    try:
        # Late import — BODY_TIMEOUT lives in proxy.py until a future phase.
        from core.proxy_handler import BODY_TIMEOUT
        raw = await asyncio.wait_for(request.content.read(8192),
                                      timeout=BODY_TIMEOUT)
        d = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(d, dict):
            raise ValueError("body must be json object")
    except (asyncio.TimeoutError, ValueError, json.JSONDecodeError):
        return web.json_response({"ok": False, "reason": "bad-request"},
                                  status=400)
    # Re-derive identity for THIS request — same as protect() does.
    identity, _sid, _fp, _is_new, _id_mode = get_identity(request)
    ip = get_ip(request)
    ua = request.headers.get("User-Agent", "")
    # Token validation: re-compute and constant-time compare. ts must
    # be within _BOTD_REPORT_TTL of the current time so an old token
    # leaked from a server-rendered page can't be replayed forever.
    try:
        ts_in = int(d.get("ts", 0))
    except (ValueError, TypeError):
        ts_in = 0
    n = int(_t.time())
    if ts_in <= 0 or abs(n - ts_in) > _BOTD_REPORT_TTL:
        return web.json_response({"ok": False, "reason": "stale-token"},
                                  status=400)
    expected = _botd_token_for(identity, ts_in)
    provided = str(d.get("token", ""))
    if not hmac.compare_digest(expected, provided):
        # Bump risk slightly + record so an operator can investigate.
        # Late import — update_risk_and_maybe_ban lives in proxy.py until Phase 5.
        from scoring import update_risk_and_maybe_ban
        await update_risk_and_maybe_ban(identity, "botd-detected", ip)
        return web.json_response({"ok": False, "reason": "bad-token"},
                                  status=403)
    # Validated — apply the report.
    if d.get("bot") is True:
        # Late imports — scoring/recording functions live in proxy.py until Phase 5.
        from scoring import update_risk_and_maybe_ban
        from core.metrics import record
        from integrations.ja4 import _request_ja4
        await update_risk_and_maybe_ban(identity, "botd-detected", ip)
        await record(ip, ua, request.path, 200, "botd-detected",
                     track_key=identity, sid=_sid, fp=_fp,
                     ja4=_request_ja4(request),
                     request_id=request.get("_rid", ""))
    return web.json_response({"ok": True}, headers={"Cache-Control": "no-store"})


# ── Tarpit / labyrinth link injection ─────────────────────────────────────────

def _tarpit_inject_html() -> str:
    """Build the hidden tarpit link block (depth=0 entry points)."""
    if not LABYRINTH_ENABLED:
        return ""
    # Late import — _tarpit_token lives in proxy.py until it is extracted to
    # a dedicated labyrinth module in a future phase.
    from challenge.tarpit import _tarpit_token
    links = [
        f'<a href="/antibot-appsec-gateway/tarpit/{_tarpit_token(0)}" '
        f'rel="nofollow noopener" style="display:none!important;visibility:hidden;'
        f'position:absolute;left:-99999px" aria-hidden="true">link-{i}</a>'
        for i in range(LABYRINTH_LINKS_PER)
    ]
    return (
        '<div style="display:none!important;visibility:hidden;height:0;width:0;'
        'overflow:hidden;position:absolute;left:-99999px" aria-hidden="true">'
        + "".join(links) + "</div>"
    )


def _inject_honey_links(body: bytes) -> bytes:
    """Insert honey-link block (static traps + tarpit entry links) before the
    LAST `</body>`.  Skips injection if the chosen position would land inside a
    `<script>` block — prevents corrupting JS string literals."""
    if not body:
        return body
    tail = body[-4096:]
    idx = tail.rfind(b"</body>")
    if idx < 0:
        return body
    # If any open <script appears AFTER our match in the tail, the </body> we
    # picked is likely inside a JS literal. Bail out.
    if b"<script" in tail[idx:].lower() or b"</script" in tail[idx:].lower():
        return body
    abs_idx = len(body) - len(tail) + idx
    inject = (HONEY_LINK_HTML + _tarpit_inject_html()).encode()
    return body[:abs_idx] + inject + body[abs_idx:]


# ── P4: Browser execution probe (1.7.3) ───────────────────────────────────────
# Real browsers automatically fetch <link rel="preload" as="fetch"> hints;
# AI agents (WebFetch, LangChain, etc.) only retrieve the HTML document itself.
#
# Per-identity state:
#   _probe_token_store  — token → (identity, expires_ts)
#   _probe_html_counts  — identity → (html_count, first_seen_ts)
#   _probe_confirmed    — identity → ts when probe was fetched

_probe_token_store: dict = {}  # token → (identity, expires_ts)
_PROBE_STORE_MAX = 8192
# identity → [first_seen_ts, html_count]
_probe_html_counts: dict = defaultdict(lambda: [0.0, 0])
_PROBE_COUNTS_MAX = 32768
# identity → last confirmed timestamp
_probe_confirmed: dict = {}
_PROBE_CONFIRMED_MAX = 32768


def _make_canary_probe_token(identity: str) -> str:
    bucket = int(_t.time()) // CANARY_PROBE_TTL_SECS
    raw = hmac.new(
        SESSION_KEY,
        f"cp|{identity}|{bucket}".encode(),
        hashlib.sha256,
    ).hexdigest()[:24]
    return raw


def _store_probe_token(token: str, identity: str) -> None:
    now = _t.time()
    if len(_probe_token_store) >= _PROBE_STORE_MAX:
        expired = [k for k, (_, exp) in _probe_token_store.items() if exp < now]
        for k in expired:
            _probe_token_store.pop(k, None)
        if len(_probe_token_store) >= _PROBE_STORE_MAX:
            for k in list(_probe_token_store.keys())[:_PROBE_STORE_MAX // 8]:
                _probe_token_store.pop(k, None)
    _probe_token_store[token] = (identity, now + CANARY_PROBE_TTL_SECS * 2)


def inject_canary_probe(body: bytes, identity: str) -> bytes:
    """Inject a hidden preload link probe into HTML. Browsers fetch it
    automatically; AI agents don't. Also increments the per-identity HTML
    counter. No-op when CANARY_PROBE_ENABLED=0 or body is empty."""
    if not CANARY_PROBE_ENABLED or not body or not identity:
        return body

    token = _make_canary_probe_token(identity)
    _store_probe_token(token, identity)

    # Track HTML page count per identity
    now = _t.time()
    if len(_probe_html_counts) >= _PROBE_COUNTS_MAX:
        stale = [k for k, v in _probe_html_counts.items()
                 if v[0] > 0 and now - v[0] > 86400]
        for k in stale:
            _probe_html_counts.pop(k, None)
        if len(_probe_html_counts) >= _PROBE_COUNTS_MAX:
            for k in list(_probe_html_counts.keys())[: _PROBE_COUNTS_MAX // 8]:
                _probe_html_counts.pop(k, None)
    rec = _probe_html_counts[identity]
    if rec[1] == 0:
        rec[0] = now  # first_seen_ts
    rec[1] += 1

    probe_url = f"{ADMIN_NS}/canary-probe/{token}"
    link_tag = (
        f'<link rel="preload" href="{probe_url}" as="fetch" '
        f'crossorigin="anonymous" data-agw="1">'
    ).encode()

    lower = body.lower()
    idx = lower.find(b"</head>")
    if idx >= 0:
        return body[:idx] + link_tag + body[idx:]
    # Fallback: prepend (still parsed before render, before </body>)
    idx = lower.find(b"</body>")
    if idx >= 0:
        return body[:idx] + link_tag + body[idx:]
    return body + link_tag


async def canary_probe_endpoint(request: web.Request):
    """GET /antibot-appsec-gateway/canary-probe/{token}
    Called automatically by browsers via preload hint. Records browser
    confirmation for the identity. Returns 204 No Content."""
    # Task J — probe rate limiter
    from core.proxy_handler import _probe_rate_limit_ok
    from helpers import get_ip as _get_ip
    if not _probe_rate_limit_ok(_get_ip(request)):
        return web.Response(status=429, text="rate limit",
                            headers={"Retry-After": "10"})
    token = request.match_info.get("token", "")
    # Reject tokens that are obviously malformed to avoid hash-cost DoS
    if token and len(token) <= 48:
        entry = _probe_token_store.get(token)
        if entry:
            identity, exp = entry
            if _t.time() <= exp:
                now_ts = _t.time()
                _probe_confirmed[identity] = now_ts
                # Evict oldest quarter when confirmed dict grows too large
                if len(_probe_confirmed) > _PROBE_CONFIRMED_MAX:
                    for k in list(_probe_confirmed.keys())[:_PROBE_CONFIRMED_MAX // 4]:
                        _probe_confirmed.pop(k, None)
    # Always return 204 — never reveal whether token was valid
    return web.Response(status=204, headers={
        "Cache-Control": "no-store, no-cache",
    })


def check_canary_probe(identity: str, ip: str) -> float:
    """Return risk delta if identity has received ≥ CANARY_PROBE_MIN_HTML
    HTML pages but the browser probe was never fetched within
    CANARY_PROBE_TTL_SECS of first serving. Returns 0.0 when no signal."""
    if not CANARY_PROBE_ENABLED or not identity:
        return 0.0

    # Already confirmed as browser — no signal
    if identity in _probe_confirmed:
        return 0.0

    rec = _probe_html_counts.get(identity)
    if not rec:
        return 0.0

    first_seen_ts, html_count = rec[0], rec[1]
    if html_count < CANARY_PROBE_MIN_HTML:
        return 0.0

    now = _t.time()
    # Only fire after the TTL window has elapsed — give the browser time to fetch
    if now - first_seen_ts < CANARY_PROBE_TTL_SECS:
        return 0.0

    # Fired — reset counter so it doesn't re-fire every request
    _probe_html_counts[identity] = [now, 0]
    slog("canary_probe_miss", level="warn", ip=ip, identity=identity[:8],
         html_count=html_count, ttl_secs=CANARY_PROBE_TTL_SECS)
    return CANARY_PROBE_SCORE


__all__ = [
    # canary
    "_new_canary",
    "_inject_canary",
    "_scan_request_for_canary",
    # botd
    "_botd_token_for",
    "_inject_botd",
    "botd_report_endpoint",
    # tarpit / honey
    "_tarpit_inject_html",
    "_inject_honey_links",
    # P4: browser execution probe (1.7.3)
    "inject_canary_probe",
    "canary_probe_endpoint",
    "check_canary_probe",
]
