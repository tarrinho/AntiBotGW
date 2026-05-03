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
)
# BODY_TIMEOUT lives in proxy.py (not yet promoted to config); late-imported
# inside botd_report_endpoint() to avoid a circular import at module load time.
from state import _canary_tokens
from helpers import get_ip
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
]
