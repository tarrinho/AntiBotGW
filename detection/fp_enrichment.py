# detection/fp_enrichment.py — 1.7.2
#
# Canvas + WebGL browser fingerprint collection.
# Injects a <script> into HTML responses that:
#   1. Draws a deterministic scene on an offscreen canvas and samples the last
#      64 chars of the resulting dataURL (pixel hash). Real GPUs vary slightly
#      per driver/OS; software renderers (headless Chrome on CPU) produce an
#      identical, known value.
#   2. Queries WEBGL_debug_renderer_info for the unmasked renderer + vendor
#      strings. Strings containing "swiftshader", "mesa", "llvmpipe", etc.
#      indicate a virtual/headless environment.
#   3. POSTs the data to /antibot-appsec-gateway/fp-report with an HMAC token
#      bound to the requester's track_key (same scheme as automation-report).
#
# Detection:
#   soft-renderer  : WebGL renderer/vendor contains a known software-renderer
#                    substring → virtual or headless environment.
#   webgl-missing  : Chrome UA but no WebGL renderer string → headless Chrome
#                    with WebGL blocked or disabled (common in bots).

import asyncio
import hashlib
import hmac
import json
import time as _t

from aiohttp import web

from config import SESSION_KEY, FP_ENRICHMENT_ENABLED
from helpers import get_ip
from identity import get_identity

_FP_REPORT_TTL   = 300
_CANVAS_STORE_MAX = 10000

_SOFT_RENDERER_PATTERNS = (
    "swiftshader", "mesa", "llvmpipe", "lavapipe", "softpipe",
    "microsoft basic render", "google swiftshader",
    "vmware", "virtualbox", "virtual machine",
)


def _fp_token_for(track_key: str, ts: int) -> str:
    msg = f"fp|{track_key}|{ts}".encode()
    return hmac.new(SESSION_KEY, msg, hashlib.sha256).hexdigest()[:32]


def _is_soft_renderer(s: str) -> bool:
    sl = s.lower()
    return any(p in sl for p in _SOFT_RENDERER_PATTERNS)


def _inject_fp_probe(body: bytes, track_key: str) -> bytes:
    """Inject canvas + WebGL fingerprint collection before </body>.
    Reports go to /antibot-appsec-gateway/fp-report with HMAC bound to
    track_key so the report cannot be forged for another identity."""
    if not FP_ENRICHMENT_ENABLED or not body or not track_key:
        return body
    n   = int(_t.time())
    tok = _fp_token_for(track_key, n)
    snippet = (
        f'<script>(function(){{'
        f'try{{'
        f'var cv=document.createElement("canvas");'
        f'cv.width=200;cv.height=50;'
        f'var cx=cv.getContext("2d");'
        f'if(!cx){{return;}}'
        f'cx.textBaseline="top";'
        f'cx.font="14px Arial";'
        f'cx.fillStyle="#f60";'
        f'cx.fillRect(125,1,62,20);'
        f'cx.fillStyle="#069";'
        f'cx.fillText("AGW172",2,15);'
        f'cx.fillStyle="rgba(102,204,0,0.7)";'
        f'cx.fillText("AGW172",4,17);'
        f'var cpx=cv.toDataURL().slice(-64);'
        f'var gl=document.createElement("canvas").getContext("webgl")||'
        f'document.createElement("canvas").getContext("experimental-webgl");'
        f'var rdr="",vnd="";'
        f'if(gl){{'
        f'var di=gl.getExtension("WEBGL_debug_renderer_info");'
        f'if(di){{'
        f'rdr=gl.getParameter(di.UNMASKED_RENDERER_WEBGL)||"";'
        f'vnd=gl.getParameter(di.UNMASKED_VENDOR_WEBGL)||"";'
        f'}}'
        f'}}'
        f'fetch("/antibot-appsec-gateway/fp-report",{{'
        f'method:"POST",'
        f'headers:{{"Content-Type":"application/json"}},'
        f'credentials:"include",'
        f'body:JSON.stringify({{token:"{tok}",ts:{n},canvas:cpx,renderer:rdr,vendor:vnd}})'
        f'}}).catch(function(){{}});'
        f'}}catch(e){{}}'
        f'}})();</script>'
    ).encode()
    lower = body.lower()
    for needle in (b"</body>", b"</html>"):
        idx = lower.find(needle)
        if idx >= 0:
            return body[:idx] + snippet + body[idx:]
    return body + snippet


async def fp_report_endpoint(request: web.Request):
    """Receive canvas + WebGL fingerprint. Validates HMAC, stores fingerprint,
    bumps risk when soft-renderer or webgl-missing is detected."""
    # Task J — probe rate limiter
    from core.proxy_handler import _probe_rate_limit_ok
    if not _probe_rate_limit_ok(get_ip(request)):
        return web.Response(status=429, text="rate limit",
                            headers={"Retry-After": "10"})
    if not FP_ENRICHMENT_ENABLED:
        return web.json_response({"ok": False, "reason": "disabled"}, status=400)
    try:
        from core.proxy_handler import BODY_TIMEOUT
        raw = await asyncio.wait_for(request.content.read(4096), timeout=BODY_TIMEOUT)
        d = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(d, dict):
            raise ValueError("body must be a JSON object")
    except Exception:
        return web.json_response({"ok": False, "reason": "bad-request"}, status=400)

    identity, _sid, _fp, _is_new, _id_mode = get_identity(request)
    ip = get_ip(request)

    try:
        ts_in = int(d.get("ts", 0))
    except (ValueError, TypeError):
        ts_in = 0
    n = int(_t.time())
    if ts_in <= 0 or abs(n - ts_in) > _FP_REPORT_TTL:
        return web.json_response({"ok": False, "reason": "stale-token"}, status=400)

    expected = _fp_token_for(identity, ts_in)
    provided = str(d.get("token", ""))
    if not hmac.compare_digest(expected, provided):
        return web.json_response({"ok": False, "reason": "bad-token"}, status=403)

    canvas_hash = str(d.get("canvas",   ""))[:128]
    renderer    = str(d.get("renderer", ""))[:256]
    vendor      = str(d.get("vendor",   ""))[:128]

    # Store fingerprint (capped)
    from state import _fp_canvas_store
    if len(_fp_canvas_store) < _CANVAS_STORE_MAX:
        _fp_canvas_store[identity] = {
            "canvas": canvas_hash, "renderer": renderer,
            "vendor": vendor, "ts": n,
        }

    ua = request.headers.get("User-Agent", "")
    is_chrome_ua = "chrome" in ua.lower() and "chromium" not in ua.lower()
    fired_reason = None

    if _is_soft_renderer(renderer) or _is_soft_renderer(vendor):
        fired_reason = "soft-renderer"
    elif not renderer and is_chrome_ua:
        fired_reason = "webgl-missing"

    if fired_reason:
        from scoring import update_risk_and_maybe_ban
        from core.metrics import record
        from integrations.ja4 import _request_ja4
        await update_risk_and_maybe_ban(identity, fired_reason, ip)
        await record(ip, ua, request.path, 200, fired_reason,
                     track_key=identity, sid=_sid, fp=_fp,
                     ja4=_request_ja4(request),
                     request_id=request.get("_rid", ""))

    return web.json_response({"ok": True}, headers={"Cache-Control": "no-store"})


__all__ = [
    "_fp_token_for",
    "_inject_fp_probe",
    "_is_soft_renderer",
    "fp_report_endpoint",
]
