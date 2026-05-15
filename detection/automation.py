# detection/automation.py — 1.7.1: lightweight browser automation probe
#
# Injects a tiny inline <script> that checks navigator.webdriver and related
# signals, then POSTs to /antibot-appsec-gateway/automation-report if enough
# indicators are set.  Pattern mirrors BotD (canary.py) but is entirely
# self-hosted — no external JS bundle, no third-party dependency.
#
# Report endpoint validates an HMAC token bound to the requester's track_key
# (same scheme as botd_report_endpoint) so an attacker cannot forge a
# "clean" report for someone else.

import asyncio
import hashlib
import hmac
import json
import time as _t

from aiohttp import web

from config import SESSION_KEY, AUTOMATION_PROBE_ENABLED
from helpers import get_ip
from identity import get_identity

_AUTOMATION_REPORT_TTL = 300   # report valid for 5 minutes


def _automation_token_for(track_key: str, ts: int) -> str:
    msg = f"automation|{track_key}|{ts}".encode()
    return hmac.new(SESSION_KEY, msg, hashlib.sha256).hexdigest()[:32]


def _inject_automation_probe(body: bytes, track_key: str) -> bytes:
    """Inject a tiny inline <script> before </body> that checks four
    automation indicators and POSTs to the report endpoint when at least
    two are set.

    Indicators checked:
      webdriver   — navigator.webdriver is truthy (Selenium / Playwright / CDP)
      noPlugins   — navigator.plugins.length === 0 (headless Chrome)
      colorDepth  — screen.colorDepth < 24 (some headless runtimes)
      noChrome    — Chrome UA string but no window.chrome object
    """
    if not AUTOMATION_PROBE_ENABLED or not body or not track_key:
        return body
    n = int(_t.time())
    tok = _automation_token_for(track_key, n)
    snippet = (
        f'<script>(function(){{'
        f'try{{'
        f'var f=!(!navigator.webdriver);'
        f'var p=!!(navigator.plugins&&navigator.plugins.length===0);'
        f'var c=!!(screen.colorDepth<24);'
        f'var w=!!(/Chrome/.test(navigator.userAgent)&&!window.chrome);'
        f'var s=(+f)+(+p)+(+c)+(+w);'
        f'if(s>=2){{'
        f'fetch("/antibot-appsec-gateway/automation-report",{{'
        f'method:"POST",'
        f'headers:{{"Content-Type":"application/json"}},'
        f'credentials:"include",'
        f'body:JSON.stringify({{token:"{tok}",ts:{n},flags:s}})'
        f'}}).catch(function(){{}});'
        f'}}'
        f'}}catch(e){{}}'
        f'}})();</script>'
    ).encode()
    lower = body.lower()
    for needle in (b"</body>", b"</html>"):
        idx = lower.find(needle)
        if idx >= 0:
            return body[:idx] + snippet + body[idx:]
    return body + snippet


async def automation_report_endpoint(request: web.Request):
    """1.7.1 — receive a browser automation probe report.

    Validates the HMAC token (bound to the requester's track_key so an
    attacker cannot forge a clean report for someone else) and bumps risk
    by webdriver-detected when flags >= 2."""
    # Task J — probe rate limiter
    from core.proxy_handler import _probe_rate_limit_ok
    from helpers import get_ip as _get_ip
    if not _probe_rate_limit_ok(_get_ip(request)):
        return web.Response(status=429, text="rate limit",
                            headers={"Retry-After": "10"})
    if not AUTOMATION_PROBE_ENABLED:
        return web.json_response({"ok": False, "reason": "disabled"}, status=400)
    try:
        from core.proxy_handler import BODY_TIMEOUT
        raw = await asyncio.wait_for(
            request.content.read(4096), timeout=BODY_TIMEOUT)
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
    if ts_in <= 0 or abs(n - ts_in) > _AUTOMATION_REPORT_TTL:
        return web.json_response({"ok": False, "reason": "stale-token"}, status=400)

    expected = _automation_token_for(identity, ts_in)
    provided = str(d.get("token", ""))
    if not hmac.compare_digest(expected, provided):
        return web.json_response({"ok": False, "reason": "bad-token"}, status=403)

    try:
        flags = int(d.get("flags", 0))
    except (ValueError, TypeError):
        flags = 0

    if flags >= 2:
        from scoring import update_risk_and_maybe_ban
        from core.metrics import record
        from integrations.ja4 import _request_ja4
        ua = request.headers.get("User-Agent", "")
        await update_risk_and_maybe_ban(identity, "webdriver-detected", ip)
        await record(ip, ua, request.path, 200, "webdriver-detected",
                     track_key=identity, sid=_sid, fp=_fp,
                     ja4=_request_ja4(request),
                     request_id=request.get("_rid", ""))

    return web.json_response({"ok": True}, headers={"Cache-Control": "no-store"})


__all__ = [
    "_automation_token_for",
    "_inject_automation_probe",
    "automation_report_endpoint",
]
