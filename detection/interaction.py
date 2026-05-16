"""
detection/interaction.py — Client-side interaction behavioural probe (v1.8.6).

Analyses mouse dynamics, scroll behaviour, keystroke timing, and overall
event entropy submitted from the JS challenge page.

Event stream format (compact array per event):
  ['m', offset_ms, dx, dy]   — mousemove delta from previous position
  ['s', offset_ms, scroll_y] — absolute scrollY at event time
  ['k', offset_ms, dwell_ms] — keyup: dwell time only, NO key identity logged

Fires into update_risk_and_maybe_ban() with one of:
  no-interaction   (+20)  zero events despite >= 3 s challenge window
  bot-motion       (+25)  perfectly straight-line mouse trajectory
  scripted-motion  (+20)  uniform mouse velocity (σ/μ < 0.05)
  bot-scroll       (+15)  uniform scroll steps (automated wheel)
  scripted-keys    (+15)  uniform keystroke dwell times
  low-entropy-input(+15)  overall event timing autocorrelated or too regular
"""

import asyncio
import hashlib
import hmac
import json
import math
import time as _time
from collections import defaultdict

from aiohttp import web

from config import SESSION_KEY, INTERACTION_PROBE_ENABLED
from helpers import get_ip
from identity import get_identity

_TOKEN_TTL = 300   # seconds — same as fp_enrichment
_MAX_EVENTS = 300  # hard cap on client-submitted event count


# ── Token ─────────────────────────────────────────────────────────────────────

def _interaction_token(ip: str, ts: int) -> str:
    """HMAC binding the probe submission to (IP, timestamp)."""
    msg = f"interaction|{ip}|{ts}".encode()
    return hmac.new(SESSION_KEY, msg, hashlib.sha256).hexdigest()[:32]


# ── JS injection ──────────────────────────────────────────────────────────────

_PROBE_JS = """<script>(function(){{
  var _itok="{tok}",_its={ts};
  var _ev=[],_t0=Date.now(),_lx=-1,_ly=-1,_sent=false;
  function _rec(t,d){{if(_ev.length<300)_ev.push([t,Date.now()-_t0].concat(d));}}
  document.addEventListener('mousemove',function(e){{
    var dx=_lx<0?0:Math.round(e.clientX-_lx);
    var dy=_ly<0?0:Math.round(e.clientY-_ly);
    _lx=e.clientX;_ly=e.clientY;_rec('m',[dx,dy]);
  }},{{passive:true}});
  document.addEventListener('scroll',function(){{
    _rec('s',[Math.round(window.scrollY)]);
  }},{{passive:true}});
  var _kd={{}};
  document.addEventListener('keydown',function(e){{_kd[e.code]=Date.now();}});
  document.addEventListener('keyup',function(e){{
    var d=_kd[e.code];if(d){{_rec('k',[Date.now()-d]);delete _kd[e.code];}}
  }});
  function _send(beacon){{
    if(_sent)return;_sent=true;
    var dur=Date.now()-_t0;
    var p=JSON.stringify({{token:_itok,ts:_its,ev:_ev,dur:dur}});
    try{{
      if(beacon&&navigator.sendBeacon){{
        navigator.sendBeacon('/antibot-appsec-gateway/interaction-report',
          new Blob([p],{{type:'application/json'}}));
      }}else{{
        fetch('/antibot-appsec-gateway/interaction-report',{{
          method:'POST',headers:{{'Content-Type':'application/json'}},
          credentials:'include',body:p,keepalive:true
        }}).catch(function(){{}});
      }}
    }}catch(ex){{}}
  }}
  setTimeout(function(){{_send(false);}},5000);
  window.addEventListener('pagehide',function(){{_send(true);}});
}})();</script>"""


def _inject_interaction_probe(html: str, ip: str) -> str:
    """Inject interaction probe <script> before </body>. No-op when disabled."""
    if not INTERACTION_PROBE_ENABLED:
        return html
    ts = int(_time.time())
    tok = _interaction_token(ip, ts)
    snippet = _PROBE_JS.format(tok=tok, ts=ts)
    lower = html.lower()
    for needle in ("</body>", "</html>"):
        idx = lower.find(needle)
        if idx >= 0:
            return html[:idx] + snippet + html[idx:]
    return html + snippet


# ── Analysis ──────────────────────────────────────────────────────────────────

def _analyze_mouse(mouse_events: list) -> tuple[str | None, str]:
    if len(mouse_events) < 5:
        return None, ""
    dxs = [e[2] for e in mouse_events]
    dys = [e[3] for e in mouse_events]
    # Straight-line: angle variance across moves < 0.05 rad
    angles = [math.atan2(dy, dx) for dx, dy in zip(dxs, dys) if dx != 0 or dy != 0]
    if len(angles) >= 5:
        mean_a = sum(angles) / len(angles)
        std_a = (sum((a - mean_a) ** 2 for a in angles) / len(angles)) ** 0.5
        if std_a < 0.05:
            return "bot-motion", f"straight-line mouse (angle σ={std_a:.3f}rad)"
    # Velocity regularity: σ/μ of inter-event intervals
    times = [e[1] for e in mouse_events]
    intervals = [times[i+1] - times[i] for i in range(len(times) - 1)
                 if times[i+1] > times[i]]
    if len(intervals) >= 5:
        mean_iv = sum(intervals) / len(intervals)
        if mean_iv > 0:
            std_iv = (sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)) ** 0.5
            cov = std_iv / mean_iv
            if cov < 0.05 and mean_iv < 500:
                return "scripted-motion", f"uniform mouse velocity (σ/μ={cov:.3f})"
    return None, ""


def _analyze_scroll(scroll_events: list) -> tuple[str | None, str]:
    if len(scroll_events) < 4:
        return None, ""
    positions = [e[2] for e in scroll_events]
    deltas = [abs(positions[i+1] - positions[i])
              for i in range(len(positions) - 1)
              if positions[i+1] != positions[i]]
    if len(deltas) < 3:
        return None, ""
    # Uniform steps: >85% of deltas in same 20-px bucket
    bins: dict[int, int] = defaultdict(int)
    for d in deltas:
        bins[d // 20] += 1
    max_pct = max(bins.values()) / len(deltas)
    if max_pct > 0.85:
        return "bot-scroll", f"uniform scroll step ({max_pct*100:.0f}% in 20px bin)"
    return None, ""


def _analyze_keys(key_events: list) -> tuple[str | None, str]:
    if len(key_events) < 4:
        return None, ""
    dwells = [e[2] for e in key_events if len(e) >= 3 and e[2] > 0]
    if len(dwells) < 4:
        return None, ""
    mean_d = sum(dwells) / len(dwells)
    if mean_d <= 0:
        return None, ""
    std_d = (sum((d - mean_d) ** 2 for d in dwells) / len(dwells)) ** 0.5
    cov = std_d / mean_d
    if cov < 0.05:
        return "scripted-keys", f"uniform dwell time (σ/μ={cov:.3f})"
    return None, ""


def _analyze_entropy(all_events: list) -> tuple[str | None, str]:
    if len(all_events) < 8:
        return None, ""
    times = sorted(e[1] for e in all_events)
    intervals = [times[i+1] - times[i] for i in range(len(times) - 1)
                 if times[i+1] > times[i]]
    if len(intervals) < 5:
        return None, ""
    mean_iv = sum(intervals) / len(intervals)
    if mean_iv <= 0:
        return None, ""
    std_iv = (sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)) ** 0.5
    cov = std_iv / mean_iv
    # Lag-1 autocorrelation (same as behavioral.py)
    var = std_iv ** 2
    if var > 0:
        num = sum((intervals[i] - mean_iv) * (intervals[i+1] - mean_iv)
                  for i in range(len(intervals) - 1))
        r1 = num / (var * len(intervals))
    else:
        r1 = 1.0
    if cov < 0.05 and mean_iv < 1000:
        return "low-entropy-input", f"event timing too regular (σ/μ={cov:.3f})"
    if r1 > 0.85:
        return "low-entropy-input", f"autocorrelated events (r₁={r1:.2f})"
    return None, ""


_MAX_OFFSET_MS = 60_000   # hard ceiling on any client-submitted timestamp offset

def interaction_analyze(events: list, duration_ms: int) -> tuple[str | None, str]:
    """
    Analyse interaction event stream from the challenge page probe.

    Returns (reason, detail): reason is None on clean, or one of:
      no-interaction, bot-motion, scripted-motion, bot-scroll,
      scripted-keys, low-entropy-input
    """
    if not INTERACTION_PROBE_ENABLED:
        return None, ""
    # Server-side clamp: duration and per-event offset come from the client and
    # must not be trusted at face value. Clamp to the max session window so a
    # bot cannot inflate or invert timestamps to defeat timing analysis.
    duration_ms = max(0, min(int(duration_ms), _MAX_OFFSET_MS))
    # Clamp + type-validate events; pin each offset to [0, _MAX_OFFSET_MS].
    valid = []
    for e in events[:_MAX_EVENTS]:
        if not (isinstance(e, list) and len(e) >= 2 and e[0] in ('m', 's', 'k')):
            continue
        try:
            clamped = [e[0], max(0, min(int(e[1]), _MAX_OFFSET_MS))] + e[2:]
        except (TypeError, ValueError):
            continue
        valid.append(clamped)
    # No events in a >=3 s window → bot loaded challenge page silently
    if duration_ms >= 3000 and not valid:
        return "no-interaction", "zero events in challenge window"
    mouse   = [e for e in valid if e[0] == 'm' and len(e) >= 4]
    scrolls = [e for e in valid if e[0] == 's' and len(e) >= 3]
    keys    = [e for e in valid if e[0] == 'k' and len(e) >= 3]
    for check_fn, subset in (
        (_analyze_mouse,  mouse),
        (_analyze_scroll, scrolls),
        (_analyze_keys,   keys),
    ):
        reason, detail = check_fn(subset)
        if reason:
            return reason, detail
    return _analyze_entropy(valid)


# ── Endpoint ──────────────────────────────────────────────────────────────────

async def interaction_report_endpoint(request: web.Request) -> web.Response:
    """POST /antibot-appsec-gateway/interaction-report
    Receives interaction probe from the JS challenge page.
    Validates HMAC, analyses event stream, updates risk if suspicious."""
    from core.proxy_handler import _probe_rate_limit_ok, BODY_TIMEOUT
    ip = get_ip(request)
    if not _probe_rate_limit_ok(ip):
        return web.Response(status=429, text="rate limit",
                            headers={"Retry-After": "10"})
    if not INTERACTION_PROBE_ENABLED:
        return web.json_response({"ok": False, "reason": "disabled"}, status=400)
    try:
        raw = await asyncio.wait_for(request.content.read(65536),
                                     timeout=BODY_TIMEOUT)
        d = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(d, dict):
            raise ValueError("body must be a JSON object")
    except Exception:
        return web.json_response({"ok": False, "reason": "bad-request"}, status=400)
    try:
        ts_in = int(d.get("ts", 0))
    except (ValueError, TypeError):
        ts_in = 0
    n = int(_time.time())
    if ts_in <= 0 or abs(n - ts_in) > _TOKEN_TTL:
        return web.json_response({"ok": False, "reason": "stale-token"}, status=400)
    expected = _interaction_token(ip, ts_in)
    provided = str(d.get("token", ""))
    if not hmac.compare_digest(expected, provided):
        return web.json_response({"ok": False, "reason": "bad-token"}, status=403)
    events = d.get("ev", [])
    if not isinstance(events, list):
        events = []
    try:
        duration_ms = max(0, min(int(d.get("dur", 0)), _MAX_OFFSET_MS))
    except (ValueError, TypeError):
        duration_ms = 0
    reason, detail = interaction_analyze(events, duration_ms)
    if reason:
        identity, _sid, _fp, _is_new, _id_mode = get_identity(request)
        from scoring import update_risk_and_maybe_ban
        from core.metrics import record
        from integrations.ja4 import _request_ja4
        ua = request.headers.get("User-Agent", "")
        await update_risk_and_maybe_ban(identity, reason, ip)
        await record(ip, ua, request.path, 200, reason,
                     track_key=identity, sid=_sid, fp=_fp,
                     ja4=_request_ja4(request),
                     request_id=request.get("_rid", ""))
    return web.json_response({"ok": True}, headers={"Cache-Control": "no-store"})


__all__ = [
    "INTERACTION_PROBE_ENABLED",
    "_interaction_token",
    "_inject_interaction_probe",
    "interaction_analyze",
    "interaction_report_endpoint",
]
