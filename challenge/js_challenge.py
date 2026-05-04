"""
challenge/js_challenge.py — JS challenge: Turnstile + Anubis cookie gate.
Extracted from proxy.py as part of Phase 6 modular refactoring.

Depends on:
  config.py  — JS_CHALLENGE, JS_CHALLENGE_TTL, CHAL_NONCE_TTL, CHAL_COOKIE,
                ANUBIS_ENABLED, ANUBIS_DIFFICULTY_BOOST,
                TURNSTILE_SITEKEY, TURNSTILE_SECRET, TURNSTILE_ENABLED,
                TURNSTILE_VERIFY_URL, TURNSTILE_RISK_THRESHOLD,
                _TURNSTILE_CONFIGURED, JS_CHAL_REQUIRE_JA4, JS_CHAL_BIND_JA4,
                JS_CHAL_STRICT_STATIC, JS_CHAL_OPEN_PATHS,
                SESSION_KEY, SESSION_SAMESITE, SESSION_SECURE,
                SOFT_CHALLENGE_SCORE, RISK_BAN_THRESHOLD,
                SW_CHALLENGE_ENABLED, POW_CHAL_THRESHOLD
  state.py   — ip_state
  helpers.py — slog, now, get_ip

  Functions still in proxy.py (late-imported to avoid circular deps):
    _is_admin_path, _endpoint_policy, _decay_risk,
    _record_chal_mint, _new_canary, _inject_canary,
    CANARY_ECHO_DETECTION, HEADER_CANARY_ENABLED,
    BODY_TIMEOUT, JA4_TRUSTED_NETS, JA4_HEADER,
    SESSION_CHURN_WINDOW_S, SESSION_CHURN_MAX
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time

from aiohttp import web, ClientSession, ClientTimeout

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from helpers import slog, now, get_ip


# ── IP-tier helpers ───────────────────────────────────────────────────────

def _ip_tier(ip: str) -> str:
    """V9: collapse client IP to a coarse network tier (v4 /24, v6 /48) so
    the chal cookie can be IP-bound without breaking ordinary mobile / NAT
    rebinds. Returns empty string for unparseable input. Note: this is the
    *raw* tier (e.g. "203.0.113.0") used only inside the HMAC payload — the
    cookie carries an opaque tier hash, never the raw value."""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address)
        return str(ipaddress.ip_network(f"{ip}/48", strict=False).network_address)
    except Exception:
        return ""


def _tier_hash(raw_tier: str) -> str:
    """V9.1: convert the raw network tier into an opaque 16-char hex digest
    so the cookie value never carries an RFC1918 / internal IP. Server-side
    only — verification re-derives this from the request-side raw tier."""
    if not raw_tier:
        return ""
    return hmac.new(SESSION_KEY, b"tier|" + raw_tier.encode(),
                    hashlib.sha256).hexdigest()[:16]


def _is_hex16(s: str) -> bool:
    return len(s) == 16 and all(c in "0123456789abcdef" for c in s)


# ── JA4 fingerprint helpers ───────────────────────────────────────────────
# Canonical implementations live in integrations/ja4.py — imported here so
# the cookie mint/verify paths in this module pick them up without duplication.

from integrations.ja4 import _ja4_peer_trusted, _request_ja4, _ja4_hash  # noqa: F401,E402


# ── Turnstile threshold ───────────────────────────────────────────────────

def _turnstile_active_threshold() -> float:
    """Resolve the threshold dynamically: explicit knob if set, else mid-orange."""
    if TURNSTILE_RISK_THRESHOLD > 0:
        return TURNSTILE_RISK_THRESHOLD
    return (SOFT_CHALLENGE_SCORE + RISK_BAN_THRESHOLD) / 2.0


# ── Nonce helpers ─────────────────────────────────────────────────────────

def _make_chal_nonce() -> str:
    nonce = secrets.token_hex(8)
    issued = str(int(time.time()))
    payload = f"{nonce}|{issued}"
    sig = hmac.new(SESSION_KEY, payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload}|{sig}"


def _verify_chal_nonce(token: str) -> bool:
    if not token:
        return False
    parts = token.split("|")
    if len(parts) != 3:
        return False
    nonce, issued, sig = parts
    expected = hmac.new(SESSION_KEY, f"{nonce}|{issued}".encode(),
                        hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        if int(time.time()) - int(issued) > CHAL_NONCE_TTL:
            return False
    except ValueError:
        return False
    return True


# ── Cookie mint / verify ──────────────────────────────────────────────────

def _make_chal_cookie(ua: str, probe_hash: str = "", ip_tier: str = "",
                      ja4: str = "") -> str:
    """V9.2: cookie is bound to (UA + probe-hash + tier-HASH + JA4-HASH).
    The HMAC payload uses the raw tier + raw JA4 (cryptographically strong),
    but the cookie value carries only opaque hashes — no internal IP /
    network leak, and the JA4 fingerprint isn't disclosed either."""
    issued = str(int(time.time()))
    payload = (f"chal|{ua[:200]}|{probe_hash}|{ip_tier}|{ja4}|{issued}")
    sig = hmac.new(SESSION_KEY, payload.encode(),
                   hashlib.sha256).hexdigest()
    return (f"{issued}|{probe_hash}|{_tier_hash(ip_tier)}"
            f"|{_ja4_hash(ja4)}|{sig}")


def _verify_chal_cookie(value: str, ua: str, ip_tier: str = "",
                         ja4: str = "") -> bool:
    if not value:
        return False
    parts = value.split("|")
    # V9.2 format: issued|probe_hash|tier_hash|ja4_hash|sig  (5 parts)
    # V9.1 format: issued|probe_hash|tier_hash|sig           (4 parts, hex16)
    # V9.0 legacy: issued|probe_hash|raw_tier|sig            (4 parts, raw IP)
    # V1  format: issued|probe_hash|sig                      (3 parts)
    # Old format: issued|sig                                 (2 parts)
    # `payload_tier` / `payload_ja4` are what were hashed into the HMAC at
    # mint time. Older cookies omitted these — must reproduce that exact
    # construction or the signature comparison breaks for legacy users.
    legacy_v9_raw = False
    cookie_ja4_hash = ""
    payload_ja4     = ""
    if len(parts) == 5:
        # V9.2 — tier_hash + ja4_hash in wire; raw tier + raw ja4 in HMAC.
        issued, probe_hash, third, fourth, sig = parts
        # 3rd field (tier_hash). Empty = minted without IP binding.
        if _is_hex16(third):
            cookie_tier_hash = third
            payload_tier     = ip_tier
        elif third == "":
            cookie_tier_hash = ""
            payload_tier     = ""
        else:
            return False                   # raw IPs aren't valid in V9.2
        # 4th field (ja4_hash). Empty = minted without JA4 binding.
        if _is_hex16(fourth):
            cookie_ja4_hash = fourth
            payload_ja4     = ja4
        elif fourth == "":
            cookie_ja4_hash = ""
            payload_ja4     = ""
        else:
            return False
    elif len(parts) == 4:
        issued, probe_hash, third, sig = parts
        if _is_hex16(third):
            # V9.1 cookie — tier_hash in the wire format, raw tier in the
            # HMAC payload. Verifier re-derives raw tier from the request.
            cookie_tier_hash = third
            payload_tier     = ip_tier
        elif third == "":
            # 4-part with empty 3rd field — minted without IP binding (e.g.
            # by tests calling _make_chal_cookie(ua) with no ip_tier). Treat
            # like V1: HMAC payload also used empty tier.
            cookie_tier_hash = ""
            payload_tier     = ""
        else:
            # V9.0 cookie — raw tier baked into both wire format and payload.
            cookie_tier_hash = ""
            payload_tier     = third
            legacy_v9_raw    = True
    elif len(parts) == 3:
        issued, probe_hash, sig = parts
        cookie_tier_hash = ""
        payload_tier     = ""        # V1 cookies had no tier in payload
    elif len(parts) == 2:
        issued, sig = parts
        probe_hash       = ""
        cookie_tier_hash = ""
        payload_tier     = ""        # pre-V1 cookies had no probe + no tier
    else:
        return False
    if len(parts) == 5:
        sig_payload = (f"chal|{ua[:200]}|{probe_hash}|{payload_tier}"
                       f"|{payload_ja4}|{issued}")
    else:
        sig_payload = (f"chal|{ua[:200]}|{probe_hash}|{payload_tier}"
                       f"|{issued}")
    expected = hmac.new(SESSION_KEY, sig_payload.encode(),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    # V9.1: tier-hash binding. If the cookie carries a tier_hash, the
    # request-side tier must hash to the same value. Empty cookie_tier_hash
    # means legacy 3- / 2-part / V9.0 — no tier check on the wire field.
    if cookie_tier_hash and ip_tier:
        if not hmac.compare_digest(cookie_tier_hash, _tier_hash(ip_tier)):
            return False
    # V9.0 legacy raw-tier cookie: also enforce match against current tier
    # (the sig already binds it via payload_tier=third, but tighten anyway).
    if legacy_v9_raw and ip_tier and payload_tier != ip_tier:
        return False
    # V9.2: JA4-hash binding. If the cookie carries a ja4_hash, the
    # request-side JA4 must hash to the same value. Empty cookie_ja4_hash
    # means cookie was minted without JA4 visible — no enforcement.
    if cookie_ja4_hash and ja4:
        if not hmac.compare_digest(cookie_ja4_hash, _ja4_hash(ja4)):
            return False
    try:
        if int(time.time()) - int(issued) > JS_CHALLENGE_TTL:
            return False
    except ValueError:
        return False
    return True


# ── Challenge HTML ────────────────────────────────────────────────────────

JS_CHAL_HTML = """<!doctype html><html lang=en><head><meta charset=utf-8>
<title>Verifying...</title>
<meta name=robots content=noindex>
<style>html,body{margin:0;height:100%}body{display:flex;flex-direction:column;
align-items:center;justify-content:center;font:14px/1.5 system-ui,sans-serif;
color:#444;background:#fafafa}.spinner{width:24px;height:24px;border:3px solid #eee;
border-top-color:#3fb950;border-radius:50%;animation:s 0.8s linear infinite;
margin-bottom:16px}@keyframes s{to{transform:rotate(360deg)}}#cf-ts{margin-top:8px}</style>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head><body>
<div class=spinner></div>
<p>Verifying browser...</p>
<div id=cf-ts></div>
<noscript><p>JavaScript is required to access this site.</p></noscript>
<script>
(async()=>{
  const n = "__NONCE__", t = "__TARGET__", TS_KEY = "__TURNSTILE_KEY__";
  const POW_CHALLENGE = "__POW_CHALLENGE__";
  const SW_ENABLED = __SW_ENABLED__;

  // 1.7.2 — Service Worker registration (opt-in via SW_CHALLENGE_ENABLED)
  if (SW_ENABLED && 'serviceWorker' in navigator) {
    navigator.serviceWorker.register('/antibot-appsec-gateway/sw.js', {scope: '/'})
      .catch(function(){});
  }

  // 1.7.2 — PoW solver (WebWorker inline blob). Activated when POW_CHALLENGE != "".
  function solvePoW(challenge) {
    return new Promise((resolve) => {
      const parts = challenge.split('|');
      const diff = parseInt(parts[2], 10);
      const prefix = '0'.repeat(diff);
      const nonce = parts[0];
      const blob = new Blob([`
        const nonce="${nonce}", prefix="${prefix}";
        let i=0;
        while(true){
          const candidate=i.toString(36);
          const msg=nonce+candidate;
          // Use SubtleCrypto for SHA-256
          crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg)).then(buf=>{
            const hex=Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
            if(hex.startsWith(prefix)){ postMessage(candidate); }
          });
          i++;
          if(i%5000===0){ /* yield */ }
        }
      `], {type:'application/javascript'});
      const url = URL.createObjectURL(blob);
      const w = new Worker(url);
      w.onmessage = e => { w.terminate(); URL.revokeObjectURL(url); resolve(e.data); };
    });
  }

  function waitForTurnstile(){
    return new Promise((resolve, reject)=>{
      const t0 = Date.now();
      function tick(){
        if(window.turnstile){
          window.turnstile.render('#cf-ts',{
            sitekey: TS_KEY,
            callback: tok => resolve(tok),
            'error-callback': () => reject(new Error('turnstile error')),
          });
        } else if (Date.now()-t0 < 30000) { setTimeout(tick, 200); }
        else { reject(new Error('turnstile load timeout')); }
      }
      tick();
    });
  }

  try{
    // Start PoW solving in parallel with Turnstile if a challenge is embedded
    const powPromise = POW_CHALLENGE ? solvePoW(POW_CHALLENGE) : Promise.resolve(null);

    const tsToken = await waitForTurnstile();
    const params = {n, t, 'cf-turnstile-response': tsToken};

    // If PoW challenge was embedded, wait for solution and include it
    if (POW_CHALLENGE) {
      document.querySelector('p').textContent = 'Solving security puzzle...';
      const powSol = await powPromise;
      params['pow_token']    = POW_CHALLENGE;
      params['pow_solution'] = powSol;
    }

    const fd = new URLSearchParams(params);
    const r = await fetch('/antibot-appsec-gateway/challenge', {
      method: 'POST', body: fd, credentials: 'include',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    });
    if (r.ok) { location.replace(t); }
    else { document.querySelector('p').textContent =
              'Verification failed (' + r.status + ').'; }
  } catch(e) {
    document.querySelector('p').textContent = 'Verification error: ' + e.message;
  }
})();
</script></body></html>"""

# Static-asset extensions used by JS-challenge (to skip them).
_STATIC_ASSET_SUFFIXES = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".otf",
    ".eot", ".map", ".mp4", ".webm", ".mp3", ".ogg",
)

# v1.4.1 (post-V8 hardening): when JS_CHAL_STRICT_STATIC=1, the static-asset
# bypass refuses to skip anything that LOOKS like an API path (so a bot can't
# slip past the cookie gate via /api/v1/users.css). Default ON.
# Canonical implementation lives in integrations/endpoint_policy.py.
from integrations.endpoint_policy import _looks_like_api, _API_PATH_HINTS  # noqa: F401,E402


# ── Serve challenge page ──────────────────────────────────────────────────

def _serve_js_challenge(request: web.Request, pow_challenge: str = ""):
    """Render the Turnstile challenge page. Only invoked when JS_CHALLENGE is
    enabled AND Turnstile is configured.

    1.7.2: when pow_challenge is provided (non-empty HMAC-signed PoW token),
    it is embedded in the HTML so the client-side WebWorker solver starts
    immediately in parallel with Turnstile. The solution is submitted together
    with the Turnstile token in a single POST to /challenge."""
    nonce = _make_chal_nonce()
    target = request.path_qs or "/"
    target_safe = re.sub(r'[^A-Za-z0-9_\-./?&=%:#]', '', target)[:512] or "/"
    if (not target_safe.startswith("/")
            or target_safe.startswith("//")
            or "\\" in target_safe):
        target_safe = "/"
    nonce_json      = json.dumps(nonce)
    target_json     = json.dumps(target_safe)
    ts_key_json     = json.dumps(TURNSTILE_SITEKEY)
    pow_chal_json   = json.dumps(pow_challenge)
    sw_enabled_json = "true" if SW_CHALLENGE_ENABLED else "false"
    html = (JS_CHAL_HTML
            .replace('"__NONCE__"',         nonce_json)
            .replace('"__TARGET__"',        target_json)
            .replace('"__TURNSTILE_KEY__"', ts_key_json)
            .replace('"__POW_CHALLENGE__"', pow_chal_json)
            .replace('__SW_ENABLED__',      sw_enabled_json))
    # R7: plant a canary on the challenge page too — the LLM summariser
    # reads the gateway's HTML before it ever reaches upstream content.
    headers = {
        "Cache-Control": "no-store",
        "X-Robots-Tag": "noindex",
        # Own CSP so upstream's restrictive policy never blocks Turnstile.
        "Content-Security-Policy": (
            "default-src 'none'; "
            "script-src 'unsafe-inline' https://challenges.cloudflare.com; "
            "style-src 'unsafe-inline'; "
            "connect-src 'self'; "
            "frame-src https://challenges.cloudflare.com; "
            "worker-src blob: 'self'; "
            "img-src data:; "
            "frame-ancestors 'none'; base-uri 'none'"
        ),
    }
    # Late import: canary helpers live in proxy.py still
    from detection.canary import _new_canary, _inject_canary
    from core.proxy_handler import BODY_TIMEOUT, _chal_mint_count, _record_chal_mint
    from helpers import _is_admin_path
    from integrations.endpoint_policy import _endpoint_policy
    from scoring import _decay_risk
    if CANARY_ECHO_DETECTION:
        canary = _new_canary()
        html = _inject_canary(html.encode(), canary).decode("utf-8")
        headers["X-Trace-Id"] = canary
        if HEADER_CANARY_ENABLED:
            headers["ETag"]         = f'"{canary}"'
            headers["X-Request-Id"] = canary
    return web.Response(status=200, text=html, content_type="text/html",
                        headers=headers)


# ── Challenge endpoint (Turnstile siteverify) ─────────────────────────────

async def js_challenge_endpoint(request: web.Request):
    """Turnstile-backed cookie minter.

    Every input on this endpoint that is computed by the client (PoW,
    browser-API probe, anchor-fetch proof, timing window) was empirically
    bypassable in pure Python — see the Threat-model section in README.md.
    Those layers are removed: the only check that the attacker cannot
    fabricate locally is the Cloudflare Turnstile token, which is minted
    server-side by Cloudflare and verified at /turnstile/v0/siteverify.

    Without `TURNSTILE_SITEKEY` + `TURNSTILE_SECRET` configured, the
    JS-challenge feature is a no-op (the middleware never routes here);
    operators rely on the gateway's other layers (UA filter, header
    completeness, behavioral, rate-limits, risk-score model)."""
    if request.method != "POST":
        return web.Response(status=405)
    if not TURNSTILE_ENABLED:
        # Defensive: middleware is supposed to disable the gate when
        # Turnstile is unconfigured, but if anyone hits us directly bail
        # rather than mint a free cookie.
        return web.Response(status=503, text="challenge unavailable\n")
    # Late import: BODY_TIMEOUT lives in proxy.py still
    try:
        body = await asyncio.wait_for(request.content.read(16384),
                                      timeout=BODY_TIMEOUT)
    except asyncio.TimeoutError:
        return web.Response(status=408, text="timeout\n")
    from urllib.parse import parse_qs
    try:
        params = parse_qs(body.decode("utf-8", errors="replace"))
    except Exception:
        return web.Response(status=400, text="bad form\n")

    nonce = params.get("n", [""])[0]
    if not _verify_chal_nonce(nonce):
        slog("chal_bad_nonce", level="warning", ip=get_ip(request),
             keys=list(params.keys()))
        return web.Response(status=400, text="bad nonce\n")

    # Cloudflare Turnstile siteverify — the only real boundary.
    ts_token = (params.get("cf-turnstile-response", [""])[0] or "").strip()
    slog("chal_token_recv", level="info", present=bool(ts_token),
         token_len=len(ts_token), token_prefix=ts_token[:24],
         keys=list(params.keys()), ip=get_ip(request))
    if not ts_token:
        return web.Response(status=403, text="missing turnstile\n")
    try:
        verify_data = {
            "secret":   TURNSTILE_SECRET,
            "response": ts_token,
            "remoteip": get_ip(request),
        }
        async with ClientSession(
                timeout=ClientTimeout(total=5)) as session:
            async with session.post(TURNSTILE_VERIFY_URL,
                                     data=verify_data) as ts_resp:
                ts_json = await ts_resp.json(content_type=None)
    except Exception as exc:
        slog("chal_siteverify_err", level="error", err=str(exc),
             ip=get_ip(request))
        return web.Response(status=502, text="turnstile verify failed\n")
    slog("chal_siteverify_resp", level="info" if ts_json.get("success") else "warning",
         success=ts_json.get("success"), error_codes=ts_json.get("error-codes", []),
         hostname=ts_json.get("hostname", ""), ip=get_ip(request))
    if not ts_json.get("success"):
        return web.Response(status=403, text="turnstile rejected\n")

    # 1.7.2 — PoW verification (risk-gated). When the challenge page embedded
    # a PoW token (because the identity's risk crossed POW_CHAL_THRESHOLD),
    # the client submits pow_token + pow_solution. Verify both are present and
    # correct before minting the cookie.
    pow_token    = (params.get("pow_token",    [""])[0] or "").strip()
    pow_solution = (params.get("pow_solution", [""])[0] or "").strip()
    if pow_token:
        from challenge.pow import verify_pow as _verify_pow
        ok, why = _verify_pow(pow_token, pow_solution, "*", "*")
        if not ok:
            return web.Response(status=403, text=f"pow rejected: {why}\n")

    # JA4 cookie-binding (opportunistic; opt-in hard requirement).
    ja4 = _request_ja4(request)
    if JS_CHAL_REQUIRE_JA4 and not ja4:
        return web.Response(status=403, text="ja4 required\n")

    ua = request.headers.get("User-Agent", "")
    ip_tier = _ip_tier(get_ip(request))
    bind_ja4 = ja4 if (JS_CHAL_BIND_JA4 and ja4) else ""
    # `probe_hash` is reused as a non-replayable per-session salt — we
    # take it from the (server-generated) Turnstile token so the cookie
    # is tied to a specific verification.
    sess_salt = hashlib.sha256(ts_token.encode()).hexdigest()[:16]
    cookie = _make_chal_cookie(ua, sess_salt, ip_tier, bind_ja4)
    # 1.6.5 — count successful chal-cookie mints (Turnstile path).
    import core.proxy_handler as _ph
    from identity import _record_chal_mint as _rcm
    _ph._chal_mint_count += 1
    resp = web.Response(status=200, text="ok",
                        headers={"Cache-Control": "no-store"})
    resp.set_cookie(CHAL_COOKIE, cookie,
                    httponly=True,
                    samesite=SESSION_SAMESITE,
                    secure=SESSION_SECURE,
                    path="/", max_age=JS_CHALLENGE_TTL)
    # 1.5.0: same churn check on the Turnstile path. Even though Turnstile
    # itself raises the cost, an attacker that can solve Turnstile (e.g.
    # via a paid CAPTCHA-farm) and then mints many cookies still trips this.
    await _rcm(
        ua, ip_tier, ja4, get_ip(request),
        rid=request.get("_rid", ""))
    return resp


# ── Gate checks ───────────────────────────────────────────────────────────

def _js_challenge_required(request) -> bool:
    """True iff the JS challenge gate is on AND this request must carry a
    valid chal cookie but doesn't. The gate engages whenever JS_CHALLENGE=1.
    Cookie minting depends on configuration:
      • TURNSTILE_SITEKEY/SECRET set → Turnstile siteverify mints the cookie
        (production-grade boundary; only widget-solved tokens validate).
      • Otherwise → cookie auto-minted at the end of any allowed HTML GET
        (heuristic friction layer — clients must pass UA/header/behavioural
        screens AND complete one round trip before reaching API paths,
        without requiring any third-party service)."""
    # 1.5.4: ANUBIS_ENABLED forces the gate even if JS_CHALLENGE=0.
    if not (JS_CHALLENGE or ANUBIS_ENABLED):
        return False
    from helpers import _is_admin_path
    from integrations.endpoint_policy import _endpoint_policy
    if _is_admin_path(request.path):
        return False  # admin / challenge-solver have their own auth
    # 1.6.0 — per-endpoint policy engine. Resolve the policy ONCE per
    # request and use it to decide gate behaviour. 'bypass' wins over
    # static-asset short-circuit (operator opted-in to expose the route).
    _epol = _endpoint_policy(request.path)
    if _epol == "bypass":
        return False
    if request.path.endswith(_STATIC_ASSET_SUFFIXES):
        # V8 hardening: don't trust a `.css` suffix on what looks like an API
        # path. Permissive backends (Spring suffix matching, Express trailing
        # tokens) would otherwise return JSON for `/api/v1/users.css`.
        if not (JS_CHAL_STRICT_STATIC and _looks_like_api(request.path)):
            # 'challenge'/'strict' policies override the static-asset
            # exemption so an operator can lock down a `*.json` API route.
            if _epol not in ("challenge", "strict"):
                return False  # public assets
    # 'challenge' / 'strict' bypass the JS_CHAL_OPEN_PATHS exemption entirely.
    if _epol in ("challenge", "strict"):
        is_open_path = False
    else:
        is_open_path = any(request.path.startswith(p) for p in JS_CHAL_OPEN_PATHS)
    if is_open_path:
        # 1.5.3 soft-challenge tier: open-path bypass is REVOKED when this
        # identity's risk score has climbed into the soft-challenge band
        # (SOFT_CHALLENGE_SCORE ≤ score < RISK_BAN_THRESHOLD). Forces a fresh
        # cookie mint on a path that would otherwise be exempt.
        track_key = request.get("_track_key")
        if track_key and SOFT_CHALLENGE_SCORE > 0:
            s = ip_state.get(track_key)
            if s and SOFT_CHALLENGE_SCORE <= s.risk_score < RISK_BAN_THRESHOLD:
                # fall through to the cookie verify
                pass
            else:
                return False
        else:
            return False
    return not _verify_chal_cookie(
        request.cookies.get(CHAL_COOKIE, ""),
        request.headers.get("User-Agent", ""),
        _ip_tier(get_ip(request)),
        _request_ja4(request))


def _js_challenge_applicable(request) -> bool:
    """True iff we should serve the interactive JS challenge HTML page.
    Only fires in Turnstile mode — without Turnstile, HTML GETs are
    forwarded normally and the cookie is auto-minted on the response.
    Only navigation-style HTML GETs see the page — non-HTML / non-GET
    requests without the cookie are silent-decoyed instead.

    1.5.4 — Turnstile is shown only when the identity's risk_score has
    crossed `_turnstile_active_threshold()` (mid-orange band by default).
    Below that, fresh clients fall through to the auto-mint heuristic —
    most legitimate users never see Turnstile, only suspected bots do.
    """
    if not _js_challenge_required(request):
        return False
    if not TURNSTILE_ENABLED:
        return False
    # 1.5.4 — gate Turnstile on the identity's risk score.
    track_key = request.get("_track_key")
    if track_key:
        s = ip_state.get(track_key)
        if s:
            _decay_risk(s, now())
            thr = _turnstile_active_threshold()
            if s.risk_score < thr:
                return False
    if request.method != "GET":
        return False
    return "text/html" in request.headers.get("Accept", "")


# ── 1.7.2 — Service Worker endpoint ──────────────────────────────────────────

_SW_SCRIPT = """\
// AppSecGW 1.7.2 — Service Worker (SW_CHALLENGE_ENABLED)
// Intercepts requests to /antibot-appsec-gateway/* and adds X-SW-Active: 1
// so the server can confirm the browser executed JS across sessions.
self.addEventListener('install', function(e) { self.skipWaiting(); });
self.addEventListener('activate', function(e) { e.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function(e) {
  var url = e.request.url;
  if (url.indexOf('/antibot-appsec-gateway/') !== -1) {
    try {
      var h = new Headers(e.request.headers);
      h.set('X-SW-Active', '1');
      e.respondWith(fetch(new Request(e.request, {headers: h})));
    } catch(err) {
      // Fall through to default fetch on any error
    }
  }
});
"""


async def sw_js_endpoint(request: web.Request):
    """Serve the Service Worker script. No auth required — public endpoint.
    Cache-Control: no-store so updated SW logic deploys immediately."""
    if not SW_CHALLENGE_ENABLED:
        return web.Response(status=404, text="not found\n")
    return web.Response(
        text=_SW_SCRIPT,
        content_type="application/javascript",
        headers={
            "Cache-Control":       "no-store, no-cache, must-revalidate",
            "Service-Worker-Allowed": "/",
            "X-Content-Type-Options": "nosniff",
        },
    )
