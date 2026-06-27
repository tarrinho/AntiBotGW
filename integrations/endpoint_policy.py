"""
integrations/endpoint_policy.py — Per-endpoint policy engine + custom rules.

Tier A: per-endpoint policy (bypass / challenge / strict / default).
Tier B: custom rules engine (Cloudflare-Custom-Rules parity).
Tier B: per-endpoint token-bucket rate limiting.

Converter functions (_to_bool, _to_path_list, etc.) are used by the
hot-reload knob table (_HOT_RELOAD_KNOBS) that lives in proxy.py and
by the ENDPOINT_POLICIES / CUSTOM_RULES initialisation below.

Note: _to_bool here is different from _to_bool_default_true in helpers.py —
both are kept; they have different semantics (strict parse vs. default-true).

Extracted from proxy.py as part of Phase 7 modular refactoring.

Depends on:
  config.py     — ENDPOINT_POLICIES_RAW, CUSTOM_RULES_RAW, CUSTOM_RULES,
                  ENDPOINT_POLICIES (populated here from the RAW strings)
  reputation/   — _city_lookup, _city_reader (via `from reputation import *`
                  already in proxy.py's namespace; referenced at call time)
  helpers.py    — slog
"""

import asyncio
import fnmatch as _fnmatch
import ipaddress as _ipaddress
import json
import time

from config import *   # noqa: F401,F403
from helpers import slog


# ── Type-coercion helpers (used by _HOT_RELOAD_KNOBS in proxy.py) ─────────

def _to_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off", ""):
        return False
    raise ValueError(f"not a boolean: {v!r}")


def _to_path_list(v) -> list:
    """Comma-separated → list of stripped non-empty path prefixes."""
    if isinstance(v, list):
        return [str(p).strip() for p in v if str(p).strip()]
    return [p.strip() for p in str(v).split(",") if p.strip()]


def _to_ja4_set(v) -> set:
    if isinstance(v, list):
        return {str(p).strip() for p in v if str(p).strip()}
    return {p.strip() for p in str(v).split(",") if p.strip()}


def _to_method_set(v) -> set:
    """Comma-separated → set of UPPER-cased HTTP methods."""
    if isinstance(v, (list, set)):
        return {str(m).strip().upper() for m in v if str(m).strip()}
    return {m.strip().upper() for m in str(v).split(",") if m.strip()}


def _to_host_set(v) -> set:
    """Comma-separated → set of lower-cased bare hostnames.
    Strips scheme (https://) and path/trailing-slash so operators can
    supply either 'example.com' or 'https://example.com/' — both work."""
    from urllib.parse import urlparse as _urlparse

    def _normalise(h: str) -> str:
        h = h.strip()
        if not h:
            return ""
        # If it looks like a URL (has a scheme), parse it; otherwise treat
        # as a bare hostname and parse with a dummy scheme so urlparse works.
        parsed = _urlparse(h if "://" in h else "x://" + h)
        return (parsed.hostname or "").lower()

    if isinstance(v, (list, set)):
        return {_normalise(str(h)) for h in v if _normalise(str(h))}
    return {_normalise(h) for h in str(v).split(",") if _normalise(h)}


def _to_country_set(v) -> set:
    """Comma-separated → set of UPPER-cased ISO-3166-1 alpha-2 codes.
    Drops anything that isn't a 2-letter token (rejects names, EU, etc.)."""
    if isinstance(v, (list, set)):
        items = [str(c).strip().upper() for c in v if str(c).strip()]
    else:
        items = [c.strip().upper() for c in str(v).split(",") if c.strip()]
    return {c for c in items if len(c) == 2 and c.isalpha()}


def _to_ip_net_list(v) -> list:
    """Comma/newline-separated IPs or CIDRs → list of normalised CIDR strings.
    Drops invalid entries so a typo never blocks startup BUT logs each
    rejection so the operator sees `TRUSTED_PROXIES=10.0.0.0/33` actually
    landed as an empty list (iter-9 code-review MED-1)."""
    import ipaddress as _ipmod
    if isinstance(v, list):
        items = [str(x).strip() for x in v if str(x).strip()]
    else:
        items = [x.strip() for x in str(v).replace("\n", ",").split(",") if x.strip()]
    result = []
    for item in items:
        try:
            result.append(str(_ipmod.ip_network(item, strict=False)))
        except ValueError as _e:
            try:
                slog("ip_net_list_rejected_entry", level="warn",
                     entry=item[:80], reason=str(_e)[:120],
                     note="silent drop is by design (a typo must not "
                          "block boot) but each rejection is logged so "
                          "operators see why their CIDR list looks empty")
            except Exception:
                pass  # nosec B110 — never block on a log path
    return result


def _to_endpoint_policies(v):
    """1.6.0 — parse the per-endpoint policy spec into a list of dicts:
    [{"path": "<glob>", "policy": "...", "rps": <int|None>, "burst": <int|None>}].
    Accepts a JSON string, a decoded list, or [path, policy] pairs (legacy).
    1.6.1 — also accepts optional `rps` + `burst` for per-endpoint
    rate-limit (Tier B). Missing means "no per-endpoint cap"."""
    _VALID = ("bypass", "challenge", "strict", "default")
    if v is None or v == "" or v == []:
        return []
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except (ValueError, json.JSONDecodeError):
            return []
    if not isinstance(v, list):
        raise ValueError("endpoint policies must be a JSON array")
    out = []
    for item in v:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            path = str(item[0]).strip()
            policy = str(item[1]).strip().lower()
            rps = burst = None
        elif isinstance(item, dict):
            path = str(item.get("path", "")).strip()
            policy = str(item.get("policy", "default")).strip().lower()
            try:
                rps = float(item["rps"]) if "rps" in item and item["rps"] not in (None, "") else None
                burst = int(item["burst"]) if "burst" in item and item["burst"] not in (None, "") else None
            except (ValueError, TypeError):
                rps = burst = None
        else:
            continue
        if not path or policy not in _VALID:
            continue
        if rps is not None and not (0 < rps <= 10000):
            rps = None
        if burst is not None and not (1 <= burst <= 100000):
            burst = None
        out.append({"path": path, "policy": policy, "rps": rps, "burst": burst})
    return out


def _to_custom_rules(v):
    """1.6.1 — parse CUSTOM_RULES (Tier B Cloudflare-Custom-Rules parity).
    Accepts a JSON string, a decoded list of dicts, or empty.
    Each rule is a dict: {"if": {<conds>}, "then": <action>, "tag": <opt>}
    Conditions (all must match — AND):
      path:<glob>, method:<list/str>, ua_contains:<str>,
      header.<Name>:<substring>,  query.<param>:<exact>,
      ip_cidr:<cidr/list>, country:<iso/list>
    Actions: allow | block | challenge | tag
    Returns a sanitised list (gateway-safe, empty on parse fail)."""
    _ACTIONS = ("allow", "block", "challenge", "tag", "authorized-robot")
    if v is None or v == "" or v == []:
        return []
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except (ValueError, json.JSONDecodeError):
            return []
    if not isinstance(v, list):
        raise ValueError("custom rules must be a JSON array")
    out = []
    for item in v:
        if not isinstance(item, dict):
            continue
        cond = item.get("if") or {}
        action = str(item.get("then", "")).strip().lower()
        tag = str(item.get("tag", "")).strip()
        if not isinstance(cond, dict) or action not in _ACTIONS:
            continue
        # Pre-compile ip_cidr for O(1) matching; keep raw strings in ip_cidr
        # so the rule dict stays JSON-serialisable for config state output.
        cidrs = cond.get("ip_cidr")
        if cidrs is not None:
            if not isinstance(cidrs, list):
                cidrs = [cidrs]
            raw = [str(c).strip() for c in cidrs if str(c).strip()]
            try:
                compiled = [_ipaddress.ip_network(c, strict=False) for c in raw]
            except (ValueError, TypeError):
                continue
            # ip_cidr = strings (JSON-safe); _ip_nets = compiled (matching only)
            cond = dict(cond, ip_cidr=raw, _ip_nets=compiled)
        out.append({"if": cond, "then": action, "tag": tag})
    return out


# ── Canonical API-path heuristic ──────────────────────────────────────────

_API_PATH_HINTS = ("/api/", "/graphql", "/rest/", "/rpc/", "/v1/", "/v2/",
                   "/v3/", "/admin/", "/internal/")


def _looks_like_api(path: str) -> bool:
    """Conservative heuristic: any path containing a typical API segment is
    NOT a static asset, even if it endswith('.css'). Prevents the
    `/api/v1/users.css` style bypass on permissive backends."""
    p = path.lower()
    return any(h in p for h in _API_PATH_HINTS)


# ── Initialise ENDPOINT_POLICIES and CUSTOM_RULES from raw env strings ────
# (Done here so the module is self-contained; proxy.py's copies of these
# lines are superseded once `from integrations import *` is in effect.)

ENDPOINT_POLICIES_RAW = os.environ.get("ENDPOINT_POLICIES", "").strip()
try:
    ENDPOINT_POLICIES = _to_endpoint_policies(ENDPOINT_POLICIES_RAW)
except (ValueError, TypeError) as _e:
    print(f"[endpoint-policies] parse failed: {_e} — ignoring", flush=True)
    ENDPOINT_POLICIES = []

CUSTOM_RULES_RAW = os.environ.get("CUSTOM_RULES", "").strip()
try:
    CUSTOM_RULES = _to_custom_rules(CUSTOM_RULES_RAW)
except (ValueError, TypeError) as _e:
    print(f"[custom-rules] parse failed: {_e} — ignoring", flush=True)
    CUSTOM_RULES = []
if CUSTOM_RULES:
    print(f"[custom-rules] {len(CUSTOM_RULES)} rule(s) loaded", flush=True)


# ── Custom-rules evaluator ────────────────────────────────────────────────

def _eval_custom_rules(request, ip: str):
    """1.6.1 — first-match-wins. Returns (action, tag) or (None, "")."""
    if not CUSTOM_RULES:
        return None, ""
    path = request.path
    method = request.method.upper()
    ua = (request.headers.get("User-Agent") or "")
    ua_lower = ua.lower()
    headers = request.headers
    query = request.query
    for rule in CUSTOM_RULES:
        cond = rule.get("if") or {}
        ok = True
        # path glob
        p = cond.get("path")
        if p and not _fnmatch.fnmatchcase(path, str(p)):
            ok = False
        # method (single str OR list)
        if ok:
            m = cond.get("method")
            if m:
                allowed_methods = (
                    [str(x).upper() for x in m] if isinstance(m, list)
                    else [str(m).upper()])
                if method not in allowed_methods:
                    ok = False
        # ua substring
        if ok:
            uac = cond.get("ua_contains")
            if uac and str(uac).lower() not in ua_lower:
                ok = False
        # header.X-Foo (case-insensitive substring)
        if ok:
            for k, want in cond.items():
                if not k.startswith("header."):
                    continue
                hv = (headers.get(k.split(".", 1)[1], "") or "").lower()
                if str(want).lower() not in hv:
                    ok = False
                    break
        # query.param exact
        if ok:
            for k, want in cond.items():
                if not k.startswith("query."):
                    continue
                if query.get(k.split(".", 1)[1], "") != str(want):
                    ok = False
                    break
        # ip in CIDR — use pre-compiled _ip_nets when available
        if ok:
            nets = cond.get("_ip_nets")
            if nets is None:
                raw = cond.get("ip_cidr")
                if raw:
                    try:
                        nets = [_ipaddress.ip_network(c, strict=False) for c in raw]
                    except (ValueError, TypeError):
                        nets = []
            if nets:
                try:
                    ipa = _ipaddress.ip_address(ip)
                    if not any(ipa in n for n in nets):
                        ok = False
                except (ValueError, TypeError):
                    ok = False
        # country (requires GeoLite2-City — _city_lookup/_city_reader from reputation)
        if ok:
            cc = cond.get("country")
            if cc:
                wanted = (
                    {str(x).upper() for x in cc} if isinstance(cc, list)
                    else {str(cc).upper()})
                # Late import: _city_lookup and _city_reader live in reputation.maxmind
                try:
                    import reputation.maxmind as _mm
                    geo = _mm._city_lookup(ip) if _mm._city_reader is not None else None
                except Exception:
                    geo = None
                cc_obs = (geo[2] if geo else "").upper()
                if cc_obs not in wanted:
                    ok = False
        if ok:
            return rule.get("then"), rule.get("tag", "")
    return None, ""


# ── Endpoint policy lookup ────────────────────────────────────────────────

def _endpoint_policy(path: str) -> str:
    """Return the matched policy ('bypass'|'challenge'|'strict'|'default')
    or 'default' when nothing matches. First match wins (operators order
    most-specific first in the JSON array)."""
    rule = _endpoint_rule(path)
    return rule["policy"] if rule else "default"


def _endpoint_rule(path: str):
    """1.6.1 — return the FULL matched rule dict (with rps/burst) or None.
    Accepts both new dict-shape and legacy [path, policy] pair entries
    (gateway-safe even if a stale config_kv blob is loaded from DB)."""
    if not ENDPOINT_POLICIES:
        return None
    for item in ENDPOINT_POLICIES:
        if isinstance(item, dict):
            if _fnmatch.fnmatchcase(path, item.get("path", "")):
                return item
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            if _fnmatch.fnmatchcase(path, item[0]):
                return {"path": item[0], "policy": item[1],
                        "rps": None, "burst": None}
    return None


# ── Per-endpoint token-bucket rate limiting ───────────────────────────────
# Key = (path_glob, identity). Lives only in memory: rate-limit state
# doesn't need to survive restart (limits reset on boot is acceptable;
# saves DB write traffic).

_endpoint_buckets: dict = {}
_endpoint_buckets_lock = asyncio.Lock()
_ENDPOINT_BUCKET_MAX  = 50_000   # trigger prune above this count
_ENDPOINT_BUCKET_IDLE = 3_600.0  # monotonic seconds — evict if idle > 1 h


async def _endpoint_rate_consume(rule: dict, identity: str) -> bool:
    """Token-bucket consume for an endpoint rule. True on accept,
    False when over budget (caller should silent-decoy with
    'rate-limit-endpoint')."""
    rps = rule.get("rps")
    burst = rule.get("burst") or (int(rps * 2) if rps else 1)
    if not rps:
        return True
    n = time.monotonic()
    key = (rule.get("path", ""), identity)
    async with _endpoint_buckets_lock:
        # Opportunistic prune: O(n) scan only when dict is oversized.
        if len(_endpoint_buckets) > _ENDPOINT_BUCKET_MAX:
            stale = [k for k, v in _endpoint_buckets.items()
                     if n - v["ts"] > _ENDPOINT_BUCKET_IDLE]
            for k in stale:
                del _endpoint_buckets[k]
        st = _endpoint_buckets.get(key)
        if st is None:
            st = {"tokens": float(burst), "ts": n}
        elapsed = max(0.0, n - st["ts"])
        st["tokens"] = min(float(burst), st["tokens"] + elapsed * float(rps))
        st["ts"] = n
        if st["tokens"] >= 1.0:
            st["tokens"] -= 1.0
            _endpoint_buckets[key] = st
            return True
        _endpoint_buckets[key] = st
        return False
