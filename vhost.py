"""
vhost.py — Per-inbound-domain config overrides (Option C multi-vhost).

VHOSTS env var: JSON mapping lowercase hostname → override dict.
Keys are uppercase config names from the supported set.
Values are coerced to match config types at parse time.

At request time:
  set_vhost(host)   → writes override dict into _vhost_ctx ContextVar
  vc(name)          → reads from context first, then falls back to global config

Each aiohttp request runs in its own asyncio Task and inherits a copy of the
context. Writes inside that task do not bleed into other concurrent requests.
"""
import contextvars
import ipaddress
import json
import os
import re
import socket
import urllib.parse
from collections import deque
from typing import Any, Dict, Optional

import config as _cfg

# RFC-1123 hostname label: 1–63 chars, a-z / 0-9 / hyphen, no leading/trailing hyphen.
_LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')


def _validate_vhost_hostname(hostname: str) -> "tuple[bool, str]":
    """Validate an inbound vhost hostname.

    Accepts:
      - plain FQDNs:   example.com, sub.example.com
      - single labels: localhost, myapp  (for local/dev setups)
      - wildcards:     *.example.com

    Rejects:
      - bare IPs, hostnames with port numbers, consecutive dots,
        labels > 63 chars, total > 253 chars, invalid characters.
    """
    h = hostname.strip().lower()
    if not h:
        return False, "hostname is empty"
    if ":" in h:
        return False, f"hostname must not include a port number: {h!r}"
    if len(h) > 253:
        return False, f"hostname too long ({len(h)} chars, max 253)"
    # Strip single trailing dot (FQDN notation)
    if h.endswith("."):
        h = h[:-1]
    # Wildcard prefix — only *.label.tld form is valid
    if h.startswith("*"):
        if not h.startswith("*.") or h.count("*") > 1:
            return False, f"only '*.example.com' wildcard form is allowed, got: {hostname!r}"
        h = h[2:]
        if not h:
            return False, "wildcard hostname has no base domain after '*.' prefix"
    # Reject bare IPv4 addresses
    try:
        ipaddress.ip_address(h)
        return False, f"hostname must be a domain name, not a bare IP address: {hostname!r}"
    except ValueError:
        pass
    labels = h.split(".")
    for label in labels:
        if not label:
            return False, f"hostname has empty label (consecutive or trailing dots): {hostname!r}"
        if len(label) > 63:
            return False, f"hostname label {label!r} exceeds 63 chars"
        if not _LABEL_RE.match(label):
            return False, (
                f"hostname label {label!r} is invalid "
                f"(only a-z, 0-9, hyphens allowed; cannot start or end with a hyphen)"
            )
    return True, ""


# RFC-1918, loopback, link-local, CGNAT, multicast, and reserved ranges
# that must never be reachable as an UPSTREAM target.
_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "0.0.0.0/8",
    )
]


def _assert_upstream_public(upstream: str, key: str = "UPSTREAM") -> None:
    """Abort startup if *upstream* resolves to an internal/private address.

    Prevents accidental or malicious VHOSTS configs from turning the gateway
    into an SSRF vector that leaks internal infrastructure over public tunnels.
    Skipped when ALLOW_PRIVATE_UPSTREAM=1 is set in the environment.
    """
    if _cfg.ALLOW_PRIVATE_UPSTREAM:
        return
    parsed = urllib.parse.urlparse(upstream)
    host = parsed.hostname
    if not host:
        raise SystemExit(f"FATAL: {key}={upstream!r} has no hostname — aborting")
    try:
        addrs = {r[4][0] for r in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        # DNS failure at startup is safe to pass through; runtime will error naturally.
        return
    for addr_str in addrs:
        try:
            addr = ipaddress.ip_address(addr_str)
            if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
                addr = addr.ipv4_mapped
        except ValueError:
            continue
        for net in _PRIVATE_NETS:
            if addr in net:
                raise SystemExit(
                    f"FATAL: {key}={upstream!r} resolves to private address "
                    f"{addr_str} ({net}) — internal exposure blocked. "
                    f"Set ALLOW_PRIVATE_UPSTREAM=1 to permit internal upstreams."
                )

# ── Supported overridable keys and their type coercions ───────────────────────
def _to_path_list(v: Any) -> list:
    if isinstance(v, list):
        return [str(p) for p in v]
    return [p.strip() for p in str(v).split(",") if p.strip()]


def _to_str_set(v: Any) -> frozenset:
    if isinstance(v, list):
        return frozenset(str(x) for x in v)
    return frozenset(p.strip() for p in str(v).split(",") if p.strip())


def _to_json_list(v: Any) -> list:
    if isinstance(v, list):
        return v
    import json as _json
    return _json.loads(v) if isinstance(v, str) else []


_VHOST_COERCE: Dict[str, Any] = {
    # ── Routing ───────────────────────────────────────────────────────────────
    "UPSTREAM":                      str,
    # ── JS challenge ──────────────────────────────────────────────────────────
    "JS_CHALLENGE":                  bool,
    "JS_CHAL_BIND_JA4":              bool,
    "JS_CHAL_REQUIRE_JA4":           bool,
    "JS_CHAL_STRICT_STATIC":         bool,
    "JS_CHAL_OPEN_PATHS":            _to_path_list,
    "JS_CHALLENGE_TTL":              int,
    "POW_MIN_SOLVE_MS":              int,
    "POW_REQUIRED_PATHS":            _to_path_list,
    "POW_CHAL_THRESHOLD":            int,
    # ── Detectors (on/off) ────────────────────────────────────────────────────
    "UA_FILTER_ENABLED":             bool,
    "UA_PLATFORM_CHECK_ENABLED":     bool,
    "SUSPICIOUS_PATH_ENABLED":       bool,
    "HONEYPOT_ENABLED":              bool,
    "HONEYPOT_PATHS":                lambda v: set(v) if isinstance(v, list) else {str(v)},
    "BOT_TRAP_FORMS":                bool,
    "BODY_PATTERN_MATCH":            bool,
    "CANARY_ECHO_DETECTION":         bool,
    "AI_PROBE_ENABLED":              bool,
    "HEADER_COMPLETENESS_ENABLED":   bool,
    "BEHAVIORAL_CHECK_ENABLED":      bool,
    "AI_ENUMERATION_ENABLED":        bool,
    "AI_NO_ASSETS_ENABLED":          bool,
    "SESSION_FLOOD_ENABLED":         bool,
    "UPSTREAM_404_TRACKING_ENABLED": bool,
    "ACCEPT_FP_ENABLED":             bool,
    "HEADER_CANARY_ENABLED":         bool,
    "HEADER_ORDER_FP_ENABLED":       bool,
    "AI_CRAWLER_VERIFY_ENABLED":     bool,
    "JA4_FAIL_CLOSED":               bool,
    "JSON_CANARY_ENABLED":           bool,
    "LOCALE_GEO_CHECK_ENABLED":      bool,
    "ROBOTS_MONITOR_ENABLED":        bool,
    "H2_FP_ENABLED":                 bool,
    "BOTD_ENABLED":                  bool,
    "COOKIE_GHOST_ENABLED":          bool,
    "COOKIE_LIFECYCLE_ENABLED":      bool,
    "REFERER_CHAIN_ENABLED":         bool,
    "IMPOSSIBLE_TRAVEL_ENABLED":     bool,
    "IMPOSSIBLE_TRAVEL_WINDOW_SECS": int,
    "FP_ENRICHMENT_ENABLED":         bool,
    "SW_CHALLENGE_ENABLED":          bool,
    # ── Anubis ────────────────────────────────────────────────────────────────
    "ANUBIS_ENABLED":                bool,
    "ANUBIS_DIFFICULTY_BOOST":       int,
    # ── Thresholds / scoring ──────────────────────────────────────────────────
    "RISK_BAN_THRESHOLD":            int,
    "SOFT_CHALLENGE_SCORE":          float,
    "ESCALATION_THRESHOLD":          float,
    "SECOND_ORDER_THRESHOLD":        float,
    "TURNSTILE_RISK_THRESHOLD":      float,
    "JA4_AUTODENY_THRESHOLD":        int,
    "ENUM_THRESHOLD":                int,
    "COOKIE_GHOST_MIN_REQUESTS":     int,
    "COOKIE_GHOST_MISS_THRESHOLD":   int,
    # ── Rate limiting ─────────────────────────────────────────────────────────
    "RATE_LIMIT_BURST":              int,
    "RATE_LIMIT_REFILL":             float,
    "IP_BURST":                      int,
    "IP_REFILL":                     float,
    "GLOBAL_RPS_LIMIT":              int,
    # ── Ban durations ─────────────────────────────────────────────────────────
    "HOSTILE_BAN_SECS":              int,
    "REALLY_BAN_SECS":               int,
    "CANARY_TTL_S":                  int,
    "SESSION_CHURN_WINDOW_S":        int,
    "SESSION_CHURN_MAX":             int,
    # ── Bypass ────────────────────────────────────────────────────────────────
    "BYPASS_MODE":                   bool,
    "BYPASS_PATHS":                  _to_path_list,
    # ── Geo / network ─────────────────────────────────────────────────────────
    "COUNTRY_BLOCK_ENABLED":         bool,
    "COUNTRY_DENYLIST":              lambda v: frozenset(
        str(x).upper() for x in (v if isinstance(v, list) else [v])),
    "COUNTRY_ALLOWLIST":             lambda v: frozenset(
        str(x).upper() for x in (v if isinstance(v, list) else [v])),
    "TOR_BLOCK_ENABLED":             bool,
    "DC_VPN_BLOCK_ENABLED":          bool,
    # ── AI crawler groups ─────────────────────────────────────────────────────
    "AI_UA_OPENAI_ENABLED":          bool,
    "AI_UA_ANTHROPIC_ENABLED":       bool,
    "AI_UA_GOOGLE_ENABLED":          bool,
    "AI_UA_PERPLEXITY_ENABLED":      bool,
    "AI_UA_META_ENABLED":            bool,
    "AI_UA_OTHER_ENABLED":           bool,
    # ── Body scanner groups ───────────────────────────────────────────────────
    "BODY_GROUP_SQLI_ENABLED":       bool,
    "BODY_GROUP_XSS_ENABLED":        bool,
    "BODY_GROUP_LFI_ENABLED":        bool,
    "BODY_GROUP_RCE_ENABLED":        bool,
    "BODY_GROUP_SSRF_ENABLED":       bool,
    "BODY_GROUP_CMD_ENABLED":        bool,
    # ── Tarpit / labyrinth ────────────────────────────────────────────────────
    "TARPIT_ENABLED":                bool,
    "TARPIT_DELAY_MS":               int,
    "LABYRINTH_ENABLED":             bool,
    "LABYRINTH_SLOW_MS":             int,
    "LABYRINTH_MAX_DEPTH":           int,
    "LABYRINTH_LINKS_PER":           int,
    "LABYRINTH_JITTER_ENABLED":      bool,
    # ── JWT ───────────────────────────────────────────────────────────────────
    "JWT_VALIDATE_PATHS":            _to_path_list,
    "JWT_REQUIRED_ISSUER":           str,
    "JWT_REQUIRED_AUDIENCE":         str,
    # ── DLP ───────────────────────────────────────────────────────────────────
    "DLP_ENABLED":                   bool,
    "DLP_REDACT":                    bool,
    "DLP_MAX_BYTES":                 int,
    "DLP_GROUP_CC_ENABLED":          bool,
    "DLP_GROUP_AWS_ENABLED":         bool,
    "DLP_GROUP_JWT_ENABLED":         bool,
    "DLP_GROUP_PRIVATE_KEY_ENABLED": bool,
    "DLP_GROUP_API_KEY_ENABLED":     bool,
    "DLP_GROUP_PII_EMAIL_ENABLED":   bool,
    "DLP_GROUP_PII_SSN_ENABLED":     bool,
    # ── Policies / rules ─────────────────────────────────────────────────────
    "ENDPOINT_POLICIES":             _to_json_list,
    "CUSTOM_RULES":                  _to_json_list,
    "AUTHORIZED_BOT_UAS":            lambda v: list(v) if isinstance(v, list) else
                                               [x.strip() for x in str(v).split(",") if x.strip()],
    "JA4_DENY_LIST":                 _to_str_set,
    "ALLOWED_HOSTS":                 _to_str_set,
    # ── Integration kill-switches (credentials stay global) ───────────────────
    "ABUSEIPDB_ENABLED":             bool,
    "CROWDSEC_ENABLED":              bool,
    "MAXMIND_ENABLED":               bool,
    "TURNSTILE_ENABLED":             bool,
    # ── Origin / headers ─────────────────────────────────────────────────────
    "STRICT_ORIGIN":                 bool,
    "INJECT_SECURITY_HEADERS":       bool,
    "ALLOWED_METHODS":               _to_str_set,
    # ── Upstream limits ───────────────────────────────────────────────────────
    "UPSTREAM_MAX_BODY":             int,
    "UPSTREAM_MAX_RESP":             int,
}

# ── Parse VHOSTS env var ───────────────────────────────────────────────────────
_VHOSTS_RAW = os.environ.get("VHOSTS", "").strip()
VHOSTS: Dict[str, Dict[str, Any]] = {}

if _VHOSTS_RAW:
    try:
        _parsed = json.loads(_VHOSTS_RAW)
        if not isinstance(_parsed, dict):
            raise ValueError("VHOSTS must be a JSON object {hostname: overrides}")
        for _host, _overrides in _parsed.items():
            if not isinstance(_overrides, dict):
                raise ValueError(f"VHOSTS[{_host!r}] must be a JSON object")
            _hvalid, _herr = _validate_vhost_hostname(_host)
            if not _hvalid:
                raise ValueError(f"VHOSTS[{_host!r}] invalid hostname: {_herr}")
            _norm: Dict[str, Any] = {}
            for _k, _v in _overrides.items():
                _ku = _k.upper()
                _coerce = _VHOST_COERCE.get(_ku)
                if _coerce is None:
                    print(f"[vhost] warning: unsupported override key {_ku!r} "
                          f"for {_host!r} — ignored", flush=True)
                    continue
                try:
                    _norm[_ku] = _coerce(_v)
                except Exception as _ce:
                    raise ValueError(
                        f"VHOSTS[{_host!r}][{_ku!r}] coerce error: {_ce}") from _ce
            if "UPSTREAM" in _norm:
                _assert_upstream_public(_norm["UPSTREAM"], key=f"VHOSTS[{_host!r}].UPSTREAM")
            VHOSTS[_host.lower()] = _norm
    except (json.JSONDecodeError, ValueError) as _e:
        print(f"FATAL: VHOSTS parse error — {_e}", flush=True)
        raise SystemExit(2)

if VHOSTS:
    _upstream_info = {h: v.get("UPSTREAM", "(global)") for h, v in VHOSTS.items()}
    print(f"[vhost] {len(VHOSTS)} virtual host(s): " +
          ", ".join(f"{h}→{u}" for h, u in _upstream_info.items()), flush=True)

# ── Per-vhost RPS windows (isolated from the global _global_rps_window) ───────
_vhost_rps_windows: Dict[str, deque] = {h: deque(maxlen=20000) for h in VHOSTS}

# ── Persistent vhost storage ───────────────────────────────────────────────────
_DATA_DIR = os.environ.get("DATA_DIR", "/data")
_VHOSTS_FILE = os.path.join(_DATA_DIR, "vhosts.json")


def _json_safe(v: Any) -> Any:
    """Convert non-JSON-serialisable types to JSON-safe equivalents."""
    if isinstance(v, (frozenset, set)):
        return sorted(str(x) for x in v)
    if isinstance(v, list):
        return [_json_safe(i) for i in v]
    if isinstance(v, dict):
        return {k: _json_safe(val) for k, val in v.items()}
    return v


def _load_vhosts_file() -> None:
    """Read /data/vhosts.json (if it exists) and merge entries into VHOSTS.

    File entries override env-derived entries so operator changes made via
    the API survive container restarts even when VHOSTS env is unchanged.
    """
    try:
        with open(_VHOSTS_FILE, "r", encoding="utf-8") as _f:
            _data = json.load(_f)
        if not isinstance(_data, dict):
            print(f"[vhost] warn: {_VHOSTS_FILE} is not a JSON object — skipped",
                  flush=True)
            return
        _loaded = 0
        for _host, _overrides in _data.items():
            if not isinstance(_overrides, dict):
                continue
            _norm: Dict[str, Any] = {}
            for _k, _v in _overrides.items():
                _ku = _k.upper()
                _coerce = _VHOST_COERCE.get(_ku)
                if _coerce is None:
                    continue
                try:
                    _norm[_ku] = _coerce(_v)
                except Exception:
                    continue
            VHOSTS[_host.lower()] = _norm
            if _host.lower() not in _vhost_rps_windows:
                _vhost_rps_windows[_host.lower()] = deque(maxlen=20000)
            _loaded += 1
        if _loaded:
            print(f"[vhost] loaded {_loaded} persisted vhost(s) from {_VHOSTS_FILE}",
                  flush=True)
    except FileNotFoundError:
        pass
    except Exception as _e:
        print(f"[vhost] warn: could not load {_VHOSTS_FILE}: {_e}", flush=True)


def _save_vhosts_file() -> None:
    """Write the current VHOSTS dict to /data/vhosts.json.

    Values are serialised to plain JSON-safe Python types so the file can
    be read back by _load_vhosts_file() without loss of information.
    """
    try:
        _serialised = {
            h: {k: _json_safe(v) for k, v in overrides.items()}
            for h, overrides in VHOSTS.items()
        }
        os.makedirs(_DATA_DIR, exist_ok=True)
        _tmp = _VHOSTS_FILE + ".tmp"
        with open(_tmp, "w", encoding="utf-8") as _f:
            json.dump(_serialised, _f, indent=2, ensure_ascii=False)
        os.replace(_tmp, _VHOSTS_FILE)
    except Exception as _e:
        print(f"[vhost] warn: could not save {_VHOSTS_FILE}: {_e}", flush=True)


def vhost_set(hostname: str, overrides: dict) -> "tuple[bool, str]":
    """Add or replace a vhost entry. Returns (True, '') on success or (False, error)."""
    h = hostname.strip().lower()
    valid, err = _validate_vhost_hostname(h)
    if not valid:
        return False, f"invalid hostname: {err}"
    _norm: Dict[str, Any] = {}
    for _k, _v in overrides.items():
        _ku = _k.upper()
        _coerce = _VHOST_COERCE.get(_ku)
        if _coerce is None:
            continue
        try:
            _norm[_ku] = _coerce(_v)
        except Exception as _ce:
            return False, f"coerce error for {_ku}: {_ce}"
    if "UPSTREAM" in _norm:
        try:
            _assert_upstream_public(_norm["UPSTREAM"], key=f"VHOSTS[{h!r}].UPSTREAM")
        except SystemExit as _se:
            return False, str(_se)
    VHOSTS[h] = _norm
    if h not in _vhost_rps_windows:
        _vhost_rps_windows[h] = deque(maxlen=20000)
    _save_vhosts_file()
    return True, ""


def vhost_delete(hostname: str) -> bool:
    """Remove a vhost entry. Returns True if it existed, False otherwise."""
    h = hostname.strip().lower()
    existed = h in VHOSTS
    VHOSTS.pop(h, None)
    _vhost_rps_windows.pop(h, None)
    _save_vhosts_file()
    return existed


def vhost_list() -> "list[dict]":
    """Return a JSON-serialisable list of all vhost entries."""
    return [
        {"hostname": h, **{k: _json_safe(v) for k, v in overrides.items()}}
        for h, overrides in VHOSTS.items()
    ]


# Merge any previously-persisted vhosts (file entries override env entries).
_load_vhosts_file()


def get_vhost_rps_window(hostname: str) -> Optional[deque]:
    """Return per-vhost RPS deque, or None if hostname has no vhost entry."""
    return _vhost_rps_windows.get(hostname)


# ── Context variables (one per request task) ──────────────────────────────────
_vhost_ctx: contextvars.ContextVar[Optional[Dict[str, Any]]] = \
    contextvars.ContextVar("_vhost_ctx", default=None)

_vhost_host_ctx: contextvars.ContextVar[str] = \
    contextvars.ContextVar("_vhost_host_ctx", default="")


def set_vhost(host: str) -> None:
    """Set per-request vhost override context from the Host header value."""
    h = (host or "").split(":", 1)[0].lower()
    _vhost_host_ctx.set(h)
    _vhost_ctx.set(VHOSTS.get(h))  # None when no match → vc() falls back to globals


def current_vhost_host() -> str:
    """Return the normalised hostname for the current request."""
    return _vhost_host_ctx.get()


def vhost_is_configured() -> bool:
    """Return True if the current request's Host has an explicit vhost entry."""
    return _vhost_ctx.get() is not None


def vc(name: str) -> Any:
    """Config accessor: returns vhost override if present, else global config value.

    Fallback order:
      1. Per-request vhost override dict (ContextVar)
      2. core.proxy_handler module namespace — the merged star-import namespace
         where tests apply patches and all sub-module exports land
      3. config module (most settings live here)
      4. sys.modules scan — handles settings in sub-modules not yet in proxy_handler
         (e.g. COUNTRY_BLOCK_ENABLED lives in reputation.maxmind, not config)
    """
    import sys as _sys
    ctx = _vhost_ctx.get()
    if ctx is not None and name in ctx:
        return ctx[name]
    # core.proxy_handler is the merged namespace (all from X import * funnelled in).
    # Tests patch values there; checking it first ensures patches are seen.
    _cph = _sys.modules.get("core.proxy_handler")
    if _cph is not None and hasattr(_cph, name):
        return getattr(_cph, name)
    if hasattr(_cfg, name):
        return getattr(_cfg, name)
    # Scan loaded modules for the attribute (covers sub-package exports)
    _skip = {id(_cfg), id(_cph)} if _cph is not None else {id(_cfg)}
    for _mod in list(_sys.modules.values()):
        if _mod is None or id(_mod) in _skip:
            continue
        if hasattr(_mod, name):
            return getattr(_mod, name)
    raise AttributeError(f"vhost.vc: config attribute {name!r} not found in any loaded module")
