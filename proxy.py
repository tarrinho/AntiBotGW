#!/usr/bin/env python3
"""
Anti-bot reverse proxy. Domain-agnostic — the upstream target is supplied
exclusively via the UPSTREAM environment variable (no domain is baked in).

Listens on $LISTEN_HOST:$LISTEN_PORT and proxies traffic to $UPSTREAM.

Protections layered (each can be bypassed independently for testing):
  1. UA blocklist  (curl, python-requests, Claude, GPTBot, ...)
  2. Honeypot paths (auto-ban for 1h)
  3. Per-IP token-bucket rate limit (429 + Retry-After)
  4. Proof-of-Work challenge for POST + sensitive paths (402 + challenge)
  5. Behavioral scoring (timing, header completeness)

Run:
  python3 proxy.py

Internal endpoints (not proxied to upstream):
  GET /__pow      → issue a fresh challenge to be solved
  GET /__solver   → in-browser JS PoW solver
  GET /__status   → rate-limiter state snapshot
"""

import asyncio
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict

import aiohttp
from aiohttp import web, ClientSession, ClientTimeout

# ── Configuration ──────────────────────────────────────────────────────────
import os
from pathlib import Path
# resolve() so we follow symlinks back to the real proxy.py location — tests
# import via a symlink in a tmp dir, the real dashboards/ lives next to the
# original file.
_DASHBOARDS_DIR = Path(__file__).resolve().parent / "dashboards"
_upstream_raw = os.environ.get("UPSTREAM", "").strip()
if not _upstream_raw:
    print("FATAL: UPSTREAM env var is required and must be a fully-qualified URL", flush=True)
    print("       e.g.  -e UPSTREAM=https://your-frontend.example.com", flush=True)
    raise SystemExit(2)
try:
    from urllib.parse import urlparse as _urlp
    _u = _urlp(_upstream_raw)
    if _u.scheme not in ("http", "https") or not _u.netloc:
        raise ValueError("UPSTREAM must be http(s)://host[:port]")
except Exception as _e:
    print(f"FATAL: invalid UPSTREAM={_upstream_raw!r} — {_e}", flush=True)
    raise SystemExit(2)
UPSTREAM        = _upstream_raw.rstrip("/")
LISTEN_HOST     = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT     = int(os.environ.get("LISTEN_PORT", "8443"))

RATE_LIMIT_BURST  = int(os.environ.get("BURST", "5"))     # tokens
RATE_LIMIT_REFILL = float(os.environ.get("REFILL", "1.0")) # tokens / second
HONEYPOT_BAN_SECS = int(os.environ.get("HONEYPOT_BAN_SECS", "3600"))  # 1 h default
# R8: longer-TTL "hostile pool" — once an identity has crossed the
# canary-echo / honeypot threshold, keep it silent-decoyed for HOSTILE_BAN_SECS
# (default 24 h). Generic bans stay at HONEYPOT_BAN_SECS; only the
# AI-agent-specific signals (canary-echo, honeypot-silent, honeypot)
# upgrade to hostile-pool duration.
HOSTILE_BAN_SECS  = int(os.environ.get("HOSTILE_BAN_SECS", "86400"))   # 24 h
_HOSTILE_REASONS  = {"canary-echo", "honeypot-silent", "honeypot",
                     "ai-probe", "suspicious-path"}
POW_DIFFICULTY    = 5       # leading hex zeros (~16M hashes for d=5)
POW_VALID_SECS    = 300     # 5 minutes
BEHAVIOR_WINDOW   = 30      # seconds
BEHAVIOR_MAX_REGULAR = 8    # >N requests with σ<10ms → bot

# PoW HMAC key — persist so restart doesn't invalidate every in-flight challenge.
_POW_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".pow_key")
if os.path.exists(_POW_KEY_FILE):
    POW_HMAC_KEY = bytes.fromhex(open(_POW_KEY_FILE).read().strip())
else:
    POW_HMAC_KEY = secrets.token_bytes(32)
    with open(_POW_KEY_FILE, "w") as _f:
        _f.write(POW_HMAC_KEY.hex())
    try:
        os.chmod(_POW_KEY_FILE, 0o600)
    except OSError:
        pass

# ── Internal-route auth: hide /__* unless the operator presents the key ────
_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".admin_key")
ADMIN_KEY_FROM_ENV = "ADMIN_KEY" in os.environ and bool(os.environ["ADMIN_KEY"])
if ADMIN_KEY_FROM_ENV:
    INTERNAL_KEY = os.environ["ADMIN_KEY"]
elif os.path.exists(_KEY_FILE):
    INTERNAL_KEY = open(_KEY_FILE).read().strip()
else:
    INTERNAL_KEY = secrets.token_urlsafe(20)

# Always mirror the active key to /data/.admin_key so operators can retrieve
# it with a single canonical command (`docker exec <container> cat
# /data/.admin_key`) regardless of whether it came from env or was generated.
try:
    with open(_KEY_FILE, "w") as _f:
        _f.write(INTERNAL_KEY)
    os.chmod(_KEY_FILE, 0o600)
except OSError:
    pass

def _internal_authed(request) -> bool:
    """Operator key check for /__* routes. Constant-time compare; no cookie path
    (cookie is never set by us, removing the dead code path)."""
    provided = request.headers.get("X-Admin-Key") or request.query.get("key") or ""
    if not provided:
        return False
    return hmac.compare_digest(provided, INTERNAL_KEY)

# ── Admin IP allowlist ─────────────────────────────────────────────────────
# Comma-separated list of source IPs / CIDRs allowed to reach /__* endpoints
# (other than /__live, which is the unauthenticated liveness probe). When
# empty, no IP restriction (admin-key auth only). When set, BOTH the IP check
# and the admin-key must pass — defence-in-depth.
import ipaddress as _ipaddress
_admin_ips_raw = os.environ.get("ADMIN_ALLOWED_IPS", "").strip()
ADMIN_ALLOWED_NETS: list = []
if _admin_ips_raw:
    for _entry in _admin_ips_raw.split(","):
        _entry = _entry.strip()
        if not _entry:
            continue
        try:
            ADMIN_ALLOWED_NETS.append(_ipaddress.ip_network(_entry, strict=False))
        except ValueError as _e:
            print(f"FATAL: invalid ADMIN_ALLOWED_IPS entry {_entry!r} — {_e}",
                  flush=True)
            raise SystemExit(2)

def _admin_ip_allowed(request) -> bool:
    """Allowed iff source IP matches one of the configured networks. Returns
    True when no allowlist is configured (open by default — admin key still
    required). Uses get_ip() so TRUST_XFF=last works behind a trusted proxy."""
    if not ADMIN_ALLOWED_NETS:
        return True
    try:
        ip = _ipaddress.ip_address(get_ip(request))
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in ADMIN_ALLOWED_NETS)

# ── Hybrid identity: session cookie + browser fingerprint ──────────────────
# Solves the "shared NAT" problem — bans apply per-browser, not per-IP.
# IP is kept only for: session-creation rate limit, dashboard display.
_SESS_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".session_key")
if os.path.exists(_SESS_KEY_FILE):
    SESSION_KEY = bytes.fromhex(open(_SESS_KEY_FILE).read().strip())
else:
    SESSION_KEY = secrets.token_bytes(32)
    with open(_SESS_KEY_FILE, "w") as _f:
        _f.write(SESSION_KEY.hex())
    os.chmod(_SESS_KEY_FILE, 0o600)

SESSION_COOKIE = "aid"
SESSION_TTL_SECS = 30 * 86400          # 30 days
NEW_SESSIONS_PER_IP_PER_MIN = 30        # anti cookie-rotation
_ss = os.environ.get("SESSION_SAMESITE", "Lax").capitalize()
SESSION_SAMESITE = _ss if _ss in ("Lax", "Strict", "None") else "Lax"
SESSION_SECURE = os.environ.get("SESSION_SECURE", "1") not in ("0", "false", "False", "")

# Per-IP session-creation tracking — maps ip → {identity: last_seen_ts}.
# Counts DISTINCT new identities per minute (not raw requests), so parallel
# cookieless sub-resource fetches sharing one identity register as 1, not N.
ip_new_sessions: Dict[str, dict] = defaultdict(dict)

def _sign_session(sid: str) -> str:
    sig = hmac.new(SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()
    return f"{sid}.{sig}"

def _verify_session(token: str):
    if not token or "." not in token:
        return None
    try:
        sid, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    # N3: reject empty sid (would otherwise yield a stable identity for every
    # client that presents a valid HMAC of the empty string).
    if not sid or len(sig) != 64:
        return None
    # N3: also clamp sid length and charset (token_urlsafe alphabet only).
    if len(sid) > 64 or not all(c.isalnum() or c in "-_" for c in sid):
        return None
    expected = hmac.new(SESSION_KEY, sid.encode(), hashlib.sha256).hexdigest()
    return sid if hmac.compare_digest(sig, expected) else None

def browser_fingerprint(request) -> str:
    """Stable hash of browser-identifying headers. Excludes Sec-Ch-Ua* — these
    Client Hints are only sent on top-level navigation by default; including
    them here splits one browser into multiple identities across navigation
    vs sub-resource fetches and causes false-positive bans on SPAs with many
    JS modules."""
    parts = [
        request.headers.get("User-Agent", "")[:200],
        request.headers.get("Accept-Language", ""),
        request.headers.get("Accept-Encoding", ""),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]

def get_identity(request):
    """
    Returns (identity, session_id, fingerprint, is_new_session, mode).
    Identity strategy:
      • Browser with valid cookie  → identity = HMAC("sess|" + sid + "|" + fp)
                                      stable per session, survives header changes
      • Cookieless / invalid cookie → identity = HMAC("anon|" + fp + "|" + ip)
                                      STABLE per (fingerprint, IP) tuple — so all
                                      requests from a Python bot with the same UA
                                      share the same identity and the same rate-limit
                                      bucket. The bot CANNOT escape by simply
                                      not storing cookies.
      • Bot rotating fp+ip on every request → still caught by IP session-flood guard
                                              (max 30 new identities/min/IP)
    Returns mode="session"|"anon" so the dashboard can display.
    """
    cookie_token = request.cookies.get(SESSION_COOKIE, "")
    sid = _verify_session(cookie_token)
    fp = browser_fingerprint(request)

    if sid:
        # Cookie-bound identity (proper browser)
        identity = hmac.new(
            SESSION_KEY, f"sess|{sid}|{fp}".encode(), hashlib.sha256
        ).hexdigest()[:16]
        return identity, sid, fp, False, "session"
    else:
        # No (valid) cookie — bind identity to fingerprint+IP for stability.
        # Bot reusing the same UA from same IP sees the SAME identity → caught.
        ip = get_ip(request)
        identity = hmac.new(
            SESSION_KEY, f"anon|{fp}|{ip}".encode(), hashlib.sha256
        ).hexdigest()[:16]
        # Still issue a fresh sid in case they DO start accepting cookies later
        new_sid = secrets.token_urlsafe(12)
        return identity, new_sid, fp, True, "anon"

HONEYPOT_PATHS = {
    # web admin / config
    "/wp-admin", "/wp-login.php", "/.env", "/.git/config", "/.git/HEAD",
    "/admin-backup", "/config.php.bak", "/phpinfo.php", "/info.php",
    "/xmlrpc.php", "/.aws/credentials", "/.aws/config", "/server-status",
    "/.well-known/admin", "/admin.php", "/phpmyadmin", "/pma",
    # Common shell scanner targets
    "/setup.sh", "/install.sh", "/run.sh", "/init.sh", "/shell.php",
    "/cgi-bin/.%2e/.%2e/etc/passwd", "/.DS_Store",
    # CVE scanners
    "/actuator/env", "/actuator/heapdump", "/console",
    "/manager/html", "/jenkins", "/jolokia",
    # Backup/secret files
    "/backup.sql", "/backup.zip", "/backup.tar.gz", "/dump.sql",
    "/database.sql", "/credentials.json", "/secrets.yaml",
    # Cloud metadata probes (SSRF tests)
    "/latest/meta-data/", "/computeMetadata/v1/",
    # Honey-links injected into HTML — visible only to HTML parsers (AI/scrapers),
    # invisible to humans (display:none, font-size:0, opacity:0 wrappers)
    "/_internal/audit-log", "/_internal/admin-api",
    "/api/_debug/dump", "/api/v0/admin",
    "/staff/dashboard.json", "/.crawler-trap/secrets",
}

# Path PATTERNS (regex) that indicate file-hunting / CTF reconnaissance.
# Triggered for paths with substrings like "flag", "secret", "*.bak", etc.
# Matches anywhere in the path (case-insensitive) so /myflag.txt,
# /api/secret/v2, /backup.tar.gz are all caught.
SUSPICIOUS_PATH_PATTERNS = (
    # Flag/CTF hunting — patterns target FILES (with extension) or last path
    # segment, not arbitrary substrings, so legit module names like
    # "password-recovery" or "credentials-manager" don't false-positive.
    re.compile(r"(^|/)flag(\.[a-z0-9]+|$)",                re.I),
    re.compile(r"(^|/)secret[s]?(\.[a-z0-9]+|$)",          re.I),
    re.compile(r"(^|/)passwd(\.[a-z0-9]+|$)",              re.I),
    re.compile(r"(^|/)password[s]?(\.[a-z0-9]+|$)",        re.I),
    re.compile(r"(^|/)credentials?\.(json|yaml|yml|txt|conf|ini)$", re.I),
    re.compile(r"(^|/)private[_-]?key(\.[a-z0-9]+|$)",     re.I),
    re.compile(r"(^|/)api[_-]?key(\.[a-z0-9]+|$)",         re.I),
    re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa)(\.[a-z0-9]+|$)", re.I),
    # Backup / leak files
    re.compile(r"\.(bak|old|orig|tmp|swp|sav|backup)$",      re.I),
    re.compile(r"\.(sql|sqlite|db|mdb|sqlite3)$",             re.I),
    re.compile(r"^/[^/]*\.(pem|key|crt|pfx|p12|jks)$",        re.I),
    # VCS metadata leaks
    re.compile(r"\.git/", re.I),
    re.compile(r"\.svn/", re.I),
    re.compile(r"\.hg/",  re.I),
    re.compile(r"\.DS_Store", re.I),
    # Debug/internal endpoints
    re.compile(r"^/debug",     re.I),
    re.compile(r"^/_internal", re.I),
    # ── Injection / traversal patterns ──
    re.compile(r"\.\.[\\/]"),                              # path traversal: ../  ..\
    re.compile(r"%2e%2e[%/]",                  re.I),     # URL-encoded ..
    re.compile(r"%252e%252e",                  re.I),     # double-encoded
    re.compile(r"%c0%ae",                      re.I),     # overlong UTF-8 ..
    # SQLi / XSS markers in path
    re.compile(r"(union[ +]+select|select[ +]+\*|or[ +]+1=1|--$|/\*|\bxp_)", re.I),
    re.compile(r"<script|javascript:|onerror=", re.I),
    # OS / file inclusion
    re.compile(r"/etc/passwd|/etc/shadow|/proc/self", re.I),
    re.compile(r"\bphp://|\bfile://|\bexpect://", re.I),
    # Shell injection
    re.compile(r"[;&|`]\s*(cat|ls|wget|curl|nc|sh|bash)\b", re.I),
)
def is_suspicious_path(path: str) -> bool:
    return any(p.search(path) for p in SUSPICIOUS_PATH_PATTERNS)

# HTML snippet to inject into upstream HTML responses.
# AI parsers / scrapers that follow links will hit /_internal/audit-log → ban.
HONEY_LINK_HTML = (
    '<div style="display:none!important;visibility:hidden;height:0;width:0;'
    'overflow:hidden;position:absolute;left:-99999px" aria-hidden="true">'
    '<a href="/_internal/audit-log" rel="nofollow">Internal audit log (do not follow)</a>'
    '<a href="/api/_debug/dump" rel="nofollow">Debug dump</a>'
    '<a href="/staff/dashboard.json" rel="nofollow">Staff dashboard</a>'
    '</div>'
)

UA_BLOCKLIST = (
    # CLI / scripting libs
    "curl/", "wget/", "fetch/", "httpie/",
    "python-requests/", "python-urllib", "python/", "urllib", "urllib3/",
    "aiohttp/", "httpx/", "httpcore/", "tornado/",
    "go-http-client/", "go-resty/", "fasthttp/",
    "java/", "okhttp/", "apache-httpclient/", "jersey/",
    "ruby/", "faraday/", "rest-client/",
    "node-fetch/", "axios/", "got/", "undici/",
    "powershell/", "winhttp/", "winhttp.winhttprequest",
    "perl/", "lwp::", "guzzlehttp/", "php/",
    # Crawlers / scanners
    "scrapy/", "crawler", "spider", "bot/", "scraper",
    "nuclei", "nikto", "sqlmap", "wpscan", "wfuzz", "ffuf", "gobuster", "dirb",
    "burp", "zap/", "zaproxy", "masscan", "nmap", "arachni",
    # AI / LLM agents (commercial APIs + frameworks + tools)
    "claude", "chatgpt", "openai", "gptbot", "anthropic", "perplexity",
    "claudebot", "google-extended", "amazonbot", "bytespider",
    "langchain", "llamaindex", "autogen", "crewai", "auto-gpt", "babyagi",
    "litellm", "openrouter", "cohere", "mistral", "groq",
    "ollama", "anthropic-ai", "openai-python", "llm-",
    "cursor", "codeium", "copilot", "tabnine",
    # Headless browsers
    "selenium", "headless", "puppeteer", "playwright", "phantomjs",
    "electron", "cypress", "webdriver", "chromedriver", "geckodriver",
    # Misc red flags
    "test", "monitor", "uptime", "pingdom", "scanner",
)

# ── AI agent specific path probes (often hit during enumeration) ───────────
AI_PROBE_PATHS = {
    "/.well-known/openapi", "/.well-known/ai-plugin.json",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/swagger-ui", "/swagger-ui.html", "/api/swagger", "/api-docs",
    "/v1/models", "/v1/chat", "/v1/completions",
    "/.well-known/llm.txt", "/.well-known/ai.txt", "/llms.txt",
    "/sitemap_ai.xml", "/ai-readme.md",
}

# Operator-configurable. PoW is only required for paths in this set.
# Default is empty so a typical SPA auth flow is not blocked. Set
# POW_REQUIRED_PATHS=/login,/admin via env to opt-in for sensitive paths.
_pow_paths_raw = os.environ.get("POW_REQUIRED_PATHS", "")
POW_REQUIRED_PATHS = {p.strip() for p in _pow_paths_raw.split(",") if p.strip()}
# Whether to also require PoW for ALL state-changing methods (POST/PUT/DELETE).
# Default off — too aggressive for legitimate JS/REST traffic.
POW_REQUIRE_ALL_WRITES = os.environ.get("POW_REQUIRE_ALL_WRITES", "0") in ("1", "true", "yes")

# ── State ──────────────────────────────────────────────────────────────────
@dataclass
class IpState:
    tokens: float = float(RATE_LIMIT_BURST)
    last_refill: float = field(default_factory=time.monotonic)
    banned_until: float = 0.0
    request_times: deque = field(default_factory=lambda: deque(maxlen=50))
    request_count: int = 0
    first_seen: float = field(default_factory=time.monotonic)
    # per-IP metrics
    allowed_count: int = 0
    blocked_count: int = 0
    blocks_by_reason: dict = field(default_factory=lambda: defaultdict(int))
    last_seen: float = field(default_factory=time.monotonic)
    last_user_agent: str = ""
    last_path: str = ""
    # Anti-AI behavioral tracking
    unique_paths: set = field(default_factory=set)        # distinct paths visited
    html_loads: int = 0                                    # HTML responses received
    static_loads: int = 0                                  # CSS/JS/img/font fetches
    suspicion_score: int = 0                               # cumulative AI signals (0-100)
    # Hybrid identity helpers (for dashboard display only)
    last_ip: str = ""
    last_session: str = ""
    last_fingerprint: str = ""
    last_ja4: str = ""        # R0: TLS handshake fingerprint (telemetry only)
    # Behavioral risk score — drives ban decision
    risk_score: float = 0.0
    last_risk_update: float = field(default_factory=time.monotonic)
    # Stealth-agent telemetry (allowed traffic only — used by /__agents)
    header_scores: deque = field(default_factory=lambda: deque(maxlen=20))
    upstream_404_count: int = 0
    last_allowed_paths: deque = field(default_factory=lambda: deque(maxlen=10))

MAX_IDENTITIES = int(os.environ.get("MAX_IDENTITIES", "100000"))
PRUNE_IDLE_SECS = int(os.environ.get("PRUNE_IDLE_SECS", "86400"))  # 24h
PRUNE_INTERVAL_SECS = 600  # run every 10 min

ip_state: Dict[str, IpState] = defaultdict(IpState)
state_lock = asyncio.Lock()

async def _prune_state_loop():
    """Background coroutine: evict idle identities + cap total count.
    Defends against unbounded growth from XFF spoofing or UA rotation."""
    while True:
        try:
            await asyncio.sleep(PRUNE_INTERVAL_SECS)
            async with state_lock:
                n = now()
                # 1. Evict by idle time
                idle = [k for k, s in ip_state.items()
                        if s.banned_until <= n
                        and (n - s.last_seen) > PRUNE_IDLE_SECS]
                for k in idle:
                    del ip_state[k]
                # 2. Cap total count — drop oldest-last-seen first
                if len(ip_state) > MAX_IDENTITIES:
                    overflow = len(ip_state) - MAX_IDENTITIES
                    candidates = sorted(
                        ((k, s.last_seen) for k, s in ip_state.items()
                         if s.banned_until <= n),
                        key=lambda kv: kv[1],
                    )[:overflow]
                    for k, _ in candidates:
                        del ip_state[k]
                # 3. Prune the per-IP new-session identity map
                stale_ips = [ip for ip, m in ip_new_sessions.items()
                             if not m or max(m.values()) < n - 3600]
                for ip in stale_ips:
                    del ip_new_sessions[ip]
                # 4. N7: prune the socket-IP token-bucket dict (idle > 1h).
                stale_buckets = [ip for ip, b in ip_buckets.items()
                                 if (n - b["last"]) > 3600]
                for ip in stale_buckets:
                    del ip_buckets[ip]
                # 4b. Hard cap on ip_buckets — trim oldest if still over.
                if len(ip_buckets) > MAX_IDENTITIES:
                    overflow = len(ip_buckets) - MAX_IDENTITIES
                    candidates = sorted(ip_buckets.items(),
                                        key=lambda kv: kv[1]["last"])[:overflow]
                    for k, _ in candidates:
                        del ip_buckets[k]
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[prune] error: {e}")

# ── Global metrics + event log ─────────────────────────────────────────────
import time as _t
START_EPOCH = _t.time()
metrics = {
    "total_requests": 0,
    "allowed": 0,
    "blocked": 0,
    "by_reason": defaultdict(int),    # {"banned":N, "honeypot":N, "ua-blocked":N, ...}
    "by_status": defaultdict(int),    # {200:N, 403:N, 429:N, 402:N, 502:N}
    "by_path":   defaultdict(int),    # top requested paths
    "by_ja4":    defaultdict(int),    # R0: TLS handshake fingerprints seen
    "rps_buckets": deque(maxlen=60),  # one entry per second (last 60s)
}
events = deque(maxlen=200)            # last 200 events for the live log

# ── SQLite persistence ─────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "antibot.db"))

def db_init():
    """Create tables if they don't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS events (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      REAL NOT NULL,
        ip      TEXT NOT NULL,
        ua      TEXT,
        path    TEXT,
        method  TEXT,
        status  INTEGER,
        reason  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts     ON events(ts);
    CREATE INDEX IF NOT EXISTS idx_events_ip     ON events(ip);
    CREATE INDEX IF NOT EXISTS idx_events_reason ON events(reason);

    CREATE TABLE IF NOT EXISTS clients (
        ip                TEXT PRIMARY KEY,
        first_seen        REAL,
        last_seen         REAL,
        request_count     INTEGER DEFAULT 0,
        allowed_count     INTEGER DEFAULT 0,
        blocked_count     INTEGER DEFAULT 0,
        banned_until_epoch REAL DEFAULT 0,
        last_user_agent   TEXT,
        last_path         TEXT,
        blocks_by_reason  TEXT  -- JSON
    );

    CREATE TABLE IF NOT EXISTS metrics_kv (
        key  TEXT PRIMARY KEY,
        val  TEXT
    );

    CREATE TABLE IF NOT EXISTS timeline (
        bucket_minute INTEGER PRIMARY KEY,
        total         INTEGER DEFAULT 0,
        allowed       INTEGER DEFAULT 0,
        blocked       INTEGER DEFAULT 0,
        by_reason     TEXT  -- JSON
    );

    CREATE TABLE IF NOT EXISTS bans (
        ip            TEXT PRIMARY KEY,
        banned_until  REAL,
        reason        TEXT,
        ts            REAL
    );

    CREATE TABLE IF NOT EXISTS svc_metrics (
        ts          REAL PRIMARY KEY,
        cpu_pct     REAL,
        load1       REAL, load5 REAL, load15 REAL,
        mem_used    INTEGER, mem_total INTEGER, mem_avail INTEGER, mem_pct REAL,
        swap_used   INTEGER, swap_total INTEGER,
        cg_used     INTEGER, cg_limit INTEGER, cg_pct REAL,
        disk_used   INTEGER, disk_total INTEGER, disk_avail INTEGER, disk_pct REAL,
        procs       INTEGER, open_fds INTEGER,
        net_rx_bps  INTEGER, net_tx_bps INTEGER,
        db_db       INTEGER, db_wal INTEGER, db_shm INTEGER, db_total INTEGER
    );
    """)
    conn.commit()
    conn.close()

# Async DB writer queue — events are batched to avoid blocking the event loop
db_queue: asyncio.Queue = None
db_writer_task = None
prune_task = None
service_metrics_task = None

# ── v1.4: Service-metrics collection (no psutil dep — pure /proc + os) ───
SERVICE_METRICS_INTERVAL = float(os.environ.get("SVC_METRICS_INTERVAL", "5"))   # secs
SERVICE_METRICS_RETENTION = int(os.environ.get("SVC_METRICS_RETENTION", "8640"))  # in-mem samples (8640 * 5s = 12 h)
SVC_DB_RETENTION_HOURS = int(os.environ.get("SVC_DB_RETENTION_HOURS", "168"))    # on-disk retention (default 7 days)
SERVICE_METRICS_HISTORY: deque = deque(maxlen=SERVICE_METRICS_RETENTION)
_PROC = "/proc"
_DATA_PATH = os.environ.get("DB_PATH", "/data/antibot.db")

def _read_proc_stat():
    try:
        with open(f"{_PROC}/stat") as f:
            line = f.readline().split()
        # cpu user nice system idle iowait irq softirq steal guest guest_nice
        nums = [int(x) for x in line[1:]]
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
        total = sum(nums)
        return total, idle
    except Exception:
        return None, None

def _read_meminfo() -> dict:
    out = {}
    try:
        with open(f"{_PROC}/meminfo") as f:
            for line in f:
                k, _, rest = line.partition(":")
                v = rest.strip().split()
                if v:
                    out[k.strip()] = int(v[0]) * 1024   # kB → bytes
    except Exception:
        pass
    return out

def _read_cgroup_mem() -> dict:
    """Try cgroup v2 first, then v1. Returns container memory (used / limit)."""
    out = {}
    for usage, limit in [
        ("/sys/fs/cgroup/memory.current",      "/sys/fs/cgroup/memory.max"),
        ("/sys/fs/cgroup/memory/memory.usage_in_bytes",
         "/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    ]:
        try:
            with open(usage) as f: u = int(f.read().strip())
            with open(limit) as f:
                lv = f.read().strip()
                l = int(lv) if lv != "max" else -1
            out["used"] = u
            out["limit"] = l
            return out
        except Exception:
            continue
    return out

def _db_file_sizes() -> dict:
    """Return on-disk sizes of the SQLite database + its sidecars (WAL/SHM)."""
    out = {"db": 0, "wal": 0, "shm": 0, "total": 0}
    base = _DATA_PATH
    for kind, path in [("db", base), ("wal", base + "-wal"), ("shm", base + "-shm")]:
        try:
            out[kind] = os.path.getsize(path)
        except (OSError, FileNotFoundError):
            pass
    out["total"] = out["db"] + out["wal"] + out["shm"]
    return out

def _disk_usage(path: str) -> dict:
    try:
        s = os.statvfs(path)
        total = s.f_frsize * s.f_blocks
        avail = s.f_frsize * s.f_bavail
        used  = total - avail
        return {"total": total, "used": used, "avail": avail,
                "pct": (used / total * 100) if total else 0.0}
    except Exception:
        return {}

def _proc_count() -> int:
    try:
        return sum(1 for d in os.listdir(_PROC) if d.isdigit())
    except Exception:
        return 0

def _fd_count() -> int:
    try:
        return len(os.listdir(f"{_PROC}/self/fd"))
    except Exception:
        return 0

def _read_loadavg() -> tuple:
    try:
        return os.getloadavg()
    except (OSError, AttributeError):
        return (0.0, 0.0, 0.0)

def _read_net_dev() -> dict:
    """Per-interface RX/TX byte counters (cumulative since boot)."""
    out = {}
    try:
        with open(f"{_PROC}/net/dev") as f:
            lines = f.readlines()[2:]
        for line in lines:
            iface, _, vals = line.partition(":")
            iface = iface.strip()
            if iface in ("lo",):       # skip loopback for clarity
                continue
            parts = vals.split()
            if len(parts) >= 16:
                out[iface] = {"rx_bytes": int(parts[0]), "tx_bytes": int(parts[8])}
    except Exception:
        pass
    return out

async def _sample_service_metrics_loop():
    last_total, last_idle = _read_proc_stat()
    last_net = _read_net_dev()
    last_ts = _t.time()
    while True:
        try:
            await asyncio.sleep(SERVICE_METRICS_INTERVAL)
            now_ts = _t.time()
            elapsed = max(0.001, now_ts - last_ts)

            total, idle = _read_proc_stat()
            cpu_pct = 0.0
            if total is not None and last_total is not None:
                d_total = total - last_total
                d_idle  = idle  - last_idle
                if d_total > 0:
                    cpu_pct = (d_total - d_idle) / d_total * 100.0
            last_total, last_idle = total, idle

            mem = _read_meminfo()
            cg  = _read_cgroup_mem()
            mem_total = mem.get("MemTotal", 0)
            mem_avail = mem.get("MemAvailable", 0)
            mem_used  = mem_total - mem_avail
            swap_total = mem.get("SwapTotal", 0)
            swap_used  = swap_total - mem.get("SwapFree", 0)
            disk = _disk_usage(os.path.dirname(_DATA_PATH) or "/")

            now_net = _read_net_dev()
            net_rx_per_s = 0
            net_tx_per_s = 0
            for iface, cur in now_net.items():
                prev = last_net.get(iface)
                if prev:
                    net_rx_per_s += max(0, (cur["rx_bytes"] - prev["rx_bytes"]) / elapsed)
                    net_tx_per_s += max(0, (cur["tx_bytes"] - prev["tx_bytes"]) / elapsed)
            last_net = now_net
            last_ts = now_ts

            l1, l5, l15 = _read_loadavg()
            sample = {
                "ts":            now_ts,
                "cpu_pct":       round(cpu_pct, 1),
                "load1":         round(l1, 2),
                "load5":         round(l5, 2),
                "load15":        round(l15, 2),
                "mem_total":     mem_total,
                "mem_used":      mem_used,
                "mem_avail":     mem_avail,
                "mem_pct":       round(mem_used / mem_total * 100, 1) if mem_total else 0,
                "swap_total":    swap_total,
                "swap_used":     swap_used,
                "cg_used":       cg.get("used", 0),
                "cg_limit":      cg.get("limit", -1),
                "cg_pct":        round(cg.get("used", 0) / cg.get("limit", 1) * 100, 1)
                                   if cg.get("limit", -1) > 0 else 0,
                "disk_total":    disk.get("total", 0),
                "disk_used":     disk.get("used", 0),
                "disk_avail":    disk.get("avail", 0),
                "disk_pct":      round(disk.get("pct", 0), 1),
                "procs":         _proc_count(),
                "open_fds":      _fd_count(),
                "net_rx_bps":    int(net_rx_per_s),
                "net_tx_bps":    int(net_tx_per_s),
                **{f"db_{k}": v for k, v in _db_file_sizes().items()},
            }
            SERVICE_METRICS_HISTORY.append(sample)

            # Persist to SQLite via the async writer so chart history survives
            # container restarts. Tuple matches the svc_metrics column order.
            if db_queue is not None:
                row = (
                    sample["ts"], sample["cpu_pct"],
                    sample["load1"], sample["load5"], sample["load15"],
                    sample["mem_used"], sample["mem_total"], sample["mem_avail"],
                    sample["mem_pct"],
                    sample["swap_used"], sample["swap_total"],
                    sample["cg_used"], sample["cg_limit"], sample["cg_pct"],
                    sample["disk_used"], sample["disk_total"],
                    sample["disk_avail"], sample["disk_pct"],
                    sample["procs"], sample["open_fds"],
                    sample["net_rx_bps"], sample["net_tx_bps"],
                    sample.get("db_db", 0), sample.get("db_wal", 0),
                    sample.get("db_shm", 0), sample.get("db_total", 0),
                )
                try:
                    db_queue.put_nowait(("svc_metric", row))
                except asyncio.QueueFull:
                    pass
                # Prune older than retention every ~120 samples (~10 min).
                if int(now_ts) % (120 * int(SERVICE_METRICS_INTERVAL or 5)) < SERVICE_METRICS_INTERVAL:
                    try:
                        db_queue.put_nowait(("svc_metric_prune",
                                             (now_ts - SVC_DB_RETENTION_HOURS * 3600,)))
                    except asyncio.QueueFull:
                        pass
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[svc-metrics] sample error: {e}", flush=True)

WAL_CHECKPOINT_EVERY_SECS = float(os.environ.get("WAL_CHECKPOINT_EVERY_SECS", "60"))

async def db_writer_loop():
    """Background coroutine: drains the queue and flushes to SQLite in batches.
    Periodically runs `wal_checkpoint(TRUNCATE)` so the WAL file stays small
    instead of inflating between auto-checkpoints (cosmetic + reduces the
    'shrinkage' visible in the SQLite-size chart at every restart)."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")  # better concurrency
    conn.execute("PRAGMA synchronous=NORMAL")
    last_checkpoint = _t.time()
    while True:
        try:
            batch = [await db_queue.get()]
            # Drain up to 100 more items if available (without waiting)
            while len(batch) < 100:
                try:
                    batch.append(db_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            for op, args in batch:
                try:
                    if op == "event":
                        conn.execute(
                            "INSERT INTO events (ts,ip,ua,path,method,status,reason) "
                            "VALUES (?,?,?,?,?,?,?)", args)
                    elif op == "upsert_client":
                        conn.execute("""
                          INSERT INTO clients (ip, first_seen, last_seen, request_count,
                                               allowed_count, blocked_count, banned_until_epoch,
                                               last_user_agent, last_path, blocks_by_reason)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(ip) DO UPDATE SET
                            last_seen=excluded.last_seen,
                            request_count=excluded.request_count,
                            allowed_count=excluded.allowed_count,
                            blocked_count=excluded.blocked_count,
                            banned_until_epoch=excluded.banned_until_epoch,
                            last_user_agent=excluded.last_user_agent,
                            last_path=excluded.last_path,
                            blocks_by_reason=excluded.blocks_by_reason
                        """, args)
                    elif op == "upsert_timeline":
                        conn.execute("""
                          INSERT INTO timeline (bucket_minute,total,allowed,blocked,by_reason)
                          VALUES (?, ?, ?, ?, ?)
                          ON CONFLICT(bucket_minute) DO UPDATE SET
                            total=excluded.total, allowed=excluded.allowed,
                            blocked=excluded.blocked, by_reason=excluded.by_reason
                        """, args)
                    elif op == "set_kv":
                        conn.execute("INSERT OR REPLACE INTO metrics_kv (key,val) VALUES (?,?)", args)
                    elif op == "ban":
                        conn.execute("""
                          INSERT INTO bans (ip,banned_until,reason,ts) VALUES (?,?,?,?)
                          ON CONFLICT(ip) DO UPDATE SET banned_until=excluded.banned_until,
                                                        reason=excluded.reason, ts=excluded.ts
                        """, args)
                    elif op == "svc_metric":
                        # args is a tuple of values matching the column order.
                        conn.execute("""
                          INSERT OR REPLACE INTO svc_metrics
                          (ts, cpu_pct, load1, load5, load15,
                           mem_used, mem_total, mem_avail, mem_pct,
                           swap_used, swap_total, cg_used, cg_limit, cg_pct,
                           disk_used, disk_total, disk_avail, disk_pct,
                           procs, open_fds, net_rx_bps, net_tx_bps,
                           db_db, db_wal, db_shm, db_total)
                          VALUES (?, ?, ?, ?, ?,
                                  ?, ?, ?, ?,
                                  ?, ?, ?, ?, ?,
                                  ?, ?, ?, ?,
                                  ?, ?, ?, ?,
                                  ?, ?, ?, ?)
                        """, args)
                    elif op == "svc_metric_prune":
                        # args = (cutoff_ts,)
                        conn.execute("DELETE FROM svc_metrics WHERE ts < ?", args)
                except Exception as e:
                    print(f"[db] write failed: {e} args={args!r}")
            conn.commit()

            # Truncate the WAL on a timer so it doesn't accumulate between
            # auto-checkpoints. PASSIVE first (no locking); only TRUNCATE if
            # we get the chance.
            now_ts = _t.time()
            if now_ts - last_checkpoint > WAL_CHECKPOINT_EVERY_SECS:
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.OperationalError:
                    pass    # readers active, retry next tick
                last_checkpoint = now_ts
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[db] loop error: {e}")

def db_load_state():
    """Load saved state at startup."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    n = _t.time()
    # Load clients (cap to MAX_IDENTITIES, newest first)
    rows = conn.execute(
        "SELECT * FROM clients ORDER BY last_seen DESC LIMIT ?",
        (MAX_IDENTITIES,)
    ).fetchall()
    for r in rows:
        s = ip_state[r["ip"]]
        s.first_seen   = n - max(0, n - (r["first_seen"] or n))  # keep monotonic-relative
        s.last_seen    = n - max(0, n - (r["last_seen"] or n))
        s.request_count = r["request_count"] or 0
        s.allowed_count = r["allowed_count"] or 0
        s.blocked_count = r["blocked_count"] or 0
        # banned_until is monotonic; if epoch > now, restore offset
        if r["banned_until_epoch"] and r["banned_until_epoch"] > n:
            s.banned_until = now() + (r["banned_until_epoch"] - n)
        s.last_user_agent = r["last_user_agent"] or ""
        s.last_path = r["last_path"] or ""
        if r["blocks_by_reason"]:
            try: s.blocks_by_reason = defaultdict(int, json.loads(r["blocks_by_reason"]))
            except: pass

    # Compute global totals from events table (always accurate, beats stale KV)
    row = conn.execute("""
        SELECT COUNT(*) AS total,
               SUM(CASE WHEN reason='' OR reason='OK' THEN 1 ELSE 0 END) AS allowed,
               SUM(CASE WHEN reason!='' AND reason!='OK' THEN 1 ELSE 0 END) AS blocked
          FROM events
    """).fetchone()
    metrics["total_requests"] = row["total"] or 0
    metrics["allowed"] = row["allowed"] or 0
    metrics["blocked"] = row["blocked"] or 0

    # Reason breakdown from events
    for r in conn.execute(
        "SELECT reason, COUNT(*) AS n FROM events WHERE reason!='' AND reason!='OK' GROUP BY reason"
    ):
        metrics["by_reason"][r["reason"]] = r["n"]

    # Status breakdown
    for r in conn.execute(
        "SELECT status, COUNT(*) AS n FROM events GROUP BY status"
    ):
        metrics["by_status"][int(r["status"])] = r["n"]

    # Path top counts (only top 100 to limit memory)
    for r in conn.execute(
        "SELECT path, COUNT(*) AS n FROM events GROUP BY path ORDER BY n DESC LIMIT 100"
    ):
        metrics["by_path"][r["path"] or ""] = r["n"]

    # Load timeline
    for row in conn.execute("SELECT * FROM timeline"):
        timeline[row["bucket_minute"]] = {
            "total": row["total"], "allowed": row["allowed"], "blocked": row["blocked"],
            "by_reason": defaultdict(int, json.loads(row["by_reason"] or "{}")),
        }

    # Load recent events into the in-memory deque (last 200)
    for row in conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 200"):
        events.appendleft({
            "ts": row["ts"], "ip": row["ip"], "ua": row["ua"] or "",
            "path": row["path"] or "", "method": row["method"] or "",
            "status": row["status"] or 0, "reason": row["reason"] or "OK",
        })

    # Re-hydrate the service-metrics history (last RETENTION samples in time
    # order). Skips silently if the table doesn't exist yet (first boot
    # against an old DB).
    svc_loaded = 0
    try:
        cur = conn.execute(
            "SELECT * FROM svc_metrics ORDER BY ts DESC LIMIT ?",
            (SERVICE_METRICS_RETENTION,))
        rows_svc = cur.fetchall()
        for row in reversed(rows_svc):       # oldest-first into the deque
            SERVICE_METRICS_HISTORY.append({k: row[k] for k in row.keys()})
        svc_loaded = len(rows_svc)
    except Exception as e:
        print(f"[db] svc_metrics not loaded: {e}")
    conn.close()
    print(f"[db] loaded: {len(rows)} clients, {len(timeline)} timeline buckets, "
          f"{metrics['total_requests']} total requests, "
          f"{svc_loaded} svc-metrics samples")

# ── Timeline: per-minute buckets, last 24h ─────────────────────────────────
TIMELINE_RETAIN_SECS = 86400  # 24 hours
timeline = {}                  # {minute_epoch_int: {"total","blocked","allowed","by_reason":{}}}

def _bucket_now() -> int:
    """Return the current minute bucket (epoch seconds rounded to the minute)."""
    return int(_t.time() // 60) * 60

def _timeline_bump(reason: str):
    """Update the current minute bucket. Caller must hold state_lock."""
    b = _bucket_now()
    if b not in timeline:
        timeline[b] = {"total": 0, "blocked": 0, "allowed": 0,
                       "by_reason": defaultdict(int)}
        # cleanup buckets older than retention
        cutoff = b - TIMELINE_RETAIN_SECS
        for k in [k for k in timeline if k < cutoff]:
            del timeline[k]
    bucket = timeline[b]
    bucket["total"] += 1
    if reason:
        bucket["blocked"] += 1
        bucket["by_reason"][reason] += 1
    else:
        bucket["allowed"] += 1

def now() -> float:
    return time.monotonic()

# ── Helpers ────────────────────────────────────────────────────────────────
TRUST_XFF = os.environ.get("TRUST_XFF", "first").lower()  # first | last | none

# 1.4.6 — structured logging + request correlation IDs.
# When LOG_FORMAT=json, every log line is a one-line JSON document so it can
# be ingested by Loki / Splunk / CloudWatch / etc. unchanged. The default
# stays text for human-readable single-host runs. Each request gets a short
# request_id that threads through the middleware, every decision (allow /
# silent-decoy / explicit deny), the events deque, the dashboard live log,
# and the response's X-Request-ID header — enabling end-to-end forensics.
LOG_FORMAT = os.environ.get("LOG_FORMAT", "text").lower()
LOG_LEVEL  = os.environ.get("LOG_LEVEL",  "info").lower()
_LOG_LEVELS = {"debug": 10, "info": 20, "warn": 30, "warning": 30,
               "error": 40, "critical": 50}
_LOG_LEVEL_N = _LOG_LEVELS.get(LOG_LEVEL, 20)
_REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_\-:.]{1,64}$")

def _new_request_id() -> str:
    """Short, sortable-by-time, easy to grep request id."""
    return f"r{int(time.time())%100000:05d}{secrets.token_hex(4)}"

def slog(event: str, level: str = "info", **fields) -> None:
    """Structured log line. In `text` mode prints a compact key=value form;
    in `json` mode emits one JSON document per line (no embedded newlines)."""
    if _LOG_LEVELS.get(level, 20) < _LOG_LEVEL_N:
        return
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if LOG_FORMAT == "json":
        try:
            line = json.dumps({"ts": ts, "level": level, "event": event,
                               **fields}, separators=(",", ":"),
                              default=str, ensure_ascii=False)
        except (TypeError, ValueError):
            # Defensive: never raise from a log call.
            line = json.dumps({"ts": ts, "level": level, "event": event,
                               "_log_error": "unserialisable_field"})
        print(line, flush=True)
    else:
        kv = " ".join(f"{k}={v!r}" for k, v in fields.items())
        print(f"[{ts}] {level} {event} {kv}", flush=True)

def get_ip(request: web.Request) -> str:
    """
    TRUST_XFF=first  → vulnerable: attacker-controlled (default, for bypass demos)
    TRUST_XFF=last   → secure: trusts only the last hop (ngrok-injected real IP)
    TRUST_XFF=none   → ignore XFF, use raw socket peer
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff and TRUST_XFF != "none":
        parts = [p.strip() for p in xff.split(",")]
        return parts[0] if TRUST_XFF == "first" else parts[-1]
    return request.remote or "0.0.0.0"

async def is_banned(ip: str) -> tuple[bool, float]:
    async with state_lock:
        s = ip_state[ip]
        n = now()
        if s.banned_until > n:
            return True, s.banned_until - n
    return False, 0.0

async def ban(ip: str, secs: int = HONEYPOT_BAN_SECS, reason: str = "honeypot"):
    async with state_lock:
        ip_state[ip].banned_until = now() + secs
    if db_queue is not None:
        try:
            db_queue.put_nowait(("ban", (ip, _t.time() + secs, reason, _t.time())))
        except asyncio.QueueFull:
            pass

# ── Risk-score model ───────────────────────────────────────────────────────
# Each bad behaviour contributes points; ban only when score crosses threshold.
# Threshold scales with NAT-suspicion: shared-IP environments need MORE evidence
# before a ban is applied, so one rogue session doesn't punish colleagues.
RISK_WEIGHTS = {
    "honeypot":              50,
    "honeypot-silent":       50,
    "suspicious-path":       40,    # CTF / file-hunting reconnaissance
    "ai-probe":              30,
    "ai-enumeration":        30,
    "behavior":              10,
    "ua-empty":              25,
    "ua-blocked":            20,
    "ua-non-browser":        20,
    "ai-headers-empty":      15,
    "ua-too-short":          15,
    "ai-headers-incomplete":  8,
    "upstream-404":           4,    # 404 from upstream — small enumeration signal
    "ai-no-assets":           5,
    "session-flood":          5,
    # Rate-limit hits are benign throttling (browsers parallel-fetching N
    # sub-resources) — they should NOT escalate to ban. The throttling itself
    # is sufficient mitigation; adding risk causes legitimate bursts to ban
    # the user.
    "rate-limit-ip":          0,
    "rate-limit":             0,
    "host-not-allowed":      40,
    "suspicious-body":       40,    # v1.4: body pattern match
    "bot-trap":              50,    # v1.4: hidden form field filled
    "canary-echo":           80,    # R7 (1.4.3): AI-canary echoed back —
                                    # near-zero false positive; one hit = ban
    "js-challenge":           5,    # v1.4: each unsolved challenge bumps slightly
    "tls-fingerprint":       30,    # v1.4.2: JA3/JA4 deny-list hit
    "origin-mismatch":       20,    # v1.4.2: STRICT_ORIGIN failure
    "missing-required-header": 15,  # v1.4.2: REQUIRED_HEADERS absent
}
RISK_BAN_THRESHOLD       = 50    # ban when score crosses this for normal IPs
RISK_BAN_THRESHOLD_NAT   = 100   # higher threshold when IP looks like NAT
RISK_DECAY_HALFLIFE_SECS = 3600  # score halves every hour
NAT_IDENTITIES_THRESHOLD = 5     # >= N distinct identities at same IP → NAT-like
RISK_BAN_DURATION_SECS   = 3600  # ban duration once threshold crossed

def _decay_risk(state, now_ts: float):
    """Apply exponential decay to risk_score based on elapsed time."""
    elapsed = max(0.0, now_ts - state.last_risk_update)
    if elapsed > 0 and state.risk_score > 0:
        state.risk_score *= 0.5 ** (elapsed / RISK_DECAY_HALFLIFE_SECS)
        if state.risk_score < 0.5:
            state.risk_score = 0.0
    state.last_risk_update = now_ts

async def update_risk_and_maybe_ban(track_key: str, reason: str, ip: str) -> bool:
    """
    Add risk for this reason. Ban only if accumulated score crosses threshold,
    using a higher threshold when the IP appears to be a NAT (many identities).
    Returns True if a ban was applied.
    """
    weight = RISK_WEIGHTS.get(reason, 0)
    if weight == 0:
        return False
    async with state_lock:
        n = now()
        s = ip_state[track_key]
        _decay_risk(s, n)
        s.risk_score += weight
        # M7: count only "legitimate-looking" identities at this IP toward NAT
        # detection. An attacker rotating UAs to spawn fake identities cannot
        # inflate this count because fake identities never fetch static assets
        # nor accumulate allowed requests.
        identities_at_ip = sum(
            1 for k, st in ip_state.items()
            if st.last_ip == ip
            and (n - st.last_seen) < 3600
            and st.static_loads >= 1
            and st.allowed_count >= 3
        )
        threshold = (
            RISK_BAN_THRESHOLD_NAT if identities_at_ip >= NAT_IDENTITIES_THRESHOLD
            else RISK_BAN_THRESHOLD
        )
        if s.risk_score >= threshold and s.banned_until <= n:
            # R8: AI-agent-specific reasons land the identity in the
            # "hostile pool" — kept silent-decoyed for HOSTILE_BAN_SECS
            # (default 24 h). Generic bans stay at the shorter duration.
            ban_secs = (HOSTILE_BAN_SECS if reason in _HOSTILE_REASONS
                        else RISK_BAN_DURATION_SECS)
            s.banned_until = n + ban_secs
            triggered = True
            ban_dur = ban_secs
        else:
            triggered = False
            ban_dur = 0
    if triggered and db_queue is not None:
        try:
            db_queue.put_nowait(("ban",
                (track_key, _t.time() + ban_dur,
                 f"risk-score:{int(s.risk_score)}:{reason}", _t.time())))
        except asyncio.QueueFull:
            pass
    return triggered

# H4: socket-IP secondary bucket — runs BEFORE per-identity bucket so an
# attacker rotating UAs/cookies from the same source IP cannot multiply their
# rate by spawning new identities. Keyed strictly by request.remote (the
# kernel-observed peer IP), independent of any client-supplied header.
IP_BURST = int(os.environ.get("IP_BURST", "30"))
IP_REFILL = float(os.environ.get("IP_REFILL", "5.0"))
ip_buckets: Dict[str, dict] = {}

async def take_socket_ip_token(socket_ip: str) -> tuple[bool, float]:
    """Atomic token-bucket per kernel-observed peer IP. Returns (allowed, retry_after).
    N6: no inline O(n) eviction — _prune_state_loop trims this dict periodically.
    Hard cap is enforced by REJECTING new IPs only when over 2× MAX_IDENTITIES
    (which means the prune cycle hasn't run yet under extreme flooding)."""
    async with state_lock:
        n = now()
        b = ip_buckets.get(socket_ip)
        if b is None:
            if len(ip_buckets) > MAX_IDENTITIES * 2:
                # Hard backpressure under extreme flood — block this new IP
                # rather than do O(n) eviction synchronously.
                return False, 1.0
            b = {"tokens": float(IP_BURST), "last": n}
            ip_buckets[socket_ip] = b
        elapsed = n - b["last"]
        b["tokens"] = min(IP_BURST, b["tokens"] + elapsed * IP_REFILL)
        b["last"] = n
        if b["tokens"] >= 1.0:
            b["tokens"] -= 1.0
            return True, 0.0
        retry = (1.0 - b["tokens"]) / IP_REFILL
        return False, retry

async def take_token(ip: str) -> tuple[bool, float, int]:
    """Returns (allowed, retry_after_secs, tokens_remaining)."""
    async with state_lock:
        s = ip_state[ip]
        n = now()
        elapsed = n - s.last_refill
        s.tokens = min(RATE_LIMIT_BURST, s.tokens + elapsed * RATE_LIMIT_REFILL)
        s.last_refill = n
        s.request_count += 1
        s.request_times.append(n)
        if s.tokens >= 1.0:
            s.tokens -= 1.0
            return True, 0.0, int(s.tokens)
        retry = (1.0 - s.tokens) / RATE_LIMIT_REFILL
        return False, retry, 0

async def behavioral_check(ip: str) -> tuple[bool, str]:
    """M5: stronger bot timing detection. Three orthogonal tests; any one
    triggers. Tests look at the last 16 request intervals.

      1. Coefficient of variation σ/μ < 0.05  (near-deterministic spacing)
      2. Autocorrelation lag-1 > 0.85 (each interval mirrors the previous one;
         common with sleep-based bot loops including jittered ones)
      3. Same-bin majority: >70% of intervals fall in a single 50-ms bin
         (sleep loops with quantised jitter)
    """
    async with state_lock:
        s = ip_state[ip]
        N = 16
        if len(s.request_times) < N:
            return False, ""
        recent = list(s.request_times)[-N:]
        intervals = [recent[i+1] - recent[i] for i in range(len(recent) - 1)]
        if not intervals or any(iv <= 0 for iv in intervals):
            return False, ""
        mean_iv = sum(intervals) / len(intervals)
        if mean_iv > 5.0:
            # Slow human-paced clicks — don't bother analysing.
            return False, ""
        var = sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)
        std = var ** 0.5
        cov = std / mean_iv if mean_iv > 0 else 0
        # Lag-1 autocorrelation
        if var > 0:
            num = sum((intervals[i] - mean_iv) * (intervals[i+1] - mean_iv)
                      for i in range(len(intervals) - 1))
            den = var * len(intervals)
            r1 = num / den if den > 0 else 0
        else:
            r1 = 1.0
        # 50-ms bin majority
        bins = defaultdict(int)
        for iv in intervals:
            bins[int(iv * 1000) // 50] += 1
        max_bin_pct = max(bins.values()) / len(intervals)

        if cov < 0.05 and mean_iv < 2.0:
            return True, f"timing too regular (σ/μ={cov:.3f}, μ={mean_iv*1000:.1f}ms)"
        if r1 > 0.85 and mean_iv < 2.0:
            return True, f"autocorrelated intervals (r₁={r1:.2f})"
        if max_bin_pct > 0.70:
            return True, f"quantised intervals ({max_bin_pct*100:.0f}% in one 50ms bin)"
    return False, ""

# ── Proof-of-Work ──────────────────────────────────────────────────────────
# N4: bind challenge to (method, path) AND maintain a seen-set so a solved
# (token, solution) pair cannot be replayed for the full validity window.
def _pow_bind(method: str, path: str) -> str:
    return f"{method.upper()}:{path}"

# Seen-pairs: {(token, solution): expires_at_epoch}.  Pruned lazily on insert.
_pow_seen: Dict[tuple, float] = {}
_POW_SEEN_MAX = 10000

def make_pow_challenge(method: str = "*", path: str = "*") -> str:
    nonce  = secrets.token_hex(8)
    issued = str(int(time.time()))
    bind = _pow_bind(method, path)
    payload = f"{nonce}|{issued}|{POW_DIFFICULTY}|{bind}"
    sig = hmac.new(POW_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"

def verify_pow(token: str, solution: str,
               method: str = "*", path: str = "*") -> tuple[bool, str]:
    if not token or not solution:
        return False, "missing token or solution"
    parts = token.split("|")
    if len(parts) == 5:
        nonce, issued, diff, bind, sig = parts
    elif len(parts) == 4:
        # Legacy challenge (no bind) — reject; the challenge MUST be bound.
        return False, "legacy unbound token; obtain a fresh challenge"
    else:
        return False, "malformed token"
    payload = f"{nonce}|{issued}|{diff}|{bind}"
    expected_sig = hmac.new(POW_HMAC_KEY, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return False, "bad signature"
    if not hmac.compare_digest(bind, _pow_bind(method, path)):
        return False, "token not bound to this method+path"
    age = int(time.time()) - int(issued)
    if age > POW_VALID_SECS:
        return False, f"expired ({age}s old)"
    try:
        diff_int = int(diff)
    except ValueError:
        return False, "bad difficulty"
    h = hashlib.sha256(f"{nonce}{solution}".encode()).hexdigest()
    if not h.startswith("0" * diff_int):
        return False, f"hash {h[:8]} does not start with {diff_int} zeros"
    # Replay protection: each (token, solution) usable exactly once within
    # the validity window. Lazy prune of expired pairs.
    now_ts = time.time()
    if len(_pow_seen) > _POW_SEEN_MAX:
        for k in [k for k, exp in _pow_seen.items() if exp < now_ts]:
            _pow_seen.pop(k, None)
        if len(_pow_seen) > _POW_SEEN_MAX:
            # Hard cap: drop oldest half — replay protection degrades but
            # memory stays bounded. (Should never happen at sane volumes.)
            for k in list(_pow_seen.keys())[:len(_pow_seen)//2]:
                _pow_seen.pop(k, None)
    pair_key = (token, solution)
    if pair_key in _pow_seen:
        return False, "solution already used (replay)"
    _pow_seen[pair_key] = now_ts + POW_VALID_SECS
    return True, "ok"

def needs_pow(request: web.Request) -> bool:
    if POW_REQUIRE_ALL_WRITES and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        return True
    return any(request.path.startswith(p) for p in POW_REQUIRED_PATHS)

# ── Metrics helpers ────────────────────────────────────────────────────────
async def record(ip: str, ua: str, path: str, status: int, reason: str,
                 track_key: str = None, sid: str = "", fp: str = "",
                 ja4: str = "", request_id: str = ""):
    """Record one request decision into global metrics + per-identity state + event log + DB.
    track_key (identity) is the primary key. ip is stored on IpState for display only.
    `ja4` (R0): TLS handshake fingerprint observed by the trusted upstream
    terminator — surfaced in the event log so the operator can see what
    fingerprints bots are using and populate JA4_DENY_LIST from telemetry.
    """
    async with state_lock:
        metrics["total_requests"] += 1
        metrics["by_status"][status] += 1
        metrics["by_path"][path] += 1
        _timeline_bump(reason)
        if ja4:
            metrics["by_ja4"][ja4[:64]] += 1
        # Default to ip if no track_key (back-compat for internal/probe paths)
        key = track_key or ip
        s = ip_state[key]
        s.last_seen = now()
        s.last_user_agent = ua[:120]
        s.last_path = path[:120]
        s.last_ip = ip
        if sid: s.last_session = sid[:24]
        if fp:  s.last_fingerprint = fp
        if ja4: s.last_ja4 = ja4[:64]
        if reason:
            metrics["blocked"] += 1
            metrics["by_reason"][reason] += 1
            s.blocked_count += 1
            s.blocks_by_reason[reason] += 1
        else:
            metrics["allowed"] += 1
            s.allowed_count += 1
        # Persist to DB (non-blocking — drops in queue)
        if db_queue is not None:
            event_ts = _t.time()
            try:
                db_queue.put_nowait(("event",
                    (event_ts, ip, ua[:200], path[:200], "", status, reason or "")))
                # Persist this client's snapshot
                banned_until_epoch = (
                    event_ts + (s.banned_until - now()) if s.banned_until > now() else 0
                )
                db_queue.put_nowait(("upsert_client", (
                    ip,
                    event_ts - (now() - s.first_seen),
                    event_ts,
                    s.request_count, s.allowed_count, s.blocked_count,
                    banned_until_epoch,
                    s.last_user_agent, s.last_path,
                    json.dumps(dict(s.blocks_by_reason)),
                )))
                # Persist timeline bucket
                b = _bucket_now()
                if b in timeline:
                    tb = timeline[b]
                    db_queue.put_nowait(("upsert_timeline", (
                        b, tb["total"], tb["allowed"], tb["blocked"],
                        json.dumps(dict(tb["by_reason"])),
                    )))
                # Periodic global counters flush (every ~50 events)
                if metrics["total_requests"] % 50 == 0:
                    db_queue.put_nowait(("set_kv", ("total_requests", str(metrics["total_requests"]))))
                    db_queue.put_nowait(("set_kv", ("allowed", str(metrics["allowed"]))))
                    db_queue.put_nowait(("set_kv", ("blocked", str(metrics["blocked"]))))
                    db_queue.put_nowait(("set_kv", ("by_reason", json.dumps(dict(metrics["by_reason"])))))
                    db_queue.put_nowait(("set_kv", ("by_status", json.dumps({str(k): v for k, v in metrics["by_status"].items()}))))
                    db_queue.put_nowait(("set_kv", ("by_path", json.dumps(dict(metrics["by_path"])))))
            except asyncio.QueueFull:
                pass  # drop on overload, not critical
        events.append({
            "ts": _t.time(),
            "ip": ip,
            "ua": ua[:80],
            "path": path[:80],
            "method": "",   # filled by caller via closure (kept simple here)
            "status": status,
            "reason": reason or "OK",
            "ja4": ja4[:64] if ja4 else "",
            "rid": request_id[:32] if request_id else "",
        })
        # 1.4.6: emit one structured log line per recorded request so the
        # full forensic record (request_id, verdict, ja4, identity) lands
        # in stdout for downstream ingestion.
        slog("request",
             level="info" if not reason else "warn",
             rid=request_id, ip=ip, ja4=ja4 or "", ua=ua[:120],
             method="", path=path[:200], status=status,
             reason=reason or "ok", track_key=(track_key or "")[:32])

# ── Silent decoy: serves upstream / contents to banned attackers ───────────
# Cache also stores the upstream's HTTP status so the decoy mirrors it. A
# previous design hard-coded 200 OK while serving the upstream's 404 body —
# that status/content mismatch was a clean fingerprint for an agent to
# detect blocked vs forwarded responses. We now match upstream verbatim.
_decoy_cache = {"body": None, "ctype": None, "status": 200, "fetched_at": 0.0}
_DECOY_TTL = 60.0  # cache the homepage for 60s
_decoy_fetch_lock = asyncio.Lock()

async def _silent_decoy_response(ip: str, ua: str, path: str, reason: str,
                                  track_key: str = None, sid: str = "",
                                  fp: str = "", ja4: str = "",
                                  request_id: str = ""):
    """
    Stealth response for blocked clients.
    Returns upstream's `/` content with upstream's actual status code, so a
    blocked request looks indistinguishable from a forwarded request that
    happened to land on `/`. The block IS still recorded under the hybrid
    identity (track_key), keyed on the cookie+fingerprint so a single bad
    actor in a NAT pool doesn't poison all peers.
    """
    n = _t.time()
    # N2: serialize the upstream fetch — many concurrent blocked requests
    # mustn't fan out a thundering herd. Double-check inside the lock.
    if not _decoy_cache["body"] or (n - _decoy_cache["fetched_at"]) > _DECOY_TTL:
        async with _decoy_fetch_lock:
            n = _t.time()
            if not _decoy_cache["body"] or (n - _decoy_cache["fetched_at"]) > _DECOY_TTL:
                try:
                    async with ClientSession(timeout=ClientTimeout(total=10)) as session:
                        async with session.get(UPSTREAM + "/", allow_redirects=False) as resp:
                            _decoy_cache["body"] = await resp.read()
                            _decoy_cache["ctype"] = resp.headers.get("Content-Type", "text/html; charset=utf-8")
                            _decoy_cache["status"] = resp.status
                            _decoy_cache["fetched_at"] = n
                except Exception:
                    _decoy_cache["body"] = (
                        b"<!doctype html><html><head><title>Welcome</title></head>"
                        b"<body><h1>Welcome</h1><p>Service operational.</p></body></html>"
                    )
                    _decoy_cache["ctype"] = "text/html; charset=utf-8"
                    _decoy_cache["status"] = 200
                    _decoy_cache["fetched_at"] = n
    decoy_status = int(_decoy_cache.get("status") or 200)
    await record(ip, ua, path, decoy_status, reason, track_key=track_key, sid=sid,
                 fp=fp, ja4=ja4, request_id=request_id)
    headers = {
        "Content-Type": _decoy_cache["ctype"],
        "Cache-Control": "no-store",
    }
    if request_id:
        headers[_REQUEST_ID_HEADER] = request_id
    return web.Response(
        status=decoy_status,
        body=_decoy_cache["body"],
        headers=headers,
    )

# ── Cookie finalizer: outer middleware. Sets the session cookie on every
#    response where the inner protect() flagged a new session — ensures the
#    cookie is set on silent-decoy responses too, not just allowed ones.
@web.middleware
async def session_cookie_finalizer(request: web.Request, handler):
    response = await handler(request)
    sid    = request.get("_sid")
    is_new = request.get("_is_new")
    if sid and is_new:
        try:
            response.set_cookie(
                SESSION_COOKIE, _sign_session(sid),
                httponly=True, samesite=SESSION_SAMESITE,
                secure=SESSION_SECURE, path="/",
                max_age=SESSION_TTL_SECS,
            )
        except Exception:
            pass  # FileResponse / streaming responses may not allow cookies post-hoc
    return response

# ── Middleware ─────────────────────────────────────────────────────────────
@web.middleware
async def protect(request: web.Request, handler):
    # 1.4.6 — request correlation. Honour an inbound X-Request-ID if it's
    # safe-looking (so a CDN / front-proxy / load balancer that already
    # tagged the request keeps its trace), otherwise mint a fresh short id.
    inbound_rid = request.headers.get(_REQUEST_ID_HEADER, "").strip()
    rid = (inbound_rid if inbound_rid and _REQUEST_ID_RE.match(inbound_rid)
           else _new_request_id())
    request["_rid"] = rid

    # L3+N5: reject paths/query with ANY ASCII control byte (0x00-0x1F or 0x7F).
    # CR/LF would enable header injection on legacy backends; NUL truncates
    # in C parsers; other control chars confuse normalisers. Whitespace stays
    # outside this range (0x20+) so legitimate URLs are unaffected.
    def _has_ctrl(s: str) -> bool:
        return any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)
    if _has_ctrl(request.path) or _has_ctrl(request.query_string or ""):
        return web.Response(status=400, text="bad request\n",
                            headers={_REQUEST_ID_HEADER: rid})

    # Unauthenticated liveness probe — used by the container HEALTHCHECK.
    if request.path == "/__live":
        return web.Response(text="ok",
                            headers={"Cache-Control": "no-store",
                                     "Content-Type": "text/plain; charset=utf-8",
                                     _REQUEST_ID_HEADER: rid})

    # v1.4 #1 — JS challenge: solver POSTs back here. Rate-limit by socket-IP
    # FIRST so an attacker can't burn proxy CPU (sha256 + JSON parse + dict
    # ops) hammering /__challenge with bogus solutions.
    if request.path == "/__challenge":
        socket_ip = request.remote or "0.0.0.0"
        sip_ok, sip_retry = await take_socket_ip_token(socket_ip)
        if not sip_ok:
            return web.Response(
                status=429, text="rate limit\n",
                headers={"Retry-After": str(int(sip_retry) + 1),
                         "Cache-Control": "no-store"})
        return await js_challenge_endpoint(request)

    # NOTE: JS challenge gate moved BELOW the stealth-block checks (host /
    # TLS / origin / required-headers). Reason: on those checks we already
    # silent-decoy without revealing the gateway, and the challenge gate
    # must not preempt them with an explicit response.

    # F3: method allowlist at Layer 0 — short-circuits before PoW / rate
    # limit / behavioral could preempt with their own response. Internal
    # /__* routes accept any method (HEAD probes, OPTIONS preflight).
    if not request.path.startswith("/__") and request.method not in ALLOWED_METHODS:
        return web.Response(status=405, text="method not allowed\n",
                            headers={"Allow": ", ".join(sorted(ALLOWED_METHODS))})

    # F1: Host header allowlist (D-i-D). When ALLOWED_HOSTS is configured,
    # silently decoy any request whose Host header is not on the list. This
    # complements the existing X-Forwarded-Host strip+overwrite by also
    # blocking host-header-based reconnaissance / cache poisoning attempts at
    # OUR gate. The hostname-only comparison strips the port (request.host
    # may be "example.com:8443").
    if ALLOWED_HOSTS:
        host = (request.host or "").split(":", 1)[0].lower()
        if host not in ALLOWED_HOSTS:
            ip = get_ip(request)
            ua = request.headers.get("User-Agent", "")
            return await _silent_decoy_response(ip, ua, request.path,
                                                "host-not-allowed",
                                                ja4=_request_ja4(request), request_id=rid)

    # ── v1.4.2 Layer 0.5: TLS fingerprint deny-list (JA3/JA4) ─────────────
    # The upstream TLS terminator (cloudflared, nginx, ALB) injects the
    # client's handshake fingerprint as a header. Off by default — operator
    # opts in via JA4_DENY_LIST.
    if _tls_fingerprint_blocked(request):
        ip = get_ip(request)
        ua = request.headers.get("User-Agent", "")
        return await _silent_decoy_response(ip, ua, request.path,
                                            "tls-fingerprint",
                                            ja4=_request_ja4(request), request_id=rid)

    # ── v1.4.2 Layer 0.6: Strict Origin / Referer enforcement ─────────────
    # On state-changing methods, require the Origin header to match
    # ALLOWED_HOSTS. Off by default (STRICT_ORIGIN=1 to enable).
    if _origin_check_failed(request):
        ip = get_ip(request)
        ua = request.headers.get("User-Agent", "")
        return await _silent_decoy_response(ip, ua, request.path,
                                            "origin-mismatch",
                                            ja4=_request_ja4(request), request_id=rid)

    # ── v1.4.2 Layer 0.7: Required custom-header presence ───────────────
    # Operator-defined headers (REQUIRED_HEADERS=X-Client-Version,...) must
    # be present on every non-/__/  /  non-static request.
    if _missing_required_header(request):
        ip = get_ip(request)
        ua = request.headers.get("User-Agent", "")
        return await _silent_decoy_response(ip, ua, request.path,
                                            "missing-required-header",
                                            ja4=_request_ja4(request), request_id=rid)

    # ── v1.4 #1 — JS challenge gate (V8 fix) ────────────────────────────
    # The chal cookie is REQUIRED on every non-static, non-admin, non-opted-
    # -out path — not only HTML. Browsers carry the cookie on XHR/fetch
    # transparently; pure-HTTP bots don't and get blocked.
    #   - HTML GET without cookie → serve interactive challenge page.
    #   - Everything else without cookie → silent decoy (preserves stealth;
    #     does NOT leak that the gateway exists by returning 401).
    # Placed AFTER host/TLS/origin/required-header stealth checks so those
    # block paths take precedence and remain undetectable.
    if _js_challenge_required(request):
        if _js_challenge_applicable(request):
            return _serve_js_challenge(request)
        # 1.4.4: heuristic auto-mint mode (no Turnstile). HTML GETs are
        # allowed through; the response gets the cookie set after the
        # request completes the rest of the layered checks. Non-HTML or
        # non-GET requests without a cookie still silent-decoy so APIs
        # cannot be used directly without first visiting an HTML page.
        if (not TURNSTILE_ENABLED
                and request.method == "GET"
                and "text/html" in request.headers.get("Accept", "")):
            request["_auto_mint_chal"] = True
            # fall through to the rest of the middleware so UA filter,
            # header completeness, behavioural, body-pattern, canary echo
            # etc. still apply before we hand back a cookie.
        else:
            ip = get_ip(request)
            ua = request.headers.get("User-Agent", "")
            return await _silent_decoy_response(ip, ua, request.path,
                                                "chal-required",
                                                ja4=_request_ja4(request), request_id=rid)

    # Internal endpoints: only authenticated operator gets through.
    # Anyone else sees the silent decoy — they don't even learn that /__* exist.
    # When ADMIN_ALLOWED_IPS is configured, the source IP MUST also match —
    # silent decoy on IP mismatch (no leak that the IP check is what blocked).
    if request.path.startswith("/__"):
        if _admin_ip_allowed(request) and _internal_authed(request):
            return await handler(request)
        ip = get_ip(request)
        ua = request.headers.get("User-Agent", "")
        reason = ("admin-ip-blocked" if not _admin_ip_allowed(request)
                  else "internal-probe")
        return await _silent_decoy_response(ip, ua, request.path, reason,
                                            request_id=rid)

    # ── Hybrid identity (primary tracking key) ──
    # 'identity' = HMAC(session_cookie + browser_fingerprint) for browser flow,
    # OR HMAC(fp + ip) for cookieless scripts (still stable per device).
    identity, sid, fp, is_new_session, id_mode = get_identity(request)
    ip = get_ip(request)            # IP for session-creation guard + display
    request["_sid"]    = sid
    request["_is_new"] = is_new_session
    request["_id_mode"] = id_mode
    request["_fp"]     = fp                   # v1.4: expose to proxy() body checks
    request["_track_key"] = identity          # v1.4: same

    # Anti cookie-rotation: limit how many DISTINCT new identities one IP can
    # spawn per minute. Counts unique identities (not requests), so parallel
    # cookieless SPA sub-resource fetches that all share one fp+ip identity
    # register as 1.
    if is_new_session:
        async with state_lock:
            now_ts = now()
            id_map = ip_new_sessions[ip]
            # Evict identities older than 60s
            stale = [k for k, ts in id_map.items() if ts < now_ts - 60]
            for k in stale:
                del id_map[k]
            id_map[identity] = now_ts
            new_session_rate = len(id_map)
        if new_session_rate > NEW_SESSIONS_PER_IP_PER_MIN:
            return await _silent_decoy_response(
                ip, request.headers.get("User-Agent",""), request.path, "session-flood"
            )

    ua = request.headers.get("User-Agent", "")
    path = request.path
    # R0: capture JA4 once for the whole decision path (telemetry only).
    ja4 = _request_ja4(request)
    # From here on, all per-client tracking uses 'identity' as the key.
    # 'ip' is recorded as the last-seen IP for dashboard display only.
    track_key = identity

    async def deny(status, reason, body, extra_headers=None):
        """
        STEALTH MODE: every block returns the upstream homepage as 200 OK,
        EXCEPT for pow-required which must return 402 + JSON challenge so
        the legitimate client can solve and retry. Risk-score still bumps.
        """
        await update_risk_and_maybe_ban(track_key, reason, ip)
        if reason == "pow-required":
            await record(ip, ua, path, status, reason,
                         track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid)
            return web.json_response(
                body, status=status,
                headers={**(extra_headers or {}), "Cache-Control": "no-store",
                         _REQUEST_ID_HEADER: rid},
            )
        return await _silent_decoy_response(
            ip, ua, path, reason, track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid
        )

    # 1. Banned check (per-identity, not per-IP) → SILENT decoy
    banned, remaining = await is_banned(track_key)
    if banned:
        return await _silent_decoy_response(
            ip, ua, path, "banned-silent", track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid
        )

    # 2. Honeypot → risk_score += 50 (potential ban). Silent decoy regardless.
    #    Threshold-based: at NAT-like IPs, requires accumulated badness.
    if request.path in HONEYPOT_PATHS:
        await update_risk_and_maybe_ban(track_key, "honeypot-silent", ip)
        return await _silent_decoy_response(
            ip, ua, path, "honeypot-silent", track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid
        )

    # 2b. Suspicious path PATTERN (flag-hunting, file-hunting, CTF recon).
    #     Catches /flag.txt, /myflag, /backup.sql, /id_rsa, /.git/HEAD, etc.
    if is_suspicious_path(request.path):
        await update_risk_and_maybe_ban(track_key, "suspicious-path", ip)
        return await _silent_decoy_response(
            ip, ua, path, "suspicious-path", track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid
        )

    # 2c. R7 — AI-canary echo. The agent has quoted our prior response back
    # at us (URL, header, or body), which is something only an LLM-driven
    # client does (it summarises the previous page into its prompt context
    # and re-emits fragments). Big risk bump + immediate silent decoy.
    # Body scanning is deferred to the proxy() function for POSTs since the
    # body isn't read yet here; the URL + headers cover the common case.
    if CANARY_ECHO_DETECTION:
        echoed = _scan_request_for_canary(request)
        if echoed:
            await update_risk_and_maybe_ban(track_key, "canary-echo", ip)
            return await _silent_decoy_response(
                ip, ua, path, "canary-echo",
                track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid)

    # 3a. Empty / suspiciously short User-Agent
    ua_stripped = ua.strip()
    if not ua_stripped:
        return await deny(403, "ua-empty",
                          {"error": "missing User-Agent header"})
    if len(ua_stripped) < 12:
        return await deny(403, "ua-too-short",
                          {"error": "User-Agent too short", "ua": ua_stripped})

    # 3b. UA blocklist (substring match, case-insensitive)
    ua_lower = ua_stripped.lower()
    for blocked in UA_BLOCKLIST:
        if blocked in ua_lower:
            return await deny(403, "ua-blocked",
                              {"error": "user-agent blocked", "matched": blocked})

    # 3c. UA must look like a browser (have one of: Mozilla / Safari / Chrome / Firefox / Edge / Opera)
    if not any(t in ua_lower for t in ("mozilla", "safari", "chrome", "firefox", "edge", "opera", "trident")):
        return await deny(403, "ua-non-browser",
                          {"error": "User-Agent does not look like a browser",
                           "ua": ua_stripped[:80]})

    # 3d. AI agent probe paths → risk_score += 30 (no immediate ban)
    if request.path in AI_PROBE_PATHS:
        await update_risk_and_maybe_ban(track_key, "ai-probe", ip)
        return await deny(403, "ai-probe",
                          {"error": "AI-probe endpoint requested"})

    # 3e. Header completeness — real browsers send rich headers, agents are minimal
    accept_lang = request.headers.get("Accept-Language", "")
    accept_enc  = request.headers.get("Accept-Encoding", "")
    accept_hdr  = request.headers.get("Accept", "")
    sec_fetch_site = request.headers.get("Sec-Fetch-Site")
    sec_fetch_mode = request.headers.get("Sec-Fetch-Mode")
    sec_fetch_dest = request.headers.get("Sec-Fetch-Dest")
    sec_ch_ua      = request.headers.get("Sec-Ch-Ua")

    # Score header completeness (0-7)
    score = (
        bool(accept_lang) + bool(accept_enc) + bool(accept_hdr)
        + bool(sec_fetch_site) + bool(sec_fetch_mode)
        + bool(sec_fetch_dest) + bool(sec_ch_ua)
    )
    # Real browsers score 5-7. Agents score 0-2.
    if score < 2 and "chrome" in ua_lower:
        # Chrome UA but no Sec-Ch-Ua = forged UA (likely scripted)
        return await deny(403, "ai-headers-incomplete",
                          {"error": "Chrome UA without browser headers",
                           "header_score": score})
    if score == 0:
        return await deny(403, "ai-headers-empty",
                          {"error": "no Accept-* nor Sec-Fetch-* headers — not a real browser",
                           "header_score": score})

    # 3f. Path-discovery rate: too many distinct paths from same identity = enumeration
    async with state_lock:
        s = ip_state[track_key]
        s.unique_paths.add(request.path)
        if len(s.unique_paths) > 400:
            s.unique_paths.pop()
        unique_n = len(s.unique_paths)
        # Track static asset discipline.
        # Only count GET requests to the root path as "html_loads", and require
        # a 200-class response. Anything else is too noisy (POSTs, redirects,
        # link-clicks count as legit nav).
        if request.method == "GET":
            if request.path.endswith((".css", ".js", ".png", ".jpg", ".jpeg",
                                      ".gif", ".svg", ".webp", ".woff", ".woff2",
                                      ".ttf", ".ico", ".map")):
                s.static_loads += 1
            elif request.path == "/" or request.path.endswith((".html", ".htm")):
                s.html_loads += 1
        # Only flag if MANY homepage visits (>=25) without ANY static fetch.
        # Note: many real sites have no CSS/JS so this is intentionally lenient.
        no_static = (s.html_loads >= 25 and s.static_loads == 0)

    # >300 distinct paths from same identity = enumeration scan.
    # SPAs (Angular/React UFE-style apps) routinely load 50–200 chunked JS
    # modules on one page; the previous 50 threshold was a false-positive
    # magnet for legit users. Operator can override via env if needed.
    if unique_n > int(os.environ.get("ENUM_THRESHOLD", "300")):
        return await deny(403, "ai-enumeration",
                          {"error": "too many distinct paths from this identity",
                           "unique_paths": unique_n})
    if no_static:
        return await deny(403, "ai-no-assets",
                          {"error": "browser UA but never fetched any asset — likely AI agent",
                           "html_loads": s.html_loads, "static_loads": s.static_loads})

    # 4a. H4: Socket-IP rate limit — keyed strictly by kernel-observed peer IP,
    #     defeats "rotate UA every request to get a fresh identity bucket"
    #     bypass. This bucket is INDEPENDENT from any client-supplied header.
    socket_ip = request.remote or "0.0.0.0"
    sip_ok, sip_retry = await take_socket_ip_token(socket_ip)
    if not sip_ok:
        return await deny(429, "rate-limit-ip",
                          {"error": "ip rate limit exceeded",
                           "retry_after": int(sip_retry) + 1},
                          extra_headers={
                              "Retry-After": str(int(sip_retry) + 1),
                              "X-RateLimit-Limit": str(IP_BURST),
                              "X-RateLimit-Remaining": "0",
                          })

    # 4b. Per-identity bucket (one user in the office doesn't consume the
    #     whole company's tokens — secondary, finer-grained limit).
    #     Skip for static-asset GETs: browsers burst-load CSS/JS/img/font on
    #     every page render, exhausting the bucket and breaking the page UI.
    #     Socket-IP bucket (Layer 8) still throttles flooders.
    is_static_asset_get = (request.method == "GET" and request.path.endswith((
        ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf", ".otf",
        ".eot", ".map", ".mp4", ".webm", ".mp3", ".ogg")))
    if not is_static_asset_get:
        allowed, retry, remaining_tokens = await take_token(track_key)
        if not allowed:
            return await deny(429, "rate-limit",
                              {"error": "rate limit exceeded", "retry_after": int(retry) + 1},
                              extra_headers={
                                  "Retry-After": str(int(retry) + 1),
                                  "X-RateLimit-Limit": str(RATE_LIMIT_BURST),
                                  "X-RateLimit-Remaining": "0",
                              })

    # 5. Behavioral (per-identity).
    #    Skip for established (cookied) sessions — once a browser has accepted
    #    our HMAC-signed session cookie it is NOT a cookieless bot. Skip for
    #    static-asset GETs because SPA frameworks queue them with very regular
    #    timing (false positive on legitimate users).
    if id_mode != "session" and not is_static_asset_get:
        suspicious, reason = await behavioral_check(track_key)
        if suspicious:
            return await deny(403, "behavior",
                              {"error": "suspicious behavior", "reason": reason})

    # 6. PoW
    if needs_pow(request):
        token = request.headers.get("X-PoW-Token", "")
        solution = request.headers.get("X-PoW-Solution", "")
        ok, why = verify_pow(token, solution, request.method, request.path)
        if not ok:
            challenge = make_pow_challenge(request.method, request.path)
            return await deny(402, "pow-required",
                              {"error": "Proof-of-Work required",
                               "reason": why,
                               "challenge": challenge,
                               "difficulty": POW_DIFFICULTY,
                               "valid_for_seconds": POW_VALID_SECS,
                               "instructions": "Use /__solver"},
                              extra_headers={
                                  "X-PoW-Challenge": challenge,
                                  "X-PoW-Difficulty": str(POW_DIFFICULTY),
                              })

    # Allowed → forward upstream and record under the identity
    response = await handler(request)

    # 1.4.4: heuristic auto-mint of the chal cookie. The request reached
    # this point because (a) JS_CHALLENGE=1, (b) Turnstile is OFF, (c) it
    # was an HTML GET without a valid chal cookie, and (d) every layer
    # above (UA filter, header completeness, behavioural, body pattern,
    # canary echo, rate limits, ...) has waved it through. Issue a cookie
    # bound to UA + IP-tier-hash + JA4-hash so subsequent API/XHR calls
    # from this client carry a session marker. NOT a hard wall — the
    # gate is a friction layer that combined with the heuristic stack
    # raises bot cost without any third-party dependency.
    if request.get("_auto_mint_chal"):
        ip_tier = _ip_tier(get_ip(request))
        bind_ja4 = ja4 if (JS_CHAL_BIND_JA4 and ja4) else ""
        cookie = _make_chal_cookie(ua, "", ip_tier, bind_ja4)
        response.set_cookie(
            CHAL_COOKIE, cookie,
            httponly=True,
            samesite=SESSION_SAMESITE,
            secure=SESSION_SECURE,
            path="/", max_age=CHAL_TTL)

    await record(ip, ua, path, response.status, "",
                 track_key=track_key, sid=sid, fp=fp, ja4=ja4, request_id=rid)
    # Stealth-agent telemetry (only on allowed traffic — feeds /__agents).
    async with state_lock:
        st = ip_state[track_key]
        st.header_scores.append(score)
        st.last_allowed_paths.append({
            "ts": _t.time(), "path": path[:120], "status": response.status,
            "header_score": score,
        })
        if response.status == 404 and not request.path.endswith((
            ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg",
            ".css", ".js", ".webp", ".woff", ".woff2", ".ttf", ".map")):
            st.upstream_404_count += 1
    # Treat upstream 404 as a small enumeration signal — repeated misses
    # accumulate risk until ban (legitimate users rarely hit many 404s).
    # Skip for static asset extensions (favicon misses are normal).
    if response.status == 404:
        if not request.path.endswith((".ico", ".png", ".jpg", ".jpeg", ".gif",
                                      ".svg", ".css", ".js", ".webp",
                                      ".woff", ".woff2", ".ttf", ".map")):
            await update_risk_and_maybe_ban(track_key, "upstream-404", ip)
    # 1.4.6: stamp the response with the request id so the client can grep
    # logs from this side using the same id.
    if rid and _REQUEST_ID_HEADER not in response.headers:
        response.headers[_REQUEST_ID_HEADER] = rid
    return response

# ── Internal endpoints ─────────────────────────────────────────────────────
async def pow_endpoint(request: web.Request):
    """Issue a fresh PoW challenge bound to (method, path) supplied via query.
    Example: /__pow?method=POST&path=/login
    """
    method = (request.query.get("method", "POST") or "POST").upper()
    path = request.query.get("path", "/") or "/"
    return web.json_response({
        "challenge": make_pow_challenge(method, path),
        "difficulty": POW_DIFFICULTY,
        "valid_for_seconds": POW_VALID_SECS,
        "bound_to": {"method": method, "path": path},
    }, headers={"Cache-Control": "no-store"})

async def solver_endpoint(request: web.Request):
    return web.Response(
        text=r"""<!doctype html><meta charset=utf-8>
<title>PoW solver</title><h2>Anti-bot PoW solver</h2>
<form id=f><label>Challenge: <input id=c size=80></label>
<button>Solve</button></form><pre id=o></pre>
<script>
async function sha256(s){const b=new TextEncoder().encode(s);
  const h=await crypto.subtle.digest('SHA-256',b);
  return [...new Uint8Array(h)].map(x=>x.toString(16).padStart(2,'0')).join('')}
document.getElementById('f').onsubmit=async e=>{e.preventDefault();
  const c=document.getElementById('c').value.trim(),o=document.getElementById('o');
  const [nonce,,d]=c.split('|');const z='0'.repeat(parseInt(d)||5);
  const t0=performance.now();
  for(let i=0;;i++){const x=i.toString();
    const h=await sha256(nonce+x);
    if(h.startsWith(z)){
      o.textContent=`Found: X=${x}\nhash=${h}\ntook ${(performance.now()-t0).toFixed(0)}ms (${i} attempts)
\nUse:\nX-PoW-Token: ${c}\nX-PoW-Solution: ${x}`;break}
    if(i%1000===0)o.textContent=`tried ${i}…`}}
</script>""",
        content_type="text/html",
    )

async def metrics_endpoint(request: web.Request):
    """JSON metrics dump consumed by the dashboard."""
    async with state_lock:
        n = now()
        clients = []
        for key, s in sorted(ip_state.items(),
                             key=lambda kv: kv[1].request_count, reverse=True):
            elapsed = n - s.last_refill
            tokens = min(RATE_LIMIT_BURST, s.tokens + elapsed * RATE_LIMIT_REFILL)
            # Apply decay before reporting current score
            _decay_risk(s, n)
            clients.append({
                "id": key,
                "ip": key,
                "last_ip": s.last_ip or key,
                "last_session": s.last_session,
                "last_fingerprint": s.last_fingerprint,
                "tokens": round(tokens, 1),
                "requests": s.request_count,
                "allowed": s.allowed_count,
                "blocked": s.blocked_count,
                "blocks_by_reason": dict(s.blocks_by_reason),
                "banned_secs": max(0, round(s.banned_until - n, 0)),
                "last_seen_secs_ago": round(n - s.last_seen, 1),
                "first_seen_secs_ago": round(n - s.first_seen, 1),
                "last_ua": s.last_user_agent,
                "last_path": s.last_path,
                "risk_score": round(s.risk_score, 1),
            })
        recent_events = list(events)[-50:]
        recent_events.reverse()  # newest first
        top_paths = sorted(metrics["by_path"].items(),
                           key=lambda kv: kv[1], reverse=True)[:10]

        # Build a timeline window with configurable granularity + scroll position.
        #   ?range=N    → window length in minutes (5..1440)
        #   ?bucket=S   → bucket width in seconds (60, 300, 900, 3600, 86400)
        #   ?end=EPOCH  → right edge of the window (defaults to now)
        try:
            range_min = max(5, min(10080, int(request.query.get("range", "60"))))  # up to 7 days
        except ValueError:
            range_min = 60
        try:
            bucket_secs = int(request.query.get("bucket", "60"))
            if bucket_secs not in (60, 300, 900, 3600, 86400):
                bucket_secs = 60
        except ValueError:
            bucket_secs = 60
        try:
            end_epoch = int(request.query.get("end", str(int(_t.time()))))
        except ValueError:
            end_epoch = int(_t.time())

        # Round end to bucket boundary for stable X-axis ticks
        end_b = (end_epoch // bucket_secs) * bucket_secs
        window_secs = range_min * 60
        # Cap number of points at ~250 to avoid mega-payloads
        bucket_count = min(250, max(2, window_secs // bucket_secs))
        start_b = end_b - (bucket_count - 1) * bucket_secs

        # If bucket >= 1m, aggregate the in-memory minute buckets into coarser ones.
        # For older data outside in-memory retention, query the DB.
        timeline_out = []
        # In-memory available range
        in_mem_oldest = end_b - TIMELINE_RETAIN_SECS
        # DB fallback only if needed
        db_buckets = {}
        if start_b < in_mem_oldest:
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                for row in conn.execute(
                    "SELECT bucket_minute, total, allowed, blocked FROM timeline "
                    "WHERE bucket_minute >= ? AND bucket_minute <= ? ORDER BY bucket_minute",
                    (start_b, end_b + 60)
                ):
                    db_buckets[row["bucket_minute"]] = row
                conn.close()
            except Exception:
                pass

        for slot in range(start_b, end_b + 1, bucket_secs):
            agg = {"total": 0, "allowed": 0, "blocked": 0}
            # Sum every 1-min bucket falling inside [slot, slot + bucket_secs)
            for m in range(slot, slot + bucket_secs, 60):
                d = timeline.get(m)
                if not d:
                    d = db_buckets.get(m)
                if d:
                    agg["total"] += d["total"]
                    agg["allowed"] += d["allowed"]
                    agg["blocked"] += d["blocked"]
            timeline_out.append({"t": slot, **agg})

        return web.json_response({
            "uptime_secs": int(_t.time() - START_EPOCH),
            "total": metrics["total_requests"],
            "allowed": metrics["allowed"],
            "blocked": metrics["blocked"],
            "by_reason": dict(metrics["by_reason"]),
            "by_status": {str(k): v for k, v in metrics["by_status"].items()},
            "top_paths": [{"path": p, "count": c} for p, c in top_paths],
            "clients": clients,
            "events": recent_events,
            "timeline": timeline_out,
            "timeline_range_min": range_min,
            "timeline_bucket_secs": bucket_secs,
            "timeline_end_epoch": end_b,
            "timeline_is_live": end_epoch >= int(_t.time()) - 30,
            "config": {
                "burst": RATE_LIMIT_BURST,
                "refill": RATE_LIMIT_REFILL,
                "trust_xff": TRUST_XFF,
                "upstream": UPSTREAM,
                "honeypot_ban_secs": HONEYPOT_BAN_SECS,
                "pow_difficulty": POW_DIFFICULTY,
            },
        }, headers={"Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff"})

async def dashboard_endpoint(request: web.Request):
    """HTML dashboard page (auto-refreshes every 2s via fetch /__metrics)."""
    return web.Response(
        text=DASHBOARD_HTML,
        content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'"
            ),
        },
    )

DASHBOARD_HTML         = (_DASHBOARDS_DIR / "main.html").read_text(encoding="utf-8")

def _serve_js_challenge(request: web.Request):
    """Render the Turnstile-only challenge page. Only invoked when
    JS_CHALLENGE is enabled AND Turnstile is configured."""
    nonce = _make_chal_nonce()
    target = request.path_qs or "/"
    target_safe = re.sub(r'[^A-Za-z0-9_\-./?&=%:#]', '', target)[:512] or "/"
    if (not target_safe.startswith("/")
            or target_safe.startswith("//")
            or "\\" in target_safe):
        target_safe = "/"
    nonce_json   = json.dumps(nonce)
    target_json  = json.dumps(target_safe)
    ts_key_json  = json.dumps(TURNSTILE_SITEKEY)
    html = (JS_CHAL_HTML
            .replace('"__NONCE__"',         nonce_json)
            .replace('"__TARGET__"',        target_json)
            .replace('"__TURNSTILE_KEY__"', ts_key_json))
    # R7: plant a canary on the challenge page too — the LLM summariser
    # reads the gateway's HTML before it ever reaches upstream content.
    headers = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex"}
    if CANARY_ECHO_DETECTION:
        canary = _new_canary()
        html = _inject_canary(html.encode(), canary).decode("utf-8")
        headers["X-Trace-Id"] = canary
    return web.Response(status=200, text=html, content_type="text/html",
                        headers=headers)

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
        return web.Response(status=400, text="bad nonce\n")

    # Cloudflare Turnstile siteverify — the only real boundary.
    ts_token = (params.get("cf-turnstile-response", [""])[0] or "").strip()
    if not ts_token:
        return web.Response(status=403, text="missing turnstile\n")
    try:
        verify_data = {
            "secret":   TURNSTILE_SECRET,
            "response": ts_token,
            "remoteip": request.remote or "",
        }
        async with ClientSession(
                timeout=ClientTimeout(total=5)) as session:
            async with session.post(TURNSTILE_VERIFY_URL,
                                     data=verify_data) as ts_resp:
                ts_json = await ts_resp.json(content_type=None)
    except Exception:
        return web.Response(status=502, text="turnstile verify failed\n")
    if not ts_json.get("success"):
        return web.Response(status=403, text="turnstile rejected\n")

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
    resp = web.Response(status=200, text="ok",
                        headers={"Cache-Control": "no-store"})
    resp.set_cookie(CHAL_COOKIE, cookie,
                    httponly=True,
                    samesite=SESSION_SAMESITE,
                    secure=SESSION_SECURE,
                    path="/", max_age=CHAL_TTL)
    return resp

async def unban_endpoint(request: web.Request):
    """Admin: clear ban + risk score for an identity (or all). Useful when a
    false-positive pushed someone over threshold.
      ?id=<identity>   — unban a single identity (track_key)
      ?ip=<ip>         — unban every identity whose last_ip matches
      ?all=1           — clear ALL bans + reset risk_score on every identity
    """
    target_id = request.query.get("id")
    target_ip = request.query.get("ip")
    do_all = request.query.get("all") in ("1", "true", "yes")
    cleared = 0
    async with state_lock:
        n = now()
        for k, s in ip_state.items():
            match = (do_all
                     or (target_id and k == target_id)
                     or (target_ip and s.last_ip == target_ip))
            if match:
                if s.banned_until > n:
                    s.banned_until = 0.0
                s.risk_score = 0.0
                cleared += 1
        # Also clear DB bans table for matched IPs (best-effort).
        try:
            conn = sqlite3.connect(DB_PATH)
            if do_all:
                conn.execute("DELETE FROM bans")
                conn.execute("UPDATE clients SET banned_until_epoch=0")
            elif target_ip:
                conn.execute("DELETE FROM bans WHERE ip=?", (target_ip,))
                conn.execute("UPDATE clients SET banned_until_epoch=0 WHERE ip=?",
                             (target_ip,))
            elif target_id:
                conn.execute("DELETE FROM bans WHERE ip=?", (target_id,))
                conn.execute("UPDATE clients SET banned_until_epoch=0 WHERE ip=?",
                             (target_id,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[unban] db error: {e}")
    return web.json_response({"cleared": cleared, "scope":
        "all" if do_all else (f"id={target_id}" if target_id else f"ip={target_ip}")},
        headers={"Cache-Control": "no-store"})

async def rotate_keys_endpoint(request: web.Request):
    """1.4.5: rotate the SESSION_KEY (and optionally POW key) atomically.

    Every cookie HMAC-signed under the old key fails verification immediately
    after this returns. Useful after upgrading the gateway, after an
    incident, or on a schedule via cron. The new key is persisted to disk
    (`.session_key` / `.pow_key`) so subsequent restarts pick it up.

    Query params:
      ?scope=session  (default) — rotate SESSION_KEY only (chal + session
                                  cookies invalidated; PoW challenges still
                                  validate against existing pow key).
      ?scope=pow                — rotate POW_HMAC_KEY only (PoW challenges
                                  in flight invalidated).
      ?scope=all                — rotate both.
    """
    global SESSION_KEY, POW_HMAC_KEY
    scope = request.query.get("scope", "session").lower()
    rotated = []
    if scope in ("session", "all"):
        new_sess = secrets.token_bytes(32)
        try:
            with open(_SESS_KEY_FILE, "w") as f:
                f.write(new_sess.hex())
            try:
                os.chmod(_SESS_KEY_FILE, 0o600)
            except OSError:
                pass
        except OSError as e:
            return web.json_response(
                {"error": f"persist failed: {e}"}, status=500,
                headers={"Cache-Control": "no-store"})
        SESSION_KEY = new_sess
        rotated.append("session")
    if scope in ("pow", "all"):
        new_pow = secrets.token_bytes(32)
        try:
            with open(_POW_KEY_FILE, "w") as f:
                f.write(new_pow.hex())
            try:
                os.chmod(_POW_KEY_FILE, 0o600)
            except OSError:
                pass
        except OSError as e:
            return web.json_response(
                {"error": f"persist failed: {e}"}, status=500,
                headers={"Cache-Control": "no-store"})
        POW_HMAC_KEY = new_pow
        rotated.append("pow")
    if not rotated:
        return web.json_response(
            {"error": "scope must be one of: session, pow, all"},
            status=400, headers={"Cache-Control": "no-store"})
    print(f"[rotate-keys] rotated: {','.join(rotated)} "
          f"(every cookie issued before this point now fails HMAC)",
          flush=True)
    return web.json_response(
        {"rotated": rotated,
         "note": "all chal/session cookies issued before this call now fail "
                 "HMAC verification. The next legitimate visitor will be "
                 "issued a fresh cookie."},
        headers={"Cache-Control": "no-store"})

async def status_endpoint(request: web.Request):
    async with state_lock:
        out = {}
        n = now()
        for ip, s in ip_state.items():
            elapsed = n - s.last_refill
            tokens = min(RATE_LIMIT_BURST, s.tokens + elapsed * RATE_LIMIT_REFILL)
            out[ip] = {
                "tokens": round(tokens, 2),
                "request_count": s.request_count,
                "banned_until": max(0, round(s.banned_until - n, 1)),
                "first_seen_secs_ago": round(n - s.first_seen, 1),
            }
    return web.json_response({"clients": out, "config": {
        "burst": RATE_LIMIT_BURST, "refill_per_sec": RATE_LIMIT_REFILL,
        "pow_difficulty": POW_DIFFICULTY, "honeypot_ban_secs": HONEYPOT_BAN_SECS,
    }})

# ── Proxy ──────────────────────────────────────────────────────────────────
# F3: tighten default to the safe-for-WAF set. Operators who proxy a REST API
# can opt-in via env (e.g. ALLOWED_METHODS=GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS).
_ALLOWED_METHODS_DEFAULT = "GET,HEAD,POST,OPTIONS"
ALLOWED_METHODS = {
    m.strip().upper()
    for m in os.environ.get("ALLOWED_METHODS", _ALLOWED_METHODS_DEFAULT).split(",")
    if m.strip()
}

# F1: optional Host header allowlist. Comma-sep hostnames; default empty
# (no enforcement, current behaviour). When set, Host headers outside the
# list get silent-decoyed at Layer 0 — defends against host-header attacks
# at OUR gate (in addition to the existing X-Forwarded-Host overwrite).
_allowed_hosts_raw = os.environ.get("ALLOWED_HOSTS", "").strip()
ALLOWED_HOSTS = {
    h.strip().lower() for h in _allowed_hosts_raw.split(",") if h.strip()
} if _allowed_hosts_raw else set()

# Hop-by-hop headers (RFC 7230 §6.1) + ones the proxy must own.
HOP_BY_HOP_REQUEST = {
    "host", "content-length", "transfer-encoding", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "upgrade",
    # Path-rewrite / source-IP spoof headers — proxy sets its own values below.
    "x-forwarded-for", "x-real-ip", "x-forwarded-host", "x-forwarded-proto",
    "x-original-url", "x-rewrite-url", "x-original-host",
    "x-admin-key",  # never forward operator credential
}
HOP_BY_HOP_RESPONSE = {
    "transfer-encoding", "content-encoding", "content-length", "connection",
    "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "upgrade",
}

UPSTREAM_MAX_BODY = int(os.environ.get("UPSTREAM_MAX_BODY", str(2 * 1024 * 1024)))  # 2 MiB
UPSTREAM_MAX_RESP = int(os.environ.get("UPSTREAM_MAX_RESP", str(8 * 1024 * 1024)))  # 8 MiB

# ── v1.4: Slowloris guard (default ON with sensible timeouts) ────────────
HEADERS_TIMEOUT = float(os.environ.get("HEADERS_TIMEOUT", "10"))   # secs to receive full headers
BODY_TIMEOUT    = float(os.environ.get("BODY_TIMEOUT",    "30"))   # secs to receive full body

# ── v1.4.2/3: TLS / HTTP/2 fingerprint deny-list (JA3 / JA4) ────────────
# The TLS terminator (cloudflared, nginx + lua-nginx-ja3, AWS ALB ja3) injects
# the client's TLS handshake fingerprint as a header.
# v1.4.3 / TLS-1 fix: the header is client-spoofable when the gateway is
# reachable directly. JA4_TRUSTED_PEERS pins the source IPs (the TLS
# terminator) that are allowed to inject this header. When unset, we trust
# all peers (back-compat — assumes the operator has firewalled direct access).
JA4_HEADER     = os.environ.get("JA4_HEADER", "CF-JA4")
JA4_DENY_LIST  = {
    e.strip() for e in os.environ.get("JA4_DENY_LIST", "").split(",")
    if e.strip()
}
_ja4_trusted_raw = os.environ.get("JA4_TRUSTED_PEERS", "").strip()
JA4_TRUSTED_NETS: list = []
if _ja4_trusted_raw:
    for _entry in _ja4_trusted_raw.split(","):
        _entry = _entry.strip()
        if not _entry:
            continue
        try:
            JA4_TRUSTED_NETS.append(_ipaddress.ip_network(_entry, strict=False))
        except ValueError as _e:
            print(f"FATAL: invalid JA4_TRUSTED_PEERS entry {_entry!r} — {_e}",
                  flush=True)
            raise SystemExit(2)

def _ja4_peer_trusted(request) -> bool:
    """True if the kernel-observed peer IP may inject the JA4 header."""
    if not JA4_TRUSTED_NETS:
        return True   # operator did not pin — trust all (firewall assumed)
    try:
        ip = _ipaddress.ip_address(request.remote or "")
    except (ValueError, TypeError):
        return False
    return any(ip in net for net in JA4_TRUSTED_NETS)

def _tls_fingerprint_blocked(request) -> bool:
    """Apply the deny-list ONLY when the JA4 header arrives from a trusted
    peer (the TLS terminator). Untrusted sources are ignored so a direct
    attacker cannot bypass by forging a 'good' fingerprint."""
    if not JA4_DENY_LIST:
        return False
    if not _ja4_peer_trusted(request):
        return False
    fp = (request.headers.get(JA4_HEADER) or "").strip()
    return bool(fp) and fp in JA4_DENY_LIST

# ── v1.4.2: Strict Origin / Referer check on state-changing methods ─────
# When STRICT_ORIGIN=1, POST/PUT/PATCH/DELETE require an Origin header whose
# host matches one of ALLOWED_HOSTS. Off by default — many legitimate API /
# server-to-server clients don't send Origin. Operator can also list paths
# that bypass the check (e.g. webhooks) via OPEN_ORIGIN_PATHS.
STRICT_ORIGIN     = os.environ.get("STRICT_ORIGIN", "0") in ("1", "true", "yes")
_OPEN_ORIGIN_PATHS_RAW = os.environ.get("OPEN_ORIGIN_PATHS", "").strip()
OPEN_ORIGIN_PATHS = [p.strip() for p in _OPEN_ORIGIN_PATHS_RAW.split(",")
                    if p.strip()]

def _origin_check_failed(request) -> bool:
    """Returns True iff STRICT_ORIGIN is on AND the request fails the check."""
    if not STRICT_ORIGIN:
        return False
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return False
    if any(request.path.startswith(p) for p in OPEN_ORIGIN_PATHS):
        return False
    origin = request.headers.get("Origin", "").strip()
    if not origin:
        return True   # missing Origin on a state-change → reject
    try:
        from urllib.parse import urlparse
        host = (urlparse(origin).netloc or "").split(":", 1)[0].lower()
    except Exception:
        return True
    if not ALLOWED_HOSTS:
        return False  # nothing to compare against; let it through
    return host not in ALLOWED_HOSTS

# ── v1.4.2: Operator-required headers (e.g. X-Client-Version) ───────────
# Comma-separated list of headers that MUST be present on EVERY non-/__/ /
# non-static request. Empty by default. Useful when the operator's first-party
# client always sends a custom marker.
_REQUIRED_HEADERS_RAW = os.environ.get("REQUIRED_HEADERS", "").strip()
REQUIRED_HEADERS = [h.strip() for h in _REQUIRED_HEADERS_RAW.split(",")
                    if h.strip()]

def _missing_required_header(request) -> bool:
    if not REQUIRED_HEADERS:
        return False
    if request.path.startswith("/__"):
        return False
    if request.path.endswith((
            ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif",
            ".svg", ".webp", ".avif", ".ico", ".woff", ".woff2",
            ".ttf", ".otf", ".eot", ".map")):
        return False
    return any(h not in request.headers for h in REQUIRED_HEADERS)

# ── v1.4: Body pattern matching (extends Layer 3 to POST/PUT bodies) ─────
BODY_PATTERN_MATCH = os.environ.get("BODY_PATTERN_MATCH", "0") in ("1", "true", "yes")
SUSPICIOUS_BODY_PATTERNS = (
    re.compile(rb"(union[ +]+select|select[ +]+\*|or[ +]+1=1|--\s*$|\bxp_)", re.I),
    re.compile(rb"<script\b|javascript:|onerror\s*=", re.I),
    re.compile(rb"\{\{[^}]{1,40}\}\}|\{%[^%]{1,40}%\}"),       # SSTI
    re.compile(rb"\.\.[\\/]|\bphp://|\bfile://|\bexpect://"),
    re.compile(rb"[;&|`]\s*(cat|ls|wget|curl|nc|sh|bash)\b", re.I),
)

def is_suspicious_body(body: bytes, ctype: str) -> bool:
    """Returns True if request body matches a known SQLi/XSS/SSTI/cmd-injection
    pattern. Only scans text-ish content types and bounds at 64 KiB.
    L3: form-encoded bodies are percent-decoded before matching so payloads
    like name=%27+OR+1%3D1 are caught (matched as `' OR 1=1`)."""
    if not BODY_PATTERN_MATCH or not body:
        return False
    cl = ctype.lower()
    if not any(t in cl for t in ("application/json", "application/x-www-form-urlencoded",
                                  "text/plain", "text/xml", "application/xml")):
        return False
    sample = body[:65536]
    if "x-www-form-urlencoded" in cl:
        from urllib.parse import unquote_to_bytes
        sample = unquote_to_bytes(sample)
    return any(p.search(sample) for p in SUSPICIOUS_BODY_PATTERNS)

# ── v1.4: Bot-trap forms (auto-inject hidden field; flag bots that fill it) ─
BOT_TRAP_FORMS = os.environ.get("BOT_TRAP_FORMS", "0") in ("1", "true", "yes")
# Field name is per-process random — same for all forms in this container,
# but rotates on every restart so static scrapers can't hard-code it.
BOT_TRAP_FIELD = "ec_" + secrets.token_hex(4)
_TRAP_INPUT_HTML = (
    f'<input type="text" name="{BOT_TRAP_FIELD}" tabindex="-1" autocomplete="off" '
    f'aria-hidden="true" '
    f'style="position:absolute;left:-9999px;top:-9999px;opacity:0;'
    f'width:0;height:0;visibility:hidden">'
).encode()
_FORM_OPEN_RX = re.compile(rb"(<form\b[^>]*>)", re.IGNORECASE)

def _inject_bot_trap(body: bytes) -> bytes:
    if not BOT_TRAP_FORMS or b"<form" not in body[:65536].lower():
        return body
    return _FORM_OPEN_RX.sub(rb"\1" + _TRAP_INPUT_HTML, body, count=20)

def _bot_trap_triggered(body: bytes, ctype: str) -> bool:
    """True iff the bot-trap field is non-empty in a form-encoded POST body."""
    if not BOT_TRAP_FORMS or not body:
        return False
    if "x-www-form-urlencoded" not in ctype.lower():
        return False
    needle = (BOT_TRAP_FIELD + "=").encode()
    if needle not in body[:65536]:
        return False
    try:
        from urllib.parse import parse_qs
        q = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=False)
        v = q.get(BOT_TRAP_FIELD, [""])[0].strip()
        return bool(v)
    except Exception:
        return False

# ── v1.4: JS challenge (Turnstile-backed cookie gate) ────────────────────
# Earlier iterations of this feature stacked client-computed primitives —
# SHA-256 Proof-of-Work, browser-API probe with cross-validation,
# anchor-fetch proof, sub-second timing windows — to try to distinguish
# real browsers from scripted clients. Empirically every one of those
# layers was bypassable in pure Python in ~1 s (see Threat-model section
# in README.md). The honest replacement is this: the gate exists ONLY
# when Cloudflare Turnstile is configured. The Turnstile success token is
# minted by Cloudflare server-side, so a scripted client cannot satisfy
# it without solving the actual CAPTCHA. Without Turnstile keys, the
# JS-challenge feature is a no-op and the gateway relies on its other
# layers (UA filter, header completeness, behavioral, rate-limits,
# risk-score, bot-trap forms, body-pattern matching, slowloris guard).
JS_CHALLENGE = os.environ.get("JS_CHALLENGE", "0") in ("1", "true", "yes")
CHAL_COOKIE  = "chal"
CHAL_TTL     = int(os.environ.get("JS_CHALLENGE_TTL", "3600"))    # 1 h
CHAL_NONCE_TTL = 120          # nonce valid for 2 min after issue
# Reuse SESSION_KEY for chal HMAC (same trust domain).

TURNSTILE_SITEKEY = os.environ.get("TURNSTILE_SITEKEY", "").strip()
TURNSTILE_SECRET  = os.environ.get("TURNSTILE_SECRET", "").strip()
TURNSTILE_ENABLED = bool(TURNSTILE_SITEKEY and TURNSTILE_SECRET)
TURNSTILE_VERIFY_URL = (
    "https://challenges.cloudflare.com/turnstile/v0/siteverify")

# v1.4.1 V9.2: JA4 TLS-fingerprint binding for the chal cookie. Unlike PoW
# / probe (computed by the attacker), the JA4 fingerprint is observed by
# the network during the TLS handshake — the attacker would have to
# replace their entire TLS stack (curl-impersonate, undetected-chromedriver)
# to forge a Chrome-like JA4. Require / bind only when configured AND a
# trusted peer is injecting the header.
#   JS_CHAL_REQUIRE_JA4=1  → /__challenge MUST receive a non-empty JA4
#                             from a trusted peer; reject otherwise.
#   JS_CHAL_BIND_JA4=1     → bind chal cookie to JA4-hash (default: ON
#                             when JA4 header is present from a trusted
#                             peer; opportunistic — does not break flows
#                             that lack the header).
JS_CHAL_REQUIRE_JA4 = os.environ.get(
    "JS_CHAL_REQUIRE_JA4", "0") in ("1", "true", "yes")
JS_CHAL_BIND_JA4 = os.environ.get(
    "JS_CHAL_BIND_JA4", "1") not in ("", "0", "false", "False", "no")

# NOTE: there is no built-in JA4 deny-list. Real JA4 fingerprints depend on
# the OpenSSL / TLS-stack version of each client and on the upstream JA4
# extractor (cloudflared, nginx-JA4, Fastly emit slightly different forms).
# Hard-coding fingerprints here would be a footgun: prefixes go stale and
# false-positive on real users. The operator must populate JA4_DENY_LIST
# from observation — the per-request JA4 is now visible in the dashboard
# and recorded in events so blocking can be driven by actual telemetry,
# not heuristics.

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

def _ip_tier(ip: str) -> str:
    """V9: collapse client IP to a coarse network tier (v4 /24, v6 /48) so
    the chal cookie can be IP-bound without breaking ordinary mobile / NAT
    rebinds. Returns empty string for unparseable input. Note: this is the
    *raw* tier (e.g. "203.0.113.0") used only inside the HMAC payload — the
    cookie carries an opaque tier hash, never the raw value."""
    try:
        import ipaddress
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

def _request_ja4(request) -> str:
    """V9.2: return the JA4 fingerprint observed by the trusted TLS
    terminator for this request, or "" if absent / untrusted. Pure read
    of an upstream-injected header; the attacker can't fabricate it from
    a direct connection because JA4_TRUSTED_PEERS pins the source."""
    if not _ja4_peer_trusted(request):
        return ""
    return (request.headers.get(JA4_HEADER) or "").strip()

def _ja4_hash(ja4: str) -> str:
    """Opaque hash of the JA4 fingerprint for the cookie value (same
    pattern as `_tier_hash`). Empty input → empty output (no binding)."""
    if not ja4:
        return ""
    return hmac.new(SESSION_KEY, b"ja4|" + ja4.encode(),
                    hashlib.sha256).hexdigest()[:16]

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
        if int(time.time()) - int(issued) > CHAL_TTL:
            return False
    except ValueError:
        return False
    return True

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
    const tsToken = await waitForTurnstile();
    const fd = new URLSearchParams({n, t, 'cf-turnstile-response': tsToken});
    const r = await fetch('/__challenge', {
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
JS_CHAL_STRICT_STATIC = os.environ.get(
    "JS_CHAL_STRICT_STATIC", "1") not in ("", "0", "false", "False", "no")
_API_PATH_HINTS = ("/api/", "/graphql", "/rest/", "/rpc/", "/v1/", "/v2/",
                   "/v3/", "/admin/", "/internal/")

def _looks_like_api(path: str) -> bool:
    """Conservative heuristic: any path containing a typical API segment is
    NOT a static asset, even if it endswith('.css'). Prevents the
    `/api/v1/users.css` style bypass on permissive backends."""
    p = path.lower()
    return any(h in p for h in _API_PATH_HINTS)

# v1.4.1 (post-V8 fix): chal cookie is required on EVERY non-static,
# non-admin, non-opted-out request — not just HTML. Browsers carry the
# cookie on XHR transparently; pure-HTTP bots don't and get blocked.
# Operator-controlled escape hatch for legit non-browser clients (S2S,
# mobile apps, webhooks). Comma-separated path prefixes.
_JS_CHAL_OPEN_PATHS_RAW = os.environ.get("JS_CHAL_OPEN_PATHS", "").strip()
JS_CHAL_OPEN_PATHS = [p.strip() for p in _JS_CHAL_OPEN_PATHS_RAW.split(",")
                      if p.strip()]

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
    if not JS_CHALLENGE:
        return False
    if request.path == "/__challenge" or request.path.startswith("/__"):
        return False  # admin / challenge-solver have their own auth
    if request.path.endswith(_STATIC_ASSET_SUFFIXES):
        # V8 hardening: don't trust a `.css` suffix on what looks like an API
        # path. Permissive backends (Spring suffix matching, Express trailing
        # tokens) would otherwise return JSON for `/api/v1/users.css`.
        if not (JS_CHAL_STRICT_STATIC and _looks_like_api(request.path)):
            return False  # public assets
    if any(request.path.startswith(p) for p in JS_CHAL_OPEN_PATHS):
        return False  # operator-defined non-browser paths
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
    requests without the cookie are silent-decoyed instead."""
    if not _js_challenge_required(request):
        return False
    if not TURNSTILE_ENABLED:
        return False
    if request.method != "GET":
        return False
    return "text/html" in request.headers.get("Accept", "")

# ── Edge-injected security response headers (HTML only) ──────────────────
# Each can be overridden / disabled via env. An empty value disables that one.
INJECT_SECURITY_HEADERS = os.environ.get(
    "INJECT_SECURITY_HEADERS", "1") not in ("", "0", "false", "False", "no")
SECURITY_HEADERS = {
    "X-Frame-Options":           os.environ.get("SEC_X_FRAME_OPTIONS", "SAMEORIGIN"),
    "X-Content-Type-Options":    os.environ.get("SEC_X_CONTENT_TYPE_OPTIONS", "nosniff"),
    "Referrer-Policy":           os.environ.get("SEC_REFERRER_POLICY",
                                                "strict-origin-when-cross-origin"),
    "X-Permitted-Cross-Domain-Policies":
                                 os.environ.get("SEC_X_PERMITTED_XDP", "none"),
    "Permissions-Policy":        os.environ.get("SEC_PERMISSIONS_POLICY",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"),
    "Strict-Transport-Security": os.environ.get("SEC_HSTS",
        "max-age=31536000; includeSubDomains"),
    # CSP is permissive by default to avoid breaking SPAs; tighten via env.
    "Content-Security-Policy":   os.environ.get("SEC_CSP", ""),
    "Cross-Origin-Opener-Policy":   os.environ.get("SEC_COOP", "same-origin"),
    "Cross-Origin-Resource-Policy": os.environ.get("SEC_CORP", "same-site"),
}

def _strip_admin_key_from_qs(path_qs: str) -> str:
    """Remove `key=` query parameter so ADMIN_KEY never leaks into upstream logs."""
    if "?" not in path_qs or "key=" not in path_qs:
        return path_qs
    path, _, qs = path_qs.partition("?")
    kept = [p for p in qs.split("&") if p and not p.startswith("key=")]
    return path + ("?" + "&".join(kept) if kept else "")

def _strip_own_session_cookie(cookie_header: str) -> str:
    """Remove our own SESSION_COOKIE from a forwarded Cookie header."""
    if not cookie_header:
        return ""
    parts = [p.strip() for p in cookie_header.split(";")]
    kept = [p for p in parts if p and not p.lower().startswith(SESSION_COOKIE.lower() + "=")]
    return "; ".join(kept)

# ── R7: AI-agent canary echo detection ───────────────────────────────────
# LLM-driven agents summarise the response into the model's context window
# and re-emit fragments of that text in subsequent prompts. So a unique
# token planted in the HTML comes back to us in the next request from the
# same identity — something a real browser will never do, and a generic
# scraper has no reason to do either. Pentester L8 (round-7 lab finding).
CANARY_ECHO_DETECTION = os.environ.get(
    "CANARY_ECHO_DETECTION", "1") not in ("", "0", "false", "False", "no")
CANARY_TTL_S    = int(os.environ.get("CANARY_TTL_S", "600"))   # 10 min
_CANARY_PREFIX  = "agw-c-"
_canary_tokens: dict = {}      # token -> expiry_epoch
_CANARY_USED_MAX = 50000
_CANARY_RE = re.compile(r"agw-c-[0-9a-f]{16}")

def _new_canary() -> str:
    tok = f"{_CANARY_PREFIX}{secrets.token_hex(8)}"
    now_ts = time.time()
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
    now_ts = time.time()
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


def _inject_honey_links(body: bytes) -> bytes:
    """Insert honey-link block before the LAST `</body>` (document terminator).
    Skips injection if the chosen position would land inside a `<script>` block
    (i.e. if any `<script` token appears after the rightmost `</body>` in the
    final 4 KiB) — prevents corrupting JS string literals."""
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
    return body[:abs_idx] + HONEY_LINK_HTML.encode() + body[abs_idx:]

def _is_ws_upgrade(request: web.Request) -> bool:
    return (request.headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in request.headers.get("Connection", "").lower())

async def proxy_websocket(request: web.Request):
    """Bidirectional WebSocket bridge to upstream. Headers/cookies/origin
    rewrites match the HTTP path; aiohttp manages the Sec-WebSocket-* dance."""
    from urllib.parse import urlparse
    u = urlparse(UPSTREAM)
    upstream_host = u.netloc
    upstream_scheme_host = f"{u.scheme}://{u.netloc}"
    ws_scheme = "wss" if u.scheme == "https" else "ws"
    target = f"{ws_scheme}://{upstream_host}{_strip_admin_key_from_qs(request.path_qs)}"

    fwd_headers = {}
    for k, v in request.headers.items():
        kl = k.lower()
        # Hop-by-hop + WS-specific (aiohttp client sets its own).
        if kl in HOP_BY_HOP_REQUEST or kl.startswith("sec-websocket"):
            continue
        if kl == "cookie":
            cleaned = _strip_own_session_cookie(v)
            if cleaned:
                fwd_headers[k] = cleaned
            continue
        if kl == "origin":
            fwd_headers[k] = upstream_scheme_host
            continue
        if kl == "referer":
            try:
                rp = urlparse(v)
                if rp.scheme and rp.netloc:
                    new_ref = upstream_scheme_host + (rp.path or "/")
                    if rp.query:
                        new_ref += "?" + rp.query
                    fwd_headers[k] = new_ref
                    continue
            except Exception:
                pass
        fwd_headers[k] = v

    gw_ip = get_ip(request)
    fwd_headers["X-Forwarded-For"] = gw_ip
    fwd_headers["X-Real-IP"] = gw_ip
    fwd_headers["X-Forwarded-Proto"] = "https" if request.secure else "http"
    if request.host:
        fwd_headers["X-Forwarded-Host"] = request.host

    # Sub-protocol negotiation (e.g. STOMP, GraphQL-WS).
    proto_hdr = request.headers.get("Sec-WebSocket-Protocol", "")
    protocols = tuple(p.strip() for p in proto_hdr.split(",") if p.strip())

    ws_server = web.WebSocketResponse(protocols=protocols, heartbeat=30, autoping=True)
    await ws_server.prepare(request)

    try:
        async with ClientSession(timeout=ClientTimeout(total=None, sock_connect=10)) as session:
            async with session.ws_connect(
                target, headers=fwd_headers, protocols=protocols,
                heartbeat=30, autoping=True, max_msg_size=4 * 1024 * 1024,
            ) as ws_client:
                async def srv_to_up():
                    async for msg in ws_server:
                        t = msg.type
                        if t == aiohttp.WSMsgType.TEXT:
                            await ws_client.send_str(msg.data)
                        elif t == aiohttp.WSMsgType.BINARY:
                            await ws_client.send_bytes(msg.data)
                        elif t in (aiohttp.WSMsgType.CLOSE,
                                   aiohttp.WSMsgType.CLOSING,
                                   aiohttp.WSMsgType.CLOSED,
                                   aiohttp.WSMsgType.ERROR):
                            return
                async def up_to_srv():
                    async for msg in ws_client:
                        t = msg.type
                        if t == aiohttp.WSMsgType.TEXT:
                            await ws_server.send_str(msg.data)
                        elif t == aiohttp.WSMsgType.BINARY:
                            await ws_server.send_bytes(msg.data)
                        elif t in (aiohttp.WSMsgType.CLOSE,
                                   aiohttp.WSMsgType.CLOSING,
                                   aiohttp.WSMsgType.CLOSED,
                                   aiohttp.WSMsgType.ERROR):
                            return
                done, pending = await asyncio.wait(
                    [asyncio.create_task(srv_to_up()),
                     asyncio.create_task(up_to_srv())],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for t in pending:
                    t.cancel()
    except aiohttp.WSServerHandshakeError as e:
        if not ws_server.closed:
            await ws_server.close(code=1011,
                                  message=f"upstream handshake: {e.status}".encode())
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        if not ws_server.closed:
            await ws_server.close(code=1011, message=str(e)[:120].encode())
    finally:
        if not ws_server.closed:
            await ws_server.close()
    return ws_server

async def proxy(request: web.Request):
    # WebSocket upgrade — bridge to upstream.
    if _is_ws_upgrade(request):
        return await proxy_websocket(request)

    # M2: method allowlist — block TRACE/CONNECT/anything unusual.
    if request.method not in ALLOWED_METHODS:
        return web.Response(status=405, text="method not allowed\n")

    target = UPSTREAM + _strip_admin_key_from_qs(request.path_qs)

    # C3 + H5: build forwarded headers from an allowlist-by-exclusion list.
    # All hop-by-hop and source-spoof headers stripped. Cookie has our own
    # SESSION_COOKIE removed before forwarding so signed token never leaves us.
    fwd_headers = {}
    for k, v in request.headers.items():
        kl = k.lower()
        if kl in HOP_BY_HOP_REQUEST:
            continue
        if kl == "cookie":
            cleaned = _strip_own_session_cookie(v)
            if cleaned:
                fwd_headers[k] = cleaned
            continue
        fwd_headers[k] = v

    # Re-assert source-IP semantics: replace any client-supplied XFF with our
    # gateway-computed IP (defends against ACL bypass on backends that trust XFF).
    gw_ip = get_ip(request)
    fwd_headers["X-Forwarded-For"] = gw_ip
    fwd_headers["X-Real-IP"] = gw_ip
    fwd_headers["X-Forwarded-Proto"] = request.scheme or "http"
    if request.host:
        fwd_headers["X-Forwarded-Host"] = request.host

    # Rewrite Origin / Referer / Host so upstream's CSRF / origin-validation
    # sees its own canonical origin instead of the gateway's public hostname.
    # Without this, upstream reverse-proxy aware backends (Keycloak, UFE) 403
    # CORS preflight + auth POSTs because Origin != upstream's expected scheme://host.
    upstream_origin = UPSTREAM.rstrip("/")
    try:
        from urllib.parse import urlparse
        u = urlparse(upstream_origin)
        upstream_host = u.netloc
        upstream_scheme_host = f"{u.scheme}://{u.netloc}"
    except Exception:
        upstream_host, upstream_scheme_host = "", upstream_origin

    if upstream_host:
        # Host header MUST match upstream's expected vhost or TLS SNI fails / wrong vhost served.
        fwd_headers["Host"] = upstream_host
        if "origin" in {k.lower() for k in fwd_headers}:
            for k in list(fwd_headers):
                if k.lower() == "origin":
                    fwd_headers[k] = upstream_scheme_host
        if "referer" in {k.lower() for k in fwd_headers}:
            # Replace client-side scheme://host prefix with upstream's, keep the path
            for k in list(fwd_headers):
                if k.lower() == "referer":
                    ref = fwd_headers[k]
                    try:
                        rp = urlparse(ref)
                        if rp.scheme and rp.netloc:
                            new_ref = upstream_scheme_host + (rp.path or "/")
                            if rp.query:
                                new_ref += "?" + rp.query
                            fwd_headers[k] = new_ref
                    except Exception:
                        pass

    # H6+v1.4: stream the body, bound it, AND apply a slowloris timeout.
    # Reject if larger than UPSTREAM_MAX_BODY or if it takes longer than
    # BODY_TIMEOUT to fully arrive.
    body = None
    if request.body_exists and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            async def _drain():
                chunks = []
                total = 0
                async for c in request.content.iter_any():
                    total += len(c)
                    if total > UPSTREAM_MAX_BODY:
                        raise web.HTTPRequestEntityTooLarge(
                            max_size=UPSTREAM_MAX_BODY, actual_size=total)
                    chunks.append(c)
                return b"".join(chunks) if chunks else None
            body = await asyncio.wait_for(_drain(), timeout=BODY_TIMEOUT)
        except asyncio.TimeoutError:
            return web.Response(status=408, text="request body timeout\n")
        except web.HTTPRequestEntityTooLarge:
            return web.Response(status=413, text="payload too large\n")
        except Exception:
            return web.Response(status=400, text="bad request\n")

    # v1.4 #4 — body pattern matching (extends Layer 3 to bodies).
    if body is not None:
        client_ctype = request.headers.get("Content-Type", "")
        if is_suspicious_body(body, client_ctype):
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",
                "suspicious-body", get_ip(request))   # L1: was "suspicious-path"
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, "suspicious-body",
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

        # R7: also scan POST/PUT bodies for echoed canaries — LLM agents
        # frequently splice prior-response text into the new prompt, which
        # then becomes the request body.
        if CANARY_ECHO_DETECTION:
            echoed = _scan_request_for_canary(request, body_bytes=body)
            if echoed:
                await update_risk_and_maybe_ban(
                    request.get("_track_key") or request.remote or "0.0.0.0",
                    "canary-echo", get_ip(request))
                return await _silent_decoy_response(
                    get_ip(request), request.headers.get("User-Agent", ""),
                    request.path, "canary-echo",
                    track_key=request.get("_track_key"),
                    sid=request.get("_sid", ""),
                    fp=request.get("_fp", ""))

        # v1.4 #6 — bot-trap form fields.
        if _bot_trap_triggered(body, client_ctype):
            await update_risk_and_maybe_ban(
                request.get("_track_key") or request.remote or "0.0.0.0",
                "bot-trap", get_ip(request))
            return await _silent_decoy_response(
                get_ip(request), request.headers.get("User-Agent", ""),
                request.path, "bot-trap",
                track_key=request.get("_track_key"),
                sid=request.get("_sid", ""),
                fp=request.get("_fp", ""))

    try:
        async with ClientSession(timeout=ClientTimeout(total=30)) as session:
            async with session.request(
                request.method, target, headers=fwd_headers, data=body,
                allow_redirects=False,
            ) as resp:
                # H6: bound the upstream response body too — defends the proxy
                # itself against a malicious upstream sending unbounded data.
                # Stream-read in chunks so we don't truncate (a single
                # `read(N)` returns only what's in the buffer at that moment).
                chunks = []
                total = 0
                async for chunk in resp.content.iter_any():
                    total += len(chunk)
                    if total > UPSTREAM_MAX_RESP:
                        return web.Response(status=502,
                                            text="upstream response too large\n")
                    chunks.append(chunk)
                resp_body = b"".join(chunks)

                # L4: complete hop-by-hop response strip. Use a multidict so
                # repeated headers (notably Set-Cookie) survive intact.
                from multidict import CIMultiDict
                response_headers = CIMultiDict()
                from urllib.parse import urlparse as _urlparse
                up_parsed = _urlparse(UPSTREAM)
                client_scheme = (request.headers.get("X-Forwarded-Proto")
                                 or ("https" if request.secure else "http"))
                client_host = request.host or up_parsed.netloc

                for k, v in resp.headers.items():
                    kl = k.lower()
                    if kl in HOP_BY_HOP_RESPONSE:
                        continue

                    # SSO flow #1: rewrite Location header in 3xx redirects
                    # so the browser keeps coming back through the gateway.
                    if kl == "location" and 300 <= resp.status < 400:
                        try:
                            lp = _urlparse(v)
                            if lp.scheme and lp.netloc and lp.netloc == up_parsed.netloc:
                                rewritten = f"{client_scheme}://{client_host}{lp.path or ''}"
                                if lp.query:    rewritten += "?" + lp.query
                                if lp.fragment: rewritten += "#" + lp.fragment
                                v = rewritten
                            else:
                                # External IdP redirect (e.g. Keycloak). Rewrite
                                # any embedded `scheme://upstream-host` references
                                # (URL-encoded or not) inside the URL — typically
                                # the redirect_uri / state OAuth2 params — so the
                                # IdP sends the user back THROUGH the gateway.
                                up_url_raw = f"{up_parsed.scheme}://{up_parsed.netloc}"
                                gw_url_raw = f"{client_scheme}://{client_host}"
                                from urllib.parse import quote as _q
                                v = v.replace(up_url_raw, gw_url_raw)
                                v = v.replace(_q(up_url_raw, safe=""),
                                              _q(gw_url_raw, safe=""))
                                v = v.replace(_q(up_url_raw, safe=":/"),
                                              _q(gw_url_raw, safe=":/"))
                        except Exception:
                            pass

                    # SSO flow #2: strip the Domain= attribute from Set-Cookie
                    # — without this the browser rejects upstream-domain-scoped
                    # cookies when it's actually visiting our gateway hostname.
                    if kl == "set-cookie":
                        v = re.sub(r";\s*[Dd]omain=[^;]+", "", v)

                    response_headers.add(k, v)

                response_headers["X-Proxy"] = "AppSecGW_1.4.6"

                # Inject baseline security response headers on HTML responses
                # (the upstream may not set them; we add them at the edge so
                # browser-side defenses kick in).  Each header can be disabled
                # individually via env or overridden by an upstream value
                # already present in the response.
                ctype = response_headers.get("Content-Type", "").lower().lstrip()
                if ctype.startswith("text/html") and INJECT_SECURITY_HEADERS:
                    for hk, hv in SECURITY_HEADERS.items():
                        if hv and hk.lower() not in {k.lower() for k in response_headers}:
                            response_headers[hk] = hv

                # H7/N1: inject honey-links only when Content-Type begins with
                # text/html (rejects `application/text/html-foo` substrings).
                if ctype.startswith("text/html"):
                    resp_body = _inject_honey_links(resp_body)
                    # v1.4 #6 — bot-trap form fields (no-op when disabled).
                    resp_body = _inject_bot_trap(resp_body)
                    # R7: plant a unique canary so we can detect LLM-agent
                    # echo behaviour on subsequent requests from this client.
                    if CANARY_ECHO_DETECTION:
                        canary = _new_canary()
                        resp_body = _inject_canary(resp_body, canary)
                        response_headers["X-Trace-Id"] = canary

                return web.Response(status=resp.status, body=resp_body, headers=response_headers)
    except aiohttp.ClientError:
        return web.Response(status=502, text="upstream error\n")
    except asyncio.TimeoutError:
        return web.Response(status=504, text="upstream timeout\n")

# ── App ────────────────────────────────────────────────────────────────────
DEBUG_ENABLED = os.environ.get("DEBUG", "0") not in ("", "0", "false", "False", "no")

_REDACT_HEADERS = {"cookie", "authorization", "x-admin-key", "x-pow-token", "x-pow-solution"}

async def debug_xff(request):
    if not DEBUG_ENABLED:
        return web.Response(status=404, text="not found\n")
    safe_headers = {
        k: ("<redacted>" if k.lower() in _REDACT_HEADERS else v)
        for k, v in request.headers.items()
    }
    return web.json_response({
        "remote": request.remote,
        "xff_raw": request.headers.get("X-Forwarded-For"),
        "trust_xff_mode": TRUST_XFF,
        "computed_ip": get_ip(request),
        "headers": safe_headers,
    }, headers={"Cache-Control": "no-store"})

async def on_startup(app):
    """Initialise SQLite DB + spawn the async writer + load saved state."""
    global db_queue, db_writer_task, prune_task, service_metrics_task
    db_init()
    db_load_state()
    db_queue = asyncio.Queue(maxsize=10000)
    db_writer_task = asyncio.create_task(db_writer_loop())
    prune_task = asyncio.create_task(_prune_state_loop())
    service_metrics_task = asyncio.create_task(_sample_service_metrics_loop())
    print(f"[db] persistence active → {DB_PATH}")
    print(f"[svc-metrics] sampling every {SERVICE_METRICS_INTERVAL}s, "
          f"keeping {SERVICE_METRICS_RETENTION} samples")
    if JS_CHALLENGE and not TURNSTILE_ENABLED:
        print("[js-challenge] active (heuristic mint, no third-party). "
              "Cookie gate engages on every non-static path; cookie is "
              "auto-issued on the first qualifying HTML GET. Bypass cost "
              "vs determined script: ~1 RTT — combine with R7 canary "
              "echo, body-pattern, UA filter, hostile pool. For a hard "
              "boundary set TURNSTILE_SITEKEY/SECRET.", flush=True)
    elif JS_CHALLENGE and TURNSTILE_ENABLED:
        print("[js-challenge] active (Turnstile-backed cookie gate)",
              flush=True)

async def on_cleanup(app):
    """Flush queue and close DB writer cleanly."""
    global prune_task, service_metrics_task
    if prune_task:
        prune_task.cancel()
    if service_metrics_task:
        service_metrics_task.cancel()
    if db_writer_task:
        # Final global counters flush
        if db_queue is not None:
            await db_queue.put(("set_kv", ("total_requests", str(metrics["total_requests"]))))
            await db_queue.put(("set_kv", ("allowed", str(metrics["allowed"]))))
            await db_queue.put(("set_kv", ("blocked", str(metrics["blocked"]))))
            await db_queue.put(("set_kv", ("by_reason", json.dumps(dict(metrics["by_reason"])))))
            await db_queue.put(("set_kv", ("by_status", json.dumps({str(k): v for k, v in metrics["by_status"].items()}))))
            await db_queue.put(("set_kv", ("by_path", json.dumps(dict(metrics["by_path"])))))
            # Wait for queue to drain
            try:
                await asyncio.wait_for(db_queue.join() if hasattr(db_queue, 'join') else asyncio.sleep(0.5), timeout=3)
            except asyncio.TimeoutError:
                pass
        db_writer_task.cancel()

# ── Stealth-agent (allowed-but-suspicious) analytics ───────────────────────
def _stealth_score(s) -> tuple[int, dict, dict]:
    """Score allowed-traffic identity for stealth-agent likelihood (0-100).
    Returns (total, components_dict, metrics_dict)."""
    if s.allowed_count == 0:
        return 0, {}, {}
    # Header-completeness component (avg over recent allowed; fewer = bot-like).
    if s.header_scores:
        avg_h = sum(s.header_scores) / len(s.header_scores)
    else:
        avg_h = 7.0
    h_pts = max(0, int((7 - avg_h) * 4))                       # 0..28
    # Asset-discipline component: many HTML, no/little static.
    a_pts = 0
    if s.html_loads >= 5:
        ratio = s.static_loads / max(1, s.html_loads)
        a_pts = max(0, int((1 - min(1, ratio * 3)) * 20))      # 0..20
    # Path-enumeration component.
    e_pts = 0
    diversity = 0.0
    if s.allowed_count >= 8 and s.unique_paths:
        diversity = len(s.unique_paths) / max(1, s.allowed_count)
        if diversity > 0.5:
            e_pts = min(15, int(diversity * 18))               # 0..15
    # Behavioral-timing component (sub-block but suspicious).
    b_pts, cov = 0, None
    if len(s.request_times) >= 8:
        recent = list(s.request_times)[-16:]
        intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
        if intervals and all(iv > 0 for iv in intervals):
            mean_iv = sum(intervals) / len(intervals)
            if 0 < mean_iv < 5.0:
                std = (sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)) ** 0.5
                cov = std / mean_iv
                if cov < 0.20:
                    b_pts = min(20, int((0.20 - cov) * 200))    # 0..20
    # Risk-score component (sub-threshold).
    r_pts = min(15, int(s.risk_score / 4))                      # 0..15
    # Upstream 404 component (probing without ban).
    f_pts = min(10, s.upstream_404_count // 2)                  # 0..10

    total = min(100, h_pts + a_pts + e_pts + b_pts + r_pts + f_pts)
    components = {
        "headers": h_pts, "assets": a_pts, "enum": e_pts,
        "timing": b_pts, "risk": r_pts, "404s": f_pts,
    }
    metrics = {
        "avg_header_score": round(avg_h, 2),
        "html_loads": s.html_loads,
        "static_loads": s.static_loads,
        "unique_paths": len(s.unique_paths),
        "path_diversity": round(diversity, 3),
        "behavioral_cov": round(cov, 3) if cov is not None else None,
        "upstream_404_count": s.upstream_404_count,
        "risk_score": round(s.risk_score, 1),
        "samples": len(s.header_scores),
    }
    return total, components, metrics

AGENT_BLOCK_REASONS = (
    "ua-blocked", "ua-empty", "ua-too-short", "ua-non-browser",
    "ai-probe", "ai-headers-empty", "ai-headers-incomplete",
    "ai-enumeration", "ai-no-assets", "behavior",
    "banned", "banned-silent", "honeypot", "honeypot-silent",
    "suspicious-path", "session-flood",
    "rate-limit-ip", "rate-limit", "host-not-allowed",
    "admin-ip-blocked",
    "suspicious-body", "bot-trap", "js-challenge",
    "tls-fingerprint", "origin-mismatch", "missing-required-header",
)

async def agents_timeline_endpoint(request: web.Request):
    """Per-bucket counts of:
      - detected:       requests blocked because they tripped an agent-signal layer
      - missed:         requests ALLOWED but originating from an identity whose
                        current stealth_score >= min_score (likely-AI bot we
                        couldn't catch at request-time)
      - clean_allowed:  remaining allowed traffic (best estimate of humans)
    Query: ?range=<minutes>&bucket=<secs>&min_score=<n>
    """
    try:
        range_min = max(5, min(10080, int(request.query.get("range", "60"))))
    except ValueError:
        range_min = 60
    try:
        bucket_secs = int(request.query.get("bucket", "60"))
        if bucket_secs not in (60, 300, 900, 3600, 86400):
            bucket_secs = 60
    except ValueError:
        bucket_secs = 60
    try:
        min_score = max(0, min(100, int(request.query.get("min_score", "20"))))
    except ValueError:
        min_score = 20

    async with state_lock:
        stealth_ips = set()
        for k, s in ip_state.items():
            if s.allowed_count and _stealth_score(s)[0] >= min_score:
                if s.last_ip:
                    stealth_ips.add(s.last_ip)

    end_b = (int(_t.time()) // bucket_secs) * bucket_secs
    bucket_count = min(250, max(2, (range_min * 60) // bucket_secs))
    start_b = end_b - (bucket_count - 1) * bucket_secs

    detected, allowed_total, missed = {}, {}, {}
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        agent_q = ",".join("?" * len(AGENT_BLOCK_REASONS))
        for r in conn.execute(
            f"SELECT (CAST(ts/{bucket_secs} AS INTEGER)*{bucket_secs}) AS b, "
            f"COUNT(*) AS n FROM events "
            f"WHERE ts >= ? AND ts <= ? AND reason IN ({agent_q}) "
            f"GROUP BY b",
            (start_b, end_b + bucket_secs, *AGENT_BLOCK_REASONS),
        ):
            detected[int(r["b"])] = r["n"]

        for r in conn.execute(
            f"SELECT (CAST(ts/{bucket_secs} AS INTEGER)*{bucket_secs}) AS b, "
            f"COUNT(*) AS n FROM events "
            f"WHERE ts >= ? AND ts <= ? AND (reason='' OR reason='OK') "
            f"GROUP BY b",
            (start_b, end_b + bucket_secs),
        ):
            allowed_total[int(r["b"])] = r["n"]

        if stealth_ips:
            ip_q = ",".join("?" * len(stealth_ips))
            for r in conn.execute(
                f"SELECT (CAST(ts/{bucket_secs} AS INTEGER)*{bucket_secs}) AS b, "
                f"COUNT(*) AS n FROM events "
                f"WHERE ts >= ? AND ts <= ? AND (reason='' OR reason='OK') "
                f"AND ip IN ({ip_q}) GROUP BY b",
                (start_b, end_b + bucket_secs, *stealth_ips),
            ):
                missed[int(r["b"])] = r["n"]
        conn.close()
    except Exception as e:
        print(f"[agents-timeline] db error: {e}")

    series = []
    tot_d = tot_m = tot_c = 0
    for b in range(start_b, end_b + 1, bucket_secs):
        d = detected.get(b, 0)
        m = missed.get(b, 0)
        a = allowed_total.get(b, 0)
        c = max(0, a - m)
        tot_d += d; tot_m += m; tot_c += c
        series.append({"t": b, "detected": d, "missed": m, "clean_allowed": c})

    return web.json_response({
        "timeline": series,
        "totals": {"detected": tot_d, "missed": tot_m, "clean_allowed": tot_c},
        "stealth_ips_count": len(stealth_ips),
        "range_min": range_min,
        "bucket_secs": bucket_secs,
        "min_score": min_score,
    }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


async def agents_data_endpoint(request: web.Request):
    """JSON feed for the stealth-agents dashboard.

    Query params:
      ?min_score=N    only return suspects with score >= N (default 20)
      ?limit=N        cap result rows (default 100, max 500)
    """
    try:
        min_score = max(0, min(100, int(request.query.get("min_score", "20"))))
    except ValueError:
        min_score = 20
    try:
        limit = max(1, min(500, int(request.query.get("limit", "100"))))
    except ValueError:
        limit = 100

    async with state_lock:
        n = now()
        suspects = []
        clean = 0
        total_allowed_identities = 0
        for key, s in ip_state.items():
            if s.allowed_count == 0:
                continue
            total_allowed_identities += 1
            score, comps, mets = _stealth_score(s)
            if score < min_score:
                clean += 1
                continue
            suspects.append({
                "id": key,
                "ip": s.last_ip or key,
                "session": s.last_session,
                "fingerprint": s.last_fingerprint,
                "ua": s.last_user_agent,
                "last_path": s.last_path,
                "last_seen_secs_ago": round(n - s.last_seen, 1),
                "first_seen_secs_ago": round(n - s.first_seen, 1),
                "requests": s.request_count,
                "allowed": s.allowed_count,
                "blocked": s.blocked_count,
                "banned_secs": max(0, round(s.banned_until - n, 0)),
                "stealth_score": score,
                "components": comps,
                "metrics": mets,
                "recent_paths": list(s.last_allowed_paths),
            })
        suspects.sort(key=lambda r: r["stealth_score"], reverse=True)
        suspects = suspects[:limit]
        # Aggregate by score bucket for the bar chart.
        buckets = {"low(20-39)": 0, "med(40-59)": 0, "high(60-79)": 0, "critical(80+)": 0}
        for r in suspects:
            sc = r["stealth_score"]
            if sc >= 80:   buckets["critical(80+)"] += 1
            elif sc >= 60: buckets["high(60-79)"] += 1
            elif sc >= 40: buckets["med(40-59)"] += 1
            else:          buckets["low(20-39)"] += 1

    return web.json_response({
        "summary": {
            "total_with_allowed": total_allowed_identities,
            "suspicious": len(suspects),
            "clean": clean,
            "min_score": min_score,
        },
        "buckets": buckets,
        "suspects": suspects,
    }, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


AGENTS_DASHBOARD_HTML  = (_DASHBOARDS_DIR / "agents.html").read_text(encoding="utf-8")

async def agents_dashboard_endpoint(request: web.Request):
    # Pre-fill the admin key into the in-page links so navigation keeps auth.
    key = request.query.get("key", "") or request.headers.get("X-Admin-Key", "")
    body = AGENTS_DASHBOARD_HTML.replace("__KEY__",
        key.replace("&","").replace("<","").replace(">","").replace('"',"")[:64])
    return web.Response(
        text=body, content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'"
            ),
        },
    )


# ── Service-metrics dashboard endpoints (admin-gated) ───────────────────
async def service_metrics_data_endpoint(request: web.Request):
    """JSON: latest sample + a windowed view of the retention buffer.
    Query params (all optional):
      ?range=N    — window length in minutes (5..720, default 60)
      ?bucket=S   — bucket width in seconds (5,30,60,300,900,3600 — default 5)
      ?end=EPOCH  — right edge of the window (default = now / live)
    Samples within each bucket are averaged for cpu/mem/disk pct, max'd for
    counters (procs/fds/db_size), summed for net throughput."""
    raw = list(SERVICE_METRICS_HISTORY)
    current = raw[-1] if raw else {}

    try:
        range_min = max(1, min(720, int(request.query.get("range", "60"))))
    except ValueError:
        range_min = 60
    try:
        bucket_secs = int(request.query.get("bucket",
                                            str(int(SERVICE_METRICS_INTERVAL))))
        if bucket_secs not in (5, 30, 60, 300, 900, 3600):
            bucket_secs = int(SERVICE_METRICS_INTERVAL) or 5
    except ValueError:
        bucket_secs = int(SERVICE_METRICS_INTERVAL) or 5
    try:
        end_epoch = float(request.query.get("end", str(_t.time())))
    except ValueError:
        end_epoch = _t.time()

    end_b   = (int(end_epoch) // bucket_secs) * bucket_secs
    window  = range_min * 60
    start_b = end_b - window + bucket_secs

    # Bucketise: average pcts/loads, max for counters, sum/per-window for net.
    AVG_KEYS  = ("cpu_pct", "mem_pct", "swap_used", "load1", "load5", "load15",
                 "disk_pct", "cg_pct", "mem_used", "disk_used")
    MAX_KEYS  = ("procs", "open_fds", "db_db", "db_wal", "db_shm", "db_total",
                 "cg_used", "cg_limit", "mem_total", "disk_total", "disk_avail",
                 "swap_total")
    SUM_KEYS  = ("net_rx_bps", "net_tx_bps")

    buckets = {}
    for s in raw:
        ts = int(s.get("ts", 0))
        if ts < start_b or ts > end_b + bucket_secs:
            continue
        b = (ts // bucket_secs) * bucket_secs
        slot = buckets.setdefault(b, {"_n": 0, "ts": b})
        slot["_n"] += 1
        for k in AVG_KEYS + MAX_KEYS + SUM_KEYS:
            v = s.get(k, 0)
            if k in MAX_KEYS:
                slot[k] = max(slot.get(k, v), v)
            else:
                slot[k] = slot.get(k, 0) + v

    history = []
    for b in range(start_b, end_b + 1, bucket_secs):
        slot = buckets.get(b)
        if not slot:
            history.append({"ts": b, **{k: 0 for k in AVG_KEYS + MAX_KEYS + SUM_KEYS}})
            continue
        n = slot.pop("_n") or 1
        out = {"ts": b}
        for k in AVG_KEYS:
            out[k] = round(slot.get(k, 0) / n, 2)
        for k in MAX_KEYS:
            out[k] = slot.get(k, 0)
        for k in SUM_KEYS:
            out[k] = round(slot.get(k, 0) / n)   # avg per second within bucket
        history.append(out)

    async with state_lock:
        identities = len(ip_state)
        ip_buckets_n = len(ip_buckets)
    app_info = {
        "uptime_secs":     int(_t.time() - START_EPOCH),
        "total_requests":  metrics["total_requests"],
        "allowed":         metrics["allowed"],
        "blocked":         metrics["blocked"],
        "identities":      identities,
        "ip_buckets":      ip_buckets_n,
        "events_buffered": len(events),
        "version":         "AppSecGW_1.4.6",
    }
    return web.json_response({
        "current":          current,
        "history":          history,
        "app":              app_info,
        "interval_secs":    SERVICE_METRICS_INTERVAL,
        "range_min":        range_min,
        "bucket_secs":      bucket_secs,
        "end_epoch":        end_b,
        "is_live":          end_epoch >= _t.time() - 30,
        "samples_in_buffer": len(raw),
        "buffer_oldest_ts": raw[0]["ts"] if raw else 0,
    }, headers={"Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff"})


SERVICE_DASHBOARD_HTML = (_DASHBOARDS_DIR / "service.html").read_text(encoding="utf-8")

async def service_dashboard_endpoint(request: web.Request):
    return web.Response(
        text=SERVICE_DASHBOARD_HTML, content_type="text/html",
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'"
            ),
        },
    )


def make_app() -> web.Application:
    app = web.Application(middlewares=[session_cookie_finalizer, protect])
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_get("/__pow", pow_endpoint)
    app.router.add_get("/__solver", solver_endpoint)
    app.router.add_get("/__status", status_endpoint)
    app.router.add_get("/__dashboard", dashboard_endpoint)
    app.router.add_get("/__metrics", metrics_endpoint)
    app.router.add_get("/__unban", unban_endpoint)
    app.router.add_post("/__rotate-keys", rotate_keys_endpoint)
    app.router.add_get("/__agents", agents_dashboard_endpoint)
    app.router.add_get("/__agents-data", agents_data_endpoint)
    app.router.add_get("/__agents-timeline", agents_timeline_endpoint)
    app.router.add_get("/__service",      service_dashboard_endpoint)
    app.router.add_get("/__service-data", service_metrics_data_endpoint)
    app.router.add_get("/__xff", debug_xff)
    app.router.add_route("*", "/{path:.*}", proxy)
    return app

if __name__ == "__main__":
    if ADMIN_KEY_FROM_ENV:
        key_line = "supplied via ADMIN_KEY env"
    else:
        key_line = f"auto-generated; first 4 chars: {INTERNAL_KEY[:4]}***  (read /data/.admin_key)"
    print(f"  ╔══════════════════════════════════════════════════════════╗")
    print(f"  ║ AppSecGW_1.4.6    →  {UPSTREAM:<37} ║")
    print(f"  ║ Listen: http://{LISTEN_HOST}:{LISTEN_PORT}{' '*36}║")
    print(f"  ║ Internal: /__pow  /__solver  /__status  /__dashboard{' '*5}║")
    print(f"  ║ DB:    {DB_PATH:<50}║")
    print(f"  ║ Admin key: {key_line:<46}║")
    if ADMIN_ALLOWED_NETS:
        nets = ", ".join(str(n) for n in ADMIN_ALLOWED_NETS)[:46]
        print(f"  ║ Admin IPs: {nets:<46}║")
    else:
        print(f"  ║ Admin IPs: any (set ADMIN_ALLOWED_IPS to restrict)    ║")
    print(f"  ╚══════════════════════════════════════════════════════════╝")
    web.run_app(make_app(), host=LISTEN_HOST, port=LISTEN_PORT, print=None,
                keepalive_timeout=HEADERS_TIMEOUT)
