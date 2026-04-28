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

Endpoints internas (não proxiadas):
  GET /__pow      → emite um challenge para resolver
  GET /__solver   → mini JS solver que resolve o PoW automaticamente
  GET /__status   → estado do rate limiter
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
HONEYPOT_BAN_SECS = 3600    # 1 hour
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
    """)
    conn.commit()
    conn.close()

# Async DB writer queue — events are batched to avoid blocking the event loop
db_queue: asyncio.Queue = None
db_writer_task = None
prune_task = None

async def db_writer_loop():
    """Background coroutine: drains the queue and flushes to SQLite in batches."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")  # better concurrency
    conn.execute("PRAGMA synchronous=NORMAL")
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
                except Exception as e:
                    print(f"[db] write failed: {e} args={args!r}")
            conn.commit()
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
    conn.close()
    print(f"[db] loaded: {len(rows)} clients, {len(timeline)} timeline buckets, "
          f"{metrics['total_requests']} total requests")

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
            s.banned_until = n + RISK_BAN_DURATION_SECS
            triggered = True
        else:
            triggered = False
    if triggered and db_queue is not None:
        try:
            db_queue.put_nowait(("ban",
                (track_key, _t.time() + RISK_BAN_DURATION_SECS,
                 f"risk-score:{int(s.risk_score)}", _t.time())))
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
                 track_key: str = None, sid: str = "", fp: str = ""):
    """Record one request decision into global metrics + per-identity state + event log + DB.
    track_key (identity) is the primary key. ip is stored on IpState for display only.
    """
    async with state_lock:
        metrics["total_requests"] += 1
        metrics["by_status"][status] += 1
        metrics["by_path"][path] += 1
        _timeline_bump(reason)
        # Default to ip if no track_key (back-compat for internal/probe paths)
        key = track_key or ip
        s = ip_state[key]
        s.last_seen = now()
        s.last_user_agent = ua[:120]
        s.last_path = path[:120]
        s.last_ip = ip
        if sid: s.last_session = sid[:24]
        if fp:  s.last_fingerprint = fp
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
        })

# ── Silent decoy: serves upstream / contents to banned attackers ───────────
_decoy_cache = {"body": None, "ctype": None, "fetched_at": 0.0}
_DECOY_TTL = 60.0  # cache the homepage for 60s
_decoy_fetch_lock = asyncio.Lock()

async def _silent_decoy_response(ip: str, ua: str, path: str, reason: str,
                                  track_key: str = None, sid: str = "", fp: str = ""):
    """
    Stealth response for blocked clients.
    Returns upstream's `/` content as a 200 OK. The block IS still recorded
    under the hybrid identity (track_key), keyed on the cookie+fingerprint
    so a single bad actor in a NAT pool doesn't poison all peers.
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
                            _decoy_cache["fetched_at"] = n
                except Exception:
                    _decoy_cache["body"] = (
                        b"<!doctype html><html><head><title>Welcome</title></head>"
                        b"<body><h1>Welcome</h1><p>Service operational.</p></body></html>"
                    )
                    _decoy_cache["ctype"] = "text/html; charset=utf-8"
                    _decoy_cache["fetched_at"] = n
    await record(ip, ua, path, 200, reason, track_key=track_key, sid=sid, fp=fp)
    return web.Response(
        status=200,
        body=_decoy_cache["body"],
        headers={
            "Content-Type": _decoy_cache["ctype"],
            "Cache-Control": "no-store",
        },
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
    # L3+N5: reject paths/query with ANY ASCII control byte (0x00-0x1F or 0x7F).
    # CR/LF would enable header injection on legacy backends; NUL truncates
    # in C parsers; other control chars confuse normalisers. Whitespace stays
    # outside this range (0x20+) so legitimate URLs are unaffected.
    def _has_ctrl(s: str) -> bool:
        return any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)
    if _has_ctrl(request.path) or _has_ctrl(request.query_string or ""):
        return web.Response(status=400, text="bad request\n")

    # Unauthenticated liveness probe — used by the container HEALTHCHECK.
    if request.path == "/__live":
        return web.Response(text="ok",
                            headers={"Cache-Control": "no-store",
                                     "Content-Type": "text/plain; charset=utf-8"})

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
                                                "host-not-allowed")

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
        return await _silent_decoy_response(ip, ua, request.path, reason)

    # ── Hybrid identity (primary tracking key) ──
    # 'identity' = HMAC(session_cookie + browser_fingerprint) for browser flow,
    # OR HMAC(fp + ip) for cookieless scripts (still stable per device).
    identity, sid, fp, is_new_session, id_mode = get_identity(request)
    ip = get_ip(request)            # IP for session-creation guard + display
    request["_sid"]    = sid
    request["_is_new"] = is_new_session
    request["_id_mode"] = id_mode

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
                         track_key=track_key, sid=sid, fp=fp)
            return web.json_response(
                body, status=status,
                headers={**(extra_headers or {}), "Cache-Control": "no-store"},
            )
        return await _silent_decoy_response(
            ip, ua, path, reason, track_key=track_key, sid=sid, fp=fp
        )

    # 1. Banned check (per-identity, not per-IP) → SILENT decoy
    banned, remaining = await is_banned(track_key)
    if banned:
        return await _silent_decoy_response(
            ip, ua, path, "banned-silent", track_key=track_key, sid=sid, fp=fp
        )

    # 2. Honeypot → risk_score += 50 (potential ban). Silent decoy regardless.
    #    Threshold-based: at NAT-like IPs, requires accumulated badness.
    if request.path in HONEYPOT_PATHS:
        await update_risk_and_maybe_ban(track_key, "honeypot-silent", ip)
        return await _silent_decoy_response(
            ip, ua, path, "honeypot-silent", track_key=track_key, sid=sid, fp=fp
        )

    # 2b. Suspicious path PATTERN (flag-hunting, file-hunting, CTF recon).
    #     Catches /flag.txt, /myflag, /backup.sql, /id_rsa, /.git/HEAD, etc.
    if is_suspicious_path(request.path):
        await update_risk_and_maybe_ban(track_key, "suspicious-path", ip)
        return await _silent_decoy_response(
            ip, ua, path, "suspicious-path", track_key=track_key, sid=sid, fp=fp
        )

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
    await record(ip, ua, path, response.status, "",
                 track_key=track_key, sid=sid, fp=fp)
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

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AppSecGW_1.3 · Dashboard</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#c9d1d9;--dim:#8b949e;
      --green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff;--purple:#bc8cff;}
*{box-sizing:border-box;margin:0;padding:0}
body{font:13px/1.4 -apple-system,'SF Pro',ui-sans-serif,sans-serif;
     background:var(--bg);color:var(--fg);padding:14px}
h1{font-size:18px;font-weight:600;color:#fff;display:flex;align-items:center;gap:8px}
h1 .pill{font-size:10px;background:var(--green);color:#000;padding:2px 8px;border-radius:10px;font-weight:700}
h2{font-size:13px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
.grid{display:grid;gap:14px;margin-top:14px}
.row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px}
.metric{font-size:30px;font-weight:600;color:#fff;line-height:1}
.metric.allowed{color:var(--green)}
.metric.blocked{color:var(--red)}
.metric.total{color:var(--blue)}
.metric.uptime{color:var(--yellow);font-size:18px}
.metric-sub{font-size:11px;color:var(--dim);margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:12px}
table th{background:#21262d;color:var(--dim);text-align:left;padding:6px 8px;font-weight:500;
         text-transform:uppercase;letter-spacing:.5px;font-size:10px}
table td{padding:5px 8px;border-bottom:1px solid var(--line);font-family:ui-monospace,Menlo,monospace;font-size:11.5px}
.tag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;font-family:ui-monospace}
.tag.OK{background:#1f4830;color:var(--green)}
.tag.banned{background:#4a1a1a;color:var(--red)}
.tag.honeypot{background:#3d1a4a;color:var(--purple)}
.tag.ua-blocked{background:#4a3a1a;color:var(--yellow)}
.tag.rate-limit{background:#4a1a1a;color:var(--red)}
.tag.behavior{background:#1a3a4a;color:#5fb3c0}
.tag.pow-required{background:#3d1a4a;color:var(--purple)}
.tag.ua-empty{background:#4a3a1a;color:var(--yellow)}
.tag.ua-too-short{background:#4a3a1a;color:var(--yellow)}
.tag.ua-non-browser{background:#4a3a1a;color:var(--yellow)}
.tag.ai-probe{background:#3d1a4a;color:var(--purple)}
.tag.ai-headers-incomplete{background:#3d2a4a;color:#dab8ff}
.tag.ai-headers-empty{background:#3d2a4a;color:#dab8ff}
.tag.ai-enumeration{background:#4a1a3d;color:#ff8acc}
.tag.ai-no-assets{background:#4a1a3d;color:#ff8acc}
.tag.banned-silent{background:#2d1a4a;color:#a78bfa}
.tag.honeypot-silent{background:#2d1a4a;color:#a78bfa}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:4px}
.bar>div{height:100%;background:var(--blue)}
.reasons{display:grid;grid-template-columns:1fr auto;gap:4px 8px;font-size:11.5px}
.reasons .lbl{color:var(--dim)}
.reasons .val{font-family:ui-monospace;color:#fff;font-weight:600;text-align:right}
code{font-family:ui-monospace;font-size:11px;color:var(--blue)}
.dim{color:var(--dim)}
.evt{font-size:11px;display:grid;grid-template-columns:80px 90px 130px 1fr;gap:8px;
     padding:3px 6px;border-bottom:1px solid var(--line);font-family:ui-monospace;
     border-left:3px solid transparent}
.evt:nth-child(even){background:#0a0e13}
.evt.evt-ok{border-left-color:var(--green);background:rgba(63,185,80,0.06)}
.evt.evt-ok:nth-child(even){background:rgba(63,185,80,0.10)}
.evt.evt-block{border-left-color:var(--red)}
.evt.evt-warn{border-left-color:var(--yellow)}
.foot{margin-top:14px;text-align:right;font-size:10px;color:var(--dim)}
.ctrl{background:#0d1117;color:var(--fg);border:1px solid var(--line);
      border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer;
      font-family:inherit;line-height:1.4}
.ctrl:hover:not(:disabled){border-color:var(--blue);color:var(--blue)}
.ctrl:disabled{opacity:.4;cursor:not-allowed}
.ctrl-now{background:#0e2c4a;border-color:#1f5fa6;color:#79c0ff}
.ctrl-now:hover{background:#1c3d5a}
@media (max-width:900px){.row{grid-template-columns:repeat(2,1fr)}}
</style></head>
<body>
<h1>AppSecGW_1.3 &middot; Dashboard <span class="pill" id="live">● LIVE</span></h1>
<div style="font-size:12px;margin-top:6px"><a id="agents-link" style="color:var(--blue)" href="#">→ Stealth Agent Hunter (allowed-but-suspicious)</a></div>
<script>
(function(){const k=new URLSearchParams(location.search).get('key')||'';
 document.getElementById('agents-link').href='/__agents'+(k?('?key='+encodeURIComponent(k)):'');})();
</script>

<div class="grid">

  <div class="row">
    <div class="card"><h2>Total requests</h2><div class="metric total" id="total">0</div>
         <div class="metric-sub" id="rps">— req/s</div></div>
    <div class="card"><h2>Allowed</h2><div class="metric allowed" id="allowed">0</div>
         <div class="metric-sub" id="allowed-pct">—</div></div>
    <div class="card"><h2>Blocked</h2><div class="metric blocked" id="blocked">0</div>
         <div class="metric-sub" id="blocked-pct">—</div></div>
    <div class="card"><h2>Uptime</h2><div class="metric uptime" id="uptime">—</div>
         <div class="metric-sub" id="config">—</div></div>
  </div>

  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:8px">
      <h2 style="margin:0">Timeline · total / permitidas / bloqueios <span id="window-label" class="dim" style="font-size:10px;font-weight:400;text-transform:none;letter-spacing:0;margin-left:8px"></span></h2>
      <div style="display:flex;gap:6px;align-items:center;font-size:11px">
        <button id="prev"  class="ctrl">‹ back</button>
        <button id="now"   class="ctrl ctrl-now">now</button>
        <button id="next"  class="ctrl" disabled>fwd ›</button>
        <span class="dim" style="margin-left:6px">window:</span>
        <select id="range" class="ctrl">
          <option value="15">15 min</option>
          <option value="60" selected>1 h</option>
          <option value="180">3 h</option>
          <option value="360">6 h</option>
          <option value="720">12 h</option>
          <option value="1440">24 h</option>
          <option value="4320">3 days</option>
          <option value="10080">7 days</option>
        </select>
        <span class="dim" style="margin-left:6px">bucket:</span>
        <select id="bucket" class="ctrl">
          <option value="60" selected>1 min</option>
          <option value="300">5 min</option>
          <option value="900">15 min</option>
          <option value="3600">1 hour</option>
          <option value="86400">1 day</option>
        </select>
      </div>
    </div>
    <div style="position:relative;height:240px">
      <canvas id="chart"></canvas>
    </div>
  </div>

  <div class="row" style="grid-template-columns:1fr 1fr">
    <div class="card">
      <h2>Block reasons</h2>
      <div class="reasons" id="reasons"><span class="dim">no blocks yet</span></div>
    </div>
    <div class="card">
      <h2>HTTP status distribution</h2>
      <div class="reasons" id="statuses"></div>
    </div>
  </div>

  <div class="card">
    <h2>Clients (top by request count)</h2>
    <table id="clients-tbl">
      <thead><tr>
        <th>Identity</th><th>Last IP</th><th>Total</th><th>Allowed</th><th>Blocked</th>
        <th>Risk</th><th>Banned</th><th>Tokens</th><th>Last seen</th><th>Last UA</th><th>Last path</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </div>

  <div class="row" style="grid-template-columns:1fr 1fr">
    <div class="card">
      <h2>Top paths</h2>
      <table id="paths-tbl"><thead><tr><th>Path</th><th>Hits</th></tr></thead><tbody></tbody></table>
    </div>
    <div class="card">
      <h2>Live events (last 50)</h2>
      <div id="events"></div>
    </div>
  </div>

</div>

<div class="foot">refreshes every 2s · <code id="ts"></code></div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
        integrity="sha384-e6nUZLBkQ86NJ6TVVKAeSaK8jWa3NhkYWZFomE39AvDbQWeie9PlQqM3pmYW5d1g"
        crossorigin="anonymous"
        referrerpolicy="no-referrer"></script>
<script>
let lastTotal = 0, lastTime = Date.now();
let chart = null;

function getRangeMin() {
  return parseInt(document.getElementById('range').value || '60', 10);
}

function fmtTime(epochSec) {
  const d = new Date(epochSec * 1000);
  return d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0');
}

function ensureChart() {
  if (chart) return chart;
  const ctx = document.getElementById('chart').getContext('2d');
  chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'total', data: [], borderColor: '#58a6ff',
          backgroundColor: 'rgba(88,166,255,0.06)', tension: 0.25, fill: false,
          borderWidth: 2, pointRadius: 0, pointHoverRadius: 4 },
        { label: 'permitidas (good)', data: [], borderColor: '#3fb950',
          backgroundColor: 'rgba(63,185,80,0.18)', tension: 0.25, fill: true,
          borderWidth: 2, pointRadius: 0, pointHoverRadius: 4 },
        { label: 'bloqueios', data: [], borderColor: '#f85149',
          backgroundColor: 'rgba(248,81,73,0.18)', tension: 0.25, fill: true,
          borderWidth: 2, pointRadius: 0, pointHoverRadius: 4 },
      ],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      animation: { duration: 250 },
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { labels: { color: '#c9d1d9', font: { size: 11 } } },
        tooltip: {
          backgroundColor: '#161b22', borderColor: '#30363d', borderWidth: 1,
          titleColor: '#c9d1d9', bodyColor: '#c9d1d9',
          callbacks: { title: items => items[0].label }
        },
      },
      scales: {
        x: { ticks: { color: '#8b949e', font: { size: 10 }, maxRotation: 0, autoSkipPadding: 18 },
             grid: { color: '#21262d' } },
        y: { beginAtZero: true, ticks: { color: '#8b949e', font: { size: 10 }, precision: 0 },
             grid: { color: '#21262d' } },
      },
    },
  });
  return chart;
}

// Forward the admin key to subsequent /__metrics calls so the dashboard works
// when accessed via the protected URL (?key=...)
const ADMIN_KEY = new URLSearchParams(location.search).get('key') || '';

// Timeline navigation state
let endEpoch = null;   // null = live (now); number = scrolled-back epoch (right edge of window)

function getRangeMin() { return parseInt(document.getElementById('range').value || '60', 10); }
function getBucketSec() { return parseInt(document.getElementById('bucket').value || '60', 10); }

function fmtTime(epochSec, bucketSec) {
  const d = new Date(epochSec * 1000);
  if (bucketSec >= 86400) {
    return d.toLocaleDateString(undefined, {month:'short', day:'numeric'});
  } else if (bucketSec >= 3600) {
    return d.toLocaleString(undefined, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
  }
  return d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0');
}

document.getElementById('prev').onclick = () => {
  const win = getRangeMin() * 60;
  const cur = endEpoch || Math.floor(Date.now()/1000);
  endEpoch = cur - win;
  refreshControls(); tick();
};
document.getElementById('next').onclick = () => {
  if (!endEpoch) return;
  const win = getRangeMin() * 60;
  endEpoch = endEpoch + win;
  if (endEpoch > Math.floor(Date.now()/1000)) endEpoch = null;
  refreshControls(); tick();
};
document.getElementById('now').onclick = () => { endEpoch = null; refreshControls(); tick(); };

function refreshControls() {
  document.getElementById('next').disabled = (endEpoch === null);
  document.getElementById('now').disabled  = (endEpoch === null);
  const lbl = document.getElementById('window-label');
  if (endEpoch === null) {
    lbl.textContent = '(live)';
    lbl.style.color = 'var(--green)';
  } else {
    const win = getRangeMin();
    const start = new Date((endEpoch - win*60) * 1000);
    const end   = new Date(endEpoch * 1000);
    const fmt = d => d.toLocaleString(undefined, {
      month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'
    });
    lbl.textContent = `${fmt(start)} → ${fmt(end)} (paused)`;
    lbl.style.color = 'var(--yellow)';
  }
}
refreshControls();

async function tick() {
  try {
    const params = new URLSearchParams({
      range:  getRangeMin().toString(),
      bucket: getBucketSec().toString(),
    });
    if (endEpoch !== null) params.set('end', endEpoch.toString());
    if (ADMIN_KEY) params.set('key', ADMIN_KEY);
    const r = await fetch('/__metrics?' + params.toString(), {cache: 'no-store', credentials: 'include'});
    const d = await r.json();
    document.getElementById('live').style.background='var(--green)';
    document.getElementById('live').textContent='● LIVE';

    document.getElementById('total').textContent = d.total.toLocaleString();
    document.getElementById('allowed').textContent = d.allowed.toLocaleString();
    document.getElementById('blocked').textContent = d.blocked.toLocaleString();
    const totalPct = d.total ? ((d.allowed/d.total)*100).toFixed(1) : 0;
    document.getElementById('allowed-pct').textContent = `${totalPct}% pass-through`;
    document.getElementById('blocked-pct').textContent = d.total ? `${(100-totalPct).toFixed(1)}% rejected` : '—';

    // RPS over last 2s
    const now = Date.now();
    const dt = (now - lastTime) / 1000;
    const rps = dt > 0 ? ((d.total - lastTotal) / dt).toFixed(1) : '0.0';
    document.getElementById('rps').textContent = `${rps} req/s (last 2s)`;
    lastTotal = d.total; lastTime = now;

    const h = Math.floor(d.uptime_secs/3600), m = Math.floor((d.uptime_secs%3600)/60), s = d.uptime_secs%60;
    document.getElementById('uptime').textContent = `${h}h ${m}m ${s}s`;
    const c = d.config;
    document.getElementById('config').textContent = `burst=${c.burst} refill=${c.refill}/s xff=${c.trust_xff}`;

    // Reasons
    const reasonOrder = ['banned-silent','honeypot-silent','banned','honeypot',
                         'ua-empty','ua-too-short','ua-blocked','ua-non-browser',
                         'ai-probe','ai-headers-incomplete','ai-headers-empty',
                         'ai-enumeration','ai-no-assets',
                         'rate-limit','behavior','pow-required'];
    const reasons = d.by_reason || {};
    const rEl = document.getElementById('reasons');
    if (Object.keys(reasons).length === 0) {
      rEl.innerHTML = '<span class="dim">no blocks yet</span>';
    } else {
      rEl.innerHTML = reasonOrder.filter(k => reasons[k])
        .map(k => `<span class="lbl"><span class="tag ${safeClass(k)}">${escapeHtml(k)}</span></span><span class="val">${reasons[k]|0}</span>`).join('');
    }

    // Statuses
    const statuses = d.by_status || {};
    const sEl = document.getElementById('statuses');
    sEl.innerHTML = Object.entries(statuses).sort()
      .map(([k,v]) => `<span class="lbl">HTTP ${k}</span><span class="val">${v}</span>`).join('');

    // Clients
    const tbody = document.querySelector('#clients-tbl tbody');
    tbody.innerHTML = (d.clients || []).slice(0, 25).map(c => {
      const banned = c.banned_secs > 0 ? `<span class="tag banned">${c.banned_secs}s</span>` : '<span class="dim">—</span>';
      const id = (c.id || c.ip || '');
      const lastIp = c.last_ip || '?';
      const risk = c.risk_score || 0;
      const riskColor = risk >= 50 ? 'var(--red)' : risk >= 25 ? 'var(--yellow)' : 'var(--dim)';
      return `<tr>
        <td title="${escapeHtml(id)}"><b>${escapeHtml(id.slice(0,16))}</b></td>
        <td class="dim">${escapeHtml(lastIp)}</td>
        <td>${c.requests}</td>
        <td style="color:var(--green)">${c.allowed}</td>
        <td style="color:${c.blocked?'var(--red)':'var(--dim)'}">${c.blocked}</td>
        <td style="color:${riskColor};font-weight:600">${risk.toFixed(1)}</td>
        <td>${banned}</td>
        <td>${c.tokens}</td>
        <td class="dim">${c.last_seen_secs_ago}s ago</td>
        <td class="dim" title="${escapeHtml(c.last_ua)}">${escapeHtml((c.last_ua||'').slice(0,30))}</td>
        <td class="dim">${escapeHtml((c.last_path||'').slice(0,30))}</td>
      </tr>`;
    }).join('') || '<tr><td colspan=11 class=dim style="text-align:center;padding:14px">no clients yet</td></tr>';

    // Top paths
    const pBody = document.querySelector('#paths-tbl tbody');
    pBody.innerHTML = (d.top_paths || []).map(p =>
      `<tr><td>${escapeHtml(p.path)}</td><td>${p.count}</td></tr>`
    ).join('') || '<tr><td colspan=2 class=dim style="text-align:center;padding:14px">no traffic yet</td></tr>';

    // Events
    const eEl = document.getElementById('events');
    eEl.innerHTML = (d.events || []).map(e => {
      const time = new Date(e.ts*1000).toTimeString().split(' ')[0];
      const isOk = (e.reason === 'OK' || e.reason === '');
      const evtCls = isOk ? 'evt-ok' : (e.reason === 'rate-limit' || e.reason === 'rate-limit-ip') ? 'evt-warn' : 'evt-block';
      return `<div class="evt ${evtCls}">
        <span class="dim">${escapeHtml(time)}</span>
        <span><span class="tag ${safeClass(e.reason)}">${escapeHtml(isOk ? 'OK' : e.reason)}</span></span>
        <span>${escapeHtml(e.ip)}</span>
        <span class="dim">${escapeHtml((e.path||'').slice(0,40))}</span>
      </div>`;
    }).join('') || '<span class="dim">no events yet</span>';

    // Timeline chart
    if (d.timeline && d.timeline.length) {
      const c = ensureChart();
      const bucketSec = d.timeline_bucket_secs || 60;
      const labels = d.timeline.map(b => fmtTime(b.t, bucketSec));
      const totals = d.timeline.map(b => b.total);
      const allowed = d.timeline.map(b => b.allowed != null ? b.allowed : Math.max(0, (b.total||0) - (b.blocked||0)));
      const blocks = d.timeline.map(b => b.blocked);
      // Dynamic decimation: aim at ~12 labels regardless of how many points
      const step = Math.max(1, Math.floor(labels.length / 12));
      const labelsView = labels.map((l, i) => (i % step === 0 || i === labels.length-1) ? l : '');
      c.data.labels = labelsView;
      c.data.datasets[0].data = totals;
      c.data.datasets[1].data = allowed;
      c.data.datasets[2].data = blocks;
      c.update('none');
    }

    document.getElementById('ts').textContent = new Date().toISOString();
  } catch (err) {
    document.getElementById('live').style.background='var(--red)';
    document.getElementById('live').textContent='○ ERR';
  }
}
function escapeHtml(s){return (s||'').replace(/[&<>"'`/]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;','/':'&#47;'}[c]))}
function safeClass(s){return (s||'').replace(/[^a-zA-Z0-9_-]/g,'')}
document.getElementById('range').addEventListener('change', () => { refreshControls(); tick(); });
document.getElementById('bucket').addEventListener('change', tick);
tick();
// Auto-refresh — but ONLY when in live mode. When user has scrolled back,
// the data is static and refreshing would just repaint the same window.
setInterval(() => { if (endEpoch === null) tick(); }, 2000);
</script>
</body></html>
"""

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

    # H6: stream the body and bound it. Reject if larger than UPSTREAM_MAX_BODY.
    body = None
    if request.body_exists and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            chunks = []
            total = 0
            async for c in request.content.iter_any():
                total += len(c)
                if total > UPSTREAM_MAX_BODY:
                    return web.Response(status=413, text="payload too large\n")
                chunks.append(c)
            body = b"".join(chunks) if chunks else None
        except Exception:
            return web.Response(status=400, text="bad request\n")

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

                response_headers["X-Proxy"] = "AppSecGW_1.3"

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
    global db_queue, db_writer_task, prune_task
    db_init()
    db_load_state()
    db_queue = asyncio.Queue(maxsize=10000)
    db_writer_task = asyncio.create_task(db_writer_loop())
    prune_task = asyncio.create_task(_prune_state_loop())
    print(f"[db] persistence active → {DB_PATH}")

async def on_cleanup(app):
    """Flush queue and close DB writer cleanly."""
    global prune_task
    if prune_task:
        prune_task.cancel()
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


AGENTS_DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AppSecGW · Stealth Agent Hunter</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#c9d1d9;--dim:#8b949e;
      --green:#3fb950;--red:#f85149;--yellow:#d29922;--blue:#58a6ff;--purple:#bc8cff;--orange:#ff7b3a;}
*{box-sizing:border-box;margin:0;padding:0}
body{font:13px/1.4 -apple-system,'SF Pro',ui-sans-serif,sans-serif;
     background:var(--bg);color:var(--fg);padding:14px}
h1{font-size:18px;font-weight:600;color:#fff;display:flex;align-items:center;gap:8px}
h1 .pill{font-size:10px;background:var(--orange);color:#000;padding:2px 8px;border-radius:10px;font-weight:700}
h2{font-size:13px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px}
.grid{display:grid;gap:14px;margin-top:14px}
.row{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px}
.metric{font-size:30px;font-weight:600;color:#fff;line-height:1}
.metric.crit{color:var(--red)}
.metric.high{color:var(--orange)}
.metric.med{color:var(--yellow)}
.metric.low{color:var(--blue)}
.metric-sub{font-size:11px;color:var(--dim);margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:12px}
table th{background:#21262d;color:var(--dim);text-align:left;padding:6px 8px;font-weight:500;
         text-transform:uppercase;letter-spacing:.5px;font-size:10px}
table td{padding:5px 8px;border-bottom:1px solid var(--line);font-family:ui-monospace,Menlo,monospace;font-size:11.5px;vertical-align:top}
.bar{height:10px;background:#0a0e13;border-radius:4px;overflow:hidden;display:flex}
.bar>div{height:100%}
.bar .h{background:#a78bfa}
.bar .a{background:#5fb3c0}
.bar .e{background:#3fb950}
.bar .t{background:#d29922}
.bar .r{background:#f85149}
.bar .f{background:#ff7b3a}
.tag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;font-family:ui-monospace}
.tag.crit{background:#4a1a1a;color:var(--red)}
.tag.high{background:#3d2a1a;color:var(--orange)}
.tag.med{background:#4a3a1a;color:var(--yellow)}
.tag.low{background:#1a3a4a;color:var(--blue)}
.dim{color:var(--dim)}
.ctrl{background:#0d1117;color:var(--fg);border:1px solid var(--line);
      border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer;font-family:inherit}
.foot{margin-top:14px;text-align:right;font-size:10px;color:var(--dim)}
.expand{cursor:pointer;color:var(--blue)}
.detail{display:none;background:#0a0e13;border-left:3px solid var(--orange);padding:8px 12px}
.detail.show{display:block}
.path-row{font-family:ui-monospace;font-size:11px;color:var(--dim);padding:2px 0}
.nav{display:flex;gap:14px;margin-top:8px;font-size:12px}
.nav a{color:var(--blue);text-decoration:none}
.nav a:hover{text-decoration:underline}
</style></head>
<body>
<h1>AppSecGW · Stealth Agent Hunter <span class="pill" id="live">● LIVE</span></h1>
<div class="nav">
  <a href="/__dashboard?key=__KEY__">← main dashboard</a>
  <span class="dim">|</span>
  <a href="/__agents?key=__KEY__">stealth agents (this page)</a>
</div>

<div class="grid">

  <div class="row">
    <div class="card"><h2>Identities w/ allowed traffic</h2>
         <div class="metric low" id="m-total">0</div>
         <div class="metric-sub">total ever passed gate</div></div>
    <div class="card"><h2>Suspicious now</h2>
         <div class="metric high" id="m-susp">0</div>
         <div class="metric-sub" id="m-susp-pct">—</div></div>
    <div class="card"><h2>Critical (≥80)</h2>
         <div class="metric crit" id="m-crit">0</div>
         <div class="metric-sub">strong stealth signals</div></div>
    <div class="card"><h2>Threshold</h2>
         <div class="metric med" id="m-thresh">20</div>
         <div class="metric-sub">
           <input id="thresh-input" type="number" min="0" max="100" value="20"
                  class="ctrl" style="width:60px"> apply</div></div>
  </div>

  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:8px">
      <h2 style="margin:0">Detection vs Miss · Timeline</h2>
      <div style="display:flex;gap:6px;align-items:center;font-size:11px">
        <span class="dim">window:</span>
        <select id="t-range" class="ctrl">
          <option value="15">15 min</option>
          <option value="60" selected>1 h</option>
          <option value="180">3 h</option>
          <option value="720">12 h</option>
          <option value="1440">24 h</option>
          <option value="10080">7 days</option>
        </select>
        <span class="dim">bucket:</span>
        <select id="t-bucket" class="ctrl">
          <option value="60" selected>1 min</option>
          <option value="300">5 min</option>
          <option value="900">15 min</option>
          <option value="3600">1 hour</option>
          <option value="86400">1 day</option>
        </select>
        <span class="dim" id="t-totals"></span>
      </div>
    </div>
    <div style="position:relative;height:240px"><canvas id="agent-chart"></canvas></div>
    <div class="dim" style="font-size:11px;margin-top:6px">
      <span style="color:var(--red)">●</span> detected = blocked because tripped an agent layer
      &nbsp;·&nbsp; <span style="color:var(--orange)">●</span> missed = allowed but identity now scores ≥ threshold
      &nbsp;·&nbsp; <span style="color:var(--green)">●</span> clean = allowed, no stealth signal
    </div>
  </div>

  <div class="card">
    <h2>Score distribution among allowed identities</h2>
    <div id="dist"></div>
  </div>

  <div class="card">
    <h2>Suspicious agents (passed all blocks but exhibit stealth signals)</h2>
    <table id="sus-tbl">
      <thead><tr>
        <th>Score</th><th>Identity</th><th>UA</th><th>IP</th>
        <th>Allowed</th><th>Blocked</th><th>Headers avg</th>
        <th>HTML/Static</th><th>Paths/req</th><th>Timing σ/μ</th>
        <th>404s</th><th>Risk</th><th>Last path</th><th></th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </div>

</div>

<div class="foot">refreshes every 3 s · <code id="ts"></code></div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
        integrity="sha384-e6nUZLBkQ86NJ6TVVKAeSaK8jWa3NhkYWZFomE39AvDbQWeie9PlQqM3pmYW5d1g"
        crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script>
const ADMIN_KEY = new URLSearchParams(location.search).get('key') || '';
function escapeHtml(s){return (s||'').replace(/[&<>"'`/]/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;','/':'&#47;'}[c]))}
function bandClass(s){return s>=80?'crit':s>=60?'high':s>=40?'med':'low'}

let MIN = 20;
document.getElementById('thresh-input').addEventListener('change', e=>{
  MIN = Math.max(0, Math.min(100, parseInt(e.target.value)||20));
  document.getElementById('m-thresh').textContent = MIN; tick();
});

async function tick(){
  try{
    const params = new URLSearchParams({min_score: MIN, limit: 200});
    if (ADMIN_KEY) params.set('key', ADMIN_KEY);
    const r = await fetch('/__agents-data?' + params, {cache:'no-store', credentials:'include'});
    const d = await r.json();
    document.getElementById('live').textContent='● LIVE';
    document.getElementById('live').style.background='var(--orange)';

    const sum = d.summary;
    document.getElementById('m-total').textContent = sum.total_with_allowed;
    document.getElementById('m-susp').textContent  = sum.suspicious;
    const pct = sum.total_with_allowed
      ? ((sum.suspicious/sum.total_with_allowed)*100).toFixed(1) + '% of allowed'
      : '—';
    document.getElementById('m-susp-pct').textContent = pct;
    const crits = d.suspects.filter(s=>s.stealth_score>=80).length;
    document.getElementById('m-crit').textContent = crits;
    document.getElementById('m-thresh').textContent = sum.min_score;

    // Distribution bars
    const dist = d.buckets;
    const total = Math.max(1, Object.values(dist).reduce((a,b)=>a+b,0));
    const distEl = document.getElementById('dist');
    distEl.innerHTML = Object.entries(dist).map(([k,v])=>{
      const pct=(v/total*100).toFixed(1);
      const cls = k.startsWith('crit')?'crit':k.startsWith('high')?'high':k.startsWith('med')?'med':'low';
      return `<div style="display:grid;grid-template-columns:120px 1fr 50px;gap:8px;align-items:center;margin:4px 0">
        <span class="tag ${cls}">${escapeHtml(k)}</span>
        <div class="bar"><div class="${cls=='crit'?'r':cls=='high'?'f':cls=='med'?'t':'a'}" style="width:${pct}%"></div></div>
        <span class="dim" style="text-align:right">${v}</span></div>`;
    }).join('');

    // Suspect table
    const tbody = document.querySelector('#sus-tbl tbody');
    if (!d.suspects.length){
      tbody.innerHTML = `<tr><td colspan=14 class=dim style="text-align:center;padding:14px">no suspicious agents at threshold ${MIN}</td></tr>`;
    } else {
      tbody.innerHTML = d.suspects.map((s,i)=>{
        const m = s.metrics, c = s.components;
        const compBar = `<div class="bar" title="headers:${c.headers} assets:${c.assets} enum:${c.enum} timing:${c.timing} risk:${c.risk} 404s:${c['404s']}">
          <div class="h" style="width:${c.headers}%"></div>
          <div class="a" style="width:${c.assets}%"></div>
          <div class="e" style="width:${c.enum}%"></div>
          <div class="t" style="width:${c.timing}%"></div>
          <div class="r" style="width:${c.risk}%"></div>
          <div class="f" style="width:${c['404s']}%"></div></div>`;
        const recentRows = (s.recent_paths||[]).slice(-5).reverse().map(p=>
          `<div class="path-row">${new Date(p.ts*1000).toLocaleTimeString()} · ${p.status} · ${escapeHtml(p.path)} · hdr=${p.header_score}</div>`
        ).join('') || '<span class=dim>—</span>';
        return `
          <tr>
            <td><span class="tag ${bandClass(s.stealth_score)}">${s.stealth_score}</span>${compBar}</td>
            <td title="${escapeHtml(s.id)}"><b>${escapeHtml((s.id||'').slice(0,12))}</b><div class="dim">${m.samples} samples</div></td>
            <td title="${escapeHtml(s.ua)}">${escapeHtml((s.ua||'').slice(0,40))}</td>
            <td>${escapeHtml(s.ip)}</td>
            <td style="color:var(--green)">${s.allowed}</td>
            <td style="color:${s.blocked?'var(--red)':'var(--dim)'}">${s.blocked}</td>
            <td>${m.avg_header_score}/7</td>
            <td>${m.html_loads}/${m.static_loads}</td>
            <td>${m.unique_paths}/${s.allowed} (${m.path_diversity})</td>
            <td>${m.behavioral_cov!==null?m.behavioral_cov:'—'}</td>
            <td style="color:${m.upstream_404_count>5?'var(--red)':'var(--dim)'}">${m.upstream_404_count}</td>
            <td>${m.risk_score}</td>
            <td class="dim">${escapeHtml((s.last_path||'').slice(0,30))}</td>
            <td><span class="expand" data-i="${i}">▸ paths</span></td>
          </tr>
          <tr id="d-${i}" class="detail-row" style="display:none"><td colspan=14>
            <div class="detail show"><b>Recent allowed paths</b>${recentRows}</div></td></tr>`;
      }).join('');
      tbody.querySelectorAll('.expand').forEach(el=>el.onclick=()=>{
        const r = document.getElementById('d-'+el.dataset.i);
        r.style.display = (r.style.display==='none')?'table-row':'none';
      });
    }
    document.getElementById('ts').textContent = new Date().toISOString();
  }catch(e){
    document.getElementById('live').style.background='var(--red)';
    document.getElementById('live').textContent='○ ERR';
  }
}
// Detection-vs-miss timeline chart
let agentChart = null;
function ensureAgentChart(){
  if (agentChart) return agentChart;
  const ctx = document.getElementById('agent-chart').getContext('2d');
  agentChart = new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets: [
      { label:'detected (blocked agent)', data:[], borderColor:'#f85149',
        backgroundColor:'rgba(248,81,73,0.20)', tension:0.25, fill:true,
        borderWidth:2, pointRadius:0, pointHoverRadius:4 },
      { label:'missed (allowed but stealth)', data:[], borderColor:'#ff7b3a',
        backgroundColor:'rgba(255,123,58,0.18)', tension:0.25, fill:true,
        borderWidth:2, pointRadius:0, pointHoverRadius:4 },
      { label:'clean allowed', data:[], borderColor:'#3fb950',
        backgroundColor:'rgba(63,185,80,0.10)', tension:0.25, fill:true,
        borderWidth:2, pointRadius:0, pointHoverRadius:4 },
    ]},
    options: { responsive:true, maintainAspectRatio:false,
      animation:{duration:200}, interaction:{mode:'index',intersect:false},
      plugins:{ legend:{ labels:{ color:'#c9d1d9', font:{size:11} } } },
      scales:{
        x:{ ticks:{color:'#8b949e',font:{size:10},maxRotation:0,autoSkipPadding:18}, grid:{color:'#21262d'} },
        y:{ beginAtZero:true, ticks:{color:'#8b949e',font:{size:10},precision:0}, grid:{color:'#21262d'} } } }
  });
  return agentChart;
}
function fmtTimeBucket(epochSec, bucketSec){
  const d = new Date(epochSec*1000);
  if (bucketSec >= 86400) return d.toLocaleDateString(undefined,{month:'short',day:'numeric'});
  if (bucketSec >= 3600)  return d.toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
  return d.getHours().toString().padStart(2,'0')+':'+d.getMinutes().toString().padStart(2,'0');
}
async function tickChart(){
  try{
    const params = new URLSearchParams({
      range: document.getElementById('t-range').value,
      bucket: document.getElementById('t-bucket').value,
      min_score: MIN,
    });
    if (ADMIN_KEY) params.set('key', ADMIN_KEY);
    const r = await fetch('/__agents-timeline?'+params, {cache:'no-store', credentials:'include'});
    const d = await r.json();
    const c = ensureAgentChart();
    const bs = d.bucket_secs || 60;
    const labels = d.timeline.map(b=>fmtTimeBucket(b.t, bs));
    const step = Math.max(1, Math.floor(labels.length/12));
    c.data.labels = labels.map((l,i)=>(i%step===0||i===labels.length-1)?l:'');
    c.data.datasets[0].data = d.timeline.map(b=>b.detected);
    c.data.datasets[1].data = d.timeline.map(b=>b.missed);
    c.data.datasets[2].data = d.timeline.map(b=>b.clean_allowed);
    c.update('none');
    const t = d.totals;
    document.getElementById('t-totals').textContent =
      `· Σ detected=${t.detected} missed=${t.missed} clean=${t.clean_allowed} · stealth IPs=${d.stealth_ips_count}`;
  }catch(e){}
}
document.getElementById('t-range').addEventListener('change', tickChart);
document.getElementById('t-bucket').addEventListener('change', tickChart);

tick(); tickChart();
setInterval(tick, 3000);
setInterval(tickChart, 5000);
</script>
</body></html>
"""

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
    app.router.add_get("/__agents", agents_dashboard_endpoint)
    app.router.add_get("/__agents-data", agents_data_endpoint)
    app.router.add_get("/__agents-timeline", agents_timeline_endpoint)
    app.router.add_get("/__xff", debug_xff)
    app.router.add_route("*", "/{path:.*}", proxy)
    return app

if __name__ == "__main__":
    if ADMIN_KEY_FROM_ENV:
        key_line = "supplied via ADMIN_KEY env"
    else:
        key_line = f"auto-generated; first 4 chars: {INTERNAL_KEY[:4]}***  (read /data/.admin_key)"
    print(f"  ╔══════════════════════════════════════════════════════════╗")
    print(f"  ║ AppSecGW_1.3    →  {UPSTREAM:<37} ║")
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
    web.run_app(make_app(), host=LISTEN_HOST, port=LISTEN_PORT, print=None)
