"""
config.py — All module-level constants, env vars, and key loading functions.
Extracted from proxy.py as part of Phase 1 modular refactoring.

Dependency rule: imports ONLY stdlib (os, re, pathlib, time, etc.) — NO project imports.
"""

import asyncio
import hashlib
import hmac
import json
import fnmatch as _fnmatch
import random
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict

import aiohttp
from aiohttp import web, ClientSession, ClientTimeout

GW_VERSION = "AppSecGW_1.8.1"

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

RATE_LIMIT_BURST  = int(os.environ.get("BURST", "20"))    # tokens
RATE_LIMIT_REFILL = max(0.001, float(os.environ.get("REFILL", "3.0")))  # tokens / second; guarded against div-by-zero
HONEYPOT_BAN_SECS = int(os.environ.get("HONEYPOT_BAN_SECS", "3600"))  # 1 h default
# R8: longer-TTL "hostile pool" — once an identity has crossed the
# canary-echo / honeypot threshold, keep it silent-decoyed for HOSTILE_BAN_SECS
# (default 24 h). Generic bans stay at HONEYPOT_BAN_SECS; only the
# AI-agent-specific signals (canary-echo, honeypot-silent, honeypot)
# upgrade to hostile-pool duration.
HOSTILE_BAN_SECS  = int(os.environ.get("HOSTILE_BAN_SECS", "86400"))   # 24 h
# 1.7.3 — "Really Ban": definitive-proof signals (canary-echo, honeypot-silent,
# honeypot) earn a 30-day ban instead of the standard 24 h. Configurable via
# REALLY_BAN_SECS env var or the Controls dashboard Thresholds card.
REALLY_BAN_SECS   = int(os.environ.get("REALLY_BAN_SECS", "2592000"))  # 30 d
# 1.5.1 — operator-controlled global throughput limit. When > 0, ANY request
# arriving while the rolling 1-second count exceeds this value is silent-
# decoyed with reason `traffic-threshold`. Hot-reloadable via /__config or
# the main dashboard's threshold slider. Default 0 = disabled (no global cap;
# per-identity / per-socket-IP buckets still apply).
GLOBAL_RPS_LIMIT = int(os.environ.get("GLOBAL_RPS_LIMIT", "0"))

# ── AWS ELB / ALB health check pass-through ──────────────────────────────────
# ELB-HealthChecker/2.0 sends GET <path> with minimal headers (no Accept,
# Accept-Language, Sec-Fetch-*) — this triggers ua-non-browser (25 pts) and
# ai-headers-incomplete (20 pts) on every request, banning the LB node after
# two hits and causing the target to be marked unhealthy.
#
# Bypass fires when BOTH path AND UA prefix match.  Default path is "/" because
# AWS ALB/NLB health checks hit the root by default.  Operators may override
# with ELB_HEALTH_CHECK_PATH to match a custom target-group health-check path.
# Set ELB_HEALTH_CHECK_UA="" to disable the bypass entirely.
#
# Security properties:
#   • Path + UA must both match — neither alone is sufficient.
#   • ELB health check IPs live inside the VPC (private range) so they arrive
#     via the trusted-proxy chain; external IP spoofing is blocked upstream.
#   • The path is never leaked in responses or logs (only the path hash is
#     logged to prevent the value from appearing in log-aggregation tools).
_elb_raw = os.environ.get("ELB_HEALTH_CHECK_PATH", "/").strip()
ELB_HEALTH_CHECK_PATH = (_elb_raw.rstrip("/") or "/")   # preserve "/" as-is
ELB_HEALTH_CHECK_UA   = os.environ.get("ELB_HEALTH_CHECK_UA",   "ELB-HealthChecker").strip()

# ── Authorized monitoring bot pass-through ────────────────────────────────────
# Each entry: {"name":str, "ua":str, "path":str, "ips":[str], "action":str, "enabled":bool}
# ua substring must appear in User-Agent; path must match exactly; ips (when
# non-empty) restrict which source IPs qualify. action: authorized-robot (default,
# returns 200 blue), allow (pass-through silently), ban / really-ban.
# Stored as JSON. Legacy "UA:path" CSV auto-migrated. Hot-reloadable.

def _parse_authorized_bot_uas(raw) -> list:
    """Parse AUTHORIZED_BOT_UAS — JSON array of dicts or legacy UA:path CSV."""
    if isinstance(raw, list):
        result = []
        for e in raw:
            if not isinstance(e, dict):
                continue
            result.append({
                "name":    str(e.get("name", e.get("ua", ""))).strip(),
                "ua":      str(e.get("ua", "")).strip(),
                "path":    str(e.get("path", "/")).strip() or "/",
                "ips":     [str(ip).strip() for ip in e.get("ips", []) if str(ip).strip()],
                "action":  str(e.get("action", "authorized-robot")).strip().lower(),
                "enabled": bool(e.get("enabled", True)),
            })
        return result
    s = str(raw).strip()
    if not s:
        return []
    if s.startswith('['):
        try:
            return _parse_authorized_bot_uas(json.loads(s))
        except Exception:
            pass  # nosec B110 — malformed JSON falls through to legacy CSV path below
    # Legacy CSV: "UA:path" or bare "UA"
    result = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        colon = part.find(":")
        if colon > 0:
            ua, path = part[:colon].strip(), part[colon + 1:].strip() or "/"
        else:
            ua, path = part, "/"
        if ua:
            result.append({"name": ua, "ua": ua, "path": path, "ips": [],
                           "action": "authorized-robot", "enabled": True})
    return result

_bot_uas_raw = os.environ.get(
    "AUTHORIZED_BOT_UAS",
    '[{"name":"UptimeRobot","ua":"UptimeRobot","path":"/","ips":[],"action":"authorized-robot","enabled":true},'
    '{"name":"Pingdom","ua":"Pingdom","path":"/","ips":[],"action":"authorized-robot","enabled":true},'
    '{"name":"StatusCake","ua":"StatusCake","path":"/","ips":[],"action":"authorized-robot","enabled":true},'
    '{"name":"Site24x7","ua":"Site24x7","path":"/","ips":[],"action":"authorized-robot","enabled":true},'
    '{"name":"freshping","ua":"freshping","path":"/","ips":[],"action":"authorized-robot","enabled":true},'
    '{"name":"HetrixTools","ua":"HetrixTools","path":"/","ips":[],"action":"authorized-robot","enabled":true},'
    '{"name":"Better Uptime","ua":"Better Uptime","path":"/","ips":[],"action":"authorized-robot","enabled":true},'
    '{"name":"updown.io","ua":"updown.io","path":"/","ips":[],"action":"authorized-robot","enabled":true}]'
).strip()
AUTHORIZED_BOT_UAS: list = _parse_authorized_bot_uas(_bot_uas_raw)

# ── Detection bypass paths ────────────────────────────────────────────────────
# Path prefixes listed here bypass ALL bot detection and are proxied directly.
# Intended for static asset directories (/static/, /assets/, /media/) where
# bot detection adds latency and false positives without security benefit.
# Prefix matching: any request.path that starts with an entry is exempt.
# Hot-reloadable. Empty list = no bypass (default, all paths protected).
_bypass_paths_raw = os.environ.get("BYPASS_PATHS", "").strip()
BYPASS_PATHS: list = [p.strip() for p in _bypass_paths_raw.split(",") if p.strip()]

_HOSTILE_REASONS  = {"canary-echo", "honeypot-silent", "honeypot",
                     "ai-probe", "suspicious-path", "session-churn"}
POW_DIFFICULTY    = 5       # leading hex zeros (~16M hashes for d=5)
POW_VALID_SECS    = 300     # 5 minutes
BEHAVIOR_WINDOW   = 30      # seconds
BEHAVIOR_MAX_REGULAR = 8    # >N requests with σ<10ms → bot

# 1.6.7 — runtime-key directory.
# Container (Dockerfile symlinks /app/.X_key → /data/.X_key on build) keeps
# the legacy "next-to-proxy.py" location. Bare-metal / venv installs set
# APPSECGW_KEY_DIR to e.g. $HOME/.config/appsecgw — the directory is
# auto-created (mode 0700) on first boot.
def _resolve_key_dir() -> str:
    env_dir = os.environ.get("APPSECGW_KEY_DIR", "").strip()
    if env_dir:
        d = os.path.expanduser(env_dir)
        try:
            os.makedirs(d, mode=0o700, exist_ok=True)
            try: os.chmod(d, 0o700)
            except OSError: pass  # nosec B110 — chmod is best-effort hardening; dir already writable
            return d
        except OSError as _e:
            print(f"[keys] APPSECGW_KEY_DIR={env_dir!r} not writable "
                  f"({_e}); falling back to script dir", flush=True)
    return os.path.dirname(os.path.abspath(__file__))

_KEY_DIR = _resolve_key_dir()
print(f"[keys] storing .admin_key / .session_key / .pow_key under {_KEY_DIR}",
      flush=True)

# PoW HMAC key — persist so restart doesn't invalidate every in-flight challenge.
_POW_KEY_FILE = os.path.join(_KEY_DIR, ".pow_key")
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
_KEY_FILE = os.path.join(_KEY_DIR, ".admin_key")
ADMIN_KEY_FROM_ENV = "ADMIN_KEY" in os.environ and bool(os.environ["ADMIN_KEY"])
if ADMIN_KEY_FROM_ENV:
    INTERNAL_KEY = os.environ["ADMIN_KEY"]
else:
    # 1.6.0 — treat an empty key file as missing. A zero-byte .admin_key
    # (left behind by a crashed/aborted previous boot) used to load as ""
    # which is unusable AND lets `key=` (empty query) constant-time-compare
    # auth to True. Now we always regenerate when the file content is empty.
    INTERNAL_KEY = ""
    if os.path.exists(_KEY_FILE):
        try:
            INTERNAL_KEY = open(_KEY_FILE).read().strip()
        except OSError:
            INTERNAL_KEY = ""
    if not INTERNAL_KEY:
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

# ── Admin IP allowlist ─────────────────────────────────────────────────────
import ipaddress as _ipaddress
_admin_ips_raw = os.environ.get("ADMIN_ALLOWED_IPS", "").strip()
ADMIN_ALLOWED_NETS: list = []          # parsed ip_network objects
ADMIN_ALLOWED_ENTRIES: list = []       # [{cidr, note, source}, …] for the UI
ADMIN_ENV_SEED: list = []              # initial env-supplied entries (read once)
if _admin_ips_raw:
    for _entry in _admin_ips_raw.split(","):
        _entry = _entry.strip()
        if not _entry:
            continue
        try:
            _net = _ipaddress.ip_network(_entry, strict=False)
            ADMIN_ALLOWED_NETS.append(_net)
            ADMIN_ENV_SEED.append(str(_net))
            ADMIN_ALLOWED_ENTRIES.append({"cidr": str(_net), "note": "env",
                                          "source": "env", "added_ts": 0})
        except ValueError as _e:
            print(f"FATAL: invalid ADMIN_ALLOWED_IPS entry {_entry!r} — {_e}",
                  flush=True)
            raise SystemExit(2)

# ── Hybrid identity: session cookie + browser fingerprint ──────────────────
_SESS_KEY_FILE = os.path.join(_KEY_DIR, ".session_key")
if os.path.exists(_SESS_KEY_FILE):
    SESSION_KEY = bytes.fromhex(open(_SESS_KEY_FILE).read().strip())
else:
    SESSION_KEY = secrets.token_bytes(32)
    with open(_SESS_KEY_FILE, "w") as _f:
        _f.write(SESSION_KEY.hex())
    os.chmod(_SESS_KEY_FILE, 0o600)

SESSION_COOKIE  = "aid"
_SESSION_COOKIE = "agw_session"   # gateway's own admin/dashboard session cookie
SESSION_TTL_SECS = 30 * 86400          # 30 days
NEW_SESSIONS_PER_IP_PER_MIN = 30        # anti cookie-rotation
_ss = os.environ.get("SESSION_SAMESITE", "Lax").capitalize()
SESSION_SAMESITE = _ss if _ss in ("Lax", "Strict", "None") else "Lax"
SESSION_SECURE = os.environ.get("SESSION_SECURE", "1").strip().lower() not in ("0", "false", "no", "off", "")

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
SUSPICIOUS_PATH_PATTERNS = (
    # ── Flag / secret hunting ────────────────────────────────────────────
    re.compile(r"(^|/)flag(\.[a-z0-9]+|$)",                re.I),
    re.compile(r"(^|/)secret[s]?(\.[a-z0-9]+|$)",          re.I),
    re.compile(r"(^|/)passwd(\.[a-z0-9]+|$)",              re.I),
    re.compile(r"(^|/)password[s]?(\.[a-z0-9]+|$)",        re.I),
    re.compile(r"(^|/)credentials?\.(json|yaml|yml|txt|conf|ini)$", re.I),
    re.compile(r"(^|/)private[_-]?key(\.[a-z0-9]+|$)",     re.I),
    re.compile(r"(^|/)api[_-]?key(\.[a-z0-9]+|$)",         re.I),
    re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.[a-z0-9]+|$)", re.I),
    re.compile(r"(^|/)\.aws/credentials\b",                re.I),
    re.compile(r"(^|/)\.ssh/(id_rsa|authorized_keys|known_hosts)\b", re.I),
    re.compile(r"(^|/)\.npmrc\b|(^|/)\.bashrc\b|(^|/)\.profile\b",  re.I),
    re.compile(r"(^|/)\.docker/config\.json\b",            re.I),
    re.compile(r"(^|/)\.env(\.[a-z]+)?$",                   re.I),
    re.compile(r"(^|/)\.htpasswd\b|(^|/)\.htaccess\b",      re.I),
    # ── Backup / leak files ──────────────────────────────────────────────
    re.compile(r"\.(bak|old|orig|tmp|swp|swo|sav|backup|~)$", re.I),
    re.compile(r"\.(sql|sqlite|db|mdb|sqlite3|dump)$",       re.I),
    re.compile(r"^/[^/]*\.(pem|key|crt|pfx|p12|jks|asc|gpg|kbx)$", re.I),
    re.compile(r"\.(tar|tar\.gz|tgz|zip|rar|7z)\.?(bak|old)?$", re.I),
    # ── VCS metadata leaks ───────────────────────────────────────────────
    re.compile(r"\.git/(HEAD|config|index|refs/|logs/|objects/)", re.I),
    re.compile(r"\.svn/(entries|wc\.db|format)", re.I),
    re.compile(r"\.hg/(store|requires|hgrc)",  re.I),
    re.compile(r"\.bzr/",                       re.I),
    re.compile(r"\.DS_Store$",                  re.I),
    re.compile(r"(^|/)Thumbs\.db$",             re.I),
    # ── Debug / admin / internal endpoints ───────────────────────────────
    re.compile(r"^/(debug|dev|test|staging|admin|administrator|backend)/?$", re.I),
    re.compile(r"^/_internal\b|^/_status\b|^/_health\b",  re.I),
    re.compile(r"(^|/)server-(status|info)\b",            re.I),  # Apache
    # Spring Boot Actuator (Tomcat/Spring) — extremely high-value targets
    re.compile(r"(^|/)actuator/(env|heapdump|threaddump|beans|mappings|shutdown|jolokia)\b", re.I),
    re.compile(r"(^|/)(manager|host-manager)/(html|status|jmxproxy)", re.I),  # Tomcat
    re.compile(r"(^|/)console(/login\.jsp)?\b",            re.I),  # WebLogic
    re.compile(r"(^|/)jmx-console\b|(^|/)web-console\b",   re.I),  # JBoss
    re.compile(r"(^|/)_cat/|(^|/)_cluster/|(^|/)_search\b", re.I), # Elasticsearch
    re.compile(r"(^|/)wp-(config\.php|admin/|login\.php)", re.I),  # WordPress
    re.compile(r"(^|/)xmlrpc\.php\b",                       re.I),  # WordPress XML-RPC
    re.compile(r"(^|/)(phpmyadmin|pma|myadmin|mysql)/?",   re.I),
    re.compile(r"(^|/)WEB-INF/(web\.xml|classes/|lib/)",   re.I),  # Java traversal target
    re.compile(r"(^|/)META-INF/MANIFEST\.MF\b",             re.I),
    re.compile(r"(^|/)(web|Web)\.config$",                  re.I),
    re.compile(r"(^|/)global\.asax$",                       re.I),
    re.compile(r"(^|/)(composer|package|yarn|Gemfile|Pipfile)\.(json|lock)$", re.I),
    # ── Cloud metadata services (SSRF target) ────────────────────────────
    re.compile(r"169\.254\.169\.254",                       re.I),  # AWS / DO / Azure
    re.compile(r"100\.100\.100\.200",                       re.I),  # Alibaba
    re.compile(r"metadata\.google\.internal",               re.I),  # GCP
    re.compile(r"/computeMetadata/v1\b|/latest/meta-data\b|/metadata/(instance|identity)", re.I),
    # ── Path traversal (encoded variants) ────────────────────────────────
    re.compile(r"\.\.[\\/]"),                          # ../  ..\
    re.compile(r"\.\.;[\\/]"),                         # semicolon trick (Tomcat)
    re.compile(r"\.{4,}/"),                            # ....//
    re.compile(r"%2e%2e[%/\\]",                  re.I),  # URL-encoded ..
    re.compile(r"%252e%252e",                    re.I),  # double-encoded
    re.compile(r"%c0%ae|%c0%2e",                 re.I),  # overlong UTF-8 ..
    re.compile(r"%c1%9c|%c1%1c",                 re.I),  # overlong /
    re.compile(r"%uff0e%uff0e",                  re.I),  # full-width ..
    re.compile(r"%00($|/|%)"),                   # null-byte truncation
    # ── SQLi markers in path / query ─────────────────────────────────────
    re.compile(r"(union[ +%]+(all[ +%]+)?select|select[ +%]+\*|or[ +%]+1[ +%]*=[ +%]*1|or[ +%]+'a'='a)", re.I),
    re.compile(r"--($|[\s+])|/\*.*?\*/|;%20--|;%00",  re.I),
    re.compile(r"\b(xp_cmdshell|sp_oacreate|load_file|into[ +%]+outfile)\b", re.I),
    re.compile(r"\b(sleep|benchmark|waitfor[ +%]+delay|pg_sleep)\s*\(",     re.I),
    re.compile(r"\binformation_schema\b|\b@@version\b",                     re.I),
    # ── XSS markers in path / query ──────────────────────────────────────
    re.compile(r"<script\b|</script>|javascript:|vbscript:|data:text/html", re.I),
    re.compile(r"on(error|load|click|mouseover|focus|blur|change|submit|toggle|animation\w*|begin|end)\s*=", re.I),
    re.compile(r"<(iframe|object|embed|svg|math|video|audio|details|frame|frameset|applet)\b", re.I),
    re.compile(r"<img[^>]+\bsrc\s*=\s*[\"']?\s*x\s*[\"']?[^>]+\bonerror\s*=", re.I),
    re.compile(r"\bsrcdoc\s*=|\bformaction\s*=",            re.I),
    re.compile(r"&\#x?[0-9a-f]{2,};",                       re.I),  # numeric/hex char ref
    # ── LFI / file inclusion ─────────────────────────────────────────────
    re.compile(r"/etc/(passwd|shadow|group|hosts|issue|os-release|crontab)\b", re.I),
    re.compile(r"/proc/(self|version|cpuinfo|cmdline|mounts|environ)\b",      re.I),
    re.compile(r"/var/log/(auth|syslog|messages|dpkg|nginx|apache2)",          re.I),
    re.compile(r"\bphp://(filter|input|memory|temp|fd)\b|\bfile://|\bexpect://|\bdata:[a-z/+-]+;base64", re.I),
    re.compile(r"\bzip://|\bphar://|\bcompress\.zlib://|\bcompress\.bzip2://", re.I),
    # Windows traversal targets
    re.compile(r"(c:[\\/])?windows[\\/](system32[\\/])?(config[\\/]sam|win\.ini|boot\.ini|drivers[\\/]etc[\\/]hosts)", re.I),
    # ── OS / shell injection ─────────────────────────────────────────────
    re.compile(r"[;&|`]\s*(cat|ls|wget|curl|nc|sh|bash|whoami|id|env|uname|nslookup|dig|ping|ifconfig|netstat|lsof|ps)\b", re.I),
    re.compile(r"\$\([^)]+\)|`[^`]+`|<\([^)]+\)",           re.I),
    re.compile(r"\b(/bin/|/usr/bin/|/sbin/|/usr/sbin/)(sh|bash|zsh|nc|cat|ls|chmod|chown|wget|curl)\b", re.I),
    re.compile(r"\b(cmd\.exe|powershell(\.exe)?|certutil|bitsadmin)\b",       re.I),
    # ── Server-side template injection (path-side hints) ─────────────────
    re.compile(r"\{\{[^}]{1,80}\}\}",                       re.I),  # Jinja / Twig
    re.compile(r"\{%[^%]{1,80}%\}|<\#assign\b|<\#list\b",   re.I),  # Jinja2 / Freemarker
    re.compile(r"<%=|<%-|\${.*?}",                          re.I),  # ERB / generic
    # ── Log4Shell-style JNDI ─────────────────────────────────────────────
    re.compile(r"\$\{(jndi|env|sys|ctx|spring|lower|upper|::-)", re.I),
    # ── XXE / XML entity probes (if a path carries XML) ──────────────────
    re.compile(r"<!ENTITY\b|<!DOCTYPE[^>]+SYSTEM\b",        re.I),
    # ── CRLF / header injection ──────────────────────────────────────────
    re.compile(r"%0d%0a|%0a%0d|\r\n",                       re.I),
    re.compile(r"%E5%98%8A|%E5%98%8D",                      re.I),  # UTF-8 hex CRLF
    # ── NoSQL injection markers ──────────────────────────────────────────
    re.compile(r"\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$where|\$regex|\$exists|\$not|\$or|\$and", re.I),
    # ── LDAP injection markers ───────────────────────────────────────────
    re.compile(r"\)\(\s*(uid|cn|objectClass)\s*=\s*\*",     re.I),
    re.compile(r"\*\)\(\s*&|\*\)\(\s*\|",                   re.I),
)

# HTML snippet to inject into upstream HTML responses.
HONEY_LINK_HTML = (
    '<div style="display:none!important;visibility:hidden;height:0;width:0;'
    'overflow:hidden;position:absolute;left:-99999px" aria-hidden="true">'
    '<a href="/_internal/audit-log" rel="nofollow">Internal audit log (do not follow)</a>'
    '<a href="/api/_debug/dump" rel="nofollow">Debug dump</a>'
    '<a href="/staff/dashboard.json" rel="nofollow">Staff dashboard</a>'
    '</div>'
)

# ── 1.6.9: AI Labyrinth — tarpit maze for AI scrapers / crawlers ─────────────
LABYRINTH_ENABLED        = os.environ.get("LABYRINTH_ENABLED",        "1") in ("1", "true", "yes")
LABYRINTH_SLOW_MS        = int(os.environ.get("LABYRINTH_SLOW_MS",        "600"))
LABYRINTH_MAX_DEPTH      = int(os.environ.get("LABYRINTH_MAX_DEPTH",      "5"))
LABYRINTH_LINKS_PER      = int(os.environ.get("LABYRINTH_LINKS_PER_PAGE", "3"))
# 1.6.10 — Gaussian jitter replaces fixed delay; mean = LABYRINTH_SLOW_MS, σ=500ms, clipped [200,3000]
LABYRINTH_JITTER_ENABLED = os.environ.get("LABYRINTH_JITTER_ENABLED",    "1") in ("1", "true", "yes")

# 1.6.10 — Accept header fingerprint: fires when HTML-nav has no text/html in Accept
ACCEPT_FP_ENABLED        = os.environ.get("ACCEPT_FP_ENABLED",           "1") in ("1", "true", "yes")

# 1.6.10 — Header canary: inject per-identity token into ETag + X-Request-Id
HEADER_CANARY_ENABLED    = os.environ.get("HEADER_CANARY_ENABLED",       "1") in ("1", "true", "yes")

# 1.6.10 — Header-order library fingerprint
HEADER_ORDER_FP_ENABLED   = os.environ.get("HEADER_ORDER_FP_ENABLED",   "1") in ("1", "true", "yes")
# 1.6.10 — AI crawler IP-range verification (OpenAI published ranges)
AI_CRAWLER_VERIFY_ENABLED = os.environ.get("AI_CRAWLER_VERIFY_ENABLED", "1") in ("1", "true", "yes")
# 1.6.10 — JA4 fail-closed: hard deny (not soft score) when JA4_TRUSTED_NETS set + header missing
JA4_FAIL_CLOSED           = os.environ.get("JA4_FAIL_CLOSED",           "0") in ("1", "true", "yes")
# JA4 TLS fingerprint deny-list
JA4_HEADER     = os.environ.get("JA4_HEADER", "CF-JA4")
JA4_DENY_LIST: set = {
    e.strip() for e in os.environ.get("JA4_DENY_LIST", "").split(",")
    if e.strip()
}
JA4_AUTODENY_THRESHOLD = int(os.environ.get("JA4_AUTODENY_THRESHOLD", "3"))
JA4_AUTODENY_WINDOW_S  = int(os.environ.get("JA4_AUTODENY_WINDOW_S",  "86400"))
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
            print(f"FATAL: invalid JA4_TRUSTED_PEERS entry {_entry!r} — {_e}", flush=True)
            raise SystemExit(2)
# 1.6.10 — JSON API canary: inject _ref token into JSON object responses
JSON_CANARY_ENABLED       = os.environ.get("JSON_CANARY_ENABLED",       "1") in ("1", "true", "yes")
# 1.6.10 — Accept-Language / GeoIP locale consistency
LOCALE_GEO_CHECK_ENABLED  = os.environ.get("LOCALE_GEO_CHECK_ENABLED",  "1") in ("1", "true", "yes")
# 1.6.10 — robots.txt compliance monitoring (serve + flag known bots that ignore it)
ROBOTS_MONITOR_ENABLED    = os.environ.get("ROBOTS_MONITOR_ENABLED",    "1") in ("1", "true", "yes")
# 1.6.10 — HTTP/2 fingerprint fallback (H2_FP_ENABLED=0 by default; off unless TLS-terminating)
H2_FP_ENABLED             = os.environ.get("H2_FP_ENABLED",             "0") in ("1", "true", "yes")
# 1.6.10 — PoW minimum solve time (ms): reject solutions that arrive suspiciously fast
POW_MIN_SOLVE_MS          = int(os.environ.get("POW_MIN_SOLVE_MS",      "200"))
# 1.6.10 — tighter session-churn threshold for hosting/datacenter ASNs
NEW_SESSIONS_PER_IP_PER_MIN_HOSTING = int(
    os.environ.get("NEW_SESSIONS_PER_IP_PER_MIN_HOSTING") or
    os.environ.get("NEW_SESSIONS_PER_HOSTING", "10")
)

_TARPIT_TOPICS = [
    ("System Configuration Reference",   "configuration"),
    ("Internal API Documentation",        "api-reference"),
    ("Database Schema Overview",          "schema"),
    ("Deployment Architecture",           "deployment"),
    ("Security Controls Summary",         "security-controls"),
    ("Monitoring & Observability Guide",  "observability"),
    ("Incident Response Playbook",        "incident-response"),
    ("Data Retention Policy",             "data-retention"),
    ("Authentication Flow Reference",     "auth-flow"),
    ("Network Segmentation Map",          "network"),
    ("Service Mesh Topology",             "service-mesh"),
    ("Audit Log Reference",               "audit-log"),
    ("Backup & Recovery Procedures",      "backup-recovery"),
    ("Rate Limit Configuration",          "rate-limits"),
    ("TLS Certificate Management",        "tls-certs"),
    ("Secrets Rotation Runbook",          "secrets-rotation"),
]

_TARPIT_SENTENCES = [
    "All credentials are rotated on a 90-day cycle and stored in the secrets manager.",
    "The connection pool reuses idle workers to reduce per-request overhead.",
    "Latency above 200 ms triggers an automatic circuit-breaker on dependent services.",
    "Replica synchronisation uses a leader-follower model; reads are served from any node.",
    "Health checks fire every 10 seconds; three failures mark the instance unhealthy.",
    "Log rotation is configured for 7 days with gzip compression after the first 24 hours.",
    "Outbound traffic must route through the egress proxy at proxy.internal:3128.",
    "The schema migration tool acquires an advisory lock before any structural change.",
    "TLS certificates are auto-renewed via ACME 30 days before expiry.",
    "Service-to-service calls are authenticated with short-lived JWTs signed by the internal CA.",
    "The batch job runs at 03:00 UTC and archives records beyond the retention window.",
    "Prometheus metrics are scraped every 15 seconds and retained for 30 days.",
    "Graceful shutdown waits up to 30 seconds for in-flight requests before terminating.",
    "The key derivation function uses PBKDF2 with 210 000 iterations and a 32-byte salt.",
    "All audit events are immutably appended to the append-only event store.",
    "Rate limits are enforced per API key with a token-bucket algorithm.",
    "The canary deployment receives 5 % of traffic before full rollout.",
    "Circuit breaker opens after 50 % error rate over a 10-second sliding window.",
    "Snapshots are taken hourly and replicated to the secondary availability zone.",
    "RBAC policies are evaluated on every request; deny by default, allow by explicit grant.",
]

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
    # Crawlers / scanners (non-AI)
    "scrapy/", "crawler", "spider", "scraper",
    "nuclei", "nikto", "sqlmap", "wpscan", "wfuzz", "ffuf", "gobuster", "dirb",
    "burp", "zap/", "zaproxy", "masscan", "nmap", "arachni",
    # Headless browsers
    "selenium", "headless", "puppeteer", "playwright", "phantomjs",
    "electron", "cypress", "webdriver", "chromedriver", "geckodriver",
    # Misc red flags
    "test", "monitor", "uptime", "pingdom", "scanner",
)

# 1.6.0 — AI-crawler granular groups (Tier A feature, Cloudflare-WAF parity).
AI_UA_GROUPS = {
    "openai":     ("gptbot", "chatgpt-user", "oai-searchbot", "openai-python",
                   "openai", "chatgpt"),
    "anthropic":  ("claudebot", "claude-web", "anthropic-ai", "anthropic",
                   "claude"),
    "google":     ("google-extended", "googleother", "googlebot-news",
                   "gemini", "bard"),
    "perplexity": ("perplexitybot", "perplexity"),
    "meta":       ("meta-externalagent", "meta-externalfetcher",
                   "facebookbot", "facebookexternalhit"),
    "other":      ("bytespider", "amazonbot", "applebot-extended", "ccbot",
                   "cohere", "mistral", "groq", "ollama", "litellm",
                   "openrouter", "langchain", "llamaindex", "autogen",
                   "crewai", "auto-gpt", "babyagi", "llm-",
                   "cursor", "codeium", "copilot", "tabnine",
                   "bot/",   # generic catch-all for un-named bots
                   ),
}
# Per-group toggles (default ON)
AI_UA_OPENAI_ENABLED     = os.environ.get("AI_UA_OPENAI_ENABLED",     "1") in ("1", "true", "yes")
AI_UA_ANTHROPIC_ENABLED  = os.environ.get("AI_UA_ANTHROPIC_ENABLED",  "1") in ("1", "true", "yes")
AI_UA_GOOGLE_ENABLED     = os.environ.get("AI_UA_GOOGLE_ENABLED",     "1") in ("1", "true", "yes")
AI_UA_PERPLEXITY_ENABLED = os.environ.get("AI_UA_PERPLEXITY_ENABLED", "1") in ("1", "true", "yes")
AI_UA_META_ENABLED       = os.environ.get("AI_UA_META_ENABLED",       "1") in ("1", "true", "yes")
AI_UA_OTHER_ENABLED      = os.environ.get("AI_UA_OTHER_ENABLED",      "1") in ("1", "true", "yes")

# ── AI agent specific path probes (often hit during enumeration) ───────────
AI_PROBE_PATHS = {
    "/.well-known/openapi", "/.well-known/ai-plugin.json",
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/swagger-ui", "/swagger-ui.html", "/api/swagger", "/api-docs",
    "/v1/models", "/v1/chat", "/v1/completions",
    "/.well-known/llm.txt", "/.well-known/ai.txt", "/llms.txt",
    "/sitemap_ai.xml", "/ai-readme.md",
}

# Operator-configurable PoW required paths
_pow_paths_raw = os.environ.get("POW_REQUIRED_PATHS", "")
POW_REQUIRED_PATHS = {p.strip() for p in _pow_paths_raw.split(",") if p.strip()}
POW_REQUIRE_ALL_WRITES = os.environ.get("POW_REQUIRE_ALL_WRITES", "0") in ("1", "true", "yes")

# ── State size limits ──────────────────────────────────────────────────────
MAX_IDENTITIES = int(os.environ.get("MAX_IDENTITIES", "100000"))
PRUNE_IDLE_SECS = int(os.environ.get("PRUNE_IDLE_SECS", "86400"))  # 24h
# 1.5.5 — promoted to module-level global so /__config can hot-reload it.
ENUM_THRESHOLD  = int(os.environ.get("ENUM_THRESHOLD", "300"))     # >N unique paths/identity = ai-enumeration
PRUNE_INTERVAL_SECS = 600  # run every 10 min

# ── Global metrics + event log ─────────────────────────────────────────────
import time as _t

# ── DB backend ─────────────────────────────────────────────────────────────
DB_BACKEND = os.environ.get("DB_BACKEND", "sqlite").strip().lower()
if DB_BACKEND not in ("sqlite", "postgres"):
    print(f"[db] unknown DB_BACKEND={DB_BACKEND!r}; falling back to sqlite",
          flush=True)
    DB_BACKEND = "sqlite"
POSTGRES_DSN = os.environ.get("POSTGRES_DSN", "").strip()

# ── SQLite persistence ─────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "antibot.db"))

# ── 1.5.0 — optional Redis-backed shared state ─────────────────────────────
REDIS_URL          = os.environ.get("REDIS_URL", "").strip()
REDIS_NS           = os.environ.get("REDIS_NS", "appsecgw").strip() or "appsecgw"
REDIS_TIMEOUT      = float(os.environ.get("REDIS_TIMEOUT", "0.5"))

# ── Webhook fan-out ────────────────────────────────────────────────────────
WEBHOOK_URL    = os.environ.get("WEBHOOK_URL", "").strip()
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "").strip()
WEBHOOK_EVENT_FILTER = [
    p.strip() for p in os.environ.get("WEBHOOK_EVENT_FILTER", "").split(",")
    if p.strip()
]

# ── v1.4: Service-metrics collection ──────────────────────────────────────
SERVICE_METRICS_INTERVAL = float(os.environ.get("SVC_METRICS_INTERVAL", "60"))    # secs (60s → 30-day window at ~22 MB)
SERVICE_METRICS_RETENTION = int(os.environ.get("SVC_METRICS_RETENTION", "43200"))  # in-mem samples (30 days × 1440/day)
SVC_DB_RETENTION_HOURS = int(os.environ.get("SVC_DB_RETENTION_HOURS", "720"))    # on-disk retention
_PROC = "/proc"
_DATA_PATH = os.environ.get("DB_PATH", "/data/antibot.db")

WAL_CHECKPOINT_EVERY_SECS = float(os.environ.get("WAL_CHECKPOINT_EVERY_SECS", "60"))

# ── TRUST_XFF / TRUSTED_PROXIES ──────────────────────────────────────────
TRUST_XFF = os.environ.get("TRUST_XFF", "first").lower()  # first | last | none
_trusted_proxies_raw = os.environ.get("TRUSTED_PROXIES", "").strip()
TRUSTED_PROXIES_NETS: list = []
if _trusted_proxies_raw:
    import ipaddress as _ipa_tp
    for _e in _trusted_proxies_raw.split(","):
        _e = _e.strip()
        if not _e:
            continue
        try:
            TRUSTED_PROXIES_NETS.append(_ipa_tp.ip_network(_e, strict=False))
        except ValueError as _e2:
            print(f"FATAL: invalid TRUSTED_PROXIES entry {_e!r} — {_e2}", flush=True)
            raise SystemExit(2)

# ── Structured logging + request correlation IDs ─────────────────────────
LOG_FORMAT = os.environ.get("LOG_FORMAT", "text").lower()
LOG_LEVEL  = os.environ.get("LOG_LEVEL",  "info").lower()
_LOG_LEVELS = {"debug": 10, "info": 20, "warn": 30, "warning": 30,
               "error": 40, "critical": 50}
_LOG_LEVEL_N = _LOG_LEVELS.get(LOG_LEVEL, 20)
_REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_\-:.]{1,64}$")

# ── Admin namespace ────────────────────────────────────────────────────────
ADMIN_NS         = "/antibot-appsec-gateway"
ADMIN_NS_SECURED = ADMIN_NS + "/secured"
_ADMIN_PUBLIC_SUBPATHS = (
    "/pow", "/solver", "/challenge",
    "/botd-report",
    "/automation-report",
    "/assets/botd.bundle.js",
    "/tarpit/",
    "/fp-report",
    "/sw.js",
    # 1.7.3 — AI-agent detection probes (public, no auth required)
    "/probe",
    "/maze",
    "/canary-probe/",
)
_ADMIN_LOGIN_SUBPATHS = ("/login", "/logout")

# High-frequency read-only polling endpoints that must not flood the events
# buffer — recording them every 2–15 s displaces real traffic events.
_ADMIN_POLL_SUBPATHS = frozenset({
    "/secured/metrics",
    "/secured/health-score",
    "/secured/status",
})

# ── Risk scoring ───────────────────────────────────────────────────────────
RISK_WEIGHTS = {
    # 1.6.3 — calibrated weights (post-Tier-C review)
    "honeypot":              50,
    "honeypot-silent":       50,
    "suspicious-path":       50,
    "ai-probe":              40,
    "ai-enumeration":        30,
    "behavior":               8,
    "ua-empty":              30,
    "ua-blocked":            20,
    "ua-non-browser":        25,
    "ai-headers-empty":      20,
    "ua-too-short":          15,
    "ai-headers-incomplete": 10,
    "upstream-404":           6,
    "ai-no-assets":           8,
    "session-flood":         10,
    "rate-limit-ip":          0,
    "rate-limit":             0,
    "host-not-allowed":      40,
    "suspicious-body":       40,
    "bot-trap":              50,
    "canary-echo":           80,
    "session-churn":         75,
    "fp-banned":              0,
    "traffic-threshold":      0,
    "js-challenge":           3,
    "tls-fingerprint":       40,
    "origin-mismatch":       20,
    "missing-required-header": 15,
    "ua-platform-mismatch":  30,
    "accept-wildcard-html":   2,
    "accept-fp":              3,
    "labyrinth-jitter":       0,
    "header-canary":          0,
    "ja4-required-missing":   3,
    "headers-suspicious":     2,
    "abuseipdb-high":        50,
    "abuseipdb-med":         20,
    "crowdsec-banned":       70,
    "asn-hosting":            5,
    "country-blocked":       50,
    "tor-exit":              40,
    "datacenter-vpn":        25,
    "ua-ai-openai":          25,
    "ua-ai-anthropic":       25,
    "ua-ai-google":          25,
    "ua-ai-perplexity":      25,
    "ua-ai-meta":            25,
    "ua-ai-other":           20,
    "custom-rule-block":     50,
    "rate-limit-endpoint":    0,
    "body-sqli":             50,
    "body-xss":              50,
    "body-lfi":              50,
    "body-rce":              50,
    "body-ssrf":             50,
    "body-cmd":              50,
    "auth-jwt-invalid":      30,
    "slow-client":            10,
    "botd-detected":          30,
    "tarpit-walk":           100,
    "dlp-cc":                 0,
    "dlp-aws":                0,
    "dlp-jwt":                0,
    "dlp-private-key":        0,
    "dlp-api-key":            0,
    "dlp-pii-email":          0,
    "dlp-pii-ssn":            0,
    "header-order-fp":        8,
    "ai-ua-ip-mismatch":     30,
    "locale-geo-mismatch":   10,
    "robots-violation":       5,
    "h2-fp":                  3,
    "json-canary":            0,
    # 1.7.1 — new signals
    "webdriver-detected":    30,
    "coordinated-probe":     25,
    "direct-api-probe":      15,
    # 1.7.2 — new signals
    "cookie-ghost":          20,
    "lifecycle-miss":        12,
    "referer-ghost":         10,
    "impossible-travel":     35,
    "soft-renderer":         25,
    "webgl-missing":         15,
    # 1.7.3 — AI-agent specific signals
    "honey-cred":            90,   # P1: fake credential used
    "redirect-maze-bot":     55,   # P2: maze completed too fast
    "llm-no-subresources":   40,   # P3: HTML fetched without CSS/JS/images
    "canary-probe-miss":     35,   # P4: preload probe never fetched
}

SOFT_CHALLENGE_SCORE = float(os.environ.get("SOFT_CHALLENGE_SCORE", "4"))
ESCALATION_THRESHOLD = float(os.environ.get("ESCALATION_THRESHOLD", "30"))
SECOND_ORDER_THRESHOLD = float(os.environ.get("SECOND_ORDER_THRESHOLD", "15"))

BOTD_ENABLED = os.environ.get("BOTD_ENABLED", "0") in ("1", "true", "yes")

# Runtime-only bypass: when True, protect() skips ALL detection and ban
# enforcement, passing every upstream request through unconditionally.
# Set only via the Controls dashboard bypass toggle, never via env var.
BYPASS_MODE: bool = False

# ── 1.7.1 — Browser automation probe (self-hosted, no external bundle) ─────────
AUTOMATION_PROBE_ENABLED     = os.environ.get("AUTOMATION_PROBE_ENABLED",   "1") in ("1", "true", "yes")
# 1.7.1 — Coordinated ASN attack clustering
COORDINATED_ATTACK_ENABLED   = os.environ.get("COORDINATED_ATTACK_ENABLED", "1") in ("1", "true", "yes")
COORDINATED_ATTACK_THRESHOLD = int(os.environ.get("COORDINATED_ATTACK_THRESHOLD", "5"))
# 1.7.1 — User journey: flag identities that probe API directly without HTML load
JOURNEY_CHECK_ENABLED        = os.environ.get("JOURNEY_CHECK_ENABLED",      "1") in ("1", "true", "yes")
_BOTD_REPORT_TTL = 300  # report valid for 5 minutes after the page loads

# ── 1.7.2 — cookie lifecycle + ghost detection ───────────────────────────────
COOKIE_GHOST_ENABLED        = os.environ.get("COOKIE_GHOST_ENABLED",        "1") in ("1", "true", "yes")
COOKIE_LIFECYCLE_ENABLED    = os.environ.get("COOKIE_LIFECYCLE_ENABLED",    "1") in ("1", "true", "yes")
COOKIE_GHOST_MIN_REQUESTS   = int(os.environ.get("COOKIE_GHOST_MIN_REQUESTS",   "3"))
COOKIE_GHOST_MISS_THRESHOLD = int(os.environ.get("COOKIE_GHOST_MISS_THRESHOLD", "3"))

# ── 1.7.2 — referrer chain integrity ────────────────────────────────────────
REFERER_CHAIN_ENABLED = os.environ.get("REFERER_CHAIN_ENABLED", "1") in ("1", "true", "yes")

# ── 1.7.2 — impossible travel ────────────────────────────────────────────────
IMPOSSIBLE_TRAVEL_ENABLED     = os.environ.get("IMPOSSIBLE_TRAVEL_ENABLED",     "1") in ("1", "true", "yes")
IMPOSSIBLE_TRAVEL_WINDOW_SECS = int(os.environ.get("IMPOSSIBLE_TRAVEL_WINDOW_SECS", "1800"))

# ── 1.7.3 — path-sweep detector ─────────────────────────────────────────────
# Fires when a post-challenge identity visits too many distinct non-static
# paths in a rolling window — characteristic of automated content discovery.
PATH_SWEEP_ENABLED      = os.environ.get("PATH_SWEEP_ENABLED",      "1") in ("1", "true", "yes")
PATH_SWEEP_WINDOW_SECS  = int(os.environ.get("PATH_SWEEP_WINDOW_SECS",  "300"))  # 5-min window
PATH_SWEEP_THRESHOLD    = int(os.environ.get("PATH_SWEEP_THRESHOLD",    "40"))   # distinct paths

# ── 1.7.3 — P1: semantic honeypot credential injection ───────────────────────
# Inject fake API keys in HTML comments. AI agents extract and use them;
# browsers never read HTML source. When the probe endpoint is hit → instant
# high-confidence bot flag.
HONEY_CRED_ENABLED = os.environ.get("HONEY_CRED_ENABLED", "1") in ("1", "true", "yes")
HONEY_CRED_SCORE   = float(os.environ.get("HONEY_CRED_SCORE", "90"))

# ── 1.7.3 — P2: risk-gated redirect maze ─────────────────────────────────────
# For identities above threshold, serve a chain of signed redirects.
# Agents follow all steps in milliseconds; humans show normal latency.
REDIRECT_MAZE_ENABLED   = os.environ.get("REDIRECT_MAZE_ENABLED",   "0") in ("1", "true", "yes")
REDIRECT_MAZE_THRESHOLD = float(os.environ.get("REDIRECT_MAZE_THRESHOLD", "20"))  # risk score
REDIRECT_MAZE_DEPTH     = int(os.environ.get("REDIRECT_MAZE_DEPTH",     "4"))     # redirect steps
REDIRECT_MAZE_MIN_MS    = float(os.environ.get("REDIRECT_MAZE_MIN_MS",  "800"))   # ms a human needs
REDIRECT_MAZE_SCORE     = float(os.environ.get("REDIRECT_MAZE_SCORE",   "55"))

# ── 1.7.3 — P3: LLM no-subresource heuristic ────────────────────────────────
# Real browsers load CSS/JS/images for every HTML page. AI agents fetch only
# HTML. Track ratio: if N HTML pages fetched with zero sub-resources → LLM.
LLM_HEURISTIC_ENABLED       = os.environ.get("LLM_HEURISTIC_ENABLED",       "1") in ("1", "true", "yes")
LLM_HTML_MIN_COUNT          = int(os.environ.get("LLM_HTML_MIN_COUNT",          "5"))   # min HTML fetches to trigger
LLM_SUBRES_RATIO_THRESHOLD  = float(os.environ.get("LLM_SUBRES_RATIO_THRESHOLD", "0.0")) # max sub-res ratio (0=none)
LLM_HEURISTIC_WINDOW_SECS   = int(os.environ.get("LLM_HEURISTIC_WINDOW_SECS",   "120"))
LLM_HEURISTIC_SCORE         = float(os.environ.get("LLM_HEURISTIC_SCORE",        "40"))

# ── 1.7.3 — P4: browser execution probe (split canary) ───────────────────────
# Inject <link rel="preload"> into HTML. Browsers auto-fetch it; curl/agents
# don't. Probes not fetched within TTL after N HTML requests → LLM signal.
CANARY_PROBE_ENABLED    = os.environ.get("CANARY_PROBE_ENABLED",    "1") in ("1", "true", "yes")
CANARY_PROBE_TTL_SECS   = int(os.environ.get("CANARY_PROBE_TTL_SECS",   "60"))   # window to fetch
CANARY_PROBE_MIN_HTML   = int(os.environ.get("CANARY_PROBE_MIN_HTML",   "5"))    # HTML pages before check
CANARY_PROBE_SCORE      = float(os.environ.get("CANARY_PROBE_SCORE",      "20"))

# ── 1.7.2 — browser fingerprint enrichment (canvas + WebGL) ─────────────────
FP_ENRICHMENT_ENABLED = os.environ.get("FP_ENRICHMENT_ENABLED", "1") in ("1", "true", "yes")

# ── 1.7.2 — service worker challenge ────────────────────────────────────────
SW_CHALLENGE_ENABLED = os.environ.get("SW_CHALLENGE_ENABLED", "0") in ("1", "true", "yes")

# ── 1.7.2 — PoW embedded in JS challenge when risk > threshold ───────────────
POW_CHAL_THRESHOLD = float(os.environ.get("POW_CHAL_THRESHOLD", "30.0"))

TARPIT_ENABLED = os.environ.get("TARPIT_ENABLED", "0") in ("1", "true", "yes")
TARPIT_DELAY_MS = int(os.environ.get("TARPIT_DELAY_MS", "1500"))

ESCALATE_ONLY_REASONS = {
    "abuseipdb-high", "abuseipdb-med",
    "crowdsec-banned",
    "asn-hosting", "datacenter-vpn",
    "coordinated-probe",
    "body-sqli", "body-xss", "body-lfi", "body-rce", "body-ssrf", "body-cmd",
    "suspicious-body",
    "dlp-cc", "dlp-aws", "dlp-jwt", "dlp-private-key",
    "dlp-api-key", "dlp-pii-email", "dlp-pii-ssn",
}

SECOND_ORDER_REASONS = {
    "ai-enumeration",
    "ai-no-assets",
    "locale-geo-mismatch",
    "tls-fingerprint",
    "ja4-required-missing",
    "direct-api-probe",
}

RISK_BAN_THRESHOLD       = 50
RISK_BAN_THRESHOLD_NAT   = 100
RISK_DECAY_HALFLIFE_SECS = 3600
NAT_IDENTITIES_THRESHOLD = 5
RISK_BAN_DURATION_SECS   = 3600

# ── Timeline retention ─────────────────────────────────────────────────────
TIMELINE_RETAIN_SECS = int(os.environ.get("TIMELINE_RETAIN_SECS", "2592000"))  # 30 days
COST_RETAIN_SECS = int(os.environ.get("COST_RETAIN_SECS", "10800"))  # 3h

# ── Canary echo detection ──────────────────────────────────────────────────
CANARY_ECHO_DETECTION = os.environ.get(
    "CANARY_ECHO_DETECTION", "1") not in ("", "0", "false", "False", "no")
CANARY_TTL_S    = int(os.environ.get("CANARY_TTL_S", "600"))   # 10 min
_CANARY_PREFIX  = "agw-c-"
_CANARY_USED_MAX = 50000
_CANARY_RE = re.compile(r"agw-c-[0-9a-f]{16}")

# ── PoW seen-set size limit ────────────────────────────────────────────────
_POW_SEEN_MAX = 10000

# ── Per-socket-IP token bucket ─────────────────────────────────────────────
IP_BURST  = int(os.environ.get("IP_BURST",  "30"))
IP_REFILL = max(0.001, float(os.environ.get("IP_REFILL", "5.0")))

# ── _to_bool_default_true helper (used during config init) ─────────────────
def _to_bool_default_true(v):
    if v is None: return True
    s = str(v).strip().lower()
    return s in ("1", "true", "yes", "on")

HONEYPOT_ENABLED          = _to_bool_default_true(os.environ.get("HONEYPOT_ENABLED", "1"))
SUSPICIOUS_PATH_ENABLED   = _to_bool_default_true(os.environ.get("SUSPICIOUS_PATH_ENABLED", "1"))
AI_PROBE_ENABLED          = _to_bool_default_true(os.environ.get("AI_PROBE_ENABLED", "1"))
UA_FILTER_ENABLED         = _to_bool_default_true(os.environ.get("UA_FILTER_ENABLED", "1"))
UA_PLATFORM_CHECK_ENABLED = _to_bool_default_true(os.environ.get("UA_PLATFORM_CHECK_ENABLED", "1"))
HEADER_COMPLETENESS_ENABLED = _to_bool_default_true(os.environ.get("HEADER_COMPLETENESS_ENABLED", "1"))
BEHAVIORAL_CHECK_ENABLED  = _to_bool_default_true(os.environ.get("BEHAVIORAL_CHECK_ENABLED", "1"))
AI_ENUMERATION_ENABLED    = _to_bool_default_true(os.environ.get("AI_ENUMERATION_ENABLED", "1"))
AI_NO_ASSETS_ENABLED      = _to_bool_default_true(os.environ.get("AI_NO_ASSETS_ENABLED", "1"))
SESSION_FLOOD_ENABLED     = _to_bool_default_true(os.environ.get("SESSION_FLOOD_ENABLED", "1"))
UPSTREAM_404_TRACKING_ENABLED = _to_bool_default_true(os.environ.get("UPSTREAM_404_TRACKING_ENABLED", "1"))

# ── JS challenge + cookie gate ───────────────────────────────────────────────
JS_CHALLENGE     = os.environ.get("JS_CHALLENGE", "0") in ("1", "true", "yes")
CHAL_COOKIE      = "chal"
JS_CHALLENGE_TTL = int(os.environ.get("JS_CHALLENGE_TTL", "3600"))
CHAL_NONCE_TTL   = 120

# ── Edge-injected security response headers (HTML only) ─────────────────────
INJECT_SECURITY_HEADERS = os.environ.get(
    "INJECT_SECURITY_HEADERS", "1") not in ("", "0", "false", "False", "no")
SECURITY_HEADERS: dict = {
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
    "Content-Security-Policy":   os.environ.get("SEC_CSP", ""),
    "Cross-Origin-Opener-Policy":   os.environ.get("SEC_COOP", "same-origin"),
    "Cross-Origin-Resource-Policy": os.environ.get("SEC_CORP", "same-site"),
}

BODY_TIMEOUT           = float(os.environ.get("BODY_TIMEOUT",           "30"))
SESSION_CHURN_WINDOW_S = int(os.environ.get("SESSION_CHURN_WINDOW_S",   "120"))
SESSION_CHURN_MAX      = int(os.environ.get("SESSION_CHURN_MAX",        "3"))

# ── Anubis-mode PoW boost (1.5.4+) ──────────────────────────────────────────
ANUBIS_ENABLED          = os.environ.get("ANUBIS_ENABLED", "0") in ("1", "true", "yes")
ANUBIS_DIFFICULTY_BOOST = int(os.environ.get("ANUBIS_DIFFICULTY_BOOST", "1"))

# ── 1.6.1 — Tier B JWT/Bearer signature validation ───────────────────────────
import base64 as _b64  # noqa: F401 — needed by integrations/jwt.py + admin modules
JWT_VALIDATE_PATHS   = [p.strip() for p in os.environ.get("JWT_VALIDATE_PATHS", "").split(",") if p.strip()]
JWT_HMAC_SECRET      = os.environ.get("JWT_HMAC_SECRET", "")
JWT_REQUIRED_ISSUER  = os.environ.get("JWT_REQUIRED_ISSUER", "").strip()
JWT_REQUIRED_AUDIENCE = os.environ.get("JWT_REQUIRED_AUDIENCE", "").strip()
JWT_LEEWAY_SECS      = int(os.environ.get("JWT_LEEWAY_SECS", "30"))

# ── Turnstile (Cloudflare JS challenge backend) ───────────────────────────────
TURNSTILE_SITEKEY = os.environ.get("TURNSTILE_SITEKEY", "").strip()
TURNSTILE_SECRET  = os.environ.get("TURNSTILE_SECRET", "").strip()
# 1.5.4 — Turnstile is now OPT-IN even when keys are configured. Operators
# explicitly enable via env (`TURNSTILE_ENABLED=1`) or the controls dashboard
# toggle. Closes the deploy-time risk where leaving the test keys in env
# silently activated Turnstile (see pentest R20).
_TURNSTILE_CONFIGURED = bool(TURNSTILE_SITEKEY and TURNSTILE_SECRET)
# Keys present → Turnstile auto-enables. Set TURNSTILE_ENABLED=0 to opt out.
_ts_env = os.environ.get("TURNSTILE_ENABLED", "").strip().lower()
TURNSTILE_ENABLED = (
    _TURNSTILE_CONFIGURED
    and _ts_env not in ("0", "false", "no")
)
# 1.5.4 — show Turnstile only when identity's risk crosses this threshold.
# 0 (default) = auto = midpoint between SOFT_CHALLENGE_SCORE and
# RISK_BAN_THRESHOLD (the upper half of the orange band). Below this,
# fresh clients fall back to the cookie auto-mint heuristic — most legitimate
# users never see Turnstile, only suspected bots do.
TURNSTILE_RISK_THRESHOLD = float(os.environ.get("TURNSTILE_RISK_THRESHOLD", "0"))
TURNSTILE_VERIFY_URL = (
    "https://challenges.cloudflare.com/turnstile/v0/siteverify")

# ── JS challenge JA4 binding + static-asset bypass ────────────────────────────
# v1.4.1 V9.2: JA4 TLS-fingerprint binding for the chal cookie.
# Mutually exclusive with TURNSTILE_ENABLED: when Turnstile is on, TLS is
# always terminated upstream (Cloudflare CDN), so JA4 is never available.
# Forcing both on silently fails every challenge with 403 "ja4 required".
JS_CHAL_REQUIRE_JA4 = (
    os.environ.get("JS_CHAL_REQUIRE_JA4", "0") in ("1", "true", "yes")
    and not TURNSTILE_ENABLED
)
JS_CHAL_BIND_JA4 = os.environ.get(
    "JS_CHAL_BIND_JA4", "1") not in ("", "0", "false", "False", "no")

# v1.4.1 (post-V8 hardening): when JS_CHAL_STRICT_STATIC=1, the static-asset
# bypass refuses to skip anything that LOOKS like an API path. Default ON.
JS_CHAL_STRICT_STATIC = os.environ.get(
    "JS_CHAL_STRICT_STATIC", "1") not in ("", "0", "false", "False", "no")

# Operator-controlled escape hatch for legit non-browser clients (S2S,
# mobile apps, webhooks). Comma-separated path prefixes.
_JS_CHAL_OPEN_PATHS_RAW = os.environ.get("JS_CHAL_OPEN_PATHS", "").strip()
JS_CHAL_OPEN_PATHS = [p.strip() for p in _JS_CHAL_OPEN_PATHS_RAW.split(",")
                      if p.strip()]

# ── v1.4: Body pattern matching (extends Layer 3 to POST/PUT bodies) ─────────
BODY_PATTERN_MATCH = os.environ.get("BODY_PATTERN_MATCH", "0") in ("1", "true", "yes")
SUSPICIOUS_BODY_PATTERNS = (
    # Legacy catch-all set kept for backwards compatibility with the
    # `suspicious-body` reason. The Tier-B BODY_PATTERN_GROUPS below are
    # checked FIRST and take precedence when they match.
    re.compile(rb"(union[ +]+select|select[ +]+\*|or[ +]+1=1|--\s*$|\bxp_)", re.I),
    re.compile(rb"<script\b|javascript:|onerror\s*=", re.I),
    re.compile(rb"\{\{[^}]{1,40}\}\}|\{%[^%]{1,40}%\}"),       # SSTI
    re.compile(rb"\.\.[\\/]|\bphp://|\bfile://|\bexpect://"),
    re.compile(rb"[;&|`]\s*(cat|ls|wget|curl|nc|sh|bash)\b", re.I),
)

# 1.6.1 — Tier B managed body-pattern groups (Cloudflare Managed Rulesets parity).
# 1.6.4 — significantly expanded based on the Portswigger / OWASP /
# PayloadsAllTheThings cheat-sheet ecosystem. Each group is independently
# toggleable; group-specific reasons let the operator attribute traffic per
# attack family in dashboards / SIEM.
BODY_PATTERN_GROUPS = {
    # ── SQL injection ────────────────────────────────────────────────────
    "sqli": (
        re.compile(rb"(?i)\bunion[ +/*]+(all[ +/*]+)?select\b"),
        re.compile(rb"(?i)\bselect[ +/*]+(\*|\d+|null)[ +/*]+from\b"),
        re.compile(rb"(?i)\bor[ +/*]+(1[ +]*=[ +]*1|'[a-z0-9]+'='[a-z0-9]+'|true|2[ +]*>[ +]*1)\b"),
        re.compile(rb"(?i)\band[ +/*]+1[ +]*=[ +]*1|\band[ +/*]+'a'='a"),
        re.compile(rb"(?i)(--|#|/\*).{0,8}($|[\r\n])"),
        re.compile(rb"(?i)\b(sleep|benchmark|pg_sleep|waitfor[ +]+delay|dbms_pipe\.receive_message)\s*\("),
        re.compile(rb"(?i)if\s*\(\s*\d+\s*=\s*\d+\s*,\s*sleep"),
        re.compile(rb"(?i)\b(load_file|into[ +]+(out|dump)file|xp_cmdshell|sp_oacreate|xp_dirtree|extractvalue|updatexml)\b"),
        re.compile(rb"(?i)\binformation_schema\.(tables|columns|schemata)\b|@@version|@@hostname|@@datadir"),
        re.compile(rb"(?i);[ +]*(drop|insert|update|delete|create|alter|exec(ute)?|truncate|grant|revoke)[ +]+"),
        re.compile(rb"(?i)\bchar\s*\(\s*\d+\s*(,\s*\d+\s*){2,}\)|\bconcat\s*\(.{1,200}select\b"),
    ),

    # ── Cross-site scripting ─────────────────────────────────────────────
    "xss": (
        re.compile(rb"(?i)<script\b[^>]*>|</script\s*>|<svg[^>]*>\s*<script\b"),
        re.compile(rb"(?i)\b(javascript|vbscript|livescript)\s*:"),
        re.compile(rb"(?i)data:\s*text/html\s*[;,]"),
        re.compile(rb"(?i)\bon(error|load|click|mouseover|mouseenter|mouseleave|focus|blur"
                   rb"|change|submit|input|toggle|cut|copy|paste|drag|drop|wheel"
                   rb"|animationstart|animationend|transitionend|begin|end|repeat"
                   rb"|pageshow|pagehide|popstate|hashchange|message|scroll"
                   rb"|select|abort|canplay|durationchange)\s*="),
        re.compile(rb"(?i)<(iframe|object|embed|svg|math|video|audio|details|frame|frameset"
                   rb"|applet|meta|link|base|form|input|textarea|button|isindex)\b[^>]*>"),
        re.compile(rb"(?i)<(img|input|video|audio|details|svg)[^>]+\bonerror\s*="),
        re.compile(rb"(?i)\b(srcdoc|formaction|background|poster|icon|action|src|href)\s*=\s*[\"']?\s*(javascript|data):"),
        re.compile(rb"(?i)<style\b[^>]*>[^<]*expression\s*\("),
        re.compile(rb"(?i)\b(import\s+url\s*\(|@import\s+[\"']?(java|vb)script:)"),
        re.compile(rb"(?i)&#x?(0*(60|3c)|[0]*[36]0|[0]*x?3c)\b"),
        re.compile(rb"\{\{.{0,80}(constructor|__proto__|alert|prompt|confirm|fetch)\b"),
    ),

    # ── Local-file-inclusion / path traversal ────────────────────────────
    "lfi": (
        re.compile(rb"\.\.[\\/]|\.\.;[\\/]|\.{4,}/"),
        re.compile(rb"(?i)\.\.(%2f|%5c|%252f|%255c)"),
        re.compile(rb"(?i)%2e%2e[%/\\]|%252e%252e|%c0%ae|%c0%2e|%c1%9c"),
        re.compile(rb"(?i)/etc/(passwd|shadow|group|hosts|issue|os-release|crontab|sudoers|fstab|nsswitch\.conf)\b"),
        re.compile(rb"(?i)/proc/(self|version|cpuinfo|cmdline|mounts|environ|net/(tcp|fib_trie))\b"),
        re.compile(rb"(?i)/var/log/(auth|syslog|messages|dpkg|nginx|apache2)|/root/\.bash_history"),
        re.compile(rb"(?i)(c:[\\/])?windows[\\/](system32[\\/])?(config[\\/]sam|win\.ini|boot\.ini|drivers[\\/]etc[\\/]hosts)"),
        re.compile(rb"(?i)WEB-INF/(web\.xml|classes/|lib/)|META-INF/MANIFEST\.MF"),
        re.compile(rb"(?i)\bphp://(filter|input|memory|temp|fd)\b|\bfile://|\bexpect://|\bdata:[a-z/+-]+;base64"),
        re.compile(rb"(?i)\bzip://|\bphar://|\bcompress\.zlib://|\bcompress\.bzip2://"),
        re.compile(rb"%00($|/|%)"),
    ),

    # ── Remote code execution (multi-language + framework) ───────────────
    "rce": (
        re.compile(rb"(?i)\$\{(jndi|env|sys|ctx|spring|lower|upper|::-)"),
        re.compile(rb"(?i)\$\{[\$:{}]*j[\$:{}]*n[\$:{}]*d[\$:{}]*i\s*:"),
        re.compile(rb"(?i)class\.module\.classLoader\."),
        re.compile(rb"(?i)\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\b|\bProcessBuilder\s*\("),
        re.compile(rb"(?i)#exec\s*\(|@\s*java\.lang\.Runtime|@\s*java\.lang\.ProcessBuilder"),
        re.compile(rb"(?i)__import__\s*\(\s*['\"](os|subprocess|sys|builtins|importlib)"),
        re.compile(rb"(?i)\b(subprocess|os)\.(system|popen|call|run|getoutput|spawn[a-z]*)\s*\("),
        re.compile(rb"(?i)\b(eval|exec|compile)\s*\(\s*['\"]?(import|__import__|open|chr\()"),
        re.compile(rb"(?i)\b(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|create_function|preg_replace_callback)\s*\("),
        re.compile(rb"(?i)\$_(GET|POST|REQUEST|COOKIE)\s*\[[^]]+\]\s*\("),
        re.compile(rb"(?i)\b(system|exec|eval|instance_eval|class_eval|Open3\.\w+|IO\.popen|Marshal\.load|ERB\.new)\s*\("),
        re.compile(rb"(?i)\b(child_process|require\s*\(\s*['\"]child_process['\"]\)|process\.binding|execSync|spawnSync)\s*\("),
        re.compile(rb"(?i)\bFunction\s*\(\s*['\"]return"),
        re.compile(rb"(?i)\beval\s*\(\s*atob\s*\("),
        re.compile(rb"(?i)\bnew\s+Function\s*\("),
        re.compile(rb"(?i)\baced0005|\brO0AB"),
        re.compile(rb"(?i)__reduce__\s*\(\s*\)|pickle\.loads"),
    ),

    # ── Server-side request forgery (URL / metadata-service targeting) ──
    "ssrf": (
        re.compile(rb"(?i)\bhttps?://(127\.\d+\.\d+\.\d+|0\.0\.0\.0|localhost|\[::1\]|\[?fe80:|\[?fc00:)"),
        re.compile(rb"(?i)\bhttps?://(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)"),
        re.compile(rb"169\.254\.169\.254"),
        re.compile(rb"100\.100\.100\.200"),
        re.compile(rb"(?i)metadata\.google\.internal"),
        re.compile(rb"(?i)/computeMetadata/v1\b|/latest/meta-data\b|/metadata/(instance|identity)"),
        re.compile(rb"\b0x7f000001\b|\b2130706433\b|\b017700000001\b"),
        re.compile(rb"(?i)\bgopher://|\bdict://|\bldap[s]?://|\btftp://|\bsftp://|\bnetdoc://|\bjar://"),
        re.compile(rb"(?i)\bfile:[/]{2,4}|\bphp://|\bjava\.net\.URL"),
        re.compile(rb"(?i)https?://[^/\s]*@(127\.|10\.|192\.168\.|169\.254\.)"),
        re.compile(rb"(?i)(\?|&)(url|uri|target|path|dest|redirect|next|continue|callback|webhook|image|file|link|src|fetch|preview)=https?://[^&]*?(127\.|10\.|192\.168\.|169\.254\.|localhost)"),
    ),

    # ── OS command injection ─────────────────────────────────────────────
    "cmd": (
        re.compile(rb"(?i)[;&|`]\s*(cat|ls|wget|curl|nc|ncat|sh|bash|zsh|whoami|id|env|uname|nslookup|dig|ping|host|ifconfig|ip\b|route|netstat|ss\b|lsof|ps|tail|head|find|chmod|chown|crontab)\b"),
        re.compile(rb"(\n|%0a|\r|%0d)\s*(cat|ls|wget|curl|nc|sh|bash|whoami|id|chmod|chown)\b", re.I),
        re.compile(rb"\$\(\s*[a-z]+[^)]*\)|`[^`\n]+`|<\(\s*[a-z]+[^)]*\)"),
        re.compile(rb"(?i)\b(/bin/|/usr/bin/|/sbin/|/usr/sbin/)(sh|bash|zsh|dash|ksh|nc|ncat|cat|ls|wget|curl|chmod|chown|chsh|find|nmap)\b"),
        re.compile(rb"(?i)(bash\s+-i\s*>&\s*/dev/tcp/|/dev/tcp/[\w.]+/\d+|nc\s+(-l\s+)?-?[ev]+\s+\S+\s+\d+|python\s+-c\s+['\"]\s*import\s+(os|socket|pty))"),
        re.compile(rb"(?i)\bsocat\s+(tcp|exec|file):"),
        re.compile(rb"(?i)\b(cmd\.exe|powershell(\.exe)?\s+-(e|enc|nop|w\s+hidden|c)\b|certutil\s+-(urlcache|decode)|bitsadmin\s+/transfer|wmic\s+process\s+call|mshta\.exe|regsvr32\.exe)\b"),
        re.compile(rb"(?i)\bIEX\s*\(?\s*New-Object\s+Net\.WebClient|FromBase64String\s*\("),
    ),
}
# Per-group toggles (default ON when BODY_PATTERN_MATCH is on).
BODY_GROUP_SQLI_ENABLED = os.environ.get("BODY_GROUP_SQLI_ENABLED", "1") in ("1", "true", "yes")
BODY_GROUP_XSS_ENABLED  = os.environ.get("BODY_GROUP_XSS_ENABLED",  "1") in ("1", "true", "yes")
BODY_GROUP_LFI_ENABLED  = os.environ.get("BODY_GROUP_LFI_ENABLED",  "1") in ("1", "true", "yes")
BODY_GROUP_RCE_ENABLED  = os.environ.get("BODY_GROUP_RCE_ENABLED",  "1") in ("1", "true", "yes")
BODY_GROUP_SSRF_ENABLED = os.environ.get("BODY_GROUP_SSRF_ENABLED", "1") in ("1", "true", "yes")
BODY_GROUP_CMD_ENABLED  = os.environ.get("BODY_GROUP_CMD_ENABLED",  "1") in ("1", "true", "yes")

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

def match_body_group(body: bytes, ctype: str):
    """1.6.1 — return the first matched group name or None.
    Groups checked in order: rce → cmd → sqli → xss → lfi → ssrf
    (most-severe first so reasons dominate when patterns overlap)."""
    if not BODY_PATTERN_MATCH or not body:
        return None
    cl = ctype.lower()
    if not any(t in cl for t in ("application/json", "application/x-www-form-urlencoded",
                                  "text/plain", "text/xml", "application/xml")):
        return None
    sample = body[:65536]
    if "x-www-form-urlencoded" in cl:
        from urllib.parse import unquote_to_bytes
        sample = unquote_to_bytes(sample)
    enabled = {
        "rce":  BODY_GROUP_RCE_ENABLED,
        "cmd":  BODY_GROUP_CMD_ENABLED,
        "sqli": BODY_GROUP_SQLI_ENABLED,
        "xss":  BODY_GROUP_XSS_ENABLED,
        "lfi":  BODY_GROUP_LFI_ENABLED,
        "ssrf": BODY_GROUP_SSRF_ENABLED,
    }
    for grp in ("rce", "cmd", "sqli", "xss", "lfi", "ssrf"):
        if not enabled[grp]:
            continue
        for pat in BODY_PATTERN_GROUPS[grp]:
            if pat.search(sample):
                return grp
    return None

# ── 1.6.2: Tier C — Outbound DLP (response-side leak detection) ─────────────
# Scans upstream response bodies for sensitive data before forwarding to
# the client. Off by default. Bounded by DLP_MAX_BYTES.
DLP_ENABLED   = os.environ.get("DLP_ENABLED", "0") in ("1", "true", "yes")
DLP_REDACT    = os.environ.get("DLP_REDACT",  "0") in ("1", "true", "yes")
DLP_MAX_BYTES = int(os.environ.get("DLP_MAX_BYTES", str(256 * 1024)))   # 256 KiB

# Per-group toggles (default ON when DLP_ENABLED is on).
DLP_GROUP_CC_ENABLED          = os.environ.get("DLP_GROUP_CC_ENABLED",         "1") in ("1", "true", "yes")
DLP_GROUP_AWS_ENABLED         = os.environ.get("DLP_GROUP_AWS_ENABLED",        "1") in ("1", "true", "yes")
DLP_GROUP_JWT_ENABLED         = os.environ.get("DLP_GROUP_JWT_ENABLED",        "1") in ("1", "true", "yes")
DLP_GROUP_PRIVATE_KEY_ENABLED = os.environ.get("DLP_GROUP_PRIVATE_KEY_ENABLED","1") in ("1", "true", "yes")
DLP_GROUP_API_KEY_ENABLED     = os.environ.get("DLP_GROUP_API_KEY_ENABLED",    "1") in ("1", "true", "yes")
DLP_GROUP_PII_EMAIL_ENABLED   = os.environ.get("DLP_GROUP_PII_EMAIL_ENABLED",  "0") in ("1", "true", "yes")  # noisy by default
DLP_GROUP_PII_SSN_ENABLED     = os.environ.get("DLP_GROUP_PII_SSN_ENABLED",    "1") in ("1", "true", "yes")

DLP_PATTERN_GROUPS = {
    "cc": (
        re.compile(rb"\b(?:\d[ -]?){13,18}\d\b"),
    ),
    "aws": (
        re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(rb"\bASIA[0-9A-Z]{16}\b"),
        re.compile(rb"(?i)aws(.{0,20})?(secret|access).{0,5}key.{0,5}[:=]\s*[\"']?[A-Za-z0-9/+=]{40}"),
    ),
    "jwt": (
        re.compile(rb"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
    "private-key": (
        re.compile(rb"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ),
    "api-key": (
        re.compile(rb"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|bearer)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{32,}"),
        re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
        re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}"),
        re.compile(rb"\bsk-[A-Za-z0-9_\-]{32,}"),
    ),
    "pii-email": (
        re.compile(rb"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b"),
    ),
    "pii-ssn": (
        re.compile(rb"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    ),
}

def _luhn_check(digits: bytes) -> bool:
    """Validate the matched digit run against the Luhn checksum so phone
    numbers / order IDs don't false-match `cc`."""
    s = 0
    n = len(digits)
    for i, b in enumerate(digits):
        if not (0x30 <= b <= 0x39):
            return False
        d = b - 0x30
        if (n - 1 - i) % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0

def dlp_scan(body: bytes, ctype: str):
    """1.6.2 — return list of (group, bytes-or-str preview) hits.
    Only scans text-ish content types and bounds at DLP_MAX_BYTES."""
    if not DLP_ENABLED or not body:
        return []
    cl = (ctype or "").lower()
    if not any(t in cl for t in (
        "application/json", "application/xml", "text/", "+xml", "+json")):
        return []
    sample = body[:DLP_MAX_BYTES]
    enabled = {
        "cc":          DLP_GROUP_CC_ENABLED,
        "aws":         DLP_GROUP_AWS_ENABLED,
        "jwt":         DLP_GROUP_JWT_ENABLED,
        "private-key": DLP_GROUP_PRIVATE_KEY_ENABLED,
        "api-key":     DLP_GROUP_API_KEY_ENABLED,
        "pii-email":   DLP_GROUP_PII_EMAIL_ENABLED,
        "pii-ssn":     DLP_GROUP_PII_SSN_ENABLED,
    }
    hits = []
    for grp, pats in DLP_PATTERN_GROUPS.items():
        if not enabled.get(grp):
            continue
        for pat in pats:
            for m in pat.finditer(sample):
                raw = m.group(0)
                if grp == "cc":
                    digits = bytes(b for b in raw if 0x30 <= b <= 0x39)
                    if not (13 <= len(digits) <= 19) or not _luhn_check(digits):
                        continue
                hits.append((grp, raw[:64]))
                if len(hits) >= 8:
                    return hits
    return hits

def dlp_redact(body: bytes, hits) -> bytes:
    """1.6.2 — replace each matched bytes-string with `[REDACTED-<group>]`.
    Single pass per group; longer matches first to avoid partial overwrites."""
    if not hits:
        return body
    out = body
    seen = set()
    for grp, raw in sorted(hits, key=lambda h: -len(h[1])):
        if (grp, raw) in seen:
            continue
        seen.add((grp, raw))
        out = out.replace(raw, f"[REDACTED-{grp}]".encode())
    return out
