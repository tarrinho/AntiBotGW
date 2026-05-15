"""
reputation/maxmind.py — MaxMind GeoLite2 ASN/City lookups + AI-crawler range
                        verification + locale/geo consistency check.
Extracted from proxy.py as part of Phase 5 modular refactoring.

Local mmdb lookups (~0.1 ms each, no network). MAXMIND_ENABLED and
MAXMIND_CITY_ENABLED start False and are set to True by _init_maxmind().
"""
from __future__ import annotations

import asyncio
import os
import time as _t
from collections import deque

import aiohttp
import ipaddress as _ipaddress

from config import *   # noqa: F401,F403
from state import *    # noqa: F401,F403
from helpers import slog, now


# ── Constants ──────────────────────────────────────────────────────────────

MAXMIND_ASN_DB_PATH = os.environ.get("MAXMIND_ASN_DB_PATH", "/data/GeoLite2-ASN.mmdb")
MAXMIND_CITY_DB_PATH = os.environ.get("MAXMIND_CITY_DB_PATH", "/data/GeoLite2-City.mmdb")
HOSTING_ASN_KEYWORDS = tuple(
    s.strip().lower() for s in os.environ.get(
        "HOSTING_ASN_KEYWORDS",
        "hetzner,ovh,digitalocean,linode,contabo,vultr,scaleway,"
        "amazon,aws,google,gce,oracle,alibaba,m247,leaseweb,"
        "datacamp,packet,equinix,choopa,namecheap,colocrossing,"
        "psychz,tencent,quadranet"
    ).split(",") if s.strip())

COUNTRY_BLOCK_ENABLED = os.environ.get("COUNTRY_BLOCK_ENABLED", "0") in ("1", "true", "yes")
COUNTRY_DENYLIST = {
    s.strip().upper() for s in os.environ.get("COUNTRY_DENYLIST", "").split(",")
    if s.strip() and len(s.strip()) == 2
}
COUNTRY_ALLOWLIST = {
    s.strip().upper() for s in os.environ.get("COUNTRY_ALLOWLIST", "").split(",")
    if s.strip() and len(s.strip()) == 2
}

# ── Mutable module-level flags (set to True by _init_maxmind()) ────────────

_asn_reader = None
_city_reader = None     # GeoLite2-City reader (lat/lng for geo dashboard)
MAXMIND_ENABLED = False
MAXMIND_CITY_ENABLED = False

# ── Telemetry ──────────────────────────────────────────────────────────────

_asn_stats = {
    "lookups_total": 0, "hits_hosting": 0, "errors": 0, "last_error": "",
    "last_latency_ms": 0.0, "avg_latency_ms": 0.0,
}
_asn_recent_latencies: deque = deque(maxlen=200)


# ── Seed / fetch helpers ───────────────────────────────────────────────────

def _maxmind_seed_from_image():
    """Copy bundled mmdbs from the image's /usr/local/share/maxmind/ into
    /data/ when /data/ doesn't have them yet. The image ships fresh mmdbs at
    build time so the GeoMap dashboard works out-of-the-box on a brand-new
    volume; operators can later replace them or use MAXMIND_LICENSE_KEY to
    auto-refresh in-process every 30 days."""
    seed_dir = "/usr/local/share/maxmind"
    if not os.path.isdir(seed_dir):
        return
    pairs = [
        (os.path.join(seed_dir, "GeoLite2-ASN.mmdb"),  MAXMIND_ASN_DB_PATH),
        (os.path.join(seed_dir, "GeoLite2-City.mmdb"), MAXMIND_CITY_DB_PATH),
    ]
    for src, dest in pairs:
        if not os.path.isfile(src):
            continue
        if os.path.exists(dest):
            continue   # operator already supplied
        try:
            os.makedirs(os.path.dirname(dest) or "/data", exist_ok=True)
            with open(src, "rb") as r, open(dest, "wb") as w:
                while chunk := r.read(64 * 1024):
                    w.write(chunk)
            size_mb = os.path.getsize(dest) / (1024 * 1024)
            slog("maxmind_seeded", level="info",
                 file=os.path.basename(dest), mb=round(size_mb, 1))
        except OSError as e:
            slog("maxmind_seed_failed", level="warn", dest=dest, error=str(e))


def _etag_path(mmdb_path: str) -> str:
    return mmdb_path + ".etag"


def _read_etag(mmdb_path: str) -> str:
    try:
        return open(_etag_path(mmdb_path)).read().strip()
    except OSError:
        return ""


def _write_etag(mmdb_path: str, etag: str) -> None:
    try:
        with open(_etag_path(mmdb_path), "w") as f:
            f.write(etag)
    except OSError:
        pass


def _maxmind_fetch_edition(edition: str, dest: str, key: str,
                           force: bool = False) -> str:
    """Download one MaxMind edition with ETag-based conditional HTTP.

    Returns: 'downloaded' | 'not_modified' | 'skipped' | 'error'

    Uses `If-None-Match` with the stored ETag so MaxMind returns 304 Not
    Modified when the database hasn't changed — 304 responses don't count
    toward the daily download limit (2000/day for GeoLite2).

    force=True: always attempt (used by refresh loop for stale files).
    force=False: skip if dest already exists (auto_fetch first-boot path).
    """
    import urllib.request, urllib.error, tarfile, tempfile
    if not force and os.path.exists(dest):
        return "skipped"
    etag = _read_etag(dest)
    url = (f"https://download.maxmind.com/app/geoip_download"
           f"?edition_id={edition}&license_key={key}&suffix=tar.gz")
    req = urllib.request.Request(url)  # nosec B310 — hardcoded HTTPS to MaxMind
    if etag:
        req.add_header("If-None-Match", etag)
    try:
        slog("maxmind_checking", level="info", edition=edition,
             conditional=bool(etag))
        with urllib.request.urlopen(req, timeout=60) as r:  # nosec B310 — hardcoded HTTPS to MaxMind
            if r.status == 304:
                # Database unchanged — touch mtime so staleness clock resets.
                if os.path.exists(dest):
                    os.utime(dest, None)
                slog("maxmind_not_modified", level="info", edition=edition)
                return "not_modified"
            if r.status != 200:
                slog("maxmind_download_http_err", level="warn",
                     edition=edition, status=r.status)
                return "error"
            new_etag = r.headers.get("ETag", "")
            with tempfile.TemporaryDirectory() as td:
                tgz = os.path.join(td, f"{edition}.tar.gz")
                with open(tgz, "wb") as f:
                    while chunk := r.read(64 * 1024):
                        f.write(chunk)
                with tarfile.open(tgz) as tar:
                    member = next(
                        (m for m in tar.getmembers()
                         if m.isfile() and m.name.endswith(f"{edition}.mmdb")),
                        None,
                    )
                    if member is None:
                        slog("maxmind_not_in_archive", level="warn",
                             edition=edition)
                        return "error"
                    fobj = tar.extractfile(member)
                    if fobj is None:
                        return "error"
                    os.makedirs(os.path.dirname(dest) or "/data", exist_ok=True)
                    with open(dest, "wb") as out:
                        while chunk := fobj.read(64 * 1024):
                            out.write(chunk)
            if new_etag:
                _write_etag(dest, new_etag)
        size_mb = os.path.getsize(dest) / (1024 * 1024)
        slog("maxmind_downloaded", level="info",
             edition=edition, dest=dest, mb=round(size_mb, 1))
        return "downloaded"
    except urllib.error.HTTPError as e:
        if e.code == 304:
            if os.path.exists(dest):
                os.utime(dest, None)
            slog("maxmind_not_modified", level="info", edition=edition)
            return "not_modified"
        slog("maxmind_fetch_failed", level="warn", edition=edition,
             error=str(e))
        return "error"
    except (urllib.error.URLError, OSError, tarfile.TarError) as e:
        slog("maxmind_fetch_failed", level="warn", edition=edition, error=str(e))
        return "error"


def _maxmind_auto_fetch():
    """First-boot convenience. When MAXMIND_LICENSE_KEY is set AND a target
    mmdb is missing, download it directly from MaxMind into /data/<edition>.mmdb.
    Uses ETag-based conditional HTTP — 304 Not Modified skips the download
    and doesn't count toward MaxMind's daily limit."""
    key = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
    if not key:
        return
    targets = [
        ("GeoLite2-ASN",  MAXMIND_ASN_DB_PATH),
        ("GeoLite2-City", MAXMIND_CITY_DB_PATH),
    ]
    for edition, dest in targets:
        _maxmind_fetch_edition(edition, dest, key, force=False)


async def _maxmind_refresh_loop():
    """Every 30 days, re-fetch any mmdb older than that AND reload the
    in-memory readers. Uses ETag-based conditional HTTP so unchanged databases
    return 304 Not Modified without counting toward MaxMind's daily limit."""
    global _asn_reader, _city_reader, MAXMIND_ENABLED, MAXMIND_CITY_ENABLED
    key = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
    if not key:
        return  # nothing to refresh — operator hasn't opted in
    THIRTY_DAYS = 30 * 86400
    while True:
        await asyncio.sleep(86400)   # check daily, refresh monthly
        try:
            stale = []
            for path in (MAXMIND_ASN_DB_PATH, MAXMIND_CITY_DB_PATH):
                if os.path.exists(path) and (_t.time() - os.path.getmtime(path)) > THIRTY_DAYS:
                    stale.append(path)
            if not stale:
                continue
            slog("maxmind_refreshing_stale", level="info", stale_count=len(stale))
            reloaded = False
            for path in stale:
                edition = "GeoLite2-ASN" if "ASN" in path else "GeoLite2-City"
                result = _maxmind_fetch_edition(edition, path, key, force=True)
                if result in ("downloaded", "not_modified"):
                    reloaded = True
            if not reloaded:
                continue
            try:
                import maxminddb
                if os.path.exists(MAXMIND_ASN_DB_PATH):
                    _asn_reader = maxminddb.open_database(MAXMIND_ASN_DB_PATH)
                    MAXMIND_ENABLED = True
                if os.path.exists(MAXMIND_CITY_DB_PATH):
                    _city_reader = maxminddb.open_database(MAXMIND_CITY_DB_PATH)
                    MAXMIND_CITY_ENABLED = True
                slog("maxmind_readers_refreshed", level="info")
            except Exception as e:
                slog("maxmind_reload_failed", level="error", error=str(e))
        except Exception as e:
            slog("maxmind_refresh_loop_error", level="error", error=str(e))


def _init_maxmind():
    """Lazy-load the mmdb. Called at startup; logs and stays disabled if
    the file is missing or malformed. Auto-fetches the dbs first when
    MAXMIND_LICENSE_KEY is set and /data/ doesn't already have them.
    Also seeds from the image-bundled mmdbs at /usr/local/share/maxmind/."""
    global _asn_reader, _city_reader, MAXMIND_ENABLED, MAXMIND_CITY_ENABLED
    _maxmind_seed_from_image()
    _maxmind_auto_fetch()
    try:
        import maxminddb
    except Exception as e:
        slog("maxmind_lib_missing", level="warn", error=str(e))
        return
    if os.path.exists(MAXMIND_ASN_DB_PATH):
        try:
            _asn_reader = maxminddb.open_database(MAXMIND_ASN_DB_PATH)
            MAXMIND_ENABLED = True
            slog("maxmind_asn_loaded", level="info", path=MAXMIND_ASN_DB_PATH)
        except Exception as e:
            _asn_stats["last_error"] = f"init: {e}"[:200]
            slog("maxmind_asn_load_failed", level="error",
                 path=MAXMIND_ASN_DB_PATH, error=str(e))
    if os.path.exists(MAXMIND_CITY_DB_PATH):
        try:
            _city_reader = maxminddb.open_database(MAXMIND_CITY_DB_PATH)
            MAXMIND_CITY_ENABLED = True
            slog("maxmind_city_loaded", level="info", path=MAXMIND_CITY_DB_PATH)
        except Exception as e:
            slog("maxmind_city_load_failed", level="error",
                 path=MAXMIND_CITY_DB_PATH, error=str(e))


# ── Lookup cache ───────────────────────────────────────────────────────────
# Keyed by IP string. ASN / city data changes at most monthly; 1-hour TTL
# is more than sufficient. Max 8 192 entries (~10 MB) — FIFO eviction via
# dict insertion order (Python 3.7+). Disabled/error results are not cached
# so a missing mmdb at startup doesn't permanently poison the cache.

_LOOKUP_CACHE_TTL  = 86400  # seconds (24 h — ASN/geo data stable for days)
_LOOKUP_CACHE_MAX  = 8192   # entries

_asn_cache:  dict = {}      # ip → (result_tuple, expiry)
_city_cache: dict = {}      # ip → (result_tuple, expiry)


def _cache_get(cache: dict, ip: str):
    entry = cache.get(ip)
    if entry and entry[1] > _t.time():
        return entry[0]
    return None


def _cache_put(cache: dict, ip: str, result) -> None:
    if len(cache) >= _LOOKUP_CACHE_MAX:
        cache.pop(next(iter(cache)))
    cache[ip] = (result, _t.time() + _LOOKUP_CACHE_TTL)


# ── Lookup functions ───────────────────────────────────────────────────────

def _city_lookup(ip: str):
    """Return (lat, lng, country_code, city_name) or None if unknown.
    City DB lookup latency ~0.1ms — same DB family as ASN. Results cached
    for _LOOKUP_CACHE_TTL seconds to avoid redundant mmdb reads per request."""
    if not ip:
        return None
    cached = _cache_get(_city_cache, ip)
    if cached is not None:
        return cached
    if _city_reader is None:
        return None
    try:
        rec = _city_reader.get(ip)
        if not rec:
            return None
        loc = rec.get("location") or {}
        lat = loc.get("latitude"); lng = loc.get("longitude")
        if lat is None or lng is None:
            return None
        country = (rec.get("country") or {}).get("iso_code") or ""
        city    = ((rec.get("city") or {}).get("names") or {}).get("en") or ""
        result = (float(lat), float(lng), country, city)
        _cache_put(_city_cache, ip, result)
        return result
    except Exception:
        return None


def _asn_lookup(ip: str):
    """Returns (asn:int|None, organisation:str, is_hosting:bool, source:str).
    Results cached for _LOOKUP_CACHE_TTL seconds; disabled/error not cached."""
    if not MAXMIND_ENABLED or _asn_reader is None:
        return None, "", False, "disabled"
    try:
        ipa = _ipaddress.ip_address(ip)
        if ipa.is_private or ipa.is_loopback or ipa.is_link_local:
            return None, "", False, "private"
    except (ValueError, TypeError):
        return None, "", False, "invalid"
    cached = _cache_get(_asn_cache, ip)
    if cached is not None:
        return cached
    _asn_stats["lookups_total"] += 1
    t0 = _t.time()
    try:
        rec = _asn_reader.get(ip) or {}
    except Exception as e:
        _asn_stats["errors"] += 1
        _asn_stats["last_error"] = f"{type(e).__name__}: {str(e)[:120]}"
        return None, "", False, "error"
    finally:
        latency_ms = (_t.time() - t0) * 1000.0
        _asn_stats["last_latency_ms"] = round(latency_ms, 3)
        _asn_recent_latencies.append(latency_ms)
        if _asn_recent_latencies:
            _asn_stats["avg_latency_ms"] = round(
                sum(_asn_recent_latencies) / len(_asn_recent_latencies), 3)
    asn = rec.get("autonomous_system_number")
    org = (rec.get("autonomous_system_organization") or "")[:120]
    org_lower = org.lower()
    is_hosting = any(k in org_lower for k in HOSTING_ASN_KEYWORDS)
    if is_hosting:
        _asn_stats["hits_hosting"] += 1
    result = asn, org, is_hosting, "ok"
    _cache_put(_asn_cache, ip, result)
    return result


# ── AI-crawler IP-range verification ──────────────────────────────────────
# OpenAI publishes their crawler IP ranges at openai.com/gptbot-ranges.txt.
# When a request claims to be an OpenAI/Perplexity crawler (UA match) but
# the source IP is not in the declared range, we add ai-ua-ip-mismatch (+30).

_ai_crawler_nets: dict = {}          # vendor → list[ip_network]; populated at startup
_AI_CRAWLER_RANGE_URLS = {
    "openai": "https://openai.com/gptbot-ranges.txt",  # nosec B310
}


async def _refresh_ai_crawler_ranges():
    """Fetch published IP ranges for AI crawlers and refresh every 24 h."""
    while True:
        for vendor, url in _AI_CRAWLER_RANGE_URLS.items():
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as _s:
                    async with _s.get(url) as _r:
                        if _r.status == 200:
                            text = await _r.text()
                            nets = []
                            for _line in text.splitlines():
                                _line = _line.strip()
                                if _line and not _line.startswith("#"):
                                    try:
                                        nets.append(_ipaddress.ip_network(_line, strict=False))
                                    except ValueError:
                                        pass
                            _ai_crawler_nets[vendor] = nets
                            slog("ai_ranges_refreshed", level="info",
                                 vendor=vendor, count=len(nets))
            except Exception as _e:
                slog("ai_ranges_failed", level="warn",
                     vendor=vendor, error=str(_e)[:80])
        await asyncio.sleep(86400)


def _ip_in_ai_range(ip: str, vendor: str) -> bool:
    """True if ip is in vendor's published crawler range (or range unknown)."""
    nets = _ai_crawler_nets.get(vendor, [])
    if not nets:
        return True   # no data loaded — can't verify, don't penalise
    try:
        ipa = _ipaddress.ip_address(ip)
        return any(ipa in net for net in nets)
    except (ValueError, TypeError):
        return True   # unparseable IP → don't penalise


# ── Accept-Language / GeoIP locale consistency ────────────────────────────
# Map ISO-3166 country code → set of plausible primary language tags.
# Only covers codes with a single dominant language; multi-lingual countries
# are excluded (avoiding false-positives on CH, BE, CA, SG, etc.).

_COUNTRY_LANG_MAP: dict = {
    "US": {"en"}, "GB": {"en"}, "AU": {"en"}, "NZ": {"en"}, "IE": {"en"},
    "FR": {"fr"}, "DE": {"de"}, "AT": {"de"},
    "ES": {"es"}, "MX": {"es"}, "AR": {"es"}, "CO": {"es"}, "CL": {"es"},
    "PT": {"pt"}, "BR": {"pt"},
    "IT": {"it"}, "RU": {"ru"}, "UA": {"uk"},
    "CN": {"zh"}, "TW": {"zh"}, "JP": {"ja"}, "KR": {"ko"},
    "NL": {"nl"}, "PL": {"pl"}, "SE": {"sv"}, "NO": {"no", "nb"},
    "DK": {"da"}, "FI": {"fi"}, "CZ": {"cs"}, "HU": {"hu"}, "RO": {"ro"},
    "TR": {"tr"}, "SA": {"ar"}, "AE": {"ar"}, "EG": {"ar"},
    "TH": {"th"}, "VN": {"vi"}, "ID": {"id"},
}


def _locale_geo_mismatch(country_code: str, accept_lang: str) -> bool:
    """True when primary Accept-Language tag is implausible for the GeoIP country.
    Returns False when the country or language is unknown (avoids false-positives).
    'en' is treated as a universal fallback and never flagged as a mismatch."""
    expected = _COUNTRY_LANG_MAP.get((country_code or "").upper())
    if not expected:
        return False
    primary = accept_lang.split(",")[0].split(";")[0].strip().split("-")[0].lower()
    if not primary or primary in ("*", "en"):
        return False
    return primary not in expected
