"""
state.py — All mutable global state: dicts, deques, locks, IpState dataclass.
Extracted from proxy.py as part of Phase 1 modular refactoring.

Dependency rule: imports from config.py only (no other project imports).
"""

import asyncio
import time
from collections import defaultdict, deque, OrderedDict
from dataclasses import dataclass, field
from typing import Dict

from config import (
    RATE_LIMIT_BURST,
    SERVICE_METRICS_RETENTION,
    MAX_IDENTITIES,
)

# ── IpState dataclass ──────────────────────────────────────────────────────
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
    # 1.5.4: per-reason contribution to risk_score (decays in lockstep).
    risk_by_reason: dict = field(default_factory=lambda: defaultdict(float))
    # Stealth-agent telemetry (allowed traffic only — used by /__agents)
    header_scores: deque = field(default_factory=lambda: deque(maxlen=20))
    upstream_404_count: int = 0
    last_allowed_paths: deque = field(default_factory=lambda: deque(maxlen=10))
    # 1.7.1 — journey sequence for direct-API-probe detection
    path_sequence: deque = field(default_factory=lambda: deque(maxlen=5))
    # 1.7.2 — cookie lifecycle tracking
    gateway_cookies_set: int = 0
    cookie_ghost_misses: int = 0
    # 1.7.2 — HTML paths served to this identity (referer-ghost check)
    served_html_paths: set = field(default_factory=set)
    # 1.7.2 — impossible travel
    last_country: str = ""
    last_country_ts: float = 0.0
    # 1.7.2 — service worker enrichment
    sw_seen: bool = False
    # 1.7.3 — path-sweep: sliding window of (monotonic_ts, path) for non-static paths
    path_sweep_times: deque = field(default_factory=lambda: deque(maxlen=500))
    # 1.8.0 — last vhost hostname this identity was seen on (empty = global upstream)
    last_vhost: str = ""


# ── Primary identity state ─────────────────────────────────────────────────
_IP_STATE_MAX = MAX_IDENTITIES


class _BoundedIpStateDict:
    """LRU-capped dict of IpState objects. Thread-safe via state_lock.
    Evicts oldest entries when capacity is reached. Allows defaultdict-like
    access: missing keys auto-create a fresh IpState."""

    def __init__(self, maxsize: int = 50000):
        self._data: OrderedDict = OrderedDict()
        self._maxsize = maxsize

    def __getitem__(self, key: str) -> "IpState":
        if key not in self._data:
            self._data[key] = IpState()
            self._data.move_to_end(key)
            if len(self._data) > self._maxsize:
                self._data.popitem(last=False)
        else:
            self._data.move_to_end(key)
        return self._data[key]

    def __setitem__(self, key: str, value: "IpState"):
        self._data[key] = value
        self._data.move_to_end(key)
        if len(self._data) > self._maxsize:
            self._data.popitem(last=False)

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def get(self, key: str, default=None):
        if key in self._data:
            self._data.move_to_end(key)
            return self._data[key]
        return default

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()

    def keys(self):
        return self._data.keys()

    def __delitem__(self, key: str):
        del self._data[key]

    def setdefault(self, key: str, default: "IpState | None" = None) -> "IpState":
        if key not in self._data:
            val = default if default is not None else IpState()
            self[key] = val
        return self._data[key]

    def pop(self, key: str, *args):
        return self._data.pop(key, *args)

    def clear(self):
        self._data.clear()

    def evict_expired(self, ttl_secs: float = 3600.0):
        """Remove entries not seen within ttl_secs. Call from background task."""
        import time as _time
        cutoff = _time.monotonic() - ttl_secs
        stale = [k for k, v in self._data.items() if v.last_seen < cutoff]
        for k in stale:
            del self._data[k]
        return len(stale)


ip_state: _BoundedIpStateDict = _BoundedIpStateDict(maxsize=_IP_STATE_MAX)
state_lock = asyncio.Lock()

_ip_state_eviction_task = None


async def _ip_state_evict_loop(ttl_secs: float = 3600.0, interval_secs: float = 300.0):
    """Background task: evict IpState entries not seen in ttl_secs."""
    from helpers import slog
    while True:
        await asyncio.sleep(interval_secs)
        try:
            evicted = ip_state.evict_expired(ttl_secs)
            if evicted:
                slog("ip_state_evicted", level="info", count=evicted,
                     remaining=len(ip_state))
        except Exception:
            pass

# Inverted index: ip → set of track_keys whose last_ip == ip.
# Maintained at every last_ip write site; allows O(1) NAT-detection lookup
# instead of a linear scan over all of ip_state.
ip_to_identities: Dict[str, set] = defaultdict(set)

# Per-IP session-creation tracking — maps ip → {identity: last_seen_ts}.
ip_new_sessions: Dict[str, dict] = defaultdict(dict)

# Per-socket-IP token-bucket dict
ip_buckets: Dict[str, dict] = {}

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
events = deque(maxlen=200)            # last 200 events for path-filter scanning
events_by_cat: dict = {               # per-category ring buffers — never crowd each other out
    "allowed":  deque(maxlen=50),
    "ban":      deque(maxlen=50),
    "missed":   deque(maxlen=50),
    "authbots": deque(maxlen=50),
    "gwmgmt":   deque(maxlen=50),
}
by_path_by_cat: dict = {              # per-category path hit counters (mirrors events_by_cat keys)
    "allowed":  defaultdict(int),
    "ban":      defaultdict(int),
    "missed":   defaultdict(int),
    "authbots": defaultdict(int),
    "gwmgmt":   defaultdict(int),
}

# ── Global RPS window ─────────────────────────────────────────────────────
_global_rps_window: deque = deque(maxlen=20000)   # timestamps within the last 1s

# ── Async DB writer queue ──────────────────────────────────────────────────
# Initialized as None; on_startup() assigns asyncio.Queue(maxsize=10000)
db_queue: asyncio.Queue = None
db_writer_task = None
prune_task = None
service_metrics_task = None

# ── Timeline: per-minute buckets ──────────────────────────────────────────
timeline = {}                  # {minute_epoch_int: {"total","blocked","allowed","by_reason":{}}}
cost_timeline: dict = {}

# ── Service metrics history ────────────────────────────────────────────────
SERVICE_METRICS_HISTORY: deque = deque(maxlen=SERVICE_METRICS_RETENTION)

# ── 1.6.3: In-memory ring buffer for the Logs dashboard ───────────────────
_GW_LOG_RING: deque = deque(maxlen=2000)

# ── Cache of the local gateway's id ───────────────────────────────────────
_LOCAL_GW_ID: str = ""

# ── 1.6.10: per-gateway signal-order overrides ────────────────────────────
_signal_order_cache: dict[str, int] = {}

# ── PoW seen-pairs: {(token, solution): expires_at_epoch} ─────────────────
_pow_seen: Dict[tuple, float] = {}

# ── 1.7.2 — canvas fingerprint store: identity → {canvas, renderer, vendor, ts}
_fp_canvas_store: dict = {}

# ── AI-agent canary tokens: token -> expiry_epoch ─────────────────────────
_canary_tokens: dict = {}

# ── 1.7.1: Coordinated-attack clustering ─────────────────────────────────
# (asn:int|None, path_prefix:str, minute:int) → set of identity strings
_asn_path_clusters: dict = {}

# ── Admin session management ───────────────────────────────────────────────
# 1.6.7 — last-seen-ts per signed-in user. Bumped on every cookie-
# authenticated request inside `_internal_authed`.
_ACTIVE_SESSIONS: dict = {}            # username → last_seen_ts
_ACTIVE_SESSION_TTL_S = 60

# ── Login rate-limit bucket ────────────────────────────────────────────────
_LOGIN_BUCKET: dict = {}               # ip → (window_start, count)
_LOGIN_BUCKET_LOCK = asyncio.Lock()

# ── Postgres state (lazy-initialized) ─────────────────────────────────────
_postgres_pool = None
_postgres_available = False
_postgres = None     # the psycopg module reference

# ── Redis client (lazy-initialized) ───────────────────────────────────────
_redis = None  # lazy-initialised singleton; None if disabled or unavailable
