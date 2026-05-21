# dashboards/service_metrics.py — Phase 8: service metrics sampling + dashboard
# Extracted from proxy.py lines 2341–2604, 11154–11317
import time as _t  # noqa: F401 — used in _sample_service_metrics_loop
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR  # noqa: F401 — leading-underscore not in *
from state import *    # noqa: F401,F403
from state import _postgres_available  # noqa: F401 — underscore not exported by *
from helpers import slog, now  # noqa: F401
from admin.auth import _internal_authed  # noqa: F401
from aiohttp import web

SERVICE_METRICS_INTERVAL  = float(os.environ.get("SVC_METRICS_INTERVAL", "5"))   # secs
SERVICE_METRICS_RETENTION = int(os.environ.get("SVC_METRICS_RETENTION", "8640"))  # in-mem samples
SVC_DB_RETENTION_HOURS    = int(os.environ.get("SVC_DB_RETENTION_HOURS", "720"))  # on-disk retention

_PROC      = "/proc"
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
                # 1.6.7+ — app-level counters so the click-to-zoom charts
                # on the Service dashboard work for the Identities + Requests
                # cards. Cheap reads — `len(ip_state)` is O(1).
                "identities_count": len(ip_state),
                "total_requests":   metrics.get("total_requests", 0),
                **{f"db_{k}": v for k, v in _db_file_sizes().items()},
            }
            # 1.6.5 — sample pg_database_size + events row count once per
            # minute whenever POSTGRES_DSN is set (regardless of which
            # backend is active). Lets the Service dashboard plot the
            # Postgres size trend even on an SQLite gateway that has a
            # standby Timescale ready to switch to.
            #
            # Between the per-minute live samples, we carry forward the
            # LAST KNOWN value so every persisted row has the field
            # populated — otherwise the chart's bucket aggregator sees
            # mostly zeros and renders a spiky / empty line.
            if _postgres_available and POSTGRES_DSN:
                if (int(_t.time()) // 60) != getattr(
                        _sample_service_metrics_loop, "_last_pg_min", -1):
                    try:
                        pg_info = pg_db_size()
                        if pg_info.get("ok"):
                            sample["pg_db_bytes"]      = pg_info["db_bytes"]
                            sample["pg_events_rows"]   = pg_info["events_rows"]
                            sample["pg_index_bytes"]   = pg_info["index_bytes"]
                            sample["pg_active_conns"]  = pg_info["active_conns"]
                            sample["pg_idle_conns"]    = pg_info["idle_conns"]
                            sample["pg_cache_hit_pct"] = pg_info["cache_hit_pct"]
                            sample["pg_tx_total"]      = pg_info["tx_total"]
                            _sample_service_metrics_loop._pg_last = pg_info
                        setattr(_sample_service_metrics_loop, "_last_pg_min",
                                int(_t.time()) // 60)
                    except Exception:
                        pass
                last = getattr(_sample_service_metrics_loop, "_pg_last", None)
                if last and "pg_db_bytes" not in sample:
                    sample["pg_db_bytes"]      = last["db_bytes"]
                    sample["pg_events_rows"]   = last["events_rows"]
                    sample["pg_index_bytes"]   = last.get("index_bytes", 0)
                    sample["pg_active_conns"]  = last.get("active_conns", 0)
                    sample["pg_idle_conns"]    = last.get("idle_conns", 0)
                    sample["pg_cache_hit_pct"] = last.get("cache_hit_pct", 0.0)
                    sample["pg_tx_total"]      = last.get("tx_total", 0)
            SERVICE_METRICS_HISTORY.append(sample)

            # Persist to SQLite via the async writer so chart history survives
            # container restarts. Tuple matches the svc_metrics column order.
            # 1.6.5: appended pg_db_bytes + pg_events_rows.
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
                    sample.get("pg_db_bytes"), sample.get("pg_events_rows"),
                    sample.get("identities_count", 0),
                    sample.get("total_requests", 0),
                    # 1.6.8 — TimescaleDB stats
                    sample.get("pg_index_bytes", 0),
                    sample.get("pg_active_conns", 0),
                    sample.get("pg_idle_conns", 0),
                    sample.get("pg_cache_hit_pct", 0.0),
                    sample.get("pg_tx_total", 0),
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


# ── DB-backed history (ranges beyond the in-memory buffer) ──────────────
def _svc_db_history(start_b: int, end_b: int, bucket_secs: int,
                    avg_keys: tuple, max_keys: tuple, sum_keys: tuple) -> list:
    """Query svc_metrics from SQLite, bucket-aggregated in SQL.

    Called only when the requested window extends beyond SERVICE_METRICS_HISTORY.
    Returns the same list-of-dicts structure as the in-memory bucketing path so
    the rest of the endpoint is unchanged.

    Aggregation rules (mirror the in-memory path):
      avg_keys  → AVG   (pcts, loads, ratios)
      max_keys  → MAX   (counters, gauges, sizes)
      sum_keys  → AVG   (net bps — sampled per-second, so AVG = correct mean rate)

    bucket_secs is validated by the caller to be in {5,30,60,300,900,3600}, so
    embedding it in the SQL string is safe (no user-controlled data in the SQL).
    """
    import sqlite3 as _sq3
    b = bucket_secs
    avg_sel = ", ".join(
        f"ROUND(AVG(COALESCE({k},0)),2) AS {k}" for k in avg_keys)
    max_sel = ", ".join(
        f"MAX(COALESCE({k},0)) AS {k}"           for k in max_keys)
    sum_sel = ", ".join(
        f"ROUND(AVG(COALESCE({k},0))) AS {k}"    for k in sum_keys)
    sql = (
        f"SELECT (CAST(ts/{b} AS INTEGER)*{b}) AS ts, "
        f"{avg_sel}, {max_sel}, {sum_sel} "
        f"FROM svc_metrics WHERE ts>=? AND ts<=? "
        f"GROUP BY CAST(ts/{b} AS INTEGER) ORDER BY ts"
    )
    db_buckets: dict = {}
    try:
        conn = _sq3.connect(_DATA_PATH)
        conn.row_factory = _sq3.Row
        for row in conn.execute(sql, (start_b, end_b + b)).fetchall():
            bt = int(row["ts"])
            db_buckets[bt] = row
        conn.close()
    except Exception as _ex:
        print(f"[svc-metrics] db history error: {_ex}", flush=True)

    zero = {k: 0 for k in avg_keys + max_keys + sum_keys}
    history: list = []
    for bt in range(start_b, end_b + 1, b):
        row = db_buckets.get(bt)
        if row is None:
            history.append({"ts": bt, **zero})
        else:
            out: dict = {"ts": bt}
            for k in avg_keys:
                out[k] = round(float(row[k] or 0), 2)
            for k in max_keys:
                out[k] = int(row[k] or 0)
            for k in sum_keys:
                out[k] = int(row[k] or 0)
            history.append(out)
    return history


# ── Service-metrics dashboard endpoints (admin-gated) ───────────────────
async def service_metrics_data_endpoint(request: web.Request):
    """JSON: latest sample + a windowed view of the retention buffer.
    Query params (all optional):
      ?range=N    — window length in minutes (5..720, default 60)
      ?bucket=S   — bucket width in seconds (5,30,60,300,900,3600 — default 5)
      ?end=EPOCH  — right edge of the window (default = now / live)
      ?vhost=H    — filter traffic counters to a single vhost (system metrics stay global)
    Samples within each bucket are averaged for cpu/mem/disk pct, max'd for
    counters (procs/fds/db_size), summed for net throughput."""
    _vhost = request.query.get("vhost", "").strip().lower()
    _mem_raw = list(SERVICE_METRICS_HISTORY)
    current = _mem_raw[-1] if _mem_raw else {}

    try:
        # 1.6.5 — range cap raised from 720 → 43200 (30 d) so the
        # Service dashboard's longer windows have data to plot.
        range_min = max(1, min(43200, int(request.query.get("range", "60"))))
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
        _end_str = request.query.get("end", "")
        if not _end_str or _end_str.lower() in ("nan", "inf", "-inf", "+inf", "infinity", "-infinity"):
            raise ValueError("non-numeric")
        end_epoch = float(_end_str)
    except ValueError:
        end_epoch = _t.time()

    end_b   = (int(end_epoch) // bucket_secs) * bucket_secs
    window  = range_min * 60
    start_b = end_b - window + bucket_secs

    # Bucketise: average pcts/loads, max for counters, sum/per-window for net.
    AVG_KEYS  = ("cpu_pct", "mem_pct", "swap_used", "load1", "load5", "load15",
                 "disk_pct", "cg_pct", "mem_used", "disk_used",
                 # 1.6.8: PG cache-hit ratio (averaged across the bucket)
                 "pg_cache_hit_pct")
    MAX_KEYS  = ("procs", "open_fds", "db_db", "db_wal", "db_shm", "db_total",
                 "cg_used", "cg_limit", "mem_total", "disk_total", "disk_avail",
                 "swap_total",
                 # 1.6.5: Postgres / TimescaleDB size + events rows
                 "pg_db_bytes", "pg_events_rows",
                 # 1.6.7+: app-level counters (identities live + requests total)
                 "identities_count", "total_requests",
                 # 1.6.8: PG/Timescale stats (counters/gauges → max within bucket)
                 "pg_index_bytes", "pg_active_conns", "pg_idle_conns",
                 "pg_tx_total")
    SUM_KEYS  = ("net_rx_bps", "net_tx_bps")

    # When the requested window extends beyond what the in-memory deque holds,
    # delegate to SQLite (which retains SVC_DB_RETENTION_HOURS, default 30 d).
    # The DB path aggregates in SQL so we never load O(500k) raw rows into Python.
    _buf_oldest = _mem_raw[0].get("ts", float("inf")) if _mem_raw else float("inf")
    if start_b < _buf_oldest:
        history = _svc_db_history(start_b, end_b, bucket_secs,
                                  AVG_KEYS, MAX_KEYS, SUM_KEYS)
    else:
        buckets: dict = {}
        for s in _mem_raw:
            ts = int(s.get("ts", 0))
            if ts < start_b or ts > end_b + bucket_secs:
                continue
            b = (ts // bucket_secs) * bucket_secs
            slot = buckets.setdefault(b, {"_n": 0, "ts": b})
            slot["_n"] += 1
            for k in AVG_KEYS + MAX_KEYS + SUM_KEYS:
                # 1.6.5 — None handling: pg_db_bytes / pg_events_rows can be
                # None on samples taken before the standby PG was probed.
                # Coerce to 0 for arithmetic (max / sum) — the carry-forward
                # logic in _sample_service_metrics_loop populates the value
                # on every subsequent tick once the first probe lands.
                v = s.get(k)
                if v is None:
                    v = 0
                if k in MAX_KEYS:
                    cur = slot.get(k, 0)
                    if cur is None:
                        cur = 0
                    slot[k] = max(cur, v)
                else:
                    cur = slot.get(k, 0)
                    if cur is None:
                        cur = 0
                    slot[k] = cur + v

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
        if _vhost:
            identities = sum(1 for s in ip_state.values()
                             if (getattr(s, "last_vhost", "") or "").lower() == _vhost)

    # Per-vhost traffic counters from events table (when vhost filter is active).
    vhost_total = vhost_allowed = vhost_blocked = None
    if _vhost:
        try:
            import sqlite3 as _sq3
            _win_start = end_b - window
            conn = _sq3.connect(_DATA_PATH)
            row = conn.execute(
                "SELECT COUNT(*), "
                "SUM(CASE WHEN reason IN ('ok','allowed','authorized-robot') THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN reason NOT IN ('ok','allowed','authorized-robot','operator-passthrough','internal-probe','operator-self') THEN 1 ELSE 0 END) "
                "FROM events WHERE ts >= ? AND ts <= ? AND vhost = ?",
                (_win_start, end_b + bucket_secs, _vhost),
            ).fetchone()
            conn.close()
            if row and row[0]:
                vhost_total, vhost_allowed, vhost_blocked = int(row[0]), int(row[1] or 0), int(row[2] or 0)
        except Exception:
            pass

    app_info = {
        "uptime_secs":     int(_t.time() - START_EPOCH),
        "total_requests":  vhost_total   if _vhost and vhost_total   is not None else metrics["total_requests"],
        "allowed":         vhost_allowed if _vhost and vhost_allowed is not None else metrics["allowed"],
        "blocked":         vhost_blocked if _vhost and vhost_blocked is not None else metrics["blocked"],
        "identities":      identities,
        "ip_buckets":      ip_buckets_n,
        "events_buffered": len(events),
        "version":         GW_VERSION,
        "vhost_filter":    _vhost or None,
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
        "samples_in_buffer": len(_mem_raw),
        "buffer_oldest_ts": _mem_raw[0]["ts"] if _mem_raw else 0,
        # 1.6.8 — TimescaleDB stats availability flag. Used by the
        # Service dashboard to hide the TimescaleDB section when no
        # POSTGRES_DSN is configured (or psycopg never loaded).
        "pg_available":     bool(_postgres_available and POSTGRES_DSN),
    }, headers={"Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff"})


SERVICE_DASHBOARD_HTML = (_DASHBOARDS_DIR / "service.html").read_text(encoding="utf-8")


async def service_dashboard_endpoint(request: web.Request):
    body = SERVICE_DASHBOARD_HTML
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
                "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'"
            ),
        },
    )
