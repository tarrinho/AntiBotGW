# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
# admin/settings.py — Phase 8: settings export/import + settings dashboard
# Extracted from proxy.py lines 11284–11612
import time as _t       # noqa: F401
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR, _DATA_PATH  # noqa: F401 — leading-underscore not in *
from state import *    # noqa: F401,F403
from helpers import slog  # noqa: F401
from admin.auth import _internal_authed, ADMIN_ALLOWED_ENTRIES, _role_denied, _request_username  # noqa: F401
from admin.mesh import _gw_audit, _gw_local_id  # noqa: F401
from aiohttp import web

SETTINGS_DASHBOARD_HTML = (_DASHBOARDS_DIR / "settings.html").read_text(encoding="utf-8")


async def settings_dashboard_endpoint(request: web.Request):
    """GET /__settings — render the Settings dashboard (admin-only)."""
    if denied := _role_denied(request, "admin"):
        return denied
    body = SETTINGS_DASHBOARD_HTML
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
        })


def _settings_build_xml(include_secrets: bool) -> bytes:
    """Serialise current hot-reload state + admin-IPs (and optionally
    secrets) into a self-describing XML document. Kept stdlib-only — no
    external XML deps in the runtime image. Returns UTF-8 encoded bytes."""
    import xml.etree.ElementTree as _ET
    import sys as _sys_exp
    try:
        from core.proxy_handler import _read_hot_reload_state, _SECRET_KEYS
        _proxy_mod = _sys_exp.modules.get("core.proxy_handler")
        g = vars(_proxy_mod) if _proxy_mod else {}
    except Exception:
        _read_hot_reload_state = lambda: {}  # noqa: E731
        _SECRET_KEYS = {}
        g = {}

    root = _ET.Element("appsecgw-config", attrib={
        "version": "1.6.5",
        "exported_at": str(int(_t.time())),
    })
    knobs_el = _ET.SubElement(root, "knobs")
    for k, v in _read_hot_reload_state().items():
        # JSON-encode each value so lists / bools / numbers / strings
        # round-trip without ambiguity. The element's text holds the
        # JSON representation; the @type attribute is informational.
        e = _ET.SubElement(knobs_el, "knob", attrib={
            "name": k, "type": type(v).__name__,
        })
        e.text = json.dumps(v, ensure_ascii=False)

    ips_el = _ET.SubElement(root, "admin_ips")
    for ent in ADMIN_ALLOWED_ENTRIES:
        # Only export *manually-added* entries — env-derived entries are
        # re-derived from $ADMIN_ALLOWED_IPS on the import side and would
        # otherwise duplicate.
        if (ent.get("source") or "").lower() == "env":
            continue
        _ET.SubElement(ips_el, "admin_ip", attrib={
            "cidr": str(ent.get("cidr") or ""),
            "note": str(ent.get("note") or ""),
            "source": str(ent.get("source") or "manual"),
            "description": str(ent.get("description") or ""),
            "added_ts": str(ent.get("added_ts") or ""),
        })

    secrets_el = _ET.SubElement(root, "secrets")
    if include_secrets:
        for public_name, (global_name, _env) in _SECRET_KEYS.items():
            v = g.get(global_name) or ""
            if not v:
                continue
            e = _ET.SubElement(secrets_el, "secret", attrib={"name": public_name})
            e.text = str(v)

    _ET.indent(root, space="  ")
    return _ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _settings_make_zip(xml_bytes: bytes) -> bytes:
    """Pack the XML document into a single-entry ZIP archive."""
    import io as _io
    import zipfile as _zf
    buf = _io.BytesIO()
    with _zf.ZipFile(buf, "w", compression=_zf.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr("appsecgw-config.xml", xml_bytes)
    return buf.getvalue()


async def settings_export_endpoint(request: web.Request):
    """GET /__settings-export?include_secrets=0|1 — return a ZIP archive
    containing `appsecgw-config.xml`. Admin-only."""
    if denied := _role_denied(request, "admin"):
        return denied
    include_secrets = (request.query.get("include_secrets") or "0").lower() in ("1", "true", "yes")
    try:
        xml_bytes = _settings_build_xml(include_secrets=include_secrets)
        zip_bytes = _settings_make_zip(xml_bytes)
    except Exception as e:
        slog("config_export_failed", level="error",
             rid=request.get("_rid", ""), err=str(e)[:200])
        return web.json_response({"error": f"export failed: {e}"}, status=500,
                                  headers={"Cache-Control": "no-store"})
    # Build a host-stamped filename for the operator's downloads folder.
    # Sanitise the Host header — operator-controlled but untrusted. Strip
    # to alphanumerics + dot/dash so a hostile Host can't break the
    # Content-Disposition quoting (alpha/digit/dot/dash is a strict subset
    # of RFC 7230 token charset).
    raw_host = (request.host or "appsecgw").split(":", 1)[0]
    host = re.sub(r"[^A-Za-z0-9._-]", "", raw_host)[:80] or "appsecgw"
    stamp = _t.strftime("%Y%m%d-%H%M%S", _t.gmtime())
    fname = f"appsecgw-config-{host}-{stamp}.zip"
    slog("config_exported", level="warn",
         rid=request.get("_rid", ""),
         include_secrets=include_secrets,
         bytes=len(zip_bytes), filename=fname)
    return web.Response(
        body=zip_bytes,
        headers={
            "Content-Type": "application/zip",
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        })


async def settings_import_endpoint(request: web.Request):
    """POST /__settings-import?dry_run=0|1&overwrite_secrets=0|1
    Body: a ZIP archive containing `appsecgw-config.xml` produced by
    `/__settings-export`. Returns a JSON summary { knobs_applied,
    knobs_rejected, admin_ips_added, secrets_applied, errors[] }.

    Validation runs through the same parser/validator pair used by
    POST /__config so an import can never sidestep bounds-checking. A
    single malformed knob does NOT abort the whole import — it lands
    in `errors[]` and the rest are still applied. Admin-only."""
    if denied := _role_denied(request, "admin"):
        return denied
    import io as _io
    import zipfile as _zf
    import xml.etree.ElementTree as _ET
    import ipaddress as _ipaddress

    import sys as _sys_imp
    try:
        from core.proxy_handler import (_HOT_RELOAD_KNOBS, _ENV_PROVIDED_KNOBS,
                                         _SECRET_KEYS, _json_safe, _NOT_PERSIST_KNOBS)
        _proxy_mod = _sys_imp.modules.get("core.proxy_handler")
        g = vars(_proxy_mod) if _proxy_mod else {}
    except Exception:
        _HOT_RELOAD_KNOBS = {}
        _ENV_PROVIDED_KNOBS = ()
        _SECRET_KEYS = {}
        _json_safe = lambda v: v  # noqa: E731
        _NOT_PERSIST_KNOBS = frozenset()
        g = {}

    dry_run = (request.query.get("dry_run") or "0").lower() in ("1", "true", "yes")
    overwrite_secrets = (request.query.get("overwrite_secrets") or "0").lower() in ("1", "true", "yes")

    # Cap the upload at 1 MiB — config archives are tiny in practice.
    try:
        raw = await asyncio.wait_for(request.content.read(1 * 1024 * 1024),
                                      timeout=BODY_TIMEOUT)
    except asyncio.TimeoutError:
        return web.json_response({"error": "upload timeout"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    if not raw:
        return web.json_response({"error": "empty body"}, status=400,
                                  headers={"Cache-Control": "no-store"})

    # Parse ZIP → extract the single XML entry. Hardened: only the
    # exact entry name `appsecgw-config.xml` is accepted (no path
    # traversal, no surprise alternate filenames), and the inflated
    # entry size is bounded to 4 MiB before calling .read() to defuse
    # ZIP-bomb amplification.
    _MAX_INFLATED = 4 * 1024 * 1024
    try:
        with _zf.ZipFile(_io.BytesIO(raw), "r") as zf:
            try:
                info = zf.getinfo("appsecgw-config.xml")
            except KeyError:
                return web.json_response(
                    {"error": "zip missing 'appsecgw-config.xml'"},
                    status=400, headers={"Cache-Control": "no-store"})
            if info.file_size > _MAX_INFLATED:
                return web.json_response(
                    {"error": f"xml entry too large ({info.file_size} bytes)"},
                    status=400, headers={"Cache-Control": "no-store"})
            xml_bytes = zf.read(info)
    except _zf.BadZipFile as e:
        return web.json_response({"error": f"bad zip: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})

    try:
        # B314 false-positive: input is bounded (DLP_MAX_BYTES already
        # capped the upload at 1 MiB above) and the endpoint is admin-IP
        # + admin-key gated, so the threat model is "operator uploads
        # malformed XML to break their own gateway" — not external XXE.
        # CPython 3.7+ ET.fromstring does not resolve external entities
        # and pyexpat applies its own entity-expansion limits.
        root = _ET.fromstring(xml_bytes)  # nosec B314
    except _ET.ParseError as e:
        return web.json_response({"error": f"bad xml: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    if root.tag != "appsecgw-config":
        return web.json_response({"error": f"unexpected root <{root.tag}>"},
                                  status=400,
                                  headers={"Cache-Control": "no-store"})

    summary = {
        "dry_run": dry_run,
        "overwrite_secrets": overwrite_secrets,
        "knobs_applied": 0,
        "knobs_rejected": 0,
        "admin_ips_added": 0,
        "secrets_applied": 0,
        "applied": [],
        "rejected": {},
        "errors": [],
    }

    # ── 1) Knobs ─────────────────────────────────────────────────
    knobs_el = root.find("knobs")
    if knobs_el is not None:
        for ke in knobs_el.findall("knob"):
            name = ke.attrib.get("name") or ""
            spec = _HOT_RELOAD_KNOBS.get(name)
            if spec is None:
                summary["rejected"][name] = "not-hot-reloadable"
                summary["knobs_rejected"] += 1
                continue
            if name in _ENV_PROVIDED_KNOBS:
                summary["rejected"][name] = "env-pinned"
                summary["knobs_rejected"] += 1
                continue
            try:
                raw_v = json.loads(ke.text or "null")
            except (ValueError, json.JSONDecodeError) as e:
                summary["rejected"][name] = f"bad json: {e}"
                summary["knobs_rejected"] += 1
                continue
            parser, validator = spec
            try:
                value = parser(raw_v)
                if validator is not None and not validator(value):
                    summary["rejected"][name] = "validation failed"
                    summary["knobs_rejected"] += 1
                    continue
            except (ValueError, TypeError) as e:
                summary["rejected"][name] = str(e)[:120]
                summary["knobs_rejected"] += 1
                continue
            if not dry_run:
                if g:
                    g[name] = value
                applied_v = sorted(value) if isinstance(value, set) else value
                if db_queue is not None and name not in _NOT_PERSIST_KNOBS:
                    try:
                        db_queue.put_nowait((
                            "set_config",
                            (name, json.dumps(_json_safe(applied_v)), _t.time()),
                        ))
                    except asyncio.QueueFull:
                        pass
            summary["applied"].append(name)
            summary["knobs_applied"] += 1

    # ── 2) Admin IPs (merge — never remove) ──────────────────────
    from admin.auth import admin_ip_add
    ips_el = root.find("admin_ips")
    if ips_el is not None:
        for ie in ips_el.findall("admin_ip"):
            cidr = ie.attrib.get("cidr") or ""
            note = ie.attrib.get("note") or ""
            description = ie.attrib.get("description") or ""
            if not cidr:
                continue
            if dry_run:
                # Fast-path validate without persisting.
                try:
                    _ipaddress.ip_network(cidr, strict=False)
                    summary["admin_ips_added"] += 1
                except ValueError as e:
                    summary["errors"].append(f"admin_ip {cidr}: {e}")
                continue
            ok, msg = await admin_ip_add(cidr, note, source="import",
                                          description=description)
            if ok:
                summary["admin_ips_added"] += 1
            elif msg != "already exists":
                summary["errors"].append(f"admin_ip {cidr}: {msg}")

    # ── 3) Secrets (opt-in, replaces existing values when present) ──
    if overwrite_secrets:
        secrets_el = root.find("secrets")
        if secrets_el is not None:
            for se in secrets_el.findall("secret"):
                name = se.attrib.get("name") or ""
                if name not in _SECRET_KEYS:
                    summary["errors"].append(f"secret {name}: unknown")
                    continue
                value = (se.text or "").strip()
                if not value:
                    continue
                if dry_run:
                    summary["secrets_applied"] += 1
                    continue
                global_name, _env = _SECRET_KEYS[name]
                if g:
                    g[global_name] = value
                if db_queue is not None:
                    try:
                        db_queue.put_nowait((
                            "set_secret", (name, value, _t.time()),
                        ))
                    except asyncio.QueueFull:
                        pass
                summary["secrets_applied"] += 1

    actor = _request_username(request)
    slog("config_imported", level="warn",
         rid=request.get("_rid", ""), actor=actor,
         dry_run=dry_run,
         knobs_applied=summary["knobs_applied"],
         knobs_rejected=summary["knobs_rejected"],
         admin_ips_added=summary["admin_ips_added"],
         secrets_applied=summary["secrets_applied"])
    if not dry_run:
        _gw_audit("settings_import", _gw_local_id(), actor,
                  knobs_applied=summary["knobs_applied"],
                  admin_ips_added=summary["admin_ips_added"],
                  secrets_applied=summary["secrets_applied"],
                  applied=summary["applied"])
    return web.json_response(summary, headers={"Cache-Control": "no-store"})


async def vhosts_endpoint(request: web.Request):
    """GET /__vhosts  — list all vhost entries.
       POST /__vhosts — add or update a vhost entry.
       DELETE /__vhosts — remove a vhost entry."""
    if denied := _role_denied(request, "admin"):
        return denied

    from vhost import vhost_list, vhost_set, vhost_delete, VHOSTS

    if request.method == "GET":
        return web.json_response({"vhosts": vhost_list()},
                                  headers={"Cache-Control": "no-store"})

    if request.method == "POST":
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        hostname = (body.get("hostname") or "").strip().lower()
        if not hostname:
            return web.json_response({"error": "hostname required"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        overrides = {k: v for k, v in body.items() if k != "hostname"}
        if "upstream" in overrides and "UPSTREAM" not in overrides:
            overrides["UPSTREAM"] = overrides.pop("upstream")
        if not overrides.get("UPSTREAM"):
            return web.json_response({"error": "UPSTREAM required"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        ok, err = vhost_set(hostname, overrides)
        if not ok:
            return web.json_response({"error": err}, status=400,
                                      headers={"Cache-Control": "no-store"})
        slog("vhost_set", level="warn", rid=request.get("_rid",""),
             actor=_request_username(request),
             hostname=hostname, upstream=overrides.get("UPSTREAM",""))
        _gw_audit("vhost_set", _gw_local_id(), _request_username(request),
                  hostname=hostname, upstream=overrides.get("UPSTREAM", ""))
        return web.json_response({"ok": True, "hostname": hostname},
                                  headers={"Cache-Control": "no-store"})

    if request.method == "DELETE":
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        hostname = (body.get("hostname") or "").strip().lower()
        if not hostname:
            return web.json_response({"error": "hostname required"}, status=400,
                                      headers={"Cache-Control": "no-store"})
        existed = vhost_delete(hostname)
        slog("vhost_delete", level="warn", rid=request.get("_rid",""),
             actor=_request_username(request),
             hostname=hostname, existed=existed)
        _gw_audit("vhost_delete", _gw_local_id(), _request_username(request),
                  hostname=hostname, existed=existed)
        return web.json_response({"ok": True, "existed": existed},
                                  headers={"Cache-Control": "no-store"})

    return web.json_response({"error": "method not allowed"}, status=405,
                              headers={"Cache-Control": "no-store"})


async def vhost_stats_endpoint(request: web.Request):
    """GET /__vhost-stats — per-vhost traffic counters for 1h and 24h."""
    if denied := _role_denied(request, "admin"):
        return denied

    import sqlite3 as _sq3
    now = _t.time()
    h1 = now - 3600
    h24 = now - 86400

    try:
        conn = _sq3.connect(_DATA_PATH)
        conn.row_factory = _sq3.Row
        rows = conn.execute(
            "SELECT vhost, "
            "  SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS total_1h, "
            "  SUM(CASE WHEN ts >= ? AND reason IN ('','ok','allowed','authorized-robot') THEN 1 ELSE 0 END) AS allowed_1h, "
            "  SUM(CASE WHEN ts >= ? AND reason NOT IN ('','ok','allowed','authorized-robot','operator-passthrough','internal-probe') THEN 1 ELSE 0 END) AS blocked_1h, "
            "  SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS total_24h, "
            "  SUM(CASE WHEN ts >= ? AND reason NOT IN ('','ok','allowed','authorized-robot','operator-passthrough','internal-probe') THEN 1 ELSE 0 END) AS blocked_24h, "
            "  MAX(ts) AS last_seen_ts "
            "FROM events WHERE ts >= ? AND vhost != '' "
            "GROUP BY vhost ORDER BY total_1h DESC",
            (h1, h1, h1, h24, h24, h24),
        ).fetchall()
        _dismissed_row = conn.execute(
            "SELECT value FROM config_kv WHERE key = 'dismissed_discovered_hosts'"
        ).fetchone()
        conn.close()
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500,
                                  headers={"Cache-Control": "no-store"})

    import json as _json
    try:
        dismissed: set = set(_json.loads(_dismissed_row["value"])) if _dismissed_row else set()
    except Exception:
        dismissed = set()

    # Ban counts from in-memory ip_state (banned_until > now, grouped by last_vhost).
    # ip_state is imported via `from state import *` at module level.
    bans: dict[str, int] = {}
    try:
        for _st in ip_state.values():  # type: ignore[name-defined]
            if getattr(_st, "banned_until", 0) > now:
                _vh = getattr(_st, "last_vhost", "") or ""
                if _vh:
                    bans[_vh] = bans.get(_vh, 0) + 1
    except Exception:
        pass

    stats = []
    for r in rows:
        vh = r["vhost"] or ""
        stats.append({
            "hostname":      vh,
            "total_1h":      int(r["total_1h"] or 0),
            "allowed_1h":    int(r["allowed_1h"] or 0),
            "blocked_1h":    int(r["blocked_1h"] or 0),
            "total_24h":     int(r["total_24h"] or 0),
            "blocked_24h":   int(r["blocked_24h"] or 0),
            "bans":          int(bans.get(vh, 0)),
            "last_seen_ts":  float(r["last_seen_ts"] or 0),
            "dismissed":     vh in dismissed,
        })
    return web.json_response({"stats": stats, "ts": int(now)},
                              headers={"Cache-Control": "no-store"})


async def vhost_dismiss_endpoint(request: web.Request):
    """POST /__vhost-dismiss  {"hostname":"..."} — add to dismissed set.
       DELETE /__vhost-dismiss {"hostname":"..."} — remove from dismissed set."""
    if denied := _role_denied(request, "admin"):
        return denied

    import sqlite3 as _sq3, json as _json
    try:
        body = await request.json()
        hostname = (body.get("hostname") or "").strip()
    except Exception:
        return web.json_response({"error": "invalid JSON"}, status=400)
    if not hostname:
        return web.json_response({"error": "hostname required"}, status=400)

    try:
        conn = _sq3.connect(_DATA_PATH)
        row = conn.execute(
            "SELECT value FROM config_kv WHERE key = 'dismissed_discovered_hosts'"
        ).fetchone()
        dismissed: set = set(_json.loads(row["value"])) if row else set()
        if request.method == "DELETE":
            dismissed.discard(hostname)
        else:
            dismissed.add(hostname)
        ts = _t.time()
        conn.execute(
            "INSERT OR REPLACE INTO config_kv (key, value, ts) VALUES (?, ?, ?)",
            ("dismissed_discovered_hosts", _json.dumps(sorted(dismissed)), ts),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)

    return web.json_response({"dismissed": sorted(dismissed)})


async def vhost_breakdown_endpoint(request: web.Request):
    """GET /__vhost-breakdown?range=720&bucket=300&end=<unix>
    Returns bucketed per-vhost event counts for stacked charts.
    """
    if denied := _role_denied(request, "admin"):
        return denied

    import sqlite3 as _sq3

    try:
        range_min  = int(request.query.get("range", 720))
        bucket_sec = int(request.query.get("bucket", 300))
        end_ts     = float(request.query.get("end", _t.time()))
    except (ValueError, TypeError):
        return web.json_response({"error": "invalid params"}, status=400,
                                  headers={"Cache-Control": "no-store"})

    range_min  = max(1, min(range_min, 44640))
    bucket_sec = max(60, min(bucket_sec, 86400))
    start_ts   = end_ts - range_min * 60

    try:
        conn = _sq3.connect(_DATA_PATH)
        conn.row_factory = _sq3.Row
        rows = conn.execute(
            "SELECT vhost, "
            "  CAST((ts - ?) / ? AS INTEGER) AS slot, "
            "  COUNT(*) AS cnt "
            "FROM events "
            "WHERE ts >= ? AND ts <= ? AND vhost != '' "
            "GROUP BY vhost, slot "
            "ORDER BY slot",
            (start_ts, bucket_sec, start_ts, end_ts),
        ).fetchall()
        conn.close()
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500,
                                  headers={"Cache-Control": "no-store"})

    n_slots = max(1, int((end_ts - start_ts) / bucket_sec))
    labels  = [int(start_ts + i * bucket_sec) for i in range(n_slots)]

    vhosts_seen: dict[str, list] = {}
    for r in rows:
        vh   = r["vhost"] or ""
        slot = int(r["slot"])
        cnt  = int(r["cnt"])
        if 0 <= slot < n_slots:
            if vh not in vhosts_seen:
                vhosts_seen[vh] = [0] * n_slots
            vhosts_seen[vh][slot] += cnt

    datasets = [{"vhost": vh, "data": data}
                for vh, data in sorted(vhosts_seen.items())]

    return web.json_response(
        {"labels": labels, "datasets": datasets, "bucket": bucket_sec},
        headers={"Cache-Control": "no-store"},
    )


# ── 1.8.1 — Per-vhost policy page ─────────────────────────────────────────────

VHOST_POLICY_DASHBOARD_HTML = (_DASHBOARDS_DIR / "vhost_policy.html").read_text(encoding="utf-8")

_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'"
    ),
}


async def vhost_policy_dashboard_endpoint(request: web.Request):
    """GET /__vhost-policy — render the per-vhost policy page (admin-only)."""
    if denied := _role_denied(request, "admin"):
        return denied
    return web.Response(
        text=VHOST_POLICY_DASHBOARD_HTML,
        content_type="text/html",
        headers=_SECURITY_HEADERS,
    )


async def vhost_policy_data_endpoint(request: web.Request):
    """GET /__vhost-policy-data?hostname=<host>
    Returns merged global config + vhost overrides for the given hostname.
    Response shape:
      {
        "hostname": str,
        "vhost_knobs": [str, ...],   # all keys declared in _VHOST_COERCE
        "overrides": {KEY: value},   # what this vhost currently overrides
        "global": {KEY: value},      # global value for every vhost-overridable knob
        "vhosts": [str, ...]         # list of all configured vhost hostnames
      }
    """
    if denied := _role_denied(request, "admin"):
        return denied

    import sys as _sys
    from vhost import VHOSTS, _VHOST_COERCE, _json_safe, vhost_list

    hostname = request.query.get("hostname", "").strip().lower()

    # All vhost-overridable knob names (stable, sorted)
    vhost_knobs = sorted(_VHOST_COERCE.keys())

    # Current overrides for the requested hostname
    overrides: dict = {}
    if hostname and hostname in VHOSTS:
        overrides = {k: _json_safe(v) for k, v in VHOSTS[hostname].items()}

    # Global value for every vhost-overridable knob (from the live process state)
    def _get_global(name: str):
        _cph = _sys.modules.get("core.proxy_handler")
        if _cph is not None and hasattr(_cph, name):
            return _json_safe(getattr(_cph, name))
        import config as _cfg
        if hasattr(_cfg, name):
            return _json_safe(getattr(_cfg, name))
        for _mod in list(_sys.modules.values()):
            if _mod is None:
                continue
            if hasattr(_mod, name):
                return _json_safe(getattr(_mod, name))
        return None

    global_vals = {k: _get_global(k) for k in vhost_knobs}

    return web.json_response(
        {
            "hostname":   hostname,
            "vhost_knobs": vhost_knobs,
            "overrides":  overrides,
            "global":     global_vals,
            "vhosts":     [v["hostname"] for v in vhost_list()],
        },
        headers={"Cache-Control": "no-store"},
    )


async def audit_log_endpoint(request: web.Request):
    """GET /__audit-log — query the append-only gw_audit table.

    Query params (all optional):
      action=<str>   — filter by action substring (e.g. config_change, vhost_set)
      actor=<str>    — filter by exact actor username
      limit=<int>    — max rows returned (default 200, max 1000)
      since=<float>  — Unix epoch lower bound (inclusive)
    Returns {rows: [{id, ts, action, gw_id, actor, details}], count}.
    Admin-only."""
    if denied := _role_denied(request, "admin"):
        return denied

    import sqlite3 as _sq3
    import json as _json

    action_filter = request.query.get("action", "").strip()
    actor_filter  = request.query.get("actor",  "").strip()
    try:
        limit = max(1, min(1000, int(request.query.get("limit", 200))))
    except (ValueError, TypeError):
        limit = 200
    try:
        since = float(request.query.get("since", 0))
    except (ValueError, TypeError):
        since = 0.0

    where_clauses = ["ts >= ?"]
    params: list = [since]
    if action_filter:
        where_clauses.append("action LIKE ?")
        params.append(f"%{action_filter}%")
    if actor_filter:
        where_clauses.append("actor = ?")
        params.append(actor_filter)
    where_sql = " AND ".join(where_clauses)
    params.append(limit)

    try:
        conn = _sq3.connect(DB_PATH)
        conn.row_factory = _sq3.Row
        rows = conn.execute(
            f"SELECT id, ts, action, gw_id, actor, details "  # nosec B608 — where clauses built from hardcoded strings; all values parameterized
            f"FROM gw_audit WHERE {where_sql} "
            f"ORDER BY ts DESC LIMIT ?",
            params,
        ).fetchall()
        conn.close()
    except Exception as e:
        return web.json_response({"error": str(e)[:200]}, status=500,
                                  headers={"Cache-Control": "no-store"})

    out = []
    for r in rows:
        try:
            details = _json.loads(r["details"] or "{}")
        except (ValueError, TypeError):
            details = r["details"]
        out.append({
            "id":      r["id"],
            "ts":      r["ts"],
            "action":  r["action"],
            "gw_id":   r["gw_id"],
            "actor":   r["actor"],
            "details": details,
        })
    return web.json_response({"rows": out, "count": len(out)},
                              headers={"Cache-Control": "no-store"})


# ── 1.8.2 — Control Center analytics endpoints ────────────────────────────────

_SKIP_REASONS = ('', 'ok', 'allowed', 'authorized-robot', 'operator-passthrough', 'internal-probe')


async def block_reasons_timeline_endpoint(request: web.Request):
    """GET /__block-reasons-timeline?range=120&bucket=300
    Bucketed blocked-request counts per block reason (top 8 reasons).
    """
    if denied := _role_denied(request, "admin"):
        return denied
    import sqlite3 as _sq3
    try:
        range_min  = max(1,  min(int(request.query.get("range",  120)), 44640))
        bucket_sec = max(60, min(int(request.query.get("bucket", 300)), 86400))
    except (ValueError, TypeError):
        return web.json_response({"error": "invalid params"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    end_ts   = _t.time()
    start_ts = end_ts - range_min * 60
    n_slots  = max(1, int((end_ts - start_ts) / bucket_sec))
    labels   = [int(start_ts + i * bucket_sec) for i in range(n_slots)]
    skip_ph  = ",".join("?" * len(_SKIP_REASONS))
    try:
        conn = _sq3.connect(_DATA_PATH)
        conn.row_factory = _sq3.Row
        rows = conn.execute(
            f"SELECT reason, CAST((ts - ?) / ? AS INTEGER) AS slot, COUNT(*) AS cnt "  # nosec B608 — slot formula uses only int constants; skip_ph is parameterized placeholders
            f"FROM events WHERE ts >= ? AND ts <= ? "
            f"AND (reason IS NULL OR reason NOT IN ({skip_ph})) "
            f"GROUP BY reason, slot ORDER BY slot",
            (start_ts, bucket_sec, start_ts, end_ts, *_SKIP_REASONS),
        ).fetchall()
        conn.close()
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500,
                                  headers={"Cache-Control": "no-store"})
    reasons_seen: dict[str, list] = {}
    for r in rows:
        reason = r["reason"] or "unknown"
        slot   = int(r["slot"])
        cnt    = int(r["cnt"])
        if 0 <= slot < n_slots:
            if reason not in reasons_seen:
                reasons_seen[reason] = [0] * n_slots
            reasons_seen[reason][slot] += cnt
    sorted_reasons = sorted(reasons_seen.items(), key=lambda kv: sum(kv[1]), reverse=True)[:8]
    datasets = [{"reason": rsn, "data": data} for rsn, data in sorted_reasons]
    return web.json_response(
        {"labels": labels, "datasets": datasets, "bucket": bucket_sec},
        headers={"Cache-Control": "no-store"},
    )


async def top_attacked_paths_endpoint(request: web.Request):
    """GET /__top-attacked-paths?range=1440&limit=10
    Top paths by blocked-request count.
    """
    if denied := _role_denied(request, "admin"):
        return denied
    import sqlite3 as _sq3
    try:
        range_min = max(1,  min(int(request.query.get("range", 1440)), 44640))
        limit     = max(1,  min(int(request.query.get("limit",   10)),    50))
    except (ValueError, TypeError):
        return web.json_response({"error": "invalid params"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    start_ts = _t.time() - range_min * 60
    skip_ph  = ",".join("?" * len(_SKIP_REASONS))
    try:
        conn = _sq3.connect(_DATA_PATH)
        conn.row_factory = _sq3.Row
        rows = conn.execute(
            f"SELECT path, COUNT(*) AS blocked FROM events "  # nosec B608 — skip_ph is parameterized placeholders only
            f"WHERE ts >= ? AND path IS NOT NULL AND path != '' "
            f"AND reason NOT IN ({skip_ph}) "
            f"GROUP BY path ORDER BY blocked DESC LIMIT ?",
            (start_ts, *_SKIP_REASONS, limit),
        ).fetchall()
        conn.close()
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500,
                                  headers={"Cache-Control": "no-store"})
    paths = [{"path": r["path"], "count": int(r["blocked"])} for r in rows]
    return web.json_response({"paths": paths, "ts": int(_t.time())},
                              headers={"Cache-Control": "no-store"})


async def attack_heatmap_endpoint(request: web.Request):
    """GET /__attack-heatmap?range=10080
    Blocked-request count per (day_of_week, hour_of_day) grid.
    dow: 0=Sunday .. 6=Saturday, hour: 0–23 (UTC).
    """
    if denied := _role_denied(request, "admin"):
        return denied
    import sqlite3 as _sq3
    try:
        range_min = max(60, min(int(request.query.get("range", 10080)), 44640))
    except (ValueError, TypeError):
        return web.json_response({"error": "invalid params"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    start_ts = _t.time() - range_min * 60
    skip_ph  = ",".join("?" * len(_SKIP_REASONS))
    try:
        conn = _sq3.connect(_DATA_PATH)
        conn.row_factory = _sq3.Row
        rows = conn.execute(
            f"SELECT CAST(strftime('%w', ts, 'unixepoch') AS INTEGER) AS dow, "  # nosec B608 — skip_ph is parameterized placeholders only
            f"       CAST(strftime('%H', ts, 'unixepoch') AS INTEGER) AS hour, "
            f"       COUNT(*) AS n "
            f"FROM events WHERE ts >= ? AND reason NOT IN ({skip_ph}) "
            f"GROUP BY dow, hour",
            (start_ts, *_SKIP_REASONS),
        ).fetchall()
        conn.close()
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500,
                                  headers={"Cache-Control": "no-store"})
    cells   = [[int(r["dow"]), int(r["hour"]), int(r["n"])] for r in rows]
    max_val = max((c[2] for c in cells), default=0)
    return web.json_response({"cells": cells, "max": max_val, "ts": int(_t.time())},
                              headers={"Cache-Control": "no-store"})
