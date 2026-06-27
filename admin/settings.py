# admin/settings.py — Phase 8: settings export/import + settings dashboard
# Extracted from proxy.py lines 11284–11612
import time as _t       # noqa: F401
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR, _DATA_PATH  # noqa: F401 — leading-underscore not in *
from state import *    # noqa: F401,F403
from helpers import slog  # noqa: F401
from admin.auth import _internal_authed, ADMIN_ALLOWED_ENTRIES, _role_denied, _request_username, _require_csrf  # noqa: F401
from admin.mesh import _gw_audit, _gw_local_id  # noqa: F401
from aiohttp import web

SETTINGS_DASHBOARD_HTML = (_DASHBOARDS_DIR / "settings.html").read_text(encoding="utf-8")


async def ui_theme_endpoint(request: web.Request):
    """GET/POST /secured/ui-theme — the single master light/dark toggle.

    GET  → {"theme": "dark"|"light"} (current persisted master).
    POST {"theme":"dark"|"light"} → persist to config_kv['ui_theme'] and echo it.
          Invalid theme → 400.

    Every dashboard bakes `config_kv['ui_theme']` into `<html data-theme>` on
    first paint, so persisting here makes the toggle on ANY page the master that
    ALL pages reflect on their next load — across browsers/devices, not just the
    local browser's localStorage. Auth is enforced by the SEC-prefix middleware
    (unauthenticated → 401); the write is additionally role-gated."""
    from db.sqlite import get_ui_theme as _get_theme, set_ui_theme as _set_theme
    if request.method == "POST":
        if denied := _role_denied(request, "admin", "maintainer"):
            return denied
        try:
            body = await request.json()
        except Exception:
            body = {}
        theme = str((body or {}).get("theme", "")).strip().lower()
        if theme not in ("dark", "light"):
            return web.json_response(
                {"error": "theme must be 'dark' or 'light'"},
                status=400, headers={"Cache-Control": "no-store"})
        if not _set_theme(DB_PATH, theme):
            return web.json_response(
                {"error": "failed to persist theme"},
                status=500, headers={"Cache-Control": "no-store"})
        slog("ui_theme_set", level="info", theme=theme,
             actor=_request_username(request) or "")
        return web.json_response({"theme": theme},
                                 headers={"Cache-Control": "no-store"})
    # GET — any authenticated dashboard user may read the current master.
    return web.json_response({"theme": _get_theme(DB_PATH)},
                             headers={"Cache-Control": "no-store"})


async def settings_dashboard_endpoint(request: web.Request):
    """GET /__settings — render the Settings dashboard (admin-only)."""
    if denied := _role_denied(request, "admin"):
        return denied
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    body = SETTINGS_DASHBOARD_HTML.replace('<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1)
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


def _settings_build_xml(include_secrets: bool = False) -> bytes:
    """1.8.14 — FULL config export. Sections (always present, may be empty):
      <knobs> · <admin_ips> · <vhosts> · <siem_alert_rules> · <dlp_patterns>
      <signal_orders> · <honey_fingerprints> · <gw_registry> · <gw_distribution>
      <users> · <secrets>

    `include_secrets=True` additionally serialises:
      - <secrets>          plaintext integration secrets (secrets_kv)
      - <users>            password hashes
      - <gw_registry>      the LOCAL gw's HMAC private_key

    Anything that's runtime/operational state (events, clients, sessions,
    bans, timeline, last_fired_ts, etc.) is intentionally NOT exported.
    Stdlib-only — kept dependency-free for the runtime image.
    """
    import xml.etree.ElementTree as _ET
    import sqlite3 as _sql
    try:
        from core.proxy_handler import _read_hot_reload_state
    except Exception:
        _read_hot_reload_state = lambda: {}  # noqa: E731

    root = _ET.Element("appsecgw-config", attrib={
        "version": "1.8.14",
        "exported_at": str(int(_t.time())),
        "includes_secrets": "1" if include_secrets else "0",
    })

    # ── 1) knobs ─────────────────────────────────────────────────
    knobs_el = _ET.SubElement(root, "knobs")
    for k, v in _read_hot_reload_state().items():
        e = _ET.SubElement(knobs_el, "knob", attrib={
            "name": k, "type": type(v).__name__,
        })
        e.text = json.dumps(v, ensure_ascii=False)

    # ── 2) admin_ips (manual entries only — env re-derives on import) ────
    ips_el = _ET.SubElement(root, "admin_ips")
    for ent in ADMIN_ALLOWED_ENTRIES:
        if (ent.get("source") or "").lower() == "env":
            continue
        _ET.SubElement(ips_el, "admin_ip", attrib={
            "cidr": str(ent.get("cidr") or ""),
            "note": str(ent.get("note") or ""),
            "source": str(ent.get("source") or "manual"),
            "description": str(ent.get("description") or ""),
            "added_ts": str(ent.get("added_ts") or ""),
        })

    # ── 3) vhost overrides ───────────────────────────────────────
    try:
        from vhost import vhost_list as _vhost_list
        _vhosts = _vhost_list()
    except Exception:
        _vhosts = []
    vhosts_el = _ET.SubElement(root, "vhosts")
    for entry in _vhosts:
        hostname = entry.get("hostname") or ""
        if not hostname:
            continue
        vh_el = _ET.SubElement(vhosts_el, "vhost", attrib={"hostname": hostname})
        for k, v in entry.items():
            if k == "hostname":
                continue
            ov_el = _ET.SubElement(vh_el, "override", attrib={
                "name": k, "type": type(v).__name__,
            })
            ov_el.text = json.dumps(v, ensure_ascii=False)

    # ── 4-10) the operator-curated data plane (1.8.14) ─────────
    # Open one read-only conn for all DB-backed sections.
    try:
        conn = _sql.connect(DB_PATH)
        conn.row_factory = _sql.Row
    except Exception:
        conn = None

    siem_el  = _ET.SubElement(root, "siem_alert_rules")
    dlp_el   = _ET.SubElement(root, "dlp_patterns")
    ord_el   = _ET.SubElement(root, "signal_orders")
    honey_el = _ET.SubElement(root, "honey_fingerprints")
    reg_el   = _ET.SubElement(root, "gw_registry")
    dist_el  = _ET.SubElement(root, "gw_distribution")
    users_el = _ET.SubElement(root, "users", attrib={
        "include_password_hash": "1" if include_secrets else "0",
    })
    secrets_el = _ET.SubElement(root, "secrets", attrib={
        "included": "1" if include_secrets else "0",
    })

    def _safe(label, fn):
        """Each section runs independently — a missing table or transient
        read error must not corrupt the whole export."""
        try:
            fn()
        except _sql.OperationalError as _e:
            # missing table on a freshly-created DB → just skip (the empty
            # container stays in the XML so the importer doesn't choke).
            slog("settings_export_skip_section", level="info",
                 section=label, reason=str(_e)[:160])
        except Exception as _e:
            slog("settings_export_section_error", level="warn",
                 section=label, err=str(_e)[:200])

    if conn is not None:
        try:
            # 4) SIEM alert rules — operator-defined thresholds + cooldowns.
            #    last_fired_ts intentionally excluded (runtime).
            def _siem():
                for r in conn.execute(
                    "SELECT metric, op, threshold, label, enabled, cooldown_s, "
                    "created_ts, created_by FROM siem_alert_rules"):
                    _ET.SubElement(siem_el, "rule", attrib={
                        "metric":     str(r["metric"] or ""),
                        "op":         str(r["op"] or ">"),
                        "threshold":  str(r["threshold"] or 0),
                        "label":      str(r["label"] or ""),
                        "enabled":    "1" if r["enabled"] else "0",
                        "cooldown_s": str(r["cooldown_s"] or 300),
                        "created_ts": str(r["created_ts"] or ""),
                        "created_by": str(r["created_by"] or ""),
                    })
            _safe("siem_alert_rules", _siem)

            # 5) DLP patterns — operator-managed regex library.
            def _dlp():
                for r in conn.execute(
                    "SELECT name, pattern, severity, enabled, added_ts, added_by "
                    "FROM dlp_patterns"):
                    _ET.SubElement(dlp_el, "pattern", attrib={
                        "name":     str(r["name"] or ""),
                        "severity": str(r["severity"] or "high"),
                        "enabled":  "1" if r["enabled"] else "0",
                        "added_ts": str(r["added_ts"] or ""),
                        "added_by": str(r["added_by"] or ""),
                    }).text = r["pattern"] or ""
            _safe("dlp_patterns", _dlp)

            # 6) signal_orders — tied to LOCAL gw_id only (other gw_ids are
            #    foreign on a restored instance).
            def _orders():
                local_row = conn.execute(
                    "SELECT gw_id FROM gw_registry WHERE is_local=1 LIMIT 1").fetchone()
                if not local_row:
                    return
                for r in conn.execute(
                    "SELECT signal, activation_order, updated_ts, updated_by "
                    "FROM signal_orders WHERE gw_id = ?", (local_row["gw_id"],)):
                    _ET.SubElement(ord_el, "order", attrib={
                        "signal":           str(r["signal"] or ""),
                        "activation_order": str(r["activation_order"] or 2),
                        "updated_ts":       str(r["updated_ts"] or ""),
                        "updated_by":       str(r["updated_by"] or ""),
                    })
            _safe("signal_orders", _orders)

            # 7) honey_fingerprints — cap at most-recent 1000 so the archive
            #    stays well under the 1 MiB upload cap.
            def _honey():
                for r in conn.execute(
                    "SELECT ts, ip, ua, ja4, asn, path, reason "
                    "FROM honey_fingerprints ORDER BY ts DESC LIMIT 1000"):
                    _ET.SubElement(honey_el, "fp", attrib={
                        "ts":     str(r["ts"] or 0),
                        "ip":     str(r["ip"] or ""),
                        "ua":     str(r["ua"] or "")[:300],
                        "ja4":    str(r["ja4"] or ""),
                        "asn":    str(r["asn"] or ""),
                        "path":   str(r["path"] or "")[:200],
                        "reason": str(r["reason"] or ""),
                    })
            _safe("honey_fingerprints", _honey)

            # 8) gw_registry — LOCAL row's private_key is the HMAC mesh secret;
            #    only export when include_secrets is set.
            def _gw_reg():
                for r in conn.execute("SELECT * FROM gw_registry"):
                    attrib = {
                        "gw_id":          str(r["gw_id"] or ""),
                        "domain":         str(r["domain"] or ""),
                        "region":         str(r["region"] or ""),
                        "environment":    str(r["environment"] or ""),
                        "status":         str(r["status"] or "active"),
                        "can_distribute": "1" if r["can_distribute"] else "0",
                        "public_key":     str(r["public_key"] or ""),
                        "key_created_ts": str(r["key_created_ts"] or 0),
                        "is_local":       "1" if r["is_local"] else "0",
                        "auto_apply":     "1" if r["auto_apply"] else "0",
                    }
                    if include_secrets and r["is_local"] and r["private_key"]:
                        attrib["private_key"] = str(r["private_key"])
                    _ET.SubElement(reg_el, "gw", attrib=attrib)
            _safe("gw_registry", _gw_reg)

            # 9) gw_distribution — directional source→target pairs.
            def _gw_dist():
                for r in conn.execute(
                    "SELECT source_gw_id, target_gw_id, ts FROM gw_distribution"):
                    _ET.SubElement(dist_el, "pair", attrib={
                        "source_gw_id": str(r["source_gw_id"] or ""),
                        "target_gw_id": str(r["target_gw_id"] or ""),
                        "ts":           str(r["ts"] or 0),
                    })
            _safe("gw_distribution", _gw_dist)

            # 10) users — non-bootstrap accounts. password_hash is sensitive
            #     so only included with include_secrets.
            def _users():
                for r in conn.execute(
                    "SELECT username, password_hash, role, status, "
                    "created_ts, updated_ts FROM users"):
                    ua = {
                        "username":   str(r["username"] or ""),
                        "role":       str(r["role"] or "admin"),
                        "status":     str(r["status"] or "active"),
                        "created_ts": str(r["created_ts"] or 0),
                        "updated_ts": str(r["updated_ts"] or 0),
                    }
                    if include_secrets:
                        ua["password_hash"] = str(r["password_hash"] or "")
                    _ET.SubElement(users_el, "user", attrib=ua)
            _safe("users", _users)

            # 11) secrets_kv — plaintext integration secrets. Hard-gated by
            #     include_secrets. Empty container otherwise so the operator
            #     can see the schema is stable.
            def _secrets():
                if not include_secrets:
                    return
                for r in conn.execute("SELECT key, value FROM secrets_kv"):
                    e = _ET.SubElement(secrets_el, "secret",
                                       attrib={"key": str(r["key"] or "")})
                    e.text = r["value"] or ""
            _safe("secrets_kv", _secrets)
        finally:
            try: conn.close()
            except Exception: pass  # nosec B110 — close() failures are uninteresting

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
    containing `appsecgw-config.xml`. Admin-only.

    Default (`include_secrets=0`) exports configuration but NEVER plaintext
    secrets, password hashes, or the local mesh private key — those export
    only when the operator explicitly ticks the include-secrets box in the
    UI (or appends `?include_secrets=1`). When set, the archive must be
    treated as credential material: encrypt at rest, never commit to git.
    """
    if denied := _role_denied(request, "admin"):
        return denied
    include_secrets = (request.query.get("include_secrets") or "0").strip().lower() in ("1", "true", "yes", "on")
    # S-W6 fix: include_secrets exports password hashes + private keys + API
    # tokens. GET is normally CSRF-exempt — require a valid X-CSRF-Token
    # header for the secrets-export variant so a malicious <img src=...> or
    # window.open() cannot trigger the download via a victim's session.
    if include_secrets:
        from admin.auth import _csrf_token_valid
        if not _csrf_token_valid(request, require_for_safe=True):
            slog("config_export_secrets_csrf_rejected", level="warn",
                 rid=request.get("_rid", ""),
                 actor=_request_username(request))
            return web.json_response(
                {"error": "secrets export requires a valid CSRF token"},
                status=403, headers={"Cache-Control": "no-store"})
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
    fname = f"appsecgw-config-{host}-{stamp}{'-with-secrets' if include_secrets else ''}.zip"
    slog("config_exported", level="warn",
         rid=request.get("_rid", ""),
         bytes=len(zip_bytes), filename=fname,
         include_secrets=include_secrets,
         actor=_request_username(request))
    return web.Response(
        body=zip_bytes,
        headers={
            "Content-Type": "application/zip",
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        })


@_require_csrf
async def settings_import_endpoint(request: web.Request):
    """POST /__settings-import?dry_run=0|1
    Body: a ZIP archive containing `appsecgw-config.xml` produced by
    `/__settings-export`. Returns a JSON summary { knobs_applied,
    knobs_rejected, admin_ips_added, errors[] }.

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
        root = _ET.fromstring(xml_bytes)  # nosec B314  # noqa: S314
    except _ET.ParseError as e:
        return web.json_response({"error": f"bad xml: {e}"}, status=400,
                                  headers={"Cache-Control": "no-store"})
    if root.tag != "appsecgw-config":
        return web.json_response({"error": f"unexpected root <{root.tag}>"},
                                  status=400,
                                  headers={"Cache-Control": "no-store"})

    summary = {
        "dry_run": dry_run,
        "knobs_applied": 0,
        "knobs_rejected": 0,
        "admin_ips_added": 0,
        "vhosts_restored": 0,
        # 1.8.14 — full export round-trip
        "siem_rules_added": 0,
        "dlp_patterns_added": 0,
        "signal_orders_restored": 0,
        "honey_fps_restored": 0,
        "gw_registry_restored": 0,
        "gw_distribution_restored": 0,
        "users_restored": 0,
        "secrets_restored": 0,
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

    # ── 3) Vhost configs (merge — existing entries updated, no deletions) ────
    from vhost import vhost_set as _vhost_set
    vhosts_el2 = root.find("vhosts")
    if vhosts_el2 is not None:
        for vh_el in vhosts_el2.findall("vhost"):
            hostname = vh_el.attrib.get("hostname") or ""
            if not hostname:
                continue
            overrides: dict = {}
            for ov_el in vh_el.findall("override"):
                k = ov_el.attrib.get("name") or ""
                if not k:
                    continue
                try:
                    overrides[k] = json.loads(ov_el.text or "null")
                except (ValueError, json.JSONDecodeError) as e:
                    summary["errors"].append(f"vhost {hostname!r} key {k!r}: bad json: {e}")
            if not dry_run:
                ok, err = _vhost_set(hostname, overrides)
                if ok:
                    summary["vhosts_restored"] += 1
                else:
                    summary["errors"].append(f"vhost {hostname!r}: {err}")
            else:
                summary["vhosts_restored"] += 1

    # ── 4-11) 1.8.14 — operator-curated data plane (siem/dlp/orders/honey/mesh/users/secrets) ──
    # Direct SQLite writes per section, atomic, dedup where the schema lets us.
    import sqlite3 as _sql_imp
    _conn = None
    if not dry_run:
        try:
            _conn = _sql_imp.connect(DB_PATH)
            _conn.row_factory = _sql_imp.Row
        except Exception as _e:
            summary["errors"].append(f"db open failed: {_e}")

    # 4) SIEM alert rules — dedup by (metric, op, threshold)
    siem_el = root.find("siem_alert_rules")
    if siem_el is not None:
        for re_el in siem_el.findall("rule"):
            metric    = re_el.attrib.get("metric") or ""
            op        = re_el.attrib.get("op") or ">"
            try:
                threshold = float(re_el.attrib.get("threshold") or 0)
            except (ValueError, TypeError):
                summary["errors"].append(f"siem rule {metric!r}: bad threshold"); continue
            if not metric or op not in (">", ">=", "<", "<="):
                summary["errors"].append(f"siem rule {metric!r}: invalid metric/op"); continue
            label     = re_el.attrib.get("label") or ""
            enabled   = 1 if (re_el.attrib.get("enabled") or "1") in ("1", "true", "yes") else 0
            try:
                cooldown = max(1, int(float(re_el.attrib.get("cooldown_s") or 300)))
            except (ValueError, TypeError):
                cooldown = 300
            if dry_run:
                summary["siem_rules_added"] += 1; continue
            if _conn is None: continue
            try:
                existing = _conn.execute(
                    "SELECT 1 FROM siem_alert_rules WHERE metric=? AND op=? AND threshold=?",
                    (metric, op, threshold)).fetchone()
                if existing:
                    continue
                _conn.execute(
                    "INSERT INTO siem_alert_rules "
                    "(metric, op, threshold, label, enabled, created_ts, created_by, cooldown_s) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (metric, op, threshold, label, enabled, _t.time(), "import", cooldown))
                summary["siem_rules_added"] += 1
            except Exception as _e:
                summary["errors"].append(f"siem rule {metric!r}: {_e}")

    # 5) DLP patterns — dedup by (name, pattern)
    dlp_el = root.find("dlp_patterns")
    if dlp_el is not None:
        for pa in dlp_el.findall("pattern"):
            name    = pa.attrib.get("name") or ""
            pattern = pa.text or ""
            if not name or not pattern:
                continue
            severity = pa.attrib.get("severity") or "high"
            enabled  = 1 if (pa.attrib.get("enabled") or "1") in ("1", "true", "yes") else 0
            if dry_run:
                summary["dlp_patterns_added"] += 1; continue
            if _conn is None: continue
            try:
                existing = _conn.execute(
                    "SELECT 1 FROM dlp_patterns WHERE name=? AND pattern=?",
                    (name, pattern)).fetchone()
                if existing:
                    continue
                _conn.execute(
                    "INSERT INTO dlp_patterns (name, pattern, severity, enabled, added_ts, added_by) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (name, pattern, severity, enabled, _t.time(), "import"))
                summary["dlp_patterns_added"] += 1
            except Exception as _e:
                summary["errors"].append(f"dlp pattern {name!r}: {_e}")

    # 6) signal_orders — write under the LOCAL gw_id (foreign gw_ids in the
    #    export are meaningless on this instance).
    ord_el = root.find("signal_orders")
    if ord_el is not None:
        local_gw_id = ""
        if _conn is not None:
            _row = _conn.execute(
                "SELECT gw_id FROM gw_registry WHERE is_local=1 LIMIT 1").fetchone()
            if _row: local_gw_id = _row["gw_id"] or ""
        for oe in ord_el.findall("order"):
            sig = oe.attrib.get("signal") or ""
            try:
                ao = int(oe.attrib.get("activation_order") or 2)
            except (ValueError, TypeError):
                ao = 2
            if not sig or ao not in (1, 2, 3):
                summary["errors"].append(f"signal_order {sig!r}: invalid"); continue
            if dry_run:
                summary["signal_orders_restored"] += 1; continue
            if _conn is None or not local_gw_id: continue
            try:
                _conn.execute(
                    "INSERT INTO signal_orders (gw_id, signal, activation_order, updated_ts, updated_by) "
                    "VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(gw_id, signal) DO UPDATE SET "
                    "  activation_order=excluded.activation_order, "
                    "  updated_ts=excluded.updated_ts, updated_by=excluded.updated_by",
                    (local_gw_id, sig, ao, _t.time(), "import"))
                summary["signal_orders_restored"] += 1
            except Exception as _e:
                summary["errors"].append(f"signal_order {sig!r}: {_e}")

    # 7) honey_fingerprints — append; auto-dedup via the natural ja4+ip+ts triple.
    honey_el = root.find("honey_fingerprints")
    if honey_el is not None:
        for fp in honey_el.findall("fp"):
            try:
                ts = float(fp.attrib.get("ts") or 0)
            except (ValueError, TypeError):
                continue
            ip = fp.attrib.get("ip") or ""
            if not ip:
                continue
            if dry_run:
                summary["honey_fps_restored"] += 1; continue
            if _conn is None: continue
            try:
                _conn.execute(
                    "INSERT INTO honey_fingerprints "
                    "(ts, track_key, ip, ua, ja4, asn, path, reason) "
                    "VALUES (?, NULL, ?, ?, ?, ?, ?, ?)",
                    (ts, ip, fp.attrib.get("ua") or "", fp.attrib.get("ja4") or "",
                     fp.attrib.get("asn") or "", fp.attrib.get("path") or "",
                     fp.attrib.get("reason") or ""))
                summary["honey_fps_restored"] += 1
            except Exception as _e:
                summary["errors"].append(f"honey_fp {ip}: {_e}")

    # 8) gw_registry — UPSERT by gw_id. NEVER overwrite the local row's
    #    private_key on a vanilla import (it's the live HMAC mesh secret).
    reg_el = root.find("gw_registry")
    if reg_el is not None:
        for ge in reg_el.findall("gw"):
            gw_id = ge.attrib.get("gw_id") or ""
            if not gw_id:
                continue
            if dry_run:
                summary["gw_registry_restored"] += 1; continue
            if _conn is None: continue
            try:
                # Probe the existing row to decide whether to keep its private_key.
                existing_priv = None
                _r = _conn.execute(
                    "SELECT private_key, is_local FROM gw_registry WHERE gw_id=?",
                    (gw_id,)).fetchone()
                if _r:
                    existing_priv = _r["private_key"]
                new_priv = ge.attrib.get("private_key") or existing_priv
                _conn.execute(
                    "INSERT INTO gw_registry "
                    "(gw_id, domain, region, environment, status, can_distribute, "
                    " public_key, private_key, key_created_ts, key_rotated_ts, "
                    " last_seen_ts, created_ts, updated_ts, is_local, auto_apply) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?) "
                    "ON CONFLICT(gw_id) DO UPDATE SET "
                    "  domain=excluded.domain, region=excluded.region, "
                    "  environment=excluded.environment, status=excluded.status, "
                    "  can_distribute=excluded.can_distribute, "
                    "  public_key=excluded.public_key, "
                    "  private_key=COALESCE(gw_registry.private_key, excluded.private_key), "
                    "  updated_ts=excluded.updated_ts, "
                    "  auto_apply=excluded.auto_apply",
                    (gw_id, ge.attrib.get("domain") or "",
                     ge.attrib.get("region") or "", ge.attrib.get("environment") or "",
                     ge.attrib.get("status") or "active",
                     1 if (ge.attrib.get("can_distribute") or "1") in ("1", "true") else 0,
                     ge.attrib.get("public_key") or "",
                     new_priv,
                     float(ge.attrib.get("key_created_ts") or _t.time()),
                     _t.time(), _t.time(),
                     1 if (ge.attrib.get("is_local") or "0") in ("1", "true") else 0,
                     1 if (ge.attrib.get("auto_apply") or "0") in ("1", "true") else 0))
                summary["gw_registry_restored"] += 1
            except Exception as _e:
                summary["errors"].append(f"gw {gw_id}: {_e}")
        # S-I5 fix: invalidate the cached LOCAL gw_id so subsequent audit /
        # mesh-sync ops re-read from the freshly imported rows.
        if not dry_run and summary["gw_registry_restored"] > 0:
            try:
                from admin.mesh import _reset_local_gw_id
                _reset_local_gw_id()
            except Exception:
                pass

    # 9) gw_distribution — UPSERT by (source, target).
    dist_el = root.find("gw_distribution")
    if dist_el is not None:
        for pe in dist_el.findall("pair"):
            src = pe.attrib.get("source_gw_id") or ""
            tgt = pe.attrib.get("target_gw_id") or ""
            if not src or not tgt:
                continue
            if dry_run:
                summary["gw_distribution_restored"] += 1; continue
            if _conn is None: continue
            try:
                _conn.execute(
                    "INSERT INTO gw_distribution (source_gw_id, target_gw_id, ts) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT(source_gw_id, target_gw_id) DO UPDATE SET ts=excluded.ts",
                    (src, tgt, _t.time()))
                summary["gw_distribution_restored"] += 1
            except Exception as _e:
                summary["errors"].append(f"gw_distribution {src}->{tgt}: {_e}")

    # 10) users — INSERT OR IGNORE so an existing admin is never silently
    #     overwritten by an import. password_hash is only present when the
    #     export was taken with include_secrets=1.
    users_el = root.find("users")
    if users_el is not None:
        for ue in users_el.findall("user"):
            uname = ue.attrib.get("username") or ""
            if not uname:
                continue
            if dry_run:
                summary["users_restored"] += 1; continue
            if _conn is None: continue
            phash = ue.attrib.get("password_hash") or ""
            if not phash:
                # without a hash the row is unusable (login would always fail)
                continue
            # S-W7 fix: validate role/status against allowlists. Crafted XML
            # could otherwise insert a row with a bogus role string (defence
            # in depth — endpoint is already admin-gated + CSRF-checked).
            from admin.users import _USER_ROLES, _USER_STATUS
            _imp_role = ue.attrib.get("role") or "admin"
            _imp_stat = ue.attrib.get("status") or "active"
            if _imp_role not in _USER_ROLES:
                summary["errors"].append(
                    f"user {uname}: invalid role {_imp_role!r}, defaulting to viewer")
                _imp_role = "viewer"
            if _imp_stat not in _USER_STATUS:
                summary["errors"].append(
                    f"user {uname}: invalid status {_imp_stat!r}, defaulting to disabled")
                _imp_stat = "disabled"
            try:
                _conn.execute(
                    "INSERT OR IGNORE INTO users "
                    "(username, password_hash, role, status, created_ts, updated_ts, "
                    " last_login_ts, last_login_ip) "
                    "VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)",
                    (uname, phash, _imp_role, _imp_stat,
                     float(ue.attrib.get("created_ts") or _t.time()),
                     float(ue.attrib.get("updated_ts") or _t.time())))
                summary["users_restored"] += 1
            except Exception as _e:
                summary["errors"].append(f"user {uname}: {_e}")

    # 11) secrets_kv — UPSERT by key. Only present when the export was
    #     taken with include_secrets=1.
    secrets_el = root.find("secrets")
    if secrets_el is not None:
        for se in secrets_el.findall("secret"):
            key = se.attrib.get("key") or ""
            if not key:
                continue
            val = se.text or ""
            if dry_run:
                summary["secrets_restored"] += 1; continue
            if _conn is None: continue
            try:
                _conn.execute(
                    "INSERT INTO secrets_kv (key, value, ts) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, ts=excluded.ts",
                    (key, val, _t.time()))
                summary["secrets_restored"] += 1
            except Exception as _e:
                summary["errors"].append(f"secret {key}: {_e}")

    if _conn is not None:
        try:
            _conn.commit()
            _conn.close()
        except Exception:
            pass  # nosec B110 — commit/close failure is logged in errors[] already

    actor = _request_username(request)
    slog("config_imported", level="warn",
         rid=request.get("_rid", ""), actor=actor,
         dry_run=dry_run,
         knobs_applied=summary["knobs_applied"],
         knobs_rejected=summary["knobs_rejected"],
         admin_ips_added=summary["admin_ips_added"],
         vhosts_restored=summary["vhosts_restored"],
         siem_rules_added=summary["siem_rules_added"],
         dlp_patterns_added=summary["dlp_patterns_added"],
         signal_orders_restored=summary["signal_orders_restored"],
         honey_fps_restored=summary["honey_fps_restored"],
         gw_registry_restored=summary["gw_registry_restored"],
         gw_distribution_restored=summary["gw_distribution_restored"],
         users_restored=summary["users_restored"],
         secrets_restored=summary["secrets_restored"])
    if not dry_run:
        _gw_audit("settings_import", _gw_local_id(), actor,
                  knobs_applied=summary["knobs_applied"],
                  admin_ips_added=summary["admin_ips_added"],
                  vhosts_restored=summary["vhosts_restored"],
                  siem_rules_added=summary["siem_rules_added"],
                  dlp_patterns_added=summary["dlp_patterns_added"],
                  signal_orders_restored=summary["signal_orders_restored"],
                  honey_fps_restored=summary["honey_fps_restored"],
                  gw_registry_restored=summary["gw_registry_restored"],
                  gw_distribution_restored=summary["gw_distribution_restored"],
                  users_restored=summary["users_restored"],
                  secrets_restored=summary["secrets_restored"],
                  applied=summary["applied"])
    return web.json_response(summary, headers={"Cache-Control": "no-store"})


@_require_csrf
async def vhosts_endpoint(request: web.Request):
    """GET /__vhosts  — list all vhost entries.
       POST /__vhosts — add or update a vhost entry.
       DELETE /__vhosts — remove a vhost entry."""
    if denied := _role_denied(request, "admin"):
        return denied

    from vhost import vhost_list, vhost_set, vhost_delete

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
    """GET /__vhost-stats — per-vhost traffic counters for 1h and 24h.

    1.9.1 iter-12 fix: previously hard-coded `sqlite3.connect(_DATA_PATH)`
    which silently returned an empty list in PG-only mode (events live in
    PG, not in the local SQLite file). Route through the backend-aware
    `db_read_events` helper so the panel works on both backends.

    1.9.2 perf — the aggregation now runs as a `GROUP BY vhost` query
    (PG: COUNT(*) FILTER WHERE; SQLite same syntax since 3.30) so the
    backend returns one row per vhost instead of every event for the
    last 24 h. On a busy gateway the previous Python-side aggregation
    pulled millions of rows over the wire just to bucket them. Result
    is cached for 15 s — the Settings page + Vhost Policy page both
    refresh it on focus, so this is enough to make back-to-back loads
    near-free.
    """
    if denied := _role_denied(request, "admin"):
        return denied

    import sqlite3 as _sq3
    now = _t.time()
    rows = _vhost_stats_cached()

    # 1.9.1 iter-18: read the dismissed-hosts config_kv row through
    # open_conn. The old bare `_sq3.connect(_DATA_PATH)` claimed config_kv
    # was "shared across backends" but in PG-only mode the writer NEVER
    # touches local SQLite — config writes go to PG only — so this read
    # returned a stale/empty local file and dismissed hosts reappeared.
    from db import open_conn as _open_conn_ds
    try:
        conn = _open_conn_ds()
        conn.row_factory = _sq3.Row
        _dismissed_row = conn.execute(
            "SELECT value FROM config_kv WHERE key = 'dismissed_discovered_hosts'"
        ).fetchone()
        conn.close()
    except Exception:
        _dismissed_row = None

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
    from admin.auth import _csrf_token_valid
    if not _csrf_token_valid(request):
        return web.json_response({"error": "CSRF token invalid"}, status=403,
                                  headers={"Cache-Control": "no-store"})

    import json as _json
    try:
        body = await request.json()
        hostname = (body.get("hostname") or "").strip()
    except Exception:
        return web.json_response({"error": "invalid JSON"}, status=400)
    if not hostname:
        return web.json_response({"error": "hostname required"}, status=400)

    # 1.9.1 iter-18: dismissed-hosts read+write must hit the active
    # backend. The old bare `_sq3.connect(_DATA_PATH)` read stale data
    # AND the SQLite-only `INSERT OR REPLACE` write never reached PG, so
    # dismissing a host silently did nothing in PG-only mode. Route
    # through open_conn + branch the upsert DML by backend.
    from db import open_conn as _open_conn_dw, active_backend as _active_dw
    _be_dw = _active_dw()
    try:
        conn = _open_conn_dw()
        row = conn.execute(
            "SELECT value FROM config_kv WHERE key = 'dismissed_discovered_hosts'"
        ).fetchone()
        dismissed: set = set(_json.loads(row["value"])) if row else set()
        if request.method == "DELETE":
            dismissed.discard(hostname)
        else:
            dismissed.add(hostname)
        ts = _t.time()
        if _be_dw == "postgres":
            conn.execute(
                "INSERT INTO config_kv (key, value, ts) VALUES (?, ?, ?) "
                "ON CONFLICT (key) DO UPDATE SET value = excluded.value, ts = excluded.ts",
                ("dismissed_discovered_hosts", _json.dumps(sorted(dismissed)), ts),
            )
        else:
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

    # 1.9.1 iter-17: per-vhost slot read. PG path projects ts → epoch
    # for the slot arithmetic and wraps the bounds in to_timestamp().
    from db import open_conn as _open_conn_vs, active_backend as _active_vs
    _be_vs = _active_vs()
    try:
        conn = _open_conn_vs()
        conn.row_factory = _sq3.Row
        if _be_vs == "postgres":
            _sql_vs = (
                "SELECT vhost, "
                # PG CAST(numeric AS INTEGER) ROUNDS half-up, so an event in the
                # final partial bucket rounds UP to slot==n_slots and is dropped
                # by the 0<=slot<n_slots filter. FLOOR truncates like SQLite's
                # CAST + the Python int() n_slots math. (vhost_breakdown D04)
                "  CAST(FLOOR((EXTRACT(EPOCH FROM ts) - ?) / ?) AS INTEGER) AS slot, "
                "  COUNT(*) AS cnt "
                "FROM events "
                "WHERE ts >= to_timestamp(?) AND ts <= to_timestamp(?) AND vhost != '' "
                "GROUP BY vhost, slot "
                "ORDER BY slot"
            )
        else:
            _sql_vs = (
                "SELECT vhost, "
                "  CAST((ts - ?) / ? AS INTEGER) AS slot, "
                "  COUNT(*) AS cnt "
                "FROM events "
                "WHERE ts >= ? AND ts <= ? AND vhost != '' "
                "GROUP BY vhost, slot "
                "ORDER BY slot"
            )
        rows = conn.execute(
            _sql_vs, (start_ts, bucket_sec, start_ts, end_ts)
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
    from db.sqlite import get_ui_theme as _get_theme
    _theme = _get_theme(DB_PATH)
    return web.Response(
        text=VHOST_POLICY_DASHBOARD_HTML.replace('<html lang="en">', f'<html lang="en" data-theme="{_theme}">', 1),
        content_type="text/html",
        headers=_SECURITY_HEADERS,
    )


async def vhost_policy_data_endpoint(request: web.Request):
    """GET /__vhost-policy-data?hostname=<host>[&summary=1]
    Returns merged global config + vhost overrides for the given hostname.

    Response shape (default):
      {
        "hostname": str,
        "vhost_knobs": [str, ...],   # all keys declared in _VHOST_COERCE
        "overrides": {KEY: value},   # what this vhost currently overrides
        "global": {KEY: value},      # global value for every vhost-overridable knob
        "vhosts": [str, ...],        # list of all configured vhost hostnames
        "seen_vhosts": [str, ...]    # 30 d distinct vhost from events table
      }

    1.9.2 perf — `summary=1` mode for the per-vhost fan-out fired by the
    Policy page's `_loadAllVhostSummary`. That code only needs `overrides`
    for each vhost, but the full payload re-runs the (expensive) DISTINCT
    vhost scan on the events table AND re-serialises ~50 globals × N
    vhosts per page load. Summary mode returns:
      {"hostname": ..., "overrides": {...}}
    skipping the events-table scan + the static `global` / `vhost_knobs`
    payloads. Cuts a 7-vhost dashboard load from N×(scan + serialise) to
    1×(scan) + N×(O(1) dict lookup).
    """
    if denied := _role_denied(request, "admin"):
        return denied

    import sys as _sys
    from vhost import VHOSTS, _VHOST_COERCE, _json_safe, vhost_list

    hostname = request.query.get("hostname", "").strip().lower()
    summary  = request.query.get("summary", "") in ("1", "true", "yes")

    # Current overrides for the requested hostname — always cheap, always
    # in the response.
    overrides: dict = {}
    if hostname and hostname in VHOSTS:
        overrides = {k: _json_safe(v) for k, v in VHOSTS[hostname].items()}

    # Summary mode short-circuit: the fan-out caller only consumes
    # `overrides`. Skip the static `vhost_knobs` / `global` payloads and
    # the events-table scan entirely.
    if summary:
        return web.json_response(
            {"hostname": hostname, "overrides": overrides},
            headers={"Cache-Control": "no-store"},
        )

    # All vhost-overridable knob names (stable, sorted)
    vhost_knobs = sorted(_VHOST_COERCE.keys())

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

    # 1.8.14 — surface every distinct vhost the gateway has EVER recorded an
    # event for (last 30 d cap to keep the query bounded). Lets the Policy
    # dropdown include historical/quiet hosts that fell outside the 24h window
    # of /vhost-stats — operators couldn't otherwise pick them to add overrides.
    # 1.9.2 — cached for 60 s in `_SEEN_VHOSTS_CACHE` so repeated page-loads
    # don't re-scan the events table; result is identical regardless of
    # `hostname` query param.
    seen_vhosts: list = _seen_vhosts_cached()

    return web.json_response(
        {
            "hostname":   hostname,
            "vhost_knobs": vhost_knobs,
            "overrides":  overrides,
            "global":     global_vals,
            "vhosts":     [v["hostname"] for v in vhost_list()],
            "seen_vhosts": seen_vhosts,
        },
        headers={"Cache-Control": "no-store"},
    )


# 1.9.2 perf — 60 s cache for the 30-day DISTINCT vhost scan on events.
# Operator UX doesn't need second-by-second freshness on a historical view,
# and the prior behaviour re-ran the scan on every /vhost-policy-data call.
_SEEN_VHOSTS_CACHE: dict = {"ts": 0.0, "value": []}
_SEEN_VHOSTS_TTL = 60.0


def _seen_vhosts_cached() -> list:
    """Return cached 30-day DISTINCT-vhost list (refreshed every 60 s).
    Backend-branched: PG TIMESTAMPTZ uses to_timestamp() bound, SQLite uses
    raw epoch. Failures return an empty list (logged-but-degraded UX)."""
    now_ts = _t.time()
    cached_ts = _SEEN_VHOSTS_CACHE.get("ts", 0.0)
    if now_ts - cached_ts < _SEEN_VHOSTS_TTL:
        return _SEEN_VHOSTS_CACHE.get("value") or []
    try:
        from db import open_conn as _open_conn_dv, active_backend as _active_dv
        _cut = now_ts - (30 * 86400)
        _be_dv = _active_dv()
        _conn = _open_conn_dv()
        try:
            if _be_dv == "postgres":
                _sql_dv = (
                    "SELECT DISTINCT vhost FROM events "
                    "WHERE vhost != '' AND ts >= to_timestamp(?) "
                    "ORDER BY vhost"
                )
            else:
                _sql_dv = (
                    "SELECT DISTINCT vhost FROM events "
                    "WHERE vhost != '' AND ts >= ? "
                    "ORDER BY vhost"
                )
            _rows = _conn.execute(_sql_dv, (_cut,)).fetchall()
            value = [r[0] for r in _rows if r[0]]
        finally:
            _conn.close()
    except Exception:
        value = _SEEN_VHOSTS_CACHE.get("value") or []
    _SEEN_VHOSTS_CACHE["ts"] = now_ts
    _SEEN_VHOSTS_CACHE["value"] = value
    return value


# 1.9.2 perf — per-vhost traffic counters, computed as a SQL GROUP BY
# instead of the previous "read all 24h rows + Python loop" pattern.
# 15 s cache so back-to-back page loads stay fast.
_VHOST_STATS_CACHE: dict = {"ts": 0.0, "value": []}
_VHOST_STATS_TTL = 15.0


def _vhost_stats_cached() -> list:
    """Return cached per-vhost stats (refreshed every 15 s).

    Returns a list of dicts:
      [{"vhost":..., "total_1h":..., "allowed_1h":..., "blocked_1h":...,
        "total_24h":..., "blocked_24h":..., "last_seen_ts":...}, ...]
    sorted by total_1h desc.

    The SQL pushes the aggregation to the DB via COUNT(*) FILTER WHERE
    (PG + SQLite ≥3.30) so the wire returns one row per vhost rather
    than every event. Backend-branched timestamp form (PG TIMESTAMPTZ
    needs to_timestamp(), SQLite uses raw epoch). Failures return the
    last cached list rather than 500-ing the dashboard.
    """
    now_ts = _t.time()
    cached_ts = _VHOST_STATS_CACHE.get("ts", 0.0)
    if now_ts - cached_ts < _VHOST_STATS_TTL:
        return _VHOST_STATS_CACHE.get("value") or []
    h1 = now_ts - 3600
    h24 = now_ts - 86400
    # Reason buckets — mirrors the previous Python-side rules.
    _ALLOWED_REASONS = ("", "ok", "allowed", "authorized-robot")
    _PASSTHROUGH_REASONS = ("", "ok", "allowed", "authorized-robot",
                            "operator-passthrough", "internal-probe",
                            "operator-self")
    try:
        from db import open_conn as _open_conn_vs, active_backend as _active_vs
        _be = _active_vs()
        # Compose placeholder lists for the IN() / NOT IN() filters. SQLite
        # uses ?, PG uses %s — but db.conn rewrites ? → %s transparently,
        # so we always write ?.
        _ph_allowed   = ",".join(["?"] * len(_ALLOWED_REASONS))
        _ph_passthru  = ",".join(["?"] * len(_PASSTHROUGH_REASONS))
        if _be == "postgres":
            _ts_h1   = "to_timestamp(?)"
            _ts_h24  = "to_timestamp(?)"
            _ts_extract = "EXTRACT(EPOCH FROM MAX(ts))"
        else:
            _ts_h1   = "?"
            _ts_h24  = "?"
            _ts_extract = "MAX(ts)"
        sql = (
            f"SELECT vhost, "
            f"  COUNT(*) FILTER (WHERE ts >= {_ts_h1}) AS total_1h, "
            f"  COUNT(*) FILTER (WHERE ts >= {_ts_h1} "
            f"                    AND reason IN ({_ph_allowed})) AS allowed_1h, "
            f"  COUNT(*) FILTER (WHERE ts >= {_ts_h1} "
            f"                    AND reason NOT IN ({_ph_passthru})) AS blocked_1h, "
            f"  COUNT(*) AS total_24h, "
            f"  COUNT(*) FILTER (WHERE reason NOT IN ({_ph_passthru})) AS blocked_24h, "
            f"  {_ts_extract} AS last_seen_ts "
            f"FROM events "
            f"WHERE vhost != '' AND ts >= {_ts_h24} "
            f"GROUP BY vhost"
        )
        # Params order matches the placeholders in the SQL:
        #   h1 (total_1h),
        #   h1 + allowed reasons (allowed_1h),
        #   h1 + passthrough reasons (blocked_1h),
        #   passthrough reasons (blocked_24h),
        #   h24 (the outer WHERE)
        params = [
            h1,
            h1, *_ALLOWED_REASONS,
            h1, *_PASSTHROUGH_REASONS,
            *_PASSTHROUGH_REASONS,
            h24,
        ]
        _conn = _open_conn_vs()
        try:
            _rows = _conn.execute(sql, params).fetchall()
        finally:
            _conn.close()
        value = []
        for r in _rows:
            # Row indexing works on both sqlite3.Row and psycopg tuples.
            value.append({
                "vhost":        r[0],
                "total_1h":     int(r[1] or 0),
                "allowed_1h":   int(r[2] or 0),
                "blocked_1h":   int(r[3] or 0),
                "total_24h":    int(r[4] or 0),
                "blocked_24h":  int(r[5] or 0),
                "last_seen_ts": float(r[6] or 0.0),
            })
        value.sort(key=lambda r: (-r["total_1h"], -r["total_24h"], r["vhost"]))
    except Exception:
        value = _VHOST_STATS_CACHE.get("value") or []
    _VHOST_STATS_CACHE["ts"] = now_ts
    _VHOST_STATS_CACHE["value"] = value
    return value


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
    # S-I4 fix: when no explicit since is supplied, default to the last 30
    # days so a wildcard `action=%` query cannot full-scan a multi-million-row
    # gw_audit table and block the SQLite writer.
    if since <= 0:
        since = _t.time() - (30 * 86400)

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

    # 1.9.1 iter-18: gw-audit log viewer must read the active backend.
    # gw_audit IS PG-mirrored (_h_gw_audit_add), so the old bare
    # `_sq3.connect(DB_PATH)` returned an empty local file in PG-only mode
    # and the audit-log viewer showed nothing. `gw_audit.ts` is DOUBLE
    # PRECISION on PG (no TIMESTAMPTZ), and the WHERE clauses filter on
    # action/actor (no ts comparison), so only the connection target
    # needed fixing.
    from db import open_conn as _open_conn_ga
    try:
        conn = _open_conn_ga()
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

_SKIP_REASONS = ('', 'ok', 'allowed', 'authorized-robot', 'operator-passthrough', 'internal-probe', 'operator-self')


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
    # 1.9.1 iter-16: PG-mode fix. Direct sqlite3.connect(_DATA_PATH) was
    # silently reading the local SQLite file (empty in PG-only mode) instead
    # of erroring — so the chart rendered blank with no diagnostic. Route
    # through the backend-aware open_conn() + branch the SQL on PG to wrap
    # the epoch bounds in to_timestamp() and project ts → epoch via
    # EXTRACT(EPOCH FROM ts) so the (ts - start_ts)/bucket_sec slot math
    # stays valid. Same fix family as iter-12 vhost-stats.
    from db import open_conn as _open_conn_e, active_backend as _active_e
    _be_e = _active_e()
    try:
        conn = _open_conn_e()
        conn.row_factory = _sq3.Row  # PG wrapper interprets as dict_row
        if _be_e == "postgres":
            sql = (
                f"SELECT reason, "
                # FLOOR so PG truncates like SQLite CAST + Python int() (see
                # vhost_breakdown above) — avoids dropping final-bucket events.
                f"  CAST(FLOOR((EXTRACT(EPOCH FROM ts) - ?) / ?) AS INTEGER) AS slot, "
                f"  COUNT(*) AS cnt "
                f"FROM events "
                f"WHERE ts >= to_timestamp(?) AND ts <= to_timestamp(?) "
                f"AND (reason IS NULL OR reason NOT IN ({skip_ph})) "
                f"GROUP BY reason, slot ORDER BY slot"
            )
        else:
            sql = (
                f"SELECT reason, CAST((ts - ?) / ? AS INTEGER) AS slot, COUNT(*) AS cnt "  # nosec B608
                f"FROM events WHERE ts >= ? AND ts <= ? "
                f"AND (reason IS NULL OR reason NOT IN ({skip_ph})) "
                f"GROUP BY reason, slot ORDER BY slot"
            )
        rows = conn.execute(
            sql,
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
    # 1.9.1 iter-17 follow-up: top-paths read also needs PG branch.
    # The iter-17 forward-looking guard had a false-negative here because
    # the dow×hour heatmap above shares the same function file and its
    # `to_timestamp(?)` lives within the ±1800-char detection window. The
    # iter-17 QA test (test_all_iter17_fixes_route_through_open_conn)
    # caught the bare `_sq3.connect()` and forced this fix.
    from db import open_conn as _open_conn_tp, active_backend as _active_tp
    _be_tp = _active_tp()
    try:
        conn = _open_conn_tp()
        conn.row_factory = _sq3.Row
        if _be_tp == "postgres":
            _sql_tp = (
                f"SELECT path, COUNT(*) AS blocked FROM events "  # nosec B608
                f"WHERE ts >= to_timestamp(?) AND path IS NOT NULL AND path != '' "
                f"AND reason NOT IN ({skip_ph}) "
                f"GROUP BY path ORDER BY blocked DESC LIMIT ?"
            )
        else:
            _sql_tp = (
                f"SELECT path, COUNT(*) AS blocked FROM events "  # nosec B608
                f"WHERE ts >= ? AND path IS NOT NULL AND path != '' "
                f"AND reason NOT IN ({skip_ph}) "
                f"GROUP BY path ORDER BY blocked DESC LIMIT ?"
            )
        rows = conn.execute(
            _sql_tp, (start_ts, *_SKIP_REASONS, limit)
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
    # 1.9.1 iter-16: PG-mode fix. strftime() is SQLite-specific — PG uses
    # EXTRACT(DOW FROM ts) and EXTRACT(HOUR FROM ts). Direct sqlite3
    # connect would also silently return empty in PG-only mode. Branch
    # by backend so the heatmap populates on both.
    from db import open_conn as _open_conn_h, active_backend as _active_h
    _be_h = _active_h()
    try:
        conn = _open_conn_h()
        conn.row_factory = _sq3.Row
        if _be_h == "postgres":
            sql = (
                f"SELECT CAST(EXTRACT(DOW  FROM ts) AS INTEGER) AS dow, "  # nosec B608
                f"       CAST(EXTRACT(HOUR FROM ts) AS INTEGER) AS hour, "
                f"       COUNT(*) AS n "
                f"FROM events WHERE ts >= to_timestamp(?) "
                f"AND reason NOT IN ({skip_ph}) "
                f"GROUP BY dow, hour"
            )
        else:
            sql = (
                f"SELECT CAST(strftime('%w', ts, 'unixepoch') AS INTEGER) AS dow, "  # nosec B608
                f"       CAST(strftime('%H', ts, 'unixepoch') AS INTEGER) AS hour, "
                f"       COUNT(*) AS n "
                f"FROM events WHERE ts >= ? AND reason NOT IN ({skip_ph}) "
                f"GROUP BY dow, hour"
            )
        rows = conn.execute(sql, (start_ts, *_SKIP_REASONS)).fetchall()
        conn.close()
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500,
                                  headers={"Cache-Control": "no-store"})
    cells   = [[int(r["dow"]), int(r["hour"]), int(r["n"])] for r in rows]
    max_val = max((c[2] for c in cells), default=0)
    return web.json_response({"cells": cells, "max": max_val, "ts": int(_t.time())},
                              headers={"Cache-Control": "no-store"})
