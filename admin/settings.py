# admin/settings.py — Phase 8: settings export/import + settings dashboard
# Extracted from proxy.py lines 11284–11612
import time as _t       # noqa: F401
from config import *   # noqa: F401,F403
from config import _DASHBOARDS_DIR  # noqa: F401 — leading-underscore not in *
from state import *    # noqa: F401,F403
from helpers import slog  # noqa: F401
from admin.auth import _internal_authed, ADMIN_ALLOWED_ENTRIES, _role_denied  # noqa: F401
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
                "frame-ancestors 'none'; base-uri 'none'"
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

    slog("config_imported", level="warn",
         rid=request.get("_rid", ""),
         dry_run=dry_run,
         knobs_applied=summary["knobs_applied"],
         knobs_rejected=summary["knobs_rejected"],
         admin_ips_added=summary["admin_ips_added"],
         secrets_applied=summary["secrets_applied"])
    return web.json_response(summary, headers={"Cache-Control": "no-store"})
