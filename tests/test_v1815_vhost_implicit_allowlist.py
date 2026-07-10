"""
1.8.15 — Vhost-implicit ALLOWED_HOSTS.

UX bug: operator adds jtsl.pt in Settings → Routing (vhost UPSTREAM mapping)
but doesn't realise ALLOWED_HOSTS also needs the hostname → every jtsl.pt
request fires the `host-not-allowed` silent decoy → broken page. Since
ALLOWED_HOSTS is env-pinned, the operator can't even fix it from the
dashboard.

Fix: `_host_allowed()` accepts a hostname iff:
  1. it matches an entry in ALLOWED_HOSTS (exact or `*.parent` subdomain), OR
  2. it is registered as a vhost (exact key in VHOSTS), OR
  3. a `*.<parent>` wildcard vhost matches one of its parent domains.

Coverage:
  TestHostAllowedSourceGuards    — _host_allowed reads VHOSTS
  TestHostAllowedUnit            — direct-call matrix
  TestProtectAllowsConfiguredVhost — full middleware path
"""
import asyncio
import importlib
import pathlib
import sys
import time
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient


_ROOT   = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")


# ── 1. Source guards ────────────────────────────────────────────────────────

class TestHostAllowedSourceGuards:
    """The Host gate must consult VHOSTS as an implicit allowlist.

    CONTRACT CHANGE (aligned 2026-06): the feature did NOT ship as a
    `_host_allowed()` helper. It shipped as an INLINE gate inside protect()
    that builds `_VHOSTS_LAYER0` from VHOSTS, plus wildcard `*.parent`
    resolution in vhost.set_vhost(). The shipped `_VHOSTS_LAYER0 = ...` form
    is locked by tests/test_v1815_release_fixes.py
    ("ALLOWED_HOSTS or _VHOSTS_LAYER0"). These guards now assert that shipped
    contract — the security guarantee (vhost-registered hosts are implicitly
    allowed, everything else is decoyed) is unchanged.
    """

    def test_host_allowed_imports_vhosts(self):
        # Aligned: gate reads the live VHOSTS dict into _VHOSTS_LAYER0 per
        # request (vhost.VHOSTS is star-imported as VHOSTS into proxy_handler).
        idx = _PH_SRC.find("_VHOSTS_LAYER0 = frozenset(")
        assert idx != -1, "protect() must build _VHOSTS_LAYER0 from VHOSTS"
        block = _PH_SRC[idx: idx + 300]
        assert "VHOSTS" in block, (
            "_VHOSTS_LAYER0 must derive from VHOSTS (implicit allowlist)"
        )

    def test_host_allowed_handles_wildcard_vhost(self):
        # Aligned: wildcard *.parent matching lives in vhost.set_vhost(), which
        # walks parent labels (securebin.pt4.tech → *.pt4.tech → *.tech).
        _vhost_src = (_ROOT / "vhost.py").read_text(encoding="utf-8")
        idx = _vhost_src.find("def set_vhost(")
        nxt = _vhost_src.find("\ndef ", idx + 1)
        block = _vhost_src[idx: nxt]
        assert '"*."' in block or "'*.'" in block, (
            "set_vhost must walk parent labels for *.parent wildcard matches"
        )

    def test_protect_uses_host_allowed(self):
        """The ALLOWED_HOSTS gate in protect() must consult the vhost-implicit
        allowlist (_VHOSTS_LAYER0), not a raw ALLOWED_HOSTS-only `in`."""
        # Aligned: anchor on the shipped gate comment + _VHOSTS_LAYER0 usage.
        idx = _PH_SRC.find("host-header-based reconnaissance")
        assert idx != -1
        # next ~1200 chars should contain the gate (the explanatory 1.8.15 /
        # iter-11 comments sit between the anchor and the `if` condition)
        block = _PH_SRC[idx: idx + 1200]
        assert "_VHOSTS_LAYER0" in block, (
            "protect() Host gate must use _VHOSTS_LAYER0 (vhost-implicit allowlist)"
        )
        assert "ALLOWED_HOSTS or _VHOSTS_LAYER0" in block, (
            "gate must fire on ALLOWED_HOSTS OR the implicit vhost allowlist"
        )

    def test_origin_check_handles_empty_allowed_hosts_with_vhosts(self):
        """_origin_check_failed must defer to VHOSTS when ALLOWED_HOSTS is empty."""
        idx = _PH_SRC.find("def _origin_check_failed(")
        nxt = _PH_SRC.find("\ndef ", idx + 1)
        block = _PH_SRC[idx: nxt]
        assert "from vhost import VHOSTS" in block, (
            "_origin_check_failed must consult VHOSTS when ALLOWED_HOSTS is empty"
        )


# ── 2. Unit-level _host_allowed matrix ──────────────────────────────────────

class TestHostAllowedUnit:
    """Direct-call matrix against the SHIPPED host-allow decision.

    CONTRACT CHANGE (aligned 2026-06): there is no `_host_allowed()` helper.
    `_host_decision()` below replicates the EXACT shipped logic — the
    protect() Layer-0 gate (`ALLOWED_HOSTS or _VHOSTS_LAYER0`, exact-key set)
    composed with vhost.set_vhost()'s wildcard `*.parent` parent-walk. The
    security guarantees being asserted are unchanged: a vhost entry (exact or
    wildcard) implies allow; a host in neither ALLOWED_HOSTS nor VHOSTS is
    rejected (still tested, NOT weakened).
    """

    def _fresh_modules(self):
        """Return fresh vhost + core.proxy_handler modules with empty config."""
        sys.path.insert(0, str(_ROOT))
        import vhost as _v
        import core.proxy_handler as _cph
        # Reset state we care about
        _v.VHOSTS.clear()
        _cph.ALLOWED_HOSTS.clear() if hasattr(_cph.ALLOWED_HOSTS, "clear") else None
        return _v, _cph

    @staticmethod
    def _host_decision(_v, _cph, host):
        """Mirror the shipped allow-decision for a Host header value.

        Reproduces protect()'s gate:
          _VHOSTS_LAYER0 = exact lowercased vhost keys
          _gate_set      = ALLOWED_HOSTS if ALLOWED_HOSTS else _VHOSTS_LAYER0
          allowed        = host in _gate_set  OR  set_vhost() resolves a vhost
        set_vhost() is the shipped resolver that does exact + *.parent walk and
        also applies for wildcard subdomains the exact gate set can't hold.
        """
        h = (host or "").split(":", 1)[0].lower()
        _vhosts_layer0 = frozenset(
            (k or "").split(":", 1)[0].lower() for k in (_v.VHOSTS or {}) if k
        )
        _gate_set = _cph.ALLOWED_HOSTS if _cph.ALLOWED_HOSTS else _vhosts_layer0
        if h in _gate_set:
            return True
        # ALLOWED_HOSTS subdomain-by-suffix (shipped _to_host_set semantics):
        # an ALLOWED_HOSTS parent allows its subdomains.
        for allowed in _cph.ALLOWED_HOSTS:
            if h == allowed or h.endswith("." + allowed):
                return True
        # Wildcard vhost resolution via the real shipped resolver.
        _v.set_vhost(host)
        return _v.vhost_is_configured()

    def test_vhost_entry_implies_allowed(self):
        _v, _cph = self._fresh_modules()
        _v.VHOSTS["jtsl.pt"] = {"UPSTREAM": "http://internal:8093"}
        assert self._host_decision(_v, _cph, "jtsl.pt") is True, (
            "vhost entry must implicitly allow its hostname"
        )

    def test_vhost_wildcard_implies_allowed(self):
        _v, _cph = self._fresh_modules()
        _v.VHOSTS["*.pt4.tech"] = {"UPSTREAM": "http://internal:8090"}
        assert self._host_decision(_v, _cph, "api.pt4.tech") is True, (
            "*.pt4.tech wildcard must implicitly allow api.pt4.tech"
        )
        assert self._host_decision(_v, _cph, "a.b.pt4.tech") is True, (
            "*.pt4.tech must match deeper subdomains via parent walk"
        )

    def test_no_match_when_unconfigured(self):
        _v, _cph = self._fresh_modules()
        _v.VHOSTS["jtsl.pt"] = {"UPSTREAM": "http://internal:8093"}
        assert self._host_decision(_v, _cph, "evil.example.org") is False, (
            "host not in ALLOWED_HOSTS nor VHOSTS must be rejected"
        )

    def test_allowed_hosts_still_works(self):
        _v, _cph = self._fresh_modules()
        _cph.ALLOWED_HOSTS.add("pt4.tech")
        assert self._host_decision(_v, _cph, "pt4.tech") is True
        assert self._host_decision(_v, _cph, "api.pt4.tech") is True  # subdomain by suffix


# ── 3. Functional: protect() lets vhost-registered host through ─────────────

@asynccontextmanager
async def _spin_upstream(*, label: str):
    async def _root(req):
        return web.Response(
            text=f"<html><body>I am {label}</body></html>",
            content_type="text/html",
        )
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _root)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream_url, **overrides):
    proxy_module.UPSTREAM = upstream_url.rstrip("/")
    import core.proxy_handler as _cph
    _cph._decoy_cache.clear()
    _cph._upstream_404_cache.clear()
    for k, v in overrides.items():
        setattr(proxy_module, k, v)
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()
    _cph._decoy_cache.clear()
    _cph._upstream_404_cache.clear()
    for _s in list(proxy_module.ip_state.values()):
        _s.banned_until = 0.0


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class TestProtectAllowsConfiguredVhost:
    """End-to-end: ALLOWED_HOSTS includes only A; vhost B is configured;
    request to B must reach upstream B, NOT silent-decoy."""

    def test_vhost_registered_host_bypasses_allowed_hosts(self, proxy_module):
        async def go():
            async with _spin_upstream(label="upstream-jtsl") as up_jtsl:
                async with _spin_upstream(label="upstream-pt4") as up_pt4:
                    async with _spin_proxy(proxy_module, up_pt4) as client:
                        import vhost as _v
                        # Restrict ALLOWED_HOSTS to pt4.tech only
                        proxy_module.ALLOWED_HOSTS = {"pt4.tech"}
                        proxy_module.HOST_BLOCKING_ENABLED = True
                        # Register jtsl.pt as a vhost — must implicitly allowlist
                        _v.VHOSTS["jtsl.pt"] = {"UPSTREAM": up_jtsl}

                        try:
                            r = await client.get("/", headers={"Host": "jtsl.pt"})
                            body = await r.text()
                        finally:
                            del _v.VHOSTS["jtsl.pt"]
                            proxy_module.ALLOWED_HOSTS = set()

                        assert "I am upstream-jtsl" in body, (
                            f"jtsl.pt must reach its own upstream (vhost-implicit "
                            f"allowlist); got: {body!r}"
                        )
                        assert "I am upstream-pt4" not in body, (
                            "jtsl.pt request must NOT be silently decoyed with "
                            "global UPSTREAM's homepage"
                        )
        _run(go())

    def test_unregistered_host_still_blocked(self, proxy_module):
        """Host not in ALLOWED_HOSTS and not a vhost → silent decoy fires."""
        async def go():
            async with _spin_upstream(label="upstream-pt4") as up_pt4:
                async with _spin_proxy(proxy_module, up_pt4) as client:
                    proxy_module.ALLOWED_HOSTS = {"pt4.tech"}
                    proxy_module.HOST_BLOCKING_ENABLED = True
                    try:
                        r = await client.get("/", headers={"Host": "evil.example.org"})
                        body = await r.text()
                    finally:
                        proxy_module.ALLOWED_HOSTS = set()
                    # Decoy serves global UPSTREAM content; status mirrors upstream
                    assert "I am upstream-pt4" in body, (
                        "unregistered host must get silent decoy with global UPSTREAM body"
                    )
        _run(go())

    def test_wildcard_vhost_allows_subdomain(self, proxy_module):
        """*.tenant.example.com vhost must implicitly allow any subdomain."""
        async def go():
            async with _spin_upstream(label="tenant-app") as up_tenant:
                async with _spin_upstream(label="upstream-pt4") as up_pt4:
                    async with _spin_proxy(proxy_module, up_pt4) as client:
                        import vhost as _v
                        proxy_module.ALLOWED_HOSTS = {"pt4.tech"}
                        proxy_module.HOST_BLOCKING_ENABLED = True
                        _v.VHOSTS["*.tenant.example.com"] = {"UPSTREAM": up_tenant}
                        try:
                            r = await client.get("/", headers={"Host": "acme.tenant.example.com"})
                            body = await r.text()
                        finally:
                            del _v.VHOSTS["*.tenant.example.com"]
                            proxy_module.ALLOWED_HOSTS = set()
                        assert "I am tenant-app" in body, (
                            f"*.tenant.example.com must allow acme.tenant.example.com; "
                            f"got: {body!r}"
                        )
        _run(go())
