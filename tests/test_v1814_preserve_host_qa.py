"""
tests/test_v1814_preserve_host_qa.py — QA for the PRESERVE_HOST knob (1.8.14).

PRESERVE_HOST skips Host / Origin / Referer rewriting when forwarding to upstream.
Default False (opt-in). Per-vhost configurable; hot-reloadable; persisted to DB.

Groups:
  P01 — Registration (HRK, config default, _VHOST_COERCE type)
  P02 — Source-code gate (HTTP + WebSocket paths check vc('PRESERVE_HOST'))
  P03 — Vhost storage (vhost_set accepts + persists the knob)
"""
import os
import pathlib

os.environ.setdefault("UPSTREAM", "http://localhost")

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


def _hot_reload_knobs():
    from core.proxy_handler import _HOT_RELOAD_KNOBS
    return _HOT_RELOAD_KNOBS


def _to_bool_ref():
    from core.proxy_handler import _to_bool
    return _to_bool


# ── P01: Registration ─────────────────────────────────────────────────────────

class TestPreserveHostRegistration:

    def test_p01_in_hot_reload_knobs(self):
        hrk = _hot_reload_knobs()
        assert "PRESERVE_HOST" in hrk, (
            "PRESERVE_HOST missing from _HOT_RELOAD_KNOBS; "
            "Controls dashboard and DB round-trip will not work"
        )

    def test_p01_parser_is_to_bool(self):
        tb = _to_bool_ref()
        parser, _ = _hot_reload_knobs()["PRESERVE_HOST"]
        assert parser is tb, (
            "PRESERVE_HOST must use _to_bool parser so '1'/'true'/'yes' "
            "all enable it via the Controls dashboard or env var"
        )

    def test_p01_default_false_in_config(self):
        import config
        assert config.PRESERVE_HOST is False, (
            "PRESERVE_HOST must default False — the safe default rewrites Host "
            "to upstream's netloc; passing the client Host is opt-in only"
        )

    def test_p01_in_vhost_coerce(self):
        import vhost
        assert "PRESERVE_HOST" in vhost._VHOST_COERCE, (
            "PRESERVE_HOST must be in _VHOST_COERCE so it can be set "
            "per-vhost via the admin API and persisted to vhosts.json"
        )

    def test_p01_vhost_coerce_accepts_string_true(self):
        import vhost
        # _VHOST_COERCE replaces bare bool with _to_bool at module load so
        # "true"/"1" from the policy UI coerce correctly (bare bool("false") == True).
        coerce = vhost._VHOST_COERCE["PRESERVE_HOST"]
        assert coerce("true") is True, "PRESERVE_HOST coerce must accept string 'true'"
        assert coerce("0") is False, "PRESERVE_HOST coerce must accept string '0' → False"
        assert coerce(True) is True, "PRESERVE_HOST coerce must accept native bool True"
        assert coerce(False) is False, "PRESERVE_HOST coerce must accept native bool False"


# ── P02: Source-code gate ─────────────────────────────────────────────────────

class TestPreserveHostGate:

    def test_p02_http_path_checks_vc_preserve_host(self):
        src = _read("core/proxy_handler.py")
        assert "vc('PRESERVE_HOST')" in src, (
            "proxy_handler HTTP forward path must check vc('PRESERVE_HOST') "
            "so the knob is read per-vhost at request time"
        )

    def test_p02_http_path_host_rewrite_gated(self):
        src = _read("core/proxy_handler.py")
        assert "upstream_host and not vc('PRESERVE_HOST')" in src, (
            "Host/Origin/Referer rewrite block must be guarded by "
            "`if upstream_host and not vc('PRESERVE_HOST'):`"
        )

    def test_p02_ws_path_checks_preserve_host(self):
        src = _read("core/proxy_handler.py")
        assert "_preserve_host_ws = vc('PRESERVE_HOST')" in src, (
            "WebSocket forward path must capture vc('PRESERVE_HOST') "
            "before the header loop so origin/referer rewrites are skipped"
        )

    def test_p02_ws_path_host_rewrite_gated(self):
        src = _read("core/proxy_handler.py")
        assert "if not _preserve_host_ws and upstream_host:" in src, (
            "WebSocket path must gate the Host header assignment on "
            "`if not _preserve_host_ws and upstream_host:`"
        )

    def test_p02_ws_origin_rewrite_gated(self):
        src = _read("core/proxy_handler.py")
        assert "if not _preserve_host_ws:" in src, (
            "WebSocket origin/referer rewrite must be inside "
            "`if not _preserve_host_ws:` block"
        )

    def test_p02_x_forwarded_host_always_set(self):
        src = _read("core/proxy_handler.py")
        # X-Forwarded-Host is still always forwarded regardless of PRESERVE_HOST,
        # but 1.9.8 M5 (CWE-644) routes it through _safe_client_host(): a valid Host
        # is reflected, a malformed / allowlist-miss falls back to the upstream
        # netloc. Confirm the (validated) assignment precedes the PRESERVE_HOST gate.
        idx_xfh = src.find('fwd_headers["X-Forwarded-Host"] = _xfh')
        idx_gate = src.find("and not vc('PRESERVE_HOST')")
        assert idx_xfh != -1, "X-Forwarded-Host must be set in the HTTP forward path"
        assert "_safe_client_host(request.host" in src, \
            "X-Forwarded-Host must be validated via _safe_client_host (M5)"
        assert idx_xfh < idx_gate, (
            "X-Forwarded-Host assignment must come BEFORE the PRESERVE_HOST gate "
            "so it is always forwarded regardless of PRESERVE_HOST setting"
        )


# ── P03: Vhost storage ────────────────────────────────────────────────────────

class TestPreserveHostVhostStorage:
    """vhost_set accepts and persists PRESERVE_HOST; vc() reads it back."""

    _HOST = "preserve-host-qa.internal"

    def _vhost(self):
        import vhost as _v
        _v.VHOSTS.pop(self._HOST, None)
        return _v

    def test_p03_vhost_set_accepts_preserve_host_true(self):
        v = self._vhost()
        ok, err = v.vhost_set(self._HOST, {
            "UPSTREAM": "https://example.com",
            "PRESERVE_HOST": True,
        })
        assert ok, f"vhost_set rejected PRESERVE_HOST=True: {err}"
        v.VHOSTS.pop(self._HOST, None)

    def test_p03_vhost_set_accepts_preserve_host_false(self):
        v = self._vhost()
        ok, err = v.vhost_set(self._HOST, {
            "UPSTREAM": "https://example.com",
            "PRESERVE_HOST": False,
        })
        assert ok, f"vhost_set rejected PRESERVE_HOST=False: {err}"
        v.VHOSTS.pop(self._HOST, None)

    def test_p03_vhost_set_persists_preserve_host_true(self):
        v = self._vhost()
        v.vhost_set(self._HOST, {
            "UPSTREAM": "https://example.com",
            "PRESERVE_HOST": True,
        })
        stored = v.VHOSTS.get(self._HOST, {})
        assert stored.get("PRESERVE_HOST") is True, (
            f"PRESERVE_HOST=True not found in VHOSTS after vhost_set; got {stored}"
        )
        v.VHOSTS.pop(self._HOST, None)

    def test_p03_vhost_set_persists_preserve_host_false(self):
        v = self._vhost()
        v.vhost_set(self._HOST, {
            "UPSTREAM": "https://example.com",
            "PRESERVE_HOST": False,
        })
        stored = v.VHOSTS.get(self._HOST, {})
        assert stored.get("PRESERVE_HOST") is False, (
            f"PRESERVE_HOST=False not found in VHOSTS after vhost_set; got {stored}"
        )
        v.VHOSTS.pop(self._HOST, None)

    def test_p03_vc_returns_vhost_override(self):
        import vhost as v
        v.VHOSTS.pop(self._HOST, None)
        v.vhost_set(self._HOST, {
            "UPSTREAM": "https://example.com",
            "PRESERVE_HOST": True,
        })
        v.set_vhost(self._HOST)
        try:
            result = v.vc("PRESERVE_HOST")
            assert result is True, (
                f"vc('PRESERVE_HOST') returned {result!r} for vhost with "
                "PRESERVE_HOST=True; per-vhost override not applied"
            )
        finally:
            v.set_vhost("")
            v.VHOSTS.pop(self._HOST, None)

    def test_p03_vc_falls_back_to_global_default(self):
        import vhost as v
        import config
        v.VHOSTS.pop(self._HOST, None)
        v.vhost_set(self._HOST, {"UPSTREAM": "https://example.com"})
        v.set_vhost(self._HOST)
        try:
            result = v.vc("PRESERVE_HOST")
            assert result == config.PRESERVE_HOST, (
                f"vc('PRESERVE_HOST') returned {result!r} but expected "
                f"global default {config.PRESERVE_HOST!r} when vhost has no override"
            )
        finally:
            v.set_vhost("")
            v.VHOSTS.pop(self._HOST, None)
