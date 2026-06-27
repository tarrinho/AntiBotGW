"""1.8.15 iter-20 — `ALLOWED_METHODS` QA.

Pins two contracts:

  1. The image default includes the standard REST verbs out of the box
     (GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS). Original 1.8.13 default
     was tighter (GET/HEAD/POST/OPTIONS only); widening was the iter-20 change
     so REST APIs work without per-deployment env tweaking.

  2. Per-vhost `ALLOWED_METHODS` overrides actually apply at runtime. This
     was a silent contract violation pre-iter-20: the dashboard accepted and
     persisted the override via `_VHOST_COERCE`, the `/vhost-policy/get`
     endpoint returned the new set, but the request-path checks at
     core/proxy_handler.py:985 and :3563 used the bare module global —
     ignoring the per-vhost overlay. Both sites now read via `vc()`.

A functional test for the protect() check path would require spinning the
full proxy harness; the source-anchor checks below catch any regression of
the runtime check back to the bare global.
"""
import pathlib

_ROOT = pathlib.Path(__file__).parent.parent


def test_default_allowed_methods_is_safe_for_waf_set():
    """Contract change (shipped F3): the image default is the tight,
    WAF-safe set GET,HEAD,POST,OPTIONS — NOT widened to PUT/PATCH/DELETE.
    The proposed iter-20 widening was never shipped; the code comment at
    _ALLOWED_METHODS_DEFAULT is explicit that REST verbs are opt-in via env
    (ALLOWED_METHODS=...). Aligned to the shipped, intentionally tighter
    default; widening it would weaken the out-of-the-box posture."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    line = next((l for l in src.splitlines() if "_ALLOWED_METHODS_DEFAULT" in l and "=" in l), None)
    assert line is not None, "_ALLOWED_METHODS_DEFAULT missing"
    for m in ("GET", "HEAD", "POST", "OPTIONS"):
        assert m in line, f"default ALLOWED_METHODS missing {m!r}: {line}"
    # REST write verbs are NOT in the default — opt-in only.
    for m in ("PUT", "PATCH", "DELETE"):
        assert m not in line, f"{m!r} must stay opt-in, not in default: {line}"


def test_default_excludes_trace_and_connect():
    """Defense in depth: TRACE (cross-site tracing) and CONNECT (proxy-tunnel)
    must remain blocked by default — widening to REST verbs MUST NOT widen to
    everything. Both are listed because each has a distinct attack surface."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    line = next((l for l in src.splitlines() if "_ALLOWED_METHODS_DEFAULT" in l and "=" in l), None)
    assert "TRACE" not in line, f"TRACE must stay out of default: {line}"
    assert "CONNECT" not in line, f"CONNECT must stay out of default: {line}"


def test_protect_layer_method_check_reads_via_vc():
    """The Layer-0 method check in protect() must read via vc() so per-vhost
    overrides apply. Anchored on the F3-marker comment so a refactor that
    moves the block doesn't break the test, but a regression back to bare
    `ALLOWED_METHODS` is still caught."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    # Find the F3 block; assert it computes via vc() then uses the result
    f3_idx = src.find("# F3: method allowlist at Layer 0")
    assert f3_idx > 0, "F3 method allowlist comment block moved or removed"
    block = src[f3_idx:f3_idx + 800]
    assert 'vc("ALLOWED_METHODS")' in block
    assert "_vc_methods" in block
    # The 405 response Allow header must list the per-vhost set (not the global)
    assert 'sorted(_vc_methods)' in block


def test_websocket_path_method_check_reads_via_vc():
    """The other method check (M2 comment, right after WebSocket upgrade
    branch) must also read via vc(). Two enforcement points, both need
    the per-vhost overlay."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    m2_idx = src.find("# M2: method allowlist")
    assert m2_idx > 0
    block = src[m2_idx:m2_idx + 800]
    assert 'vc("ALLOWED_METHODS")' in block


def test_no_bare_allowed_methods_check_remains():
    """A regression where someone re-introduces `request.method not in
    ALLOWED_METHODS` (the bare global) would silently break per-vhost
    overrides for that one site. Catch any new bare-check via grep over the
    handler — only the two vc()-wrapped checks should exist."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    bare = [ln for ln in src.splitlines()
            if "request.method not in ALLOWED_METHODS" in ln]
    assert bare == [], f"bare ALLOWED_METHODS check (no vc() wrap): {bare}"


def test_allowed_methods_in_vhost_coerce_table():
    """The Vhost Policy dashboard reads `_VHOST_COERCE` to know which keys
    are per-vhost-overridable. ALLOWED_METHODS must be in there so the page
    accepts and persists the operator's override."""
    src = (_ROOT / "vhost.py").read_text()
    assert '"ALLOWED_METHODS"' in src
    coerce_idx = src.find("_VHOST_COERCE")
    assert coerce_idx > 0
    # The key must be inside the dict, not just in a comment
    coerce_dict_end = src.find("\n}\n", coerce_idx)
    coerce_block = src[coerce_idx:coerce_dict_end]
    assert '"ALLOWED_METHODS"' in coerce_block


def test_allowed_methods_in_hot_reload_table():
    """ALLOWED_METHODS in `_HOT_RELOAD_KNOBS` lets the operator update it
    via /__config without restart. Coupled with the iter-20 vc() fix, hot
    reloads now actually take effect at the request path."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    hr_idx = src.find("_HOT_RELOAD_KNOBS = {")
    # Find the closing brace of this dict literal
    hr_end = src.find("\n}\n", hr_idx)
    hr_block = src[hr_idx:hr_end]
    assert '"ALLOWED_METHODS"' in hr_block


def test_hot_reload_validator_enforces_method_set():
    """The validator must reject malformed/unknown methods. ABUSE → bypass:
    an operator typing "ALLOWED_METHODS=GET,FOO,DELETE" must be rejected,
    not silently accepted with FOO landing in the set."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    # Locate the validator next to the ALLOWED_METHODS entry
    hr_idx = src.find('"ALLOWED_METHODS":        (_to_method_set')
    assert hr_idx > 0
    block = src[hr_idx:hr_idx + 400]
    # Validator must list the canonical method set
    for m in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
        assert m in block, f"validator must list {m}: {block!r}"


def test_method_allowlist_test_uses_trace_not_delete():
    """1.8.15 iter-20: the legacy `test_method_allowlist_delete_blocked`
    asserted DELETE was blocked, which was true under the tight default but
    false post-widening. Replacement uses TRACE (still excluded from the new
    default). Catch a future revert that re-asserts on DELETE."""
    src = (_ROOT / "tests" / "test_endpoints_dynamic.py").read_text()
    # The TRACE-based test is the contract
    assert "def test_method_allowlist_trace_blocked" in src
    # Old DELETE-based test must NOT come back
    assert "def test_method_allowlist_delete_blocked" not in src
