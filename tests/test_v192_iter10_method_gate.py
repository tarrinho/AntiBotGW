"""
1.9.1 iter-10 — method allowlist hoisted ahead of the JS-challenge gate.

DAST §15g surfaced: with JS_CHALLENGE on (production / example.com default),
a cookieless TRACE/CONNECT hit the JS-challenge gate in `protect()` and
got a 200 challenge page BEFORE the method-allowlist check in `proxy()`
(the catch-all handler) could return 405. So dangerous verbs bypassed
the allowlist whenever the challenge gate was active.

Note: no XST exposure (the challenge page does not echo the request),
but it's a protocol-hygiene defect and DAST-flagged.

Fix: hoist the upstream-traffic method-allowlist reject into `protect()`,
right after the control-byte check and BEFORE the challenge gate. Admin
paths are exempt — they are separate registered routes (add_delete /
add_post for bans, vhosts, …) whose DELETE/PUT verbs are intentionally
absent from ALLOWED_METHODS (default GET,HEAD,POST,OPTIONS).
"""
import pathlib


_ROOT   = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")


def test_iter10_method_gate_in_protect():
    """protect() must contain the method-allowlist reject, exempting
    admin paths, and it must appear BEFORE the JS-challenge gate."""
    p_idx = _PH_SRC.find("async def protect")
    assert p_idx > 0, "protect() not found"
    nxt = _PH_SRC.find("\nasync def ", p_idx + 1)
    body = _PH_SRC[p_idx:nxt if nxt > 0 else len(_PH_SRC)]

    gate = body.find("not _is_admin_path(request.path) and request.method not in ALLOWED_METHODS")
    assert gate > 0, (
        "protect() must reject non-admin requests whose method is not in "
        "ALLOWED_METHODS (hoisted method allowlist)"
    )
    # Must return 405 with an Allow header.
    seg = body[gate:gate + 400]
    assert "status=405" in seg, "method reject must be HTTP 405"
    assert '"Allow"' in seg, "405 response must carry an Allow header"


def test_iter10_method_gate_precedes_challenge():
    """The method reject must run BEFORE the JS-challenge gate so a
    cookieless TRACE can't be answered with a 200 challenge page."""
    p_idx = _PH_SRC.find("async def protect")
    nxt = _PH_SRC.find("\nasync def ", p_idx + 1)
    body = _PH_SRC[p_idx:nxt if nxt > 0 else len(_PH_SRC)]

    method_gate = body.find("request.method not in ALLOWED_METHODS")
    # The JS-challenge gate marker in protect's flow.
    chal_gate = body.find("_js_challenge_required(request)")
    assert method_gate > 0, "method gate missing in protect()"
    assert chal_gate > 0, "JS-challenge gate marker missing in protect()"
    assert method_gate < chal_gate, (
        "method allowlist reject must precede the JS-challenge gate — "
        "otherwise a cookieless TRACE gets a 200 challenge page instead "
        "of 405 (the DAST §15g finding)"
    )


def test_iter10_admin_paths_exempt_from_method_gate():
    """The hoisted gate must exempt admin paths via _is_admin_path so
    admin DELETE/PUT routes (bans, vhosts) keep working — their verbs
    are intentionally not in ALLOWED_METHODS."""
    p_idx = _PH_SRC.find("async def protect")
    nxt = _PH_SRC.find("\nasync def ", p_idx + 1)
    body = _PH_SRC[p_idx:nxt if nxt > 0 else len(_PH_SRC)]
    assert "not _is_admin_path(request.path) and request.method not in ALLOWED_METHODS" in body, (
        "method gate must exempt admin paths (separate routes with own "
        "method routing) or admin DELETE/PUT endpoints break"
    )


def test_iter10_default_allowed_methods_excludes_dangerous_verbs():
    """ALLOWED_METHODS default must exclude TRACE/CONNECT/PUT/PATCH/
    DELETE so upstream traffic with those verbs is 405'd."""
    import os
    os.environ.setdefault("UPSTREAM", "https://x.test")
    import core.proxy_handler as ph
    for m in ("TRACE", "CONNECT", "PUT", "PATCH", "DELETE"):
        assert m not in ph.ALLOWED_METHODS, (
            f"{m} must NOT be in default ALLOWED_METHODS"
        )
    for m in ("GET", "HEAD", "POST", "OPTIONS"):
        assert m in ph.ALLOWED_METHODS, (
            f"{m} must be in default ALLOWED_METHODS"
        )
