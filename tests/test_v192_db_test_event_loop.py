"""1.9.2 iter-25 — db_test_endpoint event-loop blocking guard.

Operator-reported bug (from the Switch DB Backend modal on pt4.tech):
clicking "Test" with a candidate DSN hung the entire gateway for 77 s and
returned 502/504 on every concurrent admin request (`/secured/config`,
`/secured/2fa-status`). Root cause: `pg_test_roundtrip()` does synchronous
socket I/O (DNS, TCP, libpq auth handshake). Calling it on the event loop
froze every other coroutine until the call returned.

iter-22 had already fixed the no-arg path (lines 4865-4880 — the diagnostic
view called from the Controls "External integrations" card) by wrapping
`pg_test_roundtrip` in `loop.run_in_executor` + `asyncio.wait_for(8s)`. But
the **probe-DSN path** (line ~4815, used when the operator clicks "Test" in
the switch modal) was missed — it kept calling the function directly.

This QA pins BOTH callsites to the executor+timeout pattern so a future
refactor cannot revert either branch to the blocking form.
"""
import pathlib

_ROOT = pathlib.Path(__file__).parent.parent


def _slice(src: str, sig: str, max_chars: int = 5000) -> str:
    idx = src.find(sig)
    assert idx >= 0, f"{sig!r} not found"
    return src[idx:idx + max_chars]


def test_no_arg_path_uses_executor_with_timeout():
    """iter-22 fix — the diagnostic view path must use run_in_executor +
    wait_for. Anchor on the comment marker so a refactor that touches the
    function but keeps the comment still triggers a re-check."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def db_test_endpoint")
    # The no-arg path runs AFTER the probe_dsn block
    no_arg_idx = body.find("sqlite_info = {\"ok\": False}")
    assert no_arg_idx > 0, "no-arg path marker missing"
    no_arg_block = body[no_arg_idx:no_arg_idx + 1500]
    assert "run_in_executor" in no_arg_block
    assert "pg_test_roundtrip" in no_arg_block
    assert "asyncio.wait_for" in no_arg_block


def test_probe_dsn_path_uses_executor_with_timeout():
    """iter-25 fix — the modal's `?dsn=...` probe path must ALSO use
    run_in_executor + wait_for. Catches the exact regression we're patching:
    `probe = pg_test_roundtrip()` directly on the event loop."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def db_test_endpoint")
    probe_idx = body.find("if probe_dsn:")
    end_probe = body.find("sqlite_info = {\"ok\": False}", probe_idx)
    assert probe_idx > 0 and end_probe > probe_idx, "probe_dsn block missing"
    probe_block = body[probe_idx:end_probe]
    # Forbidden — the bare sync call that blocked the event loop
    assert "probe = pg_test_roundtrip()" not in probe_block, \
        "probe-DSN path must not call pg_test_roundtrip() on the event loop"
    # Required — the offload pattern
    assert "run_in_executor" in probe_block, \
        "probe-DSN path must use loop.run_in_executor"
    assert "asyncio.wait_for" in probe_block, \
        "probe-DSN path must wrap the executor with asyncio.wait_for"
    assert "pg_test_roundtrip" in probe_block, \
        "probe-DSN path still needs to invoke pg_test_roundtrip"


def test_probe_dsn_path_timeout_is_bounded_under_cloudflare_edge():
    """The probe timeout must be < Cloudflare's 100 s edge timeout so the
    UI spinner doesn't outlive the connection — otherwise the operator sees
    the 524 timeout page instead of our actionable error message."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def db_test_endpoint")
    probe_idx = body.find("if probe_dsn:")
    end_probe = body.find("sqlite_info = {\"ok\": False}", probe_idx)
    probe_block = body[probe_idx:end_probe]
    # Find a timeout=<num> within the probe block
    import re
    m = re.search(r"timeout\s*=\s*(\d+(?:\.\d+)?)\s*\)", probe_block)
    assert m is not None, "probe-DSN path must set a numeric timeout"
    secs = float(m.group(1))
    assert 5 <= secs <= 60, \
        f"probe timeout {secs}s outside the safe band (5..60s, " \
        f"Cloudflare cap 100s, healthy DSN handshake <2s)"


def test_probe_dsn_globals_restored_in_finally_block():
    """The probe path mutates POSTGRES_DSN / DB_BACKEND globals while
    running the probe. Those mutations MUST be reverted via a finally block
    so a failed/timed-out probe doesn't leak the candidate DSN into the
    live backend state — that would silently switch the active backend to
    a non-functional DSN."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def db_test_endpoint")
    probe_idx = body.find("if probe_dsn:")
    end_probe = body.find("sqlite_info = {\"ok\": False}", probe_idx)
    probe_block = body[probe_idx:end_probe]
    assert "finally:" in probe_block
    # All three globals/module attrs restored
    assert "globals()[\"POSTGRES_DSN\"] = saved_dsn" in probe_block
    assert "globals()[\"DB_BACKEND\"]   = saved_backend" in probe_block \
        or "globals()[\"DB_BACKEND\"] = saved_backend" in probe_block
    assert "_pg_for_probe.POSTGRES_DSN = saved_pg_dsn" in probe_block
