"""
1.9.7 — Option B: defer the heavy, dashboard-cosmetic state rehydrate
(db_load_state + _rehydrate_timeline + _rehydrate_events) off the blocking
on_startup path so aiohttp accepts connections in ~3s instead of ~60s on a
large Postgres deployment (which otherwise produced a Cloudflare 502 window on
every upgrade).

Guarantees this test pins:
  1. db_load_state grows a `clear_first` param (default True for tests/
     isolation); merge mode (False) must NOT wipe ip_state and must NOT
     downgrade an already-active in-memory ban.
  2. The production deferred task runs each blocking step in a thread executor
     (run_in_executor) — never inline — so the event loop keeps serving.
  3. The deferred task calls db_load_state with clear_first=False.
  4. _rehydrate_bans() stays SYNCHRONOUS (security): called unconditionally in
     on_startup, not inside the OFFLINE_BG_TASKS gate or the deferred task.
  5. In production the synchronous db_load_state() call site is gated by
     _offline_bg (so prod defers; only tests load it inline).
"""
import inspect
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent


# ── 1. db_load_state(clear_first=...) behaviour ────────────────────────────

def test_db_load_state_has_clear_first_param():
    from db.sqlite import db_load_state
    sig = inspect.signature(db_load_state)
    assert "clear_first" in sig.parameters
    assert sig.parameters["clear_first"].default is True


def test_clear_first_false_preserves_existing_ip_state(proxy_module):
    """Merge mode must not wipe live ip_state (e.g. bans just rehydrated)."""
    import state
    from db.sqlite import db_load_state, db_init
    db_init()                           # ensure schema (clients/events/...) exists
    sentinel = "203.0.113.77"          # TEST-NET-3, not in the clients table
    state.ip_state[sentinel].request_count = 42
    db_load_state(clear_first=False)
    assert sentinel in state.ip_state, "merge mode wiped a live ip_state entry"
    assert state.ip_state[sentinel].request_count == 42


def test_clear_first_true_wipes_ip_state(proxy_module):
    """Default (test) mode clears for cross-test isolation."""
    import state
    from db.sqlite import db_load_state, db_init
    db_init()
    sentinel = "203.0.113.78"
    state.ip_state[sentinel].request_count = 42
    db_load_state()                     # default clear_first=True
    # cleared → defaultdict recreates with a fresh zero-count IpState
    assert state.ip_state[sentinel].request_count == 0


# ── 2-5. structural guarantees (source inspection) ─────────────────────────

def _on_startup_src():
    src = (_ROOT / "proxy.py").read_text()
    m = re.search(r"\nasync def on_startup\(.*?\n(async def |def )", src, re.S)
    assert m, "could not isolate on_startup()"
    return src[m.start():m.end()]


def test_deferred_task_runs_in_executor_not_inline():
    body = _on_startup_src()
    assert "_deferred_state_rehydrate" in body
    # the three blocking steps must go through run_in_executor, never be called
    # inline inside the coroutine (which would block the event loop).
    assert "run_in_executor" in body, \
        "deferred rehydrate must offload blocking DB reads to a thread executor"


def test_deferred_calls_db_load_state_merge_mode():
    body = _on_startup_src()
    assert re.search(r"db_load_state.*clear_first\s*=\s*False", body) or \
        re.search(r"partial\(\s*_dls\s*,\s*clear_first\s*=\s*False", body), \
        "deferred path must call db_load_state(clear_first=False)"


def test_bans_rehydrate_is_synchronous_and_unconditional():
    body = _on_startup_src()
    # _rehydrate_bans() must be called at column 4 (top-level of on_startup),
    # i.e. NOT indented under an `if _offline_bg:` / the deferred coroutine.
    assert re.search(r"^    _rehydrate_bans\(\)", body, re.M), \
        "_rehydrate_bans() must run synchronously at on_startup top level"


def test_prod_defers_db_load_state():
    body = _on_startup_src()
    # the early synchronous db_load_state() call must be gated by _offline_bg
    # so production does NOT load it inline (it defers instead).
    assert re.search(r"if _offline_bg:\s*\n\s*db_load_state\(\)", body), \
        "synchronous db_load_state() must be gated behind `if _offline_bg:`"


def test_offline_bg_resolved_before_first_use():
    body = _on_startup_src()
    def_pos = body.index("_offline_bg =")
    use_pos = body.index("if _offline_bg:")
    assert def_pos < use_pos, "_offline_bg must be defined before first use"
