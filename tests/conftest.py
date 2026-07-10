"""
Shared pytest fixtures.

`proxy` does work at import time (validates UPSTREAM, generates / reads HMAC
keys, etc.), so we set env vars BEFORE importing it. We also redirect the
key files into a tmp dir so test runs don't pollute the project tree.
"""
import os
import sys
import tempfile
from pathlib import Path

# When running under `mutmut run` (python -m mutmut), mutmut/__main__.py is
# sys.modules['__main__'], NOT 'mutmut.__main__'. Trampoline functions do
# `from mutmut.__main__ import record_trampoline_hit`, which re-imports the
# module fresh and hits `set_start_method('fork')` a second time →
# RuntimeError: context has already been set.
# Fix: alias __main__ as mutmut.__main__ before pytest discovers the trampolines.
def _alias_mutmut_main() -> None:
    main = sys.modules.get("__main__")
    if main is not None and "mutmut.__main__" not in sys.modules:
        if hasattr(main, "record_trampoline_hit"):
            sys.modules["mutmut.__main__"] = main
_alias_mutmut_main()

# ── 1. Tmp scratch dir for the keys + DB ───────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="appsecgw-test-")
os.environ.setdefault("UPSTREAM",          "https://example.com")
os.environ.setdefault("ADMIN_KEY",         "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",           os.path.join(_TMP, "antibot.db"))
os.environ.setdefault("ALLOWED_HOSTS",     "")
# 1.8.13 — admin-IP gate is now fail-closed (F-06): an empty allowlist denies
# ALL admin endpoints. Tests forge sessions + hit /secured/* from 127.0.0.1, so
# the test allowlist must permit the loopback client (was "" = open before F-06).
os.environ.setdefault("ADMIN_ALLOWED_IPS", "0.0.0.0/0,::/0")
os.environ.setdefault("DEBUG",             "1")  # enables /antibot-appsec-gateway/secured/xff in tests
# iter-18 follow-up: skip every periodic refresh loop that issues outbound
# HTTPS (MaxMind / Tor / CrowdSec / feeds / mesh / redis-flush / JA4 / AI
# crawler). Without this, the suite leaks ~1000 threads + 2500 FDs +
# hundreds of CLOSE-WAIT sockets to Cloudflare anycast IPs by ~70% of the
# run, slowing each subsequent test geometrically (GIL contention).
os.environ.setdefault("OFFLINE_BG_TASKS",  "1")
# 1.9.6 — disable the /__metrics response cache in tests so rapid same-query
# requests see fresh data (production default is 1s). The dedicated cache test
# turns it on explicitly.
os.environ.setdefault("METRICS_RESP_TTL",  "0")

# Make `import proxy` find the file regardless of where pytest is run from.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))

# proxy.py creates files at <dirname(__file__)>/.{admin,session,pow}_key.
# Point that directory at our scratch dir by symlinking proxy.py into it.
_PROXY_SRC = _HERE.parent / "proxy.py"
_PROXY_LINK = Path(_TMP) / "proxy.py"
if not _PROXY_LINK.exists():
    _PROXY_LINK.symlink_to(_PROXY_SRC)
sys.path.insert(0, _TMP)

import pytest


@pytest.fixture(scope="session")
def proxy_module():
    """Import proxy.py once per test session, with env pre-set."""
    import proxy as p
    return p


@pytest.fixture
def url_safe_key():
    """A predictable URL-safe admin key for /antibot-appsec-gateway/secured/metrics-style tests."""
    return "TEST-KEY-DO-NOT-USE"


@pytest.fixture(autouse=True)
def _wipe_config_kv_between_tests():
    """1.5.5 — config_kv now persists hot-reload knob mutations across
    container restart.  In a test session, that means a /antibot-appsec-gateway/secured/config POST in
    one test bleeds into the next.  This autouse fixture clears the table
    after every test so the next one starts clean.

    Also resets in-memory knobs that are safety-critical and must default
    to specific values (e.g. INJECT_SECURITY_HEADERS=True, BYPASS_MODE=False)
    so a test that toggles them can't contaminate subsequent tests even
    when the per-test restore logic has a gap."""
    yield
    import sqlite3
    # Use the proxy module's DB_PATH, not os.environ — test_functional.py
    # overrides os.environ["DB_PATH"] at import time (to its own tmp path),
    # but the proxy module reuses the already-imported config module and thus
    # uses a different DB path.  Using os.environ here would wipe the wrong DB,
    # letting the actual proxy DB accumulate config_kv rows across tests.
    db_path = ""
    try:
        import proxy as _pw
        db_path = getattr(_pw, "DB_PATH", "") or ""
    except Exception:
        pass
    if not db_path:
        db_path = os.environ.get("DB_PATH", "")
    if db_path and os.path.exists(db_path):
        try:
            conn = sqlite3.connect(db_path)
            conn.execute("DELETE FROM config_kv")
            # Wipe clients + timeline so db_load_state() in the next test's
            # on_startup does not repopulate ip_state with stale entries from
            # prior tests — which would cause risk_score / blocked-count assertions
            # to fail when those entries are mixed with the fresh test identity.
            conn.execute("DELETE FROM clients")
            conn.execute("DELETE FROM timeline")
            # Wipe events so agents-bucket / path-hits queries in the next test
            # don't see seeded rows from prior tests (events table is not
            # cleared by db_load_state, so cross-test contamination accumulates).
            conn.execute("DELETE FROM events")
            # 1.8.6 — wipe bans so _rehydrate_bans() on the next gateway
            # startup does not import bans written by prior tests.
            try:
                conn.execute("DELETE FROM bans")
            except sqlite3.OperationalError:
                pass
            # 1.8.13 — wipe ip_bans too. check_ip_ban() reads this table
            # synchronously on every request; a honeypot/suspicious hit in one
            # test writes an ip_bans row that then makes EVERY later test's
            # request from 127.0.0.1 return 'ip-ban' (it was the only ban table
            # not cleared here, causing in-file detection-test cross-contamination).
            try:
                conn.execute("DELETE FROM ip_bans")
            except sqlite3.OperationalError:
                pass
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            pass
    # In-memory reset of knobs that guard test correctness. These must always
    # be their safe default between tests; _ProxyModule.__setattr__ propagates
    # each assignment to all loaded submodules (core.proxy_handler etc.).
    try:
        import proxy as _p
        _p.INJECT_SECURITY_HEADERS = True   # security headers test would fail if False
        _p.BYPASS_MODE = False              # must be False or detection tests are skipped
        # RISK_BAN_THRESHOLD: config-endpoint integration tests set this to
        # non-default values (60, 75, …) and the propagation to sys.modules
        # survives proxy teardown, causing test_accumulated_risk_triggers_ban
        # to use the wrong threshold for its ceiling calculation.
        import config as _cfg
        _default_rbt = 50  # config.py default
        if getattr(_cfg, "RISK_BAN_THRESHOLD", _default_rbt) != _default_rbt:
            for _rm in list(sys.modules.values()):
                if _rm is not None and hasattr(_rm, "RISK_BAN_THRESHOLD"):
                    try:
                        setattr(_rm, "RISK_BAN_THRESHOLD", _default_rbt)
                    except (AttributeError, TypeError):
                        pass
    except Exception:
        pass
    # Clear VHOSTS after every test. VHOSTS is a module-level dict in vhost.py
    # (shared singleton across all proxy imports in the session). A test that
    # registers a vhost would otherwise make VHOSTS non-empty for subsequent
    # tests, causing STRICT_VHOST=1 (now the default) to reject all unregistered
    # inbound hosts in those tests with 502.
    try:
        import vhost as _vh
        _vh.VHOSTS.clear()
    except Exception:
        pass
    # 1.8.9 kill-switch knobs — tests that disable detection signals (e.g.
    # WAF_BODY_ENABLED, LLM_HEURISTIC_ENABLED) may not restore them, causing
    # test_r02_all_new_knobs_default_true to see False after a combined run.
    _KNOBS_189_DEFAULT_TRUE = [
        "WAF_BODY_ENABLED", "WAF_SMUGGLING_ENABLED", "WAF_VERB_OVERRIDE_ENABLED",
        "WAF_HEADER_INJECTION_ENABLED", "WAF_GRAPHQL_ENABLED", "WAF_UPLOAD_ENABLED",
        "WAF_SLOWLORIS_ENABLED", "ACCEPT_WILDCARD_CHECK_ENABLED",
        "SESSION_CHURN_ENABLED", "JA4H_DENY_ENABLED", "HOST_BLOCKING_ENABLED",
        "REQUIRED_HEADERS_ENABLED", "JA4_REQUIRED_ENABLED",
        "UPSTREAM_AUTH_FAIL_ENABLED", "RATE_LIMIT_IP_ENABLED",
        "RATE_LIMIT_ENABLED", "FP_BAN_CHECK_ENABLED",
        "TRAFFIC_THRESHOLD_ENABLED", "TLS_FP_BLOCK_ENABLED",
        "JWT_VALIDATION_ENABLED", "CUSTOM_RULES_ENABLED",
        "ENDPOINT_RATE_LIMIT_ENABLED", "HONEY_CRED_ENABLED",
        "CANARY_PROBE_ENABLED", "LLM_HEURISTIC_ENABLED",
        "AUTOMATION_PROBE_ENABLED", "INTERACTION_PROBE_ENABLED",
        "COORDINATED_ATTACK_ENABLED", "JOURNEY_CHECK_ENABLED",
    ]
    try:
        for _rm in list(sys.modules.values()):
            if _rm is None:
                continue
            for _kn in _KNOBS_189_DEFAULT_TRUE:
                if hasattr(_rm, _kn) and getattr(_rm, _kn) is not True:
                    try:
                        setattr(_rm, _kn, True)
                    except (AttributeError, TypeError):
                        pass
    except Exception:
        pass
    # Clear in-memory events_by_cat ring buffers so vhost-filtered timeline
    # tests (TestU1MetricsVhostFilter) don't see events from prior tests.
    try:
        from state import events_by_cat
        for _dq in events_by_cat.values():
            _dq.clear()
    except Exception:
        pass
    # 1.8.13 — reset the admin session cache between tests. Tests that forge an
    # admin session set _SESSION_CACHE_READY=True; left set, it changes how the
    # NEXT test's UNAUTHENTICATED admin requests are gated (made test_v1811
    # api08/api09 ui-theme tests fail, but only when co-run after test_v1810 —
    # a pure cross-file ordering flake, not a product defect). Clearing the cache
    # + resetting the ready flag isolates every test from forged-session bleed.
    try:
        import proxy as _ps
        _ps._SESSION_CACHE.clear()          # same dict object across modules
        _ps._SESSION_CACHE_READY = False     # _ProxyModule.__setattr__ propagates
    except Exception:
        pass
    try:
        import admin.users as _au            # also reset the canonical home
        _au._SESSION_CACHE.clear()
        _au._SESSION_CACHE_READY = False
    except Exception:
        pass
    # 1.8.13 — reset the upstream-404 decoy cache between tests. Tests that spin a
    # local echo upstream (returns 200 for every path) prime this cache with
    # status=200; it then persists module-globally and makes the admin decoy in a
    # LATER test return 200 instead of 404 — which broke test_v1811 api08/api09
    # (unauthenticated admin requests are served the mirrored 404, so its status
    # leaks the prior test's upstream). Restore the import-time defaults.
    try:
        import core.proxy_handler as _cph
        _cph._upstream_404_cache.clear()
        _cph._upstream_404_cache.update(
            {"body": None, "ctype": "text/plain; charset=utf-8",
             "status": 404, "fetched_at": 0.0})
    except Exception:
        pass

    # ── 1.8.14 iter-18: narrow cross-file pollution reset ──────────────────
    # ONLY safe resets that target the 7 known cross-file flakes without
    # touching identity state, TOTP flow, or detection knobs (those broke
    # tests that depended on intra-test state surviving).

    # Postgres pool — `test_sw07_clears_pool` sets `_state._postgres_pool`
    # to a sentinel, calls reset, expects None; if a PRIOR test left the
    # pool set to a real `_PgPool` object, the sentinel assignment + reset
    # interact in subtle ways. Force-None between tests so each starts clean.
    try:
        import state as _state_pg
        _state_pg._postgres_pool = None
    except Exception:
        pass

    # Decoy cache (homepage mirror) — vhost-isolation tests need the cache
    # cleared so the silent-decoy path doesn't serve the prior vhost's `/`.
    # Per-vhost dict (1.8.15 refactor): clearing it = empty for next test.
    try:
        import core.proxy_handler as _cph2
        if hasattr(_cph2, "_decoy_cache"):
            _cph2._decoy_cache.clear()
    except Exception:
        pass

    # Per-vhost RPS windows — vhost-stats tests reset VHOSTS but the
    # per-vhost deque survives in `_vhost_rps_windows`, causing rate-counter
    # assertions to see prior-test counts.
    try:
        from vhost import _vhost_rps_windows as _vrw
        _vrw.clear()
    except Exception:
        pass

    # POW + probe rate-limit dicts — populated by the hot path, never reset
    # between tests. Safe to clear (they're per-IP rolling counters).
    try:
        import core.proxy_handler as _cph3
        for _dn in ("_PROBE_RL", "_POW_RL", "_POW_CHAL_CACHE"):
            _d = getattr(_cph3, _dn, None)
            if _d is not None: _d.clear()
    except Exception:
        pass


# ── 1.8.11: CSRF auto-attach for the in-process test HTTP client ─────────────
# The central CSRF gate (core.proxy_handler.protect) now requires a valid
# X-CSRF-Token header on EVERY state-changing request to the admin namespace —
# exactly as the live dashboard's fetch() shim attaches it from window.__AGW_CSRF__.
# To keep the aiohttp TestClient faithful to a real browser, this autouse fixture
# wraps TestClient.request: for a non-safe method carrying an `agw_session`
# cookie, it derives the matching token (HMAC(SESSION_KEY, sid)[:32]) and adds
# the header *only when the test didn't set one*. Tests that set X-CSRF-Token
# explicitly (including deliberately-wrong values, e.g. CSRF-rejection tests)
# are left untouched, so negative-path coverage still works.
@pytest.fixture(autouse=True)
def _auto_attach_csrf_header():
    import hashlib as _hl, hmac as _hm
    try:
        from aiohttp.test_utils import TestClient
    except Exception:
        yield
        return
    # NOTE: TestClient.post/get/delete dispatch through TestClient._request
    # (the underscore coroutine), not the public request(), so we patch that.
    _orig_request = TestClient._request

    async def _request_with_csrf(self, method, path, *args, **kwargs):
        try:
            if str(method).upper() not in ("GET", "HEAD", "OPTIONS", "TRACE"):
                cookies = kwargs.get("cookies") or {}
                sess = cookies.get("agw_session", "") if isinstance(cookies, dict) else ""
                if isinstance(sess, str) and sess.count("|") >= 3:
                    hdrs = dict(kwargs.get("headers") or {})
                    if not any(k.lower() == "x-csrf-token" for k in hdrs):
                        import config as _cfg
                        sid = sess.split("|")[1]
                        hdrs["X-CSRF-Token"] = _hm.new(
                            _cfg.SESSION_KEY, sid.encode(), _hl.sha256
                        ).hexdigest()[:32]
                        kwargs["headers"] = hdrs
        except Exception:
            pass  # never let the shim break a request
        return await _orig_request(self, method, path, *args, **kwargs)

    TestClient._request = _request_with_csrf
    try:
        yield
    finally:
        TestClient._request = _orig_request
