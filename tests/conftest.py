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

# ── 1. Tmp scratch dir for the keys + DB ───────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="appsecgw-test-")
os.environ.setdefault("UPSTREAM",          "https://example.com")
os.environ.setdefault("ADMIN_KEY",         "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",           os.path.join(_TMP, "antibot.db"))
os.environ.setdefault("ALLOWED_HOSTS",     "")
os.environ.setdefault("ADMIN_ALLOWED_IPS", "")
os.environ.setdefault("DEBUG",             "1")  # enables /antibot-appsec-gateway/secured/xff in tests

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
    except Exception:
        pass
