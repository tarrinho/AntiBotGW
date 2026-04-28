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
os.environ.setdefault("DEBUG",             "1")  # enables /__xff in tests

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
    """A predictable URL-safe admin key for /__metrics-style tests."""
    return "TEST-KEY-DO-NOT-USE"
