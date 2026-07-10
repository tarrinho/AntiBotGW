"""Shared helpers for the db.export / db.import CLI scripts.

L8 fix — _mask_dsn was duplicated in both modules (~10 lines each, drift
risk on every future tweak). One implementation, two callers.
"""

from urllib.parse import urlparse


def mask_dsn(dsn: str) -> str:
    """Render a DSN as a safe-to-log string. Strips the password component;
    preserves scheme://user:****@host:port/dbname so operators can still
    verify they're pointing at the right target without leaking creds into
    CI pipelines / aggregated logs."""
    try:
        p = urlparse(dsn)
        user = p.username or "<user>"
        host = p.hostname or "<host>"
        port = f":{p.port}" if p.port else ""
        path = p.path or ""
        return f"{p.scheme}://{user}:****@{host}{port}{path}"
    except Exception:
        return "(redacted)"
