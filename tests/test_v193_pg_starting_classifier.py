"""
Postgres "still starting / WAL recovery" classifier  (1.9.3)
============================================================

After an unclean DB restart (power loss, OOM-kill, host reboot, `docker
restart`) — or when the gateway races the DB on `docker compose up` — Postgres
is up but still replaying its write-ahead log and rejects clients with SQLSTATE
57P03 ("the database system is not yet accepting connections" / "Consistent
recovery state has not been yet reached"). This is a FREQUENT, self-healing
transient, NOT a fault. `_is_pg_starting()` recognises it so the init loop logs
a calm explanatory line + keeps retrying (and the background probe reconnects)
instead of emitting a scary error and silently treating it like a hard failure.

Coverage
────────
C1  classifier MATCHES every real recovery message + SQLSTATE 57P03
C2  classifier does NOT match auth failures or plain connection-refused
C3  source guards — the calm log + give-up branch use _is_pg_starting
"""
from pathlib import Path

_PROJ = Path(__file__).resolve().parent.parent


# ── C1 / C2: behavioural classifier ──────────────────────────────────────────

class _Err(Exception):
    """Stand-in for a psycopg OperationalError carrying an optional sqlstate."""
    def __init__(self, msg, sqlstate=None):
        super().__init__(msg)
        self.sqlstate = sqlstate


def test_matches_recovery_messages(proxy_module):
    from db.postgres import _is_pg_starting
    starting = [
        "FATAL:  the database system is not yet accepting connections",
        "DETAIL:  Consistent recovery state has not been yet reached.",
        "the database system is starting up",
        "the database system is in recovery mode",
        "cannot connect now",
    ]
    for m in starting:
        assert _is_pg_starting(_Err(m)) is True, f"should classify as starting: {m!r}"
    # SQLSTATE path — message empty, code present
    assert _is_pg_starting(_Err("", sqlstate="57P03")) is True


def test_rejects_non_starting_errors(proxy_module):
    from db.postgres import _is_pg_starting, _is_pg_auth_failure
    not_starting = [
        _Err("password authentication failed for user \"appsec\""),
        _Err("could not connect to server: Connection refused"),
        _Err("role \"appsec\" does not exist"),
        _Err("timeout expired"),
    ]
    for e in not_starting:
        assert _is_pg_starting(e) is False, f"must NOT be 'starting': {e}"
    # And the two classifiers are disjoint on an auth failure
    auth = _Err("password authentication failed for user")
    assert _is_pg_auth_failure(auth) is True
    assert _is_pg_starting(auth) is False


# ── C3: source guards ─────────────────────────────────────────────────────────

def test_init_loop_uses_starting_classifier():
    src = (_PROJ / "db" / "postgres.py").read_text(encoding="utf-8")
    assert "def _is_pg_starting(" in src
    # calm per-attempt log in the retry loop
    assert "_is_pg_starting(e)" in src, \
        "retry loop must branch on _is_pg_starting(e) for the calm log"
    assert "still starting" in src.lower(), \
        "a human-readable 'still starting' message must be present"
    # give-up branch must distinguish recovery from a hard failure
    assert "_is_pg_starting(last_err)" in src, \
        "give-up branch must check _is_pg_starting(last_err) before logging an error"


def test_readme_documents_the_frequent_transient():
    readme = (_PROJ / "README.md").read_text(encoding="utf-8")
    assert "not yet accepting connections" in readme, \
        "README must document the frequent 'DB still starting' log burst"
    assert "57P03" in readme
