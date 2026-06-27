"""1.8.13 — regression: _read_events_pg must coerce psycopg Decimal values
(EXTRACT(EPOCH FROM ts) → Decimal) to float, else every db_read_events consumer
(attack-playbook, honeypots-data, agents, …) 500s with
'Object of type Decimal is not JSON serializable' on the Postgres backend.
"""
import json
import os
from decimal import Decimal

os.environ.setdefault("UPSTREAM", "https://example.com")


class _Cur:
    description = [("ts",), ("ip",), ("method",), ("path",), ("reason",)]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params):
        self._sql = sql

    def fetchall(self):
        # ts as Decimal (what EXTRACT(EPOCH …) returns under psycopg)
        return [(Decimal("1779629480.123456"), "9.9.9.9", "GET",
                 "/.git/config", "honeypot")]


class _Conn:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _Cur()


class _FakePg:
    def connect(self, dsn, **kw):
        return _Conn()


def test_pg_reader_coerces_decimal_to_float_and_is_json_safe():
    import db.postgres as pg_mod
    pg_mod._postgres_load_module = lambda: _FakePg()
    pg_mod.POSTGRES_DSN = "postgres://fake"

    rows = pg_mod._read_events_pg(
        1.0, 2.0,
        columns=["ts", "ip", "method", "path", "reason"],
        reason_in=["honeypot"], order_by="ts DESC", limit=10,
    )
    assert rows, "reader returned no rows"
    ts = rows[0]["ts"]
    assert isinstance(ts, float), f"ts must be float, got {type(ts).__name__}"
    assert not isinstance(ts, Decimal)
    # the whole row must be JSON-serializable (the actual failure mode)
    json.dumps(rows[0])  # raises if any Decimal slipped through


import contextlib


@contextlib.contextmanager
def _force_pg_backend():
    """Route db_read_events to the (faked) Postgres reader, then FULLY restore
    the mutated globals so this test can't pollute later tests (the same
    cross-test isolation class fixed in conftest)."""
    import core.proxy_handler as cph
    import state
    import db.postgres as pg_mod
    saved = (getattr(cph, "DB_BACKEND", "sqlite"),
             getattr(state, "_postgres_available", False),
             pg_mod._postgres_load_module, pg_mod.POSTGRES_DSN)
    cph.DB_BACKEND = "postgres"
    state._postgres_available = True
    pg_mod._postgres_load_module = lambda: _FakePg()
    pg_mod.POSTGRES_DSN = "postgres://fake"
    try:
        yield
    finally:
        cph.DB_BACKEND, state._postgres_available, \
            pg_mod._postgres_load_module, pg_mod.POSTGRES_DSN = saved


def test_attack_playbook_endpoint_json_safe_on_postgres(proxy_module):
    """End-to-end guard: the attack-playbook endpoint must return valid JSON when
    db_read_events is on the Postgres backend (Decimal ts). Reproduces the live
    500 'Object of type Decimal is not JSON serializable' that surfaced as the
    dashboard's HTTP 500 / 'Failed to fetch'."""
    import asyncio
    from aiohttp.test_utils import make_mocked_request
    with _force_pg_backend():
        sid = proxy_module._new_sid()
        proxy_module._SESSION_CACHE[sid] = {
            "username": "admin",
            "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
            "revoked": False}
        proxy_module._SESSION_CACHE_READY = True
        cookie = proxy_module._session_sign("admin", sid=sid)
        req = make_mocked_request(
            "GET", "/antibot-appsec-gateway/secured/attack-playbook?mins=1440",
            headers={"Cookie": proxy_module._SESSION_COOKIE + "=" + cookie})
        resp = asyncio.new_event_loop().run_until_complete(
            proxy_module.attack_playbook_endpoint(req))
    assert resp.status == 200, f"expected 200, got {resp.status}"
    body = json.loads(resp.body)            # raises if the response wasn't valid JSON
    assert "groups" in body and "predicted_probes" in body
    for g in body["groups"]:
        assert isinstance(g["last_ts"], (int, float))
