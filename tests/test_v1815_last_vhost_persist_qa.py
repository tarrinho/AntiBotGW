"""1.8.14 iter-21 — `last_vhost` persistence for the Clients Domain column.

Bug: Domain column in main.html Clients table showed "—" for every row
after a GW restart, until each client made a fresh request. Root cause:
`IpState.last_vhost` (added in iter-15 for the Domain column) was never
persisted — schema didn't have the column, upsert_client didn't write it,
load path didn't restore it.

This QA pins the 5-point persistence wiring (schema + migration + upsert
tuple + payload + load path) so a future refactor cannot silently regress
the Domain column back to "—".
"""
import pathlib

_ROOT = pathlib.Path(__file__).parent.parent


def test_clients_table_has_last_vhost_column_in_base_schema():
    """Fresh installs must get the column from CREATE TABLE — not just
    migration-restore — so a fresh /data sqlite has it immediately."""
    src = (_ROOT / "db" / "sqlite.py").read_text()
    create_idx = src.find("CREATE TABLE IF NOT EXISTS clients")
    create_end = src.find(");", create_idx)
    create_block = src[create_idx:create_end]
    assert "last_vhost" in create_block
    assert "TEXT DEFAULT ''" in create_block


def test_clients_last_vhost_has_migration_entry():
    """Existing /data sqlite dbs upgraded in place must get the column
    via _SCHEMA_MIGRATIONS — ALTER TABLE ADD COLUMN. Postgres parity is
    N/A (clients table is SQLite-only, like timeline)."""
    src = (_ROOT / "db" / "sqlite.py").read_text()
    assert '("clients",       "last_vhost",    "TEXT DEFAULT \'\'",               None),' in src \
        or '"last_vhost"' in src.split('_SCHEMA_MIGRATIONS')[1]


def test_upsert_client_tuple_includes_last_vhost():
    """The producer (core/metrics.py) must pass last_vhost in the upsert
    tuple, in the position the consumer (db/sqlite.py) expects."""
    metrics_src = (_ROOT / "core" / "metrics.py").read_text()
    sqlite_src = (_ROOT / "db" / "sqlite.py").read_text()
    # Producer tuple
    assert 'p["last_vhost"]' in metrics_src
    # Consumer SQL columns include last_vhost
    upsert_idx = sqlite_src.find('"upsert_client"')
    upsert_block = sqlite_src[upsert_idx:upsert_idx + 1200]
    assert "last_vhost" in upsert_block
    # SET clause for ON CONFLICT
    assert "last_vhost=excluded.last_vhost" in upsert_block


def test_persist_payload_includes_last_vhost():
    """The snapshot dict built inside the state-lock must capture
    s.last_vhost before json.dumps/db_queue.put_nowait happen outside
    the lock (otherwise concurrent requests could race on the field)."""
    src = (_ROOT / "core" / "metrics.py").read_text()
    assert '"last_vhost":         s.last_vhost' in src \
        or '"last_vhost": s.last_vhost' in src


def test_load_state_restores_last_vhost():
    """On GW restart, _load_state_from_sqlite must restore s.last_vhost
    from the clients row. Defensive .keys() lookup so rolling upgrades
    from a pre-iter-21 db don't KeyError."""
    src = (_ROOT / "db" / "sqlite.py").read_text()
    assert "s.last_vhost = " in src
    # Defensive lookup: pre-migration dbs may not have the column yet
    assert "last_vhost" in src and ".keys()" in src


def test_last_vhost_cap_is_functional_not_just_source_pinned():
    """1.8.14 iter-22 secure-review F-1 (functional). Drive record() with
    a 500-char synthetic vhost and assert IpState.last_vhost ends up <= 120.

    Set the ContextVar directly so we exercise the truncation inside
    record() — set_vhost() itself does not truncate. CWE-400 concern: a
    future revert of the slice would let real Host headers up to ~8 KiB
    persist into ip_state and the clients table; this functional test
    catches that even if the source-anchor regex still matches a future
    slice-on-a-different-line variant.
    """
    import asyncio
    import os
    os.environ.setdefault("UPSTREAM", "https://example.com")
    import vhost  # noqa: E402
    import state  # noqa: E402
    from core.metrics import record  # noqa: E402

    long_host = "a" * 500
    # Use a fresh track_key so we don't collide with state pre-populated
    # by earlier tests in the same pytest session.
    tk = "t-cap-iter22-functional-unique"
    state.ip_state.pop(tk, None)
    vhost._vhost_host_ctx.set(long_host)

    async def go():
        await record(ip="9.9.9.9", ua="x", path="/p", status=200, reason="",
                     track_key=tk)

    asyncio.run(go())
    s = state.ip_state[tk]
    assert len(s.last_vhost) <= 120, \
        f"last_vhost not capped: got len={len(s.last_vhost)}"
    assert s.last_vhost == long_host[:120]


def test_set_vhost_does_not_pre_truncate():
    """Truncation lives in record() (single source of truth alongside
    last_path / last_user_agent caps). set_vhost() itself does NOT truncate
    — the ContextVar carries the full value because vc() lookups against
    VHOSTS need exact matching, including any odd-length entries.

    This pin makes the contract explicit so a future refactor doesn't move
    the cap upstream and inadvertently break a long but legitimate vhost
    lookup (e.g. wildcard-pattern matching against multi-label subdomains)."""
    src = (_ROOT.parent / _ROOT.name / "vhost.py").read_text() if (_ROOT.parent / _ROOT.name / "vhost.py").exists() \
        else (_ROOT / "vhost.py").read_text()
    set_vhost_idx = src.find("def set_vhost(")
    body_end = src.find("\n\n\n", set_vhost_idx)
    body = src[set_vhost_idx:body_end]
    # No `[:120]` slice on the ContextVar set inside set_vhost
    assert "[:120]" not in body
    assert "_vhost_host_ctx.set" in body


def test_last_vhost_capped_at_120_chars():
    """1.8.14 iter-22 secure-review F-1: Host header is attacker-controlled
    and aiohttp accepts headers up to ~8 KiB. Without a cap, an oversized
    Host persists into ip_state + clients table + dashboard JSON. Must be
    capped to 120 chars like last_path / last_user_agent."""
    src = (_ROOT / "core" / "metrics.py").read_text()
    # The assignment must include a slice
    assert "s.last_vhost = (_vhost or \"\")[:120]" in src \
        or "s.last_vhost = _vhost[:120]" in src


def test_clients_payload_carries_vhost_field():
    """The /metrics endpoint must surface s.last_vhost as `vhost` in the
    clients list — the dashboard reads `c.vhost`."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    # Find the clients append block
    idx = src.find('clients.append({')
    end = src.find("})", idx)
    block = src[idx:end]
    assert '"vhost": s.last_vhost' in block
