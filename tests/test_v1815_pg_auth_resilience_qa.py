"""1.8.14 iter-17 — Postgres auth-failure resilience QA.

Goal: a wrong-password / missing-role / pg_hba.conf rejection MUST NOT block
gateway startup. The gateway falls back to SQLite, emits an actionable log
line, and surfaces the state in /service-data so operators see the recovery
command in the Service dashboard.

Root cause that motivated this fix: POSTGRES_PASSWORD only takes effect on
first initdb. A subsequent docker-compose edit looks like it set a new
password but pg_authid still carries the original. To the gateway it looks
identical to "Postgres is down" — but retrying never helps. Previously the
gateway burned the full 12-attempt backoff (sometimes blocking startup for
~30s+) on something that would never recover.

Now: on auth failure, retry stops immediately, an actionable log is emitted
with the exact ALTER USER recovery command, and a banner appears on the
Service dashboard. Gateway stays UP on SQLite throughout.
"""
import pathlib

_ROOT = pathlib.Path(__file__).parent.parent


def test_pg_auth_failure_short_circuits_retry():
    """db_init_postgres MUST detect auth failure and stop the retry loop
    immediately — never burn the full backoff window on credentials that
    won't fix themselves."""
    src = (_ROOT / "db" / "postgres.py").read_text()
    assert "_is_pg_auth_failure" in src
    assert "STOPPING retry loop" in src
    assert "if _is_pg_auth_failure(e):" in src


def test_pg_auth_failure_globals_exist():
    src = (_ROOT / "db" / "postgres.py").read_text()
    assert "_PG_AUTH_FAILED: bool = False" in src
    assert "_PG_AUTH_FAILED_TS: float = 0.0" in src
    assert "_PG_AUTH_FAILED_HINT: str = " in src


def test_pg_auth_detector_covers_common_signatures():
    """Detector MUST catch the messages psycopg / libpq actually emit on
    auth rejection — wrong password, missing role, pg_hba.conf rejection."""
    src = (_ROOT / "db" / "postgres.py").read_text()
    for needle in (
        "password authentication failed",
        "no password supplied",
        "no pg_hba.conf entry",
        "ident authentication failed",
        "InvalidPassword",
        "InvalidAuthorizationSpecification",
    ):
        assert needle in src, f"auth detector missing signature: {needle!r}"


def test_pg_auth_failure_hint_carries_actionable_recovery():
    """The hint MUST tell the operator the EXACT recovery command, not a
    generic 'check your credentials'. We don't include the password verbatim
    (secret-scanner safety) — point to docker-compose."""
    src = (_ROOT / "db" / "postgres.py").read_text()
    assert "_pg_auth_failure_hint" in src
    assert "ALTER USER" in src
    assert "POSTGRES_PASSWORD only takes effect" in src
    assert "first initdb" in src
    assert "SQLite fallback" in src


def test_pg_auth_failure_hint_does_not_leak_password():
    """The hint must NEVER include the actual password value — only the
    placeholder. A password value reaching the dashboard or logs is a leak."""
    src = (_ROOT / "db" / "postgres.py").read_text()
    # Locate the hint builder body and check it uses a placeholder, not the DSN's password
    fn_start = src.find("def _pg_auth_failure_hint")
    fn_end = src.find("\n\n\n", fn_start)
    body = src[fn_start:fn_end]
    assert "<value-from-docker-compose-or-DSN>" in body or "<value-from-" in body
    # Must not f-string the password into the hint
    assert "{pw}" not in body
    assert "{password}" not in body


def test_pg_init_returns_false_on_auth_failure():
    """db_init_postgres MUST return False on auth failure so the caller
    (on_startup) proceeds with SQLite. False == 'skip, carry on', it does
    NOT abort startup."""
    src = (_ROOT / "db" / "postgres.py").read_text()
    fn_start = src.find("def db_init_postgres(")
    fn_end = src.find("\ndef ", fn_start + 10)
    body = src[fn_start:fn_end]
    # The auth-failure branch ends with `return False`, NOT a raise
    auth_branch = body[body.find("_is_pg_auth_failure"):]
    auth_branch_until_else = auth_branch[:auth_branch.find("if attempt < max_attempts")]
    assert "return False" in auth_branch_until_else
    assert "raise" not in auth_branch_until_else


def test_on_startup_treats_pg_init_failure_as_non_fatal():
    """proxy.py's on_startup MUST NOT raise when db_init_postgres returns
    False — the SQLite backend is always available, gateway stays UP."""
    src = (_ROOT / "proxy.py").read_text()
    assert "if db_init_postgres()" in src
    # Find the if-block and verify the else / failure path doesn't raise
    idx = src.find("if db_init_postgres():")
    # Look 20 lines ahead
    block = src[idx:idx + 800]
    assert "else:" in block
    assert "raise" not in block.split("else:", 1)[1][:300], \
        "on_startup must not raise on Postgres init failure"


def test_service_data_surfaces_auth_failure_flag():
    """/service-data endpoint MUST expose pg_auth_failed + pg_auth_failed_ts
    + pg_auth_failed_hint so the dashboard can render the actionable banner."""
    src = (_ROOT / "dashboards" / "service_metrics.py").read_text()
    assert '"pg_auth_failed":' in src
    assert '"pg_auth_failed_ts":' in src
    assert '"pg_auth_failed_hint":' in src
    # Must read from db.postgres module references (not a stale literal)
    assert "_pg_module._PG_AUTH_FAILED" in src


def test_service_dashboard_renders_auth_banner():
    """service.html MUST include the auth-failure banner div + JS handler.
    The banner uses textContent (NOT innerHTML) — XSS-safe."""
    src = (_ROOT / "dashboards" / "service.html").read_text()
    assert 'id="pg-auth-banner"' in src
    assert 'id="pg-auth-banner-hint"' in src
    assert 'id="pg-auth-banner-ts"' in src
    assert "d.pg_auth_failed" in src
    assert ".textContent =" in src  # safe DOM write
    # Must not innerHTML the hint (could carry markup if upstream changes).
    # Slice tightly to the JS handler block (~25 lines) — wider slices catch
    # unrelated `.innerHTML` from helpers further down the file.
    js_anchor = src.find("Postgres auth-failure banner. Shown when")
    js_block = src[js_anchor:js_anchor + 700]
    assert ".innerHTML" not in js_block, \
        "auth banner JS handler must use textContent, not innerHTML"


def test_banner_initial_state_hidden():
    """Banner default style MUST be display:none so it never flashes on
    healthy-Postgres or no-Postgres setups."""
    src = (_ROOT / "dashboards" / "service.html").read_text()
    banner_block = src[src.find('id="pg-auth-banner"'):]
    banner_block = banner_block[:banner_block.find("</div>")]
    assert "display:none" in banner_block


def test_pg_init_failure_disables_postgres_for_process():
    """1.8.14 iter-18 — ANY init failure (auth or otherwise) MUST flip
    _postgres_available=False and revert DB_BACKEND to sqlite via
    _disable_postgres_for_process. Otherwise the svc-metrics sampler keeps
    re-opening doomed connections every 5 s and the operator's PG log fills."""
    src = (_ROOT / "db" / "postgres.py").read_text()
    assert "def _disable_postgres_for_process" in src
    # Called from BOTH auth-failure branch AND generic-failure giveup
    assert src.count("_disable_postgres_for_process(") >= 2
    # Helper itself flips _postgres_available and DB_BACKEND
    fn_start = src.find("def _disable_postgres_for_process")
    fn_end = src.find("\n\n\n", fn_start)
    body = src[fn_start:fn_end]
    assert "_postgres_available = False" in body
    assert "DB_BACKEND" in body and "sqlite" in body


def test_postgres_load_module_reports_install_only():
    """1.8.14 iter-19 — _postgres_load_module reports whether psycopg is
    *installed*, NOT whether Postgres is operationally usable. Conflating
    the two made db_switch_endpoint say "psycopg not installed in this
    image" after an auth failure, even though psycopg was clearly there.
    Suppression of post-failure connect attempts lives at the connect
    layer (_PgPool._connect + record() gating on _postgres_available)."""
    src = (_ROOT / "db" / "postgres.py").read_text()
    fn_start = src.find("def _postgres_load_module")
    fn_end = src.find("\n\n\n", fn_start)
    body = src[fn_start:fn_end]
    # Must NOT short-circuit on _PG_AUTH_FAILED — that's iter-18's mistake.
    assert "_PG_AUTH_FAILED" not in body, \
        "_postgres_load_module must report install state, not runtime status"
    # Must still return the module when psycopg is installed
    assert "_state._postgres = psycopg" in body


def test_pg_pool_connect_refuses_after_auth_failure():
    """1.8.14 iter-18 — _PgPool._connect must raise quickly when
    _PG_AUTH_FAILED is set; otherwise pooled acquires keep retrying."""
    src = (_ROOT / "db" / "postgres.py").read_text()
    # Locate _PgPool._connect specifically
    pool_start = src.find("class _PgPool")
    cn_start = src.find("def _connect(self)", pool_start)
    cn_end = src.find("\n    def ", cn_start + 1)
    body = src[cn_start:cn_end]
    assert "_PG_AUTH_FAILED" in body
    assert "raise" in body


def test_pg_auth_failure_log_event_is_distinct():
    """The auth-failure log MUST be visually distinct from generic init
    failures — operators grepping `[db-pg]` should see this category
    clearly, not buried among 12 attempt-N lines."""
    src = (_ROOT / "db" / "postgres.py").read_text()
    assert "AUTH FAILURE:" in src
    # The pre-existing generic failure log uses "init failed after %d attempts"
    assert "init failed after %d attempts" in src
