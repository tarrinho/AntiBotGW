"""1.9.2 iter-26 — surface auto-revert of DB_BACKEND in health-score + UI.

Operator-reported bug: "I just went to /secured/settings and the database
backend is showing SQLite, I have it configured to run PostgreSQL."

Root cause: when PG init/auth fails at startup, iter-17/18's
`_disable_postgres_for_process()` flips runtime `DB_BACKEND` from "postgres"
back to "sqlite" so the gateway stays up on SQLite fallback. The health-score
endpoint returned only the runtime value, so the Settings page rendered
"sqlite" with no indication the operator's PG config was being silently
ignored.

This iter adds three fields to the response — `db_backend_configured`
(what the operator's env asked for), `db_backend_reverted` (true iff the
env+runtime disagree in the "postgres→sqlite" direction), and
`db_backend_revert_reason` (specific cause). The Settings page reads those
and renders a ⚠ badge next to the backend name with a tooltip explaining
the recovery path.

These source-anchor tests pin the contract so a future refactor cannot
silently drop the surface fields or skip the UI warning.
"""
import pathlib

_ROOT = pathlib.Path(__file__).parent.parent


def _slice(src: str, sig: str, max_chars: int = 12000) -> str:
    idx = src.find(sig)
    assert idx >= 0, f"{sig!r} not found"
    return src[idx:idx + max_chars]


def test_health_score_response_includes_configured_and_reverted_flags():
    """health_score_endpoint must include 3 new fields beyond runtime
    db_backend: configured (env), reverted (bool), revert_reason (str)."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def health_score_endpoint")
    # The web.json_response must carry all three keys
    resp_idx = body.find("return web.json_response({")
    assert resp_idx > 0
    resp_block = body[resp_idx:resp_idx + 1500]
    assert '"db_backend":  DB_BACKEND' in resp_block, \
        "db_backend (runtime) must remain — UI still reads this for the badge text"
    assert '"db_backend_configured":' in resp_block, \
        "Configured-from-env value must be returned so the UI can compare"
    assert '"db_backend_reverted":' in resp_block, \
        "Boolean revert flag must be returned for the badge gating"
    assert '"db_backend_revert_reason":' in resp_block, \
        "Reason string must be returned so the tooltip can be specific"


def test_revert_flag_uses_env_not_persisted_state():
    """The configured value MUST come from `os.environ.get("DB_BACKEND", "")`,
    NOT from any persisted config_kv row. Reason: a `/__db-switch` to PG can
    write to config_kv, but if PG was always unreachable the operator's *intent*
    was still PG. Env is the authoritative cold-start input."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def health_score_endpoint")
    assert 'os.environ.get("DB_BACKEND", "")' in body, \
        "Configured value must be read from os.environ, not config_kv"


def test_revert_detector_handles_pg_auth_failure_specifically():
    """The revert_reason must distinguish auth-failure (operator-fixable via
    ALTER USER) from generic init failure (PG down, DSN typo, etc.). The
    detector reads the `_PG_AUTH_FAILED` flag from db.postgres set by
    iter-17's `_is_pg_auth_failure()` handler."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def health_score_endpoint")
    assert "_PG_AUTH_FAILED" in body, \
        "Detector must consult db.postgres._PG_AUTH_FAILED"
    assert '"pg-auth-failure"' in body
    assert '"pg-init-failure-or-unreachable"' in body


def test_revert_detector_only_triggers_on_postgres_to_sqlite_flip():
    """Only flag as reverted when env asked for postgres AND runtime is now
    sqlite. Don't flag when env is sqlite + runtime is sqlite (no revert).
    Don't flag when env is postgres + runtime is postgres (PG is fine)."""
    src = (_ROOT / "core" / "proxy_handler.py").read_text()
    body = _slice(src, "async def health_score_endpoint")
    # The condition must be EXACTLY env==postgres AND runtime != postgres
    assert '(_db_env == "postgres" and DB_BACKEND != "postgres")' in body, \
        "Revert detector must check env==postgres AND runtime!=postgres"


def test_settings_page_renders_auto_revert_badge():
    """dashboards/settings.html must check `j.db_backend_reverted` and render
    a ⚠ badge with the revert_reason embedded in the tooltip. Without this
    visual cue, the operator's only signal that PG config is ignored is
    digging through /__logs."""
    src = (_ROOT / "dashboards" / "settings.html").read_text()
    body = _slice(src, "if (j.db_backend)", max_chars=2500)
    assert "db_backend_reverted" in body, \
        "Settings JS must read the revert flag from health-score response"
    assert "db_backend_revert_reason" in body, \
        "Tooltip text must vary by the specific revert reason"
    assert "auto-reverted from" in body, \
        "Badge text must clearly state auto-revert (not just '⚠')"
    # The badge must use escapeHtml on the runtime db_backend value (XSS guard
    # against a malicious value, however unlikely it would be operator-controlled)
    assert "window.escapeHtml(j.db_backend)" in body, \
        "Badge must escape the dynamic backend name"


def test_settings_page_does_not_use_innerhtml_with_user_data():
    """The badge uses innerHTML to compose the wrapper, but the dynamic
    portion (j.db_backend) MUST be escapeHtml-wrapped. The static markup
    around it (the ⚠ glyph, the tooltip strings) is operator-trusted."""
    src = (_ROOT / "dashboards" / "settings.html").read_text()
    body = _slice(src, "if (j.db_backend)", max_chars=2500)
    # Find the innerHTML assignment within the revert branch
    if_idx = body.find("if (j.db_backend_reverted")
    assert if_idx > 0
    revert_block = body[if_idx:if_idx + 1500]
    assert "gwDb.innerHTML" in revert_block
    # The only dynamic concatenation must be the escapeHtml-wrapped backend
    # name and the reason string (which is a server-emitted enum string,
    # not free text). Verify escapeHtml is in the chain.
    assert "window.escapeHtml(j.db_backend)" in revert_block
