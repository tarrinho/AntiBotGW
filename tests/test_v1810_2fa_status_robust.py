"""1.8.10 — the 2FA card on the Settings page must handle an expired/invalid
admin session gracefully.

Bug: when the admin session expires, /secured/2fa-status (like every /secured/*
path) silently 404-decoys with an HTML body. load2fa() called r.json() on it,
which threw, and the catch set the 2FA badge to a bare 'error'. The operator saw
an unexplained "error" instead of "your session expired — sign in again".

Fix: parse JSON defensively and map 401/403/404 to a clear session-expired
message across all four 2FA calls (status / setup / confirm / disable).
"""
import re
import pathlib

SET = (pathlib.Path(__file__).resolve().parent.parent /
       "dashboards" / "settings.html").read_text(encoding="utf-8")

# isolate the 2FA IIFE (from load2fa to its load2fa() bootstrap call)
_start = SET.index("async function load2fa()")
_end = SET.index("load2fa();", _start)
TWOFA = SET[_start:_end]


def test_helpers_present():
    assert "function _isAuthFail(status)" in SET
    assert "async function _readJson(r)" in SET
    assert "_SESSION_MSG" in SET


def test_isauthfail_covers_401_403_404():
    m = re.search(r"_isAuthFail\(status\)\s*\{[^}]*\}", SET)
    assert m, "_isAuthFail not found"
    body = m.group(0)
    for code in ("401", "403", "404"):
        assert code in body, f"_isAuthFail must treat {code} as auth failure"


def test_load2fa_checks_response_ok():
    assert "if (!r.ok)" in TWOFA, "load2fa must check r.ok before parsing"
    assert "sign in again" in TWOFA, "load2fa must show a session-expired badge"


def test_no_unguarded_json_parse_in_2fa():
    """No raw `await r.json()` may remain in the 2FA block — all reads must go
    through _readJson so an HTML decoy body cannot throw."""
    assert "await r.json()" not in TWOFA, (
        "2FA card still has an unguarded await r.json() — use _readJson(r)"
    )
    assert TWOFA.count("_readJson(r)") >= 1


def test_session_message_is_actionable():
    m = re.search(r"_SESSION_MSG\s*=\s*'([^']+)'", SET)
    assert m, "_SESSION_MSG constant not found"
    msg = m.group(1).lower()
    assert "session" in msg and ("sign in" in msg or "reload" in msg), (
        f"_SESSION_MSG should tell the operator to reload/sign in: {m.group(1)!r}"
    )


# ── Health pill surfaces admin-auth failures globally ────────────────────────

def test_health_pill_exposes_auth_error_hook():
    """A global hook lets any admin call flag the Health pill on auth failure."""
    assert "window._gwPillAuthError" in SET


def test_health_pill_tick_detects_auth_failure():
    """The pill's own poll must treat 401/403/404 and non-JSON decoys as an
    expired session (not a generic 'ERR')."""
    start = SET.index("async function tick()")
    end = SET.index("async function tick()", start) + 1
    tick = SET[start:SET.index("\n  const KEY_LABELS", start)]
    assert "r.status === 401" in tick and "404" in tick, \
        "tick() must detect 401/403/404 auth failures"
    assert "_setAuthError()" in tick, "tick() must call _setAuthError on auth failure"
    # non-JSON decoy path also routes to auth error
    assert tick.count("_setAuthError()") >= 2, \
        "tick() must handle both status-code and non-JSON-decoy auth failures"


def test_health_pill_shows_signin_text():
    assert "⚠ sign in" in SET, "Health pill must show a 'sign in' state on auth failure"


def test_health_pill_modal_explains_expiry():
    assert "session expired" in SET.lower() or "session has expired" in SET.lower(), \
        "Health pill click modal must explain the expired session"


def test_2fa_card_notifies_health_pill():
    """The 2FA card must flip the Health pill when its request fails auth."""
    assert "window._gwPillAuthError) window._gwPillAuthError()" in SET or \
           "_gwPillAuthError && window._gwPillAuthError()" in SET or \
           ("_isAuthFail(r.status) && window._gwPillAuthError" in SET), \
        "load2fa auth-fail path must call window._gwPillAuthError()"
