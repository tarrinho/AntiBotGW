"""
tests/test_v1911_property_redaction.py — property-based (Hypothesis) tests for
the security-critical redaction helpers.

`helpers._strip_admin_key_from_qs` scrubs the `key=` query param so ADMIN_KEY
never reaches upstream/access logs; `helpers._strip_own_session_cookie` scrubs
the gateway's own session cookie from a forwarded Cookie header. A bug that lets
the secret SURVIVE is a credential leak, so instead of a handful of examples we
fuzz arbitrary inputs and assert the invariant holds for ALL of them:

  1. security — the secret param/cookie never survives the strip;
  2. idempotence — stripping an already-stripped value is a no-op;
  3. preservation — unrelated params/cookies and the path are kept.
"""
import os

os.environ.setdefault("UPSTREAM", "https://example.com")

from hypothesis import given, settings, strategies as st  # noqa: E402

import helpers  # noqa: E402
from config import SESSION_COOKIE  # noqa: E402

# A clean token for a param/cookie name or value: printable ASCII minus the
# structural separators, so we control where the boundaries are.
_TOKEN = st.text(
    st.characters(min_codepoint=33, max_codepoint=126,
                  blacklist_characters="&?;= "),
    min_size=1, max_size=10,
)
_PAIRS = st.lists(st.tuples(_TOKEN, _TOKEN), max_size=6)
# The secret value may be anything (including empty / weird chars).
_SECRET = st.text(max_size=24)


@settings(max_examples=250)
@given(path=st.text(st.characters(min_codepoint=33, max_codepoint=126,
                                   blacklist_characters="?"), max_size=24),
       pairs=_PAIRS, key_val=_SECRET)
def test_admin_key_never_survives_strip(path, pairs, key_val):
    qs = "&".join([f"{n}={v}" for n, v in pairs] + [f"key={key_val}"])
    out = helpers._strip_admin_key_from_qs(f"{path}?{qs}")

    # (1) security: no `key=` param survives in the output query string.
    out_qs = out.partition("?")[2]
    survivors = [p for p in out_qs.split("&") if p.startswith("key=")]
    assert not survivors, f"admin key survived redaction: {survivors!r}"

    # (2) idempotence.
    assert helpers._strip_admin_key_from_qs(out) == out

    # (3) the path component is preserved verbatim.
    assert out.partition("?")[0] == path


@settings(max_examples=250)
@given(pairs=_PAIRS, sess_val=_SECRET)
def test_session_cookie_never_survives_strip(pairs, sess_val):
    # Filter out any decoy cookie that happens to collide with our cookie name,
    # so `kept` below reflects only genuinely-unrelated cookies.
    decoys = [(n, v) for n, v in pairs
              if not n.lower().startswith(SESSION_COOKIE.lower())]
    header = "; ".join([f"{n}={v}" for n, v in decoys]
                       + [f"{SESSION_COOKIE}={sess_val}"])
    out = helpers._strip_own_session_cookie(header)

    # (1) security: the gateway's session cookie never survives (case-insensitive).
    survivors = [p.strip() for p in out.split(";")
                 if p.strip().lower().startswith(SESSION_COOKIE.lower() + "=")]
    assert not survivors, f"session cookie survived redaction: {survivors!r}"

    # (2) idempotence.
    assert helpers._strip_own_session_cookie(out) == out

    # (3) every unrelated cookie is preserved.
    for n, v in decoys:
        assert f"{n}={v}" in out


def test_strip_helpers_handle_empty_and_missing():
    # Boundary cases the property strategies rarely hit exactly.
    assert helpers._strip_admin_key_from_qs("/path/no/qs") == "/path/no/qs"
    assert helpers._strip_admin_key_from_qs("/p?a=1") == "/p?a=1"
    assert helpers._strip_own_session_cookie("") == ""
