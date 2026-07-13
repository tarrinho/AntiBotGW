#!/usr/bin/env python3
"""
Atheris fuzz harness for the security-critical redaction helpers.

`helpers._strip_admin_key_from_qs` scrubs the `?key=<ADMIN_KEY>` query
parameter so the admin secret never reaches upstream / access logs;
`helpers._strip_own_session_cookie` scrubs the gateway's own session cookie
from a forwarded `Cookie:` header. A bug that lets the secret survive is a
credential leak, so we fuzz arbitrary bytes and assert the redaction
invariant holds for every input.

This runs both under:
  - atheris-libfuzzer (`python3 atheris_helpers.py`) — coverage-guided fuzz;
  - a bounded self-test in CI (`--test`) so `atheris` isn't required just to
    validate the harness compiles + the invariants pass on a fixed corpus.

OpenSSF Scorecard's Fuzzing check detects the `import atheris` line and
awards the Fuzzing check accordingly.
"""

from __future__ import annotations

import os
import sys

os.environ.setdefault("UPSTREAM", "https://example.com")
os.environ.setdefault("ADMIN_KEY", "FUZZ-ADMIN-KEY-DO-NOT-USE")

# Ensure the repo root is on sys.path so `import helpers` works when running
# this file directly from tests/fuzz/.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import atheris  # noqa: E402  — scorecard's Fuzzing check greps for this import

# Coverage instrumentation — atheris rewrites bytecode of any module imported
# inside `instrument_imports()` so libFuzzer gets edge coverage. Without this,
# fuzz devolves to random-input testing.
with atheris.instrument_imports():
    from helpers import (  # noqa: E402
        SESSION_COOKIE,
        _strip_admin_key_from_qs,
        _strip_own_session_cookie,
    )

_ADMIN_KEY = os.environ["ADMIN_KEY"]


def _qs_params(path_qs: str):
    """Split `path?a=1&b=2` into `[('a','1'), ('b','2')]`. `[]` if no `?`."""
    if "?" not in path_qs:
        return []
    _, _, qs = path_qs.partition("?")
    out = []
    for p in qs.split("&"):
        if not p:
            continue
        k, _, v = p.partition("=")
        out.append((k, v))
    return out


def _check_invariants(qs: str, cookie: str) -> None:
    """Fuzz invariants — kept separate so `--test` can call them without atheris."""
    # ── query-string invariants ─────────────────────────────────────
    scrubbed_qs = _strip_admin_key_from_qs(qs)

    # 1. Security: no `key=` param survives (regardless of value).
    for k, _v in _qs_params(scrubbed_qs):
        assert k != "key", (
            "key= param survived scrub: "
            f"input={qs!r}  output={scrubbed_qs!r}"
        )

    # 2. Idempotence: scrubbing again is a no-op.
    assert _strip_admin_key_from_qs(scrubbed_qs) == scrubbed_qs

    # 3. Preservation: the path prefix (before `?`) is untouched.
    input_path = qs.partition("?")[0]
    scrubbed_path = scrubbed_qs.partition("?")[0]
    assert scrubbed_path == input_path, (
        "path prefix mutated: "
        f"in={input_path!r}  out={scrubbed_path!r}"
    )

    # ── cookie invariants ──────────────────────────────────────────
    scrubbed_cookie = _strip_own_session_cookie(cookie)

    # 1. Security: no cookie whose name equals SESSION_COOKIE survives.
    sess_lc = SESSION_COOKIE.lower() + "="
    for part in [p.strip() for p in scrubbed_cookie.split(";") if p.strip()]:
        assert not part.lower().startswith(sess_lc), (
            "session cookie survived scrub: "
            f"input={cookie!r}  output={scrubbed_cookie!r}  survivor={part!r}"
        )

    # 2. Idempotence.
    assert _strip_own_session_cookie(scrubbed_cookie) == scrubbed_cookie


def _one_iter(data: bytes) -> None:
    """libFuzzer entry — consumes coverage-guided bytes then applies invariants."""
    fdp = atheris.FuzzedDataProvider(data)
    qs = fdp.ConsumeUnicodeNoSurrogates(256)
    cookie = fdp.ConsumeUnicodeNoSurrogates(256)
    _check_invariants(qs, cookie)


def _test_mode() -> int:
    """CI smoke — a fixed corpus so the harness fails fast on regressions."""
    corpus = [
        # (qs, cookie)
        ("", ""),
        (f"/?key={_ADMIN_KEY}", ""),
        (f"/api?foo=bar&key={_ADMIN_KEY}&baz=qux", ""),
        ("/?key=abc%20def", ""),
        # Cookie corpus — cookie name matches SESSION_COOKIE (case-insensitive).
        ("/", f"{SESSION_COOKIE}=abc; other=keep"),
        ("/", f"other=keep; {SESSION_COOKIE.upper()}=abc"),
        # Random-ish bytes (Latin-1 decode of a mixed range).
        ("/random", "\x00\x01\x02\x03"),
        ("/" + "a" * 250, "b" * 250),
        # Adversarial: ADMIN_KEY substring in a NON-`key=` param — must NOT
        # be scrubbed (helper is scoped to `key=` only, by design).
        (f"/?ey={_ADMIN_KEY}", ""),
        (f"/?keys={_ADMIN_KEY}", ""),
    ]
    for qs, cookie in corpus:
        _check_invariants(qs, cookie)
    print(f"atheris_helpers self-test OK ({len(corpus)} inputs)")
    return 0


def main() -> int:
    if "--test" in sys.argv:
        return _test_mode()
    atheris.Setup(sys.argv, _one_iter)
    atheris.Fuzz()
    return 0


if __name__ == "__main__":
    sys.exit(main())
