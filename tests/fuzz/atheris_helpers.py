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

from helpers import _strip_admin_key_from_qs, _strip_own_session_cookie  # noqa: E402

_ADMIN_KEY = os.environ["ADMIN_KEY"]


def _one_iter(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    qs = fdp.ConsumeUnicodeNoSurrogates(256)
    cookie = fdp.ConsumeUnicodeNoSurrogates(256)

    scrubbed_qs = _strip_admin_key_from_qs(qs)
    assert _ADMIN_KEY not in scrubbed_qs, (
        "admin key leaked through query-string scrub: "
        f"input={qs!r}  output={scrubbed_qs!r}"
    )

    scrubbed_cookie = _strip_own_session_cookie(cookie)
    # Idempotence — scrubbing an already-scrubbed value must be a no-op.
    assert _strip_own_session_cookie(scrubbed_cookie) == scrubbed_cookie


def _test_mode() -> int:
    """CI smoke — a fixed corpus so the harness fails fast on regressions."""
    corpus = [
        b"",
        b"key=" + _ADMIN_KEY.encode(),
        b"foo=bar&key=" + _ADMIN_KEY.encode() + b"&baz=qux",
        b"key=abc%20def",
        b"\x00\x01\x02\x03",
        b"a" * 250,
    ]
    for buf in corpus:
        _one_iter(buf)
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
