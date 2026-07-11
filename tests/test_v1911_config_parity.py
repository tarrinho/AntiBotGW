"""
tests/test_v1911_config_parity.py — .env.example ↔ config parity.

Every key documented in `.env.example` must actually be CONSUMED by the gateway:
either read from the environment by a Python module, or referenced by
`docker-compose.yml` (compose-level vars like POSTGRES_PASSWORD). This guards
against two silent-drift bugs:

  * dead documentation — a key sits in `.env.example` that nothing reads, so an
    operator sets it and nothing happens;
  * documented-but-ignored settings — the RISK_BAN_THRESHOLD class, where a
    threshold is shown as settable but config.py hard-codes it (fixed in 1.9.11).

The reverse direction is deliberately NOT asserted: config.py reads ~250 env
knobs (every *_ENABLED signal, tuning param, …) and `.env.example` only shows
the commonly-used subset — that asymmetry is intended.
"""
import glob
import os
import re

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Reads of the form: os.environ.get("X") · os.getenv("X") · _env*("X") ·
# __import__("os").environ.get("X") · os.environ["X"]. The `environ(.get)?(`
# alternative catches the `__import__("os").environ.get(...)` form too.
_READ_RE = re.compile(
    r'(?:environ(?:\.get)?|getenv|_env[a-z_]*)\(\s*["\']([A-Z_][A-Z0-9_]*)'
)
_SUBSCRIPT_RE = re.compile(r'environ\[\s*["\']([A-Z_][A-Z0-9_]*)')
_KEYLINE_RE = re.compile(r'^\s*#?\s*([A-Z_][A-Z0-9_]*)\s*=')


def _python_env_reads():
    keys = set()
    mods = [
        "config.py", "proxy.py", "vhost.py", "state.py", "helpers.py",
        "identity.py", "rate_limit.py", "scoring.py",
    ]
    for pkg in ("db", "core", "detection", "reputation", "challenge",
                "integrations", "admin", "dashboards"):
        mods += [os.path.relpath(p, _ROOT)
                 for p in glob.glob(os.path.join(_ROOT, pkg, "*.py"))]
    for m in mods:
        p = os.path.join(_ROOT, m)
        if not os.path.exists(p):
            continue
        t = open(p, encoding="utf-8", errors="replace").read()
        keys |= set(_READ_RE.findall(t)) | set(_SUBSCRIPT_RE.findall(t))
    return keys


def _compose_refs():
    p = os.path.join(_ROOT, "docker-compose.yml")
    if not os.path.exists(p):
        return set()
    t = open(p, encoding="utf-8", errors="replace").read()
    # ${VAR} interpolations + `VAR:` environment keys.
    return (set(re.findall(r'\$\{([A-Z_][A-Z0-9_]*)', t))
            | set(re.findall(r'(?m)^\s*([A-Z_][A-Z0-9_]*):\s', t)))


def _env_example_keys():
    keys = set()
    p = os.path.join(_ROOT, ".env.example")
    for line in open(p, encoding="utf-8", errors="replace"):
        m = _KEYLINE_RE.match(line)
        if m:
            keys.add(m.group(1))
    return keys


# Documented in .env.example but consumed OUTSIDE Python / compose — keep tiny
# and justified. BKEY is a shell variable in the CrowdSec bouncer-key setup
# snippet (`BKEY=$(cscli bouncers add …)`), not a gateway config key.
_ALLOW = {"BKEY"}


def test_env_example_keys_are_all_consumed():
    documented = _env_example_keys()
    consumed = _python_env_reads() | _compose_refs() | _ALLOW
    orphans = sorted(documented - consumed)
    assert not orphans, (
        ".env.example documents key(s) that nothing reads — dead docs or a "
        "documented-but-ignored setting (make config.py read it, add it to a "
        "compose service, or remove the line): " + ", ".join(orphans)
    )


def test_env_example_is_non_empty_and_well_formed():
    # Sanity: the parser found keys (catches a moved/renamed .env.example that
    # would make the parity test vacuously pass).
    assert len(_env_example_keys()) >= 30, "expected .env.example to document ≥30 keys"
