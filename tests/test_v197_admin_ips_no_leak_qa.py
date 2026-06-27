"""
QA — `ADMIN_ALLOWED_IPS` values must NEVER leak into source/docs.

`.env` holds the live operator IP allow-list (real residential/office IPs).
That file is `.gitignore`-d, but a careless paste into a script, a copy of an
older session log into `.claude/pentest-logs/`, or an example added to a doc
could silently expose those IPs in the public GitHub mirror.

This test:
  1. Reads `.env` for `ADMIN_ALLOWED_IPS`
  2. Extracts the IP addresses (strips `/CIDR`)
  3. Drops well-known *benign* IPs that are safe to ship publicly:
       - 127.0.0.1                    (loopback)
       - 172.17.x.x / 172.18.x.x      (Docker bridge defaults)
       - 10.0.0.0/8, 192.168.0.0/16   (RFC 1918 private — likely safe)
       - 192.0.2.x, 198.51.100.x,
         203.0.113.x                  (RFC 5737 TEST-NET-1/2/3 doc IPs)
       - 0.0.0.0                      (placeholder)
  4. Greps every tracked file type (`.py/.md/.html/.yml/.yaml/.sh/.json/.toml/
     .cfg/.txt/.example/Dockerfile*`) for the remaining operator IPs
  5. Asserts ZERO hits (excluding `.env` itself, `.git/`, `.claude/`,
     `mutants/`, the test's own source).

If `.env` is absent (CI / clean checkout), the suite XFAILs with
`ENV_ABSENT`. Override with `AGW_REQUIRE_ENV=1`.
"""
import os
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_ENV = _ROOT / ".env"
_REQUIRE_ENV = os.environ.get("AGW_REQUIRE_ENV") == "1"

# IP literals that are safe to ship publicly. Examples / docs / Docker
# bridge defaults / loopback / RFC 1918 / RFC 5737.
_BENIGN_PREFIXES = (
    "127.",
    "0.0.0.0",
    "172.17.", "172.18.", "172.19.", "172.20.",  # Docker default bridge ranges
    "10.",
    "192.168.",
    "192.0.2.",       # RFC 5737 TEST-NET-1
    "198.51.100.",    # RFC 5737 TEST-NET-2
    "203.0.113.",     # RFC 5737 TEST-NET-3
)

# Source patterns to grep. Anchored on extension because we don't want
# to scan binary blobs, MaxMind DBs, etc.
_SCAN_GLOBS = (
    "*.py", "*.md", "*.html", "*.yml", "*.yaml", "*.sh",
    "*.json", "*.toml", "*.cfg", "*.txt", "*.example",
    "Dockerfile", "Dockerfile.*",
)

# Paths excluded from the scan (they are not synced to GitHub OR are
# intentionally allowed to mention the IPs in question).
_EXCLUDE_DIR_PARTS = (
    ".git", ".claude", "mutants", "node_modules", "__pycache__",
)
_EXCLUDE_NAMES = {
    ".env",                                          # source of truth
    "test_v197_admin_ips_no_leak_qa.py",             # this test
}


def _load_operator_ips() -> list[str]:
    if not _ENV.exists():
        msg = "ENV_ABSENT: .env not found — nothing to scan against."
        if _REQUIRE_ENV:
            pytest.fail(msg)
        pytest.xfail(msg)
    raw = ""
    for line in _ENV.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("ADMIN_ALLOWED_IPS="):
            raw = line.split("=", 1)[1]
            break
    if not raw:
        pytest.xfail("ENV_NO_ADMIN_ALLOWED_IPS: .env exists but lacks ADMIN_ALLOWED_IPS")
    ips: list[str] = []
    for entry in raw.split(","):
        entry = entry.strip().strip('"').strip("'")
        if not entry:
            continue
        ip = entry.split("/", 1)[0]
        if not re.fullmatch(r"[0-9.]+", ip):
            # IPv6 or junk — skip; ADMIN_ALLOWED_IPS in this project is IPv4-only today.
            continue
        if any(ip.startswith(p) for p in _BENIGN_PREFIXES):
            continue
        ips.append(ip)
    return ips


def _scan_paths():
    for path in _ROOT.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(_ROOT)
        parts = set(rel.parts)
        if parts & set(_EXCLUDE_DIR_PARTS):
            continue
        if path.name in _EXCLUDE_NAMES:
            continue
        if not any(path.match(g) for g in _SCAN_GLOBS):
            continue
        yield path


# ── Tests ────────────────────────────────────────────────────────────────────

class TestOperatorIpNoLeak:
    """No operator-real IP (from .env ADMIN_ALLOWED_IPS, minus the benign
    placeholders) may appear in any tracked source/doc file."""

    def test_some_operator_ips_to_scan(self):
        ips = _load_operator_ips()
        # If you really do only have benign IPs, the file is harmless and
        # this test becomes a no-op — but flag it so the user knows.
        if not ips:
            pytest.skip(
                "ADMIN_ALLOWED_IPS contains only benign / placeholder IPs; "
                "leak scan is a no-op."
            )
        # Sanity: well-formed IPv4 dotted quads only
        for ip in ips:
            assert re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ip), (
                f"malformed IP in ADMIN_ALLOWED_IPS: {ip!r}"
            )

    def test_no_operator_ip_in_any_tracked_file(self):
        ips = _load_operator_ips()
        if not ips:
            pytest.skip("no real operator IPs to scan for")
        # Build one regex with literal-escaped IPs.
        pattern = re.compile(
            r"\b(?:" + "|".join(re.escape(ip) for ip in ips) + r")\b"
        )
        offenders: list[tuple[str, int, str, str]] = []
        for path in _scan_paths():
            try:
                txt = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for n, line in enumerate(txt.splitlines(), start=1):
                m = pattern.search(line)
                if m:
                    offenders.append((
                        str(path.relative_to(_ROOT)),
                        n,
                        m.group(0),
                        line.strip()[:120],
                    ))
                    if len(offenders) >= 20:  # cap to keep the failure readable
                        break
            if len(offenders) >= 20:
                break
        assert not offenders, (
            "REAL_OPERATOR_IP_LEAK: an IP from ADMIN_ALLOWED_IPS appears in a "
            "tracked source / doc file. These IPs identify the operator and "
            "MUST stay in .env only.\n"
            + "\n".join(f"  {f}:{n}  {ip}  → {snippet}" for f, n, ip, snippet in offenders)
        )

    def test_env_is_gitignored(self):
        gi = (_ROOT / ".gitignore").read_text(encoding="utf-8")
        # Match either bare `.env` line or `.env` at start.
        assert re.search(r"^\.env\b", gi, flags=re.MULTILINE), (
            ".env is NOT in .gitignore — operator IPs would leak on next push"
        )

    def test_env_example_uses_placeholders_not_real_ips(self):
        ex = _ROOT / ".env.example"
        if not ex.exists():
            pytest.skip(".env.example absent")
        line = ""
        for ln in ex.read_text(encoding="utf-8").splitlines():
            if ln.startswith("ADMIN_ALLOWED_IPS="):
                line = ln
                break
        assert line, ".env.example lacks ADMIN_ALLOWED_IPS row"
        # Should mention either a placeholder token (YOUR.*, <your-ip>) or
        # only benign IPs.
        ips = _load_operator_ips()
        if ips:
            for ip in ips:
                assert ip not in line, (
                    f".env.example leaks a real operator IP {ip}: {line!r}"
                )
