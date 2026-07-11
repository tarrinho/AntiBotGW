"""
test_v1912_cache_class_sweep.py — meta-test that catches every module-level
`_*_CACHE` dict (and other TTL-cache dicts) added to the codebase and asserts
the test fixtures know how to invalidate it.

Motivation — this session found two cross-test flakes rooted in module-level
perf caches whose fixtures cleared the DB but not the cache:
  1. `admin.settings._VHOST_STATS_CACHE` (15 s TTL)  — flaked 4 tests
  2. `db.sqlite._ban_cache` / `_ban_cache_vhost`      — flaked 4 tests

Both were introduced in 1.9.5 for hot-path perf. A future cache added to any
module in the same shape would produce the same class of flake. This test
enumerates them at collection time via AST, and asserts each one is either
in the known-invalidated inventory below OR carries a `# cache: no-invalidate-needed`
marker on its declaration line.

The scan is READ-ONLY at import time — it never runs the gateway, opens
sockets, or touches the DB. Zero runtime impact.
"""
import ast
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent

# Directories whose modules we scan. Everything under tests/, mutants/, and
# scripts/ is excluded — they're not runtime code.
_SCAN_DIRS = ("admin", "core", "db", "detection", "reputation", "integrations",
              "challenge")
_SCAN_ROOT = (
    "proxy.py", "state.py", "helpers.py", "identity.py", "rate_limit.py",
    "scoring.py", "vhost.py", "config.py",
)

# Every known TTL cache in the codebase. Each entry:
#   (module dotted path, symbol name, invalidator hint)
# Adding a new cache?  Add a row here AND wire it into the relevant test
# fixtures (see tests/test_control_regressions.py::_spin_proxy for the
# canonical pattern).
KNOWN_CACHES = {
    # (module, symbol): "how it is invalidated"
    #
    # ── Known cross-test invalidators (this session's fixes) ─────────────
    ("admin.settings", "_VHOST_STATS_CACHE"):
        "cleared in tests/test_code_review_fixes.py::_wipe_events + tests/test_control_center.py::test_d05",
    ("db.sqlite", "_ban_cache"):
        "cleared in tests/test_control_regressions.py::_spin_proxy setup",
    ("db.sqlite", "_ban_cache_vhost"):
        "cleared in tests/test_control_regressions.py::_spin_proxy setup",
    #
    # ── Grandfathered baseline (1.9.12) ──────────────────────────────────
    # These caches existed at the time this gate was introduced and haven't
    # triggered a documented cross-test flake. They are NOT yet audited for
    # invalidation coverage; new caches added post-1.9.12 must be reviewed
    # explicitly. When you touch one of these, promote its hint above.
    ("state", "_signal_order_cache"):
        "grandfathered baseline — not currently invalidated across tests",
    ("admin.oidc", "_JWKS_CACHE"):
        "grandfathered baseline — TTL-refreshed JWKS; process-scoped",
    ("admin.settings", "_SEEN_VHOSTS_CACHE"):
        "grandfathered baseline — vhost discovery cache",
    ("admin.users", "_SESSION_CACHE"):
        "grandfathered baseline — cleared in conftest session teardown paths",
    ("core.proxy_handler", "_GEO_CACHE"):
        "grandfathered baseline — GeoIP lookup memoisation",
    ("core.proxy_handler", "_POW_CHAL_CACHE"):
        "grandfathered baseline — PoW challenge cache",
    ("core.proxy_handler", "_decoy_cache"):
        "grandfathered baseline — upstream decoy response cache",
    ("core.proxy_handler", "_metrics_resp_cache"):
        "grandfathered baseline — /__metrics response cache (1.9.6)",
    ("core.proxy_handler", "_upstream_404_cache"):
        "grandfathered baseline — upstream 404 response cache",
    ("reputation.crowdsec", "_crowdsec_cache"):
        "grandfathered baseline — CrowdSec decision memoisation",
    ("reputation.crowdsec", "_crowdsec_health_cache"):
        "grandfathered baseline — CrowdSec health-check memoisation",
    ("reputation.maxmind", "_asn_cache"):
        "grandfathered baseline — ASN lookup memoisation",
    ("reputation.maxmind", "_city_cache"):
        "grandfathered baseline — City lookup memoisation",
}


def _iter_source_files():
    for rel in _SCAN_ROOT:
        p = _REPO / rel
        if p.exists():
            yield p
    for d in _SCAN_DIRS:
        base = _REPO / d
        if not base.is_dir():
            continue
        for p in base.rglob("*.py"):
            if "__pycache__" in p.parts:
                continue
            yield p


def _module_dotted(path: Path) -> str:
    rel = path.relative_to(_REPO).with_suffix("")
    return ".".join(rel.parts)


# Match both SCREAMING_SNAKE (_VHOST_STATS_CACHE) and snake_case
# (_ban_cache / _ban_cache_vhost) since both patterns are used.
_CACHE_NAME_RE = re.compile(
    r"^_[A-Za-z][A-Za-z0-9_]*_cache(_[A-Za-z0-9_]+)?$", re.IGNORECASE
)


def _is_mutable_container_value(value: ast.AST | None) -> bool:
    """Only treat dict / set / list literals (or their ``dict()`` / ``set()``
    equivalents) as caches. Filters out config constants named `_*_CACHE_TTL`
    or `_*_CACHE_MAX` that are ints / floats / strings."""
    if value is None:                                    # `_x_cache: dict` — declaration
        return True
    if isinstance(value, (ast.Dict, ast.Set, ast.List)):
        return True
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
        if value.func.id in ("dict", "set", "list", "OrderedDict", "defaultdict"):
            return True
    return False


def _cache_symbols_in(path: Path):
    """Yield (symbol_name, source_line) for each module-level
    `_*_cache = {}` / `= dict()` assignment. Only top-level assignments count —
    a cache inside a function/class is per-call state, not shared. Config
    constants (`_BAN_CACHE_TTL = 5`) are filtered by value shape."""
    try:
        src = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError:
        return
    lines = src.splitlines()
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = (
            node.targets if isinstance(node, ast.Assign) else [node.target]
        )
        value = node.value if isinstance(node, ast.Assign) else node.value
        for tgt in targets:
            if not isinstance(tgt, ast.Name):
                continue
            if not _CACHE_NAME_RE.match(tgt.id):
                continue
            if not _is_mutable_container_value(value):
                continue
            line = lines[node.lineno - 1] if node.lineno - 1 < len(lines) else ""
            yield tgt.id, line


def test_every_module_level_cache_is_inventoried():
    """Static AST sweep: find every `_*_CACHE = {}` at module scope and
    require it to be either on the KNOWN_CACHES inventory OR carry a
    `# cache: no-invalidate-needed` marker on the declaration line."""
    unknown = []
    for path in _iter_source_files():
        mod = _module_dotted(path)
        for symbol, line in _cache_symbols_in(path):
            if (mod, symbol) in KNOWN_CACHES:
                continue
            if "cache: no-invalidate-needed" in line:
                continue
            unknown.append(f"  {mod}.{symbol}  — declared at:  {line.strip()}")
    if unknown:
        msg = (
            "New module-level `_*_CACHE` symbol(s) found that are not on the\n"
            "KNOWN_CACHES inventory in tests/test_v1912_cache_class_sweep.py:\n\n"
            + "\n".join(unknown) + "\n\n"
            "Two known-good options:\n"
            "  1. This cache DOES need invalidation across tests — add it to\n"
            "     KNOWN_CACHES here AND clear it in the relevant fixture (see\n"
            "     tests/test_control_regressions.py::_spin_proxy setup for the\n"
            "     canonical pattern).\n"
            "  2. This cache is per-process-immutable (e.g. compiled regex\n"
            "     precomputation) and doesn't need cross-test invalidation —\n"
            "     add a `# cache: no-invalidate-needed` comment on the\n"
            "     declaration line.\n"
        )
        assert not unknown, msg


def test_known_caches_are_still_declared():
    """Guard against the inventory going stale — if a KNOWN_CACHES entry no
    longer exists in source, drop it here."""
    live = set()
    for path in _iter_source_files():
        mod = _module_dotted(path)
        for symbol, _line in _cache_symbols_in(path):
            live.add((mod, symbol))
    stale = [f"  {m}.{s}" for (m, s) in KNOWN_CACHES if (m, s) not in live]
    assert not stale, (
        "KNOWN_CACHES has stale entries that are no longer declared in source:\n"
        + "\n".join(stale) + "\n\n"
        "Remove them from tests/test_v1912_cache_class_sweep.py::KNOWN_CACHES."
    )


def test_fixture_files_reference_each_cache():
    """Weak but useful: each KNOWN_CACHES entry's invalidator hint names one
    or more fixture files. Confirm those files still contain the symbol so
    a fixture rename doesn't silently orphan the invalidator wiring."""
    for (mod, symbol), hint in KNOWN_CACHES.items():
        # Extract test file paths from the hint text.
        for candidate in re.findall(r"tests/[a-zA-Z0-9_/.]+\.py", hint):
            p = _REPO / candidate
            if not p.exists():
                continue
            if symbol not in p.read_text(encoding="utf-8", errors="replace"):
                assert False, (
                    f"KNOWN_CACHES claims {candidate} invalidates {mod}.{symbol}, "
                    f"but the symbol name is not in that file. Fix the hint or "
                    f"restore the invalidation call."
                )
