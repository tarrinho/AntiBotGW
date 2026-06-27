#!/usr/bin/env python3
"""
check_test_coverage.py — keep GW-Tests-Full.md in sync with tests/ automatically.

Replaces the two brittle inline snippets in rules.md §13 (the `comm -23` presence
check and the per-table `**Total:` assertion) with one robust, self-fixing tool.

WHY THIS EXISTS
    GW-Tests-Full.md is hand-curated (per-test prose). The *mechanical* gate —
    "every tests/test_*.py has a section" + "every section carries a test total"
    — was maintained by hand, so it silently desynced whenever someone added a
    test file and forgot. This script makes the mechanical part derivable:

      check_test_coverage.py            # verify; exit 1 + report drift
      check_test_coverage.py --fix      # scaffold missing sections, then verify

    Curated prose is never touched: --fix only APPENDS stub sections for files
    that have none. A human enriches the stub later; the gate stays green.

GATE (drop into rules.md §13, replacing both snippets):
      python3 scripts/check_test_coverage.py

Counts are `def test_*` function counts (incl. methods in Test* classes). For
parametrized tests the runtime case count is higher — the doc's curated totals
may legitimately exceed the def count, so a section total >= the def count is
accepted; only a MISSING file or a section with NO total line fails the gate.
"""
from __future__ import annotations

import ast
import os
import re
import sys
from pathlib import Path

# Repo root is the parent of scripts/. Overridable via AGW_COVERAGE_ROOT so the
# QA suite can point the checker at a throwaway fixture tree (tests/test_v197_
# release_tooling_qa.py) instead of mutating the real GW-Tests-Full.md.
_ROOT_OVERRIDE = os.environ.get("AGW_COVERAGE_ROOT")
ROOT = Path(_ROOT_OVERRIDE) if _ROOT_OVERRIDE else Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"
DOC = ROOT / "GW-Tests-Full.md"

# A test file is "documented" if its basename appears as `test_x.py` anywhere in
# the doc (matches the existing rules.md grep). Section detection for the total
# check keys on the `### `test_x.py`` heading the doc already uses.
_FILE_IN_DOC = lambda doc, name: f"`{name}`" in doc
_SECTION_RE = re.compile(r"^### +`(test_[a-z0-9_]+\.py)`", re.M)
_TOTAL_RE = re.compile(r"\*\*Total:\s*\d+\b|\b\d+\s+tests?\b", re.I)


def _count_tests(path: Path) -> int:
    """Count `test_*` functions (module-level + methods of Test* classes)."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return 0
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            n += 1
    return n


def _docstring_summary(path: Path) -> str:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        doc = (ast.get_docstring(tree) or "").strip()
    except SyntaxError:
        doc = ""
    if not doc:
        return "(no module docstring — describe this file's coverage)"
    first = next((ln.strip() for ln in doc.splitlines() if ln.strip()), "")
    return first[:140]


def _test_files() -> list[Path]:
    return sorted(p for p in TESTS_DIR.glob("test_*.py") if p.is_file())


def _scaffold(path: Path) -> str:
    name = path.name
    n = _count_tests(path)
    summary = _docstring_summary(path)
    mver = re.search(r"test_v(\d)(\d)(\d*)", name)
    ver = f"v{mver.group(1)}.{mver.group(2)}.{mver.group(3) or '0'}" if mver else "—"
    rows = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                d = (ast.get_docstring(node) or "").strip().splitlines()
                desc = d[0].strip() if d and d[0].strip() else "(auto — describe)"
                rows.append(f"| `{node.name}` | {desc[:120]} |")
    except SyntaxError:
        pass
    table = "\n".join(rows) if rows else "| (none parsed) | — |"
    return (
        f"\n### `{name}` — {summary}\n"
        f"**Version added:** {ver}  \n"
        f"**Type:** (auto-scaffolded — refine)  \n"
        f"**Purpose:** {summary}\n\n"
        f"| Test | Description |\n|------|-------------|\n{table}\n\n"
        f"**Total: {n} tests**\n"
    )


def main(argv: list[str]) -> int:
    fix = "--fix" in argv
    if not DOC.exists():
        print(f"ERROR: {DOC} not found", file=sys.stderr)
        return 2
    doc = DOC.read_text(encoding="utf-8")

    files = _test_files()
    missing = [p for p in files if not _FILE_IN_DOC(doc, p.name)]

    if missing and fix:
        appended = "\n\n## Auto-added (pending curation)\n"
        appended += "".join(_scaffold(p) for p in missing)
        doc = doc.rstrip() + "\n" + appended
        DOC.write_text(doc, encoding="utf-8")
        print(f"[--fix] scaffolded {len(missing)} missing section(s): "
              + ", ".join(p.name for p in missing))
        missing = []  # now present

    # Verify: every documented `### `test_*.py`` section carries a total line.
    no_total = []
    sections = list(_SECTION_RE.finditer(doc))
    for i, m in enumerate(sections):
        body = doc[m.end(): sections[i + 1].start() if i + 1 < len(sections) else len(doc)]
        if not _TOTAL_RE.search(body):
            no_total.append(m.group(1))

    ok = True
    if missing:
        ok = False
        print("DRIFT — test files with no section in GW-Tests-Full.md:", file=sys.stderr)
        for p in missing:
            print(f"  - {p.name}  ({_count_tests(p)} tests)  «{_docstring_summary(p)}»", file=sys.stderr)
        print("  fix: python3 scripts/check_test_coverage.py --fix", file=sys.stderr)
    if no_total:
        ok = False
        print("DRIFT — sections missing a `**Total: N tests**` line:", file=sys.stderr)
        for s in no_total:
            print(f"  - {s}", file=sys.stderr)

    if ok:
        print(f"OK — {len(files)} test files all documented; "
              f"{len(sections)} sections all carry a total line.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
