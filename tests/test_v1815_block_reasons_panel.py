"""
1.8.15 — Block reasons panel must show every reason, not just legacy 16.

Bug: dashboards/main.html had a hardcoded `reasonOrder` list of 16 legacy
reason names; the renderer used `reasonOrder.filter(k => reasons[k])` to
pick what to show. Any reason not in that list (host-not-allowed,
tarpit-walk, ip-ban, dlp-*, honey-*, redirect-maze, body-* SQLi/XSS,
h2-settings-*, …) was silently dropped → "Methods blocked" panel looked
empty even when blocks were happening.

Fix: render `Object.entries(reasons).filter([cnt] => cnt > 0)` sorted by
count desc (curated reasonOrder kept as a tie-break, not as a filter).
"""
import pathlib
import re


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MN   = (_ROOT / "dashboards" / "main.html").read_text(encoding="utf-8")


class TestBlockReasonsPanelRenderAll:

    def test_does_not_filter_by_reasonOrder(self):
        """The renderer must NOT call reasonOrder.filter(...) — that was the bug."""
        # Locate the Block reasons panel rendering block
        idx = _MN.find("// 1.8.15 — Block reasons")
        # Fallback if comment changes — look for the rEl assignment
        if idx == -1:
            idx = _MN.find("const rEl = document.getElementById('reasons')")
            assert idx != -1, "could not locate Block reasons panel renderer"
        # Take a window of ~2500 chars around it
        block = _MN[idx: idx + 2500]
        # The bug pattern: filter the order list against the reasons dict.
        assert "reasonOrder.filter(k => reasons[k])" not in block, (
            "BUG REGRESSION: reasonOrder.filter(k => reasons[k]) silently drops "
            "any reason not in the hardcoded list. Must iterate Object.entries(reasons)"
        )

    def test_iterates_all_reason_entries(self):
        idx = _MN.find("const rEl = document.getElementById('reasons')")
        assert idx != -1
        block = _MN[idx: idx + 2500]
        # Must call Object.entries on the reasons map
        assert "Object.entries(reasons)" in block, (
            "Block reasons renderer must iterate Object.entries(reasons) so "
            "every fired reason appears, not just those in a curated list"
        )

    def test_sorted_by_count_desc(self):
        idx = _MN.find("const rEl = document.getElementById('reasons')")
        block = _MN[idx: idx + 2500]
        # The sort comparator must compare numeric counts (b[1] - a[1]) somewhere.
        assert re.search(r"b\[1\]\s*-\s*a\[1\]", block) or \
               re.search(r"b\.\d+\s*-\s*a\.\d+", block), (
            "Block reasons must be sorted by hit count descending so the "
            "most-frequent reasons appear first"
        )

    def test_reason_order_still_used_as_tiebreak(self):
        """The curated reasonOrder must remain in source as a tiebreak hint —
        not deleted, just no longer the filter. We assert both that it's still
        declared AND that it's referenced after the Object.entries call."""
        assert "const reasonOrder" in _MN, (
            "reasonOrder list should remain as a tiebreak hint"
        )
        idx = _MN.find("const reasonOrder")
        entries_idx = _MN.find("Object.entries(reasons)", idx)
        assert entries_idx != -1 and entries_idx > idx, (
            "Object.entries(reasons) must appear after reasonOrder declaration"
        )
        # Tiebreak uses indexOf
        tiebreak = _MN.find("reasonOrder.indexOf(", entries_idx)
        assert tiebreak != -1, (
            "Sort comparator must use reasonOrder.indexOf(...) as a tiebreak"
        )

    def test_empty_state_preserved(self):
        idx = _MN.find("const rEl = document.getElementById('reasons')")
        block = _MN[idx: idx + 2500]
        assert "no blocks yet" in block, (
            "Empty state ('no blocks yet') must still render when no reasons "
            "have non-zero count"
        )
