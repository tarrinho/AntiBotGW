"""
1.9.7 — dashboard aggregations must snapshot ip_state before iterating
=====================================================================

The deferred rehydrate (proxy.on_startup) populates ip_state from a WORKER
THREAD; dashboard aggregation endpoints iterate it under the asyncio state_lock,
which doesn't guard against a thread. Iterating the live dict raised
"OrderedDict mutated during iteration" (500) during the post-restart warm-up
(R-1.9.7). Fix: every dashboard iteration goes through a list() snapshot, which
collapses the race window to the list() construction. This pins that so a bare
iteration can't creep back in.
"""
import re
from pathlib import Path

_DASH = Path(__file__).resolve().parent.parent / "dashboards"
# bare `for ... in ip_state.items()/values()/keys()` NOT wrapped in list(
_BARE = re.compile(r'\bfor\b[^\n]*\bin\s+ip_state\.(items|values|keys)\(\)')


def test_no_bare_ipstate_iteration_in_dashboards():
    offenders = []
    for f in _DASH.glob("*.py"):
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if _BARE.search(line) and "list(ip_state" not in line:
                offenders.append(f"{f.name}:{i}: {line.strip()}")
    assert not offenders, "dashboard code must snapshot ip_state via list():\n" + "\n".join(offenders)
