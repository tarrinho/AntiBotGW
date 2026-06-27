"""1.8.13 — guard against the recurring 'DOMPurify strips inline on* handlers' bug.

The dashboards sanitize attacker/event-controlled HTML through _dp() = DOMPurify
.sanitize(), whose default config removes every on* event-handler attribute. So an
inline `onclick="…"` / `oninput="…"` inside a _dp()-rendered string is silently
dropped — the control renders but does nothing. This bit the honeypots Attacker
storyboard, the main.html attacker leaderboard (Ban/Unban/Chal + copy), and the
settings.html infra/log knob inputs + a modal ×.

The fix everywhere is: render with data-* attributes, then bind listeners with
addEventListener after the innerHTML is set. This test fails if any dashboard
reintroduces an inline on* handler inside a _dp()-sanitized render.
"""
import re
import pathlib

import pytest

_DASH = pathlib.Path(__file__).resolve().parent.parent / "dashboards"
_FILES = sorted(p.name for p in _DASH.glob("*.html"))

# attribute-style on*="…" (NOT a `.onclick = fn` DOM-property assignment)
_ATTR = re.compile(r'''[\s"'>]on(?:click|change|input|submit|mouse\w+|key\w+)\s*=\s*["']''')


def _violations(src: str):
    """Return contexts of inline on* attributes whose enclosing innerHTML render
    uses _dp() (DOMPurify) — those handlers get stripped at runtime."""
    out = []
    for sm in re.finditer(r"<script(?:\s[^>]*)?>(.*?)</script>", src, re.DOTALL):
        s = sm.group(1)
        for m in _ATTR.finditer(s):
            pre = s[max(0, m.start() - 3500):m.start()]
            j = pre.rfind("innerHTML")
            if j != -1 and "_dp(" in pre[j:]:
                out.append(s[max(0, m.start() - 40):m.start() + 25].replace("\n", " ").strip())
    return out


@pytest.mark.parametrize("fname", _FILES)
def test_no_inline_handler_inside_dompurify_render(fname):
    src = (_DASH / fname).read_text(encoding="utf-8")
    v = _violations(src)
    assert not v, (
        f"{fname}: inline on* handler(s) inside a _dp()-sanitized render — "
        f"DOMPurify strips these (dead control). Use data-* + addEventListener:\n  "
        + "\n  ".join(v)
    )
