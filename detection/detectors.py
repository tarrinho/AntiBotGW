"""
detection/detectors.py — Reference Detector implementations.

These thin adapter classes wrap existing module-level detection functions so
they satisfy the Detector protocol from detection.base.  Existing protect()
code still calls the module functions directly; the adapters demonstrate the
target shape for future detectors and populate detection.base.REGISTRY.

Adding a new detector:
  1. Implement the Detector protocol (observe + check)
  2. Call detection.base.register(YourDetector())
  3. Existing protect() loop will pick it up automatically once it is
     migrated to iterate REGISTRY instead of calling modules inline.
"""

from typing import Any

import detection.llm_heuristic as _llm
import detection.path_sweep as _ps
from detection.base import Detector, register  # noqa: F401 (re-exported)


class LlmHeuristicDetector:
    """Wraps detection.llm_heuristic as a Detector.

    LLM/AI-agent detection: real browsers load sub-resources (CSS, JS,
    images) for every HTML page; AI WebFetch tools fetch only the HTML.
    Fires 'llm-no-subresources' when ratio falls below threshold.
    """

    NAME = "llm-no-subresources"

    @property
    def ENABLED(self) -> bool:
        return bool(_llm.LLM_HEURISTIC_ENABLED)

    def observe(self, identity: str, ip: str, request: Any) -> None:
        if not self.ENABLED or not identity:
            return
        method = getattr(request, "method", "GET")
        path   = getattr(request, "path", "/")
        accept = request.headers.get("Accept", "") if hasattr(request, "headers") else ""
        _llm.observe(identity, method, path, accept)

    def check(self, identity: str, ip: str, request: Any) -> float:
        return _llm.check(identity, ip)


register(LlmHeuristicDetector())


__all__ = ["LlmHeuristicDetector"]
