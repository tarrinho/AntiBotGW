# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
detection/base.py — Standard Detector interface for AppSecGW detection modules.

Defines the Detector Protocol that all detection modules should satisfy.
Existing modules pre-date this protocol and call their functions directly from
protect(); new modules should implement Detector and register via REGISTRY.

Protocol shape
--------------
  NAME     — unique signal name (used in health registry and slog entries)
  ENABLED  — module-level bool; False skips observe() and check()

  observe(identity, ip, request)  → None
      Called per request BEFORE the upstream fetch. Record state without
      making blocking I/O calls; this is on the hot path.

  check(identity, ip, request) → float
      Called AFTER the upstream response. Return a risk delta ≥ 0.0.
      0.0 means no signal; positive values are added to the identity's
      risk score. The signal name is logged by the caller.

Why a Protocol and not an ABC
------------------------------
Existing modules export plain module-level functions, not class instances.
A structural Protocol lets type-checkers verify conformance without requiring
a class rewrite. New detectors can be class instances or modules — either works
as long as they expose the right attributes and callable signatures.
"""

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Detector(Protocol):
    """Structural protocol for detection modules."""

    NAME: str
    ENABLED: bool

    def observe(self, identity: str, ip: str, request: Any) -> None:
        """Record per-request state. Must not block the event loop."""
        ...

    def check(self, identity: str, ip: str, request: Any) -> float:
        """Return risk delta after upstream response. 0.0 = no signal."""
        ...


# Registry of Detector-conformant objects.
# Modules that implement the full Detector protocol register here so that
# future iterations of protect() can loop over them instead of calling each
# one inline.
REGISTRY: list[Detector] = []


def register(detector: Detector) -> Detector:
    """Register a detector in REGISTRY. Returns the detector unchanged."""
    REGISTRY.append(detector)
    return detector


__all__ = ["Detector", "REGISTRY", "register"]
