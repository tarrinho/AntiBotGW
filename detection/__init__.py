# detection/__init__.py — Phase 4
# Re-exports everything from all detection sub-modules so callers can do
# `from detection import *` and get the full surface.

from detection.ua import *
from detection.paths import *
from detection.headers import *
from detection.behavioral import *
from detection.canary import *
from detection.automation import *
from detection.cookie_lifecycle import *
from detection.referer_chain import *
from detection.impossible_travel import *
from detection.fp_enrichment import *

# Standard Detector interface + reference implementations.
from detection.base import Detector, REGISTRY, register  # noqa: F401
import detection.detectors  # noqa: F401 — side-effect: populates REGISTRY
