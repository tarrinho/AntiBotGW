# detection/__init__.py — Phase 4
# Re-exports everything from all detection sub-modules so callers can do
# `from detection import *` and get the full surface.

from detection.ua import *
from detection.paths import *
from detection.headers import *
from detection.behavioral import *
from detection.canary import *
