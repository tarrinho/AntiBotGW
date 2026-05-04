# challenge/__init__.py — Phase 6
# Re-exports everything from all challenge sub-modules so callers can do
# `from challenge import *` and get the full surface.

from challenge.pow import *
from challenge.js_challenge import *
from challenge.tarpit import *
from challenge.js_challenge import sw_js_endpoint  # noqa: F401 — underscore-free, explicit
