# detection/ua.py — Phase 4 extraction
# UA_BLOCKLIST, AI_UA_GROUPS, and all AI_UA_*_ENABLED flags live in config.py
# (populated during Phase 1). This module simply re-exports them so that code
# importing from detection.ua gets a stable public surface.

from config import (
    UA_BLOCKLIST,
    AI_UA_GROUPS,
    AI_UA_OPENAI_ENABLED,
    AI_UA_ANTHROPIC_ENABLED,
    AI_UA_GOOGLE_ENABLED,
    AI_UA_PERPLEXITY_ENABLED,
    AI_UA_META_ENABLED,
    AI_UA_OTHER_ENABLED,
    UA_FILTER_ENABLED,
    UA_PLATFORM_CHECK_ENABLED,
)

__all__ = [
    "UA_BLOCKLIST",
    "AI_UA_GROUPS",
    "AI_UA_OPENAI_ENABLED",
    "AI_UA_ANTHROPIC_ENABLED",
    "AI_UA_GOOGLE_ENABLED",
    "AI_UA_PERPLEXITY_ENABLED",
    "AI_UA_META_ENABLED",
    "AI_UA_OTHER_ENABLED",
    "UA_FILTER_ENABLED",
    "UA_PLATFORM_CHECK_ENABLED",
]
