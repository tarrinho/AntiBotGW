# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
integrations/ — external integration subpackage.

Phase 7 of the anti-bot-proxy modular refactoring.

Submodules:
  redis           — optional Redis-backed shared ban state
  webhook         — operator webhook fan-out
  ja4             — JA4 TLS fingerprint deny-list + auto-deny
  jwt             — JWT/Bearer HS256 validation (Tier B)
  endpoint_policy — per-endpoint policy engine + custom rules (Tiers A/B)
"""

from integrations.redis import *            # noqa: F401,F403
from integrations.webhook import *          # noqa: F401,F403
from integrations.ja4 import *              # noqa: F401,F403
from integrations.jwt import *              # noqa: F401,F403
from integrations.endpoint_policy import *  # noqa: F401,F403
from integrations.fingerproxy import *      # noqa: F401,F403
