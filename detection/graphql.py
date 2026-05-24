# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""detection/graphql.py — GraphQL introspection, batch, and depth protection."""
import json
import re

_GQL_INTROSPECTION_RE = re.compile(
    rb'(?:__schema|__type\b|IntrospectionQuery)', re.I)


def check_graphql(path: str, body: bytes, content_type: str) -> list:
    """Return list of signal names triggered by this GraphQL request."""
    # Import config at call time so hot-reload knobs are always current.
    import config as _cfg
    if not _cfg.GQL_ENABLED:
        return []
    if not body:
        return []
    # Only apply to configured GraphQL paths
    path_base = path.split("?")[0]
    if _cfg.GQL_PATHS and path_base not in _cfg.GQL_PATHS:
        return []
    signals = []
    sample = body[:65536]
    # Introspection check
    if not _cfg.GQL_ALLOW_INTROSPECTION and _GQL_INTROSPECTION_RE.search(sample):
        signals.append("gql-introspection")
    # Batch abuse (array of operations)
    try:
        parsed = json.loads(sample)
        if isinstance(parsed, list) and len(parsed) > _cfg.GQL_BATCH_LIMIT:
            signals.append("gql-batch-abuse")
    except Exception:
        pass
    # Depth check (count brace nesting)
    depth = max_depth = 0
    for b in sample:
        if b == ord('{'):
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif b == ord('}'):
            depth -= 1
    if max_depth > _cfg.GQL_MAX_DEPTH:
        signals.append("gql-depth-exceeded")
    return signals
