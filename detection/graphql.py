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
    # 1.8.11 (H1): scan the full accepted body, not just the first 64 KiB, so a
    # large batch / introspection payload can't be hidden behind padding.
    sample = body[:_cfg.WAF_BODY_SCAN_BYTES]
    # Introspection check (regex is C-level — cheap even over a large body).
    if not _cfg.GQL_ALLOW_INTROSPECTION and _GQL_INTROSPECTION_RE.search(sample):
        signals.append("gql-introspection")
    # Batch abuse (array of operations) — json.loads is C-level.
    try:
        parsed = json.loads(sample)
        if isinstance(parsed, list) and len(parsed) > _cfg.GQL_BATCH_LIMIT:
            signals.append("gql-batch-abuse")
    except Exception:
        pass
    # Depth check (count brace nesting). This is a Python-level byte loop, so
    # bound it to keep per-request CPU O(1) on large bodies; nesting attacks
    # manifest well within this window.
    depth = max_depth = 0
    for b in sample[:262144]:
        if b == ord('{'):
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif b == ord('}'):
            depth -= 1
    if max_depth > _cfg.GQL_MAX_DEPTH:
        signals.append("gql-depth-exceeded")
    return signals
