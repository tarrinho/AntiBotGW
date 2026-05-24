# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
# detection/paths.py — Phase 4 extraction
# HONEYPOT_PATHS, SUSPICIOUS_PATH_PATTERNS, is_suspicious_path, HONEY_LINK_HTML,
# and bot-trap form injection all live here.
#
# Constants that were already moved to config.py during Phase 1 are imported,
# not re-defined.

import re
import secrets
from config import (
    HONEYPOT_PATHS,
    SUSPICIOUS_PATH_PATTERNS,
    HONEY_LINK_HTML,
    HONEYPOT_ENABLED,
    SUSPICIOUS_PATH_ENABLED,
)


def is_suspicious_path(path: str) -> bool:
    return any(p.search(path) for p in SUSPICIOUS_PATH_PATTERNS)


# ── Bot-trap form injection ────────────────────────────────────────────────
# BOT_TRAP_FORMS, BOT_TRAP_FIELDS, BOT_TRAP_FIELD, the hidden-input HTML blob,
# and the form-open regex are defined here (they were not moved to config.py).

import os

BOT_TRAP_FORMS = os.environ.get("BOT_TRAP_FORMS", "0") in ("1", "true", "yes")


def _trap_name(prefix: str) -> str:
    return f"{prefix}_" + secrets.token_hex(3)


BOT_TRAP_FIELDS = [
    _trap_name("email_confirm"),
    _trap_name("website"),
    _trap_name("phone_alt"),
    _trap_name("address2"),
    _trap_name("ec"),                       # legacy short name kept for back-compat
]
# Back-compat alias (older code paths still reference BOT_TRAP_FIELD)
BOT_TRAP_FIELD = BOT_TRAP_FIELDS[0]

_HIDDEN_STYLE = (
    "position:absolute;left:-9999px;top:-9999px;opacity:0;"
    "width:0;height:0;visibility:hidden")

_TRAP_INPUTS_HTML = b"".join(
    (
        f'<input type="text" name="{name}" tabindex="-1" autocomplete="off" '
        f'aria-hidden="true" style="{_HIDDEN_STYLE}">'
    ).encode()
    for name in BOT_TRAP_FIELDS
)

_FORM_OPEN_RX = re.compile(rb"(<form\b[^>]*>)", re.IGNORECASE)


def _inject_bot_trap(body: bytes) -> bytes:
    if not BOT_TRAP_FORMS or b"<form" not in body[:65536].lower():
        return body
    return _FORM_OPEN_RX.sub(rb"\1" + _TRAP_INPUTS_HTML, body, count=20)


def _bot_trap_triggered(body: bytes, ctype: str) -> tuple:
    """True iff ANY of the bot-trap fields is non-empty in a form-encoded
    POST body. Returns (triggered, matched_field_or_'')."""
    if not BOT_TRAP_FORMS or not body:
        return (False, "")
    if "x-www-form-urlencoded" not in ctype.lower():
        return (False, "")
    sample = body[:65536]
    # Quick reject if no needle present
    if not any((f + "=").encode() in sample for f in BOT_TRAP_FIELDS):
        return (False, "")
    try:
        from urllib.parse import parse_qs
        q = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=False)
        for f in BOT_TRAP_FIELDS:
            v = (q.get(f, [""])[0] or "").strip()
            if v:
                return (True, f)
    except Exception:
        return (False, "")
    return (False, "")


__all__ = [
    "HONEYPOT_PATHS",
    "SUSPICIOUS_PATH_PATTERNS",
    "HONEY_LINK_HTML",
    "HONEYPOT_ENABLED",
    "SUSPICIOUS_PATH_ENABLED",
    "is_suspicious_path",
    "BOT_TRAP_FORMS",
    "BOT_TRAP_FIELDS",
    "BOT_TRAP_FIELD",
    "_HIDDEN_STYLE",
    "_TRAP_INPUTS_HTML",
    "_FORM_OPEN_RX",
    "_inject_bot_trap",
    "_bot_trap_triggered",
]
