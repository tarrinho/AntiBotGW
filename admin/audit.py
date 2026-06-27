# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
admin/audit.py — Structured audit log for admin operations.

Records 10 event types to the audit_events table via the async db_queue:
  login_success, login_failed, logout,
  user_created, user_updated, user_deleted, user_session_revoked,
  config_changed, ban_manual, csrf_rejected
"""
import json
import time as _t
from helpers import slog  # noqa: F401 — re-exported for callers that import slog from admin.audit

EVT_LOGIN_SUCCESS      = "login_success"
EVT_LOGIN_FAILED       = "login_failed"
EVT_LOGOUT             = "logout"
EVT_USER_CREATED       = "user_created"
EVT_USER_UPDATED       = "user_updated"
EVT_USER_DELETED       = "user_deleted"
EVT_SESSION_REVOKED    = "user_session_revoked"
EVT_CONFIG_CHANGED     = "config_changed"
EVT_BAN_MANUAL         = "ban_manual"
EVT_CSRF_REJECTED      = "csrf_rejected"

_KNOWN_EVENTS = frozenset([
    EVT_LOGIN_SUCCESS, EVT_LOGIN_FAILED, EVT_LOGOUT,
    EVT_USER_CREATED, EVT_USER_UPDATED, EVT_USER_DELETED, EVT_SESSION_REVOKED,
    EVT_CONFIG_CHANGED, EVT_BAN_MANUAL, EVT_CSRF_REJECTED,
])

_SEVERITY_MAP = {
    EVT_LOGIN_FAILED:    "warn",
    EVT_CSRF_REJECTED:   "warn",
    EVT_BAN_MANUAL:      "warn",
    EVT_USER_DELETED:    "warn",
    EVT_SESSION_REVOKED: "info",
}


def audit_log(event_type: str, actor: str = "", target: str = "",
              ip: str = "", session_id: str = "", **detail_kwargs) -> None:
    """Enqueue one structured audit event. Fire-and-forget — never blocks."""
    from state import db_queue
    if db_queue is None:
        return
    severity = _SEVERITY_MAP.get(event_type, "info")
    detail_json = json.dumps(detail_kwargs, separators=(",", ":"),
                              default=str) if detail_kwargs else "{}"
    try:
        db_queue.put_nowait((
            "audit_log",
            (_t.time(), event_type, actor or "", target or "",
             ip or "", detail_json, session_id or "", severity),
        ))
    except Exception:
        pass
