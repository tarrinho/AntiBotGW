"""
detection/llm_heuristic.py — P3: LLM tool-call timing / no-subresource heuristic (1.7.3).

Real browsers load CSS, JS, images, and fonts for every HTML page they render.
AI agents using WebFetch or similar tools fetch only the HTML document itself —
no sub-resources ever follow. Track the ratio per identity; when an identity
has fetched N HTML pages with zero sub-resources in the window → LLM signal.

Sub-resource classification (by path extension or Accept header):
  CSS:   .css
  JS:    .js, .mjs, .cjs
  Font:  .woff, .woff2, .ttf, .otf, .eot
  Image: .png, .jpg, .jpeg, .gif, .svg, .ico, .webp, .avif
  XHR:   Accept header contains application/json but not text/html
"""

import time as _t
from collections import defaultdict, deque

from config import (
    LLM_HEURISTIC_ENABLED,
    LLM_HTML_MIN_COUNT,
    LLM_SUBRES_RATIO_THRESHOLD,
    LLM_HEURISTIC_WINDOW_SECS,
    LLM_HEURISTIC_SCORE,
)
from helpers import slog

_SUBRES_EXTS = frozenset({
    ".css", ".js", ".mjs", ".cjs",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".mp4", ".webm",
})

# identity → deque of (ts, is_subresource: bool)
_req_log: dict = defaultdict(lambda: deque(maxlen=256))
_REQ_LOG_MAX  = 16384  # evict when exceeded
# identity → set: signals already fired (prevent double-counting per window)
_fired: dict = {}
_FIRED_TTL    = LLM_HEURISTIC_WINDOW_SECS * 2
_FIRED_MAX    = 8192  # evict when exceeded


def _is_subresource(path: str, accept: str) -> bool:
    lower_path = path.lower().split("?")[0]
    ext = "." + lower_path.rsplit(".", 1)[-1] if "." in lower_path else ""
    if ext in _SUBRES_EXTS:
        return True
    if "application/json" in accept and "text/html" not in accept:
        return True
    return False


def _is_html_request(method: str, accept: str, path: str) -> bool:
    if method != "GET":
        return False
    lower_path = path.lower().split("?")[0]
    ext = "." + lower_path.rsplit(".", 1)[-1] if "." in lower_path else ""
    if ext in _SUBRES_EXTS or ext in (".xml", ".txt", ".csv", ".pdf"):
        return False
    return "text/html" in accept or accept == "" or "*/*" in accept


def observe(identity: str, method: str, path: str, accept: str) -> None:
    """Record a request. Called for every proxied request."""
    if not LLM_HEURISTIC_ENABLED or not identity:
        return
    now = _t.time()
    is_sub = _is_subresource(path, accept)
    is_html = _is_html_request(method, accept, path)
    if is_sub or is_html:
        _req_log[identity].append((now, is_sub))
        if len(_req_log) > _REQ_LOG_MAX:
            cutoff = now - _FIRED_TTL
            stale = [k for k, dq in _req_log.items() if not dq or dq[-1][0] < cutoff]
            for k in stale:
                _req_log.pop(k, None)
            if len(_req_log) > _REQ_LOG_MAX:
                for k in list(_req_log.keys())[: _REQ_LOG_MAX // 4]:
                    _req_log.pop(k, None)


def check(identity: str, ip: str) -> float:
    """Return risk delta if LLM pattern detected, else 0.0.
    Call after every HTML response to check accumulated pattern."""
    if not LLM_HEURISTIC_ENABLED or not identity:
        return 0.0

    # Cooldown: don't re-fire within the window
    now = _t.time()
    last_fired = _fired.get(identity, 0)
    if now - last_fired < LLM_HEURISTIC_WINDOW_SECS:
        return 0.0

    cutoff = now - LLM_HEURISTIC_WINDOW_SECS
    log = _req_log.get(identity)
    if not log:
        return 0.0

    html_count  = sum(1 for ts, is_sub in log if ts >= cutoff and not is_sub)
    subres_count = sum(1 for ts, is_sub in log if ts >= cutoff and is_sub)

    if html_count < LLM_HTML_MIN_COUNT:
        return 0.0

    ratio = subres_count / html_count
    if ratio > LLM_SUBRES_RATIO_THRESHOLD:
        return 0.0

    # Evict stale fired entries when dict grows large
    if len(_fired) >= _FIRED_MAX:
        cutoff_evict = now - _FIRED_TTL
        stale = [k for k, ts in _fired.items() if ts < cutoff_evict]
        for k in stale:
            _fired.pop(k, None)
        if len(_fired) >= _FIRED_MAX:
            for k in list(_fired.keys())[:_FIRED_MAX // 4]:
                _fired.pop(k, None)
    _fired[identity] = now
    slog("llm_no_subresources", level="warn", ip=ip, identity=identity[:8],
         html_count=html_count, subres_count=subres_count,
         window_secs=LLM_HEURISTIC_WINDOW_SECS)
    return LLM_HEURISTIC_SCORE


__all__ = ["observe", "check"]
