"""
detection/honey_cred.py — P1: Semantic honeypot credential injection (1.7.3).

Injects fake API keys in HTML comments on every proxied response.
AI agents extract credentials from HTML source; browsers never read it.
When the probe endpoint is hit with a known fake key → instant high-confidence
bot flag (risk += HONEY_CRED_SCORE, typically 90 = near-instant ban).

Probe URL format:  /antibot-appsec-gateway/probe?k=<key>
Key format:        HMAC-SHA256(SESSION_KEY, "hc|<identity>|<ts_bucket>")[:32]
                   ts_bucket = unix_time // 3600  (rotates hourly)
"""

import hashlib
import hmac
import time as _t

from config import SESSION_KEY, HONEY_CRED_ENABLED, HONEY_CRED_SCORE, ADMIN_NS
from helpers import slog

# key → (identity, expires_ts)  — in-process store, bounded size
_honey_key_store: dict = {}
_STORE_MAX = 4096
_KEY_TTL   = 7200  # 2 hours (2 rotation buckets)


def _make_honey_key(identity: str) -> str:
    bucket = int(_t.time()) // 3600
    raw = hmac.new(
        SESSION_KEY,
        f"hc|{identity}|{bucket}".encode(),
        hashlib.sha256,
    ).hexdigest()[:32]
    return raw


def _store_honey_key(key: str, identity: str) -> None:
    now = _t.time()
    if len(_honey_key_store) >= _STORE_MAX:
        expired = [k for k, (_, exp) in _honey_key_store.items() if exp < now]
        for k in expired:
            _honey_key_store.pop(k, None)
        if len(_honey_key_store) >= _STORE_MAX:
            # evict oldest quarter
            for k in list(_honey_key_store.keys())[:_STORE_MAX // 4]:
                _honey_key_store.pop(k, None)
    _honey_key_store[key] = (identity, now + _KEY_TTL)


def lookup_honey_key(key: str) -> str:
    """Return identity if key is known and unexpired, else empty string."""
    if not key:
        return ""
    entry = _honey_key_store.get(key)
    if not entry:
        return ""
    identity, exp = entry
    if _t.time() > exp:
        _honey_key_store.pop(key, None)
        return ""
    return identity


def inject_honey_creds(body: bytes, identity: str) -> bytes:
    """Inject a realistic-looking debug comment with a fake API key.
    Placed just before </body> if present, otherwise appended.
    No-op when HONEY_CRED_ENABLED=0 or body is empty."""
    if not HONEY_CRED_ENABLED or not body or not identity:
        return body

    key = _make_honey_key(identity)
    _store_honey_key(key, identity)

    probe_url = f"{ADMIN_NS}/probe?k={key}"
    comment = (
        f"\n<!-- TODO: remove debug config before next release\n"
        f"     internal_api_key = {key}\n"
        f"     debug_endpoint   = {probe_url}\n"
        f"     env              = staging\n-->"
    ).encode()

    lower = body.lower()
    idx = lower.rfind(b"</body>")
    if idx >= 0:
        return body[:idx] + comment + body[idx:]
    return body + comment


__all__ = ["inject_honey_creds", "lookup_honey_key"]
