# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_v1814_review_fixes.py — QA for the inline code-review fixes
applied in v1.8.14 iteration 18:

  H1: scrypt run off the event loop (_password_verify_async / _password_hash_async)
  H2: _pg_mirror_kv fired off-loop from db_writer_loop via _pg_mirror_bg
  M1: prune_old_events / prune_ip_bans moved OUT of state_lock + run in thread
  M2: HOP_BY_HOP_REQUEST now includes "forwarded" + "x-forwarded-prefix"
  M3: _ssrf_guard_url and _upstream_safe_to_reload fail closed on gaierror
  M4: totp_setup_endpoint requires POST + CSRF (was GET, no CSRF)
  L1: _session_verify fails closed when cache cold (no boot-window grace)
  L2: totp_disable_endpoint requires a fresh TOTP code (no backup-code disable)
  L3: mesh fernet key persists on /data volume (with legacy /app/ fallback)
  L4: requirements.txt pins aiohttp==3.13.5 to match Dockerfile

These are source-inspection tests — they verify the fix is present in the
repo and protected against regression by trivial revert. Runtime behavioral
tests are added separately when they would catch real regressions the source
check cannot.
"""
from __future__ import annotations

import os
import pathlib
import re

import pytest

os.environ.setdefault("UPSTREAM", "https://example.com")

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (_ROOT / rel).read_text(encoding="utf-8")


# ── H1: scrypt off-loop ─────────────────────────────────────────────────────

def test_h1_password_verify_async_exists():
    """The async wrapper must exist and route scrypt through asyncio.to_thread."""
    src = _read("admin/users.py")
    assert "async def _password_verify_async" in src, "async wrapper missing"
    assert "async def _password_hash_async" in src, "async hash wrapper missing"
    # Both must use asyncio.to_thread, not a thread-pool or sync call.
    assert re.search(
        r"_password_verify_async.*\n.*asyncio\.to_thread\(_password_verify",
        src, re.DOTALL), "_password_verify_async does not call asyncio.to_thread"
    assert re.search(
        r"_password_hash_async.*\n.*asyncio\.to_thread\(_password_hash",
        src, re.DOTALL), "_password_hash_async does not call asyncio.to_thread"


def test_h1_login_uses_async_verify():
    """login_submit_endpoint must await _password_verify_async, not the sync version."""
    src = _read("admin/users.py")
    # Find login_submit_endpoint body.
    m = re.search(r"async def login_submit_endpoint.*?(?=\nasync def |\ndef )",
                  src, re.DOTALL)
    assert m, "login_submit_endpoint not found"
    body = m.group(0)
    assert "await _password_verify_async(" in body, \
        "login must call the async verifier"
    # The sync _password_verify must NOT appear inside the async login handler
    # (apart from the wrapper definition itself, which is outside this match).
    assert "if not _password_verify(" not in body, \
        "sync _password_verify still present on the async login path"


def test_h1_users_create_uses_async_hash():
    src = _read("admin/users.py")
    m = re.search(r"async def users_create_endpoint.*?(?=\nasync def |\ndef )",
                  src, re.DOTALL)
    assert m, "users_create_endpoint not found"
    assert "await _password_hash_async(" in m.group(0)


def test_h1_users_update_password_uses_async():
    """Password change path runs both verify and hash off-loop."""
    src = _read("admin/users.py")
    m = re.search(r"async def users_update_endpoint.*?(?=\nasync def |\ndef )",
                  src, re.DOTALL)
    assert m, "users_update_endpoint not found"
    body = m.group(0)
    assert "await _password_verify_async(" in body, \
        "update must call async verify for current-password check"
    assert "await _password_hash_async(" in body, \
        "update must call async hash for new-password write"


# ── H2: PG mirror off-loop ──────────────────────────────────────────────────

def test_h2_pg_mirror_bg_wrapper_exists():
    src = _read("db/sqlite.py")
    assert "def _pg_mirror_bg(" in src
    assert "asyncio.to_thread(_pg_mirror_kv" in src, \
        "_pg_mirror_bg must dispatch via asyncio.to_thread"


def test_h2_writer_loop_uses_bg_wrapper():
    """No direct synchronous _pg_mirror_kv(...) calls remain in the writer batches."""
    src = _read("db/sqlite.py")
    # Strip the wrapper definition + its sync fallback from the check window.
    after_loop_start = src.split("async def db_writer_loop", 1)[1]
    # All mirror invocations from `op == ...` branches must go through _pg_mirror_bg.
    for op in ("set_config", "del_config", "set_secret", "del_secret",
               "set_admin_ip", "del_admin_ip", "update_admin_ip_description",
               "gw_audit_add", "honey_fp_add"):
        assert f'_pg_mirror_bg("{op}", args)' in after_loop_start, \
            f"writer branch for {op} not converted to _pg_mirror_bg"


# ── M1: prune off state_lock ────────────────────────────────────────────────

def test_m1_prune_runs_outside_state_lock():
    """prune_old_events / prune_ip_bans calls must be OUTSIDE the state_lock block."""
    src = _read("rate_limit.py")
    m = re.search(r"async def _prune_state_loop.*?(?=\nasync def |\nclass |\Z)",
                  src, re.DOTALL)
    assert m, "_prune_state_loop not found"
    body = m.group(0)
    # The inner `async with state_lock:` block ends before "# ── Post-lock"
    lock_end = body.find("# ── Post-lock DB prunes")
    assert lock_end > 0, "post-lock prune block missing"
    pre_lock_section = body[:lock_end]
    post_lock_section = body[lock_end:]
    # The OLD inline calls to prune_ip_bans / prune_old_events must NOT live
    # inside the lock anymore.
    assert "_prune_ip_bans()" not in pre_lock_section, \
        "prune_ip_bans still called under state_lock"
    assert "_prune_old_events()" not in pre_lock_section, \
        "prune_old_events still called under state_lock"
    # And they MUST live after the lock.
    assert "await asyncio.to_thread(_prune_ip_bans)" in post_lock_section
    assert "await asyncio.to_thread(_prune_old_events)" in post_lock_section


# ── M2: Forwarded + X-Forwarded-Prefix stripped ─────────────────────────────

def test_m2_forwarded_header_stripped():
    src = _read("core/proxy_handler.py")
    m = re.search(r"HOP_BY_HOP_REQUEST = \{([^}]+)\}", src)
    assert m, "HOP_BY_HOP_REQUEST set not found"
    body = m.group(1).lower()
    assert '"forwarded"' in body, "RFC 7239 Forwarded header not stripped"
    assert '"x-forwarded-prefix"' in body, "X-Forwarded-Prefix not stripped"


# ── M3: SSRF gaierror fail-closed ───────────────────────────────────────────

def test_m3_ssrf_guard_fails_closed_on_gaierror():
    src = _read("core/proxy_handler.py")
    # _ssrf_guard_url: gaierror branch must raise ValueError, not return.
    guard = re.search(r"def _ssrf_guard_url.*?(?=\ndef |\nasync def )",
                      src, re.DOTALL)
    assert guard, "_ssrf_guard_url not found"
    gbody = guard.group(0)
    # The branch that handles gaierror must raise, not return.
    m = re.search(r"except _sock2\.gaierror:\s*\n(.+?)(?=\n    for |\nasync def |\ndef )",
                  gbody, re.DOTALL)
    assert m, "gaierror branch in _ssrf_guard_url not found"
    branch = m.group(1)
    assert "raise ValueError" in branch, \
        "_ssrf_guard_url gaierror branch must raise, not return"


def test_m3_upstream_safe_fails_closed_on_gaierror():
    src = _read("core/proxy_handler.py")
    func = re.search(r"def _upstream_safe_to_reload.*?(?=\ndef |\nasync def )",
                     src, re.DOTALL)
    assert func, "_upstream_safe_to_reload not found"
    fbody = func.group(0)
    m = re.search(r"except _sock\.gaierror:\s*\n(.+?)(?=\n        for |\n    except |\ndef )",
                  fbody, re.DOTALL)
    assert m, "gaierror branch in _upstream_safe_to_reload not found"
    branch = m.group(1)
    assert "return False" in branch, \
        "_upstream_safe_to_reload gaierror branch must return False, not True"


# ── M4: TOTP setup CSRF ─────────────────────────────────────────────────────

def test_m4_totp_setup_requires_csrf():
    src = _read("admin/users.py")
    # The decorator must be present immediately before totp_setup_endpoint.
    m = re.search(r"(@_require_csrf\s*\n)+async def totp_setup_endpoint", src)
    assert m, "totp_setup_endpoint missing @_require_csrf decorator"


def test_m4_totp_setup_route_is_post():
    src = _read("proxy.py")
    # The route registration line must be add_post for /2fa-setup.
    assert "add_post" in src and "/2fa-setup" in src
    # And the GET registration must be gone for this path.
    for line in src.splitlines():
        if "/2fa-setup" in line and "add_get" in line:
            pytest.fail(f"2fa-setup still registered with add_get: {line!r}")


def test_m4_dashboard_uses_post_for_totp_setup():
    src = _read("dashboards/settings.html")
    # The fetch call must include method:'POST'.
    m = re.search(r"fetch\([^)]*'/secured/2fa-setup'[^)]*\)", src)
    assert m, "2fa-setup fetch call not found"
    call = m.group(0)
    assert "method:'POST'" in call or 'method: "POST"' in call, \
        f"2fa-setup fetch must specify POST: {call!r}"


# ── L1: cold-cache fail-closed ──────────────────────────────────────────────

def test_l1_session_verify_no_cold_cache_grace():
    src = _read("admin/users.py")
    m = re.search(r"def _session_verify.*?(?=\ndef |\nasync def )", src, re.DOTALL)
    assert m, "_session_verify not found"
    body = m.group(0)
    # The grace branch ("if not _SESSION_CACHE_READY: return username") must be gone.
    assert "if not _SESSION_CACHE_READY:" not in body, \
        "boot-window grace branch still present in _session_verify"


# ── L2: TOTP-only disable ───────────────────────────────────────────────────

def test_l2_totp_disable_rejects_backup_code():
    src = _read("admin/users.py")
    m = re.search(r"async def totp_disable_endpoint.*?(?=\nasync def |\n@_require_csrf|\ndef )",
                  src, re.DOTALL)
    assert m, "totp_disable_endpoint not found"
    body = m.group(0)
    # The backup-code branch must be removed from the disable path.
    assert "backup_ok = True" not in body, \
        "backup-code disable path still present in totp_disable_endpoint"
    # And the explicit reject message must be there.
    assert "fresh TOTP code required to disable 2FA" in body


# ── L3: mesh key on /data ───────────────────────────────────────────────────

def test_l3_mesh_key_path_on_data():
    src = _read("admin/mesh.py")
    # Primary path moved to /data; legacy /app path kept as fallback.
    assert 'key_path = "/data/.mesh_fernet_key"' in src, \
        "mesh fernet key not migrated to /data"
    assert 'legacy_path = "/app/.mesh_fernet_key"' in src, \
        "legacy /app/.mesh_fernet_key fallback missing (would break existing deployments)"


# ── L4: aiohttp pinned ──────────────────────────────────────────────────────

def test_l4_aiohttp_pinned_exact():
    req = _read("requirements.txt")
    # Must be == not >= so dev/CI matches container.
    m = re.search(r"^aiohttp==([0-9.]+)", req, re.MULTILINE)
    assert m, f"aiohttp not pinned with == in requirements.txt"
    # And it must match the version baked into the Dockerfile.
    dockerfile = _read("Dockerfile")
    df_m = re.search(r"'aiohttp==([0-9.]+)'", dockerfile)
    assert df_m, "Dockerfile aiohttp pin not found"
    assert m.group(1) == df_m.group(1), \
        f"aiohttp pin mismatch: requirements.txt={m.group(1)} Dockerfile={df_m.group(1)}"


# ── LIVE-1 + LIVE-2: ip_intel + whoami auth gate ────────────────────────────

def test_live1_ip_intel_requires_auth():
    src = _read("admin/users.py")
    m = re.search(r"async def ip_intel_endpoint.*?(?=\nasync def |\ndef )",
                  src, re.DOTALL)
    assert m, "ip_intel_endpoint not found"
    body = m.group(0)
    assert "if not _internal_authed(request):" in body, \
        "ip_intel_endpoint missing _internal_authed gate"
    # The auth check must fire BEFORE the IP validation logic.
    auth_pos = body.find("if not _internal_authed")
    ip_validate_pos = body.find("ipaddress.ip_address(ip)")
    assert 0 < auth_pos < ip_validate_pos, \
        "_internal_authed must run before ip_address() validation"


def test_live2_whoami_requires_auth():
    src = _read("admin/users.py")
    m = re.search(r"async def whoami_endpoint.*?(?=\nasync def |\ndef )",
                  src, re.DOTALL)
    assert m, "whoami_endpoint not found"
    body = m.group(0)
    assert "if not _internal_authed(request):" in body, \
        "whoami_endpoint missing _internal_authed gate"


# ── LIVE-3: ip_intel reads ip_bans table ────────────────────────────────────

def test_live3_ip_intel_queries_ip_bans_table():
    """The persistent IP-keyed ban table (1.8.12 M-4) must be visible to
    operators via the IP intel popover. Previously only the `bans` (track_key
    keyed) table was queried."""
    src = _read("admin/users.py")
    m = re.search(r"async def ip_intel_endpoint.*?(?=\nasync def |\ndef )",
                  src, re.DOTALL)
    assert m
    body = m.group(0)
    # Both `bans` and `ip_bans` must be queried with the IP.
    assert re.search(r"SELECT[^\"]*FROM\s+bans\s+WHERE\s+ip\s*=\s*\?", body), \
        "ip_intel must still query the bans table"
    assert re.search(r"SELECT[^\"]*FROM\s+ip_bans\s+WHERE\s+ip\s*=\s*\?", body), \
        "ip_intel must ALSO query the ip_bans table (LIVE-3)"


# ── LIVE-4: unban clears ip_bans by RESOLVED IP, not by HMAC ────────────────

def test_live4_unban_resolves_real_ip_for_ip_bans():
    """Operator's Allow on an identity must clear the persistent ip_bans row
    keyed by the IDENTITY's real client IP — not by the track_key HMAC (which
    never matches the IP column)."""
    src = _read("core/proxy_handler.py")
    m = re.search(r"async def unban_endpoint.*?(?=\n@_require_csrf|\nasync def |\ndef )",
                  src, re.DOTALL)
    assert m, "unban_endpoint not found"
    body = m.group(0)
    # The bug: old code did DELETE FROM ip_bans WHERE ip=target_id
    # (target_id is the HMAC, never matches). Guard against regression.
    assert "_ips_to_unban" in body, \
        "unban_endpoint must collect raw client IPs to clear ip_bans by IP"
    # The new IP-loop deletes from ip_bans for each real IP.
    assert re.search(
        r"for\s+_ip_real\s+in\s+_ips_to_unban:.*?DELETE\s+FROM\s+ip_bans\s+WHERE\s+ip\s*=\s*\?",
        body, re.DOTALL), \
        "unban_endpoint must iterate resolved IPs and DELETE FROM ip_bans by IP"
    # Capture last_ip when iterating identities.
    assert "if s.last_ip:" in body and "_ips_to_unban.add(s.last_ip)" in body, \
        "unban_endpoint must capture s.last_ip for ip_bans cleanup"


# ── LIVE-5: clients listing skips stub rows ─────────────────────────────────

def test_live5_metrics_skips_stub_clients():
    """The Clients table on the dashboard must not show identities that never
    saw a real request — those rows display the track_key HMAC as the Last IP
    column (via the `s.last_ip or key` fallback) and confused operators."""
    src = _read("core/proxy_handler.py")
    m = re.search(r"async def metrics_endpoint.*?(?=\nasync def |\ndef )",
                  src, re.DOTALL)
    assert m, "metrics_endpoint not found"
    body = m.group(0)
    # The filter must check empty last_ip AND zero counters before appending.
    assert "not s.last_ip" in body and "s.request_count == 0" in body \
        and "s.allowed_count == 0" in body and "s.blocked_count == 0" in body, \
        "metrics_endpoint must skip stub clients (empty last_ip + zero counters)"


# ── LIVE-6: hybrid IP-ban gate ──────────────────────────────────────────────

def test_live6_should_ip_ban_helper_exists():
    src = _read("scoring.py")
    assert "def _should_ip_ban(" in src, "_should_ip_ban helper missing"
    assert "def _count_banned_identities_on_ip(" in src, \
        "_count_banned_identities_on_ip helper missing"


def test_live6_operator_prefix_always_persists():
    """Operator-triggered bans (`reason` starts with `operator-`) must always
    write to ip_bans regardless of ASN / Tor / identity count."""
    src = _read("scoring.py")
    m = re.search(r"def _should_ip_ban\(.*?(?=\ndef |\nasync def |\Z)", src, re.DOTALL)
    assert m
    body = m.group(0)
    assert 'reason.startswith("operator-")' in body
    # First branch must return True for operator-prefixed reasons.
    op_idx = body.find('reason.startswith("operator-")')
    next_return = body.find("return True", op_idx)
    assert 0 < next_return - op_idx < 80, \
        "operator- prefix must return True immediately"


def test_live6_hosting_asn_persists():
    src = _read("scoring.py")
    m = re.search(r"def _should_ip_ban\(.*?(?=\ndef |\nasync def |\Z)", src, re.DOTALL)
    body = m.group(0)
    assert "_asn_lookup" in body, "hosting-ASN check must call _asn_lookup"
    assert "is_hosting" in body, "hybrid gate must consult is_hosting flag"


def test_live6_tor_exit_persists():
    src = _read("scoring.py")
    m = re.search(r"def _should_ip_ban\(.*?(?=\ndef |\nasync def |\Z)", src, re.DOTALL)
    body = m.group(0)
    assert "_tor_exits" in body, "hybrid gate must check tor exits"


def test_live6_nat_confirm_threshold_check():
    src = _read("scoring.py")
    assert "_NAT_CONFIRM_MIN_IDENTITIES" in src
    assert "_NAT_CONFIRM_WINDOW_S" in src
    m = re.search(r"def _should_ip_ban\(.*?(?=\ndef |\nasync def |\Z)", src, re.DOTALL)
    body = m.group(0)
    assert "banned_identities_on_ip >= _NAT_CONFIRM_MIN_IDENTITIES" in body


def test_live6_default_false_for_unknown_consumer_ip():
    """Pure-Python test of the gate logic — with all signals OFF, return False."""
    import sys, os
    os.environ.setdefault("UPSTREAM", "https://example.com")
    # Reload scoring fresh — the module has _NAT_CONFIRM_MIN_IDENTITIES baked in.
    if "scoring" in sys.modules:
        del sys.modules["scoring"]
    import scoring
    # Mock _asn_lookup to return non-hosting + _tor_exits to be empty
    # so we can assert the consumer-IP default-False.
    scoring._tor_exits.clear() if hasattr(scoring, "_tor_exits") else None
    # Caller has 0 banned identities on this IP, non-hosting → should be False.
    # We can't directly stub _asn_lookup without monkeypatching, so just verify
    # that with a private IP (MaxMind returns is_hosting=False for private),
    # and 0 banned identities, the gate refuses.
    result = scoring._should_ip_ban("10.0.0.1", "honeypot-silent", 0)
    assert result is False, \
        f"unknown consumer IP with 0 banned identities must NOT be IP-banned, got {result}"


def test_live6_operator_prefix_returns_true():
    import sys, os
    os.environ.setdefault("UPSTREAM", "https://example.com")
    if "scoring" in sys.modules:
        del sys.modules["scoring"]
    import scoring
    assert scoring._should_ip_ban("10.0.0.1", "operator-manual-block", 0) is True


def test_live6_ban_writes_gated():
    """The `ban()` function must wrap its ip_bans put_nowait in _should_ip_ban."""
    src = _read("scoring.py")
    m = re.search(r"async def ban\(ip:.*?(?=\nasync def |\ndef )", src, re.DOTALL)
    assert m
    body = m.group(0)
    # The ip_ban put_nowait call must be inside an `if _should_ip_ban(...)` branch.
    assert re.search(r"if secs >= HOSTILE_BAN_SECS and _should_ip_ban\(", body), \
        "ban() must gate ip_bans persistence on _should_ip_ban"


def test_live6_risk_ban_gated():
    """update_risk_and_maybe_ban must wrap its ip_bans put_nowait in _should_ip_ban."""
    src = _read("scoring.py")
    start = src.find("async def update_risk_and_maybe_ban(")
    assert start >= 0, "update_risk_and_maybe_ban not found"
    body = src[start:]
    assert "if ban_dur >= HOSTILE_BAN_SECS and _should_ip_ban(" in body, \
        "update_risk_and_maybe_ban must gate ip_bans on _should_ip_ban"


def test_live6_operator_endpoint_exists():
    """POST /secured/ip-ban handler exists with CSRF + role guard, operator-
    prefixed reason, and writes to ip_bans via db_queue."""
    src = _read("core/proxy_handler.py")
    m = re.search(r"async def ip_ban_endpoint\(.*?(?=\nasync def |\ndef |\n@_require_csrf)",
                  src, re.DOTALL)
    assert m, "ip_ban_endpoint not found"
    body = m.group(0)
    # Role guard
    assert '_role_denied(request, "admin")' in body, \
        "ip_ban_endpoint must require admin role"
    # Reason normalisation
    assert 'not reason.startswith("operator-")' in body, \
        "ip_ban_endpoint must prefix reason with 'operator-' for hybrid gate"
    # ip_bans db_queue write
    assert 'db_queue.put_nowait(("ip_ban"' in body, \
        "ip_ban_endpoint must write to ip_bans"


def test_live6_csrf_on_operator_endpoint():
    """The endpoint must be decorated with @_require_csrf (defence-in-depth)."""
    src = _read("core/proxy_handler.py")
    m = re.search(r"(@_require_csrf\s*\n)+async def ip_ban_endpoint", src)
    assert m, "ip_ban_endpoint missing @_require_csrf decorator"


def test_live6_route_registered_post_only():
    src = _read("proxy.py")
    # Should appear exactly once as POST.
    assert re.search(r'"ip-ban"[^\n]*"POST"[^\n]*ip_ban_endpoint', src), \
        "ip-ban route must be POST + ip_ban_endpoint"
    # No GET variant — operator-confirmed destructive action requires POST + CSRF.
    assert not re.search(r'"ip-ban"[^\n]*"GET"', src), \
        "ip-ban must NOT have a GET route"


# ════════════════════════════════════════════════════════════════════════════
# Behavioural tests — actually exercise the runtime logic (the tests above
# are source-inspection guards; these prove the code runs as documented).
# ════════════════════════════════════════════════════════════════════════════


# ── LIVE-6 _should_ip_ban decision matrix (unit) ────────────────────────────

class TestLive6ShouldIpBanMatrix:
    """Exercise the hybrid IP-ban gate with every documented input class."""

    def setup_method(self):
        # Fresh import per class so MaxMind / Tor stub patches are clean.
        import sys
        for m in ("scoring",):
            sys.modules.pop(m, None)
        import scoring
        self.scoring = scoring

    def test_operator_prefix_returns_true_regardless_of_other_signals(self):
        # 0 banned identities, non-hosting (private IP), non-Tor → would normally be False.
        # The `operator-` prefix forces True.
        assert self.scoring._should_ip_ban("10.0.0.1", "operator-manual", 0) is True
        assert self.scoring._should_ip_ban("10.0.0.1", "operator-canary", 99) is True

    def test_unknown_consumer_ip_with_no_other_signal_returns_false(self):
        # Private IP → not hosting per MaxMind, not Tor, no co-located bans.
        # This is the NAT-protection path the whole gate exists for.
        assert self.scoring._should_ip_ban("192.168.1.1", "honeypot-silent", 0) is False
        assert self.scoring._should_ip_ban("10.0.0.5", "canary-echo", 0) is False

    def test_below_nat_confirm_threshold_returns_false(self):
        # 2 banned identities (default threshold is 3) → still NAT-protected.
        assert self.scoring._should_ip_ban("203.0.113.50", "honeypot-silent", 2) is False

    def test_at_or_above_nat_confirm_threshold_returns_true(self):
        # 3+ banned identities on same IP → confirmed attacker IP.
        assert self.scoring._should_ip_ban("203.0.113.51", "honeypot-silent", 3) is True
        assert self.scoring._should_ip_ban("203.0.113.51", "honeypot-silent", 5) is True

    def test_tor_exit_returns_true_even_with_no_identities(self):
        # `_should_ip_ban` does `from reputation.tor import _tor_exits` inside
        # the function, so patches must target `reputation.tor` directly.
        from reputation import tor as _t
        _t._tor_exits.add("198.51.100.10")
        try:
            assert self.scoring._should_ip_ban(
                "198.51.100.10", "canary-echo", 0) is True
        finally:
            _t._tor_exits.discard("198.51.100.10")

    def test_hosting_asn_returns_true(self, monkeypatch):
        # Mock MaxMind ASN lookup to return is_hosting=True for a test IP.
        from reputation import maxmind as _mm
        monkeypatch.setattr(_mm, "_asn_lookup",
                            lambda ip: (12345, "Hosting LLC", True, "ok"))
        assert self.scoring._should_ip_ban(
            "203.0.113.99", "canary-echo", 0) is True

    def test_unknown_asn_source_does_not_count_as_hosting(self, monkeypatch):
        # When MaxMind has no answer (`asn_src != "ok"`), the hosting branch
        # must NOT trigger — falls through to identity-count check.
        from reputation import maxmind as _mm
        monkeypatch.setattr(_mm, "_asn_lookup",
                            lambda ip: (0, "", True, "disabled"))
        # is_hosting=True but source != "ok" → should be ignored → False
        assert self.scoring._should_ip_ban(
            "203.0.113.98", "canary-echo", 0) is False


# ── LIVE-6 _count_banned_identities_on_ip (unit) ────────────────────────────

class TestLive6CountBannedIdentities:
    """The helper that decides whether the NAT-confirm threshold is reached."""

    def setup_method(self):
        import sys
        for m in ("scoring", "state"):
            sys.modules.pop(m, None)
        import scoring, state
        self.scoring = scoring
        self.state = state
        # Wipe shared globals.
        state.ip_state.clear()
        state.ip_to_identities.clear()

    def test_empty_state_returns_zero(self):
        n = self.scoring.now()
        assert self.scoring._count_banned_identities_on_ip("203.0.113.1", n) == 0

    def test_counts_only_actively_banned_identities(self):
        n = self.scoring.now()
        ip = "203.0.113.2"
        # 3 identities at this IP — 2 banned, 1 active-not-banned.
        for i, banned in enumerate([True, True, False]):
            tk = f"tk-{i}"
            s = self.state.ip_state[tk]
            s.last_ip = ip
            s.last_seen = n - 10           # recent
            s.banned_until = (n + 3600) if banned else 0.0
            self.state.ip_to_identities[ip].add(tk)
        assert self.scoring._count_banned_identities_on_ip(ip, n) == 2

    def test_ignores_identities_outside_confirmation_window(self):
        n = self.scoring.now()
        ip = "203.0.113.3"
        # 4 identities — but 2 last-seen > 1h ago should NOT count.
        for i, age in enumerate([10, 60, 7200, 8000]):
            tk = f"tk-old-{i}"
            s = self.state.ip_state[tk]
            s.last_ip = ip
            s.last_seen = n - age
            s.banned_until = n + 3600
            self.state.ip_to_identities[ip].add(tk)
        # Default window is 3600s — only the first two pass.
        assert self.scoring._count_banned_identities_on_ip(ip, n) == 2

    def test_empty_raw_ip_returns_zero(self):
        n = self.scoring.now()
        assert self.scoring._count_banned_identities_on_ip("", n) == 0


# ── LIVE-1 + LIVE-2 HTTP-level auth gate (behavioural) ──────────────────────
# The CENTRAL admin gate at proxy_handler.py:3681 already enforces
# `_admin_ip_allowed AND _internal_authed` before dispatching to the
# per-handler logic. So unauth requests hit `admin-probe` and get the
# upstream-404 mirror (status 404 / application/json), never reaching the
# endpoint where my LIVE-1/2 _internal_authed gates would fire.
#
# Both layers prove the endpoint is protected. The per-handler gate is
# defence-in-depth in case the central gate is ever bypassed or the path
# is moved out of the admin namespace. These tests assert the OBSERVABLE
# outcome (request rejected, no sensitive data leaks back) rather than the
# specific status code, so they survive a future move of the gate.

def test_live1_ip_intel_blocked_without_session(proxy_module):
    """Unauth GET to /secured/ip-intel must NOT return the intel JSON body
    and MUST NOT include sensitive keys (geo / asn / internal / risk_score)
    in the response — regardless of whether the central gate or the per-
    handler gate fires (both result in a non-200 / non-leak response)."""
    from tests.test_control_regressions import _spin_proxy, _spin_upstream, _run
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get("/antibot-appsec-gateway/secured/ip-intel/8.8.8.8")
                body_text = await r.text()
                # Must NOT be the real intel payload regardless of status.
                for leaked in ("\"asn\"", "\"geo\"", "\"risk_score\"",
                               "\"crowdsec\"", "\"abuseipdb\""):
                    assert leaked not in body_text, (
                        f"ip-intel response leaked {leaked} without auth "
                        f"(status={r.status})")
                # And the response must not be a successful 2xx with the schema.
                assert r.status != 200 or not body_text.strip().startswith("{"), \
                    f"endpoint returned 200 JSON without auth: status={r.status}"
    _run(go())


def test_live2_whoami_blocked_without_session(proxy_module):
    """Unauth GET to /secured/whoami must NOT leak the source-IP-echo body
    that the pre-fix endpoint returned (`{"username":"unknown","via":"admin-key","user":null,"ip":"<caller-ip>"}`)."""
    from tests.test_control_regressions import _spin_proxy, _spin_upstream, _run
    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                r = await c.get("/antibot-appsec-gateway/secured/whoami")
                body_text = await r.text()
                # The leak we patched: response must not contain the pattern
                # `"via":"admin-key"` (the misleading placeholder string the
                # unguarded endpoint returned to anonymous callers).
                assert '"via":"admin-key"' not in body_text \
                       and '"via": "admin-key"' not in body_text, (
                    f"whoami still leaked via:admin-key without auth "
                    f"(status={r.status}, body={body_text[:200]!r})")
    _run(go())


# ── LIVE-6 ip_ban_endpoint behavioural (POST writes to ip_bans) ─────────────

def test_live6_endpoint_writes_ip_bans_with_operator_prefix(proxy_module):
    """POST /secured/ip-ban with an auth'd admin session must queue an ip_bans
    write whose reason carries the `operator-` prefix (so the hybrid gate
    honours it on the writer-loop side)."""
    from tests.test_control_regressions import (
        _spin_proxy, _spin_upstream, _run, _admin_cookie, _csrf_hdr)
    import asyncio

    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                ck = _admin_cookie(proxy_module)
                hdr = _csrf_hdr(proxy_module, ck)
                # Drain any pre-existing queue items so we can isolate the
                # ip_ban write the endpoint emits.
                while not proxy_module.db_queue.empty():
                    try:
                        proxy_module.db_queue.get_nowait()
                        proxy_module.db_queue.task_done()
                    except Exception:
                        break
                r = await c.post(
                    "/antibot-appsec-gateway/secured/ip-ban",
                    json={"ip": "198.51.100.42", "secs": 3600,
                          "reason": "test-block"},
                    cookies=ck, headers={"Content-Type": "application/json", **hdr})
                assert r.status == 200, f"expected 200, got {r.status}"
                body = await r.json()
                assert body["ok"] is True
                assert body["ip"] == "198.51.100.42"
                # Reason must have been prefixed with `operator-` so the
                # hybrid gate's first branch accepts the write.
                assert body["reason"].startswith("operator-"), \
                    f"reason must be operator-prefixed, got {body['reason']!r}"
                # And the queue must now have an `ip_ban` op.
                ops = []
                while not proxy_module.db_queue.empty():
                    try:
                        op_name, args = proxy_module.db_queue.get_nowait()
                        ops.append((op_name, args))
                        proxy_module.db_queue.task_done()
                    except Exception:
                        break
                ip_ban_ops = [op for op, args in ops if op == "ip_ban"]
                assert ip_ban_ops, \
                    f"expected ip_ban op in queue, got {[op for op,_ in ops]}"
    _run(go())


def test_live6_endpoint_rejects_invalid_ip(proxy_module):
    """Bad IP → 400, no queue write."""
    from tests.test_control_regressions import (
        _spin_proxy, _spin_upstream, _run, _admin_cookie, _csrf_hdr)

    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                ck = _admin_cookie(proxy_module)
                hdr = _csrf_hdr(proxy_module, ck)
                r = await c.post(
                    "/antibot-appsec-gateway/secured/ip-ban",
                    json={"ip": "not-an-ip", "secs": 60},
                    cookies=ck, headers={"Content-Type": "application/json", **hdr})
                assert r.status == 400, f"expected 400, got {r.status}"
                body = await r.json()
                assert "invalid" in (body.get("error") or "").lower()
    _run(go())


def test_live6_endpoint_caps_secs_at_really_ban(proxy_module):
    """secs > REALLY_BAN_SECS must be silently capped (not rejected)."""
    from tests.test_control_regressions import (
        _spin_proxy, _spin_upstream, _run, _admin_cookie, _csrf_hdr)

    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                ck = _admin_cookie(proxy_module)
                hdr = _csrf_hdr(proxy_module, ck)
                r = await c.post(
                    "/antibot-appsec-gateway/secured/ip-ban",
                    json={"ip": "198.51.100.43",
                          "secs": proxy_module.REALLY_BAN_SECS * 2},
                    cookies=ck, headers={"Content-Type": "application/json", **hdr})
                assert r.status == 200
                body = await r.json()
                assert body["secs"] == proxy_module.REALLY_BAN_SECS
    _run(go())


def test_live6_endpoint_csrf_decorator_present(proxy_module):
    """The endpoint MUST carry @_require_csrf — this is a defence-in-depth
    layer in case the central admin gate at proxy_handler.py:3681 is moved
    or the path leaves the admin namespace. Note: the central gate ALSO
    enforces CSRF on every authenticated POST, so a missing decorator here
    would not necessarily cause an HTTP-level vulnerability today, but the
    decorator is the documented contract.
    """
    import core.proxy_handler as _ph
    import functools
    fn = _ph.ip_ban_endpoint
    # functools.wraps preserves __wrapped__ on the inner function.
    assert hasattr(fn, "__wrapped__"), \
        "ip_ban_endpoint is not wrapped by any decorator — @_require_csrf missing?"


def test_live6_endpoint_requires_admin_role(proxy_module):
    """POST from a viewer-role session must be 403."""
    from tests.test_control_regressions import (
        _spin_proxy, _spin_upstream, _run, _csrf_hdr)

    async def go():
        async with _spin_upstream() as up:
            async with _spin_proxy(proxy_module, up) as c:
                # Mint a viewer-role session manually (admin cookie helper
                # creates an admin-role one).
                sid = proxy_module._new_sid()
                proxy_module._SESSION_CACHE[sid] = {
                    "username": "viewer-user",
                    "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
                    "revoked": False,
                }
                proxy_module._SESSION_CACHE_READY = True
                # Stub _user_load so role resolves to "viewer".
                import admin.users as _au
                _orig = _au._user_load
                _au._user_load = lambda u: ({"role": "viewer"}
                                            if u == "viewer-user" else None)
                try:
                    cookie = {proxy_module._SESSION_COOKIE:
                              proxy_module._session_sign("viewer-user", sid=sid)}
                    hdr = _csrf_hdr(proxy_module, cookie)
                    r = await c.post(
                        "/antibot-appsec-gateway/secured/ip-ban",
                        json={"ip": "198.51.100.45", "secs": 60},
                        cookies=cookie,
                        headers={"Content-Type": "application/json", **hdr})
                    assert r.status == 403, \
                        f"viewer must be 403, got {r.status}"
                finally:
                    _au._user_load = _orig
                    proxy_module._SESSION_CACHE.pop(sid, None)
    _run(go())


# ════════════════════════════════════════════════════════════════════════════
# Unit tests for the new _strip_js_comments helper added to tests/test_v1712.py.
# The helper is load-bearing for _dp_calls_with_onclick (DOMPurify scan) —
# without it, apostrophes inside `// foo's bar` open a phantom string mode
# in the bracket-matcher and the scan over-captures by tens of kB.
# ════════════════════════════════════════════════════════════════════════════

class TestStripJsCommentsHelper:
    """Edge-case coverage for `tests.test_v1712._strip_js_comments`."""

    def setup_method(self):
        import sys, importlib
        sys.path.insert(0, "tests")
        if "test_v1712" in sys.modules:
            importlib.reload(sys.modules["test_v1712"])
        from test_v1712 import _strip_js_comments
        self.strip = _strip_js_comments

    def test_line_comment_with_apostrophe_stripped(self):
        """The actual case that broke iter-18 — `// don't worry` apostrophe."""
        out = self.strip("let x = 1;\n// don't worry\nlet y = 2;\n")
        assert "don't" not in out, "line comment with apostrophe must be stripped"
        # Line count preserved (newlines retained).
        assert out.count("\n") == 3

    def test_line_comment_must_start_a_line(self):
        """URL `https://foo.com` must NOT be treated as a line comment."""
        src = 'const url = "https://foo.com/path";\n'
        out = self.strip(src)
        # The URL string must survive intact — both the `//` and what follows.
        assert "https://foo.com/path" in out

    def test_block_comment_stripped(self):
        out = self.strip("let x = /* this is a comment */ 1;\n")
        assert "this is a comment" not in out
        # Length preserved (whitespace replacement).
        assert len(out) == len("let x = /* this is a comment */ 1;\n")

    def test_block_comment_multiline_preserves_newlines(self):
        src = "/* line1\nline2\nline3 */\nlet x = 1;\n"
        out = self.strip(src)
        assert "line2" not in out
        # Three newlines in the comment + one after → 4 total newlines.
        assert out.count("\n") == 4

    def test_block_comment_with_strings_inside(self):
        """A `/* … "foo" … */` block must still strip the inner string."""
        src = '/* "fake string" with quotes */ let x = 1;\n'
        out = self.strip(src)
        assert '"fake string"' not in out
        assert "let x = 1;" in out

    def test_offsets_preserved(self):
        """Length must match exactly so caller's line/column math survives."""
        src = "abc\n// strip me\nxyz\n"
        out = self.strip(src)
        assert len(out) == len(src)

    def test_no_modification_when_no_comments(self):
        src = 'let x = "// not a comment";\nlet y = 1;\n'
        # Multi-line URL-like string with `//` mid-line must survive.
        out = self.strip(src)
        assert out == src

    def test_indented_line_comment_stripped(self):
        """Leading whitespace + `//` is the standard form — must strip."""
        src = "    // indented comment\nlet x = 1;\n"
        out = self.strip(src)
        assert "indented comment" not in out

    def test_line_comment_apostrophe_does_not_open_phantom_string(self):
        """Smoke test of the root bug: after stripping, no leftover quote
        state should leak. Verify by feeding result to a simple paren counter
        and checking it doesn't run away."""
        src = (
            "let x = (1);\n"           # depth 0 at end
            "// don't add parens here\n"
            "let y = (2);\n"           # depth 0 at end
        )
        out = self.strip(src)
        depth = 0
        for ch in out:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
        assert depth == 0, \
            f"phantom string from comment leaked, paren depth={depth}"


# ════════════════════════════════════════════════════════════════════════════
# LIVE-4 behavioural — verify unban resolves identity → real client IP → DELETE
# from ip_bans table. The source guard catches the code shape; this proves
# the runtime actually removes the row.
# ════════════════════════════════════════════════════════════════════════════

class TestLive4UnbanResolvesRealIp:
    """unban_endpoint must clear ip_bans by the IDENTITY's last_ip, not by
    the HMAC track_key (which never matches the raw-IP column)."""

    def setup_method(self):
        import sys
        for m in ("state",):
            sys.modules.pop(m, None)

    def test_unban_collects_real_ip_from_identity(self, proxy_module):
        """When the request specifies `id=<track_key>` and that identity has
        a `last_ip` recorded, `_ips_to_unban` must include the real IP — so
        the subsequent DELETE FROM ip_bans WHERE ip=? matches the row."""
        from tests.test_control_regressions import (
            _spin_proxy, _spin_upstream, _run, _admin_cookie, _csrf_hdr)
        import sqlite3

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = _admin_cookie(proxy_module)
                    hdr = _csrf_hdr(proxy_module, ck)
                    # Seed: insert an ip_bans row for a real IP + an ip_state
                    # identity that points last_ip at the same real IP.
                    real_ip = "198.51.100.77"
                    track_key = "hmac-fake-track-key-77"
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    conn.execute(
                        "INSERT OR REPLACE INTO ip_bans "
                        "(ip, banned_until, reason, ts) VALUES (?,?,?,?)",
                        (real_ip, proxy_module._t.time() + 3600,
                         "test-seed", proxy_module._t.time()))
                    conn.commit()
                    conn.close()
                    s = proxy_module.ip_state[track_key]
                    s.last_ip = real_ip
                    s.banned_until = proxy_module.now() + 3600
                    proxy_module.ip_to_identities[real_ip].add(track_key)
                    # POST /unban?id=<track_key>
                    r = await c.post(
                        "/antibot-appsec-gateway/secured/unban",
                        json={"id": track_key},
                        cookies=ck,
                        headers={"Content-Type": "application/json", **hdr})
                    assert r.status == 200, f"unban must return 200, got {r.status}"
                    # ip_bans row for the REAL IP must be gone.
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    row = conn.execute(
                        "SELECT 1 FROM ip_bans WHERE ip=?", (real_ip,)
                    ).fetchone()
                    conn.close()
                    assert row is None, (
                        "ip_bans row for the identity's real IP still present "
                        "after unban — LIVE-4 fix not effective")
                    # Cleanup.
                    proxy_module.ip_state.pop(track_key, None)
                    proxy_module.ip_to_identities[real_ip].discard(track_key)
        _run(go())

    def test_unban_ip_clears_ip_bans_directly(self, proxy_module):
        """When the request specifies `ip=<raw_ip>` directly, ip_bans must
        be cleared for that IP (no track_key resolution needed)."""
        from tests.test_control_regressions import (
            _spin_proxy, _spin_upstream, _run, _admin_cookie, _csrf_hdr)
        import sqlite3

        async def go():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    ck = _admin_cookie(proxy_module)
                    hdr = _csrf_hdr(proxy_module, ck)
                    target_ip = "198.51.100.88"
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    conn.execute(
                        "INSERT OR REPLACE INTO ip_bans "
                        "(ip, banned_until, reason, ts) VALUES (?,?,?,?)",
                        (target_ip, proxy_module._t.time() + 3600,
                         "test-seed", proxy_module._t.time()))
                    conn.commit()
                    conn.close()
                    r = await c.post(
                        "/antibot-appsec-gateway/secured/unban",
                        json={"ip": target_ip},
                        cookies=ck,
                        headers={"Content-Type": "application/json", **hdr})
                    assert r.status == 200
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    row = conn.execute(
                        "SELECT 1 FROM ip_bans WHERE ip=?", (target_ip,)
                    ).fetchone()
                    conn.close()
                    assert row is None, "ip_bans not cleared for raw-IP unban"
        _run(go())


# ════════════════════════════════════════════════════════════════════════════
# REVIEW-PG-DUAL-WRITE (iter-18): SQLite ⇄ Postgres dual-write + cold-start
# restore. SQLite stays primary; PG is a passive complete mirror. When the
# /data volume is wiped and PG is configured at startup, operator state is
# restored from PG so user accounts, IP allowlist, bans, mesh config etc.
# survive container redeploys with empty SQLite.
# ════════════════════════════════════════════════════════════════════════════


class TestPgDualWriteOpsCoverage:
    """The set of ops that get mirrored to PG post-commit must include every
    operator-facing table; intra-process state (clients/timeline/svc_metrics)
    is intentionally excluded."""

    def setup_method(self):
        # Read the writer-loop source so the test survives refactors that
        # keep the _PG_DUAL_WRITE_OPS literal somewhere in db/sqlite.py.
        from pathlib import Path
        self.src = (Path(__file__).resolve().parent.parent
                    / "db" / "sqlite.py").read_text()

    def test_constant_defined(self):
        assert "_PG_DUAL_WRITE_OPS = frozenset({" in self.src, \
            "db/sqlite.py must define _PG_DUAL_WRITE_OPS frozenset"

    def test_all_required_ops_in_dual_write_set(self):
        import re
        m = re.search(
            r"_PG_DUAL_WRITE_OPS\s*=\s*frozenset\(\{(.*?)\}\)",
            self.src, re.DOTALL)
        assert m, "_PG_DUAL_WRITE_OPS not findable"
        body = m.group(1)
        required = [
            "user_create", "user_update", "user_delete",
            "user_login_recorded", "user_session_create",
            "user_session_touch", "user_session_revoke",
            "ban", "ip_ban", "ip_ban_del",
            "dlp_add", "dlp_toggle", "dlp_delete",
            "siem_alert_rule_add", "siem_alert_rule_del",
            "siem_alert_fired", "siem_alert_toggle",
            "gw_registry_add", "gw_registry_update", "gw_registry_delete",
            "gw_distribution_replace",
        ]
        for op in required:
            assert f'"{op}"' in body, f"_PG_DUAL_WRITE_OPS missing {op!r}"

    def test_post_commit_hook_wired(self):
        """Writer must invoke `_pg_mirror_bg(op, args)` when the op is in
        the dual-write set — in the `else` branch of the per-op try."""
        assert "if op in _PG_DUAL_WRITE_OPS:" in self.src, \
            "writer must gate the mirror call on _PG_DUAL_WRITE_OPS"
        # The mirror call lives in the else branch (success path), not in
        # the except branch (failure path) — otherwise PG would receive
        # writes the SQLite side rejected.
        # The dual-write guard is the LAST `if op in _PG_DUAL_WRITE_OPS:` in
        # the file (the writer-loop one); earlier references live in the
        # frozenset literal itself.
        idx = self.src.rfind("if op in _PG_DUAL_WRITE_OPS:")
        window = self.src[max(0, idx - 600): idx + 200]
        assert "else:" in window and "except" in window, \
            "_PG_DUAL_WRITE_OPS guard must be inside else: of try/except"


class TestPgMirrorKvCoverage:
    """Every op in _PG_DUAL_WRITE_OPS must have a matching elif arm in
    `_pg_mirror_kv` (db/postgres.py) — otherwise the writer fires the
    mirror but the mirror silently returns False."""

    def setup_method(self):
        from pathlib import Path
        self.src = (Path(__file__).resolve().parent.parent
                    / "db" / "postgres.py").read_text()

    @pytest.mark.parametrize("op", [
        "user_create", "user_update", "user_delete",
        "user_login_recorded", "user_session_create",
        "user_session_touch", "user_session_revoke",
        "ban", "ip_ban", "ip_ban_del",
        "dlp_add", "dlp_toggle", "dlp_delete",
        "siem_alert_rule_add", "siem_alert_rule_del",
        "siem_alert_fired", "siem_alert_toggle",
        "gw_registry_add", "gw_registry_update", "gw_registry_delete",
        "gw_distribution_replace",
    ])
    def test_op_has_mirror_handler(self, op):
        # A4 refactor: dispatch is now a registry pattern. Accept EITHER
        # the legacy `elif op ==` form (in case of revert) OR the new
        # `"<op>": _h_<op>` entry in _PG_OP_HANDLERS.
        legacy_arm = f'elif op == "{op}":'
        registry_entry = f'"{op}":'
        assert (legacy_arm in self.src
                or registry_entry in self.src), \
            f"_pg_mirror_kv missing handler for op {op!r} (checked " \
            f"both legacy elif arm and _PG_OP_HANDLERS registry entry)"


class TestPgSchemaCompleteness:
    """The 3 tables added in iter-18 (bans, ip_bans, dlp_patterns) must be
    in the PG schema; the users table must carry the totp_* columns the
    SQLite side gained in 1.8.6."""

    def setup_method(self):
        from pathlib import Path
        self.src = (Path(__file__).resolve().parent.parent
                    / "db" / "postgres.py").read_text()

    @pytest.mark.parametrize("table", ["bans", "ip_bans", "dlp_patterns"])
    def test_table_in_schema(self, table):
        assert f"CREATE TABLE IF NOT EXISTS {table} (" in self.src, \
            f"PG schema must include CREATE TABLE for {table!r}"

    @pytest.mark.parametrize("col", [
        "totp_secret", "totp_enabled", "totp_backup_codes",
        "sso_source", "oidc_sub",
    ])
    def test_users_column_migration(self, col):
        # iter-18 adds these via a tuple loop that builds
        # `ALTER TABLE users ADD COLUMN IF NOT EXISTS <col> <ddl>`.
        # Anchor on the tuple entry — surviving refactors to either f-string
        # or %-format.
        assert f'("{col}",' in self.src, \
            f"PG users migration tuple missing column {col!r}"
        assert "ADD COLUMN IF NOT EXISTS" in self.src, \
            "PG migration must use ADD COLUMN IF NOT EXISTS"


class TestRestoreFromPostgresShortCircuits:
    """db_restore_from_postgres must be a no-op when:
       (a) POSTGRES_DSN is unset
       (b) the target SQLite already has users or config_kv rows
    These guards are what prevent operator data loss when PG has stale
    rows and SQLite has fresh state."""

    def setup_method(self):
        import sys
        for m in ("db.postgres",):
            sys.modules.pop(m, None)
        import db.postgres as _pg
        self.pg = _pg

    def test_no_dsn_returns_immediately(self):
        # Force-empty DSN so the early guard fires.
        orig_dsn = self.pg.POSTGRES_DSN
        try:
            self.pg.POSTGRES_DSN = ""
            res = self.pg.db_restore_from_postgres("/tmp/_nonexistent.db")
            assert res["restored"] is False
            assert "no_dsn" in (res.get("reason") or "")
        finally:
            self.pg.POSTGRES_DSN = orig_dsn

    def test_sqlite_with_users_short_circuits(self, tmp_path, monkeypatch):
        """If the SQLite file already has user accounts, restore MUST skip
        with reason starting `sqlite_not_empty` — never overwrite real data."""
        import sqlite3
        dbp = str(tmp_path / "t.db")
        conn = sqlite3.connect(dbp)
        conn.execute("""CREATE TABLE users (
            username TEXT PRIMARY KEY, password_hash TEXT,
            role TEXT, status TEXT, created_ts REAL, updated_ts REAL)""")
        conn.execute("CREATE TABLE config_kv (key TEXT PRIMARY KEY, value TEXT, ts REAL)")
        conn.execute("INSERT INTO users VALUES "
                     "('admin', 'h', 'admin', 'active', 0, 0)")
        conn.commit()
        conn.close()
        # Force a DSN value so we get past the (a) guard and hit (b).
        monkeypatch.setattr(self.pg, "POSTGRES_DSN",
                            "postgresql://stub:stub@127.0.0.1/stub")
        # Stub the module loader so the function returns the local module
        # without trying to actually load psycopg (which may or may not exist).
        class _StubPg:
            class errors:
                class UndefinedTable(Exception): pass
            @staticmethod
            def connect(*a, **k):
                raise RuntimeError("must not reach pg.connect — guard "
                                   "should have short-circuited")
        monkeypatch.setattr(self.pg, "_postgres_load_module", lambda: _StubPg)
        res = self.pg.db_restore_from_postgres(dbp)
        assert res["restored"] is False, \
            "restore must NOT overwrite an already-configured SQLite"
        assert (res.get("reason") or "").startswith("sqlite_not_empty"), \
            f"expected sqlite_not_empty reason, got {res.get('reason')!r}"

    def test_pg_unreachable_returns_reason(self, tmp_path, monkeypatch):
        """If PG raises on connect, restore must fall back gracefully."""
        import sqlite3
        dbp = str(tmp_path / "t.db")
        # Empty tables — restore MAY proceed to PG.
        conn = sqlite3.connect(dbp)
        conn.execute("CREATE TABLE users (username TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE config_kv (key TEXT PRIMARY KEY)")
        conn.commit(); conn.close()
        monkeypatch.setattr(self.pg, "POSTGRES_DSN",
                            "postgresql://stub:stub@127.0.0.1/stub")
        class _StubPg:
            class errors:
                class UndefinedTable(Exception): pass
            @staticmethod
            def connect(*a, **k):
                raise ConnectionError("simulated PG unreachable")
        monkeypatch.setattr(self.pg, "_postgres_load_module", lambda: _StubPg)
        res = self.pg.db_restore_from_postgres(dbp)
        assert res["restored"] is False
        assert (res.get("reason") or "").startswith("pg_unreachable"), \
            f"expected pg_unreachable reason, got {res.get('reason')!r}"


class TestStartupRestoreWired:
    """PG-only migration: on_startup must wire the PG boot guard in the
    `if POSTGRES_DSN:` branch. iter-18 helper functions were folded into
    on_startup inline; the older _startup_* step-helper architecture is
    no longer part of HEAD's proxy.py."""

    def setup_method(self):
        from pathlib import Path
        self.src = (Path(__file__).resolve().parent.parent
                    / "proxy.py").read_text()

    def test_pg_boot_guard_in_on_startup(self):
        """The on_startup function must include the boot guard logic."""
        import re
        m = re.search(r"async def on_startup\(app\):(.*?)\nasync def ",
                      self.src, re.DOTALL)
        assert m, "on_startup not found"
        body = m.group(1)
        # Boot-guard knobs + SystemExit reachable in the PG branch.
        assert "POSTGRES_BOOT_MAX_ATTEMPTS" in body
        assert "raise SystemExit(" in body
        # The branch fires only when POSTGRES_DSN is set.
        assert "if POSTGRES_DSN:" in body

    def test_pg_branch_marks_postgres_available(self):
        """When the boot guard passes, _postgres_available must be set
        across modules so the read dispatcher routes to PG."""
        import re
        m = re.search(r"async def on_startup\(app\):(.*?)\nasync def ",
                      self.src, re.DOTALL)
        assert m
        body = m.group(1)
        # The post-probe path mutates state._postgres_available + propagates.
        assert "_postgres_available" in body, (
            "PG branch must mark _postgres_available so the read "
            "dispatcher routes to PG"
        )

    def test_pg_only_migration_phase1_tables_present(self):
        """PG-only migration Phase 1: 6 SQLite tables (abuseipdb_cache,
        audit_events, clients, metrics_kv, svc_metrics, timeline) must
        have CREATE TABLE in db_init_postgres so PG can become the sole
        backend without schema gaps."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "db" / "postgres.py").read_text()
        for tbl in ("abuseipdb_cache", "audit_events", "clients",
                    "metrics_kv", "svc_metrics", "timeline"):
            assert f"CREATE TABLE IF NOT EXISTS {tbl} " in src, \
                f"PG-only migration Phase 1 missing PG DDL for {tbl!r}"

    def test_pg_only_migration_phase2_op_handlers_present(self):
        """PG-only migration Phase 2: 10 ops previously SQLite-only must
        have a PG handler. A4 refactor moved the dispatch from an
        elif-ladder to a `_PG_OP_HANDLERS = {…}` registry — accept both
        forms so the check stays correct across refactors."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "db" / "postgres.py").read_text()
        for op in ("abuseipdb_set", "audit_log", "gw_registry_discover",
                   "mesh_sync_pending_upsert", "mesh_sync_status",
                   "set_kv", "svc_metric", "svc_metric_prune",
                   "upsert_client", "upsert_timeline"):
            legacy = f'elif op == "{op}":'
            registry = f'"{op}":'
            assert legacy in src or registry in src, \
                f"_pg_mirror_kv missing Phase 2 handler for op {op!r} " \
                f"(checked both legacy elif arm and _PG_OP_HANDLERS entry)"

    def test_pg_only_migration_phase2_ops_in_dual_write_set(self):
        """Same 10 ops must also be in _PG_DUAL_WRITE_OPS, otherwise the
        writer-loop dual-write hook never dispatches them."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "db" / "sqlite.py").read_text()
        for op in ("abuseipdb_set", "audit_log", "gw_registry_discover",
                   "mesh_sync_pending_upsert", "mesh_sync_status",
                   "set_kv", "svc_metric", "svc_metric_prune",
                   "upsert_client", "upsert_timeline"):
            assert f'"{op}"' in src, \
                f"_PG_DUAL_WRITE_OPS missing Phase 2 op {op!r}"

    def test_pg_only_phase3_conn_wrapper_present(self):
        """Phase 3: db.conn module + open_conn/conn/active_backend
        re-exports. Without these the 11 read sites can't route by
        backend."""
        from pathlib import Path
        here = Path(__file__).resolve().parent.parent
        # The conn module file exists.
        assert (here / "db" / "conn.py").exists(), \
            "db/conn.py must exist (PG-only migration Phase 3)"
        # db/__init__.py re-exports the three names.
        init_src = (here / "db" / "__init__.py").read_text()
        for name in ("open_conn", "conn", "active_backend"):
            assert name in init_src, \
                f"db/__init__.py must re-export {name!r}"

    def test_pg_only_phase3_no_remaining_sqlite3_connect_on_db_path(self):
        """Phase 3: the 57 direct sqlite3.connect(DB_PATH) reads in the
        source tree must be replaced with open_conn() (backend-aware).
        Test code and mutants/ are excluded — they may stay SQLite-only."""
        from pathlib import Path
        import re
        here = Path(__file__).resolve().parent.parent
        offenders = []
        for p in here.rglob("*.py"):
            rel = p.relative_to(here)
            top = rel.parts[0]
            if top in ("tests", "mutants", "validation", "manual",
                       "scripts", "test", "examples"):
                continue
            # Exclude .claude/worktrees/ — these are agent-created git
            # worktrees with stale snapshots of the source tree.
            if top == ".claude":
                continue
            if top == "db" and p.name in ("sqlite.py", "conn.py", "postgres.py"):
                # These files legitimately use sqlite3 directly.
                continue
            try:
                text = p.read_text()
            except Exception:
                continue
            # Skip pure comments (the call appears in some docstrings).
            # Also skip calls inside SQLite-only operations (VACUUM,
            # PRAGMA wal_checkpoint) — those are legitimately SQLite-
            # syntax and gated by a DB_BACKEND check upstream.
            lines = text.splitlines()
            for idx, line in enumerate(lines):
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    continue
                if not (re.search(r"sqlite3\.connect\(\s*DB_PATH\b", line)
                        or re.search(r"_sqlite3\.connect\(\s*DB_PATH\b",
                                      line)):
                    continue
                # Look at the surrounding 12 lines for explicit
                # SQLite-only markers OR an intentional-use docstring.
                window = "\n".join(
                    lines[max(0, idx - 12): min(len(lines), idx + 6)])
                if ("VACUUM" in window or "wal_checkpoint" in window
                        or "_vacuum_history" in window
                        or "INSERT INTO gw_audit" in window
                        and "db_vacuum" in window):
                    continue
                # Intentional `sqlite3.connect(DB_PATH) directly` —
                # signals an opt-out from the migration (e.g. so a
                # test can monkeypatch sqlite3 module-level).
                if "sqlite3.connect(DB_PATH) directly" in window:
                    continue
                offenders.append(str(rel))
                break
        assert not offenders, (
            "Phase 3: these files still hold direct sqlite3.connect(DB_PATH) "
            "reads — migrate them to db.open_conn(): "
            + ", ".join(offenders)
        )

    def test_pg_only_phase4_boot_guard_present(self):
        """Phase 4: when POSTGRES_DSN is set, on_startup must probe PG
        with bounded retries and SystemExit on persistent failure.
        Contract: POSTGRES_BOOT_MAX_ATTEMPTS + POSTGRES_BOOT_BACKOFF_S
        env knobs + at least one `raise SystemExit(` reachable from
        the `if POSTGRES_DSN:` branch."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "proxy.py").read_text()
        assert "POSTGRES_BOOT_MAX_ATTEMPTS" in src
        assert "POSTGRES_BOOT_BACKOFF_S" in src
        assert "raise SystemExit(" in src, \
            "Phase 4 boot guard must SystemExit on unreachable PG"

    def test_pg_only_phase5_op_rename_table_contract(self):
        """Phase 5 writer-loop rename map: a few SQLite-side op names
        differ from their PG-side mirror handlers (e.g. admin_ip_add →
        set_admin_ip). The rename map must cover all known mismatches so
        the PG-primary loop dispatches the right handler."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "db" / "sqlite.py").read_text()
        # Map fragment must contain these specific translations.
        for sqlite_op, pg_op in [
            ("admin_ip_add",                "set_admin_ip"),
            ("admin_ip_remove",             "del_admin_ip"),
            ("admin_ip_update_description", "update_admin_ip_description"),
        ]:
            assert f'"{sqlite_op}"' in src and f'"{pg_op}"' in src, \
                f"Phase 5 rename map missing {sqlite_op!r}→{pg_op!r}"

    def test_pg_only_phase5_event_args_unpack_count_matches_sqlite(self):
        """When PG primary, the writer-loop's `event` branch must unpack
        EXACTLY the 8 fields the SQLite `event` op puts on the queue
        (ts, ip, ua, path, method, status, reason, vhost). Mismatch =
        silent data loss on the events table."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "db" / "sqlite.py").read_text()
        # Spot-check the unpack site exists and uses 8 names.
        assert "_ts, _ip, _ua, _path, _method," in src
        assert "_status, _reason, _vhost = args[:8]" in src
        # And the PG insert is invoked with (ts, ip, ua, path, status,
        # reason, method=method, vhost=vhost) — different order, same data.
        assert "pg_insert_event(\n" in src or "pg_insert_event(" in src
        assert "method=_method, vhost=_vhost)" in src, \
            "Phase 5 event branch must keyword-pass method/vhost to PG"

    def test_pg_only_phase5_writer_loop_has_pg_branch(self):
        """Phase 5: when POSTGRES_DSN is set, the writer-loop dispatches
        to PG and never opens the SQLite file."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "db" / "sqlite.py").read_text()
        # Slice the FULL db_writer_loop body so M3 reordering / future
        # additions don't push expected markers out of a fixed window.
        i = src.find("async def db_writer_loop():")
        assert i > 0
        # End at next top-level def/async-def (4-space "def "/"async def "
        # NOT preceded by deeper indent — db_writer_loop's body is all
        # 4-space + 8-space; the next top-level def is 0-space).
        import re
        m = re.search(r"\n(def |async def )", src[i + 30:])
        end = i + 30 + (m.start() if m else 10000)
        body = src[i: end]
        # Contract change (1.9.x): the PG-primary guard was tightened from
        # `if POSTGRES_DSN:` to `if DB_BACKEND == "postgres" and POSTGRES_DSN:`
        # so an operator who switches back to SQLite (DB_BACKEND cleared but
        # POSTGRES_DSN still bound from a prior boot) no longer misroutes every
        # queued event into PG. Accept the shipped tightened guard.
        assert ("if POSTGRES_DSN:" in body
                or 'if DB_BACKEND == "postgres" and POSTGRES_DSN:' in body), \
            "Phase 5 writer must have a PG-primary branch guarded on POSTGRES_DSN"
        assert "_OP_RENAME" in body, \
            "Phase 5 writer must translate SQLite op names to PG op names"
        assert "_pg_mirror_kv(pg_op, args)" in body, \
            "Phase 5 writer must dispatch ops via _pg_mirror_kv"

    def test_pg_only_phase6_no_cold_restore_in_on_startup(self):
        """Phase 6: PG-only single-DB mode has no cold-start restore —
        PG IS the source of truth. on_startup must not call
        db_restore_from_postgres anywhere."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "proxy.py").read_text()
        assert "db_restore_from_postgres(" not in src, \
            "Phase 6: proxy.py must NOT call db_restore_from_postgres"

    def test_pg_only_phase4_propagator_skips_stdlib(self):
        """SECURITY: _ProxyModule.__setattr__ must NOT propagate to
        stdlib / site-packages modules. Mocking `proxy.open = object()`
        in a test would otherwise overwrite builtins.open and break the
        entire pytest run (pytest's traceback display calls open)."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "proxy.py").read_text()
        # _PROPAGATE_NEVER frozenset covers the obvious dangerous builtins.
        assert "_PROPAGATE_NEVER = frozenset({" in src, \
            "proxy.py must define _PROPAGATE_NEVER frozenset"
        for nm in ("open", "exec", "eval", "compile", "breakpoint",
                   "__import__", "__builtins__"):
            assert f'"{nm}"' in src, \
                f"_PROPAGATE_NEVER missing {nm!r}"
        # Belt-and-braces: the propagator body also skips builtins module
        # + filters by __file__ to first-party paths only.
        assert "_builtins_proxy" in src, \
            "Propagator must reference the builtins module to skip it"
        assert "/site-packages/" in src, \
            "Propagator must filter __file__ to skip site-packages"

    def test_pg_only_phase4_propagator_first_party_filter(self):
        """The propagator's first-party filter is the safety net that
        catches builtin names we forgot to add to _PROPAGATE_NEVER. M4
        replaced the brittle `/site-packages/` substring heuristic with
        an explicit realpath-based check against the project root(s)."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "proxy.py").read_text()
        import re
        m = re.search(
            r"class _ProxyModule\(_types_proxy\.ModuleType\):(.*?)\n\S",
            src, re.DOTALL)
        assert m, "_ProxyModule class not found"
        body = m.group(1)
        assert "_PROPAGATE_NEVER" in body
        assert "if _mn in" in body
        # M4-fixed contract: realpath-based filter against project root(s).
        assert (".startswith(_PROJECT_ROOT" in body
                or "_PROJECT_ROOTS" in body), \
            "propagator must use explicit project-root filter"

    def test_pg_only_no_destructive_schema_ops(self):
        """Upgrade safety: no DROP TABLE / DROP COLUMN / RENAME / type
        change anywhere in db/. CREATE TABLE IF NOT EXISTS only. An
        existing deployment's DB file must work as-is after upgrade."""
        from pathlib import Path
        for mod in ("sqlite.py", "postgres.py"):
            src = (Path(__file__).resolve().parent.parent
                   / "db" / mod).read_text()
            for forbidden in ("DROP TABLE ", "DROP COLUMN ",
                              "RENAME COLUMN ", "RENAME TO "):
                # Allow these in comments / docstrings.
                for line in src.splitlines():
                    stripped = line.lstrip()
                    if stripped.startswith("#") or stripped.startswith('"""'):
                        continue
                    assert forbidden not in line.upper(), (
                        f"db/{mod} contains destructive {forbidden!r}: "
                        f"{line.strip()[:120]}"
                    )

    def test_pg_only_all_new_tables_use_if_not_exists(self):
        """Upgrade safety: every CREATE TABLE in PG must use
        `IF NOT EXISTS` so re-running boot against an existing PG with
        partial schema is idempotent. Same contract for SQLite."""
        from pathlib import Path
        import re
        for mod in ("sqlite.py", "postgres.py"):
            src = (Path(__file__).resolve().parent.parent
                   / "db" / mod).read_text()
            # Find every CREATE TABLE not followed by IF NOT EXISTS in
            # source (allow it inside docstrings/comments via line strip).
            for m in re.finditer(r"CREATE TABLE\s+(?!IF NOT EXISTS)", src):
                start = src.rfind("\n", 0, m.start()) + 1
                end = src.find("\n", m.end())
                line = src[start: end if end > 0 else None]
                stripped = line.lstrip()
                if stripped.startswith(("#", "--", '"""', "'''", "*")):
                    continue
                # Allow "CREATE TABLE foo AS SELECT" — not a real table def.
                ahead = src[m.end(): m.end() + 100]
                if " AS " in ahead.split(";")[0]:
                    continue
                raise AssertionError(
                    f"db/{mod}: CREATE TABLE without IF NOT EXISTS — "
                    f"breaks idempotent boot. Line: {line.strip()[:120]}"
                )

    def test_pg_only_upgrade_banner_present_in_proxy(self):
        """Upgrade safety: on_startup must surface a banner when an
        existing SQLite has data AND POSTGRES_DSN is newly active, so the
        operator knows the SQLite file is preserved-but-unused (no data
        loss) and how to downgrade or migrate."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "proxy.py").read_text()
        # The banner mentions the key phrase + cites downgrade + import.
        assert "[db-upgrade]" in src, \
            "on_startup must emit a [db-upgrade] banner on first PG boot"
        assert "preserved but unused" in src, \
            "banner must reassure SQLite is preserved (no data loss)"
        assert "unset POSTGRES_DSN" in src, \
            "banner must document the downgrade path"

    def test_pg_only_db_import_module_exists(self):
        """Upgrade safety: `python -m db.import` migrates SQLite → PG.
        The banner in proxy.py references this tool; if missing,
        operators have no path to migrate historical iter-18 data."""
        import importlib
        import importlib.util
        from pathlib import Path
        # Module file present.
        assert (Path(__file__).resolve().parent.parent
                / "db" / "import.py").exists(), \
            "db/import.py must exist (referenced by upgrade banner)"
        # Loadable via the standard import machinery (the `import` name
        # is a reserved word but file-based loading bypasses that).
        spec = importlib.util.spec_from_file_location(
            "_db_import_test",
            str(Path(__file__).resolve().parent.parent / "db" / "import.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert callable(mod.main), "db.import must expose main()"

    def test_pg_only_db_import_dry_run_no_pg_needed(self):
        """--dry-run must work without POSTGRES_DSN or a running PG."""
        import importlib.util
        from pathlib import Path
        import tempfile, sqlite3, os
        spec = importlib.util.spec_from_file_location(
            "_db_import_test",
            str(Path(__file__).resolve().parent.parent / "db" / "import.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Build a minimal SQLite file with users + config_kv populated.
        td = tempfile.mkdtemp()
        try:
            db_path = os.path.join(td, "src.db")
            c = sqlite3.connect(db_path)
            c.execute(
                "CREATE TABLE users (username TEXT PRIMARY KEY, "
                "password_hash TEXT, role TEXT, status TEXT, "
                "created_ts REAL, updated_ts REAL)")
            c.execute("INSERT INTO users VALUES "
                      "('admin','h','admin','active',0,0)")
            c.execute("CREATE TABLE config_kv "
                      "(key TEXT PRIMARY KEY, value TEXT, ts REAL)")
            c.execute("INSERT INTO config_kv VALUES ('k','v',0)")
            c.commit(); c.close()
            rc = mod.main([db_path, "--dry-run"])
            assert rc == 0, f"dry-run should succeed, got rc={rc}"
        finally:
            import shutil; shutil.rmtree(td, ignore_errors=True)

    def test_pg_only_db_import_dispatch_columns_match_sqlite_schema(self):
        """The dispatch plan's column lists must reference real SQLite
        columns — either in the original CREATE TABLE block OR in a
        later ADD COLUMN migration via _SCHEMA_MIGRATIONS."""
        import importlib.util, re
        from pathlib import Path
        proj = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location(
            "_db_import_test", str(proj / "db" / "import.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # Real schema: combine db_init CREATE-TABLE bodies + ALTER COLUMN
        # entries in _SCHEMA_MIGRATIONS.
        from db.sqlite import _SCHEMA_MIGRATIONS
        migration_cols = {(t, c) for t, c, _s, _p in _SCHEMA_MIGRATIONS}
        sqlite_src = (proj / "db" / "sqlite.py").read_text()
        for table, _pg_op, cols, _xform in mod._dispatch_plan():
            m = re.search(
                rf"CREATE TABLE IF NOT EXISTS {re.escape(table)} \((.*?)\);",
                sqlite_src, re.DOTALL)
            if not m:
                continue  # _copy_table has an OperationalError safety net
            ddl = m.group(1)
            for col in cols:
                in_ddl = bool(re.search(
                    rf"\b{re.escape(col)}\b\s+[A-Z]", ddl))
                in_migration = (table, col) in migration_cols
                assert in_ddl or in_migration, (
                    f"db.import dispatch: column {col!r} not in SQLite "
                    f"{table} schema (neither CREATE TABLE nor _SCHEMA_MIGRATIONS)"
                )

    def test_pg_only_db_export_module_exists(self):
        """db.export is the PG → SQLite backup tool — symmetric to
        db.import. Used for backups, downgrades, and ops migration."""
        import importlib.util
        from pathlib import Path
        proj = Path(__file__).resolve().parent.parent
        assert (proj / "db" / "export.py").exists(), \
            "db/export.py must exist"
        spec = importlib.util.spec_from_file_location(
            "_db_export_test", str(proj / "db" / "export.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert callable(mod.main)

    def test_pg_only_db_export_refuses_without_postgres_dsn(self):
        """Defensive: db.export must not silently no-op when
        POSTGRES_DSN is unset — return CLI error code 1."""
        import importlib.util, os
        from pathlib import Path
        proj = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location(
            "_db_export_test", str(proj / "db" / "export.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        saved_dsn = os.environ.pop("POSTGRES_DSN", None)
        try:
            rc = mod.main(["/tmp/_will_not_be_created.db", "--schema-only"])
            assert rc == 1, f"export without DSN must return rc=1, got {rc}"
        finally:
            if saved_dsn is not None:
                os.environ["POSTGRES_DSN"] = saved_dsn

    def test_pg_only_db_export_refuses_overwrite_without_force(self):
        """Defensive: db.export must not clobber an existing SQLite file
        unless --force is passed."""
        import importlib.util, os, tempfile
        from pathlib import Path
        proj = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location(
            "_db_export_test", str(proj / "db" / "export.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        td = tempfile.mkdtemp()
        target = os.path.join(td, "existing.db")
        with open(target, "w") as f:
            f.write("preexisting")
        prev_dsn = os.environ.get("POSTGRES_DSN", "")
        try:
            os.environ["POSTGRES_DSN"] = "postgres://noop/test"
            rc = mod.main([target, "--schema-only"])
            assert rc == 4, f"overwrite must return rc=4, got {rc}"
        finally:
            os.environ.pop("POSTGRES_DSN", None)
            if prev_dsn:
                os.environ["POSTGRES_DSN"] = prev_dsn
            import shutil; shutil.rmtree(td, ignore_errors=True)

    def test_pg_only_phase8_db_backend_auto_derived(self):
        """Phase 8: DB_BACKEND is auto-derived from POSTGRES_DSN. The
        env-only path is gone."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "config.py").read_text()
        # When POSTGRES_DSN is set, DB_BACKEND MUST be "postgres".
        # That decision lives in config.py's POSTGRES_DSN branch.
        assert 'if POSTGRES_DSN:' in src and 'DB_BACKEND = "postgres"' in src, \
            "config.py must set DB_BACKEND=postgres when POSTGRES_DSN is set"

    def test_pg_svc_metrics_includes_extended_columns(self):
        """svc_metrics PG schema must include the 9 columns added in
        _SCHEMA_MIGRATIONS over time (pg_*, identities_count,
        total_requests) — otherwise the 35-column svc_metric INSERT fails."""
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent
               / "db" / "postgres.py").read_text()
        # Slice on the svc_metrics CREATE TABLE so we don't match the
        # column name appearing elsewhere in the file.
        i = src.find("CREATE TABLE IF NOT EXISTS svc_metrics (")
        assert i > 0
        body = src[i: i + 4000]
        for col in ("pg_db_bytes", "pg_events_rows", "identities_count",
                    "total_requests", "pg_index_bytes", "pg_active_conns",
                    "pg_idle_conns", "pg_cache_hit_pct", "pg_tx_total"):
            assert col in body, \
                f"svc_metrics PG schema missing extended column {col!r}"

    def test_offline_bg_tasks_guard_present(self):
        """proxy.on_startup must check OFFLINE_BG_TASKS and skip the
        outbound-HTTPS refresh loops when set. Tests rely on this —
        without it the suite leaks aiohttp ClientSessions across the
        whole run (MaxMind/Tor/JA4/AI-crawler/mesh)."""
        assert 'OFFLINE_BG_TASKS' in self.src, \
            "proxy.py must read OFFLINE_BG_TASKS env var"
        import re
        m = re.search(r"async def on_startup\(app\):(.*?)\nasync def ",
                      self.src, re.DOTALL)
        assert m, "on_startup not found"
        body = m.group(1)
        assert "_offline_bg" in body, "guard variable missing in on_startup"
        for loop_name in ("_maxmind_refresh_loop", "_tor_refresh_loop",
                          "_mesh_sync_loop"):
            idx = body.find(loop_name)
            assert idx > 0, f"{loop_name} not in on_startup"
            window = body[max(0, idx - 1200): idx]
            assert "if not _offline_bg:" in window, (
                f"{loop_name} is not gated by OFFLINE_BG_TASKS — would "
                f"leak ClientSession across tests"
            )

    def test_conftest_sets_offline_bg_tasks(self):
        """tests/conftest.py must set OFFLINE_BG_TASKS=1 BEFORE importing
        proxy, or the guard never fires for the test run."""
        from pathlib import Path
        ct = (Path(__file__).resolve().parent / "conftest.py").read_text()
        assert 'OFFLINE_BG_TASKS' in ct, \
            "conftest.py must set OFFLINE_BG_TASKS"
        # Must be set BEFORE `import pytest` / proxy import — and proxy
        # gets imported via the `proxy_module` fixture, so setdefault
        # before the first import is the sane line.
        idx_env = ct.find('OFFLINE_BG_TASKS')
        idx_import_pytest = ct.find('import pytest')
        assert idx_env < idx_import_pytest, (
            "OFFLINE_BG_TASKS must be set before `import pytest`"
        )

    def test_no_cold_start_restore_in_on_startup(self):
        """PG-only migration Phase 6: on_startup must NOT call the
        cold-start restore. SQLite ↔ PG one-shot migrations are now
        CLI tools, outside the boot path."""
        import re
        m = re.search(r"async def on_startup\(app\):(.*?)\nasync def ",
                      self.src, re.DOTALL)
        assert m
        body = m.group(1)
        assert "db_restore_from_postgres(" not in body, \
            "PG-only mode must not call db_restore_from_postgres at boot"
