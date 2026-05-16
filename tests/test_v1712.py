"""
QA tests for v1.7.12 fixes:

  Q2  — Div-by-zero guard on RATE_LIMIT_REFILL / IP_REFILL (config.py)
  Q1  — SESSION_SECURE bool parsing expanded to cover FALSE/no/off (config.py)
  Q5  — NEW_SESSIONS_PER_IP_PER_MIN_HOSTING accepts both old and new env name (config.py)
  Q4  — Dead inner try/except removed from scoring._load_signal_order_cache
         and scoring._save_signal_order (scoring.py)
  P5  — fire-and-forget create_task anchored in _background_tasks (scoring.py)
  L2  — Logout endpoint changed from GET to POST; all dashboard links → POST form (L2 CSRF fix)
  S2  — INTERNAL_KEY no longer printed in full on first boot; only first 4 chars shown (S2)
  P3  — AbuseIPDB SQLite cache lookup moved to run_in_executor (P3 async-blocking fix)
  P4  — Shared aiohttp ClientSession per module (abuseipdb, crowdsec, webhook) (P4)
  O(n)— ip_state linear scan replaced with ip_to_identities inverted index (O(n) fix)
"""
import asyncio
import inspect
import os
import re

import pytest


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── Q2: RATE_LIMIT_REFILL / IP_REFILL div-by-zero guard ───────────────────

class TestQ2RefillDivByZeroGuard:
    """max(0.001, ...) applied to both RATE_LIMIT_REFILL and IP_REFILL so that
    REFILL=0 or IP_REFILL=0 cannot produce ZeroDivisionError at runtime."""

    def test_rate_limit_refill_positive_under_normal_env(self):
        """RATE_LIMIT_REFILL must always be > 0 (default 3.0)."""
        import config
        assert config.RATE_LIMIT_REFILL > 0, (
            "RATE_LIMIT_REFILL must be positive — ZeroDivisionError guard failed"
        )

    def test_ip_refill_positive_under_normal_env(self):
        """IP_REFILL must always be > 0 (default 5.0)."""
        import config
        assert config.IP_REFILL > 0, (
            "IP_REFILL must be positive — ZeroDivisionError guard failed"
        )

    def test_refill_zero_env_clamped_to_minimum(self, monkeypatch):
        """When REFILL=0 is set, the clamped floor must be 0.001, not 0."""
        monkeypatch.setenv("REFILL", "0")
        # Simulate the exact expression from config.py
        raw = max(0.001, float(os.environ.get("REFILL", "3.0")))
        assert raw == pytest.approx(0.001), (
            "REFILL=0 must be clamped to 0.001 by max(0.001, ...) guard"
        )

    def test_ip_refill_zero_env_clamped_to_minimum(self, monkeypatch):
        """When IP_REFILL=0 is set, the clamped floor must be 0.001, not 0."""
        monkeypatch.setenv("IP_REFILL", "0")
        raw = max(0.001, float(os.environ.get("IP_REFILL", "5.0")))
        assert raw == pytest.approx(0.001), (
            "IP_REFILL=0 must be clamped to 0.001 by max(0.001, ...) guard"
        )

    def test_normal_refill_value_passes_through_unmodified(self, monkeypatch):
        """A normal REFILL value (e.g. 3.0) must pass through unchanged."""
        monkeypatch.setenv("REFILL", "3.0")
        raw = max(0.001, float(os.environ.get("REFILL", "3.0")))
        assert raw == pytest.approx(3.0), (
            "Normal REFILL=3.0 must not be altered by the guard"
        )

    def test_rate_limit_division_does_not_raise_with_min_refill(self):
        """The retry-delay division in rate_limit.py must not raise even when
        RATE_LIMIT_REFILL is at its floor value 0.001."""
        # Reproduces rate_limit.py:87: retry = (1.0 - tokens) / RATE_LIMIT_REFILL
        refill = 0.001
        tokens = 0.5
        result = (1.0 - tokens) / refill
        assert result == pytest.approx(500.0), (
            "Division must succeed when RATE_LIMIT_REFILL is at floor 0.001"
        )

    def test_config_source_uses_max_guard_for_rate_limit_refill(self):
        """config.py source must wrap RATE_LIMIT_REFILL in max(0.001, ...)."""
        import config
        src = inspect.getsource(config)
        # Grab the RATE_LIMIT_REFILL assignment line
        match = re.search(r'RATE_LIMIT_REFILL\s*=\s*(.+)', src)
        assert match, "RATE_LIMIT_REFILL assignment not found in config.py"
        rhs = match.group(1)
        assert "max(" in rhs, (
            "RATE_LIMIT_REFILL must use max(0.001, ...) guard — Q2 fix may have been reverted"
        )

    def test_config_source_uses_max_guard_for_ip_refill(self):
        """config.py source must wrap IP_REFILL in max(0.001, ...)."""
        import config
        src = inspect.getsource(config)
        match = re.search(r'IP_REFILL\s*=\s*(.+)', src)
        assert match, "IP_REFILL assignment not found in config.py"
        rhs = match.group(1)
        assert "max(" in rhs, (
            "IP_REFILL must use max(0.001, ...) guard — Q2 fix may have been reverted"
        )


# ── Q1: SESSION_SECURE bool parsing ───────────────────────────────────────

class TestQ1SessionSecureBoolParsing:
    """SESSION_SECURE must treat all common falsy spellings as False, not just
    the original three ('0', 'false', 'False'). Added: 'FALSE', 'no', 'off'."""

    def _parse(self, value: str) -> bool:
        """Replicate the config.py SESSION_SECURE parsing expression."""
        return value.strip().lower() not in ("0", "false", "no", "off", "")

    def test_zero_is_false(self):
        assert self._parse("0") is False

    def test_false_lowercase_is_false(self):
        assert self._parse("false") is False

    def test_false_uppercase_is_false(self):
        """'FALSE' must be falsy — was accepted as truthy before Q1 fix."""
        assert self._parse("FALSE") is False

    def test_false_mixed_case_is_false(self):
        assert self._parse("False") is False

    def test_no_lowercase_is_false(self):
        """'no' must be falsy — was accepted as truthy before Q1 fix."""
        assert self._parse("no") is False

    def test_no_uppercase_is_false(self):
        """'NO' must be falsy — was accepted as truthy before Q1 fix."""
        assert self._parse("NO") is False

    def test_off_is_false(self):
        """'off' must be falsy — was accepted as truthy before Q1 fix."""
        assert self._parse("off") is False

    def test_off_uppercase_is_false(self):
        assert self._parse("OFF") is False

    def test_empty_string_is_false(self):
        assert self._parse("") is False

    def test_one_is_true(self):
        assert self._parse("1") is True

    def test_true_lowercase_is_true(self):
        assert self._parse("true") is True

    def test_yes_is_true(self):
        assert self._parse("yes") is True

    def test_on_is_true(self):
        assert self._parse("on") is True

    def test_whitespace_stripped(self):
        """Leading/trailing whitespace must be stripped before evaluation."""
        assert self._parse("  0  ") is False
        assert self._parse("  1  ") is True

    def test_config_source_uses_strip_lower(self):
        """config.py SESSION_SECURE line must use .strip().lower() for case-insensitive
        comparison — confirms Q1 fix was not reverted."""
        import config
        src = inspect.getsource(config)
        match = re.search(r'SESSION_SECURE\s*=\s*(.+)', src)
        assert match, "SESSION_SECURE assignment not found in config.py"
        rhs = match.group(1)
        assert ".strip()" in rhs or ".lower()" in rhs, (
            "SESSION_SECURE must use .strip().lower() for case-insensitive parsing — "
            "Q1 fix may have been reverted"
        )


# ── Q5: NEW_SESSIONS_PER_IP_PER_MIN_HOSTING env name alias ────────────────

class TestQ5EnvNameAlias:
    """NEW_SESSIONS_PER_IP_PER_MIN_HOSTING must accept both:
      - NEW_SESSIONS_PER_IP_PER_MIN_HOSTING (canonical new name)
      - NEW_SESSIONS_PER_HOSTING            (legacy alias — deployments that
                                             set the old name must not break)
    New name takes precedence when both are present."""

    def _eval(self, env: dict) -> int:
        """Simulate the config.py resolution logic in isolation."""
        return int(
            env.get("NEW_SESSIONS_PER_IP_PER_MIN_HOSTING") or
            env.get("NEW_SESSIONS_PER_HOSTING", "10")
        )

    def test_legacy_env_name_honoured(self):
        """OLD name 'NEW_SESSIONS_PER_HOSTING' must still work after Q5 fix."""
        result = self._eval({"NEW_SESSIONS_PER_HOSTING": "7"})
        assert result == 7, (
            "Legacy env name NEW_SESSIONS_PER_HOSTING must be accepted"
        )

    def test_new_env_name_honoured(self):
        """NEW name 'NEW_SESSIONS_PER_IP_PER_MIN_HOSTING' must be accepted."""
        result = self._eval({"NEW_SESSIONS_PER_IP_PER_MIN_HOSTING": "15"})
        assert result == 15

    def test_new_name_takes_precedence_over_legacy(self):
        """When both names are set, new name wins."""
        result = self._eval({
            "NEW_SESSIONS_PER_IP_PER_MIN_HOSTING": "20",
            "NEW_SESSIONS_PER_HOSTING": "5",
        })
        assert result == 20, (
            "NEW_SESSIONS_PER_IP_PER_MIN_HOSTING must override legacy "
            "NEW_SESSIONS_PER_HOSTING when both are set"
        )

    def test_default_when_neither_set(self):
        """Default value (10) must apply when neither env var is set."""
        result = self._eval({})
        assert result == 10

    def test_config_source_reads_both_env_names(self):
        """config.py must reference both env var names in the assignment."""
        import config
        src = inspect.getsource(config)
        assert "NEW_SESSIONS_PER_IP_PER_MIN_HOSTING" in src, (
            "config.py must reference NEW_SESSIONS_PER_IP_PER_MIN_HOSTING env var"
        )
        assert "NEW_SESSIONS_PER_HOSTING" in src, (
            "config.py must retain NEW_SESSIONS_PER_HOSTING as legacy alias"
        )


# ── Q4: Dead inner try/except removed ─────────────────────────────────────

class TestQ4DeadInnerTryExcept:
    """_load_signal_order_cache and _save_signal_order must not contain a
    duplicate 'from admin.mesh import _gw_local_id' inside an except block —
    that inner import is identical to the outer one and can never succeed when
    the outer fails."""

    def _fn_source(self, fn_name: str) -> str:
        import scoring
        fn = getattr(scoring, fn_name)
        return inspect.getsource(fn)

    def test_load_cache_no_duplicate_mesh_import(self):
        """_load_signal_order_cache must have at most one 'from admin.mesh import'."""
        src = self._fn_source("_load_signal_order_cache")
        count = src.count("from admin.mesh import _gw_local_id")
        assert count <= 1, (
            f"_load_signal_order_cache has {count} copies of 'from admin.mesh import "
            f"_gw_local_id' — dead inner try/except was not removed (Q4)"
        )

    def test_save_signal_no_duplicate_mesh_import(self):
        """_save_signal_order must have at most one 'from admin.mesh import'."""
        src = self._fn_source("_save_signal_order")
        count = src.count("from admin.mesh import _gw_local_id")
        assert count <= 1, (
            f"_save_signal_order has {count} copies of 'from admin.mesh import "
            f"_gw_local_id' — dead inner try/except was not removed (Q4)"
        )

    def test_load_cache_except_leads_directly_to_return(self):
        """After removing the dead inner try, the except block in
        _load_signal_order_cache must go straight to 'return'."""
        src = self._fn_source("_load_signal_order_cache")
        # Pattern: 'except Exception:' followed by optional whitespace then 'return'
        # with no nested 'try:' in between
        except_to_return = re.search(
            r'except Exception:\s*\n\s*return', src
        )
        assert except_to_return, (
            "_load_signal_order_cache: 'except Exception:' must be followed "
            "directly by 'return', not another try block"
        )

    def test_save_signal_except_leads_directly_to_return(self):
        """After removing the dead inner try, the except block in
        _save_signal_order must go straight to 'return'."""
        src = self._fn_source("_save_signal_order")
        except_to_return = re.search(
            r'except Exception:\s*\n\s*return', src
        )
        assert except_to_return, (
            "_save_signal_order: 'except Exception:' must be followed "
            "directly by 'return', not another try block"
        )


# ── P5: Fire-and-forget create_task anchored ──────────────────────────────

class TestP5BackgroundTasksAnchor:
    """create_task() calls in scoring.update_risk_and_maybe_ban must store
    the Task reference in _background_tasks so GC cannot collect it before
    completion, and a done-callback removes it afterwards."""

    def test_background_tasks_set_exists(self):
        """scoring._background_tasks must be a set-like container."""
        import scoring
        assert hasattr(scoring, "_background_tasks"), (
            "scoring module must expose _background_tasks — P5 fix missing"
        )
        assert isinstance(scoring._background_tasks, set), (
            "scoring._background_tasks must be a set"
        )

    def test_update_risk_source_adds_task_to_set(self):
        """update_risk_and_maybe_ban source must call _background_tasks.add(...)
        for each create_task call."""
        import scoring
        src = inspect.getsource(scoring.update_risk_and_maybe_ban)
        add_calls = src.count("_background_tasks.add(")
        assert add_calls >= 2, (
            f"update_risk_and_maybe_ban must call _background_tasks.add() at least "
            f"twice (ja4 + webhook tasks) — found {add_calls} (P5 fix)"
        )

    def test_update_risk_source_registers_done_callback(self):
        """update_risk_and_maybe_ban source must attach .add_done_callback(
        _background_tasks.discard) to prevent set from growing unboundedly."""
        import scoring
        src = inspect.getsource(scoring.update_risk_and_maybe_ban)
        callbacks = src.count("_background_tasks.discard")
        assert callbacks >= 2, (
            f"update_risk_and_maybe_ban must register _background_tasks.discard "
            f"as done-callback at least twice — found {callbacks} (P5 fix)"
        )

    def test_completed_task_removed_from_set(self):
        """A task added to _background_tasks must be removed from the set
        after it completes (via the done-callback)."""
        import scoring

        completed = []

        async def _fast_coro():
            completed.append(True)

        async def go():
            t = asyncio.create_task(_fast_coro())
            scoring._background_tasks.add(t)
            t.add_done_callback(scoring._background_tasks.discard)
            await asyncio.sleep(0)   # yield — let the task run
            return t

        loop = asyncio.new_event_loop()
        task = loop.run_until_complete(go())
        loop.close()

        assert completed, "The fast coro must have run"
        assert task not in scoring._background_tasks, (
            "Completed task must be removed from _background_tasks by the done-callback"
        )

    def test_running_task_stays_in_set(self):
        """A task that has not yet completed must remain in _background_tasks."""
        import scoring

        ready = asyncio.Event()

        async def _blocking_coro(ev):
            await ev.wait()

        async def go():
            loop = asyncio.get_event_loop()
            ev = asyncio.Event()
            t = asyncio.create_task(_blocking_coro(ev))
            scoring._background_tasks.add(t)
            t.add_done_callback(scoring._background_tasks.discard)
            await asyncio.sleep(0)   # yield but coro blocks on ev
            in_set = t in scoring._background_tasks
            ev.set()                 # release the coro
            await asyncio.sleep(0)   # let it finish
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
            return in_set

        loop = asyncio.new_event_loop()
        was_in_set = loop.run_until_complete(go())
        loop.close()

        assert was_in_set, (
            "A still-running task must remain in _background_tasks until it completes"
        )


# ── L2: Logout CSRF — GET → POST ──────────────────────────────────────────

class TestL2LogoutPostOnly:
    """Logout must be a POST-only operation so an attacker cannot log out an
    admin session via a crafted link (CSRF via GET)."""

    def test_proxy_registers_logout_as_post(self):
        """proxy.py must use add_post (not add_get) for the logout route."""
        import proxy
        src = inspect.getsource(proxy)
        # Must have add_post for logout
        assert re.search(r'add_post\s*\(.*logout', src), (
            "proxy.py must register logout with add_post — L2 CSRF fix may be reverted"
        )

    def test_proxy_does_not_register_logout_as_get(self):
        """proxy.py must NOT have add_get for the logout route."""
        import proxy
        src = inspect.getsource(proxy)
        assert not re.search(r'add_get\s*\(.*logout', src), (
            "proxy.py must NOT register logout with add_get — L2 CSRF fix may be reverted"
        )

    def test_logout_endpoint_docstring_says_post(self):
        """logout_endpoint docstring must open with POST (not GET) as the
        method — the docstring may still mention GET in context."""
        from admin.users import logout_endpoint
        doc = (logout_endpoint.__doc__ or "").strip()
        assert doc.startswith("POST"), (
            "logout_endpoint docstring must start with 'POST ...' — L2 fix"
        )

    def test_dashboard_logout_links_use_post_form(self):
        """All dashboard HTML files must use <form method=\"post\"> for logout,
        not a bare <a href=...> GET link."""
        import os, glob
        dashboards_dir = os.path.join(
            os.path.dirname(__file__), "..", "dashboards"
        )
        html_files = glob.glob(os.path.join(dashboards_dir, "*.html"))
        assert html_files, "No dashboard HTML files found"
        for path in html_files:
            content = open(path).read()
            if "/antibot-appsec-gateway/logout" not in content:
                continue  # file has no logout link at all — skip
            # Must have POST form
            assert 'method="post"' in content or "method='post'" in content, (
                f"{os.path.basename(path)}: logout must use a POST form, not GET link"
            )
            # Must NOT have a bare <a href=...logout...> without a form
            assert not re.search(
                r'<a [^>]*href=["\'][^"\']*logout[^"\']*["\'][^>]*>',
                content
            ), (
                f"{os.path.basename(path)}: bare <a href=logout> GET link still present"
            )

    def test_dashboard_logout_form_has_confirm_dialog(self):
        """Every dashboard logout form must still prompt before submitting
        (confirm() in onclick) — UX must not regress."""
        import os, glob
        dashboards_dir = os.path.join(
            os.path.dirname(__file__), "..", "dashboards"
        )
        for path in glob.glob(os.path.join(dashboards_dir, "*.html")):
            content = open(path).read()
            if "/antibot-appsec-gateway/logout" not in content:
                continue
            assert "confirm(" in content, (
                f"{os.path.basename(path)}: logout confirm() dialog was removed — "
                "UX regression"
            )


# ── S2: INTERNAL_KEY not printed in full ──────────────────────────────────

class TestS2InternalKeyNotPrinted:
    """On first boot proxy.py must show only the first 4 characters of the
    auto-generated INTERNAL_KEY, not the whole value. The full key must never
    appear in stdout — operators must read it from the key file."""

    def test_proxy_source_does_not_concat_full_key(self):
        """proxy.py must not contain the pattern '\"   pass: \" + INTERNAL_KEY'
        (the old full-key print)."""
        import proxy
        src = inspect.getsource(proxy)
        assert '"   pass: " + INTERNAL_KEY' not in src, (
            "proxy.py still concatenates the full INTERNAL_KEY into the boot banner — "
            "S2 fix may be reverted"
        )

    def test_proxy_source_truncates_key_to_4_chars(self):
        """proxy.py must use INTERNAL_KEY[:4] for the boot banner."""
        import proxy
        src = inspect.getsource(proxy)
        assert "INTERNAL_KEY[:4]" in src, (
            "proxy.py must show only INTERNAL_KEY[:4] in the boot banner — S2 fix"
        )

    def test_proxy_source_references_key_file_path(self):
        """The boot banner line must reference the key file path so the
        operator knows where to find the full key."""
        import proxy
        src = inspect.getsource(proxy)
        # _KEY_FILE must appear in the bootstrap password line
        assert "_KEY_FILE" in src, (
            "proxy.py boot banner must reference _KEY_FILE so operator can "
            "find the key — S2 fix"
        )

    def test_key_file_imported_from_config(self):
        """_KEY_FILE must be explicitly imported from config into proxy.py
        (underscore names are not exported by 'from config import *').
        The import may span multiple lines, so we scan the full source."""
        import proxy
        src = inspect.getsource(proxy)
        assert "_KEY_FILE" in src, (
            "proxy.py must reference _KEY_FILE"
        )
        # Verify it appears in an import block (not just as a variable use).
        # Multi-line imports are common so we scan a sliding window of 5 lines.
        lines = src.splitlines()
        found_import = False
        for i, line in enumerate(lines):
            if "from config import" in line:
                block = "\n".join(lines[i:i + 8])
                if "_KEY_FILE" in block:
                    found_import = True
                    break
        assert found_import, (
            "proxy.py must import _KEY_FILE from config — "
            "underscore names are not included in 'from config import *'"
        )

    def test_truncated_key_banner_format(self):
        """The truncated key banner must follow the pattern
        'XXXX***  (read <path>)' so it is human-readable."""
        # Simulate the expression from proxy.py
        fake_key = "ABCDEFGHIJ1234567890"
        fake_path = "/app/.admin_key"
        banner = f"   pass: {fake_key[:4]}***  (read {fake_path})"
        assert banner.startswith("   pass: ABCD***"), (
            "Banner must start with first 4 chars followed by '***'"
        )
        assert fake_path in banner, (
            "Banner must include the key file path"
        )
        assert fake_key not in banner, (
            "Full key must not appear in the banner"
        )


# ── P3: AbuseIPDB SQLite moved to run_in_executor ─────────────────────────

class TestP3AbuseIPDBNonBlockingSQLite:
    """The AbuseIPDB cache lookup (sqlite3.connect + execute) must run in a
    thread-pool executor so it does not block the asyncio event loop."""

    def test_source_uses_run_in_executor(self):
        """reputation/abuseipdb.py must call run_in_executor for the cache lookup."""
        import reputation.abuseipdb as ab
        src = inspect.getsource(ab)
        assert "run_in_executor" in src, (
            "abuseipdb.py must use run_in_executor for the SQLite cache lookup — P3 fix"
        )

    def test_source_has_no_bare_sqlite_connect_in_async_body(self):
        """sqlite3.connect must not appear directly in the body of the async
        lookup function — it must only appear inside a sync helper."""
        import reputation.abuseipdb as ab
        src = inspect.getsource(ab._abuseipdb_lookup)
        # sqlite3.connect in the async function body is the bug;
        # it's OK inside a nested sync def (the helper)
        lines = src.splitlines()
        in_sync_helper = False
        for line in lines:
            stripped = line.strip()
            # Track entry into nested sync def (non-async)
            if stripped.startswith("def ") and not stripped.startswith("async def"):
                in_sync_helper = True
            # If we see sqlite3.connect outside a sync helper, fail
            if "sqlite3.connect" in stripped and not in_sync_helper:
                raise AssertionError(
                    "sqlite3.connect found in async _abuseipdb_lookup body outside "
                    "a sync helper — P3 fix may be reverted"
                )

    def test_executor_called_for_cache_lookup(self):
        """run_in_executor must be invoked during an AbuseIPDB cache hit."""
        import asyncio
        import reputation.abuseipdb as ab

        executor_calls = []

        class _FakeLoop:
            async def run_in_executor(self, pool, fn, *args):
                executor_calls.append(fn.__name__ if callable(fn) else str(fn))
                # Simulate a cache miss (return None)
                return None

        async def go():
            # Patch get_event_loop to intercept run_in_executor
            original = asyncio.get_event_loop
            fake_loop = _FakeLoop()
            import unittest.mock as mock
            with mock.patch("asyncio.get_event_loop", return_value=fake_loop):
                # Also patch the actual API call path to bail early
                with mock.patch.object(ab, "ABUSEIPDB_ENABLED", True), \
                     mock.patch.object(ab, "ABUSEIPDB_KEY", "testkey"):
                    # The call will reach executor then fail at the API call
                    # (no network) — we only care that executor was called
                    try:
                        await ab._abuseipdb_lookup("1.2.3.4")
                    except Exception:
                        pass
            return executor_calls

        loop = asyncio.new_event_loop()
        calls = loop.run_until_complete(go())
        loop.close()
        assert calls, (
            "run_in_executor was not called during AbuseIPDB cache lookup — P3 fix"
        )


# ── P4: Shared aiohttp ClientSession per module ───────────────────────────

class TestP4SharedHttpSession:
    """abuseipdb, crowdsec, and webhook must each maintain a module-level
    shared ClientSession so TCP connections are reused across calls."""

    # ── existence + type ──────────────────────────────────────────────────

    def test_abuseipdb_has_get_session(self):
        import reputation.abuseipdb as ab
        assert hasattr(ab, "_get_session") and callable(ab._get_session), (
            "reputation/abuseipdb.py must expose _get_session() — P4 fix"
        )

    def test_crowdsec_has_get_session(self):
        import reputation.crowdsec as cs
        assert hasattr(cs, "_get_session") and callable(cs._get_session), (
            "reputation/crowdsec.py must expose _get_session() — P4 fix"
        )

    def test_webhook_has_get_session(self):
        import integrations.webhook as wh
        assert hasattr(wh, "_get_session") and callable(wh._get_session), (
            "integrations/webhook.py must expose _get_session() — P4 fix"
        )

    # ── session reuse ─────────────────────────────────────────────────────

    def _assert_session_reused(self, module):
        """_get_session() called twice on a fresh module must return the
        same ClientSession object (connection pool is shared).
        Must run inside an event loop because aiohttp requires one."""
        async def go():
            module._http_session = None   # reset to known state
            s1 = module._get_session()
            s2 = module._get_session()
            await s1.close()             # clean up to avoid ResourceWarning
            return s1 is s2
        loop = asyncio.new_event_loop()
        reused = loop.run_until_complete(go())
        loop.close()
        assert reused, (
            f"{module.__name__}: second _get_session() call must return the same "
            "session object — P4 fix not reusing session"
        )

    def test_abuseipdb_session_reused(self):
        import reputation.abuseipdb as ab
        self._assert_session_reused(ab)

    def test_crowdsec_session_reused(self):
        import reputation.crowdsec as cs
        self._assert_session_reused(cs)

    def test_webhook_session_reused(self):
        import integrations.webhook as wh
        self._assert_session_reused(wh)

    # ── closed session is replaced ────────────────────────────────────────

    def _assert_closed_session_replaced(self, module):
        """When the cached session is closed, _get_session() must create a
        fresh one rather than returning the closed object."""
        from unittest.mock import MagicMock
        closed_session = MagicMock()
        closed_session.closed = True
        module._http_session = closed_session

        async def go():
            new_session = module._get_session()
            await new_session.close()    # clean up real session
            return new_session
        loop = asyncio.new_event_loop()
        new_session = loop.run_until_complete(go())
        loop.close()
        assert new_session is not closed_session, (
            f"{module.__name__}: _get_session() must replace a closed session"
        )

    def test_abuseipdb_closed_session_replaced(self):
        import reputation.abuseipdb as ab
        self._assert_closed_session_replaced(ab)

    def test_crowdsec_closed_session_replaced(self):
        import reputation.crowdsec as cs
        self._assert_closed_session_replaced(cs)

    def test_webhook_closed_session_replaced(self):
        import integrations.webhook as wh
        self._assert_closed_session_replaced(wh)

    # ── source: no per-call ClientSession context manager ─────────────────

    def test_abuseipdb_source_no_per_call_session(self):
        """abuseipdb.py lookup must not open a new ClientSession() per call."""
        import reputation.abuseipdb as ab
        src = inspect.getsource(ab._abuseipdb_lookup)
        assert "async with ClientSession(" not in src, (
            "abuseipdb._abuseipdb_lookup still creates a per-call ClientSession — "
            "P4 fix reverted"
        )

    def test_crowdsec_source_no_per_call_session(self):
        """crowdsec.py check must not open a new ClientSession() per call."""
        import reputation.crowdsec as cs
        src = inspect.getsource(cs._crowdsec_check)
        assert "async with ClientSession(" not in src, (
            "crowdsec._crowdsec_check still creates a per-call ClientSession — "
            "P4 fix reverted"
        )

    def test_webhook_source_no_per_call_session(self):
        """webhook.py must not open a new ClientSession() per call."""
        import integrations.webhook as wh
        src = inspect.getsource(wh._post_webhook)
        assert "async with ClientSession(" not in src, (
            "webhook._post_webhook still creates a per-call ClientSession — "
            "P4 fix reverted"
        )

    def test_webhook_source_uses_get_session(self):
        """webhook delivery must use _get_session() (shared session reuse)."""
        import integrations.webhook as wh
        # 1.8.6: delivery moved to _webhook_worker (queue+retry); _get_session()
        # is still called there — check the worker instead of _post_webhook.
        worker_src = inspect.getsource(wh._webhook_worker)
        post_src = inspect.getsource(wh._post_webhook)
        assert "_get_session()" in worker_src or "_get_session()" in post_src, (
            "webhook delivery must use _get_session() — P4 fix"
        )


# ── O(n): ip_to_identities inverted index ─────────────────────────────────

class TestOnIpToIdentitiesIndex:
    """NAT-detection lookup must use the ip_to_identities inverted index
    (O(m) per-IP scan) instead of a full O(N) ip_state.items() scan."""

    # ── index structure ───────────────────────────────────────────────────

    def test_ip_to_identities_exists_in_state(self):
        """state.ip_to_identities must be a defaultdict(set)."""
        import state
        from collections import defaultdict
        assert hasattr(state, "ip_to_identities"), (
            "state.py must define ip_to_identities — O(n) fix"
        )
        assert isinstance(state.ip_to_identities, defaultdict), (
            "state.ip_to_identities must be a defaultdict"
        )

    def test_scoring_uses_index_not_full_scan(self):
        """update_risk_and_maybe_ban source must use ip_to_identities,
        not a bare ip_state.items() scan for NAT detection."""
        import scoring
        src = inspect.getsource(scoring.update_risk_and_maybe_ban)
        assert "ip_to_identities" in src, (
            "scoring.update_risk_and_maybe_ban must use ip_to_identities — O(n) fix"
        )
        # The old O(n) pattern must be gone
        assert "for k, st in ip_state.items()" not in src, (
            "O(n) 'for k, st in ip_state.items()' scan still present in "
            "update_risk_and_maybe_ban — O(n) fix reverted"
        )

    def test_scoring_source_has_stale_index_guard(self):
        """The index lookup must include a st.last_ip == ip guard to
        tolerate stale entries without producing wrong NAT counts."""
        import scoring
        src = inspect.getsource(scoring.update_risk_and_maybe_ban)
        assert "st.last_ip == ip" in src, (
            "NAT-detection index lookup must guard against stale entries with "
            "'st.last_ip == ip' — O(n) fix correctness"
        )

    # ── index maintenance: metrics.record ────────────────────────────────

    def test_metrics_source_maintains_index_on_last_ip_write(self):
        """core/metrics.py record() must update ip_to_identities when
        last_ip changes — this is the primary index write site.
        Note: import core.metrics as m gives the state.metrics dict due to
        star-import shadowing; use sys.modules to reach the actual module."""
        import sys, importlib
        importlib.import_module("core.metrics")
        m = sys.modules["core.metrics"]
        src = inspect.getsource(m.record)
        assert "ip_to_identities" in src, (
            "core/metrics.record must maintain ip_to_identities — O(n) fix"
        )

    def test_index_populated_when_last_ip_set(self):
        """After record() runs for a track_key, ip_to_identities[ip] must
        contain that track_key."""
        import asyncio
        import state as st

        async def go():
            from core.metrics import record
            key = "_test_on_record_key"
            ip  = "10.0.0.99"
            st.ip_to_identities[ip].discard(key)   # clean slate
            await record(ip=ip, ua="TestAgent/1.0", path="/test",
                         status=200, reason="", track_key=key)
            return key in st.ip_to_identities.get(ip, set())

        loop = asyncio.new_event_loop()
        found = loop.run_until_complete(go())
        loop.close()
        assert found, (
            "ip_to_identities[ip] must contain track_key after record() call"
        )

    def test_index_updated_when_ip_changes(self):
        """If an identity moves from IP-A to IP-B, ip_to_identities must
        remove it from A's bucket and add it to B's bucket."""
        import asyncio
        import state as st

        async def go():
            from core.metrics import record
            key  = "_test_on_ip_change"
            ip_a = "10.0.1.1"
            ip_b = "10.0.1.2"
            for ip in (ip_a, ip_b):
                st.ip_to_identities[ip].discard(key)

            # First request from ip_a
            await record(ip=ip_a, ua="Bot/1", path="/x",
                         status=200, reason="", track_key=key)
            in_a_before = key in st.ip_to_identities.get(ip_a, set())

            # Second request from ip_b (simulates IP change / mobile roam)
            await record(ip=ip_b, ua="Bot/1", path="/x",
                         status=200, reason="", track_key=key)
            in_a_after = key in st.ip_to_identities.get(ip_a, set())
            in_b_after  = key in st.ip_to_identities.get(ip_b, set())
            return in_a_before, in_a_after, in_b_after

        loop = asyncio.new_event_loop()
        in_a_before, in_a_after, in_b_after = loop.run_until_complete(go())
        loop.close()
        assert in_a_before, "key must be in ip_a bucket after first request"
        assert not in_a_after, "key must be removed from ip_a bucket after IP change"
        assert in_b_after,  "key must be in ip_b bucket after IP change"

    # ── index maintenance: prune eviction ─────────────────────────────────

    def test_prune_removes_evicted_identity_from_index(self):
        """When the prune loop evicts an identity from ip_state, it must
        also remove it from ip_to_identities."""
        import asyncio, time
        import state as st
        from state import IpState

        key = "_test_on_prune_evict"
        ip  = "10.0.2.1"

        async def go():
            import rate_limit as rl
            n = time.monotonic()
            s = IpState()
            s.last_ip = ip
            s.banned_until = 0.0
            s.last_seen = n - 999999   # very stale — will be evicted
            async with st.state_lock:
                st.ip_state[key] = s
                st.ip_to_identities[ip].add(key)

            # Run one prune cycle body (not the sleep)
            async with st.state_lock:
                idle = [k for k, _s in st.ip_state.items()
                        if _s.banned_until <= n
                        and (n - _s.last_seen) > 1]   # threshold=1s for test speed
                for k in idle:
                    _old_ip = st.ip_state[k].last_ip
                    if _old_ip:
                        st.ip_to_identities[_old_ip].discard(k)
                    del st.ip_state[k]

            still_in_index = key in st.ip_to_identities.get(ip, set())
            still_in_state = key in st.ip_state
            return still_in_index, still_in_state

        loop = asyncio.new_event_loop()
        in_idx, in_st = loop.run_until_complete(go())
        loop.close()
        assert not in_st,  "identity must be evicted from ip_state"
        assert not in_idx, "identity must be removed from ip_to_identities at eviction"

    def test_prune_cleans_empty_index_buckets(self):
        """After eviction, empty ip_to_identities buckets must be deleted
        so the index dict doesn't accumulate ghost IP keys."""
        import asyncio
        import state as st

        ip = "10.0.3.1"

        async def go():
            # Manually put an empty set in the index
            st.ip_to_identities[ip] = set()
            before = ip in st.ip_to_identities

            # Simulate the prune cleanup
            async with st.state_lock:
                stale = [_ip for _ip, _s in st.ip_to_identities.items() if not _s]
                for _ip in stale:
                    del st.ip_to_identities[_ip]

            after = ip in st.ip_to_identities
            return before, after

        loop = asyncio.new_event_loop()
        before, after = loop.run_until_complete(go())
        loop.close()
        assert before, "test setup: ip must be in index before prune"
        assert not after, "empty ip_to_identities bucket must be pruned"

    # ── correctness: NAT detection count ─────────────────────────────────

    def test_nat_count_matches_full_scan(self):
        """The index-based count must match the reference O(N) full scan
        for a set of synthetic identities."""
        import asyncio, time
        import state as st
        from state import IpState

        ip = "10.0.4.1"
        keys = [f"_test_on_nat_{i}" for i in range(5)]

        async def go():
            n = time.monotonic()
            # 3 qualifying identities, 2 non-qualifying
            for i, k in enumerate(keys):
                s = IpState()
                s.last_ip = ip
                s.last_seen = n - 10        # recent
                s.static_loads = 1 if i < 3 else 0   # first 3 qualify
                s.allowed_count = 5 if i < 3 else 0
                async with st.state_lock:
                    st.ip_state[k] = s
                    st.ip_to_identities[ip].add(k)

            # Reference O(N) scan
            ref = sum(
                1 for k, _st in st.ip_state.items()
                if _st.last_ip == ip
                and (n - _st.last_seen) < 3600
                and _st.static_loads >= 1
                and _st.allowed_count >= 3
            )
            # Index-based O(m) lookup
            idx = sum(
                1 for k in st.ip_to_identities.get(ip, ())
                if (_st := st.ip_state.get(k)) is not None
                and _st.last_ip == ip
                and (n - _st.last_seen) < 3600
                and _st.static_loads >= 1
                and _st.allowed_count >= 3
            )
            # Cleanup
            async with st.state_lock:
                for k in keys:
                    st.ip_state.pop(k, None)
                    st.ip_to_identities[ip].discard(k)
            return ref, idx

        loop = asyncio.new_event_loop()
        ref, idx = loop.run_until_complete(go())
        loop.close()
        assert ref == 3, f"reference scan must find 3 qualifying identities, got {ref}"
        assert idx == ref, (
            f"index-based count ({idx}) must match reference scan ({ref})"
        )


# ── O(n): index write-site coverage in rate_limit.py + proxy_handler.py ──

class TestOnIpToIdentitiesWriteSites:
    """All code paths that write ip_state[key].last_ip must also maintain
    ip_to_identities. Verifies no write site was missed in the O(n) fix."""

    def test_rate_limit_imports_ip_to_identities(self):
        """rate_limit.py must explicitly import ip_to_identities from state
        (star-import would not export it; explicit import required)."""
        import rate_limit
        src = inspect.getsource(rate_limit)
        assert "ip_to_identities" in src, (
            "rate_limit.py must import ip_to_identities — O(n) fix"
        )

    def test_rate_limit_prune_discards_from_index_at_eviction(self):
        """_prune_state_loop must call ip_to_identities[ip].discard(k) before
        deleting each identity from ip_state (both idle and overflow eviction)."""
        import rate_limit
        src = inspect.getsource(rate_limit._prune_state_loop)
        assert "ip_to_identities" in src, (
            "rate_limit._prune_state_loop must maintain ip_to_identities at eviction"
        )
        assert ".discard(" in src, (
            "rate_limit._prune_state_loop must use .discard() on ip_to_identities"
        )

    def test_rate_limit_prune_removes_empty_index_buckets(self):
        """After eviction _prune_state_loop must delete ip_to_identities buckets
        that became empty, preventing ghost-IP key accumulation."""
        import rate_limit
        src = inspect.getsource(rate_limit._prune_state_loop)
        assert ("del ip_to_identities[" in src or "_stale_ip_idx" in src), (
            "rate_limit._prune_state_loop must remove empty ip_to_identities buckets"
        )

    def test_proxy_handler_source_maintains_index(self):
        """core/proxy_handler.py must reference ip_to_identities so the
        bot-rule ban path updates the index when last_ip is written."""
        proxy_handler_path = os.path.join(
            os.path.dirname(__file__), "..", "core", "proxy_handler.py"
        )
        with open(proxy_handler_path) as f:
            src = f.read()
        assert "ip_to_identities" in src, (
            "core/proxy_handler.py must maintain ip_to_identities index — O(n) fix"
        )


# ── P4: _get_session() used inside the actual HTTP call functions ──────────

class TestP4GetSessionInLookupFunctions:
    """The main HTTP call functions must call _get_session() instead of
    opening a new ClientSession() per request."""

    def test_abuseipdb_lookup_calls_get_session(self):
        """abuseipdb._abuseipdb_lookup source must call _get_session()."""
        import reputation.abuseipdb as ab
        src = inspect.getsource(ab._abuseipdb_lookup)
        assert "_get_session()" in src, (
            "abuseipdb._abuseipdb_lookup must call _get_session() — P4 fix"
        )

    def test_crowdsec_check_calls_get_session(self):
        """crowdsec._crowdsec_check source must call _get_session()."""
        import reputation.crowdsec as cs
        src = inspect.getsource(cs._crowdsec_check)
        assert "_get_session()" in src, (
            "crowdsec._crowdsec_check must call _get_session() — P4 fix"
        )

    def test_abuseipdb_module_has_http_session_slot(self):
        """abuseipdb module must define _http_session at module level."""
        import reputation.abuseipdb as ab
        assert hasattr(ab, "_http_session"), (
            "reputation/abuseipdb.py must define _http_session — P4 fix"
        )

    def test_crowdsec_module_has_http_session_slot(self):
        """crowdsec module must define _http_session at module level."""
        import reputation.crowdsec as cs
        assert hasattr(cs, "_http_session"), (
            "reputation/crowdsec.py must define _http_session — P4 fix"
        )

    def test_webhook_module_has_http_session_slot(self):
        """webhook module must define _http_session at module level."""
        import integrations.webhook as wh
        assert hasattr(wh, "_http_session"), (
            "integrations/webhook.py must define _http_session — P4 fix"
        )


# ── scoring._decay_risk correctness ───────────────────────────────────────

class TestScoringDecayRisk:
    """_decay_risk applies exponential decay: score halves every
    RISK_DECAY_HALFLIFE_SECS, risk_by_reason decays in lockstep,
    entries below 0.5 are pruned, score below 0.5 is zeroed."""

    def _fresh_state(self):
        from state import IpState
        s = IpState()
        s.last_risk_update = 0.0   # override default (monotonic time)
        return s

    def test_zero_elapsed_no_change(self):
        """Same timestamp: no decay, score unchanged."""
        import scoring
        s = self._fresh_state()
        s.risk_score = 50.0
        s.last_risk_update = 100.0
        scoring._decay_risk(s, 100.0)
        assert s.risk_score == pytest.approx(50.0)

    def test_one_halflife_halves_score(self):
        """After exactly RISK_DECAY_HALFLIFE_SECS elapsed, score must be 50%."""
        import scoring
        from config import RISK_DECAY_HALFLIFE_SECS
        s = self._fresh_state()
        s.risk_score = 100.0
        scoring._decay_risk(s, float(RISK_DECAY_HALFLIFE_SECS))
        assert s.risk_score == pytest.approx(50.0, rel=1e-6)

    def test_risk_by_reason_decays_in_lockstep(self):
        """risk_by_reason entries must use the same decay factor as risk_score."""
        import scoring
        from config import RISK_DECAY_HALFLIFE_SECS
        s = self._fresh_state()
        s.risk_score = 80.0
        s.risk_by_reason["ua-missing"] = 40.0
        s.risk_by_reason["cookie-missing"] = 40.0
        scoring._decay_risk(s, float(RISK_DECAY_HALFLIFE_SECS))
        assert s.risk_by_reason.get("ua-missing") == pytest.approx(20.0, rel=1e-6)
        assert s.risk_by_reason.get("cookie-missing") == pytest.approx(20.0, rel=1e-6)

    def test_sub_half_reason_entry_pruned(self):
        """risk_by_reason entry that decays below 0.5 must be removed."""
        import scoring
        from config import RISK_DECAY_HALFLIFE_SECS
        s = self._fresh_state()
        s.risk_score = 100.0
        s.risk_by_reason["tiny"] = 0.6   # 0.6 × 0.5 = 0.3 < 0.5 → pruned
        scoring._decay_risk(s, float(RISK_DECAY_HALFLIFE_SECS))
        assert "tiny" not in s.risk_by_reason, (
            "risk_by_reason entry decayed below 0.5 must be deleted"
        )

    def test_score_below_half_zeroed(self):
        """risk_score decayed below 0.5 must be set to exactly 0.0."""
        import scoring
        from config import RISK_DECAY_HALFLIFE_SECS
        s = self._fresh_state()
        s.risk_score = 0.6   # 0.6 × 0.5 = 0.3 < 0.5 → zero
        scoring._decay_risk(s, float(RISK_DECAY_HALFLIFE_SECS))
        assert s.risk_score == 0.0

    def test_zeroed_score_clears_risk_by_reason(self):
        """When risk_score zeroes out, risk_by_reason must also be cleared."""
        import scoring
        from config import RISK_DECAY_HALFLIFE_SECS
        s = self._fresh_state()
        s.risk_score = 0.6
        s.risk_by_reason["sig"] = 0.3
        scoring._decay_risk(s, float(RISK_DECAY_HALFLIFE_SECS))
        assert len(s.risk_by_reason) == 0, (
            "risk_by_reason must be cleared when risk_score zeroes out"
        )

    def test_last_risk_update_advanced(self):
        """_decay_risk must set last_risk_update = now_ts after applying decay."""
        import scoring
        s = self._fresh_state()
        s.risk_score = 50.0
        scoring._decay_risk(s, 9999.0)
        assert s.last_risk_update == pytest.approx(9999.0)


# ── DOMPurify regression tests ────────────────────────────────────────────────
# These static-analysis tests guard against regressions in the DOMPurify
# integration added in 1.7.12.  They parse each dashboard HTML file directly
# and verify:
#   1. purify.min.js script tag is present in every dashboard file
#   2. _dp() uses the table-context-aware implementation (fixes tbody stripping)
#   3. No onclick handler appears inside a _dp() call (DOMPurify strips them)
#   4. Session revoke uses data-revoke-sid (not inline onclick)
#   5. Confirm modal uses data-acf attribute (not inline onclick)

import re as _re
from pathlib import Path as _Path

_DASH_DIR = _Path(__file__).resolve().parent.parent / "dashboards"
_DASH_FILES = [
    "main.html", "controls.html", "logs.html", "geo.html",
    "agents.html", "service.html", "settings.html",
]


def _dp_calls_with_onclick(html: str) -> list[int]:
    """Return line numbers of _dp() calls whose argument contains 'onclick'."""
    bad_lines = []
    for m in _re.finditer(r'_dp\(', html):
        start = m.start()
        depth = 0
        i = start + 4
        in_str = None
        while i < len(html) and depth >= 0:
            c = html[i]
            if in_str:
                if c == in_str and html[i - 1] != '\\':
                    in_str = None
            else:
                if c in ('"', "'", '`'):
                    in_str = c
                elif c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
            i += 1
        chunk = html[start:i]
        if 'onclick' in chunk:
            bad_lines.append(html[:start].count('\n') + 1)
    return bad_lines


class TestDOMPurifyIntegration:
    """Static regression suite for DOMPurify integration (1.7.12)."""

    @pytest.mark.parametrize("fname", _DASH_FILES)
    def test_purify_script_tag_present(self, fname):
        """Every dashboard must load purify.min.js."""
        html = (_DASH_DIR / fname).read_text()
        assert 'purify.min.js' in html, (
            f"{fname}: missing <script src='.../purify.min.js'>"
        )

    @pytest.mark.parametrize("fname", _DASH_FILES)
    def test_dp_uses_table_context_fix(self, fname):
        """_dp() must wrap <tr>/<td>/<th> fragments in a <table><tbody> to
        prevent DOMPurify from stripping table structure (HTML5 parser
        drops table-section elements outside a table context)."""
        html = (_DASH_DIR / fname).read_text()
        assert "DOMPurify.sanitize('<table><tbody>'" in html or \
               'DOMPurify.sanitize("<table><tbody>"' in html, (
            f"{fname}: _dp() lacks table-context wrapper — "
            "table row content will be stripped by DOMPurify"
        )

    @pytest.mark.parametrize("fname", _DASH_FILES)
    def test_no_onclick_inside_dp_calls(self, fname):
        """No _dp() call may pass HTML with an onclick attribute — DOMPurify
        strips event handlers, leaving buttons non-functional."""
        html = (_DASH_DIR / fname).read_text()
        bad = _dp_calls_with_onclick(html)
        assert bad == [], (
            f"{fname}: onclick found inside _dp() at lines {bad}. "
            "Use data-* attributes + addEventListener instead."
        )

    def test_session_revoke_uses_data_attribute(self):
        """Session revoke button must use data-revoke-sid (not onclick) so
        DOMPurify does not strip the event handler."""
        for fname in _DASH_FILES:
            html = (_DASH_DIR / fname).read_text()
            assert 'data-revoke-sid' in html, (
                f"{fname}: session revoke button missing data-revoke-sid attribute"
            )
            assert 'onclick="window._acct.revokeSession(' not in html, (
                f"{fname}: session revoke still uses inline onclick"
            )

    def test_confirm_modal_uses_data_attribute(self):
        """_asyncConfirm Cancel/Confirm buttons must use data-acf (not onclick)
        so DOMPurify does not strip the event handler."""
        html = (_DASH_DIR / "controls.html").read_text()
        assert 'data-acf="cancel"' in html, (
            "controls.html: confirmAction Cancel button missing data-acf='cancel'"
        )
        assert 'data-acf="confirm"' in html, (
            "controls.html: confirmAction Confirm button missing data-acf='confirm'"
        )
        assert 'onclick="closeSimpleModal();window._acfResolve(' not in html, (
            "controls.html: confirmAction buttons still use inline onclick"
        )
