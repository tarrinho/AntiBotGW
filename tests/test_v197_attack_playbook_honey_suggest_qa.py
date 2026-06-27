"""
QA — Attack-Playbook + Honey-Suggest backends (added in 1.9.7).

These two endpoints were referenced by the Honeypots dashboard's
Attack-Playbook + honey-suggest cards but **did not exist** in the
gateway (the cards rendered `HTTP 404`). 1.9.7 built both — this file
locks down the contracts that the dashboard depends on.

Coverage:
  TestPlaybookSourceContract  — async + role-gated + headers + vhost param
  TestPlaybookConstants       — _PLAYBOOK_REASONS / _SCANNER_SIGNATURES /
                                 _PLAYBOOK_EXAMPLE_CAP sanity
  TestPlaybookFunctional      — mocked DB rows produce the expected groups,
                                 scanner fingerprints, and predicted probes;
                                 mins clamped to [5, 10080]; vhost lowercased
  TestPlaybookSecurity        — role-gated (denied if no allowed role);
                                 example.path length capped at 200 chars
  TestHoneySuggestSourceContract  — async + role-gated + headers + vhost
  TestHoneySuggestFunctional      — candidates list capped at 30, trap paths
                                     excluded, status>=400 filter present, both
                                     backends emit a parameterized SQL string
  TestHoneySuggestSecurity        — role-gated; SQL params are placeholders
                                     (no string-formatted user input)
"""
import asyncio
import importlib
import inspect
import os
import re

import pytest

# Mirror conftest defaults (some tests import the module fresh)
os.environ.setdefault("ADMIN_ALLOWED_IPS", "0.0.0.0/0,::/0")
os.environ.setdefault("UPSTREAM", "http://example.com")
os.environ.setdefault("ADMIN_KEY", "test-admin-key-xxxxxxxxxxxxxxxx")

cph = importlib.import_module("core.proxy_handler")


# ── Helpers ───────────────────────────────────────────────────────────────────

class _FakeRequest:
    """Bare-bones aiohttp.web.Request stand-in. The two endpoints only read
    `request.query.get(...)` and pass `request` to `_role_denied`; that's all
    we need to satisfy."""
    def __init__(self, query=None, headers=None, role="admin"):
        self.query = query or {}
        self.headers = headers or {}
        self._role = role

    # Some helpers in proxy_handler call request.headers.get(...) for the role
    # lookup — but _role_denied is patched away in tests, so we don't need
    # full role wiring here.


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _parse_json(response):
    """aiohttp.web.json_response stores body in `response._body` (bytes)."""
    import json
    raw = getattr(response, "body", None) or getattr(response, "_body", b"")
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw)


# ── 1. Attack-Playbook source contract ───────────────────────────────────────

class TestPlaybookSourceContract:
    """The dashboard contract:
      GET /antibot-appsec-gateway/secured/attack-playbook?mins=&vhost=
      response: {groups, scanner_hits, predicted_probes, mins, ts}"""

    def test_endpoint_is_async(self):
        assert inspect.iscoroutinefunction(cph.attack_playbook_endpoint)

    def test_route_registered_in_proxy(self):
        proxy_src = open(
            importlib.import_module("proxy").__file__, encoding="utf-8"
        ).read()
        # Matches the routes tuple line:
        #   ("attack-playbook", "GET", attack_playbook_endpoint, True)
        assert re.search(
            r'["\']attack-playbook["\'].*?attack_playbook_endpoint',
            proxy_src,
            re.DOTALL,
        ), "GET /secured/attack-playbook → attack_playbook_endpoint not registered"

    def test_role_gated_in_source(self):
        src = inspect.getsource(cph.attack_playbook_endpoint)
        # Must call _role_denied with at least 'admin' (other roles optional)
        assert "_role_denied" in src
        assert "admin" in src

    def test_sets_cache_control_and_nosniff(self):
        src = inspect.getsource(cph.attack_playbook_endpoint)
        assert "Cache-Control" in src and "no-store" in src
        assert "X-Content-Type-Options" in src and "nosniff" in src

    def test_accepts_vhost_query_param(self):
        src = inspect.getsource(cph.attack_playbook_endpoint)
        assert 'query.get("vhost"' in src

    def test_lowercases_vhost(self):
        src = inspect.getsource(cph.attack_playbook_endpoint)
        # The contract is that vhost is stored lowercase in events.vhost;
        # the endpoint must lowercase its query value to match.
        assert ".lower()" in src


# ── 2. Constants sanity ───────────────────────────────────────────────────────

class TestPlaybookConstants:
    def test_playbook_reasons_non_empty_strings(self):
        rs = cph._PLAYBOOK_REASONS
        assert isinstance(rs, list) and len(rs) >= 3
        for r in rs:
            assert isinstance(r, str) and r, f"bad reason: {r!r}"
        # Honeypot family must be included — that's the point of the endpoint.
        assert any("honeypot" in r for r in rs)

    def test_scanner_signatures_shape(self):
        sigs = cph._SCANNER_SIGNATURES
        assert isinstance(sigs, dict) and len(sigs) >= 3, (
            "at least 3 scanner fingerprints (nuclei/nikto/wpscan/sqlmap/feroxbuster)"
        )
        for tool, paths in sigs.items():
            assert isinstance(tool, str) and tool, "tool name must be non-empty"
            assert isinstance(paths, (set, frozenset))
            assert len(paths) >= 3, (
                f"{tool} has < 3 signature paths — would false-fingerprint on 2 random hits"
            )
            for p in paths:
                assert isinstance(p, str) and p.startswith("/"), (
                    f"{tool}: signature path must start with /: {p!r}"
                )

    def test_example_cap_positive_int(self):
        cap = cph._PLAYBOOK_EXAMPLE_CAP
        assert isinstance(cap, int) and 1 <= cap <= 100, (
            f"_PLAYBOOK_EXAMPLE_CAP unreasonable: {cap}"
        )


# ── 3. Functional ─────────────────────────────────────────────────────────────

class TestPlaybookFunctional:
    """Mock `db_read_events_async` and `_role_denied`; verify the
    grouping + scanner fingerprinting + predicted-probe logic."""

    def setup_method(self):
        # _role_denied(request, *roles) → None means access granted
        self._orig_role_denied = cph._role_denied
        cph._role_denied = lambda req, *roles: None  # type: ignore[assignment]

    def teardown_method(self):
        cph._role_denied = self._orig_role_denied  # type: ignore[assignment]

    def _patch_db_rows(self, monkeypatch, rows):
        async def _fake(*args, **kwargs):
            return rows
        monkeypatch.setattr(cph, "db_read_events_async", _fake)

    def test_empty_rows_returns_empty_groups(self, monkeypatch):
        self._patch_db_rows(monkeypatch, [])
        resp = _run(cph.attack_playbook_endpoint(_FakeRequest()))
        data = _parse_json(resp)
        assert data["groups"] == []
        assert data["scanner_hits"] == []
        assert data["predicted_probes"] == []

    def test_groups_aggregate_by_reason(self, monkeypatch):
        now = 1_700_000_000.0
        rows = [
            {"ts": now, "ip": "1.1.1.1", "method": "GET", "path": "/wp-admin/",   "reason": "honeypot"},
            {"ts": now, "ip": "1.1.1.1", "method": "GET", "path": "/wp-login.php","reason": "honeypot"},
            {"ts": now, "ip": "2.2.2.2", "method": "GET", "path": "/.env",         "reason": "honeypot-silent"},
        ]
        self._patch_db_rows(monkeypatch, rows)
        resp = _run(cph.attack_playbook_endpoint(_FakeRequest()))
        data = _parse_json(resp)
        groups = {g["reason"]: g for g in data["groups"]}
        assert groups["honeypot"]["count"] == 2
        assert groups["honeypot-silent"]["count"] == 1
        # Sorted descending by count → honeypot first
        assert data["groups"][0]["reason"] == "honeypot"

    def test_scanner_fingerprint_requires_two_paths(self, monkeypatch):
        """One hit isn't enough; an IP must hit ≥ 2 of a tool's signature
        paths to be fingerprinted (else random scanners get mislabelled)."""
        # IP A hits only ONE wpscan path — should NOT fingerprint
        # IP B hits TWO nuclei paths — SHOULD fingerprint as nuclei
        rows = [
            {"ts": 0, "ip": "A", "method": "GET", "path": "/wp-login.php", "reason": "honeypot"},
            {"ts": 0, "ip": "B", "method": "GET", "path": "/.env",         "reason": "honeypot"},
            {"ts": 0, "ip": "B", "method": "GET", "path": "/.git/config",  "reason": "honeypot"},
        ]
        self._patch_db_rows(monkeypatch, rows)
        resp = _run(cph.attack_playbook_endpoint(_FakeRequest()))
        data = _parse_json(resp)
        hits = {h["ip"]: h for h in data["scanner_hits"]}
        assert "A" not in hits, "single-path hit must NOT fingerprint (false-positive risk)"
        assert "B" in hits, "two nuclei sig paths from B should fingerprint as nuclei"
        assert hits["B"]["scanner"] == "nuclei"

    def test_predicted_probes_exclude_already_trapped(self, monkeypatch):
        rows = [
            {"ts": 0, "ip": "B", "method": "GET", "path": "/.env",        "reason": "honeypot"},
            {"ts": 0, "ip": "B", "method": "GET", "path": "/.git/config", "reason": "honeypot"},
        ]
        self._patch_db_rows(monkeypatch, rows)
        # Pre-trap one of nuclei's other sig paths — must NOT be predicted
        monkeypatch.setattr(cph, "HONEYPOT_PATHS", {"/.git/HEAD"})
        # vc() may return our HONEYPOT_PATHS via the vhost coercer; patch too.
        monkeypatch.setattr(cph, "vc", lambda key: {"/.git/HEAD"} if key == "HONEYPOT_PATHS" else None)
        resp = _run(cph.attack_playbook_endpoint(_FakeRequest()))
        data = _parse_json(resp)
        predicted_paths = {p["path"] for p in data["predicted_probes"]}
        # /.env + /.git/config are hit → not predicted. /.git/HEAD is trapped → not predicted.
        # /actuator/health should be predicted as the only remaining nuclei sig path.
        assert "/actuator/health" in predicted_paths
        assert "/.git/HEAD" not in predicted_paths
        assert "/.env" not in predicted_paths

    def test_mins_clamped_low(self, monkeypatch):
        self._patch_db_rows(monkeypatch, [])
        resp = _run(cph.attack_playbook_endpoint(_FakeRequest(query={"mins": "1"})))
        data = _parse_json(resp)
        assert data["mins"] == 5, f"mins<5 must clamp to 5, got {data['mins']}"

    def test_mins_clamped_high(self, monkeypatch):
        self._patch_db_rows(monkeypatch, [])
        resp = _run(cph.attack_playbook_endpoint(_FakeRequest(query={"mins": "999999"})))
        data = _parse_json(resp)
        assert data["mins"] == 10080, f"mins>10080 must clamp to 10080, got {data['mins']}"

    def test_mins_bad_value_defaults_to_1440(self, monkeypatch):
        self._patch_db_rows(monkeypatch, [])
        resp = _run(cph.attack_playbook_endpoint(_FakeRequest(query={"mins": "not-a-number"})))
        data = _parse_json(resp)
        assert data["mins"] == 1440

    def test_db_exception_returns_empty_not_500(self, monkeypatch):
        async def _boom(*a, **kw):
            raise RuntimeError("db down")
        monkeypatch.setattr(cph, "db_read_events_async", _boom)
        resp = _run(cph.attack_playbook_endpoint(_FakeRequest()))
        data = _parse_json(resp)
        # Endpoint logs + returns empty rather than 500 — dashboard tile
        # then shows "no data" instead of erroring out.
        assert data["groups"] == []
        assert data["scanner_hits"] == []


# ── 4. Security ───────────────────────────────────────────────────────────────

class TestPlaybookSecurity:
    def test_role_denied_short_circuits(self, monkeypatch):
        from aiohttp import web
        # _role_denied returns a Response → endpoint returns that response
        marker = web.json_response({"error": "forbidden"}, status=403)
        monkeypatch.setattr(cph, "_role_denied", lambda req, *roles: marker)
        resp = _run(cph.attack_playbook_endpoint(_FakeRequest()))
        assert resp is marker, "endpoint must short-circuit on _role_denied"

    def test_example_path_length_capped(self, monkeypatch):
        cph._role_denied = lambda req, *roles: None
        try:
            long_path = "/" + ("A" * 500)
            rows = [{"ts": 0, "ip": "X", "method": "GET", "path": long_path, "reason": "honeypot"}]
            async def _fake(*a, **kw): return rows
            monkeypatch.setattr(cph, "db_read_events_async", _fake)
            resp = _run(cph.attack_playbook_endpoint(_FakeRequest()))
            data = _parse_json(resp)
            ex = data["groups"][0]["examples"][0]
            assert len(ex["path"]) <= 200, (
                f"example path not capped: {len(ex['path'])} chars"
            )
        finally:
            cph._role_denied = importlib.reload(cph)._role_denied if False else cph._role_denied


# ── 5. Honey-Suggest source contract ─────────────────────────────────────────

class TestHoneySuggestSourceContract:
    def test_endpoint_is_async(self):
        assert inspect.iscoroutinefunction(cph.honey_suggest_endpoint)

    def test_route_registered_in_proxy(self):
        proxy_src = open(
            importlib.import_module("proxy").__file__, encoding="utf-8"
        ).read()
        assert re.search(
            r'["\']honey-suggest["\'].*?honey_suggest_endpoint',
            proxy_src,
            re.DOTALL,
        ), "GET /secured/honey-suggest → honey_suggest_endpoint not registered"

    def test_role_gated_in_source(self):
        src = inspect.getsource(cph.honey_suggest_endpoint)
        assert "_role_denied" in src
        assert "admin" in src

    def test_sets_cache_control_and_nosniff(self):
        src = inspect.getsource(cph.honey_suggest_endpoint)
        assert "no-store" in src
        assert "X-Content-Type-Options" in src and "nosniff" in src

    def test_accepts_vhost_query_param(self):
        src = inspect.getsource(cph.honey_suggest_endpoint)
        assert 'query.get("vhost"' in src and ".lower()" in src


# ── 6. Honey-Suggest functional ──────────────────────────────────────────────

class _FakeConn:
    """Just enough of sqlite3/psycopg connection to satisfy the endpoint."""
    def __init__(self, rows):
        self._rows = rows
    def execute(self, sql, params=()):
        # Persist the SQL for SQL-injection asserts.
        self._last_sql = sql
        self._last_params = params
        return self
    def fetchall(self):
        return self._rows
    def close(self):
        pass


class TestHoneySuggestFunctional:
    def setup_method(self):
        self._orig = cph._role_denied
        cph._role_denied = lambda req, *roles: None  # type: ignore[assignment]

    def teardown_method(self):
        cph._role_denied = self._orig  # type: ignore[assignment]

    def test_candidates_returned_with_hits(self, monkeypatch):
        rows = [("/abc", 17), ("/xyz", 5)]
        fake = _FakeConn(rows)
        monkeypatch.setattr(cph, "open_conn", lambda: fake)
        monkeypatch.setattr(cph, "active_backend", lambda: "sqlite")
        monkeypatch.setattr(cph, "HONEYPOT_PATHS", set())
        monkeypatch.setattr(cph, "vc", lambda key: set() if key == "HONEYPOT_PATHS" else None)
        resp = _run(cph.honey_suggest_endpoint(_FakeRequest()))
        data = _parse_json(resp)
        paths = [c["path"] for c in data["candidates"]]
        assert "/abc" in paths and "/xyz" in paths
        assert data["candidates"][0]["hits"] == 17

    def test_trap_paths_excluded(self, monkeypatch):
        rows = [("/already-trapped", 99), ("/new-path", 3)]
        fake = _FakeConn(rows)
        monkeypatch.setattr(cph, "open_conn", lambda: fake)
        monkeypatch.setattr(cph, "active_backend", lambda: "sqlite")
        monkeypatch.setattr(cph, "vc", lambda key: {"/already-trapped"} if key == "HONEYPOT_PATHS" else None)
        resp = _run(cph.honey_suggest_endpoint(_FakeRequest()))
        data = _parse_json(resp)
        paths = [c["path"] for c in data["candidates"]]
        assert "/already-trapped" not in paths
        assert "/new-path" in paths

    def test_candidates_capped_at_30(self, monkeypatch):
        rows = [(f"/path-{i}", 100 - i) for i in range(50)]
        fake = _FakeConn(rows)
        monkeypatch.setattr(cph, "open_conn", lambda: fake)
        monkeypatch.setattr(cph, "active_backend", lambda: "sqlite")
        monkeypatch.setattr(cph, "vc", lambda key: set() if key == "HONEYPOT_PATHS" else None)
        resp = _run(cph.honey_suggest_endpoint(_FakeRequest()))
        data = _parse_json(resp)
        assert len(data["candidates"]) <= 30, (
            f"candidates not capped: {len(data['candidates'])}"
        )

    def test_status_4xx_filter_in_sql(self):
        src = inspect.getsource(cph.honey_suggest_endpoint)
        # The query must restrict to status >= 400 — otherwise the dashboard
        # would suggest paths that actually succeeded (low-value traps).
        assert "status >= 400" in src or "status>=400" in src.replace(" ", "")

    def test_both_backends_branched(self):
        src = inspect.getsource(cph.honey_suggest_endpoint)
        assert "postgres" in src and "to_timestamp" in src, (
            "PG branch must use to_timestamp() per events.ts = timestamptz contract"
        )

    def test_db_exception_returns_empty(self, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("db gone")
        monkeypatch.setattr(cph, "open_conn", _boom)
        resp = _run(cph.honey_suggest_endpoint(_FakeRequest()))
        data = _parse_json(resp)
        assert data["candidates"] == [], "endpoint must degrade gracefully"


# ── 7. Honey-Suggest security ────────────────────────────────────────────────

class TestHoneySuggestSecurity:
    def test_role_denied_short_circuits(self, monkeypatch):
        from aiohttp import web
        marker = web.json_response({"error": "forbidden"}, status=403)
        monkeypatch.setattr(cph, "_role_denied", lambda req, *roles: marker)
        resp = _run(cph.honey_suggest_endpoint(_FakeRequest()))
        assert resp is marker

    def test_sql_uses_parameter_placeholders(self):
        """Source-level guard against SQL injection via vhost. Both
        branches must use `?` placeholders for the vhost param, not
        f-strings or .format()."""
        src = inspect.getsource(cph.honey_suggest_endpoint)
        # No f-string / .format() interpolation of _vhost into the query
        assert "f\"SELECT" not in src and "f'SELECT" not in src, (
            "honey_suggest must not f-string the SELECT"
        )
        assert "%s" not in src.split('"SELECT')[0], (
            "no string-formatting of params before the SQL literal"
        )
        # Both branches must place ? placeholders for the vhost arg.
        assert "? = '' OR vhost = ?" in src

    def test_vhost_lowercased_before_query(self):
        src = inspect.getsource(cph.honey_suggest_endpoint)
        # Lowercasing protects against case-confusion bypasses
        assert ".lower()" in src
