"""1.8.11 — Attack Playbook: honeypot/trap catches grouped by technique, shown
in a new educational area at the bottom of the Agents dashboard.

Backend: GET /secured/attack-playbook?mins=… → {groups:[{reason,count,examples,
last_ts}], mins, ts} for honeypot-family reasons only.
Frontend: agents.html renders grouped cards (what / caught requests / defense).
"""
import asyncio
import sqlite3
import time
import pathlib
from contextlib import asynccontextmanager

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

NS = "/antibot-appsec-gateway/secured"
AGENTS = (pathlib.Path(__file__).resolve().parent.parent /
          "dashboards" / "agents.html").read_text(encoding="utf-8")
# 1.8.12: attack playbook + honey-suggest moved to honeypots.html
HONEYPOTS = (pathlib.Path(__file__).resolve().parent.parent /
             "dashboards" / "honeypots.html").read_text(encoding="utf-8")

HONEYPOT_REASONS = ["honeypot", "honeypot-silent", "bot-trap",
                    "honey-cred", "canary-echo", "canary-probe-miss"]


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


async def _echo(request):
    return web.json_response({"ok": True})


@asynccontextmanager
async def _spin_proxy(proxy_module, upstream):
    proxy_module.UPSTREAM = upstream
    app = proxy_module.make_app()
    client = TestClient(TestServer(app))
    await client.start_server()
    yield client
    await client.close()


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_route("*", "/{t:.*}", _echo)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    await runner.cleanup()


def _admin_cookie(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False}
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _seed(proxy_module, rows):
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.executemany(
        "INSERT INTO events (ts, ip, ua, path, method, status, reason) "
        "VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit(); conn.close()


# ── backend ──────────────────────────────────────────────────────────────────

def test_endpoint_and_route_exist():
    import os, importlib
    os.environ.setdefault("UPSTREAM", "https://example.com")
    p = importlib.import_module("core.proxy_handler")
    assert callable(p.attack_playbook_endpoint)
    assert p._PLAYBOOK_REASONS == HONEYPOT_REASONS
    proxy_src = (pathlib.Path(__file__).resolve().parent.parent / "proxy.py").read_text()
    assert '"attack-playbook"' in proxy_src and "attack_playbook_endpoint" in proxy_src


def test_playbook_groups_honeypot_only(proxy_module):
    now = time.time()
    def go():
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    conn.execute("DELETE FROM events"); conn.commit(); conn.close()
                    _seed(proxy_module, [
                        (now-10, "1.1.1.1", "UA", "/.env",        "GET",  404, "honeypot"),
                        (now-20, "1.1.1.2", "UA", "/wp-admin/",   "GET",  404, "honeypot"),
                        (now-30, "2.2.2.2", "UA", "/login",       "POST", 403, "honey-cred"),
                        (now-40, "3.3.3.3", "UA", "/search?q=x",  "GET",  200, "ai-probe"),  # NOT honeypot
                    ])
                    cookie = _admin_cookie(proxy_module)
                    r = await c.get(NS + "/attack-playbook?mins=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    assert r.status == 200, f"got {r.status}"
                    d = await r.json()
                    reasons = {g["reason"] for g in d["groups"]}
                    assert "honeypot" in reasons and "honey-cred" in reasons
                    assert "ai-probe" not in reasons, "non-honeypot reason leaked into playbook"
                    hp = next(g for g in d["groups"] if g["reason"] == "honeypot")
                    assert hp["count"] == 2
                    paths = {e["path"] for e in hp["examples"]}
                    assert "/.env" in paths and "/wp-admin/" in paths
                    assert "no-store" in (r.headers.get("Cache-Control", ""))
        _run(_t())
    go()


def test_mins_param_clamped(proxy_module):
    def go():
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    cookie = _admin_cookie(proxy_module)
                    r = await c.get(NS + "/attack-playbook?mins=999999",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    assert d["mins"] <= 10080, "mins not clamped to 7 days"
        _run(_t())
    go()


def test_honeypot_silent_not_double_counted(proxy_module):
    """Regression: 'honeypot' is a substring of 'honeypot-silent'. A LIKE-based
    query made the honeypot group swallow every honeypot-silent row (count and
    examples). Exact reason_in must keep the two groups disjoint."""
    now = time.time()
    def go():
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    conn.execute("DELETE FROM events"); conn.commit(); conn.close()
                    _seed(proxy_module, [
                        (now-1, "1.1.1.1", "UA", "/.env",          "GET", 404, "honeypot"),
                        (now-2, "1.1.1.2", "UA", "/wp-admin/",     "GET", 404, "honeypot"),
                        (now-3, "1.1.1.3", "UA", "/admin.php",     "GET", 404, "honeypot"),
                        (now-4, "2.2.2.2", "UA", "/.git/HEAD",     "GET", 404, "honeypot-silent"),
                        (now-5, "2.2.2.3", "UA", "/server-status", "GET", 404, "honeypot-silent"),
                    ])
                    cookie = _admin_cookie(proxy_module)
                    r = await c.get(NS + "/attack-playbook?mins=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    gm = {g["reason"]: g for g in d["groups"]}
                    assert gm["honeypot"]["count"] == 3, \
                        f'honeypot double-counted: {gm["honeypot"]["count"]} (want 3)'
                    assert gm["honeypot-silent"]["count"] == 2
                    hp_paths = {e["path"] for e in gm["honeypot"]["examples"]}
                    assert "/.git/HEAD" not in hp_paths and "/server-status" not in hp_paths, \
                        "honeypot-silent paths leaked into honeypot examples"
        _run(_t())
    go()


def test_scanner_detection_uses_full_row_set_not_examples(proxy_module):
    """Regression: scanner-sequence matching previously ran on the ≤6 deduped
    examples, so a scanner IP whose hits fall outside the example window was
    missed. It must match against every row's per-IP path set."""
    now = time.time()
    def go():
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    conn.execute("DELETE FROM events"); conn.commit(); conn.close()
                    rows = [
                        # 6 newest benign honeypot hits push the scanner's older
                        # hits out of the 6-example window.
                        (now-1, "8.0.0.1", "UA", "/trap1", "GET", 404, "honeypot"),
                        (now-2, "8.0.0.2", "UA", "/trap2", "GET", 404, "honeypot"),
                        (now-3, "8.0.0.3", "UA", "/trap3", "GET", 404, "honeypot"),
                        (now-4, "8.0.0.4", "UA", "/trap4", "GET", 404, "honeypot"),
                        (now-5, "8.0.0.5", "UA", "/trap5", "GET", 404, "honeypot"),
                        (now-6, "8.0.0.6", "UA", "/trap6", "GET", 404, "honeypot"),
                        # nuclei signature triad from one IP (older → outside examples)
                        (now-7, "9.9.9.9", "UA", "/.git/config",     "GET", 404, "honeypot"),
                        (now-8, "9.9.9.9", "UA", "/.git/HEAD",       "GET", 404, "honeypot"),
                        (now-9, "9.9.9.9", "UA", "/.env",            "GET", 404, "honeypot"),
                    ]
                    _seed(proxy_module, rows)
                    cookie = _admin_cookie(proxy_module)
                    r = await c.get(NS + "/attack-playbook?mins=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    hits = {h["ip"]: h for h in d.get("scanner_hits", [])}
                    assert "9.9.9.9" in hits, \
                        "scanner IP missed — match did not use full per-IP path set"
                    assert hits["9.9.9.9"]["scanner"] == "nuclei"
                    assert len(hits["9.9.9.9"]["matched"]) >= 2
        _run(_t())
    go()


def test_predicted_probes_completes_scanner_signature(proxy_module):
    """1.8.12 F5: once an IP is fingerprinted to a tool (≥2 signature hits), the
    tool's UN-hit signature paths must surface as predicted_probes (minus any
    path already in the active trap set)."""
    now = time.time()
    def go():
        async def _t():
            async with _spin_upstream() as up:
                async with _spin_proxy(proxy_module, up) as c:
                    conn = sqlite3.connect(proxy_module.DB_PATH)
                    conn.execute("DELETE FROM events"); conn.commit(); conn.close()
                    # one IP hits 2 nuclei sigs → fingerprinted as nuclei
                    _seed(proxy_module, [
                        (now-5, "5.5.5.5", "UA", "/.git/config", "GET", 404, "honeypot"),
                        (now-6, "5.5.5.5", "UA", "/.git/HEAD",   "GET", 404, "honeypot"),
                    ])
                    cookie = _admin_cookie(proxy_module)
                    r = await c.get(NS + "/attack-playbook?mins=60",
                                    cookies={proxy_module._SESSION_COOKIE: cookie})
                    d = await r.json()
                    pred = {p["path"]: p for p in d.get("predicted_probes", [])}
                    # predicted = nuclei signature − hit − already-trapped.
                    # /actuator/health is the only nuclei sig that is neither hit
                    # nor in the default trap set, so it must be predicted.
                    assert "/actuator/health" in pred, "untrapped sig not predicted"
                    assert "nuclei" in pred["/actuator/health"]["tools"]
                    # hit paths must never be re-listed as predicted
                    assert "/.git/config" not in pred and "/.git/HEAD" not in pred
        _run(_t())
    go()


# ── frontend (honeypots.html) ────────────────────────────────────────────────
# 1.8.12: attack playbook + honey-suggest moved from agents.html to honeypots.html

def test_agents_has_playbook_card():
    assert 'id="attack-playbook-card"' in HONEYPOTS
    assert 'id="playbook-body"' in HONEYPOTS
    assert "Attack playbook" in HONEYPOTS


def test_playbook_fetches_endpoint_and_renders_safely():
    assert "secured/attack-playbook" in HONEYPOTS
    # examples rendered through escapeHtml (no unescaped path injection)
    assert "escapeHtml(e.path)" in HONEYPOTS and "escapeHtml(e.method)" in HONEYPOTS
    # interval tracked in _timers (stage-17 leak prevention)
    assert "_timers.push(setInterval(loadPlaybook" in HONEYPOTS


def test_playbook_meta_covers_all_reasons():
    for reason in HONEYPOT_REASONS:
        assert f'"{reason}":' in HONEYPOTS, f"PLAYBOOK_META missing {reason!r}"


def test_playbook_shows_defense_control():
    # each technique links its governing control knob + live state
    assert "SIGNAL_KNOB_JS[reason]" in HONEYPOTS
    assert "/antibot-appsec-gateway/secured/controls" in HONEYPOTS
