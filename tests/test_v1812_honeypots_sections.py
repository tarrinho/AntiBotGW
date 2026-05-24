"""1.8.12 — Honeypots dashboard restructure: sectioned layout (Overview / Traps /
Attackers / Threat intel) + new panels driven by extended honeypots-data:
  - trap_effectiveness  (top trap paths by hits)
  - attackers           (per-IP attack storyboard: ordered steps)
and a scanner-tool leaderboard derived (frontend) from attack-playbook scanner_hits.
"""
import asyncio
import pathlib
import sqlite3
import time
from contextlib import asynccontextmanager

from aiohttp.test_utils import TestClient, TestServer

HTML = (pathlib.Path(__file__).resolve().parent.parent /
        "dashboards" / "honeypots.html").read_text(encoding="utf-8")
NS = "/antibot-appsec-gateway/secured"


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@asynccontextmanager
async def _spin(proxy_module):
    proxy_module.UPSTREAM = "https://example.com"
    c = TestClient(TestServer(proxy_module.make_app()))
    await c.start_server()
    try:
        yield c
    finally:
        await c.close()


def _admin_cookie(proxy_module):
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username": "admin", "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked": False}
    proxy_module._SESSION_CACHE_READY = True
    return proxy_module._session_sign("admin", sid=sid)


def _seed(proxy_module, rows):
    conn = sqlite3.connect(proxy_module.DB_PATH)
    conn.executemany(
        "INSERT INTO events (ts, ip, ua, path, method, status, reason) "
        "VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit(); conn.close()


# ── frontend structure ───────────────────────────────────────────────────────

def test_sectioned_layout_present():
    for sec in ("overview", "traps", "attackers", "intel"):
        assert f'data-sec="{sec}"' in HTML, f"missing section {sec}"
    assert 'class="hp-tabs"' in HTML and "_hpTab" in HTML


def test_new_panels_present():
    for marker in ("trap-eff-body", "storyboard-body", "scanner-lb-body",
                   "renderTrapEffectiveness", "renderStoryboard", "renderScannerTools",
                   "predicted-probes-body", "renderPredictedProbes", "trapAllPredicted"):
        assert marker in HTML, f"missing {marker}"


def test_predicted_probes_wired_and_safe():
    # rendered from the playbook response + escapes the attacker-implied path
    assert "renderPredictedProbes((d && d.predicted_probes)" in HTML
    assert "escapeHtml(p.path)" in HTML


def test_storyboard_escapes_user_data():
    # steps render attacker-controlled path/method/reason — must go through escapeHtml
    assert "escapeHtml(s.path" in HTML and "escapeHtml(s.method" in HTML
    assert "escapeHtml(t.path)" in HTML  # trap effectiveness path


def test_new_renders_wired_into_loaders():
    assert "renderTrapEffectiveness(d.trap_effectiveness)" in HTML
    assert "renderStoryboard(d.attackers)" in HTML
    assert "renderScannerTools(" in HTML


# ── backend: extended honeypots-data ─────────────────────────────────────────

def test_honeypots_data_has_trap_effectiveness_and_attackers(proxy_module):
    now = time.time()
    def go():
        async def _t():
            async with _spin(proxy_module) as c:
                conn = sqlite3.connect(proxy_module.DB_PATH)
                conn.execute("DELETE FROM events"); conn.commit(); conn.close()
                _seed(proxy_module, [
                    (now-10, "7.7.7.7", "UA", "/.env",       "GET",  404, "honeypot"),
                    (now-20, "7.7.7.7", "UA", "/.git/HEAD",  "GET",  404, "honeypot"),
                    (now-30, "7.7.7.7", "UA", "/wp-login.php","POST", 403, "honey-cred"),
                    (now-40, "8.8.8.8", "UA", "/.env",       "GET",  404, "honeypot"),
                ])
                cookie = _admin_cookie(proxy_module)
                r = await c.get(NS + "/honeypots-data?mins=60",
                                cookies={proxy_module._SESSION_COOKIE: cookie})
                assert r.status == 200, r.status
                d = await r.json()
                # trap effectiveness: /.env hit twice → top
                te = {t["path"]: t for t in d["trap_effectiveness"]}
                assert te["/.env"]["hits"] == 2
                assert te["/.git/HEAD"]["hits"] == 1
                # attacker storyboard: 7.7.7.7 has 3 chronological steps
                a = {x["ip"]: x for x in d["attackers"]}
                assert a["7.7.7.7"]["count"] == 3
                steps = a["7.7.7.7"]["steps"]
                assert len(steps) == 3
                # chronological: oldest first
                assert steps[0]["ts"] <= steps[-1]["ts"]
                assert {"method", "path", "reason", "ts"} <= set(steps[0])
        _run(_t())
    go()
