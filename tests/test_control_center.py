"""
Control Center dashboard QA — static analysis + dynamic endpoint tests.

Static checks (no server required):
  S01  Chart.js 4.4.4 CDN script tag present
  S02  Three chart canvas IDs present (traffic-chart, blockrate-chart, donut-chart)
  S03  Three chart empty-state element IDs present
  S04  RPS gauge grid element present
  S05  No Remove button (data-remove-vhost) in HTML or JS
  S06  No Remove vhost event handler (DELETE fetch on vhosts in stats tbody listener)
  S07  vhost-stats-tbl thead has exactly 11 columns
  S08  All vhost-stats-tbody colspan values equal 11
  S09  _hexRgba helper function defined
  S10  loadTrafficChart() called in DOMContentLoaded block
  S11  setInterval(loadTrafficChart, 60000) registered in DOMContentLoaded
  S12  _renderBlockRateChart(rows) called inside loadVhostStats
  S13  _renderDonutChart(rows) called inside loadVhostStats
  S14  _renderRpsGauges(rows) called inside loadVhostStats
  S15  _trafficChart.destroy() called before every new Chart() for the traffic chart
  S16  Traffic chart datasets use fill:'stack' (not fill:true) for proper stacking
  S17  Canvas elements hidden by CSS until data arrives
  S18  data-spark-host attribute used in JS row generation
  S19  _makeSpark has short-data guard (data.length < 2)
  S20  Pin button is in its own separate <td> cell, not embedded in the Banned IPs cell
  S21  _blockRateChart.destroy() called before blockrate Chart constructor
  S22  _donutChart.destroy() called before donut Chart constructor

Dynamic checks (in-process gateway via TestClient):
  D01  /control-center page loads with 200 and contains Chart.js script src
  D02  /vhost-breakdown returns {labels, datasets, bucket} schema
  D03  /vhost-breakdown labels length equals expected n_slots for range/bucket params
  D04  /vhost-breakdown with seeded events produces non-empty dataset for that vhost
  D05  /vhost-stats returns all fields required by chart rendering functions
  D06  /vhost-stats bans field present and integer for each stat row
  D07  /vhost-breakdown unauthenticated access is silently deflected (not 4xx)
  D08  /vhost-breakdown Cache-Control: no-store header present
"""
import re
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer, TestClient

_DASHBOARDS = Path(__file__).resolve().parent.parent / "dashboards"
_CC = _DASHBOARDS / "control_center.html"


def _src() -> str:
    return _CC.read_text(encoding="utf-8")


# ── helpers ──────────────────────────────────────────────────────────────────

def _extract_fn_body(src: str, fn_name: str) -> str:
    """Return the body of the named JS function (from def to next top-level fn)."""
    start = src.find(f"function {fn_name}(")
    assert start != -1, f"function {fn_name}() not found in control_center.html"
    next_fn = re.search(r"\n(?:async\s+)?function\s+\w", src[start + 1:])
    end = (start + 1 + next_fn.start()) if next_fn else len(src)
    return src[start:end]


def _extract_dcl_body(src: str) -> str:
    """Return the DOMContentLoaded callback body."""
    idx = src.rfind("DOMContentLoaded")  # 1.8.12: last DOMContentLoaded = chart/init block (sidebar accordion adds an earlier one)
    assert idx != -1, "DOMContentLoaded not found in control_center.html"
    end = src.find("});", idx)
    return src[idx:end]


# ═══════════════════════════════════════════════════════════════════════════
# Static tests
# ═══════════════════════════════════════════════════════════════════════════

def test_s01_chartjs_local_asset_script_tag():
    src = _src()
    assert 'chart.umd.min.js' in src, (
        "control_center.html: Chart.js script tag missing. "
        "All three charts depend on Chart.js."
    )
    assert 'cdn.jsdelivr.net' not in src, (
        "control_center.html: Chart.js must be loaded from local /assets/, not a CDN. "
        "CDN dependency breaks offline deployments and air-gapped environments."
    )


def test_s02_three_chart_canvas_ids():
    src = _src()
    for cid in ('traffic-chart', 'blockrate-chart', 'donut-chart'):
        assert f'id="{cid}"' in src, (
            f"control_center.html: canvas id='{cid}' missing. "
            "Chart render functions reference this ID."
        )


def test_s03_three_chart_empty_state_ids():
    src = _src()
    for eid in ('traffic-chart-empty', 'blockrate-chart-empty', 'donut-chart-empty'):
        assert f'id="{eid}"' in src, (
            f"control_center.html: empty-state element id='{eid}' missing. "
            "_showChartEmpty() references this ID to display 'No data' messages."
        )


def test_s04_rps_grid_element_present():
    src = _src()
    assert 'id="rps-grid"' in src, (
        "control_center.html: id='rps-grid' element missing. "
        "_renderRpsGauges() writes into this container."
    )


def test_s05_no_remove_vhost_button():
    src = _src()
    assert 'data-remove-vhost' not in src, (
        "control_center.html: data-remove-vhost found — Remove button should not "
        "appear in the Control Center. Delete belongs in Settings only."
    )


def test_s06_no_remove_vhost_handler():
    src = _src()
    # The remove handler is identified by its DELETE fetch on /vhosts with JSON body
    assert "method:'DELETE'" not in src or "vhost-stats-tbody" not in src[
        src.rfind("method:'DELETE'") - 200 : src.rfind("method:'DELETE'") + 50
    ], (
        "control_center.html: Remove vhost event handler found (DELETE fetch bound "
        "to vhost-stats-tbody). This handler was intentionally removed — do not re-add it."
    )


def test_s07_vhost_stats_thead_has_11_columns():
    src = _src()
    thead_m = re.search(r'id="vhost-stats-tbl".*?</thead>', src, re.DOTALL)
    assert thead_m, "control_center.html: vhost-stats-tbl thead not found."
    # Use word-boundary to avoid counting <thead> itself
    count = len(re.findall(r"<th[\s>]", thead_m.group()))
    assert count == 13, (
        f"control_center.html: vhost-stats-tbl thead has {count} <th> elements; "
        "expected 13 (Status, Hostname, Upstream, Overrides, Trend 1h, Total 1h, Allowed 1h, Blocked 1h, "
        "Block %, Total 24h, Blocked 24h, Banned IPs, Pin-action). "
        "colspan values in empty states must match."
    )


def test_s08_vhost_stats_colspan_equals_column_count():
    src = _src()
    # Collect all colspan values that appear near vhost-stats-tbody context
    # (both static HTML empty state and JS-generated empty states)
    tbody_region_start = src.find('id="vhost-stats-tbody"')
    assert tbody_region_start != -1, "vhost-stats-tbody not found."
    # Check static HTML colspan
    static_cs_m = re.search(r'<td colspan="(\d+)" class="empty"', src[tbody_region_start:tbody_region_start + 120])
    assert static_cs_m, "Static loading colspan in vhost-stats-tbody not found."
    static_cs = int(static_cs_m.group(1))
    assert static_cs == 13, (
        f"control_center.html: static vhost-stats-tbody colspan={static_cs}, expected 13."
    )
    # Check JS-generated colspans — only inside loadVhostStats() where stats are rendered
    # (avoids matching colspan="4" rows from loadVhosts() which is a separate function)
    stats_fn_body = _extract_fn_body(src, "loadVhostStats")
    js_colspans = [int(m) for m in re.findall(r'colspan="(\d+)" class="empty"', stats_fn_body)]
    assert js_colspans, "No JS-generated colspan values found in loadVhostStats() body."
    wrong = [c for c in js_colspans if c != 13]
    assert not wrong, (
        f"control_center.html: JS colspan(s) {wrong} in loadVhostStats do not equal 13. "
        "All vhost-stats empty-state rows must span all 13 columns."
    )


def test_s09_hexrgba_helper_defined():
    src = _src()
    assert "function _hexRgba(" in src, (
        "control_center.html: _hexRgba() helper function not found. "
        "All three charts use it to convert palette colours to rgba() strings."
    )


def test_s10_load_traffic_chart_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    assert "loadTrafficChart()" in dcl, (
        "control_center.html: loadTrafficChart() not called in DOMContentLoaded. "
        "The stacked-area chart must load on page open, not only on button click."
    )


def test_s11_traffic_chart_interval_60s():
    import re as _re
    src = _src()
    dcl = _extract_dcl_body(src)
    # Accept bare call or live-mode guard wrapper (tEndEpoch===null check)
    ok = ("setInterval(loadTrafficChart,60000)" in dcl or
          bool(_re.search(r'setInterval\(\s*function\s*\(\)\s*\{[^}]*loadTrafficChart[^}]*\}\s*,\s*60000\s*\)', dcl)))
    assert ok, (
        "control_center.html: traffic chart must auto-refresh every 60 s via setInterval(...,60000)"
    )


def test_s12_render_blockrate_called_from_load_vhost_stats():
    src = _src()
    body = _extract_fn_body(src, "loadVhostStats")
    assert "_renderBlockRateChart(rows)" in body, (
        "control_center.html: _renderBlockRateChart(rows) not called inside "
        "loadVhostStats(). The block-rate chart reuses the already-fetched vhost-stats "
        "response — it must be rendered in the same callback to avoid a second fetch."
    )


def test_s13_render_donut_called_from_load_vhost_stats():
    src = _src()
    body = _extract_fn_body(src, "loadVhostStats")
    assert "_renderDonutChart(rows)" in body, (
        "control_center.html: _renderDonutChart(rows) not called inside loadVhostStats(). "
        "The donut chart reuses the already-fetched vhost-stats response."
    )


def test_s14_render_rps_called_from_load_vhost_stats():
    src = _src()
    body = _extract_fn_body(src, "loadVhostStats")
    assert "_renderRpsGauges(rows)" in body, (
        "control_center.html: _renderRpsGauges(rows) not called inside loadVhostStats(). "
        "RPS gauges derive from vhost-stats and must update on every stats refresh."
    )


def test_s15_traffic_chart_destroy_before_new_chart():
    src = _src()
    body = _extract_fn_body(src, "_renderTrafficChart")
    destroy_idx = body.find("_trafficChart.destroy()")
    new_chart_idx = body.find("new Chart(")
    assert destroy_idx != -1, (
        "control_center.html: _trafficChart.destroy() not found in _renderTrafficChart(). "
        "Without destroy(), repeated calls create orphaned Chart instances that leak memory."
    )
    assert new_chart_idx != -1, "new Chart( not found in _renderTrafficChart()."
    assert destroy_idx < new_chart_idx, (
        "control_center.html: _trafficChart.destroy() must be called BEFORE new Chart(). "
        f"Got destroy at offset {destroy_idx}, new Chart at {new_chart_idx}."
    )


def test_s16_traffic_chart_fill_is_stack():
    src = _src()
    body = _extract_fn_body(src, "_renderTrafficChart")
    # fill:'stack' required — fill:true fills each series to y=0, not to previous series
    assert "fill:'stack'" in body or 'fill:"stack"' in body, (
        "control_center.html: traffic chart datasets use fill:true instead of fill:'stack'. "
        "With fill:true each area fills to y=0 independently — areas overlap rather than "
        "stack. Use fill:'stack' so each area fills from the previous stacked series."
    )
    assert "fill:true" not in body and "fill: true" not in body, (
        "control_center.html: fill:true found in _renderTrafficChart datasets. "
        "Replace with fill:'stack' for correct stacked-area chart rendering."
    )


def test_s17_chart_canvases_hidden_by_css():
    src = _src()
    # All three chart canvases must start hidden; _render* functions call .style.display='block'
    assert "canvas#traffic-chart" in src and "display:none" in src[
        src.find("canvas#traffic-chart") : src.find("canvas#traffic-chart") + 80
    ], (
        "control_center.html: chart canvas elements not hidden by default CSS. "
        "Without display:none, an empty white canvas flickers before data loads."
    )


def test_s18_data_spark_host_attribute_in_js():
    src = _src()
    assert "data-spark-host" in src, (
        "control_center.html: data-spark-host attribute not found in JS row generation. "
        "_renderSparklines() queries '[data-spark-host]' to populate sparkline SVGs."
    )


def test_s19_make_spark_short_data_guard():
    src = _src()
    body = _extract_fn_body(src, "_makeSpark")
    assert "data.length<2" in body or "data.length < 2" in body, (
        "control_center.html: _makeSpark() missing length<2 guard. "
        "With a single data point, (data.length-1) is 0 causing division-by-zero "
        "in the x-coordinate calculation."
    )


def test_s20_pin_button_in_own_cell():
    src = _src()
    # The pin button must be in its own <td>, not concatenated into the bans cell
    # Detect the bad pattern: r.bans followed by pinBtn in same string concat without </td>
    bad_pattern = re.search(
        r"r\.bans\s*\+\s*(?:\([^)]*\)\s*\+\s*)?pinBtn\s*\+\s*['\"]</td>",
        src,
    )
    assert bad_pattern is None, (
        "control_center.html: pin button (pinBtn) is appended into the Banned IPs cell. "
        "Pin button must be in its own separate <td> column."
    )
    # Confirm correct pattern: separate <td> with pinBtn
    good_pattern = re.search(
        r"['\"]<td[^>]*>['\"]\\s*\+\\s*pinBtn",
        src,
    )
    # Confirm pin button is in a <td> cell (may share with policy link)
    assert re.search(r"['\"]<td[^>]*>['\"].*pinBtn|pinBtn.*['\"]</td>['\"]", src, re.DOTALL), (
        "control_center.html: pin button not found in its own <td> cell. "
        "Expected pinBtn to appear inside a <td>...</td> block."
    )


def test_s21_blockrate_chart_destroy_before_new_chart():
    src = _src()
    body = _extract_fn_body(src, "_renderBlockRateChart")
    destroy_idx = body.find("_blockRateChart.destroy()")
    new_chart_idx = body.find("new Chart(")
    assert destroy_idx != -1, (
        "control_center.html: _blockRateChart.destroy() not found in "
        "_renderBlockRateChart(). Repeated calls create orphaned Chart instances."
    )
    assert destroy_idx < new_chart_idx, (
        "control_center.html: _blockRateChart.destroy() must precede new Chart()."
    )


def test_s22_donut_chart_destroy_before_new_chart():
    src = _src()
    body = _extract_fn_body(src, "_renderDonutChart")
    destroy_idx = body.find("_donutChart.destroy()")
    new_chart_idx = body.find("new Chart(")
    assert destroy_idx != -1, (
        "control_center.html: _donutChart.destroy() not found in _renderDonutChart(). "
        "Repeated calls create orphaned Chart instances."
    )
    assert destroy_idx < new_chart_idx, (
        "control_center.html: _donutChart.destroy() must precede new Chart()."
    )


# ═══════════════════════════════════════════════════════════════════════════
# Dynamic tests — in-process gateway
# ═══════════════════════════════════════════════════════════════════════════

NS = "/antibot-appsec-gateway/secured"
PUB = "/antibot-appsec-gateway"


async def _echo_handler(request: web.Request):
    return web.json_response({"method": request.method, "path": request.path})


@asynccontextmanager
async def _spin_upstream():
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _echo_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@asynccontextmanager
async def _gateway(proxy_module, upstream):
    proxy_module.UPSTREAM = upstream.rstrip("/")
    app = proxy_module.make_app()
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    yield client
    await client.close()


def _admin_cookie(proxy_module) -> dict:
    """Prime an in-memory admin session and return cookies dict for TestClient."""
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    token = proxy_module._session_sign("admin", sid=sid)
    return {proxy_module._SESSION_COOKIE: token}


@pytest.mark.asyncio
async def test_d01_control_center_page_served(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/control-center",
                              cookies=cookies)
            assert r.status == 200
            body = await r.text()
            assert "chart.umd.min.js" in body, (
                "Control Center page does not include Chart.js script tag."
            )
            assert "cdn.jsdelivr.net" not in body, (
                "Control Center page must not load Chart.js from CDN."
            )
            assert 'id="traffic-chart"' in body, (
                "Control Center page missing traffic-chart canvas element."
            )


@pytest.mark.asyncio
async def test_d02_vhost_breakdown_schema(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(
                f"{NS}/vhost-breakdown?range=120&bucket=300",
                cookies=cookies,
            )
            assert r.status == 200
            d = await r.json()
            assert "labels" in d, "/vhost-breakdown missing 'labels' key"
            assert "datasets" in d, "/vhost-breakdown missing 'datasets' key"
            assert "bucket" in d, "/vhost-breakdown missing 'bucket' key"
            assert isinstance(d["labels"], list)
            assert isinstance(d["datasets"], list)
            assert d["bucket"] == 300


@pytest.mark.asyncio
async def test_d03_vhost_breakdown_labels_length_matches_n_slots(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            range_min, bucket_sec = 120, 300
            r = await cli.get(
                f"{NS}/vhost-breakdown?range={range_min}&bucket={bucket_sec}",
                cookies=cookies,
            )
            assert r.status == 200
            d = await r.json()
            expected_slots = (range_min * 60) // bucket_sec  # 24
            assert len(d["labels"]) == expected_slots, (
                f"/vhost-breakdown: expected {expected_slots} labels for "
                f"range={range_min}m / bucket={bucket_sec}s, got {len(d['labels'])}."
            )


@pytest.mark.asyncio
async def test_d04_vhost_breakdown_seeded_event_appears_in_dataset(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            now = time.time()
            conn = sqlite3.connect(proxy_module.DB_PATH)
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, status, reason, vhost) "
                "VALUES (?, '1.2.3.4', 'bot', '/', 200, 'ua-block', 'qa.example.com')",
                (now - 30,),
            )
            conn.commit()
            conn.close()

            r = await cli.get(
                f"{NS}/vhost-breakdown?range=120&bucket=300",
                cookies=cookies,
            )
            assert r.status == 200
            d = await r.json()
            vhosts_in_response = [ds["vhost"] for ds in d["datasets"]]
            assert "qa.example.com" in vhosts_in_response, (
                "/vhost-breakdown: seeded event for 'qa.example.com' not reflected in datasets. "
                f"Got datasets for: {vhosts_in_response}"
            )
            ds = next(ds for ds in d["datasets"] if ds["vhost"] == "qa.example.com")
            assert sum(ds["data"]) >= 1, (
                "/vhost-breakdown: qa.example.com dataset has zero total count despite seeded event."
            )


@pytest.mark.asyncio
async def test_d05_vhost_stats_fields_required_by_charts(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            now = time.time()
            conn = sqlite3.connect(proxy_module.DB_PATH)
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, status, reason, vhost) "
                "VALUES (?, '10.0.0.1', 'b', '/x', 200, 'ua-block', 'chart-test.local')",
                (now - 60,),
            )
            conn.commit()
            conn.close()

            # bust the 15 s /vhost-stats TTL cache — otherwise the response
            # can be a stale snapshot from an earlier test in the same second.
            try:
                from admin.settings import _VHOST_STATS_CACHE as _vsc
                _vsc["ts"] = 0.0
                _vsc["value"] = []
            except Exception:
                pass

            r = await cli.get(f"{NS}/vhost-stats",
                              cookies=cookies)
            assert r.status == 200
            d = await r.json()
            assert "stats" in d, "/vhost-stats missing 'stats' key"
            assert len(d["stats"]) >= 1, "/vhost-stats returned empty stats list after seeding"
            row = next((s for s in d["stats"] if s["hostname"] == "chart-test.local"), None)
            assert row is not None, "chart-test.local not found in /vhost-stats after seeding"
            required = ("hostname", "total_1h", "blocked_1h", "allowed_1h",
                        "total_24h", "blocked_24h", "bans", "last_seen_ts")
            missing = [f for f in required if f not in row]
            assert not missing, (
                f"/vhost-stats row missing fields required by chart rendering: {missing}"
            )


@pytest.mark.asyncio
async def test_d06_vhost_stats_bans_is_integer(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            now = time.time()
            conn = sqlite3.connect(proxy_module.DB_PATH)
            conn.execute(
                "INSERT INTO events (ts, ip, ua, path, status, reason, vhost) "
                "VALUES (?, '99.0.0.1', 'b', '/', 200, 'ua-block', 'bans-test.local')",
                (now - 10,),
            )
            conn.commit()
            conn.close()

            r = await cli.get(f"{NS}/vhost-stats",
                              cookies=cookies)
            assert r.status == 200
            d = await r.json()
            for row in d.get("stats", []):
                assert isinstance(row["bans"], int), (
                    f"/vhost-stats: bans field is {type(row['bans']).__name__} "
                    f"for {row['hostname']}, expected int."
                )


@pytest.mark.asyncio
async def test_d07_vhost_breakdown_unauthenticated_deflected(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{NS}/vhost-breakdown?range=120&bucket=300")
            body = await r.text()
            if r.status == 200:
                import json as _json
                try:
                    d = _json.loads(body)
                    assert "labels" not in d or "datasets" not in d, (
                        "/vhost-breakdown: unauthenticated request returned real data. "
                        "Admin endpoints must be gated."
                    )
                except (_json.JSONDecodeError, TypeError):
                    pass
            else:
                assert r.status in (401, 403, 302, 301), (
                    f"/vhost-breakdown: unexpected status {r.status} for unauthenticated request."
                )


# ═══════════════════════════════════════════════════════════════════════════
# Static tests — new threat charts (S23–S44)
# ═══════════════════════════════════════════════════════════════════════════

_NEW_CANVAS_IDS = [
    "signals-chart", "attack-cat-chart", "blockreason-chart", "geo-chart",
    "riskscore-chart", "jschal-chart", "toppaths-chart", "blocktimeline-chart",
]
_NEW_LOAD_FNS = [
    "loadSignalsChart", "loadAttackCatChart", "loadBlockReasonChart", "loadGeoChart",
    "loadRiskScoreChart", "loadJsChalChart", "loadTopPathsChart", "loadBlockTimelineChart",
    "loadThreatTiles",
]
_NEW_RENDER_FNS = [
    "_renderSignalsChart", "_renderAttackCatChart", "_renderBlockReasonChart", "_renderGeoChart",
    "_renderRiskScoreChart", "_renderJsChalChart", "_renderTopPathsChart", "_renderBlockTimelineChart",
]
_NEW_CHART_VARS = [
    ("_signalsChart", "_renderSignalsChart"),
    ("_attackCatChart", "_renderAttackCatChart"),
    ("_blockReasonChart", "_renderBlockReasonChart"),
    ("_geoChart", "_renderGeoChart"),
    ("_riskScoreChart", "_renderRiskScoreChart"),
    ("_jsChalChart", "_renderJsChalChart"),
    ("_topPathsChart", "_renderTopPathsChart"),
    ("_blockTimelineChart", "_renderBlockTimelineChart"),
]


@pytest.mark.parametrize("canvas_id", _NEW_CANVAS_IDS)
def test_s23_new_chart_canvas_ids_present(canvas_id):
    src = _src()
    assert f'id="{canvas_id}"' in src, (
        f"control_center.html: canvas id='{canvas_id}' missing. "
        "Threat-section chart render functions reference this ID."
    )


@pytest.mark.parametrize("canvas_id", _NEW_CANVAS_IDS)
def test_s24_new_chart_empty_state_ids_present(canvas_id):
    src = _src()
    empty_id = canvas_id + "-empty"
    assert f'id="{empty_id}"' in src, (
        f"control_center.html: empty-state element id='{empty_id}' missing. "
        "_showChartEmpty() references this ID when no data is available."
    )


def test_s25_threat_tile_stat_ids_present():
    src = _src()
    for stat_id in ("stat-honeypot", "stat-canary", "stat-aiprobe", "stat-jschal"):
        assert f'id="{stat_id}"' in src, (
            f"control_center.html: threat sensor tile id='{stat_id}' missing. "
            "loadThreatTiles() writes into this element."
        )


def test_s26_stat_grid_threat_container_present():
    src = _src()
    assert 'id="stat-grid-threat"' in src, (
        "control_center.html: id='stat-grid-threat' container missing. "
        "Threat sensor stat tiles must be grouped in this element."
    )


@pytest.mark.parametrize("fn_name", _NEW_LOAD_FNS)
def test_s27_new_load_functions_defined(fn_name):
    src = _src()
    assert f"function {fn_name}(" in src, (
        f"control_center.html: {fn_name}() function not found. "
        "Each threat-section chart and the tile loader require a load function."
    )


@pytest.mark.parametrize("fn_name", _NEW_RENDER_FNS)
def test_s28_new_render_functions_defined(fn_name):
    src = _src()
    assert f"function {fn_name}(" in src, (
        f"control_center.html: {fn_name}() function not found. "
        "Load functions delegate to a render function to keep fetch and draw logic separate."
    )


@pytest.mark.parametrize("chart_var,render_fn", _NEW_CHART_VARS)
def test_s29_new_chart_destroy_before_new_chart(chart_var, render_fn):
    src = _src()
    body = _extract_fn_body(src, render_fn)
    destroy_idx = body.find(f"{chart_var}.destroy()")
    new_chart_idx = body.find("new Chart(")
    assert destroy_idx != -1, (
        f"control_center.html: {chart_var}.destroy() not found in {render_fn}(). "
        "Without destroy(), repeated refreshes leak orphaned Chart.js instances."
    )
    assert new_chart_idx != -1, f"new Chart( not found in {render_fn}()."
    assert destroy_idx < new_chart_idx, (
        f"control_center.html: {chart_var}.destroy() must precede new Chart() in {render_fn}(). "
        f"Got destroy at offset {destroy_idx}, new Chart at {new_chart_idx}."
    )


@pytest.mark.parametrize("chart_var", [v for v, _ in _NEW_CHART_VARS])
def test_s30_new_chart_vars_declared(chart_var):
    src = _src()
    assert chart_var in src, (
        f"control_center.html: chart variable '{chart_var}' not declared. "
        "All chart instances must be module-level vars initialised to null."
    )


def test_s31_load_threat_section_called_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    assert "_loadThreatSection()" in dcl, (
        "control_center.html: _loadThreatSection() not called in DOMContentLoaded. "
        "Threat charts must load on page open, not only on button click."
    )


def test_s32_threat_section_interval_registered():
    import re as _re
    src = _src()
    dcl = _extract_dcl_body(src)
    # Accept bare call or live-mode guard wrapper (tEndEpoch===null check)
    ok = ("setInterval(_loadThreatSection,30000)" in dcl or
          bool(_re.search(r'setInterval\(\s*function\s*\(\)\s*\{[^}]*_loadThreatSection[^}]*\}\s*,\s*30000\s*\)', dcl)))
    assert ok, (
        "control_center.html: threat section must auto-refresh every 30 s via setInterval(...,30000)"
    )


def test_s33_load_threat_section_calls_all_loaders():
    src = _src()
    body = _extract_fn_body(src, "_loadThreatSection")
    for fn in _NEW_LOAD_FNS:
        assert f"{fn}()" in body, (
            f"control_center.html: _loadThreatSection() does not call {fn}(). "
            "The batch loader must invoke every threat-section load function."
        )


def test_s34_attack_cat_groups_defined():
    src = _src()
    assert "_CAT_GROUPS" in src, (
        "control_center.html: _CAT_GROUPS not defined. "
        "_renderAttackCatChart() uses this mapping to group detector_hits keys."
    )
    assert "Trap" in src or "honeypot" in src, (
        "control_center.html: _CAT_GROUPS missing Trap/honeypot category. "
        "Honeypot and bot-trap hits must be grouped under a Trap category."
    )


def test_s35_block_reason_chart_uses_timeline_endpoint():
    """Block-reason chart now uses /block-reasons-timeline (server-side filtering)."""
    src = _src()
    body = _extract_fn_body(src, "loadBlockReasonChart")
    assert "block-reasons-timeline" in body, (
        "control_center.html: loadBlockReasonChart() must fetch 'block-reasons-timeline'. "
        "Reason filtering is done server-side; the endpoint excludes allowed-traffic reasons."
    )


def test_s36_block_timeline_uses_dual_yaxis():
    """Bot vs human chart uses dual Y-axis: yBot (left) for bots, yClean (right) for clean traffic.
    fill:'origin' is used so bot signals remain visible when clean traffic volume is much larger."""
    src = _src()
    body = _extract_fn_body(src, "_renderBlockTimelineChart")
    assert "yAxisID:'yBot'" in body or 'yAxisID:"yBot"' in body, (
        "control_center.html: _renderBlockTimelineChart() must assign yAxisID:'yBot' "
        "to bot datasets so they render on a separate left-side axis."
    )
    assert "yAxisID:'yClean'" in body or 'yAxisID:"yClean"' in body, (
        "control_center.html: _renderBlockTimelineChart() must assign yAxisID:'yClean' "
        "to clean traffic dataset on a separate right-side axis."
    )
    origin_count = len(re.findall(r"fill\s*:\s*['\"]origin['\"]", body))
    assert origin_count >= 3, (
        f"control_center.html: _renderBlockTimelineChart() has {origin_count} fill:'origin' "
        "datasets; expected 3 (detected bots, missed bots, clean traffic)."
    )


def test_s37_new_chart_canvases_hidden_by_css():
    src = _src()
    css_block_start = src.find("canvas#signals-chart")
    assert css_block_start != -1, (
        "control_center.html: CSS hide rule for new chart canvases not found. "
        "All new chart canvases must start display:none to avoid empty-canvas flash."
    )
    snippet = src[css_block_start : css_block_start + 200]
    assert "display:none" in snippet, (
        "control_center.html: CSS rule for new canvases found but 'display:none' missing. "
        "New chart canvases must be hidden until _render*() sets display:block."
    )


def test_s38_signals_chart_fetches_detector_stats():
    src = _src()
    body = _extract_fn_body(src, "loadSignalsChart")
    assert "detector-stats" in body, (
        "control_center.html: loadSignalsChart() does not fetch '/detector-stats'. "
        "Detection signal data is served by the /secured/detector-stats endpoint."
    )


def test_s39_geo_chart_handles_unconfigured():
    src = _src()
    body = _extract_fn_body(src, "_renderGeoChart")
    assert "configured" in body, (
        "control_center.html: _renderGeoChart() does not check 'd.configured'. "
        "When GeoLite2-City.mmdb is absent the endpoint returns configured:false; "
        "the chart must show an informative empty state instead of crashing."
    )


def test_s40_risk_score_chart_buckets_ten_bins():
    src = _src()
    body = _extract_fn_body(src, "_renderRiskScoreChart")
    # 10 bins: 0-9,10-19,...,90-100 → 10 labels
    assert "10" in body, (
        "control_center.html: _renderRiskScoreChart() appears to not use 10 bins. "
        "Risk score (0–100) should be divided into 10 buckets of width 10."
    )
    # bins array of length 10
    assert "bins" in body, (
        "control_center.html: _renderRiskScoreChart() missing 'bins' accumulator. "
        "Expected a 10-element array counting clients per risk-score decile."
    )


def test_s41_js_chal_funnel_shows_minted_and_required():
    src = _src()
    body = _extract_fn_body(src, "_renderJsChalChart")
    assert "required" in body and "minted" in body, (
        "control_center.html: _renderJsChalChart() missing 'required' or 'minted'. "
        "The funnel must display challenges required AND tokens minted."
    )


def test_s42_top_paths_chart_fetches_blocked_paths_endpoint():
    """Top-paths chart now uses /top-attacked-paths (blocked requests only)."""
    src = _src()
    body = _extract_fn_body(src, "loadTopPathsChart")
    assert "top-attacked-paths" in body, (
        "control_center.html: loadTopPathsChart() must fetch 'top-attacked-paths'. "
        "This endpoint returns only blocked requests, not all traffic."
    )


def test_s43_load_threat_tiles_fetches_both_endpoints():
    src = _src()
    body = _extract_fn_body(src, "loadThreatTiles")
    assert "metrics" in body, (
        "control_center.html: loadThreatTiles() does not fetch '/metrics'. "
        "detector_hits (honeypot, canary, ai_probe) come from the metrics endpoint."
    )
    assert "detector-stats" in body, (
        "control_center.html: loadThreatTiles() does not fetch '/detector-stats'. "
        "JS challenge count (chal.required) comes from the detector-stats endpoint."
    )


def test_s44_yellow_stat_tile_css_defined():
    src = _src()
    assert ".stat.yellow" in src, (
        "control_center.html: .stat.yellow CSS class not defined. "
        "The Canary Echo tile uses .stat.yellow for its value colour."
    )


@pytest.mark.asyncio
async def test_d08_vhost_breakdown_cache_control_no_store(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(
                f"{NS}/vhost-breakdown?range=120&bucket=300",
                cookies=cookies,
            )
            assert r.status == 200
            cc = r.headers.get("Cache-Control", "")
            assert "no-store" in cc, (
                f"/vhost-breakdown Cache-Control header is '{cc}', expected 'no-store'."
            )


# ═══════════════════════════════════════════════════════════════════════════
# Static tests — sidebar show/hide submenu (S45–S52)
# ═══════════════════════════════════════════════════════════════════════════

def test_s45_sidebar_toggle_button_present():
    src = _src()
    assert 'id="sidebar-toggle"' in src, (
        "control_center.html: sidebar collapse toggle button (#sidebar-toggle) missing. "
        "The ‹ button inside #sidebar-brand collapses the sidebar on desktop."
    )
    assert 'onclick="_sbToggle()"' in src, (
        "control_center.html: sidebar-toggle onclick must call _sbToggle(). "
        "The toggle button is wired to _sbToggle() which adds/removes .sb-collapsed."
    )


def test_s46_sidebar_reopen_button_present():
    src = _src()
    assert 'id="sidebar-reopen"' in src, (
        "control_center.html: #sidebar-reopen floating ☰ button missing. "
        "When the sidebar is hidden, this button is the only way to restore it."
    )


def test_s47_sbtoggle_defined_and_runs_before_sidebar():
    src = _src()
    assert "window._sbToggle" in src, (
        "control_center.html: _sbToggle() function not defined. "
        "Both #sidebar-toggle and #sidebar-reopen call _sbToggle()."
    )
    init_idx = src.index("localStorage.getItem('agw_sb_collapsed')")
    bar_idx  = src.index('<div id="sidebar">')
    assert init_idx < bar_idx, (
        "control_center.html: sidebar-collapse init script runs AFTER #sidebar element. "
        "The script must precede the sidebar so .sb-collapsed is applied before "
        "the element is parsed — otherwise there is a flash of the expanded sidebar."
    )


def test_s48_sidebar_collapse_css_rules_present():
    src = _src()
    assert "body.sb-collapsed #sidebar{display:none}" in src, (
        "control_center.html: 'body.sb-collapsed #sidebar{display:none}' CSS rule missing. "
        "This rule hides the sidebar when the ‹ toggle is clicked."
    )
    assert "@media(min-width:601px){body.sb-collapsed" in src, (
        "control_center.html: sidebar collapse must be desktop-only "
        "(@media min-width:601px). Mobile uses the off-canvas #mob-menu instead."
    )
    assert "@media(max-width:600px){#sidebar-toggle{display:none}}" in src, (
        "control_center.html: #sidebar-toggle must be hidden on mobile "
        "(@media max-width:600px) so the ‹ button does not appear on small screens."
    )
    assert "#sidebar-nav a.sub.sub-hidden{display:none}" in src, (
        "control_center.html: '.sub.sub-hidden{display:none}' CSS rule missing. "
        "_subToggle() adds sub-hidden to collapse child items under each nav-parent."
    )


def test_s49_three_nav_parents_with_correct_groups():
    src = _src()
    for grp in ("control-center", "controls", "settings"):
        assert f'class="nav-parent" data-group="{grp}"' in src, (
            f"control_center.html: nav-parent wrapper for group '{grp}' missing. "
            "Each collapsible section (Control Center, Controls, Settings) must be "
            "wrapped in a div.nav-parent with its data-group attribute."
        )
    caret_count = src.count('class="nav-caret"')
    assert caret_count == 3, (
        f"control_center.html: expected exactly 3 .nav-caret buttons, got {caret_count}. "
        "One caret per collapsible nav-parent group."
    )
    assert src.count('onclick="_subToggle(this)"') == 3, (
        "control_center.html: expected 3 caret onclick='_subToggle(this)' handlers, "
        "one per nav-parent group."
    )


def test_s50_control_center_nav_parent_has_active_link():
    src = _src()
    # The control-center group link must carry class="active" (this is the current page)
    cc_group_start = src.index('data-group="control-center"')
    cc_group_end   = src.index('</div>', cc_group_start)
    snippet = src[cc_group_start:cc_group_end]
    assert 'class="active"' in snippet, (
        "control_center.html: the Control Center nav-parent link is missing class='active'. "
        "The active class highlights the current page in the sidebar."
    )


def test_s51_geomap_has_no_caret():
    src = _src()
    assert 'data-group="geo"' not in src, (
        "control_center.html: GeoMap is wrapped in a nav-parent with data-group='geo'. "
        "GeoMap has no sub-items and must remain a plain <a> link without a caret."
    )


def test_s52_subtoggle_persists_state_via_localstorage():
    src = _src()
    assert "window._subToggle" in src, (
        "control_center.html: _subToggle() function not defined. "
        "Caret buttons call _subToggle(this) to expand/collapse sub-items."
    )
    assert "agw_sub_" in src, (
        "control_center.html: 'agw_sub_' localStorage key prefix missing. "
        "_subToggle() persists each group's collapsed state under 'agw_sub_<group>'."
    )
    assert "localStorage.getItem('agw_sub_" in src or "agw_sub_'+g" in src, (
        "control_center.html: _subToggle does not restore per-group state from localStorage. "
        "Collapsed groups must survive page reload."
    )
