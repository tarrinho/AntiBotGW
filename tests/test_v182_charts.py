"""
v1.8.2 new charts QA — static + dynamic tests.

Six new/upgraded charts:
  1  Traffic Pipeline   — stacked area via /traffic-pipeline (upgraded from /vhost-breakdown)
  2  Bot Score Dist     — 8-bin histogram via /score-distribution
  3  Vhost Heatmap      — HTML table via /vhost-heatmap
  4  Signal Performance — horizontal bar via /signal-performance
  5  Geo Country        — top-15 bar rendered inside _renderGeoChart
  6  Threat Donut       — doughnut via /detector-stats

Static checks (no server required):
  S01  Traffic Pipeline card + canvas present
  S02  Pipeline KPI row element present
  S03  loadTrafficChart fetches /traffic-pipeline endpoint
  S04  loadTrafficChart builds URLSearchParams with range/bucket/end
  S05  _renderTrafficChart has 4 datasets (Allowed/Challenged/Blocked/Bypassed)
  S06  _renderTrafficChart uses fill:'stack'
  S07  _trafficChart.destroy() before new Chart() in _renderTrafficChart
  S08  loadTrafficChart() called in DOMContentLoaded
  S09  Traffic chart live-mode setInterval(60s) registered in DOMContentLoaded
  S10  Score Distribution card + canvas + empty-state present
  S11  Score KPI row element present
  S12  loadScoreDist fetches /score-distribution
  S13  _renderScoreDist references 8-bin labels
  S14  _scoreDistChart.destroy() before new Chart() in _renderScoreDist
  S15  loadScoreDist() called in DOMContentLoaded
  S16  Score dist 30s setInterval registered in DOMContentLoaded
  S17  Vhost heatmap card + body container present
  S18  loadVhostHeatmap fetches /vhost-heatmap
  S19  loadVhostHeatmap builds URLSearchParams with range/bucket/end
  S20  _renderVhostHeatmap generates HTML table
  S21  _renderVhostHeatmap has SILENT badge logic
  S22  loadVhostHeatmap() called in DOMContentLoaded
  S23  loadVhostHeatmap() called in _loadTimeCharts
  S24  Signal Performance card + canvas + empty-state present
  S25  loadSignalPerf fetches /signal-performance
  S26  _renderSignalPerf has 2 datasets (Hits + Blocks)
  S27  _signalPerfChart.destroy() before new Chart()
  S28  _renderSignalPerf uses indexAxis:'y' (horizontal bars)
  S29  loadSignalPerf() called in DOMContentLoaded
  S30  Signal perf 60s setInterval registered in DOMContentLoaded
  S31  Geo country canvas + empty-state present
  S32  _geoCountryChart var declared
  S33  _geoCountryChart.destroy() before new Chart() in _renderGeoChart
  S34  Geo country chart hidden by CSS display:none
  S35  Threat Donut card + canvas + legend + empty-state present
  S36  loadThreatDonut fetches /detector-stats
  S37  _renderThreatDonut groups small slices into 'Other'
  S38  _threatDonutChart.destroy() before new Chart()
  S39  Threat donut uses type:'doughnut'
  S40  loadThreatDonut() called in DOMContentLoaded
  S41  Threat donut 30s setInterval registered in DOMContentLoaded
  S42  All 4 new chart vars declared (_scoreDistChart/_signalPerfChart/_geoCountryChart/_threatDonutChart)
  S43  New chart canvases hidden by CSS block

Dynamic checks (in-process gateway via TestClient):
  D01  /score-distribution returns 200 with correct JSON schema
  D02  /score-distribution bins list has 8 items with label+count
  D03  /score-distribution has threshold_soft, threshold_ban, total_ips
  D04  /score-distribution returns Cache-Control: no-store
  D05  /score-distribution unauthenticated access is deflected
  D06  /traffic-pipeline returns 200 with correct JSON schema
  D07  /traffic-pipeline timeline items have t/allowed/challenged/blocked/bypassed
  D08  /traffic-pipeline respects range/bucket/end query params
  D09  /traffic-pipeline returns Cache-Control: no-store
  D10  /traffic-pipeline unauthenticated access is deflected
  D11  /vhost-heatmap returns 200 with correct JSON schema
  D12  /vhost-heatmap returns vhosts/buckets/cells keys
  D13  /vhost-heatmap with seeded event reflects vhost in cells
  D14  /vhost-heatmap returns Cache-Control: no-store
  D15  /vhost-heatmap unauthenticated access is deflected
  D16  /signal-performance returns 200 with correct JSON schema
  D17  /signal-performance signals items have all required fields
  D18  /signal-performance method_totals dict present
  D19  /signal-performance returns Cache-Control: no-store
  D20  /signal-performance unauthenticated access is deflected
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


def _extract_fn_body(src: str, fn_name: str) -> str:
    start = src.find(f"function {fn_name}(")
    assert start != -1, f"function {fn_name}() not found in control_center.html"
    next_fn = re.search(r"\n(?:async\s+)?function\s+\w", src[start + 1:])
    end = (start + 1 + next_fn.start()) if next_fn else len(src)
    return src[start:end]


def _extract_dcl_body(src: str) -> str:
    idx = src.rfind("DOMContentLoaded")  # 1.8.12: last DOMContentLoaded = chart/init block (sidebar accordion adds an earlier one)
    assert idx != -1, "DOMContentLoaded not found in control_center.html"
    end = src.find("});", idx)
    return src[idx:end]


# ═══════════════════════════════════════════════════════════════════════════
# Static tests
# ═══════════════════════════════════════════════════════════════════════════

# ── Chart 1: Traffic Pipeline ────────────────────────────────────────────

def test_s01_traffic_pipeline_card_and_canvas_present():
    src = _src()
    assert 'id="card-traffic-chart"' in src, (
        "control_center.html: id='card-traffic-chart' missing. "
        "The Traffic Pipeline card wraps the stacked-area canvas."
    )
    assert 'id="traffic-chart"' in src, (
        "control_center.html: canvas id='traffic-chart' missing."
    )
    assert 'id="traffic-chart-empty"' in src, (
        "control_center.html: id='traffic-chart-empty' missing."
    )


def test_s02_pipeline_kpi_row_present():
    src = _src()
    assert 'id="pipeline-kpi-row"' in src, (
        "control_center.html: id='pipeline-kpi-row' missing. "
        "_renderTrafficChart() writes Allowed/Challenged/Blocked/Bypassed totals into this element."
    )


def test_s03_load_traffic_chart_fetches_traffic_pipeline():
    src = _src()
    body = _extract_fn_body(src, "loadTrafficChart")
    assert "traffic-pipeline" in body, (
        "control_center.html: loadTrafficChart() does not fetch 'traffic-pipeline'. "
        "The chart must use /secured/traffic-pipeline (not the old /vhost-breakdown)."
    )


def test_s04_load_traffic_chart_sends_range_bucket_end_params():
    src = _src()
    body = _extract_fn_body(src, "loadTrafficChart")
    assert "URLSearchParams" in body, (
        "control_center.html: loadTrafficChart() does not use URLSearchParams. "
        "range/bucket/end must be passed as query params to support time navigation."
    )
    assert "range" in body, (
        "control_center.html: loadTrafficChart() does not include 'range' param."
    )
    assert "bucket" in body, (
        "control_center.html: loadTrafficChart() does not include 'bucket' param."
    )
    assert "tEndEpoch" in body, (
        "control_center.html: loadTrafficChart() does not check tEndEpoch for 'end' param."
    )


def test_s05_render_traffic_chart_has_four_datasets():
    src = _src()
    body = _extract_fn_body(src, "_renderTrafficChart")
    for label in ("Allowed", "Challenged", "Blocked", "Bypassed"):
        assert label in body, (
            f"control_center.html: _renderTrafficChart() missing '{label}' dataset. "
            "Traffic pipeline chart must render 4 stacked-area datasets."
        )


def test_s06_render_traffic_chart_uses_fill_stack():
    src = _src()
    body = _extract_fn_body(src, "_renderTrafficChart")
    assert "fill:'stack'" in body or 'fill:"stack"' in body, (
        "control_center.html: _renderTrafficChart() must use fill:'stack' for correct "
        "stacked-area rendering. fill:true fills each series to y=0 independently."
    )


def test_s07_traffic_chart_destroy_before_new_chart():
    src = _src()
    body = _extract_fn_body(src, "_renderTrafficChart")
    destroy_idx = body.find("_trafficChart.destroy()")
    new_chart_idx = body.find("new Chart(")
    assert destroy_idx != -1, (
        "control_center.html: _trafficChart.destroy() missing in _renderTrafficChart(). "
        "Repeated refreshes leak orphaned Chart.js instances without destroy()."
    )
    assert destroy_idx < new_chart_idx, (
        "control_center.html: _trafficChart.destroy() must precede new Chart()."
    )


def test_s08_load_traffic_chart_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    assert "loadTrafficChart()" in dcl, (
        "control_center.html: loadTrafficChart() not called in DOMContentLoaded. "
        "The traffic pipeline chart must load on page open."
    )


def test_s09_traffic_chart_live_mode_interval_60s():
    src = _src()
    dcl = _extract_dcl_body(src)
    ok = (
        "setInterval(loadTrafficChart,60000)" in dcl or
        bool(re.search(
            r"setInterval\(\s*function\s*\(\)\s*\{[^}]*loadTrafficChart[^}]*\}\s*,\s*60000\s*\)",
            dcl,
        ))
    )
    assert ok, (
        "control_center.html: traffic chart must auto-refresh every 60 s in live mode. "
        "Expected setInterval(...,60000) with optional tEndEpoch===null guard."
    )


# ── Chart 2: Bot Score Distribution ──────────────────────────────────────

def test_s10_score_dist_card_canvas_empty_present():
    src = _src()
    assert 'id="card-score-dist"' in src, (
        "control_center.html: id='card-score-dist' card missing."
    )
    assert 'id="score-dist-chart"' in src, (
        "control_center.html: canvas id='score-dist-chart' missing."
    )
    assert 'id="score-dist-empty"' in src, (
        "control_center.html: id='score-dist-empty' empty-state element missing."
    )


def test_s11_score_kpi_row_present():
    src = _src()
    assert 'id="score-kpi-row"' in src, (
        "control_center.html: id='score-kpi-row' missing. "
        "_renderScoreDist() writes Human%/Grey%/Automated% KPIs into this element."
    )


def test_s12_load_score_dist_fetches_score_distribution():
    src = _src()
    body = _extract_fn_body(src, "loadScoreDist")
    assert "score-distribution" in body, (
        "control_center.html: loadScoreDist() does not fetch 'score-distribution'. "
        "Score histogram data is served by /secured/score-distribution."
    )


def test_s13_render_score_dist_references_8_bin_labels():
    src = _src()
    body = _extract_fn_body(src, "_renderScoreDist")
    # 8-bin labels expected from the backend: "0", "1–9", "10–29", "30–49", "50–69", "70–89", "90–99", "100+"
    assert "bins" in body, (
        "control_center.html: _renderScoreDist() missing 'bins' reference. "
        "Render function must iterate the bins array from the /score-distribution response."
    )
    assert "label" in body, (
        "control_center.html: _renderScoreDist() missing 'label' key access on bins."
    )
    assert "count" in body, (
        "control_center.html: _renderScoreDist() missing 'count' key access on bins."
    )
    # Threshold lines plugin expected
    assert "threshold_soft" in body or "threshold_ban" in body, (
        "control_center.html: _renderScoreDist() does not use threshold_soft or threshold_ban. "
        "Soft-challenge and ban thresholds must be drawn as vertical lines."
    )


def test_s14_score_dist_chart_destroy_before_new_chart():
    src = _src()
    body = _extract_fn_body(src, "_renderScoreDist")
    destroy_idx = body.find("_scoreDistChart.destroy()")
    new_chart_idx = body.find("new Chart(")
    assert destroy_idx != -1, (
        "control_center.html: _scoreDistChart.destroy() missing in _renderScoreDist(). "
        "Repeated refreshes leak orphaned Chart.js instances."
    )
    assert destroy_idx < new_chart_idx, (
        "control_center.html: _scoreDistChart.destroy() must precede new Chart()."
    )


def test_s15_load_score_dist_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    assert "loadScoreDist()" in dcl, (
        "control_center.html: loadScoreDist() not called in DOMContentLoaded. "
        "Score distribution histogram must load on page open."
    )


def test_s16_score_dist_30s_interval_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    ok = (
        "setInterval(loadScoreDist,30000)" in dcl or
        bool(re.search(
            r"setInterval\(\s*function\s*\(\)\s*\{[^}]*loadScoreDist[^}]*\}\s*,\s*30000\s*\)",
            dcl,
        ))
    )
    assert ok, (
        "control_center.html: score distribution must auto-refresh every 30 s. "
        "Expected setInterval(loadScoreDist,30000) in DOMContentLoaded."
    )


# ── Chart 3: Vhost Block Rate Heatmap ────────────────────────────────────

def test_s17_vhost_heatmap_card_and_body_present():
    src = _src()
    assert 'id="card-vhost-heatmap"' in src, (
        "control_center.html: id='card-vhost-heatmap' card missing."
    )
    assert 'id="vhost-heatmap-body"' in src, (
        "control_center.html: id='vhost-heatmap-body' container missing. "
        "_renderVhostHeatmap() writes the HTML table into this element."
    )


def test_s18_load_vhost_heatmap_fetches_vhost_heatmap():
    src = _src()
    body = _extract_fn_body(src, "loadVhostHeatmap")
    assert "vhost-heatmap" in body, (
        "control_center.html: loadVhostHeatmap() does not fetch 'vhost-heatmap'. "
        "Heatmap data is served by /secured/vhost-heatmap."
    )


def test_s19_load_vhost_heatmap_sends_time_params():
    src = _src()
    body = _extract_fn_body(src, "loadVhostHeatmap")
    assert "URLSearchParams" in body, (
        "control_center.html: loadVhostHeatmap() does not use URLSearchParams. "
        "range/bucket/end must be passed to sync with the time-window controls."
    )
    assert "tEndEpoch" in body, (
        "control_center.html: loadVhostHeatmap() does not check tEndEpoch for 'end' param."
    )


def test_s20_render_vhost_heatmap_generates_html_table():
    src = _src()
    body = _extract_fn_body(src, "_renderVhostHeatmap")
    assert "<table" in body or "'<table" in body or '"<table' in body, (
        "control_center.html: _renderVhostHeatmap() does not generate an HTML table. "
        "The heatmap is implemented as a styled HTML table, not a Canvas chart."
    )
    assert "vhost-heatmap-body" in body, (
        "control_center.html: _renderVhostHeatmap() does not write into 'vhost-heatmap-body'."
    )


def test_s21_render_vhost_heatmap_has_silent_badge():
    src = _src()
    body = _extract_fn_body(src, "_renderVhostHeatmap")
    assert "SILENT" in body, (
        "control_center.html: _renderVhostHeatmap() missing SILENT badge logic. "
        "Vhosts with no recent traffic must be flagged SILENT."
    )


def test_s22_load_vhost_heatmap_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    assert "loadVhostHeatmap()" in dcl, (
        "control_center.html: loadVhostHeatmap() not called in DOMContentLoaded. "
        "The vhost block rate heatmap must load on page open."
    )


def test_s23_load_vhost_heatmap_in_load_time_charts():
    src = _src()
    body = _extract_fn_body(src, "_loadTimeCharts")
    assert "loadVhostHeatmap()" in body, (
        "control_center.html: _loadTimeCharts() does not call loadVhostHeatmap(). "
        "The heatmap is time-windowed and must refresh when the time controls change."
    )


# ── Chart 4: Signal Performance Matrix ───────────────────────────────────

def test_s24_signal_perf_card_canvas_empty_present():
    src = _src()
    assert 'id="card-signal-perf"' in src, (
        "control_center.html: id='card-signal-perf' card missing."
    )
    assert 'id="signal-perf-chart"' in src, (
        "control_center.html: canvas id='signal-perf-chart' missing."
    )
    assert 'id="signal-perf-empty"' in src, (
        "control_center.html: id='signal-perf-empty' empty-state element missing."
    )


def test_s25_load_signal_perf_fetches_signal_performance():
    src = _src()
    body = _extract_fn_body(src, "loadSignalPerf")
    assert "signal-performance" in body, (
        "control_center.html: loadSignalPerf() does not fetch 'signal-performance'. "
        "Per-signal latency/block data is served by /secured/signal-performance."
    )


def test_s26_render_signal_perf_has_two_datasets():
    src = _src()
    body = _extract_fn_body(src, "_renderSignalPerf")
    assert "Hits" in body, (
        "control_center.html: _renderSignalPerf() missing 'Hits' dataset."
    )
    assert "Blocks" in body, (
        "control_center.html: _renderSignalPerf() missing 'Blocks' dataset."
    )
    # Both datasets should exist in the datasets array
    hit_idx = body.find("Hits")
    blk_idx = body.find("Blocks")
    assert hit_idx != -1 and blk_idx != -1, (
        "control_center.html: _renderSignalPerf() must render both Hits and Blocks datasets."
    )


def test_s27_signal_perf_chart_destroy_before_new_chart():
    src = _src()
    body = _extract_fn_body(src, "_renderSignalPerf")
    destroy_idx = body.find("_signalPerfChart.destroy()")
    new_chart_idx = body.find("new Chart(")
    assert destroy_idx != -1, (
        "control_center.html: _signalPerfChart.destroy() missing in _renderSignalPerf()."
    )
    assert destroy_idx < new_chart_idx, (
        "control_center.html: _signalPerfChart.destroy() must precede new Chart()."
    )


def test_s28_render_signal_perf_uses_horizontal_bars():
    src = _src()
    body = _extract_fn_body(src, "_renderSignalPerf")
    assert "indexAxis:'y'" in body or 'indexAxis:"y"' in body, (
        "control_center.html: _renderSignalPerf() must use indexAxis:'y' for horizontal bars. "
        "Signal names are long labels — horizontal layout is required for readability."
    )


def test_s29_load_signal_perf_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    # loadSignalPerf() is invoked by _loadThreatSection() which IS called in DCL.
    # A direct call in DCL would be a duplicate (caught by test_v184_uiux.py::TestP2BDuplicateFetch).
    assert "_loadThreatSection()" in dcl, (
        "control_center.html: _loadThreatSection() not called in DOMContentLoaded — "
        "it is the entry point for loadSignalPerf(); signal performance matrix will not load on page open."
    )
    # Also verify loadSignalPerf is actually called within _loadThreatSection
    fn_start = src.find("function _loadThreatSection(")
    assert fn_start != -1, "control_center.html: _loadThreatSection() function missing"
    fn_end = src.find("\nfunction ", fn_start + 1)
    fn_body = src[fn_start: fn_end if fn_end != -1 else fn_start + 2000]
    assert "loadSignalPerf" in fn_body, (
        "control_center.html: _loadThreatSection() must call loadSignalPerf() internally"
    )


def test_s30_signal_perf_60s_interval_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    ok = (
        "setInterval(loadSignalPerf,60000)" in dcl or
        bool(re.search(
            r"setInterval\(\s*function\s*\(\)\s*\{[^}]*loadSignalPerf[^}]*\}\s*,\s*60000\s*\)",
            dcl,
        ))
    )
    assert ok, (
        "control_center.html: signal performance must auto-refresh every 60 s. "
        "Expected setInterval(loadSignalPerf,60000) in DOMContentLoaded."
    )


# ── Chart 5: Geo Country Bar ──────────────────────────────────────────────

def test_s31_geo_country_canvas_and_empty_present():
    src = _src()
    assert 'id="geo-country-chart"' in src, (
        "control_center.html: canvas id='geo-country-chart' missing. "
        "_renderGeoChart() renders the top-15 country bar into this canvas."
    )
    assert 'id="geo-country-empty"' in src, (
        "control_center.html: id='geo-country-empty' empty-state element missing."
    )


def test_s32_geo_country_chart_var_declared():
    src = _src()
    assert "_geoCountryChart" in src, (
        "control_center.html: _geoCountryChart variable not declared. "
        "The geo country chart instance must be a module-level var for destroy() to work."
    )


def test_s33_geo_country_chart_destroy_before_new_chart():
    src = _src()
    body = _extract_fn_body(src, "_renderGeoChart")
    destroy_idx = body.find("_geoCountryChart.destroy()")
    new_chart_idx = body.rfind("new Chart(")  # rfind: country chart is the second Chart() in the function
    assert destroy_idx != -1, (
        "control_center.html: _geoCountryChart.destroy() missing in _renderGeoChart(). "
        "The second (top-15 country) chart must be destroyed before each re-render."
    )
    assert destroy_idx < new_chart_idx, (
        "control_center.html: _geoCountryChart.destroy() must precede new Chart() for the country chart."
    )


def test_s34_geo_country_canvas_hidden_by_css():
    src = _src()
    css_start = src.find("canvas#geo-country-chart")
    assert css_start != -1, (
        "control_center.html: CSS rule for canvas#geo-country-chart not found. "
        "geo-country-chart must be hidden by default (display:none)."
    )
    snippet = src[css_start : css_start + 80]
    assert "display:none" in snippet or "display:none" in src[
        src.find("canvas#score-dist-chart") : src.find("canvas#score-dist-chart") + 200
    ], (
        "control_center.html: canvas#geo-country-chart not included in display:none CSS block."
    )


# ── Chart 6: Threat Donut ────────────────────────────────────────────────

def test_s35_threat_donut_card_canvas_legend_empty_present():
    src = _src()
    assert 'id="card-threat-donut"' in src, (
        "control_center.html: id='card-threat-donut' card missing."
    )
    assert 'id="threat-donut-chart"' in src, (
        "control_center.html: canvas id='threat-donut-chart' missing."
    )
    assert 'id="threat-donut-legend"' in src, (
        "control_center.html: id='threat-donut-legend' element missing. "
        "_renderThreatDonut() renders a custom HTML legend (Chart.js legend is off)."
    )
    assert 'id="threat-donut-empty"' in src, (
        "control_center.html: id='threat-donut-empty' empty-state element missing."
    )


def test_s36_load_threat_donut_fetches_detector_stats():
    src = _src()
    body = _extract_fn_body(src, "loadThreatDonut")
    assert "detector-stats" in body, (
        "control_center.html: loadThreatDonut() does not fetch 'detector-stats'. "
        "Threat category distribution is derived from the existing /detector-stats endpoint."
    )


def test_s37_render_threat_donut_groups_small_slices_into_other():
    src = _src()
    body = _extract_fn_body(src, "_renderThreatDonut")
    assert "Other" in body, (
        "control_center.html: _renderThreatDonut() does not group small slices into 'Other'. "
        "Signals below the 2% threshold must be merged into a single 'Other' segment."
    )
    assert "threshold" in body, (
        "control_center.html: _renderThreatDonut() missing threshold variable for 'Other' grouping."
    )


def test_s38_threat_donut_chart_destroy_before_new_chart():
    src = _src()
    body = _extract_fn_body(src, "_renderThreatDonut")
    destroy_idx = body.find("_threatDonutChart.destroy()")
    new_chart_idx = body.find("new Chart(")
    assert destroy_idx != -1, (
        "control_center.html: _threatDonutChart.destroy() missing in _renderThreatDonut()."
    )
    assert destroy_idx < new_chart_idx, (
        "control_center.html: _threatDonutChart.destroy() must precede new Chart()."
    )


def test_s39_threat_donut_uses_doughnut_type():
    src = _src()
    body = _extract_fn_body(src, "_renderThreatDonut")
    assert "doughnut" in body, (
        "control_center.html: _renderThreatDonut() must use type:'doughnut'. "
        "A solid pie chart would obscure the centre totals display."
    )


def test_s40_load_threat_donut_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    # loadThreatDonut() is invoked by _loadThreatSection() which IS called in DCL.
    # A direct call in DCL would be a duplicate (caught by test_v184_uiux.py::TestP2BDuplicateFetch).
    assert "_loadThreatSection()" in dcl, (
        "control_center.html: _loadThreatSection() not called in DOMContentLoaded — "
        "it is the entry point for loadThreatDonut(); threat category donut will not load on page open."
    )
    # Also verify loadThreatDonut is actually called within _loadThreatSection
    fn_start = src.find("function _loadThreatSection(")
    assert fn_start != -1, "control_center.html: _loadThreatSection() function missing"
    fn_end = src.find("\nfunction ", fn_start + 1)
    fn_body = src[fn_start: fn_end if fn_end != -1 else fn_start + 2000]
    assert "loadThreatDonut" in fn_body, (
        "control_center.html: _loadThreatSection() must call loadThreatDonut() internally"
    )


def test_s41_threat_donut_30s_interval_in_domcontentloaded():
    src = _src()
    dcl = _extract_dcl_body(src)
    ok = (
        "setInterval(loadThreatDonut,30000)" in dcl or
        bool(re.search(
            r"setInterval\(\s*function\s*\(\)\s*\{[^}]*loadThreatDonut[^}]*\}\s*,\s*30000\s*\)",
            dcl,
        ))
    )
    assert ok, (
        "control_center.html: threat donut must auto-refresh every 30 s. "
        "Expected setInterval(loadThreatDonut,30000) in DOMContentLoaded."
    )


# ── Cross-chart: var declarations + CSS ──────────────────────────────────

@pytest.mark.parametrize("var_name", [
    "_scoreDistChart",
    "_signalPerfChart",
    "_geoCountryChart",
    "_threatDonutChart",
])
def test_s42_new_chart_vars_declared(var_name):
    src = _src()
    assert var_name in src, (
        f"control_center.html: chart variable '{var_name}' not declared. "
        "All chart instances must be module-level vars so destroy() can be called on reload."
    )


def test_s43_new_chart_canvases_hidden_by_css():
    src = _src()
    css_block_start = src.find("canvas#score-dist-chart")
    assert css_block_start != -1, (
        "control_center.html: CSS hide rule for new chart canvases not found. "
        "score-dist-chart/signal-perf-chart/geo-country-chart/threat-donut-chart must start hidden."
    )
    snippet = src[css_block_start : css_block_start + 150]
    assert "display:none" in snippet, (
        "control_center.html: new chart canvas CSS block found but display:none missing."
    )
    for canvas_id in ("signal-perf-chart", "geo-country-chart", "threat-donut-chart"):
        assert canvas_id in snippet, (
            f"control_center.html: canvas#{canvas_id} not included in the display:none CSS block."
        )


# ═══════════════════════════════════════════════════════════════════════════
# Dynamic tests — in-process gateway via TestClient
# ═══════════════════════════════════════════════════════════════════════════

NS = "/antibot-appsec-gateway/secured"


async def _echo_handler(request: web.Request):
    return web.json_response({"ok": True})


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
    sid = proxy_module._new_sid()
    proxy_module._SESSION_CACHE[sid] = {
        "username":   "admin",
        "expires_ts": proxy_module._t.time() + proxy_module._SESSION_TTL,
        "revoked":    False,
    }
    proxy_module._SESSION_CACHE_READY = True
    token = proxy_module._session_sign("admin", sid=sid)
    return {proxy_module._SESSION_COOKIE: token}


# ── /score-distribution ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_d01_score_distribution_returns_200(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/score-distribution", cookies=cookies)
            assert r.status == 200, (
                f"/score-distribution returned HTTP {r.status}, expected 200."
            )
            d = await r.json()
            assert "bins" in d, "/score-distribution: 'bins' key missing from response."
            assert "total_ips" in d, "/score-distribution: 'total_ips' key missing."


@pytest.mark.asyncio
async def test_d02_score_distribution_bins_schema(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/score-distribution", cookies=cookies)
            assert r.status == 200
            d = await r.json()
            bins = d.get("bins", [])
            assert isinstance(bins, list), "/score-distribution: 'bins' must be a list."
            assert len(bins) == 8, (
                f"/score-distribution: expected 8 bins, got {len(bins)}. "
                "Bins: 0, 1–9, 10–29, 30–49, 50–69, 70–89, 90–99, 100+"
            )
            for b in bins:
                assert "label" in b, f"/score-distribution: bin missing 'label' key: {b}"
                assert "count" in b, f"/score-distribution: bin missing 'count' key: {b}"
                assert isinstance(b["count"], int), (
                    f"/score-distribution: bin count is not int: {b}"
                )


@pytest.mark.asyncio
async def test_d03_score_distribution_has_threshold_fields(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/score-distribution", cookies=cookies)
            assert r.status == 200
            d = await r.json()
            assert "threshold_soft" in d, (
                "/score-distribution: 'threshold_soft' key missing. "
                "_renderScoreDist() uses it to draw the soft-challenge threshold line."
            )
            assert "threshold_ban" in d, (
                "/score-distribution: 'threshold_ban' key missing. "
                "_renderScoreDist() uses it to draw the ban threshold line."
            )
            assert isinstance(d["total_ips"], int), (
                f"/score-distribution: total_ips is not int: {d.get('total_ips')}"
            )


@pytest.mark.asyncio
async def test_d04_score_distribution_cache_control_no_store(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/score-distribution", cookies=cookies)
            assert r.status == 200
            cc = r.headers.get("Cache-Control", "")
            assert "no-store" in cc, (
                f"/score-distribution Cache-Control is '{cc}', expected 'no-store'. "
                "Risk data must never be cached by proxies or browsers."
            )


@pytest.mark.asyncio
async def test_d05_score_distribution_unauthenticated_deflected(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{NS}/score-distribution")
            if r.status == 200:
                import json as _json
                try:
                    d = _json.loads(await r.text())
                    assert "bins" not in d, (
                        "/score-distribution: unauthenticated request returned real data."
                    )
                except (_json.JSONDecodeError, TypeError):
                    pass
            else:
                assert r.status in (401, 403, 302, 301, 404), (
                    f"/score-distribution: unexpected status {r.status} for unauthenticated request."
                )


# ── /traffic-pipeline ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_d06_traffic_pipeline_returns_200(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(
                f"{NS}/traffic-pipeline?range=60&bucket=300",
                cookies=cookies,
            )
            assert r.status == 200, (
                f"/traffic-pipeline returned HTTP {r.status}, expected 200."
            )
            d = await r.json()
            assert "timeline" in d, "/traffic-pipeline: 'timeline' key missing."
            assert "totals" in d, "/traffic-pipeline: 'totals' key missing."


@pytest.mark.asyncio
async def test_d07_traffic_pipeline_timeline_item_schema(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(
                f"{NS}/traffic-pipeline?range=15&bucket=60",
                cookies=cookies,
            )
            assert r.status == 200
            d = await r.json()
            tl = d.get("timeline", [])
            assert isinstance(tl, list), "/traffic-pipeline: 'timeline' must be a list."
            assert len(tl) > 0, "/traffic-pipeline: timeline is empty."
            first = tl[0]
            for key in ("t", "allowed", "challenged", "blocked", "bypassed"):
                assert key in first, (
                    f"/traffic-pipeline: timeline item missing '{key}' key. "
                    f"Got keys: {list(first.keys())}"
                )
            assert isinstance(first["t"], int), "/traffic-pipeline: 't' must be an int epoch."


@pytest.mark.asyncio
async def test_d08_traffic_pipeline_respects_range_bucket(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            range_min, bucket_secs = 30, 300
            r = await cli.get(
                f"{NS}/traffic-pipeline?range={range_min}&bucket={bucket_secs}",
                cookies=cookies,
            )
            assert r.status == 200
            d = await r.json()
            assert d.get("range_min") == range_min, (
                f"/traffic-pipeline: range_min={d.get('range_min')}, expected {range_min}."
            )
            assert d.get("bucket_secs") == bucket_secs, (
                f"/traffic-pipeline: bucket_secs={d.get('bucket_secs')}, expected {bucket_secs}."
            )
            tl = d.get("timeline", [])
            expected_slots = max(2, min(250, (range_min * 60) // bucket_secs))
            assert len(tl) == expected_slots, (
                f"/traffic-pipeline: expected {expected_slots} slots for "
                f"range={range_min}m / bucket={bucket_secs}s, got {len(tl)}."
            )


@pytest.mark.asyncio
async def test_d09_traffic_pipeline_cache_control_no_store(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(
                f"{NS}/traffic-pipeline?range=60&bucket=300",
                cookies=cookies,
            )
            assert r.status == 200
            cc = r.headers.get("Cache-Control", "")
            assert "no-store" in cc, (
                f"/traffic-pipeline Cache-Control is '{cc}', expected 'no-store'."
            )


@pytest.mark.asyncio
async def test_d10_traffic_pipeline_unauthenticated_deflected(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{NS}/traffic-pipeline?range=60&bucket=300")
            if r.status == 200:
                import json as _json
                try:
                    d = _json.loads(await r.text())
                    assert "timeline" not in d, (
                        "/traffic-pipeline: unauthenticated request returned real data."
                    )
                except (_json.JSONDecodeError, TypeError):
                    pass
            else:
                assert r.status in (401, 403, 302, 301, 404), (
                    f"/traffic-pipeline: unexpected status {r.status} for unauthenticated request."
                )


# ── /vhost-heatmap ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_d11_vhost_heatmap_returns_200(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(
                f"{NS}/vhost-heatmap?range=120&bucket=300",
                cookies=cookies,
            )
            assert r.status == 200, (
                f"/vhost-heatmap returned HTTP {r.status}, expected 200."
            )


@pytest.mark.asyncio
async def test_d12_vhost_heatmap_schema(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(
                f"{NS}/vhost-heatmap?range=60&bucket=300",
                cookies=cookies,
            )
            assert r.status == 200
            d = await r.json()
            assert "vhosts" in d, "/vhost-heatmap: 'vhosts' key missing."
            assert "buckets" in d, "/vhost-heatmap: 'buckets' key missing."
            assert "cells" in d, "/vhost-heatmap: 'cells' key missing."
            assert isinstance(d["vhosts"], list), "/vhost-heatmap: 'vhosts' must be a list."
            assert isinstance(d["buckets"], list), "/vhost-heatmap: 'buckets' must be a list."
            assert isinstance(d["cells"], dict), "/vhost-heatmap: 'cells' must be a dict."


@pytest.mark.asyncio
async def test_d13_vhost_heatmap_seeded_event_appears(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            now = time.time()
            # Seed into the ACTIVE backend — /vhost-heatmap reads from whichever
            # backend is active, so in PG-mode seeding SQLite would be invisible.
            import os as _os
            _pg = (_os.environ.get("APPSECGW_TEST_PG", "").lower()
                   in ("1", "true", "yes")
                   and bool(_os.environ.get("POSTGRES_DSN", "").strip()))
            if _pg:
                import psycopg
                with psycopg.connect(_os.environ["POSTGRES_DSN"],
                                     connect_timeout=5) as _c:
                    # PG events.ts is timestamptz → to_timestamp(epoch).
                    _c.execute(
                        "INSERT INTO events (ts, ip, ua, path, status, reason, vhost) "
                        "VALUES (to_timestamp(%s), '5.5.5.5', 'bot', '/heat', 200, "
                        "'ua-block', 'heatmap-test.local')",
                        (now - 30,),
                    )
                    _c.commit()
            else:
                conn = sqlite3.connect(proxy_module.DB_PATH)
                conn.execute(
                    "INSERT INTO events (ts, ip, ua, path, status, reason, vhost) "
                    "VALUES (?, '5.5.5.5', 'bot', '/heat', 200, 'ua-block', 'heatmap-test.local')",
                    (now - 30,),
                )
                conn.commit()
                conn.close()

            r = await cli.get(
                f"{NS}/vhost-heatmap?range=60&bucket=300",
                cookies=cookies,
            )
            assert r.status == 200
            d = await r.json()
            assert "heatmap-test.local" in d.get("vhosts", []), (
                "/vhost-heatmap: seeded event for 'heatmap-test.local' not reflected in vhosts. "
                f"Got: {d.get('vhosts', [])}"
            )
            cells = d.get("cells", {}).get("heatmap-test.local", [])
            total_events = sum(c.get("total", 0) for c in cells)
            assert total_events >= 1, (
                "/vhost-heatmap: heatmap-test.local cells have zero total despite seeded event."
            )


@pytest.mark.asyncio
async def test_d14_vhost_heatmap_cache_control_no_store(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(
                f"{NS}/vhost-heatmap?range=60&bucket=300",
                cookies=cookies,
            )
            assert r.status == 200
            cc = r.headers.get("Cache-Control", "")
            assert "no-store" in cc, (
                f"/vhost-heatmap Cache-Control is '{cc}', expected 'no-store'."
            )


@pytest.mark.asyncio
async def test_d15_vhost_heatmap_unauthenticated_deflected(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{NS}/vhost-heatmap?range=60&bucket=300")
            if r.status == 200:
                import json as _json
                try:
                    d = _json.loads(await r.text())
                    assert "vhosts" not in d, (
                        "/vhost-heatmap: unauthenticated request returned real data."
                    )
                except (_json.JSONDecodeError, TypeError):
                    pass
            else:
                assert r.status in (401, 403, 302, 301, 404), (
                    f"/vhost-heatmap: unexpected status {r.status} for unauthenticated request."
                )


# ── /signal-performance ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_d16_signal_performance_returns_200(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/signal-performance", cookies=cookies)
            assert r.status == 200, (
                f"/signal-performance returned HTTP {r.status}, expected 200."
            )
            d = await r.json()
            assert "signals" in d, "/signal-performance: 'signals' key missing."
            assert "method_totals" in d, "/signal-performance: 'method_totals' key missing."


@pytest.mark.asyncio
async def test_d17_signal_performance_signals_schema(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/signal-performance", cookies=cookies)
            assert r.status == 200
            d = await r.json()
            signals = d.get("signals", [])
            assert isinstance(signals, list), "/signal-performance: 'signals' must be a list."
            # With no traffic the list may be empty — test schema only when data exists
            if signals:
                sig = signals[0]
                for field in ("reason", "method", "hits", "blocks", "p50_ms", "p95_ms",
                              "p99_ms", "block_rate"):
                    assert field in sig, (
                        f"/signal-performance: signal item missing '{field}' field. "
                        f"Got keys: {list(sig.keys())}"
                    )
                assert isinstance(sig["hits"], int), "/signal-performance: hits must be int."
                assert isinstance(sig["blocks"], int), "/signal-performance: blocks must be int."
                assert isinstance(sig["block_rate"], float), (
                    "/signal-performance: block_rate must be float."
                )


@pytest.mark.asyncio
async def test_d18_signal_performance_method_totals_schema(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/signal-performance", cookies=cookies)
            assert r.status == 200
            d = await r.json()
            mt = d.get("method_totals", {})
            assert isinstance(mt, dict), "/signal-performance: 'method_totals' must be a dict."
            # If populated, each entry must have hits + blocks
            for method, totals in mt.items():
                assert "hits" in totals, (
                    f"/signal-performance: method_totals['{method}'] missing 'hits'."
                )
                assert "blocks" in totals, (
                    f"/signal-performance: method_totals['{method}'] missing 'blocks'."
                )


@pytest.mark.asyncio
async def test_d19_signal_performance_cache_control_no_store(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            cookies = _admin_cookie(proxy_module)
            r = await cli.get(f"{NS}/signal-performance", cookies=cookies)
            assert r.status == 200
            cc = r.headers.get("Cache-Control", "")
            assert "no-store" in cc, (
                f"/signal-performance Cache-Control is '{cc}', expected 'no-store'."
            )


@pytest.mark.asyncio
async def test_d20_signal_performance_unauthenticated_deflected(proxy_module):
    async with _spin_upstream() as up:
        async with _gateway(proxy_module, up) as cli:
            r = await cli.get(f"{NS}/signal-performance")
            if r.status == 200:
                import json as _json
                try:
                    d = _json.loads(await r.text())
                    assert "signals" not in d, (
                        "/signal-performance: unauthenticated request returned real data."
                    )
                except (_json.JSONDecodeError, TypeError):
                    pass
            else:
                assert r.status in (401, 403, 302, 301, 404), (
                    f"/signal-performance: unexpected status {r.status} for unauthenticated request."
                )
