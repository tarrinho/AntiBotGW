"""
1.9.9 — GeoMap scan is offloaded to a worker thread (no event-loop freeze).

geo_data_endpoint previously ran the events scan + per-IP GeoIP/ASN mmdb lookups
synchronously on the asyncio event loop. For a wide window (up to 30 days) with
many unique IPs that blocked the whole gateway while the map loaded. The scan is
now wrapped in `def _scan(): …` and run via `await asyncio.to_thread(_scan)` so
the loop stays responsive; the 60s `_GEO_CACHE` still serves repeat ticks.
"""
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_PH = (_REPO / "core" / "proxy_handler.py").read_text(encoding="utf-8")


def _geo_src():
    i = _PH.index("async def geo_data_endpoint(")
    return _PH[i: _PH.index("\nasync def ", i + 1)]


def test_geo_scan_runs_in_worker_thread():
    body = _geo_src()
    assert "def _scan():" in body, "the geo events scan must be wrapped in a _scan() helper"
    assert "await asyncio.to_thread(_scan)" in body, \
        "the geo scan must run via asyncio.to_thread so it never blocks the event loop"


def test_geo_scan_helper_declares_nonlocal_accumulators():
    body = _geo_src()
    # the counters rebound inside the worker must be declared nonlocal or their
    # updates are lost (skipped_no_geo would always read 0; sampling would break)
    assert re.search(r"nonlocal\s+skipped_no_geo,\s*_sample_seen", body), \
        "_scan must declare `nonlocal skipped_no_geo, _sample_seen`"


def test_geo_blocking_lookups_inside_scan_not_on_loop():
    body = _geo_src()
    scan_i = body.index("def _scan():")
    tothread_i = body.index("await asyncio.to_thread(_scan)")
    scan_region = body[scan_i:tothread_i]
    # the mmdb lookups + cursor iteration live inside the offloaded helper
    for needle in ("_city_lookup(", "conn.execute(", "for r in cursor:"):
        assert needle in scan_region, f"{needle} must be inside the offloaded _scan()"


def test_geo_response_surfaces_skipped_no_geo():
    # operators must be able to see events dropped for having no GeoIP coordinate
    # (private/LAN/unresolvable IPs) — both in the API payload and the dashboard.
    assert '"skipped_no_geo":  skipped_no_geo' in _PH
    geo_html = (_REPO / "dashboards" / "geo.html").read_text(encoding="utf-8")
    assert "skipped_no_geo" in geo_html and "m-nogeo" in geo_html, \
        "geo.html must display skipped_no_geo (the 'No geo' card)"
