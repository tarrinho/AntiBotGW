# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
Step 17j — Dashboard dynamic + mobile check (Playwright).

Usage:
  python3 scripts/dashboard_check.py \
      --base http://localhost:8443 \
      --prefix /antibot-appsec-gateway \
      --key <INTERNAL_KEY> \
      --admin-xff 172.17.0.1 \
      --screenshot-dir /tmp/dash_screenshots

  # The runtime INTERNAL_KEY is the bootstrap admin password. Pull it from
  # the running container (NOT the local `.admin_key` file, which may be a
  # placeholder and won't match the rotated key inside the container):
  #   KEY=$(docker exec <container> python3 -c 'from config import INTERNAL_KEY; print(INTERNAL_KEY)' | grep -v '^\[keys\]' | tail -1)

Exit 0 = all checks pass. Exit 1 = failures found.

Pre-requisite — admin-IP gate
  The gateway hides ADMIN_NS behind the silent-decoy mirror when the source
  IP isn't in ADMIN_ALLOWED_NETS — so the dashboards 404 with upstream HTML.
  This script spoofs `X-Forwarded-For` on every request (--admin-xff, default
  `172.17.0.1`) so the runner appears as an admin-allowed IP. The spoof only
  takes effect if (a) the gateway's socket peer is in TRUSTED_PROXIES and
  (b) the --admin-xff value is in ADMIN_ALLOWED_NETS.

  If you see "Refused to execute script" CSP errors with celfocus/upstream
  URLs in them, the admin-IP gate is rejecting and the decoy is mirroring
  the upstream HTML. Fix by adding the runner's IP to ADMIN_ALLOWED_NETS
  (Settings → Admin Access) or by choosing an --admin-xff value already in
  the allowlist on the target gateway.
"""
import argparse
import os
import sys
import json
from pathlib import Path
from playwright.sync_api import sync_playwright, ConsoleMessage

PAGES = [
    "live-feed",
    "geo",
    "logs",
    "agents",
    "service",
    "controls",
    "settings",
    "siem",
]

VIEWPORTS = [
    ("desktop", 1440, 900),
    ("tablet",  768,  1024),
    ("mobile",  390,  844),
]

DYNAMIC_SELECTORS = {
    "live-feed": ["#score-pill", "#score-value", "#live-log"],
    "geo":       ["#geo-map", "#geo-table", "#geo-container"],
    "logs":      ["#log-table", "#log-container", "#log-entries"],
    "agents":    ["#agent-table", "#agent-container", "#agents-table"],
    "service":   ["#service-table", "#service-container", "#service-metrics"],
    "controls":  ["#controls-form", "#rules-container", "#controls-container"],
    "settings":  ["#settings-form", "#settings-container", "#vhost-form"],
    "siem":      ["#siem-table", "#siem-container", "#event-table"],
}


def login(page, base, prefix, key, origin=None):
    # POST via fetch from page context so cookies land in browser context.
    # Same-origin fetch defaults to Origin = page origin, which is the gateway
    # itself — that satisfies the 1.8.11 eTLD+1 origin check (the gateway
    # rejects POST /login with `reason: origin-mismatch` otherwise).
    login_url = f"{base}{prefix}/login"
    page.goto(login_url, wait_until="domcontentloaded")
    page.evaluate("""async ([url, key]) => {
        const resp = await fetch(url, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'username=admin&password=' + encodeURIComponent(key),
            credentials: 'include',
            redirect: 'manual',
        });
        return resp.status;
    }""", [login_url, key])
    page.wait_for_timeout(800)


def check_page(page, base, prefix, page_name, viewport_name, width, height,
               screenshot_dir, errors_collector):
    failures = []
    url = f"{base}{prefix}/secured/{page_name}"

    page.set_viewport_size({"width": width, "height": height})

    js_errors = []
    page.on("console", lambda msg: js_errors.append(msg.text)
            if msg.type == "error" else None)
    page.on("pageerror", lambda exc: js_errors.append(str(exc)))

    resp = page.goto(url, wait_until="domcontentloaded", timeout=20000)
    page.wait_for_timeout(1500)  # let JS render dynamic content

    # 1. HTTP 200
    if resp and resp.status != 200:
        failures.append(f"{page_name}/{viewport_name}: HTTP {resp.status}")

    # 2. Not redirected to /login
    if "/login" in page.url:
        failures.append(f"{page_name}/{viewport_name}: redirected to login")

    # 3. Dynamic content present (at least one selector visible)
    candidates = DYNAMIC_SELECTORS.get(page_name, [])
    found_dynamic = False
    for sel in candidates:
        try:
            el = page.query_selector(sel)
            if el:
                found_dynamic = True
                break
        except Exception:
            pass
    if candidates and not found_dynamic:
        # Softer check: at least body has content beyond the skeleton
        body_text = page.inner_text("body") or ""
        if len(body_text.strip()) > 200:
            found_dynamic = True
    if candidates and not found_dynamic:
        failures.append(f"{page_name}/{viewport_name}: no dynamic content ({candidates})")

    # 4. No horizontal scroll on mobile
    if viewport_name == "mobile":
        scroll_width = page.evaluate("document.body.scrollWidth")
        if scroll_width > width + 5:
            failures.append(
                f"{page_name}/{viewport_name}: horizontal scroll "
                f"scrollWidth={scroll_width} > {width+5}"
            )

    # 5. JS console errors
    if js_errors:
        for e in js_errors[:3]:  # cap at 3 per page
            failures.append(f"{page_name}/{viewport_name}: JS error: {e[:120]}")

    # Screenshot
    if screenshot_dir:
        Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
        path = os.path.join(screenshot_dir, f"{page_name}_{viewport_name}.png")
        page.screenshot(path=path, full_page=(viewport_name != "mobile"))

    errors_collector.extend(failures)
    return failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base",           default="http://localhost:8443")
    ap.add_argument("--prefix",         default="/antibot-appsec-gateway")
    ap.add_argument("--key",            required=True)
    ap.add_argument("--screenshot-dir", default="/tmp/dash_screenshots")
    ap.add_argument("--json-out",       default=None)
    ap.add_argument("--admin-xff",      default="172.17.0.1",
                    help="X-Forwarded-For value sent on every request so that "
                         "the loopback/CI host appears as an admin-allowed IP "
                         "(default: docker bridge gateway 172.17.0.1). Set to "
                         "an IP present in ADMIN_ALLOWED_NETS on the target gateway.")
    args = ap.parse_args()

    all_failures = []
    results = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path="/usr/bin/chromium",
            args=["--no-sandbox", "--disable-dev-shm-usage",
                  "--disable-gpu", "--disable-extensions"],
        )
        ctx = browser.new_context(
            ignore_https_errors=True,
            extra_http_headers={"X-Forwarded-For": args.admin_xff},
        )
        page = ctx.new_page()

        # Route interceptor: Chromium occasionally strips X-Forwarded-For from
        # `extra_http_headers` (treated like a proxy-only header). Re-inject on
        # every request, including sub-resources, so the gateway's admin-IP
        # gate sees the operator's allowlisted source IP — otherwise the
        # silent-decoy mirrors the upstream HTML and every dashboard 404s.
        def _add_xff(route, request):
            new_headers = {**request.headers, "X-Forwarded-For": args.admin_xff}
            route.continue_(headers=new_headers)
        page.route("**/*", _add_xff)

        login(page, args.base, args.prefix, args.key)

        for page_name in PAGES:
            results[page_name] = {}
            for vp_name, w, h in VIEWPORTS:
                fails = check_page(
                    page, args.base, args.prefix, page_name,
                    vp_name, w, h, args.screenshot_dir, all_failures,
                )
                results[page_name][vp_name] = "PASS" if not fails else fails

        browser.close()

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"failures": all_failures, "results": results}, f, indent=2)

    # Print summary
    total_checks = len(PAGES) * len(VIEWPORTS)
    fail_count = len(all_failures)
    print(f"\n=== Step 17j Playwright Results ===")
    print(f"Pages: {len(PAGES)} × Viewports: {len(VIEWPORTS)} = {total_checks} checks")
    print(f"Failures: {fail_count}")
    if all_failures:
        for f in all_failures:
            print(f"  FAIL: {f}")
    else:
        print("  All checks PASS")
    print()
    for pname, vps in results.items():
        for vname, status in vps.items():
            icon = "✓" if status == "PASS" else "✗"
            print(f"  {icon} {pname}/{vname}: {status if isinstance(status, str) else '; '.join(status)}")

    return 1 if all_failures else 0


if __name__ == "__main__":
    sys.exit(main())
