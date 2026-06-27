"""
tests/test_v192_progress_bar.py — guard the 1.9.2 global progress-bar UX.

The progress bar is implemented as a fetch + XHR wrapper in
`dashboards/assets/dashboard-common.js`. It must be:
  • idempotent (double-load doesn't double-wrap)
  • honest (no fake percentage — width derived from in-flight count)
  • universal (every dashboard loads dashboard-common.js)
  • drained on error (a catch-path must still decrement)

Also guards the Vhost Policy phased-render contract — the per-vhost
fan-out updates a counter as each promise resolves, instead of waiting
for Promise.all to render anything.
"""
import os
import re

_REPO = os.path.join(os.path.dirname(__file__), "..")
COMMON_JS = os.path.join(_REPO, "dashboards", "assets", "dashboard-common.js")
VHOST_HTML = os.path.join(_REPO, "dashboards", "vhost_policy.html")

# Every operator-facing dashboard must wire the shared common.js so the
# progress bar covers them.
_DASHBOARDS_NEEDING_COMMON = (
    "main.html",
    "agents.html",
    "control_center.html",
    "settings.html",
    "logs.html",
    "vhost_policy.html",
    "honeypots.html",
)


def _src(path):
    return open(path, encoding="utf-8").read()


# ── Progress-bar helper contract ─────────────────────────────────────────

def test_progress_bar_install_is_idempotent():
    """Loading the script twice (stale cache reload, double-include) must
    NOT double-wrap fetch — that would decrement the counter twice per
    request and the bar would never show."""
    src = _src(COMMON_JS)
    assert "_gwProgressBarInstalled" in src, (
        "must declare window._gwProgressBarInstalled as the install guard"
    )
    # Must check the flag BEFORE wrapping anything.
    assert re.search(
        r"if\s*\(\s*window\._gwProgressBarInstalled\s*\)\s*return",
        src,
    ), "install guard must `if (window._gwProgressBarInstalled) return;`"


def test_progress_bar_wraps_window_fetch():
    src = _src(COMMON_JS)
    assert "var realFetch = window.fetch" in src, (
        "must capture the original window.fetch before wrapping"
    )
    assert "window.fetch = function" in src, (
        "must rebind window.fetch to the wrapper"
    )


def test_progress_bar_wraps_xhr():
    """Chart.js plugins + legacy helpers still use XHR — leaving it
    unhooked means those requests don't drive the bar."""
    src = _src(COMMON_JS)
    assert "XMLHttpRequest" in src and "_gwWrapped" in src, (
        "must wrap XMLHttpRequest.prototype.send with its own install guard "
        "(_gwWrapped) so a double-load doesn't double-bump"
    )
    assert '"loadend"' in src or "'loadend'" in src, (
        "XHR hook must listen on 'loadend' so any terminal state decrements"
    )


def test_progress_bar_decrements_on_error_path():
    """fetch().catch() must still drain the counter. Without this, a
    failed request leaves the bar pinned at >0 forever."""
    src = _src(COMMON_JS)
    # Either .finally() or a then(ok, err) pair — both must decrement.
    has_finally = re.search(r"\.finally\(function\s*\(\)\s*\{\s*bump\(-1\)", src)
    has_then_err = "function (e) { bump(-1); throw e; }" in src
    assert has_finally or has_then_err, (
        "fetch wrapper must decrement on BOTH success and error paths "
        "(via .finally or a then(ok, err) pair) — otherwise a network "
        "error pins the bar at >0 forever"
    )
    # Synchronous throw inside realFetch.apply (e.g. invalid argument)
    # must also drain.
    assert "catch (e) { bump(-1); throw e; }" in src, (
        "synchronous throw from realFetch.apply must also decrement"
    )


def test_progress_bar_never_claims_100_pct_until_count_zero():
    """The width is honest — it asymptotes toward 90 % while inflight > 0
    and only hits 100 % via the .gw-done drain class. A constant 90 %
    cap is the operator-visible contract."""
    src = _src(COMMON_JS)
    assert "Math.min(90" in src, (
        "width must asymptote toward 90 % while inflight > 0 — never "
        "claim '100 % done' before the counter actually drains"
    )
    assert "gw-done" in src, (
        "must use a .gw-done drain class to handle the final 90→100 % "
        "visual flourish"
    )


def test_progress_bar_uses_request_animation_frame():
    """A raw setInterval / setTimeout-per-bump would thrash the layout
    on a 100-request page. rAF batches paints to the browser's render
    cycle."""
    src = _src(COMMON_JS)
    assert "requestAnimationFrame" in src, (
        "must batch paint updates via requestAnimationFrame — never "
        "update style.width per bump (layout thrash on heavy pages)"
    )


def test_progress_bar_respects_reduced_motion():
    """Operators on accessibility settings (prefers-reduced-motion) should
    NOT see the slide animation — they get a simple opacity flip."""
    src = _src(COMMON_JS)
    assert "prefers-reduced-motion" in src, (
        "CSS must include @media (prefers-reduced-motion: reduce) so the "
        "bar respects accessibility settings"
    )


# ── Dashboard wiring ─────────────────────────────────────────────────────

def test_every_dashboard_loads_dashboard_common():
    """Without this <script src=…> line on every dashboard, the bar
    doesn't show. Catch the next dashboard that adds a new HTML file
    and forgets to include it."""
    for name in _DASHBOARDS_NEEDING_COMMON:
        path = os.path.join(_REPO, "dashboards", name)
        src = _src(path)
        assert "/assets/dashboard-common.js" in src, (
            f"dashboards/{name} must <script src=… dashboard-common.js> "
            "so the global progress bar (and escapeHtml) are available"
        )


def test_dashboard_common_loads_before_inline_csrf_wrapper():
    """The CSRF inline wrapper rebinds window.fetch. If dashboard-common.js
    loads AFTER it, the progress bar wraps the CSRF wrapper (fine) — but
    if dashboard-common.js loads after some other wrapper, the count can
    go wrong. We anchor on Vhost Policy which has both."""
    src = _src(VHOST_HTML)
    common_idx = src.find("dashboard-common.js")
    # The CSRF wrapper is the inline `(function(){var _orig=window.fetch;`.
    csrf_idx = src.find("_orig=window.fetch")
    assert common_idx != -1, "vhost_policy.html must load dashboard-common.js"
    assert csrf_idx != -1, "vhost_policy.html must wire the CSRF wrapper"
    assert common_idx < csrf_idx, (
        "dashboard-common.js must load BEFORE the inline CSRF wrapper so "
        "the progress hook is in place before fetch gets re-bound"
    )


# ── Vhost Policy phased render ───────────────────────────────────────────

def test_loadall_renders_counter_immediately():
    """Phased render — `_loadAllVhostSummary` paints a `Loading N / M`
    counter BEFORE the fetches finish, instead of leaving the page blank
    until Promise.all resolves."""
    src = _src(VHOST_HTML)
    fn_idx = src.find("function _loadAllVhostSummary")
    end = src.find("\nfunction ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else fn_idx + 4000]
    # The counter element id is operator-visible — anchor it.
    assert 'id="vh-load-counter"' in block, (
        "_loadAllVhostSummary must render an initial '<div id=\"vh-load-counter\">' "
        "placeholder so the operator sees 'Loading 0 / N…' immediately"
    )
    # The placeholder must be painted BEFORE the fetches fire.
    counter_idx = block.find('id="vh-load-counter"')
    fetch_idx = block.find("fetch(ADMIN_NS")
    assert counter_idx != -1 and fetch_idx != -1, (
        "both the counter setup and the fan-out fetch must be present"
    )
    assert counter_idx < fetch_idx, (
        "the counter placeholder must be painted BEFORE the fan-out fetches "
        "fire — otherwise the operator sees nothing until the first one resolves"
    )


def test_loadall_bumps_counter_per_resolution():
    """Each per-vhost fetch.then must bump the counter as it resolves —
    not wait for Promise.all. This is the 'phased' part of phased render."""
    src = _src(VHOST_HTML)
    fn_idx = src.find("function _loadAllVhostSummary")
    end = src.find("\nfunction ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else fn_idx + 4000]
    # The bump helper updates the counter text. Anchor on its existence
    # AND on it being called from each promise's .then.
    assert "_bump" in block, (
        "_loadAllVhostSummary must define a _bump() helper that updates "
        "the counter text as each per-vhost summary resolves"
    )
    # Bump must be called from the per-promise then — same level of
    # nesting as the fetch.
    assert re.search(r"\.then\(function\s*\(d\)\s*\{[\s\S]{0,400}_bump\(\)",
                     block), (
        "_bump() must be called from the per-vhost .then() callback so "
        "the counter increments as each promise resolves, not after "
        "Promise.all"
    )


def test_loadall_still_renders_overrides_at_end():
    """Phased render doesn't replace the final full render — _renderOverrides
    must still run once all promises settle so the grid math + sort are
    correct against the complete dataset."""
    src = _src(VHOST_HTML)
    fn_idx = src.find("function _loadAllVhostSummary")
    end = src.find("\nfunction ", fn_idx + 1)
    block = src[fn_idx: end if end > 0 else fn_idx + 4000]
    assert "Promise.all(promises)" in block, (
        "Promise.all must still be awaited so the final _renderOverrides "
        "runs against the complete merged summary"
    )
    # The Promise.all .then must call _renderOverrides.
    m = re.search(r"Promise\.all\(promises\)\.then\(function\s*\(\s*\)\s*\{[\s\S]{0,200}_renderOverrides\(\)",
                  block)
    assert m, (
        "the Promise.all completion handler must call _renderOverrides() "
        "for the final grid render"
    )
