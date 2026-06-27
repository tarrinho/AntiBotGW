/* dashboard-common.js — shared dashboard helpers (improvement #5).
 * Served from /antibot-appsec-gateway/assets/ (auth-gated like purify/chart;
 * the operator's browser sends its session cookie, so it loads with the page).
 * Included by every dashboard before its inline scripts.
 * Phase 1: escapeHtml (was inline in 14 files, with 3 drifted variants).
 */
/* 1.9.2 iter-22 UX — global reduced-motion + screen-reader-status helpers.
 *
 * U1: respect the operator's `prefers-reduced-motion: reduce` OS setting by
 *     killing the dashboard's decorative animations (pulse pill, chart
 *     transitions, opacity fades on data-stale state). Vestibular-disorder
 *     users no longer get unwanted motion in their peripheral vision.
 *     Single shared style tag injected at the top of every page — one edit
 *     covers all 16 dashboards instead of 16 CSS pastes.
 *
 * U4: surface a tiny markAsStatus(el) helper so any caller that swaps in
 *     "no data" content can announce it to screen readers without each
 *     dashboard having to remember the role/aria-live pair.
 */
(function () {
  "use strict";
  if (window._gwReducedMotionInstalled) return;
  window._gwReducedMotionInstalled = true;
  var rmStyle = document.createElement("style");
  rmStyle.textContent =
    "@media (prefers-reduced-motion: reduce){" +
      "*,*::before,*::after{" +
        "animation-duration:0.01ms!important;" +
        "animation-iteration-count:1!important;" +
        "transition-duration:0.01ms!important;" +
        "scroll-behavior:auto!important" +
      "}" +
      ".gw-pill-pulse{animation:none!important}" +
      "#page-content.data-stale{transition:none!important}" +
    "}";
  document.head.appendChild(rmStyle);
  window.markAsStatus = function (el) {
    if (!el) return;
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", "polite");
    el.setAttribute("aria-atomic", "true");
  };
})();

(function () {
  "use strict";
  if (typeof window.escapeHtml !== "function") {
    window.escapeHtml = function (s) {
      return String(s == null ? "" : s).replace(/[&<>"'`/]/g, function (c) {
        return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;",
                "'": "&#39;", "`": "&#96;", "/": "&#47;"}[c];
      });
    };
  }
})();

/* 1.9.2 UX — global top-of-page progress bar.
 *
 * Hooks window.fetch (and XMLHttpRequest) so a 2 px shimmer bar appears at
 * the top of every page while ANY request is in-flight, and drains the
 * moment all pending requests resolve. No fake percentage — just a clear
 * "something is loading" signal. Matches the YouTube / GitHub / Vercel
 * pattern: cheap, honest, universal.
 *
 * Idempotent — the install guard prevents double-wrapping if the script
 * loads twice (e.g. via a stale cache reload).
 */
(function () {
  "use strict";
  if (window._gwProgressBarInstalled) return;
  window._gwProgressBarInstalled = true;

  var style = document.createElement("style");
  style.textContent =
    "#gw-progress-bar{position:fixed;top:0;left:0;height:2px;" +
    "background:linear-gradient(90deg,var(--blue,#79c0ff) 0%," +
    "var(--blue,#79c0ff) 60%,rgba(121,192,255,.4) 100%);" +
    "width:0%;z-index:99999;pointer-events:none;" +
    "transition:width .25s ease-out,opacity .2s ease-out;opacity:0}" +
    "#gw-progress-bar.gw-on{opacity:1}" +
    "#gw-progress-bar.gw-done{width:100%!important;opacity:0}" +
    "@media (prefers-reduced-motion:reduce){" +
    "#gw-progress-bar{transition:opacity .15s linear}}";
  document.head.appendChild(style);

  var bar = null;
  function ensureBar() {
    if (bar) return bar;
    bar = document.getElementById("gw-progress-bar");
    if (!bar) {
      bar = document.createElement("div");
      bar.id = "gw-progress-bar";
      (document.body || document.documentElement).appendChild(bar);
    }
    return bar;
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ensureBar);
  } else {
    ensureBar();
  }

  var inflight = 0;
  var raf = 0;
  var doneTimer = 0;

  function paint() {
    raf = 0;
    var b = ensureBar();
    if (inflight > 0) {
      // Asymptote toward 90 % — never claim "done" until the count is 0.
      // Width grows logarithmically with the call count so a flood of
      // parallel fetches doesn't jump straight to 90 % then look stuck.
      var pct = Math.min(90, 30 + 18 * Math.log2(inflight + 1));
      b.classList.remove("gw-done");
      b.classList.add("gw-on");
      b.style.width = pct.toFixed(0) + "%";
      if (doneTimer) { clearTimeout(doneTimer); doneTimer = 0; }
    } else {
      // Drain — finish visually, fade, reset.
      b.classList.add("gw-done");
      b.classList.remove("gw-on");
      if (doneTimer) clearTimeout(doneTimer);
      doneTimer = setTimeout(function () {
        b.classList.remove("gw-done");
        b.style.width = "0%";
        doneTimer = 0;
      }, 350);
    }
  }
  function schedule() { if (!raf) raf = requestAnimationFrame(paint); }
  function bump(delta) {
    inflight = Math.max(0, inflight + delta);
    schedule();
  }

  // Hook window.fetch.
  var realFetch = window.fetch;
  if (typeof realFetch === "function") {
    window.fetch = function () {
      bump(+1);
      var p;
      try { p = realFetch.apply(this, arguments); }
      catch (e) { bump(-1); throw e; }
      if (p && typeof p.finally === "function") {
        return p.finally(function () { bump(-1); });
      }
      return p.then(
        function (r) { bump(-1); return r; },
        function (e) { bump(-1); throw e; }
      );
    };
  }

  // Hook XMLHttpRequest — Chart.js and a few legacy helpers still use it.
  var XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype && XHR.prototype.send && !XHR.prototype._gwWrapped) {
    XHR.prototype._gwWrapped = true;
    var realSend = XHR.prototype.send;
    XHR.prototype.send = function () {
      var self = this;
      var done = false;
      function dec() { if (done) return; done = true; bump(-1); }
      try {
        bump(+1);
        self.addEventListener("loadend", dec);
        return realSend.apply(self, arguments);
      } catch (e) { dec(); throw e; }
    };
  }
})();

/* 1.9.2 iter-23 UX — slow-request toast.
 *
 * The 2 px progress bar above is the universal "something is loading" signal,
 * but at 2 px on the very top of the viewport it's easy to miss when a fetch
 * takes 5+ seconds (the operator-reported pain point: "some pages take more
 * than 5 seconds and I need to have a visible way to show the user what is
 * going on").
 *
 * This toast complements the bar:
 *   - Silent for fast requests (< 1500 ms) — no flash on healthy pages
 *   - Appears top-right after 1500 ms with a live elapsed-seconds counter
 *   - Names the slowest in-flight URL (truncated to the last path segment)
 *     so the operator knows WHAT is slow, not just THAT something is
 *   - Disappears instantly when all in-flight requests resolve
 *
 * Idempotent + reduced-motion-aware (inherits the global rule above).
 * Hooks the same fetch + XHR wrappers; we tag each request with its start
 * time and URL so the toast can compute "longest-running" cheaply.
 */
(function () {
  "use strict";
  if (window._gwSlowToastInstalled) return;
  window._gwSlowToastInstalled = true;

  var SLOW_MS = 1500;     // appear after this long
  var TICK_MS = 250;      // re-render rate

  var style = document.createElement("style");
  style.textContent =
    "#gw-slow-toast{position:fixed;top:14px;right:14px;z-index:99998;" +
      "background:var(--card,#161b22);color:var(--fg,#c9d1d9);" +
      "border:1px solid var(--blue,#79c0ff);border-radius:6px;" +
      "padding:8px 12px;font:12px/1.4 -apple-system,'SF Pro',ui-sans-serif,sans-serif;" +
      "box-shadow:0 4px 14px rgba(0,0,0,.35);max-width:380px;" +
      "display:none;align-items:center;gap:10px;pointer-events:none}" +
    "#gw-slow-toast.gw-show{display:flex}" +
    "#gw-slow-toast .gw-spin{width:12px;height:12px;border:2px solid var(--blue,#79c0ff);" +
      "border-top-color:transparent;border-radius:50%;animation:gw-spin .8s linear infinite;flex-shrink:0}" +
    "#gw-slow-toast .gw-msg{font-weight:600}" +
    "#gw-slow-toast .gw-url{color:var(--dim,#8b949e);font-family:ui-monospace,Menlo,monospace;font-size:11px;" +
      "max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}" +
    "#gw-slow-toast .gw-elapsed{color:var(--blue,#79c0ff);font-weight:700;font-variant-numeric:tabular-nums}" +
    "@keyframes gw-spin{to{transform:rotate(360deg)}}" +
    "@media (prefers-reduced-motion:reduce){" +
      "#gw-slow-toast .gw-spin{animation:none;border-top-color:var(--blue,#79c0ff);opacity:.6}}";
  document.head.appendChild(style);

  var toast = null;
  function ensureToast() {
    if (toast) return toast;
    toast = document.getElementById("gw-slow-toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "gw-slow-toast";
      toast.setAttribute("role", "status");
      toast.setAttribute("aria-live", "polite");
      toast.innerHTML =
        '<span class="gw-spin" aria-hidden="true"></span>' +
        '<span class="gw-msg">Loading…</span>' +
        '<span class="gw-url"></span>' +
        '<span class="gw-elapsed"></span>';
      (document.body || document.documentElement).appendChild(toast);
    }
    return toast;
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", ensureToast);
  } else {
    ensureToast();
  }

  // In-flight registry: id -> {started, url}
  var nextId = 1;
  var registry = Object.create(null);
  var tickHandle = 0;

  function _shortUrl(u) {
    try {
      if (!u) return "";
      var s = String(u);
      // Drop origin if same-origin; show last 2 path segments + querystring
      var idx = s.indexOf("://");
      if (idx > -1) s = s.substring(s.indexOf("/", idx + 3) || s.length);
      // Last 2 segments
      var qs = "";
      var qi = s.indexOf("?");
      if (qi > -1) { qs = s.substring(qi); s = s.substring(0, qi); }
      var parts = s.split("/").filter(Boolean);
      if (parts.length > 2) parts = parts.slice(-2);
      return "/" + parts.join("/") + (qs.length > 24 ? qs.substring(0, 24) + "…" : qs);
    } catch (e) { return ""; }
  }

  function _render() {
    var t = ensureToast();
    if (!t) return;
    var ids = Object.keys(registry);
    if (!ids.length) {
      t.classList.remove("gw-show");
      if (tickHandle) { clearInterval(tickHandle); tickHandle = 0; }
      return;
    }
    var now = Date.now();
    var oldest = null, oldestAge = 0;
    for (var i = 0; i < ids.length; i++) {
      var r = registry[ids[i]];
      var age = now - r.started;
      if (age > oldestAge) { oldestAge = age; oldest = r; }
    }
    if (oldestAge < SLOW_MS) {
      // No request is slow yet — keep hidden but schedule next tick.
      t.classList.remove("gw-show");
      return;
    }
    var urlEl = t.querySelector(".gw-url");
    var elaEl = t.querySelector(".gw-elapsed");
    if (urlEl) urlEl.textContent = _shortUrl(oldest && oldest.url);
    if (elaEl) elaEl.textContent = (oldestAge / 1000).toFixed(1) + "s";
    t.classList.add("gw-show");
  }

  function _trackStart(url) {
    var id = nextId++;
    registry[id] = { started: Date.now(), url: url };
    if (!tickHandle) { tickHandle = setInterval(_render, TICK_MS); }
    // Schedule one immediate render so we know within ~SLOW_MS whether to show
    setTimeout(_render, SLOW_MS + 50);
    return id;
  }
  function _trackEnd(id) {
    if (id == null) return;
    delete registry[id];
    _render();
  }

  // Wrap fetch (a second wrap layer is fine: the progress-bar wrap from above
  // already incremented its `inflight` count, so we just observe URL + timing).
  var realFetch2 = window.fetch;
  if (typeof realFetch2 === "function") {
    window.fetch = function (input) {
      var url = (typeof input === "string") ? input :
                (input && input.url) ? input.url : "";
      var id = _trackStart(url);
      var p;
      try { p = realFetch2.apply(this, arguments); }
      catch (e) { _trackEnd(id); throw e; }
      if (p && typeof p.finally === "function") {
        return p.finally(function () { _trackEnd(id); });
      }
      return p.then(
        function (r) { _trackEnd(id); return r; },
        function (e) { _trackEnd(id); throw e; }
      );
    };
  }

  // Wrap XMLHttpRequest open() so we capture the URL, then send() for timing.
  var XHR2 = window.XMLHttpRequest;
  if (XHR2 && XHR2.prototype && !XHR2.prototype._gwSlowWrapped) {
    XHR2.prototype._gwSlowWrapped = true;
    var realOpen = XHR2.prototype.open;
    XHR2.prototype.open = function (method, url) {
      this._gwUrl = url || "";
      return realOpen.apply(this, arguments);
    };
    var realSend2 = XHR2.prototype.send;
    XHR2.prototype.send = function () {
      var self = this;
      var id = _trackStart(self._gwUrl || "");
      var done = false;
      function dec() { if (done) return; done = true; _trackEnd(id); }
      try {
        self.addEventListener("loadend", dec);
        return realSend2.apply(self, arguments);
      } catch (e) { dec(); throw e; }
    };
  }
})();
