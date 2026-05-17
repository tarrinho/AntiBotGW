"""
tests/test_v187_controls_order.py — QA for v1.8.7 activation-order cleanup.

P-tests: proxy_handler.py dead-code removal
  P01  _escalate variable not assigned in main request pipeline
  P02  _second_order variable not assigned in main request pipeline
  P03  _esc_score still computed (used by _should_run_signal)
  P04  _should_run_signal still imported from scoring

O-tests: SIGNAL_ORDER_DEFAULTS in controls.html matches backend
  O01  ua-ai-openai at order 1 (was 2 — cheap UA check, no gate needed)
  O02  ua-ai-anthropic at order 1
  O03  ua-ai-google at order 1
  O04  ua-ai-perplexity at order 1
  O05  ua-ai-meta at order 1
  O06  ua-ai-other at order 1
  O07  ai-probe at order 1 (backend never gated it)
  O08  ai-headers-empty at order 1
  O09  ai-headers-incomplete at order 1
  O10  ai-ua-ip-mismatch at order 1
  O11  robots-violation at order 1
  O12  tor-exit at order 1 (backend: not in SECOND_ORDER_REASONS)
  O13  suspicious-path at order 1 (backend: not in any gate set)
  O14  body-sqli at order 3 (was 2 — in ESCALATE_ONLY_REASONS)
  O15  body-xss at order 3
  O16  body-lfi at order 3
  O17  body-rce at order 3
  O18  body-ssrf at order 3
  O19  body-cmd at order 3
  O20  suspicious-body at order 3 (was absent — now explicit)
  O21  asn-hosting at order 3 (was 2 — in ESCALATE_ONLY_REASONS)
  O22  coordinated-probe at order 3 (was absent — now explicit)
  O23  direct-api-probe at order 2 (was absent — in SECOND_ORDER_REASONS)
  O24  ai-enumeration at order 2 (unchanged, verify not regressed)
  O25  ai-no-assets at order 2 (unchanged)
  O26  locale-geo-mismatch at order 2 (unchanged)
  O27  tls-fingerprint at order 2 (unchanged)
  O28  ja4-required-missing at order 2 (unchanged)
  O29  abuseipdb-high at order 3 (unchanged)
  O30  crowdsec-banned at order 3 (unchanged)
  O31  datacenter-vpn at order 3 (unchanged)

B-tests: backend config.py consistency (source-level)
  B01  ESCALATE_ONLY_REASONS contains body-sqli
  B02  ESCALATE_ONLY_REASONS contains body-xss
  B03  ESCALATE_ONLY_REASONS contains body-lfi
  B04  ESCALATE_ONLY_REASONS contains body-rce
  B05  ESCALATE_ONLY_REASONS contains body-ssrf
  B06  ESCALATE_ONLY_REASONS contains body-cmd
  B07  ESCALATE_ONLY_REASONS contains asn-hosting
  B08  ESCALATE_ONLY_REASONS contains coordinated-probe
  B09  SECOND_ORDER_REASONS contains direct-api-probe
  B10  SECOND_ORDER_REASONS contains ai-enumeration
  B11  SECOND_ORDER_REASONS contains locale-geo-mismatch
  B12  ua-ai signals NOT in ESCALATE_ONLY_REASONS or SECOND_ORDER_REASONS

U-tests: UI copy (controls.html) — order panel and tooltips
  U01  Panel header says "risk-score gate"
  U02  Order-2 od-body mentions SECOND_ORDER_THRESHOLD
  U03  Order-3 od-body mentions ESCALATION_THRESHOLD
  U04  Order-1 od-trigger says "Gate: none"
  U05  Order-2 od-trigger says "Set to 0 to always run"
  U06  Order-3 od-trigger mentions quota
  U07  renderRow badge tooltip says "runs on every request" for order 1
  U08  renderRow badge tooltip mentions SECOND_ORDER_THRESHOLD for order 2
  U09  renderRow badge tooltip mentions ESCALATION_THRESHOLD for order 3
"""
import ast
import os
import re
import sys
import tempfile
from pathlib import Path

import pytest

# ── env / path setup ──────────────────────────────────────────────────────────

_TMP = tempfile.mkdtemp(prefix="appsecgw-v187-order-")
os.environ.setdefault("UPSTREAM",  "https://backend.example.com")
os.environ.setdefault("ADMIN_KEY", "TEST-KEY-DO-NOT-USE")
os.environ.setdefault("DB_PATH",   os.path.join(_TMP, "antibot-v187-order.db"))

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent

sys.path.insert(0, str(_ROOT))

_CONTROLS_HTML = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")


# ── helpers ───────────────────────────────────────────────────────────────────

def _signal_defaults(src: str) -> dict[str, int]:
    """Parse SIGNAL_ORDER_DEFAULTS from controls.html JS into {signal: order}."""
    m = re.search(r'const SIGNAL_ORDER_DEFAULTS\s*=\s*\{([^}]+)\}', src, re.DOTALL)
    if not m:
        return {}
    body = m.group(1)
    result = {}
    for match in re.finditer(r"'([^']+)'\s*:\s*([123])", body):
        result[match.group(1)] = int(match.group(2))
    return result


def _render_row_block(src: str) -> str:
    """Return the renderRow function text from controls.html."""
    idx = src.find("const renderRow = (w) =>")
    if idx == -1:
        return ""
    return src[idx: idx + 1500]


def _order_panel(src: str) -> str:
    """Return the order-defs panel HTML."""
    idx = src.find('class="order-defs"')
    if idx == -1:
        return ""
    return src[idx: idx + 2000]


# ── P: proxy_handler.py dead-code removal ─────────────────────────────────────

class TestProxyHandlerDeadCode:
    def setup_method(self):
        self.src = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")

    def test_p01_escalate_not_assigned(self):
        assert "_escalate " not in self.src and "_escalate=" not in self.src, (
            "_escalate variable must be removed — it was computed but never used"
        )

    def test_p02_second_order_not_assigned(self):
        assert "_second_order " not in self.src and "_second_order=" not in self.src, (
            "_second_order variable must be removed — it was computed but never used"
        )

    def test_p03_esc_score_still_present(self):
        assert "_esc_score" in self.src, (
            "_esc_score must remain — it is passed to _should_run_signal() calls"
        )

    def test_p04_should_run_signal_imported(self):
        assert "_should_run_signal" in self.src, (
            "_should_run_signal must remain imported from scoring — it is the actual gate"
        )


# ── O: SIGNAL_ORDER_DEFAULTS sync ─────────────────────────────────────────────

class TestSignalOrderDefaults:
    def setup_method(self):
        self.defs = _signal_defaults(_CONTROLS_HTML)
        assert self.defs, "SIGNAL_ORDER_DEFAULTS not found in controls.html"

    # AI UA checks — order 1 (cheap string match, gated by own ENABLED toggle)
    def test_o01_ua_ai_openai_order1(self):
        assert self.defs.get("ua-ai-openai") == 1, "ua-ai-openai must be order 1 — µs UA string check"

    def test_o02_ua_ai_anthropic_order1(self):
        assert self.defs.get("ua-ai-anthropic") == 1

    def test_o03_ua_ai_google_order1(self):
        assert self.defs.get("ua-ai-google") == 1

    def test_o04_ua_ai_perplexity_order1(self):
        assert self.defs.get("ua-ai-perplexity") == 1

    def test_o05_ua_ai_meta_order1(self):
        assert self.defs.get("ua-ai-meta") == 1

    def test_o06_ua_ai_other_order1(self):
        assert self.defs.get("ua-ai-other") == 1

    # Cheap header / path checks — order 1 (backend never gated these)
    def test_o07_ai_probe_order1(self):
        assert self.defs.get("ai-probe") == 1, (
            "ai-probe must be order 1 — backend has no gate for it"
        )

    def test_o08_ai_headers_empty_order1(self):
        assert self.defs.get("ai-headers-empty") == 1

    def test_o09_ai_headers_incomplete_order1(self):
        assert self.defs.get("ai-headers-incomplete") == 1

    def test_o10_ai_ua_ip_mismatch_order1(self):
        assert self.defs.get("ai-ua-ip-mismatch") == 1

    def test_o11_robots_violation_order1(self):
        assert self.defs.get("robots-violation") == 1

    def test_o12_tor_exit_order1(self):
        assert self.defs.get("tor-exit") == 1, (
            "tor-exit must be order 1 — O(1) set membership, not in SECOND_ORDER_REASONS"
        )

    def test_o13_suspicious_path_order1(self):
        assert self.defs.get("suspicious-path") == 1, (
            "suspicious-path must be order 1 — regex path check, not in any gate set"
        )

    # Body attack signals — order 3 (in ESCALATE_ONLY_REASONS)
    def test_o14_body_sqli_order3(self):
        assert self.defs.get("body-sqli") == 3, (
            "body-sqli must be order 3 — in ESCALATE_ONLY_REASONS, regex scan cost"
        )

    def test_o15_body_xss_order3(self):
        assert self.defs.get("body-xss") == 3

    def test_o16_body_lfi_order3(self):
        assert self.defs.get("body-lfi") == 3

    def test_o17_body_rce_order3(self):
        assert self.defs.get("body-rce") == 3

    def test_o18_body_ssrf_order3(self):
        assert self.defs.get("body-ssrf") == 3

    def test_o19_body_cmd_order3(self):
        assert self.defs.get("body-cmd") == 3

    def test_o20_suspicious_body_order3(self):
        assert self.defs.get("suspicious-body") == 3, (
            "suspicious-body must be order 3 — in ESCALATE_ONLY_REASONS"
        )

    def test_o21_asn_hosting_order3(self):
        assert self.defs.get("asn-hosting") == 3, (
            "asn-hosting must be order 3 — in ESCALATE_ONLY_REASONS (was wrongly 2)"
        )

    def test_o22_coordinated_probe_order3(self):
        assert self.defs.get("coordinated-probe") == 3, (
            "coordinated-probe must be order 3 — in ESCALATE_ONLY_REASONS"
        )

    # Newly added to defaults
    def test_o23_direct_api_probe_order2(self):
        assert self.defs.get("direct-api-probe") == 2, (
            "direct-api-probe must be order 2 — in SECOND_ORDER_REASONS (was absent)"
        )

    # Regression guard — order 2 signals unchanged
    def test_o24_ai_enumeration_order2(self):
        assert self.defs.get("ai-enumeration") == 2

    def test_o25_ai_no_assets_order2(self):
        assert self.defs.get("ai-no-assets") == 2

    def test_o26_locale_geo_mismatch_order2(self):
        assert self.defs.get("locale-geo-mismatch") == 2

    def test_o27_tls_fingerprint_order2(self):
        assert self.defs.get("tls-fingerprint") == 2

    def test_o28_ja4_required_missing_order2(self):
        assert self.defs.get("ja4-required-missing") == 2

    # Regression guard — order 3 signals unchanged
    def test_o29_abuseipdb_high_order3(self):
        assert self.defs.get("abuseipdb-high") == 3

    def test_o30_crowdsec_banned_order3(self):
        assert self.defs.get("crowdsec-banned") == 3

    def test_o31_datacenter_vpn_order3(self):
        assert self.defs.get("datacenter-vpn") == 3


# ── B: backend config.py consistency ──────────────────────────────────────────

class TestBackendConfigConsistency:
    def setup_method(self):
        import importlib
        import config as cfg
        self.esc  = cfg.ESCALATE_ONLY_REASONS
        self.sec  = cfg.SECOND_ORDER_REASONS

    def test_b01_escalate_contains_body_sqli(self):
        assert "body-sqli" in self.esc

    def test_b02_escalate_contains_body_xss(self):
        assert "body-xss" in self.esc

    def test_b03_escalate_contains_body_lfi(self):
        assert "body-lfi" in self.esc

    def test_b04_escalate_contains_body_rce(self):
        assert "body-rce" in self.esc

    def test_b05_escalate_contains_body_ssrf(self):
        assert "body-ssrf" in self.esc

    def test_b06_escalate_contains_body_cmd(self):
        assert "body-cmd" in self.esc

    def test_b07_escalate_contains_asn_hosting(self):
        assert "asn-hosting" in self.esc, (
            "asn-hosting must remain in ESCALATE_ONLY_REASONS — MaxMind call is 3rd order"
        )

    def test_b08_escalate_contains_coordinated_probe(self):
        assert "coordinated-probe" in self.esc

    def test_b09_second_order_contains_direct_api_probe(self):
        assert "direct-api-probe" in self.sec, (
            "direct-api-probe must be in SECOND_ORDER_REASONS"
        )

    def test_b10_second_order_contains_ai_enumeration(self):
        assert "ai-enumeration" in self.sec

    def test_b11_second_order_contains_locale_geo(self):
        assert "locale-geo-mismatch" in self.sec

    def test_b12_ua_ai_signals_not_gated(self):
        """AI UA signals must NOT be in SECOND_ORDER or ESCALATE sets — they run always."""
        gated = self.esc | self.sec
        for sig in ("ua-ai-openai", "ua-ai-anthropic", "ua-ai-google",
                    "ua-ai-perplexity", "ua-ai-meta", "ua-ai-other"):
            assert sig not in gated, (
                f"{sig} must not be in a gate set — it is gated by its own ENABLED toggle"
            )


# ── U: UI copy — order panel and tooltips ─────────────────────────────────────

class TestControlsOrderUICopy:
    def setup_method(self):
        self.src   = _CONTROLS_HTML
        self.panel = _order_panel(self.src)
        self.row   = _render_row_block(self.src)

    def test_u01_panel_header_says_risk_score_gate(self):
        assert "risk-score gate" in self.src, (
            "Order panel header must say 'risk-score gate' — not 'pipeline step'"
        )

    def test_u02_order2_body_mentions_second_order_threshold(self):
        assert "SECOND_ORDER_THRESHOLD" in self.panel, (
            "Order-2 description must name SECOND_ORDER_THRESHOLD so operators know the knob"
        )

    def test_u03_order3_body_mentions_escalation_threshold(self):
        assert "ESCALATION_THRESHOLD" in self.panel, (
            "Order-3 description must name ESCALATION_THRESHOLD"
        )

    def test_u04_order1_trigger_says_gate_none(self):
        assert "Gate: none" in self.panel, (
            "Order-1 od-trigger must say 'Gate: none' — always active"
        )

    def test_u05_order2_trigger_says_set_to_0(self):
        assert "Set to 0 to always run" in self.panel, (
            "Order-2 od-trigger must explain the threshold can be set to 0"
        )

    def test_u06_order3_trigger_mentions_quota(self):
        assert "quota" in self.panel, (
            "Order-3 description must mention quota cost so operators understand why it's gated"
        )

    def test_u07_row_badge_order1_tooltip_runs_every_request(self):
        assert "runs on every request" in self.row, (
            "renderRow badge tooltip must say 'runs on every request' for order 1"
        )

    def test_u08_row_badge_order2_tooltip_mentions_second_order(self):
        assert "SECOND_ORDER_THRESHOLD" in self.row, (
            "renderRow badge tooltip must name SECOND_ORDER_THRESHOLD for order 2"
        )

    def test_u09_row_badge_order3_tooltip_mentions_escalation(self):
        assert "ESCALATION_THRESHOLD" in self.row, (
            "renderRow badge tooltip must name ESCALATION_THRESHOLD for order 3"
        )
