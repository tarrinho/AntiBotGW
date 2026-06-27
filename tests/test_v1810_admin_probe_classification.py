"""
tests/test_v1810_admin_probe_classification.py — guards for the 1.8.10 split of
the legacy "internal-probe" admin-path reason into two honest, consistent ones.

Background:
  An unauthenticated hit on an admin path (when the source IP is allowed) used
  to be labelled "internal-probe" and was counted as a block in core/metrics.py
  but EXCLUDED from the SQL blocked_1h/24h stats — an inconsistency. Worse, the
  one label conflated two very different populations:
    • the operator's OWN browser with a lapsed session (benign self-noise)
    • anonymous external reconnaissance of /secured/*, /__config, etc.

Fix (1.8.10): proxy_handler classifies by whether a genuinely-issued
agw_session cookie is present (HMAC-validated via _session_parse):
    • operator-self — valid-but-lapsed session  → benign, excluded everywhere
    • admin-probe   — no/forged session cookie   → recon, counted everywhere

Invariant under test: every "blocked" accounting agrees —
    admin-probe   == blocked   (counted in all three places)
    operator-self == not block  (excluded in all three places)

Groups
  C — proxy_handler classification logic
  X — cross-file consistency of the blocked definition
"""
import os
import re

os.environ.setdefault("UPSTREAM", "https://example.com")

_REPO = os.path.join(os.path.dirname(__file__), "..")

def _read(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8") as f:
        return f.read()


# ── C: classification logic in proxy_handler ─────────────────────────────────

class TestClassification:
    _PH = _read("core/proxy_handler.py")

    def test_c01_legacy_internal_probe_not_emitted(self):
        # The catch-all 'internal-probe' assignment must be gone (kept only as a
        # legacy label for historical DB rows / tooltips).
        assert 'else "internal-probe")' not in self._PH, (
            "proxy_handler must no longer emit the legacy 'internal-probe' reason"
        )

    def test_c02_emits_operator_self_and_admin_probe(self):
        assert '"operator-self"' in self._PH, "must emit operator-self"
        assert '"admin-probe"' in self._PH, "must emit admin-probe"

    def test_c03_classifies_via_session_parse(self):
        # Distinguishing operator-self from admin-probe must validate the session
        # HMAC (via _session_parse) — mere cookie PRESENCE would let a scanner
        # forge a benign label and dodge the recon count.
        idx = self._PH.find('reason = "operator-self"')
        assert idx != -1
        block = self._PH[max(0, idx - 600):idx + 60]
        assert "_session_parse" in block, (
            "operator-self vs admin-probe must be decided by _session_parse "
            "(HMAC-validated), not by cookie presence alone"
        )

    def test_c04_admin_ip_blocked_still_distinct(self):
        # IP-allowlist failure must remain its own reason, decided before the
        # operator-self/admin-probe split.
        assert 'reason = "admin-ip-blocked"' in self._PH


# ── X: cross-file consistency of the 'blocked' definition ────────────────────

class TestBlockedConsistency:
    _METRICS  = _read("core/metrics.py")
    _SETTINGS = _read("admin/settings.py")
    _SERVICE  = _read("dashboards/service_metrics.py")

    # -- core/metrics.py: _PASSTHROUGH_REASONS decides blocked vs allowed --
    def test_x01_metrics_passthrough_has_operator_self(self):
        m = re.search(r"_PASSTHROUGH_REASONS[^}]*\}", self._METRICS, re.S)
        assert m, "_PASSTHROUGH_REASONS set not found"
        assert '"operator-self"' in m.group(), (
            "operator-self must be a passthrough reason (not counted as a block "
            "in core/metrics.py)"
        )

    def test_x02_metrics_passthrough_excludes_admin_probe(self):
        m = re.search(r"_PASSTHROUGH_REASONS[^}]*\}", self._METRICS, re.S)
        assert '"admin-probe"' not in m.group(), (
            "admin-probe must NOT be passthrough — it must count as a block"
        )

    # -- admin/settings.py: _SKIP_REASONS + blocked SQL --
    def test_x03_settings_skip_reasons_excludes_operator_self(self):
        m = re.search(r"_SKIP_REASONS\s*=\s*\([^)]*\)", self._SETTINGS)
        assert m, "_SKIP_REASONS not found"
        assert "'operator-self'" in m.group(), (
            "operator-self must be in _SKIP_REASONS (excluded from blocked stats)"
        )
        assert "'admin-probe'" not in m.group(), (
            "admin-probe must NOT be skipped — it must count as a block"
        )

    def test_x04_settings_blocked_sql_excludes_operator_self_counts_admin_probe(self):
        # Contract change (post-1.8.10): admin/settings.py's vhost-stats blocked
        # SUM no longer inlines reason literals into the SQL — it parameterises
        # them via the _PASSTHROUGH_REASONS tuple and `reason NOT IN ({_ph_passthru})`
        # placeholders. The shipped invariant (operator-self excluded from blocked,
        # admin-probe still counted) now lives in that tuple, so assert against it
        # rather than against an inline `reason NOT IN ('...')` literal list.
        m = re.search(r"_PASSTHROUGH_REASONS\s*=\s*\([^)]*\)", self._SETTINGS, re.S)
        assert m, "_PASSTHROUGH_REASONS tuple not found in settings.py"
        passthru = m.group()
        # The blocked SUM is `reason NOT IN (_PASSTHROUGH_REASONS)`, so membership
        # in this tuple == excluded from blocked.
        assert '"operator-self"' in passthru, (
            "operator-self must be a passthrough reason (excluded from blocked SUM)"
        )
        assert '"admin-probe"' not in passthru, (
            "admin-probe must NOT be passthrough — it must count as a block"
        )
        # And confirm the SUM actually filters on this parameterised tuple.
        assert "reason NOT IN ({_ph_passthru})" in self._SETTINGS, (
            "blocked SUM must filter via the parameterised _PASSTHROUGH_REASONS list"
        )

    # -- dashboards/service_metrics.py: per-vhost blocked SQL --
    def test_x05_service_blocked_sql_consistent(self):
        sums = re.findall(r"reason NOT IN \([^)]*\)", self._SERVICE)
        blocked_sums = [s for s in sums if "operator-passthrough" in s]
        assert blocked_sums, "no blocked SUM in service_metrics.py"
        for s in blocked_sums:
            assert "'operator-self'" in s, "service blocked SUM must exclude operator-self"
            assert "'admin-probe'" not in s, "service blocked SUM must COUNT admin-probe"

    def test_x06_all_three_accountings_agree(self):
        # Summary invariant: admin-probe counted everywhere, operator-self
        # excluded everywhere.
        pass_set = re.search(r"_PASSTHROUGH_REASONS[^}]*\}", self._METRICS, re.S).group()
        skip_set = re.search(r"_SKIP_REASONS\s*=\s*\([^)]*\)", self._SETTINGS).group()
        svc_sum  = [s for s in re.findall(r"reason NOT IN \([^)]*\)", self._SERVICE)
                    if "operator-passthrough" in s][0]
        # operator-self: benign in all three
        assert '"operator-self"' in pass_set
        assert "'operator-self'" in skip_set
        assert "'operator-self'" in svc_sum
        # admin-probe: counted in all three
        assert '"admin-probe"' not in pass_set
        assert "'admin-probe'" not in skip_set
        assert "'admin-probe'" not in svc_sum
