"""
1.9.2 — QA for the two-level "disable gateway protections" controls.

There are two distinct off-switches for the whole protection pipeline:

  GLOBAL  — the emergency `BYPASS_MODE` (Controls bypass bar). Disables ALL
            protections (detection + bans + rate limits) on EVERY vhost; it is
            session-only (`_NOT_PERSIST_KNOBS`) and must be UN-SHADOWABLE by any
            per-vhost override.
  PER-VHOST — a per-vhost `BYPASS_MODE` override (Vhost Policy "Disable ALL
            protections" switch). Disables protections for one vhost only and
            PERSISTS across restarts (written via vhost_set, not the session
            global path). Other vhosts are unaffected.

The protect() gate is:
    if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path(request.path):
so the GLOBAL flag wins unconditionally and a PER-VHOST flag adds bypass for a
single host. These tests lock that contract + the dashboard wiring.
"""
import os
import pathlib

os.environ.setdefault("UPSTREAM", "https://example.com")

_ROOT      = pathlib.Path(__file__).resolve().parent.parent
_PH_SRC    = (_ROOT / "core" / "proxy_handler.py").read_text(encoding="utf-8")
_VHP_SRC   = (_ROOT / "dashboards" / "vhost_policy.html").read_text(encoding="utf-8")
_CTL_SRC   = (_ROOT / "dashboards" / "controls.html").read_text(encoding="utf-8")


# ── Engine: gate condition + knob registration ──────────────────────────────

class TestBypassGateContract:

    def test_gate_uses_global_or_vhost(self):
        """Global BYPASS_MODE must be OR-ed with the per-vhost value so it is
        un-shadowable (the "can't disable the GW" fix)."""
        assert "if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path" in _PH_SRC, (
            "bypass gate must be `(BYPASS_MODE or vc('BYPASS_MODE'))` so the "
            "global emergency switch cannot be shadowed by a per-vhost override"
        )

    def test_exactly_one_active_gate(self):
        count = sum(1 for line in _PH_SRC.splitlines()
                    if line.strip().startswith(
                        "if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path"))
        assert count == 1, f"expected exactly 1 active bypass gate, found {count}"

    def test_gate_precedes_ban_persistence_check(self):
        """Bypass must run BEFORE the IP-ban persistence lookup so a bypassed
        request skips ban enforcement too."""
        gate = _PH_SRC.find("if (BYPASS_MODE or vc('BYPASS_MODE')) and not _is_admin_path")
        ban  = _PH_SRC.find("M-4 — IP ban persistence")
        assert gate != -1 and ban != -1
        assert gate < ban, "bypass gate must precede IP-ban persistence enforcement"

    def test_bypass_mode_per_vhost_overridable(self):
        from vhost import _VHOST_COERCE
        assert "BYPASS_MODE" in _VHOST_COERCE, (
            "BYPASS_MODE must be in _VHOST_COERCE so it can be set per-vhost"
        )

    def test_bypass_mode_hot_reloadable(self):
        import core.proxy_handler as ph
        assert "BYPASS_MODE" in ph._HOT_RELOAD_KNOBS, (
            "BYPASS_MODE must be hot-reloadable (toggle takes effect live)"
        )

    def test_global_bypass_is_session_only(self):
        """The GLOBAL emergency bypass must be session-only so a forgotten panic
        toggle resets on restart."""
        import core.proxy_handler as ph
        assert "BYPASS_MODE" in ph._NOT_PERSIST_KNOBS, (
            "global BYPASS_MODE must be in _NOT_PERSIST_KNOBS (emergency, "
            "session-only — resets on restart)"
        )


# ── Engine: resolution logic (the actual gate condition) ────────────────────

def _gate(global_on, vhost_val):
    """Evaluate the protect() bypass condition for a (global, per-vhost) pair.
    vhost_val=None means the vhost overlay does not set BYPASS_MODE."""
    import core.proxy_handler as ph
    from vhost import vc, _vhost_ctx
    _saved = ph.BYPASS_MODE
    try:
        ph.BYPASS_MODE = global_on
        _vhost_ctx.set({"BYPASS_MODE": vhost_val} if vhost_val is not None else None)
        return bool(ph.BYPASS_MODE or vc("BYPASS_MODE"))
    finally:
        ph.BYPASS_MODE = _saved
        _vhost_ctx.set(None)


class TestBypassResolution:

    def test_global_on_unshadowable_by_vhost_false(self):
        """The reported bug: global ON must win even when a vhost overlay says
        BYPASS_MODE=False."""
        assert _gate(True, False) is True, (
            "global BYPASS_MODE=True must disable the GW even when a vhost "
            "overlay carries BYPASS_MODE=False (un-shadowable)"
        )

    def test_global_on_no_vhost_override(self):
        assert _gate(True, None) is True

    def test_per_vhost_on_global_off(self):
        """Per-vhost ON disables that vhost while global stays off."""
        assert _gate(False, True) is True

    def test_per_vhost_isolated_from_others(self):
        """A vhost WITHOUT a bypass override (global off) keeps protections on —
        another vhost's bypass doesn't leak."""
        assert _gate(False, None) is False

    def test_both_off_no_bypass(self):
        assert _gate(False, False) is False


# ── Per-vhost write path: coercion + (non-)persistence split ─────────────────

class TestPerVhostWrite:

    def test_bool_coercion(self):
        from vhost import _VHOST_COERCE
        c = _VHOST_COERCE["BYPASS_MODE"]
        assert c(True) is True and c("true") is True and c(1) is True
        assert c(False) is False and c("false") is False and c(0) is False

    def test_vhost_branch_does_not_filter_not_persist(self):
        """The ?vhost= config write persists per-vhost overrides via vhost_set
        WITHOUT the _NOT_PERSIST_KNOBS filter — so a per-vhost BYPASS_MODE is a
        durable policy even though the GLOBAL one is session-only. Guard: the
        _NOT_PERSIST_KNOBS gate only appears in the GLOBAL apply path."""
        vhost_branch = _PH_SRC[_PH_SRC.find("# Per-vhost override writes"):
                               _PH_SRC.find("applied, rejected, warnings")]
        assert "_vhost_set_fn(" in vhost_branch, "vhost write must go through vhost_set"
        assert "_NOT_PERSIST_KNOBS" not in vhost_branch, (
            "per-vhost write path must NOT filter _NOT_PERSIST_KNOBS — a per-vhost "
            "BYPASS_MODE persists as a deliberate policy"
        )


# ── Dashboard: per-vhost "Disable ALL protections" switch ───────────────────

class TestVhostPolicyDashboard:

    def test_switch_element_present(self):
        assert 'id="vhost-bypass-switch"' in _VHP_SRC
        assert 'data-knob="BYPASS_MODE"' in _VHP_SRC
        assert 'class="switch danger"' in _VHP_SRC, (
            "per-vhost disable switch must use the danger (red) style"
        )

    def test_danger_switch_css_present(self):
        assert ".switch.danger.on{background:var(--red)}" in _VHP_SRC, (
            "danger switch must turn red when ON (protections disabled)"
        )

    def test_switch_load_reads_effective_value(self):
        assert "_pending.hasOwnProperty('BYPASS_MODE')" in _VHP_SRC, (
            "switch must reflect pending > vhost-override > global for BYPASS_MODE"
        )
        assert "document.getElementById('vhost-bypass-switch')" in _VHP_SRC

    def test_switch_click_sets_pending(self):
        assert "_pending['BYPASS_MODE']=off" in _VHP_SRC, (
            "clicking the switch must stage BYPASS_MODE into _pending for Apply"
        )

    def test_bypass_mode_in_knob_meta(self):
        assert "BYPASS_MODE:" in _VHP_SRC and "{g:'Bypass'" in _VHP_SRC, (
            "BYPASS_MODE must be in vhost_policy KNOB_META so it's overridable"
        )

    def test_label_communicates_full_disable(self):
        assert "Disable ALL gateway protections for this vhost" in _VHP_SRC, (
            "label must make clear this disables EVERYTHING (not just detection)"
        )


# ── Dashboard: global emergency switch labelled as site-wide ────────────────

class TestControlsGlobalSwitch:

    def test_global_switch_present(self):
        assert 'id="bypass-sw"' in _CTL_SRC

    def test_global_label_says_site_wide(self):
        assert "every vhost" in _CTL_SRC and "site-wide" in _CTL_SRC, (
            "global bypass labels must call out the site-wide / every-vhost scope "
            "so it's distinct from the per-vhost control"
        )

    def test_global_warn_banner_scope(self):
        assert "GLOBAL BYPASS ACTIVE" in _CTL_SRC and "ANY vhost" in _CTL_SRC
