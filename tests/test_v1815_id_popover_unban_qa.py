"""
QA tests — Identity-details popover Unban + accurate admin-bypass banner (1.8.15).

Two coordinated fixes shipped together this iteration:

1. **Unban button on Identity popover** (`buildIdHtml`): previously only the
   Risk-score breakdown popover (`buildRiskHtml`) had the Unban + View-requests
   buttons. Operators now see the action buttons on both popovers when an
   identity is banned or has past blocks.

   The handler `wireRiskActions(container, d)` now runs for `kind === 'id-main'`
   in main.html and `kind === 'id'` in agents.html — its name is a misnomer:
   it wires `.gw-unban`, `.gw-view-logs`, `.gw-reset-risk` selectors regardless
   of which popover hosts them.

2. **Accurate self-ban banner**: was a misleading "Looks like an operator
   session (admin IP) — probably a self-ban from testing". `is_admin_ip` is
   IP-only; `_admin_authed_bypass` actually requires BOTH (a) admin-IP AND
   (b) valid agw_session cookie on the request. Banner now distinguishes
   "session seen but other requests came in without one" from "no session
   observed at all (unauthenticated probe)".

Coverage:
  TestIdPopoverHasUnban     — buildIdHtml renders Unban when banned
  TestIdPopoverActionWiring — openClientPopover wires actions for 'id-main' / 'id'
  TestAdminBanBannerAccurate — banner text reflects session presence
  TestIifeSync              — main.html ↔ agents.html share the same popover IIFE
"""
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MN_SRC = (_ROOT / "dashboards" / "main.html").read_text(encoding="utf-8")
_AG_SRC = (_ROOT / "dashboards" / "agents.html").read_text(encoding="utf-8")


# ── helpers ───────────────────────────────────────────────────────────────────

def _build_id_block(src: str) -> str:
    """Extract buildIdHtml function body (everything until next `function ` at
    same indent, or the next IIFE boundary). 600-line cap is generous."""
    start = src.find("function buildIdHtml(d){")
    assert start != -1, "buildIdHtml not found"
    # Walk forward to matching closing brace
    depth = 0
    i = src.find("{", start)
    in_str = None
    in_tpl = False
    while i < len(src):
        c = src[i]
        if in_str:
            if c == "\\":
                i += 2; continue
            if c == in_str:
                in_str = None
            i += 1; continue
        if in_tpl:
            if c == "\\":
                i += 2; continue
            if c == "`":
                in_tpl = False
            elif c == "$" and i + 1 < len(src) and src[i + 1] == "{":
                d = 1; i += 2
                while i < len(src) and d > 0:
                    if src[i] == "{": d += 1
                    elif src[i] == "}": d -= 1
                    i += 1
                continue
            i += 1; continue
        if c in "'\"":
            in_str = c
        elif c == "`":
            in_tpl = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[start: i + 1]
        i += 1
    return src[start: start + 5000]


# ── 1. TestIdPopoverHasUnban ─────────────────────────────────────────────────

class TestIdPopoverHasUnban:
    """buildIdHtml() must render `.gw-unban` (and `.gw-view-logs`) when the
    identity is banned OR has past blocks. Tested against the canonical
    main.html source — agents.html mirrors via IIFE sync."""

    def test_main_html_buildIdHtml_has_unban_button(self):
        body = _build_id_block(_MN_SRC)
        assert "gw-unban" in body, (
            "Identity-details popover (buildIdHtml) must render .gw-unban button"
        )

    def test_main_html_buildIdHtml_has_view_logs_button(self):
        body = _build_id_block(_MN_SRC)
        assert "gw-view-logs" in body, (
            "Identity-details popover must render .gw-view-logs button alongside Unban"
        )

    def test_unban_button_carries_id_and_ip(self):
        body = _build_id_block(_MN_SRC)
        # Must carry both attributes so unban endpoint can pick either as the
        # match key (id is preferred for per-identity, ip is fallback).
        assert "data-unban-id=" in body and "data-unban-ip=" in body, (
            "Unban button must pass both data-unban-id and data-unban-ip"
        )

    def test_button_label_changes_with_state(self):
        """When banned: label says 'Unban'. When not banned but has past blocks:
        label says 'Reset risk' (different action semantics)."""
        body = _build_id_block(_MN_SRC)
        assert "Unban this identity" in body, (
            "Banned label must read 'Unban this identity'"
        )
        # Either 'Reset risk' or 'Reset risk + grace' for past-blocks case
        assert "Reset risk" in body, (
            "Past-blocks label must mention 'Reset risk' to distinguish from active unban"
        )

    def test_button_gated_on_active_ban_or_past_blocks(self):
        """Buttons must NOT render for never-blocked identities (no useful
        action). The ternary guard should check bsec > 0 OR blocked > 0."""
        body = _build_id_block(_MN_SRC)
        # Look for a guard condition referencing bsec / banned and blocked
        assert ("bsec > 0" in body or "d.banned_secs" in body), (
            "Action buttons must be gated on ban state"
        )
        assert "blocked" in body, (
            "Guard must also include past-blocks fallback so the 'Reset risk' "
            "button is reachable for identities with past blocks"
        )

    def test_grace_window_hint_present(self):
        """Operator must see that the unban grants a grace window
        (ALLOW_BYPASS_SECS) so they understand the immediate-rebanning fix."""
        body = _build_id_block(_MN_SRC)
        assert "grace" in body.lower(), (
            "Identity popover must mention the grace window in the Unban hint "
            "so operators understand why immediate-rebanning is prevented"
        )


# ── 2. TestIdPopoverActionWiring ─────────────────────────────────────────────

class TestIdPopoverActionWiring:
    """openClientPopover must call wireRiskActions for the Identity popover too
    (was previously only Risk). Otherwise the new buttons render but do nothing."""

    def test_main_html_wires_id_main(self):
        # In main.html the kind string is 'id-main'.
        # Look for: if (kind === 'id-main') { ... wireRiskActions(...) }
        idx = _MN_SRC.find("if (kind === 'id-main')")
        assert idx != -1, "main.html must have a 'kind === id-main' branch"
        # Within a 300-char window after, wireRiskActions must be called.
        block = _MN_SRC[idx: idx + 600]
        assert "wireRiskActions(" in block, (
            "main.html openClientPopover must call wireRiskActions for "
            "kind === 'id-main' — otherwise the Unban button does nothing"
        )

    def test_agents_html_wires_id(self):
        # In agents.html the kind string is just 'id'.
        idx = _AG_SRC.find("if (kind === 'id')")
        assert idx != -1, "agents.html must have a 'kind === id' branch"
        block = _AG_SRC[idx: idx + 600]
        assert "wireRiskActions(" in block, (
            "agents.html openClientPopover must call wireRiskActions for "
            "kind === 'id' — otherwise the Unban button does nothing"
        )

    def test_wireRiskActions_handles_unban(self):
        """The handler must POST to /secured/unban with the identity id."""
        idx = _MN_SRC.find("function wireRiskActions(")
        assert idx != -1
        # 2000-char window covers the .gw-unban handler body
        body = _MN_SRC[idx: idx + 2000]
        assert "secured/unban" in body, (
            "wireRiskActions must POST to /secured/unban"
        )
        assert "data-unban-id" in body, (
            "Handler must read data-unban-id attribute from the clicked button"
        )


# ── 3. TestAdminBanBannerAccurate ────────────────────────────────────────────

class TestAdminBanBannerAccurate:
    """Banner text in buildRiskHtml must distinguish:
       (a) admin IP with session seen → 'some requests came in unauthenticated'
       (b) admin IP with no session   → 'no session cookie observed'
    """

    def test_old_misleading_text_removed(self):
        for src, name in ((_MN_SRC, "main.html"), (_AG_SRC, "agents.html")):
            assert "Looks like an operator session" not in src, (
                f"{name} still contains the OLD misleading 'operator session' "
                "banner — should distinguish session-seen vs session-missing"
            )

    def test_session_seen_path_present(self):
        for src, name in ((_MN_SRC, "main.html"), (_AG_SRC, "agents.html")):
            assert "bypass requires session cookie" in src, (
                f"{name} banner must explain that bypass requires session cookie "
                "(not just admin IP)"
            )

    def test_no_session_path_present(self):
        for src, name in ((_MN_SRC, "main.html"), (_AG_SRC, "agents.html")):
            assert "no session cookie observed" in src, (
                f"{name} banner must have a distinct message when no session "
                "cookie was observed at all"
            )

    def test_banner_gated_on_is_admin_ip(self):
        """The banner must still only render for admin IPs — non-admin bans
        don't need the bypass explanation."""
        for src, name in ((_MN_SRC, "main.html"), (_AG_SRC, "agents.html")):
            # Find one banner occurrence; verify a guard on is_admin_ip exists
            # within the IIFE block surrounding it.
            idx = src.find("bypass requires session cookie")
            assert idx != -1
            # Look 200 chars before for the is_admin_ip guard
            guard = src[max(0, idx - 500): idx]
            assert "is_admin_ip" in guard, (
                f"{name} banner must be gated on d.is_admin_ip"
            )


# ── 4. TestIifeSync ──────────────────────────────────────────────────────────

class TestIifeSync:
    """main.html and agents.html share the _gwIdentityPopover IIFE verbatim.
    The new Unban button in buildIdHtml is shipped via this sync, so any drift
    means agents.html is missing the feature."""

    def test_iife_present_in_both(self):
        for src, name in ((_MN_SRC, "main.html"), (_AG_SRC, "agents.html")):
            assert "window._gwIdentityPopover = (function(){" in src, (
                f"{name} must define window._gwIdentityPopover IIFE"
            )

    def test_buildIdHtml_present_in_both(self):
        for src, name in ((_MN_SRC, "main.html"), (_AG_SRC, "agents.html")):
            assert "function buildIdHtml(d){" in src, (
                f"{name} must define buildIdHtml inside the popover IIFE"
            )

    def test_both_have_gw_unban_in_id_popover(self):
        """Both main and agents must have the Unban button in buildIdHtml."""
        for src, name in ((_MN_SRC, "main.html"), (_AG_SRC, "agents.html")):
            body = _build_id_block(src)
            assert "gw-unban" in body, (
                f"{name} buildIdHtml must include the .gw-unban button — "
                "IIFE may have drifted, run the sync script"
            )
