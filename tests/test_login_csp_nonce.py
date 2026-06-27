# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Pedro Tarrinho
"""
tests/test_login_csp_nonce.py — regression guard for the login Sign-in button.

History: the login page was hardened with a strict CSP (`script-src 'self'`,
F-11 "no inline scripts") while `login.html` still shipped an inline <script>.
Browsers silently blocked that script, so the Sign-in button's click handler
never attached — login was impossible from a real browser (curl, which ignores
CSP, still saw a fine page). Fixed with a per-request CSP nonce.

These tests assert the page's inline script(s) are runnable under the served CSP
AND that injected inline scripts would still be blocked.
"""
import re

import pytest
from aiohttp.test_utils import make_mocked_request

from admin.users import login_page_endpoint


@pytest.mark.asyncio
async def test_login_inline_script_has_matching_csp_nonce():
    req = make_mocked_request("GET", "/antibot-appsec-gateway/login")
    resp = await login_page_endpoint(req)
    body = resp.text
    csp = resp.headers.get("Content-Security-Policy", "")

    # placeholder must be substituted
    assert "__CSP_NONCE__" not in body, "login.html nonce placeholder not filled"

    # CSP must carry a script nonce
    m = re.search(r"script-src[^;]*'nonce-([A-Za-z0-9_+/=-]+)'", csp)
    assert m, f"CSP script-src has no nonce: {csp!r}"
    nonce = m.group(1)

    # every inline <script> (no src=) must carry exactly that nonce, or the
    # browser blocks it and the Sign-in handler never wires up
    for tag in re.findall(r"<script\b[^>]*>", body):
        if "src=" in tag:
            continue  # external 'self' script — allowed without a nonce
        assert f'nonce="{nonce}"' in tag, (
            f"inline <script> missing the CSP nonce → browser will block it: {tag!r}"
        )


@pytest.mark.asyncio
async def test_login_csp_still_blocks_injected_inline_scripts():
    # The nonce must be specific, not a blanket 'unsafe-inline' that would
    # re-open the F-11 hole.
    req = make_mocked_request("GET", "/antibot-appsec-gateway/login")
    resp = await login_page_endpoint(req)
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0], (
        "login script-src must NOT use 'unsafe-inline' (defeats F-11) — use the nonce"
    )


@pytest.mark.asyncio
async def test_login_nonce_is_per_request():
    req = make_mocked_request("GET", "/antibot-appsec-gateway/login")
    a = (await login_page_endpoint(req)).headers.get("Content-Security-Policy", "")
    b = (await login_page_endpoint(req)).headers.get("Content-Security-Policy", "")
    na = re.search(r"'nonce-([A-Za-z0-9_+/=-]+)'", a).group(1)
    nb = re.search(r"'nonce-([A-Za-z0-9_+/=-]+)'", b).group(1)
    assert na != nb, "CSP nonce must be regenerated per request, not static"
