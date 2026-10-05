"""The portal's "Connect with OAuth" panel on MCP Gateway servers
(docs/specs/mcp-oauth-standard-providers.md, task 3).

The panel's logic is pure functions in static/tenant.html, run here under node
as tests/test_tool_policy_editor_portal.py does: what is offered, what is sent,
what the operator is told, and that server-supplied text is escaped.
"""
import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html"), encoding="utf-8").read()
PURE = HTML[HTML.index("// ── MCP OAuth connect (pure)"):HTML.index("// ── MCP OAuth connect (wiring)")]
ESC = HTML[HTML.index("function _esc(s) {"):]
ESC = ESC[:ESC.index("\n}\n") + 3]

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="needs node")

DRIVE_RO = "https://www.googleapis.com/auth/drive.readonly"
DRIVE_ALL = "https://www.googleapis.com/auth/drive"
GOOGLE = {"issuer": "https://accounts.google.com", "profile": "google",
          "access_scopes": [DRIVE_ALL, DRIVE_RO], "dynamic_registration": False}


def _js(expr: str):
    src = ESC + PURE + f"\nconsole.log(JSON.stringify({expr}));"
    out = subprocess.run(["node", "-e", src], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _form(disc=GOOGLE, status=None):
    return _js(f"mcpOAuthFormHtml('gdrive', {json.dumps(disc)}, {json.dumps(status or {})})")


# ── what is offered ────────────────────────────────────────────────────────


def test_google_scopes_are_offered_by_their_short_names_and_none_is_ticked():
    html = _form()
    assert html.count('class="mcp-oauth-scope"') == 2
    assert "checked" not in html
    assert ">drive.readonly<" in html and ">drive<" in html
    assert "read-only" in html                      # the read-only one is marked
    assert f'value="{DRIVE_RO}"' in html            # the full scope is what is sent


def test_a_provider_without_self_registration_says_the_client_is_required():
    assert "Required: this provider does not let Shield register itself" in _form()
    assert "Optional: leave blank" in _form({**GOOGLE, "dynamic_registration": True})


def test_the_secret_field_is_a_password_field():
    assert 'id="mcp-oauth-client-secret" placeholder="client secret" autocomplete="new-password"' in _form()
    assert 'type="password" id="mcp-oauth-client-secret"' in _form()


def test_the_shared_account_warning_is_always_shown():
    assert "Every agent and user of this route will act as the account that signs in" in _form()


def test_a_server_with_no_access_scopes_needs_no_choice():
    assert "This server needs no scope choice." in _form({**GOOGLE, "access_scopes": []})


def test_server_supplied_text_is_escaped():
    evil = {**GOOGLE, "issuer": '"><img src=x onerror=alert(1)>',
            "access_scopes": ['x" onclick="alert(1)']}
    html = _form(evil)
    assert "<img" not in html and 'onclick="alert(1)"' not in html


# ── what is sent ───────────────────────────────────────────────────────────


def test_the_connect_body_leaves_out_what_was_not_given():
    assert _js("mcpOAuthConnectBody('', '', [])") == {}
    assert _js(f"mcpOAuthConnectBody(' cid ', ' sec ', [{json.dumps(DRIVE_RO)}])") == {
        "client_id": "cid", "client_secret": "sec", "scopes": [DRIVE_RO]}


# ── what the operator is told ──────────────────────────────────────────────


@pytest.mark.parametrize("status, tone, words", [
    ({}, "dim", "Not connected."),
    ({"status": "pending"}, "warn", "Waiting for sign-in"),
    ({"status": "connected", "issuer": "https://accounts.google.com", "expires_at": 1791200000,
      "authorization_header": "brokered", "warning": ""}, "good", "valid until 2026-10-05"),
    ({"status": "connected", "warning": "stops working when its access token expires"},
     "warn", "stops working"),
    ({"status": "connected", "authorization_header": "other"}, "warn", "not in use"),
    ({"status": "needs_consent"}, "bad", "withdrew the grant"),
    ({"status": "error", "last_error": "invalid_grant"}, "bad", "invalid_grant"),
])
def test_status_lines(status, tone, words):
    got = _js(f"mcpOAuthStatus({json.dumps(status)})")
    assert got["tone"] == tone and words in got["text"]


def test_the_sign_in_link_opens_safely_and_only_for_https():
    html = _js("mcpOAuthResultHtml({authorize_url: 'https://accounts.google.com/o/oauth2/v2/auth?a=1&b=2', "
               "consent_note: 'Grants ongoing access'})")
    assert 'target="_blank" rel="noopener noreferrer"' in html
    assert "a=1&amp;b=2" in html and "Grants ongoing access" in html
    bad = _js("mcpOAuthResultHtml({authorize_url: 'javascript:alert(1)'})")
    assert "javascript:" not in bad and "no usable sign-in address" in bad


# ── wiring ─────────────────────────────────────────────────────────────────


def test_only_network_servers_get_the_oauth_button_and_the_panel_exists():
    render = HTML.split("function renderMcpGateway(inv) {")[1].split("\n}\n")[0]
    assert "(s.transport || '') !== 'stdio'" in render and "mcpShowOAuth(" in render
    assert 'id="mcp-oauth"' in HTML and 'id="mcp-oauth-body"' in HTML
    wiring = HTML.split("// ── MCP OAuth connect (wiring)")[1].split("function _aibomRow")[0]
    assert "/servers/${encodeURIComponent(route)}/oauth`" in wiring
    assert "base + '/discover'" in wiring and "/oauth/connect`" in wiring
    assert "client-secret').value = ''" in wiring     # the secret is cleared after use
