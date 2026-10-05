"""Headers on MCP server registration: the console's Add Server form can now
send them, and re-saving a server no longer wipes them.

Before: re-registering a route replaced its whole document, so saving a server
again from the form (which could not send headers) silently dropped its secret
header, and an OAuth route lost the Authorization header and credential_mode
its connect had wired. Headers are now kept when a re-registration sends none
and the upstream is unchanged; they never follow a route to a different host.
"""
import json
import shutil
import subprocess
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
from storage import mcp_gateway_store as gstore

H = {"X-Test-Tenant": "acme"}
URL = "https://mcp-payments.example.com/mcp"
SECRET = "s3cr3t-upstream-key-value"


@pytest.fixture(autouse=True)
def _store():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith("mcp_gateway:")]:
            del _fallback_store[k]
    _clear()

    async def no_scan(tenant_id, route, cfg):
        return {"verdict": "unavailable"}
    with patch("storage.tenant_store._get_redis", return_value=None), \
         patch.object(admin, "_rescan", no_scan):
        yield
    _clear()


@pytest.fixture
def client():
    app = FastAPI()

    @app.middleware("http")
    async def _tenant(request: Request, call_next):
        tid = request.headers.get("X-Test-Tenant")
        if tid:
            request.state.tenant_id = tid
        return await call_next(request)
    app.include_router(admin.router)
    return TestClient(app)


def _register(client, **body):
    return client.post("/v1/tenant/me/mcp/servers", headers=H,
                       json={"route": "payments", "transport": "http", "url": URL, **body})


def _stored():
    return gstore.get_upstream("acme", "payments")


def test_headers_are_stored_and_never_returned(client):
    r = _register(client, headers={"X-Upstream-Key": SECRET})
    assert r.status_code == 200, r.text
    assert _stored()["headers"] == {"X-Upstream-Key": SECRET}
    assert SECRET not in r.text
    inv = client.get("/v1/tenant/me/mcp/inventory", headers=H)
    assert SECRET not in inv.text
    assert "X-Upstream-Key" in inv.text           # the name is shown, masked


def test_re_saving_without_headers_keeps_them(client):
    _register(client, headers={"X-Upstream-Key": SECRET})
    _register(client, isolation_ack=True)          # e.g. the form, headers left empty
    assert _stored()["headers"] == {"X-Upstream-Key": SECRET}
    assert _stored()["isolation_ack"] is True


def test_an_oauth_route_keeps_its_wired_credential_when_re_saved(client):
    _register(client)
    cfg = _stored()
    cfg.update(headers={"Authorization": "Bearer shield://oauth-payments-access"},
               credential_mode="auth_code")
    gstore.set_upstream("acme", "payments", cfg)
    _register(client)
    assert _stored()["headers"] == {"Authorization": "Bearer shield://oauth-payments-access"}
    assert _stored()["credential_mode"] == "auth_code"


def test_headers_never_follow_a_route_to_a_different_host(client):
    _register(client, headers={"X-Upstream-Key": SECRET})
    _register(client, url="https://somewhere-else.example.net/mcp")
    assert "headers" not in _stored()


def test_new_headers_replace_the_old_ones(client):
    _register(client, headers={"X-Upstream-Key": SECRET})
    _register(client, headers={"X-Api-Key": "other"})
    assert _stored()["headers"] == {"X-Api-Key": "other"}


def test_an_empty_header_map_clears_them(client):
    _register(client, headers={"X-Upstream-Key": SECRET})
    _register(client, headers={})
    assert not _stored().get("headers")


# ── the form's pure functions, under node ──────────────────────────────────

import os  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "static", "tenant.html"), encoding="utf-8").read()
PURE = HTML[HTML.index("// ── MCP register headers (pure)"):HTML.index("// ── MCP OAuth connect (pure)")]
ESC = HTML[HTML.index("function _esc(s) {"):]
ESC = ESC[:ESC.index("\n}\n") + 3]
needs_node = pytest.mark.skipif(not shutil.which("node"), reason="needs node")


def _js(expr):
    out = subprocess.run(["node", "-e", ESC + PURE + f"\nconsole.log(JSON.stringify({expr}));"],
                         capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _rows(rows):
    return _js(f"mcpHeadersFromRows({json.dumps(rows)})")


@needs_node
def test_rows_become_headers_and_blank_rows_are_ignored():
    got = _rows([{"name": " X-Upstream-Key ", "value": " v1 "}, {"name": "", "value": ""}])
    assert got == {"headers": {"X-Upstream-Key": "v1"}, "errors": []}


@needs_node
@pytest.mark.parametrize("rows, words", [
    ([{"name": "Bad Name", "value": "v"}], "not a valid header name"),
    ([{"name": "X-Key", "value": "  "}], "has no value"),
    ([{"name": "X-Key", "value": "a\r\nX-Evil: 1"}], "line break"),
    ([{"name": "X-Key", "value": "a"}, {"name": "x-key", "value": "b"}], "appears twice"),
])
def test_bad_rows_are_refused(rows, words):
    got = _rows(rows)
    assert got["errors"] and words in got["errors"][0]


@needs_node
def test_values_are_password_fields_and_cards_name_headers_only():
    row = _js("mcpHeaderRowHtml()")
    assert 'class="mcp-reg-header-value" type="password"' in row and 'autocomplete="new-password"' in row
    badge = _js('mcpHeaderBadge({headers: {"X-Upstream-Key": "***", "X-Tenant": "***"}})')
    assert ">2 headers<" in badge and "X-Upstream-Key" in badge
    assert _js('mcpHeaderBadge({headers: {"Authorization": "***"}})').endswith(">authorization</span>")
    assert _js("mcpHeaderBadge({})") == ""


def test_the_form_is_wired():
    assert 'id="mcp-reg-headers-wrap"' in HTML and 'onclick="mcpAddHeaderRow()"' in HTML
    register = HTML.split("async function mcpRegisterServer() {")[1].split("\n}\n")[0]
    assert "mcpHeadersFromRows(mcpRegHeaderRows())" in register
    assert "if (Object.keys(h.headers).length) body.headers = h.headers;" in register
    assert "getElementById('mcp-reg-headers').innerHTML = ''" in register
