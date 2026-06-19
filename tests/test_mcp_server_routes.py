"""Route tests for the Guardrail MCP server endpoints (api/routes_mcp_server).

Covers tool discovery and the public-base-URL resolution used in the MCP
`initialize` response (so it never advertises an internal proxy host/IP).
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes_mcp_server import router as mcp_server_router


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(mcp_server_router)
    return TestClient(app)


def _rpc(client, method, **headers):
    return client.post(
        "/mcp/message",
        json={"jsonrpc": "2.0", "id": 1, "method": method},
        headers=headers or None,
    )


def test_tools_list_exposes_all_shield_tools(client):
    r = _rpc(client, "tools/list")
    assert r.status_code == 200
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert names == {
        "shield_check_input", "shield_check_output", "shield_check_tool",
        "shield_sanitize_output", "shield_disable_tool", "shield_enable_tool",
    }


def test_initialize_uses_forwarded_host_not_internal(client):
    r = _rpc(
        client, "initialize",
        **{"x-forwarded-host": "shield.votal.ai", "x-forwarded-proto": "https"},
    )
    assert r.status_code == 200
    meta = r.json()["result"]["serverInfo"]["authorization"]["metadata_url"]
    assert meta.startswith("https://shield.votal.ai/.well-known/")
    # must not leak the testserver/internal bind host
    assert "testserver" not in meta


def test_initialize_prefers_configured_public_base_url(client, monkeypatch):
    monkeypatch.setenv("SHIELD_PUBLIC_BASE_URL", "https://mcp.example.com/")
    r = _rpc(client, "initialize", **{"x-forwarded-host": "ignored.example"})
    meta = r.json()["result"]["serverInfo"]["authorization"]["metadata_url"]
    assert meta == "https://mcp.example.com/.well-known/oauth-authorization-server"
