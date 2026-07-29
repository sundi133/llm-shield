"""SecOps can disable a whole MCP server without losing its config.

Deleting a route throws away its URL, credentials and enforcement backend. During
an incident SecOps needs to cut access now and restore it later, so a route
carries an ``active`` flag checked in ``MCPGatewayRouter._load_cfg`` — the one
choke point every MCP method funnels through, which is what makes a single flag
disconnect every client (Cursor, Claude, Codex, Hermes, anything speaking MCP).

The backward-compatibility case is the important one: routes registered before
this field existed have no ``active`` key and must keep serving traffic.
"""

import asyncio
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as admin
from core.mcp.gateway import GatewayError, MCPGatewayRouter
from storage import mcp_gateway_store as store


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _no_redis():
    from storage.tenant_store import _fallback_store

    def _clear():
        for k in [k for k in _fallback_store if k.startswith("mcp_gateway:")]:
            del _fallback_store[k]

    _clear()
    with patch("storage.tenant_store._get_redis", return_value=None):
        yield
    _clear()


class _FakeProxy:
    def __init__(self):
        self.calls = []

    async def list_tools(self, *, agent_key, user_role, tenant_id):
        self.calls.append("list_tools")
        return [{"name": "t1"}]

    async def call_tool(self, name, arguments, *, agent_key, user_role, tenant_id, **kw):
        self.calls.append(("call_tool", name))
        return {"content": [{"type": "text", "text": "ok"}], "isError": False}


def _router(made=None):
    async def factory(cfg, tenant_id):
        p = _FakeProxy()
        if made is not None:
            made.append(p)
        return p

    return MCPGatewayRouter(proxy_factory=factory)


def _register(route="billing", **extra):
    cfg = {"route": route, "transport": "stdio", "command": "x", "isolation_ack": True}
    cfg.update(extra)
    store.set_upstream("acme", route, cfg)
    return cfg


# ── gateway enforcement of the flag ──────────────────────────────────


def test_absent_active_still_serves():
    """Backward compatibility: every route registered before this field exists
    has no 'active' key. Treating that as disabled would black out the fleet."""
    _register()
    assert "active" not in store.get_upstream("acme", "billing")
    out = run(_router().call_tool("acme", "billing", "pay", {},
                                  agent_key="bot", user_role="reader"))
    assert out["isError"] is False


def test_active_true_serves():
    _register(active=True)
    out = run(_router().call_tool("acme", "billing", "pay", {},
                                  agent_key="bot", user_role="reader"))
    assert out["isError"] is False


def test_disabled_route_blocks_tool_call():
    _register(active=False)
    with pytest.raises(GatewayError) as ei:
        run(_router().call_tool("acme", "billing", "pay", {},
                                agent_key="bot", user_role="reader"))
    assert ei.value.status == 404
    assert "disabled" in ei.value.message


def test_disabled_route_blocks_tools_list_too():
    """A disable that only stopped tools/call would still let a client enumerate
    the server, so the check has to sit above every method."""
    _register(active=False)
    with pytest.raises(GatewayError):
        run(_router().list_tools("acme", "billing", agent_key="bot", user_role="reader"))


def test_disabled_route_never_reaches_upstream():
    """The point of the flag: no connection is opened to the vendor at all."""
    made = []
    _register(active=False)
    with pytest.raises(GatewayError):
        run(_router(made).call_tool("acme", "billing", "pay", {},
                                    agent_key="bot", user_role="reader"))
    assert made == []


def test_disable_then_enable_round_trip():
    _register(active=False)
    with pytest.raises(GatewayError):
        run(_router().call_tool("acme", "billing", "pay", {},
                                agent_key="bot", user_role="reader"))

    cfg = store.get_upstream("acme", "billing")
    cfg["active"] = True
    store.set_upstream("acme", "billing", cfg)

    out = run(_router().call_tool("acme", "billing", "pay", {},
                                  agent_key="bot", user_role="reader"))
    assert out["isError"] is False


def test_disable_is_per_route():
    _register("billing", active=False)
    _register("support")
    with pytest.raises(GatewayError):
        run(_router().call_tool("acme", "billing", "pay", {},
                                agent_key="bot", user_role="reader"))
    out = run(_router().call_tool("acme", "support", "ask", {},
                                  agent_key="bot", user_role="reader"))
    assert out["isError"] is False


def test_disable_is_per_tenant():
    store.set_upstream("acme", "r", {"route": "r", "transport": "stdio",
                                     "command": "x", "active": False})
    store.set_upstream("other", "r", {"route": "r", "transport": "stdio",
                                      "command": "x", "active": True})
    with pytest.raises(GatewayError):
        run(_router().call_tool("acme", "r", "t", {}, agent_key="b", user_role="r"))
    out = run(_router().call_tool("other", "r", "t", {}, agent_key="b", user_role="r"))
    assert out["isError"] is False


# ── admin-plane endpoints ────────────────────────────────────────────


@pytest.fixture
def client():
    app = FastAPI()

    @app.middleware("http")
    async def _set_tenant(request: Request, call_next):
        tid = request.headers.get("X-Test-Tenant")
        if tid:
            request.state.tenant_id = tid
        return await call_next(request)

    app.include_router(admin.router)
    return TestClient(app)


_H = {"X-Test-Tenant": "acme"}


def test_endpoint_disable_and_enable(client):
    _register()
    r = client.post("/v1/tenant/me/mcp/servers/billing/disable", json={"reason": "incident"},
                    headers=_H)
    assert r.status_code == 200
    assert r.json()["status"] == "disabled"
    assert store.get_upstream("acme", "billing")["active"] is False

    r = client.post("/v1/tenant/me/mcp/servers/billing/enable", headers=_H)
    assert r.status_code == 200
    assert store.get_upstream("acme", "billing")["active"] is True


def test_endpoint_disable_preserves_config(client):
    """Disable must not be a soft delete — the credentials have to survive so
    re-enabling doesn't require re-entering them."""
    _register(url="https://mcp.example/mcp", headers={"Authorization": "Bearer s3cret"})
    client.post("/v1/tenant/me/mcp/servers/billing/disable", json={"reason": ""}, headers=_H)
    cfg = store.get_upstream("acme", "billing")
    assert cfg["url"] == "https://mcp.example/mcp"
    assert cfg["headers"] == {"Authorization": "Bearer s3cret"}


def test_endpoint_disable_response_redacts_secrets(client):
    _register(headers={"Authorization": "Bearer s3cret"})
    r = client.post("/v1/tenant/me/mcp/servers/billing/disable", json={"reason": ""},
                    headers=_H)
    assert "s3cret" not in r.text


def test_endpoint_unknown_route_404s(client):
    for path in ("disable", "enable"):
        r = client.post(f"/v1/tenant/me/mcp/servers/nope/{path}",
                        json={"reason": ""}, headers=_H)
        assert r.status_code == 404


def test_endpoint_requires_tenant(client):
    _register()
    r = client.post("/v1/tenant/me/mcp/servers/billing/disable", json={"reason": ""})
    assert r.status_code == 401


def test_endpoint_cannot_disable_another_tenants_route(client):
    """Tenant comes from verified state, so 'acme' naming another tenant's route
    must miss entirely rather than reach across."""
    store.set_upstream("victim", "billing", {"route": "billing", "transport": "stdio",
                                             "command": "x"})
    r = client.post("/v1/tenant/me/mcp/servers/billing/disable", json={"reason": ""},
                    headers=_H)
    assert r.status_code == 404
    assert "active" not in store.get_upstream("victim", "billing")
