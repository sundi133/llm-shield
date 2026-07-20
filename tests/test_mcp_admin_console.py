"""Portal MCP gateway console (admin plane): inventory + kill switch.

The endpoints derive the tenant from verified request.state, never the body —
the property the data-plane kill-switch endpoints lack (they read tenant_id from
the request body, a cross-tenant IDOR). These tests pin that isolation.
"""
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

import api.routes_mcp_admin as mod


@pytest.fixture
def store(monkeypatch):
    """In-memory stand-ins for the Redis-backed storage layer, per tenant."""
    upstreams: dict = {}   # tenant -> [cfg...]
    disabled: dict = {}    # tenant -> {tool: meta}

    monkeypatch.setattr(mod, "list_upstreams",
                        lambda t: list(upstreams.get(t, [])))
    monkeypatch.setattr(mod, "list_disabled_tools",
                        lambda t: [dict(tool_name=k, **v)
                                   for k, v in disabled.get(t, {}).items()])

    def _disable(tenant_id, tool_name, reason="", actor=""):
        disabled.setdefault(tenant_id, {})[tool_name] = {"reason": reason, "actor": actor}
        return {"tool_name": tool_name, "reason": reason, "actor": actor}

    def _enable(tenant_id, tool_name):
        return disabled.get(tenant_id, {}).pop(tool_name, None) is not None

    monkeypatch.setattr(mod, "disable_tool", _disable)
    monkeypatch.setattr(mod, "enable_tool", _enable)
    return {"upstreams": upstreams, "disabled": disabled}


@pytest.fixture
def client(store):
    app = FastAPI()

    @app.middleware("http")
    async def _set_tenant(request: Request, call_next):
        # Stand in for AuthMiddleware: tenant from a header, as verified state.
        tid = request.headers.get("X-Test-Tenant")
        if tid:
            request.state.tenant_id = tid
        return await call_next(request)

    app.include_router(mod.router)
    return TestClient(app)


def _hdr(tenant):
    return {"X-Test-Tenant": tenant}


# ── auth ─────────────────────────────────────────────────────────────────


def test_inventory_requires_tenant(client):
    assert client.get("/v1/tenant/me/mcp/inventory").status_code == 401


def test_disable_requires_tenant(client):
    r = client.post("/v1/tenant/me/mcp/tools/wire/disable", json={"reason": "x"})
    assert r.status_code == 401


# ── inventory ────────────────────────────────────────────────────────────


def test_inventory_lists_servers_and_threats(client, store):
    store["upstreams"]["acme"] = [{"route": "bank", "transport": "stdio", "command": "x"}]
    r = client.get("/v1/tenant/me/mcp/inventory", headers=_hdr("acme"))
    assert r.status_code == 200
    body = r.json()
    assert body["server_count"] == 1
    assert body["servers"][0]["route"] == "bank"
    assert "tool_poisoning" in body["threats_addressed"]
    assert body["scan_note"]           # honest scope note is present


def test_inventory_redacts_credentials(client, store):
    store["upstreams"]["acme"] = [{
        "route": "bank", "transport": "http", "url": "https://x",
        "headers": {"Authorization": "Bearer super-secret"},
        "shield_tenant_key": "sk-live-secret",
    }]
    body = client.get("/v1/tenant/me/mcp/inventory", headers=_hdr("acme")).json()
    srv = body["servers"][0]
    assert srv["headers"] == {"Authorization": "***"}
    assert srv["shield_tenant_key"] == "***"
    assert "super-secret" not in r_text(body)


def r_text(obj):
    import json
    return json.dumps(obj)


def test_inventory_reflects_disabled_tools(client, store):
    store["disabled"]["acme"] = {"transfer_funds": {"reason": "incident", "actor": "ciso"}}
    body = client.get("/v1/tenant/me/mcp/inventory", headers=_hdr("acme")).json()
    assert body["disabled_count"] == 1
    assert "transfer_funds" in body["_disabled_names"]


# ── kill switch ──────────────────────────────────────────────────────────


def test_disable_then_enable_roundtrip(client, store):
    d = client.post("/v1/tenant/me/mcp/tools/transfer_funds/disable",
                    json={"reason": "incident"}, headers=_hdr("acme"))
    assert d.status_code == 200 and d.json()["status"] == "disabled"
    assert "transfer_funds" in store["disabled"]["acme"]

    e = client.post("/v1/tenant/me/mcp/tools/transfer_funds/enable", headers=_hdr("acme"))
    assert e.status_code == 200 and e.json()["status"] == "enabled"
    assert "transfer_funds" not in store["disabled"].get("acme", {})


def test_enable_unknown_tool_is_404(client):
    r = client.post("/v1/tenant/me/mcp/tools/never/enable", headers=_hdr("acme"))
    assert r.status_code == 404


# ── the property the data-plane endpoints lack: tenant isolation ─────────


def test_disable_cannot_touch_another_tenant(client, store):
    """A body tenant_id must be ignored — the only tenant that matters is the
    authenticated one. Contrast api/routes_killswitch.py, which trusts the body."""
    client.post("/v1/tenant/me/mcp/tools/transfer_funds/disable",
                json={"reason": "x", "tenant_id": "victim"}, headers=_hdr("attacker"))
    # The spoofed tenant_id in the body is inert: victim is untouched...
    assert "victim" not in store["disabled"]
    # ...and the tool was disabled for the caller's own tenant instead.
    assert "transfer_funds" in store["disabled"]["attacker"]


def test_inventory_is_scoped_to_caller(client, store):
    store["upstreams"]["acme"] = [{"route": "a", "transport": "stdio", "command": "x"}]
    store["upstreams"]["other"] = [{"route": "b", "transport": "stdio", "command": "y"}]
    body = client.get("/v1/tenant/me/mcp/inventory", headers=_hdr("acme")).json()
    routes = [s["route"] for s in body["servers"]]
    assert routes == ["a"]      # never sees 'other'
