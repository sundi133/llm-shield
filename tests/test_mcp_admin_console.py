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
    upstreams: dict = {}   # tenant -> {route: cfg}
    disabled: dict = {}    # tenant -> {tool: meta}

    monkeypatch.setattr(mod, "list_upstreams",
                        lambda t: list(upstreams.get(t, {}).values()))
    monkeypatch.setattr(mod, "get_upstream",
                        lambda t, route: upstreams.get(t, {}).get(route))
    monkeypatch.setattr(mod, "set_upstream",
                        lambda t, route, cfg: upstreams.setdefault(t, {}).__setitem__(route, cfg))

    def _delete_upstream(t, route):
        return upstreams.get(t, {}).pop(route, None) is not None

    monkeypatch.setattr(mod, "delete_upstream", _delete_upstream)
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
    store["upstreams"]["acme"] = {"bank": {"route": "bank", "transport": "stdio", "command": "x"}}
    r = client.get("/v1/tenant/me/mcp/inventory", headers=_hdr("acme"))
    assert r.status_code == 200
    body = r.json()
    assert body["server_count"] == 1
    assert body["servers"][0]["route"] == "bank"
    assert "tool_poisoning" in body["threats_addressed"]
    assert body["scan_note"]           # honest scope note is present


def test_inventory_redacts_credentials(client, store):
    store["upstreams"]["acme"] = {"bank": {
        "route": "bank", "transport": "http", "url": "https://x",
        "headers": {"Authorization": "Bearer super-secret"},
        "shield_tenant_key": "sk-live-secret",
    }}
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
    store["upstreams"]["acme"] = {"a": {"route": "a", "transport": "stdio", "command": "x"}}
    store["upstreams"]["other"] = {"b": {"route": "b", "transport": "stdio", "command": "y"}}
    body = client.get("/v1/tenant/me/mcp/inventory", headers=_hdr("acme")).json()
    routes = [s["route"] for s in body["servers"]]
    assert routes == ["a"]      # never sees 'other'


# ── register / delete a server (portal write path) ───────────────────────


def test_register_server_creates_and_lists(client, store):
    r = client.post("/v1/tenant/me/mcp/servers", headers=_hdr("acme"),
                    json={"route": "crm", "transport": "http",
                          "url": "https://crm/mcp", "isolation_ack": True})
    assert r.status_code == 200
    assert r.json()["status"] == "created"
    assert "crm" in store["upstreams"]["acme"]

    inv = client.get("/v1/tenant/me/mcp/inventory", headers=_hdr("acme")).json()
    assert [s["route"] for s in inv["servers"]] == ["crm"]


def test_register_second_time_updates(client, store):
    body = {"route": "crm", "transport": "http", "url": "https://crm/mcp", "isolation_ack": True}
    client.post("/v1/tenant/me/mcp/servers", headers=_hdr("acme"), json=body)
    r = client.post("/v1/tenant/me/mcp/servers", headers=_hdr("acme"),
                    json={**body, "url": "https://crm2/mcp"})
    assert r.json()["status"] == "updated"
    assert store["upstreams"]["acme"]["crm"]["url"] == "https://crm2/mcp"


def test_register_warns_when_not_isolated(client, store):
    r = client.post("/v1/tenant/me/mcp/servers", headers=_hdr("acme"),
                    json={"route": "crm", "transport": "http",
                          "url": "https://crm/mcp", "isolation_ack": False})
    assert "warning" in r.json()
    assert "bypass" in r.json()["warning"].lower()


def test_register_redacts_secrets_in_response(client, store):
    r = client.post("/v1/tenant/me/mcp/servers", headers=_hdr("acme"),
                    json={"route": "crm", "transport": "http", "url": "https://crm/mcp",
                          "headers": {"Authorization": "Bearer secret"},
                          "isolation_ack": True})
    assert r.json()["server"]["headers"] == {"Authorization": "***"}
    assert "secret" not in r_text(r.json())


def test_register_requires_tenant(client):
    r = client.post("/v1/tenant/me/mcp/servers",
                    json={"route": "crm", "transport": "http", "url": "https://x/mcp"})
    assert r.status_code == 401


@pytest.mark.parametrize("bad", [
    {"route": "has space", "transport": "http", "url": "https://x/mcp"},
    {"route": "crm", "transport": "ftp", "url": "https://x/mcp"},
    {"route": "crm", "transport": "http"},               # missing url
    {"route": "crm", "transport": "stdio"},              # missing command
])
def test_register_rejects_bad_input(client, bad):
    r = client.post("/v1/tenant/me/mcp/servers", headers=_hdr("acme"), json=bad)
    assert r.status_code == 422


def test_delete_server(client, store):
    store["upstreams"]["acme"] = {"crm": {"route": "crm", "transport": "http", "url": "https://x"}}
    r = client.request("DELETE", "/v1/tenant/me/mcp/servers/crm", headers=_hdr("acme"))
    assert r.status_code == 200 and r.json()["status"] == "deleted"
    assert "crm" not in store["upstreams"].get("acme", {})


def test_delete_unknown_is_404(client):
    r = client.request("DELETE", "/v1/tenant/me/mcp/servers/nope", headers=_hdr("acme"))
    assert r.status_code == 404


def test_register_is_scoped_to_caller(client, store):
    """A route registered by 'acme' must not appear for, or be deletable by,
    another tenant. The write path derives tenant from verified state."""
    client.post("/v1/tenant/me/mcp/servers", headers=_hdr("acme"),
                json={"route": "crm", "transport": "http", "url": "https://x/mcp",
                      "isolation_ack": True})
    # 'other' cannot see it...
    inv = client.get("/v1/tenant/me/mcp/inventory", headers=_hdr("other")).json()
    assert inv["servers"] == []
    # ...nor delete it.
    r = client.request("DELETE", "/v1/tenant/me/mcp/servers/crm", headers=_hdr("other"))
    assert r.status_code == 404
    assert "crm" in store["upstreams"]["acme"]
