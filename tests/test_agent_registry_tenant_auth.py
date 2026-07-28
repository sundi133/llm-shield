"""Tenants register their own agents with only a tenant API key.

Agent registration is self-service: a tenant defines its agents, their tools
and their role_permissions without an operator in the loop. Nothing here should
ever require an admin credential.

The tenant is derived from the API key, never from the request body — so a body
`tenant_id` cannot be used to write into another tenant. That is the property
worth pinning, because it is easy to "helpfully" add later.
"""
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from api.routes_agents_registry import router as registry_router

REGISTRY = "/v1/agents/registry"


@pytest.fixture
def app(monkeypatch):
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)

    # Tenant ids are unique to this module on purpose. The fallback store is
    # process-wide, and registering an agent puts a tenant into managed mode —
    # reusing a name another test file mints tokens for would make ITS tokens
    # fail registry validation. Do not clear the store here either: other
    # modules set state up at import time.
    from storage.tenant_store import create_tenant, get_tenant, add_api_key
    for tid, key in (("regauth-a", "regauth-key-a"), ("regauth-b", "regauth-key-b")):
        if not get_tenant(tid):
            create_tenant(tid, {"name": tid}, api_keys=[key])
        else:
            add_api_key(tid, key)

    a = FastAPI()
    a.include_router(registry_router)
    return a


@pytest.fixture
def client(app):
    return TestClient(app)


def _agent(**over):
    body = {
        "agent_id": "support-bot",
        "name": "Support bot",
        "tools": ["get_ticket", "wire_transfer_execute"],
        "role_permissions": {"customer_support": ["get_ticket"]},
    }
    body.update(over)
    return body


class TestTenantSelfService:
    def test_tenant_key_alone_registers_an_agent(self, client):
        """No admin credential anywhere in this request."""
        r = client.post(REGISTRY, json=_agent(), headers={"X-API-Key": "regauth-key-a"})
        assert r.status_code == 200, r.text
        assert r.json()["agent"]["agent_id"] == "support-bot"

    def test_role_permissions_are_stored_as_given(self, client):
        """The role -> tool matrix is what the tool belt and admin console
        render, so it must round-trip exactly."""
        client.post(REGISTRY, json=_agent(), headers={"X-API-Key": "regauth-key-a"})
        r = client.get(REGISTRY, headers={"X-API-Key": "regauth-key-a"})
        assert r.status_code == 200, r.text
        agent = r.json()["agents"]["support-bot"]
        assert agent["role_permissions"] == {"customer_support": ["get_ticket"]}

    def test_no_admin_key_is_required(self, client):
        """Regression guard: adding an admin gate here would break every
        tenant's ability to manage its own agents."""
        r = client.post(REGISTRY, json=_agent(agent_id="another-bot"),
                        headers={"X-API-Key": "regauth-key-a"})
        assert r.status_code != 403, "agent registration must not require an admin credential"


class TestTenantIsolation:
    def test_tenant_id_in_body_cannot_target_another_tenant(self, client):
        """The tenant comes from the key, not the body."""
        r = client.post(REGISTRY, json=_agent(agent_id="cross-bot", tenant_id="regauth-b"),
                        headers={"X-API-Key": "regauth-key-a"})
        assert r.status_code == 200, r.text

        # It landed in tenant-a (the key's tenant), not tenant-b.
        seen_by_b = client.get(REGISTRY, headers={"X-API-Key": "regauth-key-b"}).json()["agents"]
        assert "cross-bot" not in seen_by_b, (
            "a body-supplied tenant_id wrote an agent into another tenant"
        )
        seen_by_a = client.get(REGISTRY, headers={"X-API-Key": "regauth-key-a"}).json()["agents"]
        assert "cross-bot" in seen_by_a

    def test_tenants_do_not_see_each_others_agents(self, client):
        client.post(REGISTRY, json=_agent(), headers={"X-API-Key": "regauth-key-a"})
        agents_b = client.get(REGISTRY, headers={"X-API-Key": "regauth-key-b"}).json()["agents"]
        assert "support-bot" not in agents_b
