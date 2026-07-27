"""Authorization on the agent-identity cert routes.

`POST /v1/shield/agent/identity/register` binds a certificate fingerprint to an
agent and grants it trust_level "high"; `/revoke` takes that away. Both take
`tenant_id` from the request body, so an unauthenticated caller could mint or
destroy an identity in any tenant. These tests pin the gate shut.
"""
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from api.routes_agent_identity import router as identity_router


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "test-admin")
    # admin_key only: SPIFFE/mTLS aren't configured in this test app.
    monkeypatch.setenv("SHIELD_WORKLOAD_IDENTITY_PROVIDERS", "admin_key")

    # No Redis in tests — the cert registry falls back to its in-process store,
    # which is module-level and would otherwise leak between tests: a legitimate
    # admin registration in one test would satisfy a "nothing was written"
    # assertion in the next.
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)
    tenant_store._fallback_store.clear()

    a = FastAPI()
    a.include_router(identity_router)
    return a


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def tenant_key():
    """An API key belonging to tenant-a, registered in the fallback store."""
    from storage.tenant_store import create_tenant, get_tenant, add_api_key
    key = "key-tenant-a"
    if not get_tenant("tenant-a"):
        create_tenant("tenant-a", {"name": "Tenant A"}, api_keys=[key])
    else:
        add_api_key("tenant-a", key)
    return key


REGISTER = "/v1/shield/agent/identity/register"
REVOKE = "/v1/shield/agent/identity/revoke"
BODY = {"agent_key": "billing-bot", "fingerprint": "a" * 64, "tenant_id": "victim-tenant"}


class TestRegisterRequiresAdmin:
    def test_no_credentials_is_refused(self, client):
        """The core issue: registering a cert grants 'high' trust to a
        fingerprint the caller chose, for a tenant the caller named."""
        r = client.post(REGISTER, json=BODY)
        assert r.status_code == 403, (
            f"unauthenticated cert registration returned {r.status_code} — "
            "any caller could bind a fingerprint to any agent in any tenant"
        )

    def test_wrong_admin_key_is_refused(self, client):
        r = client.post(REGISTER, json=BODY, headers={"X-Admin-Key": "not-the-key"})
        assert r.status_code == 403

    def test_unknown_api_key_is_refused(self, client):
        """A key that resolves to no tenant is not a credential."""
        r = client.post(REGISTER, json=BODY, headers={"X-API-Key": "not-a-real-key"})
        assert r.status_code == 403

    def test_admin_key_is_accepted(self, client):
        r = client.post(REGISTER, json=BODY, headers={"X-Admin-Key": "test-admin"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "registered"


class TestRevokeRequiresAdmin:
    def test_no_credentials_is_refused(self, client):
        """Unauthenticated revoke is a denial-of-service on every agent."""
        r = client.post(REVOKE, json={"agent_key": "billing-bot", "tenant_id": "victim-tenant"})
        assert r.status_code == 403

    def test_wrong_admin_key_is_refused(self, client):
        r = client.post(REVOKE, json={"agent_key": "billing-bot", "tenant_id": "victim-tenant"},
                        headers={"X-Admin-Key": "not-the-key"})
        assert r.status_code == 403

    def test_admin_key_is_accepted(self, client):
        client.post(REGISTER, json=BODY, headers={"X-Admin-Key": "test-admin"})
        r = client.post(REVOKE, json={"agent_key": "billing-bot", "tenant_id": "victim-tenant"},
                        headers={"X-Admin-Key": "test-admin"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "revoked"


class TestTenantSelfService:
    """Tenants register their own agents with their own API key. The control
    is confinement to their tenant, not exclusion — the original risk was that
    `tenant_id` comes from the request body."""

    def test_tenant_key_may_register_in_its_own_tenant(self, client, tenant_key):
        body = dict(BODY, tenant_id="tenant-a")
        r = client.post(REGISTER, json=body, headers={"X-API-Key": tenant_key})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "registered"

    def test_tenant_key_may_not_register_in_another_tenant(self, client, tenant_key):
        """The actual vulnerability: body-supplied tenant_id crossing tenants."""
        body = dict(BODY, tenant_id="victim-tenant")
        r = client.post(REGISTER, json=body, headers={"X-API-Key": tenant_key})
        assert r.status_code == 403, (
            f"returned {r.status_code} — tenant-a's key registered a cert in victim-tenant"
        )

    def test_tenant_key_may_revoke_in_its_own_tenant(self, client, tenant_key):
        client.post(REGISTER, json=dict(BODY, tenant_id="tenant-a"),
                    headers={"X-API-Key": tenant_key})
        r = client.post(REVOKE, json={"agent_key": "billing-bot", "tenant_id": "tenant-a"},
                        headers={"X-API-Key": tenant_key})
        assert r.status_code == 200, r.text

    def test_tenant_key_may_not_revoke_in_another_tenant(self, client, tenant_key):
        """Cross-tenant revoke is a denial of service on someone else's agents."""
        client.post(REGISTER, json=BODY, headers={"X-Admin-Key": "test-admin"})
        r = client.post(REVOKE, json={"agent_key": "billing-bot", "tenant_id": "victim-tenant"},
                        headers={"X-API-Key": tenant_key})
        assert r.status_code == 403

    def test_cross_tenant_register_has_no_side_effect(self, client, tenant_key):
        client.post(REGISTER, json=dict(BODY, tenant_id="victim-tenant"),
                    headers={"X-API-Key": tenant_key})
        from guardrails.agentic.identity.cert_registry import get_agent_trust
        trust = get_agent_trust("victim-tenant", "billing-bot")
        assert not trust or trust.get("trust_level") != "high"


class TestAuthorizationRunsBeforeSideEffects:
    def test_refused_register_does_not_register(self, client):
        """A 403 must mean nothing was written — not that the write happened
        and the response was rejected afterwards."""
        client.post(REGISTER, json=BODY)
        from guardrails.agentic.identity.cert_registry import get_agent_trust
        trust = get_agent_trust("victim-tenant", "billing-bot")
        assert not trust or trust.get("trust_level") != "high", (
            "unauthenticated request still registered the certificate"
        )
