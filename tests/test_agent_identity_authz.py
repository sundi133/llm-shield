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

    # No Redis in tests — the cert registry falls back to its in-process store.
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)

    a = FastAPI()
    a.include_router(identity_router)
    return a


@pytest.fixture
def client(app):
    return TestClient(app)


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

    def test_tenant_api_key_is_not_enough(self, client):
        """A tenant API key is not an admin credential. Accepting one here
        would let any tenant register certs in another tenant."""
        r = client.post(REGISTER, json=BODY, headers={"X-API-Key": "some-tenant-key"})
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
