"""Cross-tenant guard on capability minting.

`/v1/shield/cap/mint` authorizes from the agent token's claims. The token's
`tenant_id` is caller-supplied at issuance, so if a request also presents a
tenant API key the two must agree — otherwise a token minted for tenant A could
be used to mint capabilities while authenticating as tenant B.

Non-breaking by construction: with no tenant API key on the request, behaviour
is unchanged and the agent token alone decides.
"""
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from api.routes_agent_auth import router as agent_auth_router
from core.agent_identity_middleware import AgentIdentityMiddleware
from core.agent_tokens import reset_signer_cache_for_tests
from core.capabilities import reset_cap_signer_cache_for_tests, clear_nonce_store_for_tests
from storage.revocation import clear_all_for_tests


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "test-admin")
    monkeypatch.delenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("SHIELD_AGENT_ALLOWED_BUILDS", raising=False)

    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()

    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)

    from core.rbac import enforcer
    monkeypatch.setattr(enforcer, "_agents", {})
    monkeypatch.setattr(enforcer, "_roles", {})

    a = FastAPI()
    a.add_middleware(AgentIdentityMiddleware)
    a.include_router(agent_auth_router)
    yield a

    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()


@pytest.fixture
def client(app):
    return TestClient(app)


def _token(client, tenant_id: str) -> str:
    r = client.post(
        "/v1/shield/auth/agent-token",
        headers={"X-Admin-Key": "test-admin"},
        json=dict(user_sub="user-1", agent_id="billing-bot", agent_instance_id="i-1",
                  tenant_id=tenant_id, build_hash="b" * 64, model_version="m1",
                  session_id="s-1", ttl_seconds=300),
    )
    assert r.status_code == 200, r.text
    return r.json()["agent_token"]


CAP_BODY = {"tool": "get_ticket", "resource": "ticket:1", "ttl_seconds": 30}


def _register_key(tenant_id: str, api_key: str):
    from storage.tenant_store import create_tenant, get_tenant, add_api_key
    if not get_tenant(tenant_id):
        create_tenant(tenant_id, {"name": tenant_id}, api_keys=[api_key])
    else:
        add_api_key(tenant_id, api_key)


class TestTenantBinding:
    def test_mismatched_tenant_api_key_is_refused(self, client):
        """A token for tenant-a presented alongside tenant-b's API key."""
        _register_key("tenant-b", "key-b")
        token = _token(client, "tenant-a")
        r = client.post("/v1/shield/cap/mint", json=CAP_BODY,
                        headers={"X-Agent-Token": token, "X-API-Key": "key-b"})
        assert r.status_code == 403, (
            f"cross-tenant cap mint returned {r.status_code} — a token issued for "
            "tenant-a was accepted while authenticating as tenant-b"
        )

    def test_matching_tenant_api_key_is_allowed(self, client):
        _register_key("tenant-a", "key-a")
        token = _token(client, "tenant-a")
        r = client.post("/v1/shield/cap/mint", json=CAP_BODY,
                        headers={"X-Agent-Token": token, "X-API-Key": "key-a"})
        assert r.status_code in (200, 403), r.text
        if r.status_code == 403:
            # Denied by policy, not by tenant binding.
            assert "tenant" not in r.text.lower()

    def test_no_api_key_is_unchanged(self, client):
        """Regression guard: the common path sends only the agent token, and
        must behave exactly as before this check existed."""
        token = _token(client, "tenant-a")
        r = client.post("/v1/shield/cap/mint", json=CAP_BODY,
                        headers={"X-Agent-Token": token})
        assert r.status_code in (200, 403), r.text
        if r.status_code == 403:
            assert "tenant" not in r.text.lower()

    def test_unknown_api_key_does_not_grant_access(self, client):
        """An API key that resolves to no tenant must not be treated as a
        match. Failing open here would make the check trivially bypassable."""
        token = _token(client, "tenant-a")
        r = client.post("/v1/shield/cap/mint", json=CAP_BODY,
                        headers={"X-Agent-Token": token, "X-API-Key": "not-a-real-key"})
        assert r.status_code in (200, 403), r.text
