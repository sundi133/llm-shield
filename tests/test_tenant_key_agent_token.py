"""A tenant issues agent tokens with its own key — and only for itself.

Before this, /auth/agent-token accepted SHIELD_ADMIN_KEY: one platform-wide
operator secret authorizing issuance for EVERY tenant. Running agents meant
being handed the master key.

The property that matters here is not "a tenant key works" but "a tenant key
works for exactly one tenant". The binding is on the RESOLVED tenant, never the
one in the request body.
"""

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routes_agent_auth import router

_BODY = {
    "user_sub": "user-1", "agent_id": "billing-bot", "agent_instance_id": "inst-1",
    "tenant_id": "acme", "build_hash": "b", "model_version": "m", "session_id": "s",
}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", "11" * 32)
    monkeypatch.delenv("SHIELD_ADMIN_KEY", raising=False)
    monkeypatch.delenv("WORKERS", raising=False)
    yield


def _client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _issue(tenant_id="acme", key="acme-key", providers="tenant_key",
           resolver=lambda k: "acme" if k == "acme-key" else None):
    """POST /auth/agent-token with a tenant API key."""
    body = dict(_BODY, tenant_id=tenant_id)
    with patch.dict("os.environ", {"SHIELD_WORKLOAD_IDENTITY_PROVIDERS": providers}), \
            patch("storage.tenant_store.resolve_tenant_by_api_key", side_effect=resolver), \
            patch("api.routes_agent_auth._require_registered_agent", lambda *a, **k: None):
        return _client().post("/v1/shield/auth/agent-token", json=body,
                              headers={"X-API-Key": key} if key else {})


def test_tenant_key_issues_for_its_own_tenant():
    r = _issue()
    assert r.status_code == 200, r.text
    assert r.json()["agent_token"]


def test_tenant_key_cannot_issue_for_another_tenant():
    """The one that matters: the body asks for someone else's tenant."""
    r = _issue(tenant_id="globex")
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert "acme" in detail and "globex" in detail


def test_empty_tenant_is_a_mismatch_not_consent():
    """Substituting the resolved tenant would hand out a token for whatever
    the key happened to own, to a caller that never named one."""
    r = _issue(tenant_id="")
    assert r.status_code == 403


def test_unresolvable_key_gets_no_token():
    r = _issue(key="revoked-key")
    assert r.status_code == 403
    assert "acme" not in (r.json().get("detail") or "")


def test_no_api_key_at_all():
    r = _issue(key="")
    assert r.status_code == 403


def test_store_failure_fails_closed():
    """Redis down must not authorize issuance, and must not 500."""
    def _boom(_k):
        raise ConnectionError("redis is down")

    r = _issue(resolver=_boom)
    assert r.status_code == 403


def test_provider_is_off_by_default():
    """Enabling it widens who may mint tokens, so it is opt-in. With the
    default chain a tenant key must do nothing."""
    r = _issue(providers="admin_key,spiffe")
    assert r.status_code in (403, 500)
    assert "agent_token" not in r.text


def test_admin_key_is_not_tenant_bound(monkeypatch):
    """An operator credential deliberately issues across tenants — that is the
    distinction being preserved, not an oversight."""
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "operator-secret")
    with patch.dict("os.environ", {"SHIELD_WORKLOAD_IDENTITY_PROVIDERS": "admin_key"}), \
            patch("api.routes_agent_auth._require_registered_agent", lambda *a, **k: None):
        r = _client().post("/v1/shield/auth/agent-token",
                           json=dict(_BODY, tenant_id="any-other-tenant"),
                           headers={"X-Admin-Key": "operator-secret"})
    assert r.status_code == 200, r.text


def test_identity_records_the_provider_for_audit():
    """'which credential authorized this' has to survive into the record."""
    from starlette.requests import Request

    from core.workload_identity import resolve_workload_identity

    req = Request({"type": "http", "method": "POST", "path": "/x",
                   "headers": [(b"x-api-key", b"acme-key")]})
    with patch.dict("os.environ", {"SHIELD_WORKLOAD_IDENTITY_PROVIDERS": "tenant_key"}), \
            patch("storage.tenant_store.resolve_tenant_by_api_key",
                  side_effect=lambda k: "acme"):
        ident = resolve_workload_identity(req)
    assert ident is not None
    assert ident.provider == "tenant_key"
    assert ident.claims["tenant_id"] == "acme"
    assert ident.subject == "tenant:acme"
