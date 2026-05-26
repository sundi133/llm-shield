"""The tenant agent-token endpoint accepts workload identity and federated
id_tokens — no admin key required.

This is the customer-facing companion to test_sovereign_auth_modes.py
(which covers the admin endpoint). Same three modes (B + C₁ + C₂), but
the caller only ever sends their tenant API key.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest

os.environ.setdefault("SHIELD_AGENT_TOKEN_PRIVATE_KEY", "44" * 32)

from core.agent_tokens import (
    decode_claims_unverified,
    reset_signer_cache_for_tests,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_signer_cache_for_tests()
    yield
    reset_signer_cache_for_tests()


def _fake_request(*, tenant_id: str, spiffe=None, mtls=None, headers=None):
    """Minimal Request stand-in with .state and .headers."""
    from starlette.requests import Request as StarletteRequest

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/tenant/me/agent-auth/agent-token",
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
        "query_string": b"",
        "client": ("127.0.0.1", 0),
    }

    async def _empty_receive():
        return {"type": "http.disconnect"}

    req = StarletteRequest(scope, _empty_receive)
    req.state.tenant_id = tenant_id
    if spiffe is not None:
        req.state.spiffe_identity = spiffe
    if mtls is not None:
        req.state.mtls_identity = mtls
    return req


def _build_request_body(**overrides):
    from api.routes_agent_auth import TenantAgentTokenRequest

    base = dict(
        agent_instance_id="inst-1",
        build_hash="sha:dev",
        model_version="m",
        session_id="s",
    )
    base.update(overrides)
    return TenantAgentTokenRequest(**base)


def _fake_id_token(iss: str, sub: str, extra: dict | None = None) -> str:
    import base64
    import json

    header = {"alg": "RS256", "typ": "JWT", "kid": "k1"}
    payload = {
        "iss": iss, "sub": sub, "aud": "shield-test",
        "exp": int(time.time()) + 300,
    }
    if extra:
        payload.update(extra)

    def _b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{_b64(header)}.{_b64(payload)}.signaturePlaceholder"


# ── Tenant-key only path (no workload identity) ────────────────────────


def test_tenant_key_with_body_claims_is_accepted():
    from api.routes_agent_auth import issue_agent_token_tenant

    req = _fake_request(tenant_id="acme")
    body = _build_request_body(user_sub="alice", agent_id="billing-bot")

    resp = asyncio.run(issue_agent_token_tenant(body, req))
    claims = decode_claims_unverified(resp.agent_token)
    assert claims["user_sub"] == "alice"
    assert claims["agent_id"] == "billing-bot"
    assert claims["identity_method"] == "tenant_api_key"
    assert claims["tenant_id"] == "acme"


def test_tenant_key_missing_identity_in_body_is_rejected():
    from fastapi import HTTPException

    from api.routes_agent_auth import issue_agent_token_tenant

    req = _fake_request(tenant_id="acme")
    body = _build_request_body()  # no user_sub / agent_id

    with pytest.raises(HTTPException) as exc:
        asyncio.run(issue_agent_token_tenant(body, req))
    assert exc.value.status_code == 400


# ── Mode B: federated id_token, no admin key ───────────────────────────


def test_id_token_supplies_identity_for_tenant_caller(monkeypatch):
    from api.routes_agent_auth import issue_agent_token_tenant
    from core.oauth import oidc_client

    issuer = "https://keycloak.acme.corp/realms/main"

    class _Prov:
        client_id = "shield"
        audience = "shield"
        claim_mapping = {"sub": "user_sub", "preferred_username": "agent_id"}

        def effective_audience(self):
            return self.audience

    async def _by_issuer(tenant_id, iss):
        return _Prov() if iss == issuer and tenant_id == "acme" else None

    async def _validate(_token, _provider):
        return {"sub": "alice", "preferred_username": "billing-bot", "iss": issuer}

    monkeypatch.setattr(oidc_client.oidc_registry, "get_provider_by_issuer", _by_issuer)
    monkeypatch.setattr(oidc_client, "validate_id_token", _validate)

    token = _fake_id_token(issuer, "alice", {"preferred_username": "billing-bot"})
    req = _fake_request(tenant_id="acme", headers={"X-Id-Token": token})
    body = _build_request_body()  # caller doesn't supply identity

    resp = asyncio.run(issue_agent_token_tenant(body, req))
    claims = decode_claims_unverified(resp.agent_token)
    assert claims["identity_method"] == "oidc_id_token"
    assert claims["user_sub"] == "alice"
    assert claims["agent_id"] == "billing-bot"


def test_id_token_with_unknown_issuer_is_rejected(monkeypatch):
    from fastapi import HTTPException

    from api.routes_agent_auth import issue_agent_token_tenant
    from core.oauth import oidc_client

    async def _none(*_args, **_kwargs):
        return None

    monkeypatch.setattr(oidc_client.oidc_registry, "get_provider_by_issuer", _none)

    token = _fake_id_token("https://unknown.example/realm", "alice")
    req = _fake_request(tenant_id="acme", headers={"X-Id-Token": token})
    body = _build_request_body()

    with pytest.raises(HTTPException) as exc:
        asyncio.run(issue_agent_token_tenant(body, req))
    assert exc.value.status_code == 401
    assert "not registered" in exc.value.detail.lower()


# ── Mode C: SPIFFE / mTLS, no admin key, no id_token ───────────────────


def test_spiffe_supplies_identity_for_tenant_caller():
    from api.routes_agent_auth import issue_agent_token_tenant

    req = _fake_request(
        tenant_id="acme",
        spiffe={
            "user_sub": "spiffe://acme.corp/billing-bot",
            "agent_id": "billing-bot",
            "tenant_id": "acme",
        },
    )
    body = _build_request_body()

    resp = asyncio.run(issue_agent_token_tenant(body, req))
    claims = decode_claims_unverified(resp.agent_token)
    assert claims["identity_method"] == "spiffe"
    assert claims["user_sub"] == "spiffe://acme.corp/billing-bot"
    assert claims["agent_id"] == "billing-bot"


def test_mtls_supplies_identity_for_tenant_caller():
    from api.routes_agent_auth import issue_agent_token_tenant

    req = _fake_request(
        tenant_id="acme",
        mtls={"agent_key": "billing-bot", "tenant_id": "acme", "trust_level": "high"},
    )
    body = _build_request_body()

    resp = asyncio.run(issue_agent_token_tenant(body, req))
    claims = decode_claims_unverified(resp.agent_token)
    assert claims["identity_method"] == "mtls"
    assert claims["agent_id"] == "billing-bot"


def test_workload_identity_overrides_body_silently_when_matching():
    """When the body matches the verified identity exactly, mint succeeds."""
    from api.routes_agent_auth import issue_agent_token_tenant

    req = _fake_request(
        tenant_id="acme",
        spiffe={
            "user_sub": "spiffe://acme.corp/billing-bot",
            "agent_id": "billing-bot",
            "tenant_id": "acme",
        },
    )
    body = _build_request_body(
        user_sub="spiffe://acme.corp/billing-bot",
        agent_id="billing-bot",
    )

    resp = asyncio.run(issue_agent_token_tenant(body, req))
    assert resp.expires_in > 0


def test_workload_caller_with_conflicting_body_is_rejected():
    from fastapi import HTTPException

    from api.routes_agent_auth import issue_agent_token_tenant

    req = _fake_request(
        tenant_id="acme",
        spiffe={
            "user_sub": "spiffe://acme.corp/billing-bot",
            "agent_id": "billing-bot",
            "tenant_id": "acme",
        },
    )
    body = _build_request_body(user_sub="impostor", agent_id="billing-bot")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(issue_agent_token_tenant(body, req))
    assert exc.value.status_code == 400
    assert "conflicts" in exc.value.detail.lower()
