"""Sovereign/on-prem auth flows: Mode B (federated OIDC) and Mode C (workload identity).

Both modes hit POST /v1/shield/auth/agent-token without needing the admin
key — the verified caller identity supplies user_sub / agent_id.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest

os.environ.setdefault("SHIELD_AGENT_TOKEN_PRIVATE_KEY", "33" * 32)
os.environ.setdefault("SHIELD_ADMIN_KEY", "test-admin-key")

from core.agent_tokens import (
    decode_claims_unverified,
    reset_signer_cache_for_tests,
    verify_agent_token,
)


@pytest.fixture(autouse=True)
def _reset():
    reset_signer_cache_for_tests()
    yield
    reset_signer_cache_for_tests()


def _make_request(*, spiffe=None, mtls=None, headers=None, tenant_id: str = "t1"):
    """Build a starlette-compatible Request stand-in for _authenticate_caller."""

    class _State:
        pass

    class _Req:
        def __init__(self):
            self.state = _State()
            self.headers = headers or {}

    r = _Req()
    r.state.tenant_id = tenant_id
    if spiffe is not None:
        r.state.spiffe_identity = spiffe
    if mtls is not None:
        r.state.mtls_identity = mtls
    return r


# ─── Mode C: SPIFFE workload identity ───────────────────────────────────


def test_spiffe_authenticates_caller():
    from api.routes_agent_auth import _authenticate_caller

    req = _make_request(spiffe={
        "user_sub": "spiffe://corp.local/billing-bot",
        "agent_id": "billing-bot",
        "tenant_id": "t1",
        "identity_method": "spiffe",
    })
    ctx = asyncio.run(_authenticate_caller(req))
    assert ctx.method == "spiffe"
    assert ctx.user_sub == "spiffe://corp.local/billing-bot"
    assert ctx.agent_id == "billing-bot"
    assert ctx.is_workload


def test_mtls_authenticates_caller():
    from api.routes_agent_auth import _authenticate_caller

    req = _make_request(mtls={
        "agent_key": "billing-bot",
        "tenant_id": "t1",
        "trust_level": "high",
        "identity_method": "mtls",
    })
    ctx = asyncio.run(_authenticate_caller(req))
    assert ctx.method == "mtls"
    assert ctx.agent_id == "billing-bot"


def test_no_auth_method_is_rejected_with_403():
    from fastapi import HTTPException

    from api.routes_agent_auth import _authenticate_caller

    saved = os.environ.pop("SHIELD_ADMIN_KEY", None)
    try:
        req = _make_request()
        with pytest.raises(HTTPException) as exc:
            asyncio.run(_authenticate_caller(req))
        assert exc.value.status_code == 403
    finally:
        if saved is not None:
            os.environ["SHIELD_ADMIN_KEY"] = saved


# ─── Mode B: federated OIDC id_token ────────────────────────────────────


def _stub_oidc_provider(monkeypatch, *, issuer: str, claims: dict):
    """Patch the OIDC registry + validator so the test does not need a real IdP."""
    from core.oauth import oidc_client

    class _Provider:
        client_id = "shield-test"
        audience = "shield-test"
        issuer_ = issuer
        claim_mapping = {"sub": "user_sub", "preferred_username": "agent_id"}

        def effective_audience(self):
            return self.audience

    async def _by_issuer(tenant_id, iss):
        return _Provider() if iss == issuer else None

    async def _validate(_token, _provider):
        return claims

    monkeypatch.setattr(oidc_client.oidc_registry, "get_provider_by_issuer", _by_issuer)
    monkeypatch.setattr(oidc_client, "validate_id_token", _validate)


def _fake_id_token(iss: str, sub: str, extra: dict | None = None) -> str:
    """A JWT that decode_jwt_unverified can read. Signature is not checked here
    because the test patches the actual validator out."""
    import base64
    import json

    header = {"alg": "RS256", "typ": "JWT", "kid": "k1"}
    payload = {"iss": iss, "sub": sub, "aud": "shield-test", "exp": int(time.time()) + 300}
    if extra:
        payload.update(extra)

    def _b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{_b64(header)}.{_b64(payload)}.signaturePlaceholder"


def test_oidc_id_token_authenticates_caller(monkeypatch):
    from api.routes_agent_auth import _authenticate_caller

    issuer = "https://keycloak.corp.local/realms/main"
    _stub_oidc_provider(monkeypatch, issuer=issuer, claims={
        "sub": "alice",
        "preferred_username": "billing-bot",
        "iss": issuer,
    })

    token = _fake_id_token(issuer, "alice", {"preferred_username": "billing-bot"})
    req = _make_request(headers={"X-Id-Token": token})

    ctx = asyncio.run(_authenticate_caller(req))
    assert ctx.method == "oidc_id_token"
    assert ctx.user_sub == "alice"
    assert ctx.agent_id == "billing-bot"


def test_oidc_id_token_with_unknown_issuer_falls_through_to_admin(monkeypatch):
    """If the id_token's issuer is not registered, OIDC auth returns None
    so the next auth method (admin key) can be tried."""
    from core.oauth import oidc_client

    async def _none(*args, **kwargs):
        return None

    monkeypatch.setattr(oidc_client.oidc_registry, "get_provider_by_issuer", _none)

    from api.routes_agent_auth import _authenticate_caller

    token = _fake_id_token("https://unknown/realm", "alice")
    req = _make_request(headers={
        "X-Id-Token": token,
        "X-Admin-Key": "test-admin-key",
    })

    ctx = asyncio.run(_authenticate_caller(req))
    assert ctx.method == "admin"


# ─── End-to-end: workload identity supplies token claims ────────────────


def test_workload_identity_is_bound_into_minted_token(monkeypatch):
    """When caller is workload-authenticated, the minted agent token's
    sub/agent_id must come from the verified identity — not the body."""
    from fastapi import Request

    from api.routes_agent_auth import AgentTokenRequest, issue_agent_token

    # Build a real-ish Request via Starlette so FastAPI can dispatch.
    from starlette.requests import Request as StarletteRequest

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/shield/auth/agent-token",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 0),
    }

    async def _empty_receive():
        return {"type": "http.disconnect"}

    req = StarletteRequest(scope, _empty_receive)
    req.state.tenant_id = "t1"
    req.state.spiffe_identity = {
        "user_sub": "spiffe://corp.local/billing-bot",
        "agent_id": "billing-bot",
        "tenant_id": "t1",
    }

    body = AgentTokenRequest(
        agent_instance_id="inst-1",
        tenant_id="t1",
        build_hash="sha:abc",
        model_version="m",
        session_id="s",
    )

    resp = asyncio.run(issue_agent_token(body, req))
    claims = decode_claims_unverified(resp.agent_token)
    assert claims["user_sub"] == "spiffe://corp.local/billing-bot"
    assert claims["agent_id"] == "billing-bot"
    assert claims["identity_method"] == "spiffe"


def test_workload_caller_with_conflicting_body_is_rejected():
    from fastapi import HTTPException
    from starlette.requests import Request as StarletteRequest

    from api.routes_agent_auth import AgentTokenRequest, issue_agent_token

    scope = {"type": "http", "method": "POST", "path": "/x",
             "headers": [], "query_string": b"", "client": ("127.0.0.1", 0)}

    async def _empty_receive():
        return {"type": "http.disconnect"}

    req = StarletteRequest(scope, _empty_receive)
    req.state.tenant_id = "t1"
    req.state.spiffe_identity = {
        "user_sub": "spiffe://corp.local/billing-bot",
        "agent_id": "billing-bot",
        "tenant_id": "t1",
    }

    body = AgentTokenRequest(
        user_sub="impostor",
        agent_id="billing-bot",
        agent_instance_id="inst-1",
        tenant_id="t1",
        build_hash="sha:abc",
        model_version="m",
        session_id="s",
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(issue_agent_token(body, req))
    assert exc.value.status_code == 400
    assert "conflicts" in exc.value.detail.lower()
