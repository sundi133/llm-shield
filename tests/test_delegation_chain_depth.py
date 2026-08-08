"""Delegation chains: proven parents and bounded depth.

`parent_agent_id` is copied from the request body straight into a signed token,
verified by nothing and read by no authorization decision. A depth limit over an
unproven parent link limits nothing, because the caller picks the depth. So
provenance comes first, then the bound.

**Everything here runs against BOTH mint endpoints.** There are two:

    POST /v1/shield/auth/agent-token   (admin key, tenant in the body)
    POST /v1/tenant/me/agent-auth/agent-token   (tenant API key, tenant from key)

They carry the same parent_agent_id pattern. Fixing one and forgetting the other
leaves a bypass, and a bypass is worse than the current honest absence of a
control — so the route is a fixture parameter rather than something each test
remembers to repeat.

Spec: docs/spec-delegation-chain-depth.md
"""
from __future__ import annotations

from typing import Iterator

import pytest
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

from api.routes_agent_auth import (router as agent_auth_router,
                                   tenant_router as agent_auth_tenant_router)
from core.agent_identity_middleware import AgentIdentityMiddleware
from core.agent_tokens import (decode_claims_unverified,
                               reset_signer_cache_for_tests,
                               verify_agent_token)
from storage.revocation import clear_all_for_tests

TENANT = "t1"


class _FakeTenantAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key")
        if key:
            request.state.tenant_id = key
        return await call_next(request)


@pytest.fixture
def app(monkeypatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "admin")
    monkeypatch.delenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", raising=False)
    for k in ("SHIELD_DELEGATION_PARENT_PROOF", "SHIELD_MAX_DELEGATION_DEPTH"):
        monkeypatch.delenv(k, raising=False)

    reset_signer_cache_for_tests()
    clear_all_for_tests()

    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)

    from core.rbac import enforcer
    monkeypatch.setattr(enforcer, "_agents", {})
    monkeypatch.setattr(enforcer, "_roles", {})

    application = FastAPI()
    application.add_middleware(_FakeTenantAuthMiddleware)
    application.add_middleware(AgentIdentityMiddleware)
    application.include_router(agent_auth_router)
    application.include_router(agent_auth_tenant_router)
    yield application

    reset_signer_cache_for_tests()
    clear_all_for_tests()


@pytest.fixture
def client(app):
    return TestClient(app)


class Minter:
    """Mints through one of the two endpoints, hiding their differences.

    The admin route takes tenant_id in the body; the tenant route derives it
    from the API key. Everything else about the request is identical, which is
    exactly why both must gain the same controls.
    """

    def __init__(self, client, kind):
        self.client = client
        self.kind = kind

    def post(self, **body):
        payload = dict(
            user_sub="alice", agent_id="billing-bot",
            agent_instance_id="inst-1", build_hash="b", model_version="m",
            session_id="s", ttl_seconds=300,
        )
        payload.update(body)
        if self.kind == "admin":
            payload.setdefault("tenant_id", TENANT)
            return self.client.post("/v1/shield/auth/agent-token",
                                    headers={"X-Admin-Key": "admin"},
                                    json=payload)
        payload.pop("tenant_id", None)
        return self.client.post("/v1/tenant/me/agent-auth/agent-token",
                                headers={"X-API-Key": TENANT}, json=payload)

    def token(self, **body):
        r = self.post(**body)
        assert r.status_code == 200, r.text
        return r.json()["agent_token"]


@pytest.fixture(params=["admin", "tenant"])
def minter(client, request):
    return Minter(client, request.param)


# ── Baseline: today's behaviour, pinned before it changes ────────────────


def test_parent_agent_id_is_currently_caller_asserted(minter):
    """The defect, stated as a test.

    Nothing verifies that the named parent exists, that it delegated anything,
    or that the caller has any relationship to it. Shield signs the claim
    anyway. This pins the default so the change to it is deliberate.
    """
    token = minter.token(parent_agent_id="some-agent-i-do-not-control")
    claims = decode_claims_unverified(token)
    assert claims["parent_agent_id"] == "some-agent-i-do-not-control"


def test_a_root_token_has_no_parent(minter):
    claims = decode_claims_unverified(minter.token())
    assert claims.get("parent_agent_id") is None


def test_both_routes_mint_a_verifiable_token(minter):
    """Sanity: the fixture drives both endpoints for real, not a stub."""
    identity = verify_agent_token(minter.token())
    assert identity.agent_id == "billing-bot"
    assert identity.tenant_id == TENANT


def test_no_depth_claim_by_default(minter):
    """Absent rather than 0, so existing callers' tokens stay byte-compatible."""
    assert "delegation_depth" not in decode_claims_unverified(minter.token())
