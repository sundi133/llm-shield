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

import logging
import time
from typing import Iterator

import pytest
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

from api.routes_agent_auth import (router as agent_auth_router,
                                   tenant_router as agent_auth_tenant_router)
from core.agent_identity_middleware import AgentIdentityMiddleware
from core.agent_tokens import (TokenError, decode_claims_unverified,
                               max_delegation_depth,
                               reset_signer_cache_for_tests,
                               verify_agent_token,
                               warn_if_depth_limit_is_unenforceable)
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


# ── Provenance: the parent link must be proven ───────────────────────────


@pytest.fixture
def proof(monkeypatch):
    monkeypatch.setenv("SHIELD_DELEGATION_PARENT_PROOF", "required")
    return monkeypatch


def _foreign_token(client, tenant="other-tenant"):
    """A perfectly valid token belonging to a DIFFERENT tenant."""
    r = client.post("/v1/shield/auth/agent-token",
                    headers={"X-Admin-Key": "admin"},
                    json=dict(user_sub="mallory", agent_id="billing-bot",
                              agent_instance_id="inst-x", tenant_id=tenant,
                              build_hash="b", model_version="m",
                              session_id="s", ttl_seconds=300))
    assert r.status_code == 200, r.text
    return r.json()["agent_token"]


def test_body_parent_is_ignored_without_proof(minter, proof):
    """An unproven parent is not a parent. The body's claim is dropped rather
    than honoured, so the audit cannot be poisoned with a fictional lineage."""
    token = minter.token(parent_agent_id="some-agent-i-do-not-control")
    claims = decode_claims_unverified(token)
    assert claims.get("parent_agent_id") is None
    assert "delegation_depth" not in claims


def test_parent_comes_from_the_verified_token_not_the_body(minter, proof):
    """Send a body value that disagrees with the token. The token wins."""
    root = minter.token()
    child = minter.token(parent_agent_token=root,
                         parent_agent_id="a-different-agent-entirely")
    claims = decode_claims_unverified(child)
    assert claims["parent_agent_id"] == "billing-bot"
    assert claims["delegation_depth"] == 1


def test_garbage_parent_token_is_refused(minter, proof):
    assert minter.post(parent_agent_token="not-a-token").status_code == 400


def test_expired_parent_token_is_refused(minter, proof):
    from unittest.mock import patch as _patch

    root = minter.token()
    with _patch("core.agent_tokens.time.time", return_value=time.time() + 100000):
        assert minter.post(parent_agent_token=root).status_code == 400


def test_revoked_parent_instance_is_refused(minter, proof):
    from storage.revocation import revoke_instance

    root = minter.token()
    revoke_instance("inst-1", ttl=600)
    assert minter.post(parent_agent_token=root).status_code == 400


def test_cross_tenant_parent_is_refused(minter, proof, client):
    """A token valid for another tenant is still a perfectly valid token.
    Without an explicit check the naive implementation accepts it and lets
    tenant A seed a delegation chain inside tenant B."""
    foreign = _foreign_token(client)
    r = minter.post(parent_agent_token=foreign)
    assert r.status_code == 403
    assert "different tenant" in r.json()["detail"]


# ── Depth ────────────────────────────────────────────────────────────────


def test_depth_increments_along_the_chain(minter, proof):
    root = minter.token()
    child = minter.token(parent_agent_token=root)
    grandchild = minter.token(parent_agent_token=child)
    assert decode_claims_unverified(child)["delegation_depth"] == 1
    assert decode_claims_unverified(grandchild)["delegation_depth"] == 2


def test_identity_carries_the_depth(minter, proof):
    root = minter.token()
    child = minter.token(parent_agent_token=root)
    assert verify_agent_token(root).delegation_depth == 0
    assert verify_agent_token(child).delegation_depth == 1


def test_limit_one_allows_a_child_but_not_a_grandchild(minter, proof):
    proof.setenv("SHIELD_MAX_DELEGATION_DEPTH", "1")
    root = minter.token()
    child = minter.token(parent_agent_token=root)
    r = minter.post(parent_agent_token=child)
    assert r.status_code == 403
    assert "exceeds limit" in r.json()["detail"]


def test_limit_zero_refuses_any_delegation(minter, proof):
    proof.setenv("SHIELD_MAX_DELEGATION_DEPTH", "0")
    root = minter.token()
    assert minter.post(parent_agent_token=root).status_code == 403


def test_unset_limit_allows_a_long_chain(minter, proof):
    token = minter.token()
    for _ in range(5):
        token = minter.token(parent_agent_token=token)
    assert decode_claims_unverified(token)["delegation_depth"] == 5


def test_lowering_the_limit_invalidates_deeper_tokens(minter, proof):
    """Checked at verify as well as at mint, so lowering the ceiling takes
    effect immediately rather than waiting out every issued token's TTL."""
    token = minter.token()
    for _ in range(3):
        token = minter.token(parent_agent_token=token)

    verify_agent_token(token)          # fine while unlimited
    proof.setenv("SHIELD_MAX_DELEGATION_DEPTH", "2")
    with pytest.raises(TokenError, match="exceeds limit"):
        verify_agent_token(token)


def test_a_legacy_token_without_the_claim_is_depth_zero(minter, proof):
    """Old tokens predate the claim. Absent IS zero, and must stay valid under
    any limit."""
    proof.setenv("SHIELD_MAX_DELEGATION_DEPTH", "0")
    assert verify_agent_token(minter.token()).delegation_depth == 0


# ── Configuration hygiene ────────────────────────────────────────────────


@pytest.mark.parametrize("value", ["-1", "abc", "1.5", ""])
def test_bad_limits_are_treated_as_unset(monkeypatch, value):
    """A typo must not become an outage: misreading '-1' as 'no delegation at
    all' would refuse every chain."""
    monkeypatch.setenv("SHIELD_MAX_DELEGATION_DEPTH", value)
    assert max_delegation_depth() is None


def test_valid_limit_is_read(monkeypatch):
    monkeypatch.setenv("SHIELD_MAX_DELEGATION_DEPTH", "3")
    assert max_delegation_depth() == 3


def test_depth_limit_without_parent_proof_warns(monkeypatch, caplog):
    """The limit is computed from a caller-asserted parent, so it bounds
    nothing. An operator who believes they have a limit and does not is worse
    off than one who knows they have none."""
    monkeypatch.delenv("SHIELD_DELEGATION_PARENT_PROOF", raising=False)
    monkeypatch.setenv("SHIELD_MAX_DELEGATION_DEPTH", "2")
    with caplog.at_level(logging.WARNING):
        assert warn_if_depth_limit_is_unenforceable() is True
    assert "NOT" in caplog.text and "enforceable" in caplog.text


def test_no_warning_when_the_limit_is_enforceable(monkeypatch):
    monkeypatch.setenv("SHIELD_DELEGATION_PARENT_PROOF", "required")
    monkeypatch.setenv("SHIELD_MAX_DELEGATION_DEPTH", "2")
    assert warn_if_depth_limit_is_unenforceable() is False


def test_no_warning_when_no_limit_is_set(monkeypatch):
    monkeypatch.delenv("SHIELD_MAX_DELEGATION_DEPTH", raising=False)
    assert warn_if_depth_limit_is_unenforceable() is False
