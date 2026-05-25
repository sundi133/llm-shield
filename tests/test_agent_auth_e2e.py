"""End-to-end: token exchange → cap mint → cap verify → revocation.

Exercises the full AuthN + AuthZ flow through the FastAPI app, including
the middleware that attaches IdentityTuple to request.state.
"""

from __future__ import annotations

import os
from typing import Iterator

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from core.agent_identity_middleware import AgentIdentityMiddleware
from core.agent_tokens import reset_signer_cache_for_tests
from core.capabilities import (
    clear_nonce_store_for_tests,
    reset_cap_signer_cache_for_tests,
)
from api.routes_agent_auth import router as agent_auth_router
from storage.revocation import clear_all_for_tests


@pytest.fixture
def app(monkeypatch) -> Iterator[FastAPI]:
    """Minimal FastAPI app with only the agent-auth pieces wired in.

    Avoids loading the full ShieldConfig / RBAC / pipeline, so tests are
    isolated and don't need a real config.
    """
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "test-admin")
    monkeypatch.delenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("SHIELD_AGENT_ALLOWED_BUILDS", raising=False)

    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()

    # Force fallback store (no Redis) for deterministic tests
    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)

    # Reset RBAC enforcer so unknown agents pass through (no roles configured)
    from core.rbac import enforcer
    monkeypatch.setattr(enforcer, "_agents", {})
    monkeypatch.setattr(enforcer, "_roles", {})

    app = FastAPI()
    app.add_middleware(AgentIdentityMiddleware)
    app.include_router(agent_auth_router)
    yield app

    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()


@pytest.fixture
def client(app):
    return TestClient(app)


VALID_TOKEN_BODY = dict(
    user_sub="user-42",
    agent_id="billing-bot",
    agent_instance_id="inst-1",
    tenant_id="t1",
    build_hash="sha256:abc",
    model_version="claude-opus-4.7",
    session_id="sess-1",
    ttl_seconds=300,
)


def _mint(client):
    """Helper: get an agent_token for the standard test identity."""
    r = client.post(
        "/v1/shield/auth/agent-token",
        headers={"X-Admin-Key": "test-admin"},
        json=VALID_TOKEN_BODY,
    )
    assert r.status_code == 200, r.text
    return r.json()["agent_token"]


class TestAgentTokenIssuance:
    def test_issue_requires_admin_key(self, client):
        r = client.post("/v1/shield/auth/agent-token", json=VALID_TOKEN_BODY)
        assert r.status_code == 403

    def test_wrong_admin_key_rejected(self, client):
        r = client.post(
            "/v1/shield/auth/agent-token",
            headers={"X-Admin-Key": "wrong"},
            json=VALID_TOKEN_BODY,
        )
        assert r.status_code == 403

    def test_admin_key_issues_token(self, client):
        token = _mint(client)
        assert isinstance(token, str)
        assert "." in token


class TestCapMint:
    def test_cap_mint_requires_agent_token(self, client):
        r = client.post(
            "/v1/shield/cap/mint",
            json={"tool": "send_email", "resource": "user/1/inbox"},
        )
        assert r.status_code == 401

    def test_cap_mint_rejects_bogus_agent_token(self, client):
        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": "not-a-real-token"},
            json={"tool": "send_email", "resource": "user/1/inbox"},
        )
        assert r.status_code == 401

    def test_happy_path_mint_then_verify(self, client):
        token = _mint(client)
        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={
                "tool": "send_email",
                "resource": "user/1/inbox",
                "clearance_max": "public",
                "ttl_seconds": 30,
            },
        )
        assert r.status_code == 200, r.text
        cap = r.json()["cap_token"]

        # Tool server side: verify the cap
        v = client.post(
            "/v1/shield/cap/verify",
            json={"cap_token": cap, "expected_tool": "send_email"},
        )
        assert v.status_code == 200
        body = v.json()
        assert body["valid"] is True
        assert body["claims"]["user_sub"] == "user-42"
        assert body["claims"]["agent_id"] == "billing-bot"
        assert body["claims"]["tool"] == "send_email"
        assert body["claims"]["tenant_id"] == "t1"

    def test_cap_verify_rejects_replay(self, client):
        token = _mint(client)
        cap = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "t", "resource": "r"},
        ).json()["cap_token"]

        # First verify burns the nonce
        r1 = client.post(
            "/v1/shield/cap/verify",
            json={"cap_token": cap, "expected_tool": "t"},
        )
        assert r1.json()["valid"] is True
        # Second verify is a replay
        r2 = client.post(
            "/v1/shield/cap/verify",
            json={"cap_token": cap, "expected_tool": "t"},
        )
        assert r2.json()["valid"] is False
        assert "replay" in r2.json()["error"]

    def test_cap_verify_rejects_wrong_tool(self, client):
        token = _mint(client)
        cap = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "db_query", "resource": "orders"},
        ).json()["cap_token"]

        r = client.post(
            "/v1/shield/cap/verify",
            json={"cap_token": cap, "expected_tool": "send_email"},
        )
        assert r.json()["valid"] is False
        assert "tool mismatch" in r.json()["error"]


class TestRBACDecision:
    def test_authz_denies_when_role_lacks_tool(self, client, monkeypatch):
        # Configure RBAC: role 'agent' has only db_query, denied send_email
        from config.schema import RBACRole
        from core.rbac import enforcer
        role = RBACRole(
            name="reader",
            allowed_tools=["db_query"],
            denied_tools=["send_email"],
            allowed_data_scopes=[],
            denied_data_scopes=[],
            data_clearance="internal",
        )
        monkeypatch.setattr(enforcer, "_roles", {"reader": role})
        monkeypatch.setattr(enforcer, "_agents", {"billing-bot": "reader"})

        token = _mint(client)
        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "send_email", "resource": "user/1/inbox"},
        )
        assert r.status_code == 403
        body = r.json()["detail"]
        assert body["error"] == "authz_denied"
        assert any("send_email" in reason for reason in body["reasons"])

    def test_authz_blocks_clearance_escalation(self, client, monkeypatch):
        from config.schema import RBACRole
        from core.rbac import enforcer
        role = RBACRole(
            name="reader",
            allowed_tools=[],
            denied_tools=[],
            allowed_data_scopes=[],
            denied_data_scopes=[],
            data_clearance="internal",  # value=1
        )
        monkeypatch.setattr(enforcer, "_roles", {"reader": role})
        monkeypatch.setattr(enforcer, "_agents", {"billing-bot": "reader"})

        token = _mint(client)
        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={
                "tool": "db_query",
                "resource": "orders",
                "clearance_max": "restricted",  # value=3, exceeds role
            },
        )
        assert r.status_code == 403
        reasons = r.json()["detail"]["reasons"]
        assert any("clearance" in r for r in reasons)


class TestRevocation:
    def test_revoke_instance_breaks_future_minting(self, client):
        token = _mint(client)

        # Revoke the instance
        r = client.post(
            "/v1/shield/auth/revoke",
            headers={"X-Admin-Key": "test-admin"},
            json={"agent_instance_id": "inst-1"},
        )
        assert r.status_code == 200

        # Now the agent token is rejected at the middleware
        r2 = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "t", "resource": "r"},
        )
        assert r2.status_code == 401

    def test_revoke_requires_admin(self, client):
        r = client.post(
            "/v1/shield/auth/revoke",
            json={"agent_instance_id": "inst-x"},
        )
        assert r.status_code == 403

    def test_revoke_user_kills_everything_for_that_user(self, client):
        token = _mint(client)
        client.post(
            "/v1/shield/auth/revoke",
            headers={"X-Admin-Key": "test-admin"},
            json={"user_sub": "user-42"},
        )
        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "t", "resource": "r"},
        )
        assert r.status_code == 401
