"""Tests for portal-facing stats: event recording on each route +
the tenant-scoped /v1/tenant/me/agent-auth/* read endpoints."""

from __future__ import annotations

from typing import Iterator

import pytest
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

from api.routes_agent_auth import (
    router as agent_auth_router,
    tenant_router as agent_auth_tenant_router,
)
from core.agent_identity_middleware import AgentIdentityMiddleware
from core.agent_tokens import reset_signer_cache_for_tests
from core.capabilities import (
    clear_nonce_store_for_tests,
    reset_cap_signer_cache_for_tests,
)
from storage import agent_auth_stats as stats
from storage.revocation import clear_all_for_tests


class _FakeTenantAuthMiddleware(BaseHTTPMiddleware):
    """Sets request.state.tenant_id from the X-API-Key header (test only)."""
    async def dispatch(self, request: Request, call_next):
        key = request.headers.get("X-API-Key")
        if key:
            request.state.tenant_id = key  # use the key value as the tenant_id
        return await call_next(request)


@pytest.fixture
def app(monkeypatch) -> Iterator[FastAPI]:
    monkeypatch.setenv("SHIELD_ADMIN_KEY", "admin")
    monkeypatch.delenv("SHIELD_AGENT_TOKEN_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", raising=False)

    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()
    stats.clear_for_tests()

    from storage import tenant_store
    monkeypatch.setattr(tenant_store, "_get_redis", lambda: None)

    from core.rbac import enforcer
    monkeypatch.setattr(enforcer, "_agents", {})
    monkeypatch.setattr(enforcer, "_roles", {})

    app = FastAPI()
    # Outer (runs first): identity from X-Agent-Token
    # Inner (runs second): tenant from X-API-Key
    app.add_middleware(_FakeTenantAuthMiddleware)
    app.add_middleware(AgentIdentityMiddleware)
    app.include_router(agent_auth_router)
    app.include_router(agent_auth_tenant_router)
    yield app

    reset_signer_cache_for_tests()
    reset_cap_signer_cache_for_tests()
    clear_nonce_store_for_tests()
    clear_all_for_tests()
    stats.clear_for_tests()


@pytest.fixture
def client(app):
    return TestClient(app)


TOKEN_BODY = dict(
    user_sub="alice", agent_id="billing-bot", agent_instance_id="inst-1",
    tenant_id="t1", build_hash="b", model_version="m", session_id="s",
    ttl_seconds=300,
)


def _mint(client):
    r = client.post(
        "/v1/shield/auth/agent-token",
        headers={"X-Admin-Key": "admin"},
        json=TOKEN_BODY,
    )
    assert r.status_code == 200, r.text
    return r.json()["agent_token"]


# ── Event recording on each path ───────────────────────────────────────


class TestRecordingOnRoutes:
    def test_token_issuance_records_event(self, client):
        _mint(client)
        recent = stats.get_recent("t1")
        assert any(e["event"] == stats.EVENT_TOKEN_ISSUED for e in recent)
        totals = stats.get_counters("t1")["totals"]
        assert totals[stats.EVENT_TOKEN_ISSUED] == 1

    def test_cap_mint_records_event(self, client):
        token = _mint(client)
        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "send_email", "resource": "alice/inbox"},
        )
        assert r.status_code == 200
        totals = stats.get_counters("t1")["totals"]
        assert totals[stats.EVENT_CAP_MINTED] == 1
        # No denial happened
        assert totals[stats.EVENT_CAP_DENIED] == 0

    def test_cap_denied_records_event_with_reason(self, client, monkeypatch):
        # Configure RBAC to deny send_email for billing-bot
        from config.schema import RBACRole
        from core.rbac import enforcer
        role = RBACRole(
            name="reader", allowed_tools=["db_query"], denied_tools=["send_email"],
            allowed_data_scopes=[], denied_data_scopes=[],
            data_clearance="internal",
        )
        monkeypatch.setattr(enforcer, "_roles", {"reader": role})
        monkeypatch.setattr(enforcer, "_agents", {"billing-bot": "reader"})

        token = _mint(client)
        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "send_email", "resource": "alice/inbox"},
        )
        assert r.status_code == 403
        recent = stats.get_recent("t1")
        denial = next(e for e in recent if e["event"] == stats.EVENT_CAP_DENIED)
        assert "not permitted" in denial["reason"]
        assert denial["tool"] == "send_email"

    def test_cap_verify_records_event(self, client):
        token = _mint(client)
        cap = client.post(
            "/v1/shield/cap/mint", headers={"X-Agent-Token": token},
            json={"tool": "t", "resource": "r"},
        ).json()["cap_token"]
        client.post(
            "/v1/shield/cap/verify",
            json={"cap_token": cap, "expected_tool": "t"},
        )
        totals = stats.get_counters("t1")["totals"]
        assert totals[stats.EVENT_CAP_VERIFIED] == 1

    def test_cap_replay_records_event(self, client):
        token = _mint(client)
        cap = client.post(
            "/v1/shield/cap/mint", headers={"X-Agent-Token": token},
            json={"tool": "t", "resource": "r"},
        ).json()["cap_token"]
        # first verify succeeds
        client.post("/v1/shield/cap/verify",
                    json={"cap_token": cap, "expected_tool": "t"})
        # second is a replay
        client.post("/v1/shield/cap/verify",
                    json={"cap_token": cap, "expected_tool": "t"})
        totals = stats.get_counters("t1")["totals"]
        assert totals[stats.EVENT_CAP_VERIFIED] == 1
        assert totals[stats.EVENT_CAP_REPLAY] == 1
        replay = next(e for e in stats.get_recent("t1") if e["event"] == stats.EVENT_CAP_REPLAY)
        # tenant_id was recovered from cap claims even though verify failed
        assert "replay" in replay["reason"].lower()

    def test_cap_invalid_records_event(self, client):
        # Tampered cap with intact claims (forgery scenario) → invalid + attributable
        token = _mint(client)
        cap = client.post(
            "/v1/shield/cap/mint", headers={"X-Agent-Token": token},
            json={"tool": "t", "resource": "r"},
        ).json()["cap_token"]
        # Flip a byte in the middle of the SIGNATURE; payload stays readable
        # so we can still attribute the event to the right tenant.
        payload, sig = cap.split(".", 1)
        mid = len(sig) // 2
        flip = "X" if sig[mid] != "X" else "Y"
        bad = f"{payload}.{sig[:mid]}{flip}{sig[mid+1:]}"
        client.post("/v1/shield/cap/verify",
                    json={"cap_token": bad, "expected_tool": "t"})
        totals = stats.get_counters("t1")["totals"]
        assert totals[stats.EVENT_CAP_INVALID] == 1
        assert totals[stats.EVENT_CAP_REPLAY] == 0

    def test_revoke_records_event(self, client):
        client.post(
            "/v1/shield/auth/revoke",
            headers={"X-Admin-Key": "admin"},
            json={"agent_instance_id": "inst-1", "tenant_id": "t1"},
        )
        totals = stats.get_counters("t1")["totals"]
        assert totals[stats.EVENT_REVOKE] == 1


# ── Tenant-scoped read endpoints ──────────────────────────────────────


class TestTenantEndpoints:
    def test_stats_requires_tenant_api_key(self, client):
        r = client.get("/v1/tenant/me/agent-auth/stats")
        assert r.status_code == 401

    def test_recent_requires_tenant_api_key(self, client):
        r = client.get("/v1/tenant/me/agent-auth/recent")
        assert r.status_code == 401

    def test_stats_returns_scoped_data(self, client):
        # Generate some events for t1
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED)
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_DENIED)
        stats.record(tenant_id="t2", event=stats.EVENT_CAP_MINTED)

        r = client.get(
            "/v1/tenant/me/agent-auth/stats",
            headers={"X-API-Key": "t1"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["tenant_id"] == "t1"
        assert body["totals"][stats.EVENT_CAP_MINTED] == 1
        assert body["totals"][stats.EVENT_CAP_DENIED] == 1
        # t2's count must NOT leak in
        # (we incremented t2 by 1 but t1's count is 1)

    def test_recent_returns_scoped_events(self, client):
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED, tool="t1-tool")
        stats.record(tenant_id="t2", event=stats.EVENT_CAP_MINTED, tool="t2-tool")

        r = client.get(
            "/v1/tenant/me/agent-auth/recent",
            headers={"X-API-Key": "t1"},
        )
        assert r.status_code == 200
        events = r.json()["events"]
        tools = [e["tool"] for e in events]
        assert "t1-tool" in tools
        assert "t2-tool" not in tools

    def test_stats_days_param(self, client):
        stats.record(tenant_id="t1", event=stats.EVENT_CAP_MINTED)
        r = client.get(
            "/v1/tenant/me/agent-auth/stats?days=3",
            headers={"X-API-Key": "t1"},
        )
        assert r.status_code == 200
        assert len(r.json()["days"]) == 3

    def test_recent_limit_param(self, client):
        for _ in range(10):
            stats.record(tenant_id="t1", event=stats.EVENT_CAP_VERIFIED)
        r = client.get(
            "/v1/tenant/me/agent-auth/recent?limit=4",
            headers={"X-API-Key": "t1"},
        )
        assert len(r.json()["events"]) == 4


# ── Tenant-scoped token issuance (customer path) ──────────────────────


class TestTenantTokenIssuance:
    """Customers have a tenant API key, not the admin key. This endpoint
    is what their app/SDK calls to start the AuthN/AuthZ flow."""

    def test_requires_tenant_api_key(self, client):
        r = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            json={
                "user_sub": "alice", "agent_id": "bot", "agent_instance_id": "i1",
                "build_hash": "b", "model_version": "m", "session_id": "s",
            },
        )
        assert r.status_code == 401

    def test_tenant_can_mint_for_self(self, client):
        body = {
            "user_sub": "alice", "agent_id": "billing-bot", "agent_instance_id": "i1",
            "build_hash": "sha256:abc", "model_version": "opus", "session_id": "s1",
            "ttl_seconds": 600,
        }
        r = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "tenant-acme"},
            json=body,
        )
        assert r.status_code == 200
        token = r.json()["agent_token"]
        assert token and "." in token
        # The token must verify and carry the API key's tenant_id (not anything
        # the client provided).
        from core.agent_tokens import verify_agent_token
        identity = verify_agent_token(token)
        assert identity.tenant_id == "tenant-acme"
        assert identity.user_sub == "alice"
        assert identity.agent_id == "billing-bot"

    def test_tenant_id_not_spoofable(self, client):
        """Even if the client tries to inject tenant_id in the body, it
        must be ignored and replaced by the resolved API-key tenant."""
        body = {
            "user_sub": "alice", "agent_id": "bot", "agent_instance_id": "i1",
            "build_hash": "b", "model_version": "m", "session_id": "s",
            # An attacker tries to mint a token for someone else's tenant:
            "tenant_id": "victim-tenant",
        }
        r = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "tenant-acme"},
            json=body,
        )
        assert r.status_code == 200
        from core.agent_tokens import verify_agent_token
        identity = verify_agent_token(r.json()["agent_token"])
        assert identity.tenant_id == "tenant-acme"
        assert identity.tenant_id != "victim-tenant"

    def test_minted_token_works_with_cap_mint(self, client):
        """End-to-end: tenant mints token → uses it to mint a cap."""
        token = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "acme"},
            json={
                "user_sub": "alice", "agent_id": "bot", "agent_instance_id": "i1",
                "build_hash": "b", "model_version": "m", "session_id": "s",
            },
        ).json()["agent_token"]

        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "send_email", "resource": "alice/inbox"},
        )
        assert r.status_code == 200
        cap = r.json()["cap_token"]

        v = client.post(
            "/v1/shield/cap/verify",
            json={"cap_token": cap, "expected_tool": "send_email"},
        )
        assert v.json()["valid"] is True
        assert v.json()["claims"]["tenant_id"] == "acme"

    def test_ttl_ceiling_enforced(self, client):
        r = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "acme"},
            json={
                "user_sub": "a", "agent_id": "a", "agent_instance_id": "a",
                "build_hash": "b", "model_version": "m", "session_id": "s",
                "ttl_seconds": 100000,  # way over 15m cap
            },
        )
        assert r.status_code == 422  # pydantic validation

    def test_issuance_records_stat(self, client):
        client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "acme"},
            json={
                "user_sub": "alice", "agent_id": "bot", "agent_instance_id": "i1",
                "build_hash": "b", "model_version": "m", "session_id": "s",
            },
        )
        totals = stats.get_counters("acme")["totals"]
        assert totals[stats.EVENT_TOKEN_ISSUED] == 1


class TestRateLimiting:
    """H3 + M5 wired into the routes."""

    def test_token_issuance_rate_limited(self, client, monkeypatch):
        from core import agent_auth_safety
        monkeypatch.setattr(agent_auth_safety, "_DEFAULT_ISSUE_PER_MIN", 2)
        # Clean rate-limiter state
        from storage import rate_limiter
        rate_limiter._memory_minute.clear()

        body = {
            "user_sub": "a", "agent_id": "b", "agent_instance_id": "i",
            "build_hash": "x", "model_version": "m", "session_id": "s",
        }
        for _ in range(2):
            r = client.post(
                "/v1/tenant/me/agent-auth/agent-token",
                headers={"X-API-Key": "acme"}, json=body,
            )
            assert r.status_code == 200
        r = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "acme"}, json=body,
        )
        assert r.status_code == 429

    def test_cap_mint_rate_limited(self, client, monkeypatch):
        from core import agent_auth_safety
        monkeypatch.setattr(agent_auth_safety, "_DEFAULT_MINT_PER_MIN", 2)
        from storage import rate_limiter
        rate_limiter._memory_minute.clear()

        token = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "acme"},
            json={
                "user_sub": "a", "agent_id": "b", "agent_instance_id": "noisy-pod",
                "build_hash": "x", "model_version": "m", "session_id": "s",
            },
        ).json()["agent_token"]

        for _ in range(2):
            r = client.post(
                "/v1/shield/cap/mint",
                headers={"X-Agent-Token": token},
                json={"tool": "t", "resource": "r"},
            )
            assert r.status_code == 200
        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "t", "resource": "r"},
        )
        assert r.status_code == 429


class TestQuietDenial:
    """M3: AuthZ denial body must not leak roles/tools by default."""

    def test_default_response_hides_reasons(self, client, monkeypatch):
        # Configure RBAC so the mint is denied
        from config.schema import RBACRole
        from core.rbac import enforcer
        role = RBACRole(
            name="reader", allowed_tools=["lookup"], denied_tools=["send_email"],
            allowed_data_scopes=[], denied_data_scopes=[],
            data_clearance="internal",
        )
        monkeypatch.setattr(enforcer, "_roles", {"reader": role})
        monkeypatch.setattr(enforcer, "_agents", {"billing-bot": "reader"})
        monkeypatch.delenv("SHIELD_VERBOSE_REASONS", raising=False)

        token = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "acme"},
            json={
                "user_sub": "a", "agent_id": "billing-bot", "agent_instance_id": "i",
                "build_hash": "x", "model_version": "m", "session_id": "s",
            },
        ).json()["agent_token"]

        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "send_email", "resource": "alice/inbox"},
        )
        assert r.status_code == 403
        body = r.json()["detail"]
        assert body["error"] == "authz_denied"
        assert "request_id" in body
        # Reasons must NOT be in the response body (they're in the audit log)
        assert "reasons" not in body

    def test_verbose_mode_includes_reasons(self, client, monkeypatch):
        from config.schema import RBACRole
        from core.rbac import enforcer
        role = RBACRole(
            name="reader", allowed_tools=["lookup"], denied_tools=["send_email"],
            allowed_data_scopes=[], denied_data_scopes=[],
            data_clearance="internal",
        )
        monkeypatch.setattr(enforcer, "_roles", {"reader": role})
        monkeypatch.setattr(enforcer, "_agents", {"billing-bot": "reader"})
        monkeypatch.setenv("SHIELD_VERBOSE_REASONS", "1")

        token = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "acme"},
            json={
                "user_sub": "a", "agent_id": "billing-bot", "agent_instance_id": "i",
                "build_hash": "x", "model_version": "m", "session_id": "s",
            },
        ).json()["agent_token"]

        r = client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "send_email", "resource": "alice/inbox"},
        )
        assert r.status_code == 403
        body = r.json()["detail"]
        assert any("send_email" in reason or "not permitted" in reason
                   for reason in body["reasons"])

    def test_audit_log_always_has_full_reasons(self, client, monkeypatch):
        """Even in quiet mode, the full reasons land in the recent events
        ring buffer so operators can debug."""
        from config.schema import RBACRole
        from core.rbac import enforcer
        role = RBACRole(
            name="reader", allowed_tools=[], denied_tools=["send_email"],
            allowed_data_scopes=[], denied_data_scopes=[],
            data_clearance="internal",
        )
        monkeypatch.setattr(enforcer, "_roles", {"reader": role})
        monkeypatch.setattr(enforcer, "_agents", {"billing-bot": "reader"})
        monkeypatch.delenv("SHIELD_VERBOSE_REASONS", raising=False)

        token = client.post(
            "/v1/tenant/me/agent-auth/agent-token",
            headers={"X-API-Key": "acme"},
            json={
                "user_sub": "a", "agent_id": "billing-bot", "agent_instance_id": "i",
                "build_hash": "x", "model_version": "m", "session_id": "s",
            },
        ).json()["agent_token"]

        client.post(
            "/v1/shield/cap/mint",
            headers={"X-Agent-Token": token},
            json={"tool": "send_email", "resource": "x"},
        )
        # Quiet response, but the recent buffer still has the full reason
        denial = next(
            e for e in stats.get_recent("acme")
            if e["event"] == stats.EVENT_CAP_DENIED
        )
        assert "not permitted" in denial["reason"]
