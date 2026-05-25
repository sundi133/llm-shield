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
