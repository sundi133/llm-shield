"""Governance / access-intelligence endpoints (Phase 1 + 2).

Read-only aggregations over the registry + auth-event buffer:
- /v1/governance/agents          -> inventory (registered + shadow agents)
- /v1/governance/agents/{id}/usage -> used-vs-granted (least-privilege + drift)
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_governance as gov


REGISTERED = {
    "billing-agent": {
        "name": "Billing Agent", "status": "active",
        "tools": ["get_invoice", "send_email"],
        "role_permissions": {"admin": ["refund"]},
        "allowed_resources": ["acct/*"], "require_resource_scope": True,
        "created_at": 1, "updated_at": 2,
    },
}
UNREGISTERED = {"agents": {"mystery-bot": {"first_seen": 100, "last_seen": 200}}}
RECENT = [
    {"agent_id": "billing-agent", "tool": "get_invoice", "resource": "acct/1", "ts": 300, "event": "cap_minted"},
    {"agent_id": "billing-agent", "tool": "wire_transfer", "resource": "acct/9", "ts": 305, "event": "cap_denied"},
    {"agent_id": "mystery-bot", "tool": "scrape", "resource": "x", "ts": 310, "event": "cap_minted"},
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(gov, "get_tenant_from_api_key", lambda req: "acme")

    def fake_kv(key):
        if key == "agents:acme":
            return REGISTERED
        if key == "unregistered:acme":
            return UNREGISTERED
        return None
    monkeypatch.setattr(gov, "get_redis_data", fake_kv)
    monkeypatch.setattr(gov.stats, "get_recent", lambda t, limit=50: RECENT)

    app = FastAPI()
    app.include_router(gov.router)
    return TestClient(app)


def test_inventory_lists_registered_and_shadow(client):
    r = client.get("/v1/governance/agents")
    assert r.status_code == 200
    body = r.json()
    assert body["registered_count"] == 1
    assert body["shadow_count"] == 1
    by_id = {a["agent_id"]: a for a in body["agents"]}

    billing = by_id["billing-agent"]
    assert billing["registered"] is True
    # granted = direct tools + role_permissions union
    assert billing["granted_tools"] == ["get_invoice", "refund", "send_email"]
    assert billing["recent_tools_used"] == ["get_invoice", "wire_transfer"]
    assert billing["last_seen"] == 305

    mystery = by_id["mystery-bot"]
    assert mystery["registered"] is False
    assert mystery["status"] == "unregistered"


def test_usage_used_vs_granted(client):
    r = client.get("/v1/governance/agents/billing-agent/usage")
    assert r.status_code == 200
    u = r.json()
    assert u["registered"] is True
    assert set(u["granted_tools"]) == {"get_invoice", "refund", "send_email"}
    assert set(u["used_tools"]) == {"get_invoice", "wire_transfer"}
    # least-privilege: granted but never exercised
    assert set(u["unused_grants"]) == {"refund", "send_email"}
    # drift: used but not granted (a security signal)
    assert u["used_not_granted"] == ["wire_transfer"]
    assert u["used_resources"] == ["acct/1", "acct/9"]
    assert u["activity"] == {"cap_minted": 1, "cap_denied": 1}


def test_usage_unknown_agent_is_empty_not_error(client):
    r = client.get("/v1/governance/agents/does-not-exist/usage")
    assert r.status_code == 200
    u = r.json()
    assert u["registered"] is False
    assert u["granted_tools"] == []
    assert u["unused_grants"] == []
