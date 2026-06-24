"""Governance / access-intelligence endpoints (Phase 1 + 2).

Read-only aggregations over the registry + auth-event buffer:
- /v1/governance/agents          -> inventory (registered + shadow agents)
- /v1/governance/agents/{id}/usage -> used-vs-granted (least-privilege + drift)
"""
import copy

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
def store(monkeypatch):
    # one in-memory KV backing both reads (get_redis_data/kv_get) and writes
    kv = {"agents:acme": copy.deepcopy(REGISTERED), "unregistered:acme": copy.deepcopy(UNREGISTERED)}
    monkeypatch.setattr(gov, "get_tenant_from_api_key", lambda req: "acme")
    monkeypatch.setattr(gov, "get_redis_data", lambda k: kv.get(k))
    monkeypatch.setattr(gov, "kv_get", lambda k: kv.get(k))
    monkeypatch.setattr(gov, "kv_set", lambda k, v: kv.__setitem__(k, v))
    monkeypatch.setattr(gov, "_save_agents", lambda t, agents: kv.__setitem__(f"agents:{t}", agents))
    monkeypatch.setattr(gov.stats, "get_recent", lambda t, limit=50: RECENT)
    return kv


@pytest.fixture
def client(store):
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


# ── Phase 3 — review campaigns ──────────────────────────────────────────
def test_create_review_snapshots_with_recommendations(client):
    r = client.post("/v1/governance/reviews", json={"name": "Q3 cert"})
    assert r.status_code == 200
    c = r.json()["campaign"]
    assert c["status"] == "open"
    billing = next(i for i in c["items"] if i["agent_id"] == "billing-agent")
    recs = {t["tool"]: t["recommendation"] for t in billing["tools"]}
    # used → keep; unused grants → revoke; used-but-not-granted → investigate
    assert recs["get_invoice"] == "keep"
    assert recs["send_email"] == "revoke"
    assert recs["refund"] == "revoke"
    assert recs["wire_transfer"] == "investigate"
    # progress excludes the informational 'investigate' row (3 decidable tools)
    assert c["progress"]["total"] == 3 and c["progress"]["decided"] == 0


def test_decide_then_close_applies_revokes(client, store):
    cid = client.post("/v1/governance/reviews", json={"name": "cert"}).json()["campaign"]["campaign_id"]
    # certify: keep get_invoice, revoke send_email + refund
    client.post(f"/v1/governance/reviews/{cid}/decisions", json={"decisions": [
        {"agent_id": "billing-agent", "tool": "get_invoice", "decision": "keep"},
        {"agent_id": "billing-agent", "tool": "send_email", "decision": "revoke"},
        {"agent_id": "billing-agent", "tool": "refund", "decision": "revoke"},
    ]})
    close = client.post(f"/v1/governance/reviews/{cid}/close")
    assert close.status_code == 200
    actions = {(a["agent_id"], a["tool"]): a["action"] for a in close.json()["applied_actions"]}
    assert actions[("billing-agent", "send_email")] == "revoked"
    assert actions[("billing-agent", "refund")] == "revoked"
    # registry actually mutated
    entry = store["agents:acme"]["billing-agent"]
    assert "send_email" not in entry["tools"]
    assert entry["role_permissions"]["admin"] == []  # refund removed
    assert "get_invoice" in entry["tools"]            # kept


def test_close_is_idempotent(client):
    cid = client.post("/v1/governance/reviews", json={}).json()["campaign"]["campaign_id"]
    client.post(f"/v1/governance/reviews/{cid}/close")
    again = client.post(f"/v1/governance/reviews/{cid}/close")
    assert again.status_code == 200
    assert again.json().get("already_closed") is True


def test_decisions_on_closed_campaign_rejected(client):
    cid = client.post("/v1/governance/reviews", json={}).json()["campaign"]["campaign_id"]
    client.post(f"/v1/governance/reviews/{cid}/close")
    r = client.post(f"/v1/governance/reviews/{cid}/decisions", json={"decisions": []})
    assert r.status_code == 409


def test_list_and_get_review(client):
    cid = client.post("/v1/governance/reviews", json={"name": "listme"}).json()["campaign"]["campaign_id"]
    lst = client.get("/v1/governance/reviews").json()["campaigns"]
    assert any(c["campaign_id"] == cid for c in lst)
    got = client.get(f"/v1/governance/reviews/{cid}")
    assert got.status_code == 200 and got.json()["campaign"]["campaign_id"] == cid
    assert client.get("/v1/governance/reviews/nope").status_code == 404
