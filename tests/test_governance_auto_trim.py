"""Auto-trim unused permissions (governance Phase 4).

Spec: docs/specs/governance-auto-trim.md
Modes: suggest (default, no writes) | approve (pending → human apply) | auto
(guarded immediate apply). Candidates are ONLY unused grants; restore is an
additive union so it can't clobber unrelated edits.
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
        "role_permissions": {"admin": ["refund", "send_email"]},
        "allowed_resources": ["acct/*"], "require_resource_scope": True,
        "created_at": 1, "updated_at": 2,
    },
    "exempt-agent": {
        "name": "Exempt", "status": "active", "trim_exempt": True,
        "tools": ["never_used_tool"], "role_permissions": {},
    },
}
# billing-agent used get_invoice only → unused grants: refund, send_email
RECENT = [
    {"agent_id": "billing-agent", "tool": "get_invoice", "resource": "acct/1",
     "ts": 300, "event": "cap_minted"},
    {"agent_id": "billing-agent", "tool": "get_invoice", "resource": "acct/2",
     "ts": 305, "event": "cap_verified"},
]


@pytest.fixture
def store(monkeypatch):
    kv = {"agents:acme": copy.deepcopy(REGISTERED)}
    monkeypatch.setattr(gov, "get_tenant_from_api_key", lambda req: "acme")
    monkeypatch.setattr(gov, "get_redis_data", lambda k: kv.get(k))
    monkeypatch.setattr(gov, "kv_get", lambda k: kv.get(k))
    monkeypatch.setattr(gov, "kv_set", lambda k, v: kv.__setitem__(k, v))
    monkeypatch.setattr(gov, "_save_agents",
                        lambda t, agents: kv.__setitem__(f"agents:{t}", agents))
    monkeypatch.setattr(gov.stats, "get_recent", lambda t, limit=50: list(RECENT))
    monkeypatch.delenv("SHIELD_GOVERNANCE_AUTO_TRIM", raising=False)
    monkeypatch.delenv("SHIELD_TRIM_MIN_EVENTS", raising=False)
    return kv


@pytest.fixture
def client(store):
    app = FastAPI()
    app.include_router(gov.router)
    return TestClient(app)


def _granted(kv, agent="billing-agent"):
    e = kv["agents:acme"][agent]
    out = set(e.get("tools") or [])
    for perms in (e.get("role_permissions") or {}).values():
        out.update(perms or [])
    return out


# ── proposal + suggest (default) ─────────────────────────────────────────


def test_proposal_reads_evidence(client):
    r = client.get("/v1/governance/agents/billing-agent/trim-proposal")
    assert r.status_code == 200
    p = r.json()["proposal"]
    assert p["unused_grants"] == ["refund", "send_email"]
    assert p["used_tools"] == ["get_invoice"]
    assert p["events_seen"] == 2
    assert r.json()["mode"] == "suggest"


def test_suggest_is_default_and_writes_nothing(client, store):
    before = copy.deepcopy(store["agents:acme"])
    r = client.post("/v1/governance/agents/billing-agent/trim")
    assert r.status_code == 200
    body = r.json()
    assert body["mode"] == "suggest" and body["applied"] is False
    assert store["agents:acme"] == before          # no registry write
    assert "governance:trims:acme" not in store    # no record write


def test_unknown_agent_post_404(client):
    assert client.post("/v1/governance/agents/ghost/trim").status_code == 404


def test_exempt_agent_409(client, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "auto")
    assert client.post("/v1/governance/agents/exempt-agent/trim").status_code == 409


def test_non_subset_tools_400(client, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "auto")
    # get_invoice is USED — trimming it must be refused
    r = client.post("/v1/governance/agents/billing-agent/trim",
                    json={"tools": ["get_invoice"]})
    assert r.status_code == 400
    r2 = client.post("/v1/governance/agents/billing-agent/trim",
                     json={"tools": ["not-granted-at-all"]})
    assert r2.status_code == 400


# ── approve mode ─────────────────────────────────────────────────────────


def test_approve_mode_queues_then_applies(client, store, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "approve")
    r = client.post("/v1/governance/agents/billing-agent/trim",
                    json={"reviewer": "sai"})
    assert r.status_code == 200
    trim = r.json()["trim"]
    assert trim["status"] == "pending" and r.json()["applied"] is False
    assert _granted(store) == {"get_invoice", "send_email", "refund"}  # untouched

    r2 = client.post(f"/v1/governance/trims/{trim['trim_id']}/approve")
    assert r2.status_code == 200
    applied = r2.json()["trim"]
    assert applied["status"] == "applied"
    # both containers narrowed: direct tools AND role_permissions
    assert applied["removed"]["tools"] == ["send_email"]
    assert applied["removed"]["role_permissions"] == {"admin": ["refund", "send_email"]}
    assert _granted(store) == {"get_invoice"}
    # index status flipped
    idx = store["governance:trims:acme"]["trims"]
    assert idx[0]["status"] == "applied"

    # idempotent second approve
    r3 = client.post(f"/v1/governance/trims/{trim['trim_id']}/approve")
    assert r3.status_code == 200 and r3.json()["already_applied"] is True


def test_approve_revalidates_now_used_tools(client, store, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "approve")
    trim = client.post("/v1/governance/agents/billing-agent/trim").json()["trim"]
    # send_email gets used AFTER the proposal snapshot
    monkeypatch.setattr(gov.stats, "get_recent", lambda t, limit=50: list(RECENT) + [
        {"agent_id": "billing-agent", "tool": "send_email", "resource": "u/1",
         "ts": 400, "event": "cap_minted"},
    ])
    r = client.post(f"/v1/governance/trims/{trim['trim_id']}/approve")
    assert r.status_code == 200
    assert r.json()["skipped_now_used"] == ["send_email"]
    assert _granted(store) == {"get_invoice", "send_email"}  # only refund trimmed


# ── auto mode ────────────────────────────────────────────────────────────


def test_auto_applies_when_threshold_met(client, store, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "auto")
    monkeypatch.setenv("SHIELD_TRIM_MIN_EVENTS", "2")   # events_seen == 2
    r = client.post("/v1/governance/agents/billing-agent/trim")
    assert r.status_code == 200
    assert r.json()["applied"] is True
    assert r.json()["trim"]["threshold_met"] is True
    assert _granted(store) == {"get_invoice"}


def test_auto_insufficient_observation_409(client, store, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "auto")
    monkeypatch.setenv("SHIELD_TRIM_MIN_EVENTS", "50")
    before = copy.deepcopy(store["agents:acme"])
    r = client.post("/v1/governance/agents/billing-agent/trim")
    assert r.status_code == 409
    assert "insufficient observation" in r.json()["detail"]
    assert store["agents:acme"] == before


def test_auto_subset_only_trims_requested(client, store, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "auto")
    monkeypatch.setenv("SHIELD_TRIM_MIN_EVENTS", "1")
    r = client.post("/v1/governance/agents/billing-agent/trim",
                    json={"tools": ["refund"]})
    assert r.status_code == 200 and r.json()["applied"] is True
    assert _granted(store) == {"get_invoice", "send_email"}


# ── restore (undo) ───────────────────────────────────────────────────────


def test_restore_returns_grants_to_both_containers(client, store, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "auto")
    monkeypatch.setenv("SHIELD_TRIM_MIN_EVENTS", "1")
    trim = client.post("/v1/governance/agents/billing-agent/trim").json()["trim"]
    assert _granted(store) == {"get_invoice"}

    r = client.post(f"/v1/governance/trims/{trim['trim_id']}/restore")
    assert r.status_code == 200
    assert r.json()["trim"]["status"] == "restored"
    e = store["agents:acme"]["billing-agent"]
    assert set(e["tools"]) == {"get_invoice", "send_email"}
    assert set(e["role_permissions"]["admin"]) == {"refund", "send_email"}

    # restore of a non-applied record → 409
    assert client.post(f"/v1/governance/trims/{trim['trim_id']}/restore").status_code == 409


def test_restore_is_additive_union_not_overwrite(client, store, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "auto")
    monkeypatch.setenv("SHIELD_TRIM_MIN_EVENTS", "1")
    trim = client.post("/v1/governance/agents/billing-agent/trim").json()["trim"]
    # a concurrent manual edit adds a new tool after the trim
    store["agents:acme"]["billing-agent"]["tools"].append("new_tool")
    client.post(f"/v1/governance/trims/{trim['trim_id']}/restore")
    e = store["agents:acme"]["billing-agent"]
    assert "new_tool" in e["tools"]  # not clobbered by the restore


# ── record listing + edge cases ──────────────────────────────────────────


def test_trims_listing_and_get(client, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "approve")
    trim = client.post("/v1/governance/agents/billing-agent/trim").json()["trim"]
    lst = client.get("/v1/governance/trims").json()["trims"]
    assert [t["trim_id"] for t in lst] == [trim["trim_id"]]
    got = client.get(f"/v1/governance/trims/{trim['trim_id']}").json()["trim"]
    assert got["evidence"]["unused_grants"] == ["refund", "send_email"]
    assert client.get("/v1/governance/trims/nope").status_code == 404


def test_nothing_to_trim_noop(client, store, monkeypatch):
    monkeypatch.setenv("SHIELD_GOVERNANCE_AUTO_TRIM", "auto")
    # make every grant used
    monkeypatch.setattr(gov.stats, "get_recent", lambda t, limit=50: [
        {"agent_id": "billing-agent", "tool": t_, "resource": "r", "ts": 1,
         "event": "cap_minted"}
        for t_ in ("get_invoice", "send_email", "refund")
    ])
    r = client.post("/v1/governance/agents/billing-agent/trim")
    assert r.status_code == 200
    assert r.json()["applied"] is False
    assert r.json()["reason"] == "nothing to trim"


def test_mode_parsing_defaults():
    assert gov._trim_mode() == "suggest"
    import os
    os.environ["SHIELD_GOVERNANCE_AUTO_TRIM"] = "bogus"
    try:
        assert gov._trim_mode() == "suggest"
    finally:
        del os.environ["SHIELD_GOVERNANCE_AUTO_TRIM"]
