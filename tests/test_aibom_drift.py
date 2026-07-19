"""AIBOM snapshots + drift detection (Task 3 of docs/spec-aibom.md).

POST/GET /v1/tenant/me/aibom/snapshots and GET /v1/tenant/me/aibom/drift.
Drift compares volatile-stripped BOMs, so traffic churn (last_seen,
metrics) never reads as drift — configuration changes do.
"""
import copy

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routes_aibom as aibom_api
import storage.aibom as aibom


REGISTERED = {
    "billing-agent": {
        "name": "Billing Agent", "status": "active",
        "tools": ["get_invoice"], "role_permissions": {},
        "created_at": 1, "updated_at": 2,
    },
}
RECENT = [{"agent_id": "billing-agent", "tool": "get_invoice", "ts": 300, "event": "cap_minted"}]
CONFIG = {
    "name": "Acme App",
    "input_guardrails": {"prompt_injection": {"enabled": True}},
    "output_guardrails": {},
    "rbac": {"roles": {"admin": {}}},
}


@pytest.fixture
def env(monkeypatch):
    kv = {"agents:acme": copy.deepcopy(REGISTERED)}
    cfg = {"acme": copy.deepcopy(CONFIG)}
    recent = {"events": list(RECENT)}
    webhook_calls = []

    monkeypatch.setattr(aibom_api, "get_tenant_from_api_key", lambda req: "acme")
    monkeypatch.setattr(aibom_api, "log_admin_action", lambda **kw: None)
    monkeypatch.setattr(aibom, "kv_get", lambda k: copy.deepcopy(kv.get(k)))
    monkeypatch.setattr(aibom, "get_tenant", lambda t: copy.deepcopy(cfg.get(t)))

    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "kv_set", lambda k, v: kv.__setitem__(k, copy.deepcopy(v)))

    import storage.agent_auth_stats as stats
    monkeypatch.setattr(stats, "get_recent", lambda t, limit=50: list(recent["events"]))

    import core.webhook_dispatcher as wd

    def fake_dispatch(tenant_id, event_type, payload):
        webhook_calls.append({"tenant_id": tenant_id, "event": event_type, "payload": payload})
        async def _noop():
            return None
        return _noop()

    monkeypatch.setattr(wd, "dispatch_event", fake_dispatch)
    return {"kv": kv, "cfg": cfg, "recent": recent, "webhooks": webhook_calls}


@pytest.fixture
def client(env):
    app = FastAPI()
    app.include_router(aibom_api.router)
    return TestClient(app)


def test_snapshot_strips_volatile_fields(client):
    entry = client.post("/v1/tenant/me/aibom/snapshots",
                        json={"approved_by": "alice", "note": "baseline"}).json()
    assert entry["snapshot_id"].startswith("bom-")
    assert entry["approved_by"] == "alice"

    listed = client.get("/v1/tenant/me/aibom/snapshots").json()["snapshots"]
    assert [s["snapshot_id"] for s in listed] == [entry["snapshot_id"]]

    snap = client.get(f"/v1/tenant/me/aibom/snapshots/{entry['snapshot_id']}").json()
    bom = snap["bom"]
    for volatile in ("generation_notes", "observability", "view"):
        assert volatile not in bom
    assert "generated_at" not in bom["metadata"]
    agent = bom["agents"][0]
    for volatile in ("last_seen", "recent_tools_used", "created_at", "updated_at"):
        assert volatile not in agent

    assert client.get("/v1/tenant/me/aibom/snapshots/bom-nope").status_code == 404


def test_drift_requires_snapshot(client):
    r = client.get("/v1/tenant/me/aibom/drift")
    assert r.status_code == 404
    assert "POST /v1/tenant/me/aibom/snapshots" in r.json()["detail"]
    client.post("/v1/tenant/me/aibom/snapshots", json={})
    assert client.get("/v1/tenant/me/aibom/drift?snapshot_id=bom-nope").status_code == 404


def test_traffic_churn_is_not_drift(client, env):
    client.post("/v1/tenant/me/aibom/snapshots", json={})
    # new activity + a registry timestamp touch: volatile, must stay clean
    env["recent"]["events"].append(
        {"agent_id": "billing-agent", "tool": "get_invoice", "ts": 999, "event": "cap_minted"})
    env["kv"]["agents:acme"]["billing-agent"]["updated_at"] = 99
    report = client.get("/v1/tenant/me/aibom/drift").json()
    assert report["clean"] is True and report["drift_count"] == 0
    assert env["webhooks"] == []  # clean -> no webhook


def test_config_changes_are_drift(client, env):
    client.post("/v1/tenant/me/aibom/snapshots", json={})

    env["kv"]["agents:acme"]["billing-agent"]["tools"] = ["get_invoice", "wire_transfer"]
    env["kv"]["unregistered:acme"] = {"agents": {"rogue-bot": {"first_seen": 1}}}
    env["cfg"]["acme"]["input_guardrails"]["prompt_injection"]["enabled"] = False
    client.put("/v1/tenant/me/aibom/components/models",
               json={"components": {"gpt-5": {"provider": "openai"}}})

    report = client.get("/v1/tenant/me/aibom/drift").json()
    assert report["clean"] is False

    agents = report["drift"]["agents"]
    assert agents["added"] == ["rogue-bot"]
    assert {"key": "billing-agent", "field": "allowed_tools",
            "before": ["get_invoice"],
            "after": ["get_invoice", "wire_transfer"]} in agents["changed"]
    assert report["drift"]["guardrails"]["changed"] == [
        {"key": "input:prompt_injection", "field": "enabled", "before": True, "after": False}]
    assert report["drift"]["models"]["added"] == ["gpt-5"]
    assert report["drift_count"] == 4

    hook = env["webhooks"][0]
    assert hook["event"] == "aibom_drift_detected"
    assert hook["payload"]["drift_count"] == 4
    assert set(hook["payload"]["sections"]) == {"agents", "guardrails", "models"}
    assert "bom" not in hook["payload"]  # summary only, never the full BOM


def test_identity_changes_are_drift(client, env):
    client.post("/v1/tenant/me/aibom/snapshots", json={})
    env["cfg"]["acme"]["rbac"]["roles"]["auditor"] = {}
    report = client.get("/v1/tenant/me/aibom/drift").json()
    assert report["drift"]["identity"]["changed"] == [
        {"key": "identity", "field": "rbac_roles", "before": ["admin"], "after": ["admin", "auditor"]}]


def test_snapshot_index_evicts_oldest(client, monkeypatch):
    monkeypatch.setattr(aibom, "MAX_SNAPSHOTS", 2)
    ids = [client.post("/v1/tenant/me/aibom/snapshots", json={}).json()["snapshot_id"]
           for _ in range(3)]
    listed = [s["snapshot_id"] for s in client.get("/v1/tenant/me/aibom/snapshots").json()["snapshots"]]
    assert listed == ids[1:]
    assert client.get(f"/v1/tenant/me/aibom/snapshots/{ids[0]}").status_code == 404


def test_snapshot_size_cap(client, monkeypatch):
    monkeypatch.setattr(aibom, "MAX_SNAPSHOT_BYTES", 10)
    r = client.post("/v1/tenant/me/aibom/snapshots", json={})
    assert r.status_code == 422
    assert "max 10" in r.json()["detail"]


def test_snapshot_keys_are_tenant_scoped(client, env):
    client.post("/v1/tenant/me/aibom/snapshots", json={})
    snap_keys = [k for k in env["kv"] if k.startswith("aibom:")]
    assert snap_keys and all(":acme" in k for k in snap_keys)
