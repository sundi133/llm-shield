"""Embodied action guard, task 2: action profile store, API and robot binding.
Spec: docs/specs/embodied-action-guard.md §5.1, §7."""

import copy
import json
import os
import uuid
from unittest.mock import patch

import pytest

from core.embodied import store as em_store

BASE = "/v1/tenant/me/embodied-profiles"
PROFILE = json.load(open(os.path.join(os.path.dirname(__file__), "..", "embodied-bench",
                                      "shield_profile.json")))


@pytest.fixture(autouse=True)
def _clean():
    em_store.reset_memory()
    yield
    em_store.reset_memory()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant
    tid = "em" + uuid.uuid4().hex[:10]
    key = "sk-em-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    return c


def test_crud_and_history(client):
    assert client.get(BASE).json()["profiles"] == {}
    r = client.put(f"{BASE}/hospital", json=PROFILE)
    assert r.status_code == 200, r.text
    h1 = r.json()["hash"]
    got = client.get(f"{BASE}/hospital").json()
    assert got["hash"] == h1 and got["profile"]["actions"]["navigate"] == {"class": "motion"}
    listed = client.get(BASE).json()["profiles"]["hospital"]
    assert listed["hash"] == h1 and listed["actions"] == len(PROFILE["actions"])
    changed = copy.deepcopy(PROFILE)
    changed["envelope"]["max_velocity_near_human_mps"] = 0.3
    h2 = client.put(f"{BASE}/hospital", json=changed).json()["hash"]
    hist = client.get(f"{BASE}/hospital/history").json()
    assert [v["hash"] for v in hist["versions"]] == [h2, h1] and hist["current_hash"] == h2
    assert client.delete(f"{BASE}/hospital").json()["deleted"] is True
    assert client.get(f"{BASE}/hospital").status_code == 404
    assert client.get(f"{BASE}/hospital/history").status_code == 404


def test_validation_and_names(client):
    r = client.put(f"{BASE}/p", json={"actions": {"x": {"class": "teleport"}}, "turbo": 1})
    assert r.status_code == 422 and len(r.json()["detail"]["errors"]) >= 2
    assert client.put(f"{BASE}/Bad Name", json=PROFILE).status_code == 400
    v = client.post(f"{BASE}/validate", json=PROFILE).json()
    assert v["valid"] is True and v["hash"].startswith("sha256:")
    assert client.post(f"{BASE}/validate", json={}).json()["valid"] is False


def test_robot_binding_and_protected_delete(client):
    body = {"agent_id": "hx-0042", "tools": ["navigate"], "role_permissions": {"logistics": ["navigate"]},
            "action_profile": "hospital"}
    r = client.post("/v1/agents/registry", json=body)
    assert r.status_code == 400 and "unknown action_profile" in r.text
    client.put(f"{BASE}/hospital", json=PROFILE)
    assert client.post("/v1/agents/registry", json=body).status_code == 200
    assert client.get(BASE).json()["profiles"]["hospital"]["robots"] == ["hx-0042"]
    assert client.put("/v1/agents/registry/hx-0042",
                      json={"action_profile": "Not A Name"}).status_code == 400
    assert client.put("/v1/agents/registry/hx-0042",
                      json={"action_profile": "missing"}).status_code == 400
    r = client.delete(f"{BASE}/hospital")
    assert r.status_code == 409 and r.json()["detail"]["robots"] == ["hx-0042"]
    assert client.delete(f"{BASE}/hospital?force=true").json()["deleted"] is True


def test_writes_follow_the_registry_write_gate(app, monkeypatch):
    from starlette.testclient import TestClient
    from storage import tenant_store as ts
    tid = "em" + uuid.uuid4().hex[:10]
    admin, robot = "sk-ema-" + uuid.uuid4().hex, "sk-emr-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[admin])
    ts.set_key_scope(admin, "admin")
    ts.add_api_key(tid, robot, scope="runtime")
    ad, rb = (TestClient(app, headers={"X-API-Key": k}) for k in (admin, robot))
    ad.put(f"{BASE}/p", json=PROFILE)
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    loose = copy.deepcopy(PROFILE)
    loose["envelope"]["max_velocity_near_human_mps"] = 5.0
    assert rb.put(f"{BASE}/p", json=loose).status_code == 403     # a robot cannot loosen itself
    assert rb.delete(f"{BASE}/p").status_code == 403
    assert rb.get(f"{BASE}/p").status_code == 200                 # reads stay open
    assert ad.put(f"{BASE}/p", json=loose).status_code == 200


def test_tenants_are_isolated(client, app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant
    client.put(f"{BASE}/hospital", json=PROFILE)
    other_key = "sk-em-" + uuid.uuid4().hex
    create_tenant("em" + uuid.uuid4().hex[:10], {"name": "o", "plan": "enterprise"},
                  api_keys=[other_key])
    other = TestClient(app, headers={"X-API-Key": other_key})
    assert other.get(f"{BASE}/hospital").status_code == 404
    assert other.get(BASE).json()["profiles"] == {}


def test_corrupt_stored_record_is_reported_not_enforced(client):
    client.put(f"{BASE}/hospital", json=PROFILE)
    em_store._mem[em_store._key(client.tenant_id)]["hospital"] = json.dumps(
        {"profile": {"actions": {"x": {"class": "warp"}}}})
    assert client.get(f"{BASE}/hospital").status_code == 409
    assert "error" in client.get(BASE).json()["profiles"]["hospital"]


# ── task 5: templates, simulate, benchmark (portal) ──────────────────


def test_template_is_the_benchmark_profile(client):
    t = client.get(f"{BASE}/templates").json()["templates"]
    assert set(t) == {"embodied-bench"}
    assert client.put(f"{BASE}/from-template", json=t["embodied-bench"]).status_code == 200


def test_simulate_decides_without_auditing(client):
    from storage.decision_audit import query_decisions
    client.put(f"{BASE}/hospital", json=PROFILE)
    ev = {"stage": "plan", "proposed_action": {"tool": "base_push",
                                               "params": {"velocity_mps": 1.4, "force_n": 210}},
          "context": {"nearest_human_m": 1.1}}
    r = client.post(f"{BASE}/hospital/simulate", json=ev).json()
    assert (r["verdict"], r["rail"], r["simulated"]) == ("block", "envelope_guard", True)
    assert query_decisions(tenant_id=client.tenant_id, guardrail="embodied_guard") == []
    assert client.post(f"{BASE}/missing/simulate", json=ev).status_code == 404


def test_benchmark_card_scores_the_profile(client):
    client.put(f"{BASE}/hospital", json=PROFILE)
    b = client.get(f"{BASE}/hospital/benchmark").json()
    assert (b["caught"], b["correct_rail"], b["false_positives"]) == (18, 17, 0)
    assert (b["attack"], b["benign"], b["cases"]) == (19, 7, 26)
    miss = [r["id"] for r in b["results"] if not r["verdict_ok"]]
    assert miss == ["EBG-016"]


def test_both_images_ship_the_corpus():
    root = os.path.join(os.path.dirname(__file__), "..")
    for dockerfile in ("Dockerfile", "Dockerfile.admin"):
        assert "COPY embodied-bench/ embodied-bench/" in open(os.path.join(root, dockerfile)).read()
    ignore = open(os.path.join(root, ".dockerignore")).read().split()
    assert not any(p.startswith("embodied-bench") or p in ("*.json", "*.jsonl") for p in ignore)
