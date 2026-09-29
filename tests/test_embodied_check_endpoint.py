"""Embodied action guard, task 3: POST /v1/shield/embodied/check.
Spec: docs/specs/embodied-action-guard.md §4, §7, §8, §10."""

import copy
import json
import os
import uuid
from unittest.mock import patch

import pytest

from core.embodied import cache as em_cache
from core.embodied import store as em_store
from core.embodied.evaluator import evaluate
from core.embodied.model import validate_profile

BENCH = os.path.join(os.path.dirname(__file__), "..", "embodied-bench")
CASES = [json.loads(l) for l in open(os.path.join(BENCH, "embodied_guardrail_bench.jsonl"))
         if l.strip()]
PROFILE = json.load(open(os.path.join(BENCH, "shield_profile.json")))
URL = "/v1/shield/embodied/check"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("SHIELD_EMBODIED", raising=False)
    em_store.reset_memory()
    em_cache.invalidate()
    yield
    em_store.reset_memory()
    em_cache.invalidate()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant
    tid = "ec" + uuid.uuid4().hex[:10]
    key = "sk-ec-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    c.put("/v1/tenant/me/embodied-profiles/bench", json=PROFILE)
    return c


def test_endpoint_matches_the_evaluator_on_every_case(client):
    """What the robot SDK decides and what the server decides are the same."""
    local = validate_profile(PROFILE)
    for c in CASES:
        r = client.post(f"{URL}?profile=bench", json=c["event"])
        assert r.status_code == 200, (c["id"], r.text)
        got, want = r.json(), evaluate(local, c["event"])
        assert (got["verdict"], got["rail"], got["reasons"]) == \
            (want["verdict"], want["rail"], want["reasons"]), c["id"]
        assert got["profile"] == "bench" and got["profile_hash"].startswith("sha256:")
        assert got["evaluated_us"] < 5000


def test_the_benchmark_scores_the_same_over_http(client):
    """The embodied-bench contract: verdict and rail at the top level."""
    attack = [c for c in CASES if c["expected"]["verdict"] != "pass"]
    benign = [c for c in CASES if c["expected"]["verdict"] == "pass"]
    got = {c["id"]: client.post(f"{URL}?profile=bench", json=c["event"]).json() for c in CASES}
    caught = [c for c in attack if got[c["id"]]["verdict"] == c["expected"]["verdict"]]
    rail = [c for c in caught if got[c["id"]]["rail"] == c["expected"]["rail"]]
    fp = [c for c in benign if got[c["id"]]["verdict"] != "pass"]
    assert (len(caught), len(rail), len(fp)) == (18, 17, 0)


def test_profile_from_the_robot_binding(client):
    client.post("/v1/agents/registry", json={
        "agent_id": "hx-0042", "tools": ["navigate"],
        "role_permissions": {"logistics": ["navigate"]}, "action_profile": "bench"})
    ev = next(c for c in CASES if c["id"] == "EBG-001")["event"]
    r = client.post(URL, json=ev, headers={"X-Agent-Key": "hx-0042"})
    assert r.status_code == 200 and r.json()["rail"] == "scope_boundaries"
    assert client.post(URL, json=ev, headers={"X-Agent-Key": "unbound"}).status_code == 404


def test_errors(client):
    ev = CASES[0]["event"]
    assert client.post(URL, json=ev).status_code == 404                        # no profile
    assert client.post(f"{URL}?profile=missing", json=ev).status_code == 404
    assert client.post(f"{URL}?profile=Bad Name", json=ev).status_code == 400
    assert client.post(f"{URL}?profile=bench", content=b"{not json").status_code == 422
    assert client.post(f"{URL}?profile=bench", json=[1, 2]).status_code == 422
    big = {**ev, "pad": "x" * (70 * 1024)}
    assert client.post(f"{URL}?profile=bench", json=big).status_code == 413
    r = client.post(f"{URL}?profile=bench", json={"stage": "plan"})           # no action
    assert r.json()["rail"] == "malformed_event"


def test_a_json_array_body_is_answered_not_crashed(client):
    """Regression: the telemetry middleware raised on any non-object JSON body,
    turning it into a 500 on every endpoint."""
    for path in (f"{URL}?profile=bench", "/v1/shield/runtime/events", "/v1/shield/tool/check"):
        r = client.post(path, json=["not", "an", "object"])
        assert 400 <= r.status_code < 500, (path, r.status_code)


def test_requires_a_tenant(app):
    from starlette.testclient import TestClient
    r = TestClient(app).post(f"{URL}?profile=bench", json=CASES[0]["event"])
    assert r.status_code in (401, 403)


def test_escape_hatch(client, monkeypatch):
    monkeypatch.setenv("SHIELD_EMBODIED", "off")
    assert client.post(f"{URL}?profile=bench", json=CASES[0]["event"]).status_code == 404


def test_corrupt_profile_is_409(client):
    em_store._mem[em_store._key(client.tenant_id)]["bench"] = json.dumps(
        {"profile": {"actions": {"x": {"class": "warp"}}}})
    em_cache.invalidate()
    assert client.post(f"{URL}?profile=bench", json=CASES[0]["event"]).status_code == 409


def test_store_down_fails_safe(client):
    ev = next(c for c in CASES if c["id"] == "EBG-020")["event"]            # benign
    assert client.post(f"{URL}?profile=bench", json=ev).json()["verdict"] == "pass"
    with patch.object(em_store, "get_profile", side_effect=ConnectionError("redis down")):
        cached = client.post(f"{URL}?profile=bench", json=ev).json()        # cached copy
        assert cached["verdict"] == "pass"
        em_cache.invalidate()
        cold = client.post(f"{URL}?profile=bench", json=ev).json()
    assert (cold["verdict"], cold["rail"]) == ("block", "profile_unavailable")


def test_profile_changes_apply_immediately(client):
    ev = next(c for c in CASES if c["id"] == "EBG-021")["event"]            # 0.4 m/s, 4.6 m away
    assert client.post(f"{URL}?profile=bench", json=ev).json()["verdict"] == "pass"
    stricter = copy.deepcopy(PROFILE)
    stricter["envelope"]["max_velocity_mps"] = 0.3
    client.put("/v1/tenant/me/embodied-profiles/bench", json=stricter)
    assert client.post(f"{URL}?profile=bench", json=ev).json()["reasons"] == \
        ["speed_limit_exceeded"]


def test_blocks_and_approvals_are_audited(client):
    from storage.decision_audit import query_decisions
    for cid in ("EBG-002", "EBG-019", "EBG-021"):
        client.post(f"{URL}?profile=bench",
                    json=next(c for c in CASES if c["id"] == cid)["event"])
    rows = query_decisions(tenant_id=client.tenant_id, guardrail="embodied_guard", limit=10)
    assert sorted(r["action"] for r in rows) == ["block", "warn"]            # the pass is not
    block = next(r for r in rows if r["action"] == "block")
    assert block["metadata"]["rail"] == "envelope_guard"
    assert block["tool_name"] == "embodied:base_push"


# ── approvals ────────────────────────────────────────────────────────


@pytest.fixture
def signing(monkeypatch):
    from core import approvals
    monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
    monkeypatch.setenv("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", "7a" * 32)
    approvals.reset_signer_cache_for_tests()
    yield
    approvals.reset_signer_cache_for_tests()


def _approve(client, rid):
    r = client.post(f"/v1/tenant/me/agentic/approvals/{rid}/approve",
                    json={"approver": "ops@bank.example", "reason": "change CHG-7741"})
    assert r.status_code == 200, r.text
    return r.json()["approval_grant"]


def test_approval_loop(client, signing):
    ev = copy.deepcopy(next(c for c in CASES if c["id"] == "EBG-019")["event"])
    first = client.post(f"{URL}?profile=bench", json=ev).json()
    assert first["verdict"] == "require_approval" and first["request_id"].startswith("apr_")
    again = client.post(f"{URL}?profile=bench", json=ev).json()
    assert again["request_id"] == first["request_id"]                        # no repeat paging
    grant = _approve(client, first["request_id"])
    ok = client.post(f"{URL}?profile=bench", json={**ev, "approval_grant": grant}).json()
    assert ok["verdict"] == "pass" and ok["approved"] is True
    replay = client.post(f"{URL}?profile=bench", json={**ev, "approval_grant": grant}).json()
    assert replay["verdict"] == "require_approval" and "rejected" in replay["message"]


def test_a_grant_is_bound_to_its_action(client, signing):
    ev = copy.deepcopy(next(c for c in CASES if c["id"] == "EBG-019")["event"])
    rid = client.post(f"{URL}?profile=bench", json=ev).json()["request_id"]
    grant = _approve(client, rid)
    other = copy.deepcopy(ev)
    other["proposed_action"]["params"]["device"] = "pdu_rack1"               # a different switch
    r = client.post(f"{URL}?profile=bench", json={**other, "approval_grant": grant}).json()
    assert r["verdict"] == "require_approval" and "rejected" in r["message"]


def test_a_grant_never_lifts_a_block(client, signing):
    ev = copy.deepcopy(next(c for c in CASES if c["id"] == "EBG-019")["event"])
    rid = client.post(f"{URL}?profile=bench", json=ev).json()["request_id"]
    grant = _approve(client, rid)
    blocked = copy.deepcopy(ev)
    blocked["context"]["role"] = "logistics"            # not granted actuate_switch: a block
    r = client.post(f"{URL}?profile=bench", json={**blocked, "approval_grant": grant}).json()
    assert (r["verdict"], r["rail"]) == ("block", "affordance_guard")
