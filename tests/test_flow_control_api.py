"""Cross-app flow control policy API (/v1/tenant/me/flow-control), through the
real app so tenant resolution is the production middleware."""

import uuid
from unittest.mock import patch

import pytest

from core.xflow import runtime as xflow
from core.xflow import state as xflow_state
from core.xflow.policy import starter_policy

BASE = "/v1/tenant/me/flow-control"


@pytest.fixture(autouse=True)
def _clean():
    xflow.invalidate()
    xflow_state.reset_memory()
    xflow_state._mem_policies.clear()
    yield
    xflow.invalidate()
    xflow_state._mem_policies.clear()


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture
def tenant(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    tid = "fc" + uuid.uuid4().hex[:10]
    key = "sk-fc-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app)
    c.headers.update({"X-API-Key": key})
    c.tenant_id = tid
    return c


def test_requires_a_tenant_api_key(app):
    from starlette.testclient import TestClient
    r = TestClient(app).get(f"{BASE}/policy")
    assert r.status_code in (401, 403)


def test_policy_crud_roundtrip(tenant):
    r = tenant.get(f"{BASE}/policy")
    assert r.status_code == 200 and r.json()["configured"] is False

    p = starter_policy()
    r = tenant.put(f"{BASE}/policy", json=p)
    assert r.status_code == 200, r.text
    saved = r.json()["policy"]
    assert saved["mode"] == "monitor" and "confidential-to-public" in [x["id"] for x in saved["rules"]]

    r = tenant.get(f"{BASE}/policy").json()
    assert r["configured"] is True and r["enforced"] is True and r["policy"] == saved
    assert r["tenant_id"] == tenant.tenant_id

    r = tenant.delete(f"{BASE}/policy")
    assert r.json()["deleted"] is True
    assert tenant.get(f"{BASE}/policy").json()["configured"] is False
    assert xflow.get_policy(tenant.tenant_id) is None


def test_put_invalid_policy_is_422_with_every_error(tenant):
    r = tenant.put(f"{BASE}/policy", json={"mode": "x", "rulez": []})
    assert r.status_code == 422
    errs = r.json()["detail"]["errors"]
    assert any("mode" in e for e in errs) and any("rulez" in e for e in errs)
    assert tenant.get(f"{BASE}/policy").json()["configured"] is False


def test_disabled_policy_is_stored_but_not_enforced(tenant):
    p = starter_policy()
    p["enabled"] = False
    tenant.put(f"{BASE}/policy", json=p)
    assert tenant.get(f"{BASE}/policy").json()["enforced"] is False
    assert xflow.get_policy(tenant.tenant_id) is None


def test_stored_policy_that_no_longer_validates_is_reported_not_enforced(tenant):
    xflow_state.save_policy_json(tenant.tenant_id, '{"mode": "bogus"}')
    xflow.invalidate()
    r = tenant.get(f"{BASE}/policy").json()
    assert r["configured"] is True and r["enforced"] is False and r["errors"]
    assert xflow.get_policy(tenant.tenant_id) is None
    xflow_state.save_policy_json(tenant.tenant_id, "not json")
    xflow.invalidate()
    assert xflow.get_policy(tenant.tenant_id) is None


def test_validate_and_template(tenant):
    t = tenant.get(f"{BASE}/template").json()["policy"]
    r = tenant.post(f"{BASE}/validate", json=t).json()
    assert r["valid"] is True and r["errors"] == []
    r = tenant.post(f"{BASE}/validate", json={"apps": {"x": {}}}).json()
    assert r["valid"] is False and r["errors"]


def test_simulate_with_inline_and_saved_policy(tenant):
    body = {"tool_name": "github_create_repo", "tool_params": {"private": False},
            "sources": [{"tool_name": "drive_read_file"}]}
    assert tenant.post(f"{BASE}/simulate", json=body).status_code == 404   # nothing saved

    p = starter_policy()
    r = tenant.post(f"{BASE}/simulate", json={**body, "policy": p}).json()
    assert r["decision"]["action"] == "block"
    assert r["result"]["action"] == "log"          # the template ships in monitor mode

    p["mode"] = "enforce"
    tenant.put(f"{BASE}/policy", json=p)
    r = tenant.post(f"{BASE}/simulate", json=body).json()
    assert r["result"]["action"] == "block" and r["destination"]["exposure"] == "public"

    bad = tenant.post(f"{BASE}/simulate", json={**body, "policy": {"rulez": 1}})
    assert bad.status_code == 422


def test_simulate_reads_and_writes_no_state(tenant):
    def boom(*a, **k):
        raise AssertionError("simulate touched session state")

    with patch.object(xflow_state, "read", boom), patch.object(xflow_state, "write", boom):
        r = tenant.post(f"{BASE}/simulate", json={
            "policy": starter_policy(), "tool_name": "pastebin_create",
            "sources": [{"tool_name": "drive_read_file"}, {"tool_name": "x", "tags": ["SSN"]}]})
    assert r.status_code == 200
    assert len(r.json()["recorded_sources"]) == 2


def test_session_endpoints_validate_input(tenant):
    assert tenant.get(f"{BASE}/sessions/" + "x" * 600).status_code == 400
    r = tenant.get(f"{BASE}/sessions/never-seen").json()
    assert r["count"] == 0 and r["records"] == []


def test_save_invalidates_the_local_cache(tenant):
    p = starter_policy()
    tenant.put(f"{BASE}/policy", json=p)
    assert xflow.get_policy(tenant.tenant_id).mode == "monitor"
    p["mode"] = "enforce"
    tenant.put(f"{BASE}/policy", json=p)
    assert xflow.get_policy(tenant.tenant_id).mode == "enforce"


def test_runtime_key_cannot_loosen_enforcement_under_enforce(app, monkeypatch):
    """An agent holding only its runtime key must not be able to delete the
    policy or wipe its own session's reads and then exfiltrate."""
    from starlette.testclient import TestClient
    from storage import tenant_store as ts

    tid = "fc" + uuid.uuid4().hex[:10]
    runtime, admin = "sk-rt-" + uuid.uuid4().hex, "sk-ad-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[admin])
    ts.set_key_scope(admin, "admin")
    ts.add_api_key(tid, runtime, scope="runtime")
    rt = TestClient(app, headers={"X-API-Key": runtime})
    ad = TestClient(app, headers={"X-API-Key": admin})

    assert ad.put(f"{BASE}/policy", json=starter_policy()).status_code == 200
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    assert rt.delete(f"{BASE}/sessions/s1").status_code == 403
    assert rt.delete(f"{BASE}/policy").status_code == 403
    assert rt.put(f"{BASE}/policy", json=starter_policy()).status_code == 403
    # Reads and the simulator stay open to the runtime key.
    assert rt.get(f"{BASE}/policy").status_code == 200
    assert rt.get(f"{BASE}/sessions/s1").status_code == 200
    # The admin key still manages it.
    assert ad.delete(f"{BASE}/sessions/s1").status_code == 200
    assert ad.delete(f"{BASE}/policy").status_code == 200

    # Default (off): unchanged behaviour, any tenant key may write.
    monkeypatch.delenv("SHIELD_REGISTRY_WRITE_SCOPE")
    assert rt.put(f"{BASE}/policy", json=starter_policy()).status_code == 200
