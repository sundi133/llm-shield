"""Live runtime policy, advisor and lock. Spec: docs/specs/runtime-live-policy.md.

Task 1: profile history and the live-change preview. The preview encodes what
OpenShell 0.0.80 accepted and refused on a running sandbox (spec §1); the live
proof is tests/test_runtime_openshell_live.py (opt-in).
"""

import copy
import uuid
from unittest.mock import patch

import pytest

from core.runtime_policy import store as rt_store
from core.runtime_policy.compilers.openshell import live_change
from core.runtime_policy.model import TEMPLATES, profile_hash, validate_profile

BASE = "/v1/tenant/me/runtime-profiles"


def _p(**changes) -> dict:
    p = copy.deepcopy(TEMPLATES["research-agent"])
    for path, value in changes.items():
        node = p
        keys = path.split("__")
        for k in keys[:-1]:
            node = node[k]
        node[keys[-1]] = value
    return validate_profile(p)


# ── live_change ──────────────────────────────────────────────────────


def test_identical_profiles_change_nothing():
    assert live_change(_p(), _p()) == {"live": True, "sandbox_changed": False, "reasons": []}


def test_network_changes_apply_live():
    new = _p(network__allow=[{"host": "api.github.com", "port": 443, "methods": ["*"]},
                             {"host": "pypi.org", "port": 443, "methods": ["GET"]}])
    c = live_change(_p(), new)
    assert c == {"live": True, "sandbox_changed": True, "reasons": []}


def test_filesystem_addition_applies_live():
    c = live_change(_p(), _p(filesystem__read_write=["/sandbox", "/tmp", "/var/tmp"]))
    assert c["live"] and c["sandbox_changed"]


def test_filesystem_removal_needs_restart():
    c = live_change(_p(), _p(filesystem__read_write=["/sandbox"]))
    assert c["live"] is False
    assert any("/tmp removed" in r for r in c["reasons"])


def test_process_change_needs_restart():
    c = live_change(_p(), _p(process__run_as="agent"))
    assert c["live"] is False and any("process" in r for r in c["reasons"])


def test_kernel_enforcement_change_needs_restart():
    c = live_change(_p(), _p(filesystem__kernel_enforcement="best_effort"))
    assert c["live"] is False and any("kernel_enforcement" in r for r in c["reasons"])


def test_shield_only_change_does_not_touch_sandboxes():
    """deny_commands is enforced by Shield's tool checks, not OpenShell."""
    c = live_change(_p(), _p(process__deny_commands=["nc *"]))
    assert c == {"live": True, "sandbox_changed": False, "reasons": []}


def test_mixed_change_is_not_live():
    """OpenShell rejects a policy set atomically, so one restart-only part
    holds back the whole change."""
    new = _p(filesystem__read_write=["/sandbox"],
             network__allow=[{"host": "pypi.org", "port": 443}])
    c = live_change(_p(), new)
    assert c["live"] is False and c["sandbox_changed"] is True


# ── history (store) ──────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean():
    rt_store.reset_memory()
    yield
    rt_store.reset_memory()


def test_history_newest_first_and_dedup():
    rt_store.save_profile("t1", "p", _p(), actor="a", reason="put")
    rt_store.save_profile("t1", "p", _p(), actor="a", reason="put")          # same content
    rt_store.save_profile("t1", "p", _p(filesystem__read_write=["/sandbox"]), actor="b")
    h = rt_store.history("t1", "p")
    assert [v["actor"] for v in h] == ["b", "a"]
    assert h[0]["hash"] == profile_hash(_p(filesystem__read_write=["/sandbox"]))
    assert rt_store.history("t2", "p") == []                                 # tenant scoped


def test_history_is_trimmed():
    for i in range(rt_store.HISTORY_MAX + 5):
        rt_store.save_profile("t1", "p", _p(resources__max_pids=100 + i))
    h = rt_store.history("t1", "p")
    assert len(h) == rt_store.HISTORY_MAX
    assert h[0]["profile"]["resources"]["max_pids"] == 100 + rt_store.HISTORY_MAX + 4


def test_delete_removes_history():
    rt_store.save_profile("t1", "p", _p())
    rt_store.delete_profile("t1", "p")
    assert rt_store.history("t1", "p") == []


# ── API ──────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


@pytest.fixture
def client(app):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant

    tid = "lp" + uuid.uuid4().hex[:10]
    key = "sk-lp-" + uuid.uuid4().hex
    create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    c.tenant_id = tid
    return c


def test_put_returns_live_change_and_history_endpoint(client):
    first = client.put(f"{BASE}/ra", json=_p()).json()
    assert first["live_change"] is None                       # nothing was running it before
    second = client.put(f"{BASE}/ra", json=_p(filesystem__read_write=["/sandbox"])).json()
    assert second["live_change"]["live"] is False
    third = client.put(f"{BASE}/ra", json=_p(filesystem__read_write=["/sandbox", "/data"])).json()
    assert third["live_change"] == {"live": True, "sandbox_changed": True, "reasons": []}

    h = client.get(f"{BASE}/ra/history").json()
    assert h["current_hash"] == third["hash"]
    assert [v["hash"] for v in h["versions"]] == [third["hash"], second["hash"], first["hash"]]
    assert h["versions"][0]["live_change"]["live"] is True
    assert h["versions"][1]["live_change"]["live"] is False
    assert h["versions"][2]["live_change"] is None
    assert h["versions"][0]["actor"] == f"tenant:{client.tenant_id}"
    assert client.get(f"{BASE}/missing/history").status_code == 404


# ── task 2: applied state, drift, attestation ────────────────────────

import asyncio  # noqa: E402
from types import SimpleNamespace  # noqa: E402

from fastapi import HTTPException  # noqa: E402

from core.runtime_policy import attest  # noqa: E402
from core.runtime_policy import check as rc  # noqa: E402
from core.runtime_policy import events as rt_events  # noqa: E402


def _report(op, *, profile="research-agent", phash="", instance="sbx-1", **detail):
    return {"source": "custom", "kind": "policy", "decision": "audit", "profile": profile,
            "profile_hash": phash, "detail": {"op": op, "instance": instance, **detail}}


def test_sidecar_op_validation_and_severity_floor():
    with pytest.raises(rt_events.EventError):
        rt_events.normalize(_report("deleted_everything"))
    # On file events detail.op is the access mode, untouched by sidecar rules.
    file_ev = rt_events.normalize({"kind": "file", "decision": "allow",
                                   "detail": {"op": "read", "path": "/sandbox/a"}})
    assert file_ev["severity"] == "info"
    ev = rt_events.normalize({**_report("tampered"), "severity": "info"})
    assert ev["severity"] == "critical"
    assert rt_events.normalize(_report("applied"))["severity"] == "info"
    assert "outside Shield" in rt_events.summary(ev)


def test_ingest_records_applied_state_and_trust():
    asyncio.run(rt_events.ingest("t1", [rt_events.normalize(_report(
        "applied", phash="sha256:" + "a" * 64, runtime_hash="e732", runtime_version=3))],
        trusted=True))
    rec = attest.applied_for("t1", "research-agent", "sbx-1")
    assert rec["state"] == "current" and rec["trusted"] is True and rec["runtime_version"] == 3
    asyncio.run(rt_events.ingest("t1", [rt_events.normalize(_report(
        "restart_required", phash="sha256:" + "a" * 64, instance="sbx-2",
        target_hash="sha256:" + "b" * 64, message="process policy cannot be changed"))]))
    rec2 = attest.applied_for("t1", "research-agent", "sbx-2")
    assert rec2["state"] == "restart_required" and rec2["trusted"] is False
    assert rec2["target_hash"].startswith("sha256:bbbb") and "process" in rec2["detail"]


@pytest.fixture
def cap_env(monkeypatch):
    monkeypatch.setenv("SHIELD_SIGNER_BACKEND", "local")
    monkeypatch.setenv("SHIELD_CAP_TOKEN_PRIVATE_KEY", "52" * 32)
    monkeypatch.delenv("SHIELD_RUNTIME_ATTEST_ACCEPT_APPLIED", raising=False)
    attest.reset_memory()
    rc.invalidate()
    yield
    attest.reset_memory()
    rc.invalidate()


def _attested_tenant():
    """A profile at H1 that moved to H2 while sandbox sbx-1 kept its H1 token."""
    from storage.tenant_store import kv_set
    tenant = "la" + uuid.uuid4().hex[:8]
    prof = copy.deepcopy(TEMPLATES["research-agent"])
    prof["identity"] = {"require_attestation": "enforce"}
    h1 = profile_hash(rt_store.save_profile(tenant, "research-agent", prof))
    prof["network"]["allow"].append({"host": "pypi.org", "methods": ["GET"]})
    h2 = profile_hash(rt_store.save_profile(tenant, "research-agent", prof))
    kv_set(f"agents:{tenant}", {"bot": {"agent_id": "bot", "runtime_profile": "research-agent"}})
    rc.invalidate(tenant)
    return tenant, h1, h2


def _mint(tenant, h, instance="sbx-1"):
    from api import routes_agent_auth as aa
    from api.routes_agent_auth import CapMintRequest
    from core.identity import IdentityTuple
    from core.jwt_utils import encode_jwt
    from core.signers import LocalEd25519Signer

    token = encode_jwt({"agent_id": "bot", "runtime_profile_hash": h},
                       LocalEd25519Signer(kid="lp", private_key_hex="41" * 32))
    ident = IdentityTuple(user_sub="alice@corp.com", agent_id="bot", agent_instance_id=instance,
                          tenant_id=tenant, build_hash="h", model_version="m", session_id="s1")
    body = CapMintRequest(tool="fetch", resource="r/1", session_id="s1")
    with patch.object(aa, "rate_limit_cap_mint", return_value=(True, None)), \
         patch.object(aa, "_decide_authz", return_value={
             "allowed": True, "tool": "fetch", "resource": "r/1", "reasons": []}):
        return asyncio.run(aa.mint_capability(body, ident,
                                              SimpleNamespace(headers={"X-Agent-Token": token})))


def test_trusted_live_update_satisfies_attestation(cap_env):
    tenant, h1, h2 = _attested_tenant()
    with pytest.raises(HTTPException):
        _mint(tenant, h1)                                  # stale token, no report yet
    attest.record_applied(tenant, "research-agent", "sbx-1", op="applied", profile_hash=h2,
                          trusted=True)
    assert _mint(tenant, h1).cap_token                     # updated in place
    with pytest.raises(HTTPException):
        _mint(tenant, h1, instance="sbx-9")                # a different sandbox is still stale


def test_untrusted_or_not_running_reports_do_not(cap_env, monkeypatch):
    tenant, h1, h2 = _attested_tenant()
    attest.record_applied(tenant, "research-agent", "sbx-1", op="applied", profile_hash=h2,
                          trusted=False)
    with pytest.raises(HTTPException):
        _mint(tenant, h1)
    attest.record_applied(tenant, "research-agent", "sbx-1", op="restart_required",
                          profile_hash=h1, target_hash=h2, trusted=True)
    with pytest.raises(HTTPException):
        _mint(tenant, h1)
    attest.record_applied(tenant, "research-agent", "sbx-1", op="applied", profile_hash=h2,
                          trusted=True)
    monkeypatch.setenv("SHIELD_RUNTIME_ATTEST_ACCEPT_APPLIED", "0")
    with pytest.raises(HTTPException):
        _mint(tenant, h1)                                  # escape hatch: strict again


def test_matching_claim_reads_nothing(cap_env):
    tenant, _, h2 = _attested_tenant()
    with patch.object(attest, "applied_for") as read:
        assert _mint(tenant, h2).cap_token
    read.assert_not_called()


def test_events_endpoint_trusts_only_admin_keys(app, monkeypatch):
    """Under the default SHIELD_REGISTRY_WRITE_SCOPE=off, an unscoped key's
    report is recorded but not trusted."""
    from starlette.testclient import TestClient
    from storage import tenant_store as ts

    monkeypatch.delenv("SHIELD_REGISTRY_WRITE_SCOPE", raising=False)
    tid = "la" + uuid.uuid4().hex[:8]
    admin, plain = "sk-lad-" + uuid.uuid4().hex, "sk-lpl-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[admin])
    ts.set_key_scope(admin, "admin")
    ts.add_api_key(tid, plain)
    h = "sha256:" + "c" * 64
    for key, inst in ((admin, "sbx-admin"), (plain, "sbx-plain")):
        r = TestClient(app, headers={"X-API-Key": key}).post(
            "/v1/shield/runtime/events", json={"events": [_report("applied", phash=h,
                                                                  instance=inst)]})
        assert r.status_code == 202 and r.json()["accepted"] == 1
    assert attest.applied_for(tid, "research-agent", "sbx-admin")["trusted"] is True
    assert attest.applied_for(tid, "research-agent", "sbx-plain")["trusted"] is False
    attest.reset_memory()


def test_drift_endpoint_lists_instances(client):
    client.put(f"{BASE}/research-agent", json=_p())
    h = client.get(f"{BASE}/research-agent").json()["hash"]
    tid = client.tenant_id
    attest.record_drift(tid, "research-agent", instance="sbx-1", agent_id="bot",
                        got="sha256:" + "0" * 64, expected=h)
    attest.record_drift(tid, "research-agent", instance="sbx-2", agent_id="bot",
                        got="sha256:" + "0" * 64, expected=h)
    attest.record_applied(tid, "research-agent", "sbx-1", op="applied", profile_hash=h,
                          trusted=True, lock="global")
    d = client.get(f"{BASE}/research-agent/drift").json()
    assert [s["instance"] for s in d["stale"]] == ["sbx-2"]      # sbx-1 was updated in place
    by = {i["instance"]: i for i in d["instances"]}
    assert by["sbx-1"]["on_current"] is True and by["sbx-1"]["lock"] == "global"
    assert by["sbx-2"]["on_current"] is False and by["sbx-2"]["state"] is None
    attest.reset_memory()
