"""Claude Code guardrails as a fleet switch, task 1: the per-fleet setting in
the device policy and bundle, and device keys on the hook route.
Spec: docs/specs/claude-code-fleet-rollout.md.
"""

import hashlib
import json
import uuid
from unittest.mock import patch

import pytest

from core.dlp import agent_hooks as ah
from core.dlp import device_policy as dp
from core.dlp import devices as dv
from core.runtime_policy import check as rc
from core.runtime_policy import hook_seen, hooks
from core.runtime_policy import store as rt_store

HOOK = "/v1/shield/hooks/claude-code"
LAPTOP = {"hostname": "ana-mbp", "os": "macos", "os_version": "14.5", "agent_version": "0.1.0",
          "serial_hash": hashlib.sha256(b"C02XK0CCCODE").hexdigest()}
PROFILE = {"filesystem": {"read_write": ["@project"], "kernel_enforcement": "best_effort"},
           "process": {"deny_commands": ["openssl enc*"]}}
CALL = {"session_id": "s-1", "cwd": "/Users/ana/proj", "tool_name": "Bash",
        "transcript_path": "/Users/ana/.claude/projects/p/s.jsonl",
        "tool_input": {"command": "openssl enc -in a.txt"}}
BLOCK = {"agents": {"claude_code": "claude-code"},
         "default": {"mode": "off", "on_unreachable": "allow"},
         "fleets": {"pilot": {"mode": "monitor", "on_unreachable": "allow"},
                    "eng": {"mode": "enforce", "on_unreachable": "deny"}}}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    from core.runtime_policy import bundle as rt_bundle
    dv.reset_memory()
    dv.reset_caller_cache()
    ah.invalidate()
    hooks.reset_cache_for_tests()
    hook_seen.reset_for_tests()
    rt_store.reset_memory()
    rc.invalidate()
    monkeypatch.setenv("SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY", "3a" * 32)
    monkeypatch.delenv("SHIELD_DEVICE_AGENT_HOOKS", raising=False)
    rt_bundle.reset_signer_cache_for_tests()
    yield
    rt_bundle.reset_signer_cache_for_tests()
    dv.reset_memory()
    dv.reset_caller_cache()
    ah.invalidate()


# ── the device policy ────────────────────────────────────────────────


def test_agent_hooks_is_optional_and_stored_only_when_set():
    # A policy that never sets it normalizes to the same keys as before, so its
    # hash (and every laptop's bundle) is unchanged.
    assert set(dp.validate_policy({})) == set(dp.DEFAULT_POLICY)
    assert dp.policy_hash(dp.validate_policy({"mode": "enforce"})) == \
        dp.policy_hash(dp.validate_policy(dp.validate_policy({"mode": "enforce"})))
    p = dp.validate_policy({"agent_hooks": {"fleets": {"eng": {"mode": "enforce"}}}})
    assert p["agent_hooks"] == {"agents": {"claude_code": "claude-code"},
                                "default": {"mode": "off", "on_unreachable": "allow"},
                                "fleets": {"eng": {"mode": "enforce", "on_unreachable": "allow"}}}


@pytest.mark.parametrize("block, needle", [
    ("on", "agent_hooks: an object"),
    ({"fleets": {"eng": {"mode": "block"}}}, "agent_hooks.fleets.eng.mode"),
    ({"fleets": {"eng": {"on_unreachable": "maybe"}}}, "on_unreachable"),
    ({"fleets": {"Eng Team": {"mode": "enforce"}}}, "fleet id"),
    ({"fleets": {f"f{i}": {"mode": "monitor"} for i in range(dp.MAX_FLEETS + 1)}}, "at most"),
    ({"agents": {"claude_code": "bad agent"}}, "agent_hooks.agents.claude_code"),
    ({"agents": {"cursor": "cursor"}}, "not a supported coding agent"),
    ({"agents": {}}, "agent_hooks.agents: an object mapping"),
    ({"surprise": 1}, "unknown field 'surprise'"),
    ({"default": {"mode": "enforce", "extra": 1}}, "unknown field 'extra'"),
])
def test_agent_hooks_validation(block, needle):
    with pytest.raises(dp.PolicyError) as e:
        dp.validate_policy({"agent_hooks": block})
    assert any(needle in err for err in e.value.errors), e.value.errors


def test_each_fleet_gets_only_its_own_setting(monkeypatch):
    p = dp.validate_policy({"agent_hooks": BLOCK})
    assert dp.for_fleet(p, "eng")["agent_hooks"] == {
        "agents": {"claude_code": "claude-code"}, "mode": "enforce", "on_unreachable": "deny"}
    assert dp.for_fleet(p, "pilot")["agent_hooks"]["mode"] == "monitor"
    assert dp.for_fleet(p, "sales")["agent_hooks"]["mode"] == "off"       # the default
    assert "fleets" not in json.dumps(dp.for_fleet(p, "eng")["agent_hooks"])
    assert "agent_hooks" not in dp.for_fleet(dp.validate_policy({}), "eng")
    monkeypatch.setenv("SHIELD_DEVICE_AGENT_HOOKS", "off")
    assert dp.for_fleet(p, "eng")["agent_hooks"]["mode"] == "off"


# ── a tenant, a device and its key ───────────────────────────────────


@pytest.fixture(scope="module")
def app():
    with patch("storage.tenant_store._get_redis", return_value=None):
        from core.app import create_app
        yield create_app()


def _client(app, key=None):
    from starlette.testclient import TestClient
    return TestClient(app, headers={"X-API-Key": key} if key else {})


@pytest.fixture
def tenant(app):
    from storage import tenant_store as ts
    tid = "cc" + uuid.uuid4().hex[:10]
    key = "sk-cc-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    admin = _client(app, key)
    admin.tenant_id = tid
    assert admin.put("/v1/tenant/me/runtime-profiles/laptop", json=PROFILE).status_code == 200
    assert admin.post("/v1/agents/registry", json={"agent_id": "claude-code",
                      "runtime_profile": "laptop"}).status_code in (200, 201)
    return admin


def _device(app, tenant, fleet):
    r = tenant.post("/v1/tenant/me/devices/enrollment-tokens", json={"fleet": fleet})
    assert r.status_code == 200, r.text
    from starlette.testclient import TestClient
    body = {**LAPTOP, "serial_hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
    out = TestClient(app).post("/v1/devices/enroll", json=body,
                               headers={"X-Enrollment-Token": r.json()["enrollment_token"]})
    assert out.status_code == 200, out.text
    c = _client(app, out.json()["api_key"])
    c.device_id = out.json()["device_id"]
    return c


def _set(tenant, block):
    r = tenant.put("/v1/tenant/me/dlp-policy", json={"agent_hooks": block})
    assert r.status_code == 200, r.text


def _hook(device, **headers):
    return device.post(HOOK, json=CALL, headers=headers)


# ── the hook route with a device key ─────────────────────────────────


def test_enforce_fleet_decides_and_attributes_to_the_device(app, tenant):
    from storage.decision_audit import query_decisions
    _set(tenant, BLOCK)
    d = _device(app, tenant, "eng")
    r = _hook(d, **{"X-Agent-Key": "someone-else", "X-Device-Id": "spoofed"})
    assert r.status_code == 200
    assert r.json()["hookSpecificOutput"]["permissionDecision"] == "deny"
    (row,) = query_decisions(tenant_id=tenant.tenant_id, guardrail="runtime_boundary", limit=5)
    meta = row["metadata"] if isinstance(row["metadata"], dict) else json.loads(row["metadata"])
    assert meta["detail"]["device_id"] == d.device_id and meta["detail"]["fleet"] == "eng"
    assert row["agent_key"] == "claude-code"                # the fleet's agent, not the header
    (seen,) = hook_seen.list_seen(tenant.tenant_id)
    assert (seen["device"], seen["fleet"], seen["monitor"]) == (d.device_id, "eng", False)


def test_monitor_fleet_lets_everything_through_and_records_what_enforce_would_do(app, tenant):
    from storage.decision_audit import query_decisions
    _set(tenant, BLOCK)
    d = _device(app, tenant, "pilot")
    assert _hook(d).json() == {}
    (row,) = query_decisions(tenant_id=tenant.tenant_id, guardrail="runtime_boundary", limit=5)
    meta = row["metadata"] if isinstance(row["metadata"], dict) else json.loads(row["metadata"])
    assert row["action"] == "log"                           # recorded, not blocked
    assert meta["detail"]["monitor"] is True and meta["detail"]["would_decide"] == "deny"
    (seen,) = hook_seen.list_seen(tenant.tenant_id)
    assert seen["monitor"] is True and seen["decision"] == "deny"


def test_off_fleet_and_tenant_without_the_setting_are_not_checked(app, tenant):
    from storage.decision_audit import query_decisions
    d_none = _device(app, tenant, "eng")
    assert _hook(d_none).json() == {}                       # no agent_hooks block at all
    _set(tenant, BLOCK)
    d_off = _device(app, tenant, "sales")                   # the default: off
    assert _hook(d_off).json() == {}
    assert query_decisions(tenant_id=tenant.tenant_id, guardrail="runtime_boundary",
                           limit=5) == []
    assert hook_seen.list_seen(tenant.tenant_id) == []


def test_a_policy_change_applies_at_once(app, tenant):
    _set(tenant, BLOCK)
    d = _device(app, tenant, "pilot")
    assert _hook(d).json() == {}
    _set(tenant, {**BLOCK, "fleets": {"pilot": {"mode": "enforce"}}})   # saving invalidates
    assert _hook(d).json()["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_escape_hatch_turns_every_fleet_off(app, tenant, monkeypatch):
    _set(tenant, BLOCK)
    d = _device(app, tenant, "eng")
    monkeypatch.setenv("SHIELD_DEVICE_AGENT_HOOKS", "off")
    assert _hook(d).json() == {}


def test_the_bundle_carries_the_fleets_setting(app, tenant):
    _set(tenant, BLOCK)
    d = _device(app, tenant, "eng")
    policy = d.get("/v1/edge/dlp-bundle?fleet=eng").json()["policy"]
    assert policy["agent_hooks"] == {"agents": {"claude_code": "claude-code"},
                                     "mode": "enforce", "on_unreachable": "deny"}
    # Without the setting, the bundle is exactly as before.
    _set(tenant, BLOCK)
    tenant.put("/v1/tenant/me/dlp-policy", json={})
    assert "agent_hooks" not in d.get("/v1/edge/dlp-bundle?fleet=eng").json()["policy"]


def test_a_revoked_device_is_refused_within_the_cache_window(app, tenant):
    _set(tenant, BLOCK)
    d = _device(app, tenant, "eng")
    clock = [1000.0]
    with patch("core.dlp.devices.time.monotonic", side_effect=lambda: clock[0]):
        assert _hook(d).status_code == 200
        assert tenant.delete(f"/v1/tenant/me/devices/{d.device_id}").status_code == 200
        clock[0] += dv.CALLER_CACHE_S - 1
        assert _hook(d).status_code == 200                  # still cached: the stated window
        clock[0] += 2
        r = _hook(d)
        assert r.status_code == 401 and "revoked" in r.text
    # Every other device route checks at once.
    assert d.post("/v1/devices/heartbeat", json={"state": "ok"}).status_code == 401


def test_unknown_device_keys_are_never_cached(app):
    fake = _client(app, "vdk_" + "x" * 40)
    for _ in range(2):
        assert fake.post(HOOK, json=CALL).status_code == 401
    assert dv._caller_cache == {}


def test_tenant_keys_work_as_before(app, tenant):
    r = tenant.post(HOOK, json=CALL, headers={"X-Agent-Key": "claude-code"})
    assert r.json()["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert tenant.post(HOOK, json=CALL).status_code == 400   # X-Agent-Key still required


def test_a_device_key_still_reaches_nothing_else(app, tenant):
    d = _device(app, tenant, "eng")
    for method, path in (("POST", "/guardrails/input"), ("GET", "/v1/tenant/me/dlp-policy"),
                         ("POST", "/v1/shield/runtime/check"),
                         ("GET", "/v1/tenant/me/hooks/claude-code")):
        r = d.request(method, path, json={})
        assert r.status_code == 403 and r.json()["error"] == "device_key_scope", path
