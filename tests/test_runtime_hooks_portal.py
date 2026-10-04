"""Coding-agent guardrails as a fleet switch, task 2: turn on, fleet modes,
laptop hook states, the portal card and the Agent Registry profile field.
Spec: docs/specs/claude-code-fleet-rollout.md.
"""

import hashlib
import os
import re
import uuid
from unittest.mock import patch

import pytest

from core.dlp import agent_hooks as ah
from core.dlp import devices as dv
from core.runtime_policy import check as rc
from core.runtime_policy import hook_seen, hooks
from core.runtime_policy import store as rt_store
from core.runtime_policy.model import templates

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = "/v1/shield/hooks/claude-code"
CALL = {"session_id": "s-1", "cwd": "/Users/ana/proj", "tool_name": "Bash",
        "transcript_path": "/Users/ana/.claude/projects/p/s.jsonl",
        "tool_input": {"command": "openssl enc -in a.txt"}}


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
    for env in ("SHIELD_DEVICE_AGENT_HOOKS", "SHIELD_DEVICE_AGENT_SHIELD_URL", "SHIELD_PUBLIC_URL",
                "SHIELD_REGISTRY_WRITE_SCOPE"):
        monkeypatch.delenv(env, raising=False)
    rt_bundle.reset_signer_cache_for_tests()
    yield
    rt_bundle.reset_signer_cache_for_tests()
    dv.reset_memory()
    dv.reset_caller_cache()
    ah.invalidate()


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
    tid = "cp" + uuid.uuid4().hex[:10]
    key = "sk-cp-" + uuid.uuid4().hex
    ts.create_tenant(tid, {"name": tid, "plan": "enterprise"}, api_keys=[key])
    ts.set_key_scope(key, "admin")
    c = _client(app, key)
    c.tenant_id, c.key = tid, key
    return c


def _device(app, tenant, fleet, hostname="ana-mbp"):
    r = tenant.post("/v1/tenant/me/devices/enrollment-tokens", json={"fleet": fleet})
    assert r.status_code == 200, r.text
    body = {"hostname": hostname, "os": "macos", "os_version": "14.5", "agent_version": "0.2.0",
            "serial_hash": hashlib.sha256(uuid.uuid4().bytes).hexdigest()}
    out = _client(app).post("/v1/devices/enroll", json=body,
                            headers={"X-Enrollment-Token": r.json()["enrollment_token"]})
    assert out.status_code == 200, out.text
    c = _client(app, out.json()["api_key"])
    c.device_id = out.json()["device_id"]
    return c


def _agent(tenant, agent_id="claude-code"):
    agents = tenant.get("/v1/agents/registry").json()
    agents = agents.get("agents", agents) if isinstance(agents, dict) else agents
    if isinstance(agents, dict):
        return agents.get(agent_id)
    return next((a for a in agents if a.get("agent_id") == agent_id), None)


# ── turn on ──────────────────────────────────────────────────────────


def test_enable_creates_profile_agent_and_coverage(app, tenant):
    r = tenant.post("/v1/tenant/me/hooks/enable", json={})
    assert r.status_code == 200, r.text
    d = r.json()
    assert (d["profile"], d["profile_created"], d["agent"], d["agent_created"]) == \
        ("coding-agent-baseline", True, "claude-code", True)
    assert rt_store.get_profile(tenant.tenant_id, "coding-agent-baseline") == \
        templates()["coding-agent-baseline"]
    assert _agent(tenant)["runtime_profile"] == "coding-agent-baseline"
    pol = tenant.get("/v1/tenant/me/dlp-policy").json()["policy"]
    assert pol["agent_hooks"]["agents"] == {"claude_code": "claude-code"}
    assert pol["agent_hooks"]["fleets"] == {}                 # every fleet still off
    assert d["status"]["claude_code"] == {"agent": "claude-code", "agent_exists": True,
                                          "profile": "coding-agent-baseline", "covered": True}
    again = tenant.post("/v1/tenant/me/hooks/enable", json={}).json()
    assert (again["profile_created"], again["agent_created"]) == (False, False)


def test_enable_keeps_an_existing_profile_and_binds_an_unbound_agent(app, tenant):
    mine = {"filesystem": {"read_write": ["@project"], "kernel_enforcement": "best_effort"}}
    assert tenant.put("/v1/tenant/me/runtime-profiles/coding-agent-baseline",
                      json=mine).status_code == 200
    before = rt_store.get_profile(tenant.tenant_id, "coding-agent-baseline")
    assert tenant.post("/v1/agents/registry", json={"agent_id": "claude-code"}).status_code \
        in (200, 201)
    d = tenant.post("/v1/tenant/me/hooks/enable", json={}).json()
    assert (d["profile_created"], d["agent_created"]) == (False, False)
    assert rt_store.get_profile(tenant.tenant_id, "coding-agent-baseline") == before
    assert _agent(tenant)["runtime_profile"] == "coding-agent-baseline"


def test_enable_never_moves_an_agent_off_another_profile_unless_told(app, tenant):
    assert tenant.put("/v1/tenant/me/runtime-profiles/mine", json={}).status_code == 200
    tenant.post("/v1/agents/registry", json={"agent_id": "claude-code",
                                             "runtime_profile": "mine"})
    r = tenant.post("/v1/tenant/me/hooks/enable", json={})
    assert r.status_code == 409 and r.json()["detail"]["current_profile"] == "mine"
    # Nothing was written by the refused call.
    assert rt_store.get_profile(tenant.tenant_id, "coding-agent-baseline") is None
    assert "agent_hooks" not in tenant.get("/v1/tenant/me/dlp-policy").json()["policy"]
    # Turning on with the profile it already has is fine...
    assert tenant.post("/v1/tenant/me/hooks/enable", json={"profile": "mine"}).status_code == 200
    # ...and replace_binding moves it.
    r = tenant.post("/v1/tenant/me/hooks/enable", json={"replace_binding": True})
    assert r.status_code == 200 and _agent(tenant)["runtime_profile"] == "coding-agent-baseline"


@pytest.mark.parametrize("body, needle", [
    ({"coding_agent": "cursor"}, "coding_agent"),
    ({"profile": "Bad Name"}, "profile"),
])
def test_enable_input_errors(app, tenant, body, needle):
    r = tenant.post("/v1/tenant/me/hooks/enable", json=body)
    assert r.status_code == 422 and any(needle in e for e in r.json()["detail"]["errors"])


def test_writes_need_an_admin_key_when_registry_scope_is_enforced(app, tenant, monkeypatch):
    from storage import tenant_store as ts
    monkeypatch.setenv("SHIELD_REGISTRY_WRITE_SCOPE", "enforce")
    ts.set_key_scope(tenant.key, "runtime")
    assert tenant.post("/v1/tenant/me/hooks/enable", json={}).status_code == 403
    assert tenant.put("/v1/tenant/me/hooks/fleets", json={"fleets": {}}).status_code == 403
    assert tenant.get("/v1/tenant/me/hooks/fleets").status_code == 200      # reads are fine


# ── fleet modes ──────────────────────────────────────────────────────


def test_fleets_lists_device_fleets_with_hook_states(app, tenant):
    assert tenant.get("/v1/tenant/me/hooks/fleets").json()["configured"] is False
    a = _device(app, tenant, "eng", "a-mbp")
    b = _device(app, tenant, "eng", "b-mbp")
    _device(app, tenant, "sales", "c-mbp")
    assert a.post("/v1/devices/heartbeat", json={
        "agent_hooks": {"claude_code": {"state": "active", "hook_version": "1"}}}).status_code == 204
    assert b.post("/v1/devices/heartbeat", json={
        "agent_hooks": {"claude_code": {"state": "conflict", "reason": "settings exist"}}}).status_code == 204
    tenant.post("/v1/tenant/me/hooks/enable", json={})
    d = tenant.get("/v1/tenant/me/hooks/fleets").json()
    rows = {f["fleet"]: f for f in d["fleets"]}
    assert d["configured"] is True and set(rows) == {"eng", "sales"}
    assert rows["eng"]["laptops"] == 2 and rows["eng"]["mode"] == "off"
    assert rows["eng"]["states"]["claude_code"] == {"active": 1, "conflict": 1}
    assert rows["sales"]["states"]["claude_code"] == {"not_reported": 1}


def test_put_fleets_sets_modes_keeps_coverage_and_applies_on_the_hook_route(app, tenant):
    tenant.post("/v1/tenant/me/hooks/enable", json={})
    d = _device(app, tenant, "eng")
    assert d.post(HOOK, json=CALL).json() == {}                              # off
    r = tenant.put("/v1/tenant/me/hooks/fleets", json={
        "fleets": {"eng": {"mode": "enforce", "on_unreachable": "deny"}}})
    assert r.status_code == 200, r.text
    assert r.json()["agents"] == {"claude_code": "claude-code"}              # kept
    assert d.post(HOOK, json=CALL).json()["hookSpecificOutput"]["permissionDecision"] == "deny"
    bundle = d.get("/v1/edge/dlp-bundle?fleet=eng").json()["policy"]
    assert bundle["agent_hooks"] == {"agents": {"claude_code": "claude-code"},
                                     "mode": "enforce", "on_unreachable": "deny"}


@pytest.mark.parametrize("body, needle", [
    ({"fleets": {"eng": {"mode": "block"}}}, "agent_hooks.fleets.eng.mode"),
    ({"fleets": {"eng": {"mode": "monitor"}}, "agents": {}}, "unknown field 'agents'"),
    ({"fleets": "all"}, "agent_hooks.fleets"),
])
def test_put_fleets_validation(app, tenant, body, needle):
    tenant.post("/v1/tenant/me/hooks/enable", json={})
    r = tenant.put("/v1/tenant/me/hooks/fleets", json=body)
    assert r.status_code == 422 and any(needle in e for e in r.json()["detail"]["errors"]), r.text


def test_server_switch_is_reported(app, tenant, monkeypatch):
    monkeypatch.setenv("SHIELD_DEVICE_AGENT_HOOKS", "off")
    assert tenant.get("/v1/tenant/me/hooks/fleets").json()["disabled_by_server"] is True


# ── heartbeat state ──────────────────────────────────────────────────


@pytest.mark.parametrize("body", [
    {"agent_hooks": {"claude_code": {"state": "on"}}},
    {"agent_hooks": {"claude_code": {"state": "active", "settings_hash": "nope"}}},
    {"agent_hooks": {"claude_code": {"state": "error", "reason": "x" * 201}}},
    {"agent_hooks": "active"},
])
def test_heartbeat_hook_state_is_validated(app, tenant, body):
    d = _device(app, tenant, "eng")
    assert d.post("/v1/devices/heartbeat", json=body).status_code == 400


def test_heartbeat_ignores_coding_agents_it_does_not_know(app, tenant):
    d = _device(app, tenant, "eng")
    assert d.post("/v1/devices/heartbeat", json={"agent_hooks": {
        "claude_code": {"state": "active"}, "future_agent": {"state": "active"}}}).status_code == 204
    (row,) = dv.list_devices(tenant.tenant_id)["devices"]
    assert row["agent_hooks"] == {"claude_code": {"state": "active"}}


# ── overview ─────────────────────────────────────────────────────────


def test_overview_url_prefers_the_device_agent_url(app, tenant, monkeypatch):
    d = tenant.get("/v1/tenant/me/hooks/claude-code").json()
    assert d["shield_url_source"] == "request"
    monkeypatch.setenv("SHIELD_PUBLIC_URL", "https://public.example")
    assert tenant.get("/v1/tenant/me/hooks/claude-code").json()["shield_url"] == "https://public.example"
    monkeypatch.setenv("SHIELD_DEVICE_AGENT_SHIELD_URL", "https://api.example/")
    d = tenant.get("/v1/tenant/me/hooks/claude-code").json()
    assert (d["shield_url"], d["shield_url_source"]) == \
        ("https://api.example", "SHIELD_DEVICE_AGENT_SHIELD_URL")


def test_overview_names_agent_managed_laptops(app, tenant):
    tenant.post("/v1/tenant/me/hooks/enable", json={})
    tenant.put("/v1/tenant/me/hooks/fleets", json={"fleets": {"eng": {"mode": "monitor"}}})
    d = _device(app, tenant, "eng", "ana-mbp")
    d.post(HOOK, json=CALL)
    (row,) = tenant.get("/v1/tenant/me/hooks/claude-code").json()["laptops"]
    assert (row["hostname"], row["fleet"], row["monitor"], row["decision"]) == \
        ("ana-mbp", "eng", True, "deny")


# ── portal ───────────────────────────────────────────────────────────

HTML = open(os.path.join(ROOT, "static", "tenant.html")).read()
_START = HTML.index("// ── Coding agents on laptops")
SCRIPT = HTML[_START:HTML.index("// ── Device DLP (laptop agent)", _START)]


def test_card_wiring():
    for el in set(re.findall(r"getElementById\('(cc-[a-z-]+)'\)", SCRIPT)) | \
            set(re.findall(r"xfMsg\('(cc-[a-z-]+)'", SCRIPT)) | \
            set(re.findall(r"#(cc-[a-z-]+) ", SCRIPT)):
        assert f'id="{el}"' in HTML, el
    assert "ddApi('/hooks/enable', { method: 'POST'" in SCRIPT
    assert "ddApi('/hooks/fleets')" in SCRIPT
    assert "ddApi('/hooks/fleets', { method: 'PUT'" in SCRIPT
    for mode in ah.MODES:
        assert f"'{mode}'" in SCRIPT
    card = HTML[HTML.index('id="cc-card"'):]
    assert card.index('id="cc-fleets"') < card.index('id="cc-standalone"') < card.index('id="cc-key"')


def test_card_escapes_fleet_names_states_and_errors():
    for fn, nxt in (("function ccFleetRow", "async function ccSaveFleets"),
                    ("function ccStates", "async function ccFleets"),
                    ("function ccStatus", "async function ccEnable")):
        body = SCRIPT[SCRIPT.index(fn):SCRIPT.index(nxt)]
        safe = re.compile(r"^(xfEsc\(|DD_TD$|Number\(|CC_MODES\.map|opt\(|ccStates\(|v$|label$"
                          r"|v === cur|n$|s\[[01]\]$)")
        unsafe = [m.group(1) for m in re.finditer(r"\$\{((?:[^{}]|\{[^{}]*\})+)\}", body)
                  if not safe.match(m.group(1).strip())]
        assert unsafe == [], (fn, unsafe)


def test_agent_registry_form_has_the_runtime_profile():
    assert 'id="agent-modal-runtime-profile"' in HTML
    save = HTML[HTML.index("async function saveAgentFromModal"):]
    save = save[:save.index("\n}\n")]
    # Sent only once the list has loaded, so a failed load never clears a binding.
    assert "if (rpSel.dataset.loaded === '1') agentData.runtime_profile = rpSel.value;" in save
    assert HTML.count("agentModalProfiles(") == 3          # defined, on edit, on add
    fn = HTML[HTML.index("async function agentModalProfiles"):]
    fn = fn[:fn.index("\n}\n")]
    assert "xfEsc(n)" in fn and "sel.dataset.loaded = '1'" in fn


def test_registry_accepts_and_clears_the_binding(app, tenant):
    assert tenant.put("/v1/tenant/me/runtime-profiles/mine", json={}).status_code == 200
    tenant.post("/v1/agents/registry", json={"agent_id": "bot", "runtime_profile": "mine"})
    assert _agent(tenant, "bot")["runtime_profile"] == "mine"
    assert tenant.put("/v1/agents/registry/bot", json={"runtime_profile": ""}).status_code == 200
    assert _agent(tenant, "bot")["runtime_profile"] == ""
    assert tenant.put("/v1/agents/registry/bot",
                      json={"runtime_profile": "nope"}).status_code == 400
