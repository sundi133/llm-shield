"""The prompt check on the hook routes (task 2 of
docs/specs/agent-hooks-prompt-check.md): UserPromptSubmit on
POST /v1/shield/hooks/claude-code and /codex.

The real app, a real tenant whose input custom policies are set when it is
created (the middleware caches tenant config per key), a runtime profile with
`before_prompt`. The custom policy guard is real; only its per-policy model
call is faked.
"""
import json
import uuid
from types import SimpleNamespace

import pytest

import core.runtime_policy.hook_policies as hp
from guardrails.input.custom_policy import CustomPolicyInputGuardrail
from tests.test_claude_code_hook_tool_policies import (  # noqa: F401  (fixtures)
    BASE_PROFILE, _clean, app, events)

PROMPT_POLICIES = {"before_prompt": True}
SECRET_WORD = "zebracorn" + "falcon77"


def _policy(pid, name, action="block"):
    return {"policy_id": pid, "name": name, "description": name, "prompt": f"{name} policy text",
            "action": action, "stage": "input", "enabled": True, "confidence_threshold": 0.8,
            "priority": 100}


ENCRYPT = _policy("pol-encrypt", "No file encryption")
PRICING = _policy("pol-pricing", "Pricing data", action="warn")


@pytest.fixture
def model(monkeypatch):
    """A policy is violated when the last word of its name is in the prompt."""
    asked = []

    async def fake(self, text, policy, context):
        asked.append(policy["policy_id"])
        hit = policy["name"].split()[-1].lower() in text.lower()
        return {"passed": not hit, "action": policy["action"] if hit else "pass",
                "confidence": 0.95, "suppressed": False, "error": None,
                "message": f"Custom input policy '{policy['name']}': matched",
                "details": {"policy_id": policy["policy_id"], "policy_name": policy["name"],
                            "violation_type": "x", "confidence": 0.95, "threshold": 0.8,
                            "reasoning": f"the request asks for this ({SECRET_WORD})"}}

    monkeypatch.setattr(CustomPolicyInputGuardrail, "_evaluate_policy_with_llm", fake)
    monkeypatch.setattr(hp, "_prompt_fail_closed", lambda tenant: False)
    return asked


def _tenant(app, *policies, tool_policies=PROMPT_POLICIES, mode=None):
    from starlette.testclient import TestClient
    from storage.tenant_store import create_tenant
    tid = "pc" + uuid.uuid4().hex[:10]
    key = "sk-pc-" + uuid.uuid4().hex
    cfg = {"name": tid, "plan": "enterprise", "input_guardrails": {"custom_policy_input": {
        "enabled": True, "action": "pass", "settings": {"policies": list(policies)}}}}
    if mode:
        cfg["policy_mode"] = mode
    create_tenant(tid, cfg, api_keys=[key])
    c = TestClient(app, headers={"X-API-Key": key})
    profile = dict(BASE_PROFILE, **({"tool_policies": tool_policies} if tool_policies else {}))
    assert c.put("/v1/tenant/me/runtime-profiles/laptop", json=profile).status_code == 200, \
        c.put("/v1/tenant/me/runtime-profiles/laptop", json=profile).text
    r = c.post("/v1/agents/registry", json={"agent_id": "claude-code", "tools": ["x"],
                                            "role_permissions": {"dev": ["x"]},
                                            "runtime_profile": "laptop"})
    assert r.status_code in (200, 201), r.text
    return SimpleNamespace(id=tid, c=c)


def _prompt(text, **extra):
    return {"session_id": "s-1", "cwd": "/Users/dev/proj", "hook_event_name": "UserPromptSubmit",
            "permission_mode": "default", "prompt": text, "prompt_id": "p-42", **extra}


def _send(t, body, target="claude-code"):
    return t.c.post(f"/v1/shield/hooks/{target}", content=json.dumps(body),
                    headers={"Content-Type": "application/json", "X-Agent-Key": "claude-code",
                             "X-Shield-User": "dev"})


# ── answers ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("target", ["claude-code", "codex"])
def test_a_blocked_prompt_is_refused_in_both_agents(app, model, events, target):
    t = _tenant(app, ENCRYPT)
    out = _send(t, _prompt("please do file encryption on a.txt"), target).json()
    assert out["decision"] == "block"
    assert out["reason"].startswith("Blocked by Votal Shield: No file encryption: ")
    assert model == ["pol-encrypt"]


def test_a_clean_prompt_gets_an_empty_answer(app, model, events):
    t = _tenant(app, ENCRYPT)
    assert _send(t, _prompt("explain how TLS works")).json() == {}
    assert events[-1]["detail"]["verdict"] == "allow"


def test_a_warning_is_a_note_for_claude_and_nothing_for_codex(app, model, events):
    t = _tenant(app, PRICING)
    out = _send(t, _prompt("show the pricing data")).json()
    assert out == {"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": "Votal Shield: this request falls under your organization's "
                             "policy (Pricing data). Follow that policy."}}
    assert _send(t, _prompt("show the pricing data"), "codex").json() == {}
    assert events[-1]["decision"] == "audit"


def test_the_answer_never_echoes_the_prompt(app, model, events):
    t = _tenant(app, ENCRYPT)
    out = _send(t, _prompt(f"file encryption for {SECRET_WORD}")).json()
    assert out["decision"] == "block" and SECRET_WORD not in json.dumps(out)


# ── the event ────────────────────────────────────────────────────────────


def test_the_event_names_the_policy_and_carries_no_prompt_text(app, model, events):
    t = _tenant(app, ENCRYPT)
    text = f"file encryption for {SECRET_WORD}"
    _send(t, _prompt(text))
    ev = events[-1]
    assert (ev["kind"], ev["decision"], ev["detail"]["verdict"]) == ("dlp", "deny", "block")
    d = ev["detail"]
    assert d["hook"] == "UserPromptSubmit" and d["prompt_check_policies"] == ["No file encryption"]
    assert d["prompt_len"] == len(text) and len(d["prompt_sha256"]) == 64
    assert d["prompt_id"] == "p-42" and d["user"] == "dev"
    assert "prompt" not in d and text not in json.dumps(ev) and SECRET_WORD not in json.dumps(ev)


def test_codex_turn_id_is_kept(app, model, events):
    t = _tenant(app, ENCRYPT)
    _send(t, {**_prompt("hello"), "turn_id": "turn-7"}, "codex")
    assert events[-1]["detail"]["turn_id"] == "turn-7"


# ── when it does not run ─────────────────────────────────────────────────


def test_a_profile_without_before_prompt_answers_nothing(app, model, events):
    t = _tenant(app, ENCRYPT, tool_policies={"before_call": True})
    assert _send(t, _prompt("file encryption")).json() == {}
    assert model == [] and events == []


def test_the_fleet_switch_turns_it_off(app, model, events, monkeypatch):
    t = _tenant(app, ENCRYPT)
    monkeypatch.setenv("SHIELD_HOOK_PROMPT_CHECK", "0")
    assert _send(t, _prompt("file encryption")).json() == {}
    assert model == []


def test_tenant_monitor_mode_lets_it_through_and_records_it(app, model, events):
    t = _tenant(app, ENCRYPT, mode="monitor")
    assert _send(t, _prompt("file encryption")).json() == {}
    d = events[-1]["detail"]
    assert (events[-1]["decision"], d["verdict"], d["would_decide"]) == ("audit", "monitor", "block")


def test_a_store_outage_follows_the_fail_setting(app, model, events, monkeypatch):
    """With the tenant's config unreadable, nothing was checked: that is not
    'no policies', so the fail setting decides."""
    t = _tenant(app, ENCRYPT)
    import storage.tenant_store as ts

    def down(*a, **k):
        raise ConnectionError("redis down")

    monkeypatch.setattr(ts, "get_tenant", down)
    # Drop the middleware's copy so the route has to read the store.
    import api.routes_hooks as rh
    orig = rh._user_prompt_submit

    async def without_middleware_config(request, *a, **k):
        request.state.tenant_config = None
        return await orig(request, *a, **k)

    monkeypatch.setattr(rh, "_user_prompt_submit", without_middleware_config)
    assert _send(t, _prompt("file encryption")).json() == {}
    assert events[-1]["detail"]["verdict"] == "uncertain" and model == []
    monkeypatch.setattr(hp, "_prompt_fail_closed", lambda tenant: True)
    out = _send(t, _prompt("file encryption")).json()
    assert out["decision"] == "block" and "could not run" in out["reason"]


@pytest.fixture
def device(monkeypatch):
    """A Votal device agent's key: tenant, device and fleet from the device
    record, the mode from the fleet's agent_hooks setting."""
    import core.dlp.agent_hooks as ah
    import core.dlp.devices as dv
    state = SimpleNamespace(tenant="", mode="enforce")
    monkeypatch.setattr(dv, "caller_device_cached",
                        lambda request: (state.tenant, "dev-1", {"fleet": "laptops"}))
    monkeypatch.setattr(ah, "setting_for", lambda tenant, fleet, agent: {
        "mode": state.mode, "agent": "claude-code", "on_unreachable": "allow"})
    return state


@pytest.mark.parametrize("mode, answer, decision, verdict", [
    ("enforce", "block", "deny", "block"),
    ("monitor", None, "audit", "monitor"),
])
def test_a_device_agent_caller_gets_the_tenants_policies_and_its_fleets_mode(
        app, model, events, device, mode, answer, decision, verdict):
    from starlette.testclient import TestClient
    t = _tenant(app, ENCRYPT)
    device.tenant, device.mode = t.id, mode
    out = TestClient(app).post("/v1/shield/hooks/claude-code",
                               json=_prompt("file encryption")).json()
    assert out.get("decision") == answer and model == ["pol-encrypt"]   # config read from the store
    ev = events[-1]
    assert (ev["decision"], ev["detail"]["verdict"], ev["detail"]["fleet"]) == (decision, verdict, "laptops")
    if mode == "monitor":
        assert ev["detail"]["would_decide"] == "deny"


def test_tool_calls_still_work_beside_the_prompt_check(app, model, events):
    t = _tenant(app, ENCRYPT, tool_policies={"before_prompt": True, "before_call": False})
    r = _send(t, {"session_id": "s-1", "cwd": "/Users/dev/proj", "hook_event_name": "PreToolUse",
                  "tool_name": "Bash", "tool_input": {"command": "openssl enc -in a -out b"},
                  "tool_use_id": "t1"})
    assert r.json()["hookSpecificOutput"]["permissionDecision"] == "deny"   # profile rule
