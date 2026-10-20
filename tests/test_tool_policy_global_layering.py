"""The tenant-wide default tool policy (``__global__``) applies on every path
that judges tool data, and a tool can opt out with ``inherit_global: false``.

Before: /guardrails/output with a tool context (tool argument and result
redaction) loaded only the tool's own policy, so the default covered
tool/check and tool/output but not this path; and ``inherit_global`` was read
by the engine but dropped by the API model, so it could not be set.
Spec: docs/spec-global-tool-data-policy.md
"""

import asyncio
import json

import pytest

import api.routes_classify_output as rco

SSN = "123-45-6789"
SSN_RULE = {"pattern_id": "us_ssn", "regex": r"\b\d{3}-\d{2}-\d{4}\b", "replacement": "[SSN]",
            "description": "US SSN", "severity": "high", "action": "redact", "enabled": True}
KEY_RULE = {"pattern_id": "api_key", "regex": r"\bsk_live_[A-Za-z0-9]{8,}\b", "replacement": "[KEY]",
            "description": "API key", "severity": "high", "action": "redact", "enabled": True}


class FakeRedis:
    def __init__(self):
        self.kv = {}

    def get(self, k):
        return self.kv.get(k)

    def set(self, k, v, *a, **kw):
        self.kv[k] = v
        return True


@pytest.fixture
def redis(monkeypatch):
    import storage.tenant_store as ts
    r = FakeRedis()
    monkeypatch.setattr(ts, "_get_redis", lambda: r)
    monkeypatch.delenv("SHIELD_GLOBAL_DATA_POLICY", raising=False)
    return r


def store(r, policies, tenant="t1"):
    r.kv[f"data_policies:{tenant}"] = json.dumps(policies)


def sanitize(text, tool="send_email", stage="input"):
    block, sanitized, meta = asyncio.run(rco._apply_tool_sanitization("t1", tool, text, stage))
    return block, (sanitized if sanitized is not None else text), meta


def test_a_tool_with_no_policy_gets_the_default(redis):
    store(redis, {"__global__": {"sanitization_rules": [SSN_RULE], "enabled": True}})
    _, out, _ = sanitize(f"ssn {SSN}")
    assert SSN not in out and "[SSN]" in out
    _, out, _ = sanitize(f"ssn {SSN}", stage="output")
    assert SSN not in out


def test_a_tool_policy_adds_to_the_default(redis):
    store(redis, {"__global__": {"sanitization_rules": [SSN_RULE]},
                  "send_email": {"sanitization_rules": [KEY_RULE]}})
    _, out, meta = sanitize(f"ssn {SSN} key sk_live_ABCDEFGH12")
    assert SSN not in out and "sk_live_ABCDEFGH12" not in out
    assert meta.get("layers") == ["default", "tool"]


def test_a_tools_allowlist_does_not_exempt_values_from_the_default(redis):
    """Each layer keeps its own allowlist: the tool's cannot weaken the default."""
    store(redis, {"__global__": {"sanitization_rules": [SSN_RULE]},
                  "send_email": {"sanitization_rules": [KEY_RULE],
                                 "allowlist": [{"value": SSN, "reason": "test record"}]}})
    _, out, _ = sanitize(f"ssn {SSN}")
    assert SSN not in out


def test_the_defaults_allowlist_still_applies_to_its_own_rules(redis):
    store(redis, {"__global__": {"sanitization_rules": [SSN_RULE],
                                 "allowlist": [{"value": SSN, "reason": "published test SSN"}]}})
    _, out, _ = sanitize(f"ssn {SSN}")
    assert SSN in out


def test_inherit_global_false_is_judged_by_its_own_rules_alone(redis):
    store(redis, {"__global__": {"sanitization_rules": [SSN_RULE]},
                  "crm_lookup": {"sanitization_rules": [KEY_RULE], "inherit_global": False}})
    _, out, meta = sanitize(f"ssn {SSN} key sk_live_ABCDEFGH12", tool="crm_lookup")
    assert SSN in out and "sk_live_ABCDEFGH12" not in out and "layers" not in meta


@pytest.mark.parametrize("switch", ["env", "enabled"])
def test_the_default_can_be_switched_off(redis, monkeypatch, switch):
    glob = {"sanitization_rules": [SSN_RULE]}
    if switch == "env":
        monkeypatch.setenv("SHIELD_GLOBAL_DATA_POLICY", "off")
    else:
        glob["enabled"] = False
    store(redis, {"__global__": glob})
    _, out, _ = sanitize(f"ssn {SSN}")
    assert SSN in out


def test_no_policy_at_all_changes_nothing(redis):
    _, out, meta = sanitize(f"ssn {SSN}")
    assert out == f"ssn {SSN}" and not meta["applied"]


def test_plain_language_rules_are_joined_into_one_model_pass(redis, monkeypatch):
    import api.routes_data_policies as rdp
    calls = []

    async def fake_ai(**kw):
        calls.append(kw["intent"])
        return {"verdict": "pass", "reasoning": "", "redactions": []}
    monkeypatch.setattr(rdp, "_run_ai_sanitization", fake_ai)
    store(redis, {"__global__": {"sanitization_intent": "Never leak credentials.", "sanitization_mode": "ai"},
                  "send_email": {"sanitization_intent": "Never send account numbers.",
                                 "sanitization_mode": "both", "sanitization_rules": [KEY_RULE]}})
    sanitize("hello")
    assert len(calls) == 1
    assert "Never leak credentials." in calls[0] and "Never send account numbers." in calls[0]


def test_a_regex_only_layer_does_not_run_rules_from_an_ai_only_layer(redis):
    """A layer in `ai` mode contributes its intent, not its regex rules."""
    store(redis, {"__global__": {"sanitization_rules": [SSN_RULE], "sanitization_mode": "ai",
                                 "sanitization_intent": ""},
                  "send_email": {"sanitization_rules": [KEY_RULE]}})
    _, out, _ = sanitize(f"ssn {SSN} key sk_live_ABCDEFGH12")
    assert SSN in out and "sk_live_ABCDEFGH12" not in out


# ── the API: inherit_global can now be set ────────────────────────────


@pytest.fixture
def api(redis, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import api.routes_data_policies as rdp
    import core.auth as auth
    a = FastAPI()
    a.include_router(rdp.router)
    a.dependency_overrides[rdp.get_tenant_from_request] = lambda: "t1"
    monkeypatch.setattr(rdp, "require_config_write", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(auth, "require_config_write", lambda *a, **k: None)
    monkeypatch.setattr(auth, "require_registry_write", lambda *a, **k: None)
    monkeypatch.setattr(rdp, "_get_redis", lambda: redis, raising=False)
    return TestClient(a)


def test_inherit_global_is_saved_returned_and_honoured(api, redis):
    r = api.post("/v1/data-policies/tools/crm_lookup/policy",
                 json={"tool_name": "crm_lookup", "sanitization_rules": [KEY_RULE], "inherit_global": False})
    assert r.status_code == 200, r.text
    stored = json.loads(redis.kv["data_policies:t1"])["crm_lookup"]
    assert stored["inherit_global"] is False
    got = api.get("/v1/data-policies/tools/crm_lookup/policy").json()
    assert json.dumps(got).count('"inherit_global": false') == 1

    from guardrails.agentic.tool.payload_risk import _load_data_policies
    data = json.loads(redis.kv["data_policies:t1"])
    data["__global__"] = {"sanitization_rules": [SSN_RULE], "enabled": True}
    redis.kv["data_policies:t1"] = json.dumps(data)
    sources = [p.get("policy_source") or p.get("tool_name") for p in _load_data_policies("t1", "crm_lookup")]
    assert sources == ["tool"]                               # no default beneath it
    assert len(_load_data_policies("t1", "other_tool")) == 1  # the default still covers other tools


def test_inherit_global_defaults_to_true(api, redis):
    api.post("/v1/data-policies/tools/send_email/policy",
             json={"tool_name": "send_email", "sanitization_rules": [KEY_RULE]})
    assert json.loads(redis.kv["data_policies:t1"])["send_email"]["inherit_global"] is True
