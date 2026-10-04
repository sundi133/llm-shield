"""Tool policies that fail safe, and say so (docs/specs/tool-policy-fail-safe.md,
task 1).

Before: when the model judging a tool call's arguments errored, timed out or
replied without a verdict, the call passed as "parameters valid", the same
result a clean call got. The only fail-closed switch was the deployment env, on
results only. Now a tenant chooses per policy (`fail_closed`), an unchecked
call is labelled, and the default policy's choice cannot be cancelled by a tool.
"""
import asyncio
import json

import pytest

import guardrails.agentic.tool.payload_risk as pr
import guardrails.agentic.tool.tool_call_validation as tcv
import guardrails.agentic.tool.tool_output_sanitization as tos
from guardrails.agentic.tool.payload_risk import fail_closed_for
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail

TENANT = "fail-safe-tenant"
TOOL = "send_email"
ARGS = {"to": "ops@acme.com", "body": "weekly report"}
RULE = {"role": "*", "action": "block", "input_rules": ["Only acme.com recipients"]}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("SHIELD_DLP_FAIL_CLOSED", "SHIELD_DLP_LLM_TIMEOUT_S",
              "SHIELD_DLP_CONFIDENCE_FLOOR", "SHIELD_GLOBAL_DATA_POLICY"):
        monkeypatch.delenv(k, raising=False)


class _FakeRedis:
    def __init__(self):
        self.store = {}
        self.reads = []

    def get(self, k):
        self.reads.append(k)
        return self.store.get(k)

    def set(self, k, v):
        self.store[k] = v


@pytest.fixture
def redis(monkeypatch):
    r = _FakeRedis()
    import storage.tenant_store as ts
    monkeypatch.setattr(ts, "_get_redis", lambda: r)
    return r


def _store(redis, **policies):
    redis.store[f"data_policies:{TENANT}"] = json.dumps(policies)


def _tool_policy(fail_closed=None, **extra):
    return {"role_policies": [RULE], "fail_closed": fail_closed, **extra}


def _default(fail_closed=None):
    return {"role_policies": [RULE], "enabled": True, "fail_closed": fail_closed}


def _model(monkeypatch, reply=None, error=None, seen=None):
    async def fake(**kw):
        if seen is not None:
            seen.append(kw)
        if error:
            raise error
        return {"choices": [{"message": {"content": reply}}]}
    monkeypatch.setattr(pr, "async_llm_call", fake)


def _check(args=ARGS, tool=TOOL, guard=None):
    g = guard or ToolCallValidationGuardrail()
    return asyncio.run(g.check("", {"tool_name": tool, "tool_params": args,
                                    "tenant_id": TENANT, "user_role": "support"}))


# ── the label: "not checked" is no longer "parameters valid" ─────────────


def test_a_model_error_is_labelled_not_checked_and_let_through(monkeypatch, redis):
    _store(redis, send_email=_tool_policy())
    _model(monkeypatch, error=TimeoutError("slow"))
    r = _check()
    assert r.passed is True and r.action == "warn"
    assert r.details == {"tool": TOOL, "unjudged": True, "fail_closed": False,
                         "error": "TimeoutError"}
    assert "let through" in r.message


def test_a_clean_verdict_is_still_a_plain_pass(monkeypatch, redis):
    """Regression guard: a call the model did judge must not carry the flag."""
    _store(redis, send_email=_tool_policy(fail_closed=True))
    _model(monkeypatch, "false,0.95,none,low,all parameters comply")
    r = _check()
    assert r.passed is True and r.action == "pass"
    assert not (r.details or {}).get("unjudged")


def test_a_violation_still_blocks_with_the_configured_action(monkeypatch, redis):
    _store(redis, send_email=_tool_policy())
    _model(monkeypatch, "true,0.95,external_exfiltration,high,recipient outside acme.com")
    r = _check()
    assert r.passed is False and r.action == "block"
    assert "unjudged" not in r.details


@pytest.mark.parametrize("reply", ["maybe,0.9,none,low,unsure", "", "I think it is fine.",
                                   "0.95,true,none,low,columns swapped"])
def test_a_reply_without_a_verdict_is_not_checked(monkeypatch, redis, reply):
    """It used to parse as "no violation" and pass."""
    _store(redis, send_email=_tool_policy(fail_closed=True))
    _model(monkeypatch, reply)
    r = _check()
    assert r.details["unjudged"] is True
    assert r.details["error"] == "PolicyCheckUnavailable"
    assert r.passed is False


def test_the_error_detail_never_carries_the_arguments_or_the_reply(monkeypatch, redis):
    _store(redis, send_email=_tool_policy())
    _model(monkeypatch, error=RuntimeError(f"upstream said {ARGS['body']}"))
    r = _check()
    assert ARGS["body"] not in json.dumps(r.details)
    assert ARGS["body"] not in r.message


def test_a_verdict_below_the_confidence_floor_is_still_allowed(monkeypatch, redis):
    """A low-confidence verdict is a judgment, not a failure."""
    _store(redis, send_email=_tool_policy(fail_closed=True))
    _model(monkeypatch, "true,0.5,pii,high,maybe")
    r = _check()
    assert r.passed is True and r.action == "pass"


# ── the switch: who decides ──────────────────────────────────────────────


@pytest.mark.parametrize("stored, env, blocks", [
    ({"send_email": _tool_policy()}, False, False),                       # nothing set
    ({"send_email": _tool_policy(fail_closed=True)}, False, True),        # the tool says block
    ({"__global__": _default(True)}, False, True),                        # the default says block
    ({"__global__": _default(True),
      "send_email": _tool_policy(fail_closed=False)}, False, True),       # a tool cannot cancel it
    ({"__global__": _default(True),
      "send_email": _tool_policy(fail_closed=False,
                                 inherit_global=False)}, False, False),   # the explicit opt-out
    ({"__global__": {**_default(True), "enabled": False}}, False, False),  # default turned off
    ({}, True, True),                                                      # env, no policy at all
    ({}, False, False),                                                    # no policy, env off
    ({"send_email": _tool_policy(fail_closed=False)}, True, True),        # env is the floor
])
def test_who_decides(monkeypatch, redis, stored, env, blocks):
    if env:
        monkeypatch.setenv("SHIELD_DLP_FAIL_CLOSED", "on")
    _store(redis, **stored)
    _model(monkeypatch, error=ConnectionError("refused"))
    r = _check()
    assert r.details["fail_closed"] is blocks
    assert r.passed is (not blocks)
    assert r.action == ("block" if blocks else "warn")


def test_a_block_uses_the_guards_configured_action(monkeypatch, redis):
    """A check that could not run is never stricter than one that found a
    violation."""
    _store(redis, send_email=_tool_policy(fail_closed=True))
    _model(monkeypatch, error=TimeoutError())
    g = ToolCallValidationGuardrail()
    monkeypatch.setattr(type(g), "configured_action", property(lambda self: "warn"))
    r = _check(guard=g)
    assert r.passed is False and r.action == "warn"


def test_the_switch_round_trips_through_the_loader(redis):
    _store(redis, __global__=_default(True), send_email=_tool_policy(fail_closed=False))
    loaded = pr._load_data_policies(TENANT, TOOL)
    assert [(p["policy_source"], p["fail_closed"]) for p in loaded] == [
        ("global", True), ("tool", False)]


def test_fail_closed_for_unread_policies_falls_back_to_the_env(monkeypatch):
    assert fail_closed_for(None) is False
    monkeypatch.setenv("SHIELD_DLP_FAIL_CLOSED", "on")
    assert fail_closed_for(None) is True


def test_the_api_accepts_and_stores_the_switch():
    from api.routes_data_policies import GlobalDataPolicy, ToolDataPolicy
    assert ToolDataPolicy(tool_name=TOOL, fail_closed=True).model_dump()["fail_closed"] is True
    assert GlobalDataPolicy(fail_closed=True).model_dump()["fail_closed"] is True
    assert ToolDataPolicy(tool_name=TOOL).model_dump()["fail_closed"] is None


# ── the time limit and the latency contract ──────────────────────────────


def test_the_tool_call_check_is_bounded(monkeypatch, redis):
    """It passed no timeout, so a stalled model held a tool call for 300 s."""
    _store(redis, send_email=_tool_policy())
    seen = []
    _model(monkeypatch, "false,0.9,none,low,ok", seen=seen)
    _check()
    assert seen[-1]["timeout"] == 60.0
    monkeypatch.setenv("SHIELD_DLP_LLM_TIMEOUT_S", "7")
    _check()
    assert seen[-1]["timeout"] == 7.0


def test_the_guard_reads_the_policy_store_once(monkeypatch, redis):
    """The switch rides on the read the model's rules already needed."""
    _store(redis, __global__=_default(True), send_email=_tool_policy())
    _model(monkeypatch, error=TimeoutError())
    _check()
    assert redis.reads == [f"data_policies:{TENANT}"]


# ── the result side: same switch ─────────────────────────────────────────


def _sanitize(monkeypatch):
    async def boom(**kw):
        raise TimeoutError("slow")
    monkeypatch.setattr(tos, "async_llm_call", boom)
    return asyncio.run(ToolOutputSanitizationGuardrail()._check_inner("", {
        "tool_output": "customer note: call back tomorrow", "tool_name": TOOL,
        "tenant_id": TENANT, "user_role": "support"}))


def test_a_result_check_that_fails_is_labelled_and_delivered_by_default(monkeypatch, redis):
    _store(redis, send_email=_tool_policy(sanitization_intent="no account numbers"))
    r = _sanitize(monkeypatch)
    assert r.passed is True and r.action == "warn"
    assert r.details["unjudged"] is True and r.details["fail_closed"] is False


def test_a_result_check_that_fails_blocks_when_the_default_says_so(monkeypatch, redis):
    _store(redis, __global__=_default(True),
           send_email=_tool_policy(sanitization_intent="no account numbers"))
    r = _sanitize(monkeypatch)
    assert r.passed is False and r.action == "block"
    assert r.details["unjudged"] is True and r.details["fail_closed"] is True
    assert r.details["sanitized_output"] == "[CONTENT BLOCKED DUE TO DATA POLICY]"
    assert "SHIELD_DLP_FAIL_CLOSED" not in r.message


def test_the_env_still_blocks_results_with_its_own_message(monkeypatch, redis):
    monkeypatch.setenv("SHIELD_DLP_FAIL_CLOSED", "on")
    _store(redis, send_email=_tool_policy(sanitization_intent="no account numbers"))
    r = _sanitize(monkeypatch)
    assert r.action == "block" and "SHIELD_DLP_FAIL_CLOSED=on" in r.message


# ── end to end: a blocked call never reaches the tool (outcome 6) ────────


class _Upstream:
    def __init__(self):
        self.calls = []

    async def list_tools(self):
        return [{"name": TOOL, "description": "send an email"}]

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {"ok": True}


def _through_the_gateway(monkeypatch, redis, stored, tenant_config=None):
    from storage.tenant_store import kv_set
    from core.mcp.proxy_server import MCPProxy
    agent = "mailer"
    _store(redis, **stored)
    kv_set(f"agents:{TENANT}", {agent: {
        "agent_id": agent, "tools": [TOOL],
        "role_permissions": {"support": [TOOL]}, "status": "active"}})
    _model(monkeypatch, error=ConnectionError("model down"))

    async def boom(**kw):
        raise ConnectionError("model down")
    monkeypatch.setattr(tos, "async_llm_call", boom)
    up = _Upstream()
    res = asyncio.run(MCPProxy(up).call_tool(
        TOOL, ARGS, agent_key=agent, user_role="support", tenant_id=TENANT,
        tenant_config=tenant_config))
    return res, up


def test_a_model_outage_blocks_before_the_tool_runs(monkeypatch, redis):
    res, up = _through_the_gateway(monkeypatch, redis, {"__global__": _default(True)})
    assert res["isError"] is True
    assert up.calls == []                                     # never executed


def test_a_model_outage_lets_the_call_through_by_default(monkeypatch, redis):
    res, up = _through_the_gateway(monkeypatch, redis, {"send_email": _tool_policy()})
    assert res["isError"] is False
    assert up.calls == [(TOOL, ARGS)]


def test_a_monitor_tenant_logs_the_call_block_instead(monkeypatch, redis):
    """Monitor mode applies to the call: it runs, and the block is reported.

    The RESULT is still withheld. sanitize_tool_result does not read
    policy_mode for any block, real violation or not; that predates this
    change and is recorded in the spec as a follow-up."""
    res, up = _through_the_gateway(monkeypatch, redis, {"__global__": _default(True)},
                                   tenant_config={"policy_mode": "monitor"})
    assert up.calls == [(TOOL, ARGS)]
    assert "tool_call_validation" in res["shield"]["would_block"]


# ── the dry run says "not checked", never "allowed" ──────────────────────


def test_try_reports_not_checked_for_a_reply_without_a_verdict(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import api.routes_data_policies as rdp
    app = FastAPI()
    app.dependency_overrides[rdp.get_tenant_from_request] = lambda: TENANT
    app.include_router(rdp.router)
    _model(monkeypatch, "sure, looks fine to me")
    body = TestClient(app).post("/v1/data-policies/try", json={
        "policy": {"role_policies": [RULE]}, "tool_name": TOOL, "arguments": ARGS}).json()
    assert body["decision"] == "not_checked"
