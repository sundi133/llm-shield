"""Prefill optimization: data-policy guards must put the stable policy text in the
SYSTEM message (vLLM prefix-cached) and only the variable tool data in the user
message — without dropping any information or changing the verdict.
"""
import asyncio

from guardrails.agentic.tool import tool_output_sanitization as tos
from guardrails.agentic.tool import payload_risk as pr
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail


def _run(coro):
    return asyncio.run(coro)


# --- tool_output_sanitization (OUTPUT DLP) -------------------------------

def test_output_sanitization_policy_in_system_output_in_user(monkeypatch):
    captured = {}

    async def fake_llm(messages, **kwargs):
        captured["messages"] = messages
        return {"choices": [{"message": {"content": "true,block,0.95,ssn found"}}]}

    monkeypatch.setattr(tos, "async_llm_call", fake_llm)
    monkeypatch.setattr(ToolOutputSanitizationGuardrail, "_load_policies_text",
                        staticmethod(lambda tenant_id, tool_name="": "POLICY_MARKER redact ssn for employee"))

    res = _run(ToolOutputSanitizationGuardrail().check(
        "", {"tool_name": "lookup_employee", "tool_output": "ssn=123-45-6789 UNIQUE_OUT",
             "tenant_id": "t1", "user_role": "employee"}))

    sys_msg = captured["messages"][0]["content"]
    usr_msg = captured["messages"][1]["content"]
    # policy lives in the cacheable system prefix
    assert "POLICY_MARKER" in sys_msg
    assert "Data policies:" in sys_msg
    # variable output lives in the user message, NOT the system prefix
    assert "UNIQUE_OUT" in usr_msg
    assert "UNIQUE_OUT" not in sys_msg
    # no information dropped: tool + role still present
    assert "lookup_employee" in usr_msg and "employee" in usr_msg
    # verdict unchanged: block CSV -> blocked
    assert res.passed is False and res.action == "block"


def test_output_sanitization_fail_open_unchanged(monkeypatch):
    async def boom(messages, **kwargs):
        raise RuntimeError("backend down")
    monkeypatch.setattr(tos, "async_llm_call", boom)
    monkeypatch.setattr(ToolOutputSanitizationGuardrail, "_load_policies_text",
                        staticmethod(lambda tenant_id, tool_name="": "p"))
    res = _run(ToolOutputSanitizationGuardrail().check(
        "", {"tool_name": "x", "tool_output": "data", "tenant_id": "t1"}))
    assert res.passed is True  # still fails open


# --- payload_risk (INPUT/params DLP, also used by tool_call_validation) ---

def test_payload_risk_policy_in_system_params_in_user(monkeypatch):
    captured = {}

    async def fake_llm(messages, **kwargs):
        captured["messages"] = messages
        return {"choices": [{"message": {"content": "true,0.95,exfiltration,high,bad recipient"}}]}

    monkeypatch.setattr(pr, "async_llm_call", fake_llm)
    # pin the rendered policy text so we can assert it lands in the system prefix
    monkeypatch.setattr(pr, "_format_data_policies", lambda dp, tid, tool_name="": "POLICY_MARKER no external")

    out = _run(pr.evaluate_payload_policy_llm(
        tool_name="send_payment",
        payload={"to": "attacker@evil.com", "marker": "UNIQUE_PARAM"},
        tenant_id="t1", user_role="employee",
        data_policies=[{"field": "recipient", "action": "block"}],
    ))

    sys_msg = captured["messages"][0]["content"]
    usr_msg = captured["messages"][1]["content"]
    # policy + static "check for" guidance in the cacheable system prefix
    assert "POLICY_MARKER" in sys_msg
    assert "Check for:" in sys_msg
    # variable params in the user message, not the prefix
    assert "UNIQUE_PARAM" in usr_msg
    assert "UNIQUE_PARAM" not in sys_msg
    assert "send_payment" in usr_msg
    # verdict unchanged: violation surfaced
    assert out is not None and out["details"]["risk_type"] == "exfiltration"


def test_payload_risk_no_violation_returns_none(monkeypatch):
    async def fake_llm(messages, **kwargs):
        return {"choices": [{"message": {"content": "false,0.9,none,low,ok"}}]}
    monkeypatch.setattr(pr, "async_llm_call", fake_llm)
    out = _run(pr.evaluate_payload_policy_llm(
        tool_name="get_balance", payload={"id": "1"}, tenant_id="t1", user_role="employee"))
    assert out is None
