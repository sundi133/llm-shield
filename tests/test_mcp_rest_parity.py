"""MCP <-> REST guardrail parity (HR agent QA report findings 1-4).

The MCP tool handlers must delegate to the SAME logic as the REST endpoints,
with tenant context populated, so a block on direct REST is a block on MCP.
These tests mock the delegated REST handlers so they run without a model.
"""
import asyncio
from types import SimpleNamespace

from starlette.datastructures import Headers

import api.routes_mcp_server as mcp


class _Req:
    def __init__(self, headers=None, **state):
        self.headers = Headers(headers or {})
        self.state = SimpleNamespace(**state)


def _call(name, args, req=None):
    return asyncio.run(mcp._handle_tool_call(name, args, req or _Req(tenant_id="acme")))


# ── _is_blocked: every signal the REST responses use ────────────────────
def test_is_blocked_signals():
    assert mcp._is_blocked({"safe": False}) is True
    assert mcp._is_blocked({"action": "block"}) is True               # safe absent — Finding 1/2
    assert mcp._is_blocked({"guardrail_results": [{"passed": False, "action": "block"}]}) is True
    assert mcp._is_blocked({"safe": True, "action": "pass"}) is False
    assert mcp._is_blocked({"guardrail_results": [{"passed": True}]}) is False


# ── Finding 1: input block signalled by action=block (no safe key) ──────
def test_check_input_blocks_on_action_block(monkeypatch):
    async def fake_classify(request, body):
        return {"action": "block", "guardrail_results": [
            {"guardrail": "topic_relevance", "passed": False, "action": "block", "message": "off-topic"}]}
    monkeypatch.setattr("api.routes_classify.classify", fake_classify)
    out = _call("shield_check_input", {"message": "what is my account balance?"})
    assert out.startswith("BLOCKED")
    assert "topic_relevance" in out


def test_check_input_safe(monkeypatch):
    monkeypatch.setattr("api.routes_classify.classify",
                        lambda request, body: _async({"safe": True}))
    assert _call("shield_check_input", {"message": "hi"}).startswith("SAFE")


# ── Finding 2: output block ──────────────────────────────────────────────
def test_check_output_blocks(monkeypatch):
    monkeypatch.setattr("api.routes_classify_output.classify_output",
                        lambda request, body: _async({"safe": False}))
    assert _call("shield_check_output", {"output": "SSN 521-44-9087"}).startswith("BLOCKED")


# ── Finding 3: tool check delegates to the full pipeline ─────────────────
def test_check_tool_delegates_and_blocks(monkeypatch):
    seen = {}
    async def fake_check_tool(body, request):
        seen["body"] = body
        return {"allowed": False, "guardrail_results": [
            {"guardrail": "data_access_guard", "passed": False, "action": "block",
             "message": "external recipient domain"}]}
    monkeypatch.setattr("api.routes_tool.check_tool", fake_check_tool)
    out = _call("shield_check_tool", {
        "tool_name": "send_hr_email", "user_role": "manager",
        "arguments": {"to": "qa@gmail.com", "subject": "QA", "body": "hello"}})
    assert out.startswith("BLOCKED")
    assert seen["body"].tool_name == "send_hr_email"
    assert seen["body"].user_role == "manager"
    assert seen["body"].tool_params == {"to": "qa@gmail.com", "subject": "QA", "body": "hello"}


def test_check_tool_allows(monkeypatch):
    monkeypatch.setattr("api.routes_tool.check_tool",
                        lambda body, request: _async({"allowed": True}))
    assert _call("shield_check_tool", {"tool_name": "lookup_employee"}).startswith("ALLOWED")


# ── Finding 4 (critical): sanitize uses tool-output DLP, blocks sensitive ─
def test_sanitize_output_blocks_via_tool_output_dlp(monkeypatch):
    seen = {}
    async def fake_tool_output(body, request):
        seen["body"] = body
        return {"allowed": False}   # ToolOutputSanitizationGuardrail blocked
    monkeypatch.setattr("api.routes_tool.check_tool_output", fake_tool_output)
    out = _call("shield_sanitize_output", {
        "tool_name": "lookup_employee", "output": "ssn=521-44-9087, dob=1991-03-14"})
    assert out.startswith("BLOCKED")
    assert seen["body"].tool_name == "lookup_employee"
    assert seen["body"].tool_output == "ssn=521-44-9087, dob=1991-03-14"


def test_sanitize_output_sanitized(monkeypatch):
    monkeypatch.setattr("api.routes_tool.check_tool_output",
                        lambda body, request: _async({"allowed": True, "sanitized_output": "ssn=[REDACTED]"}))
    out = _call("shield_sanitize_output", {"tool_name": "lookup_employee", "output": "ssn=521-44-9087"})
    assert out.startswith("SANITIZED") and "[REDACTED]" in out


def test_sanitize_output_clean(monkeypatch):
    monkeypatch.setattr("api.routes_tool.check_tool_output",
                        lambda body, request: _async({"allowed": True}))
    assert _call("shield_sanitize_output", {"tool_name": "x", "output": "name=Jane"}).startswith("CLEAN")


# ── Tenant context is populated so delegated handlers apply policy ───────
def test_populate_request_state_loads_tenant_config(monkeypatch):
    monkeypatch.setattr("storage.tenant_store.get_tenant",
                        lambda tid: {"input_guardrails": {"x": {}}})
    req = _Req(tenant_id="acme")
    mcp._populate_request_state(req, "acme", "agent1", "manager")
    assert req.state.tenant_config == {"input_guardrails": {"x": {}}}
    assert req.state.agent_key == "agent1"
    assert req.state.user_role == "manager"


def _async(value):
    async def _f():
        return value
    return _f()
