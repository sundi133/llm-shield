"""Standalone reproductions for four MCP Gateway findings from the 2026-09
product review (see LLM-Shield-Issues-Improvements.xlsx, rows LS-13..LS-16).

Run from the repo root:

    python -m pytest scripts/repro_mcp_gateway_findings.py -v -s

Each test asserts the CURRENT (buggy) behavior, so a PASS means the issue is
reproduced. They monkeypatch only at the same seams the repo's own tests use
(see tests/test_tool_output_action_authority.py and
tests/test_mcp_control_plane_parity.py), so no live Redis/LLM/upstream MCP
server is required. Not part of the pytest collection under `tests/` and not
named test_*.py at the tests/ root, so `python -m pytest tests -q` is
unaffected by this file.
"""
import asyncio
import pytest


# ── LS-13: output-sanitization fails open on any LLM backend error ──────────

def test_ls13_llm_error_leaks_raw_output(monkeypatch):
    import guardrails.agentic.tool.tool_output_sanitization as tos

    guard = tos.ToolOutputSanitizationGuardrail()
    guard._temp_config = {"enabled": True, "action": "block", "settings": {}}

    async def _boom(**kw):
        raise RuntimeError("upstream LLM 503")

    monkeypatch.setattr(tos, "async_llm_call", _boom)
    monkeypatch.setattr(
        tos.ToolOutputSanitizationGuardrail, "_load_policies_text",
        staticmethod(lambda tenant_id, tool_name="", user_role="":
                     "Block full customer profiles and SSNs."))

    secret_output = "ssn=784-1990-1234567-1 diagnosis=HIV+ balance=$482,110.44"
    result = asyncio.run(guard.check("", {
        "tool_name": "customer_profile_get",
        "tool_output": secret_output,
        "tenant_id": "acme",
        "user_role": "user",
    }))

    print("LS-13 result:", result.action, "| passed:", result.passed,
          "| sanitized_output leaked raw:", result.details.get("sanitized_output") == secret_output)

    # BUG: a transient LLM failure returns passed=True/action=pass and hands
    # back the UNREDACTED secret output, instead of blocking/withholding it.
    assert result.passed is True
    assert result.action == "pass"
    assert result.details.get("sanitized_output") == secret_output


# ── LS-14: wildcard block-all-except-role is bypassable via a spoofed role ──

def test_ls14_claimed_admin_role_defeats_wildcard_block():
    from guardrails.agentic.tool.payload_risk import _resolve_role_policies

    role_policies = [
        {"role": "*", "action": "block"},       # "block everyone by default"
        {"role": "admin", "action": "allow"},   # "except admin"
    ]

    # The gateway resolves user_role from the caller-supplied X-User-Role
    # header (api/routes_mcp_server.py::_resolve_identity) unless a
    # verified-identity middleware overrides it. Simulate an attacker who
    # simply sends `X-User-Role: admin`.
    spoofed_role = "admin"
    resolved = _resolve_role_policies(role_policies, spoofed_role)

    print("LS-14 resolved policy for spoofed role 'admin':", resolved)

    # BUG: nothing here verified the caller actually IS admin -- the string
    # "admin" alone is enough to win over the wildcard block.
    assert resolved[0]["action"] == "allow"
    assert resolved[0]["_role_match"] == "exact"


# ── LS-15: approval-required tools execute unapproved in default (monitor) mode ──

@pytest.mark.asyncio
async def test_ls15_approval_required_tool_runs_unapproved_by_default(monkeypatch):
    from core.mcp import enforcement

    monkeypatch.delenv("SHIELD_MCP_CONTROL_PLANE", raising=False)  # default = monitor
    assert enforcement._control_plane_mode() == "monitor"

    # Isolate from Redis/local-guard state the way the repo's own parity test
    # does: stub the guard chain empty, and stub the control-plane result to
    # a synthetic "approval_required" denial.
    monkeypatch.setattr(enforcement, "_tool_guard_chain", lambda: [])

    async def _fake_control_plane_results(tool_name, arguments, **kw):
        return [{
            "guardrail": "approval_required", "passed": False, "action": "block",
            "message": f"Tool '{tool_name}' requires human approval, which the "
                       f"MCP path cannot supply",
            "details": {"rule": {"tool_name": tool_name}},
        }]

    monkeypatch.setattr(enforcement, "_control_plane_results", _fake_control_plane_results)

    decision = await enforcement.enforce_tool_call(
        "wire_transfer", {"amount": 250000, "to_account": "attacker-controlled"},
        agent_key="agent-1", user_role="user", tenant_id="acme",
        tenant_config={},  # non-None so enforce_tool_call skips the tenant_store lookup
    )

    print("LS-15 decision:", decision)

    # BUG: a tool the control plane explicitly flagged as needing human
    # approval is nonetheless ALLOWED, because monitor mode rewrites the
    # denial to a log line instead of blocking it.
    assert decision["allowed"] is True
    assert decision["action"] == "pass"
    logged = [r for r in decision["results"] if r["guardrail"] == "approval_required"]
    assert logged and logged[0]["passed"] is True and logged[0]["action"] == "log"


# ── LS-16: policy-load failure silently reintroduces model-improvised policy ──

def test_ls16_storage_failure_runs_judge_with_no_real_policy(monkeypatch):
    from guardrails.agentic.tool import tool_output_sanitization as tos
    from guardrails.agentic.tool import payload_risk as pr

    def _boom_load(tenant_id, tool_name):
        raise ConnectionError("redis unavailable")

    monkeypatch.setattr(pr, "_load_data_policies", _boom_load)

    policies_text = tos.ToolOutputSanitizationGuardrail._load_policies_text(
        "acme", "customer_profile_get", "user")

    print(repr(f"LS-16 policies_text on storage failure: {policies_text!r}"))

    # BUG: this is meant to "fail closed by letting the caller run with no
    # policy text" per the code comment, but " " (a single space) is TRUTHY,
    # so the guard's `if not policies_text: return pass` short-circuit --
    # added specifically to stop the judge from inventing rules -- never
    # fires. The LLM judge runs anyway, with an empty/near-empty policy block.
    assert policies_text == " "
    assert bool(policies_text) is True  # truthy -> skip-judge branch is bypassed
