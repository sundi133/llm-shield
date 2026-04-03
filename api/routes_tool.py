"""Tool checking routes — pre-execution validation, output sanitization, confirmation."""

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.agentic.tool.tool_allowlist import ToolAllowlistGuardrail
from guardrails.agentic.tool.tool_use_control import ToolUseControlGuardrail
from guardrails.agentic.tool.tool_call_rate_limiting import ToolCallRateLimitingGuardrail
from guardrails.agentic.tool.tool_call_validation import ToolCallValidationGuardrail
from guardrails.agentic.tool.tool_output_sanitization import ToolOutputSanitizationGuardrail
from guardrails.agentic.tool.sensitive_action_confirmation import SensitiveActionConfirmationGuardrail

router = APIRouter(prefix="/v1/shield/tool", tags=["tool"])

_CHECK_GUARDS = [
    ("tool_allowlist", ToolAllowlistGuardrail),
    ("tool_use_control", ToolUseControlGuardrail),
    ("tool_call_rate_limiting", ToolCallRateLimitingGuardrail),
    ("tool_call_validation", ToolCallValidationGuardrail),
    ("sensitive_action_confirmation", SensitiveActionConfirmationGuardrail),
]


class ToolCheckRequest(BaseModel):
    agent_key: str
    tool_name: str
    session_id: Optional[str] = None
    tool_params: Optional[dict] = None
    tool_schema: Optional[dict] = None
    workflow: Optional[str] = None
    confirmation_token: Optional[str] = None
    guardrails: Optional[list[str]] = None


class ToolOutputRequest(BaseModel):
    tool_name: str
    tool_output: str
    agent_key: Optional[str] = None
    session_id: Optional[str] = None


class ToolConfirmRequest(BaseModel):
    session_id: str
    confirmation_token: str
    tool_name: str = ""


def _format(result):
    return {"guardrail": result.guardrail_name, "passed": result.passed,
            "action": result.action, "message": result.message,
            "details": result.details, "latency_ms": round(result.latency_ms, 2)}


@router.post("/check")
async def check_tool(body: ToolCheckRequest):
    context = {
        "agent_key": body.agent_key,
        "tool_name": body.tool_name,
        "session_id": body.session_id,
        "tool_params": body.tool_params or {},
        "tool_schema": body.tool_schema,
        "workflow": body.workflow,
        "confirmation_token": body.confirmation_token,
    }
    results = []
    for name, cls in _CHECK_GUARDS:
        if body.guardrails and name not in body.guardrails:
            continue
        guard = cls()
        if not guard.enabled:
            continue
        r = await guard.check("", context)
        results.append(_format(r))
        if not r.passed and r.action == "block":
            break  # early exit

    allowed = all(r["passed"] or r["action"] not in ("block", "pending_confirmation") for r in results)
    action = "pass"
    for r in results:
        if not r["passed"]:
            action = r["action"]
            break

    return {"allowed": allowed, "action": action, "guardrail_results": results}


@router.post("/output")
async def check_tool_output(body: ToolOutputRequest):
    guard = ToolOutputSanitizationGuardrail()
    context = {
        "tool_name": body.tool_name,
        "tool_output": body.tool_output,
        "agent_key": body.agent_key,
        "session_id": body.session_id,
    }
    r = await guard.check(body.tool_output, context)
    sanitized = (r.details or {}).get("sanitized_output", body.tool_output)
    return {
        "allowed": r.passed,
        "action": r.action,
        "sanitized_output": sanitized,
        "guardrail_results": [_format(r)],
    }


@router.post("/confirm")
async def confirm_tool(body: ToolConfirmRequest):
    guard = SensitiveActionConfirmationGuardrail()
    context = {
        "session_id": body.session_id,
        "confirmation_token": body.confirmation_token,
        "tool_name": body.tool_name,
        "agent_key": "",
    }
    r = await guard.check("", context)
    return {"allowed": r.passed, "action": r.action, "message": r.message, "details": r.details}
