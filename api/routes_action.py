"""Action checking routes for LLM Shield."""

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.agentic.action_guard import ActionGuard
from storage.audit_log import audit_logger

router = APIRouter(prefix="/v1/shield/action", tags=["action"])


class ActionCheckRequest(BaseModel):
    agent_key: str
    session_id: str
    action_type: str
    action_details: dict = Field(default_factory=dict)
    approved: bool = False


@router.post("/check")
async def check_action(body: ActionCheckRequest, request: Request):
    """Check an agent action against policies.

    Returns allowed/denied with reason.
    """
    guard = ActionGuard()
    context = {
        "agent_key": body.agent_key,
        "session_id": body.session_id,
        "action_type": body.action_type,
        "action_details": body.action_details,
        "approved": body.approved,
    }
    result = await guard.check("", context)

    tenant_id = (getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None) or ""
    await audit_logger.log({
        "agent_key": body.agent_key or "",
        "endpoint": "/v1/shield/action/check",
        "input_text": f"action_check:{body.action_type}",
        "action_taken": result.action,
        "guardrails_triggered": ["action_guard"] if not result.passed else [],
        "latency_ms": round(result.latency_ms, 2),
        "metadata": {
            "kind": "agent_chat_telemetry",
            "tenant_id": tenant_id,
            "user_role": "",
            "stage": "action_check",
            "blocked": not result.passed and result.action == "block",
            "block_reason": result.message if not result.passed else None,
            "session_id": body.session_id or "",
            "tool_calls": [],
            "tool_call_count": 0,
            "input_guardrails": [{"guardrail": "action_guard", "passed": result.passed, "action": result.action, "message": result.message}],
            "output_guardrails": [],
            "usage": {},
        },
    })

    return {
        "allowed": result.passed,
        "action": result.action,
        "message": result.message,
        "details": result.details,
    }
