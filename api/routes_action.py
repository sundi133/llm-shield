"""Action checking routes for LLM Shield."""

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.agentic.action_guard import ActionGuard

router = APIRouter(prefix="/v1/shield/action", tags=["action"])


class ActionCheckRequest(BaseModel):
    agent_key: str
    session_id: str
    action_type: str
    action_details: dict = Field(default_factory=dict)
    approved: bool = False


@router.post("/check")
async def check_action(body: ActionCheckRequest):
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
    return {
        "allowed": result.passed,
        "action": result.action,
        "message": result.message,
        "details": result.details,
    }
