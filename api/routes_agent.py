"""Agent checking routes — classification, scope, loops, budgets, delegation, monitoring."""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from guardrails.agentic.scope.action_classification import ActionClassificationGuardrail
from guardrails.agentic.scope.scope_boundaries import ScopeBoundariesGuardrail
from guardrails.agentic.scope.loop_detection import LoopDetectionGuardrail
from guardrails.agentic.scope.budget_controls import BudgetControlsGuardrail
from guardrails.agentic.scope.delegation_control import DelegationControlGuardrail
from guardrails.agentic.monitoring.chain_of_thought_monitoring import ChainOfThoughtMonitoringGuardrail
from guardrails.agentic.monitoring.context_window_guardrails import ContextWindowGuardrailsGuardrail

router = APIRouter(prefix="/v1/shield/agent", tags=["agent"])

_GUARDS = [
    ("action_classification", ActionClassificationGuardrail),
    ("scope_boundaries", ScopeBoundariesGuardrail),
    ("loop_detection", LoopDetectionGuardrail),
    ("budget_controls", BudgetControlsGuardrail),
    ("delegation_control", DelegationControlGuardrail),
    ("chain_of_thought_monitoring", ChainOfThoughtMonitoringGuardrail),
    ("context_window_guardrails", ContextWindowGuardrailsGuardrail),
]


class AgentCheckRequest(BaseModel):
    agent_key: str
    session_id: Optional[str] = None
    action_type: Optional[str] = None
    tool_name: Optional[str] = None
    tool_params_hash: Optional[str] = None
    error: Optional[bool] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    namespace: Optional[str] = None
    delegate_to: Optional[str] = None
    delegation_chain: Optional[list[str]] = None
    chain_of_thought: Optional[str] = None
    messages: Optional[list[dict]] = None
    total_tokens: Optional[int] = None
    max_context_tokens: Optional[int] = None
    system_prompt_hash: Optional[str] = None
    tokens_used: Optional[int] = None
    cost_usd: Optional[float] = None
    api_calls: Optional[int] = None
    guardrails: Optional[list[str]] = None


class BudgetRequest(BaseModel):
    agent_key: str
    session_id: Optional[str] = None


def _format(result):
    return {"guardrail": result.guardrail_name, "passed": result.passed,
            "action": result.action, "message": result.message,
            "details": result.details, "latency_ms": round(result.latency_ms, 2)}


def _should_run(name: str, body: AgentCheckRequest) -> bool:
    """Only run guardrails that have relevant context fields."""
    if name == "action_classification":
        return bool(body.action_type or body.tool_name)
    if name == "scope_boundaries":
        return bool(body.resource_type)
    if name == "loop_detection":
        return bool(body.session_id and body.tool_name)
    if name == "budget_controls":
        return bool(body.tokens_used or body.cost_usd or body.api_calls)
    if name == "delegation_control":
        return bool(body.delegate_to)
    if name == "chain_of_thought_monitoring":
        return bool(body.chain_of_thought)
    if name == "context_window_guardrails":
        return bool(body.messages or body.total_tokens)
    return True


@router.post("/check")
async def check_agent(body: AgentCheckRequest):
    context = body.model_dump(exclude_none=True)

    results = []
    for name, cls in _GUARDS:
        if body.guardrails and name not in body.guardrails:
            continue
        if not _should_run(name, body):
            continue
        guard = cls()
        if not guard.enabled:
            continue
        r = await guard.check("", context)
        results.append(_format(r))
        if not r.passed and r.action == "block":
            break

    allowed = all(r["passed"] or r["action"] not in ("block",) for r in results)
    action = "pass"
    for r in results:
        if not r["passed"]:
            action = r["action"]
            break

    return {"allowed": allowed, "action": action, "guardrail_results": results}


@router.post("/budget")
async def get_budget(body: BudgetRequest):
    """Return current budget usage for an agent."""
    from storage.state_store import agentic_state
    prefix = f"budget:{body.agent_key}:"
    keys = agentic_state.keys(prefix)
    usage = {}
    for key in keys:
        short_key = key.replace(prefix, "")
        usage[short_key] = agentic_state.get(key)

    if body.session_id:
        sess_prefix = f"budget:sess:{body.session_id}:"
        for key in agentic_state.keys(sess_prefix):
            short_key = f"session_{key.replace(sess_prefix, '')}"
            usage[short_key] = agentic_state.get(key)

    return {"agent_key": body.agent_key, "usage": usage}
