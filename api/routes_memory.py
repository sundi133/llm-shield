"""Memory checking routes — access control, PII scrubbing, injection detection, retention."""

from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional

from guardrails.agentic.memory.memory_access_control import MemoryAccessControlGuardrail
from guardrails.agentic.memory.memory_guardrails import MemoryGuardrailsGuardrail
from guardrails.agentic.memory.memory_pii_scrubbing import MemoryPIIScrrubbingGuardrail
from guardrails.agentic.memory.memory_injection_detection import MemoryInjectionDetectionGuardrail
from guardrails.agentic.memory.memory_retention_policies import MemoryRetentionPoliciesGuardrail
from storage.audit_log import audit_logger

router = APIRouter(prefix="/v1/shield/memory", tags=["memory"])

# Write pipeline: access_control → general → pii_scrubbing → retention
_WRITE_GUARDS = [
    ("memory_access_control", MemoryAccessControlGuardrail),
    ("memory_guardrails", MemoryGuardrailsGuardrail),
    ("memory_pii_scrubbing", MemoryPIIScrrubbingGuardrail),
    ("memory_retention_policies", MemoryRetentionPoliciesGuardrail),
]

# Read pipeline: access_control → general → injection_detection → retention
_READ_GUARDS = [
    ("memory_access_control", MemoryAccessControlGuardrail),
    ("memory_guardrails", MemoryGuardrailsGuardrail),
    ("memory_injection_detection", MemoryInjectionDetectionGuardrail),
    ("memory_retention_policies", MemoryRetentionPoliciesGuardrail),
]


class MemoryCheckRequest(BaseModel):
    agent_key: str
    operation: str  # "read", "write", "delete"
    memory_key: str
    memory_value: Optional[str] = None
    memory_type: Optional[str] = None
    memory_namespace: Optional[str] = None
    data_classification: Optional[str] = None
    source_agent: Optional[str] = None
    session_id: Optional[str] = None
    guardrails: Optional[list[str]] = None


def _format(result):
    return {"guardrail": result.guardrail_name, "passed": result.passed,
            "action": result.action, "message": result.message,
            "details": result.details, "latency_ms": round(result.latency_ms, 2)}


@router.post("/check")
async def check_memory(body: MemoryCheckRequest, request: Request):
    context = {
        "agent_key": body.agent_key,
        "operation": body.operation,
        "memory_key": body.memory_key,
        "memory_value": body.memory_value or "",
        "memory_type": body.memory_type or "",
        "memory_namespace": body.memory_namespace or "",
        "data_classification": body.data_classification or "",
        "source_agent": body.source_agent or "",
        "session_id": body.session_id or "",
    }

    guards = _WRITE_GUARDS if body.operation == "write" else _READ_GUARDS
    results = []
    for name, cls in guards:
        if body.guardrails and name not in body.guardrails:
            continue
        guard = cls()
        if not guard.enabled:
            continue
        r = await guard.check(body.memory_value or "", context)
        results.append(_format(r))
        if not r.passed and r.action == "block":
            break

    allowed = all(r["passed"] or r["action"] not in ("block",) for r in results)
    action = "pass"
    for r in results:
        if not r["passed"]:
            action = r["action"]
            break

    tenant_id = (getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None) or ""
    triggered = [r["guardrail"] for r in results if not r["passed"]]
    latency_ms = sum(r.get("latency_ms", 0) for r in results)
    await audit_logger.log({
        "agent_key": body.agent_key or "",
        "endpoint": "/v1/shield/memory/check",
        "input_text": f"memory_{body.operation}:{body.memory_key}",
        "action_taken": action,
        "guardrails_triggered": triggered,
        "latency_ms": round(latency_ms, 2),
        "metadata": {
            "kind": "agent_chat_telemetry",
            "tenant_id": tenant_id,
            "user_role": "",
            "stage": "memory_check",
            "blocked": not allowed,
            "block_reason": "; ".join(r["message"] for r in results if not r["passed"]) or None,
            "session_id": body.session_id or "",
            "tool_calls": [],
            "tool_call_count": 0,
            "input_guardrails": [{"guardrail": r["guardrail"], "passed": r["passed"], "action": r["action"], "message": r.get("message", "")} for r in results],
            "output_guardrails": [],
            "usage": {},
        },
    })

    return {"allowed": allowed, "action": action, "guardrail_results": results}


@router.post("/cleanup")
async def cleanup_memory(body: dict = None):
    guard = MemoryRetentionPoliciesGuardrail()
    context = {"operation": "cleanup", "memory_key": "*"}
    r = await guard.check("", context)
    return {"message": r.message, "details": r.details}
