"""Tenant self-service control plane for agentic workflow operations."""

from typing import Optional, Any

from fastapi import APIRouter, HTTPException, Request, Query
from pydantic import BaseModel, Field

from core.auth import get_tenant_from_request
from storage.admin_audit import log_admin_action
from core.telemetry import record_event, build_tool_execution_event
from storage.agentic_control_plane import (
    get_control_plane_config,
    set_control_plane_config,
    list_approval_requests,
    update_approval_request,
    issue_execution_grant,
    list_execution_grants,
    revoke_execution_grant,
    create_checkpoint,
    list_checkpoints,
    resume_checkpoint,
    list_circuit_breakers,
    reset_circuit_breaker,
    report_tool_execution,
)

router = APIRouter(prefix="/v1/tenant/me/agentic", tags=["tenant-agentic-control-plane"])


def _tenant_id(request: Request) -> str:
    return get_tenant_from_request(request)


def _audit(request: Request, action: str, *, tenant_id: str, metadata: Optional[dict[str, Any]] = None):
    log_admin_action(
        action=action,
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        metadata=metadata or {},
    )


class ControlPlaneConfigRequest(BaseModel):
    approvals: Optional[dict[str, Any]] = None
    parameter_policies: Optional[dict[str, Any]] = None
    workflow_policies: Optional[dict[str, Any]] = None
    delegation_controls: Optional[dict[str, Any]] = None
    circuit_breakers: Optional[dict[str, Any]] = None
    execution_grants: Optional[dict[str, Any]] = None
    checkpoints: Optional[dict[str, Any]] = None


class ApprovalDecisionRequest(BaseModel):
    approver: str = Field(..., description="Approver identifier or email")
    reason: str = Field("", description="Approval or denial reason")


class GrantCreateRequest(BaseModel):
    tool_name: str
    agent_key: Optional[str] = None
    session_id: Optional[str] = None
    workflow: Optional[str] = None
    ttl_seconds: Optional[int] = Field(None, ge=60, le=86400)
    max_uses: Optional[int] = Field(None, ge=1, le=100)
    constraints: Optional[dict[str, Any]] = None
    created_by: Optional[str] = None


class CheckpointCreateRequest(BaseModel):
    session_id: str
    workflow: str = "default"
    label: str
    state: Optional[dict[str, Any]] = None
    created_by: Optional[str] = None


class ToolExecutionReportRequest(BaseModel):
    tool_name: str
    success: bool
    latency_ms: Optional[float] = None
    error_type: str = ""
    tool_input: str = ""
    tool_output: str = ""
    conversation_history: Optional[list] = None
    session_id: str = ""
    role_name: str = ""
    agentic_decisions: Optional[dict] = None


@router.get("/config")
async def get_agentic_control_plane(request: Request):
    tenant_id = _tenant_id(request)
    return {
        "tenant_id": tenant_id,
        "config": get_control_plane_config(tenant_id),
    }


@router.put("/config")
async def update_agentic_control_plane(request: Request, body: ControlPlaneConfigRequest):
    tenant_id = _tenant_id(request)
    config = set_control_plane_config(
        tenant_id,
        body.model_dump(exclude_none=True),
    )
    _audit(
        request,
        "tenant_update_agentic_control_plane",
        tenant_id=tenant_id,
        metadata={"updated_sections": list(body.model_dump(exclude_none=True).keys())},
    )
    return {"status": "updated", "tenant_id": tenant_id, "config": config}


@router.get("/approvals")
async def get_approvals(request: Request, status: Optional[str] = Query(None)):
    tenant_id = _tenant_id(request)
    return {
        "tenant_id": tenant_id,
        "approvals": list_approval_requests(tenant_id, status=status),
    }


@router.post("/approvals/{request_id}/approve")
async def approve_request(request_id: str, body: ApprovalDecisionRequest, request: Request):
    tenant_id = _tenant_id(request)
    updated = update_approval_request(
        tenant_id,
        request_id,
        decision="approve",
        approver=body.approver,
        reason=body.reason,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Approval request not found")
    _audit(request, "tenant_approve_agentic_request", tenant_id=tenant_id, metadata={"request_id": request_id})
    return {"status": "approved", "request": updated}


@router.post("/approvals/{request_id}/deny")
async def deny_request(request_id: str, body: ApprovalDecisionRequest, request: Request):
    tenant_id = _tenant_id(request)
    updated = update_approval_request(
        tenant_id,
        request_id,
        decision="deny",
        approver=body.approver,
        reason=body.reason,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Approval request not found")
    _audit(request, "tenant_deny_agentic_request", tenant_id=tenant_id, metadata={"request_id": request_id})
    return {"status": "denied", "request": updated}


@router.get("/execution-grants")
async def get_execution_grants(request: Request, include_inactive: bool = Query(False)):
    tenant_id = _tenant_id(request)
    return {
        "tenant_id": tenant_id,
        "execution_grants": list_execution_grants(tenant_id, include_inactive=include_inactive),
    }


@router.post("/execution-grants")
async def create_execution_grant(body: GrantCreateRequest, request: Request):
    tenant_id = _tenant_id(request)
    grant = issue_execution_grant(
        tenant_id,
        body.model_dump(exclude_none=True),
        actor=body.created_by or f"tenant:{tenant_id}",
    )
    _audit(request, "tenant_issue_execution_grant", tenant_id=tenant_id, metadata={"grant_id": grant["grant_id"]})
    return {"status": "created", "grant": grant}


@router.post("/execution-grants/{grant_id}/revoke")
async def revoke_grant(grant_id: str, request: Request):
    tenant_id = _tenant_id(request)
    grant = revoke_execution_grant(tenant_id, grant_id, actor=f"tenant:{tenant_id}")
    if not grant:
        raise HTTPException(status_code=404, detail="Execution grant not found")
    _audit(request, "tenant_revoke_execution_grant", tenant_id=tenant_id, metadata={"grant_id": grant_id})
    return {"status": "revoked", "grant": grant}


@router.get("/checkpoints")
async def get_checkpoints(
    request: Request,
    session_id: Optional[str] = Query(None),
    workflow: Optional[str] = Query(None),
):
    tenant_id = _tenant_id(request)
    return {
        "tenant_id": tenant_id,
        "checkpoints": list_checkpoints(tenant_id, session_id=session_id, workflow=workflow),
    }


@router.post("/checkpoints")
async def create_workflow_checkpoint(body: CheckpointCreateRequest, request: Request):
    tenant_id = _tenant_id(request)
    checkpoint = create_checkpoint(
        tenant_id,
        session_id=body.session_id,
        workflow=body.workflow,
        label=body.label,
        state=body.state,
        actor=body.created_by or f"tenant:{tenant_id}",
    )
    _audit(request, "tenant_create_checkpoint", tenant_id=tenant_id, metadata={"checkpoint_id": checkpoint["checkpoint_id"]})
    return {"status": "created", "checkpoint": checkpoint}


@router.post("/checkpoints/{checkpoint_id}/resume")
async def resume_workflow_checkpoint(checkpoint_id: str, request: Request):
    tenant_id = _tenant_id(request)
    checkpoint = resume_checkpoint(tenant_id, checkpoint_id, actor=f"tenant:{tenant_id}")
    if not checkpoint:
        raise HTTPException(status_code=404, detail="Checkpoint not found")
    _audit(request, "tenant_resume_checkpoint", tenant_id=tenant_id, metadata={"checkpoint_id": checkpoint_id})
    return {"status": "resumed", "checkpoint": checkpoint}


@router.get("/circuit-breakers")
async def get_circuit_breakers(request: Request):
    tenant_id = _tenant_id(request)
    return {"tenant_id": tenant_id, "circuit_breakers": list_circuit_breakers(tenant_id)}


@router.post("/circuit-breakers/report")
async def report_execution(body: ToolExecutionReportRequest, request: Request):
    import uuid

    tenant_id = _tenant_id(request)
    trace_id = request.headers.get("x-trace-id", uuid.uuid4().hex[:16])
    source_ip = request.client.host if request.client else ""

    # Report to agentic control plane
    state = report_tool_execution(
        tenant_id,
        tool_name=body.tool_name,
        success=body.success,
        latency_ms=body.latency_ms,
        error_type=body.error_type,
    )

    # Log comprehensive telemetry event with conversation context
    record_event(build_tool_execution_event(
        trace_id=trace_id,
        tool_name=body.tool_name,
        success=body.success,
        latency_ms=body.latency_ms or 0,
        error_type=body.error_type,
        tool_input=body.tool_input,
        tool_output=body.tool_output,
        conversation_history=body.conversation_history,
        session_id=body.session_id,
        tenant_id=tenant_id,
        role_name=body.role_name,
        source_ip=source_ip,
        agentic_decisions=body.agentic_decisions,
    ))

    return {"status": "recorded", "tool_state": state}


@router.post("/circuit-breakers/{tool_name}/reset")
async def reset_breaker(tool_name: str, request: Request):
    tenant_id = _tenant_id(request)
    state = reset_circuit_breaker(tenant_id, tool_name, actor=f"tenant:{tenant_id}")
    _audit(request, "tenant_reset_circuit_breaker", tenant_id=tenant_id, metadata={"tool_name": tool_name})
    return {"status": "reset", "tool_state": state}
