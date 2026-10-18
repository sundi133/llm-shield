"""Tenant self-service control plane for agentic workflow operations."""

import logging
import os
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
    attach_approval_grant,
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
from core.auth import require_config_write

logger = logging.getLogger("votal.agentic_control_plane")

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
    require_config_write(request, tenant_id, "change the agentic control plane")
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


_APPROVALS_HATCH_ENV = "SHIELD_APPROVALS_TENANT_KEY"
_warned_hatch = False


def _decider(request: Request, tenant_id: str, asserted: str) -> tuple[str, str]:
    """(approver, method) for an approve/deny, or 403.

    An approval exists so that a person decides, so the agent that asked must
    not be able to answer it with the key it already holds. Allowed:

    * a signed-in portal user of the tenant: the approver is the session's
      subject, whatever the body says ("portal_session");
    * the trusted proxy (core.proxy_trust) vouching for a person with
      X-Approver-Sub ("sso"). From anyone else that header is ignored: it used
      to make any caller's approval read as SSO-verified;
    * an admin identity, or an admin-scoped tenant key ("admin"), with the
      approver as asserted in the body.

    A runtime or unscoped key is refused in every mode. Hatch
    SHIELD_APPROVALS_TENANT_KEY (one release) lets an unscoped key decide,
    recorded "asserted"; never a runtime key.
    docs/specs/tenant-config-write-scope.md, finding C.
    """
    global _warned_hatch
    from core.auth import admin_caller, caller_key_scope, portal_principal, require_admin_scope
    from core.proxy_trust import peer_is_trusted, trusted_proxy_only

    principal = portal_principal(request)
    if principal and principal.get("tenant_id") == tenant_id and principal.get("sub"):
        return principal.get("email") or principal["sub"], "portal_session"

    vouched = request.headers.get("x-approver-sub", "").strip()
    if vouched and trusted_proxy_only() and peer_is_trusted(request):
        return vouched, "sso"

    if admin_caller(request) is not None:
        require_admin_scope(request, "tenants:write", tenant_id)
        return asserted, "admin"

    scope, _ = caller_key_scope(request)
    if scope == "admin":
        return asserted, "admin"
    if scope is None and os.environ.get(_APPROVALS_HATCH_ENV, "").strip().lower() in ("1", "true", "yes", "on"):
        if not _warned_hatch:
            _warned_hatch = True
            logger.warning("%s is on: an unscoped tenant key can decide approvals, so an "
                           "agent holding one can approve its own requests. Turn it off.",
                           _APPROVALS_HATCH_ENV)
        return asserted, "asserted"
    raise HTTPException(
        status_code=403,
        detail="approvals are decided by a signed-in person or an admin-scoped key, "
               "not by an agent's API key")


def _mint_request_grant(req: dict[str, Any], method: str) -> str:
    """Freeze an approved request into a signed, single-use approval grant."""
    from core.approvals import mint_grant, params_hash

    approvers = [
        {"sub": a.get("approver", ""), "method": a.get("method") or method, "at": a.get("approved_at")}
        for a in req.get("approvals", [])
    ]
    # Cap/mint (L3) requests carry the real instance + resource; cooperative
    # (tool/check) requests don't, so fall back to agent_key + a session resource.
    instance = req.get("agent_instance_id") or req.get("agent_key", "")
    resource = req.get("resource") or f"session:{req.get('session_id', '')}"
    return mint_grant(
        tenant_id=req.get("tenant_id", ""),
        agent_id=req.get("agent_key", ""),
        agent_instance_id=instance,
        session_id=req.get("session_id", ""),
        tool=req.get("tool_name", ""),
        resource=resource,
        params_hash=params_hash(req.get("tool_params")),
        approvers=approvers,
        request_id=req.get("request_id", ""),
    )


@router.post("/approvals/{request_id}/approve")
async def approve_request(request_id: str, body: ApprovalDecisionRequest, request: Request):
    tenant_id = _tenant_id(request)
    approver, method = _decider(request, tenant_id, body.approver)

    updated = update_approval_request(
        tenant_id,
        request_id,
        decision="approve",
        approver=approver,
        reason=body.reason,
        method=method,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Approval request not found")

    grant_token = None
    if updated.get("status") == "approved":
        grant_token = _mint_request_grant(updated, method)
        attach_approval_grant(tenant_id, request_id, grant_token)

    _audit(
        request, "tenant_approve_agentic_request", tenant_id=tenant_id,
        metadata={"request_id": request_id, "approver": approver, "approver_method": method,
                  "granted": bool(grant_token)},
    )
    resp: dict[str, Any] = {"status": updated.get("status", "pending"), "request": updated}
    if grant_token:
        resp["approval_grant"] = grant_token
    return resp


@router.post("/approvals/{request_id}/deny")
async def deny_request(request_id: str, body: ApprovalDecisionRequest, request: Request):
    tenant_id = _tenant_id(request)
    approver, method = _decider(request, tenant_id, body.approver)
    updated = update_approval_request(
        tenant_id,
        request_id,
        decision="deny",
        approver=approver,
        reason=body.reason,
        method=method,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Approval request not found")
    _audit(request, "tenant_deny_agentic_request", tenant_id=tenant_id,
           metadata={"request_id": request_id, "approver": approver, "approver_method": method})
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
    require_config_write(request, tenant_id, "create an execution grant")
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
    require_config_write(request, tenant_id, "revoke an execution grant")
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
    require_config_write(request, tenant_id, "resume a workflow checkpoint")
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
    require_config_write(request, tenant_id, "reset a circuit breaker")
    state = reset_circuit_breaker(tenant_id, tool_name, actor=f"tenant:{tenant_id}")
    _audit(request, "tenant_reset_circuit_breaker", tenant_id=tenant_id, metadata={"tool_name": tool_name})
    return {"status": "reset", "tool_state": state}
