"""Tenant self-service API for cross-app flow control.

Off the hot path: policy CRUD, validation, a pure simulator and the per-session
lineage view. Enforcement lives in core/xflow/runtime.py and runs inside
/v1/shield/tool/check, MCP tools/call and cap/mint.

Spec: docs/specs/cross-app-flow-control.md §4.2. Mounted on both planes, like
/v1/tenant/me/agentic/*. The tenant always comes from the authenticated API
key, never from the path or body.

Writes that can LOOSEN enforcement (saving or deleting the policy, clearing a
session's recorded reads) go through the same gate as agent-registry writes
(core.auth.require_registry_write, SHIELD_REGISTRY_WRITE_SCOPE). Otherwise an
agent holding only its runtime key could erase its own session's taint and
then exfiltrate. Off by default, like that gate; under `enforce` only an
admin-scoped key or a signed-in portal administrator may make these changes.
"""

from typing import Any, Optional

from fastapi import APIRouter, Body, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import get_tenant_from_request, require_registry_write
from core.xflow import runtime as xflow
from core.xflow import state as xflow_state
from core.xflow.policy import PolicyError, starter_policy, validate_policy
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/tenant/me/flow-control", tags=["cross-app-flow-control"])


def _audit(request: Request, action: str, tenant_id: str, metadata: Optional[dict] = None) -> None:
    try:
        log_admin_action(
            action=action,
            actor=f"tenant:{tenant_id}",
            tenant_id=tenant_id,
            source_ip=request.client.host if request.client else "",
            metadata=metadata or {},
        )
    except Exception:
        pass


def _invalid(e: PolicyError) -> HTTPException:
    return HTTPException(status_code=422,
                         detail={"message": "invalid flow policy", "errors": e.errors})


def _summary(policy: dict) -> dict:
    return {"enabled": policy.get("enabled"), "mode": policy.get("mode"),
            "apps": len(policy.get("apps") or {}),
            "exposure_rules": len(policy.get("exposure_rules") or []),
            "rules": len(policy.get("rules") or [])}


@router.get("/policy")
async def get_policy(request: Request):
    tenant_id = get_tenant_from_request(request)
    try:
        policy = xflow.load_policy(tenant_id)
    except PolicyError as e:
        # A stored policy that no longer validates is NOT enforced. Say so.
        return {"tenant_id": tenant_id, "configured": True, "enforced": False,
                "policy": None, "errors": e.errors}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"flow policy store unavailable: {e}")
    return {
        "tenant_id": tenant_id,
        "configured": policy is not None,
        "enforced": bool(policy and policy.get("enabled") and xflow.enabled()),
        "globally_disabled": not xflow.enabled(),
        "policy": policy,
    }


@router.put("/policy")
async def put_policy(request: Request, policy: dict = Body(...)):
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "change the cross-app flow policy")
    try:
        normalized = xflow.save_policy(tenant_id, policy)
    except PolicyError as e:
        raise _invalid(e)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"flow policy store unavailable: {e}")
    _audit(request, "tenant_set_flow_policy", tenant_id, _summary(normalized))
    return {"tenant_id": tenant_id, "policy": normalized,
            "note": "Other replicas apply the change within "
                    "SHIELD_XFLOW_POLICY_CACHE_S (default 5 s)."}


@router.delete("/policy")
async def delete_policy(request: Request):
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "delete the cross-app flow policy")
    try:
        deleted = xflow.delete_policy(tenant_id)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"flow policy store unavailable: {e}")
    _audit(request, "tenant_delete_flow_policy", tenant_id, {"deleted": deleted})
    return {"tenant_id": tenant_id, "deleted": deleted}


@router.post("/validate")
async def validate(request: Request, policy: dict = Body(...)):
    get_tenant_from_request(request)
    try:
        normalized = validate_policy(policy)
    except PolicyError as e:
        return {"valid": False, "errors": e.errors, "policy": None}
    return {"valid": True, "errors": [], "policy": normalized}


@router.get("/template")
async def template(request: Request):
    get_tenant_from_request(request)
    return {"policy": starter_policy()}


class SimSource(BaseModel):
    tool_name: str = Field(..., max_length=256)
    route: Optional[str] = Field(None, max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=20)


class SimulateRequest(BaseModel):
    policy: Optional[dict] = Field(None, description="Policy to test; the saved one when omitted")
    tool_name: str = Field(..., max_length=256)
    route: Optional[str] = Field(None, max_length=128)
    tool_params: Optional[dict] = None
    resource: Optional[str] = Field(None, max_length=512)
    sources: list[SimSource] = Field(default_factory=list, max_length=50)


@router.post("/simulate")
async def simulate(request: Request, body: SimulateRequest):
    """Decide a call exactly as enforcement would, against the listed sources.
    Reads and writes no session state."""
    tenant_id = get_tenant_from_request(request)
    policy: Any = body.policy
    if policy is None:
        try:
            policy = xflow.load_policy(tenant_id)
        except PolicyError as e:
            raise _invalid(e)
        if policy is None:
            raise HTTPException(status_code=404,
                                detail="No flow policy saved; pass one as `policy`")
    try:
        return xflow.simulate(
            policy, tool_name=body.tool_name, route=body.route, params=body.tool_params,
            resource=body.resource, sources=[s.model_dump() for s in body.sources],
        )
    except PolicyError as e:
        raise _invalid(e)


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, request: Request):
    """What this session has read, oldest first: the lineage an auditor needs
    to explain a flow decision."""
    tenant_id = get_tenant_from_request(request)
    if not session_id or len(session_id) > 512:
        raise HTTPException(status_code=400, detail="session_id must be 1..512 characters")
    try:
        records = xflow_state.read_session(tenant_id, session_id)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"flow state unavailable: {e}")
    return {"tenant_id": tenant_id, "session_id": session_id,
            "count": len(records), "records": records}


@router.delete("/sessions/{session_id}")
async def clear_session(session_id: str, request: Request):
    """Forget a session's recorded sources (e.g. after an approved incident
    review). Audited: clearing state lifts every flow rule for that session."""
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "clear a session's cross-app flow record")
    if not session_id or len(session_id) > 512:
        raise HTTPException(status_code=400, detail="session_id must be 1..512 characters")
    try:
        xflow_state.clear_session(tenant_id, session_id)
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"flow state unavailable: {e}")
    _audit(request, "tenant_clear_flow_session", tenant_id, {"session_id": session_id[:128]})
    return {"tenant_id": tenant_id, "session_id": session_id, "cleared": True}
