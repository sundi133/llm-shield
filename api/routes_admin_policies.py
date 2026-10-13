"""Author a tenant's declarative authorization policy (admin plane).

    GET  /v1/admin/policies/{tenant}                current version + draft
    PUT  /v1/admin/policies/{tenant}/draft          upsert the draft (YAML or JSON)
    POST /v1/admin/policies/{tenant}/validate       validate without saving
    POST /v1/admin/policies/{tenant}/simulate       {role, tool} -> allow/deny
    POST /v1/admin/policies/{tenant}/publish         compile draft -> new version
    POST /v1/admin/policies/{tenant}/rollback        {version} -> set current
    GET  /v1/admin/policies/{tenant}/versions        publish history

A policy document says which roles may call which tools, with an explicit
default. Publishing compiles it to an immutable numbered snapshot; the guard
path (M2 Task 2) enforces the current version. `simulate` runs the SAME
evaluator the guard path will, so a preview and the live decision cannot
disagree.

Gated by the admin credential gate and scoped with require_admin_scope:
`policy:read` for reads/validate/simulate, `policy:write` to edit/publish/roll
back. Off the guard path. Spec: docs/specs/spec-mcp-gateway-m2-policy-engine.md.
M2 Task 1.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import admin_actor, require_admin_scope
from core.mcp.policy_lang import PolicyError, compile_source, evaluate, validate_document
from storage import policy_snapshot_store as store

router = APIRouter(prefix="/v1/admin/policies", tags=["admin-policies"])


class DocumentRequest(BaseModel):
    # The policy document, as a YAML/JSON string or an object.
    document: Any = None


class SimulateRequest(BaseModel):
    role: str = Field("", max_length=128)
    tool: str = Field(..., min_length=1, max_length=256)
    version: Optional[int] = None       # a published version; default = the draft


class PublishRequest(BaseModel):
    note: str = Field("", max_length=500)


class RollbackRequest(BaseModel):
    version: int = Field(..., ge=1)


def _audit(request: Request, tenant_id: str, action: str, after: dict) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=admin_actor(request),
                         tenant_id=tenant_id,
                         source_ip=(request.client.host if request.client else ""),
                         after=after)
    except Exception:       # noqa: BLE001
        pass


@router.get("/{tenant}")
async def get_policy(tenant: str, request: Request):
    require_admin_scope(request, "policy:read", tenant)
    return {
        "tenant_id": tenant,
        "current_version": store.get_current_version(tenant),
        "has_draft": store.get_draft(tenant) is not None,
        "draft": store.get_draft(tenant),
        "versions": len(store.list_versions(tenant)),
    }


@router.put("/{tenant}/draft")
async def put_draft(tenant: str, body: DocumentRequest, request: Request):
    require_admin_scope(request, "policy:write", tenant)
    try:
        saved = store.save_draft(tenant, body.document)
    except PolicyError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(request, tenant, "policy_draft_saved", {"rules": len(saved.get("rules", []))})
    return {"status": "saved", "tenant_id": tenant, "draft": saved}


@router.post("/{tenant}/validate")
async def validate_policy(tenant: str, body: DocumentRequest, request: Request):
    require_admin_scope(request, "policy:read", tenant)
    ok, errors = validate_document(body.document)
    return {"ok": ok, "errors": errors}


@router.post("/{tenant}/simulate")
async def simulate_policy(tenant: str, body: SimulateRequest, request: Request):
    """The allow/deny the guard path would return for (role, tool), against the
    draft by default or a published version."""
    require_admin_scope(request, "policy:read", tenant)
    if body.version is not None:
        snapshot = store.get_snapshot(tenant, body.version)
        if snapshot is None:
            raise HTTPException(status_code=404, detail=f"version {body.version} not found")
    else:
        draft = store.get_draft(tenant)
        if draft is None:
            raise HTTPException(status_code=404, detail="no draft to simulate; save one first")
        try:
            snapshot = compile_source(draft)
        except PolicyError as e:
            raise HTTPException(status_code=400, detail=str(e))
    decision = evaluate(snapshot, body.role, body.tool)
    return {"tenant_id": tenant, "role": body.role, "tool": body.tool,
            "against": ("version:" + str(body.version)) if body.version else "draft",
            **decision}


@router.post("/{tenant}/publish")
async def publish_policy(tenant: str, body: PublishRequest, request: Request):
    require_admin_scope(request, "policy:write", tenant)
    try:
        result = store.publish(tenant, published_by=admin_actor(request), note=body.note)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PolicyError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(request, tenant, "policy_published", result)
    return {"status": "published", "tenant_id": tenant, **result}


@router.post("/{tenant}/rollback")
async def rollback_policy(tenant: str, body: RollbackRequest, request: Request):
    require_admin_scope(request, "policy:write", tenant)
    try:
        result = store.rollback(tenant, body.version)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    _audit(request, tenant, "policy_rolled_back", result)
    return {"status": "rolled_back", "tenant_id": tenant, **result}


@router.get("/{tenant}/versions")
async def list_policy_versions(tenant: str, request: Request):
    require_admin_scope(request, "policy:read", tenant)
    versions = store.list_versions(tenant)
    return {"tenant_id": tenant, "current_version": store.get_current_version(tenant),
            "versions": versions, "count": len(versions)}
