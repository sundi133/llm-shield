"""Tenant management API — CRUD for multi-tenant guardrail configs."""

from fastapi import APIRouter, HTTPException, Request, Query
from typing import Optional

from storage.tenant_store import (
    create_tenant,
    get_tenant,
    update_tenant,
    delete_tenant,
    list_tenants,
    add_api_key,
    remove_api_key,
)
from storage.tenant_models import TenantCreateRequest, TenantUpdateRequest
from storage.admin_audit import log_admin_action, query_admin_audit
from storage.rate_limiter import get_usage

router = APIRouter(prefix="/v1/admin/tenants", tags=["tenants"])


def _actor_from_request(request: Request) -> str:
    """Extract admin actor identity from the X-Admin-Key header (hashed)."""
    import hashlib
    key = request.headers.get("X-Admin-Key", "")
    if not key:
        return "unknown"
    return f"admin:{hashlib.sha256(key.encode()).hexdigest()[:12]}"


def _source_ip(request: Request) -> str:
    return request.client.host if request.client else ""


@router.get("")
async def list_all_tenants(include_deleted: bool = Query(False)):
    """List all tenants with summary info."""
    return {"tenants": list_tenants(include_deleted=include_deleted)}


@router.post("")
async def create_new_tenant(request: Request, body: TenantCreateRequest):
    """Create a new tenant with validated config."""
    tenant_id = body.tenant_id

    existing = get_tenant(tenant_id, include_deleted=True)
    if existing and not existing.get("deleted_at"):
        raise HTTPException(status_code=409, detail=f"Tenant '{tenant_id}' already exists")

    # Build config dict from validated model
    config_dict = body.model_dump(exclude={"api_keys"})
    api_keys = body.api_keys

    config = create_tenant(tenant_id, config_dict, api_keys)

    log_admin_action(
        action="create_tenant",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={"name": config.get("name"), "plan": config.get("plan"), "api_key_count": len(api_keys)},
    )

    return {"status": "created", "tenant_id": tenant_id, "config": config}


@router.get("/{tenant_id}")
async def get_tenant_config(tenant_id: str):
    """Get a tenant's full config."""
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return config


@router.put("/{tenant_id}")
async def update_tenant_config(tenant_id: str, body: TenantUpdateRequest, request: Request):
    """Update a tenant's config (merges with existing)."""
    before = get_tenant(tenant_id)
    if not before:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    updates = body.model_dump(exclude_none=True)
    config = update_tenant(tenant_id, updates)

    log_admin_action(
        action="update_tenant",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        before={"plan": before.get("plan"), "input_guardrails": list(before.get("input_guardrails", {}).keys())},
        after={"plan": config.get("plan"), "input_guardrails": list(config.get("input_guardrails", {}).keys())},
        metadata={"updated_fields": list(updates.keys())},
    )

    return {"status": "updated", "tenant_id": tenant_id, "config": config}


@router.delete("/{tenant_id}")
async def delete_tenant_config(
    tenant_id: str,
    request: Request,
    hard: bool = Query(False, description="If true, permanently delete; otherwise soft delete"),
):
    """Delete a tenant (soft by default)."""
    before = get_tenant(tenant_id, include_deleted=True)
    if not before:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    delete_tenant(tenant_id, soft=not hard)

    log_admin_action(
        action="delete_tenant_hard" if hard else "delete_tenant_soft",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        before={"name": before.get("name"), "plan": before.get("plan")},
    )

    return {"status": "deleted", "tenant_id": tenant_id, "hard": hard}


@router.post("/{tenant_id}/api-keys")
async def add_tenant_api_key(tenant_id: str, body: dict, request: Request):
    """Add an API key for a tenant."""
    existing = get_tenant(tenant_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    api_key = body.get("api_key")
    if not api_key:
        raise HTTPException(status_code=400, detail="'api_key' is required")

    add_api_key(tenant_id, api_key)

    log_admin_action(
        action="add_api_key",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
    )

    return {"status": "added", "tenant_id": tenant_id}


@router.delete("/{tenant_id}/api-keys")
async def remove_tenant_api_key(tenant_id: str, body: dict, request: Request):
    """Remove an API key for a tenant."""
    api_key = body.get("api_key")
    if not api_key:
        raise HTTPException(status_code=400, detail="'api_key' is required")

    remove_api_key(api_key)

    log_admin_action(
        action="remove_api_key",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
    )

    return {"status": "removed", "tenant_id": tenant_id}


@router.get("/{tenant_id}/usage")
async def get_tenant_usage(tenant_id: str):
    """Get current usage stats for a tenant (requests/tokens)."""
    existing = get_tenant(tenant_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    usage = get_usage(tenant_id)
    quota = existing.get("quota", {})
    return {
        "tenant_id": tenant_id,
        "usage": usage,
        "quota": quota,
    }


@router.get("/{tenant_id}/audit")
async def get_tenant_audit_log(
    tenant_id: str,
    action: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Get admin audit log for a specific tenant."""
    entries = query_admin_audit(tenant_id=tenant_id, action=action, limit=limit, offset=offset)
    return {"tenant_id": tenant_id, "entries": entries}


# Global admin audit log (not scoped to a tenant)
global_router = APIRouter(prefix="/v1/admin", tags=["admin-audit"])


@global_router.get("/audit")
async def get_global_audit_log(
    tenant_id: Optional[str] = None,
    action: Optional[str] = None,
    actor: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Query the global admin audit log with filters."""
    entries = query_admin_audit(
        tenant_id=tenant_id,
        action=action,
        actor=actor,
        limit=limit,
        offset=offset,
    )
    return {"entries": entries, "count": len(entries)}


@global_router.get("/dashboard")
async def get_admin_dashboard():
    """Aggregate dashboard — all tenants with usage and quota info in one call."""
    tenants = list_tenants(include_deleted=False)

    rows = []
    total_requests_today = 0
    total_tokens_today = 0
    total_requests_this_minute = 0
    plan_counts = {"basic": 0, "pro": 0, "enterprise": 0}

    for t_summary in tenants:
        tid = t_summary["tenant_id"]
        config = get_tenant(tid)
        if not config:
            continue

        usage = get_usage(tid)
        quota = config.get("quota") or {}

        req_today = usage.get("requests_today", 0)
        tok_today = usage.get("tokens_today", 0)
        req_min = usage.get("requests_this_minute", 0)

        total_requests_today += req_today
        total_tokens_today += tok_today
        total_requests_this_minute += req_min

        plan = config.get("plan", "basic")
        if plan in plan_counts:
            plan_counts[plan] += 1

        max_min = quota.get("max_requests_per_minute", 0) or 1
        max_day = quota.get("max_requests_per_day", 0) or 1
        max_tok = quota.get("max_tokens_per_day", 0) or 1

        rows.append({
            "tenant_id": tid,
            "name": config.get("name", ""),
            "plan": plan,
            "input_guardrail_count": len(config.get("input_guardrails", {})),
            "output_guardrail_count": len(config.get("output_guardrails", {})),
            "agent_count": len(config.get("rbac", {}).get("agents", {})),
            "usage": {
                "requests_this_minute": req_min,
                "requests_today": req_today,
                "tokens_today": tok_today,
            },
            "quota": quota,
            "pct_of_minute_limit": round(100 * req_min / max_min, 1),
            "pct_of_daily_limit": round(100 * req_today / max_day, 1),
            "pct_of_token_limit": round(100 * tok_today / max_tok, 1) if max_tok > 0 else 0,
        })

    # Sort by requests today (most active first)
    rows.sort(key=lambda r: r["usage"]["requests_today"], reverse=True)

    return {
        "summary": {
            "total_tenants": len(rows),
            "total_requests_today": total_requests_today,
            "total_tokens_today": total_tokens_today,
            "total_requests_this_minute": total_requests_this_minute,
            "plan_counts": plan_counts,
        },
        "tenants": rows,
    }
