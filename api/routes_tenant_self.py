"""Tenant self-service API — read + edit access for a tenant to manage their policies.

Uses the request.state.tenant_id set by ShieldMiddleware (resolved from API key).
Tenants can view and update their own guardrail policies. They cannot modify
RBAC, quota, plan, or API keys — those are admin-only.
"""

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from storage.tenant_store import get_tenant, update_tenant
from storage.tenant_models import GuardrailPolicy
from storage.rate_limiter import get_usage
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/tenant", tags=["tenant-self"])


class TenantSelfUpdateRequest(BaseModel):
    """Fields a tenant is allowed to modify on their own config."""
    input_guardrails: Optional[dict[str, GuardrailPolicy]] = None
    output_guardrails: Optional[dict[str, GuardrailPolicy]] = None


def _require_tenant(request: Request) -> str:
    """Ensure request has a resolved tenant, else reject."""
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(
            status_code=401,
            detail="Tenant API key required to access /v1/tenant/* endpoints",
        )
    return tenant_id


@router.get("/me")
async def get_my_tenant(request: Request):
    """Return the current tenant's config (sanitized — no internal fields)."""
    tenant_id = _require_tenant(request)
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Return sanitized view (no internal fields)
    return {
        "tenant_id": config.get("tenant_id"),
        "name": config.get("name"),
        "plan": config.get("plan"),
        "input_guardrails": list(config.get("input_guardrails", {}).keys()),
        "output_guardrails": list(config.get("output_guardrails", {}).keys()),
        "quota": config.get("quota"),
        "agents": list(config.get("rbac", {}).get("agents", {}).keys()),
    }


@router.get("/me/usage")
async def get_my_usage(request: Request):
    """Return the current tenant's usage against quota."""
    tenant_id = _require_tenant(request)
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant not found")

    usage = get_usage(tenant_id)
    quota = config.get("quota") or {}
    max_min = quota.get("max_requests_per_minute") or 1
    max_day = quota.get("max_requests_per_day") or 1
    return {
        "tenant_id": tenant_id,
        "plan": config.get("plan"),
        "usage": usage,
        "quota": quota,
        "pct_of_minute_limit": round(100 * (usage.get("requests_this_minute", 0)) / max_min, 1),
        "pct_of_daily_limit": round(100 * (usage.get("requests_today", 0)) / max_day, 1),
    }


@router.get("/me/policies")
async def get_my_policies(request: Request):
    """Return the tenant's current input + output guardrail policies (full detail)."""
    tenant_id = _require_tenant(request)
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {
        "tenant_id": tenant_id,
        "input_guardrails": config.get("input_guardrails", {}),
        "output_guardrails": config.get("output_guardrails", {}),
    }


@router.put("/me/policies")
async def update_my_policies(request: Request, body: TenantSelfUpdateRequest):
    """Tenant updates their own input/output guardrail policies.

    Tenants cannot modify RBAC, quota, plan, or API keys via this route.
    Changes are logged in the admin audit with actor=tenant:<id>.
    """
    tenant_id = _require_tenant(request)
    existing = get_tenant(tenant_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Tenant not found")

    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    config = update_tenant(tenant_id, updates)

    log_admin_action(
        action="tenant_self_update_policies",
        actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id,
        source_ip=request.client.host if request.client else "",
        before={"input_guardrails": list((existing.get("input_guardrails") or {}).keys()),
                "output_guardrails": list((existing.get("output_guardrails") or {}).keys())},
        after={"input_guardrails": list((config.get("input_guardrails") or {}).keys()),
               "output_guardrails": list((config.get("output_guardrails") or {}).keys())},
        metadata={"updated_fields": list(updates.keys())},
    )

    return {
        "status": "updated",
        "tenant_id": tenant_id,
        "input_guardrails": config.get("input_guardrails", {}),
        "output_guardrails": config.get("output_guardrails", {}),
    }


@router.get("/me/audit")
async def get_my_audit_log(request: Request, limit: int = 50):
    """Return recent admin audit entries scoped to this tenant."""
    tenant_id = _require_tenant(request)
    from storage.admin_audit import query_admin_audit
    entries = query_admin_audit(tenant_id=tenant_id, limit=limit)
    return {"tenant_id": tenant_id, "entries": entries}
