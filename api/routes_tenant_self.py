"""Tenant self-service API — read-only access for a tenant to see their own data.

Uses the request.state.tenant_id set by ShieldMiddleware (resolved from API key).
Tenants can only see their own config, usage, and audit logs.
"""

from fastapi import APIRouter, HTTPException, Request

from storage.tenant_store import get_tenant
from storage.rate_limiter import get_usage

router = APIRouter(prefix="/v1/tenant", tags=["tenant-self"])


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
