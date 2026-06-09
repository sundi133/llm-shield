"""Guardrail effectiveness metrics API.

Endpoints:
    GET /v1/tenant/me/guardrails/metrics           — all guardrails summary
    GET /v1/tenant/me/guardrails/metrics/{name}    — single guardrail detail
"""

from fastapi import APIRouter, HTTPException, Request

from storage.guardrail_metrics import get_all_guardrails_summary, get_effectiveness

router = APIRouter(prefix="/v1/tenant/me/guardrails", tags=["guardrail-metrics"])


def _require_tenant(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant API key required")
    return tenant_id


@router.get("/metrics")
async def all_guardrails_metrics(request: Request, days: int = 30):
    """Get effectiveness summary for all guardrails (sorted by block count)."""
    tenant_id = _require_tenant(request)
    summary = get_all_guardrails_summary(tenant_id, days=days)
    return {
        "tenant_id": tenant_id,
        "days": days,
        "guardrails": summary,
        "total_guardrails": len(summary),
    }


@router.get("/metrics/{guardrail_name}")
async def single_guardrail_metrics(guardrail_name: str, request: Request, days: int = 30):
    """Get detailed effectiveness metrics for a single guardrail with daily breakdown."""
    tenant_id = _require_tenant(request)
    result = get_effectiveness(tenant_id, guardrail_name, days=days)
    return {
        "tenant_id": tenant_id,
        **result,
    }
