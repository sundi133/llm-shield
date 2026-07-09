"""Guardrail effectiveness metrics API.

Endpoints:
    GET /v1/tenant/me/guardrails/metrics           — all guardrails summary
    GET /v1/tenant/me/guardrails/metrics/{name}    — single guardrail detail
    GET /v1/tenant/me/guardrails/dashboard         — DLP-style issues dashboard

NOTE: the dashboard lives at /dashboard, NOT /metrics/dashboard — the
/metrics/{guardrail_name} route would capture "dashboard" as a guardrail name.
"""

from fastapi import APIRouter, HTTPException, Request

from storage.guardrail_metrics import (
    get_all_guardrails_summary,
    get_blocked_dashboard,
    get_effectiveness,
)

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


@router.get("/dashboard")
async def guardrails_dashboard(request: Request, days: int = 30):
    """DLP-style dashboard: severity split, daily trend, top issues, top
    users/devices, recent blocked events. Read-only; days clamped to 1..90."""
    tenant_id = _require_tenant(request)
    return get_blocked_dashboard(tenant_id, days=days)


@router.get("/metrics/{guardrail_name}")
async def single_guardrail_metrics(guardrail_name: str, request: Request, days: int = 30):
    """Get detailed effectiveness metrics for a single guardrail with daily breakdown."""
    tenant_id = _require_tenant(request)
    result = get_effectiveness(tenant_id, guardrail_name, days=days)
    return {
        "tenant_id": tenant_id,
        **result,
    }
