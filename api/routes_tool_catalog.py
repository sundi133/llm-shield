"""GET /v1/tenant/me/tool-catalog: one page of the tenant's tools and a summary.

Spec: docs/specs/tool-registry-scale.md (task 1). Admin plane only (the
portal's Tool Registry list); not on the guard path. Not /v1/tenant/me/tools,
which is the tenant's OpenAI-format tool definitions (routes_tenant_self.py).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from core.auth import get_tenant_from_request
from storage import tool_catalog

router = APIRouter(prefix="/v1/tenant/me/tool-catalog", tags=["tool-catalog"])


@router.get("")
async def list_tool_catalog(request: Request):
    """Tools in name order, `limit` (1 to 500, default 50) at a time, with a
    tenant-wide summary. Filters: q (name contains), agent, source
    (registered | policy_only | all), policy (any | none | custom),
    sanitization=true, audit (on | off), role. cursor: the previous page's
    next_cursor. fresh=1 rebuilds the cached catalog first."""
    tenant_id = get_tenant_from_request(request)
    try:
        params = tool_catalog.parse_params(request.query_params)
        out = tool_catalog.page(tenant_id, **params)
    except tool_catalog.CatalogError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except tool_catalog.CatalogUnavailable:
        raise HTTPException(status_code=503, detail="tool catalog unavailable: storage not reachable")
    return {"tenant_id": tenant_id, **out}
