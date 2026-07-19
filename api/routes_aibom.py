"""AIBOM API — per-tenant AI Bill of Materials (docs/spec-aibom.md).

    GET /v1/tenant/me/aibom?view=full|observed|declared

Read-only aggregation on the admin plane over data already written by the
registry/auth/guard paths; nothing here touches the guard path.
"""

from fastapi import APIRouter, HTTPException, Request

from api.routes_agents_registry import get_tenant_from_api_key
from storage.aibom import VIEWS, generate_aibom

router = APIRouter(prefix="/v1/tenant/me/aibom", tags=["aibom"])


@router.get("")
async def get_aibom(request: Request, view: str = "full"):
    """Generate the tenant's current AIBOM document."""
    tenant_id = get_tenant_from_api_key(request)
    if view not in VIEWS:
        raise HTTPException(status_code=422, detail=f"view must be one of: {', '.join(VIEWS)}")
    return generate_aibom(tenant_id, view=view)
