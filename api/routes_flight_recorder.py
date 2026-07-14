"""Flight recorder API — retrieve forensic incident snapshots.

Read-only, tenant-scoped via ``X-API-Key`` (resolved to ``request.state.tenant_id``
by the auth middleware, same as the evidence-pack router). Mounted on both planes
for parity with the evidence and decisions routers. Off the guard path.

Endpoints:
    GET /v1/tenant/me/flight-recorder/incidents               — list summaries
    GET /v1/tenant/me/flight-recorder/incidents/{incident_id} — full snapshot
"""

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from typing import Optional

from core.feature_flags import flight_recorder_enabled
from storage.flight_recorder import get_incident, list_incidents, render_incident_html

router = APIRouter(prefix="/v1/tenant/me/flight-recorder", tags=["flight-recorder"])


def _require_enabled() -> None:
    if not flight_recorder_enabled():
        raise HTTPException(status_code=404, detail="Flight recorder not enabled")


def _require_tenant(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant API key required")
    return tenant_id


@router.get("/incidents")
async def list_flight_incidents(
    request: Request,
    limit: int = Query(50, ge=1, le=200, description="Max results"),
    offset: int = Query(0, ge=0, description="Skip first N results"),
    trigger: Optional[str] = Query(None, description="Filter by trigger"),
    agent_instance_id: Optional[str] = Query(None, description="Filter by agent instance"),
    session_id: Optional[str] = Query(None, description="Filter by session"),
):
    """List forensic incident summaries for the calling tenant (newest first)."""
    _require_enabled()
    tenant_id = _require_tenant(request)
    incidents = list_incidents(
        tenant_id=tenant_id,
        limit=limit,
        offset=offset,
        trigger=trigger,
        agent_instance_id=agent_instance_id,
        session_id=session_id,
    )
    return {"count": len(incidents), "incidents": incidents}


@router.get("/incidents/{incident_id}")
async def get_flight_incident(
    incident_id: str,
    request: Request,
    format: str = Query("json", pattern="^(json|html)$"),
):
    """Return one full incident snapshot (JSON by default, or printable HTML)."""
    _require_enabled()
    tenant_id = _require_tenant(request)
    snapshot = get_incident(tenant_id, incident_id)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Incident not found")
    if format == "html":
        return HTMLResponse(content=render_incident_html(snapshot))
    return snapshot
