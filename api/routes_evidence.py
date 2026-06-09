"""Compliance evidence pack API.

Endpoints:
    POST /v1/tenant/me/compliance/evidence-pack  — generate evidence pack
    GET  /v1/tenant/me/compliance/frameworks     — list available frameworks
"""

from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from typing import Optional

from storage.evidence_pack import FRAMEWORKS, generate_evidence_pack

router = APIRouter(prefix="/v1/tenant/me/compliance", tags=["compliance"])


def _require_tenant(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant API key required")
    return tenant_id


class EvidencePackRequest(BaseModel):
    start_date: str = Field("", description="ISO date (YYYY-MM-DD). Defaults to 30 days ago.")
    end_date: str = Field("", description="ISO date (YYYY-MM-DD). Defaults to today.")
    format: str = Field("json", pattern="^(json|html)$")
    framework: str = Field("generic", pattern="^(generic|hipaa|pci_dss|gdpr)$")


@router.post("/evidence-pack")
async def create_evidence_pack(body: EvidencePackRequest, request: Request):
    """Generate a compliance evidence pack from audit data."""
    tenant_id = _require_tenant(request)

    end_date = body.end_date or datetime.utcnow().strftime("%Y-%m-%d")
    start_date = body.start_date or (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%d")

    result = generate_evidence_pack(
        tenant_id=tenant_id,
        start_date=start_date,
        end_date=end_date,
        framework=body.framework,
        fmt=body.format,
    )

    if body.format == "html":
        return HTMLResponse(content=result)
    return result


@router.get("/frameworks")
async def list_frameworks(request: Request):
    """List available compliance frameworks."""
    _require_tenant(request)
    return {"frameworks": FRAMEWORKS}
