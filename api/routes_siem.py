"""SIEM integration API — CRUD for Splunk, Sentinel, and generic SIEM endpoints.

Endpoints:
    POST   /v1/tenant/me/siem       — create a SIEM integration
    GET    /v1/tenant/me/siem       — list integrations
    DELETE /v1/tenant/me/siem/{id}  — remove an integration
    POST   /v1/tenant/me/siem/test  — send a test event
"""

import time
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional

from storage.siem_store import (
    create_siem_config,
    delete_siem_config,
    get_siem_configs,
)

router = APIRouter(prefix="/v1/tenant/me/siem", tags=["siem"])


def _require_tenant(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant API key required")
    return tenant_id


_VALID_STATUSES = {"block", "warn"}


class SIEMCreateRequest(BaseModel):
    type: str = Field("generic", pattern="^(splunk|sentinel|elastic|wazuh|generic)$")
    url: str = Field("", description="HEC / index / generic endpoint URL")
    token: str = Field("", description="HEC token, Bearer token, or Elastic API key")
    workspace_id: str = Field("", description="Azure workspace ID (sentinel only)")
    shared_key: str = Field("", description="Azure shared key (sentinel only)")
    log_type: str = Field("LLMShield", description="Azure log type (sentinel only)")
    events: list[str] = Field(default_factory=list, description="Event-type filter (empty = all)")
    statuses: list[str] = Field(
        default_factory=list,
        description="Event-status filter: subset of ['block','warn'] (empty = all)",
    )
    enabled: bool = True


@router.post("")
async def create_siem(body: SIEMCreateRequest, request: Request):
    """Create a new SIEM integration."""
    tenant_id = _require_tenant(request)

    if body.type == "splunk" and not body.url:
        raise HTTPException(status_code=400, detail="Splunk HEC URL required")
    if body.type == "sentinel" and not body.workspace_id:
        raise HTTPException(status_code=400, detail="Azure workspace_id required")
    if body.type == "elastic" and (not body.url or not body.token):
        raise HTTPException(status_code=400, detail="Elastic index URL and API key required")
    if body.type == "wazuh" and (not body.url or not body.token):
        raise HTTPException(status_code=400, detail="Wazuh indexer URL and token required")
    if body.type == "generic" and not body.url:
        raise HTTPException(status_code=400, detail="Endpoint URL required")

    invalid = set(body.statuses) - _VALID_STATUSES
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status(es): {sorted(invalid)}. Allowed: {sorted(_VALID_STATUSES)}",
        )

    config = create_siem_config(tenant_id, body.model_dump())
    return {"success": True, "siem": config}


@router.get("")
async def list_siem(request: Request):
    """List all SIEM integrations for this tenant."""
    tenant_id = _require_tenant(request)
    configs = get_siem_configs(tenant_id)
    # Redact secrets in response
    safe = []
    for c in configs:
        sc = dict(c)
        if sc.get("token"):
            sc["token"] = sc["token"][:8] + "..."
        if sc.get("shared_key"):
            sc["shared_key"] = "***"
        safe.append(sc)
    return {"success": True, "integrations": safe, "total": len(safe)}


@router.delete("/{siem_id}")
async def remove_siem(siem_id: str, request: Request):
    """Remove a SIEM integration."""
    tenant_id = _require_tenant(request)
    deleted = delete_siem_config(tenant_id, siem_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"SIEM integration '{siem_id}' not found")
    return {"success": True, "message": f"SIEM integration '{siem_id}' deleted"}


@router.post("/test")
async def test_siem(request: Request):
    """Send a test event to all configured SIEM endpoints."""
    import asyncio
    from core.siem_dispatcher import dispatch_to_siem

    tenant_id = _require_tenant(request)
    configs = get_siem_configs(tenant_id)
    if not configs:
        raise HTTPException(status_code=404, detail="No SIEM integrations configured")

    test_event = {
        "event_type": "test_event",
        "tenant_id": tenant_id,
        "timestamp": time.time(),
        "payload": {
            "message": "LLM Shield SIEM integration test",
            "source": "shield-admin",
        },
    }

    await dispatch_to_siem(tenant_id, test_event)
    return {"success": True, "message": f"Test event dispatched to {len(configs)} endpoint(s)"}


@router.post("/ingest")
async def ingest_siem_event(request: Request):
    """Ingest a client-side event and fan out to all configured SIEM endpoints.

    Used by agent runtimes to forward GuardedToolCall audit records (or any
    custom event) to the tenant's SIEM without needing direct SIEM credentials.
    The client POSTs here; Shield dispatches to Splunk/Sentinel/generic.
    """
    from core.siem_dispatcher import dispatch_to_siem

    tenant_id = _require_tenant(request)
    body = await request.json()

    event = {
        "event_type": body.get("event_type", "guarded_tool_call"),
        "tenant_id": tenant_id,
        "timestamp": body.get("timestamp", time.time()),
        "payload": {k: v for k, v in body.items() if k not in ("event_type", "timestamp")},
    }

    await dispatch_to_siem(tenant_id, event)
    return {"success": True, "event_type": event["event_type"]}
