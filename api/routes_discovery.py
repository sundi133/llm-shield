"""The AI inventory (admin plane). Spec: docs/specs/ai-discovery.md, section 4.2.

    GET  /v1/tenant/me/discovery/inventory?kind=&governed=&status=&source=&q=&cursor=&limit=
    GET  /v1/tenant/me/discovery/inventory/{entry_id}
    PUT  /v1/tenant/me/discovery/inventory/{entry_id}   {status, owner, note}
    GET  /v1/tenant/me/discovery/events
    GET  /v1/tenant/me/discovery/catalog
    PUT  /v1/tenant/me/discovery/catalog/custom          {entries: [...]}

Reads need the tenant; writes go through the config write gate. Off the guard path.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import get_tenant_from_request, require_config_write
from core.discovery import catalog as cat
from core.discovery import inventory

router = APIRouter(prefix="/v1/tenant/me/discovery", tags=["discovery"])


class Review(BaseModel):
    status: Optional[str] = None
    owner: Optional[str] = Field(None, max_length=200)
    note: Optional[str] = Field(None, max_length=1000)


class CustomCatalog(BaseModel):
    entries: list = Field(default_factory=list)


def _actor(request: Request) -> str:
    from core.auth import audit_actor
    try:
        return audit_actor(request)
    except Exception:
        return ""


@router.get("/inventory")
async def list_inventory(request: Request, kind: str = "", governed: str = "", status: str = "",
                         source: str = "", q: str = "", cursor: int = 0, limit: int = 50):
    tenant_id = get_tenant_from_request(request)
    try:
        inventory.sync_shield(tenant_id)
    except Exception:
        pass
    return inventory.listing(tenant_id, kind=kind, governed=governed, status=status, source=source,
                             q=q, cursor=max(0, cursor), limit=limit)


@router.get("/inventory/{entry_id:path}")
async def get_entry(entry_id: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    entry = inventory.get(tenant_id, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"no entry '{entry_id}'")
    subs = sorted(inventory.subjects(tenant_id, entry_id).items(), key=lambda kv: -kv[1])
    return {**entry, "subject_list": [{"subject": s, "last_seen": at} for s, at in subs[:200]],
            "subject_total": len(subs)}


@router.put("/inventory/{entry_id:path}")
async def review_entry(entry_id: str, body: Review, request: Request):
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "review an AI inventory entry")
    try:
        entry = inventory.review(tenant_id, entry_id, status=body.status, owner=body.owner,
                                 note=body.note, actor=_actor(request))
    except inventory.InventoryError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="ai_inventory_reviewed", actor=_actor(request), tenant_id=tenant_id,
                         after={"entry_id": entry_id, "status": entry.get("status"),
                                "owner": entry.get("owner")})
    except Exception:
        pass
    return entry


@router.get("/events")
async def list_events(request: Request, limit: int = 50):
    tenant_id = get_tenant_from_request(request)
    return {"events": inventory.events(tenant_id, max(1, min(int(limit), 500)))}


@router.get("/catalog")
async def get_catalog(request: Request):
    tenant_id = get_tenant_from_request(request)
    entries = cat.entries(tenant_id)
    return {"version": cat.VERSION, "count": len(entries),
            "custom": [e for e in entries if e.get("custom")],
            "entries": entries, "mcp_config_paths": cat.MCP_CONFIG_PATHS}


@router.put("/catalog/custom")
async def put_custom_catalog(body: CustomCatalog, request: Request):
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "change the AI catalog")
    try:
        entries = cat.validate_custom(body.entries)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    from storage.tenant_store import kv_set
    kv_set(f"discovery_catalog:{tenant_id}", entries)
    return {"custom": entries, "count": len(entries)}
