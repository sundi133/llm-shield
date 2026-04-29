"""Tool Kill Switch routes — instantly disable/enable tools globally."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional

import asyncio
from storage.tool_killswitch import disable_tool, enable_tool, list_disabled_tools
from storage.admin_audit import log_admin_action
from core.webhook_dispatcher import dispatch_event

router = APIRouter(prefix="/v1/shield/tools", tags=["killswitch"])


def _actor_from_request(request: Request) -> str:
    import hashlib
    key = (
        request.headers.get("X-Admin-Key") or
        request.headers.get("X-API-Key") or
        request.headers.get("Authorization", "").replace("Bearer ", "")
    )
    if not key:
        return "unknown"
    return f"user:{hashlib.sha256(key.encode()).hexdigest()[:12]}"


def _source_ip(request: Request) -> str:
    return request.client.host if request.client else ""


class DisableToolRequest(BaseModel):
    tenant_id: str = Field(..., description="Tenant ID")
    reason: str = Field("", description="Why the tool is being disabled")


class EnableToolRequest(BaseModel):
    tenant_id: str = Field(..., description="Tenant ID")


@router.post("/{tool_name}/disable")
async def disable_tool_endpoint(tool_name: str, body: DisableToolRequest, request: Request):
    """Disable a tool globally across all agents for a tenant. Immediate effect."""
    actor = _actor_from_request(request)

    meta = disable_tool(
        tenant_id=body.tenant_id,
        tool_name=tool_name,
        reason=body.reason,
        actor=actor,
    )

    log_admin_action(
        action="tool_disabled",
        actor=actor,
        tenant_id=body.tenant_id,
        source_ip=_source_ip(request),
        after={"tool_name": tool_name, "reason": body.reason},
    )

    # Fire webhook event
    asyncio.create_task(dispatch_event(
        tenant_id=body.tenant_id,
        event_type="tool_disabled",
        payload={"tool_name": tool_name, "reason": body.reason, "actor": actor},
    ))

    return {
        "status": "disabled",
        "tenant_id": body.tenant_id,
        "tool_name": tool_name,
        "metadata": meta,
    }


@router.post("/{tool_name}/enable")
async def enable_tool_endpoint(tool_name: str, body: EnableToolRequest, request: Request):
    """Re-enable a previously disabled tool."""
    actor = _actor_from_request(request)

    was_disabled = enable_tool(tenant_id=body.tenant_id, tool_name=tool_name)

    if not was_disabled:
        raise HTTPException(
            status_code=404,
            detail=f"Tool '{tool_name}' was not disabled for tenant '{body.tenant_id}'"
        )

    log_admin_action(
        action="tool_enabled",
        actor=actor,
        tenant_id=body.tenant_id,
        source_ip=_source_ip(request),
        after={"tool_name": tool_name},
    )

    return {
        "status": "enabled",
        "tenant_id": body.tenant_id,
        "tool_name": tool_name,
    }


@router.get("/disabled")
async def list_disabled_tools_endpoint(tenant_id: str):
    """List all currently disabled tools for a tenant."""
    tools = list_disabled_tools(tenant_id)
    return {
        "tenant_id": tenant_id,
        "disabled_tools": tools,
        "count": len(tools),
    }
