"""Tool Kill Switch routes — instantly disable/enable tools for a tenant.

A caller acts for its own tenant; an admin identity for the tenant it names.
See docs/specs/killswitch-tenant-scope.md.
"""

import logging
import os

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional

import asyncio
from core.auth import (SCOPE_ADMIN, SCOPE_TENANT, authorized_tenant_scope,
                       caller_tenant_scope, require_registry_write)
from storage.tool_killswitch import disable_tool, enable_tool, list_disabled_tools
from storage.admin_audit import log_admin_action
from core.webhook_dispatcher import dispatch_event

logger = logging.getLogger("votal.killswitch")

router = APIRouter(prefix="/v1/shield/tools", tags=["killswitch"])

# Escape hatch for one release: a tenant credential may act for whichever
# tenant it names, as before. A credential is still required. Temporary; see
# the spec's migration note.
_TRUST_BODY_ENV = "SHIELD_KILLSWITCH_TRUST_BODY_TENANT"
SCOPE_CROSS_TENANT = "cross_tenant"
_warned_open = False


def _trust_body_tenant() -> bool:
    return os.environ.get(_TRUST_BODY_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _scope(request: Request, claimed: Optional[str], write: bool) -> tuple:
    """(tenant_id, scope) for this request, or raise 400/401/403/503."""
    global _warned_open
    claimed = (claimed or "").strip()
    if _trust_body_tenant():
        # Still a credential: the hatch exists for tenant keys that act for
        # other tenants during migration, never for anonymous callers.
        scope, own = caller_tenant_scope(request)
        if scope == SCOPE_TENANT and claimed and claimed != own:
            if not _warned_open:
                _warned_open = True
                logger.warning("%s is on: tenant credentials may use the tool kill "
                               "switch for other tenants. Turn it off.", _TRUST_BODY_ENV)
            logger.warning("kill switch: tenant %s acted for tenant %s (%s)",
                           own, claimed, _TRUST_BODY_ENV)
            if write:
                require_registry_write(request, own, action="use the tool kill switch")
            return claimed, SCOPE_CROSS_TENANT
    tenant_id, scope = authorized_tenant_scope(request, claimed)
    if write and scope == SCOPE_TENANT:
        require_registry_write(request, tenant_id, action="use the tool kill switch")
    return tenant_id, scope


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


def _audit_metadata(request: Request, scope: str, tenant_id: str) -> dict:
    """Who acted, and for whom: an admin acting for a tenant shows as such."""
    if scope == SCOPE_ADMIN:
        return {"scope": scope, "caller_tenant": None}
    if scope == SCOPE_CROSS_TENANT:
        return {"scope": scope, "caller_tenant": caller_tenant_scope(request)[1]}
    return {"scope": scope, "caller_tenant": tenant_id}


class DisableToolRequest(BaseModel):
    tenant_id: Optional[str] = Field(None, description="Tenant ID. Optional for a tenant key "
                                     "(its own tenant is used); required for an admin identity")
    reason: str = Field("", description="Why the tool is being disabled")


class EnableToolRequest(BaseModel):
    tenant_id: Optional[str] = Field(None, description="Tenant ID. Optional for a tenant key "
                                     "(its own tenant is used); required for an admin identity")


@router.post("/{tool_name}/disable")
async def disable_tool_endpoint(tool_name: str, body: DisableToolRequest, request: Request):
    """Disable a tool across all agents of a tenant. Immediate effect."""
    tenant_id, scope = _scope(request, body.tenant_id, write=True)
    actor = _actor_from_request(request)

    meta = disable_tool(
        tenant_id=tenant_id,
        tool_name=tool_name,
        reason=body.reason,
        actor=actor,
    )

    log_admin_action(
        action="tool_disabled",
        actor=actor,
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={"tool_name": tool_name, "reason": body.reason},
        metadata=_audit_metadata(request, scope, tenant_id),
    )

    # Fire webhook event (only if webhooks enabled)
    from core.feature_flags import WEBHOOKS_ENABLED
    if WEBHOOKS_ENABLED:
        asyncio.create_task(dispatch_event(
            tenant_id=tenant_id,
            event_type="tool_disabled",
            payload={"tool_name": tool_name, "reason": body.reason, "actor": actor},
        ))

    return {
        "status": "disabled",
        "tenant_id": tenant_id,
        "tool_name": tool_name,
        "metadata": meta,
    }


@router.post("/{tool_name}/enable")
async def enable_tool_endpoint(tool_name: str, body: EnableToolRequest, request: Request):
    """Re-enable a previously disabled tool."""
    tenant_id, scope = _scope(request, body.tenant_id, write=True)
    actor = _actor_from_request(request)

    was_disabled = enable_tool(tenant_id=tenant_id, tool_name=tool_name)

    if not was_disabled:
        raise HTTPException(
            status_code=404,
            detail=f"Tool '{tool_name}' was not disabled for tenant '{tenant_id}'"
        )

    log_admin_action(
        action="tool_enabled",
        actor=actor,
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={"tool_name": tool_name},
        metadata=_audit_metadata(request, scope, tenant_id),
    )

    return {
        "status": "enabled",
        "tenant_id": tenant_id,
        "tool_name": tool_name,
    }


@router.get("/disabled")
async def list_disabled_tools_endpoint(request: Request, tenant_id: Optional[str] = None):
    """List all currently disabled tools for a tenant."""
    tenant_id, _ = _scope(request, tenant_id, write=False)
    tools = list_disabled_tools(tenant_id)
    return {
        "tenant_id": tenant_id,
        "disabled_tools": tools,
        "count": len(tools),
    }
