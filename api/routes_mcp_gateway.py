"""Tenant self-service config for the MCP gateway.

Manage which unmodified upstream MCP server each route fronts. Tenant-scoped:
a tenant key can only see/edit its own routes. Upstream credentials
(headers/env/shield_tenant_key) are stored but redacted on read.
"""

import time
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, model_validator

from core.auth import get_tenant_from_request
from core.mcp.gateway import router as gateway_router
from storage.admin_audit import log_admin_action
from storage.mcp_gateway_store import (
    ROUTE_NAME_RULE,
    delete_upstream,
    get_upstream,
    is_valid_route_name,
    list_upstreams,
    set_upstream,
)

router = APIRouter(prefix="/v1/tenant/me/mcp-gateway", tags=["mcp-gateway"])

_SECRET_KEYS = ("headers", "env", "shield_tenant_key")


class UpstreamConfigRequest(BaseModel):
    transport: str = Field(..., description="stdio | sse | http")
    # stdio
    command: Optional[str] = None
    args: Optional[list[str]] = None
    env: Optional[dict[str, str]] = None
    # sse / http (streamable)
    url: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    # Shield enforcement
    enforcement_backend: str = Field("inprocess", description="inprocess | http")
    shield_url: Optional[str] = None
    shield_tenant_key: Optional[str] = None
    scan_descriptions: bool = False
    # Non-bypassability: set true once the upstream is network-isolated to the gateway.
    isolation_ack: bool = False
    # Administrative on/off for the whole server. False makes the gateway refuse
    # every method for this route (core/mcp/gateway.py::_load_cfg) without losing
    # the config, so SecOps can park a server instead of deleting it.
    # Optional, not defaulted — see the note in api/routes_mcp_admin.py.
    active: Optional[bool] = None

    @model_validator(mode="after")
    def _check(self):
        if self.transport not in ("stdio", "sse", "http"):
            raise ValueError("transport must be one of: stdio, sse, http")
        if self.transport == "stdio" and not self.command:
            raise ValueError("stdio transport requires 'command'")
        if self.transport in ("sse", "http") and not self.url:
            raise ValueError(f"{self.transport} transport requires 'url'")
        if self.enforcement_backend not in ("inprocess", "http"):
            raise ValueError("enforcement_backend must be inprocess or http")
        return self


def _tenant_id(request: Request) -> str:
    return get_tenant_from_request(request)


def _redact(cfg: dict) -> dict:
    """Mask secret values on read (keep shape so operators see what's set)."""
    out = dict(cfg)
    for k in _SECRET_KEYS:
        v = out.get(k)
        if isinstance(v, dict) and v:
            out[k] = {kk: "***" for kk in v}
        elif v:
            out[k] = "***"
    return out


@router.get("/upstreams")
async def list_routes(request: Request):
    tenant_id = _tenant_id(request)
    return {"tenant_id": tenant_id, "upstreams": [_redact(c) for c in list_upstreams(tenant_id)]}


@router.get("/upstreams/{route}")
async def get_route(route: str, request: Request):
    tenant_id = _tenant_id(request)
    cfg = get_upstream(tenant_id, route)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"route '{route}' not configured")
    return {"tenant_id": tenant_id, "route": route, "upstream": _redact(cfg)}


@router.put("/upstreams/{route}")
async def put_route(route: str, body: UpstreamConfigRequest, request: Request):
    tenant_id = _tenant_id(request)
    existing = get_upstream(tenant_id, route)
    # Validate only when CREATING. A route registered before this rule existed
    # must stay editable by its owner; rejecting the update would strand it with
    # no way to fix its config short of delete-and-recreate.
    if existing is None and not is_valid_route_name(route):
        raise HTTPException(status_code=422, detail=ROUTE_NAME_RULE)
    cfg: dict[str, Any] = body.model_dump(exclude_none=True)
    cfg["route"] = route
    cfg["tenant_id"] = tenant_id
    cfg["created_at"] = (existing or {}).get("created_at") or int(time.time())
    cfg["updated_at"] = int(time.time())
    # Mirror the admin plane: a config rewrite must not silently unbind the route
    # from its policy profile or re-enable a server an operator disabled.
    from api.routes_mcp_admin import _carry_over
    _carry_over(cfg, existing)
    set_upstream(tenant_id, route, cfg)
    gateway_router.invalidate(tenant_id, route)  # drop any pooled connection
    log_admin_action(
        action="mcp_gateway_upsert_upstream", actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id, source_ip=request.client.host if request.client else "",
        metadata={"route": route, "transport": body.transport,
                  "enforcement_backend": body.enforcement_backend,
                  "isolation_ack": body.isolation_ack},
    )
    resp = {"status": "updated" if existing else "created", "route": route,
            "upstream": _redact(cfg)}
    if not body.isolation_ack:
        resp["warning"] = ("isolation_ack is false — Shield only enforces if the upstream "
                           "accepts connections ONLY from this gateway (firewall/mTLS/localhost).")
    return resp


@router.delete("/upstreams/{route}")
async def delete_route(route: str, request: Request):
    tenant_id = _tenant_id(request)
    # Mirror the admin plane: a deleted route left in its profile's fan-out
    # index would block that profile from ever being deleted.
    existing = get_upstream(tenant_id, route)
    if existing and existing.get("profile_id"):
        from storage.mcp_policy_store import unbind_route
        unbind_route(tenant_id, existing["profile_id"], route)
    if not delete_upstream(tenant_id, route):
        raise HTTPException(status_code=404, detail=f"route '{route}' not configured")
    gateway_router.invalidate(tenant_id, route)
    log_admin_action(
        action="mcp_gateway_delete_upstream", actor=f"tenant:{tenant_id}",
        tenant_id=tenant_id, source_ip=request.client.host if request.client else "",
        metadata={"route": route},
    )
    return {"status": "deleted", "route": route}
