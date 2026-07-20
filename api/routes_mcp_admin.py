"""Tenant-facing MCP gateway console (admin plane / portal).

The MCP gateway config + enforcement routers live on the DATA plane
(core/app.py). The portal runs on the ADMIN plane and, until now, had no MCP
surface at all — a tenant using the gateway managed it blind through curl.

This router gives the portal a read view of the tenant's MCP footprint plus a
kill-switch control, reading the same Redis keys the data plane writes (no
cross-plane HTTP). Every handler derives the tenant from the VERIFIED
request.state, never from the body or a query param:

    api/routes_killswitch.py takes tenant_id from the request BODY with no check
    that it matches the caller — a cross-tenant IDOR. We do not build on it; we
    call the storage layer directly with the authenticated tenant. (That router
    is flagged for a separate fix.)

Scope of the poisoning/threat view: it is the static threat mapping the AIBOM
pipeline already computes from the registered server list (storage.aibom_mappings
+ storage.aibom). The LIVE per-tool description scan runs in the data-plane proxy
on tools/list and is deliberately not duplicated here — the admin image does not
carry the scanner package, and a stale persisted copy would be worse than a
truthful "scanned live at call time" note.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from storage.mcp_gateway_store import list_upstreams
from storage.tool_killswitch import (
    disable_tool,
    enable_tool,
    list_disabled_tools,
)

router = APIRouter(prefix="/v1/tenant/me/mcp", tags=["mcp-console"])

_SECRET_KEYS = ("headers", "env", "shield_tenant_key")

# Threats a registered MCP server exposes, per the AIBOM mapping. Imported
# lazily so a missing mapping module degrades to "no threats listed" rather
# than a 500 (the console must render even if the AIBOM layer is absent).
_MCP_THREAT_KEY = "mcp_servers"


def _require_tenant(request: Request) -> str:
    """Verified tenant from middleware state, or 401. Never from body/query."""
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(
            status_code=401,
            detail="Tenant API key required to access /v1/tenant/* endpoints",
        )
    return tenant_id


def _redact(cfg: dict) -> dict:
    """Mask secret values, mirroring api/routes_mcp_gateway.py::_redact so the
    portal never shows upstream credentials."""
    out = dict(cfg)
    for k in _SECRET_KEYS:
        v = out.get(k)
        if isinstance(v, dict) and v:
            out[k] = {kk: "***" for kk in v}
        elif v:
            out[k] = "***"
    return out


def _mcp_threats() -> list[str]:
    try:
        from storage.aibom_mappings import CATEGORY_THREATS
        return list(CATEGORY_THREATS.get(_MCP_THREAT_KEY, []))
    except Exception:
        return []


class ToolActionRequest(BaseModel):
    # Note: no tenant_id field. The tenant is the authenticated one, full stop.
    reason: str = Field("", max_length=500,
                        description="Why the tool is being disabled (audited)")


def _actor(request: Request) -> str:
    ident = getattr(request.state, "identity", None) if hasattr(request, "state") else None
    sub = getattr(ident, "user_sub", None)
    return sub or "portal"


@router.get("/inventory")
async def mcp_inventory(request: Request):
    """One call for the portal MCP tab: registered upstreams (redacted), the
    kill-switch state, and the threats the gateway posture addresses.

    Read-only. All data is this tenant's, keyed by the verified tenant_id.
    """
    tenant_id = _require_tenant(request)

    servers = [_redact(c) for c in list_upstreams(tenant_id)]
    disabled = list_disabled_tools(tenant_id)
    disabled_names = {d.get("tool_name") for d in disabled}

    return {
        "tenant_id": tenant_id,
        "servers": servers,
        "server_count": len(servers),
        "disabled_tools": disabled,
        "disabled_count": len(disabled),
        "threats_addressed": _mcp_threats(),
        # Honest scope note the UI renders verbatim, so the tab never implies it
        # ran a live description scan it did not.
        "scan_note": ("Tool descriptions are scanned live in the gateway on "
                      "tools/list; disabled tools are enforced immediately. "
                      "This view reflects registered servers and kill-switch "
                      "state, not a point-in-time description scan."),
        "_disabled_names": sorted(n for n in disabled_names if n),
    }


@router.post("/tools/{tool_name}/disable")
async def disable(tool_name: str, body: ToolActionRequest, request: Request):
    """Kill-switch a tool for THIS tenant. Immediate effect on the guard path."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)

    meta = disable_tool(tenant_id=tenant_id, tool_name=tool_name,
                        reason=body.reason, actor=actor)

    # Audit + webhook, matching the data-plane kill-switch path.
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="tool_disabled", actor=actor, tenant_id=tenant_id,
                         after={"tool_name": tool_name, "reason": body.reason,
                                "via": "portal"})
    except Exception:
        pass
    try:
        from core.feature_flags import WEBHOOKS_ENABLED
        if WEBHOOKS_ENABLED:
            import asyncio
            from core.webhook_dispatcher import dispatch_event
            asyncio.create_task(dispatch_event(
                tenant_id=tenant_id, event_type="tool_disabled",
                payload={"tool_name": tool_name, "reason": body.reason,
                         "actor": actor, "via": "portal"}))
    except Exception:
        pass

    return {"status": "disabled", "tenant_id": tenant_id,
            "tool_name": tool_name, "metadata": meta}


@router.post("/tools/{tool_name}/enable")
async def enable(tool_name: str, request: Request):
    """Re-enable a tool this tenant previously disabled."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)

    if not enable_tool(tenant_id=tenant_id, tool_name=tool_name):
        raise HTTPException(status_code=404,
                            detail=f"Tool '{tool_name}' was not disabled")

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="tool_enabled", actor=actor, tenant_id=tenant_id,
                         after={"tool_name": tool_name, "via": "portal"})
    except Exception:
        pass

    return {"status": "enabled", "tenant_id": tenant_id, "tool_name": tool_name}
