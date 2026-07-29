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
import time
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from storage.mcp_gateway_store import (
    ROUTE_NAME_RULE,
    delete_upstream,
    get_upstream,
    is_valid_route_name,
    list_upstreams,
    set_upstream,
)
from storage.mcp_policy_store import (
    bind_route,
    delete_profile,
    fanout_profile,
    get_profile,
    is_drifted,
    list_bound_routes,
    list_profiles,
    set_profile,
    stamp_effective_policy,
    unbind_route,
)
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
    route: Optional[str] = Field(
        None,
        description="Disable only on this MCP server. Omit for fleet-wide "
                    "(the original behavior).")


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
    # Normalize the administrative on/off flag so the console never has to know
    # that a missing key means enabled (routes predating the flag have no key).
    for s in servers:
        s["active"] = bool(s.get("active", True))
        # Denormalizing policy onto the route buys a free guard path but can go
        # stale if a fan-out only partly succeeded. Surface that rather than
        # letting a route quietly serve a superseded revision.
        profile_id = s.get("profile_id")
        s["drift"] = is_drifted(s, get_profile(tenant_id, profile_id) if profile_id else None)
    disabled = list_disabled_tools(tenant_id)
    disabled_names = {d.get("tool_name") for d in disabled}

    return {
        "tenant_id": tenant_id,
        "servers": servers,
        "server_count": len(servers),
        "inactive_server_count": sum(1 for s in servers if not s["active"]),
        "drifted_server_count": sum(1 for s in servers if s["drift"]),
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
                        reason=body.reason, actor=actor, route=body.route)

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
            "tool_name": tool_name, "route": body.route, "metadata": meta}


class ToolEnableRequest(BaseModel):
    route: Optional[str] = Field(
        None, description="Must match the scope the tool was disabled at.")


@router.post("/tools/{tool_name}/enable")
async def enable(tool_name: str, request: Request,
                 body: Optional[ToolEnableRequest] = None):
    """Re-enable a tool this tenant previously disabled.

    The body is optional so existing callers that send none keep working; with
    no ``route`` this lifts the fleet-wide disable, exactly as before.
    """
    tenant_id = _require_tenant(request)
    actor = _actor(request)
    route = body.route if body else None

    if not enable_tool(tenant_id=tenant_id, tool_name=tool_name, route=route):
        scope = f" on route '{route}'" if route else ""
        raise HTTPException(status_code=404,
                            detail=f"Tool '{tool_name}' was not disabled{scope}")

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="tool_enabled", actor=actor, tenant_id=tenant_id,
                         after={"tool_name": tool_name, "route": route,
                                "via": "portal"})
    except Exception:
        pass

    return {"status": "enabled", "tenant_id": tenant_id, "tool_name": tool_name,
            "route": route}


# ── server registration (portal write path) ──────────────────────────────
#
# The data-plane gateway API (api/routes_mcp_gateway.py) owns the same store;
# this admin-plane pair lets the portal register/remove a server without the
# dev dropping to curl. The data plane reads get_upstream() per request
# (core/mcp/gateway.py:_load_cfg), so a write here is picked up on the next
# call with no cross-plane invalidation — a new route has no pooled connection,
# and a delete makes _load_cfg 404 immediately. (Only a long-lived stdio
# connection object is pooled; config/enforcement is always re-read.)

# Route names become a URL path segment and a Redis key component — constrain
# them rather than trusting the caller. The pattern now lives in
# storage.mcp_gateway_store so the data plane applies the identical rule.


class RegisterServerRequest(BaseModel):
    """Mirrors api/routes_mcp_gateway.py::UpstreamConfigRequest. Kept in sync
    deliberately; the portal must not accept a shape the data plane rejects."""
    route: str = Field(..., description="short route id, used in the gateway URL")
    transport: str = Field(..., description="stdio | sse | http")
    command: Optional[str] = None
    args: Optional[list[str]] = None
    env: Optional[dict[str, str]] = None
    url: Optional[str] = None
    headers: Optional[dict[str, str]] = None
    enforcement_backend: str = Field("inprocess", description="inprocess | http")
    shield_url: Optional[str] = None
    shield_tenant_key: Optional[str] = None
    scan_descriptions: bool = False
    isolation_ack: bool = False
    # Administrative on/off for the whole server (see core/mcp/gateway.py).
    active: bool = True

    @model_validator(mode="after")
    def _check(self):
        if not is_valid_route_name(self.route or ""):
            raise ValueError(ROUTE_NAME_RULE)
        if self.transport not in ("stdio", "sse", "http"):
            raise ValueError("transport must be one of: stdio, sse, http")
        if self.transport == "stdio" and not self.command:
            raise ValueError("stdio transport requires 'command'")
        if self.transport in ("sse", "http") and not self.url:
            raise ValueError(f"{self.transport} transport requires 'url'")
        if self.enforcement_backend not in ("inprocess", "http"):
            raise ValueError("enforcement_backend must be inprocess or http")
        return self


@router.post("/servers")
async def register_server(body: RegisterServerRequest, request: Request):
    """Register or replace an upstream MCP server for THIS tenant."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)
    route = body.route

    existing = get_upstream(tenant_id, route)
    cfg = body.model_dump(exclude_none=True)
    cfg.pop("route", None)
    cfg["route"] = route
    cfg["tenant_id"] = tenant_id
    cfg["created_at"] = (existing or {}).get("created_at") or int(time.time())
    cfg["updated_at"] = int(time.time())
    set_upstream(tenant_id, route, cfg)

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="mcp_gateway_register_upstream", actor=actor,
                         tenant_id=tenant_id,
                         after={"route": route, "transport": body.transport,
                                "enforcement_backend": body.enforcement_backend,
                                "isolation_ack": body.isolation_ack, "via": "portal"})
    except Exception:
        pass

    resp = {"status": "updated" if existing else "created",
            "route": route, "server": _redact(cfg)}
    if not body.isolation_ack:
        resp["warning"] = ("isolation_ack is false — Shield only enforces if this "
                           "upstream accepts connections ONLY from the gateway "
                           "(firewall / mTLS / localhost). Otherwise an agent can "
                           "reach it directly and bypass Shield.")
    return resp


@router.delete("/servers/{route}")
async def delete_server(route: str, request: Request):
    """Remove an upstream this tenant registered."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)

    # Drop the fan-out index entry first. A deleted route left in a profile's
    # index would block that profile from ever being deleted (the 409 lists a
    # route that no longer exists) and make every fan-out report it missing.
    existing = get_upstream(tenant_id, route)
    if existing and existing.get("profile_id"):
        unbind_route(tenant_id, existing["profile_id"], route)

    if not delete_upstream(tenant_id, route):
        raise HTTPException(status_code=404, detail=f"route '{route}' not found")

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="mcp_gateway_delete_upstream", actor=actor,
                         tenant_id=tenant_id, after={"route": route, "via": "portal"})
    except Exception:
        pass

    return {"status": "deleted", "tenant_id": tenant_id, "route": route}


# ── server enable / disable ──────────────────────────────────────────────
#
# Deleting a server loses its config (URL, credentials, enforcement backend).
# During an incident SecOps wants to cut access NOW and restore it later, so
# these flip an `active` flag the gateway checks in _load_cfg — one choke point
# that every MCP method funnels through, which means one flag disconnects every
# client (Cursor, Claude, Codex, and anything else speaking MCP) at once.

def _set_active(tenant_id: str, route: str, active: bool) -> dict:
    cfg = get_upstream(tenant_id, route)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"route '{route}' not found")
    updated = dict(cfg)
    updated["active"] = active
    updated["updated_at"] = int(time.time())
    set_upstream(tenant_id, route, updated)
    return updated


@router.post("/servers/{route}/disable")
async def disable_server(route: str, body: ToolActionRequest, request: Request):
    """Stop serving a whole MCP server, keeping its config. Effective on the
    next call — the gateway re-reads config per request."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)
    cfg = _set_active(tenant_id, route, False)

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="mcp_server_disabled", actor=actor,
                         tenant_id=tenant_id,
                         after={"route": route, "reason": body.reason,
                                "via": "portal"})
    except Exception:
        pass

    return {"status": "disabled", "tenant_id": tenant_id, "route": route,
            "server": _redact(cfg)}


@router.post("/servers/{route}/enable")
async def enable_server(route: str, request: Request):
    """Re-enable a server previously disabled here."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)
    cfg = _set_active(tenant_id, route, True)

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="mcp_server_enabled", actor=actor,
                         tenant_id=tenant_id, after={"route": route, "via": "portal"})
    except Exception:
        pass

    return {"status": "enabled", "tenant_id": tenant_id, "route": route,
            "server": _redact(cfg)}


# ── policy profiles ──────────────────────────────────────────────────────
#
# A profile is a named policy bundle bound to many servers, so a fleet is
# governed centrally. This phase stores and serves them; nothing enforces a
# profile yet (see docs/spec-mcp-fleet-control-plane.md phases 3+), which is
# deliberate — policy that is authored but inert cannot break the guard path.

class ProfileRequest(BaseModel):
    """Author-supplied profile body. Field shapes are validated as policy is
    wired into enforcement, phase by phase; storing an unknown key now would let
    an operator believe a control is live before it is, so the accepted set is
    explicit and everything else is rejected."""

    # Pydantic ignores unknown keys by default. Silently dropping a misspelled
    # `output_guardrail` would store a profile the operator believes is stricter
    # than it is, so unknown keys are an error.
    model_config = ConfigDict(extra="forbid")

    description: str = Field("", max_length=500)
    tools: Optional[dict[str, Any]] = None
    input_guardrails: Optional[dict[str, Any]] = None
    output_guardrails: Optional[dict[str, Any]] = None
    dlp: Optional[dict[str, Any]] = None
    result_scanning: Optional[dict[str, Any]] = None
    scan_policy: Optional[dict[str, Any]] = None


@router.get("/profiles")
async def list_policy_profiles(request: Request):
    tenant_id = _require_tenant(request)
    profiles = list_profiles(tenant_id)
    return {
        "tenant_id": tenant_id,
        "profiles": profiles,
        "count": len(profiles),
        # State exactly which controls are live, so nobody assumes a field that
        # is merely storable is also enforced.
        "enforcement_note": (
            "Enforced on bound routes: tools.allow / tools.deny (tools/list and "
            "tools/call), dlp.sanitize_as (tool results and resources/read), "
            "output_guardrails, result_scanning, and scan_policy (tool-description "
            "scanning at tools/list). input_guardrails and output_guardrails apply "
            "on the inprocess backend only. scan_policy gates discovery, not "
            "invocation — use tools.deny to make a flagged tool unreachable."),
    }


@router.get("/profiles/{profile_id}")
async def get_policy_profile(profile_id: str, request: Request):
    tenant_id = _require_tenant(request)
    doc = get_profile(tenant_id, profile_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"profile '{profile_id}' not found")
    return {"tenant_id": tenant_id, "profile": doc,
            "bound_routes": list_bound_routes(tenant_id, profile_id)}


@router.put("/profiles/{profile_id}")
async def put_policy_profile(profile_id: str, body: ProfileRequest, request: Request):
    """Create or replace a profile. Profile ids share the route charset: both
    end up in Redis keys, and one rule is easier to hold than two."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)
    if not is_valid_route_name(profile_id):
        raise HTTPException(status_code=422,
                            detail=ROUTE_NAME_RULE.replace("route", "profile_id"))

    existing = get_profile(tenant_id, profile_id)
    doc = set_profile(tenant_id, profile_id, body.model_dump(exclude_none=True))
    # Push the new revision to every bound route. Partial failure is reported,
    # not raised: one unwritable route must not abort the rest of the fleet, and
    # whatever is left behind shows up as drift in the inventory.
    fanout = fanout_profile(tenant_id, profile_id)

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="mcp_profile_upsert", actor=actor,
                         tenant_id=tenant_id, before=existing,
                         after={"profile_id": profile_id, "via": "portal",
                                "fanout": fanout})
    except Exception:
        pass

    resp = {"status": "updated" if existing else "created",
            "tenant_id": tenant_id, "profile": doc, "fanout": fanout}
    if fanout["failed"] or fanout["missing"]:
        resp["warning"] = (
            "Some bound routes were not updated and are now serving a stale "
            "policy revision; they are flagged as drifted in the inventory.")
    return resp


@router.delete("/profiles/{profile_id}")
async def delete_policy_profile(profile_id: str, request: Request):
    """Delete a profile. Refused while routes are bound: silently unbinding
    servers would drop their policy without anyone asking for that."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)

    bound = list_bound_routes(tenant_id, profile_id)
    if bound:
        raise HTTPException(
            status_code=409,
            detail=f"profile '{profile_id}' is bound to {len(bound)} route(s): "
                   f"{', '.join(bound)}. Unbind them first.")

    if not delete_profile(tenant_id, profile_id):
        raise HTTPException(status_code=404, detail=f"profile '{profile_id}' not found")

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="mcp_profile_delete", actor=actor,
                         tenant_id=tenant_id, after={"profile_id": profile_id,
                                                     "via": "portal"})
    except Exception:
        pass

    return {"status": "deleted", "tenant_id": tenant_id, "profile_id": profile_id}


# ── binding a server to a profile ────────────────────────────────────────
#
# Binding is its own sub-resource rather than a field on the server PUT, because
# that PUT replaces the whole document: editing policy through it would force the
# operator to re-send the upstream's credentials every time, which is how bearer
# tokens end up in shell history.

class BindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str = Field(..., description="profile to apply to this server")
    overrides: Optional[dict[str, Any]] = Field(
        None, description="per-server exceptions; same shape as a profile, partial")


@router.put("/servers/{route}/binding")
async def put_binding(route: str, body: BindingRequest, request: Request):
    """Bind a server to a policy profile and materialize its effective policy."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)

    cfg = get_upstream(tenant_id, route)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"route '{route}' not found")
    profile = get_profile(tenant_id, body.profile_id)
    if not profile:
        raise HTTPException(status_code=404,
                            detail=f"profile '{body.profile_id}' not found")

    previous = cfg.get("profile_id")
    if previous and previous != body.profile_id:
        # Leave no dangling entry in the old profile's fan-out index, or its
        # next write would try to recompute a route it no longer governs.
        unbind_route(tenant_id, previous, route)

    updated = dict(cfg)
    updated["profile_id"] = body.profile_id
    if body.overrides is None:
        updated.pop("overrides", None)
    else:
        updated["overrides"] = body.overrides
    updated = stamp_effective_policy(updated, profile, updated.get("overrides"))
    updated["updated_at"] = int(time.time())
    set_upstream(tenant_id, route, updated)
    bind_route(tenant_id, body.profile_id, route)

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="mcp_binding_set", actor=actor, tenant_id=tenant_id,
                         before={"profile_id": previous},
                         after={"route": route, "profile_id": body.profile_id,
                                "via": "portal"})
    except Exception:
        pass

    resp = {"status": "bound", "tenant_id": tenant_id, "route": route,
            "profile_id": body.profile_id, "server": _redact(updated)}

    # The guard chain runs on the central Shield under the `http` backend, so
    # per-server input_guardrails silently would not apply there. Say so at bind
    # time, where the operator can still change the backend or the profile.
    if (updated.get("enforcement_backend") == "http"
            and (updated.get("effective_policy") or {}).get("input_guardrails")):
        resp["warning"] = (
            "This route uses the 'http' enforcement backend, where the guard "
            "chain runs on the central Shield: the profile's input_guardrails "
            "will NOT apply. The tool allowlist and kill switch still do. Use "
            "the 'inprocess' backend for route-scoped input screening.")
    return resp


@router.delete("/servers/{route}/binding")
async def delete_binding(route: str, request: Request):
    """Unbind a server, dropping its materialized policy. The server keeps
    serving traffic under the tenant-wide defaults it used before binding."""
    tenant_id = _require_tenant(request)
    actor = _actor(request)

    cfg = get_upstream(tenant_id, route)
    if not cfg:
        raise HTTPException(status_code=404, detail=f"route '{route}' not found")
    previous = cfg.get("profile_id")
    if not previous:
        raise HTTPException(status_code=404, detail=f"route '{route}' is not bound")

    updated = dict(cfg)
    for k in ("profile_id", "overrides", "effective_policy", "effective_rev"):
        updated.pop(k, None)
    updated["updated_at"] = int(time.time())
    set_upstream(tenant_id, route, updated)
    unbind_route(tenant_id, previous, route)

    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action="mcp_binding_cleared", actor=actor,
                         tenant_id=tenant_id, before={"profile_id": previous},
                         after={"route": route, "via": "portal"})
    except Exception:
        pass

    return {"status": "unbound", "tenant_id": tenant_id, "route": route,
            "previous_profile_id": previous}
