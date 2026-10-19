"""Model routing configuration (admin plane).

Spec: docs/specs/gateway-routing-failover.md, section 4.2.

    GET    /v1/tenant/me/gateway/targets
    GET    /v1/tenant/me/gateway/targets/{id}
    PUT    /v1/tenant/me/gateway/targets/{id}
    DELETE /v1/tenant/me/gateway/targets/{id}
    GET    /v1/tenant/me/gateway/routes
    GET    /v1/tenant/me/gateway/routes/{name}
    PUT    /v1/tenant/me/gateway/routes/{name}
    DELETE /v1/tenant/me/gateway/routes/{name}
    POST   /v1/tenant/me/gateway/routes/{name}/simulate   {messages, flagged, data_class, agent, role}
    GET    /v1/tenant/me/gateway/usage?days=&route=
    GET    /v1/tenant/me/gateway/health

Reads need the tenant; writes go through the config write gate, and a target
that may reach a private address also through the registry write gate, as an
MCP server does. Off the proxy path.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import get_tenant_from_request, require_config_write
from core.llm_gateway import config, select

router = APIRouter(prefix="/v1/tenant/me/gateway", tags=["model-routing"])


class Simulation(BaseModel):
    messages: list = Field(default_factory=list)
    flagged: list[str] = Field(default_factory=list, max_length=50)
    data_class: str = ""
    agent: str = ""
    role: str = ""


def _actor(request: Request, tenant_id: str) -> str:
    try:
        from core.auth import audit_actor
        return audit_actor(request, tenant_id)
    except Exception:
        return ""


def _audit(request: Request, tenant_id: str, action: str, after: dict) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=_actor(request, tenant_id), tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "", after=after)
    except Exception:
        pass


def _err(e: config.ConfigError):
    return HTTPException(status_code=e.status, detail={"message": "invalid routing config", "errors": e.errors})


def _check_vault_binding(tenant_id: str, target: dict) -> None:
    """A vault reference must exist and be bound to the target's host, so the
    proxy can never send a placeholder as if it were a key."""
    auth = target.get("auth") or {}
    if auth.get("mode") != "vault":
        return
    from core.secret_vault.keyprovider import vault_enabled
    from core.secret_vault.materialize import _binding_matches, is_self_host
    from storage.vault_store import resolve_binding
    if not vault_enabled():
        raise config.ConfigError(["auth.mode vault: the secret vault is not enabled on this deployment "
                                  "(SECRET_VAULT_ENABLED); use passthrough or none"])
    ref = auth["secret_ref"]
    bound = resolve_binding(tenant_id, ref.removeprefix("shield://"))
    if bound is None:
        bound = resolve_binding(tenant_id, ref)
    if bound is None:
        raise config.ConfigError([f"auth.secret_ref: no vault secret {ref}"])
    _, bindings, tool_ids = bound
    if tool_ids:
        raise config.ConfigError([f"auth.secret_ref: {ref} is scoped to tools; use a secret without a tool scope"])
    url = config.target_url(target)
    if is_self_host(url) or not _binding_matches(url, bindings):
        raise config.ConfigError([f"auth.secret_ref: {ref} is not bound to {url.split('/')[2]}; "
                                  f"add that host to the secret's bindings"])


# ── targets ──────────────────────────────────────────────────────────


@router.get("/targets")
async def list_targets(request: Request):
    tenant_id = get_tenant_from_request(request)
    targets, routes = config.load(tenant_id)
    used = {}
    for name, r in routes.items():
        for t in r.get("targets") or []:
            used.setdefault(t, []).append(name)
    return {"targets": [{**config.public_target(t), "routes": sorted(used.get(tid, []))}
                        for tid, t in sorted(targets.items())], "max": config.TARGETS_MAX}


@router.get("/targets/{target_id}")
async def get_target(target_id: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    targets, _ = config.load(tenant_id)
    if target_id not in targets:
        raise HTTPException(status_code=404, detail=f"no target '{target_id}'")
    return config.public_target(targets[target_id])


@router.put("/targets/{target_id}")
async def put_target(target_id: str, request: Request, body: dict = Body(...)):
    from core.llm_gateway.dispatch import check_url_sync
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "change a model routing target")
    if body.get("allow_private") is True:
        from core.auth import require_registry_write
        require_registry_write(request, tenant_id, "let a model target reach a private address")
    try:
        target = config.validate_target(target_id, body, check_url=check_url_sync)
        _check_vault_binding(tenant_id, target)
        saved = config.save_target(tenant_id, target, actor=_actor(request, tenant_id))
    except config.ConfigError as e:
        raise _err(e)
    _audit(request, tenant_id, "gateway_target_set",
           {"id": target_id, "base_url": saved["base_url"], "model": saved["model"],
            "auth_mode": saved["auth"]["mode"], "location": saved["location"],
            "allow_private": saved["allow_private"]})
    return config.public_target(saved)


@router.delete("/targets/{target_id}")
async def delete_target(target_id: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "delete a model routing target")
    try:
        if not config.delete_target(tenant_id, target_id):
            raise HTTPException(status_code=404, detail=f"no target '{target_id}'")
    except config.ConfigError as e:
        raise _err(e)
    _audit(request, tenant_id, "gateway_target_deleted", {"id": target_id})
    return {"deleted": target_id}


# ── routes ───────────────────────────────────────────────────────────


@router.get("/routes")
async def list_routes(request: Request):
    tenant_id = get_tenant_from_request(request)
    _, routes = config.load(tenant_id)
    return {"routes": [routes[n] for n in sorted(routes)], "max": config.ROUTES_MAX}


@router.get("/routes/{name:path}/simulate")
async def simulate_needs_post(name: str):
    raise HTTPException(status_code=405, detail="POST a sample request to simulate a route")


@router.post("/routes/{name:path}/simulate")
async def simulate_route(name: str, body: Simulation, request: Request):
    """Which targets a call would try, in order, and why. Calls no model and
    runs no guardrails (they run on the data plane): `flagged` names the
    guardrails that would flag the prompt."""
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "simulate a model route")
    targets, routes = config.load(tenant_id)
    route = routes.get(name)
    if route is None:
        raise HTTPException(status_code=404, detail=f"no route '{name}'")
    from core.llm_gateway.proxy import _prompt_chars
    ctx = select.CallContext(tenant_id=tenant_id, agent=body.agent[:128], role=body.role[:128],
                             data_class=body.data_class.strip().lower()[:64],
                             flagged=tuple(sorted({f[:128] for f in body.flagged})),
                             prompt_chars=_prompt_chars(body.messages))
    snap = config.Snapshot(targets, routes, _spend(tenant_id))
    p = select.plan(snap, route, ctx)
    if isinstance(p, select.Refusal):
        return {"route": name, "outcome": "refused", "reason": p.reason, "code": p.code}
    return {"route": name, "outcome": "routed", "order": [t["id"] for t in p.targets], "rule": p.rule,
            "budget": p.budget, "skipped": p.skipped}


def _spend(tenant_id: str) -> dict:
    try:
        from core.llm_gateway import usage
        return usage.month_spend(tenant_id)
    except Exception:
        return {}


@router.get("/routes/{name:path}")
async def get_route(name: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    _, routes = config.load(tenant_id)
    if name not in routes:
        raise HTTPException(status_code=404, detail=f"no route '{name}'")
    return routes[name]


@router.put("/routes/{name:path}")
async def put_route(name: str, request: Request, body: dict = Body(...)):
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "change a model route")
    targets, _ = config.load(tenant_id)
    try:
        route = config.validate_route(name, body, targets)
        saved = config.save_route(tenant_id, route, actor=_actor(request, tenant_id))
    except config.ConfigError as e:
        raise _err(e)
    _audit(request, tenant_id, "gateway_route_set",
           {"name": name, "targets": saved["targets"], "strategy": saved["strategy"],
            "rules": len(saved["rules"]), "budget": saved["budget"]})
    return saved


@router.delete("/routes/{name:path}")
async def delete_route(name: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    require_config_write(request, tenant_id, "delete a model route")
    if not config.delete_route(tenant_id, name):
        raise HTTPException(status_code=404, detail=f"no route '{name}'")
    _audit(request, tenant_id, "gateway_route_deleted", {"name": name})
    return {"deleted": name}


@router.get("/health")
async def get_health(request: Request):
    """Each data-plane process's last view of its targets (flushed every 30 s).
    A target can be open in one process and closed in another."""
    from core.llm_gateway import health
    tenant_id = get_tenant_from_request(request)
    return {"targets": health.stored(tenant_id), "flush_s": health.FLUSH_S, "open_s": health.OPEN_S,
            "fail_threshold": health.FAIL_THRESHOLD}
