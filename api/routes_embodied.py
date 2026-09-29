"""Action profiles for the embodied action guard: tenant API (both planes).

Spec: docs/specs/embodied-action-guard.md §7. Off the hot path: nothing here
runs on /guardrails/*, cap/mint or tools/call.

  /v1/tenant/me/embodied-profiles/...   list, validate, get, put, delete, history

The tenant always comes from the authenticated key. Writes go through the
registry write gate (SHIELD_REGISTRY_WRITE_SCOPE), like runtime profiles: a
robot's own key must not be able to loosen the rules it is held to.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Query, Request

from core.auth import get_tenant_from_request, require_registry_write
from core.embodied import store as em_store
from core.embodied.model import ProfileError, profile_hash, valid_name, validate_profile
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/tenant/me/embodied-profiles", tags=["embodied-profiles"])


def _audit(request: Request, action: str, tenant_id: str, metadata: dict) -> None:
    try:
        log_admin_action(action=action, actor=f"tenant:{tenant_id}", tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "",
                         metadata=metadata)
    except Exception:
        pass


def _actor(request: Request, tenant_id: str) -> str:
    try:
        from core.auth import portal_principal
        principal = portal_principal(request)
    except Exception:
        principal = None
    if principal:
        return f"user:{principal.get('email') or principal.get('sub') or '?'}"
    return f"tenant:{tenant_id}"


def _name(name: str) -> str:
    if not valid_name(name):
        raise HTTPException(status_code=400, detail="profile name: lowercase letters, digits, "
                                                    ". _ - (1-64 characters)")
    return name


def _invalid(e: ProfileError) -> HTTPException:
    return HTTPException(status_code=422, detail={"message": "invalid action profile",
                                                  "errors": e.errors})


def _bound_robots(tenant_id: str) -> dict[str, list[str]]:
    """profile name -> agent ids (robots) bound to it in the registry."""
    out: dict[str, list[str]] = {}
    try:
        from storage.tenant_store import kv_get
        for agent_id, agent in (kv_get(f"agents:{tenant_id}") or {}).items():
            name = (agent or {}).get("action_profile")
            if name:
                out.setdefault(name, []).append(agent_id)
    except Exception:
        pass
    return out


def load(tenant_id: str, name: str) -> dict:
    """The normalized profile or an HTTP error (404 missing, 409 no longer valid)."""
    try:
        profile = em_store.get_profile(tenant_id, name)
    except ProfileError as e:
        raise HTTPException(status_code=409, detail={
            "message": f"stored action profile '{name}' no longer validates; save it again",
            "errors": e.errors})
    if profile is None:
        raise HTTPException(status_code=404, detail=f"action profile '{name}' not found")
    return profile


@router.get("")
async def list_embodied_profiles(request: Request):
    tenant_id = get_tenant_from_request(request)
    bound = _bound_robots(tenant_id)
    profiles = {}
    for name, rec in em_store.list_profiles(tenant_id).items():
        if "error" in rec:
            profiles[name] = {"error": rec["error"], "robots": bound.get(name, [])}
        else:
            profiles[name] = {"hash": rec["hash"], "updated_at": rec.get("updated_at"),
                              "description": rec["profile"].get("description", ""),
                              "actions": len(rec["profile"]["actions"]),
                              "robots": bound.get(name, [])}
    return {"tenant_id": tenant_id, "profiles": profiles}


@router.post("/validate")
async def validate_embodied_profile(request: Request, profile: dict = Body(...)):
    get_tenant_from_request(request)
    try:
        normalized = validate_profile(profile)
    except ProfileError as e:
        return {"valid": False, "errors": e.errors, "profile": None}
    return {"valid": True, "errors": [], "profile": normalized, "hash": profile_hash(normalized)}


@router.get("/{name}")
async def get_embodied_profile(name: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    profile = load(tenant_id, _name(name))
    return {"tenant_id": tenant_id, "name": name, "profile": profile,
            "hash": profile_hash(profile), "robots": _bound_robots(tenant_id).get(name, [])}


@router.put("/{name}")
async def put_embodied_profile(name: str, request: Request, profile: dict = Body(...)):
    tenant_id = get_tenant_from_request(request)
    _name(name)
    require_registry_write(request, tenant_id, "change an action profile")
    try:
        normalized = em_store.save_profile(tenant_id, name, profile,
                                           actor=_actor(request, tenant_id))
    except ProfileError as e:
        raise _invalid(e)
    phash = profile_hash(normalized)
    _invalidate(tenant_id)
    _audit(request, "tenant_set_embodied_profile", tenant_id, {"profile": name, "hash": phash})
    return {"tenant_id": tenant_id, "name": name, "profile": normalized, "hash": phash}


@router.delete("/{name}")
async def delete_embodied_profile(name: str, request: Request, force: bool = Query(False)):
    tenant_id = get_tenant_from_request(request)
    _name(name)
    require_registry_write(request, tenant_id, "delete an action profile")
    robots = _bound_robots(tenant_id).get(name, [])
    if robots and not force:
        raise HTTPException(status_code=409, detail={
            "message": f"action profile '{name}' is bound to {len(robots)} robot(s); rebind "
                       f"them or pass force=true", "robots": robots})
    deleted = em_store.delete_profile(tenant_id, name)
    _invalidate(tenant_id)
    _audit(request, "tenant_delete_embodied_profile", tenant_id,
           {"profile": name, "deleted": deleted, "bound_robots": robots})
    return {"tenant_id": tenant_id, "name": name, "deleted": deleted}


@router.get("/{name}/history")
async def embodied_profile_history(name: str, request: Request):
    tenant_id = get_tenant_from_request(request)
    current = profile_hash(load(tenant_id, _name(name)))
    return {"tenant_id": tenant_id, "name": name, "current_hash": current,
            "versions": em_store.history(tenant_id, name)}


def _invalidate(tenant_id: str) -> None:
    """Drop the check endpoint's cached profiles for this tenant (task 3)."""
    try:
        from core.embodied import cache
        cache.invalidate(tenant_id)
    except Exception:
        pass
