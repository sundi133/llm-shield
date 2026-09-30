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


@router.get("/templates")
async def embodied_profile_templates(request: Request):
    """Starting points. 'embodied-bench' is the profile that scores the
    benchmark: one profile for all 26 cases, written from their stated rules."""
    from core.embodied.bench import example_profile
    get_tenant_from_request(request)
    ex = example_profile()
    return {"templates": {"embodied-bench": validate_profile(ex)} if ex else {}}


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


@router.post("/{name}/simulate")
async def simulate_embodied_action(name: str, request: Request, event: dict = Body(...)):
    """What the guard would decide for this event under this profile. The same
    evaluator as the robot and /v1/shield/embodied/check, but nothing is audited
    and no approval is opened: for trying profiles in the portal."""
    import time as _time
    from core.embodied.evaluator import evaluate
    tenant_id = get_tenant_from_request(request)
    profile = load(tenant_id, _name(name))
    t0 = _time.perf_counter()
    decision = evaluate(profile, event)
    return {**decision, "profile": name, "profile_hash": profile_hash(profile),
            "evaluated_us": round((_time.perf_counter() - t0) * 1e6, 1), "simulated": True}


@router.get("/{name}/benchmark")
async def benchmark_embodied_profile(name: str, request: Request):
    """Score this profile against embodied-bench: caught, correct rail, false
    positives, and every case's result."""
    from core.embodied.bench import load_corpus, score
    tenant_id = get_tenant_from_request(request)
    profile = load(tenant_id, _name(name))
    cases = load_corpus()
    if cases is None:
        raise HTTPException(status_code=404, detail="embodied-bench is not installed on this server")
    return {"tenant_id": tenant_id, "name": name, "profile_hash": profile_hash(profile),
            **score(profile, cases)}


# ── signed bundles for robots (both planes) ──────────────────────────

edge_router = APIRouter(prefix="/v1/edge", tags=["edge"])


@edge_router.get("/embodied-bundle")
async def embodied_bundle(request: Request, profile: str = Query(...),
                          fleet: str = Query(..., description="fleet id the bundle is bound to")):
    """The action profile as a signed bundle in shield-mavlink's format, bound to
    this tenant and fleet, with an expiry. Robots verify it against a key pinned
    on disk (see /embodied-bundle/pubkey for provisioning). ETag/304 for polling."""
    import hashlib
    from fastapi import Response
    from core.embodied import bundle as em_bundle
    tenant_id = get_tenant_from_request(request)
    _name(profile)
    if not valid_name(fleet):
        raise HTTPException(status_code=400, detail="fleet: lowercase letters, digits, . _ -")
    policy = load(tenant_id, profile)
    phash = profile_hash(policy)
    # The bucket changes every half-validity, so an unchanged profile is still
    # re-signed before a robot's copy expires (see freshness_bucket).
    bucket = em_bundle.freshness_bucket(em_bundle.valid_for_s())
    etag = '"' + hashlib.sha256(f"{phash}|{fleet}|{tenant_id}|{bucket}".encode()
                                ).hexdigest()[:32] + '"'
    if (request.headers.get("if-none-match") or "").strip() == etag:
        return Response(status_code=304, headers={"ETag": etag})
    rec = em_store.list_profiles(tenant_id).get(profile) or {}
    signed = em_bundle.sign_bundle(policy, tenant_id=tenant_id, fleet_id=fleet,
                                   bundle_version=int(rec.get("updated_at") or 0))
    if signed is None:
        raise HTTPException(status_code=503, detail="bundle signing is not configured on this "
                            "Shield (SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY); robots only accept "
                            "signed bundles")
    from fastapi.responses import JSONResponse
    return JSONResponse({**signed, "profile": profile, "profile_hash": phash},
                        headers={"ETag": etag, "Cache-Control": "no-cache"})


@edge_router.get("/embodied-bundle/pubkey")
async def embodied_bundle_pubkey(request: Request):
    """For provisioning only: copy this key onto robots out of band and pin it.
    A robot that fetches its trust anchor over the network trusts the network."""
    from core.embodied import bundle as em_bundle
    get_tenant_from_request(request)
    key = em_bundle.public_key_hex()
    if key is None:
        raise HTTPException(status_code=503, detail="bundle signing is not configured")
    return {"kid": em_bundle.kid(), "public_key_hex": key,
            "note": "pin this on the robot at provisioning; never fetch it at runtime"}


def _invalidate(tenant_id: str) -> None:
    """Drop the check endpoint's cached profiles for this tenant (task 3)."""
    try:
        from core.embodied import cache
        cache.invalidate(tenant_id)
    except Exception:
        pass
