"""Device DLP policy: tenant API (both planes) and the signed bundle (data plane).

Spec: docs/specs/device-dlp-agent.md §5.1, §6. Off the hot path: nothing here
runs on /guardrails/*, cap/mint or tools/call. Agents poll the bundle with
ETag/304; the decision itself runs on the laptop.

  /v1/tenant/me/dlp-policy            GET, PUT; POST /validate
  /v1/edge/dlp-bundle?fleet=          signed bundle (data plane only)

The tenant always comes from the authenticated key. Writes go through the
registry write gate (SHIELD_REGISTRY_WRITE_SCOPE): a device's own key must not
be able to loosen the policy it is held to.
"""

from __future__ import annotations

import hashlib
import os

from fastapi import APIRouter, Body, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from core.auth import get_tenant_from_request, require_registry_write
from core.dlp import device_store
from core.dlp.device_policy import PolicyError, for_fleet, policy_hash, valid_fleet, validate_policy
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/tenant/me/dlp-policy", tags=["device-dlp"])


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


def _load(tenant_id: str) -> tuple[dict, dict]:
    """(policy, meta). 409 when the stored policy no longer validates: laptops
    keep their last good bundle rather than receive a broken one."""
    try:
        rec = device_store.get_record(tenant_id)
    except PolicyError as e:
        raise HTTPException(status_code=409, detail={
            "message": "stored DLP policy no longer validates; save it again", "errors": e.errors})
    if rec is None:
        return device_store.get_policy(tenant_id), {"stored": False}
    return rec["policy"], {"stored": True, "updated_at": rec.get("updated_at"),
                           "updated_by": rec.get("updated_by", "")}


@router.get("")
async def get_dlp_policy(request: Request):
    tenant_id = get_tenant_from_request(request)
    policy, meta = _load(tenant_id)
    return {"tenant_id": tenant_id, "policy": policy, "hash": policy_hash(policy), **meta}


@router.post("/validate")
async def validate_dlp_policy(request: Request, policy: dict = Body(...)):
    get_tenant_from_request(request)
    try:
        normalized = validate_policy(policy)
    except PolicyError as e:
        return {"valid": False, "errors": e.errors, "policy": None}
    return {"valid": True, "errors": [], "policy": normalized, "hash": policy_hash(normalized)}


@router.put("")
async def put_dlp_policy(request: Request, policy: dict = Body(...)):
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "change the device DLP policy")
    try:
        normalized = device_store.save_policy(tenant_id, policy, actor=_actor(request, tenant_id))
    except PolicyError as e:
        raise HTTPException(status_code=422, detail={"message": "invalid DLP policy",
                                                     "errors": e.errors})
    phash = policy_hash(normalized)
    _audit(request, "tenant_set_dlp_policy", tenant_id,
           {"hash": phash, "mode": normalized["mode"], "fleet_modes": normalized["fleet_modes"]})
    return {"tenant_id": tenant_id, "policy": normalized, "hash": phash}


# ── the signed bundle for laptops (data plane) ───────────────────────

edge_router = APIRouter(prefix="/v1/edge", tags=["edge"])


def _valid_s() -> int:
    try:
        return max(300, int(os.environ.get("SHIELD_DLP_BUNDLE_VALID_S", "86400")))
    except ValueError:
        return 86400


def bundle_policy(tenant_id: str, fleet: str) -> dict:
    """What one fleet's agents enforce: the DLP policy with its mode resolved
    for the fleet, plus the tenant's rules and blocklists from the same builder
    as /v1/edge/policy-bundle, so extension, ICAP and agent run one rule set."""
    from api.routes_edge import _build_bundle
    policy, _meta = _load(tenant_id)
    rules = _build_bundle(tenant_id)
    return {**for_fleet(policy, fleet), "rules": rules["rules"],
            "blocklists": rules["blocklists"], "rules_version": rules["version"]}


@edge_router.get("/dlp-bundle")
async def dlp_bundle(request: Request,
                     fleet: str = Query(..., description="fleet id the bundle is bound to")):
    """The device DLP policy as a signed bundle in shield-mavlink's format, bound
    to this tenant and fleet, with an expiry. Agents verify it against the key
    pinned at enrollment. ETag/304 for polling."""
    from core.embodied import bundle as edge_bundle
    tenant_id = get_tenant_from_request(request)
    if not valid_fleet(fleet):
        raise HTTPException(status_code=400, detail="fleet: lowercase letters, digits, . _ - "
                                                    "(1-64 characters)")
    policy = bundle_policy(tenant_id, fleet)
    phash = policy_hash(policy)
    etag = '"' + hashlib.sha256(f"{phash}|{fleet}|{tenant_id}".encode()).hexdigest()[:32] + '"'
    if (request.headers.get("if-none-match") or "").strip() == etag:
        return Response(status_code=304, headers={"ETag": etag})
    import time
    now = int(time.time())
    # The version is the issue time: monotonic, so an agent can refuse an older
    # bundle replayed to it (rules change without touching the stored policy).
    signed = edge_bundle.sign_bundle(policy, tenant_id=tenant_id, fleet_id=fleet,
                                     bundle_version=now, now=now, valid_s=_valid_s())
    if signed is None:
        raise HTTPException(status_code=503, detail="bundle signing is not configured on this "
                            "Shield (SHIELD_RUNTIME_BUNDLE_PRIVATE_KEY); agents only accept "
                            "signed bundles")
    return JSONResponse({**signed, "policy_hash": phash},
                        headers={"ETag": etag, "Cache-Control": "no-cache"})
