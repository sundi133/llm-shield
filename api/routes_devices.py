"""Laptops running the DLP agent. Spec: docs/specs/device-dlp-agent.md §5.2, §6.

  POST   /v1/devices/enroll                                   data plane, enrollment token
  POST   /v1/devices/heartbeat                                data plane, device key
  POST   /v1/devices/ca                                       data plane, device key: CSR -> 7-day CA
  GET    /v1/tenant/me/devices/root-ca[.mobileconfig]         both planes: the tenant root, MDM profile
  POST   /v1/tenant/me/devices/root-ca/reissue                both planes: cover new AI hosts
  GET    /v1/tenant/me/devices                                both planes, fleet view
  DELETE /v1/tenant/me/devices/{device_id}                    both planes, revoke
  POST   /v1/tenant/me/devices/enrollment-tokens              both planes
  GET    /v1/tenant/me/devices/enrollment-tokens              both planes
  DELETE /v1/tenant/me/devices/enrollment-tokens/{token_id}   both planes

Off the hot path: nothing here runs on /guardrails/*, cap/mint or tools/call.
Token and revoke operations go through the registry write gate, like every
other change to what the tenant's agents may do.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Header, HTTPException, Request, Response

from core.auth import get_tenant_from_request, require_registry_write
from core.dlp import devices as dv
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/devices", tags=["devices"])
tenant_router = APIRouter(prefix="/v1/tenant/me/devices", tags=["devices"])


def _audit(request: Request, action: str, tenant_id: str, actor: str, metadata: dict) -> None:
    try:
        log_admin_action(action=action, actor=actor, tenant_id=tenant_id,
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


def _http(e: dv.DeviceError) -> HTTPException:
    return HTTPException(status_code=e.status, detail=str(e))


def _enabled() -> None:
    if not dv.enabled():
        raise HTTPException(status_code=404, detail="the device agent is turned off on this "
                                                    "Shield (SHIELD_DEVICE_AGENT)")


# ── the agent's own calls (data plane) ───────────────────────────────


@router.post("/enroll")
async def enroll_device(request: Request, body: dict = Body(...),
                        x_enrollment_token: str = Header("", alias="X-Enrollment-Token")):
    """Exchange an enrollment token (from MDM) for this device's own key."""
    _enabled()
    try:
        out = dv.enroll(x_enrollment_token, body)
    except dv.DeviceError as e:
        raise _http(e)
    _audit(request, "device_enrolled", out["tenant_id"], f"device:{out['device_id']}",
           {"device_id": out["device_id"], "fleet": out["fleet"],
            "hostname": body.get("hostname", "")[:255]})
    return out


@router.post("/heartbeat", status_code=204)
async def device_heartbeat(request: Request, body: dict = Body(...)):
    try:
        caller = dv.caller_device(request)
        if caller is None:
            raise dv.DeviceError("heartbeats come from a device key", status=403)
        tenant_id, device_id, _record = caller
        dv.heartbeat(tenant_id, device_id, body)
    except dv.DeviceError as e:
        raise _http(e)
    return Response(status_code=204)


def _policy_hosts(tenant_id: str) -> list:
    from core.dlp import device_store
    return device_store.get_policy(tenant_id)["ai_hosts"]


@router.post("/ca")
async def device_intermediate_ca(request: Request, body: dict = Body(...)):
    """{csr_pem} -> this laptop's intermediate CA for 7 days, and the tenant root.
    Spec §3.1, task 6 amendment: the root is trusted through MDM, the laptop's
    key never leaves it, and a revoked laptop gets no renewal."""
    from core.dlp import device_ca
    try:
        caller = dv.caller_device(request)
        if caller is None:
            raise dv.DeviceError("a device CA is issued to a device key", status=403)
    except dv.DeviceError as e:
        raise _http(e)
    tenant_id, device_id, record = caller
    try:
        out = device_ca.issue_intermediate(tenant_id, device_id, str(body.get("csr_pem") or ""),
                                           _policy_hosts(tenant_id))
    except device_ca.DeviceCAError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    dv.note_ca(tenant_id, device_id, out["not_after"])
    return out


# ── the tenant's view (both planes) ──────────────────────────────────


def _root(tenant_id: str) -> dict:
    from core.dlp import device_ca
    try:
        return device_ca.get_root(tenant_id, _policy_hosts(tenant_id))
    except device_ca.DeviceCAError as e:
        raise HTTPException(status_code=e.status, detail=str(e))


@tenant_router.get("/root-ca")
async def tenant_root_ca(request: Request):
    """The tenant's device root: what the MDM profile trusts on Macs."""
    tenant_id = get_tenant_from_request(request)
    root = _root(tenant_id)
    return {"tenant_id": tenant_id, **{k: root[k] for k in (
        "pem", "hosts", "fingerprint_sha256", "issued_at", "not_after", "covers_policy",
        "missing_hosts")}}


@tenant_router.get("/root-ca.mobileconfig")
async def tenant_root_ca_profile(request: Request):
    from core.dlp import device_ca
    tenant_id = get_tenant_from_request(request)
    return Response(content=device_ca.mobileconfig(tenant_id, _root(tenant_id)),
                    media_type="application/x-apple-aspen-config",
                    headers={"Content-Disposition":
                             'attachment; filename="votal-device-agent-root.mobileconfig"'})


@tenant_router.post("/root-ca/reissue")
async def reissue_tenant_root_ca(request: Request):
    """A new root certificate (same key) covering the policy's current AI hosts.
    Upload the new profile to MDM; until then, new hosts are not inspected."""
    from core.dlp import device_ca
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "reissue the device root CA")
    try:
        rec = device_ca.issue_root(tenant_id, _policy_hosts(tenant_id))
    except device_ca.DeviceCAError as e:
        raise HTTPException(status_code=e.status, detail=str(e))
    _audit(request, "tenant_reissue_device_root_ca", tenant_id, _actor(request, tenant_id),
           {"fingerprint_sha256": rec["fingerprint_sha256"], "hosts": rec["hosts"]})
    return {"tenant_id": tenant_id, **rec}


@tenant_router.get("")
async def list_devices(request: Request):
    tenant_id = get_tenant_from_request(request)
    try:
        from core.dlp import device_store
        expected = device_store.get_policy(tenant_id)["model"].get("digest", "")
    except Exception:
        expected = ""
    return {"tenant_id": tenant_id, **dv.list_devices(tenant_id, expected_digest=expected)}


@tenant_router.post("/enrollment-tokens")
async def create_enrollment_token(request: Request, body: dict = Body(...)):
    """{fleet, uses (default 50), expires_in_days (default 7)}. The token is
    shown once: put it in the MDM install profile."""
    tenant_id = get_tenant_from_request(request)
    _enabled()
    require_registry_write(request, tenant_id, "create a device enrollment token")
    actor = _actor(request, tenant_id)
    try:
        token, rec = dv.create_enrollment_token(
            tenant_id, body.get("fleet", ""), uses=body.get("uses", 50),
            expires_in_days=body.get("expires_in_days", 7), created_by=actor)
    except dv.DeviceError as e:
        raise _http(e)
    _audit(request, "tenant_create_device_enrollment_token", tenant_id, actor,
           {"fleet": rec["fleet"], "uses": rec["uses"], "token_id": rec["token_id"],
            "expires_at": rec["expires_at"]})
    return {"tenant_id": tenant_id, "enrollment_token": token, **rec,
            "note": "Shown once. Shield keeps only its hash."}


@tenant_router.get("/enrollment-tokens")
async def list_enrollment_tokens(request: Request):
    tenant_id = get_tenant_from_request(request)
    return {"tenant_id": tenant_id, "tokens": dv.list_enrollment_tokens(tenant_id)}


@tenant_router.delete("/enrollment-tokens/{token_id}")
async def revoke_enrollment_token(token_id: str, request: Request):
    """Stop a token enrolling more devices. Devices it already enrolled keep
    working; revoke them one by one."""
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "revoke a device enrollment token")
    if not dv.revoke_enrollment_token(tenant_id, token_id):
        raise HTTPException(status_code=404, detail="enrollment token not found")
    _audit(request, "tenant_revoke_device_enrollment_token", tenant_id,
           _actor(request, tenant_id), {"token_id": token_id})
    return {"tenant_id": tenant_id, "token_id": token_id, "revoked": True}


@tenant_router.delete("/{device_id}")
async def revoke_device(device_id: str, request: Request):
    """The device key stops working at once on every endpoint a device can reach."""
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "revoke a device")
    removed = dv.revoke(tenant_id, device_id)
    if removed is None:
        raise HTTPException(status_code=404, detail="device not found")
    _audit(request, "tenant_revoke_device", tenant_id, _actor(request, tenant_id),
           {"device_id": device_id, "fleet": removed.get("fleet"),
            "hostname": removed.get("hostname")})
    return {"tenant_id": tenant_id, "device_id": device_id, "revoked": True}
