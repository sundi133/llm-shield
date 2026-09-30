"""Laptops running the DLP agent. Spec: docs/specs/device-dlp-agent.md §5.2, §6.

  POST   /v1/devices/enroll                                   data plane, enrollment token
  POST   /v1/devices/heartbeat                                data plane, device key
  POST   /v1/devices/ca                                       data plane, device key: CSR -> 7-day CA
  GET    /v1/tenant/me/devices/root-ca[.mobileconfig]         both planes: the tenant root, MDM profile
  POST   /v1/tenant/me/devices/root-ca/reissue                both planes: cover new AI hosts
  GET    /v1/tenant/me/devices/rollout-kits                   both planes: kits, never a token
  POST   /v1/tenant/me/devices/rollout-kits                   both planes: a kit (zip), token minted
  DELETE /v1/tenant/me/devices/rollout-kits/{kit_id}          both planes: revoke its token
  GET, PUT, DELETE /v1/tenant/me/devices/inventory            both planes: opt-in serial allow list
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


async def _enrollment_alert(request: Request, alert: dict) -> None:
    """A refused enrollment (over a live device, or from a laptop missing from the
    company inventory): a high-severity event in the tenant's decision audit and
    telemetry, and an admin audit record."""
    from core.runtime_policy import events as rt_events
    tenant_id = alert["tenant_id"]
    why = alert.get("why", "live_serial")
    reason = {"live_serial": "an enrollment claimed the serial of a device that is still "
                             "reporting",
              "not_in_inventory": "an enrollment came from a laptop that is not in the "
                                  "company inventory"}.get(why, why)
    detail = {"verdict": "block", "event": "enrollment_refused", "reason": reason,
              **{k: str(v)[:200] for k, v in alert.items() if k != "tenant_id"}}
    try:
        ev = rt_events.normalize({"source": "custom", "kind": "dlp", "decision": "deny",
                                  "severity": "high", "agent_id": alert.get("device_id", ""),
                                  "agent_instance_id": alert.get("device_id", ""),
                                  "detail": detail})
        await rt_events.ingest(tenant_id, [ev],
                               source_ip=request.client.host if request.client else "")
    except Exception:
        pass
    _audit(request, f"device_enrollment_refused_{why}", tenant_id, "device:unenrolled",
           {k: v for k, v in alert.items() if k != "tenant_id"})


@router.post("/enroll")
async def enroll_device(request: Request, body: dict = Body(...),
                        x_enrollment_token: str = Header("", alias="X-Enrollment-Token")):
    """Exchange an enrollment token (from MDM) for this device's own key."""
    _enabled()
    try:
        out = dv.enroll(x_enrollment_token, body)
    except dv.DeviceError as e:
        if e.alert:
            await _enrollment_alert(request, e.alert)
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


# ── company inventory (docs/specs/device-rollout-kit.md, task 4) ────
# Declared before DELETE /{device_id}, which would otherwise take "inventory"
# for a device id.

INVENTORY_MAX_BYTES = 16 * 1024 * 1024


@tenant_router.get("/inventory")
async def get_inventory(request: Request):
    tenant_id = get_tenant_from_request(request)
    return {"tenant_id": tenant_id, **dv.inventory_status(tenant_id)}


@tenant_router.put("/inventory")
async def put_inventory(request: Request):
    """Body: the MDM's serial number export (CSV with a "Serial..." column, or
    one serial per line), or JSON. Replaces the inventory; once it is
    non-empty only those laptops can enroll. Serials are hashed on arrival."""
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "replace the device inventory")
    raw = await request.body()
    if len(raw) > INVENTORY_MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"body over {INVENTORY_MAX_BYTES} bytes")
    try:
        serials, skipped = dv.parse_serials(raw, request.headers.get("content-type", ""))
        if not serials:
            raise dv.DeviceError("no serial numbers found; to stop restricting enrollment, "
                                 "DELETE the inventory instead")
        meta = dv.set_inventory(tenant_id, serials, actor=_actor(request, tenant_id))
    except dv.DeviceError as e:
        raise _http(e)
    _audit(request, "tenant_set_device_inventory", tenant_id, _actor(request, tenant_id),
           {"count": meta["count"], "skipped": skipped})
    return {"tenant_id": tenant_id, **meta, "skipped": skipped, "enforced": True}


@tenant_router.delete("/inventory")
async def delete_inventory(request: Request):
    """Stop restricting enrollment to the inventory."""
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "clear the device inventory")
    had = dv.clear_inventory(tenant_id)
    _audit(request, "tenant_clear_device_inventory", tenant_id, _actor(request, tenant_id),
           {"had_inventory": had})
    return {"tenant_id": tenant_id, "cleared": had, "enforced": False}


# ── rollout kits (docs/specs/device-rollout-kit.md, task 3) ─────────


def _kit_shield_url(request: Request) -> str:
    """The URL laptops use to reach this Shield's data plane.

    SHIELD_DEVICE_AGENT_SHIELD_URL when set. Otherwise this request's own URL,
    but only when this app mounts the enrollment route (the data plane) and
    the URL is https: a kit generated through the admin plane must not point
    laptops at a host that cannot enroll them.
    """
    import os
    env = os.environ.get("SHIELD_DEVICE_AGENT_SHIELD_URL", "").strip().rstrip("/")
    if env:
        return env
    # url_path_for, not a scan of app.routes: newer FastAPI (0.141+) keeps
    # included routers nested, so their paths are not in app.routes.
    try:
        request.app.url_path_for("enroll_device")
        serves_enroll = True
    except Exception:
        serves_enroll = False
    base = str(request.base_url).rstrip("/")
    if serves_enroll and base.startswith("https://"):
        return base
    raise HTTPException(status_code=503, detail="set SHIELD_DEVICE_AGENT_SHIELD_URL to the https "
                        "URL laptops use to reach this Shield's data plane")


@tenant_router.get("/rollout-kits")
async def list_rollout_kits(request: Request):
    from core.dlp import kits
    tenant_id = get_tenant_from_request(request)
    s = kits.settings()
    return {"tenant_id": tenant_id, "kits": kits.list_kits(tenant_id),
            "defaults": {"agent_version": s["agent_version"], "extension_ids": s["extension_ids"],
                         "signed_release": bool(s["apple_team_id"]),
                         "mdms": list(kits.rk.MDMS),
                         "platforms": {m: list(p) for m, p in kits.rk.PLATFORMS.items()}}}


@tenant_router.post("/rollout-kits")
async def create_rollout_kit(request: Request, body: dict = Body(...)):
    """A rollout kit for one fleet and MDM, as a zip. It contains a new
    enrollment token, shown nowhere else: the kit is the only copy."""
    from core.dlp import kits
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "create a device rollout kit")
    actor = _actor(request, tenant_id)
    shield_url = _kit_shield_url(request)
    try:
        out = kits.create_kit(tenant_id, body, shield_url=shield_url, actor=actor)
    except kits.KitAPIError as e:
        raise HTTPException(status_code=e.status, detail={"message": str(e), "errors": e.errors}
                            if e.errors else str(e))
    rec = out["record"]
    if out["root_reissued"]:
        _audit(request, "tenant_reissue_device_root_ca", tenant_id, actor,
               {"fingerprint_sha256": rec["root_fingerprint_sha256"], "reason": "rollout kit",
                "kit_id": rec["kit_id"]})
    _audit(request, "tenant_create_rollout_kit", tenant_id, actor,
           {k: rec[k] for k in ("kit_id", "fleet", "mdm", "platforms", "token_id",
                                "expires_at", "uses", "include_proxy")}
           | {"revoked_previous": out["revoked"]})
    name = f"votal-rollout-kit-{rec['fleet']}-{rec['mdm']}.zip"
    return Response(content=out["zip"], media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store",
        "X-Votal-Kit-Id": rec["kit_id"], "X-Votal-Root-Reissued": "1" if out["root_reissued"]
        else "0"})


@tenant_router.delete("/rollout-kits/{kit_id}")
async def revoke_rollout_kit(kit_id: str, request: Request):
    from core.dlp import kits
    tenant_id = get_tenant_from_request(request)
    require_registry_write(request, tenant_id, "revoke a device rollout kit")
    rec = kits.revoke_kit(tenant_id, kit_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="rollout kit not found")
    _audit(request, "tenant_revoke_rollout_kit", tenant_id, _actor(request, tenant_id),
           {"kit_id": kit_id, "fleet": rec.get("fleet"), "token_id": rec.get("token_id")})
    return {"tenant_id": tenant_id, "kit_id": kit_id, "revoked": True}


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
