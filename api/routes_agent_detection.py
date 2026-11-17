"""AI agent detection, admin plane (docs/specs/agent-impersonation-defense.md
section 9). Mounted by admin_app.py; nothing here is on the guard path.

Site keys for the tag (rev 8 step R1):

  GET    /v1/agent-detection/sitekeys              the tenant's site keys
  POST   /v1/agent-detection/sitekeys              create one
  DELETE /v1/agent-detection/sitekeys/{site_key}   delete one

Reads take a portal session or a tenant key. Writes also pass the
configuration write gate (a portal admin or an admin-scoped key, per
SHIELD_CONFIG_WRITE_SCOPE). SHIELD_AGENT_DETECTION=off answers 404.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core import agent_detection as _agd
from core.agent_detection import sitekeys

router = APIRouter(tags=["agent-detection"])


class SiteKeyIn(BaseModel):
    origins: list[Any] = Field(default_factory=list)
    platform: str = "web"
    consent: str = "none"
    xff_hops: int = 1
    label: Optional[str] = ""


def _on() -> None:
    if not _agd.enabled():
        raise HTTPException(status_code=404, detail="Not Found")


def _tenant(request: Request) -> str:
    from api.routes_tenant_self import _require_tenant
    return _require_tenant(request)


def _write(request: Request, tenant_id: str, action: str) -> None:
    from core.auth import require_config_write
    require_config_write(request, tenant_id, action)


def _actor(request: Request, tenant_id: str) -> str:
    try:
        from api.routes_tenant_self import _actor as actor
        return actor(request, tenant_id) or ""
    except Exception:       # noqa: BLE001 - attribution is best effort
        return ""


def _audit(request: Request, tenant_id: str, action: str, **meta) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=_actor(request, tenant_id), tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "", metadata=meta)
    except Exception:       # noqa: BLE001 - the action happened; the audit is best effort
        pass


@router.get("/v1/agent-detection/sitekeys")
def list_site_keys(request: Request):
    _on()
    tid = _tenant(request)
    return {"site_keys": sitekeys.list_for(tid), "max": sitekeys.MAX_PER_TENANT}


@router.post("/v1/agent-detection/sitekeys", status_code=201)
def create_site_key(body: SiteKeyIn, request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "create an agent detection site key")
    try:
        rec = sitekeys.create(tid, origins=body.origins, platform=body.platform,
                              consent=body.consent, xff_hops=body.xff_hops,
                              label=body.label or "", created_by=_actor(request, tid))
    except sitekeys.SiteKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except sitekeys.LimitReached as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    _audit(request, tid, "agent_detection.sitekey.create", site_key=rec["site_key"],
           origins=rec["origins"])
    return rec


@router.delete("/v1/agent-detection/sitekeys/{site_key}")
def delete_site_key(site_key: str, request: Request):
    _on()
    tid = _tenant(request)
    _write(request, tid, "delete an agent detection site key")
    if not sitekeys.delete(tid, site_key):
        raise HTTPException(status_code=404, detail="no such site key")
    _audit(request, tid, "agent_detection.sitekey.delete", site_key=site_key)
    return {"deleted": site_key}
