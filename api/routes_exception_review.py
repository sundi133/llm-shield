"""Prompt exception requests: the tenant's side (both planes).

Spec: docs/specs/prompt-exception-requests.md §4.3. Off the hot path. Mounted
by the admin plane too, so nothing here may import the screening pipeline:
asking and polling live in api/routes_exceptions.py (data plane).

  GET /v1/tenant/me/exceptions/settings     the tenant's settings
  PUT /v1/tenant/me/exceptions/settings
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Body, HTTPException, Request

from core import prompt_exceptions as pe
from core.auth import get_tenant_from_request, require_registry_write
from storage.admin_audit import log_admin_action

tenant_router = APIRouter(prefix="/v1/tenant/me/exceptions", tags=["exceptions"])


def fail(e: pe.ExceptionError):
    raise HTTPException(status_code=e.status,
                        detail={"error": e.code, "message": e.message, **e.extra})


def tenant_of(request: Request) -> str:
    tenant_id = get_tenant_from_request(request)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="No valid tenant API key provided. "
                                                    "Use X-API-Key header.")
    return tenant_id


def signing_configured() -> bool:
    """Approving a request mints a signed grant. Without a stable key there is
    nothing a request could ever turn into, so refuse it up front."""
    return bool(os.environ.get("SHIELD_APPROVAL_TOKEN_PRIVATE_KEY", "").strip()
                or os.environ.get("SHIELD_SIGNER_BACKEND_APPROVAL", "").strip()
                or os.environ.get("SHIELD_SIGNER_BACKEND", "").strip() not in ("", "local"))


def audit(request: Request, action: str, tenant_id: str, actor: str, metadata: dict) -> None:
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


@tenant_router.get("/settings")
async def get_exception_settings(request: Request):
    tenant_id = tenant_of(request)
    return {"tenant_id": tenant_id, "settings": pe.get_settings(tenant_id),
            "signing_configured": signing_configured()}


@tenant_router.put("/settings")
async def put_exception_settings(request: Request, body: dict = Body(...)):
    tenant_id = tenant_of(request)
    require_registry_write(request, tenant_id, "change prompt exception settings")
    try:
        settings = pe.save_settings(tenant_id, body)
    except pe.ExceptionError as e:
        fail(e)
    audit(request, "tenant_set_prompt_exception_settings", tenant_id,
           _actor(request, tenant_id), {"settings": settings})
    return {"tenant_id": tenant_id, "settings": settings}
