"""Prompt exception requests: the tenant's side (both planes).

Spec: docs/specs/prompt-exception-requests.md §4.3. Off the hot path. Mounted
by the admin plane too, so nothing here may import the screening pipeline:
asking and polling live in api/routes_exceptions.py (data plane).

  GET  /v1/tenant/me/exceptions/settings          the tenant's settings
  PUT  /v1/tenant/me/exceptions/settings
  GET  /v1/tenant/me/exceptions                   the review queue, with the prompts
  GET  /v1/tenant/me/exceptions/{id}
  POST /v1/tenant/me/exceptions/{id}/approve      {reason?, false_positive?}
  POST /v1/tenant/me/exceptions/{id}/deny         {reason?, false_positive?}

Approving records the decision. The signed grant is minted on the data plane
when the requester collects it, so this module needs no signing key.
"""

from __future__ import annotations

import os

import asyncio

from fastapi import APIRouter, Body, HTTPException, Query, Request

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


# ── review ───────────────────────────────────────────────────────────

def _for_reviewer(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if k != "changed"}


def _notify_decided(tenant_id: str, rec: dict) -> None:
    """Webhook, in the background. Never the prompt or either reason."""
    try:
        from core.webhook_dispatcher import dispatch_event
        payload = {
            "request_id": rec["request_id"], "status": rec["status"],
            "user_id": rec["user_id"], "destination": rec["destination"],
            "approver": (rec.get("decision") or {}).get("approver", ""),
            "false_positive": bool((rec.get("decision") or {}).get("false_positive")),
            "blocked_by": [{"guardrail": b["guardrail"], "policy": b["policy"]}
                           for b in rec["blocked_by"]],
        }
        asyncio.get_running_loop().create_task(
            dispatch_event(tenant_id, "exception_decided", payload))
    except Exception:
        pass


@tenant_router.get("")
async def list_exception_requests(request: Request, status: str = Query(None),
                                  limit: int = Query(100, ge=1, le=500)):
    tenant_id = tenant_of(request)
    if status is not None and status not in pe.STATUSES:
        raise HTTPException(status_code=400, detail=f"status: one of {', '.join(pe.STATUSES)}")
    return {"tenant_id": tenant_id,
            "requests": [_for_reviewer(r) for r in pe.list_requests(tenant_id, status, limit)],
            "by_policy": pe.counters(tenant_id)}


@tenant_router.get("/{request_id}")
async def get_exception_request(request_id: str, request: Request):
    tenant_id = tenant_of(request)
    rec = pe.get(tenant_id, request_id)
    if rec is None:
        raise HTTPException(status_code=404, detail={"error": "not_found",
                                                     "message": "No such exception request."})
    return _for_reviewer(rec)


async def _decide(request_id: str, request: Request, body: dict, approve: bool):
    tenant_id = tenant_of(request)
    require_registry_write(request, tenant_id, "decide a prompt exception request")
    reason = body.get("reason") or ""
    if not isinstance(reason, str) or len(reason) > pe.REASON_MAX:
        raise HTTPException(status_code=400,
                            detail=f"reason: text of at most {pe.REASON_MAX} characters")
    actor = _actor(request, tenant_id)
    try:
        rec = pe.decide(tenant_id, request_id, approve=approve, approver=actor,
                        method="portal" if actor.startswith("user:") else "tenant_key",
                        reason=reason, false_positive=body.get("false_positive") is True)
    except pe.ExceptionError as e:
        fail(e)
    if not rec["changed"]:
        # Someone else decided first, or it expired: say what it is now.
        raise HTTPException(status_code=409, detail={
            "error": "not_pending", "status": rec["status"],
            "message": f"This request is already {rec['status']}."})
    audit(request, "prompt_exception_approved" if approve else "prompt_exception_denied",
          tenant_id, actor, {"request_id": request_id, "user_id": rec["user_id"],
                             "prompt_sha256": rec["prompt_sha256"],
                             "false_positive": rec["decision"]["false_positive"],
                             "blocked_by": [b["guardrail"] for b in rec["blocked_by"]]})
    _notify_decided(tenant_id, rec)
    return _for_reviewer(rec)


@tenant_router.post("/{request_id}/approve")
async def approve_exception_request(request_id: str, request: Request, body: dict = Body(default={})):
    return await _decide(request_id, request, body, approve=True)


@tenant_router.post("/{request_id}/deny")
async def deny_exception_request(request_id: str, request: Request, body: dict = Body(default={})):
    return await _decide(request_id, request, body, approve=False)
