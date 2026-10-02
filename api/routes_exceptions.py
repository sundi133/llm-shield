"""Prompt exception requests: ask and poll (data plane).

Spec: docs/specs/prompt-exception-requests.md §4. Off the hot path: nothing
here is called by /guardrails/*, cap/mint or tools/call. Creating a request
screens the prompt once, on a call the user is waiting on anyway.

  POST /v1/shield/exceptions                 a blocked prompt, with a reason
  GET  /v1/shield/exceptions/{request_id}    its status, for the person who asked

Data plane only: asking screens the prompt, and the admin image does not ship
the screening pipeline. The tenant's side (settings, review) is
api/routes_exception_review.py, which both planes mount.

The tenant always comes from the authenticated key. The prompt is stored so a
reviewer can read it; webhooks and audit rows never carry it.
"""

from __future__ import annotations

import asyncio
import re

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import JSONResponse

from api.routes_classify import classify
from api.routes_exception_review import audit as _audit, fail as _fail, signing_configured, \
    tenant_of as _tenant
from core import prompt_exceptions as pe

router = APIRouter(prefix="/v1/shield/exceptions", tags=["exceptions"])

PROMPT_MAX = 200_000
_DESTINATION = re.compile(r"^[\w .:/@-]{1,100}$")


def _requester(request: Request) -> tuple[str, str]:
    """(user id, device id) as the extension sends them. The user id is what
    ties a request to the person allowed to read it back."""
    user = (getattr(request.state, "agent_key", None) or request.headers.get("x-agent-key")
            or "").strip()
    device = (request.headers.get("x-device-id") or "").strip()
    return user or device, device


def _settings_or_404(tenant_id: str) -> dict:
    settings = pe.get_settings(tenant_id)
    if not settings["enabled"]:
        raise HTTPException(status_code=404, detail={
            "error": "exceptions_disabled",
            "message": "Exception requests are not enabled for this tenant."})
    return settings


def _notify(tenant_id: str, event: str, rec: dict) -> None:
    """Webhook, in the background. Never the prompt or the reason."""
    try:
        from core.webhook_dispatcher import dispatch_event
        payload = {
            "request_id": rec["request_id"], "status": rec["status"],
            "user_id": rec["user_id"], "device_id": rec["device_id"],
            "destination": rec["destination"], "expires_at": rec["expires_at"],
            "blocked_by": [{"guardrail": b["guardrail"], "policy": b["policy"]}
                           for b in rec["blocked_by"]],
        }
        asyncio.get_running_loop().create_task(dispatch_event(tenant_id, event, payload))
    except Exception:
        pass


@router.post("")
async def request_exception(request: Request, body: dict = Body(...)):
    tenant_id = _tenant(request)
    settings = _settings_or_404(tenant_id)
    if not signing_configured():
        raise HTTPException(status_code=503, detail={
            "error": "approvals_not_configured",
            "message": "Approval signing is not configured on this Shield "
                       "(SHIELD_APPROVAL_TOKEN_PRIVATE_KEY)."})

    prompt = body.get("prompt")
    reason = body.get("reason")
    destination = str(body.get("destination") or
                      request.headers.get("x-shield-destination") or "").strip()
    errors = []
    if not isinstance(prompt, str) or not prompt.strip():
        errors.append("prompt: the blocked prompt")
    elif len(prompt) > PROMPT_MAX:
        errors.append(f"prompt: at most {PROMPT_MAX} characters")
    if not isinstance(reason, str) or len(reason.strip()) < 3:
        errors.append("reason: why this prompt should be allowed")
    elif len(reason) > pe.REASON_MAX:
        errors.append(f"reason: at most {pe.REASON_MAX} characters")
    if not _DESTINATION.match(destination):
        errors.append("destination: the AI tool the prompt was going to (up to 100 characters)")
    user_id, device_id = _requester(request)
    if not user_id:
        errors.append("X-Agent-Key or X-Device-Id: who is asking")
    if errors:
        raise HTTPException(status_code=400, detail={"error": "invalid_request",
                                                     "errors": errors})

    # Cheap checks before the screen: an existing request, then the limit.
    existing = pe.find_pending(tenant_id, user_id, pe.prompt_sha256(prompt), destination)
    if existing:
        return pe.for_requester(existing)
    try:
        pe.check_limit(tenant_id, user_id, settings)
    except pe.ExceptionError as e:
        _fail(e)

    # What blocked it is decided here, by the tenant's own policy, not taken
    # from the caller.
    result = await classify(request, {"message": prompt, "agent_key": user_id,
                                      "device_id": device_id,
                                      "context": {"source": "exception_request"}})
    blocked_by = pe.blocking_results(result)
    blocked = result.get("safe") is False or result.get("action") in pe.BLOCKING_ACTIONS
    if not blocked or not blocked_by:
        raise HTTPException(status_code=409, detail={
            "error": "not_blocked",
            "message": "This prompt is not blocked by the current policy. Send it again."})
    hard = sorted({b["guardrail"] for b in blocked_by} & set(settings["non_appealable"]))
    if hard:
        raise HTTPException(status_code=403, detail={
            "error": "not_appealable", "guardrails": hard,
            "message": "This policy does not accept exception requests."})

    rec = pe.create(tenant_id, user_id=user_id, device_id=device_id, destination=destination,
                    prompt=prompt, reason=reason.strip(), blocked_by=blocked_by,
                    settings=settings)
    _audit(request, "prompt_exception_requested", tenant_id, f"user:{user_id}", {
        "request_id": rec["request_id"], "destination": destination,
        "prompt_sha256": rec["prompt_sha256"],
        "blocked_by": [b["guardrail"] for b in blocked_by]})
    _notify(tenant_id, "exception_requested", rec)
    return JSONResponse(pe.for_requester(rec), status_code=201)


@router.get("/{request_id}")
async def exception_status(request_id: str, request: Request):
    tenant_id = _tenant(request)
    _settings_or_404(tenant_id)
    user_id, _device = _requester(request)
    rec = pe.get(tenant_id, request_id)
    # One answer for "no such request" and "not yours": no oracle for ids.
    if not rec or not user_id or rec["user_id"] != user_id[:256]:
        raise HTTPException(status_code=404, detail={"error": "not_found",
                                                     "message": "No such exception request."})
    return pe.for_requester(rec)
