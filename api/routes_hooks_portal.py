"""Portal side of the Claude Code hook adapter (both planes).

GET  /v1/tenant/me/hooks/claude-code       laptops' last hook calls, the URL to use
POST /v1/tenant/me/hooks/claude-code/kit   the files to deploy (managed settings,
                                           .mobileconfig, install script, hook)

Spec: docs/specs/agent-hook-adapter.md task 3. Not on any guard path: the hook
route itself is api/routes_hooks.py (data plane only). The hook key posted to
/kit builds the files and is never stored or logged.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, HTTPException, Request

from core.auth import get_tenant_from_request
from core.runtime_policy import hook_kit, hook_seen

router = APIRouter(prefix="/v1/tenant/me/hooks", tags=["runtime"])


@router.get("/claude-code")
async def claude_code_overview(request: Request):
    tenant_id = get_tenant_from_request(request)
    return {"shield_url": hook_kit.public_url(str(request.base_url)),
            "laptops": hook_seen.list_seen(tenant_id),
            "variants": list(hook_kit.VARIANTS), "oses": list(hook_kit.OSES)}


@router.post("/claude-code/kit")
async def claude_code_kit(request: Request, body: dict = Body(...)):
    """Body: {variant: http|command, os: macos|linux|windows, shield_url,
    hook_key, agent}. Returns {files: {name: {content, path, mime}}}."""
    tenant_id = get_tenant_from_request(request)
    try:
        files = hook_kit.build(
            str(body.get("variant") or ""), str(body.get("os") or ""),
            shield_url=str(body.get("shield_url") or "").strip(),
            key=str(body.get("hook_key") or "").strip(),
            agent=str(body.get("agent") or "claude-code").strip(), tenant_id=tenant_id)
    except hook_kit.KitError as e:
        raise HTTPException(status_code=422, detail={"message": "The files could not be built.",
                                                     "errors": e.errors})
    return {"files": files}
