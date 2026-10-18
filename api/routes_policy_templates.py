"""Policy templates + enforcement-mode lifecycle endpoints (admin).

Gives security operators a guided lifecycle:
  1. GET  /v1/admin/policy-templates                       — pick a starting point
  2. POST /v1/admin/tenants/{tenant_id}/apply-template     — land it in monitor mode
  3. (review what *would* block in telemetry)
  4. PUT  /v1/admin/tenants/{tenant_id}/policy-mode        — flip to enforce

All routes live under /v1/admin/* and therefore require an admin identity. A
managed admin credential is also held to its scope: `tenants:write` on the
tenant to apply a template or change its mode, `tenants:read` to read (the same
operations as PUT /v1/admin/tenants/{tenant_id}, which also changes a tenant's
guardrails). These were the only /v1/admin routes without it
(docs/specs/principals-and-template-authz.md, gap 2).
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from core.policy_mode import ENFORCE, MONITOR
from core.policy_templates import list_templates, get_template
from storage.tenant_store import get_tenant, update_tenant, set_tenant_policies
from storage.admin_audit import log_admin_action
from core.auth import admin_actor, require_admin_scope

router = APIRouter(prefix="/v1/admin", tags=["policy-templates"])


def _scope(request: Request, operation: str, tenant_id: str = "") -> None:
    require_admin_scope(request, operation, tenant_id)


def _source_ip(request: Request) -> str:
    return request.client.host if request.client else ""


class ApplyTemplateRequest(BaseModel):
    template_id: str
    mode: str | None = None  # defaults to the template's recommended_mode (monitor)


class PolicyModeRequest(BaseModel):
    mode: str  # "monitor" or "enforce"


@router.get("/policy-templates")
async def get_policy_templates(request: Request):
    """List available industry policy templates."""
    _scope(request, "tenants:read")
    return {"templates": list_templates()}


@router.get("/policy-templates/{template_id}")
async def get_policy_template(template_id: str, request: Request):
    """Get one template, including its full guardrail bodies."""
    _scope(request, "tenants:read")
    template = get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Unknown template '{template_id}'")
    return {"id": template_id, **template}


@router.post("/tenants/{tenant_id}/apply-template")
async def apply_template(tenant_id: str, body: ApplyTemplateRequest, request: Request):
    """Apply a template's guardrails to a tenant.

    Replaces the tenant's input/output guardrail policy with the template's,
    and sets the enforcement mode. Defaults to the template's recommended mode
    (``monitor``) so the policy starts in dry-run, not blocking live traffic.
    """
    _scope(request, "tenants:write", tenant_id)
    template = get_template(body.template_id)
    if not template:
        raise HTTPException(status_code=404, detail=f"Unknown template '{body.template_id}'")

    if not get_tenant(tenant_id):
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    mode = body.mode or template.get("recommended_mode", MONITOR)
    if mode not in (MONITOR, ENFORCE):
        raise HTTPException(status_code=400, detail="mode must be 'monitor' or 'enforce'")

    set_tenant_policies(
        tenant_id,
        input_guardrails=template["input_guardrails"],
        output_guardrails=template["output_guardrails"],
    )
    config = update_tenant(tenant_id, {"policy_mode": mode})

    log_admin_action(
        action="apply_policy_template",
        actor=admin_actor(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={"template_id": body.template_id, "policy_mode": mode},
        metadata={
            "input_guardrails": list(template["input_guardrails"].keys()),
            "output_guardrails": list(template["output_guardrails"].keys()),
        },
    )

    return {
        "status": "applied",
        "tenant_id": tenant_id,
        "template_id": body.template_id,
        "policy_mode": mode,
        "input_guardrail_count": len(template["input_guardrails"]),
        "output_guardrail_count": len(template["output_guardrails"]),
        "note": ("Policy is in MONITOR mode — it records what would block but does "
                 "not enforce. Review, then PUT policy-mode 'enforce'.")
        if mode == MONITOR else "Policy is ENFORCING.",
        "config": config,
    }


@router.put("/tenants/{tenant_id}/policy-mode")
async def set_policy_mode(tenant_id: str, body: PolicyModeRequest, request: Request):
    """Flip a tenant between monitor (dry-run) and enforce."""
    _scope(request, "tenants:write", tenant_id)
    if body.mode not in (MONITOR, ENFORCE):
        raise HTTPException(status_code=400, detail="mode must be 'monitor' or 'enforce'")

    before = get_tenant(tenant_id)
    if not before:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")

    config = update_tenant(tenant_id, {"policy_mode": body.mode})

    log_admin_action(
        action="set_policy_mode",
        actor=admin_actor(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        before={"policy_mode": before.get("policy_mode", ENFORCE)},
        after={"policy_mode": body.mode},
    )

    return {"status": "updated", "tenant_id": tenant_id, "policy_mode": body.mode}


@router.get("/tenants/{tenant_id}/policy-mode")
async def get_policy_mode(tenant_id: str, request: Request):
    """Read a tenant's current enforcement mode."""
    _scope(request, "tenants:read", tenant_id)
    config = get_tenant(tenant_id)
    if not config:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return {"tenant_id": tenant_id, "policy_mode": config.get("policy_mode", ENFORCE)}
