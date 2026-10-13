"""Operator view of persisted delegations (admin plane).

    GET  /v1/admin/delegations?tenant_id=              list (cross-tenant or one)
    POST /v1/admin/delegations/{tenant_id}/{jti}/revoke

A delegation is an agent acting on behalf of a person (X-On-Behalf-Of,
core/delegation.py). When persistence is enabled they are recorded per tenant;
this lets an operator see who an agent acted for and revoke a specific
delegation — the delegated token is refused from its next use.

Gated by the admin credential gate and scoped with require_admin_scope:
`delegations:read` for the list, `delegations:write` to revoke. A
tenant-restricted credential cannot list across all tenants (cross_tenant) but
may act within its allowlisted tenants. Off the guard path.

Spec: docs/specs/spec-mcp-gateway-enterprise.md (M1). M1 tail, item 3.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from core.auth import admin_actor, require_admin_scope
from storage.delegation_store import list_delegations, revoke_delegation

router = APIRouter(prefix="/v1/admin/delegations", tags=["admin-delegations"])


def _audit(request: Request, tenant_id: str, action: str, after: dict) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=admin_actor(request),
                         tenant_id=tenant_id,
                         source_ip=(request.client.host if request.client else ""),
                         after=after)
    except Exception:       # noqa: BLE001
        pass


@router.get("")
async def list_delegations_admin(request: Request, tenant_id: Optional[str] = None,
                                 limit: int = 500):
    """List recorded delegations. Without `tenant_id`, spans every tenant."""
    if tenant_id:
        require_admin_scope(request, "delegations:read", tenant_id)
        tenant_ids = [tenant_id]
    else:
        require_admin_scope(request, "delegations:read", cross_tenant=True)
        from storage.tenant_store import list_tenants
        tenant_ids = [t.get("tenant_id") for t in list_tenants() if t.get("tenant_id")]

    cap = max(1, min(int(limit or 500), 2000))
    out = []
    for tid in tenant_ids:
        for rec in list_delegations(tid):
            out.append({"tenant_id": tid, **rec})
            if len(out) >= cap:
                break
        if len(out) >= cap:
            break
    return {"delegations": out, "count": len(out), "truncated": len(out) >= cap}


@router.post("/{tenant_id}/{jti}/revoke")
async def revoke_delegation_admin(tenant_id: str, jti: str, request: Request):
    """Revoke a delegation by jti — the delegated token is refused next use."""
    require_admin_scope(request, "delegations:write", tenant_id)
    found = revoke_delegation(tenant_id, jti)
    _audit(request, tenant_id, "delegation_revoked", {"jti": jti, "record_found": found})
    return {"status": "revoked", "tenant_id": tenant_id, "jti": jti,
            "record_found": found}
