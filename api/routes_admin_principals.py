"""Operator view of principals across every tenant (admin plane).

    GET  /v1/admin/principals                         list across all tenants
    GET  /v1/admin/principals/{tenant_id}/{pid}       one, with key metadata
    POST /v1/admin/principals/{tenant_id}/{pid}/suspend
    POST /v1/admin/principals/{tenant_id}/{pid}/reactivate

The per-tenant console already manages a tenant's own principals at
/v1/tenant/me/principals (api/routes_principals.py). This is the platform
operator's cross-tenant counterpart, for support and incident response: list and
read principals anywhere, and suspend/reactivate one during an incident.

Gated by the admin credential gate (core.auth.AuthMiddleware, /v1/admin/*) and
scoped with require_admin_scope: `principals:read` for the views,
`principals:write` for suspend/reactivate. A tenant-restricted managed
credential cannot list across all tenants (cross_tenant) but may read/act within
its allowlisted tenants. Off the guard path.

Spec: docs/specs/spec-mcp-gateway-enterprise.md (M1). M1 tail.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from core.auth import admin_actor, require_admin_scope
from api.routes_principals import _view

router = APIRouter(prefix="/v1/admin/principals", tags=["admin-principals"])

_MAX_LIST = 2000


def _scope(request: Request, operation: str, tenant_id: str = "",
           *, cross_tenant: bool = False) -> None:
    require_admin_scope(request, operation, tenant_id, cross_tenant=cross_tenant)


def _audit(request: Request, tenant_id: str, action: str, after: dict) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=admin_actor(request),
                         tenant_id=tenant_id,
                         source_ip=(request.client.host if request.client else ""),
                         after=after)
    except Exception:       # noqa: BLE001 — audit must never fail the action
        pass


@router.get("")
async def list_principals_admin(
    request: Request,
    tenant_id: Optional[str] = None,
    type: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    limit: int = 500,
):
    """List principals. Without `tenant_id`, spans every tenant (operator-wide);
    with it, one tenant. Same projection as the tenant console, plus the tenant
    each row belongs to."""
    from storage.principal_store import list_principals
    from storage.tenant_store import list_tenants

    if tenant_id:
        _scope(request, "principals:read", tenant_id)
        tenant_ids = [tenant_id]
    else:
        _scope(request, "principals:read", cross_tenant=True)
        tenant_ids = [t.get("tenant_id") for t in list_tenants() if t.get("tenant_id")]

    needle = (q or "").strip().lower()
    cap = max(1, min(int(limit or 500), _MAX_LIST))
    out = []
    for tid in tenant_ids:
        for doc in list_principals(tid):
            if type and doc.get("type") != type:
                continue
            if status and doc.get("status") != status:
                continue
            if needle and needle not in f"{doc.get('email', '')} {doc.get('name', '')}".lower():
                continue
            out.append({"tenant_id": tid, **_view(doc)})
            if len(out) >= cap:
                break
        if len(out) >= cap:
            break
    out.sort(key=lambda d: (d.get("email") or d.get("name") or d.get("id") or "").lower())
    return {"principals": out, "count": len(out), "truncated": len(out) >= cap}


@router.get("/{tenant_id}/{pid}")
async def get_principal_admin(tenant_id: str, pid: str, request: Request):
    """One principal, with its key metadata (never a secret or full hash)."""
    _scope(request, "principals:read", tenant_id)
    from storage.principal_store import get_principal, list_principal_keys
    doc = get_principal(tenant_id, pid)
    if doc is None:
        raise HTTPException(status_code=404, detail="no such principal")
    keys = [{k: v for k, v in rec.items() if k != "tenant_id"}
            for rec in list_principal_keys(tenant_id, pid)]
    return {"tenant_id": tenant_id, **_view(doc), "keys": keys}


async def _change(tenant_id: str, pid: str, request: Request,
                  status: str, action: str) -> dict:
    _scope(request, "principals:write", tenant_id)
    from core.principal_lifecycle import change_status
    try:
        summary = await change_status(tenant_id, pid, status)
    except KeyError:
        raise HTTPException(status_code=404, detail="no such principal")
    _audit(request, tenant_id, action, summary)
    return summary


@router.post("/{tenant_id}/{pid}/suspend")
async def suspend_principal_admin(tenant_id: str, pid: str, request: Request):
    """Refuse this principal's access and revoke its upstream connections —
    operator incident response, within ~15s on the guard path."""
    return await _change(tenant_id, pid, request, "suspended", "principal_suspended_admin")


@router.post("/{tenant_id}/{pid}/reactivate")
async def reactivate_principal_admin(tenant_id: str, pid: str, request: Request):
    return await _change(tenant_id, pid, request, "active", "principal_reactivated_admin")
