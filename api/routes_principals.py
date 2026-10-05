"""The people and service accounts that call the MCP gateway (admin plane).

    GET  /v1/tenant/me/principals?type=&status=&q=   list
    GET  /v1/tenant/me/principals/{pid}              one, with its connections and keys
    POST /v1/tenant/me/principals/{pid}/suspend      refuse access, revoke connections
    POST /v1/tenant/me/principals/{pid}/reactivate

Task B4 of docs/specs/mcp-verified-callers-and-user-credentials.md; task A3
adds service accounts and keys to this router. Reads need the tenant; changes
also need a portal administrator when the caller is a signed-in person.
Off the guard path.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request

from core.auth import get_tenant_from_request

router = APIRouter(prefix="/v1/tenant/me/principals", tags=["principals"])


def _view(doc: dict) -> dict:
    keep = ("id", "type", "email", "name", "issuer", "groups", "roles", "status",
            "source", "created_at", "status_changed_at")
    return {k: doc.get(k) for k in keep if k in doc}


@router.get("")
async def list_people(request: Request, type: Optional[str] = None,
                      status: Optional[str] = None, q: Optional[str] = None):
    from storage.principal_store import list_principals
    tenant_id = get_tenant_from_request(request)
    needle = (q or "").strip().lower()
    out = []
    for doc in list_principals(tenant_id):
        if type and doc.get("type") != type:
            continue
        if status and doc.get("status") != status:
            continue
        if needle and needle not in f"{doc.get('email', '')} {doc.get('name', '')}".lower():
            continue
        out.append(_view(doc))
    out.sort(key=lambda d: (d.get("email") or d.get("name") or d["id"]).lower())
    return {"principals": out, "count": len(out)}


@router.get("/{pid}")
async def get_person(pid: str, request: Request):
    from storage.mcp_grant_store import get_grant, routes_for_principal
    from storage.principal_store import get_principal, list_principal_keys
    tenant_id = get_tenant_from_request(request)
    doc = get_principal(tenant_id, pid)
    if doc is None:
        raise HTTPException(status_code=404, detail="no such person or service account")
    connections = [g for g in (get_grant(tenant_id, r, pid) for r in routes_for_principal(tenant_id, pid)) if g]
    keys = [{k: v for k, v in rec.items() if k != "tenant_id"} for rec in list_principal_keys(tenant_id, pid)]
    return {**_view(doc), "connections": connections, "keys": keys}


async def _change(pid: str, request: Request, status: str, action: str) -> dict:
    from core.auth import audit_actor, require_portal_admin
    from core.principal_lifecycle import change_status
    from storage.admin_audit import log_admin_action
    tenant_id = get_tenant_from_request(request)
    require_portal_admin(request)
    try:
        summary = await change_status(tenant_id, pid, status)
    except KeyError:
        raise HTTPException(status_code=404, detail="no such person or service account")
    try:
        log_admin_action(action=action, actor=audit_actor(request, tenant_id),
                         tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "",
                         after=summary)
    except Exception:       # noqa: BLE001
        pass
    return summary


@router.post("/{pid}/suspend")
async def suspend(pid: str, request: Request):
    """Refuse this person's gateway access (within 15 s) and revoke every
    upstream account they connected. Reactivating does not restore those."""
    return await _change(pid, request, "suspended", "principal_suspended")


@router.post("/{pid}/reactivate")
async def reactivate(pid: str, request: Request):
    return await _change(pid, request, "active", "principal_reactivated")
