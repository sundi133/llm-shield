"""The people and service accounts that call the MCP gateway (admin plane).

    GET    /v1/tenant/me/principals?type=&status=&q=      list
    GET    /v1/tenant/me/principals/{pid}                 one, with connections, keys, clients
    POST   /v1/tenant/me/principals/{pid}/suspend         refuse access, revoke connections
    POST   /v1/tenant/me/principals/{pid}/reactivate
    PATCH  /v1/tenant/me/principals/{pid}                 a service account's name or roles
    POST   /v1/tenant/me/principals/{pid}/keys            a key, shown once (service accounts)
    DELETE /v1/tenant/me/principals/{pid}/keys/{key_id}
    POST   /v1/tenant/me/principals/{pid}/oauth-clients   client id + secret, shown once
    DELETE /v1/tenant/me/principals/{pid}/oauth-clients/{client_id}
    POST   /v1/tenant/me/service-accounts                 create
    DELETE /v1/tenant/me/service-accounts/{pid}           remove (deprovision)

Tasks B4 and A3 of docs/specs/mcp-verified-callers-and-user-credentials.md.
Reads need the tenant; changes also need a portal administrator when the
caller is a signed-in person. Off the guard path.

**Keys and OAuth clients are for service accounts only.** An administrator who
could mint a key for a person could act as that person, with their roles and
their personal upstream connections. People sign in instead (task A2).
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import get_tenant_from_request

router = APIRouter(prefix="/v1/tenant/me/principals", tags=["principals"])
sa_router = APIRouter(prefix="/v1/tenant/me/service-accounts", tags=["principals"])

_MAX_ROLES = 20


class ServiceAccountRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    roles: list[str] = Field(default_factory=list, max_length=_MAX_ROLES)


class ServiceAccountUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    roles: Optional[list[str]] = Field(None, max_length=_MAX_ROLES)


class KeyRequest(BaseModel):
    label: str = Field("", max_length=100)


def _admin(request: Request) -> str:
    from core.auth import require_portal_admin
    tenant_id = get_tenant_from_request(request)
    require_portal_admin(request)
    return tenant_id


def _audit(request: Request, tenant_id: str, action: str, after: dict) -> None:
    try:
        from core.auth import audit_actor
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=audit_actor(request, tenant_id), tenant_id=tenant_id,
                         source_ip=request.client.host if request.client else "", after=after)
    except Exception:       # noqa: BLE001
        pass


def _service_account(tenant_id: str, pid: str) -> dict:
    from storage.principal_store import TYPE_SERVICE_ACCOUNT, get_principal
    doc = get_principal(tenant_id, pid)
    if doc is None:
        raise HTTPException(status_code=404, detail="no such person or service account")
    if doc.get("type") != TYPE_SERVICE_ACCOUNT:
        raise HTTPException(status_code=400, detail=(
            "keys and OAuth clients are for service accounts only; people sign in "
            "from their AI app with your company login"))
    return doc


def _roles(values) -> list[str]:
    out = []
    for r in values or []:
        r = str(r).strip()
        if not r or len(r) > 64:
            raise HTTPException(status_code=422, detail="each role must be 1 to 64 characters")
        if r not in out:
            out.append(r)
    return out


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
    from core.principal_lifecycle import principal_clients
    connections = [g for g in (get_grant(tenant_id, r, pid) for r in routes_for_principal(tenant_id, pid)) if g]
    keys = [{k: v for k, v in rec.items() if k != "tenant_id"} for rec in list_principal_keys(tenant_id, pid)]
    clients = [{"client_id": c.client_id, "name": c.client_name, "created_at": c.created_at}
               for c in await principal_clients(tenant_id, pid)]
    return {**_view(doc), "connections": connections, "keys": keys, "oauth_clients": clients}


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


# ── service accounts, keys and OAuth clients (A3) ────────────────────────


@sa_router.post("")
async def create_service_account(body: ServiceAccountRequest, request: Request):
    """A headless caller (CI job, nightly agent) that cannot sign in through a
    browser. It acts with exactly the roles set here."""
    from storage.principal_store import create_service_account as create
    tenant_id = _admin(request)
    from core.auth import audit_actor
    doc = create(tenant_id, name=body.name, roles=_roles(body.roles),
                 created_by=audit_actor(request, tenant_id))
    _audit(request, tenant_id, "service_account_created",
           {"principal_id": doc["id"], "name": doc["name"], "roles": doc["roles"]})
    return _view(doc)


@sa_router.delete("/{pid}")
async def remove_service_account(pid: str, request: Request):
    """Deprovision: refused from the next call, keys and OAuth clients deleted,
    personal connections revoked. The record stays for the audit trail."""
    from core.principal_lifecycle import change_status
    tenant_id = _admin(request)
    _service_account(tenant_id, pid)
    summary = await change_status(tenant_id, pid, "deprovisioned")
    _audit(request, tenant_id, "service_account_removed", summary)
    return summary


@router.patch("/{pid}")
async def update_service_account(pid: str, body: ServiceAccountUpdate, request: Request):
    from storage.principal_store import update_service_account as update
    tenant_id = _admin(request)
    before = _service_account(tenant_id, pid)
    doc = update(tenant_id, pid, name=body.name,
                 roles=_roles(body.roles) if body.roles is not None else None)
    _audit(request, tenant_id, "service_account_updated",
           {"principal_id": pid, "before": {"name": before.get("name"), "roles": before.get("roles")},
            "name": doc.get("name"), "roles": doc.get("roles")})
    return _view(doc)


@router.post("/{pid}/keys")
async def create_key(pid: str, request: Request, body: Optional[KeyRequest] = None):
    """A key for a service account. The key is in this response only."""
    from storage.principal_store import create_principal_key, is_active
    tenant_id = _admin(request)
    doc = _service_account(tenant_id, pid)
    if not is_active(doc):
        raise HTTPException(status_code=409, detail="the service account is not active")
    key, record = create_principal_key(tenant_id, pid, label=(body.label if body else ""))
    _audit(request, tenant_id, "service_account_key_created",
           {"principal_id": pid, "key_id": record["key_id"], "prefix": record["prefix"]})
    return {"key": key, **{k: v for k, v in record.items() if k != "tenant_id"},
            "note": "Store this key now. Shield keeps only its hash and cannot show it again."}


@router.delete("/{pid}/keys/{key_id}")
async def delete_key(pid: str, key_id: str, request: Request):
    from storage.principal_store import delete_principal_key_by_id
    tenant_id = _admin(request)
    _service_account(tenant_id, pid)
    if not delete_principal_key_by_id(tenant_id, pid, key_id):
        raise HTTPException(status_code=404, detail="no such key")
    _audit(request, tenant_id, "service_account_key_deleted", {"principal_id": pid, "key_id": key_id})
    return {"status": "deleted", "key_id": key_id}


@router.post("/{pid}/oauth-clients")
async def create_oauth_client(pid: str, request: Request):
    """An OAuth client for the client-credentials grant, authenticating as this
    service account. The secret is in this response only."""
    import time

    from core.oauth.authz_server import generate_client_id, generate_client_secret
    from storage.oauth_store import OAuthClient, hash_client_secret, save_client
    from storage.principal_store import is_active
    tenant_id = _admin(request)
    doc = _service_account(tenant_id, pid)
    if not is_active(doc):
        raise HTTPException(status_code=409, detail="the service account is not active")
    client_id, secret = generate_client_id(), generate_client_secret()
    await save_client(OAuthClient(
        client_id=client_id, client_name=f"service account: {doc.get('name', '')}"[:100],
        client_secret_hash=hash_client_secret(secret), redirect_uris=[],
        grant_types=["client_credentials"], token_endpoint_auth_method="client_secret_post",
        scope="mcp", tenant_id=tenant_id, created_at=int(time.time()), principal_id=pid))
    _audit(request, tenant_id, "service_account_oauth_client_created",
           {"principal_id": pid, "client_id": client_id})
    return {"client_id": client_id, "client_secret": secret, "grant_type": "client_credentials",
            "note": "Store the secret now. Shield keeps only its hash and cannot show it again."}


@router.delete("/{pid}/oauth-clients/{client_id}")
async def delete_oauth_client(pid: str, client_id: str, request: Request):
    from core.principal_lifecycle import principal_clients
    from storage.oauth_store import delete_client
    tenant_id = _admin(request)
    _service_account(tenant_id, pid)
    if client_id not in {c.client_id for c in await principal_clients(tenant_id, pid)}:
        raise HTTPException(status_code=404, detail="no such OAuth client")
    await delete_client(client_id)
    _audit(request, tenant_id, "service_account_oauth_client_deleted",
           {"principal_id": pid, "client_id": client_id})
    return {"status": "deleted", "client_id": client_id}
