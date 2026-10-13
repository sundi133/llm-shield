"""Manage admin-plane credentials (named, expiring, revocable partner keys).

    POST   /v1/admin/credentials             mint; secret shown once
    GET    /v1/admin/credentials             list (prefix only, never the secret)
    GET    /v1/admin/credentials/{id}        one
    DELETE /v1/admin/credentials/{id}        revoke (refused from the next call)

The admin gate (core/auth.AuthMiddleware) admits the root SHIELD_ADMIN_KEY, a
managed credential, or an SSO operator. These endpoints additionally require the
ROOT key or an operator — a managed credential cannot manage credentials, so a
minted key cannot mint itself more or revoke the operator's (anti-escalation).

Spec: docs/specs/admin-partner-credentials.md (Task 1). Off the guard path.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from core.auth import admin_actor, require_admin_root_or_operator

router = APIRouter(prefix="/v1/admin/credentials", tags=["admin-credentials"])

_MAX_NAME_LEN = 128


class CreateCredentialRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=_MAX_NAME_LEN)
    expires_in_days: Optional[int] = Field(None, ge=1, le=3650)
    # scope is accepted but not yet enforced (Task 2). Stored as-is; null = full
    # admin. Documented so an operator is not misled into thinking it narrows.
    scope: Optional[dict] = None


def _audit(request: Request, action: str, after: dict) -> None:
    try:
        from storage.admin_audit import log_admin_action
        log_admin_action(action=action, actor=admin_actor(request),
                         source_ip=(request.client.host if request.client else ""),
                         after=after)
    except Exception:       # noqa: BLE001 — audit must never fail the action
        pass


@router.post("")
async def create_credential(body: CreateCredentialRequest, request: Request):
    """Mint a credential. The secret is in this response only."""
    require_admin_root_or_operator(request)
    from storage.admin_credentials import create_credential as _create
    try:
        secret, record = _create(
            body.name,
            expires_in_days=body.expires_in_days,
            created_by=admin_actor(request),
            scope=body.scope,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(request, "admin_credential_created",
           {"id": record["id"], "name": record["name"],
            "expires_at": record.get("expires_at")})
    return {"secret": secret, **record,
            "note": "Store this now. Shield keeps only its hash and cannot show "
                    "it again. Send it as X-Admin-Key."}


@router.get("")
async def list_credentials(request: Request):
    """Every credential, newest first. Never the secret or full hash."""
    require_admin_root_or_operator(request)
    from storage.admin_credentials import list_credentials as _list
    creds = _list()
    return {"credentials": creds, "count": len(creds)}


@router.get("/{cred_id}")
async def get_credential(cred_id: str, request: Request):
    require_admin_root_or_operator(request)
    from storage.admin_credentials import get_credential as _get
    record = _get(cred_id)
    if record is None:
        raise HTTPException(status_code=404, detail="no such credential")
    return record


@router.delete("/{cred_id}")
async def revoke_credential(cred_id: str, request: Request):
    """Revoke a credential; it is refused from the next call."""
    require_admin_root_or_operator(request)
    from storage.admin_credentials import revoke_credential as _revoke
    if not _revoke(cred_id):
        raise HTTPException(status_code=404, detail="no such credential")
    _audit(request, "admin_credential_revoked", {"id": cred_id})
    return {"status": "revoked", "id": cred_id}
