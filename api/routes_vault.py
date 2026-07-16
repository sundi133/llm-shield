"""Secret vault API — register secrets that Shield keeps out of the LLM path.

Endpoints (admin plane, tenant X-API-Key):
    POST   /v1/tenant/me/vault       — register (or replace by name) a secret
    GET    /v1/tenant/me/vault       — list secrets (metadata only, never values)
    DELETE /v1/tenant/me/vault/{ref} — remove a secret

There is deliberately no endpoint that returns a decrypted value. The only path
to plaintext is server-side egress materialization to a bound destination.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from storage.vault_store import (
    create_vault_entry,
    delete_vault_entry,
    list_vault_entries,
)

router = APIRouter(prefix="/v1/tenant/me/vault", tags=["vault"])


def _require_tenant(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant API key required")
    return tenant_id


class VaultCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128,
                      description="Stable reference name, e.g. 'stripe_key'")
    value: str = Field(..., min_length=1, description="The real secret value")
    bindings: list[str] = Field(..., min_length=1,
                                description="Allowed egress destinations (hosts). Required.")
    mode: str = Field("inject", pattern="^(inject|token)$")
    tool_ids: list[str] = Field(default_factory=list,
                                description="Tools allowed to use this secret (tier-1)")


@router.post("")
async def create_secret(body: VaultCreateRequest, request: Request):
    """Register a secret. Returns metadata (ref + opaque token), never the value."""
    tenant_id = _require_tenant(request)
    try:
        entry = create_vault_entry(
            tenant_id, body.name, body.value, body.bindings,
            mode=body.mode, tool_ids=body.tool_ids,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"success": True, "secret": entry}


@router.get("")
async def list_secrets(request: Request):
    """List secrets for this tenant — metadata only (no ciphertext, no value)."""
    tenant_id = _require_tenant(request)
    entries = list_vault_entries(tenant_id)
    return {"success": True, "secrets": entries, "total": len(entries)}


@router.delete("/{ref}")
async def remove_secret(ref: str, request: Request):
    """Remove a secret by its reference name."""
    tenant_id = _require_tenant(request)
    if not delete_vault_entry(tenant_id, ref):
        raise HTTPException(status_code=404, detail=f"secret '{ref}' not found")
    return {"success": True, "message": f"secret '{ref}' deleted"}
