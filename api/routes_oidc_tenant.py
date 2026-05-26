"""Tenant self-serve endpoints for managing the tenant's own OIDC providers.

A tenant on sovereign / on-prem deployments needs to register their own
Keycloak / Dex / ADFS provider so federated id_tokens validate against
the right issuer. They should be able to do this with just their tenant
API key — the admin key belongs to the platform operator and is never
shared with customers.

The tenant_id is always taken from the resolved API key; clients cannot
target other tenants.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from core.oauth.oidc_client import OIDCProvider, discover_openid_config, oidc_registry

logger = logging.getLogger("votal.routes_oidc_tenant")
router = APIRouter(prefix="/v1/tenant/me/oidc-providers", tags=["oidc-tenant"])


def _require_tenant(request: Request) -> str:
    tenant_id = getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant API key required")
    return tenant_id


@router.get("")
async def list_providers(request: Request):
    """List all OIDC providers configured for the calling tenant."""
    tenant_id = _require_tenant(request)
    providers = await oidc_registry.get_providers(tenant_id)
    return {
        "tenant_id": tenant_id,
        "providers": {
            name: {
                "issuer": p.issuer,
                "client_id": p.client_id,
                "audience": p.audience,
                "jwks_uri": p.jwks_uri,
                "claim_mapping": p.claim_mapping,
            }
            for name, p in providers.items()
        },
    }


@router.post("")
async def register_provider(request: Request):
    """Register or update an OIDC provider for the calling tenant.

    Body:
        name: Provider name (e.g. "keycloak", "dex")
        issuer: OIDC issuer URL
        client_id: Shield's client_id at the IdP
        audience: Expected aud claim (defaults to client_id)
        jwks_uri: JWKS endpoint (auto-discovered if empty)
        claim_mapping: Dict mapping IdP claims to Shield claims
    """
    tenant_id = _require_tenant(request)

    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        return JSONResponse(status_code=400, content={"error": "name is required"})

    issuer = (body.get("issuer") or "").strip()
    client_id = (body.get("client_id") or "").strip()
    if not issuer or not client_id:
        return JSONResponse(
            status_code=400,
            content={"error": "issuer and client_id are required"},
        )

    jwks_uri = (body.get("jwks_uri") or "").strip()
    if not jwks_uri:
        try:
            config = await discover_openid_config(issuer)
            jwks_uri = config.get("jwks_uri", "")
        except Exception as e:
            logger.warning(f"OIDC discovery failed for {issuer}: {e}")
            # proceed without jwks_uri — discovered later at validation time

    provider = OIDCProvider(
        issuer=issuer,
        client_id=client_id,
        audience=body.get("audience", ""),
        jwks_uri=jwks_uri,
        claim_mapping=body.get("claim_mapping") or {},
    )
    await oidc_registry.register_provider(tenant_id, name, provider)

    return {
        "status": "registered",
        "tenant_id": tenant_id,
        "name": name,
        "issuer": issuer,
        "jwks_uri": jwks_uri,
    }


@router.delete("/{provider_name}")
async def delete_provider(provider_name: str, request: Request):
    """Remove one of the calling tenant's OIDC providers."""
    tenant_id = _require_tenant(request)
    removed = await oidc_registry.remove_provider(tenant_id, provider_name)
    if not removed:
        return JSONResponse(
            status_code=404,
            content={"error": f"provider {provider_name!r} not found"},
        )
    return {"status": "removed", "tenant_id": tenant_id, "name": provider_name}
