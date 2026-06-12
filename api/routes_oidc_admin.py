"""Admin endpoints for managing external OIDC provider configurations.

Per-tenant CRUD at /v1/admin/oidc-providers. Requires X-Admin-Key.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from core.oauth.oidc_client import OIDCProvider, oidc_registry, discover_openid_config

logger = logging.getLogger("votal.routes_oidc_admin")
router = APIRouter(prefix="/v1/admin/oidc-providers", tags=["oidc-admin"])


def _require_admin(request: Request) -> None:
    """Check that the request carries a valid admin key.

    Fails closed when SHIELD_ADMIN_KEY is unset — matching the admin gate
    used everywhere else (core/auth.py, core/app.py, routes_agent_auth.py).
    An unconfigured key must never mean "open access": these endpoints
    register the OIDC providers a tenant trusts, so leaving them open to
    unauthenticated callers would let anyone establish IdP trust for any
    tenant. The key comparison is constant-time to avoid leaking it via
    timing.
    """
    import hmac
    import os
    admin_key = os.environ.get("SHIELD_ADMIN_KEY", "").strip()
    if not admin_key:
        raise PermissionError(
            "SHIELD_ADMIN_KEY not configured — admin endpoints disabled"
        )
    provided = request.headers.get("X-Admin-Key", "").strip()
    if not provided or not hmac.compare_digest(provided, admin_key):
        raise PermissionError("invalid admin key")


@router.get("/{tenant_id}")
async def list_providers(tenant_id: str, request: Request):
    """List all OIDC providers configured for a tenant."""
    try:
        _require_admin(request)
    except PermissionError:
        return JSONResponse(status_code=403, content={"error": "forbidden"})

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


@router.post("/{tenant_id}")
async def register_provider(tenant_id: str, request: Request):
    """Register or update an OIDC provider for a tenant.

    Body:
        name: Provider name (e.g. "okta", "keycloak")
        issuer: OIDC issuer URL
        client_id: Shield's client_id at the IdP
        audience: Expected aud claim (defaults to client_id)
        jwks_uri: JWKS endpoint (auto-discovered if empty)
        claim_mapping: Dict mapping IdP claims to Shield claims
    """
    try:
        _require_admin(request)
    except PermissionError:
        return JSONResponse(status_code=403, content={"error": "forbidden"})

    body = await request.json()
    name = body.get("name", "").strip()
    if not name:
        return JSONResponse(status_code=400, content={"error": "name is required"})

    issuer = body.get("issuer", "").strip()
    client_id = body.get("client_id", "").strip()
    if not issuer or not client_id:
        return JSONResponse(
            status_code=400,
            content={"error": "issuer and client_id are required"},
        )

    # Optionally verify the issuer is reachable
    jwks_uri = body.get("jwks_uri", "").strip()
    if not jwks_uri:
        try:
            config = await discover_openid_config(issuer)
            jwks_uri = config.get("jwks_uri", "")
        except Exception as e:
            logger.warning(f"OIDC discovery failed for {issuer}: {e}")
            # Proceed without jwks_uri -- will be discovered at validation time

    provider = OIDCProvider(
        issuer=issuer,
        client_id=client_id,
        audience=body.get("audience", ""),
        jwks_uri=jwks_uri,
        claim_mapping=body.get("claim_mapping", {}),
    )
    await oidc_registry.register_provider(tenant_id, name, provider)

    return {
        "status": "registered",
        "tenant_id": tenant_id,
        "name": name,
        "issuer": issuer,
        "jwks_uri": jwks_uri,
    }


@router.delete("/{tenant_id}/{provider_name}")
async def delete_provider(tenant_id: str, provider_name: str, request: Request):
    """Remove an OIDC provider from a tenant."""
    try:
        _require_admin(request)
    except PermissionError:
        return JSONResponse(status_code=403, content={"error": "forbidden"})

    removed = await oidc_registry.remove_provider(tenant_id, provider_name)
    if not removed:
        return JSONResponse(
            status_code=404,
            content={"error": f"provider {provider_name!r} not found"},
        )

    return {"status": "removed", "tenant_id": tenant_id, "name": provider_name}
