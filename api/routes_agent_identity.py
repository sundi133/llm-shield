"""Agent identity management routes — register/revoke certs, query trust."""

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.agentic.identity.cert_registry import (
    register_cert,
    revoke_cert,
    get_agent_trust,
)
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/shield/agent/identity", tags=["agent-identity"])


def _authorized_tenant(request: Request) -> Optional[str]:
    """Authorize cert register/revoke and return the caller's tenant scope.

    Registering a fingerprint grants the holder trust_level "high" as the named
    agent, and ``tenant_id`` comes from the request body — so an unauthenticated
    caller could previously mint an identity in any tenant, or revoke every
    agent in one.

    Two callers are legitimate:

    * An **admin identity** (resolved through the modular workload-identity
      providers, so SPIFFE and mTLS deployments work too) — may act on any
      tenant. Returns None, meaning "no tenant restriction".
    * A **tenant API key** — tenants register their own agents. Returns that
      tenant id, and the caller is confined to it.

    Confinement, not exclusion, is the control here: the risk was never that a
    tenant registers its own agents, it was that the request body could name
    somebody else's tenant.
    """
    from core.workload_identity import resolve_workload_identity, enabled_providers

    identity = resolve_workload_identity(request)
    if identity is not None:
        request.state.workload_identity = identity
        return None  # admin — unrestricted

    api_key = (
        request.headers.get("X-API-Key")
        or request.headers.get("x-api-key")
        or ""
    ).strip()
    if api_key:
        from storage.tenant_store import resolve_tenant_by_api_key

        tenant = resolve_tenant_by_api_key(api_key)
        if tenant:
            return tenant

    names = [p.name for p in enabled_providers()]
    if "admin_key" in names and not os.environ.get("SHIELD_ADMIN_KEY", ""):
        raise HTTPException(
            status_code=500,
            detail="SHIELD_ADMIN_KEY not configured — cert registration disabled",
        )
    raise HTTPException(status_code=403, detail="admin key or tenant API key required")


def _confine_to_tenant(scope: Optional[str], body_tenant_id: str) -> None:
    """A tenant-scoped caller may only act on its own tenant."""
    if scope is not None and body_tenant_id != scope:
        raise HTTPException(
            status_code=403,
            detail="tenant mismatch: this API key is not authorized for that tenant",
        )


def _actor_from_request(request: Request) -> str:
    import hashlib
    key = (
        request.headers.get("X-Admin-Key") or
        request.headers.get("X-API-Key") or
        request.headers.get("Authorization", "").replace("Bearer ", "")
    )
    if not key:
        return "unknown"
    return f"user:{hashlib.sha256(key.encode()).hexdigest()[:12]}"


def _source_ip(request: Request) -> str:
    return request.client.host if request.client else ""


class CertRegisterRequest(BaseModel):
    agent_key: str = Field(..., description="Agent identifier to bind certificate to")
    fingerprint: str = Field(..., description="SHA-256 fingerprint of client certificate")
    tenant_id: str = Field(..., description="Tenant identifier")


class CertRevokeRequest(BaseModel):
    agent_key: str = Field(..., description="Agent whose certificate to revoke")
    tenant_id: str = Field(..., description="Tenant identifier")


@router.post("/register")
async def register_agent_cert(
    body: CertRegisterRequest,
    request: Request,
    scope: Optional[str] = Depends(_authorized_tenant),
):
    """Register a certificate fingerprint for an agent.

    After registration, requests with X-Client-Cert-Fingerprint matching
    this fingerprint will be identified as this agent with 'high' trust level.
    """
    _confine_to_tenant(scope, body.tenant_id)

    trust_record = register_cert(
        tenant_id=body.tenant_id,
        agent_key=body.agent_key,
        fingerprint=body.fingerprint,
    )

    log_admin_action(
        action="register_agent_cert",
        actor=_actor_from_request(request),
        tenant_id=body.tenant_id,
        source_ip=_source_ip(request),
        after={
            "agent_key": body.agent_key,
            "fingerprint": body.fingerprint[:16] + "...",
            "trust_level": "high",
        },
    )

    return {
        "status": "registered",
        "agent_key": body.agent_key,
        "trust": trust_record,
    }


@router.post("/revoke")
async def revoke_agent_cert(
    body: CertRevokeRequest,
    request: Request,
    scope: Optional[str] = Depends(_authorized_tenant),
):
    """Revoke a certificate for an agent.

    The agent will fall back to string_key identity with 'medium' trust.
    """
    _confine_to_tenant(scope, body.tenant_id)

    revoked = revoke_cert(tenant_id=body.tenant_id, agent_key=body.agent_key)

    if not revoked:
        raise HTTPException(
            status_code=404,
            detail=f"No certificate found for agent '{body.agent_key}'"
        )

    log_admin_action(
        action="revoke_agent_cert",
        actor=_actor_from_request(request),
        tenant_id=body.tenant_id,
        source_ip=_source_ip(request),
        after={"agent_key": body.agent_key},
    )

    return {
        "status": "revoked",
        "agent_key": body.agent_key,
        "new_trust_level": "medium",
    }


@router.get("/{agent_key}")
async def get_agent_identity(agent_key: str, tenant_id: str):
    """Get trust metadata for an agent."""
    trust = get_agent_trust(tenant_id, agent_key)
    return {
        "agent_key": agent_key,
        "tenant_id": tenant_id,
        "trust": trust,
    }
