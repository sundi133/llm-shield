"""Agent identity management routes — register/revoke certs, query trust."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional

from guardrails.agentic.identity.cert_registry import (
    register_cert,
    revoke_cert,
    get_agent_trust,
)
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/shield/agent/identity", tags=["agent-identity"])


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
async def register_agent_cert(body: CertRegisterRequest, request: Request):
    """Register a certificate fingerprint for an agent.

    After registration, requests with X-Client-Cert-Fingerprint matching
    this fingerprint will be identified as this agent with 'high' trust level.
    """
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
async def revoke_agent_cert(body: CertRevokeRequest, request: Request):
    """Revoke a certificate for an agent.

    The agent will fall back to string_key identity with 'medium' trust.
    """
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
