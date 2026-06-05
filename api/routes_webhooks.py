"""Webhook management routes — CRUD for webhook endpoint configurations."""

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel, Field
from typing import Optional, List

from core.auth import verify_tenant_path_access
from core.url_safety import UnsafeURLError, validate_outbound_url
from storage.webhook_store import (
    create_webhook,
    get_webhooks,
    get_webhook,
    update_webhook,
    delete_webhook,
)
from storage.admin_audit import log_admin_action

router = APIRouter(
    prefix="/v1/shield/webhooks",
    tags=["webhooks"],
    dependencies=[Depends(verify_tenant_path_access)],
)


def _validate_webhook_url(url: str) -> None:
    """Reject webhook URLs that target internal/metadata addresses (SSRF).

    Webhooks legitimately call arbitrary external endpoints, so we use
    the network-level filter (block private/loopback/link-local/metadata
    + non-http(s) schemes) rather than the LLM-provider allowlist.

    Boundary check only (resolve_dns=False): catches bad schemes and
    internal IP literals/metadata hosts without depending on DNS being
    reachable. The dispatcher re-validates with full DNS resolution
    immediately before each delivery, which is the real SSRF guarantee.
    """
    try:
        validate_outbound_url(url, purpose="webhook", resolve_dns=False)
    except UnsafeURLError:
        raise HTTPException(
            status_code=400,
            detail="Webhook URL is not allowed (must be a public http(s) endpoint)",
        )

# Supported event types
VALID_EVENTS = [
    "guardrail_blocked",
    "tool_disabled",
    "tool_enabled",
    "policy_changed",
    "budget_exceeded",
    "shadow_agent_detected",
]


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


class WebhookCreateRequest(BaseModel):
    url: str = Field(..., description="HTTPS endpoint URL to receive events")
    secret: str = Field("", description="Shared secret for HMAC-SHA256 signature verification")
    events: List[str] = Field(..., description="Event types to subscribe to")
    enabled: bool = Field(True, description="Whether webhook is active")


class WebhookUpdateRequest(BaseModel):
    url: Optional[str] = None
    secret: Optional[str] = None
    events: Optional[List[str]] = None
    enabled: Optional[bool] = None


@router.post("/{tenant_id}")
async def create_webhook_endpoint(tenant_id: str, body: WebhookCreateRequest, request: Request):
    """Create a new webhook for a tenant."""
    # Validate event types
    invalid = [e for e in body.events if e not in VALID_EVENTS]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid event types: {invalid}. Valid: {VALID_EVENTS}"
        )

    _validate_webhook_url(body.url)

    webhook = create_webhook(tenant_id, body.model_dump())

    log_admin_action(
        action="create_webhook",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={"webhook_id": webhook["webhook_id"], "url": body.url, "events": body.events},
    )

    return {"status": "created", "tenant_id": tenant_id, "webhook": webhook}


@router.get("/{tenant_id}")
async def list_webhooks_endpoint(tenant_id: str):
    """List all webhooks for a tenant."""
    webhooks = get_webhooks(tenant_id)
    # Redact secrets in response
    safe_webhooks = []
    for wh in webhooks:
        wh_copy = dict(wh)
        if wh_copy.get("secret"):
            wh_copy["secret"] = "***"
        safe_webhooks.append(wh_copy)

    return {"tenant_id": tenant_id, "webhooks": safe_webhooks, "count": len(safe_webhooks)}


@router.get("/{tenant_id}/{webhook_id}")
async def get_webhook_endpoint(tenant_id: str, webhook_id: str):
    """Get a specific webhook configuration."""
    webhook = get_webhook(tenant_id, webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail=f"Webhook '{webhook_id}' not found")

    # Redact secret
    wh_copy = dict(webhook)
    if wh_copy.get("secret"):
        wh_copy["secret"] = "***"
    return wh_copy


@router.put("/{tenant_id}/{webhook_id}")
async def update_webhook_endpoint(
    tenant_id: str, webhook_id: str, body: WebhookUpdateRequest, request: Request
):
    """Update a webhook configuration."""
    if body.events:
        invalid = [e for e in body.events if e not in VALID_EVENTS]
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid event types: {invalid}. Valid: {VALID_EVENTS}"
            )

    if body.url is not None:
        _validate_webhook_url(body.url)

    updates = body.model_dump(exclude_none=True)
    updated = update_webhook(tenant_id, webhook_id, updates)

    if not updated:
        raise HTTPException(status_code=404, detail=f"Webhook '{webhook_id}' not found")

    log_admin_action(
        action="update_webhook",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={"webhook_id": webhook_id, "updated_fields": list(updates.keys())},
    )

    return {"status": "updated", "tenant_id": tenant_id, "webhook": updated}


@router.delete("/{tenant_id}/{webhook_id}")
async def delete_webhook_endpoint(tenant_id: str, webhook_id: str, request: Request):
    """Delete a webhook configuration."""
    deleted = delete_webhook(tenant_id, webhook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Webhook '{webhook_id}' not found")

    log_admin_action(
        action="delete_webhook",
        actor=_actor_from_request(request),
        tenant_id=tenant_id,
        source_ip=_source_ip(request),
        after={"webhook_id": webhook_id},
    )

    return {"status": "deleted", "tenant_id": tenant_id, "webhook_id": webhook_id}
