"""Webhook management routes — CRUD for webhook endpoint configurations."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional, List

from storage.webhook_store import (
    create_webhook,
    get_webhooks,
    get_webhook,
    update_webhook,
    delete_webhook,
)
from storage.admin_audit import log_admin_action

router = APIRouter(prefix="/v1/shield/webhooks", tags=["webhooks"])

# Supported event types
VALID_EVENTS = [
    "guardrail_blocked",
    "tool_disabled",
    "tool_enabled",
    "policy_changed",
    "budget_exceeded",
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
