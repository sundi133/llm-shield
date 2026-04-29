"""Webhook configuration store — CRUD for webhook endpoints per tenant.

Redis keys:
    webhooks:{tenant_id}  → JSON string of list[webhook_config]
"""

import json
import logging
import time
import uuid
from typing import Optional

from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.webhook_store")


def create_webhook(tenant_id: str, webhook_config: dict) -> dict:
    """Create a new webhook configuration for a tenant.

    Args:
        tenant_id: Tenant identifier
        webhook_config: Dict with url, secret, events, enabled

    Returns:
        The stored webhook config with generated webhook_id.
    """
    webhook_config.setdefault("webhook_id", str(uuid.uuid4())[:8])
    webhook_config.setdefault("created_at", int(time.time()))
    webhook_config.setdefault("enabled", True)
    webhook_config["tenant_id"] = tenant_id

    key = f"webhooks:{tenant_id}"

    r = _get_redis()
    if r:
        existing = r.get(key)
        webhooks = json.loads(existing) if existing else []
        webhooks.append(webhook_config)
        r.set(key, json.dumps(webhooks))
    else:
        existing = _fallback_store.get(key, "[]")
        webhooks = json.loads(existing)
        webhooks.append(webhook_config)
        _fallback_store[key] = json.dumps(webhooks)

    logger.info(f"Created webhook {webhook_config['webhook_id']} for tenant {tenant_id}")
    return webhook_config


def get_webhooks(tenant_id: str) -> list[dict]:
    """Get all webhook configurations for a tenant."""
    key = f"webhooks:{tenant_id}"

    r = _get_redis()
    if r:
        data = r.get(key)
    else:
        data = _fallback_store.get(key)

    return json.loads(data) if data else []


def get_webhook(tenant_id: str, webhook_id: str) -> Optional[dict]:
    """Get a specific webhook by ID."""
    webhooks = get_webhooks(tenant_id)
    for wh in webhooks:
        if wh.get("webhook_id") == webhook_id:
            return wh
    return None


def update_webhook(tenant_id: str, webhook_id: str, updates: dict) -> Optional[dict]:
    """Update a webhook configuration.

    Returns:
        Updated webhook config, or None if not found.
    """
    key = f"webhooks:{tenant_id}"
    webhooks = get_webhooks(tenant_id)

    updated = None
    for i, wh in enumerate(webhooks):
        if wh.get("webhook_id") == webhook_id:
            webhooks[i].update(updates)
            webhooks[i]["updated_at"] = int(time.time())
            updated = webhooks[i]
            break

    if updated is None:
        return None

    r = _get_redis()
    if r:
        r.set(key, json.dumps(webhooks))
    else:
        _fallback_store[key] = json.dumps(webhooks)

    return updated


def delete_webhook(tenant_id: str, webhook_id: str) -> bool:
    """Delete a webhook configuration.

    Returns:
        True if deleted, False if not found.
    """
    key = f"webhooks:{tenant_id}"
    webhooks = get_webhooks(tenant_id)

    original_count = len(webhooks)
    webhooks = [wh for wh in webhooks if wh.get("webhook_id") != webhook_id]

    if len(webhooks) == original_count:
        return False

    r = _get_redis()
    if r:
        r.set(key, json.dumps(webhooks))
    else:
        _fallback_store[key] = json.dumps(webhooks)

    return True


def get_webhooks_for_event(tenant_id: str, event_type: str) -> list[dict]:
    """Get all enabled webhooks subscribed to a specific event type.

    Args:
        tenant_id: Tenant identifier
        event_type: Event type to match (e.g., 'guardrail_blocked')

    Returns:
        List of matching webhook configs.
    """
    webhooks = get_webhooks(tenant_id)
    return [
        wh for wh in webhooks
        if wh.get("enabled", True) and event_type in wh.get("events", [])
    ]
