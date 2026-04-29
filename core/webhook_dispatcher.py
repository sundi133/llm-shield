"""Webhook dispatcher — async HTTP POST with HMAC signing and retry.

Dispatches events to configured webhook endpoints. Non-blocking via asyncio.create_task().
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
from typing import Optional

import httpx

from storage.webhook_store import get_webhooks_for_event

logger = logging.getLogger("votal.webhook_dispatcher")

_TIMEOUT = 10.0  # seconds per request
_MAX_RETRIES = 3
_RETRY_DELAYS = [1, 3, 5]  # seconds between retries


def _sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Generate HMAC-SHA256 signature for webhook verification.

    Args:
        payload_bytes: The JSON payload as bytes
        secret: The webhook's shared secret

    Returns:
        Hex-encoded HMAC-SHA256 signature.
    """
    return hmac.HMAC(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()


async def _send_with_retry(
    url: str,
    headers: dict,
    body: bytes,
    max_retries: int = _MAX_RETRIES,
) -> bool:
    """Send HTTP POST with exponential backoff retry.

    Returns:
        True if successfully delivered (2xx), False otherwise.
    """
    for attempt in range(max_retries):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(url, content=body, headers=headers)
                if 200 <= resp.status_code < 300:
                    return True
                logger.warning(
                    f"Webhook delivery failed: {url} returned {resp.status_code} "
                    f"(attempt {attempt + 1}/{max_retries})"
                )
        except Exception as e:
            logger.warning(
                f"Webhook delivery error: {url} - {e} "
                f"(attempt {attempt + 1}/{max_retries})"
            )

        if attempt < max_retries - 1:
            await asyncio.sleep(_RETRY_DELAYS[attempt])

    logger.error(f"Webhook delivery permanently failed after {max_retries} attempts: {url}")
    return False


async def dispatch_event(
    tenant_id: str,
    event_type: str,
    payload: dict,
) -> None:
    """Dispatch an event to all subscribed webhooks for a tenant.

    This should be called via asyncio.create_task() to avoid blocking.

    Args:
        tenant_id: Tenant identifier
        event_type: Event type (guardrail_blocked, tool_disabled, policy_changed, budget_exceeded)
        payload: Event payload dict
    """
    webhooks = get_webhooks_for_event(tenant_id, event_type)
    if not webhooks:
        return

    # Build the event envelope
    event = {
        "event_type": event_type,
        "tenant_id": tenant_id,
        "timestamp": time.time(),
        "payload": payload,
    }
    event_bytes = json.dumps(event).encode()

    # Dispatch to all matching webhooks concurrently
    tasks = []
    for wh in webhooks:
        url = wh.get("url", "")
        secret = wh.get("secret", "")

        if not url:
            continue

        signature = _sign_payload(event_bytes, secret) if secret else ""
        headers = {
            "Content-Type": "application/json",
            "X-Shield-Event": event_type,
            "X-Shield-Signature": f"sha256={signature}" if signature else "",
            "X-Shield-Tenant": tenant_id,
        }

        tasks.append(_send_with_retry(url, headers, event_bytes))

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        delivered = sum(1 for r in results if r is True)
        logger.info(
            f"Webhook dispatch: event={event_type} tenant={tenant_id} "
            f"delivered={delivered}/{len(tasks)}"
        )
