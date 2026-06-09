"""SIEM integration — dispatch Shield events to Splunk HEC, Azure Sentinel, or generic SIEM.

Runs alongside the webhook dispatcher. When a tenant configures a SIEM
endpoint, every event that fires a webhook also fans out to the SIEM.

Supported targets:
    - Splunk HTTP Event Collector (HEC)
    - Azure Sentinel (Log Analytics HTTP Data Collector API)
    - Generic (POST JSON to any URL with Bearer token)
"""

import asyncio
import base64
import datetime
import hashlib
import hmac
import json
import logging
import time

import httpx

logger = logging.getLogger("votal.siem")

_TIMEOUT = 10.0
_MAX_RETRIES = 2


# ── Splunk HEC ────────────────────────────────────────────────────────────

def format_splunk_event(event: dict) -> dict:
    """Convert Shield event envelope to Splunk HEC JSON format."""
    return {
        "time": event.get("timestamp", time.time()),
        "source": "llm-shield",
        "sourcetype": "shield:guardrail",
        "index": "main",
        "event": {
            "event_type": event.get("event_type", ""),
            "tenant_id": event.get("tenant_id", ""),
            **event.get("payload", {}),
        },
    }


async def dispatch_to_splunk(event: dict, hec_url: str, hec_token: str) -> bool:
    """POST event to Splunk HTTP Event Collector."""
    splunk_event = format_splunk_event(event)
    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
    }
    return await _post(hec_url, headers, json.dumps(splunk_event).encode())


# ── Azure Sentinel (Log Analytics) ────────────────────────────────────────

def _sentinel_signature(
    workspace_id: str,
    shared_key: str,
    body: bytes,
    date_str: str,
) -> str:
    """Build the Azure Log Analytics API authorization header."""
    content_length = len(body)
    string_to_sign = (
        f"POST\n{content_length}\napplication/json\n"
        f"x-ms-date:{date_str}\n/api/logs"
    )
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {workspace_id}:{encoded_hash}"


def format_sentinel_event(event: dict) -> list[dict]:
    """Convert Shield event to Azure Sentinel log format (array of records)."""
    return [{
        "EventType": event.get("event_type", ""),
        "TenantId": event.get("tenant_id", ""),
        "Timestamp": datetime.datetime.utcfromtimestamp(
            event.get("timestamp", time.time())
        ).isoformat() + "Z",
        "Source": "llm-shield",
        **{k: json.dumps(v) if isinstance(v, (dict, list)) else str(v)
           for k, v in event.get("payload", {}).items()},
    }]


async def dispatch_to_sentinel(
    event: dict,
    workspace_id: str,
    shared_key: str,
    log_type: str = "LLMShield",
) -> bool:
    """POST event to Azure Log Analytics HTTP Data Collector API."""
    body = json.dumps(format_sentinel_event(event)).encode()
    date_str = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    auth = _sentinel_signature(workspace_id, shared_key, body, date_str)

    url = f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        "Content-Type": "application/json",
        "Authorization": auth,
        "Log-Type": log_type,
        "x-ms-date": date_str,
    }
    return await _post(url, headers, body)


# ── Generic SIEM ──────────────────────────────────────────────────────────

async def dispatch_to_generic(event: dict, url: str, token: str) -> bool:
    """POST event as-is to any URL with Bearer auth."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}" if token else "",
    }
    return await _post(url, headers, json.dumps(event).encode())


# ── Dispatcher (fan-out to all configured SIEM endpoints) ─────────────────

async def dispatch_to_siem(tenant_id: str, event: dict) -> None:
    """Dispatch an event to all SIEM endpoints configured for this tenant."""
    from storage.siem_store import get_siem_configs

    configs = get_siem_configs(tenant_id)
    if not configs:
        return

    event_type = event.get("event_type", "")
    tasks = []

    for cfg in configs:
        if not cfg.get("enabled", True):
            continue
        # Check event filter
        events_filter = cfg.get("events", [])
        if events_filter and event_type not in events_filter:
            continue

        siem_type = cfg.get("type", "generic")
        try:
            if siem_type == "splunk":
                tasks.append(dispatch_to_splunk(
                    event, cfg["url"], cfg.get("token", ""),
                ))
            elif siem_type == "sentinel":
                tasks.append(dispatch_to_sentinel(
                    event, cfg["workspace_id"], cfg.get("shared_key", ""),
                    log_type=cfg.get("log_type", "LLMShield"),
                ))
            else:
                tasks.append(dispatch_to_generic(
                    event, cfg["url"], cfg.get("token", ""),
                ))
        except Exception as e:
            logger.warning(f"SIEM dispatch setup failed for {siem_type}: {e}")

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        delivered = sum(1 for r in results if r is True)
        logger.info(
            f"SIEM dispatch: event={event_type} tenant={tenant_id} "
            f"delivered={delivered}/{len(tasks)}"
        )


# ── HTTP helper ───────────────────────────────────────────────────────────

async def _post(url: str, headers: dict, body: bytes) -> bool:
    """POST with retry. Returns True on success."""
    for attempt in range(_MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(url, headers=headers, content=body)
                if resp.status_code < 300:
                    return True
                logger.warning(f"SIEM POST {url}: {resp.status_code}")
        except Exception as e:
            if attempt == _MAX_RETRIES:
                logger.error(f"SIEM POST {url} failed after {_MAX_RETRIES + 1} attempts: {e}")
                return False
    return False
