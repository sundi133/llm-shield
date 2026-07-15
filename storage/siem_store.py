"""SIEM configuration storage — CRUD for tenant SIEM integrations in Redis.

Redis key: siem:{tenant_id} → JSON list of SIEM configs.

Each config:
    {
        "siem_id": "unique-id",
        "type": "splunk" | "sentinel" | "elastic" | "wazuh" | "generic",
        "url": "https://splunk-hec.company.com:8088/services/collector",
        "token": "HEC-token / bearer / elastic-api-key",
        "workspace_id": "azure-workspace-id",  (sentinel only)
        "shared_key": "azure-shared-key",      (sentinel only)
        "log_type": "LLMShield",               (sentinel only)
        "events": ["guardrail_blocked", "shadow_agent_detected"],  (empty = all)
        "statuses": ["block", "warn"],  (empty = all; absent = block only, legacy)
        "enabled": true,
        "created_at": 1717700000,
        "updated_at": 1717700000,
    }
"""

import json
import logging
import time
import uuid

logger = logging.getLogger("votal.siem_store")


def _get_redis():
    from storage.tenant_store import _get_redis as _gr
    return _gr()


def _key(tenant_id: str) -> str:
    return f"siem:{tenant_id}"


def get_siem_configs(tenant_id: str) -> list[dict]:
    """Get all SIEM configs for a tenant."""
    r = _get_redis()
    if not r:
        return []
    try:
        raw = r.get(_key(tenant_id))
        if not raw:
            return []
        data = json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        return data if isinstance(data, list) else []
    except Exception as e:
        logger.debug(f"siem_store get failed: {e}")
        return []


def create_siem_config(tenant_id: str, config: dict) -> dict:
    """Create a new SIEM integration. Returns the created config with siem_id."""
    r = _get_redis()
    if not r:
        raise RuntimeError("Redis not available")

    configs = get_siem_configs(tenant_id)
    now = int(time.time())

    new_config = {
        "siem_id": uuid.uuid4().hex[:12],
        "type": config.get("type", "generic"),
        "url": config.get("url", ""),
        "token": config.get("token", ""),
        "workspace_id": config.get("workspace_id", ""),
        "shared_key": config.get("shared_key", ""),
        "log_type": config.get("log_type", "LLMShield"),
        "events": config.get("events", []),
        "statuses": config.get("statuses", []),
        "enabled": config.get("enabled", True),
        "created_at": now,
        "updated_at": now,
    }

    configs.append(new_config)
    r.set(_key(tenant_id), json.dumps(configs))
    return new_config


def delete_siem_config(tenant_id: str, siem_id: str) -> bool:
    """Delete a SIEM config by ID. Returns True if found and deleted."""
    r = _get_redis()
    if not r:
        return False

    configs = get_siem_configs(tenant_id)
    updated = [c for c in configs if c.get("siem_id") != siem_id]

    if len(updated) == len(configs):
        return False  # not found

    r.set(_key(tenant_id), json.dumps(updated))
    return True


def update_siem_config(tenant_id: str, siem_id: str, updates: dict) -> dict | None:
    """Update a SIEM config. Returns updated config or None if not found."""
    r = _get_redis()
    if not r:
        return None

    configs = get_siem_configs(tenant_id)
    for cfg in configs:
        if cfg.get("siem_id") == siem_id:
            for k, v in updates.items():
                if k not in ("siem_id", "created_at"):
                    cfg[k] = v
            cfg["updated_at"] = int(time.time())
            r.set(_key(tenant_id), json.dumps(configs))
            return cfg
    return None
