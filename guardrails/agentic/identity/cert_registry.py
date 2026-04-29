"""Certificate registry — maps cert fingerprints to agent identities.

Stores cert-to-agent mappings and trust metadata in Redis per tenant.

Redis keys:
    cert_registry:{tenant_id}                    → HASH fingerprint → agent_key
    agent_trust:{tenant_id}:{agent_key}          → JSON trust metadata
"""

import json
import logging
import time
from typing import Optional

from storage.tenant_store import _get_redis, _fallback_store

logger = logging.getLogger("votal.cert_registry")

# Trust levels: cert > string_key > anonymous
TRUST_LEVELS = {
    "high": 3,
    "medium": 2,
    "low": 1,
}

DEFAULT_TRUST_BY_METHOD = {
    "cert": "high",
    "string_key": "medium",
    "anonymous": "low",
}


def register_cert(tenant_id: str, agent_key: str, fingerprint: str) -> dict:
    """Register a certificate fingerprint for an agent.

    Args:
        tenant_id: Tenant identifier
        agent_key: Agent identifier to bind to
        fingerprint: SHA-256 fingerprint of the client certificate

    Returns:
        Trust metadata record.
    """
    registry_key = f"cert_registry:{tenant_id}"
    trust_key = f"agent_trust:{tenant_id}:{agent_key}"

    trust_record = {
        "agent_key": agent_key,
        "fingerprint": fingerprint,
        "identity_method": "cert",
        "trust_level": "high",
        "registered_at": int(time.time()),
    }

    r = _get_redis()
    if r:
        r.hset(registry_key, fingerprint, agent_key)
        r.set(trust_key, json.dumps(trust_record))
    else:
        # Fallback store
        existing = _fallback_store.get(registry_key, "{}")
        registry = json.loads(existing)
        registry[fingerprint] = agent_key
        _fallback_store[registry_key] = json.dumps(registry)
        _fallback_store[trust_key] = json.dumps(trust_record)

    logger.info(f"Cert registered: tenant={tenant_id} agent={agent_key} fingerprint={fingerprint[:16]}...")
    return trust_record


def resolve_agent_by_cert(tenant_id: str, fingerprint: str) -> Optional[str]:
    """Resolve a certificate fingerprint to an agent_key.

    Args:
        tenant_id: Tenant identifier
        fingerprint: SHA-256 fingerprint from X-Client-Cert-Fingerprint header

    Returns:
        agent_key if found, None otherwise.
    """
    registry_key = f"cert_registry:{tenant_id}"

    r = _get_redis()
    if r:
        agent_key = r.hget(registry_key, fingerprint)
        if agent_key:
            if isinstance(agent_key, bytes):
                agent_key = agent_key.decode()
            return agent_key
    else:
        existing = _fallback_store.get(registry_key, "{}")
        registry = json.loads(existing)
        return registry.get(fingerprint)

    return None


def revoke_cert(tenant_id: str, agent_key: str) -> bool:
    """Revoke a certificate for an agent (removes fingerprint mapping).

    Returns:
        True if cert was found and revoked.
    """
    registry_key = f"cert_registry:{tenant_id}"
    trust_key = f"agent_trust:{tenant_id}:{agent_key}"

    # Find fingerprint for this agent
    r = _get_redis()
    if r:
        all_mappings = r.hgetall(registry_key)
        revoked = False
        for fp, ak in all_mappings.items():
            if isinstance(fp, bytes):
                fp = fp.decode()
            if isinstance(ak, bytes):
                ak = ak.decode()
            if ak == agent_key:
                r.hdel(registry_key, fp)
                revoked = True
        r.delete(trust_key)
        # Set trust back to string_key level
        r.set(trust_key, json.dumps({
            "agent_key": agent_key,
            "identity_method": "string_key",
            "trust_level": "medium",
            "registered_at": int(time.time()),
        }))
        return revoked
    else:
        existing = _fallback_store.get(registry_key, "{}")
        registry = json.loads(existing)
        revoked = False
        to_remove = [fp for fp, ak in registry.items() if ak == agent_key]
        for fp in to_remove:
            del registry[fp]
            revoked = True
        _fallback_store[registry_key] = json.dumps(registry)
        _fallback_store[trust_key] = json.dumps({
            "agent_key": agent_key,
            "identity_method": "string_key",
            "trust_level": "medium",
            "registered_at": int(time.time()),
        })
        return revoked


def get_agent_trust(tenant_id: str, agent_key: str) -> dict:
    """Get trust metadata for an agent.

    Returns:
        Trust record with trust_level and identity_method.
        Defaults to string_key/medium if no record exists.
    """
    trust_key = f"agent_trust:{tenant_id}:{agent_key}"

    r = _get_redis()
    if r:
        data = r.get(trust_key)
        if data:
            if isinstance(data, bytes):
                data = data.decode()
            return json.loads(data)
    else:
        data = _fallback_store.get(trust_key)
        if data:
            return json.loads(data)

    # Default: string_key / medium
    return {
        "agent_key": agent_key,
        "identity_method": "string_key",
        "trust_level": "medium",
    }


def get_trust_level_value(trust_level: str) -> int:
    """Convert trust level name to numeric value for comparison."""
    return TRUST_LEVELS.get(trust_level, 0)
