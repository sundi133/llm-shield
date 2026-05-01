"""Per-tenant configuration store backed by Redis.

Stores tenant guardrail policies, API keys, and RBAC configs in Redis.
Falls back to in-memory dict when Redis is unavailable (dev/testing).

Redis keys:
    tenant:{tenant_id}     → JSON tenant config
    apikey:{sha256_hash}   → tenant_id
    tenants:index          → SET of all tenant IDs
"""

import hashlib
import json
import logging
import os
import time
from typing import Optional

logger = logging.getLogger("votal.tenant_store")

# In-memory cache with TTL to avoid hitting Redis on every request
_cache: dict[str, tuple[dict, float]] = {}  # key → (value, expires_at)
_CACHE_TTL = int(os.environ.get("TENANT_CACHE_TTL", "60"))  # seconds

# Redis connection (lazy init)
_redis = None
_redis_available = False
_fallback_store: dict[str, str] = {}  # in-memory fallback


def _get_redis():
    """Lazy-init Redis connection.

    Priority:
    1. Upstash REST API (UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN)
       — preferred for serverless / RunPod
    2. Standard Redis TCP (REDIS_URL)
       — for on-prem docker-compose or self-hosted Redis
    3. In-memory fallback (dev/testing only)
    """
    global _redis, _redis_available
    if _redis is not None:
        return _redis

    # Try Upstash REST first (serverless-friendly, no persistent TCP)
    upstash_url = os.environ.get("UPSTASH_REDIS_REST_URL", "").strip()
    upstash_token = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "").strip()
    if upstash_url and upstash_token:
        # Validate URL protocol — Upstash REST requires https://
        if not upstash_url.startswith(("http://", "https://")):
            logger.warning(
                f"UPSTASH_REDIS_REST_URL has invalid protocol: {upstash_url[:20]}... "
                "(must start with https://). Skipping Upstash, trying REDIS_URL."
            )
        else:
            try:
                from upstash_redis import Redis as UpstashRedis
                client = UpstashRedis(url=upstash_url, token=upstash_token)
                # Sanity check — must assign to local first, set global only on success
                client.set("_votal:healthcheck", "ok")
                _redis = client
                _redis_available = True
                logger.info(f"Tenant store connected to Upstash REST: {upstash_url}")
                return _redis
            except Exception as e:
                logger.warning(f"Upstash REST unavailable ({e}), trying REDIS_URL fallback")
                _redis = None  # ensure we don't cache a broken client

    # Fall back to standard Redis TCP
    redis_url = os.environ.get("REDIS_URL", "")
    if not redis_url:
        logger.info("No Redis configured (neither UPSTASH_REDIS_REST_URL nor REDIS_URL), using in-memory tenant store")
        _redis_available = False
        return None

    try:
        import redis as redis_lib
        _redis = redis_lib.Redis.from_url(redis_url, decode_responses=True)
        _redis.ping()
        _redis_available = True
        logger.info(f"Tenant store connected to Redis (TCP): {redis_url.split('@')[-1] if '@' in redis_url else redis_url}")
        return _redis
    except Exception as e:
        logger.warning(f"Redis unavailable ({e}), using in-memory fallback")
        _redis_available = False
        return None


def _cache_get(key: str) -> Optional[dict]:
    """Get from in-memory cache if not expired."""
    if key in _cache:
        value, expires_at = _cache[key]
        if time.time() < expires_at:
            return value
        del _cache[key]
    return None


def _cache_set(key: str, value: dict):
    """Set in-memory cache with TTL."""
    _cache[key] = (value, time.time() + _CACHE_TTL)


def _cache_delete(key: str):
    """Remove from cache."""
    _cache.pop(key, None)


def _hash_key(api_key: str) -> str:
    """SHA-256 hash an API key for storage."""
    return hashlib.sha256(api_key.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_tenant(tenant_id: str, config: dict, api_keys: list[str] = None) -> dict:
    """Create a new tenant with guardrail config and API keys.

    Args:
        tenant_id: Unique tenant identifier (e.g., "acme", "globex")
        config: Tenant configuration dict containing:
            - name: Display name
            - plan: Subscription plan
            - input_guardrails: Per-guardrail settings for input stage
            - output_guardrails: Per-guardrail settings for output stage
            - rbac: Roles and agent mappings
        api_keys: List of plaintext API keys for this tenant

    Returns:
        The stored tenant config.
    """
    config.setdefault("tenant_id", tenant_id)
    config_json = json.dumps(config)

    r = _get_redis()
    if r:
        r.set(f"tenant:{tenant_id}", config_json)
        r.sadd("tenants:index", tenant_id)
        # Map API keys to tenant
        for key in (api_keys or []):
            key_hash = _hash_key(key)
            r.set(f"apikey:{key_hash}", tenant_id)
    else:
        _fallback_store[f"tenant:{tenant_id}"] = config_json
        for key in (api_keys or []):
            key_hash = _hash_key(key)
            _fallback_store[f"apikey:{key_hash}"] = tenant_id

    _cache_set(f"tenant:{tenant_id}", config)
    logger.info(f"Created tenant: {tenant_id}")
    return config


def get_tenant(tenant_id: str, include_deleted: bool = False) -> Optional[dict]:
    """Get tenant config by tenant ID.

    Args:
        tenant_id: Tenant identifier
        include_deleted: If False (default), returns None for soft-deleted tenants
    """
    # Check cache first
    cached = _cache_get(f"tenant:{tenant_id}")
    if cached:
        if not include_deleted and cached.get("deleted_at"):
            return None
        return cached

    r = _get_redis()
    if r:
        data = r.get(f"tenant:{tenant_id}")
    else:
        data = _fallback_store.get(f"tenant:{tenant_id}")

    if not data:
        return None

    config = json.loads(data)
    _cache_set(f"tenant:{tenant_id}", config)

    if not include_deleted and config.get("deleted_at"):
        return None
    return config


def update_tenant(tenant_id: str, updates: dict) -> Optional[dict]:
    """Update a tenant's config (merge, not replace).

    Args:
        tenant_id: Tenant to update
        updates: Fields to merge into existing config

    Returns:
        Updated config, or None if tenant not found.
    """
    config = get_tenant(tenant_id)
    if config is None:
        return None
    updates = dict(updates)

    # Deep merge guardrail configs
    for section in ("input_guardrails", "output_guardrails", "rbac"):
        if section in updates and section in config:
            if isinstance(config[section], dict) and isinstance(updates[section], dict):
                config[section].update(updates[section])
                updates.pop(section)

    config.update(updates)
    config_json = json.dumps(config)

    r = _get_redis()
    if r:
        r.set(f"tenant:{tenant_id}", config_json)
    else:
        _fallback_store[f"tenant:{tenant_id}"] = config_json

    _cache_set(f"tenant:{tenant_id}", config)
    _cache_delete(f"tenant:{tenant_id}")
    logger.info(f"Updated tenant: {tenant_id}")
    return config


def set_tenant_policies(
    tenant_id: str,
    input_guardrails: dict = None,
    output_guardrails: dict = None,
) -> Optional[dict]:
    """Replace guardrail policy sections entirely (full replace, not merge).

    Unlike update_tenant which merges dicts, this replaces the entire
    input_guardrails / output_guardrails section so that removed
    guardrails are actually deleted from the config.
    """
    config = get_tenant(tenant_id)
    if config is None:
        return None

    if input_guardrails is not None:
        config["input_guardrails"] = input_guardrails
    if output_guardrails is not None:
        config["output_guardrails"] = output_guardrails

    config_json = json.dumps(config)

    r = _get_redis()
    if r:
        r.set(f"tenant:{tenant_id}", config_json)
    else:
        _fallback_store[f"tenant:{tenant_id}"] = config_json

    _cache_delete(f"tenant:{tenant_id}")
    logger.info(f"Replaced policies for tenant: {tenant_id}")
    return config


def delete_tenant(tenant_id: str, soft: bool = True) -> bool:
    """Delete a tenant.

    Args:
        tenant_id: Tenant identifier
        soft: If True (default), mark as deleted_at; if False, hard delete
    """
    if soft:
        from datetime import datetime, timezone
        config = get_tenant(tenant_id, include_deleted=True)
        if config is None:
            return False

        config["deleted_at"] = datetime.now(timezone.utc).isoformat()
        config_json = json.dumps(config)

        r = _get_redis()
        if r:
            r.set(f"tenant:{tenant_id}", config_json)
            # Revoke API keys by deleting apikey:* mappings
            cursor = 0
            while True:
                cursor, keys = r.scan(cursor, match="apikey:*", count=100)
                for key in keys:
                    if r.get(key) == tenant_id:
                        r.delete(key)
                if cursor == 0:
                    break
        else:
            _fallback_store[f"tenant:{tenant_id}"] = config_json
            to_remove = [k for k, v in _fallback_store.items()
                         if k.startswith("apikey:") and v == tenant_id]
            for k in to_remove:
                del _fallback_store[k]

        _cache_delete(f"tenant:{tenant_id}")
        logger.info(f"Soft-deleted tenant: {tenant_id}")
        return True

    # Hard delete
    r = _get_redis()
    if r:
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match="apikey:*", count=100)
            for key in keys:
                if r.get(key) == tenant_id:
                    r.delete(key)
            if cursor == 0:
                break
        r.delete(f"tenant:{tenant_id}")
        r.srem("tenants:index", tenant_id)
    else:
        _fallback_store.pop(f"tenant:{tenant_id}", None)
        to_remove = [k for k, v in _fallback_store.items()
                     if k.startswith("apikey:") and v == tenant_id]
        for k in to_remove:
            del _fallback_store[k]

    _cache_delete(f"tenant:{tenant_id}")
    logger.info(f"Hard-deleted tenant: {tenant_id}")
    return True


def list_tenants(include_deleted: bool = False) -> list[dict]:
    """List all tenants (summary only, no secrets)."""
    r = _get_redis()
    if r:
        tenant_ids = r.smembers("tenants:index")
    else:
        tenant_ids = {k.split(":", 1)[1] for k in _fallback_store
                      if k.startswith("tenant:")}

    tenants = []
    for tid in sorted(tenant_ids):
        config = get_tenant(tid, include_deleted=include_deleted)
        if config:
            tenants.append({
                "tenant_id": tid,
                "name": config.get("name", ""),
                "plan": config.get("plan", ""),
                "input_guardrails": list(config.get("input_guardrails", {}).keys()),
                "output_guardrails": list(config.get("output_guardrails", {}).keys()),
                "agent_count": len(config.get("rbac", {}).get("agents", {})),
                "deleted_at": config.get("deleted_at"),
            })
    return tenants


def resolve_tenant_by_api_key(api_key: str) -> Optional[str]:
    """Resolve an API key to a tenant ID.

    Args:
        api_key: Plaintext API key from the request

    Returns:
        tenant_id if found, None otherwise.
    """
    key_hash = _hash_key(api_key)
    cache_key = f"apikey:{key_hash}"

    # Check cache
    cached = _cache_get(cache_key)
    if cached:
        return cached.get("tenant_id")

    r = _get_redis()
    if r:
        tenant_id = r.get(f"apikey:{key_hash}")
    else:
        tenant_id = _fallback_store.get(f"apikey:{key_hash}")

    if tenant_id:
        _cache_set(cache_key, {"tenant_id": tenant_id})
        return tenant_id
    return None


def add_api_key(tenant_id: str, api_key: str):
    """Add an API key for a tenant."""
    key_hash = _hash_key(api_key)

    r = _get_redis()
    if r:
        r.set(f"apikey:{key_hash}", tenant_id)
    else:
        _fallback_store[f"apikey:{key_hash}"] = tenant_id

    logger.info(f"Added API key for tenant: {tenant_id}")


def remove_api_key(api_key: str):
    """Remove an API key."""
    key_hash = _hash_key(api_key)

    r = _get_redis()
    if r:
        r.delete(f"apikey:{key_hash}")
    else:
        _fallback_store.pop(f"apikey:{key_hash}", None)

    _cache_delete(f"apikey:{key_hash}")


# ============================================================================
# Tenant Hierarchy (Cross-Tenant Policy Inheritance)
# ============================================================================


def set_tenant_parent(tenant_id: str, parent_tenant_id: str) -> bool:
    """Set parent tenant for policy inheritance.

    Args:
        tenant_id: Child tenant identifier
        parent_tenant_id: Parent tenant identifier

    Returns:
        True if set successfully.
    """
    # Prevent self-reference
    if tenant_id == parent_tenant_id:
        return False

    # Prevent circular dependency
    if _would_create_cycle(tenant_id, parent_tenant_id):
        return False

    key = f"tenant_hierarchy:{tenant_id}"

    r = _get_redis()
    if r:
        r.set(key, parent_tenant_id)
    else:
        _fallback_store[key] = parent_tenant_id

    logger.info(f"Set tenant parent: {tenant_id} → {parent_tenant_id}")
    return True


def get_tenant_parent(tenant_id: str) -> Optional[str]:
    """Get parent tenant ID for inheritance.

    Returns:
        Parent tenant ID, or None if no parent.
    """
    key = f"tenant_hierarchy:{tenant_id}"

    r = _get_redis()
    if r:
        data = r.get(key)
        if isinstance(data, bytes):
            data = data.decode()
    else:
        data = _fallback_store.get(key)

    return data if data else None


def clear_tenant_parent(tenant_id: str) -> bool:
    """Remove parent tenant relationship.

    Returns:
        True if a parent was removed, False if no parent existed.
    """
    key = f"tenant_hierarchy:{tenant_id}"

    r = _get_redis()
    if r:
        existed = r.exists(key)
        r.delete(key)
        return bool(existed)
    else:
        existed = key in _fallback_store
        _fallback_store.pop(key, None)
        return existed


def _would_create_cycle(child_id: str, proposed_parent_id: str) -> bool:
    """Check if setting proposed_parent_id as parent of child_id would create a cycle.

    Walks up the ancestry chain from proposed_parent_id; if we ever reach child_id,
    that's a cycle.
    """
    visited = set()
    current = proposed_parent_id
    while current:
        if current == child_id:
            return True
        if current in visited:
            return False  # Already a cycle in the data, but not involving us
        visited.add(current)
        current = get_tenant_parent(current)
    return False


def get_tenant_ancestors(tenant_id: str, max_depth: int = 10) -> list[str]:
    """Get the full ancestor chain for a tenant (immediate parent first).

    Args:
        tenant_id: Starting tenant
        max_depth: Maximum depth to traverse (prevents infinite loops)

    Returns:
        List of ancestor tenant IDs [parent, grandparent, ...].
    """
    ancestors = []
    current = tenant_id
    for _ in range(max_depth):
        parent = get_tenant_parent(current)
        if not parent:
            break
        ancestors.append(parent)
        current = parent
    return ancestors
