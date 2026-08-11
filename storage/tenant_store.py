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


def kv_get(key: str):
    """Read a JSON value by raw key, Redis-or-fallback.

    Mirrors the Redis-or-in-memory pattern used throughout this module so
    callers (e.g. the agent registry routes) work identically whether or not
    Redis is configured. Returns the decoded value, or None if absent.
    """
    r = _get_redis()
    data = r.get(key) if r else _fallback_store.get(key)
    if data is None:
        return None
    if isinstance(data, (bytes, bytearray)):
        data = data.decode()
    if isinstance(data, str):
        try:
            return json.loads(data)
        except (json.JSONDecodeError, ValueError):
            return data
    return data


def kv_set(key: str, value, ttl: Optional[int] = None) -> None:
    """Write a JSON value by raw key, Redis-or-fallback.

    Lets registry/policy writes succeed in local dev with no Redis instead of
    raising "Redis connection not available". The in-memory fallback holds the
    JSON string, matching how RBACGuard reads it back.

    ttl is seconds, and is a best-effort reclaim hint for Redis only — the
    in-memory fallback has no expiry at all. Anything whose correctness depends
    on expiring must ALSO carry its own deadline in the value and check it on
    read, or a Redis-less deployment keeps it forever. API key metadata does
    both.
    """
    payload = json.dumps(value)
    r = _get_redis()
    if r:
        if ttl and ttl > 0:
            try:
                r.setex(key, int(ttl), payload)
                return
            except Exception:
                # Upstash REST and older clients may not expose setex. The
                # value's own deadline still governs correctness.
                logger.debug("setex unavailable for %s, falling back to set", key)
        r.set(key, payload)
    else:
        _fallback_store[key] = payload


def kv_delete(key: str) -> None:
    """Delete a raw key, Redis-or-fallback."""
    r = _get_redis()
    if r:
        r.delete(key)
    else:
        _fallback_store.pop(key, None)


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
        # A cache MISS, and only here. Redis has already been reached, so the
        # marginal cost is one metadata read plus at most one write, bounded by
        # the 60-second cache to once per key per process per minute however
        # much traffic the key carries. A cache HIT above returns without
        # touching any of this — which is the overwhelming majority of guarded
        # requests, and the reason this is affordable at all.
        meta = key_metadata_by_hash(key_hash)
        if meta:
            # Redis TTL does the expiring where Redis exists; this covers the
            # in-memory fallback, which has no TTL, and a Redis whose expire()
            # call failed at mint time. Without it a Redis-less deployment
            # would honour an expired key forever.
            expires_at = meta.get("expires_at")
            if isinstance(expires_at, int) and time.time() >= expires_at:
                return None
            _record_last_used(key_hash)

        _cache_set(cache_key, {"tenant_id": tenant_id})
        return tenant_id
    return None


def resolve_request_tenant_id(request) -> str:
    """Best-effort tenant_id for a request.

    Prefers the value the auth middleware put on ``request.state``; otherwise
    falls back to the ``X-Tenant-ID`` header, then resolves the ``X-API-Key``
    directly. Some deployments (e.g. a data plane behind an auth proxy) don't
    run the middleware that populates ``request.state.tenant_id`` for the
    guardrail endpoints, so without this fallback those requests resolve no
    tenant and their guardrail metrics are silently dropped. Mirrors the
    fallback already used by the tool-check route. Returns "" if unresolved.
    """
    tid = (getattr(request.state, "tenant_id", None) if hasattr(request, "state") else None) or ""
    if tid:
        return tid
    tid = request.headers.get("X-Tenant-ID") or request.headers.get("x-tenant-id") or ""
    if tid:
        return tid
    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        try:
            tid = resolve_tenant_by_api_key(api_key) or ""
            if not tid and api_key.startswith("sk-test-"):
                tid = "test-tenant-001"  # shared sandbox tenant
        except Exception:
            tid = ""
    return tid


# ---------------------------------------------------------------------------
# API key scopes
#
# A key resolves to a tenant and nothing else, which means the credential an
# agent uses to be guarded is also the credential that can rewrite the agent
# registry. Scope splits those: `runtime` for the guard path, `admin` for
# registry writes.
#
# Stored in a SIDECAR key rather than inside the apikey:* value on purpose.
# Putting it in the value would place a scope read inside
# resolve_tenant_by_api_key(), which every guarded request calls — a new Redis
# read on the hot path. The sidecar is read only by write routes, so the guard
# path is untouched by construction rather than by review. It also means no
# migration: an absent record is a legacy unscoped key, which is every key that
# exists today.
#
# See docs/spec-registry-write-authorization.md
# ---------------------------------------------------------------------------

SCOPE_RUNTIME = "runtime"
SCOPE_ADMIN = "admin"
KEY_SCOPES = (SCOPE_RUNTIME, SCOPE_ADMIN)


def _scope_key(key_hash: str) -> str:
    return f"apikeyscope:{key_hash}"


def set_key_scope(api_key: str, scope: Optional[str]) -> None:
    """Set (or clear, with None) a key's scope.

    Raises ValueError for an unknown scope. Storage must not depend on the web
    framework; the minting route translates this to a 400.
    """
    if scope is not None and scope not in KEY_SCOPES:
        raise ValueError(
            f"scope must be one of {', '.join(KEY_SCOPES)}, or omitted")

    key_hash = _hash_key(api_key)
    k = _scope_key(key_hash)
    r = _get_redis()
    if scope is None:
        if r:
            r.delete(k)
        else:
            _fallback_store.pop(k, None)
    else:
        if r:
            r.set(k, scope)
        else:
            _fallback_store[k] = scope

    # Invalidate BOTH ways. A downgrade from admin to runtime that a stale
    # cache ignores is a control that silently does not apply, which is worse
    # than never having set it.
    _cache_delete(k)


def key_scope_by_hash(key_hash: str) -> Optional[str]:
    """A key's scope from its hash, or None when unscoped.

    A stored value that is neither runtime nor admin reads as unscoped rather
    than as admin: garbage must never read as privilege.
    """
    if not key_hash:
        return None
    k = _scope_key(key_hash)

    cached = _cache_get(k)
    if cached is not None:
        return cached.get("scope")

    r = _get_redis()
    scope = r.get(k) if r else _fallback_store.get(k)
    if isinstance(scope, bytes):
        scope = scope.decode()
    if scope not in KEY_SCOPES:
        scope = None

    _cache_set(k, {"scope": scope})
    return scope


def key_scope(api_key: str) -> Optional[str]:
    """A key's scope from the plaintext key, or None when unscoped."""
    return key_scope_by_hash(_hash_key(api_key)) if api_key else None


# ---------------------------------------------------------------------------
# API key lifecycle
#
# A key was a bare hash → tenant mapping: no creation date, no label, no
# expiry, no last-used, and no way to enumerate a tenant's keys. Rotation was
# mechanically possible and operationally impossible, because nobody could see
# what existed or tell whether the old key was still carrying traffic.
#
# A SIDECAR again, for the same reason as scopes: apikey:{hash} keeps holding a
# bare tenant id, so resolve_tenant_by_api_key — which runs on every guarded
# request — is unchanged and there is no migration. Absent metadata is legal
# and permanent; it describes every key that exists today.
#
# See docs/spec-api-key-lifecycle.md
# ---------------------------------------------------------------------------

_META_PREFIX = "apikeymeta:"

# How much of a key to keep so a human can tell rows apart. Enough to recognise
# a key you are holding, not enough to reconstruct one.
_KEY_PREFIX_LEN = 12


def _meta_key(key_hash: str) -> str:
    return f"{_META_PREFIX}{key_hash}"


def track_usage_enabled() -> bool:
    """Whether to record last_used. On by default; see set_key_metadata."""
    return os.environ.get("SHIELD_API_KEY_TRACK_USAGE", "1").strip().lower() \
        not in ("0", "false", "no", "off")


def set_key_metadata(tenant_id: str, api_key: str, *, label: str = "",
                     expires_in_days: Optional[int] = None) -> dict:
    """Record who this key is for and when it should stop working.

    Raises ValueError for a non-positive expiry: a key that expires in the past
    is a key that never worked, and finding that out from a 401 an hour later
    is worse than a 400 now.
    """
    if expires_in_days is not None:
        if not isinstance(expires_in_days, int) or isinstance(expires_in_days, bool):
            raise ValueError("expires_in_days must be an integer")
        if expires_in_days <= 0:
            raise ValueError("expires_in_days must be greater than zero")

    now = int(time.time())
    expires_at = now + expires_in_days * 86400 if expires_in_days else None
    record = {
        "tenant_id": tenant_id,
        "label": str(label or "")[:128],
        # Prefix only. A list of bare hashes cannot be acted on, and a full key
        # in a listing would hand back the credential.
        "prefix": str(api_key or "")[:_KEY_PREFIX_LEN],
        "created_at": now,
        "expires_at": expires_at,
        "last_used": None,
    }
    key_hash = _hash_key(api_key)
    # TTL slightly beyond the deadline so the record survives long enough to
    # explain an expiry rather than vanishing with the key it describes.
    kv_set(_meta_key(key_hash), record,
           ttl=(expires_in_days * 86400 + 86400) if expires_in_days else None)

    # And a TTL on the credential itself. Redis then does the expiring, so the
    # guard-path lookup is byte-identical — no deadline check, no extra read.
    if expires_at:
        r = _get_redis()
        if r:
            try:
                r.expire(f"apikey:{key_hash}", expires_in_days * 86400)
            except Exception:
                # The in-memory fallback has no TTL either way; the expires_at
                # check in resolve_tenant_by_api_key is what covers both.
                logger.debug("could not set TTL on apikey:%s", key_hash[:8])
    return record


def key_metadata_by_hash(key_hash: str) -> Optional[dict]:
    """Metadata for a key hash, or None. Absent is normal, not an error."""
    if not key_hash:
        return None
    record = kv_get(_meta_key(key_hash))
    return record if isinstance(record, dict) else None


def key_metadata(api_key: str) -> Optional[dict]:
    return key_metadata_by_hash(_hash_key(api_key)) if api_key else None


def _record_last_used(key_hash: str) -> None:
    """Stamp last_used. Called ONLY from a cache miss.

    The 60-second resolution cache bounds this: at most one write per key per
    process per minute however much traffic the key carries. Writing it per
    request would put a Redis write on /guardrails/*, which is the bottleneck
    the throughput work already identified — that version is a non-option, not
    a slower alternative.

    Best effort throughout. Losing a timestamp must never fail a guarded
    request.
    """
    if not track_usage_enabled():
        return
    try:
        record = key_metadata_by_hash(key_hash)
        if not record:
            return          # a key minted before this existed; nothing to stamp
        record["last_used"] = int(time.time())
        expires_at = record.get("expires_at")
        ttl = (expires_at - int(time.time()) + 86400) if expires_at else None
        if ttl is not None and ttl <= 0:
            return
        kv_set(_meta_key(key_hash), record, ttl=ttl)
    except Exception as e:
        logger.debug("last_used not recorded: %s", e)


def list_tenant_api_keys(tenant_id: str) -> list:
    """Every key recorded for a tenant, newest first.

    Never returns a plaintext key or a full hash. Keys minted before metadata
    existed do not appear — they cannot, since nothing recorded them — which is
    stated in the docs rather than papered over with a scan of apikey:*.
    """
    if not tenant_id:
        return []
    out = []
    try:
        r = _get_redis()
        if r:
            cursor, seen = 0, []
            while True:
                cursor, keys = r.scan(cursor, match=f"{_META_PREFIX}*", count=200)
                seen.extend(keys)
                if cursor == 0:
                    break
            records = [(k, kv_get(k)) for k in seen]
        else:
            records = [(k, kv_get(k)) for k in list(_fallback_store)
                       if k.startswith(_META_PREFIX)]
    except Exception as e:
        logger.warning("could not list API keys for %s: %s", tenant_id, e)
        return []

    for k, record in records:
        if not isinstance(record, dict) or record.get("tenant_id") != tenant_id:
            continue
        key_hash = k[len(_META_PREFIX):]
        out.append({
            "label": record.get("label", ""),
            "prefix": record.get("prefix", ""),
            # A short fingerprint matches a row to a key without being one.
            "fingerprint": key_hash[:8],
            "scope": key_scope_by_hash(key_hash),
            "created_at": record.get("created_at"),
            "expires_at": record.get("expires_at"),
            "last_used": record.get("last_used"),
        })
    out.sort(key=lambda e: e.get("created_at") or 0, reverse=True)
    return out


def add_api_key(tenant_id: str, api_key: str, scope: Optional[str] = None,
                *, label: str = "", expires_in_days: Optional[int] = None):
    """Add an API key for a tenant.

    scope=None keeps the pre-existing behaviour exactly: an unscoped key that
    every code path treats as it did before scopes existed.
    """
    key_hash = _hash_key(api_key)

    r = _get_redis()
    if r:
        r.set(f"apikey:{key_hash}", tenant_id)
    else:
        _fallback_store[f"apikey:{key_hash}"] = tenant_id

    # Set unconditionally, including the None case: minting over a hash that
    # already carried a scope must not silently inherit the old one.
    set_key_scope(api_key, scope)
    set_key_metadata(tenant_id, api_key, label=label,
                     expires_in_days=expires_in_days)

    logger.info(f"Added API key for tenant: {tenant_id} (scope={scope or 'unscoped'})")


def remove_api_key(api_key: str):
    """Remove an API key and any scope recorded for it."""
    key_hash = _hash_key(api_key)

    r = _get_redis()
    if r:
        r.delete(f"apikey:{key_hash}")
        r.delete(_scope_key(key_hash))
        r.delete(_meta_key(key_hash))
    else:
        _fallback_store.pop(f"apikey:{key_hash}", None)
        _fallback_store.pop(_scope_key(key_hash), None)
        _fallback_store.pop(_meta_key(key_hash), None)

    # Metadata goes with the key. Listing credentials that no longer exist is
    # worse than not listing them at all.
    _cache_delete(f"apikey:{key_hash}")
    _cache_delete(_scope_key(key_hash))


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
