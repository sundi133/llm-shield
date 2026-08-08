"""Per-tenant role-binding configuration: one key, one cache, one read.

`core/identity_resolution.py` supports a per-tenant `role_claim` (a dotted path
into a verified credential's claims) and `role_map` (IdP group name to Shield
role). Keycloak puts realm roles at ``realm_access.roles``; Okta uses
``groups``; Entra ID uses ``roles``. Without per-tenant configuration, role
binding only works against Keycloak.

This module owns the key, the schema and the caching. It exists because the
previous arrangement issued **two** Redis GETs on the same key per guarded
request — one cached read for the mode, one uncached read for the claim path
(the old `role_binding_config`). That was tolerable only while the config was
unreachable and the second read was effectively dead code. Making it live
without fixing the caching would have put a synchronous Redis round trip on
`/guardrails/*` and `cap/mint` for every request.

Contract:

  * One Redis GET per tenant per ``_CACHE_TTL_S``, whole config, not per field.
  * Misses are cached too. A tenant with no stored config is the common case,
    and re-reading an absent key every request is the same round trip.
  * A store that is unreachable resolves to "no stored config" rather than
    raising. The failure mode of "cannot read config" must not be "deny every
    tenant" — see the fail-open note in `role_binding_mode`.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

logger = logging.getLogger("votal.role_binding_config")

KEY_PREFIX = "shield:role_binding:"


_CACHE_TTL_S = 30

#: tenant_id -> (config_or_None, cached_at)
_CACHE: dict = {}


def key_for(tenant_id: str) -> str:
    return f"{KEY_PREFIX}{tenant_id}"


def clear_cache_for_tests() -> None:
    _CACHE.clear()


def _load(tenant_id: str) -> Optional[dict]:
    """Read and parse the stored config. None when absent or unreadable.

    Goes through ``tenant_store.kv_get`` rather than talking to Redis directly,
    so reads and writes agree about where the value lives. ``kv_get``/``kv_set``
    fall back to an in-memory store when Redis is not configured; a reader that
    bypassed that would never see a write made in a Redis-less environment, and
    the config would appear to save and then do nothing.
    """
    try:
        from storage.tenant_store import kv_get
        stored = kv_get(key_for(tenant_id))
        # kv_get returns the raw string when the value is not valid JSON, and
        # whatever type it decoded to otherwise. Only an object is a config.
        return stored if isinstance(stored, dict) else None
    except Exception as e:
        # Deliberately not re-raised. This runs on the guard path; a malformed
        # value or a Redis blip must degrade to the env default, not 500 a
        # request that would otherwise have been decided correctly.
        logger.debug("role_binding config unreadable for %r: %s", tenant_id, e)
        return None


#: Modes ordered weakest to strongest. Used to stop a tenant self-service write
#: from downgrading a deployment-wide baseline: an operator who sets
#: SHIELD_ROLE_BINDING=strict has made a security decision, and a tenant able to
#: store "off" over it would quietly undo that decision for their own traffic.
MODE_STRENGTH = {"off": 0, "prefer": 1, "strict_proxy": 2, "strict": 3}


def set_config(tenant_id: str, cfg: dict) -> dict:
    """Persist config for a tenant and drop the local cache entry.

    Raises on a write failure rather than returning quietly: a config that
    looks saved and is not is worse than an error, because the operator moves
    on believing role binding is configured.

    NOTE: the cache drop is process-local. Other replicas keep their cached
    copy for up to ``_CACHE_TTL_S``, so a change takes effect fleet-wide within
    that window. Callers should say so rather than implying it is instant.
    """
    from storage.tenant_store import kv_set
    kv_set(key_for(tenant_id), cfg)
    _CACHE.pop(tenant_id, None)
    return cfg


def get_config(tenant_id: Optional[str]) -> Optional[dict]:
    """Stored config for a tenant, or None if there is none.

    Cached for ``_CACHE_TTL_S``, including negative results, so the common case
    (no stored config) costs one Redis GET per tenant per TTL rather than one
    per request.
    """
    if not tenant_id:
        return None

    now = time.time()
    hit = _CACHE.get(tenant_id)
    if hit is not None and now - hit[1] < _CACHE_TTL_S:
        return hit[0]

    cfg = _load(tenant_id)
    _CACHE[tenant_id] = (cfg, now)
    return cfg
