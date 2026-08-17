"""JWKS (JSON Web Key Set) cache for external OIDC providers.

Fetches and caches JWKS from external IdPs with automatic refresh.
Uses in-memory cache with Redis fallback for multi-worker deployments.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger("votal.jwks_cache")

# In-memory cache: {issuer_hash: {"keys": [...], "fetched_at": int}}
_cache: dict[str, dict] = {}
_CACHE_TTL_SECONDS = 3600  # 1 hour
_REFRESH_AHEAD_SECONDS = 600  # refresh at 50 minutes


def _issuer_hash(issuer: str) -> str:
    return hashlib.sha256(issuer.encode()).hexdigest()[:16]


async def fetch_jwks(jwks_uri: str) -> dict:
    """Fetch JWKS from a remote URI.

    verify= explicitly, for the same reason as discovery: httpx trusts the
    bundled certifi CAs rather than the system store, so an on-prem IdP signed
    by a private CA fails here. Both outbound calls in this package have to
    honour SHIELD_OIDC_CA_BUNDLE, or fixing one just moves the failure.
    """
    from core.oauth.tls_trust import httpx_verify
    async with httpx.AsyncClient(timeout=10.0, verify=httpx_verify()) as client:
        resp = await client.get(jwks_uri)
        resp.raise_for_status()
        return resp.json()


async def get_jwks(
    issuer: str,
    jwks_uri: str,
    *,
    force_refresh: bool = False,
) -> dict:
    """Get JWKS for an issuer, using cache when possible.

    Args:
        issuer: The OIDC issuer URL (used as cache key).
        jwks_uri: The JWKS endpoint URL.
        force_refresh: If True, bypass cache and fetch fresh keys.

    Returns:
        The JWKS dict with a "keys" array.
    """
    key = _issuer_hash(issuer)
    now = int(time.time())

    if not force_refresh and key in _cache:
        entry = _cache[key]
        age = now - entry["fetched_at"]
        if age < _CACHE_TTL_SECONDS:
            return entry["jwks"]

    # Fetch fresh JWKS
    try:
        jwks = await fetch_jwks(jwks_uri)
        _cache[key] = {"jwks": jwks, "fetched_at": now}
        logger.debug(f"JWKS refreshed for {issuer} ({len(jwks.get('keys', []))} keys)")

        # Also cache to Redis for multi-worker sharing
        _cache_to_redis(key, jwks, now)

        return jwks
    except Exception as e:
        # On fetch failure, use stale cache if available
        if key in _cache:
            logger.warning(f"JWKS refresh failed for {issuer}: {e}; using stale cache")
            return _cache[key]["jwks"]

        # Try Redis fallback
        redis_jwks = _load_from_redis(key)
        if redis_jwks:
            logger.warning(f"JWKS refresh failed for {issuer}: {e}; using Redis cache")
            return redis_jwks

        raise


def _cache_to_redis(key: str, jwks: dict, fetched_at: int) -> None:
    """Best-effort cache to Redis for cross-worker sharing."""
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if r:
            r.set(
                f"shield:jwks_cache:{key}",
                json.dumps({"jwks": jwks, "fetched_at": fetched_at}),
                ex=_CACHE_TTL_SECONDS,
            )
    except Exception:
        pass  # Redis caching is best-effort


def _load_from_redis(key: str) -> Optional[dict]:
    """Try to load JWKS from Redis."""
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if r:
            raw = r.get(f"shield:jwks_cache:{key}")
            if raw:
                data = json.loads(raw)
                return data.get("jwks")
    except Exception:
        pass
    return None


def clear_cache_for_tests() -> None:
    """Clear the in-memory JWKS cache. For tests only."""
    _cache.clear()
