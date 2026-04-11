"""Shield middleware for enriching requests with agent/tenant context and rate limiting."""

import time
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from core.rbac import enforcer
from storage.tenant_store import resolve_tenant_by_api_key, get_tenant
from storage.rate_limiter import check_and_increment

# In-memory cache for tenant lookups to reduce Redis hits
_tenant_cache: dict[str, tuple[Optional[str], Optional[dict], float]] = {}
_CACHE_TTL_SECONDS = 60  # Cache tenant data for 1 minute


def _get_cached_tenant(api_key: str) -> tuple[Optional[str], Optional[dict]]:
    """Get tenant data from cache or fetch from Redis if expired."""
    now = time.time()

    # Check cache first
    if api_key in _tenant_cache:
        tenant_id, tenant_config, cache_time = _tenant_cache[api_key]
        if now - cache_time < _CACHE_TTL_SECONDS:
            return tenant_id, tenant_config

    # Cache miss or expired - fetch from Redis
    tenant_id = resolve_tenant_by_api_key(api_key)
    tenant_config = None
    if tenant_id:
        tenant_config = get_tenant(tenant_id)

    # Cache the result
    _tenant_cache[api_key] = (tenant_id, tenant_config, now)

    # Cleanup old entries periodically (simple approach)
    if len(_tenant_cache) > 1000:  # Prevent unbounded growth
        cutoff = now - _CACHE_TTL_SECONDS * 2
        _tenant_cache.clear()  # Simple cleanup - could be more sophisticated

    return tenant_id, tenant_config


class ShieldMiddleware(BaseHTTPMiddleware):
    """Intercepts requests to /v1/shield/* and /v1/tenant/* endpoints.

    1. Resolves agent identity and RBAC role from headers
    2. Resolves tenant from API key (via Redis)
    3. Enforces per-tenant rate limits / quotas
    4. Attaches context to request.state for downstream handlers
    """

    _SKIP_PATHS = {"/health", "/ping", "/docs", "/redoc", "/openapi.json"}
    _GUARDED_PREFIXES = ("/v1/shield", "/v1/tenant", "/v1/agents")
    _GUARDED_EXACT = {"/classify", "/classify_output", "/guardrails/input", "/guardrails/output"}

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Skip enrichment for non-guarded paths
        if path in self._SKIP_PATHS or path.startswith("/v1/admin"):
            return await call_next(request)

        is_guarded = (
            any(path.startswith(p) for p in self._GUARDED_PREFIXES)
            or path in self._GUARDED_EXACT
        )
        if is_guarded:
            # Extract agent key from header or query param
            agent_key = request.headers.get("X-Agent-Key")
            if not agent_key:
                agent_key = request.query_params.get("api_key")

            request.state.agent_key = agent_key

            # Resolve role if agent key is present
            if agent_key:
                role = enforcer.resolve_role(agent_key)
                request.state.role = role
                request.state.role_name = role.name if role else None
            else:
                request.state.role = None
                request.state.role_name = None

            # Resolve tenant from API key with caching
            request.state.tenant_id = None
            request.state.tenant_config = None
            api_key = _extract_api_key(request)
            if api_key:
                tenant_id, tenant_config = _get_cached_tenant(api_key)
                if tenant_id and tenant_config:
                    request.state.tenant_id = tenant_id
                    request.state.tenant_config = tenant_config

                    # Per-tenant rate limiting based on quota
                    quota = tenant_config.get("quota") or {}
                    max_per_min = quota.get("max_requests_per_minute", 60)
                    max_per_day = quota.get("max_requests_per_day", 100_000)
                    max_tokens = quota.get("max_tokens_per_day", 0)

                    allowed, err = check_and_increment(
                        tenant_id=tenant_id,
                        max_per_minute=max_per_min,
                        max_per_day=max_per_day,
                        max_tokens_per_day=max_tokens,
                    )
                    if not allowed:
                        return JSONResponse(
                            status_code=429,
                            content={"error": err, "tenant_id": tenant_id},
                            headers={"Retry-After": "60"},
                        )

        return await call_next(request)


def _extract_api_key(request: Request) -> str | None:
    """Extract tenant API key from request headers.

    Priority order (prefers X-API-Key to avoid collision with upstream
    proxies like RunPod which also use Authorization: Bearer):
      1. X-API-Key header
      2. X-Tenant-Key header
      3. Authorization: Bearer <key>
    """
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()
    tenant_key = request.headers.get("X-Tenant-Key")
    if tenant_key:
        return tenant_key.strip()
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    return None
