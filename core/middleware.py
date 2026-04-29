"""Shield middleware for enriching requests with agent/tenant context and rate limiting."""

import json
import time
import threading
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

# ── Shadow Agent Discovery ──────────────────────────────────────────
# Buffers shadow agent sightings in-memory and flushes to Redis
# periodically to avoid adding latency to every request.
_shadow_buffer: dict[str, dict] = {}  # key = "tenant_id::agent_key"
_shadow_lock = threading.Lock()
_shadow_last_flush = 0.0
_SHADOW_FLUSH_INTERVAL = 30  # seconds

# In-memory cache of registered agent keys per tenant (avoids Redis on every req)
_registry_cache: dict[str, tuple[set[str], float]] = {}
_REGISTRY_CACHE_TTL = 120  # seconds


def _get_registered_agents(tenant_id: str) -> set[str]:
    """Get the set of registered agent keys for a tenant (cached)."""
    now = time.time()
    if tenant_id in _registry_cache:
        keys, ts = _registry_cache[tenant_id]
        if now - ts < _REGISTRY_CACHE_TTL:
            return keys
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if r:
            raw = r.get(f"agents:{tenant_id}")
            if raw:
                data = json.loads(raw) if isinstance(raw, str) else raw
                if isinstance(data, dict):
                    keys = set(data.keys())
                    _registry_cache[tenant_id] = (keys, now)
                    return keys
    except Exception:
        pass
    _registry_cache[tenant_id] = (set(), now)
    return set()


def _record_shadow_agent(tenant_id: str, agent_key: str, endpoint: str,
                         user_role: str | None):
    """Buffer a shadow agent sighting (non-blocking, in-memory)."""
    buf_key = f"{tenant_id}::{agent_key}"
    now = int(time.time())
    with _shadow_lock:
        if buf_key in _shadow_buffer:
            entry = _shadow_buffer[buf_key]
            entry["last_seen"] = now
            entry["call_count"] += 1
            entry["endpoints"].add(endpoint)
            if user_role:
                entry["roles"].add(user_role)
        else:
            _shadow_buffer[buf_key] = {
                "tenant_id": tenant_id,
                "agent_key": agent_key,
                "first_seen": now,
                "last_seen": now,
                "call_count": 1,
                "endpoints": {endpoint},
                "roles": {user_role} if user_role else set(),
            }
    _maybe_flush_shadows()


def _maybe_flush_shadows():
    """Flush the buffer to Redis if enough time has passed."""
    global _shadow_last_flush
    now = time.time()
    if now - _shadow_last_flush < _SHADOW_FLUSH_INTERVAL:
        return
    _shadow_last_flush = now
    threading.Thread(target=_flush_shadows_to_redis, daemon=True).start()


def _flush_shadows_to_redis():
    """Write buffered shadow agent sightings to Redis (runs in background thread)."""
    with _shadow_lock:
        if not _shadow_buffer:
            return
        batch = dict(_shadow_buffer)
        _shadow_buffer.clear()

    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if not r:
            return

        per_tenant: dict[str, list] = {}
        for entry in batch.values():
            tid = entry["tenant_id"]
            per_tenant.setdefault(tid, []).append(entry)

        for tid, entries in per_tenant.items():
            key = f"unregistered:{tid}"
            raw = r.get(key)
            store = json.loads(raw) if raw and isinstance(raw, str) else {}
            if not isinstance(store, dict):
                store = {}
            agents_map = store.get("agents", {})

            for e in entries:
                aid = e["agent_key"]
                if aid in agents_map:
                    existing = agents_map[aid]
                    existing["last_seen"] = e["last_seen"]
                    existing["call_count"] = existing.get("call_count", 0) + e["call_count"]
                    prev_ep = set(existing.get("endpoints", []))
                    existing["endpoints"] = sorted(prev_ep | e["endpoints"])
                    prev_roles = set(existing.get("roles", []))
                    existing["roles"] = sorted(prev_roles | e["roles"])
                else:
                    agents_map[aid] = {
                        "first_seen": e["first_seen"],
                        "last_seen": e["last_seen"],
                        "call_count": e["call_count"],
                        "endpoints": sorted(e["endpoints"]),
                        "roles": sorted(e["roles"]),
                        "source": "middleware_discovery",
                    }

            store["agents"] = agents_map
            r.set(key, json.dumps(store))
    except Exception:
        pass


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
    _GUARDED_PREFIXES = (
        "/v1/shield",
        "/v1/tenant",
        "/v1/agents",
        "/v1/data-policies",
    )
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

            # Certificate-based identity: resolve fingerprint → agent_key
            cert_fingerprint = request.headers.get("X-Client-Cert-Fingerprint")
            request.state.trust_level = None
            request.state.identity_method = None

            if cert_fingerprint:
                # Cert fingerprint takes precedence — resolve to agent_key
                tenant_id_for_cert = getattr(request.state, "tenant_id", None)
                if not tenant_id_for_cert:
                    # Try resolving tenant first from API key
                    _api_key = _extract_api_key(request)
                    if _api_key:
                        _tid, _ = _get_cached_tenant(_api_key)
                        tenant_id_for_cert = _tid

                if tenant_id_for_cert:
                    try:
                        from guardrails.agentic.identity.cert_registry import resolve_agent_by_cert
                        cert_agent = resolve_agent_by_cert(tenant_id_for_cert, cert_fingerprint)
                        if cert_agent:
                            agent_key = cert_agent
                            request.state.trust_level = "high"
                            request.state.identity_method = "cert"
                    except Exception:
                        pass

            if not request.state.trust_level:
                request.state.trust_level = "medium" if agent_key else "low"
                request.state.identity_method = "string_key" if agent_key else "anonymous"

            request.state.agent_key = agent_key

            # Resolve role if agent key is present
            user_role = request.headers.get("X-User-Role")
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

                    # Shadow agent discovery — detect unregistered agent keys
                    if agent_key:
                        registered = _get_registered_agents(tenant_id)
                        if registered and agent_key not in registered:
                            request.state.shadow_agent = True
                            _record_shadow_agent(
                                tenant_id, agent_key, path, user_role,
                            )
                        else:
                            request.state.shadow_agent = False

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
