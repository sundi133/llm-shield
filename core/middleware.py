"""Shield middleware for enriching requests with agent identity and tenant config."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from core.rbac import enforcer
from storage.tenant_store import resolve_tenant_by_api_key, get_tenant


class ShieldMiddleware(BaseHTTPMiddleware):
    """Intercepts requests to /v1/shield/* endpoints.

    Extracts agent identity from X-Agent-Key header or api_key query param
    and adds agent_key, resolved role, and tenant config to request state.
    Does NOT block — just enriches context.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Only enrich /v1/shield/ requests
        if request.url.path.startswith("/v1/shield"):
            # Extract agent key from header or query param
            agent_key = request.headers.get("X-Agent-Key")
            if not agent_key:
                agent_key = request.query_params.get("api_key")

            # Store on request state
            request.state.agent_key = agent_key

            # Resolve role if agent key is present
            if agent_key:
                role = enforcer.resolve_role(agent_key)
                request.state.role = role
                request.state.role_name = role.name if role else None
            else:
                request.state.role = None
                request.state.role_name = None

            # Resolve tenant from API key
            request.state.tenant_id = None
            request.state.tenant_config = None
            api_key = _extract_api_key(request)
            if api_key:
                tenant_id = resolve_tenant_by_api_key(api_key)
                if tenant_id:
                    request.state.tenant_id = tenant_id
                    request.state.tenant_config = get_tenant(tenant_id)

        return await call_next(request)


def _extract_api_key(request: Request) -> str | None:
    """Extract API key from Authorization header or X-API-Key header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].strip()
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()
    return None
