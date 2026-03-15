"""Shield middleware for enriching requests with agent identity."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from core.rbac import enforcer


class ShieldMiddleware(BaseHTTPMiddleware):
    """Intercepts requests to /v1/shield/* endpoints.

    Extracts agent identity from X-Agent-Key header or api_key query param
    and adds agent_key and resolved role to request state.
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

        return await call_next(request)
