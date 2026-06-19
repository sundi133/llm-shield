"""Middleware that verifies X-Agent-Token and attaches an IdentityTuple.

Additive — does not replace tenant API-key auth. When the header is
absent, the request passes through unchanged (so existing flows keep
working). When the header is present, it MUST verify or the request is
rejected — a token that is present-but-invalid is a stronger signal than
no token at all.
"""

from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from core.agent_tokens import TokenError, verify_agent_token

logger = logging.getLogger("votal.agent_identity_mw")

HEADER_NAME = "X-Agent-Token"


class AgentIdentityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        token = request.headers.get(HEADER_NAME, "").strip()
        if not token:
            # Fallback: synthesize identity from mTLS if available
            mtls = getattr(request.state, "mtls_identity", None)
            if mtls:
                from core.identity import IdentityTuple
                request.state.identity = IdentityTuple(
                    user_sub=mtls.get("agent_key", "mtls-user"),
                    agent_id=mtls.get("agent_key", "mtls-agent"),
                    agent_instance_id=f"mtls-{mtls.get('fingerprint', 'unknown')[:16]}",
                    tenant_id=mtls.get("tenant_id", ""),
                    build_hash="mtls",
                    model_version="n/a",
                    session_id="mtls",
                    trust_level=mtls.get("trust_level", "high"),
                    identity_method="mtls",
                )
            return await call_next(request)

        try:
            identity = verify_agent_token(token)
        except TokenError as e:
            logger.info(f"agent_token rejected: {e}")
            # Telemetry: count the rejection. Recover tenant/agent from the
            # token's (unverified) claims so the portal can attribute it —
            # an expired/revoked/wrong-key token still has decodable claims.
            try:
                from storage import agent_auth_stats as _stats
                from core.jwt_utils import decode_jwt_unverified
                _t = _a = None
                try:
                    _c = decode_jwt_unverified(token)
                    _t = _c.get("tenant_id")
                    _a = _c.get("agent_id")
                except Exception:
                    pass
                _stats.record(
                    tenant_id=_t,
                    event=_stats.EVENT_TOKEN_REJECTED,
                    agent_id=_a,
                    reason=str(e)[:240],
                )
            except Exception:
                pass
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_agent_token", "detail": str(e)},
            )

        request.state.identity = identity
        return await call_next(request)
