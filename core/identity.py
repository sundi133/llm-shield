"""Identity tuple shared across AuthN and AuthZ layers.

The IdentityTuple is what AuthN proves and AuthZ consumes. It is attached
to request.state.identity by AgentIdentityMiddleware, and baked into every
capability token minted on the request's behalf.

Carrying these as a single dataclass (rather than ad-hoc context dict keys)
makes it impossible for a guardrail to accidentally see only part of the
identity — e.g. an agent_id without the user_sub that delegated to it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from fastapi import HTTPException
from starlette.requests import Request


@dataclass(frozen=True)
class IdentityTuple:
    user_sub: str
    agent_id: str
    agent_instance_id: str
    tenant_id: str
    build_hash: str
    model_version: str
    session_id: str
    parent_agent_id: Optional[str] = None
    trust_level: str = "medium"
    identity_method: str = "agent_token"

    def to_dict(self) -> dict:
        return asdict(self)

    def to_context(self) -> dict:
        """Project into the dict shape expected by guardrails' context kwarg."""
        return {
            "user_sub": self.user_sub,
            "agent_key": self.agent_id,
            "agent_instance_id": self.agent_instance_id,
            "parent_agent_id": self.parent_agent_id,
            "tenant_id": self.tenant_id,
            "build_hash": self.build_hash,
            "model_version": self.model_version,
            "session_id": self.session_id,
            "trust_level": self.trust_level,
            "identity_method": self.identity_method,
        }


def get_identity_from_request(request: Request) -> IdentityTuple:
    """FastAPI dependency that returns the verified IdentityTuple.

    Raises 401 if AgentIdentityMiddleware did not attach one (no token,
    invalid token, or token verification failed). Use this on every route
    that mints capability tokens or performs agent actions.
    """
    identity = getattr(request.state, "identity", None)
    if not isinstance(identity, IdentityTuple):
        raise HTTPException(
            status_code=401,
            detail="No verified agent identity. Send a signed X-Agent-Token.",
        )
    return identity
