"""Where an authorization decision's identity actually came from.

Shield verifies agent identity well — Ed25519 agent tokens, SPIFFE SVIDs, OIDC
service-account tokens — and then authorizes from `X-Agent-Key` and
`X-User-Role` read straight off the request. The verified `IdentityTuple` is
attached to `request.state.identity` and read by one route.

This module is the seam that closes that. Every authorization site calls
`resolve_identity()` instead of reading headers directly, so:

  * the *source* of each field is recorded and auditable, and
  * when verified role claims land (docs/spec-agent-role-binding.md), one
    function changes rather than four call sites.

It deliberately changes NO outcome today. `resolve_identity()` returns exactly
what the header-reading code returned, plus provenance. Making the gap visible
has to come before closing it: you cannot roll out "reject unverified roles"
without first knowing who is sending them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

# Ordered strongest-first. A verified claim outranks anything self-asserted.
SOURCE_AGENT_TOKEN = "agent_token"   # signed by Shield, verified by middleware
SOURCE_MTLS = "mtls"                 # client cert, via the trusted-proxy boundary
SOURCE_OIDC = "oidc"                 # external IdP token, signature + aud verified
SOURCE_BODY = "body"                 # caller asserted it in the request body
SOURCE_HEADER = "header"             # caller asserted it in a request header
SOURCE_NONE = "none"                 # absent

#: Sources where the value was proven cryptographically rather than claimed.
VERIFIED_SOURCES = frozenset({SOURCE_AGENT_TOKEN, SOURCE_MTLS, SOURCE_OIDC})


@dataclass(frozen=True)
class ResolvedIdentity:
    """The identity an authorization decision was made on, and its provenance."""

    agent_key: str = ""
    agent_source: str = SOURCE_NONE
    user_role: str = ""
    role_source: str = SOURCE_NONE
    identity_method: str = ""
    trust_level: str = ""

    @property
    def agent_verified(self) -> bool:
        return self.agent_source in VERIFIED_SOURCES

    @property
    def role_verified(self) -> bool:
        """Today this is always False: no identity method carries a role claim.

        That is the finding, not an omission — see the role-binding spec.
        """
        return self.role_source in VERIFIED_SOURCES

    def audit_fields(self) -> dict:
        """Flat fields for the decision audit. Cheap to add, and the only way
        to tell an escalation from a legitimate call after the fact."""
        return {
            "agent_source": self.agent_source,
            "role_source": self.role_source,
            "identity_method": self.identity_method or "",
            "agent_verified": self.agent_verified,
            "role_verified": self.role_verified,
        }


def _header(request: Any, name: str) -> str:
    try:
        h = request.headers
    except Exception:
        return ""
    return (h.get(name) or h.get(name.lower()) or "").strip()


def _verified_identity(request: Any):
    """The IdentityTuple AgentIdentityMiddleware attached, if any."""
    state = getattr(request, "state", None)
    return getattr(state, "identity", None) if state is not None else None


def resolve_identity(
    request: Any,
    *,
    body_agent_key: Optional[str] = None,
    body_user_role: Optional[str] = None,
) -> ResolvedIdentity:
    """Resolve agent and role for an authorization decision, with provenance.

    Precedence for the agent: a verified token's ``agent_id`` first, then the
    body, then the header. The first two already agreed in practice — the route
    cross-checks them — so preferring the verified one changes no outcome while
    making the source truthful.

    The role has no verified source yet, so body then header, exactly as before.
    ``role_source`` will read ``oidc``/``agent_token`` once claims carry it.
    """
    ident = _verified_identity(request)

    agent_key, agent_source = "", SOURCE_NONE
    identity_method, trust_level = "", ""
    if ident is not None and getattr(ident, "agent_id", ""):
        agent_key = ident.agent_id
        identity_method = getattr(ident, "identity_method", "") or ""
        trust_level = getattr(ident, "trust_level", "") or ""
        agent_source = {
            "mtls": SOURCE_MTLS,
            "oidc_sa": SOURCE_OIDC,
            "oidc": SOURCE_OIDC,
        }.get(identity_method, SOURCE_AGENT_TOKEN)
    elif (body_agent_key or "").strip():
        agent_key, agent_source = body_agent_key.strip(), SOURCE_BODY
    else:
        hdr = _header(request, "X-Agent-Key")
        if hdr:
            agent_key, agent_source = hdr, SOURCE_HEADER

    if (body_user_role or "").strip():
        user_role, role_source = body_user_role.strip(), SOURCE_BODY
    else:
        hdr = _header(request, "X-User-Role")
        user_role, role_source = (hdr, SOURCE_HEADER) if hdr else ("", SOURCE_NONE)

    return ResolvedIdentity(
        agent_key=agent_key,
        agent_source=agent_source,
        user_role=user_role,
        role_source=role_source,
        identity_method=identity_method,
        trust_level=trust_level,
    )
