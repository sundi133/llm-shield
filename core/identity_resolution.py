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

import os
import time
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

MODE_OFF, MODE_PREFER, MODE_STRICT = "off", "prefer", "strict"
_MODES = (MODE_OFF, MODE_PREFER, MODE_STRICT)
_ENV = "SHIELD_ROLE_BINDING"
_CACHE: dict = {}
_CACHE_TTL_S = 30


def _env_mode() -> str:
    v = os.environ.get(_ENV, MODE_OFF).strip().lower()
    return v if v in _MODES else MODE_OFF


def role_binding_mode(tenant_id: Optional[str] = None) -> str:
    """off | prefer | strict — default off, so nothing changes until opted in.

    ``SHIELD_ROLE_BINDING=off`` disables the feature globally regardless of
    tenant config: the operator kill switch. Otherwise a tenant setting wins.

    Cached briefly. A store that is unreachable resolves to the env default
    rather than locking out every tenant on a Redis blip — the failure mode of
    "cannot read config" should not be "deny everything".
    """
    env = _env_mode()
    if env == MODE_OFF or not tenant_id:
        return env
    hit = _CACHE.get(tenant_id)
    now = time.time()
    if hit and now - hit[1] < _CACHE_TTL_S:
        return hit[0]
    mode = env
    try:
        from storage.tenant_store import _get_redis
        r = _get_redis()
        if r:
            import json
            raw = r.get(f"shield:role_binding:{tenant_id}")
            if raw:
                cfg = json.loads(raw if isinstance(raw, str) else raw.decode())
                cand = str(cfg.get("mode", "")).strip().lower()
                if cand in _MODES:
                    mode = cand
    except Exception:
        mode = env
    _CACHE[tenant_id] = (mode, now)
    return mode


def clear_role_binding_cache_for_tests() -> None:
    _CACHE.clear()


@dataclass(frozen=True)
class ResolvedIdentity:
    """The identity an authorization decision was made on, and its provenance."""

    agent_key: str = ""
    agent_source: str = SOURCE_NONE
    user_role: str = ""
    role_source: str = SOURCE_NONE
    identity_method: str = ""
    trust_level: str = ""
    #: Roles the verified credential asserted, whether or not they were used.
    claimed_roles: tuple = ()
    #: The binding mode this decision resolved under.
    mode: str = "off"

    @property
    def agent_verified(self) -> bool:
        return self.agent_source in VERIFIED_SOURCES

    @property
    def role_verified(self) -> bool:
        """True only when the role came from a verified credential's claim."""
        return self.role_source in VERIFIED_SOURCES

    @property
    def header_overridden(self) -> bool:
        """A verified claim was used while the caller also asserted a role.

        This is the escalation signal: the caller tried to name its own role and
        was ignored. Worth auditing loudly rather than silently discarding.
        """
        return bool(self.claimed_roles) and self.role_verified

    def audit_fields(self) -> dict:
        """Flat fields for the decision audit. Cheap to add, and the only way
        to tell an escalation from a legitimate call after the fact."""
        return {
            "agent_source": self.agent_source,
            "role_source": self.role_source,
            "identity_method": self.identity_method or "",
            "agent_verified": self.agent_verified,
            "role_verified": self.role_verified,
            "role_binding_mode": self.mode,
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
    tenant_id: Optional[str] = None,
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

    # A verified role claim, when the credential carries one and the tenant has
    # opted in. Off by default, so this branch is inert until configured.
    claimed = tuple(getattr(ident, "roles", ()) or ()) if ident is not None else ()
    mode = role_binding_mode(tenant_id)
    if claimed and mode in (MODE_PREFER, MODE_STRICT):
        # The claim wins and the header is ignored. Deterministic ordering: the
        # first role as issued, never set iteration.
        user_role, role_source = str(claimed[0]), agent_source
    elif (body_user_role or "").strip():
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
        claimed_roles=claimed,
        mode=mode,
    )
